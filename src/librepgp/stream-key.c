/*
 * Copyright (c) 2018, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "stream-def.h"
#include "stream-key.h"
#include "stream-armor.h"
#include "stream-packet.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "defs.h"
#include "types.h"
#include "symmetric.h"
#include "fingerprint.h"
#include "pgp-key.h"
#include "list.h"
#include "packet-parse.h"
#include "utils.h"
#include "crypto.h"
#include "crypto/s2k.h"

static void
signature_list_destroy(list *sigs)
{
    for (list_item *li = list_front(*sigs); li; li = list_next(li)) {
        free_signature((pgp_signature_t *) li);
    }
    list_destroy(sigs);
}

void
transferable_key_destroy(pgp_transferable_key_t *key)
{
    forget_secret_key_fields(&key->key);

    for (list_item *li = list_front(key->userids); li; li = list_next(li)) {
        pgp_transferable_userid_t *uid = (pgp_transferable_userid_t *) li;
        free_userid_pkt(&uid->uid);
        signature_list_destroy(&uid->signatures);
    }
    list_destroy(&key->userids);

    for (list_item *li = list_front(key->subkeys); li; li = list_next(li)) {
        pgp_transferable_subkey_t *skey = (pgp_transferable_subkey_t *) li;
        forget_secret_key_fields(&skey->subkey);
        free_key_pkt(&skey->subkey);
        signature_list_destroy(&skey->signatures);
    }
    list_destroy(&key->subkeys);

    signature_list_destroy(&key->signatures);
    free_key_pkt(&key->key);
}

void
key_sequence_destroy(pgp_key_sequence_t *keys)
{
    for (list_item *li = list_front(keys->keys); li; li = list_next(li)) {
        transferable_key_destroy((pgp_transferable_key_t *) li);
    }
    list_destroy(&keys->keys);
}

rnp_result_t
process_pgp_keys(pgp_source_t *src, pgp_key_sequence_t *keys)
{
    int                        ptag;
    bool                       armored = false;
    pgp_source_t               armorsrc = {0};
    bool                       has_secret = false;
    bool                       has_public = false;
    pgp_transferable_key_t *   curkey = NULL;
    pgp_transferable_subkey_t *cursubkey = NULL;
    pgp_transferable_userid_t *curuid = NULL;
    rnp_result_t               ret = RNP_ERROR_GENERIC;

    memset(keys, 0, sizeof(*keys));

    /* check whether keys are armored */
    if (is_armored_source(src)) {
        if ((ret = init_armored_src(&armorsrc, src))) {
            RNP_LOG("failed to parse armored data");
            goto finish;
        }
        armored = true;
        src = &armorsrc;
    }

    /* read sequence of transferable OpenPGP keys as described in RFC 4880, 11.1 - 11.2 */
    while (!src_eof(src)) {
        if ((ptag = stream_pkt_type(src)) < 0) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }

        switch (ptag) {
        case PGP_PTAG_CT_SECRET_KEY:
        case PGP_PTAG_CT_PUBLIC_KEY:
            if (!(curkey = (pgp_transferable_key_t *) list_append(
                    &keys->keys, NULL, sizeof(*curkey)))) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto finish;
            }
            if ((ret = stream_parse_key(src, &curkey->key))) {
                list_remove((list_item *) curkey);
                goto finish;
            }
            cursubkey = NULL;
            curuid = NULL;
            has_secret |= (ptag == PGP_PTAG_CT_SECRET_KEY);
            has_public |= (ptag == PGP_PTAG_CT_PUBLIC_KEY);
            break;
        case PGP_PTAG_CT_PUBLIC_SUBKEY:
        case PGP_PTAG_CT_SECRET_SUBKEY:
            if (!curkey) {
                RNP_LOG("unexpected subkey packet");
                ret = RNP_ERROR_BAD_FORMAT;
                goto finish;
            }
            if (!(cursubkey = (pgp_transferable_subkey_t *) list_append(
                    &curkey->subkeys, NULL, sizeof(*cursubkey)))) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto finish;
            }
            curuid = NULL;
            if ((ret = stream_parse_key(src, &cursubkey->subkey))) {
                list_remove((list_item *) cursubkey);
                goto finish;
            }
            break;
        case PGP_PTAG_CT_SIGNATURE: {
            list *           siglist = NULL;
            pgp_signature_t *sig;

            if (!curkey) {
                RNP_LOG("unexpected signature");
                ret = RNP_ERROR_BAD_FORMAT;
                goto finish;
            }

            if (curuid) {
                siglist = &curuid->signatures;
            } else if (cursubkey) {
                siglist = &cursubkey->signatures;
            } else {
                siglist = &curkey->signatures;
            }

            if (!(sig = (pgp_signature_t *) list_append(siglist, NULL, sizeof(*sig)))) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto finish;
            }
            if ((ret = stream_parse_signature(src, sig))) {
                list_remove((list_item *) sig);
                goto finish;
            }
            break;
        }
        case PGP_PTAG_CT_USER_ID:
        case PGP_PTAG_CT_USER_ATTR:
            if (cursubkey) {
                RNP_LOG("userid after the subkey");
                ret = RNP_ERROR_BAD_FORMAT;
                goto finish;
            }

            if (!(curuid = (pgp_transferable_userid_t *) list_append(
                    &curkey->userids, NULL, sizeof(*curuid)))) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto finish;
            }

            if ((ret = stream_parse_userid(src, &curuid->uid))) {
                list_remove((list_item *) curuid);
                goto finish;
            }
            break;
        case PGP_PTAG_CT_TRUST:
            ret = stream_skip_packet(src);
            break;
        default:
            RNP_LOG("unexpected packet %d in key sequence", ptag);
            ret = RNP_ERROR_BAD_FORMAT;
        }

        if (ret) {
            goto finish;
        }
    }

    if (has_secret && has_public) {
        RNP_LOG("warning! public keys are mixed together with secret ones!");
    }

    ret = RNP_SUCCESS;
finish:
    if (armored) {
        src_close(&armorsrc);
    }
    if (ret) {
        key_sequence_destroy(keys);
    }
    return ret;
}

static bool
write_pgp_signatures(list signatures, pgp_dest_t *dst)
{
    for (list_item *sig = list_front(signatures); sig; sig = list_next(sig)) {
        if (!stream_write_signature((pgp_signature_t *) sig, dst)) {
            return false;
        }
    }

    return true;
}

rnp_result_t
write_pgp_keys(pgp_key_sequence_t *keys, pgp_dest_t *dst, bool armor)
{
    pgp_dest_t   armdst = {0};
    rnp_result_t ret = RNP_ERROR_GENERIC;

    if (armor) {
        pgp_armored_msg_t       msgtype = PGP_ARMORED_PUBLIC_KEY;
        pgp_transferable_key_t *fkey = (pgp_transferable_key_t *) list_front(keys->keys);
        if (fkey && is_secret_key_pkt(fkey->key.tag)) {
            msgtype = PGP_ARMORED_SECRET_KEY;
        }

        if ((ret = init_armored_dst(&armdst, dst, msgtype))) {
            return ret;
        }
        dst = &armdst;
    }

    for (list_item *li = list_front(keys->keys); li; li = list_next(li)) {
        pgp_transferable_key_t *key = (pgp_transferable_key_t *) li;

        /* main key */
        if (!stream_write_key(&key->key, dst)) {
            ret = RNP_ERROR_WRITE;
            goto finish;
        }
        /* revocation signatures */
        if (!write_pgp_signatures(key->signatures, dst)) {
            ret = RNP_ERROR_WRITE;
            goto finish;
        }
        /* user ids/attrs and signatures */
        for (list_item *li = list_front(key->userids); li; li = list_next(li)) {
            pgp_transferable_userid_t *uid = (pgp_transferable_userid_t *) li;

            if (!stream_write_userid(&uid->uid, dst) ||
                !write_pgp_signatures(uid->signatures, dst)) {
                ret = RNP_ERROR_WRITE;
                goto finish;
            }
        }
        /* subkeys with signatures */
        for (list_item *li = list_front(key->subkeys); li; li = list_next(li)) {
            pgp_transferable_subkey_t *skey = (pgp_transferable_subkey_t *) li;

            if (!stream_write_key(&skey->subkey, dst) ||
                !write_pgp_signatures(skey->signatures, dst)) {
                ret = RNP_ERROR_WRITE;
                goto finish;
            }
        }
    }

    ret = RNP_SUCCESS;

finish:
    if (armor) {
        dst_close(&armdst, ret);
    }

    return ret;
}

static rnp_result_t
decrypt_secret_key_v3(pgp_crypt_t *crypt, uint8_t *dec, const uint8_t *enc, size_t len)
{
    size_t idx;
    size_t pos = 0;
    size_t mpilen;
    size_t blsize;

    if (!(blsize = pgp_cipher_block_size(crypt))) {
        RNP_LOG("wrong crypto");
        return RNP_ERROR_BAD_STATE;
    }

    /* 4 RSA secret mpis with cleartext header */
    for (idx = 0; idx < 4; idx++) {
        if (pos + 2 > len) {
            RNP_LOG("bad v3 secret key data");
            return RNP_ERROR_BAD_FORMAT;
        }
        mpilen = (read_uint16(enc + pos) + 7) >> 3;
        memcpy(dec + pos, enc + pos, 2);
        pos += 2;
        if (pos + mpilen > len) {
            RNP_LOG("bad v3 secret key data");
            return RNP_ERROR_BAD_FORMAT;
        }
        pgp_cipher_cfb_decrypt(crypt, dec + pos, enc + pos, mpilen);
        pos += mpilen;
        if (mpilen < blsize) {
            RNP_LOG("bad rsa v3 mpi len");
            return RNP_ERROR_BAD_FORMAT;
        }
        pgp_cipher_cfb_resync(crypt, enc + pos - blsize);
    }

    /* sum16 */
    if (pos + 2 != len) {
        return RNP_ERROR_BAD_FORMAT;
    }
    memcpy(dec + pos, enc + pos, 2);
    return RNP_SUCCESS;
}

static rnp_result_t
parse_secret_key_mpis(pgp_key_pkt_t *key, const uint8_t *mpis, size_t len)
{
    pgp_packet_body_t body;
    bool              res;

    /* check the cleartext data */
    switch (key->sec_protection.s2k.usage) {
    case PGP_S2KU_NONE:
    case PGP_S2KU_ENCRYPTED: {
        /* calculate and check sum16 of the cleartext */
        uint16_t sum = 0;
        size_t   idx;

        len -= 2;
        for (idx = 0; idx < len; idx++) {
            sum += mpis[idx];
        }
        if (sum != read_uint16(mpis + len)) {
            RNP_LOG("wrong key checksum");
            return RNP_ERROR_DECRYPT_FAILED;
        }
        break;
    }
    case PGP_S2KU_ENCRYPTED_AND_HASHED: {
        /* calculate and check sha1 hash of the cleartext */
        pgp_hash_t hash;
        uint8_t    hval[PGP_MAX_HASH_SIZE];

        if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
            return RNP_ERROR_BAD_STATE;
        }
        len -= PGP_SHA1_HASH_SIZE;
        pgp_hash_add(&hash, mpis, len);
        if (pgp_hash_finish(&hash, hval) != PGP_SHA1_HASH_SIZE) {
            return RNP_ERROR_BAD_STATE;
        }
        if (memcmp(hval, mpis + len, PGP_SHA1_HASH_SIZE)) {
            return RNP_ERROR_DECRYPT_FAILED;
        }
        break;
    }
    default:
        RNP_LOG("unknown s2k usage: %d", (int) key->sec_protection.s2k.usage);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* parse mpis depending on algorithm */
    packet_body_part_from_mem(&body, mpis, len);

    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        res = get_packet_body_mpi(&body, &key->material.rsa.d) &&
              get_packet_body_mpi(&body, &key->material.rsa.p) &&
              get_packet_body_mpi(&body, &key->material.rsa.q) &&
              get_packet_body_mpi(&body, &key->material.rsa.u);
        break;
    case PGP_PKA_DSA:
        res = get_packet_body_mpi(&body, &key->material.dsa.x);
        break;
    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
        res = get_packet_body_mpi(&body, &key->material.ecc.x);
        break;
    case PGP_PKA_ECDH:
        res = get_packet_body_mpi(&body, &key->material.ecdh.x);
        break;
    case PGP_PKA_ELGAMAL:
        res = get_packet_body_mpi(&body, &key->material.eg.x);
        break;
    default:
        RNP_LOG("uknown pk alg : %d", (int) key->alg);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!res) {
        RNP_LOG("failed to parse secret data");
        return RNP_ERROR_BAD_FORMAT;
    }

    if (body.pos < body.len) {
        RNP_LOG("extra data in sec key");
        return RNP_ERROR_BAD_FORMAT;
    }

    return RNP_SUCCESS;
}

rnp_result_t
decrypt_secret_key(pgp_key_pkt_t *key, const char *password)
{
    size_t       keysize;
    uint8_t      keybuf[PGP_MAX_KEY_SIZE];
    uint8_t *    decdata = NULL;
    pgp_crypt_t  crypt;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    if (!key || !password) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!is_secret_key_pkt(key->tag)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* check whether data is not encrypted */
    if (!key->sec_protection.s2k.usage) {
        return parse_secret_key_mpis(key, key->sec_data, key->sec_len);
    }

    /* data is encrypted */
    if (key->sec_protection.cipher_mode != PGP_CIPHER_MODE_CFB) {
        RNP_LOG("unsupported secret key encryption mode");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    keysize = pgp_key_size(key->sec_protection.symm_alg);
    if (!keysize || !pgp_s2k_derive_key(&key->sec_protection.s2k, password, keybuf, keysize)) {
        RNP_LOG("failed to derive key");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!(decdata = malloc(key->sec_len))) {
        RNP_LOG("allocation failed");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto finish;
    }

    if (!pgp_cipher_cfb_start(
          &crypt, key->sec_protection.symm_alg, keybuf, key->sec_protection.iv)) {
        RNP_LOG("failed to start cfb decryption");
        ret = RNP_ERROR_DECRYPT_FAILED;
        goto finish;
    }

    switch (key->version) {
    case PGP_V3:
        if (!is_rsa_key_alg(key->alg)) {
            RNP_LOG("non-RSA v3 key");
            ret = RNP_ERROR_BAD_PARAMETERS;
            break;
        }
        ret = decrypt_secret_key_v3(&crypt, decdata, key->sec_data, key->sec_len);
        break;
    case PGP_V4:
        pgp_cipher_cfb_decrypt(&crypt, decdata, key->sec_data, key->sec_len);
        ret = RNP_SUCCESS;
        break;
    default:
        ret = RNP_ERROR_BAD_PARAMETERS;
    }

    pgp_cipher_cfb_finish(&crypt);
    if (ret) {
        goto finish;
    }

    ret = parse_secret_key_mpis(key, decdata, key->sec_len);
finish:
    pgp_forget(keybuf, sizeof(keybuf));
    if (decdata) {
        pgp_forget(decdata, key->sec_len);
        free(decdata);
    }
    return ret;
}

void
forget_secret_key_fields(pgp_key_pkt_t *key)
{
    if (!is_secret_key_pkt(key->tag) || !key->sec_avail) {
        return;
    }

    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        mpi_forget(&key->material.rsa.d);
        mpi_forget(&key->material.rsa.p);
        mpi_forget(&key->material.rsa.q);
        mpi_forget(&key->material.rsa.u);
        break;
    case PGP_PKA_DSA:
        mpi_forget(&key->material.dsa.x);
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        mpi_forget(&key->material.eg.x);
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        mpi_forget(&key->material.ecc.x);
        break;
    case PGP_PKA_ECDH:
        mpi_forget(&key->material.ecdh.x);
        break;
    default:
        RNP_LOG("unknown key algorithm: %d", (int) key->alg);
    }

    key->sec_avail = false;
}
