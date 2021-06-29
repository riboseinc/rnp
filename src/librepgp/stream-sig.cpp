/*
 * Copyright (c) 2018-2020, [Ribose Inc](https://www.ribose.com).
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
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#else
#include "uniwin.h"
#endif
#include <string.h>
#include <type_traits>
#include <stdexcept>
#include <rnp/rnp_def.h>
#include "types.h"
#include "stream-sig.h"
#include "stream-packet.h"
#include "stream-armor.h"
#include "pgp-key.h"
#include "crypto/signatures.h"

#include <time.h>

bool
signature_set_embedded_sig(pgp_signature_t *sig, pgp_signature_t *esig)
{
    pgp_sig_subpkt_t *subpkt = NULL;
    pgp_dest_t        memdst = {};
    pgp_source_t      memsrc = {};
    size_t            len = 0;
    bool              res = false;

    if (init_mem_dest(&memdst, NULL, 0)) {
        RNP_LOG("alloc failed");
        return false;
    }
    try {
        esig->write(memdst);
    } catch (const std::exception &e) {
        RNP_LOG("failed to write signature: %s", e.what());
        goto finish;
    }
    if (init_mem_src(&memsrc, mem_dest_get_memory(&memdst), memdst.writeb, false)) {
        RNP_LOG("failed to init mem src");
        goto finish;
    }
    if (!stream_read_pkt_len(&memsrc, &len)) {
        RNP_LOG("wrong pkt len");
        goto finish;
    }

    try {
        subpkt = &sig->add_subpkt(PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE, len, true);
        subpkt->hashed = false;
        if (!src_read_eq(&memsrc, subpkt->data, len)) {
            RNP_LOG("failed to read back signature");
            goto finish;
        }
        subpkt->fields.sig = new pgp_signature_t(*esig);
        subpkt->parsed = true;
        res = true;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
    }
finish:
    if (!res && subpkt) {
        sig->remove_subpkt(subpkt);
    }
    src_close(&memsrc);
    dst_close(&memdst, true);
    return res;
}

bool
signature_add_notation_data(pgp_signature_t *sig,
                            bool             readable,
                            const char *     name,
                            const char *     value)
{
    size_t nlen = strlen(name);
    size_t vlen = strlen(value);

    if ((nlen > 0xffff) || (vlen > 0xffff)) {
        RNP_LOG("wrong length");
        return false;
    }

    try {
        pgp_sig_subpkt_t &subpkt =
          sig->add_subpkt(PGP_SIG_SUBPKT_NOTATION_DATA, 8 + nlen + vlen, false);
        subpkt.hashed = true;
        if (readable) {
            subpkt.data[0] = 0x80;
            subpkt.fields.notation.flags[0] = 0x80;
        }
        write_uint16(subpkt.data + 4, nlen);
        memcpy(subpkt.data + 6, name, nlen);
        write_uint16(subpkt.data + 6 + nlen, vlen);
        memcpy(subpkt.data + 8 + nlen, value, vlen);
        return subpkt.parse();
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

bool
signature_fill_hashed_data(pgp_signature_t *sig)
{
    /* we don't have a need to write v2-v3 signatures */
    if ((sig->version < PGP_V2) || (sig->version > PGP_V4)) {
        RNP_LOG("don't know version %d", (int) sig->version);
        return false;
    }
    try {
        pgp_packet_body_t hbody(PGP_PKT_RESERVED);
        if (sig->version < PGP_V4) {
            hbody.add_byte(sig->type());
            hbody.add_uint32(sig->creation_time);
        } else {
            hbody.add_byte(sig->version);
            hbody.add_byte(sig->type());
            hbody.add_byte(sig->palg);
            hbody.add_byte(sig->halg);
            hbody.add_subpackets(*sig, true);
        }

        free(sig->hashed_data);
        sig->hashed_data = (uint8_t *) malloc(hbody.size());
        if (!sig->hashed_data) {
            RNP_LOG("allocation failed");
            return false;
        }
        memcpy(sig->hashed_data, hbody.data(), hbody.size());
        sig->hashed_len = hbody.size();
        return true;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

bool
signature_hash_key(const pgp_key_pkt_t *key, pgp_hash_t *hash)
{
    if (!key || !hash) {
        RNP_LOG("null key or hash");
        return false;
    }

    uint8_t hdr[3] = {0x99, 0x00, 0x00};
    if (key->hashed_data) {
        write_uint16(hdr + 1, key->hashed_len);
        return !pgp_hash_add(hash, hdr, 3) &&
               !pgp_hash_add(hash, key->hashed_data, key->hashed_len);
    }

    /* call self recursively if hashed data is not filled, to overcome const restriction */
    try {
        pgp_key_pkt_t keycp(*key, true);
        keycp.fill_hashed_data();
        return signature_hash_key(&keycp, hash);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

bool
signature_hash_userid(const pgp_userid_pkt_t *uid, pgp_hash_t *hash, pgp_version_t sigver)
{
    uint8_t hdr[5] = {0};

    if (!uid || !hash) {
        RNP_LOG("null uid or hash");
        return false;
    }

    if (sigver < PGP_V4) {
        return !pgp_hash_add(hash, uid->uid, uid->uid_len);
    }

    switch (uid->tag) {
    case PGP_PKT_USER_ID:
        hdr[0] = 0xB4;
        break;
    case PGP_PKT_USER_ATTR:
        hdr[0] = 0xD1;
        break;
    default:
        RNP_LOG("wrong uid");
        return false;
    }
    STORE32BE(hdr + 1, uid->uid_len);

    return !pgp_hash_add(hash, hdr, 5) && !pgp_hash_add(hash, uid->uid, uid->uid_len);
}

bool
signature_hash_signature(pgp_signature_t *sig, pgp_hash_t *hash)
{
    uint8_t hdr[5] = {0x88, 0x00, 0x00, 0x00, 0x00};

    if (!sig || !hash) {
        RNP_LOG("null sig or hash");
        return false;
    }

    if (!sig->hashed_data) {
        RNP_LOG("hashed data not filled");
        return false;
    }

    STORE32BE(hdr + 1, sig->hashed_len);
    return !pgp_hash_add(hash, hdr, 5) &&
           !pgp_hash_add(hash, sig->hashed_data, sig->hashed_len);
}

bool
signature_hash_certification(const pgp_signature_t * sig,
                             const pgp_key_pkt_t *   key,
                             const pgp_userid_pkt_t *userid,
                             pgp_hash_t *            hash)
{
    bool res = false;

    if (signature_init(&key->material, sig->halg, hash) != RNP_SUCCESS) {
        return false;
    }

    res = signature_hash_key(key, hash) && signature_hash_userid(userid, hash, sig->version);

    if (!res) {
        pgp_hash_finish(hash, NULL);
    }

    return res;
}

bool
signature_hash_binding(const pgp_signature_t *sig,
                       const pgp_key_pkt_t *  key,
                       const pgp_key_pkt_t *  subkey,
                       pgp_hash_t *           hash)
{
    bool res = false;

    if (signature_init(&key->material, sig->halg, hash) != RNP_SUCCESS) {
        return false;
    }

    res = signature_hash_key(key, hash) && signature_hash_key(subkey, hash);

    if (!res) {
        pgp_hash_finish(hash, NULL);
    }

    return res;
}

bool
signature_hash_direct(const pgp_signature_t *sig, const pgp_key_pkt_t *key, pgp_hash_t *hash)
{
    bool res = false;

    if (signature_init(&key->material, sig->halg, hash) != RNP_SUCCESS) {
        return false;
    }

    res = signature_hash_key(key, hash);

    if (!res) {
        pgp_hash_finish(hash, NULL);
    }

    return res;
}

rnp_result_t
signature_check(pgp_signature_info_t *sinfo, pgp_hash_t *hash)
{
    uint32_t     now;
    uint32_t     create, expiry, kcreate;
    rnp_result_t ret = RNP_ERROR_SIGNATURE_INVALID;

    sinfo->no_signer = !sinfo->signer;
    sinfo->valid = false;
    sinfo->expired = false;

    if (!sinfo->sig) {
        ret = RNP_ERROR_NULL_POINTER;
        goto finish;
    }

    if (!sinfo->signer) {
        ret = RNP_ERROR_NO_SUITABLE_KEY;
        goto finish;
    }

    /* Validate signature itself */
    if (sinfo->signer_valid || sinfo->signer->valid_at(sinfo->sig->creation())) {
        sinfo->valid = !signature_validate(sinfo->sig, &sinfo->signer->material(), hash);
    } else {
        sinfo->valid = false;
        RNP_LOG("invalid or untrusted key");
    }

    /* Check signature's expiration time */
    now = time(NULL);
    create = sinfo->sig->creation();
    expiry = sinfo->sig->expiration();
    if (create > now) {
        /* signature created later then now */
        RNP_LOG("signature created %d seconds in future", (int) (create - now));
        sinfo->expired = true;
    }
    if (create && expiry && (create + expiry < now)) {
        /* signature expired */
        RNP_LOG("signature expired");
        sinfo->expired = true;
    }

    /* check key creation time vs signature creation */
    kcreate = sinfo->signer->creation();
    if (kcreate > create) {
        RNP_LOG("key is newer than signature");
        sinfo->valid = false;
    }

    /* check whether key was not expired when sig created */
    if (!sinfo->ignore_expiry && sinfo->signer->expiration() &&
        (kcreate + sinfo->signer->expiration() < create)) {
        RNP_LOG("signature made after key expiration");
        sinfo->valid = false;
    }

    /* Check signer's fingerprint */
    if (sinfo->sig->has_keyfp() && (sinfo->sig->keyfp() != sinfo->signer->fp())) {
        RNP_LOG("issuer fingerprint doesn't match signer's one");
        sinfo->valid = false;
    }

    if (sinfo->expired && sinfo->valid) {
        ret = RNP_ERROR_SIGNATURE_EXPIRED;
    } else {
        ret = sinfo->valid ? RNP_SUCCESS : RNP_ERROR_SIGNATURE_INVALID;
    }
finish:
    pgp_hash_finish(hash, NULL);
    return ret;
}

rnp_result_t
signature_check_certification(pgp_signature_info_t *  sinfo,
                              const pgp_key_pkt_t *   key,
                              const pgp_userid_pkt_t *uid)
{
    pgp_hash_t hash = {};

    if (!signature_hash_certification(sinfo->sig, key, uid, &hash)) {
        return RNP_ERROR_BAD_FORMAT;
    }

    return signature_check(sinfo, &hash);
}

rnp_result_t
signature_check_binding(pgp_signature_info_t *sinfo,
                        const pgp_key_pkt_t * key,
                        const pgp_key_t *     subkey)
{
    pgp_hash_t   hash = {};
    rnp_result_t res = RNP_ERROR_SIGNATURE_INVALID;

    if (!signature_hash_binding(sinfo->sig, key, &subkey->pkt(), &hash)) {
        return RNP_ERROR_BAD_FORMAT;
    }

    res = signature_check(sinfo, &hash);
    if (res || !(sinfo->sig->key_flags() & PGP_KF_SIGN)) {
        return res;
    }

    /* check primary key binding signature if any */
    res = RNP_ERROR_SIGNATURE_INVALID;
    sinfo->valid = false;
    pgp_sig_subpkt_t *subpkt =
      sinfo->sig->get_subpkt(PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE, false);
    if (!subpkt) {
        RNP_LOG("error! no primary key binding signature");
        return res;
    }
    if (!subpkt->parsed) {
        RNP_LOG("invalid embedded signature subpacket");
        return res;
    }
    if (subpkt->fields.sig->type() != PGP_SIG_PRIMARY) {
        RNP_LOG("invalid primary key binding signature");
        return res;
    }
    if (subpkt->fields.sig->version < PGP_V4) {
        RNP_LOG("invalid primary key binding signature version");
        return res;
    }

    if (!signature_hash_binding(subpkt->fields.sig, key, &subkey->pkt(), &hash)) {
        return RNP_ERROR_BAD_FORMAT;
    }
    pgp_signature_info_t bindinfo = {};
    bindinfo.sig = subpkt->fields.sig;
    bindinfo.signer = subkey;
    bindinfo.signer_valid = true;
    bindinfo.ignore_expiry = true;
    res = signature_check(&bindinfo, &hash);
    sinfo->valid = !res;
    return res;
}

rnp_result_t
signature_check_direct(pgp_signature_info_t *sinfo, const pgp_key_pkt_t *key)
{
    pgp_hash_t hash = {};

    if (!signature_hash_direct(sinfo->sig, key, &hash)) {
        return RNP_ERROR_BAD_FORMAT;
    }

    return signature_check(sinfo, &hash);
}

rnp_result_t
signature_check_subkey_revocation(pgp_signature_info_t *sinfo,
                                  const pgp_key_pkt_t * key,
                                  const pgp_key_pkt_t * subkey)
{
    pgp_hash_t hash = {};

    if (!signature_hash_binding(sinfo->sig, key, subkey, &hash)) {
        return RNP_ERROR_BAD_FORMAT;
    }

    return signature_check(sinfo, &hash);
}

rnp_result_t
process_pgp_signatures(pgp_source_t *src, pgp_signature_list_t &sigs)
{
    bool          armored = false;
    pgp_source_t  armorsrc = {0};
    pgp_source_t *origsrc = src;
    rnp_result_t  ret = RNP_ERROR_GENERIC;

    sigs.clear();
    /* check whether signatures are armored */
armoredpass:
    if (is_armored_source(src)) {
        if ((ret = init_armored_src(&armorsrc, src))) {
            RNP_LOG("failed to parse armored data");
            goto finish;
        }
        armored = true;
        src = &armorsrc;
    }

    /* read sequence of OpenPGP signatures */
    while (!src_eof(src) && !src_error(src)) {
        int ptag = stream_pkt_type(src);

        if (ptag != PGP_PKT_SIGNATURE) {
            RNP_LOG("wrong signature tag: %d", ptag);
            ret = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }

        try {
            sigs.emplace_back();
            if ((ret = sigs.back().parse(*src))) {
                goto finish;
            }
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto finish;
        }
    }

    /* file may have multiple armored keys */
    if (armored && !src_eof(origsrc) && is_armored_source(origsrc)) {
        src_close(&armorsrc);
        armored = false;
        src = origsrc;
        goto armoredpass;
    }
    ret = RNP_SUCCESS;
finish:
    if (armored) {
        src_close(&armorsrc);
    }
    if (ret) {
        sigs.clear();
    }
    return ret;
}

pgp_sig_subpkt_t::pgp_sig_subpkt_t(const pgp_sig_subpkt_t &src)
{
    type = src.type;
    len = src.len;
    data = (uint8_t *) malloc(len);
    if (!data) {
        throw std::bad_alloc();
    }
    memcpy(data, src.data, len);
    critical = src.critical;
    hashed = src.hashed;
    parsed = false;
    parse();
}

pgp_sig_subpkt_t::pgp_sig_subpkt_t(pgp_sig_subpkt_t &&src)
{
    type = src.type;
    len = src.len;
    data = src.data;
    src.data = NULL;
    critical = src.critical;
    hashed = src.hashed;
    parsed = src.parsed;
    memcpy(&fields, &src.fields, sizeof(fields));
    src.fields = {};
}

pgp_sig_subpkt_t &
pgp_sig_subpkt_t::operator=(pgp_sig_subpkt_t &&src)
{
    if (&src == this) {
        return *this;
    }

    if (parsed && (type == PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE)) {
        delete fields.sig;
    }
    type = src.type;
    len = src.len;
    free(data);
    data = src.data;
    src.data = NULL;
    critical = src.critical;
    hashed = src.hashed;
    parsed = src.parsed;
    fields = src.fields;
    src.fields = {};
    return *this;
}

pgp_sig_subpkt_t &
pgp_sig_subpkt_t::operator=(const pgp_sig_subpkt_t &src)
{
    if (&src == this) {
        return *this;
    }

    if (parsed && (type == PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE)) {
        delete fields.sig;
    }
    type = src.type;
    len = src.len;
    free(data);
    data = (uint8_t *) malloc(len);
    if (!data) {
        throw std::bad_alloc();
    }
    memcpy(data, src.data, len);
    critical = src.critical;
    hashed = src.hashed;
    parsed = false;
    fields = {};
    parse();
    return *this;
}

bool
pgp_sig_subpkt_t::parse()
{
    bool oklen = true;
    bool checked = true;

    switch (type) {
    case PGP_SIG_SUBPKT_CREATION_TIME:
        if (!hashed) {
            RNP_LOG("creation time subpacket must be hashed");
            checked = false;
        }
        if ((oklen = len == 4)) {
            fields.create = read_uint32(data);
        }
        break;
    case PGP_SIG_SUBPKT_EXPIRATION_TIME:
    case PGP_SIG_SUBPKT_KEY_EXPIRY:
        if ((oklen = len == 4)) {
            fields.expiry = read_uint32(data);
        }
        break;
    case PGP_SIG_SUBPKT_EXPORT_CERT:
        if ((oklen = len == 1)) {
            fields.exportable = data[0] != 0;
        }
        break;
    case PGP_SIG_SUBPKT_TRUST:
        if ((oklen = len == 2)) {
            fields.trust.level = data[0];
            fields.trust.amount = data[1];
        }
        break;
    case PGP_SIG_SUBPKT_REGEXP:
        fields.regexp.str = (const char *) data;
        fields.regexp.len = len;
        break;
    case PGP_SIG_SUBPKT_REVOCABLE:
        if ((oklen = len == 1)) {
            fields.revocable = data[0] != 0;
        }
        break;
    case PGP_SIG_SUBPKT_PREFERRED_SKA:
    case PGP_SIG_SUBPKT_PREFERRED_HASH:
    case PGP_SIG_SUBPKT_PREF_COMPRESS:
    case PGP_SIG_SUBPKT_PREFERRED_AEAD:
        fields.preferred.arr = data;
        fields.preferred.len = len;
        break;
    case PGP_SIG_SUBPKT_REVOCATION_KEY:
        if ((oklen = len == 22)) {
            fields.revocation_key.klass = data[0];
            fields.revocation_key.pkalg = (pgp_pubkey_alg_t) data[1];
            fields.revocation_key.fp = &data[2];
        }
        break;
    case PGP_SIG_SUBPKT_ISSUER_KEY_ID:
        if ((oklen = len == 8)) {
            fields.issuer = data;
        }
        break;
    case PGP_SIG_SUBPKT_NOTATION_DATA:
        if ((oklen = len >= 8)) {
            memcpy(fields.notation.flags, data, 4);
            fields.notation.nlen = read_uint16(&data[4]);
            fields.notation.vlen = read_uint16(&data[6]);

            if (len != 8 + fields.notation.nlen + fields.notation.vlen) {
                oklen = false;
            } else {
                fields.notation.name = (const char *) &data[8];
                fields.notation.value = (const char *) &data[8 + fields.notation.nlen];
            }
        }
        break;
    case PGP_SIG_SUBPKT_KEYSERV_PREFS:
        if ((oklen = len >= 1)) {
            fields.ks_prefs.no_modify = (data[0] & 0x80) != 0;
        }
        break;
    case PGP_SIG_SUBPKT_PREF_KEYSERV:
        fields.preferred_ks.uri = (const char *) data;
        fields.preferred_ks.len = len;
        break;
    case PGP_SIG_SUBPKT_PRIMARY_USER_ID:
        if ((oklen = len == 1)) {
            fields.primary_uid = data[0] != 0;
        }
        break;
    case PGP_SIG_SUBPKT_POLICY_URI:
        fields.policy.uri = (const char *) data;
        fields.policy.len = len;
        break;
    case PGP_SIG_SUBPKT_KEY_FLAGS:
        if ((oklen = len >= 1)) {
            fields.key_flags = data[0];
        }
        break;
    case PGP_SIG_SUBPKT_SIGNERS_USER_ID:
        fields.signer.uid = (const char *) data;
        fields.signer.len = len;
        break;
    case PGP_SIG_SUBPKT_REVOCATION_REASON:
        if ((oklen = len >= 1)) {
            fields.revocation_reason.code = (pgp_revocation_type_t) data[0];
            fields.revocation_reason.str = (const char *) &data[1];
            fields.revocation_reason.len = len - 1;
        }
        break;
    case PGP_SIG_SUBPKT_FEATURES:
        if ((oklen = len >= 1)) {
            fields.features = data[0];
        }
        break;
    case PGP_SIG_SUBPKT_SIGNATURE_TARGET:
        if ((oklen = len >= 18)) {
            fields.sig_target.pkalg = (pgp_pubkey_alg_t) data[0];
            fields.sig_target.halg = (pgp_hash_alg_t) data[1];
            fields.sig_target.hash = &data[2];
            fields.sig_target.hlen = len - 2;
        }
        break;
    case PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE:
        try {
            /* parse signature */
            pgp_packet_body_t pkt(data, len);
            pgp_signature_t   sig;
            oklen = checked = !sig.parse(pkt);
            if (checked) {
                fields.sig = new pgp_signature_t(std::move(sig));
            }
            break;
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return false;
        }
    case PGP_SIG_SUBPKT_ISSUER_FPR:
        if ((oklen = len >= 21)) {
            fields.issuer_fp.version = data[0];
            fields.issuer_fp.fp = &data[1];
            fields.issuer_fp.len = len - 1;
        }
        break;
    case PGP_SIG_SUBPKT_PRIVATE_100:
    case PGP_SIG_SUBPKT_PRIVATE_101:
    case PGP_SIG_SUBPKT_PRIVATE_102:
    case PGP_SIG_SUBPKT_PRIVATE_103:
    case PGP_SIG_SUBPKT_PRIVATE_104:
    case PGP_SIG_SUBPKT_PRIVATE_105:
    case PGP_SIG_SUBPKT_PRIVATE_106:
    case PGP_SIG_SUBPKT_PRIVATE_107:
    case PGP_SIG_SUBPKT_PRIVATE_108:
    case PGP_SIG_SUBPKT_PRIVATE_109:
    case PGP_SIG_SUBPKT_PRIVATE_110:
        oklen = true;
        checked = !critical;
        if (!checked) {
            RNP_LOG("unknown critical private subpacket %d", (int) type);
        }
        break;
    case PGP_SIG_SUBPKT_RESERVED_1:
    case PGP_SIG_SUBPKT_RESERVED_8:
    case PGP_SIG_SUBPKT_PLACEHOLDER:
    case PGP_SIG_SUBPKT_RESERVED_13:
    case PGP_SIG_SUBPKT_RESERVED_14:
    case PGP_SIG_SUBPKT_RESERVED_15:
    case PGP_SIG_SUBPKT_RESERVED_17:
    case PGP_SIG_SUBPKT_RESERVED_18:
    case PGP_SIG_SUBPKT_RESERVED_19:
        /* do not report reserved/placeholder subpacket */
        return !critical;
    default:
        RNP_LOG("unknown subpacket : %d", (int) type);
        return !critical;
    }

    if (!oklen) {
        RNP_LOG("wrong len %d of subpacket type %d", (int) len, (int) type);
    } else {
        parsed = 1;
    }
    return oklen && checked;
}

pgp_sig_subpkt_t::~pgp_sig_subpkt_t()
{
    if (parsed && (type == PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE)) {
        delete fields.sig;
    }
    free(data);
}

pgp_signature_t::pgp_signature_t(const pgp_signature_t &src)
{
    version = src.version;
    type_ = src.type_;
    palg = src.palg;
    halg = src.halg;
    memcpy(lbits, src.lbits, sizeof(src.lbits));
    creation_time = src.creation_time;
    signer = src.signer;

    hashed_len = src.hashed_len;
    hashed_data = NULL;
    if (src.hashed_data) {
        if (!(hashed_data = (uint8_t *) malloc(hashed_len))) {
            throw std::bad_alloc();
        }
        memcpy(hashed_data, src.hashed_data, hashed_len);
    }
    material_len = src.material_len;
    material_buf = NULL;
    if (src.material_buf) {
        if (!(material_buf = (uint8_t *) malloc(material_len))) {
            throw std::bad_alloc();
        }
        memcpy(material_buf, src.material_buf, material_len);
    }
    subpkts = src.subpkts;
}

pgp_signature_t::pgp_signature_t(pgp_signature_t &&src)
{
    version = src.version;
    type_ = src.type_;
    palg = src.palg;
    halg = src.halg;
    memcpy(lbits, src.lbits, sizeof(src.lbits));
    creation_time = src.creation_time;
    signer = src.signer;
    hashed_len = src.hashed_len;
    hashed_data = src.hashed_data;
    src.hashed_data = NULL;
    material_len = src.material_len;
    material_buf = src.material_buf;
    src.material_buf = NULL;
    subpkts = std::move(src.subpkts);
}

pgp_signature_t &
pgp_signature_t::operator=(pgp_signature_t &&src)
{
    if (this == &src) {
        return *this;
    }

    version = src.version;
    type_ = src.type_;
    palg = src.palg;
    halg = src.halg;
    memcpy(lbits, src.lbits, sizeof(src.lbits));
    creation_time = src.creation_time;
    signer = src.signer;
    hashed_len = src.hashed_len;
    free(hashed_data);
    hashed_data = src.hashed_data;
    src.hashed_data = NULL;
    material_len = src.material_len;
    free(material_buf);
    material_buf = src.material_buf;
    src.material_buf = NULL;
    subpkts = std::move(src.subpkts);

    return *this;
}

pgp_signature_t &
pgp_signature_t::operator=(const pgp_signature_t &src)
{
    if (this == &src) {
        return *this;
    }

    version = src.version;
    type_ = src.type_;
    palg = src.palg;
    halg = src.halg;
    memcpy(lbits, src.lbits, sizeof(src.lbits));
    creation_time = src.creation_time;
    signer = src.signer;

    hashed_len = src.hashed_len;
    free(hashed_data);
    hashed_data = NULL;
    if (src.hashed_data) {
        if (!(hashed_data = (uint8_t *) malloc(hashed_len))) {
            throw std::bad_alloc();
        }
        memcpy(hashed_data, src.hashed_data, hashed_len);
    }
    material_len = src.material_len;
    free(material_buf);
    material_buf = NULL;
    if (src.material_buf) {
        if (!(material_buf = (uint8_t *) malloc(material_len))) {
            throw std::bad_alloc();
        }
        memcpy(material_buf, src.material_buf, material_len);
    }
    subpkts = src.subpkts;

    return *this;
}

bool
pgp_signature_t::operator==(const pgp_signature_t &src) const
{
    if ((lbits[0] != src.lbits[0]) || (lbits[1] != src.lbits[1])) {
        return false;
    }
    if ((hashed_len != src.hashed_len) || memcmp(hashed_data, src.hashed_data, hashed_len)) {
        return false;
    }
    return (material_len == src.material_len) &&
           !memcmp(material_buf, src.material_buf, material_len);
}

bool
pgp_signature_t::operator!=(const pgp_signature_t &src) const
{
    return !(*this == src);
}

pgp_signature_t::~pgp_signature_t()
{
    free(hashed_data);
    free(material_buf);
}

pgp_sig_id_t
pgp_signature_t::get_id() const
{
    pgp_hash_t hash = {};
    if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
        RNP_LOG("bad sha1 alloc");
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }

    pgp_hash_add(&hash, hashed_data, hashed_len);
    pgp_hash_add(&hash, material_buf, material_len);
    pgp_sig_id_t res;
    static_assert(std::tuple_size<decltype(res)>::value == PGP_SHA1_HASH_SIZE,
                  "pgp_sig_id_t size mismatch");
    pgp_hash_finish(&hash, res.data());
    return res;
}

pgp_sig_subpkt_t *
pgp_signature_t::get_subpkt(pgp_sig_subpacket_type_t stype, bool hashed)
{
    if (version < PGP_V4) {
        return NULL;
    }
    for (auto &subpkt : subpkts) {
        /* if hashed is false then accept any hashed/not hashed subpacket */
        if ((subpkt.type == stype) && (!hashed || subpkt.hashed)) {
            return &subpkt;
        }
    }
    return NULL;
}

const pgp_sig_subpkt_t *
pgp_signature_t::get_subpkt(pgp_sig_subpacket_type_t stype, bool hashed) const
{
    if (version < PGP_V4) {
        return NULL;
    }
    for (auto &subpkt : subpkts) {
        /* if hashed is false then accept any hashed/not hashed subpacket */
        if ((subpkt.type == stype) && (!hashed || subpkt.hashed)) {
            return &subpkt;
        }
    }
    return NULL;
}

bool
pgp_signature_t::has_subpkt(pgp_sig_subpacket_type_t stype, bool hashed) const
{
    if (version < PGP_V4) {
        return false;
    }
    for (auto &subpkt : subpkts) {
        /* if hashed is false then accept any hashed/not hashed subpacket */
        if ((subpkt.type == stype) && (!hashed || subpkt.hashed)) {
            return true;
        }
    }
    return false;
}

bool
pgp_signature_t::has_keyid() const
{
    return (version < PGP_V4) || has_subpkt(PGP_SIG_SUBPKT_ISSUER_KEY_ID, false) ||
           has_keyfp();
}

pgp_key_id_t
pgp_signature_t::keyid() const
{
    /* version 3 uses signature field */
    if (version < PGP_V4) {
        return signer;
    }

    /* version 4 and up use subpackets */
    pgp_key_id_t res;
    static_assert(std::tuple_size<decltype(res)>::value == PGP_KEY_ID_SIZE,
                  "pgp_key_id_t size mismatch");

    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_ISSUER_KEY_ID, false);
    if (subpkt) {
        memcpy(res.data(), subpkt->fields.issuer, PGP_KEY_ID_SIZE);
        return res;
    }
    if ((subpkt = get_subpkt(PGP_SIG_SUBPKT_ISSUER_FPR))) {
        memcpy(res.data(),
               subpkt->fields.issuer_fp.fp + subpkt->fields.issuer_fp.len - PGP_KEY_ID_SIZE,
               PGP_KEY_ID_SIZE);
        return res;
    }
    throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
}

void
pgp_signature_t::set_keyid(const pgp_key_id_t &id)
{
    if (version < PGP_V4) {
        signer = id;
        return;
    }

    static_assert(std::tuple_size<std::remove_reference<decltype(id)>::type>::value ==
                    PGP_KEY_ID_SIZE,
                  "pgp_key_id_t size mismatch");
    pgp_sig_subpkt_t &subpkt = add_subpkt(PGP_SIG_SUBPKT_ISSUER_KEY_ID, PGP_KEY_ID_SIZE, true);
    subpkt.parsed = true;
    subpkt.hashed = false;
    memcpy(subpkt.data, id.data(), PGP_KEY_ID_SIZE);
    subpkt.fields.issuer = subpkt.data;
}

bool
pgp_signature_t::has_keyfp() const
{
    if (version < PGP_V4) {
        return false;
    }
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_ISSUER_FPR);
    return subpkt && (subpkt->fields.issuer_fp.len <= PGP_FINGERPRINT_SIZE);
}

pgp_fingerprint_t
pgp_signature_t::keyfp() const
{
    if (version < PGP_V4) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_ISSUER_FPR);
    pgp_fingerprint_t       res;
    if (!subpkt || (subpkt->fields.issuer_fp.len > sizeof(res.fingerprint))) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }
    res.length = subpkt->fields.issuer_fp.len;
    memcpy(res.fingerprint, subpkt->fields.issuer_fp.fp, subpkt->fields.issuer_fp.len);
    return res;
}

void
pgp_signature_t::set_keyfp(const pgp_fingerprint_t &fp)
{
    if (version < PGP_V4) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }
    pgp_sig_subpkt_t &subpkt = add_subpkt(PGP_SIG_SUBPKT_ISSUER_FPR, 1 + fp.length, true);
    subpkt.parsed = true;
    subpkt.hashed = true;
    subpkt.data[0] = 4;
    memcpy(subpkt.data + 1, fp.fingerprint, fp.length);
    subpkt.fields.issuer_fp.len = fp.length;
    subpkt.fields.issuer_fp.version = subpkt.data[0];
    subpkt.fields.issuer_fp.fp = subpkt.data + 1;
}

uint32_t
pgp_signature_t::creation() const
{
    if (version < PGP_V4) {
        return creation_time;
    }
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_CREATION_TIME);
    return subpkt ? subpkt->fields.create : 0;
}

void
pgp_signature_t::set_creation(uint32_t ctime)
{
    if (version < PGP_V4) {
        creation_time = ctime;
        return;
    }

    pgp_sig_subpkt_t &subpkt = add_subpkt(PGP_SIG_SUBPKT_CREATION_TIME, 4, true);
    subpkt.parsed = true;
    subpkt.hashed = true;
    STORE32BE(subpkt.data, ctime);
    subpkt.fields.create = ctime;
}

uint32_t
pgp_signature_t::expiration() const
{
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_EXPIRATION_TIME);
    return subpkt ? subpkt->fields.expiry : 0;
}

void
pgp_signature_t::set_expiration(uint32_t etime)
{
    if (version < PGP_V4) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }

    pgp_sig_subpkt_t &subpkt = add_subpkt(PGP_SIG_SUBPKT_EXPIRATION_TIME, 4, true);
    subpkt.parsed = true;
    subpkt.hashed = true;
    STORE32BE(subpkt.data, etime);
    subpkt.fields.expiry = etime;
}

uint32_t
pgp_signature_t::key_expiration() const
{
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_KEY_EXPIRY);
    return subpkt ? subpkt->fields.expiry : 0;
}

void
pgp_signature_t::set_key_expiration(uint32_t etime)
{
    if (version < PGP_V4) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }

    pgp_sig_subpkt_t &subpkt = add_subpkt(PGP_SIG_SUBPKT_KEY_EXPIRY, 4, true);
    subpkt.parsed = true;
    subpkt.hashed = true;
    STORE32BE(subpkt.data, etime);
    subpkt.fields.expiry = etime;
}

uint8_t
pgp_signature_t::key_flags() const
{
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_KEY_FLAGS);
    return subpkt ? subpkt->fields.key_flags : 0;
}

void
pgp_signature_t::set_key_flags(uint8_t flags)
{
    pgp_sig_subpkt_t &subpkt = add_subpkt(PGP_SIG_SUBPKT_KEY_FLAGS, 1, true);
    subpkt.parsed = true;
    subpkt.hashed = true;
    subpkt.data[0] = flags;
    subpkt.fields.key_flags = flags;
}

bool
pgp_signature_t::primary_uid() const
{
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_PRIMARY_USER_ID);
    return subpkt ? subpkt->fields.primary_uid : false;
}

void
pgp_signature_t::set_primary_uid(bool primary)
{
    pgp_sig_subpkt_t &subpkt = add_subpkt(PGP_SIG_SUBPKT_PRIMARY_USER_ID, 1, true);
    subpkt.parsed = true;
    subpkt.hashed = true;
    subpkt.data[0] = primary;
    subpkt.fields.primary_uid = primary;
}

std::vector<uint8_t>
pgp_signature_t::preferred(pgp_sig_subpacket_type_t type) const
{
    const pgp_sig_subpkt_t *subpkt = get_subpkt(type);
    return subpkt ? std::vector<uint8_t>(subpkt->fields.preferred.arr,
                                         subpkt->fields.preferred.arr +
                                           subpkt->fields.preferred.len) :
                    std::vector<uint8_t>();
}

void
pgp_signature_t::set_preferred(const std::vector<uint8_t> &data, pgp_sig_subpacket_type_t type)
{
    if (version < PGP_V4) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }

    if (data.empty()) {
        pgp_sig_subpkt_t *subpkt = get_subpkt(type);
        if (subpkt) {
            remove_subpkt(subpkt);
        }
        return;
    }

    pgp_sig_subpkt_t &subpkt = add_subpkt(type, data.size(), true);
    subpkt.parsed = true;
    subpkt.hashed = true;
    memcpy(subpkt.data, data.data(), data.size());
    subpkt.fields.preferred.arr = subpkt.data;
    subpkt.fields.preferred.len = data.size();
}

std::vector<uint8_t>
pgp_signature_t::preferred_symm_algs() const
{
    return preferred(PGP_SIG_SUBPKT_PREFERRED_SKA);
}

void
pgp_signature_t::set_preferred_symm_algs(const std::vector<uint8_t> &algs)
{
    set_preferred(algs, PGP_SIG_SUBPKT_PREFERRED_SKA);
}

std::vector<uint8_t>
pgp_signature_t::preferred_hash_algs() const
{
    return preferred(PGP_SIG_SUBPKT_PREFERRED_HASH);
}

void
pgp_signature_t::set_preferred_hash_algs(const std::vector<uint8_t> &algs)
{
    set_preferred(algs, PGP_SIG_SUBPKT_PREFERRED_HASH);
}

std::vector<uint8_t>
pgp_signature_t::preferred_z_algs() const
{
    return preferred(PGP_SIG_SUBPKT_PREF_COMPRESS);
}

void
pgp_signature_t::set_preferred_z_algs(const std::vector<uint8_t> &algs)
{
    set_preferred(algs, PGP_SIG_SUBPKT_PREF_COMPRESS);
}

uint8_t
pgp_signature_t::key_server_prefs() const
{
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_KEYSERV_PREFS);
    return subpkt ? subpkt->data[0] : 0;
}

void
pgp_signature_t::set_key_server_prefs(uint8_t prefs)
{
    if (version < PGP_V4) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }

    pgp_sig_subpkt_t &subpkt = add_subpkt(PGP_SIG_SUBPKT_KEYSERV_PREFS, 1, true);
    subpkt.parsed = true;
    subpkt.hashed = true;
    subpkt.data[0] = prefs;
    subpkt.fields.ks_prefs.no_modify = prefs & 0x80;
}

std::string
pgp_signature_t::key_server() const
{
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_PREF_KEYSERV);
    return subpkt ? std::string((char *) subpkt->data, subpkt->len) : "";
}

void
pgp_signature_t::set_key_server(const std::string &uri)
{
    if (version < PGP_V4) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }

    if (uri.empty()) {
        pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_PREF_KEYSERV);
        if (subpkt) {
            remove_subpkt(subpkt);
        }
        return;
    }

    pgp_sig_subpkt_t &subpkt = add_subpkt(PGP_SIG_SUBPKT_PREF_KEYSERV, uri.size(), true);
    subpkt.parsed = true;
    subpkt.hashed = true;
    memcpy(subpkt.data, uri.data(), uri.size());
    subpkt.fields.preferred_ks.uri = (char *) subpkt.data;
    subpkt.fields.preferred_ks.len = uri.size();
}

uint8_t
pgp_signature_t::trust_level() const
{
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_TRUST);
    return subpkt ? subpkt->fields.trust.level : 0;
}

uint8_t
pgp_signature_t::trust_amount() const
{
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_TRUST);
    return subpkt ? subpkt->fields.trust.amount : 0;
}

void
pgp_signature_t::set_trust(uint8_t level, uint8_t amount)
{
    pgp_sig_subpkt_t &subpkt = add_subpkt(PGP_SIG_SUBPKT_TRUST, 2, true);
    subpkt.parsed = true;
    subpkt.hashed = true;
    subpkt.data[0] = level;
    subpkt.data[1] = amount;
    subpkt.fields.trust.level = level;
    subpkt.fields.trust.amount = amount;
}

bool
pgp_signature_t::revocable() const
{
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_REVOCABLE);
    return subpkt ? subpkt->fields.revocable : true;
}

void
pgp_signature_t::set_revocable(bool status)
{
    pgp_sig_subpkt_t &subpkt = add_subpkt(PGP_SIG_SUBPKT_REVOCABLE, 1, true);
    subpkt.parsed = true;
    subpkt.hashed = true;
    subpkt.data[0] = status;
    subpkt.fields.revocable = status;
}

std::string
pgp_signature_t::revocation_reason() const
{
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_REVOCATION_REASON);
    return subpkt ? std::string(subpkt->fields.revocation_reason.str,
                                subpkt->fields.revocation_reason.len) :
                    "";
}

pgp_revocation_type_t
pgp_signature_t::revocation_code() const
{
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_REVOCATION_REASON);
    return subpkt ? subpkt->fields.revocation_reason.code : PGP_REVOCATION_NO_REASON;
}

void
pgp_signature_t::set_revocation_reason(pgp_revocation_type_t code, const std::string &reason)
{
    size_t            datalen = 1 + reason.size();
    pgp_sig_subpkt_t &subpkt = add_subpkt(PGP_SIG_SUBPKT_REVOCATION_REASON, datalen, true);
    subpkt.hashed = true;
    subpkt.data[0] = code;
    memcpy(subpkt.data + 1, reason.data(), reason.size());

    if (!subpkt.parse()) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }
}

bool
pgp_signature_t::key_has_features(pgp_key_feature_t flags) const
{
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_FEATURES);
    return subpkt ? subpkt->data[0] & flags : false;
}

void
pgp_signature_t::set_key_features(pgp_key_feature_t flags)
{
    pgp_sig_subpkt_t &subpkt = add_subpkt(PGP_SIG_SUBPKT_FEATURES, 1, true);
    subpkt.hashed = true;
    subpkt.data[0] = flags;
    subpkt.fields.features = flags;
    subpkt.parsed = true;
}

std::string
pgp_signature_t::signer_uid() const
{
    const pgp_sig_subpkt_t *subpkt = get_subpkt(PGP_SIG_SUBPKT_SIGNERS_USER_ID);
    return subpkt ? std::string(subpkt->fields.signer.uid, subpkt->fields.signer.len) : "";
}

void
pgp_signature_t::set_signer_uid(const std::string &uid)
{
    pgp_sig_subpkt_t &subpkt = add_subpkt(PGP_SIG_SUBPKT_SIGNERS_USER_ID, uid.size(), true);
    subpkt.hashed = true;
    memcpy(subpkt.data, uid.data(), uid.size());
    subpkt.fields.signer.uid = (const char *) subpkt.data;
    subpkt.fields.signer.len = subpkt.len;
    subpkt.parsed = true;
}

pgp_sig_subpkt_t &
pgp_signature_t::add_subpkt(pgp_sig_subpacket_type_t type, size_t datalen, bool reuse)
{
    if (version < PGP_V4) {
        RNP_LOG("wrong signature version");
        throw std::invalid_argument("version");
    }

    uint8_t *newdata = (uint8_t *) calloc(1, datalen);
    if (!newdata) {
        RNP_LOG("Allocation failed");
        throw std::bad_alloc();
    }

    pgp_sig_subpkt_t *subpkt = NULL;
    if (reuse && (subpkt = get_subpkt(type))) {
        *subpkt = {};
    } else {
        subpkts.push_back({});
        subpkt = &subpkts.back();
    }

    subpkt->data = newdata;
    subpkt->type = type;
    subpkt->len = datalen;
    return *subpkt;
}

void
pgp_signature_t::remove_subpkt(pgp_sig_subpkt_t *subpkt)
{
    for (auto it = subpkts.begin(); it < subpkts.end(); it++) {
        if (&*it == subpkt) {
            subpkts.erase(it);
            return;
        }
    }
}

bool
pgp_signature_t::matches_onepass(const pgp_one_pass_sig_t &onepass) const
{
    if (!has_keyid()) {
        return false;
    }
    return (halg == onepass.halg) && (palg == onepass.palg) && (type_ == onepass.type) &&
           (onepass.keyid == keyid());
}

rnp_result_t
pgp_signature_t::parse_v3(pgp_packet_body_t &pkt)
{
    /* parse v3-specific fields, not the whole signature */
    uint8_t buf[16] = {};
    if (!pkt.get(buf, 16)) {
        RNP_LOG("cannot get enough bytes");
        return RNP_ERROR_BAD_FORMAT;
    }
    /* length of hashed data, 5 */
    if (buf[0] != 5) {
        RNP_LOG("wrong length of hashed data");
        return RNP_ERROR_BAD_FORMAT;
    }
    /* hashed data */
    free(hashed_data);
    if (!(hashed_data = (uint8_t *) malloc(5))) {
        RNP_LOG("allocation failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    memcpy(hashed_data, &buf[1], 5);
    hashed_len = 5;
    /* signature type */
    type_ = (pgp_sig_type_t) buf[1];
    /* creation time */
    creation_time = read_uint32(&buf[2]);
    /* signer's key id */
    static_assert(std::tuple_size<decltype(signer)>::value == PGP_KEY_ID_SIZE,
                  "v3 signer field size mismatch");
    memcpy(signer.data(), &buf[6], PGP_KEY_ID_SIZE);
    /* public key algorithm */
    palg = (pgp_pubkey_alg_t) buf[14];
    /* hash algorithm */
    halg = (pgp_hash_alg_t) buf[15];
    return RNP_SUCCESS;
}

bool
pgp_signature_t::parse_subpackets(uint8_t *buf, size_t len, bool hashed)
{
    bool res = true;

    while (len > 0) {
        if (len < 2) {
            RNP_LOG("got single byte %d", (int) *buf);
            return false;
        }

        /* subpacket length */
        size_t splen;
        if (*buf < 192) {
            splen = *buf;
            buf++;
            len--;
        } else if (*buf < 255) {
            splen = ((buf[0] - 192) << 8) + buf[1] + 192;
            buf += 2;
            len -= 2;
        } else {
            if (len < 5) {
                RNP_LOG("got 4-byte len but only %d bytes in buffer", (int) len);
                return false;
            }
            splen = read_uint32(&buf[1]);
            buf += 5;
            len -= 5;
        }

        if (splen < 1) {
            RNP_LOG("got subpacket with 0 length, skipping");
            continue;
        }

        /* subpacket data */
        if (len < splen) {
            RNP_LOG("got subpacket len %d, while only %d bytes left", (int) splen, (int) len);
            return false;
        }

        pgp_sig_subpkt_t subpkt;
        if (!(subpkt.data = (uint8_t *) malloc(splen - 1))) {
            RNP_LOG("subpacket data allocation failed");
            return false;
        }

        subpkt.type = (pgp_sig_subpacket_type_t)(*buf & 0x7f);
        subpkt.critical = !!(*buf & 0x80);
        subpkt.hashed = hashed;
        subpkt.parsed = 0;
        memcpy(subpkt.data, buf + 1, splen - 1);
        subpkt.len = splen - 1;

        res = res && subpkt.parse();
        subpkts.push_back(std::move(subpkt));
        len -= splen;
        buf += splen;
    }
    return res;
}

rnp_result_t
pgp_signature_t::parse_v4(pgp_packet_body_t &pkt)
{
    /* parse v4-specific fields, not the whole signature */
    uint8_t buf[5];
    if (!pkt.get(buf, 5)) {
        RNP_LOG("cannot get first 5 bytes");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* signature type */
    type_ = (pgp_sig_type_t) buf[0];
    /* public key algorithm */
    palg = (pgp_pubkey_alg_t) buf[1];
    /* hash algorithm */
    halg = (pgp_hash_alg_t) buf[2];
    /* hashed subpackets length */
    uint16_t splen = read_uint16(&buf[3]);
    /* hashed subpackets length + 2 bytes of length of unhashed subpackets */
    if (pkt.left() < (size_t)(splen + 2)) {
        RNP_LOG("wrong packet or hashed subpackets length");
        return RNP_ERROR_BAD_FORMAT;
    }
    /* building hashed data */
    free(hashed_data);
    if (!(hashed_data = (uint8_t *) malloc(splen + 6))) {
        RNP_LOG("allocation failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    hashed_data[0] = version;
    memcpy(hashed_data + 1, buf, 5);

    if (!pkt.get(hashed_data + 6, splen)) {
        RNP_LOG("cannot get hashed subpackets data");
        return RNP_ERROR_BAD_FORMAT;
    }
    hashed_len = splen + 6;
    /* parsing hashed subpackets */
    if (!parse_subpackets(hashed_data + 6, splen, true)) {
        RNP_LOG("failed to parse hashed subpackets");
        return RNP_ERROR_BAD_FORMAT;
    }
    /* reading unhashed subpackets */
    if (!pkt.get(splen)) {
        RNP_LOG("cannot get unhashed len");
        return RNP_ERROR_BAD_FORMAT;
    }
    if (pkt.left() < splen) {
        RNP_LOG("not enough data for unhashed subpackets");
        return RNP_ERROR_BAD_FORMAT;
    }
    std::vector<uint8_t> spbuf(splen);
    if (!pkt.get(spbuf.data(), splen)) {
        RNP_LOG("read of unhashed subpackets failed");
        return RNP_ERROR_READ;
    }
    if (!parse_subpackets(spbuf.data(), splen, false)) {
        RNP_LOG("failed to parse unhashed subpackets");
        return RNP_ERROR_BAD_FORMAT;
    }
    return RNP_SUCCESS;
}

rnp_result_t
pgp_signature_t::parse(pgp_packet_body_t &pkt)
{
    uint8_t ver = 0;
    if (!pkt.get(ver)) {
        return RNP_ERROR_BAD_FORMAT;
    }
    version = (pgp_version_t) ver;

    /* v3 or v4 signature body */
    rnp_result_t res;
    if ((ver == PGP_V2) || (ver == PGP_V3)) {
        res = parse_v3(pkt);
    } else if (ver == PGP_V4) {
        res = parse_v4(pkt);
    } else {
        RNP_LOG("unknown signature version: %d", (int) ver);
        res = RNP_ERROR_BAD_FORMAT;
    }

    if (res) {
        return res;
    }

    /* left 16 bits of the hash */
    if (!pkt.get(lbits, 2)) {
        RNP_LOG("not enough data for hash left bits");
        return RNP_ERROR_BAD_FORMAT;
    }
    /* raw signature material */
    material_len = pkt.left();
    if (!material_len) {
        RNP_LOG("No signature material");
        return RNP_ERROR_BAD_FORMAT;
    }
    material_buf = (uint8_t *) malloc(material_len);
    if (!material_buf) {
        RNP_LOG("Allocation failed");
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    /* we cannot fail here */
    pkt.get(material_buf, material_len);
    /* check whether it can be parsed */
    pgp_signature_material_t material = {};
    if (!parse_material(material)) {
        return RNP_ERROR_BAD_FORMAT;
    }
    return RNP_SUCCESS;
}

rnp_result_t
pgp_signature_t::parse(pgp_source_t &src)
{
    pgp_packet_body_t pkt(PGP_PKT_SIGNATURE);
    rnp_result_t      res = pkt.read(src);
    if (res) {
        return res;
    }
    return parse(pkt);
}

bool
pgp_signature_t::parse_material(pgp_signature_material_t &material) const
{
    pgp_packet_body_t pkt(material_buf, material_len);

    switch (palg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_SIGN_ONLY:
        if (!pkt.get(material.rsa.s)) {
            return false;
        }
        break;
    case PGP_PKA_DSA:
        if (!pkt.get(material.dsa.r) || !pkt.get(material.dsa.s)) {
            return false;
        }
        break;
    case PGP_PKA_EDDSA:
        if (version < PGP_V4) {
            RNP_LOG("Warning! v3 EdDSA signature.");
        }
        /* FALLTHROUGH */
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        if (!pkt.get(material.ecc.r) || !pkt.get(material.ecc.s)) {
            return false;
        }
        break;
    case PGP_PKA_ELGAMAL: /* we support reading it but will not validate */
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        if (!pkt.get(material.eg.r) || !pkt.get(material.eg.s)) {
            return false;
        }
        break;
    default:
        RNP_LOG("Unknown pk algorithm : %d", (int) palg);
        return false;
    }

    if (pkt.left()) {
        RNP_LOG("extra %d bytes in signature packet", (int) pkt.left());
        return false;
    }
    return true;
}

void
pgp_signature_t::write(pgp_dest_t &dst) const
{
    if ((version < PGP_V2) || (version > PGP_V4)) {
        RNP_LOG("don't know version %d", (int) version);
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    pgp_packet_body_t pktbody(PGP_PKT_SIGNATURE);

    if (version < PGP_V4) {
        /* for v3 signatures hashed data includes only type + creation_time */
        pktbody.add_byte(version);
        pktbody.add_byte(hashed_len);
        pktbody.add(hashed_data, hashed_len);
        pktbody.add(signer);
        pktbody.add_byte(palg);
        pktbody.add_byte(halg);
    } else {
        /* for v4 sig->hashed_data must contain most of signature fields */
        pktbody.add(hashed_data, hashed_len);
        pktbody.add_subpackets(*this, false);
    }
    pktbody.add(lbits, 2);
    /* write mpis */
    pktbody.add(material_buf, material_len);
    pktbody.write(dst);
}

void
pgp_signature_t::write_material(const pgp_signature_material_t &material)
{
    pgp_packet_body_t pktbody(PGP_PKT_SIGNATURE);
    switch (palg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_SIGN_ONLY:
        pktbody.add(material.rsa.s);
        break;
    case PGP_PKA_DSA:
        pktbody.add(material.dsa.r);
        pktbody.add(material.dsa.s);
        break;
    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        pktbody.add(material.ecc.r);
        pktbody.add(material.ecc.s);
        break;
    case PGP_PKA_ELGAMAL: /* we support writing it but will not generate */
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        pktbody.add(material.eg.r);
        pktbody.add(material.eg.s);
        break;
    default:
        RNP_LOG("Unknown pk algorithm : %d", (int) palg);
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    free(material_buf);
    material_buf = (uint8_t *) malloc(pktbody.size());
    if (!material_buf) {
        RNP_LOG("allocation failed");
        throw rnp::rnp_exception(RNP_ERROR_OUT_OF_MEMORY);
    }
    memcpy(material_buf, pktbody.data(), pktbody.size());
    material_len = pktbody.size();
}
