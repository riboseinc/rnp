/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: keyring.c,v 1.50 2011/06/25 00:37:44 agc Exp $");
#endif

#include <stdlib.h>
#include <string.h>

#include <rnp/rnp_sdk.h>
#include <librepgp/packet-show.h>
#include <librepgp/reader.h>
#include <librepgp/stream-common.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-packet.h>
#include <librepgp/stream-key.h>
#include <librepgp/stream-armor.h>

#include "types.h"
#include "key_store_pgp.h"
#include "pgp-key.h"
#include "utils.h"

void print_packet_hex(const pgp_rawpacket_t *pkt);

/* used to point to data during keyring read */
typedef struct keyringcb_t {
    rnp_key_store_t *         keyring; /* the keyring we're reading */
    pgp_io_t *                io;
    pgp_key_t                 key; /* the key we're currently loading */
    const pgp_key_provider_t *key_provider;
} keyringcb_t;

#define SUBSIG_REQUIRED_BEFORE(str)                                 \
    do {                                                            \
        if (!(subsig)) {                                            \
            RNP_LOG("Signature packet expected before %s.", (str)); \
            PGP_ERROR_1(cbinfo->errors,                             \
                        PGP_E_R_BAD_FORMAT,                         \
                        "Signature packet expected before %s.",     \
                        (str));                                     \
            return PGP_FINISHED;                                    \
        }                                                           \
    } while (0)

static pgp_cb_ret_t
parse_key_attributes(pgp_key_t *key, const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    const pgp_contents_t *content = &pkt->u;

    // bail early if errors have already occurred
    if (cbinfo->errors && *cbinfo->errors) {
        // TODO: no way to tell the parser to stop
        return PGP_RELEASE_MEMORY;
    }

    // handle these earlier, since they don't actually
    // require a key
    switch (pkt->tag) {
    case PGP_PARSER_DONE:
    case PGP_PARSER_PTAG:
        return PGP_RELEASE_MEMORY;
    case PGP_PARSER_ERROR:
        // these will be printed out later
        PGP_ERROR_1(cbinfo->errors, PGP_E_FAIL, "%s", content->error);
        return PGP_RELEASE_MEMORY;
    default:
        // handle everything else below
        break;
    }

    // we should definitely have a key at this point
    if (!key) {
        PGP_ERROR(cbinfo->errors, PGP_E_R_BAD_FORMAT, "Key packet missing.");
        return PGP_FINISHED;
    }

    pgp_subsig_t *subsig = key->subsigc ? &key->subsigs[key->subsigc - 1] : NULL;
    switch (pkt->tag) {
    case PGP_PTAG_CT_USER_ID:
        if (!pgp_add_userid(key, content->userid)) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to add userid to key.");
            return PGP_FINISHED;
        }
        break;
    case PGP_PARSER_PACKET_END:
        EXPAND_ARRAY(key, packet);
        if (!key->packets) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
            return PGP_RELEASE_MEMORY;
        }
        key->packets[key->packetc++] = content->packet;
        return PGP_KEEP_MEMORY;
    case PGP_PARSER_ERROR:
        RNP_LOG("Error: %s", content->error);
        return PGP_FINISHED;
    case PGP_PARSER_ERRCODE:
        RNP_LOG("parse error: %s", pgp_errcode(content->errcode.errcode));
        break;
    case PGP_PTAG_CT_SIGNATURE: {
        EXPAND_ARRAY(key, subsig);
        if (key->subsigs == NULL) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
            return PGP_FINISHED;
        }
        subsig = &key->subsigs[key->subsigc++];
        subsig->uid = key->uidc - 1;
        subsig->sig = content->sig;

        if (signature_has_key_expiration(&subsig->sig)) {
            key->expiration = signature_get_key_expiration(&subsig->sig);
        }
        if (signature_has_trust(&subsig->sig)) {
            signature_get_trust(&subsig->sig, &subsig->trustlevel, &subsig->trustamount);
        }
        if (signature_get_primary_uid(&subsig->sig)) {
            key->uid0 = key->uidc - 1;
            key->uid0_set = 1;
        }
        uint8_t *         algs = NULL;
        size_t            count = 0;
        pgp_user_prefs_t *prefs = &subsig->prefs;

        if (signature_get_preferred_symm_algs(&subsig->sig, &algs, &count)) {
            for (size_t i = 0; i < count; i++) {
                EXPAND_ARRAY(prefs, symm_alg);
                if (!prefs->symm_algs) {
                    PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
                    return PGP_FINISHED;
                }
                prefs->symm_algs[i] = algs[i];
                prefs->symm_algc++;
            }
        }
        if (signature_get_preferred_hash_algs(&subsig->sig, &algs, &count)) {
            for (size_t i = 0; i < count; i++) {
                EXPAND_ARRAY(prefs, hash_alg);
                if (!prefs->hash_algs) {
                    PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
                    return PGP_FINISHED;
                }
                prefs->hash_algs[i] = algs[i];
                prefs->hash_algc++;
            }
        }
        if (signature_get_preferred_z_algs(&subsig->sig, &algs, &count)) {
            for (size_t i = 0; i < count; i++) {
                EXPAND_ARRAY(prefs, compress_alg);
                if (!prefs->compress_algs) {
                    PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
                    return PGP_FINISHED;
                }
                prefs->compress_algs[i] = algs[i];
                prefs->compress_algc++;
            }
        }
        if (signature_has_key_flags(&subsig->sig)) {
            subsig->key_flags = signature_get_key_flags(&subsig->sig);
            key->key_flags = subsig->key_flags;
        }
        if (signature_has_key_server_prefs(&subsig->sig)) {
            EXPAND_ARRAY(prefs, key_server_pref);
            if (!prefs->key_server_prefs) {
                PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
                return PGP_FINISHED;
            }
            subsig->prefs.key_server_prefs[0] = signature_get_key_server_prefs(&subsig->sig);
            subsig->prefs.key_server_prefc++;
        }
        if (signature_has_key_server(&subsig->sig)) {
            subsig->prefs.key_server = (uint8_t *) signature_get_key_server(&subsig->sig);
        }
        if (signature_has_revocation_reason(&subsig->sig)) {
            /* not sure whether this logic is correct - we should check signature type? */
            pgp_revoke_t *revocation = NULL;
            if (key->uidc == 0) {
                /* revoke whole key */
                key->revoked = 1;
                revocation = &key->revocation;
            } else {
                /* revoke the user id */
                EXPAND_ARRAY(key, revoke);
                if (key->revokes == NULL) {
                    PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
                    return PGP_FINISHED;
                }
                revocation = &key->revokes[key->revokec];
                key->revokes[key->revokec].uid = key->uidc - 1;
                key->revokec += 1;
            }
            signature_get_revocation_reason(
              &subsig->sig, &revocation->code, &revocation->reason);
            if (!strlen(revocation->reason)) {
                free(revocation->reason);
                revocation->reason = rnp_strdup(pgp_show_ss_rr_code(revocation->code));
            }
        }
        return PGP_KEEP_MEMORY;
    }
    case PGP_PTAG_CT_TRUST:
        // valid, but not currently used
        break;
    default:
        PGP_ERROR_1(cbinfo->errors, PGP_E_FAIL, "Unexpected tag 0x%02x", pkt->tag);
        break;
    }
    return PGP_RELEASE_MEMORY;
}

static pgp_cb_ret_t
cb_keyattrs_parse(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    pgp_key_t *key = (pgp_key_t *) pgp_callback_arg(cbinfo);
    return parse_key_attributes(key, pkt, cbinfo);
}

bool
pgp_parse_key_attrs(pgp_key_t *key, const uint8_t *data, size_t data_len)
{
    pgp_stream_t *stream = NULL;
    bool          ret = false;

    stream = (pgp_stream_t *) pgp_new(sizeof(*stream));
    if (!stream) {
        goto done;
    }
    if (!pgp_reader_set_memory(stream, data, data_len)) {
        goto done;
    }
    pgp_set_callback(stream, cb_keyattrs_parse, key);
    stream->readinfo.accumulate = 1;
    ret = repgp_parse(stream, 0);
    pgp_print_errors(stream->errors);

done:
    pgp_stream_delete(stream);
    return ret;
}

static bool
finish_loading_key(keyringcb_t *cb, pgp_cbdata_t *cbinfo)
{
    if (pgp_key_is_subkey(&cb->key)) {
        pgp_key_t *primary =
          pgp_get_primary_key_for(cb->io, &cb->key, cb->keyring, cb->key_provider);
        if (!primary) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Subkey missing primary key.");
            return false;
        }
        cb->key.primary_grip = (uint8_t *) malloc(PGP_FINGERPRINT_SIZE);
        if (!cb->key.primary_grip) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Alloc failed");
            return PGP_FINISHED;
        }
        memcpy(cb->key.primary_grip, primary->grip, PGP_FINGERPRINT_SIZE);
        if (!list_append(&primary->subkey_grips, cb->key.grip, PGP_FINGERPRINT_SIZE)) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Alloc failed");
            return PGP_FINISHED;
        }
    }
    if (!rnp_key_store_add_key(cb->io, cb->keyring, &cb->key)) {
        PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to add key to key store.");
        return false;
    }
    cb->key = (pgp_key_t){0};
    return true;
}

static pgp_cb_ret_t
cb_keyring_parse(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    const pgp_contents_t *content = &pkt->u;
    keyringcb_t *         cb;

    cb = (keyringcb_t *) pgp_callback_arg(cbinfo);

    switch (pkt->tag) {
    case PGP_PTAG_CT_SECRET_KEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
        // finish up with previous key (if any)
        if (pgp_get_key_type(&cb->key)) {
            if (!finish_loading_key(cb, cbinfo)) {
                return PGP_FINISHED;
            }
        }
        // start to process the new key
        if (!pgp_key_from_keypkt(&cb->key, &content->key, pkt->tag)) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to create key from keydata.");
            return PGP_FINISHED;
        }
        cb->key.format = GPG_KEY_STORE;
        // Set some default key flags which will be overridden by signature
        // subpackets for V4 keys.
        cb->key.key_flags = pgp_pk_alg_capabilities(pgp_get_key_pkt(&cb->key)->alg);
        return PGP_KEEP_MEMORY;
    case PGP_PARSER_DONE:
        // finish up with previous key (if any)
        if (pgp_get_key_type(&cb->key)) {
            if (!finish_loading_key(cb, cbinfo)) {
                return PGP_FINISHED;
            }
        }
        break;
    default:
        return parse_key_attributes(&cb->key, pkt, cbinfo);
    }
    return PGP_RELEASE_MEMORY;
}

static bool
rnp_key_add_stream_rawpacket(pgp_key_t *key, int tag, pgp_dest_t *memdst)
{
    pgp_rawpacket_t rawpkt = {};
    EXPAND_ARRAY(key, packet);
    if (!key->packets) {
        RNP_LOG("Failed to expand packet array.");
        dst_close(memdst, true);
        return false;
    }

    rawpkt.tag = (pgp_content_enum) tag;
    rawpkt.length = memdst->writeb;
    rawpkt.raw = (uint8_t*) mem_dest_own_memory(memdst);
    key->packets[key->packetc++] = rawpkt;

    dst_close(memdst, false);
    return true;
}

static bool
rnp_key_add_key_rawpacket(pgp_key_t *key, pgp_key_pkt_t *pkt)
{
    pgp_dest_t dst = {};

    if (init_mem_dest(&dst, NULL, 0)) {
        return false;
    }

    if (!stream_write_key(pkt, &dst)) {
        dst_close(&dst, true);
        return false;
    }

    return rnp_key_add_stream_rawpacket(key, pkt->tag, &dst);
}

static bool
rnp_key_add_sig_rawpacket(pgp_key_t *key, pgp_signature_t *pkt)
{
    pgp_dest_t dst = {};

    if (init_mem_dest(&dst, NULL, 0)) {
        return false;
    }

    if (!stream_write_signature(pkt, &dst)) {
        dst_close(&dst, true);
        return false;
    }

    return rnp_key_add_stream_rawpacket(key, PGP_PTAG_CT_SIGNATURE, &dst);
}

static bool
rnp_key_add_uid_rawpacket(pgp_key_t *key, pgp_userid_pkt_t *pkt)
{
    pgp_dest_t dst = {};

    if (init_mem_dest(&dst, NULL, 0)) {
        return false;
    }

    if (!stream_write_userid(pkt, &dst)) {
        dst_close(&dst, true);
        return false;
    }

    return rnp_key_add_stream_rawpacket(key, pkt->tag, &dst);
}

static bool
create_key_from_pkt(pgp_key_t *key, pgp_key_pkt_t *pkt)
{
    pgp_key_pkt_t keypkt = {};

    memset(key, 0, sizeof(*key));

    if (!copy_key_pkt(&keypkt, pkt)) {
        RNP_LOG("failed to copy key packet");
        return false;
    }

    /* parse secret key if not encrypted */
    if (is_secret_key_pkt(keypkt.tag)) {
        bool cleartext = keypkt.sec_protection.s2k.usage == PGP_S2KU_NONE;
        if (cleartext && decrypt_secret_key(&keypkt, NULL)) {
            RNP_LOG("failed to setup key fields");
            free_key_pkt(&keypkt);
            return false;
        }
    }

    /* this call transfers ownership */
    if (!pgp_key_from_keypkt(key, &keypkt, (pgp_content_enum) pkt->tag)) {
        RNP_LOG("failed to setup key fields");
        free_key_pkt(&keypkt);
        return false;
    }

    /* add key rawpacket */
    if (!rnp_key_add_key_rawpacket(key, pkt)) {
        free_key_pkt(&keypkt);
        return false;
    }

    key->format = GPG_KEY_STORE;
    key->key_flags = pgp_pk_alg_capabilities(pgp_get_key_pkt(key)->alg);
    return true;
}

static bool
rnp_key_add_signature(pgp_key_t *key, pgp_signature_t *sig)
{
    pgp_subsig_t *subsig = NULL;

    EXPAND_ARRAY(key, subsig);
    if (key->subsigs == NULL) {
        RNP_LOG("Failed to expand signature array.");
        return false;
    }

    /* add signature rawpacket */
    if (!rnp_key_add_sig_rawpacket(key, sig)) {
        return false;
    }

    subsig = &key->subsigs[key->subsigc++];
    subsig->uid = key->uidc - 1;
    if (!copy_signature_packet(&subsig->sig, sig)) {
        return false;
    }

    if (signature_has_key_expiration(&subsig->sig)) {
        key->expiration = signature_get_key_expiration(&subsig->sig);
    }
    if (signature_has_trust(&subsig->sig)) {
        signature_get_trust(&subsig->sig, &subsig->trustlevel, &subsig->trustamount);
    }
    if (signature_get_primary_uid(&subsig->sig)) {
        key->uid0 = key->uidc - 1;
        key->uid0_set = 1;
    }

    uint8_t *         algs = NULL;
    size_t            count = 0;
    pgp_user_prefs_t *prefs = &subsig->prefs;

    if (signature_get_preferred_symm_algs(&subsig->sig, &algs, &count)) {
        for (size_t i = 0; i < count; i++) {
            EXPAND_ARRAY(prefs, symm_alg);
            if (!prefs->symm_algs) {
                RNP_LOG("Failed to expand symm array.");
                return false;
            }
            prefs->symm_algs[i] = algs[i];
            prefs->symm_algc++;
        }
    }
    if (signature_get_preferred_hash_algs(&subsig->sig, &algs, &count)) {
        for (size_t i = 0; i < count; i++) {
            EXPAND_ARRAY(prefs, hash_alg);
            if (!prefs->hash_algs) {
                RNP_LOG("Failed to expand hash array.");
                return false;
            }
            prefs->hash_algs[i] = algs[i];
            prefs->hash_algc++;
        }
    }
    if (signature_get_preferred_z_algs(&subsig->sig, &algs, &count)) {
        for (size_t i = 0; i < count; i++) {
            EXPAND_ARRAY(prefs, compress_alg);
            if (!prefs->compress_algs) {
                RNP_LOG("Failed to expand z array.");
                return PGP_FINISHED;
            }
            prefs->compress_algs[i] = algs[i];
            prefs->compress_algc++;
        }
    }
    if (signature_has_key_flags(&subsig->sig)) {
        subsig->key_flags = signature_get_key_flags(&subsig->sig);
        key->key_flags = subsig->key_flags;
    }
    if (signature_has_key_server_prefs(&subsig->sig)) {
        EXPAND_ARRAY(prefs, key_server_pref);
        if (!prefs->key_server_prefs) {
            RNP_LOG("Failed to expand key serv prefs array.");
            return PGP_FINISHED;
        }
        subsig->prefs.key_server_prefs[0] = signature_get_key_server_prefs(&subsig->sig);
        subsig->prefs.key_server_prefc++;
    }
    if (signature_has_key_server(&subsig->sig)) {
        subsig->prefs.key_server = (uint8_t *) signature_get_key_server(&subsig->sig);
    }
    if (signature_has_revocation_reason(&subsig->sig)) {
        /* not sure whether this logic is correct - we should check signature type? */
        pgp_revoke_t *revocation = NULL;
        if (key->uidc == 0) {
            /* revoke whole key */
            key->revoked = 1;
            revocation = &key->revocation;
        } else {
            /* revoke the user id */
            EXPAND_ARRAY(key, revoke);
            if (key->revokes == NULL) {
                RNP_LOG("Failed to expand revoke array.");
                return PGP_FINISHED;
            }
            revocation = &key->revokes[key->revokec];
            key->revokes[key->revokec].uid = key->uidc - 1;
            key->revokec += 1;
        }
        signature_get_revocation_reason(&subsig->sig, &revocation->code, &revocation->reason);
        if (!strlen(revocation->reason)) {
            free(revocation->reason);
            revocation->reason = rnp_strdup(pgp_show_ss_rr_code(revocation->code));
        }
    }

    return true;
}

static bool
rnp_key_add_signatures(pgp_key_t *key, list signatures)
{
    for (list_item *sig = list_front(signatures); sig; sig = list_next(sig)) {
        if (!rnp_key_add_signature(key, (pgp_signature_t *) sig)) {
            return false;
        }
    }
    return true;
}

bool
rnp_key_store_add_transferable_subkey(rnp_key_store_t *          keyring,
                                      pgp_transferable_subkey_t *tskey,
                                      pgp_key_t *                pkey)
{
    pgp_key_t skey = {};
    pgp_io_t  io = {.outs = stdout, .errs = stderr, .res = stdout};

    /* create key */
    if (!create_key_from_pkt(&skey, &tskey->subkey)) {
        return false;
    }

    /* add subkey binding signatures */
    if (!rnp_key_add_signatures(&skey, tskey->signatures)) {
        RNP_LOG("failed to add subkey signatures");
        goto error;
    }

    skey.primary_grip = (uint8_t*) malloc(PGP_FINGERPRINT_SIZE);
    if (!skey.primary_grip) {
        RNP_LOG("alloc failed");
        goto error;
    }
    memcpy(skey.primary_grip, pkey->grip, PGP_FINGERPRINT_SIZE);
    if (!list_append(&pkey->subkey_grips, skey.grip, PGP_FINGERPRINT_SIZE)) {
        RNP_LOG("failed to add subkey grip");
        goto error;
    }

    if (!rnp_key_store_add_key(&io, keyring, &skey)) {
        RNP_LOG("Failed to add subkey to key store.");
        goto error;
    }

    return true;
error:
    pgp_key_free_data(&skey);
    return false;
}

bool
rnp_key_store_add_transferable_key(rnp_key_store_t *keyring, pgp_transferable_key_t *tkey)
{
    pgp_key_t  key = {};
    pgp_key_t *addkey = NULL;
    pgp_io_t   io = {.outs = stdout, .errs = stderr, .res = stdout};

    /* create key */
    if (!create_key_from_pkt(&key, &tkey->key)) {
        return false;
    }

    /* add direct-key signatures */
    if (!rnp_key_add_signatures(&key, tkey->signatures)) {
        goto error;
    }

    /* add userids and their signatures */
    for (list_item *uid = list_front(tkey->userids); uid; uid = list_next(uid)) {
        pgp_transferable_userid_t *tuid = (pgp_transferable_userid_t *) uid;
        uint8_t *                  uidz;

        if (!rnp_key_add_uid_rawpacket(&key, &tuid->uid)) {
            goto error;
        }

        if (!(uidz = (uint8_t*) calloc(1, tuid->uid.uid_len + 1))) {
            RNP_LOG("uid alloc failed");
            goto error;
        }

        memcpy(uidz, tuid->uid.uid, tuid->uid.uid_len);
        uidz[tuid->uid.uid_len] = 0;
        if (!pgp_add_userid(&key, uidz)) {
            RNP_LOG("failed to add user id");
            free(uidz);
            goto error;
        }
        free(uidz);
        if (!rnp_key_add_signatures(&key, tuid->signatures)) {
            goto error;
        }
    }

    /* add key to the storage before subkeys */
    if (!(addkey = rnp_key_store_add_key(&io, keyring, &key))) {
        RNP_LOG("Failed to add key to key store.");
        goto error;
    }

    /* add subkeys */
    for (list_item *skey = list_front(tkey->subkeys); skey; skey = list_next(skey)) {
        pgp_transferable_subkey_t *subkey = (pgp_transferable_subkey_t *) skey;
        if (!rnp_key_store_add_transferable_subkey(keyring, subkey, addkey)) {
            goto error;
        }
    }

    return true;
error:
    if (addkey) {
        /* during key addition all fields are copied so will be cleaned below */
        rnp_key_store_remove_key(&io, keyring, addkey);
        pgp_key_free_data(addkey);
    } else {
        pgp_key_free_data(&key);
    }
    return false;
}

rnp_result_t
rnp_key_store_pgp_read_from_src(rnp_key_store_t *keyring, pgp_source_t *src)
{
    pgp_key_sequence_t keys = {};
    rnp_result_t       ret = RNP_ERROR_GENERIC;

    if ((ret = process_pgp_keys(src, &keys))) {
        return ret;
    }

    for (list_item *key = list_front(keys.keys); key; key = list_next(key)) {
        if (!rnp_key_store_add_transferable_key(keyring, (pgp_transferable_key_t *) key)) {
            ret = RNP_ERROR_BAD_STATE;
            goto done;
        }
    }

    ret = RNP_SUCCESS;
done:
    key_sequence_destroy(&keys);
    return ret;
}

bool
rnp_key_store_pgp_read_from_mem(pgp_io_t *                io,
                                rnp_key_store_t *         keyring,
                                pgp_memory_t *            mem,
                                const pgp_key_provider_t *key_provider)
{
    pgp_source_t src = {};
    bool         res = false;

    if (init_mem_src(&src, mem->buf, mem->length, false)) {
        return false;
    }

    res = !rnp_key_store_pgp_read_from_src(keyring, &src);

    src_close(&src);
    return res;
}

static bool
pgp_key_write_packets_stream(const pgp_key_t *key, pgp_dest_t *dst)
{
    if (DYNARRAY_IS_EMPTY(key, packet)) {
        return false;
    }
    for (unsigned i = 0; i < key->packetc; i++) {
        pgp_rawpacket_t *pkt = &key->packets[i];
        if (!pkt->raw || !pkt->length) {
            return false;
        }
        dst_write(dst, pkt->raw, pkt->length);
    }
    return !dst->werr;
}

static bool
do_write(rnp_key_store_t *key_store, pgp_dest_t *dst, bool secret)
{
    pgp_key_search_t search;
    for (list_item *key_item = list_front(key_store->keys); key_item;
         key_item = list_next(key_item)) {
        pgp_key_t *key = (pgp_key_t *) key_item;
        if (pgp_is_key_secret(key) != secret) {
            continue;
        }
        // skip subkeys, they are written below (orphans are ignored)
        if (!pgp_key_is_primary_key(key)) {
            continue;
        }

        if (key->format != GPG_KEY_STORE) {
            RNP_LOG("incorrect format (conversions not supported): %d", key->format);
            return false;
        }
        if (!pgp_key_write_packets_stream(key, dst)) {
            return false;
        }
        for (list_item *subkey_grip = list_front(key->subkey_grips); subkey_grip;
             subkey_grip = list_next(subkey_grip)) {
            search.type = PGP_KEY_SEARCH_GRIP;
            memcpy(search.by.grip, (uint8_t *) subkey_grip, PGP_FINGERPRINT_SIZE);
            pgp_key_t *subkey = NULL;
            for (list_item *subkey_item = list_front(key_store->keys); subkey_item;
                 subkey_item = list_next(subkey_item)) {
                pgp_key_t *candidate = (pgp_key_t *) subkey_item;
                if (pgp_is_key_secret(candidate) != secret) {
                    continue;
                }
                if (rnp_key_matches_search(candidate, &search)) {
                    subkey = candidate;
                    break;
                }
            }
            if (!subkey) {
                RNP_LOG("Missing subkey");
                continue;
            }
            if (!pgp_key_write_packets_stream(subkey, dst)) {
                return false;
            }
        }
    }
    return true;
}

bool
rnp_key_store_pgp_write_to_dst(rnp_key_store_t *key_store, bool armor, pgp_dest_t *dst)
{
    pgp_dest_t armordst;
    bool       res = false;

    if (armor) {
        pgp_armored_msg_t type = PGP_ARMORED_PUBLIC_KEY;
        if (list_length(key_store->keys) &&
            pgp_is_key_secret((pgp_key_t *) list_front(key_store->keys))) {
            type = PGP_ARMORED_SECRET_KEY;
        }
        if (init_armored_dst(&armordst, dst, type)) {
            return false;
        }
        dst = &armordst;
    }
    // two separate passes (public keys, then secret keys)
    res = do_write(key_store, dst, false) && do_write(key_store, dst, true);

    if (armor) {
        dst_close(&armordst, !res);
    }

    return res;
}

bool
rnp_key_store_pgp_write_to_mem(pgp_io_t *       io,
                               rnp_key_store_t *key_store,
                               bool             armor,
                               pgp_memory_t *   mem)
{
    pgp_dest_t   dst = {};
    bool         res = false;
    pgp_output_t output = {};

    if (init_mem_dest(&dst, NULL, 0)) {
        return false;
    }

    res = rnp_key_store_pgp_write_to_dst(key_store, armor, &dst);

    if (!res) {
        goto done;
    }

    pgp_writer_set_memory(&output, mem);
    res = pgp_write(&output, mem_dest_get_memory(&dst), dst.writeb);
    if (!pgp_writer_close(&output)) {
        res = false;
    }
    pgp_writer_info_delete(&output.writer);
done:
    dst_close(&dst, true);
    return res;
}
