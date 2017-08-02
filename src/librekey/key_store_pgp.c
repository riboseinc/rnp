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

#include "types.h"
#include "key_store_pgp.h"
#include "signature.h"
#include "packet-show.h"
#include "readerwriter.h"
#include "pgp-key.h"

void print_packet_hex(const pgp_rawpacket_t *pkt);

/* used to point to data during keyring read */
typedef struct keyringcb_t {
    rnp_key_store_t *keyring; /* the keyring we're reading */
    pgp_io_t *       io;
    pgp_key_t *      key;    /* the key we're currently loading */
    pgp_subsig_t *   subsig; /* the signature we're currently loading */
} keyringcb_t;

#define KEY_REQUIRED_BEFORE(str)                                                            \
    do {                                                                                    \
        if (!(key)) {                                                                       \
            RNP_LOG("Key packet expected before %s.", (str));                               \
            PGP_ERROR_1(                                                                    \
              cbinfo->errors, PGP_E_R_BAD_FORMAT, "Key packet expected before %s.", (str)); \
            return PGP_FINISHED;                                                            \
        }                                                                                   \
    } while (0)

#define SUBSIG_REQUIRED_BEFORE(str)                                 \
    do {                                                            \
        KEY_REQUIRED_BEFORE((str));                                 \
        if (!(key->subsigc) || !(subsig)) {                         \
            RNP_LOG("Signature packet expected before %s.", (str)); \
            PGP_ERROR_1(cbinfo->errors,                             \
                        PGP_E_R_BAD_FORMAT,                         \
                        "Signature packet expected before %s.",     \
                        (str));                                     \
            return PGP_FINISHED;                                    \
        }                                                           \
    } while (0)

static pgp_cb_ret_t
cb_keyring_read(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    const pgp_contents_t *content = &pkt->u;
    rnp_key_store_t *     keyring;
    pgp_revoke_t *        revocation;
    keyringcb_t *         cb;
    pgp_io_t *            io;
    pgp_key_t *           key;
    pgp_subsig_t *        subsig;
    pgp_keydata_key_t     keydata;

    cb = pgp_callback_arg(cbinfo);
    keyring = cb->keyring;
    io = cb->io;
    key = cb->key;
    subsig = cb->subsig;

    switch (pkt->tag) {
    case PGP_PTAG_CT_SECRET_KEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
    case PGP_PTAG_CT_ENCRYPTED_SECRET_KEY:
    case PGP_PTAG_CT_ENCRYPTED_SECRET_SUBKEY:
        keydata.seckey = content->seckey;
        if (!rnp_key_store_add_keydata(io, keyring, &keydata, &cb->key, pkt->tag)) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to add keydata to key store.");
            return PGP_FINISHED;
        }
        cb->subsig = NULL;
        return PGP_KEEP_MEMORY;
    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
        keydata.pubkey = content->pubkey;
        if (!rnp_key_store_add_keydata(io, keyring, &keydata, &cb->key, pkt->tag)) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to add keydata to key store.");
            return PGP_FINISHED;
        }
        cb->subsig = NULL;
        return PGP_KEEP_MEMORY;
    case PGP_PTAG_CT_USER_ID:
        KEY_REQUIRED_BEFORE("userid");
        if (!pgp_add_userid(key, content->userid)) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to add userid to key.");
            return PGP_FINISHED;
        }
        break;
    case PGP_PARSER_PACKET_END:
        KEY_REQUIRED_BEFORE("raw packet");
        // TODO: pgp_add_rawpacket allocates and copies the data, which we could probably
        // avoid and just use PGP_KEEP_MEMORY.
        if (!pgp_add_rawpacket(key, &content->packet)) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to add raw packet to key.");
            return PGP_FINISHED;
        }
        break;
    case PGP_PARSER_ERROR:
        RNP_LOG("Error: %s\n", content->error);
        return PGP_FINISHED;
    case PGP_PARSER_ERRCODE:
        RNP_LOG("parse error: %s\n", pgp_errcode(content->errcode.errcode));
        break;
    case PGP_PTAG_CT_SIGNATURE_HEADER:
    case PGP_PTAG_CT_SIGNATURE:
        KEY_REQUIRED_BEFORE("signature");
        EXPAND_ARRAY(key, subsig);
        if (key->subsigs == NULL) {
            PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
            return PGP_FINISHED;
        }
        subsig = cb->subsig = &key->subsigs[key->subsigc];
        subsig->uid = key->uidc - 1;
        memcpy(&subsig->sig, &pkt->u.sig, sizeof(pkt->u.sig));
        key->subsigc++;
        return PGP_KEEP_MEMORY;
    case PGP_PTAG_SS_TRUST:
        SUBSIG_REQUIRED_BEFORE("ss trust");
        subsig->trustlevel = pkt->u.ss_trust.level;
        subsig->trustamount = pkt->u.ss_trust.amount;
        break;
    case PGP_PTAG_SS_KEY_EXPIRY:
        KEY_REQUIRED_BEFORE("ss key expiry");
        key->key.pubkey.duration = pkt->u.ss_time;
        break;
    case PGP_PTAG_SS_ISSUER_KEY_ID:
        SUBSIG_REQUIRED_BEFORE("ss issuer key id");
        memcpy(&subsig->sig.info.signer_id, pkt->u.ss_issuer, sizeof(pkt->u.ss_issuer));
        subsig->sig.info.signer_id_set = 1;
        break;
    case PGP_PTAG_SS_CREATION_TIME:
        SUBSIG_REQUIRED_BEFORE("ss creation time");
        subsig->sig.info.birthtime = pkt->u.ss_time;
        subsig->sig.info.birthtime_set = 1;
        break;
    case PGP_PTAG_SS_EXPIRATION_TIME:
        SUBSIG_REQUIRED_BEFORE("ss expiration time");
        subsig->sig.info.duration = pkt->u.ss_time;
        subsig->sig.info.duration_set = 1;
        break;
    case PGP_PTAG_SS_PRIMARY_USER_ID:
        KEY_REQUIRED_BEFORE("ss primary userid");
        key->uid0 = key->uidc - 1;
        break;
    case PGP_PTAG_SS_REVOCATION_REASON:
        SUBSIG_REQUIRED_BEFORE("ss revocation reason");
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
        revocation->code = pkt->u.ss_revocation.code;
        revocation->reason = rnp_strdup(pgp_show_ss_rr_code(pkt->u.ss_revocation.code));
        break;
    case PGP_PTAG_SS_KEY_FLAGS:
        SUBSIG_REQUIRED_BEFORE("ss key flags");
        subsig->key_flags = pkt->u.ss_key_flags.contents[0];
        key->key_flags = subsig->key_flags;
        break;
    case PGP_PTAG_SS_PREFERRED_SKA:
        SUBSIG_REQUIRED_BEFORE("ss preferred symmetric key algs");
        {
            const pgp_data_t *data = &content->ss_skapref;
            pgp_user_prefs_t *prefs = &subsig->prefs;
            for (int i = 0; i < data->len; i++) {
                EXPAND_ARRAY(prefs, symm_alg);
                if (!subsig->prefs.symm_algs) {
                    PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
                    return PGP_FINISHED;
                }
                subsig->prefs.symm_algs[i] = data->contents[i];
                subsig->prefs.symm_algc++;
            }
        }
        break;
    case PGP_PTAG_SS_PREFERRED_HASH:
        SUBSIG_REQUIRED_BEFORE("ss preferred hash algs");
        {
            const pgp_data_t *data = &content->ss_hashpref;
            pgp_user_prefs_t *prefs = &subsig->prefs;
            for (int i = 0; i < data->len; i++) {
                EXPAND_ARRAY(prefs, hash_alg);
                if (!subsig->prefs.hash_algs) {
                    PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
                    return PGP_FINISHED;
                }
                subsig->prefs.hash_algs[i] = data->contents[i];
                subsig->prefs.hash_algc++;
            }
        }
        break;
    case PGP_PTAG_SS_PREF_COMPRESS:
        SUBSIG_REQUIRED_BEFORE("ss preferred compression algs");
        {
            const pgp_data_t *data = &content->ss_zpref;
            pgp_user_prefs_t *prefs = &subsig->prefs;
            for (int i = 0; i < data->len; i++) {
                EXPAND_ARRAY(prefs, compress_alg);
                if (!subsig->prefs.compress_algs) {
                    PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
                    return PGP_FINISHED;
                }
                subsig->prefs.compress_algs[i] = data->contents[i];
                subsig->prefs.compress_algc++;
            }
        }
        break;
    case PGP_PTAG_SS_KEYSERV_PREFS:
        SUBSIG_REQUIRED_BEFORE("ss key server prefs");
        {
            const pgp_data_t *data = &content->ss_key_server_prefs;
            pgp_user_prefs_t *prefs = &subsig->prefs;
            for (int i = 0; i < data->len; i++) {
                EXPAND_ARRAY(prefs, key_server_pref);
                if (!subsig->prefs.key_server_prefs) {
                    PGP_ERROR(cbinfo->errors, PGP_E_FAIL, "Failed to expand array.");
                    return PGP_FINISHED;
                }
                subsig->prefs.key_server_prefs[i] = data->contents[i];
                subsig->prefs.key_server_prefc++;
            }
        }
        break;
    case PGP_PTAG_SS_PREF_KEYSERV:
        SUBSIG_REQUIRED_BEFORE("ss preferred key server");
        subsig->prefs.key_server = (uint8_t*)content->ss_keyserv;
        return PGP_KEEP_MEMORY;
    default:
        break;
    }

    return PGP_RELEASE_MEMORY;
}

/**
   \ingroup HighLevel_KeyringRead

   \brief Reads a keyring from memory

   \param keyring Pointer to existing keyring_t struct
   \param armour 1 if file is armoured; else 0
   \param mem Pointer to a pgp_memory_t struct containing keyring to be read

   \return pgp true if OK; false on error

   \note Keyring struct must already exist.

   \note Can be used with either a public or secret keyring.

   \note You must call pgp_keyring_free() after usage to free alloc-ed memory.

   \note If you call this twice on the same keyring struct, without calling
   pgp_keyring_free() between these calls, you will introduce a memory leak.

   \sa pgp_keyring_fileread
   \sa pgp_keyring_free
*/
bool
rnp_key_store_pgp_read_from_mem(pgp_io_t *       io,
                                rnp_key_store_t *keyring,
                                const unsigned   armour,
                                pgp_memory_t *   mem)
{
    pgp_stream_t * stream;
    const unsigned printerrors = 1;
    const unsigned accum = 1;
    keyringcb_t    cb = {0};
    bool           res;

    cb.keyring = keyring;
    cb.io = io;
    if (!pgp_setup_memory_read(io, &stream, mem, &cb, cb_keyring_read, accum)) {
        (void) fprintf(io->errs, "can't setup memory read\n");
        return false;
    }
    pgp_parse_options(stream, PGP_PTAG_SS_ALL, PGP_PARSE_PARSED);
    if (armour) {
        pgp_reader_push_dearmour(stream);
    }
    res = pgp_parse(stream, printerrors);
    pgp_print_errors(pgp_stream_get_errors(stream));
    if (armour) {
        pgp_reader_pop_dearmour(stream);
    }
    /* don't call teardown_memory_read because memory was passed in */
    pgp_stream_delete(stream);
    return res;
}

int
rnp_key_store_pgp_write_to_mem(pgp_io_t *       io,
                               rnp_key_store_t *key_store,
                               const uint8_t *  passphrase,
                               const unsigned   armour,
                               pgp_memory_t *   mem)
{
    int          i;
    unsigned     rc;
    pgp_key_t *  key;
    pgp_output_t output = {};

    __PGP_USED(io);
    pgp_writer_set_memory(&output, mem);

    for (i = 0; i < key_store->keyc; i++) {
        key = &key_store->keys[i];

        if (!pgp_write_xfer_anykey(&output, key, passphrase, NULL, armour)) {
            return false;
        }
    }

    rc = pgp_writer_close(&output);
    pgp_writer_info_delete(&output.writer);

    return rc;
}
