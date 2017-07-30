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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
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

#include "pgp-key.h"
#include "signature.h"
#include "utils.h"
#include <rnp/rnp_sdk.h>
#include "readerwriter.h"
#include "validate.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void
subsig_free(pgp_subsig_t *subsig)
{
    if (!subsig) {
        return;
    }
    pgp_sig_free(&subsig->sig);
}

static void
revoke_free(pgp_revoke_t *revoke)
{
    if (!revoke) {
        return;
    }
    free(revoke->reason);
    revoke->reason = NULL;
}

/**
   \ingroup HighLevel_Keyring

   \brief Creates a new pgp_key_t struct

   \return A new pgp_key_t struct, initialised to zero.

   \note The returned pgp_key_t struct must be freed after use with pgp_key_free.
*/

pgp_key_t *
pgp_key_new(void)
{
    return calloc(1, sizeof(pgp_key_t));
}

/**
 \ingroup HighLevel_Keyring

 \brief Frees key and its memory

 \param key Key to be freed.

 \note This frees the key itself, as well as any other memory alloc-ed by it.
*/
void
pgp_key_free(pgp_key_t *key)
{
    unsigned n;

    if (key == NULL) {
        return;
    }

    if (key->uids != NULL) {
        for (n = 0; n < key->uidc; ++n) {
            pgp_userid_free(&key->uids[n]);
        }
        free(key->uids);
        key->uids = NULL;
        key->uidc = 0;
    }

    if (key->packets != NULL) {
        for (n = 0; n < key->packetc; ++n) {
            pgp_rawpacket_free(&key->packets[n]);
        }
        free(key->packets);
        key->packets = NULL;
        key->packetc = 0;
    }

    if (key->subsigs) {
        for (n = 0; n < key->subsigc; ++n) {
            subsig_free(&key->subsigs[n]);
        }
        free(key->subsigs);
        key->subsigs = NULL;
        key->subsigc = 0;
    }

    if (key->revokes) {
        for (n = 0; n < key->revokec; ++n) {
            revoke_free(&key->revokes[n]);
        }
        free(key->revokes);
        key->revokes = NULL;
        key->revokec = 0;
    }
    revoke_free(&key->revocation);

    if (key->type == PGP_PTAG_CT_PUBLIC_KEY) {
        pgp_pubkey_free(&key->key.pubkey);
    } else {
        pgp_seckey_free(&key->key.seckey);
    }

    free(key);
}

/**
 \ingroup HighLevel_KeyGeneral

 \brief Returns the public key in the given key.
 \param key

  \return Pointer to public key

  \note This is not a copy, do not free it after use.
*/

const pgp_pubkey_t *
pgp_get_pubkey(const pgp_key_t *key)
{
    return (key->type == PGP_PTAG_CT_PUBLIC_KEY) ? &key->key.pubkey : &key->key.seckey.pubkey;
}

bool
pgp_is_key_public(const pgp_key_t *key)
{
    return key->type == PGP_PTAG_CT_PUBLIC_KEY || key->type == PGP_PTAG_CT_PUBLIC_SUBKEY;
}

bool
pgp_is_key_secret(const pgp_key_t *key)
{
    return !pgp_is_key_public(key);
}

/**
 \ingroup HighLevel_KeyGeneral

 \brief Returns the secret key in the given key.

 \note This is not a copy, do not free it after use.

 \note This returns a const.  If you need to be able to write to this
 pointer, use pgp_get_writable_seckey
*/

const pgp_seckey_t *
pgp_get_seckey(const pgp_key_t *data)
{
    return (data->type == PGP_PTAG_CT_SECRET_KEY) ? &data->key.seckey : NULL;
}

/**
 \ingroup HighLevel_KeyGeneral

  \brief Returns the secret key in the given key.

  \note This is not a copy, do not free it after use.

  \note If you do not need to be able to modify this key, there is an
  equivalent read-only function pgp_get_seckey.
*/

pgp_seckey_t *
pgp_get_writable_seckey(pgp_key_t *data)
{
    return (data->type == PGP_PTAG_CT_SECRET_KEY) ? &data->key.seckey : NULL;
}

typedef struct {
    FILE *           passfp;
    const pgp_key_t *key;
    char *           passphrase;
    pgp_seckey_t *   seckey;
} decrypt_t;

static pgp_cb_ret_t
decrypt_cb(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    const pgp_contents_t *content = &pkt->u;
    decrypt_t *           decrypt;
    char                  pass[MAX_PASSPHRASE_LENGTH];

    decrypt = pgp_callback_arg(cbinfo);
    switch (pkt->tag) {
    case PGP_PARSER_PTAG:
    case PGP_PTAG_CT_USER_ID:
    case PGP_PTAG_CT_SIGNATURE:
    case PGP_PTAG_CT_SIGNATURE_HEADER:
    case PGP_PTAG_CT_SIGNATURE_FOOTER:
    case PGP_PTAG_CT_TRUST:
        break;

    case PGP_GET_PASSPHRASE:
        if (pgp_getpassphrase(decrypt->passfp, pass, sizeof(pass)) == 0) {
            pass[0] = '\0';
        }
        *content->skey_passphrase.passphrase = rnp_strdup(pass);
        pgp_forget(pass, sizeof(pass));
        return PGP_KEEP_MEMORY;

    case PGP_PARSER_ERRCODE:
        switch (content->errcode.errcode) {
        case PGP_E_P_MPI_FORMAT_ERROR:
            /* Generally this means a bad passphrase */
            fprintf(stderr, "Bad passphrase!\n");
            return PGP_RELEASE_MEMORY;

        case PGP_E_P_PACKET_CONSUMED:
            /* And this is because of an error we've accepted */
            return PGP_RELEASE_MEMORY;
        default:
            break;
        }
        (void) fprintf(stderr, "parse error: %s\n", pgp_errcode(content->errcode.errcode));
        return PGP_FINISHED;

    case PGP_PARSER_ERROR:
        fprintf(stderr, "parse error: %s\n", content->error);
        return PGP_FINISHED;

    case PGP_PTAG_CT_SECRET_KEY:
        if ((decrypt->seckey = calloc(1, sizeof(*decrypt->seckey))) == NULL) {
            (void) fprintf(stderr, "decrypt_cb: bad alloc\n");
            return PGP_FINISHED;
        }
        *decrypt->seckey = content->seckey;
        return PGP_KEEP_MEMORY;

    case PGP_PARSER_PACKET_END:
        /* nothing to do */
        break;

    default:
        fprintf(stderr, "Unexpected tag %d (0x%x)\n", pkt->tag, pkt->tag);
        return PGP_FINISHED;
    }

    return PGP_RELEASE_MEMORY;
}

static pgp_cb_ret_t
decrypt_cb_empty(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    const pgp_contents_t *content = &pkt->u;

    switch (pkt->tag) {
    case PGP_GET_PASSPHRASE:
        *content->skey_passphrase.passphrase = rnp_strdup("");
        return PGP_KEEP_MEMORY;
    default:
        return decrypt_cb(pkt, cbinfo);
    }
}

/**
\ingroup Core_Keys
\brief Decrypts secret key from given key with given passphrase
\param key Key from which to get secret key
\param passphrase Passphrase to use to decrypt secret key
\return secret key
*/
pgp_seckey_t *
pgp_decrypt_seckey(const pgp_key_t *key, FILE *passfp)
{
    pgp_stream_t *stream;
    const int     printerrors = 1;
    decrypt_t     decrypt;

    /* XXX first try with an empty passphrase */
    (void) memset(&decrypt, 0x0, sizeof(decrypt));

    decrypt.key = key;
    stream = pgp_new(sizeof(*stream));
    pgp_key_reader_set(stream, key);
    pgp_set_callback(stream, decrypt_cb_empty, &decrypt);
    stream->readinfo.accumulate = 1;
    pgp_parse(stream, !printerrors);

    if (decrypt.seckey != NULL) {
        return decrypt.seckey;
    }

    /* ask for a passphrase */
    decrypt.passfp = passfp;
    stream = pgp_new(sizeof(*stream));
    pgp_key_reader_set(stream, key);
    pgp_set_callback(stream, decrypt_cb, &decrypt);
    stream->readinfo.accumulate = 1;
    pgp_parse(stream, !printerrors);
    return decrypt.seckey;
}

/**
\ingroup Core_Keys
\brief Set secret key in content
\param content Content to be set
\param key Key to get secret key from
*/
void
pgp_set_seckey(pgp_contents_t *cont, const pgp_key_t *key)
{
    *cont->get_seckey.seckey = &key->key.seckey;
}

/**
\ingroup Core_Keys
\brief Get Key ID from key
\param key Key to get Key ID from
\return Pointer to Key ID inside key
*/
const uint8_t *
pgp_get_key_id(const pgp_key_t *key)
{
    return key->sigid;
}

/**
\ingroup Core_Keys
\brief How many User IDs in this key?
\param key Key to check
\return Num of user ids
*/
unsigned
pgp_get_userid_count(const pgp_key_t *key)
{
    return key->uidc;
}

/**
\ingroup Core_Keys
\brief Get indexed user id from key
\param key Key to get user id from
\param index Which key to get
\return Pointer to requested user id
*/
const uint8_t *
pgp_get_userid(const pgp_key_t *key, unsigned subscript)
{
    return key->uids[subscript];
}

/* \todo check where userid pointers are copied */
/**
\ingroup Core_Keys
\brief Copy user id, including contents
\param dst Destination User ID
\param src Source User ID
\note If dst already has a userid, it will be freed.
*/
static uint8_t *
copy_userid(uint8_t **dst, const uint8_t *src)
{
    size_t len;

    len = strlen((const char *) src);
    if (*dst) {
        free(*dst);
    }
    if ((*dst = calloc(1, len + 1)) == NULL) {
        (void) fprintf(stderr, "copy_userid: bad alloc\n");
    } else {
        (void) memcpy(*dst, src, len);
    }
    return *dst;
}

/* \todo check where pkt pointers are copied */
/**
\ingroup Core_Keys
\brief Copy packet, including contents
\param dst Destination packet
\param src Source packet
\note If dst already has a packet, it will be freed.
*/
static pgp_rawpacket_t *
copy_packet(pgp_rawpacket_t *dst, const pgp_rawpacket_t *src)
{
    if (dst->raw) {
        free(dst->raw);
    }
    if ((dst->raw = calloc(1, src->length)) == NULL) {
        (void) fprintf(stderr, "copy_packet: bad alloc\n");
    } else {
        dst->length = src->length;
        (void) memcpy(dst->raw, src->raw, src->length);
    }
    return dst;
}

/**
\ingroup Core_Keys
\brief Add User ID to key
\param key Key to which to add User ID
\param userid User ID to add
\return Pointer to new User ID
*/
uint8_t *
pgp_add_userid(pgp_key_t *key, const uint8_t *userid)
{
    uint8_t **uidp;

    EXPAND_ARRAY(key, uid);
    if (key->uids == NULL) {
        return NULL;
    }
    /* initialise new entry in array */
    uidp = &key->uids[key->uidc++];
    *uidp = NULL;
    /* now copy it */
    return copy_userid(uidp, userid);
}

/**
\ingroup Core_Keys
\brief Add packet to key
\param key Key to which to add packet
\param packet Packet to add
\return Pointer to new packet
*/
pgp_rawpacket_t *
pgp_add_rawpacket(pgp_key_t *key, const pgp_rawpacket_t *packet)
{
    pgp_rawpacket_t *subpktp;

    EXPAND_ARRAY(key, packet);
    if (key->packets == NULL) {
        return NULL;
    }
    /* initialise new entry in array */
    subpktp = &key->packets[key->packetc++];
    subpktp->length = 0;
    subpktp->raw = NULL;
    /* now copy it */
    return copy_packet(subpktp, packet);
}

/**
\ingroup Core_Keys
\brief Add selfsigned User ID to key
\param key Key to which to add user ID
\param userid Self-signed User ID to add
\return true if OK; else false
*/
bool
pgp_add_selfsigned_userid(pgp_key_t *key, const uint8_t *userid)
{
    struct pgp_create_sig_t *sig;
    pgp_rawpacket_t          sigpacket;
    struct pgp_memory_t *    mem_userid = NULL;
    pgp_output_t *           useridoutput = NULL;
    struct pgp_memory_t *    mem_sig = NULL;
    pgp_output_t *           sigoutput = NULL;

    /*
     * create signature packet for this userid
     */

    /* create userid pkt */
    if (!pgp_setup_memory_write(NULL, &useridoutput, &mem_userid, 128)) {
        (void) fprintf(stderr, "cat't setup memory write\n");
        return false;
    }
    pgp_write_struct_userid(useridoutput, userid);

    /* create sig for this pkt */
    sig = pgp_create_sig_new();
    pgp_sig_start_key_sig(
      sig, &key->key.seckey.pubkey, userid, PGP_CERT_POSITIVE, key->key.seckey.hash_alg);
    pgp_sig_add_time(sig, (int64_t) time(NULL), PGP_PTAG_SS_CREATION_TIME);
    pgp_sig_add_issuer_keyid(sig, key->sigid);
    pgp_sig_add_primary_userid(sig, 1);
    pgp_sig_end_hashed_subpkts(sig);

    if (!pgp_setup_memory_write(NULL, &sigoutput, &mem_sig, 128)) {
        (void) fprintf(stderr, "can't setup memory write\n");
        return false;
    }
    pgp_sig_write(sigoutput, sig, &key->key.seckey.pubkey, &key->key.seckey);

    /* add this packet to key */
    sigpacket.length = pgp_mem_len(mem_sig);
    sigpacket.raw = pgp_mem_data(mem_sig);

    /* add userid to key */
    (void) pgp_add_userid(key, userid);
    (void) pgp_add_rawpacket(key, &sigpacket);

    /* cleanup */
    pgp_create_sig_delete(sig);
    pgp_output_delete(useridoutput);
    pgp_output_delete(sigoutput);
    pgp_memory_free(mem_userid);
    pgp_memory_free(mem_sig);

    return true;
}

/**
\ingroup Core_Keys
\brief Initialise pgp_key_t
\param key Key to initialise
\param type PGP_PTAG_CT_PUBLIC_KEY or PGP_PTAG_CT_SECRET_KEY
*/
void
pgp_key_init(pgp_key_t *key, const pgp_content_enum type)
{
    if (key->type != PGP_PTAG_CT_RESERVED) {
        (void) fprintf(stderr, "pgp_key_init: wrong key type\n");
    } else if (type != PGP_PTAG_CT_PUBLIC_KEY && type != PGP_PTAG_CT_SECRET_KEY) {
        (void) fprintf(stderr, "pgp_key_init: wrong type\n");
    } else {
        key->type = type;
    }
}
