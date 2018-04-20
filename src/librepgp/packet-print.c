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

/*
 * ! \file \brief Standard API print functions
 */
#include "config.h"

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: packet-print.c,v 1.42 2012/02/22 06:29:40 agc Exp $");
#endif

#ifdef RNP_DEBUG
#include <assert.h>
#endif

#include <rnp/rnp_sdk.h>

#include "crypto/ec.h"
#include "packet-show.h"
#include "pgp-key.h"
#include "reader.h"

#define F_REVOKED 1

#define F_PRINTSIGS 2

#define PTIMESTR_LEN 10

#define PUBKEY_DOES_EXPIRE(pk) ((pk)->expiration > 0)

#define PUBKEY_HAS_EXPIRED(pk, t) (((pk)->creation + (pk)->expiration) < (t))

#define SIGNATURE_PADDING "          "

/* static functions */
static bool format_key_usage(char *buffer, size_t size, uint8_t flags);

// returns bitlength of a key
size_t
key_bitlength(const pgp_pubkey_t *pubkey)
{
    size_t sz = 0;
    switch (pubkey->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        (void) bn_num_bytes(pubkey->key.rsa.n, &sz);
        return sz * 8;
    case PGP_PKA_DSA:
        (void) bn_num_bytes(pubkey->key.dsa.p, &sz);
        return sz * 8;
    case PGP_PKA_ELGAMAL:
        (void) bn_num_bytes(pubkey->key.elgamal.y, &sz);
        return sz * 8;
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2: {
        // bn_num_bytes returns value <= curve order
        const ec_curve_desc_t *curve = get_curve_desc(pubkey->key.ecc.curve);
        return curve ? curve->bitlen : 0;
    }
    default:
        RNP_LOG("Unknown public key alg in key_bitlength");
        return -1;
    }
}

/* Write the time as a string to buffer `dest`. The time string is guaranteed
 * to be PTIMESTR_LEN characters long.
 */
static char *
ptimestr(char *dest, size_t size, time_t t)
{
    struct tm *tm;

    tm = gmtime(&t);

    /* Remember - we guarantee that the time string will be PTIMESTR_LEN
     * characters long.
     */
    snprintf(dest, size, "%04d-%02d-%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
#ifdef RNP_DEBUG
    assert(stelen(dest) == PTIMESTR_LEN);
#endif
    return dest;
}

/* Print the sub key binding signature info. */
static int
psubkeybinding(char *buf, size_t size, const pgp_key_t *key, const char *expired)
{
    char keyid[512];
    char t[32];
    char key_usage[8];

    format_key_usage(key_usage, sizeof(key_usage), key->key_flags);
    const pgp_pubkey_t *pubkey = pgp_get_pubkey(key);
    return snprintf(buf,
                    size,
                    "encryption %zu/%s %s %s [%s] %s\n",
                    key_bitlength(pubkey),
                    pgp_show_pka(pubkey->alg),
                    rnp_strhexdump(keyid, key->keyid, PGP_KEY_ID_SIZE, ""),
                    ptimestr(t, sizeof(t), pubkey->creation),
                    key_usage,
                    expired);
}

/* Searches a key's revocation list for the given key UID. If it is found its
 * index is returned, otherwise -1 is returned.
 */
static int
isrevoked(const pgp_key_t *key, unsigned uid)
{
    unsigned i;

    for (i = 0; i < key->revokec; i++) {
        if (key->revokes[i].uid == uid)
            return i;
    }
    return -1;
}

static bool
iscompromised(const pgp_key_t *key, unsigned uid)
{
    int r = isrevoked(key, uid);

    return r >= 0 && key->revokes[r].code == PGP_REVOCATION_COMPROMISED;
}

/* Formats a public key expiration notice. Assumes that the public key
 * expires. Return 1 on success and 0 on failure.
 */
static bool
format_pubkey_expiration_notice(char *              buffer,
                                const pgp_pubkey_t *pubkey,
                                time_t              time,
                                size_t              size)
{
    char *buffer_end = buffer + size;

    buffer[0] = '\0';

    /* Write the opening bracket. */
    buffer += snprintf(buffer, buffer_end - buffer, "%s", "[");
    if (buffer >= buffer_end)
        return false;

    /* Write the expiration state label. */
    buffer += snprintf(buffer,
                       buffer_end - buffer,
                       "%s ",
                       PUBKEY_HAS_EXPIRED(pubkey, time) ? "EXPIRED" : "EXPIRES");

    /* Ensure that there will be space for tihe time. */
    if (buffer_end - buffer < PTIMESTR_LEN + 1)
        return false;

    /* Write the expiration time. */
    ptimestr(buffer, buffer_end - buffer, pubkey->creation + pubkey->expiration);
    buffer += PTIMESTR_LEN;
    if (buffer >= buffer_end)
        return false;

    /* Write the closing bracket. */
    buffer += snprintf(buffer, buffer_end - buffer, "%s", "]");
    if (buffer >= buffer_end)
        return false;

    return true;
}

static int
format_uid_line(char *buffer, uint8_t *uid, size_t size, int flags)
{
    return snprintf(buffer,
                    size,
                    "uid    %s%s%s\n",
                    flags & F_PRINTSIGS ? "" : SIGNATURE_PADDING,
                    uid,
                    flags & F_REVOKED ? " [REVOKED]" : "");
}

/* TODO: Consider replacing `trustkey` with an optional `uid` parameter. */
/* TODO: Consider passing only signer_id and creation. */
static int
format_sig_line(char *buffer, const pgp_sig_t *sig, const pgp_key_t *trustkey, size_t size)
{
    char keyid[PGP_KEY_ID_SIZE * 3];
    char time[PTIMESTR_LEN + sizeof(char)];

    ptimestr(time, sizeof(time), sig->info.creation);
    return snprintf(buffer,
                    size,
                    "sig        %s  %s  %s\n",
                    rnp_strhexdump(keyid, sig->info.signer_id, PGP_KEY_ID_SIZE, ""),
                    time,
                    trustkey != NULL ? (char *) trustkey->uids[trustkey->uid0] : "[unknown]");
}

static int
format_subsig_line(char *              buffer,
                   const pgp_key_t *   key,
                   const pgp_key_t *   trustkey,
                   const pgp_subsig_t *subsig,
                   size_t              size)
{
    char expired[128];
    int  n = 0;

    expired[0] = '\0';
    if (PUBKEY_DOES_EXPIRE(&key->key.pubkey)) {
        format_pubkey_expiration_notice(
          expired, &key->key.pubkey, time(NULL), sizeof(expired));
    }
    if (subsig->sig.info.version == 4 && subsig->sig.info.type == PGP_SIG_SUBKEY) {
        /* XXX: The character count of this was previously ignored.
         *      This seems to have been incorrect, but if not
         *      you should revert it.
         */
        n += psubkeybinding(buffer, size, key, expired);
    } else
        n += format_sig_line(buffer, &subsig->sig, trustkey, size);

    return n;
}

static int
format_uid_notice(char *                 buffer,
                  pgp_io_t *             io,
                  const rnp_key_store_t *keyring,
                  const pgp_key_t *      key,
                  unsigned               uid,
                  size_t                 size,
                  int                    flags)
{
    unsigned n = 0;

    if (isrevoked(key, uid) >= 0)
        flags |= F_REVOKED;

    n += format_uid_line(buffer, key->uids[uid], size, flags);

    for (unsigned i = 0; i < key->subsigc; i++) {
        pgp_subsig_t *   subsig = &key->subsigs[i];
        const pgp_key_t *trustkey;

        /* TODO: To me this looks like an unnecessary consistency
         *       check that should be performed upstream before
         *       passing the information down here. Maybe not,
         *       if anyone can shed alternate light on this
         *       that would be great.
         */
        if (flags & F_PRINTSIGS && subsig->uid != uid) {
            continue;

            /* TODO: I'm also unsure about this one. */
        } else if (!(subsig->sig.info.version == 4 &&
                     subsig->sig.info.type == PGP_SIG_SUBKEY && uid == key->uidc - 1)) {
            continue;
        }

        trustkey =
          rnp_key_store_get_key_by_id(io, keyring, subsig->sig.info.signer_id, NULL, NULL);

        n += format_subsig_line(buffer + n, key, trustkey, subsig, size - n);
    }

    return n;
}

static bool
format_key_usage(char *buffer, size_t size, uint8_t flags)
{
    static const pgp_bit_map_t flags_map[] = {
      {PGP_KF_ENCRYPT, "E"}, {PGP_KF_SIGN, "S"}, {PGP_KF_CERTIFY, "C"}, {PGP_KF_AUTH, "A"},
    };

    *buffer = '\0';
    for (size_t i = 0; i < ARRAY_SIZE(flags_map); i++) {
        if (flags & flags_map[i].mask) {
            const size_t current_length = strlen(buffer);
            if (current_length == size - 1) {
                return false;
            }
            strncat(buffer, flags_map[i].string, size - current_length - 1);
        }
    }
    return true;
}

static bool
format_key_usage_json(json_object *arr, uint8_t flags)
{
    static const pgp_bit_map_t flags_map[] = {
      {PGP_KF_ENCRYPT, "encrypt"},
      {PGP_KF_SIGN, "sign"},
      {PGP_KF_CERTIFY, "certify"},
      {PGP_KF_AUTH, "authenticate"},
    };

    for (size_t i = 0; i < ARRAY_SIZE(flags_map); i++) {
        if (flags & flags_map[i].mask) {
            json_object *str = json_object_new_string(flags_map[i].string);
            if (!str) {
                return false;
            }
            if (json_object_array_add(arr, str) != 0) {
                return false;
            }
        }
    }
    return true;
}

#ifndef KB
#define KB(x) ((x) *1024)
#endif

/* XXX: Why 128KiB? */
#define NOTICE_BUFFER_SIZE KB(128)

/* print into a string (malloc'ed) the pubkeydata */
int
pgp_sprint_key(pgp_io_t *             io,
               const rnp_key_store_t *keyring,
               const pgp_key_t *      key,
               char **                buf,
               const char *           header,
               const pgp_pubkey_t *   pubkey,
               const int              psigs)
{
    unsigned i;
    time_t   now;
    char *   uid_notices;
    int      uid_notices_offset = 0;
    char *   string;
    int      total_length;
    char     keyid[PGP_KEY_ID_SIZE * 3];
    char     fingerprint[PGP_FINGERPRINT_HEX_SIZE];
    char     expiration_notice[128];
    char     creation[32];
    char     key_usage[8];

    if (key->revoked)
        return -1;

    now = time(NULL);

    if (PUBKEY_DOES_EXPIRE(pubkey)) {
        format_pubkey_expiration_notice(
          expiration_notice, pubkey, now, sizeof(expiration_notice));
    } else
        expiration_notice[0] = '\0';

    uid_notices = (char *) malloc(NOTICE_BUFFER_SIZE);
    if (uid_notices == NULL)
        return -1;

    /* TODO: Perhaps this should index key->uids instead of using the
     *       iterator index.
     */
    for (i = 0; i < key->uidc; i++) {
        int flags = 0;

        if (iscompromised(key, i))
            continue;

        if (psigs)
            flags |= F_PRINTSIGS;

        uid_notices_offset += format_uid_notice(uid_notices + uid_notices_offset,
                                                io,
                                                keyring,
                                                key,
                                                i,
                                                NOTICE_BUFFER_SIZE - uid_notices_offset,
                                                flags);
    }
    uid_notices[uid_notices_offset] = '\0';

    rnp_strhexdump(keyid, key->keyid, PGP_KEY_ID_SIZE, "");

    rnp_strhexdump(fingerprint, key->fingerprint.fingerprint, key->fingerprint.length, " ");

    ptimestr(creation, sizeof(creation), pubkey->creation);

    if (!format_key_usage(key_usage, sizeof(key_usage), key->key_flags)) {
        return -1;
    }

    /* XXX: For now we assume that the output string won't exceed 16KiB
     *      in length but this is completely arbitrary. What this
     *      really needs is some objective facts to base this
     *      size on.
     */

    total_length = -1;
    string = (char *) malloc(KB(16));
    if (string != NULL) {
        total_length = snprintf(string,
                                KB(16),
                                "%s %zu/%s %s %s [%s] %s\n                 %s\n%s",
                                header,
                                key_bitlength(pubkey),
                                pgp_show_pka(pubkey->alg),
                                keyid,
                                creation,
                                key_usage,
                                expiration_notice,
                                fingerprint,
                                uid_notices);
        *buf = string;
    }

    free((void *) uid_notices);

    return total_length;
}

/* return the key info as a JSON encoded string */
int
repgp_sprint_json(pgp_io_t *                    io,
                  const struct rnp_key_store_t *keyring,
                  const pgp_key_t *             key,
                  json_object *                 keyjson,
                  const char *                  header,
                  const pgp_pubkey_t *          pubkey,
                  const int                     psigs)
{
    char     keyid[PGP_KEY_ID_SIZE * 3];
    char     fp[PGP_FINGERPRINT_HEX_SIZE];
    int      r;
    unsigned i;
    unsigned j;

    if (key == NULL || key->revoked) {
        return -1;
    }

    // add the top-level values
    json_object_object_add(keyjson, "header", json_object_new_string(header));
    json_object_object_add(keyjson, "key bits", json_object_new_int(key_bitlength(pubkey)));
    json_object_object_add(keyjson, "pka", json_object_new_string(pgp_show_pka(pubkey->alg)));
    json_object_object_add(
      keyjson,
      "key id",
      json_object_new_string(rnp_strhexdump(keyid, key->keyid, PGP_KEY_ID_SIZE, "")));
    json_object_object_add(keyjson,
                           "fingerprint",
                           json_object_new_string(rnp_strhexdump(
                             fp, key->fingerprint.fingerprint, key->fingerprint.length, "")));
    json_object_object_add(keyjson, "creation time", json_object_new_int(pubkey->creation));
    json_object_object_add(keyjson, "expiration", json_object_new_int(pubkey->expiration));
    json_object_object_add(keyjson, "key flags", json_object_new_int(key->key_flags));
    json_object *usage_arr = json_object_new_array();
    format_key_usage_json(usage_arr, key->key_flags);
    json_object_object_add(keyjson, "usage", usage_arr);

    // iterating through the uids
    json_object *uid_arr = json_object_new_array();
    for (i = 0; i < key->uidc; i++) {
        if ((r = isrevoked(key, i)) >= 0 &&
            key->revokes[r].code == PGP_REVOCATION_COMPROMISED) {
            continue;
        }
        // add an array of the uids (and checking whether is REVOKED and
        // indicate it as well)
        json_object *uidobj = json_object_new_object();
        json_object_object_add(
          uidobj, "user id", json_object_new_string((char *) key->uids[i]));
        json_object_object_add(
          uidobj, "revoked", json_object_new_boolean((r >= 0) ? TRUE : FALSE));
        for (j = 0; j < key->subsigc; j++) {
            if (psigs) {
                if (key->subsigs[j].uid != i) {
                    continue;
                }
            } else {
                if (!(key->subsigs[j].sig.info.version == 4 &&
                      key->subsigs[j].sig.info.type == PGP_SIG_SUBKEY && i == key->uidc - 1)) {
                    continue;
                }
            }
            json_object *subsigc = json_object_new_object();
            json_object_object_add(
              subsigc,
              "signer id",
              json_object_new_string(rnp_strhexdump(
                keyid, key->subsigs[j].sig.info.signer_id, PGP_KEY_ID_SIZE, "")));
            json_object_object_add(
              subsigc,
              "creation time",
              json_object_new_int((int64_t)(key->subsigs[j].sig.info.creation)));

            const pgp_key_t *trustkey = rnp_key_store_get_key_by_id(
              io, keyring, key->subsigs[j].sig.info.signer_id, NULL, NULL);

            json_object_object_add(
              subsigc,
              "user id",
              json_object_new_string((trustkey) ? (char *) trustkey->uids[trustkey->uid0] :
                                                  "[unknown]"));
            json_object_object_add(uidobj, "signature", subsigc);
        }
        json_object_array_add(uid_arr, uidobj);
    } // for uidc
    json_object_object_add(keyjson, "user ids", uid_arr);
    if (rnp_get_debug(__FILE__)) {
        printf("%s,%d: The json object created: %s\n",
               __FILE__,
               __LINE__,
               json_object_to_json_string_ext(keyjson, JSON_C_TO_STRING_PRETTY));
    }
    return 1;
}

int
pgp_hkp_sprint_key(pgp_io_t *                    io,
                   const struct rnp_key_store_t *keyring,
                   const pgp_key_t *             key,
                   char **                       buf,
                   const pgp_pubkey_t *          pubkey,
                   const int                     psigs)
{
    const pgp_key_t *trustkey;
    unsigned         i;
    unsigned         j;
    char             keyid[PGP_KEY_ID_SIZE * 3];
    char             uidbuf[KB(128)];
    char             fingerprint[PGP_FINGERPRINT_HEX_SIZE];
    int              n;

    if (key->revoked) {
        return -1;
    }
    for (i = 0, n = 0; i < key->uidc; i++) {
        n += snprintf(&uidbuf[n],
                      sizeof(uidbuf) - n,
                      "uid:%lld:%lld:%s\n",
                      (long long) pubkey->creation,
                      (long long) pubkey->expiration,
                      key->uids[i]);
        for (j = 0; j < key->subsigc; j++) {
            if (psigs) {
                if (key->subsigs[j].uid != i) {
                    continue;
                }
            } else {
                if (!(key->subsigs[j].sig.info.version == 4 &&
                      key->subsigs[j].sig.info.type == PGP_SIG_SUBKEY && i == key->uidc - 1)) {
                    continue;
                }
            }
            trustkey = rnp_key_store_get_key_by_id(
              io, keyring, key->subsigs[j].sig.info.signer_id, NULL, NULL);
            if (key->subsigs[j].sig.info.version == 4 &&
                key->subsigs[j].sig.info.type == PGP_SIG_SUBKEY) {
                n +=
                  snprintf(&uidbuf[n],
                           sizeof(uidbuf) - n,
                           "sub:%zu:%d:%s:%lld:%lld\n",
                           key_bitlength(pubkey),
                           key->subsigs[j].sig.info.key_alg,
                           rnp_strhexdump(
                             keyid, key->subsigs[j].sig.info.signer_id, PGP_KEY_ID_SIZE, ""),
                           (long long) (key->subsigs[j].sig.info.creation),
                           (long long) pubkey->expiration);
            } else {
                n +=
                  snprintf(&uidbuf[n],
                           sizeof(uidbuf) - n,
                           "sig:%s:%lld:%s\n",
                           rnp_strhexdump(
                             keyid, key->subsigs[j].sig.info.signer_id, PGP_KEY_ID_SIZE, ""),
                           (long long) key->subsigs[j].sig.info.creation,
                           (trustkey) ? (char *) trustkey->uids[trustkey->uid0] : "");
            }
        }
    }

    rnp_strhexdump(fingerprint, key->fingerprint.fingerprint, PGP_FINGERPRINT_SIZE, "");

    n = -1;
    {
        /* XXX: This number is completely arbitrary. */
        char *buffer = (char *) malloc(KB(16));

        if (buffer != NULL) {
            n = snprintf(buffer,
                         KB(16),
                         "pub:%s:%d:%zu:%lld:%lld\n%s",
                         fingerprint,
                         pubkey->alg,
                         key_bitlength(pubkey),
                         (long long) pubkey->creation,
                         (long long) pubkey->expiration,
                         uidbuf);
            *buf = buffer;
        }
    }
    return n;
}

/* print the key data for a pub or sec key */
void
repgp_print_key(pgp_io_t *             io,
                const rnp_key_store_t *keyring,
                const pgp_key_t *      key,
                const char *           header,
                const pgp_pubkey_t *   pubkey,
                const int              psigs)
{
    char *cp;

    if (pgp_sprint_key(io, keyring, key, &cp, header, pubkey, psigs) >= 0) {
        (void) fprintf(io->res, "%s", cp);
        free(cp);
    }
}

int
pgp_sprint_pubkey(const pgp_key_t *key, char *out, size_t outsize)
{
    char fp[PGP_FINGERPRINT_HEX_SIZE];
    int  cc;

    cc = snprintf(out,
                  outsize,
                  "key=%s\nname=%s\ncreation=%lld\nexpiry=%lld\nversion=%d\nalg=%d\n",
                  rnp_strhexdump(fp, key->fingerprint.fingerprint, PGP_FINGERPRINT_SIZE, ""),
                  key->uids[key->uid0],
                  (long long) key->key.pubkey.creation,
                  (long long) key->key.pubkey.days_valid,
                  key->key.pubkey.version,
                  key->key.pubkey.alg);
    switch (key->key.pubkey.alg) {
    case PGP_PKA_DSA:
        cc += snprintf(&out[cc],
                       outsize - cc,
                       "p=%s\nq=%s\ng=%s\ny=%s\n",
                       bn_bn2hex(key->key.pubkey.key.dsa.p),
                       bn_bn2hex(key->key.pubkey.key.dsa.q),
                       bn_bn2hex(key->key.pubkey.key.dsa.g),
                       bn_bn2hex(key->key.pubkey.key.dsa.y));
        break;
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        cc += snprintf(&out[cc],
                       outsize - cc,
                       "n=%s\ne=%s\n",
                       bn_bn2hex(key->key.pubkey.key.rsa.n),
                       bn_bn2hex(key->key.pubkey.key.rsa.e));
        break;
    case PGP_PKA_EDDSA:
        cc += snprintf(
          &out[cc], outsize - cc, "point=%s\n", bn_bn2hex(key->key.pubkey.key.ecc.point));
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH: {
        const ec_curve_desc_t *curve = get_curve_desc(key->key.pubkey.key.ecc.curve);
        if (curve) {
            cc += snprintf(&out[cc],
                           outsize - cc,
                           "curve=%s\npoint=%s\n",
                           curve->botan_name,
                           bn_bn2hex(key->key.pubkey.key.ecc.point));
        }
        break;
    }
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        cc += snprintf(&out[cc],
                       outsize - cc,
                       "p=%s\ng=%s\ny=%s\n",
                       bn_bn2hex(key->key.pubkey.key.elgamal.p),
                       bn_bn2hex(key->key.pubkey.key.elgamal.g),
                       bn_bn2hex(key->key.pubkey.key.elgamal.y));
        break;
    default:
        (void) fprintf(stderr, "pgp_print_pubkey: Unusual algorithm\n");
    }
    return cc;
}
