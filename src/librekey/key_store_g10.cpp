/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
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

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>

#include <rnp/rnp_sdk.h>
#include <botan/ffi.h>

#include <librepgp/stream-packet.h>
#include "key_store_pgp.h"
#include "key_store_g10.h"

#include "crypto/common.h"
#include "pgp-key.h"
#include "utils.h"

#define G10_CBC_IV_SIZE 16

#define G10_OCB_NONCE_SIZE 12

#define G10_SHA1_HASH_SIZE 20

#define G10_PROTECTED_AT_SIZE 15

typedef struct {
    size_t   len;
    uint8_t *bytes;
} s_exp_block_t;

typedef struct sub_element_t sub_element_t;

typedef struct {
    DYNARRAY(sub_element_t, sub_element);
} s_exp_t;

struct sub_element_t {
    bool is_block;
    union {
        s_exp_t       s_exp;
        s_exp_block_t block;
    };
};

typedef struct format_info {
    pgp_symm_alg_t    cipher;
    pgp_cipher_mode_t cipher_mode;
    pgp_hash_alg_t    hash_alg;
    const char *      botan_cipher_name;
    size_t            chiper_block_size;
    const char *      g10_type;
    size_t            iv_size;
} format_info;

static bool    g10_calculated_hash(const pgp_key_pkt_t *key,
                                   const char *         protected_at,
                                   uint8_t *            checksum);
pgp_key_pkt_t *g10_decrypt_seckey(const uint8_t *      data,
                                  size_t               data_len,
                                  const pgp_key_pkt_t *pubkey,
                                  const char *         password);

static const format_info formats[] = {{PGP_SA_AES_128,
                                       PGP_CIPHER_MODE_CBC,
                                       PGP_HASH_SHA1,
                                       "AES-128/CBC/NoPadding",
                                       16,
                                       "openpgp-s2k3-sha1-aes-cbc",
                                       G10_CBC_IV_SIZE},
                                      {PGP_SA_AES_256,
                                       PGP_CIPHER_MODE_CBC,
                                       PGP_HASH_SHA1,
                                       "AES-256/CBC/NoPadding",
                                       16,
                                       "openpgp-s2k3-sha1-aes256-cbc",
                                       G10_CBC_IV_SIZE},
                                      {PGP_SA_AES_128,
                                       PGP_CIPHER_MODE_OCB,
                                       PGP_HASH_SHA1,
                                       "AES-128/OCB/NoPadding",
                                       16,
                                       "openpgp-s2k3-ocb-aes",
                                       G10_OCB_NONCE_SIZE}};

static const pgp_map_t g10_alg_aliases[] = {{PGP_PKA_RSA, "rsa"},
                                            {PGP_PKA_RSA, "openpgp-rsa"},
                                            {PGP_PKA_RSA, "oid.1.2.840.113549.1.1.1"},
                                            {PGP_PKA_RSA, "oid.1.2.840.113549.1.1.1"},
                                            {PGP_PKA_ELGAMAL, "elg"},
                                            {PGP_PKA_ELGAMAL, "elgamal"},
                                            {PGP_PKA_ELGAMAL, "openpgp-elg"},
                                            {PGP_PKA_ELGAMAL, "openpgp-elg-sig"},
                                            {PGP_PKA_DSA, "dsa"},
                                            {PGP_PKA_DSA, "openpgp-dsa"},
                                            {PGP_PKA_ECDSA, "ecc"},
                                            {PGP_PKA_ECDSA, "ecdsa"},
                                            {PGP_PKA_ECDH, "ecdh"},
                                            {PGP_PKA_EDDSA, "eddsa"}};

static const pgp_map_t g10_curve_aliases[] = {
  {PGP_CURVE_NIST_P_256, "NIST P-256"},
  {PGP_CURVE_NIST_P_256, "1.2.840.10045.3.1.7"},
  {PGP_CURVE_NIST_P_256, "prime256v1"},
  {PGP_CURVE_NIST_P_256, "secp256r1"},
  {PGP_CURVE_NIST_P_256, "nistp256"},

  {PGP_CURVE_NIST_P_384, "NIST P-384"},
  {PGP_CURVE_NIST_P_384, "secp384r1"},
  {PGP_CURVE_NIST_P_384, "1.3.132.0.34"},
  {PGP_CURVE_NIST_P_384, "nistp384"},

  {PGP_CURVE_NIST_P_521, "NIST P-521"},
  {PGP_CURVE_NIST_P_521, "secp521r1"},
  {PGP_CURVE_NIST_P_521, "1.3.132.0.35"},
  {PGP_CURVE_NIST_P_521, "nistp521"},

  /* Ed25519 and Curve25519 are actually different curves with different usage, needs to be
     re-checked */
  {PGP_CURVE_ED25519, "Curve25519"},
  {PGP_CURVE_ED25519, "1.3.6.1.4.1.3029.1.5.1"},
  {PGP_CURVE_ED25519, "Ed25519"},
  {PGP_CURVE_ED25519, "1.3.6.1.4.1.11591.15.1"}};

static const pgp_map_t g10_curve_names[] = {{PGP_CURVE_NIST_P_256, "NIST P-256"},
                                            {PGP_CURVE_NIST_P_384, "NIST P-384"},
                                            {PGP_CURVE_NIST_P_521, "NIST P-521"},
                                            {PGP_CURVE_ED25519, "Ed25519"}};

static const format_info *
find_format(pgp_symm_alg_t cipher, pgp_cipher_mode_t mode, pgp_hash_alg_t hash_alg)
{
    for (size_t i = 0; i < ARRAY_SIZE(formats); i++) {
        if (formats[i].cipher == cipher && formats[i].cipher_mode == mode &&
            formats[i].hash_alg == hash_alg) {
            return &formats[i];
        }
    }
    return NULL;
}

static const format_info *
parse_format(const char *format, size_t format_len)
{
    for (size_t i = 0; i < ARRAY_SIZE(formats); i++) {
        if (strlen(formats[i].g10_type) == format_len &&
            !strncmp(formats[i].g10_type, format, format_len)) {
            return &formats[i];
        }
    }
    return NULL;
}

static void
destroy_s_exp(s_exp_t *s_exp)
{
    unsigned i;

    if (s_exp == NULL) {
        return;
    }

    if (s_exp->sub_elements != NULL) {
        for (i = 0; i < s_exp->sub_elementc; i++) {
            if (s_exp->sub_elements[i].is_block) {
                if (s_exp->sub_elements[i].block.len > 0 &&
                    s_exp->sub_elements[i].block.bytes != NULL) {
                    free(s_exp->sub_elements[i].block.bytes);
                    s_exp->sub_elements[i].block.bytes = NULL;
                    s_exp->sub_elements[i].block.len = 0;
                }
            } else {
                destroy_s_exp(&s_exp->sub_elements[i].s_exp);
            }
        }
        FREE_ARRAY(s_exp, sub_element);
    }
}

static bool
add_block_to_sexp(s_exp_t *s_exp, const uint8_t *bytes, size_t len)
{
    sub_element_t *sub_element;

    for (unsigned i = 0; i < s_exp->sub_elementc; i++) {
        if (!s_exp->sub_elements[i].is_block) {
            continue;
        }
        if (len == s_exp->sub_elements[i].block.len &&
            !memcmp(s_exp->sub_elements[i].block.bytes, bytes, len)) {
            // do not duplicate blocks
            return true;
        }
    }

    EXPAND_ARRAY(s_exp, sub_element);
    if (s_exp->sub_elements == NULL) {
        return false;
    }

    sub_element = &s_exp->sub_elements[s_exp->sub_elementc++];

    sub_element->is_block = true;
    sub_element->block.len = (size_t) len;
    sub_element->block.bytes = (uint8_t *) malloc(sub_element->block.len);
    if (sub_element->block.bytes == NULL) {
        RNP_LOG("can't allocate memory");
        return false;
    }

    memcpy(sub_element->block.bytes, bytes, sub_element->block.len);
    return true;
}

static bool
add_string_block_to_sexp(s_exp_t *s_exp, const char *s)
{
    return add_block_to_sexp(s_exp, (uint8_t *) s, strlen(s));
}

static bool
add_sub_sexp_to_sexp(s_exp_t *s_exp, s_exp_t **sub_s_exp)
{
    sub_element_t *sub_element;

    EXPAND_ARRAY(s_exp, sub_element);
    if (s_exp->sub_elements == NULL) {
        return false;
    }

    sub_element = &s_exp->sub_elements[s_exp->sub_elementc++];
    sub_element->is_block = false;
    *sub_s_exp = &sub_element->s_exp;

    return true;
}

/*
 * Parse G10 S-exp.
 *
 * Supported format: (1:a2:ab(3:asd1:a))
 * It should be parsed to:
 *   - a
 *   - ab
 *   + - asd
 *     - a
 *
 */
static bool
parse_sexp(s_exp_t *s_exp, const char **r_bytes, size_t *r_length)
{
    size_t      length = *r_length;
    const char *bytes = *r_bytes;

    s_exp_t new_s_exp = {0};

    if (bytes == NULL || length == 0) {
        RNP_LOG("empty s-exp");
        return true;
    }

    if (*bytes != '(') { // doesn't start from (
        return false;
    }

    bytes++;
    length--;

    do {
        if (length <= 0) { // unexpected end
            RNP_LOG("s-exp finished before ')'");
            destroy_s_exp(&new_s_exp);
            return false;
        }

        if (*bytes == '(') {
            s_exp_t *new_sub_s_exp;

            if (!add_sub_sexp_to_sexp(&new_s_exp, &new_sub_s_exp)) {
                return false;
            }

            if (!parse_sexp(new_sub_s_exp, &bytes, &length)) {
                destroy_s_exp(&new_s_exp);
                return false;
            }

            continue;
        }

        char *next;
        long  len = strtol(bytes, &next, 10);

        if (*next != ':') { // doesn't contain :
            RNP_LOG("s-exp doesn't contain ':'");
            destroy_s_exp(&new_s_exp);
            return false;
        }

        next++;

        length -= (next - bytes);
        bytes = next;

        if (len == LONG_MIN || len == LONG_MAX || len <= 0 || (size_t) len >= length) {
            RNP_LOG(
              "len over/under flow or bigger than remaining bytes, len: %ld, length: %zu",
              len,
              length);
            destroy_s_exp(&new_s_exp);
            return false;
        }

        if (!add_block_to_sexp(&new_s_exp, (uint8_t *) bytes, (size_t) len)) {
            destroy_s_exp(&new_s_exp);
            return false;
        }

        bytes += len;
        length -= len;

    } while (*bytes != ')');

    bytes++;
    length--;

    *s_exp = new_s_exp;
    *r_bytes = bytes;
    *r_length = length;

    return true;
}

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

static unsigned
block_to_unsigned(s_exp_block_t *block)
{
    char s[sizeof(STR(UINT_MAX)) + 1] = {0};
    if (!block->len || block->len >= sizeof(s)) {
        return UINT_MAX;
    }

    memcpy(s, block->bytes, block->len);
    return (unsigned int) atoi(s);
}

static bool
add_unsigned_block_to_sexp(s_exp_t *s_exp, unsigned u)
{
    char s[sizeof(STR(UINT_MAX)) + 1];
    snprintf(s, sizeof(s), "%u", u);
    return add_block_to_sexp(s_exp, (uint8_t *) s, strlen(s));
}

static s_exp_t *
lookup_variable(s_exp_t *s_exp, const char *name)
{
    size_t name_len = strlen(name);
    for (unsigned i = 0; i < s_exp->sub_elementc; i++) {
        if (s_exp->sub_elements[i].is_block) {
            continue;
        }
        if (s_exp->sub_elements[i].s_exp.sub_elementc < 2 ||
            !s_exp->sub_elements[i].s_exp.sub_elements[0].is_block) {
            RNP_LOG("Expected sub-s-exp with 2 first blocks");
            return NULL;
        }
        if (name_len == s_exp->sub_elements[i].s_exp.sub_elements[0].block.len &&
            !strncmp(name,
                     (const char *) s_exp->sub_elements[i].s_exp.sub_elements[0].block.bytes,
                     s_exp->sub_elements[i].s_exp.sub_elements[0].block.len)) {
            return &s_exp->sub_elements[i].s_exp;
        }
    }
    RNP_LOG("Haven't got variable '%s'", name);
    return NULL;
}

static bool
read_mpi(s_exp_t *s_exp, const char *name, pgp_mpi_t *val)
{
    s_exp_t *var = lookup_variable(s_exp, name);
    if (var == NULL) {
        return false;
    }

    if (!var->sub_elements[1].is_block) {
        RNP_LOG("Expected block value");
        return false;
    }

    /* strip leading zero */
    if ((var->sub_elements[1].block.len > 1) && !var->sub_elements[1].block.bytes[0] &&
        (var->sub_elements[1].block.bytes[1] & 0x80)) {
        return mem2mpi(
          val, var->sub_elements[1].block.bytes + 1, var->sub_elements[1].block.len - 1);
    }

    return mem2mpi(val, var->sub_elements[1].block.bytes, var->sub_elements[1].block.len);
}

static bool
read_curve(s_exp_t *s_exp, const char *name, pgp_ec_key_t *key)
{
    s_exp_t *var = lookup_variable(s_exp, name);
    if (!var) {
        return false;
    }

    if (!var->sub_elements[1].is_block) {
        RNP_LOG("Expected block value");
        return false;
    }

    for (size_t i = 0; i < ARRAY_SIZE(g10_curve_aliases); i++) {
        if (strlen(g10_curve_aliases[i].string) != var->sub_elements[1].block.len) {
            continue;
        }
        if (!memcmp(g10_curve_aliases[i].string,
                    var->sub_elements[1].block.bytes,
                    var->sub_elements[1].block.len)) {
            key->curve = (pgp_curve_t) g10_curve_aliases[i].type;
            return true;
        }
    }

    RNP_LOG("Unknown curve: %.*s",
            (int) var->sub_elements[1].block.len,
            var->sub_elements[1].block.bytes);
    return false;
}

static bool
write_mpi(s_exp_t *s_exp, const char *name, const pgp_mpi_t *val)
{
    uint8_t  buf[PGP_MPINT_SIZE + 1] = {0};
    size_t   len;
    size_t   idx;
    s_exp_t *sub_s_exp;

    if (!add_sub_sexp_to_sexp(s_exp, &sub_s_exp)) {
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, name)) {
        return false;
    }

    len = mpi_bytes(val);
    for (idx = 0; (idx < len) && (val->mpi[idx] == 0); idx++)
        ;

    if (idx >= len) {
        return add_block_to_sexp(sub_s_exp, buf, 1);
    }

    if (val->mpi[idx] & 0x80) {
        memcpy(buf + 1, val->mpi + idx, len - idx);
        return add_block_to_sexp(sub_s_exp, buf, len - idx + 1);
    }

    return add_block_to_sexp(sub_s_exp, val->mpi + idx, len - idx);
}

static bool
write_curve(s_exp_t *s_exp, const char *name, const pgp_ec_key_t *key)
{
    const char *curve = NULL;
    s_exp_t *   sub_s_exp;

    ARRAY_LOOKUP_BY_ID(g10_curve_names, type, string, key->curve, curve);
    if (!curve) {
        RNP_LOG("unknown curve");
        return false;
    }

    if (!add_sub_sexp_to_sexp(s_exp, &sub_s_exp)) {
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, name)) {
        return false;
    }

    if (!add_string_block_to_sexp(sub_s_exp, curve)) {
        return false;
    }

    if (key->curve == PGP_CURVE_ED25519) {
        if (!add_sub_sexp_to_sexp(s_exp, &sub_s_exp)) {
            return false;
        }

        if (!add_string_block_to_sexp(sub_s_exp, "flags")) {
            return false;
        }

        if (!add_string_block_to_sexp(sub_s_exp, "eddsa")) {
            return false;
        }
    }

    return true;
}

static bool
parse_pubkey(pgp_key_pkt_t *pubkey, s_exp_t *s_exp, pgp_pubkey_alg_t alg)
{
    pubkey->version = PGP_V4;
    pubkey->alg = alg;
    pubkey->material.alg = alg;
    switch (alg) {
    case PGP_PKA_DSA:
        if (!read_mpi(s_exp, "p", &pubkey->material.dsa.p) ||
            !read_mpi(s_exp, "q", &pubkey->material.dsa.q) ||
            !read_mpi(s_exp, "g", &pubkey->material.dsa.g) ||
            !read_mpi(s_exp, "y", &pubkey->material.dsa.y)) {
            return false;
        }
        break;

    case PGP_PKA_RSA:
        if (!read_mpi(s_exp, "n", &pubkey->material.rsa.n) ||
            !read_mpi(s_exp, "e", &pubkey->material.rsa.e)) {
            return false;
        }
        break;

    case PGP_PKA_ELGAMAL:
        if (!read_mpi(s_exp, "p", &pubkey->material.eg.p) ||
            !read_mpi(s_exp, "g", &pubkey->material.eg.g) ||
            !read_mpi(s_exp, "y", &pubkey->material.eg.y)) {
            return false;
        }
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
        if (!read_curve(s_exp, "curve", &pubkey->material.ec) ||
            !read_mpi(s_exp, "q", &pubkey->material.ec.p)) {
            return false;
        }
        break;
    default:
        RNP_LOG("Unsupported public key algorithm: %d", (int) alg);
        return false;
    }

    return true;
}

static bool
parse_seckey(pgp_key_pkt_t *seckey, s_exp_t *s_exp, pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_DSA:
        if (!read_mpi(s_exp, "x", &seckey->material.dsa.x)) {
            return false;
        }
        break;

    case PGP_PKA_RSA:
        if (!read_mpi(s_exp, "d", &seckey->material.rsa.d) ||
            !read_mpi(s_exp, "p", &seckey->material.rsa.p) ||
            !read_mpi(s_exp, "q", &seckey->material.rsa.q) ||
            !read_mpi(s_exp, "u", &seckey->material.rsa.u)) {
            return false;
        }
        break;

    case PGP_PKA_ELGAMAL:
        if (!read_mpi(s_exp, "x", &seckey->material.eg.x)) {
            return false;
        }
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
        if (!read_mpi(s_exp, "d", &seckey->material.ec.x)) {
            return false;
        }
        break;
    default:
        RNP_LOG("Unsupported public key algorithm: %d", (int) alg);
        return false;
    }

    seckey->material.secret = true;
    return true;
}

static bool
decrypt_protected_section(const uint8_t *      encrypted_data,
                          size_t               encrypted_data_len,
                          const pgp_key_pkt_t *seckey,
                          const char *         password,
                          s_exp_t *            r_s_exp)
{
    const format_info *info = NULL;
    unsigned           keysize = 0;
    uint8_t            derived_key[PGP_MAX_KEY_SIZE];
    uint8_t *          decrypted_data = NULL;
    size_t             decrypted_data_len = 0;
    size_t             output_written = 0;
    size_t             input_consumed = 0;
    botan_cipher_t     decrypt = NULL;
    bool               ret = false;

    const char *decrypted_bytes;
    size_t      s_exp_len;

    // sanity checks
    const pgp_key_protection_t *prot = &seckey->sec_protection;
    keysize = pgp_key_size(prot->symm_alg);
    if (!keysize) {
        RNP_LOG("parse_seckey: unknown symmetric algo");
        goto done;
    }
    // find the protection format in our table
    info = find_format(prot->symm_alg, prot->cipher_mode, prot->s2k.hash_alg);
    if (!info) {
        RNP_LOG("Unsupported format, alg: %d, chiper_mode: %d, hash: %d",
                prot->symm_alg,
                prot->cipher_mode,
                prot->s2k.hash_alg);
        goto done;
    }

    // derive the key
    if (pgp_s2k_iterated(prot->s2k.hash_alg,
                         derived_key,
                         keysize,
                         password,
                         prot->s2k.salt,
                         prot->s2k.iterations)) {
        RNP_LOG("pgp_s2k_iterated failed");
        goto done;
    }
    RNP_DHEX("input iv", prot->iv, G10_CBC_IV_SIZE);
    RNP_DHEX("key", derived_key, keysize);
    RNP_DHEX("encrypted", encrypted_data, encrypted_data_len);

    // decrypt
    decrypted_data = (uint8_t *) malloc(encrypted_data_len);
    if (decrypted_data == NULL) {
        RNP_LOG("can't allocate memory");
        goto done;
    }
    if (botan_cipher_init(&decrypt, info->botan_cipher_name, BOTAN_CIPHER_INIT_FLAG_DECRYPT)) {
        RNP_LOG("botan_cipher_init failed");
        goto done;
    }
    if (botan_cipher_set_key(decrypt, derived_key, keysize) ||
        botan_cipher_start(decrypt, prot->iv, info->iv_size)) {
        goto done;
    }
    if (botan_cipher_update(decrypt,
                            BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                            decrypted_data,
                            encrypted_data_len,
                            &output_written,
                            encrypted_data,
                            encrypted_data_len,
                            &input_consumed)) {
        RNP_LOG("botan_cipher_update failed");
        goto done;
    }
    decrypted_data_len = output_written;
    s_exp_len = decrypted_data_len;
    decrypted_bytes = (const char *) decrypted_data;
    RNP_DHEX("decrypted data", decrypted_data, decrypted_data_len);

    // parse and validate the decrypted s-exp
    if (!parse_sexp(r_s_exp, &decrypted_bytes, &s_exp_len)) {
        goto done;
    }
    if (r_s_exp->sub_elementc == 0 || r_s_exp->sub_elements[0].is_block) {
        RNP_LOG("Hasn't got sub s-exp with key data.");
        goto done;
    }

    ret = true;

done:
    if (!ret) {
        destroy_s_exp(r_s_exp);
    }
    pgp_forget(decrypted_data, decrypted_data_len);
    free(decrypted_data);
    botan_cipher_destroy(decrypt);
    return ret;
}

static bool
parse_protected_seckey(pgp_key_pkt_t *seckey, s_exp_t *s_exp, const char *password)
{
    const format_info *   format;
    bool                  ret = false;
    s_exp_t               decrypted_s_exp = {0};
    s_exp_t *             protected_at_s_exp = NULL;
    s_exp_t *             alg = NULL;
    s_exp_t *             params = NULL;
    pgp_key_protection_t *prot;

    // find and validate the protected section
    s_exp_t *protected_key = lookup_variable(s_exp, "protected");
    if (!protected_key) {
        RNP_LOG("missing protected section");
        goto done;
    }
    if (protected_key->sub_elementc != 4 || !protected_key->sub_elements[1].is_block ||
        protected_key->sub_elements[2].is_block || !protected_key->sub_elements[3].is_block) {
        RNP_LOG("Wrong protected format, expected: (protected mode (parms) "
                "encrypted_octet_string)\n");
        goto done;
    }

    // lookup the protection format
    format = parse_format((const char *) protected_key->sub_elements[1].block.bytes,
                          protected_key->sub_elements[1].block.len);
    if (format == NULL) {
        RNP_LOG("Unsupported protected mode: '%.*s'\n",
                (int) protected_key->sub_elements[1].block.len,
                protected_key->sub_elements[1].block.bytes);
        goto done;
    }

    // fill in some fields based on the lookup above
    prot = &seckey->sec_protection;
    prot->symm_alg = format->cipher;
    prot->cipher_mode = format->cipher_mode;
    prot->s2k.hash_alg = format->hash_alg;

    // locate and validate the protection parameters
    params = &protected_key->sub_elements[2].s_exp;
    if (params->sub_elementc != 2 || params->sub_elements[0].is_block ||
        !params->sub_elements[1].is_block) {
        RNP_LOG("Wrong params format, expected: ((hash salt no_of_iterations) iv)\n");
        goto done;
    }

    // locate and validate the (hash salt no_of_iterations) exp
    alg = &params->sub_elements[0].s_exp;
    if (alg->sub_elementc != 3 || !alg->sub_elements[0].is_block ||
        !alg->sub_elements[1].is_block || !alg->sub_elements[2].is_block) {
        RNP_LOG("Wrong params sub-level format, expected: (hash salt no_of_iterations)\n");
        goto done;
    }
    if (strncmp("sha1",
                (const char *) alg->sub_elements[0].block.bytes,
                alg->sub_elements[0].block.len) != 0) {
        RNP_LOG("Wrong hashing algorithm, should be sha1 but %.*s\n",
                (int) alg->sub_elements[0].block.len,
                alg->sub_elements[0].block.bytes);
        goto done;
    }

    // fill in some constant values
    prot->s2k.hash_alg = PGP_HASH_SHA1;
    prot->s2k.usage = PGP_S2KU_ENCRYPTED_AND_HASHED;
    prot->s2k.specifier = PGP_S2KS_ITERATED_AND_SALTED;

    // check salt size
    if (alg->sub_elements[1].block.len != PGP_SALT_SIZE) {
        RNP_LOG("Wrong salt size, should be %d but %d\n",
                PGP_SALT_SIZE,
                (int) alg->sub_elements[1].block.len);
        goto done;
    }

    // salt
    memcpy(prot->s2k.salt, alg->sub_elements[1].block.bytes, alg->sub_elements[1].block.len);
    prot->s2k.iterations = block_to_unsigned(&alg->sub_elements[2].block);
    if (prot->s2k.iterations == UINT_MAX) {
        RNP_LOG("Wrong numbers of iteration, %.*s\n",
                (int) alg->sub_elements[2].block.len,
                alg->sub_elements[2].block.bytes);
        goto done;
    }

    // iv
    if (params->sub_elements[1].block.len != format->iv_size) {
        RNP_LOG("Wrong nonce size, should be %zu but %d\n",
                format->iv_size,
                (int) params->sub_elements[1].block.len);
        goto done;
    }
    memcpy(prot->iv, params->sub_elements[1].block.bytes, params->sub_elements[1].block.len);

    // we're all done if no password was provided (decryption not requested)
    if (!password) {
        seckey->material.secret = false;
        ret = true;
        goto done;
    }

    // password was provided, so decrypt
    if (!decrypt_protected_section(protected_key->sub_elements[3].block.bytes,
                                   protected_key->sub_elements[3].block.len,
                                   seckey,
                                   password,
                                   &decrypted_s_exp)) {
        goto done;
    }
    // see if we have a protected-at section
    protected_at_s_exp = lookup_variable(s_exp, "protected-at");
    char protected_at[G10_PROTECTED_AT_SIZE];
    if (protected_at_s_exp != NULL && protected_at_s_exp->sub_elements[1].is_block) {
        if (protected_at_s_exp->sub_elements[1].block.len != G10_PROTECTED_AT_SIZE) {
            RNP_LOG("protected-at has wrong length: %zu, expected, %d\n",
                    protected_at_s_exp->sub_elements[1].block.len,
                    G10_PROTECTED_AT_SIZE);
            goto done;
        }
        memcpy(protected_at,
               protected_at_s_exp->sub_elements[1].block.bytes,
               protected_at_s_exp->sub_elements[1].block.len);
    }
    // parse MPIs
    if (!parse_seckey(seckey, &decrypted_s_exp.sub_elements[0].s_exp, seckey->alg)) {
        RNP_LOG("failed to parse seckey");
        goto done;
    }
    // check hash, if present
    if (decrypted_s_exp.sub_elementc > 1) {
        if (decrypted_s_exp.sub_elements[1].is_block ||
            decrypted_s_exp.sub_elements[1].s_exp.sub_elementc < 3 ||
            !decrypted_s_exp.sub_elements[1].s_exp.sub_elements[0].is_block ||
            !decrypted_s_exp.sub_elements[1].s_exp.sub_elements[1].is_block ||
            !decrypted_s_exp.sub_elements[1].s_exp.sub_elements[2].is_block ||
            strncmp(
              "hash",
              (const char *) decrypted_s_exp.sub_elements[1].s_exp.sub_elements[0].block.bytes,
              decrypted_s_exp.sub_elements[1].s_exp.sub_elements[0].block.len) != 0) {
            RNP_LOG("Has got wrong hash block at encrypted key data.");
            goto done;
        }

        if (strncmp(
              "sha1",
              (const char *) decrypted_s_exp.sub_elements[1].s_exp.sub_elements[1].block.bytes,
              decrypted_s_exp.sub_elements[1].s_exp.sub_elements[1].block.len) != 0) {
            RNP_LOG("Supported only sha1 hash at encrypted private key.");
            goto done;
        }

        uint8_t checkhash[G10_SHA1_HASH_SIZE];
        if (!g10_calculated_hash(seckey, protected_at, checkhash)) {
            RNP_LOG("failed to calculate hash");
            goto done;
        }

        if (decrypted_s_exp.sub_elements[1].s_exp.sub_elements[2].block.len !=
              G10_SHA1_HASH_SIZE ||
            memcmp(checkhash,
                   decrypted_s_exp.sub_elements[1].s_exp.sub_elements[2].block.bytes,
                   G10_SHA1_HASH_SIZE) != 0) {
            RNP_DHEX("Expected hash", checkhash, G10_SHA1_HASH_SIZE);
            RNP_DHEX("Has hash",
                     decrypted_s_exp.sub_elements[1].s_exp.sub_elements[2].block.bytes,
                     decrypted_s_exp.sub_elements[1].s_exp.sub_elements[2].block.len);
            RNP_LOG("Incorrect hash at encrypted private key.");
            goto done;
        }
    }
    seckey->material.secret = true;
    ret = true;

done:
    destroy_s_exp(&decrypted_s_exp);
    return ret;
}

static bool
g10_parse_seckey(pgp_key_pkt_t *           seckey,
                 const uint8_t *           data,
                 size_t                    data_len,
                 const char *              password,
                 const pgp_key_provider_t *key_provider)
{
    s_exp_t          s_exp = {0};
    bool             ret = false;
    pgp_pubkey_alg_t alg = PGP_PKA_NOTHING;
    s_exp_t *        algorithm_s_exp = NULL;

    RNP_DHEX("S-exp", (const uint8_t *) data, data_len);

    const char *bytes = (const char *) data;
    if (!parse_sexp(&s_exp, &bytes, &data_len)) {
        goto done;
    }

    /* expected format:
     *  (<type>
     *    (<algo>
     *	   (x <mpi>)
     *	   (y <mpi>)
     *    )
     *  )
     */

    if (s_exp.sub_elementc != 2 || !s_exp.sub_elements[0].is_block ||
        s_exp.sub_elements[1].is_block) {
        RNP_LOG("Wrong format, expected: (<type> (...))");
        goto done;
    }

    bool is_protected;
    if (!strncmp("private-key",
                 (const char *) s_exp.sub_elements[0].block.bytes,
                 s_exp.sub_elements[0].block.len)) {
        is_protected = false;
    } else if (!strncmp("protected-private-key",
                        (const char *) s_exp.sub_elements[0].block.bytes,
                        s_exp.sub_elements[0].block.len)) {
        is_protected = true;
    } else {
        RNP_LOG("Unsupported top-level block: '%.*s'",
                (int) s_exp.sub_elements[0].block.len,
                s_exp.sub_elements[0].block.bytes);
        goto done;
    }

    algorithm_s_exp = &s_exp.sub_elements[1].s_exp;

    if (algorithm_s_exp->sub_elementc < 2) {
        RNP_LOG("Wrong count of algorithm-level elements: %d, should great than 1",
                algorithm_s_exp->sub_elementc);
        goto done;
    }

    if (!algorithm_s_exp->sub_elements[0].is_block) {
        RNP_LOG("Expected block with algorithm name, but has s-exp");
        goto done;
    }

    alg = PGP_PKA_NOTHING;
    for (size_t i = 0; i < ARRAY_SIZE(g10_alg_aliases); i++) {
        if (strlen(g10_alg_aliases[i].string) != algorithm_s_exp->sub_elements[0].block.len) {
            continue;
        }
        if (!memcmp(g10_alg_aliases[i].string,
                    algorithm_s_exp->sub_elements[0].block.bytes,
                    algorithm_s_exp->sub_elements[0].block.len)) {
            alg = (pgp_pubkey_alg_t) g10_alg_aliases[i].type;
            break;
        }
    }

    if (alg == PGP_PKA_NOTHING) {
        RNP_LOG("Unsupported algorithm: '%.*s'",
                (int) algorithm_s_exp->sub_elements[0].block.len,
                algorithm_s_exp->sub_elements[0].block.bytes);
        goto done;
    }

    if (!parse_pubkey(seckey, algorithm_s_exp, alg)) {
        RNP_LOG("failed to parse pubkey");
        goto done;
    }

    if (key_provider) {
        pgp_key_search_t search = {.type = PGP_KEY_SEARCH_GRIP};
        if (!rnp_key_store_get_key_grip(&seckey->material, search.by.grip)) {
            goto done;
        }
        pgp_key_t *pubkey = NULL;

        pgp_key_request_ctx_t req_ctx;
        memset(&req_ctx, 0, sizeof(req_ctx));
        req_ctx.op = PGP_OP_MERGE_INFO;
        req_ctx.secret = false;
        req_ctx.search = search;

        if (!(pubkey = pgp_request_key(key_provider, &req_ctx))) {
            goto done;
        }

        if (!copy_key_pkt(seckey, pgp_get_key_pkt(pubkey), false)) {
            goto done;
        }
    }

    if (is_protected) {
        if (!parse_protected_seckey(seckey, algorithm_s_exp, password)) {
            goto done;
        }
    } else {
        seckey->sec_protection.s2k.usage = PGP_S2KU_NONE;
        seckey->sec_protection.symm_alg = PGP_SA_PLAINTEXT;
        seckey->sec_protection.s2k.hash_alg = PGP_HASH_UNKNOWN;
        if (!parse_seckey(seckey, algorithm_s_exp, alg)) {
            RNP_LOG("failed to parse seckey");
            goto done;
        }
    }

    if (rnp_get_debug(__FILE__)) {
        uint8_t grip[PGP_FINGERPRINT_SIZE];
        char    grips[PGP_FINGERPRINT_HEX_SIZE];
        if (rnp_key_store_get_key_grip(&seckey->material, grip)) {
            RNP_LOG("loaded G10 key with GRIP: %s\n",
                    rnp_strhexdump_upper(grips, grip, PGP_FINGERPRINT_SIZE, ""));
        }
    }
    ret = true;

done:
    destroy_s_exp(&s_exp);
    if (!ret) {
        free_key_pkt(seckey);
    }
    return ret;
}

pgp_key_pkt_t *
g10_decrypt_seckey(const uint8_t *      data,
                   size_t               data_len,
                   const pgp_key_pkt_t *pubkey,
                   const char *         password)
{
    pgp_key_pkt_t *seckey = NULL;
    bool           ok = false;

    if (!password) {
        return NULL;
    }

    seckey = (pgp_key_pkt_t *) calloc(1, sizeof(*seckey));
    if (pubkey && !copy_key_pkt(seckey, pubkey, false)) {
        goto done;
    }
    if (!g10_parse_seckey(seckey, data, data_len, password, NULL)) {
        goto done;
    }
    ok = true;

done:
    if (!ok) {
        free(seckey);
        seckey = NULL;
    }
    return seckey;
}

bool
rnp_key_store_g10_from_mem(rnp_key_store_t *         key_store,
                           pgp_memory_t *            memory,
                           const pgp_key_provider_t *key_provider)
{
    pgp_key_t     key = {0};
    pgp_key_pkt_t keypkt = {0};
    bool          ret = false;

    if (!g10_parse_seckey(&keypkt, memory->buf, memory->length, NULL, key_provider)) {
        goto done;
    }
    if (!pgp_key_from_keypkt(&key, &keypkt, PGP_PTAG_CT_SECRET_KEY)) {
        goto done;
    }
    // this data belongs to the key now
    keypkt = (pgp_key_pkt_t){0};
    EXPAND_ARRAY((&key), packet);
    if (!key.packets) {
        goto done;
    }
    key.packets[0].raw = (uint8_t *) malloc(memory->length);
    if (!key.packets[0].raw) {
        goto done;
    }
    key.packets[0].length = memory->length;
    memcpy(key.packets[0].raw, memory->buf, memory->length);
    key.packetc++;
    key.format = G10_KEY_STORE;
    if (!rnp_key_store_add_key(key_store, &key)) {
        goto done;
    }
    ret = true;

done:
    if (!ret) {
        free_key_pkt(&keypkt);
        pgp_key_free_data(&key);
    }
    return ret;
}

#define MAX_SIZE_T_LEN ((3 * sizeof(size_t) * CHAR_BIT / 8) + 2)

static bool
write_block(s_exp_block_t *block, pgp_memory_t *mem)
{
    if (!pgp_memory_pad(mem, MAX_SIZE_T_LEN)) {
        return false;
    }
    mem->length +=
      snprintf((char *) (mem->buf + mem->length), MAX_SIZE_T_LEN, "%zu", block->len);

    if (!pgp_memory_add(mem, (const uint8_t *) ":", 1)) {
        return false;
    }

    return pgp_memory_add(mem, block->bytes, block->len);
}

/*
 * Write G10 S-exp to buffer
 *
 * Supported format: (1:a2:ab(3:asd1:a))
 */
static bool
write_sexp(s_exp_t *s_exp, pgp_memory_t *mem)
{
    if (!pgp_memory_add(mem, (const uint8_t *) "(", 1)) {
        return false;
    }

    for (unsigned i = 0; i < s_exp->sub_elementc; i++) {
        if (s_exp->sub_elements[i].is_block) {
            if (!write_block(&s_exp->sub_elements[i].block, mem)) {
                return false;
            }
        } else {
            if (!write_sexp(&s_exp->sub_elements[i].s_exp, mem)) {
                return false;
            }
        }
    }

    return pgp_memory_add(mem, (const uint8_t *) ")", 1);
}

static bool
write_pubkey(s_exp_t *s_exp, const pgp_key_pkt_t *key)
{
    const pgp_key_material_t *kmaterial = &key->material;
    switch (key->alg) {
    case PGP_PKA_DSA:
        if (!add_string_block_to_sexp(s_exp, "dsa")) {
            return false;
        }
        if (!write_mpi(s_exp, "p", &kmaterial->dsa.p) ||
            !write_mpi(s_exp, "q", &kmaterial->dsa.q) ||
            !write_mpi(s_exp, "g", &kmaterial->dsa.g) ||
            !write_mpi(s_exp, "y", &kmaterial->dsa.y)) {
            return false;
        }
        break;
    case PGP_PKA_RSA_SIGN_ONLY:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA:
        if (!add_string_block_to_sexp(s_exp, "rsa")) {
            return false;
        }
        if (!write_mpi(s_exp, "n", &kmaterial->rsa.n) ||
            !write_mpi(s_exp, "e", &kmaterial->rsa.e)) {
            return false;
        }
        break;
    case PGP_PKA_ELGAMAL:
        if (!add_string_block_to_sexp(s_exp, "elg")) {
            return false;
        }
        if (!write_mpi(s_exp, "p", &kmaterial->eg.p) ||
            !write_mpi(s_exp, "g", &kmaterial->eg.g) ||
            !write_mpi(s_exp, "y", &kmaterial->eg.y)) {
            return false;
        }
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
        if (!add_string_block_to_sexp(s_exp, "ecc")) {
            return false;
        }
        if (!write_curve(s_exp, "curve", &kmaterial->ec) ||
            !write_mpi(s_exp, "q", &kmaterial->ec.p)) {
            return false;
        }
        break;
    default:
        RNP_LOG("Unsupported public key algorithm: %d", (int) key->alg);
        return false;
    }

    return true;
}

static bool
write_seckey(s_exp_t *s_exp, const pgp_key_pkt_t *key)
{
    switch (key->alg) {
    case PGP_PKA_DSA:
        if (!write_mpi(s_exp, "x", &key->material.dsa.x)) {
            return false;
        }
        break;
    case PGP_PKA_RSA_SIGN_ONLY:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA:
        if (!write_mpi(s_exp, "d", &key->material.rsa.d) ||
            !write_mpi(s_exp, "p", &key->material.rsa.p) ||
            !write_mpi(s_exp, "q", &key->material.rsa.q) ||
            !write_mpi(s_exp, "u", &key->material.rsa.u)) {
            return false;
        }
        break;
    case PGP_PKA_ELGAMAL:
        if (!write_mpi(s_exp, "x", &key->material.eg.x)) {
            return false;
        }
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA: {
        if (!write_mpi(s_exp, "d", &key->material.ec.x)) {
            return false;
        }
        break;
    }
    default:
        RNP_LOG("Unsupported public key algorithm: %d", (int) key->alg);
        return false;
    }

    return true;
}

static bool
write_protected_seckey(s_exp_t *s_exp, pgp_key_pkt_t *seckey, const char *password)
{
    bool                  ret = false;
    const format_info *   format;
    s_exp_t               raw_s_exp = {0};
    s_exp_t *             sub_s_exp, *sub_sub_s_exp, *sub_sub_sub_s_exp;
    pgp_memory_t          raw = {0};
    uint8_t *             encrypted_data = NULL;
    botan_cipher_t        encrypt = NULL;
    unsigned              keysize;
    uint8_t               checksum[G10_SHA1_HASH_SIZE];
    uint8_t               derived_key[PGP_MAX_KEY_SIZE];
    pgp_key_protection_t *prot = &seckey->sec_protection;
    size_t                encrypted_data_len = 0;
    size_t                output_written, input_consumed;

    if (prot->s2k.specifier != PGP_S2KS_ITERATED_AND_SALTED) {
        return false;
    }
    format = find_format(prot->symm_alg, prot->cipher_mode, prot->s2k.hash_alg);
    if (format == NULL) {
        return false;
    }

    // randomize IV and salt
    rng_t rng = {0};
    if (!rng_init(&rng, RNG_SYSTEM) || !rng_get_data(&rng, &prot->iv[0], sizeof(prot->iv)) ||
        !rng_get_data(&rng, &prot->s2k.salt[0], sizeof(prot->s2k.salt))) {
        rng_destroy(&rng);
        return false;
    }
    rng_destroy(&rng);

    if (!add_sub_sexp_to_sexp(&raw_s_exp, &sub_s_exp) || !write_seckey(sub_s_exp, seckey)) {
        goto done;
    }

    // calculated hash
    time_t now;
    time(&now);
    char protected_at[G10_PROTECTED_AT_SIZE + 1];
    strftime(protected_at, sizeof(protected_at), "%Y%m%dT%H%M%S", gmtime(&now));

    if (!g10_calculated_hash(seckey, protected_at, checksum) ||
        !add_sub_sexp_to_sexp(&raw_s_exp, &sub_s_exp) ||
        !add_string_block_to_sexp(sub_s_exp, "hash") ||
        !add_string_block_to_sexp(sub_s_exp, "sha1") ||
        !add_block_to_sexp(sub_s_exp, checksum, sizeof(checksum)) ||
        !write_sexp(&raw_s_exp, &raw)) {
        goto done;
    }

    keysize = pgp_key_size(prot->symm_alg);
    if (keysize == 0) {
        goto done;
    }

    if (pgp_s2k_iterated(format->hash_alg,
                         derived_key,
                         keysize,
                         (const char *) password,
                         prot->s2k.salt,
                         prot->s2k.iterations)) {
        goto done;
    }

    // add padding!
    for (int i = (int) (format->chiper_block_size - raw.length % format->chiper_block_size);
         i > 0;
         i--) {
        if (!pgp_memory_add(&raw, (const uint8_t *) "X", 1)) {
            goto done;
        }
    }

    encrypted_data_len = raw.length;
    encrypted_data = (uint8_t *) malloc(encrypted_data_len);
    if (!encrypted_data) {
        goto done;
    }

    RNP_DHEX("input iv", prot->iv, G10_CBC_IV_SIZE);
    RNP_DHEX("key", derived_key, keysize);
    RNP_DHEX("raw data", raw.buf, raw.length);

    if (botan_cipher_init(
          &encrypt, format->botan_cipher_name, BOTAN_CIPHER_INIT_FLAG_ENCRYPT) ||
        botan_cipher_set_key(encrypt, derived_key, keysize) ||
        botan_cipher_start(encrypt, prot->iv, format->iv_size)) {
        goto done;
    }
    if (botan_cipher_update(encrypt,
                            BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                            encrypted_data,
                            encrypted_data_len,
                            &output_written,
                            raw.buf,
                            raw.length,
                            &input_consumed)) {
        goto done;
    }

    if (!add_sub_sexp_to_sexp(s_exp, &sub_s_exp) ||
        !add_string_block_to_sexp(sub_s_exp, "protected") ||
        !add_string_block_to_sexp(sub_s_exp, format->g10_type) ||
        !add_sub_sexp_to_sexp(sub_s_exp, &sub_sub_s_exp) ||
        !add_sub_sexp_to_sexp(sub_sub_s_exp, &sub_sub_sub_s_exp) ||
        !add_string_block_to_sexp(sub_sub_sub_s_exp, "sha1") ||
        !add_block_to_sexp(sub_sub_sub_s_exp, prot->s2k.salt, PGP_SALT_SIZE) ||
        !add_unsigned_block_to_sexp(sub_sub_sub_s_exp, prot->s2k.iterations) ||
        !add_block_to_sexp(sub_sub_s_exp, prot->iv, format->iv_size) ||
        !add_block_to_sexp(sub_s_exp, encrypted_data, encrypted_data_len) ||
        !add_sub_sexp_to_sexp(s_exp, &sub_s_exp) ||
        !add_string_block_to_sexp(sub_s_exp, "protected-at") ||
        !add_block_to_sexp(sub_s_exp, (uint8_t *) protected_at, G10_PROTECTED_AT_SIZE)) {
        goto done;
    }
    ret = true;

done:
    pgp_forget(derived_key, sizeof(derived_key));
    free(encrypted_data);
    destroy_s_exp(&raw_s_exp);
    pgp_memory_release(&raw);
    botan_cipher_destroy(encrypt);
    return ret;
}

bool
g10_write_seckey(pgp_dest_t *dst, pgp_key_pkt_t *seckey, const char *password)
{
    s_exp_t      s_exp = {0};
    s_exp_t *    sub_s_exp = NULL;
    pgp_memory_t mem = {0};
    bool         is_protected = true;
    bool         ret = false;

    switch (seckey->sec_protection.s2k.usage) {
    case PGP_S2KU_NONE:
        is_protected = false;
        break;
    case PGP_S2KU_ENCRYPTED_AND_HASHED:
        is_protected = true;
        // TODO: these are forced for now, until openpgp-native is implemented
        seckey->sec_protection.symm_alg = PGP_SA_AES_128;
        seckey->sec_protection.cipher_mode = PGP_CIPHER_MODE_CBC;
        seckey->sec_protection.s2k.hash_alg = PGP_HASH_SHA1;
        break;
    default:
        RNP_LOG("unsupported s2k usage");
        goto done;
    }
    if (!add_string_block_to_sexp(&s_exp,
                                  is_protected ? "protected-private-key" : "private-key") ||
        !add_sub_sexp_to_sexp(&s_exp, &sub_s_exp) || !write_pubkey(sub_s_exp, seckey)) {
        goto done;
    }
    if (is_protected) {
        if (!write_protected_seckey(sub_s_exp, seckey, password)) {
            goto done;
        }
    } else {
        if (!write_seckey(sub_s_exp, seckey)) {
            goto done;
        }
    }
    if (!write_sexp(&s_exp, &mem)) {
        goto done;
    }
    dst_write(dst, mem.buf, mem.length);
    ret = !dst->werr;
done:
    pgp_memory_release(&mem);
    destroy_s_exp(&s_exp);
    return ret;
}

static bool
g10_calculated_hash(const pgp_key_pkt_t *key, const char *protected_at, uint8_t *checksum)
{
    s_exp_t      s_exp = {0};
    s_exp_t *    sub_s_exp;
    pgp_memory_t mem = {0};
    pgp_hash_t   hash = {0};

    if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
        goto error;
    }

    if (hash._output_len != G10_SHA1_HASH_SIZE) {
        RNP_LOG(
          "wrong hash size %zu, should be %d bytes", hash._output_len, G10_SHA1_HASH_SIZE);
        goto error;
    }

    if (!write_pubkey(&s_exp, key)) {
        RNP_LOG("failed to write pubkey");
        goto error;
    }

    if (!write_seckey(&s_exp, key)) {
        RNP_LOG("failed to write seckey");
        goto error;
    }

    if (!add_sub_sexp_to_sexp(&s_exp, &sub_s_exp)) {
        goto error;
    }

    if (!add_string_block_to_sexp(sub_s_exp, "protected-at")) {
        goto error;
    }

    if (!add_block_to_sexp(sub_s_exp, (uint8_t *) protected_at, G10_PROTECTED_AT_SIZE)) {
        goto error;
    }

    if (!write_sexp(&s_exp, &mem)) {
        goto error;
    }

    destroy_s_exp(&s_exp);

    RNP_DHEX("data for hashing", mem.buf, mem.length);

    pgp_hash_add(&hash, mem.buf, mem.length);

    pgp_memory_release(&mem);

    if (!pgp_hash_finish(&hash, checksum)) {
        goto error;
    }

    return true;

error:
    destroy_s_exp(&s_exp);
    return false;
}

bool
rnp_key_store_g10_key_to_mem(pgp_key_t *key, pgp_memory_t *memory)
{
    if (DYNARRAY_IS_EMPTY(key, packet)) {
        return false;
    }
    if (key->format != G10_KEY_STORE) {
        RNP_LOG("incorrect format: %d", key->format);
        return false;
    }
    return pgp_memory_add(memory, key->packets[0].raw, key->packets[0].length);
}
