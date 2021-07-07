/*
 * Copyright (c) 2021, [Ribose Inc](https://www.ribose.com).
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

#include "ecdh_utils.h"
#include "types.h"
#include "utils.h"
#include <cassert>

/* Used by ECDH keys. Specifies which hash and wrapping algorithm
 * to be used (see point 15. of RFC 4880).
 *
 * Note: sync with ec_curves.
 */
static const struct ecdh_params_t {
    pgp_curve_t    curve;    /* Curve ID */
    pgp_hash_alg_t hash;     /* Hash used by kdf */
    pgp_symm_alg_t wrap_alg; /* Symmetric algorithm used to wrap KEK*/
} ecdh_params[] = {
  {.curve = PGP_CURVE_NIST_P_256, .hash = PGP_HASH_SHA256, .wrap_alg = PGP_SA_AES_128},
  {.curve = PGP_CURVE_NIST_P_384, .hash = PGP_HASH_SHA384, .wrap_alg = PGP_SA_AES_192},
  {.curve = PGP_CURVE_NIST_P_521, .hash = PGP_HASH_SHA512, .wrap_alg = PGP_SA_AES_256},
  {.curve = PGP_CURVE_BP256, .hash = PGP_HASH_SHA256, .wrap_alg = PGP_SA_AES_128},
  {.curve = PGP_CURVE_BP384, .hash = PGP_HASH_SHA384, .wrap_alg = PGP_SA_AES_192},
  {.curve = PGP_CURVE_BP512, .hash = PGP_HASH_SHA512, .wrap_alg = PGP_SA_AES_256},
  {.curve = PGP_CURVE_25519, .hash = PGP_HASH_SHA256, .wrap_alg = PGP_SA_AES_128},
  {.curve = PGP_CURVE_P256K1, .hash = PGP_HASH_SHA256, .wrap_alg = PGP_SA_AES_128},
};

// "Anonymous Sender " in hex
static const unsigned char ANONYMOUS_SENDER[] = {0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F,
                                                 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64,
                                                 0x65, 0x72, 0x20, 0x20, 0x20, 0x20};

// returns size of data written to other_info
size_t
kdf_other_info_serialize(uint8_t                  other_info[MAX_SP800_56A_OTHER_INFO],
                         const ec_curve_desc_t *  ec_curve,
                         const pgp_fingerprint_t &fingerprint,
                         const pgp_hash_alg_t     kdf_hash,
                         const pgp_symm_alg_t     wrap_alg)
{
    assert(fingerprint.length >= 20);
    uint8_t *buf_ptr = &other_info[0];

    /* KDF-OtherInfo: AlgorithmID
     *   Current implementation will always use SHA-512 and AES-256 for KEK wrapping
     */
    *(buf_ptr++) = ec_curve->OIDhex_len;
    memcpy(buf_ptr, ec_curve->OIDhex, ec_curve->OIDhex_len);
    buf_ptr += ec_curve->OIDhex_len;
    *(buf_ptr++) = PGP_PKA_ECDH;
    // size of following 3 params (each 1 byte)
    *(buf_ptr++) = 0x03;
    // Value reserved for future use
    *(buf_ptr++) = 0x01;
    // Hash used with KDF
    *(buf_ptr++) = kdf_hash;
    // Algorithm ID used for key wrapping
    *(buf_ptr++) = wrap_alg;

    /* KDF-OtherInfo: PartyUInfo
     *   20 bytes representing "Anonymous Sender "
     */
    memcpy(buf_ptr, ANONYMOUS_SENDER, sizeof(ANONYMOUS_SENDER));
    buf_ptr += sizeof(ANONYMOUS_SENDER);

    // keep 20, as per spec
    memcpy(buf_ptr, fingerprint.fingerprint, 20);
    return (buf_ptr - other_info) + 20 /*anonymous_sender*/;
}

bool
pad_pkcs7(uint8_t *buf, size_t buf_len, size_t offset)
{
    if (buf_len <= offset) {
        // Must have at least 1 byte of padding
        return false;
    }

    const uint8_t pad_byte = buf_len - offset;
    memset(buf + offset, pad_byte, pad_byte);
    return true;
}

bool
unpad_pkcs7(uint8_t *buf, size_t buf_len, size_t *offset)
{
    if (!buf || !offset || !buf_len) {
        return false;
    }

    uint8_t        err = 0;
    const uint8_t  pad_byte = buf[buf_len - 1];
    const uint32_t pad_begin = buf_len - pad_byte;

    // TODO: Still >, <, and <=,==  are not constant time (maybe?)
    err |= (pad_byte > buf_len);
    err |= (pad_byte == 0);

    /* Check if padding is OK */
    for (size_t c = 0; c < buf_len; c++) {
        err |= (buf[c] ^ pad_byte) * (pad_begin <= c);
    }

    *offset = pad_begin;
    return (err == 0);
}

bool
ecdh_set_params(pgp_ec_key_t *key, pgp_curve_t curve_id)
{
    for (size_t i = 0; i < ARRAY_SIZE(ecdh_params); i++) {
        if (ecdh_params[i].curve == curve_id) {
            key->kdf_hash_alg = ecdh_params[i].hash;
            key->key_wrap_alg = ecdh_params[i].wrap_alg;
            return true;
        }
    }

    return false;
}
