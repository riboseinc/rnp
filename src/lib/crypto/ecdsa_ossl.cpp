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

#include "ecdsa.h"
#include "utils.h"
#include <string.h>
#include "bn.h"
#include "ec_ossl.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>

static bool
ecdsa_decode_sig(const uint8_t *data, size_t len, pgp_ec_signature_t &sig)
{
    ECDSA_SIG *esig = d2i_ECDSA_SIG(NULL, &data, len);
    if (!esig) {
        RNP_LOG("Failed to parse ECDSA sig: %lu", ERR_peek_last_error());
        return false;
    }
    const BIGNUM *r, *s;
    ECDSA_SIG_get0(esig, &r, &s);
    bn2mpi(r, &sig.r);
    bn2mpi(s, &sig.s);
    ECDSA_SIG_free(esig);
    return true;
}

static bool
ecdsa_encode_sig(uint8_t *data, size_t *len, const pgp_ec_signature_t &sig)
{
    bool       res = false;
    ECDSA_SIG *dsig = ECDSA_SIG_new();
    BIGNUM *   r = mpi2bn(&sig.r);
    BIGNUM *   s = mpi2bn(&sig.s);
    if (!dsig || !r || !s) {
        RNP_LOG("Allocation failed.");
        goto done;
    }
    ECDSA_SIG_set0(dsig, r, s);
    r = NULL;
    s = NULL;
    int outlen;
    outlen = i2d_ECDSA_SIG(dsig, &data);
    if (outlen < 0) {
        RNP_LOG("Failed to encode signature.");
        goto done;
    }
    *len = outlen;
    res = true;
done:
    ECDSA_SIG_free(dsig);
    BN_free(r);
    BN_free(s);
    return res;
}

rnp_result_t
ecdsa_validate_key(rng_t *rng, const pgp_ec_key_t *key, bool secret)
{
    return ec_validate_key(*key, secret);
}

rnp_result_t
ecdsa_sign(rng_t *             rng,
           pgp_ec_signature_t *sig,
           pgp_hash_alg_t      hash_alg,
           const uint8_t *     hash,
           size_t              hash_len,
           const pgp_ec_key_t *key)
{
    if (mpi_bytes(&key->x) == 0) {
        RNP_LOG("private key not set");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* Load secret key to DSA structure*/
    EVP_PKEY *evpkey = ec_load_key(key->p, &key->x, key->curve);
    if (!evpkey) {
        RNP_LOG("Failed to load key");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t ret = RNP_ERROR_GENERIC;
    /* init context and sign */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (!ctx) {
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        RNP_LOG("Failed to initialize signing: %lu", ERR_peek_last_error());
        goto done;
    }
    sig->s.len = PGP_MPINT_SIZE;
    if (EVP_PKEY_sign(ctx, sig->s.mpi, &sig->s.len, hash, hash_len) <= 0) {
        RNP_LOG("Signing failed: %lu", ERR_peek_last_error());
        sig->s.len = 0;
        goto done;
    }
    if (!ecdsa_decode_sig(&sig->s.mpi[0], sig->s.len, *sig)) {
        RNP_LOG("Failed to parse ECDSA sig: %lu", ERR_peek_last_error());
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evpkey);
    return ret;
}

rnp_result_t
ecdsa_verify(const pgp_ec_signature_t *sig,
             pgp_hash_alg_t            hash_alg,
             const uint8_t *           hash,
             size_t                    hash_len,
             const pgp_ec_key_t *      key)
{
    /* Load secret key to DSA structure*/
    EVP_PKEY *evpkey = ec_load_key(key->p, NULL, key->curve);
    if (!evpkey) {
        RNP_LOG("Failed to load key");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t ret = RNP_ERROR_SIGNATURE_INVALID;
    /* init context and sign */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (!ctx) {
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        RNP_LOG("Failed to initialize verify: %lu", ERR_peek_last_error());
        goto done;
    }
    pgp_mpi_t sigbuf;
    if (!ecdsa_encode_sig(sigbuf.mpi, &sigbuf.len, *sig)) {
        goto done;
    }
    if (EVP_PKEY_verify(ctx, sigbuf.mpi, sigbuf.len, hash, hash_len) > 0) {
        ret = RNP_SUCCESS;
    }
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evpkey);
    return ret;
}

pgp_hash_alg_t
ecdsa_get_min_hash(pgp_curve_t curve)
{
    switch (curve) {
    case PGP_CURVE_NIST_P_256:
    case PGP_CURVE_BP256:
    case PGP_CURVE_P256K1:
        return PGP_HASH_SHA256;
    case PGP_CURVE_NIST_P_384:
    case PGP_CURVE_BP384:
        return PGP_HASH_SHA384;
    case PGP_CURVE_NIST_P_521:
    case PGP_CURVE_BP512:
        return PGP_HASH_SHA512;
    default:
        return PGP_HASH_UNKNOWN;
    }
}
