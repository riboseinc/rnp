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

#include <stdlib.h>
#include <string.h>
#include <rnp/rnp_def.h>
#include "bn.h"
#include "dsa.h"
#include "dl_ossl.h"
#include "hash.h"
#include "utils.h"
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define DSA_MAX_Q_BITLEN 256

static bool
dsa_decode_sig(const uint8_t *data, size_t len, pgp_dsa_signature_t &sig)
{
    DSA_SIG *dsig = d2i_DSA_SIG(NULL, &data, len);
    if (!dsig) {
        RNP_LOG("Failed to parse DSA sig: %lu", ERR_peek_last_error());
        return false;
    }
    const BIGNUM *r, *s;
    DSA_SIG_get0(dsig, &r, &s);
    bn2mpi(r, &sig.r);
    bn2mpi(s, &sig.s);
    DSA_SIG_free(dsig);
    return true;
}

static bool
dsa_encode_sig(uint8_t *data, size_t *len, const pgp_dsa_signature_t &sig)
{
    bool     res = false;
    DSA_SIG *dsig = DSA_SIG_new();
    BIGNUM * r = mpi2bn(&sig.r);
    BIGNUM * s = mpi2bn(&sig.s);
    if (!dsig || !r || !s) {
        RNP_LOG("Allocation failed.");
        goto done;
    }
    DSA_SIG_set0(dsig, r, s);
    r = NULL;
    s = NULL;
    int outlen;
    outlen = i2d_DSA_SIG(dsig, &data);
    if (outlen < 0) {
        RNP_LOG("Failed to encode signature.");
        goto done;
    }
    *len = outlen;
    res = true;
done:
    DSA_SIG_free(dsig);
    BN_free(r);
    BN_free(s);
    return res;
}

static EVP_PKEY *
dsa_load_key(const pgp_dsa_key_t *key, bool secret = false)
{
    DSA *     dsa = NULL;
    EVP_PKEY *evpkey = NULL;
    bignum_t *p = mpi2bn(&key->p);
    bignum_t *q = mpi2bn(&key->q);
    bignum_t *g = mpi2bn(&key->g);
    bignum_t *y = mpi2bn(&key->y);
    bignum_t *x = secret ? mpi2bn(&key->x) : NULL;

    if (!p || !q || !g || !y || (secret && !x)) {
        RNP_LOG("out of memory");
        goto done;
    }

    dsa = DSA_new();
    if (!dsa) {
        RNP_LOG("Out of memory");
        goto done;
    }
    if (DSA_set0_pqg(dsa, p, q, g) != 1) {
        RNP_LOG("Failed to set pqg. Error: %lu", ERR_peek_last_error());
        goto done;
    }
    p = NULL;
    q = NULL;
    g = NULL;
    if (DSA_set0_key(dsa, y, x) != 1) {
        RNP_LOG("Secret key load error: %lu", ERR_peek_last_error());
        goto done;
    }
    y = NULL;
    x = NULL;

    evpkey = EVP_PKEY_new();
    if (!evpkey) {
        RNP_LOG("allocation failed");
        goto done;
    }
    if (EVP_PKEY_set1_DSA(evpkey, dsa) <= 0) {
        RNP_LOG("Failed to set key: %lu", ERR_peek_last_error());
        EVP_PKEY_free(evpkey);
        evpkey = NULL;
    }
done:
    DSA_free(dsa);
    bn_free(p);
    bn_free(q);
    bn_free(g);
    bn_free(y);
    bn_free(x);
    return evpkey;
}

rnp_result_t
dsa_validate_key(rng_t *rng, const pgp_dsa_key_t *key, bool secret)
{
    /* OpenSSL doesn't implement key checks for the DSA, however we may use DL via DH */
    EVP_PKEY *pkey = dl_load_key(key->p, &key->q, key->g, key->y, NULL);
    if (!pkey) {
        RNP_LOG("Failed to load key");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp_result_t ret = dl_validate_key(pkey, secret ? &key->x : NULL);
    EVP_PKEY_free(pkey);
    return ret;
}

rnp_result_t
dsa_sign(rng_t *              rng,
         pgp_dsa_signature_t *sig,
         const uint8_t *      hash,
         size_t               hash_len,
         const pgp_dsa_key_t *key)
{
    if (mpi_bytes(&key->x) == 0) {
        RNP_LOG("private key not set");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* Load secret key to DSA structure*/
    EVP_PKEY *evpkey = dsa_load_key(key, true);
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
    if (!dsa_decode_sig(&sig->s.mpi[0], sig->s.len, *sig)) {
        RNP_LOG("Failed to parse DSA sig: %lu", ERR_peek_last_error());
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evpkey);
    return ret;
}

rnp_result_t
dsa_verify(const pgp_dsa_signature_t *sig,
           const uint8_t *            hash,
           size_t                     hash_len,
           const pgp_dsa_key_t *      key)
{
    /* Load secret key to DSA structure*/
    EVP_PKEY *evpkey = dsa_load_key(key, false);
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
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        RNP_LOG("Failed to initialize verify: %lu", ERR_peek_last_error());
        goto done;
    }
    pgp_mpi_t sigbuf;
    if (!dsa_encode_sig(sigbuf.mpi, &sigbuf.len, *sig)) {
        goto done;
    }
    if (EVP_PKEY_verify(ctx, sigbuf.mpi, sigbuf.len, hash, hash_len) <= 0) {
        ret = RNP_ERROR_SIGNATURE_INVALID;
    } else {
        ret = RNP_SUCCESS;
    }
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evpkey);
    return ret;
}

rnp_result_t
dsa_generate(rng_t *rng, pgp_dsa_key_t *key, size_t keylen, size_t qbits)
{
    if ((keylen < 1024) || (keylen > 3072) || (qbits < 160) || (qbits > 256)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t  ret = RNP_ERROR_GENERIC;
    DSA *         dsa = NULL;
    EVP_PKEY *    pkey = NULL;
    EVP_PKEY *    parmkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    /* Generate DSA params */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
    if (!ctx) {
        RNP_LOG("Failed to create ctx: %lu", ERR_peek_last_error());
        return ret;
    }
    if (EVP_PKEY_paramgen_init(ctx) <= 0) {
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, keylen) <= 0) {
        RNP_LOG("Failed to set key bits: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, qbits) <= 0) {
        RNP_LOG("Failed to set key qbits: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_paramgen(ctx, &parmkey) <= 0) {
        RNP_LOG("Failed to generate parameters: %lu", ERR_peek_last_error());
        goto done;
    }
    EVP_PKEY_CTX_free(ctx);
    /* Generate DSA key */
    ctx = EVP_PKEY_CTX_new(parmkey, NULL);
    if (!ctx) {
        RNP_LOG("Failed to create ctx: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        RNP_LOG("DSA keygen failed: %lu", ERR_peek_last_error());
        goto done;
    }
    dsa = EVP_PKEY_get0_DSA(pkey);
    if (!dsa) {
        RNP_LOG("Failed to retrieve DSA key: %lu", ERR_peek_last_error());
        goto done;
    }

    const bignum_t *p;
    const bignum_t *q;
    const bignum_t *g;
    const bignum_t *y;
    const bignum_t *x;
    p = DSA_get0_p(dsa);
    q = DSA_get0_q(dsa);
    g = DSA_get0_g(dsa);
    y = DSA_get0_pub_key(dsa);
    x = DSA_get0_priv_key(dsa);
    if (!p || !q || !g || !y || !x) {
        ret = RNP_ERROR_BAD_STATE;
        goto done;
    }
    bn2mpi(p, &key->p);
    bn2mpi(q, &key->q);
    bn2mpi(g, &key->g);
    bn2mpi(y, &key->y);
    bn2mpi(x, &key->x);
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(parmkey);
    EVP_PKEY_free(pkey);
    return ret;
}

pgp_hash_alg_t
dsa_get_min_hash(size_t qsize)
{
    /*
     * I'm using _broken_ SHA1 here only because
     * some old implementations may not understand keys created
     * with other hashes. If you're sure we don't have to support
     * such implementations, please be my guest and remove it.
     */
    return (qsize < 160)  ? PGP_HASH_UNKNOWN :
           (qsize == 160) ? PGP_HASH_SHA1 :
           (qsize <= 224) ? PGP_HASH_SHA224 :
           (qsize <= 256) ? PGP_HASH_SHA256 :
           (qsize <= 384) ? PGP_HASH_SHA384 :
           (qsize <= 512) ? PGP_HASH_SHA512
                            /*(qsize>512)*/ :
                            PGP_HASH_UNKNOWN;
}

size_t
dsa_choose_qsize_by_psize(size_t psize)
{
    return (psize == 1024) ? 160 :
           (psize <= 2047) ? 224 :
           (psize <= 3072) ? DSA_MAX_Q_BITLEN :
                             0;
}
