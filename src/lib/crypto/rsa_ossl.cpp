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

#include <string>
#include <cstring>
#include "crypto/rsa.h"
#include "hash.h"
#include "config.h"
#include "utils.h"
#include "bn.h"
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>

static RSA *
rsa_load_public_key(const pgp_rsa_key_t *key)
{
    RSA *     rsa = NULL;
    bignum_t *n = mpi2bn(&key->n);
    bignum_t *e = mpi2bn(&key->e);

    if (!n || !e) {
        RNP_LOG("out of memory");
        goto done;
    }
    rsa = RSA_new();
    if (!rsa) {
        RNP_LOG("Out of memory");
        goto done;
    }
    if (RSA_set0_key(rsa, n, e, NULL) != 1) {
        RNP_LOG("Public key load error: %lu", ERR_peek_last_error());
        RSA_free(rsa);
        rsa = NULL;
        goto done;
    }
done:
    /* OpenSSL set0 function transfers ownership of bignums */
    if (!rsa) {
        bn_free(n);
        bn_free(e);
    }
    return rsa;
}

static RSA *
rsa_load_secret_key(const pgp_rsa_key_t *key)
{
    RSA *     rsa = NULL;
    bignum_t *n = mpi2bn(&key->n);
    bignum_t *e = mpi2bn(&key->e);
    bignum_t *p = mpi2bn(&key->p);
    bignum_t *q = mpi2bn(&key->q);
    bignum_t *d = mpi2bn(&key->d);

    if (!n || !p || !q || !e || !d) {
        RNP_LOG("out of memory");
        goto done;
    }

    rsa = RSA_new();
    if (!rsa) {
        RNP_LOG("Out of memory");
        goto done;
    }
    if (RSA_set0_key(rsa, n, e, d) != 1) {
        RNP_LOG("Secret key load error: %lu", ERR_peek_last_error());
        RSA_free(rsa);
        rsa = NULL;
        goto done;
    }
    /* OpenSSL has p < q, as we do */
    if (RSA_set0_factors(rsa, p, q) != 1) {
        RNP_LOG("Factors load error: %lu", ERR_peek_last_error());
        RSA_free(rsa);
        rsa = NULL;
        goto done;
    }
done:
    /* OpenSSL set0 function transfers ownership of bignums */
    if (!rsa) {
        bn_free(n);
        bn_free(p);
        bn_free(q);
        bn_free(e);
        bn_free(d);
    }
    return rsa;
}

static EVP_PKEY_CTX *
rsa_init_context(const pgp_rsa_key_t *key, bool secret)
{
    EVP_PKEY *evpkey = EVP_PKEY_new();
    if (!evpkey) {
        RNP_LOG("allocation failed");
        return NULL;
    }
    EVP_PKEY_CTX *ctx = NULL;
    RSA *         rsakey = secret ? rsa_load_secret_key(key) : rsa_load_public_key(key);
    if (!rsakey) {
        goto done;
    }
    if (EVP_PKEY_set1_RSA(evpkey, rsakey) <= 0) {
        RNP_LOG("Failed to set key: %lu", ERR_peek_last_error());
        goto done;
    }
    ctx = EVP_PKEY_CTX_new(evpkey, NULL);
    if (!ctx) {
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error());
    }
done:
    RSA_free(rsakey);
    EVP_PKEY_free(evpkey);
    return ctx;
}

rnp_result_t
rsa_validate_key(rng_t *rng, const pgp_rsa_key_t *key, bool secret)
{
    if (secret) {
        EVP_PKEY_CTX *ctx = rsa_init_context(key, secret);
        if (!ctx) {
            return RNP_ERROR_GENERIC;
        }
        int res = EVP_PKEY_check(ctx);
        if (res < 0) {
            RNP_LOG("Key validation error: %lu", ERR_peek_last_error());
        }
        EVP_PKEY_CTX_free(ctx);
        return res > 0 ? RNP_SUCCESS : RNP_ERROR_GENERIC;
    }

    /* OpenSSL 1.1.1 doesn't have RSA public key check function, so let's do some checks */
    rnp_result_t ret = RNP_ERROR_GENERIC;
    bignum_t *   n = mpi2bn(&key->n);
    bignum_t *   e = mpi2bn(&key->e);
    if (!n || !e) {
        RNP_LOG("out of memory");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    if ((BN_num_bits(n) < 512) || !BN_is_odd(n) || (BN_num_bits(e) < 2) || !BN_is_odd(e)) {
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    bn_free(n);
    bn_free(e);
    return ret;
}

static bool
rsa_setup_context(EVP_PKEY_CTX *ctx, pgp_hash_alg_t hash_alg = PGP_HASH_UNKNOWN)
{
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        RNP_LOG("Failed to set padding: %lu", ERR_peek_last_error());
        return false;
    }
    if (hash_alg == PGP_HASH_UNKNOWN) {
        return true;
    }
    const char *hash_name = pgp_hash_name_openssl(hash_alg);
    if (!hash_name) {
        RNP_LOG("Unknown hash: %d", (int) hash_alg);
        return false;
    }
    const EVP_MD *hash_tp = EVP_get_digestbyname(hash_name);
    if (!hash_tp) {
        RNP_LOG("Error creating hash object for '%s'", hash_name);
        return false;
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, hash_tp) <= 0) {
        RNP_LOG("Failed to set digest: %lu", ERR_peek_last_error());
        return false;
    }
    return true;
}

rnp_result_t
rsa_encrypt_pkcs1(rng_t *              rng,
                  pgp_rsa_encrypted_t *out,
                  const uint8_t *      in,
                  size_t               in_len,
                  const pgp_rsa_key_t *key)
{
    rnp_result_t  ret = RNP_ERROR_GENERIC;
    EVP_PKEY_CTX *ctx = rsa_init_context(key, false);
    if (!ctx) {
        return ret;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        RNP_LOG("Failed to initialize encryption: %lu", ERR_peek_last_error());
        goto done;
    }
    if (!rsa_setup_context(ctx)) {
        goto done;
    }
    out->m.len = sizeof(out->m.mpi);
    if (EVP_PKEY_encrypt(ctx, out->m.mpi, &out->m.len, in, in_len) <= 0) {
        RNP_LOG("Encryption failed: %lu", ERR_peek_last_error());
        out->m.len = 0;
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

rnp_result_t
rsa_verify_pkcs1(const pgp_rsa_signature_t *sig,
                 pgp_hash_alg_t             hash_alg,
                 const uint8_t *            hash,
                 size_t                     hash_len,
                 const pgp_rsa_key_t *      key)
{
    rnp_result_t  ret = RNP_ERROR_SIGNATURE_INVALID;
    EVP_PKEY_CTX *ctx = rsa_init_context(key, false);
    if (!ctx) {
        return ret;
    }
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        RNP_LOG("Failed to initialize verification: %lu", ERR_peek_last_error());
        goto done;
    }
    if (!rsa_setup_context(ctx, hash_alg)) {
        goto done;
    }
    int res;
    if (sig->s.len < key->n.len) {
        /* OpenSSL doesn't like signatures smaller then N */
        pgp_mpi_t sn;
        sn.len = key->n.len;
        size_t diff = key->n.len - sig->s.len;
        memset(sn.mpi, 0, diff);
        memcpy(&sn.mpi[diff], sig->s.mpi, sig->s.len);
        res = EVP_PKEY_verify(ctx, sn.mpi, sn.len, hash, hash_len);
    } else {
        res = EVP_PKEY_verify(ctx, sig->s.mpi, sig->s.len, hash, hash_len);
    }
    if (res > 0) {
        ret = RNP_SUCCESS;
    } else {
        RNP_LOG("RSA verification failure: %s",
                ERR_reason_error_string(ERR_peek_last_error()));
    }
done:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

rnp_result_t
rsa_sign_pkcs1(rng_t *              rng,
               pgp_rsa_signature_t *sig,
               pgp_hash_alg_t       hash_alg,
               const uint8_t *      hash,
               size_t               hash_len,
               const pgp_rsa_key_t *key)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;
    if (mpi_bytes(&key->q) == 0) {
        RNP_LOG("private key not set");
        return ret;
    }
    EVP_PKEY_CTX *ctx = rsa_init_context(key, true);
    if (!ctx) {
        return ret;
    }
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        RNP_LOG("Failed to initialize signing: %lu", ERR_peek_last_error());
        goto done;
    }
    if (!rsa_setup_context(ctx, hash_alg)) {
        goto done;
    }
    sig->s.len = PGP_MPINT_SIZE;
    if (EVP_PKEY_sign(ctx, sig->s.mpi, &sig->s.len, hash, hash_len) <= 0) {
        RNP_LOG("Encryption failed: %lu", ERR_peek_last_error());
        sig->s.len = 0;
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

rnp_result_t
rsa_decrypt_pkcs1(rng_t *                    rng,
                  uint8_t *                  out,
                  size_t *                   out_len,
                  const pgp_rsa_encrypted_t *in,
                  const pgp_rsa_key_t *      key)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;
    if (mpi_bytes(&key->q) == 0) {
        RNP_LOG("private key not set");
        return ret;
    }
    EVP_PKEY_CTX *ctx = rsa_init_context(key, true);
    if (!ctx) {
        return ret;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        RNP_LOG("Failed to initialize encryption: %lu", ERR_peek_last_error());
        goto done;
    }
    if (!rsa_setup_context(ctx)) {
        goto done;
    }
    *out_len = PGP_MPINT_SIZE;
    if (EVP_PKEY_decrypt(ctx, out, out_len, in->m.mpi, in->m.len) <= 0) {
        RNP_LOG("Encryption failed: %lu", ERR_peek_last_error());
        *out_len = 0;
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

rnp_result_t
rsa_generate(rng_t *rng, pgp_rsa_key_t *key, size_t numbits)
{
    if ((numbits < 1024) || (numbits > PGP_MPINT_BITS)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t  ret = RNP_ERROR_GENERIC;
    RSA *         rsa = NULL;
    EVP_PKEY *    pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    bignum_t *    u = NULL;
    bignum_t *    nq = NULL;
    BN_CTX *      bnctx = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        RNP_LOG("Failed to create ctx: %lu", ERR_peek_last_error());
        return ret;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, numbits) <= 0) {
        RNP_LOG("Failed to set rsa bits: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        RNP_LOG("RSA keygen failed: %lu", ERR_peek_last_error());
        goto done;
    }
    rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        RNP_LOG("Failed to retrieve RSA key: %lu", ERR_peek_last_error());
        goto done;
    }
    if (RSA_check_key(rsa) != 1) {
        RNP_LOG("Key validation error: %lu", ERR_peek_last_error());
        goto done;
    }

    const bignum_t *n;
    const bignum_t *e;
    const bignum_t *p;
    const bignum_t *q;
    const bignum_t *d;
    n = RSA_get0_n(rsa);
    e = RSA_get0_e(rsa);
    d = RSA_get0_d(rsa);
    p = RSA_get0_p(rsa);
    q = RSA_get0_q(rsa);
    if (!n || !e || !d || !p || !q) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    /* we need to calculate u, since we need inverse of p mod q, while OpenSSL has inverse of q
     * mod p */
    bnctx = BN_CTX_new();
    u = BN_new();
    nq = BN_new();
    if (!ctx || !u || !nq) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    BN_with_flags(nq, RSA_get0_q(rsa), BN_FLG_CONSTTIME);
    /* calculate inverse of p mod q */
    if (!BN_mod_inverse(u, RSA_get0_p(rsa), nq, bnctx)) {
        bn_free(nq);
        RNP_LOG("Failed to calculate u");
        ret = RNP_ERROR_BAD_STATE;
        goto done;
    }
    bn_free(nq);
    bn2mpi(n, &key->n);
    bn2mpi(e, &key->e);
    bn2mpi(p, &key->p);
    bn2mpi(q, &key->q);
    bn2mpi(d, &key->d);
    bn2mpi(u, &key->u);
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BN_CTX_free(bnctx);
    bn_free(u);
    return ret;
}
