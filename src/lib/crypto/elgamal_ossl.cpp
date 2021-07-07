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

#include <cstdlib>
#include <string>
#include <cassert>
#include <rnp/rnp_def.h>
#include "elgamal.h"
#include "dl_ossl.h"
#include "utils.h"
#include "bn.h"
#include "mem.h"
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>

// Max supported key byte size
#define ELGAMAL_MAX_P_BYTELEN BITS_TO_BYTES(PGP_MPINT_BITS)

rnp_result_t
elgamal_validate_key(rng_t *rng, const pgp_eg_key_t *key, bool secret)
{
    /* OpenSSL doesn't implement ElGamal, however we may use DL via DH */
    EVP_PKEY *pkey = dl_load_key(key->p, NULL, key->g, key->y, NULL);
    if (!pkey) {
        RNP_LOG("Failed to load key");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp_result_t ret = dl_validate_key(pkey, secret ? &key->x : NULL);
    EVP_PKEY_free(pkey);
    return ret;
}

static bool
pkcs1v15_pad(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
    assert(out && in);
    if (out_len < in_len + 11) {
        return false;
    }
    out[0] = 0x00;
    out[1] = 0x02;
    size_t rnd = out_len - in_len - 3;
    out[2 + rnd] = 0x00;
    if (!rng_generate(&out[2], rnd)) {
        return false;
    }
    for (size_t i = 2; i < 2 + rnd; i++) {
        /* we need non-zero bytes */
        size_t cntr = 16;
        while (!out[i] && cntr) {
            rng_generate(&out[i], 1);
        }
        if (!out[i]) {
            RNP_LOG("Something is wrong with RNG.");
            return false;
        }
    }
    memcpy(out + rnd + 3, in, in_len);
    return true;
}

static bool
pkcs1v15_unpad(size_t *padlen, const uint8_t *in, size_t in_len, bool skip0)
{
    if (in_len <= (size_t)(11 - skip0)) {
        return false;
    }
    if (!skip0 && in[0]) {
        return false;
    }
    if (in[1 - skip0] != 0x02) {
        return false;
    }
    size_t pad = 2 - skip0;
    while ((pad < in_len) && in[pad]) {
        pad++;
    }
    if (pad >= in_len) {
        return false;
    }
    *padlen = pad + 1;
    return true;
}

rnp_result_t
elgamal_encrypt_pkcs1(rng_t *             rng,
                      pgp_eg_encrypted_t *out,
                      const uint8_t *     in,
                      size_t              in_len,
                      const pgp_eg_key_t *key)
{
    pgp_mpi_t mm = {};
    mm.len = key->p.len;
    if (!pkcs1v15_pad(mm.mpi, mm.len, in, in_len)) {
        RNP_LOG("Failed to add PKCS1 v1.5 padding.");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp_result_t ret = RNP_ERROR_GENERIC;
    BN_CTX *     ctx = BN_CTX_new();
    if (!ctx) {
        RNP_LOG("Allocation failed.");
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    BN_CTX_start(ctx);
    BN_MONT_CTX *mctx = BN_MONT_CTX_new();
    bignum_t *   m = mpi2bn(&mm);
    bignum_t *   p = mpi2bn(&key->p);
    bignum_t *   g = mpi2bn(&key->g);
    bignum_t *   y = mpi2bn(&key->y);
    bignum_t *   c1 = BN_CTX_get(ctx);
    bignum_t *   c2 = BN_CTX_get(ctx);
    bignum_t *   k = BN_secure_new();
    if (!mctx || !m || !p || !g || !y || !c1 || !c2 || !k) {
        RNP_LOG("Allocation failed.");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    /* initialize Montgomery context */
    if (BN_MONT_CTX_set(mctx, p, ctx) < 1) {
        RNP_LOG("Failed to setup Montgomery context.");
        goto done;
    }
    int res;
    /* must not fail */
    res = BN_rshift1(c1, p);
    assert(res == 1);
    if (res < 1) {
        RNP_LOG("BN_rshift1 failed.");
        goto done;
    }
    /* generate k */
    if (BN_rand_range(k, c1) < 1) {
        RNP_LOG("Failed to generate k.");
        goto done;
    }
    /* calculate c1 = g ^ k (mod p) */
    if (BN_mod_exp_mont_consttime(c1, g, k, p, ctx, mctx) < 1) {
        RNP_LOG("Exponentiation 1 failed");
        goto done;
    }
    /* calculate c2 = m * y ^ k (mod p)*/
    if (BN_mod_exp_mont_consttime(c2, y, k, p, ctx, mctx) < 1) {
        RNP_LOG("Exponentiation 2 failed");
        goto done;
    }
    if (BN_mod_mul(c2, c2, m, p, ctx) < 1) {
        RNP_LOG("Multiplication failed");
        goto done;
    }
    res = bn2mpi(c1, &out->g) && bn2mpi(c2, &out->m);
    assert(res == 1);
    ret = RNP_SUCCESS;
done:
    BN_MONT_CTX_free(mctx);
    BN_CTX_free(ctx);
    bn_free(m);
    bn_free(p);
    bn_free(g);
    bn_free(y);
    bn_free(k);
    return ret;
}

rnp_result_t
elgamal_decrypt_pkcs1(rng_t *                   rng,
                      uint8_t *                 out,
                      size_t *                  out_len,
                      const pgp_eg_encrypted_t *in,
                      const pgp_eg_key_t *      key)
{
    if (!mpi_bytes(&key->x)) {
        RNP_LOG("Secret key not set.");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        RNP_LOG("Allocation failed.");
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    pgp_mpi_t    mm = {};
    size_t       padlen = 0;
    rnp_result_t ret = RNP_ERROR_GENERIC;
    BN_CTX_start(ctx);
    BN_MONT_CTX *mctx = BN_MONT_CTX_new();
    bignum_t *   p = mpi2bn(&key->p);
    bignum_t *   g = mpi2bn(&key->g);
    bignum_t *   x = mpi2bn(&key->x);
    bignum_t *   c1 = mpi2bn(&in->g);
    bignum_t *   c2 = mpi2bn(&in->m);
    bignum_t *   s = BN_CTX_get(ctx);
    bignum_t *   m = BN_secure_new();
    if (!mctx || !p || !g || !x || !c1 || !c2 || !m) {
        RNP_LOG("Allocation failed.");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    /* initialize Montgomery context */
    if (BN_MONT_CTX_set(mctx, p, ctx) < 1) {
        RNP_LOG("Failed to setup Montgomery context.");
        goto done;
    }
    /* calculate s = c1 ^ x (mod p) */
    if (BN_mod_exp_mont_consttime(s, c1, x, p, ctx, mctx) < 1) {
        RNP_LOG("Exponentiation 1 failed");
        goto done;
    }
    /* calculate s^-1 (mod p) */
    BN_set_flags(s, BN_FLG_CONSTTIME);
    if (!BN_mod_inverse(s, s, p, ctx)) {
        RNP_LOG("Failed to calculate inverse.");
        goto done;
    }
    /* calculate m = c2 * s ^ -1 (mod p)*/
    if (BN_mod_mul(m, c2, s, p, ctx) < 1) {
        RNP_LOG("Multiplication failed");
        goto done;
    }
    bool res;
    res = bn2mpi(m, &mm);
    assert(res);
    if (!res) {
        RNP_LOG("bn2mpi failed.");
        goto done;
    }
    /* unpad, handling skipped leftmost 0 case */
    if (!pkcs1v15_unpad(&padlen, mm.mpi, mm.len, mm.len == key->p.len - 1)) {
        RNP_LOG("Unpad failed.");
        goto done;
    }
    *out_len = mm.len - padlen;
    memcpy(out, &mm.mpi[padlen], *out_len);
    ret = RNP_SUCCESS;
done:
    secure_clear(mm.mpi, PGP_MPINT_SIZE);
    BN_MONT_CTX_free(mctx);
    BN_CTX_free(ctx);
    bn_free(p);
    bn_free(g);
    bn_free(x);
    bn_free(c1);
    bn_free(c2);
    bn_free(m);
    return ret;
}

rnp_result_t
elgamal_generate(rng_t *rng, pgp_eg_key_t *key, size_t keybits)
{
    if ((keybits < 1024) || (keybits > PGP_MPINT_BITS)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t  ret = RNP_ERROR_GENERIC;
    DH *          dh = NULL;
    EVP_PKEY *    pkey = NULL;
    EVP_PKEY *    parmkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    /* Generate DH params, which usable for ElGamal as well */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!ctx) {
        RNP_LOG("Failed to create ctx: %lu", ERR_peek_last_error());
        return ret;
    }
    if (EVP_PKEY_paramgen_init(ctx) <= 0) {
        RNP_LOG("Failed to init keygen: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, keybits) <= 0) {
        RNP_LOG("Failed to set key bits: %lu", ERR_peek_last_error());
        goto done;
    }
    /* OpenSSL correctly handles case with g = 5, making sure that g is primitive root of
     * q-group */
    if (EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, DH_GENERATOR_5) <= 0) {
        RNP_LOG("Failed to set key generator: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_paramgen(ctx, &parmkey) <= 0) {
        RNP_LOG("Failed to generate parameters: %lu", ERR_peek_last_error());
        goto done;
    }
    EVP_PKEY_CTX_free(ctx);
    /* Generate DH (ElGamal) key */
start:
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
        RNP_LOG("ElGamal keygen failed: %lu", ERR_peek_last_error());
        goto done;
    }
    dh = EVP_PKEY_get0_DH(pkey);
    if (!dh) {
        RNP_LOG("Failed to retrieve DH key: %lu", ERR_peek_last_error());
        goto done;
    }
    if (BITS_TO_BYTES(BN_num_bits(DH_get0_pub_key(dh))) != BITS_TO_BYTES(keybits)) {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto start;
    }

    const bignum_t *p;
    const bignum_t *g;
    const bignum_t *y;
    const bignum_t *x;
    p = DH_get0_p(dh);
    g = DH_get0_g(dh);
    y = DH_get0_pub_key(dh);
    x = DH_get0_priv_key(dh);
    if (!p || !g || !y || !x) {
        ret = RNP_ERROR_BAD_STATE;
        goto done;
    }
    bn2mpi(p, &key->p);
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
