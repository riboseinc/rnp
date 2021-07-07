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
#include "bn.h"
#include "dl_ossl.h"
#include "utils.h"
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>

EVP_PKEY *
dl_load_key(const pgp_mpi_t &mp,
            const pgp_mpi_t *mq,
            const pgp_mpi_t &mg,
            const pgp_mpi_t &my,
            const pgp_mpi_t *mx)
{
    DH *      dh = NULL;
    EVP_PKEY *evpkey = NULL;
    bignum_t *p = mpi2bn(&mp);
    bignum_t *q = mq ? mpi2bn(mq) : NULL;
    bignum_t *g = mpi2bn(&mg);
    bignum_t *y = mpi2bn(&my);
    bignum_t *x = mx ? mpi2bn(mx) : NULL;

    if (!p || (mq && !q) || !g || !y || (mx && !x)) {
        RNP_LOG("out of memory");
        goto done;
    }

    dh = DH_new();
    if (!dh) {
        RNP_LOG("out of memory");
        goto done;
    }
    int res;
    /* line below must not fail */
    res = DH_set0_pqg(dh, p, q, g);
    assert(res == 1);
    if (res < 1) {
        goto done;
    }
    p = NULL;
    q = NULL;
    g = NULL;
    /* line below must not fail */
    res = DH_set0_key(dh, y, x);
    assert(res == 1);
    if (res < 1) {
        goto done;
    }
    y = NULL;
    x = NULL;

    evpkey = EVP_PKEY_new();
    if (!evpkey) {
        RNP_LOG("allocation failed");
        goto done;
    }
    if (EVP_PKEY_set1_DH(evpkey, dh) <= 0) {
        RNP_LOG("Failed to set key: %lu", ERR_peek_last_error());
        EVP_PKEY_free(evpkey);
        evpkey = NULL;
    }
done:
    DH_free(dh);
    bn_free(p);
    bn_free(q);
    bn_free(g);
    bn_free(y);
    bn_free(x);
    return evpkey;
}

static rnp_result_t
dl_validate_secret_key(EVP_PKEY *dlkey, const pgp_mpi_t &mx)
{
    DH *dh = EVP_PKEY_get0_DH(dlkey);
    assert(dh);
    const bignum_t *p = DH_get0_p(dh);
    const bignum_t *q = DH_get0_q(dh);
    const bignum_t *g = DH_get0_g(dh);
    const bignum_t *y = DH_get0_pub_key(dh);
    assert(p && g && y);
    bignum_t *p1 = NULL;

    rnp_result_t ret = RNP_ERROR_GENERIC;

    BN_CTX *  ctx = BN_CTX_new();
    bignum_t *x = mpi2bn(&mx);
    bignum_t *cy = bn_new();

    if (!x || !cy || !ctx) {
        RNP_LOG("Allocation failed");
        goto done;
    }
    if (!q) {
        /* if q is NULL then group order is (p - 1) / 2 */
        p1 = BN_dup(p);
        if (!p1) {
            RNP_LOG("Allocation failed");
            goto done;
        }
        int res;
        res = BN_rshift(p1, p1, 1);
        assert(res == 1);
        if (res < 1) {
            RNP_LOG("BN_rshift failed.");
            goto done;
        }
        q = p1;
    }
    if (BN_cmp(x, q) != -1) {
        RNP_LOG("x is too large.");
        goto done;
    }
    if (BN_mod_exp_mont_consttime(cy, g, x, p, ctx, NULL) < 1) {
        RNP_LOG("Exponentiation failed");
        goto done;
    }
    if (BN_cmp(cy, y) == 0) {
        ret = RNP_SUCCESS;
    }
done:
    BN_CTX_free(ctx);
    bn_free(x);
    bn_free(cy);
    bn_free(p1);
    return ret;
}

rnp_result_t
dl_validate_key(EVP_PKEY *pkey, const pgp_mpi_t *x)
{
    rnp_result_t  ret = RNP_ERROR_GENERIC;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error());
        goto done;
    }
    int res;
    res = EVP_PKEY_param_check(ctx);
    if (res < 0) {
        RNP_LOG("Param validation error: %lu (%s)",
                ERR_peek_last_error(),
                ERR_reason_error_string(ERR_peek_last_error()));
    }
    if (res < 1) {
        /* ElGamal specification doesn't seem to restrict P to the safe prime */
        auto err = ERR_peek_last_error();
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_P_NOT_SAFE_PRIME);
        if ((ERR_GET_FUNC(err) == DH_F_DH_CHECK_EX) &&
            (ERR_GET_REASON(err) == DH_R_CHECK_P_NOT_SAFE_PRIME)) {
            RNP_LOG("Warning! P is not a safe prime.");
        } else {
            goto done;
        }
    }
    res = EVP_PKEY_public_check(ctx);
    if (res < 0) {
        RNP_LOG("Key validation error: %lu", ERR_peek_last_error());
    }
    if (res < 1) {
        goto done;
    }
    /* There is no private key check in OpenSSL yet, so need to check x vs y manually */
    if (!x) {
        ret = RNP_SUCCESS;
        goto done;
    }
    ret = dl_validate_secret_key(pkey, *x);
done:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}
