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
#include <assert.h>
#include "bn.h"
#include "logging.h"

/* store in unsigned [big endian] format */
int
bn_bn2bin(const bignum_t *a, unsigned char *b)
{
    if (!a || !b) {
        return -1;
    }
    return BN_bn2bin(a, b) >= 0 ? 0 : -1;
}

bignum_t *
mpi2bn(const pgp_mpi_t *val)
{
    assert(val);
    if (!val) {
        RNP_LOG("NULL val.");
        return NULL;
    }
    bignum_t *res = bn_new();
    if (!res) {
        return NULL;
    }
    if (!BN_bin2bn(val->mpi, val->len, res)) {
        bn_free(res);
        res = NULL;
    }
    return res;
}

bool
bn2mpi(const bignum_t *bn, pgp_mpi_t *val)
{
    val->len = bn_num_bytes(*bn);
    return bn_bn2bin(bn, val->mpi) == 0;
}

bignum_t *
bn_new(void)
{
    return BN_new();
}

void
bn_free(bignum_t *a)
{
    BN_clear_free(a);
}

size_t
bn_num_bytes(const bignum_t &a)
{
    return (BN_num_bits(&a) + 7) / 8;
}
