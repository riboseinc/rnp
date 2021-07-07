/*-
 * Copyright (c) 2017-2021 Ribose Inc.
 * Copyright (c) 2012 Alistair Crooks <agc@NetBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RNP_BN_H_
#define RNP_BN_H_

#include <stdio.h>
#include <stdint.h>
#include "config.h"
#include "mpi.h"

#if defined(CRYPTO_BACKEND_OPENSSL)
#include <openssl/bn.h>

#define bignum_t BIGNUM
#elif defined(CRYPTO_BACKEND_BOTAN)
typedef struct botan_mp_struct *botan_mp_t;
typedef struct bignum_t_st {
    botan_mp_t mp;
} bignum_t;

#define BN_HANDLE(x) ((x).mp)
#define BN_HANDLE_PTR(x) ((x)->mp)
#else
#error "Unknown crypto backend."
#endif

/*********************************/

bignum_t *bn_new(void);
void      bn_free(bignum_t * /*a*/);

int bn_bn2bin(const bignum_t * /*a*/, unsigned char * /*b*/);

bignum_t *mpi2bn(const pgp_mpi_t *val);

bool bn2mpi(const bignum_t *bn, pgp_mpi_t *val);

size_t bn_num_bytes(const bignum_t &a);

#endif
