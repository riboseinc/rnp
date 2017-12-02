/*-
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
#ifndef FAUXBN_H_
#define FAUXBN_H_ 20100108

#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>

#define USE_BN_INTERFACE

#ifdef USE_BN_INTERFACE
#define BIGNUM PGPV_BIGNUM
#define BN_is_negative PGPV_BN_is_negative
#define BN_is_zero PGPV_BN_is_zero
#define BN_is_odd PGPV_BN_is_odd
#define BN_is_even PGPV_BN_is_even
#define BN_new PGPV_BN_new
#define BN_dup PGPV_BN_dup
#define BN_bin2bn PGPV_BN_bin2bn
#define BN_copy PGPV_BN_copy
#define BN_init PGPV_BN_init
#define BN_free PGPV_BN_free
#define BN_clear PGPV_BN_clear
#define BN_clear_free PGPV_BN_clear_free
#define BN_cmp PGPV_BN_cmp
#define BN_bn2bin PGPV_BN_bn2bin
#define BN_bn2hex PGPV_BN_bn2hex
#define BN_bn2dec PGPV_BN_bn2dec
#define BN_bn2radix PGPV_BN_bn2radix
#define BN_hex2bn PGPV_BN_hex2bn
#define BN_dec2bn PGPV_BN_dec2bn
#define BN_radix2bn PGPV_BN_radix2bn
#define BN_print_fp PGPV_BN_print_fp
#define BN_add PGPV_BN_add
#define BN_sub PGPV_BN_sub
#define BN_mul PGPV_BN_mul
#define BN_div PGPV_BN_div
#define BN_swap PGPV_BN_swap
#define BN_lshift PGPV_BN_lshift
#define BN_lshift1 PGPV_BN_lshift1
#define BN_rshift PGPV_BN_rshift
#define BN_rshift1 PGPV_BN_rshift1
#define BN_set_word PGPV_BN_set_word
#define BN_set_negative PGPV_BN_set_negative
#define BN_mod_exp PGPV_BN_mod_exp
#define BN_mod_inverse PGPV_BN_mod_inverse
#define BN_mod_mul PGPV_BN_mod_mul
#define BN_mod_sub PGPV_BN_mod_sub
#define BN_raise PGPV_BN_raise
#define BN_factorial PGPV_BN_factorial
#define BN_rand PGPV_BN_rand
#define BN_rand_range PGPV_BN_rand_range
#define BN_is_prime PGPV_BN_is_prime
#define BN_value_one PGPV_BN_value_one
#define BN_is_bit_set PGPV_BN_is_bit_set
#define BN_gcd PGPV_BN_gcd
#define BN_words_used PGPV_BN_words_used
#endif /* USE_BN_INTERFACE */

typedef struct botan_mp_struct *botan_mp_t;

/*
 * PGPV_BIGNUM struct
 */
typedef struct PGPV_BIGNUM_st {
    botan_mp_t mp;
} PGPV_BIGNUM;

#define MP_LT -1
#define MP_EQ 0
#define MP_GT 1

#define MP_ZPOS 0
#define MP_NEG 1

#define MP_OKAY 0
#define MP_MEM -2
#define MP_VAL -3
#define MP_RANGE MP_VAL

/*********************************/

PGPV_BIGNUM *PGPV_BN_new(void);
PGPV_BIGNUM *PGPV_BN_dup(const PGPV_BIGNUM * /*a*/);
int          PGPV_BN_copy(PGPV_BIGNUM * /*b*/, const PGPV_BIGNUM * /*a*/);

void PGPV_BN_init(PGPV_BIGNUM * /*a*/);
void PGPV_BN_free(PGPV_BIGNUM * /*a*/);
void PGPV_BN_clear(PGPV_BIGNUM * /*a*/);
void PGPV_BN_clear_free(PGPV_BIGNUM * /*a*/);

int PGPV_BN_cmp(PGPV_BIGNUM * /*a*/, PGPV_BIGNUM * /*b*/);

int PGPV_BN_is_even(const PGPV_BIGNUM *n);
int PGPV_BN_is_odd(const PGPV_BIGNUM *n);
int PGPV_BN_is_zero(const PGPV_BIGNUM *n);
int PGPV_BN_is_negative(const PGPV_BIGNUM *n);

PGPV_BIGNUM *PGPV_BN_bin2bn(const uint8_t * /*buf*/, int /*size*/, PGPV_BIGNUM * /*bn*/);
int          PGPV_BN_bn2bin(const PGPV_BIGNUM * /*a*/, unsigned char * /*b*/);
char *       PGPV_BN_bn2hex(const PGPV_BIGNUM * /*a*/);
char *       PGPV_BN_bn2dec(const PGPV_BIGNUM * /*a*/);
char *       PGPV_BN_bn2radix(const PGPV_BIGNUM * /*a*/, unsigned /*radix*/);
int          PGPV_BN_hex2bn(PGPV_BIGNUM ** /*a*/, const char * /*str*/);
int          PGPV_BN_dec2bn(PGPV_BIGNUM ** /*a*/, const char * /*str*/);
int          PGPV_BN_radix2bn(PGPV_BIGNUM ** /*a*/, const char * /*str*/, unsigned /*radix*/);
int          PGPV_BN_print_fp(FILE * /*fp*/, const PGPV_BIGNUM * /*a*/);

int PGPV_BN_add(PGPV_BIGNUM * /*r*/, const PGPV_BIGNUM * /*a*/, const PGPV_BIGNUM * /*b*/);
int PGPV_BN_sub(PGPV_BIGNUM * /*r*/, const PGPV_BIGNUM * /*a*/, const PGPV_BIGNUM * /*b*/);
int PGPV_BN_mul(PGPV_BIGNUM * /*r*/, const PGPV_BIGNUM * /*a*/, const PGPV_BIGNUM * /*b*/);
int PGPV_BN_div(PGPV_BIGNUM * /*q*/,
                PGPV_BIGNUM * /*r*/,
                const PGPV_BIGNUM * /*a*/,
                const PGPV_BIGNUM * /*b*/);
void PGPV_BN_swap(PGPV_BIGNUM * /*a*/, PGPV_BIGNUM * /*b*/);
int  PGPV_BN_lshift(PGPV_BIGNUM * /*r*/, const PGPV_BIGNUM * /*a*/, int /*n*/);
int  PGPV_BN_lshift1(PGPV_BIGNUM * /*r*/, PGPV_BIGNUM * /*a*/);
int  PGPV_BN_rshift(PGPV_BIGNUM * /*r*/, const PGPV_BIGNUM * /*a*/, int /*n*/);
int  PGPV_BN_rshift1(PGPV_BIGNUM * /*r*/, PGPV_BIGNUM * /*a*/);

typedef uint32_t PGPV_BN_ULONG;
size_t PGPV_BN_words_used(const PGPV_BIGNUM *n);
PGPV_BN_ULONG PGPV_BN_get_word(const PGPV_BIGNUM *n);
int PGPV_BN_set_word(PGPV_BIGNUM * /*a*/, PGPV_BN_ULONG /*w*/);

void PGPV_BN_set_negative(PGPV_BIGNUM * /*a*/, int /*n*/);

/*
 * @param a Initialized PGPV_BIGNUM structure
 * @param bits [out] bitlength of a
 *
 * @returns true on success, otherwise false
 */
bool BN_num_bits(const PGPV_BIGNUM *a, size_t *bits);
/*
 * @param a Initialized PGPV_BIGNUM structure
 * @param bytes [out] byte length of a
 *
 * @returns true on success, otherwise false
 */
bool BN_num_bytes(const PGPV_BIGNUM *a, size_t *bytes);

int PGPV_BN_mod_exp(PGPV_BIGNUM * /*r*/,
                    PGPV_BIGNUM * /*a*/,
                    PGPV_BIGNUM * /*p*/,
                    PGPV_BIGNUM * /*m*/);
PGPV_BIGNUM *PGPV_BN_mod_inverse(PGPV_BIGNUM * /*ret*/,
                                 PGPV_BIGNUM * /*a*/,
                                 const PGPV_BIGNUM * /*n*/);

int PGPV_BN_mod_mul(PGPV_BIGNUM * /*ret*/,
                    PGPV_BIGNUM * /*a*/,
                    PGPV_BIGNUM * /*b*/,
                    const PGPV_BIGNUM * /*m*/);

int PGPV_BN_rand(PGPV_BIGNUM * /*rnd*/, int /*bits*/, int /*top*/, int /*bottom*/);
int PGPV_BN_rand_range(PGPV_BIGNUM * /*rnd*/, PGPV_BIGNUM * /*range*/);

int PGPV_BN_is_prime(const PGPV_BIGNUM * /*a*/,
                     int /*checks*/,
                     void (*callback)(int, int, void *),
                     void * /*cb_arg*/);

const PGPV_BIGNUM *PGPV_BN_value_one(void);
int                PGPV_BN_is_bit_set(const PGPV_BIGNUM * /*a*/, int /*n*/);

int PGPV_BN_gcd(PGPV_BIGNUM * /*r*/, PGPV_BIGNUM * /*a*/, PGPV_BIGNUM * /*b*/);

/*
* This type is used to represent any signature where
* a pair of MPIs is used (DSA, ECDSA, EdDSA, ...)
*/
typedef struct DSA_SIG_st {
    BIGNUM *r;
    BIGNUM *s;
} DSA_SIG;

DSA_SIG *DSA_SIG_new(void);
void DSA_SIG_free(DSA_SIG *sig);

#endif
