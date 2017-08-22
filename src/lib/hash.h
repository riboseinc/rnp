/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
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

#ifndef CRYPTO_HASH_H_
#define CRYPTO_HASH_H_

#include <rnp/rnp_sdk.h>
#include <repgp/repgp_def.h>
#include "types.h"
#include "utils.h"

/**
 * Output size (in bytes) of biggest supported hash algo
 */
#define PGP_MAX_HASH_SIZE BITS_TO_BYTES(512)

/** pgp_hash_t */
typedef struct pgp_hash_t {
    void *         handle; /* hash object */
    size_t         _output_len;
    pgp_hash_alg_t _alg; /* algorithm */
} pgp_hash_t;

const char *pgp_hash_name_botan(const pgp_hash_alg_t alg);

bool pgp_hash_create(pgp_hash_t *hash, pgp_hash_alg_t alg);
void pgp_hash_add(pgp_hash_t *hash, const uint8_t *input, size_t len);
void pgp_hash_add_int(pgp_hash_t *hash, unsigned n, size_t bytes);
size_t pgp_hash_finish(pgp_hash_t *hash, uint8_t *output);

size_t pgp_hash_output_length(const pgp_hash_t *hash);
const char *pgp_hash_name(const pgp_hash_t *hash);

pgp_hash_alg_t pgp_hash_alg_type(const pgp_hash_t *hash);

pgp_hash_alg_t pgp_str_to_hash_alg(const char *);

unsigned pgp_is_hash_alg_supported(const pgp_hash_alg_t *);

void pgp_calc_mdc_hash(
  const uint8_t *, const size_t, const uint8_t *, const unsigned, uint8_t *);

/* -----------------------------------------------------------------------------
 * @brief   Returns output size of an digest algorithm
 *
 * @param   [in] alg
 * @param   [out] output_length: must be not NULL
 *
 * @return  true if provided algorithm is supported and it's size was
 *          correctly retrieved, otherwise false
 *
-------------------------------------------------------------------------------- */
bool pgp_digest_length(pgp_hash_alg_t alg, size_t *output_length);

#endif
