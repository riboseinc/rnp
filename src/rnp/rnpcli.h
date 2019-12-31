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
#ifndef RNPCLI_H_
#define RNPCLI_H_

#include <stddef.h>
#include <stdbool.h>
#include "rnp.h"
#include "rnpcfg.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct rnp_ctx_t       rnp_ctx_t;
typedef struct rnp_key_store_t rnp_key_store_t;

/* structure used to keep application-wide rnp configuration: keyrings, password io, whatever
 * else */
typedef struct rnp_t {
    rnp_key_store_t *pubring;       /* public key ring */
    rnp_key_store_t *secring;       /* s3kr1t key ring */
    FILE *           resfp;         /* where to put result messages, defaults to stdout */
    FILE *           user_input_fp; /* file pointer for user input */
    FILE *           passfp;        /* file pointer for password input */
    char *           defkey;        /* default key id */
    int              pswdtries;     /* number of password tries, -1 for unlimited */
    pgp_password_provider_t password_provider;
    pgp_key_provider_t      key_provider;
    rng_t                   rng; /* handle to rng_t */
} rnp_t;

/* initialize rnp using the init structure  */
rnp_result_t rnp_init(rnp_t *, const rnp_cfg_t *);
/* finish work with rnp and cleanup the memory */
void rnp_end(rnp_t *);
/* load keys */
bool rnp_load_keyrings(rnp_t *rnp, bool loadsecret);

/**
 * @brief Set keystore parameters to the rnp_cfg_t. This includes keyring pathes, types and
 *        default key.
 *
 * @param cfg pointer to the allocated rnp_cfg_t structure
 * @return true on success or false otherwise.
 * @return false
 */
bool cli_cfg_set_keystore_info(rnp_cfg_t *cfg);

/* key management */
void       rnp_print_key_info(FILE *, rnp_key_store_t *, const pgp_key_t *, bool);
bool       rnp_find_key(rnp_t *, const char *);
char *     rnp_export_key(rnp_t *, const char *, bool);
bool       rnp_add_key(rnp_t *rnp, const char *path, bool print);
pgp_key_t *resolve_userid(rnp_t *rnp, const rnp_key_store_t *keyring, const char *userid);

size_t     rnp_secret_count(rnp_t *);
size_t     rnp_public_count(rnp_t *);

/* file management */
rnp_result_t rnp_process_file(rnp_t *, rnp_ctx_t *, const char *, const char *);
rnp_result_t rnp_protect_file(rnp_t *, rnp_ctx_t *, const char *, const char *);
rnp_result_t rnp_dump_file(rnp_ctx_t *, const char *, const char *);

/* memory signing and encryption */
rnp_result_t rnp_process_mem(
  rnp_t *, rnp_ctx_t *, const void *, size_t, void *, size_t, size_t *);
rnp_result_t rnp_protect_mem(
  rnp_t *, rnp_ctx_t *, const void *, size_t, void *, size_t, size_t *);

/**
 * @brief   Armor (convert to ASCII) or dearmor (convert back to binary) PGP data
 *
 * @param   ctx  Initialized rnp context. Field armortype may specify the type of armor
 *               header used, otherwise it will be detected automatically from the source.
 * @param   in   Input file path
 * @param   out  Output file path
 *
 * @return  RNP_SUCCESS on success, error code on failure
 */
rnp_result_t rnp_armor_stream(rnp_ctx_t *ctx, bool armor, const char *in, const char *out);

rnp_result_t rnp_validate_keys_signatures(rnp_t *rnp);

rnp_result_t rnp_encrypt_add_password(rnp_t *rnp, rnp_ctx_t *ctx);

rnp_result_t disable_core_dumps(void);

bool set_pass_fd(FILE **file, int passfd);

char *ptimestr(char *dest, size_t size, time_t t);

#if defined(__cplusplus)
}
#endif

#endif /* !RNPCLI_H_ */
