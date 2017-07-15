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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef RNP_H_
#define RNP_H_

#include <stddef.h>
#include <stdbool.h>
#include "packet.h"
#include "constants.h"

#ifndef __BEGIN_DECLS
#if defined(__cplusplus)
#define __BEGIN_DECLS extern "C" {
#define __END_DECLS }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#endif

__BEGIN_DECLS

enum key_store_format_t { GPG_KEY_STORE, SSH_KEY_STORE, KBX_KEY_STORE };

/* structure used to keep application-wide rnp configuration: keyrings, password io, whatever
 * else */
typedef struct rnp_t {
    void *    pubring;       /* public key ring */
    void *    secring;       /* s3kr1t key ring */
    pgp_io_t *io;            /* the io struct for results/errs */
    void *    user_input_fp; /* file pointer for password input */
    char *    pubpath;       /* path to the public keyring */
    char *    secpath;       /* path to the secret keyring */
    char *    defkey;        /* default key id */
    int       pswdtries;     /* number of password tries, -1 for unlimited */

    enum key_store_format_t key_store_format; /* keyring format */
    union {
        rnp_keygen_desc_t generate_key_ctx;
    } action;
} rnp_t;

/* rnp initialization parameters : keyring pathes, flags, whatever else */
typedef struct rnp_params_t {
    unsigned enable_coredumps; /* enable coredumps: if it is allowed then they are disabled by
                                  default to not leak confidential information */

    int         passfd; /* password file descriptor */
    const char *outs;   /* output stream : may be <stderr> , most likel these are subject for
                           refactoring  */
    const char *errs;   /* error stream : may be <stdout> */
    const char *ress;   /* results stream : maye be <stdout>, <stderr> or file name/path */

    enum key_store_format_t ks_format; /* format of the key store */
    char *                  pubpath;   /* public keystore path */
    char *                  secpath;   /* secret keystore path */
    char *                  defkey;    /* default/preferred key id */
} rnp_params_t;

/* rnp operation context : contains additional data about the currently ongoing operation */
typedef struct rnp_ctx_t {
    rnp_t *        rnp;       /* rnp structure */
    char *         filename;  /* name of the input file to store in literal data packet */
    int64_t        filemtime; /* file modification time to store in literal data packet */
    int64_t        sigcreate; /* signature creation time */
    uint64_t       sigexpire; /* signature expiration time */
    pgp_hash_alg_t halg;      /* hash algorithm */
    pgp_symm_alg_t ealg;      /* encryption algorithm */
    int            zalg;      /* compression algorithm used */
    int            zlevel;    /* compression level */
    int            overwrite; /* allow to overwrite output file if exists */
    int            armour;    /* use ASCII armour on output */
} rnp_ctx_t;

/* initialize rnp using the init structure  */
int rnp_init(rnp_t *, const rnp_params_t *);
/* finish work with rnp and cleanup the memory */
void rnp_end(rnp_t *);

/* rnp initialization parameters : init and free */
void rnp_params_init(rnp_params_t *);
void rnp_params_free(rnp_params_t *);

/* init, reset and free rnp operation context */
int  rnp_ctx_init(rnp_ctx_t *, rnp_t *);
void rnp_ctx_reset(rnp_ctx_t *);
void rnp_ctx_free(rnp_ctx_t *);

/* debugging, reflection and information */
int         rnp_set_debug(const char *);
int         rnp_get_debug(const char *);
const char *rnp_get_info(const char *);
int         rnp_list_packets(rnp_t *, char *, int);

/* set key store format information */
int rnp_set_key_store_format(rnp_t *, const char *);

/* key management */
int   rnp_list_keys(rnp_t *, const int);
int   rnp_list_keys_json(rnp_t *, char **, const int);
bool  rnp_find_key(rnp_t *, const char *);
char *rnp_get_key(rnp_t *, const char *, const char *);
char *rnp_export_key(rnp_t *, const char *);
int   rnp_import_key(rnp_t *, char *);
int   rnp_generate_key(rnp_t *, const char *);
int   rnp_secret_count(rnp_t *);
int   rnp_public_count(rnp_t *);

/* file management */
int rnp_encrypt_file(rnp_ctx_t *, const char *, const char *, const char *);
int rnp_decrypt_file(rnp_ctx_t *, const char *, const char *);
int rnp_sign_file(rnp_ctx_t *, const char *, const char *, const char *, bool, bool);
int rnp_verify_file(rnp_ctx_t *, const char *, const char *, int);

/* memory signing and encryption */
int rnp_sign_memory(rnp_ctx_t *, const char *, char *, size_t, char *, size_t, bool);
int rnp_verify_memory(rnp_ctx_t *, const void *, const size_t, void *, size_t, const int);
int rnp_encrypt_memory(rnp_ctx_t *, const char *, void *, const size_t, char *, size_t);
int rnp_decrypt_memory(rnp_ctx_t *, const void *, const size_t, char *, size_t);

/* match and hkp-related functions */
int rnp_match_keys_json(rnp_t *, char **, char *, const char *, const int);
int rnp_match_keys(rnp_t *, char *, const char *, void *, const int);
int rnp_match_pubkeys(rnp_t *, char *, void *);
int rnp_format_json(void *, const char *, const int);

bool rnp_validate_sigs(rnp_t *);

/* save pgp key in ssh format */
int rnp_write_sshkey(rnp_t *, char *, const char *, char *, size_t);

__END_DECLS

#endif /* !RNP_H_ */
