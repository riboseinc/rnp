/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009-2010 The NetBSD Foundation, Inc.
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
/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** \file
 */
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: misc.c,v 1.41 2012/03/05 02:20:18 christos Exp $");
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <botan/ffi.h>

#include "errors.h"
#include "packet.h"
#include "crypto.h"
#include "bn.h"
#include "create.h"
#include "packet-parse.h"
#include "packet-show.h"
#include "signature.h"
#include "rnpsdk.h"
#include "rnpdefs.h"
#include "memory.h"
#include "readerwriter.h"
#include "rnpdigest.h"

#ifdef WIN32
#define vsnprintf _vsnprintf
#endif

/** \file
 * \brief Error Handling
 */
#define ERRNAME(code) \
    {                 \
        code, #code   \
    }

static pgp_errcode_name_map_t errcode_name_map[] = {
  ERRNAME(PGP_E_OK),
  ERRNAME(PGP_E_FAIL),
  ERRNAME(PGP_E_SYSTEM_ERROR),
  ERRNAME(PGP_E_UNIMPLEMENTED),

  ERRNAME(PGP_E_R),
  ERRNAME(PGP_E_R_READ_FAILED),
  ERRNAME(PGP_E_R_EARLY_EOF),
  ERRNAME(PGP_E_R_BAD_FORMAT),
  ERRNAME(PGP_E_R_UNCONSUMED_DATA),

  ERRNAME(PGP_E_W),
  ERRNAME(PGP_E_W_WRITE_FAILED),
  ERRNAME(PGP_E_W_WRITE_TOO_SHORT),

  ERRNAME(PGP_E_P),
  ERRNAME(PGP_E_P_NOT_ENOUGH_DATA),
  ERRNAME(PGP_E_P_UNKNOWN_TAG),
  ERRNAME(PGP_E_P_PACKET_CONSUMED),
  ERRNAME(PGP_E_P_MPI_FORMAT_ERROR),

  ERRNAME(PGP_E_C),

  ERRNAME(PGP_E_V),
  ERRNAME(PGP_E_V_BAD_SIGNATURE),
  ERRNAME(PGP_E_V_NO_SIGNATURE),
  ERRNAME(PGP_E_V_UNKNOWN_SIGNER),

  ERRNAME(PGP_E_ALG),
  ERRNAME(PGP_E_ALG_UNSUPPORTED_SYMMETRIC_ALG),
  ERRNAME(PGP_E_ALG_UNSUPPORTED_PUBLIC_KEY_ALG),
  ERRNAME(PGP_E_ALG_UNSUPPORTED_SIGNATURE_ALG),
  ERRNAME(PGP_E_ALG_UNSUPPORTED_HASH_ALG),

  ERRNAME(PGP_E_PROTO),
  ERRNAME(PGP_E_PROTO_BAD_SYMMETRIC_DECRYPT),
  ERRNAME(PGP_E_PROTO_UNKNOWN_SS),
  ERRNAME(PGP_E_PROTO_CRITICAL_SS_IGNORED),
  ERRNAME(PGP_E_PROTO_BAD_PUBLIC_KEY_VRSN),
  ERRNAME(PGP_E_PROTO_BAD_SIGNATURE_VRSN),
  ERRNAME(PGP_E_PROTO_BAD_ONE_PASS_SIG_VRSN),
  ERRNAME(PGP_E_PROTO_BAD_PKSK_VRSN),
  ERRNAME(PGP_E_PROTO_DECRYPTED_MSG_WRONG_LEN),
  ERRNAME(PGP_E_PROTO_BAD_SK_CHECKSUM),

  {0x00, NULL}, /* this is the end-of-array marker */
};

/**
 * \ingroup Core_Errors
 * \brief returns error code name
 * \param errcode
 * \return error code name or "Unknown"
 */
const char *
pgp_errcode(const pgp_errcode_t errcode)
{
    return (pgp_str_from_map((int) errcode, (pgp_map_t *) errcode_name_map));
}

/* generic grab new storage function */
void *
pgp_new(size_t size)
{
    void *vp;

    if ((vp = calloc(1, size)) == NULL) {
        (void) fprintf(stderr, "allocation failure for %" PRIsize "u bytes", size);
    }
    return vp;
}

/* utility function to zero out memory */
void
pgp_forget(void *vp, size_t size)
{
    (void) memset(vp, 0x0, size);
}

/**
 * \ingroup Core_Errors
 * \brief Pushes the given error on the given errorstack
 * \param errstack Error stack to use
 * \param errcode Code of error to push
 * \param sys_errno System errno (used if errcode=PGP_E_SYSTEM_ERROR)
 * \param file Source filename where error occurred
 * \param line Line in source file where error occurred
 * \param fmt Comment
 *
 */

void
pgp_push_error(pgp_error_t **errstack,
               pgp_errcode_t errcode,
               int           sys_errno,
               const char *  file,
               int           line,
               const char *  fmt,
               ...)
{
    /* first get the varargs and generate the comment */
    pgp_error_t *err;
    unsigned     maxbuf = 128;
    va_list      args;
    char *       comment;

    if ((comment = calloc(1, maxbuf + 1)) == NULL) {
        (void) fprintf(stderr, "calloc comment failure\n");
        return;
    }

    va_start(args, fmt);
    vsnprintf(comment, maxbuf + 1, fmt, args);
    va_end(args);

    /* alloc a new error and add it to the top of the stack */

    if ((err = calloc(1, sizeof(*err))) == NULL) {
        (void) fprintf(stderr, "calloc comment failure\n");
        free((void *) comment);
        return;
    }

    err->next = *errstack;
    *errstack = err;

    /* fill in the details */
    err->errcode = errcode;
    err->sys_errno = sys_errno;
    err->file = file;
    err->line = line;

    err->comment = comment;
}

/**
\ingroup Core_Errors
\brief print this error
\param err Error to print
*/
void
pgp_print_error(pgp_error_t *err)
{
    printf("%s:%d: ", err->file, err->line);
    if (err->errcode == PGP_E_SYSTEM_ERROR) {
        printf("system error %d returned from %s()\n", err->sys_errno, err->comment);
    } else {
        printf("%s, %s\n", pgp_errcode(err->errcode), err->comment);
    }
}

/**
\ingroup Core_Errors
\brief Print all errors on stack
\param errstack Error stack to print
*/
void
pgp_print_errors(pgp_error_t *errstack)
{
    pgp_error_t *err;

    for (err = errstack; err != NULL; err = err->next) {
        pgp_print_error(err);
    }
}

/**
\ingroup Core_Errors
\brief Return 1 if given error is present anywhere on stack
\param errstack Error stack to check
\param errcode Error code to look for
\return 1 if found; else 0
*/
int
pgp_has_error(pgp_error_t *errstack, pgp_errcode_t errcode)
{
    pgp_error_t *err;

    for (err = errstack; err != NULL; err = err->next) {
        if (err->errcode == errcode) {
            return RNP_OK;
        }
    }
    return RNP_FAIL;
}

/**
\ingroup Core_Errors
\brief Frees all errors on stack
\param errstack Error stack to free
*/
void
pgp_free_errors(pgp_error_t *errstack)
{
    pgp_error_t *next;

    while (errstack != NULL) {
        next = errstack->next;
        free(errstack->comment);
        free(errstack);
        errstack = next;
    }
}

/* hash a 32-bit integer */
static int
hash_uint32(pgp_hash_t *hash, uint32_t n)
{
    uint8_t ibuf[4];

    ibuf[0] = (uint8_t)(n >> 24) & 0xff;
    ibuf[1] = (uint8_t)(n >> 16) & 0xff;
    ibuf[2] = (uint8_t)(n >> 8) & 0xff;
    ibuf[3] = (uint8_t) n & 0xff;
    pgp_hash_add(hash, ibuf, sizeof(ibuf));
    return sizeof(ibuf);
}

/* hash a string - first length, then string itself */
int
hash_string(pgp_hash_t *hash, const uint8_t *buf, uint32_t len)
{
    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "hash_string", buf, len);
    }
    hash_uint32(hash, len);
    pgp_hash_add(hash, buf, len);
    return (int) (sizeof(len) + len);
}

/* hash a bignum, possibly padded - first length, then string itself */
int
hash_bignum(pgp_hash_t *hash, const BIGNUM *bignum)
{
    uint8_t *bn;
    size_t   len;
    int      padbyte;

    if (BN_is_zero(bignum)) {
        hash_uint32(hash, 0);
        return sizeof(len);
    }
    if ((len = (size_t) BN_num_bytes(bignum)) < 1) {
        (void) fprintf(stderr, "hash_bignum: bad size\n");
        return 0;
    }
    if ((bn = calloc(1, len + 1)) == NULL) {
        (void) fprintf(stderr, "hash_bignum: bad bn alloc\n");
        return 0;
    }
    BN_bn2bin(bignum, bn + 1);
    bn[0] = 0x0;
    padbyte = (bn[1] & 0x80) ? 1 : 0;
    hash_string(hash, bn + 1 - padbyte, (unsigned) (len + padbyte));
    free(bn);
    return (int) (sizeof(len) + len + padbyte);
}

/** \file
 */

/**
 * \ingroup Core_Keys
 * \brief Calculate a public key fingerprint.
 * \param fp Where to put the calculated fingerprint
 * \param key The key for which the fingerprint is calculated
 */
int
pgp_fingerprint(pgp_fingerprint_t *fp, const pgp_pubkey_t *key)
{
    pgp_memory_t *mem;
    pgp_hash_t    hash = {0};
    uint32_t      len;

    if (key->version == 2 || key->version == 3) {
        if (key->alg != PGP_PKA_RSA && key->alg != PGP_PKA_RSA_ENCRYPT_ONLY &&
            key->alg != PGP_PKA_RSA_SIGN_ONLY) {
            (void) fprintf(stderr, "pgp_fingerprint: bad algorithm\n");
            return RNP_FAIL;
        }
        if (!pgp_hash_create(&hash, PGP_HASH_MD5)) {
            (void) fprintf(stderr, "pgp_fingerprint: bad md5 alloc\n");
            return RNP_FAIL;
        }
        hash_bignum(&hash, key->key.rsa.n);
        hash_bignum(&hash, key->key.rsa.e);
        fp->length = pgp_hash_finish(&hash, fp->fingerprint);
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "v2/v3 fingerprint", fp->fingerprint, fp->length);
        }
        fp->hashtype = PGP_HASH_MD5;
    } else if (key->version == 4) {
        mem = pgp_memory_new();
        if (mem == NULL) {
            (void) fprintf(stderr, "can't allocate mem\n");
            return RNP_FAIL;
        }
        pgp_build_pubkey(mem, key, 0);
        if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
            (void) fprintf(stderr, "pgp_fingerprint: bad sha1 alloc\n");
            pgp_memory_free(mem);
            return RNP_FAIL;
        }
        len = (unsigned) pgp_mem_len(mem);
        pgp_hash_add_int(&hash, 0x99, 1);
        pgp_hash_add_int(&hash, len, 2);
        pgp_hash_add(&hash, pgp_mem_data(mem), len);
        fp->length = pgp_hash_finish(&hash, fp->fingerprint);
        pgp_memory_free(mem);
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "sha1 fingerprint", fp->fingerprint, fp->length);
        }
        fp->hashtype = PGP_HASH_SHA1;
    } else {
        (void) fprintf(stderr, "pgp_fingerprint: unsupported key version\n");
        return RNP_FAIL;
    }
    return RNP_OK;
}

/**
 * \ingroup Core_Keys
 * \brief Calculate the Key ID from the public key.
 * \param keyid Space for the calculated ID to be stored
 * \param key The key for which the ID is calculated
 */

int
pgp_keyid(uint8_t *keyid, const size_t idlen, const pgp_pubkey_t *key)
{
    pgp_fingerprint_t finger;

    if (key->version == 2 || key->version == 3) {
        unsigned n;
        uint8_t  bn[RNP_BUFSIZ];

        n = (unsigned) BN_num_bytes(key->key.rsa.n);
        if (n > sizeof(bn)) {
            (void) fprintf(stderr, "pgp_keyid: bad num bytes\n");
            return RNP_FAIL;
        }
        if (key->alg != PGP_PKA_RSA && key->alg != PGP_PKA_RSA_ENCRYPT_ONLY &&
            key->alg != PGP_PKA_RSA_SIGN_ONLY) {
            (void) fprintf(stderr, "pgp_keyid: bad algorithm\n");
            return RNP_FAIL;
        }
        BN_bn2bin(key->key.rsa.n, bn);
        (void) memcpy(keyid, bn + n - idlen, idlen);
    } else {
        pgp_fingerprint(&finger, key);
        (void) memcpy(keyid, finger.fingerprint + finger.length - idlen, idlen);
    }
    return RNP_OK;
}

/**
\ingroup Core_Hashes
\brief Calculate hash for MDC packet
\param preamble Preamble to hash
\param sz_preamble Size of preamble
\param plaintext Plaintext to hash
\param sz_plaintext Size of plaintext
\param hashed Resulting hash
*/
void
pgp_calc_mdc_hash(const uint8_t *preamble,
                  const size_t   sz_preamble,
                  const uint8_t *plaintext,
                  const unsigned sz_plaintext,
                  uint8_t *      hashed)
{
    pgp_hash_t hash = {0};
    uint8_t    c;

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "preamble", preamble, sz_preamble);
        hexdump(stderr, "plaintext", plaintext, sz_plaintext);
    }
    /* init */
    if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
        (void) fprintf(stderr, "pgp_calc_mdc_hash: bad alloc\n");
        /* we'll just continue here - it will die anyway */
        /* agc - XXX - no way to return failure */
    }

    /* preamble */
    pgp_hash_add(&hash, preamble, (unsigned) sz_preamble);
    /* plaintext */
    pgp_hash_add(&hash, plaintext, sz_plaintext);
    /* MDC packet tag */
    c = MDC_PKT_TAG;
    pgp_hash_add(&hash, &c, 1);
    /* MDC packet len */
    c = PGP_SHA1_HASH_SIZE;
    pgp_hash_add(&hash, &c, 1);

    /* finish */
    pgp_hash_finish(&hash, hashed);

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "hashed", hashed, PGP_SHA1_HASH_SIZE);
    }
}

int
pgp_random(void *dest, size_t length)
{
    int rc;

    // todo should this be a global instead?
    botan_rng_t rng;

    if (botan_rng_init(&rng, NULL)) {
        (void) fprintf(stderr, "pgp_random: can't init botan\n");
        return -1;
    }
    rc = botan_rng_get(rng, dest, length);
    botan_rng_destroy(rng);

    return rc;
}

/**
\ingroup HighLevel_Memory
\brief Memory to initialise
\param mem memory to initialise
\param needed Size to initialise to
*/
void
pgp_memory_init(pgp_memory_t *mem, size_t needed)
{
    uint8_t *temp;

    mem->length = 0;
    if (mem->buf) {
        if (mem->allocated < needed) {
            if ((temp = realloc(mem->buf, needed)) == NULL) {
                (void) fprintf(stderr, "pgp_memory_init: bad alloc\n");
            } else {
                mem->buf = temp;
                mem->allocated = needed;
            }
        }
    } else {
        if ((mem->buf = calloc(1, needed)) == NULL) {
            (void) fprintf(stderr, "pgp_memory_init: bad alloc\n");
        } else {
            mem->allocated = needed;
        }
    }
}

/**
\ingroup HighLevel_Memory
\brief Pad memory to required length
\param mem Memory to use
\param length New size
*/
int
pgp_memory_pad(pgp_memory_t *mem, size_t length)
{
    uint8_t *temp;

    if (mem->allocated < mem->length) {
        (void) fprintf(stderr, "pgp_memory_pad: bad alloc in\n");
        return RNP_FAIL;
    }
    if (mem->allocated < mem->length + length) {
        mem->allocated = mem->allocated * 2 + length;
        temp = realloc(mem->buf, mem->allocated);
        if (temp == NULL) {
            (void) fprintf(stderr, "pgp_memory_pad: bad alloc\n");
            return RNP_FAIL;
        } else {
            mem->buf = temp;
        }
    }
    if (mem->allocated < mem->length + length) {
        (void) fprintf(stderr, "pgp_memory_pad: bad alloc out\n");
        return RNP_FAIL;
    }

    return RNP_OK;
}

/**
\ingroup HighLevel_Memory
\brief Add data to memory
\param mem Memory to which to add
\param src Data to add
\param length Length of data to add
*/
int
pgp_memory_add(pgp_memory_t *mem, const uint8_t *src, size_t length)
{
    if (!pgp_memory_pad(mem, length)) {
        return RNP_FAIL;
    }
    (void) memcpy(mem->buf + mem->length, src, length);
    mem->length += length;
    return RNP_OK;
}

/* XXX: this could be refactored via the writer, but an awful lot of */
/* hoops to jump through for 2 lines of code! */
void
pgp_memory_place_int(pgp_memory_t *mem, unsigned offset, unsigned n, size_t length)
{
    if (mem->allocated < offset + length) {
        (void) fprintf(stderr, "pgp_memory_place_int: bad alloc\n");
    } else {
        while (length-- > 0) {
            mem->buf[offset++] = n >> (length * 8);
        }
    }
}

/**
 * \ingroup HighLevel_Memory
 * \brief Retains allocated memory and set length of stored data to zero.
 * \param mem Memory to clear
 * \sa pgp_memory_release()
 * \sa pgp_memory_free()
 */
void
pgp_memory_clear(pgp_memory_t *mem)
{
    mem->length = 0;
}

/**
\ingroup HighLevel_Memory
\brief Free memory and associated data
\param mem Memory to free
\note This does not free mem itself
\sa pgp_memory_clear()
\sa pgp_memory_free()
*/
void
pgp_memory_release(pgp_memory_t *mem)
{
    if (mem->mmapped) {
        (void) munmap(mem->buf, mem->length);
    } else {
        free(mem->buf);
    }
    mem->buf = NULL;
    mem->length = 0;
}

void
pgp_memory_make_packet(pgp_memory_t *out, pgp_content_enum tag)
{
    size_t extra;

    extra = (out->length < 192) ? 1 : (out->length < 8192 + 192) ? 2 : 5;
    if (!pgp_memory_pad(out, extra + 1)) {
        return;
    }
    memmove(out->buf + extra + 1, out->buf, out->length);

    out->buf[0] = PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT | tag;

    if (out->length < 192) {
        out->buf[1] = (uint8_t) out->length;
    } else if (out->length < 8192 + 192) {
        out->buf[1] = (uint8_t)((out->length - 192) >> 8) + 192;
        out->buf[2] = (uint8_t)(out->length - 192);
    } else {
        out->buf[1] = 0xff;
        out->buf[2] = (uint8_t)(out->length >> 24);
        out->buf[3] = (uint8_t)(out->length >> 16);
        out->buf[4] = (uint8_t)(out->length >> 8);
        out->buf[5] = (uint8_t)(out->length);
    }

    out->length += extra + 1;
}

/**
   \ingroup HighLevel_Memory
   \brief Create a new zeroed pgp_memory_t
   \return Pointer to new pgp_memory_t
   \note Free using pgp_memory_free() after use.
   \sa pgp_memory_free()
*/

pgp_memory_t *
pgp_memory_new(void)
{
    return calloc(1, sizeof(pgp_memory_t));
}

/**
   \ingroup HighLevel_Memory
   \brief Free memory ptr and associated memory
   \param mem Memory to be freed
   \sa pgp_memory_release()
   \sa pgp_memory_clear()
*/

void
pgp_memory_free(pgp_memory_t *mem)
{
    if (!mem) {
        return;
    }
    pgp_memory_release(mem);
    free(mem);
}

/**
   \ingroup HighLevel_Memory
   \brief Get length of data stored in pgp_memory_t struct
   \return Number of bytes in data
*/
size_t
pgp_mem_len(const pgp_memory_t *mem)
{
    return mem->length;
}

/**
   \ingroup HighLevel_Memory
   \brief Get data stored in pgp_memory_t struct
   \return Pointer to data
*/
void *
pgp_mem_data(pgp_memory_t *mem)
{
    return mem->buf;
}

/* read a gile into an pgp_memory_t */
bool
pgp_mem_readfile(pgp_memory_t *mem, const char *f)
{
    struct stat st;
    FILE *      fp;
    int         cc;

    if ((fp = fopen(f, "rb")) == NULL) {
        (void) fprintf(stderr, "pgp_mem_readfile: can't open \"%s\"\n", f);
        return false;
    }
    (void) fstat(fileno(fp), &st);
    mem->allocated = (size_t) st.st_size;
    mem->buf = mmap(NULL, mem->allocated, PROT_READ, MAP_PRIVATE | MAP_FILE, fileno(fp), 0);
    if (mem->buf == MAP_FAILED) {
        /* mmap failed for some reason - try to allocate memory */
        if ((mem->buf = calloc(1, mem->allocated)) == NULL) {
            (void) fprintf(stderr, "pgp_mem_readfile: calloc\n");
            (void) fclose(fp);
            return false;
        }
        /* read into contents of mem */
        for (mem->length = 0; (cc = (int) read(fileno(fp),
                                               &mem->buf[mem->length],
                                               (size_t)(mem->allocated - mem->length))) > 0;
             mem->length += (size_t) cc) {
        }
    } else {
        mem->length = mem->allocated;
        mem->mmapped = 1;
    }
    (void) fclose(fp);
    return (mem->allocated == mem->length);
}

int
pgp_mem_writefile(pgp_memory_t *mem, const char *f)
{
    FILE *fp;
    int   fd;
    char  tmp[MAXPATHLEN];

    snprintf(tmp, sizeof(tmp), "%s.rnp-tmp.XXXXXX", f);

    fd = mkstemp(tmp);
    if (fd < 0) {
        fprintf(stderr, "pgp_mem_writefile: can't open temp file: %s\n", strerror(errno));
        return RNP_FAIL;
    }

    if ((fp = fdopen(fd, "wb")) == NULL) {
        fprintf(stderr, "pgp_mem_writefile: can't open \"%s\"\n", strerror(errno));
        return RNP_FAIL;
    }

    fwrite(mem->buf, mem->length, 1, fp);
    if (ferror(fp)) {
        fprintf(stderr, "pgp_mem_writefile: can't write to file\n");
        fclose(fp);
        return RNP_FAIL;
    }

    fclose(fp);

    if (rename(tmp, f)) {
        fprintf(
          stderr, "pgp_mem_writefile: can't rename to traget file: %s\n", strerror(errno));
        return RNP_FAIL;
    }

    return RNP_OK;
}

typedef struct {
    uint16_t sum;
} sum16_t;

/**
 * Searches the given map for the given type.
 * Returns a human-readable descriptive string if found,
 * returns NULL if not found
 *
 * It is the responsibility of the calling function to handle the
 * error case sensibly (i.e. don't just print out the return string.
 *
 */
static const char *
str_from_map_or_null(int type, pgp_map_t *map)
{
    pgp_map_t *row;

    for (row = map; row->string != NULL; row++) {
        if (row->type == type) {
            return row->string;
        }
    }
    return NULL;
}

/**
 * \ingroup Core_Print
 *
 * Searches the given map for the given type.
 * Returns a readable string if found, "Unknown" if not.
 */

const char *
pgp_str_from_map(int type, pgp_map_t *map)
{
    const char *str;

    str = str_from_map_or_null(type, map);
    return (str) ? str : "Unknown";
}

#define LINELEN 16

/* show hexadecimal/ascii dump */
void
hexdump(FILE *fp, const char *header, const uint8_t *src, size_t length)
{
    size_t i;
    char   line[LINELEN + 1];

    (void) fprintf(fp, "%s%s", (header) ? header : "", (header) ? "\n" : "");
    (void) fprintf(fp, "[%" PRIsize "u char%s]\n", length, (length == 1) ? "" : "s");
    for (i = 0; i < length; i++) {
        if (i % LINELEN == 0) {
            (void) fprintf(fp, "%.5" PRIsize "u | ", i);
        }
        (void) fprintf(fp, "%.02x ", (uint8_t) src[i]);
        line[i % LINELEN] = (isprint(src[i])) ? src[i] : '.';
        if (i % LINELEN == LINELEN - 1) {
            line[LINELEN] = 0x0;
            (void) fprintf(fp, " | %s\n", line);
        }
    }
    if (i % LINELEN != 0) {
        for (; i % LINELEN != 0; i++) {
            (void) fprintf(fp, "   ");
            line[i % LINELEN] = ' ';
        }
        line[LINELEN] = 0x0;
        (void) fprintf(fp, " | %s\n", line);
    }
}

/**
 * \ingroup HighLevel_Functions
 * \brief Closes down OpenPGP::SDK.
 *
 * Close down OpenPGP:SDK, release any resources under the control of
 * the library.
 */

void
pgp_finish(void)
{
    pgp_crypto_finish();
}

static int
sum16_reader(pgp_stream_t *stream,
             void *        dest_,
             size_t        length,
             pgp_error_t **errors,
             pgp_reader_t *readinfo,
             pgp_cbdata_t *cbinfo)
{
    const uint8_t *dest = dest_;
    sum16_t *      arg = pgp_reader_get_arg(readinfo);
    int            r;
    int            n;

    r = pgp_stacked_read(stream, dest_, length, errors, readinfo, cbinfo);
    if (r < 0) {
        return r;
    }
    for (n = 0; n < r; ++n) {
        arg->sum = (arg->sum + dest[n]) & 0xffff;
    }
    return r;
}

static void
sum16_destroyer(pgp_reader_t *readinfo)
{
    free(pgp_reader_get_arg(readinfo));
}

/**
   \ingroup Internal_Readers_Sum16
   \param stream Parse settings
*/

void
pgp_reader_push_sum16(pgp_stream_t *stream)
{
    sum16_t *arg;

    arg = calloc(1, sizeof(*arg));
    if (arg == NULL) {
        (void) fprintf(stderr, "pgp_reader_push_sum16: bad alloc\n");
        return;
    }

    if (!pgp_reader_push(stream, sum16_reader, sum16_destroyer, arg)) {
        free(arg);
    }
}

/**
   \ingroup Internal_Readers_Sum16
   \param stream Parse settings
   \return sum
*/
uint16_t
pgp_reader_pop_sum16(pgp_stream_t *stream)
{
    uint16_t sum;
    sum16_t *arg;

    arg = pgp_reader_get_arg(pgp_readinfo(stream));
    sum = arg->sum;
    pgp_reader_pop(stream);
    free(arg);
    return sum;
}

/* small useful functions for setting the file-level debugging levels */
/* if the debugv list contains the filename in question, we're debugging it */

enum { MAX_DEBUG_NAMES = 32 };

static int   debugc;
static char *debugv[MAX_DEBUG_NAMES];

/* set the debugging level per filename */
int
rnp_set_debug(const char *f)
{
    const char *name;
    int         i;

    if (f == NULL) {
        f = "all";
    }
    if ((name = strrchr(f, '/')) == NULL) {
        name = f;
    } else {
        name += 1;
    }
    for (i = 0; ((i < MAX_DEBUG_NAMES) && (i < debugc)); i++) {
        if (strcmp(debugv[i], name) == 0) {
            return 1;
        }
    }
    if (i == MAX_DEBUG_NAMES) {
        return RNP_FAIL;
    }
    debugv[debugc++] = rnp_strdup(name);
    return RNP_OK;
}

/* get the debugging level per filename */
int
rnp_get_debug(const char *f)
{
    const char *name;
    int         i;

    if ((name = strrchr(f, '/')) == NULL) {
        name = f;
    } else {
        name += 1;
    }
    for (i = 0; i < debugc; i++) {
        if (strcmp(debugv[i], "all") == 0 || strcmp(debugv[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

/* return the version for the library */
const char *
rnp_get_info(const char *type)
{
    if (strcmp(type, "version") == 0) {
        return PACKAGE_STRING "[" GIT_REVISION "]";
    }
    if (strcmp(type, "maintainer") == 0) {
        return PACKAGE_BUGREPORT;
    }
    return "[unknown]";
}

void
rnp_log(const char *fmt, ...)
{
    va_list vp;
    time_t  t;
    char    buf[BUFSIZ * 2];
    int     cc;

    (void) time(&t);
    cc = snprintf(buf, sizeof(buf), "%.24s: rnp: ", ctime(&t));
    va_start(vp, fmt);
    (void) vsnprintf(&buf[cc], sizeof(buf) - (size_t) cc, fmt, vp);
    va_end(vp);
    /* do something with message */
    /* put into log buffer? */
}

/* portable replacement for strdup(3) */
char *
rnp_strdup(const char *s)
{
    size_t len;
    char * cp;

    len = strlen(s);
    if ((cp = calloc(1, len + 1)) != NULL) {
        (void) memcpy(cp, s, len);
        cp[len] = 0x0;
    }
    return cp;
}

/* portable replacement for strcasecmp(3) */
int
rnp_strcasecmp(const char *s1, const char *s2)
{
    int n;

    for (n = 0; *s1 && *s2 && (n = tolower((uint8_t) *s1) - tolower((uint8_t) *s2)) == 0;
         s1++, s2++) {
    }
    return n;
}

/* return the hexdump as a string */
char *
rnp_strhexdump(char *dest, const uint8_t *src, size_t length, const char *sep)
{
    unsigned i;
    int      n;

    for (n = 0, i = 0; i < length; i += 2) {
        n += snprintf(&dest[n], 3, "%02x", *src++);
        n += snprintf(&dest[n], 10, "%02x%s", *src++, sep);
    }
    return dest;
}

/* return the file modification time */
int64_t
rnp_filemtime(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        return 0;
    } else {
        return st.st_mtime;
    }
}

/* return the filename from the given path */
const char *
rnp_filename(const char *path)
{
    char *res = strrchr(path, '/');
    if (!res) {
        return path;
    } else {
        return res + 1;
    }
}
