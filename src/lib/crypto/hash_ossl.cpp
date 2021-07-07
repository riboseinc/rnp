/*-
 * Copyright (c) 2021 Ribose Inc.
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

#include <stdio.h>
#include <memory>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "config.h"
#include "hash.h"
#include "types.h"
#include "utils.h"
#include "defaults.h"
#include "hash_crc24.h"

static const struct hash_alg_map_t {
    pgp_hash_alg_t type;
    const char *   name;
    const char *   ossl_name;
    size_t         digest_size;
} hash_alg_map[] = {{PGP_HASH_MD5, "MD5", "md5", 16},
                    {PGP_HASH_SHA1, "SHA1", "sha1", 20},
                    {PGP_HASH_RIPEMD, "RIPEMD160", "ripemd160", 20},
                    {PGP_HASH_SHA256, "SHA256", "sha256", 32},
                    {PGP_HASH_SHA384, "SHA384", "sha384", 48},
                    {PGP_HASH_SHA512, "SHA512", "sha512", 64},
                    {PGP_HASH_SHA224, "SHA224", "sha224", 28},
                    {PGP_HASH_SM3, "SM3", "sm3", 32},
                    {PGP_HASH_SHA3_256, "SHA3-256", "sha3-256", 32},
                    {PGP_HASH_SHA3_512, "SHA3-512", "sha3-512", 64}};

const char *
pgp_show_hash_alg(uint8_t hash)
{
    const char *ret = NULL;
    ARRAY_LOOKUP_BY_ID(hash_alg_map, type, name, hash, ret);
    return ret;
}

const char *
pgp_hash_name_openssl(pgp_hash_alg_t hash)
{
    const char *ret = NULL;
    ARRAY_LOOKUP_BY_ID(hash_alg_map, type, ossl_name, hash, ret);
    return ret;
}

const char *
pgp_hash_name(const pgp_hash_t *hash)
{
    return pgp_show_hash_alg(hash->_alg);
}

pgp_hash_alg_t
pgp_str_to_hash_alg(const char *hash)
{
    if (hash == NULL) {
        return DEFAULT_PGP_HASH_ALG;
    }
    for (size_t i = 0; i < ARRAY_SIZE(hash_alg_map); i++) {
        if (!rnp_strcasecmp(hash, hash_alg_map[i].name)) {
            return hash_alg_map[i].type;
        }
    }
    return PGP_HASH_UNKNOWN;
}

bool
pgp_hash_create(pgp_hash_t *hash, pgp_hash_alg_t alg)
{
    const char *hash_name = pgp_hash_name_openssl(alg);
    if (!hash_name) {
        return false;
    }
#if !defined(ENABLE_SM2)
    if (alg == PGP_HASH_SM3) {
        RNP_LOG("SM3 hash is not available.");
        return false;
    }
#endif
    const EVP_MD *hash_tp = EVP_get_digestbyname(hash_name);
    if (!hash_tp) {
        RNP_LOG("Error creating hash object for '%s'", hash_name);
        return false;
    }
    EVP_MD_CTX *hash_fn = EVP_MD_CTX_new();
    if (!hash_fn) {
        RNP_LOG("Allocation failure");
        return false;
    }
    int res = EVP_DigestInit_ex(hash_fn, hash_tp, NULL);
    if (res != 1) {
        RNP_LOG("Digest initializataion error %d : %lu", res, ERR_peek_last_error());
        EVP_MD_CTX_free(hash_fn);
        return false;
    }

    hash->_alg = alg;
    hash->_output_len = EVP_MD_size(hash_tp);
    hash->handle = hash_fn;
    return true;
}

bool
pgp_hash_create_crc24(pgp_hash_t *hash)
{
    return pgp_crc24_create(hash);
}

bool
pgp_hash_copy(pgp_hash_t *dst, const pgp_hash_t *src)
{
    if (!src || !dst || !src->handle) {
        return false;
    }
    if (src->_alg == PGP_HASH_UNKNOWN) {
        return pgp_crc24_copy(dst, src);
    }

    EVP_MD_CTX *hash_fn = EVP_MD_CTX_new();
    if (!hash_fn) {
        RNP_LOG("Allocation failure");
        return false;
    }

    int res = EVP_MD_CTX_copy(hash_fn, static_cast<EVP_MD_CTX *>(src->handle));
    if (res != 1) {
        RNP_LOG("Digest copying error %d: %lu", res, ERR_peek_last_error());
        EVP_MD_CTX_free(hash_fn);
        return false;
    }

    dst->_output_len = src->_output_len;
    dst->_alg = src->_alg;
    dst->handle = hash_fn;
    return true;
}

int
pgp_hash_add(pgp_hash_t *hash, const void *buf, size_t len)
{
    if (!hash || !hash->handle) {
        return -1;
    }
    if (hash->_alg == PGP_HASH_UNKNOWN) {
        return pgp_crc24_add(hash, buf, len);
    }

    EVP_MD_CTX *hash_fn = static_cast<EVP_MD_CTX *>(hash->handle);
    int         res = EVP_DigestUpdate(hash_fn, buf, len);
    if (res != 1) {
        RNP_LOG("Digest updating error %d: %lu", res, ERR_peek_last_error());
        return -2;
    }
    return 0;
}

size_t
pgp_hash_finish(pgp_hash_t *hash, uint8_t *out)
{
    if (!hash || !hash->handle) {
        return 0;
    }
    if (hash->_alg == PGP_HASH_UNKNOWN) {
        return pgp_crc24_finish(hash, out);
    }

    EVP_MD_CTX *hash_fn = static_cast<EVP_MD_CTX *>(hash->handle);
    int         res = out ? EVP_DigestFinal_ex(hash_fn, out, NULL) : 1;
    EVP_MD_CTX_free(hash_fn);
    hash->handle = NULL;
    if (res != 1) {
        RNP_LOG("Digest finalization error %d: %lu", res, ERR_peek_last_error());
        return 0;
    }

    size_t outlen = hash->_output_len;
    hash->_output_len = 0;
    return outlen;
}

pgp_hash_alg_t
pgp_hash_alg_type(const pgp_hash_t *hash)
{
    return hash->_alg;
}

size_t
pgp_digest_length(pgp_hash_alg_t alg)
{
    size_t val = 0;
    ARRAY_LOOKUP_BY_ID(hash_alg_map, type, digest_size, alg, val);
    return val;
}

bool
pgp_hash_list_add(std::vector<pgp_hash_t> &hashes, pgp_hash_alg_t alg)
{
    pgp_hash_t hash = {0};
    if (!pgp_hash_list_get(hashes, alg)) {
        if (!pgp_hash_create(&hash, alg)) {
            RNP_LOG("failed to initialize hash algorithm %d", (int) alg);
            return false;
        }
        try {
            hashes.push_back(hash);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            pgp_hash_finish(&hash, NULL);
            return false;
        }
    }
    return true;
}

const pgp_hash_t *
pgp_hash_list_get(std::vector<pgp_hash_t> &hashes, pgp_hash_alg_t alg)
{
    for (auto &hash : hashes) {
        if (pgp_hash_alg_type(&hash) == alg) {
            return &hash;
        }
    }
    return NULL;
}

void
pgp_hash_list_update(std::vector<pgp_hash_t> &hashes, const void *buf, size_t len)
{
    for (auto &hash : hashes) {
        pgp_hash_add(&hash, buf, len);
    }
}

bool
pgp_hash_uint32(pgp_hash_t *hash, uint32_t n)
{
    uint8_t ibuf[4];
    STORE32BE(ibuf, n);
    return !pgp_hash_add(hash, ibuf, sizeof(ibuf));
}
