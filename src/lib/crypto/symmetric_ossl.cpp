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

#include "crypto.h"
#include "config.h"
#include "defaults.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "utils.h"

static const char *
pgp_sa_to_openssl_string(pgp_symm_alg_t alg)
{
    switch (alg) {
    case PGP_SA_IDEA:
        return "idea-ecb";
    case PGP_SA_TRIPLEDES:
        return "des-ede3-ecb";
    case PGP_SA_CAST5:
        return "cast5-ecb";
    case PGP_SA_BLOWFISH:
        return "bf-ecb";
    case PGP_SA_AES_128:
        return "aes-128-ecb";
    case PGP_SA_AES_192:
        return "aes-192-ecb";
    case PGP_SA_AES_256:
        return "aes-256-ecb";
    case PGP_SA_SM4:
        return "sm4-ecb";
    case PGP_SA_CAMELLIA_128:
        return "camellia-128-ecb";
    case PGP_SA_CAMELLIA_192:
        return "camellia-192-ecb";
    case PGP_SA_CAMELLIA_256:
        return "camellia-256-ecb";
    default:
        RNP_LOG("Unsupported PGP symmetric alg %d", (int) alg);
        return NULL;
    }
}

bool
pgp_cipher_cfb_start(pgp_crypt_t *  crypt,
                     pgp_symm_alg_t alg,
                     const uint8_t *key,
                     const uint8_t *iv)
{
    memset(crypt, 0x0, sizeof(*crypt));

    const char *cipher_name = pgp_sa_to_openssl_string(alg);
    if (!cipher_name) {
        RNP_LOG("Unsupported algorithm: %d", alg);
        return false;
    }

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) {
        RNP_LOG("Cipher %s is not supported by OpenSSL.", cipher_name);
        return false;
    }

    crypt->alg = alg;
    crypt->blocksize = pgp_block_size(alg);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int             res = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    if (res != 1) {
        RNP_LOG("Failed to initialize cipher.");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    crypt->cfb.obj = ctx;

    if (iv) {
        // Otherwise left as all zeros via memset at start of function
        memcpy(crypt->cfb.iv, iv, crypt->blocksize);
    }

    crypt->cfb.remaining = 0;
    return true;
}

void
pgp_cipher_cfb_resync(pgp_crypt_t *crypt, const uint8_t *buf)
{
    /* iv will be encrypted in the upcoming call to encrypt/decrypt */
    memcpy(crypt->cfb.iv, buf, crypt->blocksize);
    crypt->cfb.remaining = 0;
}

int
pgp_cipher_cfb_finish(pgp_crypt_t *crypt)
{
    if (!crypt) {
        return 0;
    }
    if (crypt->cfb.obj) {
        EVP_CIPHER_CTX_free(crypt->cfb.obj);
        crypt->cfb.obj = NULL;
    }
    OPENSSL_cleanse((uint8_t *) crypt, sizeof(*crypt));
    return 0;
}

/* we rely on fact that in and out could be the same */
int
pgp_cipher_cfb_encrypt(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t bytes)
{
    uint64_t *in64;
    uint64_t  buf64[512]; // 4KB - page size
    uint64_t  iv64[2];
    size_t    blocks, blockb;
    unsigned  blsize = crypt->blocksize;

    /* encrypting till the block boundary */
    while (bytes && crypt->cfb.remaining) {
        *out = *in++ ^ crypt->cfb.iv[blsize - crypt->cfb.remaining];
        crypt->cfb.iv[blsize - crypt->cfb.remaining] = *out++;
        crypt->cfb.remaining--;
        bytes--;
    }

    if (!bytes) {
        return 0;
    }

    /* encrypting full blocks */
    if (bytes > blsize) {
        memcpy(iv64, crypt->cfb.iv, blsize);
        while ((blocks = bytes & ~(blsize - 1)) > 0) {
            if (blocks > sizeof(buf64)) {
                blocks = sizeof(buf64);
            }
            bytes -= blocks;
            blockb = blocks;
            memcpy(buf64, in, blockb);
            in64 = buf64;

            if (blsize == 16) {
                blocks >>= 4;
                while (blocks--) {
                    int outlen = 16;
                    EVP_EncryptUpdate(
                      crypt->cfb.obj, (uint8_t *) iv64, &outlen, (uint8_t *) iv64, 16);
                    if (outlen != 16) {
                        RNP_LOG("Bad outlen: must be 16");
                    }
                    *in64 ^= iv64[0];
                    iv64[0] = *in64++;
                    *in64 ^= iv64[1];
                    iv64[1] = *in64++;
                }
            } else {
                blocks >>= 3;
                while (blocks--) {
                    int outlen = 8;
                    EVP_EncryptUpdate(
                      crypt->cfb.obj, (uint8_t *) iv64, &outlen, (uint8_t *) iv64, 8);
                    if (outlen != 8) {
                        RNP_LOG("Bad outlen: must be 8");
                    }
                    *in64 ^= iv64[0];
                    iv64[0] = *in64++;
                }
            }

            memcpy(out, buf64, blockb);
            out += blockb;
            in += blockb;
        }

        memcpy(crypt->cfb.iv, iv64, blsize);
    }

    if (!bytes) {
        return 0;
    }

    int outlen = blsize;
    EVP_EncryptUpdate(crypt->cfb.obj, crypt->cfb.iv, &outlen, crypt->cfb.iv, (int) blsize);
    if (outlen != (int) blsize) {
        RNP_LOG("Bad outlen: must be %u", blsize);
    }
    crypt->cfb.remaining = blsize;

    /* encrypting tail */
    while (bytes) {
        *out = *in++ ^ crypt->cfb.iv[blsize - crypt->cfb.remaining];
        crypt->cfb.iv[blsize - crypt->cfb.remaining] = *out++;
        crypt->cfb.remaining--;
        bytes--;
    }

    return 0;
}

/* we rely on fact that in and out could be the same */
int
pgp_cipher_cfb_decrypt(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t bytes)
{
    /* for better code readability */
    uint64_t *out64, *in64;
    uint64_t  inbuf64[512]; // 4KB - page size
    uint64_t  outbuf64[512];
    uint64_t  iv64[2];
    size_t    blocks, blockb;
    unsigned  blsize = crypt->blocksize;

    /* decrypting till the block boundary */
    while (bytes && crypt->cfb.remaining) {
        uint8_t c = *in++;
        *out++ = c ^ crypt->cfb.iv[blsize - crypt->cfb.remaining];
        crypt->cfb.iv[blsize - crypt->cfb.remaining] = c;
        crypt->cfb.remaining--;
        bytes--;
    }

    if (!bytes) {
        return 0;
    }

    /* decrypting full blocks */
    if (bytes > blsize) {
        memcpy(iv64, crypt->cfb.iv, blsize);

        while ((blocks = bytes & ~(blsize - 1)) > 0) {
            if (blocks > sizeof(inbuf64)) {
                blocks = sizeof(inbuf64);
            }
            bytes -= blocks;
            blockb = blocks;
            memcpy(inbuf64, in, blockb);
            out64 = outbuf64;
            in64 = inbuf64;

            if (blsize == 16) {
                blocks >>= 4;
                while (blocks--) {
                    int outlen = 16;
                    EVP_EncryptUpdate(
                      crypt->cfb.obj, (uint8_t *) iv64, &outlen, (uint8_t *) iv64, 16);
                    if (outlen != 16) {
                        RNP_LOG("Bad outlen: must be 16");
                    }
                    *out64++ = *in64 ^ iv64[0];
                    iv64[0] = *in64++;
                    *out64++ = *in64 ^ iv64[1];
                    iv64[1] = *in64++;
                }
            } else {
                blocks >>= 3;
                while (blocks--) {
                    int outlen = 8;
                    EVP_EncryptUpdate(
                      crypt->cfb.obj, (uint8_t *) iv64, &outlen, (uint8_t *) iv64, 8);
                    if (outlen != 8) {
                        RNP_LOG("Bad outlen: must be 8");
                    }
                    *out64++ = *in64 ^ iv64[0];
                    iv64[0] = *in64++;
                }
            }

            memcpy(out, outbuf64, blockb);
            out += blockb;
            in += blockb;
        }

        memcpy(crypt->cfb.iv, iv64, blsize);
    }

    if (!bytes) {
        return 0;
    }

    int outlen = blsize;
    EVP_EncryptUpdate(crypt->cfb.obj, crypt->cfb.iv, &outlen, crypt->cfb.iv, (int) blsize);
    if (outlen != (int) blsize) {
        RNP_LOG("Bad outlen: must be %u", blsize);
    }
    crypt->cfb.remaining = blsize;

    /* decrypting tail */
    while (bytes) {
        uint8_t c = *in++;
        *out++ = c ^ crypt->cfb.iv[blsize - crypt->cfb.remaining];
        crypt->cfb.iv[blsize - crypt->cfb.remaining] = c;
        crypt->cfb.remaining--;
        bytes--;
    }

    return 0;
}

size_t
pgp_cipher_block_size(pgp_crypt_t *crypt)
{
    return crypt->blocksize;
}

unsigned
pgp_block_size(pgp_symm_alg_t alg)
{
    switch (alg) {
    case PGP_SA_IDEA:
    case PGP_SA_TRIPLEDES:
    case PGP_SA_CAST5:
    case PGP_SA_BLOWFISH:
        return 8;

    case PGP_SA_AES_128:
    case PGP_SA_AES_192:
    case PGP_SA_AES_256:
    case PGP_SA_TWOFISH:
    case PGP_SA_CAMELLIA_128:
    case PGP_SA_CAMELLIA_192:
    case PGP_SA_CAMELLIA_256:
    case PGP_SA_SM4:
        return 16;

    default:
        RNP_DLOG("Unknown PGP symmetric alg %d", (int) alg);
        return 0;
    }
}

unsigned
pgp_key_size(pgp_symm_alg_t alg)
{
    /* Update MAX_SYMM_KEY_SIZE after adding algorithm
     * with bigger key size.
     */
    static_assert(32 == MAX_SYMM_KEY_SIZE, "MAX_SYMM_KEY_SIZE must be updated");

    switch (alg) {
    case PGP_SA_IDEA:
    case PGP_SA_CAST5:
    case PGP_SA_BLOWFISH:
    case PGP_SA_AES_128:
    case PGP_SA_CAMELLIA_128:
    case PGP_SA_SM4:
        return 16;

    case PGP_SA_TRIPLEDES:
    case PGP_SA_AES_192:
    case PGP_SA_CAMELLIA_192:
        return 24;

    case PGP_SA_TWOFISH:
    case PGP_SA_AES_256:
    case PGP_SA_CAMELLIA_256:
        return 32;

    default:
        return 0;
    }
}

bool
pgp_is_sa_supported(pgp_symm_alg_t alg)
{
    const char *cipher_name = pgp_sa_to_openssl_string(alg);
    if (cipher_name) {
        return true;
    }
    RNP_LOG("Warning: cipher %d not supported", (int) alg);
    return false;
}

#if defined(ENABLE_AEAD)
bool
pgp_cipher_aead_init(pgp_crypt_t *  crypt,
                     pgp_symm_alg_t ealg,
                     pgp_aead_alg_t aalg,
                     const uint8_t *key,
                     bool           decrypt)
{
    return false;
}

size_t
pgp_cipher_aead_granularity(pgp_crypt_t *crypt)
{
    return crypt->aead.granularity;
}
#endif

size_t
pgp_cipher_aead_nonce_len(pgp_aead_alg_t aalg)
{
    switch (aalg) {
    case PGP_AEAD_EAX:
        return PGP_AEAD_EAX_NONCE_LEN;
    case PGP_AEAD_OCB:
        return PGP_AEAD_OCB_NONCE_LEN;
    default:
        return 0;
    }
}

size_t
pgp_cipher_aead_tag_len(pgp_aead_alg_t aalg)
{
    switch (aalg) {
    case PGP_AEAD_EAX:
    case PGP_AEAD_OCB:
        return PGP_AEAD_EAX_OCB_TAG_LEN;
    default:
        return 0;
    }
}

#if defined(ENABLE_AEAD)
bool
pgp_cipher_aead_set_ad(pgp_crypt_t *crypt, const uint8_t *ad, size_t len)
{
    return false;
}

bool
pgp_cipher_aead_start(pgp_crypt_t *crypt, const uint8_t *nonce, size_t len)
{
    return false;
}

bool
pgp_cipher_aead_update(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t len)
{
    return false;
}

void
pgp_cipher_aead_reset(pgp_crypt_t *crypt)
{
    ;
}

bool
pgp_cipher_aead_finish(pgp_crypt_t *crypt, uint8_t *out, const uint8_t *in, size_t len)
{
    return false;
}

void
pgp_cipher_aead_destroy(pgp_crypt_t *crypt)
{
    ;
}

size_t
pgp_cipher_aead_nonce(pgp_aead_alg_t aalg, const uint8_t *iv, uint8_t *nonce, size_t index)
{
    switch (aalg) {
    case PGP_AEAD_EAX:
        /* The nonce for EAX mode is computed by treating the starting
        initialization vector as a 16-octet, big-endian value and
        exclusive-oring the low eight octets of it with the chunk index.
        */
        memcpy(nonce, iv, PGP_AEAD_EAX_NONCE_LEN);
        for (int i = 15; (i > 7) && index; i--) {
            nonce[i] ^= index & 0xff;
            index = index >> 8;
        }
        return PGP_AEAD_EAX_NONCE_LEN;
    case PGP_AEAD_OCB:
        /* The nonce for a chunk of chunk index "i" in OCB processing is defined as:
           OCB-Nonce_{i} = IV[1..120] xor i
        */
        memcpy(nonce, iv, PGP_AEAD_OCB_NONCE_LEN);
        for (int i = 14; (i >= 0) && index; i--) {
            nonce[i] ^= index & 0xff;
            index = index >> 8;
        }
        return PGP_AEAD_OCB_NONCE_LEN;
    default:
        return 0;
    }
}
#endif
