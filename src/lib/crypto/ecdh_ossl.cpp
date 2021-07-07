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

#include <string>
#include <cassert>
#include "ecdh.h"
#include "ecdh_utils.h"
#include "ec_ossl.h"
#include "hash.h"
#include "symmetric.h"
#include "types.h"
#include "utils.h"
#include "logging.h"
#include "mem.h"
#include <openssl/evp.h>
#include <openssl/err.h>

static const struct ecdh_wrap_alg_map_t {
    pgp_symm_alg_t alg;
    const char *   name;
} ecdh_wrap_alg_map[] = {{PGP_SA_AES_128, "aes128-wrap"},
                         {PGP_SA_AES_192, "aes192-wrap"},
                         {PGP_SA_AES_256, "aes256-wrap"}};

rnp_result_t
ecdh_validate_key(rng_t *rng, const pgp_ec_key_t *key, bool secret)
{
    return ec_validate_key(*key, secret);
}

static rnp_result_t
ecdh_derive_kek(uint8_t *                x,
                size_t                   xlen,
                const pgp_ec_key_t &     key,
                const pgp_fingerprint_t &fingerprint,
                uint8_t *                kek,
                const size_t             kek_len)
{
    const ec_curve_desc_t *curve_desc = get_curve_desc(key.curve);
    if (!curve_desc) {
        RNP_LOG("unsupported curve");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    // Serialize other info, see 13.5 of RFC 4880 bis
    uint8_t      other_info[MAX_SP800_56A_OTHER_INFO];
    const size_t hash_len = pgp_digest_length(key.kdf_hash_alg);
    if (!hash_len) {
        // must not assert here as kdf/hash algs are not checked during key parsing
        RNP_LOG("Unsupported key wrap hash algorithm.");
        return RNP_ERROR_NOT_SUPPORTED;
    }
    size_t other_len = kdf_other_info_serialize(
      other_info, curve_desc, fingerprint, key.kdf_hash_alg, key.key_wrap_alg);
    // Self-check
    assert(other_len == curve_desc->OIDhex_len + 46);
    // Derive KEK, using the KDF from SP800-56A
    rnp::secure_array<uint8_t, PGP_MAX_HASH_SIZE> dgst;
    assert(hash_len <= PGP_MAX_HASH_SIZE);
    size_t reps = (kek_len + hash_len - 1) / hash_len;
    // As we use AES & SHA2 we should not get more then 2 iterations
    if (reps > 2) {
        RNP_LOG("Invalid key wrap/hash alg combination.");
        return RNP_ERROR_NOT_SUPPORTED;
    }
    size_t have = 0;
    for (size_t i = 1; i <= reps; i++) {
        pgp_hash_t hash = {};
        if (!pgp_hash_create(&hash, key.kdf_hash_alg)) {
            RNP_LOG("Failed to create hash.");
            return RNP_ERROR_GENERIC;
        }
        if (!pgp_hash_uint32(&hash, i) || pgp_hash_add(&hash, x, xlen) ||
            pgp_hash_add(&hash, other_info, other_len)) {
            RNP_LOG("Failed to hash.");
            pgp_hash_finish(&hash, NULL);
            return RNP_ERROR_GENERIC;
        }
        pgp_hash_finish(&hash, dgst.data());
        size_t bytes = std::min(hash_len, kek_len - have);
        memcpy(kek + have, dgst.data(), bytes);
        have += bytes;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
ecdh_rfc3394_wrap_ctx(EVP_CIPHER_CTX **ctx,
                      pgp_symm_alg_t   wrap_alg,
                      const uint8_t *  key,
                      bool             decrypt)
{
    /* get OpenSSL EVP cipher for key wrap */
    const char *cipher_name = NULL;
    ARRAY_LOOKUP_BY_ID(ecdh_wrap_alg_map, alg, name, wrap_alg, cipher_name);
    if (!cipher_name) {
        RNP_LOG("Unsupported key wrap algorithm: %d", (int) wrap_alg);
        return RNP_ERROR_NOT_SUPPORTED;
    }
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) {
        RNP_LOG("Cipher %s is not supported by OpenSSL.", cipher_name);
        return RNP_ERROR_NOT_SUPPORTED;
    }
    *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        RNP_LOG("Context allocation failed : %lu", ERR_peek_last_error());
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    EVP_CIPHER_CTX_set_flags(*ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    int res = decrypt ? EVP_DecryptInit_ex(*ctx, cipher, NULL, key, NULL) :
                        EVP_EncryptInit_ex(*ctx, cipher, NULL, key, NULL);
    if (res <= 0) {
        RNP_LOG("Failed to initialize cipher : %lu", ERR_peek_last_error());
        EVP_CIPHER_CTX_free(*ctx);
        *ctx = NULL;
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
ecdh_rfc3394_wrap(uint8_t *            out,
                  size_t *             out_len,
                  const uint8_t *const in,
                  size_t               in_len,
                  const uint8_t *      key,
                  pgp_symm_alg_t       wrap_alg)
{
    EVP_CIPHER_CTX *ctx = NULL;
    rnp_result_t    ret = ecdh_rfc3394_wrap_ctx(&ctx, wrap_alg, key, false);
    if (ret) {
        RNP_LOG("Wrap context initialization failed.");
        return ret;
    }
    int intlen = *out_len;
    /* encrypts in one pass, no final is needed */
    int res = EVP_EncryptUpdate(ctx, out, &intlen, in, in_len);
    if (res <= 0) {
        RNP_LOG("Failed to encrypt data : %lu", ERR_peek_last_error());
    } else {
        *out_len = intlen;
    }
    EVP_CIPHER_CTX_free(ctx);
    return res > 0 ? RNP_SUCCESS : RNP_ERROR_GENERIC;
}

static rnp_result_t
ecdh_rfc3394_unwrap(uint8_t *            out,
                    size_t *             out_len,
                    const uint8_t *const in,
                    size_t               in_len,
                    const uint8_t *      key,
                    pgp_symm_alg_t       wrap_alg)
{
    if ((in_len < 16) || (in_len % 8)) {
        RNP_LOG("Invalid wrapped key size.");
        return RNP_ERROR_GENERIC;
    }
    EVP_CIPHER_CTX *ctx = NULL;
    rnp_result_t    ret = ecdh_rfc3394_wrap_ctx(&ctx, wrap_alg, key, true);
    if (ret) {
        RNP_LOG("Unwrap context initialization failed.");
        return ret;
    }
    int intlen = *out_len;
    /* decrypts in one pass, no final is needed */
    int res = EVP_DecryptUpdate(ctx, out, &intlen, in, in_len);
    if (res <= 0) {
        RNP_LOG("Failed to decrypt data : %lu", ERR_peek_last_error());
    } else {
        *out_len = intlen;
    }
    EVP_CIPHER_CTX_free(ctx);
    return res > 0 ? RNP_SUCCESS : RNP_ERROR_GENERIC;
}

static bool
ecdh_derive_secret(EVP_PKEY *sec, EVP_PKEY *peer, uint8_t *x, size_t *xlen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(sec, NULL);
    if (!ctx) {
        RNP_LOG("Context allocation failed: %lu", ERR_peek_last_error());
        return false;
    }
    bool res = false;
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        RNP_LOG("Key derivation init failed: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
        RNP_LOG("Peer setting failed: %lu", ERR_peek_last_error());
        goto done;
    }
    if (EVP_PKEY_derive(ctx, x, xlen) <= 0) {
        RNP_LOG("Failed to obtain shared secret size: %lu", ERR_peek_last_error());
        goto done;
    }
    res = true;
done:
    EVP_PKEY_CTX_free(ctx);
    return res;
}

static size_t
ecdh_kek_len(pgp_symm_alg_t wrap_alg)
{
    switch (wrap_alg) {
    case PGP_SA_AES_128:
    case PGP_SA_AES_192:
    case PGP_SA_AES_256:
        return pgp_key_size(wrap_alg);
    default:
        return 0;
    }
}

rnp_result_t
ecdh_encrypt_pkcs5(rng_t *                  rng,
                   pgp_ecdh_encrypted_t *   out,
                   const uint8_t *const     in,
                   size_t                   in_len,
                   const pgp_ec_key_t *     key,
                   const pgp_fingerprint_t &fingerprint)
{
    if (!key || !out || !in || (in_len > MAX_SESSION_KEY_SIZE)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
#if !defined(ENABLE_SM2)
    if (key->curve == PGP_CURVE_SM2_P_256) {
        RNP_LOG("SM2 curve support is disabled.");
        return RNP_ERROR_NOT_IMPLEMENTED;
    }
#endif
    /* check whether we have valid wrap_alg before doing heavy operations */
    size_t keklen = ecdh_kek_len(key->key_wrap_alg);
    if (!keklen) {
        RNP_LOG("Unsupported key wrap algorithm: %d", (int) key->key_wrap_alg);
        return RNP_ERROR_NOT_SUPPORTED;
    }
    /* load our public key */
    EVP_PKEY *pkey = ec_load_key(key->p, NULL, key->curve);
    if (!pkey) {
        RNP_LOG("Failed to load public key.");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp::secure_array<uint8_t, MAX_CURVE_BYTELEN + 1> sec;
    rnp::secure_array<uint8_t, MAX_AES_KEY_SIZE>      kek;
    rnp::secure_array<uint8_t, MAX_SESSION_KEY_SIZE>  mpad;

    size_t       seclen = sec.size();
    rnp_result_t ret = RNP_ERROR_GENERIC;
    /* generate ephemeral key */
    EVP_PKEY *ephkey = ec_generate_pkey(PGP_PKA_ECDH, key->curve);
    if (!ephkey) {
        RNP_LOG("Failed to generate ephemeral key.");
        ret = RNP_ERROR_KEY_GENERATION;
        goto done;
    }
    /* do ECDH derivation */
    if (!ecdh_derive_secret(ephkey, pkey, sec.data(), &seclen)) {
        RNP_LOG("ECDH derivation failed.");
        goto done;
    }
    /* here we got x value in sec, deriving kek */
    ret = ecdh_derive_kek(sec.data(), seclen, *key, fingerprint, kek.data(), keklen);
    if (ret) {
        RNP_LOG("Failed to derive KEK.");
        goto done;
    }
    /* add PKCS#7 padding */
    size_t m_padded_len;
    m_padded_len = ((in_len / 8) + 1) * 8;
    memcpy(mpad.data(), in, in_len);
    if (!pad_pkcs7(mpad.data(), m_padded_len, in_len)) {
        RNP_LOG("Failed to add PKCS #7 padding.");
        goto done;
    }
    /* do RFC 3394 AES key wrap */
    static_assert(sizeof(out->m) == ECDH_WRAPPED_KEY_SIZE, "Wrong ECDH wrapped key size.");
    out->mlen = ECDH_WRAPPED_KEY_SIZE;
    ret = ecdh_rfc3394_wrap(
      out->m, &out->mlen, mpad.data(), m_padded_len, kek.data(), key->key_wrap_alg);
    if (ret) {
        RNP_LOG("Failed to wrap key.");
        goto done;
    }
    /* write ephemeral public key */
    if (!ec_write_pubkey(ephkey, out->p, key->curve)) {
        RNP_LOG("Failed to write ec key.");
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_free(ephkey);
    EVP_PKEY_free(pkey);
    return ret;
}

rnp_result_t
ecdh_decrypt_pkcs5(uint8_t *                   out,
                   size_t *                    out_len,
                   const pgp_ecdh_encrypted_t *in,
                   const pgp_ec_key_t *        key,
                   const pgp_fingerprint_t &   fingerprint)
{
    if (!out || !out_len || !in || !key || !mpi_bytes(&key->x)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* check whether we have valid wrap_alg before doing heavy operations */
    size_t keklen = ecdh_kek_len(key->key_wrap_alg);
    if (!keklen) {
        RNP_LOG("Unsupported key wrap algorithm: %d", (int) key->key_wrap_alg);
        return RNP_ERROR_NOT_SUPPORTED;
    }
    /* load ephemeral public key */
    EVP_PKEY *ephkey = ec_load_key(in->p, NULL, key->curve);
    if (!ephkey) {
        RNP_LOG("Failed to load ephemeral public key.");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    /* load our secret key */
    rnp::secure_array<uint8_t, MAX_CURVE_BYTELEN + 1> sec;
    rnp::secure_array<uint8_t, MAX_AES_KEY_SIZE>      kek;
    rnp::secure_array<uint8_t, MAX_SESSION_KEY_SIZE>  mpad;

    size_t       seclen = sec.size();
    size_t       mpadlen = mpad.size();
    rnp_result_t ret = RNP_ERROR_GENERIC;
    EVP_PKEY *   pkey = ec_load_key(key->p, &key->x, key->curve);
    if (!pkey) {
        RNP_LOG("Failed to load secret key.");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }
    /* do ECDH derivation */
    if (!ecdh_derive_secret(pkey, ephkey, sec.data(), &seclen)) {
        RNP_LOG("ECDH derivation failed.");
        goto done;
    }
    /* here we got x value in sec, deriving kek */
    ret = ecdh_derive_kek(sec.data(), seclen, *key, fingerprint, kek.data(), keklen);
    if (ret) {
        RNP_LOG("Failed to derive KEK.");
        goto done;
    }
    /* do RFC 3394 AES key unwrap */
    ret = ecdh_rfc3394_unwrap(
      mpad.data(), &mpadlen, in->m, in->mlen, kek.data(), key->key_wrap_alg);
    if (ret) {
        RNP_LOG("Failed to unwrap key.");
        goto done;
    }
    /* remove PKCS#7 padding */
    if (!unpad_pkcs7(mpad.data(), mpadlen, &mpadlen)) {
        RNP_LOG("Failed to unpad key.");
        goto done;
    }
    assert(mpadlen <= *out_len);
    *out_len = mpadlen;
    memcpy(out, mpad.data(), mpadlen);
    ret = RNP_SUCCESS;
done:
    EVP_PKEY_free(ephkey);
    EVP_PKEY_free(pkey);
    return ret;
}
