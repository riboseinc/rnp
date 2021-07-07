/*
 * Copyright (c) 2017-2019 [Ribose Inc](https://www.ribose.com).
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

#include <crypto/common.h>
#include <crypto.h>
#include <pgp-key.h>
#include "rnp.h"
#include <librepgp/stream-packet.h>
#include <librepgp/stream-key.h>

#include "rnp_tests.h"
#include "support.h"
#include "fingerprint.h"

extern rng_t global_rng;

TEST_F(rnp_tests, hash_test_success)
{
    pgp_hash_t hash = {0};
    uint8_t    hash_output[PGP_MAX_HASH_SIZE];

    const pgp_hash_alg_t hash_algs[] = {PGP_HASH_MD5,
                                        PGP_HASH_SHA1,
                                        PGP_HASH_SHA256,
                                        PGP_HASH_SHA384,
                                        PGP_HASH_SHA512,
                                        PGP_HASH_SHA224,
                                        PGP_HASH_SM3,
                                        PGP_HASH_SHA3_256,
                                        PGP_HASH_SHA3_512,
                                        PGP_HASH_UNKNOWN};

    const uint8_t test_input[3] = {'a', 'b', 'c'};
    const char *  hash_alg_expected_outputs[] = {
      "900150983CD24FB0D6963F7D28E17F72",
      "A9993E364706816ABA3E25717850C26C9CD0D89D",
      "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
      "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1"
      "E7CC2358BAECA"
      "134C825A7",
      "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A27"
      "4FC1A836BA3C2"
      "3A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F",
      "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7",
      "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0",
      "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532",
      "B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E1"
      "0E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0"};

    for (int i = 0; hash_algs[i] != PGP_HASH_UNKNOWN; ++i) {
#if !defined(ENABLE_SM2)
        if (hash_algs[i] == PGP_HASH_SM3) {
            assert_false(pgp_hash_create(&hash, hash_algs[i]));
            size_t hash_size = pgp_digest_length(hash_algs[i]);
            assert_int_equal(hash_size * 2, strlen(hash_alg_expected_outputs[i]));
            continue;
        }
#endif
        assert_true(pgp_hash_create(&hash, hash_algs[i]));
        size_t hash_size = pgp_digest_length(hash_algs[i]);
        assert_int_equal(hash_size * 2, strlen(hash_alg_expected_outputs[i]));

        pgp_hash_add(&hash, test_input, 1);
        pgp_hash_add(&hash, test_input + 1, sizeof(test_input) - 1);
        pgp_hash_finish(&hash, hash_output);

        assert_int_equal(
          0,
          test_value_equal(
            pgp_hash_name(&hash), hash_alg_expected_outputs[i], hash_output, hash_size));
    }
}

TEST_F(rnp_tests, cipher_test_success)
{
    const uint8_t  key[16] = {0};
    uint8_t        iv[16];
    pgp_symm_alg_t alg = PGP_SA_AES_128;
    pgp_crypt_t    crypt;

    uint8_t cfb_data[20] = {0};
    memset(iv, 0x42, sizeof(iv));

    assert_int_equal(1, pgp_cipher_cfb_start(&crypt, alg, key, iv));

    assert_int_equal(0, pgp_cipher_cfb_encrypt(&crypt, cfb_data, cfb_data, sizeof(cfb_data)));

    assert_int_equal(0,
                     test_value_equal("AES CFB encrypt",
                                      "BFDAA57CB812189713A950AD9947887983021617",
                                      cfb_data,
                                      sizeof(cfb_data)));
    assert_int_equal(0, pgp_cipher_cfb_finish(&crypt));

    assert_int_equal(1, pgp_cipher_cfb_start(&crypt, alg, key, iv));
    assert_int_equal(0, pgp_cipher_cfb_decrypt(&crypt, cfb_data, cfb_data, sizeof(cfb_data)));
    assert_int_equal(0,
                     test_value_equal("AES CFB decrypt",
                                      "0000000000000000000000000000000000000000",
                                      cfb_data,
                                      sizeof(cfb_data)));
    assert_int_equal(0, pgp_cipher_cfb_finish(&crypt));
}

TEST_F(rnp_tests, pkcs1_rsa_test_success)
{
    uint8_t             ptext[1024 / 8] = {'a', 'b', 'c', 0};
    uint8_t             dec[1024 / 8];
    pgp_rsa_encrypted_t enc;
    size_t              dec_size;
    pgp_key_pkt_t       seckey;

    const pgp_rsa_key_t *key_rsa;

    rnp_keygen_crypto_params_t key_desc;
    key_desc.key_alg = PGP_PKA_RSA;
    key_desc.hash_alg = PGP_HASH_SHA256;
    key_desc.rsa.modulus_bit_len = 1024;
    key_desc.rng = &global_rng;
    assert_true(pgp_generate_seckey(&key_desc, &seckey, true));
    key_rsa = &seckey.material.rsa;

    assert_rnp_success(rsa_encrypt_pkcs1(&global_rng, &enc, ptext, 3, key_rsa));
    assert_int_equal(enc.m.len, 1024 / 8);

    memset(dec, 0, sizeof(dec));
    dec_size = 0;
    assert_rnp_success(rsa_decrypt_pkcs1(&global_rng, dec, &dec_size, &enc, key_rsa));
    test_value_equal("RSA 1024 decrypt", "616263", dec, 3);
    assert_int_equal(dec_size, 3);
}

TEST_F(rnp_tests, rnp_test_eddsa)
{
    rnp_keygen_crypto_params_t key_desc;
    key_desc.key_alg = PGP_PKA_EDDSA;
    key_desc.hash_alg = PGP_HASH_SHA256;
    key_desc.rng = &global_rng;

    pgp_key_pkt_t seckey;
    assert_true(pgp_generate_seckey(&key_desc, &seckey, true));

    const uint8_t      hash[32] = {0};
    pgp_ec_signature_t sig = {{{0}}};

    assert_rnp_success(eddsa_sign(&global_rng, &sig, hash, sizeof(hash), &seckey.material.ec));

    assert_rnp_success(eddsa_verify(&sig, hash, sizeof(hash), &seckey.material.ec));

    // cut one byte off hash -> invalid sig
    assert_rnp_failure(eddsa_verify(&sig, hash, sizeof(hash) - 1, &seckey.material.ec));

    // swap r/s -> invalid sig
    pgp_mpi_t tmp = sig.r;
    sig.r = sig.s;
    sig.s = tmp;
    assert_rnp_failure(eddsa_verify(&sig, hash, sizeof(hash), &seckey.material.ec));
}

TEST_F(rnp_tests, rnp_test_x25519)
{
    rnp_keygen_crypto_params_t key_desc = {};
    pgp_key_pkt_t              seckey;
    pgp_ecdh_encrypted_t       enc = {};
    uint8_t           in[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t           out[16] = {};
    size_t            outlen = 0;
    pgp_fingerprint_t fp = {};

    key_desc.key_alg = PGP_PKA_ECDH;
    key_desc.hash_alg = PGP_HASH_SHA256;
    key_desc.rng = &global_rng;
    key_desc.ecc.curve = PGP_CURVE_25519;

    assert_true(pgp_generate_seckey(&key_desc, &seckey, true));
    assert_rnp_success(pgp_fingerprint(fp, seckey));
    assert_rnp_success(
      ecdh_encrypt_pkcs5(&global_rng, &enc, in, sizeof(in), &seckey.material.ec, fp));
    assert_true(enc.mlen > 16);
    assert_true((enc.p.mpi[0] == 0x40) && (enc.p.len == 33));
    outlen = sizeof(out);
    assert_rnp_success(ecdh_decrypt_pkcs5(out, &outlen, &enc, &seckey.material.ec, fp));
    assert_true(outlen == 16);
    assert_true(memcmp(in, out, 16) == 0);

    /* negative cases */
    enc.p.mpi[16] ^= 0xff;
    assert_rnp_failure(ecdh_decrypt_pkcs5(out, &outlen, &enc, &seckey.material.ec, fp));

    enc.p.mpi[16] ^= 0xff;
    enc.p.mpi[0] = 0x04;
    assert_rnp_failure(ecdh_decrypt_pkcs5(out, &outlen, &enc, &seckey.material.ec, fp));

    enc.p.mpi[0] = 0x40;
    enc.mlen--;
    assert_rnp_failure(ecdh_decrypt_pkcs5(out, &outlen, &enc, &seckey.material.ec, fp));

    enc.mlen += 2;
    assert_rnp_failure(ecdh_decrypt_pkcs5(out, &outlen, &enc, &seckey.material.ec, fp));
}

static void
elgamal_roundtrip(pgp_eg_key_t *key)
{
    const uint8_t      in_b[] = {0x01, 0x02, 0x03, 0x04, 0x17};
    pgp_eg_encrypted_t enc = {{{0}}};
    uint8_t            res[1024];
    size_t             res_len = 0;

    assert_int_equal(elgamal_encrypt_pkcs1(&global_rng, &enc, in_b, sizeof(in_b), key),
                     RNP_SUCCESS);
    assert_int_equal(elgamal_decrypt_pkcs1(&global_rng, res, &res_len, &enc, key),
                     RNP_SUCCESS);
    assert_int_equal(res_len, sizeof(in_b));
    assert_int_equal(0, test_value_equal("ElGamal decrypt", "0102030417", res, res_len));
}

TEST_F(rnp_tests, raw_elgamal_random_key_test_success)
{
    pgp_eg_key_t key;

    assert_int_equal(elgamal_generate(&global_rng, &key, 1024), RNP_SUCCESS);
    elgamal_roundtrip(&key);
}

TEST_F(rnp_tests, ecdsa_signverify_success)
{
    uint8_t              message[64];
    const pgp_hash_alg_t hash_alg = PGP_HASH_SHA512;

    struct curve {
        pgp_curve_t id;
        size_t      size;
    } curves[] = {
      {PGP_CURVE_NIST_P_256, 32}, {PGP_CURVE_NIST_P_384, 48}, {PGP_CURVE_NIST_P_521, 64}};

    for (size_t i = 0; i < ARRAY_SIZE(curves); i++) {
        // Generate test data. Mainly to make valgrind not to complain about uninitialized data
        assert_true(rng_get_data(&global_rng, message, sizeof(message)));

        pgp_ec_signature_t         sig = {{{0}}};
        rnp_keygen_crypto_params_t key_desc;
        key_desc.key_alg = PGP_PKA_ECDSA;
        key_desc.hash_alg = hash_alg;
        key_desc.ecc.curve = curves[i].id;
        key_desc.rng = &global_rng;

        pgp_key_pkt_t seckey1;
        pgp_key_pkt_t seckey2;

        assert_true(pgp_generate_seckey(&key_desc, &seckey1, true));
        assert_true(pgp_generate_seckey(&key_desc, &seckey2, true));

        const pgp_ec_key_t *key1 = &seckey1.material.ec;
        const pgp_ec_key_t *key2 = &seckey2.material.ec;

        assert_rnp_success(
          ecdsa_sign(&global_rng, &sig, hash_alg, message, sizeof(message), key1));

        assert_rnp_success(ecdsa_verify(&sig, hash_alg, message, sizeof(message), key1));

        // Fails because of different key used
        assert_rnp_failure(ecdsa_verify(&sig, hash_alg, message, sizeof(message), key2));

        // Fails because message won't verify
        message[0] = ~message[0];
        assert_rnp_failure(ecdsa_verify(&sig, hash_alg, message, sizeof(message), key1));
    }
}

TEST_F(rnp_tests, ecdh_roundtrip)
{
    struct curve {
        pgp_curve_t id;
        size_t      size;
    } curves[] = {
      {PGP_CURVE_NIST_P_256, 32}, {PGP_CURVE_NIST_P_384, 48}, {PGP_CURVE_NIST_P_521, 66}};

    pgp_ecdh_encrypted_t enc;
    uint8_t              plaintext[32] = {0};
    size_t               plaintext_len = sizeof(plaintext);
    uint8_t              result[32] = {0};
    size_t               result_len = sizeof(result);

    for (size_t i = 0; i < ARRAY_SIZE(curves); i++) {
        rnp_keygen_crypto_params_t key_desc;
        key_desc.key_alg = PGP_PKA_ECDH;
        key_desc.hash_alg = PGP_HASH_SHA512;
        key_desc.ecc.curve = curves[i].id;
        key_desc.rng = &global_rng;

        pgp_key_pkt_t ecdh_key1;
        assert_true(pgp_generate_seckey(&key_desc, &ecdh_key1, true));

        pgp_fingerprint_t ecdh_key1_fpr = {};
        assert_rnp_success(pgp_fingerprint(ecdh_key1_fpr, ecdh_key1));

        assert_rnp_success(ecdh_encrypt_pkcs5(
          &global_rng, &enc, plaintext, plaintext_len, &ecdh_key1.material.ec, ecdh_key1_fpr));

        assert_rnp_success(ecdh_decrypt_pkcs5(
          result, &result_len, &enc, &ecdh_key1.material.ec, ecdh_key1_fpr));

        assert_int_equal(plaintext_len, result_len);
        assert_int_equal(memcmp(plaintext, result, result_len), 0);
    }
}

TEST_F(rnp_tests, ecdh_decryptionNegativeCases)
{
    uint8_t              plaintext[32] = {0};
    size_t               plaintext_len = sizeof(plaintext);
    uint8_t              result[32] = {0};
    size_t               result_len = sizeof(result);
    pgp_ecdh_encrypted_t enc;

    rnp_keygen_crypto_params_t key_desc;
    key_desc.key_alg = PGP_PKA_ECDH;
    key_desc.hash_alg = PGP_HASH_SHA512;
    key_desc.ecc = {.curve = PGP_CURVE_NIST_P_256};
    key_desc.rng = &global_rng;

    pgp_key_pkt_t ecdh_key1;
    assert_true(pgp_generate_seckey(&key_desc, &ecdh_key1, true));

    pgp_fingerprint_t ecdh_key1_fpr = {};
    assert_rnp_success(pgp_fingerprint(ecdh_key1_fpr, ecdh_key1));

    assert_rnp_success(ecdh_encrypt_pkcs5(
      &global_rng, &enc, plaintext, plaintext_len, &ecdh_key1.material.ec, ecdh_key1_fpr));

    assert_int_equal(ecdh_decrypt_pkcs5(NULL, 0, &enc, &ecdh_key1.material.ec, ecdh_key1_fpr),
                     RNP_ERROR_BAD_PARAMETERS);

    assert_int_equal(ecdh_decrypt_pkcs5(result, &result_len, &enc, NULL, ecdh_key1_fpr),
                     RNP_ERROR_BAD_PARAMETERS);

    assert_int_equal(
      ecdh_decrypt_pkcs5(result, &result_len, NULL, &ecdh_key1.material.ec, ecdh_key1_fpr),
      RNP_ERROR_BAD_PARAMETERS);

    size_t mlen = enc.mlen;
    enc.mlen = 0;
    assert_int_equal(
      ecdh_decrypt_pkcs5(result, &result_len, &enc, &ecdh_key1.material.ec, ecdh_key1_fpr),
      RNP_ERROR_GENERIC);

    enc.mlen = mlen - 1;
    assert_int_equal(
      ecdh_decrypt_pkcs5(result, &result_len, &enc, &ecdh_key1.material.ec, ecdh_key1_fpr),
      RNP_ERROR_GENERIC);

    int key_wrapping_alg = ecdh_key1.material.ec.key_wrap_alg;
    ecdh_key1.material.ec.key_wrap_alg = PGP_SA_IDEA;
    assert_int_equal(
      ecdh_decrypt_pkcs5(result, &result_len, &enc, &ecdh_key1.material.ec, ecdh_key1_fpr),
      RNP_ERROR_NOT_SUPPORTED);
    ecdh_key1.material.ec.key_wrap_alg = (pgp_symm_alg_t) key_wrapping_alg;
}

#if defined(ENABLE_SM2)
TEST_F(rnp_tests, sm2_roundtrip)
{
    uint8_t key[27] = {0};
    uint8_t decrypted[27];
    size_t  decrypted_size;

    rnp_keygen_crypto_params_t key_desc;
    key_desc.key_alg = PGP_PKA_SM2;
    key_desc.hash_alg = PGP_HASH_SM3;
    key_desc.ecc = {.curve = PGP_CURVE_SM2_P_256};
    key_desc.rng = &global_rng;

    assert_true(rng_get_data(&global_rng, key, sizeof(key)));

    pgp_key_pkt_t seckey;
    assert_true(pgp_generate_seckey(&key_desc, &seckey, true));

    const pgp_ec_key_t *eckey = &seckey.material.ec;

    pgp_hash_alg_t      hashes[] = {PGP_HASH_SM3, PGP_HASH_SHA256, PGP_HASH_SHA512};
    pgp_sm2_encrypted_t enc;
    rnp_result_t        ret;

    for (size_t i = 0; i < ARRAY_SIZE(hashes); ++i) {
        ret = sm2_encrypt(&global_rng, &enc, key, sizeof(key), hashes[i], eckey);
        assert_int_equal(ret, RNP_SUCCESS);

        memset(decrypted, 0, sizeof(decrypted));
        decrypted_size = sizeof(decrypted);
        ret = sm2_decrypt(decrypted, &decrypted_size, &enc, eckey);
        assert_int_equal(ret, RNP_SUCCESS);
        assert_int_equal(decrypted_size, sizeof(key));
        for (size_t i = 0; i < decrypted_size; ++i) {
            assert_int_equal(key[i], decrypted[i]);
        }
    }
}
#endif

#if defined(ENABLE_SM2)
TEST_F(rnp_tests, sm2_sm3_signature_test)
{
    const char *msg = "no backdoors here";

    pgp_ec_key_t       sm2_key;
    pgp_hash_t         hash;
    rng_t              rng;
    pgp_ec_signature_t sig;

    pgp_hash_alg_t hash_alg = PGP_HASH_SM3;
    const size_t   hash_len = pgp_digest_length(hash_alg);

    uint8_t digest[PGP_MAX_HASH_SIZE];

    rng_init(&rng, RNG_SYSTEM);

    sm2_key.curve = PGP_CURVE_NIST_P_256;

    hex2mpi(&sm2_key.p,
            "04d9a2025f1ab59bc44e35fc53aeb8e87a79787d30cd70a1f7c49e064b8b8a2fb24d8"
            "c82f49ee0a5b11df22cb0c3c6d9d5526d9e24d02ff8c83c06a859c26565f1");
    hex2mpi(&sm2_key.x, "110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC");

    assert_int_equal(sm2_validate_key(&rng, &sm2_key, true), RNP_SUCCESS);

    pgp_hash_create(&hash, hash_alg);

    assert_int_equal(sm2_compute_za(&sm2_key, &hash, "sm2_p256_test@example.com"),
                     RNP_SUCCESS);

    pgp_hash_add(&hash, msg, strlen(msg));

    pgp_hash_finish(&hash, digest);

    // First generate a signature, then verify it
    assert_int_equal(sm2_sign(&rng, &sig, hash_alg, digest, hash_len, &sm2_key), RNP_SUCCESS);

    assert_int_equal(sm2_verify(&sig, hash_alg, digest, hash_len, &sm2_key), RNP_SUCCESS);

    // Check that invalid signatures are rejected
    digest[0] ^= 1;

    assert_int_not_equal(sm2_verify(&sig, hash_alg, digest, hash_len, &sm2_key), RNP_SUCCESS);

    digest[0] ^= 1;

    assert_int_equal(sm2_verify(&sig, hash_alg, digest, hash_len, &sm2_key), RNP_SUCCESS);

    // Now verify a known good signature for this key/message (generated by GmSSL)
    hex2mpi(&sig.r, "96AA39A0C4A5C454653F394E86386F2E38BE14C57D0E555F3A27A5CEF30E51BD");
    hex2mpi(&sig.s, "62372BE4AC97DBE725AC0B279BB8FD15883858D814FD792DDB0A401DCC988E70");
    assert_int_equal(sm2_verify(&sig, hash_alg, digest, hash_len, &sm2_key), RNP_SUCCESS);
    rng_destroy(&rng);
}
#endif

#if defined(ENABLE_SM2)
TEST_F(rnp_tests, sm2_sha256_signature_test)
{
    const char *msg = "hi chappy";

    pgp_ec_key_t       sm2_key;
    pgp_hash_t         hash;
    rng_t              rng;
    pgp_ec_signature_t sig;

    pgp_hash_alg_t hash_alg = PGP_HASH_SHA256;
    const size_t   hash_len = pgp_digest_length(hash_alg);

    uint8_t digest[PGP_MAX_HASH_SIZE];

    rng_init(&rng, RNG_SYSTEM);

    sm2_key.curve = PGP_CURVE_SM2_P_256;

    hex2mpi(&sm2_key.p,
            "04d03d30dd01ca3422aeaccf9b88043b554659d3092b0a9e8cce3e8c4530a98cb79d7"
            "05e6213eee145b748e36e274e5f101dc10d7bbc9dab9a04022e73b76e02cd");
    hex2mpi(&sm2_key.x, "110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC");

    assert_int_equal(sm2_validate_key(&rng, &sm2_key, true), RNP_SUCCESS);

    pgp_hash_create(&hash, hash_alg);

    assert_int_equal(sm2_compute_za(&sm2_key, &hash, "sm2test@example.com"), RNP_SUCCESS);

    pgp_hash_add(&hash, msg, strlen(msg));

    pgp_hash_finish(&hash, digest);

    // First generate a signature, then verify it
    assert_int_equal(sm2_sign(&rng, &sig, hash_alg, digest, hash_len, &sm2_key), RNP_SUCCESS);

    assert_int_equal(sm2_verify(&sig, hash_alg, digest, hash_len, &sm2_key), RNP_SUCCESS);

    // Check that invalid signatures are rejected
    digest[0] ^= 1;

    assert_int_not_equal(sm2_verify(&sig, hash_alg, digest, hash_len, &sm2_key), RNP_SUCCESS);

    digest[0] ^= 1;

    assert_int_equal(sm2_verify(&sig, hash_alg, digest, hash_len, &sm2_key), RNP_SUCCESS);

    // Now verify a known good signature for this key/message (generated by GmSSL)
    hex2mpi(&sig.r, "94DA20EA69E4FC70692158BF3D30F87682A4B2F84DF4A4829A1EFC5D9C979D3F");
    hex2mpi(&sig.s, "EE15AF8D455B728AB80E592FCB654BF5B05620B2F4D25749D263D5C01FAD365F");
    assert_int_equal(sm2_verify(&sig, hash_alg, digest, hash_len, &sm2_key), RNP_SUCCESS);
    rng_destroy(&rng);
}
#endif

TEST_F(rnp_tests, test_dsa_roundtrip)
{
    uint8_t             message[PGP_MAX_HASH_SIZE];
    pgp_key_pkt_t       seckey;
    pgp_dsa_signature_t sig;

    struct key_params {
        size_t         p;
        size_t         q;
        pgp_hash_alg_t h;
    } keys[] = {
      // all 1024 key-hash combinations
      {1024, 160, PGP_HASH_SHA1},
      {1024, 160, PGP_HASH_SHA224},
      {1024, 160, PGP_HASH_SHA256},
      {1024, 160, PGP_HASH_SHA384},
      {1024, 160, PGP_HASH_SHA512},
      // all 2048 key-hash combinations
      {2048, 256, PGP_HASH_SHA256},
      {2048, 256, PGP_HASH_SHA384},
      {2048, 256, PGP_HASH_SHA512},
      // misc
      {1088, 224, PGP_HASH_SHA512},
      {1024, 256, PGP_HASH_SHA256},
    };

    assert_true(rng_get_data(&global_rng, message, sizeof(message)));

    for (size_t i = 0; i < ARRAY_SIZE(keys); i++) {
        sig = {};
        rnp_keygen_crypto_params_t key_desc;
        key_desc.key_alg = PGP_PKA_DSA;
        key_desc.hash_alg = keys[i].h;
        key_desc.dsa.p_bitlen = keys[i].p;
        key_desc.dsa.q_bitlen = keys[i].q;
        key_desc.rng = &global_rng;

        assert_true(pgp_generate_seckey(&key_desc, &seckey, true));
        // try to prevent timeouts in travis-ci
        printf("p: %zu q: %zu h: %s\n",
               key_desc.dsa.p_bitlen,
               key_desc.dsa.q_bitlen,
               pgp_show_hash_alg(key_desc.hash_alg));
        fflush(stdout);

        pgp_dsa_key_t *key1 = &seckey.material.dsa;

        size_t h_size = pgp_digest_length(keys[i].h);
        assert_int_equal(dsa_sign(&global_rng, &sig, message, h_size, key1), RNP_SUCCESS);
        assert_int_equal(dsa_verify(&sig, message, h_size, key1), RNP_SUCCESS);
    }
}

TEST_F(rnp_tests, test_dsa_verify_negative)
{
    uint8_t             message[PGP_MAX_HASH_SIZE];
    pgp_key_pkt_t       sec_key1;
    pgp_key_pkt_t       sec_key2;
    pgp_dsa_signature_t sig = {};

    struct key_params {
        size_t         p;
        size_t         q;
        pgp_hash_alg_t h;
    } key = {1024, 160, PGP_HASH_SHA1};

    assert_true(rng_get_data(&global_rng, message, sizeof(message)));

    rnp_keygen_crypto_params_t key_desc;
    key_desc.key_alg = PGP_PKA_DSA;
    key_desc.hash_alg = key.h;
    key_desc.dsa.p_bitlen = key.p;
    key_desc.dsa.q_bitlen = key.q;
    key_desc.rng = &global_rng;

    assert_true(pgp_generate_seckey(&key_desc, &sec_key1, true));
    // try to prevent timeouts in travis-ci
    printf("p: %zu q: %zu h: %s\n",
           key_desc.dsa.p_bitlen,
           key_desc.dsa.q_bitlen,
           pgp_show_hash_alg(key_desc.hash_alg));
    assert_true(pgp_generate_seckey(&key_desc, &sec_key2, true));

    pgp_dsa_key_t *key1 = &sec_key1.material.dsa;
    pgp_dsa_key_t *key2 = &sec_key2.material.dsa;

    size_t h_size = pgp_digest_length(key.h);
    assert_int_equal(dsa_sign(&global_rng, &sig, message, h_size, key1), RNP_SUCCESS);
    // wrong key used
    assert_int_equal(dsa_verify(&sig, message, h_size, key2), RNP_ERROR_SIGNATURE_INVALID);
    // different message
    message[0] = ~message[0];
    assert_int_equal(dsa_verify(&sig, message, h_size, key1), RNP_ERROR_SIGNATURE_INVALID);
}

TEST_F(rnp_tests, s2k_iteration_tuning)
{
    pgp_hash_alg_t hash_alg = PGP_HASH_SHA512;

    /*
    Run trials for a while (1/4 second) to ensure dynamically clocked
    cores spin up to full speed.
    */
    const size_t TRIAL_MSEC = 250;

    const size_t iters_100 = pgp_s2k_compute_iters(hash_alg, 100, TRIAL_MSEC);
    const size_t iters_10 = pgp_s2k_compute_iters(hash_alg, 10, TRIAL_MSEC);

    // fprintf(stderr, "%d %d\n", iters_10, iters_100);
    // Test roughly linear cost, often skeyed by clock idle
    assert_greater_than(static_cast<double>(iters_100) / iters_10, 6);

    // Should not crash for unknown hash algorithm
    assert_int_equal(pgp_s2k_compute_iters(PGP_HASH_UNKNOWN, 1000, TRIAL_MSEC), 0);
    /// TODO test that hashing iters_xx data takes roughly requested time
}

TEST_F(rnp_tests, s2k_iteration_encode_decode)
{
    const size_t MAX_ITER = 0x3e00000; // 0x1F << (0xF + 6);
    // encoding tests
    assert_int_equal(pgp_s2k_encode_iterations(0), 0);
    assert_int_equal(pgp_s2k_encode_iterations(512), 0);
    assert_int_equal(pgp_s2k_encode_iterations(1024), 0);
    assert_int_equal(pgp_s2k_encode_iterations(1024), 0);
    assert_int_equal(pgp_s2k_encode_iterations(1025), 1);
    assert_int_equal(pgp_s2k_encode_iterations(1088), 1);
    assert_int_equal(pgp_s2k_encode_iterations(1089), 2);
    assert_int_equal(pgp_s2k_encode_iterations(2048), 16);
    assert_int_equal(pgp_s2k_encode_iterations(MAX_ITER - 1), 0xFF);
    assert_int_equal(pgp_s2k_encode_iterations(MAX_ITER), 0xFF);
    assert_int_equal(pgp_s2k_encode_iterations(MAX_ITER + 1), 0xFF);
    assert_int_equal(pgp_s2k_encode_iterations(SIZE_MAX), 0xFF);
    // decoding tests
    assert_int_equal(pgp_s2k_decode_iterations(0), 1024);
    assert_int_equal(pgp_s2k_decode_iterations(1), 1088);
    assert_int_equal(pgp_s2k_decode_iterations(16), 2048);
    assert_int_equal(pgp_s2k_decode_iterations(0xFF), MAX_ITER);
}

static bool
read_key_pkt(pgp_key_pkt_t *key, const char *path)
{
    pgp_source_t src = {};
    if (init_file_src(&src, path)) {
        return false;
    }
    bool res = !key->parse(src);
    src_close(&src);
    return res;
}

#define KEYS "data/test_validate_key_material/"

TEST_F(rnp_tests, test_validate_key_material)
{
    pgp_key_pkt_t key;
    rng_t         rng = {};
    rng_init(&rng, RNG_SYSTEM);

    /* RSA key and subkey */
    assert_true(read_key_pkt(&key, KEYS "rsa-pub.pgp"));
    assert_rnp_success(validate_pgp_key_material(&key.material, &rng));
    key.material.rsa.n.mpi[key.material.rsa.n.len - 1] &= ~1;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.rsa.n.mpi[key.material.rsa.n.len - 1] |= 1;
    key.material.rsa.e.mpi[key.material.rsa.e.len - 1] &= ~1;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key = pgp_key_pkt_t();

    assert_true(read_key_pkt(&key, KEYS "rsa-sub.pgp"));
    assert_rnp_success(validate_pgp_key_material(&key.material, &rng));
    key.material.rsa.n.mpi[key.material.rsa.n.len - 1] &= ~1;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.rsa.n.mpi[key.material.rsa.n.len - 1] |= 1;
    key.material.rsa.e.mpi[key.material.rsa.e.len - 1] &= ~1;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key = pgp_key_pkt_t();

    assert_true(read_key_pkt(&key, KEYS "rsa-sec.pgp"));
    assert_rnp_success(decrypt_secret_key(&key, NULL));
    assert_true(key.material.secret);
    assert_rnp_success(validate_pgp_key_material(&key.material, &rng));
    key.material.rsa.e.mpi[key.material.rsa.e.len - 1] += 1;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.rsa.e.mpi[key.material.rsa.e.len - 1] -= 1;
    key.material.rsa.p.mpi[key.material.rsa.p.len - 1] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.rsa.p.mpi[key.material.rsa.p.len - 1] -= 2;
    key.material.rsa.p.mpi[key.material.rsa.q.len - 1] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.rsa.p.mpi[key.material.rsa.q.len - 1] -= 2;
    assert_rnp_success(validate_pgp_key_material(&key.material, &rng));
    key = pgp_key_pkt_t();

    assert_true(read_key_pkt(&key, KEYS "rsa-ssb.pgp"));
    assert_rnp_success(decrypt_secret_key(&key, NULL));
    assert_true(key.material.secret);
    assert_rnp_success(validate_pgp_key_material(&key.material, &rng));
    key.material.rsa.e.mpi[key.material.rsa.e.len - 1] += 1;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.rsa.e.mpi[key.material.rsa.e.len - 1] -= 1;
    key.material.rsa.p.mpi[key.material.rsa.p.len - 1] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.rsa.p.mpi[key.material.rsa.p.len - 1] -= 2;
    key.material.rsa.p.mpi[key.material.rsa.q.len - 1] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.rsa.p.mpi[key.material.rsa.q.len - 1] -= 2;
    assert_rnp_success(validate_pgp_key_material(&key.material, &rng));
    key = pgp_key_pkt_t();

    /* DSA-ElGamal key */
    assert_true(read_key_pkt(&key, KEYS "dsa-sec.pgp"));
    key.material.dsa.q.mpi[key.material.dsa.q.len - 1] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.dsa.q.mpi[key.material.dsa.q.len - 1] -= 2;
    assert_rnp_success(decrypt_secret_key(&key, NULL));
    assert_true(key.material.secret);
    assert_rnp_success(validate_pgp_key_material(&key.material, &rng));
    key.material.dsa.y.mpi[key.material.dsa.y.len - 1] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.dsa.y.mpi[key.material.dsa.y.len - 1] -= 2;
    key.material.dsa.p.mpi[key.material.dsa.p.len - 1] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.dsa.p.mpi[key.material.dsa.p.len - 1] -= 2;
    /* since Botan calculates y from x on key load we do not check x vs y */
    key.material.dsa.x = key.material.dsa.q;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key = pgp_key_pkt_t();

    assert_true(read_key_pkt(&key, KEYS "eg-sec.pgp"));
    key.material.eg.p.mpi[key.material.eg.p.len - 1] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.eg.p.mpi[key.material.eg.p.len - 1] -= 2;
    assert_rnp_success(decrypt_secret_key(&key, NULL));
    assert_true(key.material.secret);
    assert_rnp_success(validate_pgp_key_material(&key.material, &rng));
    key.material.eg.p.mpi[key.material.eg.p.len - 1] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.eg.p.mpi[key.material.eg.p.len - 1] -= 2;
    /* since Botan calculates y from x on key load we do not check x vs y */
    key.material.eg.x = key.material.eg.p;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key = pgp_key_pkt_t();

    /* ECDSA key */
    assert_true(read_key_pkt(&key, KEYS "ecdsa-p256-sec.pgp"));
    assert_rnp_success(validate_pgp_key_material(&key.material, &rng));
    key.material.ec.p.mpi[0] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.ec.p.mpi[0] -= 2;
    key.material.ec.p.mpi[10] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.ec.p.mpi[10] -= 2;
    assert_rnp_success(decrypt_secret_key(&key, NULL));
    assert_true(key.material.secret);
    key = pgp_key_pkt_t();

    /* ECDH key */
    assert_true(read_key_pkt(&key, KEYS "ecdh-p256-sec.pgp"));
    assert_rnp_success(validate_pgp_key_material(&key.material, &rng));
    key.material.ec.p.mpi[0] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.ec.p.mpi[0] -= 2;
    key.material.ec.p.mpi[10] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.ec.p.mpi[10] -= 2;
    assert_rnp_success(decrypt_secret_key(&key, NULL));
    assert_true(key.material.secret);
    key = pgp_key_pkt_t();

    /* EDDSA key, just test for header since any value can be secret key */
    assert_true(read_key_pkt(&key, KEYS "ed25519-sec.pgp"));
    assert_rnp_success(validate_pgp_key_material(&key.material, &rng));
    key.material.ec.p.mpi[0] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.ec.p.mpi[0] -= 2;
    key = pgp_key_pkt_t();

    /* x25519 key, same as the previous - botan calculates pub key from the secret one */
    assert_true(read_key_pkt(&key, KEYS "x25519-sec.pgp"));
    assert_rnp_success(validate_pgp_key_material(&key.material, &rng));
    key.material.ec.p.mpi[0] += 2;
    assert_rnp_failure(validate_pgp_key_material(&key.material, &rng));
    key.material.ec.p.mpi[0] -= 2;
    key = pgp_key_pkt_t();

    rng_destroy(&rng);
}

TEST_F(rnp_tests, test_sm2_enabled)
{
    char *features = NULL;
    bool  supported = false;
    /* check whether FFI returns value which corresponds to defines */
#if defined(ENABLE_SM2)
    assert_true(sm2_enabled());
    /* SM2 */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_PK_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM2") != std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "SM2", &supported));
    assert_true(supported);
    /* SM3 */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_HASH_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM3") != std::string::npos);
    rnp_buffer_destroy(features);
    supported = false;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "SM3", &supported));
    assert_true(supported);
    /* SM4 */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_SYMM_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM4") != std::string::npos);
    rnp_buffer_destroy(features);
    supported = false;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "SM4", &supported));
    assert_true(supported);
    /* Curve */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_CURVE, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM2 P-256") != std::string::npos);
    rnp_buffer_destroy(features);
    supported = false;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "SM2 P-256", &supported));
    assert_true(supported);
#else
    assert_false(sm2_enabled());
    /* SM2 */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_PK_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM2") == std::string::npos);
    rnp_buffer_destroy(features);
    supported = true;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "SM2", &supported));
    assert_false(supported);
    /* SM3 */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_HASH_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM3") == std::string::npos);
    rnp_buffer_destroy(features);
    supported = true;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "SM3", &supported));
    assert_false(supported);
    /* SM4 */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_SYMM_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM4") == std::string::npos);
    rnp_buffer_destroy(features);
    supported = true;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "SM4", &supported));
    assert_false(supported);
    /* Curve */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_CURVE, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM2 P-256") == std::string::npos);
    rnp_buffer_destroy(features);
    supported = true;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "SM2 P-256", &supported));
    assert_false(supported);
#endif
}

TEST_F(rnp_tests, test_aead_enabled)
{
    char *features = NULL;
    bool  supported = false;
    /* check whether FFI returns value which corresponds to defines */
#if defined(ENABLE_AEAD)
    assert_true(aead_eax_enabled());
    assert_true(aead_ocb_enabled());
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_AEAD_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("EAX") != std::string::npos);
    assert_true(std::string(features).find("OCB") != std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_AEAD_ALG, "EAX", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_AEAD_ALG, "OCB", &supported));
    assert_true(supported);
#else
    assert_false(aead_eax_enabled());
    assert_false(aead_ocb_enabled());
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_AEAD_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("EAX") == std::string::npos);
    assert_true(std::string(features).find("OCB") == std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_AEAD_ALG, "EAX", &supported));
    assert_false(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_AEAD_ALG, "OCB", &supported));
    assert_false(supported);
#endif
}

TEST_F(rnp_tests, test_twofish_enabled)
{
    char *features = NULL;
    bool  supported = false;
    /* check whether FFI returns value which corresponds to defines */
#if defined(ENABLE_TWOFISH)
    assert_true(twofish_enabled());
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_SYMM_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("TWOFISH") != std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "TWOFISH", &supported));
    assert_true(supported);
#else
    assert_false(twofish_enabled());
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_SYMM_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("TWOFISH") == std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "TWOFISH", &supported));
    assert_false(supported);
#endif
}

TEST_F(rnp_tests, test_brainpool_enabled)
{
    char *features = NULL;
    bool  supported = false;
    /* check whether FFI returns value which corresponds to defines */
#if defined(ENABLE_BRAINPOOL)
    assert_true(brainpool_enabled());
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_CURVE, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("brainpool") != std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP256r1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP384r1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP512r1", &supported));
    assert_true(supported);
#else
    assert_false(brainpool_enabled());
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_CURVE, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("brainpool") == std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP256r1", &supported));
    assert_false(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP384r1", &supported));
    assert_false(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP512r1", &supported));
    assert_false(supported);
#endif
}
