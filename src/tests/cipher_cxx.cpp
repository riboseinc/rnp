/*
 * Copyright (c) 2017-2021 [Ribose Inc](https://www.ribose.com).
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

#include <fstream>
#include <vector>
#include <string>

#include <cstring>
#include <rnp/rnp.h>
#include "rnp_tests.h"
#include "support.h"
#include "utils.h"
#include <vector>
#include <string>
#include <crypto/cipher.hpp>
#include <crypto/mem.h>

static std::vector<uint8_t>
decode_hex(const char *hex)
{
    if (!hex) {
        return {};
    }
    std::vector<uint8_t> data(strlen(hex) / 2);
    assert_true(rnp::hex_decode(hex, data.data(), data.size()));
    return data;
}

void
test_cipher(pgp_symm_alg_t    alg,
            pgp_cipher_mode_t mode,
            size_t            tag_size,
            bool              disable_padding,
            const char *      key_hex,
            const char *      iv_hex,
            const char *      ad_hex,
            const char *      pt_hex,
            const char *      expected_ct_hex)
{
    const std::vector<uint8_t> key(decode_hex(key_hex));
    const std::vector<uint8_t> iv(decode_hex(iv_hex));
    const std::vector<uint8_t> ad(decode_hex(ad_hex));
    const std::vector<uint8_t> pt(decode_hex(pt_hex));
    const std::vector<uint8_t> expected_ct(decode_hex(expected_ct_hex));

    auto                 enc = Cipher::encryption(alg, mode, tag_size, disable_padding);
    const size_t         block_size = enc->block_size();
    const size_t         ud = enc->update_granularity();
    std::vector<uint8_t> ct;
    // make room for padding
    ct.resize(((pt.size() + tag_size) / block_size + 1) * block_size);
    // set key & iv
    assert_true(enc->set_key(key.data(), key.size()));
    assert_true(enc->set_iv(iv.data(), iv.size()));
    if (!ad.empty()) {
        assert_true(enc->set_ad(ad.data(), ad.size()));
    }

    // encrypt all in one go
    size_t output_written, input_consumed;
    assert_true(enc->finish(
      ct.data(), ct.size(), &output_written, pt.data(), pt.size(), &input_consumed));
    ct.resize(output_written);
    assert_memory_equal(ct.data(), expected_ct.data(), expected_ct.size());

    // start over
    enc.reset(Cipher::encryption(alg, mode, tag_size, disable_padding).release());
    assert_true(enc->set_key(key.data(), key.size()));
    assert_true(enc->set_iv(iv.data(), iv.size()));
    if (!ad.empty()) {
        assert_true(enc->set_ad(ad.data(), ad.size()));
    }
    ct.clear();
    ct.resize(((pt.size() + tag_size) / block_size + 1) * block_size);
    // encrypt in pieces
    assert_memory_not_equal(ct.data(), expected_ct.data(), expected_ct.size());
    // all except the last block
    size_t nonfinal_bytes = rnp_round_up(pt.size(), ud) - ud;
    output_written = 0;
    input_consumed = 0;
    size_t written, consumed;
    while (input_consumed != nonfinal_bytes) {
        assert_true(enc->update(ct.data() + output_written,
                                ct.size() - output_written,
                                &written,
                                pt.data() + input_consumed,
                                ud,
                                &consumed));
        output_written += written;
        input_consumed += consumed;
    }
    assert_true(enc->finish(ct.data() + output_written,
                            ct.size() - output_written,
                            &written,
                            pt.data() + input_consumed,
                            pt.size() - input_consumed,
                            &consumed));
    output_written += written;
    ct.resize(output_written);
    assert_int_equal(ct.size(), expected_ct.size());
    assert_memory_equal(ct.data(), expected_ct.data(), expected_ct.size());
    enc.reset();

    // decrypt
    auto dec = Cipher::decryption(alg, mode, tag_size, disable_padding);
    assert_true(dec->set_key(key.data(), key.size()));
    assert_true(dec->set_iv(iv.data(), iv.size()));
    if (!ad.empty()) {
        assert_true(dec->set_ad(ad.data(), ad.size()));
    }
    // decrypt in pieces
    std::vector<uint8_t> decrypted(ct.size());
    // all except the last block
    nonfinal_bytes = rnp_round_up(ct.size(), ud) - ud;
    output_written = 0;
    input_consumed = 0;
    while (input_consumed != nonfinal_bytes) {
        assert_true(dec->update(decrypted.data() + output_written,
                                decrypted.size() - output_written,
                                &written,
                                (const uint8_t *) ct.data() + input_consumed,
                                ud,
                                &consumed));
        output_written += written;
        input_consumed += consumed;
    }
    assert_true(dec->finish(decrypted.data() + output_written,
                            decrypted.size() - output_written,
                            &written,
                            (const uint8_t *) ct.data() + input_consumed,
                            ct.size() - input_consumed,
                            &consumed));
    output_written += written;
    decrypted.resize(output_written);
    assert_int_equal(decrypted.size(), pt.size());
    assert_memory_equal(decrypted.data(), pt.data(), pt.size());

    // decrypt with a bad tag
    if (tag_size) {
        dec.reset(Cipher::decryption(alg, mode, tag_size, disable_padding).release());
        assert_true(dec->set_key(key.data(), key.size()));
        assert_true(dec->set_iv(iv.data(), iv.size()));
        if (!ad.empty()) {
            assert_true(dec->set_ad(ad.data(), ad.size()));
        }
        // decrypt in pieces
        std::vector<uint8_t> decrypted(ct.size());
        // all except the last block
        nonfinal_bytes = rnp_round_up(ct.size(), ud) - ud;
        output_written = 0;
        input_consumed = 0;
        while (input_consumed != nonfinal_bytes) {
            assert_true(dec->update(decrypted.data() + output_written,
                                    decrypted.size() - output_written,
                                    &written,
                                    (const uint8_t *) ct.data() + input_consumed,
                                    ud,
                                    &consumed));
            output_written += written;
            input_consumed += consumed;
        }
        // tamper with the tag
        ct.back() ^= 0xff;
        assert_false(dec->finish(decrypted.data() + output_written,
                                 decrypted.size() - output_written,
                                 &written,
                                 (const uint8_t *) ct.data() + input_consumed,
                                 ct.size() - input_consumed,
                                 &consumed));
    }
}

TEST_F(rnp_tests, test_cipher_idea)
{
    // OpenSSL do_crypt man page example
    test_cipher(PGP_SA_IDEA,
                PGP_CIPHER_MODE_CBC,
                0,
                false,
                "000102030405060708090a0b0c0d0e0f",
                "0102030405060708",
                NULL,
                "536f6d652043727970746f2054657874",
                "8974b718d0cb68b44e27c480546dfcc7a33895f461733219");
}

TEST_F(rnp_tests, test_cipher_aes_128_ocb)
{
    // RFC 7253
    test_cipher(PGP_SA_AES_128,
                PGP_CIPHER_MODE_OCB,
                16,
                false,
                "000102030405060708090A0B0C0D0E0F",
                "BBAA99887766554433221104",
                "000102030405060708090A0B0C0D0E0F",
                "000102030405060708090A0B0C0D0E0F",
                "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358");
}

TEST_F(rnp_tests, test_cipher_aes_128_cbc)
{
    // botan test vectors
    test_cipher(PGP_SA_AES_128,
                PGP_CIPHER_MODE_CBC,
                0,
                false,
                "10d6f8e78c0ccf8736e4307aaf5b07ef",
                "3eb182d95bbd5a609aecfb59a0ca898b",
                NULL,
                "3a",
                "a7d290687ae325054a8691014d6821d7");
    test_cipher(PGP_SA_AES_128,
                PGP_CIPHER_MODE_CBC,
                0,
                false,
                "10d6f8e78c0ccf8736e4307aaf5b07ef",
                "3eb182d95bbd5a609aecfb59a0ca898b",
                NULL,
                "3a513eb569a503b4413b31fa883ddc88",
                "0cbaf4fa94df265fe264633a994bc25fc7654f19c282a3e2db81499c941ca2b3");
}

TEST_F(rnp_tests, test_cipher_aes_128_cbc_nopadding)
{
    // botan test vectors
    test_cipher(PGP_SA_AES_128,
                PGP_CIPHER_MODE_CBC,
                0,
                true,
                "1f8e4973953f3fb0bd6b16662e9a3c17",
                "2fe2b333ceda8f98f4a99b40d2cd34a8",
                NULL,
                "45cf12964fc824ab76616ae2f4bf0822",
                "0f61c4d44c5147c03c195ad7e2cc12b2");
}
