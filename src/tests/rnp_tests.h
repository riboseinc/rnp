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

#ifndef RNP_TESTS_H
#define RNP_TESTS_H

#include <gtest/gtest.h>
#include "support.h"

class rnp_tests : public ::testing::Test {
  public:
    rnp_tests();
    virtual ~rnp_tests();

    const char *original_dir() const;

  protected:
    char *m_dir;
};

typedef struct {
    char *original_dir;
    char *home;
    char *data_dir;
    int   not_fatal;
} rnp_test_state_t;

void rnpkeys_exportkey_verifyUserId(void **state);

void rnpkeys_generatekey_testSignature(void **state);

void rnpkeys_generatekey_testEncryption(void **state);

void rnpkeys_generatekey_verifySupportedHashAlg(void **state);

void rnpkeys_generatekey_verifyUserIdOption(void **state);

void rnpkeys_generatekey_verifykeyHomeDirOption(void **state);

void rnpkeys_generatekey_verifykeyKBXHomeDirOption(void **state);

void rnpkeys_generatekey_verifykeyHomeDirNoPermission(void **state);

void rnp_test_eddsa(void **state);

void rnp_test_x25519(void **state);

void hash_test_success(void **state);

void cipher_test_success(void **state);

void pkcs1_rsa_test_success(void **state);

void raw_elgamal_random_key_test_success(void **state);

void ecdsa_signverify_success(void **state);

void rnpkeys_generatekey_testExpertMode(void **state);

void generatekeyECDSA_explicitlySetSmallOutputDigest_DigestAlgAdjusted(void **state);

void generatekeyECDSA_explicitlySetBiggerThanNeededDigest_ShouldSuceed(void **state);

void generatekey_multipleUserIds_ShouldFail(void **state);

void generatekeyECDSA_explicitlySetUnknownDigest_ShouldFail(void **state);

void s2k_iteration_tuning(void **state);
void s2k_iteration_encode_decode(void **state);

void test_s2k_iterations(void **state);

void test_validate_key_material(void **state);

void test_utils_list(void **state);

void test_rnpcfg(void **state);

void test_load_user_prefs(void **state);

void ecdh_roundtrip(void **state);

void ecdh_decryptionNegativeCases(void **state);

void sm2_roundtrip(void **state);
void sm2_sm3_signature_test(void **state);
void sm2_sha256_signature_test(void **state);

void test_load_v3_keyring_pgp(void **state);

void test_load_v4_keyring_pgp(void **state);

void test_load_keyring_and_count_pgp(void **state);

void test_load_check_bitfields_and_times(void **state);

void test_load_check_bitfields_and_times_v3(void **state);

void test_load_g10(void **state);

void test_load_armored_pub_sec(void **state);

void test_load_merge(void **state);

void test_load_public_from_secret(void **state);

void test_key_import(void **state);

void test_key_grip(void **state);

void test_key_prefs(void **state);

void test_load_subkey(void **state);

void test_key_unlock_pgp(void **state);

void test_key_validate(void **state);

void test_forged_key_validate(void **state);

void test_key_protect_load_pgp(void **state);

void test_key_add_userid(void **state);

void test_generated_key_sigs(void **state);

void test_key_store_search(void **state);

void test_key_store_search_by_name(void **state);

void test_ffi_api(void **state);

void test_ffi_homedir(void **state);

void test_ffi_keygen_json_pair(void **state);

void test_ffi_keygen_json_pair_dsa_elg(void **state);

void test_ffi_keygen_json_primary(void **state);

void test_ffi_keygen_json_sub(void **state);

void test_ffi_keygen_json_sub_pass_required(void **state);

void test_ffi_key_generate_misc(void **state);

void test_ffi_key_generate_rsa(void **state);

void test_ffi_key_generate_dsa(void **state);

void test_ffi_key_generate_ecdsa(void **state);

void test_ffi_key_generate_eddsa(void **state);

void test_ffi_key_generate_sm2(void **state);

void test_ffi_key_generate_ex(void **state);

void test_ffi_key_generate_algnamecase(void **state);

void test_ffi_key_generate_protection(void **state);

void test_ffi_add_userid(void **state);

void test_ffi_detect_key_format(void **state);

void test_ffi_load_keys(void **state);

void test_ffi_clear_keys(void **state);

void test_ffi_save_keys(void **state);

void test_ffi_load_save_keys_to_utf8_path(void **state);

void test_ffi_encrypt_pass(void **state);

void test_ffi_encrypt_pass_provider(void **state);

void test_ffi_encrypt_pk(void **state);

void test_ffi_encrypt_pk_subkey_selection(void **state);

void test_ffi_encrypt_and_sign(void **state);

void test_ffi_signatures_memory(void **state);

void test_ffi_signatures_detached_memory(void **state);

void test_ffi_signatures_detached(void **state);

void test_ffi_signatures(void **state);

void test_ffi_signatures_dump(void **state);

void test_ffi_encrypt_pk_key_provider(void **state);

void test_ffi_key_to_json(void **state);

void test_ffi_key_iter(void **state);

void test_ffi_locate_key(void **state);

void test_ffi_signatures_detached_memory_g10(void **state);

void test_ffi_enarmor_dearmor(void **state);

void test_ffi_customized_enarmor(void **state);

void test_ffi_dearmor_edge_cases(void **state);

void test_ffi_version(void **state);

void test_ffi_key_export(void **state);

void test_ffi_key_export_customized_enarmor(void **state);

void test_ffi_key_dump(void **state);

void test_ffi_key_dump_edge_cases(void **state);

void test_ffi_key_userid_dump_has_no_special_chars(void **state);

void test_ffi_pkt_dump(void **state);

void test_ffi_rsa_v3_dump(void **state);

void test_ffi_load_userattr(void **state);

void test_ffi_revocations(void **state);

void test_ffi_file_output(void **state);

void test_ffi_key_signatures(void **state);

void test_ffi_keys_import(void **state);

void test_ffi_iterated_key_import(void **state);

void test_ffi_stripped_keys_import(void **state);

void test_ffi_malformed_keys_import(void **state);

void test_ffi_import_keys_check_pktlen(void **state);

void test_ffi_elgamal4096(void **state);

void test_ffi_calculate_iterations(void **state);

void test_ffi_supported_features(void **state);

void test_ffi_enable_debug(void **state);

void test_ffi_rnp_key_get_primary_grip(void **state);

void test_ffi_rnp_key_get_primary_fprint(void **state);

void test_ffi_output_to_armor(void **state);

void test_ffi_rnp_guess_contents(void **state);

void test_ffi_literal_filename(void **state);

void test_ffi_op_set_hash(void **state);

void test_ffi_op_set_compression(void **state);

void test_ffi_aead_params(void **state);

void test_ffi_detached_verify_input(void **state);

void test_ffi_op_verify_sig_count(void **state);

void test_ffi_op_verify_get_protection_info(void **state);

void test_ffi_op_verify_recipients_info(void **state);

void test_ffi_import_signatures(void **state);

void test_ffi_export_revocation(void **state);

void test_ffi_secret_sig_import(void **state);

void test_ffi_rnp_request_password(void **state);

void test_ffi_key_revoke(void **state);

void test_ffi_set_key_expiry(void **state);

void test_ffi_mdc_8k_boundary(void **state);

void test_ffi_decrypt_wrong_mpi_bits(void **state);

void test_ffi_key_import_edge_cases(void **state);

void test_ffi_key_import_gpg_s2k(void **state);

void test_ffi_key_remove(void **state);

void test_ffi_literal_packet(void **state);

void test_ffi_detached_cleartext_signed_input(void **state);

void test_ffi_key_export_autocrypt(void **state);

void test_ffi_decrypt_edge_cases(void **state);

void test_ffi_key_get_protection_info(void **state);

void test_ffi_sig_validity(void **state);

void test_ffi_get_signature_type(void **state);

void test_ffi_remove_signature(void **state);

void test_ffi_remove_signatures(void **state);

void test_ffi_remove_uid(void **state);

void test_rnp_mkstemp(void **state);

void test_rnp_access(void **state);

void test_dsa_roundtrip(void **state);

void test_dsa_verify_negative(void **state);

void test_stream_memory(void **state);

void test_stream_memory_discard(void **state);

void test_stream_file(void **state);

void test_stream_signatures(void **state);

void test_stream_signatures_revoked_key(void **state);

void test_stream_key_load(void **state);

void test_stream_key_load_errors(void **state);

void test_stream_key_decrypt(void **state);

void test_stream_key_encrypt(void **state);

void test_stream_key_signatures(void **state);

void test_stream_dumper(void **state);

void test_y2k38(void **state);

void test_stream_dumper_y2k38(void **state);

void test_stream_z(void **state);

void test_stream_verify_no_key(void **state);

void test_stream_key_signature_validate(void **state);

void test_stream_deep_packet_nesting(void **state);

void test_stream_cache(void **state);

void test_key_validity(void **state);

void test_stream_814_dearmor_double_free(void **state);

void test_stream_825_dearmor_blank_line(void **state);

void test_stream_dearmor_edge_cases(void **state);

void test_cli_rnpkeys(void **state);

void test_cli_rnpkeys_unicode(void **state);

void test_cli_rnp(void **state);

void test_cli_rnp_keyfile(void **state);

void test_cli_g10_operations(void **state);

void test_cli_examples(void **state);

void test_cli_dump(void **state);

void test_large_packet(void **state);

void test_large_mpi_rsa_pub(void **state);

void test_large_mpi_rsa_priv(void **state);

void test_partial_length_signature(void **state);

void test_partial_length_public_key(void **state);

void test_partial_length_first_packet_256(void **state);

void test_partial_length_zero_last_chunk(void **state);

void test_partial_length_largest(void **state);

void test_partial_length_first_packet_length(void **state);

void test_pipe(void **state);

void test_pipe_source_error(void **state);

void test_pipe_dest_error(void **state);

void test_kbx_nsigs(void **state);

void test_issue_1115(void **state);

void issue_1030_rnpkeys_secret_keys_unprotected(void **state);

void test_issue_1171_key_import_and_remove(void **state);

void test_log_switch(void **state);

void test_fuzz_keyring(void **state);

void test_fuzz_keyring_g10(void **state);

void test_fuzz_keyring_kbx(void **state);

void test_fuzz_keyimport(void **state);

void test_fuzz_dump(void **state);

void test_fuzz_verify_detached(void **state);

#define assert_true(a) EXPECT_TRUE((a))
#define assert_false(a) EXPECT_FALSE((a))
#define assert_string_equal(a, b) EXPECT_STREQ((a), (b))
#define assert_int_equal(a, b) EXPECT_EQ((a), (b))
#define assert_int_not_equal(a, b) EXPECT_NE((a), (b))
#define assert_greater_than(a, b) EXPECT_GT((a), (b))
#define assert_non_null(a) EXPECT_NE((a), nullptr)
#define assert_null(a) EXPECT_EQ((a), nullptr)
#define assert_rnp_success(a) EXPECT_EQ((a), RNP_SUCCESS)
#define assert_rnp_failure(a) EXPECT_NE((a), RNP_SUCCESS)
#define assert_memory_equal(a, b, sz) EXPECT_EQ(0, memcmp((a), (b), (sz)))
#define assert_memory_not_equal(a, b, sz) EXPECT_NE(0, memcmp((a), (b), (sz)))

#endif // RNP_TESTS_H
