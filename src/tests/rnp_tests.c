/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>

#include <crypto/rng.h>
#include "rnp_tests.h"
#include "support.h"

static const char *exe_path = NULL;
static char        original_dir[PATH_MAX];

/*
 * Handler used to access DRBG.
 */
rng_t global_rng;

static char *
get_data_dir(void)
{
    char  data_dir[PATH_MAX];
    char *exe_dir = directory_from_file_path(exe_path, original_dir);

    if (!exe_dir) {
        return NULL;
    }
    paths_concat(data_dir, sizeof(data_dir), exe_dir, "../data", NULL);
    free(exe_dir);
    return realpath(data_dir, NULL);
}

static int
setup_test_group(void **state)
{
    rnp_test_state_t *rstate = calloc(1, sizeof(rnp_test_state_t));

    if (!rstate) {
        return -1;
    }
    *state = rstate;
    return 0;
}

static int
teardown_test_group(void **state)
{
    rnp_test_state_t *rstate = *state;

    if (!rstate) {
        return -1;
    }

    free(rstate);

    *state = NULL;
    return 0;
}

static int
setup_test(void **state)
{
    rnp_test_state_t *rstate = *state;

    rstate->home = make_temp_dir();
    if (rstate->home == NULL) {
        return -1;
    }
    rstate->data_dir = rnp_compose_path(rstate->home, "data", NULL);
    if (!rstate->data_dir) {
        return -1;
    }
    if (getenv("RNP_TEST_NOT_FATAL")) {
        rstate->not_fatal = 1;
    } else {
        rstate->not_fatal = 0;
    }
    assert_int_equal(0, setenv("HOME", rstate->home, 1));
    assert_int_equal(0, chdir(rstate->home));
    char *src_data = get_data_dir();
    if (!src_data) {
        return -1;
    }
    copy_recursively(src_data, rstate->data_dir);
    free(src_data);
    return 0;
}

static int
teardown_test(void **state)
{
    rnp_test_state_t *rstate = *state;
    delete_recursively(rstate->home);
    free(rstate->home);
    rstate->home = NULL;
    free(rstate->data_dir);
    rstate->data_dir = NULL;
    rng_destroy(&global_rng);
    return 0;
}

int
main(int argc, char *argv[])
{
    exe_path = argv[0];
    assert_non_null(getcwd(original_dir, sizeof(original_dir)));

    /* We use LOGNAME in a few places within the tests
     * and it isn't always set in every environment.
     */
    if (!getenv("LOGNAME")) {
        setenv("LOGNAME", "test-user", 1);
    }
    int iteration = 1;
    if (getenv("RNP_TEST_ITERATIONS")) {
        iteration = atoi(getenv("RNP_TEST_ITERATIONS"));
    }

    struct CMUnitTest tests[] = {
      cmocka_unit_test(hash_test_success),
      cmocka_unit_test(cipher_test_success),
      cmocka_unit_test(pkcs1_rsa_test_success),
      cmocka_unit_test(raw_elgamal_fixed_512bit_key_test_success),
      cmocka_unit_test(raw_elgamal_random_key_test_success),
      cmocka_unit_test(rnp_test_eddsa),
      cmocka_unit_test(ecdsa_signverify_success),
      cmocka_unit_test(rnpkeys_generatekey_testSignature),
      cmocka_unit_test(rnpkeys_generatekey_testEncryption),
      cmocka_unit_test(rnpkeys_generatekey_verifySupportedHashAlg),
      cmocka_unit_test(rnpkeys_generatekey_verifyUserIdOption),
      cmocka_unit_test(rnpkeys_generatekey_verifykeyHomeDirOption),
      cmocka_unit_test(rnpkeys_generatekey_verifykeyKBXHomeDirOption),
      cmocka_unit_test(rnpkeys_generatekey_verifykeyNonexistingHomeDir),
      cmocka_unit_test(rnpkeys_generatekey_verifykeyHomeDirNoPermission),
      cmocka_unit_test(rnpkeys_exportkey_verifyUserId),
      cmocka_unit_test(rnpkeys_generatekey_testExpertMode),
      cmocka_unit_test(generatekeyECDSA_explicitlySetSmallOutputDigest_DigestAlgAdjusted),
      cmocka_unit_test(generatekeyECDSA_explicitlySetBiggerThanNeededDigest_ShouldSuceed),
      cmocka_unit_test(generatekeyECDSA_explicitlySetWrongDigest_ShouldSuceed),
      cmocka_unit_test(test_utils_list),
      cmocka_unit_test(test_rnpcfg),
      cmocka_unit_test(pgp_parse_keyrings_1_pubring),
      cmocka_unit_test(test_load_user_prefs),
      cmocka_unit_test(ecdh_roundtrip),
      cmocka_unit_test(ecdh_decryptionNegativeCases),
      cmocka_unit_test(sm2_roundtrip),
      cmocka_unit_test(test_dsa_roundtrip),
      cmocka_unit_test(test_dsa_verify_negative),
      cmocka_unit_test(test_load_v3_keyring_pgp),
      cmocka_unit_test(test_load_v4_keyring_pgp),
      cmocka_unit_test(test_load_keyring_and_count_pgp),
      cmocka_unit_test(test_load_check_bitfields_and_times),
      cmocka_unit_test(test_load_check_bitfields_and_times_v3),
      cmocka_unit_test(test_key_unlock_pgp),
      cmocka_unit_test(test_key_protect_load_pgp),
      cmocka_unit_test(test_key_add_userid),
      cmocka_unit_test(test_repgp_decrypt),
      cmocka_unit_test(test_repgp_verify),
      cmocka_unit_test(test_repgp_list_packets),
      cmocka_unit_test(test_generated_key_sigs),
      cmocka_unit_test(test_key_store_search),
      cmocka_unit_test(test_stream_signatures),
      cmocka_unit_test(test_ffi_homedir),
      cmocka_unit_test(test_ffi_keygen_json_pair),
      cmocka_unit_test(test_ffi_keygen_json_primary),
      cmocka_unit_test(test_ffi_keygen_json_sub),
      cmocka_unit_test(test_ffi_keygen_json_sub_pass_required),
      cmocka_unit_test(test_ffi_add_userid),
      cmocka_unit_test(test_ffi_detect_key_format),
      cmocka_unit_test(test_ffi_encrypt_pass),
      cmocka_unit_test(test_ffi_encrypt_pk),
      cmocka_unit_test(test_ffi_encrypt_and_sign),
      cmocka_unit_test(test_ffi_signatures_memory),
      cmocka_unit_test(test_ffi_signatures_detached_memory),
      cmocka_unit_test(test_ffi_signatures_detached),
      cmocka_unit_test(test_ffi_signatures),
      cmocka_unit_test(test_ffi_load_keys),
      cmocka_unit_test(test_ffi_save_keys),
      cmocka_unit_test(test_ffi_key_to_json),
      cmocka_unit_test(test_ffi_key_iter),
    };

    /* Each test entry will invoke setup_test before running
     * and teardown_test after running. */
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        tests[i].setup_func = setup_test;
        tests[i].teardown_func = teardown_test;
    }

    int ret = 0;
    for (int i = 0; i < iteration; i++) {
        printf("Iteration %d\n", i);
        ret = cmocka_run_group_tests(tests, setup_test_group, teardown_test_group);
        if (ret != 0) {
            break;
        }
    }
    return ret;
}
