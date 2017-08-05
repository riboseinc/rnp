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

#include "rnp_tests.h"
#include "support.h"

static const char *exe_path = NULL;
static char        original_dir[PATH_MAX];

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
    rstate->data_dir = get_data_dir();
    if (!rstate->data_dir) {
        printf("setup_test_group: failed to obtain data_dir\n");
        free(rstate);
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
    free(rstate->data_dir);
    rstate->data_dir = NULL;

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
    if (getenv("RNP_TEST_NOT_FATAL")) {
        rstate->not_fatal = 1;
    } else {
        rstate->not_fatal = 0;
    }
    assert_int_equal(0, setenv("HOME", rstate->home, 1));
    assert_int_equal(0, chdir(rstate->home));
    return 0;
}

static int
teardown_test(void **state)
{
    rnp_test_state_t *rstate = *state;
    delete_recursively(rstate->home);
    free(rstate->home);
    rstate->home = NULL;
    return 0;
}

int
run_lib(int iterations)
{
    int ret, i, j;

    struct CMUnitTest tests[] = {
      cmocka_unit_test(hash_test_success),
      cmocka_unit_test(cipher_test_success),
      cmocka_unit_test(pkcs1_rsa_test_success),
      cmocka_unit_test(raw_elg_test_success),
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
      cmocka_unit_test(generatekeyECDSA_explicitlySetWrongDigest_ShouldFail),
      cmocka_unit_test(test_utils_list),
      cmocka_unit_test(pgp_parse_keyrings_1_pubring),
      cmocka_unit_test(test_load_user_prefs),
      cmocka_unit_test(ecdh_roundtrip),
      cmocka_unit_test(ecdh_decryptionNegativeCases)
    };

    /* Each test entry will invoke setup_test before running
     * and teardown_test after running. */
    for (int i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        tests[i].setup_func = setup_test;
        tests[i].teardown_func = teardown_test;
    }

    if (iterations == 0) {
        ret = cmocka_run_group_tests(tests, setup_test_group, teardown_test_group);
    } else {
        for (i = 0; i < iterations; i++) {
            for (j = 0; j < sizeof(tests) / sizeof(tests[0]); j++) {
                printf("Run iteration %d, test: %s\n", i, tests[j].name);
                void *state;
                if (setup_test(&state)) {
                    continue;
                }
                tests[j].test_func(&state);
                teardown_test(&state);
            }
        }
        ret = 0;
    }

    return ret;
}

int
run_cli()
{
    int ret, i;

    struct CMUnitTest clitests[] = {cmocka_unit_test(cli_rnp), cmocka_unit_test(cli_rnpkeys)};

    for (i = 0; i < sizeof(clitests) / sizeof(clitests[0]); i++) {
        clitests[i].setup_func = setup_test;
        clitests[i].teardown_func = teardown_test;
    }

    ret = cmocka_run_group_tests(clitests, setup_test_group, teardown_test_group);
    return ret;
}

int
run_perf()
{
    int ret, i;

    struct CMUnitTest perftests[] = {cmocka_unit_test(cli_performance)};

    for (i = 0; i < sizeof(perftests) / sizeof(perftests[0]); i++) {
        perftests[i].setup_func = setup_test;
        perftests[i].teardown_func = teardown_test;
    }

    ret = cmocka_run_group_tests(perftests, setup_test_group, teardown_test_group);
    return ret;
}

void
print_usage()
{
    printf("Usage: rnp_tests [cli | perf | lib]\nWithout parameters lib tests are selected\n");
}

int
main(int argc, char **argv)
{
    int  ret;
    int  tests = TST_LIB;
    char cwd[PATH_MAX];

    exe_path = argv[0];
    assert_non_null(getcwd(original_dir, sizeof(original_dir)));

    /* Saving original working directory so we can use it later while calling python scripts.
     * Currently they work only if called from the original directory.
     * This was done before exe_path was introduced in parallel branches, needs review
     */
    assert_non_null(getcwd(cwd, sizeof(cwd)));
    assert_int_equal(0, setenv("ORIGCWD", cwd, 1));

    /* Create a temporary HOME.
     * This is just an extra guard to protect against accidental
     * modifications of a user's HOME.
     */
    char *tmphome = make_temp_dir();
    assert_int_equal(0, setenv("HOME", tmphome, 1));
    assert_int_equal(0, chdir(tmphome));

    /* We use LOGNAME in a few places within the tests
     * and it isn't always set in every environment.
     */
    if (!getenv("LOGNAME"))
        setenv("LOGNAME", "test-user", 1);

    int iterations = 0;
    if (getenv("RNP_TEST_ITERATIONS")) {
        iterations = atoi(getenv("RNP_TEST_ITERATIONS"));
    }

    /* Checking input parameters */
    if (argc == 2) {
        if (strcmp(argv[1], "cli") == 0) {
            tests = TST_CLI;
        } else if (strcmp(argv[1], "perf") == 0) {
            tests = TST_PERF;
        } else if (strcmp(argv[1], "lib") == 0) {
            tests = TST_LIB;
        } else {
            printf("Wrong parameter: %s\n", argv[1]);
            print_usage();
            return 1;
        }
    } else if (argc > 2) {
        printf("Wrong parameter count.\n");
        print_usage();
        return 1;
    }

    /* Running selected tests */
    if (tests == TST_LIB) {
        ret = run_lib(iterations);
    } else if (tests == TST_CLI) {
        ret = run_cli();
    } else if (tests == TST_PERF) {
        ret = run_perf();
    } else {
        ret = 1;
    }

    delete_recursively(tmphome);
    free(tmphome);

    return ret;
}
