/*
 * Copyright (c) 2017-2020 [Ribose Inc](https://www.ribose.com).
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

#include <rnp/rnp.h>
#include "rnp_tests.h"
#include "support.h"
#include "librepgp/stream-common.h"
#include "librepgp/stream-packet.h"
#include "librepgp/stream-sig.h"
#include <json.h>
#include <vector>
#include <string>
#include "file-utils.h"
#include <librepgp/stream-ctx.h>
#include "pgp-key.h"
#include "ffi-priv-types.h"

TEST_F(rnp_tests, test_ffi_homedir)
{
    rnp_ffi_t ffi = NULL;
    char *    pub_format = NULL;
    char *    pub_path = NULL;
    char *    sec_format = NULL;
    char *    sec_path = NULL;

    // get the default homedir (not a very thorough test)
    {
        char *homedir = NULL;
        assert_rnp_success(rnp_get_default_homedir(&homedir));
        assert_non_null(homedir);
        rnp_buffer_destroy(homedir);
    }

    // detect the formats+paths
    assert_rnp_success(rnp_detect_homedir_info(
      "data/keyrings/1", &pub_format, &pub_path, &sec_format, &sec_path));
    // check formats
    assert_string_equal(pub_format, "GPG");
    assert_string_equal(sec_format, "GPG");
    // check paths
    assert_string_equal(pub_path, "data/keyrings/1/pubring.gpg");
    assert_string_equal(sec_path, "data/keyrings/1/secring.gpg");
    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, pub_format, sec_format));
    // load our keyrings
    assert_true(load_keys_gpg(ffi, pub_path, sec_path));
    // free formats+paths
    rnp_buffer_destroy(pub_format);
    pub_format = NULL;
    rnp_buffer_destroy(pub_path);
    pub_path = NULL;
    rnp_buffer_destroy(sec_format);
    sec_format = NULL;
    rnp_buffer_destroy(sec_path);
    sec_path = NULL;
    // check key counts
    size_t count = 0;
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    // detect the formats+paths
    assert_rnp_success(rnp_detect_homedir_info(
      "data/keyrings/3", &pub_format, &pub_path, &sec_format, &sec_path));
    // check formats
    assert_string_equal(pub_format, "KBX");
    assert_string_equal(sec_format, "G10");
    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, pub_format, sec_format));
    // load our keyrings
    assert_true(load_keys_kbx_g10(ffi, pub_path, sec_path));
    // free formats+paths
    rnp_buffer_destroy(pub_format);
    pub_format = NULL;
    rnp_buffer_destroy(pub_path);
    pub_path = NULL;
    rnp_buffer_destroy(sec_format);
    sec_format = NULL;
    rnp_buffer_destroy(sec_path);
    sec_path = NULL;
    // check key counts
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);
    // check grip (1)
    rnp_key_handle_t key = NULL;
    assert_int_equal(
      RNP_SUCCESS,
      rnp_locate_key(ffi, "grip", "63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59", &key));
    assert_non_null(key);
    char *grip = NULL;
    assert_rnp_success(rnp_key_get_grip(key, &grip));
    assert_non_null(grip);
    assert_string_equal(grip, "63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59");
    rnp_buffer_destroy(grip);
    grip = NULL;
    rnp_key_handle_destroy(key);
    key = NULL;
    // check grip (2)
    assert_int_equal(
      RNP_SUCCESS,
      rnp_locate_key(ffi, "grip", "7EAB41A2F46257C36F2892696F5A2F0432499AD3", &key));
    assert_non_null(key);
    grip = NULL;
    assert_rnp_success(rnp_key_get_grip(key, &grip));
    assert_non_null(grip);
    assert_string_equal(grip, "7EAB41A2F46257C36F2892696F5A2F0432499AD3");
    rnp_buffer_destroy(grip);
    grip = NULL;
    assert_rnp_success(rnp_key_handle_destroy(key));
    key = NULL;
    // cleanup
    rnp_ffi_destroy(ffi);
}

static void
load_test_data(const char *file, char **data, size_t *size)
{
    char *      path = NULL;
    struct stat st = {0};

    assert_non_null(file);
    assert_non_null(data);

    path = rnp_compose_path("data", file, NULL);
    assert_non_null(path);

    assert_int_equal(0, rnp_stat(path, &st));
    if (size) {
        *size = st.st_size;
    }
    *data = (char *) calloc(1, st.st_size + 1);
    assert_non_null(*data);

    FILE *fp = rnp_fopen(path, "rb");
    assert_non_null(fp);
    assert_int_equal(st.st_size, fread(*data, 1, st.st_size, fp));
    assert_int_equal(0, fclose(fp));
    free(path);
}

TEST_F(rnp_tests, test_ffi_detect_key_format)
{
    char * data = NULL;
    size_t data_size = 0;
    char * format = NULL;

    // GPG
    data = NULL;
    format = NULL;
    load_test_data("keyrings/1/pubring.gpg", &data, &data_size);
    assert_rnp_success(rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_string_equal(format, "GPG");
    free(data);
    free(format);

    // GPG
    data = NULL;
    format = NULL;
    load_test_data("keyrings/1/secring.gpg", &data, &data_size);
    assert_rnp_success(rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_string_equal(format, "GPG");
    free(data);
    free(format);
    format = NULL;

    // GPG (armored)
    data = NULL;
    format = NULL;
    load_test_data("keyrings/4/rsav3-p.asc", &data, &data_size);
    assert_rnp_success(rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_string_equal(format, "GPG");
    free(data);
    free(format);

    // KBX
    data = NULL;
    format = NULL;
    load_test_data("keyrings/3/pubring.kbx", &data, &data_size);
    assert_rnp_success(rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_string_equal(format, "KBX");
    free(data);
    free(format);

    // G10
    data = NULL;
    format = NULL;
    load_test_data("keyrings/3/private-keys-v1.d/63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59.key",
                   &data,
                   &data_size);
    assert_rnp_success(rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_string_equal(format, "G10");
    free(data);
    free(format);

    // invalid
    format = NULL;
    assert_rnp_success(rnp_detect_key_format((uint8_t *) "ABC", 3, &format));
    assert_null(format);
}

TEST_F(rnp_tests, test_ffi_load_keys)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;
    size_t      count;

    /* load public keys from pubring */
    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring
    assert_true(load_keys_gpg(ffi, "data/keyrings/1/pubring.gpg"));
    // again
    assert_true(load_keys_gpg(ffi, "data/keyrings/1/pubring.gpg"));
    // check counts
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(0, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    /* load public keys from secring */
    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load
    assert_true(load_keys_gpg(ffi, "data/keyrings/1/secring.gpg"));
    // check counts
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(0, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    /* load secret keys from secring */
    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load secring
    assert_true(load_keys_gpg(ffi, "", "data/keyrings/1/secring.gpg"));
    // again
    assert_true(load_keys_gpg(ffi, "", "data/keyrings/1/secring.gpg"));
    // check counts
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(0, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    /* load secret keys from pubring */
    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring
    assert_true(load_keys_gpg(ffi, "", "data/keyrings/1/pubring.gpg"));
    // check counts
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(0, count);
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(0, count);
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    /* concatenate the pubring and secrings into a single buffer */
    char * pub_buf = NULL;
    size_t pub_buf_len = 0;
    char * sec_buf = NULL;
    size_t sec_buf_len = 0;
    FILE * fp = fopen("combined-rings.gpg", "wb");
    assert_non_null(fp);
    load_test_data("keyrings/1/pubring.gpg", &pub_buf, &pub_buf_len);
    load_test_data("keyrings/1/secring.gpg", &sec_buf, &sec_buf_len);
    size_t   buf_len = pub_buf_len + sec_buf_len;
    uint8_t *buf = (uint8_t *) malloc(buf_len);
    memcpy(buf, pub_buf, pub_buf_len);
    memcpy(buf + pub_buf_len, sec_buf, sec_buf_len);
    free(pub_buf);
    free(sec_buf);

    /* load secret keys from pubring */
    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load
    assert_rnp_success(rnp_input_from_memory(&input, buf, buf_len, true));
    assert_non_null(input);
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // again
    assert_rnp_success(rnp_input_from_memory(&input, buf, buf_len, true));
    assert_non_null(input);
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check counts
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    free(buf);
}

static void
test_ffi_init(rnp_ffi_t *ffi)
{
    // setup FFI
    assert_rnp_success(rnp_ffi_create(ffi, "GPG", "GPG"));
    // load our keyrings
    assert_true(
      load_keys_gpg(*ffi, "data/keyrings/1/pubring.gpg", "data/keyrings/1/secring.gpg"));
}

TEST_F(rnp_tests, test_ffi_clear_keys)
{
    rnp_ffi_t ffi = NULL;
    size_t    pub_count;
    size_t    sec_count;

    // setup FFI
    test_ffi_init(&ffi);
    // check counts
    assert_rnp_success(rnp_get_public_key_count(ffi, &pub_count));
    assert_int_equal(7, pub_count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &sec_count));
    assert_int_equal(7, sec_count);
    // clear public keys
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_rnp_success(rnp_get_public_key_count(ffi, &pub_count));
    assert_int_equal(pub_count, 0);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &sec_count));
    assert_int_equal(sec_count, 7);
    // clear secret keys
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(rnp_get_public_key_count(ffi, &pub_count));
    assert_int_equal(pub_count, 0);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &sec_count));
    assert_int_equal(sec_count, 0);
    // load public and clear secret keys
    assert_true(load_keys_gpg(ffi, "data/keyrings/1/pubring.gpg"));
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(rnp_get_public_key_count(ffi, &pub_count));
    assert_int_equal(pub_count, 7);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &sec_count));
    assert_int_equal(sec_count, 0);
    // load secret keys and clear all
    assert_true(load_keys_gpg(ffi, "", "data/keyrings/1/secring.gpg"));
    assert_rnp_success(rnp_get_public_key_count(ffi, &pub_count));
    assert_int_equal(7, pub_count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &sec_count));
    assert_int_equal(7, sec_count);
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(rnp_get_public_key_count(ffi, &pub_count));
    assert_int_equal(pub_count, 0);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &sec_count));
    assert_int_equal(sec_count, 0);
    // attempt to clear NULL ffi
    assert_rnp_failure(rnp_unload_keys(NULL, RNP_KEY_UNLOAD_SECRET));
    // attempt to pass wrong flags
    assert_rnp_failure(rnp_unload_keys(ffi, 255));
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
}

TEST_F(rnp_tests, test_ffi_save_keys)
{
    rnp_ffi_t    ffi = NULL;
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;
    char *       temp_dir = NULL;
    char *       pub_path = NULL;
    char *       sec_path = NULL;
    char *       both_path = NULL;
    size_t       count;

    temp_dir = make_temp_dir();

    // setup FFI
    test_ffi_init(&ffi);
    // save pubring
    pub_path = rnp_compose_path(temp_dir, "pubring.gpg", NULL);
    assert_false(rnp_file_exists(pub_path));
    assert_rnp_success(rnp_output_to_path(&output, pub_path));
    assert_rnp_success(rnp_save_keys(ffi, "GPG", output, RNP_LOAD_SAVE_PUBLIC_KEYS));
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_file_exists(pub_path));
    // save secring
    sec_path = rnp_compose_path(temp_dir, "secring.gpg", NULL);
    assert_false(rnp_file_exists(sec_path));
    assert_rnp_success(rnp_output_to_path(&output, sec_path));
    assert_rnp_success(rnp_save_keys(ffi, "GPG", output, RNP_LOAD_SAVE_SECRET_KEYS));
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_file_exists(sec_path));
    // save pubring && secring
    both_path = rnp_compose_path(temp_dir, "bothring.gpg", NULL);
    assert_false(rnp_file_exists(both_path));
    assert_rnp_success(rnp_output_to_path(&output, both_path));
    assert_int_equal(
      RNP_SUCCESS,
      rnp_save_keys(
        ffi, "GPG", output, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS));
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_file_exists(both_path));
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    // start over (read from the saved locations)
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring & secring
    assert_true(load_keys_gpg(ffi, pub_path, sec_path));
    // check the counts
    count = 0;
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    count = 0;
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    // load both keyrings from the single file
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring
    assert_rnp_success(rnp_input_from_path(&input, both_path));
    assert_non_null(input);
    assert_int_equal(
      RNP_SUCCESS,
      rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check the counts. We should get both secret and public keys, since public keys are
    // extracted from the secret ones.
    count = 0;
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    count = 0;
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    free(pub_path);
    free(sec_path);
    free(both_path);

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "KBX", "G10"));
    // load pubring & secring
    assert_true(load_keys_kbx_g10(
      ffi, "data/keyrings/3/pubring.kbx", "data/keyrings/3/private-keys-v1.d"));
    // save pubring
    pub_path = rnp_compose_path(temp_dir, "pubring.kbx", NULL);
    assert_rnp_success(rnp_output_to_path(&output, pub_path));
    assert_rnp_success(rnp_save_keys(ffi, "KBX", output, RNP_LOAD_SAVE_PUBLIC_KEYS));
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_file_exists(pub_path));
    // save secring to file - will fail for G10
    sec_path = rnp_compose_path(temp_dir, "secring.file", NULL);
    assert_rnp_success(rnp_output_to_path(&output, sec_path));
    assert_rnp_failure(rnp_save_keys(ffi, "G10", output, RNP_LOAD_SAVE_SECRET_KEYS));
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    free(sec_path);
    // save secring
    sec_path = rnp_compose_path(temp_dir, "private-keys-v1.d", NULL);
    assert_false(rnp_dir_exists(sec_path));
    assert_int_equal(0, RNP_MKDIR(sec_path, S_IRWXU));
    assert_rnp_success(rnp_output_to_path(&output, sec_path));
    assert_rnp_success(rnp_save_keys(ffi, "G10", output, RNP_LOAD_SAVE_SECRET_KEYS));
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_dir_exists(sec_path));
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    // start over (read from the saved locations)
    assert_rnp_success(rnp_ffi_create(&ffi, "KBX", "G10"));
    // load pubring & secring
    assert_true(load_keys_kbx_g10(ffi, pub_path, sec_path));
    // check the counts
    count = 0;
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    count = 0;
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    free(pub_path);
    free(sec_path);

    // final cleanup
    free(temp_dir);
}

TEST_F(rnp_tests, test_ffi_load_save_keys_to_utf8_path)
{
    rnp_ffi_t    ffi = NULL;
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;
    char *       temp_dir = NULL;
    char *       pub_path = NULL;
    char *       sec_path = NULL;
    char *       both_path = NULL;
    size_t       count;
    const char   kbx_pubring_utf8_filename[] = "pubring_\xC2\xA2.kbx";
    const char   g10_secring_utf8_dirname[] = "private-keys-\xC2\xA2.d";
    const char   utf8_filename[] = "bothring_\xC2\xA2.gpg";
    temp_dir = make_temp_dir();

    // setup FFI
    test_ffi_init(&ffi);
    // save pubring && secring
    both_path = rnp_compose_path(temp_dir, utf8_filename, NULL);
    assert_false(rnp_file_exists(both_path));
    assert_rnp_success(rnp_output_to_path(&output, both_path));
    assert_rnp_success(rnp_save_keys(
      ffi, "GPG", output, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS));
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_file_exists(both_path));
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    // start over (read from the saved locations)
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load both keyrings from the single file
    assert_rnp_success(rnp_input_from_path(&input, both_path));
    assert_non_null(input);
    assert_rnp_success(
      rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check the counts. We should get both secret and public keys, since public keys are
    // extracted from the secret ones.
    count = 0;
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    count = 0;
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    free(pub_path);
    free(sec_path);
    free(both_path);

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "KBX", "G10"));
    // load pubring
    assert_true(load_keys_kbx_g10(
      ffi, "data/keyrings/3/pubring.kbx", "data/keyrings/3/private-keys-v1.d"));
    // save pubring
    pub_path = rnp_compose_path(temp_dir, kbx_pubring_utf8_filename, NULL);
    assert_rnp_success(rnp_output_to_path(&output, pub_path));
    assert_rnp_success(rnp_save_keys(ffi, "KBX", output, RNP_LOAD_SAVE_PUBLIC_KEYS));
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_file_exists(pub_path));
    // save secring
    sec_path = rnp_compose_path(temp_dir, g10_secring_utf8_dirname, NULL);
    assert_false(rnp_dir_exists(sec_path));
    assert_int_equal(0, RNP_MKDIR(sec_path, S_IRWXU));
    assert_rnp_success(rnp_output_to_path(&output, sec_path));
    assert_rnp_success(rnp_save_keys(ffi, "G10", output, RNP_LOAD_SAVE_SECRET_KEYS));
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_dir_exists(sec_path));
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    // start over (read from the saved locations)
    assert_rnp_success(rnp_ffi_create(&ffi, "KBX", "G10"));
    // load pubring & secring
    assert_true(load_keys_kbx_g10(ffi, pub_path, sec_path));
    // check the counts
    count = 0;
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    count = 0;
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    free(pub_path);
    free(sec_path);

    // final cleanup
    free(temp_dir);
}

static void
unused_getkeycb(rnp_ffi_t   ffi,
                void *      app_ctx,
                const char *identifier_type,
                const char *identifier,
                bool        secret)
{
    assert_true(false);
}

static bool
unused_getpasscb(rnp_ffi_t        ffi,
                 void *           app_ctx,
                 rnp_key_handle_t key,
                 const char *     pgp_context,
                 char *           buf,
                 size_t           buf_len)
{
    assert_true(false);
    return false;
}

static void
check_key_properties(rnp_key_handle_t key,
                     bool             primary_exptected,
                     bool             have_public_expected,
                     bool             have_secret_expected)
{
    bool isprimary = !primary_exptected;
    assert_rnp_success(rnp_key_is_primary(key, &isprimary));
    assert_true(isprimary == primary_exptected);
    bool issub = primary_exptected;
    assert_rnp_success(rnp_key_is_sub(key, &issub));
    assert_true(issub == !primary_exptected);
    bool have_public = !have_public_expected;
    assert_rnp_success(rnp_key_have_public(key, &have_public));
    assert_true(have_public == have_public_expected);
    bool have_secret = !have_secret_expected;
    assert_rnp_success(rnp_key_have_secret(key, &have_secret));
    assert_true(have_secret == have_secret_expected);
}

static size_t
get_longest_line_length(const std::string &str, const std::set<std::string> lines_to_skip)
{
    // eol could be \n or \r\n
    size_t index = 0;
    size_t max_len = 0;
    for (;;) {
        auto new_index = str.find('\n', index);
        if (new_index == std::string::npos) {
            break;
        }
        size_t line_length = new_index - index;
        if (str[new_index - 1] == '\r') {
            line_length--;
        }
        if (line_length > max_len &&
            lines_to_skip.find(str.substr(index, line_length)) == lines_to_skip.end()) {
            max_len = line_length;
        }
        index = new_index + 1;
    }
    return max_len;
}

TEST_F(rnp_tests, test_ffi_keygen_json_pair)
{
    rnp_ffi_t ffi = NULL;
    char *    json = NULL;
    char *    results = NULL;
    size_t    count = 0;

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(
      RNP_SUCCESS,
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "abc"));

    // load our JSON
    load_test_data("test_ffi_json/generate-pair.json", &json, NULL);

    // generate the keys
    assert_rnp_success(rnp_generate_key_json(ffi, json, &results));
    assert_non_null(results);
    free(json);
    json = NULL;

    // parse the results JSON
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_destroy(results);
    results = NULL;
    // get a handle for the primary
    rnp_key_handle_t primary = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(true, json_object_object_get_ex(parsed_results, "primary", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(true, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_rnp_success(rnp_locate_key(ffi, "grip", grip, &primary));
        assert_non_null(primary);
    }
    // get a handle for the sub
    rnp_key_handle_t sub = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(true, json_object_object_get_ex(parsed_results, "sub", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(true, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_rnp_success(rnp_locate_key(ffi, "grip", grip, &sub));
        assert_non_null(sub);
    }
    // cleanup
    json_object_put(parsed_results);

    // check the key counts
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);

    // check some key properties
    check_key_properties(primary, true, true, true);
    check_key_properties(sub, false, true, true);

    // check sub bit length
    uint32_t length = 0;
    assert_rnp_success(rnp_key_get_bits(sub, &length));
    assert_int_equal(1024, length);

    // cleanup
    rnp_key_handle_destroy(primary);
    rnp_key_handle_destroy(sub);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_keygen_json_pair_dsa_elg)
{
    rnp_ffi_t ffi = NULL;
    char *    json = NULL;
    char *    results = NULL;
    size_t    count = 0;

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "abc"));

    // load our JSON
    load_test_data("test_ffi_json/generate-pair-dsa-elg.json", &json, NULL);

    // generate the keys
    assert_rnp_success(rnp_generate_key_json(ffi, json, &results));
    assert_non_null(results);
    free(json);
    json = NULL;

    // parse the results JSON
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_destroy(results);
    results = NULL;
    // get a handle for the primary
    rnp_key_handle_t primary = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(true, json_object_object_get_ex(parsed_results, "primary", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(true, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_rnp_success(rnp_locate_key(ffi, "grip", grip, &primary));
        assert_non_null(primary);
    }
    // get a handle for the sub
    rnp_key_handle_t sub = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(true, json_object_object_get_ex(parsed_results, "sub", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(true, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_rnp_success(rnp_locate_key(ffi, "grip", grip, &sub));
        assert_non_null(sub);
    }
    // cleanup
    json_object_put(parsed_results);

    // check the key counts
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);

    // check some key properties
    check_key_properties(primary, true, true, true);
    check_key_properties(sub, false, true, true);

    // check bit lengths
    uint32_t length = 0;
    assert_rnp_success(rnp_key_get_bits(primary, &length));
    assert_int_equal(length, 1024);
    assert_rnp_success(rnp_key_get_bits(sub, &length));
    assert_int_equal(length, 1536);

    // cleanup
    rnp_key_handle_destroy(primary);
    rnp_key_handle_destroy(sub);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_keygen_json_primary)
{
    rnp_ffi_t ffi = NULL;
    char *    json = NULL;
    char *    results = NULL;
    size_t    count = 0;

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    // load our JSON
    load_test_data("test_ffi_json/generate-primary.json", &json, NULL);

    // generate the keys
    assert_rnp_success(rnp_generate_key_json(ffi, json, &results));
    assert_non_null(results);
    free(json);
    json = NULL;

    // parse the results JSON
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_destroy(results);
    results = NULL;
    // get a handle for the primary
    rnp_key_handle_t primary = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(true, json_object_object_get_ex(parsed_results, "primary", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(true, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_rnp_success(rnp_locate_key(ffi, "grip", grip, &primary));
        assert_non_null(primary);
    }
    // cleanup
    json_object_put(parsed_results);
    parsed_results = NULL;

    // check the key counts
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(1, count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(1, count);

    // check some key properties
    check_key_properties(primary, true, true, true);

    // cleanup
    rnp_key_handle_destroy(primary);
    rnp_ffi_destroy(ffi);
}

/* This test generates a primary key, and then a subkey (separately).
 */
TEST_F(rnp_tests, test_ffi_keygen_json_sub)
{
    char *    json = NULL;
    char *    results = NULL;
    size_t    count = 0;
    rnp_ffi_t ffi = NULL;

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    // generate our primary key
    load_test_data("test_ffi_json/generate-primary.json", &json, NULL);
    assert_rnp_success(rnp_generate_key_json(ffi, json, &results));
    free(json);
    assert_non_null(results);
    // check key counts
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(1, count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(1, count);

    // parse the results JSON
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_destroy(results);
    results = NULL;
    // get a handle+grip for the primary
    rnp_key_handle_t primary = NULL;
    char *           primary_grip = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(true, json_object_object_get_ex(parsed_results, "primary", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(true, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        primary_grip = strdup(json_object_get_string(jsogrip));
        assert_non_null(primary_grip);
        assert_rnp_success(rnp_locate_key(ffi, "grip", primary_grip, &primary));
        assert_non_null(primary);
    }
    // cleanup
    json_object_put(parsed_results);
    parsed_results = NULL;

    // load our JSON template
    load_test_data("test_ffi_json/generate-sub.json", &json, NULL);
    // modify our JSON
    {
        // parse
        json_object *jso = json_tokener_parse(json);
        assert_non_null(jso);
        free(json);
        json = NULL;
        // find the relevant fields
        json_object *jsosub = NULL;
        json_object *jsoprimary = NULL;
        assert_true(json_object_object_get_ex(jso, "sub", &jsosub));
        assert_non_null(jsosub);
        assert_true(json_object_object_get_ex(jsosub, "primary", &jsoprimary));
        assert_non_null(jsoprimary);
        // replace the placeholder grip with the correct one
        json_object_object_del(jsoprimary, "grip");
        json_object_object_add(jsoprimary, "grip", json_object_new_string(primary_grip));
        assert_int_equal(1, json_object_object_length(jsoprimary));
        json = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));
        assert_non_null(json);
        json_object_put(jso);
    }
    // cleanup
    rnp_buffer_destroy(primary_grip);
    primary_grip = NULL;

    // generate the subkey
    assert_rnp_success(rnp_generate_key_json(ffi, json, &results));
    assert_non_null(results);
    // cleanup
    free(json);
    json = NULL;

    // parse the results JSON
    parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_destroy(results);
    results = NULL;
    // get a handle for the sub
    rnp_key_handle_t sub = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(true, json_object_object_get_ex(parsed_results, "sub", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(true, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_rnp_success(rnp_locate_key(ffi, "grip", grip, &sub));
        assert_non_null(sub);
    }
    // cleanup
    json_object_put(parsed_results);
    parsed_results = NULL;

    // check the key counts
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);

    // check some key properties
    check_key_properties(primary, true, true, true);
    check_key_properties(sub, false, true, true);

    // check sub bit length
    uint32_t length = 0;
    assert_rnp_success(rnp_key_get_bits(sub, &length));
    assert_int_equal(length, 1024);

    // cleanup
    rnp_key_handle_destroy(primary);
    rnp_key_handle_destroy(sub);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_generate_misc)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));

    /* make sure we do not leak key handle and do not access NULL */
    assert_rnp_success(rnp_generate_key_rsa(ffi, 1024, 1024, "rsa", NULL, NULL));

    /* make sure we do not leak password on failed key generation */
    rnp_key_handle_t key = NULL;
    assert_rnp_failure(rnp_generate_key_rsa(ffi, 768, 2048, "rsa_768", "password", &key));
    assert_rnp_failure(rnp_generate_key_rsa(ffi, 1024, 768, "rsa_768", "password", &key));

    /* make sure we behave correctly and do not leak data on wrong parameters to _generate_ex
     * function */
    assert_rnp_failure(rnp_generate_key_ex(
      ffi, "RSA", "RSA", 1024, 1024, "Curve", NULL, "userid", "password", &key));
    assert_rnp_failure(rnp_generate_key_ex(
      ffi, "RSA", "RSA", 1024, 1024, "Curve", NULL, NULL, "password", &key));
    assert_rnp_failure(rnp_generate_key_ex(
      ffi, "RSA", "RSA", 1024, 768, NULL, "Curve", NULL, "password", &key));
    assert_rnp_failure(rnp_generate_key_ex(
      ffi, "ECDSA", "ECDH", 1024, 0, "Unknown", "Curve", NULL, NULL, &key));
    assert_rnp_failure(rnp_generate_key_ex(
      ffi, "ECDSA", "ECDH", 0, 1024, "Unknown", "Curve", NULL, "password", &key));

    /* generate RSA-RSA key without password */
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "abc"));
    assert_rnp_success(rnp_generate_key_rsa(ffi, 1024, 1024, "rsa_1024", NULL, &key));
    assert_non_null(key);
    bool locked = false;
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_false(locked);
    /* check key and subkey flags */
    bool flag = false;
    assert_rnp_success(rnp_key_allows_usage(key, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "certify", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "authenticate", &flag));
    assert_false(flag);
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(subkey));
    /* generate encrypted RSA-RSA key */
    assert_rnp_success(rnp_generate_key_rsa(ffi, 1024, 1024, "rsa_1024", "123", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_true(locked);
    /* make sure it can be unlocked with correct password */
    assert_rnp_success(rnp_key_unlock(key, "123"));
    /* do the same for subkey */
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_key_is_locked(subkey, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_unlock(subkey, "123"));
    /* cleanup */
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(subkey));
    /* generate encrypted RSA key (primary only) */
    key = NULL;
    assert_rnp_success(
      rnp_generate_key_ex(ffi, "RSA", NULL, 1024, 0, NULL, NULL, "rsa_1024", "123", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_true(locked);
    bool prot = false;
    assert_rnp_success(rnp_key_is_protected(key, &prot));
    assert_true(prot);
    /* cleanup */
    rnp_key_handle_destroy(key);

    /* generate key with signing subkey */
    rnp_op_generate_t op = NULL;
    assert_rnp_success(rnp_op_generate_create(&op, ffi, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(op, "secp256k1"));
    assert_rnp_success(rnp_op_generate_set_userid(op, "ecdsa_ecdsa"));
    assert_rnp_success(rnp_op_generate_add_usage(op, "sign"));
    assert_rnp_success(rnp_op_generate_add_usage(op, "certify"));
    assert_rnp_success(rnp_op_generate_execute(op));
    rnp_key_handle_t primary = NULL;
    assert_rnp_success(rnp_op_generate_get_key(op, &primary));
    rnp_op_generate_destroy(op);
    char *keyid = NULL;
    assert_rnp_success(rnp_key_get_keyid(primary, &keyid));

    rnp_op_generate_t subop = NULL;
    assert_rnp_success(rnp_op_generate_subkey_create(&subop, ffi, primary, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(subop, "NIST P-256"));
    assert_rnp_success(rnp_op_generate_add_usage(subop, "sign"));
    assert_rnp_success(rnp_op_generate_add_usage(subop, "certify"));
    assert_rnp_success(rnp_op_generate_execute(subop));
    assert_rnp_success(rnp_op_generate_get_key(subop, &subkey));
    rnp_op_generate_destroy(subop);
    char *subid = NULL;
    assert_rnp_success(rnp_key_get_keyid(subkey, &subid));

    rnp_output_t output = NULL;
    rnp_output_to_memory(&output, 0);
    assert_rnp_success(
      rnp_key_export(primary,
                     output,
                     RNP_KEY_EXPORT_ARMORED | RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));
    rnp_key_handle_destroy(primary);
    rnp_key_handle_destroy(subkey);
    uint8_t *buf = NULL;
    size_t   len = 0;
    rnp_output_memory_get_buf(output, &buf, &len, false);
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_pub_keys(ffi, buf, len));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", keyid, &primary));
    assert_non_null(primary);
    assert_true(primary->pub->valid());
    bool valid = false;
    assert_rnp_failure(rnp_key_is_valid(primary, NULL));
    assert_rnp_failure(rnp_key_is_valid(NULL, &valid));
    assert_rnp_success(rnp_key_is_valid(primary, &valid));
    assert_true(valid);
    uint32_t till = 0;
    assert_rnp_failure(rnp_key_valid_till(primary, NULL));
    assert_rnp_failure(rnp_key_valid_till(NULL, &till));
    assert_rnp_success(rnp_key_valid_till(primary, &till));
    assert_int_equal(till, 0xffffffff);
    uint64_t till64 = 0;
    assert_rnp_failure(rnp_key_valid_till64(primary, NULL));
    assert_rnp_failure(rnp_key_valid_till64(NULL, &till64));
    assert_rnp_success(rnp_key_valid_till64(primary, &till64));
    assert_int_equal(till64, UINT64_MAX);
    rnp_key_handle_destroy(primary);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", subid, &subkey));
    assert_non_null(subkey);
    assert_true(subkey->pub->valid());
    valid = false;
    assert_rnp_success(rnp_key_is_valid(subkey, &valid));
    assert_true(valid);
    till = 0;
    assert_rnp_success(rnp_key_valid_till(subkey, &till));
    assert_int_equal(till, 0xffffffff);
    assert_rnp_success(rnp_key_valid_till64(subkey, &till64));
    assert_int_equal(till64, UINT64_MAX);
    rnp_key_handle_destroy(subkey);
    rnp_buffer_destroy(keyid);
    rnp_buffer_destroy(subid);
    rnp_output_destroy(output);

    /* cleanup */
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_rsa)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    /* make sure we fail to generate too small and too large keys/subkeys */
    rnp_key_handle_t key = NULL;
    assert_rnp_failure(rnp_generate_key_rsa(ffi, 768, 2048, "rsa_768", NULL, &key));
    assert_rnp_failure(rnp_generate_key_rsa(ffi, 1024, 768, "rsa_768", NULL, &key));
    assert_rnp_failure(rnp_generate_key_rsa(ffi, 20480, 1024, "rsa_20480", NULL, &key));
    assert_rnp_failure(rnp_generate_key_rsa(ffi, 1024, 20480, "rsa_20480", NULL, &key));
    /* generate RSA-RSA key */
    assert_rnp_success(rnp_generate_key_rsa(ffi, 1024, 2048, "rsa_1024", NULL, &key));
    assert_non_null(key);
    /* check properties of the generated key */
    bool boolres = false;
    assert_rnp_success(rnp_key_is_primary(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_public(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(key, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(key, &boolres));
    assert_false(boolres);
    /* algorithm */
    char *alg = NULL;
    assert_rnp_success(rnp_key_get_alg(key, &alg));
    assert_int_equal(strcasecmp(alg, "RSA"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    uint32_t bits = 0;
    assert_rnp_failure(rnp_key_get_bits(key, NULL));
    assert_rnp_success(rnp_key_get_bits(key, &bits));
    assert_int_equal(bits, 1024);
    assert_rnp_failure(rnp_key_get_dsa_qbits(key, &bits));
    /* key flags */
    bool flag = false;
    assert_rnp_success(rnp_key_allows_usage(key, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "certify", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "authenticate", &flag));
    assert_false(flag);
    /* curve - must fail */
    char *curve = NULL;
    assert_rnp_failure(rnp_key_get_curve(key, NULL));
    assert_rnp_failure(rnp_key_get_curve(key, &curve));
    assert_null(curve);
    /* user ids */
    size_t uids = 0;
    char * uid = NULL;
    assert_rnp_success(rnp_key_get_uid_count(key, &uids));
    assert_int_equal(uids, 1);
    assert_rnp_failure(rnp_key_get_uid_at(key, 1, &uid));
    assert_null(uid);
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_string_equal(uid, "rsa_1024");
    rnp_buffer_destroy(uid);
    /* subkey */
    size_t subkeys = 0;
    assert_rnp_failure(rnp_key_get_subkey_count(key, NULL));
    assert_rnp_success(rnp_key_get_subkey_count(key, &subkeys));
    assert_int_equal(subkeys, 1);
    rnp_key_handle_t subkey = NULL;
    assert_rnp_failure(rnp_key_get_subkey_at(key, 1, &subkey));
    assert_rnp_failure(rnp_key_get_subkey_at(key, 0, NULL));
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    /* check properties of the generated subkey */
    assert_rnp_success(rnp_key_is_primary(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_have_public(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(subkey, &boolres));
    assert_false(boolres);
    /* algorithm */
    assert_rnp_success(rnp_key_get_alg(subkey, &alg));
    assert_int_equal(strcasecmp(alg, "RSA"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    assert_rnp_success(rnp_key_get_bits(subkey, &bits));
    assert_int_equal(bits, 2048);
    /* subkey flags */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    /* cleanup */
    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* generate RSA key without the subkey */
    assert_rnp_success(rnp_generate_key_rsa(ffi, 1024, 0, "rsa_1024", NULL, &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_subkey_count(key, &subkeys));
    assert_int_equal(subkeys, 0);
    /* cleanup */
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_dsa)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    /* try to generate keys with invalid sizes */
    rnp_key_handle_t key = NULL;
    assert_rnp_failure(rnp_generate_key_dsa_eg(ffi, 768, 2048, "dsa_768", NULL, &key));
    assert_rnp_failure(rnp_generate_key_dsa_eg(ffi, 1024, 768, "dsa_768", NULL, &key));
    assert_rnp_failure(rnp_generate_key_dsa_eg(ffi, 4096, 1024, "dsa_20480", NULL, &key));
    assert_rnp_failure(rnp_generate_key_dsa_eg(ffi, 1024, 20480, "dsa_20480", NULL, &key));
    /* generate DSA-ElGamal keypair */
    assert_rnp_success(rnp_generate_key_dsa_eg(ffi, 1024, 1024, "dsa_1024", NULL, &key));
    assert_non_null(key);
    /* check properties of the generated key */
    bool boolres = false;
    assert_rnp_success(rnp_key_is_primary(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_public(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(key, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(key, &boolres));
    assert_false(boolres);
    /* algorithm */
    char *alg = NULL;
    assert_rnp_success(rnp_key_get_alg(key, &alg));
    assert_int_equal(strcasecmp(alg, "DSA"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    uint32_t bits = 0;
    assert_rnp_success(rnp_key_get_bits(key, &bits));
    assert_int_equal(bits, 1024);
    assert_rnp_success(rnp_key_get_dsa_qbits(key, &bits));
    assert_int_equal(bits, 160);
    /* key flags */
    bool flag = false;
    assert_rnp_success(rnp_key_allows_usage(key, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "certify", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "authenticate", &flag));
    assert_false(flag);
    /* user ids */
    size_t uids = 0;
    char * uid = NULL;
    assert_rnp_success(rnp_key_get_uid_count(key, &uids));
    assert_int_equal(uids, 1);
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_string_equal(uid, "dsa_1024");
    rnp_buffer_destroy(uid);
    /* subkey */
    size_t subkeys = 0;
    assert_rnp_success(rnp_key_get_subkey_count(key, &subkeys));
    assert_int_equal(subkeys, 1);
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    /* check properties of the generated subkey */
    assert_rnp_success(rnp_key_is_primary(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_have_public(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(subkey, &boolres));
    assert_false(boolres);
    /* algorithm */
    assert_rnp_success(rnp_key_get_alg(subkey, &alg));
    assert_int_equal(strcasecmp(alg, "ELGAMAL"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    assert_rnp_success(rnp_key_get_bits(subkey, &bits));
    assert_int_equal(bits, 1024);
    /* subkey flags */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    /* cleanup */
    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* generate DSA key without the subkey */
    assert_rnp_success(rnp_generate_key_dsa_eg(ffi, 1024, 0, "dsa_1024", NULL, &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_subkey_count(key, &subkeys));
    assert_int_equal(subkeys, 0);
    /* cleanup */
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_ecdsa)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    /* try to generate key with invalid curve */
    rnp_key_handle_t key = NULL;
    assert_rnp_failure(rnp_generate_key_ec(ffi, "curve_wrong", "wrong", NULL, &key));
    assert_null(key);
    /* generate secp256k1 key */
    assert_rnp_success(rnp_generate_key_ec(ffi, "secp256k1", "ec_256k1", NULL, &key));
    assert_non_null(key);
    /* check properties of the generated key */
    bool boolres = false;
    assert_rnp_success(rnp_key_is_primary(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_public(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(key, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(key, &boolres));
    assert_false(boolres);
    /* algorithm */
    char *alg = NULL;
    assert_rnp_success(rnp_key_get_alg(key, &alg));
    assert_int_equal(strcasecmp(alg, "ECDSA"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    uint32_t bits = 0;
    assert_rnp_success(rnp_key_get_bits(key, &bits));
    assert_int_equal(bits, 256);
    assert_rnp_failure(rnp_key_get_dsa_qbits(key, &bits));
    /* curve */
    char *curve = NULL;
    assert_rnp_failure(rnp_key_get_curve(key, NULL));
    assert_rnp_success(rnp_key_get_curve(key, &curve));
    assert_int_equal(strcasecmp(curve, "secp256k1"), 0);
    rnp_buffer_destroy(curve);
    /* key flags */
    bool flag = false;
    assert_rnp_success(rnp_key_allows_usage(key, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "certify", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "authenticate", &flag));
    assert_false(flag);
    /* user ids */
    size_t uids = 0;
    char * uid = NULL;
    assert_rnp_success(rnp_key_get_uid_count(key, &uids));
    assert_int_equal(uids, 1);
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_string_equal(uid, "ec_256k1");
    rnp_buffer_destroy(uid);
    /* subkey */
    size_t subkeys = 0;
    assert_rnp_success(rnp_key_get_subkey_count(key, &subkeys));
    assert_int_equal(subkeys, 1);
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    /* check properties of the generated subkey */
    assert_rnp_success(rnp_key_is_primary(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_have_public(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(subkey, &boolres));
    assert_false(boolres);
    /* algorithm */
    assert_rnp_success(rnp_key_get_alg(subkey, &alg));
    assert_int_equal(strcasecmp(alg, "ECDH"), 0);
    rnp_buffer_destroy(alg);
    /* bits */
    assert_rnp_success(rnp_key_get_bits(subkey, &bits));
    assert_int_equal(bits, 256);
    /* curve */
    curve = NULL;
    assert_rnp_success(rnp_key_get_curve(subkey, &curve));
    assert_int_equal(strcasecmp(curve, "secp256k1"), 0);
    rnp_buffer_destroy(curve);
    /* subkey flags */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);

    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_eddsa)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    /* generate key with subkey */
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_generate_key_25519(ffi, "eddsa_25519", NULL, &key));
    assert_non_null(key);
    /* check properties of the generated key */
    bool boolres = false;
    assert_rnp_success(rnp_key_is_primary(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_public(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(key, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(key, &boolres));
    assert_false(boolres);
    /* algorithm */
    char *alg = NULL;
    assert_rnp_success(rnp_key_get_alg(key, &alg));
    assert_int_equal(strcasecmp(alg, "EDDSA"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    uint32_t bits = 0;
    assert_rnp_success(rnp_key_get_bits(key, &bits));
    assert_int_equal(bits, 255);
    /* curve */
    char *curve = NULL;
    assert_rnp_success(rnp_key_get_curve(key, &curve));
    assert_int_equal(strcasecmp(curve, "ed25519"), 0);
    rnp_buffer_destroy(curve);
    /* key flags */
    bool flag = false;
    assert_rnp_success(rnp_key_allows_usage(key, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "certify", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "authenticate", &flag));
    assert_false(flag);
    /* user ids */
    size_t uids = 0;
    char * uid = NULL;
    assert_rnp_success(rnp_key_get_uid_count(key, &uids));
    assert_int_equal(uids, 1);
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_string_equal(uid, "eddsa_25519");
    rnp_buffer_destroy(uid);
    /* subkey */
    size_t subkeys = 0;
    assert_rnp_success(rnp_key_get_subkey_count(key, &subkeys));
    assert_int_equal(subkeys, 1);
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    /* check properties of the generated subkey */
    assert_rnp_success(rnp_key_is_primary(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_have_public(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(subkey, &boolres));
    assert_false(boolres);
    /* algorithm */
    assert_rnp_success(rnp_key_get_alg(subkey, &alg));
    assert_int_equal(strcasecmp(alg, "ECDH"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    assert_rnp_success(rnp_key_get_bits(subkey, &bits));
    assert_int_equal(bits, 255);
    /* curve */
    curve = NULL;
    assert_rnp_success(rnp_key_get_curve(subkey, &curve));
    assert_int_equal(strcasecmp(curve, "Curve25519"), 0);
    rnp_buffer_destroy(curve);
    /* subkey flags */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);

    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_sm2)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));

    /* generate sm2 key */
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_generate_key_sm2(ffi, "sm2", NULL, &key));
    assert_non_null(key);
    /* check properties of the generated key */
    bool boolres = false;
    assert_rnp_success(rnp_key_is_primary(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_public(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(key, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(key, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(key, &boolres));
    assert_false(boolres);
    /* algorithm */
    char *alg = NULL;
    assert_rnp_success(rnp_key_get_alg(key, &alg));
    assert_int_equal(strcasecmp(alg, "SM2"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    uint32_t bits = 0;
    assert_rnp_success(rnp_key_get_bits(key, &bits));
    assert_int_equal(bits, 256);
    /* curve */
    char *curve = NULL;
    assert_rnp_success(rnp_key_get_curve(key, &curve));
    assert_int_equal(strcasecmp(curve, "SM2 P-256"), 0);
    rnp_buffer_destroy(curve);
    /* key flags */
    bool flag = false;
    assert_rnp_success(rnp_key_allows_usage(key, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "certify", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "authenticate", &flag));
    assert_false(flag);
    /* user ids */
    size_t uids = 0;
    char * uid = NULL;
    assert_rnp_success(rnp_key_get_uid_count(key, &uids));
    assert_int_equal(uids, 1);
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_string_equal(uid, "sm2");
    rnp_buffer_destroy(uid);
    /* subkey */
    size_t subkeys = 0;
    assert_rnp_success(rnp_key_get_subkey_count(key, &subkeys));
    assert_int_equal(subkeys, 1);
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &subkey));
    /* check properties of the generated subkey */
    assert_rnp_success(rnp_key_is_primary(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_have_public(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_have_secret(subkey, &boolres));
    assert_true(boolres);
    assert_rnp_success(rnp_key_is_protected(subkey, &boolres));
    assert_false(boolres);
    assert_rnp_success(rnp_key_is_locked(subkey, &boolres));
    assert_false(boolres);
    /* algorithm */
    assert_rnp_success(rnp_key_get_alg(subkey, &alg));
    assert_int_equal(strcasecmp(alg, "SM2"), 0);
    rnp_buffer_destroy(alg);
    /* key bits */
    assert_rnp_success(rnp_key_get_bits(subkey, &bits));
    assert_int_equal(bits, 256);
    /* curve */
    curve = NULL;
    assert_rnp_success(rnp_key_get_curve(subkey, &curve));
    assert_int_equal(strcasecmp(curve, "SM2 P-256"), 0);
    rnp_buffer_destroy(curve);
    /* subkey flags */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);

    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_ex)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "123"));

    /* Generate RSA key with misc options set */
    rnp_op_generate_t keygen = NULL;
    assert_rnp_success(rnp_op_generate_create(&keygen, ffi, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_failure(rnp_op_generate_set_dsa_qbits(keygen, 256));
    /* key usage */
    assert_rnp_success(rnp_op_generate_clear_usage(keygen));
    assert_rnp_failure(rnp_op_generate_add_usage(keygen, "usage"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "sign"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "encrypt"));
    /* preferred ciphers */
    assert_rnp_success(rnp_op_generate_clear_pref_ciphers(keygen));
    assert_rnp_failure(rnp_op_generate_add_pref_cipher(keygen, "unknown"));
    assert_rnp_success(rnp_op_generate_add_pref_cipher(keygen, "BLOWFISH"));
    assert_rnp_success(rnp_op_generate_clear_pref_ciphers(keygen));
    assert_rnp_success(rnp_op_generate_add_pref_cipher(keygen, "CAMELLIA256"));
    assert_rnp_success(rnp_op_generate_add_pref_cipher(keygen, "AES256"));
    /* preferred compression algorithms */
    assert_rnp_success(rnp_op_generate_clear_pref_compression(keygen));
    assert_rnp_failure(rnp_op_generate_add_pref_compression(keygen, "unknown"));
    assert_rnp_success(rnp_op_generate_add_pref_compression(keygen, "zlib"));
    assert_rnp_success(rnp_op_generate_clear_pref_compression(keygen));
    assert_rnp_success(rnp_op_generate_add_pref_compression(keygen, "zip"));
    assert_rnp_success(rnp_op_generate_add_pref_compression(keygen, "zlib"));
    /* preferred hash algorithms */
    assert_rnp_success(rnp_op_generate_clear_pref_hashes(keygen));
    assert_rnp_failure(rnp_op_generate_add_pref_hash(keygen, "unknown"));
    assert_rnp_success(rnp_op_generate_add_pref_hash(keygen, "SHA1"));
    assert_rnp_success(rnp_op_generate_clear_pref_hashes(keygen));
    assert_rnp_success(rnp_op_generate_add_pref_hash(keygen, "SHA512"));
    assert_rnp_success(rnp_op_generate_add_pref_hash(keygen, "SHA256"));
    /* key expiration */
    assert_rnp_success(rnp_op_generate_set_expiration(keygen, 60 * 60 * 24 * 100));
    assert_rnp_success(rnp_op_generate_set_expiration(keygen, 60 * 60 * 24 * 300));
    /* preferred key server */
    assert_rnp_success(rnp_op_generate_set_pref_keyserver(keygen, NULL));
    assert_rnp_success(rnp_op_generate_set_pref_keyserver(keygen, "hkp://first.server/"));
    assert_rnp_success(rnp_op_generate_set_pref_keyserver(keygen, "hkp://second.server/"));
    /* user id */
    assert_rnp_failure(rnp_op_generate_set_userid(keygen, NULL));
    assert_rnp_success(rnp_op_generate_set_userid(keygen, "userid_cleared"));
    assert_rnp_success(rnp_op_generate_set_userid(keygen, "userid"));
    /* protection */
    assert_rnp_failure(rnp_op_generate_set_protection_cipher(keygen, NULL));
    assert_rnp_failure(rnp_op_generate_set_protection_cipher(keygen, "unknown"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES256"));
    assert_rnp_failure(rnp_op_generate_set_protection_hash(keygen, NULL));
    assert_rnp_failure(rnp_op_generate_set_protection_hash(keygen, "unknown"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA256"));
    assert_rnp_success(rnp_op_generate_set_protection_iterations(keygen, 65536));
    assert_rnp_failure(rnp_op_generate_set_protection_mode(keygen, NULL));
    assert_rnp_failure(rnp_op_generate_set_protection_mode(keygen, "unknown"));
    assert_rnp_success(rnp_op_generate_set_protection_mode(keygen, "cfb"));
    /* now execute keygen operation */
    assert_rnp_success(rnp_op_generate_set_request_password(keygen, true));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &key));
    assert_non_null(key);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check key usage */
    bool flag = false;
    assert_rnp_success(rnp_key_allows_usage(key, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(key, "authenticate", &flag));
    assert_false(flag);
    /* check key creation and expiration */
    uint32_t create = 0;
    assert_rnp_success(rnp_key_get_creation(key, &create));
    assert_true((create != 0) && (create <= time(NULL)));
    uint32_t expiry = 0;
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_true(expiry == 60 * 60 * 24 * 300);
    uint32_t till = 0;
    assert_rnp_success(rnp_key_valid_till(key, &till));
    assert_int_equal(till, create + expiry);
    /* check whether key is encrypted */
    assert_rnp_success(rnp_key_is_protected(key, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_is_locked(key, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_unlock(key, "123"));
    assert_rnp_success(rnp_key_is_locked(key, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_lock(key));

    /* generate DSA subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "DSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1536));
    assert_rnp_success(rnp_op_generate_set_dsa_qbits(keygen, 224));
    /* key flags */
    assert_rnp_failure(rnp_op_generate_add_usage(keygen, "encrypt"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "certify"));
    /* these should not work for subkey */
    assert_rnp_failure(rnp_op_generate_clear_pref_ciphers(keygen));
    assert_rnp_failure(rnp_op_generate_add_pref_cipher(keygen, "AES256"));
    assert_rnp_failure(rnp_op_generate_clear_pref_compression(keygen));
    assert_rnp_failure(rnp_op_generate_add_pref_compression(keygen, "zlib"));
    assert_rnp_failure(rnp_op_generate_clear_pref_hashes(keygen));
    assert_rnp_failure(rnp_op_generate_add_pref_hash(keygen, "unknown"));
    assert_rnp_failure(rnp_op_generate_set_pref_keyserver(keygen, "hkp://first.server/"));
    assert_rnp_failure(rnp_op_generate_set_userid(keygen, "userid"));
    /* key expiration */
    assert_rnp_success(rnp_op_generate_set_expiration(keygen, 60 * 60 * 24 * 300));
    /* key protection */
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES256"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA256"));
    assert_rnp_success(rnp_op_generate_set_protection_iterations(keygen, 65536));
    assert_rnp_success(rnp_op_generate_set_request_password(keygen, true));
    /* now generate the subkey */
    assert_rnp_success(rnp_op_generate_execute(keygen));
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check subkey usage */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    /* check subkey creation and expiration */
    create = 0;
    assert_rnp_success(rnp_key_get_creation(subkey, &create));
    assert_true((create != 0) && (create <= time(NULL)));
    expiry = 0;
    assert_rnp_success(rnp_key_get_expiration(subkey, &expiry));
    assert_true(expiry == 60 * 60 * 24 * 300);
    /* check whether subkey is encrypted */
    assert_rnp_success(rnp_key_is_protected(subkey, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_is_locked(subkey, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_unlock(subkey, "123"));
    assert_rnp_success(rnp_key_is_locked(subkey, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_lock(subkey));
    /* destroy key handle */
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* generate RSA sign/encrypt subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "sign"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "encrypt"));
    assert_rnp_success(rnp_op_generate_set_expiration(keygen, 0));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA1"));
    /* set bits for iterations instead of exact iterations number */
    assert_rnp_success(rnp_op_generate_set_protection_iterations(keygen, 12));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check subkey usage */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    /* check whether subkey is encrypted - it should not */
    assert_rnp_success(rnp_key_is_protected(subkey, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* generate ElGamal subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ELGAMAL"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_failure(rnp_op_generate_add_usage(keygen, "sign"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "encrypt"));
    assert_rnp_success(rnp_op_generate_set_expiration(keygen, 0));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check subkey usage */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* generate ECDSA subkeys for each curve */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_failure(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_failure(rnp_op_generate_set_dsa_qbits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "sign"));
    assert_rnp_failure(rnp_op_generate_add_usage(keygen, "encrypt"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "NIST P-256"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check subkey usage */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "NIST P-384"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "NIST P-521"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "brainpoolP256r1"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "brainpoolP384r1"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "brainpoolP512r1"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "secp256k1"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* These curves will not work with ECDSA*/
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "Ed25519"));
    assert_rnp_failure(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_destroy(keygen));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "Curve25519"));
    assert_rnp_failure(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_destroy(keygen));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDSA"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "SM2 P-256"));
    assert_rnp_failure(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_destroy(keygen));

    /* Add EDDSA subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "EDDSA"));
    assert_rnp_failure(rnp_op_generate_set_curve(keygen, "secp256k1"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "sign"));
    assert_rnp_failure(rnp_op_generate_add_usage(keygen, "encrypt"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check subkey usage */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* Add ECDH subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDH"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "NIST P-256"));
    assert_rnp_failure(rnp_op_generate_add_usage(keygen, "sign"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "encrypt"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check subkey usage */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* Add ECDH x25519 subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ECDH"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "Curve25519"));
    assert_rnp_failure(rnp_op_generate_add_usage(keygen, "sign"));
    assert_rnp_success(rnp_op_generate_add_usage(keygen, "encrypt"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* now check subkey usage */
    assert_rnp_success(rnp_key_allows_usage(subkey, "sign", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "certify", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "encrypt", &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_allows_usage(subkey, "authenticate", &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* Add SM2 subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "SM2"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "AES128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "SHA1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_expiry_32bit)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "123"));

    /* Generate RSA key with creation + expiration > 32 bit */
    rnp_op_generate_t keygen = NULL;
    assert_rnp_success(rnp_op_generate_create(&keygen, ffi, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    /* key expiration */
    assert_rnp_success(rnp_op_generate_set_expiration(keygen, UINT32_MAX));
    /* now execute keygen operation */
    assert_rnp_success(rnp_op_generate_set_request_password(keygen, true));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &key));
    assert_non_null(key);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* check key creation and expiration */
    uint32_t create = 0;
    assert_rnp_success(rnp_key_get_creation(key, &create));
    assert_true((create != 0) && (create <= time(NULL)));
    uint32_t expiry = 0;
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_true(expiry == UINT32_MAX);
    uint32_t till = 0;
    assert_rnp_success(rnp_key_valid_till(key, &till));
    assert_int_equal(till, UINT32_MAX - 1);
    uint64_t till64 = 0;
    assert_rnp_success(rnp_key_valid_till64(key, &till64));
    assert_int_equal(till64, (uint64_t) create + expiry);
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* Load key with creation + expiration == UINT32_MAX */
    assert_true(import_pub_keys(ffi, "data/test_key_edge_cases/key-create-expiry-32bit.asc"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "60eac9ddf0d9ac9f", &key));
    /* check key creation and expiration */
    create = 0;
    assert_rnp_success(rnp_key_get_creation(key, &create));
    assert_int_equal(create, 1619611313);
    expiry = 0;
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_true(expiry == UINT32_MAX - create);
    till = 0;
    assert_rnp_success(rnp_key_valid_till(key, &till));
    assert_int_equal(till, UINT32_MAX - 1);
    till64 = 0;
    assert_rnp_success(rnp_key_valid_till64(key, &till64));
    assert_int_equal(till64, UINT32_MAX);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_algnamecase)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "123"));

    /* Generate RSA key with misc options set */
    rnp_op_generate_t keygen = NULL;
    assert_rnp_success(rnp_op_generate_create(&keygen, ffi, "rsa"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &key));
    assert_non_null(key);
    assert_rnp_success(rnp_op_generate_destroy(keygen));

    /* generate DSA subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "dsa"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1536));
    /* now generate the subkey */
    assert_rnp_success(rnp_op_generate_execute(keygen));
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* destroy key handle */
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* generate ElGamal subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "elgamal"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* generate ECDSA subkeys for each curve */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ecdsa"));
    assert_rnp_failure(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "NIST P-256"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ecdsa"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "NIST P-384"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ecdsa"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "NIST P-521"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ecdsa"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "brainpoolP256r1"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ecdsa"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "brainpoolP384r1"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ecdsa"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "brainpoolP512r1"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ecdsa"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "secp256k1"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* These curves will not work with ECDSA*/
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ecdsa"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "Ed25519"));
    assert_rnp_failure(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_destroy(keygen));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ecdsa"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "Curve25519"));
    assert_rnp_failure(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_destroy(keygen));

    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ecdsa"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "SM2 P-256"));
    assert_rnp_failure(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_destroy(keygen));

    /* Add EDDSA subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "eddsa"));
    assert_rnp_failure(rnp_op_generate_set_curve(keygen, "secp256k1"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* Add ECDH subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ecdh"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "NIST P-256"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* Add ECDH x25519 subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "ecdh"));
    assert_rnp_success(rnp_op_generate_set_curve(keygen, "Curve25519"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    /* Add SM2 subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "sm2"));
    assert_rnp_success(rnp_op_generate_set_protection_cipher(keygen, "aes128"));
    assert_rnp_success(rnp_op_generate_set_protection_hash(keygen, "sha1"));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_handle_destroy(subkey));

    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_generate_protection)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "123"));

    /* Generate key and subkey without protection */
    rnp_op_generate_t keygen = NULL;
    assert_rnp_success(rnp_op_generate_create(&keygen, ffi, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &key));
    assert_non_null(key);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* check whether key is encrypted */
    bool flag = true;
    assert_rnp_success(rnp_key_is_protected(key, &flag));
    assert_false(flag);
    /* generate subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    rnp_key_handle_t subkey = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_is_protected(subkey, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* Generate RSA key with password */
    assert_rnp_success(rnp_op_generate_create(&keygen, ffi, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_set_protection_password(keygen, "password"));
    /* Line below should not change password from 'password' to '123' */
    assert_rnp_success(rnp_op_generate_set_request_password(keygen, true));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    key = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &key));
    assert_non_null(key);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* check whether key is encrypted */
    assert_rnp_success(rnp_key_is_protected(key, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_is_locked(key, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_unlock(key, "password"));
    assert_rnp_success(rnp_key_is_locked(key, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_lock(key));
    /* generate subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_set_protection_password(keygen, "password"));
    /* this should fail since primary key is locked */
    assert_rnp_failure(rnp_op_generate_execute(keygen));
    assert_rnp_success(rnp_key_unlock(key, "password"));
    /* now it should work */
    assert_rnp_success(rnp_op_generate_execute(keygen));
    subkey = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_is_protected(subkey, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_is_locked(subkey, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_unlock(subkey, "password"));
    assert_rnp_success(rnp_key_is_locked(subkey, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* Generate RSA key via password request */
    assert_rnp_success(rnp_op_generate_create(&keygen, ffi, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_set_request_password(keygen, true));
    assert_rnp_success(rnp_op_generate_execute(keygen));
    key = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &key));
    assert_non_null(key);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    /* check whether key is encrypted */
    assert_rnp_success(rnp_key_is_protected(key, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_is_locked(key, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_unlock(key, "123"));
    assert_rnp_success(rnp_key_is_locked(key, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_lock(key));
    /* generate subkey */
    assert_rnp_success(rnp_op_generate_subkey_create(&keygen, ffi, key, "RSA"));
    assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
    assert_rnp_success(rnp_op_generate_set_request_password(keygen, true));
    /* this should succeed since password for primary key is returned via provider */
    assert_rnp_success(rnp_op_generate_execute(keygen));
    subkey = NULL;
    assert_rnp_success(rnp_op_generate_get_key(keygen, &subkey));
    assert_non_null(subkey);
    assert_rnp_success(rnp_op_generate_destroy(keygen));
    assert_rnp_success(rnp_key_is_protected(subkey, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_is_locked(subkey, &flag));
    assert_true(flag);
    assert_rnp_success(rnp_key_unlock(subkey, "123"));
    assert_rnp_success(rnp_key_is_locked(subkey, &flag));
    assert_false(flag);
    assert_rnp_success(rnp_key_handle_destroy(subkey));
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_add_userid)
{
    rnp_ffi_t              ffi = NULL;
    char *                 json = NULL;
    char *                 results = NULL;
    size_t                 count = 0;
    rnp_uid_handle_t       uid;
    rnp_signature_handle_t sig;
    char *                 hash_alg_name = NULL;

    const char *new_userid = "my new userid <user@example.com>";
    const char *default_hash_userid = "default hash <user@example.com";
    const char *ripemd_hash_userid = "ripemd160 <user@example.com";

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));

    // load our JSON
    load_test_data("test_ffi_json/generate-primary.json", &json, NULL);

    // generate the keys
    assert_rnp_success(rnp_generate_key_json(ffi, json, &results));
    assert_non_null(results);
    rnp_buffer_destroy(results);
    results = NULL;
    free(json);
    json = NULL;

    // check the key counts
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(1, count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(1, count);

    rnp_key_handle_t key_handle = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "test0", &key_handle));
    assert_non_null(key_handle);

    assert_rnp_success(rnp_key_get_uid_count(key_handle, &count));
    assert_int_equal(1, count);

    // protect+lock the key
    assert_rnp_success(rnp_key_protect(key_handle, "pass", "SM4", "CFB", "SM3", 999999));
    assert_rnp_success(rnp_key_lock(key_handle));

    // add the userid (no pass provider, should fail)
    assert_int_equal(
      RNP_ERROR_BAD_PASSWORD,
      rnp_key_add_uid(key_handle, new_userid, "SHA256", 2147317200, 0x00, false));

    // actually add the userid
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "pass"));
    // add with default hash algorithm
    assert_rnp_success(
      rnp_key_add_uid(key_handle, default_hash_userid, NULL, 2147317200, 0, false));
    // check if default hash was used
    assert_rnp_success(rnp_key_get_uid_handle_at(key_handle, 1, &uid));
    assert_rnp_success(rnp_uid_get_signature_at(uid, 0, &sig));
    assert_rnp_success(rnp_signature_get_hash_alg(sig, &hash_alg_name));
    assert_int_equal(strcasecmp(hash_alg_name, DEFAULT_HASH_ALG), 0);
    rnp_buffer_destroy(hash_alg_name);
    hash_alg_name = NULL;
    assert_rnp_success(rnp_signature_handle_destroy(sig));
    assert_rnp_success(rnp_uid_handle_destroy(uid));

    assert_int_equal(
      RNP_SUCCESS, rnp_key_add_uid(key_handle, new_userid, "SHA256", 2147317200, 0x00, false));

    assert_rnp_success(
      rnp_key_add_uid(key_handle, ripemd_hash_userid, "RIPEMD160", 2147317200, 0, false));

    assert_rnp_success(rnp_key_get_uid_count(key_handle, &count));
    assert_int_equal(4, count);

    rnp_key_handle_t key_handle2 = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", new_userid, &key_handle2));
    assert_non_null(key_handle2);

    rnp_key_handle_destroy(key_handle);
    rnp_key_handle_destroy(key_handle2);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_keygen_json_sub_pass_required)
{
    char *    json = NULL;
    char *    results = NULL;
    size_t    count = 0;
    rnp_ffi_t ffi = NULL;

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    // generate our primary key
    load_test_data("test_ffi_json/generate-primary.json", &json, NULL);
    assert_rnp_success(rnp_generate_key_json(ffi, json, &results));
    free(json);
    assert_non_null(results);
    // check key counts
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(1, count);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(1, count);

    // parse the results JSON
    json_object *parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_destroy(results);
    results = NULL;
    // get a handle+grip for the primary
    rnp_key_handle_t primary = NULL;
    char *           primary_grip = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(true, json_object_object_get_ex(parsed_results, "primary", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(true, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        primary_grip = strdup(json_object_get_string(jsogrip));
        assert_non_null(primary_grip);
        assert_rnp_success(rnp_locate_key(ffi, "grip", primary_grip, &primary));
        assert_non_null(primary);
    }
    // cleanup
    json_object_put(parsed_results);
    parsed_results = NULL;

    // protect+lock the primary key
    assert_rnp_success(rnp_key_protect(primary, "pass123", NULL, NULL, NULL, 0));
    assert_rnp_success(rnp_key_lock(primary));
    rnp_key_handle_destroy(primary);
    primary = NULL;

    // load our JSON template
    load_test_data("test_ffi_json/generate-sub.json", &json, NULL);
    // modify our JSON
    {
        // parse
        json_object *jso = json_tokener_parse(json);
        assert_non_null(jso);
        free(json);
        json = NULL;
        // find the relevant fields
        json_object *jsosub = NULL;
        json_object *jsoprimary = NULL;
        assert_true(json_object_object_get_ex(jso, "sub", &jsosub));
        assert_non_null(jsosub);
        assert_true(json_object_object_get_ex(jsosub, "primary", &jsoprimary));
        assert_non_null(jsoprimary);
        // replace the placeholder grip with the correct one
        json_object_object_del(jsoprimary, "grip");
        json_object_object_add(jsoprimary, "grip", json_object_new_string(primary_grip));
        assert_int_equal(1, json_object_object_length(jsoprimary));
        json = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));
        assert_non_null(json);
        json_object_put(jso);
    }
    // cleanup
    rnp_buffer_destroy(primary_grip);
    primary_grip = NULL;

    // generate the subkey (no ffi_string_password_provider, should fail)
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, NULL, NULL));
    assert_rnp_failure(rnp_generate_key_json(ffi, json, &results));

    // generate the subkey (wrong pass, should fail)
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "wrong"));
    assert_rnp_failure(rnp_generate_key_json(ffi, json, &results));

    // generate the subkey
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "pass123"));
    assert_rnp_success(rnp_generate_key_json(ffi, json, &results));
    free(json);
    json = NULL;
    assert_non_null(results);

    // parse the results JSON
    parsed_results = json_tokener_parse(results);
    assert_non_null(parsed_results);
    rnp_buffer_destroy(results);
    results = NULL;
    // get a handle for the sub
    rnp_key_handle_t sub = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(true, json_object_object_get_ex(parsed_results, "sub", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(true, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_rnp_success(rnp_locate_key(ffi, "grip", grip, &sub));
        assert_non_null(sub);
    }
    // cleanup
    json_object_put(parsed_results);
    parsed_results = NULL;

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);

    // check some key properties
    check_key_properties(sub, false, true, true);

    // cleanup
    rnp_key_handle_destroy(primary);
    rnp_key_handle_destroy(sub);
    rnp_ffi_destroy(ffi);
}

static bool
file_equals(const char *filename, const void *data, size_t len)
{
    pgp_source_t msrc = {};
    bool         res = false;

    if (file_to_mem_src(&msrc, filename)) {
        return false;
    }

    res = (msrc.size == len) && !memcmp(mem_src_get_memory(&msrc), data, len);
    src_close(&msrc);
    return res;
}

static void
test_ffi_init_sign_file_input(rnp_input_t *input, rnp_output_t *output)
{
    const char *plaintext = "this is some data that will be signed";

    // write out some data
    FILE *fp = fopen("plaintext", "wb");
    assert_non_null(fp);
    assert_int_equal(1, fwrite(plaintext, strlen(plaintext), 1, fp));
    assert_int_equal(0, fclose(fp));

    // create input+output
    assert_rnp_success(rnp_input_from_path(input, "plaintext"));
    assert_non_null(*input);
    assert_rnp_success(rnp_output_to_path(output, "signed"));
    assert_non_null(*output);
}

static void
test_ffi_init_sign_memory_input(rnp_input_t *input, rnp_output_t *output)
{
    const char *plaintext = "this is some data that will be signed";

    assert_rnp_success(
      rnp_input_from_memory(input, (uint8_t *) plaintext, strlen(plaintext), true));
    assert_non_null(*input);
    if (output) {
        assert_rnp_success(rnp_output_to_memory(output, 0));
        assert_non_null(*output);
    }
}

static void
test_ffi_init_verify_file_input(rnp_input_t *input, rnp_output_t *output)
{
    // create input+output
    assert_rnp_success(rnp_input_from_path(input, "signed"));
    assert_non_null(*input);
    assert_rnp_success(rnp_output_to_path(output, "recovered"));
    assert_non_null(*output);
}

static void
test_ffi_init_verify_detached_file_input(rnp_input_t *input, rnp_input_t *signature)
{
    assert_rnp_success(rnp_input_from_path(input, "plaintext"));
    assert_non_null(*input);
    assert_rnp_success(rnp_input_from_path(signature, "signed"));
    assert_non_null(*signature);
}

static void
test_ffi_init_verify_memory_input(rnp_input_t * input,
                                  rnp_output_t *output,
                                  uint8_t *     signed_buf,
                                  size_t        signed_len)
{
    // create input+output
    assert_rnp_success(rnp_input_from_memory(input, signed_buf, signed_len, false));
    assert_non_null(*input);
    assert_rnp_success(rnp_output_to_memory(output, 0));
    assert_non_null(*output);
}

static void
test_ffi_setup_signatures(rnp_ffi_t *ffi, rnp_op_sign_t *op)
{
    rnp_key_handle_t        key = NULL;
    rnp_op_sign_signature_t sig = NULL;
    // set signature times
    const uint32_t issued = 1516211899;   // Unix epoch, nowish
    const uint32_t expires = 1000000000;  // expires later
    const uint32_t issued2 = 1516211900;  // Unix epoch, nowish
    const uint32_t expires2 = 2000000000; // expires later

    assert_rnp_success(rnp_op_sign_set_armor(*op, true));
    assert_rnp_success(rnp_op_sign_set_hash(*op, "SHA256"));
    assert_rnp_success(rnp_op_sign_set_creation_time(*op, issued));
    assert_rnp_success(rnp_op_sign_set_expiration_time(*op, expires));

    // set pass provider
    assert_rnp_success(
      rnp_ffi_set_pass_provider(*ffi, ffi_string_password_provider, (void *) "password"));

    // set first signature key
    assert_rnp_success(rnp_locate_key(*ffi, "userid", "key0-uid2", &key));
    assert_rnp_success(rnp_op_sign_add_signature(*op, key, NULL));
    assert_rnp_success(rnp_key_handle_destroy(key));
    key = NULL;
    // set second signature key
    assert_rnp_success(rnp_locate_key(*ffi, "userid", "key0-uid1", &key));
    assert_rnp_success(rnp_op_sign_add_signature(*op, key, &sig));
    assert_rnp_success(rnp_op_sign_signature_set_creation_time(sig, issued2));
    assert_rnp_success(rnp_op_sign_signature_set_expiration_time(sig, expires2));
    assert_rnp_success(rnp_op_sign_signature_set_hash(sig, "SHA512"));
    assert_rnp_success(rnp_key_handle_destroy(key));
}

static void
test_ffi_check_signatures(rnp_op_verify_t *verify)
{
    rnp_op_verify_signature_t sig;
    size_t                    sig_count;
    uint32_t                  sig_create;
    uint32_t                  sig_expires;
    char *                    hname = NULL;
    const uint32_t            issued = 1516211899;   // Unix epoch, nowish
    const uint32_t            expires = 1000000000;  // expires later
    const uint32_t            issued2 = 1516211900;  // Unix epoch, nowish
    const uint32_t            expires2 = 2000000000; // expires later

    assert_rnp_success(rnp_op_verify_get_signature_count(*verify, &sig_count));
    assert_int_equal(sig_count, 2);
    // first signature
    assert_rnp_success(rnp_op_verify_get_signature_at(*verify, 0, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    assert_rnp_success(rnp_op_verify_signature_get_times(sig, &sig_create, &sig_expires));
    assert_int_equal(sig_create, issued);
    assert_int_equal(sig_expires, expires);
    assert_rnp_success(rnp_op_verify_signature_get_hash(sig, &hname));
    assert_string_equal(hname, "SHA256");
    rnp_buffer_destroy(hname);
    // second signature
    assert_rnp_success(rnp_op_verify_get_signature_at(*verify, 1, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    assert_rnp_success(rnp_op_verify_signature_get_times(sig, &sig_create, &sig_expires));
    assert_int_equal(sig_create, issued2);
    assert_int_equal(sig_expires, expires2);
    assert_rnp_success(rnp_op_verify_signature_get_hash(sig, &hname));
    assert_string_equal(hname, "SHA512");
    rnp_buffer_destroy(hname);
}

static bool
test_ffi_check_recovered()
{
    pgp_source_t msrc1 = {};
    pgp_source_t msrc2 = {};
    bool         res = false;

    if (file_to_mem_src(&msrc1, "recovered")) {
        return false;
    }

    if (file_to_mem_src(&msrc2, "plaintext")) {
        goto finish;
    }

    res = (msrc1.size == msrc2.size) &&
          !memcmp(mem_src_get_memory(&msrc1), mem_src_get_memory(&msrc2), msrc1.size);
finish:
    src_close(&msrc1);
    src_close(&msrc2);
    return res;
}

TEST_F(rnp_tests, test_ffi_signatures_memory)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_output_t    output = NULL;
    rnp_op_sign_t   op = NULL;
    rnp_op_verify_t verify;
    uint8_t *       signed_buf;
    size_t          signed_len;
    uint8_t *       verified_buf;
    size_t          verified_len;

    // init ffi
    test_ffi_init(&ffi);
    // init input
    test_ffi_init_sign_memory_input(&input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(&ffi, &op);
    // execute the operation
    assert_rnp_success(rnp_op_sign_execute(op));
    // make sure the output file was created
    assert_rnp_success(rnp_output_memory_get_buf(output, &signed_buf, &signed_len, true));
    assert_non_null(signed_buf);
    assert_true(signed_len > 0);

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_op_sign_destroy(op));
    op = NULL;

    /* now verify */
    // make sure it is correctly armored
    assert_int_equal(memcmp(signed_buf, "-----BEGIN PGP MESSAGE-----", 27), 0);
    // create input and output
    test_ffi_init_verify_memory_input(&input, &output, signed_buf, signed_len);
    // call verify
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    test_ffi_check_signatures(&verify);
    // get output
    assert_rnp_success(rnp_output_memory_get_buf(output, &verified_buf, &verified_len, true));
    assert_non_null(verified_buf);
    assert_true(verified_len > 0);
    // cleanup
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_ffi_destroy(ffi));
    rnp_buffer_destroy(signed_buf);
    rnp_buffer_destroy(verified_buf);
}

TEST_F(rnp_tests, test_ffi_signatures)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_output_t    output = NULL;
    rnp_op_sign_t   op = NULL;
    rnp_op_verify_t verify;

    // init ffi
    test_ffi_init(&ffi);
    // init file input
    test_ffi_init_sign_file_input(&input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(&ffi, &op);
    // execute the operation
    assert_rnp_success(rnp_op_sign_execute(op));
    // make sure the output file was created
    assert_true(rnp_file_exists("signed"));

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_op_sign_destroy(op));
    op = NULL;

    /* now verify */

    // create input and output
    test_ffi_init_verify_file_input(&input, &output);
    // call verify
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    test_ffi_check_signatures(&verify);
    // cleanup
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_ffi_destroy(ffi));
    // check output
    assert_true(test_ffi_check_recovered());
}

TEST_F(rnp_tests, test_ffi_signatures_detached_memory)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_input_t     signature = NULL;
    rnp_output_t    output = NULL;
    rnp_op_sign_t   op = NULL;
    rnp_op_verify_t verify;
    uint8_t *       signed_buf;
    size_t          signed_len;

    // init ffi
    test_ffi_init(&ffi);
    // init input
    test_ffi_init_sign_memory_input(&input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_detached_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(&ffi, &op);
    // execute the operation
    assert_rnp_success(rnp_op_sign_execute(op));
    assert_rnp_success(rnp_output_memory_get_buf(output, &signed_buf, &signed_len, true));
    assert_non_null(signed_buf);
    assert_true(signed_len > 0);

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_op_sign_destroy(op));
    op = NULL;

    /* now verify */
    // make sure it is correctly armored
    assert_int_equal(memcmp(signed_buf, "-----BEGIN PGP SIGNATURE-----", 29), 0);
    // create input and output
    test_ffi_init_sign_memory_input(&input, NULL);
    assert_rnp_success(rnp_input_from_memory(&signature, signed_buf, signed_len, true));
    assert_non_null(signature);
    // call verify
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, input, signature));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    test_ffi_check_signatures(&verify);
    // cleanup
    rnp_buffer_destroy(signed_buf);
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_input_destroy(signature));
    signature = NULL;
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_signatures_detached)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_input_t     signature = NULL;
    rnp_output_t    output = NULL;
    rnp_op_sign_t   op = NULL;
    rnp_op_verify_t verify;

    // init ffi
    test_ffi_init(&ffi);
    // init file input
    test_ffi_init_sign_file_input(&input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_detached_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(&ffi, &op);
    // execute the operation
    assert_rnp_success(rnp_op_sign_execute(op));
    // make sure the output file was created
    assert_true(rnp_file_exists("signed"));

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_op_sign_destroy(op));
    op = NULL;

    /* now verify */

    // create input and output
    test_ffi_init_verify_detached_file_input(&input, &signature);
    // call verify
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, input, signature));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    test_ffi_check_signatures(&verify);
    // cleanup
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_input_destroy(signature));
    signature = NULL;
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_signatures_dump)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_input_t     signature = NULL;
    rnp_op_verify_t verify;

    /* init ffi and inputs */
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    load_keys_gpg(ffi, "data/test_stream_signatures/pub.asc");
    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_signatures/source.txt"));
    assert_rnp_success(
      rnp_input_from_path(&signature, "data/test_stream_signatures/source.txt.sig"));
    /* call verify detached to obtain signatures */
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, input, signature));
    assert_rnp_success(rnp_op_verify_execute(verify));
    /* get signature and check it */
    rnp_op_verify_signature_t sig;
    size_t                    sig_count;
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sig_count));
    assert_int_equal(sig_count, 1);
    /* get signature handle  */
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 0, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    rnp_signature_handle_t sighandle = NULL;
    assert_rnp_success(rnp_op_verify_signature_get_handle(sig, &sighandle));
    assert_non_null(sighandle);
    /* check signature type */
    char *sigtype = NULL;
    assert_rnp_success(rnp_signature_get_type(sighandle, &sigtype));
    assert_string_equal(sigtype, "binary");
    rnp_buffer_destroy(sigtype);
    /* attempt to validate it via wrong function */
    assert_int_equal(rnp_signature_is_valid(sighandle, 0), RNP_ERROR_BAD_PARAMETERS);
    /* cleanup, making sure that sighandle doesn't depend on verify */
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_input_destroy(signature));
    /* check whether getters work on sighandle: algorithm */
    char *alg = NULL;
    assert_rnp_success(rnp_signature_get_alg(sighandle, &alg));
    assert_non_null(alg);
    assert_string_equal(alg, "RSA");
    rnp_buffer_destroy(alg);
    /* keyid */
    char *keyid = NULL;
    assert_rnp_success(rnp_signature_get_keyid(sighandle, &keyid));
    assert_non_null(keyid);
    assert_string_equal(keyid, "5873BD738E575398");
    rnp_buffer_destroy(keyid);
    /* creation time */
    uint32_t create = 0;
    assert_rnp_success(rnp_signature_get_creation(sighandle, &create));
    assert_int_equal(create, 1522241943);
    /* hash algorithm */
    assert_rnp_success(rnp_signature_get_hash_alg(sighandle, &alg));
    assert_non_null(alg);
    assert_string_equal(alg, "SHA256");
    rnp_buffer_destroy(alg);
    /* now dump signature packet to json */
    char *json = NULL;
    assert_rnp_success(rnp_signature_packet_to_json(sighandle, 0, &json));
    json_object *jso = json_tokener_parse(json);
    rnp_buffer_destroy(json);
    assert_non_null(jso);
    assert_true(json_object_is_type(jso, json_type_array));
    assert_int_equal(json_object_array_length(jso), 1);
    /* check the signature packet dump */
    json_object *pkt = json_object_array_get_idx(jso, 0);
    /* check helper functions */
    assert_false(check_json_field_int(pkt, "unknown", 4));
    assert_false(check_json_field_int(pkt, "version", 5));
    assert_true(check_json_field_int(pkt, "version", 4));
    assert_true(check_json_field_int(pkt, "type", 0));
    assert_true(check_json_field_str(pkt, "type.str", "Signature of a binary document"));
    assert_true(check_json_field_int(pkt, "algorithm", 1));
    assert_true(check_json_field_str(pkt, "algorithm.str", "RSA (Encrypt or Sign)"));
    assert_true(check_json_field_int(pkt, "hash algorithm", 8));
    assert_true(check_json_field_str(pkt, "hash algorithm.str", "SHA256"));
    assert_true(check_json_field_str(pkt, "lbits", "816e"));
    json_object *subpkts = NULL;
    assert_true(json_object_object_get_ex(pkt, "subpackets", &subpkts));
    assert_non_null(subpkts);
    assert_true(json_object_is_type(subpkts, json_type_array));
    assert_int_equal(json_object_array_length(subpkts), 3);
    /* subpacket 0 */
    json_object *subpkt = json_object_array_get_idx(subpkts, 0);
    assert_true(check_json_field_int(subpkt, "type", 33));
    assert_true(check_json_field_str(subpkt, "type.str", "issuer fingerprint"));
    assert_true(check_json_field_int(subpkt, "length", 21));
    assert_true(check_json_field_bool(subpkt, "hashed", true));
    assert_true(check_json_field_bool(subpkt, "critical", false));
    assert_true(
      check_json_field_str(subpkt, "fingerprint", "7a60e671179f9b920f6478a25873bd738e575398"));
    /* subpacket 1 */
    subpkt = json_object_array_get_idx(subpkts, 1);
    assert_true(check_json_field_int(subpkt, "type", 2));
    assert_true(check_json_field_str(subpkt, "type.str", "signature creation time"));
    assert_true(check_json_field_int(subpkt, "length", 4));
    assert_true(check_json_field_bool(subpkt, "hashed", true));
    assert_true(check_json_field_bool(subpkt, "critical", false));
    assert_true(check_json_field_int(subpkt, "creation time", 1522241943));
    /* subpacket 2 */
    subpkt = json_object_array_get_idx(subpkts, 2);
    assert_true(check_json_field_int(subpkt, "type", 16));
    assert_true(check_json_field_str(subpkt, "type.str", "issuer key ID"));
    assert_true(check_json_field_int(subpkt, "length", 8));
    assert_true(check_json_field_bool(subpkt, "hashed", false));
    assert_true(check_json_field_bool(subpkt, "critical", false));
    assert_true(check_json_field_str(subpkt, "issuer keyid", "5873bd738e575398"));
    json_object_put(jso);
    rnp_signature_handle_destroy(sighandle);
    /* check text-mode detached signature */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_signatures/source.txt"));
    assert_rnp_success(
      rnp_input_from_path(&signature, "data/test_stream_signatures/source.txt.text.sig"));
    /* call verify detached to obtain signatures */
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, input, signature));
    assert_rnp_success(rnp_op_verify_execute(verify));
    /* get signature and check it */
    sig_count = 0;
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sig_count));
    assert_int_equal(sig_count, 1);
    /* get signature handle  */
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 0, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    assert_rnp_success(rnp_op_verify_signature_get_handle(sig, &sighandle));
    assert_non_null(sighandle);
    /* check signature type */
    assert_rnp_success(rnp_signature_get_type(sighandle, &sigtype));
    assert_string_equal(sigtype, "text");
    rnp_buffer_destroy(sigtype);
    /* attempt to validate it via wrong function */
    assert_int_equal(rnp_signature_is_valid(sighandle, 0), RNP_ERROR_BAD_PARAMETERS);
    /* cleanup, making sure that sighandle doesn't depend on verify */
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_input_destroy(signature));
    /* check whether getters work on sighandle: algorithm */
    assert_rnp_success(rnp_signature_get_alg(sighandle, &alg));
    assert_non_null(alg);
    assert_string_equal(alg, "RSA");
    rnp_buffer_destroy(alg);
    /* keyid */
    assert_rnp_success(rnp_signature_get_keyid(sighandle, &keyid));
    assert_non_null(keyid);
    assert_string_equal(keyid, "5873BD738E575398");
    rnp_buffer_destroy(keyid);
    /* creation time */
    assert_rnp_success(rnp_signature_get_creation(sighandle, &create));
    assert_int_equal(create, 1608118321);
    /* hash algorithm */
    assert_rnp_success(rnp_signature_get_hash_alg(sighandle, &alg));
    assert_non_null(alg);
    assert_string_equal(alg, "SHA256");
    rnp_buffer_destroy(alg);
    /* now dump signature packet to json */
    assert_rnp_success(rnp_signature_packet_to_json(sighandle, 0, &json));
    jso = json_tokener_parse(json);
    rnp_buffer_destroy(json);
    assert_non_null(jso);
    assert_true(json_object_is_type(jso, json_type_array));
    assert_int_equal(json_object_array_length(jso), 1);
    /* check the signature packet dump */
    pkt = json_object_array_get_idx(jso, 0);
    /* check helper functions */
    assert_false(check_json_field_int(pkt, "unknown", 4));
    assert_false(check_json_field_int(pkt, "version", 5));
    assert_true(check_json_field_int(pkt, "version", 4));
    assert_true(check_json_field_int(pkt, "type", 1));
    assert_true(
      check_json_field_str(pkt, "type.str", "Signature of a canonical text document"));
    assert_true(check_json_field_int(pkt, "algorithm", 1));
    assert_true(check_json_field_str(pkt, "algorithm.str", "RSA (Encrypt or Sign)"));
    assert_true(check_json_field_int(pkt, "hash algorithm", 8));
    assert_true(check_json_field_str(pkt, "hash algorithm.str", "SHA256"));
    assert_true(check_json_field_str(pkt, "lbits", "1037"));
    subpkts = NULL;
    assert_true(json_object_object_get_ex(pkt, "subpackets", &subpkts));
    assert_non_null(subpkts);
    assert_true(json_object_is_type(subpkts, json_type_array));
    assert_int_equal(json_object_array_length(subpkts), 3);
    /* subpacket 0 */
    subpkt = json_object_array_get_idx(subpkts, 0);
    assert_true(check_json_field_int(subpkt, "type", 33));
    assert_true(check_json_field_str(subpkt, "type.str", "issuer fingerprint"));
    assert_true(check_json_field_int(subpkt, "length", 21));
    assert_true(check_json_field_bool(subpkt, "hashed", true));
    assert_true(check_json_field_bool(subpkt, "critical", false));
    assert_true(
      check_json_field_str(subpkt, "fingerprint", "7a60e671179f9b920f6478a25873bd738e575398"));
    /* subpacket 1 */
    subpkt = json_object_array_get_idx(subpkts, 1);
    assert_true(check_json_field_int(subpkt, "type", 2));
    assert_true(check_json_field_str(subpkt, "type.str", "signature creation time"));
    assert_true(check_json_field_int(subpkt, "length", 4));
    assert_true(check_json_field_bool(subpkt, "hashed", true));
    assert_true(check_json_field_bool(subpkt, "critical", false));
    assert_true(check_json_field_int(subpkt, "creation time", 1608118321));
    /* subpacket 2 */
    subpkt = json_object_array_get_idx(subpkts, 2);
    assert_true(check_json_field_int(subpkt, "type", 16));
    assert_true(check_json_field_str(subpkt, "type.str", "issuer key ID"));
    assert_true(check_json_field_int(subpkt, "length", 8));
    assert_true(check_json_field_bool(subpkt, "hashed", false));
    assert_true(check_json_field_bool(subpkt, "critical", false));
    assert_true(check_json_field_str(subpkt, "issuer keyid", "5873bd738e575398"));
    json_object_put(jso);
    rnp_signature_handle_destroy(sighandle);

    /* attempt to validate a timestamp signature instead of detached */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_signatures/source.txt"));
    assert_rnp_success(
      rnp_input_from_path(&signature, "data/test_stream_signatures/signature-timestamp.asc"));
    /* call verify detached to obtain signatures */
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, input, signature));
    assert_rnp_success(rnp_op_verify_execute(verify));
    /* get signature and check it */
    sig_count = 0;
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sig_count));
    assert_int_equal(sig_count, 1);
    /* get signature handle  */
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 0, &sig));
    assert_int_equal(rnp_op_verify_signature_get_status(sig), RNP_ERROR_KEY_NOT_FOUND);
    assert_rnp_success(rnp_op_verify_signature_get_handle(sig, &sighandle));
    assert_non_null(sighandle);
    /* check signature type */
    assert_rnp_success(rnp_signature_get_type(sighandle, &sigtype));
    assert_string_equal(sigtype, "timestamp");
    rnp_buffer_destroy(sigtype);
    /* attempt to validate it via wrong function */
    assert_int_equal(rnp_signature_is_valid(sighandle, 0), RNP_ERROR_BAD_PARAMETERS);
    /* cleanup, making sure that sighandle doesn't depend on verify */
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_input_destroy(signature));
    /* check whether getters work on sighandle: algorithm */
    assert_rnp_success(rnp_signature_get_alg(sighandle, &alg));
    assert_non_null(alg);
    assert_string_equal(alg, "DSA");
    rnp_buffer_destroy(alg);
    /* keyid */
    assert_rnp_success(rnp_signature_get_keyid(sighandle, &keyid));
    assert_non_null(keyid);
    assert_string_equal(keyid, "2D727CC768697734");
    rnp_buffer_destroy(keyid);
    /* creation time */
    assert_rnp_success(rnp_signature_get_creation(sighandle, &create));
    assert_int_equal(create, 1535389094);
    /* hash algorithm */
    assert_rnp_success(rnp_signature_get_hash_alg(sighandle, &alg));
    assert_non_null(alg);
    assert_string_equal(alg, "SHA512");
    rnp_buffer_destroy(alg);
    /* now dump signature packet to json */
    assert_rnp_success(rnp_signature_packet_to_json(sighandle, 0, &json));
    jso = json_tokener_parse(json);
    rnp_buffer_destroy(json);
    assert_non_null(jso);
    assert_true(json_object_is_type(jso, json_type_array));
    assert_int_equal(json_object_array_length(jso), 1);
    /* check the signature packet dump */
    pkt = json_object_array_get_idx(jso, 0);
    /* check helper functions */
    assert_false(check_json_field_int(pkt, "unknown", 4));
    assert_false(check_json_field_int(pkt, "version", 5));
    assert_true(check_json_field_int(pkt, "version", 4));
    assert_true(check_json_field_int(pkt, "type", 0x40));
    assert_true(check_json_field_str(pkt, "type.str", "Timestamp signature"));
    assert_true(check_json_field_int(pkt, "algorithm", 17));
    assert_true(check_json_field_str(pkt, "algorithm.str", "DSA"));
    assert_true(check_json_field_int(pkt, "hash algorithm", 10));
    assert_true(check_json_field_str(pkt, "hash algorithm.str", "SHA512"));
    assert_true(check_json_field_str(pkt, "lbits", "2727"));
    subpkts = NULL;
    assert_true(json_object_object_get_ex(pkt, "subpackets", &subpkts));
    assert_non_null(subpkts);
    assert_true(json_object_is_type(subpkts, json_type_array));
    assert_int_equal(json_object_array_length(subpkts), 7);
    /* subpacket 0 */
    subpkt = json_object_array_get_idx(subpkts, 0);
    assert_true(check_json_field_int(subpkt, "type", 2));
    assert_true(check_json_field_str(subpkt, "type.str", "signature creation time"));
    assert_true(check_json_field_int(subpkt, "length", 4));
    assert_true(check_json_field_bool(subpkt, "hashed", true));
    assert_true(check_json_field_bool(subpkt, "critical", true));
    assert_true(check_json_field_int(subpkt, "creation time", 1535389094));
    /* subpacket 1 */
    subpkt = json_object_array_get_idx(subpkts, 1);
    assert_true(check_json_field_int(subpkt, "type", 7));
    assert_true(check_json_field_str(subpkt, "type.str", "revocable"));
    assert_true(check_json_field_int(subpkt, "length", 1));
    assert_true(check_json_field_bool(subpkt, "hashed", true));
    assert_true(check_json_field_bool(subpkt, "critical", true));
    assert_true(check_json_field_bool(subpkt, "revocable", false));
    /* subpacket 2 */
    subpkt = json_object_array_get_idx(subpkts, 2);
    assert_true(check_json_field_int(subpkt, "type", 16));
    assert_true(check_json_field_str(subpkt, "type.str", "issuer key ID"));
    assert_true(check_json_field_int(subpkt, "length", 8));
    assert_true(check_json_field_bool(subpkt, "hashed", true));
    assert_true(check_json_field_bool(subpkt, "critical", true));
    assert_true(check_json_field_str(subpkt, "issuer keyid", "2d727cc768697734"));
    /* subpacket 3 */
    subpkt = json_object_array_get_idx(subpkts, 3);
    assert_true(check_json_field_int(subpkt, "type", 20));
    assert_true(check_json_field_str(subpkt, "type.str", "notation data"));
    assert_true(check_json_field_int(subpkt, "length", 51));
    assert_true(check_json_field_bool(subpkt, "hashed", true));
    assert_true(check_json_field_bool(subpkt, "critical", false));
    assert_true(check_json_field_str(subpkt,
                                     "raw",
                                     "800000000021000a73657269616c6e756d62657240646f74732e7465"
                                     "7374646f6d61696e2e7465737454455354303030303031"));
    /* subpacket 4 */
    subpkt = json_object_array_get_idx(subpkts, 4);
    assert_true(check_json_field_int(subpkt, "type", 26));
    assert_true(check_json_field_str(subpkt, "type.str", "policy URI"));
    assert_true(check_json_field_int(subpkt, "length", 44));
    assert_true(check_json_field_bool(subpkt, "hashed", true));
    assert_true(check_json_field_bool(subpkt, "critical", false));
    assert_true(
      check_json_field_str(subpkt, "uri", "https://policy.testdomain.test/timestamping/"));
    /* subpacket 5 */
    subpkt = json_object_array_get_idx(subpkts, 5);
    assert_true(check_json_field_int(subpkt, "type", 32));
    assert_true(check_json_field_str(subpkt, "type.str", "embedded signature"));
    assert_true(check_json_field_int(subpkt, "length", 105));
    assert_true(check_json_field_bool(subpkt, "hashed", true));
    assert_true(check_json_field_bool(subpkt, "critical", true));
    json_object *embsig = NULL;
    assert_true(json_object_object_get_ex(subpkt, "signature", &embsig));
    assert_true(check_json_field_int(embsig, "version", 4));
    assert_true(check_json_field_int(embsig, "type", 0));
    assert_true(check_json_field_str(embsig, "type.str", "Signature of a binary document"));
    assert_true(check_json_field_int(embsig, "algorithm", 17));
    assert_true(check_json_field_str(embsig, "algorithm.str", "DSA"));
    assert_true(check_json_field_int(embsig, "hash algorithm", 10));
    assert_true(check_json_field_str(embsig, "hash algorithm.str", "SHA512"));
    assert_true(check_json_field_str(embsig, "lbits", "a386"));
    /* subpacket 6 */
    subpkt = json_object_array_get_idx(subpkts, 6);
    assert_true(check_json_field_int(subpkt, "type", 33));
    assert_true(check_json_field_str(subpkt, "type.str", "issuer fingerprint"));
    assert_true(check_json_field_int(subpkt, "length", 21));
    assert_true(check_json_field_bool(subpkt, "hashed", true));
    assert_true(check_json_field_bool(subpkt, "critical", false));
    assert_true(
      check_json_field_str(subpkt, "fingerprint", "a0ff4590bb6122edef6e3c542d727cc768697734"));
    json_object_put(jso);
    rnp_signature_handle_destroy(sighandle);

    /* cleanup ffi */
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

/** get the value of a (potentially nested) field in a json object
 *
 *  Note that this does not support JSON arrays, only objects.
 *
 *  @param jso the json object to search within. This should be an object, not a string,
 *         array, etc.
 *  @param field the field to retrieve. The format is "first.second.third".
 *  @return a pointer to the located json object, or NULL
 **/
static json_object *
get_json_obj(json_object *jso, const char *field)
{
    const char *start = field;
    const char *end;
    char        buf[32];

    do {
        end = strchr(start, '.');

        size_t len = end ? (end - start) : strlen(start);
        if (len >= sizeof(buf)) {
            return NULL;
        }
        memcpy(buf, start, len);
        buf[len] = '\0';

        if (!json_object_object_get_ex(jso, buf, &jso)) {
            return NULL;
        }

        start = end + 1;
    } while (end);
    return jso;
}

/* This test loads a keyring and converts the keys to JSON,
 * then validates some properties.
 *
 * We could just do a simple strcmp, but that would depend
 * on json-c sorting the keys consistently, across versions,
 * etc.
 */
TEST_F(rnp_tests, test_ffi_key_to_json)
{
    rnp_ffi_t        ffi = NULL;
    char *           pub_format = NULL;
    char *           pub_path = NULL;
    char *           sec_format = NULL;
    char *           sec_path = NULL;
    rnp_key_handle_t key = NULL;
    char *           json = NULL;
    json_object *    jso = NULL;

    // detect the formats+paths
    assert_rnp_success(rnp_detect_homedir_info(
      "data/keyrings/5", &pub_format, &pub_path, &sec_format, &sec_path));
    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, pub_format, sec_format));
    // load our keyrings
    assert_true(load_keys_gpg(ffi, pub_path, sec_path));
    // free formats+paths
    rnp_buffer_destroy(pub_format);
    pub_format = NULL;
    rnp_buffer_destroy(pub_path);
    pub_path = NULL;
    rnp_buffer_destroy(sec_format);
    sec_format = NULL;
    rnp_buffer_destroy(sec_path);
    sec_path = NULL;

    // locate key (primary)
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0E33FD46FF10F19C", &key));
    assert_non_null(key);
    // convert to JSON
    json = NULL;
    assert_rnp_success(rnp_key_to_json(key, 0xff, &json));
    assert_non_null(json);
    // parse it back in
    jso = json_tokener_parse(json);
    assert_non_null(jso);
    // validate some properties
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "type")), "ECDSA"), 0);
    assert_int_equal(json_object_get_int(get_json_obj(jso, "length")), 256);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "curve")), "NIST P-256"), 0);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "keyid")), "0E33FD46FF10F19C"),
      0);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "fingerprint")),
                                    "B6B5E497A177551ECB8862200E33FD46FF10F19C"),
                     0);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "grip")),
                                    "20A48B3C61525DCDF8B3B9D82C6BBCF4D8BFB5E5"),
                     0);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "revoked")), false);
    assert_int_equal(json_object_get_int64(get_json_obj(jso, "creation time")), 1511313500);
    assert_int_equal(json_object_get_int64(get_json_obj(jso, "expiration")), 0);
    // usage
    assert_int_equal(json_object_array_length(get_json_obj(jso, "usage")), 2);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(json_object_array_get_idx(
                                      get_json_obj(jso, "usage"), 0)),
                                    "sign"),
                     0);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(json_object_array_get_idx(
                                      get_json_obj(jso, "usage"), 1)),
                                    "certify"),
                     0);
    // primary key grip
    assert_null(get_json_obj(jso, "primary key grip"));
    // subkey grips
    assert_int_equal(json_object_array_length(get_json_obj(jso, "subkey grips")), 1);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(json_object_array_get_idx(
                                      get_json_obj(jso, "subkey grips"), 0)),
                                    "FFFA72FC225214DC712D0127172EE13E88AF93B4"),
                     0);
    // public key
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "public key.present")), true);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "public key.mpis.point")),
                     "04B0C6F2F585C1EEDF805C4492CB683839D5EAE6246420780F063D558"
                     "A33F607876BE6F818A665722F8204653CC4DCFAD4F4765521AC8A6E9F"
                     "793CEBAE8600BEEF"),
      0);
    // secret key
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.present")), true);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "secret key.mpis.x")),
                     "46DE93CA439735F36B9CF228F10D8586DA824D88BBF4E24566D5312D061802C8"),
      0);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.locked")), false);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.protected")),
                     false);
    // userids
    assert_int_equal(json_object_array_length(get_json_obj(jso, "userids")), 1);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(json_object_array_get_idx(
                                      get_json_obj(jso, "userids"), 0)),
                                    "test0"),
                     0);
    // signatures
    assert_int_equal(json_object_array_length(get_json_obj(jso, "signatures")), 1);
    json_object *jsosig = json_object_array_get_idx(get_json_obj(jso, "signatures"), 0);
    assert_int_equal(json_object_get_int(get_json_obj(jsosig, "userid")), 0);
    // TODO: other properties of signature
    // cleanup
    json_object_put(jso);
    rnp_key_handle_destroy(key);
    key = NULL;
    rnp_buffer_destroy(json);
    json = NULL;

    // locate key (sub)
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "074131BC8D16C5C9", &key));
    assert_non_null(key);
    // convert to JSON
    assert_rnp_success(rnp_key_to_json(key, 0xff, &json));
    assert_non_null(json);
    // parse it back in
    jso = json_tokener_parse(json);
    assert_non_null(jso);
    // validate some properties
    assert_int_equal(rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "type")), "ECDH"),
                     0);
    assert_int_equal(json_object_get_int(get_json_obj(jso, "length")), 256);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "curve")), "NIST P-256"), 0);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "keyid")), "074131BC8D16C5C9"),
      0);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "fingerprint")),
                                    "481E6A41B10ECD71A477DB02074131BC8D16C5C9"),
                     0);
    // ECDH-specific
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "kdf hash")), "SHA256"), 0);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "key wrap cipher")), "AES128"),
      0);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "grip")),
                                    "FFFA72FC225214DC712D0127172EE13E88AF93B4"),
                     0);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "revoked")), false);
    assert_int_equal(json_object_get_int64(get_json_obj(jso, "creation time")), 1511313500);
    assert_int_equal(json_object_get_int64(get_json_obj(jso, "expiration")), 0);
    // usage
    assert_int_equal(json_object_array_length(get_json_obj(jso, "usage")), 1);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(json_object_array_get_idx(
                                      get_json_obj(jso, "usage"), 0)),
                                    "encrypt"),
                     0);
    // primary key grip
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "primary key grip")),
                     "20A48B3C61525DCDF8B3B9D82C6BBCF4D8BFB5E5"),
      0);
    // subkey grips
    assert_null(get_json_obj(jso, "subkey grips"));
    // public key
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "public key.present")), true);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "public key.mpis.point")),
                     "04E2746BA4D180011B17A6909EABDBF2F3733674FBE00B20A3B857C2597233651544150B"
                     "896BCE7DCDF47C49FC1E12D5AD86384D26336A48A18845940A3F65F502"),
      0);
    // secret key
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.present")), true);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "secret key.mpis.x")),
                     "DF8BEB7272117AD7AFE2B7E882453113059787FBC785C82F78624EE7EF2117FB"),
      0);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.locked")), false);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.protected")),
                     false);
    // userids
    assert_null(get_json_obj(jso, "userids"));
    // signatures
    assert_int_equal(json_object_array_length(get_json_obj(jso, "signatures")), 1);
    jsosig = json_object_array_get_idx(get_json_obj(jso, "signatures"), 0);
    assert_null(get_json_obj(jsosig, "userid"));
    // TODO: other properties of signature
    // cleanup
    json_object_put(jso);
    rnp_key_handle_destroy(key);
    rnp_buffer_destroy(json);

    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_iter)
{
    rnp_ffi_t ffi = NULL;
    char *    pub_format = NULL;
    char *    pub_path = NULL;
    char *    sec_format = NULL;
    char *    sec_path = NULL;

    // detect the formats+paths
    assert_rnp_success(rnp_detect_homedir_info(
      "data/keyrings/1", &pub_format, &pub_path, &sec_format, &sec_path));
    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, pub_format, sec_format));

    // test invalid identifier type
    {
        rnp_identifier_iterator_t it = NULL;
        assert_rnp_failure(rnp_identifier_iterator_create(ffi, &it, "keyidz"));
        assert_null(it);
    }

    // test empty rings
    // keyid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_rnp_success(rnp_identifier_iterator_create(ffi, &it, "keyid"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_rnp_success(rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_rnp_success(rnp_identifier_iterator_destroy(it));
    }
    // grip
    {
        rnp_identifier_iterator_t it = NULL;
        assert_rnp_success(rnp_identifier_iterator_create(ffi, &it, "grip"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_rnp_success(rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_rnp_success(rnp_identifier_iterator_destroy(it));
    }
    // userid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_rnp_success(rnp_identifier_iterator_create(ffi, &it, "userid"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_rnp_success(rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_rnp_success(rnp_identifier_iterator_destroy(it));
    }

    // test with both rings empty
    // keyid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_rnp_success(rnp_identifier_iterator_create(ffi, &it, "keyid"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_rnp_success(rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_rnp_success(rnp_identifier_iterator_destroy(it));
    }
    // grip
    {
        rnp_identifier_iterator_t it = NULL;
        assert_rnp_success(rnp_identifier_iterator_create(ffi, &it, "grip"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_rnp_success(rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_rnp_success(rnp_identifier_iterator_destroy(it));
    }
    // userid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_rnp_success(rnp_identifier_iterator_create(ffi, &it, "userid"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_rnp_success(rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_rnp_success(rnp_identifier_iterator_destroy(it));
    }

    // load our keyrings
    assert_true(load_keys_gpg(ffi, pub_path, sec_path));
    // free formats+paths
    rnp_buffer_destroy(pub_format);
    pub_format = NULL;
    rnp_buffer_destroy(pub_path);
    pub_path = NULL;
    rnp_buffer_destroy(sec_format);
    sec_format = NULL;
    rnp_buffer_destroy(sec_path);
    sec_path = NULL;

    // keyid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_rnp_success(rnp_identifier_iterator_create(ffi, &it, "keyid"));
        assert_non_null(it);
        {
            static const char *expected[] = {"7BC6709B15C23A4A",
                                             "1ED63EE56FADC34D",
                                             "1D7E8A5393C997A8",
                                             "8A05B89FAD5ADED1",
                                             "2FCADF05FFA501BB",
                                             "54505A936A4A970E",
                                             "326EF111425D14A5"};
            size_t             i = 0;
            const char *       ident = NULL;
            do {
                ident = NULL;
                assert_rnp_success(rnp_identifier_iterator_next(it, &ident));
                if (ident) {
                    assert_int_equal(0, rnp_strcasecmp(expected[i], ident));
                    i++;
                }
            } while (ident);
            assert_int_equal(i, ARRAY_SIZE(expected));
        }
        assert_rnp_success(rnp_identifier_iterator_destroy(it));
    }

    // grip
    {
        rnp_identifier_iterator_t it = NULL;
        assert_rnp_success(rnp_identifier_iterator_create(ffi, &it, "grip"));
        assert_non_null(it);
        {
            static const char *expected[] = {"66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA",
                                             "D9839D61EDAF0B3974E0A4A341D6E95F3479B9B7",
                                             "B1CC352FEF9A6BD4E885B5351840EF9306D635F0",
                                             "E7C8860B70DC727BED6DB64C633683B41221BB40",
                                             "B2A7F6C34AA2C15484783E9380671869A977A187",
                                             "43C01D6D96BE98C3C87FE0F175870ED92DE7BE45",
                                             "8082FE753013923972632550838A5F13D81F43B9"};
            size_t             i = 0;
            const char *       ident = NULL;
            do {
                ident = NULL;
                assert_rnp_success(rnp_identifier_iterator_next(it, &ident));
                if (ident) {
                    assert_int_equal(0, rnp_strcasecmp(expected[i], ident));
                    i++;
                }
            } while (ident);
            assert_int_equal(i, ARRAY_SIZE(expected));
        }
        assert_rnp_success(rnp_identifier_iterator_destroy(it));
    }

    // userid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_rnp_success(rnp_identifier_iterator_create(ffi, &it, "userid"));
        assert_non_null(it);
        {
            static const char *expected[] = {
              "key0-uid0", "key0-uid1", "key0-uid2", "key1-uid0", "key1-uid2", "key1-uid1"};
            size_t      i = 0;
            const char *ident = NULL;
            do {
                ident = NULL;
                assert_rnp_success(rnp_identifier_iterator_next(it, &ident));
                if (ident) {
                    assert_int_equal(0, rnp_strcasecmp(expected[i], ident));
                    i++;
                }
            } while (ident);
            assert_int_equal(i, ARRAY_SIZE(expected));
        }
        assert_rnp_success(rnp_identifier_iterator_destroy(it));
    }

    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_locate_key)
{
    rnp_ffi_t ffi = NULL;

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load our keyrings
    assert_true(load_keys_gpg(ffi, "data/keyrings/1/pubring.gpg"));

    // keyid
    {
        static const char *ids[] = {"7BC6709B15C23A4A",
                                    "1ED63EE56FADC34D",
                                    "1D7E8A5393C997A8",
                                    "8A05B89FAD5ADED1",
                                    "2FCADF05FFA501BB",
                                    "54505A936A4A970E",
                                    "326EF111425D14A5"};
        for (size_t i = 0; i < ARRAY_SIZE(ids); i++) {
            const char *     id = ids[i];
            rnp_key_handle_t key = NULL;
            assert_rnp_success(rnp_locate_key(ffi, "keyid", id, &key));
            assert_non_null(key);
            rnp_key_handle_destroy(key);
        }
        // invalid - value did not change
        {
            rnp_key_handle_t key = (rnp_key_handle_t) 0x111;
            assert_rnp_failure(rnp_locate_key(ffi, "keyid", "invalid-keyid", &key));
            assert_true(key == (rnp_key_handle_t) 0x111);
        }
        // valid but non-existent - null returned
        {
            rnp_key_handle_t key = (rnp_key_handle_t) 0x111;
            assert_rnp_success(rnp_locate_key(ffi, "keyid", "AAAAAAAAAAAAAAAA", &key));
            assert_null(key);
        }
    }

    // userid
    {
        static const char *ids[] = {
          "key0-uid0", "key0-uid1", "key0-uid2", "key1-uid0", "key1-uid2", "key1-uid1"};
        for (size_t i = 0; i < ARRAY_SIZE(ids); i++) {
            const char *     id = ids[i];
            rnp_key_handle_t key = NULL;
            assert_rnp_success(rnp_locate_key(ffi, "userid", id, &key));
            assert_non_null(key);
            rnp_key_handle_destroy(key);
        }
        // valid but non-existent
        {
            rnp_key_handle_t key = (rnp_key_handle_t) 0x111;
            assert_rnp_success(rnp_locate_key(ffi, "userid", "bad-userid", &key));
            assert_null(key);
        }
    }

    // fingerprint
    {
        static const char *ids[] = {"E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A",
                                    "E332B27CAF4742A11BAA677F1ED63EE56FADC34D",
                                    "C5B15209940A7816A7AF3FB51D7E8A5393C997A8",
                                    "5CD46D2A0BD0B8CFE0B130AE8A05B89FAD5ADED1",
                                    "BE1C4AB951F4C2F6B604C7F82FCADF05FFA501BB",
                                    "A3E94DE61A8CB229413D348E54505A936A4A970E",
                                    "57F8ED6E5C197DB63C60FFAF326EF111425D14A5"};
        for (size_t i = 0; i < ARRAY_SIZE(ids); i++) {
            const char *     id = ids[i];
            rnp_key_handle_t key = NULL;
            assert_rnp_success(rnp_locate_key(ffi, "fingerprint", id, &key));
            assert_non_null(key);
            rnp_key_handle_destroy(key);
        }
        // invalid
        {
            rnp_key_handle_t key = (rnp_key_handle_t) 0x111;
            assert_rnp_failure(rnp_locate_key(ffi, "fingerprint", "invalid-fpr", &key));
            assert_true(key == (rnp_key_handle_t) 0x111);
        }
        // valid but non-existent
        {
            rnp_key_handle_t key = (rnp_key_handle_t) 0x111;
            assert_rnp_success(rnp_locate_key(
              ffi, "fingerprint", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &key));
            assert_null(key);
        }
    }

    // grip
    {
        static const char *ids[] = {"66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA",
                                    "D9839D61EDAF0B3974E0A4A341D6E95F3479B9B7",
                                    "B1CC352FEF9A6BD4E885B5351840EF9306D635F0",
                                    "E7C8860B70DC727BED6DB64C633683B41221BB40",
                                    "B2A7F6C34AA2C15484783E9380671869A977A187",
                                    "43C01D6D96BE98C3C87FE0F175870ED92DE7BE45",
                                    "8082FE753013923972632550838A5F13D81F43B9"};
        for (size_t i = 0; i < ARRAY_SIZE(ids); i++) {
            const char *     id = ids[i];
            rnp_key_handle_t key = NULL;
            assert_rnp_success(rnp_locate_key(ffi, "grip", id, &key));
            assert_non_null(key);
            rnp_key_handle_destroy(key);
        }
        // invalid
        {
            rnp_key_handle_t key = (rnp_key_handle_t) 0x111;
            assert_rnp_failure(rnp_locate_key(ffi, "grip", "invalid-fpr", &key));
            assert_true(key == (rnp_key_handle_t) 0x111);
        }
        // valid but non-existent
        {
            rnp_key_handle_t key = (rnp_key_handle_t) 0x111;
            assert_rnp_success(
              rnp_locate_key(ffi, "grip", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &key));
            assert_null(key);
        }
    }

    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_signatures_detached_memory_g10)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_input_t      input_sig = NULL;
    rnp_output_t     output = NULL;
    rnp_key_handle_t key = NULL;
    rnp_op_sign_t    opsign = NULL;
    rnp_op_verify_t  opverify = NULL;
    const char *     data = "my data";
    uint8_t *        sig = NULL;
    size_t           sig_len = 0;

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "KBX", "G10"));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));

    // load our keyrings
    assert_true(load_keys_kbx_g10(
      ffi, "data/keyrings/3/pubring.kbx", "data/keyrings/3/private-keys-v1.d"));

    // find our signing key
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "4BE147BB22DF1E60", &key));
    assert_non_null(key);

    // create our input
    assert_rnp_success(rnp_input_from_memory(&input, (uint8_t *) data, strlen(data), false));
    assert_non_null(input);
    // create our output
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_non_null(output);
    // create the signing operation
    assert_rnp_success(rnp_op_sign_detached_create(&opsign, ffi, input, output));
    assert_non_null(opsign);

    // add the signer
    assert_rnp_success(rnp_op_sign_add_signature(opsign, key, NULL));
    // execute the signing operation
    assert_rnp_success(rnp_op_sign_execute(opsign));
    // get the resulting signature
    assert_rnp_success(rnp_output_memory_get_buf(output, &sig, &sig_len, true));
    assert_non_null(sig);
    assert_int_not_equal(0, sig_len);
    // cleanup
    rnp_op_sign_destroy(opsign);
    opsign = NULL;
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // verify
    // create our data input
    assert_rnp_success(rnp_input_from_memory(&input, (uint8_t *) data, strlen(data), false));
    assert_non_null(input);
    // create our signature input
    assert_rnp_success(rnp_input_from_memory(&input_sig, sig, sig_len, true));
    assert_non_null(input_sig);
    // create our operation
    assert_rnp_success(rnp_op_verify_detached_create(&opverify, ffi, input, input_sig));
    assert_non_null(opverify);
    // execute the verification
    assert_rnp_success(rnp_op_verify_execute(opverify));
    // cleanup
    rnp_op_verify_destroy(opverify);
    opverify = NULL;
    rnp_input_destroy(input);
    input = NULL;
    rnp_input_destroy(input_sig);
    input_sig = NULL;

    // verify (tamper with signature)
    // create our data input
    assert_rnp_success(rnp_input_from_memory(&input, (uint8_t *) data, strlen(data), false));
    assert_non_null(input);
    // create our signature input
    sig[sig_len - 5] ^= 0xff;
    assert_rnp_success(rnp_input_from_memory(&input_sig, sig, sig_len, true));
    assert_non_null(input_sig);
    // create our operation
    assert_rnp_success(rnp_op_verify_detached_create(&opverify, ffi, input, input_sig));
    assert_non_null(opverify);
    // execute the verification
    assert_rnp_failure(rnp_op_verify_execute(opverify));
    // cleanup
    rnp_op_verify_destroy(opverify);
    opverify = NULL;
    rnp_input_destroy(input);
    input = NULL;
    rnp_input_destroy(input_sig);
    input_sig = NULL;

    // cleanup
    rnp_buffer_destroy(sig);
    rnp_key_handle_destroy(key);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_enarmor_dearmor)
{
    std::string data;

    // enarmor plain message
    const std::string msg("this is a test");
    data.clear();
    {
        uint8_t *    buf = NULL;
        size_t       buf_size = 0;
        rnp_input_t  input = NULL;
        rnp_output_t output = NULL;

        assert_rnp_success(
          rnp_input_from_memory(&input, (const uint8_t *) msg.data(), msg.size(), true));
        assert_rnp_success(rnp_output_to_memory(&output, 0));

        assert_rnp_success(rnp_enarmor(input, output, "message"));

        rnp_output_memory_get_buf(output, &buf, &buf_size, false);
        data = std::string(buf, buf + buf_size);
        assert_true(starts_with(data, "-----BEGIN PGP MESSAGE-----\r\n"));
        assert_true(ends_with(data, "-----END PGP MESSAGE-----\r\n"));

        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }
    {
        uint8_t *    buf = NULL;
        size_t       buf_size = 0;
        rnp_input_t  input = NULL;
        rnp_output_t output = NULL;

        assert_rnp_success(
          rnp_input_from_memory(&input, (const uint8_t *) data.data(), data.size(), true));
        assert_rnp_success(rnp_output_to_memory(&output, 0));

        assert_rnp_success(rnp_dearmor(input, output));

        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_size, false));
        std::string dearmored(buf, buf + buf_size);
        assert_true(msg == dearmored);

        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }

    // enarmor public key
    data.clear();
    {
        uint8_t *    buf = NULL;
        size_t       buf_size = 0;
        rnp_input_t  input = NULL;
        rnp_output_t output = NULL;

        // enarmor
        assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
        assert_rnp_success(rnp_output_to_memory(&output, 0));

        assert_rnp_success(rnp_enarmor(input, output, NULL));

        rnp_output_memory_get_buf(output, &buf, &buf_size, false);
        data = std::string(buf, buf + buf_size);
        assert_true(starts_with(data, "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n"));
        assert_true(ends_with(data, "-----END PGP PUBLIC KEY BLOCK-----\r\n"));

        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }
    // dearmor public key
    {
        uint8_t *    buf = NULL;
        size_t       buf_size = 0;
        rnp_input_t  input = NULL;
        rnp_output_t output = NULL;

        assert_rnp_success(
          rnp_input_from_memory(&input, (const uint8_t *) data.data(), data.size(), true));
        assert_rnp_success(rnp_output_to_memory(&output, 0));

        assert_rnp_success(rnp_dearmor(input, output));

        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_size, false));
        std::string   dearmored(buf, buf + buf_size);
        std::ifstream inf("data/keyrings/1/pubring.gpg", std::ios::binary | std::ios::ate);
        std::string   from_disk(inf.tellg(), ' ');
        inf.seekg(0);
        inf.read(&from_disk[0], from_disk.size());
        inf.close();
        assert_true(dearmored == from_disk);

        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }
    // test truncated armored data
    {
        std::ifstream keyf("data/test_stream_key_load/rsa-rsa-pub.asc",
                           std::ios::binary | std::ios::ate);
        std::string   keystr(keyf.tellg(), ' ');
        keyf.seekg(0);
        keyf.read(&keystr[0], keystr.size());
        keyf.close();
        for (size_t sz = keystr.size() - 2; sz > 0; sz--) {
            rnp_input_t  input = NULL;
            rnp_output_t output = NULL;

            assert_rnp_success(
              rnp_input_from_memory(&input, (const uint8_t *) keystr.data(), sz, true));
            assert_rnp_success(rnp_output_to_memory(&output, 0));
            assert_rnp_failure(rnp_dearmor(input, output));

            rnp_input_destroy(input);
            rnp_output_destroy(output);
        }
    }
}

TEST_F(rnp_tests, test_ffi_dearmor_edge_cases)
{
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/long_header_line.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dearmor(input, output));
    uint8_t *buf = NULL;
    size_t   len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 2226);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/empty_header_line.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dearmor(input, output));
    buf = NULL;
    len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 2226);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(rnp_input_from_path(
      &input, "data/test_stream_armor/64k_whitespace_before_armored_message.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_failure(rnp_dearmor(input, output));
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* Armor header starts and fits in the first 1024 bytes of the input. Prepended by
     * whitespaces. */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/1024_peek_buf.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dearmor(input, output));
    buf = NULL;
    len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 2226);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/blank_line_with_whitespace.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dearmor(input, output));
    buf = NULL;
    len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 2226);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/duplicate_header_line.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dearmor(input, output));
    buf = NULL;
    len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 2226);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/long_header_line_1024.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dearmor(input, output));
    buf = NULL;
    len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 2226);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/long_header_line_64k.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dearmor(input, output));
    buf = NULL;
    len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 2226);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/long_header_nameline_64k.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dearmor(input, output));
    buf = NULL;
    len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 2226);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* Armored message encoded in a single >64k text line */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/message_64k_oneline.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dearmor(input, output));
    buf = NULL;
    len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 68647);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/wrong_header_line.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dearmor(input, output));
    buf = NULL;
    len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 2226);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* invalid, > 127 (negative char), preceding the armor header - just warning */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/wrong_chars_header.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dearmor(input, output));
    buf = NULL;
    len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 2226);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* invalid, > 127, base64 chars at positions 1..4 */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/wrong_chars_base64_1.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_failure(rnp_dearmor(input, output));
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/wrong_chars_base64_2.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_failure(rnp_dearmor(input, output));
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/wrong_chars_base64_3.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_failure(rnp_dearmor(input, output));
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/wrong_chars_base64_4.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_failure(rnp_dearmor(input, output));
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* invalid, > 127 base64 char in the crc */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/wrong_chars_crc.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_failure(rnp_dearmor(input, output));
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* too short armor header */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_armor/too_short_header.asc"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_failure(rnp_dearmor(input, output));
    rnp_input_destroy(input);
    rnp_output_destroy(output);
}

TEST_F(rnp_tests, test_ffi_customized_enarmor)
{
    rnp_input_t           input = NULL;
    rnp_output_t          output = NULL;
    rnp_output_t          armor_layer = NULL;
    const std::string     msg("this is a test long enough to have more than 76 characters in "
                          "enarmored representation");
    std::set<std::string> lines_to_skip{"-----BEGIN PGP MESSAGE-----",
                                        "-----END PGP MESSAGE-----"};

    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_output_to_armor(output, &armor_layer, "message"));
    // should fail when trying to set line length on non-armor output
    assert_rnp_failure(rnp_output_armor_set_line_length(output, 64));
    // should fail when trying to set zero line length
    assert_rnp_failure(rnp_output_armor_set_line_length(armor_layer, 0));
    // should fail when trying to set line length less than the minimum allowed 16
    assert_rnp_failure(rnp_output_armor_set_line_length(armor_layer, 15));
    assert_rnp_success(rnp_output_armor_set_line_length(armor_layer, 16));
    assert_rnp_success(rnp_output_armor_set_line_length(armor_layer, 76));
    // should fail when trying to set line length greater than the maximum allowed 76
    assert_rnp_failure(rnp_output_armor_set_line_length(armor_layer, 77));
    assert_rnp_success(rnp_output_destroy(armor_layer));
    assert_rnp_success(rnp_output_destroy(output));

    for (size_t llen = 16; llen <= 76; llen++) {
        std::string data;
        uint8_t *   buf = NULL;
        size_t      buf_size = 0;

        input = NULL;
        output = NULL;
        armor_layer = NULL;
        assert_rnp_success(
          rnp_input_from_memory(&input, (const uint8_t *) msg.data(), msg.size(), true));
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_rnp_success(rnp_output_to_armor(output, &armor_layer, "message"));
        assert_rnp_success(rnp_output_armor_set_line_length(armor_layer, llen));
        assert_rnp_success(rnp_output_pipe(input, armor_layer));
        assert_rnp_success(rnp_output_finish(armor_layer));
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_size, false));
        data = std::string(buf, buf + buf_size);
        auto effective_llen = get_longest_line_length(data, lines_to_skip);
        assert_int_equal(llen / 4, effective_llen / 4);
        assert_true(llen >= effective_llen);
        assert_rnp_success(rnp_input_destroy(input));
        assert_rnp_success(rnp_output_destroy(armor_layer));
        assert_rnp_success(rnp_output_destroy(output));

        // test that the dearmored message is correct
        assert_rnp_success(
          rnp_input_from_memory(&input, (const uint8_t *) data.data(), data.size(), true));
        assert_rnp_success(rnp_output_to_memory(&output, 0));

        assert_rnp_success(rnp_dearmor(input, output));

        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_size, false));
        std::string dearmored(buf, buf + buf_size);
        assert_true(msg == dearmored);

        assert_rnp_success(rnp_input_destroy(input));
        assert_rnp_success(rnp_output_destroy(output));
    }
}

TEST_F(rnp_tests, test_ffi_version)
{
    const uint32_t version = rnp_version();
    const uint32_t major = rnp_version_major(version);
    const uint32_t minor = rnp_version_minor(version);
    const uint32_t patch = rnp_version_patch(version);

    // reconstruct the version string
    assert_string_equal(fmt("%d.%d.%d", major, minor, patch).c_str(), rnp_version_string());

    // full version string should probably be at least as long as regular version string
    assert_true(strlen(rnp_version_string_full()) >= strlen(rnp_version_string()));

    // reconstruct the version value
    assert_int_equal(version, rnp_version_for(major, minor, patch));

    // check out-of-range handling
    assert_int_equal(0, rnp_version_for(1024, 0, 0));
    assert_int_equal(0, rnp_version_for(0, 1024, 0));
    assert_int_equal(0, rnp_version_for(0, 0, 1024));

    // check component extraction again
    assert_int_equal(rnp_version_major(rnp_version_for(5, 4, 3)), 5);
    assert_int_equal(rnp_version_minor(rnp_version_for(5, 4, 3)), 4);
    assert_int_equal(rnp_version_patch(rnp_version_for(5, 4, 3)), 3);

    // simple comparisons
    assert_true(rnp_version_for(1, 0, 1) > rnp_version_for(1, 0, 0));
    assert_true(rnp_version_for(1, 1, 0) > rnp_version_for(1, 0, 1023));
    assert_true(rnp_version_for(2, 0, 0) > rnp_version_for(1, 1023, 1023));
}

static void
check_loaded_keys(const char *                    format,
                  bool                            armored,
                  uint8_t *                       buf,
                  size_t                          buf_len,
                  const char *                    id_type,
                  const std::vector<std::string> &expected_ids,
                  bool                            secret)
{
    rnp_ffi_t                 ffi = NULL;
    rnp_input_t               input = NULL;
    rnp_identifier_iterator_t it = NULL;
    const char *              identifier = NULL;

    if (armored) {
        assert_memory_equal("-----", buf, 5);
    } else {
        assert_memory_not_equal("-----", buf, 5);
    }

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, format, format));

    // load our keyrings
    assert_rnp_success(rnp_input_from_memory(&input, buf, buf_len, true));
    assert_rnp_success(rnp_load_keys(
      ffi, format, input, secret ? RNP_LOAD_SAVE_SECRET_KEYS : RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    std::vector<std::string> ids;
    assert_rnp_success(rnp_identifier_iterator_create(ffi, &it, id_type));
    do {
        identifier = NULL;
        assert_rnp_success(rnp_identifier_iterator_next(it, &identifier));
        if (identifier) {
            rnp_key_handle_t key = NULL;
            bool             expected_secret = secret;
            bool             expected_public = !secret;
            bool             result;
            assert_rnp_success(rnp_locate_key(ffi, id_type, identifier, &key));
            assert_non_null(key);
            assert_rnp_success(rnp_key_have_secret(key, &result));
            assert_int_equal(result, expected_secret);
            assert_rnp_success(rnp_key_have_public(key, &result));
            assert_int_equal(result, expected_public);
            assert_rnp_success(rnp_key_handle_destroy(key));
            ids.push_back(identifier);
        }
    } while (identifier);
    assert_true(ids == expected_ids);
    rnp_identifier_iterator_destroy(it);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_export)
{
    rnp_ffi_t        ffi = NULL;
    rnp_output_t     output = NULL;
    rnp_key_handle_t key = NULL;
    uint8_t *        buf = NULL;
    size_t           buf_len = 0;

    // setup FFI
    test_ffi_init(&ffi);

    // primary pub only
    {
        // locate key
        key = NULL;
        assert_rnp_success(rnp_locate_key(ffi, "keyid", "2FCADF05FFA501BB", &key));
        assert_non_null(key);

        // create output
        output = NULL;
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_non_null(output);

        // export
        assert_rnp_success(rnp_key_export(key, output, RNP_KEY_EXPORT_PUBLIC));

        // get output
        buf = NULL;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
        assert_non_null(buf);

        // check results
        check_loaded_keys("GPG", false, buf, buf_len, "keyid", {"2FCADF05FFA501BB"}, false);

        // cleanup
        rnp_output_destroy(output);
        rnp_key_handle_destroy(key);
    }

    // primary sec only (armored)
    {
        // locate key
        key = NULL;
        assert_rnp_success(rnp_locate_key(ffi, "keyid", "2FCADF05FFA501BB", &key));
        assert_non_null(key);

        // create output
        output = NULL;
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_non_null(output);

        // export
        assert_rnp_success(
          rnp_key_export(key, output, RNP_KEY_EXPORT_SECRET | RNP_KEY_EXPORT_ARMORED));

        // get output
        buf = NULL;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
        assert_non_null(buf);

        // check results
        check_loaded_keys("GPG", true, buf, buf_len, "keyid", {"2FCADF05FFA501BB"}, true);

        // cleanup
        rnp_output_destroy(output);
        rnp_key_handle_destroy(key);
    }

    // primary pub and subs
    {
        // locate key
        key = NULL;
        assert_rnp_success(rnp_locate_key(ffi, "keyid", "2FCADF05FFA501BB", &key));
        assert_non_null(key);

        // create output
        output = NULL;
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_non_null(output);

        // export
        assert_rnp_success(
          rnp_key_export(key, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));

        // get output
        buf = NULL;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
        assert_non_null(buf);

        // check results
        check_loaded_keys("GPG",
                          false,
                          buf,
                          buf_len,
                          "keyid",
                          {"2FCADF05FFA501BB", "54505A936A4A970E", "326EF111425D14A5"},
                          false);

        // cleanup
        rnp_output_destroy(output);
        rnp_key_handle_destroy(key);
    }

    // primary sec and subs (armored)
    {
        // locate key
        key = NULL;
        assert_rnp_success(rnp_locate_key(ffi, "keyid", "2FCADF05FFA501BB", &key));
        assert_non_null(key);

        // create output
        output = NULL;
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_non_null(output);

        // export
        assert_rnp_success(rnp_key_export(key,
                                          output,
                                          RNP_KEY_EXPORT_SECRET | RNP_KEY_EXPORT_SUBKEYS |
                                            RNP_KEY_EXPORT_ARMORED));

        // get output
        buf = NULL;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
        assert_non_null(buf);

        // check results
        check_loaded_keys("GPG",
                          true,
                          buf,
                          buf_len,
                          "keyid",
                          {"2FCADF05FFA501BB", "54505A936A4A970E", "326EF111425D14A5"},
                          true);

        // cleanup
        rnp_output_destroy(output);
        rnp_key_handle_destroy(key);
    }

    // sub pub
    {
        // locate key
        key = NULL;
        assert_rnp_success(rnp_locate_key(ffi, "keyid", "54505A936A4A970E", &key));
        assert_non_null(key);

        // create output
        output = NULL;
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_non_null(output);

        // export
        assert_rnp_success(
          rnp_key_export(key, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_ARMORED));

        // get output
        buf = NULL;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
        assert_non_null(buf);

        // check results
        check_loaded_keys(
          "GPG", true, buf, buf_len, "keyid", {"2FCADF05FFA501BB", "54505A936A4A970E"}, false);

        // cleanup
        rnp_output_destroy(output);
        rnp_key_handle_destroy(key);
    }

    // sub sec
    {
        // locate key
        key = NULL;
        assert_rnp_success(rnp_locate_key(ffi, "keyid", "54505A936A4A970E", &key));
        assert_non_null(key);

        // create output
        output = NULL;
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_non_null(output);

        // export
        assert_rnp_success(
          rnp_key_export(key, output, RNP_KEY_EXPORT_SECRET | RNP_KEY_EXPORT_ARMORED));

        // get output
        buf = NULL;
        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
        assert_non_null(buf);

        // check results
        check_loaded_keys(
          "GPG", true, buf, buf_len, "keyid", {"2FCADF05FFA501BB", "54505A936A4A970E"}, true);

        // cleanup
        rnp_output_destroy(output);
        rnp_key_handle_destroy(key);
    }

    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_export_customized_enarmor)
{
    rnp_ffi_t             ffi = NULL;
    rnp_output_t          output = NULL;
    rnp_output_t          armor_layer = NULL;
    rnp_key_handle_t      key = NULL;
    uint8_t *             buf = NULL;
    size_t                buf_len = 0;
    std::set<std::string> lines_to_skip{"-----BEGIN PGP PUBLIC KEY BLOCK-----",
                                        "-----END PGP PUBLIC KEY BLOCK-----",
                                        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
                                        "-----END PGP PRIVATE KEY BLOCK-----"};
    // setup FFI
    test_ffi_init(&ffi);

    for (size_t llen = 16; llen <= 76; llen++) {
        // primary pub only
        {
            // locate key
            key = NULL;
            assert_rnp_success(rnp_locate_key(ffi, "keyid", "2FCADF05FFA501BB", &key));
            assert_non_null(key);

            // create output
            output = NULL;
            assert_rnp_success(rnp_output_to_memory(&output, 0));
            assert_non_null(output);
            assert_rnp_success(rnp_output_to_armor(output, &armor_layer, "public key"));
            assert_non_null(armor_layer);
            assert_rnp_success(rnp_output_armor_set_line_length(armor_layer, llen));

            // export
            assert_rnp_success(rnp_key_export(key, armor_layer, RNP_KEY_EXPORT_PUBLIC));
            assert_rnp_success(rnp_output_finish(armor_layer));
            // get output
            buf = NULL;
            assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
            assert_non_null(buf);
            std::string data = std::string(buf, buf + buf_len);
            auto        effective_llen = get_longest_line_length(data, lines_to_skip);
            assert_int_equal(llen / 4, effective_llen / 4);
            assert_true(llen >= effective_llen);

            // check results
            check_loaded_keys("GPG", true, buf, buf_len, "keyid", {"2FCADF05FFA501BB"}, false);

            // cleanup
            rnp_output_destroy(armor_layer);
            rnp_output_destroy(output);
            rnp_key_handle_destroy(key);
        }

        // primary sec only
        {
            // locate key
            key = NULL;
            assert_rnp_success(rnp_locate_key(ffi, "keyid", "2FCADF05FFA501BB", &key));
            assert_non_null(key);

            // create output
            output = NULL;
            assert_rnp_success(rnp_output_to_memory(&output, 0));
            assert_non_null(output);
            assert_rnp_success(rnp_output_to_armor(output, &armor_layer, "secret key"));
            assert_non_null(armor_layer);
            assert_rnp_success(rnp_output_armor_set_line_length(armor_layer, llen));

            // export
            assert_rnp_success(rnp_key_export(key, armor_layer, RNP_KEY_EXPORT_SECRET));
            assert_rnp_success(rnp_output_finish(armor_layer));

            // get output
            buf = NULL;
            assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
            assert_non_null(buf);
            std::string data = std::string(buf, buf + buf_len);
            auto        effective_llen = get_longest_line_length(data, lines_to_skip);
            assert_int_equal(llen / 4, effective_llen / 4);
            assert_true(llen >= effective_llen);

            // check results
            check_loaded_keys("GPG", true, buf, buf_len, "keyid", {"2FCADF05FFA501BB"}, true);

            // cleanup
            rnp_output_destroy(armor_layer);
            rnp_output_destroy(output);
            rnp_key_handle_destroy(key);
        }

        // sub pub
        {
            // locate key
            key = NULL;
            assert_rnp_success(rnp_locate_key(ffi, "keyid", "54505A936A4A970E", &key));
            assert_non_null(key);

            // create output
            output = NULL;
            assert_rnp_success(rnp_output_to_memory(&output, 0));
            assert_non_null(output);
            assert_rnp_success(rnp_output_to_armor(output, &armor_layer, "public key"));
            assert_non_null(armor_layer);
            assert_rnp_success(rnp_output_armor_set_line_length(armor_layer, llen));

            // export
            assert_rnp_success(rnp_key_export(key, armor_layer, RNP_KEY_EXPORT_PUBLIC));
            assert_rnp_success(rnp_output_finish(armor_layer));

            // get output
            buf = NULL;
            assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
            assert_non_null(buf);
            std::string data = std::string(buf, buf + buf_len);
            auto        effective_llen = get_longest_line_length(data, lines_to_skip);
            assert_int_equal(llen / 4, effective_llen / 4);
            assert_true(llen >= effective_llen);

            // check results
            check_loaded_keys("GPG",
                              true,
                              buf,
                              buf_len,
                              "keyid",
                              {"2FCADF05FFA501BB", "54505A936A4A970E"},
                              false);

            // cleanup
            rnp_output_destroy(armor_layer);
            rnp_output_destroy(output);
            rnp_key_handle_destroy(key);
        }

        // sub sec
        {
            // locate key
            key = NULL;
            assert_rnp_success(rnp_locate_key(ffi, "keyid", "54505A936A4A970E", &key));
            assert_non_null(key);

            // create output
            output = NULL;
            assert_rnp_success(rnp_output_to_memory(&output, 0));
            assert_non_null(output);
            assert_rnp_success(rnp_output_to_armor(output, &armor_layer, "secret key"));
            assert_non_null(armor_layer);
            assert_rnp_success(rnp_output_armor_set_line_length(armor_layer, llen));

            // export
            assert_rnp_success(rnp_key_export(key, armor_layer, RNP_KEY_EXPORT_SECRET));
            assert_rnp_success(rnp_output_finish(armor_layer));

            // get output
            buf = NULL;
            assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_len, false));
            assert_non_null(buf);
            std::string data = std::string(buf, buf + buf_len);
            auto        effective_llen = get_longest_line_length(data, lines_to_skip);
            assert_int_equal(llen / 4, effective_llen / 4);
            assert_true(llen >= effective_llen);

            // check results
            check_loaded_keys("GPG",
                              true,
                              buf,
                              buf_len,
                              "keyid",
                              {"2FCADF05FFA501BB", "54505A936A4A970E"},
                              true);

            // cleanup
            rnp_output_destroy(armor_layer);
            rnp_output_destroy(output);
            rnp_key_handle_destroy(key);
        }
    }
    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_dump)
{
    rnp_ffi_t        ffi = NULL;
    rnp_key_handle_t key = NULL;
    char *           json = NULL;
    json_object *    jso = NULL;

    // setup FFI
    test_ffi_init(&ffi);

    // locate key
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "2FCADF05FFA501BB", &key));
    assert_non_null(key);

    // dump public key and check results
    assert_rnp_success(rnp_key_packets_to_json(
      key, false, RNP_JSON_DUMP_MPI | RNP_JSON_DUMP_RAW | RNP_JSON_DUMP_GRIP, &json));
    assert_non_null(json);
    jso = json_tokener_parse(json);
    assert_non_null(jso);
    assert_true(json_object_is_type(jso, json_type_array));
    json_object_put(jso);
    rnp_buffer_destroy(json);

    // dump secret key and check results
    assert_rnp_success(rnp_key_packets_to_json(
      key, true, RNP_JSON_DUMP_MPI | RNP_JSON_DUMP_RAW | RNP_JSON_DUMP_GRIP, &json));
    assert_non_null(json);
    jso = json_tokener_parse(json);
    assert_non_null(jso);
    assert_true(json_object_is_type(jso, json_type_array));
    json_object_put(jso);
    rnp_buffer_destroy(json);

    // cleanup
    rnp_key_handle_destroy(key);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_dump_edge_cases)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    /* secret key, stored on gpg card, with too large card serial len */
    rnp_input_t input = NULL;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/alice-s2k-101-2-card-len.pgp"));
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dump_packets_to_output(input, output, 0));
    rnp_input_destroy(input);
    uint8_t *buf = NULL;
    size_t   len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    std::string dstr(buf, buf + len);
    assert_true(
      dstr.find("card serial number: 0x000102030405060708090a0b0c0d0e0f (16 bytes)") !=
      std::string::npos);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/alice-s2k-101-2-card-len.pgp"));
    char *json = NULL;
    assert_rnp_success(rnp_dump_packets_to_json(input, 0, &json));
    rnp_input_destroy(input);
    dstr = json;
    assert_true(dstr.find("\"card serial number\":\"000102030405060708090a0b0c0d0e0f\"") !=
                std::string::npos);
    rnp_buffer_destroy(json);

    /* secret key, stored with unknown gpg s2k */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/alice-s2k-101-3.pgp"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dump_packets_to_output(input, output, 0));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    dstr = std::string(buf, buf + len);
    assert_true(dstr.find("Unknown experimental s2k: 0x474e5503 (4 bytes)") !=
                std::string::npos);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/alice-s2k-101-3.pgp"));
    assert_rnp_success(rnp_dump_packets_to_json(input, 0, &json));
    rnp_input_destroy(input);
    dstr = json;
    assert_true(dstr.find("\"unknown experimental\":\"474e5503\"") != std::string::npos);
    rnp_buffer_destroy(json);

    /* secret key, stored with unknown s2k */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/alice-s2k-101-unknown.pgp"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dump_packets_to_output(input, output, 0));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    dstr = std::string(buf, buf + len);
    assert_true(dstr.find("Unknown experimental s2k: 0x554e4b4e (4 bytes)") !=
                std::string::npos);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/alice-s2k-101-unknown.pgp"));
    assert_rnp_success(rnp_dump_packets_to_json(input, 0, &json));
    rnp_input_destroy(input);
    dstr = json;
    assert_true(dstr.find("\"unknown experimental\":\"554e4b4e\"") != std::string::npos);
    rnp_buffer_destroy(json);

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_userid_dump_has_no_special_chars)
{
    rnp_ffi_t    ffi = NULL;
    char *       json = NULL;
    json_object *jso = NULL;
    const char * trackers[] = {
      "userid\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f@rnp",
      "userid\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f@rnp"};
    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    for (int i = 0; i < 2; i++) {
        // generate RSA key
        rnp_op_generate_t keygen = NULL;
        assert_rnp_success(rnp_op_generate_create(&keygen, ffi, "RSA"));
        assert_rnp_success(rnp_op_generate_set_bits(keygen, 1024));
        // user id
        assert_rnp_success(rnp_op_generate_set_userid(keygen, trackers[0]));
        // now execute keygen operation
        assert_rnp_success(rnp_op_generate_execute(keygen));
        rnp_key_handle_t key = NULL;
        assert_rnp_success(rnp_op_generate_get_key(keygen, &key));
        assert_non_null(key);
        assert_rnp_success(rnp_op_generate_destroy(keygen));
        keygen = NULL;

        // dump public key and check results
        assert_rnp_success(rnp_key_packets_to_json(
          key, false, RNP_JSON_DUMP_MPI | RNP_JSON_DUMP_RAW | RNP_JSON_DUMP_GRIP, &json));
        assert_non_null(json);
        for (char c = 1; c < 0x20; c++) {
            if (c != '\n') {
                assert_null(strchr(json, c));
            }
        }
        jso = json_tokener_parse(json);
        assert_non_null(jso);
        assert_true(json_object_is_type(jso, json_type_array));
        json_object_put(jso);
        rnp_buffer_destroy(json);

        // cleanup
        rnp_key_handle_destroy(key);
    }
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_pkt_dump)
{
    rnp_ffi_t    ffi = NULL;
    rnp_input_t  input = NULL;
    char *       json = NULL;
    json_object *jso = NULL;

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    // setup input
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));

    // try with wrong parameters
    assert_rnp_failure(rnp_dump_packets_to_json(input, 0, NULL));
    assert_rnp_failure(rnp_dump_packets_to_json(NULL, 0, &json));
    assert_rnp_failure(rnp_dump_packets_to_json(input, 117, &json));
    // dump
    assert_rnp_success(rnp_dump_packets_to_json(
      input, RNP_JSON_DUMP_MPI | RNP_JSON_DUMP_RAW | RNP_JSON_DUMP_GRIP, &json));
    rnp_input_destroy(input);
    input = NULL;
    assert_non_null(json);

    // check results
    jso = json_tokener_parse(json);
    assert_non_null(jso);
    assert_true(json_object_is_type(jso, json_type_array));
    /* make sure that correct number of packets dumped */
    assert_int_equal(json_object_array_length(jso), 35);
    json_object_put(jso);
    rnp_buffer_destroy(json);

    // setup input and output
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));

    // try with wrong parameters
    assert_rnp_failure(rnp_dump_packets_to_output(input, NULL, 0));
    assert_rnp_failure(rnp_dump_packets_to_output(NULL, output, 0));
    assert_rnp_failure(rnp_dump_packets_to_output(input, output, 117));
    // dump
    assert_rnp_success(
      rnp_dump_packets_to_output(input, output, RNP_DUMP_MPI | RNP_DUMP_RAW | RNP_DUMP_GRIP));

    uint8_t *buf = NULL;
    size_t   len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    /* make sure output is not cut */
    assert_true(len > 45000);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    // dump data with marker packet
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.marker"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(
      rnp_dump_packets_to_output(input, output, RNP_DUMP_MPI | RNP_DUMP_RAW | RNP_DUMP_GRIP));
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    buf[len - 1] = '\0';
    assert_non_null(strstr((char *) buf, "contents: PGP"));
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    // dump data with marker packet to json
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.marker"));
    assert_rnp_success(rnp_dump_packets_to_json(
      input, RNP_JSON_DUMP_MPI | RNP_JSON_DUMP_RAW | RNP_JSON_DUMP_GRIP, &json));
    assert_non_null(strstr(json, "\"contents\":\"PGP\""));
    rnp_buffer_destroy(json);
    rnp_input_destroy(input);

    // dump data with malformed marker packet
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.marker.malf"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(
      rnp_dump_packets_to_output(input, output, RNP_DUMP_MPI | RNP_DUMP_RAW | RNP_DUMP_GRIP));
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    buf[len - 1] = '\0';
    assert_non_null(strstr((char *) buf, "contents: invalid"));
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    // dump data with malformed marker packet to json
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.marker.malf"));
    assert_rnp_success(rnp_dump_packets_to_json(
      input, RNP_JSON_DUMP_MPI | RNP_JSON_DUMP_RAW | RNP_JSON_DUMP_GRIP, &json));
    assert_non_null(strstr(json, "\"contents\":\"invalid\""));
    rnp_buffer_destroy(json);
    rnp_input_destroy(input);

    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_rsa_v3_dump)
{
    rnp_input_t input = NULL;
    char *      json = NULL;

    /* dump rsav3 key to json via FFI */
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/4/rsav3-p.asc"));
    assert_rnp_success(rnp_dump_packets_to_json(input, RNP_JSON_DUMP_GRIP, &json));
    rnp_input_destroy(input);
    /* parse dump */
    json_object *jso = json_tokener_parse(json);
    rnp_buffer_destroy(json);
    assert_non_null(jso);
    assert_true(json_object_is_type(jso, json_type_array));
    json_object *rsapkt = json_object_array_get_idx(jso, 0);
    assert_non_null(rsapkt);
    assert_true(json_object_is_type(rsapkt, json_type_object));
    /* check algorithm string */
    json_object *fld = NULL;
    assert_true(json_object_object_get_ex(rsapkt, "algorithm.str", &fld));
    assert_non_null(fld);
    const char *str = json_object_get_string(fld);
    assert_non_null(str);
    assert_string_equal(str, "RSA (Encrypt or Sign)");
    /* check fingerprint */
    fld = NULL;
    assert_true(json_object_object_get_ex(rsapkt, "fingerprint", &fld));
    assert_non_null(fld);
    str = json_object_get_string(fld);
    assert_non_null(str);
    assert_string_equal(str, "06a044022bb5aa7991077466aeba2ce7");
    json_object_put(jso);
}

TEST_F(rnp_tests, test_ffi_load_userattr)
{
    rnp_ffi_t ffi = NULL;

    // init ffi and load key
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_true(load_keys_gpg(ffi, "data/test_stream_key_load/ecc-25519-photo-pub.asc"));
    // check userid 0 : ecc-25519
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "cc786278981b0728", &key));
    assert_non_null(key);
    size_t uid_count = 0;
    assert_rnp_success(rnp_key_get_uid_count(key, &uid_count));
    assert_int_equal(uid_count, 2);
    char *uid = NULL;
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_string_equal(uid, "ecc-25519");
    rnp_buffer_destroy(uid);
    // check userattr 1, must be text instead of binary JPEG data
    assert_rnp_success(rnp_key_get_uid_at(key, 1, &uid));
    assert_string_equal(uid, "(photo)");
    rnp_buffer_destroy(uid);
    assert_rnp_success(rnp_key_handle_destroy(key));
    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_revocations)
{
    rnp_ffi_t ffi = NULL;

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load key with revoked userid
    assert_true(load_keys_gpg(ffi, "data/test_stream_key_load/ecc-p256-revoked-uid.asc"));
    // check userid 0 : ecc-p256
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "ecc-p256", &key));
    assert_non_null(key);
    size_t uid_count = 0;
    assert_rnp_success(rnp_key_get_uid_count(key, &uid_count));
    assert_int_equal(uid_count, 2);
    char *uid = NULL;
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_string_equal(uid, "ecc-p256");
    rnp_buffer_destroy(uid);
    rnp_uid_handle_t uid_handle = NULL;
    assert_rnp_success(rnp_key_get_uid_handle_at(key, 0, &uid_handle));
    assert_non_null(uid_handle);
    bool revoked = true;
    assert_rnp_failure(rnp_uid_is_revoked(NULL, &revoked));
    assert_rnp_failure(rnp_uid_is_revoked(uid_handle, NULL));
    assert_rnp_success(rnp_uid_is_revoked(uid_handle, &revoked));
    assert_false(revoked);
    rnp_signature_handle_t sig = (rnp_signature_handle_t) 0xdeadbeef;
    assert_rnp_failure(rnp_uid_get_revocation_signature(NULL, &sig));
    assert_rnp_failure(rnp_uid_get_revocation_signature(uid_handle, NULL));
    assert_rnp_success(rnp_uid_get_revocation_signature(uid_handle, &sig));
    assert_null(sig);
    assert_rnp_success(rnp_uid_handle_destroy(uid_handle));
    // check userid 1: ecc-p256-revoked
    assert_rnp_success(rnp_key_get_uid_at(key, 1, &uid));
    assert_string_equal(uid, "ecc-p256-revoked");
    rnp_buffer_destroy(uid);
    assert_rnp_success(rnp_key_get_uid_handle_at(key, 1, &uid_handle));
    assert_non_null(uid_handle);
    assert_rnp_success(rnp_uid_is_revoked(uid_handle, &revoked));
    assert_true(revoked);
    assert_rnp_success(rnp_uid_get_revocation_signature(uid_handle, &sig));
    assert_non_null(sig);
    uint32_t creation = 0;
    assert_rnp_success(rnp_signature_get_creation(sig, &creation));
    assert_int_equal(creation, 1556630215);
    assert_rnp_success(rnp_signature_handle_destroy(sig));
    assert_rnp_success(rnp_uid_handle_destroy(uid_handle));
    assert_rnp_success(rnp_key_handle_destroy(key));

    // load key with revoked subkey
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_true(load_keys_gpg(ffi, "data/test_stream_key_load/ecc-p256-revoked-sub.asc"));
    // key is not revoked
    assert_rnp_success(rnp_locate_key(ffi, "userid", "ecc-p256", &key));
    assert_rnp_success(rnp_key_is_revoked(key, &revoked));
    assert_false(revoked);
    assert_rnp_failure(rnp_key_get_revocation_signature(NULL, &sig));
    assert_rnp_failure(rnp_key_get_revocation_signature(key, NULL));
    assert_rnp_success(rnp_key_get_revocation_signature(key, &sig));
    assert_null(sig);
    bool valid = false;
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_true(valid);
    uint32_t till = 0;
    assert_rnp_success(rnp_key_valid_till(key, &till));
    assert_int_equal(till, 0xFFFFFFFF);
    assert_rnp_success(rnp_key_handle_destroy(key));
    // subkey is revoked
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "37E285E9E9851491", &key));
    assert_rnp_success(rnp_key_is_revoked(key, &revoked));
    assert_true(revoked);
    char *reason = NULL;
    assert_rnp_success(rnp_key_get_revocation_reason(key, &reason));
    assert_string_equal(reason, "Subkey revocation test.");
    rnp_buffer_destroy(reason);
    assert_rnp_success(rnp_key_is_superseded(key, &revoked));
    assert_false(revoked);
    assert_rnp_success(rnp_key_is_compromised(key, &revoked));
    assert_true(revoked);
    assert_rnp_success(rnp_key_is_retired(key, &revoked));
    assert_false(revoked);
    assert_rnp_success(rnp_key_get_revocation_signature(key, &sig));
    assert_non_null(sig);
    assert_rnp_success(rnp_signature_get_creation(sig, &creation));
    assert_int_equal(creation, 1556630749);
    assert_rnp_success(rnp_signature_handle_destroy(sig));
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_false(valid);
    assert_rnp_success(rnp_key_valid_till(key, &till));
    assert_int_equal(till, 0);
    assert_rnp_success(rnp_key_handle_destroy(key));

    // load revoked key
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_true(load_keys_gpg(ffi, "data/test_stream_key_load/ecc-p256-revoked-key.asc"));
    // key is revoked
    assert_rnp_success(rnp_locate_key(ffi, "userid", "ecc-p256", &key));
    assert_rnp_success(rnp_key_is_revoked(key, &revoked));
    assert_true(revoked);
    reason = NULL;
    assert_rnp_success(rnp_key_get_revocation_reason(key, &reason));
    assert_string_equal(reason, "Superseded key test.");
    rnp_buffer_destroy(reason);
    assert_rnp_success(rnp_key_is_superseded(key, &revoked));
    assert_true(revoked);
    assert_rnp_success(rnp_key_is_compromised(key, &revoked));
    assert_false(revoked);
    assert_rnp_success(rnp_key_is_retired(key, &revoked));
    assert_false(revoked);
    assert_rnp_success(rnp_key_get_revocation_signature(key, &sig));
    assert_non_null(sig);
    assert_rnp_success(rnp_signature_get_creation(sig, &creation));
    assert_int_equal(creation, 1556799806);
    assert_rnp_success(rnp_signature_handle_destroy(sig));
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_false(valid);
    assert_rnp_success(rnp_key_valid_till(key, &till));
    assert_int_equal(till, 1556799806);
    uint64_t till64 = 0;
    assert_rnp_success(rnp_key_valid_till64(key, &till64));
    assert_int_equal(till64, 1556799806);
    assert_rnp_success(rnp_key_handle_destroy(key));

    // cleanup
    rnp_ffi_destroy(ffi);
}

#define KEY_OUT_PATH "exported-key.asc"

TEST_F(rnp_tests, test_ffi_file_output)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load two keys
    assert_true(load_keys_gpg(ffi, "data/test_stream_key_load/ecc-p256-pub.asc"));
    assert_true(load_keys_gpg(ffi, "data/test_stream_key_load/ecc-p521-pub.asc"));

    rnp_key_handle_t k256 = NULL;
    rnp_key_handle_t k521 = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "ecc-p256", &k256));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "ecc-p521", &k521));

    rnp_output_t output = NULL;
    // test output to path - must overwrite if exists
    assert_rnp_success(rnp_output_to_path(&output, KEY_OUT_PATH));
    assert_rnp_success(rnp_key_export(
      k256, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_ARMORED | RNP_KEY_EXPORT_SUBKEYS));
    assert_rnp_success(rnp_output_destroy(output));
    assert_true(rnp_file_exists(KEY_OUT_PATH));
    off_t sz = file_size(KEY_OUT_PATH);
    assert_rnp_success(rnp_output_to_path(&output, KEY_OUT_PATH));
    assert_rnp_success(rnp_key_export(
      k521, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_ARMORED | RNP_KEY_EXPORT_SUBKEYS));
    assert_rnp_success(rnp_output_destroy(output));
    assert_true(rnp_file_exists(KEY_OUT_PATH));
    assert_true(sz != file_size(KEY_OUT_PATH));
    sz = file_size(KEY_OUT_PATH);
    // test output to file - will fail without overwrite
    assert_rnp_failure(rnp_output_to_file(&output, KEY_OUT_PATH, 0));
    // fail with wrong flags
    assert_rnp_failure(rnp_output_to_file(&output, KEY_OUT_PATH, 0x100));
    // test output to random file - will succeed on creation and export but fail on finish.
    assert_rnp_success(rnp_output_to_file(&output, KEY_OUT_PATH, RNP_OUTPUT_FILE_RANDOM));
    assert_true(file_size(KEY_OUT_PATH) == sz);
    assert_rnp_success(
      rnp_key_export(k256, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));
    assert_rnp_failure(rnp_output_finish(output));
    assert_rnp_success(rnp_output_destroy(output));
    // test output with random + overwrite - will succeed
    assert_rnp_success(rnp_output_to_file(
      &output, KEY_OUT_PATH, RNP_OUTPUT_FILE_RANDOM | RNP_OUTPUT_FILE_OVERWRITE));
    assert_true(file_size(KEY_OUT_PATH) == sz);
    assert_rnp_success(
      rnp_key_export(k256, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));
    assert_rnp_success(rnp_output_finish(output));
    assert_rnp_success(rnp_output_destroy(output));
    assert_true(file_size(KEY_OUT_PATH) != sz);
    sz = file_size(KEY_OUT_PATH);
    // test output with just overwrite - will succeed
    assert_rnp_success(rnp_output_to_file(&output, KEY_OUT_PATH, RNP_OUTPUT_FILE_OVERWRITE));
    assert_true(file_size(KEY_OUT_PATH) == 0);
    assert_rnp_success(
      rnp_key_export(k521, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));
    assert_rnp_success(rnp_output_finish(output));
    assert_rnp_success(rnp_output_destroy(output));
    assert_true(file_size(KEY_OUT_PATH) != sz);
    assert_int_equal(rnp_unlink(KEY_OUT_PATH), 0);
    // cleanup
    assert_rnp_success(rnp_key_handle_destroy(k256));
    assert_rnp_success(rnp_key_handle_destroy(k521));
    rnp_ffi_destroy(ffi);
}

static bool
check_import_keys_ex(rnp_ffi_t     ffi,
                     json_object **jso,
                     uint32_t      flags,
                     rnp_input_t   input,
                     size_t        rescount,
                     size_t        pubcount,
                     size_t        seccount)
{
    bool         res = false;
    char *       keys = NULL;
    size_t       keycount = 0;
    json_object *keyarr = NULL;
    *jso = NULL;

    if (rnp_import_keys(ffi, input, flags, &keys)) {
        goto done;
    }
    if (rnp_get_public_key_count(ffi, &keycount) || (keycount != pubcount)) {
        goto done;
    }
    if (rnp_get_secret_key_count(ffi, &keycount) || (keycount != seccount)) {
        goto done;
    }
    if (!keys) {
        goto done;
    }

    *jso = json_tokener_parse(keys);
    if (!jso) {
        goto done;
    }
    if (!json_object_is_type(*jso, json_type_object)) {
        goto done;
    }
    if (!json_object_object_get_ex(*jso, "keys", &keyarr)) {
        goto done;
    }
    if (!json_object_is_type(keyarr, json_type_array)) {
        goto done;
    }
    if (json_object_array_length(keyarr) != rescount) {
        goto done;
    }
    res = true;
done:
    if (!res) {
        json_object_put(*jso);
        *jso = NULL;
    }
    rnp_buffer_destroy(keys);
    return res;
}

static bool
check_import_keys(rnp_ffi_t     ffi,
                  json_object **jso,
                  const char *  keypath,
                  size_t        rescount,
                  size_t        pubcount,
                  size_t        seccount)
{
    rnp_input_t input = NULL;

    if (rnp_input_from_path(&input, keypath)) {
        return false;
    }
    bool res = check_import_keys_ex(ffi,
                                    jso,
                                    RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS,
                                    input,
                                    rescount,
                                    pubcount,
                                    seccount);
    rnp_input_destroy(input);
    return res;
}

static bool
check_key_status(
  json_object *jso, size_t idx, const char *pub, const char *sec, const char *fp)
{
    if (!jso) {
        return false;
    }
    if (!json_object_is_type(jso, json_type_object)) {
        return false;
    }
    json_object *keys = NULL;
    if (!json_object_object_get_ex(jso, "keys", &keys)) {
        return false;
    }
    if (!json_object_is_type(keys, json_type_array)) {
        return false;
    }
    json_object *key = json_object_array_get_idx(keys, idx);
    if (!json_object_is_type(key, json_type_object)) {
        return false;
    }
    json_object *fld = NULL;
    if (!json_object_object_get_ex(key, "public", &fld)) {
        return false;
    }
    if (strcmp(json_object_get_string(fld), pub) != 0) {
        return false;
    }
    if (!json_object_object_get_ex(key, "secret", &fld)) {
        return false;
    }
    if (strcmp(json_object_get_string(fld), sec) != 0) {
        return false;
    }
    if (!json_object_object_get_ex(key, "fingerprint", &fld)) {
        return false;
    }
    if (strcmp(json_object_get_string(fld), fp) != 0) {
        return false;
    }
    return true;
}

TEST_F(rnp_tests, test_ffi_keys_import)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // some edge cases
    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_key_merge/key-both.asc"));
    assert_rnp_failure(rnp_import_keys(NULL, input, RNP_LOAD_SAVE_PUBLIC_KEYS, NULL));
    assert_rnp_failure(rnp_import_keys(ffi, NULL, RNP_LOAD_SAVE_PUBLIC_KEYS, NULL));
    assert_rnp_failure(rnp_import_keys(ffi, input, 0, NULL));
    assert_rnp_failure(rnp_import_keys(ffi, input, 0x31, NULL));
    // load just public keys
    assert_rnp_success(rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, NULL));
    rnp_input_destroy(input);
    size_t keycount = 0;
    assert_rnp_success(rnp_get_public_key_count(ffi, &keycount));
    assert_int_equal(keycount, 3);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &keycount));
    assert_int_equal(keycount, 0);
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    // load just secret keys from pubkey file
    assert_true(import_sec_keys(ffi, "data/test_stream_key_merge/key-pub.asc"));
    assert_rnp_success(rnp_get_public_key_count(ffi, &keycount));
    assert_int_equal(keycount, 0);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &keycount));
    assert_int_equal(keycount, 0);
    // load both public and secret keys by specifying just secret (it will create pub part)
    assert_true(import_sec_keys(ffi, "data/test_stream_key_merge/key-sec.asc"));
    assert_rnp_success(rnp_get_public_key_count(ffi, &keycount));
    assert_int_equal(keycount, 3);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &keycount));
    assert_int_equal(keycount, 3);
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    // import just a public key without subkeys
    json_object *jso = NULL;
    assert_true(check_import_keys(
      ffi, &jso, "data/test_stream_key_merge/key-pub-just-key.pgp", 1, 1, 0));
    assert_true(
      check_key_status(jso, 0, "new", "none", "090bd712a1166be572252c3c9747d2a6b3a63124"));
    json_object_put(jso);
    // import just subkey 1
    assert_true(check_import_keys(
      ffi, &jso, "data/test_stream_key_merge/key-pub-just-subkey-1.pgp", 1, 2, 0));
    assert_true(
      check_key_status(jso, 0, "new", "none", "51b45a4c74917272e4e34180af1114a47f5f5b28"));
    json_object_put(jso);
    // import just subkey 2 without sigs
    assert_true(check_import_keys(
      ffi, &jso, "data/test_stream_key_merge/key-pub-just-subkey-2-no-sigs.pgp", 1, 3, 0));
    assert_true(
      check_key_status(jso, 0, "new", "none", "5fe514a54816e1b331686c2c16cd16f267ccdd4f"));
    json_object_put(jso);
    // import subkey 2 with sigs
    assert_true(check_import_keys(
      ffi, &jso, "data/test_stream_key_merge/key-pub-just-subkey-2.pgp", 1, 3, 0));
    assert_true(
      check_key_status(jso, 0, "updated", "none", "5fe514a54816e1b331686c2c16cd16f267ccdd4f"));
    json_object_put(jso);
    // import first uid
    assert_true(
      check_import_keys(ffi, &jso, "data/test_stream_key_merge/key-pub-uid-1.pgp", 1, 3, 0));
    assert_true(
      check_key_status(jso, 0, "updated", "none", "090bd712a1166be572252c3c9747d2a6b3a63124"));
    json_object_put(jso);
    // import the whole key
    assert_true(
      check_import_keys(ffi, &jso, "data/test_stream_key_merge/key-pub.pgp", 3, 3, 0));
    assert_true(
      check_key_status(jso, 0, "updated", "none", "090bd712a1166be572252c3c9747d2a6b3a63124"));
    assert_true(check_key_status(
      jso, 1, "unchanged", "none", "51b45a4c74917272e4e34180af1114a47f5f5b28"));
    assert_true(check_key_status(
      jso, 2, "unchanged", "none", "5fe514a54816e1b331686c2c16cd16f267ccdd4f"));
    json_object_put(jso);
    // import the first secret subkey
    assert_true(check_import_keys(
      ffi, &jso, "data/test_stream_key_merge/key-sec-just-subkey-1.pgp", 1, 3, 1));
    assert_true(check_key_status(
      jso, 0, "unchanged", "new", "51b45a4c74917272e4e34180af1114a47f5f5b28"));
    json_object_put(jso);
    // import the second secret subkey
    assert_true(check_import_keys(
      ffi, &jso, "data/test_stream_key_merge/key-sec-just-subkey-2-no-sigs.pgp", 1, 3, 2));
    assert_true(check_key_status(
      jso, 0, "unchanged", "new", "5fe514a54816e1b331686c2c16cd16f267ccdd4f"));
    json_object_put(jso);
    // import the whole secret key
    assert_true(
      check_import_keys(ffi, &jso, "data/test_stream_key_merge/key-sec.pgp", 3, 3, 3));
    assert_true(check_key_status(
      jso, 0, "unchanged", "new", "090bd712a1166be572252c3c9747d2a6b3a63124"));
    assert_true(check_key_status(
      jso, 1, "unchanged", "unchanged", "51b45a4c74917272e4e34180af1114a47f5f5b28"));
    assert_true(check_key_status(
      jso, 2, "unchanged", "unchanged", "5fe514a54816e1b331686c2c16cd16f267ccdd4f"));
    json_object_put(jso);
    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_malformed_keys_import)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    /* import keys with bad key0-uid0 certification, first without flag */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/pubring-malf-cert.pgp"));
    assert_rnp_failure(rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, NULL));
    rnp_input_destroy(input);
    size_t keycount = 255;
    assert_rnp_success(rnp_get_public_key_count(ffi, &keycount));
    assert_int_equal(keycount, 0);
    /* now try with RNP_LOAD_SAVE_PERMISSIVE */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/pubring-malf-cert.pgp"));
    assert_rnp_success(
      rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_PERMISSIVE, NULL));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_get_public_key_count(ffi, &keycount));
    assert_int_equal(keycount, 7);
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    assert_non_null(key);
    size_t uidcount = 255;
    assert_rnp_success(rnp_key_get_uid_count(key, &uidcount));
    assert_int_equal(uidcount, 3);
    size_t subcount = 255;
    assert_rnp_success(rnp_key_get_subkey_count(key, &subcount));
    assert_int_equal(subcount, 3);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "2fcadf05ffa501bb", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* import keys with bad key0-sub0 binding */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_rnp_success(rnp_get_public_key_count(ffi, &keycount));
    assert_int_equal(keycount, 0);
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/pubring-malf-key0-sub0-bind.pgp"));
    assert_rnp_success(
      rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_PERMISSIVE, NULL));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_get_public_key_count(ffi, &keycount));
    assert_int_equal(keycount, 7);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    assert_non_null(key);
    uidcount = 255;
    assert_rnp_success(rnp_key_get_uid_count(key, &uidcount));
    assert_int_equal(uidcount, 3);
    subcount = 255;
    assert_rnp_success(rnp_key_get_subkey_count(key, &subcount));
    assert_int_equal(subcount, 3);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "2fcadf05ffa501bb", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* import keys with bad key0-sub0 packet */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/pubring-malf-key0-sub0.pgp"));
    assert_rnp_success(
      rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_PERMISSIVE, NULL));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_get_public_key_count(ffi, &keycount));
    assert_int_equal(keycount, 6);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    assert_non_null(key);
    uidcount = 255;
    assert_rnp_success(rnp_key_get_uid_count(key, &uidcount));
    assert_int_equal(uidcount, 3);
    subcount = 255;
    assert_rnp_success(rnp_key_get_subkey_count(key, &subcount));
    assert_int_equal(subcount, 2);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "2fcadf05ffa501bb", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* import keys with bad key0 packet */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/pubring-malf-key0.pgp"));
    assert_rnp_success(
      rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_PERMISSIVE, NULL));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_get_public_key_count(ffi, &keycount));
    assert_int_equal(keycount, 3);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    assert_null(key);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "2fcadf05ffa501bb", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* import secret keys with bad key1 packet - public should be added as well */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/secring-malf-key1.pgp"));
    assert_rnp_success(
      rnp_import_keys(ffi, input, RNP_LOAD_SAVE_SECRET_KEYS | RNP_LOAD_SAVE_PERMISSIVE, NULL));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_get_public_key_count(ffi, &keycount));
    assert_int_equal(keycount, 7);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &keycount));
    assert_int_equal(keycount, 4);

    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    assert_non_null(key);
    bool secret = false;
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "326ef111425d14a5", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_false(secret);
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* import secret keys with bad key0 packet */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/secring-malf-key0.pgp"));
    assert_rnp_success(
      rnp_import_keys(ffi, input, RNP_LOAD_SAVE_SECRET_KEYS | RNP_LOAD_SAVE_PERMISSIVE, NULL));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_get_public_key_count(ffi, &keycount));
    assert_int_equal(keycount, 7);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &keycount));
    assert_int_equal(keycount, 7);

    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "key1-uid2", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "326ef111425d14a5", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    assert_rnp_success(rnp_key_handle_destroy(key));

    /* cleanup */
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_iterated_key_import)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;
    uint32_t    flags =
      RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS | RNP_LOAD_SAVE_SINGLE;

    /* two primary keys with attached subkeys in binary keyring */
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    json_object *jso = NULL;
    assert_true(check_import_keys_ex(ffi, &jso, flags, input, 4, 4, 0));
    assert_true(
      check_key_status(jso, 0, "new", "none", "e95a3cbf583aa80a2ccc53aa7bc6709b15c23a4a"));
    assert_true(
      check_key_status(jso, 1, "new", "none", "e332b27caf4742a11baa677f1ed63ee56fadc34d"));
    assert_true(
      check_key_status(jso, 2, "new", "none", "c5b15209940a7816a7af3fb51d7e8a5393c997a8"));
    assert_true(
      check_key_status(jso, 3, "new", "none", "5cd46d2a0bd0b8cfe0b130ae8a05b89fad5aded1"));
    json_object_put(jso);

    assert_true(check_import_keys_ex(ffi, &jso, flags, input, 3, 7, 0));
    assert_true(
      check_key_status(jso, 0, "new", "none", "be1c4ab951f4c2f6b604c7f82fcadf05ffa501bb"));
    assert_true(
      check_key_status(jso, 1, "new", "none", "a3e94de61a8cb229413d348e54505a936a4a970e"));
    assert_true(
      check_key_status(jso, 2, "new", "none", "57f8ed6e5c197db63c60ffaf326ef111425d14a5"));
    json_object_put(jso);

    char *results = NULL;
    assert_int_equal(RNP_ERROR_EOF, rnp_import_keys(ffi, input, flags, &results));
    assert_null(results);
    rnp_input_destroy(input);

    /* public + secret key, armored separately */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_key_merge/key-both.asc"));
    assert_true(check_import_keys_ex(ffi, &jso, flags, input, 3, 3, 0));
    assert_true(
      check_key_status(jso, 0, "new", "none", "090bd712a1166be572252c3c9747d2a6b3a63124"));
    assert_true(
      check_key_status(jso, 1, "new", "none", "51b45a4c74917272e4e34180af1114a47f5f5b28"));
    assert_true(
      check_key_status(jso, 2, "new", "none", "5fe514a54816e1b331686c2c16cd16f267ccdd4f"));
    json_object_put(jso);

    assert_true(check_import_keys_ex(ffi, &jso, flags, input, 3, 3, 3));
    assert_true(check_key_status(
      jso, 0, "unchanged", "new", "090bd712a1166be572252c3c9747d2a6b3a63124"));
    assert_true(check_key_status(
      jso, 1, "unchanged", "new", "51b45a4c74917272e4e34180af1114a47f5f5b28"));
    assert_true(check_key_status(
      jso, 2, "unchanged", "new", "5fe514a54816e1b331686c2c16cd16f267ccdd4f"));
    json_object_put(jso);

    assert_int_equal(RNP_ERROR_EOF, rnp_import_keys(ffi, input, flags, &results));
    assert_null(results);
    rnp_input_destroy(input);

    /* public keyring, enarmored */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg.asc"));
    flags |= RNP_LOAD_SAVE_PERMISSIVE;
    assert_true(check_import_keys_ex(ffi, &jso, flags, input, 4, 4, 0));
    assert_true(
      check_key_status(jso, 0, "new", "none", "e95a3cbf583aa80a2ccc53aa7bc6709b15c23a4a"));
    assert_true(
      check_key_status(jso, 1, "new", "none", "e332b27caf4742a11baa677f1ed63ee56fadc34d"));
    assert_true(
      check_key_status(jso, 2, "new", "none", "c5b15209940a7816a7af3fb51d7e8a5393c997a8"));
    assert_true(
      check_key_status(jso, 3, "new", "none", "5cd46d2a0bd0b8cfe0b130ae8a05b89fad5aded1"));
    json_object_put(jso);

    assert_true(check_import_keys_ex(ffi, &jso, flags, input, 3, 7, 0));
    assert_true(
      check_key_status(jso, 0, "new", "none", "be1c4ab951f4c2f6b604c7f82fcadf05ffa501bb"));
    assert_true(
      check_key_status(jso, 1, "new", "none", "a3e94de61a8cb229413d348e54505a936a4a970e"));
    assert_true(
      check_key_status(jso, 2, "new", "none", "57f8ed6e5c197db63c60ffaf326ef111425d14a5"));
    json_object_put(jso);

    results = NULL;
    assert_int_equal(RNP_ERROR_EOF, rnp_import_keys(ffi, input, flags, &results));
    assert_null(results);
    rnp_input_destroy(input);

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_stripped_keys_import)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    /* load stripped key as keyring */
    assert_true(load_keys_gpg(ffi, "data/test_key_validity/case8/pubring.gpg"));
    /* validate signatures - must succeed */
    rnp_op_verify_t verify = NULL;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_validity/case8/message.txt.asc"));
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_op_verify_signature_t sig;
    /* signature 1 - by primary key */
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 0, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    /* signature 2 - by subkey */
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 1, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    rnp_op_verify_destroy(verify);

    /* load stripped key by parts via import */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/case8/primary.pgp"));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/case8/subkey.pgp"));
    /* validate signatures - must be valid */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_validity/case8/message.txt.asc"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    /* signature 1 - by primary key */
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 0, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    /* signature 2 - by subkey */
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 1, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    rnp_op_verify_destroy(verify);

    /* load stripped key with subkey first */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/case8/subkey.pgp"));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/case8/primary.pgp"));
    /* validate signatures - must be valid */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_validity/case8/message.txt.asc"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    /* signature 1 - by primary key */
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 0, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    /* signature 2 - by subkey */
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 1, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    rnp_op_verify_destroy(verify);

    /* load stripped key without subkey binding */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/case8/primary.pgp"));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/case8/subkey-no-sig.pgp"));
    /* validate signatures - must be invalid */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_validity/case8/message.txt.asc"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_int_equal(rnp_op_verify_execute(verify), RNP_ERROR_SIGNATURE_INVALID);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    /* signature 1 - by primary key */
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 0, &sig));
    assert_int_equal(rnp_op_verify_signature_get_status(sig), RNP_ERROR_SIGNATURE_INVALID);
    /* signature 2 - by subkey */
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 1, &sig));
    assert_int_equal(rnp_op_verify_signature_get_status(sig), RNP_ERROR_SIGNATURE_INVALID);
    rnp_op_verify_destroy(verify);

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_elgamal4096)
{
    rnp_ffi_t ffi = NULL;

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    /* load public key */
    json_object *jso = NULL;
    assert_true(
      check_import_keys(ffi, &jso, "data/test_key_edge_cases/key-eg-4096-pub.pgp", 2, 2, 0));
    assert_true(
      check_key_status(jso, 0, "new", "none", "6541db10cdfcdba89db2dffea8f0408eb3369d8e"));
    assert_true(
      check_key_status(jso, 1, "new", "none", "c402a09b74acd0c11efc0527a3d630b457a0b15b"));
    json_object_put(jso);
    /* load secret key */
    assert_true(
      check_import_keys(ffi, &jso, "data/test_key_edge_cases/key-eg-4096-sec.pgp", 2, 2, 2));
    assert_true(check_key_status(
      jso, 0, "unchanged", "new", "6541db10cdfcdba89db2dffea8f0408eb3369d8e"));
    assert_true(check_key_status(
      jso, 1, "unchanged", "new", "c402a09b74acd0c11efc0527a3d630b457a0b15b"));
    json_object_put(jso);
    // cleanup
    rnp_ffi_destroy(ffi);
}

/* shrink the length to 1 packet
 * set packet length type as PGP_PTAG_OLD_LEN_1 and remove one octet from length header
 */
static std::vector<uint8_t>
shrink_len_2_to_1(const std::vector<uint8_t> &src)
{
    std::vector<uint8_t> dst = std::vector<uint8_t>();
    dst.reserve(src.size() - 1);
    dst.insert(dst.end(),
               PGP_PTAG_ALWAYS_SET | (PGP_PKT_PUBLIC_KEY << PGP_PTAG_OF_CONTENT_TAG_SHIFT) |
                 PGP_PTAG_OLD_LEN_1);
    // make sure the most significant octet of 2-octet length is actually zero
    assert_int_equal(src[1], 0);
    dst.insert(dst.end(), src[2]);
    dst.insert(dst.end(), src.begin() + 3, src.end());
    return dst;
}

/*
 * fake a packet with len = 0xEEEE
 */
static std::vector<uint8_t>
fake_len_EEEE(const std::vector<uint8_t> &src)
{
    std::vector<uint8_t> dst = std::vector<uint8_t>(src);
    dst[1] = 0xEE;
    dst[2] = 0xEE;
    return dst;
}

/*
 * fake a packet with len = 0x00
 */
static std::vector<uint8_t>
fake_len_0(const std::vector<uint8_t> &src)
{
    std::vector<uint8_t> dst = shrink_len_2_to_1(src);
    // erase subsequent octets for the packet to correspond the length
    uint8_t old_length = dst[1];
    dst.erase(dst.begin() + 2, dst.begin() + 2 + old_length);
    dst[1] = 0;
    return dst;
}

/* extend the length to 4 octets (preserving the value)
 * set packet length type as PGP_PTAG_OLD_LEN_4 and set 4 octet length instead of 2
 */
static std::vector<uint8_t>
extend_len_2_to_4(const std::vector<uint8_t> &src)
{
    std::vector<uint8_t> dst = std::vector<uint8_t>();
    dst.reserve(src.size() + 2);
    dst.insert(dst.end(), src.begin(), src.begin() + 3);
    dst[0] &= ~PGP_PTAG_OF_LENGTH_TYPE_MASK;
    dst[0] |= PGP_PTAG_OLD_LEN_4;
    dst.insert(dst.begin() + 1, 2, 0);
    dst.insert(dst.end(), src.begin() + 3, src.end());
    return dst;
}

static bool
import_public_keys_from_vector(std::vector<uint8_t> keyring)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    bool res = import_pub_keys(ffi, &keyring[0], keyring.size());
    rnp_ffi_destroy(ffi);
    return res;
}

TEST_F(rnp_tests, test_ffi_import_keys_check_pktlen)
{
    std::vector<uint8_t> keyring = file_to_vec("data/keyrings/2/pubring.gpg");
    // check tag
    // we are assuming that original key uses old format and packet length type is
    // PGP_PTAG_OLD_LEN_2
    assert_true(keyring.size() >= 5);
    uint8_t expected_tag = PGP_PTAG_ALWAYS_SET |
                           (PGP_PKT_PUBLIC_KEY << PGP_PTAG_OF_CONTENT_TAG_SHIFT) |
                           PGP_PTAG_OLD_LEN_2;
    assert_int_equal(expected_tag, 0x99);
    assert_int_equal(keyring[0], expected_tag);
    // original file can be loaded correctly
    assert_true(import_public_keys_from_vector(keyring));
    {
        // Shrink the packet length to 1 octet
        std::vector<uint8_t> keyring_valid_1 = shrink_len_2_to_1(keyring);
        assert_int_equal(keyring_valid_1.size(), keyring.size() - 1);
        assert_true(import_public_keys_from_vector(keyring_valid_1));
    }
    {
        // get invalid key with length 0
        std::vector<uint8_t> keyring_invalid_0 = fake_len_0(keyring);
        assert_false(import_public_keys_from_vector(keyring_invalid_0));
    }
    {
        // get invalid key with length 0xEEEE
        std::vector<uint8_t> keyring_invalid_EEEE = fake_len_EEEE(keyring);
        assert_int_equal(keyring_invalid_EEEE.size(), keyring.size());
        assert_false(import_public_keys_from_vector(keyring_invalid_EEEE));
    }
    {
        std::vector<uint8_t> keyring_len_4 = extend_len_2_to_4(keyring);
        assert_int_equal(keyring_len_4.size(), keyring.size() + 2);
        assert_true(import_public_keys_from_vector(keyring_len_4));
        // get invalid key with length 0xEEEEEEEE
        keyring_len_4[1] = 0xEE;
        keyring_len_4[2] = 0xEE;
        keyring_len_4[3] = 0xEE;
        keyring_len_4[4] = 0xEE;
        assert_false(import_public_keys_from_vector(keyring_len_4));
    }
}

TEST_F(rnp_tests, test_ffi_calculate_iterations)
{
    size_t iterations = 0;
    assert_rnp_success(rnp_calculate_iterations("SHA256", 500, &iterations));
    assert_true(iterations > 65536);
}

static bool
check_features(const char *type, const char *json, size_t count)
{
    json_object *features = json_tokener_parse(json);
    if (!features) {
        return false;
    }
    bool res = false;
    if (!json_object_is_type(features, json_type_array)) {
        goto done;
    }
    if ((size_t) json_object_array_length(features) != count) {
        RNP_LOG("wrong feature count for %s", type);
        goto done;
    }
    for (size_t i = 0; i < count; i++) {
        json_object *val = json_object_array_get_idx(features, i);
        const char * str = json_object_get_string(val);
        bool         supported = false;
        if (!str || rnp_supports_feature(type, str, &supported) || !supported) {
            goto done;
        }
    }

    res = true;
done:
    json_object_put(features);
    return res;
}

TEST_F(rnp_tests, test_ffi_supported_features)
{
    char *features = NULL;
    /* some edge cases */
    assert_rnp_failure(rnp_supported_features(NULL, &features));
    assert_rnp_failure(rnp_supported_features("something", NULL));
    assert_rnp_failure(rnp_supported_features(RNP_FEATURE_SYMM_ALG, NULL));
    assert_rnp_failure(rnp_supported_features("something", &features));
    /* symmetric algorithms */
    assert_rnp_success(rnp_supported_features("Symmetric Algorithm", &features));
    assert_non_null(features);
    assert_true(check_features(RNP_FEATURE_SYMM_ALG, features, 12));
    rnp_buffer_destroy(features);
    bool supported = false;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "IDEA", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "TRIPLEDES", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "CAST5", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "BLOWFISH", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "AES128", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "AES192", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "AES256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "TWOFISH", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "CAMELLIA128", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "CAMELLIA192", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "CAMELLIA256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "SM4", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "idea", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "tripledes", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "cast5", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "blowfish", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "aes128", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "aes192", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "aes256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "twofish", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "camellia128", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "camellia192", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "camellia256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "sm4", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "wrong", &supported));
    assert_false(supported);
    /* aead algorithms */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_AEAD_ALG, &features));
    assert_non_null(features);
    assert_true(check_features(RNP_FEATURE_AEAD_ALG, features, 2));
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_AEAD_ALG, "eax", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_AEAD_ALG, "ocb", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_AEAD_ALG, "wrong", &supported));
    assert_false(supported);
    /* protection mode */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_PROT_MODE, &features));
    assert_non_null(features);
    assert_true(check_features(RNP_FEATURE_PROT_MODE, features, 1));
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PROT_MODE, "cfb", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PROT_MODE, "wrong", &supported));
    assert_false(supported);
    /* public key algorithm */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_PK_ALG, &features));
    assert_non_null(features);
    assert_true(check_features(RNP_FEATURE_PK_ALG, features, 7));
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "RSA", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "DSA", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "ELGAMAL", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "ECDSA", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "ECDH", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "EDDSA", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "SM2", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "rsa", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "dsa", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "elgamal", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "ecdsa", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "ecdh", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "eddsa", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "sm2", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "wrong", &supported));
    assert_false(supported);
    /* hash algorithm */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_HASH_ALG, &features));
    assert_non_null(features);
    assert_true(check_features(RNP_FEATURE_HASH_ALG, features, 10));
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "MD5", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "SHA1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "RIPEMD160", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "SHA256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "SHA384", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "SHA512", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "SHA224", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "SHA3-256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "SHA3-512", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "SM3", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "md5", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "sha1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "ripemd160", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "sha256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "sha384", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "sha512", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "sha224", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "sha3-256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "sha3-512", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "sm3", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "wrong", &supported));
    assert_false(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "CRC24", &supported));
    assert_false(supported);
    /* compression algorithm */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_COMP_ALG, &features));
    assert_non_null(features);
    assert_true(check_features(RNP_FEATURE_COMP_ALG, features, 4));
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_COMP_ALG, "Uncompressed", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_COMP_ALG, "Zlib", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_COMP_ALG, "ZIP", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_COMP_ALG, "BZIP2", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_COMP_ALG, "wrong", &supported));
    assert_false(supported);
    /* elliptic curve */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_CURVE, &features));
    assert_non_null(features);
    assert_true(check_features(RNP_FEATURE_CURVE, features, 10));
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "NIST P-256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "NIST P-384", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "NIST P-521", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "ed25519", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "curve25519", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP256r1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP384r1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP512r1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "secp256k1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "SM2 P-256", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "wrong", &supported));
    assert_false(supported);
}

TEST_F(rnp_tests, test_ffi_enable_debug)
{
    assert_rnp_success(rnp_enable_debug("dummy.c"));
    assert_rnp_success(rnp_enable_debug("1.c"));
    assert_true(rnp_get_debug("dummy.c"));
    assert_true(rnp_get_debug("1.c"));
    assert_false(rnp_get_debug("dummy"));
    /* NULL enables debug for all sources */
    assert_rnp_success(rnp_enable_debug(NULL));
    assert_true(rnp_get_debug("anything"));
    assert_rnp_success(rnp_disable_debug());
    assert_false(rnp_get_debug("anything"));
    assert_false(rnp_get_debug("dummy.c"));
    assert_false(rnp_get_debug("1.c"));
    assert_rnp_success(rnp_enable_debug("all"));
    assert_true(rnp_get_debug("anything other"));
    /* need to clean it up afterwards - otherwise tests will go crazy */
    assert_rnp_success(rnp_disable_debug());
}

TEST_F(rnp_tests, test_ffi_rnp_key_get_primary_grip)
{
    rnp_ffi_t        ffi = NULL;
    rnp_key_handle_t key = NULL;
    char *           grip = NULL;

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_true(load_keys_gpg(ffi, "data/keyrings/1/pubring.gpg"));

    // locate primary key
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7BC6709B15C23A4A", &key));
    assert_non_null(key);

    // some edge cases
    assert_rnp_failure(rnp_key_get_primary_grip(NULL, NULL));
    assert_rnp_failure(rnp_key_get_primary_grip(NULL, &grip));
    assert_rnp_failure(rnp_key_get_primary_grip(key, NULL));
    assert_rnp_failure(rnp_key_get_primary_grip(key, &grip));
    assert_null(grip);
    rnp_key_handle_destroy(key);

    // locate subkey 1
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "1ED63EE56FADC34D", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_primary_grip(key, &grip));
    assert_non_null(grip);
    assert_string_equal(grip, "66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA");
    rnp_buffer_destroy(grip);
    grip = NULL;
    rnp_key_handle_destroy(key);

    // locate subkey 2
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "1D7E8A5393C997A8", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_primary_grip(key, &grip));
    assert_non_null(grip);
    assert_string_equal(grip, "66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA");
    rnp_buffer_destroy(grip);
    grip = NULL;
    rnp_key_handle_destroy(key);

    // locate subkey 3
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "8A05B89FAD5ADED1", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_primary_grip(key, &grip));
    assert_non_null(grip);
    assert_string_equal(grip, "66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA");
    rnp_buffer_destroy(grip);
    grip = NULL;
    rnp_key_handle_destroy(key);

    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_rnp_key_get_primary_fprint)
{
    rnp_ffi_t ffi = NULL;

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_true(load_keys_gpg(ffi, "data/keyrings/1/pubring.gpg"));

    // locate primary key
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7BC6709B15C23A4A", &key));
    assert_non_null(key);

    // some edge cases
    char *fp = NULL;
    assert_rnp_failure(rnp_key_get_primary_fprint(NULL, NULL));
    assert_rnp_failure(rnp_key_get_primary_fprint(NULL, &fp));
    assert_rnp_failure(rnp_key_get_primary_fprint(key, NULL));
    assert_rnp_failure(rnp_key_get_primary_fprint(key, &fp));
    assert_null(fp);
    rnp_key_handle_destroy(key);

    // locate subkey 1
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "1ED63EE56FADC34D", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_primary_fprint(key, &fp));
    assert_non_null(fp);
    assert_string_equal(fp, "E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A");
    rnp_buffer_destroy(fp);
    fp = NULL;
    rnp_key_handle_destroy(key);

    // locate subkey 2
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "1D7E8A5393C997A8", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_primary_fprint(key, &fp));
    assert_non_null(fp);
    assert_string_equal(fp, "E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A");
    rnp_buffer_destroy(fp);
    fp = NULL;
    rnp_key_handle_destroy(key);

    // locate subkey 3
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "8A05B89FAD5ADED1", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_primary_fprint(key, &fp));
    assert_non_null(fp);
    assert_string_equal(fp, "E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A");
    rnp_buffer_destroy(fp);
    fp = NULL;
    rnp_key_handle_destroy(key);

    // locate key 1 - subkey 0
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "54505A936A4A970E", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_primary_fprint(key, &fp));
    assert_non_null(fp);
    assert_string_equal(fp, "BE1C4AB951F4C2F6B604C7F82FCADF05FFA501BB");
    rnp_buffer_destroy(fp);
    fp = NULL;
    rnp_key_handle_destroy(key);

    // locate key 2 - subkey 1
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "326EF111425D14A5", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_primary_fprint(key, &fp));
    assert_non_null(fp);
    assert_string_equal(fp, "BE1C4AB951F4C2F6B604C7F82FCADF05FFA501BB");
    rnp_buffer_destroy(fp);
    fp = NULL;
    rnp_key_handle_destroy(key);

    // cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_output_to_armor)
{
    rnp_ffi_t    ffi = NULL;
    rnp_output_t memory = NULL;
    rnp_output_t armor = NULL;
    rnp_input_t  input = NULL;

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_true(load_keys_gpg(ffi, "data/keyrings/1/pubring.gpg"));

    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "2FCADF05FFA501BB", &key));
    assert_non_null(key);

    assert_rnp_success(rnp_output_to_memory(&memory, 0));
    /* some edge cases */
    assert_rnp_failure(rnp_output_to_armor(NULL, &armor, "message"));
    assert_null(armor);
    assert_rnp_failure(rnp_output_to_armor(memory, NULL, "message"));
    assert_null(armor);
    assert_rnp_failure(rnp_output_to_armor(memory, &armor, "wrong"));
    assert_null(armor);
    /* export raw key to armored stream with 'message' header */
    assert_rnp_success(rnp_output_to_armor(memory, &armor, "message"));
    assert_rnp_success(rnp_key_export(key, armor, RNP_KEY_EXPORT_PUBLIC));
    assert_rnp_success(rnp_output_destroy(armor));
    uint8_t *buf = NULL;
    size_t   buf_len = 0;
    /* check contents to make sure it is correct armored stream */
    assert_rnp_success(rnp_output_memory_get_buf(memory, &buf, &buf_len, false));
    assert_non_null(buf);
    const char *hdr = "-----BEGIN PGP MESSAGE-----";
    assert_true(buf_len > strlen(hdr));
    assert_int_equal(strncmp((char *) buf, hdr, strlen(hdr)), 0);
    assert_rnp_success(rnp_input_from_memory(&input, buf, buf_len, false));
    rnp_output_t memory2 = NULL;
    assert_rnp_success(rnp_output_to_memory(&memory2, 0));
    assert_rnp_success(rnp_dearmor(input, memory2));
    rnp_output_destroy(memory2);
    rnp_input_destroy(input);

    rnp_key_handle_destroy(key);
    rnp_output_destroy(memory);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_rnp_guess_contents)
{
    char *      msgt = NULL;
    rnp_input_t input = NULL;
    assert_rnp_failure(rnp_guess_contents(NULL, &msgt));

    assert_rnp_success(
      rnp_input_from_path(&input, "data/issue1188/armored_revocation_signature.pgp"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_int_equal(strcmp(msgt, "signature"), 0);
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_key_merge/key-pub.pgp"));
    assert_rnp_failure(rnp_guess_contents(input, NULL));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_string_equal(msgt, "public key");
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_key_merge/key-pub-just-subkey-1.pgp"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_string_equal(msgt, "public key");
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_key_merge/key-pub.asc"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_string_equal(msgt, "public key");
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_key_merge/key-sec.pgp"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_string_equal(msgt, "secret key");
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_key_merge/key-sec.asc"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_string_equal(msgt, "secret key");
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_key_merge/key-sec-just-subkey-1.pgp"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_string_equal(msgt, "secret key");
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_z/128mb.zip"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_string_equal(msgt, "message");
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_z/4gb.bzip2.asc"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_string_equal(msgt, "message");
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_signatures/source.txt.sig"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_string_equal(msgt, "signature");
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_signatures/source.txt.sig.asc"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_string_equal(msgt, "signature");
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_signatures/source.txt.asc.asc"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_string_equal(msgt, "cleartext");
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_stream_signatures/source.txt"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_string_equal(msgt, "unknown");
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.marker"));
    assert_rnp_success(rnp_guess_contents(input, &msgt));
    assert_string_equal(msgt, "message");
    rnp_buffer_destroy(msgt);
    rnp_input_destroy(input);
}

TEST_F(rnp_tests, test_ffi_literal_filename)
{
    rnp_ffi_t     ffi = NULL;
    rnp_input_t   input = NULL;
    rnp_output_t  output = NULL;
    rnp_op_sign_t op = NULL;
    uint8_t *     signed_buf;
    size_t        signed_len;

    // init ffi
    test_ffi_init(&ffi);
    // init input
    test_ffi_init_sign_memory_input(&input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(&ffi, &op);
    // setup filename and modification time
    assert_rnp_success(rnp_op_sign_set_file_name(op, "checkleak.dat"));
    assert_rnp_success(rnp_op_sign_set_file_name(op, NULL));
    assert_rnp_success(rnp_op_sign_set_file_name(op, "testfile.dat"));
    assert_rnp_success(rnp_op_sign_set_file_mtime(op, 12345678));
    // execute the operation
    assert_rnp_success(rnp_op_sign_execute(op));
    // make sure the output file was created
    assert_rnp_success(rnp_output_memory_get_buf(output, &signed_buf, &signed_len, true));
    assert_non_null(signed_buf);
    assert_true(signed_len > 0);

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_op_sign_destroy(op));
    op = NULL;

    // check the resulting stream for correct name/time
    assert_rnp_success(rnp_input_from_memory(&input, signed_buf, signed_len, false));
    char *json = NULL;
    assert_rnp_success(rnp_dump_packets_to_json(input, 0, &json));
    assert_non_null(json);

    std::string jstr = json;
    assert_true(jstr.find("\"filename\":\"testfile.dat\"") != std::string::npos);
    assert_true(jstr.find("\"timestamp\":12345678") != std::string::npos);

    assert_rnp_success(rnp_input_destroy(input));
    rnp_buffer_destroy(signed_buf);
    rnp_buffer_destroy(json);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_op_set_hash)
{
    rnp_ffi_t     ffi = NULL;
    rnp_input_t   input = NULL;
    rnp_output_t  output = NULL;
    rnp_op_sign_t op = NULL;
    uint8_t *     signed_buf;
    size_t        signed_len;

    // init ffi
    test_ffi_init(&ffi);
    // init input
    test_ffi_init_sign_memory_input(&input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(&ffi, &op);
    // make sure it doesn't fail on NULL hash value
    assert_rnp_failure(rnp_op_sign_set_hash(op, NULL));
    assert_rnp_failure(rnp_op_sign_set_hash(op, "Unknown"));
    assert_rnp_success(rnp_op_sign_set_hash(op, "SHA256"));
    // execute the operation
    assert_rnp_success(rnp_op_sign_execute(op));
    // make sure the output file was created
    assert_rnp_success(rnp_output_memory_get_buf(output, &signed_buf, &signed_len, true));
    assert_non_null(signed_buf);
    assert_true(signed_len > 0);

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_output_destroy(output));
    assert_rnp_success(rnp_op_sign_destroy(op));

    rnp_buffer_destroy(signed_buf);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_op_set_compression)
{
    rnp_ffi_t     ffi = NULL;
    rnp_input_t   input = NULL;
    rnp_output_t  output = NULL;
    rnp_op_sign_t op = NULL;
    uint8_t *     signed_buf;
    size_t        signed_len;

    // init ffi
    test_ffi_init(&ffi);
    // init input
    test_ffi_init_sign_memory_input(&input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(&ffi, &op);
    // make sure it doesn't fail on NULL compression algorithm value
    assert_rnp_failure(rnp_op_sign_set_compression(op, NULL, 6));
    assert_rnp_failure(rnp_op_sign_set_compression(op, "Unknown", 6));
    assert_rnp_failure(rnp_op_sign_set_compression(NULL, "ZLib", 6));
    assert_rnp_success(rnp_op_sign_set_compression(op, "ZLib", 6));
    // execute the operation
    assert_rnp_success(rnp_op_sign_execute(op));
    // make sure the output file was created
    assert_rnp_success(rnp_output_memory_get_buf(output, &signed_buf, &signed_len, true));
    assert_non_null(signed_buf);
    assert_true(signed_len > 0);

    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_output_destroy(output));
    assert_rnp_success(rnp_op_sign_destroy(op));

    rnp_buffer_destroy(signed_buf);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_aead_params)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *plaintext = "Some data to encrypt using the AEAD-EAX and AEAD-OCB encryption.";

    // setup FFI
    test_ffi_init(&ffi);

    // write out some data
    FILE *fp = fopen("plaintext", "wb");
    assert_non_null(fp);
    assert_int_equal(1, fwrite(plaintext, strlen(plaintext), 1, fp));
    assert_int_equal(0, fclose(fp));

    // create input+output
    assert_rnp_success(rnp_input_from_path(&input, "plaintext"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "encrypted"));
    assert_non_null(output);
    // create encrypt operation
    assert_rnp_success(rnp_op_encrypt_create(&op, ffi, input, output));
    // setup AEAD params
    assert_rnp_success(rnp_op_encrypt_set_aead(op, "OCB"));
    assert_rnp_failure(rnp_op_encrypt_set_aead_bits(op, -1));
    assert_rnp_failure(rnp_op_encrypt_set_aead_bits(op, 60));
    assert_rnp_success(rnp_op_encrypt_set_aead_bits(op, 10));
    // add password (using all defaults)
    assert_rnp_success(rnp_op_encrypt_add_password(op, "pass1", NULL, 0, NULL));
    // execute the operation
    assert_rnp_success(rnp_op_encrypt_execute(op));
    // make sure the output file was created
    assert_true(rnp_file_exists("encrypted"));
    // cleanup
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_op_encrypt_destroy(op));
    op = NULL;

    // list packets
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    char *json = NULL;
    assert_rnp_success(rnp_dump_packets_to_json(input, 0, &json));
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    json_object *jso = json_tokener_parse(json);
    rnp_buffer_destroy(json);
    assert_non_null(jso);
    assert_true(json_object_is_type(jso, json_type_array));
    /* check the symmetric-key encrypted session key packet */
    json_object *pkt = json_object_array_get_idx(jso, 0);
    assert_true(check_json_pkt_type(pkt, PGP_PKT_SK_SESSION_KEY));
    assert_true(check_json_field_int(pkt, "version", 5));
    assert_true(check_json_field_str(pkt, "aead algorithm.str", "OCB"));
    /* check the aead-encrypted packet */
    pkt = json_object_array_get_idx(jso, 1);
    assert_true(check_json_pkt_type(pkt, PGP_PKT_AEAD_ENCRYPTED));
    assert_true(check_json_field_int(pkt, "version", 1));
    assert_true(check_json_field_str(pkt, "aead algorithm.str", "OCB"));
    assert_true(check_json_field_int(pkt, "chunk size", 10));
    json_object_put(jso);

    /* decrypt */
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "pass1"));
    assert_rnp_success(rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // compare the decrypted file
    assert_true(file_equals("decrypted", plaintext, strlen(plaintext)));
    rnp_unlink("decrypted");

    // final cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_detached_verify_input)
{
    rnp_ffi_t    ffi = NULL;
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    // init ffi
    test_ffi_init(&ffi);
    /* verify detached signature via rnp_op_verify_create - should not crash */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_stream_signatures/source.txt.sig"));
    assert_rnp_success(rnp_output_to_null(&output));
    rnp_op_verify_t verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_detached_cleartext_signed_input)
{
    rnp_ffi_t ffi = NULL;
    test_ffi_init(&ffi);
    /* verify detached signature with cleartext input - must fail */
    rnp_input_t inputmsg = NULL;
    assert_rnp_success(rnp_input_from_path(&inputmsg, "data/test_messages/message.txt"));
    rnp_input_t inputsig = NULL;
    assert_rnp_success(
      rnp_input_from_path(&inputsig, "data/test_messages/message.txt.cleartext-signed"));
    rnp_op_verify_t verify = NULL;
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, inputmsg, inputsig));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(inputmsg);
    rnp_input_destroy(inputsig);
    /* verify detached signature with signed/embedded input - must fail */
    assert_rnp_success(rnp_input_from_path(&inputmsg, "data/test_messages/message.txt"));
    assert_rnp_success(
      rnp_input_from_path(&inputsig, "data/test_messages/message.txt.empty.sig"));
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, inputmsg, inputsig));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(inputmsg);
    rnp_input_destroy(inputsig);
    /* verify detached signature as a whole message - must fail */
    assert_rnp_success(rnp_input_from_path(&inputmsg, "data/test_messages/message.txt.sig"));
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, inputmsg, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    rnp_op_verify_destroy(verify);
    rnp_output_destroy(output);
    rnp_input_destroy(inputmsg);

    rnp_ffi_destroy(ffi);
}

static bool
check_signature(rnp_op_verify_t op, size_t idx, rnp_result_t status)
{
    rnp_op_verify_signature_t sig = NULL;
    if (rnp_op_verify_get_signature_at(op, idx, &sig)) {
        return false;
    }
    return rnp_op_verify_signature_get_status(sig) == status;
}

TEST_F(rnp_tests, test_ffi_op_verify_sig_count)
{
    rnp_ffi_t    ffi = NULL;
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    // init ffi
    test_ffi_init(&ffi);

    /* signed message */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.signed"));
    assert_rnp_success(rnp_output_to_null(&output));
    rnp_op_verify_t verify = NULL;
    assert_rnp_failure(rnp_op_verify_create(NULL, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_create(&verify, NULL, input, output));
    assert_rnp_failure(rnp_op_verify_create(&verify, ffi, NULL, output));
    assert_rnp_failure(rnp_op_verify_create(&verify, ffi, input, NULL));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(NULL));
    assert_rnp_success(rnp_op_verify_execute(verify));
    size_t sigcount = 0;
    assert_rnp_failure(rnp_op_verify_get_signature_count(verify, NULL));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* signed with unknown key */
    sigcount = 255;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.signed.unknown"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_ERROR_KEY_NOT_FOUND));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* signed with malformed signature (bad version) */
    sigcount = 255;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.signed.malfsig"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 0);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* signed with invalid signature (modified hash alg) */
    sigcount = 255;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.signed.invsig"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_int_equal(rnp_op_verify_execute(verify), RNP_ERROR_SIGNATURE_INVALID);
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_ERROR_SIGNATURE_INVALID));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* signed without the signature */
    sigcount = 255;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.signed.nosig"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 0);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* detached signature */
    rnp_input_t source = NULL;
    sigcount = 255;
    assert_rnp_success(rnp_input_from_path(&source, "data/test_messages/message.txt"));
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.sig"));
    assert_rnp_failure(rnp_op_verify_detached_create(NULL, ffi, source, input));
    assert_rnp_failure(rnp_op_verify_detached_create(&verify, NULL, source, input));
    assert_rnp_failure(rnp_op_verify_detached_create(&verify, ffi, NULL, input));
    assert_rnp_failure(rnp_op_verify_detached_create(&verify, ffi, source, NULL));
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, source, input));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(source);
    rnp_input_destroy(input);

    /* detached text-mode signature */
    source = NULL;
    sigcount = 255;
    assert_rnp_success(rnp_input_from_path(&source, "data/test_messages/message.txt"));
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.sig-text"));
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, source, input));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(source);
    rnp_input_destroy(input);

    source = NULL;
    sigcount = 255;
    assert_rnp_success(rnp_input_from_path(&source, "data/test_messages/message.txt.crlf"));
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.sig-text"));
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, source, input));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(source);
    rnp_input_destroy(input);

    /* detached text-mode signature with trailing CR characters */
    source = NULL;
    sigcount = 255;
    assert_rnp_success(
      rnp_input_from_path(&source, "data/test_messages/message-trailing-cr.txt"));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message-trailing-cr.txt.sig-text"));
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, source, input));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(source);
    rnp_input_destroy(input);

    /* detached text-mode signature with CRLF on 32k boundary */
    source = NULL;
    sigcount = 255;
    assert_rnp_success(
      rnp_input_from_path(&source, "data/test_messages/message-32k-crlf.txt"));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message-32k-crlf.txt.sig"));
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, source, input));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(source);
    rnp_input_destroy(input);

    /* embedded text-mode signature with CRLF on 32k boundary */
    sigcount = 255;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message-32k-crlf.txt.gpg"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* malformed detached signature */
    sigcount = 255;
    assert_rnp_success(rnp_input_from_path(&source, "data/test_messages/message.txt"));
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.sig.malf"));
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, source, input));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 0);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(source);
    rnp_input_destroy(input);

    /* malformed detached signature, wrong bitlen in MPI  */
    sigcount = 255;
    assert_rnp_success(rnp_input_from_path(&source, "data/test_messages/message.txt"));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.sig.wrong-mpi-bitlen"));
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, source, input));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(source);
    rnp_input_destroy(input);

    /* encrypted message */
    sigcount = 255;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.encrypted"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 0);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* encrypted and signed message */
    sigcount = 255;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.signed-encrypted"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* cleartext signed message */
    sigcount = 255;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.cleartext-signed"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* cleartext signed with malformed signature (wrong mpi len) */
    sigcount = 255;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.cleartext-malf"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_int_equal(rnp_op_verify_execute(verify), RNP_ERROR_SIGNATURE_INVALID);
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_ERROR_SIGNATURE_INVALID));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* cleartext signed without the signature */
    sigcount = 255;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.cleartext-nosig"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 0);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* signed message without compression */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.signed-no-z"));
    assert_rnp_success(rnp_output_to_null(&output));
    verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    sigcount = 255;
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* signed message with one-pass with wrong version */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.signed-no-z-malf"));
    assert_rnp_success(rnp_output_to_null(&output));
    verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* encrypted and signed message with marker packet */
    sigcount = 255;
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.marker"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* encrypted and signed message with marker packet, armored */
    sigcount = 255;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.marker.asc"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* encrypted and signed message with malformed marker packet */
    sigcount = 255;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.marker.malf"));
    assert_rnp_success(rnp_output_to_null(&output));
    verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* signed message with key which is now expired */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    import_pub_keys(ffi, "data/test_messages/expired_signing_key-pub.asc");
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "30FC0D776915BA44", &key));
    uint64_t till = 0;
    assert_rnp_success(rnp_key_valid_till64(key, &till));
    assert_int_equal(till, 1623424417);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.signed-expired-key"));
    assert_rnp_success(rnp_output_to_null(&output));
    verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    sigcount = 255;
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* signed message with subkey which is now expired */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    import_pub_keys(ffi, "data/test_messages/expired_signing_sub-pub.asc");
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "D93A47FD93191FD1", &key));
    till = 0;
    assert_rnp_success(rnp_key_valid_till64(key, &till));
    assert_int_equal(till, 1623933507);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.signed-expired-sub"));
    assert_rnp_success(rnp_output_to_null(&output));
    verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    sigcount = 255;
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sigcount));
    assert_int_equal(sigcount, 1);
    assert_true(check_signature(verify, 0, RNP_SUCCESS));
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_op_verify_get_protection_info)
{
    rnp_ffi_t    ffi = NULL;
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    // init ffi
    test_ffi_init(&ffi);
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));

    /* message just signed */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.signed"));
    assert_rnp_success(rnp_output_to_null(&output));
    rnp_op_verify_t verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    char *mode = NULL;
    char *cipher = NULL;
    bool  valid = true;
    assert_rnp_failure(rnp_op_verify_get_protection_info(NULL, &mode, &cipher, &valid));
    assert_rnp_success(rnp_op_verify_get_protection_info(verify, &mode, NULL, NULL));
    assert_string_equal(mode, "none");
    rnp_buffer_destroy(mode);
    assert_rnp_success(rnp_op_verify_get_protection_info(verify, NULL, &cipher, NULL));
    assert_string_equal(cipher, "none");
    rnp_buffer_destroy(cipher);
    valid = true;
    assert_rnp_success(rnp_op_verify_get_protection_info(verify, NULL, NULL, &valid));
    assert_false(valid);
    assert_rnp_failure(rnp_op_verify_get_protection_info(verify, NULL, NULL, NULL));
    assert_rnp_success(rnp_op_verify_get_protection_info(verify, &mode, &cipher, &valid));
    assert_string_equal(mode, "none");
    assert_string_equal(cipher, "none");
    assert_false(valid);
    rnp_buffer_destroy(mode);
    rnp_buffer_destroy(cipher);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* message without MDC */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-no-mdc"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    mode = NULL;
    cipher = NULL;
    valid = true;
    assert_rnp_success(rnp_op_verify_get_protection_info(verify, &mode, &cipher, &valid));
    assert_string_equal(mode, "cfb");
    assert_string_equal(cipher, "AES256");
    assert_false(valid);
    rnp_buffer_destroy(mode);
    rnp_buffer_destroy(cipher);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* message with MDC */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.enc-mdc"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    mode = NULL;
    cipher = NULL;
    valid = false;
    assert_rnp_success(rnp_op_verify_get_protection_info(verify, &mode, &cipher, &valid));
    assert_string_equal(mode, "cfb-mdc");
    assert_string_equal(cipher, "AES256");
    assert_true(valid);
    rnp_buffer_destroy(mode);
    rnp_buffer_destroy(cipher);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* message with AEAD-OCB */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-aead-ocb"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    mode = NULL;
    cipher = NULL;
    valid = false;
    assert_rnp_success(rnp_op_verify_get_protection_info(verify, &mode, &cipher, &valid));
    assert_string_equal(mode, "aead-ocb");
    assert_string_equal(cipher, "CAMELLIA192");
    assert_true(valid);
    rnp_buffer_destroy(mode);
    rnp_buffer_destroy(cipher);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* modified message with AEAD-OCB */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-aead-ocb-malf"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    mode = NULL;
    cipher = NULL;
    valid = false;
    assert_rnp_success(rnp_op_verify_get_protection_info(verify, &mode, &cipher, &valid));
    assert_string_equal(mode, "aead-ocb");
    assert_string_equal(cipher, "CAMELLIA192");
    assert_false(valid);
    rnp_buffer_destroy(mode);
    rnp_buffer_destroy(cipher);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* message with AEAD-EAX */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-aead-eax"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    mode = NULL;
    cipher = NULL;
    valid = false;
    assert_rnp_success(rnp_op_verify_get_protection_info(verify, &mode, &cipher, &valid));
    assert_string_equal(mode, "aead-eax");
    assert_string_equal(cipher, "AES256");
    assert_true(valid);
    rnp_buffer_destroy(mode);
    rnp_buffer_destroy(cipher);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* modified message with AEAD-EAX */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-aead-eax-malf"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    mode = NULL;
    cipher = NULL;
    valid = false;
    assert_rnp_success(rnp_op_verify_get_protection_info(verify, &mode, &cipher, &valid));
    assert_string_equal(mode, "aead-eax");
    assert_string_equal(cipher, "AES256");
    assert_false(valid);
    rnp_buffer_destroy(mode);
    rnp_buffer_destroy(cipher);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    rnp_ffi_destroy(ffi);
}

static bool
getpasscb_for_key(rnp_ffi_t        ffi,
                  void *           app_ctx,
                  rnp_key_handle_t key,
                  const char *     pgp_context,
                  char *           buf,
                  size_t           buf_len)
{
    if (!key) {
        return false;
    }
    char *keyid = NULL;
    rnp_key_get_keyid(key, &keyid);
    if (!keyid) {
        return false;
    }
    const char *pass = "password";
    if (strcmp(keyid, (const char *) app_ctx)) {
        pass = "wrongpassword";
    }
    size_t pass_len = strlen(pass);
    rnp_buffer_destroy(keyid);

    if (pass_len >= buf_len) {
        return false;
    }
    memcpy(buf, pass, pass_len + 1);
    return true;
}

TEST_F(rnp_tests, test_ffi_op_verify_recipients_info)
{
    rnp_ffi_t    ffi = NULL;
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    // init ffi
    test_ffi_init(&ffi);
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));

    /* message just signed */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.signed"));
    assert_rnp_success(rnp_output_to_null(&output));
    rnp_op_verify_t verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    /* rnp_op_verify_get_recipient_count */
    assert_rnp_failure(rnp_op_verify_get_recipient_count(verify, NULL));
    size_t count = 255;
    assert_rnp_failure(rnp_op_verify_get_recipient_count(NULL, &count));
    assert_rnp_success(rnp_op_verify_get_recipient_count(verify, &count));
    assert_int_equal(count, 0);
    /* rnp_op_verify_get_recipient_at */
    rnp_recipient_handle_t recipient = NULL;
    assert_rnp_failure(rnp_op_verify_get_recipient_at(NULL, 0, &recipient));
    assert_rnp_failure(rnp_op_verify_get_recipient_at(verify, 0, NULL));
    assert_rnp_failure(rnp_op_verify_get_recipient_at(verify, 0, &recipient));
    assert_rnp_failure(rnp_op_verify_get_recipient_at(verify, 10, &recipient));
    /* rnp_op_verify_get_used_recipient */
    assert_rnp_failure(rnp_op_verify_get_used_recipient(NULL, &recipient));
    assert_rnp_failure(rnp_op_verify_get_used_recipient(verify, NULL));
    assert_rnp_success(rnp_op_verify_get_used_recipient(verify, &recipient));
    assert_null(recipient);
    /* rnp_op_verify_get_symenc_count */
    assert_rnp_failure(rnp_op_verify_get_symenc_count(verify, NULL));
    count = 255;
    assert_rnp_failure(rnp_op_verify_get_symenc_count(NULL, &count));
    assert_rnp_success(rnp_op_verify_get_symenc_count(verify, &count));
    assert_int_equal(count, 0);
    /* rnp_op_verify_get_symenc_at */
    rnp_symenc_handle_t symenc = NULL;
    assert_rnp_failure(rnp_op_verify_get_symenc_at(NULL, 0, &symenc));
    assert_rnp_failure(rnp_op_verify_get_symenc_at(verify, 0, NULL));
    assert_rnp_failure(rnp_op_verify_get_symenc_at(verify, 0, &symenc));
    assert_rnp_failure(rnp_op_verify_get_symenc_at(verify, 10, &symenc));
    /* rnp_op_verify_get_used_symenc */
    assert_rnp_failure(rnp_op_verify_get_used_symenc(NULL, &symenc));
    assert_rnp_failure(rnp_op_verify_get_used_symenc(verify, NULL));
    assert_rnp_success(rnp_op_verify_get_used_symenc(verify, &symenc));
    assert_null(symenc);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* message without MDC: single recipient */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-no-mdc"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_recipient_count(verify, &count));
    assert_int_equal(count, 1);
    assert_rnp_failure(rnp_op_verify_get_recipient_at(verify, 1, &recipient));
    assert_rnp_success(rnp_op_verify_get_recipient_at(verify, 0, &recipient));
    assert_non_null(recipient);
    char *alg = NULL;
    assert_rnp_failure(rnp_recipient_get_alg(NULL, &alg));
    assert_rnp_failure(rnp_recipient_get_alg(recipient, NULL));
    assert_rnp_success(rnp_recipient_get_alg(recipient, &alg));
    assert_string_equal(alg, "RSA");
    rnp_buffer_destroy(alg);
    char *keyid = NULL;
    assert_rnp_failure(rnp_recipient_get_keyid(NULL, &keyid));
    assert_rnp_failure(rnp_recipient_get_keyid(recipient, NULL));
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &keyid));
    assert_string_equal(keyid, "8A05B89FAD5ADED1");
    rnp_buffer_destroy(keyid);
    recipient = NULL;
    assert_rnp_success(rnp_op_verify_get_used_recipient(verify, &recipient));
    assert_non_null(recipient);
    alg = NULL;
    assert_rnp_success(rnp_recipient_get_alg(recipient, &alg));
    assert_string_equal(alg, "RSA");
    rnp_buffer_destroy(alg);
    keyid = NULL;
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &keyid));
    assert_string_equal(keyid, "8A05B89FAD5ADED1");
    rnp_buffer_destroy(keyid);
    assert_rnp_success(rnp_op_verify_get_symenc_count(verify, &count));
    assert_int_equal(count, 0);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* message with AEAD-OCB: single password */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-aead-ocb"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    count = 255;
    assert_rnp_success(rnp_op_verify_get_recipient_count(verify, &count));
    assert_int_equal(count, 0);
    assert_rnp_success(rnp_op_verify_get_symenc_count(verify, &count));
    assert_int_equal(count, 1);
    assert_rnp_failure(rnp_op_verify_get_symenc_at(verify, 1, &symenc));
    assert_rnp_success(rnp_op_verify_get_symenc_at(verify, 0, &symenc));
    assert_non_null(symenc);
    char *cipher = NULL;
    assert_rnp_failure(rnp_symenc_get_cipher(symenc, NULL));
    assert_rnp_success(rnp_symenc_get_cipher(symenc, &cipher));
    assert_string_equal(cipher, "CAMELLIA192");
    rnp_buffer_destroy(cipher);
    char *aead = NULL;
    assert_rnp_failure(rnp_symenc_get_aead_alg(symenc, NULL));
    assert_rnp_success(rnp_symenc_get_aead_alg(symenc, &aead));
    assert_string_equal(aead, "OCB");
    rnp_buffer_destroy(aead);
    char *hash = NULL;
    assert_rnp_failure(rnp_symenc_get_hash_alg(symenc, NULL));
    assert_rnp_success(rnp_symenc_get_hash_alg(symenc, &hash));
    assert_string_equal(hash, "SHA1");
    rnp_buffer_destroy(hash);
    char *s2k = NULL;
    assert_rnp_failure(rnp_symenc_get_s2k_type(symenc, NULL));
    assert_rnp_success(rnp_symenc_get_s2k_type(symenc, &s2k));
    assert_string_equal(s2k, "Iterated and salted");
    rnp_buffer_destroy(s2k);
    uint32_t iterations = 0;
    assert_rnp_failure(rnp_symenc_get_s2k_iterations(symenc, NULL));
    assert_rnp_success(rnp_symenc_get_s2k_iterations(symenc, &iterations));
    assert_int_equal(iterations, 30408704);
    assert_rnp_success(rnp_op_verify_get_used_symenc(verify, &symenc));
    assert_non_null(symenc);
    cipher = NULL;
    assert_rnp_success(rnp_symenc_get_cipher(symenc, &cipher));
    assert_string_equal(cipher, "CAMELLIA192");
    rnp_buffer_destroy(cipher);
    aead = NULL;
    assert_rnp_success(rnp_symenc_get_aead_alg(symenc, &aead));
    assert_string_equal(aead, "OCB");
    rnp_buffer_destroy(aead);
    hash = NULL;
    assert_rnp_success(rnp_symenc_get_hash_alg(symenc, &hash));
    assert_string_equal(hash, "SHA1");
    rnp_buffer_destroy(hash);
    s2k = NULL;
    assert_rnp_success(rnp_symenc_get_s2k_type(symenc, &s2k));
    assert_string_equal(s2k, "Iterated and salted");
    rnp_buffer_destroy(s2k);
    iterations = 0;
    assert_rnp_success(rnp_symenc_get_s2k_iterations(symenc, &iterations));
    assert_int_equal(iterations, 30408704);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* modified message with AEAD-EAX: one recipient and one password, decrypt with recipient
     */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-aead-eax-malf"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    count = 255;
    assert_rnp_success(rnp_op_verify_get_recipient_count(verify, &count));
    assert_int_equal(count, 1);
    assert_rnp_success(rnp_op_verify_get_recipient_at(verify, 0, &recipient));
    assert_non_null(recipient);
    alg = NULL;
    assert_rnp_success(rnp_recipient_get_alg(recipient, &alg));
    assert_string_equal(alg, "RSA");
    rnp_buffer_destroy(alg);
    keyid = NULL;
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &keyid));
    assert_string_equal(keyid, "1ED63EE56FADC34D");
    rnp_buffer_destroy(keyid);
    recipient = NULL;
    assert_rnp_success(rnp_op_verify_get_used_recipient(verify, &recipient));
    assert_non_null(recipient);
    assert_rnp_success(rnp_recipient_get_alg(recipient, &alg));
    assert_string_equal(alg, "RSA");
    rnp_buffer_destroy(alg);
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &keyid));
    assert_string_equal(keyid, "1ED63EE56FADC34D");
    rnp_buffer_destroy(keyid);
    assert_rnp_success(rnp_op_verify_get_used_recipient(verify, &recipient));
    assert_non_null(recipient);
    alg = NULL;
    assert_rnp_success(rnp_recipient_get_alg(recipient, &alg));
    assert_string_equal(alg, "RSA");
    rnp_buffer_destroy(alg);
    keyid = NULL;
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &keyid));
    assert_string_equal(keyid, "1ED63EE56FADC34D");
    rnp_buffer_destroy(keyid);
    recipient = NULL;
    assert_rnp_success(rnp_op_verify_get_used_recipient(verify, &recipient));
    assert_non_null(recipient);
    assert_rnp_success(rnp_recipient_get_alg(recipient, &alg));
    assert_string_equal(alg, "RSA");
    rnp_buffer_destroy(alg);
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &keyid));
    assert_string_equal(keyid, "1ED63EE56FADC34D");
    rnp_buffer_destroy(keyid);

    count = 255;
    assert_rnp_success(rnp_op_verify_get_symenc_count(verify, &count));
    assert_int_equal(count, 1);
    assert_rnp_success(rnp_op_verify_get_symenc_at(verify, 0, &symenc));
    assert_non_null(symenc);
    cipher = NULL;
    assert_rnp_success(rnp_symenc_get_cipher(symenc, &cipher));
    assert_string_equal(cipher, "AES256");
    rnp_buffer_destroy(cipher);
    aead = NULL;
    assert_rnp_success(rnp_symenc_get_aead_alg(symenc, &aead));
    assert_string_equal(aead, "EAX");
    rnp_buffer_destroy(aead);
    hash = NULL;
    assert_rnp_success(rnp_symenc_get_hash_alg(symenc, &hash));
    assert_string_equal(hash, "SHA256");
    rnp_buffer_destroy(hash);
    s2k = NULL;
    assert_rnp_success(rnp_symenc_get_s2k_type(symenc, &s2k));
    assert_string_equal(s2k, "Iterated and salted");
    rnp_buffer_destroy(s2k);
    iterations = 0;
    assert_rnp_success(rnp_symenc_get_s2k_iterations(symenc, &iterations));
    assert_int_equal(iterations, 3932160);
    assert_rnp_success(rnp_op_verify_get_used_symenc(verify, &symenc));
    assert_null(symenc);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* message with AEAD-EAX: one recipient and one password, decrypt with password */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-aead-eax"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    count = 255;
    assert_rnp_success(rnp_op_verify_get_recipient_count(verify, &count));
    assert_int_equal(count, 1);
    assert_rnp_success(rnp_op_verify_get_used_recipient(verify, &recipient));
    assert_null(recipient);
    count = 255;
    assert_rnp_success(rnp_op_verify_get_symenc_count(verify, &count));
    assert_int_equal(count, 1);
    assert_rnp_success(rnp_op_verify_get_symenc_at(verify, 0, &symenc));
    assert_non_null(symenc);
    assert_rnp_success(rnp_op_verify_get_used_symenc(verify, &symenc));
    assert_non_null(symenc);
    cipher = NULL;
    assert_rnp_success(rnp_symenc_get_cipher(symenc, &cipher));
    assert_string_equal(cipher, "AES256");
    rnp_buffer_destroy(cipher);
    aead = NULL;
    assert_rnp_success(rnp_symenc_get_aead_alg(symenc, &aead));
    assert_string_equal(aead, "EAX");
    rnp_buffer_destroy(aead);
    hash = NULL;
    assert_rnp_success(rnp_symenc_get_hash_alg(symenc, &hash));
    assert_string_equal(hash, "SHA256");
    rnp_buffer_destroy(hash);
    s2k = NULL;
    assert_rnp_success(rnp_symenc_get_s2k_type(symenc, &s2k));
    assert_string_equal(s2k, "Iterated and salted");
    rnp_buffer_destroy(s2k);
    iterations = 0;
    assert_rnp_success(rnp_symenc_get_s2k_iterations(symenc, &iterations));
    assert_int_equal(iterations, 3932160);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* message encrypted to 3 recipients and 2 passwords: password1, password2 */
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "wrongpassword"));
    assert_true(import_sec_keys(ffi, "data/keyrings/1/secring.gpg"));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-3key-2p"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    count = 255;
    assert_rnp_success(rnp_op_verify_get_recipient_count(verify, &count));
    assert_int_equal(count, 3);
    assert_rnp_success(rnp_op_verify_get_recipient_at(verify, 0, &recipient));
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &keyid));
    assert_string_equal(keyid, "1ED63EE56FADC34D");
    rnp_buffer_destroy(keyid);
    assert_rnp_success(rnp_op_verify_get_recipient_at(verify, 1, &recipient));
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &keyid));
    assert_string_equal(keyid, "8A05B89FAD5ADED1");
    rnp_buffer_destroy(keyid);
    assert_rnp_success(rnp_op_verify_get_recipient_at(verify, 2, &recipient));
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &keyid));
    assert_string_equal(keyid, "54505A936A4A970E");
    rnp_buffer_destroy(keyid);
    assert_rnp_success(rnp_op_verify_get_used_recipient(verify, &recipient));
    assert_null(recipient);
    count = 255;
    assert_rnp_success(rnp_op_verify_get_symenc_count(verify, &count));
    assert_int_equal(count, 2);
    assert_rnp_success(rnp_op_verify_get_symenc_at(verify, 0, &symenc));
    assert_rnp_success(rnp_symenc_get_s2k_iterations(symenc, &iterations));
    assert_int_equal(iterations, 3932160);
    assert_rnp_success(rnp_op_verify_get_symenc_at(verify, 1, &symenc));
    assert_rnp_success(rnp_symenc_get_s2k_iterations(symenc, &iterations));
    assert_int_equal(iterations, 3276800);
    assert_rnp_success(rnp_op_verify_get_used_symenc(verify, &symenc));
    assert_null(symenc);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password2"));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-3key-2p"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_used_symenc(verify, &symenc));
    assert_rnp_success(rnp_symenc_get_s2k_iterations(symenc, &iterations));
    assert_rnp_success(rnp_op_verify_get_used_recipient(verify, &recipient));
    assert_null(recipient);
    assert_int_equal(iterations, 3276800);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, getpasscb_for_key, (void *) "8A05B89FAD5ADED1"));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-3key-2p"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    assert_rnp_success(rnp_op_verify_get_used_symenc(verify, &symenc));
    assert_null(symenc);
    assert_rnp_success(rnp_op_verify_get_used_recipient(verify, &recipient));
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &keyid));
    assert_string_equal(keyid, "8A05B89FAD5ADED1");
    rnp_buffer_destroy(keyid);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_secret_sig_import)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_true(import_sec_keys(ffi, "data/test_key_validity/alice-sec.asc"));
    rnp_key_handle_t key_handle = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key_handle));
    bool locked = false;
    /* unlock secret key */
    assert_rnp_success(rnp_key_is_locked(key_handle, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_unlock(key_handle, "password"));
    assert_rnp_success(rnp_key_is_locked(key_handle, &locked));
    assert_false(locked);
    /* import revocation signature */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_key_validity/alice-rev.pgp"));
    assert_rnp_success(rnp_import_signatures(ffi, input, 0, NULL));
    assert_rnp_success(rnp_input_destroy(input));
    /* make sure that key is still unlocked */
    assert_rnp_success(rnp_key_is_locked(key_handle, &locked));
    assert_false(locked);
    /* import subkey */
    assert_true(import_sec_keys(ffi, "data/test_key_validity/alice-sub-sec.pgp"));
    /* make sure that primary key is still unlocked */
    assert_rnp_success(rnp_key_is_locked(key_handle, &locked));
    assert_false(locked);
    /* unlock subkey and make sure it is unlocked after revocation */
    rnp_key_handle_t sub_handle = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub_handle));
    assert_rnp_success(rnp_key_unlock(sub_handle, "password"));
    assert_rnp_success(rnp_key_is_locked(sub_handle, &locked));
    assert_false(locked);
    assert_rnp_success(rnp_key_revoke(sub_handle, 0, "SHA256", "retired", "Custom reason"));
    assert_rnp_success(rnp_key_is_locked(sub_handle, &locked));
    assert_false(locked);
    assert_rnp_success(rnp_key_handle_destroy(sub_handle));
    assert_rnp_success(rnp_key_handle_destroy(key_handle));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

static bool
getpasscb_fail(rnp_ffi_t        ffi,
               void *           app_ctx,
               rnp_key_handle_t key,
               const char *     pgp_context,
               char *           buf,
               size_t           buf_len)
{
    return false;
}

static bool
getpasscb_context(rnp_ffi_t        ffi,
                  void *           app_ctx,
                  rnp_key_handle_t key,
                  const char *     pgp_context,
                  char *           buf,
                  size_t           buf_len)
{
    strncpy(buf, pgp_context, buf_len - 1);
    return true;
}

static bool
getpasscb_keyid(rnp_ffi_t        ffi,
                void *           app_ctx,
                rnp_key_handle_t key,
                const char *     pgp_context,
                char *           buf,
                size_t           buf_len)
{
    if (!key) {
        return false;
    }
    char *keyid = NULL;
    if (rnp_key_get_keyid(key, &keyid)) {
        return false;
    }
    strncpy(buf, keyid, buf_len - 1);
    rnp_buffer_destroy(keyid);
    return true;
}

TEST_F(rnp_tests, test_ffi_rnp_request_password)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    /* check wrong parameters cases */
    char *password = NULL;
    assert_rnp_failure(rnp_request_password(ffi, NULL, "sign", &password));
    assert_null(password);
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_failure(rnp_request_password(NULL, NULL, "sign", &password));
    assert_rnp_failure(rnp_request_password(ffi, NULL, "sign", NULL));
    /* now it should succeed */
    assert_rnp_success(rnp_request_password(ffi, NULL, "sign", &password));
    assert_string_equal(password, "password");
    rnp_buffer_destroy(password);
    /* let's try failing password provider */
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb_fail, NULL));
    assert_rnp_failure(rnp_request_password(ffi, NULL, "sign", &password));
    /* let's try to return request context */
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb_context, NULL));
    assert_rnp_success(rnp_request_password(ffi, NULL, "custom context", &password));
    assert_string_equal(password, "custom context");
    rnp_buffer_destroy(password);
    /* let's check whether key is correctly passed to handler */
    assert_true(import_sec_keys(ffi, "data/test_key_validity/alice-sec.asc"));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb_keyid, NULL));
    assert_rnp_success(rnp_request_password(ffi, key, NULL, &password));
    assert_string_equal(password, "0451409669FFDE3C");
    rnp_buffer_destroy(password);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_revoke)
{
    rnp_ffi_t ffi = NULL;

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/alice-sub-pub.pgp"));
    rnp_key_handle_t key_handle = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key_handle));
    /* check for failure with wrong parameters */
    assert_rnp_failure(rnp_key_revoke(NULL, 0, "SHA256", "superseded", "test key revocation"));
    assert_rnp_failure(rnp_key_revoke(key_handle, 0, "SHA256", NULL, NULL));
    assert_rnp_failure(rnp_key_revoke(key_handle, 0x17, "SHA256", NULL, NULL));
    assert_rnp_failure(rnp_key_revoke(key_handle, 0, "Wrong hash", NULL, NULL));
    assert_rnp_failure(rnp_key_revoke(key_handle, 0, "SHA256", "Wrong reason code", NULL));
    /* attempt to revoke key without the secret */
    assert_rnp_failure(rnp_key_revoke(key_handle, 0, "SHA256", "retired", "Custom reason"));
    assert_rnp_success(rnp_key_handle_destroy(key_handle));
    /* attempt to revoke subkey without the secret */
    rnp_key_handle_t sub_handle = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub_handle));
    assert_rnp_failure(rnp_key_revoke(sub_handle, 0, "SHA256", "retired", "Custom reason"));
    assert_rnp_success(rnp_key_handle_destroy(sub_handle));
    /* load secret key */
    assert_true(import_sec_keys(ffi, "data/test_key_validity/alice-sub-sec.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key_handle));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub_handle));
    /* wrong password - must fail */
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "wrong"));
    assert_rnp_failure(rnp_key_revoke(key_handle, 0, "SHA256", "superseded", NULL));
    assert_rnp_failure(rnp_key_revoke(sub_handle, 0, "SHA256", "superseded", NULL));
    /* unlocked key - must succeed */
    bool revoked = false;
    assert_rnp_success(rnp_key_is_revoked(key_handle, &revoked));
    assert_false(revoked);
    assert_rnp_success(rnp_key_unlock(key_handle, "password"));
    assert_rnp_success(rnp_key_revoke(key_handle, 0, "SHA256", NULL, NULL));
    assert_rnp_success(rnp_key_is_revoked(key_handle, &revoked));
    assert_true(revoked);
    /* subkey */
    assert_rnp_success(rnp_key_is_revoked(sub_handle, &revoked));
    assert_false(revoked);
    bool locked = true;
    assert_rnp_success(rnp_key_is_locked(key_handle, &locked));
    assert_false(locked);
    assert_rnp_success(rnp_key_revoke(sub_handle, 0, "SHA256", NULL, "subkey revoked"));
    assert_rnp_success(rnp_key_is_revoked(sub_handle, &revoked));
    assert_true(revoked);
    assert_rnp_success(rnp_key_lock(key_handle));
    assert_rnp_success(rnp_key_handle_destroy(key_handle));
    assert_rnp_success(rnp_key_handle_destroy(sub_handle));
    /* correct password provider - must succeed */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_SECRET | RNP_KEY_UNLOAD_PUBLIC));
    assert_true(import_sec_keys(ffi, "data/test_key_validity/alice-sub-sec.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key_handle));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_success(rnp_key_is_revoked(key_handle, &revoked));
    assert_false(revoked);
    assert_rnp_success(
      rnp_key_revoke(key_handle, 0, "SHA256", "superseded", "test key revocation"));
    assert_rnp_success(rnp_key_is_revoked(key_handle, &revoked));
    assert_true(revoked);
    /* make sure FFI locks key back */
    assert_rnp_success(rnp_key_is_locked(key_handle, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_handle_destroy(key_handle));
    /* repeat for subkey */
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub_handle));
    assert_rnp_success(rnp_key_is_revoked(sub_handle, &revoked));
    assert_false(revoked);
    assert_rnp_success(rnp_key_revoke(sub_handle, 0, "SHA256", "no", "test sub revocation"));
    assert_rnp_success(rnp_key_is_revoked(sub_handle, &revoked));
    assert_true(revoked);
    assert_rnp_success(rnp_key_handle_destroy(sub_handle));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_key_set_expiry)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/alice-sub-pub.pgp"));

    /* check edge cases */
    assert_rnp_failure(rnp_key_set_expiration(NULL, 0));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    /* cannot set key expiration with public key only */
    assert_rnp_failure(rnp_key_set_expiration(key, 1000));
    rnp_key_handle_t sub = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub));
    assert_rnp_failure(rnp_key_set_expiration(sub, 1000));
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(sub));

    /* load secret key */
    assert_true(import_sec_keys(ffi, "data/test_key_validity/alice-sub-sec.pgp"));
    uint32_t       expiry = 0;
    const uint32_t new_expiry = 10 * 365 * 24 * 60 * 60;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    expiry = 255;
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0);
    assert_rnp_success(rnp_key_set_expiration(key, 0));
    /* will fail on locked key */
    assert_rnp_failure(rnp_key_set_expiration(key, new_expiry));
    assert_rnp_success(rnp_key_unlock(key, "password"));
    assert_rnp_success(rnp_key_set_expiration(key, new_expiry));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, new_expiry);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub));
    /* will succeed on locked subkey since it is not signing one */
    assert_rnp_success(rnp_key_set_expiration(sub, 0));
    assert_rnp_success(rnp_key_set_expiration(sub, new_expiry * 2));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, new_expiry * 2);
    /* make sure new expiration times are properly saved */
    rnp_output_t keymem = NULL;
    rnp_output_t seckeymem = NULL;
    assert_rnp_success(rnp_output_to_memory(&keymem, 0));
    assert_rnp_success(
      rnp_key_export(key, keymem, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));
    assert_rnp_success(rnp_output_to_memory(&seckeymem, 0));
    assert_rnp_success(
      rnp_key_export(key, seckeymem, RNP_KEY_EXPORT_SECRET | RNP_KEY_EXPORT_SUBKEYS));
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(sub));
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    uint8_t *keybuf = NULL;
    size_t   keylen = 0;
    assert_rnp_success(rnp_output_memory_get_buf(keymem, &keybuf, &keylen, false));
    /* load public key */
    assert_true(import_pub_keys(ffi, keybuf, keylen));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, new_expiry);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, new_expiry * 2);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(sub));
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    /* now load exported secret key */
    assert_rnp_success(rnp_output_memory_get_buf(seckeymem, &keybuf, &keylen, false));
    assert_true(import_sec_keys(ffi, keybuf, keylen));
    assert_rnp_success(rnp_output_destroy(seckeymem));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, new_expiry);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, new_expiry * 2);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(sub));
    /* now unset expiration time back, first loading the public key back */
    assert_rnp_success(rnp_output_memory_get_buf(keymem, &keybuf, &keylen, false));
    assert_true(import_pub_keys(ffi, keybuf, keylen));
    assert_rnp_success(rnp_output_destroy(keymem));
    /* set primary key expiration */
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    assert_rnp_success(rnp_key_unlock(key, "password"));
    assert_rnp_success(rnp_key_set_expiration(key, 0));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub));
    assert_rnp_success(rnp_key_set_expiration(sub, 0));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, 0);
    /* let's export them and reload */
    assert_rnp_success(rnp_output_to_memory(&keymem, 0));
    assert_rnp_success(
      rnp_key_export(key, keymem, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(sub));
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(rnp_output_memory_get_buf(keymem, &keybuf, &keylen, false));
    assert_true(import_pub_keys(ffi, keybuf, keylen));
    assert_rnp_success(rnp_output_destroy(keymem));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, 0);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(sub));

    /* now try the sign-able subkey */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/alice-sign-sub-pub.pgp"));
    assert_true(import_sec_keys(ffi, "data/test_key_validity/alice-sign-sub-sec.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "22F3A217C0E439CB", &sub));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, 0);
    assert_rnp_failure(rnp_key_set_expiration(sub, new_expiry));
    /* now unlock only primary key - should fail */
    assert_rnp_success(rnp_key_unlock(key, "password"));
    assert_rnp_failure(rnp_key_set_expiration(sub, new_expiry));
    /* unlock subkey */
    assert_rnp_success(rnp_key_unlock(sub, "password"));
    assert_rnp_success(rnp_key_set_expiration(sub, new_expiry));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, new_expiry);
    assert_rnp_success(rnp_output_to_memory(&keymem, 0));
    assert_rnp_success(
      rnp_key_export(key, keymem, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(sub));
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(rnp_output_memory_get_buf(keymem, &keybuf, &keylen, false));
    assert_true(import_pub_keys(ffi, keybuf, keylen));
    assert_rnp_success(rnp_output_destroy(keymem));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "22F3A217C0E439CB", &sub));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, new_expiry);
    assert_rnp_success(rnp_key_handle_destroy(sub));

    /* check whether we can change expiration for already expired key */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/alice-sign-sub-pub.pgp"));
    assert_true(import_sec_keys(ffi, "data/test_key_validity/alice-sign-sub-sec.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "22F3A217C0E439CB", &sub));
    assert_rnp_success(rnp_key_unlock(key, "password"));
    assert_rnp_success(rnp_key_unlock(sub, "password"));
    assert_rnp_success(rnp_key_set_expiration(key, 1));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 1);
    /* key is invalid since it is expired */
    assert_false(key->pub->valid());
    bool valid = true;
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_false(valid);
    uint32_t till = 0;
    assert_rnp_success(rnp_key_valid_till(key, &till));
    assert_int_equal(till, 1577369391 + 1);
    uint64_t till64 = 0;
    assert_rnp_success(rnp_key_valid_till64(key, &till64));
    assert_int_equal(till64, 1577369391 + 1);
    assert_rnp_success(rnp_key_set_expiration(sub, 1));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, 1);
    assert_false(sub->pub->valid());
    valid = true;
    assert_rnp_success(rnp_key_is_valid(sub, &valid));
    assert_false(valid);
    till = 1;
    assert_rnp_success(rnp_key_valid_till(sub, &till));
    assert_int_equal(till, 1577369391 + 1);
    assert_rnp_success(rnp_key_valid_till64(sub, &till64));
    assert_int_equal(till64, 1577369391 + 1);
    assert_rnp_success(rnp_key_set_expiration(key, 0));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0);
    assert_true(key->pub->valid());
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_true(valid);
    assert_rnp_success(rnp_key_valid_till(key, &till));
    assert_int_equal(till, 0xffffffff);
    assert_rnp_success(rnp_key_valid_till64(key, &till64));
    assert_int_equal(till64, UINT64_MAX);
    assert_rnp_success(rnp_key_set_expiration(sub, 0));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, 0);
    assert_true(sub->pub->valid());
    valid = false;
    assert_rnp_success(rnp_key_is_valid(sub, &valid));
    assert_true(valid);
    till = 0;
    assert_rnp_success(rnp_key_valid_till(sub, &till));
    assert_int_equal(till, 0xffffffff);
    till64 = 0;
    assert_rnp_success(rnp_key_valid_till64(sub, &till64));
    assert_int_equal(till64, UINT64_MAX);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(sub));

    /* check whether we can change expiration with password provider/locked key */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/alice-sign-sub-pub.pgp"));
    assert_true(import_sec_keys(ffi, "data/test_key_validity/alice-sign-sub-sec.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "22F3A217C0E439CB", &sub));

    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "wrong"));
    assert_rnp_failure(rnp_key_set_expiration(key, 1));
    expiry = 255;
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0);
    assert_rnp_failure(rnp_key_set_expiration(sub, 1));
    expiry = 255;
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, 0);

    bool locked = true;
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_true(locked);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(sub, &locked));
    assert_true(locked);
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    uint32_t creation = 0;
    assert_rnp_success(rnp_key_get_creation(key, &creation));
    creation = time(NULL) - creation;
    assert_rnp_success(rnp_key_set_expiration(key, creation + 2));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, creation + 2);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_get_creation(sub, &creation));
    creation = time(NULL) - creation;
    assert_rnp_success(rnp_key_set_expiration(sub, creation + 3));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, creation + 3);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(sub, &locked));
    assert_true(locked);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_true(locked);

    /* now change just subkey's expiration - should also work */
    assert_rnp_success(rnp_key_set_expiration(sub, 4));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, 4);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(sub, &locked));
    assert_true(locked);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_true(locked);

    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(sub));

    /* now try to update already expired key and subkey */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/alice-sign-sub-exp-pub.asc"));
    assert_true(import_sec_keys(ffi, "data/test_key_validity/alice-sign-sub-exp-sec.asc"));
    /* Alice key is searchable by userid since self-sig is not expired, and it just marks key
     * as expired */
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "22F3A217C0E439CB", &sub));
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    /* key is not valid since function checks public key */
    assert_false(valid);
    assert_rnp_success(rnp_key_valid_till(key, &till));
    assert_int_equal(till, 1577369391 + 16324055);
    assert_rnp_success(rnp_key_valid_till64(key, &till64));
    assert_int_equal(till64, 1577369391 + 16324055);
    assert_false(key->pub->valid());
    assert_true(key->sec->valid());
    assert_rnp_success(rnp_key_is_valid(sub, &valid));
    assert_false(valid);
    assert_rnp_success(rnp_key_valid_till(sub, &till));
    /* subkey valid no longer then the primary key */
    assert_int_equal(till, 1577369391 + 16324055);
    assert_rnp_success(rnp_key_valid_till64(sub, &till64));
    assert_int_equal(till64, 1577369391 + 16324055);
    assert_false(sub->pub->valid());
    assert_true(sub->sec->valid());
    creation = 0;
    uint32_t validity = 2 * 30 * 24 * 60 * 60; // 2 monthes
    assert_rnp_success(rnp_key_get_creation(key, &creation));
    uint32_t keytill = creation + validity;
    creation = time(NULL) - creation;
    keytill += creation;
    assert_rnp_success(rnp_key_set_expiration(key, creation + validity));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, creation + validity);
    assert_rnp_success(rnp_key_get_creation(sub, &creation));
    /* use smaller validity for the subkey */
    validity = validity / 2;
    uint32_t subtill = creation + validity;
    creation = time(NULL) - creation;
    subtill += creation;
    assert_rnp_success(rnp_key_set_expiration(sub, creation + validity));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, creation + validity);
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_true(valid);
    assert_rnp_success(rnp_key_valid_till(key, &till));
    assert_int_equal(till, keytill);
    assert_rnp_success(rnp_key_valid_till64(key, &till64));
    assert_int_equal(till64, keytill);
    assert_true(key->pub->valid());
    assert_true(key->sec->valid());
    assert_rnp_success(rnp_key_is_valid(sub, &valid));
    assert_true(valid);
    assert_rnp_success(rnp_key_valid_till(sub, &till));
    assert_int_equal(till, subtill);
    assert_rnp_success(rnp_key_valid_till64(sub, &till64));
    assert_int_equal(till64, subtill);
    assert_true(sub->pub->valid());
    assert_true(sub->sec->valid());
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(sub));

    /* update expiration time when only secret key is available */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "22F3A217C0E439CB", &sub));
    validity = 30 * 24 * 60 * 60; // 1 month
    assert_rnp_success(rnp_key_get_creation(key, &creation));
    creation = time(NULL) - creation;
    assert_rnp_success(rnp_key_set_expiration(key, creation + validity));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, creation + validity);
    assert_rnp_success(rnp_key_get_creation(sub, &creation));
    creation = time(NULL) - creation;
    assert_rnp_success(rnp_key_set_expiration(sub, creation + validity));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, creation + validity);
    /* public key is not available - bad parameters */
    assert_int_equal(rnp_key_is_valid(key, &valid), RNP_ERROR_BAD_PARAMETERS);
    assert_int_equal(rnp_key_valid_till(key, &till), RNP_ERROR_BAD_PARAMETERS);
    assert_int_equal(rnp_key_valid_till64(key, &till64), RNP_ERROR_BAD_PARAMETERS);
    assert_null(key->pub);
    assert_true(key->sec->valid());
    assert_int_equal(rnp_key_is_valid(sub, &valid), RNP_ERROR_BAD_PARAMETERS);
    assert_int_equal(rnp_key_valid_till(sub, &till), RNP_ERROR_BAD_PARAMETERS);
    assert_int_equal(rnp_key_valid_till64(sub, &till64), RNP_ERROR_BAD_PARAMETERS);
    assert_null(sub->pub);
    assert_true(sub->sec->valid());
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(sub));
    assert_rnp_success(rnp_ffi_destroy(ffi));

    /* check whether things work for G10 keyring */
    assert_rnp_success(rnp_ffi_create(&ffi, "KBX", "G10"));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_true(load_keys_kbx_g10(
      ffi, "data/keyrings/3/pubring.kbx", "data/keyrings/3/private-keys-v1.d"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "4BE147BB22DF1E60", &key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "A49BAE05C16E8BC8", &sub));
    assert_rnp_success(rnp_key_get_creation(key, &creation));
    keytill = creation + validity;
    creation = time(NULL) - creation;
    keytill += creation;
    assert_rnp_success(rnp_key_set_expiration(key, creation + validity));
    expiry = 255;
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, creation + validity);
    size_t key_expiry = expiry;
    assert_rnp_success(rnp_key_get_creation(sub, &creation));
    creation = time(NULL) - creation;
    assert_rnp_success(rnp_key_set_expiration(sub, creation + validity));
    expiry = 255;
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, creation + validity);
    size_t sub_expiry = expiry;
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_true(valid);
    assert_rnp_success(rnp_key_valid_till(key, &till));
    assert_int_equal(till, keytill);
    assert_rnp_success(rnp_key_valid_till64(key, &till64));
    assert_int_equal(till64, keytill);
    assert_true(key->pub->valid());
    assert_true(key->sec->valid());
    assert_rnp_success(rnp_key_is_valid(sub, &valid));
    assert_true(valid);
    assert_rnp_success(rnp_key_valid_till(sub, &till));
    assert_int_equal(till, keytill);
    assert_rnp_success(rnp_key_valid_till64(sub, &till64));
    assert_int_equal(till64, keytill);
    assert_true(sub->pub->valid());
    assert_true(sub->sec->valid());
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(sub));

    /* save keyring to KBX and reload it: fails now */
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_output_to_path(&output, "pubring.kbx"));
    assert_rnp_success(rnp_save_keys(ffi, "KBX", output, RNP_LOAD_SAVE_PUBLIC_KEYS));
    assert_rnp_success(rnp_output_destroy(output));
    assert_rnp_success(rnp_ffi_destroy(ffi));
    assert_rnp_success(rnp_ffi_create(&ffi, "KBX", "G10"));
    assert_rnp_success(rnp_input_from_path(&input, "pubring.kbx"));
    /* Saving to KBX doesn't work well, or was broken at some point. */
    assert_rnp_failure(rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, NULL));
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "4BE147BB22DF1E60", &key));
    assert_null(key);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "A49BAE05C16E8BC8", &sub));
    assert_null(sub);
    expiry = 255;
    assert_rnp_failure(rnp_key_get_expiration(key, &expiry));
    assert_int_not_equal(expiry, key_expiry);
    expiry = 255;
    assert_rnp_failure(rnp_key_get_expiration(sub, &expiry));
    assert_int_not_equal(expiry, sub_expiry);
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(sub));
    assert_int_equal(rnp_unlink("pubring.kbx"), 0);
    assert_rnp_success(rnp_ffi_destroy(ffi));

    /* load G10/KBX and unload public keys - must succeed */
    assert_rnp_success(rnp_ffi_create(&ffi, "KBX", "G10"));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_true(load_keys_kbx_g10(
      ffi, "data/keyrings/3/pubring.kbx", "data/keyrings/3/private-keys-v1.d"));
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "4BE147BB22DF1E60", &key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "A49BAE05C16E8BC8", &sub));
    assert_rnp_success(rnp_key_get_creation(key, &creation));
    creation = time(NULL) - creation;
    assert_rnp_success(rnp_key_set_expiration(key, creation + validity));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, creation + validity);
    key_expiry = expiry;
    assert_rnp_success(rnp_key_get_creation(sub, &creation));
    creation = time(NULL) - creation;
    assert_rnp_success(rnp_key_set_expiration(sub, creation + validity));
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, creation + validity);
    sub_expiry = expiry;
    assert_rnp_success(rnp_key_handle_destroy(key));
    assert_rnp_success(rnp_key_handle_destroy(sub));

    // TODO: check expiration date in direct-key signature, check without
    // self-signature/binding signature.

    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_mdc_8k_boundary)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;

    test_ffi_init(&ffi);
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));

    /* correctly process two messages */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message_mdc_8k_1.pgp"));
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_output_to_null(&output));
    rnp_op_verify_t verify;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    /* check signature */
    size_t sig_count = 0;
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sig_count));
    assert_int_equal(sig_count, 1);
    rnp_op_verify_signature_t sig = NULL;
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 0, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    /* cleanup */
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));

    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message_mdc_8k_2.pgp"));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    /* check signature */
    sig_count = 0;
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sig_count));
    assert_int_equal(sig_count, 1);
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 0, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    /* cleanup */
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));

    /* let it gracefully fail on message 1 with the last byte cut */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message_mdc_8k_cut1.pgp"));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    /* cleanup */
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));

    /* let it gracefully fail on message 1 with the last 22 bytes (MDC size) cut */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message_mdc_8k_cut22.pgp"));
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(verify));
    /* cleanup */
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));

    assert_rnp_success(rnp_output_destroy(output));
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

TEST_F(rnp_tests, test_ffi_decrypt_wrong_mpi_bits)
{
    rnp_ffi_t    ffi = NULL;
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    // init ffi
    test_ffi_init(&ffi);

    /* 1024 bitcount instead of 1023 */
    rnp_op_verify_t op = NULL;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-malf-1"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_success(rnp_op_verify_create(&op, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(op));
    rnp_op_verify_destroy(op);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* 1025 bitcount instead of 1023 */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-malf-2"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_success(rnp_op_verify_create(&op, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(op));
    rnp_op_verify_destroy(op);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* 1031 bitcount instead of 1023 */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-malf-3"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_success(rnp_op_verify_create(&op, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(op));
    rnp_op_verify_destroy(op);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* 1040 bitcount instead of 1023 */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-malf-4"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_success(rnp_op_verify_create(&op, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(op));
    rnp_op_verify_destroy(op);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* 1017 bitcount instead of 1023 */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-malf-5"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_success(rnp_op_verify_create(&op, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(op));
    rnp_op_verify_destroy(op);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_decrypt_edge_cases)
{
    rnp_ffi_t    ffi = NULL;
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    test_ffi_init(&ffi);

    /* unknown algorithm in public-key encrypted session key */
    rnp_op_verify_t op = NULL;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.txt.enc-wrong-alg"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_success(rnp_op_verify_create(&op, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(op));
    rnp_op_verify_destroy(op);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* endless recursive compression packets, 'quine'.
     * Generated using the code by Taylor R. Campbell */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.zlib-quine"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&op, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(op));
    rnp_op_verify_destroy(op);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.zlib-quine"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_dump_packets_to_output(input, output, 0));
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.zlib-quine"));
    char *json = NULL;
    assert_rnp_success(rnp_dump_packets_to_json(input, 0, &json));
    assert_non_null(json);
    rnp_buffer_destroy(json);
    rnp_input_destroy(input);

    /* 128 levels of compression - fail decryption*/
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.compr.128-rounds"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_op_verify_create(&op, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(op));
    rnp_op_verify_destroy(op);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* but dumping will succeed */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.compr.128-rounds"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dump_packets_to_output(input, output, 0));
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.compr.128-rounds"));
    json = NULL;
    assert_rnp_success(rnp_dump_packets_to_json(input, 0, &json));
    assert_non_null(json);
    rnp_buffer_destroy(json);
    rnp_input_destroy(input);

    /* 32 levels of compression + encryption */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.compr-encr.32-rounds"));
    assert_rnp_success(rnp_output_to_null(&output));
    assert_rnp_success(rnp_op_verify_create(&op, ffi, input, output));
    assert_rnp_failure(rnp_op_verify_execute(op));
    rnp_op_verify_destroy(op);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.compr-encr.32-rounds"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dump_packets_to_output(input, output, 0));
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.compr-encr.32-rounds"));
    json = NULL;
    assert_rnp_success(rnp_dump_packets_to_json(input, 0, &json));
    assert_non_null(json);
    rnp_buffer_destroy(json);
    rnp_input_destroy(input);

    /* 31 levels of compression + encryption */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.compr-encr.31-rounds"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_op_verify_create(&op, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(op));
    rnp_op_verify_destroy(op);
    rnp_input_destroy(input);
    uint8_t *buf = NULL;
    size_t   len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 7);
    assert_int_equal(memcmp(buf, "message", 7), 0);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.compr-encr.31-rounds"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_dump_packets_to_output(input, output, 0));
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_messages/message.compr-encr.31-rounds"));
    json = NULL;
    assert_rnp_success(rnp_dump_packets_to_json(input, 0, &json));
    assert_non_null(json);
    rnp_buffer_destroy(json);
    rnp_input_destroy(input);

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_import_edge_cases)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    /* key with empty packets - must fail with bad format */
    rnp_input_t input = NULL;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/key-empty-packets.pgp"));
    char *results = NULL;
    assert_int_equal(rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, &results),
                     RNP_ERROR_BAD_FORMAT);
    assert_null(results);
    rnp_input_destroy(input);

    /* key with empty uid - must succeed */
    json_object *jso = NULL;
    assert_true(
      check_import_keys(ffi, &jso, "data/test_key_edge_cases/key-empty-uid.pgp", 1, 1, 0));
    assert_true(
      check_key_status(jso, 0, "new", "none", "753d5b947e9a2b2e01147c1fc972affd358bf887"));
    json_object_put(jso);

    /* key with experimental signature subpackets - must succeed and append uid and signature
     */
    assert_true(check_import_keys(
      ffi, &jso, "data/test_key_edge_cases/key-subpacket-101-110.pgp", 1, 1, 0));
    assert_true(
      check_key_status(jso, 0, "updated", "none", "753d5b947e9a2b2e01147c1fc972affd358bf887"));
    json_object_put(jso);

    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "C972AFFD358BF887", &key));
    size_t count = 0;
    assert_rnp_success(rnp_key_get_uid_count(key, &count));
    assert_int_equal(count, 2);
    char *uid = NULL;
    assert_rnp_success(rnp_key_get_uid_at(key, 0, &uid));
    assert_string_equal(uid, "");
    rnp_buffer_destroy(uid);
    assert_rnp_success(rnp_key_get_uid_at(key, 1, &uid));
    assert_string_equal(uid, "NoUID");
    rnp_buffer_destroy(uid);
    rnp_key_handle_destroy(key);

    /* key with malformed signature - must fail */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/key-malf-sig.pgp"));
    assert_int_equal(rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, &results),
                     RNP_ERROR_BAD_FORMAT);
    assert_null(results);
    rnp_input_destroy(input);

    /* revoked key without revocation reason signature subpacket */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/alice-rev-no-reason.pgp"));
    assert_rnp_success(rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, &results));
    rnp_input_destroy(input);
    assert_non_null(results);
    rnp_buffer_destroy(results);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    assert_rnp_success(rnp_key_get_revocation_reason(key, &results));
    assert_string_equal(results, "No reason specified");
    rnp_buffer_destroy(results);
    bool revoked = false;
    assert_rnp_success(rnp_key_is_revoked(key, &revoked));
    assert_true(revoked);
    rnp_key_handle_destroy(key);
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));

    /* revoked subkey without revocation reason signature subpacket */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/alice-sub-rev-no-reason.pgp"));
    assert_rnp_success(rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, &results));
    rnp_input_destroy(input);
    assert_non_null(results);
    rnp_buffer_destroy(results);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    assert_int_equal(rnp_key_get_revocation_reason(key, &results), RNP_ERROR_BAD_PARAMETERS);
    revoked = true;
    assert_rnp_success(rnp_key_is_revoked(key, &revoked));
    assert_false(revoked);
    rnp_key_handle_destroy(key);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &key));
    assert_rnp_success(rnp_key_get_revocation_reason(key, &results));
    assert_string_equal(results, "No reason specified");
    rnp_buffer_destroy(results);
    revoked = false;
    assert_rnp_success(rnp_key_is_revoked(key, &revoked));
    assert_true(revoked);
    rnp_key_handle_destroy(key);

    /* key with two subkeys with same material but different creation time */
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/alice-2-subs-same-grip.pgp"));
    assert_rnp_success(rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, &results));
    rnp_input_destroy(input);
    assert_non_null(results);
    rnp_buffer_destroy(results);
    count = 0;
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 3);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    assert_rnp_success(rnp_key_get_subkey_count(key, &count));
    assert_int_equal(count, 2);
    rnp_key_handle_t sub = NULL;
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &sub));
    char *keyid = NULL;
    assert_rnp_success(rnp_key_get_keyid(sub, &keyid));
    assert_string_equal(keyid, "DD23CEB7FEBEFF17");
    rnp_buffer_destroy(keyid);
    char *fp = NULL;
    assert_rnp_success(rnp_key_get_primary_fprint(sub, &fp));
    assert_string_equal(fp, "73EDCC9119AFC8E2DBBDCDE50451409669FFDE3C");
    rnp_buffer_destroy(fp);
    rnp_key_handle_destroy(sub);
    assert_rnp_success(rnp_key_get_subkey_at(key, 1, &sub));
    assert_rnp_success(rnp_key_get_keyid(sub, &keyid));
    assert_string_equal(keyid, "C2E7FDCC9CD59FB5");
    rnp_buffer_destroy(keyid);
    assert_rnp_success(rnp_key_get_primary_fprint(sub, &fp));
    assert_string_equal(fp, "73EDCC9119AFC8E2DBBDCDE50451409669FFDE3C");
    rnp_buffer_destroy(fp);
    rnp_key_handle_destroy(sub);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub));
    assert_rnp_success(rnp_key_get_primary_fprint(sub, &fp));
    assert_string_equal(fp, "73EDCC9119AFC8E2DBBDCDE50451409669FFDE3C");
    rnp_buffer_destroy(fp);
    rnp_key_handle_destroy(sub);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "C2E7FDCC9CD59FB5", &sub));
    assert_rnp_success(rnp_key_get_primary_fprint(sub, &fp));
    assert_string_equal(fp, "73EDCC9119AFC8E2DBBDCDE50451409669FFDE3C");
    rnp_buffer_destroy(fp);
    rnp_key_handle_destroy(sub);
    rnp_key_handle_destroy(key);

    /* two keys with subkeys with same material but different creation time */
    assert_true(import_pub_keys(ffi, "data/test_key_edge_cases/alice-2-keys-same-grip.pgp"));
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 4);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    assert_rnp_success(rnp_key_get_subkey_count(key, &count));
    assert_int_equal(count, 2);
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &sub));
    assert_rnp_success(rnp_key_get_keyid(sub, &keyid));
    assert_string_equal(keyid, "DD23CEB7FEBEFF17");
    rnp_buffer_destroy(keyid);
    assert_rnp_success(rnp_key_get_primary_fprint(sub, &fp));
    assert_string_equal(fp, "73EDCC9119AFC8E2DBBDCDE50451409669FFDE3C");
    rnp_buffer_destroy(fp);
    rnp_key_handle_destroy(sub);
    assert_rnp_success(rnp_key_get_subkey_at(key, 1, &sub));
    assert_rnp_success(rnp_key_get_keyid(sub, &keyid));
    assert_string_equal(keyid, "C2E7FDCC9CD59FB5");
    rnp_buffer_destroy(keyid);
    assert_rnp_success(rnp_key_get_primary_fprint(sub, &fp));
    assert_string_equal(fp, "73EDCC9119AFC8E2DBBDCDE50451409669FFDE3C");
    rnp_buffer_destroy(fp);
    rnp_key_handle_destroy(sub);
    rnp_key_handle_destroy(key);
    /* subkey should belong to original key */
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "467A2DE826ABA0DB", &key));
    assert_rnp_success(rnp_key_get_subkey_count(key, &count));
    assert_int_equal(count, 0);
    rnp_key_handle_destroy(key);

    /* key with signing subkey, where primary binding has different from subkey binding hash
     * algorithm */
    assert_true(import_pub_keys(ffi, "data/test_key_edge_cases/key-binding-hash-alg.asc"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "F81A30AA5DCBD01E", &key));
    bool valid = false;
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_true(valid);
    assert_true(key->pub->valid());
    rnp_key_handle_destroy(key);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD716516A7249711", &sub));
    assert_rnp_success(rnp_key_is_valid(sub, &valid));
    assert_true(valid);
    assert_true(sub->pub->valid());
    rnp_key_handle_destroy(sub);

    /* key and subkey both has 0 key expiration with corresponding subpacket */
    assert_true(import_pub_keys(ffi, "data/test_key_edge_cases/key-sub-0-expiry.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "6EFF45F2201AC5F8", &key));
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_true(valid);
    assert_true(key->pub->valid());
    uint32_t expiry = 0;
    assert_rnp_success(rnp_key_valid_till(key, &expiry));
    assert_int_equal(expiry, 0xffffffff);
    uint64_t expiry64 = 0;
    assert_rnp_success(rnp_key_valid_till64(key, &expiry64));
    assert_int_equal(expiry64, UINT64_MAX);

    rnp_key_handle_destroy(key);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "74F971795A5DDBC9", &sub));
    assert_rnp_success(rnp_key_is_valid(sub, &valid));
    assert_true(valid);
    assert_true(sub->pub->valid());
    assert_rnp_success(rnp_key_valid_till(sub, &expiry));
    assert_int_equal(expiry, 0xffffffff);
    assert_rnp_success(rnp_key_valid_till64(sub, &expiry64));
    assert_int_equal(expiry64, UINT64_MAX);
    rnp_key_handle_destroy(sub);

    /* key/subkey with expiration times in unhashed subpackets */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_pub_keys(ffi, "data/test_key_edge_cases/key-unhashed-subpkts.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7BC6709B15C23A4A", &key));
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_true(valid);
    assert_true(key->pub->valid());
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0);
    assert_rnp_success(rnp_key_valid_till(key, &expiry));
    assert_int_equal(expiry, 0xffffffff);
    assert_rnp_success(rnp_key_valid_till64(key, &expiry64));
    assert_int_equal(expiry64, UINT64_MAX);
    rnp_key_handle_destroy(key);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "1ED63EE56FADC34D", &sub));
    assert_true(sub->pub->valid());
    expiry = 100;
    assert_rnp_success(rnp_key_get_expiration(sub, &expiry));
    assert_int_equal(expiry, 0);
    rnp_key_handle_destroy(sub);

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_import_gpg_s2k)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    /* secret subkeys, exported via gpg --export-secret-subkeys (no primary secret key data) */
    rnp_input_t input = NULL;
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/alice-s2k-101-1-subs.pgp"));
    assert_rnp_success(rnp_import_keys(
      ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS, NULL));
    rnp_input_destroy(input);
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    bool secret = false;
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    bool locked = false;
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_true(locked);
    char *type = NULL;
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "GPG-None");
    rnp_buffer_destroy(type);
    assert_rnp_failure(rnp_key_unlock(key, "password"));
    size_t count = 0;
    assert_rnp_success(rnp_key_get_subkey_count(key, &count));
    assert_int_equal(count, 2);
    /* signing secret subkey */
    rnp_key_handle_t sub = NULL;
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &sub));
    char *keyid = NULL;
    assert_rnp_success(rnp_key_get_keyid(sub, &keyid));
    assert_string_equal(keyid, "22F3A217C0E439CB");
    rnp_buffer_destroy(keyid);
    secret = false;
    assert_rnp_success(rnp_key_have_secret(sub, &secret));
    assert_true(secret);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(sub, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_get_protection_type(sub, &type));
    assert_string_equal(type, "Encrypted-Hashed");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_unlock(sub, "password"));
    assert_rnp_success(rnp_key_is_locked(sub, &locked));
    assert_false(locked);
    rnp_key_handle_destroy(sub);
    /* encrypting secret subkey */
    assert_rnp_success(rnp_key_get_subkey_at(key, 1, &sub));
    assert_rnp_success(rnp_key_get_keyid(sub, &keyid));
    assert_string_equal(keyid, "DD23CEB7FEBEFF17");
    rnp_buffer_destroy(keyid);
    secret = false;
    assert_rnp_success(rnp_key_have_secret(sub, &secret));
    assert_true(secret);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(sub, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_get_protection_type(sub, &type));
    assert_string_equal(type, "Encrypted-Hashed");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_unlock(sub, "password"));
    assert_rnp_success(rnp_key_is_locked(sub, &locked));
    assert_false(locked);
    rnp_key_handle_destroy(sub);
    rnp_key_handle_destroy(key);

    /* save keyrings and reload */
    reload_keyrings(&ffi);

    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    secret = false;
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "GPG-None");
    rnp_buffer_destroy(type);
    count = 0;
    assert_rnp_success(rnp_key_get_subkey_count(key, &count));
    assert_int_equal(count, 2);
    /* signing secret subkey */
    sub = NULL;
    assert_rnp_success(rnp_key_get_subkey_at(key, 0, &sub));
    keyid = NULL;
    assert_rnp_success(rnp_key_get_keyid(sub, &keyid));
    assert_string_equal(keyid, "22F3A217C0E439CB");
    rnp_buffer_destroy(keyid);
    secret = false;
    assert_rnp_success(rnp_key_have_secret(sub, &secret));
    assert_true(secret);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(sub, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_get_protection_type(sub, &type));
    assert_string_equal(type, "Encrypted-Hashed");
    rnp_buffer_destroy(type);
    rnp_key_handle_destroy(sub);
    /* encrypting secret subkey */
    assert_rnp_success(rnp_key_get_subkey_at(key, 1, &sub));
    assert_rnp_success(rnp_key_get_keyid(sub, &keyid));
    assert_string_equal(keyid, "DD23CEB7FEBEFF17");
    rnp_buffer_destroy(keyid);
    secret = false;
    assert_rnp_success(rnp_key_have_secret(sub, &secret));
    assert_true(secret);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(sub, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_get_protection_type(sub, &type));
    assert_string_equal(type, "Encrypted-Hashed");
    rnp_buffer_destroy(type);
    rnp_key_handle_destroy(sub);
    rnp_key_handle_destroy(key);

    /* secret subkeys, and primary key stored on the smartcard by gpg */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/alice-s2k-101-2-card.pgp"));
    assert_rnp_success(rnp_import_keys(
      ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS, NULL));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    secret = false;
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "GPG-Smartcard");
    rnp_buffer_destroy(type);
    assert_rnp_failure(rnp_key_unlock(key, "password"));
    count = 0;
    assert_rnp_success(rnp_key_get_subkey_count(key, &count));
    assert_int_equal(count, 2);
    /* signing secret subkey */
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "22F3A217C0E439CB", &sub));
    secret = false;
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(sub, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_get_protection_type(sub, &type));
    assert_string_equal(type, "Encrypted-Hashed");
    rnp_buffer_destroy(type);
    rnp_key_handle_destroy(sub);
    /* encrypting secret subkey */
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub));
    secret = false;
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(sub, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_get_protection_type(sub, &type));
    assert_string_equal(type, "Encrypted-Hashed");
    rnp_buffer_destroy(type);
    rnp_key_handle_destroy(sub);
    rnp_key_handle_destroy(key);

    /* save keyrings and reload */
    reload_keyrings(&ffi);

    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    secret = false;
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    count = 0;
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "GPG-Smartcard");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_subkey_count(key, &count));
    assert_int_equal(count, 2);
    rnp_key_handle_destroy(key);

    /* load key with too large gpg_serial_len */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/alice-s2k-101-2-card-len.pgp"));
    assert_rnp_success(rnp_import_keys(
      ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS, NULL));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    secret = false;
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "GPG-Smartcard");
    rnp_buffer_destroy(type);
    assert_rnp_failure(rnp_key_unlock(key, "password"));
    rnp_key_handle_destroy(key);

    /* secret subkeys, and primary key stored with unknown gpg s2k */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/alice-s2k-101-3.pgp"));
    assert_rnp_success(rnp_import_keys(
      ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS, NULL));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    secret = false;
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "Unknown");
    rnp_buffer_destroy(type);
    assert_rnp_failure(rnp_key_unlock(key, "password"));
    count = 0;
    assert_rnp_success(rnp_key_get_subkey_count(key, &count));
    assert_int_equal(count, 2);
    rnp_key_handle_destroy(key);

    /* save keyrings and reload */
    reload_keyrings(&ffi);

    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    secret = false;
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    count = 0;
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "Unknown");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_subkey_count(key, &count));
    assert_int_equal(count, 2);
    rnp_key_handle_destroy(key);

    /* secret subkeys, and primary key stored with unknown s2k */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_rnp_success(
      rnp_input_from_path(&input, "data/test_key_edge_cases/alice-s2k-101-unknown.pgp"));
    assert_rnp_success(rnp_import_keys(
      ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS, NULL));
    rnp_input_destroy(input);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    secret = false;
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    locked = false;
    assert_rnp_success(rnp_key_is_locked(key, &locked));
    assert_true(locked);
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "Unknown");
    rnp_buffer_destroy(type);
    assert_rnp_failure(rnp_key_unlock(key, "password"));
    count = 0;
    assert_rnp_success(rnp_key_get_subkey_count(key, &count));
    assert_int_equal(count, 2);
    rnp_key_handle_destroy(key);

    /* save keyrings and reload */
    reload_keyrings(&ffi);

    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    secret = false;
    assert_rnp_success(rnp_key_have_secret(key, &secret));
    assert_true(secret);
    count = 0;
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "Unknown");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_subkey_count(key, &count));
    assert_int_equal(count, 2);
    rnp_key_handle_destroy(key);

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_get_protection_info)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    /* Edge cases - public key, NULL parameters, etc. */
    assert_true(import_pub_keys(ffi, "data/test_key_validity/alice-sub-pub.pgp"));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    char *type = NULL;
    assert_rnp_failure(rnp_key_get_protection_type(key, NULL));
    assert_rnp_failure(rnp_key_get_protection_type(NULL, &type));
    assert_rnp_failure(rnp_key_get_protection_type(key, &type));
    char *mode = NULL;
    assert_rnp_failure(rnp_key_get_protection_mode(key, NULL));
    assert_rnp_failure(rnp_key_get_protection_mode(NULL, &mode));
    assert_rnp_failure(rnp_key_get_protection_mode(key, &mode));
    char *cipher = NULL;
    assert_rnp_failure(rnp_key_get_protection_cipher(key, NULL));
    assert_rnp_failure(rnp_key_get_protection_cipher(NULL, &cipher));
    assert_rnp_failure(rnp_key_get_protection_cipher(key, &cipher));
    char *hash = NULL;
    assert_rnp_failure(rnp_key_get_protection_hash(key, NULL));
    assert_rnp_failure(rnp_key_get_protection_hash(NULL, &hash));
    assert_rnp_failure(rnp_key_get_protection_hash(key, &hash));
    size_t iterations = 0;
    assert_rnp_failure(rnp_key_get_protection_iterations(key, NULL));
    assert_rnp_failure(rnp_key_get_protection_iterations(NULL, &iterations));
    assert_rnp_failure(rnp_key_get_protection_iterations(key, &iterations));
    rnp_key_handle_destroy(key);

    /* Encrypted secret key with subkeys */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_true(import_all_keys(ffi, "data/test_key_validity/alice-sub-sec.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "Encrypted-Hashed");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(key, &mode));
    assert_string_equal(mode, "CFB");
    rnp_buffer_destroy(mode);
    assert_rnp_success(rnp_key_get_protection_cipher(key, &cipher));
    assert_string_equal(cipher, "AES128");
    rnp_buffer_destroy(cipher);
    assert_rnp_success(rnp_key_get_protection_hash(key, &hash));
    assert_string_equal(hash, "SHA1");
    rnp_buffer_destroy(hash);
    assert_rnp_success(rnp_key_get_protection_iterations(key, &iterations));
    assert_int_equal(iterations, 22020096);
    assert_rnp_success(rnp_key_unprotect(key, "password"));
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "None");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(key, &mode));
    assert_string_equal(mode, "None");
    rnp_buffer_destroy(mode);
    assert_rnp_failure(rnp_key_get_protection_cipher(key, &cipher));
    assert_rnp_failure(rnp_key_get_protection_hash(key, &hash));
    assert_rnp_failure(rnp_key_get_protection_iterations(key, &iterations));
    rnp_key_handle_destroy(key);

    rnp_key_handle_t sub = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub));
    assert_rnp_success(rnp_key_get_protection_type(sub, &type));
    assert_string_equal(type, "Encrypted-Hashed");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(sub, &mode));
    assert_string_equal(mode, "CFB");
    rnp_buffer_destroy(mode);
    assert_rnp_success(rnp_key_get_protection_cipher(sub, &cipher));
    assert_string_equal(cipher, "AES128");
    rnp_buffer_destroy(cipher);
    assert_rnp_success(rnp_key_get_protection_hash(sub, &hash));
    assert_string_equal(hash, "SHA1");
    rnp_buffer_destroy(hash);
    assert_rnp_success(rnp_key_get_protection_iterations(sub, &iterations));
    assert_int_equal(iterations, 22020096);
    assert_rnp_success(rnp_key_unprotect(sub, "password"));
    assert_rnp_success(rnp_key_get_protection_type(sub, &type));
    assert_string_equal(type, "None");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(sub, &mode));
    assert_string_equal(mode, "None");
    rnp_buffer_destroy(mode);
    assert_rnp_failure(rnp_key_get_protection_cipher(sub, &cipher));
    assert_rnp_failure(rnp_key_get_protection_hash(sub, &hash));
    assert_rnp_failure(rnp_key_get_protection_iterations(sub, &iterations));
    rnp_key_handle_destroy(sub);

    /* v3 secret key */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_pub_keys(ffi, "data/keyrings/4/pubring.pgp"));
    assert_true(import_sec_keys(ffi, "data/keyrings/4/secring.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7D0BC10E933404C9", &key));
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "Encrypted");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(key, &mode));
    assert_string_equal(mode, "CFB");
    rnp_buffer_destroy(mode);
    assert_rnp_success(rnp_key_get_protection_cipher(key, &cipher));
    assert_string_equal(cipher, "IDEA");
    rnp_buffer_destroy(cipher);
    assert_rnp_success(rnp_key_get_protection_hash(key, &hash));
    assert_string_equal(hash, "MD5");
    rnp_buffer_destroy(hash);
    assert_rnp_success(rnp_key_get_protection_iterations(key, &iterations));
    assert_int_equal(iterations, 1);
    assert_rnp_success(rnp_key_unprotect(key, "password"));
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "None");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(key, &mode));
    assert_string_equal(mode, "None");
    rnp_buffer_destroy(mode);
    assert_rnp_failure(rnp_key_get_protection_cipher(key, &cipher));
    assert_rnp_failure(rnp_key_get_protection_hash(key, &hash));
    assert_rnp_failure(rnp_key_get_protection_iterations(key, &iterations));
    rnp_key_handle_destroy(key);

    /* G10 keys */
    rnp_ffi_destroy(ffi);
    assert_rnp_success(rnp_ffi_create(&ffi, "KBX", "G10"));

    assert_true(load_keys_kbx_g10(
      ffi, "data/keyrings/3/pubring.kbx", "data/keyrings/3/private-keys-v1.d"));

    assert_rnp_success(rnp_locate_key(ffi, "keyid", "4BE147BB22DF1E60", &key));
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "Encrypted-Hashed");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(key, &mode));
    assert_string_equal(mode, "CBC");
    rnp_buffer_destroy(mode);
    assert_rnp_success(rnp_key_get_protection_cipher(key, &cipher));
    assert_string_equal(cipher, "AES128");
    rnp_buffer_destroy(cipher);
    assert_rnp_success(rnp_key_get_protection_hash(key, &hash));
    assert_string_equal(hash, "SHA1");
    rnp_buffer_destroy(hash);
    assert_rnp_success(rnp_key_get_protection_iterations(key, &iterations));
    assert_int_equal(iterations, 1024);
    assert_rnp_success(rnp_key_unprotect(key, "password"));
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "None");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(key, &mode));
    assert_string_equal(mode, "None");
    rnp_buffer_destroy(mode);
    assert_rnp_failure(rnp_key_get_protection_cipher(key, &cipher));
    assert_rnp_failure(rnp_key_get_protection_hash(key, &hash));
    assert_rnp_failure(rnp_key_get_protection_iterations(key, &iterations));
    rnp_key_handle_destroy(key);

    assert_rnp_success(rnp_locate_key(ffi, "keyid", "A49BAE05C16E8BC8", &sub));
    assert_rnp_success(rnp_key_get_protection_type(sub, &type));
    assert_string_equal(type, "Encrypted-Hashed");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(sub, &mode));
    assert_string_equal(mode, "CBC");
    rnp_buffer_destroy(mode);
    assert_rnp_success(rnp_key_get_protection_cipher(sub, &cipher));
    assert_string_equal(cipher, "AES128");
    rnp_buffer_destroy(cipher);
    assert_rnp_success(rnp_key_get_protection_hash(sub, &hash));
    assert_string_equal(hash, "SHA1");
    rnp_buffer_destroy(hash);
    assert_rnp_success(rnp_key_get_protection_iterations(sub, &iterations));
    assert_int_equal(iterations, 1024);
    assert_rnp_success(rnp_key_unprotect(sub, "password"));
    assert_rnp_success(rnp_key_get_protection_type(sub, &type));
    assert_string_equal(type, "None");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(sub, &mode));
    assert_string_equal(mode, "None");
    rnp_buffer_destroy(mode);
    assert_rnp_failure(rnp_key_get_protection_cipher(sub, &cipher));
    assert_rnp_failure(rnp_key_get_protection_hash(sub, &hash));
    assert_rnp_failure(rnp_key_get_protection_iterations(sub, &iterations));
    rnp_key_handle_destroy(sub);

    /* Secret subkeys, exported via gpg --export-secret-subkeys (no primary secret key data) */
    rnp_ffi_destroy(ffi);
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_all_keys(ffi, "data/test_key_edge_cases/alice-s2k-101-1-subs.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "GPG-None");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(key, &mode));
    assert_string_equal(mode, "Unknown");
    rnp_buffer_destroy(mode);
    assert_rnp_failure(rnp_key_get_protection_cipher(key, &cipher));
    assert_rnp_failure(rnp_key_get_protection_hash(key, &hash));
    assert_rnp_failure(rnp_key_get_protection_iterations(key, &iterations));
    rnp_key_handle_destroy(key);

    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub));
    assert_rnp_success(rnp_key_get_protection_type(sub, &type));
    assert_string_equal(type, "Encrypted-Hashed");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(sub, &mode));
    assert_string_equal(mode, "CFB");
    rnp_buffer_destroy(mode);
    assert_rnp_success(rnp_key_get_protection_cipher(sub, &cipher));
    assert_string_equal(cipher, "AES128");
    rnp_buffer_destroy(cipher);
    assert_rnp_success(rnp_key_get_protection_hash(sub, &hash));
    assert_string_equal(hash, "SHA1");
    rnp_buffer_destroy(hash);
    assert_rnp_success(rnp_key_get_protection_iterations(sub, &iterations));
    assert_int_equal(iterations, 30408704);
    assert_rnp_success(rnp_key_unprotect(sub, "password"));
    assert_rnp_success(rnp_key_get_protection_type(sub, &type));
    assert_string_equal(type, "None");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(sub, &mode));
    assert_string_equal(mode, "None");
    rnp_buffer_destroy(mode);
    assert_rnp_failure(rnp_key_get_protection_cipher(sub, &cipher));
    assert_rnp_failure(rnp_key_get_protection_hash(sub, &hash));
    assert_rnp_failure(rnp_key_get_protection_iterations(sub, &iterations));
    rnp_key_handle_destroy(sub);

    /* secret subkey is available, but primary key is stored on the smartcard by gpg */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_all_keys(ffi, "data/test_key_edge_cases/alice-s2k-101-2-card.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "GPG-Smartcard");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(key, &mode));
    assert_string_equal(mode, "Unknown");
    rnp_buffer_destroy(mode);
    assert_rnp_failure(rnp_key_get_protection_cipher(key, &cipher));
    assert_rnp_failure(rnp_key_get_protection_hash(key, &hash));
    assert_rnp_failure(rnp_key_get_protection_iterations(key, &iterations));
    rnp_key_handle_destroy(key);

    assert_rnp_success(rnp_locate_key(ffi, "keyid", "DD23CEB7FEBEFF17", &sub));
    assert_rnp_success(rnp_key_get_protection_type(sub, &type));
    assert_string_equal(type, "Encrypted-Hashed");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(sub, &mode));
    assert_string_equal(mode, "CFB");
    rnp_buffer_destroy(mode);
    assert_rnp_success(rnp_key_get_protection_cipher(sub, &cipher));
    assert_string_equal(cipher, "AES128");
    rnp_buffer_destroy(cipher);
    assert_rnp_success(rnp_key_get_protection_hash(sub, &hash));
    assert_string_equal(hash, "SHA1");
    rnp_buffer_destroy(hash);
    assert_rnp_success(rnp_key_get_protection_iterations(sub, &iterations));
    assert_int_equal(iterations, 30408704);
    assert_rnp_success(rnp_key_unprotect(sub, "password"));
    assert_rnp_success(rnp_key_get_protection_type(sub, &type));
    assert_string_equal(type, "None");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(sub, &mode));
    assert_string_equal(mode, "None");
    rnp_buffer_destroy(mode);
    assert_rnp_failure(rnp_key_get_protection_cipher(sub, &cipher));
    assert_rnp_failure(rnp_key_get_protection_hash(sub, &hash));
    assert_rnp_failure(rnp_key_get_protection_iterations(sub, &iterations));
    rnp_key_handle_destroy(sub);

    /* primary key is stored with unknown gpg s2k */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_all_keys(ffi, "data/test_key_edge_cases/alice-s2k-101-3.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "Unknown");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(key, &mode));
    assert_string_equal(mode, "Unknown");
    rnp_buffer_destroy(mode);
    assert_rnp_failure(rnp_key_get_protection_cipher(key, &cipher));
    assert_rnp_failure(rnp_key_get_protection_hash(key, &hash));
    assert_rnp_failure(rnp_key_get_protection_iterations(key, &iterations));
    rnp_key_handle_destroy(key);

    /* primary key is stored with unknown s2k */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_all_keys(ffi, "data/test_key_edge_cases/alice-s2k-101-unknown.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669FFDE3C", &key));
    assert_rnp_success(rnp_key_get_protection_type(key, &type));
    assert_string_equal(type, "Unknown");
    rnp_buffer_destroy(type);
    assert_rnp_success(rnp_key_get_protection_mode(key, &mode));
    assert_string_equal(mode, "Unknown");
    rnp_buffer_destroy(mode);
    assert_rnp_failure(rnp_key_get_protection_cipher(key, &cipher));
    assert_rnp_failure(rnp_key_get_protection_hash(key, &hash));
    assert_rnp_failure(rnp_key_get_protection_iterations(key, &iterations));
    rnp_key_handle_destroy(key);

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_key_remove)
{
    rnp_ffi_t ffi = NULL;
    test_ffi_init(&ffi);

    rnp_key_handle_t key0 = NULL;
    rnp_key_handle_t key0_sub0 = NULL;
    rnp_key_handle_t key0_sub1 = NULL;
    rnp_key_handle_t key0_sub2 = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key0));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "1ed63ee56fadc34d", &key0_sub0));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "1d7e8a5393c997a8", &key0_sub1));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "8a05b89fad5aded1", &key0_sub2));

    /* edge cases */
    assert_rnp_failure(rnp_key_remove(NULL, RNP_KEY_REMOVE_PUBLIC));
    assert_rnp_failure(rnp_key_remove(key0, 0));
    /* make sure we correctly remove public and secret keys */
    bool pub = false;
    assert_rnp_success(rnp_key_have_public(key0_sub2, &pub));
    assert_true(pub);
    bool sec = false;
    assert_rnp_success(rnp_key_have_secret(key0_sub2, &sec));
    assert_true(sec);
    assert_rnp_success(rnp_key_remove(key0_sub2, RNP_KEY_REMOVE_PUBLIC));
    pub = true;
    assert_rnp_success(rnp_key_have_public(key0_sub2, &pub));
    assert_false(pub);
    sec = false;
    assert_rnp_success(rnp_key_have_secret(key0_sub2, &sec));
    assert_true(sec);
    assert_rnp_failure(rnp_key_remove(key0_sub2, RNP_KEY_REMOVE_PUBLIC));
    rnp_key_handle_destroy(key0_sub2);
    /* locate it back */
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "8a05b89fad5aded1", &key0_sub2));
    assert_non_null(key0_sub2);
    pub = true;
    assert_rnp_success(rnp_key_have_public(key0_sub2, &pub));
    assert_false(pub);
    sec = false;
    assert_rnp_success(rnp_key_have_secret(key0_sub2, &sec));
    assert_true(sec);

    pub = false;
    assert_rnp_success(rnp_key_have_public(key0_sub0, &pub));
    assert_true(pub);
    sec = false;
    assert_rnp_success(rnp_key_have_secret(key0_sub0, &sec));
    assert_true(sec);
    assert_rnp_success(rnp_key_remove(key0_sub0, RNP_KEY_REMOVE_SECRET));
    pub = false;
    assert_rnp_success(rnp_key_have_public(key0_sub0, &pub));
    assert_true(pub);
    sec = true;
    assert_rnp_success(rnp_key_have_secret(key0_sub0, &sec));
    assert_false(sec);
    assert_rnp_failure(rnp_key_remove(key0_sub0, RNP_KEY_REMOVE_SECRET));
    rnp_key_handle_destroy(key0_sub0);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "1ed63ee56fadc34d", &key0_sub0));
    assert_non_null(key0_sub0);

    size_t count = 0;
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 6);
    count = 0;
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(count, 6);

    /* while there are 2 public and 1 secret subkey, this calculates only public */
    assert_rnp_success(rnp_key_get_subkey_count(key0, &count));
    assert_int_equal(count, 2);

    assert_rnp_success(rnp_key_remove(key0_sub0, RNP_KEY_REMOVE_PUBLIC));
    assert_rnp_success(rnp_key_get_subkey_count(key0, &count));
    assert_int_equal(count, 1);
    count = 0;
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 5);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(count, 6);

    assert_rnp_success(rnp_key_remove(key0_sub2, RNP_KEY_REMOVE_SECRET));
    assert_rnp_success(rnp_key_get_subkey_count(key0, &count));
    assert_int_equal(count, 1);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(count, 5);

    assert_rnp_success(rnp_key_remove(key0, RNP_KEY_REMOVE_PUBLIC | RNP_KEY_REMOVE_SECRET));
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 4);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(count, 4);

    rnp_key_handle_destroy(key0_sub1);
    /* key0_sub1 should be left in keyring */
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "1d7e8a5393c997a8", &key0_sub1));
    pub = false;
    assert_rnp_success(rnp_key_have_public(key0_sub1, &pub));
    assert_true(pub);
    sec = false;
    assert_rnp_success(rnp_key_have_secret(key0_sub1, &sec));
    assert_true(sec);

    rnp_key_handle_destroy(key0);
    rnp_key_handle_destroy(key0_sub0);
    rnp_key_handle_destroy(key0_sub1);
    rnp_key_handle_destroy(key0_sub2);

    /* let's import keys back */
    assert_true(import_pub_keys(ffi, "data/keyrings/1/pubring.gpg"));
    assert_true(import_sec_keys(ffi, "data/keyrings/1/secring.gpg"));

    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 7);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(count, 7);

    /* now try to remove the whole key */
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key0));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "1ed63ee56fadc34d", &key0_sub0));

    assert_rnp_failure(
      rnp_key_remove(key0_sub0, RNP_KEY_REMOVE_SECRET | RNP_KEY_REMOVE_SUBKEYS));
    assert_rnp_success(rnp_key_remove(key0_sub0, RNP_KEY_REMOVE_SECRET));
    assert_rnp_success(rnp_key_remove(key0_sub0, RNP_KEY_REMOVE_PUBLIC));

    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 6);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(count, 6);

    assert_rnp_success(rnp_key_remove(key0, RNP_KEY_REMOVE_SECRET | RNP_KEY_REMOVE_SUBKEYS));
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 6);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(count, 3);

    assert_rnp_success(rnp_key_remove(key0, RNP_KEY_REMOVE_PUBLIC | RNP_KEY_REMOVE_SUBKEYS));
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 3);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(count, 3);

    rnp_key_handle_destroy(key0);
    rnp_key_handle_destroy(key0_sub0);

    /* delete the second key all at once */
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "2fcadf05ffa501bb", &key0));
    assert_rnp_success(rnp_key_remove(
      key0, RNP_KEY_REMOVE_PUBLIC | RNP_KEY_REMOVE_SECRET | RNP_KEY_REMOVE_SUBKEYS));
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 0);
    assert_rnp_success(rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(count, 0);
    rnp_key_handle_destroy(key0);

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_literal_packet)
{
    rnp_ffi_t    ffi = NULL;
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    // init ffi
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    /* try rnp_decrypt() */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.literal"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_decrypt(ffi, input, output));
    uint8_t *buf = NULL;
    size_t   len = 0;
    rnp_output_memory_get_buf(output, &buf, &len, false);
    std::string out;
    out.assign((char *) buf, len);
    assert_true(out == file_to_str("data/test_messages/message.txt"));
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* try rnp_op_verify() */
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/message.txt.literal"));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    rnp_op_verify_t verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    rnp_output_memory_get_buf(output, &buf, &len, false);
    out.assign((char *) buf, len);
    assert_true(out == file_to_str("data/test_messages/message.txt"));
    char *mode = NULL;
    char *cipher = NULL;
    bool  valid = true;
    assert_rnp_success(rnp_op_verify_get_protection_info(verify, &mode, &cipher, &valid));
    assert_string_equal(mode, "none");
    assert_string_equal(cipher, "none");
    assert_false(valid);
    rnp_buffer_destroy(mode);
    rnp_buffer_destroy(cipher);
    size_t count = 255;
    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &count));
    assert_int_equal(count, 0);
    count = 255;
    assert_rnp_success(rnp_op_verify_get_recipient_count(verify, &count));
    assert_int_equal(count, 0);
    count = 255;
    assert_rnp_success(rnp_op_verify_get_symenc_count(verify, &count));
    assert_int_equal(count, 0);
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    rnp_ffi_destroy(ffi);
}

static bool
check_key_autocrypt(rnp_output_t       memout,
                    const std::string &keyid,
                    const std::string &subid,
                    const std::string &uid)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    uint8_t *buf = NULL;
    size_t   len = 0;
    if (rnp_output_memory_get_buf(memout, &buf, &len, false) || !buf || !len) {
        return false;
    }
    rnp_input_t input = NULL;
    if (!import_all_keys(ffi, buf, len)) {
        return false;
    }
    rnp_input_destroy(input);
    size_t count = 0;
    rnp_get_public_key_count(ffi, &count);
    if (count != 2) {
        return false;
    }
    rnp_get_secret_key_count(ffi, &count);
    if (count != 0) {
        return false;
    }
    rnp_key_handle_t key = NULL;
    if (rnp_locate_key(ffi, "keyid", keyid.c_str(), &key) || !key) {
        return false;
    }
    rnp_key_handle_t sub = NULL;
    if (rnp_locate_key(ffi, "keyid", subid.c_str(), &sub) || !sub) {
        return false;
    }
    if (!key->pub->valid() || !sub->pub->valid()) {
        return false;
    }
    if ((key->pub->sig_count() != 1) || (sub->pub->sig_count() != 1)) {
        return false;
    }
    if (!key->pub->can_sign() || !sub->pub->can_encrypt()) {
        return false;
    }
    if ((key->pub->uid_count() != 1) || (key->pub->get_uid(0).str != uid)) {
        return false;
    }
    rnp_key_handle_destroy(key);
    rnp_key_handle_destroy(sub);
    rnp_ffi_destroy(ffi);
    return true;
}

TEST_F(rnp_tests, test_ffi_key_export_autocrypt)
{
    rnp_ffi_t ffi = NULL;
    test_ffi_init(&ffi);

    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    rnp_key_handle_t sub = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "8a05b89fad5aded1", &sub));

    /* edge cases */
    assert_rnp_failure(rnp_key_export_autocrypt(key, NULL, NULL, NULL, 0));
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_failure(rnp_key_export_autocrypt(key, sub, NULL, output, 17));
    assert_rnp_failure(rnp_key_export_autocrypt(NULL, sub, "key0-uid0", output, 0));
    assert_rnp_failure(rnp_key_export_autocrypt(key, sub, NULL, output, 0));
    assert_rnp_failure(rnp_key_export_autocrypt(key, key, NULL, output, 0));
    assert_rnp_failure(rnp_key_export_autocrypt(key, key, "key0-uid0", output, 0));
    assert_rnp_failure(rnp_key_export_autocrypt(sub, sub, "key0-uid0", output, 0));
    assert_rnp_failure(rnp_key_export_autocrypt(sub, key, "key0-uid0", output, 0));
    assert_int_equal(output->dst.writeb, 0);

    /* export key + uid1 + sub2 */
    assert_rnp_success(rnp_key_export_autocrypt(key, sub, "key0-uid1", output, 0));
    assert_true(
      check_key_autocrypt(output, "7bc6709b15c23a4a", "8a05b89fad5aded1", "key0-uid1"));
    rnp_output_destroy(output);

    /* export key + uid0 + sub1 (fail) */
    rnp_key_handle_destroy(sub);
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "1d7e8a5393c997a8", &sub));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_failure(rnp_key_export_autocrypt(key, sub, "key0-uid0", output, 0));
    assert_int_equal(output->dst.writeb, 0);
    rnp_key_handle_destroy(sub);

    /* export key without specifying subkey */
    assert_rnp_success(rnp_key_export_autocrypt(key, NULL, "key0-uid2", output, 0));
    assert_true(
      check_key_autocrypt(output, "7bc6709b15c23a4a", "8a05b89fad5aded1", "key0-uid2"));
    rnp_output_destroy(output);

    /* remove first subkey and export again */
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "1ed63ee56fadc34d", &sub));
    assert_rnp_success(rnp_key_remove(sub, RNP_KEY_REMOVE_PUBLIC));
    rnp_key_handle_destroy(sub);
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_key_export_autocrypt(key, NULL, "key0-uid0", output, 0));
    assert_true(
      check_key_autocrypt(output, "7bc6709b15c23a4a", "8a05b89fad5aded1", "key0-uid0"));
    rnp_output_destroy(output);
    rnp_key_handle_destroy(key);

    /* primary key with encrypting capability, make sure subkey is exported */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/encrypting-primary.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "92091b7b76c50017", &key));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_key_export_autocrypt(
      key, NULL, "encrypting primary <encrypting_primary@rnp>", output, 0));
    assert_true(check_key_autocrypt(output,
                                    "92091b7b76c50017",
                                    "c2e243e872c1fe50",
                                    "encrypting primary <encrypting_primary@rnp>"));
    rnp_output_destroy(output);
    rnp_key_handle_destroy(key);

    /* export key with single uid and subkey */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/alice-sub-pub.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669ffde3c", &key));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_key_export_autocrypt(key, NULL, NULL, output, 0));
    assert_true(check_key_autocrypt(
      output, "0451409669ffde3c", "dd23ceb7febeff17", "Alice <alice@rnp>"));
    rnp_output_destroy(output);
    rnp_key_handle_destroy(key);

    /* export key with sign-only subkey: fail */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/alice-sign-sub-pub.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669ffde3c", &key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "22f3a217c0e439cb", &sub));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_failure(rnp_key_export_autocrypt(key, sub, NULL, output, 0));
    assert_int_equal(output->dst.writeb, 0);
    assert_rnp_failure(rnp_key_export_autocrypt(key, NULL, NULL, output, 0));
    assert_int_equal(output->dst.writeb, 0);
    rnp_output_destroy(output);
    rnp_key_handle_destroy(key);
    rnp_key_handle_destroy(sub);

    /* export key without subkey: fail */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_pub_keys(ffi, "data/test_key_validity/alice-pub.asc"));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669ffde3c", &key));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_failure(rnp_key_export_autocrypt(key, NULL, NULL, output, 0));
    assert_int_equal(output->dst.writeb, 0);
    rnp_output_destroy(output);
    rnp_key_handle_destroy(key);

    /* export secret key: make sure public is exported */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(import_all_keys(ffi, "data/test_key_validity/alice-sub-sec.pgp"));
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669ffde3c", &key));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_key_export_autocrypt(key, NULL, NULL, output, 0));
    assert_true(check_key_autocrypt(
      output, "0451409669ffde3c", "dd23ceb7febeff17", "Alice <alice@rnp>"));
    rnp_output_destroy(output);
    rnp_key_handle_destroy(key);

    /* make sure that only self-certification is exported */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    /* load key alice with 2 self-sigs, one of those is expired */
    assert_true(import_pub_keys(ffi, "data/test_key_validity/case9/pubring.gpg"));
    /* add one corrupted alice's signature and one valid from Basil */
    assert_true(import_pub_keys(ffi, "data/test_key_validity/case2/pubring.gpg"));

    assert_rnp_success(rnp_locate_key(ffi, "keyid", "0451409669ffde3c", &key));
    assert_int_equal(key->pub->sig_count(), 4);
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_key_export_autocrypt(key, NULL, NULL, output, 0));
    assert_true(check_key_autocrypt(
      output, "0451409669ffde3c", "dd23ceb7febeff17", "Alice <alice@rnp>"));
    rnp_output_destroy(output);
    rnp_key_handle_destroy(key);

    rnp_ffi_destroy(ffi);
}

/* This test checks that any exceptions thrown by the internal library
 * will not propagate beyond the FFI boundary.
 * In this case we (ab)use a callback to mimic this scenario.
 */
TEST_F(rnp_tests, test_ffi_exception)
{
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;

    // bad_alloc -> RNP_ERROR_OUT_OF_MEMORY
    {
        auto reader = [](void *app_ctx, void *buf, size_t len, size_t *read) {
            throw std::bad_alloc();
            return true;
        };
        assert_rnp_success(rnp_input_from_callback(&input, reader, NULL, NULL));
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_int_equal(RNP_ERROR_OUT_OF_MEMORY, rnp_output_pipe(input, output));
        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }

    // runtime_error -> RNP_ERROR_GENERIC
    {
        auto reader = [](void *app_ctx, void *buf, size_t len, size_t *read) {
            throw std::runtime_error("");
            return true;
        };
        assert_rnp_success(rnp_input_from_callback(&input, reader, NULL, NULL));
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_int_equal(RNP_ERROR_GENERIC, rnp_output_pipe(input, output));
        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }

    // everything else -> RNP_ERROR_GENERIC
    {
        auto reader = [](void *app_ctx, void *buf, size_t len, size_t *read) {
            throw 5;
            return true;
        };
        assert_rnp_success(rnp_input_from_callback(&input, reader, NULL, NULL));
        assert_rnp_success(rnp_output_to_memory(&output, 0));
        assert_int_equal(RNP_ERROR_GENERIC, rnp_output_pipe(input, output));
        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }
}

TEST_F(rnp_tests, test_ffi_key_protection_change)
{
    rnp_ffi_t ffi = NULL;
    test_ffi_init(&ffi);

    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    rnp_key_handle_t sub = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "8a05b89fad5aded1", &sub));

    assert_rnp_success(rnp_key_unprotect(key, "password"));
    assert_rnp_success(rnp_key_unprotect(sub, "password"));

    bool protect = true;
    assert_rnp_success(rnp_key_is_protected(key, &protect));
    assert_false(protect);
    protect = true;
    assert_rnp_success(rnp_key_is_protected(sub, &protect));
    assert_false(protect);

    assert_rnp_success(rnp_key_protect(key, "password2", "Camellia128", NULL, "SHA1", 0));
    assert_rnp_success(rnp_key_protect(sub, "password2", "Camellia256", NULL, "SHA512", 0));
    protect = false;
    assert_rnp_success(rnp_key_is_protected(key, &protect));
    assert_true(protect);
    protect = false;
    assert_rnp_success(rnp_key_is_protected(sub, &protect));
    assert_true(protect);

    rnp_key_handle_destroy(key);
    rnp_key_handle_destroy(sub);

    reload_keyrings(&ffi);

    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "8a05b89fad5aded1", &sub));

    protect = false;
    assert_rnp_success(rnp_key_is_protected(key, &protect));
    assert_true(protect);
    protect = false;
    assert_rnp_success(rnp_key_is_protected(sub, &protect));
    assert_true(protect);

    char *cipher = NULL;
    assert_rnp_success(rnp_key_get_protection_cipher(key, &cipher));
    assert_string_equal(cipher, "CAMELLIA128");
    rnp_buffer_destroy(cipher);
    char *hash = NULL;
    assert_rnp_success(rnp_key_get_protection_hash(key, &hash));
    assert_string_equal(hash, "SHA1");
    rnp_buffer_destroy(hash);
    cipher = NULL;
    assert_rnp_success(rnp_key_get_protection_cipher(sub, &cipher));
    assert_string_equal(cipher, "CAMELLIA256");
    rnp_buffer_destroy(cipher);
    hash = NULL;
    assert_rnp_success(rnp_key_get_protection_hash(sub, &hash));
    assert_string_equal(hash, "SHA512");
    rnp_buffer_destroy(hash);

    assert_rnp_failure(rnp_key_unlock(key, "password"));
    assert_rnp_failure(rnp_key_unlock(sub, "password"));

    assert_rnp_success(rnp_key_unlock(key, "password2"));
    assert_rnp_success(rnp_key_unlock(sub, "password2"));

    protect = false;
    assert_rnp_success(rnp_key_is_protected(key, &protect));
    assert_true(protect);
    protect = false;
    assert_rnp_success(rnp_key_is_protected(sub, &protect));
    assert_true(protect);

    assert_rnp_success(rnp_key_protect(key, "password3", "AES256", NULL, "SHA512", 10000000));
    assert_rnp_success(rnp_key_protect(sub, "password3", "AES128", NULL, "SHA1", 10000000));
    protect = false;
    assert_rnp_success(rnp_key_is_protected(key, &protect));
    assert_true(protect);
    protect = false;
    assert_rnp_success(rnp_key_is_protected(sub, &protect));
    assert_true(protect);

    rnp_key_handle_destroy(key);
    rnp_key_handle_destroy(sub);

    reload_keyrings(&ffi);

    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "8a05b89fad5aded1", &sub));

    protect = false;
    assert_rnp_success(rnp_key_is_protected(key, &protect));
    assert_true(protect);
    protect = false;
    assert_rnp_success(rnp_key_is_protected(sub, &protect));
    assert_true(protect);

    cipher = NULL;
    assert_rnp_success(rnp_key_get_protection_cipher(key, &cipher));
    assert_string_equal(cipher, "AES256");
    rnp_buffer_destroy(cipher);
    hash = NULL;
    assert_rnp_success(rnp_key_get_protection_hash(key, &hash));
    assert_string_equal(hash, "SHA512");
    rnp_buffer_destroy(hash);
    size_t iterations = 0;
    assert_rnp_success(rnp_key_get_protection_iterations(key, &iterations));
    assert_true(iterations >= 10000000);
    cipher = NULL;
    assert_rnp_success(rnp_key_get_protection_cipher(sub, &cipher));
    assert_string_equal(cipher, "AES128");
    rnp_buffer_destroy(cipher);
    hash = NULL;
    assert_rnp_success(rnp_key_get_protection_hash(sub, &hash));
    assert_string_equal(hash, "SHA1");
    rnp_buffer_destroy(hash);
    iterations = 0;
    assert_rnp_success(rnp_key_get_protection_iterations(sub, &iterations));
    assert_true(iterations >= 10000000);

    assert_rnp_failure(rnp_key_unlock(key, "password"));
    assert_rnp_failure(rnp_key_unlock(sub, "password"));

    assert_rnp_success(rnp_key_unlock(key, "password3"));
    assert_rnp_success(rnp_key_unlock(sub, "password3"));

    rnp_key_handle_destroy(key);
    rnp_key_handle_destroy(sub);

    rnp_ffi_destroy(ffi);
}
