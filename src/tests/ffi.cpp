/*
 * Copyright (c) 2017-2018 [Ribose Inc](https://www.ribose.com).
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

#include <rnp/rnp2.h>
#include "rnp_tests.h"
#include "support.h"
#include "utils.h"
#include <json.h>
#include <vector>
#include <string>

void
test_ffi_homedir(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    rnp_ffi_t         ffi = NULL;
    char *            homedir = NULL;
    size_t            homedir_size = 0;
    char *            path = NULL;
    size_t            path_size = 0;
    char *            pub_format = NULL;
    char *            pub_path = NULL;
    char *            sec_format = NULL;
    char *            sec_path = NULL;
    rnp_input_t       input = NULL;

    // get the default homedir (not a very thorough test)
    homedir = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_get_default_homedir(&homedir));
    assert_non_null(homedir);
    rnp_buffer_destroy(homedir);
    homedir = NULL;

    // homedir tests/data/keyrings/1
    assert_non_null(
      rnp_compose_path_ex(&homedir, &homedir_size, rstate->data_dir, "keyrings/1", NULL));
    // detect the formats+paths
    assert_int_equal(
      RNP_SUCCESS,
      rnp_detect_homedir_info(homedir, &pub_format, &pub_path, &sec_format, &sec_path));
    // check formats
    assert_int_equal(0, strcmp(pub_format, "GPG"));
    assert_int_equal(0, strcmp(sec_format, "GPG"));
    // check paths
    assert_non_null(rnp_compose_path_ex(
      &path, &path_size, rstate->data_dir, "keyrings/1/pubring.gpg", NULL));
    assert_int_equal(0, strcmp(pub_path, path));
    assert_non_null(rnp_compose_path_ex(
      &path, &path_size, rstate->data_dir, "keyrings/1/secring.gpg", NULL));
    assert_int_equal(0, strcmp(sec_path, path));
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, pub_format, sec_format));
    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, pub_path));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, sec_path));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
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
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    // homedir tests/data/keyrings/3
    assert_non_null(
      rnp_compose_path_ex(&homedir, &homedir_size, rstate->data_dir, "keyrings/3", NULL));
    // detect the formats+paths
    assert_int_equal(
      RNP_SUCCESS,
      rnp_detect_homedir_info(homedir, &pub_format, &pub_path, &sec_format, &sec_path));
    // check formats
    assert_int_equal(0, strcmp(pub_format, "KBX"));
    assert_int_equal(0, strcmp(sec_format, "G10"));
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, pub_format, sec_format));
    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, pub_path));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "KBX", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, sec_path));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "G10", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
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
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);
    // check grip (1)
    rnp_key_handle_t key = NULL;
    assert_int_equal(
      RNP_SUCCESS,
      rnp_locate_key(ffi, "grip", "63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59", &key));
    assert_non_null(key);
    char *grip = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_key_get_grip(key, &grip));
    assert_non_null(grip);
    assert_true(strcmp(grip, "63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59") == 0);
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
    assert_int_equal(RNP_SUCCESS, rnp_key_get_grip(key, &grip));
    assert_non_null(grip);
    assert_true(strcmp(grip, "7EAB41A2F46257C36F2892696F5A2F0432499AD3") == 0);
    rnp_buffer_destroy(grip);
    grip = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_key_handle_destroy(key));
    key = NULL;
    // cleanup
    rnp_ffi_destroy(ffi);

    // final cleanup
    free(homedir);
    free(path);
}

static void
load_test_data(const char *data_dir, const char *file, char **data, size_t *size)
{
    char *      path = NULL;
    struct stat st = {0};

    assert_non_null(data_dir);
    assert_non_null(file);
    assert_non_null(data);

    path = rnp_compose_path(data_dir, file, NULL);
    assert_non_null(path);

    assert_int_equal(0, stat(path, &st));
    if (size) {
        *size = st.st_size;
    }
    *data = (char *) calloc(1, st.st_size + 1);
    assert_non_null(*data);

    FILE *fp = fopen(path, "r");
    assert_non_null(fp);
    assert_int_equal(st.st_size, fread(*data, 1, st.st_size, fp));
    assert_int_equal(0, fclose(fp));
    free(path);
}

void
test_ffi_detect_key_format(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    char *            data = NULL;
    size_t            data_size = 0;
    char *            format = NULL;

    // GPG
    data = NULL;
    format = NULL;
    load_test_data(rstate->data_dir, "keyrings/1/pubring.gpg", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "GPG"));
    free(data);
    free(format);

    // GPG
    data = NULL;
    format = NULL;
    load_test_data(rstate->data_dir, "keyrings/1/secring.gpg", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "GPG"));
    free(data);
    free(format);
    format = NULL;

    // GPG (armored)
    data = NULL;
    format = NULL;
    load_test_data(rstate->data_dir, "keyrings/4/rsav3-p.asc", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "GPG"));
    free(data);
    free(format);

    // KBX
    data = NULL;
    format = NULL;
    load_test_data(rstate->data_dir, "keyrings/3/pubring.kbx", &data, &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "KBX"));
    free(data);
    free(format);

    // G10
    data = NULL;
    format = NULL;
    load_test_data(rstate->data_dir,
                   "keyrings/3/private-keys-v1.d/63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59.key",
                   &data,
                   &data_size);
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) data, data_size, &format));
    assert_int_equal(0, strcmp(format, "G10"));
    free(data);
    free(format);

    // invalid
    format = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_detect_key_format((uint8_t *) "ABC", 3, &format));
    assert_null(format);
}

void
test_ffi_load_keys(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    rnp_ffi_t         ffi = NULL;
    rnp_input_t       input = NULL;
    size_t            count;

    /* load public keys from pubring */
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // again
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(0, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    /* load public keys from secring */
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(0, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    /* load secret keys from secring */
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load secring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // again
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check counts
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(0, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;

    /* load secret keys from pubring */
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    // check counts
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(0, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
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
    load_test_data(rstate->data_dir, "keyrings/1/pubring.gpg", &pub_buf, &pub_buf_len);
    load_test_data(rstate->data_dir, "keyrings/1/secring.gpg", &sec_buf, &sec_buf_len);
    size_t   buf_len = pub_buf_len + sec_buf_len;
    uint8_t *buf = (uint8_t *) malloc(buf_len);
    memcpy(buf, pub_buf, pub_buf_len);
    memcpy(buf + pub_buf_len, sec_buf, sec_buf_len);
    free(pub_buf);
    free(sec_buf);

    /* load secret keys from pubring */
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load
    assert_int_equal(RNP_SUCCESS, rnp_input_from_memory(&input, buf, buf_len, true));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // again
    assert_int_equal(RNP_SUCCESS, rnp_input_from_memory(&input, buf, buf_len, true));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check counts
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    free(buf);
}

void
test_ffi_save_keys(void **state)
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
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // load secring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // save pubring
    pub_path = rnp_compose_path(temp_dir, "pubring.gpg", NULL);
    assert_false(rnp_file_exists(pub_path));
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, pub_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_save_keys(ffi, "GPG", output, RNP_LOAD_SAVE_PUBLIC_KEYS));
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_file_exists(pub_path));
    // save secring
    sec_path = rnp_compose_path(temp_dir, "secring.gpg", NULL);
    assert_false(rnp_file_exists(sec_path));
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, sec_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_save_keys(ffi, "GPG", output, RNP_LOAD_SAVE_SECRET_KEYS));
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_file_exists(sec_path));
    // save pubring && secring
    both_path = rnp_compose_path(temp_dir, "bothring.gpg", NULL);
    assert_false(rnp_file_exists(both_path));
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, both_path));
    assert_int_equal(
      RNP_SUCCESS,
      rnp_save_keys(
        ffi, "GPG", output, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS));
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_file_exists(both_path));
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    // start over (read from the saved locations)
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, pub_path));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // load secring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, sec_path));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check the counts
    count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    // load both keyrings from the single file
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load pubring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, both_path));
    assert_non_null(input);
    assert_int_equal(
      RNP_SUCCESS,
      rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check the counts. We should get both secret and public keys, since public keys are
    // extracted from the secret ones.
    count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(7, count);
    count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(7, count);
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    free(pub_path);
    free(sec_path);
    free(both_path);

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "KBX", "G10"));
    // load pubring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/3/pubring.kbx"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "KBX", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // load secring
    assert_int_equal(RNP_SUCCESS,
                     rnp_input_from_path(&input, "data/keyrings/3/private-keys-v1.d"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "G10", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // save pubring
    pub_path = rnp_compose_path(temp_dir, "pubring.kbx", NULL);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, pub_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_save_keys(ffi, "KBX", output, RNP_LOAD_SAVE_PUBLIC_KEYS));
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_file_exists(pub_path));
    // save secring to file - will fail for G10
    sec_path = rnp_compose_path(temp_dir, "secring.file", NULL);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, sec_path));
    assert_int_not_equal(RNP_SUCCESS,
                         rnp_save_keys(ffi, "G10", output, RNP_LOAD_SAVE_SECRET_KEYS));
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    free(sec_path);
    // save secring
    sec_path = rnp_compose_path(temp_dir, "private-keys-v1.d", NULL);
    assert_false(rnp_dir_exists(sec_path));
    assert_int_equal(0, mkdir(sec_path, S_IRWXU));
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, sec_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_save_keys(ffi, "G10", output, RNP_LOAD_SAVE_SECRET_KEYS));
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_true(rnp_dir_exists(sec_path));
    // cleanup
    rnp_ffi_destroy(ffi);
    ffi = NULL;
    // start over (read from the saved locations)
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "KBX", "G10"));
    // load pubring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, pub_path));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "KBX", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // load secring
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, sec_path));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "G10", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // check the counts
    count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    count = 0;
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
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

#define TBL_MAX_USERIDS 4
typedef struct key_tbl_t {
    const uint8_t *key_data;
    size_t         key_data_size;
    bool           secret;
    const char *   keyid;
    const char *   grip;
    const char *   userids[TBL_MAX_USERIDS + 1];
} key_tbl_t;

static void
tbl_getkeycb(rnp_ffi_t   ffi,
             void *      app_ctx,
             const char *identifier_type,
             const char *identifier,
             bool        secret)
{
    key_tbl_t *found = NULL;
    for (key_tbl_t *tbl = (key_tbl_t *) app_ctx; tbl && tbl->key_data && !found; tbl++) {
        if (tbl->secret != secret) {
            continue;
        }
        if (!strcmp(identifier_type, "keyid") && !strcmp(identifier, tbl->keyid)) {
            found = tbl;
            break;
        } else if (!strcmp(identifier_type, "grip") && !strcmp(identifier, tbl->grip)) {
            found = tbl;
            break;
        } else if (!strcmp(identifier_type, "userid")) {
            for (size_t i = 0; i < TBL_MAX_USERIDS; i++) {
                if (!strcmp(identifier, tbl->userids[i])) {
                    found = tbl;
                    break;
                }
            }
        }
    }
    if (found) {
        char *format = NULL;
        assert_rnp_success(
          rnp_detect_key_format(found->key_data, found->key_data_size, &format));
        assert_non_null(format);
        uint32_t    flags = secret ? RNP_LOAD_SAVE_SECRET_KEYS : RNP_LOAD_SAVE_PUBLIC_KEYS;
        rnp_input_t input = NULL;
        assert_rnp_success(
          rnp_input_from_memory(&input, found->key_data, found->key_data_size, true));
        assert_non_null(input);
        assert_rnp_success(rnp_load_keys(ffi, format, input, flags));
        free(format);
        assert_rnp_success(rnp_input_destroy(input));
        input = NULL;
    }
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

static bool
getpasscb(rnp_ffi_t        ffi,
          void *           app_ctx,
          rnp_key_handle_t key,
          const char *     pgp_context,
          char *           buf,
          size_t           buf_len)
{
    strcpy(buf, (const char *) app_ctx);
    return true;
}

static bool
getpasscb_once(rnp_ffi_t        ffi,
               void *           app_ctx,
               rnp_key_handle_t key,
               const char *     pgp_context,
               char *           buf,
               size_t           buf_len)
{
    const char **pass = (const char **) app_ctx;
    if (!*pass) {
        return false;
    }
    strcpy(buf, *pass);
    *pass = NULL;
    return true;
}

static void
check_key_properties(rnp_key_handle_t key,
                     bool             primary_exptected,
                     bool             have_public_expected,
                     bool             have_secret_expected)
{
    bool isprimary = !primary_exptected;
    assert_int_equal(RNP_SUCCESS, rnp_key_is_primary(key, &isprimary));
    assert_true(isprimary == primary_exptected);
    bool issub = primary_exptected;
    assert_int_equal(RNP_SUCCESS, rnp_key_is_sub(key, &issub));
    assert_true(issub == !primary_exptected);
    bool have_public = !have_public_expected;
    assert_int_equal(RNP_SUCCESS, rnp_key_have_public(key, &have_public));
    assert_true(have_public == have_public_expected);
    bool have_secret = !have_secret_expected;
    assert_int_equal(RNP_SUCCESS, rnp_key_have_secret(key, &have_secret));
    assert_true(have_secret == have_secret_expected);
}

void
test_ffi_keygen_json_pair(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    rnp_ffi_t         ffi = NULL;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    // load our JSON
    load_test_data(rstate->data_dir, "test_ffi_json/generate-pair.json", &json, NULL);

    // generate the keys
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
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
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "primary", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", grip, &primary));
        assert_non_null(primary);
    }
    // get a handle for the sub
    rnp_key_handle_t sub = NULL;
    {
        json_object *jsokey = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "sub", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", grip, &sub));
        assert_non_null(sub);
    }
    // cleanup
    json_object_put(parsed_results);

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(2, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(2, count);

    // check some key properties
    check_key_properties(primary, true, true, true);
    check_key_properties(sub, false, true, true);

    // cleanup
    rnp_key_handle_destroy(primary);
    rnp_key_handle_destroy(sub);
    rnp_ffi_destroy(ffi);
}

void
test_ffi_keygen_json_primary(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    rnp_ffi_t         ffi = NULL;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    // load our JSON
    load_test_data(rstate->data_dir, "test_ffi_json/generate-primary.json", &json, NULL);

    // generate the keys
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
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
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "primary", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", grip, &primary));
        assert_non_null(primary);
    }
    // cleanup
    json_object_put(parsed_results);
    parsed_results = NULL;

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(1, count);

    // check some key properties
    check_key_properties(primary, true, true, true);

    // cleanup
    rnp_key_handle_destroy(primary);
    rnp_ffi_destroy(ffi);
}

/* This test generates a primary key, and then a subkey (separately).
 */
void
test_ffi_keygen_json_sub(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;
    rnp_ffi_t         ffi = NULL;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    // generate our primary key
    load_test_data(rstate->data_dir, "test_ffi_json/generate-primary.json", &json, NULL);
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    free(json);
    assert_non_null(results);
    // check key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
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
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "primary", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        primary_grip = strdup(json_object_get_string(jsogrip));
        assert_non_null(primary_grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", primary_grip, &primary));
        assert_non_null(primary);
    }
    // cleanup
    json_object_put(parsed_results);
    parsed_results = NULL;

    // load our JSON template
    load_test_data(rstate->data_dir, "test_ffi_json/generate-sub.json", &json, NULL);
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
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
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
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "sub", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", grip, &sub));
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
    check_key_properties(primary, true, true, true);
    check_key_properties(sub, false, true, true);

    // cleanup
    rnp_key_handle_destroy(primary);
    rnp_key_handle_destroy(sub);
    rnp_ffi_destroy(ffi);
}

void
test_ffi_add_userid(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    rnp_ffi_t         ffi = NULL;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;

    const char *new_userid = "my new userid <user@example.com>";

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));

    // load our JSON
    load_test_data(rstate->data_dir, "test_ffi_json/generate-primary.json", &json, NULL);

    // generate the keys
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    assert_non_null(results);
    rnp_buffer_destroy(results);
    results = NULL;
    free(json);
    json = NULL;

    // check the key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
    assert_int_equal(1, count);

    rnp_key_handle_t key_handle = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "userid", "test0", &key_handle));
    assert_non_null(key_handle);

    assert_int_equal(RNP_SUCCESS, rnp_key_get_uid_count(key_handle, &count));
    assert_int_equal(1, count);

    // protect+lock the key
    assert_int_equal(RNP_SUCCESS,
                     rnp_key_protect(key_handle, "pass", "SM4", "CFB", "SM3", 999999));
    assert_int_equal(RNP_SUCCESS, rnp_key_lock(key_handle));

    // add the userid (no pass provider, should fail)
    assert_int_equal(
      RNP_ERROR_BAD_PASSWORD,
      rnp_key_add_uid(key_handle, new_userid, "SHA256", 2147317200, 0x00, false));

    // actually add the userid
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "pass"));
    assert_int_equal(
      RNP_SUCCESS, rnp_key_add_uid(key_handle, new_userid, "SHA256", 2147317200, 0x00, false));

    assert_int_equal(RNP_SUCCESS, rnp_key_get_uid_count(key_handle, &count));
    assert_int_equal(2, count);

    rnp_key_handle_t key_handle2 = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "userid", new_userid, &key_handle2));
    assert_non_null(key_handle2);

    rnp_key_handle_destroy(key_handle);
    rnp_key_handle_destroy(key_handle2);
    rnp_ffi_destroy(ffi);
}

void
test_ffi_keygen_json_sub_pass_required(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    char *            json = NULL;
    char *            results = NULL;
    size_t            count = 0;
    rnp_ffi_t         ffi = NULL;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, unused_getpasscb, NULL));

    // generate our primary key
    load_test_data(rstate->data_dir, "test_ffi_json/generate-primary.json", &json, NULL);
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
    free(json);
    assert_non_null(results);
    // check key counts
    assert_int_equal(RNP_SUCCESS, rnp_get_public_key_count(ffi, &count));
    assert_int_equal(1, count);
    assert_int_equal(RNP_SUCCESS, rnp_get_secret_key_count(ffi, &count));
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
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "primary", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        primary_grip = strdup(json_object_get_string(jsogrip));
        assert_non_null(primary_grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", primary_grip, &primary));
        assert_non_null(primary);
    }
    // cleanup
    json_object_put(parsed_results);
    parsed_results = NULL;

    // protect+lock the primary key
    assert_int_equal(RNP_SUCCESS, rnp_key_protect(primary, "pass123", NULL, NULL, NULL, 0));
    assert_int_equal(RNP_SUCCESS, rnp_key_lock(primary));
    rnp_key_handle_destroy(primary);
    primary = NULL;

    // load our JSON template
    load_test_data(rstate->data_dir, "test_ffi_json/generate-sub.json", &json, NULL);
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

    // generate the subkey (no getpasscb, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, unused_getkeycb, NULL));
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, NULL, NULL));
    assert_int_not_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));

    // generate the subkey (wrong pass, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "wrong"));
    assert_int_not_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));

    // generate the subkey
    assert_int_equal(RNP_SUCCESS,
                     rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "pass123"));
    assert_int_equal(RNP_SUCCESS, rnp_generate_key_json(ffi, json, &results));
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
        assert_int_equal(TRUE, json_object_object_get_ex(parsed_results, "sub", &jsokey));
        assert_non_null(jsokey);
        json_object *jsogrip = NULL;
        assert_int_equal(TRUE, json_object_object_get_ex(jsokey, "grip", &jsogrip));
        assert_non_null(jsogrip);
        const char *grip = json_object_get_string(jsogrip);
        assert_non_null(grip);
        assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "grip", grip, &sub));
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

void
test_ffi_encrypt_pass(void **state)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *     plaintext = "data1";

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    // write out some data
    FILE *fp = fopen("plaintext", "w");
    assert_non_null(fp);
    assert_int_equal(1, fwrite(plaintext, strlen(plaintext), 1, fp));
    assert_int_equal(0, fclose(fp));

    // create input+output w/ bad paths (should fail)
    input = NULL;
    assert_int_not_equal(RNP_SUCCESS, rnp_input_from_path(&input, "noexist"));
    assert_null(input);
    assert_int_not_equal(RNP_SUCCESS, rnp_output_to_path(&output, ""));
    assert_null(output);

    // create input+output
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "plaintext"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "encrypted"));
    assert_non_null(output);
    // create encrypt operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_create(&op, ffi, input, output));
    // add password (using all defaults)
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_add_password(op, "pass1", NULL, 0, NULL));
    // add password
    assert_int_equal(RNP_SUCCESS,
                     rnp_op_encrypt_add_password(op, "pass2", "SM3", 12345, "Twofish"));
    // set the data encryption cipher
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_set_cipher(op, "CAST5"));
    // execute the operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_execute(op));

    // make sure the output file was created
    assert_true(rnp_file_exists("encrypted"));

    // cleanup
    assert_int_equal(RNP_SUCCESS, rnp_input_destroy(input));
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_destroy(op));
    op = NULL;

    /* decrypt */

    // decrypt (no pass provider, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, NULL, NULL));
    assert_int_not_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // decrypt (wrong pass, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    const char *pass = "wrong1";
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb_once, &pass));
    assert_int_not_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // decrypt (pass1)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "pass1"));
    assert_int_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // read in the decrypted file
    pgp_memory_t mem = {0};
    assert_true(pgp_mem_readfile(&mem, "decrypted"));
    // compare
    assert_int_equal(mem.length, strlen(plaintext));
    assert_true(memcmp(mem.buf, plaintext, strlen(plaintext)) == 0);
    // cleanup
    pgp_memory_release(&mem);
    unlink("decrypted");

    // decrypt (pass2)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "pass2"));
    assert_int_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // read in the decrypted file
    mem = (pgp_memory_t){0};
    assert_true(pgp_mem_readfile(&mem, "decrypted"));
    // compare
    assert_int_equal(mem.length, strlen(plaintext));
    assert_true(memcmp(mem.buf, plaintext, strlen(plaintext)) == 0);
    // cleanup
    pgp_memory_release(&mem);

    // final cleanup
    rnp_ffi_destroy(ffi);
}

void
test_ffi_encrypt_pk(void **state)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *     plaintext = "data1";

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    // write out some data
    FILE *fp = fopen("plaintext", "w");
    assert_non_null(fp);
    assert_int_equal(1, fwrite(plaintext, strlen(plaintext), 1, fp));
    assert_int_equal(0, fclose(fp));

    // create input+output
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "plaintext"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "encrypted"));
    assert_non_null(output);
    // create encrypt operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_create(&op, ffi, input, output));
    // add recipients
    rnp_key_handle_t key = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "userid", "key0-uid2", &key));
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_add_recipient(op, key));
    rnp_key_handle_destroy(key);
    key = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "userid", "key1-uid1", &key));
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_add_recipient(op, key));
    rnp_key_handle_destroy(key);
    key = NULL;
    // set the data encryption cipher
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_set_cipher(op, "CAST5"));
    // execute the operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_execute(op));

    // make sure the output file was created
    assert_true(rnp_file_exists("encrypted"));

    // cleanup
    assert_int_equal(RNP_SUCCESS, rnp_input_destroy(input));
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_destroy(op));
    op = NULL;

    /* decrypt */

    // decrypt (no pass provider, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, NULL, NULL));
    assert_int_not_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // decrypt (wrong pass, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    const char *pass = "wrong1";
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_pass_provider(ffi, getpasscb_once, &pass));
    assert_int_not_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // decrypt
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS,
                     rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "password"));
    assert_int_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // read in the decrypted file
    pgp_memory_t mem = {0};
    assert_true(pgp_mem_readfile(&mem, "decrypted"));
    // compare
    assert_int_equal(mem.length, strlen(plaintext));
    assert_true(memcmp(mem.buf, plaintext, strlen(plaintext)) == 0);
    // cleanup
    pgp_memory_release(&mem);
    // final cleanup
    rnp_ffi_destroy(ffi);
}

void
test_ffi_encrypt_pk_key_provider(void **state)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *     plaintext = "data1";
    uint8_t *        primary_sec_key_data = NULL;
    size_t           primary_sec_size = 0;
    uint8_t *        sub_sec_key_data = NULL;
    size_t           sub_sec_size = 0;

    /* first, let's generate some encrypted data */
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_non_null(ffi);
    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    // write out some data
    FILE *fp = fopen("plaintext", "w");
    assert_non_null(fp);
    assert_int_equal(1, fwrite(plaintext, strlen(plaintext), 1, fp));
    assert_int_equal(0, fclose(fp));
    // create input+output
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "plaintext"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "encrypted"));
    assert_non_null(output);
    // create encrypt operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_create(&op, ffi, input, output));
    // add recipient 1
    rnp_key_handle_t key = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "userid", "key0-uid2", &key));
    assert_non_null(key);
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_add_recipient(op, key));
    // cleanup
    assert_int_equal(RNP_SUCCESS, rnp_key_handle_destroy(key));
    key = NULL;
    // add recipient 2
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "userid", "key1-uid1", &key));
    assert_non_null(key);
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_add_recipient(op, key));
    // save the primary key data for later
    assert_int_equal(RNP_SUCCESS,
                     rnp_get_secret_key_data(key, &primary_sec_key_data, &primary_sec_size));
    assert_non_null(primary_sec_key_data);
    assert_int_equal(RNP_SUCCESS, rnp_key_handle_destroy(key));
    key = NULL;
    // save the appropriate encrypting subkey for the key provider to use during decryption
    // later
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "keyid", "54505A936A4A970E", &key));
    assert_non_null(key);
    assert_int_equal(RNP_SUCCESS,
                     rnp_get_secret_key_data(key, &sub_sec_key_data, &sub_sec_size));
    assert_non_null(sub_sec_key_data);
    // cleanup
    assert_int_equal(RNP_SUCCESS, rnp_key_handle_destroy(key));
    key = NULL;
    // set the data encryption cipher
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_set_cipher(op, "CAST5"));
    // execute the operation
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_execute(op));
    // make sure the output file was created
    assert_true(rnp_file_exists("encrypted"));
    // cleanup
    assert_int_equal(RNP_SUCCESS, rnp_input_destroy(input));
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_output_destroy(output));
    output = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_op_encrypt_destroy(op));
    op = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_ffi_destroy(ffi));
    ffi = NULL;

    /* decrypt */
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load the primary
    input = NULL;
    assert_int_equal(
      RNP_SUCCESS,
      rnp_input_from_memory(&input, primary_sec_key_data, primary_sec_size, true));
    assert_non_null(input);
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    // decrypt (no key to decrypt, should fail)
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_ERROR_NO_SUITABLE_KEY, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // key_data key_data_size secret keyid grip userids
    const key_tbl_t keydb[] = {
      {sub_sec_key_data, sub_sec_size, true, "54505A936A4A970E", NULL, {NULL}}, {0}};

    // decrypt
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "password"));
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_int_equal(RNP_SUCCESS, rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_SUCCESS, rnp_ffi_set_key_provider(ffi, tbl_getkeycb, (void *) keydb));
    assert_int_equal(RNP_SUCCESS, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // read in the decrypted file
    pgp_memory_t mem = {0};
    assert_true(pgp_mem_readfile(&mem, "decrypted"));
    // compare
    assert_int_equal(mem.length, strlen(plaintext));
    assert_true(memcmp(mem.buf, plaintext, strlen(plaintext)) == 0);
    // cleanup
    pgp_memory_release(&mem);
    // final cleanup
    rnp_ffi_destroy(ffi);
    free(sub_sec_key_data);
    free(primary_sec_key_data);
}

void
test_ffi_encrypt_and_sign(void **state)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *     plaintext = "data1";

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    // write out some data
    FILE *fp = fopen("plaintext", "w");
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
    // add recipients
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "key0-uid2", &key));
    assert_rnp_success(rnp_op_encrypt_add_recipient(op, key));
    rnp_key_handle_destroy(key);
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "key1-uid1", &key));
    assert_rnp_success(rnp_op_encrypt_add_recipient(op, key));
    rnp_key_handle_destroy(key);
    key = NULL;
    // set the data encryption cipher
    assert_rnp_success(rnp_op_encrypt_set_cipher(op, "CAST5"));
    // enable armoring
    assert_rnp_success(rnp_op_encrypt_set_armor(op, true));
    // add signature
    const uint32_t issued = 1516211899;  // Unix epoch, nowish
    const uint32_t expires = 1000000000; // expires later
    assert_rnp_success(rnp_op_encrypt_set_hash(op, "SHA256"));
    assert_rnp_success(rnp_op_encrypt_set_creation_time(op, issued));
    assert_rnp_success(rnp_op_encrypt_set_expiration_time(op, expires));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "key1-uid1", &key));
    assert_rnp_success(rnp_op_encrypt_add_signature(op, key, NULL));
    rnp_key_handle_destroy(key);
    key = NULL;
    // execute the operation
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "password"));
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

    /* decrypt */

    // decrypt (no pass provider, should fail)
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, NULL, NULL));
    assert_rnp_failure(rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // decrypt (wrong pass, should fail)
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    const char *pass = "wrong1";
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb_once, &pass));
    assert_rnp_failure(rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // decrypt
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "password"));
    assert_rnp_success(rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // read in the decrypted file
    pgp_memory_t mem = {0};
    assert_true(pgp_mem_readfile(&mem, "decrypted"));
    // compare
    assert_int_equal(mem.length, strlen(plaintext));
    assert_true(memcmp(mem.buf, plaintext, strlen(plaintext)) == 0);
    // cleanup
    pgp_memory_release(&mem);

    // verify and check signatures
    rnp_op_verify_t verify;
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "verified"));
    assert_non_null(output);
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "password"));

    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    rnp_op_verify_signature_t sig;
    size_t                    sig_count;
    uint32_t                  sig_create;
    uint32_t                  sig_expires;
    char *                    hname = NULL;

    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sig_count));
    assert_int_equal(sig_count, 1);
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 0, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    assert_rnp_success(rnp_op_verify_signature_get_times(sig, &sig_create, &sig_expires));
    assert_int_equal(sig_create, issued);
    assert_int_equal(sig_expires, expires);
    assert_rnp_success(rnp_op_verify_signature_get_hash(sig, &hname));
    assert_string_equal(hname, "SHA256");
    rnp_buffer_destroy(hname);
    hname = NULL;
    // cleanup
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // read in the decrypted file
    assert_true(pgp_mem_readfile(&mem, "verified"));
    // compare
    assert_int_equal(mem.length, strlen(plaintext));
    assert_true(memcmp(mem.buf, plaintext, strlen(plaintext)) == 0);
    // cleanup
    pgp_memory_release(&mem);

    // final cleanup
    rnp_ffi_destroy(ffi);
}

static void
test_ffi_init(void **state, rnp_ffi_t *ffi)
{
    // setup FFI
    assert_rnp_success(rnp_ffi_create(ffi, "GPG", "GPG"));

    // load our keyrings
    rnp_input_t input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS,
                     rnp_load_keys(*ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_int_equal(RNP_SUCCESS,
                     rnp_load_keys(*ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
}

static void
test_ffi_init_sign_file_input(void **state, rnp_input_t *input, rnp_output_t *output)
{
    const char *plaintext = "this is some data that will be signed";

    // write out some data
    FILE *fp = fopen("plaintext", "w");
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
test_ffi_init_sign_memory_input(void **state, rnp_input_t *input, rnp_output_t *output)
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
test_ffi_init_verify_file_input(void **state, rnp_input_t *input, rnp_output_t *output)
{
    // create input+output
    assert_rnp_success(rnp_input_from_path(input, "signed"));
    assert_non_null(*input);
    assert_rnp_success(rnp_output_to_path(output, "recovered"));
    assert_non_null(*output);
}

static void
test_ffi_init_verify_detached_file_input(void **      state,
                                         rnp_input_t *input,
                                         rnp_input_t *signature)
{
    assert_rnp_success(rnp_input_from_path(input, "plaintext"));
    assert_non_null(*input);
    assert_rnp_success(rnp_input_from_path(signature, "signed"));
    assert_non_null(*signature);
}

static void
test_ffi_init_verify_memory_input(void **       state,
                                  rnp_input_t * input,
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
test_ffi_setup_signatures(void **state, rnp_ffi_t *ffi, rnp_op_sign_t *op)
{
    // set signature times
    const uint32_t issued = 1516211899;  // Unix epoch, nowish
    const uint32_t expires = 1000000000; // expires later

    assert_rnp_success(rnp_op_sign_set_armor(*op, true));
    assert_rnp_success(rnp_op_sign_set_hash(*op, "SHA256"));
    assert_rnp_success(rnp_op_sign_set_creation_time(*op, issued));
    assert_rnp_success(rnp_op_sign_set_expiration_time(*op, expires));

    // set pass provider
    assert_rnp_success(rnp_ffi_set_pass_provider(*ffi, getpasscb, (void *) "password"));

    // set signature key
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(*ffi, "userid", "key0-uid2", &key));
    assert_rnp_success(rnp_op_sign_add_signature(*op, key, NULL));
    assert_rnp_success(rnp_key_handle_destroy(key));
}

static void
test_ffi_check_signatures(void **state, rnp_op_verify_t *verify)
{
    rnp_op_verify_signature_t sig;
    size_t                    sig_count;
    uint32_t                  sig_create;
    uint32_t                  sig_expires;
    char *                    hname = NULL;
    const uint32_t            issued = 1516211899;  // Unix epoch, nowish
    const uint32_t            expires = 1000000000; // expires later

    assert_rnp_success(rnp_op_verify_get_signature_count(*verify, &sig_count));
    assert_int_equal(sig_count, 1);
    assert_rnp_success(rnp_op_verify_get_signature_at(*verify, 0, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    assert_rnp_success(rnp_op_verify_signature_get_times(sig, &sig_create, &sig_expires));
    assert_int_equal(sig_create, issued);
    assert_int_equal(sig_expires, expires);
    assert_rnp_success(rnp_op_verify_signature_get_hash(sig, &hname));
    assert_string_equal(hname, "SHA256");
    rnp_buffer_destroy(hname);
}

static void
test_ffi_check_recovered(void **state)
{
    // read in the recovered data from signature
    pgp_memory_t recovered = {0};
    pgp_memory_t plaintext = {0};

    assert_true(pgp_mem_readfile(&recovered, "recovered"));
    assert_true(pgp_mem_readfile(&plaintext, "plaintext"));
    // compare
    assert_int_equal(recovered.length, plaintext.length);
    assert_true(memcmp(recovered.buf, plaintext.buf, recovered.length) == 0);
    // cleanup
    pgp_memory_release(&recovered);
    pgp_memory_release(&plaintext);
}

void
test_ffi_signatures_memory(void **state)
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
    test_ffi_init(state, &ffi);
    // init input
    test_ffi_init_sign_memory_input(state, &input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(state, &ffi, &op);
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

    // create input and output
    test_ffi_init_verify_memory_input(state, &input, &output, signed_buf, signed_len);
    // call verify
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    test_ffi_check_signatures(state, &verify);
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

void
test_ffi_signatures(void **state)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_output_t    output = NULL;
    rnp_op_sign_t   op = NULL;
    rnp_op_verify_t verify;

    // init ffi
    test_ffi_init(state, &ffi);
    // init file input
    test_ffi_init_sign_file_input(state, &input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(state, &ffi, &op);
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
    test_ffi_init_verify_file_input(state, &input, &output);
    // call verify
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    test_ffi_check_signatures(state, &verify);
    // cleanup
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_output_destroy(output));
    output = NULL;
    assert_rnp_success(rnp_ffi_destroy(ffi));
    // check output
    test_ffi_check_recovered(state);
}

void
test_ffi_signatures_detached_memory(void **state)
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
    test_ffi_init(state, &ffi);
    // init input
    test_ffi_init_sign_memory_input(state, &input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_detached_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(state, &ffi, &op);
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

    // create input and output
    test_ffi_init_sign_memory_input(state, &input, NULL);
    assert_rnp_success(rnp_input_from_memory(&signature, signed_buf, signed_len, true));
    assert_non_null(signature);
    // call verify
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, input, signature));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    test_ffi_check_signatures(state, &verify);
    // cleanup
    rnp_buffer_destroy(signed_buf);
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_input_destroy(signature));
    signature = NULL;
    assert_rnp_success(rnp_ffi_destroy(ffi));
}

void
test_ffi_signatures_detached(void **state)
{
    rnp_ffi_t       ffi = NULL;
    rnp_input_t     input = NULL;
    rnp_input_t     signature = NULL;
    rnp_output_t    output = NULL;
    rnp_op_sign_t   op = NULL;
    rnp_op_verify_t verify;

    // init ffi
    test_ffi_init(state, &ffi);
    // init file input
    test_ffi_init_sign_file_input(state, &input, &output);
    // create signature operation
    assert_rnp_success(rnp_op_sign_detached_create(&op, ffi, input, output));
    // setup signature(s)
    test_ffi_setup_signatures(state, &ffi, &op);
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
    test_ffi_init_verify_detached_file_input(state, &input, &signature);
    // call verify
    assert_rnp_success(rnp_op_verify_detached_create(&verify, ffi, input, signature));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    test_ffi_check_signatures(state, &verify);
    // cleanup
    assert_rnp_success(rnp_op_verify_destroy(verify));
    assert_rnp_success(rnp_input_destroy(input));
    input = NULL;
    assert_rnp_success(rnp_input_destroy(signature));
    signature = NULL;
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
void
test_ffi_key_to_json(void **state)
{
    rnp_ffi_t        ffi = NULL;
    char *           pub_format = NULL;
    char *           pub_path = NULL;
    char *           sec_format = NULL;
    char *           sec_path = NULL;
    rnp_key_handle_t key = NULL;
    char *           json = NULL;
    json_object *    jso = NULL;
    rnp_input_t      input = NULL;

    // detect the formats+paths
    assert_int_equal(RNP_SUCCESS,
                     rnp_detect_homedir_info(
                       "data/keyrings/5", &pub_format, &pub_path, &sec_format, &sec_path));
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, pub_format, sec_format));
    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, pub_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_load_keys(ffi, pub_format, input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, sec_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_load_keys(ffi, sec_format, input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
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
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "keyid", "0E33FD46FF10F19C", &key));
    assert_non_null(key);
    // convert to JSON
    json = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_key_to_json(key, 0xff, &json));
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
    // TODO: check grip (GH #540)
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "revoked")), FALSE);
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
    // TODO: check subkey grips array values (GH #540)
    // public key
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "public key.present")), TRUE);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "public key.mpis.point")),
                     "04B0C6F2F585C1EEDF805C4492CB683839D5EAE6246420780F063D558"
                     "A33F607876BE6F818A665722F8204653CC4DCFAD4F4765521AC8A6E9F"
                     "793CEBAE8600BEEF"),
      0);
    // secret key
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.present")), TRUE);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "secret key.mpis.x")),
                     "46DE93CA439735F36B9CF228F10D8586DA824D88BBF4E24566D5312D061802C8"),
      0);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.locked")), FALSE);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.protected")),
                     FALSE);
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
    assert_int_equal(RNP_SUCCESS, rnp_locate_key(ffi, "keyid", "074131BC8D16C5C9", &key));
    assert_non_null(key);
    // convert to JSON
    assert_int_equal(RNP_SUCCESS, rnp_key_to_json(key, 0xff, &json));
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
    // TODO: check grip (GH #540)
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "revoked")), FALSE);
    assert_int_equal(json_object_get_int64(get_json_obj(jso, "creation time")), 1511313500);
    assert_int_equal(json_object_get_int64(get_json_obj(jso, "expiration")), 0);
    // usage
    assert_int_equal(json_object_array_length(get_json_obj(jso, "usage")), 1);
    assert_int_equal(rnp_strcasecmp(json_object_get_string(json_object_array_get_idx(
                                      get_json_obj(jso, "usage"), 0)),
                                    "encrypt"),
                     0);
    // primary key grip
    assert_non_null(get_json_obj(jso, "primary key grip"));
    // TODO: check grip (GH #540)
    // subkey grips
    assert_null(get_json_obj(jso, "subkey grips"));
    // TODO: check subkey grips array values (GH #540)
    // public key
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "public key.present")), TRUE);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "public key.mpis.point")),
                     "04E2746BA4D180011B17A6909EABDBF2F3733674FBE00B20A3B857C2597233651544150B"
                     "896BCE7DCDF47C49FC1E12D5AD86384D26336A48A18845940A3F65F502"),
      0);
    // secret key
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.present")), TRUE);
    assert_int_equal(
      rnp_strcasecmp(json_object_get_string(get_json_obj(jso, "secret key.mpis.x")),
                     "DF8BEB7272117AD7AFE2B7E882453113059787FBC785C82F78624EE7EF2117FB"),
      0);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.locked")), FALSE);
    assert_int_equal(json_object_get_boolean(get_json_obj(jso, "secret key.protected")),
                     FALSE);
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

void
test_ffi_key_iter(void **state)
{
    rnp_ffi_t   ffi = NULL;
    char *      pub_format = NULL;
    char *      pub_path = NULL;
    char *      sec_format = NULL;
    char *      sec_path = NULL;
    rnp_input_t input = NULL;

    // detect the formats+paths
    assert_int_equal(RNP_SUCCESS,
                     rnp_detect_homedir_info(
                       "data/keyrings/1", &pub_format, &pub_path, &sec_format, &sec_path));
    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, pub_format, sec_format));

    // test invalid identifier type
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_not_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "keyidz"));
        assert_null(it);
    }

    // test empty rings
    // keyid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "keyid"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }
    // grip
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "grip"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }
    // userid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "userid"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }

    // test with both rings empty
    // keyid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "keyid"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }
    // grip
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "grip"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }
    // userid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "userid"));
        assert_non_null(it);
        const char *ident = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
        assert_null(ident);
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, pub_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_load_keys(ffi, pub_format, input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, sec_path));
    assert_int_equal(RNP_SUCCESS,
                     rnp_load_keys(ffi, sec_format, input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;
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
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "keyid"));
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
                assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
                if (ident) {
                    assert_int_equal(0, rnp_strcasecmp(expected[i], ident));
                    i++;
                }
            } while (ident);
            assert_int_equal(i, ARRAY_SIZE(expected));
        }
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }

    // grip
    // TODO: add test once key grip calculation for all algs is fixed

    // userid
    {
        rnp_identifier_iterator_t it = NULL;
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_create(ffi, &it, "userid"));
        assert_non_null(it);
        {
            static const char *expected[] = {
              "key0-uid0", "key0-uid1", "key0-uid2", "key1-uid0", "key1-uid2", "key1-uid1"};
            size_t      i = 0;
            const char *ident = NULL;
            do {
                ident = NULL;
                assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &ident));
                if (ident) {
                    assert_int_equal(0, rnp_strcasecmp(expected[i], ident));
                    i++;
                }
            } while (ident);
            assert_int_equal(i, ARRAY_SIZE(expected));
        }
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_destroy(it));
    }

    // cleanup
    rnp_ffi_destroy(ffi);
}

void
test_ffi_locate_key(void **state)
{
    rnp_ffi_t   ffi = NULL;
    rnp_input_t input = NULL;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;

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
        // invalid
        {
            rnp_key_handle_t key = NULL;
            assert_rnp_failure(rnp_locate_key(ffi, "keyid", "invalid-keyid", &key));
            assert_null(key);
        }
        // valid but non-existent
        {
            rnp_key_handle_t key = NULL;
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
            rnp_key_handle_t key = NULL;
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
            rnp_key_handle_t key = NULL;
            assert_rnp_failure(rnp_locate_key(ffi, "fingerprint", "invalid-fpr", &key));
            assert_null(key);
        }
        // valid but non-existent
        {
            rnp_key_handle_t key = NULL;
            assert_rnp_success(rnp_locate_key(
              ffi, "fingerprint", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &key));
            assert_null(key);
        }
    }

    // grip
    // TODO: add test once key grip calculation for all algs is fixed

    // cleanup
    rnp_ffi_destroy(ffi);
}

void
test_ffi_signatures_detached_memory_g10(void **state)
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
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "KBX", "G10"));
    assert_int_equal(RNP_SUCCESS,
                     rnp_ffi_set_pass_provider(ffi, getpasscb, (void *) "password"));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/3/pubring.kbx"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "KBX", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS,
                     rnp_input_from_path(&input, "data/keyrings/3/private-keys-v1.d"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "G10", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

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

void
test_ffi_enarmor_dearmor(void **state)
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
}

void
test_ffi_version(void **state)
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
        assert_int_equal(RNP_SUCCESS, rnp_identifier_iterator_next(it, &identifier));
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

void
test_ffi_key_export(void **state)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_key_handle_t key = NULL;
    uint8_t *        buf = NULL;
    size_t           buf_len = 0;

    // setup FFI
    assert_int_equal(RNP_SUCCESS, rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_input_destroy(input);
    input = NULL;
    assert_int_equal(RNP_SUCCESS, rnp_input_from_path(&input, "data/keyrings/1/secring.gpg"));
    assert_int_equal(RNP_SUCCESS, rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

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
