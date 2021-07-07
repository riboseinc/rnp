/*
 * Copyright (c) 2020 [Ribose Inc](https://www.ribose.com).
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
    size_t pass_len = strlen(*pass);
    if (pass_len >= buf_len) {
        return false;
    }
    memcpy(buf, *pass, pass_len);
    *pass = NULL;
    return true;
}

static bool
getpasscb_inc(rnp_ffi_t        ffi,
              void *           app_ctx,
              rnp_key_handle_t key,
              const char *     pgp_context,
              char *           buf,
              size_t           buf_len)
{
    int *       num = (int *) app_ctx;
    std::string pass = "pass" + std::to_string(*num);
    (*num)++;
    strncpy(buf, pass.c_str(), buf_len - 1);
    return true;
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

TEST_F(rnp_tests, test_ffi_encrypt_pass)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *     plaintext = "data1";

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_true(
      load_keys_gpg(ffi, "data/keyrings/1/pubring.gpg", "data/keyrings/1/secring.gpg"));

    // write out some data
    FILE *fp = fopen("plaintext", "wb");
    assert_non_null(fp);
    assert_int_equal(1, fwrite(plaintext, strlen(plaintext), 1, fp));
    assert_int_equal(0, fclose(fp));

    // create input+output w/ bad paths (should fail)
    input = NULL;
    assert_rnp_failure(rnp_input_from_path(&input, "noexist"));
    assert_null(input);
    assert_rnp_failure(rnp_output_to_path(&output, ""));
    assert_null(output);

    // create input+output
    assert_rnp_success(rnp_input_from_path(&input, "plaintext"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "encrypted"));
    assert_non_null(output);
    // create encrypt operation
    assert_rnp_success(rnp_op_encrypt_create(&op, ffi, input, output));
    // add password (using all defaults)
    assert_rnp_success(rnp_op_encrypt_add_password(op, "pass1", NULL, 0, NULL));
    // add password
    if (!sm2_enabled() && !twofish_enabled()) {
        assert_rnp_failure(rnp_op_encrypt_add_password(op, "pass2", "SM3", 12345, "TWOFISH"));
        assert_rnp_failure(
          rnp_op_encrypt_add_password(op, "pass2", "SHA256", 12345, "TWOFISH"));
        assert_rnp_success(
          rnp_op_encrypt_add_password(op, "pass2", "SHA256", 12345, "BLOWFISH"));
    } else if (!sm2_enabled() && twofish_enabled()) {
        assert_rnp_failure(rnp_op_encrypt_add_password(op, "pass2", "SM3", 12345, "TWOFISH"));
        assert_rnp_success(
          rnp_op_encrypt_add_password(op, "pass2", "SHA256", 12345, "TWOFISH"));
    } else if (sm2_enabled() && !twofish_enabled()) {
        assert_rnp_failure(rnp_op_encrypt_add_password(op, "pass2", "SM3", 12345, "TWOFISH"));
        assert_rnp_success(rnp_op_encrypt_add_password(op, "pass2", "SM3", 12345, "BLOWFISH"));
    } else {
        assert_rnp_success(rnp_op_encrypt_add_password(op, "pass2", "SM3", 12345, "TWOFISH"));
    }
    // set the data encryption cipher
    assert_rnp_success(rnp_op_encrypt_set_cipher(op, "CAST5"));
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

    // decrypt (pass1)
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
    assert_string_equal(file_to_str("decrypted").c_str(), plaintext);
    unlink("decrypted");

    // decrypt (pass2)
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "pass2"));
    assert_rnp_success(rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // compare the decrypted file
    assert_string_equal(file_to_str("decrypted").c_str(), plaintext);
    // final cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_encrypt_pass_provider)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *plaintext = "Data encrypted with password provided via password provider.";

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // write out some data
    FILE *fp = fopen("plaintext", "wb");
    assert_non_null(fp);
    assert_int_equal(1, fwrite(plaintext, strlen(plaintext), 1, fp));
    assert_int_equal(0, fclose(fp));
    // create input + output
    assert_rnp_success(rnp_input_from_path(&input, "plaintext"));
    assert_rnp_success(rnp_output_to_path(&output, "encrypted"));
    // create encrypt operation
    assert_rnp_success(rnp_op_encrypt_create(&op, ffi, input, output));
    // add password with NULL password provider set - should fail
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, NULL, NULL));
    assert_rnp_failure(rnp_op_encrypt_add_password(op, NULL, NULL, 0, NULL));
    // add password with password provider set.
    int pswdnum = 1;
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb_inc, &pswdnum));
    assert_rnp_success(rnp_op_encrypt_add_password(op, NULL, NULL, 0, NULL));
    // add another password with different encryption parameters
    if (!sm2_enabled() && !twofish_enabled()) {
        assert_rnp_failure(rnp_op_encrypt_add_password(op, NULL, "SM3", 12345, "TWOFISH"));
        assert_rnp_failure(rnp_op_encrypt_add_password(op, NULL, "SHA256", 12345, "TWOFISH"));
        assert_rnp_success(rnp_op_encrypt_add_password(op, NULL, "SHA256", 12345, "BLOWFISH"));
    } else if (!sm2_enabled() && twofish_enabled()) {
        assert_rnp_failure(rnp_op_encrypt_add_password(op, NULL, "SM3", 12345, "TWOFISH"));
        assert_rnp_success(rnp_op_encrypt_add_password(op, NULL, "SHA256", 12345, "TWOFISH"));
    } else if (sm2_enabled() && !twofish_enabled()) {
        assert_rnp_failure(rnp_op_encrypt_add_password(op, NULL, "SM3", 12345, "TWOFISH"));
        assert_rnp_success(rnp_op_encrypt_add_password(op, NULL, "SM3", 12345, "BLOWFISH"));
    } else {
        assert_rnp_success(rnp_op_encrypt_add_password(op, NULL, "SM3", 12345, "TWOFISH"));
    }
    // set the data encryption cipher
    assert_rnp_success(rnp_op_encrypt_set_cipher(op, "CAMELLIA256"));
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

    /* decrypt with pass1 */
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "pass1"));
    assert_rnp_success(rnp_decrypt(ffi, input, output));
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    assert_string_equal(file_to_str("decrypted").c_str(), plaintext);
    unlink("decrypted");

    /* decrypt with pass2 via provider */
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    pswdnum = 2;
    assert_rnp_success(rnp_ffi_set_pass_provider(ffi, getpasscb_inc, &pswdnum));
    assert_rnp_success(rnp_decrypt(ffi, input, output));
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    assert_string_equal(file_to_str("decrypted").c_str(), plaintext);
    unlink("decrypted");

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_encrypt_pk)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *     plaintext = "data1";

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_true(
      load_keys_gpg(ffi, "data/keyrings/1/pubring.gpg", "data/keyrings/1/secring.gpg"));

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
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_success(rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // read in the decrypted file
    assert_string_equal(file_to_str("decrypted").c_str(), plaintext);
    // final cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_encrypt_pk_key_provider)
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
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_non_null(ffi);
    // load our keyrings
    assert_true(
      load_keys_gpg(ffi, "data/keyrings/1/pubring.gpg", "data/keyrings/1/secring.gpg"));
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
    // add recipient 1
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "key0-uid2", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_op_encrypt_add_recipient(op, key));
    // cleanup
    assert_rnp_success(rnp_key_handle_destroy(key));
    key = NULL;
    // add recipient 2
    assert_rnp_success(rnp_locate_key(ffi, "userid", "key1-uid1", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_op_encrypt_add_recipient(op, key));
    // save the primary key data for later
    assert_rnp_success(rnp_get_secret_key_data(key, &primary_sec_key_data, &primary_sec_size));
    assert_non_null(primary_sec_key_data);
    assert_rnp_success(rnp_key_handle_destroy(key));
    key = NULL;
    // save the appropriate encrypting subkey for the key provider to use during decryption
    // later
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "8A05B89FAD5ADED1", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_get_secret_key_data(key, &sub_sec_key_data, &sub_sec_size));
    assert_non_null(sub_sec_key_data);
    // cleanup
    assert_rnp_success(rnp_key_handle_destroy(key));
    key = NULL;
    // set the data encryption cipher
    assert_rnp_success(rnp_op_encrypt_set_cipher(op, "CAST5"));
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
    assert_rnp_success(rnp_ffi_destroy(ffi));
    ffi = NULL;

    /* decrypt */
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    // load the primary
    input = NULL;
    assert_rnp_success(
      rnp_input_from_memory(&input, primary_sec_key_data, primary_sec_size, true));
    assert_non_null(input);
    assert_rnp_success(rnp_load_keys(ffi, "GPG", input, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_input_destroy(input);
    input = NULL;

    // decrypt (no key to decrypt, should fail)
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_int_equal(RNP_ERROR_NO_SUITABLE_KEY, rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;

    // key_data key_data_size secret keyid grip userids
    const key_tbl_t keydb[] = {
      {sub_sec_key_data, sub_sec_size, true, "8A05B89FAD5ADED1", NULL, {NULL}}, {0}};

    // decrypt
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "decrypted"));
    assert_non_null(output);
    assert_rnp_success(rnp_ffi_set_key_provider(ffi, tbl_getkeycb, (void *) keydb));
    assert_rnp_success(rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // compare the decrypted file
    assert_string_equal(file_to_str("decrypted").c_str(), plaintext);
    // final cleanup
    rnp_ffi_destroy(ffi);
    free(sub_sec_key_data);
    free(primary_sec_key_data);
}

TEST_F(rnp_tests, test_ffi_encrypt_and_sign)
{
    rnp_ffi_t               ffi = NULL;
    rnp_input_t             input = NULL;
    rnp_output_t            output = NULL;
    rnp_op_encrypt_t        op = NULL;
    rnp_op_sign_signature_t signsig = NULL;
    const char *            plaintext = "data1";
    rnp_key_handle_t        key = NULL;
    const uint32_t          issued = 1516211899;   // Unix epoch, nowish
    const uint32_t          expires = 1000000000;  // expires later
    const uint32_t          issued2 = 1516211900;  // Unix epoch, nowish
    const uint32_t          expires2 = 2000000000; // expires later

    // setup FFI
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    // load our keyrings
    assert_true(
      load_keys_gpg(ffi, "data/keyrings/1/pubring.gpg", "data/keyrings/1/secring.gpg"));

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
    // add recipients
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
    assert_rnp_success(rnp_op_encrypt_set_hash(op, "SHA1"));
    assert_rnp_success(rnp_op_encrypt_set_creation_time(op, 0));
    assert_rnp_success(rnp_op_encrypt_set_expiration_time(op, 0));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "key1-uid1", &key));
    assert_rnp_success(rnp_op_encrypt_add_signature(op, key, NULL));
    rnp_key_handle_destroy(key);
    key = NULL;
    // add second signature with different hash/issued/expiration
    assert_rnp_success(rnp_locate_key(ffi, "userid", "key1-uid2", &key));
    assert_rnp_success(rnp_op_encrypt_add_signature(op, key, &signsig));
    assert_rnp_success(rnp_op_sign_signature_set_creation_time(signsig, issued2));
    assert_rnp_success(rnp_op_sign_signature_set_expiration_time(signsig, expires2));
    assert_rnp_success(rnp_op_sign_signature_set_hash(signsig, "SHA512"));
    rnp_key_handle_destroy(key);
    key = NULL;
    // set default sig parameters after the signature is added - those should be picked up
    assert_rnp_success(rnp_op_encrypt_set_hash(op, "SHA256"));
    assert_rnp_success(rnp_op_encrypt_set_creation_time(op, issued));
    assert_rnp_success(rnp_op_encrypt_set_expiration_time(op, expires));
    // execute the operation
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
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
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_success(rnp_decrypt(ffi, input, output));
    // cleanup
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // compare the decrypted file
    assert_string_equal(file_to_str("decrypted").c_str(), plaintext);
    // verify and check signatures
    rnp_op_verify_t verify;
    assert_rnp_success(rnp_input_from_path(&input, "encrypted"));
    assert_non_null(input);
    assert_rnp_success(rnp_output_to_path(&output, "verified"));
    assert_non_null(output);
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));

    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));
    // check signatures
    rnp_op_verify_signature_t sig;
    size_t                    sig_count;
    uint32_t                  sig_create;
    uint32_t                  sig_expires;
    char *                    hname = NULL;

    assert_rnp_success(rnp_op_verify_get_signature_count(verify, &sig_count));
    assert_int_equal(sig_count, 2);
    // signature 1
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 0, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    assert_rnp_success(rnp_op_verify_signature_get_times(sig, &sig_create, &sig_expires));
    assert_int_equal(sig_create, issued);
    assert_int_equal(sig_expires, expires);
    assert_rnp_success(rnp_op_verify_signature_get_hash(sig, &hname));
    assert_string_equal(hname, "SHA256");
    rnp_buffer_destroy(hname);
    hname = NULL;
    // signature 2
    assert_rnp_success(rnp_op_verify_get_signature_at(verify, 1, &sig));
    assert_rnp_success(rnp_op_verify_signature_get_status(sig));
    assert_rnp_success(rnp_op_verify_signature_get_times(sig, &sig_create, &sig_expires));
    assert_int_equal(sig_create, issued2);
    assert_int_equal(sig_expires, expires2);
    assert_rnp_success(rnp_op_verify_signature_get_hash(sig, &hname));
    assert_string_equal(hname, "SHA512");
    rnp_buffer_destroy(hname);
    hname = NULL;
    // cleanup
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    input = NULL;
    rnp_output_destroy(output);
    output = NULL;
    // compare the decrypted file
    assert_string_equal(file_to_str("verified").c_str(), plaintext);
    // final cleanup
    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_encrypt_pk_subkey_selection)
{
    rnp_ffi_t        ffi = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    rnp_op_encrypt_t op = NULL;
    const char *     plaintext = "data1";

    /* check whether a latest subkey is selected for encryption */
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));

    /* case 1: three encryption subkeys, second expired, third has later creation time */
    assert_true(load_keys_gpg(ffi, "data/test_stream_key_load/key0-sub02.pgp"));

    assert_rnp_success(
      rnp_input_from_memory(&input, (uint8_t *) plaintext, strlen(plaintext), false));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    /* create encrypt operation, add recipient and execute */
    assert_rnp_success(rnp_op_encrypt_create(&op, ffi, input, output));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "key0-uid0", &key));
    assert_rnp_success(rnp_op_encrypt_add_recipient(op, key));
    rnp_key_handle_destroy(key);
    assert_rnp_success(rnp_op_encrypt_execute(op));
    /* get output */
    uint8_t *buf = NULL;
    size_t   len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, true));
    assert_true(buf && len);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_op_encrypt_destroy(op);
    /* decrypt */
    assert_true(load_keys_gpg(ffi, "", "data/keyrings/1/secring.gpg"));
    assert_rnp_success(rnp_input_from_memory(&input, buf, len, true));
    rnp_buffer_destroy(buf);
    assert_rnp_success(rnp_output_to_memory(&output, 0));

    rnp_op_verify_t verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));

    /* check whether we used correct subkey */
    size_t count = 0;
    assert_rnp_success(rnp_op_verify_get_recipient_count(verify, &count));
    assert_int_equal(count, 1);
    rnp_recipient_handle_t recipient = NULL;
    assert_rnp_success(rnp_op_verify_get_recipient_at(verify, 0, &recipient));
    assert_non_null(recipient);
    char *keyid = NULL;
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &keyid));
    assert_non_null(keyid);
    assert_string_equal(keyid, "8A05B89FAD5ADED1");
    rnp_buffer_destroy(keyid);

    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* case 2: only subkeys 1-2, make sure that latest but expired subkey is not selected */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(load_keys_gpg(ffi, "data/test_stream_key_load/key0-sub01.pgp"));
    assert_rnp_success(
      rnp_input_from_memory(&input, (uint8_t *) plaintext, strlen(plaintext), false));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    /* create encrypt operation, add recipient and execute */
    assert_rnp_success(rnp_op_encrypt_create(&op, ffi, input, output));
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    assert_rnp_success(rnp_op_encrypt_add_recipient(op, key));
    rnp_key_handle_destroy(key);
    assert_rnp_success(rnp_op_encrypt_execute(op));
    /* get output */
    buf = NULL;
    len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, true));
    assert_true(buf && len);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_op_encrypt_destroy(op);
    /* decrypt */
    assert_true(load_keys_gpg(ffi, "", "data/keyrings/1/secring.gpg"));
    assert_rnp_success(rnp_input_from_memory(&input, buf, len, true));
    rnp_buffer_destroy(buf);
    assert_rnp_success(rnp_output_to_memory(&output, 0));

    verify = NULL;
    assert_rnp_success(rnp_op_verify_create(&verify, ffi, input, output));
    assert_rnp_success(rnp_op_verify_execute(verify));

    /* check whether we used correct subkey */
    count = 0;
    assert_rnp_success(rnp_op_verify_get_recipient_count(verify, &count));
    assert_int_equal(count, 1);
    recipient = NULL;
    assert_rnp_success(rnp_op_verify_get_recipient_at(verify, 0, &recipient));
    assert_non_null(recipient);
    keyid = NULL;
    assert_rnp_success(rnp_recipient_get_keyid(recipient, &keyid));
    assert_non_null(keyid);
    assert_string_equal(keyid, "1ED63EE56FADC34D");
    rnp_buffer_destroy(keyid);

    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    /* case 3: only expired subkey, make sure encryption operation fails */
    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    assert_true(load_keys_gpg(ffi, "data/test_stream_key_load/key0-sub1.pgp"));

    assert_rnp_success(
      rnp_input_from_memory(&input, (uint8_t *) plaintext, strlen(plaintext), false));
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    /* create encrypt operation, add recipient and execute */
    assert_rnp_success(rnp_op_encrypt_create(&op, ffi, input, output));
    key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "keyid", "7bc6709b15c23a4a", &key));
    assert_rnp_success(rnp_op_encrypt_add_recipient(op, key));
    rnp_key_handle_destroy(key);
    assert_rnp_failure(rnp_op_encrypt_execute(op));
    rnp_op_encrypt_destroy(op);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    rnp_ffi_destroy(ffi);
}

TEST_F(rnp_tests, test_ffi_decrypt_small_rsa)
{
    rnp_ffi_t   ffi = NULL;
    const char *plaintext = "data1";

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_true(import_all_keys(ffi, "data/test_key_validity/rsa_key_small_sig-sec.asc"));
    rnp_input_t input = NULL;
    assert_rnp_success(rnp_input_from_path(&input, "data/test_messages/data.enc.small-rsa"));
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_decrypt(ffi, input, output));
    size_t   len = 0;
    uint8_t *buf = NULL;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 5);
    assert_int_equal(memcmp(plaintext, buf, 5), 0);
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_output_destroy(output));
    rnp_ffi_destroy(ffi);
}
