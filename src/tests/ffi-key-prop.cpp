/*
 * Copyright (c) 2021 [Ribose Inc](https://www.ribose.com).
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

#include <sstream>
#include <rnp/rnp.h>
#include "rnp_tests.h"
#include "support.h"

static bool
check_uid_valid(rnp_key_handle_t key, size_t idx, bool valid)
{
    rnp_uid_handle_t uid = NULL;
    if (rnp_key_get_uid_handle_at(key, idx, &uid)) {
        return false;
    }
    bool val = !valid;
    rnp_uid_is_valid(uid, &val);
    rnp_uid_handle_destroy(uid);
    return val == valid;
}

static bool
check_uid_primary(rnp_key_handle_t key, size_t idx, bool primary)
{
    rnp_uid_handle_t uid = NULL;
    if (rnp_key_get_uid_handle_at(key, idx, &uid)) {
        return false;
    }
    bool prim = !primary;
    rnp_uid_is_primary(uid, &prim);
    rnp_uid_handle_destroy(uid);
    return prim == primary;
}

TEST_F(rnp_tests, test_ffi_key_set_expiry_multiple_uids)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));

    /* load key with 3 uids with zero key expiration */
    assert_true(import_all_keys(ffi, "data/test_key_edge_cases/alice-3-uids.pgp"));
    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    size_t count = 0;
    assert_rnp_success(rnp_key_get_uid_count(key, &count));
    assert_int_equal(count, 3);
    uint32_t expiry = 10;
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    assert_true(check_uid_primary(key, 0, false));
    assert_true(check_uid_primary(key, 1, false));
    assert_true(check_uid_primary(key, 2, false));
    /* set expiration time to minimum value so key is expired now, but uids are still valid */
    assert_rnp_success(rnp_key_set_expiration(key, 1));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 1);
    bool valid = true;
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_false(valid);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    /* reload */
    rnp_key_handle_destroy(key);
    reload_keyrings(&ffi);
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    assert_non_null(key);
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 1);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    /* set expiration to maximum value */
    assert_rnp_success(
      rnp_ffi_set_pass_provider(ffi, ffi_string_password_provider, (void *) "password"));
    assert_rnp_success(rnp_key_set_expiration(key, 0xFFFFFFFF));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0xFFFFFFFF);
    valid = false;
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_true(valid);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    rnp_key_handle_destroy(key);
    /* reload and make sure changes are saved */
    reload_keyrings(&ffi);
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Caesar <caesar@rnp>", &key));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0xFFFFFFFF);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    rnp_key_handle_destroy(key);

    assert_rnp_success(rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET));
    /* load key with 3 uids, including primary, with key expiration */
    assert_true(
      import_all_keys(ffi, "data/test_key_edge_cases/alice-3-uids-primary-expiring.pgp"));
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Alice <alice@rnp>", &key));
    expiry = 0;
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 674700647);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    assert_true(check_uid_primary(key, 0, true));
    assert_true(check_uid_primary(key, 1, false));
    assert_true(check_uid_primary(key, 2, false));
    assert_rnp_success(rnp_key_unlock(key, "password"));
    assert_rnp_success(rnp_key_set_expiration(key, 0));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0);
    valid = false;
    assert_rnp_success(rnp_key_is_valid(key, &valid));
    assert_true(valid);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    rnp_key_handle_destroy(key);
    /* reload and make sure it is saved */
    reload_keyrings(&ffi);
    assert_rnp_success(rnp_locate_key(ffi, "userid", "Caesar <caesar@rnp>", &key));
    assert_rnp_success(rnp_key_get_expiration(key, &expiry));
    assert_int_equal(expiry, 0);
    assert_true(check_uid_valid(key, 0, true));
    assert_true(check_uid_valid(key, 1, true));
    assert_true(check_uid_valid(key, 2, true));
    assert_true(check_uid_primary(key, 0, true));
    rnp_key_handle_destroy(key);

    rnp_ffi_destroy(ffi);
}
