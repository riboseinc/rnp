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

#include "../librekey/key_store_pgp.h"
#include "pgp-key.h"

#include "rnp_tests.h"
#include "support.h"
#include "utils.h"
#include "hash.h"

/* This test loads a .gpg keyring and tests protect/unprotect functionality.
 * There is also some lock/unlock testing in here, since the two are
 * somewhat related.
 */
void
test_key_protect_load_pgp(void **state)
{
    rnp_test_state_t * rstate = *state;
    char               path[PATH_MAX];
    pgp_io_t           io = {.errs = stderr, .res = stdout, .outs = stdout};
    pgp_key_t *        key = NULL;
    static const char *keyids[] = {"7bc6709b15c23a4a", // primary
                                   "1ed63ee56fadc34d",
                                   "1d7e8a5393c997a8",
                                   "8a05b89fad5aded1",
                                   "2fcadf05ffa501bb", // primary
                                   "54505a936a4a970e",
                                   "326ef111425d14a5"};

    // load our keyring and do some quick checks
    {
        rnp_key_store_t *ks = calloc(1, sizeof(*ks));
        assert_non_null(ks);

        pgp_memory_t mem = {0};
        paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/1/secring.gpg", NULL);
        assert_true(pgp_mem_readfile(&mem, path));
        assert_true(rnp_key_store_pgp_read_from_mem(&io, ks, 0, &mem));
        pgp_memory_release(&mem);

        for (size_t i = 0; i < ARRAY_SIZE(keyids); i++) {
            pgp_key_t * key = NULL;
            const char *keyid = keyids[i];
            assert_true(rnp_key_store_get_key_by_name(&io, ks, keyid, &key));
            assert_non_null(key);
            // all keys in this keyring are encrypted and thus should be both protected and
            // locked initially
            assert_true(pgp_key_is_protected(key));
            assert_true(pgp_key_is_locked(key));
        }

        pgp_key_t *tmp = NULL;
        assert_true(rnp_key_store_get_key_by_name(&io, ks, keyids[0], &tmp));
        assert_non_null(tmp);

        // steal this key from the store
        key = calloc(1, sizeof(*key));
        assert_non_null(key);
        memcpy(key, tmp, sizeof(*key));
        assert_true(rnp_key_store_remove_key(&io, ks, tmp));
        rnp_key_store_free(ks);
    }

    // confirm that this key is indeed RSA
    assert_int_equal(key->key.pubkey.alg, PGP_PKA_RSA);

    // confirm key material is currently all NULL (in other words, the key is locked)
    assert_null(key->key.seckey.key.rsa.d);
    assert_null(key->key.seckey.key.rsa.p);
    assert_null(key->key.seckey.key.rsa.q);
    assert_null(key->key.seckey.key.rsa.u);

    // try to unprotect with a failing passphrase provider
    assert_false(
      pgp_key_unprotect(key,
                        &(pgp_passphrase_provider_t){.callback = failing_passphrase_callback,
                                                     .userdata = NULL}));

    // try to unprotect with an incorrect passphrase
    assert_false(pgp_key_unprotect(
      key,
      &(pgp_passphrase_provider_t){.callback = string_copy_passphrase_callback,
                                   .userdata = "badpass"}));

    // unprotect with the correct passphrase
    assert_true(pgp_key_unprotect(
      key,
      &(pgp_passphrase_provider_t){.callback = string_copy_passphrase_callback,
                                   .userdata = "password"}));
    assert_false(pgp_key_is_protected(key));

    // should still be locked
    assert_true(pgp_key_is_locked(key));

    // confirm secret key material is still NULL
    assert_null(key->key.seckey.key.rsa.d);
    assert_null(key->key.seckey.key.rsa.p);
    assert_null(key->key.seckey.key.rsa.q);
    assert_null(key->key.seckey.key.rsa.u);

    // unlock (no passphrase required since the key is not protected)
    assert_true(
      pgp_key_unlock(key,
                     &(pgp_passphrase_provider_t){.callback = asserting_passphrase_callback,
                                                  .userdata = NULL}));
    assert_false(pgp_key_is_locked(key));

    // secret key material should be available
    assert_non_null(key->key.seckey.key.rsa.d);
    assert_non_null(key->key.seckey.key.rsa.p);
    assert_non_null(key->key.seckey.key.rsa.q);
    assert_non_null(key->key.seckey.key.rsa.u);

    // save the secret MPIs for some later comparisons
    BIGNUM *d = BN_dup(key->key.seckey.key.rsa.d);
    BIGNUM *p = BN_dup(key->key.seckey.key.rsa.p);
    BIGNUM *q = BN_dup(key->key.seckey.key.rsa.q);
    BIGNUM *u = BN_dup(key->key.seckey.key.rsa.u);

    // confirm that packets[0] is no longer encrypted
    {
        rnp_key_store_t *ks = calloc(1, sizeof(*ks));
        assert_non_null(ks);

        pgp_memory_t mem = {0};
        mem.buf = key->packets[0].raw;
        mem.length = key->packets[0].length;
        assert_true(rnp_key_store_pgp_read_from_mem(&io, ks, 0, &mem));

        // grab the first key
        pgp_key_t *reloaded_key = NULL;
        assert_true(rnp_key_store_get_key_by_name(&io, ks, keyids[0], &reloaded_key));
        assert_non_null(reloaded_key);

        // should not be locked, nor protected
        assert_false(pgp_key_is_locked(reloaded_key));
        assert_false(pgp_key_is_protected(reloaded_key));
        // secret key material should not be NULL
        assert_non_null(reloaded_key->key.seckey.key.rsa.d);
        assert_non_null(reloaded_key->key.seckey.key.rsa.p);
        assert_non_null(reloaded_key->key.seckey.key.rsa.q);
        assert_non_null(reloaded_key->key.seckey.key.rsa.u);

        // compare MPIs of the reloaded key, with the unlocked key from earlier
        assert_int_equal(
          0, BN_cmp(key->key.seckey.key.rsa.d, reloaded_key->key.seckey.key.rsa.d));
        assert_int_equal(
          0, BN_cmp(key->key.seckey.key.rsa.p, reloaded_key->key.seckey.key.rsa.p));
        assert_int_equal(
          0, BN_cmp(key->key.seckey.key.rsa.q, reloaded_key->key.seckey.key.rsa.q));
        assert_int_equal(
          0, BN_cmp(key->key.seckey.key.rsa.u, reloaded_key->key.seckey.key.rsa.u));
        // negative test to try to ensure the above is a valid test
        assert_int_not_equal(
          0, BN_cmp(key->key.seckey.key.rsa.d, reloaded_key->key.seckey.key.rsa.p));

        // lock it
        assert_true(pgp_key_lock(reloaded_key));
        assert_true(pgp_key_is_locked(reloaded_key));
        // confirm that secret MPIs are NULL again
        assert_null(reloaded_key->key.seckey.key.rsa.d);
        assert_null(reloaded_key->key.seckey.key.rsa.p);
        assert_null(reloaded_key->key.seckey.key.rsa.q);
        assert_null(reloaded_key->key.seckey.key.rsa.u);
        // unlock it (no passphrase, since it's not protected)
        assert_true(
          pgp_key_unlock(reloaded_key,
                         &(pgp_passphrase_provider_t){
                           .callback = asserting_passphrase_callback, .userdata = NULL}));
        assert_false(pgp_key_is_locked(reloaded_key));
        // compare MPIs of the reloaded key, with the unlocked key from earlier
        assert_int_equal(
          0, BN_cmp(key->key.seckey.key.rsa.d, reloaded_key->key.seckey.key.rsa.d));
        assert_int_equal(
          0, BN_cmp(key->key.seckey.key.rsa.p, reloaded_key->key.seckey.key.rsa.p));
        assert_int_equal(
          0, BN_cmp(key->key.seckey.key.rsa.q, reloaded_key->key.seckey.key.rsa.q));
        assert_int_equal(
          0, BN_cmp(key->key.seckey.key.rsa.u, reloaded_key->key.seckey.key.rsa.u));

        rnp_key_store_free(ks);
    }

    // lock
    assert_true(pgp_key_lock(key));

    // try to protect (will fail when key is locked)
    assert_false(
      pgp_key_protect(key,
                      key->format, // same format
                      NULL,        // default protection
                      &(pgp_passphrase_provider_t){.callback = string_copy_passphrase_callback,
                                                   .userdata = "newpass"}));
    assert_false(pgp_key_is_protected(key));

    // unlock
    assert_true(
      pgp_key_unlock(key,
                     &(pgp_passphrase_provider_t){.callback = asserting_passphrase_callback,
                                                  .userdata = NULL}));
    assert_false(pgp_key_is_locked(key));

    // try to protect with a failing passphrase provider
    assert_false(
      pgp_key_protect(key,
                      key->format, // same format
                      NULL,        // default protection
                      &(pgp_passphrase_provider_t){.callback = failing_passphrase_callback,
                                                   .userdata = NULL}));
    assert_false(pgp_key_is_protected(key));

    // (re)protect with a new password
    assert_true(
      pgp_key_protect(key,
                      key->format, // same format
                      NULL,        // default protection
                      &(pgp_passphrase_provider_t){.callback = string_copy_passphrase_callback,
                                                   .userdata = "newpass"}));
    assert_true(pgp_key_is_protected(key));

    // lock
    assert_true(pgp_key_lock(key));
    assert_true(pgp_key_is_locked(key));

    // try to unlock with old password
    assert_false(
      pgp_key_unlock(key,
                     &(pgp_passphrase_provider_t){.callback = string_copy_passphrase_callback,
                                                  .userdata = "password"}));
    assert_true(pgp_key_is_locked(key));

    // unlock with new password
    assert_true(
      pgp_key_unlock(key,
                     &(pgp_passphrase_provider_t){.callback = string_copy_passphrase_callback,
                                                  .userdata = "newpass"}));
    assert_false(pgp_key_is_locked(key));

    // compare secret MPIs with those from earlier
    assert_int_equal(0, BN_cmp(key->key.seckey.key.rsa.d, d));
    assert_int_equal(0, BN_cmp(key->key.seckey.key.rsa.p, p));
    assert_int_equal(0, BN_cmp(key->key.seckey.key.rsa.q, q));
    assert_int_equal(0, BN_cmp(key->key.seckey.key.rsa.u, u));

    // cleanup
    pgp_key_free(key);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(u);
}
