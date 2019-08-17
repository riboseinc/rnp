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

#include "../librekey/key_store_pgp.h"
#include "../librepgp/stream-ctx.h"
#include "pgp-key.h"

#include "rnp_tests.h"
#include "support.h"
#include "utils.h"
#include "crypto/hash.h"

TEST_F(rnp_tests, test_key_unlock_pgp)
{
    rnp_t                   rnp;
    pgp_key_t *             key = NULL;
    rnp_ctx_t               ctx;
    rnp_signer_info_t       signer = {};
    rnp_result_t            ret;
    const char *            data = "my test data";
    char                    signature[512] = {0};
    size_t                  siglen = 0;
    size_t                  enclen = 0;
    size_t                  declen = 0;
    char                    encrypted[512] = {0};
    char                    decrypted[512] = {0};
    pgp_password_provider_t provider = {0};
    static const char *     keyids[] = {"7bc6709b15c23a4a", // primary
                                   "1ed63ee56fadc34d",
                                   "1d7e8a5393c997a8",
                                   "8a05b89fad5aded1",
                                   "2fcadf05ffa501bb", // primary
                                   "54505a936a4a970e",
                                   "326ef111425d14a5"};

    assert_true(setup_rnp_common(&rnp, RNP_KEYSTORE_GPG, "data/keyrings/1/", NULL));
    assert_true(rnp_load_keyrings(&rnp, true));

    for (size_t i = 0; i < ARRAY_SIZE(keyids); i++) {
        const char *keyid = keyids[i];
        assert_non_null(key = rnp_key_store_get_key_by_name(rnp.secring, keyid, NULL));
        assert_non_null(key);
        // all keys in this keyring are encrypted and thus should be locked initially
        assert_true(pgp_key_is_locked(key));
    }

    // try signing with a failing password provider (should fail)
    rnp.password_provider =
      (pgp_password_provider_t){.callback = failing_password_callback, .userdata = NULL};
    rnp_ctx_init(&ctx, &rnp.rng);
    ctx.halg = pgp_str_to_hash_alg("SHA1");
    assert_non_null(key = rnp_key_store_get_key_by_name(rnp.secring, keyids[0], NULL));
    signer.key = key;
    signer.halg = ctx.halg;
    assert_non_null(list_append(&ctx.signers, &signer, sizeof(signer)));
    memset(signature, 0, sizeof(signature));
    ret =
      rnp_protect_mem(&rnp, &ctx, data, strlen(data), signature, sizeof(signature), &siglen);
    assert_int_not_equal(ret, RNP_SUCCESS);
    rnp_ctx_free(&ctx);

    // grab the signing key to unlock
    assert_non_null(key = rnp_key_store_get_key_by_name(rnp.secring, keyids[0], NULL));
    assert_non_null(key);

    // confirm that this key is indeed RSA first
    assert_int_equal(pgp_key_get_alg(key), PGP_PKA_RSA);
    // confirm the secret MPIs are NULL
    assert_int_equal(pgp_key_get_material(key)->rsa.d.len, 0);
    assert_int_equal(pgp_key_get_material(key)->rsa.p.len, 0);
    assert_int_equal(pgp_key_get_material(key)->rsa.q.len, 0);
    assert_int_equal(pgp_key_get_material(key)->rsa.u.len, 0);

    // try to unlock with a failing password provider
    provider =
      (pgp_password_provider_t){.callback = failing_password_callback, .userdata = NULL};
    assert_false(pgp_key_unlock(key, &provider));
    assert_true(pgp_key_is_locked(key));

    // try to unlock with an incorrect password
    provider = (pgp_password_provider_t){.callback = string_copy_password_callback,
                                         .userdata = (void *) "badpass"};
    assert_false(pgp_key_unlock(key, &provider));
    assert_true(pgp_key_is_locked(key));

    // unlock the signing key
    provider = (pgp_password_provider_t){.callback = string_copy_password_callback,
                                         .userdata = (void *) "password"};
    assert_true(pgp_key_unlock(key, &provider));
    assert_false(pgp_key_is_locked(key));

    // confirm the secret MPIs are now filled in
    assert_int_not_equal(pgp_key_get_material(key)->rsa.d.len, 0);
    assert_int_not_equal(pgp_key_get_material(key)->rsa.p.len, 0);
    assert_int_not_equal(pgp_key_get_material(key)->rsa.q.len, 0);
    assert_int_not_equal(pgp_key_get_material(key)->rsa.u.len, 0);

    // now the signing key is unlocked, confirm that no password is required for signing
    rnp.password_provider =
      (pgp_password_provider_t){.callback = asserting_password_callback, .userdata = NULL};

    // sign, with no password
    rnp_ctx_init(&ctx, &rnp.rng);
    ctx.halg = pgp_str_to_hash_alg("SHA1");
    assert_non_null(key = rnp_key_store_get_key_by_name(rnp.secring, keyids[0], NULL));
    signer.halg = ctx.halg;
    signer.key = key;
    assert_non_null(list_append(&ctx.signers, &signer, sizeof(signer)));
    memset(signature, 0, sizeof(signature));
    ret =
      rnp_protect_mem(&rnp, &ctx, data, strlen(data), signature, sizeof(signature), &siglen);
    assert_int_equal(ret, RNP_SUCCESS);
    rnp_ctx_free(&ctx);

    // verify
    rnp_ctx_init(&ctx, &rnp.rng);
    ctx.armor = false;
    ret = rnp_process_mem(&rnp, &ctx, signature, siglen, NULL, 0, NULL);
    assert_int_equal(ret, RNP_SUCCESS);
    rnp_ctx_free(&ctx);

    // verify (negative)
    rnp_ctx_init(&ctx, &rnp.rng);
    signature[siglen / 2] ^= 0xff;
    ret = rnp_process_mem(&rnp, &ctx, signature, siglen, NULL, 0, NULL);
    assert_int_not_equal(ret, RNP_SUCCESS);
    rnp_ctx_free(&ctx);

    // lock the signing key
    assert_true(pgp_key_lock(key));
    assert_true(pgp_key_is_locked(key));
    rnp.password_provider =
      (pgp_password_provider_t){.callback = failing_password_callback, .userdata = NULL};

    // sign, with no password (should now fail)
    rnp_ctx_init(&ctx, &rnp.rng);
    ctx.halg = pgp_str_to_hash_alg("SHA1");
    assert_non_null(key = rnp_key_store_get_key_by_name(rnp.secring, keyids[0], NULL));
    signer.key = key;
    signer.halg = ctx.halg;
    assert_non_null(list_append(&ctx.signers, &signer, sizeof(signer)));
    memset(signature, 0, sizeof(signature));
    ret =
      rnp_protect_mem(&rnp, &ctx, data, strlen(data), signature, sizeof(signature), &siglen);
    assert_int_not_equal(ret, RNP_SUCCESS);
    rnp_ctx_free(&ctx);

    // encrypt
    rnp_ctx_init(&ctx, &rnp.rng);
    ctx.ealg = PGP_SA_AES_256;
    assert_non_null(key = rnp_key_store_get_key_by_name(rnp.pubring, keyids[1], NULL));
    list_append(&ctx.recipients, &key, sizeof(key));
    // Note: keyids[1] is an encrypting subkey
    ret =
      rnp_protect_mem(&rnp, &ctx, data, strlen(data), encrypted, sizeof(encrypted), &enclen);
    assert_int_equal(ret, RNP_SUCCESS);
    rnp_ctx_free(&ctx);

    // try decrypting with a failing password provider (should fail)
    rnp.password_provider =
      (pgp_password_provider_t){.callback = failing_password_callback, .userdata = NULL};
    rnp_ctx_init(&ctx, &rnp.rng);
    ret =
      rnp_process_mem(&rnp, &ctx, encrypted, enclen, decrypted, sizeof(decrypted), &declen);
    assert_int_not_equal(ret, RNP_SUCCESS);
    rnp_ctx_free(&ctx);

    // grab the encrypting key to unlock
    assert_non_null(key = rnp_key_store_get_key_by_name(rnp.secring, keyids[1], NULL));

    // unlock the encrypting key
    provider = (pgp_password_provider_t){.callback = string_copy_password_callback,
                                         .userdata = (void *) "password"};
    assert_true(pgp_key_unlock(key, &provider));
    assert_false(pgp_key_is_locked(key));

    // decrypt, with no password
    rnp_ctx_init(&ctx, &rnp.rng);
    ret =
      rnp_process_mem(&rnp, &ctx, encrypted, enclen, decrypted, sizeof(decrypted), &declen);
    assert_int_equal(ret, RNP_SUCCESS);
    assert_int_equal(declen, strlen(data));
    assert_string_equal(data, decrypted);
    rnp_ctx_free(&ctx);

    // lock the encrypting key
    assert_true(pgp_key_lock(key));
    assert_true(pgp_key_is_locked(key));
    rnp.password_provider =
      (pgp_password_provider_t){.callback = failing_password_callback, .userdata = NULL};

    // decrypt, with no password (should now fail)
    rnp_ctx_init(&ctx, &rnp.rng);
    ret =
      rnp_process_mem(&rnp, &ctx, encrypted, enclen, decrypted, sizeof(decrypted), &declen);
    assert_int_not_equal(ret, RNP_SUCCESS);
    rnp_ctx_free(&ctx);

    // cleanup
    rnp_end(&rnp);
}
