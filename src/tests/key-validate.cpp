/*
 * Copyright (c) 2018-2019 [Ribose Inc](https://www.ribose.com).
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
#include "../librepgp/stream-packet.h"
#include "../librepgp/stream-armor.h"

static bool
all_keys_valid(const rnp_key_store_t *keyring, pgp_key_t *except = NULL)
{
    char keyid[PGP_KEY_ID_SIZE * 2 + 3] = {0};

    for (auto &key : keyring->keys) {
        if ((!key.valid() || key.expired()) && (&key != except)) {
            assert_true(rnp::hex_encode(key.keyid().data(),
                                        key.keyid().size(),
                                        keyid,
                                        sizeof(keyid),
                                        rnp::HEX_LOWERCASE));
            RNP_LOG("key %s is not valid", keyid);
            return false;
        }
    }
    return true;
}

TEST_F(rnp_tests, test_key_validate)
{
    rnp_key_store_t *pubring;
    rnp_key_store_t *secring;
    pgp_key_t *      key = NULL;

    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, "data/keyrings/1/pubring.gpg");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    /* this keyring has one expired subkey */
    assert_non_null(key = rnp_tests_get_key_by_id(pubring, "1d7e8a5393c997a8", NULL));
    assert_false(key->valid());
    assert_true(key->expired());
    assert_true(all_keys_valid(pubring, key));
    delete pubring;

    /* secret key doesn't have expired binding signature so considered as valid */
    secring = new rnp_key_store_t(PGP_KEY_STORE_GPG, "data/keyrings/1/secring.gpg");
    assert_true(rnp_key_store_load_from_path(secring, NULL));
    assert_non_null(key = rnp_tests_get_key_by_id(secring, "1d7e8a5393c997a8", NULL));
    assert_true(key->valid());
    assert_false(key->expired());
    assert_true(all_keys_valid(secring));
    delete secring;

    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, "data/keyrings/2/pubring.gpg");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_true(all_keys_valid(pubring));
    delete pubring;

    secring = new rnp_key_store_t(PGP_KEY_STORE_GPG, "data/keyrings/2/secring.gpg");
    assert_true(rnp_key_store_load_from_path(secring, NULL));
    assert_true(all_keys_valid(secring));
    delete secring;

    pubring = new rnp_key_store_t(PGP_KEY_STORE_KBX, "data/keyrings/3/pubring.kbx");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_true(all_keys_valid(pubring));

    secring = new rnp_key_store_t(PGP_KEY_STORE_G10, "data/keyrings/3/private-keys-v1.d");
    pgp_key_provider_t key_provider = {.callback = rnp_key_provider_store,
                                       .userdata = pubring};
    assert_true(rnp_key_store_load_from_path(secring, &key_provider));
    assert_true(all_keys_valid(secring));
    delete pubring;
    delete secring;

    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, "data/keyrings/4/pubring.pgp");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_true(all_keys_valid(pubring));
    delete pubring;

    secring = new rnp_key_store_t(PGP_KEY_STORE_GPG, "data/keyrings/4/secring.pgp");
    assert_true(rnp_key_store_load_from_path(secring, NULL));
    assert_true(all_keys_valid(secring));
    delete secring;

    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, "data/keyrings/5/pubring.gpg");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_true(all_keys_valid(pubring));
    delete pubring;

    secring = new rnp_key_store_t(PGP_KEY_STORE_GPG, "data/keyrings/5/secring.gpg");
    assert_true(rnp_key_store_load_from_path(secring, NULL));
    assert_true(all_keys_valid(secring));
    delete secring;
}

#define DATA_PATH "data/test_forged_keys/"

static void
key_store_add(rnp_key_store_t *keyring, const char *keypath)
{
    pgp_source_t           keysrc = {};
    pgp_transferable_key_t tkey = {};

    assert_rnp_success(init_file_src(&keysrc, keypath));
    assert_rnp_success(process_pgp_key(&keysrc, tkey, false));
    assert_true(rnp_key_store_add_transferable_key(keyring, &tkey));
    src_close(&keysrc);
}

static bool
key_check(rnp_key_store_t *keyring, const std::string &keyid, bool valid, bool expired = false)
{
    pgp_key_t *key = rnp_tests_get_key_by_id(keyring, keyid, NULL);
    return key && (key->validated()) && (key->valid() == valid) && (key->expired() == expired);
}

TEST_F(rnp_tests, test_forged_key_validate)
{
    rnp_key_store_t *pubring;
    pgp_key_t *      key = NULL;

    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, "");

    /* load valid dsa-eg key */
    key_store_add(pubring, DATA_PATH "dsa-eg-pub.pgp");
    assert_true(key_check(pubring, "C8A10A7D78273E10", true));
    rnp_key_store_clear(pubring);

    /* load dsa-eg key with forged self-signature and binding. Subkey will not be valid as
     * well. */
    key_store_add(pubring, DATA_PATH "dsa-eg-pub-forged-key.pgp");
    assert_true(key_check(pubring, "C8A10A7D78273E10", false));
    assert_true(key_check(pubring, "02A5715C3537717E", false));
    rnp_key_store_clear(pubring);

    /* load dsa-eg key with forged key material */
    key_store_add(pubring, DATA_PATH "dsa-eg-pub-forged-material.pgp");
    key = rnp_tests_get_key_by_id(pubring, "C8A10A7D78273E10", NULL);
    assert_null(key);
    /* malformed key material causes keyid change */
    key = rnp_tests_get_key_by_id(pubring, "C258AB3B54097B9B", NULL);
    assert_non_null(key);
    assert_false(key->valid());
    assert_false(key->expired());
    rnp_key_store_clear(pubring);

    /* load dsa-eg keypair with forged subkey binding signature */
    key_store_add(pubring, DATA_PATH "dsa-eg-pub-forged-subkey.pgp");
    assert_true(key_check(pubring, "02A5715C3537717E", false));
    assert_true(key_check(pubring, "C8A10A7D78273E10", true));
    rnp_key_store_clear(pubring);

    /* load valid eddsa key */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub.pgp");
    assert_true(key_check(pubring, "CC786278981B0728", true));
    rnp_key_store_clear(pubring);

    /* load eddsa key with forged self-signature */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub-forged-key.pgp");
    assert_true(key_check(pubring, "CC786278981B0728", false));
    rnp_key_store_clear(pubring);

    /* load eddsa key with forged key material */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub-forged-material.pgp");
    key = rnp_tests_get_key_by_id(pubring, "1BEF78DF765B79A2", NULL);
    assert_non_null(key);
    assert_false(key->valid());
    assert_false(key->expired());
    rnp_key_store_clear(pubring);

    /* load valid ecdsa/ecdh p-256 keypair */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub.pgp");
    assert_true(key_check(pubring, "23674F21B2441527", true));
    assert_true(key_check(pubring, "37E285E9E9851491", true));
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh key with forged self-signature. Both valid since there is valid binding.
     */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-forged-key.pgp");
    assert_true(key_check(pubring, "23674F21B2441527", true));
    assert_true(key_check(pubring, "37E285E9E9851491", true));
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh key with forged key material. Subkey is not valid as well. */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-forged-material.pgp");
    key = rnp_tests_get_key_by_id(pubring, "23674F21B2441527", NULL);
    assert_null(key);
    key = rnp_tests_get_key_by_id(pubring, "41DEA786D18E5184", NULL);
    assert_non_null(key);
    assert_false(key->valid());
    assert_false(key->expired());
    assert_true(key_check(pubring, "37E285E9E9851491", false));
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair with forged subkey binding signature */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-forged-subkey.pgp");
    assert_true(key_check(pubring, "37E285E9E9851491", false));
    assert_true(key_check(pubring, "23674F21B2441527", true));
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair without certification: valid since have binding */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-no-certification.pgp");
    assert_true(key_check(pubring, "23674F21B2441527", true));
    assert_true(key_check(pubring, "37E285E9E9851491", true));
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair without certification and invalid binding */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-no-cert-malf-binding.pgp");
    assert_true(key_check(pubring, "23674F21B2441527", false));
    assert_true(key_check(pubring, "37E285E9E9851491", false));
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair without subkey binding */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-no-binding.pgp");
    assert_true(key_check(pubring, "23674F21B2441527", true));
    assert_true(key_check(pubring, "37E285E9E9851491", false));
    rnp_key_store_clear(pubring);

    /* load valid rsa/rsa keypair */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub.pgp");
    assert_true(key_check(pubring, "2FB9179118898E8B", true));
    assert_true(key_check(pubring, "6E2F73008F8B8D6E", true));
    rnp_key_store_clear(pubring);

    /* load rsa/rsa key with forged self-signature. Valid because of valid binding. */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-forged-key.pgp");
    assert_true(key_check(pubring, "2FB9179118898E8B", true));
    assert_true(key_check(pubring, "6E2F73008F8B8D6E", true));
    rnp_key_store_clear(pubring);

    /* load rsa/rsa key with forged key material. Subkey is not valid as well. */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-forged-material.pgp");
    key = rnp_tests_get_key_by_id(pubring, "2FB9179118898E8B", NULL);
    assert_null(key);
    key = rnp_tests_get_key_by_id(pubring, "791B14952D8F906C", NULL);
    assert_non_null(key);
    assert_false(key->valid());
    assert_false(key->expired());
    assert_true(key_check(pubring, "6E2F73008F8B8D6E", false));
    rnp_key_store_clear(pubring);

    /* load rsa/rsa keypair with forged subkey binding signature */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-forged-subkey.pgp");
    assert_true(key_check(pubring, "2FB9179118898E8B", true));
    assert_true(key_check(pubring, "6E2F73008F8B8D6E", false));
    rnp_key_store_clear(pubring);

    /* load rsa/rsa keypair with future creation date */
    key_store_add(pubring, DATA_PATH "rsa-rsa-pub-future-key.pgp");
    assert_true(key_check(pubring, "3D032D00EE1EC3F5", false));
    assert_true(key_check(pubring, "021085B640CE8DCE", false));
    rnp_key_store_clear(pubring);

    /* load eddsa/rsa keypair with certification with future creation date - valid because of
     * binding. */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub-future-cert.pgp");
    assert_true(key_check(pubring, "D3B746FA852C2BE8", true));
    assert_true(key_check(pubring, "EB8C21ACDC15CA14", true));
    rnp_key_store_clear(pubring);

    /* load eddsa/rsa keypair with certification with future creation date - invalid because of
     * invalid binding. */
    key_store_add(pubring, DATA_PATH "ecc-25519-pub-future-cert-malf-bind.pgp");
    assert_true(key_check(pubring, "D3B746FA852C2BE8", false));
    assert_true(key_check(pubring, "EB8C21ACDC15CA14", false));
    rnp_key_store_clear(pubring);

    /* load ecdsa/rsa keypair with expired subkey */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-expired-subkey.pgp");
    assert_true(key_check(pubring, "23674F21B2441527", true));
    assert_true(key_check(pubring, "37E285E9E9851491", false, true));
    rnp_key_store_clear(pubring);

    /* load ecdsa/ecdh keypair with expired key */
    key_store_add(pubring, DATA_PATH "ecc-p256-pub-expired-key.pgp");
    assert_true(key_check(pubring, "23674F21B2441527", false, true));
    assert_true(key_check(pubring, "37E285E9E9851491", false));
    rnp_key_store_clear(pubring);

    delete pubring;
}

#define KEYSIG_PATH "data/test_key_validity/"

TEST_F(rnp_tests, test_key_validity)
{
    rnp_key_store_t *pubring;
    pgp_key_t *      key = NULL;

    /* Case1:
     * Keys: Alice [pub]
     * Alice is signed by Basil, but without the Basil's key.
     * Result: Alice [valid]
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case1/pubring.gpg");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_key_search(pubring, "Alice <alice@rnp>"));
    assert_true(key->valid());
    assert_false(key->expired());
    delete pubring;

    /* Case2:
     * Keys: Alice [pub], Basil [pub]
     * Alice is signed by Basil, Basil is signed by Alice, but Alice's self-signature is
     * corrupted.
     * Result: Alice [invalid], Basil [valid]
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case2/pubring.gpg");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_get_key_by_id(pubring, "0451409669FFDE3C", NULL));
    assert_false(key->valid());
    assert_false(key->expired());
    assert_non_null(key = rnp_tests_key_search(pubring, "Basil <basil@rnp>"));
    assert_true(key->valid());
    assert_false(key->expired());
    delete pubring;

    /* Case3:
     * Keys: Alice [pub], Basil [pub]
     * Alice is signed by Basil, but doesn't have self-signature
     * Result: Alice [invalid]
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case3/pubring.gpg");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_get_key_by_id(pubring, "0451409669FFDE3C", NULL));
    assert_false(key->valid());
    assert_false(key->expired());
    assert_non_null(key = rnp_tests_key_search(pubring, "Basil <basil@rnp>"));
    assert_true(key->valid());
    assert_false(key->expired());
    delete pubring;

    /* Case4:
     * Keys Alice [pub, sub]
     * Alice subkey has invalid binding signature
     * Result: Alice [valid], Alice sub [invalid]
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case4/pubring.gpg");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_key_search(pubring, "Alice <alice@rnp>"));
    assert_true(key->valid());
    assert_false(key->expired());
    assert_int_equal(key->subkey_count(), 1);
    pgp_key_t *subkey = NULL;
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_false(subkey->valid());
    assert_false(subkey->expired());
    delete pubring;

    /* Case5:
     * Keys Alice [pub, sub], Basil [pub]
     * Alice subkey has valid binding signature, but from the key Basil
     * Result: Alice [valid], Alice sub [invalid]
     *
     * Note: to re-generate keyring file, use generate.cpp from case5 folder.
     *       To build it, feed -DBUILD_TESTING_GENERATORS=On to the cmake.
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case5/pubring.gpg");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_key_search(pubring, "Alice <alice@rnp>"));
    assert_true(key->valid());
    assert_false(key->expired());
    assert_int_equal(key->subkey_count(), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_false(subkey->valid());
    assert_false(subkey->expired());
    delete pubring;

    /* Case6:
     * Keys Alice [pub, sub]
     * Key Alice has revocation signature by Alice, and subkey doesn't
     * Result: Alice [invalid], Alice sub [invalid]
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case6/pubring.gpg");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_key_search(pubring, "Alice <alice@rnp>"));
    assert_false(key->valid());
    assert_false(key->expired());
    assert_true(key->revoked());
    assert_int_equal(key->subkey_count(), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_false(subkey->valid());
    assert_false(subkey->expired());
    assert_false(subkey->revoked());
    delete pubring;

    /* Case7:
     * Keys Alice [pub, sub]
     * Alice subkey has revocation signature by Alice
     * Result: Alice [valid], Alice sub [invalid]
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case7/pubring.gpg");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_key_search(pubring, "Alice <alice@rnp>"));
    assert_true(key->valid());
    assert_false(key->expired());
    assert_false(key->revoked());
    assert_int_equal(key->subkey_count(), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_false(subkey->valid());
    assert_false(subkey->expired());
    assert_true(subkey->revoked());
    delete pubring;

    /* Case8:
     * Keys Alice [pub, sub]
     * Userid is stripped from the key, but it still has valid subkey binding
     * Result: Alice [valid], Alice sub[valid]
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case8/pubring.gpg");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_get_key_by_id(pubring, "0451409669FFDE3C", NULL));
    assert_true(key->valid());
    assert_int_equal(key->subkey_count(), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_true(subkey->valid());
    delete pubring;

    /* Case9:
     * Keys Alice [pub, sub]
     * Alice key has two self-signatures, one which expires key and second without key
     * expiration.
     * Result: Alice [valid], Alice sub[valid]
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case9/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_get_key_by_id(pubring, "0451409669FFDE3C", NULL));
    assert_true(key->valid());
    assert_false(key->expired());
    assert_int_equal(key->subkey_count(), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_true(subkey->valid());
    assert_false(subkey->expired());
    delete pubring;

    /* Case10:
     * Keys Alice [pub, sub]
     * Alice key has expiring direct-key signature and non-expiring self-certification.
     * Result: Alice [invalid], Alice sub[invalid]
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case10/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_get_key_by_id(pubring, "0451409669FFDE3C", NULL));
    assert_false(key->valid());
    assert_true(key->expired());
    assert_int_equal(key->subkey_count(), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_false(subkey->valid());
    assert_false(subkey->expired());
    delete pubring;

    /* Case11:
     * Keys Alice [pub, sub]
     * Alice key has expiring direct-key signature, non-expiring self-certification and
     * expiring primary userid certification. Result: Alice [invalid], Alice sub[invalid]
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case11/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_get_key_by_id(pubring, "0451409669FFDE3C", NULL));
    assert_false(key->valid());
    assert_true(key->expired());
    assert_int_equal(key->expiration(), 100);
    assert_int_equal(key->subkey_count(), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_false(subkey->valid());
    assert_false(subkey->expired());
    delete pubring;

    /* Case12:
     * Keys Alice [pub, sub]
     * Alice key has non-expiring direct-key signature, non-expiring self-certification and
     * expiring primary userid certification. Result: Alice [invalid], Alice sub[invalid]
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case12/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_get_key_by_id(pubring, "0451409669FFDE3C", NULL));
    assert_false(key->valid());
    assert_true(key->expired());
    assert_int_equal(key->expiration(), 2000);
    assert_int_equal(key->subkey_count(), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_false(subkey->valid());
    assert_false(subkey->expired());
    delete pubring;

    /* Case13:
     * Keys Alice [pub, sub]
     * Alice key has expiring direct-key signature, non-expiring self-certification and
     * non-expiring primary userid certification. Result: Alice [invalid], Alice sub[invalid]
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case13/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_get_key_by_id(pubring, "0451409669FFDE3C", NULL));
    assert_false(key->valid());
    assert_true(key->expired());
    assert_int_equal(key->expiration(), 6);
    assert_int_equal(key->subkey_count(), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_false(subkey->valid());
    assert_false(subkey->expired());
    delete pubring;

    /* Case14:
     * Keys Alice [pub, sub]
     * Alice key has expiring direct-key signature, non-expiring self-certification and
     * non-expiring primary userid certification (with 0 key expiration subpacket). Result:
     * Alice [invalid], Alice sub[invalid]
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case14/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_get_key_by_id(pubring, "0451409669FFDE3C", NULL));
    assert_false(key->valid());
    assert_true(key->expired());
    assert_int_equal(key->expiration(), 6);
    assert_int_equal(key->subkey_count(), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_false(subkey->valid());
    assert_false(subkey->expired());
    delete pubring;

    /* Case15:
     * Keys [pub, sub]
     * Signing subkey has expired primary-key signature embedded into the subkey binding.
     * Result: primary [valid], sub[invalid]
     */
    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "case15/pubring.gpg");
    assert_non_null(pubring);
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(key = rnp_tests_get_key_by_id(pubring, "E863072D3E9042EE", NULL));
    assert_true(key->valid());
    assert_false(key->expired());
    assert_int_equal(key->expiration(), 0);
    assert_int_equal(key->subkey_count(), 1);
    assert_non_null(subkey = pgp_key_get_subkey(key, pubring, 0));
    assert_false(subkey->valid());
    assert_false(subkey->expired());
    delete pubring;
}

TEST_F(rnp_tests, test_key_expiry_direct_sig)
{
    /* this test was mainly used to generate test data for cases 10-12 in test_key_validity */
    rnp_key_store_t *secring =
      new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "alice-sub-sec.pgp");
    assert_true(rnp_key_store_load_from_path(secring, NULL));
    pgp_key_t *key = NULL;
    assert_non_null(key = rnp_tests_key_search(secring, "Alice <alice@rnp>"));
    assert_true(key->valid());
    assert_false(key->expired());
    /* create direct-key signature */
    pgp_signature_t sig;

    sig.version = PGP_V4;
    sig.halg = PGP_HASH_SHA256;
    sig.palg = key->alg();
    sig.set_type(PGP_SIG_DIRECT);
    sig.set_creation(key->creation());
    sig.set_key_expiration(1000);
    sig.set_keyfp(key->fp());
    sig.set_keyid(key->keyid());

    pgp_password_provider_t pprov = {.callback = string_copy_password_callback,
                                     .userdata = (void *) "password"};
    key->unlock(pprov);
    assert_true(signature_calculate_direct(&key->pkt(), &sig, &key->pkt()));
    key->add_sig(sig, PGP_UID_NONE);
    key->revalidate(*secring);

    /* key is still valid since it is secret */
    assert_int_equal(key->expiration(), 1000);
    assert_true(key->valid());
    assert_false(key->expired());

    rnp_key_store_t *pubring =
      new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "alice-sub-pub.pgp");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    pgp_key_t *pubkey = NULL;
    assert_non_null(pubkey = rnp_tests_key_search(pubring, "Alice <alice@rnp>"));
    assert_int_equal(pubkey->expiration(), 0);
    assert_true(pubkey->valid());
    assert_false(pubkey->expired());
    pgp_key_t *subpub = NULL;
    assert_non_null(subpub = rnp_tests_get_key_by_id(pubring, "dd23ceb7febeff17", NULL));
    assert_int_equal(subpub->expiration(), 0);
    assert_true(subpub->valid());
    assert_false(subpub->expired());

    pubkey->add_sig(sig, PGP_UID_NONE);
    pubkey->revalidate(*pubring);
    assert_int_equal(pubkey->expiration(), 1000);
    assert_false(pubkey->valid());
    assert_true(pubkey->expired());
    assert_int_equal(subpub->expiration(), 0);
    assert_false(subpub->valid());
    assert_false(subpub->expired());

    /* add primary userid with smaller expiration date */
    rnp_selfsig_cert_info_t selfsig1 = {};
    const char *            boris = "Boris <boris@rnp>";
    memcpy(selfsig1.userid, boris, strlen(boris));
    selfsig1.key_expiration = 100;
    selfsig1.primary = true;
    assert_true(pgp_key_add_userid_certified(key, &key->pkt(), PGP_HASH_SHA256, &selfsig1));
    key->revalidate(*secring);
    /* key is still valid since it is secret, however expiration was changed */
    assert_int_equal(key->expiration(), 100);
    assert_true(key->valid());
    assert_false(key->expired());

    delete secring;
    delete pubring;

    secring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "alice-sub-sec.pgp");
    assert_true(rnp_key_store_load_from_path(secring, NULL));
    assert_non_null(key = rnp_tests_key_search(secring, "Alice <alice@rnp>"));
    /* create direct-key signature */
    sig = {};
    sig.version = PGP_V4;
    sig.halg = PGP_HASH_SHA256;
    sig.palg = key->alg();
    sig.set_type(PGP_SIG_DIRECT);
    sig.set_creation(key->creation());
    sig.set_key_expiration(6);
    sig.set_keyfp(key->fp());
    sig.set_keyid(key->keyid());

    key->unlock(pprov);
    assert_true(signature_calculate_direct(&key->pkt(), &sig, &key->pkt()));
    key->add_sig(sig, PGP_UID_NONE);
    key->revalidate(*secring);
    assert_int_equal(key->expiration(), 6);
    /* add primary userid with 0 expiration */
    selfsig1 = {};
    memcpy(selfsig1.userid, boris, strlen(boris));
    selfsig1.key_expiration = 0;
    selfsig1.primary = true;
    assert_true(pgp_key_add_userid_certified(key, &key->pkt(), PGP_HASH_SHA256, &selfsig1));
    key->revalidate(*secring);
    assert_int_equal(key->expiration(), 6);

    pubring = new rnp_key_store_t(PGP_KEY_STORE_GPG, KEYSIG_PATH "alice-sub-pub.pgp");
    assert_true(rnp_key_store_load_from_path(pubring, NULL));
    assert_non_null(pubkey = rnp_tests_key_search(pubring, "Alice <alice@rnp>"));
    assert_non_null(subpub = rnp_tests_get_key_by_id(pubring, "dd23ceb7febeff17", NULL));
    assert_int_equal(subpub->expiration(), 0);
    assert_true(subpub->valid());
    assert_false(subpub->expired());

    pubkey->add_sig(sig, PGP_UID_NONE);
    pubkey->revalidate(*pubring);
    assert_int_equal(pubkey->expiration(), 6);
    assert_false(pubkey->valid());
    assert_true(pubkey->expired());

    pgp_transferable_userid_t truid = {};
    truid.uid = key->get_uid(1).pkt;
    truid.signatures.push_back(key->get_sig(key->get_uid(1).get_sig(0)).sig);
    pubkey->add_uid(truid);
    pubkey->revalidate(*pubring);

    assert_int_equal(pubkey->expiration(), 6);
    assert_false(pubkey->valid());
    assert_true(pubkey->expired());

    /* code below may be used to print out generated key to save it somewhere */
    /*
    pgp_dest_t out = {};
    pgp_dest_t armored = {};
    assert_rnp_success(init_stdout_dest(&out));
    assert_rnp_success(init_armored_dst(&armored, &out, PGP_ARMORED_PUBLIC_KEY));
    pubkey->write_xfer(armored, pubring);
    dst_close(&armored, false);
    dst_close(&out, false);
    */

    delete secring;
    delete pubring;
}
