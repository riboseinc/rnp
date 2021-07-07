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

#include "rnp.h"
#include <rekey/rnp_key_store.h>
#include <rnp/rnpcfg.h>
#include <rnpkeys/rnpkeys.h>

#include "rnp_tests.h"
#include "support.h"
#include "crypto/common.h"
#include "crypto.h"
#include "pgp-key.h"
#include "librepgp/stream-ctx.h"
#include "librepgp/stream-sig.h"
#include "librepgp/stream-key.h"
#include "defaults.h"
#include <fstream>

extern rng_t global_rng;

static bool
generate_test_key(const char *keystore, const char *userid, const char *hash, const char *home)
{
    cli_rnp_t rnp;
    int       pipefd[2] = {-1, -1};
    bool      res = false;
    size_t    keycount = 0;

    /* Initialize the cli rnp structure and generate key */
    if (!setup_cli_rnp_common(&rnp, keystore, home, pipefd)) {
        return false;
    }

    std::vector<rnp_key_handle_t> keys;
    /* Generate the key */
    cli_set_default_rsa_key_desc(cli_rnp_cfg(rnp), hash);
    if (!cli_rnp_generate_key(&rnp, userid)) {
        goto done;
    }

    if (!cli_rnp_load_keyrings(&rnp, true)) {
        goto done;
    }
    if (rnp_get_public_key_count(rnp.ffi, &keycount) || (keycount != 2)) {
        goto done;
    }
    if (rnp_get_secret_key_count(rnp.ffi, &keycount) || (keycount != 2)) {
        goto done;
    }
    if (!cli_rnp_keys_matching_string(
          &rnp, keys, userid ? userid : "", CLI_SEARCH_SUBKEYS_AFTER)) {
        goto done;
    }
    if (keys.size() != 2) {
        goto done;
    }
    res = true;
done:
    if (pipefd[0] != -1) {
        close(pipefd[0]);
    }
    clear_key_handles(keys);
    cli_rnp_end(&rnp);
    return res;
}

static bool
hash_supported(const std::string &hash)
{
    if (!sm2_enabled() && lowercase(hash) == "sm3") {
        return false;
    }
    return true;
}

TEST_F(rnp_tests, rnpkeys_generatekey_testSignature)
{
    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new pair of private/public
     * key
     * Sign a message, then verify it
     */

    const char *hashAlg[] = {"SHA1",
                             "SHA224",
                             "SHA256",
                             "SHA384",
                             "SHA512",
                             "SM3",
                             "sha1",
                             "sha224",
                             "sha256",
                             "sha384",
                             "sha512",
                             "sm3",
                             NULL};
    int         pipefd[2] = {-1, -1};
    char        memToSign[] = "A simple test message";
    cli_rnp_t   rnp;

    std::ofstream out("dummyfile.dat");
    out << memToSign;
    out.close();

    for (int i = 0; hashAlg[i] != NULL; i++) {
        std::string userId = std::string("sigtest_") + hashAlg[i];
        /* Generate key for test */
        assert_true(
          generate_test_key(RNP_KEYSTORE_GPG, userId.c_str(), DEFAULT_HASH_ALG, NULL));

        for (unsigned int cleartext = 0; cleartext <= 1; ++cleartext) {
            for (unsigned int armored = 0; armored <= 1; ++armored) {
                if (cleartext && !armored) {
                    // This combination doesn't make sense
                    continue;
                }
                /* Setup password input and rnp structure */
                assert_true(setup_cli_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, pipefd));
                /* Load keyring */
                assert_true(cli_rnp_load_keyrings(&rnp, true));
                size_t seccount = 0;
                assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &seccount));
                assert_true(seccount > 0);

                /* Setup signing context */
                rnp_cfg &cfg = cli_rnp_cfg(rnp);
                cfg.load_defaults();
                cfg.set_bool(CFG_ARMOR, armored);
                cfg.set_bool(CFG_SIGN_NEEDED, true);
                cfg.set_str(CFG_HASH, hashAlg[i]);
                cfg.set_int(CFG_ZLEVEL, 0);
                cfg.set_str(CFG_INFILE, "dummyfile.dat");
                cfg.set_str(CFG_OUTFILE, "dummyfile.dat.pgp");
                cfg.set_bool(CFG_CLEARTEXT, cleartext);
                cfg.add_str(CFG_SIGNERS, userId);

                /* Sign the file */
                if (!hash_supported(hashAlg[i])) {
                    assert_false(cli_rnp_protect_file(&rnp));
                    cli_rnp_end(&rnp);
                    assert_int_equal(rnp_unlink("dummyfile.dat.pgp"), -1);
                    continue;
                }
                assert_true(cli_rnp_protect_file(&rnp));
                if (pipefd[0] != -1) {
                    close(pipefd[0]);
                    pipefd[0] = -1;
                }

                /* Verify the file */
                cfg.clear();
                cfg.load_defaults();
                cfg.set_bool(CFG_OVERWRITE, true);
                cfg.set_str(CFG_INFILE, "dummyfile.dat.pgp");
                cfg.set_str(CFG_OUTFILE, "dummyfile.verify");
                assert_true(cli_rnp_process_file(&rnp));

                /* Ensure signature verification passed */
                std::string verify = file_to_str("dummyfile.verify");
                if (cleartext) {
                    verify = strip_eol(verify);
                }
                assert_true(verify == memToSign);

                /* Corrupt the signature if not armored/cleartext */
                if (!cleartext && !armored) {
                    std::fstream verf("dummyfile.dat.pgp",
                                      std::ios_base::binary | std::ios_base::out |
                                        std::ios_base::in);
                    off_t        versize = file_size("dummyfile.dat.pgp");
                    verf.seekg(versize - 10, std::ios::beg);
                    char sigch = 0;
                    verf.read(&sigch, 1);
                    sigch = sigch ^ 0xff;
                    verf.seekg(versize - 10, std::ios::beg);
                    verf.write(&sigch, 1);
                    verf.close();
                    assert_false(cli_rnp_process_file(&rnp));
                }

                cli_rnp_end(&rnp);
                assert_int_equal(rnp_unlink("dummyfile.dat.pgp"), 0);
                rnp_unlink("dummyfile.verify");
            }
        }
    }
    assert_int_equal(rnp_unlink("dummyfile.dat"), 0);
}

static bool
cipher_supported(const std::string &cipher)
{
    if (!sm2_enabled() && lowercase(cipher) == "sm4") {
        return false;
    }
    if (!twofish_enabled() && lowercase(cipher) == "twofish") {
        return false;
    }
    return true;
}

TEST_F(rnp_tests, rnpkeys_generatekey_testEncryption)
{
    const char *cipherAlg[] = {
      "BLOWFISH",    "TWOFISH",     "CAST5",       "TRIPLEDES",   "AES128", "AES192",
      "AES256",      "CAMELLIA128", "CAMELLIA192", "CAMELLIA256", "SM4",    "blowfish",
      "twofish",     "cast5",       "tripledes",   "aes128",      "aes192", "aes256",
      "camellia128", "camellia192", "camellia256", "sm4",         NULL};

    cli_rnp_t   rnp = {};
    char        memToEncrypt[] = "A simple test message";
    int         pipefd[2] = {-1, -1};
    const char *userid = "ciphertest";

    std::ofstream out("dummyfile.dat");
    out << memToEncrypt;
    out.close();

    assert_true(generate_test_key(RNP_KEYSTORE_GPG, userid, "SHA256", NULL));
    for (int i = 0; cipherAlg[i] != NULL; i++) {
        for (unsigned int armored = 0; armored <= 1; ++armored) {
            /* Set up rnp and encrypt the dataa */
            assert_true(setup_cli_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, NULL));
            /* Load keyring */
            assert_true(cli_rnp_load_keyrings(&rnp, false));
            size_t seccount = 0;
            assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &seccount));
            assert_true(seccount == 0);
            /* Set the cipher and armored flags */
            rnp_cfg &cfg = cli_rnp_cfg(rnp);
            cfg.load_defaults();
            cfg.set_bool(CFG_ARMOR, armored);
            cfg.set_bool(CFG_ENCRYPT_PK, true);
            cfg.set_int(CFG_ZLEVEL, 0);
            cfg.set_str(CFG_INFILE, "dummyfile.dat");
            cfg.set_str(CFG_OUTFILE, "dummyfile.dat.pgp");
            cfg.set_str(CFG_CIPHER, cipherAlg[i]);
            cfg.add_str(CFG_RECIPIENTS, userid);
            /* Encrypt the file */
            bool supported = cipher_supported(cipherAlg[i]);
            assert_true(cli_rnp_protect_file(&rnp) == supported);
            cli_rnp_end(&rnp);
            if (!supported) {
                continue;
            }

            /* Set up rnp again and decrypt the file */
            assert_true(setup_cli_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, pipefd));
            /* Load the keyrings */
            assert_true(cli_rnp_load_keyrings(&rnp, true));
            assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &seccount));
            assert_true(seccount > 0);
            /* Setup the decryption context and decrypt */
            rnp_cfg &newcfg = cli_rnp_cfg(rnp);
            newcfg.load_defaults();
            newcfg.set_bool(CFG_OVERWRITE, true);
            newcfg.set_str(CFG_INFILE, "dummyfile.dat.pgp");
            newcfg.set_str(CFG_OUTFILE, "dummyfile.decrypt");
            assert_true(cli_rnp_process_file(&rnp));
            cli_rnp_end(&rnp);
            if (pipefd[0] != -1) {
                close(pipefd[0]);
            }

            /* Ensure plaintext recovered */
            std::string decrypt = file_to_str("dummyfile.decrypt");
            assert_true(decrypt == memToEncrypt);
            assert_int_equal(rnp_unlink("dummyfile.dat.pgp"), 0);
            assert_int_equal(rnp_unlink("dummyfile.decrypt"), 0);
        }
    }
    assert_int_equal(rnp_unlink("dummyfile.dat"), 0);
}

TEST_F(rnp_tests, rnpkeys_generatekey_verifySupportedHashAlg)
{
    /* Generate key for each of the hash algorithms. Check whether key was generated
     * successfully */

    const char *hashAlg[] = {"MD5",
                             "SHA1",
                             "SHA256",
                             "SHA384",
                             "SHA512",
                             "SHA224",
                             "SM3",
                             "md5",
                             "sha1",
                             "sha256",
                             "sha384",
                             "sha512",
                             "sha224",
                             "sm3"};
    const char *keystores[] = {RNP_KEYSTORE_GPG, RNP_KEYSTORE_GPG21, RNP_KEYSTORE_KBX};
    cli_rnp_t   rnp = {};

    for (size_t i = 0; i < ARRAY_SIZE(hashAlg); i++) {
        const char *keystore = keystores[i % ARRAY_SIZE(keystores)];
        /* Setting up rnp again and decrypting memory */
        printf("keystore: %s, hashalg %s\n", keystore, hashAlg[i]);
        /* Generate key with specified hash algorithm */
        bool supported = hash_supported(hashAlg[i]);
        assert_true(generate_test_key(keystore, hashAlg[i], hashAlg[i], NULL) == supported);
        if (!supported) {
            continue;
        }
        /* Load and check key */
        assert_true(setup_cli_rnp_common(&rnp, keystore, NULL, NULL));
        /* Loading the keyrings */
        assert_true(cli_rnp_load_keyrings(&rnp, true));
        /* Some minor checks */
        size_t keycount = 0;
        assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &keycount));
        assert_true(keycount > 0);
        keycount = 0;
        assert_rnp_success(rnp_get_public_key_count(rnp.ffi, &keycount));
        assert_true(keycount > 0);
        rnp_key_handle_t handle = NULL;
        assert_rnp_success(rnp_locate_key(rnp.ffi, "userid", hashAlg[i], &handle));
        assert_non_null(handle);
        rnp_key_handle_destroy(handle);
        cli_rnp_end(&rnp);
        delete_recursively(".rnp");
    }
}

TEST_F(rnp_tests, rnpkeys_generatekey_verifyUserIdOption)
{
    /* Set the UserId = custom value.
     * Execute the Generate-key command to generate a new keypair
     * Verify the key was generated with the correct UserId. */

    const char *userIds[] = {"rnpkeys_generatekey_verifyUserIdOption_MD5",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA-1",
                             "rnpkeys_generatekey_verifyUserIdOption_RIPEMD160",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA256",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA384",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA512",
                             "rnpkeys_generatekey_verifyUserIdOption_SHA224"};

    const char *keystores[] = {RNP_KEYSTORE_GPG, RNP_KEYSTORE_GPG21, RNP_KEYSTORE_KBX};
    cli_rnp_t   rnp = {};

    for (size_t i = 0; i < ARRAY_SIZE(userIds); i++) {
        const char *keystore = keystores[i % ARRAY_SIZE(keystores)];
        /* Generate key with specified hash algorithm */
        assert_true(generate_test_key(keystore, userIds[i], "SHA256", NULL));

        /* Initialize the basic RNP structure. */
        assert_true(setup_cli_rnp_common(&rnp, keystore, NULL, NULL));
        /* Load the newly generated rnp key*/
        assert_true(cli_rnp_load_keyrings(&rnp, true));
        size_t keycount = 0;
        assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &keycount));
        assert_true(keycount > 0);
        keycount = 0;
        assert_rnp_success(rnp_get_public_key_count(rnp.ffi, &keycount));
        assert_true(keycount > 0);

        rnp_key_handle_t handle = NULL;
        assert_rnp_success(rnp_locate_key(rnp.ffi, "userid", userIds[i], &handle));
        assert_non_null(handle);
        rnp_key_handle_destroy(handle);
        cli_rnp_end(&rnp);
        delete_recursively(".rnp");
    }
}

TEST_F(rnp_tests, rnpkeys_generatekey_verifykeyHomeDirOption)
{
    /* Try to generate keypair in different home directories */
    cli_rnp_t rnp = {};

    /* Initialize the rnp structure. */
    assert_true(setup_cli_rnp_common(&rnp, RNP_KEYSTORE_GPG, NULL, NULL));

    /* Pubring and secring should not exist yet */
    assert_false(path_rnp_file_exists(".rnp/pubring.gpg", NULL));
    assert_false(path_rnp_file_exists(".rnp/secring.gpg", NULL));

    /* Ensure the key was generated. */
    assert_true(generate_test_key(RNP_KEYSTORE_GPG, NULL, "SHA256", NULL));

    /* Pubring and secring should now exist */
    assert_true(path_rnp_file_exists(".rnp/pubring.gpg", NULL));
    assert_true(path_rnp_file_exists(".rnp/secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    assert_true(cli_rnp_load_keyrings(&rnp, true));
    size_t keycount = 0;
    assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);
    keycount = 0;
    assert_rnp_success(rnp_get_public_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);

    std::string userid =
      fmt("RSA (Encrypt or Sign) 1024-bit key <%s@localhost>", getenv_logname());
    rnp_key_handle_t handle = NULL;
    assert_rnp_success(rnp_locate_key(rnp.ffi, "userid", userid.c_str(), &handle));
    assert_non_null(handle);
    rnp_key_handle_destroy(handle);
    cli_rnp_end(&rnp);

    /* Now we start over with a new home. When home is specified explicitly then it should
     * include .rnp as well */
    std::string newhome = "newhome/.rnp";
    path_mkdir(0700, "newhome", NULL);
    path_mkdir(0700, newhome.c_str(), NULL);

    /* Initialize the rnp structure. */
    assert_true(setup_cli_rnp_common(&rnp, RNP_KEYSTORE_GPG, newhome.c_str(), NULL));

    /* Pubring and secring should not exist yet */
    assert_false(path_rnp_file_exists(newhome.c_str(), "pubring.gpg", NULL));
    assert_false(path_rnp_file_exists(newhome.c_str(), "secring.gpg", NULL));

    /* Ensure the key was generated. */
    assert_true(generate_test_key(RNP_KEYSTORE_GPG, "newhomekey", "SHA256", newhome.c_str()));

    /* Pubring and secring should now exist */
    assert_true(path_rnp_file_exists(newhome.c_str(), "pubring.gpg", NULL));
    assert_true(path_rnp_file_exists(newhome.c_str(), "secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    assert_true(cli_rnp_load_keyrings(&rnp, true));
    keycount = 0;
    assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);
    keycount = 0;
    assert_rnp_success(rnp_get_public_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);

    /* We should not find this key */
    assert_rnp_success(rnp_locate_key(rnp.ffi, "userid", userid.c_str(), &handle));
    assert_null(handle);
    assert_rnp_success(rnp_locate_key(rnp.ffi, "userid", "newhomekey", &handle));
    assert_non_null(handle);
    rnp_key_handle_destroy(handle);
    cli_rnp_end(&rnp); // Free memory and other allocated resources.
}

TEST_F(rnp_tests, rnpkeys_generatekey_verifykeyKBXHomeDirOption)
{
    /* Try to generate keypair in different home directories for KBX keystorage */
    const char *newhome = "newhome";
    cli_rnp_t   rnp = {};

    /* Initialize the rnp structure. */
    assert_true(setup_cli_rnp_common(&rnp, RNP_KEYSTORE_KBX, NULL, NULL));
    /* Pubring and secring should not exist yet */
    assert_false(path_rnp_file_exists(".rnp/pubring.kbx", NULL));
    assert_false(path_rnp_file_exists(".rnp/secring.kbx", NULL));
    assert_false(path_rnp_file_exists(".rnp/pubring.gpg", NULL));
    assert_false(path_rnp_file_exists(".rnp/secring.gpg", NULL));
    /* Ensure the key was generated. */
    assert_true(generate_test_key(RNP_KEYSTORE_KBX, NULL, "SHA256", NULL));
    /* Pubring and secring should now exist, but only for the KBX */
    assert_true(path_rnp_file_exists(".rnp/pubring.kbx", NULL));
    assert_true(path_rnp_file_exists(".rnp/secring.kbx", NULL));
    assert_false(path_rnp_file_exists(".rnp/pubring.gpg", NULL));
    assert_false(path_rnp_file_exists(".rnp/secring.gpg", NULL));

    /* Loading keyrings and checking whether they have correct key */
    assert_true(cli_rnp_load_keyrings(&rnp, true));
    size_t keycount = 0;
    assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);
    keycount = 0;
    assert_rnp_success(rnp_get_public_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);
    std::string userid =
      fmt("RSA (Encrypt or Sign) 1024-bit key <%s@localhost>", getenv_logname());
    rnp_key_handle_t handle = NULL;
    assert_rnp_success(rnp_locate_key(rnp.ffi, "userid", userid.c_str(), &handle));
    assert_non_null(handle);
    rnp_key_handle_destroy(handle);
    cli_rnp_end(&rnp);

    /* Now we start over with a new home. */
    path_mkdir(0700, newhome, NULL);
    /* Initialize the rnp structure. */
    assert_true(setup_cli_rnp_common(&rnp, RNP_KEYSTORE_KBX, newhome, NULL));
    /* Pubring and secring should not exist yet */
    assert_false(path_rnp_file_exists(newhome, "pubring.kbx", NULL));
    assert_false(path_rnp_file_exists(newhome, "secring.kbx", NULL));
    assert_false(path_rnp_file_exists(newhome, "pubring.gpg", NULL));
    assert_false(path_rnp_file_exists(newhome, "secring.gpg", NULL));

    /* Ensure the key was generated. */
    assert_true(generate_test_key(RNP_KEYSTORE_KBX, "newhomekey", "SHA256", newhome));
    /* Pubring and secring should now exist, but only for the KBX */
    assert_true(path_rnp_file_exists(newhome, "pubring.kbx", NULL));
    assert_true(path_rnp_file_exists(newhome, "secring.kbx", NULL));
    assert_false(path_rnp_file_exists(newhome, "pubring.gpg", NULL));
    assert_false(path_rnp_file_exists(newhome, "secring.gpg", NULL));
    /* Loading keyrings and checking whether they have correct key */
    assert_true(cli_rnp_load_keyrings(&rnp, true));
    keycount = 0;
    assert_rnp_success(rnp_get_secret_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);
    keycount = 0;
    assert_rnp_success(rnp_get_public_key_count(rnp.ffi, &keycount));
    assert_int_equal(keycount, 2);
    /* We should not find this key */
    assert_rnp_success(rnp_locate_key(rnp.ffi, "userid", userid.c_str(), &handle));
    assert_null(handle);
    assert_rnp_success(rnp_locate_key(rnp.ffi, "userid", "newhomekey", &handle));
    assert_non_null(handle);
    rnp_key_handle_destroy(handle);
    cli_rnp_end(&rnp);
}

TEST_F(rnp_tests, rnpkeys_generatekey_verifykeyHomeDirNoPermission)
{
    const char *nopermsdir = "noperms";
    path_mkdir(0000, nopermsdir, NULL);
/* Try to generate key in the directory and make sure generation fails */
#ifndef _WIN32
    assert_false(generate_test_key(RNP_KEYSTORE_GPG, NULL, "SHA256", nopermsdir));
#else
    /* There are no permissions for mkdir() under the Windows */
    assert_true(generate_test_key(RNP_KEYSTORE_GPG, NULL, "SHA256", nopermsdir));
#endif
}

static bool
ask_expert_details(cli_rnp_t *ctx, rnp_cfg &ops, const char *rsp)
{
    /* Run tests*/
    bool   ret = false;
    int    pipefd[2] = {-1, -1};
    int    user_input_pipefd[2] = {-1, -1};
    size_t rsp_len;

    if (pipe(pipefd) == -1) {
        return false;
    }
    ops.set_int(CFG_PASSFD, pipefd[0]);
    write_pass_to_pipe(pipefd[1], 2);
    close(pipefd[1]);
    if (!rnpkeys_init(ctx, ops)) {
        close(pipefd[0]); // otherwise will be closed via passfp
        goto end;
    }

    /* Write response to fd */
    if (pipe(user_input_pipefd) == -1) {
        goto end;
    }
    rsp_len = strlen(rsp);
    for (size_t i = 0; i < rsp_len;) {
        i += write(user_input_pipefd[1], rsp + i, rsp_len - i);
    }
    close(user_input_pipefd[1]);

    /* Mock user-input*/
    cli_rnp_cfg(*ctx).set_int(CFG_USERINPUTFD, user_input_pipefd[0]);

    if (!rnp_cmd(ctx, CMD_GENERATE_KEY, NULL)) {
        ret = false;
        goto end;
    }
    ops.copy(cli_rnp_cfg(*ctx));
    ret = true;
end:
    /* Close & clean fd*/
    if (user_input_pipefd[0]) {
        close(user_input_pipefd[0]);
    }
    return ret;
}

static bool
check_key_props(cli_rnp_t * rnp,
                const char *uid,
                const char *primary_alg,
                const char *sub_alg,
                const char *primary_curve,
                const char *sub_curve,
                int         bits,
                int         sub_bits,
                const char *hash)
{
    rnp_key_handle_t       key = NULL;
    rnp_key_handle_t       subkey = NULL;
    rnp_signature_handle_t sig = NULL;
    uint32_t               kbits = 0;
    char *                 str = NULL;
    bool                   res = false;

    /* check primary key properties */
    if (rnp_locate_key(rnp->ffi, "userid", uid, &key) || !key) {
        return false;
    }
    if (rnp_key_get_alg(key, &str) || strcmp(str, primary_alg)) {
        goto done;
    }
    rnp_buffer_destroy(str);
    str = NULL;

    if (primary_curve && (rnp_key_get_curve(key, &str) || strcmp(str, primary_curve))) {
        goto done;
    }
    rnp_buffer_destroy(str);
    str = NULL;
    if (bits && (rnp_key_get_bits(key, &kbits) || (bits != (int) kbits))) {
        goto done;
    }

    /* check subkey properties */
    if (!sub_alg) {
        res = true;
        goto done;
    }

    if (rnp_key_get_subkey_at(key, 0, &subkey)) {
        goto done;
    }

    if (rnp_key_get_alg(subkey, &str) || strcmp(str, sub_alg)) {
        goto done;
    }
    rnp_buffer_destroy(str);
    str = NULL;

    if (sub_curve && (rnp_key_get_curve(subkey, &str) || strcmp(str, sub_curve))) {
        goto done;
    }
    rnp_buffer_destroy(str);
    str = NULL;
    if (sub_bits && (rnp_key_get_bits(subkey, &kbits) || (sub_bits != (int) kbits))) {
        goto done;
    }

    if (rnp_key_get_signature_at(subkey, 0, &sig) || !sig) {
        goto done;
    }
    if (rnp_signature_get_hash_alg(sig, &str) || strcmp(str, hash)) {
        goto done;
    }

    res = true;
done:
    rnp_signature_handle_destroy(sig);
    rnp_key_handle_destroy(key);
    rnp_key_handle_destroy(subkey);
    rnp_buffer_destroy(str);
    return res;
}

static bool
check_cfg_props(const rnp_cfg &cfg,
                const char *   primary_alg,
                const char *   sub_alg,
                const char *   primary_curve,
                const char *   sub_curve,
                int            bits,
                int            sub_bits)
{
    if (cfg.get_str(CFG_KG_PRIMARY_ALG) != primary_alg) {
        return false;
    }
    if (cfg.get_str(CFG_KG_SUBKEY_ALG) != sub_alg) {
        return false;
    }
    if (primary_curve && (cfg.get_str(CFG_KG_PRIMARY_CURVE) != primary_curve)) {
        return false;
    }
    if (sub_curve && (cfg.get_str(CFG_KG_SUBKEY_CURVE) != sub_curve)) {
        return false;
    }
    if (bits && (cfg.get_int(CFG_KG_PRIMARY_BITS) != bits)) {
        return false;
    }
    if (sub_bits && (cfg.get_int(CFG_KG_SUBKEY_BITS) != sub_bits)) {
        return false;
    }
    return true;
}

TEST_F(rnp_tests, rnpkeys_generatekey_testExpertMode)
{
    cli_rnp_t rnp;
    rnp_cfg   ops;

    ops.set_bool(CFG_EXPERT, true);
    ops.set_int(CFG_S2K_ITER, 1);

    /* ecdsa/ecdh p256 keypair */
    ops.unset(CFG_USERID);
    ops.add_str(CFG_USERID, "expert_ecdsa_p256");
    assert_true(ask_expert_details(&rnp, ops, "19\n1\n"));
    assert_false(check_cfg_props(ops, "ECDH", "ECDH", "NIST P-256", "NIST P-256", 0, 0));
    assert_false(check_cfg_props(ops, "ECDSA", "ECDSA", "NIST P-256", "NIST P-256", 0, 0));
    assert_false(check_cfg_props(ops, "ECDSA", "ECDH", "NIST P-384", "NIST P-256", 0, 0));
    assert_false(check_cfg_props(ops, "ECDSA", "ECDH", "NIST P-256", "NIST P-384", 0, 0));
    assert_false(check_cfg_props(ops, "ECDSA", "ECDH", "NIST P-256", "NIST P-256", 1024, 0));
    assert_false(check_cfg_props(ops, "ECDSA", "ECDH", "NIST P-256", "NIST P-256", 0, 1024));
    assert_true(check_cfg_props(ops, "ECDSA", "ECDH", "NIST P-256", "NIST P-256", 0, 0));
    assert_true(check_key_props(
      &rnp, "expert_ecdsa_p256", "ECDSA", "ECDH", "NIST P-256", "NIST P-256", 0, 0, "SHA256"));
    cli_rnp_end(&rnp);

    /* ecdsa/ecdh p384 keypair */
    ops.unset(CFG_USERID);
    ops.add_str(CFG_USERID, "expert_ecdsa_p384");
    assert_true(ask_expert_details(&rnp, ops, "19\n2\n"));
    assert_true(check_cfg_props(ops, "ECDSA", "ECDH", "NIST P-384", "NIST P-384", 0, 0));
    assert_false(check_key_props(
      &rnp, "expert_ecdsa_p256", "ECDSA", "ECDH", "NIST P-384", "NIST P-384", 0, 0, "SHA384"));
    assert_true(check_key_props(
      &rnp, "expert_ecdsa_p384", "ECDSA", "ECDH", "NIST P-384", "NIST P-384", 0, 0, "SHA384"));
    cli_rnp_end(&rnp);

    /* ecdsa/ecdh p521 keypair */
    ops.unset(CFG_USERID);
    ops.add_str(CFG_USERID, "expert_ecdsa_p521");
    assert_true(ask_expert_details(&rnp, ops, "19\n3\n"));
    assert_true(check_cfg_props(ops, "ECDSA", "ECDH", "NIST P-521", "NIST P-521", 0, 0));
    assert_true(check_key_props(
      &rnp, "expert_ecdsa_p521", "ECDSA", "ECDH", "NIST P-521", "NIST P-521", 0, 0, "SHA512"));
    cli_rnp_end(&rnp);

    /* ecdsa/ecdh brainpool256 keypair */
    ops.unset(CFG_USERID);
    ops.add_str(CFG_USERID, "expert_ecdsa_bp256");
    assert_true(ask_expert_details(&rnp, ops, "19\n4\n"));
    if (brainpool_enabled()) {
        assert_true(
          check_cfg_props(ops, "ECDSA", "ECDH", "brainpoolP256r1", "brainpoolP256r1", 0, 0));
        assert_true(check_key_props(&rnp,
                                    "expert_ecdsa_bp256",
                                    "ECDSA",
                                    "ECDH",
                                    "brainpoolP256r1",
                                    "brainpoolP256r1",
                                    0,
                                    0,
                                    "SHA256"));
    } else {
        /* secp256k1 will be selected instead */
        assert_true(check_cfg_props(ops, "ECDSA", "ECDH", "secp256k1", "secp256k1", 0, 0));
        assert_true(check_key_props(&rnp,
                                    "expert_ecdsa_bp256",
                                    "ECDSA",
                                    "ECDH",
                                    "secp256k1",
                                    "secp256k1",
                                    0,
                                    0,
                                    "SHA256"));
    }
    cli_rnp_end(&rnp);

    /* ecdsa/ecdh brainpool384 keypair */
    ops.unset(CFG_USERID);
    ops.add_str(CFG_USERID, "expert_ecdsa_bp384");
    if (brainpool_enabled()) {
        assert_true(ask_expert_details(&rnp, ops, "19\n5\n"));
        assert_true(
          check_cfg_props(ops, "ECDSA", "ECDH", "brainpoolP384r1", "brainpoolP384r1", 0, 0));
        assert_true(check_key_props(&rnp,
                                    "expert_ecdsa_bp384",
                                    "ECDSA",
                                    "ECDH",
                                    "brainpoolP384r1",
                                    "brainpoolP384r1",
                                    0,
                                    0,
                                    "SHA384"));
    } else {
        assert_false(ask_expert_details(&rnp, ops, "19\n5\n"));
    }
    cli_rnp_end(&rnp);

    /* ecdsa/ecdh brainpool512 keypair */
    ops.unset(CFG_USERID);
    ops.add_str(CFG_USERID, "expert_ecdsa_bp512");
    if (brainpool_enabled()) {
        assert_true(ask_expert_details(&rnp, ops, "19\n6\n"));
        assert_true(
          check_cfg_props(ops, "ECDSA", "ECDH", "brainpoolP512r1", "brainpoolP512r1", 0, 0));
        assert_true(check_key_props(&rnp,
                                    "expert_ecdsa_bp512",
                                    "ECDSA",
                                    "ECDH",
                                    "brainpoolP512r1",
                                    "brainpoolP512r1",
                                    0,
                                    0,
                                    "SHA512"));
    } else {
        assert_false(ask_expert_details(&rnp, ops, "19\n6\n"));
    }
    cli_rnp_end(&rnp);

    /* ecdsa/ecdh secp256k1 keypair */
    ops.unset(CFG_USERID);
    ops.add_str(CFG_USERID, "expert_ecdsa_p256k1");
    if (brainpool_enabled()) {
        assert_true(ask_expert_details(&rnp, ops, "19\n7\n"));
        assert_true(check_cfg_props(ops, "ECDSA", "ECDH", "secp256k1", "secp256k1", 0, 0));
        assert_true(check_key_props(&rnp,
                                    "expert_ecdsa_p256k1",
                                    "ECDSA",
                                    "ECDH",
                                    "secp256k1",
                                    "secp256k1",
                                    0,
                                    0,
                                    "SHA256"));
    } else {
        assert_false(ask_expert_details(&rnp, ops, "19\n7\n"));
    }
    cli_rnp_end(&rnp);

    /* eddsa/x25519 keypair */
    ops.clear();
    ops.set_bool(CFG_EXPERT, true);
    ops.set_int(CFG_S2K_ITER, 1);
    ops.unset(CFG_USERID);
    ops.add_str(CFG_USERID, "expert_eddsa_ecdh");
    assert_true(ask_expert_details(&rnp, ops, "22\n"));
    assert_true(check_cfg_props(ops, "EDDSA", "ECDH", NULL, "Curve25519", 0, 0));
    assert_true(check_key_props(
      &rnp, "expert_eddsa_ecdh", "EDDSA", "ECDH", "Ed25519", "Curve25519", 0, 0, "SHA256"));
    cli_rnp_end(&rnp);

    /* rsa/rsa 1024 key */
    ops.clear();
    ops.set_bool(CFG_EXPERT, true);
    ops.set_int(CFG_S2K_ITER, 1);
    ops.unset(CFG_USERID);
    ops.add_str(CFG_USERID, "expert_rsa_1024");
    assert_true(ask_expert_details(&rnp, ops, "1\n1024\n"));
    assert_true(check_cfg_props(ops, "RSA", "RSA", NULL, NULL, 1024, 1024));
    assert_true(check_key_props(
      &rnp, "expert_rsa_1024", "RSA", "RSA", NULL, NULL, 1024, 1024, "SHA256"));
    cli_rnp_end(&rnp);

    /* rsa 4096 key, asked twice */
    ops.unset(CFG_USERID);
    ops.add_str(CFG_USERID, "expert_rsa_4096");
    assert_true(ask_expert_details(&rnp, ops, "1\n1023\n4096\n"));
    assert_true(check_cfg_props(ops, "RSA", "RSA", NULL, NULL, 4096, 4096));
    assert_true(check_key_props(
      &rnp, "expert_rsa_4096", "RSA", "RSA", NULL, NULL, 4096, 4096, "SHA256"));
    cli_rnp_end(&rnp);

    /* sm2 key */
    ops.clear();
    ops.set_bool(CFG_EXPERT, true);
    ops.set_int(CFG_S2K_ITER, 1);
    ops.unset(CFG_USERID);
    ops.add_str(CFG_USERID, "expert_sm2");
    if (!sm2_enabled()) {
        assert_false(ask_expert_details(&rnp, ops, "99\n"));
    } else {
        assert_true(ask_expert_details(&rnp, ops, "99\n"));
        assert_true(check_cfg_props(ops, "SM2", "SM2", NULL, NULL, 0, 0));
        assert_true(check_key_props(
          &rnp, "expert_sm2", "SM2", "SM2", "SM2 P-256", "SM2 P-256", 0, 0, "SM3"));
    }
    cli_rnp_end(&rnp);
}

TEST_F(rnp_tests, generatekeyECDSA_explicitlySetSmallOutputDigest_DigestAlgAdjusted)
{
    cli_rnp_t rnp;
    rnp_cfg   ops;

    ops.set_bool(CFG_EXPERT, true);
    ops.set_str(CFG_HASH, "SHA1");
    ops.set_int(CFG_S2K_ITER, 1);
    ops.add_str(CFG_USERID, "expert_small_digest");
    assert_true(ask_expert_details(&rnp, ops, "19\n2\n"));
    assert_true(check_cfg_props(ops, "ECDSA", "ECDH", "NIST P-384", "NIST P-384", 0, 0));
    assert_true(check_key_props(&rnp,
                                "expert_small_digest",
                                "ECDSA",
                                "ECDH",
                                "NIST P-384",
                                "NIST P-384",
                                0,
                                0,
                                "SHA384"));
    cli_rnp_end(&rnp);
}

TEST_F(rnp_tests, generatekey_multipleUserIds_ShouldFail)
{
    cli_rnp_t rnp;
    rnp_cfg   ops;

    ops.set_bool(CFG_EXPERT, true);
    ops.set_int(CFG_S2K_ITER, 1);
    ops.add_str(CFG_USERID, "multi_userid_1");
    ops.add_str(CFG_USERID, "multi_userid_2");
    assert_false(ask_expert_details(&rnp, ops, "1\n1024\n"));
    cli_rnp_end(&rnp);
}

TEST_F(rnp_tests, generatekeyECDSA_explicitlySetBiggerThanNeededDigest_ShouldSuceed)
{
    cli_rnp_t rnp;
    rnp_cfg   ops;

    ops.set_bool(CFG_EXPERT, true);
    ops.set_str(CFG_HASH, "SHA512");
    ops.set_int(CFG_S2K_ITER, 1);
    ops.add_str(CFG_USERID, "expert_large_digest");
    assert_true(ask_expert_details(&rnp, ops, "19\n2\n"));
    assert_true(check_cfg_props(ops, "ECDSA", "ECDH", "NIST P-384", "NIST P-384", 0, 0));
    assert_true(check_key_props(&rnp,
                                "expert_large_digest",
                                "ECDSA",
                                "ECDH",
                                "NIST P-384",
                                "NIST P-384",
                                0,
                                0,
                                "SHA512"));
    cli_rnp_end(&rnp);
}

TEST_F(rnp_tests, generatekeyECDSA_explicitlySetUnknownDigest_ShouldFail)
{
    cli_rnp_t rnp;
    rnp_cfg   ops;

    ops.set_bool(CFG_EXPERT, true);
    ops.set_str(CFG_HASH, "WRONG_DIGEST_ALGORITHM");
    ops.set_int(CFG_S2K_ITER, 1);

    // Finds out that hash doesn't exist and returns an error
    assert_false(ask_expert_details(&rnp, ops, "19\n2\n"));
    cli_rnp_end(&rnp);
}

/* This tests some of the mid-level key generation functions and their
 * generated sigs in the keyring.
 */
TEST_F(rnp_tests, test_generated_key_sigs)
{
    rnp_key_store_t *pubring = new rnp_key_store_t();
    rnp_key_store_t *secring = new rnp_key_store_t();
    pgp_key_t *      primary_pub = NULL, *primary_sec = NULL;
    pgp_key_t *      sub_pub = NULL, *sub_sec = NULL;

    // primary
    {
        pgp_key_t                 pub;
        pgp_key_t                 sec;
        rnp_keygen_primary_desc_t desc;
        pgp_sig_subpkt_t *        subpkt = NULL;
        pgp_signature_t *         psig = NULL;
        pgp_signature_t *         ssig = NULL;
        pgp_signature_info_t      psiginfo = {};
        pgp_signature_info_t      ssiginfo = {};

        desc.crypto.key_alg = PGP_PKA_RSA;
        desc.crypto.rsa.modulus_bit_len = 1024;
        desc.crypto.rng = &global_rng;
        memcpy(desc.cert.userid, "test", 5);

        // generate
        assert_true(pgp_generate_primary_key(&desc, true, &sec, &pub, PGP_KEY_STORE_GPG));

        // add to our rings
        assert_true(rnp_key_store_add_key(pubring, &pub));
        assert_true(rnp_key_store_add_key(secring, &sec));
        // retrieve back from our rings (for later)
        primary_pub = rnp_key_store_get_key_by_grip(pubring, pub.grip());
        primary_sec = rnp_key_store_get_key_by_grip(secring, pub.grip());
        assert_non_null(primary_pub);
        assert_non_null(primary_sec);
        assert_true(primary_pub->valid());
        assert_true(primary_pub->validated());
        assert_false(primary_pub->expired());
        assert_true(primary_sec->valid());
        assert_true(primary_sec->validated());
        assert_false(primary_sec->expired());

        // check packet and subsig counts
        assert_int_equal(3, pub.rawpkt_count());
        assert_int_equal(3, sec.rawpkt_count());
        assert_int_equal(1, pub.sig_count());
        assert_int_equal(1, sec.sig_count());
        psig = &pub.get_sig(0).sig;
        ssig = &sec.get_sig(0).sig;
        // make sure our sig MPI is not NULL
        assert_int_not_equal(psig->material_len, 0);
        assert_int_not_equal(ssig->material_len, 0);
        // make sure we're targeting the right packet
        assert_int_equal(PGP_PKT_SIGNATURE, pub.get_sig(0).rawpkt.tag);
        assert_int_equal(PGP_PKT_SIGNATURE, sec.get_sig(0).rawpkt.tag);

        // validate the userid self-sig

        psiginfo.sig = psig;
        psiginfo.signer = &pub;
        assert_rnp_success(
          signature_check_certification(&psiginfo, &pub.pkt(), &pub.get_uid(0).pkt));
        assert_true(psig->keyfp() == pub.fp());
        // check subpackets and their contents
        subpkt = psig->get_subpkt(PGP_SIG_SUBPKT_ISSUER_FPR);
        assert_non_null(subpkt);
        assert_true(subpkt->hashed);
        subpkt = psig->get_subpkt(PGP_SIG_SUBPKT_ISSUER_KEY_ID, false);
        assert_non_null(subpkt);
        assert_false(subpkt->hashed);
        assert_int_equal(0,
                         memcmp(subpkt->fields.issuer, pub.keyid().data(), PGP_KEY_ID_SIZE));
        subpkt = psig->get_subpkt(PGP_SIG_SUBPKT_CREATION_TIME);
        assert_non_null(subpkt);
        assert_true(subpkt->hashed);
        assert_true(subpkt->fields.create <= time(NULL));

        ssiginfo.sig = ssig;
        ssiginfo.signer = &sec;
        assert_rnp_success(
          signature_check_certification(&ssiginfo, &sec.pkt(), &sec.get_uid(0).pkt));
        assert_true(ssig->keyfp() == sec.fp());

        // modify a hashed portion of the sig packets
        psig->hashed_data[32] ^= 0xff;
        ssig->hashed_data[32] ^= 0xff;
        // ensure validation fails
        assert_rnp_failure(
          signature_check_certification(&psiginfo, &pub.pkt(), &pub.get_uid(0).pkt));
        assert_rnp_failure(
          signature_check_certification(&ssiginfo, &sec.pkt(), &sec.get_uid(0).pkt));
        // restore the original data
        psig->hashed_data[32] ^= 0xff;
        ssig->hashed_data[32] ^= 0xff;
        // ensure validation fails with incorrect uid
        pgp_userid_pkt_t uid;
        uid.tag = PGP_PKT_USER_ID;
        uid.uid = (uint8_t *) malloc(4);
        uid.uid_len = 4;
        memcpy(uid.uid, "fake", 4);

        assert_rnp_failure(signature_check_certification(&psiginfo, &pub.pkt(), &uid));
        assert_rnp_failure(signature_check_certification(&ssiginfo, &sec.pkt(), &uid));

        // validate via an alternative method
        // primary_pub + pubring
        primary_pub->validate(*pubring);
        assert_true(primary_pub->valid());
        assert_true(primary_pub->validated());
        assert_false(primary_pub->expired());
        // primary_sec + pubring
        primary_sec->validate(*pubring);
        assert_true(primary_sec->valid());
        assert_true(primary_sec->validated());
        assert_false(primary_sec->expired());
        // primary_pub + secring
        primary_pub->validate(*secring);
        assert_true(primary_pub->valid());
        assert_true(primary_pub->validated());
        assert_false(primary_pub->expired());
        // primary_sec + secring
        primary_sec->validate(*secring);
        assert_true(primary_sec->valid());
        assert_true(primary_sec->validated());
        assert_false(primary_sec->expired());
        // modify a hashed portion of the sig packet, offset may change in future
        pgp_subsig_t &sig = primary_pub->get_sig(0);
        sig.sig.hashed_data[10] ^= 0xff;
        sig.validity.validated = false;
        // ensure validation fails
        primary_pub->validate(*pubring);
        assert_false(primary_pub->valid());
        assert_true(primary_pub->validated());
        assert_false(primary_pub->expired());
        // restore the original data
        sig.sig.hashed_data[10] ^= 0xff;
        sig.validity.validated = false;
        primary_pub->validate(*pubring);
        assert_true(primary_pub->valid());
        assert_true(primary_pub->validated());
        assert_false(primary_pub->expired());
    }

    // sub
    {
        pgp_key_t                pub;
        pgp_key_t                sec;
        rnp_keygen_subkey_desc_t desc;
        pgp_sig_subpkt_t *       subpkt = NULL;
        pgp_signature_t *        psig = NULL;
        pgp_signature_t *        ssig = NULL;
        pgp_signature_info_t     psiginfo = {};
        pgp_signature_info_t     ssiginfo = {};

        memset(&desc, 0, sizeof(desc));
        desc.crypto.key_alg = PGP_PKA_RSA;
        desc.crypto.rsa.modulus_bit_len = 1024;
        desc.crypto.rng = &global_rng;

        // generate
        assert_true(pgp_generate_subkey(
          &desc, true, primary_sec, primary_pub, &sec, &pub, NULL, PGP_KEY_STORE_GPG));
        assert_true(pub.valid());
        assert_true(pub.validated());
        assert_false(pub.expired());
        assert_true(sec.valid());
        assert_true(sec.validated());
        assert_false(sec.expired());

        // check packet and subsig counts
        assert_int_equal(2, pub.rawpkt_count());
        assert_int_equal(2, sec.rawpkt_count());
        assert_int_equal(1, pub.sig_count());
        assert_int_equal(1, sec.sig_count());
        psig = &pub.get_sig(0).sig;
        ssig = &sec.get_sig(0).sig;
        // make sure our sig MPI is not NULL
        assert_int_not_equal(psig->material_len, 0);
        assert_int_not_equal(ssig->material_len, 0);
        // make sure we're targeting the right packet
        assert_int_equal(PGP_PKT_SIGNATURE, pub.get_sig(0).rawpkt.tag);
        assert_int_equal(PGP_PKT_SIGNATURE, sec.get_sig(0).rawpkt.tag);
        // validate the binding sig
        psiginfo.sig = psig;
        psiginfo.signer = primary_pub;
        assert_rnp_success(signature_check_binding(&psiginfo, &primary_pub->pkt(), &pub));
        assert_true(psig->keyfp() == primary_pub->fp());
        // check subpackets and their contents
        subpkt = psig->get_subpkt(PGP_SIG_SUBPKT_ISSUER_FPR);
        assert_non_null(subpkt);
        assert_true(subpkt->hashed);
        subpkt = psig->get_subpkt(PGP_SIG_SUBPKT_ISSUER_KEY_ID, false);
        assert_non_null(subpkt);
        assert_false(subpkt->hashed);
        assert_int_equal(
          0, memcmp(subpkt->fields.issuer, primary_pub->keyid().data(), PGP_KEY_ID_SIZE));
        subpkt = psig->get_subpkt(PGP_SIG_SUBPKT_CREATION_TIME);
        assert_non_null(subpkt);
        assert_true(subpkt->hashed);
        assert_true(subpkt->fields.create <= time(NULL));

        ssiginfo.sig = ssig;
        ssiginfo.signer = primary_pub;
        assert_rnp_success(signature_check_binding(&ssiginfo, &primary_pub->pkt(), &sec));
        assert_true(ssig->keyfp() == primary_sec->fp());

        // modify a hashed portion of the sig packets
        psig->hashed_data[10] ^= 0xff;
        ssig->hashed_data[10] ^= 0xff;
        // ensure validation fails
        assert_rnp_failure(signature_check_binding(&psiginfo, &primary_pub->pkt(), &pub));
        assert_rnp_failure(signature_check_binding(&ssiginfo, &primary_pub->pkt(), &sec));
        // restore the original data
        psig->hashed_data[10] ^= 0xff;
        ssig->hashed_data[10] ^= 0xff;

        // add to our rings
        assert_true(rnp_key_store_add_key(pubring, &pub));
        assert_true(rnp_key_store_add_key(secring, &sec));
        // retrieve back from our rings
        sub_pub = rnp_key_store_get_key_by_grip(pubring, pub.grip());
        sub_sec = rnp_key_store_get_key_by_grip(secring, pub.grip());
        assert_non_null(sub_pub);
        assert_non_null(sub_sec);
        assert_true(sub_pub->valid());
        assert_true(sub_pub->validated());
        assert_false(sub_pub->expired());
        assert_true(sub_sec->valid());
        assert_true(sub_sec->validated());
        assert_false(sub_sec->expired());

        // validate via an alternative method
        sub_pub->validate(*pubring);
        assert_true(sub_pub->valid());
        assert_true(sub_pub->validated());
        assert_false(sub_pub->expired());
        sub_sec->validate(*pubring);
        assert_true(sub_sec->valid());
        assert_true(sub_sec->validated());
        assert_false(sub_sec->expired());
    }

    delete pubring;
    delete secring;
}
