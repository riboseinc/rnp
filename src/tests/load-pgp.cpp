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
#include "../librepgp/stream-packet.h"
#include "../librepgp/stream-sig.h"
#include "pgp-key.h"

#include "rnp_tests.h"
#include "support.h"

/* This test loads a .gpg pubring with a single V3 key,
 * and confirms that appropriate key flags are set.
 */
void
test_load_v3_keyring_pgp(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    char              path[PATH_MAX];
    pgp_io_t          io = pgp_io_from_fp(stderr, stdout, stdout);
    pgp_memory_t      mem = {0};

    paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/2/pubring.gpg", NULL);
    // read the pubring into memory
    assert_true(pgp_mem_readfile(&mem, path));

    rnp_key_store_t *key_store = (rnp_key_store_t *) calloc(1, sizeof(*key_store));
    assert_non_null(key_store);

    // load it in to the key store
    assert_true(rnp_key_store_pgp_read_from_mem(&io, key_store, &mem, NULL));
    assert_int_equal(1, list_length(key_store->keys));

    // find the key by keyid
    static const uint8_t keyid[] = {0xDC, 0x70, 0xC1, 0x24, 0xA5, 0x02, 0x83, 0xF1};
    const pgp_key_t *    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL);
    assert_non_null(key);

    // confirm the key flags are correct
    assert_int_equal(key->key_flags,
                     PGP_KF_ENCRYPT | PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH);

    // cleanup
    rnp_key_store_free(key_store);
    pgp_memory_release(&mem);

    // load secret keyring and decrypt the key
    paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/4/secring.pgp", NULL);
    assert_true(pgp_mem_readfile(&mem, path));

    key_store = (rnp_key_store_t *) calloc(1, sizeof(*key_store));
    assert_non_null(key_store);

    assert_true(rnp_key_store_pgp_read_from_mem(&io, key_store, &mem, NULL));
    assert_int_equal(1, list_length(key_store->keys));

    static const uint8_t keyid2[] = {0x7D, 0x0B, 0xC1, 0x0E, 0x93, 0x34, 0x04, 0xC9};
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid2, NULL);
    assert_non_null(key);

    // confirm the key flags are correct
    assert_int_equal(key->key_flags,
                     PGP_KF_ENCRYPT | PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH);

    // check if the key is secret and is locked
    assert_true(pgp_is_key_secret(key));
    assert_true(pgp_key_is_locked(key));

    // decrypt the key
    pgp_key_pkt_t *seckey = pgp_decrypt_seckey_pgp(
      key->packets[0].raw, key->packets[0].length, pgp_get_key_pkt(key), "password");
    assert_non_null(seckey);

    // cleanup
    free_key_pkt(seckey);
    free(seckey);
    rnp_key_store_free(key_store);
    pgp_memory_release(&mem);
}

/* This test loads a .gpg pubring with multiple V4 keys,
 * finds a particular key of interest, and confirms that
 * the appropriate key flags are set.
 */
void
test_load_v4_keyring_pgp(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    char              path[PATH_MAX];
    pgp_io_t          io = pgp_io_from_fp(stderr, stdout, stdout);
    pgp_memory_t      mem = {0};

    paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/1/pubring.gpg", NULL);
    // read the pubring into memory
    assert_true(pgp_mem_readfile(&mem, path));

    rnp_key_store_t *key_store = (rnp_key_store_t *) calloc(1, sizeof(*key_store));
    assert_non_null(key_store);

    // load it in to the key store
    assert_true(rnp_key_store_pgp_read_from_mem(&io, key_store, &mem, NULL));
    assert_int_equal(7, list_length(key_store->keys));

    // find the key by keyid
    static const uint8_t keyid[] = {0x8a, 0x05, 0xb8, 0x9f, 0xad, 0x5a, 0xde, 0xd1};
    const pgp_key_t *    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL);
    assert_non_null(key);

    // confirm the key flags are correct
    assert_int_equal(key->key_flags, PGP_KF_ENCRYPT);

    // cleanup
    rnp_key_store_free(key_store);
    pgp_memory_release(&mem);
}

/* Just a helper for the below test */
static void
check_pgp_keyring_counts(const char *   path,
                         unsigned       primary_count,
                         const unsigned subkey_counts[])
{
    pgp_io_t     io = pgp_io_from_fp(stderr, stdout, stdout);
    pgp_memory_t mem = {0};

    // read the keyring into memory
    assert_true(pgp_mem_readfile(&mem, path));

    rnp_key_store_t *key_store = (rnp_key_store_t *) calloc(1, sizeof(*key_store));
    assert_non_null(key_store);

    // load it in to the key store
    assert_true(rnp_key_store_pgp_read_from_mem(&io, key_store, &mem, NULL));

    // count primary keys first
    unsigned total_primary_count = 0;
    for (list_item *key_item = list_front(key_store->keys); key_item;
         key_item = list_next(key_item)) {
        pgp_key_t *key = (pgp_key_t *) key_item;
        if (pgp_key_is_primary_key(key)) {
            total_primary_count++;
        }
    }
    assert_int_equal(primary_count, total_primary_count);

    // now count subkeys in each primary key
    unsigned total_subkey_count = 0;
    unsigned primary = 0;
    for (list_item *key_item = list_front(key_store->keys); key_item;
         key_item = list_next(key_item)) {
        pgp_key_t *key = (pgp_key_t *) key_item;
        if (pgp_key_is_primary_key(key)) {
            // check the subkey count for this primary key
            assert_int_equal(list_length(key->subkey_grips), subkey_counts[primary++]);
        } else if (pgp_key_is_subkey(key)) {
            total_subkey_count++;
        }
    }

    // check the total (not really needed)
    assert_int_equal(list_length(key_store->keys), total_primary_count + total_subkey_count);

    // cleanup
    rnp_key_store_free(key_store);
    pgp_memory_release(&mem);
}

/* This test loads a pubring.gpg and secring.gpg and confirms
 * that it contains the expected number of primary keys
 * and the expected number of subkeys for each primary key.
 */
void
test_load_keyring_and_count_pgp(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    char              path[PATH_MAX];

    unsigned int primary_count = 2;
    unsigned int subkey_counts[2] = {3, 2};

    // check pubring
    paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/1/pubring.gpg", NULL);
    check_pgp_keyring_counts(path, primary_count, subkey_counts);

    // check secring
    paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/1/secring.gpg", NULL);
    check_pgp_keyring_counts(path, primary_count, subkey_counts);
}

/* This test loads a V4 keyring and confirms that certain
 * bitfields and time fields are set correctly.
 */
void
test_load_check_bitfields_and_times(void **state)
{
    pgp_io_t         io = pgp_io_from_fp(stderr, stdout, stdout);
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    uint8_t          signer_id[PGP_KEY_ID_SIZE] = {0};
    const pgp_key_t *key;

    // load keyring
    rnp_key_store_t *key_store = rnp_key_store_new("GPG", "data/keyrings/1/pubring.gpg");
    assert_non_null(key_store);
    assert_true(rnp_key_store_load_from_file(&io, key_store, NULL));

    // find
    key = NULL;
    assert_true(rnp_hex_decode("7BC6709B15C23A4A", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(key->subsigc, 3);
    // check subsig properties
    for (unsigned i = 0; i < key->subsigc; i++) {
        const pgp_subsig_t *ss = &key->subsigs[i];
        static const time_t expected_creation_times[] = {1500569820, 1500569836, 1500569846};
        // check SS_ISSUER_KEY_ID
        assert_true(signature_get_keyid(&ss->sig, signer_id));
        assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
        // check SS_CREATION_TIME
        assert_int_equal(signature_get_creation(&ss->sig), expected_creation_times[i]);
        // check SS_EXPIRATION_TIME
        assert_int_equal(signature_get_expiration(&ss->sig), 0);
    }
    // check SS_KEY_EXPIRY
    assert_int_equal(key->expiration, 0);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("1ED63EE56FADC34D", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(key->subsigc, 1);
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("7BC6709B15C23A4A", keyid, sizeof(keyid)));
    assert_true(signature_get_keyid(&key->subsigs[0].sig, signer_id));
    assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(signature_get_creation(&key->subsigs[0].sig), 1500569820);
    assert_int_equal(signature_get_creation(&key->subsigs[0].sig),
                     pgp_get_key_pkt(key)->creation_time);
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(signature_get_expiration(&key->subsigs[0].sig), 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(key->expiration, 0);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("1D7E8A5393C997A8", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(key->subsigc, 1);
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("7BC6709B15C23A4A", keyid, sizeof(keyid)));
    assert_true(signature_get_keyid(&key->subsigs[0].sig, signer_id));
    assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(signature_get_creation(&key->subsigs[0].sig), 1500569851);
    assert_int_equal(signature_get_creation(&key->subsigs[0].sig),
                     pgp_get_key_pkt(key)->creation_time);
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(signature_get_expiration(&key->subsigs[0].sig), 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(key->expiration, 123 * 24 * 60 * 60 /* 123 days */);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("8A05B89FAD5ADED1", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(key->subsigc, 1);
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("7BC6709B15C23A4A", keyid, sizeof(keyid)));
    assert_true(signature_get_keyid(&key->subsigs[0].sig, signer_id));
    assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(signature_get_creation(&key->subsigs[0].sig), 1500569896);
    assert_int_equal(signature_get_creation(&key->subsigs[0].sig),
                     pgp_get_key_pkt(key)->creation_time);
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(signature_get_expiration(&key->subsigs[0].sig), 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(key->expiration, 0);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("2FCADF05FFA501BB", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(key->subsigc, 3);
    // check subsig properties
    for (unsigned i = 0; i < key->subsigc; i++) {
        const pgp_subsig_t *ss = &key->subsigs[i];
        static const time_t expected_creation_times[] = {1501372449, 1500570153, 1500570147};

        // check SS_ISSUER_KEY_ID
        assert_true(signature_get_keyid(&ss->sig, signer_id));
        assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
        // check SS_CREATION_TIME
        assert_int_equal(signature_get_creation(&ss->sig), expected_creation_times[i]);
        // check SS_EXPIRATION_TIME
        assert_int_equal(signature_get_expiration(&ss->sig), 0);
    }
    // check SS_KEY_EXPIRY
    assert_int_equal(key->expiration, 2076663808);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("54505A936A4A970E", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(key->subsigc, 1);
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("2FCADF05FFA501BB", keyid, sizeof(keyid)));
    assert_true(signature_get_keyid(&key->subsigs[0].sig, signer_id));
    assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(signature_get_creation(&key->subsigs[0].sig), 1500569946);
    assert_int_equal(signature_get_creation(&key->subsigs[0].sig),
                     pgp_get_key_pkt(key)->creation_time);
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(signature_get_expiration(&key->subsigs[0].sig), 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(key->expiration, 2076663808);

    // find
    key = NULL;
    assert_true(rnp_hex_decode("326EF111425D14A5", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL);
    assert_non_null(key);
    // check subsig count
    assert_int_equal(key->subsigc, 1);
    // check SS_ISSUER_KEY_ID
    assert_true(rnp_hex_decode("2FCADF05FFA501BB", keyid, sizeof(keyid)));
    assert_true(signature_get_keyid(&key->subsigs[0].sig, signer_id));
    assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
    // check SS_CREATION_TIME [0]
    assert_int_equal(signature_get_creation(&key->subsigs[0].sig), 1500570165);
    assert_int_equal(signature_get_creation(&key->subsigs[0].sig),
                     pgp_get_key_pkt(key)->creation_time);
    // check SS_EXPIRATION_TIME [0]
    assert_int_equal(signature_get_expiration(&key->subsigs[0].sig), 0);
    // check SS_KEY_EXPIRY
    assert_int_equal(key->expiration, 0);

    // cleanup
    rnp_key_store_free(key_store);
}

/* This test loads a V3 keyring and confirms that certain
 * bitfields and time fields are set correctly.
 */
void
test_load_check_bitfields_and_times_v3(void **state)
{
    pgp_io_t         io = pgp_io_from_fp(stderr, stdout, stdout);
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    uint8_t          signer_id[PGP_KEY_ID_SIZE];
    const pgp_key_t *key;

    // load keyring
    rnp_key_store_t *key_store = rnp_key_store_new("GPG", "data/keyrings/2/pubring.gpg");
    assert_non_null(key_store);
    assert_true(rnp_key_store_load_from_file(&io, key_store, NULL));

    // find
    key = NULL;
    assert_true(rnp_hex_decode("DC70C124A50283F1", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL);
    assert_non_null(key);
    // check key version
    assert_int_equal(pgp_get_key_pkt(key)->version, PGP_V3);
    // check subsig count
    assert_int_equal(key->subsigc, 1);
    // check signature version
    assert_int_equal(key->subsigs[0].sig.version, 3);
    // check issuer
    assert_true(rnp_hex_decode("DC70C124A50283F1", keyid, sizeof(keyid)));
    assert_true(signature_get_keyid(&key->subsigs[0].sig, signer_id));
    assert_int_equal(memcmp(keyid, signer_id, PGP_KEY_ID_SIZE), 0);
    // check creation time
    assert_int_equal(signature_get_creation(&key->subsigs[0].sig), 1005209227);
    assert_int_equal(signature_get_creation(&key->subsigs[0].sig),
                     pgp_get_key_pkt(key)->creation_time);
    // check signature expiration time (V3 sigs have none)
    assert_int_equal(signature_get_expiration(&key->subsigs[0].sig), 0);
    // check key expiration
    assert_int_equal(key->expiration, 0); // only for V4 keys
    assert_int_equal(pgp_get_key_pkt(key)->v3_days, 0);

    // cleanup
    rnp_key_store_free(key_store);
}

#define MERGE_PATH "data/test_stream_key_merge/"

void
test_load_armored_pub_sec(void **state)
{
    pgp_io_t   io = {.outs = stdout, .errs = stderr, .res = stdout};
    pgp_key_t *key;
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    rnp_key_store_t *key_store;

    key_store = rnp_key_store_new("GPG", MERGE_PATH "key-both.asc");
    assert_non_null(key_store);
    assert_true(rnp_key_store_load_from_file(&io, key_store, NULL));

    /* we must have 1 main key and 2 subkeys */
    assert_int_equal(list_length(key_store->keys), 3);

    assert_true(rnp_hex_decode("9747D2A6B3A63124", keyid, sizeof(keyid)));
    assert_non_null(key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL));
    assert_true(key->valid);
    assert_true(pgp_key_is_primary_key(key));
    assert_true(pgp_is_key_secret(key));
    assert_int_equal(key->packetc, 5);
    assert_int_equal(key->packets[0].tag, PGP_PTAG_CT_SECRET_KEY);
    assert_int_equal(key->packets[1].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[2].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(key->packets[3].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[4].tag, PGP_PTAG_CT_SIGNATURE);

    assert_true(rnp_hex_decode("AF1114A47F5F5B28", keyid, sizeof(keyid)));
    assert_non_null(key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL));
    assert_true(key->valid);
    assert_true(pgp_key_is_subkey(key));
    assert_true(pgp_is_key_secret(key));
    assert_int_equal(key->packetc, 2);
    assert_int_equal(key->packets[0].tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_int_equal(key->packets[1].tag, PGP_PTAG_CT_SIGNATURE);

    assert_true(rnp_hex_decode("16CD16F267CCDD4F", keyid, sizeof(keyid)));
    assert_non_null(key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL));
    assert_true(key->valid);
    assert_true(pgp_key_is_subkey(key));
    assert_true(pgp_is_key_secret(key));
    assert_int_equal(key->packetc, 2);
    assert_int_equal(key->packets[0].tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_int_equal(key->packets[1].tag, PGP_PTAG_CT_SIGNATURE);

    /* both user ids should be present */
    assert_non_null(rnp_key_store_get_key_by_name(&io, key_store, "key-merge-uid-1", NULL));
    assert_non_null(rnp_key_store_get_key_by_name(&io, key_store, "key-merge-uid-2", NULL));

    rnp_key_store_free(key_store);
}

static bool
load_transferable_key(pgp_transferable_key_t *key, const char *fname)
{
    pgp_source_t src = {};
    bool res = !init_file_src(&src, fname) && !process_pgp_key(&src, key);
    src_close(&src);
    return res;
}

static bool
load_transferable_subkey(pgp_transferable_subkey_t *key, const char *fname)
{
    pgp_source_t src = {};
    bool res = !init_file_src(&src, fname) && !process_pgp_subkey(&src, key);
    src_close(&src);
    return res;
}

void
test_load_merge(void **state)
{
    pgp_io_t   io = {.outs = stdout, .errs = stderr, .res = stdout};
    pgp_key_t *key, *skey1, *skey2;
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    uint8_t          sub1id[PGP_KEY_ID_SIZE];
    uint8_t          sub2id[PGP_KEY_ID_SIZE];
    rnp_key_store_t *key_store;
    pgp_transferable_key_t tkey = {};
    pgp_transferable_subkey_t tskey = {};
    pgp_password_provider_t provider = (pgp_password_provider_t){.callback = string_copy_password_callback,
                                         .userdata = (void *) "password"};

    key_store = rnp_key_store_new("GPG", "");
    assert_non_null(key_store);
    assert_true(rnp_hex_decode("9747D2A6B3A63124", keyid, sizeof(keyid)));
    assert_true(rnp_hex_decode("AF1114A47F5F5B28", sub1id, sizeof(sub1id)));
    assert_true(rnp_hex_decode("16CD16F267CCDD4F", sub2id, sizeof(sub2id)));

    /* load just key packet */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-pub-just-key.pgp"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(list_length(key_store->keys), 1);
    assert_non_null(key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL));
    assert_false(key->valid);
    assert_int_equal(key->packetc, 1);
    assert_int_equal(key->packets[0].tag, PGP_PTAG_CT_PUBLIC_KEY);

    /* load key + user id 1 without sigs */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-pub-uid-1-no-sigs.pgp"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(list_length(key_store->keys), 1);
    assert_non_null(key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL));
    assert_false(key->valid);
    assert_int_equal(key->uidc, 1);
    assert_int_equal(key->packetc, 2);
    assert_int_equal(key->packets[0].tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_int_equal(key->packets[1].tag, PGP_PTAG_CT_USER_ID);
    assert_true(key == rnp_key_store_get_key_by_name(&io, key_store, "key-merge-uid-1", NULL));

    /* load key + user id 1 with sigs */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-pub-uid-1.pgp"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(list_length(key_store->keys), 1);
    assert_non_null(key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL));
    assert_true(key->valid);
    assert_int_equal(key->uidc, 1);
    assert_int_equal(key->packetc, 3);
    assert_int_equal(key->packets[0].tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_int_equal(key->packets[1].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[2].tag, PGP_PTAG_CT_SIGNATURE);
    assert_true(key == rnp_key_store_get_key_by_name(&io, key_store, "key-merge-uid-1", NULL));

    /* load key + user id 2 with sigs */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-pub-uid-2.pgp"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    /* try to add it twice */
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(list_length(key_store->keys), 1);
    assert_non_null(key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL));
    assert_true(key->valid);
    assert_int_equal(key->uidc, 2);
    assert_int_equal(key->packetc, 5);
    assert_int_equal(key->packets[0].tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_int_equal(key->packets[1].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[2].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(key->packets[3].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[4].tag, PGP_PTAG_CT_SIGNATURE);
    assert_true(key == rnp_key_store_get_key_by_name(&io, key_store, "key-merge-uid-1", NULL));
    assert_true(key == rnp_key_store_get_key_by_name(&io, key_store, "key-merge-uid-2", NULL));

    /* load key + subkey 1 without sigs */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-pub-subkey-1-no-sigs.pgp"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(list_length(key_store->keys), 2);
    assert_non_null(key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL));
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(&io, key_store, sub1id, NULL));
    assert_true(key->valid);
    assert_false(skey1->valid);
    assert_int_equal(key->uidc, 2);
    assert_int_equal(list_length(key->subkey_grips), 1);
    assert_int_equal(memcmp(list_front(key->subkey_grips), skey1->grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(key->packetc, 5);
    assert_int_equal(key->packets[0].tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_int_equal(key->packets[1].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[2].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(key->packets[3].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[4].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(skey1->uidc, 0);
    assert_int_equal(memcmp(key->grip, skey1->primary_grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(skey1->packetc, 1);
    assert_int_equal(skey1->packets[0].tag, PGP_PTAG_CT_PUBLIC_SUBKEY);

    /* load just subkey 1 but with signature */
    assert_true(load_transferable_subkey(&tskey, MERGE_PATH "key-pub-no-key-subkey-1.pgp"));
    assert_true(rnp_key_store_add_transferable_subkey(key_store, &tskey, key));
    /* try to add it twice */
    assert_true(rnp_key_store_add_transferable_subkey(key_store, &tskey, key));
    transferable_subkey_destroy(&tskey);
    assert_int_equal(list_length(key_store->keys), 2);
    assert_non_null(key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL));
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(&io, key_store, sub1id, NULL));
    assert_true(key->valid);
    assert_true(skey1->valid);
    assert_int_equal(key->uidc, 2);
    assert_int_equal(list_length(key->subkey_grips), 1);
    assert_int_equal(memcmp(list_front(key->subkey_grips), skey1->grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(key->packetc, 5);
    assert_int_equal(key->packets[0].tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_int_equal(key->packets[1].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[2].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(key->packets[3].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[4].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(skey1->uidc, 0);
    assert_int_equal(memcmp(key->grip, skey1->primary_grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(skey1->packetc, 2);
    assert_int_equal(skey1->packets[0].tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    assert_int_equal(skey1->packets[1].tag, PGP_PTAG_CT_SIGNATURE);

    /* load key + subkey 2 with signature */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-pub-subkey-2.pgp"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    /* try to add it twice */
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(list_length(key_store->keys), 3);
    assert_non_null(key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL));
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(&io, key_store, sub1id, NULL));
    assert_non_null(skey2 = rnp_key_store_get_key_by_id(&io, key_store, sub2id, NULL));
    assert_true(key->valid);
    assert_true(skey1->valid);
    assert_true(skey2->valid);
    assert_int_equal(key->uidc, 2);
    assert_int_equal(list_length(key->subkey_grips), 2);
    assert_int_equal(memcmp(list_front(key->subkey_grips), skey1->grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(memcmp(list_next(list_front(key->subkey_grips)), skey2->grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(key->packetc, 5);
    assert_int_equal(key->packets[0].tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_int_equal(key->packets[1].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[2].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(key->packets[3].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[4].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(skey1->uidc, 0);
    assert_int_equal(memcmp(key->grip, skey1->primary_grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(skey1->packetc, 2);
    assert_int_equal(skey1->packets[0].tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    assert_int_equal(skey1->packets[1].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(skey2->uidc, 0);
    assert_int_equal(memcmp(key->grip, skey2->primary_grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(skey2->packetc, 2);
    assert_int_equal(skey2->packets[0].tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    assert_int_equal(skey2->packets[1].tag, PGP_PTAG_CT_SIGNATURE);

    /* load secret key & subkeys */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-sec-no-uid-no-sigs.pgp"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    /* try to add it twice */
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(list_length(key_store->keys), 3);
    assert_non_null(key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL));
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(&io, key_store, sub1id, NULL));
    assert_non_null(skey2 = rnp_key_store_get_key_by_id(&io, key_store, sub2id, NULL));
    assert_true(key->valid);
    assert_true(skey1->valid);
    assert_true(skey2->valid);
    assert_int_equal(key->uidc, 2);
    assert_int_equal(list_length(key->subkey_grips), 2);
    assert_int_equal(memcmp(list_front(key->subkey_grips), skey1->grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(memcmp(list_next(list_front(key->subkey_grips)), skey2->grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(key->packetc, 5);
    assert_int_equal(key->packets[0].tag, PGP_PTAG_CT_SECRET_KEY);
    assert_int_equal(key->packets[1].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[2].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(key->packets[3].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[4].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(skey1->uidc, 0);
    assert_int_equal(memcmp(key->grip, skey1->primary_grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(skey1->packetc, 2);
    assert_int_equal(skey1->packets[0].tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_int_equal(skey1->packets[1].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(skey2->uidc, 0);
    assert_int_equal(memcmp(key->grip, skey2->primary_grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(skey2->packetc, 2);
    assert_int_equal(skey2->packets[0].tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_int_equal(skey2->packets[1].tag, PGP_PTAG_CT_SIGNATURE);

    assert_true(pgp_key_unlock(key, &provider));
    assert_true(pgp_key_unlock(skey1, &provider));
    assert_true(pgp_key_unlock(skey2, &provider));

    /* load the whole public + secret key */
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-pub.asc"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_true(load_transferable_key(&tkey, MERGE_PATH "key-sec.asc"));
    assert_true(rnp_key_store_add_transferable_key(key_store, &tkey));
    transferable_key_destroy(&tkey);
    assert_int_equal(list_length(key_store->keys), 3);
    assert_non_null(key = rnp_key_store_get_key_by_id(&io, key_store, keyid, NULL));
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(&io, key_store, sub1id, NULL));
    assert_non_null(skey2 = rnp_key_store_get_key_by_id(&io, key_store, sub2id, NULL));
    assert_true(key->valid);
    assert_true(skey1->valid);
    assert_true(skey2->valid);
    assert_int_equal(key->uidc, 2);
    assert_int_equal(list_length(key->subkey_grips), 2);
    assert_int_equal(memcmp(list_front(key->subkey_grips), skey1->grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(memcmp(list_next(list_front(key->subkey_grips)), skey2->grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(key->packetc, 5);
    assert_int_equal(key->packets[0].tag, PGP_PTAG_CT_SECRET_KEY);
    assert_int_equal(key->packets[1].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[2].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(key->packets[3].tag, PGP_PTAG_CT_USER_ID);
    assert_int_equal(key->packets[4].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(skey1->uidc, 0);
    assert_int_equal(memcmp(key->grip, skey1->primary_grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(skey1->packetc, 2);
    assert_int_equal(skey1->packets[0].tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_int_equal(skey1->packets[1].tag, PGP_PTAG_CT_SIGNATURE);
    assert_int_equal(skey2->uidc, 0);
    assert_int_equal(memcmp(key->grip, skey2->primary_grip, PGP_FINGERPRINT_SIZE), 0);
    assert_int_equal(skey2->packetc, 2);
    assert_int_equal(skey2->packets[0].tag, PGP_PTAG_CT_SECRET_SUBKEY);
    assert_int_equal(skey2->packets[1].tag, PGP_PTAG_CT_SIGNATURE);
    assert_true(key == rnp_key_store_get_key_by_name(&io, key_store, "key-merge-uid-1", NULL));
    assert_true(key == rnp_key_store_get_key_by_name(&io, key_store, "key-merge-uid-2", NULL));

    rnp_key_store_free(key_store);
}

void
test_load_public_from_secret(void **state)
{
    pgp_io_t   io = {.outs = stdout, .errs = stderr, .res = stdout};
    pgp_key_t *key, *skey1, *skey2, keycp;
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    uint8_t          sub1id[PGP_KEY_ID_SIZE];
    uint8_t          sub2id[PGP_KEY_ID_SIZE];
    rnp_key_store_t *secstore, *pubstore;

    assert_non_null(secstore = rnp_key_store_new("GPG", MERGE_PATH "key-sec.asc"));
    assert_true(rnp_key_store_load_from_file(&io, secstore, NULL));
    assert_non_null(pubstore = rnp_key_store_new("GPG", "pubring.gpg"));

    assert_true(rnp_hex_decode("9747D2A6B3A63124", keyid, sizeof(keyid)));
    assert_true(rnp_hex_decode("AF1114A47F5F5B28", sub1id, sizeof(sub1id)));
    assert_true(rnp_hex_decode("16CD16F267CCDD4F", sub2id, sizeof(sub2id)));

    assert_non_null(key = rnp_key_store_get_key_by_id(&io, secstore, keyid, NULL));
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(&io, secstore, sub1id, NULL));
    assert_non_null(skey2 = rnp_key_store_get_key_by_id(&io, secstore, sub2id, NULL));

    /* copy the secret key */
    assert_rnp_success(pgp_key_copy(&keycp, key, false));
    assert_true(pgp_is_key_secret(&keycp));
    assert_int_equal(list_length(keycp.subkey_grips), 2);
    assert_false(memcmp(list_front(keycp.subkey_grips), skey1->grip, PGP_FINGERPRINT_SIZE));
    assert_false(memcmp(list_back(keycp.subkey_grips), skey2->grip, PGP_FINGERPRINT_SIZE));
    assert_false(memcmp(keycp.grip, key->grip, PGP_FINGERPRINT_SIZE));
    assert_int_equal(key->packets[0].tag, PGP_PTAG_CT_SECRET_KEY);
    pgp_key_free_data(&keycp);

    /* copy the public part */
    assert_rnp_success(pgp_key_copy(&keycp, key, true));
    assert_false(pgp_is_key_secret(&keycp));
    assert_int_equal(list_length(keycp.subkey_grips), 2);
    assert_false(memcmp(list_front(keycp.subkey_grips), skey1->grip, PGP_FINGERPRINT_SIZE));
    assert_false(memcmp(list_back(keycp.subkey_grips), skey2->grip, PGP_FINGERPRINT_SIZE));
    assert_false(memcmp(keycp.grip, key->grip, PGP_FINGERPRINT_SIZE));
    assert_int_equal(keycp.packets[0].tag, PGP_PTAG_CT_PUBLIC_KEY);
    assert_null(pgp_get_key_pkt(&keycp)->sec_data);
    assert_int_equal(pgp_get_key_pkt(&keycp)->sec_len, 0);
    assert_false(pgp_get_key_pkt(&keycp)->material.secret);
    rnp_key_store_add_key(&io, pubstore, &keycp);
    /* subkey 1 */
    assert_rnp_success(pgp_key_copy(&keycp, skey1, true));
    assert_false(pgp_is_key_secret(&keycp));
    assert_int_equal(list_length(keycp.subkey_grips), 0);
    assert_false(memcmp(keycp.primary_grip, key->grip, PGP_FINGERPRINT_SIZE));
    assert_false(memcmp(keycp.grip, skey1->grip, PGP_FINGERPRINT_SIZE));
    assert_false(memcmp(keycp.keyid, sub1id, PGP_KEY_ID_SIZE));
    assert_int_equal(keycp.packets[0].tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    assert_null(pgp_get_key_pkt(&keycp)->sec_data);
    assert_int_equal(pgp_get_key_pkt(&keycp)->sec_len, 0);
    assert_false(pgp_get_key_pkt(&keycp)->material.secret);
    rnp_key_store_add_key(&io, pubstore, &keycp);
    /* subkey 2 */
    assert_rnp_success(pgp_key_copy(&keycp, skey2, true));
    assert_false(pgp_is_key_secret(&keycp));
    assert_int_equal(list_length(keycp.subkey_grips), 0);
    assert_false(memcmp(keycp.primary_grip, key->grip, PGP_FINGERPRINT_SIZE));
    assert_false(memcmp(keycp.grip, skey2->grip, PGP_FINGERPRINT_SIZE));
    assert_false(memcmp(keycp.keyid, sub2id, PGP_KEY_ID_SIZE));
    assert_int_equal(keycp.packets[0].tag, PGP_PTAG_CT_PUBLIC_SUBKEY);
    assert_null(pgp_get_key_pkt(&keycp)->sec_data);
    assert_int_equal(pgp_get_key_pkt(&keycp)->sec_len, 0);
    assert_false(pgp_get_key_pkt(&keycp)->material.secret);
    rnp_key_store_add_key(&io, pubstore, &keycp);
    /* save pubring */
    assert_true(rnp_key_store_write_to_file(&io, pubstore, false));
    rnp_key_store_free(pubstore);
    /* reload */
    assert_non_null(pubstore = rnp_key_store_new("GPG", "pubring.gpg"));
    assert_true(rnp_key_store_load_from_file(&io, pubstore, NULL));
    assert_non_null(key = rnp_key_store_get_key_by_id(&io, pubstore, keyid, NULL));
    assert_non_null(skey1 = rnp_key_store_get_key_by_id(&io, pubstore, sub1id, NULL));
    assert_non_null(skey2 = rnp_key_store_get_key_by_id(&io, pubstore, sub2id, NULL));

    rnp_key_store_free(pubstore);
    rnp_key_store_free(secstore);
}
