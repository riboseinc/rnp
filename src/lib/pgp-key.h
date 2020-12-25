/*
 * Copyright (c) 2017-2020 [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RNP_PACKET_KEY_H
#define RNP_PACKET_KEY_H

#include <stdbool.h>
#include <stdio.h>
#include <vector>
#include <unordered_map>
#include "pass-provider.h"
#include "../librepgp/stream-key.h"
#include <rekey/rnp_key_store.h>
#include "../librepgp/stream-packet.h"
#include "crypto/symmetric.h"
#include "types.h"

/* validity information for the signature */
typedef struct pgp_sig_validity_t {
    bool validated{}; /* signature was validated */
    bool sigvalid{};  /* signature is valid by signature/key checks and calculations.
                         Still may be revoked or expired. */
    bool expired{};   /* signature is expired */
} pgp_sig_validity_t;

/** information about the signature */
typedef struct pgp_subsig_t {
    uint32_t           uid{};         /* index in userid array in key for certification sig */
    pgp_signature_t    sig{};         /* signature packet */
    pgp_sig_id_t       sigid{};       /* signature identifier */
    pgp_rawpacket_t    rawpkt{};      /* signature's rawpacket */
    uint8_t            trustlevel{};  /* level of trust */
    uint8_t            trustamount{}; /* amount of trust */
    uint8_t            key_flags{};   /* key flags for certification/direct key sig */
    pgp_user_prefs_t   prefs{};       /* user preferences for certification sig */
    pgp_sig_validity_t validity{};    /* signature validity information */

    pgp_subsig_t() = delete;
    pgp_subsig_t(const pgp_signature_t &sig);

    bool valid() const;
} pgp_subsig_t;

typedef std::unordered_map<pgp_sig_id_t, pgp_subsig_t> pgp_sig_map_t;

/* userid, built on top of userid packet structure */
typedef struct pgp_userid_t {
  private:
    std::vector<pgp_sig_id_t> sigs_{}; /* all signatures related to this userid */
  public:
    pgp_userid_pkt_t pkt{};    /* User ID or User Attribute packet as it was loaded */
    pgp_rawpacket_t  rawpkt{}; /* Raw packet contents */
    std::string      str{};    /* Human-readable representation of the userid */
    bool         valid{}; /* User ID is valid, i.e. has valid, non-expired self-signature */
    bool         revoked{};
    pgp_revoke_t revocation{};

    pgp_userid_t(const pgp_userid_pkt_t &pkt);

    size_t              sig_count() const;
    const pgp_sig_id_t &get_sig(size_t idx) const;
    bool                has_sig(const pgp_sig_id_t &id) const;
    void                add_sig(const pgp_sig_id_t &sig);
    void                replace_sig(const pgp_sig_id_t &id, const pgp_sig_id_t &newsig);
} pgp_userid_t;

#define PGP_UID_NONE ((uint32_t) -1)

/* describes a user's key */
struct pgp_key_t {
  private:
    pgp_sig_map_t             sigs_map_{}; /* map with subsigs stored by their id */
    std::vector<pgp_sig_id_t> sigs_{};     /* subsig ids to lookup actual sig in map */
    std::vector<pgp_sig_id_t> keysigs_{};  /* direct-key signature ids in the original order */
    std::vector<pgp_userid_t> uids_{};     /* array of user ids */
    pgp_key_pkt_t             pkt_{};      /* pubkey/seckey data packet */
    uint8_t                   flags_{};    /* key flags */
    time_t                    expiration_{}; /* key expiration time, if available */
    pgp_key_id_t              keyid_{};
    pgp_fingerprint_t         fingerprint_{};
    pgp_key_grip_t            grip_{};

  public:
    std::vector<pgp_fingerprint_t>
                           subkey_fps{}; /* array of subkey fingerprints (for primary keys) */
    pgp_fingerprint_t      primary_fp{}; /* fingerprint of primary key (for subkeys) */
    bool                   primary_fp_set{};
    pgp_rawpacket_t        rawpkt{};     /* key raw packet */
    uint32_t               uid0{};       /* primary uid index in uids array */
    bool                   uid0_set{};   /* flag for the above */
    bool                   revoked{};    /* key has been revoked */
    pgp_revoke_t           revocation{}; /* revocation reason */
    pgp_key_store_format_t format{};     /* the format of the key in packets[0] */
    bool                   valid{};      /* this key is valid and usable */
    bool                   validated{};  /* this key was validated */

    pgp_key_t() = default;
    pgp_key_t(const pgp_key_pkt_t &pkt);
    pgp_key_t(const pgp_key_t &src, bool pubonly = false);
    pgp_key_t(const pgp_transferable_key_t &src);
    pgp_key_t(const pgp_transferable_subkey_t &src, pgp_key_t *primary);

    size_t              sig_count() const;
    pgp_subsig_t &      get_sig(size_t idx);
    const pgp_subsig_t &get_sig(size_t idx) const;
    bool                has_sig(const pgp_sig_id_t &id) const;
    pgp_subsig_t &      replace_sig(const pgp_sig_id_t &id, const pgp_signature_t &newsig);
    pgp_subsig_t &      get_sig(const pgp_sig_id_t &id);
    const pgp_subsig_t &get_sig(const pgp_sig_id_t &id) const;
    pgp_subsig_t &      add_sig(const pgp_signature_t &sig, size_t uid = PGP_UID_NONE);
    size_t              keysig_count() const;
    pgp_subsig_t &      get_keysig(size_t idx);
    size_t              uid_count() const;
    pgp_userid_t &      get_uid(size_t idx);
    const pgp_userid_t &get_uid(size_t idx) const;
    pgp_userid_t &      add_uid(const pgp_transferable_userid_t &uid);
    bool                has_uid(const std::string &uid) const;
    void                clear_revokes();

    const pgp_key_pkt_t &pkt() const;
    pgp_key_pkt_t &      pkt();
    void                 set_pkt(const pgp_key_pkt_t &pkt);

    const pgp_key_material_t &material() const;

    pgp_pubkey_alg_t alg() const;
    pgp_curve_t      curve() const;
    pgp_version_t    version() const;
    pgp_pkt_type_t   type() const;
    bool             encrypted() const;
    uint8_t          flags() const;
    void             set_flags(uint8_t flags);
    bool             can_sign() const;
    bool             can_certify() const;
    bool             can_encrypt() const;
    /** @brief Get key's expiration time in seconds. If 0 then it doesn't expire. */
    uint32_t expiration() const;
    void     set_expiration(uint32_t expiry);
    /** @brief Get key's creation time in seconds since Jan, 1 1970. */
    uint32_t creation() const;
    bool     is_public() const;
    bool     is_secret() const;
    bool     is_primary() const;
    bool     is_subkey() const;

    /** @brief Get key's id */
    const pgp_key_id_t &keyid() const;
    /** @brief Get key's fingerprint */
    const pgp_fingerprint_t &fp() const;
    /** @brief Get key's grip */
    const pgp_key_grip_t &grip() const;
};

typedef struct rnp_key_store_t rnp_key_store_t;

pgp_key_pkt_t *pgp_decrypt_seckey_pgp(const uint8_t *,
                                      size_t,
                                      const pgp_key_pkt_t *,
                                      const char *);

pgp_key_pkt_t *pgp_decrypt_seckey(const pgp_key_t *,
                                  const pgp_password_provider_t *,
                                  const pgp_password_ctx_t *);

/**
 * @brief Get primary key's fingerprint for the subkey, if available.
 *
 * @param key subkey, which primary key's fingerprint should be returned
 * @return reference to the fingerprint or NULL if it is not available
 */
const pgp_fingerprint_t &pgp_key_get_primary_fp(const pgp_key_t *key);

bool pgp_key_has_primary_fp(const pgp_key_t *key);

/**
 * @brief Set primary key's fingerprint for the subkey
 *
 * @param key subkey
 * @param fp buffer with fingerprint
 * @return void
 */
void pgp_key_set_primary_fp(pgp_key_t *key, const pgp_fingerprint_t &fp);

/**
 * @brief Link key with subkey via primary_fp and subkey_fps list
 *
 * @param key primary key
 * @param subkey subkey of the primary key
 * @return true on success or false otherwise (allocation failed, wrong key types)
 */
bool pgp_key_link_subkey_fp(pgp_key_t *key, pgp_key_t *subkey);

/**
 * @brief Get the latest valid self-signature with information about the primary key,
 * containing the specified subpacket. It could be userid certification or direct-key
 * signature.
 *
 * @param key key which should be searched for signature.
 * @param subpkt subpacket type. Pass 0 to return just latest signature.
 * @return pointer to signature object or NULL if failed/not found.
 */
pgp_subsig_t *pgp_key_latest_selfsig(pgp_key_t *key, pgp_sig_subpacket_type_t subpkt);

/**
 * @brief Get the latest valid subkey binding.
 *
 * @param subkey subkey which should be searched for signature.
 * @param validated set to true whether binding signature must be validated
 * @return pointer to signature object or NULL if failed/not found.
 */
pgp_subsig_t *pgp_key_latest_binding(pgp_key_t *subkey, bool validated);

/**
 * @brief Get the signer's key for signature
 *
 * @param sig signature
 * @param keyring keyring to search for the key. May be NULL.
 * @param prov key provider to request needed key, may be NULL.
 * @return pointer to the key or NULL if key is not found.
 */
pgp_key_t *pgp_sig_get_signer(const pgp_subsig_t &sig,
                              rnp_key_store_t *   keyring,
                              pgp_key_provider_t *prov);

/**
 * @brief Validate key's signature.
 *
 * @param key key (primary or subkey) which signature belongs to.
 * @param signer signing key/subkey.
 * @param primary primary key when it is applicable (for the subkey binding signature, or NULL.
 * @param sig signature to validate.
 */
void pgp_key_validate_signature(pgp_key_t &   key,
                                pgp_key_t &   signer,
                                pgp_key_t *   primary,
                                pgp_subsig_t &sig);

bool pgp_key_refresh_data(pgp_key_t *key);

bool pgp_subkey_refresh_data(pgp_key_t *sub, pgp_key_t *key);

size_t pgp_key_get_rawpacket_count(const pgp_key_t *);

pgp_rawpacket_t &      pgp_key_get_rawpacket(pgp_key_t *);
const pgp_rawpacket_t &pgp_key_get_rawpacket(const pgp_key_t *);

/**
 * @brief Get the number of pgp key's subkeys.
 *
 * @param key pointer to the primary key
 * @return number of the subkeys
 */
size_t pgp_key_get_subkey_count(const pgp_key_t *key);

/**
 * @brief Add subkey fp to key's list.
 *        Note: this function will check for duplicates.
 *
 * @param key key pointer to the primary key
 * @param fp subkey's fingerprint.
 * @return true if succeeded (fingerprint already exists in list or added), or false otherwise.
 */
bool pgp_key_add_subkey_fp(pgp_key_t *key, const pgp_fingerprint_t &fp);

/**
 * @brief Remove subkey fingerprint from key's list.
 *
 * @param key key pointer to the primary key
 * @param fp subkey's fingerprint.
 */
void pgp_key_remove_subkey_fp(pgp_key_t *key, const pgp_fingerprint_t &fp);

/**
 * @brief Get the pgp key's subkey fingerprint
 *
 * @param key key pointer to the primary key
 * @param idx index of the subkey
 * @return grip or throws std::out_of_range exception
 */
const pgp_fingerprint_t &pgp_key_get_subkey_fp(const pgp_key_t *key, size_t idx);

/**
 * @brief Get the key's subkey by it's index
 *
 * @param key primary key
 * @param store key store wich will be searched for subkeys
 * @param idx index of the subkey
 * @return pointer to the subkey or NULL if subkey not found
 */
pgp_key_t *pgp_key_get_subkey(const pgp_key_t *key, rnp_key_store_t *store, size_t idx);

pgp_key_flags_t pgp_pk_alg_capabilities(pgp_pubkey_alg_t alg);

/** check if a key is currently locked
 *
 *  Note: Key locking does not apply to unprotected keys.
 *
 *  @param key the key
 *  @return true if the key is locked, false otherwise
 **/
bool pgp_key_is_locked(const pgp_key_t *key);

/** unlock a key
 *
 *  Note: Key locking does not apply to unprotected keys.
 *
 *  @param key the key
 *  @param pass_provider the password provider that may be used
 *         to unlock the key, if necessary
 *  @return true if the key was unlocked, false otherwise
 **/
bool pgp_key_unlock(pgp_key_t *key, const pgp_password_provider_t *provider);

/** lock a key
 *
 *  Note: Key locking does not apply to unprotected keys.
 *
 *  @param key the key
 *  @return true if the key was unlocked, false otherwise
 **/
bool pgp_key_lock(pgp_key_t *key);

/** add protection to an unlocked key
 *
 *  @param key the key, which must be unlocked
 *  @param format
 *  @param protection
 *  @param password_provider the password provider, which is used to retrieve
 *         the new password for the key.
 *  @return true if key was successfully protected, false otherwise
 **/
bool rnp_key_add_protection(pgp_key_t *                    key,
                            pgp_key_store_format_t         format,
                            rnp_key_protection_params_t *  protection,
                            const pgp_password_provider_t *password_provider);

/** add protection to a key
 *
 *  @param key
 *  @param decrypted_seckey
 *  @param format
 *  @param protection
 *  @param new_password
 *  @return true if key was successfully protected, false otherwise
 **/
bool pgp_key_protect(pgp_key_t *                  key,
                     pgp_key_pkt_t *              decrypted_seckey,
                     pgp_key_store_format_t       format,
                     rnp_key_protection_params_t *protection,
                     const char *                 new_password);

/** remove protection from a key
 *
 *  @param key
 *  @param password_provider
 *  @return true if protection was successfully removed, false otherwise
 **/
bool pgp_key_unprotect(pgp_key_t *key, const pgp_password_provider_t *password_provider);

/** check if a key is currently protected
 *
 *  @param key
 *  @return true if the key is protected, false otherwise
 **/
bool pgp_key_is_protected(const pgp_key_t *key);

/** add a new certified userid to a key
 *
 *  @param key
 *  @param seckey the decrypted seckey for signing
 *  @param hash_alg the hash algorithm to be used for the signature
 *  @param cert the self-signature information
 *  @return true if the userid was added, false otherwise
 */
bool pgp_key_add_userid_certified(pgp_key_t *              key,
                                  const pgp_key_pkt_t *    seckey,
                                  pgp_hash_alg_t           hash_alg,
                                  rnp_selfsig_cert_info_t *cert);

bool pgp_key_set_expiration(pgp_key_t *                    key,
                            pgp_key_t *                    signer,
                            uint32_t                       expiry,
                            const pgp_password_provider_t *prov);

bool pgp_subkey_set_expiration(pgp_key_t *                    sub,
                               pgp_key_t *                    primsec,
                               pgp_key_t *                    secsub,
                               uint32_t                       expiry,
                               const pgp_password_provider_t *prov);

bool pgp_key_write_packets(const pgp_key_t *key, pgp_dest_t *dst);

/**
 * @brief Write OpenPGP key packets (including subkeys) to the specified stream
 *
 * @param dst stream to write packets
 * @param key key
 * @param keyring keyring, which will be searched for subkeys
 * @return true on success or false otherwise
 */
bool pgp_key_write_xfer(pgp_dest_t *dst, const pgp_key_t *key, const rnp_key_store_t *keyring);

/**
 * @brief Export key with subkey as it is required by Autocrypt (5-packet sequence: key, uid,
 *        sig, subkey, sig).
 *
 * @param dst stream to write packets
 * @param key primary key
 * @param sub subkey
 * @param uid index of uid to export
 * @return true on success or false otherwise
 */
bool pgp_key_write_autocrypt(pgp_dest_t &dst, pgp_key_t &key, pgp_key_t &sub, size_t uid);

/** find a key suitable for a particular operation
 *
 *  If the key passed is suitable, it will be returned.
 *  Otherwise, its subkeys (if it is a primary w/subs)
 *  will be checked. NULL will be returned if no suitable
 *  key is found.
 *
 *  @param op the operation for which the key should be suitable
 *  @param key the key
 *  @param desired_usage
 *  @param key_provider the key provider. This will be used
 *         if/when subkeys are checked.
 *
 *  @returns key or last created subkey with desired usage flag
 *           set or NULL if not found
 */
pgp_key_t *find_suitable_key(pgp_op_t            op,
                             pgp_key_t *         key,
                             pgp_key_provider_t *key_provider,
                             uint8_t             desired_usage);

/*
 *  Picks up hash algorithm according to domain parameters set
 *  in `pubkey' and user provided hash. That's mostly because DSA
 *  and ECDSA needs special treatment.
 *
 *  @param hash set by the caller
 *  @param pubkey initialized public key
 *
 *  @returns hash algorithm that must be use for operation (mostly
             signing with secure key which corresponds to 'pubkey')
 */
pgp_hash_alg_t pgp_hash_adjust_alg_to_key(pgp_hash_alg_t hash, const pgp_key_pkt_t *pubkey);

void pgp_key_validate_subkey(pgp_key_t *subkey, pgp_key_t *key);

void pgp_key_validate(pgp_key_t *key, rnp_key_store_t *keyring);

void pgp_key_revalidate_updated(pgp_key_t *key, rnp_key_store_t *keyring);

#endif // RNP_PACKET_KEY_H
