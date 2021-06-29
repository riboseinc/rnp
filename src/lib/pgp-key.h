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

/** pgp_rawpacket_t */
typedef struct pgp_rawpacket_t {
    pgp_pkt_type_t       tag;
    std::vector<uint8_t> raw;

    pgp_rawpacket_t() = default;
    pgp_rawpacket_t(const uint8_t *data, size_t len, pgp_pkt_type_t tag)
        : tag(tag),
          raw(data ? std::vector<uint8_t>(data, data + len) : std::vector<uint8_t>()){};
    pgp_rawpacket_t(const pgp_signature_t &sig);
    pgp_rawpacket_t(pgp_key_pkt_t &key);
    pgp_rawpacket_t(const pgp_userid_pkt_t &uid);

    void write(pgp_dest_t &dst) const;
} pgp_rawpacket_t;

/* validity information for the signature/key/userid */
typedef struct pgp_validity_t {
    bool validated{}; /* item was validated */
    bool valid{};     /* item is valid by signature/key checks and calculations.
                         Still may be revoked or expired. */
    bool expired{};   /* item is expired */

    void mark_valid();
    void reset();
} pgp_validity_t;

/** information about the signature */
typedef struct pgp_subsig_t {
    uint32_t         uid{};         /* index in userid array in key for certification sig */
    pgp_signature_t  sig{};         /* signature packet */
    pgp_sig_id_t     sigid{};       /* signature identifier */
    pgp_rawpacket_t  rawpkt{};      /* signature's rawpacket */
    uint8_t          trustlevel{};  /* level of trust */
    uint8_t          trustamount{}; /* amount of trust */
    uint8_t          key_flags{};   /* key flags for certification/direct key sig */
    pgp_user_prefs_t prefs{};       /* user preferences for certification sig */
    pgp_validity_t   validity{};    /* signature validity information */

    pgp_subsig_t() = delete;
    pgp_subsig_t(const pgp_signature_t &sig);

    bool validated() const;
    bool valid() const;
    /** @brief Returns true if signature is certification */
    bool is_cert() const;
    /** @brief Returns true if signature is expired */
    bool expired() const;
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
    bool                del_sig(const pgp_sig_id_t &id);
    void                clear_sigs();
} pgp_userid_t;

#define PGP_UID_NONE ((uint32_t) -1)

typedef struct rnp_key_store_t rnp_key_store_t;

/* describes a user's key */
struct pgp_key_t {
  private:
    pgp_sig_map_t             sigs_map_{}; /* map with subsigs stored by their id */
    std::vector<pgp_sig_id_t> sigs_{};     /* subsig ids to lookup actual sig in map */
    std::vector<pgp_sig_id_t> keysigs_{};  /* direct-key signature ids in the original order */
    std::vector<pgp_userid_t> uids_{};     /* array of user ids */
    pgp_key_pkt_t             pkt_{};      /* pubkey/seckey data packet */
    uint8_t                   flags_{};    /* key flags */
    uint32_t                  expiration_{}; /* key expiration time, if available */
    pgp_key_id_t              keyid_{};
    pgp_fingerprint_t         fingerprint_{};
    pgp_key_grip_t            grip_{};
    pgp_fingerprint_t         primary_fp_{}; /* fingerprint of the primary key (for subkeys) */
    bool                      primary_fp_set_{};
    std::vector<pgp_fingerprint_t>
                    subkey_fps_{}; /* array of subkey fingerprints (for primary keys) */
    pgp_rawpacket_t rawpkt_{};     /* key raw packet */
    uint32_t        uid0_{};       /* primary uid index in uids array */
    bool            uid0_set_{};   /* flag for the above */
    bool            revoked_{};    /* key has been revoked */
    pgp_revoke_t    revocation_{}; /* revocation reason */
    pgp_validity_t  validity_{};   /* key's validity */
    uint64_t        valid_till_{}; /* date till which key is/was valid */

    pgp_subsig_t *latest_uid_selfcert(uint32_t uid);
    void          validate_primary(rnp_key_store_t &keyring);
    void          merge_validity(const pgp_validity_t &src);
    uint64_t      valid_till_common(bool expiry) const;
    /** @brief helper function: write secret key data to the rawpkt, encrypting with password
     */
    bool write_sec_rawpkt(pgp_key_pkt_t &seckey, const std::string &password);
    bool write_sec_pgp(pgp_dest_t &dst, pgp_key_pkt_t &seckey, const std::string &password);

  public:
    pgp_key_store_format_t format{}; /* the format of the key in packets[0] */

    pgp_key_t() = default;
    pgp_key_t(const pgp_key_pkt_t &pkt);
    pgp_key_t(const pgp_key_t &src, bool pubonly = false);
    pgp_key_t(const pgp_transferable_key_t &src);
    pgp_key_t(const pgp_transferable_subkey_t &src, pgp_key_t *primary);
    pgp_key_t &operator=(const pgp_key_t &) = default;
    pgp_key_t &operator=(pgp_key_t &&) = default;

    size_t              sig_count() const;
    pgp_subsig_t &      get_sig(size_t idx);
    const pgp_subsig_t &get_sig(size_t idx) const;
    bool                has_sig(const pgp_sig_id_t &id) const;
    pgp_subsig_t &      replace_sig(const pgp_sig_id_t &id, const pgp_signature_t &newsig);
    pgp_subsig_t &      get_sig(const pgp_sig_id_t &id);
    const pgp_subsig_t &get_sig(const pgp_sig_id_t &id) const;
    pgp_subsig_t &      add_sig(const pgp_signature_t &sig, size_t uid = PGP_UID_NONE);
    bool                del_sig(const pgp_sig_id_t &sigid);
    size_t              del_sigs(const std::vector<pgp_sig_id_t> &sigs);
    size_t              keysig_count() const;
    pgp_subsig_t &      get_keysig(size_t idx);
    size_t              uid_count() const;
    pgp_userid_t &      get_uid(size_t idx);
    const pgp_userid_t &get_uid(size_t idx) const;
    pgp_userid_t &      add_uid(const pgp_transferable_userid_t &uid);
    bool                has_uid(const std::string &uid) const;
    void                del_uid(size_t idx);
    bool                has_primary_uid() const;
    uint32_t            get_primary_uid() const;
    bool                revoked() const;
    const pgp_revoke_t &revocation() const;
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
    bool             can_sign() const;
    bool             can_certify() const;
    bool             can_encrypt() const;
    /** @brief Get key's expiration time in seconds. If 0 then it doesn't expire. */
    uint32_t expiration() const;
    /** @brief Check whether key is expired. Must be validated before that. */
    bool expired() const;
    /** @brief Get key's creation time in seconds since Jan, 1 1970. */
    uint32_t creation() const;
    bool     is_public() const;
    bool     is_secret() const;
    bool     is_primary() const;
    bool     is_subkey() const;
    /** @brief check if a key is currently locked, i.e. secret fields are not decrypted.
     *  Note: Key locking does not apply to unprotected keys.
     */
    bool is_locked() const;
    /** @brief check if a key is currently protected, i.e. its secret data is encrypted */
    bool is_protected() const;

    bool valid() const;
    bool validated() const;
    /** @brief return time till which key is considered to be valid */
    uint64_t valid_till() const;
    /** @brief check whether key was/will be valid at the specified time */
    bool valid_at(uint64_t timestamp) const;

    /** @brief Get key's id */
    const pgp_key_id_t &keyid() const;
    /** @brief Get key's fingerprint */
    const pgp_fingerprint_t &fp() const;
    /** @brief Get key's grip */
    const pgp_key_grip_t &grip() const;
    /** @brief Get primary key's fingerprint for the subkey, if it is available.
     *         Note: will throw if it is not available, use has_primary_fp() to check.
     */
    const pgp_fingerprint_t &primary_fp() const;
    /** @brief Check whether key has primary key's fingerprint */
    bool has_primary_fp() const;
    /** @brief Clean primary_fp */
    void unset_primary_fp();
    /** @brief Link key with subkey via primary_fp and subkey_fps list */
    void link_subkey_fp(pgp_key_t &subkey);
    /**
     * @brief Add subkey fp to key's list.
     *        Note: this function will check for duplicates.
     */
    void add_subkey_fp(const pgp_fingerprint_t &fp);
    /** @brief Get the number of pgp key's subkeys. */
    size_t subkey_count() const;
    /** @brief Remove subkey fingerprint from key's list. */
    void remove_subkey_fp(const pgp_fingerprint_t &fp);
    /**
     *  @brief Get the pgp key's subkey fingerprint
     *  @return fingerprint or throws std::out_of_range exception
     */
    const pgp_fingerprint_t &             get_subkey_fp(size_t idx) const;
    const std::vector<pgp_fingerprint_t> &subkey_fps() const;

    size_t                 rawpkt_count() const;
    pgp_rawpacket_t &      rawpkt();
    const pgp_rawpacket_t &rawpkt() const;
    void                   set_rawpkt(const pgp_rawpacket_t &src);

    /** @brief Unlock a key, i.e. decrypt its secret data so it can be used for
     *signing/decryption. Note: Key locking does not apply to unprotected keys.
     *
     *  @param pass_provider the password provider that may be used
     *         to unlock the key, if necessary
     *  @return true if the key was unlocked, false otherwise
     **/
    bool unlock(const pgp_password_provider_t &provider);
    /** @brief Lock a key, i.e. cleanup decrypted secret data.
     *  Note: Key locking does not apply to unprotected keys.
     *
     *  @param key the key
     *  @return true if the key was locked, false otherwise
     **/
    bool lock();
    /** @brief Add protection to an unlocked key, i.e. encrypt its secret data with specified
     *         parameters. */
    bool protect(const rnp_key_protection_params_t &protection,
                 const pgp_password_provider_t &    password_provider);
    /** @brief Add/change protection of a key */
    bool protect(pgp_key_pkt_t &                    decrypted,
                 const rnp_key_protection_params_t &protection,
                 const std::string &                new_password);
    /** @brief Remove protection from a key, i.e. leave secret fields unencrypted */
    bool unprotect(const pgp_password_provider_t &password_provider);

    /** @brief Write key's packets to the output. */
    void write(pgp_dest_t &dst) const;
    /**
     * @brief Write OpenPGP key packets (including subkeys) to the specified stream
     *
     * @param dst stream to write packets
     * @param keyring keyring, which will be searched for subkeys. Pass NULL to skip subkeys.
     * @return void, but error may be checked via dst.werr
     */
    void write_xfer(pgp_dest_t &dst, const rnp_key_store_t *keyring = NULL) const;
    /**
     * @brief Export key with subkey as it is required by Autocrypt (5-packet sequence: key,
     * uid, sig, subkey, sig).
     *
     * @param dst stream to write packets
     * @param sub subkey
     * @param uid index of uid to export
     * @return true on success or false otherwise
     */
    bool write_autocrypt(pgp_dest_t &dst, pgp_key_t &sub, uint32_t uid);

    /**
     * @brief Get the latest valid self-signature with information about the primary key for
     *        the specified uid (including the special cases). It could be userid certification
     *        or direct-key signature.
     *
     * @param uid uid for which latest self-signature should be returned,
     *            PGP_UID_NONE for direct-key signature,
     *            PGP_UID_PRIMARY for any primary key,
     *            PGP_UID_ANY for any uid.
     * @return pointer to signature object or NULL if failed/not found.
     */
    pgp_subsig_t *latest_selfsig(uint32_t uid);

    /**
     * @brief Get the latest valid subkey binding. Should be called on subkey.
     *
     * @param validated set to true whether binding signature must be validated
     * @return pointer to signature object or NULL if failed/not found.
     */
    pgp_subsig_t *latest_binding(bool validated = true);

    /** @brief Returns true if signature is produced by the key itself. */
    bool is_signer(const pgp_subsig_t &sig) const;

    /** @brief Returns true if key is expired according to sig. */
    bool expired_with(const pgp_subsig_t &sig) const;

    /** @brief Check whether signature is key's self certification. */
    bool is_self_cert(const pgp_subsig_t &sig) const;

    /** @brief Check whether signature is key's direct-key self-signature */
    bool is_direct_self(const pgp_subsig_t &sig) const;

    /** @brief Check whether signature is key's/subkey's revocation */
    bool is_revocation(const pgp_subsig_t &sig) const;

    /** @brief Check whether signature is userid revocation */
    bool is_uid_revocation(const pgp_subsig_t &sig) const;

    /** @brief Check whether signature is subkey binding */
    bool is_binding(const pgp_subsig_t &sig) const;

    /**
     * @brief Validate key's signature, assuming that 'this' is a signing key.
     *
     * @param key key or subkey to which signature belongs.
     * @param sig signature to validate.
     */
    void validate_sig(const pgp_key_t &key, pgp_subsig_t &sig) const;
    void validate_self_signatures();
    void validate_self_signatures(pgp_key_t &primary);
    void validate(rnp_key_store_t &keyring);
    void validate_subkey(pgp_key_t *primary = NULL);
    void revalidate(rnp_key_store_t &keyring);
    void mark_valid();

    /** @brief Refresh internal fields after primary key is updated */
    bool refresh_data();
    /** @brief Refresh internal fields after subkey is updated */
    bool refresh_data(pgp_key_t *primary);
    /** @brief Merge primary key with the src, i.e. add all new userids/signatures/subkeys */
    bool merge(const pgp_key_t &src);
    /** @brief Merge subkey with the source, i.e. add all new signatures */
    bool merge(const pgp_key_t &src, pgp_key_t *primary);
};

pgp_key_pkt_t *pgp_decrypt_seckey_pgp(const uint8_t *,
                                      size_t,
                                      const pgp_key_pkt_t *,
                                      const char *);

pgp_key_pkt_t *pgp_decrypt_seckey(const pgp_key_t *,
                                  const pgp_password_provider_t *,
                                  const pgp_password_ctx_t *);

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
 * @brief Get the key's subkey by its index
 *
 * @param key primary key
 * @param store key store which will be searched for subkeys
 * @param idx index of the subkey
 * @return pointer to the subkey or NULL if subkey not found
 */
pgp_key_t *pgp_key_get_subkey(const pgp_key_t *key, rnp_key_store_t *store, size_t idx);

pgp_key_flags_t pgp_pk_alg_capabilities(pgp_pubkey_alg_t alg);

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
                            const pgp_password_provider_t &prov);

bool pgp_subkey_set_expiration(pgp_key_t *                    sub,
                               pgp_key_t *                    primsec,
                               pgp_key_t *                    secsub,
                               uint32_t                       expiry,
                               const pgp_password_provider_t &prov);

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
 *  @param no_primary set true if only subkeys must be returned
 *
 *  @returns key or last created subkey with desired usage flag
 *           set or NULL if not found
 */
pgp_key_t *find_suitable_key(pgp_op_t            op,
                             pgp_key_t *         key,
                             pgp_key_provider_t *key_provider,
                             uint8_t             desired_usage,
                             bool                no_primary = false);

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

#endif // RNP_PACKET_KEY_H
