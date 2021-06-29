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

#include "pgp-key.h"
#include "utils.h"
#include <librekey/key_store_pgp.h>
#include <librekey/key_store_g10.h>
#include "crypto.h"
#include "crypto/s2k.h"
#include "crypto/mem.h"
#include "fingerprint.h"

#include <librepgp/stream-packet.h>
#include <librepgp/stream-key.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-armor.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <algorithm>
#include <stdexcept>
#include "defaults.h"

pgp_key_pkt_t *
pgp_decrypt_seckey_pgp(const uint8_t *      data,
                       size_t               data_len,
                       const pgp_key_pkt_t *pubkey,
                       const char *         password)
{
    pgp_source_t   src = {0};
    pgp_key_pkt_t *res = NULL;

    if (init_mem_src(&src, data, data_len, false)) {
        return NULL;
    }
    try {
        res = new pgp_key_pkt_t();
        if (res->parse(src)) {
            goto error;
        }
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        goto error;
    }
    if (decrypt_secret_key(res, password)) {
        goto error;
    }

    src_close(&src);
    return res;
error:
    src_close(&src);
    delete res;
    return NULL;
}

/* Note that this function essentially serves two purposes.
 * - In the case of a protected key, it requests a password and
 *   uses it to decrypt the key and fill in key->key.seckey.
 * - In the case of an unprotected key, it simply re-loads
 *   key->key.seckey by parsing the key data in packets[0].
 */
pgp_key_pkt_t *
pgp_decrypt_seckey(const pgp_key_t *              key,
                   const pgp_password_provider_t *provider,
                   const pgp_password_ctx_t *     ctx)
{
    typedef struct pgp_key_pkt_t *pgp_seckey_decrypt_t(
      const uint8_t *data, size_t data_len, const pgp_key_pkt_t *pubkey, const char *password);
    pgp_seckey_decrypt_t *decryptor = NULL;

    // sanity checks
    if (!key || !key->is_secret() || !provider) {
        RNP_LOG("invalid args");
        return NULL;
    }
    switch (key->format) {
    case PGP_KEY_STORE_GPG:
    case PGP_KEY_STORE_KBX:
        decryptor = pgp_decrypt_seckey_pgp;
        break;
    case PGP_KEY_STORE_G10:
        decryptor = g10_decrypt_seckey;
        break;
    default:
        RNP_LOG("unexpected format: %d", key->format);
        return NULL;
    }

    // ask the provider for a password
    rnp::secure_array<char, MAX_PASSWORD_LENGTH> password;
    if (key->is_protected() &&
        !pgp_request_password(provider, ctx, password.data(), password.size())) {
        return NULL;
    }
    // attempt to decrypt with the provided password
    const pgp_rawpacket_t &pkt = key->rawpkt();
    return decryptor(pkt.raw.data(), pkt.raw.size(), &key->pkt(), password.data());
}

pgp_key_t *
pgp_sig_get_signer(const pgp_subsig_t &sig, rnp_key_store_t *keyring, pgp_key_provider_t *prov)
{
    pgp_key_request_ctx_t ctx = {};
    /* if we have fingerprint let's check it */
    if (sig.sig.has_keyfp()) {
        ctx.search.by.fingerprint = sig.sig.keyfp();
        ctx.search.type = PGP_KEY_SEARCH_FINGERPRINT;
    }
    if ((ctx.search.type == PGP_KEY_SEARCH_UNKNOWN) && sig.sig.has_keyid()) {
        ctx.search.by.keyid = sig.sig.keyid();
        ctx.search.type = PGP_KEY_SEARCH_KEYID;
    }
    if (ctx.search.type == PGP_KEY_SEARCH_UNKNOWN) {
        RNP_LOG("No way to search for the signer.");
        return NULL;
    }

    pgp_key_t *key = rnp_key_store_search(keyring, &ctx.search, NULL);
    if (key || !prov) {
        return key;
    }

    ctx.op = PGP_OP_VERIFY;
    ctx.secret = false;
    return pgp_request_key(prov, &ctx);
}

static pgp_map_t ss_rr_code_map[] = {
  {PGP_REVOCATION_NO_REASON, "No reason specified"},
  {PGP_REVOCATION_SUPERSEDED, "Key is superseded"},
  {PGP_REVOCATION_COMPROMISED, "Key material has been compromised"},
  {PGP_REVOCATION_RETIRED, "Key is retired and no longer used"},
  {PGP_REVOCATION_NO_LONGER_VALID, "User ID information is no longer valid"},
  {0x00, NULL}, /* this is the end-of-array marker */
};

pgp_key_t *
pgp_key_get_subkey(const pgp_key_t *key, rnp_key_store_t *store, size_t idx)
{
    try {
        return rnp_key_store_get_key_by_fpr(store, key->get_subkey_fp(idx));
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return NULL;
    }
}

pgp_key_flags_t
pgp_pk_alg_capabilities(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_RSA:
        return pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH | PGP_KF_ENCRYPT);

    case PGP_PKA_RSA_SIGN_ONLY:
        // deprecated, but still usable
        return PGP_KF_SIGN;

    case PGP_PKA_RSA_ENCRYPT_ONLY:
        // deprecated, but still usable
        return PGP_KF_ENCRYPT;

    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN: /* deprecated */
        // These are no longer permitted per the RFC
        return PGP_KF_NONE;

    case PGP_PKA_DSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
        return pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH);

    case PGP_PKA_SM2:
        return pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH | PGP_KF_ENCRYPT);

    case PGP_PKA_ECDH:
    case PGP_PKA_ELGAMAL:
        return PGP_KF_ENCRYPT;

    default:
        RNP_LOG("unknown pk alg: %d\n", alg);
        return PGP_KF_NONE;
    }
}

bool
pgp_key_t::write_sec_pgp(pgp_dest_t &dst, pgp_key_pkt_t &seckey, const std::string &password)
{
    bool           res = false;
    pgp_pkt_type_t oldtag = seckey.tag;

    seckey.tag = type();
    if (encrypt_secret_key(&seckey, password.c_str(), NULL)) {
        goto done;
    }
    try {
        seckey.write(dst);
        res = !dst.werr;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
    }
done:
    seckey.tag = oldtag;
    return res;
}

bool
pgp_key_t::write_sec_rawpkt(pgp_key_pkt_t &seckey, const std::string &password)
{
    pgp_dest_t memdst = {};
    if (init_mem_dest(&memdst, NULL, 0)) {
        return false;
    }

    bool ret = false;
    // encrypt+write the key in the appropriate format
    try {
        switch (format) {
        case PGP_KEY_STORE_GPG:
        case PGP_KEY_STORE_KBX:
            if (!write_sec_pgp(memdst, seckey, password)) {
                RNP_LOG("failed to write secret key");
                goto done;
            }
            break;
        case PGP_KEY_STORE_G10:
            if (!g10_write_seckey(&memdst, &seckey, password.c_str())) {
                RNP_LOG("failed to write g10 secret key");
                goto done;
            }
            break;
        default:
            RNP_LOG("invalid format");
            goto done;
        }

        uint8_t *mem = (uint8_t *) mem_dest_get_memory(&memdst);
        rawpkt_ = pgp_rawpacket_t(mem, memdst.writeb, type());
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        goto done;
    }
    ret = true;
done:
    dst_close(&memdst, true);
    return ret;
}

bool
pgp_key_add_userid_certified(pgp_key_t *              key,
                             const pgp_key_pkt_t *    seckey,
                             pgp_hash_alg_t           hash_alg,
                             rnp_selfsig_cert_info_t *cert)
{
    // sanity checks
    if (!key || !seckey || !cert || !cert->userid[0]) {
        RNP_LOG("wrong parameters");
        return false;
    }
    // userids are only valid for primary keys, not subkeys
    if (!key->is_primary()) {
        RNP_LOG("cannot add a userid to a subkey");
        return false;
    }
    // see if the key already has this userid
    if (key->has_uid((const char *) cert->userid)) {
        RNP_LOG("key already has this userid");
        return false;
    }
    // this isn't really valid for this format
    if (key->format == PGP_KEY_STORE_G10) {
        RNP_LOG("Unsupported key store type");
        return false;
    }
    // We only support modifying v4 and newer keys
    if (key->pkt().version < PGP_V4) {
        RNP_LOG("adding a userid to V2/V3 key is not supported");
        return false;
    }
    // TODO: changing the primary userid is not currently supported
    if (key->has_primary_uid() && cert->primary) {
        RNP_LOG("changing the primary userid is not supported");
        return false;
    }

    /* Fill the transferable userid */
    pgp_transferable_userid_t uid;
    uid.uid.tag = PGP_PKT_USER_ID;
    uid.uid.uid_len = strlen((char *) cert->userid);
    if (!(uid.uid.uid = (uint8_t *) malloc(uid.uid.uid_len))) {
        RNP_LOG("allocation failed");
        return false;
    }
    /* uid.uid.uid looks really weird */
    memcpy(uid.uid.uid, (char *) cert->userid, uid.uid.uid_len);
    if (!transferable_userid_certify(*seckey, uid, *seckey, hash_alg, *cert)) {
        RNP_LOG("failed to add userid certification");
        return false;
    }
    try {
        key->add_uid(uid);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }

    return key->refresh_data();
}

static bool
update_sig_expiration(pgp_signature_t *dst, const pgp_signature_t *src, uint32_t expiry)
{
    try {
        *dst = *src;
        if (!expiry) {
            dst->remove_subpkt(dst->get_subpkt(PGP_SIG_SUBPKT_KEY_EXPIRY));
        } else {
            dst->set_key_expiration(expiry);
        }
        dst->set_creation(time(NULL));
        return true;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

bool
pgp_key_set_expiration(pgp_key_t *                    key,
                       pgp_key_t *                    seckey,
                       uint32_t                       expiry,
                       const pgp_password_provider_t &prov)
{
    if (!key->is_primary()) {
        RNP_LOG("Not a primary key");
        return false;
    }

    std::vector<pgp_sig_id_t> sigs;
    /* update expiration for the latest direct-key signature and self-signature for each userid
     */
    pgp_subsig_t *sig = key->latest_selfsig(PGP_UID_NONE);
    if (sig) {
        sigs.push_back(sig->sigid);
    }
    for (size_t uid = 0; uid < key->uid_count(); uid++) {
        sig = key->latest_selfsig(uid);
        if (sig) {
            sigs.push_back(sig->sigid);
        }
    }
    if (sigs.empty()) {
        RNP_LOG("No valid self-signature(s)");
        return false;
    }

    bool locked = false;
    bool res = false;
    for (const auto &sigid : sigs) {
        pgp_subsig_t &sig = key->get_sig(sigid);
        /* update signature and re-sign it */
        if (!expiry && !sig.sig.has_subpkt(PGP_SIG_SUBPKT_KEY_EXPIRY)) {
            continue;
        }

        /* unlock secret key if needed */
        locked = seckey->is_locked();
        if (locked && !seckey->unlock(prov)) {
            RNP_LOG("Failed to unlock secret key");
            return false;
        }

        pgp_signature_t newsig;
        pgp_sig_id_t    oldsigid = sigid;
        if (!update_sig_expiration(&newsig, &sig.sig, expiry)) {
            goto done;
        }
        if (sig.is_cert()) {
            if (sig.uid >= key->uid_count()) {
                RNP_LOG("uid not found");
                goto done;
            }
            if (!signature_calculate_certification(
                  &key->pkt(), &key->get_uid(sig.uid).pkt, &newsig, &seckey->pkt())) {
                RNP_LOG("failed to calculate signature");
                goto done;
            }
        } else {
            /* direct-key signature case */
            if (!signature_calculate_direct(&key->pkt(), &newsig, &seckey->pkt())) {
                RNP_LOG("failed to calculate signature");
                goto done;
            }
        }

        /* replace signature, first for secret key since it may be replaced in public */
        try {
            if (seckey->has_sig(oldsigid)) {
                seckey->replace_sig(oldsigid, newsig);
            }
            if (key != seckey) {
                key->replace_sig(oldsigid, newsig);
            }
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            goto done;
        }
    }

    if (!seckey->refresh_data()) {
        RNP_LOG("Failed to refresh seckey data.");
        goto done;
    }
    if ((key != seckey) && !key->refresh_data()) {
        RNP_LOG("Failed to refresh key data.");
        goto done;
    }
    res = true;
done:
    if (locked) {
        seckey->lock();
    }
    return res;
}

bool
pgp_subkey_set_expiration(pgp_key_t *                    sub,
                          pgp_key_t *                    primsec,
                          pgp_key_t *                    secsub,
                          uint32_t                       expiry,
                          const pgp_password_provider_t &prov)
{
    if (!sub->is_subkey()) {
        RNP_LOG("Not a subkey");
        return false;
    }

    /* find the latest valid subkey binding */
    pgp_subsig_t *subsig = sub->latest_binding();
    if (!subsig) {
        RNP_LOG("No valid subkey binding");
        return false;
    }
    if (!expiry && !subsig->sig.has_subpkt(PGP_SIG_SUBPKT_KEY_EXPIRY)) {
        return true;
    }

    bool res = false;
    bool subsign = secsub->can_sign();
    bool locked = primsec->is_locked();
    if (locked && !primsec->unlock(prov)) {
        RNP_LOG("Failed to unlock primary key");
        return false;
    }
    pgp_signature_t newsig;
    pgp_sig_id_t    oldsigid = subsig->sigid;
    bool            sublocked = false;
    if (subsign && secsub->is_locked()) {
        if (!secsub->unlock(prov)) {
            RNP_LOG("Failed to unlock subkey");
            goto done;
        }
        sublocked = true;
    }

    /* update signature and re-sign */
    if (!update_sig_expiration(&newsig, &subsig->sig, expiry)) {
        goto done;
    }
    if (!signature_calculate_binding(&primsec->pkt(), &secsub->pkt(), &newsig, subsign)) {
        RNP_LOG("failed to calculate signature");
        goto done;
    }

    /* replace signature, first for the secret key since it may be replaced in public */
    if (secsub->has_sig(oldsigid)) {
        try {
            secsub->replace_sig(oldsigid, newsig);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            goto done;
        }
        if (!secsub->refresh_data(primsec)) {
            goto done;
        }
    }
    if (sub == secsub) {
        res = true;
        goto done;
    }
    try {
        sub->replace_sig(oldsigid, newsig);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        goto done;
    }
    res = sub->refresh_data(primsec);
done:
    if (locked) {
        primsec->lock();
    }
    if (sublocked) {
        secsub->lock();
    }
    return res;
}

pgp_key_t *
find_suitable_key(pgp_op_t            op,
                  pgp_key_t *         key,
                  pgp_key_provider_t *key_provider,
                  uint8_t             desired_usage,
                  bool                no_primary)
{
    assert(desired_usage);
    if (!key) {
        return NULL;
    }
    if (!no_primary && key->valid() && (key->flags() & desired_usage)) {
        return key;
    }
    pgp_key_request_ctx_t ctx{.op = op, .secret = key->is_secret()};
    ctx.search.type = PGP_KEY_SEARCH_FINGERPRINT;

    pgp_key_t *subkey = NULL;
    for (auto &fp : key->subkey_fps()) {
        ctx.search.by.fingerprint = fp;
        pgp_key_t *cur = pgp_request_key(key_provider, &ctx);
        if (!cur || !(cur->flags() & desired_usage) || !cur->valid()) {
            continue;
        }
        if (!subkey || (cur->creation() > subkey->creation())) {
            subkey = cur;
        }
    }
    return subkey;
}

pgp_hash_alg_t
pgp_hash_adjust_alg_to_key(pgp_hash_alg_t hash, const pgp_key_pkt_t *pubkey)
{
    if ((pubkey->alg != PGP_PKA_DSA) && (pubkey->alg != PGP_PKA_ECDSA)) {
        return hash;
    }

    pgp_hash_alg_t hash_min;
    if (pubkey->alg == PGP_PKA_ECDSA) {
        hash_min = ecdsa_get_min_hash(pubkey->material.ec.curve);
    } else {
        hash_min = dsa_get_min_hash(mpi_bits(&pubkey->material.dsa.q));
    }

    if (pgp_digest_length(hash) < pgp_digest_length(hash_min)) {
        return hash_min;
    }
    return hash;
}

static void
mem_dest_to_vector(pgp_dest_t *dst, std::vector<uint8_t> &vec)
{
    uint8_t *mem = (uint8_t *) mem_dest_get_memory(dst);
    try {
        vec = std::vector<uint8_t>(mem, mem + dst->writeb);
        dst_close(dst, true);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        dst_close(dst, true);
        throw;
    }
}

static void
bytevec_append_uniq(std::vector<uint8_t> &vec, uint8_t val)
{
    if (std::find(vec.begin(), vec.end(), val) == vec.end()) {
        vec.push_back(val);
    }
}

void
pgp_user_prefs_t::set_symm_algs(const std::vector<uint8_t> &algs)
{
    symm_algs = algs;
}

void
pgp_user_prefs_t::add_symm_alg(pgp_symm_alg_t alg)
{
    bytevec_append_uniq(symm_algs, alg);
}

void
pgp_user_prefs_t::set_hash_algs(const std::vector<uint8_t> &algs)
{
    hash_algs = algs;
}

void
pgp_user_prefs_t::add_hash_alg(pgp_hash_alg_t alg)
{
    bytevec_append_uniq(hash_algs, alg);
}

void
pgp_user_prefs_t::set_z_algs(const std::vector<uint8_t> &algs)
{
    z_algs = algs;
}

void
pgp_user_prefs_t::add_z_alg(pgp_compression_type_t alg)
{
    bytevec_append_uniq(z_algs, alg);
}

void
pgp_user_prefs_t::set_ks_prefs(const std::vector<uint8_t> &prefs)
{
    ks_prefs = prefs;
}

void
pgp_user_prefs_t::add_ks_pref(pgp_key_server_prefs_t pref)
{
    bytevec_append_uniq(ks_prefs, pref);
}

pgp_rawpacket_t::pgp_rawpacket_t(const pgp_signature_t &sig)
{
    pgp_dest_t dst = {};

    if (init_mem_dest(&dst, NULL, 0)) {
        throw std::bad_alloc();
    }

    try {
        sig.write(dst);
    } catch (const std::exception &e) {
        dst_close(&dst, true);
        throw;
    }
    mem_dest_to_vector(&dst, raw);
    tag = PGP_PKT_SIGNATURE;
}

pgp_rawpacket_t::pgp_rawpacket_t(pgp_key_pkt_t &key)
{
    pgp_dest_t dst = {};

    if (init_mem_dest(&dst, NULL, 0)) {
        throw std::bad_alloc();
    }
    try {
        key.write(dst);
    } catch (const std::exception &e) {
        dst_close(&dst, true);
        throw;
    }
    mem_dest_to_vector(&dst, raw);
    tag = key.tag;
}

pgp_rawpacket_t::pgp_rawpacket_t(const pgp_userid_pkt_t &uid)
{
    pgp_dest_t dst = {};

    if (init_mem_dest(&dst, NULL, 0)) {
        throw std::bad_alloc();
    }
    try {
        uid.write(dst);
    } catch (const std::exception &e) {
        dst_close(&dst, true);
        throw;
    }
    mem_dest_to_vector(&dst, raw);
    tag = uid.tag;
}

void
pgp_rawpacket_t::write(pgp_dest_t &dst) const
{
    dst_write(&dst, raw.data(), raw.size());
}

void
pgp_validity_t::mark_valid()
{
    validated = true;
    valid = true;
    expired = false;
}

void
pgp_validity_t::reset()
{
    validated = false;
    valid = false;
    expired = false;
}

pgp_subsig_t::pgp_subsig_t(const pgp_signature_t &pkt)
{
    sig = pkt;
    sigid = sig.get_id();
    if (sig.has_subpkt(PGP_SIG_SUBPKT_TRUST)) {
        trustlevel = sig.trust_level();
        trustamount = sig.trust_amount();
    }
    prefs.set_symm_algs(sig.preferred_symm_algs());
    prefs.set_hash_algs(sig.preferred_hash_algs());
    prefs.set_z_algs(sig.preferred_z_algs());

    if (sig.has_subpkt(PGP_SIG_SUBPKT_KEY_FLAGS)) {
        key_flags = sig.key_flags();
    }
    if (sig.has_subpkt(PGP_SIG_SUBPKT_KEYSERV_PREFS)) {
        prefs.set_ks_prefs({sig.key_server_prefs()});
    }
    if (sig.has_subpkt(PGP_SIG_SUBPKT_PREF_KEYSERV)) {
        prefs.key_server = sig.key_server();
    }
    /* add signature rawpacket */
    rawpkt = pgp_rawpacket_t(sig);
}

bool
pgp_subsig_t::valid() const
{
    return validity.validated && validity.valid && !validity.expired;
}

bool
pgp_subsig_t::validated() const
{
    return validity.validated;
}

bool
pgp_subsig_t::is_cert() const
{
    pgp_sig_type_t type = sig.type();
    return (type == PGP_CERT_CASUAL) || (type == PGP_CERT_GENERIC) ||
           (type == PGP_CERT_PERSONA) || (type == PGP_CERT_POSITIVE);
}

bool
pgp_subsig_t::expired() const
{
    /* sig expiration: absence of subpkt or 0 means it never expires */
    uint64_t expiration = sig.expiration();
    if (!expiration) {
        return false;
    }
    uint64_t now = time(NULL);
    return expiration + sig.creation() < now;
}

pgp_userid_t::pgp_userid_t(const pgp_userid_pkt_t &uidpkt)
{
    /* copy packet data */
    pkt = uidpkt;
    rawpkt = pgp_rawpacket_t(uidpkt);
    /* populate uid string */
    if (uidpkt.tag == PGP_PKT_USER_ID) {
        str = std::string(uidpkt.uid, uidpkt.uid + uidpkt.uid_len);
    } else {
        str = "(photo)";
    }
}

size_t
pgp_userid_t::sig_count() const
{
    return sigs_.size();
}

const pgp_sig_id_t &
pgp_userid_t::get_sig(size_t idx) const
{
    if (idx >= sigs_.size()) {
        throw std::out_of_range("idx");
    }
    return sigs_[idx];
}

bool
pgp_userid_t::has_sig(const pgp_sig_id_t &id) const
{
    return std::find(sigs_.begin(), sigs_.end(), id) != sigs_.end();
}

void
pgp_userid_t::add_sig(const pgp_sig_id_t &sig)
{
    sigs_.push_back(sig);
}

void
pgp_userid_t::replace_sig(const pgp_sig_id_t &id, const pgp_sig_id_t &newsig)
{
    auto it = std::find(sigs_.begin(), sigs_.end(), id);
    if (it == sigs_.end()) {
        throw std::invalid_argument("id");
    }
    *it = newsig;
}

bool
pgp_userid_t::del_sig(const pgp_sig_id_t &id)
{
    auto it = std::find(sigs_.begin(), sigs_.end(), id);
    if (it == sigs_.end()) {
        return false;
    }
    sigs_.erase(it);
    return true;
}

void
pgp_userid_t::clear_sigs()
{
    sigs_.clear();
}

pgp_revoke_t::pgp_revoke_t(pgp_subsig_t &sig)
{
    uid = sig.uid;
    sigid = sig.sigid;
    if (!sig.sig.has_subpkt(PGP_SIG_SUBPKT_REVOCATION_REASON)) {
        RNP_LOG("Warning: no revocation reason in the revocation");
        code = PGP_REVOCATION_NO_REASON;
    } else {
        code = sig.sig.revocation_code();
        reason = sig.sig.revocation_reason();
    }
    if (reason.empty()) {
        reason = pgp_str_from_map(code, ss_rr_code_map);
    }
}

pgp_key_t::pgp_key_t(const pgp_key_pkt_t &keypkt) : pkt_(keypkt)
{
    if (!is_key_pkt(pkt_.tag) || !pkt_.material.alg) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    if (pgp_keyid(keyid_, pkt_) || pgp_fingerprint(fingerprint_, pkt_) ||
        !rnp_key_store_get_key_grip(&pkt_.material, grip_)) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }

    /* parse secret key if not encrypted */
    if (is_secret_key_pkt(pkt_.tag)) {
        bool cleartext = pkt_.sec_protection.s2k.usage == PGP_S2KU_NONE;
        if (cleartext && decrypt_secret_key(&pkt_, NULL)) {
            RNP_LOG("failed to setup key fields");
            throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
        }
    }
    /* add rawpacket */
    rawpkt_ = pgp_rawpacket_t(pkt_);
    format = PGP_KEY_STORE_GPG;
}

pgp_key_t::pgp_key_t(const pgp_key_t &src, bool pubonly)
{
    /* Do some checks for g10 keys */
    if (src.format == PGP_KEY_STORE_G10) {
        if (pubonly) {
            RNP_LOG("attempt to copy public part from g10 key");
            throw std::invalid_argument("pubonly");
        }
    }

    if (pubonly) {
        pkt_ = pgp_key_pkt_t(src.pkt_, true);
        rawpkt_ = pgp_rawpacket_t(pkt_);
    } else {
        pkt_ = src.pkt_;
        rawpkt_ = src.rawpkt_;
    }

    uids_ = src.uids_;
    sigs_ = src.sigs_;
    sigs_map_ = src.sigs_map_;
    keysigs_ = src.keysigs_;
    subkey_fps_ = src.subkey_fps_;
    primary_fp_set_ = src.primary_fp_set_;
    primary_fp_ = src.primary_fp_;
    expiration_ = src.expiration_;
    flags_ = src.flags_;
    keyid_ = src.keyid_;
    fingerprint_ = src.fingerprint_;
    grip_ = src.grip_;
    uid0_ = src.uid0_;
    uid0_set_ = src.uid0_set_;
    revoked_ = src.revoked_;
    revocation_ = src.revocation_;
    format = src.format;
    validity_ = src.validity_;
    valid_till_ = src.valid_till_;
}

pgp_key_t::pgp_key_t(const pgp_transferable_key_t &src) : pgp_key_t(src.key)
{
    /* add direct-key signatures */
    for (auto &sig : src.signatures) {
        add_sig(sig);
    }

    /* add userids and their signatures */
    for (auto &uid : src.userids) {
        add_uid(uid);
    }
}

pgp_key_t::pgp_key_t(const pgp_transferable_subkey_t &src, pgp_key_t *primary)
    : pgp_key_t(src.subkey)
{
    /* add subkey binding signatures */
    for (auto &sig : src.signatures) {
        add_sig(sig);
    }

    /* setup key grips if primary is available */
    if (primary) {
        primary->link_subkey_fp(*this);
    }
}

size_t
pgp_key_t::sig_count() const
{
    return sigs_.size();
}

pgp_subsig_t &
pgp_key_t::get_sig(size_t idx)
{
    if (idx >= sigs_.size()) {
        throw std::out_of_range("idx");
    }
    return get_sig(sigs_[idx]);
}

const pgp_subsig_t &
pgp_key_t::get_sig(size_t idx) const
{
    if (idx >= sigs_.size()) {
        throw std::out_of_range("idx");
    }
    return get_sig(sigs_[idx]);
}

bool
pgp_key_t::has_sig(const pgp_sig_id_t &id) const
{
    return sigs_map_.count(id);
}

pgp_subsig_t &
pgp_key_t::get_sig(const pgp_sig_id_t &id)
{
    if (!has_sig(id)) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    return sigs_map_.at(id);
}

const pgp_subsig_t &
pgp_key_t::get_sig(const pgp_sig_id_t &id) const
{
    if (!has_sig(id)) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    return sigs_map_.at(id);
}

pgp_subsig_t &
pgp_key_t::replace_sig(const pgp_sig_id_t &id, const pgp_signature_t &newsig)
{
    /* save oldsig's uid */
    size_t uid = get_sig(id).uid;
    /* delete first old sig since we may have theoretically the same sigid */
    pgp_sig_id_t oldid = id;
    sigs_map_.erase(oldid);
    auto &res = sigs_map_.emplace(std::make_pair(newsig.get_id(), newsig)).first->second;
    res.uid = uid;
    auto it = std::find(sigs_.begin(), sigs_.end(), oldid);
    *it = res.sigid;
    if (uid == PGP_UID_NONE) {
        auto it = std::find(keysigs_.begin(), keysigs_.end(), oldid);
        *it = res.sigid;
    } else {
        uids_[uid].replace_sig(oldid, res.sigid);
    }
    return res;
}

pgp_subsig_t &
pgp_key_t::add_sig(const pgp_signature_t &sig, size_t uid)
{
    const pgp_sig_id_t sigid = sig.get_id();
    sigs_map_.erase(sigid);
    pgp_subsig_t &res = sigs_map_.emplace(std::make_pair(sigid, sig)).first->second;
    res.uid = uid;
    sigs_.push_back(sigid);
    if (uid == PGP_UID_NONE) {
        keysigs_.push_back(sigid);
    } else {
        uids_[uid].add_sig(sigid);
    }
    return res;
}

bool
pgp_key_t::del_sig(const pgp_sig_id_t &sigid)
{
    if (!has_sig(sigid)) {
        return false;
    }
    uint32_t uid = get_sig(sigid).uid;
    if (uid == PGP_UID_NONE) {
        /* signature over the key itself */
        auto it = std::find(keysigs_.begin(), keysigs_.end(), sigid);
        if (it != keysigs_.end()) {
            keysigs_.erase(it);
        }
    } else if (uid < uids_.size()) {
        /* userid-related signature */
        uids_[uid].del_sig(sigid);
    }
    auto it = std::find(sigs_.begin(), sigs_.end(), sigid);
    if (it != sigs_.end()) {
        sigs_.erase(it);
    }
    return sigs_map_.erase(sigid);
}

size_t
pgp_key_t::del_sigs(const std::vector<pgp_sig_id_t> &sigs)
{
    /* delete actual signatures */
    size_t res = 0;
    for (auto &sig : sigs) {
        res += sigs_map_.erase(sig);
    }
    /* rebuild vectors with signatures order */
    keysigs_.clear();
    for (auto &uid : uids_) {
        uid.clear_sigs();
    }
    std::vector<pgp_sig_id_t> newsigs;
    newsigs.reserve(sigs_map_.size());
    for (auto &sigid : sigs_) {
        if (!sigs_map_.count(sigid)) {
            continue;
        }
        newsigs.push_back(sigid);
        uint32_t uid = get_sig(sigid).uid;
        if (uid == PGP_UID_NONE) {
            keysigs_.push_back(sigid);
        } else {
            uids_[uid].add_sig(sigid);
        }
    }
    sigs_ = std::move(newsigs);
    return res;
}

size_t
pgp_key_t::keysig_count() const
{
    return keysigs_.size();
}

pgp_subsig_t &
pgp_key_t::get_keysig(size_t idx)
{
    if (idx >= keysigs_.size()) {
        throw std::out_of_range("idx");
    }
    return get_sig(keysigs_[idx]);
}

size_t
pgp_key_t::uid_count() const
{
    return uids_.size();
}

pgp_userid_t &
pgp_key_t::get_uid(size_t idx)
{
    if (idx >= uids_.size()) {
        throw std::out_of_range("idx");
    }
    return uids_[idx];
}

const pgp_userid_t &
pgp_key_t::get_uid(size_t idx) const
{
    if (idx >= uids_.size()) {
        throw std::out_of_range("idx");
    }
    return uids_[idx];
}

bool
pgp_key_t::has_uid(const std::string &uidstr) const
{
    for (auto &userid : uids_) {
        if (!userid.valid) {
            continue;
        }
        if (userid.str == uidstr) {
            return true;
        }
    }
    return false;
}

void
pgp_key_t::del_uid(size_t idx)
{
    if (idx >= uids_.size()) {
        throw std::out_of_range("idx");
    }

    std::vector<pgp_sig_id_t> newsigs;
    /* copy sigs which do not belong to uid */
    newsigs.reserve(sigs_.size());
    for (auto &id : sigs_) {
        if (get_sig(id).uid == idx) {
            sigs_map_.erase(id);
            continue;
        }
        newsigs.push_back(id);
    }
    sigs_ = newsigs;
    uids_.erase(uids_.begin() + idx);
    /* update uids */
    if (idx == uids_.size()) {
        return;
    }
    for (auto &sig : sigs_map_) {
        if ((sig.second.uid == PGP_UID_NONE) || (sig.second.uid <= idx)) {
            continue;
        }
        sig.second.uid--;
    }
}

bool
pgp_key_t::has_primary_uid() const
{
    return uid0_set_;
}

uint32_t
pgp_key_t::get_primary_uid() const
{
    if (!uid0_set_) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    return uid0_;
}

pgp_userid_t &
pgp_key_t::add_uid(const pgp_transferable_userid_t &uid)
{
    /* construct userid */
    uids_.emplace_back(uid.uid);
    /* add certifications */
    for (auto &sig : uid.signatures) {
        add_sig(sig, uid_count() - 1);
    }
    return uids_.back();
}

bool
pgp_key_t::revoked() const
{
    return revoked_;
}

const pgp_revoke_t &
pgp_key_t::revocation() const
{
    if (!revoked_) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    return revocation_;
}

void
pgp_key_t::clear_revokes()
{
    revoked_ = false;
    revocation_ = {};
    for (auto &uid : uids_) {
        uid.revoked = false;
        uid.revocation = {};
    }
}

const pgp_key_pkt_t &
pgp_key_t::pkt() const
{
    return pkt_;
}

pgp_key_pkt_t &
pgp_key_t::pkt()
{
    return pkt_;
}

void
pgp_key_t::set_pkt(const pgp_key_pkt_t &pkt)
{
    pkt_ = pkt;
}

const pgp_key_material_t &
pgp_key_t::material() const
{
    return pkt_.material;
}

pgp_pubkey_alg_t
pgp_key_t::alg() const
{
    return pkt_.alg;
}

pgp_curve_t
pgp_key_t::curve() const
{
    switch (alg()) {
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        return material().ec.curve;
    default:
        return PGP_CURVE_UNKNOWN;
    }
}

pgp_version_t
pgp_key_t::version() const
{
    return pkt().version;
}

pgp_pkt_type_t
pgp_key_t::type() const
{
    return pkt().tag;
}

bool
pgp_key_t::encrypted() const
{
    return is_secret() && !pkt().material.secret;
}

uint8_t
pgp_key_t::flags() const
{
    return flags_;
}

bool
pgp_key_t::can_sign() const
{
    return flags_ & PGP_KF_SIGN;
}

bool
pgp_key_t::can_certify() const
{
    return flags_ & PGP_KF_CERTIFY;
}

bool
pgp_key_t::can_encrypt() const
{
    return flags_ & PGP_KF_ENCRYPT;
}

uint32_t
pgp_key_t::expiration() const
{
    if (pkt_.version >= 4) {
        return expiration_;
    }
    /* too large value for pkt.v3_days may overflow uint32_t */
    if (pkt_.v3_days > (0xffffffffu / 86400)) {
        return 0xffffffffu;
    }
    return (uint32_t) pkt_.v3_days * 86400;
}

bool
pgp_key_t::expired() const
{
    return validity_.expired;
}

uint32_t
pgp_key_t::creation() const
{
    return pkt_.creation_time;
}

bool
pgp_key_t::is_public() const
{
    return is_public_key_pkt(pkt_.tag);
}

bool
pgp_key_t::is_secret() const
{
    return is_secret_key_pkt(pkt_.tag);
}

bool
pgp_key_t::is_primary() const
{
    return is_primary_key_pkt(pkt_.tag);
}

bool
pgp_key_t::is_subkey() const
{
    return is_subkey_pkt(pkt_.tag);
}

bool
pgp_key_t::is_locked() const
{
    if (!is_secret()) {
        RNP_LOG("key is not a secret key");
        return false;
    }
    return encrypted();
}

bool
pgp_key_t::is_protected() const
{
    // sanity check
    if (!is_secret()) {
        RNP_LOG("Warning: this is not a secret key");
    }
    return pkt_.sec_protection.s2k.usage != PGP_S2KU_NONE;
}

bool
pgp_key_t::valid() const
{
    return validity_.validated && validity_.valid && !validity_.expired;
}

bool
pgp_key_t::validated() const
{
    return validity_.validated;
}

uint64_t
pgp_key_t::valid_till_common(bool expiry) const
{
    if (!validated()) {
        return 0;
    }
    uint64_t till = expiration() ? (uint64_t) creation() + expiration() : UINT64_MAX;
    if (valid()) {
        return till;
    }
    if (revoked()) {
        /* we should not believe to the compromised key at all */
        if (revocation_.code == PGP_REVOCATION_COMPROMISED) {
            return 0;
        }
        const pgp_subsig_t &revsig = get_sig(revocation_.sigid);
        if (revsig.sig.creation() > creation()) {
            /* pick less time from revocation time and expiration time */
            return std::min((uint64_t) revsig.sig.creation(), till);
        }
        return 0;
    }
    /* if key is not marked as expired then it wasn't valid at all */
    return expiry ? till : 0;
}

uint64_t
pgp_key_t::valid_till() const
{
    return valid_till_;
}

bool
pgp_key_t::valid_at(uint64_t timestamp) const
{
    /* TODO: consider implementing more sophisticated checks, as key validity time could
     * possibly be non-continuous */
    return (timestamp >= creation()) && timestamp && (timestamp <= valid_till());
}

const pgp_key_id_t &
pgp_key_t::keyid() const
{
    return keyid_;
}

const pgp_fingerprint_t &
pgp_key_t::fp() const
{
    return fingerprint_;
}

const pgp_key_grip_t &
pgp_key_t::grip() const
{
    return grip_;
}

const pgp_fingerprint_t &
pgp_key_t::primary_fp() const
{
    if (!primary_fp_set_) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    return primary_fp_;
}

bool
pgp_key_t::has_primary_fp() const
{
    return primary_fp_set_;
}

void
pgp_key_t::unset_primary_fp()
{
    primary_fp_set_ = false;
    primary_fp_ = {};
}

void
pgp_key_t::link_subkey_fp(pgp_key_t &subkey)
{
    if (!is_primary() || !subkey.is_subkey()) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    subkey.primary_fp_ = fp();
    subkey.primary_fp_set_ = true;
    add_subkey_fp(subkey.fp());
}

void
pgp_key_t::add_subkey_fp(const pgp_fingerprint_t &fp)
{
    if (std::find(subkey_fps_.begin(), subkey_fps_.end(), fp) == subkey_fps_.end()) {
        subkey_fps_.push_back(fp);
    }
}

size_t
pgp_key_t::subkey_count() const
{
    return subkey_fps_.size();
}

void
pgp_key_t::remove_subkey_fp(const pgp_fingerprint_t &fp)
{
    auto it = std::find(subkey_fps_.begin(), subkey_fps_.end(), fp);
    if (it != subkey_fps_.end()) {
        subkey_fps_.erase(it);
    }
}

const pgp_fingerprint_t &
pgp_key_t::get_subkey_fp(size_t idx) const
{
    return subkey_fps_[idx];
}

const std::vector<pgp_fingerprint_t> &
pgp_key_t::subkey_fps() const
{
    return subkey_fps_;
}

size_t
pgp_key_t::rawpkt_count() const
{
    if (format == PGP_KEY_STORE_G10) {
        return 1;
    }
    return 1 + uid_count() + sig_count();
}

pgp_rawpacket_t &
pgp_key_t::rawpkt()
{
    return rawpkt_;
}

const pgp_rawpacket_t &
pgp_key_t::rawpkt() const
{
    return rawpkt_;
}

void
pgp_key_t::set_rawpkt(const pgp_rawpacket_t &src)
{
    rawpkt_ = src;
}

bool
pgp_key_t::unlock(const pgp_password_provider_t &provider)
{
    // sanity checks
    if (!is_secret()) {
        RNP_LOG("key is not a secret key");
        return false;
    }
    // see if it's already unlocked
    if (!is_locked()) {
        return true;
    }

    pgp_password_ctx_t ctx = {.op = PGP_OP_UNLOCK, .key = this};
    pgp_key_pkt_t *    decrypted_seckey = pgp_decrypt_seckey(this, &provider, &ctx);
    if (!decrypted_seckey) {
        return false;
    }

    // this shouldn't really be necessary, but just in case
    forget_secret_key_fields(&pkt_.material);
    // copy the decrypted mpis into the pgp_key_t
    pkt_.material = decrypted_seckey->material;
    pkt_.material.secret = true;
    delete decrypted_seckey;
    return true;
}

bool
pgp_key_t::lock()
{
    // sanity checks
    if (!is_secret()) {
        RNP_LOG("invalid args");
        return false;
    }

    // see if it's already locked
    if (is_locked()) {
        return true;
    }

    forget_secret_key_fields(&pkt_.material);
    return true;
}

bool
pgp_key_t::protect(const rnp_key_protection_params_t &protection,
                   const pgp_password_provider_t &    password_provider)
{
    pgp_password_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.op = PGP_OP_PROTECT;
    ctx.key = this;

    // ask the provider for a password
    rnp::secure_array<char, MAX_PASSWORD_LENGTH> password;
    if (!pgp_request_password(&password_provider, &ctx, password.data(), password.size())) {
        return false;
    }
    return protect(pkt_, protection, password.data());
}

bool
pgp_key_t::protect(pgp_key_pkt_t &                    decrypted,
                   const rnp_key_protection_params_t &protection,
                   const std::string &                new_password)
{
    if (!is_secret()) {
        RNP_LOG("Warning: this is not a secret key");
        return false;
    }
    bool ownpkt = &decrypted == &pkt_;
    if (!decrypted.material.secret) {
        RNP_LOG("Decrypted secret key must be provided");
        return false;
    }

    /* force encrypted-and-hashed and iterated-and-salted as it's the only method we support*/
    pkt_.sec_protection.s2k.usage = PGP_S2KU_ENCRYPTED_AND_HASHED;
    pkt_.sec_protection.s2k.specifier = PGP_S2KS_ITERATED_AND_SALTED;
    /* use default values where needed */
    pkt_.sec_protection.symm_alg =
      protection.symm_alg ? protection.symm_alg : DEFAULT_PGP_SYMM_ALG;
    pkt_.sec_protection.cipher_mode =
      protection.cipher_mode ? protection.cipher_mode : DEFAULT_PGP_CIPHER_MODE;
    pkt_.sec_protection.s2k.hash_alg =
      protection.hash_alg ? protection.hash_alg : DEFAULT_PGP_HASH_ALG;
    auto iter = protection.iterations;
    if (!iter) {
        iter = pgp_s2k_compute_iters(
          pkt_.sec_protection.s2k.hash_alg, DEFAULT_S2K_MSEC, DEFAULT_S2K_TUNE_MSEC);
    }
    pkt_.sec_protection.s2k.iterations = pgp_s2k_round_iterations(iter);
    if (!ownpkt) {
        /* decrypted is assumed to be temporary variable so we may modify it */
        decrypted.sec_protection = pkt_.sec_protection;
    }

    /* write the protected key to raw packet */
    return write_sec_rawpkt(decrypted, new_password);
}

bool
pgp_key_t::unprotect(const pgp_password_provider_t &password_provider)
{
    /* sanity check */
    if (!is_secret()) {
        RNP_LOG("Warning: this is not a secret key");
        return false;
    }
    /* already unprotected */
    if (!is_protected()) {
        return true;
    }
    /* simple case */
    if (!encrypted()) {
        pkt_.sec_protection.s2k.usage = PGP_S2KU_NONE;
        return write_sec_rawpkt(pkt_, "");
    }

    pgp_password_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.op = PGP_OP_UNPROTECT;
    ctx.key = this;

    pgp_key_pkt_t *decrypted_seckey = pgp_decrypt_seckey(this, &password_provider, &ctx);
    if (!decrypted_seckey) {
        return false;
    }
    decrypted_seckey->sec_protection.s2k.usage = PGP_S2KU_NONE;
    if (!write_sec_rawpkt(*decrypted_seckey, "")) {
        delete decrypted_seckey;
        return false;
    }
    pkt_ = std::move(*decrypted_seckey);
    /* current logic is that unprotected key should be additionally unlocked */
    forget_secret_key_fields(&pkt_.material);
    delete decrypted_seckey;
    return true;
}

void
pgp_key_t::write(pgp_dest_t &dst) const
{
    /* write key rawpacket */
    rawpkt_.write(dst);

    if (format == PGP_KEY_STORE_G10) {
        return;
    }

    /* write signatures on key */
    for (auto &sigid : keysigs_) {
        get_sig(sigid).rawpkt.write(dst);
    }

    /* write uids and their signatures */
    for (const auto &uid : uids_) {
        uid.rawpkt.write(dst);
        for (size_t idx = 0; idx < uid.sig_count(); idx++) {
            get_sig(uid.get_sig(idx)).rawpkt.write(dst);
        }
    }
}

void
pgp_key_t::write_xfer(pgp_dest_t &dst, const rnp_key_store_t *keyring) const
{
    write(dst);
    if (dst.werr) {
        RNP_LOG("Failed to export primary key");
        return;
    }

    if (!keyring) {
        return;
    }

    // Export subkeys
    for (auto &fp : subkey_fps_) {
        const pgp_key_t *subkey = rnp_key_store_get_key_by_fpr(keyring, fp);
        if (!subkey) {
            char fphex[PGP_FINGERPRINT_SIZE * 2 + 1] = {0};
            rnp::hex_encode(
              fp.fingerprint, fp.length, fphex, sizeof(fphex), rnp::HEX_LOWERCASE);
            RNP_LOG("Warning! Subkey %s not found.", fphex);
            continue;
        }
        subkey->write(dst);
        if (dst.werr) {
            RNP_LOG("Error occurred when exporting a subkey");
            return;
        }
    }
}

bool
pgp_key_t::write_autocrypt(pgp_dest_t &dst, pgp_key_t &sub, uint32_t uid)
{
    pgp_subsig_t *cert = latest_uid_selfcert(uid);
    if (!cert) {
        RNP_LOG("No valid uid certification");
        return false;
    }
    pgp_subsig_t *binding = sub.latest_binding();
    if (!binding) {
        RNP_LOG("No valid binding for subkey");
        return false;
    }
    /* write all or nothing */
    pgp_dest_t memdst = {};
    if (init_mem_dest(&memdst, NULL, 0)) {
        RNP_LOG("Allocation failed");
        return false;
    }

    bool res = false;
    try {
        if (is_secret()) {
            pgp_key_pkt_t pkt(pkt_, true);
            pkt.write(memdst);
        } else {
            pkt().write(memdst);
        }
        get_uid(uid).pkt.write(memdst);
        cert->sig.write(memdst);
        if (sub.is_secret()) {
            pgp_key_pkt_t pkt(sub.pkt(), true);
            pkt.write(memdst);
        } else {
            sub.pkt().write(memdst);
        }
        binding->sig.write(memdst);
        dst_write(&dst, mem_dest_get_memory(&memdst), memdst.writeb);
        res = !dst.werr;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
    }
    dst_close(&memdst, true);
    return res;
}

/* look only for primary userids */
#define PGP_UID_PRIMARY ((uint32_t) -2)
/* look for any uid, except PGP_UID_NONE) */
#define PGP_UID_ANY ((uint32_t) -3)

pgp_subsig_t *
pgp_key_t::latest_selfsig(uint32_t uid)
{
    uint32_t      latest = 0;
    pgp_subsig_t *res = NULL;

    for (auto &sigid : sigs_) {
        auto &sig = get_sig(sigid);
        if (!sig.valid()) {
            continue;
        }
        bool skip = false;
        switch (uid) {
        case PGP_UID_NONE:
            skip = (sig.uid != PGP_UID_NONE) || !is_direct_self(sig);
            break;
        case PGP_UID_PRIMARY: {
            pgp_sig_subpkt_t *subpkt = sig.sig.get_subpkt(PGP_SIG_SUBPKT_PRIMARY_USER_ID);
            skip = !is_self_cert(sig) || !subpkt || !subpkt->fields.primary_uid;
            break;
        }
        case PGP_UID_ANY:
            skip = !is_self_cert(sig) || (sig.uid == PGP_UID_NONE);
            break;
        default:
            skip = (sig.uid != uid) || !is_self_cert(sig);
            break;
        }
        if (skip) {
            continue;
        }

        uint32_t creation = sig.sig.creation();
        if (creation >= latest) {
            latest = creation;
            res = &sig;
        }
    }
    return res;
}

pgp_subsig_t *
pgp_key_t::latest_binding(bool validated)
{
    uint32_t      latest = 0;
    pgp_subsig_t *res = NULL;

    for (auto &sigid : sigs_) {
        auto &sig = get_sig(sigid);
        if (validated && !sig.valid()) {
            continue;
        }
        if (!is_binding(sig)) {
            continue;
        }

        uint32_t creation = sig.sig.creation();
        if (creation >= latest) {
            latest = creation;
            res = &sig;
        }
    }
    return res;
}

pgp_subsig_t *
pgp_key_t::latest_uid_selfcert(uint32_t uid)
{
    uint32_t      latest = 0;
    pgp_subsig_t *res = NULL;

    if (uid >= uids_.size()) {
        return NULL;
    }

    for (size_t idx = 0; idx < uids_[uid].sig_count(); idx++) {
        auto &sig = get_sig(uids_[uid].get_sig(idx));
        if (!sig.valid() || (sig.uid != uid)) {
            continue;
        }
        if (!is_self_cert(sig)) {
            continue;
        }

        uint32_t creation = sig.sig.creation();
        if (creation >= latest) {
            latest = creation;
            res = &sig;
        }
    }
    return res;
}

bool
pgp_key_t::is_signer(const pgp_subsig_t &sig) const
{
    /* if we have fingerprint let's check it */
    if (sig.sig.has_keyfp()) {
        return sig.sig.keyfp() == fp();
    }
    if (!sig.sig.has_keyid()) {
        return false;
    }
    return keyid() == sig.sig.keyid();
}

bool
pgp_key_t::expired_with(const pgp_subsig_t &sig) const
{
    /* key expiration: absence of subpkt or 0 means it never expires */
    uint64_t expiration = sig.sig.key_expiration();
    if (!expiration) {
        return false;
    }
    uint64_t now = time(NULL);
    return expiration + creation() < now;
}

bool
pgp_key_t::is_self_cert(const pgp_subsig_t &sig) const
{
    return is_primary() && sig.is_cert() && is_signer(sig);
}

bool
pgp_key_t::is_direct_self(const pgp_subsig_t &sig) const
{
    return is_primary() && (sig.sig.type() == PGP_SIG_DIRECT) && is_signer(sig);
}

bool
pgp_key_t::is_revocation(const pgp_subsig_t &sig) const
{
    return is_primary() ? (sig.sig.type() == PGP_SIG_REV_KEY) :
                          (sig.sig.type() == PGP_SIG_REV_SUBKEY);
}

bool
pgp_key_t::is_uid_revocation(const pgp_subsig_t &sig) const
{
    return is_primary() && (sig.sig.type() == PGP_SIG_REV_CERT);
}

bool
pgp_key_t::is_binding(const pgp_subsig_t &sig) const
{
    return is_subkey() && (sig.sig.type() == PGP_SIG_SUBKEY);
}

void
pgp_key_t::validate_sig(const pgp_key_t &key, pgp_subsig_t &sig) const
{
    sig.validity.reset();

    pgp_signature_info_t sinfo = {};
    sinfo.sig = &sig.sig;
    sinfo.signer = this;
    sinfo.signer_valid = true;
    if (key.is_self_cert(sig) || key.is_binding(sig)) {
        sinfo.ignore_expiry = true;
    }

    pgp_sig_type_t stype = sig.sig.type();
    switch (stype) {
    case PGP_SIG_BINARY:
    case PGP_SIG_TEXT:
    case PGP_SIG_STANDALONE:
    case PGP_SIG_PRIMARY:
        RNP_LOG("Invalid key signature type: %d", (int) stype);
        return;
    case PGP_CERT_GENERIC:
    case PGP_CERT_PERSONA:
    case PGP_CERT_CASUAL:
    case PGP_CERT_POSITIVE:
    case PGP_SIG_REV_CERT: {
        if (sig.uid >= key.uid_count()) {
            RNP_LOG("Userid not found");
            return;
        }
        signature_check_certification(&sinfo, &key.pkt(), &key.get_uid(sig.uid).pkt);
        break;
    }
    case PGP_SIG_SUBKEY:
        if (!is_signer(sig)) {
            RNP_LOG("Invalid subkey binding's signer.");
            return;
        }
        signature_check_binding(&sinfo, &this->pkt(), &key);
        break;
    case PGP_SIG_DIRECT:
    case PGP_SIG_REV_KEY:
        signature_check_direct(&sinfo, &key.pkt());
        break;
    case PGP_SIG_REV_SUBKEY:
        if (!is_signer(sig)) {
            RNP_LOG("Invalid subkey revocation's signer.");
            return;
        }
        signature_check_subkey_revocation(&sinfo, &this->pkt(), &key.pkt());
        break;
    default:
        RNP_LOG("Unsupported key signature type: %d", (int) stype);
        return;
    }

    sig.validity.validated = true;
    sig.validity.valid = sinfo.valid;
    /* revocation signature cannot expire */
    if ((stype != PGP_SIG_REV_KEY) && (stype != PGP_SIG_REV_SUBKEY) &&
        (stype != PGP_SIG_REV_CERT)) {
        sig.validity.expired = sinfo.expired;
    }
}

void
pgp_key_t::validate_self_signatures()
{
    for (auto &sigid : sigs_) {
        pgp_subsig_t &sig = get_sig(sigid);
        if (sig.validity.validated) {
            continue;
        }

        if (is_direct_self(sig) || is_self_cert(sig) || is_uid_revocation(sig) ||
            is_revocation(sig)) {
            validate_sig(*this, sig);
        }
    }
}

void
pgp_key_t::validate_self_signatures(pgp_key_t &primary)
{
    for (auto &sigid : sigs_) {
        pgp_subsig_t &sig = get_sig(sigid);
        if (sig.validity.validated) {
            continue;
        }

        if (is_binding(sig) || is_revocation(sig)) {
            primary.validate_sig(*this, sig);
        }
    }
}

void
pgp_key_t::validate_primary(rnp_key_store_t &keyring)
{
    /* validate signatures if needed */
    validate_self_signatures();

    /* consider public key as valid on this level if it is not expired and has at least one
     * valid self-signature (or it is secret), and is not revoked */
    validity_.reset();
    validity_.validated = true;
    bool has_cert = false;
    bool has_expired = false;
    /* check whether key is revoked */
    for (auto &sigid : sigs_) {
        pgp_subsig_t &sig = get_sig(sigid);
        if (!sig.valid()) {
            continue;
        }
        if (is_revocation(sig)) {
            return;
        }
    }
    /* if we have direct-key signature, then it has higher priority for expiration check */
    pgp_subsig_t *dirsig = latest_selfsig(PGP_UID_NONE);
    if (dirsig) {
        has_expired = expired_with(*dirsig);
        has_cert = !has_expired;
    }
    /* if we have primary uid and it is more restrictive, then use it as well */
    pgp_subsig_t *prisig = NULL;
    if (!has_expired && (prisig = latest_selfsig(PGP_UID_PRIMARY))) {
        has_expired = expired_with(*prisig);
        has_cert = !has_expired;
    }
    /* if we don't have direct-key sig and primary uid, use the latest self-cert */
    pgp_subsig_t *latest = NULL;
    if (!dirsig && !prisig && (latest = latest_selfsig(PGP_UID_ANY))) {
        has_expired = expired_with(*latest);
        has_cert = !has_expired;
    }

    /* we have at least one non-expiring key self-signature or secret key */
    if (has_cert || is_secret()) {
        validity_.valid = true;
        return;
    }
    /* we have valid self-signature which expires key */
    if (has_expired) {
        validity_.expired = true;
        return;
    }

    /* let's check whether key has at least one valid subkey binding */
    for (size_t i = 0; i < subkey_count(); i++) {
        pgp_key_t *sub = pgp_key_get_subkey(this, &keyring, i);
        if (!sub) {
            continue;
        }
        sub->validate_self_signatures(*this);
        pgp_subsig_t *sig = sub->latest_binding();
        if (!sig) {
            continue;
        }
        /* check whether subkey is expired - then do not mark key as valid */
        if (sub->expired_with(*sig)) {
            continue;
        }
        validity_.valid = true;
        return;
    }
}

void
pgp_key_t::validate_subkey(pgp_key_t *primary)
{
    /* consider subkey as valid on this level if it has valid primary key, has at least one
     * non-expired binding signature (or is secret), and is not revoked. */
    validity_.reset();
    validity_.validated = true;
    if (!primary || !primary->valid()) {
        return;
    }
    /* validate signatures if needed */
    validate_self_signatures(*primary);

    bool has_binding = false;
    bool has_expired = false;
    for (auto &sigid : sigs_) {
        pgp_subsig_t &sig = get_sig(sigid);
        if (!sig.valid()) {
            continue;
        }

        if (is_binding(sig) && !has_binding) {
            /* check whether subkey is expired */
            if (expired_with(sig)) {
                has_expired = true;
                continue;
            }
            has_binding = true;
        } else if (is_revocation(sig)) {
            return;
        }
    }
    validity_.valid = has_binding || (is_secret() && primary->is_secret());
    if (!validity_.valid) {
        validity_.expired = has_expired;
    }
}

void
pgp_key_t::validate(rnp_key_store_t &keyring)
{
    validity_.reset();
    if (!is_subkey()) {
        validate_primary(keyring);
    } else {
        pgp_key_t *primary = NULL;
        if (has_primary_fp()) {
            primary = rnp_key_store_get_key_by_fpr(&keyring, primary_fp());
        }
        validate_subkey(primary);
    }
}

void
pgp_key_t::revalidate(rnp_key_store_t &keyring)
{
    if (is_subkey()) {
        pgp_key_t *primary = rnp_key_store_get_primary_key(&keyring, this);
        if (primary) {
            primary->revalidate(keyring);
        } else {
            validate_subkey(NULL);
        }
        return;
    }

    validate(keyring);
    if (!refresh_data()) {
        RNP_LOG("Failed to refresh key data");
    }
    /* validate/re-validate all subkeys as well */
    for (auto &fp : subkey_fps_) {
        pgp_key_t *subkey = rnp_key_store_get_key_by_fpr(&keyring, fp);
        if (subkey) {
            subkey->validate_subkey(this);
            if (!subkey->refresh_data(this)) {
                RNP_LOG("Failed to refresh subkey data");
            }
        }
    }
}

void
pgp_key_t::mark_valid()
{
    validity_.mark_valid();
    for (size_t i = 0; i < sig_count(); i++) {
        get_sig(i).validity.mark_valid();
    }
}

bool
pgp_key_t::refresh_data()
{
    if (!is_primary()) {
        RNP_LOG("key must be primary");
        return false;
    }
    /* validate self-signatures if not done yet */
    validate_self_signatures();
    /* key expiration */
    expiration_ = 0;
    /* if we have direct-key signature, then it has higher priority */
    pgp_subsig_t *dirsig = latest_selfsig(PGP_UID_NONE);
    if (dirsig) {
        expiration_ = dirsig->sig.key_expiration();
    }
    /* if we have primary uid and it is more restrictive, then use it as well */
    pgp_subsig_t *prisig = latest_selfsig(PGP_UID_PRIMARY);
    if (prisig && prisig->sig.key_expiration() &&
        (!expiration_ || (prisig->sig.key_expiration() < expiration_))) {
        expiration_ = prisig->sig.key_expiration();
    }
    /* if we don't have direct-key sig and primary uid, use the latest self-cert */
    pgp_subsig_t *latest = latest_selfsig(PGP_UID_ANY);
    if (!dirsig && !prisig && latest) {
        expiration_ = latest->sig.key_expiration();
    }
    /* key flags: check in direct-key sig first, then primary uid, and then latest */
    if (dirsig && dirsig->sig.has_subpkt(PGP_SIG_SUBPKT_KEY_FLAGS)) {
        flags_ = dirsig->key_flags;
    } else if (prisig && prisig->sig.has_subpkt(PGP_SIG_SUBPKT_KEY_FLAGS)) {
        flags_ = prisig->key_flags;
    } else if (latest && latest->sig.has_subpkt(PGP_SIG_SUBPKT_KEY_FLAGS)) {
        flags_ = latest->key_flags;
    } else {
        flags_ = pgp_pk_alg_capabilities(alg());
    }
    /* revocation(s) */
    clear_revokes();
    for (size_t i = 0; i < sig_count(); i++) {
        pgp_subsig_t &sig = get_sig(i);
        if (!sig.valid()) {
            continue;
        }
        try {
            if (is_revocation(sig)) {
                if (revoked_) {
                    continue;
                }
                revoked_ = true;
                revocation_ = pgp_revoke_t(sig);
            } else if (is_uid_revocation(sig)) {
                if (sig.uid >= uid_count()) {
                    RNP_LOG("Invalid uid index");
                    continue;
                }
                pgp_userid_t &uid = get_uid(sig.uid);
                if (uid.revoked) {
                    continue;
                }
                uid.revoked = true;
                uid.revocation = pgp_revoke_t(sig);
            }
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return false;
        }
    }
    /* valid till */
    valid_till_ = valid_till_common(expired());
    /* userid validities */
    for (size_t i = 0; i < uid_count(); i++) {
        get_uid(i).valid = false;
    }
    for (size_t i = 0; i < sig_count(); i++) {
        pgp_subsig_t &sig = get_sig(i);
        /* if certification expires key then consider userid as expired too */
        if (!sig.valid() || !sig.is_cert() || !is_signer(sig) || sig.expired()) {
            continue;
        }
        if (sig.uid >= uid_count()) {
            continue;
        }
        get_uid(sig.uid).valid = true;
    }
    /* check whether uid is revoked */
    for (size_t i = 0; i < uid_count(); i++) {
        pgp_userid_t &uid = get_uid(i);
        if (uid.revoked) {
            uid.valid = false;
        }
    }
    /* primary userid: pick it only from valid ones */
    uid0_set_ = false;
    for (size_t i = 0; i < sig_count(); i++) {
        pgp_subsig_t &sig = get_sig(i);
        if (!sig.valid() || !sig.is_cert() || !is_signer(sig)) {
            continue;
        }
        if ((sig.uid >= uid_count()) || !get_uid(sig.uid).valid) {
            continue;
        }
        if (sig.sig.primary_uid()) {
            uid0_ = sig.uid;
            uid0_set_ = true;
            break;
        }
    }
    return true;
}

bool
pgp_key_t::refresh_data(pgp_key_t *primary)
{
    /* validate self-signatures if not done yet */
    if (primary) {
        validate_self_signatures(*primary);
    }
    pgp_subsig_t *sig = latest_binding(primary);
    /* subkey expiration */
    expiration_ = sig ? sig->sig.key_expiration() : 0;
    /* subkey flags */
    if (sig && sig->sig.has_subpkt(PGP_SIG_SUBPKT_KEY_FLAGS)) {
        flags_ = sig->key_flags;
    } else {
        flags_ = pgp_pk_alg_capabilities(alg());
    }
    /* revocation */
    clear_revokes();
    for (size_t i = 0; i < sig_count(); i++) {
        pgp_subsig_t &sig = get_sig(i);
        if (!sig.valid() || !is_revocation(sig)) {
            continue;
        }
        revoked_ = true;
        try {
            revocation_ = pgp_revoke_t(sig);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return false;
        }
        break;
    }
    /* valid till */
    if (primary) {
        valid_till_ =
          std::min(primary->valid_till(), valid_till_common(expired() || primary->expired()));
    } else {
        valid_till_ = valid_till_common(expired());
    }
    return true;
}

void
pgp_key_t::merge_validity(const pgp_validity_t &src)
{
    validity_.valid = validity_.valid && src.valid;
    /* We may safely leave validated status only if both merged keys are valid && validated.
     * Otherwise we'll need to revalidate. For instance, one validated but invalid key may add
     * revocation signature, or valid key may add certification to the invalid one. */
    validity_.validated = validity_.valid && validity_.validated && src.validated;
    /* if expired is true at least in one case then valid and validated are false */
    validity_.expired = false;
}

bool
pgp_key_t::merge(const pgp_key_t &src)
{
    if (is_subkey() || src.is_subkey()) {
        RNP_LOG("wrong key merge call");
        return false;
    }

    pgp_transferable_key_t dstkey;
    if (transferable_key_from_key(dstkey, *this)) {
        RNP_LOG("failed to get transferable key from dstkey");
        return false;
    }

    pgp_transferable_key_t srckey;
    if (transferable_key_from_key(srckey, src)) {
        RNP_LOG("failed to get transferable key from srckey");
        return false;
    }

    /* if src is secret key then merged key will become secret as well. */
    if (is_secret_key_pkt(srckey.key.tag) && !is_secret_key_pkt(dstkey.key.tag)) {
        pgp_key_pkt_t tmp = dstkey.key;
        dstkey.key = srckey.key;
        srckey.key = tmp;
        /* no subkey processing here - they are separated from the main key */
    }

    if (transferable_key_merge(dstkey, srckey)) {
        RNP_LOG("failed to merge transferable keys");
        return false;
    }

    pgp_key_t tmpkey;
    try {
        tmpkey = std::move(dstkey);
        for (auto &fp : subkey_fps()) {
            tmpkey.add_subkey_fp(fp);
        }
        for (auto &fp : src.subkey_fps()) {
            tmpkey.add_subkey_fp(fp);
        }
    } catch (const std::exception &e) {
        RNP_LOG("failed to process key/add subkey fps: %s", e.what());
        return false;
    }
    /* check whether key was unlocked and assign secret key data */
    if (is_secret() && !is_locked()) {
        /* we may do thing below only because key material is opaque structure without
         * pointers! */
        tmpkey.pkt().material = pkt().material;
    } else if (src.is_secret() && !src.is_locked()) {
        tmpkey.pkt().material = src.pkt().material;
    }
    /* copy validity status */
    tmpkey.validity_ = validity_;
    tmpkey.merge_validity(src.validity_);

    *this = std::move(tmpkey);
    return true;
}

bool
pgp_key_t::merge(const pgp_key_t &src, pgp_key_t *primary)
{
    if (!is_subkey() || !src.is_subkey()) {
        RNP_LOG("wrong subkey merge call");
        return false;
    }

    pgp_transferable_subkey_t dstkey;
    if (transferable_subkey_from_key(dstkey, *this)) {
        RNP_LOG("failed to get transferable key from dstkey");
        return false;
    }

    pgp_transferable_subkey_t srckey;
    if (transferable_subkey_from_key(srckey, src)) {
        RNP_LOG("failed to get transferable key from srckey");
        return false;
    }

    /* if src is secret key then merged key will become secret as well. */
    if (is_secret_key_pkt(srckey.subkey.tag) && !is_secret_key_pkt(dstkey.subkey.tag)) {
        pgp_key_pkt_t tmp = dstkey.subkey;
        dstkey.subkey = srckey.subkey;
        srckey.subkey = tmp;
    }

    if (transferable_subkey_merge(dstkey, srckey)) {
        RNP_LOG("failed to merge transferable subkeys");
        return false;
    }

    pgp_key_t tmpkey;
    try {
        tmpkey = pgp_key_t(dstkey, primary);
    } catch (const std::exception &e) {
        RNP_LOG("failed to process subkey: %s", e.what());
        return false;
    }

    /* check whether key was unlocked and assign secret key data */
    if (is_secret() && !is_locked()) {
        /* we may do thing below only because key material is opaque structure without
         * pointers! */
        tmpkey.pkt().material = pkt().material;
    } else if (src.is_secret() && !src.is_locked()) {
        tmpkey.pkt().material = src.pkt().material;
    }
    /* copy validity status */
    tmpkey.validity_ = validity_;
    tmpkey.merge_validity(src.validity_);

    *this = std::move(tmpkey);
    return true;
}

size_t
pgp_key_material_t::bits() const
{
    switch (alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return 8 * mpi_bytes(&rsa.n);
    case PGP_PKA_DSA:
        return 8 * mpi_bytes(&dsa.p);
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        return 8 * mpi_bytes(&eg.y);
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2: {
        // bn_num_bytes returns value <= curve order
        const ec_curve_desc_t *curve = get_curve_desc(ec.curve);
        return curve ? curve->bitlen : 0;
    }
    default:
        RNP_LOG("Unknown public key alg: %d", (int) alg);
        return 0;
    }
}

size_t
pgp_key_material_t::qbits() const
{
    if (alg != PGP_PKA_DSA) {
        return 0;
    }
    return 8 * mpi_bytes(&dsa.q);
}
