/*-
 * Copyright (c) 2017-2020, Ribose Inc.
 * All rights reserved.
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
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "crypto.h"
#include "crypto/common.h"
#include "pgp-key.h"
#include "defaults.h"
#include <assert.h>
#include <json_object.h>
#include <json.h>
#include <librekey/key_store_pgp.h>
#include <librepgp/stream-ctx.h>
#include <librepgp/stream-common.h>
#include <librepgp/stream-armor.h>
#include <librepgp/stream-parse.h>
#include <librepgp/stream-write.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-packet.h>
#include <librepgp/stream-key.h>
#include <librepgp/stream-dump.h>
#include <rnp/rnp.h>
#include <stdarg.h>
#include <stdlib.h>
#ifdef _MSC_VER
#include "uniwin.h"
#include <inttypes.h>
#else
#include <unistd.h>
#endif
#include <string.h>
#include <sys/stat.h>
#include <stdexcept>
#include "utils.h"
#include "json_utils.h"
#include "version.h"
#include "ffi-priv-types.h"
#include "file-utils.h"

#define FFI_LOG(ffi, ...)            \
    do {                             \
        FILE *fp = stderr;           \
        if (ffi && ffi->errs) {      \
            fp = ffi->errs;          \
        }                            \
        RNP_LOG_FD(fp, __VA_ARGS__); \
    } while (0)

static pgp_key_t *get_key_require_public(rnp_key_handle_t handle);
static pgp_key_t *get_key_prefer_public(rnp_key_handle_t handle);
static pgp_key_t *get_key_require_secret(rnp_key_handle_t handle);

static bool locator_to_str(const pgp_key_search_t *locator,
                           const char **           identifier_type,
                           char *                  identifier,
                           size_t                  identifier_size);

static bool rnp_password_cb_bounce(const pgp_password_ctx_t *ctx,
                                   char *                    password,
                                   size_t                    password_size,
                                   void *                    userdata_void);

static rnp_result_t rnp_dump_src_to_json(pgp_source_t *src, uint32_t flags, char **result);

static pgp_key_t *
find_key(rnp_ffi_t               ffi,
         const pgp_key_search_t *search,
         key_type_t              key_type,
         bool                    try_key_provider)
{
    pgp_key_t *key = NULL;

    switch (key_type) {
    case KEY_TYPE_PUBLIC:
        key = rnp_key_store_search(ffi->pubring, search, NULL);
        break;
    case KEY_TYPE_SECRET:
        key = rnp_key_store_search(ffi->secring, search, NULL);
        break;
    default:
        assert(false);
        break;
    }
    if (!key && ffi->getkeycb && try_key_provider) {
        char        identifier[1 + MAX(MAX(MAX(PGP_KEY_ID_SIZE * 2, PGP_KEY_GRIP_SIZE),
                                    PGP_FINGERPRINT_SIZE * 2),
                                MAX_ID_LENGTH)];
        const char *identifier_type = NULL;

        if (locator_to_str(search, &identifier_type, identifier, sizeof(identifier))) {
            ffi->getkeycb(ffi,
                          ffi->getkeycb_ctx,
                          identifier_type,
                          identifier,
                          key_type == KEY_TYPE_SECRET);
            // recurse and try the store search above once more
            return find_key(ffi, search, key_type, false);
        }
    }
    return key;
}

static pgp_key_t *
ffi_key_provider(const pgp_key_request_ctx_t *ctx, void *userdata)
{
    rnp_ffi_t ffi = (rnp_ffi_t) userdata;
    return find_key(ffi, &ctx->search, ctx->secret ? KEY_TYPE_SECRET : KEY_TYPE_PUBLIC, true);
}

static void
rnp_ctx_init_ffi(rnp_ctx_t &ctx, rnp_ffi_t ffi)
{
    ctx.rng = &ffi->rng;
    ctx.ealg = DEFAULT_PGP_SYMM_ALG;
}

static const pgp_map_t sig_type_map[] = {{PGP_SIG_BINARY, "binary"},
                                         {PGP_SIG_TEXT, "text"},
                                         {PGP_SIG_STANDALONE, "standalone"},
                                         {PGP_CERT_GENERIC, "certification (generic)"},
                                         {PGP_CERT_PERSONA, "certification (persona)"},
                                         {PGP_CERT_CASUAL, "certification (casual)"},
                                         {PGP_CERT_POSITIVE, "certification (positive)"},
                                         {PGP_SIG_SUBKEY, "subkey binding"},
                                         {PGP_SIG_PRIMARY, "primary key binding"},
                                         {PGP_SIG_DIRECT, "direct"},
                                         {PGP_SIG_REV_KEY, "key revocation"},
                                         {PGP_SIG_REV_SUBKEY, "subkey revocation"},
                                         {PGP_SIG_REV_CERT, "certification revocation"},
                                         {PGP_SIG_TIMESTAMP, "timestamp"},
                                         {PGP_SIG_3RD_PARTY, "third-party"}};

static const pgp_map_t pubkey_alg_map[] = {
  {PGP_PKA_RSA, RNP_ALGNAME_RSA},
  {PGP_PKA_RSA_ENCRYPT_ONLY, RNP_ALGNAME_RSA},
  {PGP_PKA_RSA_SIGN_ONLY, RNP_ALGNAME_RSA},
  {PGP_PKA_ELGAMAL, RNP_ALGNAME_ELGAMAL},
  {PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN, RNP_ALGNAME_ELGAMAL},
  {PGP_PKA_DSA, RNP_ALGNAME_DSA},
  {PGP_PKA_ECDH, RNP_ALGNAME_ECDH},
  {PGP_PKA_ECDSA, RNP_ALGNAME_ECDSA},
  {PGP_PKA_EDDSA, RNP_ALGNAME_EDDSA},
  {PGP_PKA_SM2, RNP_ALGNAME_SM2}};

static const pgp_map_t symm_alg_map[] = {{PGP_SA_IDEA, RNP_ALGNAME_IDEA},
                                         {PGP_SA_TRIPLEDES, RNP_ALGNAME_TRIPLEDES},
                                         {PGP_SA_CAST5, RNP_ALGNAME_CAST5},
                                         {PGP_SA_BLOWFISH, RNP_ALGNAME_BLOWFISH},
                                         {PGP_SA_AES_128, RNP_ALGNAME_AES_128},
                                         {PGP_SA_AES_192, RNP_ALGNAME_AES_192},
                                         {PGP_SA_AES_256, RNP_ALGNAME_AES_256},
                                         {PGP_SA_TWOFISH, RNP_ALGNAME_TWOFISH},
                                         {PGP_SA_CAMELLIA_128, RNP_ALGNAME_CAMELLIA_128},
                                         {PGP_SA_CAMELLIA_192, RNP_ALGNAME_CAMELLIA_192},
                                         {PGP_SA_CAMELLIA_256, RNP_ALGNAME_CAMELLIA_256},
                                         {PGP_SA_SM4, RNP_ALGNAME_SM4}};

static const pgp_map_t aead_alg_map[] = {
  {PGP_AEAD_NONE, "None"}, {PGP_AEAD_EAX, "EAX"}, {PGP_AEAD_OCB, "OCB"}};

static const pgp_map_t cipher_mode_map[] = {
  {PGP_CIPHER_MODE_CFB, "CFB"}, {PGP_CIPHER_MODE_CBC, "CBC"}, {PGP_CIPHER_MODE_OCB, "OCB"}};

static const pgp_map_t compress_alg_map[] = {{PGP_C_NONE, "Uncompressed"},
                                             {PGP_C_ZIP, "ZIP"},
                                             {PGP_C_ZLIB, "ZLIB"},
                                             {PGP_C_BZIP2, "BZip2"}};

static const pgp_map_t hash_alg_map[] = {{PGP_HASH_MD5, RNP_ALGNAME_MD5},
                                         {PGP_HASH_SHA1, RNP_ALGNAME_SHA1},
                                         {PGP_HASH_RIPEMD, RNP_ALGNAME_RIPEMD160},
                                         {PGP_HASH_SHA256, RNP_ALGNAME_SHA256},
                                         {PGP_HASH_SHA384, RNP_ALGNAME_SHA384},
                                         {PGP_HASH_SHA512, RNP_ALGNAME_SHA512},
                                         {PGP_HASH_SHA224, RNP_ALGNAME_SHA224},
                                         {PGP_HASH_SHA3_256, RNP_ALGNAME_SHA3_256},
                                         {PGP_HASH_SHA3_512, RNP_ALGNAME_SHA3_512},
                                         {PGP_HASH_SM3, RNP_ALGNAME_SM3}};

static const pgp_map_t s2k_type_map[] = {
  {PGP_S2KS_SIMPLE, "Simple"},
  {PGP_S2KS_SALTED, "Salted"},
  {PGP_S2KS_ITERATED_AND_SALTED, "Iterated and salted"}};

static const pgp_bit_map_t key_usage_map[] = {{PGP_KF_SIGN, "sign"},
                                              {PGP_KF_CERTIFY, "certify"},
                                              {PGP_KF_ENCRYPT, "encrypt"},
                                              {PGP_KF_AUTH, "authenticate"}};

static const pgp_bit_map_t key_flags_map[] = {{PGP_KF_SPLIT, "split"},
                                              {PGP_KF_SHARED, "shared"}};

static const pgp_map_t identifier_type_map[] = {{PGP_KEY_SEARCH_USERID, "userid"},
                                                {PGP_KEY_SEARCH_KEYID, "keyid"},
                                                {PGP_KEY_SEARCH_FINGERPRINT, "fingerprint"},
                                                {PGP_KEY_SEARCH_GRIP, "grip"}};

static const pgp_map_t key_server_prefs_map[] = {{PGP_KEY_SERVER_NO_MODIFY, "no-modify"}};

static const pgp_map_t armor_type_map[] = {{PGP_ARMORED_MESSAGE, "message"},
                                           {PGP_ARMORED_PUBLIC_KEY, "public key"},
                                           {PGP_ARMORED_SECRET_KEY, "secret key"},
                                           {PGP_ARMORED_SIGNATURE, "signature"},
                                           {PGP_ARMORED_CLEARTEXT, "cleartext"}};

static const pgp_map_t key_import_status_map[] = {
  {PGP_KEY_IMPORT_STATUS_UNKNOWN, "unknown"},
  {PGP_KEY_IMPORT_STATUS_UNCHANGED, "unchanged"},
  {PGP_KEY_IMPORT_STATUS_UPDATED, "updated"},
  {PGP_KEY_IMPORT_STATUS_NEW, "new"}};

static const pgp_map_t sig_import_status_map[] = {
  {PGP_SIG_IMPORT_STATUS_UNKNOWN, "unknown"},
  {PGP_SIG_IMPORT_STATUS_UNKNOWN_KEY, "unknown key"},
  {PGP_SIG_IMPORT_STATUS_UNCHANGED, "unchanged"},
  {PGP_SIG_IMPORT_STATUS_NEW, "new"}};

static const pgp_map_t revocation_code_map[] = {
  {PGP_REVOCATION_NO_REASON, "no"},
  {PGP_REVOCATION_SUPERSEDED, "superseded"},
  {PGP_REVOCATION_COMPROMISED, "compromised"},
  {PGP_REVOCATION_RETIRED, "retired"},
  {PGP_REVOCATION_NO_LONGER_VALID, "no longer valid"}};

static bool
curve_str_to_type(const char *str, pgp_curve_t *value)
{
    *value = find_curve_by_name(str);
    return *value != PGP_CURVE_MAX;
}

static bool
curve_type_to_str(pgp_curve_t type, const char **str)
{
    const ec_curve_desc_t *desc = get_curve_desc(type);
    if (!desc) {
        return false;
    }
    *str = desc->pgp_name;
    return true;
}

static bool
str_to_cipher(const char *str, pgp_symm_alg_t *cipher)
{
    pgp_symm_alg_t alg = PGP_SA_UNKNOWN;
    ARRAY_LOOKUP_BY_STRCASE(symm_alg_map, string, type, str, alg);
    if (alg == PGP_SA_UNKNOWN) {
        return false;
    }

    *cipher = alg;
    return true;
}

static bool
str_to_hash_alg(const char *str, pgp_hash_alg_t *hash_alg)
{
    pgp_hash_alg_t alg = PGP_HASH_UNKNOWN;
    ARRAY_LOOKUP_BY_STRCASE(hash_alg_map, string, type, str, alg);
    if (alg == PGP_HASH_UNKNOWN) {
        return false;
    }

    *hash_alg = alg;
    return true;
}

static bool
str_to_aead_alg(const char *str, pgp_aead_alg_t *aead_alg)
{
    pgp_aead_alg_t alg = PGP_AEAD_UNKNOWN;
    ARRAY_LOOKUP_BY_STRCASE(aead_alg_map, string, type, str, alg);
    if (alg == PGP_AEAD_UNKNOWN) {
        return false;
    }

    *aead_alg = alg;
    return true;
}

static bool
str_to_compression_alg(const char *str, pgp_compression_type_t *zalg)
{
    pgp_compression_type_t alg = PGP_C_UNKNOWN;
    ARRAY_LOOKUP_BY_STRCASE(compress_alg_map, string, type, str, alg);
    if (alg == PGP_C_UNKNOWN) {
        return false;
    }
    *zalg = alg;
    return true;
}

static bool
str_to_revocation_type(const char *str, pgp_revocation_type_t *code)
{
    pgp_revocation_type_t rev = PGP_REVOCATION_NO_REASON;
    ARRAY_LOOKUP_BY_STRCASE(revocation_code_map, string, type, str, rev);
    if ((rev == PGP_REVOCATION_NO_REASON) && rnp_strcasecmp(str, "no")) {
        return false;
    }
    *code = rev;
    return true;
}

static bool
str_to_cipher_mode(const char *str, pgp_cipher_mode_t *mode)
{
    pgp_cipher_mode_t c_mode = PGP_CIPHER_MODE_NONE;
    ARRAY_LOOKUP_BY_STRCASE(cipher_mode_map, string, type, str, c_mode);
    if (c_mode == PGP_CIPHER_MODE_NONE) {
        return false;
    }

    *mode = c_mode;
    return true;
}

static bool
str_to_pubkey_alg(const char *str, pgp_pubkey_alg_t *pub_alg)
{
    pgp_pubkey_alg_t alg = PGP_PKA_NOTHING;
    ARRAY_LOOKUP_BY_STRCASE(pubkey_alg_map, string, type, str, alg);
    if (alg == PGP_PKA_NOTHING) {
        return false;
    }

    *pub_alg = alg;
    return true;
}

static bool
str_to_key_flag(const char *str, uint8_t *flag)
{
    uint8_t _flag = 0;
    ARRAY_LOOKUP_BY_STRCASE(key_usage_map, string, mask, str, _flag);
    if (!_flag) {
        return false;
    }
    *flag = _flag;
    return true;
}

static bool
parse_ks_format(pgp_key_store_format_t *key_store_format, const char *format)
{
    if (!strcmp(format, RNP_KEYSTORE_GPG)) {
        *key_store_format = PGP_KEY_STORE_GPG;
    } else if (!strcmp(format, RNP_KEYSTORE_KBX)) {
        *key_store_format = PGP_KEY_STORE_KBX;
    } else if (!strcmp(format, RNP_KEYSTORE_G10)) {
        *key_store_format = PGP_KEY_STORE_G10;
    } else {
        return false;
    }
    return true;
}

static rnp_result_t
hex_encode_value(const uint8_t *   value,
                 size_t            len,
                 char **           res,
                 rnp::hex_format_t format = rnp::HEX_UPPERCASE)
{
    size_t hex_len = len * 2 + 1;
    *res = (char *) malloc(hex_len);
    if (!*res) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!rnp::hex_encode(value, len, *res, hex_len, format)) {
        free(*res);
        *res = NULL;
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
get_map_value(const pgp_map_t *map, size_t msize, int val, char **res)
{
    const char *str = NULL;
    for (size_t i = 0; i < msize; i++) {
        if (map[i].type == val) {
            str = map[i].string;
            break;
        }
    }
    if (!str) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    char *strcp = strdup(str);
    if (!strcp) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    *res = strcp;
    return RNP_SUCCESS;
}

static rnp_result_t
ret_str_value(const char *str, char **res)
{
    if (!str) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    char *strcp = strdup(str);
    if (!strcp) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    *res = strcp;
    return RNP_SUCCESS;
}

static uint32_t
ffi_exception(FILE *fp, const char *func, const char *msg, uint32_t ret = RNP_ERROR_GENERIC)
{
    if (rnp_log_switch()) {
        fprintf(
          fp, "[%s()] Error 0x%08X (%s): %s\n", func, ret, rnp_result_to_string(ret), msg);
    }
    return ret;
}

#define FFI_GUARD_FP(fp)                                                            \
    catch (rnp::rnp_exception & e)                                                  \
    {                                                                               \
        return ffi_exception((fp), __func__, e.what(), e.code());                   \
    }                                                                               \
    catch (std::bad_alloc &)                                                        \
    {                                                                               \
        return ffi_exception((fp), __func__, "bad_alloc", RNP_ERROR_OUT_OF_MEMORY); \
    }                                                                               \
    catch (std::exception & e)                                                      \
    {                                                                               \
        return ffi_exception((fp), __func__, e.what());                             \
    }                                                                               \
    catch (...)                                                                     \
    {                                                                               \
        return ffi_exception((fp), __func__, "unknown exception");                  \
    }

#define FFI_GUARD FFI_GUARD_FP((stderr))

rnp_result_t
rnp_ffi_create(rnp_ffi_t *ffi, const char *pub_format, const char *sec_format)
try {
    struct rnp_ffi_st *ob = NULL;
    rnp_result_t       ret = RNP_ERROR_GENERIC;

    // checks
    if (!ffi || !pub_format || !sec_format) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_store_format_t pub_ks_format = PGP_KEY_STORE_UNKNOWN;
    pgp_key_store_format_t sec_ks_format = PGP_KEY_STORE_UNKNOWN;
    if (!parse_ks_format(&pub_ks_format, pub_format) ||
        !parse_ks_format(&sec_ks_format, sec_format)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    ob = (rnp_ffi_st *) calloc(1, sizeof(struct rnp_ffi_st));
    if (!ob) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // default to all stderr
    ob->errs = stderr;
    try {
        ob->pubring = new rnp_key_store_t(pub_ks_format, "");
        ob->secring = new rnp_key_store_t(sec_ks_format, "");
    } catch (const std::exception &e) {
        FFI_LOG(ob, "%s", e.what());
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    ob->key_provider.callback = ffi_key_provider;
    ob->key_provider.userdata = ob;
    ob->pass_provider.callback = rnp_password_cb_bounce;
    ob->pass_provider.userdata = ob;
    if (!rng_init(&ob->rng, RNG_DRBG)) {
        ret = RNP_ERROR_RNG;
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    if (ret) {
        rnp_ffi_destroy(ob);
        ob = NULL;
    }
    *ffi = ob;
    return ret;
}
FFI_GUARD

static bool
is_std_file(FILE *fp)
{
    return fp == stdout || fp == stderr;
}

static void
close_io_file(FILE **fp)
{
    if (*fp && !is_std_file(*fp)) {
        fclose(*fp);
    }
    *fp = NULL;
}

rnp_result_t
rnp_ffi_destroy(rnp_ffi_t ffi)
try {
    if (ffi) {
        close_io_file(&ffi->errs);
        delete ffi->pubring;
        delete ffi->secring;
        rng_destroy(&ffi->rng);
        free(ffi);
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_ffi_set_log_fd(rnp_ffi_t ffi, int fd)
try {
    FILE *errs = NULL;

    // checks
    if (!ffi) {
        return RNP_ERROR_NULL_POINTER;
    }

    // open
    errs = fdopen(fd, "a");
    if (!errs) {
        close_io_file(&errs);
        return RNP_ERROR_ACCESS;
    }
    // close previous streams and replace them
    close_io_file(&ffi->errs);
    ffi->errs = errs;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_ffi_set_key_provider(rnp_ffi_t ffi, rnp_get_key_cb getkeycb, void *getkeycb_ctx)
try {
    if (!ffi) {
        return RNP_ERROR_NULL_POINTER;
    }
    ffi->getkeycb = getkeycb;
    ffi->getkeycb_ctx = getkeycb_ctx;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_ffi_set_pass_provider(rnp_ffi_t ffi, rnp_password_cb getpasscb, void *getpasscb_ctx)
try {
    if (!ffi) {
        return RNP_ERROR_NULL_POINTER;
    }
    ffi->getpasscb = getpasscb;
    ffi->getpasscb_ctx = getpasscb_ctx;
    return RNP_SUCCESS;
}
FFI_GUARD

static const char *
operation_description(uint8_t op)
{
    switch (op) {
    case PGP_OP_ADD_SUBKEY:
        return "add subkey";
    case PGP_OP_ADD_USERID:
        return "add userid";
    case PGP_OP_SIGN:
        return "sign";
    case PGP_OP_DECRYPT:
        return "decrypt";
    case PGP_OP_UNLOCK:
        return "unlock";
    case PGP_OP_PROTECT:
        return "protect";
    case PGP_OP_UNPROTECT:
        return "unprotect";
    case PGP_OP_DECRYPT_SYM:
        return "decrypt (symmetric)";
    case PGP_OP_ENCRYPT_SYM:
        return "encrypt (symmetric)";
    default:
        return "unknown";
    }
}

static bool
rnp_password_cb_bounce(const pgp_password_ctx_t *ctx,
                       char *                    password,
                       size_t                    password_size,
                       void *                    userdata_void)
{
    rnp_ffi_t ffi = (rnp_ffi_t) userdata_void;

    if (!ffi || !ffi->getpasscb) {
        return false;
    }

    struct rnp_key_handle_st key = {};
    key.ffi = ffi;
    key.sec = (pgp_key_t *) ctx->key;
    return ffi->getpasscb(ffi,
                          ffi->getpasscb_ctx,
                          ctx->key ? &key : NULL,
                          operation_description(ctx->op),
                          password,
                          password_size);
}

const char *
rnp_result_to_string(rnp_result_t result)
{
    switch (result) {
    case RNP_SUCCESS:
        return "Success";

    case RNP_ERROR_GENERIC:
        return "Unknown error";
    case RNP_ERROR_BAD_FORMAT:
        return "Bad format";
    case RNP_ERROR_BAD_PARAMETERS:
        return "Bad parameters";
    case RNP_ERROR_NOT_IMPLEMENTED:
        return "Not implemented";
    case RNP_ERROR_NOT_SUPPORTED:
        return "Not supported";
    case RNP_ERROR_OUT_OF_MEMORY:
        return "Out of memory";
    case RNP_ERROR_SHORT_BUFFER:
        return "Buffer too short";
    case RNP_ERROR_NULL_POINTER:
        return "Null pointer";

    case RNP_ERROR_ACCESS:
        return "Error accessing file";
    case RNP_ERROR_READ:
        return "Error reading file";
    case RNP_ERROR_WRITE:
        return "Error writing file";

    case RNP_ERROR_BAD_STATE:
        return "Bad state";
    case RNP_ERROR_MAC_INVALID:
        return "Invalid MAC";
    case RNP_ERROR_SIGNATURE_INVALID:
        return "Invalid signature";
    case RNP_ERROR_KEY_GENERATION:
        return "Error during key generation";
    case RNP_ERROR_BAD_PASSWORD:
        return "Bad password";
    case RNP_ERROR_KEY_NOT_FOUND:
        return "Key not found";
    case RNP_ERROR_NO_SUITABLE_KEY:
        return "No suitable key";
    case RNP_ERROR_DECRYPT_FAILED:
        return "Decryption failed";
    case RNP_ERROR_NO_SIGNATURES_FOUND:
        return "No signatures found cannot verify";

    case RNP_ERROR_NOT_ENOUGH_DATA:
        return "Not enough data";
    case RNP_ERROR_UNKNOWN_TAG:
        return "Unknown tag";
    case RNP_ERROR_PACKET_NOT_CONSUMED:
        return "Packet not consumed";
    case RNP_ERROR_NO_USERID:
        return "No userid";
    case RNP_ERROR_EOF:
        return "EOF detected";
    }

    return "Unknown error";
}

const char *
rnp_version_string()
{
    return RNP_VERSION_STRING;
}

const char *
rnp_version_string_full()
{
    return RNP_VERSION_STRING_FULL;
}

uint32_t
rnp_version()
{
    return RNP_VERSION_CODE;
}

uint32_t
rnp_version_for(uint32_t major, uint32_t minor, uint32_t patch)
{
    if (major > RNP_VERSION_COMPONENT_MASK || minor > RNP_VERSION_COMPONENT_MASK ||
        patch > RNP_VERSION_COMPONENT_MASK) {
        RNP_LOG("invalid version, out of range: %d.%d.%d", major, minor, patch);
        return 0;
    }
    return RNP_VERSION_CODE_FOR(major, minor, patch);
}

uint32_t
rnp_version_major(uint32_t version)
{
    return (version >> RNP_VERSION_MAJOR_SHIFT) & RNP_VERSION_COMPONENT_MASK;
}

uint32_t
rnp_version_minor(uint32_t version)
{
    return (version >> RNP_VERSION_MINOR_SHIFT) & RNP_VERSION_COMPONENT_MASK;
}

uint32_t
rnp_version_patch(uint32_t version)
{
    return (version >> RNP_VERSION_PATCH_SHIFT) & RNP_VERSION_COMPONENT_MASK;
}

uint64_t
rnp_version_commit_timestamp()
{
    return RNP_VERSION_COMMIT_TIMESTAMP;
}

rnp_result_t
rnp_enable_debug(const char *file)
try {
    return rnp_set_debug(file) ? RNP_SUCCESS : RNP_ERROR_GENERIC;
}
FFI_GUARD

rnp_result_t
rnp_disable_debug()
try {
    rnp_clear_debug();
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_get_default_homedir(char **homedir)
try {
    // checks
    if (!homedir) {
        return RNP_ERROR_NULL_POINTER;
    }

    // get the users home dir
    char *home = getenv("HOME");
    if (!home) {
        return RNP_ERROR_NOT_SUPPORTED;
    }
    if (!rnp_compose_path_ex(homedir, NULL, home, ".rnp", NULL)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_detect_homedir_info(
  const char *homedir, char **pub_format, char **pub_path, char **sec_format, char **sec_path)
try {
    rnp_result_t ret = RNP_ERROR_GENERIC;
    char *       path = NULL;
    size_t       path_size = 0;

    // checks
    if (!homedir || !pub_format || !pub_path || !sec_format || !sec_path) {
        return RNP_ERROR_NULL_POINTER;
    }

    // we only support the common cases of GPG+GPG or GPG+G10, we don't
    // support unused combinations like KBX+KBX

    *pub_format = NULL;
    *pub_path = NULL;
    *sec_format = NULL;
    *sec_path = NULL;

    const char *pub_format_guess = NULL;
    const char *pub_path_guess = NULL;
    const char *sec_format_guess = NULL;
    const char *sec_path_guess = NULL;
    // check for pubring.kbx file
    if (!rnp_compose_path_ex(&path, &path_size, homedir, "pubring.kbx", NULL)) {
        goto done;
    }
    if (rnp_file_exists(path)) {
        // we have a pubring.kbx, now check for private-keys-v1.d dir
        if (!rnp_compose_path_ex(&path, &path_size, homedir, "private-keys-v1.d", NULL)) {
            goto done;
        }
        if (rnp_dir_exists(path)) {
            pub_format_guess = "KBX";
            pub_path_guess = "pubring.kbx";
            sec_format_guess = "G10";
            sec_path_guess = "private-keys-v1.d";
        }
    } else {
        // check for pubring.gpg
        if (!rnp_compose_path_ex(&path, &path_size, homedir, "pubring.gpg", NULL)) {
            goto done;
        }
        if (rnp_file_exists(path)) {
            // we have a pubring.gpg, now check for secring.gpg
            if (!rnp_compose_path_ex(&path, &path_size, homedir, "secring.gpg", NULL)) {
                goto done;
            }
            if (rnp_file_exists(path)) {
                pub_format_guess = "GPG";
                pub_path_guess = "pubring.gpg";
                sec_format_guess = "GPG";
                sec_path_guess = "secring.gpg";
            }
        }
    }

    // set our results
    if (pub_format_guess) {
        *pub_format = strdup(pub_format_guess);
        *pub_path = rnp_compose_path(homedir, pub_path_guess, NULL);
        if (!*pub_format || !*pub_path) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    }
    if (sec_format_guess) {
        *sec_format = strdup(sec_format_guess);
        *sec_path = rnp_compose_path(homedir, sec_path_guess, NULL);
        if (!*sec_format || !*sec_path) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    }
    // we leave the *formats as NULL if we were not able to determine the format
    // (but no error occurred)

    ret = RNP_SUCCESS;
done:
    if (ret) {
        free(*pub_format);
        *pub_format = NULL;
        free(*pub_path);
        *pub_path = NULL;

        free(*sec_format);
        *sec_format = NULL;
        free(*sec_path);
        *sec_path = NULL;
    }
    free(path);
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_detect_key_format(const uint8_t buf[], size_t buf_len, char **format)
try {
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!buf || !format) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!buf_len) {
        return RNP_ERROR_SHORT_BUFFER;
    }

    *format = NULL;
    // ordered from most reliable detection to least
    const char *guess = NULL;
    if (buf_len >= 12 && memcmp(buf + 8, "KBXf", 4) == 0) {
        // KBX has a magic KBXf marker
        guess = "KBX";
    } else if (buf_len >= 5 && memcmp(buf, "-----", 5) == 0) {
        // likely armored GPG
        guess = "GPG";
    } else if (buf[0] == '(') {
        // G10 is s-exprs and should start end end with parentheses
        guess = "G10";
    } else if (buf[0] & PGP_PTAG_ALWAYS_SET) {
        // this is harder to reliably determine, but could likely be improved
        guess = "GPG";
    }
    if (guess) {
        *format = strdup(guess);
        if (!*format) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    }

    // success
    ret = RNP_SUCCESS;
done:
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_calculate_iterations(const char *hash, size_t msec, size_t *iterations)
try {
    if (!hash || !iterations) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_hash_alg_t halg = PGP_HASH_UNKNOWN;
    if (!str_to_hash_alg(hash, &halg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    *iterations = pgp_s2k_compute_iters(halg, msec, 0);
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_supports_feature(const char *type, const char *name, bool *supported)
try {
    if (!type || !name || !supported) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!rnp_strcasecmp(type, RNP_FEATURE_SYMM_ALG)) {
        pgp_symm_alg_t alg = PGP_SA_UNKNOWN;
        *supported = str_to_cipher(name, &alg);
    } else if (!rnp_strcasecmp(type, RNP_FEATURE_AEAD_ALG)) {
        pgp_aead_alg_t alg = PGP_AEAD_UNKNOWN;
        *supported = str_to_aead_alg(name, &alg);
    } else if (!rnp_strcasecmp(type, RNP_FEATURE_PROT_MODE)) {
        // for now we support only CFB for key encryption
        *supported = rnp_strcasecmp(name, "CFB") == 0;
    } else if (!rnp_strcasecmp(type, RNP_FEATURE_PK_ALG)) {
        pgp_pubkey_alg_t alg = PGP_PKA_NOTHING;
        *supported = str_to_pubkey_alg(name, &alg);
    } else if (!rnp_strcasecmp(type, RNP_FEATURE_HASH_ALG)) {
        pgp_hash_alg_t alg = PGP_HASH_UNKNOWN;
        *supported = str_to_hash_alg(name, &alg);
    } else if (!rnp_strcasecmp(type, RNP_FEATURE_COMP_ALG)) {
        pgp_compression_type_t alg = PGP_C_UNKNOWN;
        *supported = str_to_compression_alg(name, &alg);
    } else if (!rnp_strcasecmp(type, RNP_FEATURE_CURVE)) {
        pgp_curve_t curve = PGP_CURVE_UNKNOWN;
        *supported = curve_str_to_type(name, &curve);
    } else {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

static rnp_result_t
json_array_add_map_str(json_object *arr, const pgp_map_t *map, int from, int to)
{
    while (map->string) {
        if (map->type < from) {
            map++;
            continue;
        }
        if (!array_add_element_json(arr, json_object_new_string(map->string))) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        if (map->type >= to) {
            break;
        }
        map++;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_supported_features(const char *type, char **result)
try {
    if (!type || !result) {
        return RNP_ERROR_NULL_POINTER;
    }

    json_object *features = json_object_new_array();
    if (!features) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    rnp_result_t ret = RNP_ERROR_BAD_PARAMETERS;

    if (!rnp_strcasecmp(type, RNP_FEATURE_SYMM_ALG)) {
        ret = json_array_add_map_str(features, symm_alg_map, PGP_SA_IDEA, PGP_SA_SM4);
    } else if (!rnp_strcasecmp(type, RNP_FEATURE_AEAD_ALG)) {
        ret = json_array_add_map_str(features, aead_alg_map, PGP_AEAD_EAX, PGP_AEAD_OCB);
    } else if (!rnp_strcasecmp(type, RNP_FEATURE_PROT_MODE)) {
        ret = json_array_add_map_str(
          features, cipher_mode_map, PGP_CIPHER_MODE_CFB, PGP_CIPHER_MODE_CFB);
    } else if (!rnp_strcasecmp(type, RNP_FEATURE_PK_ALG)) {
        // workaround to avoid duplicates, maybe there is a better solution
        (void) json_array_add_map_str(features, pubkey_alg_map, PGP_PKA_RSA, PGP_PKA_RSA);
        ret = json_array_add_map_str(features, pubkey_alg_map, PGP_PKA_DSA, PGP_PKA_SM2);
    } else if (!rnp_strcasecmp(type, RNP_FEATURE_HASH_ALG)) {
        ret = json_array_add_map_str(features, hash_alg_map, PGP_HASH_MD5, PGP_HASH_SM3);
    } else if (!rnp_strcasecmp(type, RNP_FEATURE_COMP_ALG)) {
        ret = json_array_add_map_str(features, compress_alg_map, PGP_C_NONE, PGP_C_BZIP2);
    } else if (!rnp_strcasecmp(type, RNP_FEATURE_CURVE)) {
        for (pgp_curve_t curve = PGP_CURVE_NIST_P_256; curve < PGP_CURVE_MAX;
             curve = (pgp_curve_t)(curve + 1)) {
            const ec_curve_desc_t *desc = get_curve_desc(curve);
            if (!desc) {
                ret = RNP_ERROR_BAD_STATE;
                goto done;
            }
            if (!array_add_element_json(features, json_object_new_string(desc->pgp_name))) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto done;
            }
        }
        ret = RNP_SUCCESS;
    }

    if (ret) {
        goto done;
    }

    *result = (char *) json_object_to_json_string_ext(features, JSON_C_TO_STRING_PRETTY);
    if (!*result) {
        ret = RNP_ERROR_BAD_STATE;
        goto done;
    }
    *result = strdup(*result);
    if (!*result) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
    }
done:
    json_object_put(features);
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_request_password(rnp_ffi_t ffi, rnp_key_handle_t key, const char *context, char **password)
{
    if (!ffi || !password || !ffi->getpasscb) {
        return RNP_ERROR_NULL_POINTER;
    }

    rnp::secure_vector<char> pass(MAX_PASSWORD_LENGTH, '\0');
    bool                     req_res =
      ffi->getpasscb(ffi, ffi->getpasscb_ctx, key, context, pass.data(), pass.size());
    if (!req_res) {
        return RNP_ERROR_GENERIC;
    }
    size_t pass_len = strlen(pass.data()) + 1;
    *password = (char *) malloc(pass_len);
    if (!*password) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    memcpy(*password, pass.data(), pass_len);
    return RNP_SUCCESS;
}

static rnp_result_t
load_keys_from_input(rnp_ffi_t ffi, rnp_input_t input, rnp_key_store_t *store)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    pgp_key_provider_t chained;
    chained.callback = rnp_key_provider_store;
    chained.userdata = store;

    const pgp_key_provider_t *key_providers[] = {&chained, &ffi->key_provider, NULL};

    const pgp_key_provider_t key_provider = {.callback = rnp_key_provider_chained,
                                             .userdata = key_providers};

    if (input->src_directory) {
        // load the keys
        try {
            store->path = input->src_directory;
        } catch (const std::exception &e) {
            FFI_LOG(ffi, "%s", e.what());
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        if (!rnp_key_store_load_from_path(store, &key_provider)) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }
    } else {
        // load the keys
        if (!rnp_key_store_load_from_src(store, &input->src, &key_provider)) {
            ret = RNP_ERROR_BAD_FORMAT;
            goto done;
        }
    }

    ret = RNP_SUCCESS;
done:
    return ret;
}

static bool
key_needs_conversion(const pgp_key_t *key, const rnp_key_store_t *store)
{
    pgp_key_store_format_t key_format = key->format;
    pgp_key_store_format_t store_format = store->format;
    /* pgp_key_t->format is only ever GPG or G10.
     *
     * The key store, however, could have a format of KBX, GPG, or G10.
     * A KBX (and GPG) key store can only handle a pgp_key_t with a format of GPG.
     * A G10 key store can only handle a pgp_key_t with a format of G10.
     */
    // should never be the case
    assert(key_format != PGP_KEY_STORE_KBX);
    // normalize the store format
    if (store_format == PGP_KEY_STORE_KBX) {
        store_format = PGP_KEY_STORE_GPG;
    }
    // from here, both the key and store formats can only be GPG or G10
    return key_format != store_format;
}

static rnp_result_t
do_load_keys(rnp_ffi_t              ffi,
             rnp_input_t            input,
             pgp_key_store_format_t format,
             key_type_t             key_type)
{
    rnp_result_t     ret = RNP_ERROR_GENERIC;
    rnp_key_store_t *tmp_store = NULL;
    pgp_key_t        keycp;
    rnp_result_t     tmpret;

    // create a temporary key store to hold the keys
    try {
        tmp_store = new rnp_key_store_t(format, "");
    } catch (const std::invalid_argument &e) {
        FFI_LOG(ffi, "Failed to create key store of format: %d", (int) format);
        return RNP_ERROR_BAD_PARAMETERS;
    } catch (const std::exception &e) {
        FFI_LOG(ffi, "%s", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    // load keys into our temporary store
    tmpret = load_keys_from_input(ffi, input, tmp_store);
    if (tmpret) {
        ret = tmpret;
        goto done;
    }
    // go through all the loaded keys
    for (auto &key : tmp_store->keys) {
        // check that the key is the correct type and has not already been loaded
        // add secret key part if it is and we need it
        if (key.is_secret() && ((key_type == KEY_TYPE_SECRET) || (key_type == KEY_TYPE_ANY))) {
            if (key_needs_conversion(&key, ffi->secring)) {
                FFI_LOG(ffi, "This key format conversion is not yet supported");
                ret = RNP_ERROR_NOT_IMPLEMENTED;
                goto done;
            }

            if (!rnp_key_store_add_key(ffi->secring, &key)) {
                FFI_LOG(ffi, "Failed to add secret key");
                ret = RNP_ERROR_GENERIC;
                goto done;
            }
        }

        // add public key part if needed
        if ((key.format == PGP_KEY_STORE_G10) ||
            ((key_type != KEY_TYPE_ANY) && (key_type != KEY_TYPE_PUBLIC))) {
            continue;
        }

        try {
            keycp = pgp_key_t(key, true);
        } catch (const std::exception &e) {
            RNP_LOG("Failed to copy public key part: %s", e.what());
            ret = RNP_ERROR_GENERIC;
            goto done;
        }

        /* TODO: We could do this a few different ways. There isn't an obvious reason
         * to restrict what formats we load, so we don't necessarily need to require a
         * conversion just to load and use a G10 key when using GPG keyrings, for
         * example. We could just convert when saving.
         */

        if (key_needs_conversion(&key, ffi->pubring)) {
            FFI_LOG(ffi, "This key format conversion is not yet supported");
            ret = RNP_ERROR_NOT_IMPLEMENTED;
            goto done;
        }

        if (!rnp_key_store_add_key(ffi->pubring, &keycp)) {
            FFI_LOG(ffi, "Failed to add public key");
            ret = RNP_ERROR_GENERIC;
            goto done;
        }
    }

    // success, even if we didn't actually load any
    ret = RNP_SUCCESS;
done:
    delete tmp_store;
    return ret;
}

static key_type_t
flags_to_key_type(uint32_t *flags)
{
    key_type_t type = KEY_TYPE_NONE;
    // figure out what type of keys to operate on, based on flags
    if ((*flags & RNP_LOAD_SAVE_PUBLIC_KEYS) && (*flags & RNP_LOAD_SAVE_SECRET_KEYS)) {
        type = KEY_TYPE_ANY;
        *flags &= ~(RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS);
    } else if (*flags & RNP_LOAD_SAVE_PUBLIC_KEYS) {
        type = KEY_TYPE_PUBLIC;
        *flags &= ~RNP_LOAD_SAVE_PUBLIC_KEYS;
    } else if (*flags & RNP_LOAD_SAVE_SECRET_KEYS) {
        type = KEY_TYPE_SECRET;
        *flags &= ~RNP_LOAD_SAVE_SECRET_KEYS;
    }
    return type;
}

rnp_result_t
rnp_load_keys(rnp_ffi_t ffi, const char *format, rnp_input_t input, uint32_t flags)
try {
    // checks
    if (!ffi || !format || !input) {
        return RNP_ERROR_NULL_POINTER;
    }
    key_type_t type = flags_to_key_type(&flags);
    if (!type) {
        FFI_LOG(ffi, "invalid flags - must have public and/or secret keys");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_key_store_format_t ks_format = PGP_KEY_STORE_UNKNOWN;
    if (!parse_ks_format(&ks_format, format)) {
        FFI_LOG(ffi, "invalid key store format: %s", format);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    // check for any unrecognized flags (not forward-compat, but maybe still a good idea)
    if (flags) {
        FFI_LOG(ffi, "unexpected flags remaining: 0x%X", flags);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return do_load_keys(ffi, input, ks_format, type);
}
FFI_GUARD

rnp_result_t
rnp_unload_keys(rnp_ffi_t ffi, uint32_t flags)
try {
    if (!ffi) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (flags & ~(RNP_KEY_UNLOAD_PUBLIC | RNP_KEY_UNLOAD_SECRET)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (flags & RNP_KEY_UNLOAD_PUBLIC) {
        rnp_key_store_clear(ffi->pubring);
    }
    if (flags & RNP_KEY_UNLOAD_SECRET) {
        rnp_key_store_clear(ffi->secring);
    }

    return RNP_SUCCESS;
}
FFI_GUARD

static rnp_result_t
rnp_input_dearmor_if_needed(rnp_input_t input)
{
    if (!input) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (input->src_directory) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    bool require_armor = false;
    /* check whether we already have armored stream */
    if (input->src.type == PGP_STREAM_ARMORED) {
        if (!src_eof(&input->src)) {
            return RNP_SUCCESS;
        }
        /* eof - probably next we have another armored message */
        src_close(&input->src);
        void *app_ctx = input->app_ctx;
        *input = *(rnp_input_t) app_ctx;
        free(app_ctx);
        /* we should not mix armored data with binary */
        require_armor = true;
    }
    if (src_eof(&input->src)) {
        return RNP_ERROR_EOF;
    }
    if (!is_armored_source(&input->src)) {
        return require_armor ? RNP_ERROR_BAD_FORMAT : RNP_SUCCESS;
    }

    rnp_input_t app_ctx = (rnp_input_t) calloc(1, sizeof(*input));
    if (!app_ctx) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    *app_ctx = *input;

    pgp_source_t armored;
    rnp_result_t ret = init_armored_src(&armored, &app_ctx->src);
    if (ret) {
        /* original src may be changed during init_armored_src call, so copy it back */
        input->src = app_ctx->src;
        free(app_ctx);
        return ret;
    }

    input->src = armored;
    input->app_ctx = app_ctx;
    return RNP_SUCCESS;
}

static const char *
key_status_to_str(pgp_key_import_status_t status)
{
    if (status == PGP_KEY_IMPORT_STATUS_UNKNOWN) {
        return "none";
    }
    const char *str = "none";
    ARRAY_LOOKUP_BY_ID(key_import_status_map, type, string, status, str);
    return str;
}

static rnp_result_t
add_key_status(json_object *           keys,
               const pgp_key_t *       key,
               pgp_key_import_status_t pub,
               pgp_key_import_status_t sec)
{
    json_object *jsokey = json_object_new_object();
    if (!jsokey) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (!obj_add_field_json(
          jsokey, "public", json_object_new_string(key_status_to_str(pub))) ||
        !obj_add_field_json(
          jsokey, "secret", json_object_new_string(key_status_to_str(sec))) ||
        !obj_add_hex_json(jsokey, "fingerprint", key->fp().fingerprint, key->fp().length) ||
        !array_add_element_json(keys, jsokey)) {
        json_object_put(jsokey);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    return RNP_SUCCESS;
}

rnp_result_t
rnp_import_keys(rnp_ffi_t ffi, rnp_input_t input, uint32_t flags, char **results)
try {
    if (!ffi || !input) {
        return RNP_ERROR_NULL_POINTER;
    }
    bool sec = false;
    bool pub = false;
    if (flags & RNP_LOAD_SAVE_SECRET_KEYS) {
        sec = true;
        flags &= ~RNP_LOAD_SAVE_SECRET_KEYS;
    }
    if (flags & RNP_LOAD_SAVE_PUBLIC_KEYS) {
        pub = true;
        flags &= ~RNP_LOAD_SAVE_PUBLIC_KEYS;
    }
    if (!pub && !sec) {
        FFI_LOG(ffi, "bad flags: need to specify public and/or secret keys");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    bool skipbad = false;
    if (flags & RNP_LOAD_SAVE_PERMISSIVE) {
        skipbad = true;
        flags &= ~RNP_LOAD_SAVE_PERMISSIVE;
    }
    bool single = false;
    if (flags & RNP_LOAD_SAVE_SINGLE) {
        single = true;
        flags &= ~RNP_LOAD_SAVE_SINGLE;
    }
    if (flags) {
        FFI_LOG(ffi, "unexpected flags remaining: 0x%X", flags);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t     ret = RNP_ERROR_GENERIC;
    rnp_key_store_t *tmp_store = NULL;
    rnp_result_t     tmpret;
    json_object *    jsores = NULL;
    json_object *    jsokeys = NULL;

    // load keys to temporary keystore.
    try {
        tmp_store = new rnp_key_store_t(PGP_KEY_STORE_GPG, "");
    } catch (const std::exception &e) {
        FFI_LOG(ffi, "Failed to create key store: %s.", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (single) {
        /* we need to init and handle dearmor on this layer since it may be used for the next
         * keys import */
        ret = rnp_input_dearmor_if_needed(input);
        if (ret == RNP_ERROR_EOF) {
            goto done;
        }
        if (ret) {
            FFI_LOG(ffi, "Failed to init/check dearmor.");
            goto done;
        }
        ret = rnp_key_store_pgp_read_key_from_src(*tmp_store, input->src, skipbad);
        if (ret) {
            goto done;
        }
    } else {
        ret = rnp_key_store_pgp_read_from_src(tmp_store, &input->src, skipbad);
        if (ret) {
            goto done;
        }
    }
    jsores = json_object_new_object();
    if (!jsores) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    jsokeys = json_object_new_array();
    if (!obj_add_field_json(jsores, "keys", jsokeys)) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    // import keys to the main keystore.
    for (auto &key : tmp_store->keys) {
        pgp_key_import_status_t pub_status = PGP_KEY_IMPORT_STATUS_UNKNOWN;
        pgp_key_import_status_t sec_status = PGP_KEY_IMPORT_STATUS_UNKNOWN;
        if (!pub && key.is_public()) {
            continue;
        }
        if (validate_pgp_key_material(&key.material(), &ffi->rng)) {
            char hex[PGP_KEY_ID_SIZE * 2 + 1] = {0};
            rnp::hex_encode(
              key.keyid().data(), key.keyid().size(), hex, sizeof(hex), rnp::HEX_LOWERCASE);
            FFI_LOG(ffi, "warning! attempt to import key %s with invalid material.", hex);
            continue;
        }
        // if we got here then we add public key itself or public part of the secret key
        if (!rnp_key_store_import_key(ffi->pubring, &key, true, &pub_status)) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }
        // import secret key part if available and requested
        if (sec && key.is_secret()) {
            if (!rnp_key_store_import_key(ffi->secring, &key, false, &sec_status)) {
                ret = RNP_ERROR_BAD_PARAMETERS;
                goto done;
            }
            // add uids, certifications and other stuff from the public key if any
            pgp_key_t *expub = rnp_key_store_get_key_by_fpr(ffi->pubring, key.fp());
            if (expub && !rnp_key_store_import_key(ffi->secring, expub, true, NULL)) {
                ret = RNP_ERROR_BAD_PARAMETERS;
                goto done;
            }
        }
        // now add key fingerprint to json based on statuses
        if ((tmpret = add_key_status(jsokeys, &key, pub_status, sec_status))) {
            ret = tmpret;
            goto done;
        }
    }

    if (results) {
        *results = (char *) json_object_to_json_string_ext(jsores, JSON_C_TO_STRING_PRETTY);
        if (!*results) {
            goto done;
        }
        *results = strdup(*results);
        if (!*results) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    }

    ret = RNP_SUCCESS;
done:
    delete tmp_store;
    json_object_put(jsores);
    return ret;
}
FFI_GUARD

static const char *
sig_status_to_str(pgp_sig_import_status_t status)
{
    if (status == PGP_SIG_IMPORT_STATUS_UNKNOWN) {
        return "none";
    }
    const char *str = "none";
    ARRAY_LOOKUP_BY_ID(sig_import_status_map, type, string, status, str);
    return str;
}

static rnp_result_t
add_sig_status(json_object *           sigs,
               const pgp_key_t *       signer,
               pgp_sig_import_status_t pub,
               pgp_sig_import_status_t sec)
{
    json_object *jsosig = json_object_new_object();
    if (!jsosig) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (!obj_add_field_json(
          jsosig, "public", json_object_new_string(sig_status_to_str(pub))) ||
        !obj_add_field_json(
          jsosig, "secret", json_object_new_string(sig_status_to_str(sec)))) {
        json_object_put(jsosig);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (signer) {
        const pgp_fingerprint_t &fp = signer->fp();
        if (!obj_add_hex_json(jsosig, "signer fingerprint", fp.fingerprint, fp.length)) {
            json_object_put(jsosig);
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }

    if (!array_add_element_json(sigs, jsosig)) {
        json_object_put(jsosig);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    return RNP_SUCCESS;
}

rnp_result_t
rnp_import_signatures(rnp_ffi_t ffi, rnp_input_t input, uint32_t flags, char **results)
try {
    if (!ffi || !input) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (flags) {
        FFI_LOG(ffi, "wrong flags: %d", (int) flags);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t         ret = RNP_ERROR_GENERIC;
    json_object *        jsores = NULL;
    json_object *        jsosigs = NULL;
    pgp_signature_list_t sigs;
    rnp_result_t         sigret = process_pgp_signatures(&input->src, sigs);
    if (sigret) {
        ret = sigret;
        FFI_LOG(ffi, "failed to parse signature(s)");
        goto done;
    }

    jsores = json_object_new_object();
    if (!jsores) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    jsosigs = json_object_new_array();
    if (!obj_add_field_json(jsores, "sigs", jsosigs)) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    for (auto &sig : sigs) {
        pgp_sig_import_status_t pub_status = PGP_SIG_IMPORT_STATUS_UNKNOWN;
        pgp_sig_import_status_t sec_status = PGP_SIG_IMPORT_STATUS_UNKNOWN;
        pgp_key_t *pkey = rnp_key_store_import_signature(ffi->pubring, &sig, &pub_status);
        pgp_key_t *skey = rnp_key_store_import_signature(ffi->secring, &sig, &sec_status);
        sigret = add_sig_status(jsosigs, pkey ? pkey : skey, pub_status, sec_status);
        if (sigret) {
            ret = sigret;
            goto done;
        }
    }

    if (results) {
        *results = (char *) json_object_to_json_string_ext(jsores, JSON_C_TO_STRING_PRETTY);
        if (!*results) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        *results = strdup(*results);
        if (!*results) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    }
    ret = RNP_SUCCESS;
done:
    json_object_put(jsores);
    return ret;
}
FFI_GUARD

static bool
copy_store_keys(rnp_ffi_t ffi, rnp_key_store_t *dest, rnp_key_store_t *src)
{
    for (auto &key : src->keys) {
        if (!rnp_key_store_add_key(dest, &key)) {
            FFI_LOG(ffi, "failed to add key to the store");
            return false;
        }
    }
    return true;
}

static rnp_result_t
do_save_keys(rnp_ffi_t              ffi,
             rnp_output_t           output,
             pgp_key_store_format_t format,
             key_type_t             key_type)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // create a temporary key store to hold the keys
    rnp_key_store_t *tmp_store = NULL;
    try {
        tmp_store = new rnp_key_store_t(format, "");
    } catch (const std::invalid_argument &e) {
        FFI_LOG(ffi, "Failed to create key store of format: %d", (int) format);
        return RNP_ERROR_BAD_PARAMETERS;
    } catch (const std::exception &e) {
        FFI_LOG(ffi, "%s", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // include the public keys, if desired
    if (key_type == KEY_TYPE_PUBLIC || key_type == KEY_TYPE_ANY) {
        if (!copy_store_keys(ffi, tmp_store, ffi->pubring)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    }
    // include the secret keys, if desired
    if (key_type == KEY_TYPE_SECRET || key_type == KEY_TYPE_ANY) {
        if (!copy_store_keys(ffi, tmp_store, ffi->secring)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    }
    // preliminary check on the format
    for (auto &key : tmp_store->keys) {
        if (key_needs_conversion(&key, tmp_store)) {
            FFI_LOG(ffi, "This key format conversion is not yet supported");
            ret = RNP_ERROR_NOT_IMPLEMENTED;
            goto done;
        }
    }
    // write
    if (output->dst_directory) {
        try {
            tmp_store->path = output->dst_directory;
        } catch (const std::exception &e) {
            FFI_LOG(ffi, "%s", e.what());
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        if (!rnp_key_store_write_to_path(tmp_store)) {
            ret = RNP_ERROR_WRITE;
            goto done;
        }
        ret = RNP_SUCCESS;
    } else {
        if (!rnp_key_store_write_to_dst(tmp_store, &output->dst)) {
            ret = RNP_ERROR_WRITE;
            goto done;
        }
        dst_flush(&output->dst);
        output->keep = (output->dst.werr == RNP_SUCCESS);
        ret = output->dst.werr;
    }

done:
    delete tmp_store;
    return ret;
}

rnp_result_t
rnp_save_keys(rnp_ffi_t ffi, const char *format, rnp_output_t output, uint32_t flags)
try {
    // checks
    if (!ffi || !format || !output) {
        return RNP_ERROR_NULL_POINTER;
    }
    key_type_t type = flags_to_key_type(&flags);
    if (!type) {
        FFI_LOG(ffi, "invalid flags - must have public and/or secret keys");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    // check for any unrecognized flags (not forward-compat, but maybe still a good idea)
    if (flags) {
        FFI_LOG(ffi, "unexpected flags remaining: 0x%X", flags);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_key_store_format_t ks_format = PGP_KEY_STORE_UNKNOWN;
    if (!parse_ks_format(&ks_format, format)) {
        FFI_LOG(ffi, "unknown key store format: %s", format);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return do_save_keys(ffi, output, ks_format, type);
}
FFI_GUARD

rnp_result_t
rnp_get_public_key_count(rnp_ffi_t ffi, size_t *count)
try {
    if (!ffi || !count) {
        return RNP_ERROR_NULL_POINTER;
    }
    *count = rnp_key_store_get_key_count(ffi->pubring);
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_get_secret_key_count(rnp_ffi_t ffi, size_t *count)
try {
    if (!ffi || !count) {
        return RNP_ERROR_NULL_POINTER;
    }
    *count = rnp_key_store_get_key_count(ffi->secring);
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_input_from_path(rnp_input_t *input, const char *path)
try {
    struct rnp_input_st *ob = NULL;
    struct stat          st = {0};

    if (!input || !path) {
        return RNP_ERROR_NULL_POINTER;
    }
    ob = (rnp_input_st *) calloc(1, sizeof(*ob));
    if (!ob) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (rnp_stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        // a bit hacky, just save the directory path
        ob->src_directory = strdup(path);
        if (!ob->src_directory) {
            free(ob);
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        // return error on attempt to read from this source
        (void) init_null_src(&ob->src);
    } else {
        // simple input from a file
        rnp_result_t ret = init_file_src(&ob->src, path);
        if (ret) {
            free(ob);
            return ret;
        }
    }
    *input = ob;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_input_from_memory(rnp_input_t *input, const uint8_t buf[], size_t buf_len, bool do_copy)
try {
    if (!input || !buf) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!buf_len) {
        return RNP_ERROR_SHORT_BUFFER;
    }
    *input = (rnp_input_t) calloc(1, sizeof(**input));
    if (!*input) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    uint8_t *data = (uint8_t *) buf;
    if (do_copy) {
        data = (uint8_t *) malloc(buf_len);
        if (!data) {
            free(*input);
            *input = NULL;
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        memcpy(data, buf, buf_len);
    }
    rnp_result_t ret = init_mem_src(&(*input)->src, data, buf_len, do_copy);
    if (ret) {
        if (do_copy) {
            free(data);
        }
        free(*input);
        *input = NULL;
        return ret;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

static bool
input_reader_bounce(pgp_source_t *src, void *buf, size_t len, size_t *read)
{
    rnp_input_t input = (rnp_input_t) src->param;
    if (!input->reader) {
        return false;
    }
    return input->reader(input->app_ctx, buf, len, read);
}

static void
input_closer_bounce(pgp_source_t *src)
{
    rnp_input_t input = (rnp_input_t) src->param;
    if (input->closer) {
        input->closer(input->app_ctx);
    }
}

rnp_result_t
rnp_input_from_callback(rnp_input_t *       input,
                        rnp_input_reader_t *reader,
                        rnp_input_closer_t *closer,
                        void *              app_ctx)
try {
    struct rnp_input_st *obj = NULL;

    // checks
    if (!input || !reader) {
        return RNP_ERROR_NULL_POINTER;
    }
    obj = (rnp_input_st *) calloc(1, sizeof(*obj));
    if (!obj) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    pgp_source_t *src = &obj->src;
    obj->reader = reader;
    obj->closer = closer;
    obj->app_ctx = app_ctx;
    if (!init_src_common(src, 0)) {
        free(obj);
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    src->param = obj;
    src->read = input_reader_bounce;
    src->close = input_closer_bounce;
    src->type = PGP_STREAM_MEMORY;
    *input = obj;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_input_destroy(rnp_input_t input)
try {
    if (input) {
        bool armored = input->src.type == PGP_STREAM_ARMORED;
        src_close(&input->src);
        if (armored) {
            rnp_input_destroy((rnp_input_t) input->app_ctx);
        }
        free(input->src_directory);
        free(input);
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_output_to_path(rnp_output_t *output, const char *path)
try {
    struct rnp_output_st *ob = NULL;
    struct stat           st = {0};

    if (!output || !path) {
        return RNP_ERROR_NULL_POINTER;
    }
    ob = (rnp_output_st *) calloc(1, sizeof(*ob));
    if (!ob) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (rnp_stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        // a bit hacky, just save the directory path
        ob->dst_directory = strdup(path);
        if (!ob->dst_directory) {
            free(ob);
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    } else {
        // simple output to a file
        rnp_result_t ret = init_file_dest(&ob->dst, path, true);
        if (ret) {
            free(ob);
            return ret;
        }
    }
    *output = ob;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_output_to_file(rnp_output_t *output, const char *path, uint32_t flags)
try {
    if (!output || !path) {
        return RNP_ERROR_NULL_POINTER;
    }
    bool overwrite = false;
    bool random = false;
    if (flags & RNP_OUTPUT_FILE_OVERWRITE) {
        overwrite = true;
        flags &= ~RNP_OUTPUT_FILE_OVERWRITE;
    }
    if (flags & RNP_OUTPUT_FILE_RANDOM) {
        random = true;
        flags &= ~RNP_OUTPUT_FILE_RANDOM;
    }
    if (flags) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp_output_t res = (rnp_output_t) calloc(1, sizeof(*res));
    if (!res) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    rnp_result_t ret = RNP_ERROR_GENERIC;
    if (random) {
        ret = init_tmpfile_dest(&res->dst, path, overwrite);
    } else {
        ret = init_file_dest(&res->dst, path, overwrite);
    }
    if (ret) {
        free(res);
        return ret;
    }
    *output = res;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_output_to_memory(rnp_output_t *output, size_t max_alloc)
try {
    // checks
    if (!output) {
        return RNP_ERROR_NULL_POINTER;
    }

    *output = (rnp_output_t) calloc(1, sizeof(**output));
    if (!*output) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    rnp_result_t ret = init_mem_dest(&(*output)->dst, NULL, max_alloc);
    if (ret) {
        free(*output);
        *output = NULL;
        return ret;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_output_to_armor(rnp_output_t base, rnp_output_t *output, const char *type)
try {
    if (!base || !output) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_armored_msg_t msgtype = PGP_ARMORED_MESSAGE;
    if (type) {
        msgtype = PGP_ARMORED_UNKNOWN;
        ARRAY_LOOKUP_BY_STRCASE(armor_type_map, string, type, type, msgtype);
        if (!msgtype) {
            RNP_LOG("Unsupported armor type: %s", type);
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }
    *output = (rnp_output_t) calloc(1, sizeof(**output));
    if (!*output) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    rnp_result_t ret = init_armored_dst(&(*output)->dst, &base->dst, msgtype);
    if (ret) {
        free(*output);
        *output = NULL;
        return ret;
    }
    (*output)->app_ctx = base;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_output_memory_get_buf(rnp_output_t output, uint8_t **buf, size_t *len, bool do_copy)
try {
    if (!output || !buf || !len) {
        return RNP_ERROR_NULL_POINTER;
    }

    *len = output->dst.writeb;
    *buf = (uint8_t *) mem_dest_get_memory(&output->dst);
    if (!*buf) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (do_copy) {
        uint8_t *tmp_buf = *buf;
        *buf = (uint8_t *) malloc(*len);
        if (!*buf) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        memcpy(*buf, tmp_buf, *len);
    }
    return RNP_SUCCESS;
}
FFI_GUARD

static rnp_result_t
output_writer_bounce(pgp_dest_t *dst, const void *buf, size_t len)
{
    rnp_output_t output = (rnp_output_t) dst->param;
    if (!output->writer) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!output->writer(output->app_ctx, buf, len)) {
        return RNP_ERROR_WRITE;
    }
    return RNP_SUCCESS;
}

static void
output_closer_bounce(pgp_dest_t *dst, bool discard)
{
    rnp_output_t output = (rnp_output_t) dst->param;
    if (output->closer) {
        output->closer(output->app_ctx, discard);
    }
}

rnp_result_t
rnp_output_to_null(rnp_output_t *output)
try {
    // checks
    if (!output) {
        return RNP_ERROR_NULL_POINTER;
    }

    *output = (rnp_output_t) calloc(1, sizeof(**output));
    if (!*output) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    rnp_result_t ret = init_null_dest(&(*output)->dst);
    if (ret) {
        free(*output);
        *output = NULL;
        return ret;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_output_write(rnp_output_t output, const void *data, size_t size, size_t *written)
try {
    if (!output || (!data && size)) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!data && !size) {
        if (written) {
            *written = 0;
        }
        return RNP_SUCCESS;
    }
    size_t old = output->dst.writeb + output->dst.clen;
    dst_write(&output->dst, data, size);
    if (!output->dst.werr && written) {
        *written = output->dst.writeb + output->dst.clen - old;
    }
    output->keep = !output->dst.werr;
    return output->dst.werr;
}
FFI_GUARD

rnp_result_t
rnp_output_to_callback(rnp_output_t *       output,
                       rnp_output_writer_t *writer,
                       rnp_output_closer_t *closer,
                       void *               app_ctx)
try {
    // checks
    if (!output || !writer) {
        return RNP_ERROR_NULL_POINTER;
    }

    *output = (rnp_output_t) calloc(1, sizeof(**output));
    if (!*output) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    (*output)->writer = writer;
    (*output)->closer = closer;
    (*output)->app_ctx = app_ctx;

    pgp_dest_t *dst = &(*output)->dst;
    dst->write = output_writer_bounce;
    dst->close = output_closer_bounce;
    dst->param = *output;
    dst->type = PGP_STREAM_MEMORY;
    dst->writeb = 0;
    dst->werr = RNP_SUCCESS;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_output_finish(rnp_output_t output)
try {
    if (!output) {
        return RNP_ERROR_NULL_POINTER;
    }
    return dst_finish(&output->dst);
}
FFI_GUARD

rnp_result_t
rnp_output_destroy(rnp_output_t output)
try {
    if (output) {
        if (output->dst.type == PGP_STREAM_ARMORED) {
            ((rnp_output_t) output->app_ctx)->keep = output->keep;
        }
        dst_close(&output->dst, !output->keep);
        free(output->dst_directory);
        free(output);
    }
    return RNP_SUCCESS;
}
FFI_GUARD

static rnp_result_t
rnp_op_add_signature(rnp_ffi_t                 ffi,
                     rnp_op_sign_signatures_t &signatures,
                     rnp_key_handle_t          key,
                     rnp_ctx_t &               ctx,
                     rnp_op_sign_signature_t * sig)
{
    if (!key) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *signkey = find_suitable_key(
      PGP_OP_SIGN, get_key_prefer_public(key), &key->ffi->key_provider, PGP_KF_SIGN);
    if (signkey && !signkey->is_secret()) {
        pgp_key_request_ctx_t ctx = {.op = PGP_OP_SIGN, .secret = true};
        ctx.search.type = PGP_KEY_SEARCH_GRIP;
        ctx.search.by.grip = signkey->grip();
        signkey = pgp_request_key(&key->ffi->key_provider, &ctx);
    }
    if (!signkey) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }

    try {
        signatures.emplace_back();
    } catch (const std::exception &e) {
        FFI_LOG(ffi, "%s", e.what());
        return RNP_ERROR_BAD_PARAMETERS;
    }
    rnp_op_sign_signature_t newsig = &signatures.back();
    newsig->signer.key = signkey;
    /* set default create/expire times */
    newsig->signer.sigcreate = ctx.sigcreate;
    newsig->signer.sigexpire = ctx.sigexpire;
    newsig->ffi = ffi;

    if (sig) {
        *sig = newsig;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
rnp_op_set_armor(rnp_ctx_t &ctx, bool armored)
{
    ctx.armor = armored;
    return RNP_SUCCESS;
}

static rnp_result_t
rnp_op_set_compression(rnp_ffi_t ffi, rnp_ctx_t &ctx, const char *compression, int level)
{
    if (!compression) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_compression_type_t zalg = PGP_C_UNKNOWN;
    if (!str_to_compression_alg(compression, &zalg)) {
        FFI_LOG(ffi, "Invalid compression: %s", compression);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    ctx.zalg = (int) zalg;
    ctx.zlevel = level;
    return RNP_SUCCESS;
}

static rnp_result_t
rnp_op_set_hash(rnp_ffi_t ffi, rnp_ctx_t &ctx, const char *hash)
{
    if (!hash) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (!str_to_hash_alg(hash, &ctx.halg)) {
        FFI_LOG(ffi, "Invalid hash: %s", hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
rnp_op_set_creation_time(rnp_ctx_t &ctx, uint32_t create)
{
    ctx.sigcreate = create;
    return RNP_SUCCESS;
}

static rnp_result_t
rnp_op_set_expiration_time(rnp_ctx_t &ctx, uint32_t expire)
{
    ctx.sigexpire = expire;
    return RNP_SUCCESS;
}

static rnp_result_t
rnp_op_set_file_name(rnp_ctx_t &ctx, const char *filename)
{
    ctx.filename = filename ? filename : "";
    return RNP_SUCCESS;
}

static rnp_result_t
rnp_op_set_file_mtime(rnp_ctx_t &ctx, uint32_t mtime)
{
    ctx.filemtime = mtime;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_encrypt_create(rnp_op_encrypt_t *op,
                      rnp_ffi_t         ffi,
                      rnp_input_t       input,
                      rnp_output_t      output)
try {
    // checks
    if (!op || !ffi || !input || !output) {
        return RNP_ERROR_NULL_POINTER;
    }

    *op = new rnp_op_encrypt_st();
    rnp_ctx_init_ffi((*op)->rnpctx, ffi);
    (*op)->ffi = ffi;
    (*op)->input = input;
    (*op)->output = output;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_encrypt_add_recipient(rnp_op_encrypt_t op, rnp_key_handle_t handle)
try {
    // checks
    if (!op || !handle) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *key = find_suitable_key(PGP_OP_ENCRYPT,
                                       get_key_prefer_public(handle),
                                       &handle->ffi->key_provider,
                                       PGP_KF_ENCRYPT);
    if (!key) {
        key = get_key_prefer_public(handle);
    }
    op->rnpctx.recipients.push_back(key);
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_encrypt_add_signature(rnp_op_encrypt_t         op,
                             rnp_key_handle_t         key,
                             rnp_op_sign_signature_t *sig)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_add_signature(op->ffi, op->signatures, key, op->rnpctx, sig);
}
FFI_GUARD

rnp_result_t
rnp_op_encrypt_set_hash(rnp_op_encrypt_t op, const char *hash)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_hash(op->ffi, op->rnpctx, hash);
}
FFI_GUARD

rnp_result_t
rnp_op_encrypt_set_creation_time(rnp_op_encrypt_t op, uint32_t create)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_creation_time(op->rnpctx, create);
}
FFI_GUARD

rnp_result_t
rnp_op_encrypt_set_expiration_time(rnp_op_encrypt_t op, uint32_t expire)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_expiration_time(op->rnpctx, expire);
}
FFI_GUARD

rnp_result_t
rnp_op_encrypt_add_password(rnp_op_encrypt_t op,
                            const char *     password,
                            const char *     s2k_hash,
                            size_t           iterations,
                            const char *     s2k_cipher)
try {
    // checks
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (password && !*password) {
        // no blank passwords
        FFI_LOG(op->ffi, "Blank password");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    // set some defaults
    if (!s2k_hash) {
        s2k_hash = DEFAULT_HASH_ALG;
    }
    if (!s2k_cipher) {
        s2k_cipher = DEFAULT_SYMM_ALG;
    }
    // parse
    pgp_hash_alg_t hash_alg = PGP_HASH_UNKNOWN;
    if (!str_to_hash_alg(s2k_hash, &hash_alg)) {
        FFI_LOG(op->ffi, "Invalid hash: %s", s2k_hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_symm_alg_t symm_alg = PGP_SA_UNKNOWN;
    if (!str_to_cipher(s2k_cipher, &symm_alg)) {
        FFI_LOG(op->ffi, "Invalid cipher: %s", s2k_hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    try {
        rnp::secure_vector<char> ask_pass(MAX_PASSWORD_LENGTH, '\0');
        if (!password) {
            pgp_password_ctx_t pswdctx = {.op = PGP_OP_ENCRYPT_SYM, .key = NULL};
            if (!pgp_request_password(
                  &op->ffi->pass_provider, &pswdctx, ask_pass.data(), ask_pass.size())) {
                return RNP_ERROR_BAD_PASSWORD;
            }
            password = ask_pass.data();
        }
        return rnp_ctx_add_encryption_password(
          op->rnpctx, password, hash_alg, symm_alg, iterations);
    } catch (const std::exception &e) {
        FFI_LOG(op->ffi, "%s", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }
}
FFI_GUARD

rnp_result_t
rnp_op_encrypt_set_armor(rnp_op_encrypt_t op, bool armored)
try {
    // checks
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_armor(op->rnpctx, armored);
}
FFI_GUARD

rnp_result_t
rnp_op_encrypt_set_cipher(rnp_op_encrypt_t op, const char *cipher)
try {
    // checks
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!str_to_cipher(cipher, &op->rnpctx.ealg)) {
        FFI_LOG(op->ffi, "Invalid cipher: %s", cipher);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_encrypt_set_aead(rnp_op_encrypt_t op, const char *alg)
try {
    // checks
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!str_to_aead_alg(alg, &op->rnpctx.aalg)) {
        FFI_LOG(op->ffi, "Invalid AEAD algorithm: %s", alg);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_encrypt_set_aead_bits(rnp_op_encrypt_t op, int bits)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if ((bits < 0) || (bits > 56)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    op->rnpctx.abits = bits;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_encrypt_set_compression(rnp_op_encrypt_t op, const char *compression, int level)
try {
    // checks
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_compression(op->ffi, op->rnpctx, compression, level);
}
FFI_GUARD

rnp_result_t
rnp_op_encrypt_set_file_name(rnp_op_encrypt_t op, const char *filename)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_file_name(op->rnpctx, filename);
}
FFI_GUARD

rnp_result_t
rnp_op_encrypt_set_file_mtime(rnp_op_encrypt_t op, uint32_t mtime)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_file_mtime(op->rnpctx, mtime);
}
FFI_GUARD

static pgp_write_handler_t
pgp_write_handler(pgp_password_provider_t *pass_provider,
                  rnp_ctx_t *              rnpctx,
                  void *                   param,
                  pgp_key_provider_t *     key_provider)
{
    pgp_write_handler_t handler;
    memset(&handler, 0, sizeof(handler));
    handler.password_provider = pass_provider;
    handler.ctx = rnpctx;
    handler.param = param;
    handler.key_provider = key_provider;
    return handler;
}

static rnp_result_t
rnp_op_add_signatures(rnp_op_sign_signatures_t &opsigs, rnp_ctx_t &ctx)
{
    for (auto &sig : opsigs) {
        if (!sig.signer.key) {
            return RNP_ERROR_NO_SUITABLE_KEY;
        }

        rnp_signer_info_t sinfo = sig.signer;
        if (!sig.hash_set) {
            sinfo.halg = ctx.halg;
        }
        if (!sig.expiry_set) {
            sinfo.sigexpire = ctx.sigexpire;
        }
        if (!sig.create_set) {
            sinfo.sigcreate = ctx.sigcreate;
        }
        ctx.signers.push_back(sinfo);
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_op_encrypt_execute(rnp_op_encrypt_t op)
try {
    // checks
    if (!op || !op->input || !op->output) {
        return RNP_ERROR_NULL_POINTER;
    }

    // set the default hash alg if none was specified
    if (!op->rnpctx.halg) {
        op->rnpctx.halg = DEFAULT_PGP_HASH_ALG;
    }
    pgp_write_handler_t handler =
      pgp_write_handler(&op->ffi->pass_provider, &op->rnpctx, NULL, &op->ffi->key_provider);

    rnp_result_t ret;
    if (!op->signatures.empty()) {
        if ((ret = rnp_op_add_signatures(op->signatures, op->rnpctx))) {
            return ret;
        }
        ret = rnp_encrypt_sign_src(&handler, &op->input->src, &op->output->dst);
    } else {
        ret = rnp_encrypt_src(&handler, &op->input->src, &op->output->dst);
    }

    dst_flush(&op->output->dst);
    op->output->keep = ret == RNP_SUCCESS;
    op->input = NULL;
    op->output = NULL;
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_op_encrypt_destroy(rnp_op_encrypt_t op)
try {
    delete op;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_sign_create(rnp_op_sign_t *op, rnp_ffi_t ffi, rnp_input_t input, rnp_output_t output)
try {
    // checks
    if (!op || !ffi || !input || !output) {
        return RNP_ERROR_NULL_POINTER;
    }

    *op = new rnp_op_sign_st();
    rnp_ctx_init_ffi((*op)->rnpctx, ffi);
    (*op)->ffi = ffi;
    (*op)->input = input;
    (*op)->output = output;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_sign_cleartext_create(rnp_op_sign_t *op,
                             rnp_ffi_t      ffi,
                             rnp_input_t    input,
                             rnp_output_t   output)
try {
    rnp_result_t res = rnp_op_sign_create(op, ffi, input, output);
    if (!res) {
        (*op)->rnpctx.clearsign = true;
    }
    return res;
}
FFI_GUARD

rnp_result_t
rnp_op_sign_detached_create(rnp_op_sign_t *op,
                            rnp_ffi_t      ffi,
                            rnp_input_t    input,
                            rnp_output_t   signature)
try {
    rnp_result_t res = rnp_op_sign_create(op, ffi, input, signature);
    if (!res) {
        (*op)->rnpctx.detached = true;
    }
    return res;
}
FFI_GUARD

rnp_result_t
rnp_op_sign_add_signature(rnp_op_sign_t op, rnp_key_handle_t key, rnp_op_sign_signature_t *sig)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_add_signature(op->ffi, op->signatures, key, op->rnpctx, sig);
}
FFI_GUARD

rnp_result_t
rnp_op_sign_signature_set_hash(rnp_op_sign_signature_t sig, const char *hash)
try {
    if (!sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!str_to_hash_alg(hash, &sig->signer.halg)) {
        FFI_LOG(sig->ffi, "Invalid hash: %s", hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    sig->hash_set = true;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_sign_signature_set_creation_time(rnp_op_sign_signature_t sig, uint32_t create)
try {
    if (!sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    sig->signer.sigcreate = create;
    sig->create_set = true;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_sign_signature_set_expiration_time(rnp_op_sign_signature_t sig, uint32_t expires)
try {
    if (!sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    sig->signer.sigexpire = expires;
    sig->expiry_set = true;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_sign_set_armor(rnp_op_sign_t op, bool armored)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_armor(op->rnpctx, armored);
}
FFI_GUARD

rnp_result_t
rnp_op_sign_set_compression(rnp_op_sign_t op, const char *compression, int level)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_compression(op->ffi, op->rnpctx, compression, level);
}
FFI_GUARD

rnp_result_t
rnp_op_sign_set_hash(rnp_op_sign_t op, const char *hash)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_hash(op->ffi, op->rnpctx, hash);
}
FFI_GUARD

rnp_result_t
rnp_op_sign_set_creation_time(rnp_op_sign_t op, uint32_t create)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_creation_time(op->rnpctx, create);
}
FFI_GUARD

rnp_result_t
rnp_op_sign_set_expiration_time(rnp_op_sign_t op, uint32_t expire)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_expiration_time(op->rnpctx, expire);
}
FFI_GUARD

rnp_result_t
rnp_op_sign_set_file_name(rnp_op_sign_t op, const char *filename)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_file_name(op->rnpctx, filename);
}
FFI_GUARD

rnp_result_t
rnp_op_sign_set_file_mtime(rnp_op_sign_t op, uint32_t mtime)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    return rnp_op_set_file_mtime(op->rnpctx, mtime);
}
FFI_GUARD

rnp_result_t
rnp_op_sign_execute(rnp_op_sign_t op)
try {
    // checks
    if (!op || !op->input || !op->output) {
        return RNP_ERROR_NULL_POINTER;
    }

    // set the default hash alg if none was specified
    if (!op->rnpctx.halg) {
        op->rnpctx.halg = DEFAULT_PGP_HASH_ALG;
    }
    pgp_write_handler_t handler =
      pgp_write_handler(&op->ffi->pass_provider, &op->rnpctx, NULL, &op->ffi->key_provider);

    rnp_result_t ret;
    if ((ret = rnp_op_add_signatures(op->signatures, op->rnpctx))) {
        return ret;
    }
    ret = rnp_sign_src(&handler, &op->input->src, &op->output->dst);

    dst_flush(&op->output->dst);
    op->output->keep = ret == RNP_SUCCESS;
    op->input = NULL;
    op->output = NULL;
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_op_sign_destroy(rnp_op_sign_t op)
try {
    delete op;
    return RNP_SUCCESS;
}
FFI_GUARD

static void
rnp_op_verify_on_signatures(const std::vector<pgp_signature_info_t> &sigs, void *param)
{
    rnp_op_verify_t op = (rnp_op_verify_t) param;

    try {
        /* in case we have multiple signed layers */
        delete[] op->signatures;
        op->signatures = new rnp_op_verify_signature_st[sigs.size()];
    } catch (const std::exception &e) {
        FFI_LOG(op->ffi, "%s", e.what());
        return;
    }
    op->signature_count = sigs.size();

    size_t i = 0;
    for (const auto &sinfo : sigs) {
        rnp_op_verify_signature_t res = &op->signatures[i++];
        /* sinfo.sig may be NULL */
        if (sinfo.sig) {
            try {
                res->sig_pkt = *sinfo.sig;
            } catch (const std::exception &e) {
                FFI_LOG(op->ffi, "%s", e.what());
            }
        }

        if (sinfo.unknown) {
            res->verify_status = RNP_ERROR_SIGNATURE_INVALID;
        } else if (sinfo.valid) {
            res->verify_status = sinfo.expired ? RNP_ERROR_SIGNATURE_EXPIRED : RNP_SUCCESS;
        } else {
            res->verify_status =
              sinfo.no_signer ? RNP_ERROR_KEY_NOT_FOUND : RNP_ERROR_SIGNATURE_INVALID;
        }
        res->ffi = op->ffi;
    }
}

static bool
rnp_verify_src_provider(pgp_parse_handler_t *handler, pgp_source_t *src)
{
    /* this one is called only when input for detached signature is needed */
    rnp_op_verify_t op = (rnp_op_verify_t) handler->param;
    if (!op->detached_input) {
        return false;
    }
    *src = op->detached_input->src;
    /* we should give ownership on src to caller */
    memset(&op->detached_input->src, 0, sizeof(op->detached_input->src));
    return true;
};

static bool
rnp_verify_dest_provider(pgp_parse_handler_t *handler,
                         pgp_dest_t **        dst,
                         bool *               closedst,
                         const char *         filename)
{
    rnp_op_verify_t op = (rnp_op_verify_t) handler->param;
    if (!op->output) {
        return false;
    }
    *dst = &(op->output->dst);
    *closedst = false;
    op->filename = filename ? strdup(filename) : NULL;
    return true;
}

static void
recipient_handle_from_pk_sesskey(rnp_recipient_handle_t  handle,
                                 const pgp_pk_sesskey_t &sesskey)
{
    static_assert(sizeof(handle->keyid) == PGP_KEY_ID_SIZE, "Keyid size mismatch");
    memcpy(handle->keyid, sesskey.key_id.data(), PGP_KEY_ID_SIZE);
    handle->palg = sesskey.alg;
}

static void
symenc_handle_from_sk_sesskey(rnp_symenc_handle_t handle, const pgp_sk_sesskey_t &sesskey)
{
    handle->alg = sesskey.alg;
    handle->halg = sesskey.s2k.hash_alg;
    handle->s2k_type = sesskey.s2k.specifier;
    if (sesskey.s2k.specifier == PGP_S2KS_ITERATED_AND_SALTED) {
        handle->iterations = pgp_s2k_decode_iterations(sesskey.s2k.iterations);
    } else {
        handle->iterations = 1;
    }
    handle->aalg = sesskey.aalg;
}

static void
rnp_verify_on_recipients(const std::vector<pgp_pk_sesskey_t> &recipients,
                         const std::vector<pgp_sk_sesskey_t> &passwords,
                         void *                               param)
{
    rnp_op_verify_t op = (rnp_op_verify_t) param;
    /* store only top-level encrypted stream recipients info for now */
    if (op->encrypted_layers++) {
        return;
    }
    if (!recipients.empty()) {
        op->recipients =
          (rnp_recipient_handle_t) calloc(recipients.size(), sizeof(*op->recipients));
        if (!op->recipients) {
            FFI_LOG(op->ffi, "allocation failed");
            return;
        }
        for (size_t i = 0; i < recipients.size(); i++) {
            recipient_handle_from_pk_sesskey(&op->recipients[i], recipients[i]);
        }
    }
    op->recipient_count = recipients.size();
    if (!passwords.empty()) {
        op->symencs = (rnp_symenc_handle_t) calloc(passwords.size(), sizeof(*op->symencs));
        if (!op->symencs) {
            FFI_LOG(op->ffi, "allocation failed");
            return;
        }
        for (size_t i = 0; i < passwords.size(); i++) {
            symenc_handle_from_sk_sesskey(&op->symencs[i], passwords[i]);
        }
    }
    op->symenc_count = passwords.size();
}

static void
rnp_verify_on_decryption_start(pgp_pk_sesskey_t *pubenc, pgp_sk_sesskey_t *symenc, void *param)
{
    rnp_op_verify_t op = (rnp_op_verify_t) param;
    /* store only top-level encrypted stream info */
    if (op->encrypted_layers > 1) {
        return;
    }
    if (pubenc) {
        op->used_recipient = (rnp_recipient_handle_t) calloc(1, sizeof(*op->used_recipient));
        if (!op->used_recipient) {
            FFI_LOG(op->ffi, "allocation failed");
            return;
        }
        recipient_handle_from_pk_sesskey(op->used_recipient, *pubenc);
        return;
    }
    if (symenc) {
        op->used_symenc = (rnp_symenc_handle_t) calloc(1, sizeof(*op->used_symenc));
        if (!op->used_symenc) {
            FFI_LOG(op->ffi, "allocation failed");
            return;
        }
        symenc_handle_from_sk_sesskey(op->used_symenc, *symenc);
        return;
    }
    FFI_LOG(op->ffi, "Warning! Both pubenc and symenc are NULL.");
}

static void
rnp_verify_on_decryption_info(bool mdc, pgp_aead_alg_t aead, pgp_symm_alg_t salg, void *param)
{
    rnp_op_verify_t op = (rnp_op_verify_t) param;
    /* store only top-level encrypted stream info for now */
    if (op->encrypted_layers > 1) {
        return;
    }
    op->mdc = mdc;
    op->aead = aead;
    op->salg = salg;
    op->encrypted = true;
}

static void
rnp_verify_on_decryption_done(bool validated, void *param)
{
    rnp_op_verify_t op = (rnp_op_verify_t) param;
    if (op->encrypted_layers > 1) {
        return;
    }
    op->validated = validated;
}

rnp_result_t
rnp_op_verify_create(rnp_op_verify_t *op,
                     rnp_ffi_t        ffi,
                     rnp_input_t      input,
                     rnp_output_t     output)
try {
    if (!op || !ffi || !input || !output) {
        return RNP_ERROR_NULL_POINTER;
    }

    *op = new rnp_op_verify_st();
    rnp_ctx_init_ffi((*op)->rnpctx, ffi);
    (*op)->ffi = ffi;
    (*op)->input = input;
    (*op)->output = output;

    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_verify_detached_create(rnp_op_verify_t *op,
                              rnp_ffi_t        ffi,
                              rnp_input_t      input,
                              rnp_input_t      signature)
try {
    if (!op || !ffi || !input || !signature) {
        return RNP_ERROR_NULL_POINTER;
    }

    *op = new rnp_op_verify_st();
    rnp_ctx_init_ffi((*op)->rnpctx, ffi);
    (*op)->rnpctx.detached = true;
    (*op)->ffi = ffi;
    (*op)->input = signature;
    (*op)->detached_input = input;

    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_verify_execute(rnp_op_verify_t op)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_parse_handler_t handler;

    handler.password_provider = &op->ffi->pass_provider;
    handler.key_provider = &op->ffi->key_provider;
    handler.on_signatures = rnp_op_verify_on_signatures;
    handler.src_provider = rnp_verify_src_provider;
    handler.dest_provider = rnp_verify_dest_provider;
    handler.on_recipients = rnp_verify_on_recipients;
    handler.on_decryption_start = rnp_verify_on_decryption_start;
    handler.on_decryption_info = rnp_verify_on_decryption_info;
    handler.on_decryption_done = rnp_verify_on_decryption_done;
    handler.param = op;
    handler.ctx = &op->rnpctx;

    rnp_result_t ret = process_pgp_source(&handler, op->input->src);
    if (op->output) {
        dst_flush(&op->output->dst);
        op->output->keep = ret == RNP_SUCCESS;
    }
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_op_verify_get_signature_count(rnp_op_verify_t op, size_t *count)
try {
    if (!op || !count) {
        return RNP_ERROR_NULL_POINTER;
    }

    *count = op->signature_count;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_verify_get_signature_at(rnp_op_verify_t op, size_t idx, rnp_op_verify_signature_t *sig)
try {
    if (!op || !sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (idx >= op->signature_count) {
        FFI_LOG(op->ffi, "Invalid signature index: %zu", idx);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *sig = &op->signatures[idx];
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_verify_get_file_info(rnp_op_verify_t op, char **filename, uint32_t *mtime)
try {
    if (mtime) {
        *mtime = op->file_mtime;
    }
    if (filename) {
        if (op->filename) {
            *filename = strdup(op->filename);
        } else {
            *filename = NULL;
        }
    }
    return RNP_SUCCESS;
}
FFI_GUARD

static const char *
get_protection_mode(rnp_op_verify_t op)
{
    if (!op->encrypted) {
        return "none";
    }
    if (op->mdc) {
        return "cfb-mdc";
    }
    if (op->aead == PGP_AEAD_NONE) {
        return "cfb";
    }
    switch (op->aead) {
    case PGP_AEAD_EAX:
        return "aead-eax";
    case PGP_AEAD_OCB:
        return "aead-ocb";
    default:
        return "aead-unknown";
    }
}

static const char *
get_protection_cipher(rnp_op_verify_t op)
{
    if (!op->encrypted) {
        return "none";
    }
    const char *str = "unknown";
    ARRAY_LOOKUP_BY_ID(symm_alg_map, type, string, op->salg, str);
    return str;
}

rnp_result_t
rnp_op_verify_get_protection_info(rnp_op_verify_t op, char **mode, char **cipher, bool *valid)
try {
    if (!op || (!mode && !cipher && !valid)) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (mode) {
        *mode = strdup(get_protection_mode(op));
        if (!*mode) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }
    if (cipher) {
        *cipher = strdup(get_protection_cipher(op));
        if (!*cipher) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }
    if (valid) {
        *valid = op->validated;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_verify_get_recipient_count(rnp_op_verify_t op, size_t *count)
try {
    if (!op || !count) {
        return RNP_ERROR_NULL_POINTER;
    }
    *count = op->recipient_count;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_verify_get_used_recipient(rnp_op_verify_t op, rnp_recipient_handle_t *recipient)
try {
    if (!op || !recipient) {
        return RNP_ERROR_NULL_POINTER;
    }
    *recipient = op->used_recipient;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_verify_get_recipient_at(rnp_op_verify_t         op,
                               size_t                  idx,
                               rnp_recipient_handle_t *recipient)
try {
    if (!op || !recipient) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (idx >= op->recipient_count) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *recipient = &op->recipients[idx];
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_recipient_get_keyid(rnp_recipient_handle_t recipient, char **keyid)
try {
    if (!recipient || !keyid) {
        return RNP_ERROR_NULL_POINTER;
    }
    static_assert(sizeof(recipient->keyid) == PGP_KEY_ID_SIZE,
                  "rnp_recipient_handle_t.keyid size mismatch");
    return hex_encode_value(recipient->keyid, PGP_KEY_ID_SIZE, keyid);
}
FFI_GUARD

rnp_result_t
rnp_recipient_get_alg(rnp_recipient_handle_t recipient, char **alg)
try {
    if (!recipient || !alg) {
        return RNP_ERROR_NULL_POINTER;
    }
    return get_map_value(pubkey_alg_map, ARRAY_SIZE(pubkey_alg_map), recipient->palg, alg);
}
FFI_GUARD

rnp_result_t
rnp_op_verify_get_symenc_count(rnp_op_verify_t op, size_t *count)
try {
    if (!op || !count) {
        return RNP_ERROR_NULL_POINTER;
    }
    *count = op->symenc_count;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_verify_get_used_symenc(rnp_op_verify_t op, rnp_symenc_handle_t *symenc)
try {
    if (!op || !symenc) {
        return RNP_ERROR_NULL_POINTER;
    }
    *symenc = op->used_symenc;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_verify_get_symenc_at(rnp_op_verify_t op, size_t idx, rnp_symenc_handle_t *symenc)
try {
    if (!op || !symenc) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (idx >= op->symenc_count) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *symenc = &op->symencs[idx];
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_symenc_get_cipher(rnp_symenc_handle_t symenc, char **cipher)
try {
    if (!symenc || !cipher) {
        return RNP_ERROR_NULL_POINTER;
    }
    return get_map_value(symm_alg_map, ARRAY_SIZE(symm_alg_map), symenc->alg, cipher);
}
FFI_GUARD

rnp_result_t
rnp_symenc_get_aead_alg(rnp_symenc_handle_t symenc, char **alg)
try {
    if (!symenc || !alg) {
        return RNP_ERROR_NULL_POINTER;
    }
    return get_map_value(aead_alg_map, ARRAY_SIZE(aead_alg_map), symenc->aalg, alg);
}
FFI_GUARD

rnp_result_t
rnp_symenc_get_hash_alg(rnp_symenc_handle_t symenc, char **alg)
try {
    if (!symenc || !alg) {
        return RNP_ERROR_NULL_POINTER;
    }
    return get_map_value(hash_alg_map, ARRAY_SIZE(hash_alg_map), symenc->halg, alg);
}
FFI_GUARD

rnp_result_t
rnp_symenc_get_s2k_type(rnp_symenc_handle_t symenc, char **type)
try {
    if (!symenc || !type) {
        return RNP_ERROR_NULL_POINTER;
    }
    return get_map_value(s2k_type_map, ARRAY_SIZE(s2k_type_map), symenc->s2k_type, type);
}
FFI_GUARD

rnp_result_t
rnp_symenc_get_s2k_iterations(rnp_symenc_handle_t symenc, uint32_t *iterations)
try {
    if (!symenc || !iterations) {
        return RNP_ERROR_NULL_POINTER;
    }
    *iterations = symenc->iterations;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_verify_destroy(rnp_op_verify_t op)
try {
    delete op;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_op_verify_st::~rnp_op_verify_st()
{
    delete[] signatures;
    free(filename);
    free(recipients);
    free(used_recipient);
    free(symencs);
    free(used_symenc);
}

rnp_result_t
rnp_op_verify_signature_get_status(rnp_op_verify_signature_t sig)
try {
    if (!sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    return sig->verify_status;
}
FFI_GUARD

rnp_result_t
rnp_op_verify_signature_get_handle(rnp_op_verify_signature_t sig,
                                   rnp_signature_handle_t *  handle)
try {
    if (!sig || !handle) {
        return RNP_ERROR_NULL_POINTER;
    }

    *handle = (rnp_signature_handle_t) calloc(1, sizeof(**handle));
    if (!*handle) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    try {
        (*handle)->sig = new pgp_subsig_t(sig->sig_pkt);
    } catch (const std::exception &e) {
        FFI_LOG(sig->ffi, "%s", e.what());
        free(*handle);
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    (*handle)->ffi = sig->ffi;
    (*handle)->key = NULL;
    (*handle)->own_sig = true;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_verify_signature_get_hash(rnp_op_verify_signature_t sig, char **hash)
try {
    if (!sig || !hash) {
        return RNP_ERROR_NULL_POINTER;
    }
    return get_map_value(hash_alg_map, ARRAY_SIZE(hash_alg_map), sig->sig_pkt.halg, hash);
}
FFI_GUARD

rnp_result_t
rnp_op_verify_signature_get_key(rnp_op_verify_signature_t sig, rnp_key_handle_t *key)
try {
    rnp_ffi_t        ffi = sig->ffi;
    pgp_key_search_t search = {};

    if (!sig->sig_pkt.has_keyid()) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    search.by.keyid = sig->sig_pkt.keyid();
    // create a search (since we'll use this later anyways)
    search.type = PGP_KEY_SEARCH_KEYID;

    // search the stores
    pgp_key_t *pub = rnp_key_store_search(ffi->pubring, &search, NULL);
    pgp_key_t *sec = rnp_key_store_search(ffi->secring, &search, NULL);
    if (!pub && !sec) {
        return RNP_ERROR_KEY_NOT_FOUND;
    }

    struct rnp_key_handle_st *handle = (rnp_key_handle_st *) calloc(1, sizeof(*handle));
    if (!handle) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    handle->ffi = ffi;
    handle->pub = pub;
    handle->sec = sec;
    handle->locator = search;
    *key = handle;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_verify_signature_get_times(rnp_op_verify_signature_t sig,
                                  uint32_t *                create,
                                  uint32_t *                expires)
try {
    if (create) {
        *create = sig->sig_pkt.creation();
    }
    if (expires) {
        *expires = sig->sig_pkt.expiration();
    }

    return RNP_SUCCESS;
}
FFI_GUARD

static bool
rnp_decrypt_dest_provider(pgp_parse_handler_t *handler,
                          pgp_dest_t **        dst,
                          bool *               closedst,
                          const char *         filename)
{
    *dst = &((rnp_output_t) handler->param)->dst;
    *closedst = false;
    return true;
}

rnp_result_t
rnp_decrypt(rnp_ffi_t ffi, rnp_input_t input, rnp_output_t output)
try {
    // checks
    if (!ffi || !input || !output) {
        return RNP_ERROR_NULL_POINTER;
    }

    rnp_ctx_t rnpctx;
    rnp_ctx_init_ffi(rnpctx, ffi);
    pgp_parse_handler_t handler;
    memset(&handler, 0, sizeof(handler));
    handler.password_provider = &ffi->pass_provider;
    handler.key_provider = &ffi->key_provider;
    handler.dest_provider = rnp_decrypt_dest_provider;
    handler.param = output;
    handler.ctx = &rnpctx;

    rnp_result_t ret = process_pgp_source(&handler, input->src);
    dst_flush(&output->dst);
    output->keep = (ret == RNP_SUCCESS);
    return ret;
}
FFI_GUARD

static rnp_result_t
str_to_locator(rnp_ffi_t         ffi,
               pgp_key_search_t *locator,
               const char *      identifier_type,
               const char *      identifier)
{
    // parse the identifier type
    locator->type = PGP_KEY_SEARCH_UNKNOWN;
    ARRAY_LOOKUP_BY_STRCASE(identifier_type_map, string, type, identifier_type, locator->type);
    if (locator->type == PGP_KEY_SEARCH_UNKNOWN) {
        FFI_LOG(ffi, "Invalid identifier type: %s", identifier_type);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    // see what type we have
    switch (locator->type) {
    case PGP_KEY_SEARCH_USERID:
        if (snprintf(locator->by.userid, sizeof(locator->by.userid), "%s", identifier) >=
            (int) sizeof(locator->by.userid)) {
            FFI_LOG(ffi, "UserID too long");
            return RNP_ERROR_BAD_PARAMETERS;
        }
        break;
    case PGP_KEY_SEARCH_KEYID: {
        if (strlen(identifier) != (PGP_KEY_ID_SIZE * 2) ||
            !rnp::hex_decode(identifier, locator->by.keyid.data(), locator->by.keyid.size())) {
            FFI_LOG(ffi, "Invalid keyid: %s", identifier);
            return RNP_ERROR_BAD_PARAMETERS;
        }
    } break;
    case PGP_KEY_SEARCH_FINGERPRINT: {
        // TODO: support v5 fingerprints
        // Note: v2/v3 fingerprint are 16 bytes (32 chars) long.
        if ((strlen(identifier) != (PGP_FINGERPRINT_SIZE * 2)) && (strlen(identifier) != 32)) {
            FFI_LOG(ffi, "Invalid fingerprint: %s", identifier);
            return RNP_ERROR_BAD_PARAMETERS;
        }
        locator->by.fingerprint.length = rnp::hex_decode(
          identifier, locator->by.fingerprint.fingerprint, PGP_FINGERPRINT_SIZE);
        if (!locator->by.fingerprint.length) {
            FFI_LOG(ffi, "Invalid fingerprint: %s", identifier);
            return RNP_ERROR_BAD_PARAMETERS;
        }
    } break;
    case PGP_KEY_SEARCH_GRIP: {
        if (strlen(identifier) != (PGP_KEY_GRIP_SIZE * 2) ||
            !rnp::hex_decode(identifier, locator->by.grip.data(), locator->by.grip.size())) {
            FFI_LOG(ffi, "Invalid grip: %s", identifier);
            return RNP_ERROR_BAD_PARAMETERS;
        }
    } break;
    default:
        // should never happen
        assert(false);
        return RNP_ERROR_BAD_STATE;
    }
    return RNP_SUCCESS;
}

static bool
locator_to_str(const pgp_key_search_t *locator,
               const char **           identifier_type,
               char *                  identifier,
               size_t                  identifier_size)
{
    // find the identifier type string with the map
    *identifier_type = NULL;
    ARRAY_LOOKUP_BY_ID(identifier_type_map, type, string, locator->type, *identifier_type);
    if (!*identifier_type) {
        return false;
    }
    // fill in the actual identifier
    switch (locator->type) {
    case PGP_KEY_SEARCH_USERID:
        if (snprintf(identifier, identifier_size, "%s", locator->by.userid) >=
            (int) identifier_size) {
            return false;
        }
        break;
    case PGP_KEY_SEARCH_KEYID:
        if (!rnp::hex_encode(locator->by.keyid.data(),
                             locator->by.keyid.size(),
                             identifier,
                             identifier_size)) {
            return false;
        }
        break;
    case PGP_KEY_SEARCH_FINGERPRINT:
        if (!rnp::hex_encode(locator->by.fingerprint.fingerprint,
                             locator->by.fingerprint.length,
                             identifier,
                             identifier_size)) {
            return false;
        }
        break;
    case PGP_KEY_SEARCH_GRIP:
        if (!rnp::hex_encode(
              locator->by.grip.data(), locator->by.grip.size(), identifier, identifier_size)) {
            return false;
        }
        break;
    default:
        assert(false);
        return false;
    }
    return true;
}

rnp_result_t
rnp_locate_key(rnp_ffi_t         ffi,
               const char *      identifier_type,
               const char *      identifier,
               rnp_key_handle_t *handle)
try {
    // checks
    if (!ffi || !identifier_type || !identifier || !handle) {
        return RNP_ERROR_NULL_POINTER;
    }

    // figure out the identifier type
    pgp_key_search_t locator = {(pgp_key_search_type_t) 0};
    rnp_result_t     ret = str_to_locator(ffi, &locator, identifier_type, identifier);
    if (ret) {
        return ret;
    }

    // search pubring
    pgp_key_t *pub = rnp_key_store_search(ffi->pubring, &locator, NULL);
    // search secring
    pgp_key_t *sec = rnp_key_store_search(ffi->secring, &locator, NULL);

    if (pub || sec) {
        *handle = (rnp_key_handle_t) malloc(sizeof(**handle));
        if (!*handle) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        (*handle)->ffi = ffi;
        (*handle)->pub = pub;
        (*handle)->sec = sec;
        (*handle)->locator = locator;
    } else {
        *handle = NULL;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_export(rnp_key_handle_t handle, rnp_output_t output, uint32_t flags)
try {
    pgp_dest_t *     dst = NULL;
    pgp_dest_t       armordst = {};
    pgp_key_t *      key = NULL;
    rnp_key_store_t *store = NULL;
    bool             export_subs = false;
    bool             armored = false;

    // checks
    if (!handle || !output) {
        return RNP_ERROR_NULL_POINTER;
    }
    dst = &output->dst;
    if ((flags & RNP_KEY_EXPORT_PUBLIC) && (flags & RNP_KEY_EXPORT_SECRET)) {
        FFI_LOG(handle->ffi, "Invalid export flags, select only public or secret, not both.");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    // handle flags
    if (flags & RNP_KEY_EXPORT_ARMORED) {
        flags &= ~RNP_KEY_EXPORT_ARMORED;
        armored = true;
    }
    if (flags & RNP_KEY_EXPORT_PUBLIC) {
        flags &= ~RNP_KEY_EXPORT_PUBLIC;
        key = get_key_require_public(handle);
        store = handle->ffi->pubring;
    } else if (flags & RNP_KEY_EXPORT_SECRET) {
        flags &= ~RNP_KEY_EXPORT_SECRET;
        key = get_key_require_secret(handle);
        store = handle->ffi->secring;
    } else {
        FFI_LOG(handle->ffi, "must specify public or secret key for export");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (flags & RNP_KEY_EXPORT_SUBKEYS) {
        flags &= ~RNP_KEY_EXPORT_SUBKEYS;
        export_subs = true;
    }
    // check for any unrecognized flags
    if (flags) {
        FFI_LOG(handle->ffi, "unrecognized flags remaining: 0x%X", flags);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    // make sure we found our key
    if (!key) {
        FFI_LOG(handle->ffi, "no suitable key found");
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    // only PGP packets supported for now
    if (key->format != PGP_KEY_STORE_GPG && key->format != PGP_KEY_STORE_KBX) {
        return RNP_ERROR_NOT_IMPLEMENTED;
    }
    if (armored) {
        auto msgtype = key->is_secret() ? PGP_ARMORED_SECRET_KEY : PGP_ARMORED_PUBLIC_KEY;
        rnp_result_t res = init_armored_dst(&armordst, &output->dst, msgtype);
        if (res) {
            return res;
        }
        dst = &armordst;
    }
    // write
    if (key->is_primary()) {
        // primary key, write just the primary or primary and all subkeys
        key->write_xfer(*dst, export_subs ? store : NULL);
        if (dst->werr) {
            return RNP_ERROR_WRITE;
        }
    } else {
        // subkeys flag is only valid for primary
        if (export_subs) {
            FFI_LOG(handle->ffi, "export with subkeys requested but key is not primary");
            return RNP_ERROR_BAD_PARAMETERS;
        }
        // subkey, write the primary + this subkey only
        pgp_key_t *primary = rnp_key_store_get_primary_key(store, key);
        if (!primary) {
            // shouldn't happen
            return RNP_ERROR_GENERIC;
        }
        primary->write_xfer(*dst);
        if (dst->werr) {
            return RNP_ERROR_WRITE;
        }
        key->write_xfer(*dst);
        if (dst->werr) {
            return RNP_ERROR_WRITE;
        }
    }
    if (armored) {
        dst_finish(&armordst);
        dst_close(&armordst, false);
    }
    output->keep = true;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_export_autocrypt(rnp_key_handle_t key,
                         rnp_key_handle_t subkey,
                         const char *     uid,
                         rnp_output_t     output,
                         uint32_t         flags)
try {
    if (!key || !output) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (flags) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    /* Get the primary key */
    pgp_key_t *primary = get_key_prefer_public(key);
    if (!primary || !primary->is_primary() || !primary->valid() || !primary->can_sign()) {
        FFI_LOG(key->ffi, "No valid signing primary key");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    /* Get encrypting subkey */
    pgp_key_t *sub = NULL;
    if (subkey) {
        sub = get_key_prefer_public(subkey);
        if (sub && (!sub->valid() || !sub->can_encrypt())) {
            FFI_LOG(key->ffi, "Invalid or non-encrypting subkey");
            return RNP_ERROR_BAD_PARAMETERS;
        }
    } else {
        sub = find_suitable_key(
          PGP_OP_ENCRYPT, primary, &key->ffi->key_provider, PGP_KF_ENCRYPT, true);
    }
    if (!sub || sub->is_primary()) {
        FFI_LOG(key->ffi, "No encrypting subkey");
        return RNP_ERROR_KEY_NOT_FOUND;
    }
    /* Get userid */
    size_t uididx = primary->uid_count();
    if (uid) {
        for (size_t idx = 0; idx < primary->uid_count(); idx++) {
            if (primary->get_uid(idx).str == uid) {
                uididx = idx;
                break;
            }
        }
    } else {
        if (primary->uid_count() > 1) {
            FFI_LOG(key->ffi, "Ambiguous userid");
            return RNP_ERROR_BAD_PARAMETERS;
        }
        uididx = 0;
    }
    if (uididx >= primary->uid_count()) {
        FFI_LOG(key->ffi, "Userid not found");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!primary->write_autocrypt(output->dst, *sub, uididx)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

static pgp_key_t *
rnp_key_get_revoker(rnp_key_handle_t key)
{
    pgp_key_t *exkey = get_key_prefer_public(key);
    if (!exkey) {
        return NULL;
    }
    if (exkey->is_subkey()) {
        return rnp_key_store_get_primary_key(key->ffi->secring, exkey);
    }
    // TODO: search through revocation key subpackets as well
    return get_key_require_secret(key);
}

static rnp_result_t
rnp_key_get_revocation(rnp_ffi_t         ffi,
                       pgp_key_t *       key,
                       pgp_key_t *       revoker,
                       const char *      hash,
                       const char *      code,
                       const char *      reason,
                       pgp_signature_t **sig)
{
    *sig = NULL;
    if (!hash) {
        hash = DEFAULT_HASH_ALG;
    }
    pgp_hash_alg_t halg = PGP_HASH_UNKNOWN;
    if (!str_to_hash_alg(hash, &halg)) {
        FFI_LOG(ffi, "Unknown hash algorithm: %s", hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_revoke_t revinfo = {};
    if (code && !str_to_revocation_type(code, &revinfo.code)) {
        FFI_LOG(ffi, "Wrong revocation code: %s", code);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (revinfo.code > PGP_REVOCATION_RETIRED) {
        FFI_LOG(ffi, "Wrong key revocation code: %d", (int) revinfo.code);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (reason) {
        try {
            revinfo.reason = reason;
        } catch (const std::exception &e) {
            FFI_LOG(ffi, "%s", e.what());
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }
    /* unlock the secret key if needed */
    bool locked = revoker->is_locked();
    if (locked && !revoker->unlock(ffi->pass_provider)) {
        FFI_LOG(ffi, "Failed to unlock secret key");
        return RNP_ERROR_BAD_PASSWORD;
    }
    *sig = transferable_key_revoke(key->pkt(), revoker->pkt(), halg, revinfo);
    if (!*sig) {
        FFI_LOG(ffi, "Failed to generate revocation signature");
    }
    if (locked) {
        revoker->lock();
    }
    return *sig ? RNP_SUCCESS : RNP_ERROR_BAD_STATE;
}

rnp_result_t
rnp_key_export_revocation(rnp_key_handle_t key,
                          rnp_output_t     output,
                          uint32_t         flags,
                          const char *     hash,
                          const char *     code,
                          const char *     reason)
try {
    if (!key || !key->ffi || !output) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (flags) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    pgp_key_t *exkey = get_key_prefer_public(key);
    if (!exkey || !exkey->is_primary()) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_key_t *revoker = rnp_key_get_revoker(key);
    if (!revoker) {
        FFI_LOG(key->ffi, "Revoker secret key not found");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    pgp_signature_t *sig = NULL;
    rnp_result_t     ret =
      rnp_key_get_revocation(key->ffi, exkey, revoker, hash, code, reason, &sig);
    if (ret) {
        return ret;
    }

    sig->write(output->dst);
    ret = output->dst.werr;
    dst_flush(&output->dst);
    output->keep = !ret;
    delete sig;
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_key_revoke(
  rnp_key_handle_t key, uint32_t flags, const char *hash, const char *code, const char *reason)
try {
    if (!key || !key->ffi) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (flags) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    pgp_key_t *exkey = get_key_prefer_public(key);
    if (!exkey) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_key_t *revoker = rnp_key_get_revoker(key);
    if (!revoker) {
        FFI_LOG(key->ffi, "Revoker secret key not found");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    pgp_signature_t *sig = NULL;
    rnp_result_t     ret =
      rnp_key_get_revocation(key->ffi, exkey, revoker, hash, code, reason, &sig);
    if (ret) {
        return ret;
    }
    pgp_sig_import_status_t pub_status = PGP_SIG_IMPORT_STATUS_UNKNOWN_KEY;
    pgp_sig_import_status_t sec_status = PGP_SIG_IMPORT_STATUS_UNKNOWN_KEY;
    if (key->pub) {
        pub_status = rnp_key_store_import_key_signature(key->ffi->pubring, key->pub, sig);
    }
    if (key->sec) {
        sec_status = rnp_key_store_import_key_signature(key->ffi->secring, key->sec, sig);
    }
    delete sig;

    if ((pub_status == PGP_SIG_IMPORT_STATUS_UNKNOWN) ||
        (sec_status == PGP_SIG_IMPORT_STATUS_UNKNOWN)) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_remove(rnp_key_handle_t key, uint32_t flags)
try {
    if (!key || !key->ffi) {
        return RNP_ERROR_NULL_POINTER;
    }
    bool pub = false;
    if (flags & RNP_KEY_REMOVE_PUBLIC) {
        pub = true;
        flags &= ~RNP_KEY_REMOVE_PUBLIC;
    }
    bool sec = false;
    if (flags & RNP_KEY_REMOVE_SECRET) {
        sec = true;
        flags &= ~RNP_KEY_REMOVE_SECRET;
    }
    bool sub = false;
    if (flags & RNP_KEY_REMOVE_SUBKEYS) {
        sub = true;
        flags &= ~RNP_KEY_REMOVE_SUBKEYS;
    }
    if (flags) {
        FFI_LOG(key->ffi, "Unknown flags: %" PRIu32, flags);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!pub && !sec) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (sub && get_key_prefer_public(key)->is_subkey()) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (pub) {
        if (!key->ffi->pubring || !key->pub) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        if (!rnp_key_store_remove_key(key->ffi->pubring, key->pub, sub)) {
            return RNP_ERROR_KEY_NOT_FOUND;
        }
        key->pub = NULL;
    }
    if (sec) {
        if (!key->ffi->secring || !key->sec) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        if (!rnp_key_store_remove_key(key->ffi->secring, key->sec, sub)) {
            return RNP_ERROR_KEY_NOT_FOUND;
        }
        key->sec = NULL;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

static void
report_signature_removal(rnp_ffi_t             ffi,
                         const pgp_key_t &     key,
                         rnp_key_signatures_cb sigcb,
                         void *                app_ctx,
                         pgp_subsig_t &        keysig,
                         bool &                remove)
{
    if (!sigcb) {
        return;
    }
    rnp_signature_handle_t sig = (rnp_signature_handle_t) calloc(1, sizeof(*sig));
    if (!sig) {
        FFI_LOG(ffi, "Signature handle allocation failed.");
        return;
    }
    sig->ffi = ffi;
    sig->key = &key;
    sig->sig = &keysig;
    uint32_t action = remove ? RNP_KEY_SIGNATURE_REMOVE : RNP_KEY_SIGNATURE_KEEP;
    sigcb(ffi, app_ctx, sig, &action);
    switch (action) {
    case RNP_KEY_SIGNATURE_REMOVE:
        remove = true;
        break;
    case RNP_KEY_SIGNATURE_KEEP:
        remove = false;
        break;
    default:
        FFI_LOG(ffi, "Invalid signature removal action: %" PRIu32, action);
        break;
    }
    rnp_signature_handle_destroy(sig);
}

static bool
signature_needs_removal(rnp_ffi_t ffi, const pgp_key_t &key, pgp_subsig_t &sig, uint32_t flags)
{
    /* quick check for non-self signatures */
    bool nonself = flags & RNP_KEY_SIGNATURE_NON_SELF_SIG;
    if (nonself && key.is_primary() && !key.is_signer(sig)) {
        return true;
    }
    if (nonself && key.is_subkey()) {
        pgp_key_t *primary = rnp_key_store_get_primary_key(ffi->pubring, &key);
        if (primary && !primary->is_signer(sig)) {
            return true;
        }
    }
    /* unknown signer */
    pgp_key_t *signer = pgp_sig_get_signer(sig, ffi->pubring, &ffi->key_provider);
    if (!signer && (flags & RNP_KEY_SIGNATURE_UNKNOWN_KEY)) {
        return true;
    }
    /* validate signature if didn't */
    if (signer && !sig.validated()) {
        signer->validate_sig(key, sig);
    }
    /* we cannot check for invalid/expired if sig was not validated */
    if (!sig.validated()) {
        return false;
    }
    if ((flags & RNP_KEY_SIGNATURE_INVALID) && !sig.validity.valid) {
        return true;
    }
    return false;
}

static void
remove_key_signatures(rnp_ffi_t             ffi,
                      pgp_key_t &           pub,
                      pgp_key_t *           sec,
                      uint32_t              flags,
                      rnp_key_signatures_cb sigcb,
                      void *                app_ctx)
{
    std::vector<pgp_sig_id_t> sigs;

    for (size_t idx = 0; idx < pub.sig_count(); idx++) {
        pgp_subsig_t &sig = pub.get_sig(idx);
        bool          remove = signature_needs_removal(ffi, pub, sig, flags);
        report_signature_removal(ffi, pub, sigcb, app_ctx, sig, remove);
        if (remove) {
            sigs.push_back(sig.sigid);
        }
    }
    size_t deleted = pub.del_sigs(sigs);
    if (deleted != sigs.size()) {
        FFI_LOG(ffi, "Invalid deleted sigs count: %zu instead of %zu.", deleted, sigs.size());
    }
    /* delete from the secret key if any */
    if (sec && (sec != &pub)) {
        sec->del_sigs(sigs);
    }
}

rnp_result_t
rnp_key_remove_signatures(rnp_key_handle_t      handle,
                          uint32_t              flags,
                          rnp_key_signatures_cb sigcb,
                          void *                app_ctx)
try {
    if (!handle) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!flags && !sigcb) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    uint32_t origflags = flags;
    if (flags & RNP_KEY_SIGNATURE_INVALID) {
        flags &= ~RNP_KEY_SIGNATURE_INVALID;
    }
    if (flags & RNP_KEY_SIGNATURE_NON_SELF_SIG) {
        flags &= ~RNP_KEY_SIGNATURE_NON_SELF_SIG;
    }
    if (flags & RNP_KEY_SIGNATURE_UNKNOWN_KEY) {
        flags &= ~RNP_KEY_SIGNATURE_UNKNOWN_KEY;
    }
    if (flags) {
        FFI_LOG(handle->ffi, "Invalid flags: %" PRIu32, flags);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    flags = origflags;

    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* process key itself */
    pgp_key_t *sec = get_key_require_secret(handle);
    remove_key_signatures(handle->ffi, *key, sec, flags, sigcb, app_ctx);

    /* process subkeys */
    for (size_t idx = 0; key->is_primary() && (idx < key->subkey_count()); idx++) {
        pgp_key_t *sub = pgp_key_get_subkey(key, handle->ffi->pubring, idx);
        if (!sub) {
            FFI_LOG(handle->ffi, "Failed to get subkey at idx %zu.", idx);
            continue;
        }
        pgp_key_t *subsec = rnp_key_store_get_key_by_fpr(handle->ffi->secring, sub->fp());
        remove_key_signatures(handle->ffi, *sub, subsec, flags, sigcb, app_ctx);
    }
    /* revalidate key/subkey */
    key->revalidate(*handle->ffi->pubring);
    if (sec) {
        sec->revalidate(*handle->ffi->secring);
    }
    return RNP_SUCCESS;
}
FFI_GUARD

static bool
pk_alg_allows_custom_curve(pgp_pubkey_alg_t pkalg)
{
    switch (pkalg) {
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
        return true;
    default:
        return false;
    }
}

static bool
parse_preferences(json_object *jso, pgp_user_prefs_t &prefs)
{
    static const struct {
        const char *   key;
        enum json_type type;
    } properties[] = {{"hashes", json_type_array},
                      {"ciphers", json_type_array},
                      {"compression", json_type_array},
                      {"key server", json_type_string}};

    for (size_t iprop = 0; iprop < ARRAY_SIZE(properties); iprop++) {
        json_object *value = NULL;
        const char * key = properties[iprop].key;

        if (!json_object_object_get_ex(jso, key, &value)) {
            continue;
        }

        if (!json_object_is_type(value, properties[iprop].type)) {
            return false;
        }
        try {
            if (!rnp_strcasecmp(key, "hashes")) {
                int length = json_object_array_length(value);
                for (int i = 0; i < length; i++) {
                    json_object *item = json_object_array_get_idx(value, i);
                    if (!json_object_is_type(item, json_type_string)) {
                        return false;
                    }
                    pgp_hash_alg_t hash_alg = PGP_HASH_UNKNOWN;
                    if (!str_to_hash_alg(json_object_get_string(item), &hash_alg)) {
                        return false;
                    }
                    prefs.add_hash_alg(hash_alg);
                }
            } else if (!rnp_strcasecmp(key, "ciphers")) {
                int length = json_object_array_length(value);
                for (int i = 0; i < length; i++) {
                    json_object *item = json_object_array_get_idx(value, i);
                    if (!json_object_is_type(item, json_type_string)) {
                        return false;
                    }
                    pgp_symm_alg_t symm_alg = PGP_SA_UNKNOWN;
                    if (!str_to_cipher(json_object_get_string(item), &symm_alg)) {
                        return false;
                    }
                    prefs.add_symm_alg(symm_alg);
                }
            } else if (!rnp_strcasecmp(key, "compression")) {
                int length = json_object_array_length(value);
                for (int i = 0; i < length; i++) {
                    json_object *item = json_object_array_get_idx(value, i);
                    if (!json_object_is_type(item, json_type_string)) {
                        return false;
                    }
                    pgp_compression_type_t z_alg = PGP_C_UNKNOWN;
                    if (!str_to_compression_alg(json_object_get_string(item), &z_alg)) {
                        return false;
                    }
                    prefs.add_z_alg(z_alg);
                }
            } else if (!rnp_strcasecmp(key, "key server")) {
                prefs.key_server = json_object_get_string(value);
            }
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return false;
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return true;
}

static bool
parse_keygen_crypto(json_object *jso, rnp_keygen_crypto_params_t *crypto)
{
    static const struct {
        const char *   key;
        enum json_type type;
    } properties[] = {{"type", json_type_string},
                      {"curve", json_type_string},
                      {"length", json_type_int},
                      {"hash", json_type_string}};

    for (size_t i = 0; i < ARRAY_SIZE(properties); i++) {
        json_object *value = NULL;
        const char * key = properties[i].key;

        if (!json_object_object_get_ex(jso, key, &value)) {
            continue;
        }

        if (!json_object_is_type(value, properties[i].type)) {
            return false;
        }
        // TODO: make sure there are no duplicate keys in the JSON
        if (!rnp_strcasecmp(key, "type")) {
            if (!str_to_pubkey_alg(json_object_get_string(value), &crypto->key_alg)) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "length")) {
            int length = json_object_get_int(value);
            switch (crypto->key_alg) {
            case PGP_PKA_RSA:
                crypto->rsa.modulus_bit_len = length;
                break;
            case PGP_PKA_DSA:
                crypto->dsa.p_bitlen = length;
                break;
            case PGP_PKA_ELGAMAL:
                crypto->elgamal.key_bitlen = length;
                break;
            default:
                return false;
            }
        } else if (!rnp_strcasecmp(key, "curve")) {
            if (!pk_alg_allows_custom_curve(crypto->key_alg)) {
                return false;
            }
            if (!curve_str_to_type(json_object_get_string(value), &crypto->ecc.curve)) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "hash")) {
            if (!str_to_hash_alg(json_object_get_string(value), &crypto->hash_alg)) {
                return false;
            }
        } else {
            // shouldn't happen
            return false;
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return true;
}

static bool
parse_protection(json_object *jso, rnp_key_protection_params_t *protection)
{
    static const struct {
        const char *   key;
        enum json_type type;
    } properties[] = {{"cipher", json_type_string},
                      {"mode", json_type_string},
                      {"iterations", json_type_int},
                      {"hash", json_type_string}};

    for (size_t i = 0; i < ARRAY_SIZE(properties); i++) {
        json_object *value = NULL;
        const char * key = properties[i].key;

        if (!json_object_object_get_ex(jso, key, &value)) {
            continue;
        }

        if (!json_object_is_type(value, properties[i].type)) {
            return false;
        }
        // TODO: make sure there are no duplicate keys in the JSON
        if (!rnp_strcasecmp(key, "cipher")) {
            if (!str_to_cipher(json_object_get_string(value), &protection->symm_alg)) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "mode")) {
            if (!str_to_cipher_mode(json_object_get_string(value), &protection->cipher_mode)) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "iterations")) {
            protection->iterations = json_object_get_int(value);
        } else if (!rnp_strcasecmp(key, "hash")) {
            if (!str_to_hash_alg(json_object_get_string(value), &protection->hash_alg)) {
                return false;
            }
        } else {
            // shouldn't happen
            return false;
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return true;
}

static bool
parse_keygen_primary(json_object *jso, rnp_action_keygen_t *desc)
{
    static const char *properties[] = {
      "userid", "usage", "expiration", "preferences", "protection"};
    rnp_selfsig_cert_info_t *cert = &desc->primary.keygen.cert;

    if (!parse_keygen_crypto(jso, &desc->primary.keygen.crypto)) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(properties); i++) {
        json_object *value = NULL;
        const char * key = properties[i];

        if (!json_object_object_get_ex(jso, key, &value)) {
            continue;
        }
        if (!rnp_strcasecmp(key, "userid")) {
            if (!json_object_is_type(value, json_type_string)) {
                return false;
            }
            const char *userid = json_object_get_string(value);
            size_t      userid_len = strlen(userid);
            if (userid_len >= sizeof(cert->userid)) {
                return false;
            }
            memcpy(cert->userid, userid, userid_len + 1);
        } else if (!rnp_strcasecmp(key, "usage")) {
            switch (json_object_get_type(value)) {
            case json_type_array: {
                int length = json_object_array_length(value);
                for (int j = 0; j < length; j++) {
                    json_object *item = json_object_array_get_idx(value, j);
                    if (!json_object_is_type(item, json_type_string)) {
                        return false;
                    }
                    uint8_t flag = 0;
                    if (!str_to_key_flag(json_object_get_string(item), &flag)) {
                        return false;
                    }
                    // check for duplicate
                    if (cert->key_flags & flag) {
                        return false;
                    }
                    cert->key_flags |= flag;
                }
            } break;
            case json_type_string: {
                if (!str_to_key_flag(json_object_get_string(value), &cert->key_flags)) {
                    return false;
                }
            } break;
            default:
                return false;
            }
        } else if (!rnp_strcasecmp(key, "expiration")) {
            if (!json_object_is_type(value, json_type_int)) {
                return false;
            }
            cert->key_expiration = json_object_get_int(value);
        } else if (!rnp_strcasecmp(key, "preferences")) {
            if (!json_object_is_type(value, json_type_object)) {
                return false;
            }
            if (!parse_preferences(value, cert->prefs)) {
                return false;
            }
            if (json_object_object_length(value) != 0) {
                return false;
            }
        } else if (!rnp_strcasecmp(key, "protection")) {
            if (!json_object_is_type(value, json_type_object)) {
                return false;
            }
            if (!parse_protection(value, &desc->primary.protection)) {
                return false;
            }
            if (json_object_object_length(value) != 0) {
                return false;
            }
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return json_object_object_length(jso) == 0;
}

static bool
parse_keygen_sub(json_object *jso, rnp_action_keygen_t *desc)
{
    static const char *         properties[] = {"usage", "expiration", "protection"};
    rnp_selfsig_binding_info_t *binding = &desc->subkey.keygen.binding;

    if (!parse_keygen_crypto(jso, &desc->subkey.keygen.crypto)) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(properties); i++) {
        json_object *value = NULL;
        const char * key = properties[i];

        if (!json_object_object_get_ex(jso, key, &value)) {
            continue;
        }
        if (!rnp_strcasecmp(key, "usage")) {
            switch (json_object_get_type(value)) {
            case json_type_array: {
                int length = json_object_array_length(value);
                for (int j = 0; j < length; j++) {
                    json_object *item = json_object_array_get_idx(value, j);
                    if (!json_object_is_type(item, json_type_string)) {
                        return false;
                    }
                    uint8_t flag = 0;
                    if (!str_to_key_flag(json_object_get_string(item), &flag)) {
                        return false;
                    }
                    if (binding->key_flags & flag) {
                        return false;
                    }
                    binding->key_flags |= flag;
                }
            } break;
            case json_type_string: {
                if (!str_to_key_flag(json_object_get_string(value), &binding->key_flags)) {
                    return false;
                }
            } break;
            default:
                return false;
            }
        } else if (!rnp_strcasecmp(key, "expiration")) {
            if (!json_object_is_type(value, json_type_int)) {
                return false;
            }
            binding->key_expiration = json_object_get_int(value);
        } else if (!rnp_strcasecmp(key, "protection")) {
            if (!json_object_is_type(value, json_type_object)) {
                return false;
            }
            if (!parse_protection(value, &desc->subkey.protection)) {
                return false;
            }
            if (json_object_object_length(value) != 0) {
                return false;
            }
        }
        // delete this field since it has been handled
        json_object_object_del(jso, key);
    }
    return json_object_object_length(jso) == 0;
}

static bool
gen_json_grips(char **result, const pgp_key_t *primary, const pgp_key_t *sub)
{
    bool         ret = false;
    json_object *jso = NULL;
    char         grip[PGP_KEY_GRIP_SIZE * 2 + 1];

    if (!result) {
        return false;
    }

    jso = json_object_new_object();
    if (!jso) {
        return false;
    }

    if (primary) {
        json_object *jsoprimary = json_object_new_object();
        if (!jsoprimary) {
            goto done;
        }
        json_object_object_add(jso, "primary", jsoprimary);
        if (!rnp::hex_encode(
              primary->grip().data(), primary->grip().size(), grip, sizeof(grip))) {
            goto done;
        }
        json_object *jsogrip = json_object_new_string(grip);
        if (!jsogrip) {
            goto done;
        }
        json_object_object_add(jsoprimary, "grip", jsogrip);
    }
    if (sub) {
        json_object *jsosub = json_object_new_object();
        if (!jsosub) {
            goto done;
        }
        json_object_object_add(jso, "sub", jsosub);
        if (!rnp::hex_encode(sub->grip().data(), sub->grip().size(), grip, sizeof(grip))) {
            goto done;
        }
        json_object *jsogrip = json_object_new_string(grip);
        if (!jsogrip) {
            goto done;
        }
        json_object_object_add(jsosub, "grip", jsogrip);
    }
    *result = strdup(json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY));

    ret = true;
done:
    json_object_put(jso);
    return ret;
}

rnp_result_t
rnp_generate_key_json(rnp_ffi_t ffi, const char *json, char **results)
try {
    rnp_result_t        ret = RNP_ERROR_GENERIC;
    json_object *       jso = NULL;
    rnp_action_keygen_t keygen_desc = {};
    char *              identifier_type = NULL;
    char *              identifier = NULL;
    pgp_key_t           primary_pub;
    pgp_key_t           primary_sec;
    pgp_key_t           sub_pub;
    pgp_key_t           sub_sec;
    json_object *       jsoprimary = NULL;
    json_object *       jsosub = NULL;
    json_tokener_error  error;

    // checks
    if (!ffi || !ffi->secring || !json) {
        return RNP_ERROR_NULL_POINTER;
    }

    // parse the JSON
    jso = json_tokener_parse_verbose(json, &error);
    if (!jso) {
        // syntax error or some other issue
        FFI_LOG(ffi, "Invalid JSON: %s", json_tokener_error_desc(error));
        ret = RNP_ERROR_BAD_FORMAT;
        goto done;
    }

    // locate the appropriate sections
    {
        json_object_object_foreach(jso, key, value)
        {
            json_object **dest = NULL;

            if (rnp_strcasecmp(key, "primary") == 0) {
                dest = &jsoprimary;
            } else if (rnp_strcasecmp(key, "sub") == 0) {
                dest = &jsosub;
            } else {
                // unrecognized key in the object
                FFI_LOG(ffi, "Unexpected key in JSON: %s", key);
                ret = RNP_ERROR_BAD_PARAMETERS;
                goto done;
            }

            // duplicate "primary"/"sub"
            if (*dest) {
                ret = RNP_ERROR_BAD_PARAMETERS;
                goto done;
            }
            *dest = value;
        }
    }

    if (jsoprimary && jsosub) { // generating primary+sub
        if (!parse_keygen_primary(jsoprimary, &keygen_desc) ||
            !parse_keygen_sub(jsosub, &keygen_desc)) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }
        if (!pgp_generate_keypair(&ffi->rng,
                                  &keygen_desc.primary.keygen,
                                  &keygen_desc.subkey.keygen,
                                  true,
                                  &primary_sec,
                                  &primary_pub,
                                  &sub_sec,
                                  &sub_pub,
                                  ffi->secring->format)) {
            goto done;
        }
        if (results && !gen_json_grips(results, &primary_pub, &sub_pub)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        if (ffi->pubring) {
            if (!rnp_key_store_add_key(ffi->pubring, &primary_pub)) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto done;
            }
            if (!rnp_key_store_add_key(ffi->pubring, &sub_pub)) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto done;
            }
        }
        /* add key/subkey protection */
        if (keygen_desc.primary.protection.symm_alg &&
            !primary_sec.protect(keygen_desc.primary.protection, ffi->pass_provider)) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }

        if (keygen_desc.subkey.protection.symm_alg &&
            !sub_sec.protect(keygen_desc.subkey.protection, ffi->pass_provider)) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }

        if (!rnp_key_store_add_key(ffi->secring, &primary_sec)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        if (!rnp_key_store_add_key(ffi->secring, &sub_sec)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    } else if (jsoprimary && !jsosub) { // generating primary only
        keygen_desc.primary.keygen.crypto.rng = &ffi->rng;
        if (!parse_keygen_primary(jsoprimary, &keygen_desc)) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }
        if (!pgp_generate_primary_key(&keygen_desc.primary.keygen,
                                      true,
                                      &primary_sec,
                                      &primary_pub,
                                      ffi->secring->format)) {
            goto done;
        }
        if (results && !gen_json_grips(results, &primary_pub, NULL)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        if (ffi->pubring) {
            if (!rnp_key_store_add_key(ffi->pubring, &primary_pub)) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto done;
            }
        }
        /* encrypt secret key if specified */
        if (keygen_desc.primary.protection.symm_alg &&
            !primary_sec.protect(keygen_desc.primary.protection, ffi->pass_provider)) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }

        if (!rnp_key_store_add_key(ffi->secring, &primary_sec)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    } else if (jsosub) { // generating subkey only
        if (!ffi->pubring) {
            ret = RNP_ERROR_NULL_POINTER;
            goto done;
        }
        json_object *jsoparent = NULL;
        if (!json_object_object_get_ex(jsosub, "primary", &jsoparent) ||
            json_object_object_length(jsoparent) != 1) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }
        json_object_object_foreach(jsoparent, key, value)
        {
            if (!json_object_is_type(value, json_type_string)) {
                ret = RNP_ERROR_BAD_PARAMETERS;
                goto done;
            }
            identifier_type = strdup(key);
            identifier = strdup(json_object_get_string(value));
        }
        if (!identifier_type || !identifier) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        rnp_strlwr(identifier_type);
        json_object_object_del(jsosub, "primary");

        pgp_key_search_t locator = {(pgp_key_search_type_t) 0};
        rnp_result_t     tmpret = str_to_locator(ffi, &locator, identifier_type, identifier);
        if (tmpret) {
            ret = tmpret;
            goto done;
        }

        pgp_key_t *primary_pub = rnp_key_store_search(ffi->pubring, &locator, NULL);
        pgp_key_t *primary_sec = rnp_key_store_search(ffi->secring, &locator, NULL);
        if (!primary_sec || !primary_pub) {
            ret = RNP_ERROR_KEY_NOT_FOUND;
            goto done;
        }
        if (!parse_keygen_sub(jsosub, &keygen_desc)) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }
        keygen_desc.subkey.keygen.crypto.rng = &ffi->rng;
        if (!pgp_generate_subkey(&keygen_desc.subkey.keygen,
                                 true,
                                 primary_sec,
                                 primary_pub,
                                 &sub_sec,
                                 &sub_pub,
                                 &ffi->pass_provider,
                                 ffi->secring->format)) {
            goto done;
        }
        if (results && !gen_json_grips(results, NULL, &sub_pub)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        if (ffi->pubring) {
            if (!rnp_key_store_add_key(ffi->pubring, &sub_pub)) {
                ret = RNP_ERROR_OUT_OF_MEMORY;
                goto done;
            }
        }
        /* encrypt subkey if specified */
        if (keygen_desc.subkey.protection.symm_alg &&
            !sub_sec.protect(keygen_desc.subkey.protection, ffi->pass_provider)) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }

        if (!rnp_key_store_add_key(ffi->secring, &sub_sec)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    } else {
        // nothing to generate...
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    json_object_put(jso);
    free(identifier_type);
    free(identifier);
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_generate_key_ex(rnp_ffi_t         ffi,
                    const char *      key_alg,
                    const char *      sub_alg,
                    uint32_t          key_bits,
                    uint32_t          sub_bits,
                    const char *      key_curve,
                    const char *      sub_curve,
                    const char *      userid,
                    const char *      password,
                    rnp_key_handle_t *key)
try {
    rnp_op_generate_t op = NULL;
    rnp_op_generate_t subop = NULL;
    rnp_key_handle_t  primary = NULL;
    rnp_key_handle_t  subkey = NULL;
    rnp_result_t      ret = RNP_ERROR_KEY_GENERATION;

    /* generate primary key */
    if ((ret = rnp_op_generate_create(&op, ffi, key_alg))) {
        return ret;
    }
    if (key_bits && (ret = rnp_op_generate_set_bits(op, key_bits))) {
        goto done;
    }
    if (key_curve && (ret = rnp_op_generate_set_curve(op, key_curve))) {
        goto done;
    }
    if ((ret = rnp_op_generate_set_userid(op, userid))) {
        goto done;
    }
    if ((ret = rnp_op_generate_add_usage(op, "sign"))) {
        goto done;
    }
    if ((ret = rnp_op_generate_add_usage(op, "certify"))) {
        goto done;
    }
    if ((ret = rnp_op_generate_execute(op))) {
        goto done;
    }
    if ((ret = rnp_op_generate_get_key(op, &primary))) {
        goto done;
    }
    /* generate subkey if requested */
    if (!sub_alg) {
        goto done;
    }
    if ((ret = rnp_op_generate_subkey_create(&subop, ffi, primary, sub_alg))) {
        goto done;
    }
    if (sub_bits && (ret = rnp_op_generate_set_bits(subop, sub_bits))) {
        goto done;
    }
    if (sub_curve && (ret = rnp_op_generate_set_curve(subop, sub_curve))) {
        goto done;
    }
    if (password && (ret = rnp_op_generate_set_protection_password(subop, password))) {
        goto done;
    }
    if ((ret = rnp_op_generate_add_usage(subop, "encrypt"))) {
        goto done;
    }
    if ((ret = rnp_op_generate_execute(subop))) {
        goto done;
    }
    if ((ret = rnp_op_generate_get_key(subop, &subkey))) {
        goto done;
    }
done:
    /* only now will protect the primary key - to not spend time on unlocking to sign
     * subkey */
    if (!ret && password) {
        ret = rnp_key_protect(primary, password, NULL, NULL, NULL, 0);
    }
    if (ret && primary) {
        rnp_key_remove(primary, RNP_KEY_REMOVE_PUBLIC | RNP_KEY_REMOVE_SECRET);
    }
    if (ret && subkey) {
        rnp_key_remove(subkey, RNP_KEY_REMOVE_PUBLIC | RNP_KEY_REMOVE_SECRET);
    }
    if (!ret && key) {
        *key = primary;
    } else {
        rnp_key_handle_destroy(primary);
    }
    rnp_key_handle_destroy(subkey);
    rnp_op_generate_destroy(op);
    rnp_op_generate_destroy(subop);
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_generate_key_rsa(rnp_ffi_t         ffi,
                     uint32_t          bits,
                     uint32_t          subbits,
                     const char *      userid,
                     const char *      password,
                     rnp_key_handle_t *key)
try {
    return rnp_generate_key_ex(ffi,
                               RNP_ALGNAME_RSA,
                               subbits ? RNP_ALGNAME_RSA : NULL,
                               bits,
                               subbits,
                               NULL,
                               NULL,
                               userid,
                               password,
                               key);
}
FFI_GUARD

rnp_result_t
rnp_generate_key_dsa_eg(rnp_ffi_t         ffi,
                        uint32_t          bits,
                        uint32_t          subbits,
                        const char *      userid,
                        const char *      password,
                        rnp_key_handle_t *key)
try {
    return rnp_generate_key_ex(ffi,
                               RNP_ALGNAME_DSA,
                               subbits ? RNP_ALGNAME_ELGAMAL : NULL,
                               bits,
                               subbits,
                               NULL,
                               NULL,
                               userid,
                               password,
                               key);
}
FFI_GUARD

rnp_result_t
rnp_generate_key_ec(rnp_ffi_t         ffi,
                    const char *      curve,
                    const char *      userid,
                    const char *      password,
                    rnp_key_handle_t *key)
try {
    return rnp_generate_key_ex(
      ffi, RNP_ALGNAME_ECDSA, RNP_ALGNAME_ECDH, 0, 0, curve, curve, userid, password, key);
}
FFI_GUARD

rnp_result_t
rnp_generate_key_25519(rnp_ffi_t         ffi,
                       const char *      userid,
                       const char *      password,
                       rnp_key_handle_t *key)
try {
    return rnp_generate_key_ex(ffi,
                               RNP_ALGNAME_EDDSA,
                               RNP_ALGNAME_ECDH,
                               0,
                               0,
                               NULL,
                               "Curve25519",
                               userid,
                               password,
                               key);
}
FFI_GUARD

rnp_result_t
rnp_generate_key_sm2(rnp_ffi_t         ffi,
                     const char *      userid,
                     const char *      password,
                     rnp_key_handle_t *key)
try {
    return rnp_generate_key_ex(
      ffi, RNP_ALGNAME_SM2, RNP_ALGNAME_SM2, 0, 0, NULL, NULL, userid, password, key);
}
FFI_GUARD

static pgp_key_flags_t
default_key_flags(pgp_pubkey_alg_t alg, bool subkey)
{
    switch (alg) {
    case PGP_PKA_RSA:
        return subkey ? PGP_KF_ENCRYPT : pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY);
    case PGP_PKA_DSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
        return subkey ? PGP_KF_SIGN : pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY);
    case PGP_PKA_SM2:
        return subkey ? PGP_KF_ENCRYPT : pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY);
    case PGP_PKA_ECDH:
    case PGP_PKA_ELGAMAL:
        return PGP_KF_ENCRYPT;
    default:
        return PGP_KF_NONE;
    }
}

rnp_result_t
rnp_op_generate_create(rnp_op_generate_t *op, rnp_ffi_t ffi, const char *alg)
try {
    pgp_pubkey_alg_t key_alg = PGP_PKA_NOTHING;

    if (!op || !ffi || !alg) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (!ffi->pubring || !ffi->secring) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!str_to_pubkey_alg(alg, &key_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!(pgp_pk_alg_capabilities(key_alg) & PGP_KF_SIGN)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    *op = new rnp_op_generate_st();
    (*op)->ffi = ffi;
    (*op)->primary = true;
    (*op)->crypto.key_alg = key_alg;
    (*op)->crypto.rng = &ffi->rng;
    (*op)->cert.key_flags = default_key_flags(key_alg, false);

    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_subkey_create(rnp_op_generate_t *op,
                              rnp_ffi_t          ffi,
                              rnp_key_handle_t   primary,
                              const char *       alg)
try {
    if (!op || !ffi || !alg || !primary) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (!ffi->pubring || !ffi->secring) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* TODO: should we do these checks here or may leave it up till generate call? */
    bool flag = false;
    if (rnp_key_have_secret(primary, &flag) || !flag) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (rnp_key_is_primary(primary, &flag) || !flag) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!primary->sec->can_sign()) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    pgp_pubkey_alg_t key_alg = PGP_PKA_NOTHING;
    if (!str_to_pubkey_alg(alg, &key_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    *op = new rnp_op_generate_st();
    (*op)->ffi = ffi;
    (*op)->primary = false;
    (*op)->crypto.key_alg = key_alg;
    (*op)->crypto.rng = &ffi->rng;
    (*op)->binding.key_flags = default_key_flags(key_alg, true);
    (*op)->primary_sec = primary->sec;
    (*op)->primary_pub = primary->pub;

    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_set_bits(rnp_op_generate_t op, uint32_t bits)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }

    switch (op->crypto.key_alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        op->crypto.rsa.modulus_bit_len = bits;
        break;
    case PGP_PKA_ELGAMAL:
        op->crypto.elgamal.key_bitlen = bits;
        break;
    case PGP_PKA_DSA:
        op->crypto.dsa.p_bitlen = bits;
        break;
    default:
        return RNP_ERROR_BAD_PARAMETERS;
    }

    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_set_hash(rnp_op_generate_t op, const char *hash)
try {
    if (!op || !hash) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!str_to_hash_alg(hash, &op->crypto.hash_alg)) {
        FFI_LOG(op->ffi, "Invalid hash: %s", hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_set_dsa_qbits(rnp_op_generate_t op, uint32_t qbits)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (op->crypto.key_alg != PGP_PKA_DSA) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    op->crypto.dsa.q_bitlen = qbits;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_set_curve(rnp_op_generate_t op, const char *curve)
try {
    if (!op || !curve) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!pk_alg_allows_custom_curve(op->crypto.key_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!curve_str_to_type(curve, &op->crypto.ecc.curve)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_set_protection_password(rnp_op_generate_t op, const char *password)
try {
    if (!op || !password) {
        return RNP_ERROR_NULL_POINTER;
    }
    op->password.assign(password, password + strlen(password) + 1);
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_set_request_password(rnp_op_generate_t op, bool request)
try {
    if (!op || !request) {
        return RNP_ERROR_NULL_POINTER;
    }
    op->request_password = request;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_set_protection_cipher(rnp_op_generate_t op, const char *cipher)
try {
    if (!op || !cipher) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!str_to_cipher(cipher, &op->protection.symm_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_set_protection_hash(rnp_op_generate_t op, const char *hash)
try {
    if (!op || !hash) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!str_to_hash_alg(hash, &op->protection.hash_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_set_protection_mode(rnp_op_generate_t op, const char *mode)
try {
    if (!op || !mode) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!str_to_cipher_mode(mode, &op->protection.cipher_mode)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_set_protection_iterations(rnp_op_generate_t op, uint32_t iterations)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    op->protection.iterations = iterations;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_add_usage(rnp_op_generate_t op, const char *usage)
try {
    if (!op || !usage) {
        return RNP_ERROR_NULL_POINTER;
    }
    uint8_t flag = 0;
    if (!str_to_key_flag(usage, &flag)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!(pgp_pk_alg_capabilities(op->crypto.key_alg) & flag)) {
        return RNP_ERROR_NOT_SUPPORTED;
    }
    if (op->primary) {
        op->cert.key_flags |= flag;
    } else {
        op->binding.key_flags |= flag;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_clear_usage(rnp_op_generate_t op)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (op->primary) {
        op->cert.key_flags = 0;
    } else {
        op->binding.key_flags = 0;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_set_userid(rnp_op_generate_t op, const char *userid)
try {
    if (!op || !userid) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    size_t userid_len = strlen(userid);
    if (userid_len >= sizeof(op->cert.userid)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    memcpy(op->cert.userid, userid, userid_len + 1);
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_set_expiration(rnp_op_generate_t op, uint32_t expiration)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (op->primary) {
        op->cert.key_expiration = expiration;
    } else {
        op->binding.key_expiration = expiration;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_clear_pref_hashes(rnp_op_generate_t op)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    op->cert.prefs.set_hash_algs({});
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_add_pref_hash(rnp_op_generate_t op, const char *hash)
try {
    if (!op || !hash) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_hash_alg_t hash_alg = PGP_HASH_UNKNOWN;
    if (!str_to_hash_alg(hash, &hash_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    op->cert.prefs.add_hash_alg(hash_alg);
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_clear_pref_compression(rnp_op_generate_t op)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    op->cert.prefs.set_z_algs({});
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_add_pref_compression(rnp_op_generate_t op, const char *compression)
try {
    if (!op || !compression) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_compression_type_t z_alg = PGP_C_UNKNOWN;
    if (!str_to_compression_alg(compression, &z_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    op->cert.prefs.add_z_alg(z_alg);
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_clear_pref_ciphers(rnp_op_generate_t op)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    op->cert.prefs.set_symm_algs({});
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_add_pref_cipher(rnp_op_generate_t op, const char *cipher)
try {
    if (!op || !cipher) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_symm_alg_t symm_alg = PGP_SA_UNKNOWN;
    if (!str_to_cipher(cipher, &symm_alg)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    op->cert.prefs.add_symm_alg(symm_alg);
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_set_pref_keyserver(rnp_op_generate_t op, const char *keyserver)
try {
    if (!op) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->primary) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    op->cert.prefs.key_server = keyserver ? keyserver : "";
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_execute(rnp_op_generate_t op)
try {
    if (!op || !op->ffi) {
        return RNP_ERROR_NULL_POINTER;
    }

    rnp_result_t            ret = RNP_ERROR_GENERIC;
    pgp_key_t               pub;
    pgp_key_t               sec;
    pgp_password_provider_t prov = {.callback = NULL};

    if (op->primary) {
        rnp_keygen_primary_desc_t keygen = {};
        keygen.crypto = op->crypto;
        keygen.cert = op->cert;
        op->cert.prefs = {}; /* generate call will free prefs */

        if (!pgp_generate_primary_key(&keygen, true, &sec, &pub, op->ffi->secring->format)) {
            return RNP_ERROR_KEY_GENERATION;
        }
    } else {
        /* subkey generation */
        rnp_keygen_subkey_desc_t keygen = {};
        keygen.crypto = op->crypto;
        keygen.binding = op->binding;
        if (!pgp_generate_subkey(&keygen,
                                 true,
                                 op->primary_sec,
                                 op->primary_pub,
                                 &sec,
                                 &pub,
                                 &op->ffi->pass_provider,
                                 op->ffi->secring->format)) {
            return RNP_ERROR_KEY_GENERATION;
        }
    }

    /* add public key part to the keyring */
    if (!(op->gen_pub = rnp_key_store_add_key(op->ffi->pubring, &pub))) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    /* encrypt secret key if requested */
    if (!op->password.empty()) {
        prov = {.callback = rnp_password_provider_string,
                .userdata = (void *) op->password.data()};
    } else if (op->request_password) {
        prov = {.callback = rnp_password_cb_bounce, .userdata = op->ffi};
    }
    if (prov.callback && !sec.protect(op->protection, prov)) {
        FFI_LOG(op->ffi, "failed to encrypt the key");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    /* add secret key to the keyring */
    if (!(op->gen_sec = rnp_key_store_add_key(op->ffi->secring, &sec))) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    ret = RNP_SUCCESS;
done:
    op->password.clear();
    if (ret && op->gen_pub) {
        rnp_key_store_remove_key(op->ffi->pubring, op->gen_pub, false);
        op->gen_pub = NULL;
    }
    if (ret && op->gen_sec) {
        rnp_key_store_remove_key(op->ffi->secring, op->gen_sec, false);
        op->gen_sec = NULL;
    }
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_get_key(rnp_op_generate_t op, rnp_key_handle_t *handle)
try {
    if (!op || !handle) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!op->gen_sec || !op->gen_pub) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    *handle = (rnp_key_handle_t) malloc(sizeof(**handle));
    if (!*handle) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    (*handle)->ffi = op->ffi;
    (*handle)->pub = op->gen_pub;
    (*handle)->sec = op->gen_sec;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_op_generate_destroy(rnp_op_generate_t op)
try {
    delete op;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_handle_destroy(rnp_key_handle_t key)
try {
    // This does not free key->key which is owned by the keyring
    free(key);
    return RNP_SUCCESS;
}
FFI_GUARD

void
rnp_buffer_destroy(void *ptr)
{
    free(ptr);
}

void
rnp_buffer_clear(void *ptr, size_t size)
{
    if (ptr) {
        secure_clear(ptr, size);
    }
}

static pgp_key_t *
get_key_require_public(rnp_key_handle_t handle)
{
    if (!handle->pub) {
        pgp_key_request_ctx_t request;
        request.secret = false;

        // try fingerprint
        request.search.type = PGP_KEY_SEARCH_FINGERPRINT;
        request.search.by.fingerprint = handle->sec->fp();
        handle->pub = pgp_request_key(&handle->ffi->key_provider, &request);
        if (handle->pub) {
            return handle->pub;
        }

        // try keyid
        request.search.type = PGP_KEY_SEARCH_KEYID;
        request.search.by.keyid = handle->sec->keyid();
        handle->pub = pgp_request_key(&handle->ffi->key_provider, &request);
    }
    return handle->pub;
}

static pgp_key_t *
get_key_prefer_public(rnp_key_handle_t handle)
{
    pgp_key_t *pub = get_key_require_public(handle);
    return pub ? pub : get_key_require_secret(handle);
}

static pgp_key_t *
get_key_require_secret(rnp_key_handle_t handle)
{
    if (!handle->sec) {
        pgp_key_request_ctx_t request;
        request.secret = true;

        // try fingerprint
        request.search.type = PGP_KEY_SEARCH_FINGERPRINT;
        request.search.by.fingerprint = handle->pub->fp();
        handle->sec = pgp_request_key(&handle->ffi->key_provider, &request);
        if (handle->sec) {
            return handle->sec;
        }

        // try keyid
        request.search.type = PGP_KEY_SEARCH_KEYID;
        request.search.by.keyid = handle->pub->keyid();
        handle->sec = pgp_request_key(&handle->ffi->key_provider, &request);
    }
    return handle->sec;
}

static rnp_result_t
key_get_uid_at(pgp_key_t *key, size_t idx, char **uid)
{
    if (!key || !uid) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (idx >= key->uid_count()) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *uid = strdup(key->get_uid(idx).str.c_str());
    if (!*uid) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_add_uid(rnp_key_handle_t handle,
                const char *     uid,
                const char *     hash,
                uint32_t         expiration,
                uint8_t          key_flags,
                bool             primary)
try {
    rnp_result_t            ret = RNP_ERROR_GENERIC;
    rnp_selfsig_cert_info_t info = {};
    pgp_hash_alg_t          hash_alg = PGP_HASH_UNKNOWN;
    pgp_key_t *             public_key = NULL;
    pgp_key_t *             secret_key = NULL;
    pgp_key_pkt_t *         seckey = NULL;
    pgp_key_pkt_t *         decrypted_seckey = NULL;

    if (!handle || !uid) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (!hash) {
        hash = DEFAULT_HASH_ALG;
    }

    if (!str_to_hash_alg(hash, &hash_alg)) {
        FFI_LOG(handle->ffi, "Invalid hash: %s", hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    size_t uid_len = strlen(uid);
    if (uid_len >= sizeof(info.userid)) {
        FFI_LOG(handle->ffi, "UserID too long");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    memcpy(info.userid, uid, uid_len + 1);

    info.key_flags = key_flags;
    info.key_expiration = expiration;
    info.primary = primary;

    secret_key = get_key_require_secret(handle);
    if (!secret_key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    public_key = get_key_prefer_public(handle);
    if (!public_key && secret_key->format == PGP_KEY_STORE_G10) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    seckey = &secret_key->pkt();
    if (!seckey->material.secret) {
        pgp_password_ctx_t ctx = {.op = PGP_OP_ADD_USERID, .key = secret_key};
        decrypted_seckey = pgp_decrypt_seckey(secret_key, &handle->ffi->pass_provider, &ctx);
        if (!decrypted_seckey) {
            return RNP_ERROR_BAD_PASSWORD;
        }
        seckey = decrypted_seckey;
    }
    if (public_key && !pgp_key_add_userid_certified(public_key, seckey, hash_alg, &info)) {
        goto done;
    }
    if ((secret_key && secret_key->format != PGP_KEY_STORE_G10) &&
        !pgp_key_add_userid_certified(secret_key, seckey, hash_alg, &info)) {
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    delete decrypted_seckey;
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_key_get_primary_uid(rnp_key_handle_t handle, char **uid)
try {
    if (!handle || !uid) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *key = get_key_prefer_public(handle);
    if (key->has_primary_uid()) {
        return key_get_uid_at(key, key->get_primary_uid(), uid);
    }
    for (size_t i = 0; i < key->uid_count(); i++) {
        if (!key->get_uid(i).valid) {
            continue;
        }
        return key_get_uid_at(key, i, uid);
    }
    return RNP_ERROR_BAD_PARAMETERS;
}
FFI_GUARD

rnp_result_t
rnp_key_get_uid_count(rnp_key_handle_t handle, size_t *count)
try {
    if (!handle || !count) {
        return RNP_ERROR_NULL_POINTER;
    }

    *count = get_key_prefer_public(handle)->uid_count();
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_get_uid_at(rnp_key_handle_t handle, size_t idx, char **uid)
try {
    if (handle == NULL || uid == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_prefer_public(handle);
    return key_get_uid_at(key, idx, uid);
}
FFI_GUARD

rnp_result_t
rnp_key_get_uid_handle_at(rnp_key_handle_t key, size_t idx, rnp_uid_handle_t *uid)
try {
    if (!key || !uid) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *akey = get_key_prefer_public(key);
    if (!akey) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (idx >= akey->uid_count()) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    *uid = (rnp_uid_handle_t) malloc(sizeof(**uid));
    if (!*uid) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    (*uid)->ffi = key->ffi;
    (*uid)->key = akey;
    (*uid)->idx = idx;
    return RNP_SUCCESS;
}
FFI_GUARD

static pgp_userid_t *
rnp_uid_handle_get_uid(rnp_uid_handle_t uid)
{
    if (!uid || !uid->key) {
        return NULL;
    }
    return &uid->key->get_uid(uid->idx);
}

rnp_result_t
rnp_uid_get_type(rnp_uid_handle_t uid, uint32_t *type)
try {
    if (!type) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_userid_t *id = rnp_uid_handle_get_uid(uid);
    if (!id) {
        return RNP_ERROR_NULL_POINTER;
    }
    switch (id->pkt.tag) {
    case PGP_PKT_USER_ID:
        *type = RNP_USER_ID;
        return RNP_SUCCESS;
    case PGP_PKT_USER_ATTR:
        *type = RNP_USER_ATTR;
        return RNP_SUCCESS;
    default:
        return RNP_ERROR_BAD_STATE;
    }
}
FFI_GUARD

rnp_result_t
rnp_uid_get_data(rnp_uid_handle_t uid, void **data, size_t *size)
try {
    if (!data || !size) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_userid_t *id = rnp_uid_handle_get_uid(uid);
    if (!id) {
        return RNP_ERROR_NULL_POINTER;
    }
    *data = malloc(id->pkt.uid_len);
    if (id->pkt.uid_len && !*data) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    memcpy(*data, id->pkt.uid, id->pkt.uid_len);
    *size = id->pkt.uid_len;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_uid_is_primary(rnp_uid_handle_t uid, bool *primary)
try {
    if (!primary) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_userid_t *id = rnp_uid_handle_get_uid(uid);
    if (!id) {
        return RNP_ERROR_NULL_POINTER;
    }
    *primary = uid->key->has_primary_uid() && (uid->key->get_primary_uid() == uid->idx);
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_uid_is_valid(rnp_uid_handle_t uid, bool *valid)
try {
    if (!valid) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_userid_t *id = rnp_uid_handle_get_uid(uid);
    if (!id) {
        return RNP_ERROR_NULL_POINTER;
    }
    *valid = id->valid;
    return RNP_SUCCESS;
}
FFI_GUARD

static rnp_result_t
rnp_key_return_signature(rnp_ffi_t               ffi,
                         pgp_key_t *             key,
                         pgp_subsig_t *          subsig,
                         rnp_signature_handle_t *sig)
{
    *sig = (rnp_signature_handle_t) calloc(1, sizeof(**sig));
    if (!*sig) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    (*sig)->ffi = ffi;
    (*sig)->key = key;
    (*sig)->sig = subsig;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_signature_count(rnp_key_handle_t handle, size_t *count)
try {
    if (!handle || !count) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *count = key->keysig_count();
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_get_signature_at(rnp_key_handle_t handle, size_t idx, rnp_signature_handle_t *sig)
try {
    if (!handle || !sig) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key || (idx >= key->keysig_count())) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return rnp_key_return_signature(handle->ffi, key, &key->get_keysig(idx), sig);
}
FFI_GUARD

rnp_result_t
rnp_key_get_revocation_signature(rnp_key_handle_t handle, rnp_signature_handle_t *sig)
try {
    if (!handle || !sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!key->revoked()) {
        *sig = NULL;
        return RNP_SUCCESS;
    }
    if (!key->has_sig(key->revocation().sigid)) {
        return RNP_ERROR_BAD_STATE;
    }
    return rnp_key_return_signature(
      handle->ffi, key, &key->get_sig(key->revocation().sigid), sig);
}
FFI_GUARD

rnp_result_t
rnp_uid_get_signature_count(rnp_uid_handle_t handle, size_t *count)
try {
    if (!handle || !count) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!handle->key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *count = handle->key->get_uid(handle->idx).sig_count();
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_uid_get_signature_at(rnp_uid_handle_t handle, size_t idx, rnp_signature_handle_t *sig)
try {
    if (!handle || !sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!handle->key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_userid_t &uid = handle->key->get_uid(handle->idx);
    if (idx >= uid.sig_count()) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    const pgp_sig_id_t &sigid = uid.get_sig(idx);
    if (!handle->key->has_sig(sigid)) {
        return RNP_ERROR_BAD_STATE;
    }
    return rnp_key_return_signature(
      handle->ffi, handle->key, &handle->key->get_sig(sigid), sig);
}
FFI_GUARD

rnp_result_t
rnp_signature_get_type(rnp_signature_handle_t handle, char **type)
try {
    if (!handle || !type) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!handle->sig) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    const char *sigtype = "unknown";
    ARRAY_LOOKUP_BY_ID(sig_type_map, type, string, handle->sig->sig.type(), sigtype);
    return ret_str_value(sigtype, type);
}
FFI_GUARD

rnp_result_t
rnp_signature_get_alg(rnp_signature_handle_t handle, char **alg)
try {
    if (!handle || !alg) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!handle->sig) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return get_map_value(
      pubkey_alg_map, ARRAY_SIZE(pubkey_alg_map), handle->sig->sig.palg, alg);
}
FFI_GUARD

rnp_result_t
rnp_signature_get_hash_alg(rnp_signature_handle_t handle, char **alg)
try {
    if (!handle || !alg) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!handle->sig) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return get_map_value(hash_alg_map, ARRAY_SIZE(hash_alg_map), handle->sig->sig.halg, alg);
}
FFI_GUARD

rnp_result_t
rnp_signature_get_creation(rnp_signature_handle_t handle, uint32_t *create)
try {
    if (!handle || !create) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!handle->sig) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *create = handle->sig->sig.creation();
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_signature_get_keyid(rnp_signature_handle_t handle, char **result)
try {
    if (!handle || !result) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!handle->sig) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!handle->sig->sig.has_keyid()) {
        *result = NULL;
        return RNP_SUCCESS;
    }
    pgp_key_id_t keyid = handle->sig->sig.keyid();
    return hex_encode_value(keyid.data(), keyid.size(), result);
}
FFI_GUARD

rnp_result_t
rnp_signature_get_signer(rnp_signature_handle_t sig, rnp_key_handle_t *key)
try {
    char *       keyid = NULL;
    rnp_result_t ret = rnp_signature_get_keyid(sig, &keyid);
    if (ret) {
        return ret;
    }
    if (!keyid) {
        *key = NULL;
        return RNP_SUCCESS;
    }

    ret = rnp_locate_key(sig->ffi, "keyid", keyid, key);
    rnp_buffer_destroy(keyid);
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_signature_is_valid(rnp_signature_handle_t sig, uint32_t flags)
try {
    if (!sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!sig->sig || sig->own_sig || flags) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!sig->sig->validity.validated) {
        pgp_key_t *signer =
          pgp_sig_get_signer(*sig->sig, sig->ffi->pubring, &sig->ffi->key_provider);
        if (!signer) {
            return RNP_ERROR_KEY_NOT_FOUND;
        }
        signer->validate_sig(*sig->key, *sig->sig);
    }

    if (!sig->sig->validity.validated) {
        return RNP_ERROR_VERIFICATION_FAILED;
    }
    if (sig->sig->validity.expired) {
        return RNP_ERROR_SIGNATURE_EXPIRED;
    }
    return sig->sig->valid() ? RNP_SUCCESS : RNP_ERROR_SIGNATURE_INVALID;
}
FFI_GUARD

rnp_result_t
rnp_signature_packet_to_json(rnp_signature_handle_t sig, uint32_t flags, char **json)
try {
    if (!sig || !json) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_dest_t memdst = {};
    if (init_mem_dest(&memdst, NULL, 0)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    try {
        sig->sig->sig.write(memdst);
    } catch (const std::exception &e) {
        FFI_LOG(sig->ffi, "%s", e.what());
        dst_close(&memdst, true);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    pgp_source_t memsrc = {};
    rnp_result_t ret = RNP_ERROR_BAD_STATE;
    if (init_mem_src(&memsrc, mem_dest_get_memory(&memdst), memdst.writeb, false)) {
        goto done;
    }

    ret = rnp_dump_src_to_json(&memsrc, flags, json);
done:
    dst_close(&memdst, true);
    src_close(&memsrc);
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_signature_remove(rnp_key_handle_t key, rnp_signature_handle_t sig)
try {
    if (!key || !sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (sig->own_sig || !sig->sig) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_key_t *pkey = get_key_require_public(key);
    pgp_key_t *skey = get_key_require_secret(key);
    if (!pkey && !skey) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    const pgp_sig_id_t sigid = sig->sig->sigid;
    bool               ok = false;
    if (pkey) {
        ok = pkey->del_sig(sigid);
        pkey->revalidate(*key->ffi->pubring);
    }
    if (skey) {
        /* secret key may not have signature, but we still need to delete it at least once to
         * succeed */
        ok = skey->del_sig(sigid) || ok;
        skey->revalidate(*key->ffi->secring);
    }
    return ok ? RNP_SUCCESS : RNP_ERROR_NO_SIGNATURES_FOUND;
}
FFI_GUARD

rnp_result_t
rnp_signature_handle_destroy(rnp_signature_handle_t sig)
try {
    if (sig && sig->own_sig) {
        delete sig->sig;
    }
    free(sig);
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_uid_is_revoked(rnp_uid_handle_t uid, bool *result)
try {
    if (!uid || !result) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (!uid->key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    *result = uid->key->get_uid(uid->idx).revoked;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_uid_get_revocation_signature(rnp_uid_handle_t uid, rnp_signature_handle_t *sig)
try {
    if (!uid || !sig) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!uid->key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (uid->idx >= uid->key->uid_count()) {
        return RNP_ERROR_BAD_STATE;
    }
    const pgp_userid_t &userid = uid->key->get_uid(uid->idx);
    if (!userid.revoked) {
        *sig = NULL;
        return RNP_SUCCESS;
    }
    if (!uid->key->has_sig(userid.revocation.sigid)) {
        return RNP_ERROR_BAD_STATE;
    }
    return rnp_key_return_signature(
      uid->ffi, uid->key, &uid->key->get_sig(userid.revocation.sigid), sig);
}
FFI_GUARD

rnp_result_t
rnp_uid_remove(rnp_key_handle_t key, rnp_uid_handle_t uid)
try {
    if (!key || !uid) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *pkey = get_key_require_public(key);
    pgp_key_t *skey = get_key_require_secret(key);
    if (!pkey && !skey) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if ((uid->key != pkey) && (uid->key != skey)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    bool ok = false;
    if (pkey && (pkey->uid_count() > uid->idx)) {
        pkey->del_uid(uid->idx);
        pkey->revalidate(*key->ffi->pubring);
        ok = true;
    }
    if (skey && (skey->uid_count() > uid->idx)) {
        skey->del_uid(uid->idx);
        skey->revalidate(*key->ffi->secring);
        ok = true;
    }
    return ok ? RNP_SUCCESS : RNP_ERROR_BAD_PARAMETERS;
}
FFI_GUARD

rnp_result_t
rnp_uid_handle_destroy(rnp_uid_handle_t uid)
try {
    free(uid);
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_get_subkey_count(rnp_key_handle_t handle, size_t *count)
try {
    if (!handle || !count) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    *count = key->subkey_count();
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_get_subkey_at(rnp_key_handle_t handle, size_t idx, rnp_key_handle_t *subkey)
try {
    if (!handle || !subkey) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    if (idx >= key->subkey_count()) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    const pgp_fingerprint_t &fp = key->get_subkey_fp(idx);
    char                     fphex[PGP_FINGERPRINT_SIZE * 2 + 1] = {0};
    if (!rnp::hex_encode(fp.fingerprint, fp.length, fphex, sizeof(fphex))) {
        return RNP_ERROR_BAD_STATE;
    }
    return rnp_locate_key(handle->ffi, "fingerprint", fphex, subkey);
}
FFI_GUARD

rnp_result_t
rnp_key_get_alg(rnp_key_handle_t handle, char **alg)
try {
    if (!handle || !alg) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    return get_map_value(pubkey_alg_map, ARRAY_SIZE(pubkey_alg_map), key->alg(), alg);
}
FFI_GUARD

rnp_result_t
rnp_key_get_bits(rnp_key_handle_t handle, uint32_t *bits)
try {
    if (!handle || !bits) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    size_t     _bits = key->material().bits();
    if (!_bits) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *bits = _bits;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_get_dsa_qbits(rnp_key_handle_t handle, uint32_t *qbits)
try {
    if (!handle || !qbits) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    size_t     _qbits = key->material().qbits();
    if (!_qbits) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *qbits = _qbits;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_get_curve(rnp_key_handle_t handle, char **curve)
try {
    if (!handle || !curve) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t * key = get_key_prefer_public(handle);
    pgp_curve_t _curve = key->curve();
    if (_curve == PGP_CURVE_UNKNOWN) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    const char *curvename = NULL;
    if (!curve_type_to_str(_curve, &curvename)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    char *curvenamecp = strdup(curvename);
    if (!curvenamecp) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    *curve = curvenamecp;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_get_fprint(rnp_key_handle_t handle, char **fprint)
try {
    if (!handle || !fprint) {
        return RNP_ERROR_NULL_POINTER;
    }

    const pgp_fingerprint_t &fp = get_key_prefer_public(handle)->fp();
    return hex_encode_value(fp.fingerprint, fp.length, fprint);
}
FFI_GUARD

rnp_result_t
rnp_key_get_keyid(rnp_key_handle_t handle, char **keyid)
try {
    if (!handle || !keyid) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *key = get_key_prefer_public(handle);
    return hex_encode_value(key->keyid().data(), key->keyid().size(), keyid);
}
FFI_GUARD

rnp_result_t
rnp_key_get_grip(rnp_key_handle_t handle, char **grip)
try {
    if (!handle || !grip) {
        return RNP_ERROR_NULL_POINTER;
    }

    const pgp_key_grip_t &kgrip = get_key_prefer_public(handle)->grip();
    return hex_encode_value(kgrip.data(), kgrip.size(), grip);
}
FFI_GUARD

static const pgp_key_grip_t *
rnp_get_grip_by_fp(rnp_ffi_t ffi, const pgp_fingerprint_t &fp)
{
    pgp_key_t *key = NULL;
    if (ffi->pubring) {
        key = rnp_key_store_get_key_by_fpr(ffi->pubring, fp);
    }
    if (!key && ffi->secring) {
        key = rnp_key_store_get_key_by_fpr(ffi->secring, fp);
    }
    return key ? &key->grip() : NULL;
}

rnp_result_t
rnp_key_get_primary_grip(rnp_key_handle_t handle, char **grip)
try {
    if (!handle || !grip) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key->is_subkey()) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!key->has_primary_fp()) {
        *grip = NULL;
        return RNP_SUCCESS;
    }
    const pgp_key_grip_t *pgrip = rnp_get_grip_by_fp(handle->ffi, key->primary_fp());
    if (!pgrip) {
        *grip = NULL;
        return RNP_SUCCESS;
    }
    return hex_encode_value(pgrip->data(), pgrip->size(), grip);
}
FFI_GUARD

rnp_result_t
rnp_key_get_primary_fprint(rnp_key_handle_t handle, char **fprint)
try {
    if (!handle || !fprint) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key->is_subkey()) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!key->has_primary_fp()) {
        *fprint = NULL;
        return RNP_SUCCESS;
    }
    const pgp_fingerprint_t &fp = key->primary_fp();
    return hex_encode_value(fp.fingerprint, fp.length, fprint);
}
FFI_GUARD

rnp_result_t
rnp_key_allows_usage(rnp_key_handle_t handle, const char *usage, bool *result)
try {
    if (!handle || !usage || !result) {
        return RNP_ERROR_NULL_POINTER;
    }
    uint8_t flag = 0;
    if (!str_to_key_flag(usage, &flag)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *result = key->flags() & flag;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_get_creation(rnp_key_handle_t handle, uint32_t *result)
try {
    if (!handle || !result) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *result = key->creation();
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_is_revoked(rnp_key_handle_t handle, bool *result)
try {
    if (!handle || !result) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *result = key->revoked();
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_is_valid(rnp_key_handle_t handle, bool *result)
try {
    if (!handle || !result) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_require_public(handle);
    if (!key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!key->validated()) {
        key->validate(*handle->ffi->pubring);
    }
    if (!key->validated()) {
        return RNP_ERROR_VERIFICATION_FAILED;
    }
    *result = key->valid();
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_valid_till(rnp_key_handle_t handle, uint32_t *result)
try {
    if (!result) {
        return RNP_ERROR_NULL_POINTER;
    }
    uint64_t     res = 0;
    rnp_result_t ret = rnp_key_valid_till64(handle, &res);
    if (ret) {
        return ret;
    }
    if (res == UINT64_MAX) {
        *result = UINT32_MAX;
    } else if (res >= UINT32_MAX) {
        *result = UINT32_MAX - 1;
    } else {
        *result = (uint32_t) res;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_valid_till64(rnp_key_handle_t handle, uint64_t *result)
try {
    if (!handle || !result) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_require_public(handle);
    if (!key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!key->validated()) {
        key->validate(*handle->ffi->pubring);
    }
    if (!key->validated()) {
        return RNP_ERROR_VERIFICATION_FAILED;
    }

    if (key->is_subkey()) {
        /* check validity time of the primary key as well */
        pgp_key_t *primary = rnp_key_store_get_primary_key(handle->ffi->pubring, key);
        if (!primary) {
            /* no primary key - subkey considered as never valid */
            *result = 0;
            return RNP_SUCCESS;
        }
        if (!primary->validated()) {
            primary->validate(*handle->ffi->pubring);
        }
        if (!primary->validated()) {
            return RNP_ERROR_VERIFICATION_FAILED;
        }
        *result = key->valid_till();
    } else {
        *result = key->valid_till();
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_get_expiration(rnp_key_handle_t handle, uint32_t *result)
try {
    if (!handle || !result) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    *result = key->expiration();
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_set_expiration(rnp_key_handle_t key, uint32_t expiry)
try {
    if (!key) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *pkey = get_key_prefer_public(key);
    if (!pkey) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    pgp_key_t *skey = get_key_require_secret(key);
    if (!skey) {
        FFI_LOG(key->ffi, "Secret key required.");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (pkey->is_primary()) {
        if (!pgp_key_set_expiration(pkey, skey, expiry, key->ffi->pass_provider)) {
            return RNP_ERROR_GENERIC;
        }
        pkey->revalidate(*key->ffi->pubring);
        if (pkey != skey) {
            skey->revalidate(*key->ffi->secring);
        }
        return RNP_SUCCESS;
    }

    /* for subkey we need primary key */
    if (!pkey->has_primary_fp()) {
        FFI_LOG(key->ffi, "Primary key fp not available.");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    pgp_key_search_t search = {};
    search.type = PGP_KEY_SEARCH_FINGERPRINT;
    search.by.fingerprint = pkey->primary_fp();
    pgp_key_t *prim_sec = find_key(key->ffi, &search, KEY_TYPE_SECRET, true);
    if (!prim_sec) {
        FFI_LOG(key->ffi, "Primary secret key not found.");
        return RNP_ERROR_KEY_NOT_FOUND;
    }
    if (!pgp_subkey_set_expiration(pkey, prim_sec, skey, expiry, key->ffi->pass_provider)) {
        return RNP_ERROR_GENERIC;
    }
    prim_sec->revalidate(*key->ffi->secring);
    pgp_key_t *prim_pub = find_key(key->ffi, &search, KEY_TYPE_PUBLIC, true);
    if (prim_pub) {
        prim_pub->revalidate(*key->ffi->pubring);
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_get_revocation_reason(rnp_key_handle_t handle, char **result)
try {
    if (!handle || !result) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key || !key->revoked()) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    *result = strdup(key->revocation().reason.c_str());
    if (!*result) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

static rnp_result_t
rnp_key_is_revoked_with_code(rnp_key_handle_t handle, bool *result, int code)
{
    if (!handle || !result) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_prefer_public(handle);
    if (!key || !key->revoked()) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    *result = key->revocation().code == code;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_is_superseded(rnp_key_handle_t handle, bool *result)
try {
    return rnp_key_is_revoked_with_code(handle, result, PGP_REVOCATION_SUPERSEDED);
}
FFI_GUARD

rnp_result_t
rnp_key_is_compromised(rnp_key_handle_t handle, bool *result)
try {
    return rnp_key_is_revoked_with_code(handle, result, PGP_REVOCATION_COMPROMISED);
}
FFI_GUARD

rnp_result_t
rnp_key_is_retired(rnp_key_handle_t handle, bool *result)
try {
    return rnp_key_is_revoked_with_code(handle, result, PGP_REVOCATION_RETIRED);
}
FFI_GUARD

rnp_result_t
rnp_key_get_protection_type(rnp_key_handle_t key, char **type)
try {
    if (!key || !type) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!key->sec) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const pgp_s2k_t &s2k = key->sec->pkt().sec_protection.s2k;
    const char *     res = "Unknown";
    if (s2k.usage == PGP_S2KU_NONE) {
        res = "None";
    }
    if ((s2k.usage == PGP_S2KU_ENCRYPTED) && (s2k.specifier != PGP_S2KS_EXPERIMENTAL)) {
        res = "Encrypted";
    }
    if ((s2k.usage == PGP_S2KU_ENCRYPTED_AND_HASHED) &&
        (s2k.specifier != PGP_S2KS_EXPERIMENTAL)) {
        res = "Encrypted-Hashed";
    }
    if ((s2k.specifier == PGP_S2KS_EXPERIMENTAL) &&
        (s2k.gpg_ext_num == PGP_S2K_GPG_NO_SECRET)) {
        res = "GPG-None";
    }
    if ((s2k.specifier == PGP_S2KS_EXPERIMENTAL) &&
        (s2k.gpg_ext_num == PGP_S2K_GPG_SMARTCARD)) {
        res = "GPG-Smartcard";
    }

    return ret_str_value(res, type);
}
FFI_GUARD

rnp_result_t
rnp_key_get_protection_mode(rnp_key_handle_t key, char **mode)
try {
    if (!key || !mode) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!key->sec) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (key->sec->pkt().sec_protection.s2k.usage == PGP_S2KU_NONE) {
        return ret_str_value("None", mode);
    }
    if (key->sec->pkt().sec_protection.s2k.specifier == PGP_S2KS_EXPERIMENTAL) {
        return ret_str_value("Unknown", mode);
    }

    return get_map_value(cipher_mode_map,
                         ARRAY_SIZE(cipher_mode_map),
                         key->sec->pkt().sec_protection.cipher_mode,
                         mode);
}
FFI_GUARD

static bool
pgp_key_has_encryption_info(const pgp_key_t *key)
{
    return (key->pkt().sec_protection.s2k.usage != PGP_S2KU_NONE) &&
           (key->pkt().sec_protection.s2k.specifier != PGP_S2KS_EXPERIMENTAL);
}

rnp_result_t
rnp_key_get_protection_cipher(rnp_key_handle_t key, char **cipher)
try {
    if (!key || !cipher) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!key->sec) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!pgp_key_has_encryption_info(key->sec)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    return get_map_value(
      symm_alg_map, ARRAY_SIZE(symm_alg_map), key->sec->pkt().sec_protection.symm_alg, cipher);
}
FFI_GUARD

rnp_result_t
rnp_key_get_protection_hash(rnp_key_handle_t key, char **hash)
try {
    if (!key || !hash) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!key->sec) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!pgp_key_has_encryption_info(key->sec)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    return get_map_value(hash_alg_map,
                         ARRAY_SIZE(hash_alg_map),
                         key->sec->pkt().sec_protection.s2k.hash_alg,
                         hash);
}
FFI_GUARD

rnp_result_t
rnp_key_get_protection_iterations(rnp_key_handle_t key, size_t *iterations)
try {
    if (!key || !iterations) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!key->sec) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!pgp_key_has_encryption_info(key->sec)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (key->sec->pkt().sec_protection.s2k.specifier == PGP_S2KS_ITERATED_AND_SALTED) {
        *iterations = pgp_s2k_decode_iterations(key->sec->pkt().sec_protection.s2k.iterations);
    } else {
        *iterations = 1;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_is_locked(rnp_key_handle_t handle, bool *result)
try {
    if (handle == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    *result = key->is_locked();
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_lock(rnp_key_handle_t handle)
try {
    if (handle == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    if (!key->lock()) {
        return RNP_ERROR_GENERIC;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_unlock(rnp_key_handle_t handle, const char *password)
try {
    if (!handle) {
        return RNP_ERROR_NULL_POINTER;
    }
    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    bool ok = false;
    if (password) {
        pgp_password_provider_t prov = {.callback = rnp_password_provider_string,
                                        .userdata = RNP_CONST_TO_VOID_PTR(password)};
        ok = key->unlock(prov);
    } else {
        ok = key->unlock(handle->ffi->pass_provider);
    }
    if (!ok) {
        // likely a bad password
        return RNP_ERROR_BAD_PASSWORD;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_is_protected(rnp_key_handle_t handle, bool *result)
try {
    if (handle == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    *result = key->is_protected();
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_protect(rnp_key_handle_t handle,
                const char *     password,
                const char *     cipher,
                const char *     cipher_mode,
                const char *     hash,
                size_t           iterations)
try {
    rnp_key_protection_params_t protection = {};

    // checks
    if (!handle || !password) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (cipher && !str_to_cipher(cipher, &protection.symm_alg)) {
        FFI_LOG(handle->ffi, "Invalid cipher: %s", cipher);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (cipher_mode && !str_to_cipher_mode(cipher_mode, &protection.cipher_mode)) {
        FFI_LOG(handle->ffi, "Invalid cipher mode: %s", cipher_mode);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (hash && !str_to_hash_alg(hash, &protection.hash_alg)) {
        FFI_LOG(handle->ffi, "Invalid hash: %s", hash);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    protection.iterations = iterations;

    // get the key
    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    pgp_key_pkt_t *   decrypted_key = NULL;
    const std::string pass = password;
    if (key->encrypted()) {
        pgp_password_ctx_t ctx = {.op = PGP_OP_PROTECT, .key = key};
        decrypted_key = pgp_decrypt_seckey(key, &handle->ffi->pass_provider, &ctx);
        if (!decrypted_key) {
            return RNP_ERROR_GENERIC;
        }
    }
    bool res = key->protect(decrypted_key ? *decrypted_key : key->pkt(), protection, pass);
    delete decrypted_key;
    return res ? RNP_SUCCESS : RNP_ERROR_GENERIC;
}
FFI_GUARD

rnp_result_t
rnp_key_unprotect(rnp_key_handle_t handle, const char *password)
try {
    // checks
    if (!handle) {
        return RNP_ERROR_NULL_POINTER;
    }

    // get the key
    pgp_key_t *key = get_key_require_secret(handle);
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    bool ok = false;
    if (password) {
        pgp_password_provider_t prov = {.callback = rnp_password_provider_string,
                                        .userdata = RNP_CONST_TO_VOID_PTR(password)};
        ok = key->unprotect(prov);
    } else {
        ok = key->unprotect(handle->ffi->pass_provider);
    }
    if (!ok) {
        // likely a bad password
        return RNP_ERROR_BAD_PASSWORD;
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_is_primary(rnp_key_handle_t handle, bool *result)
try {
    if (handle == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_prefer_public(handle);
    if (key->format == PGP_KEY_STORE_G10) {
        // we can't currently determine this for a G10 secret key
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    *result = key->is_primary();
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_is_sub(rnp_key_handle_t handle, bool *result)
try {
    if (handle == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;

    pgp_key_t *key = get_key_prefer_public(handle);
    if (key->format == PGP_KEY_STORE_G10) {
        // we can't currently determine this for a G10 secret key
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    *result = key->is_subkey();
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_have_secret(rnp_key_handle_t handle, bool *result)
try {
    if (handle == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;

    *result = handle->sec != NULL;
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_key_have_public(rnp_key_handle_t handle, bool *result)
try {
    if (handle == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;
    *result = handle->pub != NULL;
    return RNP_SUCCESS;
}
FFI_GUARD

static rnp_result_t
key_to_bytes(pgp_key_t *key, uint8_t **buf, size_t *buf_len)
{
    pgp_dest_t memdst = {};

    if (init_mem_dest(&memdst, NULL, 0)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    key->write(memdst);
    if (memdst.werr) {
        dst_close(&memdst, true);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    *buf_len = memdst.writeb;
    *buf = (uint8_t *) mem_dest_own_memory(&memdst);
    dst_close(&memdst, true);
    if (*buf_len && !*buf) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_get_public_key_data(rnp_key_handle_t handle, uint8_t **buf, size_t *buf_len)
try {
    // checks
    if (!handle || !buf || !buf_len) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *key = handle->pub;
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    return key_to_bytes(key, buf, buf_len);
}
FFI_GUARD

rnp_result_t
rnp_get_secret_key_data(rnp_key_handle_t handle, uint8_t **buf, size_t *buf_len)
try {
    // checks
    if (!handle || !buf || !buf_len) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_key_t *key = handle->sec;
    if (!key) {
        return RNP_ERROR_NO_SUITABLE_KEY;
    }
    return key_to_bytes(key, buf, buf_len);
}
FFI_GUARD

static bool
add_json_string_field(json_object *jso, const char *key, const char *value)
{
    json_object *jsostr = json_object_new_string(value);
    if (!jsostr) {
        return false;
    }
    json_object_object_add(jso, key, jsostr);
    return true;
}

static bool
add_json_int_field(json_object *jso, const char *key, int32_t value)
{
    json_object *jsoval = json_object_new_int(value);
    if (!jsoval) {
        return false;
    }
    json_object_object_add(jso, key, jsoval);
    return true;
}

static bool
add_json_key_usage(json_object *jso, uint8_t key_flags)
{
    json_object *jsoarr = json_object_new_array();
    if (!jsoarr) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(key_usage_map); i++) {
        if (key_usage_map[i].mask & key_flags) {
            json_object *jsostr = json_object_new_string(key_usage_map[i].string);
            if (!jsostr) {
                json_object_put(jsoarr);
                return false;
            }
            json_object_array_add(jsoarr, jsostr);
        }
    }
    if (json_object_array_length(jsoarr)) {
        json_object_object_add(jso, "usage", jsoarr);
    } else {
        json_object_put(jsoarr);
    }
    return true;
}

static bool
add_json_key_flags(json_object *jso, uint8_t key_flags)
{
    json_object *jsoarr = json_object_new_array();
    if (!jsoarr) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(key_flags_map); i++) {
        if (key_flags_map[i].mask & key_flags) {
            json_object *jsostr = json_object_new_string(key_flags_map[i].string);
            if (!jsostr) {
                json_object_put(jsoarr);
                return false;
            }
            json_object_array_add(jsoarr, jsostr);
        }
    }
    if (json_object_array_length(jsoarr)) {
        json_object_object_add(jso, "flags", jsoarr);
    } else {
        json_object_put(jsoarr);
    }
    return true;
}

static rnp_result_t
add_json_mpis(json_object *jso, ...)
{
    va_list      ap;
    const char * name;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    va_start(ap, jso);
    while ((name = va_arg(ap, const char *))) {
        pgp_mpi_t *val = va_arg(ap, pgp_mpi_t *);
        if (!val) {
            ret = RNP_ERROR_BAD_PARAMETERS;
            goto done;
        }
        char *hex = mpi2hex(val);
        if (!hex) {
            // this could probably be other things
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        json_object *jsostr = json_object_new_string(hex);
        free(hex);
        if (!jsostr) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        json_object_object_add(jso, name, jsostr);
    }
    ret = RNP_SUCCESS;

done:
    va_end(ap);
    return ret;
}

static rnp_result_t
add_json_public_mpis(json_object *jso, pgp_key_t *key)
{
    const pgp_key_material_t &km = key->material();
    switch (km.alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return add_json_mpis(jso, "n", &km.rsa.n, "e", &km.rsa.e, NULL);
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        return add_json_mpis(jso, "p", &km.eg.p, "g", &km.eg.g, "y", &km.eg.y, NULL);
    case PGP_PKA_DSA:
        return add_json_mpis(
          jso, "p", &km.dsa.p, "q", &km.dsa.q, "g", &km.dsa.g, "y", &km.dsa.y, NULL);
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        return add_json_mpis(jso, "point", &km.ec.p, NULL);
    default:
        return RNP_ERROR_NOT_SUPPORTED;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
add_json_secret_mpis(json_object *jso, pgp_key_t *key)
{
    const pgp_key_material_t &km = key->material();
    switch (key->alg()) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return add_json_mpis(
          jso, "d", &km.rsa.d, "p", &km.rsa.p, "q", &km.rsa.q, "u", &km.rsa.u, NULL);
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        return add_json_mpis(jso, "x", &km.eg.x, NULL);
    case PGP_PKA_DSA:
        return add_json_mpis(jso, "x", &km.dsa.x, NULL);
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        return add_json_mpis(jso, "x", &km.ec.x, NULL);
    default:
        return RNP_ERROR_NOT_SUPPORTED;
    }
    return RNP_SUCCESS;
}

static rnp_result_t
add_json_sig_mpis(json_object *jso, const pgp_signature_t *sig)
{
    pgp_signature_material_t material = {};
    try {
        if (!sig->parse_material(material)) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    switch (sig->palg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return add_json_mpis(jso, "sig", &material.rsa.s, NULL);
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        return add_json_mpis(jso, "r", &material.eg.r, "s", &material.eg.s, NULL);
    case PGP_PKA_DSA:
        return add_json_mpis(jso, "r", &material.dsa.r, "s", &material.dsa.s, NULL);
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        return add_json_mpis(jso, "r", &material.ecc.r, "s", &material.ecc.s, NULL);
    default:
        // TODO: we could use info->unknown and add a hex string of raw data here
        return RNP_ERROR_NOT_SUPPORTED;
    }
    return RNP_SUCCESS;
}

static bool
add_json_user_prefs(json_object *jso, const pgp_user_prefs_t &prefs)
{
    // TODO: instead of using a string "Unknown" as a fallback for these,
    // we could add a string of hex/dec (or even an int)
    if (!prefs.symm_algs.empty()) {
        json_object *jsoarr = json_object_new_array();
        if (!jsoarr) {
            return false;
        }
        json_object_object_add(jso, "ciphers", jsoarr);
        for (auto alg : prefs.symm_algs) {
            const char *name = "Unknown";
            ARRAY_LOOKUP_BY_ID(symm_alg_map, type, string, alg, name);
            json_object *jsoname = json_object_new_string(name);
            if (!jsoname || json_object_array_add(jsoarr, jsoname)) {
                return false;
            }
        }
    }
    if (!prefs.hash_algs.empty()) {
        json_object *jsoarr = json_object_new_array();
        if (!jsoarr) {
            return false;
        }
        json_object_object_add(jso, "hashes", jsoarr);
        for (auto alg : prefs.hash_algs) {
            const char *name = "Unknown";
            ARRAY_LOOKUP_BY_ID(hash_alg_map, type, string, alg, name);
            json_object *jsoname = json_object_new_string(name);
            if (!jsoname || json_object_array_add(jsoarr, jsoname)) {
                return false;
            }
        }
    }
    if (!prefs.z_algs.empty()) {
        json_object *jsoarr = json_object_new_array();
        if (!jsoarr) {
            return false;
        }
        json_object_object_add(jso, "compression", jsoarr);
        for (auto alg : prefs.z_algs) {
            const char *name = "Unknown";
            ARRAY_LOOKUP_BY_ID(compress_alg_map, type, string, alg, name);
            json_object *jsoname = json_object_new_string(name);
            if (!jsoname || json_object_array_add(jsoarr, jsoname)) {
                return false;
            }
        }
    }
    if (!prefs.ks_prefs.empty()) {
        json_object *jsoarr = json_object_new_array();
        if (!jsoarr) {
            return false;
        }
        json_object_object_add(jso, "key server preferences", jsoarr);
        for (auto flag : prefs.ks_prefs) {
            const char *name = "Unknown";
            ARRAY_LOOKUP_BY_ID(key_server_prefs_map, type, string, flag, name);
            json_object *jsoname = json_object_new_string(name);
            if (!jsoname || json_object_array_add(jsoarr, jsoname)) {
                return false;
            }
        }
    }
    if (!prefs.key_server.empty()) {
        if (!add_json_string_field(jso, "key server", prefs.key_server.c_str())) {
            return false;
        }
    }
    return true;
}

static rnp_result_t
add_json_subsig(json_object *jso, bool is_sub, uint32_t flags, const pgp_subsig_t *subsig)
{
    // userid (if applicable)
    if (!is_sub) {
        json_object *jsouid = json_object_new_int(subsig->uid);
        if (!jsouid) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "userid", jsouid);
    }
    // trust
    json_object *jsotrust = json_object_new_object();
    if (!jsotrust) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "trust", jsotrust);
    // trust (level)
    json_object *jsotrust_level = json_object_new_int(subsig->trustlevel);
    if (!jsotrust_level) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jsotrust, "level", jsotrust_level);
    // trust (amount)
    json_object *jsotrust_amount = json_object_new_int(subsig->trustamount);
    if (!jsotrust_amount) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jsotrust, "amount", jsotrust_amount);
    // key flags (usage)
    if (!add_json_key_usage(jso, subsig->key_flags)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // key flags (other)
    if (!add_json_key_flags(jso, subsig->key_flags)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // preferences
    const pgp_user_prefs_t &prefs = subsig->prefs;
    if (!prefs.symm_algs.empty() || !prefs.hash_algs.empty() || !prefs.z_algs.empty() ||
        !prefs.ks_prefs.empty() || !prefs.key_server.empty()) {
        json_object *jsoprefs = json_object_new_object();
        if (!jsoprefs) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "preferences", jsoprefs);
        if (!add_json_user_prefs(jsoprefs, prefs)) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }
    const pgp_signature_t *sig = &subsig->sig;
    // version
    json_object *jsoversion = json_object_new_int(sig->version);
    if (!jsoversion) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "version", jsoversion);
    // signature type
    const char *type = "unknown";
    ARRAY_LOOKUP_BY_ID(sig_type_map, type, string, sig->type(), type);
    if (!add_json_string_field(jso, "type", type)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // signer key type
    const char *key_type = "unknown";
    ARRAY_LOOKUP_BY_ID(pubkey_alg_map, type, string, sig->palg, key_type);
    if (!add_json_string_field(jso, "key type", key_type)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // hash
    const char *hash = "unknown";
    ARRAY_LOOKUP_BY_ID(hash_alg_map, type, string, sig->halg, hash);
    if (!add_json_string_field(jso, "hash", hash)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // creation time
    json_object *jsocreation_time = json_object_new_int64(sig->creation());
    if (!jsocreation_time) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "creation time", jsocreation_time);
    // expiration (seconds)
    json_object *jsoexpiration = json_object_new_int64(sig->expiration());
    if (!jsoexpiration) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "expiration", jsoexpiration);
    // signer
    json_object *jsosigner = NULL;
    // TODO: add signer fingerprint as well (no support internally yet)
    if (sig->has_keyid()) {
        jsosigner = json_object_new_object();
        if (!jsosigner) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        char         keyid[PGP_KEY_ID_SIZE * 2 + 1];
        pgp_key_id_t signer = sig->keyid();
        if (!rnp::hex_encode(signer.data(), signer.size(), keyid, sizeof(keyid))) {
            return RNP_ERROR_GENERIC;
        }
        if (!add_json_string_field(jsosigner, "keyid", keyid)) {
            json_object_put(jsosigner);
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }
    json_object_object_add(jso, "signer", jsosigner);
    // mpis
    json_object *jsompis = NULL;
    if (flags & RNP_JSON_SIGNATURE_MPIS) {
        jsompis = json_object_new_object();
        if (!jsompis) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        rnp_result_t tmpret;
        if ((tmpret = add_json_sig_mpis(jsompis, sig))) {
            json_object_put(jsompis);
            return tmpret;
        }
    }
    json_object_object_add(jso, "mpis", jsompis);
    return RNP_SUCCESS;
}

static rnp_result_t
key_to_json(json_object *jso, rnp_key_handle_t handle, uint32_t flags)
{
    bool                      have_sec = handle->sec != NULL;
    bool                      have_pub = handle->pub != NULL;
    pgp_key_t *               key = get_key_prefer_public(handle);
    const char *              str = NULL;
    const pgp_key_material_t &material = key->material();

    // type
    ARRAY_LOOKUP_BY_ID(pubkey_alg_map, type, string, key->alg(), str);
    if (!str) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!add_json_string_field(jso, "type", str)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // length
    if (!add_json_int_field(jso, "length", key->material().bits())) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // curve / alg-specific items
    switch (key->alg()) {
    case PGP_PKA_ECDH: {
        const char *hash_name = NULL;
        ARRAY_LOOKUP_BY_ID(hash_alg_map, type, string, material.ec.kdf_hash_alg, hash_name);
        if (!hash_name) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        const char *cipher_name = NULL;
        ARRAY_LOOKUP_BY_ID(symm_alg_map, type, string, material.ec.key_wrap_alg, cipher_name);
        if (!cipher_name) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        json_object *jsohash = json_object_new_string(hash_name);
        if (!jsohash) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "kdf hash", jsohash);
        json_object *jsocipher = json_object_new_string(cipher_name);
        if (!jsocipher) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "key wrap cipher", jsocipher);
    } // fall through
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2: {
        const char *curve_name = NULL;
        if (!curve_type_to_str(material.ec.curve, &curve_name)) {
            return RNP_ERROR_BAD_PARAMETERS;
        }
        json_object *jsocurve = json_object_new_string(curve_name);
        if (!jsocurve) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "curve", jsocurve);
    } break;
    default:
        break;
    }

    // keyid
    char keyid[PGP_KEY_ID_SIZE * 2 + 1];
    if (!rnp::hex_encode(key->keyid().data(), key->keyid().size(), keyid, sizeof(keyid))) {
        return RNP_ERROR_GENERIC;
    }
    if (!add_json_string_field(jso, "keyid", keyid)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // fingerprint
    char fpr[PGP_FINGERPRINT_SIZE * 2 + 1];
    if (!rnp::hex_encode(key->fp().fingerprint, key->fp().length, fpr, sizeof(fpr))) {
        return RNP_ERROR_GENERIC;
    }
    if (!add_json_string_field(jso, "fingerprint", fpr)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // grip
    char grip[PGP_KEY_GRIP_SIZE * 2 + 1];
    if (!rnp::hex_encode(key->grip().data(), key->grip().size(), grip, sizeof(grip))) {
        return RNP_ERROR_GENERIC;
    }
    if (!add_json_string_field(jso, "grip", grip)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // revoked
    json_object *jsorevoked = json_object_new_boolean(key->revoked() ? true : false);
    if (!jsorevoked) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "revoked", jsorevoked);
    // creation time
    json_object *jsocreation_time = json_object_new_int64(key->creation());
    if (!jsocreation_time) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "creation time", jsocreation_time);
    // expiration
    json_object *jsoexpiration = json_object_new_int64(key->expiration());
    if (!jsoexpiration) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "expiration", jsoexpiration);
    // key flags (usage)
    if (!add_json_key_usage(jso, key->flags())) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // key flags (other)
    if (!add_json_key_flags(jso, key->flags())) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    // parent / subkeys
    if (key->is_primary()) {
        json_object *jsosubkeys_arr = json_object_new_array();
        if (!jsosubkeys_arr) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "subkey grips", jsosubkeys_arr);
        for (auto &subfp : key->subkey_fps()) {
            const pgp_key_grip_t *subgrip = rnp_get_grip_by_fp(handle->ffi, subfp);
            if (!subgrip) {
                continue;
            }
            if (!rnp::hex_encode(subgrip->data(), subgrip->size(), grip, sizeof(grip))) {
                return RNP_ERROR_GENERIC;
            }
            json_object *jsostr = json_object_new_string(grip);
            if (!jsostr || json_object_array_add(jsosubkeys_arr, jsostr)) {
                json_object_put(jsostr);
                return RNP_ERROR_OUT_OF_MEMORY;
            }
        }
    } else if (key->has_primary_fp()) {
        auto pgrip = rnp_get_grip_by_fp(handle->ffi, key->primary_fp());
        if (pgrip) {
            if (!rnp::hex_encode(pgrip->data(), pgrip->size(), grip, sizeof(grip))) {
                return RNP_ERROR_GENERIC;
            }
            if (!add_json_string_field(jso, "primary key grip", grip)) {
                return RNP_ERROR_OUT_OF_MEMORY;
            }
        }
    }
    // public
    json_object *jsopublic = json_object_new_object();
    if (!jsopublic) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "public key", jsopublic);
    json_object_object_add(
      jsopublic, "present", json_object_new_boolean(have_pub ? true : false));
    if (flags & RNP_JSON_PUBLIC_MPIS) {
        json_object *jsompis = json_object_new_object();
        if (!jsompis) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jsopublic, "mpis", jsompis);
        rnp_result_t tmpret;
        if ((tmpret = add_json_public_mpis(jsompis, key))) {
            return tmpret;
        }
    }
    // secret
    json_object *jsosecret = json_object_new_object();
    if (!jsosecret) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    json_object_object_add(jso, "secret key", jsosecret);
    json_object_object_add(
      jsosecret, "present", json_object_new_boolean(have_sec ? true : false));
    if (have_sec) {
        bool locked = handle->sec->is_locked();
        if (flags & RNP_JSON_SECRET_MPIS) {
            if (locked) {
                json_object_object_add(jsosecret, "mpis", NULL);
            } else {
                json_object *jsompis = json_object_new_object();
                if (!jsompis) {
                    return RNP_ERROR_OUT_OF_MEMORY;
                }
                json_object_object_add(jsosecret, "mpis", jsompis);
                rnp_result_t tmpret;
                if ((tmpret = add_json_secret_mpis(jsompis, handle->sec))) {
                    return tmpret;
                }
            }
        }
        json_object *jsolocked = json_object_new_boolean(locked ? true : false);
        if (!jsolocked) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jsosecret, "locked", jsolocked);
        json_object *jsoprotected =
          json_object_new_boolean(handle->sec->is_protected() ? true : false);
        if (!jsoprotected) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jsosecret, "protected", jsoprotected);
    }
    // userids
    if (key->is_primary()) {
        json_object *jsouids_arr = json_object_new_array();
        if (!jsouids_arr) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "userids", jsouids_arr);
        for (size_t i = 0; i < key->uid_count(); i++) {
            json_object *jsouid = json_object_new_string(key->get_uid(i).str.c_str());
            if (!jsouid || json_object_array_add(jsouids_arr, jsouid)) {
                json_object_put(jsouid);
                return RNP_ERROR_OUT_OF_MEMORY;
            }
        }
    }
    // signatures
    if (flags & RNP_JSON_SIGNATURES) {
        json_object *jsosigs_arr = json_object_new_array();
        if (!jsosigs_arr) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        json_object_object_add(jso, "signatures", jsosigs_arr);
        for (size_t i = 0; i < key->sig_count(); i++) {
            json_object *jsosig = json_object_new_object();
            if (!jsosig || json_object_array_add(jsosigs_arr, jsosig)) {
                json_object_put(jsosig);
                return RNP_ERROR_OUT_OF_MEMORY;
            }
            rnp_result_t tmpret;
            if ((tmpret =
                   add_json_subsig(jsosig, key->is_subkey(), flags, &key->get_sig(i)))) {
                return tmpret;
            }
        }
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_to_json(rnp_key_handle_t handle, uint32_t flags, char **result)
try {
    rnp_result_t ret = RNP_ERROR_GENERIC;
    json_object *jso = NULL;

    // checks
    if (!handle || !result) {
        return RNP_ERROR_NULL_POINTER;
    }
    jso = json_object_new_object();
    if (!jso) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    if ((ret = key_to_json(jso, handle, flags))) {
        goto done;
    }
    *result = (char *) json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY);
    if (!*result) {
        goto done;
    }
    *result = strdup(*result);
    if (!*result) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    json_object_put(jso);
    return ret;
}
FFI_GUARD

static rnp_result_t
rnp_dump_src_to_json(pgp_source_t *src, uint32_t flags, char **result)
{
    rnp_dump_ctx_t dumpctx = {};
    json_object *  jso = NULL;
    rnp_result_t   ret = RNP_ERROR_GENERIC;

    if (flags & RNP_JSON_DUMP_MPI) {
        dumpctx.dump_mpi = true;
        flags &= ~RNP_JSON_DUMP_MPI;
    }
    if (flags & RNP_JSON_DUMP_RAW) {
        dumpctx.dump_packets = true;
        flags &= ~RNP_JSON_DUMP_RAW;
    }
    if (flags & RNP_JSON_DUMP_GRIP) {
        dumpctx.dump_grips = true;
        flags &= ~RNP_JSON_DUMP_GRIP;
    }
    if (flags) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    ret = stream_dump_packets_json(&dumpctx, src, &jso);
    if (ret) {
        goto done;
    }

    *result = (char *) json_object_to_json_string_ext(jso, JSON_C_TO_STRING_PRETTY);
    if (!*result) {
        goto done;
    }
    *result = strdup(*result);
    if (!*result) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    ret = RNP_SUCCESS;
done:
    json_object_put(jso);
    return ret;
}

rnp_result_t
rnp_key_packets_to_json(rnp_key_handle_t handle, bool secret, uint32_t flags, char **result)
try {
    pgp_key_t *  key = NULL;
    rnp_result_t ret = RNP_ERROR_GENERIC;
    pgp_dest_t   memdst = {};
    pgp_source_t memsrc = {};

    if (!handle || !result) {
        return RNP_ERROR_NULL_POINTER;
    }

    key = secret ? handle->sec : handle->pub;
    if (!key || (key->format == PGP_KEY_STORE_G10)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (init_mem_dest(&memdst, NULL, 0)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    key->write(memdst);
    if (memdst.werr) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    if (init_mem_src(&memsrc, mem_dest_get_memory(&memdst), memdst.writeb, false)) {
        ret = RNP_ERROR_BAD_STATE;
        goto done;
    }

    ret = rnp_dump_src_to_json(&memsrc, flags, result);
done:
    dst_close(&memdst, true);
    src_close(&memsrc);
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_dump_packets_to_json(rnp_input_t input, uint32_t flags, char **result)
try {
    if (!input || !result) {
        return RNP_ERROR_NULL_POINTER;
    }

    return rnp_dump_src_to_json(&input->src, flags, result);
}
FFI_GUARD

rnp_result_t
rnp_dump_packets_to_output(rnp_input_t input, rnp_output_t output, uint32_t flags)
try {
    if (!input || !output) {
        return RNP_ERROR_NULL_POINTER;
    }

    rnp_dump_ctx_t dumpctx = {};

    if (flags & RNP_DUMP_MPI) {
        dumpctx.dump_mpi = true;
        flags &= ~RNP_DUMP_MPI;
    }
    if (flags & RNP_DUMP_RAW) {
        dumpctx.dump_packets = true;
        flags &= ~RNP_DUMP_RAW;
    }
    if (flags & RNP_DUMP_GRIP) {
        dumpctx.dump_grips = true;
        flags &= ~RNP_DUMP_GRIP;
    }
    if (flags) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    rnp_result_t ret = stream_dump_packets(&dumpctx, &input->src, &output->dst);
    output->keep = true;
    return ret;
}
FFI_GUARD

// move to next key
static bool
key_iter_next_key(rnp_identifier_iterator_t it)
{
    // check if we not reached the end of the ring
    *it->keyp = std::next(*it->keyp);
    if (*it->keyp != it->store->keys.end()) {
        it->uididx = 0;
        return true;
    }
    // if we are currently on pubring, switch to secring (if not empty)
    if (it->store == it->ffi->pubring && !it->ffi->secring->keys.empty()) {
        it->store = it->ffi->secring;
        *it->keyp = it->store->keys.begin();
        it->uididx = 0;
        return true;
    }
    // we've gone through both rings
    it->store = NULL;
    if (it->keyp) {
        delete it->keyp;
        it->keyp = NULL;
    }
    return false;
}

// move to next item (key or userid)
static bool
key_iter_next_item(rnp_identifier_iterator_t it)
{
    switch (it->type) {
    case PGP_KEY_SEARCH_KEYID:
    case PGP_KEY_SEARCH_FINGERPRINT:
    case PGP_KEY_SEARCH_GRIP:
        return key_iter_next_key(it);
    case PGP_KEY_SEARCH_USERID:
        it->uididx++;
        while (it->uididx >= (*it->keyp)->uid_count()) {
            if (!key_iter_next_key(it)) {
                return false;
            }
            it->uididx = 0;
        }
        break;
    default:
        assert(false);
        break;
    }
    return true;
}

static bool
key_iter_first_key(rnp_identifier_iterator_t it)
{
    if (rnp_key_store_get_key_count(it->ffi->pubring)) {
        it->store = it->ffi->pubring;
    } else if (rnp_key_store_get_key_count(it->ffi->secring)) {
        it->store = it->ffi->secring;
    } else {
        it->store = NULL;
        return false;
    }
    it->keyp = new std::list<pgp_key_t>::iterator(it->store->keys.begin());
    it->uididx = 0;
    return true;
}

static bool
key_iter_first_item(rnp_identifier_iterator_t it)
{
    switch (it->type) {
    case PGP_KEY_SEARCH_KEYID:
    case PGP_KEY_SEARCH_FINGERPRINT:
    case PGP_KEY_SEARCH_GRIP:
        return key_iter_first_key(it);
    case PGP_KEY_SEARCH_USERID:
        if (!key_iter_first_key(it)) {
            return false;
        }
        it->uididx = 0;
        while (it->uididx >= (*it->keyp)->uid_count()) {
            if (!key_iter_next_key(it)) {
                return false;
            }
        }
        break;
    default:
        assert(false);
        break;
    }
    return true;
}

static bool
key_iter_get_item(const rnp_identifier_iterator_t it, char *buf, size_t buf_len)
{
    const pgp_key_t *key = &**it->keyp;
    switch (it->type) {
    case PGP_KEY_SEARCH_KEYID: {
        if (!rnp::hex_encode(key->keyid().data(), key->keyid().size(), buf, buf_len)) {
            return false;
        }
        break;
    }
    case PGP_KEY_SEARCH_FINGERPRINT:
        if (!rnp::hex_encode(key->fp().fingerprint, key->fp().length, buf, buf_len)) {
            return false;
        }
        break;
    case PGP_KEY_SEARCH_GRIP:
        if (!rnp::hex_encode(key->grip().data(), key->grip().size(), buf, buf_len)) {
            return false;
        }
        break;
    case PGP_KEY_SEARCH_USERID: {
        if (it->uididx >= key->uid_count()) {
            return false;
        }
        const pgp_userid_t &uid = key->get_uid(it->uididx);
        if (uid.str.size() >= buf_len) {
            return false;
        }
        memcpy(buf, uid.str.c_str(), uid.str.size() + 1);
    } break;
    default:
        assert(false);
        break;
    }
    return true;
}

rnp_result_t
rnp_identifier_iterator_create(rnp_ffi_t                  ffi,
                               rnp_identifier_iterator_t *it,
                               const char *               identifier_type)
try {
    rnp_result_t                       ret = RNP_ERROR_GENERIC;
    struct rnp_identifier_iterator_st *obj = NULL;

    // checks
    if (!ffi || !it || !identifier_type) {
        return RNP_ERROR_NULL_POINTER;
    }
    // create iterator
    obj = (struct rnp_identifier_iterator_st *) calloc(1, sizeof(*obj));
    if (!obj) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    obj->ffi = ffi;
    // parse identifier type
    obj->type = PGP_KEY_SEARCH_UNKNOWN;
    ARRAY_LOOKUP_BY_STRCASE(identifier_type_map, string, type, identifier_type, obj->type);
    if (obj->type == PGP_KEY_SEARCH_UNKNOWN) {
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }
    obj->tbl = json_object_new_object();
    if (!obj->tbl) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    // move to first item (if any)
    key_iter_first_item(obj);
    *it = obj;

    ret = RNP_SUCCESS;
done:
    if (ret) {
        rnp_identifier_iterator_destroy(obj);
    }
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_identifier_iterator_next(rnp_identifier_iterator_t it, const char **identifier)
try {
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // checks
    if (!it || !identifier) {
        return RNP_ERROR_NULL_POINTER;
    }
    // initialize the result to NULL
    *identifier = NULL;
    // this means we reached the end of the rings
    if (!it->store) {
        return RNP_SUCCESS;
    }
    // get the item
    if (!key_iter_get_item(it, it->buf, sizeof(it->buf))) {
        return RNP_ERROR_GENERIC;
    }
    bool exists;
    bool iterator_valid = true;
    while ((exists = json_object_object_get_ex(it->tbl, it->buf, NULL))) {
        if (!((iterator_valid = key_iter_next_item(it)))) {
            break;
        }
        if (!key_iter_get_item(it, it->buf, sizeof(it->buf))) {
            return RNP_ERROR_GENERIC;
        }
    }
    // see if we actually found a new entry
    if (!exists) {
        // TODO: Newer json-c has a useful return value for json_object_object_add,
        // which doesn't require the json_object_object_get_ex check below.
        json_object_object_add(it->tbl, it->buf, NULL);
        if (!json_object_object_get_ex(it->tbl, it->buf, NULL)) {
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        *identifier = it->buf;
    }
    // prepare for the next one
    if (iterator_valid) {
        key_iter_next_item(it);
    }
    ret = RNP_SUCCESS;

done:
    if (ret) {
        *identifier = NULL;
    }
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_identifier_iterator_destroy(rnp_identifier_iterator_t it)
try {
    if (it) {
        json_object_put(it->tbl);
        if (it->keyp) {
            delete it->keyp;
        }
        free(it);
    }
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_guess_contents(rnp_input_t input, char **contents)
try {
    if (!input || !contents) {
        return RNP_ERROR_NULL_POINTER;
    }

    pgp_armored_msg_t msgtype = PGP_ARMORED_UNKNOWN;
    if (is_armored_source(&input->src)) {
        msgtype = rnp_armored_get_type(&input->src);
    } else {
        msgtype = rnp_armor_guess_type(&input->src);
    }
    const char *msg = "unknown";
    ARRAY_LOOKUP_BY_ID(armor_type_map, type, string, msgtype, msg);
    size_t len = strlen(msg);
    *contents = (char *) calloc(1, len + 1);
    if (!*contents) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    memcpy(*contents, msg, len);
    return RNP_SUCCESS;
}
FFI_GUARD

rnp_result_t
rnp_enarmor(rnp_input_t input, rnp_output_t output, const char *type)
try {
    pgp_armored_msg_t msgtype = PGP_ARMORED_UNKNOWN;
    if (!input || !output) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (type) {
        ARRAY_LOOKUP_BY_STRCASE(armor_type_map, string, type, type, msgtype);
        if (!msgtype) {
            RNP_LOG("Unsupported armor type: %s", type);
            return RNP_ERROR_BAD_PARAMETERS;
        }
    } else {
        msgtype = rnp_armor_guess_type(&input->src);
        if (!msgtype) {
            RNP_LOG("Unrecognized data to armor (try specifying a type)");
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }
    rnp_result_t ret = rnp_armor_source(&input->src, &output->dst, msgtype);
    output->keep = !ret;
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_dearmor(rnp_input_t input, rnp_output_t output)
try {
    if (!input || !output) {
        return RNP_ERROR_NULL_POINTER;
    }
    rnp_result_t ret = rnp_dearmor_source(&input->src, &output->dst);
    output->keep = !ret;
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_output_pipe(rnp_input_t input, rnp_output_t output)
try {
    if (!input || !output) {
        return RNP_ERROR_NULL_POINTER;
    }
    rnp_result_t ret = dst_write_src(&input->src, &output->dst);
    output->keep = !ret;
    return ret;
}
FFI_GUARD

rnp_result_t
rnp_output_armor_set_line_length(rnp_output_t output, size_t llen)
try {
    if (!output || !llen) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return armored_dst_set_line_length(&output->dst, llen);
}
FFI_GUARD
