/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

/** \file
 * packet related headers.
 */

#ifndef PACKET_H_
#define PACKET_H_

#include <time.h>
#include <stdint.h>

#include <rnp/rnp_def.h>
#include <repgp/rnp_repgp_def.h>
#include "types.h"
#include "defs.h"
#include "hash.h"
#include "errors.h"

#include "crypto/bn.h"
#include "crypto/dsa.h"
#include "crypto/rsa.h"
#include "crypto/elgamal.h"

/* structure to keep track of printing state variables */
typedef struct pgp_printstate_t {
    unsigned unarmoured;
    unsigned skipping;
    int      indent;
} pgp_printstate_t;

/** General-use structure for variable-length data
 */

typedef struct {
    size_t   len;
    uint8_t *contents;
    uint8_t  mmapped; /* contents need an munmap(2) */
} pgp_data_t;

/************************************/
/* Packet Tags - RFC4880, 4.2 */
/************************************/

/** Packet Tag - Bit 7 Mask (this bit is always set).
 * The first byte of a packet is the "Packet Tag".  It always
 * has bit 7 set.  This is the mask for it.
 *
 * \see RFC4880 4.2
 */
#define PGP_PTAG_ALWAYS_SET 0x80

/** Packet Tag - New Format Flag.
 * Bit 6 of the Packet Tag is the packet format indicator.
 * If it is set, the new format is used, if cleared the
 * old format is used.
 *
 * \see RFC4880 4.2
 */
#define PGP_PTAG_NEW_FORMAT 0x40

/** Old Packet Format: Mask for content tag.
 * In the old packet format bits 5 to 2 (including)
 * are the content tag.  This is the mask to apply
 * to the packet tag.  Note that you need to
 * shift by #PGP_PTAG_OF_CONTENT_TAG_SHIFT bits.
 *
 * \see RFC4880 4.2
 */
#define PGP_PTAG_OF_CONTENT_TAG_MASK 0x3c
/** Old Packet Format: Offset for the content tag.
 * As described at #PGP_PTAG_OF_CONTENT_TAG_MASK the
 * content tag needs to be shifted after being masked
 * out from the Packet Tag.
 *
 * \see RFC4880 4.2
 */
#define PGP_PTAG_OF_CONTENT_TAG_SHIFT 2
/** Old Packet Format: Mask for length type.
 * Bits 1 and 0 of the packet tag are the length type
 * in the old packet format.
 *
 * See #pgp_ptag_of_lt_t for the meaning of the values.
 *
 * \see RFC4880 4.2
 */
#define PGP_PTAG_OF_LENGTH_TYPE_MASK 0x03

/**
 * Maximal length of the OID in hex representation.
 *
 * \see RFC4880 bis01 - 9.2 ECC Curve OID
 */
#define MAX_CURVE_OID_HEX_LEN 9U

/* Maximum block size for symmetric crypto */
#define PGP_MAX_BLOCK_SIZE 16

/* Maximum key size for symmetric crypto */
#define PGP_MAX_KEY_SIZE 32

/* Salt size for hashing */
#define PGP_SALT_SIZE 8

/** Old Packet Format Lengths.
 * Defines the meanings of the 2 bits for length type in the
 * old packet format.
 *
 * \see RFC4880 4.2.1
 */
typedef enum {
    PGP_PTAG_OLD_LEN_1 = 0x00,            /* Packet has a 1 byte length -
                                           * header is 2 bytes long. */
    PGP_PTAG_OLD_LEN_2 = 0x01,            /* Packet has a 2 byte length -
                                           * header is 3 bytes long. */
    PGP_PTAG_OLD_LEN_4 = 0x02,            /* Packet has a 4 byte
                                           * length - header is 5 bytes
                                           * long. */
    PGP_PTAG_OLD_LEN_INDETERMINATE = 0x03 /* Packet has a
                                           * indeterminate length. */
} pgp_ptag_of_lt_t;

/** New Packet Format: Mask for content tag.
 * In the new packet format the 6 rightmost bits
 * are the content tag.  This is the mask to apply
 * to the packet tag.  Note that you need to
 * shift by #PGP_PTAG_NF_CONTENT_TAG_SHIFT bits.
 *
 * \see RFC4880 4.2
 */
#define PGP_PTAG_NF_CONTENT_TAG_MASK 0x3f
/** New Packet Format: Offset for the content tag.
 * As described at #PGP_PTAG_NF_CONTENT_TAG_MASK the
 * content tag needs to be shifted after being masked
 * out from the Packet Tag.
 *
 * \see RFC4880 4.2
 */
#define PGP_PTAG_NF_CONTENT_TAG_SHIFT 0

#define MDC_PKT_TAG 0xd3

enum {
    PGP_REVOCATION_NO_REASON = 0,
    PGP_REVOCATION_SUPERSEDED = 1,
    PGP_REVOCATION_COMPROMISED = 2,
    PGP_REVOCATION_RETIRED = 3,
    PGP_REVOCATION_NO_LONGER_VALID = 0x20
};

/** Structure to hold one error code */
typedef struct {
    pgp_errcode_t errcode;
} pgp_parser_errcode_t;

/** Structure to hold one packet tag.
 * \see RFC4880 4.2
 */
typedef struct {
    unsigned new_format;            /* Whether this packet tag is new
                                     * (1) or old format (0) */
    unsigned type;                  /* content_tag value - See
                                     * #pgp_content_enum for meanings */
    pgp_ptag_of_lt_t length_type;   /* Length type (#pgp_ptag_of_lt_t)
                                     * - only if this packet tag is old
                                     * format.  Set to 0 if new format. */
    unsigned length; /* The length of the packet.  This value
                 * is set when we read and compute the length
                 * information, not at the same moment we
                 * create the packet tag structure. Only
     * defined if #readc is set. */ /* XXX: Ben, is this correct? */
    unsigned position;              /* The position (within the
                                     * current reader) of the packet */
    unsigned size;                  /* number of bits */
} pgp_ptag_t;

/** Public Key Algorithm Numbers.
 * OpenPGP assigns a unique Algorithm Number to each algorithm that is part of OpenPGP.
 *
 * This lists algorithm numbers for public key algorithms.
 *
 * \see RFC4880 9.1
 */
typedef enum {
    PGP_PKA_NOTHING = 0,          /* No PKA */
    PGP_PKA_RSA = 1,              /* RSA (Encrypt or Sign) */
    PGP_PKA_RSA_ENCRYPT_ONLY = 2, /* RSA Encrypt-Only (deprecated -
                                   * \see RFC4880 13.5) */
    PGP_PKA_RSA_SIGN_ONLY = 3,    /* RSA Sign-Only (deprecated -
                                   * \see RFC4880 13.5) */
    PGP_PKA_ELGAMAL = 16,         /* Elgamal (Encrypt-Only) */
    PGP_PKA_DSA = 17,             /* DSA (Digital Signature Algorithm) */
    PGP_PKA_ECDH = 18,            /* ECDH public key algorithm */
    PGP_PKA_ECDSA = 19,           /* ECDSA public key algorithm [FIPS186-3] */
    PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN =
      20,                     /* Deprecated. Reserved (formerly Elgamal Encrypt or Sign) */
    PGP_PKA_RESERVED_DH = 21, /* Reserved for Diffie-Hellman
                               * (X9.42, as defined for
                               * IETF-S/MIME) */
    PGP_PKA_EDDSA = 22,       /* EdDSA from draft-ietf-openpgp-rfc4880bis */

    PGP_PKA_SM2_ENCRYPT = 98, /* SM2 encryption */
    PGP_PKA_SM2 = 99,         /* SM2 signatures */

    PGP_PKA_PRIVATE00 = 100, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE01 = 101, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE02 = 102, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE03 = 103, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE04 = 104, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE05 = 105, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE06 = 106, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE07 = 107, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE08 = 108, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE09 = 109, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE10 = 110  /* Private/Experimental Algorithm */
} pgp_pubkey_alg_t;

/**
 * Enumeration of elliptic curves used by PGP.
 *
 * \see RFC4880-bis01 9.2. ECC Curve OID
 *
 * Values in this enum correspond to order in ec_curve array (in ec.c)
 */
typedef enum {
    PGP_CURVE_UNKNOWN = 0,
    PGP_CURVE_NIST_P_256,
    PGP_CURVE_NIST_P_384,
    PGP_CURVE_NIST_P_521,
    PGP_CURVE_ED25519,

    PGP_CURVE_SM2_P_256,

    // Keep always last one
    PGP_CURVE_MAX
} pgp_curve_t;

/** Symmetric Key Algorithm Numbers.
 * OpenPGP assigns a unique Algorithm Number to each algorithm that is
 * part of OpenPGP.
 *
 * This lists algorithm numbers for symmetric key algorithms.
 *
 * \see RFC4880 9.2
 */
typedef enum {
    PGP_SA_PLAINTEXT = 0,     /* Plaintext or unencrypted data */
    PGP_SA_IDEA = 1,          /* IDEA */
    PGP_SA_TRIPLEDES = 2,     /* TripleDES */
    PGP_SA_CAST5 = 3,         /* CAST5 */
    PGP_SA_BLOWFISH = 4,      /* Blowfish */
    PGP_SA_AES_128 = 7,       /* AES with 128-bit key (AES) */
    PGP_SA_AES_192 = 8,       /* AES with 192-bit key */
    PGP_SA_AES_256 = 9,       /* AES with 256-bit key */
    PGP_SA_TWOFISH = 10,      /* Twofish with 256-bit key (TWOFISH) */
    PGP_SA_CAMELLIA_128 = 11, /* Camellia with 128-bit key (CAMELLIA) */
    PGP_SA_CAMELLIA_192 = 12, /* Camellia with 192-bit key */
    PGP_SA_CAMELLIA_256 = 13, /* Camellia with 256-bit key */

    PGP_SA_SM4 = 105 /* RNP extension - SM4 */
} pgp_symm_alg_t;

typedef enum {
    PGP_CIPHER_MODE_NONE = 0,
    PGP_CIPHER_MODE_CFB = 1,
    PGP_CIPHER_MODE_CBC = 2,
    PGP_CIPHER_MODE_OCB = 3,
} pgp_cipher_mode_t;

typedef struct symmetric_key_t {
    pgp_symm_alg_t type;
    uint8_t        key[PGP_MAX_KEY_SIZE];
    size_t         key_size;
} symmetric_key_t;

/** Structure to hold an ECC public key params.
 *
 * \see RFC 6637
 */
typedef struct {
    pgp_curve_t curve;
    BIGNUM *    point; /* octet string encoded as MPI */
} pgp_ecc_pubkey_t;

/** Structure to hold an ECDH public key params.
 *
 * \see RFC 6637
 */
typedef struct pgp_ecdh_pubkey_t {
    pgp_ecc_pubkey_t ec;
    pgp_hash_alg_t   kdf_hash_alg; /* Hash used by kdf */
    pgp_symm_alg_t   key_wrap_alg; /* Symmetric algorithm used to wrap KEK*/
} pgp_ecdh_pubkey_t;

/** Version.
 * OpenPGP has two different protocol versions: version 3 and version 4.
 *
 * \see RFC4880 5.2
 */
typedef enum {
    PGP_V2 = 2, /* Version 2 (essentially the same as v3) */
    PGP_V3 = 3, /* Version 3 */
    PGP_V4 = 4  /* Version 4 */
} pgp_version_t;

/** Structure to hold a pgp public key */
typedef struct pgp_pubkey_t {
    pgp_version_t version; /* version of the key (v3, v4...) */
    time_t        birthtime;
    time_t        duration;
    /* validity period of the key in days since
     * creation.  A value of 0 has a special meaning
     * indicating this key does not expire.  Only used with
     * v3 keys.  */
    unsigned         days_valid; /* v4 duration */
    pgp_pubkey_alg_t alg;        /* Public Key Algorithm type */
    union {
        pgp_dsa_pubkey_t     dsa;     /* A DSA public key */
        pgp_rsa_pubkey_t     rsa;     /* An RSA public key */
        pgp_elgamal_pubkey_t elgamal; /* An ElGamal public key */
        /*TODO: This field is common to ECC signing algorithms only. Change it to ec_sign*/
        pgp_ecc_pubkey_t  ecc;  /* An ECC public key */
        pgp_ecdh_pubkey_t ecdh; /* Public Key Parameters for ECDH */
    } key;                      /* Public Key Parameters */
} pgp_pubkey_t;

/** pgp_ecc_seckey_t */
typedef struct {
    BIGNUM *x;
} pgp_ecc_seckey_t;
/** s2k_usage_t
 */
typedef enum {
    PGP_S2KU_NONE = 0,
    PGP_S2KU_ENCRYPTED_AND_HASHED = 254,
    PGP_S2KU_ENCRYPTED = 255
} pgp_s2k_usage_t;

/** s2k_specifier_t
 */
typedef enum {
    PGP_S2KS_SIMPLE = 0,
    PGP_S2KS_SALTED = 1,
    PGP_S2KS_ITERATED_AND_SALTED = 3
} pgp_s2k_specifier_t;

#define PGP_SA_DEFAULT_CIPHER_MODE PGP_CIPHER_MODE_CFB

void pgp_calc_mdc_hash(
  const uint8_t *, const size_t, const uint8_t *, const unsigned, uint8_t *);
unsigned pgp_is_hash_alg_supported(const pgp_hash_alg_t *);

#define PGP_PROTECTED_AT_SIZE 15

typedef struct pgp_key_t pgp_key_t;

struct pgp_seckey_t;

typedef struct pgp_seckey_t *pgp_seckey_decrypt_t(const pgp_key_t *key, FILE *passfp);

/** pgp_seckey_t
 */
typedef struct pgp_seckey_t {
    pgp_pubkey_t        pubkey; /* public key */
    pgp_s2k_usage_t     s2k_usage;
    pgp_s2k_specifier_t s2k_specifier;
    pgp_symm_alg_t      alg;         /* symmetric alg */
    pgp_cipher_mode_t   cipher_mode; /* block cipher mode */
    pgp_hash_alg_t      hash_alg;    /* hash algorithm */
    uint8_t             salt[PGP_SALT_SIZE];
    unsigned            s2k_iterations;
    uint8_t             iv[PGP_MAX_BLOCK_SIZE];
    union {
        pgp_rsa_seckey_t     rsa;
        pgp_dsa_seckey_t     dsa;
        pgp_elgamal_seckey_t elgamal;
        pgp_ecc_seckey_t     ecc;
    } key;
    unsigned checksum;
    uint8_t *checkhash;

    size_t                encrypted_len;
    uint8_t *             encrypted;
    pgp_seckey_decrypt_t *decrypt_cb;
    const char *protected_at[PGP_PROTECTED_AT_SIZE + 1]; // keep 1 byte for \0 and padding
} pgp_seckey_t;

/** Signature Type.
 * OpenPGP defines different signature types that allow giving
 * different meanings to signatures.  Signature types include 0x10 for
 * generitc User ID certifications (used when Ben signs Weasel's key),
 * Subkey binding signatures, document signatures, key revocations,
 * etc.
 *
 * Different types are used in different places, and most make only
 * sense in their intended location (for instance a subkey binding has
 * no place on a UserID).
 *
 * \see RFC4880 5.2.1
 */
typedef enum {
    PGP_SIG_BINARY = 0x00,     /* Signature of a binary document */
    PGP_SIG_TEXT = 0x01,       /* Signature of a canonical text document */
    PGP_SIG_STANDALONE = 0x02, /* Standalone signature */

    PGP_CERT_GENERIC = 0x10,  /* Generic certification of a User ID and
                               * Public Key packet */
    PGP_CERT_PERSONA = 0x11,  /* Persona certification of a User ID and
                               * Public Key packet */
    PGP_CERT_CASUAL = 0x12,   /* Casual certification of a User ID and
                               * Public Key packet */
    PGP_CERT_POSITIVE = 0x13, /* Positive certification of a
                               * User ID and Public Key packet */

    PGP_SIG_SUBKEY = 0x18,  /* Subkey Binding Signature */
    PGP_SIG_PRIMARY = 0x19, /* Primary Key Binding Signature */
    PGP_SIG_DIRECT = 0x1f,  /* Signature directly on a key */

    PGP_SIG_REV_KEY = 0x20,    /* Key revocation signature */
    PGP_SIG_REV_SUBKEY = 0x28, /* Subkey revocation signature */
    PGP_SIG_REV_CERT = 0x30,   /* Certification revocation signature */

    PGP_SIG_TIMESTAMP = 0x40, /* Timestamp signature */

    PGP_SIG_3RD_PARTY = 0x50 /* Third-Party Confirmation signature */
} pgp_sig_type_t;

/** Key Flags
 *
 * \see RFC4880 5.2.3.21
 */
typedef enum {
    PGP_KF_CERTIFY = 0x01,         /* This key may be used to certify other keys. */
    PGP_KF_SIGN = 0x02,            /* This key may be used to sign data. */
    PGP_KF_ENCRYPT_COMMS = 0x04,   /* This key may be used to encrypt communications. */
    PGP_KF_ENCRYPT_STORAGE = 0x08, /* This key may be used to encrypt storage. */
    PGP_KF_SPLIT = 0x10,           /* The private component of this key may have been split
                                            by a secret-sharing mechanism. */
    PGP_KF_AUTH = 0x20,            /* This key may be used for authentication. */
    PGP_KF_SHARED = 0x80,          /* The private component of this key may be in the
                                            possession of more than one person. */
    /* pseudo flags */
    PGP_KF_NONE = 0x00,
    PGP_KF_ENCRYPT = PGP_KF_ENCRYPT_COMMS | PGP_KF_ENCRYPT_STORAGE,
} pgp_key_flags_t;

/** Struct to hold params of a Elgamal signature */
typedef pgp_dsa_sig_t pgp_elgamal_sig_t;

/** Struct to hold params of a ECDSA signature */
typedef pgp_dsa_sig_t pgp_ecc_sig_t;

#define PGP_KEY_ID_SIZE 8
#define PGP_FINGERPRINT_SIZE 20
#define PGP_FINGERPRINT_HEX_SIZE (PGP_FINGERPRINT_SIZE * 3) + 1

/** Struct to hold a signature packet.
 *
 * \see RFC4880 5.2.2
 * \see RFC4880 5.2.3
 */
typedef struct pgp_sig_info_t {
    pgp_version_t  version;                    /* signature version number */
    pgp_sig_type_t type;                       /* signature type value */
    time_t         birthtime;                  /* creation time of the signature */
    time_t         duration;                   /* number of seconds it's valid for */
    uint8_t        signer_id[PGP_KEY_ID_SIZE]; /* Eight-octet key ID
                                                * of signer */
    pgp_pubkey_alg_t key_alg;                  /* public key algorithm number */
    pgp_hash_alg_t   hash_alg;                 /* hashing algorithm number */
    union {
        pgp_rsa_sig_t     rsa;     /* An RSA Signature */
        pgp_dsa_sig_t     dsa;     /* A DSA Signature */
        pgp_elgamal_sig_t elgamal; /* deprecated */
        pgp_ecc_sig_t     ecc;     /* An ECDSA or EdDSA signature */
        pgp_ecc_sig_t     ecdsa;   /* A ECDSA signature */
        pgp_data_t        unknown; /* private or experimental */
    } sig;                         /* signature params */
    size_t   v4_hashlen;
    uint8_t *v4_hashed;
    unsigned birthtime_set : 1;
    unsigned signer_id_set : 1;
    unsigned duration_set : 1;
} pgp_sig_info_t;

/** Struct used when parsing a signature */
typedef struct pgp_sig_t {
    pgp_sig_info_t info; /* The signature information */
    /* The following fields are only used while parsing the signature */
    uint8_t     hash2[2];     /* high 2 bytes of hashed value */
    size_t      v4_hashstart; /* only valid if accumulate is set */
    pgp_hash_t *hash;         /* the hash filled in for the data so far */
} pgp_sig_t;

/** The raw bytes of a signature subpacket */

typedef struct pgp_ss_raw_t {
    pgp_content_enum tag;
    size_t           length;
    uint8_t *        raw;
} pgp_ss_raw_t;

/** Signature Subpacket : Trust Level */

typedef struct pgp_ss_trust_t {
    uint8_t level;  /* Trust Level */
    uint8_t amount; /* Amount */
} pgp_ss_trust_t;

/** Signature Subpacket : Notation Data */
typedef struct pgp_ss_notation_t {
    pgp_data_t flags;
    pgp_data_t name;
    pgp_data_t value;
} pgp_ss_notation_t;

/** Signature Subpacket : Signature Target */
typedef struct pgp_ss_sig_target_t {
    pgp_pubkey_alg_t pka_alg;
    pgp_hash_alg_t   hash_alg;
    pgp_data_t       hash;
} pgp_ss_sig_target_t;

/** pgp_rawpacket_t */
typedef struct pgp_rawpacket_t {
    pgp_content_enum tag;
    size_t           length;
    uint8_t *        raw;
} pgp_rawpacket_t;

/** Types of Compression */
typedef enum {
    PGP_C_NONE = 0,
    PGP_C_ZIP = 1,
    PGP_C_ZLIB = 2,
    PGP_C_BZIP2 = 3
} pgp_compression_type_t;

typedef enum {
    /* first octet */
    PGP_KEY_SERVER_NO_MODIFY = 0x80
} pgp_key_server_prefs_t;

/** pgp_one_pass_sig_t */
typedef struct {
    uint8_t          version;
    pgp_sig_type_t   sig_type;
    pgp_hash_alg_t   hash_alg;
    pgp_pubkey_alg_t key_alg;
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    unsigned         nested;
} pgp_one_pass_sig_t;

/** Signature Subpacket : Revocation Key */
typedef struct {
    uint8_t class;
    uint8_t algid;
    uint8_t fingerprint[PGP_FINGERPRINT_SIZE];
} pgp_ss_revocation_key_t;

/** Signature Subpacket : Revocation Reason */
typedef struct {
    uint8_t code;
    char *  reason;
} pgp_ss_revocation_t;

/** litdata_type_t */
typedef enum {
    PGP_LDT_BINARY = 'b',
    PGP_LDT_TEXT = 't',
    PGP_LDT_UTF8 = 'u',
    PGP_LDT_LOCAL = 'l',
    PGP_LDT_LOCAL2 = '1'
} pgp_litdata_enum;

/** pgp_litdata_header_t */
typedef struct {
    pgp_litdata_enum format;
    char             filename[256];
    time_t           mtime;
} pgp_litdata_header_t;

/** pgp_litdata_body_t */
typedef struct {
    unsigned length;
    uint8_t *data;
    void *   mem; /* pgp_memory_t pointer */
} pgp_litdata_body_t;

/** pgp_header_var_t */
typedef struct {
    char *key;
    char *value;
} pgp_header_var_t;

/** pgp_headers_t */
typedef struct {
    pgp_header_var_t *headers;
    unsigned          headerc;
} pgp_headers_t;

/** pgp_armour_header_t */
typedef struct {
    const char *  type;
    pgp_headers_t headers;
} pgp_armour_header_t;

/** pgp_fixed_body_t */
typedef struct pgp_fixed_body_t {
    unsigned length;
    uint8_t  data[8192]; /* \todo fix hard-coded value? */
} pgp_fixed_body_t;

/** pgp_dyn_body_t */
typedef struct pgp_dyn_body_t {
    unsigned length;
    uint8_t *data;
} pgp_dyn_body_t;

enum { PGP_SE_IP_DATA_VERSION = 1, PGP_PKSK_V3 = 3 };

/** pgp_pk_sesskey_params_rsa_t */
typedef struct {
    BIGNUM *encrypted_m;
    BIGNUM *m;
} pgp_pk_sesskey_params_rsa_t;

/** pgp_pk_sesskey_params_elgamal_t */
typedef struct {
    BIGNUM *g_to_k;
    BIGNUM *encrypted_m;
} pgp_pk_sesskey_params_elgamal_t;

/** pgp_pk_sesskey_params_sm2_t */
typedef struct {
    BIGNUM *encrypted_m;
} pgp_pk_sesskey_params_sm2_t;

/** pgp_pk_sesskey_params_elgamal_t */
typedef struct {
    uint8_t  encrypted_m[48];  // wrapped_key
    unsigned encrypted_m_size; // wrapped_key_size
    BIGNUM * ephemeral_point;
} pgp_pk_sesskey_params_ecdh_t;

/** pgp_pk_sesskey_params_t */
typedef union {
    pgp_pk_sesskey_params_rsa_t     rsa;
    pgp_pk_sesskey_params_elgamal_t elgamal;
    pgp_pk_sesskey_params_ecdh_t    ecdh;
    pgp_pk_sesskey_params_sm2_t     sm2;
} pgp_pk_sesskey_params_t;

/** pgp_pk_sesskey_t */
typedef struct {
    unsigned                version;
    uint8_t                 key_id[PGP_KEY_ID_SIZE];
    pgp_pubkey_alg_t        alg;
    pgp_pk_sesskey_params_t params;
    pgp_symm_alg_t          symm_alg;
    uint8_t                 key[PGP_MAX_KEY_SIZE];
    uint16_t                checksum;
} pgp_pk_sesskey_t;

/** pgp_seckey_passphrase_t */
typedef struct {
    const pgp_seckey_t *seckey;
    char **             passphrase; /* point somewhere that gets filled
                                     * in to work around constness of
                                     * content */
} pgp_seckey_passphrase_t;

/** pgp_get_seckey_t */
typedef struct {
    const pgp_seckey_t **   seckey;
    const pgp_pk_sesskey_t *pk_sesskey;
} pgp_get_seckey_t;

/** pgp_parser_union_content_t */
typedef union {
    const char *            error;
    pgp_parser_errcode_t    errcode;
    pgp_ptag_t              ptag;
    pgp_pubkey_t            pubkey;
    pgp_data_t              trust;
    uint8_t *               userid;
    pgp_data_t              userattr;
    pgp_sig_t               sig;
    pgp_ss_raw_t            ss_raw;
    pgp_ss_trust_t          ss_trust;
    unsigned                ss_revocable;
    time_t                  ss_time;
    uint8_t                 ss_issuer[PGP_KEY_ID_SIZE];
    pgp_ss_notation_t       ss_notation;
    pgp_rawpacket_t         packet;
    pgp_compression_type_t  compressed;
    pgp_one_pass_sig_t      one_pass_sig;
    pgp_data_t              ss_skapref;
    pgp_data_t              ss_hashpref;
    pgp_data_t              ss_zpref;
    pgp_data_t              ss_key_flags;
    pgp_data_t              ss_key_server_prefs;
    unsigned                ss_primary_userid;
    char *                  ss_regexp;
    char *                  ss_policy;
    char *                  ss_keyserv;
    pgp_ss_revocation_key_t ss_revocation_key;
    pgp_data_t              ss_userdef;
    pgp_data_t              ss_unknown;
    pgp_litdata_header_t    litdata_header;
    pgp_litdata_body_t      litdata_body;
    pgp_dyn_body_t          mdc;
    pgp_data_t              ss_features;
    pgp_ss_sig_target_t     ss_sig_target;
    pgp_data_t              ss_embedded_sig;
    pgp_data_t              ss_issuer_fpr;
    pgp_ss_revocation_t     ss_revocation;
    pgp_seckey_t            seckey;
    uint8_t *               ss_signer;
    pgp_armour_header_t     armour_header;
    const char *            armour_trailer;
    pgp_headers_t           cleartext_head;
    pgp_fixed_body_t        cleartext_body;
    struct pgp_hash_t *     cleartext_trailer;
    pgp_dyn_body_t          unarmoured_text;
    pgp_pk_sesskey_t        pk_sesskey;
    pgp_seckey_passphrase_t skey_passphrase;
    unsigned                se_ip_data_header;
    pgp_dyn_body_t          se_ip_data_body;
    pgp_fixed_body_t        se_data_body;
    pgp_get_seckey_t        get_seckey;
} pgp_contents_t;

/** pgp_packet_t */
struct pgp_packet_t {
    pgp_content_enum tag;      /* type of contents */
    uint8_t          critical; /* for sig subpackets */
    pgp_contents_t   u;        /* union for contents */
};

/** pgp_fingerprint_t */
typedef struct pgp_fingerprint_t {
    uint8_t  fingerprint[PGP_FINGERPRINT_SIZE];
    unsigned length;
} pgp_fingerprint_t;

int pgp_keyid(uint8_t *, const size_t, const pgp_pubkey_t *);
int pgp_fingerprint(pgp_fingerprint_t *, const pgp_pubkey_t *);

void pgp_finish(void);
void pgp_pubkey_free(pgp_pubkey_t *);
void pgp_userid_free(uint8_t **);
void pgp_data_free(pgp_data_t *);
void pgp_sig_free(pgp_sig_t *);
void pgp_ss_notation_free(pgp_ss_notation_t *);
void pgp_ss_revocation_free(pgp_ss_revocation_t *);
void pgp_ss_sig_target_free(pgp_ss_sig_target_t *);

void pgp_rawpacket_free(pgp_rawpacket_t *);
void pgp_seckey_free(pgp_seckey_t *);
void pgp_pk_sesskey_free(pgp_pk_sesskey_t *);

bool pgp_print_packet(pgp_printstate_t *, const pgp_packet_t *);

/** pgp_keydata_key_t
 */
typedef union {
    pgp_pubkey_t pubkey;
    pgp_seckey_t seckey;
} pgp_keydata_key_t;

/* sigpacket_t */
typedef struct sigpacket_t {
    uint8_t **       userid;
    pgp_rawpacket_t *packet;
} sigpacket_t;

/* user revocation info */
typedef struct pgp_revoke_t {
    uint32_t uid;    /* index in uid array */
    uint8_t  code;   /* revocation code */
    char *   reason; /* c'mon, spill the beans */
} pgp_revoke_t;

typedef struct pgp_user_prefs_t {
    // preferred symmetric algs (pgp_symm_alg_t)
    DYNARRAY(uint8_t, symm_alg);
    // preferred hash algs (pgp_hash_alg_t)
    DYNARRAY(uint8_t, hash_alg);
    // preferred compression algs (pgp_compression_type_t)
    DYNARRAY(uint8_t, compress_alg);
    // key server preferences (pgp_key_server_prefs_t)
    DYNARRAY(uint8_t, key_server_pref);
    // preferred key server
    uint8_t *key_server;
} pgp_user_prefs_t;

/** signature subpackets */
typedef struct pgp_subsig_t {
    uint32_t         uid;         /* index in userid array in key */
    pgp_sig_t        sig;         /* trust signature */
    uint8_t          trustlevel;  /* level of trust */
    uint8_t          trustamount; /* amount of trust */
    uint8_t          key_flags;   /* key flags */
    pgp_user_prefs_t prefs;       /* user preferences */
} pgp_subsig_t;

/* describes a user's key */
struct pgp_key_t {
    DYNARRAY(uint8_t *, uid);          /* array of user ids */
    DYNARRAY(pgp_rawpacket_t, packet); /* array of raw packets */
    DYNARRAY(pgp_subsig_t, subsig);    /* array of signature subkeys */
    DYNARRAY(pgp_revoke_t, revoke);    /* array of signature revocations */
    DYNARRAY(struct pgp_key_t *, subkey);
    pgp_content_enum  type;      /* type of key */
    pgp_keydata_key_t key;       /* pubkey/seckey data */
    uint8_t           key_flags; /* key flags */
    uint8_t           keyid[PGP_KEY_ID_SIZE];
    pgp_fingerprint_t fingerprint;
    uint8_t           grip[PGP_FINGERPRINT_SIZE];
    uint32_t          uid0;       /* primary uid index in uids array */
    uint8_t           revoked;    /* key has been revoked */
    pgp_revoke_t      revocation; /* revocation reason */
    symmetric_key_t   session_key;
};

/* structure used to hold context of key generation */
typedef struct rnp_keygen_crypto_params_t {
    // Asymmteric algorithm that user requesed key for
    pgp_pubkey_alg_t key_alg;
    // Hash to be used for key signature
    pgp_hash_alg_t hash_alg;
    // Symmetric algorithm to be used for secret key encryption
    pgp_symm_alg_t sym_alg;
    union {
        struct ecc_t {
            pgp_curve_t curve;
        } ecc;
        struct rsa_t {
            uint32_t modulus_bit_len;
        } rsa;
    };

    uint8_t passphrase[MAX_PASSPHRASE_LENGTH];
} rnp_keygen_crypto_params_t;

typedef struct rnp_selfsig_cert_info {
    uint8_t          userid[MAX_ID_LENGTH]; /* userid, required */
    uint8_t          key_flags;             /* key flags */
    uint32_t         key_expiration;        /* key expiration time (sec), 0 = no expiration */
    pgp_user_prefs_t prefs;                 /* user preferences, optional */
    unsigned         primary : 1;           /* mark this as the primary user id */
} rnp_selfsig_cert_info;

typedef struct rnp_selfsig_binding_info {
    uint8_t  key_flags;
    uint32_t key_expiration;
} rnp_selfsig_binding_info;

typedef struct rnp_keygen_primary_desc_t {
    rnp_keygen_crypto_params_t crypto;
    rnp_selfsig_cert_info      cert;
} rnp_keygen_primary_desc_t;

typedef struct rnp_keygen_subkey_desc_t {
    rnp_keygen_crypto_params_t crypto;
    rnp_selfsig_binding_info   binding;
} rnp_keygen_subkey_desc_t;

typedef struct rnp_keygen_desc_t {
    rnp_keygen_primary_desc_t primary;
    rnp_keygen_subkey_desc_t  subkey;
} rnp_keygen_desc_t;

#define DEFAULT_PK_ALG PGP_PKA_RSA
#define DEFAULT_RSA_NUMBITS 2048
static const pgp_symm_alg_t DEFAULT_SYMMETRIC_ALGS[] = {
  PGP_SA_AES_256, PGP_SA_AES_192, PGP_SA_AES_128, PGP_SA_TRIPLEDES};
static const pgp_hash_alg_t DEFAULT_HASH_ALGS[] = {
  PGP_HASH_SHA256, PGP_HASH_SHA384, PGP_HASH_SHA512, PGP_HASH_SHA224, PGP_HASH_SHA1};
static const pgp_compression_type_t DEFAULT_COMPRESS_ALGS[] = {
  PGP_C_ZLIB, PGP_C_BZIP2, PGP_C_ZIP, PGP_C_NONE};
#define PGP_SA_DEFAULT_CIPHER PGP_SA_AES_256

#endif /* PACKET_H_ */
