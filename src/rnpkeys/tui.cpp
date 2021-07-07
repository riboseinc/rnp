/*
 * Copyright (c) 2017-2020, [Ribose Inc](https://www.ribose.com).
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

#include <algorithm>
#ifdef _MSC_VER
#include "uniwin.h"
#else
#include <unistd.h>
#endif
#include <errno.h>
#include <iterator>
#include "rnp/rnpcfg.h"
#include "rnpkeys.h"
#include "defaults.h"
#include "logging.h"

/* -----------------------------------------------------------------------------
 * @brief   Reads input from file pointer and converts it securelly to ints
 *          Partially based on ERR34-C from SEI CERT C Coding Standard
 *
 * @param   fp          pointer to opened pipe
 * @param   result[out] result read from file pointer and converted to int
 *
 * @returns true and value in result if integer was parsed correctly,
 *          otherwise false
 *
-------------------------------------------------------------------------------- */
static bool
rnp_secure_get_long_from_fd(FILE *fp, long *result, bool allow_empty)
{
    char  buff[BUFSIZ];
    char *end_ptr;
    long  num_long;
    bool  ret = false;

    if (!result) {
        goto end;
    }

    if (fgets(buff, sizeof(buff), fp) == NULL) {
        RNP_LOG("EOF or read error");
        goto end;
    } else {
        errno = 0;
        num_long = strtol(buff, &end_ptr, 10);

        if (ERANGE == errno) {
            RNP_LOG("Number out of range");
            goto end;
        } else if (end_ptr == buff) {
            ret = allow_empty;
            goto end;
        } else if ('\n' != *end_ptr && '\0' != *end_ptr) {
            RNP_LOG("Unexpected end of line");
            goto end;
        }
    }

    *result = num_long;
    ret = true;

end:
    return ret;
}

static bool
is_rsa_keysize_supported(uint32_t keysize)
{
    return ((keysize >= 1024) && (keysize <= 4096) && !(keysize % 8));
}

static const char *
ask_curve_name(FILE *input_fp)
{
    std::vector<const char *> curves;
    static const char *const  known_curves[] = {
      "NIST P-256",
      "NIST P-384",
      "NIST P-521",
      "brainpoolP256r1",
      "brainpoolP384r1",
      "brainpoolP512r1",
      "secp256k1",
    };
    const size_t curvenum = sizeof(known_curves) / sizeof(*known_curves);

    try {
        std::copy_if(known_curves,
                     known_curves + curvenum,
                     std::back_inserter(curves),
                     [](const char *curve) {
                         bool supported = false;
                         return !rnp_supports_feature(RNP_FEATURE_CURVE, curve, &supported) &&
                                supported;
                     });
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return NULL;
    }
    const size_t ccount = curves.size();
    if (!ccount) {
        return NULL;
    }
    bool        ok = false;
    const char *result = NULL;
    int         attempts = 0;
    do {
        if (attempts >= 10) {
            printf("Too many attempts. Aborting.\n");
            return NULL;
        }
        printf("Please select which elliptic curve you want:\n");
        for (size_t i = 0; i < ccount; i++) {
            printf("\t(%zu) %s\n", i + 1, curves[i]);
        }
        printf("(default %s)> ", DEFAULT_CURVE);
        long val = 0;
        ok = rnp_secure_get_long_from_fd(input_fp, &val, true) && (val > 0) &&
             (val <= (long) ccount);
        if (ok) {
            result = curves[val - 1];
        }
        attempts++;
    } while (!ok);

    return result;
}

static long
ask_rsa_bitlen(FILE *input_fp)
{
    long result = 0;
    do {
        result = DEFAULT_RSA_NUMBITS;
        printf("Please provide bit length of the key (between 1024 and 4096):\n(default %d)> ",
               DEFAULT_RSA_NUMBITS);
    } while (!rnp_secure_get_long_from_fd(input_fp, &result, true) ||
             !is_rsa_keysize_supported(result));
    return result;
}

static long
ask_dsa_bitlen(FILE *input_fp)
{
    long result = 0;
    do {
        result = DSA_DEFAULT_P_BITLEN;
        printf(
          "Please provide bit length of the DSA key (between %d and %d):\n(default %d) > ",
          DSA_MIN_P_BITLEN,
          DSA_MAX_P_BITLEN,
          DSA_DEFAULT_P_BITLEN);
    } while (!rnp_secure_get_long_from_fd(input_fp, &result, true) ||
             (result < DSA_MIN_P_BITLEN) || (result > DSA_MAX_P_BITLEN));

    // round up to multiple of 1024
    result = ((result + 63) / 64) * 64;
    printf("Bitlen of the key will be %lu\n", result);
    return result;
}

static bool
rnpkeys_ask_generate_params(rnp_cfg &cfg, FILE *input_fp)
{
    long option = 0;
    do {
        printf("Please select what kind of key you want:\n"
               "\t(1)  RSA (Encrypt or Sign)\n"
               "\t(16) DSA + ElGamal\n"
               "\t(17) DSA + RSA\n" // TODO: See #584
               "\t(19) ECDSA + ECDH\n"
               "\t(22) EDDSA + X25519\n"
               "\t(99) SM2\n"
               "> ");
        if (!rnp_secure_get_long_from_fd(input_fp, &option, false)) {
            option = 0;
            continue;
        }
        switch (option) {
        case 1: {
            int bits = ask_rsa_bitlen(input_fp);
            cfg.set_str(CFG_KG_PRIMARY_ALG, RNP_ALGNAME_RSA);
            cfg.set_str(CFG_KG_SUBKEY_ALG, RNP_ALGNAME_RSA);
            cfg.set_int(CFG_KG_PRIMARY_BITS, bits);
            cfg.set_int(CFG_KG_SUBKEY_BITS, bits);
            break;
        }
        case 16: {
            int bits = ask_dsa_bitlen(input_fp);
            cfg.set_str(CFG_KG_PRIMARY_ALG, RNP_ALGNAME_DSA);
            cfg.set_str(CFG_KG_SUBKEY_ALG, RNP_ALGNAME_ELGAMAL);
            cfg.set_int(CFG_KG_PRIMARY_BITS, bits);
            cfg.set_int(CFG_KG_SUBKEY_BITS, bits);
            break;
        }
        case 17: {
            int bits = ask_dsa_bitlen(input_fp);
            cfg.set_str(CFG_KG_PRIMARY_ALG, RNP_ALGNAME_DSA);
            cfg.set_str(CFG_KG_SUBKEY_ALG, RNP_ALGNAME_RSA);
            cfg.set_int(CFG_KG_PRIMARY_BITS, bits);
            cfg.set_int(CFG_KG_SUBKEY_BITS, bits);
            break;
        }
        case 19: {
            const char *curve = ask_curve_name(input_fp);
            if (!curve) {
                return false;
            }
            cfg.set_str(CFG_KG_PRIMARY_ALG, RNP_ALGNAME_ECDSA);
            cfg.set_str(CFG_KG_SUBKEY_ALG, RNP_ALGNAME_ECDH);
            cfg.set_str(CFG_KG_PRIMARY_CURVE, curve);
            cfg.set_str(CFG_KG_SUBKEY_CURVE, curve);
            break;
        }
        case 22: {
            cfg.set_str(CFG_KG_PRIMARY_ALG, RNP_ALGNAME_EDDSA);
            cfg.set_str(CFG_KG_SUBKEY_ALG, RNP_ALGNAME_ECDH);
            cfg.set_str(CFG_KG_SUBKEY_CURVE, "Curve25519");
            break;
        }
        case 99: {
            cfg.set_str(CFG_KG_PRIMARY_ALG, RNP_ALGNAME_SM2);
            cfg.set_str(CFG_KG_SUBKEY_ALG, RNP_ALGNAME_SM2);
            if (!cfg.has(CFG_KG_HASH)) {
                cfg.set_str(CFG_KG_HASH, RNP_ALGNAME_SM3);
            }
            break;
        }
        default:
            option = 0;
            break;
        }
    } while (!option);

    return true;
}

bool
cli_rnp_set_generate_params(rnp_cfg &cfg)
{
    bool res = true;
    // hash algorithms for signing and protection
    if (cfg.has(CFG_HASH)) {
        cfg.set_str(CFG_KG_HASH, cfg.get_str(CFG_HASH));
        cfg.set_str(CFG_KG_PROT_HASH, cfg.get_str(CFG_HASH));
    }

    // key and subkey algorithms, bit length/curve
    if (!cfg.get_bool(CFG_EXPERT)) {
        cfg.set_str(CFG_KG_PRIMARY_ALG, RNP_ALGNAME_RSA);
        cfg.set_int(CFG_KG_PRIMARY_BITS, cfg.get_int(CFG_NUMBITS));
        cfg.set_str(CFG_KG_SUBKEY_ALG, RNP_ALGNAME_RSA);
        cfg.set_int(CFG_KG_SUBKEY_BITS, cfg.get_int(CFG_NUMBITS));
    } else {
        FILE *input = stdin;
        if (cfg.has(CFG_USERINPUTFD)) {
            int inputfd = dup(cfg.get_int(CFG_USERINPUTFD));
            if (inputfd != -1) {
                input = fdopen(inputfd, "r");
                if (!input) {
                    close(inputfd);
                }
            }
        }
        if (!input) {
            return false;
        }
        if (!rnpkeys_ask_generate_params(cfg, input)) {
            return false;
        }
        if (input && (input != stdin)) {
            fclose(input);
        }
    }

    // make sure hash algorithms are set
    if (!cfg.has(CFG_KG_HASH)) {
        cfg.set_str(CFG_KG_HASH, DEFAULT_HASH_ALG);
    }
    if (!cfg.has(CFG_KG_PROT_HASH)) {
        cfg.set_str(CFG_KG_PROT_HASH, DEFAULT_HASH_ALG);
    }

    // protection symmetric algorithm
    cfg.set_str(CFG_KG_PROT_ALG,
                cfg.has(CFG_CIPHER) ? cfg.get_str(CFG_CIPHER) : DEFAULT_SYMM_ALG);
    // protection iterations count
    size_t iterations = cfg.get_int(CFG_S2K_ITER);
    if (!iterations) {
        res = res && !rnp_calculate_iterations(cfg.get_str(CFG_KG_PROT_HASH).c_str(),
                                               cfg.get_int(CFG_S2K_MSEC),
                                               &iterations);
    }
    cfg.set_int(CFG_KG_PROT_ITERATIONS, iterations);
    return res;
}
