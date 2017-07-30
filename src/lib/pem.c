/*-
 * Copyright (c) 2017 Ribose Inc.
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
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*-
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Alistair Crooks (agc@NetBSD.org)
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
 */
#include "config.h"

#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "crypto.h"
#include "utils.h"
#include "bn.h"

bool
read_pem_seckey(const char *f, pgp_key_t *key, const char *type, int verbose)
{
    uint8_t keybuf[RNP_BUFSIZ] = {0};
    FILE *  fp;
    char    prompt[BUFSIZ];
    char *  pass;
    bool    ok;
    size_t  read;

    botan_rng_t     rng;
    botan_privkey_t priv_key;

    /* TODO */
    if ((fp = fopen(f, "r")) == NULL) {
        if (verbose) {
            (void) fprintf(stderr, "can't open '%s'\n", f);
        }
        return false;
    }

    read = fread(keybuf, 1, RNP_BUFSIZ, fp);

    if (!feof(fp)) {
        (void) fclose(fp);
        return false;
    }
    (void) fclose(fp);

    botan_rng_init(&rng, NULL);

    if (strcmp(type, "ssh-rsa") == 0) {
        if (botan_privkey_load(&priv_key, rng, keybuf, read, NULL) != 0) {
            (void) snprintf(prompt, sizeof(prompt), "rnp PEM %s passphrase: ", f);
            for (;;) {
                pass = getpass(prompt);

                if (botan_privkey_load(&priv_key, rng, keybuf, read, pass) == 0)
                    break;
            }
        }

        if (botan_privkey_check_key(priv_key, rng, 0) != 0) {
            return false;
        }

        {
            botan_mp_t x;
            botan_mp_init(&x);
            botan_privkey_get_field(x, priv_key, "d");
            key->key.seckey.key.rsa.d = new_BN_take_mp(x);

            botan_mp_init(&x);
            botan_privkey_get_field(x, priv_key, "p");
            key->key.seckey.key.rsa.p = new_BN_take_mp(x);

            botan_mp_init(&x);
            botan_privkey_get_field(x, priv_key, "q");
            key->key.seckey.key.rsa.q = new_BN_take_mp(x);
            botan_privkey_destroy(priv_key);
            ok = true;
        }
    } else if (strcmp(type, "ssh-dss") == 0) {
        if (botan_privkey_load(&priv_key, rng, keybuf, read, NULL) != 0) {
            ok = false;
        } else {
            botan_mp_t x;
            botan_mp_init(&x);
            botan_privkey_get_field(x, priv_key, "x");
            key->key.seckey.key.dsa.x = new_BN_take_mp(x);
            botan_privkey_destroy(priv_key);
            ok = true;
        }
    } else {
        ok = false;
    }

    botan_rng_destroy(rng);

    return ok;
}
