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

#ifndef PACKET_PRINT_H_
#define PACKET_PRINT_H_

#include <time.h>

#include "packet-parse.h"
#include <rekey/rnp_key_store.h>

typedef struct pgp_pubkey_t pgp_pubkey_t;
typedef struct pgp_io_t     pgp_io_t;
typedef struct pgp_key_t    pgp_key_t;

/* structure to keep track of printing state variables */
typedef struct pgp_printstate_t {
    unsigned unarmoured;
    unsigned skipping;
    int      indent;
} pgp_printstate_t;

void repgp_print_key(pgp_io_t *,
                     const struct rnp_key_store_t *,
                     const pgp_key_t *,
                     const char *,
                     const pgp_pubkey_t *,
                     const int);

int repgp_sprint_json(pgp_io_t *,
                      const struct rnp_key_store_t *,
                      const pgp_key_t *,
                      json_object *,
                      const char *,
                      const pgp_pubkey_t *,
                      const int);

bool pgp_print_packet(pgp_printstate_t *, const pgp_packet_t *);

int pgp_sprint_key(pgp_io_t *,
                   const rnp_key_store_t *,
                   const pgp_key_t *,
                   char **,
                   const char *,
                   const pgp_pubkey_t *,
                   const int);
int pgp_sprint_json(pgp_io_t *,
                    const rnp_key_store_t *,
                    const pgp_key_t *,
                    json_object *,
                    const char *,
                    const pgp_pubkey_t *,
                    const int);
int pgp_hkp_sprint_key(pgp_io_t *,
                       const rnp_key_store_t *,
                       const pgp_key_t *,
                       char **,
                       const pgp_pubkey_t *,
                       const int);
void pgp_print_key(pgp_io_t *,
                   const rnp_key_store_t *,
                   const pgp_key_t *,
                   const char *,
                   const pgp_pubkey_t *,
                   const int);
void pgp_print_pubkey(const pgp_pubkey_t *);
int  pgp_sprint_pubkey(const pgp_key_t *, char *, size_t);

#endif /* PACKET_PRINT_H_ */
