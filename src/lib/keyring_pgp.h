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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
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

#ifndef KEYRING_PGP_H_
#define KEYRING_PGP_H_

#include "packet.h"
#include "packet-parse.h"
#include <json.h>
#include "keyring.h"

enum {
	MAX_ID_LENGTH		= 128,
	MAX_PASSPHRASE_LENGTH	= 256
};

int pgp_keyring_load_keys(rnp_t *rnp, char *homedir);

const pgp_key_t *pgp_getkeybyid(io_t *,
					const keyring_t *,
					const uint8_t *,
					unsigned *,
					pgp_pubkey_t **);
const pgp_key_t *pgp_getkeybyname(io_t *,
					const keyring_t *,
					const char *);
const pgp_key_t *pgp_getnextkeybyname(io_t *,
					const keyring_t *,
					const char *,
					unsigned *);
void pgp_keydata_free(pgp_key_t *);
void pgp_dump_keyring(const keyring_t *);
const pgp_pubkey_t *pgp_get_pubkey(const pgp_key_t *);
unsigned   pgp_is_key_secret(const pgp_key_t *);
const pgp_seckey_t *pgp_get_seckey(const pgp_key_t *);
pgp_seckey_t *pgp_get_writable_seckey(pgp_key_t *);
pgp_seckey_t *pgp_decrypt_seckey(const pgp_key_t *, void *);

unsigned   pgp_keyring_fileread(keyring_t *, const unsigned,
					const char *);

int pgp_keyring_list(io_t *, const keyring_t *, const int);
int pgp_keyring_json(io_t *, const keyring_t *, json_object *, const int);

void pgp_set_seckey(pgp_contents_t *, const pgp_key_t *);
void pgp_forget(void *, unsigned);

const uint8_t *pgp_get_key_id(const pgp_key_t *);
unsigned pgp_get_userid_count(const pgp_key_t *);
const uint8_t *pgp_get_userid(const pgp_key_t *, unsigned);
unsigned pgp_is_key_supported(const pgp_key_t *);

uint8_t *pgp_add_userid(pgp_key_t *, const uint8_t *);
pgp_subpacket_t *pgp_add_subpacket(pgp_key_t *,
						const pgp_subpacket_t *);

unsigned pgp_add_selfsigned_userid(pgp_key_t *, uint8_t *);

pgp_key_t  *pgp_keydata_new(void);
void pgp_keydata_init(pgp_key_t *, const pgp_content_enum);

int pgp_parse_and_accumulate(keyring_t *, pgp_stream_t *);

int pgp_sprint_keydata(io_t *, const keyring_t *,
			const pgp_key_t *, char **, const char *,
			const pgp_pubkey_t *, const int);
int pgp_sprint_json(io_t *, const keyring_t *,
			const pgp_key_t *, json_object *, const char *,
			const pgp_pubkey_t *, const int);
int pgp_hkp_sprint_keydata(io_t *, const keyring_t *,
			const pgp_key_t *, char **,
			const pgp_pubkey_t *, const int);
void pgp_print_keydata(io_t *, const keyring_t *, const pgp_key_t *,
			const char *, const pgp_pubkey_t *, const int);
void pgp_print_sig(io_t *, const pgp_key_t *, const char *,
			const pgp_pubkey_t *);
void pgp_print_pubkey(const pgp_pubkey_t *);
int pgp_sprint_pubkey(const pgp_key_t *, char *, size_t);

int pgp_list_packets(io_t *,
			char *,
			unsigned,
			keyring_t *,
			keyring_t *,
			void *,
			pgp_cbfunc_t *);

char *pgp_export_key(io_t *, const pgp_key_t *, uint8_t *);

int pgp_add_to_pubring(keyring_t *, const pgp_pubkey_t *, pgp_content_enum tag);
int pgp_add_to_secring(keyring_t *, const pgp_seckey_t *);

int pgp_append_keyring(keyring_t *, keyring_t *);

#endif /* KEYRING_PGP_H_ */
