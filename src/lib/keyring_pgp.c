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
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: keyring.c,v 1.50 2011/06/25 00:37:44 agc Exp $");
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <regex.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "types.h"
#include "keyring_pgp.h"
#include "packet-parse.h"
#include "signature.h"
#include "rnpsdk.h"
#include "readerwriter.h"
#include "rnpdefs.h"
#include "packet.h"
#include "crypto.h"
#include "validate.h"
#include "rnpdefs.h"
#include "rnpdigest.h"
#include <json.h>
#include "keyring.h"
#include "packet-key.h"

#include <sys/types.h>
#include <sys/param.h>

#include <stdio.h>
#include <string.h>

/* read any gpg config file */
static int
conffile(rnp_t *rnp, char *homedir, char *userid, size_t length)
{
    regmatch_t	 matchv[10];
    regex_t		 keyre;
    char		 buf[BUFSIZ];
    FILE		*fp;

    __PGP_USED(rnp);
    (void) snprintf(buf, sizeof(buf), "%s/gpg.conf", homedir);
    if ((fp = fopen(buf, "r")) == NULL) {
        return 0;
    }
    (void) memset(&keyre, 0x0, sizeof(keyre));
    (void) regcomp(&keyre, "^[ \t]*default-key[ \t]+([0-9a-zA-F]+)",
                   REG_EXTENDED);
    while (fgets(buf, (int)sizeof(buf), fp) != NULL) {
        if (regexec(&keyre, buf, 10, matchv, 0) == 0) {
            (void) memcpy(userid, &buf[(int)matchv[1].rm_so],
                          MIN((unsigned)(matchv[1].rm_eo -
                                         matchv[1].rm_so), length));
            if (rnp->passfp == NULL) {
                (void) fprintf(stderr,
                               "rnp: default key set to \"%.*s\"\n",
                               (int)(matchv[1].rm_eo - matchv[1].rm_so),
                               &buf[(int)matchv[1].rm_so]);
            }
        }
    }
    (void) fclose(fp);
    regfree(&keyre);
    return 1;
}

/* read a keyring and return it */
static void *
readkeyring(rnp_t *rnp, const char *name, const char *homedir)
{
    keyring_t	*keyring;
    const unsigned	 noarmor = 0;
    char		 f[MAXPATHLEN];
    char		*filename;

    if ((filename = rnp_getvar(rnp, name)) == NULL) {
        (void) snprintf(f, sizeof(f), "%s/%s.gpg", homedir, name);
        filename = f;
    }
    if ((keyring = calloc(1, sizeof(*keyring))) == NULL) {
        (void) fprintf(stderr, "readkeyring: bad alloc\n");
        return NULL;
    }
    if (!pgp_keyring_fileread(keyring, noarmor, filename)) {
        free(keyring);
        (void) fprintf(stderr, "cannot read %s %s\n", name, filename);
        return NULL;
    }
    rnp_setvar(rnp, name, filename);
    return keyring;
}

int
pgp_keyring_load_keys(rnp_t *rnp, char *homedir)
{
	char     *userid;
	char      id[MAX_ID_LENGTH];
	io_t *io = rnp->io;

	/* TODO: Some of this might be split up into sub-functions. */
	/* TODO: Figure out what unhandled error is causing an
	 *       empty keyring to end up in keyring_get_first_ring
	 *       and ensure that it's not present in the
	 *       ssh implementation too.
	 */

	rnp->pubring = readkeyring(rnp, "pubring", homedir);

	if (rnp->pubring == NULL) {
		fprintf(io->errs, "cannot read pub keyring\n");
		return 0;
	}

	if (((keyring_t *) rnp->pubring)->keyc < 1) {
		fprintf(io->errs, "pub keyring is empty\n");
		return 0;
	}

	/* If a userid has been given, we'll use it. */
	if ((userid = rnp_getvar(rnp, "userid")) == NULL) {
		/* also search in config file for default id */
		memset(id, 0, sizeof(id));
		conffile(rnp, homedir, id, sizeof(id));
		if (id[0] != 0x0) {
			rnp_setvar(rnp, "userid", userid = id);
		}
	}

	/* Only read secret keys if we need to. */
	if (rnp_getvar(rnp, "need seckey")) {

		rnp->secring = readkeyring(rnp, "secring", homedir);

		if (rnp->secring == NULL) {
			fprintf(io->errs, "cannot read sec keyring\n");
			return 0;
		}

		if (((keyring_t *) rnp->secring)->keyc < 1) {
			fprintf(io->errs, "sec keyring is empty\n");
			return 0;
		}

		/* Now, if we don't have a valid user, use the first
		 * in secring.
		 */
		if (! userid && rnp_getvar(rnp,
								   "need userid") != NULL) {

			if (!keyring_get_first_ring(rnp->secring, id,
										sizeof(id), 0)) {
				/* TODO: This is _temporary_. A more
				 *       suitable replacement will be
				 *       required.
				 */
				fprintf(io->errs, "failed to read id\n");
				return 0;
			}

			rnp_setvar(rnp, "userid", userid = id);
		}

	} else if (rnp_getvar(rnp, "need userid") != NULL) {
		/* encrypting - get first in pubring */
		if (! userid && keyring_get_first_ring(
				rnp->pubring, id, sizeof(id), 0)) {
			rnp_setvar(rnp, "userid", userid = id);
		}
	}

	if (! userid && rnp_getvar(rnp, "need userid")) {
		/* if we don't have a user id, and we need one, fail */
		fprintf(io->errs, "cannot find user id\n");
		return 0;
	}

	return 1;
}


void print_packet_hex(const pgp_subpacket_t *pkt);

/* used to point to data during keyring read */
typedef struct keyringcb_t {
	keyring_t		*keyring;	/* the keyring we're reading */
} keyringcb_t;


static pgp_cb_ret_t
cb_keyring_read(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
	keyring_t	*keyring;
	pgp_revoke_t	*revocation;
	pgp_key_t	*key;
	keyringcb_t	*cb;

	cb = pgp_callback_arg(cbinfo);
	keyring = cb->keyring;
	switch (pkt->tag) {
	case PGP_PARSER_PTAG:
	case PGP_PTAG_CT_ENCRYPTED_SECRET_KEY:
		/* we get these because we didn't prompt */
		break;
	case PGP_PTAG_CT_SIGNATURE_HEADER:
		key = &keyring->keys[keyring->keyc - 1];
		EXPAND_ARRAY(key, subsig);
		key->subsigs[key->subsigc].uid = key->uidc - 1;
		(void) memcpy(&key->subsigs[key->subsigc].sig, &pkt->u.sig,
				sizeof(pkt->u.sig));
		key->subsigc += 1;
		break;
	case PGP_PTAG_CT_SIGNATURE:
		key = &keyring->keys[keyring->keyc - 1];
		EXPAND_ARRAY(key, subsig);
		key->subsigs[key->subsigc].uid = key->uidc - 1;
		(void) memcpy(&key->subsigs[key->subsigc].sig, &pkt->u.sig,
				sizeof(pkt->u.sig));
		key->subsigc += 1;
		break;
	case PGP_PTAG_CT_TRUST:
		key = &keyring->keys[keyring->keyc - 1];
		key->subsigs[key->subsigc - 1].trustlevel = pkt->u.ss_trust.level;
		key->subsigs[key->subsigc - 1].trustamount = pkt->u.ss_trust.amount;
		break;
	case PGP_PTAG_SS_KEY_EXPIRY:
		EXPAND_ARRAY(keyring, key);
		if (keyring->keyc > 0) {
			keyring->keys[keyring->keyc - 1].key.pubkey.duration = pkt->u.ss_time;
		}
		break;
	case PGP_PTAG_SS_ISSUER_KEY_ID:
		key = &keyring->keys[keyring->keyc - 1];
		(void) memcpy(&key->subsigs[key->subsigc - 1].sig.info.signer_id,
			      pkt->u.ss_issuer,
			      sizeof(pkt->u.ss_issuer));
		key->subsigs[key->subsigc - 1].sig.info.signer_id_set = 1;
		break;
	case PGP_PTAG_SS_CREATION_TIME:
		key = &keyring->keys[keyring->keyc - 1];
		key->subsigs[key->subsigc - 1].sig.info.birthtime = pkt->u.ss_time;
		key->subsigs[key->subsigc - 1].sig.info.birthtime_set = 1;
		break;
	case PGP_PTAG_SS_EXPIRATION_TIME:
		key = &keyring->keys[keyring->keyc - 1];
		key->subsigs[key->subsigc - 1].sig.info.duration = pkt->u.ss_time;
		key->subsigs[key->subsigc - 1].sig.info.duration_set = 1;
		break;
	case PGP_PTAG_SS_PRIMARY_USER_ID:
		key = &keyring->keys[keyring->keyc - 1];
		key->uid0 = key->uidc - 1;
		break;
	case PGP_PTAG_SS_REVOCATION_REASON:
		key = &keyring->keys[keyring->keyc - 1];
		if (key->uidc == 0) {
			/* revoke whole key */
			key->revoked = 1;
			revocation = &key->revocation;
		} else {
			/* revoke the user id */
			EXPAND_ARRAY(key, revoke);
			revocation = &key->revokes[key->revokec];
			key->revokes[key->revokec].uid = key->uidc - 1;
			key->revokec += 1;
		}
		revocation->code = pkt->u.ss_revocation.code;
		revocation->reason = rnp_strdup(pgp_show_ss_rr_code(pkt->u.ss_revocation.code));
		break;
	case PGP_PTAG_CT_SIGNATURE_FOOTER:
	case PGP_PARSER_ERRCODE:
		break;

	default:
		break;
	}

	return PGP_RELEASE_MEMORY;
}

/**
   \ingroup HighLevel_KeyringRead

   \brief Reads a keyring from a file

   \param keyring Pointer to an existing keyring_t struct
   \param armour 1 if file is armoured; else 0
   \param filename Filename of keyring to be read

   \return pgp 1 if OK; 0 on error

   \note Keyring struct must already exist.

   \note Can be used with either a public or secret keyring.

   \note You must call pgp_keyring_free() after usage to free alloc-ed memory.

   \note If you call this twice on the same keyring struct, without calling
   pgp_keyring_free() between these calls, you will introduce a memory leak.

   \sa pgp_keyring_read_from_mem()
   \sa pgp_keyring_free()

*/

unsigned 
pgp_keyring_fileread(keyring_t *keyring,
			const unsigned armour,
			const char *filename)
{
	pgp_stream_t	*stream;
	keyringcb_t	 cb;
	unsigned	 res = 1;
	int		 fd;

	(void) memset(&cb, 0x0, sizeof(cb));
	cb.keyring = keyring;
	stream = pgp_new(sizeof(*stream));

	/* add this for the moment, */
	/*
	 * \todo need to fix the problems with reading signature subpackets
	 * later
	 */

	/* pgp_parse_options(parse,PGP_PTAG_SS_ALL,PGP_PARSE_RAW); */
	pgp_parse_options(stream, PGP_PTAG_SS_ALL, PGP_PARSE_PARSED);

#ifdef O_BINARY
	fd = open(filename, O_RDONLY | O_BINARY);
#else
	fd = open(filename, O_RDONLY);
#endif
	if (fd < 0) {
		pgp_stream_delete(stream);
		perror(filename);
		return 0;
	}
#ifdef USE_MMAP_FOR_FILES
	pgp_reader_set_mmap(stream, fd);
#else
	pgp_reader_set_fd(stream, fd);
#endif

	pgp_set_callback(stream, cb_keyring_read, &cb);

	if (armour) {
		pgp_reader_push_dearmour(stream);
	}
	res = pgp_parse_and_accumulate(keyring, stream);
	pgp_print_errors(pgp_stream_get_errors(stream));

	if (armour) {
		pgp_reader_pop_dearmour(stream);
	}

	(void)close(fd);

	pgp_stream_delete(stream);

	return res;
}

/**
   \ingroup HighLevel_KeyringRead

   \brief Reads a keyring from memory

   \param keyring Pointer to existing keyring_t struct
   \param armour 1 if file is armoured; else 0
   \param mem Pointer to a pgp_memory_t struct containing keyring to be read

   \return pgp 1 if OK; 0 on error

   \note Keyring struct must already exist.

   \note Can be used with either a public or secret keyring.

   \note You must call pgp_keyring_free() after usage to free alloc-ed memory.

   \note If you call this twice on the same keyring struct, without calling
   pgp_keyring_free() between these calls, you will introduce a memory leak.

   \sa pgp_keyring_fileread
   \sa pgp_keyring_free
*/
unsigned 
pgp_keyring_read_from_mem(io_t *io,
				keyring_t *keyring,
				const unsigned armour,
				pgp_memory_t *mem)
{
	pgp_stream_t	*stream;
	const unsigned	 noaccum = 0;
	keyringcb_t	 cb;
	unsigned	 res;

	(void) memset(&cb, 0x0, sizeof(cb));
	cb.keyring = keyring;
	stream = pgp_new(sizeof(*stream));
	pgp_parse_options(stream, PGP_PTAG_SS_ALL, PGP_PARSE_PARSED);
	pgp_setup_memory_read(io, &stream, mem, &cb, cb_keyring_read,
					noaccum);
	if (armour) {
		pgp_reader_push_dearmour(stream);
	}
	res = (unsigned)pgp_parse_and_accumulate(keyring, stream);
	pgp_print_errors(pgp_stream_get_errors(stream));
	if (armour) {
		pgp_reader_pop_dearmour(stream);
	}
	/* don't call teardown_memory_read because memory was passed in */
	pgp_stream_delete(stream);
	return res;
}
