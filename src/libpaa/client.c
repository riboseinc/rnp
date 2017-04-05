/*-
 * Copyright (c) 2010 Alistair Crooks <agc@NetBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/types.h>

#include <netdb.h>

#include <rnp.h>
#include <regex.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../common/constants.h"
#include "libpaa.h"

#define DEFAULT_HASH_ALG "SHA256"

int
main(int argc, char **argv)
{
	paa_response_t response;
	rnp_t          rnp;
	char           challenge[2048];
	char           buf[2048];
	int            challengec;
	int            cc;
	int            i;

	memset(&response, '\0', sizeof(response));

	if (! rnp_init(&rnp)) {
		fprintf(stderr, "can't initialise rnp\n");
		return EXIT_FAILURE;
	}

	while ((i = getopt(argc, argv, "S:d:r:u:")) != -1) {
		switch(i) {
		case 'S':
			rnp_setvar(&rnp, "ssh keys", "1");
			rnp_setvar(&rnp, "sshkeyfile", optarg);
			break;
		/* XXX: Why are these options knocked out? */
		case 'd':
			/* challenge.domain = optarg */;
			break;
		case 'r':
			/* challenge.realm = optarg */;
			response.realm = optarg;
			break;
		case 'u':
			rnp_setvar(&rnp, "userid", optarg);
			break;
		}
	}

	rnp_setvar(&rnp, "hash", DEFAULT_HASH_ALG);
	rnp_setvar(&rnp, "need seckey", "1");
	rnp_setvar(&rnp, "need userid", "1");

	/* XXX: This action is common to every implementation - it needs to
	 *      be either delegated to the library or a common modules
	 *      library.
	 */
	rnp_set_homedir(&rnp, getenv("HOME"),
			rnp_getvar(&rnp, "ssh keys")
				? SUBDIRECTORY_SSH : SUBDIRECTORY_GNUPG, 1);

	/* read challenge into challenge */
	challengec = read(0, challenge, sizeof(challenge));
	cc = paa_format_response(&response, &rnp, challenge, buf, sizeof(buf));
	write(1, buf, cc);

	/* TODO: Free the rnp context. */

	return EXIT_SUCCESS;
}
