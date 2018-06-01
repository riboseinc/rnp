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
 */

#ifndef SIGNATURE_H_
#define SIGNATURE_H_

#include <sys/types.h>
#include <stdbool.h>

#include <inttypes.h>

#include <repgp/repgp.h>
#include <rnp/rnp_types.h>
#include "memory.h"

bool pgp_check_useridcert_sig(rnp_ctx_t *,
                              const pgp_key_pkt_t *,
                              const uint8_t *,
                              const pgp_sig_t *,
                              const pgp_key_pkt_t *,
                              const uint8_t *);
bool pgp_check_userattrcert_sig(rnp_ctx_t *,
                                const pgp_key_pkt_t *,
                                const pgp_data_t *,
                                const pgp_sig_t *,
                                const pgp_key_pkt_t *,
                                const uint8_t *);
bool pgp_check_subkey_sig(rnp_ctx_t *,
                          const pgp_key_pkt_t *,
                          const pgp_key_pkt_t *,
                          const pgp_sig_t *,
                          const pgp_key_pkt_t *,
                          const uint8_t *);
bool pgp_check_direct_sig(rnp_ctx_t *,
                          const pgp_key_pkt_t *,
                          const pgp_sig_t *,
                          const pgp_key_pkt_t *,
                          const uint8_t *);

/* Standard Interface */

bool pgp_check_sig(
  rng_t *, const uint8_t *, unsigned, const pgp_sig_t *, const pgp_key_pkt_t *);

#endif /* SIGNATURE_H_ */
