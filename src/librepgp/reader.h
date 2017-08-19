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

#ifndef READER_H_
#define READER_H_

#include "packet-create.h"

/* if this is defined, we'll use mmap in preference to file ops */
#define USE_MMAP_FOR_FILES 1

void pgp_reader_set_fd(pgp_stream_t *, int);
void pgp_reader_set_mmap(pgp_stream_t *, int);
void pgp_reader_set_memory(pgp_stream_t *, const void *, size_t);

/* Do a sum mod 65536 of all bytes read (as needed for secret keys) */
void     pgp_reader_push_sum16(pgp_stream_t *);
uint16_t pgp_reader_pop_sum16(pgp_stream_t *);

void pgp_reader_push_se_ip_data(pgp_stream_t *, pgp_crypt_t *, pgp_region_t *);
void pgp_reader_pop_se_ip_data(pgp_stream_t *);

unsigned pgp_reader_set_accumulate(pgp_stream_t *, unsigned);

/* file reading */
int pgp_setup_file_read(pgp_io_t *,
                        pgp_stream_t **,
                        const char *,
                        void *,
                        pgp_cb_ret_t callback(const pgp_packet_t *, pgp_cbdata_t *),
                        unsigned);
void pgp_teardown_file_read(pgp_stream_t *, int);

/* memory reading */
int pgp_setup_memory_read(pgp_io_t *,
                          pgp_stream_t **,
                          pgp_memory_t *,
                          void *,
                          pgp_cb_ret_t callback(const pgp_packet_t *, pgp_cbdata_t *),
                          unsigned);
void pgp_teardown_memory_read(pgp_stream_t *, pgp_memory_t *);

void pgp_reader_push_dearmour(pgp_stream_t *);
void pgp_reader_pop_dearmour(pgp_stream_t *);

#endif /* READER_H_ */
