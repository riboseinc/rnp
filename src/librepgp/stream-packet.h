/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#ifndef STREAM_PACKET_H_
#define STREAM_PACKET_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "errors.h"
#include <repgp/repgp.h>
#include <rnp/rnp.h>
#include "stream-common.h"

/* structure to write non-stream packets without need to precalculate the length */
typedef struct pgp_packet_body_t {
    int      tag;       /* packet tag */
    uint8_t *data;      /* packet body data */
    size_t   len;       /* current len of the data */
    size_t   allocated; /* allocated bytes in data */
} pgp_packet_body_t;

/** @brief write new packet length
 *  @param buf pre-allocated buffer, must have 5 bytes
 *  @param len packet length
 *  @return number of bytes, saved in buf
 **/
size_t write_packet_len(uint8_t *buf, size_t len);

/** @brief get packet type from the packet header byte
 *  @param ptag first byte of the packet header
 *  @return packet type or -1 if ptag is wrong
 **/
int get_packet_type(uint8_t ptag);

/** @brief Read packet length for fixed-size (say, small) packet. Returns -1 on error.
 *  Will also read packet tag byte. We do not allow partial length here as well as large packets (so ignoring possible ssize_t overflow)
 * 
 *  @param src source to read length from
 *  @return length of the packet or -1 if there is read error or packet length is ill-formed
 **/
ssize_t stream_read_pkt_len(pgp_source_t *src);

/** @brief initialize writing of packet body
 *  @param body preallocated structure
 *  @param tag tag of the packet
 *  @return true on success or false otherwise
 **/
bool init_packet_body(pgp_packet_body_t *body, int tag);

/** @brief add chunk of the data to packet body
 *  @param body pointer to the structure, initialized with init_packet_body
 *  @param data non-NULL pointer to the data
 *  @param len number of bytes to add
 *  @return true if data was copied successfully, or false otherwise
 **/
bool add_packet_body(pgp_packet_body_t *body, void *data, size_t len);

/** @brief add single byte to packet body
 *  @param body pointer to the structure, initialized with init_packet_body
 *  @param byte byte to add
 *  @return true if byte was added successfully, or false otherwise
 **/
bool add_packet_body_byte(pgp_packet_body_t *body, uint8_t byte);

/** @brief deallocate data inside of packet body structure
 *  @param body initialized packet body
 *  @return void
 **/
void free_packet_body(pgp_packet_body_t *body);

/** @brief write packet header, length and body to the dest
 *  This will also deallocate internally used memory, so no free_packet_body call is needed
 * 
 *  @param body populated with data packet body
 *  @param dst destination to write to
 *  @return void
 **/
void stream_flush_packet_body(pgp_packet_body_t *body, pgp_dest_t *dst);

/** @brief read 'short-length' packet body (including tag and length bytes) from the source
 *  @param src source to read from
 *  @param body pre-allocated body structure. Do not call init_packet_body on it!
 *  @return RNP_SUCCESS or error code if operation failed
 **/
rnp_result_t stream_read_packet_body(pgp_source_t *src, pgp_packet_body_t *body);

/* Packet handling functions */

bool stream_write_sk_sesskey(pgp_sk_sesskey_t *skey, pgp_dest_t *dst);

bool stream_write_pk_sesskey(pgp_pk_sesskey_pkt_t *skey, pgp_dest_t *dst);

rnp_result_t stream_parse_sk_sesskey(pgp_source_t *src, pgp_sk_sesskey_t *skey);

rnp_result_t stream_parse_pk_sesskey(pgp_source_t *src, pgp_pk_sesskey_t *pkey);


#endif
