/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#include <sys/types.h>
#include <sys/param.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "create.h"
#include "key_store.h"
#include "key_store_pgp.h"
#include "key_store_kbx.h"

#define BLOB_SIZE_LIMIT (5 * 1024 * 1024) // same limit with GnuPG 2.1

#define BLOB_HEADER_SIZE 0x5
#define BLOB_FIRST_SIZE 0x20

static uint8_t
ru8(uint8_t *p)
{
    return (uint8_t) p[0];
}

static uint16_t
ru16(uint8_t *p)
{
    return (uint16_t)(((uint8_t) p[0] << 8) | (uint8_t) p[1]);
}

static uint32_t
ru32(uint8_t *p)
{
    return (uint32_t)(((uint8_t) p[0] << 24) | ((uint8_t) p[1] << 16) | ((uint8_t) p[2] << 8) |
                      (uint8_t) p[3]);
}

static int
rnp_key_store_kbx_parse_header_blob(kbx_header_blob_t *first_blob)
{
    uint8_t *image = first_blob->blob.image;

    image += BLOB_HEADER_SIZE;

    if (first_blob->blob.length != BLOB_FIRST_SIZE) {
        fprintf(stderr,
                "The first blob has wrong length: %u but expected %u\n",
                first_blob->blob.length,
                BLOB_FIRST_SIZE);
        return 0;
    }

    first_blob->version = ru8(image);
    image += 1;

    if (first_blob->version != 1) {
        fprintf(stderr, "Wrong version, expect 1 but has %u\n", first_blob->version);
        return 0;
    }

    first_blob->flags = ru16(image);
    image += 2;

    // blob should contains a magic KBXf
    if (strncasecmp((const char *) (image), "KBXf", 4)) {
        fprintf(stderr, "The first blob hasn't got a KBXf magic string\n");
        return 0;
    }

    image += 3;

    // RFU
    image += 4;

    first_blob->file_created_at = ru32(image);
    image += 4;

    first_blob->file_created_at = ru32(image + 15);
    image += 4;

    // RFU
    image += 4;

    // RFU
    image += 4;

    return 1;
}

static int
rnp_key_store_kbx_parse_pgp_blob(kbx_pgp_blob_t *pgp_blob)
{
    int      i;
    uint8_t *image = pgp_blob->blob.image;

    image += BLOB_HEADER_SIZE;

    pgp_blob->version = ru8(image);
    image += 1;

    if (pgp_blob->version != 1) {
        fprintf(stderr, "Wrong version, expect 1 but has %u\n", pgp_blob->version);
        return 0;
    }

    pgp_blob->flags = ru16(image);
    image += 2;

    pgp_blob->keyblock_offset = ru32(image);
    image += 4;

    pgp_blob->keyblock_length = ru32(image);
    image += 4;

    if (pgp_blob->keyblock_offset > pgp_blob->blob.length ||
        pgp_blob->blob.length < (pgp_blob->keyblock_offset + pgp_blob->keyblock_length)) {
        fprintf(
          stderr,
          "Wrong keyblock offset/length, blob size: %u, keyblock offset: %u, length: %u\n",
          pgp_blob->blob.length,
          pgp_blob->keyblock_offset,
          pgp_blob->keyblock_length);
        return 0;
    }

    pgp_blob->nkeys = ru16(image);
    image += 2;

    if (pgp_blob->nkeys < 1) {
        fprintf(stderr,
                "PGP blob should contains at least 1 key, it contains: %u keys\n",
                pgp_blob->nkeys);
        return 0;
    }

    pgp_blob->keys_len = ru16(image);
    image += 2;

    if (pgp_blob->keys_len < 28) {
        fprintf(
          stderr,
          "PGP blob should contains keys structure at least 28 bytes, it contains: %u bytes\n",
          pgp_blob->keys_len);
        return 0;
    }

    for (i = 0; i < pgp_blob->nkeys; i++) {
        EXPAND_ARRAY(pgp_blob, key);
        if (pgp_blob->keys == NULL) {
            return 0;
        }

        // copy fingerprint
        memcpy(pgp_blob->keys[pgp_blob->keyc].fp, image, 20);
        image += 20;

        pgp_blob->keys[pgp_blob->keyc].keyid_offset = ru32(image);
        image += 4;

        pgp_blob->keys[pgp_blob->keyc].flags = ru16(image);
        image += 2;

        // RFU
        image += 2;

        // skip padding bytes if it existed
        image += (pgp_blob->keys_len - 28);
    }

    pgp_blob->sn_size = ru16(image);
    image += 2;

    if (pgp_blob->sn_size > pgp_blob->blob.length - (image - pgp_blob->blob.image)) {
        fprintf(stderr,
                "Serial number is %u and it's bigger that blob size it can use: %u\n",
                pgp_blob->sn_size,
                (uint32_t)(pgp_blob->blob.length - (image - pgp_blob->blob.image)));
        return 0;
    }

    if (pgp_blob->sn_size > 0) {
        pgp_blob->sn = malloc(pgp_blob->sn_size);
        if (pgp_blob->sn == NULL) {
            fprintf(stderr, "bad malloc\n");
            return 0;
        }

        memcpy(pgp_blob->sn, image, pgp_blob->sn_size);
        image += pgp_blob->sn_size;
    }

    pgp_blob->nuids = ru16(image);
    image += 2;

    pgp_blob->uids_len = ru16(image);
    image += 2;

    if (pgp_blob->uids_len < 12) {
        fprintf(
          stderr,
          "PGP blob should contains UID structure at least 12 bytes, it contains: %u bytes\n",
          pgp_blob->uids_len);
        return 0;
    }

    for (i = 0; i < pgp_blob->nuids; i++) {
        EXPAND_ARRAY(pgp_blob, uid);
        if (pgp_blob->uids == NULL) {
            return 0;
        }

        pgp_blob->uids[pgp_blob->uidc].offset = ru32(image);
        image += 4;

        pgp_blob->uids[pgp_blob->uidc].length = ru32(image);
        image += 4;

        pgp_blob->uids[pgp_blob->uidc].flags = ru16(image);
        image += 2;

        pgp_blob->uids[pgp_blob->uidc].validity = ru8(image);
        image += 1;

        // RFU
        image += 1;

        // skip padding bytes if it existed
        image += (pgp_blob->uids_len - 12);
    }

    pgp_blob->nsigs = ru16(image);
    image += 2;

    pgp_blob->sigs_len = ru16(image);
    image += 2;

    if (pgp_blob->sigs_len < 4) {
        fprintf(
          stderr,
          "PGP blob should contains SIGN structure at least 4 bytes, it contains: %u bytes\n",
          pgp_blob->uids_len);
        return 0;
    }

    for (i = 0; i < pgp_blob->nsigs; i++) {
        EXPAND_ARRAY(pgp_blob, sig);
        if (pgp_blob->sigs == NULL) {
            return 0;
        }

        pgp_blob->sigs[pgp_blob->sigc].expired = ru32(image);
        image += 4;

        // skip padding bytes if it existed
        image += (pgp_blob->sigs_len - 4);
    }

    pgp_blob->ownertrust = ru8(image);
    image += 1;

    pgp_blob->all_Validity = ru8(image);
    image += 1;

    // RFU
    image += 2;

    pgp_blob->recheck_after = ru32(image);
    image += 4;

    pgp_blob->latest_timestamp = ru32(image);
    image += 4;

    pgp_blob->blob_created_at = ru32(image);
    image += 4;

    // here starts keyblock, UID and reserved space for future usage

    // Maybe we should add checksum verify but GnuPG never checked it
    // Checksum is last 20 bytes of blob and it is SHA-1, if it invalid MD5 and starts from 4
    // zero it is MD5.

    return 1;
}

static kbx_blob_t *
rnp_key_store_kbx_parse_blob(uint8_t *image, uint32_t image_len)
{
    uint32_t      length;
    kbx_blob_t *  blob;
    kbx_blob_type type;

    // a blob shouldn't be less of length + type
    if (image_len < BLOB_HEADER_SIZE) {
        fprintf(stderr, "Blob size is %u but it shouldn't be less of header\n", image_len);
        return NULL;
    }

    length = ru32(image + 0);
    type = (kbx_blob_type) ru8(image + 4);

    switch (type) {
    case KBX_EMPTY_BLOB:
        blob = calloc(1, sizeof(kbx_blob_t));
        break;

    case KBX_HEADER_BLOB:
        blob = calloc(1, sizeof(kbx_header_blob_t));
        break;

    case KBX_PGP_BLOB:
        blob = calloc(1, sizeof(kbx_pgp_blob_t));
        break;

    case KBX_X509_BLOB:
        // current we doesn't parse X509 blob, so, keep it as is
        blob = calloc(1, sizeof(kbx_blob_t));
        break;

    // unsuported blob type
    default:
        fprintf(stderr, "Unsupported blob type: %d\n", type);
        return NULL;
    }

    if (blob == NULL) {
        fprintf(stderr, "Can't allocate memory\n");
        return NULL;
    }

    blob->image = image;
    blob->length = length;
    blob->type = type;

    // call real parser of blob
    switch (type) {
    case KBX_HEADER_BLOB:
        if (!rnp_key_store_kbx_parse_header_blob((kbx_header_blob_t *) blob)) {
            free(blob);
            return NULL;
        }
        break;

    case KBX_PGP_BLOB:
        if (!rnp_key_store_kbx_parse_pgp_blob((kbx_pgp_blob_t *) blob)) {
            free(blob);
            return NULL;
        }
        break;

    default:
        break;
    }

    return blob;
}

int
rnp_key_store_kbx_from_mem(pgp_io_t *io, rnp_key_store_t *key_store, pgp_memory_t *memory)
{
    size_t   has_bytes;
    uint8_t *buf;
    uint32_t blob_length;

    pgp_memory_t    mem;
    kbx_pgp_blob_t *pgp_blob;

    has_bytes = memory->length;
    buf = memory->buf;
    while (has_bytes > 0) {
        blob_length = ru32(buf);
        if (blob_length > BLOB_SIZE_LIMIT) {
            fprintf(io->errs,
                    "Blob size is %d bytes but limit is %d bytes\n",
                    blob_length,
                    BLOB_SIZE_LIMIT);
            return 0;
        }
        if (has_bytes < blob_length) {
            fprintf(io->errs,
                    "Blob have size %d bytes but file contains only %zu bytes\n",
                    blob_length,
                    has_bytes);
            return 0;
        }
        EXPAND_ARRAY(key_store, blob);
        if (key_store->blobs == NULL) {
            return 0;
        }
        key_store->blobs[key_store->blobc] = rnp_key_store_kbx_parse_blob(buf, blob_length);
        if (key_store->blobs[key_store->blobc] == NULL) {
            return 0;
        }

        if (key_store->blobs[key_store->blobc]->type == KBX_PGP_BLOB) {
            // parse keyblock if it existed
            pgp_blob = ((kbx_pgp_blob_t *) key_store->blobs[key_store->blobc]);

            mem.buf = key_store->blobs[key_store->blobc]->image + pgp_blob->keyblock_offset;
            mem.length = pgp_blob->keyblock_length;
            mem.mmapped = 0;
            mem.allocated = 0;

            if (pgp_blob->keyblock_length == 0) {
                fprintf(io->errs, "PGP blob have zero size\n");
                return 0;
            }

            if (!rnp_key_store_pgp_read_from_mem(io, key_store, 0, &mem)) {
                return 0;
            }
        }

        key_store->blobc++;
        has_bytes -= blob_length;
        buf += blob_length;
    }

    return 1;
}

static int
pu8(pgp_memory_t *mem, uint8_t p)
{
    return pgp_memory_add(mem, &p, 1);
}

static int
pu16(pgp_memory_t *mem, uint16_t f)
{
    uint8_t p[2];

    p[0] = (uint8_t)(f >> 8);
    p[1] = (uint8_t) f;

    return pgp_memory_add(mem, p, 2);
}

static int
pu32(pgp_memory_t *mem, uint32_t f)
{
    uint8_t p[4];

    p[0] = (uint8_t)(f >> 24);
    p[1] = (uint8_t)(f >> 16);
    p[2] = (uint8_t)(f >> 8);
    p[3] = (uint8_t) f;

    return pgp_memory_add(mem, p, 4);
}

static int
rnp_key_store_kbx_write_header(rnp_key_store_t *key_store, pgp_memory_t *m)
{
    uint16_t flags = 0;
    uint32_t file_created_at = time(NULL);

    if (key_store->blobc > 0 && key_store->blobs[0]->type == KBX_HEADER_BLOB) {
        file_created_at = ((kbx_header_blob_t *) key_store->blobs[0])->file_created_at;
    }

    return !(!pu32(m, BLOB_FIRST_SIZE) || !pu8(m, KBX_HEADER_BLOB) || !pu8(m, 1) // version
             ||
             !pu16(m, flags) || !pgp_memory_add(m, (const uint8_t *) "KBXf", 4) ||
             !pu32(m, 0) // RFU
             ||
             !pu32(m, 0) // RFU
             ||
             !pu32(m, file_created_at) || !pu32(m, time(NULL)) || !pu32(m, 0)); // RFU
}

static int
rnp_key_store_kbx_write_pgp(pgp_io_t *     io,
                            pgp_key_t *    key,
                            const uint8_t *passphrase,
                            pgp_memory_t * m)
{
    int          i, rc;
    size_t       start, key_start, uid_start;
    uint8_t *    p;
    uint8_t      checksum[20];
    uint32_t     pt;
    pgp_hash_t   hash = {0};
    pgp_output_t output = {};

    start = m->length;

    if (!pu32(m, 0)) { // length, we don't know length of blbo, so it's 0 right now
        return 0;
    }

    if (!pu8(m, KBX_PGP_BLOB) || !pu8(m, 1)) { // type, version
        return 0;
    }

    if (!pu16(m, 0)) { // flags, not used by GnuPG
        return 0;
    }

    if (!pu32(m, 0) || !pu32(m, 0)) { // offset and length of keyblock, update later
        return 0;
    }

    if (!pu16(m, 1) || !pu16(m, 28)) {
        return 0;
    }

    if (!pgp_memory_add(m, key->sigfingerprint.fingerprint, PGP_FINGERPRINT_SIZE)) {
        return 0;
    }

    if (!pu32(m, (m->length - PGP_FINGERPRINT_SIZE + 8) - start)) {
        return 0;
    }

    if (!pu16(m, 0)) { // flags, not used by GnuPG
        return 0;
    }

    if (!pu16(m, 0)) { // RFU
        return 0;
    }

    // here we can add something to padding, but we keep 28 byte per record

    if (!pu16(m, 0)) { // Zero size of serial number
        return 0;
    }

    // skip serial number

    if (!pu16(m, key->uidc) || !pu16(m, 12)) {
        return 0;
    }

    uid_start = m->length;

    for (i = 0; i < key->uidc; i++) {
        if (!pu32(m, 0) || !pu32(m, 0)) { // UID offset and length, update when blob has done
            return 0;
        }

        if (!pu16(m, 0)) { // flags, (not yet used)
            return 0;
        }

        if (!pu8(m, 0) || !pu8(m, 0)) { // Validity & RFU
            return 0;
        }
    }

    if (!pu16(m, key->subsigc) || !pu16(m, 4)) {
        return 0;
    }

    for (i = 0; i < key->subsigc; i++) {
        if (!pu32(m, key->subsigs[i].sig.info.duration)) {
            return 0;
        }
    }

    if (!pu8(m, 0) || !pu8(m, 0)) { // Assigned ownertrust & All_Validity (not yet used)
        return 0;
    }

    if (!pu16(m, 0) || !pu32(m, 0)) { // RFU & Recheck_after
        return 0;
    }

    if (!pu32(m, time(NULL)) || !pu32(m, time(NULL))) { // Latest timestamp && created
        return 0;
    }

    if (!pu32(m, 0)) { // Size of reserved space
        return 0;
    }

    // wrtite UID, we might redesign PGP write and use this information from keyblob
    for (i = 0; i < key->uidc; i++) {
        p = m->buf + uid_start + (12 * i);
        pt = m->length - start;

        p[0] = (uint8_t)(pt >> 24);
        p[1] = (uint8_t)(pt >> 16);
        p[2] = (uint8_t)(pt >> 8);
        p[3] = (uint8_t) pt;

        pt = strlen((const char *) key->uids[i]);
        if (!pgp_memory_add(m, key->uids[i], pt)) {
            return 0;
        }

        p += 4;
        p[0] = (uint8_t)(pt >> 24);
        p[1] = (uint8_t)(pt >> 16);
        p[2] = (uint8_t)(pt >> 8);
        p[3] = (uint8_t) pt;
    }

    // write keyblock and fix the offset/length
    key_start = m->length;
    pt = key_start - start;
    p = m->buf + start + 8;
    p[0] = (uint8_t)(pt >> 24);
    p[1] = (uint8_t)(pt >> 16);
    p[2] = (uint8_t)(pt >> 8);
    p[3] = (uint8_t) pt;

    pgp_writer_set_memory(&output, m);

    if (!pgp_write_xfer_anykey(&output, key, passphrase, NULL, 0)) {
        return 0;
    }

    rc = pgp_writer_close(&output);
    pgp_writer_info_delete(&output.writer);
    if (!rc) {
        return 0;
    }

    pt = m->length - key_start;
    p = m->buf + start + 12;

    p[0] = (uint8_t)(pt >> 24);
    p[1] = (uint8_t)(pt >> 16);
    p[2] = (uint8_t)(pt >> 8);
    p[3] = (uint8_t) pt;

    // fix the length of blob
    pt = m->length - start + 20;
    p = m->buf + start;

    p[0] = (uint8_t)(pt >> 24);
    p[1] = (uint8_t)(pt >> 16);
    p[2] = (uint8_t)(pt >> 8);
    p[3] = (uint8_t) pt;

    // checksum
    if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
        fprintf(stderr, "rnp_key_store_kbx_write_pgp: bad sha1 alloc\n");
        return 0;
    }

    if (hash._output_len != 20) {
        fprintf(stderr,
                "rnp_key_store_kbx_write_pgp: wrong hash size %zu, should be 20 bytes\n",
                hash._output_len);
        return 0;
    }

    pgp_hash_add(&hash, m->buf + start, m->length - start);

    if (!pgp_hash_finish(&hash, checksum)) {
        return 0;
    }

    if (!(pgp_memory_add(m, checksum, 20))) {
        return 0;
    }

    return 1;
}

static int
rnp_key_store_kbx_write_x509(rnp_key_store_t *key_store, pgp_memory_t *m)
{
    for (int i = 0; i < key_store->blobc; i++) {
        if (key_store->blobs[i]->type == KBX_X509_BLOB) {
            if (!pgp_memory_add(m, key_store->blobs[i]->image, key_store->blobs[i]->length)) {
                return 0;
            }
        }
    }

    return 1;
}

int
rnp_key_store_kbx_to_mem(pgp_io_t *       io,
                         rnp_key_store_t *key_store,
                         const uint8_t *  passphrase,
                         pgp_memory_t *   memory)
{
    int i;

    pgp_memory_clear(memory);

    if (!rnp_key_store_kbx_write_header(key_store, memory)) {
        fprintf(io->errs, "Can't write KBX header\n");
        return 0;
    }

    for (i = 0; i < key_store->keyc; i++) {
        if (!rnp_key_store_kbx_write_pgp(io, &key_store->keys[i], passphrase, memory)) {
            fprintf(io->errs, "Can't write PGP blobs for key %d\n", i);
            return 0;
        }
    }

    if (!rnp_key_store_kbx_write_x509(key_store, memory)) {
        fprintf(io->errs, "Can't write X509 blobs\n");
        return 0;
    }

    return 1;
}
