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
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: reader.c,v 1.49 2012/03/05 02:20:18 christos Exp $");
#endif

#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <repgp/repgp.h>

#include <rnp/rnp_sdk.h>
#include "signature.h"
#include "pgp-key.h"

#include "packet-print.h"

/* data from partial blocks is queued up in virtual block in stream */
static int
read_partial_data(pgp_stream_t *stream, void *dest, size_t length)
{
    unsigned n;

    if (rnp_get_debug(__FILE__)) {
        (void) fprintf(stderr, "fd_reader: coalesced data, off %d\n", stream->virtualoff);
    }
    n = MIN(stream->virtualc - stream->virtualoff, (unsigned) length);
    (void) memcpy(dest, &stream->virtualpkt[stream->virtualoff], n);
    stream->virtualoff += n;
    if (stream->virtualoff == stream->virtualc) {
        free(stream->virtualpkt);
        stream->virtualpkt = NULL;
        stream->virtualc = stream->virtualoff = 0;
    }
    return (int) n;
}

/* get a pass phrase from the user */
bool
pgp_getpassphrase(void *in, char *phrase, size_t size)
{
    char * p;
    size_t len;

    if (in == NULL) {
        while ((p = getpass("rnp passphrase: ")) == NULL) {
        }
        (void) snprintf(phrase, size, "%s", p);
    } else {
        memset(phrase, 0, size);
        if (fgets(phrase, (int) size, in) == NULL) {
            return false;
        }

        len = strlen(phrase);
        if (len >= 1 && phrase[len - 1] == '\n') {
            phrase[len - 1] = '\0';
        }
    }
    return true;
}

/**
 * \ingroup Internal_Readers_Generic
 * \brief Starts reader stack
 * \param stream Parse settings
 * \param reader Reader to use
 * \param destroyer Destroyer to use
 * \param vp Reader-specific arg
 */
void
pgp_reader_set(pgp_stream_t *          stream,
               pgp_reader_func_t *     reader,
               pgp_reader_destroyer_t *destroyer,
               void *                  vp)
{
    stream->readinfo.reader = reader;
    stream->readinfo.destroyer = destroyer;
    stream->readinfo.arg = vp;
}

/**
 * \ingroup Internal_Readers_Generic
 * \brief Adds to reader stack
 * \param stream Parse settings
 * \param reader Reader to use
 * \param destroyer Reader's destroyer
 * \param vp Reader-specific arg
 */
bool
pgp_reader_push(pgp_stream_t *          stream,
                pgp_reader_func_t *     reader,
                pgp_reader_destroyer_t *destroyer,
                void *                  vp)
{
    pgp_reader_t *readinfo;

    if ((readinfo = calloc(1, sizeof(*readinfo))) == NULL) {
        (void) fprintf(stderr, "pgp_reader_push: bad alloc\n");
        return false;
    }

    *readinfo = stream->readinfo;
    (void) memset(&stream->readinfo, 0x0, sizeof(stream->readinfo));
    stream->readinfo.next = readinfo;
    stream->readinfo.parent = stream;

    /* should copy accumulate flags from other reader? RW */
    stream->readinfo.accumulate = readinfo->accumulate;

    pgp_reader_set(stream, reader, destroyer, vp);
    return true;
}

/**
 * \ingroup Internal_Readers_Generic
 * \brief Removes from reader stack
 * \param stream Parse settings
 */
void
pgp_reader_pop(pgp_stream_t *stream)
{
    pgp_reader_t *next = stream->readinfo.next;

    stream->readinfo = *next;
    free(next);
}

/**
 * \ingroup Internal_Readers_Generic
 * \brief Gets arg from reader
 * \param readinfo Reader info
 * \return Pointer to reader info's arg
 */
void *
pgp_reader_get_arg(pgp_reader_t *readinfo)
{
    return readinfo->arg;
}

/**************************************************************************/

#define CRC24_POLY 0x1864cfbL

enum {
    NONE = 0,
    BEGIN_PGP_MESSAGE,
    BEGIN_PGP_PUBLIC_KEY_BLOCK,
    BEGIN_PGP_PRIVATE_KEY_BLOCK,
    BEGIN_PGP_MULTI,
    BEGIN_PGP_SIGNATURE,

    END_PGP_MESSAGE,
    END_PGP_PUBLIC_KEY_BLOCK,
    END_PGP_PRIVATE_KEY_BLOCK,
    END_PGP_MULTI,
    END_PGP_SIGNATURE,

    BEGIN_PGP_SIGNED_MESSAGE
};

/**
 * \struct dearmour_t
 */
typedef struct {
    enum { OUTSIDE_BLOCK = 0, BASE64, AT_TRAILER_NAME } state;
    int           lastseen;
    pgp_stream_t *parse_info;
    unsigned      seen_nl : 1;
    unsigned      prev_nl : 1;
    unsigned      allow_headers_without_gap : 1;
    /* !< allow headers in armoured data that are
     * not separated from the data by a blank line
     * */
    unsigned allow_no_gap : 1;
    /* !< allow no blank line at the start of
     * armoured data */
    unsigned allow_trailing_whitespace : 1;
    /* !< allow armoured stuff to have trailing
     * whitespace where we wouldn't strictly expect
     * it */
    /* it is an error to get a cleartext message without a sig */
    unsigned expect_sig : 1;
    unsigned got_sig : 1;
    /* base64 stuff */
    unsigned buffered;
    uint8_t  buffer[3];
    unsigned eof64;
    uint32_t checksum;
    uint32_t read_checksum;
    /* unarmoured text blocks */
    uint8_t unarmoured[RNP_BUFSIZ];
    size_t  unarmoredc;
    /* pushed back data (stored backwards) */
    uint8_t *pushback;
    unsigned pushbackc;
    /* armoured block headers */
    pgp_headers_t headers;
} dearmour_t;

static void
push_back(dearmour_t *dearmour, const uint8_t *buf, unsigned length)
{
    unsigned n;

    if (dearmour->pushback) {
        (void) fprintf(stderr, "push_back: already pushed back\n");
    } else if ((dearmour->pushback = calloc(1, length)) == NULL) {
        (void) fprintf(stderr, "push_back: bad alloc\n");
    } else {
        for (n = 0; n < length; ++n) {
            dearmour->pushback[n] = buf[(length - n) - 1];
        }
        dearmour->pushbackc = length;
    }
}

/* this struct holds a textual header line */
typedef struct headerline_t {
    const char *s;    /* the header line */
    size_t      len;  /* its length */
    int         type; /* the defined type */
} headerline_t;

static headerline_t headerlines[] = {
  {"BEGIN PGP MESSAGE", 17, BEGIN_PGP_MESSAGE},
  {"BEGIN PGP PUBLIC KEY BLOCK", 26, BEGIN_PGP_PUBLIC_KEY_BLOCK},
  {"BEGIN PGP PRIVATE KEY BLOCK", 27, BEGIN_PGP_PRIVATE_KEY_BLOCK},
  {"BEGIN PGP MESSAGE, PART ", 25, BEGIN_PGP_MULTI},
  {"BEGIN PGP SIGNATURE", 19, BEGIN_PGP_SIGNATURE},

  {"END PGP MESSAGE", 15, END_PGP_MESSAGE},
  {"END PGP PUBLIC KEY BLOCK", 24, END_PGP_PUBLIC_KEY_BLOCK},
  {"END PGP PRIVATE KEY BLOCK", 25, END_PGP_PRIVATE_KEY_BLOCK},
  {"END PGP MESSAGE, PART ", 22, END_PGP_MULTI},
  {"END PGP SIGNATURE", 17, END_PGP_SIGNATURE},

  {"BEGIN PGP SIGNED MESSAGE", 24, BEGIN_PGP_SIGNED_MESSAGE},

  {NULL, 0, -1}};

/* search through the table of header lines */
static int
findheaderline(char *headerline)
{
    headerline_t *hp;

    for (hp = headerlines; hp->s; hp++) {
        if (strncmp(headerline, hp->s, hp->len) == 0) {
            break;
        }
    }
    return hp->type;
}

static bool
set_lastseen_headerline(dearmour_t *dearmour, char *hdr, pgp_error_t **errors)
{
    int lastseen;
    int prev;

    prev = dearmour->lastseen;
    if ((lastseen = findheaderline(hdr)) == -1) {
        PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "Unrecognised Header Line %s", hdr);
        return false;
    }
    dearmour->lastseen = lastseen;
    if (rnp_get_debug(__FILE__)) {
        printf("set header: hdr=%s, dearmour->lastseen=%d, prev=%d\n",
               hdr,
               dearmour->lastseen,
               prev);
    }
    switch (dearmour->lastseen) {
    case NONE:
        PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "Unrecognised last seen Header Line %s", hdr);
        break;

    case END_PGP_MESSAGE:
        if (prev != BEGIN_PGP_MESSAGE) {
            PGP_ERROR_1(
              errors, PGP_E_R_BAD_FORMAT, "%s", "Got END PGP MESSAGE, but not after BEGIN");
        }
        break;

    case END_PGP_PUBLIC_KEY_BLOCK:
        if (prev != BEGIN_PGP_PUBLIC_KEY_BLOCK) {
            PGP_ERROR_1(errors,
                        PGP_E_R_BAD_FORMAT,
                        "%s",
                        "Got END PGP PUBLIC KEY BLOCK, but not after BEGIN");
        }
        break;

    case END_PGP_PRIVATE_KEY_BLOCK:
        if (prev != BEGIN_PGP_PRIVATE_KEY_BLOCK) {
            PGP_ERROR_1(errors,
                        PGP_E_R_BAD_FORMAT,
                        "%s",
                        "Got END PGP PRIVATE KEY BLOCK, but not after BEGIN");
        }
        break;

    case BEGIN_PGP_MULTI:
    case END_PGP_MULTI:
        PGP_ERROR_1(
          errors, PGP_E_R_UNSUPPORTED, "%s", "Multi-part messages are not yet supported");
        break;

    case END_PGP_SIGNATURE:
        if (prev != BEGIN_PGP_SIGNATURE) {
            PGP_ERROR_1(
              errors, PGP_E_R_BAD_FORMAT, "%s", "Got END PGP SIGNATURE, but not after BEGIN");
        }
        break;

    case BEGIN_PGP_MESSAGE:
    case BEGIN_PGP_PUBLIC_KEY_BLOCK:
    case BEGIN_PGP_PRIVATE_KEY_BLOCK:
    case BEGIN_PGP_SIGNATURE:
    case BEGIN_PGP_SIGNED_MESSAGE:
        break;
    }
    return true;
}

static int
read_char(pgp_stream_t *stream,
          dearmour_t *  dearmour,
          pgp_error_t **errors,
          pgp_reader_t *readinfo,
          pgp_cbdata_t *cbinfo,
          unsigned      skip)
{
    uint8_t c;

    do {
        if (dearmour->pushbackc) {
            c = dearmour->pushback[--dearmour->pushbackc];
            if (dearmour->pushbackc == 0) {
                free(dearmour->pushback);
                dearmour->pushback = NULL;
            }
        } else if (pgp_stacked_read(stream, &c, 1, errors, readinfo, cbinfo) != 1) {
            return -1;
        }
    } while (skip && c == '\r');
    dearmour->prev_nl = dearmour->seen_nl;
    dearmour->seen_nl = c == '\n';
    return c;
}

static int
eat_whitespace(pgp_stream_t *stream,
               int           first,
               dearmour_t *  dearmour,
               pgp_error_t **errors,
               pgp_reader_t *readinfo,
               pgp_cbdata_t *cbinfo,
               unsigned      skip)
{
    int c = first;

    while (c == ' ' || c == '\t') {
        c = read_char(stream, dearmour, errors, readinfo, cbinfo, skip);
    }
    return c;
}

static int
read_and_eat_whitespace(pgp_stream_t *stream,
                        dearmour_t *  dearmour,
                        pgp_error_t **errors,
                        pgp_reader_t *readinfo,
                        pgp_cbdata_t *cbinfo,
                        unsigned      skip)
{
    int c;

    do {
        c = read_char(stream, dearmour, errors, readinfo, cbinfo, skip);
    } while (c == ' ' || c == '\t');
    return c;
}

static void
flush(dearmour_t *dearmour, pgp_cbdata_t *cbinfo)
{
    pgp_packet_t content;

    if (dearmour->unarmoredc > 0) {
        content.u.unarmoured_text.data = dearmour->unarmoured;
        content.u.unarmoured_text.length = (unsigned) dearmour->unarmoredc;
        CALLBACK(PGP_PTAG_CT_UNARMOURED_TEXT, cbinfo, &content);
        dearmour->unarmoredc = 0;
    }
}

static int
unarmoured_read_char(pgp_stream_t *stream,
                     dearmour_t *  dearmour,
                     pgp_error_t **errors,
                     pgp_reader_t *readinfo,
                     pgp_cbdata_t *cbinfo,
                     unsigned      skip)
{
    int c;

    do {
        c = read_char(stream, dearmour, errors, readinfo, cbinfo, 0);
        if (c < 0) {
            return c;
        }
        dearmour->unarmoured[dearmour->unarmoredc++] = c;
        if (dearmour->unarmoredc == sizeof(dearmour->unarmoured)) {
            flush(dearmour, cbinfo);
        }
    } while (skip && c == '\r');
    return c;
}

/**
 * \param headers
 * \param key
 *
 * \return header value if found, otherwise NULL
 */
static const char *
find_header(pgp_headers_t *headers, const char *key)
{
    unsigned n;

    for (n = 0; n < headers->headerc; ++n) {
        if (strcmp(headers->headers[n].key, key) == 0) {
            return headers->headers[n].value;
        }
    }
    return NULL;
}

/**
 * \param dest
 * \param src
 */
static void
dup_headers(pgp_headers_t *dest, const pgp_headers_t *src)
{
    unsigned n;

    if ((dest->headers = calloc(src->headerc, sizeof(*dest->headers))) == NULL) {
        (void) fprintf(stderr, "dup_headers: bad alloc\n");
    } else {
        dest->headerc = src->headerc;
        for (n = 0; n < src->headerc; ++n) {
            dest->headers[n].key = rnp_strdup(src->headers[n].key);
            dest->headers[n].value = rnp_strdup(src->headers[n].value);
        }
    }
}

/*
 * Note that this skips CRs so implementations always see just straight LFs
 * as line terminators
 */
static int
process_dash_escaped(pgp_stream_t *stream,
                     dearmour_t *  dearmour,
                     pgp_error_t **errors,
                     pgp_reader_t *readinfo,
                     pgp_cbdata_t *cbinfo)
{
    pgp_fixed_body_t *body;
    pgp_packet_t      content2;
    pgp_packet_t      content;
    const char *      hashstr;
    int               total;
    pgp_hash_alg_t    alg = PGP_HASH_MD5; // default

    body = &content.u.cleartext_body;
    hashstr = find_header(&dearmour->headers, "Hash");
    if (hashstr) {
        alg = pgp_str_to_hash_alg(hashstr);
        if (!pgp_is_hash_alg_supported(&alg)) {
            PGP_ERROR_1(
              errors, PGP_E_R_BAD_FORMAT, "Unsupported hash algorithm '%s'", hashstr);
            return -1;
        }
        if (alg == PGP_HASH_UNKNOWN) {
            PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "Unknown hash algorithm '%s'", hashstr);
            return -1;
        }
    }

    body->length = 0;
    total = 0;
    for (;;) {
        int      c;
        unsigned count;

        c = read_char(stream, dearmour, errors, readinfo, cbinfo, 1);
        if (c < 0) {
            return -1;
        }
        if (dearmour->prev_nl && c == '-') {
            if ((c = read_char(stream, dearmour, errors, readinfo, cbinfo, 0)) < 0) {
                return -1;
            }
            if (c != ' ') {
                /* then this had better be a trailer! */
                if (c != '-') {
                    PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Bad dash-escaping");
                }
                for (count = 2; count < 5; ++count) {
                    if ((c = read_char(stream, dearmour, errors, readinfo, cbinfo, 0)) < 0) {
                        return -1;
                    }
                    if (c != '-') {
                        PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Bad dash-escaping (2)");
                    }
                }
                dearmour->state = AT_TRAILER_NAME;
                break;
            }
            /* otherwise we read the next character */
            if ((c = read_char(stream, dearmour, errors, readinfo, cbinfo, 0)) < 0) {
                return -1;
            }
        }
        if (c == '\n' && body->length) {
            if (memchr(body->data + 1, '\n', body->length - 1) != NULL) {
                (void) fprintf(stderr, "process_dash_escaped: newline found\n");
                return -1;
            }
            if (rnp_get_debug(__FILE__)) {
                fprintf(stderr, "Got body:\n%s\n", body->data);
            }
            CALLBACK(PGP_PTAG_CT_SIGNED_CLEARTEXT_BODY, cbinfo, &content);
            body->length = 0;
        }
        body->data[body->length++] = c;
        total += 1;
        if (body->length == sizeof(body->data)) {
            if (rnp_get_debug(__FILE__)) {
                (void) fprintf(stderr, "Got body (2):\n%s\n", body->data);
            }
            CALLBACK(PGP_PTAG_CT_SIGNED_CLEARTEXT_BODY, cbinfo, &content);
            body->length = 0;
        }
    }
    if (body->data[0] != '\n') {
        (void) fprintf(stderr, "process_dash_escaped: no newline in body data\n");
        return -1;
    }
    if (body->length != 1) {
        (void) fprintf(stderr, "process_dash_escaped: bad body length\n");
        return -1;
    }
    /* don't send that one character, because it's part of the trailer */
    (void) memset(&content2, 0x0, sizeof(content2));
    CALLBACK(PGP_PTAG_CT_SIGNED_CLEARTEXT_TRAILER, cbinfo, &content2);
    return total;
}

static bool
add_header(dearmour_t *dearmour, const char *key, const char *value)
{
    int n;

    /*
     * Check that the header is valid
     */
    if (strcmp(key, "Version") == 0 || strcmp(key, "Comment") == 0 ||
        strcmp(key, "MessageID") == 0 || strcmp(key, "Hash") == 0 ||
        strcmp(key, "Charset") == 0) {
        n = dearmour->headers.headerc;
        dearmour->headers.headers =
          realloc(dearmour->headers.headers, (n + 1) * sizeof(*dearmour->headers.headers));
        if (dearmour->headers.headers == NULL) {
            (void) fprintf(stderr, "add_header: bad alloc\n");
            return false;
        }
        dearmour->headers.headers[n].key = rnp_strdup(key);
        dearmour->headers.headers[n].value = rnp_strdup(value);
        dearmour->headers.headerc = n + 1;
        return true;
    }
    return false;
}

static rnp_result
parse_headers(pgp_stream_t *stream,
              dearmour_t *  dearmour,
              pgp_error_t **errors,
              pgp_reader_t *readinfo,
              pgp_cbdata_t *cbinfo)
{
    unsigned   nbuf;
    unsigned   size;
    unsigned   first = 1;
    char *     buf;
    rnp_result ret = RNP_SUCCESS;

    nbuf = 0;
    size = 80;
    if ((buf = calloc(1, size)) == NULL) {
        RNP_LOG("bad calloc");
        return RNP_ERROR_GENERIC;
    }
    for (;;) {
        int c;

        if ((c = read_char(stream, dearmour, errors, readinfo, cbinfo, 1)) < 0) {
            PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Unexpected EOF");
            ret = RNP_ERROR_EOF;
            break;
        }
        if (c == '\n') {
            char *s;

            if (nbuf == 0) {
                break;
            }

            if (nbuf >= size) {
                RNP_LOG("bad size");
                return RNP_ERROR_EOF;
            }
            buf[nbuf] = '\0';

            if ((s = strchr(buf, ':')) == NULL) {
                if (!first && !dearmour->allow_headers_without_gap) {
                    /*
                     * then we have seriously malformed
                     * armour
                     */
                    PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "No colon in armour header");
                    ret = RNP_ERROR_EOF;
                    break;
                } else {
                    if (first &&
                        !(dearmour->allow_headers_without_gap || dearmour->allow_no_gap)) {
                        PGP_ERROR_1(errors,
                                    PGP_E_R_BAD_FORMAT,
                                    "%s",
                                    "No colon in"
                                    " armour header (2)");
                        /*
                         * then we have a nasty
                         * armoured block with no
                         * headers, not even a blank
                         * line.
                         */
                        buf[nbuf] = '\n';
                        push_back(dearmour, (uint8_t *) buf, nbuf + 1);
                        ret = RNP_ERROR_EOF;
                        break;
                    }
                }
            } else {
                *s = '\0';
                if (s[1] != ' ') {
                    PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "No space in armour header");
                    ret = RNP_ERROR_EOF;
                    goto end;
                }
                if (!add_header(dearmour, buf, s + 2)) {
                    PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "Invalid header %s", buf);
                    ret = RNP_ERROR_EOF;
                    goto end;
                }
                nbuf = 0;
            }
            first = 0;
        } else {
            if (size <= nbuf + 1) {
                size += size + 80;
                buf = realloc(buf, size);
                if (buf == NULL) {
                    (void) fprintf(stderr, "bad alloc\n");
                    ret = RNP_ERROR_EOF;
                    goto end;
                }
            }
            buf[nbuf++] = c;
        }
    }

end:
    free(buf);

    return ret;
}

static int
read4(pgp_stream_t *stream,
      dearmour_t *  dearmour,
      pgp_error_t **errors,
      pgp_reader_t *readinfo,
      pgp_cbdata_t *cbinfo,
      int *         pc,
      unsigned *    pn,
      uint32_t *    pl)
{
    int      n, c;
    uint32_t l = 0;

    for (n = 0; n < 4; ++n) {
        c = read_char(stream, dearmour, errors, readinfo, cbinfo, 1);
        if (c < 0) {
            dearmour->eof64 = 1;
            return -1;
        }
        if (c == '-' || c == '=') {
            break;
        }
        l <<= 6;
        if (c >= 'A' && c <= 'Z') {
            l += (uint32_t)(c - 'A');
        } else if (c >= 'a' && c <= 'z') {
            l += (uint32_t)(c - 'a') + 26;
        } else if (c >= '0' && c <= '9') {
            l += (uint32_t)(c - '0') + 52;
        } else if (c == '+') {
            l += 62;
        } else if (c == '/') {
            l += 63;
        } else {
            --n;
            l >>= 6;
        }
    }

    *pc = c;
    *pn = n;
    *pl = l;

    return 4;
}

unsigned
pgp_crc24(unsigned checksum, uint8_t c)
{
    unsigned i;

    checksum ^= c << 16;
    for (i = 0; i < 8; i++) {
        checksum <<= 1;
        if (checksum & 0x1000000)
            checksum ^= CRC24_POLY;
    }
    return (unsigned) (checksum & 0xffffffL);
}

static bool
decode64(pgp_stream_t *stream,
         dearmour_t *  dearmour,
         pgp_error_t **errors,
         pgp_reader_t *readinfo,
         pgp_cbdata_t *cbinfo)
{
    unsigned n;
    int      n2;
    uint32_t l;
    int      c;
    int      ret;

    if (dearmour->buffered) {
        (void) fprintf(stderr, "decode64: bad dearmour->buffered\n");
        return false;
    }

    ret = read4(stream, dearmour, errors, readinfo, cbinfo, &c, &n, &l);
    if (ret < 0) {
        PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Badly formed base64");
        return false;
    }
    if (n == 3) {
        if (c != '=') {
            PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Badly terminated base64 (2)");
            return false;
        }
        dearmour->buffered = 2;
        dearmour->eof64 = 1;
        l >>= 2;
    } else if (n == 2) {
        if (c != '=') {
            PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Badly terminated base64 (3)");
            return false;
        }
        dearmour->buffered = 1;
        dearmour->eof64 = 1;
        l >>= 4;
        c = read_char(stream, dearmour, errors, readinfo, cbinfo, 0);
        if (c != '=') {
            PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Badly terminated base64");
            return false;
        }
    } else if (n == 0) {
        if (!dearmour->prev_nl || c != '=') {
            PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Badly terminated base64 (4)");
            return false;
        }
        dearmour->buffered = 0;
    } else {
        if (n != 4) {
            (void) fprintf(stderr, "decode64: bad n (!= 4)\n");
            return false;
        }
        dearmour->buffered = 3;
        if (c == '-' || c == '=') {
            (void) fprintf(stderr, "decode64: bad c\n");
            return false;
        }
    }

    if (dearmour->buffered < 3 && dearmour->buffered > 0) {
        /* then we saw padding */
        if (c != '=') {
            (void) fprintf(stderr, "decode64: bad c (=)\n");
            return false;
        }
        c = read_and_eat_whitespace(stream, dearmour, errors, readinfo, cbinfo, 1);
        if (c != '\n') {
            PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "No newline at base64 end");
            return false;
        }
        c = read_char(stream, dearmour, errors, readinfo, cbinfo, 0);
        if (c != '=') {
            PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "No checksum at base64 end");
            return false;
        }
    }
    if (c == '=') {
        /* now we are at the checksum */
        ret =
          read4(stream, dearmour, errors, readinfo, cbinfo, &c, &n, &dearmour->read_checksum);
        if (ret < 0 || n != 4) {
            PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Error in checksum");
            return false;
        }
        c = read_char(stream, dearmour, errors, readinfo, cbinfo, 1);
        if (dearmour->allow_trailing_whitespace)
            c = eat_whitespace(stream, c, dearmour, errors, readinfo, cbinfo, 1);
        if (c != '\n') {
            PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Badly terminated checksum");
            return false;
        }
        c = read_char(stream, dearmour, errors, readinfo, cbinfo, 0);
        if (c != '-') {
            PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Bad base64 trailer (2)");
            return false;
        }
    }
    if (c == '-') {
        for (n = 0; n < 4; ++n)
            if (read_char(stream, dearmour, errors, readinfo, cbinfo, 0) != '-') {
                PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Bad base64 trailer");
                return false;
            }
        dearmour->eof64 = 1;
    } else {
        if (!dearmour->buffered) {
            (void) fprintf(stderr, "decode64: not buffered\n");
            return false;
        }
    }

    for (n = 0; n < dearmour->buffered; ++n) {
        dearmour->buffer[n] = (uint8_t) l;
        l >>= 8;
    }

    for (n2 = dearmour->buffered - 1; n2 >= 0; --n2)
        dearmour->checksum = pgp_crc24((unsigned) dearmour->checksum, dearmour->buffer[n2]);

    if (dearmour->eof64 && dearmour->read_checksum != dearmour->checksum) {
        PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Checksum mismatch");
        return false;
    }
    return true;
}

static void
base64(dearmour_t *dearmour)
{
    dearmour->state = BASE64;
    dearmour->checksum = CRC24_INIT;
    dearmour->eof64 = 0;
    dearmour->buffered = 0;
}

/* This reader is rather strange in that it can generate callbacks for */
/* content - this is because plaintext is not encapsulated in PGP */
/* packets... it also calls back for the text between the blocks. */

static int
armoured_data_reader(pgp_stream_t *stream,
                     void *        dest_,
                     size_t        length,
                     pgp_error_t **errors,
                     pgp_reader_t *readinfo,
                     pgp_cbdata_t *cbinfo)
{
    pgp_packet_t content;
    dearmour_t * dearmour;
    unsigned     first;
    uint8_t *    dest = dest_;
    char         buf[1024];
    int          saved;
    rnp_result   ret;

    dearmour = pgp_reader_get_arg(readinfo);
    saved = (int) length;
    if (dearmour->eof64 && !dearmour->buffered) {
        if (dearmour->state != OUTSIDE_BLOCK && dearmour->state != AT_TRAILER_NAME) {
            (void) fprintf(stderr, "armoured_data_reader: bad dearmour state\n");
            return 0;
        }
    }

    while (length > 0) {
        unsigned count;
        unsigned n;
        int      c;

        flush(dearmour, cbinfo);
        switch (dearmour->state) {
        case OUTSIDE_BLOCK:
            /*
             * This code returns EOF rather than EARLY_EOF
             * because if we don't see a header line at all, then
             * it is just an EOF (and not a BLOCK_END)
             */
            while (!dearmour->seen_nl) {
                if ((c = unarmoured_read_char(stream, dearmour, errors, readinfo, cbinfo, 1)) <
                    0) {
                    return 0;
                }
            }

            /*
             * flush at this point so we definitely have room for
             * the header, and so we can easily erase it from the
             * buffer
             */
            flush(dearmour, cbinfo);
            /* Find and consume the 5 leading '-' */
            for (count = 0; count < 5; ++count) {
                if ((c = unarmoured_read_char(stream, dearmour, errors, readinfo, cbinfo, 0)) <
                    0) {
                    return 0;
                }
                if (c != '-') {
                    goto reloop;
                }
            }

            /* Now find the block type */
            for (n = 0; n < sizeof(buf) - 1;) {
                if ((c = unarmoured_read_char(stream, dearmour, errors, readinfo, cbinfo, 0)) <
                    0) {
                    return 0;
                }
                if (c == '-') {
                    goto got_minus;
                }
                buf[n++] = c;
            }
            /* then I guess this wasn't a proper header */
            break;

        got_minus:
            buf[n] = '\0';

            /* Consume trailing '-' */
            for (count = 1; count < 5; ++count) {
                if ((c = unarmoured_read_char(stream, dearmour, errors, readinfo, cbinfo, 0)) <
                    0) {
                    return 0;
                }
                if (c != '-') {
                    /* wasn't a header after all */
                    goto reloop;
                }
            }

            /* Consume final NL */
            if ((c = unarmoured_read_char(stream, dearmour, errors, readinfo, cbinfo, 1)) <
                0) {
                return 0;
            }
            if (dearmour->allow_trailing_whitespace) {
                if ((c = eat_whitespace(stream, c, dearmour, errors, readinfo, cbinfo, 1)) <
                    0) {
                    return 0;
                }
            }
            if (c != '\n') {
                /* wasn't a header line after all */
                break;
            }

            /*
             * Now we've seen the header, scrub it from the
             * buffer
             */
            dearmour->unarmoredc = 0;

            /*
             * But now we've seen a header line, then errors are
             * EARLY_EOF
             */
            if (parse_headers(stream, dearmour, errors, readinfo, cbinfo)) {
                return -1;
            }

            if (!set_lastseen_headerline(dearmour, buf, errors)) {
                return -1;
            }

            if (strcmp(buf, "BEGIN PGP SIGNED MESSAGE") == 0) {
                dup_headers(&content.u.cleartext_head, &dearmour->headers);
                CALLBACK(PGP_PTAG_CT_SIGNED_CLEARTEXT_HEADER, cbinfo, &content);
                ret = process_dash_escaped(stream, dearmour, errors, readinfo, cbinfo);
                if (ret <= 0) {
                    return ret;
                }
            } else {
                content.u.armour_header.type = buf;
                content.u.armour_header.headers = dearmour->headers;
                (void) memset(&dearmour->headers, 0x0, sizeof(dearmour->headers));
                CALLBACK(PGP_PTAG_CT_ARMOUR_HEADER, cbinfo, &content);
                base64(dearmour);
            }
            break;

        case BASE64:
            first = 1;
            while (length > 0) {
                if (!dearmour->buffered) {
                    if (!dearmour->eof64) {
                        ret = decode64(stream, dearmour, errors, readinfo, cbinfo);
                        if (ret <= 0) {
                            return ret;
                        }
                    }
                    if (!dearmour->buffered) {
                        if (!dearmour->eof64) {
                            (void) fprintf(stderr,
                                           "armoured_data_reader: bad dearmour eof64\n");
                            return 0;
                        }
                        if (first) {
                            dearmour->state = AT_TRAILER_NAME;
                            goto reloop;
                        }
                        return -1;
                    }
                }
                if (!dearmour->buffered) {
                    (void) fprintf(stderr, "armoured_data_reader: bad dearmour buffered\n");
                    return 0;
                }
                *dest = dearmour->buffer[--dearmour->buffered];
                ++dest;
                --length;
                first = 0;
            }
            if (dearmour->eof64 && !dearmour->buffered) {
                dearmour->state = AT_TRAILER_NAME;
            }
            break;

        case AT_TRAILER_NAME:
            for (n = 0; n < sizeof(buf) - 1;) {
                if ((c = read_char(stream, dearmour, errors, readinfo, cbinfo, 0)) < 0) {
                    return -1;
                }
                if (c == '-') {
                    goto got_minus2;
                }
                buf[n++] = c;
            }
            /* then I guess this wasn't a proper trailer */
            PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Bad ASCII armour trailer");
            break;

        got_minus2:
            buf[n] = '\0';

            if (!set_lastseen_headerline(dearmour, buf, errors)) {
                return -1;
            }

            /* Consume trailing '-' */
            for (count = 1; count < 5; ++count) {
                if ((c = read_char(stream, dearmour, errors, readinfo, cbinfo, 0)) < 0) {
                    return -1;
                }
                if (c != '-') {
                    /* wasn't a trailer after all */
                    PGP_ERROR_1(
                      errors, PGP_E_R_BAD_FORMAT, "%s", "Bad ASCII armour trailer (2)");
                }
            }

            /* Consume final NL */
            if ((c = read_char(stream, dearmour, errors, readinfo, cbinfo, 1)) < 0) {
                return -1;
            }
            if (dearmour->allow_trailing_whitespace) {
                if ((c = eat_whitespace(stream, c, dearmour, errors, readinfo, cbinfo, 1)) <
                    0) {
                    return 0;
                }
            }
            if (c != '\n') {
                /* wasn't a trailer line after all */
                PGP_ERROR_1(errors, PGP_E_R_BAD_FORMAT, "%s", "Bad ASCII armour trailer (3)");
            }

            if (strncmp(buf, "BEGIN ", 6) == 0) {
                if (!set_lastseen_headerline(dearmour, buf, errors)) {
                    return -1;
                }
                ret = parse_headers(stream, dearmour, errors, readinfo, cbinfo);
                if (ret) {
                    return ret == RNP_ERROR_EOF ? -1 : 0;
                }
                content.u.armour_header.type = buf;
                content.u.armour_header.headers = dearmour->headers;
                (void) memset(&dearmour->headers, 0x0, sizeof(dearmour->headers));
                CALLBACK(PGP_PTAG_CT_ARMOUR_HEADER, cbinfo, &content);
                base64(dearmour);
            } else {
                content.u.armour_trailer = buf;
                CALLBACK(PGP_PTAG_CT_ARMOUR_TRAILER, cbinfo, &content);
                dearmour->state = OUTSIDE_BLOCK;
            }
            break;
        }
    reloop:
        continue;
    }

    return saved;
}

static void
armoured_data_destroyer(pgp_reader_t *readinfo)
{
    free(pgp_reader_get_arg(readinfo));
}

/**
 * \ingroup Core_Readers_Armour
 * \brief Pushes dearmouring reader onto stack
 * \param parse_info Usual structure containing information about to how to do the parse
 * \sa pgp_reader_pop_dearmour()
 */
void
pgp_reader_push_dearmour(pgp_stream_t *parse_info)
/*
 * This function originally had these params to cater for packets which
 * didn't strictly match the RFC. The initial 0.5 release is only going to
 * support strict checking. If it becomes desirable to support loose checking
 * of armoured packets and these params are reinstated, parse_headers() must
 * be fixed so that these flags work correctly.
 *
 * // Allow headers in armoured data that are not separated from the data by a
 * blank line unsigned without_gap,
 *
 * // Allow no blank line at the start of armoured data unsigned no_gap,
 *
 * //Allow armoured data to have trailing whitespace where we strictly would not
 * expect it                  unsigned trailing_whitespace
 */
{
    dearmour_t *dearmour;

    if ((dearmour = calloc(1, sizeof(*dearmour))) == NULL) {
        (void) fprintf(stderr, "pgp_reader_push_dearmour: bad alloc\n");
    } else {
        dearmour->seen_nl = 1;
        /*
            dearmour->allow_headers_without_gap=without_gap;
            dearmour->allow_no_gap=no_gap;
            dearmour->allow_trailing_whitespace=trailing_whitespace;
        */
        dearmour->expect_sig = 0;
        dearmour->got_sig = 0;

        if (!pgp_reader_push(
              parse_info, armoured_data_reader, armoured_data_destroyer, dearmour)) {
            free(dearmour);
        }
    }
}

/**
 * \ingroup Core_Readers_Armour
 * \brief Pops dearmour reader from stock
 * \param stream
 * \sa pgp_reader_push_dearmour()
 */
void
pgp_reader_pop_dearmour(pgp_stream_t *stream)
{
    dearmour_t *dearmour;

    dearmour = pgp_reader_get_arg(pgp_readinfo(stream));
    free(dearmour);
    pgp_reader_pop(stream);
}

/**************************************************************************/

/* this is actually used for *decrypting* */
typedef struct {
    uint8_t       decrypted[1024 * 15];
    size_t        c;
    size_t        off;
    pgp_crypt_t * decrypt;
    pgp_region_t *region;
    unsigned      prevplain : 1;
} encrypted_t;

static int
encrypted_data_reader(pgp_stream_t *stream,
                      void *        dest,
                      size_t        length,
                      pgp_error_t **errors,
                      pgp_reader_t *readinfo,
                      pgp_cbdata_t *cbinfo)
{
    encrypted_t *encrypted;
    char *       cdest;
    int          saved;

    encrypted = pgp_reader_get_arg(readinfo);
    saved = (int) length;

    if (!pgp_is_sa_supported(encrypted->decrypt->alg)) {
        RNP_LOG("Unsupported symmetric cipher algorithm");
        return 0;
    }

    /*
     * V3 MPIs have the count plain and the cipher is reset after each
     * count
     */
    if (encrypted->prevplain && !readinfo->parent->reading_mpi_len) {
        if (!readinfo->parent->reading_v3_secret) {
            (void) fprintf(stderr, "encrypted_data_reader: bad v3 secret\n");
            return -1;
        }
        pgp_cipher_cfb_resync(encrypted->decrypt);
        encrypted->prevplain = 0;
    } else if (readinfo->parent->reading_v3_secret && readinfo->parent->reading_mpi_len) {
        encrypted->prevplain = 1;
    }
    while (length > 0) {
        if (encrypted->c) {
            unsigned n;

            /*
             * if we are reading v3 we should never read
             * more than we're asked for */
            if (length < encrypted->c &&
                (readinfo->parent->reading_v3_secret || readinfo->parent->exact_read)) {
                (void) fprintf(stderr, "encrypted_data_reader: bad v3 read\n");
                return 0;
            }
            n = (int) MIN(length, encrypted->c);
            (void) memcpy(dest, encrypted->decrypted + encrypted->off, n);
            encrypted->c -= n;
            encrypted->off += n;
            length -= n;
            cdest = dest;
            cdest += n;
            dest = cdest;
        } else {
            unsigned n = encrypted->region->length;
            uint8_t  buffer[1024];

            if (!n) {
                return -1;
            }
            if (!encrypted->region->indeterminate) {
                n -= encrypted->region->readc;
                if (n == 0) {
                    return (int) (saved - length);
                }
                if (n > sizeof(buffer)) {
                    n = sizeof(buffer);
                }
            } else {
                n = sizeof(buffer);
            }

            /*
             * we can only read as much as we're asked for
             * in v3 keys because they're partially
             * unencrypted!  */
            if ((readinfo->parent->reading_v3_secret || readinfo->parent->exact_read) &&
                n > length) {
                n = (unsigned) length;
            }

            if (!pgp_stacked_limited_read(
                  stream, buffer, n, encrypted->region, errors, readinfo, cbinfo)) {
                return -1;
            }
            if (!readinfo->parent->reading_v3_secret || !readinfo->parent->reading_mpi_len) {
                pgp_cipher_cfb_decrypt(encrypted->decrypt, encrypted->decrypted, buffer, n);
                encrypted->c = n;

                if (rnp_get_debug(__FILE__)) {
                    hexdump(stderr, "encrypted", buffer, 16);
                    hexdump(stderr, "decrypted", encrypted->decrypted, 16);
                }
            } else {
                (void) memcpy(&encrypted->decrypted[encrypted->off], buffer, n);
                encrypted->c = n;
            }

            if (encrypted->c == 0) {
                (void) fprintf(stderr, "encrypted_data_reader: 0 decrypted count\n");
                return 0;
            }

            encrypted->off = 0;
        }
    }

    return saved;
}

static void
encrypted_data_destroyer(pgp_reader_t *readinfo)
{
    free(pgp_reader_get_arg(readinfo));
}

/**
 * \ingroup Core_Readers_SE
 * \brief Pushes decryption reader onto stack
 * \sa pgp_reader_pop_decrypt()
 */
void
pgp_reader_push_decrypt(pgp_stream_t *stream, pgp_crypt_t *decrypt, pgp_region_t *region)
{
    encrypted_t *encrypted;

    if ((encrypted = calloc(1, sizeof(*encrypted))) == NULL) {
        (void) fprintf(stderr, "pgp_reader_push_decrypted: bad alloc\n");
    } else {
        encrypted->decrypt = decrypt;
        encrypted->region = region;
        if (!pgp_reader_push(
              stream, encrypted_data_reader, encrypted_data_destroyer, encrypted)) {
            free(encrypted);
        }
    }
}

/**
 * \ingroup Core_Readers_Encrypted
 * \brief Pops decryption reader from stack
 * \sa pgp_reader_push_decrypt()
 */
void
pgp_reader_pop_decrypt(pgp_stream_t *stream)
{
    encrypted_t *encrypted;

    encrypted = pgp_reader_get_arg(pgp_readinfo(stream));
    pgp_cipher_finish(encrypted->decrypt);
    free(encrypted);
    pgp_reader_pop(stream);
}

/**************************************************************************/

typedef struct {
    /* boolean: 0 once we've done the preamble/MDC checks */
    /* and are reading from the plaintext */
    int           passed_checks;
    uint8_t *     plaintext;
    size_t        plaintext_available;
    size_t        plaintext_offset;
    pgp_region_t *region;
    pgp_crypt_t * decrypt;
} decrypt_se_ip_t;

/*
  Gets entire SE_IP data packet.
  Verifies leading preamble
  Verifies trailing MDC packet
  Then passes up plaintext as requested
*/
static int
se_ip_data_reader(pgp_stream_t *stream,
                  void *        dest_,
                  size_t        len,
                  pgp_error_t **errors,
                  pgp_reader_t *readinfo,
                  pgp_cbdata_t *cbinfo)
{
    decrypt_se_ip_t *se_ip;
    pgp_region_t     decrypted_region;
    unsigned         n = 0;

    se_ip = pgp_reader_get_arg(readinfo);
    if (!se_ip->passed_checks) {
        uint8_t *  buf = NULL;
        uint8_t    hashed[PGP_SHA1_HASH_SIZE];
        uint8_t *  preamble;
        uint8_t *  plaintext;
        uint8_t *  mdc;
        uint8_t *  mdc_hash;
        pgp_hash_t hash = {0};
        size_t     sz_preamble;
        size_t     sz_mdc_hash;
        size_t     sz_mdc;
        size_t     sz_plaintext;

        if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
            (void) fprintf(stderr, "se_ip_data_reader: can't init hash\n");
            return -1;
        }

        pgp_init_subregion(&decrypted_region, NULL);
        decrypted_region.length = se_ip->region->length - se_ip->region->readc;
        if ((buf = calloc(1, decrypted_region.length)) == NULL) {
            (void) fprintf(stderr, "se_ip_data_reader: bad alloc\n");
            return -1;
        }

        /* read entire SE IP packet */
        if (!pgp_stacked_limited_read(stream,
                                      buf,
                                      decrypted_region.length,
                                      &decrypted_region,
                                      errors,
                                      readinfo,
                                      cbinfo)) {
            free(buf);
            return -1;
        }
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "SE IP packet", buf, decrypted_region.length);
        }
        const size_t blocksize = pgp_cipher_block_size(se_ip->decrypt);

        /* verify leading preamble */
        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "preamble", buf, blocksize);
        }
        if (buf[blocksize - 2] != buf[blocksize] || buf[blocksize - 1] != buf[blocksize + 1]) {
            fprintf(stderr,
                    "Bad symmetric decrypt (%02x%02x vs %02x%02x)\n",
                    buf[blocksize - 2],
                    buf[blocksize - 1],
                    buf[blocksize],
                    buf[blocksize + 1]);
            PGP_ERROR_1(errors,
                        PGP_E_PROTO_BAD_SYMMETRIC_DECRYPT,
                        "%s",
                        "Bad symmetric decrypt when parsing SE IP"
                        " packet");
            free(buf);
            return -1;
        }
        /* Verify trailing MDC hash */

        sz_preamble = blocksize + 2;
        sz_mdc_hash = PGP_SHA1_HASH_SIZE;
        sz_mdc = 1 + 1 + sz_mdc_hash;
        sz_plaintext = (decrypted_region.length - sz_preamble) - sz_mdc;

        preamble = buf;
        plaintext = buf + sz_preamble;
        mdc = plaintext + sz_plaintext;
        mdc_hash = mdc + 2;

        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "plaintext", plaintext, sz_plaintext);
            hexdump(stderr, "mdc", mdc, sz_mdc);
        }
        pgp_calc_mdc_hash(preamble, sz_preamble, plaintext, (unsigned) sz_plaintext, hashed);

        if (memcmp(mdc_hash, hashed, PGP_SHA1_HASH_SIZE) != 0) {
            PGP_ERROR_1(errors, PGP_E_V_BAD_HASH, "%s", "Bad hash in MDC packet");
            free(buf);
            return 0;
        }
        /* all done with the checks */
        /* now can start reading from the plaintext */
        if (se_ip->plaintext) {
            (void) fprintf(stderr, "se_ip_data_reader: bad plaintext\n");
            return 0;
        }
        if ((se_ip->plaintext = calloc(1, sz_plaintext)) == NULL) {
            (void) fprintf(stderr, "se_ip_data_reader: bad alloc\n");
            return 0;
        }
        memcpy(se_ip->plaintext, plaintext, sz_plaintext);
        se_ip->plaintext_available = sz_plaintext;

        se_ip->passed_checks = 1;

        free(buf);
    }
    n = (unsigned) len;
    if (n > se_ip->plaintext_available) {
        n = (unsigned) se_ip->plaintext_available;
    }

    memcpy(dest_, se_ip->plaintext + se_ip->plaintext_offset, n);
    se_ip->plaintext_available -= n;
    se_ip->plaintext_offset += n;
    /* len -= n; - not used at all, for info only */

    return n;
}

static void
se_ip_data_destroyer(pgp_reader_t *readinfo)
{
    decrypt_se_ip_t *se_ip;

    se_ip = pgp_reader_get_arg(readinfo);
    free(se_ip->plaintext);
    free(se_ip);
}

/**
   \ingroup Internal_Readers_SEIP
*/
void
pgp_reader_push_se_ip_data(pgp_stream_t *stream, pgp_crypt_t *decrypt, pgp_region_t *region)
{
    decrypt_se_ip_t *se_ip;

    if ((se_ip = calloc(1, sizeof(*se_ip))) == NULL) {
        (void) fprintf(stderr, "pgp_reader_push_se_ip_data: bad alloc\n");
    } else {
        se_ip->region = region;
        se_ip->decrypt = decrypt;
        if (!pgp_reader_push(stream, se_ip_data_reader, se_ip_data_destroyer, se_ip)) {
            free(se_ip);
        }
    }
}

/**
   \ingroup Internal_Readers_SEIP
 */
void
pgp_reader_pop_se_ip_data(pgp_stream_t *stream)
{
    /*
     * decrypt_se_ip_t
     * *se_ip=pgp_reader_get_arg(pgp_readinfo(stream));
     */
    /* free(se_ip); */
    pgp_reader_pop(stream);
}

/**************************************************************************/

/** Arguments for reader_fd
 */
typedef struct mmap_reader_t {
    void *   mem;    /* memory mapped file */
    uint64_t size;   /* size of file */
    uint64_t offset; /* current offset in file */
    int      fd;     /* file descriptor */
} mmap_reader_t;

/**
 * \ingroup Core_Readers
 *
 * pgp_reader_fd() attempts to read up to "plength" bytes from the file
 * descriptor in "parse_info" into the buffer starting at "dest" using the
 * rules contained in "flags"
 *
 * \param    dest    Pointer to previously allocated buffer
 * \param    plength Number of bytes to try to read
 * \param    flags    Rules about reading to use
 * \param    readinfo    Reader info
 * \param    cbinfo    Callback info
 *
 * \return    n    Number of bytes read
 *
 * PGP_R_EARLY_EOF and PGP_R_ERROR push errors on the stack
 */
static int
fd_reader(pgp_stream_t *stream,
          void *        dest,
          size_t        length,
          pgp_error_t **errors,
          pgp_reader_t *readinfo,
          pgp_cbdata_t *cbinfo)
{
    mmap_reader_t *reader;
    int            n;

    RNP_USED(cbinfo);
    reader = pgp_reader_get_arg(readinfo);
    if (!stream->coalescing && stream->virtualc && stream->virtualoff < stream->virtualc) {
        n = read_partial_data(stream, dest, length);
    } else {
        n = (int) read(reader->fd, dest, length);
    }
    if (n == 0) {
        return 0;
    }
    if (n < 0) {
        PGP_SYSTEM_ERROR_1(
          errors, PGP_E_R_READ_FAILED, "read", "file descriptor %d", reader->fd);
        return -1;
    }
    return n;
}

static void
reader_fd_destroyer(pgp_reader_t *readinfo)
{
    free(pgp_reader_get_arg(readinfo));
}

/**
   \ingroup Core_Readers_First
   \brief Starts stack with file reader
*/

void
pgp_reader_set_fd(pgp_stream_t *stream, int fd)
{
    mmap_reader_t *reader;

    if ((reader = calloc(1, sizeof(*reader))) == NULL) {
        (void) fprintf(stderr, "pgp_reader_set_fd: bad alloc\n");
    } else {
        reader->fd = fd;
        pgp_reader_set(stream, fd_reader, reader_fd_destroyer, reader);
    }
}

/**************************************************************************/

typedef struct {
    const uint8_t *buffer;
    size_t         length;
    size_t         offset;
} reader_mem_t;

static int
mem_reader(pgp_stream_t *stream,
           void *        dest,
           size_t        length,
           pgp_error_t **errors,
           pgp_reader_t *readinfo,
           pgp_cbdata_t *cbinfo)
{
    reader_mem_t *reader = pgp_reader_get_arg(readinfo);
    unsigned      n;

    RNP_USED(cbinfo);
    RNP_USED(errors);
    if (!stream->coalescing && stream->virtualc && stream->virtualoff < stream->virtualc) {
        n = read_partial_data(stream, dest, length);
    } else {
        if (reader->offset + length > reader->length) {
            n = (unsigned) (reader->length - reader->offset);
        } else {
            n = (unsigned) length;
        }
        if (n == (unsigned) 0) {
            return 0;
        }
        memcpy(dest, reader->buffer + reader->offset, n);
        reader->offset += n;
    }
    return n;
}

static void
mem_destroyer(pgp_reader_t *readinfo)
{
    free(pgp_reader_get_arg(readinfo));
}

/**
   \ingroup Core_Readers_First
   \brief Starts stack with memory reader
*/

void
pgp_reader_set_memory(pgp_stream_t *stream, const void *buffer, size_t length)
{
    reader_mem_t *mem;

    if ((mem = calloc(1, sizeof(*mem))) == NULL) {
        (void) fprintf(stderr, "pgp_reader_set_memory: bad alloc\n");
    } else {
        mem->buffer = buffer;
        mem->length = length;
        mem->offset = 0;
        pgp_reader_set(stream, mem_reader, mem_destroyer, mem);
    }
}

/**************************************************************************/

int
pgp_setup_memory_read(pgp_io_t *     io,
                      pgp_stream_t **stream,
                      pgp_memory_t * mem,
                      void *         vp,
                      pgp_cb_ret_t   callback(const pgp_packet_t *, pgp_cbdata_t *),
                      unsigned       accumulate)
{
    *stream = pgp_new(sizeof(**stream));
    if (*stream == NULL) {
        return false;
    }
    (*stream)->io = (*stream)->cbinfo.io = io;
    pgp_set_callback(*stream, callback, vp);
    pgp_reader_set_memory(*stream, pgp_mem_data(mem), pgp_mem_len(mem));
    if (accumulate) {
        (*stream)->readinfo.accumulate = 1;
    }

    return true;
}

/**
   \ingroup Core_Readers
   \brief Frees stream and mem
   \param stream
   \param mem
   \sa pgp_setup_memory_read()
*/
void
pgp_teardown_memory_read(pgp_stream_t *stream, pgp_memory_t *mem)
{
    pgp_stream_delete(stream);
    pgp_memory_free(mem);
}

/**
 \ingroup Core_Writers
 \brief Create and initialise output and mem; Set for writing to file
 \param ctx Operation context, may be null
 \param output Address where new output pointer will be set
 \param filename File to write to
 \param allow_overwrite Allows file to be overwritten, if set.
 \return Newly-opened file descriptor
 \note It is the caller's responsiblity to free output and to close fd.
 \sa pgp_teardown_file_write()
*/
int
pgp_setup_file_write(rnp_ctx_t *    ctx,
                     pgp_output_t **output,
                     const char *   filename,
                     unsigned       allow_overwrite)
{
    int fd = 0;
    int flags = 0;

    /*
     * initialise needed structures for writing to file
     */
    if (filename == NULL) {
        /* write to stdout */
        fd = STDOUT_FILENO;
    } else {
        flags = O_WRONLY | O_CREAT;
        if (allow_overwrite)
            flags |= O_TRUNC;
        else
            flags |= O_EXCL;
#ifdef O_BINARY
        flags |= O_BINARY;
#endif
        fd = open(filename, flags, 0600);
        if (fd < 0) {
            perror(filename);
            return fd;
        }
    }

    *output = pgp_output_new();
    if (*output == NULL) {
        fprintf(stderr, "Can't allocate memory\n");
        return -1;
    }
    (*output)->ctx = ctx;
    pgp_writer_set_fd(*output, fd);
    return fd;
}

/**
   \ingroup Core_Writers
   \brief Closes writer, frees info, closes fd
   \param output
   \param fd
*/
void
pgp_teardown_file_write(pgp_output_t *output, int fd)
{
    pgp_writer_close(output);
    close(fd);
    pgp_output_delete(output);
}

/**
   \ingroup Core_Writers
   \brief As pgp_setup_file_write, but appends to file
*/
int
pgp_setup_file_append(rnp_ctx_t *ctx, pgp_output_t **output, const char *filename)
{
    int fd;

/*
 * initialise needed structures for writing to file
 */
#ifdef O_BINARY
    fd = open(filename, O_WRONLY | O_APPEND | O_BINARY, 0600);
#else
    fd = open(filename, O_WRONLY | O_APPEND, 0600);
#endif
    if (fd >= 0) {
        *output = pgp_output_new();
        if (*output == NULL) {
            fprintf(stderr, "Can't allocate memory\n");
            return -1;
        }
        (*output)->ctx = ctx;
        pgp_writer_set_fd(*output, fd);
    }
    return fd;
}

/**
   \ingroup Core_Writers
   \brief As pgp_teardown_file_write()
*/
void
pgp_teardown_file_append(pgp_output_t *output, int fd)
{
    pgp_teardown_file_write(output, fd);
}

/**
   \ingroup Core_Readers
   \brief Creates parse_info, opens file, and sets to read from file
   \param stream Address where new parse_info will be set
   \param filename Name of file to read
   \param vp Reader-specific arg
   \param callback Callback to use when reading
   \param accumulate Set if we need to accumulate as we read. (Usually 0 unless doing signature
   verification)
   \note It is the caller's responsiblity to free parse_info and to close fd
   \sa pgp_teardown_file_read()
*/
int
pgp_setup_file_read(pgp_io_t *     io,
                    pgp_stream_t **stream,
                    const char *   filename,
                    void *         vp,
                    pgp_cb_ret_t   callback(const pgp_packet_t *, pgp_cbdata_t *),
                    unsigned       accumulate)
{
    int fd;

#ifdef O_BINARY
    fd = open(filename, O_RDONLY | O_BINARY);
#else
    fd = open(filename, O_RDONLY);
#endif
    if (fd < 0) {
        (void) fprintf(io->errs, "can't open \"%s\"\n", filename);
        return fd;
    }
    *stream = pgp_new(sizeof(**stream));
    (*stream)->io = (*stream)->cbinfo.io = io;
    pgp_set_callback(*stream, callback, vp);
#ifdef USE_MMAP_FOR_FILES
    pgp_reader_set_mmap(*stream, fd);
#else
    pgp_reader_set_fd(*stream, fd);
#endif
    if (accumulate) {
        (*stream)->readinfo.accumulate = 1;
    }
    return fd;
}

/**
   \ingroup Core_Readers
   \brief Frees stream and closes fd
   \param stream
   \param fd
   \sa pgp_setup_file_read()
*/
void
pgp_teardown_file_read(pgp_stream_t *stream, int fd)
{
    close(fd);
    pgp_stream_delete(stream);
}

pgp_cb_ret_t
pgp_litdata_cb(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    const pgp_contents_t *content = &pkt->u;

    if (rnp_get_debug(__FILE__)) {
        printf("pgp_litdata_cb: ");
        pgp_print_packet(&cbinfo->printstate, pkt);
    }
    /* Read data from packet into static buffer */
    switch (pkt->tag) {
    case PGP_PTAG_CT_LITDATA_BODY:
        /* if writer enabled, use it */
        if (cbinfo->output) {
            if (rnp_get_debug(__FILE__)) {
                printf("pgp_litdata_cb: length is %u\n", content->litdata_body.length);
            }
            pgp_write(
              cbinfo->output, content->litdata_body.data, content->litdata_body.length);
        }
        break;

    case PGP_PTAG_CT_LITDATA_HEADER:
        /* ignore */
        break;

    default:
        break;
    }

    return PGP_RELEASE_MEMORY;
}

pgp_cb_ret_t
pgp_pk_sesskey_cb(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    const pgp_contents_t *content = &pkt->u;
    unsigned              from;
    pgp_io_t *            io;

    io = cbinfo->io;
    if (rnp_get_debug(__FILE__)) {
        pgp_print_packet(&cbinfo->printstate, pkt);
    }
    /* Read data from packet into static buffer */
    switch (pkt->tag) {
    case PGP_PTAG_CT_PK_SESSION_KEY:
        if (rnp_get_debug(__FILE__)) {
            printf("PGP_PTAG_CT_PK_SESSION_KEY\n");
        }
        if (!cbinfo->cryptinfo.secring) {
            (void) fprintf(io->errs, "pgp_pk_sesskey_cb: bad keyring\n");
            return (pgp_cb_ret_t) 0;
        }
        from = 0;
        cbinfo->cryptinfo.key = rnp_key_store_get_key_by_id(
          io, cbinfo->cryptinfo.secring, content->pk_sesskey.key_id, &from, NULL);
        if (!cbinfo->cryptinfo.key) {
            break;
        }
        break;

    default:
        break;
    }

    return PGP_RELEASE_MEMORY;
}

/**
 \ingroup Core_Callbacks

\brief Callback to get secret key, decrypting if necessary.

@verbatim
 This callback does the following:
 * finds the session key in the keyring
 * gets a passphrase if required
 * decrypts the secret key, if necessary
 * sets the seckey in the content struct
@endverbatim
*/

pgp_cb_ret_t
pgp_get_seckey_cb(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    const pgp_contents_t *content = &pkt->u;
    const pgp_seckey_t *  secret;
    const pgp_key_t *     pubkey;
    const pgp_key_t *     keypair;
    unsigned              from;
    pgp_io_t *            io;
    int                   i;

    io = cbinfo->io;
    if (rnp_get_debug(__FILE__)) {
        pgp_print_packet(&cbinfo->printstate, pkt);
    }
    switch (pkt->tag) {
    case PGP_GET_SECKEY:
        /* print key from pubring */
        from = 0;
        pubkey = rnp_key_store_get_key_by_id(
          io, cbinfo->cryptinfo.pubring, content->get_seckey.pk_sesskey->key_id, &from, NULL);
        /* validate key from secring */
        from = 0;
        cbinfo->cryptinfo.key = rnp_key_store_get_key_by_id(
          io, cbinfo->cryptinfo.secring, content->get_seckey.pk_sesskey->key_id, &from, NULL);
        if (!cbinfo->cryptinfo.key || !pgp_is_key_secret(cbinfo->cryptinfo.key)) {
            return (pgp_cb_ret_t) 0;
        }
        keypair = cbinfo->cryptinfo.key;
        if (pubkey == NULL) {
            pubkey = keypair;
        }
        secret = NULL;
        cbinfo->gotpass = 0;
        for (i = 0; cbinfo->numtries == -1 || i < cbinfo->numtries; i++) {
            /* print out the user id */
            repgp_print_key(
              io, cbinfo->cryptinfo.pubring, pubkey, "signature ", &pubkey->key.pubkey, 0);
            /* now decrypt key */
            secret = pgp_decrypt_seckey(keypair, cbinfo->passfp);
            if (secret != NULL) {
                break;
            }
            (void) fprintf(io->errs, "Bad passphrase\n");
        }
        if (secret == NULL) {
            (void) fprintf(io->errs, "Exhausted passphrase attempts\n");
            return (pgp_cb_ret_t) PGP_RELEASE_MEMORY;
        }
        cbinfo->gotpass = 1;
        *content->get_seckey.seckey = secret;
        break;

    default:
        break;
    }

    return PGP_RELEASE_MEMORY;
}

unsigned
pgp_reader_set_accumulate(pgp_stream_t *stream, unsigned state)
{
    return stream->readinfo.accumulate = state;
}

/**************************************************************************/

static int
hash_reader(pgp_stream_t *stream,
            void *        dest,
            size_t        length,
            pgp_error_t **errors,
            pgp_reader_t *readinfo,
            pgp_cbdata_t *cbinfo)
{
    pgp_hash_t *hash = pgp_reader_get_arg(readinfo);
    int         r;

    r = pgp_stacked_read(stream, dest, length, errors, readinfo, cbinfo);
    if (r <= 0) {
        return r;
    }
    pgp_hash_add(hash, dest, (unsigned) r);
    return r;
}

/**
   \ingroup Internal_Readers_Hash
   \brief Push hashed data reader on stack
*/
int
pgp_reader_push_hash(pgp_stream_t *stream, pgp_hash_t *hash)
{
    return pgp_reader_push(stream, hash_reader, NULL, hash);
}

/**
   \ingroup Internal_Readers_Hash
   \brief Pop hashed data reader from stack
*/
void
pgp_reader_pop_hash(pgp_stream_t *stream)
{
    pgp_reader_pop(stream);
}

/* read memory from the previously mmap-ed file */
static int
mmap_reader(pgp_stream_t *stream,
            void *        dest,
            size_t        length,
            pgp_error_t **errors,
            pgp_reader_t *readinfo,
            pgp_cbdata_t *cbinfo)
{
    mmap_reader_t *mem = pgp_reader_get_arg(readinfo);
    unsigned       n;
    char *         cmem = mem->mem;

    RNP_USED(errors);
    RNP_USED(cbinfo);
    if (!stream->coalescing && stream->virtualc && stream->virtualoff < stream->virtualc) {
        n = read_partial_data(stream, dest, length);
    } else {
        n = (unsigned) MIN(length, (unsigned) (mem->size - mem->offset));
        if (n > 0) {
            (void) memcpy(dest, &cmem[(int) mem->offset], (unsigned) n);
            mem->offset += n;
        }
    }
    return (int) n;
}

/* tear down the mmap, close the fd */
static void
mmap_destroyer(pgp_reader_t *readinfo)
{
    mmap_reader_t *mem = pgp_reader_get_arg(readinfo);

    (void) munmap(mem->mem, (unsigned) mem->size);
    (void) close(mem->fd);
    free(pgp_reader_get_arg(readinfo));
}

/* set up the file to use mmap-ed memory if available, file IO otherwise */
void
pgp_reader_set_mmap(pgp_stream_t *stream, int fd)
{
    mmap_reader_t *mem;
    struct stat    st;

    if (fstat(fd, &st) != 0) {
        (void) fprintf(stderr, "pgp_reader_set_mmap: can't fstat\n");
    } else if ((mem = calloc(1, sizeof(*mem))) == NULL) {
        (void) fprintf(stderr, "pgp_reader_set_mmap: bad alloc\n");
    } else {
        mem->size = (uint64_t) st.st_size;
        mem->offset = 0;
        mem->fd = fd;
        mem->mem = mmap(NULL, (size_t) st.st_size, PROT_READ, MAP_PRIVATE | MAP_FILE, fd, 0);
        if (mem->mem == MAP_FAILED) {
            pgp_reader_set(stream, fd_reader, reader_fd_destroyer, mem);
        } else {
            pgp_reader_set(stream, mmap_reader, mmap_destroyer, mem);
        }
    }
}
