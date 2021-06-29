/*
 * Copyright (c) 2017-2020 [Ribose Inc](https://www.ribose.com).
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
/** File utilities
 *  @file
 */

#include "file-utils.h"
#include "config.h"
#ifdef _MSC_VER
#include <stdlib.h>
#include <stdio.h>
#include "uniwin.h"
#include <errno.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif // !_MSC_VER
#ifdef _WIN32
#include <random> // for rnp_mkstemp
#include "str-utils.h"
#define CATCH_AND_RETURN(v) \
    catch (...)             \
    {                       \
        errno = ENOMEM;     \
        return v;           \
    }
#else
#include <string.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <stdarg.h>

int
rnp_unlink(const char *filename)
{
#ifdef _WIN32
    try {
        return _wunlink(wstr_from_utf8(filename).c_str());
    }
    CATCH_AND_RETURN(-1)
#else
    return unlink(filename);
#endif
}

bool
rnp_file_exists(const char *path)
{
    struct stat st;
    return rnp_stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

bool
rnp_dir_exists(const char *path)
{
    struct stat st;
    return rnp_stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

int
rnp_open(const char *filename, int oflag, int pmode)
{
#ifdef _WIN32
    try {
        return _wopen(wstr_from_utf8(filename).c_str(), oflag, pmode);
    }
    CATCH_AND_RETURN(-1)
#else
    return open(filename, oflag, pmode);
#endif
}

FILE *
rnp_fopen(const char *filename, const char *mode)
{
#ifdef _WIN32
    try {
        return _wfopen(wstr_from_utf8(filename).c_str(), wstr_from_utf8(mode).c_str());
    }
    CATCH_AND_RETURN(NULL)
#else
    return fopen(filename, mode);
#endif
}

int
rnp_access(const char *path, int mode)
{
#ifdef _WIN32
    try {
        return _waccess(wstr_from_utf8(path).c_str(), mode);
    }
    CATCH_AND_RETURN(-1)
#else
    return access(path, mode);
#endif
}

int
rnp_stat(const char *filename, struct stat *statbuf)
{
#ifdef _WIN32
    static_assert(sizeof(struct stat) == sizeof(struct _stat64i32),
                  "stat is expected to match _stat64i32");
    try {
        return _wstat64i32(wstr_from_utf8(filename).c_str(), (struct _stat64i32 *) statbuf);
    }
    CATCH_AND_RETURN(-1)
#else
    return stat(filename, statbuf);
#endif
}

#ifdef _WIN32
int
rnp_mkdir(const char *path)
{
    try {
        return _wmkdir(wstr_from_utf8(path).c_str());
    }
    CATCH_AND_RETURN(-1)
}
#endif

int
rnp_rename(const char *oldpath, const char *newpath)
{
#ifdef _WIN32
    try {
        return _wrename(wstr_from_utf8(oldpath).c_str(), wstr_from_utf8(newpath).c_str());
    }
    CATCH_AND_RETURN(-1)
#else
    return rename(oldpath, newpath);
#endif
}

#ifdef _WIN32
_WDIR *
#else
DIR *
#endif
rnp_opendir(const char *path)
{
#ifdef _WIN32
    try {
        return _wopendir(wstr_from_utf8(path).c_str());
    }
    CATCH_AND_RETURN(NULL)
#else
    return opendir(path);
#endif
}

std::string
#ifdef _WIN32
rnp_readdir_name(_WDIR *dir)
{
    _wdirent *ent;
    for (;;) {
        if ((ent = _wreaddir(dir)) == NULL) {
            return std::string();
        }
        if (wcscmp(ent->d_name, L".") && wcscmp(ent->d_name, L"..")) {
            break;
        }
    }
    try {
        return wstr_to_utf8(ent->d_name);
    }
    CATCH_AND_RETURN(std::string())
#else
rnp_readdir_name(DIR *dir)
{
    dirent *ent;
    for (;;) {
        if ((ent = readdir(dir)) == NULL) {
            return std::string();
        }
        if (strcmp(ent->d_name, ".") && strcmp(ent->d_name, "..")) {
            break;
        }
    }
    return std::string(ent->d_name);
#endif
}

/* return the file modification time */
int64_t
rnp_filemtime(const char *path)
{
    struct stat st;

    if (rnp_stat(path, &st) != 0) {
        return 0;
    } else {
        return st.st_mtime;
    }
}

#ifdef _WIN32
static const char letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/** @private
 *  generate a temporary file name based on TMPL.
 *
 *  @param tmpl filename template in UTF-8 ending in XXXXXX
 *  @return file descriptor of newly created and opened file, or -1 on error
 **/
int
rnp_mkstemp(char *tmpl)
{
    try {
        int       save_errno = errno;
        const int mask_length = 6;
        int       len = strlen(tmpl);
        if (len < mask_length || strcmp(&tmpl[len - mask_length], "XXXXXX")) {
            errno = EINVAL;
            return -1;
        }
        std::wstring tmpl_w = wstr_from_utf8(tmpl, tmpl + len - mask_length);

        /* This is where the Xs start.  */
        char *XXXXXX = &tmpl[len - mask_length];

        std::random_device rd;
        std::mt19937_64    rng(rd());

        for (unsigned int countdown = TMP_MAX; --countdown;) {
            unsigned long long v = rng();

            XXXXXX[0] = letters[v % 36];
            v /= 36;
            XXXXXX[1] = letters[v % 36];
            v /= 36;
            XXXXXX[2] = letters[v % 36];
            v /= 36;
            XXXXXX[3] = letters[v % 36];
            v /= 36;
            XXXXXX[4] = letters[v % 36];
            v /= 36;
            XXXXXX[5] = letters[v % 36];

            int flags = O_WRONLY | O_CREAT | O_EXCL | O_BINARY;
            int fd =
              _wopen((tmpl_w + wstr_from_utf8(XXXXXX)).c_str(), flags, _S_IREAD | _S_IWRITE);
            if (fd != -1) {
                errno = save_errno;
                return fd;
            } else if (errno != EEXIST)
                return -1;
        }

        // We got out of the loop because we ran out of combinations to try.
        errno = EEXIST;
        return -1;
    }
    CATCH_AND_RETURN(-1)
}
#endif // _WIN32

static char *
vcompose_path(char **buf, size_t *buf_len, const char *first, va_list ap)
{
    size_t curlen = 0;
    char * tmp_buf = NULL;
    size_t tmp_buf_len = 0;

    if (!first) {
        return NULL;
    }
    if (!buf) {
        buf = &tmp_buf;
    }
    if (!buf_len) {
        buf_len = &tmp_buf_len;
    }

    const char *s = first;
    do {
        size_t len = strlen(s);

        // current string len + NULL terminator + possible '/' +
        // len of this path component
        size_t reqsize = curlen + 1 + 1 + len;
        if (*buf_len < reqsize) {
            char *newbuf = (char *) realloc(*buf, reqsize);
            if (!newbuf) {
                // realloc failed, bail
                free(*buf);
                *buf = NULL;
                break;
            }
            *buf = newbuf;
            *buf_len = reqsize;
        }

        if (s != first) {
            if ((*buf)[curlen - 1] != '/' && *s != '/') {
                // add missing separator
                (*buf)[curlen] = '/';
                curlen += 1;
            } else if ((*buf)[curlen - 1] == '/' && *s == '/') {
                // skip duplicate separator
                s++;
                len--;
            }
        }
        memcpy(*buf + curlen, s, len + 1);
        curlen += len;
    } while ((s = va_arg(ap, const char *)));

    return *buf;
}

/** compose a path from one or more components
 *
 *  Notes:
 *  - The final argument must be NULL.
 *  - The caller must free the returned buffer.
 *  - The returned buffer is always NULL-terminated.
 *
 *  @param first the first path component
 *  @return the composed path buffer. The caller must free it.
 */
char *
rnp_compose_path(const char *first, ...)
{
    va_list ap;
    va_start(ap, first);
    char *path = vcompose_path(NULL, NULL, first, ap);
    va_end(ap);
    return path;
}

/** compose a path from one or more components
 *
 *  This version is useful when a function is composing
 *  multiple paths and wants to try to avoid unnecessary
 *  allocations.
 *
 *  Notes:
 *  - The final argument must be NULL.
 *  - The caller must free the returned buffer.
 *  - The returned buffer is always NULL-terminated.
 *
 *  @code
 *  char *buf = NULL;
 *  size_t buf_len = 0;
 *  rnp_compose_path_ex(&buf, &buf_len, "/tmp", dir1, file1, NULL);
 *  // the calls below will realloc the buffer if needed
 *  rnp_compose_path_ex(&buf, &buf_len, "/tmp", dir3, NULL);
 *  rnp_compose_path_ex(&buf, &buf_len, "/tmp", something, NULL);
 *  free(buf);
 *  @endcode
 *
 *  @param buf pointer to the buffer where the result will be stored.
 *         If buf is NULL, the caller must use the returned value.
 *         If *buf is NULL, a new buffer will be allocated.
 *  @param buf_len pointer to the allocated buffer size.
 *         Can be NULL.
 *  @param first the first path component
 *  @return the composed path buffer. The caller must free it.
 */
char *
rnp_compose_path_ex(char **buf, size_t *buf_len, const char *first, ...)
{
    va_list ap;
    va_start(ap, first);
    char *path = vcompose_path(buf, buf_len, first, ap);
    va_end(ap);
    return path;
}
