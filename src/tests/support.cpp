/*
 * Copyright (c) 2017-2019 [Ribose Inc](https://www.ribose.com).
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

#include "support.h"
#include "rnp_tests.h"
#include "file-utils.h"

#ifdef _MSC_VER
#include "uniwin.h"
#include <shlwapi.h>
#else
#include <sys/types.h>
#include <sys/param.h>
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include <crypto.h>
#include <pgp-key.h>
#include <fstream>
#include <vector>
#include <algorithm>

#ifndef WINSHELLAPI
#include <ftw.h>
#endif

extern rng_t global_rng;

#ifdef _WIN32
int
setenv(const char *name, const char *value, int overwrite)
{
    if (getenv(name) && !overwrite) {
        return 0;
    }
    char varbuf[512] = {0};
    snprintf(varbuf, sizeof(varbuf) - 1, "%s=%s", name, value);
    return _putenv(varbuf);
}

int
unsetenv(const char *name)
{
    char varbuf[512] = {0};
    snprintf(varbuf, sizeof(varbuf) - 1, "%s=", name);
    return _putenv(varbuf);
}
#endif

/* Check if a file is empty
 * Use with assert_true and rnp_assert_false(rstate, .
 */
bool
file_empty(const char *path)
{
    return file_size(path) == 0;
}

std::string
file_to_str(const std::string &path)
{
    // TODO: wstring path _WIN32
    std::ifstream infile(path);
    assert_true(infile);
    return std::string(std::istreambuf_iterator<char>(infile),
                       std::istreambuf_iterator<char>());
}

std::vector<uint8_t>
file_to_vec(const std::string &path)
{
    // TODO: wstring path _WIN32
    std::ifstream stream(path, std::ios::in | std::ios::binary);
    assert_true(stream);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(stream)),
                                std::istreambuf_iterator<char>());
}

off_t
file_size(const char *path)
{
    struct stat path_stat;
    if (rnp_stat(path, &path_stat) != -1) {
        if (S_ISDIR(path_stat.st_mode)) {
            return -1;
        }
        return path_stat.st_size;
    }
    return -1;
}

/* Concatenate multiple strings into a full path.
 * A directory separator is added between components.
 * Must be called in between va_start and va_end.
 * Final argument of calling function must be NULL.
 */
void
vpaths_concat(char *buffer, size_t buffer_size, const char *first, va_list ap)
{
    size_t      length = strlen(first);
    const char *s;

    assert_true(length < buffer_size);

    memset(buffer, 0, buffer_size);

    strncpy(buffer, first, buffer_size - 1);
    while ((s = va_arg(ap, const char *))) {
        length += strlen(s) + 1;
        assert_true(length < buffer_size);
        strncat(buffer, "/", buffer_size - 1);
        strncat(buffer, s, buffer_size - 1);
    }
}

/* Concatenate multiple strings into a full path.
 * Final argument must be NULL.
 */
char *
paths_concat(char *buffer, size_t buffer_length, const char *first, ...)
{
    va_list ap;

    va_start(ap, first);
    vpaths_concat(buffer, buffer_length, first, ap);
    va_end(ap);
    return buffer;
}

/* Concatenate multiple strings into a full path and
 * check that the file exists.
 * Final argument must be NULL.
 */
int
path_rnp_file_exists(const char *first, ...)
{
    va_list ap;
    char    buffer[512] = {0};

    va_start(ap, first);
    vpaths_concat(buffer, sizeof(buffer), first, ap);
    va_end(ap);
    return rnp_file_exists(buffer);
}

/* Concatenate multiple strings into a full path and
 * create the directory.
 * Final argument must be NULL.
 */
void
path_mkdir(mode_t mode, const char *first, ...)
{
    va_list ap;
    char    buffer[512];

    va_start(ap, first);
    vpaths_concat(buffer, sizeof(buffer), first, ap);
    va_end(ap);

    assert_int_equal(0, RNP_MKDIR(buffer, mode));
}

static int
remove_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    int ret = remove(fpath);
    if (ret)
        perror(fpath);

    return ret;
}

static const char *
get_tmp()
{
    const char *tmp = getenv("TEMP");
    return tmp ? tmp : "/tmp";
}

static bool
is_tmp_path(const char *path)
{
    char rlpath[PATH_MAX] = {0};
    char rltmp[PATH_MAX] = {0};
    if (!realpath(path, rlpath)) {
        strncpy(rlpath, path, sizeof(rlpath));
        rlpath[sizeof(rlpath) - 1] = '\0';
    }
    const char *tmp = get_tmp();
    if (!realpath(tmp, rltmp)) {
        strncpy(rltmp, tmp, sizeof(rltmp));
    }
    return strncmp(rlpath, rltmp, strlen(rltmp)) == 0;
}

/* Recursively remove a directory.
 * The path must be located in /tmp, for safety.
 */
void
delete_recursively(const char *path)
{
    bool relative =
#ifdef _MSC_VER
      PathIsRelativeA(path);
#else
      *path != '/';
#endif
    char *fullpath = const_cast<char *>(path);
    if (relative) {
        char *cwd = getcwd(NULL, 0);
        fullpath = rnp_compose_path(cwd, path, NULL);
        free(cwd);
    }
    /* sanity check, we should only be purging things from /tmp/ */
    assert_true(is_tmp_path(fullpath));

#ifdef WINSHELLAPI
    SHFILEOPSTRUCTA fileOp = {};
    fileOp.fFlags = FOF_NOCONFIRMATION;
    assert_true(strlen(fullpath) < MAX_PATH);
    char newFrom[MAX_PATH + 1];
    strcpy_s(newFrom, fullpath);
    newFrom[strlen(fullpath) + 1] = NULL; // two NULLs are required
    fileOp.pFrom = newFrom;
    fileOp.pTo = NULL;
    fileOp.wFunc = FO_DELETE;
    fileOp.hNameMappings = NULL;
    fileOp.hwnd = NULL;
    fileOp.lpszProgressTitle = NULL;
    assert_int_equal(0, SHFileOperationA(&fileOp));
#else
    nftw(path, remove_cb, 64, FTW_DEPTH | FTW_PHYS);
    if (*path != '/') {
        free(fullpath);
    }
#endif
}

void
copy_recursively(const char *src, const char *dst)
{
    /* sanity check, we should only be copying things to /tmp/ */
    assert_true(is_tmp_path(dst));

#ifdef WINSHELLAPI
    SHFILEOPSTRUCTA fileOp = {};
    fileOp.fFlags = FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_NOCONFIRMMKDIR;
    fileOp.pFrom = src;
    fileOp.pTo = dst;
    assert_true(strlen(src) < MAX_PATH);
    char newFrom[MAX_PATH + 1];
    strcpy_s(newFrom, src);
    newFrom[strlen(src) + 1] = NULL; // two NULLs are required
    fileOp.pFrom = newFrom;
    assert_true(strlen(dst) < MAX_PATH);
    char newTo[MAX_PATH + 1];
    strcpy_s(newTo, dst);
    newTo[strlen(dst) + 1] = NULL; // two NULLs are required
    fileOp.wFunc = FO_COPY;
    fileOp.hNameMappings = NULL;
    fileOp.hwnd = NULL;
    fileOp.lpszProgressTitle = NULL;
    assert_int_equal(0, SHFileOperationA(&fileOp));
#else
    // TODO: maybe use fts or something less hacky
    char buf[2048];
#ifndef _WIN32
    snprintf(buf, sizeof(buf), "cp -a '%s' '%s'", src, dst);
#else
    snprintf(buf, sizeof(buf), "xcopy \"%s\" \"%s\" /I /Q /E /Y", src, dst);
#endif // _WIN32
    assert_int_equal(0, system(buf));
#endif // WINSHELLAPI
}

/* Creates and returns a temporary directory path.
 * Caller must free the string.
 */
#if defined(HAVE_MKDTEMP)
char *
make_temp_dir()
{
    char rltmp[PATH_MAX] = {0};
    if (!realpath(get_tmp(), rltmp)) {
        printf("Fatal: realpath on tmp folder failed. Error %d.\n", errno);
        return NULL;
    }

    const char *tmplate = "/rnp-gtest-XXXXXX";
    char *      buffer = (char *) calloc(1, strlen(rltmp) + strlen(tmplate) + 1);
    if (buffer == NULL) {
        return NULL;
    }
    memcpy(buffer, rltmp, strlen(rltmp));
    memcpy(buffer + strlen(rltmp), tmplate, strlen(tmplate));
    buffer[strlen(rltmp) + strlen(tmplate)] = '\0';
    char *res = mkdtemp(buffer);
    if (!res) {
        free(buffer);
    }
    return res;
}
#elif defined(HAVE__TEMPNAM)
char *
make_temp_dir()
{
    const int MAX_ATTEMPTS = 10;
    for (int i = 0; i < MAX_ATTEMPTS; i++) {
        char *dir = _tempnam(NULL, "rnp-gtest-");
        if (!dir) {
            fprintf(stderr, "_tempnam failed to generate temporary path");
            continue;
        }
        if (RNP_MKDIR(dir, S_IRWXU)) {
            fprintf(stderr, "Failed to create temporary directory");
            free(dir);
            continue;
        }
        return dir;
    }
    fprintf(stderr, "Failed to make temporary directory, aborting");
    return NULL;
}
#else
#error Unsupported platform
#endif

static char *
directory_from_absolute_file_path(const char *file_path)
{
    const char *last_sep = strrchr(file_path, '/');
    if (!last_sep) {
        return NULL;
    }

    size_t file_path_len = (last_sep - file_path);
    size_t dir_len = file_path_len + 1;
    char * dir = (char *) calloc(1, dir_len);
    if (!dir) {
        return NULL;
    }
    strncpy(dir, file_path, file_path_len);

    char *full_dir = realpath(dir, NULL);
    free(dir);
    dir = NULL;
    return full_dir;
}

static char *
directory_from_relative_file_path(const char *file_path, const char *reldir)
{
    const char *last_sep = strrchr(file_path, '/');
    if (!last_sep) {
        return NULL;
    }

    size_t file_path_len = (last_sep - file_path);
    size_t dir_len = strlen(reldir) + 1 + file_path_len + 1;
    char * dir = (char *) calloc(1, dir_len);
    if (!dir) {
        return NULL;
    }

    strncpy(dir, reldir, dir_len);
    strncat(dir, "/", dir_len);
    strncat(dir, file_path, file_path_len);

    char *full_dir = realpath(dir, NULL);
    free(dir);
    dir = NULL;
    return full_dir;
}

char *
directory_from_file_path(const char *file_path, const char *reldir)
{
    if (!file_path) {
        return NULL;
    }
    if (*file_path == '/') {
        return directory_from_absolute_file_path(file_path);
    }
    return directory_from_relative_file_path(file_path, reldir);
}

bool
bin_eq_hex(const uint8_t *data, size_t len, const char *val)
{
    uint8_t *dec;
    size_t   stlen = strlen(val);
    if (stlen != len * 2) {
        return false;
    }

    assert_non_null(dec = (uint8_t *) malloc(len));
    assert_true(rnp::hex_decode(val, dec, len));
    bool res = !memcmp(data, dec, len);
    free(dec);
    return res;
}

bool
hex2mpi(pgp_mpi_t *val, const char *hex)
{
    const size_t hex_len = strlen(hex);
    size_t       buf_len = hex_len / 2;
    bool         ok;

    uint8_t *buf = NULL;

    buf = (uint8_t *) malloc(buf_len);

    if (buf == NULL) {
        return false;
    }

    rnp::hex_decode(hex, buf, buf_len);

    ok = mem2mpi(val, buf, buf_len);
    free(buf);
    return ok;
}

bool
cmp_keyid(const pgp_key_id_t &id, const char *val)
{
    return bin_eq_hex(id.data(), id.size(), val);
}

bool
cmp_keyfp(const pgp_fingerprint_t &fp, const char *val)
{
    return bin_eq_hex(fp.fingerprint, fp.length, val);
}

int
test_value_equal(const char *what, const char *expected_value, const uint8_t v[], size_t v_len)
{
    assert_int_equal(strlen(expected_value), v_len * 2);
    char *produced = (char *) calloc(1, v_len * 2 + 1);
    if (!produced) {
        return -1;
    }
    rnp::hex_encode(v, v_len, produced, v_len * 2 + 1);
    assert_string_equal(produced, expected_value);
    free(produced);
    return 0;
}

bool
mpi_empty(const pgp_mpi_t &val)
{
    pgp_mpi_t zero{};
    return (val.len == 0) && !memcmp(val.mpi, zero.mpi, PGP_MPINT_SIZE);
}

char *
uint_to_string(char *buff, const int buffsize, unsigned int num, int base)
{
    char *ptr;
    ptr = &buff[buffsize - 1];
    *ptr = '\0';

    do {
        *--ptr = "0123456789abcdef"[num % base];
        num /= base;
    } while (num != 0);

    return ptr;
}

bool
write_pass_to_pipe(int fd, size_t count)
{
    const char *const password = "passwordforkeygeneration\n";
    for (size_t i = 0; i < count; i++) {
        const char *p = password;
        ssize_t     remaining = strlen(p);

        do {
            ssize_t written = write(fd, p, remaining);
            if (written <= 0) {
                perror("write");
                return false;
            }
            p += written;
            remaining -= written;
        } while (remaining);
    }
    return true;
}

bool
setupPasswordfd(int *pipefd)
{
    bool ok = false;

    if (pipe(pipefd) == -1) {
        perror("pipe");
        goto end;
    }
    // write it twice for normal keygen (primary+sub)
    if (!write_pass_to_pipe(pipefd[1], 2)) {
        close(pipefd[1]);
        goto end;
    }
    ok = true;

end:
    close(pipefd[1]);
    return ok;
}

static bool
setup_rnp_cfg(rnp_cfg &cfg, const char *ks_format, const char *homedir, int *pipefd)
{
    bool res;
    char pubpath[MAXPATHLEN];
    char secpath[MAXPATHLEN];
    char homepath[MAXPATHLEN];

    /* set password fd if any */
    if (pipefd) {
        if (!(res = setupPasswordfd(pipefd))) {
            return res;
        }
        cfg.set_int(CFG_PASSFD, pipefd[0]);
        // pipefd[0] will be closed via passfp
        pipefd[0] = -1;
    }
    /* setup keyring paths */
    if (homedir == NULL) {
        /* if we use default homedir then we append '.rnp' and create directory as well */
        homedir = getenv("HOME");
        paths_concat(homepath, sizeof(homepath), homedir, ".rnp", NULL);
        if (!rnp_dir_exists(homepath)) {
            path_mkdir(0700, homepath, NULL);
        }
        homedir = homepath;
    }

    if (homedir == NULL) {
        return false;
    }

    cfg.set_str(CFG_KR_PUB_FORMAT, ks_format);
    cfg.set_str(CFG_KR_SEC_FORMAT, ks_format);

    if (strcmp(ks_format, RNP_KEYSTORE_GPG) == 0) {
        paths_concat(pubpath, MAXPATHLEN, homedir, PUBRING_GPG, NULL);
        paths_concat(secpath, MAXPATHLEN, homedir, SECRING_GPG, NULL);
    } else if (strcmp(ks_format, RNP_KEYSTORE_KBX) == 0) {
        paths_concat(pubpath, MAXPATHLEN, homedir, PUBRING_KBX, NULL);
        paths_concat(secpath, MAXPATHLEN, homedir, SECRING_KBX, NULL);
    } else if (strcmp(ks_format, RNP_KEYSTORE_G10) == 0) {
        paths_concat(pubpath, MAXPATHLEN, homedir, PUBRING_G10, NULL);
        paths_concat(secpath, MAXPATHLEN, homedir, SECRING_G10, NULL);
    } else if (strcmp(ks_format, RNP_KEYSTORE_GPG21) == 0) {
        paths_concat(pubpath, MAXPATHLEN, homedir, PUBRING_KBX, NULL);
        paths_concat(secpath, MAXPATHLEN, homedir, SECRING_G10, NULL);
        cfg.set_str(CFG_KR_PUB_FORMAT, RNP_KEYSTORE_KBX);
        cfg.set_str(CFG_KR_SEC_FORMAT, RNP_KEYSTORE_G10);
    } else {
        return false;
    }

    cfg.set_str(CFG_KR_PUB_PATH, (char *) pubpath);
    cfg.set_str(CFG_KR_SEC_PATH, (char *) secpath);
    return true;
}

bool
setup_cli_rnp_common(cli_rnp_t *rnp, const char *ks_format, const char *homedir, int *pipefd)
{
    rnp_cfg cfg;
    if (!setup_rnp_cfg(cfg, ks_format, homedir, pipefd)) {
        return false;
    }

    /*initialize the basic RNP structure. */
    return cli_rnp_init(rnp, cfg);
}

void
cli_set_default_rsa_key_desc(rnp_cfg &cfg, const char *hashalg)
{
    cfg.set_int(CFG_NUMBITS, 1024);
    cfg.set_str(CFG_HASH, hashalg);
    cfg.set_int(CFG_S2K_ITER, 1);
    cli_rnp_set_generate_params(cfg);
}

// this is a password callback that will always fail
bool
failing_password_callback(const pgp_password_ctx_t *ctx,
                          char *                    password,
                          size_t                    password_size,
                          void *                    userdata)
{
    return false;
}

bool
ffi_failing_password_provider(rnp_ffi_t        ffi,
                              void *           app_ctx,
                              rnp_key_handle_t key,
                              const char *     pgp_context,
                              char *           buf,
                              size_t           buf_len)
{
    return false;
}

bool
ffi_asserting_password_provider(rnp_ffi_t        ffi,
                                void *           app_ctx,
                                rnp_key_handle_t key,
                                const char *     pgp_context,
                                char *           buf,
                                size_t           buf_len)
{
    assert_false(true);
    return false;
}

bool
ffi_string_password_provider(rnp_ffi_t        ffi,
                             void *           app_ctx,
                             rnp_key_handle_t key,
                             const char *     pgp_context,
                             char *           buf,
                             size_t           buf_len)
{
    size_t pass_len = strlen((const char *) app_ctx);
    if (pass_len >= buf_len) {
        return false;
    }
    memcpy(buf, app_ctx, pass_len + 1);
    return true;
}

// this is a password callback that should never be called
bool
asserting_password_callback(const pgp_password_ctx_t *ctx,
                            char *                    password,
                            size_t                    password_size,
                            void *                    userdata)
{
    assert_false(true);
    return false;
}

// this is a password callback that just copies the string in userdata to
// the password buffer
bool
string_copy_password_callback(const pgp_password_ctx_t *ctx,
                              char *                    password,
                              size_t                    password_size,
                              void *                    userdata)
{
    const char *str = (const char *) userdata;
    strncpy(password, str, password_size - 1);
    return true;
}

bool
starts_with(const std::string &data, const std::string &match)
{
    return data.find(match) == 0;
}

bool
ends_with(const std::string &data, const std::string &match)
{
    return data.size() >= match.size() &&
           data.substr(data.size() - match.size(), match.size()) == match;
}

std::string
fmt(const char *format, ...)
{
    int     size;
    va_list ap;

    va_start(ap, format);
    size = vsnprintf(NULL, 0, format, ap);
    va_end(ap);

    // +1 for terminating null
    std::string buf(size + 1, '\0');

    va_start(ap, format);
    size = vsnprintf(&buf[0], buf.size(), format, ap);
    va_end(ap);

    // drop terminating null
    buf.resize(size);
    return buf;
}

std::string
strip_eol(const std::string &str)
{
    size_t endpos = str.find_last_not_of("\r\n");
    if (endpos != std::string::npos) {
        return str.substr(0, endpos + 1);
    }
    return str;
}

std::string
lowercase(const std::string &str)
{
    std::string res = str;
    std::transform(
      res.begin(), res.end(), res.begin(), [](unsigned char ch) { return std::tolower(ch); });
    return res;
}

static bool
jso_get_field(json_object *obj, json_object **fld, const std::string &name)
{
    if (!obj || !json_object_is_type(obj, json_type_object)) {
        return false;
    }
    return json_object_object_get_ex(obj, name.c_str(), fld);
}

bool
check_json_field_str(json_object *obj, const std::string &field, const std::string &value)
{
    json_object *fld = NULL;
    if (!jso_get_field(obj, &fld, field)) {
        return false;
    }
    if (!json_object_is_type(fld, json_type_string)) {
        return false;
    }
    const char *jsoval = json_object_get_string(fld);
    return jsoval && (value == jsoval);
}

bool
check_json_field_int(json_object *obj, const std::string &field, int value)
{
    json_object *fld = NULL;
    if (!jso_get_field(obj, &fld, field)) {
        return false;
    }
    if (!json_object_is_type(fld, json_type_int)) {
        return false;
    }
    return json_object_get_int(fld) == value;
}

bool
check_json_field_bool(json_object *obj, const std::string &field, bool value)
{
    json_object *fld = NULL;
    if (!jso_get_field(obj, &fld, field)) {
        return false;
    }
    if (!json_object_is_type(fld, json_type_boolean)) {
        return false;
    }
    return json_object_get_boolean(fld) == value;
}

bool
check_json_pkt_type(json_object *pkt, int tag)
{
    if (!pkt || !json_object_is_type(pkt, json_type_object)) {
        return false;
    }
    json_object *hdr = NULL;
    if (!json_object_object_get_ex(pkt, "header", &hdr)) {
        return false;
    }
    if (!json_object_is_type(hdr, json_type_object)) {
        return false;
    }
    return check_json_field_int(hdr, "tag", tag);
}

static bool
ishex(const std::string &hexid)
{
    /* duplicates str_is_hex from fficli.cpp */
    size_t hexlen = hexid.length();
    size_t hexidx = 0;
    if ((hexlen >= 2) && (hexid[0] == '0') && ((hexid[1] == 'x') || (hexid[1] == 'X'))) {
        hexidx += 2;
    }

    for (size_t i = hexidx; i < hexlen; i++) {
        if ((hexid[i] >= '0') && (hexid[i] <= '9')) {
            continue;
        }
        if ((hexid[i] >= 'a') && (hexid[i] <= 'f')) {
            continue;
        }
        if ((hexid[i] >= 'A') && (hexid[i] <= 'F')) {
            continue;
        }
        if ((hexid[i] == ' ') || (hexid[i] == '\t')) {
            continue;
        }
        return false;
    }
    return true;
}

pgp_key_t *
rnp_tests_get_key_by_id(rnp_key_store_t *keyring, const std::string &keyid, pgp_key_t *after)
{
    if (!keyring || keyid.empty() || !ishex(keyid)) {
        return NULL;
    }
    pgp_key_id_t keyid_bin = {};
    size_t       binlen = rnp::hex_decode(keyid.c_str(), keyid_bin.data(), keyid_bin.size());
    if (binlen > PGP_KEY_ID_SIZE) {
        return NULL;
    }
    return rnp_key_store_get_key_by_id(keyring, keyid_bin, after);
}

pgp_key_t *
rnp_tests_get_key_by_fpr(rnp_key_store_t *keyring, const std::string &keyid)
{
    if (!keyring || keyid.empty() || !ishex(keyid)) {
        return NULL;
    }
    std::vector<uint8_t> keyid_bin(PGP_FINGERPRINT_SIZE, 0);
    size_t binlen = rnp::hex_decode(keyid.c_str(), keyid_bin.data(), keyid_bin.size());
    if (binlen > PGP_FINGERPRINT_SIZE) {
        return NULL;
    }
    pgp_fingerprint_t fp = {{}, static_cast<unsigned>(binlen)};
    memcpy(fp.fingerprint, keyid_bin.data(), binlen);
    return rnp_key_store_get_key_by_fpr(keyring, fp);
}

pgp_key_t *
rnp_tests_key_search(rnp_key_store_t *keyring, const std::string &keyid)
{
    if (!keyring || keyid.empty()) {
        return NULL;
    }

    pgp_key_search_t srch_userid = {PGP_KEY_SEARCH_USERID};
    strncpy(srch_userid.by.userid, keyid.c_str(), sizeof(srch_userid.by.userid));
    srch_userid.by.userid[sizeof(srch_userid.by.userid) - 1] = '\0';
    return rnp_key_store_search(keyring, &srch_userid, NULL);
}

void
reload_pubring(rnp_ffi_t *ffi)
{
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_save_keys(*ffi, "GPG", output, RNP_LOAD_SAVE_PUBLIC_KEYS));
    assert_rnp_success(rnp_ffi_destroy(*ffi));

    /* get output */
    uint8_t *buf = NULL;
    size_t   len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    rnp_input_t input = NULL;
    assert_rnp_success(rnp_input_from_memory(&input, buf, len, false));

    /* re-init ffi and load keys */
    assert_rnp_success(rnp_ffi_create(ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_import_keys(*ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, NULL));
    assert_rnp_success(rnp_output_destroy(output));
    assert_rnp_success(rnp_input_destroy(input));
}

void
reload_keyrings(rnp_ffi_t *ffi)
{
    rnp_output_t outpub = NULL;
    assert_rnp_success(rnp_output_to_memory(&outpub, 0));
    assert_rnp_success(rnp_save_keys(*ffi, "GPG", outpub, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_output_t outsec = NULL;
    assert_rnp_success(rnp_output_to_memory(&outsec, 0));
    assert_rnp_success(rnp_save_keys(*ffi, "GPG", outsec, RNP_LOAD_SAVE_SECRET_KEYS));
    assert_rnp_success(rnp_ffi_destroy(*ffi));
    /* re-init ffi and load keys */
    assert_rnp_success(rnp_ffi_create(ffi, "GPG", "GPG"));

    uint8_t *buf = NULL;
    size_t   len = 0;
    assert_rnp_success(rnp_output_memory_get_buf(outpub, &buf, &len, false));
    rnp_input_t input = NULL;
    assert_rnp_success(rnp_input_from_memory(&input, buf, len, false));
    assert_rnp_success(rnp_import_keys(*ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, NULL));
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_output_destroy(outpub));

    assert_rnp_success(rnp_output_memory_get_buf(outsec, &buf, &len, false));
    assert_rnp_success(rnp_input_from_memory(&input, buf, len, false));
    assert_rnp_success(rnp_import_keys(*ffi, input, RNP_LOAD_SAVE_SECRET_KEYS, NULL));
    assert_rnp_success(rnp_input_destroy(input));
    assert_rnp_success(rnp_output_destroy(outsec));
}

static bool
load_keys_internal(rnp_ffi_t          ffi,
                   const std::string &format,
                   const std::string &path,
                   bool               secret)
{
    if (path.empty()) {
        return true;
    }
    rnp_input_t input = NULL;
    if (rnp_input_from_path(&input, path.c_str())) {
        return false;
    }
    bool res = !rnp_load_keys(ffi,
                              format.c_str(),
                              input,
                              secret ? RNP_LOAD_SAVE_SECRET_KEYS : RNP_LOAD_SAVE_PUBLIC_KEYS);
    rnp_input_destroy(input);
    return res;
}

bool
load_keys_gpg(rnp_ffi_t ffi, const std::string &pub, const std::string &sec)
{
    return load_keys_internal(ffi, "GPG", pub, false) &&
           load_keys_internal(ffi, "GPG", sec, true);
}

bool
load_keys_kbx_g10(rnp_ffi_t ffi, const std::string &pub, const std::string &sec)
{
    return load_keys_internal(ffi, "KBX", pub, false) &&
           load_keys_internal(ffi, "G10", sec, true);
}

static bool
import_keys(rnp_ffi_t ffi, const std::string &path, uint32_t flags)
{
    rnp_input_t input = NULL;
    if (rnp_input_from_path(&input, path.c_str())) {
        return false;
    }
    bool res = !rnp_import_keys(ffi, input, flags, NULL);
    rnp_input_destroy(input);
    return res;
}

bool
import_all_keys(rnp_ffi_t ffi, const std::string &path)
{
    return import_keys(ffi, path, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS);
}

bool
import_pub_keys(rnp_ffi_t ffi, const std::string &path)
{
    return import_keys(ffi, path, RNP_LOAD_SAVE_PUBLIC_KEYS);
}

bool
import_sec_keys(rnp_ffi_t ffi, const std::string &path)
{
    return import_keys(ffi, path, RNP_LOAD_SAVE_SECRET_KEYS);
}

static bool
import_keys(rnp_ffi_t ffi, const uint8_t *data, size_t len, uint32_t flags)
{
    rnp_input_t input = NULL;
    if (rnp_input_from_memory(&input, data, len, false)) {
        return false;
    }
    bool res = !rnp_import_keys(ffi, input, flags, NULL);
    rnp_input_destroy(input);
    return res;
}

bool
import_all_keys(rnp_ffi_t ffi, const uint8_t *data, size_t len)
{
    return import_keys(ffi, data, len, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS);
}

bool
import_pub_keys(rnp_ffi_t ffi, const uint8_t *data, size_t len)
{
    return import_keys(ffi, data, len, RNP_LOAD_SAVE_PUBLIC_KEYS);
}

bool
import_sec_keys(rnp_ffi_t ffi, const uint8_t *data, size_t len)
{
    return import_keys(ffi, data, len, RNP_LOAD_SAVE_SECRET_KEYS);
}

void
dump_key_stdout(rnp_key_handle_t key, bool secret)
{
    rnp_output_t output = NULL;
    rnp_output_to_memory(&output, 0);
    rnp_key_export(
      key, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS | RNP_KEY_EXPORT_ARMORED);
    if (secret) {
        rnp_key_export(key,
                       output,
                       RNP_KEY_EXPORT_SECRET | RNP_KEY_EXPORT_SUBKEYS |
                         RNP_KEY_EXPORT_ARMORED);
    }
    size_t   len = 0;
    uint8_t *buf = NULL;
    rnp_output_memory_get_buf(output, &buf, &len, false);
    printf("%.*s", (int) len, (char *) buf);
    rnp_output_destroy(output);
}

bool
sm2_enabled()
{
    bool enabled = false;
    if (rnp_supports_feature(RNP_FEATURE_PK_ALG, "SM2", &enabled)) {
        return false;
    }
    return enabled;
}

bool
aead_eax_enabled()
{
    bool enabled = false;
    if (rnp_supports_feature(RNP_FEATURE_AEAD_ALG, "EAX", &enabled)) {
        return false;
    }
    return enabled;
}

bool
aead_ocb_enabled()
{
    bool enabled = false;
    if (rnp_supports_feature(RNP_FEATURE_AEAD_ALG, "OCB", &enabled)) {
        return false;
    }
    return enabled;
}

bool
twofish_enabled()
{
    bool enabled = false;
    if (rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "Twofish", &enabled)) {
        return false;
    }
    return enabled;
}

bool
brainpool_enabled()
{
    bool enabled = false;
    if (rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP256r1", &enabled)) {
        return false;
    }
    return enabled;
}
