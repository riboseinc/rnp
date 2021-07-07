/*-
 * Copyright (c) 2021 Ribose Inc.
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

#ifndef CRYPTO_MEM_H_
#define CRYPTO_MEM_H_

#include "config.h"
#include <array>
#include <vector>
#if defined(CRYPTO_BACKEND_BOTAN)
#include <botan/secmem.h>
#include <botan/ffi.h>
#elif defined(CRYPTO_BACKEND_OPENSSL)
#include <openssl/crypto.h>
#endif

namespace rnp {

#if defined(CRYPTO_BACKEND_BOTAN)
template <typename T> using secure_vector = Botan::secure_vector<T>;
#else
template <typename T> using secure_vector = std::vector<T>;
#endif

template <typename T, std::size_t N> struct secure_array {
  private:
    static_assert(std::is_integral<T>::value, "T must be integer type");
    std::array<T, N> data_;

  public:
    secure_array() : data_({0})
    {
    }

    T *
    data()
    {
        return &data_[0];
    }

    std::size_t
    size() const
    {
        return data_.size();
    }

    T
    operator[](size_t idx) const
    {
        return data_[idx];
    }

    T &
    operator[](size_t idx)
    {
        return data_[idx];
    }

    ~secure_array()
    {
#if defined(CRYPTO_BACKEND_BOTAN)
        botan_scrub_mem(&data_[0], sizeof(data_));
#elif defined(CRYPTO_BACKEND_OPENSSL)
        OPENSSL_cleanse(&data_[0], sizeof(data_));
#else
#error "Unsupported crypto backend."
#endif
    }
};

typedef enum { HEX_LOWERCASE, HEX_UPPERCASE } hex_format_t;

bool   hex_encode(const uint8_t *buf,
                  size_t         buf_len,
                  char *         hex,
                  size_t         hex_len,
                  hex_format_t   format = HEX_UPPERCASE);
size_t hex_decode(const char *hex, uint8_t *buf, size_t buf_len);
} // namespace rnp

void secure_clear(void *vp, size_t size);

#endif // CRYPTO_MEM_H_
