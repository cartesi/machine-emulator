// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef UNIQUE_C_PTR
#define UNIQUE_C_PTR

#include <memory>
#include <new>
#include <system_error>
#include <cstdlib>
#include <cstdio>

namespace cartesi {

namespace detail {
    struct free_deleter {
        template <typename T>
        void operator()(T *p) const {
            // NOLINTNEXTLINE(cppcoreguidelines-no-malloc, cppcoreguidelines-pro-type-const-cast)
            std::free(const_cast<std::remove_const_t<T> *>(p));
        }
    };

    struct fclose_deleter {
        void operator()(FILE *p) const {
            std::fclose(p);
        }
    };
}

template <typename T>
using unique_calloc_ptr = std::unique_ptr<T, detail::free_deleter>;

using unique_file_ptr = std::unique_ptr<FILE, detail::fclose_deleter>;

template <typename T>
static inline unique_calloc_ptr<T> unique_calloc(size_t nmemb) {
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
    T *ptr = reinterpret_cast<T *>(calloc(nmemb, sizeof(T)));
    if (!ptr) {
        throw std::bad_alloc{};
    }
    return unique_calloc_ptr<T>(ptr);
}

template <typename T>
static inline unique_calloc_ptr<T> unique_calloc(size_t nmemb, const std::nothrow_t &tag) {
    (void) tag;
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
    return unique_calloc_ptr<T>(reinterpret_cast<T*>(calloc(nmemb, sizeof(T))));
}

static inline unique_file_ptr unique_fopen(const char *pathname, const char *mode) {
    FILE *fp = fopen(pathname, mode);
    if (!fp) {
        throw std::system_error(errno, std::generic_category(),
            "unable to open '" + std::string{pathname} +
            "' in mode '" + std::string{mode} + "'");
    }
    return unique_file_ptr{fp};
}

static inline unique_file_ptr unique_fopen(const char *pathname, const char *mode, const std::nothrow_t &tag) {
    (void) tag;
    return unique_file_ptr{fopen(pathname, mode)};
}

} // namespace cartesi

#endif
