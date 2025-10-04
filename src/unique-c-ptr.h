// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

#ifndef UNIQUE_C_PTR_H
#define UNIQUE_C_PTR_H

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <new>
#include <system_error>
#include <tuple>

namespace cartesi {

namespace detail {

//??D Cannot use lambda expression to create the deleters because lambda expressions are not copy-assignable
//??D and we need them to be so we can put pointers using these deleters into containers

struct free_deleter {
    template <typename T>
    void operator()(T *ptr) const {
        std::free(ptr); // NOLINT(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    }
};

struct fclose_deleter {
    void operator()(FILE *p) const {
        std::ignore = std::fclose(p);
    }
};

} // namespace detail

template <typename T>
using unique_calloc_ptr = std::unique_ptr<T, detail::free_deleter>;

using unique_file_ptr = std::unique_ptr<FILE, detail::fclose_deleter>;

template <typename T>
static inline auto make_unique_calloc(size_t nmemb) {
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    T *ptr = static_cast<T *>(calloc(nmemb, sizeof(T)));
    if (ptr == nullptr) {
        throw std::bad_alloc{}; // LCOV_EXCL_LINE
    }
    return unique_calloc_ptr<T>(ptr);
}

template <typename T>
static inline auto make_unique_calloc(size_t nmemb, const std::nothrow_t & /*tag*/) {
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    return unique_calloc_ptr<T>(static_cast<T *>(calloc(nmemb, sizeof(T))));
}

static inline auto make_unique_fopen(const char *pathname, const char *mode) {
    FILE *fp = fopen(pathname, mode);
    if (fp == nullptr) {
        throw std::system_error(errno, std::generic_category(),
            "unable to open '" + std::string{pathname} + "' in mode '" + std::string{mode} + "'");
    }
    return unique_file_ptr{fp};
}

static inline auto make_unique_fopen(const char *pathname, const char *mode, const std::nothrow_t & /*tag*/) {
    return unique_file_ptr{fopen(pathname, mode)};
}

} // namespace cartesi

#endif
