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

#ifndef OS_MMAP_H
#define OS_MMAP_H

#include <cstdint>
#include <memory>
#include <string>

namespace cartesi {

struct os_mmap_flags {
    bool shared{false};    ///< Share mapped memory with the backing file
    bool read_only{false}; ///< Mark mapped memory as read-only
    bool truncate{false};  ///< Truncate mapped memory to match the specified length when backing file length mismatches
    bool lock_backing{false}; ///< Lock backing file for exclusive writing when shared, otherwise for shared read
};

struct os_mmapd {
    void *host_memory{};
    uint64_t length{};
    os_mmap_flags flags{};
    int backing_fd{-1};
    uint64_t backing_length{};
    std::string backing_filename;
};

/// \brief Maps OS memory
os_mmapd os_mmap(uint64_t length, const os_mmap_flags &flags, const std::string &backing_filename);

/// \brief Unmaps OS memory
void os_munmap(const os_mmapd &mmapd);

namespace detail {

struct mmap_deleter {
    os_mmapd m_mmapd;
    explicit mmap_deleter(os_mmapd mmapd) : m_mmapd(std::move(mmapd)) {};
    template <typename T>
    void operator()(T * /*ptr*/) const {
        os_munmap(m_mmapd);
    }
};

} // namespace detail

template <typename T>
using unique_mmap_ptr = std::unique_ptr<T, detail::mmap_deleter>;

template <typename T>
static inline auto make_unique_mmap(size_t nmemb, const os_mmap_flags &flags = {},
    const std::string &backing_filename = "") {
    const size_t size = nmemb * sizeof(T);
    const os_mmapd mmapd = os_mmap(size, flags, backing_filename); // os_map_file throws on error
    T *ptr = static_cast<T *>(mmapd.host_memory);
    return unique_mmap_ptr<T>(ptr, detail::mmap_deleter{mmapd});
}

} // namespace cartesi

#endif
