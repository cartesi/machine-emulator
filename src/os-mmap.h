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
#include <string>

namespace cartesi {

enum os_mmap_flags {
    OS_MMAP_SHARED = 1 << 0,      ///< Share memory with the backing file
    OS_MMAP_LOCKBACKING = 1 << 1, ///< Lock backing file (for shared read or exclusive writing)
    OS_MMAP_READONLY = 1 << 2,    ///< Mark memory as read-only
    OS_MMAP_NORESERVE = 1 << 3,   ///< Do not reserve swap space, allowing to map large address space
};

struct os_mmapd {
    unsigned char *host_memory{};
    uint64_t length{};
    int flags{};
    int backing_fd{-1};
    uint64_t backing_length{};
    std::string backing_filename{};
};

/// \brief Maps OS memory
os_mmapd os_mmap(uint64_t length, int flags = 0, const std::string &backing_filename = "");

/// \brief Unmaps OS memory
void os_munmap(const os_mmapd &mmapd);

} // namespace cartesi

#endif
