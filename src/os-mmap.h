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

/// \file
/// \brief Operating system memory mapping operations.
/// \details \{
/// This header file defines the interface for memory mapping operations for the emulator.
/// It provides a cross-platform abstraction for memory-mapped regions, supporting both anonymous
/// and file-backed mappings. The implementation ensures compatibility with various operating
/// systems, including Linux, Windows, and fallback environments without native `mmap` support.
///
/// Key Features:
/// - Memory mapping with optional file backing.
/// - Support for read-only, shared, and exclusive access modes.
/// - Automatic alignment to system page size for efficient memory access.
/// - Cross-platform compatibility with platform-specific optimizations.
///
/// This module is designed to handle complex memory mapping scenarios, such as partial file
/// mappings, and synchronization of file-backed memory regions.
/// \}

#include <cstdint>
#include <memory>
#include <string>

#include "os-features.h"

#ifndef HAVE_MMAP
#include <cstdio>
#endif

namespace cartesi {

/// \brief Flags for memory mapping operations.
struct os_mmap_flags {
    bool read_only{false};  ///< Mark mapped memory as read-only
    bool shared{false};     ///< Share mapped memory with the backing file
    bool no_reserve{false}; ///< Do not reserve sawp memory for the mapping
};

/// \brief Structure representing a memory-mapped region.
struct os_mmapd {
    void *host_memory{nullptr};      ///< Pointer to the mapped memory region
    uint64_t length{0};              ///< The total size of the mapped memory
    os_mmap_flags flags;             ///< Flags used for the mapping
    uint64_t backing_sync_length{0}; ///< Length of file-backed portion for which memory sync is needed
#ifdef HAVE_MMAP
    int backing_fd{-1}; ///< File descriptor of the backing file
#elif defined(_WIN32)
    void *memory_mapping{nullptr};      ///< Handle of the memory mapping
    void *backing_host_memory{nullptr}; ///< Pointer to the backing file mapped memory region
    void *backing_mapping{nullptr};     ///< Handle of the backing file mapping
    void *backing_fh{nullptr};          ///< Handle of the backing file
#else
    FILE *backing_fp{nullptr};            ///< Pointer of the backing file
    void *unaligned_host_memory{nullptr}; ///< Pointer to the memory that we can deallocate with std::free()
#endif
};

/// \brief Retrieves the system's memory page size.
/// \details Typically 4KB, but may vary (e.g., 8KB on Solaris, 16KB on macOS arm64).
uint64_t os_get_mmap_page_size();

/// \brief Maps a memory region, optionally backed by a file.
/// \param length Total memory length to map.
/// \param flags Flags for the mapping.
/// \param backing_filename Path to the file to back the memory mapping.
/// \param backing_length The expected size of the backing file in bytes (must be <= length).
/// \returns Structure containing the memory mapping information.
/// \details The memory is guaranteed to be aligned to 4096-byte boundaries.
/// Memory above backing file length are zereod, and modifications to that region are not written out to the file.
os_mmapd os_mmap(uint64_t length, const os_mmap_flags &flags = {}, const std::string &backing_filename = {},
    uint64_t backing_length = 0);

/// \brief Unmaps a previously mapped memory region.
void os_munmap(const os_mmapd &mmapd) noexcept;

namespace detail {

struct mmap_deleter {
    os_mmapd m_mmapd;
    explicit mmap_deleter(os_mmapd mmapd) : m_mmapd(mmapd) {};
    template <typename T>
    void operator()(T * /*ptr*/) const noexcept {
        os_munmap(m_mmapd);
    }
};

} // namespace detail

template <typename T>
using unique_mmap_ptr = std::unique_ptr<T, detail::mmap_deleter>;

template <typename T>
static inline auto make_unique_mmap(size_t nmemb, const os_mmap_flags &flags = {},
    const std::string &backing_filename = {}, uint64_t backing_length = 0) {
    const size_t size = nmemb * sizeof(T);
    const os_mmapd mmapd = os_mmap(size, flags, backing_filename, backing_length); // os_map throws on error
    T *ptr = static_cast<T *>(mmapd.host_memory);
    return unique_mmap_ptr<T>(ptr, detail::mmap_deleter{mmapd});
}

} // namespace cartesi

#endif
