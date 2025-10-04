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

#ifndef OS_MAPPED_MEMORY_H
#define OS_MAPPED_MEMORY_H

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
#include <optional>
#include <span>
#include <string>

#include "os-features.h"

#ifndef HAVE_MMAP
#include <cstdio>
#endif

namespace cartesi::os {

/// \brief Flags for memory mapping operations.
struct mapped_memory_flags {
    bool read_only{false};  ///< Mark mapped memory as read-only
    bool shared{false};     ///< Share mapped memory with the backing file
    bool no_reserve{false}; ///< Do not reserve swap memory for the mapping
};

/// \brief Represents a memory-mapped region, optionally backed by a file.
class mapped_memory final {
    void *m_host_memory{nullptr};      ///< Pointer to the mapped memory region
    uint64_t m_length{0};              ///< The total size of the mapped memory
    std::string m_backing_filename;    ///< Path to the backing file
    uint64_t m_backing_length{0};      ///< Backing file length in bytes
    uint64_t m_backing_sync_length{0}; ///< Length of file-backed portion for which memory sync is needed
    mapped_memory_flags m_flags;       ///< Flags used for the mapping
#ifdef HAVE_MMAP
    int m_backing_fd{-1}; ///< File descriptor of the backing file
#elif defined(_WIN32)
    void *m_memory_mapping{nullptr};      ///< Handle of the memory mapping
    void *m_backing_host_memory{nullptr}; ///< Pointer to the backing file mapped memory region
    void *m_backing_mapping{nullptr};     ///< Handle of the backing file mapping
    void *m_backing_fh{nullptr};          ///< Handle of the backing file
#else
    FILE *m_backing_fp{nullptr};            ///< Pointer of the backing file
    void *m_unaligned_host_memory{nullptr}; ///< Pointer to the memory that we can deallocate with std::free()
#endif

    mapped_memory() = default;

public:
    /// \brief Maps a memory region, optionally backed by a file.
    /// \param length Total memory length to map.
    /// \param flags Flags for the mapping.
    /// \param backing_filename Path to the file to back the memory mapping.
    /// \param backing_length The expected size of the backing file in bytes (must be <= length).
    /// \returns Structure containing the memory mapping information.
    /// \details The memory is guaranteed to be aligned to 4096-byte boundaries.
    /// Memory above backing file length are zereod, and modifications to that region are not written out to the file.
    explicit mapped_memory(uint64_t length, const mapped_memory_flags &flags = {},
        const std::string &backing_filename = {}, std::optional<uint64_t> backing_length = {});

    /// \brief Destructor.
    ~mapped_memory() noexcept;

    // No copy or move constructors or assignments
    mapped_memory(const mapped_memory &other) = delete;
    mapped_memory &operator=(const mapped_memory &other) = delete;
    mapped_memory(mapped_memory &&other) noexcept = delete;
    mapped_memory &operator=(mapped_memory &&other) noexcept = delete;

    /// \brief Returns a pointer to the mapped memory region.
    unsigned char *get_ptr() {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return reinterpret_cast<unsigned char *>(m_host_memory);
    };

    /// \brief Returns a pointer to the mapped memory region.
    const unsigned char *get_ptr() const {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return reinterpret_cast<const unsigned char *>(m_host_memory);
    };

    /// \brief Returns a span representing the mapped memory region.
    std::span<unsigned char> get_span() noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return std::span<unsigned char>{reinterpret_cast<unsigned char *>(m_host_memory), m_length};
    }

    /// \brief Returns a span representing the mapped memory region.
    std::span<const unsigned char> get_span() const noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return std::span<const unsigned char>{reinterpret_cast<const unsigned char *>(m_host_memory), m_length};
    }

    /// \brief Returns a span representing the backing portion of the mapped memory region.
    std::span<unsigned char> get_backing_span() noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return std::span<unsigned char>{reinterpret_cast<unsigned char *>(m_host_memory), m_backing_length};
    }

    /// \brief Returns a span representing the backing portion of the mapped memory region.
    std::span<const unsigned char> get_backing_span() const noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return std::span<const unsigned char>{reinterpret_cast<const unsigned char *>(m_host_memory), m_backing_length};
    }

    /// \brief Returns the total length of the mapped memory region.
    uint64_t get_length() const noexcept {
        return m_length;
    }

    /// \brief Returns the length of the backing file portion of the mapped memory region.
    uint64_t get_backing_length() const noexcept {
        return m_backing_length;
    }

    /// \brief Returns the flags used for the mapping.
    mapped_memory_flags get_flags() const noexcept {
        return m_flags;
    }
};

} // namespace cartesi::os

#endif
