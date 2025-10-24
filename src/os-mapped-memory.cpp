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

#include "os-features.h"

// Must be included before
#include "os-posix-compat.h" // IWYU pragma: keep

#if defined(HAVE_MMAP)
#include <fcntl.h>    // open
#include <sys/mman.h> // mmap/munmap
#include <sys/stat.h> // fstat
#include <unistd.h>   // write/read/close
#else
#include <cstdio>  // fopen/fclose/fread/fwrite/fflush
#include <cstdlib> // calloc/free
#include <memory>  // align
#endif

#if defined(HAVE_FLOCK)
#include <sys/file.h> // flock
#endif

#include "os-mapped-memory.h"

#include "scope-exit.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

namespace cartesi::os {

using namespace std::string_literals;

constexpr uint64_t DEFAULT_MMAP_PAGE_SIZE = 4096;

/// \brief Retrieves the system's memory page size.
/// \details Typically 4KB, but may vary (e.g., 8KB on Solaris, 16KB on macOS arm64).
static uint64_t get_mmap_page_size() {
#ifdef HAVE_MMAP
    const auto page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 0) {
        throw std::system_error{errno, std::generic_category(), "unable to retrieve system page size"s};
    }
    return static_cast<uint64_t>(page_size);

#elif defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return static_cast<uint64_t>(si.dwPageSize);

#else
    return DEFAULT_MMAP_PAGE_SIZE;

#endif // HAVE_MMAP
}

mapped_memory::mapped_memory(uint64_t length, const mapped_memory_flags &flags, const std::string &backing_filename,
    std::optional<uint64_t> backing_length) :
    m_length(length),
    m_backing_filename(backing_filename),
    m_flags(flags) {
    const uint64_t desired_backing_length = backing_length.has_value() ? backing_length.value() : length;

    // Check some preconditions
    if (backing_filename.empty() && flags.shared) {
        throw std::invalid_argument{"backing filename must be specified"s};
    }
    if (length == 0) {
        throw std::invalid_argument{"memory map length cannot be zero"s};
    }
    if (length < desired_backing_length) {
        throw std::invalid_argument{"length must be greater or equal than max backing length"s};
    }
    const bool shared_write = flags.shared && !flags.read_only;

    // Ensure mapped pages are 4096-byte aligned for compatibility with
    // routines using efficient SIMD operations on memory pages.
    const uint64_t page_size = get_mmap_page_size();
    if (page_size < DEFAULT_MMAP_PAGE_SIZE) {
        throw std::runtime_error{"system memory page size is less than "s + std::to_string(DEFAULT_MMAP_PAGE_SIZE)};
    }

#ifdef HAVE_MMAP
    int backing_fd = -1;
    uint64_t backing_file_length = 0;

    // Auto close backing file on failure
    auto backing_closer = scope_fail([&] {
        if (backing_fd >= 0) {
            // Close backing file
            close(backing_fd);
        }
    });

    // Handle backing file if specified
    if (!backing_filename.empty()) {
        // Determine backing file open flags
        int oflags = (shared_write ? O_RDWR : O_RDONLY);
        oflags |= O_CLOEXEC; // to remove file locks on fork + exec

        // Open backing file
        backing_fd = open(backing_filename.c_str(), oflags);
        if (backing_fd < 0) {
            throw std::system_error{errno, std::generic_category(),
                "unable to open backing file '"s + backing_filename + "'"s};
        }

#ifdef HAVE_FLOCK
        // Lock backing file immediately after opening it
        const int flockop = (shared_write ? LOCK_EX : LOCK_SH) | LOCK_NB;
        if (flock(backing_fd, flockop) != 0) {
            throw std::system_error{errno, std::generic_category(),
                "unable to lock backing file '"s + backing_filename + "'"s};
        }
#endif // HAVE_FLOCK

        // Get backing file size
        struct stat statbuf{};
        if (fstat(backing_fd, &statbuf) != 0) {
            throw std::system_error{errno, std::generic_category(),
                "unable to obtain length of backing file '"s + backing_filename + "'"s};
        }
        backing_file_length = static_cast<uint64_t>(statbuf.st_size);

        // Check backing file length mismatch
        if (backing_file_length != desired_backing_length) {
            if (backing_file_length > desired_backing_length) {
                throw std::runtime_error{"backing file '"s + backing_filename + "' length ("s +
                    std::to_string(backing_file_length) + ") cannot be less than desired backing length ("s +
                    std::to_string(desired_backing_length) + ")"s};
            }
            if (flags.shared || !flags.backing_gap) {
                throw std::runtime_error{"backing file '"s + backing_filename + "' length ("s +
                    std::to_string(backing_file_length) + ") does not match desired backing length ("s +
                    std::to_string(desired_backing_length) + ")"s};
            }
            // Backing file length may be less than desired backing length,
            // but this is fine, as we are not sharing the file.
            // The gap between the file length and the memory length will be allocated as anonymous memory.
        }
    }

    // Determine map memory flags
    int mflags = flags.shared ? MAP_SHARED : MAP_PRIVATE;
    if (backing_fd < 0) { // The mapping is not backed by any file
        mflags |= MAP_ANONYMOUS;
    }
    int extra_mflags = 0;
    if (flags.no_reserve) {
        extra_mflags |= MAP_NORESERVE;
    }
    mflags |= extra_mflags;

    // Determine map protection flags
    int mprot = PROT_READ;
    if (!flags.read_only) {
        mprot |= PROT_WRITE;
    }

    // Unmap memory in case memory mapping fails
    void *host_memory = nullptr;
    auto memory_closer = scope_fail([&] {
        if (host_memory != nullptr) {
            munmap(host_memory, length);
        }
    });

    // Map memory
    if (backing_fd >= 0 && length != backing_file_length) {
        // Here we need to split the mapping into two parts:
        // 1. Map the entire memory range with anonymous memory first
        // 2. Replace memory map related to backing file portion
        // This will leave a contiguous memory region where the first portion is backed by a file,
        // and the second portion is backed by anonymous memory.

        // Map entire memory range, this is required to use the subsequent MAP_FIXED safely.
        // const int m
        host_memory = mmap(nullptr, length, mprot, MAP_PRIVATE | MAP_ANONYMOUS | extra_mflags, -1, 0);
        if (host_memory == MAP_FAILED) {
            throw std::system_error{errno, std::generic_category(), "unable to map memory"s};
        }

        // Replace memory map related to backing file portion
        void *backing_host_memory = mmap(host_memory, backing_file_length, mprot, mflags | MAP_FIXED, backing_fd, 0);
        if (backing_host_memory != host_memory) {
            throw std::system_error{errno, std::generic_category(),
                "unable to map backing file '"s + backing_filename + "' to memory"s};
        }

        // POSIX ensures that any partial page at the end of a file is zero-filled,
        // and modifications beyond the file's end are never written to disk.
        // However on Linux, writing beyond such a partial page updates the page cache but not the file,
        // and subsequent mappings may see the cached modifications even after the file is closed and unmapped,
        // so we have to zero fill the last partial page just to be safe.
        // See more about this on BUGS section in mmap() Linux man pages.
        const uint64_t partial_page_size = backing_file_length % page_size;
        const uint64_t partial_page_remaining = std::min(page_size - partial_page_size, length - backing_file_length);
        if (partial_page_remaining > 0) {
            if (flags.read_only) {
                // We can't write on read-only mappings.
                // This kind of mapping is unlikely to happen, so there is no need to support it.
                throw std::runtime_error{
                    "possible non zero partial page when mapping backing file '"s + backing_filename + "' to memory"s};
            }
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            std::memset(reinterpret_cast<uint8_t *>(backing_host_memory) + backing_file_length, 0,
                partial_page_remaining);
        }
    } else { // Can perform a single mmap()
        host_memory = mmap(nullptr, length, mprot, mflags, backing_fd, 0);
        if (host_memory == MAP_FAILED) {
            if (backing_fd < 0) {
                throw std::system_error{errno, std::generic_category(), "unable to map memory"s};
            }
            throw std::system_error{errno, std::generic_category(),
                "unable to map backing file '"s + backing_filename + "' to memory"s};
        }
    }

    // Commit state
    m_host_memory = host_memory;
    m_backing_sync_length = shared_write ? desired_backing_length : 0;
    m_backing_fd = backing_fd;

#elif defined(_WIN32)
    HANDLE backing_fh = INVALID_HANDLE_VALUE;
    HANDLE backing_mapping = nullptr;
    HANDLE memory_mapping = nullptr;
    void *backing_host_memory = nullptr;
    void *host_memory = nullptr;
    uint64_t backing_file_length = 0;

    // Auto cleanup on failure
    auto failure_cleaner = scope_fail([&] {
        if (backing_host_memory != nullptr) {
            std::ignore = UnmapViewOfFile(backing_host_memory);
        }
        if (host_memory != nullptr) {
            std::ignore = UnmapViewOfFile(host_memory);
        }
        if (backing_mapping != nullptr) {
            std::ignore = CloseHandle(backing_mapping);
        }
        if (memory_mapping != nullptr) {
            std::ignore = CloseHandle(memory_mapping);
        }
        if (backing_fh != INVALID_HANDLE_VALUE) {
            // Unlock file
            OVERLAPPED overlapped{};
            std::ignore = UnlockFileEx(backing_fh, 0, MAXDWORD, MAXDWORD, &overlapped);
            // Close backing file
            std::ignore = CloseHandle(backing_fh);
        }
    });

    // Handle backing file if specified
    if (!backing_filename.empty()) {
        // Determine backing file open flags
        const DWORD open_access = GENERIC_READ | (!flags.read_only ? GENERIC_WRITE : 0);
        const DWORD share_mode = FILE_SHARE_READ | (!flags.read_only ? FILE_SHARE_WRITE : 0);
        const DWORD creation = OPEN_EXISTING;

        // Open backing file
        backing_fh = CreateFileA(backing_filename.c_str(), open_access, share_mode, nullptr, creation,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (backing_fh == INVALID_HANDLE_VALUE) {
            throw std::system_error{static_cast<int>(GetLastError()), std::system_category(),
                "unable to open backing file '"s + backing_filename + "'"s};
        }

        // Lock backing file immediately after opening it
        DWORD lock_flags = LOCKFILE_FAIL_IMMEDIATELY; // Non-blocking lock
        if (shared_write) {
            lock_flags |= LOCKFILE_EXCLUSIVE_LOCK; // Exclusive lock for writing
        }
        OVERLAPPED overlapped{};
        if (!LockFileEx(backing_fh, lock_flags, 0, MAXDWORD, MAXDWORD, &overlapped)) {
            throw std::system_error{static_cast<int>(GetLastError()), std::system_category(),
                "unable to lock backing file '" + backing_filename + "'"};
        }

        // Get backing file size
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(backing_fh, &size)) {
            throw std::system_error{static_cast<int>(GetLastError()), std::system_category(),
                "unable to obtain length of backing file '"s + backing_filename + "'"s};
        }
        backing_file_length = static_cast<uint64_t>(size.QuadPart);

        // Check backing file length mismatch
        if (backing_file_length != desired_backing_length) {
            if (backing_file_length > desired_backing_length) {
                throw std::runtime_error{"backing file '"s + backing_filename + "' length ("s +
                    std::to_string(backing_file_length) + ") cannot be less than desired backing length ("s +
                    std::to_string(desired_backing_length) + ")"s};
            }
            if (flags.shared || !flags.backing_gap) {
                throw std::runtime_error{"backing file '"s + backing_filename + "' length ("s +
                    std::to_string(backing_file_length) + ") does not match desired backing length ("s +
                    std::to_string(desired_backing_length) + ")"s};
            }
            // Backing file length may be less than desired backing length,
            // but this is fine, as we are not sharing the file.
            // The gap between the file length and the memory length will be allocated as anonymous memory.
        }
    }

    HANDLE memory_handle = INVALID_HANDLE_VALUE;
    if (backing_file_length > 0 && backing_file_length == length) {
        // When backing file length matches memory length, we can map it directly
        memory_handle = backing_fh;
    } else if (backing_file_length > 0) {
        // Unfortunately Windows does not easily support creating a contiguous memory region with
        // mixed file-backed and anonymous memory mappings. Instead, we create an auxiliary
        // mapping for the backing file and handle data transfers explicitly:
        // 1) Copy data from backing file to host memory during mapping
        // 2) Copy modified data back to the backing file during unmapping in case of shared write access

        // Determine backing file mapping flags
        const DWORD backing_access = shared_write ? FILE_MAP_WRITE : FILE_MAP_READ;
        const DWORD backing_protect = shared_write ? PAGE_READWRITE : PAGE_READONLY;

        // Create backing file mapping
        backing_mapping =
            CreateFileMappingA(backing_fh, nullptr, backing_protect, static_cast<DWORD>(backing_file_length >> 32),
                static_cast<DWORD>(backing_file_length & 0xffffffff), nullptr);
        if (backing_mapping == nullptr) {
            throw std::system_error{static_cast<int>(GetLastError()), std::system_category(),
                "unable to create memory mapping of backing file '"s + backing_filename + "'"s};
        }

        // Map backing file
        backing_host_memory = MapViewOfFile(backing_mapping, backing_access, 0, 0, backing_file_length);
        if (backing_host_memory == nullptr) {
            throw std::system_error{static_cast<int>(GetLastError()), std::system_category(),
                "unable to map memory of backing file '"s + backing_filename + "'"s};
        }
    }

    // Determine memory mapping flags
    const DWORD protect = flags.read_only ? PAGE_READONLY : PAGE_READWRITE;
    DWORD access = FILE_MAP_READ;
    if (!flags.read_only) {
        access |= FILE_MAP_WRITE;
        if (!flags.shared) {
            access |= FILE_MAP_COPY;
        }
    }

    // Create memory mapping
    memory_mapping = CreateFileMappingA(memory_handle, nullptr, protect, static_cast<DWORD>(length >> 32),
        static_cast<DWORD>(length & 0xffffffff), nullptr);
    if (memory_mapping == nullptr) {
        throw std::system_error{static_cast<int>(GetLastError()), std::system_category(),
            "unable to create memory mapping"s};
    }

    // Map memory
    host_memory = MapViewOfFile(memory_mapping, access, 0, 0, length);
    if (host_memory == nullptr) {
        throw std::system_error{static_cast<int>(GetLastError()), std::system_category(), "unable to map memory"s};
    }

    // Copy contents from the backing file if needed
    if (backing_host_memory != nullptr && backing_file_length > 0) {
        std::memcpy(host_memory, backing_host_memory, backing_file_length);
    }

    // Commit state
    m_host_memory = host_memory;
    m_backing_sync_length = shared_write ? desired_backing_length : 0;
    m_memory_mapping = static_cast<void *>(memory_mapping);
    m_backing_host_memory = backing_host_memory;
    m_backing_mapping = backing_mapping;
    m_backing_fh = static_cast<void *>(backing_fh);

#else  // Fallback implementation using standard C APIs
    // Over-allocate to ensure we can align the pointer and store the original pointer.
    // Use calloc() instead of aligned_alloc() to initialize memory to zeros.
    std::size_t space = length + DEFAULT_MMAP_PAGE_SIZE - 1;
    void *unaligned_host_memory = std::calloc(1, space); // NOLINT(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    if (unaligned_host_memory == nullptr) {
        throw std::bad_alloc{};
    }

    // Automatically deallocate memory on failure
    auto memory_closer = scope_fail([&] {
        std::free(unaligned_host_memory); // NOLINT(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    });

    // Align allocated memory
    void *host_memory = unaligned_host_memory;
    if (std::align(DEFAULT_MMAP_PAGE_SIZE, length, host_memory, space) == nullptr) {
        throw std::runtime_error{"unable to align allocated memory"};
    }

    FILE *backing_fp = nullptr;

    // Automatically close backing file on failure
    auto backing_closer = scope_fail([&] {
        if (backing_fp != nullptr) {
            // Close backing file
            std::ignore = std::fclose(backing_fp);
        }
    });

    // Handle backing file if specified
    if (!backing_filename.empty()) {
        // Determine backing file open flags
        const char *mode{};
        if (shared_write) {
            mode = "r+b";
        } else {
            mode = "rb";
        }

        // Open backing file
        backing_fp = std::fopen(backing_filename.c_str(), mode);
        if (backing_fp == nullptr) {
            throw std::system_error{errno, std::generic_category(),
                "unable to open backing file '"s + backing_filename + "'"s};
        }

        // Get backing file size
        if (std::fseek(backing_fp, 0, SEEK_END) < 0) {
            throw std::system_error{errno, std::generic_category(),
                "unable to obtain length of backing file '"s + backing_filename + "'"s};
        }
        const auto file_size = std::ftell(backing_fp);
        if (file_size < 0) {
            throw std::system_error{errno, std::generic_category(),
                "unable to obtain length of backing file '"s + backing_filename + "'"s};
        }
        const auto backing_file_length = static_cast<uint64_t>(file_size);

        // Copy backing file contents
        if (std::fseek(backing_fp, 0, SEEK_SET) < 0) {
            throw std::system_error{errno, std::generic_category(),
                "unable to seek to beginning of backing file '"s + backing_filename + "'"s};
        }
        const auto copy_length = std::min(backing_file_length, desired_backing_length);
        if (static_cast<uint64_t>(std::fread(host_memory, 1, copy_length, backing_fp)) != copy_length) {
            throw std::system_error{errno, std::generic_category(),
                "unable to read from backing file '"s + backing_filename + "'"s};
        }

        // Check backing file length mismatch
        if (backing_file_length != desired_backing_length) {
            if (backing_file_length > desired_backing_length) {
                throw std::runtime_error{"backing file '"s + backing_filename + "' length ("s +
                    std::to_string(backing_file_length) + ") cannot be less than desired backing length ("s +
                    std::to_string(desired_backing_length) + ")"s};
            }
            if (flags.shared || !flags.backing_gap) {
                throw std::runtime_error{"backing file '"s + backing_filename + "' length ("s +
                    std::to_string(backing_file_length) + ") does not match desired backing length ("s +
                    std::to_string(desired_backing_length) + ")"s};
            }
            // Backing file length may be less than desired backing length,
            // but this is fine, as we are not sharing the file.
            // The gap between the file length and the memory length will be allocated as anonymous memory.
        }

        // Rewind the backing file to the beginning
        if (std::fseek(backing_fp, 0, SEEK_SET) < 0) {
            throw std::system_error{errno, std::generic_category(),
                "unable to rewind backing file '"s + backing_filename + "'"s};
        }
    }

    // Commit state
    m_host_memory = host_memory;
    m_backing_sync_length = shared_write ? desired_backing_length : 0;
    m_backing_fp = backing_fp;
    m_unaligned_host_memory = unaligned_host_memory;
#endif // HAVE_MMAP
}

mapped_memory::~mapped_memory() noexcept {
#ifdef HAVE_MMAP
    if (m_host_memory != nullptr && m_length > 0) {
        // Asynchronously flush mapped memory to disk to help prevent data loss
        if (m_backing_sync_length > 0) {
            std::ignore = msync(m_host_memory, m_backing_sync_length, MS_ASYNC);
        }
        std::ignore = munmap(m_host_memory, m_length);
    }
    if (m_backing_fd != -1) {
        // Closing a file will also release file locks
        while (close(m_backing_fd) != 0 && errno == EINTR) {
            // Interrupted by signal, retry
        };
    }

#elif defined(_WIN32) // Windows implementation
    // Flush changes to disk if necessary
    if (m_backing_sync_length > 0 && m_host_memory != nullptr) {
        // Asynchronously flush mapped memory to disk to help prevent data loss
        if (m_backing_host_memory != nullptr) {
            std::memcpy(m_backing_host_memory, m_host_memory, m_backing_sync_length);
            std::ignore = FlushViewOfFile(m_backing_host_memory, m_backing_sync_length);
        } else {
            std::ignore = FlushViewOfFile(m_host_memory, m_backing_sync_length);
        }
    }
    if (m_host_memory != nullptr) {
        std::ignore = UnmapViewOfFile(m_host_memory);
    }
    if (m_backing_host_memory != nullptr) {
        std::ignore = UnmapViewOfFile(m_backing_host_memory);
    }
    if (m_memory_mapping != nullptr) {
        std::ignore = CloseHandle(static_cast<HANDLE>(m_memory_mapping));
    }
    if (m_backing_mapping != nullptr) {
        std::ignore = CloseHandle(static_cast<HANDLE>(m_backing_mapping));
    }
    if (m_backing_fh != nullptr && m_backing_fh != INVALID_HANDLE_VALUE) {
        OVERLAPPED overlapped{};
        std::ignore = UnlockFileEx(static_cast<HANDLE>(m_backing_fh), 0, MAXDWORD, MAXDWORD, &overlapped);
        std::ignore = CloseHandle(static_cast<HANDLE>(m_backing_fh));
    }

#else // Fallback implementation using standard C APIs
    if (m_backing_sync_length > 0 && m_host_memory != nullptr && m_backing_fp != nullptr) {
        // Write back changes to backing file
        std::ignore = std::fwrite(m_host_memory, 1, m_backing_sync_length, m_backing_fp);
    }
    if (m_unaligned_host_memory != nullptr) {
        std::free(m_unaligned_host_memory); // NOLINT(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    }
    if (m_backing_fp != nullptr) {
        std::ignore = std::fclose(m_backing_fp);
    }

#endif // HAVE_MMAP
}

} // namespace cartesi::os
