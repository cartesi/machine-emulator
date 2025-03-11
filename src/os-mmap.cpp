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

#include <stdexcept>
#include <system_error>

#include "os-features.h"
#include "os-mmap.h"

//------------------------------------------------------------------------------

#if defined(HAVE_MMAP)
#include <fcntl.h>    // open
#include <sys/mman.h> // mmap/munmap
#include <sys/stat.h> // fstat
#include <unistd.h>   // write/read/close
#endif

#if defined(HAVE_FLOCK)
#include <sys/file.h> // flock
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <io.h>       // _write/_close
#include <sys/stat.h> // fstat
#include <windows.h>
#endif // _WIN32

namespace cartesi {

using namespace std::string_literals;

os_mmapd os_mmap(uint64_t length, const os_mmap_flags &flags, const std::string &backing_filename) {
    if (backing_filename.empty() && (flags.lock_backing || flags.shared)) {
        throw std::invalid_argument{"backing file must be specified"s};
    }

#ifdef HAVE_MMAP
    void *host_memory = nullptr;
    int backing_fd = -1;
    uint64_t backing_length = 0;
    uint64_t backing_mmap_length = 0;
    try {
        if (!backing_filename.empty()) {
            // Determine file open flags
            const bool writeable = flags.shared && !flags.read_only;
            int oflags = (writeable ? O_RDWR : O_RDONLY);
            oflags |= O_CLOEXEC; // to remove file locks on fork + exec

            // Open backing file
            backing_fd = open(backing_filename.c_str(), oflags);
            if (backing_fd < 0) {
                throw std::system_error{errno, std::generic_category(),
                    "could not open backing file '"s + backing_filename + "'"s};
            }

            // Get system page size
            const auto sc_page_size = sysconf(_SC_PAGESIZE);
            if (sc_page_size < 0) {
                throw std::system_error{errno, std::generic_category(), "unable to retrieve system page size"s};
            }
            const auto page_size = static_cast<uint64_t>(sc_page_size);

            // Get file size
            struct stat statbuf{};
            if (fstat(backing_fd, &statbuf) < 0) {
                throw std::system_error{errno, std::generic_category(),
                    "unable to obtain length of backing file '"s + backing_filename + "'"s};
            }
            backing_length = static_cast<uint64_t>(statbuf.st_size);

            // When backing file length mismatch the memory length we may need to truncate
            if (backing_length != length) {
                if (!flags.truncate) { // Can we truncate?
                    throw std::runtime_error{"backing file '"s + backing_filename + "' length ("s +
                        std::to_string(backing_length) + ") does not match range length ("s + std::to_string(length) +
                        ")"s};
                }
                if (flags.shared) { // Truncate backing file to match the desired length
                    if (ftruncate(backing_fd, static_cast<off_t>(length)) < 0) {
                        throw std::runtime_error{"unable to truncate backing file '"s + backing_filename +
                            "' length ("s + std::to_string(backing_length) + ") to range length ("s +
                            std::to_string(length) + ")"s};
                    }
                    backing_length = length;
                }
            }

            // Determine length of the backing file mmaped portion
            backing_mmap_length = (backing_length + (page_size - 1)) & ~(page_size - 1);

#ifdef HAVE_FLOCK
            // Set file lock
            if (flags.lock_backing) {
                const int flockop = (writeable ? LOCK_EX : LOCK_SH) | LOCK_NB;
                if (flock(backing_fd, flockop) < 0) {
                    throw std::system_error{errno, std::generic_category(),
                        "could not lock backing file '"s + backing_filename + "'"s};
                }
            }
#endif
        }

        // Determine map memory flags
        int mflags = flags.shared ? MAP_SHARED : MAP_PRIVATE;
        if (backing_fd < 0) { // The mapping is not backed by any file
            mflags |= MAP_ANONYMOUS;
        }

        // Determine map protection flags
        int mprot = PROT_READ;
        if (!flags.read_only) {
            mprot |= PROT_WRITE;
        }

        // Map memory
        if (backing_fd >= 0 && backing_mmap_length < length) { // Backing file smaller than range length
            host_memory = mmap(nullptr, length, mprot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (host_memory == MAP_FAILED) {
                throw std::system_error{errno, std::generic_category(), "could not map memory"s};
            }
            // Replace memory map related to backing file range
            void *backing_host_memory =
                mmap(host_memory, backing_mmap_length, mprot, mflags | MAP_FIXED, backing_fd, 0);
            if (backing_host_memory != host_memory) {
                throw std::system_error{errno, std::generic_category(),
                    "could not map backing file '"s + backing_filename + "' to memory"s};
            }
        } else { // No backing file or backing file with enough size
            host_memory = mmap(nullptr, length, mprot, mflags, backing_fd, 0);
            if (host_memory == MAP_FAILED) {
                if (backing_fd < 0) {
                    throw std::system_error{errno, std::generic_category(), "could not map memory"s};
                }
                throw std::system_error{errno, std::generic_category(),
                    "could not map backing file '"s + backing_filename + "' to memory"s};
            }
        }

        return os_mmapd{.host_memory = host_memory,
            .length = length,
            .flags = flags,
            .backing_fd = backing_fd,
            .backing_length = backing_length,
            .backing_filename = backing_filename};
    } catch (std::exception &e) {
        // Unmap host memory
        if (host_memory != nullptr) {
            munmap(host_memory, length);
        }
        // Close backing file
        if (backing_fd >= 0) {
            close(backing_fd);
        }
        throw;
    }

#elif defined(_WIN32)
#error "NYI"
    /*
    const int oflags = (shared ? _O_RDWR : _O_RDONLY) | _O_BINARY;

    // Try to open backing file
    const int backing_file = _open(path, oflags);
    if (backing_file < 0) {
        throw std::system_error{errno, std::generic_category(), "could not open backing file '"s + path + "'"s};
    }

    // Try to get file size
    struct __stat64 statbuf {};
    if (_fstat64(backing_file, &statbuf) < 0) {
        _close(backing_file);
        throw std::system_error{errno, std::generic_category(),
            "unable to obtain length of backing file '"s + path + "'"s};
    }

    // Check that it matches range length
    if (static_cast<uint64_t>(statbuf.st_size) != length) {
        _close(backing_file);
        throw std::invalid_argument{"backing file '"s + path + "' size ("s +
            std::to_string(static_cast<uint64_t>(statbuf.st_size)) + ") does not match range length ("s +
            std::to_string(length) + ")"s};
    }

    // Try to map backing file to host memory
    DWORD flProtect = shared ? PAGE_READWRITE : PAGE_READONLY;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    HANDLE hFile = reinterpret_cast<HANDLE>(_get_osfhandle(backing_file));
    HANDLE hFileMappingObject = CreateFileMapping(hFile, NULL, flProtect, length >> 32, length & 0xffffffff, NULL);
    if (!hFileMappingObject) {
        _close(backing_file);
        throw std::system_error{errno, std::generic_category(),
            "could not map backing file '"s + path + "' to memory"s};
    }

    DWORD dwDesiredAccess = shared ? FILE_MAP_WRITE : FILE_MAP_COPY;
    auto *host_memory = static_cast<unsigned char *>(MapViewOfFile(hFileMappingObject, dwDesiredAccess, 0, 0, length));
    if (!host_memory) {
        _close(backing_file);
        throw std::system_error{errno, std::generic_category(),
            "could not map backing file '"s + path + "' to memory"s};
    }

    // We can close the file after mapping it, because the OS will retain a reference of the file on its own
    _close(backing_file);
    return host_memory;
    */

#else
#error "NYI"
    /*
    if (shared) {
        throw std::runtime_error{"shared backing file mapping is unsupported"s};
    }

    auto fp = unique_fopen(path, "rb", std::nothrow_t{});
    if (!fp) {
        throw std::system_error{errno, std::generic_category(), "error opening backing file '"s + path + "'"s};
    }
    // Get file size
    if (fseek(fp.get(), 0, SEEK_END)) {
        throw std::system_error{errno, std::generic_category(),
            "error obtaining length of backing file '"s + path + "'"s};
    }
    auto backing_length = ftell(fp.get());
    if (fseek(fp.get(), 0, SEEK_SET)) {
        throw std::system_error{errno, std::generic_category(),
            "error obtaining length of backing file '"s + path + "'"s};
    }
    // Check against PMA range size
    if (static_cast<uint64_t>(backing_length) > length) {
        throw std::runtime_error{"backing file '"s + path + "' of "s + " is too large for range"s};
    }

    // use calloc to improve performance
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc, cppcoreguidelines-prefer-member-initializer)
    auto host_memory = static_cast<unsigned char *>(std::calloc(1, length));
    if (!host_memory) {
        throw std::runtime_error{"error allocating memory"s};
    }

    // Read to host memory
    auto read = fread(host_memory, 1, length, fp.get());
    (void) read;
    if (ferror(fp.get())) {
        throw std::system_error{errno, std::generic_category(), "error reading from backing file '"s + path + "'"s};
    }
    return host_memory;
    */

#endif // HAVE_MMAP
}

void os_munmap(const os_mmapd &mmapd) {
#ifdef HAVE_MMAP
    if (mmapd.host_memory != nullptr && mmapd.length > 0) {
        munmap(mmapd.host_memory, mmapd.length);
    }
    if (mmapd.backing_fd != -1) {
        // Closing a file will also release file locks
        close(mmapd.backing_fd);
    }

#elif defined(_WIN32)
    if (mmapd.host_memory != nullptr) {
        UnmapViewOfFile(mmapd.host_memory);
    }
    if (mmapd.backing_fd != -1) {
        _close(mmapd.backing_fd);
    }

#else
    if (mmapd.host_memory != nullptr) {
        std::free(mmapd.host_memory);
    }

#endif
}

} // namespace cartesi
