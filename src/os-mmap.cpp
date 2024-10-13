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

#include <system_error>

#include "os-features.h"
#include "os-mmap.h"
#include "unique-c-ptr.h"

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

os_mmapd os_mmap(uint64_t length, int flags, const std::string &backing_filename) {
    if (backing_filename.empty() && (flags & (OS_MMAP_LOCKBACKING | OS_MMAP_SHARED | OS_MMAP_READONLY))) {
        throw std::runtime_error{"backing file path must be specified"s};
    }

#ifdef HAVE_MMAP
    unsigned char *host_memory = nullptr;
    int backing_fd = -1;
    uint64_t backing_length = 0;
    try {
        if (!backing_filename.empty()) {
            // Determine file open flags
            const bool writeable = (flags & OS_MMAP_SHARED) && !(flags & OS_MMAP_READONLY);
            int oflags = (writeable ? O_RDWR : O_RDONLY);
            oflags |= O_CLOEXEC; // to remove file locks on fork + exec

            // Try to open backing file
            backing_fd = open(backing_filename.c_str(), oflags);
            if (backing_fd < 0) {
                throw std::system_error{errno, std::generic_category(),
                    "could not open backing file '"s + backing_filename + "'"s};
            }

            // Try to get file size
            struct stat statbuf {};
            if (fstat(backing_fd, &statbuf) < 0) {
                throw std::system_error{errno, std::generic_category(),
                    "unable to obtain length of backing file '"s + backing_filename + "'"s};
            }
            backing_length = static_cast<uint64_t>(statbuf.st_size);

            // Check file length for shared mappings
            if ((flags & OS_MMAP_SHARED) && backing_length != length) {
                throw std::invalid_argument{"backing file '"s + backing_filename + "' size ("s +
                    std::to_string(backing_length) + ") does not match range length ("s + std::to_string(length) +
                    ")"s};
            }

#ifdef HAVE_FLOCK
            // Set file lock
            if (flags & OS_MMAP_LOCKBACKING) {
                const int flockop = (writeable ? LOCK_EX : LOCK_SH) | LOCK_NB;
                if (flock(backing_fd, flockop) < 0) {
                    throw std::system_error{errno, std::generic_category(),
                        "could not lock backing file '"s + backing_filename + "'"s};
                }
            }
#endif
        }

        // Determine map memory flags
        int mflags = (flags & OS_MMAP_SHARED) ? MAP_SHARED : MAP_PRIVATE;
        if (backing_fd < 0) { // The mapping is not backed by any file
            mflags |= MAP_ANONYMOUS;
        }
        if (flags & OS_MMAP_NORESERVE) {
            mflags |= MAP_NORESERVE;
        }
        // Determine map protection flags
        int mprot = PROT_READ;
        if (!(flags & OS_MMAP_READONLY)) {
            mprot |= PROT_WRITE;
        }

        // Try to map backing file to host memory
        host_memory = static_cast<unsigned char *>(mmap(nullptr, length, mprot, mflags, backing_fd, 0));
        if (host_memory == MAP_FAILED) {
            if (!backing_filename.empty()) {
                throw std::system_error{errno, std::generic_category(),
                    "could not map backing file '"s + backing_filename + "' to memory"s};
            } else {
                throw std::system_error{errno, std::generic_category(), "could not map memory"s};
            }
        }

        if (backing_fd >= 0) {
            // Retrieve system page size
            const long page_size = sysconf(_SC_PAGESIZE);
            if (page_size < 0) {
                throw std::system_error{errno, std::generic_category(), "unable to retrieve system page size"s};
            }
            // Determine length of the backing file based
            const uint64_t backing_mmaped_length = (backing_length + (page_size - 1)) & ~(page_size - 1);

            if (backing_mmaped_length < length) {
                unsigned char *
                    above_memory = // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
                    reinterpret_cast<unsigned char *>(reinterpret_cast<uintptr_t>(host_memory) + backing_mmaped_length);
                const uint64_t above_length = length - backing_mmaped_length;
                int above_mflags = MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;
                if (flags & OS_MMAP_NORESERVE) {
                    above_mflags |= MAP_NORESERVE;
                }

                // Overwrite mapping
                auto *got_above_memory =
                    static_cast<unsigned char *>(mmap(above_memory, above_length, mprot, above_mflags, -1, 0));
                if (got_above_memory != above_memory) {
                    throw std::system_error{errno, std::generic_category(),
                        "could not map memory space above backing file"s};
                }
            }
        }

        return os_mmapd{host_memory, length, flags, backing_fd, backing_length, backing_filename};
    } catch (std::exception &e) {
        // Close backing file
        if (backing_fd >= 0) {
            close(backing_fd);
        }
        // Unmap host memory
        if (host_memory) {
            munmap(host_memory, length);
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
