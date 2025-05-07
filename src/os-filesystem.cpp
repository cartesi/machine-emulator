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
#include "os-posix-compat.h"

#include <fcntl.h>    // open
#include <sys/stat.h> // stat/fstat/mkdir/fchmod
#include <unistd.h>   // unlink/rmdir/close/ftruncate/pread/pwrite

#include "os-filesystem.h"

#include "address-range-constants.h"
#include "is-pristine.h"
#include "scope-exit.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <span>
#include <sstream>
#include <system_error>
#include <tuple>
#include <utility>

#ifdef HAVE_FLOCK
#include <sys/file.h> // flock
#endif

#ifdef HAVE_CLONEFILE
#include <sys/clonefile.h> // clonefile
#endif

#ifdef HAVE_FICLONE
#include <sys/ioctl.h> // ioctl
#ifndef FICLONE
#define FICLONE _IOW(0x94, 9, int)
#endif
#endif

namespace cartesi::os {

constexpr auto S_WRITE_ALL = S_IWUSR | S_IWGRP | S_IWOTH;
constexpr auto S_CREATE_DIRECTORY = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
constexpr auto S_CREATE_FILE = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
constexpr auto S_ACCESS_ALL = S_IRWXU | S_IRWXG | S_IRWXO;

using namespace std::string_literals;

/// \brief Retry a function call on EINTR error.
/// \param func Function to be retried.
/// \details Some POSIX functions may be interrupted by external signal handlers,
/// this helper ensures that the function is retried until it succeeds or fails with a different error.
template <typename F>
static constexpr auto retry_on_eintr(const F &func) {
    while (true) {
        auto result = func();
        if (!(result == -1 && errno == EINTR)) {
            return result;
        }
    }
}

/// \brief Rethrow system error with additional path name context.
/// \param e Original system error.
/// \param description Description of the error.
/// \param pathname Path name.
/// \param operation Operation that failed.
static inline std::system_error make_path_system_error(int errno_code, const std::string &description,
    const std::string &pathname, const std::string &operation = {}) {
    std::ostringstream sout;
    sout << description << " '"s << pathname << "'"s;
    if (!operation.empty()) {
        sout << ": "s << operation;
    }
    return std::system_error{errno_code, std::generic_category(), sout.str()};
}

/// \brief Rethrow system error with additional path name contexts.
/// \param e Original system error.
/// \param description Description of the error.
/// \param from From path name.
/// \param to To path name.
/// \param operation Operation that failed.
static inline std::system_error make_copy_path_system_error(int errno_code, const std::string &description,
    const std::string &from, const std::string &to, const std::string &operation = {}) {
    std::ostringstream sout;
    sout << description << " from '"s << from << "' to '"s << to << "'"s;
    if (!operation.empty()) {
        sout << ": "s << operation;
    }
    return std::system_error{errno_code, std::generic_category(), sout.str()};
}

bool exists(const std::string &pathname) {
    struct stat st{};
    if (stat(pathname.c_str(), &st) == 0) { // Exists
        return true;
    }
    if (errno == ENOENT) { // Does not exist
        return false;
    }
    throw make_path_system_error(errno, "unable to check existence of path"s, pathname);
}

uint64_t file_size(const std::string &filename) {
    struct stat st{};
    if (stat(filename.c_str(), &st) != 0) {
        throw make_path_system_error(errno, "unable to get size of file"s, filename);
    }
    if (S_ISDIR(st.st_mode)) { // Not a file
        throw make_path_system_error(EISDIR, "unable to get size of file"s, filename);
    }
    return static_cast<uint64_t>(st.st_size);
}

void create_directory(const std::string &dirname) {
    if (mkdir(dirname.c_str(), S_CREATE_DIRECTORY) != 0) {
        throw make_path_system_error(errno, "unable to create directory"s, dirname);
    }
}

void remove_directory(const std::string &dirname) {
    if (rmdir(dirname.c_str()) != 0) {
        throw make_path_system_error(errno, "unable to remove directory"s, dirname);
    }
}

void remove_file(const std::string &filename) {
    if (unlink(filename.c_str()) != 0) {
        throw make_path_system_error(errno, "unable to remove file"s, filename);
    }
}

void change_writable(const std::string &pathname, bool writable) {
    // Open the path
    const auto fd = open(pathname.c_str(), O_RDONLY | O_BINARY); // NOLINT(misc-redundant-expression)
    if (fd < 0) {
        throw make_path_system_error(errno, "unable to change write perms of path"s, pathname, "open() failed"s);
    }
    auto failure_close = scope_fail([&] { std::ignore = retry_on_eintr([&] { return close(fd); }); });

    // Get permissions
    struct stat st{};
    if (fstat(fd, &st) != 0) {
        throw make_path_system_error(errno, "unable to change write perms of path"s, pathname, "stat() failed"s);
    }

    // Remove write permissions
    auto new_mode = (st.st_mode & ~S_WRITE_ALL);

    // Add write permissions for user, group and others if read permissions are set
    if (writable) {
        if ((st.st_mode & S_IRUSR) != 0) {
            new_mode |= S_IWUSR;
        }
        if ((st.st_mode & S_IRGRP) != 0) {
            new_mode |= S_IWGRP;
        }
        if ((st.st_mode & S_IROTH) != 0) {
            new_mode |= S_IWOTH;
        }
    }

    // Change permissions
    if (new_mode != st.st_mode && fchmod(fd, new_mode) != 0) {
        throw make_path_system_error(errno, "unable to change write perms of path"s, pathname, "chmod() failed"s);
    }

    // Ensure the path is closed gracefully
    failure_close.release();
    if (retry_on_eintr([&] { return close(fd); }) != 0) {
        throw make_path_system_error(errno, "unable to change write perms of path"s, pathname, "close() failed"s);
    }
}

void truncate_file(const std::string &filename, uint64_t size, bool create) {
    // Determine flags based on whether we should create the file
    const int flags = O_WRONLY | O_BINARY | (create ? (O_CREAT | O_EXCL) : 0); // NOLINT(misc-redundant-expression)
    const mode_t mode = create ? S_CREATE_FILE : 0;

    // Open the file
    const auto fd = open(filename.c_str(), flags, mode);
    if (fd < 0) {
        throw make_path_system_error(errno, "unable to truncate file"s, filename, "open() failed"s);
    }
    auto failure_unlink = scope_fail([&] {
        if (create) {
            std::ignore = unlink(filename.c_str());
        }
    });
    auto failure_close = scope_fail([&] { std::ignore = retry_on_eintr([&] { return close(fd); }); });

#ifdef HAVE_FLOCK
    // Lock file immediately for writing
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        throw make_path_system_error(errno, "unable to truncate file"s, filename, "flock() failed"s);
    }
#endif

    // Truncate file size
    if (retry_on_eintr([&] { return ftruncate(fd, static_cast<off_t>(size)); }) != 0) {
        throw make_path_system_error(errno, "unable to truncate file"s, filename, "ftruncate() failed"s);
    }

    // Ensure the file is closed gracefully
    failure_close.release();
    if (retry_on_eintr([&] { return close(fd); }) != 0) {
        throw make_path_system_error(errno, "unable to truncate file"s, filename, "close() failed"s);
    }
}

std::pair<std::unique_ptr<uint8_t[]>, std::span<uint8_t>> read_file(const std::string &filename) {
    // Open file
    const auto fd = open(filename.c_str(), O_RDONLY | O_BINARY); // NOLINT(misc-redundant-expression)
    if (fd < 0) {
        throw make_path_system_error(errno, "unable to read file"s, filename, "open() failed"s);
    }
    auto cleanup = scope_exit([&] { std::ignore = retry_on_eintr([&] { return close(fd); }); });

#ifdef HAVE_FLOCK
    // Lock file imediatelly for reading
    if (flock(fd, LOCK_SH | LOCK_NB) != 0) {
        throw make_path_system_error(errno, "unable to read file"s, filename, "flock() failed");
    }
#endif

    // Get file size
    struct stat st{};
    if (fstat(fd, &st) != 0) {
        throw make_path_system_error(errno, "unable to read file"s, filename, "fstat() failed"s);
    }
    const auto size = static_cast<size_t>(st.st_size);

    // Check if file is empty
    if (size == 0) {
        return {};
    }

    // Allocate data
    auto data = std::make_unique<uint8_t[]>(size);

    // Read data
    size_t offset = 0;
    while (offset < size) {
        const auto bytes_read =
            retry_on_eintr([&] { return pread(fd, data.get() + offset, size - offset, static_cast<off_t>(offset)); });
        if (bytes_read < 0) {
            throw make_path_system_error(errno, "unable to read file"s, filename, "pread() failed"s);
        }
        if (bytes_read == 0) {
            throw make_path_system_error(ERANGE, "unable to read file"s, filename, "pread() read 0 bytes"s);
        }
        offset += static_cast<size_t>(bytes_read);
    }

    return {std::move(data), std::span<uint8_t>{data.get(), size}};
}

void create_file(const std::string &filename, std::span<const uint8_t> data) {
    // Create file
    const auto fd = open(filename.c_str(), O_WRONLY | O_BINARY | O_CREAT | O_EXCL,
        S_CREATE_FILE); // NOLINT(misc-redundant-expression)
    if (fd < 0) {
        throw make_path_system_error(errno, "unable to create file"s, filename, "open() failed"s);
    }
    auto failure_unlink = scope_fail([&] { std::ignore = unlink(filename.c_str()); });
    auto failure_close = scope_fail([&] { std::ignore = retry_on_eintr([&] { return close(fd); }); });

#ifdef HAVE_FLOCK
    // Lock file immediately for writing
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        throw make_path_system_error(errno, "unable to create file"s, filename, "flock() failed"s);
    }
#endif

    // Truncate file size
    if (retry_on_eintr([&] { return ftruncate(fd, static_cast<off_t>(data.size())); }) != 0) {
        throw make_path_system_error(errno, "unable to create file"s, filename, "ftruncate() failed"s);
    }

    // Write data keeping file sparsity
    size_t offset = 0;
    while (offset < data.size()) {
        auto bytes_to_write = std::min<size_t>(AR_PAGE_SIZE, data.size() - offset);
        // Only write non-sparse blocks
        if (!is_pristine(std::span<const unsigned char>{data.data() + offset, bytes_to_write})) {
            const auto bytes_written = retry_on_eintr(
                [&] { return pwrite(fd, data.data() + offset, bytes_to_write, static_cast<off_t>(offset)); });
            if (bytes_written < 0) {
                throw make_path_system_error(errno, "unable to create file"s, filename, "pwrite() failed"s);
            }
            if (bytes_written == 0) {
                throw make_path_system_error(EIO, "unable to create file"s, filename, "pwrite() wrote 0 bytes"s);
            }
            offset += static_cast<size_t>(bytes_written);
        } else {
            offset += bytes_to_write;
        }
    }

    // Ensure the file is closed gracefully
    failure_close.release();
    if (retry_on_eintr([&] { return close(fd); }) != 0) {
        throw make_path_system_error(errno, "unable to create file"s, filename, "close() failed"s);
    }
}

void copy_file(const std::string &from, const std::string &to, uint64_t size) {
    // Open source file
    const auto from_fd = open(from.c_str(), O_RDONLY | O_BINARY); // NOLINT(misc-redundant-expression)
    if (from_fd < 0) {
        throw make_copy_path_system_error(errno, "unable to copy file"s, from, to, "open() failed"s);
    }
    auto cleanup_from = scope_exit([&] { std::ignore = retry_on_eintr([&] { return close(from_fd); }); });

#ifdef HAVE_FLOCK
    // Lock source file immediately for reading
    if (flock(from_fd, LOCK_SH | LOCK_NB) != 0) {
        throw make_copy_path_system_error(errno, "unable to copy file"s, from, to, "flock() failed"s);
    }
#endif

    // Get source file permissions and size
    struct stat st{};
    if (fstat(from_fd, &st) != 0) {
        throw make_copy_path_system_error(errno, "unable to copy file"s, from, to, "fstat() failed"s);
    }

    // Determine actual copy size
    if (size == UINT64_MAX) {
        size = static_cast<uint64_t>(st.st_size);
    }
    const size_t copy_size = std::min<size_t>(st.st_size, size);

    // Create destination file
    const auto to_fd = open(to.c_str(), O_WRONLY | O_BINARY | O_CREAT | O_EXCL,
        st.st_mode & S_ACCESS_ALL); // NOLINT(misc-redundant-expression)
    if (to_fd < 0) {
        throw make_copy_path_system_error(errno, "unable to copy file"s, from, to, "open() failed"s);
    }
    auto failure_unlink_to = scope_fail([&] { std::ignore = unlink(to.c_str()); });
    auto failure_close_to = scope_fail([&] { std::ignore = retry_on_eintr([&] { return close(to_fd); }); });

#ifdef HAVE_FLOCK
    // Lock destination file immediately for writing
    if (flock(to_fd, LOCK_EX | LOCK_NB) != 0) {
        throw make_copy_path_system_error(errno, "unable to copy file"s, from, to, "flock() failed"s);
    }
#endif

    // Truncate destination file size
    if (retry_on_eintr([&] { return ftruncate(to_fd, static_cast<off_t>(size)); }) != 0) {
        throw make_copy_path_system_error(errno, "unable to copy file"s, from, to, "ftruncate() failed"s);
    }

    // 16-byte aligned buffer for efficient pristine page checks during file copy
    alignas(16) std::array<uint8_t, AR_PAGE_SIZE> buffer{};

    // Copy data keeping file sparsity
    size_t offset = 0;
    while (offset < copy_size) {
        const auto bytes_to_read = std::min<size_t>(buffer.size(), copy_size - offset);

        // Read data from source
        const auto bytes_read =
            retry_on_eintr([&] { return pread(from_fd, buffer.data(), bytes_to_read, static_cast<off_t>(offset)); });
        if (bytes_read < 0) {
            throw make_copy_path_system_error(errno, "unable to copy file"s, from, to, "pread() failed"s);
        }
        if (bytes_read == 0) {
            throw make_copy_path_system_error(EIO, "unable to copy file"s, from, to, "pread() read 0 bytes"s);
        }

        // Write only non-sparse blocks to destination
        if (!is_pristine(std::span<const unsigned char>{buffer.data(), static_cast<size_t>(bytes_read)})) {
            const auto bytes_written =
                retry_on_eintr([&] { return pwrite(to_fd, buffer.data(), bytes_read, static_cast<off_t>(offset)); });
            if (bytes_written < 0) {
                throw make_copy_path_system_error(errno, "unable to copy file"s, from, to, "pwrite() failed"s);
            }
            if (bytes_written == 0) {
                throw make_copy_path_system_error(EIO, "unable to copy file"s, from, to, "pwrite() wrote 0 bytes"s);
            }
            offset += static_cast<size_t>(bytes_written);
        } else {
            offset += bytes_read;
        }

        // Attempt to advance the offset to the next data block if SEEK_DATA is supported.
        // This efficiently skips over holes in sparse files (supported on Linux, not on macOS).
#ifdef SEEK_DATA
        auto next_offset = lseek(from_fd, static_cast<off_t>(offset), SEEK_DATA);
        if (next_offset == -1) {
            if (errno == ENXIO) { // End of file, or within a hole at the end of the file
                break;
            }
            if (errno == EINVAL || errno == ENOTSUP) { // SEEK_DATA is not supported
                continue;
            }
            throw make_copy_path_system_error(errno, "unable to copy file"s, from, to, "lseek() failed"s);
        }
        offset = static_cast<size_t>(next_offset);
#endif
    }

    // Ensure destination file is closed gracefully
    failure_close_to.release();
    if (retry_on_eintr([&] { return close(to_fd); }) != 0) {
        throw make_copy_path_system_error(errno, "unable to copy file"s, from, to, "close() failed"s);
    }
}

void hardlink_file(const std::string &from, const std::string &to) {
    if (link(from.c_str(), to.c_str()) != 0) {
        throw make_copy_path_system_error(errno, "unable to create hard link"s, from, to);
    }
}

void reflink_file(const std::string &from, const std::string &to) {
#if defined(HAVE_FICLONE) // Linux
    // Open source file
    const auto from_fd = open(from.c_str(), O_RDONLY | O_BINARY); // NOLINT(misc-redundant-expression)
    if (from_fd < 0) {
        throw make_copy_path_system_error(errno, "unable to create reference link"s, from, to, "open() failed"s);
    }
    auto cleanup_from = scope_exit([&] { std::ignore = retry_on_eintr([&] { return close(from_fd); }); });

#ifdef HAVE_FLOCK
    // Lock source file immediately for reading
    if (flock(from_fd, LOCK_SH | LOCK_NB) != 0) {
        throw make_copy_path_system_error(errno, "unable to create reference link"s, from, to, "flock() failed"s);
    }
#endif

    // Get source file permissions
    struct stat st{};
    if (fstat(from_fd, &st) != 0) {
        throw make_copy_path_system_error(errno, "unable to create reference link"s, from, to, "fstat() failed"s);
    }

    // Create destination file
    const auto to_fd = open(to.c_str(), O_WRONLY | O_BINARY | O_CREAT | O_EXCL,
        st.st_mode & ACCESSPERMS); // NOLINT(misc-redundant-expression)
    if (to_fd < 0) {
        throw make_copy_path_system_error(errno, "unable to create reference link"s, from, to, "open() failed"s);
    }
    auto failure_unlink = scope_fail([&] { std::ignore = unlink(to.c_str()); });
    auto failure_close = scope_fail([&] { std::ignore = retry_on_eintr([&] { return close(to_fd); }); });

#ifdef HAVE_FLOCK
    // Lock destination file immediately for writing
    if (flock(to_fd, LOCK_EX | LOCK_NB) != 0) {
        throw make_copy_path_system_error(errno, "unable to create reference link"s, from, to, "flock() failed"s);
    }
#endif

    // Clone the file
    if (ioctl(to_fd, FICLONE, from_fd) != 0) {
        throw make_copy_path_system_error(errno, "unable to create reference link"s, from, to,
            "FICLONE ioctl() failed"s);
    }

    // Ensure the file is closed gracefully
    failure_close.release();
    if (retry_on_eintr([&] { return close(to_fd); }) != 0) {
        throw make_copy_path_system_error(errno, "unable to create reference link"s, from, to, "close() failed"s);
    }
#elif defined(HAVE_CLONEFILE) // macOS
    if (clonefile(from.c_str(), to.c_str(), 0) != 0) {
        throw make_copy_path_system_error(errno, "unable to create reference link"s, from, to, "clonefile() failed"s);
    }
#else
    throw make_copy_path_system_error(ENOTSUP, "unable to create reference link"s, from, to);
#endif
}

void clone_file(const std::string &from, const std::string &to) {
    // Open source file
    const auto from_fd = open(from.c_str(), O_RDONLY | O_BINARY); // NOLINT(misc-redundant-expression)
    if (from_fd < 0) {
        throw make_copy_path_system_error(errno, "unable to clone file"s, from, to, "open() failed"s);
    }
    auto cleanup_from = scope_exit([&] { std::ignore = retry_on_eintr([&] { return close(from_fd); }); });

#ifdef HAVE_FLOCK
    // Lock source file immediately for reading
    if (flock(from_fd, LOCK_SH | LOCK_NB) != 0) {
        throw make_copy_path_system_error(errno, "unable to clone file"s, from, to, "flock() failed"s);
    }
#endif

    // Check if source file exists and get its permissions
    struct stat st{};
    if (fstat(from_fd, &st) != 0) {
        throw make_copy_path_system_error(errno, "unable to clone file"s, from, to, "stat() failed"s);
    }
    if (S_ISDIR(st.st_mode)) { // Not a file
        throw make_copy_path_system_error(EISDIR, "unable to clone file"s, from, to);
    }

    // Attempt to link the file, otherwise fall back to copy
    try {
        if ((st.st_mode & S_WRITE_ALL) != 0) {
            reflink_file(from, to);
        } else {
            hardlink_file(from, to);
        }
    } catch (const std::system_error &e) {
        if (e.code().value() == ENOTSUP || // Operation not supported
            e.code().value() == EXDEV ||   // Not on the same mounted filesystem
            e.code().value() == EPERM      // Can happen if the filesystem does not support hard link
        ) {
            // Fall back to regular copy
            copy_file(from, to, UINT64_MAX);
        } else {
            // Error is not related to platform support, rethrow
            throw;
        }
    }
}

} // namespace cartesi::os
