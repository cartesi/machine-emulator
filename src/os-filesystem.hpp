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

#ifndef OS_FILESYSTEM_HPP
#define OS_FILESYSTEM_HPP

#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace cartesi::os {

/// \brief Check if given path exists.
/// \param pathname Path to a file or directory.
/// \returns True if exists, false otherwise.
/// \throw std::system_error on error.
/// \details Symbolic links are followed.
[[nodiscard]] bool exists(const std::string &pathname);

/// \brief Get the length of a file.
/// \param filename Path to the file.
/// \returns Length of the file in bytes.
/// \throw std::system_error on error.
/// \details Symbolic links are followed.
[[nodiscard]] uint64_t file_size(const std::string &filename);

/// \brief Creates a new directory.
/// \param dirname Path to the directory, must not already exist.
/// \throw std::system_error on error.
void create_directory(const std::string &dirname);

/// \brief Removes a directory.
/// \param dirname Path to the directory, must exist.
/// \throw std::system_error on error.
void remove_directory(const std::string &dirname);

/// \brief Lists the entries of a directory.
/// \param dirname Path to the directory, must exist.
/// \returns Names of the entries, excluding "." and "..", in lexicographic order.
/// \throw std::system_error on error.
[[nodiscard]] std::vector<std::string> list_directory(const std::string &dirname);

/// \brief Renames a directory.
/// \param from Source directory, must exist.
/// \param to Destination directory, must not exist.
/// \throw std::system_error on error.
/// \details The operation fails when the directories are on different filesystems.
void rename_directory(const std::string &from, const std::string &to);

/// \brief Removes a file.
/// \param filename Path to the file, must exist.
/// \throw std::system_error on error.
void remove_file(const std::string &filename);

/// \brief Changes write permissions of a path.
/// \param pathname Path to the file or directory.
/// \param writable If true, makes the path writable, otherwise read-only.
/// \throw std::system_error on error.
/// \details Symbolic links are followed.
void change_writable(const std::string &pathname, bool writable);

/// \brief Truncates a file.
/// \param filename Path to the file.
/// \param size New size of the file.
/// \param create If true, creates the file if it does not exist.
/// \details The file is locked for exclusive writing during the operation.
void truncate_file(const std::string &filename, uint64_t size, bool create = false);

/// \brief Reads a file.
/// \param filename Path to the file, must exist.
/// \returns A pair containing a unique pointer to the data and a span to the data.
/// \throw std::system_error on error.
/// The file is locked for shared reading during the operation.
[[nodiscard]] std::pair<std::unique_ptr<uint8_t[]>, std::span<uint8_t>> read_file(const std::string &filename);

/// \brief Creates a new file and writes data to it.
/// \param filename Path to the file, must not already exist.
/// \param data A span containing the data to be written to the file.
/// \throw std::system_error on error.
/// \details File sparsity is preserved at 4KB granularity.
/// The file is locked for exclusive writing during the operation.
void create_file(const std::string &filename, std::span<const uint8_t> data);

/// \brief Copies a file.
/// \param from Path to the source file.
/// \param to Path to the destination file, must not already exist.
/// \param size Size of the destination file. If UINT64_MAX, the entire file is copied.
/// If the source file is smaller than size, the destination file is padded with zeros.
/// If the source file is larger than size, the destination file is truncated to size.
/// \details The sparsity of the original file is preserved at 4KB granularity.
/// The source file is locked for shared reading during the operation.
/// The destination file is locked for exclusive writing during the operation.
/// \throw std::system_error on error.
void copy_file(const std::string &from, const std::string &to, uint64_t size = UINT64_MAX);

/// \brief Creates a hard link to a file.
/// \param from Path to the source file.
/// \param to Path to the destination file, must not already exist.
/// \throw std::system_error on error.
/// \details This is only supported on some filesystems (e.g. EXT4).
/// Recommended for use with read-only files.
void hardlink_file(const std::string &from, const std::string &to);

/// \brief Creates a reference link to a file.
/// \param from Path to the source file.
/// \param to Path to the destination file, must not already exist.
/// \throw std::system_error on error.
/// \details This is only supported on copy-on-write filesystems (e.g. BTRFS or XFS).
/// The source file is locked for shared reading during the operation.
/// The destination file is locked for exclusive writing during the operation.
void reflink_file(const std::string &from, const std::string &to);

/// \brief Clones a file.
/// \param from Path to the source file.
/// \param to Path to the destination file, must not already exist.
/// \throw std::system_error on error.
/// \details If the original file is read-only, the new file is also read-only, and os::hardlink_file() is used.
/// If the original file is writable, the new file is also writable, and os::reflink_file() is used.
/// If neither os::hardlink_file() nor os::reflink_file() is supported, then os::copy_file() is used.
/// File sparsity is preserved for all cases.
/// The source file is locked for shared reading during the operation.
/// The destination file may be locked for exclusive writing during the operation.
void clone_file(const std::string &from, const std::string &to);

/// \brief Flushes all modifications of a file to permanent storage.
/// \param filename Path to the file, must exist.
/// \param lock Whether to lock the file for reading during the operation.
/// \throw std::system_error on error.
/// \details Without \p lock, the file may be locked by a running machine that maps it.
/// With \p lock, the operation fails if a running machine maps the file for writing,
/// where file locks are available.
void sync_file(const std::string &filename, bool lock = false);

/// \brief Creates a new directory with a unique name, accessible only by its owner on POSIX.
/// \param dirname Directory to create the directory in, must exist.
/// \param prefix Start of the directory name, which random characters complete.
/// \returns Path of the new directory. The caller must remove it.
/// \throw std::system_error on error.
[[nodiscard]] std::string create_temporary_directory(const std::string &dirname, const std::string &prefix);

/// \brief Creates a new file with a unique name, readable and writable only by its owner.
/// \param dirname Directory to create the file in, must exist.
/// \param prefix Start of the file name, which random characters complete.
/// \returns File opened for reading and writing, closed on exec, and the path of the new file.
/// \throw std::system_error on error.
[[nodiscard]] std::pair<FILE *, std::string> create_temporary_file(const std::string &dirname,
    const std::string &prefix);

/// \brief Flushes all modifications of an open file to permanent storage.
/// \param fd Open file descriptor.
/// \param pathname Path name for error messages.
/// \throw std::system_error on error.
void sync_file_descriptor(int fd, const std::string &pathname);

/// \brief Flushes all modifications of a directory entry list to permanent storage.
/// \param dirname Path to the directory, must exist.
/// \throw std::system_error on error.
/// \details On Windows this is a no-op, directory metadata durability is handled by the filesystem.
void sync_directory(const std::string &dirname);

/// \brief Reads a file to EOF without locking it, including files held open by a machine.
[[nodiscard]] std::string read_file_contents(const std::string &filename);

/// \brief Writes to an open stream, reporting write errors without flushing or closing it.
void write_file(FILE *file, const std::string &filename, std::span<const uint8_t> data);

/// \brief Writes a file, creating it or overwriting its contents, without locking or syncing it.
/// \details Reports errors from writing and closing the stream.
void write_file(const std::string &filename, std::span<const uint8_t> data);

/// \brief Renames a file, atomically replacing an existing destination.
void rename_file(const std::string &from, const std::string &to);

/// \brief Returns the parent directory, or "." for a path with no slash.
[[nodiscard]] std::string get_parent_directory(const std::string &path);

/// \brief Flushes a stream's write buffer and syncs its descriptor without closing it.
/// \details Rejects streams with a previous write error, even if flushing succeeds.
void sync_file_stream(FILE *file, const std::string &filename);

/// \brief Owns a temporary file and removes it on destruction unless renamed or released.
class temporary_file final {
public:
    temporary_file();
    temporary_file(const std::string &dirname, const std::string &prefix);
    ~temporary_file() noexcept;
    temporary_file(const temporary_file &) = delete;
    temporary_file &operator=(const temporary_file &) = delete;
    temporary_file(temporary_file &&) = delete;
    temporary_file &operator=(temporary_file &&) = delete;

    [[nodiscard]] FILE *get_file() const noexcept;
    [[nodiscard]] const std::string &get_path() const noexcept;
    void write(std::span<const uint8_t> data);
    /// \brief Closes the stream, reporting close errors. Does not remove the file.
    void close_stream();
    /// \brief Closes the stream and removes the file. Repeated calls are harmless.
    /// \details Like Lua's scoped cleanup, ignores stream close errors but reports removal errors.
    void close();
    /// \brief Closes the stream and renames the file, replacing the destination.
    void rename(const std::string &to);
    /// \brief Closes the stream and transfers ownership of the path to the caller.
    [[nodiscard]] std::string release();

private:
    explicit temporary_file(std::pair<FILE *, std::string> result) noexcept;
    FILE *m_file = nullptr;
    std::string m_path;
};

/// \brief Creates an empty temporary file and returns its name. The caller must remove it.
[[nodiscard]] std::string temp_filename();

/// \brief Writes and closes a temporary file. The caller must remove the returned path.
[[nodiscard]] std::string write_temp_file(std::span<const uint8_t> data);

/// \brief Writes through a temporary file, syncs it, and renames it onto the destination.
/// \details The caller must sync the parent directory to make the rename durable.
void write_durable_file(const std::string &filename, std::span<const uint8_t> data);

} // namespace cartesi::os

#endif // OS_FILESYSTEM_HPP
