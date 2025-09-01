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

#ifndef OS_FILESYSTEM_H
#define OS_FILESYSTEM_H

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>

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

} // namespace cartesi::os

#endif // OS_FILESYSTEM_H
