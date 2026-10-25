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

#ifndef CARTESI_MACHINE_FILESYSTEM_H // NOLINTBEGIN
#define CARTESI_MACHINE_FILESYSTEM_H

#include "cm.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

// -----------------------------------------------------------------------------
// Filesystem API functions
// -----------------------------------------------------------------------------

/// \brief Checks if a path exists, following symbolic links.
/// \param path Path to a file or directory.
/// \param exists Receives true if the path exists, false otherwise. Set to false on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_exists(const char *path, bool *exists);

/// \brief Creates a new directory.
/// \param path Path to the directory, must not already exist.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_create_directory(const char *path);

/// \brief Lists the entries of a directory, excluding "." and "..", in lexicographic order.
/// \param path Path to the directory, must exist.
/// \param names Receives a JSON array of Base64-encoded entry names in a string, guaranteed to remain valid only
/// until the next CM_API function is called from the same thread. Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
/// \details Base64 preserves filename bytes that are not valid UTF-8. The returned string must not be changed
/// nor deallocated. Ordering is by the original names, before encoding.
CM_API cm_error cm_filesystem_list_directory(const char *path, const char **names);

/// \brief Clones a file into a new path.
/// \param from Path to the source file, must exist.
/// \param to Path to the destination file, must not already exist.
/// \returns 0 for success, non zero code for error.
/// \details Uses a hard link if the source is read-only, or a reflink if writable, falling back to a copy.
/// Symbolic links are followed. A read-only source produces a read-only destination.
CM_API cm_error cm_filesystem_clone_file(const char *from, const char *to);

/// \brief Truncates or extends a file, filling an extension with zeros.
/// \param path Path to the file, must exist.
/// \param size New size of the file in bytes.
/// \returns 0 for success, non zero code for error.
/// \details The file is locked for exclusive writing during the operation.
CM_API cm_error cm_filesystem_truncate_file(const char *path, uint64_t size);

/// \brief Creates a new directory with a unique name, accessible only by its owner on POSIX.
/// \param dirname Directory to create the directory in, must exist.
/// \param prefix Start of the directory name, which random characters complete.
/// \param path Receives a borrowed path, valid until the next CM_API call on this thread. NULL on failure.
/// \returns 0 for success, non zero code for error.
/// \details The caller must remove the directory. Copy the returned path before making another CM_API call.
CM_API cm_error cm_filesystem_create_temporary_directory(const char *dirname, const char *prefix, const char **path);

/// \brief Creates a new file with a unique name, readable and writable only by its owner.
/// \param dirname Directory to create the file in, must exist.
/// \param prefix Start of the file name, which random characters complete.
/// \param file Receives a stream opened for reading and writing, closed on exec. Set to NULL on failure.
/// \param path Receives the path of the new file, guaranteed to remain valid only until the next CM_API function
/// is called from the same thread. Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
/// \details The caller owns the stream and must close it with fclose(). Closing the stream does not remove the file.
/// The returned path must not be changed nor deallocated; copy it before making another CM_API call if needed.
CM_API cm_error cm_filesystem_create_temporary_file(const char *dirname, const char *prefix, FILE **file,
    const char **path);

/// \brief Flushes all modifications of a file to permanent storage.
/// \param path Path to the file, must exist.
/// \returns 0 for success, non zero code for error.
/// \details The file is deliberately not locked, so it may be locked by a running machine that maps it.
CM_API cm_error cm_filesystem_sync_file(const char *path);

/// \brief Flushes all modifications of an open file to permanent storage.
/// \param fd Open file descriptor. Ownership remains with the caller.
/// \param path Path name for error messages.
/// \returns 0 for success, non zero code for error.
/// \details The caller must flush any userspace write buffers first. The descriptor is not closed by this function.
CM_API cm_error cm_filesystem_sync_file_descriptor(int fd, const char *path);

/// \brief Flushes all modifications of a directory entry list to permanent storage.
/// \param path Path to the directory, must exist.
/// \returns 0 for success, non zero code for error.
/// \details On Windows this is a no-op, directory metadata durability is handled by the filesystem.
CM_API cm_error cm_filesystem_sync_directory(const char *path);

/// \brief Reads a file to EOF without locking it.
/// \param path Path to the file.
/// \param data Receives borrowed binary data, valid until the next CM_API call on this thread. NULL on failure.
/// \param length Receives the byte length, including embedded zero bytes. Zero on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_read_file(const char *path, const uint8_t **data, uint64_t *length);

/// \brief Writes data to a file, creating it or overwriting it, without locking or syncing it.
/// \param path Destination path.
/// \param data Input bytes; may be NULL only when length is zero.
/// \param length Number of input bytes.
/// \returns 0 for success, non zero code for error. Includes errors detected when closing the file.
CM_API cm_error cm_filesystem_write_file(const char *path, const uint8_t *data, uint64_t length);

/// \brief Writes data through a temporary file, syncs it, and renames it onto the destination.
/// \param path Destination path.
/// \param data Input bytes; may be NULL only when length is zero.
/// \param length Number of input bytes.
/// \returns 0 for success, non zero code for error.
/// \details The caller must sync the parent directory to make the rename durable.
CM_API cm_error cm_filesystem_write_durable_file(const char *path, const uint8_t *data, uint64_t length);

/// \brief Removes a file. Returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_remove_file(const char *path);

/// \brief Removes an empty directory. Returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_remove_directory(const char *path);

/// \brief Renames a file, atomically replacing the destination. Returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_rename_file(const char *from, const char *to);

/// \brief Gets a file's size, following symbolic links. Sets size to zero on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_get_file_size(const char *path, uint64_t *size);

/// \brief Gets the parent directory, or "." for a path with no slash.
/// \param path Input path.
/// \param parent Receives a borrowed string, valid until the next CM_API call on this thread. NULL on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_get_parent_directory(const char *path, const char **parent);

/// \brief Creates an empty temporary file. The caller must remove it.
/// \param path Receives a borrowed path, valid until the next CM_API call on this thread. NULL on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_temp_filename(const char **path);

/// \brief Writes and closes a temporary file. The caller must remove it.
/// \param data Input bytes; may be NULL only when length is zero.
/// \param length Number of input bytes.
/// \param path Receives a borrowed path, valid until the next CM_API call on this thread. NULL on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_write_temp_file(const uint8_t *data, uint64_t length, const char **path);

/// \brief Flushes a stream's write buffer and syncs its descriptor without closing it.
/// \details Rejects streams with a previous write error. The caller retains ownership of the stream.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_sync_file_stream(FILE *file, const char *path);

// -----------------------------------------------------------------------------
// Owned temporary files
// -----------------------------------------------------------------------------

typedef struct cm_filesystem_temporary_file cm_filesystem_temporary_file;

/// \brief Creates an owned temporary file. Delete it with cm_filesystem_delete_temporary_file().
/// \param dirname Directory in which to create the file.
/// \param prefix Start of the file name, which random characters complete.
/// \param file Receives the new owner. NULL on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_new_temporary_file(const char *dirname, const char *prefix,
    cm_filesystem_temporary_file **file);

/// \brief Writes and closes an owned temporary file. Deleting the owner removes its path.
/// \param data Input bytes; may be NULL only when length is zero.
/// \param length Number of input bytes.
/// \param file Receives the new owner. NULL on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_write_scope_temp_file(const uint8_t *data, uint64_t length,
    cm_filesystem_temporary_file **file);

/// \brief Obtains the owner's borrowed stream, or NULL if closed. NULL on failure.
/// \details Do not fclose() this stream; use cm_filesystem_close_temporary_file_stream().
/// The stream remains valid until it is closed or its owner is closed, renamed, or deleted.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_get_temporary_file_stream(cm_filesystem_temporary_file *file, FILE **stream);

/// \brief Gets a borrowed path, valid until the next CM_API call on this thread.
/// \details Sets path to NULL if removed or renamed, or on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_get_temporary_file_path(cm_filesystem_temporary_file *file, const char **path);

/// \brief Closes the stream without removing the file, reporting close errors. Repeated calls are harmless.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_close_temporary_file_stream(cm_filesystem_temporary_file *file);

/// \brief Closes the stream and removes the file. Repeated calls are harmless.
/// \details Ignores stream close errors but reports removal errors, matching scoped cleanup.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_close_temporary_file(cm_filesystem_temporary_file *file);

/// \brief Closes the stream and renames the file, atomically replacing the destination.
/// \details Reports close errors before renaming. On success, deleting the owner no longer removes the file.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_filesystem_rename_temporary_file(cm_filesystem_temporary_file *file, const char *to);

/// \brief Deletes the owner, closing its stream and removing its file unless it was renamed.
/// \details Accepts NULL. Cleanup errors are ignored, as with cm_delete().
CM_API void cm_filesystem_delete_temporary_file(cm_filesystem_temporary_file *file);

#ifdef __cplusplus
}
#endif

#endif // NOLINTEND
