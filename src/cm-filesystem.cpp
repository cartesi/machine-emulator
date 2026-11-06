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

#include "cm-filesystem.h"

#include <cstdio>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <tuple>

#include <json.hpp>

#include "base64.hpp"
#include "cm-internal.hpp"
#include "os-filesystem.hpp"
#include "scope-exit.hpp"

cm_error cm_filesystem_exists(const char *path, bool *exists) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    if (exists == nullptr) {
        throw std::invalid_argument("invalid exists output");
    }
    *exists = cartesi::os::exists(path);
    return cm_result_success();
} catch (...) {
    if (exists != nullptr) {
        *exists = false;
    }
    return cm_result_failure();
}

cm_error cm_filesystem_create_directory(const char *path) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    cartesi::os::create_directory(path);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_filesystem_list_directory(const char *path, const char **names) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    if (names == nullptr) {
        throw std::invalid_argument("invalid names output");
    }
    auto cpp_names = cartesi::os::list_directory(path);
    for (auto &name : cpp_names) {
        name = cartesi::encode_base64(name);
    }
    *names = cm_set_temp_string(nlohmann::json(cpp_names).dump());
    return cm_result_success();
} catch (...) {
    if (names != nullptr) {
        *names = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_filesystem_clone_file(const char *from, const char *to) try {
    if (from == nullptr) {
        throw std::invalid_argument("invalid source path");
    }
    if (to == nullptr) {
        throw std::invalid_argument("invalid destination path");
    }
    cartesi::os::clone_file(from, to);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_filesystem_truncate_file(const char *path, uint64_t size) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    cartesi::os::truncate_file(path, size);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_filesystem_create_temporary_directory(const char *dirname, const char *prefix, const char **path) try {
    if (dirname == nullptr) {
        throw std::invalid_argument("invalid directory path");
    }
    if (prefix == nullptr) {
        throw std::invalid_argument("invalid prefix");
    }
    if (path == nullptr) {
        throw std::invalid_argument("invalid path output");
    }
    const auto cpp_path = cartesi::os::create_temporary_directory(dirname, prefix);
    auto failure_remove = cartesi::scope_fail([&] { std::ignore = cm_filesystem_remove_directory(cpp_path.c_str()); });
    *path = cm_set_temp_string(cpp_path);
    return cm_result_success();
} catch (...) {
    if (path != nullptr) {
        *path = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_filesystem_create_temporary_file(const char *dirname, const char *prefix, FILE **file,
    const char **path) try {
    if (dirname == nullptr) {
        throw std::invalid_argument("invalid directory path");
    }
    if (prefix == nullptr) {
        throw std::invalid_argument("invalid prefix");
    }
    if (file == nullptr) {
        throw std::invalid_argument("invalid file output");
    }
    if (path == nullptr) {
        throw std::invalid_argument("invalid path output");
    }
    const auto [cpp_file, cpp_path] = cartesi::os::create_temporary_file(dirname, prefix);
    auto failure_remove = cartesi::scope_fail([&] {
        std::ignore = fclose(cpp_file);
        std::ignore = remove(cpp_path.c_str());
    });
    *path = cm_set_temp_string(cpp_path);
    *file = cpp_file;
    return cm_result_success();
} catch (...) {
    if (file != nullptr) {
        *file = nullptr;
    }
    if (path != nullptr) {
        *path = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_filesystem_sync_file(const char *path) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    cartesi::os::sync_file(path);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_filesystem_sync_file_descriptor(int fd, const char *path) try {
    if (fd < 0) {
        throw std::invalid_argument("invalid file descriptor");
    }
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    cartesi::os::sync_file_descriptor(fd, path);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_filesystem_sync_directory(const char *path) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    cartesi::os::sync_directory(path);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

static cartesi::os::temporary_file *convert_from_c(cm_filesystem_temporary_file *file) {
    if (file == nullptr) {
        throw std::invalid_argument("invalid temporary file");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<cartesi::os::temporary_file *>(file);
}

static cm_filesystem_temporary_file *convert_to_c(cartesi::os::temporary_file *file) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<cm_filesystem_temporary_file *>(file);
}

cm_error cm_filesystem_read_file(const char *path, const uint8_t **data, uint64_t *length) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    if (data == nullptr) {
        throw std::invalid_argument("invalid data output");
    }
    if (length == nullptr) {
        throw std::invalid_argument("invalid length output");
    }
    const auto contents = cartesi::os::read_file_contents(path);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *data = reinterpret_cast<const uint8_t *>(cm_set_temp_string(contents));
    *length = contents.size();
    return cm_result_success();
} catch (...) {
    if (data != nullptr) {
        *data = nullptr;
    }
    if (length != nullptr) {
        *length = 0;
    }
    return cm_result_failure();
}

cm_error cm_filesystem_write_file(const char *path, const uint8_t *data, uint64_t length) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    if (data == nullptr && length != 0) {
        throw std::invalid_argument("invalid data");
    }
    cartesi::os::write_file(path, {data, static_cast<size_t>(length)});
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_filesystem_write_durable_file(const char *path, const uint8_t *data, uint64_t length) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    if (data == nullptr && length != 0) {
        throw std::invalid_argument("invalid data");
    }
    cartesi::os::write_durable_file(path, {data, static_cast<size_t>(length)});
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_filesystem_remove_file(const char *path) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    cartesi::os::remove_file(path);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_filesystem_remove_directory(const char *path) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    cartesi::os::remove_directory(path);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_filesystem_rename_file(const char *from, const char *to) try {
    if (from == nullptr) {
        throw std::invalid_argument("invalid source path");
    }
    if (to == nullptr) {
        throw std::invalid_argument("invalid destination path");
    }
    cartesi::os::rename_file(from, to);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_filesystem_get_file_size(const char *path, uint64_t *size) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    if (size == nullptr) {
        throw std::invalid_argument("invalid size output");
    }
    *size = cartesi::os::file_size(path);
    return cm_result_success();
} catch (...) {
    if (size != nullptr) {
        *size = 0;
    }
    return cm_result_failure();
}

cm_error cm_filesystem_get_parent_directory(const char *path, const char **parent) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    if (parent == nullptr) {
        throw std::invalid_argument("invalid parent output");
    }
    *parent = cm_set_temp_string(cartesi::os::get_parent_directory(path));
    return cm_result_success();
} catch (...) {
    if (parent != nullptr) {
        *parent = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_filesystem_temp_filename(const char **path) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path output");
    }
    const auto cpp_path = cartesi::os::temp_filename();
    auto failure_remove = cartesi::scope_fail([&] { std::ignore = remove(cpp_path.c_str()); });
    *path = cm_set_temp_string(cpp_path);
    return cm_result_success();
} catch (...) {
    if (path != nullptr) {
        *path = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_filesystem_write_temp_file(const uint8_t *data, uint64_t length, const char **path) try {
    if (data == nullptr && length != 0) {
        throw std::invalid_argument("invalid data");
    }
    if (path == nullptr) {
        throw std::invalid_argument("invalid path output");
    }
    const auto cpp_path = cartesi::os::write_temp_file({data, static_cast<size_t>(length)});
    auto failure_remove = cartesi::scope_fail([&] { std::ignore = remove(cpp_path.c_str()); });
    *path = cm_set_temp_string(cpp_path);
    return cm_result_success();
} catch (...) {
    if (path != nullptr) {
        *path = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_filesystem_sync_file_stream(FILE *file, const char *path) try {
    if (file == nullptr) {
        throw std::invalid_argument("invalid file");
    }
    if (path == nullptr) {
        throw std::invalid_argument("invalid path");
    }
    cartesi::os::sync_file_stream(file, path);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_filesystem_new_temporary_file(const char *dirname, const char *prefix,
    cm_filesystem_temporary_file **file) try {
    if (dirname == nullptr) {
        throw std::invalid_argument("invalid directory path");
    }
    if (prefix == nullptr) {
        throw std::invalid_argument("invalid prefix");
    }
    if (file == nullptr) {
        throw std::invalid_argument("invalid temporary file output");
    }
    *file = convert_to_c(new cartesi::os::temporary_file(dirname, prefix));
    return cm_result_success();
} catch (...) {
    if (file != nullptr) {
        *file = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_filesystem_write_scope_temp_file(const uint8_t *data, uint64_t length,
    cm_filesystem_temporary_file **file) try {
    if (data == nullptr && length != 0) {
        throw std::invalid_argument("invalid data");
    }
    if (file == nullptr) {
        throw std::invalid_argument("invalid temporary file output");
    }
    auto cpp_file = std::make_unique<cartesi::os::temporary_file>();
    cpp_file->write({data, static_cast<size_t>(length)});
    cpp_file->close_stream();
    *file = convert_to_c(cpp_file.release());
    return cm_result_success();
} catch (...) {
    if (file != nullptr) {
        *file = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_filesystem_get_temporary_file_stream(cm_filesystem_temporary_file *file, FILE **stream) try {
    if (stream == nullptr) {
        throw std::invalid_argument("invalid stream output");
    }
    *stream = convert_from_c(file)->get_file();
    return cm_result_success();
} catch (...) {
    if (stream != nullptr) {
        *stream = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_filesystem_get_temporary_file_path(cm_filesystem_temporary_file *file, const char **path) try {
    if (path == nullptr) {
        throw std::invalid_argument("invalid path output");
    }
    const auto &cpp_path = convert_from_c(file)->get_path();
    *path = cpp_path.empty() ? nullptr : cm_set_temp_string(cpp_path);
    return cm_result_success();
} catch (...) {
    if (path != nullptr) {
        *path = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_filesystem_close_temporary_file_stream(cm_filesystem_temporary_file *file) try {
    convert_from_c(file)->close_stream();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_filesystem_close_temporary_file(cm_filesystem_temporary_file *file) try {
    convert_from_c(file)->close();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_filesystem_rename_temporary_file(cm_filesystem_temporary_file *file, const char *to) try {
    if (to == nullptr) {
        throw std::invalid_argument("invalid destination path");
    }
    convert_from_c(file)->rename(to);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

void cm_filesystem_delete_temporary_file(cm_filesystem_temporary_file *file) {
    if (file != nullptr) {
        delete convert_from_c(file);
    }
}
