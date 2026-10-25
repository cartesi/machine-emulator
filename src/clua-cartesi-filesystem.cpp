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

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>

extern "C" {
#include <lauxlib.h>
#include <lua.h>
}

#include "clua-i-machine.hpp"
#include "clua.hpp"
#include "cm-filesystem.h"
#include "cm.h"

/// \file
/// \brief Scripting interface for the Cartesi filesystem API.

namespace cartesi {

static int filesystem_mod_exists(lua_State *L) {
    bool exists{};
    if (cm_filesystem_exists(luaL_checkstring(L, 1), &exists) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushboolean(L, static_cast<int>(exists));
    return 1;
}

static int filesystem_mod_create_directory(lua_State *L) {
    if (cm_filesystem_create_directory(luaL_checkstring(L, 1)) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

static int filesystem_mod_list_directory(lua_State *L) {
    const char *names = nullptr;
    if (cm_filesystem_list_directory(luaL_checkstring(L, 1), &names) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_fromjson(L, names, "Base64Array");
    return 1;
}

// Clones a file into a new path by a hard link if it is read-only, or a reflink if it is writable,
// falling back to a copy.
static int filesystem_mod_clone_file(lua_State *L) {
    if (cm_filesystem_clone_file(luaL_checkstring(L, 1), luaL_checkstring(L, 2)) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

// Truncates or extends a file to a size, filling an extension with zeros.
static int filesystem_mod_truncate_file(lua_State *L) {
    const lua_Integer size = luaL_checkinteger(L, 2);
    luaL_argcheck(L, size >= 0, 2, "size must not be negative");
    if (cm_filesystem_truncate_file(luaL_checkstring(L, 1), static_cast<uint64_t>(size)) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

// Closes a file created by create_temporary_file, as the io library closes its own files.
static int filesystem_file_close(lua_State *L) {
    auto *stream = static_cast<luaL_Stream *>(luaL_checkudata(L, 1, LUA_FILEHANDLE));
    return luaL_fileresult(L, static_cast<int>(fclose(stream->f) == 0), nullptr);
}

static int filesystem_mod_create_temporary_directory(lua_State *L) {
    const char *dirname = luaL_checkstring(L, 1);
    const char *prefix = luaL_checkstring(L, 2);
    const char *path = nullptr;
    if (cm_filesystem_create_temporary_directory(dirname, prefix, &path) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushstring(L, path);
    return 1;
}

// Returns an open Lua file and the path of a new file created exclusively with a unique name.
static int filesystem_mod_create_temporary_file(lua_State *L) {
    const char *dirname = luaL_checkstring(L, 1);
    const char *prefix = luaL_checkstring(L, 2);
    const char *path = nullptr;
    auto *stream = static_cast<luaL_Stream *>(lua_newuserdatauv(L, sizeof(luaL_Stream), 0));
    stream->closef = nullptr; // a closed file until fully initialized
    luaL_setmetatable(L, LUA_FILEHANDLE);
    if (cm_filesystem_create_temporary_file(dirname, prefix, &stream->f, &path) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    stream->closef = &filesystem_file_close;
    lua_pushstring(L, path);
    return 2;
}

// Syncs an open Lua file, after flushing its buffer, or the file at a path.
static int filesystem_mod_sync_file(lua_State *L) {
    auto *stream = static_cast<luaL_Stream *>(luaL_testudata(L, 1, LUA_FILEHANDLE));
    if (stream == nullptr) {
        if (cm_filesystem_sync_file(luaL_checkstring(L, 1)) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
        return 0;
    }
    if (stream->closef == nullptr) {
        return luaL_error(L, "attempt to sync a closed file");
    }
    if (cm_filesystem_sync_file_stream(stream->f, "<open file>") != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

static int filesystem_mod_sync_directory(lua_State *L) {
    if (cm_filesystem_sync_directory(luaL_checkstring(L, 1)) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

using temporary_file_ptr =
    std::unique_ptr<cm_filesystem_temporary_file, decltype(&cm_filesystem_delete_temporary_file)>;

// The Lua file borrows the stream from its C++ owner. Every close updates that owner.
static int temporary_file_stream_close(lua_State *L) {
    lua_getiuservalue(L, 1, 1);
    // The owner's GC may already have closed the stream and removed its metatable.
    if (lua_getmetatable(L, -1) == 0) {
        lua_pushboolean(L, 1);
        return 1;
    }
    lua_pop(L, 1);
    auto &owner = clua_to<temporary_file_ptr>(L, -1);
    if (cm_filesystem_close_temporary_file_stream(owner.get()) != 0) {
        lua_pushnil(L);
        lua_pushstring(L, cm_get_last_error_message());
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}

static void temporary_file_mark_stream_closed(lua_State *L) {
    if (lua_getiuservalue(L, 1, 1) == LUA_TUSERDATA) {
        auto *stream = static_cast<luaL_Stream *>(lua_touserdata(L, -1));
        stream->closef = nullptr;
        stream->f = nullptr;
    }
    lua_pop(L, 1);
}

static int temporary_file_close(lua_State *L) {
    auto &owner = clua_check<temporary_file_ptr>(L, 1);
    temporary_file_mark_stream_closed(L);
    if (cm_filesystem_close_temporary_file(owner.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

static int temporary_file_rename(lua_State *L) {
    auto &owner = clua_check<temporary_file_ptr>(L, 1);
    const char *to = luaL_checkstring(L, 2);
    temporary_file_mark_stream_closed(L);
    if (cm_filesystem_rename_temporary_file(owner.get(), to) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

static int temporary_file_gc(lua_State *L) {
    temporary_file_mark_stream_closed(L);
    return clua_gc<temporary_file_ptr>(L);
}

static int temporary_file_index(lua_State *L) {
    auto &owner = clua_check<temporary_file_ptr>(L, 1);
    const char *key = luaL_checkstring(L, 2);
    if (strcmp(key, "file") == 0) {
        lua_getiuservalue(L, 1, 1);
    } else if (strcmp(key, "path") == 0) {
        const char *path = nullptr;
        if (cm_filesystem_get_temporary_file_path(owner.get(), &path) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
        lua_pushstring(L, path);
    } else {
        clua_gettypemetatable<temporary_file_ptr>(L);
        lua_pushvalue(L, 2);
        lua_rawget(L, -2);
    }
    return 1;
}

static const auto temporary_file_meta = clua_make_luaL_Reg_array({
    {.name = "__gc", .func = temporary_file_gc},
    {.name = "__close", .func = temporary_file_close},
    {.name = "__index", .func = temporary_file_index},
    {.name = "close", .func = temporary_file_close},
    {.name = "rename", .func = temporary_file_rename},
});

static int filesystem_mod_new_temporary_file(lua_State *L) {
    const char *dirname = luaL_checkstring(L, 1);
    const char *prefix = luaL_checkstring(L, 2);
    auto &owner = clua_push_to(L, temporary_file_ptr(nullptr, &cm_filesystem_delete_temporary_file));
    const int owneridx = lua_gettop(L);
    auto *stream = static_cast<luaL_Stream *>(lua_newuserdatauv(L, sizeof(luaL_Stream), 1));
    stream->f = nullptr;
    stream->closef = nullptr;
    luaL_setmetatable(L, LUA_FILEHANDLE);
    lua_pushvalue(L, owneridx);
    lua_setiuservalue(L, -2, 1); // stream keeps its owner alive
    lua_pushvalue(L, -1);
    lua_setiuservalue(L, owneridx, 1); // owner exposes the stream as .file
    cm_filesystem_temporary_file *file = nullptr;
    if (cm_filesystem_new_temporary_file(dirname, prefix, &file) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    owner.reset(file);
    if (cm_filesystem_get_temporary_file_stream(file, &stream->f) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    stream->closef = &temporary_file_stream_close;
    lua_pop(L, 1);
    return 1;
}

static int filesystem_mod_write_scope_temp_file(lua_State *L) {
    size_t length = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const uint8_t *>(luaL_checklstring(L, 1, &length));
    auto &owner = clua_push_to(L, temporary_file_ptr(nullptr, &cm_filesystem_delete_temporary_file));
    cm_filesystem_temporary_file *file = nullptr;
    if (cm_filesystem_write_scope_temp_file(data, length, &file) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    owner.reset(file);
    const char *path = nullptr;
    if (cm_filesystem_get_temporary_file_path(file, &path) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushstring(L, path);
    return 2;
}

static int filesystem_mod_read_file(lua_State *L) {
    const uint8_t *data = nullptr;
    uint64_t length = 0;
    if (cm_filesystem_read_file(luaL_checkstring(L, 1), &data, &length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    lua_pushlstring(L, reinterpret_cast<const char *>(data), length);
    return 1;
}

static int filesystem_mod_write_file(lua_State *L) {
    size_t length = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const uint8_t *>(luaL_checklstring(L, 1, &length));
    if (cm_filesystem_write_file(luaL_checkstring(L, 2), data, length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

static int filesystem_mod_write_durable_file(lua_State *L) {
    size_t length = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const uint8_t *>(luaL_checklstring(L, 1, &length));
    if (cm_filesystem_write_durable_file(luaL_checkstring(L, 2), data, length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

static int filesystem_mod_remove_file(lua_State *L) {
    if (cm_filesystem_remove_file(luaL_checkstring(L, 1)) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

static int filesystem_mod_remove_directory(lua_State *L) {
    if (cm_filesystem_remove_directory(luaL_checkstring(L, 1)) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

static int filesystem_mod_rename_file(lua_State *L) {
    if (cm_filesystem_rename_file(luaL_checkstring(L, 1), luaL_checkstring(L, 2)) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

static int filesystem_mod_get_file_size(lua_State *L) {
    uint64_t size = 0;
    if (cm_filesystem_get_file_size(luaL_checkstring(L, 1), &size) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(size));
    return 1;
}

static int filesystem_mod_temp_filename(lua_State *L) {
    const char *path = nullptr;
    if (cm_filesystem_temp_filename(&path) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushstring(L, path);
    return 1;
}

static int filesystem_mod_get_parent_directory(lua_State *L) {
    const char *path = nullptr;
    if (cm_filesystem_get_parent_directory(luaL_checkstring(L, 1), &path) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushstring(L, path);
    return 1;
}

static int filesystem_mod_write_temp_file(lua_State *L) {
    size_t length = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const uint8_t *>(luaL_checklstring(L, 1, &length));
    const char *path = nullptr;
    if (cm_filesystem_write_temp_file(data, length, &path) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushstring(L, path);
    return 1;
}

/// \brief Contents of the cartesi.filesystem module table.
static const auto filesystem_mod = clua_make_luaL_Reg_array({
    {.name = "new_temporary_file", .func = filesystem_mod_new_temporary_file},
    {.name = "write_scope_temp_file", .func = filesystem_mod_write_scope_temp_file},
    {.name = "read_file", .func = filesystem_mod_read_file},
    {.name = "write_file", .func = filesystem_mod_write_file},
    {.name = "write_durable_file", .func = filesystem_mod_write_durable_file},
    {.name = "remove_file", .func = filesystem_mod_remove_file},
    {.name = "remove_directory", .func = filesystem_mod_remove_directory},
    {.name = "rename_file", .func = filesystem_mod_rename_file},
    {.name = "get_file_size", .func = filesystem_mod_get_file_size},
    {.name = "get_parent_directory", .func = filesystem_mod_get_parent_directory},
    {.name = "temp_filename", .func = filesystem_mod_temp_filename},
    {.name = "write_temp_file", .func = filesystem_mod_write_temp_file},
    {.name = "exists", .func = filesystem_mod_exists},
    {.name = "create_directory", .func = filesystem_mod_create_directory},
    {.name = "list_directory", .func = filesystem_mod_list_directory},
    {.name = "clone_file", .func = filesystem_mod_clone_file},
    {.name = "truncate_file", .func = filesystem_mod_truncate_file},
    {.name = "create_temporary_file", .func = filesystem_mod_create_temporary_file},
    {.name = "create_temporary_directory", .func = filesystem_mod_create_temporary_directory},
    {.name = "sync_file", .func = filesystem_mod_sync_file},
    {.name = "sync_directory", .func = filesystem_mod_sync_directory},
});

} // namespace cartesi

extern "C" {

/// \brief Entrypoint to the Cartesi filesystem Lua library.
/// \param L Lua state.
CM_API int luaopen_cartesi_filesystem(lua_State *L) {
    using namespace cartesi;
    clua_init(L);
    clua_i_machine_init(L, -1);
    if (!clua_typeexists<temporary_file_ptr>(L, -1)) {
        clua_createtype<temporary_file_ptr>(L, "filesystem temporary file", -1);
        clua_setmetamethods<temporary_file_ptr>(L, temporary_file_meta.data(), 0, -1);
    }
    lua_newtable(L);
    lua_pushvalue(L, -2);
    luaL_setfuncs(L, filesystem_mod.data(), 1);
    return 1;
}
}
