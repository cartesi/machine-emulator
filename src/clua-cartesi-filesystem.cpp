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

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <string>

extern "C" {
#include <lauxlib.h>
#include <lua.h>
}

#include "clua.hpp"
#include "cm.h"
#include "os-filesystem.hpp"

/// \file
/// \brief Core of the cartesi.filesystem module, with the operations Lua cannot perform on its own.

namespace cartesi {

static int filesystem_core_mod_exists(lua_State *L) try {
    lua_pushboolean(L, static_cast<int>(os::exists(luaL_checkstring(L, 1))));
    return 1;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return 1;
}

static int filesystem_core_mod_create_directory(lua_State *L) try {
    os::create_directory(luaL_checkstring(L, 1));
    return 0;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return 1;
}

static int filesystem_core_mod_list_directory(lua_State *L) try {
    const auto names = os::list_directory(luaL_checkstring(L, 1));
    lua_createtable(L, static_cast<int>(names.size()), 0);
    lua_Integer index = 0;
    for (const auto &name : names) {
        lua_pushlstring(L, name.data(), name.size());
        lua_rawseti(L, -2, ++index);
    }
    return 1;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return 1;
}

// Clones a file into a new path by a hard link if it is read-only, or a reflink if it is writable,
// falling back to a copy.
static int filesystem_core_mod_clone_file(lua_State *L) try {
    os::clone_file(luaL_checkstring(L, 1), luaL_checkstring(L, 2));
    return 0;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return 1;
}

// Truncates or extends a file to a size, filling an extension with zeros.
static int filesystem_core_mod_truncate_file(lua_State *L) try {
    const lua_Integer size = luaL_checkinteger(L, 2);
    luaL_argcheck(L, size >= 0, 2, "size must not be negative");
    os::truncate_file(luaL_checkstring(L, 1), static_cast<uint64_t>(size));
    return 0;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return 1;
}

// Closes a file created by create_temporary_file, as the io library closes its own files.
static int filesystem_core_file_close(lua_State *L) {
    auto *stream = static_cast<luaL_Stream *>(luaL_checkudata(L, 1, LUA_FILEHANDLE));
    return luaL_fileresult(L, static_cast<int>(fclose(stream->f) == 0), nullptr);
}

// Returns an open Lua file and the path of a new file created exclusively with a unique name.
static int filesystem_core_mod_create_temporary_file(lua_State *L) try {
    auto *stream = static_cast<luaL_Stream *>(lua_newuserdatauv(L, sizeof(luaL_Stream), 0));
    stream->closef = nullptr; // a closed file until fully initialized
    luaL_setmetatable(L, LUA_FILEHANDLE);
    const auto [file, path] = os::create_temporary_file(luaL_checkstring(L, 1), luaL_checkstring(L, 2));
    stream->f = file;
    stream->closef = &filesystem_core_file_close;
    lua_pushlstring(L, path.data(), path.size());
    return 2;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return 1;
}

// Syncs an open Lua file, after flushing its buffer, or the file at a path.
static int filesystem_core_mod_sync_file(lua_State *L) try {
    auto *stream = static_cast<luaL_Stream *>(luaL_testudata(L, 1, LUA_FILEHANDLE));
    if (stream == nullptr) {
        os::sync_file(luaL_checkstring(L, 1));
        return 0;
    }
    if (stream->closef == nullptr) {
        return luaL_error(L, "attempt to sync a closed file");
    }
    if (fflush(stream->f) != 0) {
        return luaL_error(L, "unable to sync file: fflush() failed: %s", strerror(errno));
    }
    os::sync_file_descriptor(fileno(stream->f), "<open file>");
    return 0;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return 1;
}

static int filesystem_core_mod_sync_directory(lua_State *L) try {
    os::sync_directory(luaL_checkstring(L, 1));
    return 0;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return 1;
}

/// \brief Contents of the cartesi.filesystem.core module table.
static const auto filesystem_core_mod = clua_make_luaL_Reg_array({
    {.name = "exists", .func = filesystem_core_mod_exists},
    {.name = "create_directory", .func = filesystem_core_mod_create_directory},
    {.name = "list_directory", .func = filesystem_core_mod_list_directory},
    {.name = "clone_file", .func = filesystem_core_mod_clone_file},
    {.name = "truncate_file", .func = filesystem_core_mod_truncate_file},
    {.name = "create_temporary_file", .func = filesystem_core_mod_create_temporary_file},
    {.name = "sync_file", .func = filesystem_core_mod_sync_file},
    {.name = "sync_directory", .func = filesystem_core_mod_sync_directory},
});

} // namespace cartesi

extern "C" {

/// \brief Entrypoint to the cartesi.filesystem.core Lua library, found inside the cartesi library by
/// Lua's all-in-one loader.
/// \param L Lua state.
CM_API int luaopen_cartesi_filesystem_core(lua_State *L) {
    using namespace cartesi;
    lua_newtable(L);
    luaL_setfuncs(L, filesystem_core_mod.data(), 0);
    return 1;
}
}
