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

#if defined(__clang__) && defined(__APPLE__)
#if !defined(__ENVIRONMENT_OS_VERSION_MIN_REQUIRED__) && defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__)
#define __ENVIRONMENT_OS_VERSION_MIN_REQUIRED__ __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__
#endif
#endif

#define BOOST_TEST_MODULE Lua filesystem test // NOLINT(cppcoreguidelines-macro-usage)
#define BOOST_TEST_NO_OLD_TOOLS

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <boost/test/included/unit_test.hpp>
#pragma GCC diagnostic pop

#include <exception>
#include <memory>
#include <string_view>

extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}

#ifdef __clang__
#pragma clang diagnostic ignored "-Wc2y-extensions"
#endif

// Lua's pcall catches luaL_error's longjmp, but it cannot end an abandoned C++ catch.
// Unlike RSS measurements, current_exception detects that leak on the first failed call.
BOOST_AUTO_TEST_CASE(filesystem_errors_destroy_cpp_exceptions) {
    const std::unique_ptr<lua_State, decltype(&lua_close)> state(luaL_newstate(), &lua_close);
    BOOST_REQUIRE(state != nullptr);
    lua_State *L = state.get();
    luaL_openlibs(L);
    BOOST_REQUIRE_EQUAL(luaL_dostring(L, "filesystem = require('cartesi.filesystem')"), LUA_OK);
    BOOST_REQUIRE(!std::current_exception());
    const struct {
        const char *call;
        const char *message;
    } cases[] = {
        {"return pcall(filesystem.exists, string.rep('x', 4096))", "unable to check existence of path"},
        {"return pcall(filesystem.create_directory, '/dev/null/child')", "unable to create directory"},
        {"return pcall(filesystem.list_directory, '/dev/null')", "unable to list directory"},
        {"return pcall(filesystem.clone_file, '/dev/null/source', '/dev/null/target')", "unable to clone file"},
        {"return pcall(filesystem.truncate_file, '/dev/null/child', 0)", "unable to truncate file"},
        {"return pcall(filesystem.create_temporary_file, '/dev/null', 'cartesi-')", "unable to create temporary file"},
        {"return pcall(filesystem.create_temporary_directory, '/dev/null', 'cartesi-')",
            "unable to create temporary directory"},
        {"return pcall(filesystem.new_temporary_file, '/dev/null', 'cartesi-')", "unable to create temporary file"},
        {"return pcall(filesystem.read_file, '/dev/null/child')", "unable to read file"},
        {"return pcall(filesystem.write_file, 'data', '/dev/null/child')", "unable to write file"},
        {"return pcall(filesystem.write_durable_file, 'data', '/dev/null/child')", "unable to create temporary file"},
        {"return pcall(filesystem.rename_file, '/dev/null/child', '/dev/null/target')", "unable to rename file"},
        {"return pcall(filesystem.sync_file, '/dev/null/child')", "unable to sync file"},
        {"return pcall(filesystem.sync_directory, '/dev/null/child')", "unable to sync directory"},
    };
    for (const auto &test : cases) {
        BOOST_TEST_CONTEXT(test.call) {
            BOOST_REQUIRE_EQUAL(luaL_dostring(L, test.call), LUA_OK);
            BOOST_REQUIRE_MESSAGE(!std::current_exception(), "Lua error left a caught C++ exception alive");
            BOOST_REQUIRE_EQUAL(lua_toboolean(L, -2), 0);
            BOOST_REQUIRE(lua_isstring(L, -1));
            BOOST_REQUIRE(std::string_view(lua_tostring(L, -1)).find(test.message) != std::string_view::npos);
            lua_settop(L, 0);
            lua_gc(L, LUA_GCCOLLECT);
        }
    }
}
