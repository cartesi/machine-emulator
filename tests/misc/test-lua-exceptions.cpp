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

#define BOOST_TEST_MODULE Lua exception test // NOLINT(cppcoreguidelines-macro-usage)
#define BOOST_TEST_NO_OLD_TOOLS

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <boost/test/included/unit_test.hpp>
#pragma GCC diagnostic pop

#include <exception>
#include <memory>
#include <string>
#include <string_view>

#include "cm.h"

extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

int luaopen_cartesi(lua_State *L);
}

#ifdef __clang__
#pragma clang diagnostic ignored "-Wc2y-extensions"
#endif

// A Lua longjmp must never leave a C++ catch active after pcall returns.
BOOST_AUTO_TEST_CASE(lua_errors_destroy_cpp_exceptions) {
    const std::unique_ptr<lua_State, decltype(&lua_close)> state(luaL_newstate(), &lua_close);
    BOOST_REQUIRE(state != nullptr);
    lua_State *L = state.get();
    luaL_openlibs(L);
    // Use the linked Lua module so these C API calls and the bindings share the same library instance.
    luaL_requiref(L, "cartesi", luaopen_cartesi, 1);
    lua_pop(L, 1);
    BOOST_REQUIRE_EQUAL(luaL_dostring(L, "cartesi = require('cartesi'); machine = cartesi.new()"), LUA_OK);
    BOOST_REQUIRE(!std::current_exception());
    const struct {
        const char *call;
        const char *message;
    } cases[] = {
        {"return pcall(cartesi.fromhex, '0xzz')", "invalid hex"},
        {"return pcall(cartesi.frombase64, '!!!!')", "base64"},
        {"return pcall(cartesi.fromjson, '{bad')", "failed to parse JSON from a string"},
        {"return pcall(cartesi.tojson, string.char(255))", "failed to convert a Lua value to JSON"},
        {"return pcall(cartesi.fromjson, '{}', 'MissingSchema')", "is not defined in schema dictionary"},
        {"return pcall(cartesi.tojson, {}, -1, 'MissingSchema')", "is not defined in schema dictionary"},
        {"return pcall(cartesi.fromjson, '\"0xzz\"', 'Hex')", "invalid hex"},
        {"return pcall(function() local s = {}; s.x = s; return cartesi.tojson({}, -1, 'X', s) end)",
            "JSON nesting depth exceeds 256"},
        {"return pcall(function() local s = {}; s.x = s; return cartesi.fromjson('{}', 'X', s) end)",
            "JSON nesting depth exceeds 256"},
        {"return pcall(machine.read_reg, machine, 'not_a_register')", "unknown register"},
    };
    for (const auto &test : cases) {
        BOOST_TEST_CONTEXT(test.call) {
            for (int repetition = 0; repetition < 3; ++repetition) {
                BOOST_REQUIRE_EQUAL(cm_new(nullptr), CM_ERROR_INVALID_ARGUMENT);
                const std::string pending_error = cm_get_last_error_message();
                BOOST_REQUIRE_EQUAL(luaL_dostring(L, test.call), LUA_OK);
                BOOST_CHECK_EQUAL(cm_get_last_error_message(), pending_error);
                BOOST_REQUIRE_MESSAGE(!std::current_exception(), "Lua error left a caught C++ exception alive");
                BOOST_REQUIRE_EQUAL(lua_toboolean(L, -2), 0);
                BOOST_REQUIRE(lua_isstring(L, -1));
                BOOST_REQUIRE_MESSAGE(std::string_view(lua_tostring(L, -1)).find(test.message) !=
                        std::string_view::npos,
                    lua_tostring(L, -1));
                lua_settop(L, 0);
                lua_gc(L, LUA_GCCOLLECT);
            }
        }
    }
    // Check both sides of the 1023-byte payload limit, including a much longer exception.
    for (const size_t length : {1022, 1023, 1024, 4096}) {
        const std::string prefix = "type \"";
        const std::string suffix = "\" is not defined in schema dictionary";
        const std::string schema_name(length - prefix.size() - suffix.size(), 'x');
        const std::string exception_message = prefix + schema_name + suffix;
        lua_getglobal(L, "cartesi");
        lua_getfield(L, -1, "fromjson");
        lua_pushliteral(L, "{}");
        lua_pushlstring(L, schema_name.data(), schema_name.size());
        BOOST_REQUIRE_EQUAL(cm_new(nullptr), CM_ERROR_INVALID_ARGUMENT);
        const std::string pending_error = cm_get_last_error_message();
        BOOST_REQUIRE_EQUAL(lua_pcall(L, 2, 1, 0), LUA_ERRRUN);
        BOOST_REQUIRE(!std::current_exception());
        BOOST_CHECK_EQUAL(cm_get_last_error_message(), pending_error);
        BOOST_REQUIRE(lua_isstring(L, -1));
        BOOST_CHECK_EQUAL(lua_tostring(L, -1),
            "failed to parse JSON from a string: " + exception_message.substr(0, 1023));
        lua_settop(L, 0);
        lua_gc(L, LUA_GCCOLLECT);
    }
    BOOST_REQUIRE_EQUAL(cm_new(nullptr), CM_ERROR_INVALID_ARGUMENT);
    const std::string pending_error = cm_get_last_error_message();
    BOOST_REQUIRE_EQUAL(luaL_dostring(L, R"(
        local binary = "a\0b"
        assert(cartesi.fromhex(cartesi.tohex(binary)) == binary)
        assert(cartesi.frombase64(cartesi.tobase64(binary)) == binary)
        assert(cartesi.fromjson(cartesi.tojson({42}))[1] == 42)
        assert(cartesi.fromjson('"0x6162"', 'Hex') == 'ab')
    )"),
        LUA_OK);
    BOOST_REQUIRE(!std::current_exception());
    BOOST_CHECK_EQUAL(cm_get_last_error_message(), pending_error);
}
