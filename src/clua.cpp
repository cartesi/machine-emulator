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

#include "clua.h"

#include <cstddef>
#include <cstdint>

extern "C" {
#include <lua.h>
}

namespace cartesi {

int clua_init(lua_State *L) {
    lua_pushstring(L, clua_registry_key);     // key
    lua_rawget(L, LUA_REGISTRYINDEX);         // ctxtab_or_nil
    if (lua_isnil(L, -1)) {                   // nil
        lua_pop(L, 1);                        //
        lua_newtable(L);                      // ctxtab
        lua_pushstring(L, clua_registry_key); // ctx key
        lua_pushvalue(L, -2);                 // ctxtab key ctxtab
        lua_rawset(L, LUA_REGISTRYINDEX);     // ctxtab
    }
    // ctxtab
    return 1;
}

void clua_setintegerfield(lua_State *L, uint64_t val, const char *name, int idx) {
    auto absidx = lua_absindex(L, idx);
    lua_pushinteger(L, static_cast<lua_Integer>(val));
    lua_setfield(L, absidx, name);
}

void clua_setstringfield(lua_State *L, const char *val, const char *name, int idx) {
    auto absidx = lua_absindex(L, idx);
    lua_pushstring(L, val);
    lua_setfield(L, absidx, name);
}

void clua_setlstringfield(lua_State *L, const char *val, size_t length, const char *name, int idx) {
    auto absidx = lua_absindex(L, idx);
    lua_pushlstring(L, val, length);
    lua_setfield(L, absidx, name);
}

#ifdef CLUA_DEBUG_UTILS

static void fprint_str(FILE *out, const char *str, int max) {
    int i = 0;
    int m = max;
    for (i = 0; m > 0 && str[i]; ++i) {
        if (isprint(str[i])) {
            std::ignore = fputc(str[i], out);
            m -= 1;
        } else {
            std::ignore = fprintf(out, "\\0x%02x", static_cast<unsigned char>(str[i]));
            m -= 5;
        }
    }
    if (str[i]) {
        std::ignore = fprintf(out, "...");
    }
}

void clua_print(lua_State *L, int idx) {
    idx = lua_absindex(L, idx);
    lua_getglobal(L, "tostring");
    lua_pushvalue(L, idx);
    lua_call(L, 1, 1);
    std::ignore = fprintf(stderr, "%02d: ", idx);
    fprint_str(stderr, lua_tostring(L, -1), 68);
    std::ignore = fputc('\n', stderr);
    lua_pop(L, 1);
}

void clua_dumpstack(lua_State *L) {
    for (int i = 1; i <= lua_gettop(L); i++) {
        clua_print(L, i);
    }
}

#endif

} // namespace cartesi
