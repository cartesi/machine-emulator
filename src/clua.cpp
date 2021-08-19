// Copyright 2020 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#include "clua.h"

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

void clua_setlstringfield(lua_State *L, const char *val, size_t len, const char *name, int idx) {
    auto absidx = lua_absindex(L, idx);
    lua_pushlstring(L, val, len);
    lua_setfield(L, absidx, name);
}

void clua_setbooleanfield(lua_State *L, bool val, const char *name, int idx) {
    auto absidx = lua_absindex(L, idx);
    lua_pushboolean(L, val);
    lua_setfield(L, absidx, name);
}

} // namespace cartesi
