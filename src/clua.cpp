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

/// \brief Dummy variable from which we only pick the address
/// that should be unique in this process
static int clua_key = 0;

int clua_init(lua_State *L) {
    lua_pushlightuserdata(L, &clua_key); // key
    lua_rawget(L, LUA_REGISTRYINDEX); // ctxtab_or_nil
    if (lua_isnil(L, -1)) { // nil
        lua_pop(L, 1); //
        lua_newtable(L); // ctxtab
        lua_pushlightuserdata(L, &clua_key); // ctx key
        lua_pushvalue(L, -2); // ctxtab key ctxtab
        lua_rawset(L, LUA_REGISTRYINDEX); // ctxtab
    }
    // ctxtab
    return 1;
}

} // namespace cartesi
