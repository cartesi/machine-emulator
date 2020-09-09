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

#include <cinttypes>

#include "clua.h"
#include "clua-i-virtual-machine.h"
#include "clua-htif.h"
#include "clua-machine-util.h"
#include "virtual-machine.h"

namespace cartesi {

/// \brief This is the machine.get_default_machine_config()
/// method implementation.
static int machine_class__index_get_default_config(lua_State *L) {
    clua_push_machine_config(L, machine::get_default_config());
    return 1;
}

/// \brief This is the machine.verify_access_log() method implementation.
static int machine_class__index_verify_access_log(lua_State *L) try {
    machine::verify_access_log(clua_check_access_log(L, 1),
        true /* 1-based indices in errors */ );
    lua_pushnumber(L, 1);
    return 1;
} catch (std::exception &x) {
    lua_pushnil(L);
    lua_pushstring(L, x.what());
    return 2;
}

/// \brief This is the machine.verify_state_transition() method implementation.
static int machine_class__index_verify_state_transition(lua_State *L) try {
    machine::verify_state_transition(clua_check_hash(L, 1),
        clua_check_access_log(L, 2),
        clua_check_hash(L, 3), true /* 1-based indices in errors */);
    lua_pushnumber(L, 1);
    return 1;
} catch (std::exception &x) {
    lua_pushnil(L);
    lua_pushstring(L, x.what());
    return 2;
}

/// \brief Contents of the machine class metatable __index table.
static const luaL_Reg machine_class__index[] = {
    {"get_default_config", machine_class__index_get_default_config},
    {"verify_access_log", machine_class__index_verify_access_log},
    {"verify_state_transition", machine_class__index_verify_state_transition},
    { nullptr, nullptr }
};

/// \brief This is the cartesi.machine() constructor implementation.
/// \param L Lua state.
static int machine_ctor(lua_State *L) try {
    // Allocate room for clua_i_virtual_machine_ptr as a Lua userdata
    clua_i_virtual_machine_ptr *p = reinterpret_cast<clua_i_virtual_machine_ptr *>(
        lua_newuserdata(L, sizeof(clua_i_virtual_machine_ptr)));
    new (p) clua_i_virtual_machine_ptr();
    if (lua_type(L, 2) == LUA_TTABLE) {
        *p = std::make_unique<virtual_machine>(clua_check_machine_config(L, 2));
    } else {
        *p = std::make_unique<virtual_machine>(luaL_checkstring(L, 2));
    }
    clua_setmetatable<clua_i_virtual_machine_ptr>(L, -1);
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief Tag to identify the machine class-like constructor
struct machine_class {};

int clua_machine_init(lua_State *L, int ctxidx) {
    if (!clua_typeexists<machine_class>(L, ctxidx)) {
        clua_createtype<machine_class>(L, "cartesi machine class", ctxidx);
        clua_setmethods<machine_class>(L, machine_class__index, 0, ctxidx);
        static luaL_Reg machine_class_meta[] = {
            { "__call", machine_ctor },
            { nullptr, nullptr }
        };
        clua_setmetamethods<machine_class>(L, machine_class_meta, 0, ctxidx);
        clua_gettypemetatable<machine_class>(L, ctxidx);
        lua_getfield(L, -1, "__index");
        clua_htif_export(L, ctxidx);
        lua_pop(L, 2);
    }
    return 1;
}

int clua_machine_export(lua_State *L, int ctxidx) {
    int ctxabsidx = lua_absindex(L, ctxidx);
    // cartesi
    clua_machine_init(L, ctxabsidx); // cartesi
    lua_newtable(L); // cartesi machine_class
    clua_setmetatable<machine_class>(L, -1, ctxabsidx); // cartesi machine_class
    lua_setfield(L, -2, "machine"); // cartesi
    return 0;
}

} // namespace cartesi
