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
#include "machine-c-api.h"

namespace cartesi {

/// \brief This is the machine.get_default_machine_config()
/// method implementation.
static int machine_class_index_get_default_config(lua_State *L) {
    const cm_machine_config *default_config{};
    char *err_msg{};
    if (cm_get_default_config(&default_config, &err_msg) != 0) {
        lua_pushnil(L);
        lua_pushstring(L, err_msg);
        return 2;
    }

    clua_push_cm_machine_config(L, default_config);
    return 1;
}

/// \brief This is the machine.verify_access_log() method implementation.
static int machine_class_index_verify_access_log(lua_State *L) {
    char *err_msg{};
    cm_access_log *log = clua_check_cm_access_log(L, 1);
    cm_machine_runtime_config *runtime_config = clua_check_cm_machine_runtime_config(L, 2);

    int result{};
    if (cm_verify_access_log(log, runtime_config, true, &err_msg) != 0) {
        lua_pushnil(L);
        lua_pushstring(L, err_msg);
        result = 2;
    } else {
        lua_pushnumber(L, 1);
        result = 1;
    }
    cm_delete_machine_runtime_config(runtime_config);
    cm_delete_access_log(log);
    return result;
}

/// \brief This is the machine.verify_state_transition() method implementation.
static int machine_class__index_verify_state_transition(lua_State *L) {

    char *err_msg{};
    cm_hash root_hash{};
    clua_check_cm_hash(L, 1, &root_hash);
    cm_access_log *log = clua_check_cm_access_log(L, 2);
    cm_hash target_hash{};
    clua_check_cm_hash(L, 3, &target_hash);
    cm_machine_runtime_config *runtime_config = clua_check_cm_machine_runtime_config(L, 4);

    int result{};
    if (cm_verify_state_transition(&root_hash, log, &target_hash, runtime_config, true, &err_msg) != 0) {
        lua_pushnil(L);
        lua_pushstring(L, err_msg);
        result = 2;
    } else {
        lua_pushnumber(L, 1);
        result = 1;
    }
    cm_delete_machine_runtime_config(runtime_config);
    cm_delete_access_log(log);
    return result;
}

/// \brief This is the machine.get_x_address() method implementation.
static int machine_class_index_get_x_address(lua_State *L) {
    lua_pushnumber(L, cm_get_x_address(luaL_checkinteger(L, 1)));
    return 1;
}

/// \brief This is the machine.get_csr_address() method implementation.
static int machine_class_index_get_csr_address(lua_State *L) {
    lua_pushnumber(L, cm_get_csr_address(clua_check_cm_proc_csr(L, 1)));
    return 1;
}

/// \brief This is the machine.get_dhd_h_address() method implementation.
static int machine_class__index_get_dhd_h_address(lua_State *L) {
    lua_pushnumber(L, cm_get_dhd_h_address(luaL_checkinteger(L, 1)));
    return 1;
}

/// \brief Contents of the machine class metatable __index table.
static const auto machine_class_index = cartesi::clua_make_luaL_Reg_array({
    {"get_default_config", machine_class_index_get_default_config},
    {"verify_access_log", machine_class_index_verify_access_log},
    {"verify_state_transition", machine_class_index_verify_state_transition},
    {"get_x_address", machine_class_index_get_x_address},
    {"get_csr_address", machine_class_index_get_csr_address},
    {"get_dhd_h_address", machine_class_index_get_dhd_h_address},
});

/// \brief This is the cartesi.machine() constructor implementation.
/// \param L Lua state.
static int machine_ctor(lua_State *L) try {
    lua_settop(L, 3);
    // Allocate room for clua_i_virtual_machine_ptr as a Lua userdata
    auto *p = static_cast<clua_i_virtual_machine_ptr *>(
        lua_newuserdata(L, sizeof(clua_i_virtual_machine_ptr)));
    new (p) clua_i_virtual_machine_ptr();
    if (lua_type(L, 2) == LUA_TTABLE) {
        *p = std::make_unique<virtual_machine>(clua_check_machine_config(L, 2),
            clua_opt_machine_runtime_config(L, 3, {}));
    } else {
        *p = std::make_unique<virtual_machine>(luaL_checkstring(L, 2),
            clua_opt_machine_runtime_config(L, 3, {}));
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
        clua_setmethods<machine_class>(L, machine_class_index.data(), 0, ctxidx);
        static const auto machine_class_meta = cartesi::clua_make_luaL_Reg_array({
            {"__call", machine_ctor},
        });
        clua_setmetamethods<machine_class>(L, machine_class_meta.data(), 0, ctxidx);
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
