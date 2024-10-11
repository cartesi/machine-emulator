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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "clua-jsonrpc-machine.h"
#include "clua-machine-util.h"
#include "clua.h"
#include "jsonrpc-machine-c-api.h"
#include "machine-c-api.h"

namespace cartesi {

/// \brief Deleter for C api jsonrpc connection
template <>
void clua_delete(cm_jsonrpc_connection *ptr) {
    cm_jsonrpc_release_connection(ptr);
}

/// \brief This is the machine.get_default_machine_config()
/// static method implementation.
static int jsonrpc_machine_class_get_default_config(lua_State *L) {
    const int conidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    auto &managed_jsonrpc_connection = clua_check<clua_managed_cm_ptr<cm_jsonrpc_connection>>(L, conidx, ctxidx);
    const char *config = nullptr;
    if (cm_jsonrpc_get_default_config(managed_jsonrpc_connection.get(), &config) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_json_table(L, config, ctxidx);
    return 1;
}

/// \brief This is the machine.get_reg_address() method implementation.
static int jsonrpc_machine_class_get_reg_address(lua_State *L) {
    auto &managed_jsonrpc_connection =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_connection>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    uint64_t reg_address{};
    const cm_reg reg = clua_check_cm_proc_reg(L, 1);
    if (cm_jsonrpc_get_reg_address(managed_jsonrpc_connection.get(), reg, &reg_address) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(reg_address));
    return 1;
}

/// \brief This is the machine.verify_step_uarch()
/// static method implementation.
static int jsonrpc_machine_class_verify_step_uarch(lua_State *L) {
    const int conidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    lua_settop(L, 5);
    auto &managed_jsonrpc_connection = clua_check<clua_managed_cm_ptr<cm_jsonrpc_connection>>(L, conidx, ctxidx);
    const char *log = clua_check_schemed_json_string(L, 2, "AccessLog", ctxidx);
    cm_hash root_hash{};
    clua_check_cm_hash(L, 1, &root_hash);
    cm_hash target_hash{};
    clua_check_cm_hash(L, 3, &target_hash);
    if (cm_jsonrpc_verify_step_uarch(managed_jsonrpc_connection.get(), &root_hash, log, &target_hash) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine.verify_reset_uarch()
/// static method implementation.
static int jsonrpc_machine_class_verify_reset_uarch(lua_State *L) {
    const int conidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    lua_settop(L, 5);
    auto &managed_jsonrpc_connection = clua_check<clua_managed_cm_ptr<cm_jsonrpc_connection>>(L, conidx, ctxidx);
    const char *log = clua_check_schemed_json_string(L, 2, "AccessLog", ctxidx);
    cm_hash root_hash{};
    clua_check_cm_hash(L, 1, &root_hash);
    cm_hash target_hash{};
    clua_check_cm_hash(L, 3, &target_hash);
    if (cm_jsonrpc_verify_reset_uarch(managed_jsonrpc_connection.get(), &root_hash, log, &target_hash) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine.verify_send_cmio_response()
/// static method implementation.
static int jsonrpc_machine_class_verify_send_cmio_response(lua_State *L) {
    const int conidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    lua_settop(L, 6);
    auto &managed_jsonrpc_connection = clua_check<clua_managed_cm_ptr<cm_jsonrpc_connection>>(L, conidx, ctxidx);
    const uint16_t reason = static_cast<uint16_t>(luaL_checkinteger(L, 1));
    size_t length{0};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 2, &length));
    const char *log = clua_check_schemed_json_string(L, 4, "AccessLog", ctxidx);
    cm_hash root_hash{};
    clua_check_cm_hash(L, 3, &root_hash);
    cm_hash target_hash{};
    clua_check_cm_hash(L, 5, &target_hash);
    if (cm_jsonrpc_verify_send_cmio_response(managed_jsonrpc_connection.get(), reason, data, length, &root_hash, log,
            &target_hash) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief Contents of the machine class metatable __index table.
static const auto jsonrpc_machine_static_methods = cartesi::clua_make_luaL_Reg_array({
    {"get_default_config", jsonrpc_machine_class_get_default_config},
    {"get_reg_address", jsonrpc_machine_class_get_reg_address},
    {"verify_step_uarch", jsonrpc_machine_class_verify_step_uarch},
    {"verify_reset_uarch", jsonrpc_machine_class_verify_reset_uarch},
    {"verify_send_cmio_response", jsonrpc_machine_class_verify_send_cmio_response},
});

/// \brief Prints a JSONRPC machine class
/// \param L Lua state.
static int jsonrpc_machine_tostring(lua_State *L) {
    lua_pushliteral(L, "JSONRPC machine class");
    return 1;
}

/// \brief This is the cartesi.machine() constructor implementation.
/// \param L Lua state.
static int jsonrpc_machine_ctor(lua_State *L) {
    const int conidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    lua_settop(L, 3);
    auto &managed_jsonrpc_connection = clua_check<clua_managed_cm_ptr<cm_jsonrpc_connection>>(L, conidx, ctxidx);
    auto &managed_machine = clua_push_to(L, clua_managed_cm_ptr<cm_machine>(nullptr), ctxidx);
    const char *runtime_config = !lua_isnil(L, 3) ? clua_check_json_string(L, 3, -1, ctxidx) : nullptr;
    if (!lua_isstring(L, 2)) {
        const char *config = clua_check_json_string(L, 2, -1, ctxidx);
        if (cm_jsonrpc_create_machine(managed_jsonrpc_connection.get(), config, runtime_config,
                &managed_machine.get()) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    } else {
        const char *dir = luaL_checkstring(L, 2);
        if (cm_jsonrpc_load_machine(managed_jsonrpc_connection.get(), dir, runtime_config, &managed_machine.get()) !=
            0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    }
    return 1;
}

/// \brief Contents of the jsonrpc machine class metatable.
static const auto jsonrpc_machine_class_meta = cartesi::clua_make_luaL_Reg_array({
    {"__call", jsonrpc_machine_ctor},
    {"__tostring", jsonrpc_machine_tostring},
});

/// \brief This is the machine.get_machine() static method implementation.
static int jsonrpc_connection_class_get_machine(lua_State *L) {
    lua_settop(L, 1);
    auto &managed_jsonrpc_connection =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_connection>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    const int ctxidx = lua_upvalueindex(2);
    auto &managed_machine = clua_push_to(L, clua_managed_cm_ptr<cm_machine>(nullptr), ctxidx);
    if (cm_jsonrpc_get_machine(managed_jsonrpc_connection.get(), &managed_machine.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 1;
}

/// \brief This is the machine.get_version() static method implementation.
static int jsonrpc_connection_class_get_version(lua_State *L) {
    const int conidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    auto &managed_jsonrpc_connection = clua_check<clua_managed_cm_ptr<cm_jsonrpc_connection>>(L, conidx, ctxidx);
    const char *version = nullptr;
    if (cm_jsonrpc_get_version(managed_jsonrpc_connection.get(), &version) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_json_table(L, version, ctxidx);
    return 1;
}

/// \brief This is the rebind method implementation.
static int jsonrpc_connection_class_rebind(lua_State *L) {
    auto &managed_jsonrpc_connection =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_connection>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    const char *address = luaL_checkstring(L, 1);
    const char *new_address = nullptr;
    if (cm_jsonrpc_rebind(managed_jsonrpc_connection.get(), address, &new_address) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    if (new_address) {
        lua_pushstring(L, new_address);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

/// \brief This is the fork method implementation.
static int jsonrpc_connection_class_fork(lua_State *L) {
    auto &managed_jsonrpc_connection =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_connection>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    const char *address = nullptr;
    int32_t pid = 0;
    if (cm_jsonrpc_fork(managed_jsonrpc_connection.get(), &address, &pid) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushstring(L, address);
    lua_pushinteger(L, pid);
    return 2;
}

/// \brief JSONRPC connection static methods
static const auto jsonrpc_connection_static_methods = cartesi::clua_make_luaL_Reg_array({
    {"get_machine", jsonrpc_connection_class_get_machine},
    {"get_version", jsonrpc_connection_class_get_version},
    {"fork", jsonrpc_connection_class_fork},
    {"rebind", jsonrpc_connection_class_rebind},
});

/// \brief Takes underlying cm_jsonrpc_connection in top of stack and encapsulates it in its Lua interface
static void wrap_jsonrpc_connection(lua_State *L) {
    lua_newtable(L);                                               // ccon luacon
    lua_newtable(L);                                               // ccon luacon mtab
    lua_pushvalue(L, -3);                                          // ccon luacon mtab ccon
    lua_pushvalue(L, lua_upvalueindex(1));                         // ccon luacon mtab ccon cluactx
    luaL_setfuncs(L, jsonrpc_machine_static_methods.data(), 2);    // ccon luacon mtab
    lua_newtable(L);                                               // ccon luacon mtab mmeta
    lua_pushvalue(L, -4);                                          // ccon luacon mtab mmeta ccon
    lua_pushvalue(L, lua_upvalueindex(1));                         // ccon luacon mtab mmeta ccon cluactx
    luaL_setfuncs(L, jsonrpc_machine_class_meta.data(), 2);        // ccon luacon mtab mmeta
    lua_setmetatable(L, -2);                                       // ccon luacon mtab
    lua_setfield(L, -2, "machine");                                // ccon luacon
    lua_pushvalue(L, -2);                                          // ccon luacon ccon
    lua_pushvalue(L, lua_upvalueindex(1));                         // ccon luacon ccon cluactx
    luaL_setfuncs(L, jsonrpc_connection_static_methods.data(), 2); // ccon luacon
    lua_insert(L, -2);                                             // luacon ccon
    lua_pop(L, 1);                                                 // luacon
}

static cm_jsonrpc_manage check_cm_jsonrpc_manage(lua_State *L, int idx) {
    const char *strwhat = luaL_checkstring(L, idx);
    if (strcmp(strwhat, "server") == 0) {
        return CM_JSONRPC_MANAGE_SERVER;
    } else if (strcmp(strwhat, "machine") == 0) {
        return CM_JSONRPC_MANAGE_MACHINE;
    } else if (strcmp(strwhat, "none") == 0) {
        return CM_JSONRPC_MANAGE_NONE;
    } else {
        luaL_argerror(L, idx, R"(expected "server", "machine", or "none")");
        return CM_JSONRPC_MANAGE_SERVER;
    }
}

/// \brief This is the jsonrpc.connect() method implementation.
static int mod_connect(lua_State *L) {
    // create and push the underlying cm_jsonrpc_connection
    const char *address = luaL_checkstring(L, 1);
    auto what = check_cm_jsonrpc_manage(L, 2);
    auto &managed_jsonrpc_connection = clua_push_to(L, clua_managed_cm_ptr<cm_jsonrpc_connection>(nullptr));
    if (cm_jsonrpc_connect(address, what, &managed_jsonrpc_connection.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    // wrap it into its Lua interface
    wrap_jsonrpc_connection(L);
    return 1;
}

/// \brief This is the jsonrpc.connect() method implementation.
static int mod_spawn(lua_State *L) {
    const char *address = luaL_checkstring(L, 1);
    auto what = check_cm_jsonrpc_manage(L, 2);
    // create and push the underlying cm_jsonrpc_connection
    auto &managed_jsonrpc_connection = clua_push_to(L, clua_managed_cm_ptr<cm_jsonrpc_connection>(nullptr));
    const char *bound_address = nullptr;
    int32_t pid = 0;
    if (cm_jsonrpc_spawn(address, what, &managed_jsonrpc_connection.get(), &bound_address, &pid) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    // wrap it into its Lua interface
    wrap_jsonrpc_connection(L);
    lua_pushstring(L, bound_address);
    lua_pushinteger(L, pid);
    return 3;
}

/// \brief Contents of the jsonrpc module.
static const auto mod = cartesi::clua_make_luaL_Reg_array({
    {"connect", mod_connect},
    {"spawn", mod_spawn},
});

//    jsonrpc.connect()
//        return connection object
//    jsonrpc.spawn()
//        return connection object, bound address, pid
//
//    connection object
//        machine
//            either load or create new machine
//        get_machine
//            return existing machine object
//        get_version
//        manage
//        rebind
//        fork
//        __gc/__close call release on connection
//
//    machine object
//        all methods of normal machine
//        get_connection
//        destroy?
//        __gc/__close call release on connection

int clua_jsonrpc_machine_init(lua_State *L, int ctxidx) {
    clua_createnewtype<clua_managed_cm_ptr<unsigned char>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<std::string>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<nlohmann::json>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<cm_jsonrpc_connection>>(L, ctxidx);
    return 1;
}

int clua_jsonrpc_machine_export(lua_State *L, int ctxidx) {
    const int ctxabsidx = lua_absindex(L, ctxidx);
    // jsonrpc
    clua_jsonrpc_machine_init(L, ctxabsidx); // jsonrpc
    lua_pushvalue(L, ctxabsidx);             // jsonrpc cluactx
    luaL_setfuncs(L, mod.data(), 1);         // jsonrpc
    return 0;
}

} // namespace cartesi
