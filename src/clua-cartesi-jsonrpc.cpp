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

#include "clua-i-virtual-machine.h"
#include "clua.h"
#include "jsonrpc-machine-c-api.h"
#include "machine-c-api.h"

namespace cartesi {

/// \file
/// \brief Scripting interface for the Cartesi JSONRPC API SDK.

/// \brief This is the machine:set_timeout() method implementation.
/// \param L Lua state.
static int jsonrpc_machine_obj_index_set_timeout(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_jsonrpc_set_timeout(m.get(), luaL_checkinteger(L, 2)) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_settop(L, 1);
    return 1;
}

/// \brief This is the machine:get_timeout() method implementation.
/// \param L Lua state.
static int jsonrpc_machine_obj_index_get_timeout(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    int64_t ms = -1;
    if (cm_jsonrpc_get_timeout(m.get(), &ms) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, ms);
    return 1;
}

/// \brief This is the machine:set_cleanup_call() method implementation.
/// \param L Lua state.
static int jsonrpc_machine_obj_index_set_cleanup_call(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_jsonrpc_set_cleanup_call(m.get(), static_cast<cm_jsonrpc_cleanup_call>(luaL_checkinteger(L, 2))) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_settop(L, 1);
    return 1;
}

/// \brief This is the machine:get_cleanup_call() method implementation.
/// \param L Lua state.
static int jsonrpc_machine_obj_index_get_cleanup_call(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    cm_jsonrpc_cleanup_call call = CM_JSONRPC_NOTHING;
    if (cm_jsonrpc_get_cleanup_call(m.get(), &call) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<int>(call));
    return 1;
}

/// \brief This is the machine:get_server_version() method implementation.
static int jsonrpc_machine_obj_index_get_server_version(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *version = nullptr;
    if (cm_jsonrpc_get_server_version(m.get(), &version) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_json_table(L, version);
    return 1;
}

/// \brief This is the machine:get_server_address() method implementation.
static int jsonrpc_machine_obj_index_get_server_address(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *address = nullptr;
    if (cm_jsonrpc_get_server_address(m.get(), &address) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushstring(L, address);
    return 1;
}

/// \brief This is the machine:emancipate_server() method implementation.
/// \param L Lua state.
static int jsonrpc_machine_obj_index_emancipate_server(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_jsonrpc_emancipate_server(m.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_settop(L, 1);
    return 1;
}

/// \brief This is the machine:rebind_server() method implementation.
static int jsonrpc_machine_obj_index_rebind_server(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *address = luaL_checkstring(L, 2);
    const char *new_address = nullptr;
    if (cm_jsonrpc_rebind_server(m.get(), address, &new_address) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushstring(L, new_address);
    return 1;
}

/// \brief This is the machine:fork_server() static method implementation.
static int jsonrpc_machine_obj_index_fork_server(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    auto &new_m = clua_push_to(L, clua_managed_cm_ptr<cm_machine>(nullptr));
    const char *address = nullptr;
    uint32_t pid = 0;
    if (cm_jsonrpc_fork_server(m.get(), &new_m.get(), &address, &pid) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushstring(L, address);
    lua_pushinteger(L, pid);
    return 3;
}

/// \brief This is the machine:shutdown_server() method implementation.
static int jsonrpc_machine_obj_index_shutdown_server(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_jsonrpc_shutdown_server(m.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:delay_next_request() method implementation.
static int jsonrpc_machine_obj_index_delay_next_request(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_jsonrpc_delay_next_request(m.get(), static_cast<uint64_t>(luaL_checkinteger(L, 2))) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief Contents of the machine object metatable __index table.
static const auto jsonrpc_machine_obj_index = cartesi::clua_make_luaL_Reg_array(
    {{"set_timeout", jsonrpc_machine_obj_index_set_timeout}, {"get_timeout", jsonrpc_machine_obj_index_get_timeout},
        {"set_cleanup_call", jsonrpc_machine_obj_index_set_cleanup_call},
        {"get_cleanup_call", jsonrpc_machine_obj_index_get_cleanup_call},
        {"get_server_address", jsonrpc_machine_obj_index_get_server_address},
        {"get_server_version", jsonrpc_machine_obj_index_get_server_version},
        {"fork_server", jsonrpc_machine_obj_index_fork_server},
        {"rebind_server", jsonrpc_machine_obj_index_rebind_server},
        {"shutdown_server", jsonrpc_machine_obj_index_shutdown_server},
        {"emancipate_server", jsonrpc_machine_obj_index_emancipate_server},
        {"delay_next_request", jsonrpc_machine_obj_index_delay_next_request}});

/// \brief This is the jsonrpc.connect() method implementation.
static int mod_connect_server(lua_State *L) {
    const char *address = luaL_checkstring(L, 1);
    auto &m = clua_push_to(L, clua_managed_cm_ptr<cm_machine>(nullptr));
    if (cm_jsonrpc_connect_server(address, &m.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 1;
}

/// \brief This is the jsonrpc.spawn_server() method implementation.
static int mod_spawn_server(lua_State *L) {
    lua_settop(L, 1);
    const char *address = luaL_optstring(L, 1, "127.0.0.1:0");
    lua_newtable(L);                                                     // server
    auto &m = clua_push_to(L, clua_managed_cm_ptr<cm_machine>(nullptr)); // server object
    const char *bound_address = nullptr;
    uint32_t pid = 0;
    if (cm_jsonrpc_spawn_server(address, &m.get(), &bound_address, &pid) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushstring(L, bound_address); // server address
    lua_pushinteger(L, pid);          // server address pid
    return 3;
}

/// \brief Contents of the jsonrpc module.
static const auto mod = cartesi::clua_make_luaL_Reg_array({
    {"connect_server", mod_connect_server},
    {"spawn_server", mod_spawn_server},
});

} // namespace cartesi

extern "C" {

/// \brief Entrypoint to the Cartesi JSONRPC Lua library.
/// \param L Lua state.
CM_API int luaopen_cartesi_jsonrpc(lua_State *L) {
    using namespace cartesi;
    // Initialize clua
    clua_init(L);    // cluactx
    lua_newtable(L); // cluactx jsonrpc
    // Initialize and export jsonrpc machine bind
    clua_i_virtual_machine_export(L, -2);                                                         // cluactx jsonrpc
    clua_setmethods<clua_managed_cm_ptr<cm_machine>>(L, jsonrpc_machine_obj_index.data(), 0, -2); // cluactx jsonrpc
    // Set module functions
    lua_pushvalue(L, -2);            // cluactx jsonrpc cluactx
    luaL_setfuncs(L, mod.data(), 1); // cluactx jsonrpc
    // Set public C API constants
    clua_setintegerfield(L, CM_JSONRPC_NOTHING, "NOTHING", -1);   // jsonrpctab
    clua_setintegerfield(L, CM_JSONRPC_DESTROY, "DESTROY", -1);   // jsonrpctab
    clua_setintegerfield(L, CM_JSONRPC_SHUTDOWN, "SHUTDOWN", -1); // jsonrpctab
    return 1;
}
}
