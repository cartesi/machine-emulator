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

#include "clua-jsonrpc-machine.h"
#include "clua-machine-util.h"
#include "clua.h"
#include "jsonrpc-machine-c-api.h"

namespace cartesi {

/// \brief Deleter for C api jsonrpc stub
template <>
void clua_delete(cm_jsonrpc_mgr *ptr) {
    cm_jsonrpc_delete_mgr(ptr);
}

/// \brief This is the machine.get_default_machine_config()
/// static method implementation.
static int jsonrpc_machine_class_get_default_config(lua_State *L) {
    const int stubidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    auto &managed_jsonrpc_mgr = clua_check<clua_managed_cm_ptr<cm_jsonrpc_mgr>>(L, stubidx, ctxidx);
    const char *config = nullptr;
    if (cm_jsonrpc_get_default_config(managed_jsonrpc_mgr.get(), &config) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_json_table(L, config, ctxidx);
    return 1;
}

/// \brief This is the machine.get_reg_address() method implementation.
static int jsonrpc_machine_class_get_reg_address(lua_State *L) {
    auto &managed_jsonrpc_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    uint64_t reg_address{};
    const cm_reg reg = clua_check_cm_proc_reg(L, 1);
    if (cm_jsonrpc_get_reg_address(managed_jsonrpc_mgr.get(), reg, &reg_address) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(reg_address));
    return 1;
}

/// \brief This is the machine.verify_step_uarch()
/// static method implementation.
static int jsonrpc_machine_class_verify_step_uarch(lua_State *L) {
    const int stubidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    lua_settop(L, 5);
    auto &managed_jsonrpc_mgr = clua_check<clua_managed_cm_ptr<cm_jsonrpc_mgr>>(L, stubidx, ctxidx);
    const char *log = clua_check_schemed_json_string(L, 2, "AccessLog", ctxidx);
    if (!lua_isnil(L, 1) || !lua_isnil(L, 3)) {
        cm_hash root_hash{};
        clua_check_cm_hash(L, 1, &root_hash);
        cm_hash target_hash{};
        clua_check_cm_hash(L, 3, &target_hash);
        if (cm_jsonrpc_verify_step_uarch(managed_jsonrpc_mgr.get(), &root_hash, log, &target_hash) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    } else {
        if (cm_jsonrpc_verify_step_uarch(managed_jsonrpc_mgr.get(), nullptr, log, nullptr) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    }
    return 0;
}

/// \brief This is the machine.verify_reset_uarch()
/// static method implementation.
static int jsonrpc_machine_class_verify_reset_uarch(lua_State *L) {
    const int stubidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    lua_settop(L, 5);
    auto &managed_jsonrpc_mgr = clua_check<clua_managed_cm_ptr<cm_jsonrpc_mgr>>(L, stubidx, ctxidx);
    const char *log = clua_check_schemed_json_string(L, 2, "AccessLog", ctxidx);
    if (!lua_isnil(L, 1) || !lua_isnil(L, 3)) {
        cm_hash root_hash{};
        clua_check_cm_hash(L, 1, &root_hash);
        cm_hash target_hash{};
        clua_check_cm_hash(L, 3, &target_hash);
        if (cm_jsonrpc_verify_reset_uarch(managed_jsonrpc_mgr.get(), &root_hash, log, &target_hash) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    } else {
        if (cm_jsonrpc_verify_reset_uarch(managed_jsonrpc_mgr.get(), nullptr, log, nullptr) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    }
    return 0;
}

/// \brief This is the machine.verify_send_cmio_response()
/// static method implementation.
static int jsonrpc_machine_class_verify_send_cmio_response(lua_State *L) {
    const int stubidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    lua_settop(L, 6);
    auto &managed_jsonrpc_mgr = clua_check<clua_managed_cm_ptr<cm_jsonrpc_mgr>>(L, stubidx, ctxidx);
    const uint16_t reason = static_cast<uint16_t>(luaL_checkinteger(L, 1));
    uint64_t length{0};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 2, &length));
    const char *log = clua_check_schemed_json_string(L, 4, "AccessLog", ctxidx);
    if (!lua_isnil(L, 3) || !lua_isnil(L, 5)) {
        cm_hash root_hash{};
        clua_check_cm_hash(L, 3, &root_hash);
        cm_hash target_hash{};
        clua_check_cm_hash(L, 5, &target_hash);
        if (cm_jsonrpc_verify_send_cmio_response(managed_jsonrpc_mgr.get(), reason, data, length, &root_hash, log,
                &target_hash) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    } else {
        if (cm_jsonrpc_verify_send_cmio_response(managed_jsonrpc_mgr.get(), reason, data, length, nullptr, log,
                nullptr) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
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
    const int stubidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    lua_settop(L, 3);
    auto &managed_jsonrpc_mgr = clua_check<clua_managed_cm_ptr<cm_jsonrpc_mgr>>(L, stubidx, ctxidx);
    auto &managed_machine = clua_push_to(L, clua_managed_cm_ptr<cm_machine>(nullptr), ctxidx);
    const char *runtime_config = !lua_isnil(L, 3) ? clua_check_json_string(L, 3, -1, ctxidx) : nullptr;
    if (!lua_isstring(L, 2)) {
        const char *config = clua_check_json_string(L, 2, -1, ctxidx);
        if (cm_jsonrpc_create_machine(managed_jsonrpc_mgr.get(), config, runtime_config, &managed_machine.get()) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    } else {
        const char *dir = luaL_checkstring(L, 2);
        if (cm_jsonrpc_load_machine(managed_jsonrpc_mgr.get(), dir, runtime_config, &managed_machine.get()) != 0) {
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
static int jsonrpc_server_class_get_machine(lua_State *L) {
    lua_settop(L, 1);
    auto &managed_jsonrpc_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    const int ctxidx = lua_upvalueindex(2);
    auto &managed_machine = clua_push_to(L, clua_managed_cm_ptr<cm_machine>(nullptr), ctxidx);
    if (cm_jsonrpc_get_machine(managed_jsonrpc_mgr.get(), &managed_machine.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 1;
}

/// \brief This is the machine.get_version() static method implementation.
static int jsonrpc_server_class_get_version(lua_State *L) {
    const int stubidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    auto &managed_jsonrpc_mgr = clua_check<clua_managed_cm_ptr<cm_jsonrpc_mgr>>(L, stubidx, ctxidx);
    const char *version = nullptr;
    if (cm_jsonrpc_get_version(managed_jsonrpc_mgr.get(), &version) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_json_table(L, version, ctxidx);
    return 1;
}

/// \brief This is the machine.shutdown() static method implementation.
static int jsonrpc_server_class_shutdown(lua_State *L) {
    auto &managed_jsonrpc_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    if (cm_jsonrpc_shutdown(managed_jsonrpc_mgr.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the rebind method implementation.
static int jsonrpc_server_class_rebind(lua_State *L) {
    auto &managed_jsonrpc_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    const char *address = luaL_checkstring(L, 1);
    const char *new_address = nullptr;
    if (cm_jsonrpc_rebind(managed_jsonrpc_mgr.get(), address, &new_address) != 0) {
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
static int jsonrpc_server_class_fork(lua_State *L) {
    auto &managed_jsonrpc_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    const char *address = nullptr;
    int32_t pid = 0;
    if (cm_jsonrpc_fork(managed_jsonrpc_mgr.get(), &address, &pid) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushstring(L, address);
    lua_pushinteger(L, pid);
    return 2;
}

/// \brief JSONRPC server static methods
static const auto jsonrpc_server_static_methods = cartesi::clua_make_luaL_Reg_array({
    {"get_machine", jsonrpc_server_class_get_machine},
    {"get_version", jsonrpc_server_class_get_version},
    {"shutdown", jsonrpc_server_class_shutdown},
    {"fork", jsonrpc_server_class_fork},
    {"rebind", jsonrpc_server_class_rebind},
});

/// \brief This is the jsonrpc.stub() method implementation.
static int mod_stub(lua_State *L) {
    const char *remote_address = luaL_checkstring(L, 1);
    // Create stub
    auto &managed_jsonrpc_mgr = clua_push_to(L, clua_managed_cm_ptr<cm_jsonrpc_mgr>(nullptr));
    if (cm_jsonrpc_create_mgr(remote_address, &managed_jsonrpc_mgr.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_newtable(L);                                            // stub server
    lua_newtable(L);                                            // stub server jsonrpc_machine_class
    lua_pushvalue(L, -3);                                       // stub server jsonrpc_machine_class stub
    lua_pushvalue(L, lua_upvalueindex(1));                      // stub server jsonrpc_machine_class stub cluactx
    luaL_setfuncs(L, jsonrpc_machine_static_methods.data(), 2); // stub server jsonrpc_machine_class
    lua_newtable(L);                                            // stub server jsonrpc_machine_class meta
    lua_pushvalue(L, -4);                                       // stub server jsonrpc_machine_class meta stub
    lua_pushvalue(L, lua_upvalueindex(1));                      // stub server jsonrpc_machine_class meta stub cluactx
    luaL_setfuncs(L, jsonrpc_machine_class_meta.data(), 2);     // stub server jsonrpc_machine_class meta
    lua_setmetatable(L, -2);                                    // stub server jsonrpc_machine_class
    lua_setfield(L, -2, "machine");                             // stub server
    lua_pushvalue(L, -2);                                       // stub server stub
    lua_pushvalue(L, lua_upvalueindex(1));                      // stub server stub cluactx
    luaL_setfuncs(L, jsonrpc_server_static_methods.data(), 2);
    return 1;
}

/// \brief Contents of the jsonrpc module.
static const auto mod = cartesi::clua_make_luaL_Reg_array({
    {"stub", mod_stub},
});

int clua_jsonrpc_machine_init(lua_State *L, int ctxidx) {
    clua_createnewtype<clua_managed_cm_ptr<unsigned char>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<std::string>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<nlohmann::json>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<cm_jsonrpc_mgr>>(L, ctxidx);
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
