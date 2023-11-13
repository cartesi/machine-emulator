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
#include "clua-htif.h"
#include "clua-i-virtual-machine.h"
#include "clua-machine-util.h"
#include "clua.h"
#include "jsonrpc-machine-c-api.h"

namespace cartesi {

/// \brief Deleter for C api jsonrpc stub
template <>
void cm_delete(cm_jsonrpc_mg_mgr *ptr) {
    cm_delete_jsonrpc_mg_mgr(ptr);
}

/// \brief This is the machine.get_default_machine_config()
/// static method implementation.
static int jsonrpc_machine_class_get_default_config(lua_State *L) {
    auto &managed_jsonrpc_mg_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    auto &managed_default_config =
        clua_push_to(L, clua_managed_cm_ptr<const cm_machine_config>(nullptr), lua_upvalueindex(2));
    TRY_EXECUTE(cm_jsonrpc_get_default_config(managed_jsonrpc_mg_mgr.get(), &managed_default_config.get(), err_msg));
    clua_push_cm_machine_config(L, managed_default_config.get());
    managed_default_config.reset();
    return 1;
}

/// \brief This is the machine.verify_uarch_step_log()
/// static method implementation.
static int jsonrpc_machine_class_verify_uarch_step_log(lua_State *L) {
    const int stubidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    lua_settop(L, 3);
    auto &managed_jsonrpc_mg_mgr = clua_check<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, stubidx, ctxidx);
    auto &managed_log =
        clua_push_to(L, clua_managed_cm_ptr<cm_access_log>(clua_check_cm_access_log(L, 1, ctxidx)), ctxidx);
    auto &managed_runtime_config = clua_push_to(L,
        clua_managed_cm_ptr<cm_machine_runtime_config>(clua_opt_cm_machine_runtime_config(L, 2, {}, ctxidx)), ctxidx);
    TRY_EXECUTE(cm_jsonrpc_verify_uarch_step_log(managed_jsonrpc_mg_mgr.get(), managed_log.get(),
        managed_runtime_config.get(), true, err_msg));
    managed_log.reset();
    managed_runtime_config.reset();
    lua_pop(L, 2);
    lua_pushnumber(L, 1);
    return 1;
}

/// \brief This is the machine.verify_uarch_reset_log()
/// static method implementation.
static int jsonrpc_machine_class_verify_uarch_reset_log(lua_State *L) {
    const int stubidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    lua_settop(L, 3);
    auto &managed_jsonrpc_mg_mgr = clua_check<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, stubidx, ctxidx);
    auto &managed_log =
        clua_push_to(L, clua_managed_cm_ptr<cm_access_log>(clua_check_cm_access_log(L, 1, ctxidx)), ctxidx);
    auto &managed_runtime_config = clua_push_to(L,
        clua_managed_cm_ptr<cm_machine_runtime_config>(clua_opt_cm_machine_runtime_config(L, 2, {}, ctxidx)), ctxidx);
    TRY_EXECUTE(cm_jsonrpc_verify_uarch_reset_log(managed_jsonrpc_mg_mgr.get(), managed_log.get(),
        managed_runtime_config.get(), true, err_msg));
    managed_log.reset();
    managed_runtime_config.reset();
    lua_pop(L, 2);
    lua_pushnumber(L, 1);
    return 1;
}

/// \brief This is the machine.verify_uarch_step_state_transition()
/// static method implementation.
static int jsonrpc_machine_class_verify_uarch_step_state_transition(lua_State *L) {
    const int stubidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    lua_settop(L, 5);
    auto &managed_jsonrpc_mg_mgr = clua_check<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, stubidx, ctxidx);
    cm_hash root_hash{};
    clua_check_cm_hash(L, 1, &root_hash);
    auto &managed_log =
        clua_push_to(L, clua_managed_cm_ptr<cm_access_log>(clua_check_cm_access_log(L, 2, ctxidx)), ctxidx);
    cm_hash target_hash{};
    clua_check_cm_hash(L, 3, &target_hash);
    auto &managed_runtime_config = clua_push_to(L,
        clua_managed_cm_ptr<cm_machine_runtime_config>(clua_opt_cm_machine_runtime_config(L, 4, {}, ctxidx)), ctxidx);
    TRY_EXECUTE(cm_jsonrpc_verify_uarch_step_state_transition(managed_jsonrpc_mg_mgr.get(), &root_hash,
        managed_log.get(), &target_hash, managed_runtime_config.get(), true, err_msg));
    managed_log.reset();
    managed_runtime_config.reset();
    lua_pop(L, 2);
    lua_pushnumber(L, 1); // result
    return 1;
}

/// \brief This is the machine.verify_uarch_reset_state_transition()
/// static method implementation.
static int jsonrpc_machine_class_verify_uarch_reset_state_transition(lua_State *L) {
    const int stubidx = lua_upvalueindex(1);
    const int ctxidx = lua_upvalueindex(2);
    lua_settop(L, 5);
    auto &managed_jsonrpc_mg_mgr = clua_check<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, stubidx, ctxidx);
    cm_hash root_hash{};
    clua_check_cm_hash(L, 1, &root_hash);
    auto &managed_log =
        clua_push_to(L, clua_managed_cm_ptr<cm_access_log>(clua_check_cm_access_log(L, 2, ctxidx)), ctxidx);
    cm_hash target_hash{};
    clua_check_cm_hash(L, 3, &target_hash);
    auto &managed_runtime_config = clua_push_to(L,
        clua_managed_cm_ptr<cm_machine_runtime_config>(clua_opt_cm_machine_runtime_config(L, 4, {}, ctxidx)), ctxidx);
    TRY_EXECUTE(cm_jsonrpc_verify_uarch_reset_state_transition(managed_jsonrpc_mg_mgr.get(), &root_hash,
        managed_log.get(), &target_hash, managed_runtime_config.get(), true, err_msg));
    managed_log.reset();
    managed_runtime_config.reset();
    lua_pop(L, 2);
    lua_pushnumber(L, 1); // result
    return 1;
}

/// \brief This is the machine.get_x_address() method implementation.
static int jsonrpc_machine_class_get_x_address(lua_State *L) {
    auto &managed_jsonrpc_mg_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    uint64_t reg_address{};
    TRY_EXECUTE(cm_jsonrpc_get_x_address(managed_jsonrpc_mg_mgr.get(), luaL_checkinteger(L, 1), &reg_address, err_msg));
    lua_pushinteger(L, static_cast<lua_Integer>(reg_address));
    return 1;
}

/// \brief This is the machine.get_f_address() method implementation.
static int jsonrpc_machine_class_get_f_address(lua_State *L) {
    auto &managed_jsonrpc_mg_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    uint64_t reg_address{};
    TRY_EXECUTE(cm_jsonrpc_get_f_address(managed_jsonrpc_mg_mgr.get(), luaL_checkinteger(L, 1), &reg_address, err_msg));
    lua_pushinteger(L, static_cast<lua_Integer>(reg_address));
    return 1;
}

/// \brief This is the machine.get_uarch_x_address() method implementation.
static int jsonrpc_machine_class_get_uarch_x_address(lua_State *L) {
    auto &managed_jsonrpc_mg_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    uint64_t reg_address{};
    TRY_EXECUTE(
        cm_jsonrpc_get_uarch_x_address(managed_jsonrpc_mg_mgr.get(), luaL_checkinteger(L, 1), &reg_address, err_msg));
    lua_pushinteger(L, static_cast<lua_Integer>(reg_address));
    return 1;
}

/// \brief This is the machine.get_csr_address() method implementation.
static int jsonrpc_machine_class_get_csr_address(lua_State *L) {
    auto &managed_jsonrpc_mg_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    uint64_t csr_address{};
    const CM_PROC_CSR csr = clua_check_cm_proc_csr(L, 1);
    TRY_EXECUTE(cm_jsonrpc_get_csr_address(managed_jsonrpc_mg_mgr.get(), csr, &csr_address, err_msg));
    lua_pushinteger(L, static_cast<lua_Integer>(csr_address));
    return 1;
}

/// \brief Contents of the machine class metatable __index table.
static const auto jsonrpc_machine_static_methods = cartesi::clua_make_luaL_Reg_array({
    {"get_default_config", jsonrpc_machine_class_get_default_config},
    {"verify_uarch_step_log", jsonrpc_machine_class_verify_uarch_step_log},
    {"verify_uarch_step_state_transition", jsonrpc_machine_class_verify_uarch_step_state_transition},
    {"verify_uarch_reset_log", jsonrpc_machine_class_verify_uarch_reset_log},
    {"verify_uarch_reset_state_transition", jsonrpc_machine_class_verify_uarch_reset_state_transition},
    {"get_x_address", jsonrpc_machine_class_get_x_address},
    {"get_f_address", jsonrpc_machine_class_get_f_address},
    {"get_uarch_x_address", jsonrpc_machine_class_get_uarch_x_address},
    {"get_csr_address", jsonrpc_machine_class_get_csr_address},
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
    lua_settop(L, 3);
    auto &managed_jsonrpc_mg_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    const int ctxidx = lua_upvalueindex(2);
    auto &managed_machine = clua_push_to(L, clua_managed_cm_ptr<cm_machine>(nullptr), ctxidx);
    auto &managed_runtime_config = clua_push_to(L,
        clua_managed_cm_ptr<cm_machine_runtime_config>(clua_opt_cm_machine_runtime_config(L, 3, {}, ctxidx)), ctxidx);
    if (lua_type(L, 2) == LUA_TTABLE) {
        auto &managed_config =
            clua_push_to(L, clua_managed_cm_ptr<cm_machine_config>(clua_check_cm_machine_config(L, 2, ctxidx)), ctxidx);
        TRY_EXECUTE(cm_create_jsonrpc_machine(managed_jsonrpc_mg_mgr.get(), managed_config.get(),
            managed_runtime_config.get(), &managed_machine.get(), err_msg));
        managed_config.reset();
        managed_runtime_config.reset();
        lua_pop(L, 2);
    } else {
        TRY_EXECUTE(cm_load_jsonrpc_machine(managed_jsonrpc_mg_mgr.get(), luaL_checkstring(L, 2),
            managed_runtime_config.get(), &managed_machine.get(), err_msg));
        managed_runtime_config.reset();
        lua_pop(L, 1);
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
    auto &managed_jsonrpc_mg_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    const int ctxidx = lua_upvalueindex(2);
    auto &managed_machine = clua_push_to(L, clua_managed_cm_ptr<cm_machine>(nullptr), ctxidx);
    TRY_EXECUTE(cm_get_jsonrpc_machine(managed_jsonrpc_mg_mgr.get(), &managed_machine.get(), err_msg));
    return 1;
}

/// \brief This is the machine.get_version() static method implementation.
static int jsonrpc_server_class_get_version(lua_State *L) {
    auto &managed_jsonrpc_mg_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    auto &managed_version =
        clua_push_to(L, clua_managed_cm_ptr<const cm_semantic_version>(nullptr), lua_upvalueindex(2));
    TRY_EXECUTE(cm_jsonrpc_get_semantic_version(managed_jsonrpc_mg_mgr.get(), &managed_version.get(), err_msg));
    clua_push_cm_semantic_version(L, managed_version.get());
    managed_version.reset();
    return 1;
}

/// \brief This is the machine.shutdown() static method implementation.
static int jsonrpc_server_class_shutdown(lua_State *L) {
    auto &managed_jsonrpc_mg_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    TRY_EXECUTE(cm_jsonrpc_shutdown(managed_jsonrpc_mg_mgr.get(), err_msg));
    lua_pushnumber(L, 1);
    return 1;
}

/// \brief This is the fork method implementation.
static int jsonrpc_server_class_fork(lua_State *L) {
    auto &managed_jsonrpc_mg_mgr =
        clua_check<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    char *address = nullptr;
    TRY_EXECUTE(cm_jsonrpc_fork(managed_jsonrpc_mg_mgr.get(), &address, err_msg));
    lua_pushstring(L, address);
    cm_delete_cstring(address);
    return 1;
}

/// \brief JSONRPC server static methods
static const auto jsonrpc_server_static_methods = cartesi::clua_make_luaL_Reg_array({
    {"get_machine", jsonrpc_server_class_get_machine},
    {"get_version", jsonrpc_server_class_get_version},
    {"shutdown", jsonrpc_server_class_shutdown},
    {"fork", jsonrpc_server_class_fork},
});

/// \brief This is the jsonrpc.stub() method implementation.
static int mod_stub(lua_State *L) {
    const char *remote_address = luaL_checkstring(L, 1);
    // Create stub
    auto &managed_jsonrpc_mg_mgr = clua_push_to(L, clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>(nullptr));
    TRY_EXECUTE(cm_create_jsonrpc_mg_mgr(remote_address, &managed_jsonrpc_mg_mgr.get(), err_msg));
    lua_newtable(L);                                            // stub server
    lua_newtable(L);                                            // stub server jsonrpc_machine_class
    lua_pushvalue(L, -3);                                       // stub server jsonrpc_machine_class stub
    lua_pushvalue(L, lua_upvalueindex(1));                      // stub server jsonrpc_machine_class stub cluactx
    luaL_setfuncs(L, jsonrpc_machine_static_methods.data(), 2); // stub server jsonrpc_machine_class
    clua_htif_export(L, lua_upvalueindex(1));                   // stub server jsonrpc_machine_class
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
    clua_createnewtype<clua_managed_cm_ptr<const cm_machine_config>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<cm_machine_config>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<cm_access_log>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<cm_machine_runtime_config>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<cm_merkle_tree_proof>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<char>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<unsigned char>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<cm_memory_range_config>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<const cm_semantic_version>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<cm_jsonrpc_mg_mgr>>(L, ctxidx);
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
