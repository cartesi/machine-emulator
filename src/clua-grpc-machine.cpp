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

#include "clua-grpc-machine.h"
#include "clua-htif.h"
#include "clua-i-virtual-machine.h"
#include "clua-machine-util.h"
#include "clua.h"
#include "grpc-machine-c-api.h"

namespace cartesi {

/// \brief Deleter for C api semantic version
template <>
void cm_delete(const cm_semantic_version *p) {
    cm_delete_semantic_version(p);
}

/// \brief Deleter for C api grpc stub
template <>
void cm_delete(cm_grpc_machine_stub *ptr) {
    cm_delete_grpc_machine_stub(ptr);
}

/// \brief This is the machine.get_default_machine_config()
/// static method implementation.
static int grpc_machine_class_get_default_config(lua_State *L) {
    auto &managed_grpc_stub =
        clua_check<clua_managed_cm_ptr<cm_grpc_machine_stub>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    auto &managed_default_config = clua_push_to(L, clua_managed_cm_ptr<const cm_machine_config>(nullptr));
    TRY_EXECUTE(cm_grpc_get_default_config(managed_grpc_stub.get(), &managed_default_config.get(), err_msg));
    clua_push_cm_machine_config(L, managed_default_config.get());
    managed_default_config.reset();
    return 1;
}

/// \brief This is the machine.verify_access_log()
/// static method implementation.
static int grpc_machine_class_verify_access_log(lua_State *L) {
    lua_settop(L, 2);
    auto &managed_grpc_stub =
        clua_check<clua_managed_cm_ptr<cm_grpc_machine_stub>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    auto &managed_log = clua_push_to(L, clua_managed_cm_ptr<cm_access_log>(clua_check_cm_access_log(L, 1)));
    TRY_EXECUTE(cm_grpc_verify_access_log(managed_grpc_stub.get(), managed_log.get(), lua_toboolean(L, 2), err_msg));
    managed_log.reset();
    lua_pop(L, 1); // managed pointer
    lua_pushnumber(L, 1);
    return 1;
}

/// \brief This is the machine.verify_state_transition()
/// static method implementation.
static int grpc_machine_class_verify_state_transition(lua_State *L) {
    lua_settop(L, 4);
    auto &managed_grpc_stub =
        clua_check<clua_managed_cm_ptr<cm_grpc_machine_stub>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    cm_hash root_hash{};
    clua_check_cm_hash(L, 1, &root_hash);
    auto &managed_log = clua_push_to(L, clua_managed_cm_ptr<cm_access_log>(clua_check_cm_access_log(L, 2)));
    cm_hash target_hash{};
    clua_check_cm_hash(L, 3, &target_hash);
    const bool one_based = lua_toboolean(L, 4);
    TRY_EXECUTE(cm_grpc_verify_state_transition(managed_grpc_stub.get(), &root_hash, managed_log.get(), &target_hash,
        one_based, err_msg));
    managed_log.reset();
    lua_pop(L, 1);        // managed pointer
    lua_pushnumber(L, 1); // result
    return 1;
}

/// \brief This is the machine.get_x_address() method implementation.
static int grpc_machine_class_get_x_address(lua_State *L) {
    auto &managed_grpc_stub =
        clua_check<clua_managed_cm_ptr<cm_grpc_machine_stub>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    uint64_t reg_address{};
    TRY_EXECUTE(cm_grpc_get_x_address(managed_grpc_stub.get(), luaL_checkinteger(L, 1), &reg_address, err_msg));
    lua_pushinteger(L, static_cast<lua_Integer>(reg_address));
    return 1;
}

/// \brief This is the machine.get_csr_address() method implementation.
static int grpc_machine_class_get_csr_address(lua_State *L) {
    auto &managed_grpc_stub =
        clua_check<clua_managed_cm_ptr<cm_grpc_machine_stub>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    uint64_t csr_address{};
    const CM_PROC_CSR csr = clua_check_cm_proc_csr(L, 1);
    TRY_EXECUTE(cm_grpc_get_csr_address(managed_grpc_stub.get(), csr, &csr_address, err_msg));
    lua_pushinteger(L, static_cast<lua_Integer>(csr_address));
    return 1;
}

/// \brief This is the machine.get_x_address() method implementation.
static int grpc_machine_class_get_dhd_h_address(lua_State *L) {
    auto &managed_grpc_stub =
        clua_check<clua_managed_cm_ptr<cm_grpc_machine_stub>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    uint64_t dhd_h_address{};
    TRY_EXECUTE(cm_grpc_dhd_h_address(managed_grpc_stub.get(), luaL_checkinteger(L, 1), &dhd_h_address, err_msg));
    lua_pushinteger(L, static_cast<lua_Integer>(dhd_h_address));
    return 1;
}

/// \brief Contents of the machine class metatable __index table.
static const auto grpc_machine_static_methods = cartesi::clua_make_luaL_Reg_array({
    {"get_default_config", grpc_machine_class_get_default_config},
    {"verify_access_log", grpc_machine_class_verify_access_log},
    {"verify_state_transition", grpc_machine_class_verify_state_transition},
    {"get_x_address", grpc_machine_class_get_x_address},
    {"get_csr_address", grpc_machine_class_get_csr_address},
    {"get_dhd_h_address", grpc_machine_class_get_dhd_h_address},
});

/// \brief Prints a GRPC machine class
/// \param L Lua state.
static int grpc_machine_tostring(lua_State *L) {
    lua_pushliteral(L, "GRPC machine class");
    return 1;
}

/// \brief This is the cartesi.machine() constructor implementation.
/// \param L Lua state.
static int grpc_machine_ctor(lua_State *L) {
    lua_settop(L, 3);
    auto &managed_grpc_stub =
        clua_check<clua_managed_cm_ptr<cm_grpc_machine_stub>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    const int ctxidx = lua_upvalueindex(2);
    auto &managed_machine = clua_push_to(L, clua_managed_cm_ptr<cm_machine>(nullptr), ctxidx);
    auto &managed_runtime_config = clua_push_to(L,
        clua_managed_cm_ptr<cm_machine_runtime_config>(clua_opt_cm_machine_runtime_config(L, 3, {}, ctxidx)), ctxidx);
    if (lua_type(L, 2) == LUA_TTABLE) {
        auto &managed_config =
            clua_push_to(L, clua_managed_cm_ptr<cm_machine_config>(clua_check_cm_machine_config(L, 2, ctxidx)), ctxidx);
        TRY_EXECUTE_CTXIDX(cm_create_grpc_machine(managed_grpc_stub.get(), managed_config.get(),
                               managed_runtime_config.get(), &managed_machine.get(), err_msg),
            ctxidx);
        managed_config.reset();
        managed_runtime_config.reset();
        lua_pop(L, 2);
    } else {
        TRY_EXECUTE_CTXIDX(cm_load_grpc_machine(managed_grpc_stub.get(), luaL_checkstring(L, 2),
                               managed_runtime_config.get(), &managed_machine.get(), err_msg),
            ctxidx);
        managed_runtime_config.reset();
        lua_pop(L, 1);
    }
    return 1;
}

/// \brief Contents of the grpc machine class metatable.
static const auto grpc_machine_class_meta = cartesi::clua_make_luaL_Reg_array({
    {"__call", grpc_machine_ctor},
    {"__tostring", grpc_machine_tostring},
});

/// \brief This is the machine.get_version() static method implementation.
static int grpc_server_class_get_version(lua_State *L) {
    auto &managed_grpc_stub =
        clua_check<clua_managed_cm_ptr<cm_grpc_machine_stub>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    auto &managed_version =
        clua_push_to(L, clua_managed_cm_ptr<const cm_semantic_version>(nullptr), lua_upvalueindex(2));
    TRY_EXECUTE_CTXIDX(cm_grpc_get_semantic_version(managed_grpc_stub.get(), &managed_version.get(), err_msg),
        lua_upvalueindex(2));
    clua_push_cm_semantic_version(L, managed_version.get());
    managed_version.reset();
    return 1;
}

/// \brief This is the machine.shutdown() static method implementation.
static int grpc_server_class_shutdown(lua_State *L) {
    auto &managed_grpc_stub =
        clua_check<clua_managed_cm_ptr<cm_grpc_machine_stub>>(L, lua_upvalueindex(1), lua_upvalueindex(2));
    TRY_EXECUTE_CTXIDX(cm_grpc_shutdown(managed_grpc_stub.get(), err_msg), lua_upvalueindex(2));
    lua_pushnumber(L, 1);
    return 1;
}

/// \brief GRPC server static methods
static const auto grpc_server_static_methods = cartesi::clua_make_luaL_Reg_array({
    {"get_version", grpc_server_class_get_version},
    {"shutdown", grpc_server_class_shutdown},
});

/// \brief This is the grpc.stub() method implementation.
static int mod_stub(lua_State *L) {
    const char *remote_address = luaL_checkstring(L, 1);
    const char *checkin_address = luaL_checkstring(L, 2);
    // Create stub
    auto &managed_grpc_stub = clua_push_to(L, clua_managed_cm_ptr<cm_grpc_machine_stub>(nullptr));
    TRY_EXECUTE(cm_create_grpc_machine_stub(remote_address, checkin_address, &managed_grpc_stub.get(), err_msg));
    lua_newtable(L);                                         // stub server
    lua_newtable(L);                                         // stub server grpc_machine_class
    lua_pushvalue(L, -3);                                    // stub server grpc_machine_class stub
    lua_pushvalue(L, lua_upvalueindex(1));                   // stub server grpc_machine_class stub cluactx
    luaL_setfuncs(L, grpc_machine_static_methods.data(), 2); // stub server grpc_machine_class
    clua_htif_export(L, lua_upvalueindex(1));                // stub server grpc_machine_class
    lua_newtable(L);                                         // stub server grpc_machine_class meta
    lua_pushvalue(L, -4);                                    // stub server grpc_machine_class meta stub
    lua_pushvalue(L, lua_upvalueindex(1));                   // stub server grpc_machine_class meta stub cluactx
    luaL_setfuncs(L, grpc_machine_class_meta.data(), 2);     // stub server grpc_machine_class meta
    lua_setmetatable(L, -2);                                 // stub server grpc_machine_class
    lua_setfield(L, -2, "machine");                          // stub server
    lua_pushvalue(L, -2);                                    // stub server stub
    lua_pushvalue(L, lua_upvalueindex(1));                   // stub server stub cluactx
    luaL_setfuncs(L, grpc_server_static_methods.data(), 2);
    return 1;
}

/// \brief Contents of the grpc module.
static const auto mod = cartesi::clua_make_luaL_Reg_array({
    {"stub", mod_stub},
});

int clua_grpc_machine_init(lua_State *L, int ctxidx) {
    clua_createnewtype<clua_managed_cm_ptr<const cm_machine_config>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<cm_machine_config>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<cm_access_log>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<cm_machine_runtime_config>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<cm_merkle_tree_proof>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<char>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<unsigned char>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<cm_memory_range_config>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<const cm_semantic_version>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<cm_grpc_machine_stub>>(L, ctxidx);
    return 1;
}

int clua_grpc_machine_export(lua_State *L, int ctxidx) {
    int ctxabsidx = lua_absindex(L, ctxidx);
    // grpc
    clua_grpc_machine_init(L, ctxabsidx); // grpc
    lua_pushvalue(L, ctxabsidx);          // grpc cluactx
    luaL_setfuncs(L, mod.data(), 1);      // grpc
    return 0;
}

} // namespace cartesi
