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

#include "grpc-virtual-machine.h"
#include "clua.h"
#include "clua-i-virtual-machine.h"
#include "clua-htif.h"
#include "clua-machine-util.h"
#include "clua-grpc-machine.h"

namespace cartesi {

/// \brief This is the machine.get_default_machine_config()
/// static method implementation.
static int grpc_machine_class_get_default_config(lua_State *L) try {
    auto &stub = clua_check<grpc_machine_stub_ptr>(L, lua_upvalueindex(1),
        lua_upvalueindex(2));
    clua_push_machine_config(L, grpc_virtual_machine::get_default_config(stub));
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine.verify_access_log()
/// static method implementation.
static int grpc_machine_class_verify_access_log(lua_State *L) try {
    auto &stub = clua_check<grpc_machine_stub_ptr>(L, lua_upvalueindex(1),
        lua_upvalueindex(2));
    grpc_virtual_machine::verify_access_log(stub, clua_check_access_log(L, 1),
        lua_toboolean(L, 2));
    lua_pushnumber(L, 1);
    return 1;
} catch (std::exception &x) {
    lua_pushnil(L);
    lua_pushstring(L, x.what());
    return 2;
}

/// \brief This is the machine.verify_state_transition()
/// static method implementation.
static int grpc_machine_class_verify_state_transition(lua_State *L) try {
    auto &stub = clua_check<grpc_machine_stub_ptr>(L, lua_upvalueindex(1),
        lua_upvalueindex(2));
    grpc_virtual_machine::verify_state_transition(stub,
        clua_check_hash(L, 1),
        clua_check_access_log(L, 2),
        clua_check_hash(L, 3),
        lua_toboolean(L, 4));
    lua_pushnumber(L, 1);
    return 1;
} catch (std::exception &x) {
    lua_pushnil(L);
    lua_pushstring(L, x.what());
    return 2;
}

/// \brief Contents of the machine class metatable __index table.
static const luaL_Reg grpc_machine_static_methods[] = {
    {"get_default_config", grpc_machine_class_get_default_config},
    {"verify_access_log", grpc_machine_class_verify_access_log},
    {"verify_state_transition", grpc_machine_class_verify_state_transition},
    { nullptr, nullptr }
};

/// \brief Prints a GRPC machine class
/// \param L Lua state.
static int grpc_machine_tostring(lua_State *L) {
    lua_pushliteral(L, "GRPC machine class");
    return 1;
}

/// \brief This is the cartesi.machine() constructor implementation.
/// \param L Lua state.
static int grpc_machine_ctor(lua_State *L) try {
    auto &stub = *reinterpret_cast<grpc_machine_stub_ptr *>(
        lua_touserdata(L, lua_upvalueindex(1)));
    clua_i_virtual_machine_ptr *p = reinterpret_cast<
		clua_i_virtual_machine_ptr *>(lua_newuserdata(L,
			sizeof(clua_i_virtual_machine_ptr)));
    new (p) clua_i_virtual_machine_ptr();
    if (lua_type(L, 2) == LUA_TTABLE) {
        *p = std::make_unique<grpc_virtual_machine>(stub,
            clua_check_machine_config(L, 2));
    } else {
        *p = std::make_unique<grpc_virtual_machine>(stub,
            luaL_checkstring(L, 2));
    }
    clua_setmetatable<clua_i_virtual_machine_ptr>(L, -1, lua_upvalueindex(2));
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief Contents of the grpc machine class metatable.
static const luaL_Reg grpc_machine_class_meta[] = {
    {"__call", grpc_machine_ctor },
    {"__tostring", grpc_machine_tostring },
    { nullptr, nullptr }
};

/// \brief This is the machine.get_version() static method implementation.
static int grpc_server_class_get_version(lua_State *L) try {
    auto &stub = clua_check<grpc_machine_stub_ptr>(L, lua_upvalueindex(1),
        lua_upvalueindex(2));
    clua_push_semantic_version(L, grpc_virtual_machine::get_version(stub));
    return 1;
} catch (std::exception &x) {
    lua_pushnil(L);
    lua_pushstring(L, x.what());
    return 2;
}

/// \brief GRPC server static methods
static const luaL_Reg grpc_server_static_methods[] = {
    { "get_version", grpc_server_class_get_version },
    { nullptr, nullptr }
};

/// \brief This is the grpc.stub() method implementation.
static int mod_stub(lua_State *L) {
    const char *address = luaL_checkstring(L, 1);
    grpc_machine_stub_ptr *p = reinterpret_cast<grpc_machine_stub_ptr *>(
        lua_newuserdata(L, sizeof(grpc_machine_stub_ptr))); // stub
    new (p) grpc_machine_stub_ptr();
    *p = grpc_virtual_machine::stub(address);
    if (!(*p)) {
        lua_pop(L, 2);
        lua_pushnil(L);
        lua_pushliteral(L, "stub creation failed");
        return 2;
    }
    clua_setmetatable<grpc_machine_stub_ptr>(L, -1); // stub
    lua_newtable(L); // stub server grpc_machine_class
    lua_newtable(L); // stub server grpc_machine_class
    lua_pushvalue(L, -3); // stub server grpc_machine_class stub
    lua_pushvalue(L, lua_upvalueindex(1)); // stub server grpc_machine_class stub cluactx
    luaL_setfuncs(L, grpc_machine_static_methods, 2); // stub server grpc_machine_class
    clua_htif_export(L, lua_upvalueindex(1)); // stub server grpc_machine_class
    lua_newtable(L); // stub server grpc_machine_class meta
    lua_pushvalue(L, -4); // stub server grpc_machine_class meta stub
    lua_pushvalue(L, lua_upvalueindex(1)); // stub server grpc_machine_class meta stub cluactx
    luaL_setfuncs(L, grpc_machine_class_meta, 2); // stub server grpc_machine_class meta
    lua_setmetatable(L, -2); // stub server grpc_machine_class
    lua_setfield(L, -2, "machine"); // stub server
    lua_pushvalue(L, -2); // stub server stub
    lua_pushvalue(L, lua_upvalueindex(1)); // stub server stub cluactx
    luaL_setfuncs(L, grpc_server_static_methods, 2);
    return 1;
}

/// \brief Contents of the grpc module.
static luaL_Reg mod[] = {
    {"stub", mod_stub },
    { nullptr, nullptr }
};

int clua_grpc_machine_init(lua_State *L, int ctxidx) {
    if (!clua_typeexists<grpc_machine_stub_ptr>(L, ctxidx)) {
        clua_createtype<grpc_machine_stub_ptr>(L, "GRPC stub",
            ctxidx);
    }
    return 1;
}

int clua_grpc_machine_export(lua_State *L, int ctxidx) {
    int ctxabsidx = lua_absindex(L, ctxidx);
    // grpc
    clua_grpc_machine_init(L, ctxabsidx); // grpc
    lua_pushvalue(L, ctxabsidx); // grpc cluactx
    luaL_setfuncs(L, mod, 1); // grpc
    return 0;
}

} // namespace cartesi
