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

#include "keccak-256-hasher.h"

#include "clua.h"
#include "clua-i-virtual-machine.h"
#include "clua-machine-util.h"
#include "clua-machine.h"

/// \file
/// \brief Scripting interface for the Cartesi SDK.

#ifdef GPERF
#include "gperftools/profiler.h"
#endif

#ifdef GPERF
static int gperf__gc(lua_State *) {
    ProfilerStop();
    return 0;
}

static const luaL_Reg gperf_meta[] = {
    {"__gc", gperf__gc},
    { NULL, NULL }
};
#endif

/// \brief This is the cartesi.keccak() function implementation.
/// \param L Lua state.
static int cartesi_mod_keccak(lua_State *L) {
    using namespace cartesi;
    keccak_256_hasher h;
    keccak_256_hasher::hash_type hash;
    if (lua_gettop(L) > 2) {
        luaL_argerror(L, 3, "too many arguments");
    }
    if (lua_gettop(L) < 1) {
        luaL_argerror(L, 1, "too few arguments");
    }
    if (lua_isinteger(L, 1)) {
        uint64_t word = luaL_checkinteger(L, 1);
        h.begin();
        h.add_data(reinterpret_cast<const unsigned char *>(&word),
            sizeof(word));
        h.end(hash);
        clua_push_hash(L, hash);
        return 1;
    } else {
        h.begin();
        size_t len1 = 0;
        const char *hash1 = luaL_checklstring(L, 1, &len1);
        h.add_data(reinterpret_cast<const unsigned char *>(hash1), len1);
        size_t len2 = 0;
        const char *hash2 = luaL_optlstring(L, 2, "", &len2);
        h.add_data(reinterpret_cast<const unsigned char *>(hash2), len2);
        h.end(hash);
        clua_push_hash(L, hash);
        return 1;
    }
}

/// \brief Contents of the cartesi module table.
static const luaL_Reg cartesi_mod[] = {
    {"keccak", cartesi_mod_keccak},
    { NULL, NULL }
};

extern "C"
__attribute__((visibility("default")))
/// \brief Entrypoint to the Cartesi Lua library.
/// \param L Lua state.
int luaopen_cartesi(lua_State *L) {
    using namespace cartesi;
#ifdef GPERF
    lua_newuserdata(L, 1); // gperf
    lua_pushvalue(L, -1); // gperf gperf
    lua_newtable(L); // gperf gperf gperfmeta
    luaL_setfuncs(L, gperf_meta, 0); // gperf gperf gperfmeta
    lua_setmetatable(L, -2); // gperf gperf
    lua_settable(L, LUA_REGISTRYINDEX); //
    ProfilerStart("cartesi.prof");
#endif

    // Initialize clua
    clua_init(L); // cluactx
    lua_newtable(L); // cluactx cartesi
    // Initialize and export machine bind
    clua_i_virtual_machine_export(L, -2); // cluactx cartesi
    clua_machine_export(L, -2); // cluactx cartesi
    // Set module functions
    lua_pushvalue(L, -2); // cluactx cartesi cluactx
    luaL_setfuncs(L, cartesi_mod, 1); // cluactx cartesi

    return 1;
}
