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
#include "clua-machine.h"
#include "clua-machine-util.h"
#include "clua-grpc-machine.h"

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
    switch (lua_gettop(L)) {
        case 0:
            luaL_argerror(L, 1, "too few arguments");
            break;
        case 1: {
            uint64_t word = luaL_checkinteger(L, 1);
            h.begin();
            h.add_data(reinterpret_cast<const unsigned char *>(&word),
                sizeof(word));
            h.end(hash);
            clua_push_hash(L, hash);
            break;
        }
        case 2: {
            size_t len1 = 0;
            const char *hash1 = luaL_checklstring(L, 1, &len1);
            if (len1 != keccak_256_hasher::hash_size) {
                luaL_argerror(L, 1, "invalid hash size");
            }
            size_t len2 = 0;
            const char *hash2 = luaL_checklstring(L, 2, &len2);
            if (len2 != keccak_256_hasher::hash_size) {
                luaL_argerror(L, 2, "invalid hash size");
            }
            h.begin();
            h.add_data(reinterpret_cast<const unsigned char *>(hash1), len1);
            h.add_data(reinterpret_cast<const unsigned char *>(hash2), len2);
            h.end(hash);
            clua_push_hash(L, hash);
            break;
        }
        default:
            luaL_argerror(L, 3, "too many arguments");
            break;
    }
    return 1;
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
    clua_machine_export(L, -2); // cluactx cartesi
    // Initialize and export grpc machine bind
    clua_grpc_machine_export(L, -2); // cluactx cartesi
	// Set module functions
    lua_pushvalue(L, -2); // cluactx cartesi cluactx
    luaL_setfuncs(L, cartesi_mod, 1); // cluactx cartesi

    return 1;
}
