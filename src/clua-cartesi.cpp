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
#include "clua-machine.h"
#include "clua.h"
#include "keccak-256-hasher.h"
#include "machine-c-api.h"
#include "riscv-constants.h"
#include "uarch-constants.h"
#include "uarch-pristine.h"

/// \file
/// \brief Scripting interface for the Cartesi SDK.

#ifdef GPERF
#include "gperftools/profiler.h"
#endif

#ifdef GPERF
static int gperf_gc(lua_State *) {
    ProfilerStop();
    return 0;
}

static const auto gperf_meta = cartesi::clua_make_luaL_Reg_array({
    {"__gc", gperf_gc},
});
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
        if (lua_gettop(L) > 1) {
            luaL_argerror(L, 2, "too many arguments");
        }
        uint64_t word = luaL_checkinteger(L, 1);
        h.begin();
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        h.add_data(reinterpret_cast<const unsigned char *>(&word), sizeof(word));
        h.end(hash);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        lua_pushlstring(L, reinterpret_cast<const char *>(hash.data()), hash.size());
        return 1;
    } else {
        h.begin();
        size_t len1 = 0;
        const char *hash1 = luaL_checklstring(L, 1, &len1);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        h.add_data(reinterpret_cast<const unsigned char *>(hash1), len1);
        size_t len2 = 0;
        const char *hash2 = luaL_optlstring(L, 2, "", &len2);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        h.add_data(reinterpret_cast<const unsigned char *>(hash2), len2);
        h.end(hash);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        lua_pushlstring(L, reinterpret_cast<const char *>(hash.data()), hash.size());
        return 1;
    }
}

/// \brief Contents of the cartesi module table.
static const auto cartesi_mod = cartesi::clua_make_luaL_Reg_array({
    {"keccak", cartesi_mod_keccak},
});

extern "C" {

/// \brief Entrypoint to the Cartesi Lua library.
/// \param L Lua state.
CM_API int luaopen_cartesi(lua_State *L) {
    using namespace cartesi;
#ifdef GPERF
    lua_newuserdata(L, 1);                  // gperf
    lua_pushvalue(L, -1);                   // gperf gperf
    lua_newtable(L);                        // gperf gperf gperfmeta
    luaL_setfuncs(L, gperf_meta.data(), 0); // gperf gperf gperfmeta
    lua_setmetatable(L, -2);                // gperf gperf
    lua_settable(L, LUA_REGISTRYINDEX);     //
    ProfilerStart("cartesi.prof");
#endif

    // Initialize clua
    clua_init(L);    // cluactx
    lua_newtable(L); // cluactx cartesi
    // Initialize and export machine bind
    clua_i_virtual_machine_export(L, -2); // cluactx cartesi
    clua_machine_export(L, -2);           // cluactx cartesi
    // Set module functions
    lua_pushvalue(L, -2);                    // cluactx cartesi cluactx
    luaL_setfuncs(L, cartesi_mod.data(), 1); // cluactx cartesi

    // Set cartesi constants
    clua_setintegerfield(L, CM_BREAK_REASON_FAILED, "BREAK_REASON_FAILED", -1);
    clua_setintegerfield(L, CM_BREAK_REASON_HALTED, "BREAK_REASON_HALTED", -1);
    clua_setintegerfield(L, CM_BREAK_REASON_YIELDED_MANUALLY, "BREAK_REASON_YIELDED_MANUALLY", -1);
    clua_setintegerfield(L, CM_BREAK_REASON_YIELDED_AUTOMATICALLY, "BREAK_REASON_YIELDED_AUTOMATICALLY", -1);
    clua_setintegerfield(L, CM_BREAK_REASON_YIELDED_SOFTLY, "BREAK_REASON_YIELDED_SOFTLY", -1);
    clua_setintegerfield(L, CM_BREAK_REASON_REACHED_TARGET_MCYCLE, "BREAK_REASON_REACHED_TARGET_MCYCLE", -1);
    clua_setintegerfield(L, CM_UARCH_BREAK_REASON_REACHED_TARGET_CYCLE, "UARCH_BREAK_REASON_REACHED_TARGET_CYCLE", -1);
    clua_setintegerfield(L, CM_UARCH_BREAK_REASON_UARCH_HALTED, "UARCH_BREAK_REASON_UARCH_HALTED", -1);
    clua_setintegerfield(L, UARCH_STATE_START_ADDRESS, "UARCH_STATE_START_ADDRESS", -1);
    clua_setintegerfield(L, UARCH_STATE_LOG2_SIZE, "UARCH_STATE_LOG2_SIZE", -1);
    clua_setintegerfield(L, UARCH_SHADOW_START_ADDRESS, "UARCH_SHADOW_START_ADDRESS", -1);
    clua_setintegerfield(L, UARCH_SHADOW_LENGTH, "UARCH_SHADOW_LENGTH", -1);
    clua_setintegerfield(L, UARCH_RAM_LENGTH, "UARCH_RAM_LENGTH", -1);
    clua_setintegerfield(L, UARCH_RAM_START_ADDRESS, "UARCH_RAM_START_ADDRESS", -1);
    clua_setintegerfield(L, UARCH_ECALL_FN_HALT, "UARCH_ECALL_FN_HALT", -1);
    clua_setintegerfield(L, UARCH_ECALL_FN_PUTCHAR, "UARCH_ECALL_FN_PUTCHAR", -1);
    clua_setintegerfield(L, PMA_CMIO_RX_BUFFER_START, "PMA_CMIO_RX_BUFFER_START", -1);
    clua_setintegerfield(L, PMA_CMIO_RX_BUFFER_LOG2_SIZE, "PMA_CMIO_RX_BUFFER_LOG2_SIZE", -1);
    clua_setintegerfield(L, PMA_CMIO_TX_BUFFER_START, "PMA_CMIO_TX_BUFFER_START", -1);
    clua_setintegerfield(L, PMA_CMIO_TX_BUFFER_LOG2_SIZE, "PMA_CMIO_TX_BUFFER_LOG2_SIZE", -1);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    clua_setlstringfield(L, reinterpret_cast<const char *>(uarch_pristine_hash), uarch_pristine_hash_len,
        "UARCH_PRISTINE_STATE_HASH", -1);
    clua_setintegerfield(L, MVENDORID_INIT, "MVENDORID", -1);
    clua_setintegerfield(L, MARCHID_INIT, "MARCHID", -1);
    clua_setintegerfield(L, MIMPID_INIT, "MIMPID", -1);
    clua_setintegerfield(L, CM_VERSION_MAJOR, "VERSION_MAJOR", -1);
    clua_setintegerfield(L, CM_VERSION_MINOR, "VERSION_MINOR", -1);
    clua_setintegerfield(L, CM_VERSION_PATCH, "VERSION_PATCH", -1);
    clua_setstringfield(L, CM_VERSION_LABEL, "VERSION_LABEL", -1);
    clua_setstringfield(L, CM_VERSION, "VERSION", -1);
    clua_setstringfield(L, BOOST_COMPILER, "COMPILER", -1);
    clua_setstringfield(L, BOOST_PLATFORM, "PLATFORM", -1);
#ifdef GIT_COMMIT
    clua_setstringfield(L, GIT_COMMIT, "GIT_COMMIT", -1);
#endif
#if defined(__DATE__) && defined(__TIME__)
    clua_setstringfield(L, __DATE__ " " __TIME__, "BUILD_TIME", -1);
#endif
    return 1;
}
}
