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
#include <exception>
#include <string>
#include <string_view>

#include <boost/config.hpp>

extern "C" {
#include <lauxlib.h>
#include <lua.h>
}

#include "base64.h"
#include "clua-i-machine.h"
#include "clua.h"
#include "htif-constants.h"
#include "machine-c-api.h"
#include "machine-c-version.h"
#include "riscv-constants.h"
#include "uarch-constants.h"
#include "uarch-pristine.h"

/// \file
/// \brief Scripting interface for the Cartesi SDK.

#ifdef GPERF
#include "gperftools/profiler.h"
#endif

namespace cartesi {

#ifdef GPERF
static int gperf_gc(lua_State *) {
    ProfilerStop();
    return 0;
}

static const auto gperf_meta = clua_make_luaL_Reg_array({
    {"__gc", gperf_gc},
});
#endif

/// \brief Generic hasher function implementation.
/// \tparam hash_function Hash function type (keccak256 or sha256).
/// \param L Lua state.
template <cm_hash_function hash_function>
static int cartesi_mod_hasher(lua_State *L) {
    const auto nargs = lua_gettop(L);
    if (nargs > 2) {
        luaL_argerror(L, 3, "too many arguments");
    }
    if (nargs < 1) {
        luaL_argerror(L, 1, "too few arguments");
    }
    size_t len1 = 0;
    size_t len2 = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data1 = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 1, &len1));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data2 = reinterpret_cast<const unsigned char *>(luaL_optlstring(L, 2, "", &len2));

    cm_hash hash{};

    if (len2 > 0) { // Concat hash of two inputs
        if (len1 != CM_HASH_SIZE || len2 != CM_HASH_SIZE) {
            luaL_argerror(L, 1, "concatenate hash is only supported for inputs with size of hash");
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto *left = reinterpret_cast<const cm_hash *>(data1);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto *right = reinterpret_cast<const cm_hash *>(data2);
        if (cm_get_concat_hash(hash_function, left, right, &hash) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    } else { // Single hash
        if (cm_get_hash(hash_function, data1, len1, &hash) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    lua_pushlstring(L, reinterpret_cast<const char *>(hash), sizeof(hash));
    return 1;
}

/// \brief This is the cartesi.keccak256() function implementation.
/// \param L Lua state.
static int cartesi_mod_keccak256(lua_State *L) {
    return cartesi_mod_hasher<CM_HASH_KECCAK256>(L);
}

/// \brief This is the cartesi.sha256() function implementation.
/// \param L Lua state.
static int cartesi_mod_sha256(lua_State *L) {
    return cartesi_mod_hasher<CM_HASH_SHA256>(L);
}

static int cartesi_mod_tobase64(lua_State *L) try {
    size_t size = 0;
    const char *data = luaL_checklstring(L, 1, &size);
    std::string &value = *clua_push_new_managed_toclose_ptr(L, encode_base64(std::string_view(data, size)));
    lua_pushlstring(L, value.data(), value.size());
    value.clear();
    return 1;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return 1;
}

static int cartesi_mod_frombase64(lua_State *L) try {
    size_t size = 0;
    const char *data = luaL_checklstring(L, 1, &size);
    std::string &value = *clua_push_new_managed_toclose_ptr(L, decode_base64(std::string_view(data, size)));
    lua_pushlstring(L, value.data(), value.size());
    value.clear();
    return 1;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return 1;
}

static int cartesi_mod_tojson(lua_State *L) try {
    const int indent = static_cast<int>(luaL_optinteger(L, 2, -1));
    lua_settop(L, 1);
    clua_check_json_string(L, 1, indent);
    return 1;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return 1;
}

static int cartesi_mod_fromjson(lua_State *L) try {
    clua_push_json_table(L, luaL_checkstring(L, 1));
    return 1;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return 1;
}

static int cartesi_mod_new(lua_State *L) try {
    auto &m = clua_push_to(L, clua_managed_cm_ptr<cm_machine>(nullptr));
    if (cm_new(&m.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 1;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return 1;
}

/// \brief Contents of the cartesi module table.
static const auto cartesi_mod = clua_make_luaL_Reg_array({
    {"keccak256", cartesi_mod_keccak256},
    {"sha256", cartesi_mod_sha256},
    {"tobase64", cartesi_mod_tobase64},
    {"frombase64", cartesi_mod_frombase64},
    {"tojson", cartesi_mod_tojson},
    {"fromjson", cartesi_mod_fromjson},
    {"new", cartesi_mod_new},
});

} // namespace cartesi

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
    clua_i_machine_export(L, -2); // cluactx cartesi
    // Set module functions
    lua_pushvalue(L, -2);                                                    // cluactx cartesi cluactx
    luaL_setfuncs(L, cartesi_mod.data(), 1);                                 // cluactx cartesi
    auto &m = clua_push_to(L, clua_managed_cm_ptr<cm_machine>(nullptr), -2); // cluactx cartesi machine
    if (cm_new(&m.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_setfield(L, -2, "machine"); // cluactx cartesi
    // Set public C API constants
    clua_setstringfield(L, CM_VERSION_LABEL, "VERSION_LABEL", -1);
    clua_setstringfield(L, CM_VERSION, "VERSION", -1);
    clua_setintegerfield(L, CM_VERSION_MAJOR, "VERSION_MAJOR", -1);
    clua_setintegerfield(L, CM_VERSION_MINOR, "VERSION_MINOR", -1);
    clua_setintegerfield(L, CM_VERSION_PATCH, "VERSION_PATCH", -1);
    clua_setintegerfield(L, CM_HASH_SIZE, "HASH_SIZE", -1);
    clua_setintegerfield(L, CM_MCYCLE_MAX, "MCYCLE_MAX", -1);
    clua_setintegerfield(L, CM_UARCH_CYCLE_MAX, "UARCH_CYCLE_MAX", -1);
    clua_setintegerfield(L, CM_TREE_LOG2_WORD_SIZE, "TREE_LOG2_WORD_SIZE", -1);
    clua_setintegerfield(L, CM_TREE_LOG2_PAGE_SIZE, "TREE_LOG2_PAGE_SIZE", -1);
    clua_setintegerfield(L, CM_TREE_LOG2_ROOT_SIZE, "TREE_LOG2_ROOT_SIZE", -1);
    clua_setintegerfield(L, CM_BREAK_REASON_FAILED, "BREAK_REASON_FAILED", -1);
    clua_setintegerfield(L, CM_BREAK_REASON_HALTED, "BREAK_REASON_HALTED", -1);
    clua_setintegerfield(L, CM_BREAK_REASON_YIELDED_MANUALLY, "BREAK_REASON_YIELDED_MANUALLY", -1);
    clua_setintegerfield(L, CM_BREAK_REASON_YIELDED_AUTOMATICALLY, "BREAK_REASON_YIELDED_AUTOMATICALLY", -1);
    clua_setintegerfield(L, CM_BREAK_REASON_YIELDED_SOFTLY, "BREAK_REASON_YIELDED_SOFTLY", -1);
    clua_setintegerfield(L, CM_BREAK_REASON_REACHED_TARGET_MCYCLE, "BREAK_REASON_REACHED_TARGET_MCYCLE", -1);
    clua_setintegerfield(L, CM_UARCH_BREAK_REASON_REACHED_TARGET_CYCLE, "UARCH_BREAK_REASON_REACHED_TARGET_CYCLE", -1);
    clua_setintegerfield(L, CM_UARCH_BREAK_REASON_UARCH_HALTED, "UARCH_BREAK_REASON_UARCH_HALTED", -1);
    clua_setintegerfield(L, CM_UARCH_BREAK_REASON_CYCLE_OVERFLOW, "UARCH_BREAK_REASON_CYCLE_OVERFLOW", -1);
    clua_setintegerfield(L, CM_ACCESS_LOG_TYPE_ANNOTATIONS, "ACCESS_LOG_TYPE_ANNOTATIONS", -1);
    clua_setintegerfield(L, CM_ACCESS_LOG_TYPE_LARGE_DATA, "ACCESS_LOG_TYPE_LARGE_DATA", -1);
    clua_setintegerfield(L, CM_CMIO_YIELD_COMMAND_AUTOMATIC, "CMIO_YIELD_COMMAND_AUTOMATIC", -1);
    clua_setintegerfield(L, CM_CMIO_YIELD_COMMAND_MANUAL, "CMIO_YIELD_COMMAND_MANUAL", -1);
    clua_setintegerfield(L, CM_CMIO_YIELD_AUTOMATIC_REASON_PROGRESS, "CMIO_YIELD_AUTOMATIC_REASON_PROGRESS", -1);
    clua_setintegerfield(L, CM_CMIO_YIELD_AUTOMATIC_REASON_TX_OUTPUT, "CMIO_YIELD_AUTOMATIC_REASON_TX_OUTPUT", -1);
    clua_setintegerfield(L, CM_CMIO_YIELD_AUTOMATIC_REASON_TX_REPORT, "CMIO_YIELD_AUTOMATIC_REASON_TX_REPORT", -1);
    clua_setintegerfield(L, CM_CMIO_YIELD_MANUAL_REASON_RX_ACCEPTED, "CMIO_YIELD_MANUAL_REASON_RX_ACCEPTED", -1);
    clua_setintegerfield(L, CM_CMIO_YIELD_MANUAL_REASON_RX_REJECTED, "CMIO_YIELD_MANUAL_REASON_RX_REJECTED", -1);
    clua_setintegerfield(L, CM_CMIO_YIELD_MANUAL_REASON_TX_EXCEPTION, "CMIO_YIELD_MANUAL_REASON_TX_EXCEPTION", -1);
    clua_setintegerfield(L, CM_CMIO_YIELD_REASON_ADVANCE_STATE, "CMIO_YIELD_REASON_ADVANCE_STATE", -1);
    clua_setintegerfield(L, CM_CMIO_YIELD_REASON_INSPECT_STATE, "CMIO_YIELD_REASON_INSPECT_STATE", -1);
    clua_setintegerfield(L, CM_SHARING_NONE, "SHARING_NONE", -1);
    clua_setintegerfield(L, CM_SHARING_CONFIG, "SHARING_CONFIG", -1);
    clua_setintegerfield(L, CM_SHARING_ALL, "SHARING_ALL", -1);
    clua_setintegerfield(L, CM_AR_CMIO_RX_BUFFER_START, "AR_CMIO_RX_BUFFER_START", -1);
    clua_setintegerfield(L, CM_AR_CMIO_RX_BUFFER_LOG2_SIZE, "AR_CMIO_RX_BUFFER_LOG2_SIZE", -1);
    clua_setintegerfield(L, CM_AR_CMIO_TX_BUFFER_START, "AR_CMIO_TX_BUFFER_START", -1);
    clua_setintegerfield(L, CM_AR_CMIO_TX_BUFFER_LOG2_SIZE, "AR_CMIO_TX_BUFFER_LOG2_SIZE", -1);
    clua_setintegerfield(L, CM_AR_RAM_START, "AR_RAM_START", -1);
    // HTIF masks
    clua_setintegerfield(L, HTIF_HALT_CMD_HALT_MASK, "HTIF_HALT_CMD_HALT_MASK", -1);
    clua_setintegerfield(L, HTIF_CONSOLE_CMD_GETCHAR_MASK, "HTIF_CONSOLE_CMD_GETCHAR_MASK", -1);
    clua_setintegerfield(L, HTIF_CONSOLE_CMD_PUTCHAR_MASK, "HTIF_CONSOLE_CMD_PUTCHAR_MASK", -1);
    clua_setintegerfield(L, HTIF_YIELD_CMD_MANUAL_MASK, "HTIF_YIELD_CMD_MANUAL_MASK", -1);
    clua_setintegerfield(L, HTIF_YIELD_CMD_AUTOMATIC_MASK, "HTIF_YIELD_CMD_AUTOMATIC_MASK", -1);
    // Set other constants used by internal tests
    clua_setintegerfield(L, UARCH_STATE_START_ADDRESS, "UARCH_STATE_START_ADDRESS", -1);
    clua_setintegerfield(L, UARCH_STATE_LOG2_SIZE, "UARCH_STATE_LOG2_SIZE", -1);
    clua_setintegerfield(L, UARCH_SHADOW_START_ADDRESS, "UARCH_SHADOW_START_ADDRESS", -1);
    clua_setintegerfield(L, UARCH_SHADOW_LENGTH, "UARCH_SHADOW_LENGTH", -1);
    clua_setintegerfield(L, UARCH_RAM_LENGTH, "UARCH_RAM_LENGTH", -1);
    clua_setintegerfield(L, UARCH_RAM_START_ADDRESS, "UARCH_RAM_START_ADDRESS", -1);
    clua_setintegerfield(L, UARCH_ECALL_FN_HALT, "UARCH_ECALL_FN_HALT", -1);
    clua_setintegerfield(L, UARCH_ECALL_FN_PUTCHAR, "UARCH_ECALL_FN_PUTCHAR", -1);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    clua_setlstringfield(L, reinterpret_cast<const char *>(uarch_pristine_hash), uarch_pristine_hash_len,
        "UARCH_PRISTINE_STATE_HASH", -1);
    clua_setintegerfield(L, MVENDORID_INIT, "MVENDORID", -1);
    clua_setintegerfield(L, MARCHID_INIT, "MARCHID", -1);
    clua_setintegerfield(L, MIMPID_INIT, "MIMPID", -1);
    // Build-related constants
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
