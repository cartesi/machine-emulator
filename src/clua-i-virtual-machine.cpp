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
#include <new>

#include "clua-i-virtual-machine.h"
#include "clua-machine-util.h"
#include "clua.h"
#include "machine-c-api.h"

namespace cartesi {

/// \brief This is the machine:get_proof() method implementation.
/// \param L Lua state.
static int machine_obj_index_get_proof(lua_State *L) {
    lua_settop(L, 3);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t address = luaL_checkinteger(L, 2);
    const int log2_size = static_cast<int>(luaL_checkinteger(L, 3));
    const char *proof = nullptr;
    if (cm_get_proof(m.get(), address, log2_size, &proof) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_schemed_json_table(L, proof, "Proof");
    return 1;
}

static int machine_obj_index_get_initial_config(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *config = nullptr;
    if (cm_get_initial_config(m.get(), &config) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_json_table(L, config);
    return 1;
}

/// \brief This is the machine:get_root_hash() method implementation.
/// \param L Lua state.
static int machine_obj_index_get_root_hash(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    cm_hash root_hash{};
    if (cm_get_root_hash(m.get(), &root_hash) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_cm_hash(L, &root_hash);
    return 1;
}

static int machine_obj_index_read_mcycle(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    uint64_t val{};
    if (cm_read_mcycle(m.get(), &val) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(val));
    return 1;
}

static int machine_obj_index_read_uarch_cycle(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    uint64_t val{};
    if (cm_read_uarch_cycle(m.get(), &val) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(val));
    return 1;
}

/// \brief This is the machine:read_reg() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_reg(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    uint64_t val{};
    if (cm_read_reg(m.get(), clua_check_cm_proc_reg(L, 2), &val) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(val));
    return 1;
}

/// \brief This is the machine:read_iflags_H() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_iflags_H(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    bool val{};
    if (cm_read_iflags_H(m.get(), &val) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushboolean(L, val);
    return 1;
}

/// \brief This is the machine:read_iflags_Y() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_iflags_Y(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    bool val{};
    if (cm_read_iflags_Y(m.get(), &val) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushboolean(L, val);
    return 1;
}

/// \brief This is the machine:read_iflags_X() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_iflags_X(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    bool val{};
    if (cm_read_iflags_X(m.get(), &val) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushboolean(L, val);
    return 1;
}

/// \brief This is the machine:set_iflags_Y() method implementation.
/// \param L Lua state.
static int machine_obj_index_set_iflags_Y(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_set_iflags_Y(m.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:reset_iflags_Y() method implementation.
/// \param L Lua state.
static int machine_obj_index_reset_iflags_Y(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_reset_iflags_Y(m.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:read_memory() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_memory(lua_State *L) {
    lua_settop(L, 3);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t address = luaL_checkinteger(L, 2);
    const uint64_t length = luaL_checkinteger(L, 3);
    unsigned char *data{};
    try {
        data = new unsigned char[length];
    } catch (std::bad_alloc &e) {
        luaL_error(L, "failed to allocate memory for buffer");
    }
    auto &managed_data = clua_push_to(L, clua_managed_cm_ptr<unsigned char>(data));
    if (cm_read_memory(m.get(), address, managed_data.get(), length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    lua_pushlstring(L, reinterpret_cast<const char *>(managed_data.get()), length);
    managed_data.reset();
    return 1;
}

/// \brief This is the machine:read_virtual_memory() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_virtual_memory(lua_State *L) {
    lua_settop(L, 3);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t address = luaL_checkinteger(L, 2);
    const uint64_t length = luaL_checkinteger(L, 3);
    unsigned char *data{};
    try {
        data = new unsigned char[length];
    } catch (std::bad_alloc &e) {
        luaL_error(L, "failed to allocate memory for buffer");
    }
    auto &managed_data = clua_push_to(L, clua_managed_cm_ptr<unsigned char>(data));
    if (cm_read_virtual_memory(m.get(), address, managed_data.get(), length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    lua_pushlstring(L, reinterpret_cast<const char *>(managed_data.get()), length);
    managed_data.reset();
    return 1;
}

/// \brief This is the machine:read_word() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_word(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    uint64_t word_value{0};
    if (cm_read_word(m.get(), luaL_checkinteger(L, 2), &word_value) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(word_value));
    return 1;
}

/// \brief This is the machine:run() method implementation.
/// \param L Lua state.
static int machine_obj_index_run(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t mcycle_end = luaL_optinteger(L, 2, UINT64_MAX);
    cm_break_reason break_reason = CM_BREAK_REASON_FAILED;
    if (cm_run(m.get(), mcycle_end, &break_reason) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(break_reason));
    return 1;
}

/// \brief This is the machine:read_uarch_halt_flag() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_uarch_halt_flag(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    bool val{};
    if (cm_read_uarch_halt_flag(m.get(), &val) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushboolean(L, val);
    return 1;
}

/// \brief This is the machine:set_uarch_halt_flag() method implementation.
/// \param L Lua state.
static int machine_obj_index_set_uarch_halt_flag(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_set_uarch_halt_flag(m.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:reset_uarch() method implementation.
/// \param L Lua state.
static int machine_obj_index_reset_uarch(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_reset_uarch(m.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:get_memory_ranges() method implementation.
/// \param L Lua state.
static int machine_obj_index_get_memory_ranges(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *ranges = nullptr;
    if (cm_get_memory_ranges(m.get(), &ranges) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_json_table(L, ranges);
    return 1;
}

/// \brief This is the machine:reset_uarch() method implementation.
/// \param L Lua state.
static int machine_obj_index_log_reset_uarch(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const int log_type = static_cast<int>(luaL_optinteger(L, 2, 0));
    const char *log = nullptr;
    if (cm_log_reset_uarch(m.get(), log_type, &log) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_schemed_json_table(L, log, "AccessLog");
    return 1;
}

/// \brief This is the machine:run_uarch() method implementation.
/// \param L Lua state.
static int machine_obj_index_run_uarch(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t cycle_end = luaL_optinteger(L, 2, UINT64_MAX);
    cm_uarch_break_reason status = CM_UARCH_BREAK_REASON_FAILED;
    if (cm_run_uarch(m.get(), cycle_end, &status) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(status));
    return 1;
}

/// \brief This is the machine:log_step_uarch() method implementation.
/// \param L Lua state.
static int machine_obj_index_log_step_uarch(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const int log_type = static_cast<int>(luaL_optinteger(L, 2, 0));
    const char *log = nullptr;
    if (cm_log_step_uarch(m.get(), log_type, &log) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_schemed_json_table(L, log, "AccessLog");
    return 1;
}

/// \brief This is the machine:store() method implementation.
/// \param L Lua state.
static int machine_obj_index_store(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_store(m.get(), luaL_checkstring(L, 2)) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:verify_dirty_page_maps() method implementation.
/// \param L Lua state.
static int machine_obj_index_verify_dirty_page_maps(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    bool result{};
    if (cm_verify_dirty_page_maps(m.get(), &result) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushboolean(L, result);
    return 1;
}

/// \brief This is the machine:verify_merkle_tree() method implementation.
/// \param L Lua state.
static int machine_obj_index_verify_merkle_tree(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    bool result{};
    if (cm_verify_merkle_tree(m.get(), &result) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushboolean(L, result);
    return 1;
}

/// \brief This is the machine:write_reg() method implementation.
/// \param L Lua state.
static int machine_obj_index_write_reg(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_write_reg(m.get(), clua_check_cm_proc_reg(L, 2), luaL_checkinteger(L, 3)) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:write_memory() method implementation.
/// \param L Lua state.
static int machine_obj_index_write_memory(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    size_t length{0};
    const uint64_t address = luaL_checkinteger(L, 2);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 3, &length));
    if (cm_write_memory(m.get(), address, data, length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:write_virtual_memory() method implementation.
/// \param L Lua state.
static int machine_obj_index_write_virtual_memory(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    size_t length{0};
    const uint64_t address = luaL_checkinteger(L, 2);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 3, &length));
    if (cm_write_virtual_memory(m.get(), address, data, length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:translate_virtual_address() method implementation.
/// \param L Lua state.
static int machine_obj_index_translate_virtual_address(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    uint64_t paddr_value{0};
    if (cm_translate_virtual_address(m.get(), luaL_checkinteger(L, 2), &paddr_value) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(paddr_value));
    return 1;
}

/// \brief Replaces a memory range.
/// \param L Lua state.
static int machine_obj_index_replace_memory_range(lua_State *L) {
    lua_settop(L, 5);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t start = luaL_checkinteger(L, 2);
    const uint64_t length = luaL_checkinteger(L, 3);
    const bool shared = lua_toboolean(L, 4);
    const char *image_filename = luaL_optstring(L, 5, nullptr);
    if (cm_replace_memory_range(m.get(), start, length, shared, image_filename) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:snapshot() method implementation.
/// \param L Lua state.
static int machine_obj_index_snapshot(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_snapshot(m.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:commit() method implementation.
/// \param L Lua state.
static int machine_obj_index_commit(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_commit(m.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:rollback() method implementation.
/// \param L Lua state.
static int machine_obj_index_rollback(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_rollback(m.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:receive_cmio_request() method implementation.
/// \param L Lua state.
static int machine_obj_index_receive_cmio_request(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    uint64_t length{};
    if (cm_receive_cmio_request(m.get(), nullptr, nullptr, nullptr, &length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    unsigned char *data{};
    try {
        data = new unsigned char[length];
    } catch (std::bad_alloc &e) {
        luaL_error(L, "failed to allocate memory for buffer");
    }
    auto &managed_data = clua_push_to(L, clua_managed_cm_ptr<unsigned char>(data));
    uint8_t cmd{};
    uint16_t reason{};
    if (cm_receive_cmio_request(m.get(), &cmd, &reason, data, &length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, cmd);
    lua_pushinteger(L, reason);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    lua_pushlstring(L, reinterpret_cast<const char *>(managed_data.get()), length);
    managed_data.reset();
    return 3;
}

/// \brief This is the machine:send_cmio_response() method implementation.
/// \param L Lua state.
static int machine_obj_index_send_cmio_response(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint16_t reason = static_cast<uint16_t>(luaL_checkinteger(L, 2));
    size_t length{0};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 3, &length));
    if (cm_send_cmio_response(m.get(), reason, data, length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:log_send_cmio_response() method implementation.
/// \param L Lua state.
static int machine_obj_index_log_send_cmio_response(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint16_t reason = static_cast<uint16_t>(luaL_checkinteger(L, 2));
    const int log_type = static_cast<int>(luaL_optinteger(L, 4, 0));
    size_t length{0};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 3, &length));
    const char *log = nullptr;
    if (cm_log_send_cmio_response(m.get(), reason, data, length, log_type, &log) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_schemed_json_table(L, log, "AccessLog");
    return 1;
}

/// \brief Contents of the machine object metatable __index table.
static const auto machine_obj_index = cartesi::clua_make_luaL_Reg_array({
    {"get_proof", machine_obj_index_get_proof},
    {"get_initial_config", machine_obj_index_get_initial_config},
    {"get_root_hash", machine_obj_index_get_root_hash},
    {"read_reg", machine_obj_index_read_reg},
    {"read_uarch_cycle", machine_obj_index_read_uarch_cycle},
    {"read_iflags_H", machine_obj_index_read_iflags_H},
    {"read_iflags_Y", machine_obj_index_read_iflags_Y},
    {"read_iflags_X", machine_obj_index_read_iflags_X},
    {"set_iflags_Y", machine_obj_index_set_iflags_Y},
    {"reset_iflags_Y", machine_obj_index_reset_iflags_Y},
    {"read_mcycle", machine_obj_index_read_mcycle},
    {"read_memory", machine_obj_index_read_memory},
    {"read_virtual_memory", machine_obj_index_read_virtual_memory},
    {"read_word", machine_obj_index_read_word},
    {"run", machine_obj_index_run},
    {"run_uarch", machine_obj_index_run_uarch},
    {"log_step_uarch", machine_obj_index_log_step_uarch},
    {"store", machine_obj_index_store},
    {"verify_dirty_page_maps", machine_obj_index_verify_dirty_page_maps},
    {"verify_merkle_tree", machine_obj_index_verify_merkle_tree},
    {"write_reg", machine_obj_index_write_reg},
    {"write_memory", machine_obj_index_write_memory},
    {"write_virtual_memory", machine_obj_index_write_virtual_memory},
    {"translate_virtual_address", machine_obj_index_translate_virtual_address},
    {"replace_memory_range", machine_obj_index_replace_memory_range},
    {"snapshot", machine_obj_index_snapshot},
    {"commit", machine_obj_index_commit},
    {"rollback", machine_obj_index_rollback},
    {"read_uarch_halt_flag", machine_obj_index_read_uarch_halt_flag},
    {"set_uarch_halt_flag", machine_obj_index_set_uarch_halt_flag},
    {"get_memory_ranges", machine_obj_index_get_memory_ranges},
    {"reset_uarch", machine_obj_index_reset_uarch},
    {"log_reset_uarch", machine_obj_index_log_reset_uarch},
    {"receive_cmio_request", machine_obj_index_receive_cmio_request},
    {"send_cmio_response", machine_obj_index_send_cmio_response},
    {"log_send_cmio_response", machine_obj_index_log_send_cmio_response},
});

int clua_i_virtual_machine_init(lua_State *L, int ctxidx) {
    if (!clua_typeexists<clua_managed_cm_ptr<cm_machine>>(L, ctxidx)) {
        clua_createtype<clua_managed_cm_ptr<cm_machine>>(L, "cartesi machine object", ctxidx);
        clua_setmethods<clua_managed_cm_ptr<cm_machine>>(L, machine_obj_index.data(), 0, ctxidx);
    }
    return 1;
}

int clua_i_virtual_machine_export(lua_State *L, int ctxidx) {
    clua_i_virtual_machine_init(L, ctxidx); // cartesi
    return 0;
}

} // namespace cartesi
