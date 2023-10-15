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

#include <cinttypes>

#include "clua-htif.h"
#include "clua-i-virtual-machine.h"
#include "clua-machine-util.h"
#include "clua.h"
#include "unique-c-ptr.h"
#include "virtual-machine.h"

namespace cartesi {

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define PRINT_PROCESSOR_CSR(machine, regname)                                                                          \
    do {                                                                                                               \
        uint64_t val{0};                                                                                               \
        TRY_EXECUTE(cm_read_##regname(machine, &val, err_msg));                                                        \
        (void) fprintf(stderr, #regname " = %" PRIx64 "\n", val);                                                      \
    } while (0)

/// \brief This is the machine:dump_pmas() method implementation.
/// \param L Lua state.
static int machine_obj_index_dump_pmas(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    TRY_EXECUTE(cm_dump_pmas(m.get(), err_msg));
    return 1;
}

/// \brief This is the machine:get_proof() method implementation.
/// \param L Lua state.
static int machine_obj_index_get_proof(lua_State *L) {
    lua_settop(L, 3);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t address = luaL_checkinteger(L, 2);
    auto log2_size = luaL_checkinteger(L, 3);
    auto &managed_proof = clua_push_to(L, clua_managed_cm_ptr<cm_merkle_tree_proof>(nullptr));
    TRY_EXECUTE(cm_get_proof(m.get(), address, log2_size, &managed_proof.get(), err_msg));
    clua_push_cm_proof(L, managed_proof.get());
    managed_proof.reset();
    return 1;
}

static int machine_obj_index_get_initial_config(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    auto &managed_config = clua_push_to(L, clua_managed_cm_ptr<const cm_machine_config>(nullptr));
    TRY_EXECUTE(cm_get_initial_config(m.get(), &managed_config.get(), err_msg));
    clua_push_cm_machine_config(L, managed_config.get());
    managed_config.reset();
    return 1;
}

/// \brief This is the machine:get_root_hash() method implementation.
/// \param L Lua state.
static int machine_obj_index_get_root_hash(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    cm_hash root_hash{};
    TRY_EXECUTE(cm_get_root_hash(m.get(), &root_hash, err_msg));
    clua_push_cm_hash(L, &root_hash);
    return 1;
}

/// \brief Generation of machine getters and setters for CSR registers
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define IMPL_MACHINE_OBJ_READ_WRITE(field)                                                                             \
    static int machine_obj_index_read_##field(lua_State *L) {                                                          \
        auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);                                                   \
        uint64_t val{};                                                                                                \
        TRY_EXECUTE(cm_read_##field(m.get(), &val, err_msg));                                                          \
        lua_pushinteger(L, val);                                                                                       \
        return 1;                                                                                                      \
    }                                                                                                                  \
    static int machine_obj_index_write_##field(lua_State *L) {                                                         \
        auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);                                                   \
        TRY_EXECUTE(cm_write_##field(m.get(), luaL_checkinteger(L, 2), err_msg));                                      \
        return 0;                                                                                                      \
    }

/// \brief Generation of machine getters for CSR registers
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define IMPL_MACHINE_OBJ_READ(field)                                                                                   \
    static int machine_obj_index_read_##field(lua_State *L) {                                                          \
        auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);                                                   \
        uint64_t val{};                                                                                                \
        TRY_EXECUTE(cm_read_##field(m.get(), &val, err_msg));                                                          \
        lua_pushinteger(L, val);                                                                                       \
        return 1;                                                                                                      \
    }

/// \brief Generation of machine setters for CSR registers
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define IMPL_MACHINE_OBJ_WRITE(field)                                                                                  \
    static int machine_obj_index_write_##field(lua_State *L) {                                                         \
        auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);                                                   \
        TRY_EXECUTE(cm_write_##field(m.get(), luaL_checkinteger(L, 2), err_msg));                                      \
        return 0;                                                                                                      \
    }

IMPL_MACHINE_OBJ_READ_WRITE(pc)
IMPL_MACHINE_OBJ_READ_WRITE(fcsr)
IMPL_MACHINE_OBJ_READ(mvendorid)
IMPL_MACHINE_OBJ_READ(marchid)
IMPL_MACHINE_OBJ_READ(mimpid)
IMPL_MACHINE_OBJ_READ_WRITE(mcycle)
IMPL_MACHINE_OBJ_READ_WRITE(icycleinstret)
IMPL_MACHINE_OBJ_READ_WRITE(mstatus)
IMPL_MACHINE_OBJ_READ_WRITE(mtvec)
IMPL_MACHINE_OBJ_READ_WRITE(mscratch)
IMPL_MACHINE_OBJ_READ_WRITE(mepc)
IMPL_MACHINE_OBJ_READ_WRITE(mcause)
IMPL_MACHINE_OBJ_READ_WRITE(mtval)
IMPL_MACHINE_OBJ_READ_WRITE(misa)
IMPL_MACHINE_OBJ_READ_WRITE(mie)
IMPL_MACHINE_OBJ_READ_WRITE(mip)
IMPL_MACHINE_OBJ_READ_WRITE(medeleg)
IMPL_MACHINE_OBJ_READ_WRITE(mideleg)
IMPL_MACHINE_OBJ_READ_WRITE(mcounteren)
IMPL_MACHINE_OBJ_READ_WRITE(menvcfg)
IMPL_MACHINE_OBJ_READ_WRITE(stvec)
IMPL_MACHINE_OBJ_READ_WRITE(sscratch)
IMPL_MACHINE_OBJ_READ_WRITE(sepc)
IMPL_MACHINE_OBJ_READ_WRITE(scause)
IMPL_MACHINE_OBJ_READ_WRITE(stval)
IMPL_MACHINE_OBJ_READ_WRITE(satp)
IMPL_MACHINE_OBJ_READ_WRITE(scounteren)
IMPL_MACHINE_OBJ_READ_WRITE(senvcfg)
IMPL_MACHINE_OBJ_READ_WRITE(hstatus)
IMPL_MACHINE_OBJ_READ_WRITE(hideleg)
IMPL_MACHINE_OBJ_READ_WRITE(hedeleg)
IMPL_MACHINE_OBJ_READ_WRITE(hie)
IMPL_MACHINE_OBJ_READ_WRITE(hip)
IMPL_MACHINE_OBJ_READ_WRITE(hvip)
IMPL_MACHINE_OBJ_READ_WRITE(hgatp)
IMPL_MACHINE_OBJ_READ_WRITE(henvcfg)
IMPL_MACHINE_OBJ_READ_WRITE(htimedelta)
IMPL_MACHINE_OBJ_READ_WRITE(htval)
IMPL_MACHINE_OBJ_READ_WRITE(vsepc)
IMPL_MACHINE_OBJ_READ_WRITE(vsstatus)
IMPL_MACHINE_OBJ_READ_WRITE(vscause)
IMPL_MACHINE_OBJ_READ_WRITE(vstval)
IMPL_MACHINE_OBJ_READ_WRITE(vstvec)
IMPL_MACHINE_OBJ_READ_WRITE(vsscratch)
IMPL_MACHINE_OBJ_READ_WRITE(vsatp)
IMPL_MACHINE_OBJ_READ_WRITE(vsie)
IMPL_MACHINE_OBJ_READ_WRITE(vsip)
IMPL_MACHINE_OBJ_READ_WRITE(ilrsc)
IMPL_MACHINE_OBJ_READ_WRITE(iflags)
IMPL_MACHINE_OBJ_READ_WRITE(htif_tohost)
IMPL_MACHINE_OBJ_READ(htif_tohost_dev)
IMPL_MACHINE_OBJ_READ(htif_tohost_cmd)
IMPL_MACHINE_OBJ_READ(htif_tohost_data)
IMPL_MACHINE_OBJ_READ_WRITE(htif_fromhost)
IMPL_MACHINE_OBJ_WRITE(htif_fromhost_data)
IMPL_MACHINE_OBJ_READ_WRITE(htif_ihalt)
IMPL_MACHINE_OBJ_READ_WRITE(htif_iconsole)
IMPL_MACHINE_OBJ_READ_WRITE(htif_iyield)
IMPL_MACHINE_OBJ_READ_WRITE(clint_mtimecmp)
IMPL_MACHINE_OBJ_READ_WRITE(uarch_cycle)
IMPL_MACHINE_OBJ_READ_WRITE(uarch_pc)
IMPL_MACHINE_OBJ_READ(uarch_ram_length)

/// \brief This is the machine:read_csr() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_csr(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    uint64_t val{};
    TRY_EXECUTE(cm_read_csr(m.get(), clua_check_cm_proc_csr(L, 2), &val, err_msg));
    lua_pushinteger(L, static_cast<lua_Integer>(val));
    return 1;
}

/// \brief This is the machine:read_x() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_x(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    auto i = luaL_checkinteger(L, 2);
    if (i < 0 || i >= X_REG_COUNT) {
        luaL_error(L, "register index out of range");
    }
    uint64_t val{};
    TRY_EXECUTE(cm_read_x(m.get(), i, &val, err_msg));
    lua_pushinteger(L, static_cast<lua_Integer>(val));
    return 1;
}

/// \brief This is the machine:read_f() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_f(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    auto i = luaL_checkinteger(L, 2);
    if (i < 0 || i >= F_REG_COUNT) {
        luaL_error(L, "register index out of range");
    }
    uint64_t val{};
    TRY_EXECUTE(cm_read_f(m.get(), i, &val, err_msg));
    lua_pushinteger(L, static_cast<lua_Integer>(val));
    return 1;
}

/// \brief This is the machine:read_uarch_x() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_uarch_x(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    auto i = luaL_checkinteger(L, 2);
    if (i < 0 || i >= UARCH_X_REG_COUNT) {
        luaL_error(L, "register index out of range");
    }
    uint64_t val{};
    TRY_EXECUTE(cm_read_uarch_x(m.get(), i, &val, err_msg));
    lua_pushinteger(L, static_cast<lua_Integer>(val));
    return 1;
}

/// \brief This is the machine:read_iflags_H() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_iflags_H(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    bool val{};
    TRY_EXECUTE(cm_read_iflags_H(m.get(), &val, err_msg));
    lua_pushboolean(L, val);
    return 1;
}

/// \brief This is the machine:read_iflags_Y() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_iflags_Y(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    bool val{};
    TRY_EXECUTE(cm_read_iflags_Y(m.get(), &val, err_msg));
    lua_pushboolean(L, val);
    return 1;
}

/// \brief This is the machine:read_iflags_X() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_iflags_X(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    bool val{};
    TRY_EXECUTE(cm_read_iflags_X(m.get(), &val, err_msg));
    lua_pushboolean(L, val);
    return 1;
}

/// \brief This is the machine:set_iflags_H() method implementation.
/// \param L Lua state.
static int machine_obj_index_set_iflags_H(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    TRY_EXECUTE(cm_set_iflags_H(m.get(), err_msg));
    return 0;
}

/// \brief This is the machine:set_iflags_Y() method implementation.
/// \param L Lua state.
static int machine_obj_index_set_iflags_Y(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    TRY_EXECUTE(cm_set_iflags_Y(m.get(), err_msg));
    return 0;
}

/// \brief This is the machine:set_iflags_X() method implementation.
/// \param L Lua state.
static int machine_obj_index_set_iflags_X(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    TRY_EXECUTE(cm_set_iflags_X(m.get(), err_msg));
    return 0;
}

/// \brief This is the machine:reset_iflags_Y() method implementation.
/// \param L Lua state.
static int machine_obj_index_reset_iflags_Y(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    TRY_EXECUTE(cm_reset_iflags_Y(m.get(), err_msg));
    return 0;
}

/// \brief This is the machine:reset_iflags_X() method implementation.
/// \param L Lua state.
static int machine_obj_index_reset_iflags_X(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    TRY_EXECUTE(cm_reset_iflags_X(m.get(), err_msg));
    return 0;
}

/// \brief This is the machine:read_memory() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_memory(lua_State *L) {
    lua_settop(L, 3);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t address = luaL_checkinteger(L, 2);
    const size_t length = luaL_checkinteger(L, 3);
    unsigned char *data{};
    try {
        data = new unsigned char[length];
    } catch (std::bad_alloc &e) {
        luaL_error(L, "failed to allocate memory for buffer");
    }
    auto &managed_data = clua_push_to(L, clua_managed_cm_ptr<unsigned char>(data));
    TRY_EXECUTE(cm_read_memory(m.get(), address, managed_data.get(), length, err_msg));
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
    const size_t length = luaL_checkinteger(L, 3);
    unsigned char *data{};
    try {
        data = new unsigned char[length];
    } catch (std::bad_alloc &e) {
        luaL_error(L, "failed to allocate memory for buffer");
    }
    auto &managed_data = clua_push_to(L, clua_managed_cm_ptr<unsigned char>(data));
    TRY_EXECUTE(cm_read_virtual_memory(m.get(), address, managed_data.get(), length, err_msg));
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
    TRY_EXECUTE(cm_read_word(m.get(), luaL_checkinteger(L, 2), &word_value, err_msg));
    lua_pushinteger(L, static_cast<lua_Integer>(word_value));
    return 1;
}

/// \brief This is the machine:run() method implementation.
/// \param L Lua state.
static int machine_obj_index_run(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t mcycle_end = luaL_optinteger(L, 2, UINT64_MAX);
    CM_BREAK_REASON break_reason = CM_BREAK_REASON_FAILED;
    TRY_EXECUTE(cm_machine_run(m.get(), mcycle_end, &break_reason, err_msg));
    lua_pushinteger(L, static_cast<lua_Integer>(break_reason));
    return 1;
}

/// \brief This is the machine:read_uarch_halt_flag() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_uarch_halt_flag(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    bool val{};
    TRY_EXECUTE(cm_read_uarch_halt_flag(m.get(), &val, err_msg));
    lua_pushboolean(L, val);
    return 1;
}

/// \brief This is the machine:set_uarch_halt_flag() method implementation.
/// \param L Lua state.
static int machine_obj_index_set_uarch_halt_flag(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    TRY_EXECUTE(cm_set_uarch_halt_flag(m.get(), err_msg));
    return 0;
}

/// \brief This is the machine:reset_uarch_state() method implementation.
/// \param L Lua state.
static int machine_obj_index_reset_uarch_state(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    TRY_EXECUTE(cm_reset_uarch_state(m.get(), err_msg));
    return 0;
}

/// \brief This is the machine:run_uarch() method implementation.
/// \param L Lua state.
static int machine_obj_index_run_uarch(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t cycle_end = luaL_optinteger(L, 2, UINT64_MAX);
    CM_UARCH_BREAK_REASON status = CM_UARCH_BREAK_REASON_REACHED_TARGET_CYCLE;
    TRY_EXECUTE(cm_machine_run_uarch(m.get(), cycle_end, &status, err_msg));
    lua_pushinteger(L, static_cast<lua_Integer>(status));
    return 1;
}

/// \brief This is the machine:step_uarch() method implementation.
/// \param L Lua state.
static int machine_obj_index_step_uarch(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    auto &managed_log = clua_push_to(L, clua_managed_cm_ptr<cm_access_log>(nullptr));
    TRY_EXECUTE(cm_step_uarch(m.get(), clua_check_cm_log_type(L, 2), true, &managed_log.get(), err_msg));
    clua_push_cm_access_log(L, managed_log.get());
    managed_log.reset();
    return 1;
}

/// \brief This is the machine:store() method implementation.
/// \param L Lua state.
static int machine_obj_index_store(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    TRY_EXECUTE(cm_store(m.get(), luaL_checkstring(L, 2), err_msg));
    return 0;
}

/// \brief This is the machine:verify_dirty_page_maps() method implementation.
/// \param L Lua state.
static int machine_obj_index_verify_dirty_page_maps(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    bool result{};
    TRY_EXECUTE(cm_verify_dirty_page_maps(m.get(), &result, err_msg));
    lua_pushboolean(L, result);
    return 1;
}

/// \brief This is the machine:verify_merkle_tree() method implementation.
/// \param L Lua state.
static int machine_obj_index_verify_merkle_tree(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    bool result{};
    TRY_EXECUTE(cm_verify_merkle_tree(m.get(), &result, err_msg));
    lua_pushboolean(L, result);
    return 1;
}

/// \brief This is the machine:write_csr() method implementation.
/// \param L Lua state.
static int machine_obj_index_write_csr(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    TRY_EXECUTE(cm_write_csr(m.get(), clua_check_cm_proc_csr(L, 2), luaL_checkinteger(L, 3), err_msg));
    return 0;
}

/// \brief This is the machine:write_x() method implementation.
/// \param L Lua state.
static int machine_obj_index_write_x(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    auto i = luaL_checkinteger(L, 2);
    if (i < 1 || i >= X_REG_COUNT) {
        luaL_error(L, "register index out of range");
    }
    TRY_EXECUTE(cm_write_x(m.get(), i, luaL_checkinteger(L, 3), err_msg));
    return 0;
}

/// \brief This is the machine:write_f() method implementation.
/// \param L Lua state.
static int machine_obj_index_write_f(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    auto i = luaL_checkinteger(L, 2);
    if (i < 0 || i >= F_REG_COUNT) {
        luaL_error(L, "register index out of range");
    }
    TRY_EXECUTE(cm_write_f(m.get(), i, luaL_checkinteger(L, 3), err_msg));
    return 0;
}

/// \brief This is the machine:write_uarch_x() method implementation.
/// \param L Lua state.
static int machine_obj_index_write_uarch_x(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    auto i = luaL_checkinteger(L, 2);
    if (i < 1 || i >= UARCH_X_REG_COUNT) {
        luaL_error(L, "register index out of range");
    }
    TRY_EXECUTE(cm_write_uarch_x(m.get(), i, luaL_checkinteger(L, 3), err_msg));
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
    TRY_EXECUTE(cm_write_memory(m.get(), address, data, length, err_msg));
    lua_pushboolean(L, true);
    return 1;
}

/// \brief This is the machine:write_virtual_memory() method implementation.
/// \param L Lua state.
static int machine_obj_index_write_virtual_memory(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    size_t length{0};
    const uint64_t address = luaL_checkinteger(L, 2);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 3, &length));
    TRY_EXECUTE(cm_write_virtual_memory(m.get(), address, data, length, err_msg));
    lua_pushboolean(L, true);
    return 1;
}

/// \brief Replaces a memory range.
/// \param L Lua state.
static int machine_obj_index_replace_memory_range(lua_State *L) {
    lua_settop(L, 2);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    cm_memory_range_config *memory_range_config{};
    try {
        memory_range_config = new cm_memory_range_config{};
    } catch (std::bad_alloc &e) {
        luaL_error(L, "failed to allocate memory range config");
    }
    auto &managed_memory_range_config =
        clua_push_to(L, clua_managed_cm_ptr<cm_memory_range_config>(memory_range_config));
    clua_check_cm_memory_range_config(L, 2, "replace", managed_memory_range_config.get());
    TRY_EXECUTE(cm_replace_memory_range(m.get(), managed_memory_range_config.get(), err_msg));
    managed_memory_range_config.reset();
    return 0;
}

/// \brief This is the machine:destroy() method implementation.
/// \param L Lua state.
static int machine_obj_index_destroy(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    TRY_EXECUTE(cm_destroy(m.get(), err_msg));
    return 0;
}

/// \brief This is the machine:snapshot() method implementation.
/// \param L Lua state.
static int machine_obj_index_snapshot(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    TRY_EXECUTE(cm_snapshot(m.get(), err_msg));
    return 0;
}

/// \brief This is the machine:rollback() method implementation.
/// \param L Lua state.
static int machine_obj_index_rollback(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    TRY_EXECUTE(cm_rollback(m.get(), err_msg));
    return 0;
}

/// \brief Contents of the machine object metatable __index table.
static const auto machine_obj_index = cartesi::clua_make_luaL_Reg_array({
    {"dump_pmas", machine_obj_index_dump_pmas},
    {"get_proof", machine_obj_index_get_proof},
    {"get_initial_config", machine_obj_index_get_initial_config},
    {"get_root_hash", machine_obj_index_get_root_hash},
    {"read_clint_mtimecmp", machine_obj_index_read_clint_mtimecmp},
    {"read_csr", machine_obj_index_read_csr},
    {"read_htif_fromhost", machine_obj_index_read_htif_fromhost},
    {"read_htif_tohost", machine_obj_index_read_htif_tohost},
    {"read_htif_tohost_dev", machine_obj_index_read_htif_tohost_dev},
    {"read_htif_tohost_cmd", machine_obj_index_read_htif_tohost_cmd},
    {"read_htif_tohost_data", machine_obj_index_read_htif_tohost_data},
    {"read_htif_ihalt", machine_obj_index_read_htif_ihalt},
    {"read_htif_iconsole", machine_obj_index_read_htif_iconsole},
    {"read_htif_iyield", machine_obj_index_read_htif_iyield},
    {"read_uarch_cycle", machine_obj_index_read_uarch_cycle},
    {"read_uarch_pc", machine_obj_index_read_uarch_pc},
    {"read_uarch_x", machine_obj_index_read_uarch_x},
    {"read_uarch_ram_length", machine_obj_index_read_uarch_ram_length},
    {"read_iflags", machine_obj_index_read_iflags},
    {"read_iflags_H", machine_obj_index_read_iflags_H},
    {"read_iflags_Y", machine_obj_index_read_iflags_Y},
    {"read_iflags_X", machine_obj_index_read_iflags_X},
    {"set_iflags_H", machine_obj_index_set_iflags_H},
    {"set_iflags_Y", machine_obj_index_set_iflags_Y},
    {"set_iflags_X", machine_obj_index_set_iflags_X},
    {"reset_iflags_Y", machine_obj_index_reset_iflags_Y},
    {"reset_iflags_X", machine_obj_index_reset_iflags_X},
    {"read_ilrsc", machine_obj_index_read_ilrsc},
    {"read_marchid", machine_obj_index_read_marchid},
    {"read_mcause", machine_obj_index_read_mcause},
    {"read_mcounteren", machine_obj_index_read_mcounteren},
    {"read_menvcfg", machine_obj_index_read_menvcfg},
    {"read_mcycle", machine_obj_index_read_mcycle},
    {"read_medeleg", machine_obj_index_read_medeleg},
    {"read_memory", machine_obj_index_read_memory},
    {"read_virtual_memory", machine_obj_index_read_virtual_memory},
    {"read_mepc", machine_obj_index_read_mepc},
    {"read_mideleg", machine_obj_index_read_mideleg},
    {"read_mie", machine_obj_index_read_mie},
    {"read_mimpid", machine_obj_index_read_mimpid},
    {"read_icycleinstret", machine_obj_index_read_icycleinstret},
    {"read_mip", machine_obj_index_read_mip},
    {"read_misa", machine_obj_index_read_misa},
    {"read_mscratch", machine_obj_index_read_mscratch},
    {"read_mstatus", machine_obj_index_read_mstatus},
    {"read_mtval", machine_obj_index_read_mtval},
    {"read_mtvec", machine_obj_index_read_mtvec},
    {"read_mvendorid", machine_obj_index_read_mvendorid},
    {"read_pc", machine_obj_index_read_pc},
    {"read_fcsr", machine_obj_index_read_fcsr},
    {"read_satp", machine_obj_index_read_satp},
    {"read_scause", machine_obj_index_read_scause},
    {"read_scounteren", machine_obj_index_read_scounteren},
    {"read_senvcfg", machine_obj_index_read_senvcfg},
    {"read_sepc", machine_obj_index_read_sepc},
    {"read_sscratch", machine_obj_index_read_sscratch},
    {"read_stval", machine_obj_index_read_stval},
    {"read_stvec", machine_obj_index_read_stvec},
    {"read_hstatus", machine_obj_index_read_hstatus},
    {"read_hideleg", machine_obj_index_read_hideleg},
    {"read_hedeleg", machine_obj_index_read_hedeleg},
    {"read_hie", machine_obj_index_read_hie},
    {"read_hip", machine_obj_index_read_hip},
    {"read_hvip", machine_obj_index_read_hvip},
    {"read_hgatp", machine_obj_index_read_hgatp},
    {"read_henvcfg", machine_obj_index_read_henvcfg},
    {"read_htimedelta", machine_obj_index_read_htimedelta},
    {"read_htval", machine_obj_index_read_htval},
    {"read_vsepc", machine_obj_index_read_vsepc},
    {"read_vsstatus", machine_obj_index_read_vsstatus},
    {"read_vscause", machine_obj_index_read_vscause},
    {"read_vstval", machine_obj_index_read_vstval},
    {"read_vstvec", machine_obj_index_read_vstvec},
    {"read_vsscratch", machine_obj_index_read_vsscratch},
    {"read_vsatp", machine_obj_index_read_vsatp},
    {"read_vsie", machine_obj_index_read_vsie},
    {"read_vsip", machine_obj_index_read_vsip},
    {"read_word", machine_obj_index_read_word},
    {"read_x", machine_obj_index_read_x},
    {"read_f", machine_obj_index_read_f},
    {"run", machine_obj_index_run},
    {"run_uarch", machine_obj_index_run_uarch},
    {"step_uarch", machine_obj_index_step_uarch},
    {"store", machine_obj_index_store},
    {"verify_dirty_page_maps", machine_obj_index_verify_dirty_page_maps},
    {"verify_merkle_tree", machine_obj_index_verify_merkle_tree},
    {"write_clint_mtimecmp", machine_obj_index_write_clint_mtimecmp},
    {"write_csr", machine_obj_index_write_csr},
    {"write_htif_fromhost", machine_obj_index_write_htif_fromhost},
    {"write_htif_fromhost_data", machine_obj_index_write_htif_fromhost_data},
    {"write_htif_tohost", machine_obj_index_write_htif_tohost},
    {"write_htif_ihalt", machine_obj_index_write_htif_ihalt},
    {"write_htif_iconsole", machine_obj_index_write_htif_iconsole},
    {"write_htif_iyield", machine_obj_index_write_htif_iyield},
    {"write_uarch_cycle", machine_obj_index_write_uarch_cycle},
    {"write_uarch_pc", machine_obj_index_write_uarch_pc},
    {"write_uarch_x", machine_obj_index_write_uarch_x},
    {"write_iflags", machine_obj_index_write_iflags},
    {"write_ilrsc", machine_obj_index_write_ilrsc},
    {"write_mcause", machine_obj_index_write_mcause},
    {"write_mcounteren", machine_obj_index_write_mcounteren},
    {"write_menvcfg", machine_obj_index_write_menvcfg},
    {"write_mcycle", machine_obj_index_write_mcycle},
    {"write_medeleg", machine_obj_index_write_medeleg},
    {"write_memory", machine_obj_index_write_memory},
    {"write_virtual_memory", machine_obj_index_write_virtual_memory},
    {"write_mepc", machine_obj_index_write_mepc},
    {"write_mideleg", machine_obj_index_write_mideleg},
    {"write_mie", machine_obj_index_write_mie},
    {"write_icycleinstret", machine_obj_index_write_icycleinstret},
    {"write_mip", machine_obj_index_write_mip},
    {"write_misa", machine_obj_index_write_misa},
    {"write_mscratch", machine_obj_index_write_mscratch},
    {"write_mstatus", machine_obj_index_write_mstatus},
    {"write_mtval", machine_obj_index_write_mtval},
    {"write_mtvec", machine_obj_index_write_mtvec},
    {"write_pc", machine_obj_index_write_pc},
    {"write_fcsr", machine_obj_index_write_fcsr},
    {"write_satp", machine_obj_index_write_satp},
    {"write_scause", machine_obj_index_write_scause},
    {"write_scounteren", machine_obj_index_write_scounteren},
    {"write_senvcfg", machine_obj_index_write_senvcfg},
    {"write_sepc", machine_obj_index_write_sepc},
    {"write_sscratch", machine_obj_index_write_sscratch},
    {"write_stval", machine_obj_index_write_stval},
    {"write_stvec", machine_obj_index_write_stvec},
    {"write_hstatus", machine_obj_index_write_hstatus},
    {"write_hideleg", machine_obj_index_write_hideleg},
    {"write_hedeleg", machine_obj_index_write_hedeleg},
    {"write_hie", machine_obj_index_write_hie},
    {"write_hip", machine_obj_index_write_hip},
    {"write_hvip", machine_obj_index_write_hvip},
    {"write_hgatp", machine_obj_index_write_hgatp},
    {"write_henvcfg", machine_obj_index_write_henvcfg},
    {"write_htimedelta", machine_obj_index_write_htimedelta},
    {"write_htval", machine_obj_index_write_htval},
    {"write_vsepc", machine_obj_index_write_vsepc},
    {"write_vsstatus", machine_obj_index_write_vsstatus},
    {"write_vscause", machine_obj_index_write_vscause},
    {"write_vstval", machine_obj_index_write_vstval},
    {"write_vstvec", machine_obj_index_write_vstvec},
    {"write_vsscratch", machine_obj_index_write_vsscratch},
    {"write_vsatp", machine_obj_index_write_vsatp},
    {"write_vsie", machine_obj_index_write_vsie},
    {"write_vsip", machine_obj_index_write_vsip},
    {"write_x", machine_obj_index_write_x},
    {"write_f", machine_obj_index_write_f},
    {"replace_memory_range", machine_obj_index_replace_memory_range},
    {"destroy", machine_obj_index_destroy},
    {"snapshot", machine_obj_index_snapshot},
    {"rollback", machine_obj_index_rollback},
    {"read_uarch_halt_flag", machine_obj_index_read_uarch_halt_flag},
    {"set_uarch_halt_flag", machine_obj_index_set_uarch_halt_flag},
    {"reset_uarch_state", machine_obj_index_reset_uarch_state},
});

/// \brief This is the machine __close metamethod implementation.
/// \param L Lua state.
static int machine_obj_close(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    TRY_EXECUTE(cm_destroy(m.get(), err_msg));
    clua_close<clua_managed_cm_ptr<cm_machine>>(L);
    return 0;
}

int clua_i_virtual_machine_init(lua_State *L, int ctxidx) {
    if (!clua_typeexists<clua_managed_cm_ptr<cm_machine>>(L, ctxidx)) {
        clua_createtype<clua_managed_cm_ptr<cm_machine>>(L, "cartesi machine object", ctxidx);
        clua_setmethods<clua_managed_cm_ptr<cm_machine>>(L, machine_obj_index.data(), 0, ctxidx);
        // Override __close to actually destroy the machine
        static const auto machine_class_meta = cartesi::clua_make_luaL_Reg_array({
            {"__close", machine_obj_close},
        });
        clua_setmetamethods<clua_managed_cm_ptr<cm_machine>>(L, machine_class_meta.data(), 0, ctxidx);
    }
    return 1;
}

int clua_i_virtual_machine_export(lua_State *L, int ctxidx) {
    clua_i_virtual_machine_init(L, ctxidx); // cartesi
    return 0;
}

} // namespace cartesi
