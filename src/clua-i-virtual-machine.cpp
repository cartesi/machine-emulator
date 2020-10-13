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

#include <cinttypes>

#include "clua.h"
#include "clua-i-virtual-machine.h"
#include "clua-htif.h"
#include "clua-machine-util.h"
#include "unique-c-ptr.h"
#include "virtual-machine.h"

namespace cartesi {

/// \brief This is the machine:dump_pmas() method implementation.
/// \param L Lua state.
static int machine_obj__index_dump_pmas(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->dump_pmas();
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:dump_regs() method implementation.
/// \param L Lua state.
static int machine_obj__index_dump_regs(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    fprintf(stderr, "pc = %" PRIx64 "\n", m->read_pc());
    for (int i = 0; i < 32; ++i) {
        fprintf(stderr, "x%d = %" PRIx64 "\n", i, m->read_x(i));
    }
    fprintf(stderr, "minstret = %" PRIx64 "\n", m->read_minstret());
    fprintf(stderr, "mcycle = %" PRIx64 "\n", m->read_mcycle());
    fprintf(stderr, "mvendorid = %" PRIx64 "\n", m->read_mvendorid());
    fprintf(stderr, "marchid = %" PRIx64 "\n", m->read_marchid());
    fprintf(stderr, "mimpid = %" PRIx64 "\n", m->read_mimpid());
    fprintf(stderr, "mstatus = %" PRIx64 "\n", m->read_mstatus());
    fprintf(stderr, "mtvec = %" PRIx64 "\n", m->read_mtvec());
    fprintf(stderr, "mscratch = %" PRIx64 "\n", m->read_mscratch());
    fprintf(stderr, "mepc = %" PRIx64 "\n", m->read_mepc());
    fprintf(stderr, "mcause = %" PRIx64 "\n", m->read_mcause());
    fprintf(stderr, "mtval = %" PRIx64 "\n", m->read_mtval());
    fprintf(stderr, "misa = %" PRIx64 "\n", m->read_misa());
    fprintf(stderr, "mie = %" PRIx64 "\n", m->read_mie());
    fprintf(stderr, "mip = %" PRIx64 "\n", m->read_mip());
    fprintf(stderr, "medeleg = %" PRIx64 "\n", m->read_medeleg());
    fprintf(stderr, "mideleg = %" PRIx64 "\n", m->read_mideleg());
    fprintf(stderr, "mcounteren = %" PRIx64 "\n", m->read_mcounteren());
    fprintf(stderr, "stvec = %" PRIx64 "\n", m->read_stvec());
    fprintf(stderr, "sscratch = %" PRIx64 "\n", m->read_sscratch());
    fprintf(stderr, "sepc = %" PRIx64 "\n", m->read_sepc());
    fprintf(stderr, "scause = %" PRIx64 "\n", m->read_scause());
    fprintf(stderr, "stval = %" PRIx64 "\n", m->read_stval());
    fprintf(stderr, "satp = %" PRIx64 "\n", m->read_satp());
    fprintf(stderr, "scounteren = %" PRIx64 "\n", m->read_scounteren());
    fprintf(stderr, "ilrsc = %" PRIx64 "\n", m->read_ilrsc());
    fprintf(stderr, "iflags = %" PRIx64 "\n", m->read_iflags());
    fprintf(stderr, "clint_mtimecmp = %" PRIx64 "\n", m->read_clint_mtimecmp());
    fprintf(stderr, "htif_tohost = %" PRIx64 "\n", m->read_htif_tohost());
    fprintf(stderr, "htif_fromhost = %" PRIx64 "\n", m->read_htif_fromhost());
    fprintf(stderr, "htif_ihalt = %" PRIx64 "\n", m->read_htif_ihalt());
    fprintf(stderr, "htif_iconsole = %" PRIx64 "\n", m->read_htif_iconsole());
    fprintf(stderr, "htif_iyield = %" PRIx64 "\n", m->read_htif_iyield());
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:get_proof() method implementation.
/// \param L Lua state.
static int machine_obj__index_get_proof(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    merkle_tree::proof_type proof;
    m->get_proof(luaL_checkinteger(L, 2), luaL_checkinteger(L, 3), proof);
    clua_push_proof(L, proof);
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

static int machine_obj__index_get_initial_config(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    clua_push_machine_config(L, m->get_initial_config());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:get_root_hash() method implementation.
/// \param L Lua state.
static int machine_obj__index_get_root_hash(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    merkle_tree::hash_type hash;
    m->get_root_hash(hash);
    clua_push_hash(L, hash);
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_clint_mtimecmp() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_clint_mtimecmp(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_clint_mtimecmp());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_csr() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_csr(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_csr(clua_check_csr(L, 2)));
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_dhd_tstart() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_dhd_tstart(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_dhd_tstart());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_dhd_tlength() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_dhd_tlength(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_dhd_tlength());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_dhd_dlength() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_dhd_dlength(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_dhd_dlength());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_dhd_hlength() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_dhd_hlength(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_dhd_hlength());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_x() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_x(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    int i = luaL_checkinteger(L, 2);
    if (i < 0 || i >= X_REG_COUNT)
        throw std::invalid_argument{"register index out of range"};
    lua_pushinteger(L, m->read_x(i));
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_dhd_h() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_dhd_h(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    int i = luaL_checkinteger(L, 2);
    if (i < 0 || i >= DHD_H_REG_COUNT)
        throw std::invalid_argument{"register index out of range"};
    lua_pushinteger(L, m->read_dhd_h(i));
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_htif_fromhost() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_htif_fromhost(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_htif_fromhost());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_htif_tohost() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_htif_tohost(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_htif_tohost());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_htif_tohost_dev() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_htif_tohost_dev(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_htif_tohost_dev());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_htif_tohost_cmd() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_htif_tohost_cmd(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_htif_tohost_cmd());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_htif_tohost_data() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_htif_tohost_data(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_htif_tohost_data());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_htif_ihalt() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_htif_ihalt(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_htif_ihalt());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_htif_iconsole() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_htif_iconsole(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_htif_iconsole());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_htif_yield() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_htif_iyield(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_htif_iyield());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_iflags() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_iflags(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_iflags());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_iflags_H() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_iflags_H(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushboolean(L, m->read_iflags_H());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_iflags_I() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_iflags_I(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushboolean(L, m->read_iflags_I());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_iflags_Y() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_iflags_Y(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushboolean(L, m->read_iflags_Y());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_ilrsc() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_ilrsc(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_ilrsc());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_marchid() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_marchid(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_marchid());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_mcause() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_mcause(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_mcause());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_mcounteren() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_mcounteren(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_mcounteren());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_mcycle() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_mcycle(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_mcycle());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_medeleg() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_medeleg(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_medeleg());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_memory() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_memory(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    size_t length = luaL_checkinteger(L, 3);
    auto data = cartesi::unique_calloc<unsigned char>(length);
    m->read_memory(luaL_checkinteger(L, 2), data.get(), length);
    lua_pushlstring(L, reinterpret_cast<const char *>(data.get()), length);
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_mepc() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_mepc(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_mepc());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_mideleg() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_mideleg(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_mideleg());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_mie() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_mie(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_mie());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_mimpid() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_mimpid(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_mimpid());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_minstret() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_minstret(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_minstret());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_mip() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_mip(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_mip());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_misa() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_misa(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_misa());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_mscratch() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_mscratch(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_mscratch());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_mstatus() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_mstatus(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_mstatus());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_mtval() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_mtval(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_mtval());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_mtvec() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_mtvec(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_mtvec());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_mvendorid() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_mvendorid(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_mvendorid());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_pc() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_pc(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_pc());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_satp() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_satp(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_satp());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_scause() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_scause(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_scause());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_scounteren() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_scounteren(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_scounteren());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_sepc() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_sepc(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_sepc());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_sscratch() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_sscratch(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_sscratch());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_stval() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_stval(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_stval());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_stvec() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_stvec(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushinteger(L, m->read_stvec());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_word() method implementation.
/// \param L Lua state.
static int machine_obj__index_read_word(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    uint64_t word_value = 0;
    if (m->read_word(luaL_checkinteger(L, 2), word_value)) {
        lua_pushinteger(L, word_value);
        return 1;
    } else {
        lua_pushboolean(L, false);
        return 1;
    }
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:run() method implementation.
/// \param L Lua state.
static int machine_obj__index_run(lua_State *L) try {
    clua_check<clua_i_virtual_machine_ptr>(L, 1)->run(luaL_checkinteger(L, 2));
    lua_pushboolean(L, true);
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:step() method implementation.
/// \param L Lua state.
static int machine_obj__index_step(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    clua_push_access_log(L, m->step(clua_check_log_type(L, 2), true));
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:store() method implementation.
/// \param L Lua state.
static int machine_obj__index_store(lua_State *L) try {
    clua_check<clua_i_virtual_machine_ptr>(L, 1)->store(luaL_checkstring(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:update_merkle_tree() method implementation.
/// \param L Lua state.
static int machine_obj__index_update_merkle_tree(lua_State *L) try {
    lua_pushboolean(L, clua_check<clua_i_virtual_machine_ptr>(L, 1)->update_merkle_tree());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:verify_dirty_page_maps() method implementation.
/// \param L Lua state.
static int machine_obj__index_verify_dirty_page_maps(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    lua_pushboolean(L, m->verify_dirty_page_maps());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:verify_merkle_tree() method implementation.
/// \param L Lua state.
static int machine_obj__index_verify_merkle_tree(lua_State *L) try {
    lua_pushboolean(L, clua_check<clua_i_virtual_machine_ptr>(L, 1)->verify_merkle_tree());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_clint_mtimecmp() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_clint_mtimecmp(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_clint_mtimecmp(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_csr() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_csr(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_csr(clua_check_csr(L, 2), luaL_checkinteger(L, 3));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_dhd_tstart() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_dhd_tstart(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_dhd_tstart(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_dhd_tlength() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_dhd_tlength(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_dhd_tlength(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_dhd_dlength() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_dhd_dlength(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_dhd_dlength(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_dhd_hlength() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_dhd_hlength(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_dhd_hlength(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_x() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_x(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    int i = luaL_checkinteger(L, 2);
    if (i < 1 || i >= X_REG_COUNT)
        throw std::invalid_argument{"register index out of range"};
    m->write_x(i, luaL_checkinteger(L, 3));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_dhd_h() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_dhd_h(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    int i = luaL_checkinteger(L, 2);
    if (i < 0 || i >= DHD_H_REG_COUNT)
        throw std::invalid_argument{"register index out of range"};
    m->write_dhd_h(i, luaL_checkinteger(L, 3));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}


/// \brief This is the machine:write_htif_fromhost() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_htif_fromhost(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_htif_fromhost(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_htif_fromhost_data() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_htif_fromhost_data(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_htif_fromhost_data(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_htif_tohost() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_htif_tohost(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_htif_tohost(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_iflags() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_iflags(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_iflags(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_ilrsc() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_ilrsc(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_ilrsc(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_mcause() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_mcause(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_mcause(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_mcounteren() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_mcounteren(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_mcounteren(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_mcycle() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_mcycle(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_mcycle(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_medeleg() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_medeleg(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_medeleg(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_memory() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_memory(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    size_t length = 0;
    const unsigned char *data = reinterpret_cast<const unsigned char *>(
        luaL_checklstring(L, 3, &length));
    m->write_memory(luaL_checkinteger(L, 2), data, length);
    lua_pushboolean(L, true);
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_mepc() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_mepc(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_mepc(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_mideleg() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_mideleg(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_mideleg(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_mie() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_mie(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_mie(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_minstret() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_minstret(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_minstret(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_mip() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_mip(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_mip(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_misa() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_misa(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_misa(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_mscratch() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_mscratch(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_mscratch(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_mstatus() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_mstatus(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_mstatus(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_mtval() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_mtval(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_mtval(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_mtvec() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_mtvec(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_mtvec(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_pc() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_pc(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_pc(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_satp() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_satp(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_satp(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_scause() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_scause(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_scause(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_scounteren() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_scounteren(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_scounteren(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_sepc() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_sepc(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_sepc(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_sscratch() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_sscratch(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_sscratch(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_stval() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_stval(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_stval(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_stvec() method implementation.
/// \param L Lua state.
static int machine_obj__index_write_stvec(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->write_stvec(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief Replaces a flash drive.
/// \param L Lua state.
static int machine_obj__index_replace_flash_drive(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->replace_flash_drive(clua_check_flash_drive_config(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:destroy() method implementation.
/// \param L Lua state.
static int machine_obj__index_destroy(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->destroy();
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:snapshot() method implementation.
/// \param L Lua state.
static int machine_obj__index_snapshot(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->snapshot();
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:rollback() method implementation.
/// \param L Lua state.
static int machine_obj__index_rollback(lua_State *L) try {
    auto &m = clua_check<clua_i_virtual_machine_ptr>(L, 1);
    m->rollback();
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief Contents of the machine object metatable __index table.
static const luaL_Reg machine_obj__index[] = {
    {"dump_pmas", machine_obj__index_dump_pmas},
    {"dump_regs", machine_obj__index_dump_regs},
    {"get_proof", machine_obj__index_get_proof},
    {"get_initial_config", machine_obj__index_get_initial_config},
    {"get_root_hash", machine_obj__index_get_root_hash},
    {"read_clint_mtimecmp", machine_obj__index_read_clint_mtimecmp},
    {"read_csr", machine_obj__index_read_csr},
    {"read_dhd_dlength", machine_obj__index_read_dhd_dlength},
    {"read_dhd_h", machine_obj__index_read_dhd_h},
    {"read_dhd_hlength", machine_obj__index_read_dhd_hlength},
    {"read_dhd_tlength", machine_obj__index_read_dhd_tlength},
    {"read_dhd_tstart", machine_obj__index_read_dhd_tstart},
    {"read_htif_fromhost", machine_obj__index_read_htif_fromhost},
    {"read_htif_tohost", machine_obj__index_read_htif_tohost},
    {"read_htif_tohost_dev", machine_obj__index_read_htif_tohost_dev},
    {"read_htif_tohost_cmd", machine_obj__index_read_htif_tohost_cmd},
    {"read_htif_tohost_data", machine_obj__index_read_htif_tohost_data},
    {"read_htif_ihalt", machine_obj__index_read_htif_ihalt},
    {"read_htif_iconsole", machine_obj__index_read_htif_iconsole},
    {"read_htif_iyield", machine_obj__index_read_htif_iyield},
    {"read_iflags", machine_obj__index_read_iflags},
    {"read_iflags_H", machine_obj__index_read_iflags_H},
    {"read_iflags_I", machine_obj__index_read_iflags_I},
    {"read_iflags_Y", machine_obj__index_read_iflags_Y},
    {"read_ilrsc", machine_obj__index_read_ilrsc},
    {"read_marchid", machine_obj__index_read_marchid},
    {"read_mcause", machine_obj__index_read_mcause},
    {"read_mcounteren", machine_obj__index_read_mcounteren},
    {"read_mcycle", machine_obj__index_read_mcycle},
    {"read_medeleg", machine_obj__index_read_medeleg},
    {"read_memory", machine_obj__index_read_memory},
    {"read_mepc", machine_obj__index_read_mepc},
    {"read_mideleg", machine_obj__index_read_mideleg},
    {"read_mie", machine_obj__index_read_mie},
    {"read_mimpid", machine_obj__index_read_mimpid},
    {"read_minstret", machine_obj__index_read_minstret},
    {"read_mip", machine_obj__index_read_mip},
    {"read_misa", machine_obj__index_read_misa},
    {"read_mscratch", machine_obj__index_read_mscratch},
    {"read_mstatus", machine_obj__index_read_mstatus},
    {"read_mtval", machine_obj__index_read_mtval},
    {"read_mtvec", machine_obj__index_read_mtvec},
    {"read_mvendorid", machine_obj__index_read_mvendorid},
    {"read_pc", machine_obj__index_read_pc},
    {"read_satp", machine_obj__index_read_satp},
    {"read_scause", machine_obj__index_read_scause},
    {"read_scounteren", machine_obj__index_read_scounteren},
    {"read_sepc", machine_obj__index_read_sepc},
    {"read_sscratch", machine_obj__index_read_sscratch},
    {"read_stval", machine_obj__index_read_stval},
    {"read_stvec", machine_obj__index_read_stvec},
    {"read_word", machine_obj__index_read_word},
    {"read_x", machine_obj__index_read_x},
    {"run", machine_obj__index_run},
    {"step", machine_obj__index_step},
    {"store", machine_obj__index_store},
    {"update_merkle_tree", machine_obj__index_update_merkle_tree},
    {"verify_dirty_page_maps", machine_obj__index_verify_dirty_page_maps},
    {"verify_merkle_tree", machine_obj__index_verify_merkle_tree},
    {"write_clint_mtimecmp", machine_obj__index_write_clint_mtimecmp},
    {"write_csr", machine_obj__index_write_csr},
    {"write_dhd_dlength", machine_obj__index_write_dhd_dlength},
    {"write_dhd_h", machine_obj__index_write_dhd_h},
    {"write_dhd_hlength", machine_obj__index_write_dhd_hlength},
    {"write_dhd_tlength", machine_obj__index_write_dhd_tlength},
    {"write_dhd_tstart", machine_obj__index_write_dhd_tstart},
    {"write_htif_fromhost", machine_obj__index_write_htif_fromhost},
    {"write_htif_fromhost_data", machine_obj__index_write_htif_fromhost_data},
    {"write_htif_tohost", machine_obj__index_write_htif_tohost},
    {"write_iflags", machine_obj__index_write_iflags},
    {"write_ilrsc", machine_obj__index_write_ilrsc},
    {"write_mcause", machine_obj__index_write_mcause},
    {"write_mcounteren", machine_obj__index_write_mcounteren},
    {"write_mcycle", machine_obj__index_write_mcycle},
    {"write_medeleg", machine_obj__index_write_medeleg},
    {"write_memory", machine_obj__index_write_memory},
    {"write_mepc", machine_obj__index_write_mepc},
    {"write_mideleg", machine_obj__index_write_mideleg},
    {"write_mie", machine_obj__index_write_mie},
    {"write_minstret", machine_obj__index_write_minstret},
    {"write_mip", machine_obj__index_write_mip},
    {"write_misa", machine_obj__index_write_misa},
    {"write_mscratch", machine_obj__index_write_mscratch},
    {"write_mstatus", machine_obj__index_write_mstatus},
    {"write_mtval", machine_obj__index_write_mtval},
    {"write_mtvec", machine_obj__index_write_mtvec},
    {"write_pc", machine_obj__index_write_pc},
    {"write_satp", machine_obj__index_write_satp},
    {"write_scause", machine_obj__index_write_scause},
    {"write_scounteren", machine_obj__index_write_scounteren},
    {"write_sepc", machine_obj__index_write_sepc},
    {"write_sscratch", machine_obj__index_write_sscratch},
    {"write_stval", machine_obj__index_write_stval},
    {"write_stvec", machine_obj__index_write_stvec},
    {"write_x", machine_obj__index_write_x},
    {"replace_flash_drive", machine_obj__index_replace_flash_drive},
    {"destroy", machine_obj__index_destroy},
    {"snapshot", machine_obj__index_snapshot},
    {"rollback", machine_obj__index_rollback},
    { nullptr, nullptr }
};

int clua_i_virtual_machine_init(lua_State *L, int ctxidx) {
    if (!clua_typeexists<clua_i_virtual_machine_ptr>(L, ctxidx)) {
        clua_createtype<clua_i_virtual_machine_ptr>(L,
            "cartesi machine object", ctxidx);
        clua_setmethods<clua_i_virtual_machine_ptr>(L,
            machine_obj__index, 0, ctxidx);
    }
    return 1;
}

int clua_i_virtual_machine_export(lua_State *L, int ctxidx) {
    clua_i_virtual_machine_init(L, ctxidx); // cartesi
    return 0;
}

} // namespace cartesi
