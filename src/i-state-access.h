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

#ifndef I_STATE_ACCESS_H
#define I_STATE_ACCESS_H

/// \file
/// \brief State access interface

#include <cstdint>
#include <type_traits>
#include <utility>

#include "compiler-defines.h"
#include "meta.h"
#include "tlb.h"

#ifdef DUMP_STATE_ACCESS
#include "pm-type-name.h"
#endif

namespace cartesi {

// Forward declarations
enum class bracket_type;

// Type trait that should return the pma_entry type for a state access class
template <typename STATE_ACCESS>
struct i_state_access_pma_entry {};
template <typename STATE_ACCESS>
using i_state_access_pma_entry_t = typename i_state_access_pma_entry<STATE_ACCESS>::type;

// Type trait that should return the fast_addr type for a state access class
template <typename STATE_ACCESS>
struct i_state_access_fast_addr {};
template <typename STATE_ACCESS>
using i_state_access_fast_addr_t = typename i_state_access_fast_addr<STATE_ACCESS>::type;

/// \class i_state_access
/// \brief Interface for machine state access.
/// \details \{
/// The final "step" function must log all read and write accesses to the state.
/// The "run" function does not need a log, and must be as fast as possible.
/// Both functions share the exact same implementation of what it means to advance the machine state by one cycle.
/// In this common implementation, all state accesses go through a class that implements the i_state_access interface.
/// When logging is needed, a record state access class is used.
/// When no logging is needed, a direct state access class is used.
///
/// In a typical design, i_state_access would be pure virtual.
/// For speed, we avoid virtual methods and instead use templates.
/// State access classes inherit from i_state_access, and declare it as friend.
/// They then implement all private do_* methods.
/// Clients call the methods without the do_ prefix, which are inherited from the i_state_access
/// interface and simply forward the call to the methods with do_ prefix implemented by the derived class.
/// This is a form of "static polymorphism" that incurs no runtime cost
///
/// Methods are provided to read and write each state component.
/// \}
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
template <typename DERIVED>
class i_state_access { // CRTP
    i_state_access() = default;
    friend DERIVED;

    /// \brief Returns object cast as the derived class
    DERIVED &derived() {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived() const {
        return *static_cast<const DERIVED *>(this);
    }

public:
    using pma_entry = i_state_access_pma_entry_t<DERIVED>;
    using fast_addr = i_state_access_fast_addr_t<DERIVED>;

    //??D We should probably remove this from the interface
    /// \brief Returns machine state for direct access.
    auto &get_naked_state() {
        return derived().do_get_naked_state();
    }

    /// \brief Reads from general-purpose register.
    /// \param i Register index.
    /// \returns Register value.
    uint64_t read_x(int i) {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_x(i);
        fprintf(stderr, "%s::read_x(%d) = %llu(0x%llx)\n", get_name(), i, val, val);
        return val;
#else
        return derived().do_read_x(i);
#endif
    }

    /// \brief Writes register to general-purpose register.
    /// \param i Register index.
    /// \param val New register value.
    /// \details Writes to register zero *break* the machine.
    /// There is an assertion to catch this, but NDEBUG will let the value pass through.
    void write_x(int i, uint64_t val) {
        derived().do_write_x(i, val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_x(%d, %llu(0x%llx))\n", get_name(), i, val, val);
#endif
    }

    /// \brief Reads from floating-point register.
    /// \param i Register index.
    /// \returns Register value.
    uint64_t read_f(int i) {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_f(i);
        fprintf(stderr, "%s::read_f(%d) = %llu(0x%llx)\n", get_name(), i, val, val);
        return val;
#else
        return derived().do_read_f(i);
#endif
    }

    /// \brief Writes register to floating-point register.
    /// \param i Register index.
    /// \param val New register value.
    void write_f(int i, uint64_t val) {
        derived().do_write_f(i, val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_f(%d, %llu(%llx))\n", get_name(), i, val, val);
#endif
    }

    /// \brief Reads the program counter.
    /// \returns Register value.
    uint64_t read_pc() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_pc();
        fprintf(stderr, "%s::read_pc() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_pc();
#endif
    }

    /// \brief Writes the program counter.
    /// \param val New register value.
    void write_pc(uint64_t val) {
        derived().do_write_pc(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_pc(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Writes CSR fcsr.
    /// \param val New register value.
    void write_fcsr(uint64_t val) {
        derived().do_write_fcsr(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_fcsr(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR fcsr.
    /// \returns Register value.
    uint64_t read_fcsr() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_fcsr();
        fprintf(stderr, "%s::read_fcsr() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_fcsr();
#endif
    }

    /// \brief Reads CSR icycleinstret.
    /// \returns Register value.
    uint64_t read_icycleinstret() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_icycleinstret();
        fprintf(stderr, "%s::read_icycleinstret() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_icycleinstret();
#endif
    }

    /// \brief Writes CSR icycleinstret.
    /// \param val New register value.
    void write_icycleinstret(uint64_t val) {
        derived().do_write_icycleinstret(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_icycleinstret(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR mvendorid.
    /// \returns Register value.
    uint64_t read_mvendorid() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_mvendorid();
        fprintf(stderr, "%s::read_mvendorid() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_mvendorid();
#endif
    }

    /// \brief Reads CSR marchid.
    /// \returns Register value.
    uint64_t read_marchid() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_marchid();
        fprintf(stderr, "%s::read_marchid() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_marchid();
#endif
    }

    /// \brief Reads CSR mimpid.
    /// \returns Register value.
    uint64_t read_mimpid() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_mimpid();
        fprintf(stderr, "%s::read_mimpid() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_mimpid();
#endif
    }

    /// \brief Reads CSR mcycle.
    /// \returns Register value.
    uint64_t read_mcycle() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_mcycle();
        fprintf(stderr, "%s::read_mcycle() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_mcycle();
#endif
    }

    /// \brief Writes CSR mcycle.
    /// \param val New register value.
    void write_mcycle(uint64_t val) {
        derived().do_write_mcycle(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_mcycle(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR mstatus.
    /// \returns Register value.
    uint64_t read_mstatus() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_mstatus();
        fprintf(stderr, "%s::read_mstatus() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_mstatus();
#endif
    }

    /// \brief Writes CSR mstatus.
    /// \param val New register value.
    void write_mstatus(uint64_t val) {
        derived().do_write_mstatus(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_mstatus(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR menvcfg.
    /// \returns Register value.
    uint64_t read_menvcfg() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_menvcfg();
        fprintf(stderr, "%s::read_menvcfg() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_menvcfg();
#endif
    }

    /// \brief Writes CSR menvcfg.
    /// \param val New register value.
    void write_menvcfg(uint64_t val) {
        derived().do_write_menvcfg(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_menvcfg(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR mtvec.
    /// \returns Register value.
    uint64_t read_mtvec() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_mtvec();
        fprintf(stderr, "%s::read_mtvec() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_mtvec();
#endif
    }

    /// \brief Writes CSR mtvec.
    /// \param val New register value.
    void write_mtvec(uint64_t val) {
        derived().do_write_mtvec(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_mtvec(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR mscratch.
    /// \returns Register value.
    uint64_t read_mscratch() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_mscratch();
        fprintf(stderr, "%s::read_mscratch() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_mscratch();
#endif
    }

    /// \brief Writes CSR mscratch.
    /// \param val New register value.
    void write_mscratch(uint64_t val) {
        derived().do_write_mscratch(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_mscratch(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR mepc.
    /// \returns Register value.
    uint64_t read_mepc() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_mepc();
        fprintf(stderr, "%s::read_mepc() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_mepc();
#endif
    }

    /// \brief Writes CSR mepc.
    /// \param val New register value.
    void write_mepc(uint64_t val) {
        derived().do_write_mepc(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_mepc(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR mcause.
    /// \returns Register value.
    uint64_t read_mcause() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_mcause();
        fprintf(stderr, "%s::read_mcause() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_mcause();
#endif
    }

    /// \brief Writes CSR mcause.
    /// \param val New register value.
    void write_mcause(uint64_t val) {
        derived().do_write_mcause(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_mcause(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR mtval.
    /// \returns Register value.
    uint64_t read_mtval() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_mtval();
        fprintf(stderr, "%s::read_mtval() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_mtval();
#endif
    }

    /// \brief Writes CSR mtval.
    /// \param val New register value.
    void write_mtval(uint64_t val) {
        derived().do_write_mtval(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_mtval(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR misa.
    /// \returns Register value.
    uint64_t read_misa() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_misa();
        fprintf(stderr, "%s::read_misa() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_misa();
#endif
    }

    /// \brief Writes CSR misa.
    /// \param val New register value.
    void write_misa(uint64_t val) {
        derived().do_write_misa(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_misa(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR mie.
    /// \returns Register value.
    uint64_t read_mie() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_mie();
        fprintf(stderr, "%s::read_mie() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_mie();
#endif
    }

    /// \brief Writes CSR mie.
    /// \param val New register value.
    void write_mie(uint64_t val) {
        derived().do_write_mie(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_mie(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR mip.
    /// \returns Register value.
    uint64_t read_mip() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_mip();
        fprintf(stderr, "%s::read_mip() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_mip();
#endif
    }

    /// \brief Writes CSR mip.
    /// \param val New register value.
    void write_mip(uint64_t val) {
        derived().do_write_mip(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_mip(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR medeleg.
    /// \returns Register value.
    uint64_t read_medeleg() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_medeleg();
        fprintf(stderr, "%s::read_medeleg() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_medeleg();
#endif
    }

    /// \brief Writes CSR medeleg.
    /// \param val New register value.
    void write_medeleg(uint64_t val) {
        derived().do_write_medeleg(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_medeleg(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR mideleg.
    /// \returns Register value.
    uint64_t read_mideleg() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_mideleg();
        fprintf(stderr, "%s::read_mideleg() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_mideleg();
#endif
    }

    /// \brief Writes CSR mideleg.
    /// \param val New register value.
    void write_mideleg(uint64_t val) {
        derived().do_write_mideleg(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_mideleg(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR iprv.
    /// \returns Register value.
    uint64_t read_iprv() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_iprv();
        fprintf(stderr, "%s::read_iprv() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_iprv();
#endif
    }

    /// \brief Writes CSR iprv.
    /// \param val New register value.
    void write_iprv(uint64_t val) {
        derived().do_write_iprv(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_iprv(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR iflags_X.
    /// \returns Register value.
    uint64_t read_iflags_X() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_iflags_X();
        fprintf(stderr, "%s::read_iflags_X() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_iflags_X();
#endif
    }

    /// \brief Writes CSR iflags_X.
    /// \param val New register value.
    void write_iflags_X(uint64_t val) {
        derived().do_write_iflags_X(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_iflags_X(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR iflags_Y.
    /// \returns Register value.
    uint64_t read_iflags_Y() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_iflags_Y();
        fprintf(stderr, "%s::read_iflags_Y() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_iflags_Y();
#endif
    }

    /// \brief Writes CSR iflags_Y.
    /// \param val New register value.
    void write_iflags_Y(uint64_t val) {
        derived().do_write_iflags_Y(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_iflags_Y(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR iflags_H.
    /// \returns Register value.
    uint64_t read_iflags_H() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_iflags_H();
        fprintf(stderr, "%s::read_iflags_H() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_iflags_H();
#endif
    }

    /// \brief Writes CSR iflags_H.
    /// \param val New register value.
    void write_iflags_H(uint64_t val) {
        derived().do_write_iflags_H(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_iflags_H(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR mcounteren.
    /// \returns Register value.
    uint64_t read_mcounteren() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_mcounteren();
        fprintf(stderr, "%s::read_mcounteren() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_mcounteren();
#endif
    }

    /// \brief Writes CSR mcounteren.
    /// \param val New register value.
    void write_mcounteren(uint64_t val) {
        derived().do_write_mcounteren(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_mcounteren(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR senvcfg.
    /// \returns Register value.
    uint64_t read_senvcfg() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_senvcfg();
        fprintf(stderr, "%s::read_senvcfg() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_senvcfg();
#endif
    }

    /// \brief Writes CSR senvcfg.
    /// \param val New register value.
    void write_senvcfg(uint64_t val) {
        derived().do_write_senvcfg(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_senvcfg(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR stvec.
    /// \returns Register value.
    uint64_t read_stvec() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_stvec();
        fprintf(stderr, "%s::read_stvec() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_stvec();
#endif
    }

    /// \brief Writes CSR stvec.
    /// \param val New register value.
    void write_stvec(uint64_t val) {
        derived().do_write_stvec(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_stvec(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR sscratch.
    /// \returns Register value.
    uint64_t read_sscratch() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_sscratch();
        fprintf(stderr, "%s::read_sscratch() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_sscratch();
#endif
    }

    /// \brief Writes CSR sscratch.
    /// \param val New register value.
    void write_sscratch(uint64_t val) {
        derived().do_write_sscratch(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_sscratch(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR sepc.
    /// \returns Register value.
    uint64_t read_sepc() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_sepc();
        fprintf(stderr, "%s::read_sepc() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_sepc();
#endif
    }

    /// \brief Writes CSR sepc.
    /// \param val New register value.
    void write_sepc(uint64_t val) {
        derived().do_write_sepc(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_sepc(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR scause.
    /// \returns Register value.
    uint64_t read_scause() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_scause();
        fprintf(stderr, "%s::read_scause() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_scause();
#endif
    }

    /// \brief Writes CSR scause.
    /// \param val New register value.
    void write_scause(uint64_t val) {
        derived().do_write_scause(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_scause(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR stval.
    /// \returns Register value.
    uint64_t read_stval() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_stval();
        fprintf(stderr, "%s::read_stval() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_stval();
#endif
    }

    /// \brief Writes CSR stval.
    /// \param val New register value.
    void write_stval(uint64_t val) {
        derived().do_write_stval(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_stval(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR satp.
    /// \returns Register value.
    uint64_t read_satp() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_satp();
        fprintf(stderr, "%s::read_satp() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_satp();
#endif
    }

    /// \brief Writes CSR satp.
    /// \param val New register value.
    void write_satp(uint64_t val) {
        derived().do_write_satp(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_satp(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR scounteren.
    /// \returns Register value.
    uint64_t read_scounteren() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_scounteren();
        fprintf(stderr, "%s::read_scounteren() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_scounteren();
#endif
    }

    /// \brief Writes CSR scounteren.
    /// \param val New register value.
    void write_scounteren(uint64_t val) {
        derived().do_write_scounteren(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_scounteren(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR ilrsc.
    /// \returns Register value.
    /// \details This is Cartesi-specific.
    uint64_t read_ilrsc() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_ilrsc();
        fprintf(stderr, "%s::read_ilrsc() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_ilrsc();
#endif
    }

    /// \brief Writes CSR ilrsc.
    /// \param val New register value.
    /// \details This is Cartesi-specific.
    void write_ilrsc(uint64_t val) {
        derived().do_write_ilrsc(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_ilrsc(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CSR iunrep.
    /// \returns Register value.
    /// \details This is Cartesi-specific.
    uint64_t read_iunrep() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_iunrep();
        fprintf(stderr, "%s::read_iunrep() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_iunrep();
#endif
    }

    /// \brief Writes CSR iunrep.
    /// \param val New register value.
    /// \details This is Cartesi-specific.
    void write_iunrep(uint64_t val) {
        derived().do_write_iunrep(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_iunrep(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads CLINT's mtimecmp.
    /// \returns Register value.
    uint64_t read_clint_mtimecmp() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_clint_mtimecmp();
        fprintf(stderr, "%s::read_clint_mtimecmp() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_clint_mtimecmp();
#endif
    }

    /// \brief Writes CLINT's mtimecmp.
    /// \param val New register value.
    void write_clint_mtimecmp(uint64_t val) {
        derived().do_write_clint_mtimecmp(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_clint_mtimecmp(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads PLIC's girqpend.
    /// \returns Register value.
    uint64_t read_plic_girqpend() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_plic_girqpend();
        fprintf(stderr, "%s::read_plic_girqpend() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_plic_girqpend();
#endif
    }

    /// \brief Writes PLIC's girqpend.
    /// \param val New register value.
    void write_plic_girqpend(uint64_t val) {
        derived().do_write_plic_girqpend(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_plic_girqpend(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads PLIC's girqsrvd.
    /// \returns Register value.
    uint64_t read_plic_girqsrvd() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_plic_girqsrvd();
        fprintf(stderr, "%s::read_plic_girqsrvd() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_plic_girqsrvd();
#endif
    }

    /// \brief Writes PLIC's girqsrvd.
    /// \param val New register value.
    void write_plic_girqsrvd(uint64_t val) {
        derived().do_write_plic_girqsrvd(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_plic_girqsrvd(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads HTIF's fromhost.
    /// \returns Register value.
    uint64_t read_htif_fromhost() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_htif_fromhost();
        fprintf(stderr, "%s::read_htif_fromhost() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_htif_fromhost();
#endif
    }

    /// \brief Writes HTIF's fromhost.
    /// \param val New register value.
    void write_htif_fromhost(uint64_t val) {
        derived().do_write_htif_fromhost(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_htif_fromhost(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads HTIF's tohost.
    /// \returns Register value.
    uint64_t read_htif_tohost() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_htif_tohost();
        fprintf(stderr, "%s::read_htif_tohost() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_htif_tohost();
#endif
    }

    /// \brief Writes HTIF's tohost.
    /// \param val New register value.
    void write_htif_tohost(uint64_t val) {
        derived().do_write_htif_tohost(val);
#ifdef DUMP_STATE_ACCESS
        fprintf(stderr, "%s::write_htif_tohost(%llu(0x%llx))\n", get_name(), val, val);
#endif
    }

    /// \brief Reads HTIF's ihalt.
    /// \returns Register value.
    uint64_t read_htif_ihalt() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_htif_ihalt();
        fprintf(stderr, "%s::read_htif_ihalt() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_htif_ihalt();
#endif
    }

    /// \brief Reads HTIF's iconsole.
    /// \returns Register value.
    uint64_t read_htif_iconsole() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_htif_iconsole();
        fprintf(stderr, "%s::read_htif_iconsole() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_htif_iconsole();
#endif
    }

    /// \brief Reads HTIF's iyield.
    /// \returns Register value.
    uint64_t read_htif_iyield() {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_read_htif_iyield();
        fprintf(stderr, "%s::read_htif_iyield() = %llu(0x%llx)\n", get_name(), val, val);
        return val;
#else
        return derived().do_read_htif_iyield();
#endif
    }

    /// \brief Reads PMA entry at a given index.
    /// \param index Index of PMA
    pma_entry &read_pma_entry(uint64_t index) {
#ifdef DUMP_STATE_ACCESS
        auto &pma = derived().do_read_pma_entry(index);
        fprintf(stderr, "%s::read_pma_entry(%llu) = {%s, 0x%llx, 0x%llx}\n", get_name(), index,
            pma_get_DID_name(pma.get_istart_DID()), pma.get_start(), pma.get_length());
        return pma;
#else
        return derived().do_read_pma_entry(index);
#endif
    }

    /// \brief Converts a target physical address to the implementation-defined fast address
    /// \param paddr Target physical address to convert
    /// \param pma_index Index of PMA where address falls
    /// \returns Corresponding implementation-defined fast address
    fast_addr get_faddr(uint64_t paddr, uint64_t pma_index) const {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().do_get_faddr(paddr, pma_index);
        const char *fast_addr_name = std::is_same_v<fast_addr, uint64_t> ? "phys_addr" : "fast_addr";
        fprintf(stderr, "%s::get_faddr(%llu(0x%llx)) = %s{%llu(0x%llx)}\n", get_name(), paddr, paddr, fast_addr_name,
            val, val);
        return val;
#else
        return derived().do_get_faddr(paddr, pma_index);
#endif
    }

    /// \brief Reads a chunk of data from a memory PMA range.
    /// \param paddr Target physical address.
    /// \param data Receives chunk of memory.
    /// \param length Size of chunk.
    /// \returns True if PMA was found and memory fully read, false otherwise.
    /// \details The entire chunk of data must fit inside the same memory
    /// PMA range, otherwise it fails. The search for the PMA range is implicit, and not logged.
    bool read_memory(uint64_t paddr, unsigned char *data, uint64_t length) {
        return derived().do_read_memory(paddr, data, length);
    }

    /// \brief Writes a chunk of data to a memory PMA range.
    /// \param paddr Target physical address.
    /// \param data Pointer to chunk of data.
    /// \param length Size of chunk.
    /// \returns True if PMA was found and memory fully written, false otherwise.
    /// \details The entire chunk of data must fit inside the same memory
    /// PMA range, otherwise it fails. The search for the PMA range is implicit, and not logged.
    bool write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) {
        return derived().do_write_memory(paddr, data, length);
    }

    /// \brief Write a data buffer to memory padded with 0
    /// \param paddr Destination physical address.
    /// \param data Pointer to source data buffer.
    /// \param data_length Length of data buffer.
    /// \param write_length_log2_size Log2 size of the total write length.
    void write_memory_with_padding(uint64_t paddr, const unsigned char *data, uint64_t data_length,
        int write_length_log2_size) {
        derived().do_write_memory_with_padding(paddr, data, data_length, write_length_log2_size);
    }

    /// \brief Reads a word from memory.
    /// \tparam T Type of word to read, potentially unaligned.
    /// \tparam A Type to which \p paddr and \p haddr are known to be aligned.
    /// \param faddr Implementation-defined fast address.
    /// \param pval Pointer to word receiving value.
    /// \warning T must not cross page boundary starting from \p faddr
    /// \warning T may or may not cross a Merkle tree word boundary starting from \p faddr!
    template <typename T, typename A = T>
    void read_memory_word(fast_addr faddr, uint64_t pma_index, T *pval) {
        static_assert(std::is_integral_v<T> && sizeof(T) <= sizeof(uint64_t), "unsupported type");
#ifdef DUMP_STATE_ACCESS
        derived().template do_read_memory_word<T, A>(faddr, pma_index, pval);
        const char *fast_addr_name = std::is_same_v<fast_addr, uint64_t> ? "phys_addr" : "fast_addr";
        fprintf(stderr, "%s::read_memory_word<%s,%s>(%s{0x%llx}, %llu) = %llu(0x%llx)\n", get_name(), pm_type_name_v<T>,
            pm_type_name_v<A>, fast_addr_name, faddr, pma_index, static_cast<uint64_t>(*pval),
            static_cast<uint64_t>(*pval));
#else
        derived().template do_read_memory_word<T, A>(faddr, pma_index, pval);
#endif
    }

    /// \brief Writes a word to memory.
    /// \tparam T Type of word to write.
    /// \tparam A Type to which \p paddr and \p haddr are known to be aligned.
    /// \param faddr Implementation-defined fast address.
    /// \param val Value to be written.
    /// \details \p haddr is ONLY valid when there is a host machine.
    /// It should never be referenced outside of this context.
    /// \warning T must not cross page boundary starting from \p faddr
    /// \warning T may or may not cross a Merkle tree word boundary starting from \p faddr!
    template <typename T, typename A = T>
    void write_memory_word(fast_addr faddr, uint64_t pma_index, T val) {
        static_assert(std::is_integral_v<T> && sizeof(T) <= sizeof(uint64_t), "unsupported type");
        derived().template do_write_memory_word<T, A>(faddr, pma_index, val);
#ifdef DUMP_STATE_ACCESS
        const char *fast_addr_name = std::is_same_v<fast_addr, uint64_t> ? "phys_addr" : "fast_addr";
        fprintf(stderr, "%s::write_memory_word<%s,%s>(%s{0x%llx}, %llu, %llu(0x%llx))\n", get_name(), pm_type_name_v<T>,
            pm_type_name_v<A>, fast_addr_name, faddr, pma_index, static_cast<uint64_t>(val),
            static_cast<uint64_t>(val));
#endif
    }

    /// \brief Reads TLB's vaddr_page
    /// \tparam USE TLB set
    /// \param slot_index Slot index
    /// \returns Value in slot.
    template <TLB_set_index SET>
    uint64_t read_tlb_vaddr_page(uint64_t slot_index) {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().template do_read_tlb_vaddr_page<SET>(slot_index);
        fprintf(stderr, "%s::read_tlb_vaddr_page<%llu>(%llu) = 0x%llx\n", get_name(), SET, slot_index, val);
        return val;
#else
        return derived().template do_read_tlb_vaddr_page<SET>(slot_index);
#endif
    }

    /// \brief Reads TLB's vp_offset
    /// \tparam USE TLB set
    /// \param slot_index Slot index
    /// \returns Value in slot.
    template <TLB_set_index SET>
    fast_addr read_tlb_vp_offset(uint64_t slot_index) {
#ifdef DUMP_STATE_ACCESS
        const char *fast_addr_name = std::is_same_v<fast_addr, uint64_t> ? "phys_addr" : "fast_addr";
        const auto val = derived().template do_read_tlb_vp_offset<SET>(slot_index);
        fprintf(stderr, "%s::read_tlb_vp_offset<%llu>(%llu) = %s{0x%llx}\n", get_name(), SET, slot_index,
            fast_addr_name, val);
        return val;
#else
        return derived().template do_read_tlb_vp_offset<SET>(slot_index);
#endif
    }

    /// \brief Reads TLB's pma_index
    /// \tparam USE TLB set
    /// \param slot_index Slot index
    /// \returns Value in slot.
    template <TLB_set_index SET>
    uint64_t read_tlb_pma_index(uint64_t slot_index) {
#ifdef DUMP_STATE_ACCESS
        const auto val = derived().template do_read_tlb_pma_index<SET>(slot_index);
        fprintf(stderr, "%s::read_tlb_pma_index<%llu>(%llu) = %llu(0x%llx)\n", get_name(), SET, slot_index, val, val);
        return val;
#else
        return derived().template do_read_tlb_pma_index<SET>(slot_index);
#endif
    }

    /// \brief Writes to a TLB slot
    /// \tparam USE TLB set
    /// \param slot_index Slot index
    /// \param vaddr_page Value to write
    /// \param vp_offset Value to write
    /// \param pma_index Value to write
    /// \detail Writes to the TLB must be modify all fields atomically to prevent an inconsistent state.
    /// This simplifies all state access implementations.
    template <TLB_set_index SET>
    void write_tlb(uint64_t slot_index, uint64_t vaddr_page, fast_addr vp_offset, uint64_t pma_index) {
        derived().template do_write_tlb<SET>(slot_index, vaddr_page, vp_offset, pma_index);
#ifdef DUMP_STATE_ACCESS
        const char *fast_addr_name = std::is_same_v<fast_addr, uint64_t> ? "phys_addr" : "fast_addr";
        fprintf(stderr, "%s::write_tlb<%llu>(%llu, 0x%llx, %s{0x%llx}, %llu)\n", get_name(), SET, slot_index,
            vaddr_page, fast_addr_name, vp_offset, pma_index);
#endif
    }

    /// \brief Marks a page as dirty
    /// \param faddr Implementation-defined fast address.
    /// \param pma_index Index of PMA where page falls
    /// \details When there is a host machine, the Merkle tree only updates the hashes for pages that
    /// have been modified. Pages can only be written to if they appear in the write TLB. Therefore,
    /// the Merkle tree only considers the pages that are currently in the write TLB and those that
    /// have been marked dirty. When a page leaves the write TLB, it is marked dirty.
    /// If the state belongs to a host machine, then this call MUST be forwarded to machine::mark_dirty_page();
    void mark_dirty_page(fast_addr faddr, uint64_t pma_index) {
        derived().do_mark_dirty_page(faddr, pma_index);
    }

    /// \brief Writes a character to the console
    /// \param c Character to output
    void putchar(uint8_t c) {
        derived().do_putchar(c);
    }

#ifdef DUMP_COUNTERS
    //??D we should probably remove this from the interface
    auto &get_statistics() {
        return derived().do_get_statistics();
    }
#endif

    constexpr const char *get_name() const {
        return derived().do_get_name();
    }
};

/// \brief SFINAE test implementation of the i_state_access interface
template <typename DERIVED>
using is_an_i_state_access =
    std::integral_constant<bool, is_template_base_of_v<i_state_access, std::remove_cvref_t<DERIVED>>>;

template <typename DERIVED>
constexpr bool is_an_i_state_access_v = is_an_i_state_access<DERIVED>::value;

} // namespace cartesi

#endif
