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

#include "machine-statistics.h"
#include "meta.h"
#include "shadow-tlb.h"

namespace cartesi {

// Forward declarations
enum class bracket_type;

/// \class i_state_access
/// \brief Interface for machine state access.
/// \details \{
/// The final "step" function must log all read and write accesses to the state.
/// The "run" function does not need a log, and must be as fast as possible.
/// Both functions share the exact same implementation of what it means to advance the machine state by one cycle.
/// In this common implementation, all state accesses go through a class that implements the i_state_access interface.
/// When looging is needed, a logged_state_access class is used.
/// When no logging is needed, a state_access class is used.
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
template <typename DERIVED, typename PMA_ENTRY_TYPE>
class i_state_access { // CRTP

    /// \brief Returns object cast as the derived class
    DERIVED &derived(void) {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived(void) const {
        return *static_cast<const DERIVED *>(this);
    }

public:
    /// \brief Returns machine state for direct access.
    auto &get_naked_state(void) {
        return derived().do_get_naked_state();
    }

    /// \brief Adds an annotation bracket to the log
    /// \param type Type of bracket
    /// \param text String with the text for the annotation
    void push_bracket(bracket_type type, const char *text) {
        return derived().do_push_bracket(type, text);
    }

    /// \brief Adds annotations to the state, bracketing a scope
    /// \param text String with the text for the annotation
    /// \returns An object that, when constructed and destroyed issues an annonation.
    auto make_scoped_note(const char *text) {
        return derived().do_make_scoped_note(text);
    }

    /// \brief Reads from general-purpose register.
    /// \param reg Register index.
    /// \returns Register value.
    uint64_t read_x(int reg) {
        return derived().do_read_x(reg);
    }

    /// \brief Writes register to general-purpose register.
    /// \param reg Register index.
    /// \param val New register value.
    /// \details Writes to register zero *break* the machine. There is an assertion to catch this, but NDEBUG will let
    /// the value pass through.
    void write_x(int reg, uint64_t val) {
        return derived().do_write_x(reg, val);
    }

    /// \brief Reads from floating-point register.
    /// \param reg Register index.
    /// \returns Register value.
    uint64_t read_f(int reg) {
        return derived().do_read_f(reg);
    }

    /// \brief Writes register to floating-point register.
    /// \param reg Register index.
    /// \param val New register value.
    void write_f(int reg, uint64_t val) {
        return derived().do_write_f(reg, val);
    }

    /// \brief Reads the program counter.
    /// \returns Register value.
    uint64_t read_pc(void) {
        return derived().do_read_pc();
    }

    /// \brief Writes the program counter.
    /// \param val New register value.
    void write_pc(uint64_t val) {
        return derived().do_write_pc(val);
    }

    /// \brief Writes CSR fcsr.
    /// \param val New register value.
    void write_fcsr(uint64_t val) {
        return derived().do_write_fcsr(val);
    }

    /// \brief Reads CSR fcsr.
    /// \returns Register value.
    uint64_t read_fcsr(void) {
        return derived().do_read_fcsr();
    }

    /// \brief Reads CSR icycleinstret.
    /// \returns Register value.
    uint64_t read_icycleinstret(void) {
        return derived().do_read_icycleinstret();
    }

    /// \brief Writes CSR icycleinstret.
    /// \param val New register value.
    void write_icycleinstret(uint64_t val) {
        return derived().do_write_icycleinstret(val);
    }

    /// \brief Reads CSR mvendorid.
    /// \returns Register value.
    uint64_t read_mvendorid(void) {
        return derived().do_read_mvendorid();
    }

    /// \brief Reads CSR marchid.
    /// \returns Register value.
    uint64_t read_marchid(void) {
        return derived().do_read_marchid();
    }

    /// \brief Reads CSR mimpid.
    /// \returns Register value.
    uint64_t read_mimpid(void) {
        return derived().do_read_mimpid();
    }

    /// \brief Reads CSR mcycle.
    /// \returns Register value.
    uint64_t read_mcycle(void) {
        return derived().do_read_mcycle();
    }

    /// \brief Writes CSR mcycle.
    /// \param val New register value.
    void write_mcycle(uint64_t val) {
        return derived().do_write_mcycle(val);
    }

    /// \brief Reads CSR mstatus.
    /// \returns Register value.
    uint64_t read_mstatus(void) {
        return derived().do_read_mstatus();
    }

    /// \brief Writes CSR mstatus.
    /// \param val New register value.
    void write_mstatus(uint64_t val) {
        return derived().do_write_mstatus(val);
    }

    /// \brief Reads CSR menvcfg.
    /// \returns Register value.
    uint64_t read_menvcfg(void) {
        return derived().do_read_menvcfg();
    }

    /// \brief Writes CSR menvcfg.
    /// \param val New register value.
    void write_menvcfg(uint64_t val) {
        return derived().do_write_menvcfg(val);
    }

    /// \brief Reads CSR mtvec.
    /// \returns Register value.
    uint64_t read_mtvec(void) {
        return derived().do_read_mtvec();
    }

    /// \brief Writes CSR mtvec.
    /// \param val New register value.
    void write_mtvec(uint64_t val) {
        return derived().do_write_mtvec(val);
    }

    /// \brief Reads CSR mscratch.
    /// \returns Register value.
    uint64_t read_mscratch(void) {
        return derived().do_read_mscratch();
    }

    /// \brief Writes CSR mscratch.
    /// \param val New register value.
    void write_mscratch(uint64_t val) {
        return derived().do_write_mscratch(val);
    }

    /// \brief Reads CSR mepc.
    /// \returns Register value.
    uint64_t read_mepc(void) {
        return derived().do_read_mepc();
    }

    /// \brief Writes CSR mepc.
    /// \param val New register value.
    void write_mepc(uint64_t val) {
        return derived().do_write_mepc(val);
    }

    /// \brief Reads CSR mcause.
    /// \returns Register value.
    uint64_t read_mcause(void) {
        return derived().do_read_mcause();
    }

    /// \brief Writes CSR mcause.
    /// \param val New register value.
    void write_mcause(uint64_t val) {
        return derived().do_write_mcause(val);
    }

    /// \brief Reads CSR mtval.
    /// \returns Register value.
    uint64_t read_mtval(void) {
        return derived().do_read_mtval();
    }

    /// \brief Writes CSR mtval.
    /// \param val New register value.
    void write_mtval(uint64_t val) {
        return derived().do_write_mtval(val);
    }

    /// \brief Reads CSR misa.
    /// \returns Register value.
    uint64_t read_misa(void) {
        return derived().do_read_misa();
    }

    /// \brief Writes CSR misa.
    /// \param val New register value.
    void write_misa(uint64_t val) {
        return derived().do_write_misa(val);
    }

    /// \brief Reads CSR mie.
    /// \returns Register value.
    uint64_t read_mie(void) {
        return derived().do_read_mie();
    }

    /// \brief Writes CSR mie.
    /// \param val New register value.
    void write_mie(uint64_t val) {
        return derived().do_write_mie(val);
    }

    /// \brief Reads CSR mip.
    /// \returns Register value.
    uint64_t read_mip(void) {
        return derived().do_read_mip();
    }

    /// \brief Writes CSR mip.
    /// \param val New register value.
    void write_mip(uint64_t val) {
        return derived().do_write_mip(val);
    }

    /// \brief Reads CSR medeleg.
    /// \returns Register value.
    uint64_t read_medeleg(void) {
        return derived().do_read_medeleg();
    }

    /// \brief Writes CSR medeleg.
    /// \param val New register value.
    void write_medeleg(uint64_t val) {
        return derived().do_write_medeleg(val);
    }

    /// \brief Reads CSR mideleg.
    /// \returns Register value.
    uint64_t read_mideleg(void) {
        return derived().do_read_mideleg();
    }

    /// \brief Writes CSR mideleg.
    /// \param val New register value.
    void write_mideleg(uint64_t val) {
        return derived().do_write_mideleg(val);
    }

    /// \brief Reads CSR iflags.
    /// \returns CSR value.
    auto read_iflags(void) {
        return derived().do_read_iflags();
    }

    /// \brief Writes CSR iflags.
    /// \param val New register value.
    auto write_iflags(uint64_t val) {
        return derived().do_write_iflags(val);
    }

    /// \brief Reads CSR mcounteren.
    /// \returns Register value.
    uint64_t read_mcounteren(void) {
        return derived().do_read_mcounteren();
    }

    /// \brief Writes CSR mcounteren.
    /// \param val New register value.
    void write_mcounteren(uint64_t val) {
        return derived().do_write_mcounteren(val);
    }

    /// \brief Reads CSR senvcfg.
    /// \returns Register value.
    uint64_t read_senvcfg(void) {
        return derived().do_read_senvcfg();
    }

    /// \brief Writes CSR senvcfg.
    /// \param val New register value.
    void write_senvcfg(uint64_t val) {
        return derived().do_write_senvcfg(val);
    }

    /// \brief Reads CSR hstatus.
    /// \returns Register value.
    uint64_t read_hstatus(void) {
        return derived().do_read_hstatus();
    }

    /// \brief Writes CSR hstatus.
    /// \param val New register value.
    void write_hstatus(uint64_t val) {
        return derived().do_write_hstatus(val);
    }

    /// \brief Reads CSR hideleg.
    /// \returns Register value.
    uint64_t read_hideleg(void) {
        return derived().do_read_hideleg();
    }

    /// \brief Writes CSR hideleg.
    /// \param val New register value.
    void write_hideleg(uint64_t val) {
        return derived().do_write_hideleg(val);
    }

    /// \brief Reads CSR hedeleg.
    /// \returns Register value.
    uint64_t read_hedeleg(void) {
        return derived().do_read_hedeleg();
    }

    /// \brief Writes CSR hedeleg.
    /// \param val New register value.
    void write_hedeleg(uint64_t val) {
        return derived().do_write_hedeleg(val);
    }

    /// \brief Reads CSR hip.
    /// \returns Register value.
    uint64_t read_hip(void) {
        return derived().do_read_hip();
    }

    /// \brief Writes CSR hip.
    /// \param val New register value.
    void write_hip(uint64_t val) {
        return derived().do_write_hip(val);
    }

    /// \brief Reads CSR hvip.
    /// \returns Register value.
    uint64_t read_hvip(void) {
        return derived().do_read_hvip();
    }

    /// \brief Writes CSR hvip.
    /// \param val New register value.
    void write_hvip(uint64_t val) {
        return derived().do_write_hvip(val);
    }

    /// \brief Reads CSR hie.
    /// \returns Register value.
    uint64_t read_hie(void) {
        return derived().do_read_hie();
    }

    /// \brief Writes CSR hie.
    /// \param val New register value.
    void write_hie(uint64_t val) {
        return derived().do_write_hie(val);
    }

    /// \brief Reads CSR hgatp.
    /// \returns Register value.
    uint64_t read_hgatp(void) {
        return derived().do_read_hgatp();
    }

    /// \brief Writes CSR hgatp.
    /// \param val New register value.
    void write_hgatp(uint64_t val) {
        return derived().do_write_hgatp(val);
    }

    /// \brief Reads CSR henvcfg.
    /// \returns Register value.
    uint64_t read_henvcfg(void) {
        return derived().do_read_henvcfg();
    }

    /// \brief Writes CSR henvcfg.
    /// \param val New register value.
    void write_henvcfg(uint64_t val) {
        return derived().do_write_henvcfg(val);
    }

    /// \brief Reads CSR htimedelta.
    /// \returns Register value.
    uint64_t read_htimedelta(void) {
        return derived().do_read_htimedelta();
    }

    /// \brief Writes CSR htimedelta.
    /// \param val New register value.
    void write_htimedelta(uint64_t val) {
        return derived().do_write_htimedelta(val);
    }

    /// \brief Reads CSR htval.
    /// \returns Register value.
    uint64_t read_htval(void) {
        return derived().do_read_htval();
    }

    /// \brief Writes CSR htval.
    /// \param val New register value.
    void write_htval(uint64_t val) {
        return derived().do_write_htval(val);
    }

    /// \brief Reads CSR vsepc.
    /// \returns Register value.
    uint64_t read_vsepc(void) {
        return derived().do_read_vsepc();
    }

    /// \brief Writes CSR vsepc.
    /// \param val New register value.
    void write_vsepc(uint64_t val) {
        return derived().do_write_vsepc(val);
    }

    /// \brief Reads CSR vsstatus.
    /// \returns Register value.
    uint64_t read_vsstatus(void) {
        return derived().do_read_vsstatus();
    }

    /// \brief Writes CSR vsstatus.
    /// \param val New register value.
    void write_vsstatus(uint64_t val) {
        return derived().do_write_vsstatus(val);
    }

    /// \brief Reads CSR vscause.
    /// \returns Register value.
    uint64_t read_vscause(void) {
        return derived().do_read_vscause();
    }

    /// \brief Writes CSR vscause.
    /// \param val New register value.
    void write_vscause(uint64_t val) {
        return derived().do_write_vscause(val);
    }

    /// \brief Reads CSR vstval.
    /// \returns Register value.
    uint64_t read_vstval(void) {
        return derived().do_read_vstval();
    }

    /// \brief Writes CSR vstval.
    /// \param val New register value.
    void write_vstval(uint64_t val) {
        return derived().do_write_vstval(val);
    }

    /// \brief Reads CSR vstvec.
    /// \returns Register value.
    uint64_t read_vstvec(void) {
        return derived().do_read_vstvec();
    }

    /// \brief Writes CSR vstvec.
    /// \param val New register value.
    void write_vstvec(uint64_t val) {
        return derived().do_write_vstvec(val);
    }

    /// \brief Reads CSR vsscratch.
    /// \returns Register value.
    uint64_t read_vsscratch(void) {
        return derived().do_read_vsscratch();
    }

    /// \brief Writes CSR vsscratch.
    /// \param val New register value.
    void write_vsscratch(uint64_t val) {
        return derived().do_write_vsscratch(val);
    }

    /// \brief Reads CSR vsatp.
    /// \returns Register value.
    uint64_t read_vsatp(void) {
        return derived().do_read_vsatp();
    }

    /// \brief Writes CSR vsatp.
    /// \param val New register value.
    void write_vsatp(uint64_t val) {
        return derived().do_write_vsatp(val);
    }

    /// \brief Reads CSR vsip.
    /// \returns Register value.
    uint64_t read_vsip(void) {
        return derived().do_read_vsip();
    }

    /// \brief Writes CSR vsip.
    /// \param val New register value.
    void write_vsip(uint64_t val) {
        return derived().do_write_vsip(val);
    }

    /// \brief Reads CSR vsie.
    /// \returns Register value.
    uint64_t read_vsie(void) {
        return derived().do_read_vsie();
    }

    /// \brief Writes CSR vsie.
    /// \param val New register value.
    void write_vsie(uint64_t val) {
        return derived().do_write_vsie(val);
    }

    /// \brief Reads CSR stvec.
    /// \returns Register value.
    uint64_t read_stvec(void) {
        return derived().do_read_stvec();
    }

    /// \brief Writes CSR stvec.
    /// \param val New register value.
    void write_stvec(uint64_t val) {
        return derived().do_write_stvec(val);
    }

    /// \brief Reads CSR sscratch.
    /// \returns Register value.
    uint64_t read_sscratch(void) {
        return derived().do_read_sscratch();
    }

    /// \brief Writes CSR sscratch.
    /// \param val New register value.
    void write_sscratch(uint64_t val) {
        return derived().do_write_sscratch(val);
    }

    /// \brief Reads CSR sepc.
    /// \returns Register value.
    uint64_t read_sepc(void) {
        return derived().do_read_sepc();
    }

    /// \brief Writes CSR sepc.
    /// \param val New register value.
    void write_sepc(uint64_t val) {
        return derived().do_write_sepc(val);
    }

    /// \brief Reads CSR scause.
    /// \returns Register value.
    uint64_t read_scause(void) {
        return derived().do_read_scause();
    }

    /// \brief Writes CSR scause.
    /// \param val New register value.
    void write_scause(uint64_t val) {
        return derived().do_write_scause(val);
    }

    /// \brief Reads CSR stval.
    /// \returns Register value.
    uint64_t read_stval(void) {
        return derived().do_read_stval();
    }

    /// \brief Writes CSR stval.
    /// \param val New register value.
    void write_stval(uint64_t val) {
        return derived().do_write_stval(val);
    }

    /// \brief Reads CSR satp.
    /// \returns Register value.
    uint64_t read_satp(void) {
        return derived().do_read_satp();
    }

    /// \brief Writes CSR satp.
    /// \param val New register value.
    void write_satp(uint64_t val) {
        return derived().do_write_satp(val);
    }

    /// \brief Reads CSR scounteren.
    /// \returns Register value.
    uint64_t read_scounteren(void) {
        return derived().do_read_scounteren();
    }

    /// \brief Writes CSR scounteren.
    /// \param val New register value.
    void write_scounteren(uint64_t val) {
        return derived().do_write_scounteren(val);
    }

    /// \brief Reads CSR ilrsc.
    /// \returns Register value.
    /// \details This is Cartesi-specific.
    uint64_t read_ilrsc(void) {
        return derived().do_read_ilrsc();
    }

    /// \brief Writes CSR ilrsc.
    /// \param val New register value.
    /// \details This is Cartesi-specific.
    void write_ilrsc(uint64_t val) {
        return derived().do_write_ilrsc(val);
    }

    /// \brief Sets the iflags_H flag.
    /// \details This is Cartesi-specific.
    void set_iflags_H(void) {
        return derived().do_set_iflags_H();
    }

    /// \brief Reads the iflags_H flag.
    /// \returns The flag value.
    /// \details This is Cartesi-specific.
    bool read_iflags_H(void) {
        return derived().do_read_iflags_H();
    }

    /// \brief Sets the iflags_Y flag.
    /// \details This is Cartesi-specific.
    void set_iflags_Y(void) {
        return derived().do_set_iflags_Y();
    }

    /// \brief Sets the iflags_X flag.
    /// \details This is Cartesi-specific.
    void set_iflags_X(void) {
        return derived().do_set_iflags_X();
    }

    /// \brief Resets the iflags_Y flag.
    /// \details This is Cartesi-specific.
    void reset_iflags_Y(void) {
        return derived().do_reset_iflags_Y();
    }

    /// \brief Resets the iflags_X flag.
    /// \details This is Cartesi-specific.
    void reset_iflags_X(void) {
        return derived().do_reset_iflags_X();
    }

    /// \brief Reads the iflags_Y flag.
    /// \returns The flag value.
    /// \details This is Cartesi-specific.
    bool read_iflags_Y(void) {
        return derived().do_read_iflags_Y();
    }

    /// \brief Reads the iflags_X flag.
    /// \returns The flag value.
    /// \details This is Cartesi-specific.
    bool read_iflags_X(void) {
        return derived().do_read_iflags_X();
    }

    /// \brief Reads the iflags_VRT flag.
    /// \returns The flag value.
    /// \details This is Cartesi-specific.
    bool read_iflags_VRT(void) {
        return derived().do_read_iflags_VRT();
    }

    /// \brief Resets the iflags_VRT flag.
    /// \details This is Cartesi-specific.
    void reset_iflags_VRT(void) {
        return derived().do_reset_iflags_VRT();
    }

    /// \brief Sets the iflags_VRT flag.
    /// \details This is Cartesi-specific.
    void set_iflags_VRT(void) {
        return derived().do_set_iflags_VRT();
    }

    /// \brief Reads the current privilege mode from iflags_PRV.
    /// \details This is Cartesi-specific.
    /// \returns Current privilege mode.
    uint8_t read_iflags_PRV(void) {
        return derived().do_read_iflags_PRV();
    }

    /// \brief Changes the privilege mode in iflags_PRV.
    /// \details This is Cartesi-specific.
    void write_iflags_PRV(uint8_t val) {
        return derived().do_write_iflags_PRV(val);
    }

    /// \brief Reads CLINT's mtimecmp.
    /// \returns Register value.
    uint64_t read_clint_mtimecmp(void) {
        return derived().do_read_clint_mtimecmp();
    }

    /// \brief Writes CLINT's mtimecmp.
    /// \param val New register value.
    void write_clint_mtimecmp(uint64_t val) {
        return derived().do_write_clint_mtimecmp(val);
    }

    /// \brief Reads HTIF's fromhost.
    /// \returns Register value.
    uint64_t read_htif_fromhost(void) {
        return derived().do_read_htif_fromhost();
    }

    /// \brief Writes HTIF's fromhost.
    /// \param val New register value.
    void write_htif_fromhost(uint64_t val) {
        return derived().do_write_htif_fromhost(val);
    }

    /// \brief Reads HTIF's tohost.
    /// \returns Register value.
    uint64_t read_htif_tohost(void) {
        return derived().do_read_htif_tohost();
    }

    /// \brief Writes HTIF's tohost.
    /// \param val New register value.
    void write_htif_tohost(uint64_t val) {
        return derived().do_write_htif_tohost(val);
    }

    /// \brief Reads HTIF's ihalt.
    /// \returns Register value.
    uint64_t read_htif_ihalt(void) {
        return derived().do_read_htif_ihalt();
    }

    /// \brief Reads HTIF's iconsole.
    /// \returns Register value.
    uint64_t read_htif_iconsole(void) {
        return derived().do_read_htif_iconsole();
    }

    /// \brief Reads HTIF's iyield.
    /// \returns Register value.
    uint64_t read_htif_iyield(void) {
        return derived().do_read_htif_iyield();
    }

    /// \brief Polls console for pending input.
    /// \param mcycle Current machine mcycle.
    /// \returns The new machine mcycle advanced by the relative time elapsed while polling.
    uint64_t poll_console(uint64_t mcycle) {
        return derived().do_poll_console(mcycle);
    }

    /// \brief Reads PMA at a given index.
    /// \param pma PMA entry.
    /// \param i Index of PMA index.
    void read_pma(const PMA_ENTRY_TYPE &pma, int i) {
        return derived().do_read_pma(pma, i);
    }

    /// \brief Reads the istart field of a PMA entry
    /// \param p Index of PMA
    uint64_t read_pma_istart(int p) {
        return derived().do_read_pma_istart(p);
    }

    /// \brief Reads the ilength field of a PMA entry
    /// \param p Index of PMA
    uint64_t read_pma_ilength(int p) {
        return derived().do_read_pma_ilength(p);
    }

    /// \brief Writes a chunk of data to a memory PMA range.
    /// \param paddr Target physical address. Must be aligned to data size.
    /// \param data Pointer to chunk of data.
    /// \param log2_size Log 2 of data length. Must be >= 3 and < 64.
    /// \details The entire chunk of data must fit inside the same memory
    /// PMA range. The search for the PMA range is implicit, and not logged.
    void write_memory(uint64_t paddr, const unsigned char *data, uint64_t log2_size) {
        return derived().do_write_memory(paddr, data, log2_size);
    }

    /// \brief Reads a word from memory.
    /// \tparam T Type of word to read.
    /// \param paddr Target physical address.
    /// \param hpage Pointer to page start in host memory.
    /// \param hoffset Offset in page (must be aligned to sizeof(T)).
    /// \param pval Pointer to word receiving value.
    template <typename T>
    void read_memory_word(uint64_t paddr, const unsigned char *hpage, uint64_t hoffset, T *pval) {
        static_assert(std::is_integral<T>::value && sizeof(T) <= sizeof(uint64_t), "unsupported type");
        return derived().template do_read_memory_word<T>(paddr, hpage, hoffset, pval);
    }

    /// \brief Writes a word to memory.
    /// \tparam T Type of word to write.
    /// \param paddr Target physical address.
    /// \param hpage Pointer to page start in host memory.
    /// \param hoffset Offset in page (must be aligned to sizeof(T)).
    /// \param val Value to be written.
    template <typename T>
    void write_memory_word(uint64_t paddr, unsigned char *hpage, uint64_t hoffset, T val) {
        static_assert(std::is_integral<T>::value && sizeof(T) <= sizeof(uint64_t), "unsupported type");
        return derived().template do_write_memory_word<T>(paddr, hpage, hoffset, val);
    }

    /// \brief Obtain PMA entry covering a physical memory word
    /// \param paddr Target physical address.
    /// \returns Corresponding entry if found, or a sentinel entry
    /// for an empty range.
    /// \tparam T Type of word.
    template <typename T>
    PMA_ENTRY_TYPE &find_pma_entry(uint64_t paddr) {
        return derived().template do_find_pma_entry<T>(paddr);
    }

    auto get_host_memory(PMA_ENTRY_TYPE &pma) {
        return derived().do_get_host_memory(pma);
    }

    PMA_ENTRY_TYPE &get_pma_entry(int index) {
        return derived().do_get_pma_entry(index);
    }

    auto read_device(PMA_ENTRY_TYPE &pma, uint64_t mcycle, uint64_t offset, uint64_t *pval, int log2_size) {
        return derived().do_read_device(pma, mcycle, offset, pval, log2_size);
    }

    auto write_device(PMA_ENTRY_TYPE &pma, uint64_t mcycle, uint64_t offset, uint64_t pval, int log2_size) {
        return derived().do_write_device(pma, mcycle, offset, pval, log2_size);
    }

    auto read_uarch_ram_length() {
        return derived().do_read_uarch_ram_length();
    }

    /// \brief Try to translate a virtual address to a host pointer through the TLB.
    /// \tparam ETYPE TLB entry type.
    /// \tparam T Type of word that would be read with the pointer.
    /// \param vaddr Target virtual address.
    /// \param phptr Pointer to host pointer receiving value.
    /// \returns True if successful (TLB hit), false otherwise.
    template <TLB_entry_type ETYPE, typename T>
    bool translate_vaddr_via_tlb(uint64_t vaddr, unsigned char **phptr) {
        return derived().template do_translate_vaddr_via_tlb<ETYPE, T>(vaddr, phptr);
    }

    /// \brief Try to read a word from memory through the TLB.
    /// \tparam ETYPE TLB entry type.
    /// \tparam T Type of word to read.
    /// \param vaddr Target virtual address.
    /// \param pval Pointer to word receiving value.
    /// \returns True if successful (TLB hit), false otherwise.
    template <TLB_entry_type ETYPE, typename T>
    bool read_memory_word_via_tlb(uint64_t vaddr, T *pval) {
        static_assert(std::is_integral<T>::value && sizeof(T) <= sizeof(uint64_t), "unsupported type");
        return derived().template do_read_memory_word_via_tlb<ETYPE, T>(vaddr, pval);
    }

    /// \brief Try to write a word to memory through the TLB.
    /// \tparam ETYPE TLB entry type.
    /// \tparam T Type of word to write.
    /// \param vaddr Target virtual address.
    /// \param val Value to be written.
    /// \returns True if successful (TLB hit), false otherwise.
    template <TLB_entry_type ETYPE, typename T>
    bool write_memory_word_via_tlb(uint64_t vaddr, T val) {
        static_assert(std::is_integral<T>::value && sizeof(T) <= sizeof(uint64_t), "unsupported type");
        return derived().template do_write_memory_word_via_tlb<ETYPE, T>(vaddr, val);
    }

    /// \brief Replaces an entry in the TLB.
    /// \tparam ETYPE TLB entry type to replace.
    /// \param vaddr Target virtual address.
    /// \param paddr Target physical address.
    /// \param pma PMA entry for the physical address.
    /// \returns Pointer to page start in host memory.
    template <TLB_entry_type ETYPE>
    unsigned char *replace_tlb_entry(uint64_t vaddr, uint64_t paddr, PMA_ENTRY_TYPE &pma) {
        return derived().template do_replace_tlb_entry<ETYPE>(vaddr, paddr, pma);
    }

    /// \brief Invalidates all TLB entries of a type.
    /// \tparam ETYPE TLB entry type to flush.
    template <TLB_entry_type ETYPE>
    void flush_tlb_type() {
        return derived().template do_flush_tlb_type<ETYPE>();
    }

    /// \brief Invalidates all TLB entries of all types.
    void flush_all_tlb() {
        derived().template flush_tlb_type<TLB_CODE>();
        derived().template flush_tlb_type<TLB_READ>();
        derived().template flush_tlb_type<TLB_WRITE>();
    }

    /// \brief Invalidates TLB entries for a specific virtual address.
    /// \param vaddr Target virtual address.
    void flush_tlb_vaddr(uint64_t vaddr) {
        return derived().do_flush_tlb_vaddr(vaddr);
    }

#ifdef DUMP_COUNTERS
    auto &get_statistics() {
        return derived().do_get_statistics();
    }
#endif
};

/// \brief SFINAE test implementation of the i_state_access interface
template <typename DERIVED>
using is_an_i_state_access =
    std::integral_constant<bool, is_template_base_of<i_state_access, typename remove_cvref<DERIVED>::type>::value>;

} // namespace cartesi

#endif
