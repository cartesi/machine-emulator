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

#ifndef STATE_H
#define STATE_H

/// \file
/// \brief Cartesi machine state structure definition.

#include <cassert>
#include <cstdint>
#include <iostream>

#ifdef DUMP_HIST
#include <unordered_map>
#endif

#include <boost/container/static_vector.hpp>

#include "machine-statistics.h"
#include "pma.h"
#include "riscv-constants.h"
#include "shadow-tlb.h"

namespace cartesi {

struct unpacked_iflags {
    bool V;      ///< Virtual mode.
    uint8_t NOM; ///< Nominal privilege level.
    bool X;      ///< CPU has yielded with automatic reset.
    bool Y;      ///< CPU has yielded with manual reset.
    bool H;      ///< CPU has been permanently halted.
};               ///< Cartesi-specific unpacked CSR iflags.

/// \brief Machine state.
/// \details The machine_state structure contains the entire
/// state of a Cartesi machine.
struct machine_state {

    ~machine_state() {
        ;
    } // Due to bug in clang++

    /// \brief No copy or move constructor or assignment
    machine_state(const machine_state &other) = delete;
    machine_state(machine_state &&other) = delete;
    machine_state &operator=(const machine_state &other) = delete;
    machine_state &operator=(machine_state &&other) = delete;

    // The following state fields are very hot,
    // and are carefully ordered to have better data locality in the interpreter loop.
    uint64_t mcycle;                     ///< CSR mcycle.
    uint64_t pc;                         ///< Program counter.
    std::array<uint64_t, X_REG_COUNT> x; ///< Register file.
    uint64_t fcsr;                       ///< CSR fcsr.
    std::array<uint64_t, F_REG_COUNT> f; ///< Floating-point register file.

    uint64_t icycleinstret; ///< CSR icycleinstret.

    uint64_t mstatus;  ///< CSR mstatus.
    uint64_t mtvec;    ///< CSR mtvec.
    uint64_t mscratch; ///< CSR mscratch.
    uint64_t mepc;     ///< CSR mepc.
    uint64_t mcause;   ///< CSR mcause.
    uint64_t mtval;    ///< CSR mtval.
    uint64_t misa;     ///< CSR misa.

    uint64_t mie;        ///< CSR mie.
    uint64_t mip;        ///< CSR mip.
    uint64_t medeleg;    ///< CSR medeleg.
    uint64_t mideleg;    ///< CSR mideleg.
    uint64_t mcounteren; ///< CSR mcounteren.
    uint64_t menvcfg;    ///< CSR menvcfg.

    uint64_t stvec;      ///< CSR stvec.
    uint64_t sscratch;   ///< CSR sscratch.
    uint64_t sepc;       ///< CSR sepc.
    uint64_t scause;     ///< CSR scause.
    uint64_t stval;      ///< CSR stval.
    uint64_t satp;       ///< CSR satp.
    uint64_t scounteren; ///< CSR scounteren.
    uint64_t senvcfg;    ///< CSR senvcfg.

    uint64_t hstatus;    ///< CSR hstatus.
    uint64_t hideleg;    ///< CSR hideleg.
    uint64_t hedeleg;    ///< CSR hedeleg.
    uint64_t hip;        ///< CSR hip.
    uint64_t hvip;       ///< CSR hvip.
    uint64_t hie;        ///< CSR hie.
    uint64_t hgatp;      ///< CSR hgatp.
    uint64_t henvcfg;    ///< CSR henvcfg.
    uint64_t htimedelta; ///< CSR htimedelta.
    uint64_t htval;      ///< CSR htval.

    uint64_t vsepc;     ///< CSR vsepc.
    uint64_t vsstatus;  ///< CSR vsstatus.
    uint64_t vscause;   ///< CSR vscause.
    uint64_t vstval;    ///< CSR vstval.
    uint64_t vstvec;    ///< CSR vstvec.
    uint64_t vsscratch; ///< CSR vsscratch.
    uint64_t vsatp;     ///< CSR vsatp.
    uint64_t vsie;      ///< CSR vsie.
    uint64_t vsip;      ///< CSR vsip.

    // Cartesi-specific state
    uint64_t ilrsc; ///< Cartesi-specific CSR ilrsc (For LR/SC instructions).

    unpacked_iflags iflags; ///< Cartesi-specific unpacked CSR iflags.

    /// \brief CLINT state
    struct {
        uint64_t mtimecmp; ///< CSR mtimecmp.
    } clint;

    /// \brief TLB state
    shadow_tlb_state tlb;

    /// \brief HTIF state
    struct {
        uint64_t tohost;   ///< CSR tohost.
        uint64_t fromhost; ///< CSR fromhost.
        uint64_t ihalt;    ///< CSR ihalt.
        uint64_t iconsole; ///< CSR iconsole.
        uint64_t iyield;   ///< CSR iyield.
    } htif;

    /// Map of physical memory ranges
    boost::container::static_vector<pma_entry, PMA_MAX> pmas;

    pma_entry empty_pma; ///< fallback to PMA for empty range

    // Entries below this mark are not needed in the blockchain

#ifdef DUMP_COUNTERS
    machine_statistics stats;
#endif

#ifdef DUMP_HIST
    std::unordered_map<std::string, uint64_t> insn_hist;
#endif

    /// \brief Reads the value of the iflags register.
    /// \returns The value of the register.
    uint64_t read_iflags(void) const {
        return packed_iflags(iflags.V, iflags.NOM, iflags.X, iflags.Y, iflags.H);
    }

    /// \brief Reads the value of the iflags register.
    /// \param val New register value.
    void write_iflags(uint64_t val) {
        iflags.H = (val & IFLAGS_H_MASK) >> IFLAGS_H_SHIFT;
        iflags.Y = (val & IFLAGS_Y_MASK) >> IFLAGS_Y_SHIFT;
        iflags.X = (val & IFLAGS_X_MASK) >> IFLAGS_X_SHIFT;
        iflags.NOM = (val & IFLAGS_NOM_MASK) >> IFLAGS_NOM_SHIFT;
        iflags.V = (val & IFLAGS_V_MASK) >> IFLAGS_V_SHIFT;
    }

    /// \brief Packs iflags into the CSR value
    /// \param V virtual mode
    /// \param NOM nominal privilege level
    /// \param I Waiting for interrupts flag
    /// \param Y Yielded flag
    /// \param H Halted flag
    /// \returns Packed iflags
    static uint64_t packed_iflags(int V, int NOM, int X, int Y, int H) {
        return (V << IFLAGS_V_SHIFT) | (NOM << IFLAGS_NOM_SHIFT) | (X << IFLAGS_X_SHIFT) | (Y << IFLAGS_Y_SHIFT) |
            (H << IFLAGS_H_SHIFT);
    }
};

} // namespace cartesi

#endif
