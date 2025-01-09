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

#include <array>
#include <cstdint>

#ifdef DUMP_HIST
#include <unordered_map>
#endif

#include <boost/container/static_vector.hpp>

#include "pma-constants.h"
#include "pma.h"
#include "riscv-constants.h"
#include "shadow-tlb.h"

namespace cartesi {

/// \brief Machine state.
/// \details The machine_state structure contains the entire
/// state of a Cartesi machine.
struct machine_state {
    machine_state() = default;
    ~machine_state() = default;

    /// \brief No copy or move constructor or assignment
    machine_state(const machine_state &other) = delete;
    machine_state(machine_state &&other) = delete;
    machine_state &operator=(const machine_state &other) = delete;
    machine_state &operator=(machine_state &&other) = delete;

    // The following state fields are very hot,
    // and are carefully ordered to have better data locality in the interpreter loop.
    uint64_t mcycle{};                     ///< CSR mcycle.
    uint64_t pc{};                         ///< Program counter.
    std::array<uint64_t, X_REG_COUNT> x{}; ///< Register file.
    uint64_t fcsr{};                       ///< CSR fcsr.
    std::array<uint64_t, F_REG_COUNT> f{}; ///< Floating-point register file.

    uint64_t icycleinstret{}; ///< CSR icycleinstret.

    uint64_t mstatus{};  ///< CSR mstatus.
    uint64_t mtvec{};    ///< CSR mtvec.
    uint64_t mscratch{}; ///< CSR mscratch.
    uint64_t mepc{};     ///< CSR mepc.
    uint64_t mcause{};   ///< CSR mcause.
    uint64_t mtval{};    ///< CSR mtval.
    uint64_t misa{};     ///< CSR misa.

    uint64_t mie{};        ///< CSR mie.
    uint64_t mip{};        ///< CSR mip.
    uint64_t medeleg{};    ///< CSR medeleg.
    uint64_t mideleg{};    ///< CSR mideleg.
    uint64_t mcounteren{}; ///< CSR mcounteren.
    uint64_t menvcfg{};    ///< CSR menvcfg.

    uint64_t stvec{};      ///< CSR stvec.
    uint64_t sscratch{};   ///< CSR sscratch.
    uint64_t sepc{};       ///< CSR sepc.
    uint64_t scause{};     ///< CSR scause.
    uint64_t stval{};      ///< CSR stval.
    uint64_t satp{};       ///< CSR satp.
    uint64_t scounteren{}; ///< CSR scounteren.
    uint64_t senvcfg{};    ///< CSR senvcfg.

    // Cartesi-specific state
    uint64_t ilrsc{}; ///< For LR/SC instructions (Cartesi-specific).
    uint64_t iprv{};  ///< Privilege level (Cartesi-specific).
    struct {
        uint64_t X{}; ///< CPU has yielded with automatic reset (Cartesi-specific).
        uint64_t Y{}; ///< CPU has yielded with manual reset (Cartesi-specific).
        uint64_t H{}; ///< CPU has been permanently halted (Cartesi-specific).
    } iflags;
    uint64_t iunrep{}; ///< Unreproducible mode (Cartesi-specific).

    /// \brief CLINT state
    struct {
        uint64_t mtimecmp{}; ///< CSR mtimecmp.
    } clint;

    /// \brief PLIC state
    struct {
        uint64_t girqpend{}; ///< CSR girqpend (global interrupts pending).
        uint64_t girqsrvd{}; ///< CSR girqsrvd (global interrupts served).
    } plic;

    /// \brief TLB state
    tlb_state tlb{};

    /// \brief HTIF state
    struct {
        uint64_t tohost{};   ///< CSR tohost.
        uint64_t fromhost{}; ///< CSR fromhost.
        uint64_t ihalt{};    ///< CSR ihalt.
        uint64_t iconsole{}; ///< CSR iconsole.
        uint64_t iyield{};   ///< CSR iyield.
    } htif;

    /// Soft yield
    bool soft_yield{};

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
};

} // namespace cartesi

#endif
