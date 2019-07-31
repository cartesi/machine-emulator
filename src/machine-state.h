// Copyright 2019 Cartesi Pte. Ltd.
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

#ifndef STATE_H
#define STATE_H

/// \file
/// \brief Cartesi machine state structure definition.

#include <cstdint>

#include <boost/container/static_vector.hpp>

#include "pma.h"
#include "riscv-constants.h"

#ifdef DUMP_COUNTERS
#define INC_COUNTER(state, counter) do {state.stats.counter++;} while (0)
#else
#define INC_COUNTER(state, counter) do {} while (0)
#endif

namespace cartesi {

/// \brief Translation Lookaside Buffer entry.
/// \details The TLB is a small cache used to speed up translation between
/// virtual target addresses and the corresponding memory address in the host.
struct tlb_entry {
    pma_entry *pma;            ///< PMA entry for corresponding range
    uint64_t paddr_page;       ///< Target physical address of page start
    uint64_t vaddr_page;       ///< Target virtual address of page start
    unsigned char *hpage;      ///< Pointer to page start in host memory
};

/// \brief TLB constants
enum TLB_constants {
    TLB_SIZE = 256 ///< Number of entries in TLB
};

#ifdef DUMP_COUNTERS
/// \brief Machine statistics
struct machine_statistics {
    uint64_t inner_loop;       ///< Counts executions of inner loop
    uint64_t outer_loop;       ///< Counts executions of outer loop
    uint64_t sv_int;           ///< Counts supervisor interrupts
    uint64_t sv_ex;            ///< Counts supervisor exceptions (except ECALL)
    uint64_t m_int;            ///< Counts machine interrupts
    uint64_t m_ex;             ///< Counts machine exceptions (except ECALL)
    uint64_t atomic_mop;       ///< Counts atomic memory operations
    uint64_t tlb_rhit;         ///< Counts TLB read access hits
    uint64_t tlb_rmiss;        ///< Counts TLB read access misses
    uint64_t tlb_whit;         ///< Counts TLB write access hits
    uint64_t tlb_wmiss;        ///< Counts TLB write access misses
    uint64_t tlb_chit;         ///< Counts TLB code access hits
    uint64_t tlb_cmiss;        ///< Counts TLB code access misses
    uint64_t flush_all;        ///< Counts flush all calls
    uint64_t flush_va;         ///< Counts flush virtual address calls
    uint64_t fence;            ///< Counts fence calls
    uint64_t fence_i;          ///< Counts fence.i calls
    uint64_t fence_vma;        ///< Counts fence.vma calls
    uint64_t priv_level[4];    ///< Counts changes to privilege levels
};
#endif

/// \brief Machine state.
/// \details The machine_state structure contains the entire
/// state of a Cartesi machine.
struct machine_state {

    ~machine_state() { ; } // Due to bug in clang++

    /// \brief No copy or move constructor or assignment
    machine_state(const machine_state &other) = delete;
    machine_state(machine_state &&other) = delete;
    machine_state &operator=(const machine_state &other) = delete;
    machine_state &operator=(machine_state &&other) = delete;

    uint64_t pc;        ///< Program counter.
    uint64_t x[32];     ///< Register file.

    uint64_t minstret;  ///< CSR minstret.
    uint64_t mcycle;

    uint64_t mvendorid; ///< CSR mvendorid;
    uint64_t marchid;   ///< CSR marchid;
    uint64_t mimpid;    ///< CSR mimpid;

    uint64_t mstatus; ///< CSR mstatus.
    uint64_t mtvec; ///< CSR mtvec.
    uint64_t mscratch; ///< CSR mscratch.
    uint64_t mepc; ///< CSR mepc.
    uint64_t mcause; ///< CSR mcause.
    uint64_t mtval; ///< CSR mtval.
    uint64_t misa; ///< CSR misa.

    uint64_t mie; ///< CSR mie.
    uint64_t mip; ///< CSR mip.
    uint64_t medeleg; ///< CSR medeleg.
    uint64_t mideleg; ///< CSR mideleg.
    uint64_t mcounteren; ///< CSR mcounteren.

    uint64_t stvec; ///< CSR stvec.
    uint64_t sscratch; ///< CSR sscratch.
    uint64_t sepc; ///< CSR sepc.
    uint64_t scause; ///< CSR scause.
    uint64_t stval; ///< CSR stval.
    uint64_t satp; ///< CSR satp.
    uint64_t scounteren; ///< CSR scounteren.

    // Cartesi-specific state
    uint64_t ilrsc;  ///< Cartesi-specific CSR ilrsc (For LR/SC instructions).
    struct {
        uint8_t PRV; ///< Privilege level.
        bool I;      ///< CPU is idle (waiting for interrupts).
        bool H;      ///< CPU has been permanently halted.
    } iflags;        ///< Cartesi-specific unpacked CSR iflags.

    /// \brief CLINT state
    struct {
        uint64_t mtimecmp; ///< CSR mtimecmp.
    } clint;

    /// \brief HTIF state
    struct {
        uint64_t tohost;    ///< CSR tohost.
        uint64_t fromhost;  ///< CSR fromhost.
    } htif;

    /// Map of physical memory ranges
    boost::container::static_vector<pma_entry, PMA_MAX> pmas;

    pma_entry empty_pma;         ///< fallback to PMA for empty range

    // Entries below this mark are not needed in the blockchain

    bool brk;           ///< Flag set when the tight loop must be broken.

    tlb_entry tlb_read[TLB_SIZE]; ///< Read TLB
    tlb_entry tlb_write[TLB_SIZE]; ///< Write TLB
    tlb_entry tlb_code[TLB_SIZE]; ///< Code TLB

#ifdef DUMP_COUNTERS
    struct machine_statistics stats;
#endif

    /// \brief Updates the brk flag from changes in mip and mie registers.
    void set_brk_from_mip_mie(void) {
        brk = mip & mie;
    }

    /// \brief Updates the brk flag from changes in the iflags_H flag.
    void set_brk_from_iflags_H(void) {
        brk = iflags.H;
    }

    /// \brief Reads the value of the iflags register.
    /// \returns The value of the register.
    uint64_t read_iflags(void) const {
        return packed_iflags(
            iflags.PRV,
            iflags.I,
            iflags.H
        );
    }

    /// \brief Reads the value of the iflags register.
    /// \param val New register value.
    void write_iflags(uint64_t val) {
        iflags.H = (val >> IFLAGS_H_SHIFT) & 1;
        iflags.I = (val >> IFLAGS_I_SHIFT) & 1;
        iflags.PRV = (val >> IFLAGS_PRV_SHIFT) & 3;
    }

    static uint64_t packed_iflags(int PRV, int I, int H) {
        return (PRV << IFLAGS_PRV_SHIFT) |
               (I << IFLAGS_I_SHIFT) |
               (H << IFLAGS_H_SHIFT);
    }

    /// \brief Initializes all TLBs with invalid entries.
    void init_tlb(void) {
        for (int i = 0; i < TLB_SIZE; ++i) {
            tlb_read[i].pma = nullptr;
            tlb_read[i].vaddr_page = UINT64_C(-1);
            tlb_read[i].paddr_page = UINT64_C(-1);
            tlb_read[i].hpage = nullptr;
            tlb_write[i].pma = nullptr;
            tlb_write[i].vaddr_page = UINT64_C(-1);
            tlb_write[i].paddr_page = UINT64_C(-1);
            tlb_write[i].hpage = nullptr;
            tlb_code[i].pma = nullptr;
            tlb_code[i].vaddr_page = UINT64_C(-1);
            tlb_code[i].paddr_page = UINT64_C(-1);
            tlb_code[i].hpage = nullptr;
        }
    }

};

} // namespace cartesi

#endif
