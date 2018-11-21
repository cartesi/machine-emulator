#ifndef STATE_H
#define STATE_H

/// \file
/// \brief Cartesi machine state structure definition.

#include <cstdint>

#include "pma.h"

/// \brief Translation Lookaside Buffer entry.
/// \details The TLB is a small cache used to speed up translation between
/// virtual target addresses and the corresponding memory address in the host.
struct tlb_entry {
    uint64_t vaddr;       ///< Virtual address of page start
    uintptr_t mem_addend; ///< Value added to translate from virtual to physical addresses in page
};

#define TLB_SIZE 256 ///< Number of entries in TLB

/// \brief Machine state.
/// \details The machine_state structure contains the entire
/// state of a Cartesi machine.
struct machine_state {
    uint64_t pc;        ///< Program counter.
    uint64_t x[32];     ///< Register file.

    uint8_t iflags_PRV; ///< Privilege level.
    bool iflags_I;      ///< CPU is idle (waiting for interrupts).
    bool iflags_H;      ///< CPU has been permanently halted.

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

    uint64_t ilrsc; ///< For LR/SC instructions

    uint64_t clint_mtimecmp; ///< CLINT CSR mtimecmp.
    uint64_t htif_tohost;    ///< HTIF CSR tohost.
    uint64_t htif_fromhost;  ///< HTIF CSR fromhost.

    /// Map of physical memory ranges
    pma_entries pmas;

    const pma_entry *shadow_pma; ///< PMA for shadow device
    const pma_entry *htif_pma; ///< PMA for HTIF device
    const pma_entry *clint_pma; ///< PMA for CLINT device

    // Entries below this mark are not needed in the blockchain

    bool brk;           ///< Flag set when the tight loop must be broken.

    tlb_entry tlb_read[TLB_SIZE]; ///< Read TLB
    tlb_entry tlb_write[TLB_SIZE]; ///< Write TLB
    tlb_entry tlb_code[TLB_SIZE]; ///< Code TLB

#ifdef DUMP_COUNTERS
    uint64_t count_inners; ///< Counts executions of inner loop
    uint64_t count_outers; ///< Counts executions of outer loop
    uint64_t count_si;     ///< Counts supervisor interrupts
    uint64_t count_se;     ///< Counts supervisor exceptions (except ECALL)
    uint64_t count_mi;     ///< Counts machine interrupts
    uint64_t count_me;     ///< Counts machine exceptions (except ECALL)
    uint64_t count_amo;    ///< Counts atomic memory operations
#endif

};

#endif
