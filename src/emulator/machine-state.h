#ifndef STATE_H
#define STATE_H

/// \file
/// \brief Cartesi machine state.

#include <cstdint>

/// \brief Data for memory ranges.
struct pma_memory {
    uint8_t *host_memory;      ///< Start of associated memory region in host.
    int backing_file;          ///< File descryptor for backed memory.
} ;

//??D change this to a class with a virtual interface
/// \brief Data for device ranges.
struct pma_device {
    void *context;            ///< Device context set during initialization.
    pma_device_read read;     ///< Callback for read operations.
    pma_device_write write;   ///< Callback for write operations.
    pma_device_peek peek;     ///< Callback for peek operations.
    pma_device_update_merkle_tree update_merkle_tree; ///< Callback for Merkle tree updates.
};

/// \brief Physical Memory Attribute entry.
/// \details The target's physical memory layout is described by an
/// array of PMA entries.
struct pma_entry {
    uint64_t start;        ///< Start of physical memory range in target.
    uint64_t length;       ///< Length of physical memory range in target.
    uint32_t type_flags;   ///< Type and flags of range.
    union {
        pma_memory memory; ///< Memory-specific data.
        pma_device device; ///< Device-specific data.
    }; // anonymous union
};

#define PMA_SIZE 32 ///< Maximum number of PMAs

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
    uint64_t reg[32];   ///< Register file.

    uint8_t iflags_PRV; ///< Privilege level.
    bool iflags_I;      ///< CPU is idle (waiting for interrupts).
    bool iflags_H;      ///< CPU has been permanently halted.

    uint64_t minstret;  ///< CSR minstret.
    uint64_t mcycle;

    uint64_t mstatus; ///< CSR mstatus.
    uint64_t mtvec; ///< CSR mtvec.
    uint64_t mscratch; ///< CSR mscratch.
    uint64_t mepc; ///< CSR mepc.
    uint64_t mcause; ///< CSR mcause.
    uint64_t mtval; ///< CSR mtval.
    uint64_t misa; ///< CSR misa.

    uint32_t mie; ///< CSR mie.
    uint32_t mip; ///< CSR mip.
    uint32_t medeleg; ///< CSR medeleg.
    uint32_t mideleg; ///< CSR mideleg.
    uint32_t mcounteren; ///< CSR mcounteren.

    uint64_t stvec; ///< CSR stvec.
    uint64_t sscratch; ///< CSR sscratch.
    uint64_t sepc; ///< CSR sepc.
    uint64_t scause; ///< CSR scause.
    uint64_t stval; ///< CSR stval.
    uint64_t satp; ///< CSR satp.
    uint32_t scounteren; ///< CSR scounteren.

    uint64_t ilrsc; ///< For LR/SC instructions

    uint64_t mtimecmp; ///< CLINT register mtimecmp.
    uint64_t tohost; ///< HTIF register tohost.
    uint64_t fromhost; ///< HTIF register fromhost.

    pma_entry physical_memory[PMA_SIZE]; ///< Physical memory map
    int pma_count;             ///< Number of entries in map

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
