#ifndef STATE_H
#define STATE_H

#include <cstdint>

struct pma_memory {
    uint8_t *host_memory;      // start of associated memory region in host
    int backing_file;          // file descryptor for backed memory
} ;

//??D change this to a class with a virtual interface
struct pma_device {
    void *context;
    pma_device_read read;
    pma_device_write write;
    pma_device_peek peek;
    pma_device_update_merkle_tree update_merkle_tree;
};

// physical memory attribute entry
struct pma_entry {
    uint64_t start;        // start of physical memory range
    uint64_t length;       // end of physical memory range
    uint32_t type_flags;   // type and flags of range
    union {
        pma_memory memory; // memory-specific data
        pma_device device; // device-specific data
    }; // anonymous union
};

#define PMA_SIZE 32

struct tlb_entry {
    uint64_t vaddr;       // virtual address of page start
    uintptr_t mem_addend; // value added to translate from virtual to physical addresses in page
};

#define TLB_SIZE 256

struct machine_state {
    uint64_t pc;
    uint64_t reg[32];

    uint8_t iflags_PRV; // current privilege level
    bool iflags_I;      // CPU is idle (waiting for interrupts)
    bool iflags_H;      // CPU has been permanently halted

    /* CSRs */
    uint64_t minstret;
    uint64_t mcycle;

    uint64_t mstatus;
    uint64_t mtvec;
    uint64_t mscratch;
    uint64_t mepc;
    uint64_t mcause;
    uint64_t mtval;
    uint64_t misa;

    uint32_t mie;
    uint32_t mip;
    uint32_t medeleg;
    uint32_t mideleg;
    uint32_t mcounteren;

    uint64_t stvec;
    uint64_t sscratch;
    uint64_t sepc;
    uint64_t scause;
    uint64_t stval;
    uint64_t satp;
    uint32_t scounteren;

    uint64_t ilrsc; // For LR/SC instructions

    uint64_t mtimecmp; // CLINT
    uint64_t tohost, fromhost; // HTIF

    pma_entry physical_memory[PMA_SIZE]; // Physical memory map
    int pma_count;             // number of entries in map

    // Entries below this mark are not needed in the blockchain

    bool brk;           // Set when the tight loop must be broken

    tlb_entry tlb_read[TLB_SIZE];
    tlb_entry tlb_write[TLB_SIZE];
    tlb_entry tlb_code[TLB_SIZE];

#ifdef DUMP_COUNTERS
    uint64_t count_inners; // Executions of inner loop
    uint64_t count_outers; // Executions of outer loop
    uint64_t count_si;     // Supervisor interrupts
    uint64_t count_se;     // Supervisor exceptions (except ECALL)
    uint64_t count_mi;     // Machine interrupts
    uint64_t count_me;     // Machine exceptions (except ECALL)
    uint64_t count_amo;    // Atomic memory operations
#endif

};

#endif
