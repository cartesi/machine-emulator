#ifndef PROCESSOR_STATE_H
#define PROCESSOR_STATE_H

#include <cstdint>

#define TLB_SIZE 256

#include "iomem.h"

typedef struct {
    uint64_t vaddr;
    uintptr_t mem_addend;
} tlb_entry;

struct processor_state {
    uint64_t pc;
    uint64_t reg[32];

    uint8_t iflags_PRV; // current privilege level
    bool iflags_I;      // CPU is idle (waiting for interrupts)
    bool iflags_H;      // CPU has been permanently halted
    bool brk;           // Set when the tight loop must be broken

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

    PhysMemoryMap *mem_map;

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
