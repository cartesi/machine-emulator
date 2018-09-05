/*
 * RISCV CPU emulator
 *
 * Copyright (c) 2016-2017 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cinttypes>
#include <cstdint>
#include <cassert>
#include <bitset>
#include <iostream>
#include <functional>
#include <limits>
#include <type_traits>

//??D
//
// This code assumes the host's byte-ordering is the same as RISC-V's.
// RISC-V is little endian, and so is x86.
// There is a static_assert to prevent the code from compiling otherwise.
//
// This code assumes the modulo operator is such that
//
//      (a/b)*b + a%b = a
//
// i.e., the sign of the result is the sign of a.
// This is only guaranteed from C++11 forward.
//
//   https://en.cppreference.com/w/cpp/language/operator_arithmetic
//
// RISC-V does not define this (at least I have not found it
// in the documentation), but the tests seem assume this behavior.
//
//   https://github.com/riscv/riscv-tests/blob/master/isa/rv64um/rem.S
//
// EVM defines the same behavior. See the yellowpaper.
//
// This code assumes right-shifts of negative values are arithmetic shifts.
// This is implementation-defined in C and C++.
// Most compilers indeed do arithmetic shifts:
//
//   https://docs.microsoft.com/en-us/cpp/c-language/right-shifts
//   https://gcc.gnu.org/onlinedocs/gcc-7.3.0/gcc/Integers-implementation.html#Integers-implementation
//   (clang should behave the same as gcc, but does not document it)
//   (I have not found documentation for icc)
//
// EVM does not have a shift operator.
// Solidity defines shift as division, which means it rounds negative numbers towards zero.
// WARNING: An arithmetic shift right would "round" a negative number away from zero!
//
// The code assumes narrowing conversions of signed types are modulo operations.
// This is implementation-defined in C and C++.
// Most compilers indeed do modulo narrowing:
//
//   https://docs.microsoft.com/en-us/cpp/c-language/demotion-of-integers
//   https://gcc.gnu.org/onlinedocs/gcc-7.3.0/gcc/Integers-implementation.html#Integers-implementation
//   (clang should behave the same as gcc, but does not document it)
//   (I have not found documentation for icc)
//
// Signed integer overflows are UNDEFINED according to C and C++.
// We do not assume signed integers handle overflow with modulo arithmetic.
// Detecting and preventing overflows is awkward and costly.
// Fortunately, GCC offers intrinsics that have well-defined overflow behavior.
//
//   https://gcc.gnu.org/onlinedocs/gcc-7.3.0/gcc/Integer-Overflow-Builtins.html#Integer-Overflow-Builtins
//

// GCC complains about __int128 with -pedantic or -pedantic-errors
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;
#pragma GCC diagnostic pop

#define XLEN 64
#define MXL   2

#include "iomem.h"
#include "processor.h"
#include "processor-state.h"
#include "state-access.h"
#include "device-state-access.h"

#define CAUSE_MISALIGNED_FETCH             0x0
#define CAUSE_FETCH_FAULT                  0x1
#define CAUSE_ILLEGAL_INSTRUCTION          0x2
#define CAUSE_BREAKPOINT                   0x3
#define CAUSE_LOAD_ADDRESS_MISALIGNED      0x4
#define CAUSE_LOAD_FAULT                   0x5
#define CAUSE_STORE_AMO_ADDRESS_MISALIGNED 0x6
#define CAUSE_STORE_AMO_FAULT              0x7
#define CAUSE_ECALL_BASE                   0x8
#define CAUSE_FETCH_PAGE_FAULT             0xc
#define CAUSE_LOAD_PAGE_FAULT              0xd
#define CAUSE_STORE_AMO_PAGE_FAULT         0xf

#define CAUSE_INTERRUPT  ((uint64_t)1 << 63)

/* privilege levels */
#define PRV_U 0
#define PRV_S 1
#define PRV_H 2
#define PRV_M 3

/* misa CSR */
#define MCPUID_SUPER   (1 << ('S' - 'A'))
#define MCPUID_USER    (1 << ('U' - 'A'))
#define MCPUID_I       (1 << ('I' - 'A'))
#define MCPUID_M       (1 << ('M' - 'A'))
#define MCPUID_A       (1 << ('A' - 'A'))
#define MCPUID_F       (1 << ('F' - 'A'))
#define MCPUID_D       (1 << ('D' - 'A'))
#define MCPUID_Q       (1 << ('Q' - 'A'))
#define MCPUID_C       (1 << ('C' - 'A'))

/* mstatus CSR */
#define MSTATUS_UIE_SHIFT 0
#define MSTATUS_SIE_SHIFT 1
#define MSTATUS_HIE_SHIFT 2
#define MSTATUS_MIE_SHIFT 3
#define MSTATUS_UPIE_SHIFT 4
#define MSTATUS_SPIE_SHIFT 5
#define MSTATUS_MPIE_SHIFT 7
#define MSTATUS_SPP_SHIFT 8
#define MSTATUS_MPP_SHIFT 11
#define MSTATUS_FS_SHIFT 13
#define MSTATUS_SD_SHIFT 31
#define MSTATUS_UXL_SHIFT 32
#define MSTATUS_SXL_SHIFT 34

#define MSTATUS_UIE (1 << 0)
#define MSTATUS_SIE (1 << 1)
#define MSTATUS_HIE (1 << 2)
#define MSTATUS_MIE (1 << 3)
#define MSTATUS_UPIE (1 << 4)
#define MSTATUS_SPIE (1 << MSTATUS_SPIE_SHIFT)
#define MSTATUS_HPIE (1 << 6)
#define MSTATUS_MPIE (1 << MSTATUS_MPIE_SHIFT)
#define MSTATUS_SPP (1 << MSTATUS_SPP_SHIFT)
#define MSTATUS_HPP (3 << 9)
#define MSTATUS_MPP (3 << MSTATUS_MPP_SHIFT)
#define MSTATUS_FS (3 << MSTATUS_FS_SHIFT)
#define MSTATUS_XS (3 << 15)
#define MSTATUS_MPRV (1 << 17)
#define MSTATUS_SUM (1 << 18)
#define MSTATUS_MXR (1 << 19)
#define MSTATUS_TVM (1 << 20)
#define MSTATUS_TW (1 << 21)
#define MSTATUS_TSR (1 << 22)
#define MSTATUS_SD ((uint64_t)1 << MSTATUS_SD_SHIFT)
#define MSTATUS_UXL ((uint64_t)3 << MSTATUS_UXL_SHIFT)
#define MSTATUS_SXL ((uint64_t)3 << MSTATUS_SXL_SHIFT)

#define PG_SHIFT 12
#define PG_MASK ((1 << PG_SHIFT) - 1)

static void print_uint64_t(uint64_t a) {
    fprintf(stderr, "%016" PRIx64, a);
}

static const char *reg_name[32] = {
"zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
"s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
"a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
"s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
};

void dump_regs(processor_state *s)
{
    int i, cols;
    const char priv_str[] = "USHM";
    cols = 256 / XLEN;
    fprintf(stderr, "pc = ");
    print_uint64_t(s->pc);
    fprintf(stderr, " ");
    for(i = 1; i < 32; i++) {
        fprintf(stderr, "%-3s= ", reg_name[i]);
        print_uint64_t(s->reg[i]);
        if ((i & (cols - 1)) == (cols - 1))
            fprintf(stderr, "\n");
        else
            fprintf(stderr, " ");
    }
    fprintf(stderr, "priv=%c", priv_str[s->iflags_PRV]);
    fprintf(stderr, " mstatus=");
    print_uint64_t(s->mstatus);
    fprintf(stderr, " cycles=%" PRId64, s->mcycle);
    fprintf(stderr, " insns=%" PRId64, s->minstret);
    fprintf(stderr, "\n");
#if 1
    fprintf(stderr, "mideleg=");
    print_uint64_t(s->mideleg);
    fprintf(stderr, " mie=");
    print_uint64_t(s->mie);
    fprintf(stderr, " mip=");
    print_uint64_t(s->mip);
    fprintf(stderr, "\n");
#endif
}

/* addr must be aligned. Only RAM accesses are supported */
template <typename T>
static inline void phys_write(processor_state *s, uint64_t addr, T val) {
    PhysMemoryRange *pr = get_phys_mem_range(s->mem_map, addr);
    if (!pr || !pr->is_ram)
        return;
    *(T *)(pr->phys_mem + (uintptr_t)(addr - pr->addr)) = val;
}

template <typename T>
static inline T phys_read(processor_state *s, uint64_t addr) {
    PhysMemoryRange *pr = get_phys_mem_range(s->mem_map, addr);
    if (!pr || !pr->is_ram)
        return 0;
    return *(T *)(pr->phys_mem + (uintptr_t)(addr - pr->addr));
}

template <typename T> int size_log2(void);

template <> int size_log2<uint8_t>(void) { return 0; }
template <> int size_log2<uint16_t>(void) { return 1; }
template <> int size_log2<uint32_t>(void) { return 2; }
template <> int size_log2<uint64_t>(void) { return 3; }

#define PTE_V_MASK (1 << 0)
#define PTE_U_MASK (1 << 4)
#define PTE_A_MASK (1 << 6)
#define PTE_D_MASK (1 << 7)
#define PTE_XWR_READ_SHIFT  0
#define PTE_XWR_WRITE_SHIFT 1
#define PTE_XWR_CODE_SHIFT  2

// return 0 if OK, -1 if translation error
static int get_phys_addr(processor_state *s,
                         uint64_t *ppaddr, uint64_t vaddr,
                         int xwr_shift)
{
    int priv = s->iflags_PRV;

    // When MPRV is set, data loads and stores use privilege in MPP
    // instead of the current privilege level (code access is unaffected)
    if ((s->mstatus & MSTATUS_MPRV) && xwr_shift != PTE_XWR_CODE_SHIFT) {
        priv = (s->mstatus >> MSTATUS_MPP_SHIFT) & 3;
    }

    // M-mode code does not use virtual memory
    if (priv == PRV_M) {
        *ppaddr = vaddr;
        return 0;
    }

    // In RV64, mode can be
    //   0: Bare: No translation or protection
    //   8: sv39: Page-based 39-bit virtual addressing
    //   9: sv48: Page-based 48-bit virtual addressing
    int mode = (s->satp >> 60) & 0xf;
    if (mode == 0) {
        *ppaddr = vaddr;
        return 0;
    } else if (mode < 8 || mode > 9) {
        return -1;
    }
    // Here we know we are in sv39 or sv48 modes

    // Page table hierarchy of sv39 has 3 levels, and sv48 has 4 levels
    // ??D It doesn't seem like restricting to one or the other will
    //     simplify the code much
    int levels = mode - 8 + 3;

    // The least significant 12 bits of vaddr are the page offset
    // Then come levels virtual page numbers (VPN)
    // The rest of vaddr must be filled with copies of the
    // most significant bit in VPN[levels]
    // Hence, the use of arithmetic shifts here
    int vaddr_shift = XLEN - (PG_SHIFT + levels * 9);
    if ((((int64_t)vaddr << vaddr_shift) >> vaddr_shift) != (int64_t) vaddr)
        return -1;

    // The least significant 44 bits of satp contain the physical page number for the root page table
    const int satp_ppn_bits = 44;
    // Initialize pte_addr with the base address for the root page table
    uint64_t pte_addr = (s->satp & (((uint64_t)1 << satp_ppn_bits) - 1)) << PG_SHIFT;
    // All page table entries have 8 bytes
    const int pte_size_log2 = 3;
    // Each page table has 4k/pte_size entries
    // To index all entries, we need vpn_bits
    const int vpn_bits = 12 - pte_size_log2;
    uint64_t vpn_mask = (1 << vpn_bits) - 1;
    for (int i = 0; i < levels; i++) {
        // Mask out VPN[levels-i-1]
        vaddr_shift = PG_SHIFT + vpn_bits * (levels - 1 - i);
        uint64_t vpn = (vaddr >> vaddr_shift) & vpn_mask;
        // Add offset to find physical address of page table entry
        pte_addr += vpn << pte_size_log2; //??D we can probably save this shift here
        // Read page table entry from physical memory
        uint64_t pte = phys_read<uint64_t>(s, pte_addr);
        // The OS can mark page table entries as invalid,
        // but these entries shouldn't be reached during page lookups
        if (!(pte & PTE_V_MASK))
            return -1;
        // Clear all flags in least significant bits, then shift back to multiple of page size to form physical address
        uint64_t ppn = (pte >> 10) << PG_SHIFT;
        // Obtain X, W, R protection bits
        int xwr = (pte >> 1) & 7;
        // xwr != 0 means we are done walking the page tables
        if (xwr != 0) {
            // These protection bit combinations are reserved for future use
            if (xwr == 2 || xwr == 6)
                return -1;
            // (We know we are not PRV_M if we reached here)
            if (priv == PRV_S) {
                // If SUM is set, forbid S-mode code from accessing U-mode memory
                if ((pte & PTE_U_MASK) && !(s->mstatus & MSTATUS_SUM))
                    return -1;
            } else {
                // Forbid U-mode code from accessing S-mode memory
                if (!(pte & PTE_U_MASK))
                    return -1;
            }
            // MXR allows read access to execute-only pages
            if (s->mstatus & MSTATUS_MXR)
                // Set R bit if X bit is set
                xwr |= (xwr >> 2);
            // Check protection bits against requested access
            if (((xwr >> xwr_shift) & 1) == 0)
                return -1;
            // Check page, megapage, and gigapage alignment
            uint64_t vaddr_mask = ((uint64_t)1 << vaddr_shift) - 1;
            if (ppn & vaddr_mask)
                return -1;
            // Decide if we need to update access bits in pte
            bool update_pte = !(pte & PTE_A_MASK) || (!(pte & PTE_D_MASK) && xwr_shift == PTE_XWR_WRITE_SHIFT);
            pte |= PTE_A_MASK;
            if (xwr_shift == PTE_XWR_WRITE_SHIFT)
                pte |= PTE_D_MASK;
            // If so, update pte
            if (update_pte)
                phys_write<uint64_t>(s, pte_addr, pte);
            // Add page offset in vaddr to ppn to form physical address
            *ppaddr = (vaddr & vaddr_mask) | (ppn & ~vaddr_mask);
            return 0;
        // xwr == 0 means we have a pointer to the start of the next page table
        } else {
            pte_addr = ppn;
        }
    }
    return -1;
}


static void tlb_init(processor_state *s) {
    for (int i = 0; i < TLB_SIZE; i++) {
        s->tlb_read[i].vaddr = -1;
        s->tlb_write[i].vaddr = -1;
        s->tlb_code[i].vaddr = -1;
    }
}

static void tlb_flush_all(processor_state *s) {
    tlb_init(s);
}

static void tlb_flush_vaddr(processor_state *s, uint64_t vaddr) {
    (void) vaddr;
    //??D Optimize depending on how often it is used
    tlb_flush_all(s);
}

void processor_flush_tlb_write_range_ram(processor_state *s, uint8_t *ram_ptr, size_t ram_size)
{
    //??D Optimize depending on how often it is used
    uint8_t *ram_end = ram_ptr + ram_size;
    for (int i = 0; i < TLB_SIZE; i++) {
        if (s->tlb_write[i].vaddr != (uint64_t) -1) {
            uint8_t *ptr = (uint8_t *)(s->tlb_write[i].mem_addend + (uintptr_t)s->tlb_write[i].vaddr);
            if (ptr >= ram_ptr && ptr < ram_end) {
                s->tlb_write[i].vaddr = -1;
            }
        }
    }
}

#define SSTATUS_WRITE_MASK ( \
    MSTATUS_UIE  | \
    MSTATUS_SIE  | \
    MSTATUS_UPIE | \
    MSTATUS_SPIE | \
    MSTATUS_SPP  | \
    MSTATUS_FS   | \
    MSTATUS_SUM  | \
    MSTATUS_MXR  \
)

#define SSTATUS_READ_MASK ( \
    MSTATUS_UIE  | \
    MSTATUS_SIE  | \
    MSTATUS_UPIE | \
    MSTATUS_SPIE | \
    MSTATUS_SPP  | \
    MSTATUS_FS   | \
    MSTATUS_SUM  | \
    MSTATUS_MXR  | \
    MSTATUS_UXL  | \
    MSTATUS_SD  \
)

#define MSTATUS_WRITE_MASK ( \
    MSTATUS_UIE  | \
    MSTATUS_SIE  | \
    MSTATUS_MIE  | \
    MSTATUS_UPIE | \
    MSTATUS_SPIE | \
    MSTATUS_MPIE | \
    MSTATUS_SPP  | \
    MSTATUS_MPP  | \
    MSTATUS_FS   | \
    MSTATUS_MPRV | \
    MSTATUS_SUM  | \
    MSTATUS_MXR  | \
    MSTATUS_TVM  | \
    MSTATUS_TW   | \
    MSTATUS_TSR  \
)

#define MSTATUS_READ_MASK ( \
    MSTATUS_UIE  | \
    MSTATUS_SIE  | \
    MSTATUS_MIE  | \
    MSTATUS_UPIE | \
    MSTATUS_SPIE | \
    MSTATUS_MPIE | \
    MSTATUS_SPP  | \
    MSTATUS_MPP  | \
    MSTATUS_FS   | \
    MSTATUS_MPRV | \
    MSTATUS_SUM  | \
    MSTATUS_MXR  | \
    MSTATUS_TVM  | \
    MSTATUS_TW   | \
    MSTATUS_TSR  | \
    MSTATUS_UXL  | \
    MSTATUS_SXL  | \
    MSTATUS_SD  \
)

/* cycle and insn counters */
#define COUNTEREN_MASK ((1 << 0) | (1 << 2))

enum class CSR_address: uint32_t {
    ustatus = 0x000,
    uie = 0x004,
    utvec = 0x005,

    uscratch = 0x040,
    uepc = 0x041,
    ucause = 0x042,
    utval = 0x043,
    uip = 0x044,

    ucycle = 0xc00,
    utime = 0xc01,
    uinstret =  0xc02,
    ucycleh = 0xc80,
    utimeh = 0xc81,
    uinstreth = 0xc82,

    sstatus = 0x100,
    sedeleg = 0x102,
    sideleg = 0x103,
    sie = 0x104,
    stvec = 0x105,
    scounteren = 0x106,

    sscratch = 0x140,
    sepc = 0x141,
    scause = 0x142,
    stval = 0x143,
    sip = 0x144,

    satp = 0x180,

    mvendorid = 0xf11,
    marchid = 0xf12,
    mimplid = 0xf13,
    mhartid = 0xf14,

    mstatus = 0x300,
    misa = 0x301,
    medeleg = 0x302,
    mideleg = 0x303,
    mie = 0x304,
    mtvec = 0x305,
    mcounteren = 0x306,

    mscratch = 0x340,
    mepc = 0x341,
    mcause = 0x342,
    mtval = 0x343,
    mip = 0x344,

    mcycle = 0xb00,
    minstret = 0xb02,
    mcycleh = 0xb80,
    minstreth = 0xb82,

    tselect = 0x7a0,
    tdata1 = 0x7a1,
    tdata2 = 0x7a2,
    tdata3 = 0x7a3,
};

static inline bool csr_is_read_only(CSR_address csraddr) {
    // 0xc00--0xcff, 0xd00--0xdff, and 0xf00--0xfff are all read-only.
    // so as long as bits 0xc00 are set, the register is read-only
    return ((static_cast<uint32_t>(csraddr) & 0xc00) == 0xc00);
}

static inline uint32_t csr_priv(CSR_address csr) {
    return (static_cast<uint32_t>(csr) >> 8) & 3;
}

template <typename STATE_ACCESS>
static void set_priv(STATE_ACCESS &a, processor_state *s, int previous_priv, int new_priv)
{
    if (previous_priv != new_priv) {
        tlb_flush_all(s);
        a.write_iflags_PRV(s, new_priv);
        a.write_ilrsc(s, 0);
    }
}

template <typename STATE_ACCESS>
static void raise_exception(STATE_ACCESS &a, processor_state *s, uint64_t cause, uint64_t tval) {
#if defined(DUMP_EXCEPTIONS) || defined(DUMP_MMU_EXCEPTIONS) || defined(DUMP_INTERRUPTS)
    {
        int flag;
        flag = 0;
#ifdef DUMP_MMU_EXCEPTIONS
        if (cause == CAUSE_FETCH_FAULT ||
            cause == CAUSE_LOAD_FAULT ||
            cause == CAUSE_STORE_AMO_FAULT ||
            cause == CAUSE_FETCH_PAGE_FAULT ||
            cause == CAUSE_LOAD_PAGE_FAULT ||
            cause == CAUSE_STORE_AMO_PAGE_FAULT)
            flag = 1;
#endif
#ifdef DUMP_INTERRUPTS
        flag |= (cause & CAUSE_INTERRUPT) != 0;
#endif
#ifdef DUMP_EXCEPTIONS
        flag |= (cause & CAUSE_INTERRUPT) == 0;
#endif
        if (flag) {
            fprintf(stderr, "raise_exception: cause=0x");
            print_uint64_t(cause);
            fprintf(stderr, " tval=0x");
            print_uint64_t(tval);
            fprintf(stderr, "\n");
            dump_regs(s);
        }
    }
#endif

    // Check if exception should be delegated to supervisor privilege
    // For each interrupt or exception number, there is a bit at mideleg
    // or medeleg saying if it should be delegated
    bool deleg = false;
    int priv = a.read_iflags_PRV(s);
    if (priv <= PRV_S) {
        if (cause & CAUSE_INTERRUPT) {
            // Clear the CAUSE_INTERRUPT bit before shifting
            deleg = (a.read_mideleg(s) >> (cause & (XLEN - 1))) & 1;
        } else {
            deleg = (a.read_medeleg(s) >> cause) & 1;
        }
    }

    if (deleg) {
        a.write_scause(s, cause);
        a.write_sepc(s, a.read_pc(s));
        a.write_stval(s, tval);
        uint64_t mstatus = a.read_mstatus(s);
        mstatus = (mstatus & ~MSTATUS_SPIE) | (((mstatus >> priv) & 1) << MSTATUS_SPIE_SHIFT);
        mstatus = (mstatus & ~MSTATUS_SPP) | (priv << MSTATUS_SPP_SHIFT);
        mstatus &= ~MSTATUS_SIE;
        a.write_mstatus(s, mstatus);
        set_priv(a, s, priv, PRV_S);
        a.write_pc(s, a.read_stvec(s));
#ifdef DUMP_COUNTERS
        if (cause & CAUSE_INTERRUPT) {
            s->count_si++;
        } else {
            // Do not count environment calls
            if (cause >= CAUSE_ECALL_BASE && cause <= CAUSE_ECALL_BASE + PRV_M)
                s->count_se++;
        }
#endif
    } else {
        a.write_mcause(s, cause);
        a.write_mepc(s, a.read_pc(s));
        a.write_mtval(s, tval);
        uint64_t mstatus = a.read_mstatus(s);
        mstatus = (mstatus & ~MSTATUS_MPIE) | (((mstatus >> priv) & 1) << MSTATUS_MPIE_SHIFT);
        mstatus = (mstatus & ~MSTATUS_MPP) | (priv << MSTATUS_MPP_SHIFT);
        mstatus &= ~MSTATUS_MIE;
        a.write_mstatus(s, mstatus);
        set_priv(a, s, priv, PRV_M);
        a.write_pc(s, a.read_mtvec(s));
#ifdef DUMP_COUNTERS
        if (cause & CAUSE_INTERRUPT) {
            s->count_mi++;
        } else {
            // Do not count environment calls
            if (cause >= CAUSE_ECALL_BASE && cause <= CAUSE_ECALL_BASE + PRV_M)
                s->count_me++;
        }
#endif
    }
}

template <typename STATE_ACCESS>
static inline uint32_t get_pending_irq_mask(STATE_ACCESS &a, processor_state *s) {

    uint64_t mip = a.read_mip(s);
    uint64_t mie = a.read_mie(s);

    uint32_t pending_ints = mip & mie;
    if (pending_ints == 0)
        return 0;

    uint32_t enabled_ints = 0;
    switch (a.read_iflags_PRV(s)) {
        case PRV_M: {
            uint64_t mstatus = a.read_mstatus(s);
            if (mstatus & MSTATUS_MIE) {
                enabled_ints = ~a.read_mideleg(s);
            }
            break;
        }
        case PRV_S: {
            uint64_t mstatus = a.read_mstatus(s);
            uint64_t mideleg = a.read_mideleg(s);
            // Interrupts not set in mideleg are machine-mode
            // and cannot be masked by supervisor mode
            enabled_ints = ~mideleg;
            if (mstatus & MSTATUS_SIE)
                enabled_ints |= mideleg;
            break;
        }
        default:
            assert(s->iflags_PRV == PRV_U);
            enabled_ints = -1;
            break;
    }

    return pending_ints & enabled_ints;
}

// The return value is undefined if v == 0
// This works on gcc and clang and uses the lzcnt instruction
static inline uint32_t ilog2(uint32_t v) {
    return 31 - __builtin_clz(v);
}

template <typename STATE_ACCESS>
static void raise_interrupt_if_any(STATE_ACCESS &a, processor_state *s) {
    uint32_t mask = get_pending_irq_mask(a, s);
    if (mask != 0) {
        uint64_t irq_num = ilog2(mask);
        raise_exception(a, s, irq_num | CAUSE_INTERRUPT, 0);
    }
}


processor_state *processor_init(PhysMemoryMap *mem_map)
{
    processor_state *s = reinterpret_cast<processor_state *>(calloc(1, sizeof(*s)));
    s->mem_map = mem_map;
    s->iflags_I = false;
    s->iflags_H = false;
    s->pc = 0x1000;
    s->iflags_PRV = PRV_M;
    s->mstatus = ((uint64_t)MXL << MSTATUS_UXL_SHIFT) |
        ((uint64_t)MXL << MSTATUS_SXL_SHIFT);
    s->misa = MXL; s->misa <<= (XLEN-2); /* set xlen to 64 */
    s->misa |= MCPUID_SUPER | MCPUID_USER | MCPUID_I | MCPUID_M | MCPUID_A;
    tlb_init(s);
    s->brk = false;
    return s;
}

void processor_end(processor_state *s) {
#if DUMP_COUNTERS
    fprintf(stderr, "inner loops: %" PRIu64 "\n", s->count_inners);
    fprintf(stderr, "outers loops: %" PRIu64 "\n", s->count_outers);
    fprintf(stderr, "si: %" PRIu64 "\n", s->count_si);
    fprintf(stderr, "se: %" PRIu64 "\n", s->count_se);
    fprintf(stderr, "mi: %" PRIu64 "\n", s->count_mi);
    fprintf(stderr, "me: %" PRIu64 "\n", s->count_me);
    fprintf(stderr, "amo: %" PRIu64 "\n", s->count_amo);
#endif
    free(s);
}

/// \brief Instruction fetch status code
enum class execute_status: int {
    illegal, ///< Illegal instruction: exception raised
    retired ///< Instruction was retired: exception may or may not have been raised
};

enum class opcode {
    LUI   = 0b0110111,
    AUIPC = 0b0010111,
    JAL   = 0b1101111,
    JALR  = 0b1100111,

    branch_group = 0b1100011,
    load_group = 0b0000011,
    store_group = 0b0100011,
    arithmetic_immediate_group = 0b0010011,
    arithmetic_group = 0b0110011,
    fence_group = 0b0001111,
    csr_env_trap_int_mm_group = 0b1110011,
    arithmetic_immediate_32_group = 0b0011011,
    arithmetic_32_group = 0b0111011,
    atomic_group = 0b0101111,
};

enum class branch_funct3 {
    BEQ  = 0b000,
    BNE  = 0b001,
    BLT  = 0b100,
    BGE  = 0b101,
    BLTU = 0b110,
    BGEU = 0b111
};

enum class load_funct3 {
    LB  = 0b000,
    LH  = 0b001,
    LW  = 0b010,
    LD  = 0b011,
    LBU = 0b100,
    LHU = 0b101,
    LWU = 0b110
};

enum class store_funct3 {
    SB = 0b000,
    SH = 0b001,
    SW = 0b010,
    SD = 0b011
};

enum class arithmetic_immediate_funct3 {
    ADDI  = 0b000,
    SLTI  = 0b010,
    SLTIU = 0b011,
    XORI  = 0b100,
    ORI   = 0b110,
    ANDI  = 0b111,
    SLLI  = 0b001,

    shift_right_immediate_group = 0b101,
};

enum class shift_right_immediate_funct6 {
    SRLI = 0b000000,
    SRAI = 0b010000
};

enum class arithmetic_funct3_funct7 {
    ADD    = 0b0000000000,
    SUB    = 0b0000100000,
    SLL    = 0b0010000000,
    SLT    = 0b0100000000,
    SLTU   = 0b0110000000,
    XOR    = 0b1000000000,
    SRL    = 0b1010000000,
    SRA    = 0b1010100000,
    OR     = 0b1100000000,
    AND    = 0b1110000000,
    MUL    = 0b0000000001,
    MULH   = 0b0010000001,
    MULHSU = 0b0100000001,
    MULHU  = 0b0110000001,
    DIV    = 0b1000000001,
    DIVU   = 0b1010000001,
    REM    = 0b1100000001,
    REMU   = 0b1110000001,
};

enum class fence_group_funct3 {
    FENCE   = 0b000,
    FENCE_I = 0b001
};

enum class env_trap_int_group_insn {
    ECALL  = 0b00000000000000000000000001110011,
    EBREAK = 0b00000000000100000000000001110011,
    URET   = 0b00000000001000000000000001110011,
    SRET   = 0b00010000001000000000000001110011,
    MRET   = 0b00110000001000000000000001110011,
    WFI    = 0b00010000010100000000000001110011
};

enum class csr_env_trap_int_mm_funct3 {
    CSRRW  = 0b001,
    CSRRS  = 0b010,
    CSRRC  = 0b011,
    CSRRWI = 0b101,
    CSRRSI = 0b110,
    CSRRCI = 0b111,

    env_trap_int_mm_group  = 0b000,
};

enum class arithmetic_immediate_32_funct3 {
    ADDIW = 0b000,
    SLLIW = 0b001,

    shift_right_immediate_32_group = 0b101,
};

enum class shift_right_immediate_32_funct7 {
    SRLIW = 0b0000000,
    SRAIW = 0b0100000
};

enum class arithmetic_32_funct3_funct7 {
    ADDW  = 0b0000000000,
    SUBW  = 0b0000100000,
    SLLW  = 0b0010000000,
    SRLW  = 0b1010000000,
    SRAW  = 0b1010100000,
    MULW  = 0b0000000001,
    DIVW  = 0b1000000001,
    DIVUW = 0b1010000001,
    REMW  = 0b1100000001,
    REMUW = 0b1110000001
};

enum class atomic_funct3_funct5 {
    LR_W      = 0b01000010,
    SC_W      = 0b01000011,
    AMOSWAP_W = 0b01000001,
    AMOADD_W  = 0b01000000,
    AMOXOR_W  = 0b01000100,
    AMOAND_W  = 0b01001100,
    AMOOR_W   = 0b01001000,
    AMOMIN_W  = 0b01010000,
    AMOMAX_W  = 0b01010100,
    AMOMINU_W = 0b01011000,
    AMOMAXU_W = 0b01011100,
    LR_D      = 0b01100010,
    SC_D      = 0b01100011,
    AMOSWAP_D = 0b01100001,
    AMOADD_D  = 0b01100000,
    AMOXOR_D  = 0b01100100,
    AMOAND_D  = 0b01101100,
    AMOOR_D   = 0b01101000,
    AMOMIN_D  = 0b01110000,
    AMOMAX_D  = 0b01110100,
    AMOMINU_D = 0b01111000,
    AMOMAXU_D = 0b01111100
};

static inline uint32_t insn_rd(uint32_t insn) {
    return (insn >> 7) & 0b11111;
}

static inline uint32_t insn_rs1(uint32_t insn) {
    return (insn >> 15) & 0b11111;
}

static inline uint32_t insn_rs2(uint32_t insn) {
    return (insn >> 20) & 0b11111;
}

static inline int32_t insn_I_imm(uint32_t insn) {
    return (int32_t)insn >> 20;
}

static inline uint32_t insn_I_uimm(uint32_t insn) {
    return insn >> 20;
}

static inline int32_t insn_U_imm(uint32_t insn) {
    return static_cast<int32_t>(insn & 0xfffff000);
}

static inline int32_t insn_B_imm(uint32_t insn) {
    int32_t imm = ((insn >> (31 - 12)) & (1 << 12)) |
        ((insn >> (25 - 5)) & 0x7e0) |
        ((insn >> (8 - 1)) & 0x1e) |
        ((insn << (11 - 7)) & (1 << 11));
    imm = (imm << 19) >> 19;
    return imm;
}

static inline int32_t insn_J_imm(uint32_t insn) {
    int32_t imm = ((insn >> (31 - 20)) & (1 << 20)) |
        ((insn >> (21 - 1)) & 0x7fe) |
        ((insn >> (20 - 11)) & (1 << 11)) |
        (insn & 0xff000);
    imm = (imm << 11) >> 11;
    return imm;
}

static inline int32_t insn_S_imm(uint32_t insn) {
    return (static_cast<int32_t>(insn & 0xfe000000) >> (25 - 5)) | ((insn >> 7) & 0b11111);
}

static inline uint32_t insn_opcode(uint32_t insn) {
    //std::cerr << "opcode: " << std::bitset<7>(insn & 0b1111111) << '\n';
    return insn & 0b1111111;
}

static inline uint32_t insn_funct3(uint32_t insn) {
    //std::cerr << "funct3: " << std::bitset<3>((insn >> 12) & 0b111) << '\n';
    return (insn >> 12) & 0b111;
}

static inline uint32_t insn_funct3_funct7(uint32_t insn) {
    //std::cerr << "funct3_funct7: " << std::bitset<10>(((insn >> 5) & 0b1110000000) | (insn >> 24)) << '\n';
    return ((insn >> 5) & 0b1110000000) | (insn >> 25);
}

static inline uint32_t insn_funct3_funct5(uint32_t insn) {
    //std::cerr << "funct3_funct5: " << std::bitset<8>(((insn >> 7) & 0b11100000) | (insn >> 27)) << '\n';
    return ((insn >> 7) & 0b11100000) | (insn >> 27);
}

static inline uint32_t insn_funct7(uint32_t insn) {
    //std::cerr << "funct7: " << std::bitset<7>((insn >> 25) & 0b1111111) << '\n';
    return (insn >> 25) & 0b1111111;
}

static inline uint32_t insn_funct6(uint32_t insn) {
    //std::cerr << "funct6: " << std::bitset<6>((insn >> 26) & 0b111111) << '\n';
    return (insn >> 26) & 0b111111;
}

template <typename T, typename STATE_ACCESS>
static bool read_memory_slow(STATE_ACCESS &a, processor_state *s, uint64_t addr, T *pval);

template <typename T, typename STATE_ACCESS>
static inline bool read_memory(STATE_ACCESS &a, processor_state *s, uint64_t addr, T *pval)  {
    int tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (s->tlb_read[tlb_idx].vaddr == (addr & ~(PG_MASK & ~(sizeof(T) - 1)))) {
        *pval = *reinterpret_cast<T *>(s->tlb_read[tlb_idx].mem_addend + (uintptr_t)addr);
        return true;
    } else {
        return read_memory_slow<T>(a, s, addr, pval);
    }
}

/* return 0 if OK, != 0 if exception */
template <typename T, typename STATE_ACCESS>
static bool read_memory_slow(STATE_ACCESS &a, processor_state *s, uint64_t addr, T *pval) {
    using U = std::make_unsigned_t<T>;
    // No support for misaligned accesses: They are handled by a trap in BBL
    if (addr & (sizeof(T)-1)) {
        raise_exception(a, s, CAUSE_LOAD_ADDRESS_MISALIGNED, addr);
        return false;
    // Deal with aligned accesses
    } else {
        uint64_t paddr;
        if (get_phys_addr(s, &paddr, addr, PTE_XWR_READ_SHIFT)) {
            raise_exception(a, s, CAUSE_LOAD_PAGE_FAULT, addr);
            return false;
        }
        PhysMemoryRange *pr = get_phys_mem_range(s->mem_map, paddr);
        if (!pr) {
            // If we do not have the range in our map, we treat this as a PMA violation
            raise_exception(a, s, CAUSE_LOAD_FAULT, addr);
            return false;
        } else if (pr->is_ram) {
            int tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
            uint8_t *ptr = pr->phys_mem + (uintptr_t)(paddr - pr->addr);
            s->tlb_read[tlb_idx].vaddr = addr & ~PG_MASK;
            s->tlb_read[tlb_idx].mem_addend = (uintptr_t)ptr - addr;
            *pval = *reinterpret_cast<T *>(ptr);
            return true;
        } else {
            uint64_t offset = paddr - pr->addr;
            uint64_t val;
            device_state_access<STATE_ACCESS> da(a, s);
            // If we do not know how to read, we treat this as a PMA violation
            if (!pr->read_func(&da, pr->opaque, offset, &val, size_log2<U>())) {
                raise_exception(a, s, CAUSE_LOAD_FAULT, addr);
                return false;
            }
            *pval = static_cast<T>(val);
            return true;
        }
    }
}

template <typename T, typename STATE_ACCESS>
static inline bool write_memory(STATE_ACCESS &a, processor_state *s, uint64_t addr, uint64_t val);

template <typename T, typename STATE_ACCESS>
static bool write_memory_slow(STATE_ACCESS &a, processor_state *s, uint64_t addr, uint64_t val) {
    using U = std::make_unsigned_t<T>;
    // No support for misaligned accesses: They are handled by a trap in BBL
    if (addr & (sizeof(T)-1)) {
        raise_exception(a, s, CAUSE_STORE_AMO_ADDRESS_MISALIGNED, addr);
        return false;
    // Deal with aligned accesses
    } else {
        uint64_t paddr, offset;
        if (get_phys_addr(s, &paddr, addr, PTE_XWR_WRITE_SHIFT)) {
            raise_exception(a, s, CAUSE_STORE_AMO_PAGE_FAULT, addr);
            return false;
        }
        PhysMemoryRange *pr = get_phys_mem_range(s->mem_map, paddr);
        if (!pr) {
            // If we do not have the range in our map, we treat this as a PMA violation
            raise_exception(a, s, CAUSE_STORE_AMO_FAULT, addr);
            return false;
        } else if (pr->is_ram) {
            int tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
            uint8_t *ptr = pr->phys_mem + (uintptr_t)(paddr - pr->addr);
            s->tlb_write[tlb_idx].vaddr = addr & ~PG_MASK;
            s->tlb_write[tlb_idx].mem_addend = (uintptr_t)ptr - addr;
            *reinterpret_cast<T *>(ptr) = static_cast<T>(val);
            return true;
        } else {
            device_state_access<STATE_ACCESS> da(a, s);
            offset = paddr - pr->addr;
            // If we do not know how to write, we treat this as a PMA violation
            if (!pr->write_func(&da, pr->opaque, offset, val, size_log2<U>())) {
                raise_exception(a, s, CAUSE_STORE_AMO_FAULT, addr);
                return false;
            }
            return true;
        }
    }
}

template <typename T, typename STATE_ACCESS>
static inline bool write_memory(STATE_ACCESS &a, processor_state *s, uint64_t addr, uint64_t val) {
    uint32_t tlb_idx;
    tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (s->tlb_write[tlb_idx].vaddr == (addr & ~(PG_MASK & ~(sizeof(T) - 1)))) {
        *reinterpret_cast<T *>(s->tlb_write[tlb_idx].mem_addend + (uintptr_t)addr) = static_cast<T>(val);
        return true;
    } else {
        return write_memory_slow<T>(a, s, addr, val);
    }
}

static void dump_insn(processor_state *s, uint64_t pc, uint32_t insn, const char *name) {
#ifdef DUMP_INSN
    fprintf(stderr, "%s\n", name);
    uint64_t ppc;
    if (!get_phys_addr(s, &ppc, pc, PTE_XWR_CODE_SHIFT)) {
        fprintf(stderr, "p    %08" PRIx64, ppc);
    } else {
        ppc = pc;
        fprintf(stderr, "v    %08" PRIx64, ppc);
    }
    fprintf(stderr, ":   %08" PRIx32 "   ", insn);
    fprintf(stderr, "\n");
//    dump_regs(s);
#else
    (void) s;
    (void) pc;
    (void) insn;
    (void) name;
#endif
}

// An execute_OP function is only invoked when the opcode
// has been decoded enough to preclude any other instruction.
// In some cases, further checks are needed to ensure the
// instruction is valid.

template <typename STATE_ACCESS>
static inline execute_status execute_illegal_insn_exception(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    (void) a; (void) pc;
    raise_exception(a, s, CAUSE_ILLEGAL_INSTRUCTION, insn);
    return execute_status::illegal;
}

template <typename STATE_ACCESS>
static inline execute_status execute_misaligned_fetch_exception(STATE_ACCESS &a, processor_state *s, uint64_t pc) {
    (void) a;
    raise_exception(a, s, CAUSE_MISALIGNED_FETCH, pc);
    return execute_status::retired;
}

template <typename STATE_ACCESS>
static inline execute_status execute_raised_exception(STATE_ACCESS &a, processor_state *s, uint64_t pc) {
    (void) a; (void) s; (void) pc;
    return execute_status::retired;
}

template <typename STATE_ACCESS>
static inline execute_status execute_jump(STATE_ACCESS &a, processor_state *s, uint64_t pc) {
    a.write_pc(s, pc);
    // s->brk = true; // overkill
    return execute_status::retired;
}

template <typename STATE_ACCESS>
static inline execute_status execute_next_insn(STATE_ACCESS &a, processor_state *s, uint64_t pc) {
    a.write_pc(s, pc + 4);
    return execute_status::retired;
}

template <typename T, typename STATE_ACCESS>
static inline execute_status execute_LR(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    uint64_t addr = a.read_register(s, insn_rs1(insn));
    T val = 0;
    if (!read_memory<T>(a, s, addr, &val))
        return execute_status::retired;
    a.write_ilrsc(s, addr);
    uint32_t rd = insn_rd(insn);
    if (rd != 0)
        a.write_register(s, rd, static_cast<uint64_t>(val));
    return execute_next_insn(a, s, pc);
}

template <typename T, typename STATE_ACCESS>
static inline execute_status execute_SC(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    uint64_t val = 0;
    uint64_t addr = a.read_register(s, insn_rs1(insn));
    if (a.read_ilrsc(s) == addr) {
        if (!write_memory<T>(a, s, addr, static_cast<T>(a.read_register(s, insn_rs2(insn)))))
            return execute_status::retired;
    } else {
        val = 1;
    }
    uint32_t rd = insn_rd(insn);
    if (rd != 0)
        a.write_register(s, rd, val);
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_LR_W(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    if ((insn & 0b00000001111100000000000000000000) == 0 ) {
        dump_insn(s, pc, insn, "LR_W");
        return execute_LR<int32_t>(a, s, pc, insn);
    } else {
        return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

template <typename STATE_ACCESS>
static inline execute_status execute_SC_W(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SC_W");
    return execute_SC<int32_t>(a, s, pc, insn);
}

template <typename T, typename STATE_ACCESS, typename F>
static inline execute_status execute_AMO(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn, const F &f) {
    uint64_t addr = a.read_register(s, insn_rs1(insn));
    T valm = 0;
    if (!read_memory<T>(a, s, addr, &valm))
        return execute_status::retired;
    T valr = static_cast<T>(a.read_register(s, insn_rs2(insn)));
    valr = f(valm, valr);
    if (!write_memory<T>(a, s, addr, valr))
        return execute_status::retired;
    uint32_t rd = insn_rd(insn);
    if (rd != 0)
        a.write_register(s, rd, static_cast<uint64_t>(valm));
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOSWAP_W(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOSWAP_W");
    return execute_AMO<int32_t>(a, s, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { (void) valm; return valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOADD_W(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOADD_W");
    return execute_AMO<int32_t>(a, s, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm + valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOXOR_W(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    return execute_AMO<int32_t>(a, s, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm ^ valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOAND_W(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOAND_W");
    return execute_AMO<int32_t>(a, s, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm & valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOOR_W(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOOR_W");
    return execute_AMO<int32_t>(a, s, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm | valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOMIN_W(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOMIN_W");
    return execute_AMO<int32_t>(a, s, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm < valr? valm: valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOMAX_W(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOMAX_W");
    return execute_AMO<int32_t>(a, s, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm > valr? valm: valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOMINU_W(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOMINU_W");
    return execute_AMO<int32_t>(a, s, pc, insn, [](int32_t valm, int32_t valr) -> int32_t {
        return static_cast<uint32_t>(valm) < static_cast<uint32_t>(valr)? valm: valr;
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOMAXU_W(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOMAXU_W");
    return execute_AMO<int32_t>(a, s, pc, insn, [](int32_t valm, int32_t valr) -> int32_t {
        return static_cast<uint32_t>(valm) > static_cast<uint32_t>(valr)? valm: valr;
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_LR_D(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    if ((insn & 0b00000001111100000000000000000000) == 0 ) {
        dump_insn(s, pc, insn, "LR_D");
        return execute_LR<uint64_t>(a, s, pc, insn);
    } else {
        return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

template <typename STATE_ACCESS>
static inline execute_status execute_SC_D(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SC_D");
    return execute_SC<uint64_t>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOSWAP_D(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOSWAP_D");
    return execute_AMO<int64_t>(a, s, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { (void) valm; return valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOADD_D(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOADD_D");
    return execute_AMO<int64_t>(a, s, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm + valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOXOR_D(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    return execute_AMO<int64_t>(a, s, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm ^ valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOAND_D(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOAND_D");
    return execute_AMO<int64_t>(a, s, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm & valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOOR_D(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOOR_D");
    return execute_AMO<int64_t>(a, s, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm | valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOMIN_D(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOMIN_D");
    return execute_AMO<int64_t>(a, s, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm < valr? valm: valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOMAX_D(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOMAX_D");
    return execute_AMO<int64_t>(a, s, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm > valr? valm: valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOMINU_D(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOMINU_D");
    return execute_AMO<uint64_t>(a, s, pc, insn,
        [](uint64_t valm, uint64_t valr) -> uint64_t { return valm < valr? valm: valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOMAXU_D(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AMOMAXU_D");
    return execute_AMO<uint64_t>(a, s, pc, insn,
        [](uint64_t valm, uint64_t valr) -> uint64_t { return valm > valr? valm: valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_ADDW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "ADDW");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        // Discard upper 32 bits
        int32_t rs1w = static_cast<int32_t>(rs1);
        int32_t rs2w = static_cast<int32_t>(rs2);
        int32_t val = 0;
        __builtin_add_overflow(rs1w, rs2w, &val);
        return static_cast<uint64_t>(val);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SUBW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SUBW");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        // Convert 64-bit to 32-bit
        int32_t rs1w = static_cast<int32_t>(rs1);
        int32_t rs2w = static_cast<int32_t>(rs2);
        int32_t val = 0;
        __builtin_sub_overflow(rs1w, rs2w, &val);
        return static_cast<uint64_t>(val);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLLW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SLLW");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(rs1) << (rs2 & 31);
        return static_cast<uint64_t>(rs1w);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRLW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SRLW");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(static_cast<uint32_t>(rs1) >> (rs2 & 31));
        return static_cast<uint64_t>(rs1w);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRAW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SRAW");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(rs1) >> (rs2 & 31);
        return static_cast<uint64_t>(rs1w);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_MULW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "MULW");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(rs1);
        int32_t rs2w = static_cast<int32_t>(rs2);
        int32_t val = 0;
        __builtin_mul_overflow(rs1w, rs2w, &val);
        return static_cast<uint64_t>(val);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_DIVW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "DIVW");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(rs1);
        int32_t rs2w = static_cast<int32_t>(rs2);
        if (rs2w == 0) {
            return static_cast<uint64_t>(-1);
        } else if (rs1w == ((int32_t)1 << (32 - 1)) && rs2w == -1) {
            return static_cast<uint64_t>(rs1w);
        } else {
            return static_cast<uint64_t>(rs1w / rs2w);
        }
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_DIVUW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "DIVUW");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        uint32_t rs1w = static_cast<uint32_t>(rs1);
        uint32_t rs2w = static_cast<uint32_t>(rs2);
        if (rs2w == 0) {
            return static_cast<uint64_t>(-1);
        } else {
            return static_cast<uint64_t>(static_cast<int32_t>(rs1w / rs2w));
        }
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_REMW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "REMW");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(rs1);
        int32_t rs2w = static_cast<int32_t>(rs2);
        if (rs2w == 0) {
            return static_cast<uint64_t>(rs1w);
        } else if (rs1w == ((int32_t)1 << (32 - 1)) && rs2w == -1) {
            return static_cast<uint64_t>(0);
        } else {
            return static_cast<uint64_t>(rs1w % rs2w);
        }
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_REMUW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn(s, pc, insn, "REMUW");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        uint32_t rs1w = static_cast<uint32_t>(rs1);
        uint32_t rs2w = static_cast<uint32_t>(rs2);
        if (rs2w == 0) {
            return static_cast<uint64_t>(static_cast<int32_t>(rs1w));
        } else {
            return static_cast<uint64_t>(static_cast<int32_t>(rs1w % rs2w));
        }
    });
}

static inline uint64_t read_csr_fail(bool *status) {
    *status = false;
    return 0;
}

static inline uint64_t read_csr_success(uint64_t val, bool *status) {
    *status = true;
    return val;
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_cycle(STATE_ACCESS &a, processor_state *s, CSR_address csraddr, bool *status) {
    uint32_t counteren;
    if (s->iflags_PRV < PRV_M) {
        if (s->iflags_PRV < PRV_S) {
            counteren = a.read_scounteren(s);
        } else {
            counteren = a.read_mcounteren(s);
        }
        if (((counteren >> (static_cast<int>(csraddr) & 0x1f)) & 1) == 0) {
            return read_csr_fail(status);
        }
    }
    return read_csr_success(a.read_mcycle(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_instret(STATE_ACCESS &a, processor_state *s, CSR_address csraddr, bool *status) {
    uint32_t counteren;
    if (s->iflags_PRV < PRV_M) {
        if (s->iflags_PRV < PRV_S) {
            counteren = a.read_scounteren(s);
        } else {
            counteren = a.read_mcounteren(s);
        }
        if (((counteren >> (static_cast<int>(csraddr) & 0x1f)) & 1) == 0) {
            return read_csr_fail(status);
        }
    }
    return read_csr_success(a.read_minstret(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sstatus(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_mstatus(s) & SSTATUS_READ_MASK, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sie(STATE_ACCESS &a, processor_state *s, bool *status) {
    uint64_t mie = a.read_mie(s);
    uint64_t mideleg = a.read_mideleg(s);
    return read_csr_success(mie & mideleg, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_stvec(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_stvec(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_scounteren(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_scounteren(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sscratch(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_sscratch(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sepc(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_sepc(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_scause(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_scause(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_stval(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_stval(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sip(STATE_ACCESS &a, processor_state *s, bool *status) {
    // Ensure values are are loaded in order: do not nest with operator
    uint64_t mip = a.read_mip(s);
    uint64_t mideleg = a.read_mideleg(s);
    return read_csr_success(mip & mideleg, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_satp(STATE_ACCESS &a, processor_state *s, bool *status) {
    uint64_t mstatus = a.read_mstatus(s);
    if (s->iflags_PRV == PRV_S && mstatus & MSTATUS_TVM) {
        return read_csr_fail(status);
    } else {
        return read_csr_success(a.read_satp(s), status);
    }
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mstatus(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_mstatus(s) & MSTATUS_READ_MASK, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_misa(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_misa(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_medeleg(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_medeleg(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mideleg(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_mideleg(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mie(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_mie(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mtvec(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_mtvec(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mcounteren(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_mcounteren(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mscratch(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_mscratch(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mepc(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_mepc(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mcause(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_mcause(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mtval(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_mtval(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mip(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_mip(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mcycle(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_mcycle(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_minstret(STATE_ACCESS &a, processor_state *s, bool *status) {
    return read_csr_success(a.read_minstret(s), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_utime(STATE_ACCESS &a, processor_state *s, bool *status) {
    uint64_t mtime = processor_rtc_cycles_to_time(a.read_mcycle(s));
    return read_csr_success(mtime, status);
}

template <typename STATE_ACCESS>
static uint64_t read_csr(STATE_ACCESS &a, processor_state *s, CSR_address csraddr, bool *status) {

    if (csr_priv(csraddr) > s->iflags_PRV)
        return read_csr_fail(status);

    switch (csraddr) {
        case CSR_address::ucycle: return read_csr_cycle(a, s, csraddr, status);
        case CSR_address::uinstret: return read_csr_instret(a, s, csraddr, status);
        case CSR_address::utime: return read_csr_utime(a, s, status);

        case CSR_address::sstatus: return read_csr_sstatus(a, s, status);
        case CSR_address::sie: return read_csr_sie(a, s, status);
        case CSR_address::stvec: return read_csr_stvec(a, s, status);
        case CSR_address::scounteren: return read_csr_scounteren(a, s, status);
        case CSR_address::sscratch: return read_csr_sscratch(a, s, status);
        case CSR_address::sepc: return read_csr_sepc(a, s, status);
        case CSR_address::scause: return read_csr_scause(a, s, status);
        case CSR_address::stval: return read_csr_stval(a, s, status);
        case CSR_address::sip: return read_csr_sip(a, s, status);
        case CSR_address::satp: return read_csr_satp(a, s, status);


        case CSR_address::mstatus: return read_csr_mstatus(a, s, status);
        case CSR_address::misa: return read_csr_misa(a, s, status);
        case CSR_address::medeleg: return read_csr_medeleg(a, s, status);
        case CSR_address::mideleg: return read_csr_mideleg(a, s, status);
        case CSR_address::mie: return read_csr_mie(a, s, status);
        case CSR_address::mtvec: return read_csr_mtvec(a, s, status);
        case CSR_address::mcounteren: return read_csr_mcounteren(a, s, status);


        case CSR_address::mscratch: return read_csr_mscratch(a, s, status);
        case CSR_address::mepc: return read_csr_mepc(a, s, status);
        case CSR_address::mcause: return read_csr_mcause(a, s, status);
        case CSR_address::mtval: return read_csr_mtval(a, s, status);
        case CSR_address::mip: return read_csr_mip(a, s, status);

        case CSR_address::mcycle: return read_csr_mcycle(a, s, status);
        case CSR_address::minstret: return read_csr_minstret(a, s, status);

        // All hardwired to zero
        case CSR_address::tselect:
        case CSR_address::tdata1:
        case CSR_address::tdata2:
        case CSR_address::tdata3:
        case CSR_address::mvendorid:
        case CSR_address::marchid:
        case CSR_address::mimplid:
        case CSR_address::mhartid:
           return read_csr_success(0, status);

        // Invalid CSRs
        default:
        //case CSR_address::ustatus: // no U-mode traps
        //case CSR_address::uie: // no U-mode traps
        //case CSR_address::utvec: // no U-mode traps
        //case CSR_address::uscratch: // no U-mode traps
        //case CSR_address::uepc: // no U-mode traps
        //case CSR_address::ucause: // no U-mode traps
        //case CSR_address::utval: // no U-mode traps
        //case CSR_address::uip: // no U-mode traps
        //case CSR_address::sedeleg: // no U-mode traps
        //case CSR_address::sideleg: // no U-mode traps
        //case CSR_address::ucycleh: // 32-bit only
        //case CSR_address::utimeh: // 32-bit only
        //case CSR_address::uinstreth: // 32-bit only
        //case CSR_address::mcycleh: // 32-bit only
        //case CSR_address::minstreth: // 32-bit only
#ifdef DUMP_INVALID_CSR
            fprintf(stderr, "csr_read: invalid CSR=0x%x\n", static_cast<int>(csraddr));
#endif
            return read_csr_fail(status);
    }
}

template <typename STATE_ACCESS>
static bool write_csr_sstatus(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    uint64_t mstatus = a.read_mstatus(s);
    return write_csr_mstatus(a, s, (mstatus & ~SSTATUS_WRITE_MASK) | (val & SSTATUS_WRITE_MASK));
}

template <typename STATE_ACCESS>
static bool write_csr_sie(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    uint64_t mask = a.read_mideleg(s);
    uint64_t mie = a.read_mie(s);
    a.write_mie(s, (mie & ~mask) | (val & mask));
    processor_set_brk_from_mip_mie(s);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_stvec(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    a.write_stvec(s, val & ~3);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_scounteren(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    a.write_scounteren(s, val & COUNTEREN_MASK);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_sscratch(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    a.write_sscratch(s, val);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_sepc(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    a.write_sepc(s, val & ~3);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_scause(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    a.write_scause(s, val);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_stval(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    a.write_stval(s, val);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_sip(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    uint64_t mask = a.read_mideleg(s);
    uint64_t mip = a.read_mip(s);
    mip = (mip & ~mask) | (val & mask);
    a.write_mip(s, mip);
    processor_set_brk_from_mip_mie(s);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_satp(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    uint64_t satp = a.read_satp(s);
    int mode = satp >> 60;
    int new_mode = (val >> 60) & 0xf;
    if (new_mode == 0 || (new_mode >= 8 && new_mode <= 9))
        mode = new_mode;
    // no ASID implemented
    a.write_satp(s, (val & (((uint64_t)1 << 44) - 1)) | ((uint64_t)mode << 60));
    // Since MMU configuration was changted, flush the TLBs
    // This does not need to be done within the blockchain
    tlb_flush_all(s);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mstatus(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    uint64_t mstatus = a.read_mstatus(s) & MSTATUS_READ_MASK;

    // If MMU configuration was changed, flush the TLBs
    // This does not need to be done within the blockchain
    uint64_t mod = mstatus ^ val;
    if ((mod & (MSTATUS_MPRV | MSTATUS_SUM | MSTATUS_MXR)) != 0 ||
        ((mstatus & MSTATUS_MPRV) && (mod & MSTATUS_MPP) != 0)) {
        tlb_flush_all(s);
    }

    // Modify only bits that can be written to
    mstatus = (mstatus & ~MSTATUS_WRITE_MASK) | (val & MSTATUS_WRITE_MASK);
    // Update the SD bit
    if ((mstatus & MSTATUS_FS) == MSTATUS_FS) mstatus |= MSTATUS_SD;
    // Store results
    a.write_mstatus(s, mstatus);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_medeleg(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    const uint64_t mask = (1 << (CAUSE_STORE_AMO_PAGE_FAULT + 1)) - 1;
    a.write_medeleg(s, (a.read_medeleg(s) & ~mask) | (val & mask));
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mideleg(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    const uint64_t mask = MIP_SSIP | MIP_STIP | MIP_SEIP;
    a.write_mideleg(s, (a.read_mideleg(s) & ~mask) | (val & mask));
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mie(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    const uint64_t mask = MIP_MSIP | MIP_MTIP | MIP_SSIP | MIP_STIP | MIP_SEIP;
    a.write_mie(s, (a.read_mie(s) & ~mask) | (val & mask));
    processor_set_brk_from_mip_mie(s);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mtvec(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    a.write_mtvec(s, val & ~3);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mcounteren(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    a.write_mcounteren(s, val & COUNTEREN_MASK);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_minstret(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    a.write_minstret(s, val-1); // The value will be incremented after the instruction is executed
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mcycle(STATE_ACCESS &a, processor_state *s, uint64_t val) {
#if 0
    (void) csraddr;
    a.write_mcycle(s, val-1); // The value will be incremented after the instruction is executed
    return true;
#endif
    //??D We should decide if we want to allow writes to mcycle
    //    RISC-V says it is an MRW CSR, read-writeable in machine-mode
    //    It doesn't look as though BBL does this, so we are
    //    fine making it read-only
    (void) a; (void) s; (void) val;
    return false;
}

template <typename STATE_ACCESS>
static bool write_csr_mscratch(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    a.write_mscratch(s, val);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mepc(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    a.write_mepc(s, val & ~3);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mcause(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    a.write_mcause(s, val);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mtval(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    a.write_mtval(s, val);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mip(STATE_ACCESS &a, processor_state *s, uint64_t val) {
    const uint64_t mask = MIP_SSIP | MIP_STIP;
    uint64_t mip = a.read_mip(s);
    mip = (mip & ~mask) | (val & mask);
    a.write_mip(s, mip);
    processor_set_brk_from_mip_mie(s);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr(STATE_ACCESS &a, processor_state *s, CSR_address csraddr, uint64_t val) {
#if defined(DUMP_CSR)
    fprintf(stderr, "csr_write: csr=0x%03x val=0x", static_cast<int>(csraddr));
    print_uint64_t(val);
    fprintf(stderr, "\n");
#endif
    if (csr_is_read_only(csraddr)) return false;
    if (csr_priv(csraddr) > s->iflags_PRV) return false;

    switch(csraddr) {
        case CSR_address::sstatus: return write_csr_sstatus(a, s, val);
        case CSR_address::sie: return write_csr_sie(a, s, val);
        case CSR_address::stvec: return write_csr_stvec(a, s, val);
        case CSR_address::scounteren: return write_csr_scounteren(a, s, val);

        case CSR_address::sscratch: return write_csr_sscratch(a, s, val);
        case CSR_address::sepc: return write_csr_sepc(a, s, val);
        case CSR_address::scause: return write_csr_scause(a, s, val);
        case CSR_address::stval: return write_csr_stval(a, s, val);
        case CSR_address::sip: return write_csr_sip(a, s, val);

        case CSR_address::satp: return write_csr_satp(a, s, val);

        case CSR_address::mstatus: return write_csr_mstatus(a, s, val);
        case CSR_address::medeleg: return write_csr_medeleg(a, s, val);
        case CSR_address::mideleg: return write_csr_mideleg(a, s, val);
        case CSR_address::mie: return write_csr_mie(a, s, val);
        case CSR_address::mtvec: return write_csr_mtvec(a, s, val);
        case CSR_address::mcounteren: return write_csr_mcounteren(a, s, val);

        case CSR_address::mscratch: return write_csr_mscratch(a, s, val);
        case CSR_address::mepc: return write_csr_mepc(a, s, val);
        case CSR_address::mcause: return write_csr_mcause(a, s, val);
        case CSR_address::mtval: return write_csr_mtval(a, s, val);
        case CSR_address::mip: return write_csr_mip(a, s, val);

        case CSR_address::mcycle: return write_csr_mcycle(a, s, val);
        case CSR_address::minstret: return write_csr_minstret(a, s, val);

        // Ignore writes
        case CSR_address::misa:
        case CSR_address::tselect:
        case CSR_address::tdata1:
        case CSR_address::tdata2:
        case CSR_address::tdata3:
            return true;

        // Invalid CSRs
        default:
        //case CSR_address::ucycle: // read-only
        //case CSR_address::utime: // read-only
        //case CSR_address::uinstret: // read-only
        //case CSR_address::ustatus: // no U-mode traps
        //case CSR_address::uie: // no U-mode traps
        //case CSR_address::utvec: // no U-mode traps
        //case CSR_address::uscratch: // no U-mode traps
        //case CSR_address::uepc: // no U-mode traps
        //case CSR_address::ucause: // no U-mode traps
        //case CSR_address::utval: // no U-mode traps
        //case CSR_address::uip: // no U-mode traps
        //case CSR_address::ucycleh: // 32-bit only
        //case CSR_address::utimeh: // 32-bit only
        //case CSR_address::uinstreth: // 32-bit only
        //case CSR_address::sedeleg: // no U-mode traps
        //case CSR_address::sideleg: // no U-mode traps
        //case CSR_address::mvendorid: // read-only
        //case CSR_address::marchid: // read-only
        //case CSR_address::mimplid: // read-only
        //case CSR_address::mhartid: // read-only
        //case CSR_address::mcycleh: // 32-bit only
        //case CSR_address::minstreth: // 32-bit only
#ifdef DUMP_INVALID_CSR
            fprintf(stderr, "csr_write: invalid CSR=0x%x\n", static_cast<int>(csraddr));
#endif
            return false;
    }
}

template <typename STATE_ACCESS, typename RS1VAL>
static inline execute_status execute_csr_RW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn, const RS1VAL &rs1val) {
    CSR_address csraddr = static_cast<CSR_address>(insn_I_uimm(insn));
    // Try to read old CSR value
    bool status = true;
    uint64_t csrval = 0;
    // If rd=r0, we do not read from the CSR to avoid side-effects
    uint32_t rd = insn_rd(insn);
    if (rd != 0)
        csrval = read_csr(a, s, csraddr, &status);
    if (!status)
        return execute_illegal_insn_exception(a, s, pc, insn);
    // Try to write new CSR value
    //??D When we optimize the inner interpreter loop, we
    //    will have to check if there was a change to the
    //    memory manager and report back from here so we
    //    break out of the inner loop
    if (!write_csr(a, s, csraddr, rs1val(a, s, insn)))
        return execute_illegal_insn_exception(a, s, pc, insn);
    if (rd != 0)
        a.write_register(s, rd, csrval);
    return execute_next_insn(a, s, pc);

}

template <typename STATE_ACCESS>
static inline execute_status execute_CSRRW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "CSRRW");
    return execute_csr_RW(a, s, pc, insn,
        [](STATE_ACCESS &a, processor_state *s, uint32_t insn) -> uint64_t { return a.read_register(s, insn_rs1(insn)); }
    );
}

template <typename STATE_ACCESS>
static inline execute_status execute_CSRRWI(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "CSRRWI");
    return execute_csr_RW(a, s, pc, insn,
        [](STATE_ACCESS, processor_state *, uint32_t insn) -> uint64_t { return static_cast<uint64_t>(insn_rs1(insn)); }
    );
}

template <typename STATE_ACCESS, typename F>
static inline execute_status execute_csr_SC(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn, const F &f) {
    CSR_address csraddr = static_cast<CSR_address>(insn_I_uimm(insn));
    // Try to read old CSR value
    bool status = false;
    uint64_t csrval = read_csr(a, s, csraddr, &status);
    if (!status)
        return execute_illegal_insn_exception(a, s, pc, insn);
    // Load value of rs1 before potentially overwriting it
    // with the value of the csr when rd=rs1
    uint32_t rs1 = insn_rs1(insn);
    uint64_t rs1val = a.read_register(s, rs1);
    uint32_t rd = insn_rd(insn);
    if (rd != 0)
        a.write_register(s, rd, csrval);
    if (rs1 != 0) {
        //??D When we optimize the inner interpreter loop, we
        //    will have to check if there was a change to the
        //    memory manager and report back from here so we
        //    break out of the inner loop
        if (!write_csr(a, s, csraddr, f(csrval, rs1val)))
            return execute_illegal_insn_exception(a, s, pc, insn);
    }
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_CSRRS(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "CSRRS");
    return execute_csr_SC(a, s, pc, insn, [](uint64_t csr, uint64_t rs1) -> uint64_t { return csr | rs1; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_CSRRC(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "CSRRC");
    return execute_csr_SC(a, s, pc, insn, [](uint64_t csr, uint64_t rs1) -> uint64_t {
        return csr & ~rs1;
    });
}

template <typename STATE_ACCESS, typename F>
static inline execute_status execute_csr_SCI(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn, const F &f) {
    CSR_address csraddr = static_cast<CSR_address>(insn_I_uimm(insn));
    // Try to read old CSR value
    bool status = false;
    uint64_t csrval = read_csr(a, s, csraddr, &status);
    if (!status)
        return execute_illegal_insn_exception(a, s, pc, insn);
    uint32_t rd = insn_rd(insn);
    if (rd != 0)
        a.write_register(s, rd, csrval);
    uint32_t rs1 = insn_rs1(insn);
    if (rs1 != 0) {
        //??D When we optimize the inner interpreter loop, we
        //    will have to check if there was a change to the
        //    memory manager and report back from here so we
        //    break out of the inner loop
        if (!write_csr(a, s, csraddr, f(csrval, rs1)))
            return execute_illegal_insn_exception(a, s, pc, insn);
    }
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_CSRRSI(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "CSRRSI");
    return execute_csr_SCI(a, s, pc, insn, [](uint64_t csr, uint32_t rs1) -> uint64_t { return csr | rs1; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_CSRRCI(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "CSRRCI");
    return execute_csr_SCI(a, s, pc, insn, [](uint64_t csr, uint32_t rs1) -> uint64_t { return csr & ~rs1; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_ECALL(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    (void) a;
    dump_insn(s, pc, insn, "ECALL");
    //??D Need another version of raise_exception that does not modify mtval
    raise_exception(a, s, CAUSE_ECALL_BASE + s->iflags_PRV, s->mtval);
    return execute_status::retired;
}

template <typename STATE_ACCESS>
static inline execute_status execute_EBREAK(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    (void) a;
    dump_insn(s, pc, insn, "EBREAK");
    //??D Need another version of raise_exception that does not modify mtval
    raise_exception(a, s, CAUSE_BREAKPOINT, s->mtval);
    return execute_status::retired;
}

template <typename STATE_ACCESS>
static inline execute_status execute_URET(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "URET"); // no U-mode traps
    return execute_illegal_insn_exception(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRET(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SRET");
    int priv = a.read_iflags_PRV(s);
    uint64_t mstatus = a.read_mstatus(s);
    if (priv < PRV_S || (priv == PRV_S && (mstatus & MSTATUS_TSR))) {
        return execute_illegal_insn_exception(a, s, pc, insn);
    } else {
        int spp = (mstatus >> MSTATUS_SPP_SHIFT) & 1;
        /* set the IE state to previous IE state */
        int spie = (mstatus >> MSTATUS_SPIE_SHIFT) & 1;
        mstatus = (mstatus & ~(1 << MSTATUS_SIE_SHIFT)) | (spie << MSTATUS_SIE_SHIFT);
        /* set SPIE to 1 */
        mstatus |= MSTATUS_SPIE;
        /* set SPP to U */
        mstatus &= ~MSTATUS_SPP;
        a.write_mstatus(s, mstatus);
        set_priv(a, s, priv, spp);
        a.write_pc(s, a.read_sepc(s));
        // s->brk = true; // overkill
        return execute_status::retired;
    }
}

template <typename STATE_ACCESS>
static inline execute_status execute_MRET(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "MRET");
    int priv = a.read_iflags_PRV(s);
    if (priv < PRV_M) {
        return execute_illegal_insn_exception(a, s, pc, insn);
    } else {
        uint64_t mstatus = a.read_mstatus(s);
        int mpp = (mstatus >> MSTATUS_MPP_SHIFT) & 3;
        /* set the IE state to previous IE state */
        int mpie = (mstatus >> MSTATUS_MPIE_SHIFT) & 1;
        mstatus = (mstatus & ~(1 << MSTATUS_MIE_SHIFT)) | (mpie << MSTATUS_MIE_SHIFT);
        /* set MPIE to 1 */
        mstatus |= MSTATUS_MPIE;
        /* set MPP to U */
        mstatus &= ~MSTATUS_MPP;
        a.write_mstatus(s, mstatus);
        set_priv(a, s, priv, mpp);
        a.write_pc(s, a.read_mepc(s));
        // s->brk = true; // overkill
        return execute_status::retired;
    }
}

template <typename STATE_ACCESS>
static inline execute_status execute_WFI(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "WFI");
    if (s->iflags_PRV == PRV_U || (s->iflags_PRV == PRV_S && (s->mstatus & MSTATUS_TW)))
        return execute_illegal_insn_exception(a, s, pc, insn);
    // Go to power down if no enabled interrupts are pending
    if ((s->mip & s->mie) == 0) {
        s->iflags_I = true;
        s->brk = true; // set brk so the outer loop can skip time if it wants too
    }
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_FENCE(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    (void) insn;
    dump_insn(s, pc, insn, "FENCE");
    // Really do nothing
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_FENCE_I(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    (void) insn;
    dump_insn(s, pc, insn, "FENCE_I");
    // Really do nothing
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS, typename F>
static inline execute_status execute_arithmetic(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn, const F &f) {
    uint32_t rd = insn_rd(insn);
    if (rd != 0) {
        // Ensure rs1 and rs2 are loaded in order: do not nest with call to f() as
        // the order of evaluation of arguments in a function call is undefined.
        uint64_t rs1 = a.read_register(s, insn_rs1(insn));
        uint64_t rs2 = a.read_register(s, insn_rs2(insn));
        // Now we can safely invoke f()
        a.write_register(s, rd, f(rs1, rs2));
    }
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_ADD(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "ADD");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        uint64_t val = 0;
        __builtin_add_overflow(rs1, rs2, &val);
        return val;
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SUB(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SUB");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        uint64_t val = 0;
        __builtin_sub_overflow(rs1, rs2, &val);
        return val;
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLL(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SLL");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return rs1 << (rs2 & (XLEN-1));
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLT(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SLT");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return static_cast<int64_t>(rs1) < static_cast<int64_t>(rs2);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLTU(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SLTU");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return rs1 < rs2;
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_XOR(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "XOR");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return rs1 ^ rs2;
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRL(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SRL");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return rs1 >> (rs2 & (XLEN-1));
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRA(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SRA");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return static_cast<uint64_t>(static_cast<int64_t>(rs1) >> (rs2 & (XLEN-1)));
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_OR(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "OR");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return rs1 | rs2;
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AND(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AND");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return rs1 & rs2;
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_MUL(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "MUL");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int64_t srs1 = static_cast<int64_t>(rs1);
        int64_t srs2 = static_cast<int64_t>(rs2);
        int64_t val = 0;
        __builtin_mul_overflow(srs1, srs2, &val);
        return static_cast<uint64_t>(val);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_MULH(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "MULH");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int64_t srs1 = static_cast<int64_t>(rs1);
        int64_t srs2 = static_cast<int64_t>(rs2);
        return static_cast<uint64_t>((static_cast<int128_t>(srs1) * static_cast<int128_t>(srs2)) >> 64);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_MULHSU(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "MULHSU");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int64_t srs1 = static_cast<int64_t>(rs1);
        return static_cast<uint64_t>((static_cast<int128_t>(srs1) * static_cast<int128_t>(rs2)) >> 64);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_MULHU(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "MULHU");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return static_cast<uint64_t>((static_cast<int128_t>(rs1) * static_cast<int128_t>(rs2)) >> 64);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_DIV(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "DIV");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int64_t srs1 = static_cast<int64_t>(rs1);
        int64_t srs2 = static_cast<int64_t>(rs2);
        if (srs2 == 0) {
            return static_cast<uint64_t>(-1);
        } else if (srs1 == ((int64_t)1 << (XLEN - 1)) && srs2 == -1) {
            return static_cast<uint64_t>(srs1);
        } else {
            return static_cast<uint64_t>(srs1 / srs2);
        }
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_DIVU(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "DIVU");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        if (rs2 == 0) {
            return static_cast<uint64_t>(-1);
        } else {
            return rs1 / rs2;
        }
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_REM(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "REM");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int64_t srs1 = static_cast<int64_t>(rs1);
        int64_t srs2 = static_cast<int64_t>(rs2);
        if (srs2 == 0) {
            return srs1;
        } else if (srs1 == ((int64_t)1 << (XLEN - 1)) && srs2 == -1) {
            return 0;
        } else {
            return static_cast<uint64_t>(srs1 % srs2);
        }
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_REMU(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "REMU");
    return execute_arithmetic(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        if (rs2 == 0) {
            return rs1;
        } else {
            return rs1 % rs2;
        }
    });
}

template <typename STATE_ACCESS, typename F>
static inline execute_status execute_arithmetic_immediate(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn, const F &f) {
    uint32_t rd = insn_rd(insn);
    if (rd != 0) {
        uint64_t rs1 = a.read_register(s, insn_rs1(insn));
        int32_t imm = insn_I_imm(insn);
        a.write_register(s, rd, f(rs1, imm));
    }
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRLI(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SRLI");
    return execute_arithmetic_immediate(a, s, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return rs1 >> (imm & (XLEN - 1));
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRAI(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SRAI");
    return execute_arithmetic_immediate(a, s, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return static_cast<uint64_t>(static_cast<int64_t>(rs1) >> (imm & (XLEN - 1)));
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_ADDI(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "ADDI");
    return execute_arithmetic_immediate(a, s, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return rs1+imm;
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLTI(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SLTI");
    return execute_arithmetic_immediate(a, s, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return static_cast<int64_t>(rs1) < static_cast<int64_t>(imm);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLTIU(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SLTIU");
    return execute_arithmetic_immediate(a, s, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return rs1 < static_cast<uint64_t>(imm);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_XORI(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "XORI");
    return execute_arithmetic_immediate(a, s, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return rs1 ^ imm;
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_ORI(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "ORI");
    return execute_arithmetic_immediate(a, s, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return rs1 | imm;
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_ANDI(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "ANDI");
    return execute_arithmetic_immediate(a, s, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return rs1 & imm;
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLLI(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    if ((insn & (0b111111 << 26)) == 0) {
        dump_insn(s, pc, insn, "SLLI");
        return execute_arithmetic_immediate(a, s, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
            // No need to mask lower 6 bits in imm because of the if condition a above
            // We do it anyway here to prevent problems if this code is moved
            return rs1 << (imm & 0b111111);
        });
    } else {
        return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

template <typename STATE_ACCESS>
static inline execute_status execute_ADDIW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "ADDIW");
    return execute_arithmetic_immediate(a, s, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return static_cast<uint64_t>(static_cast<int32_t>(rs1) + imm);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLLIW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    if (insn_funct7(insn) == 0) {
        dump_insn(s, pc, insn, "SLLIW");
        return execute_arithmetic_immediate(a, s, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
            // No need to mask lower 5 bits in imm because of the if condition a above
            // We do it anyway here to prevent problems if this code is moved
            int32_t rs1w = static_cast<int32_t>(rs1) << (imm & 0b11111);
            return static_cast<uint64_t>(rs1w);
        });
    } else {
        return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRLIW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SRLIW");
    return execute_arithmetic_immediate(a, s, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        // No need to mask lower 5 bits in imm because of funct7 test in caller
        // We do it anyway here to prevent problems if this code is moved
        int32_t rs1w = static_cast<int32_t>(static_cast<uint32_t>(rs1) >> (imm & 0b11111));
        return static_cast<uint64_t>(rs1w);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRAIW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SRAIW");
    return execute_arithmetic_immediate(a, s, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(rs1) >> (imm & 0b11111);
        return static_cast<uint64_t>(rs1w);
    });
}

template <typename T, typename STATE_ACCESS>
static inline execute_status execute_S(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    uint64_t addr = a.read_register(s, insn_rs1(insn));
    int32_t imm = insn_S_imm(insn);
    uint64_t val = a.read_register(s, insn_rs2(insn));
    if (write_memory<T>(a, s, addr+imm, val)) {
        return execute_next_insn(a, s, pc);
    } else {
        return execute_raised_exception(a, s, pc);
    }
}

template <typename STATE_ACCESS>
static inline execute_status execute_SB(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SB");
    return execute_S<uint8_t>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SH(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SH");
    return execute_S<uint16_t>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SW");
    return execute_S<uint32_t>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SD(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "SD");
    return execute_S<uint64_t>(a, s, pc, insn);
}

template <typename T, typename STATE_ACCESS>
static inline execute_status execute_L(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    uint64_t addr = a.read_register(s, insn_rs1(insn));
    int32_t imm = insn_I_imm(insn);
    T val;
    if (read_memory<T>(a, s, addr+imm, &val)) {
        // This static branch is eliminated by the compiler
        if (std::is_signed<T>::value) {
            a.write_register(s, insn_rd(insn), static_cast<int64_t>(val));
        } else {
            a.write_register(s, insn_rd(insn), static_cast<uint64_t>(val));
        }
        return execute_next_insn(a, s, pc);
    } else {
        return execute_raised_exception(a, s, pc);
    }
}

template <typename STATE_ACCESS>
static inline execute_status execute_LB(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "LB");
    return execute_L<int8_t>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline execute_status execute_LH(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "LH");
    return execute_L<int16_t>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline execute_status execute_LW(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "LW");
    return execute_L<int32_t>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline execute_status execute_LD(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "LD");
    return execute_L<int64_t>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline execute_status execute_LBU(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "LBU");
    return execute_L<uint8_t>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline execute_status execute_LHU(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "LHU");
    return execute_L<uint16_t>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline execute_status execute_LWU(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "LWU");
    return execute_L<uint32_t>(a, s, pc, insn);
}

template <typename STATE_ACCESS, typename F>
static inline execute_status execute_branch(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn, const F &f) {
    uint64_t rs1 = a.read_register(s, insn_rs1(insn));
    uint64_t rs2 = a.read_register(s, insn_rs2(insn));
    if (f(rs1, rs2)) {
        uint64_t new_pc = (int64_t)(pc + insn_B_imm(insn));
        if (new_pc & 3) {
            return execute_misaligned_fetch_exception(a, s, new_pc);
        } else {
            return execute_jump(a, s, new_pc);
        }
    }
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_BEQ(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "BEQ");
    return execute_branch(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool { return rs1 == rs2; });
}


template <typename STATE_ACCESS>
static inline execute_status execute_BNE(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "BNE");
    return execute_branch(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool { return rs1 != rs2; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_BLT(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "BLT");
    return execute_branch(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool {
        return static_cast<int64_t>(rs1) < static_cast<int64_t>(rs2);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_BGE(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "BGE");
    return execute_branch(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool {
        return static_cast<int64_t>(rs1) >= static_cast<int64_t>(rs2);
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_BLTU(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "BLTU");
    return execute_branch(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool {
        return rs1 < rs2;
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_BGEU(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "BGEU");
    return execute_branch(a, s, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool {
        return rs1 >= rs2;
    });
}

template <typename STATE_ACCESS>
static inline execute_status execute_LUI(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "LUI");
    uint32_t rd = insn_rd(insn);
    if (rd != 0)
        a.write_register(s, rd, insn_U_imm(insn));
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_AUIPC(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "AUIPC");
    uint32_t rd = insn_rd(insn);
    if (rd != 0)
        a.write_register(s, rd, pc + insn_U_imm(insn));
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_JAL(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "JAL");
    uint64_t new_pc = pc + insn_J_imm(insn);
    if (new_pc & 3) {
        return execute_misaligned_fetch_exception(a, s, new_pc);
    }
    uint32_t rd = insn_rd(insn);
    if (rd != 0)
        a.write_register(s, rd, pc + 4);
    return execute_jump(a, s, new_pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_JALR(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    dump_insn(s, pc, insn, "JALR");
    uint64_t val = pc + 4;
    uint64_t new_pc = (int64_t)(a.read_register(s, insn_rs1(insn)) + insn_I_imm(insn)) & ~1;
    if (new_pc & 3)
        return execute_misaligned_fetch_exception(a, s, new_pc);
    uint32_t rd = insn_rd(insn);
    if (rd != 0)
        a.write_register(s, rd, val);
    return execute_jump(a, s, new_pc);
}

template <typename STATE_ACCESS>
static execute_status execute_SFENCE_VMA(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    // rs1 and rs2 are arbitrary, rest is set
    if ((insn & 0b11111110000000000111111111111111) == 0b00010010000000000000000001110011) {
        dump_insn(s, pc, insn, "SFENCE_VMA");
        if (s->iflags_PRV == PRV_U ||
            (s->iflags_PRV == PRV_S && (s->mstatus & MSTATUS_TVM)))
            return execute_illegal_insn_exception(a, s, pc, insn);
        uint32_t rs1 = insn_rs1(insn);
        if (rs1 == 0) {
            tlb_flush_all(s);
        } else {
            tlb_flush_vaddr(s, s->reg[rs1]);
        }
        //??D The current code TLB may have been flushed
        // s->brk = true;
        return execute_next_insn(a, s, pc);
    } else {
        return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

/// \brief Executes an instruction of the atomic group.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_atomic_group(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
#ifdef DUMP_COUNTERS
    s->count_amo++;
#endif
    switch (static_cast<atomic_funct3_funct5>(insn_funct3_funct5(insn))) {
        case atomic_funct3_funct5::LR_W: return execute_LR_W(a, s, pc, insn);
        case atomic_funct3_funct5::SC_W: return execute_SC_W(a, s, pc, insn);
        case atomic_funct3_funct5::AMOSWAP_W: return execute_AMOSWAP_W(a, s, pc, insn);
        case atomic_funct3_funct5::AMOADD_W: return execute_AMOADD_W(a, s, pc, insn);
        case atomic_funct3_funct5::AMOXOR_W: return execute_AMOXOR_W(a, s, pc, insn);
        case atomic_funct3_funct5::AMOAND_W: return execute_AMOAND_W(a, s, pc, insn);
        case atomic_funct3_funct5::AMOOR_W: return execute_AMOOR_W(a, s, pc, insn);
        case atomic_funct3_funct5::AMOMIN_W: return execute_AMOMIN_W(a, s, pc, insn);
        case atomic_funct3_funct5::AMOMAX_W: return execute_AMOMAX_W(a, s, pc, insn);
        case atomic_funct3_funct5::AMOMINU_W: return execute_AMOMINU_W(a, s, pc, insn);
        case atomic_funct3_funct5::AMOMAXU_W: return execute_AMOMAXU_W(a, s, pc, insn);
        case atomic_funct3_funct5::LR_D: return execute_LR_D(a, s, pc, insn);
        case atomic_funct3_funct5::SC_D: return execute_SC_D(a, s, pc, insn);
        case atomic_funct3_funct5::AMOSWAP_D: return execute_AMOSWAP_D(a, s, pc, insn);
        case atomic_funct3_funct5::AMOADD_D: return execute_AMOADD_D(a, s, pc, insn);
        case atomic_funct3_funct5::AMOXOR_D: return execute_AMOXOR_D(a, s, pc, insn);
        case atomic_funct3_funct5::AMOAND_D: return execute_AMOAND_D(a, s, pc, insn);
        case atomic_funct3_funct5::AMOOR_D: return execute_AMOOR_D(a, s, pc, insn);
        case atomic_funct3_funct5::AMOMIN_D: return execute_AMOMIN_D(a, s, pc, insn);
        case atomic_funct3_funct5::AMOMAX_D: return execute_AMOMAX_D(a, s, pc, insn);
        case atomic_funct3_funct5::AMOMINU_D: return execute_AMOMINU_D(a, s, pc, insn);
        case atomic_funct3_funct5::AMOMAXU_D: return execute_AMOMAXU_D(a, s, pc, insn);
        default: return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

/// \brief Executes an instruction of the arithmetic-32 group.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_arithmetic_32_group(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    switch (static_cast<arithmetic_32_funct3_funct7>(insn_funct3_funct7(insn))) {
        case arithmetic_32_funct3_funct7::ADDW: return execute_ADDW(a, s, pc, insn);
        case arithmetic_32_funct3_funct7::SUBW: return execute_SUBW(a, s, pc, insn);
        case arithmetic_32_funct3_funct7::SLLW: return execute_SLLW(a, s, pc, insn);
        case arithmetic_32_funct3_funct7::SRLW: return execute_SRLW(a, s, pc, insn);
        case arithmetic_32_funct3_funct7::SRAW: return execute_SRAW(a, s, pc, insn);
        case arithmetic_32_funct3_funct7::MULW: return execute_MULW(a, s, pc, insn);
        case arithmetic_32_funct3_funct7::DIVW: return execute_DIVW(a, s, pc, insn);
        case arithmetic_32_funct3_funct7::DIVUW: return execute_DIVUW(a, s, pc, insn);
        case arithmetic_32_funct3_funct7::REMW: return execute_REMW(a, s, pc, insn);
        case arithmetic_32_funct3_funct7::REMUW: return execute_REMUW(a, s, pc, insn);
        default: return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

/// \brief Executes an instruction of the shift-rightimmediate-32 group.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_shift_right_immediate_32_group(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    switch (static_cast<shift_right_immediate_32_funct7>(insn_funct7(insn))) {
        case shift_right_immediate_32_funct7::SRLIW: return execute_SRLIW(a, s, pc, insn);
        case shift_right_immediate_32_funct7::SRAIW: return execute_SRAIW(a, s, pc, insn);
        default: return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

/// \brief Executes an instruction of the arithmetic-immediate-32 group.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_arithmetic_immediate_32_group(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    switch (static_cast<arithmetic_immediate_32_funct3>(insn_funct3(insn))) {
        case arithmetic_immediate_32_funct3::ADDIW: return execute_ADDIW(a, s, pc, insn);
        case arithmetic_immediate_32_funct3::SLLIW: return execute_SLLIW(a, s, pc, insn);
        case arithmetic_immediate_32_funct3::shift_right_immediate_32_group:
            return execute_shift_right_immediate_32_group(a, s, pc, insn);
        default: return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

/// \brief Executes an instruction of the environment, trap, interrupt, or memory management groups.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_env_trap_int_mm_group(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    switch (static_cast<env_trap_int_group_insn>(insn)) {
        case env_trap_int_group_insn::ECALL: return execute_ECALL(a, s, pc, insn);
        case env_trap_int_group_insn::EBREAK: return execute_EBREAK(a, s, pc, insn);
        case env_trap_int_group_insn::URET: return execute_URET(a, s, pc, insn);
        case env_trap_int_group_insn::SRET: return execute_SRET(a, s, pc, insn);
        case env_trap_int_group_insn::MRET: return execute_MRET(a, s, pc, insn);
        case env_trap_int_group_insn::WFI: return execute_WFI(a, s, pc, insn);
        default: return execute_SFENCE_VMA(a, s, pc, insn);
    }
}

/// \brief Executes an instruction of the CSR, environment, trap, interrupt, or memory management groups.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_csr_env_trap_int_mm_group(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    switch (static_cast<csr_env_trap_int_mm_funct3>(insn_funct3(insn))) {
        case csr_env_trap_int_mm_funct3::CSRRW: return execute_CSRRW(a, s, pc, insn);
        case csr_env_trap_int_mm_funct3::CSRRS: return execute_CSRRS(a, s, pc, insn);
        case csr_env_trap_int_mm_funct3::CSRRC: return execute_CSRRC(a, s, pc, insn);
        case csr_env_trap_int_mm_funct3::CSRRWI: return execute_CSRRWI(a, s, pc, insn);
        case csr_env_trap_int_mm_funct3::CSRRSI: return execute_CSRRSI(a, s, pc, insn);
        case csr_env_trap_int_mm_funct3::CSRRCI: return execute_CSRRCI(a, s, pc, insn);
        case csr_env_trap_int_mm_funct3::env_trap_int_mm_group:
             return execute_env_trap_int_mm_group(a, s, pc, insn);
        default: return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

/// \brief Executes an instruction of the fence group.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_fence_group(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    if (insn == 0x0000100f) {
        return execute_FENCE_I(a, s, pc, insn);
    } else if (insn & 0xf00fff80) {
        return execute_illegal_insn_exception(a, s, pc, insn);
    } else {
        return execute_FENCE(a, s, pc, insn);
    }
}

/// \brief Executes an instruction of the shift-right-immediate group.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_shift_right_immediate_group(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    switch (static_cast<shift_right_immediate_funct6>(insn_funct6(insn))) {
        case shift_right_immediate_funct6::SRLI: return execute_SRLI(a, s, pc, insn);
        case shift_right_immediate_funct6::SRAI: return execute_SRAI(a, s, pc, insn);
        default: return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

/// \brief Executes an instruction of the arithmetic group.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_arithmetic_group(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    //std::cerr << "funct3_funct7: " << std::bitset<10>(insn_funct3_funct7(insn)) << '\n';
    switch (static_cast<arithmetic_funct3_funct7>(insn_funct3_funct7(insn))) {
        case arithmetic_funct3_funct7::ADD: return execute_ADD(a, s, pc, insn);
        case arithmetic_funct3_funct7::SUB: return execute_SUB(a, s, pc, insn);
        case arithmetic_funct3_funct7::SLL: return execute_SLL(a, s, pc, insn);
        case arithmetic_funct3_funct7::SLT: return execute_SLT(a, s, pc, insn);
        case arithmetic_funct3_funct7::SLTU: return execute_SLTU(a, s, pc, insn);
        case arithmetic_funct3_funct7::XOR: return execute_XOR(a, s, pc, insn);
        case arithmetic_funct3_funct7::SRL: return execute_SRL(a, s, pc, insn);
        case arithmetic_funct3_funct7::SRA: return execute_SRA(a, s, pc, insn);
        case arithmetic_funct3_funct7::OR: return execute_OR(a, s, pc, insn);
        case arithmetic_funct3_funct7::AND: return execute_AND(a, s, pc, insn);
        case arithmetic_funct3_funct7::MUL: return execute_MUL(a, s, pc, insn);
        case arithmetic_funct3_funct7::MULH: return execute_MULH(a, s, pc, insn);
        case arithmetic_funct3_funct7::MULHSU: return execute_MULHSU(a, s, pc, insn);
        case arithmetic_funct3_funct7::MULHU: return execute_MULHU(a, s, pc, insn);
        case arithmetic_funct3_funct7::DIV: return execute_DIV(a, s, pc, insn);
        case arithmetic_funct3_funct7::DIVU: return execute_DIVU(a, s, pc, insn);
        case arithmetic_funct3_funct7::REM: return execute_REM(a, s, pc, insn);
        case arithmetic_funct3_funct7::REMU: return execute_REMU(a, s, pc, insn);
        default: return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

/// \brief Executes an instruction of the arithmetic-immediate group.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_arithmetic_immediate_group(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    switch (static_cast<arithmetic_immediate_funct3>(insn_funct3(insn))) {
        case arithmetic_immediate_funct3::ADDI: return execute_ADDI(a, s, pc, insn);
        case arithmetic_immediate_funct3::SLTI: return execute_SLTI(a, s, pc, insn);
        case arithmetic_immediate_funct3::SLTIU: return execute_SLTIU(a, s, pc, insn);
        case arithmetic_immediate_funct3::XORI: return execute_XORI(a, s, pc, insn);
        case arithmetic_immediate_funct3::ORI: return execute_ORI(a, s, pc, insn);
        case arithmetic_immediate_funct3::ANDI: return execute_ANDI(a, s, pc, insn);
        case arithmetic_immediate_funct3::SLLI: return execute_SLLI(a, s, pc, insn);
        case arithmetic_immediate_funct3::shift_right_immediate_group:
            return execute_shift_right_immediate_group(a, s, pc, insn);
        default: return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

/// \brief Executes an instruction of the store group.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_store_group(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    switch (static_cast<store_funct3>(insn_funct3(insn))) {
        case store_funct3::SB: return execute_SB(a, s, pc, insn);
        case store_funct3::SH: return execute_SH(a, s, pc, insn);
        case store_funct3::SW: return execute_SW(a, s, pc, insn);
        case store_funct3::SD: return execute_SD(a, s, pc, insn);
        default: return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

/// \brief Executes an instruction of the load group.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_load_group(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    switch (static_cast<load_funct3>(insn_funct3(insn))) {
        case load_funct3::LB: return execute_LB(a, s, pc, insn);
        case load_funct3::LH: return execute_LH(a, s, pc, insn);
        case load_funct3::LW: return execute_LW(a, s, pc, insn);
        case load_funct3::LD: return execute_LD(a, s, pc, insn);
        case load_funct3::LBU: return execute_LBU(a, s, pc, insn);
        case load_funct3::LHU: return execute_LHU(a, s, pc, insn);
        case load_funct3::LWU: return execute_LWU(a, s, pc, insn);
        default: return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

/// \brief Executes an instruction of the branch group.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_branch_group(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
    switch (static_cast<branch_funct3>(insn_funct3(insn))) {
        case branch_funct3::BEQ: return execute_BEQ(a, s, pc, insn);
        case branch_funct3::BNE: return execute_BNE(a, s, pc, insn);
        case branch_funct3::BLT: return execute_BLT(a, s, pc, insn);
        case branch_funct3::BGE: return execute_BGE(a, s, pc, insn);
        case branch_funct3::BLTU: return execute_BLTU(a, s, pc, insn);
        case branch_funct3::BGEU: return execute_BGEU(a, s, pc, insn);
        default: return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

/// \brief Executes an instruction.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_insn(STATE_ACCESS &a, processor_state *s, uint64_t pc, uint32_t insn) {
//std::cerr << "insn: " << std::bitset<32>(insn) << '\n';
//??D We should probably try doing the first branch on the combined opcode, funct3, and funct7.
//    Maybe it reduces the number of levels needed to decode most instructions.
    switch (static_cast<opcode>(insn_opcode(insn))) {
        case opcode::LUI: return execute_LUI(a, s, pc, insn);
        case opcode::AUIPC: return execute_AUIPC(a, s, pc, insn);
        case opcode::JAL: return execute_JAL(a, s, pc, insn);
        case opcode::JALR: return execute_JALR(a, s, pc, insn);
        case opcode::branch_group: return execute_branch_group(a, s, pc, insn);
        case opcode::load_group: return execute_load_group(a, s, pc, insn);
        case opcode::store_group: return execute_store_group(a, s, pc, insn);
        case opcode::arithmetic_immediate_group: return execute_arithmetic_immediate_group(a, s, pc, insn);
        case opcode::arithmetic_group: return execute_arithmetic_group(a, s, pc, insn);
        case opcode::fence_group: return execute_fence_group(a, s, pc, insn);
        case opcode::csr_env_trap_int_mm_group: return execute_csr_env_trap_int_mm_group(a, s, pc, insn);
        case opcode::arithmetic_immediate_32_group: return execute_arithmetic_immediate_32_group(a, s, pc, insn);
        case opcode::arithmetic_32_group: return execute_arithmetic_32_group(a, s, pc, insn);
        case opcode::atomic_group: return execute_atomic_group(a, s, pc, insn);
        default: return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

/// \brief Instruction fetch status code
enum class fetch_status: int {
    exception, ///< Instruction fetch failed: exception raised
    success ///< Instruction fetch succeeded: proceed to execute
};

/// \brief Loads the next instruction.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Receives current pc.
/// \param insn Receives fetched instruction.
/// \return Returns fetch_status::success if load succeeded, fetch_status::exception if it caused an exception.
//          In that case, raise the exception.
template <typename STATE_ACCESS>
static fetch_status fetch_insn(STATE_ACCESS &a, processor_state *s, uint64_t *pc, uint32_t *insn) {
    // Get current pc from state
    uint64_t vaddr = a.read_pc(s);
    // Translate pc address from virtual to physical
    // First, check TLB
    int tlb_idx = (vaddr >> PG_SHIFT) & (TLB_SIZE - 1);
    uintptr_t mem_addend;
    // TLB match
    if (s->tlb_code[tlb_idx].vaddr == (vaddr & ~PG_MASK)) {
        mem_addend = s->tlb_code[tlb_idx].mem_addend;
    // TLB miss
    } else {
        uint64_t paddr;
        // Walk page table and obtain the physical address
        if (get_phys_addr(s, &paddr, vaddr, PTE_XWR_CODE_SHIFT)) {
            raise_exception(a, s, CAUSE_FETCH_PAGE_FAULT, vaddr);
            return fetch_status::exception;
        }
        // Walk memory map to find the range that contains the physical address
        PhysMemoryRange *pr = get_phys_mem_range(s->mem_map, paddr);
        // We only execute directly from RAM (as in "random access memory", which includes ROM)
        // If we are not in RAM or if we are not in any range, we treat this as a PMA violation
        if (!pr || !pr->is_ram) {
            raise_exception(a, s, CAUSE_FETCH_FAULT, vaddr);
            return fetch_status::exception;
        }
        // Update TLB with the new mapping between virtual and physical
        tlb_idx = (vaddr >> PG_SHIFT) & (TLB_SIZE - 1);
        uint8_t *ptr = pr->phys_mem + (uintptr_t)(paddr - pr->addr);
        s->tlb_code[tlb_idx].vaddr = vaddr & ~PG_MASK;
        s->tlb_code[tlb_idx].mem_addend = (uintptr_t)ptr - vaddr;
        mem_addend = s->tlb_code[tlb_idx].mem_addend;
    }

    // Finally load the instruction
    *pc = vaddr;
    *insn = *reinterpret_cast<uint32_t *>(mem_addend + (uintptr_t)vaddr);
    return fetch_status::success;
}

/// \brief Interpreter status code
enum class interpreter_status: int {
    brk,    ///< brk is set, indicating the tight loop was broken
    success ///< mcycle reached target value
};

/// \brief Tries to run the interpreter until mcycle hits a target
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param mcycle_end Target value for mcycle.
/// \returns Returns a status code that tells if the loop hit the target mcycle or stopped early.
/// \details The interpret may stop early if the machine halts permanently or becomes temporarily idle (waiting for interrupts).
template <typename STATE_ACCESS>
interpreter_status interpret(STATE_ACCESS &a, processor_state *s, uint64_t mcycle_end) {

    static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
        "code assumes little-endian byte ordering");

    static_assert(is_an_i_state_access<STATE_ACCESS>::value,
        "not an i_state_access");

    // If the cpu is halted, we are done
    if (a.read_iflags_H(s)) {
        return interpreter_status::success;
    }

    // If we reached the target mcycle, we are done
    // This is not necessary in the blockchain
    if (s->mcycle >= mcycle_end) {
        return interpreter_status::success;
    }

    // Raise the highest priority pending interrupt, if any
    raise_interrupt_if_any(a, s);

    uint64_t pc = 0;
    uint32_t insn = 0;

#ifdef DUMP_COUNTERS
        s->count_outers++;
#endif

    // The inner loops continues until there is an interrupt condition
    // or mcycle reaches mcycle_end
    for ( ;; )  {
        // Try to fetch the next instruction
        if (fetch_insn(a, s, &pc, &insn) == fetch_status::success) {
            // Try to execute it
            if (execute_insn(a, s, pc, insn) == execute_status::retired) {
                // If successful, increment the number of retired instructions minstret
                // WARNING: if an instruction modifies minstret, it needs to take into
                // account it this unconditional increment and set the value accordingly
                a.write_minstret(s, a.read_minstret(s)+1);
            }
        }
        // Increment the cycle counter mcycle
        // WARNING: if an instruction modifies mcycle, it needs to take into
        // account it this unconditional increment and set the value accordingly
        uint64_t mcycle = a.read_mcycle(s) + 1;
        a.write_mcycle(s, mcycle);

        // If the break flag is active, break from the inner loop
        if (s->brk) {
            return interpreter_status::brk;
        }
        // Otherwise, there can be no pending interrupts
        // An interrupt is pending when mie & mip != 0
        // and when interrupts are not globally disabled
        // in mstatus (MIE or SIE). The logic is a bit
        // complicated by privilege and delegation. See
        // get_pending_irq_mask for details.
        // assert(get_pending_irq_mask(s) == 0);
        // For simplicity, we brk whenever mie & mip != 0
        assert((s->mie & s->mip) == 0);
        // or whenever iflags_H is set
        assert(!s->iflags_H);

        // If we reached the target mcycle, we are done
        if (mcycle >= mcycle_end) {
            return interpreter_status::success;
        }
#ifdef DUMP_COUNTERS
        s->count_inners++;
#endif
    }
}

void processor_run(processor_state *s, uint64_t mcycle_end) {
    state_access a;
    interpret(a, s, mcycle_end);
}

uint64_t processor_read_mcycle(const processor_state *s) {
    return s->mcycle;
}

void processor_write_mcycle(processor_state *s, uint64_t cycles) {
    s->mcycle = cycles;
}

void processor_set_mip(processor_state *s, uint32_t mask) {
    s->mip |= mask;
    s->iflags_I = false;
    processor_set_brk_from_mip_mie(s);
}

void processor_reset_mip(processor_state *s, uint32_t mask) {
    s->mip &= ~mask;
    processor_set_brk_from_mip_mie(s);
}

uint32_t processor_read_mip(const processor_state *s) {
    return s->mip;
}

bool processor_read_iflags_I(const processor_state *s) {
    return s->iflags_I;
}

void processor_reset_iflags_I(processor_state *s) {
    s->iflags_I = false;
}

bool processor_read_iflags_H(const processor_state *s) {
    return s->iflags_H;
}

void processor_set_iflags_H(processor_state *s) {
    s->iflags_H = true;
    processor_set_brk_from_iflags_H(s);
}

int processor_get_max_xlen(const processor_state *) {
    return XLEN;
}

void processor_set_brk_from_mip_mie(processor_state *s) {
    s->brk = s->mip & s->mie;
}

void processor_set_brk_from_iflags_H(processor_state *s) {
    s->brk = true;
}

uint64_t processor_read_tohost(const processor_state *p) {
    return p->tohost;
}

void processor_write_tohost(processor_state *p, uint64_t val) {
    p->tohost = val;
}

uint64_t processor_read_fromhost(const processor_state *p) {
    return p->fromhost;
}

void processor_write_fromhost(processor_state *p, uint64_t val) {
    p->fromhost = val;
}

uint64_t processor_read_mtimecmp(const processor_state *p) {
    return p->mtimecmp;
}

void processor_write_mtimecmp(processor_state *p, uint64_t val) {
    p->mtimecmp = val;
}

uint64_t processor_read_misa(const processor_state *s) {
    return s->misa;
}
