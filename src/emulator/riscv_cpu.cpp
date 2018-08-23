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


//??D This code uses right-shifts of potentially negative
// values assuming the result will be an arithmetic shift.
// This is undefined in C and C++, but most compilers will
// do the expected. GCC, Clang, and Visual C all do the
// right thing, but if some other compiler is used, problems
// can arise.

/* this test works at least with gcc */
#if defined(__SIZEOF_INT128__)
#define HAVE_INT128
#endif

#ifdef HAVE_INT128

#ifdef __GNUC__
// GCC complains about __int128 with -pedantic or -pedantic-errors
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#endif

#define XLEN 64
#define MXL   2

#include "iomem.h"
#include "riscv_cpu.h"

#ifdef DUMP_INSN
extern "C" {
#include "dis/riscv-opc.h"
}
#endif

#define __exception __attribute__((warn_unused_result))

typedef uint64_t target_ulong;
typedef int64_t target_long;
#define PR_target_ulong "016" PRIx64

typedef uint64_t mem_uint_t;

#define TLB_SIZE 256

#define CAUSE_MISALIGNED_FETCH    0x0
#define CAUSE_FAULT_FETCH         0x1
#define CAUSE_ILLEGAL_INSTRUCTION 0x2
#define CAUSE_BREAKPOINT          0x3
#define CAUSE_MISALIGNED_LOAD     0x4
#define CAUSE_FAULT_LOAD          0x5
#define CAUSE_MISALIGNED_STORE    0x6
#define CAUSE_FAULT_STORE         0x7
#define CAUSE_USER_ECALL          0x8
#define CAUSE_SUPERVISOR_ECALL    0x9
#define CAUSE_HYPERVISOR_ECALL    0xa
#define CAUSE_MACHINE_ECALL       0xb
#define CAUSE_FETCH_PAGE_FAULT    0xc
#define CAUSE_LOAD_PAGE_FAULT     0xd
#define CAUSE_STORE_PAGE_FAULT    0xf

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
#define MSTATUS_UXL ((uint64_t)3 << MSTATUS_UXL_SHIFT)
#define MSTATUS_SXL ((uint64_t)3 << MSTATUS_SXL_SHIFT)

#define PG_SHIFT 12
#define PG_MASK ((1 << PG_SHIFT) - 1)

typedef struct {
    target_ulong vaddr;
    uintptr_t mem_addend;
} TLBEntry;

struct RISCVCPUState {
    target_ulong pc;
    target_ulong reg[32];

    uint8_t iflags_PRV; // current privilege level
    bool iflags_I; // CPU is idle (waiting for interrupts)
    bool iflags_H; // CPU is permanently halted
    bool iflags_CI; // same as (mie & mip)

    uint8_t mstatus_FS; /* MSTATUS_FS value */

    int pending_exception; /* used during MMU exception handling */
    target_ulong pending_tval;

    /* CSRs */
    uint64_t minstret;
    uint64_t mcycle;

    target_ulong mstatus;
    target_ulong mtvec;
    target_ulong mscratch;
    target_ulong mepc;
    target_ulong mcause;
    target_ulong mtval;
    target_ulong misa;

    uint32_t mie;
    uint32_t mip;
    uint32_t medeleg;
    uint32_t mideleg;
    uint32_t mcounteren;

    target_ulong stvec;
    target_ulong sscratch;
    target_ulong sepc;
    target_ulong scause;
    target_ulong stval;
    uint64_t satp;
    uint32_t scounteren;

    target_ulong ilrsc; /* for atomic LR/SC */

    PhysMemoryMap *mem_map;

    TLBEntry tlb_read[TLB_SIZE];
    TLBEntry tlb_write[TLB_SIZE];
    TLBEntry tlb_code[TLB_SIZE];
};

static int target_read_slow(RISCVCPUState *s, mem_uint_t *pval,
                                      target_ulong addr, int size_log2);
static int target_write_slow(RISCVCPUState *s, target_ulong addr,
                                       mem_uint_t val, int size_log2);

static void fprint_target_ulong(FILE *f, target_ulong a)
{
    fprintf(f, "%" PR_target_ulong, a);
}

static void print_target_ulong(target_ulong a)
{
    fprint_target_ulong(stderr, a);
}

static const char *reg_name[32] = {
"zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
"s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
"a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
"s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
};

void dump_regs(RISCVCPUState *s)
{
    int i, cols;
    const char priv_str[] = "USHM";
    cols = 256 / XLEN;
    fprintf(stderr, "pc = ");
    print_target_ulong(s->pc);
    fprintf(stderr, " ");
    for(i = 1; i < 32; i++) {
        fprintf(stderr, "%-3s= ", reg_name[i]);
        print_target_ulong(s->reg[i]);
        if ((i & (cols - 1)) == (cols - 1))
            fprintf(stderr, "\n");
        else
            fprintf(stderr, " ");
    }
    fprintf(stderr, "priv=%c", priv_str[s->iflags_PRV]);
    fprintf(stderr, " mstatus=");
    print_target_ulong(s->mstatus);
    fprintf(stderr, " cycles=%" PRId64, s->mcycle);
    fprintf(stderr, " insns=%" PRId64, s->minstret);
    fprintf(stderr, "\n");
#if 1
    fprintf(stderr, "mideleg=");
    print_target_ulong(s->mideleg);
    fprintf(stderr, " mie=");
    print_target_ulong(s->mie);
    fprintf(stderr, " mip=");
    print_target_ulong(s->mip);
    fprintf(stderr, "\n");
#endif
}

/* addr must be aligned. Only RAM accesses are supported */
template <typename T>
static inline void phys_write(RISCVCPUState *s, target_ulong addr, T val) {
    PhysMemoryRange *pr = get_phys_mem_range(s->mem_map, addr);
    if (!pr || !pr->is_ram)
        return;
    *(T *)(pr->phys_mem + (uintptr_t)(addr - pr->addr)) = val;
}

template <typename T>
static inline T phys_read(RISCVCPUState *s, target_ulong addr) {
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

/* return 0 if OK, != 0 if exception */
template <typename T>
static inline int target_read(RISCVCPUState *s, T *pval, target_ulong addr)  {
    uint32_t tlb_idx;
    tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (s->tlb_read[tlb_idx].vaddr == (addr & ~(PG_MASK & ~(sizeof(T) - 1)))) {
        *pval = *(T *)(s->tlb_read[tlb_idx].mem_addend + (uintptr_t)addr);
    } else {
        mem_uint_t val;
        int ret;
        ret = target_read_slow(s, &val, addr, size_log2<T>());
        if (ret) return ret;
        *pval = val;
    }
    return 0;
}

template <typename T>
static inline int target_write(RISCVCPUState *s, target_ulong addr, T val) {
    uint32_t tlb_idx;
    tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (s->tlb_write[tlb_idx].vaddr == (addr & ~(PG_MASK & ~(sizeof(T) - 1)))) {
        *(T *)(s->tlb_write[tlb_idx].mem_addend + (uintptr_t)addr) = val;
        return 0;
    } else {
        return target_write_slow(s, addr, val, size_log2<T>());
    }
}

static inline int32_t div32(int32_t a, int32_t b)
{
    if (b == 0) {
        return -1;
    } else if (a == ((int32_t)1 << (32 - 1)) && b == -1) {
        return a;
    } else {
        return a / b;
    }
}

static inline uint32_t divu32(uint32_t a, uint32_t b)
{
    if (b == 0) {
        return -1;
    } else {
        return a / b;
    }
}

static inline int32_t rem32(int32_t a, int32_t b)
{
    if (b == 0) {
        return a;
    } else if (a == ((int32_t)1 << (32 - 1)) && b == -1) {
        return 0;
    } else {
        return a % b;
    }
}

static inline uint32_t remu32(uint32_t a, uint32_t b)
{
    if (b == 0) {
        return a;
    } else {
        return a % b;
    }
}

#define PTE_V_MASK (1 << 0)
#define PTE_U_MASK (1 << 4)
#define PTE_A_MASK (1 << 6)
#define PTE_D_MASK (1 << 7)

#define ACCESS_READ  0
#define ACCESS_WRITE 1
#define ACCESS_CODE  2

/* access = 0: read, 1 = write, 2 = code. Set the exception_pending
   field if necessary. return 0 if OK, -1 if translation error */
static int get_phys_addr(RISCVCPUState *s,
                         target_ulong *ppaddr, target_ulong vaddr,
                         int access)
{
    int mode, levels, pte_bits, pte_idx, pte_mask, pte_size_log2, xwr, priv;
    int need_write, vaddr_shift, i, pte_addr_bits;
    target_ulong pte_addr, pte, vaddr_mask, paddr;

    if ((s->mstatus & MSTATUS_MPRV) && access != ACCESS_CODE) {
        /* use previous priviledge */
        priv = (s->mstatus >> MSTATUS_MPP_SHIFT) & 3;
    } else {
        priv = s->iflags_PRV;
    }

    if (priv == PRV_M) {
        *ppaddr = vaddr;
        return 0;
    }
    mode = (s->satp >> 60) & 0xf;
    /* bare: no translation */
    if (mode == 0) {
        *ppaddr = vaddr;
        return 0;
    }
    /* sv39/sv48 */
    levels = mode - 8 + 3;
    pte_size_log2 = 3;
    vaddr_shift = XLEN - (PG_SHIFT + levels * 9);
    if ((((target_long)vaddr << vaddr_shift) >> vaddr_shift) != (target_long) vaddr)
        return -1;
    pte_addr_bits = 44;
    pte_addr = (s->satp & (((target_ulong)1 << pte_addr_bits) - 1)) << PG_SHIFT;
    pte_bits = 12 - pte_size_log2;
    pte_mask = (1 << pte_bits) - 1;
    for(i = 0; i < levels; i++) {
        vaddr_shift = PG_SHIFT + pte_bits * (levels - 1 - i);
        pte_idx = (vaddr >> vaddr_shift) & pte_mask;
        pte_addr += pte_idx << pte_size_log2;
        pte = phys_read<uint64_t>(s, pte_addr);
        if (!(pte & PTE_V_MASK))
            return -1; /* invalid PTE */
        paddr = (pte >> 10) << PG_SHIFT;
        xwr = (pte >> 1) & 7;
        if (xwr != 0) {
            if (xwr == 2 || xwr == 6)
                return -1;
            /* priviledge check */
            if (priv == PRV_S) {
                if ((pte & PTE_U_MASK) && !(s->mstatus & MSTATUS_SUM))
                    return -1;
            } else {
                if (!(pte & PTE_U_MASK))
                    return -1;
            }
            /* protection check */
            /* MXR allows read access to execute-only pages */
            if (s->mstatus & MSTATUS_MXR)
                xwr |= (xwr >> 2);

            if (((xwr >> access) & 1) == 0)
                return -1;
            vaddr_mask = ((target_ulong)1 << vaddr_shift) - 1;
            if (paddr  & vaddr_mask) /* alignment check */
                return -1;
            need_write = !(pte & PTE_A_MASK) ||
                (!(pte & PTE_D_MASK) && access == ACCESS_WRITE);
            pte |= PTE_A_MASK;
            if (access == ACCESS_WRITE)
                pte |= PTE_D_MASK;
            if (need_write) {
                phys_write<uint64_t>(s, pte_addr, pte);
            }
            *ppaddr = (vaddr & vaddr_mask) | (paddr  & ~vaddr_mask);
            return 0;
        } else {
            pte_addr = paddr;
        }
    }
    return -1;
}

/* return 0 if OK, != 0 if exception */
static int target_read_slow(RISCVCPUState *s, mem_uint_t *pval,
                                      target_ulong addr, int size_log2)
{
    int size, tlb_idx, err, al;
    target_ulong paddr, offset;
    uint8_t *ptr;
    PhysMemoryRange *pr;
    mem_uint_t ret;

    /* first handle unaligned accesses */
    size = 1 << size_log2;
    al = addr & (size - 1);
    if (al != 0) {
        switch(size_log2) {
        case 1:
            {
                uint8_t v0, v1;
                err = target_read<uint8_t>(s, &v0, addr);
                if (err)
                    return err;
                err = target_read<uint8_t>(s, &v1, addr + 1);
                if (err)
                    return err;
                ret = v0 | (v1 << 8);
            }
            break;
        case 2:
            {
                uint32_t v0, v1;
                addr -= al;
                err = target_read<uint32_t>(s, &v0, addr);
                if (err)
                    return err;
                err = target_read<uint32_t>(s, &v1, addr + 4);
                if (err)
                    return err;
                ret = (v0 >> (al * 8)) | (v1 << (32 - al * 8));
            }
            break;
        case 3:
            {
                uint64_t v0, v1;
                addr -= al;
                err = target_read<uint64_t>(s, &v0, addr);
                if (err)
                    return err;
                err = target_read<uint64_t>(s, &v1, addr + 8);
                if (err)
                    return err;
                ret = (v0 >> (al * 8)) | (v1 << (64 - al * 8));
            }
            break;
        default:
            abort();
        }
    } else {
        if (get_phys_addr(s, &paddr, addr, ACCESS_READ)) {
            s->pending_tval = addr;
            s->pending_exception = CAUSE_LOAD_PAGE_FAULT;
            return -1;
        }
        pr = get_phys_mem_range(s->mem_map, paddr);
        if (!pr) {
#ifdef DUMP_INVALID_MEM_ACCESS
            fprintf(stderr, "target_read_slow: invalid physical address 0x");
            print_target_ulong(paddr);
            fprintf(stderr, "\n");
#endif
            s->pending_tval = addr;
            s->pending_exception = CAUSE_FAULT_LOAD;
            return -1;
        } else if (pr->is_ram) {
            tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
            ptr = pr->phys_mem + (uintptr_t)(paddr - pr->addr);
            s->tlb_read[tlb_idx].vaddr = addr & ~PG_MASK;
            s->tlb_read[tlb_idx].mem_addend = (uintptr_t)ptr - addr;
            switch(size_log2) {
            case 0:
                ret = *(uint8_t *)ptr;
                break;
            case 1:
                ret = *(uint16_t *)ptr;
                break;
            case 2:
                ret = *(uint32_t *)ptr;
                break;
            case 3:
                ret = *(uint64_t *)ptr;
                break;
            default:
                abort();
            }
        } else {
            offset = paddr - pr->addr;
            if (((pr->devio_flags >> size_log2) & 1) != 0) {
                ret = pr->read_func(pr->opaque, offset, size_log2);
            }
            else if ((pr->devio_flags & DEVIO_SIZE32) && size_log2 == 3) {
                /* emulate 64 bit access */
                ret = pr->read_func(pr->opaque, offset, 2);
                ret |= (uint64_t)pr->read_func(pr->opaque, offset + 4, 2) << 32;

            }
            else {
#ifdef DUMP_INVALID_MEM_ACCESS
                fprintf(stderr, "unsupported device read access: addr=0x");
                print_target_ulong(paddr);
                fprintf(stderr, " width=%d bits\n", 1 << (3 + size_log2));
#endif
                ret = 0;
            }
        }
    }
    *pval = ret;
    return 0;
}

/* return 0 if OK, != 0 if exception */
static int target_write_slow(RISCVCPUState *s, target_ulong addr,
                                       mem_uint_t val, int size_log2)
{
    int size, i, tlb_idx, err;
    target_ulong paddr, offset;
    uint8_t *ptr;
    PhysMemoryRange *pr;

    /* first handle unaligned accesses */
    size = 1 << size_log2;
    if ((addr & (size - 1)) != 0) {
        /* XXX: should avoid modifying the memory in case of exception */
        for(i = 0; i < size; i++) {
            err = target_write<uint8_t>(s, addr + i, (val >> (8 * i)) & 0xff);
            if (err)
                return err;
        }
    } else {
        if (get_phys_addr(s, &paddr, addr, ACCESS_WRITE)) {
            s->pending_tval = addr;
            s->pending_exception = CAUSE_STORE_PAGE_FAULT;
            return -1;
        }
        pr = get_phys_mem_range(s->mem_map, paddr);
        if (!pr) {
            /*??D should raise exception here */
#ifdef DUMP_INVALID_MEM_ACCESS
            fprintf(stderr, "target_write_slow: invalid physical address 0x");
            print_target_ulong(paddr);
            fprintf(stderr, "\n");
#endif
        } else if (pr->is_ram) {
            phys_mem_set_dirty_bit(pr, paddr - pr->addr);
            tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
            ptr = pr->phys_mem + (uintptr_t)(paddr - pr->addr);
            s->tlb_write[tlb_idx].vaddr = addr & ~PG_MASK;
            s->tlb_write[tlb_idx].mem_addend = (uintptr_t)ptr - addr;
            switch(size_log2) {
            case 0:
                *(uint8_t *)ptr = val;
                break;
            case 1:
                *(uint16_t *)ptr = val;
                break;
            case 2:
                *(uint32_t *)ptr = val;
                break;
            case 3:
                *(uint64_t *)ptr = val;
                break;
            default:
                abort();
            }
        } else {
            offset = paddr - pr->addr;
            if (((pr->devio_flags >> size_log2) & 1) != 0) {
                pr->write_func(pr->opaque, offset, val, size_log2);
            }
            else if ((pr->devio_flags & DEVIO_SIZE32) && size_log2 == 3) {
                /* emulate 64 bit access */
                pr->write_func(pr->opaque, offset,
                               val & 0xffffffff, 2);
                pr->write_func(pr->opaque, offset + 4,
                               (val >> 32) & 0xffffffff, 2);
            }
            else {
#ifdef DUMP_INVALID_MEM_ACCESS
                fprintf(stderr, "unsupported device write access: addr=0x");
                print_target_ulong(paddr);
                fprintf(stderr, " width=%d bits\n", 1 << (3 + size_log2));
#endif
            }
        }
    }
    return 0;
}

static inline uint32_t get_insn32(uint8_t *ptr)
{
    return *((uint32_t*) ptr);
}

/* return 0 if OK, != 0 if exception */
static __exception int target_read_insn_slow(RISCVCPUState *s,
                                                       uintptr_t *pmem_addend,
                                                       target_ulong addr)
{
    int tlb_idx;
    target_ulong paddr;
    uint8_t *ptr;
    PhysMemoryRange *pr;

    if (get_phys_addr(s, &paddr, addr, ACCESS_CODE)) {
        s->pending_tval = addr;
        s->pending_exception = CAUSE_FETCH_PAGE_FAULT;
        return -1;
    }
    pr = get_phys_mem_range(s->mem_map, paddr);
    if (!pr || !pr->is_ram) {
        /* XXX: we only access to execute code from RAM */
        s->pending_tval = addr;
        s->pending_exception = CAUSE_FAULT_FETCH;
        return -1;
    }
    tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    ptr = pr->phys_mem + (uintptr_t)(paddr - pr->addr);
    s->tlb_code[tlb_idx].vaddr = addr & ~PG_MASK;
    s->tlb_code[tlb_idx].mem_addend = (uintptr_t)ptr - addr;
    *pmem_addend = s->tlb_code[tlb_idx].mem_addend;
    return 0;
}

static void tlb_init(RISCVCPUState *s)
{
    int i;

    for(i = 0; i < TLB_SIZE; i++) {
        s->tlb_read[i].vaddr = -1;
        s->tlb_write[i].vaddr = -1;
        s->tlb_code[i].vaddr = -1;
    }
}

static void tlb_flush_all(RISCVCPUState *s)
{
    tlb_init(s);
}

static void tlb_flush_vaddr(RISCVCPUState *s, target_ulong vaddr)
{
    (void) vaddr;
    tlb_flush_all(s);
}

/* XXX: inefficient but not critical as long as it is seldom used */
void riscv_cpu_flush_tlb_write_range_ram(RISCVCPUState *s,
                                         uint8_t *ram_ptr, size_t ram_size)
{
    uint8_t *ptr, *ram_end;
    int i;

    ram_end = ram_ptr + ram_size;
    for(i = 0; i < TLB_SIZE; i++) {
        if (s->tlb_write[i].vaddr != (target_ulong) -1) {
            ptr = (uint8_t *)(s->tlb_write[i].mem_addend +
                              (uintptr_t)s->tlb_write[i].vaddr);
            if (ptr >= ram_ptr && ptr < ram_end) {
                s->tlb_write[i].vaddr = -1;
            }
        }
    }
}


#define SSTATUS_MASK (MSTATUS_UIE | MSTATUS_SIE |       \
                      MSTATUS_UPIE | MSTATUS_SPIE |     \
                      MSTATUS_SPP | \
                      MSTATUS_FS | MSTATUS_XS | \
                      MSTATUS_SUM | MSTATUS_MXR | MSTATUS_UXL)

#define MSTATUS_MASK (MSTATUS_UIE | MSTATUS_SIE | MSTATUS_MIE |      \
                      MSTATUS_UPIE | MSTATUS_SPIE | MSTATUS_MPIE |    \
                      MSTATUS_SPP | MSTATUS_MPP | \
                      MSTATUS_FS | \
                      MSTATUS_MPRV | MSTATUS_SUM | MSTATUS_MXR |\
                      MSTATUS_TVM | MSTATUS_TW | MSTATUS_TSR )
/* cycle and insn counters */
#define COUNTEREN_MASK ((1 << 0) | (1 << 2))

/* return the complete mstatus */
static target_ulong get_mstatus(RISCVCPUState *s, target_ulong mask)
{
    target_ulong val = s->mstatus | (s->mstatus_FS << MSTATUS_FS_SHIFT);
    val &= mask;
    bool sd = ((val & MSTATUS_FS) == MSTATUS_FS) |
        ((val & MSTATUS_XS) == MSTATUS_XS);
    if (sd)
        val |= (target_ulong)1 << (XLEN - 1);
    return val;
}

static void set_mstatus(RISCVCPUState *s, target_ulong val)
{

    /* flush the TLBs if change of MMU config */
    target_ulong mod = s->mstatus ^ val;
    if ((mod & (MSTATUS_MPRV | MSTATUS_SUM | MSTATUS_MXR)) != 0 ||
        ((s->mstatus & MSTATUS_MPRV) && (mod & MSTATUS_MPP) != 0)) {
        tlb_flush_all(s);
    }
    s->mstatus_FS = (val >> MSTATUS_FS_SHIFT) & 3;
    target_ulong mask = MSTATUS_MASK & ~MSTATUS_FS;
    s->mstatus = (s->mstatus & ~mask) | (val & mask);
}

enum class CSR {
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

static inline int csr_is_read_only(CSR csr) {
    //??D 0xd00 and 0xf00 are also read-only, but we don't need to detect here
    return ((static_cast<int>(csr) & 0xc00) == 0xc00);
}

static inline int csr_priv(CSR csr) {
    return ((static_cast<int>(csr) >> 8) & 3);
}

/* return -1 if invalid CSR. 0 if OK. 'will_write' indicate that the
   csr will be written after (used for CSR access check) */
static int csr_read(RISCVCPUState *s, target_ulong *pval, CSR csr, bool will_write)
{
    target_ulong val;

    if (csr_is_read_only(csr) && will_write) return -1;
    if (csr_priv(csr) > s->iflags_PRV) return -1;

    switch(csr) {
    case CSR::ucycle:
        {
            uint32_t counteren;
            if (s->iflags_PRV < PRV_M) {
                if (s->iflags_PRV < PRV_S)
                    counteren = s->scounteren;
                else
                    counteren = s->mcounteren;
                if (((counteren >> (static_cast<int>(csr) & 0x1f)) & 1) == 0)
                    goto invalid_csr;
            }
        }
        val = (int64_t)s->mcycle;
        break;
    case CSR::uinstret:
        {
            uint32_t counteren;
            if (s->iflags_PRV < PRV_M) {
                if (s->iflags_PRV < PRV_S)
                    counteren = s->scounteren;
                else
                    counteren = s->mcounteren;
                if (((counteren >> (static_cast<int>(csr) & 0x1f)) & 1) == 0)
                    goto invalid_csr;
            }
        }
        val = (int64_t)s->minstret;
        break;
    case CSR::ucycleh:
        goto invalid_csr;
        break;
    case CSR::uinstreth:
        goto invalid_csr;
        break;
    case CSR::sstatus:
        val = get_mstatus(s, SSTATUS_MASK);
        break;
    case CSR::sie:
        val = s->mie & s->mideleg;
        break;
    case CSR::stvec:
        val = s->stvec;
        break;
    case CSR::scounteren:
        val = s->scounteren;
        break;
    case CSR::sscratch:
        val = s->sscratch;
        break;
    case CSR::sepc:
        val = s->sepc;
        break;
    case CSR::scause:
        val = s->scause;
        break;
    case CSR::stval:
        val = s->stval;
        break;
    case CSR::sip:
        val = s->mip & s->mideleg;
        break;
    case CSR::satp:
        if (s->iflags_PRV == PRV_S && s->mstatus & MSTATUS_TVM)
            return -1;
        val = s->satp;
        break;
    case CSR::mstatus:
        val = get_mstatus(s, (target_ulong)-1);
        break;
    case CSR::misa:
        val = s->misa;
        break;
    case CSR::medeleg:
        val = s->medeleg;
        break;
    case CSR::mideleg:
        val = s->mideleg;
        break;
    case CSR::mie:
        val = s->mie;
        break;
    case CSR::mtvec:
        val = s->mtvec;
        break;
    case CSR::mcounteren:
        val = s->mcounteren;
        break;
    case CSR::mscratch:
        val = s->mscratch;
        break;
    case CSR::mepc:
        val = s->mepc;
        break;
    case CSR::mcause:
        val = s->mcause;
        break;
    case CSR::mtval:
        val = s->mtval;
        break;
    case CSR::mip:
        val = s->mip;
        break;
    case CSR::mcycle:
        val = (int64_t)s->mcycle;
        break;
    case CSR::minstret:
        val = (int64_t)s->minstret;
        break;
    case CSR::mcycleh:
        goto invalid_csr;
        break;
    case CSR::minstreth:
        goto invalid_csr;
        break;
    case CSR::tselect: /* ignore all */
    case CSR::tdata1:
    case CSR::tdata2:
    case CSR::tdata3:
        val = 0;
        break;
    case CSR::mvendorid:
        val = 0;
        break;
    case CSR::marchid:
        val = 0;
        break;
    case CSR::mimplid:
        val = 0;
        break;
    case CSR::mhartid:
        val = 0;
        break;
    default:
    invalid_csr:
#ifdef DUMP_INVALID_CSR
        /* the 'time' counter is usually emulated */
        //??D but we don't emulate it, so maybe we should handle it right here
        if (csr != CSR::utime) {
            fprintf(stderr, "csr_read: invalid CSR=0x%x\n", static_cast<int>(csr));
        }
#endif
        *pval = 0;
        return -1;
    }
    *pval = val;
    return 0;
}

// return -1 if invalid CSR, 0 if OK, 2 if TLBs have been flushed.
static int csr_write(RISCVCPUState *s, CSR csr, target_ulong val)
{
    target_ulong mask;

#if defined(DUMP_CSR)
    fprintf(stderr, "csr_write: csr=0x%03x val=0x", static_cast<int>(csr));
    print_target_ulong(val);
    fprintf(stderr, "\n");
#endif
    switch(csr) {
    case CSR::sstatus:
        set_mstatus(s, (s->mstatus & ~SSTATUS_MASK) | (val & SSTATUS_MASK));
        break;
    case CSR::sie:
        mask = s->mideleg;
        s->mie = (s->mie & ~mask) | (val & mask);
        break;
    case CSR::stvec:
        s->stvec = val & ~3;
        break;
    case CSR::scounteren:
        s->scounteren = val & COUNTEREN_MASK;
        break;
    case CSR::sscratch:
        s->sscratch = val;
        break;
    case CSR::sepc:
        s->sepc = val & ~1;
        break;
    case CSR::scause:
        s->scause = val;
        break;
    case CSR::stval:
        s->stval = val;
        break;
    case CSR::sip:
        mask = s->mideleg;
        s->mip = (s->mip & ~mask) | (val & mask);
        break;
    case CSR::satp:
        /* no ASID implemented */
        {
            int mode, new_mode;
            mode = s->satp >> 60;
            new_mode = (val >> 60) & 0xf;
            if (new_mode == 0 || (new_mode >= 8 && new_mode <= 9))
                mode = new_mode;
            s->satp = (val & (((uint64_t)1 << 44) - 1)) |
                ((uint64_t)mode << 60);
        }
        tlb_flush_all(s);
        return 2;

    case CSR::mstatus:
        set_mstatus(s, val);
        break;
    case CSR::misa:
        /* ignore writes to misa */
        break;
    case CSR::medeleg:
        mask = (1 << (CAUSE_STORE_PAGE_FAULT + 1)) - 1;
        s->medeleg = (s->medeleg & ~mask) | (val & mask);
        break;
    case CSR::mideleg:
        mask = MIP_SSIP | MIP_STIP | MIP_SEIP;
        s->mideleg = (s->mideleg & ~mask) | (val & mask);
        break;
    case CSR::mie:
        mask = MIP_MSIP | MIP_MTIP | MIP_SSIP | MIP_STIP | MIP_SEIP;
        s->mie = (s->mie & ~mask) | (val & mask);
        break;
    case CSR::mtvec:
        /* ??D no support for vectored iterrupts */
        s->mtvec = val & ~3;
        break;
    case CSR::mcounteren:
        s->mcounteren = val & COUNTEREN_MASK;
        break;
    case CSR::mscratch:
        s->mscratch = val;
        break;
    case CSR::mepc:
        s->mepc = val & ~1;
        break;
    case CSR::mcause:
        s->mcause = val;
        break;
    case CSR::mtval:
        s->mtval = val;
        break;
    case CSR::mip:
        mask = MIP_SSIP | MIP_STIP;
        s->mip = (s->mip & ~mask) | (val & mask);
        break;
    case CSR::tselect: /* ignore all */
    case CSR::tdata1: /* tdata1 */
    case CSR::tdata2: /* tdata2 */
    case CSR::tdata3: /* tdata3 */
        break;

    default:
#ifdef DUMP_INVALID_CSR
        fprintf(stderr, "csr_write: invalid CSR=0x%x\n", static_cast<int>(csr));
#endif
        return -1;
    }
    return 0;
}

static void set_priv(RISCVCPUState *s, int priv)
{
    if (s->iflags_PRV != priv) {
        tlb_flush_all(s);
        s->iflags_PRV = priv;
        s->ilrsc = 0;
    }
}

static void raise_exception(RISCVCPUState *s, target_ulong cause,
    target_ulong tval)
{
#if defined(DUMP_EXCEPTIONS) || defined(DUMP_MMU_EXCEPTIONS) || defined(DUMP_INTERRUPTS)
    {
        int flag;
        flag = 0;
#ifdef DUMP_MMU_EXCEPTIONS
        if (cause == CAUSE_FAULT_FETCH ||
            cause == CAUSE_FAULT_LOAD ||
            cause == CAUSE_FAULT_STORE ||
            cause == CAUSE_FETCH_PAGE_FAULT ||
            cause == CAUSE_LOAD_PAGE_FAULT ||
            cause == CAUSE_STORE_PAGE_FAULT)
            flag = 1;
#endif
#ifdef DUMP_INTERRUPTS
        flag |= (cause & CAUSE_INTERRUPT) != 0;
#endif
#ifdef DUMP_EXCEPTIONS
        flag |= (cause & CAUSE_INTERRUPT) == 0;
        if (cause == CAUSE_SUPERVISOR_ECALL)
            flag = 0;
#endif
        if (flag) {
            fprintf(stderr, "raise_exception: cause=0x");
            print_target_ulong(cause);
            fprintf(stderr, " tval=0x");
            print_target_ulong(tval);
            fprintf(stderr, "\n");
            dump_regs(s);
        }
    }
#endif

    // Check if exception should be delegated to supervisor privilege
    // For each interrupt or exception number, there is a bit at mideleg
    // or medeleg saying if it should be delegated
    bool deleg;
    if (s->iflags_PRV <= PRV_S) {
        if (cause & CAUSE_INTERRUPT)
            // Clear the CAUSE_INTERRUPT bit before shifting
            deleg = (s->mideleg >> (cause & (XLEN - 1))) & 1;
        else
            deleg = (s->medeleg >> cause) & 1;
    } else {
        deleg = 0;
    }

    if (deleg) {
        s->scause = cause;
        s->sepc = s->pc;
        s->stval = tval;
        s->mstatus = (s->mstatus & ~MSTATUS_SPIE) |
            (((s->mstatus >> s->iflags_PRV) & 1) << MSTATUS_SPIE_SHIFT);
        s->mstatus = (s->mstatus & ~MSTATUS_SPP) |
            (s->iflags_PRV << MSTATUS_SPP_SHIFT);
        s->mstatus &= ~MSTATUS_SIE;
        set_priv(s, PRV_S);
        s->pc = s->stvec;
    } else {
        s->mcause = cause;
        s->mepc = s->pc;
        s->mtval = tval;
        s->mstatus = (s->mstatus & ~MSTATUS_MPIE) |
            (((s->mstatus >> s->iflags_PRV) & 1) << MSTATUS_MPIE_SHIFT);
        s->mstatus = (s->mstatus & ~MSTATUS_MPP) |
            (s->iflags_PRV << MSTATUS_MPP_SHIFT);
        s->mstatus &= ~MSTATUS_MIE;
        set_priv(s, PRV_M);
        s->pc = s->mtvec;
    }
}

static void handle_sret(RISCVCPUState *s)
{
    int spp, spie;
    spp = (s->mstatus >> MSTATUS_SPP_SHIFT) & 1;
    /* set the IE state to previous IE state */
    spie = (s->mstatus >> MSTATUS_SPIE_SHIFT) & 1;
    s->mstatus = (s->mstatus & ~(1 << MSTATUS_SIE_SHIFT)) |
        (spie << MSTATUS_SIE_SHIFT);
    /* set SPIE to 1 */
    s->mstatus |= MSTATUS_SPIE;
    /* set SPP to U */
    s->mstatus &= ~MSTATUS_SPP;
    set_priv(s, spp);
    s->pc = s->sepc;
}

static void handle_mret(RISCVCPUState *s)
{
    int mpp, mpie;
    mpp = (s->mstatus >> MSTATUS_MPP_SHIFT) & 3;
    /* set the IE state to previous IE state */
    mpie = (s->mstatus >> MSTATUS_MPIE_SHIFT) & 1;
    s->mstatus = (s->mstatus & ~(1 << MSTATUS_MIE_SHIFT)) |
        (mpie << MSTATUS_MIE_SHIFT);
    /* set MPIE to 1 */
    s->mstatus |= MSTATUS_MPIE;
    /* set MPP to U */
    s->mstatus &= ~MSTATUS_MPP;
    set_priv(s, mpp);
    s->pc = s->mepc;
}

static inline uint32_t get_pending_irq_mask(RISCVCPUState *s)
{
    uint32_t pending_ints, enabled_ints;

    pending_ints = s->mip & s->mie;
    if (pending_ints == 0)
        return 0;

    enabled_ints = 0;
    switch(s->iflags_PRV) {
    case PRV_M:
        if (s->mstatus & MSTATUS_MIE)
            enabled_ints = ~s->mideleg;
        break;
    case PRV_S:
        // Interrupts not set in mideleg are machine-mode
        // and cannot be masked by supervisor mode
        enabled_ints = ~s->mideleg;
        if (s->mstatus & MSTATUS_SIE)
            enabled_ints |= s->mideleg;
        break;
    default:
    case PRV_U:
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

static int raise_interrupt(RISCVCPUState *s)
{
    uint32_t mask = get_pending_irq_mask(s);
    if (mask == 0) return 0;
    target_ulong irq_num = ilog2(mask);
    raise_exception(s, irq_num | CAUSE_INTERRUPT, 0);
    return -1;
}

static inline int64_t div64(int64_t a, int64_t b)
{
    if (b == 0) {
        return -1;
    } else if (a == ((int64_t)1 << (XLEN - 1)) && b == -1) {
        return a;
    } else {
        return a / b;
    }
}

static inline uint64_t divu64(uint64_t a, uint64_t b)
{
    if (b == 0) {
        return -1;
    } else {
        return a / b;
    }
}

static inline int64_t rem64(int64_t a, int64_t b)
{
    if (b == 0) {
        return a;
    } else if (a == ((int64_t)1 << (XLEN - 1)) && b == -1) {
        return 0;
    } else {
        return a % b;
    }
}

static inline uint64_t remu64(uint64_t a, uint64_t b)
{
    if (b == 0) {
        return a;
    } else {
        return a % b;
    }
}

static inline uint64_t mulh64(int64_t a, int64_t b)
{
    return ((int128_t)a * (int128_t)b) >> 64;
}

static inline uint64_t mulhsu64(int64_t a, uint64_t b)
{
    return ((int128_t)a * (int128_t)b) >> 64;
}

static inline uint64_t mulhu64(uint64_t a, uint64_t b)
{
    return ((int128_t)a * (int128_t)b) >> 64;
}

#define GET_PC() (target_ulong)((uintptr_t)code_ptr + code_to_pc_addend)
#define GET_INSN_COUNTER() (minstret_end - n_cycles)
#define GET_CYCLE_COUNTER() (mcycle_end - n_cycles)

#define NEXT_INSN code_ptr += 4; break

#define CHECK_JUMP do { \
    if (s->pc & 3) { \
        s->pending_exception = CAUSE_MISALIGNED_FETCH; \
        s->pending_tval = s->pc; \
        goto exception; \
    } \
} while (0)

#define JUMP_INSN do {   \
    code_ptr = NULL;           \
    code_end = NULL;           \
    code_to_pc_addend = s->pc; \
    goto jump_insn;            \
} while (0)

enum class Atomic {
    lr      = 0x02,
    sc      = 0x03,
    amoswap = 0x01,
    amoadd  = 0x00,
    amoxor  = 0x04,
    amoand  = 0x0c,
    amoor   = 0x08,
    amomin  = 0x10,
    amomax  = 0x14,
    amominu = 0x18,
    amomaxu = 0x1c
};

static void riscv_cpu_interpret(RISCVCPUState *s, uint64_t mcycle_end) {
    uint32_t opcode, insn, rd, rs1, rs2, funct3;
    int32_t imm, cond, err;
    target_ulong addr, val, val2;
    uint64_t minstret_end;
    uint64_t n_cycles;
    uint8_t *code_ptr, *code_end;
    target_ulong code_to_pc_addend;

    if (s->mcycle >= mcycle_end)
        return;

    n_cycles = mcycle_end - s->mcycle;

    minstret_end = s->minstret + n_cycles;

    s->pending_exception = -1;
    n_cycles++;
    /* Note: we assume NULL is represented as a zero number */
    code_ptr = NULL;
    code_end = NULL;
    code_to_pc_addend = s->pc;

    for(;;) {

#if 0
    fprintf(stderr, " mstatus=");
    print_target_ulong(s->mstatus);
    fprintf(stderr, "\n");
#endif

        if (!--n_cycles || s->iflags_H) {
            s->pc = GET_PC();
            goto the_end;
        }

        if (code_ptr >= code_end) {
            uint32_t tlb_idx;
            uintptr_t mem_addend;
            target_ulong addr;

            s->pc = GET_PC();

            /* check pending interrupts */
            if ((s->mip & s->mie) != 0) {
                if (raise_interrupt(s)) {
                    goto the_end;
                }
            }

            addr = s->pc;
            tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
            if (s->tlb_code[tlb_idx].vaddr == (addr & ~PG_MASK)) {
                /* TLB match */
                mem_addend = s->tlb_code[tlb_idx].mem_addend;
            } else {
                if (target_read_insn_slow(s, &mem_addend, addr))
                    goto mmu_exception;
            }
            code_ptr = (uint8_t *)(mem_addend + (uintptr_t)addr);
            code_end = (uint8_t *)(mem_addend +
                                   (uintptr_t)((addr & ~PG_MASK) + PG_MASK - 1));
            code_to_pc_addend = addr - (uintptr_t)code_ptr;
        }

        insn = get_insn32(code_ptr);
#ifdef DUMP_INSN
        {
            target_ulong pc = GET_PC();
            target_ulong ppc;
            if (!get_phys_addr(s, &ppc, pc, ACCESS_CODE)) {
                fprintf(stderr, "p    %08" PRIx64, ppc);
            } else {
                ppc = pc;
                fprintf(stderr, "v    %08" PRIx64, ppc);
            }
            fprintf(stderr, ":   %08" PRIx32 "   ", insn);
            fprintf(stderr, "\n");
        }
#endif
        opcode = insn & 0x7f;
        rd = (insn >> 7) & 0x1f;
        rs1 = (insn >> 15) & 0x1f;
        rs2 = (insn >> 20) & 0x1f;
        switch(opcode) {
        case 0x37: /* lui */
            if (rd != 0)
                s->reg[rd] = (int32_t)(insn & 0xfffff000);
            NEXT_INSN;
        case 0x17: /* auipc */
            if (rd != 0)
                s->reg[rd] = (int64_t)(GET_PC() + (int32_t)(insn & 0xfffff000));
            NEXT_INSN;
        case 0x6f: /* jal */
            imm = ((insn >> (31 - 20)) & (1 << 20)) |
                ((insn >> (21 - 1)) & 0x7fe) |
                ((insn >> (20 - 11)) & (1 << 11)) |
                (insn & 0xff000);
            imm = (imm << 11) >> 11;
            s->pc = (int64_t)(GET_PC() + imm);
            CHECK_JUMP;
            if (rd != 0)
                s->reg[rd] = GET_PC() + 4;
            JUMP_INSN;
        case 0x67: /* jalr */
            imm = (int32_t)insn >> 20;
            val = GET_PC() + 4;
            s->pc = (int64_t)(s->reg[rs1] + imm) & ~1;
            CHECK_JUMP;
            if (rd != 0)
                s->reg[rd] = val;
            JUMP_INSN;
        case 0x63:
            funct3 = (insn >> 12) & 7;
            switch(funct3 >> 1) {
            case 0: /* beq/bne */
                cond = (s->reg[rs1] == s->reg[rs2]);
                break;
            case 2: /* blt/bge */
                cond = ((target_long)s->reg[rs1] < (target_long)s->reg[rs2]);
                break;
            case 3: /* bltu/bgeu */
                cond = (s->reg[rs1] < s->reg[rs2]);
                break;
            default:
                goto illegal_insn;
            }
            cond ^= (funct3 & 1);
            if (cond) {
                imm = ((insn >> (31 - 12)) & (1 << 12)) |
                    ((insn >> (25 - 5)) & 0x7e0) |
                    ((insn >> (8 - 1)) & 0x1e) |
                    ((insn << (11 - 7)) & (1 << 11));
                imm = (imm << 19) >> 19;
                s->pc = (int64_t)(GET_PC() + imm);
                CHECK_JUMP;
                JUMP_INSN;
            }
            NEXT_INSN;
        case 0x03: /* load */
            funct3 = (insn >> 12) & 7;
            imm = (int32_t)insn >> 20;
            addr = s->reg[rs1] + imm;
            switch(funct3) {
            case 0: /* lb */
                {
                    uint8_t rval;
                    if (target_read<uint8_t>(s, &rval, addr))
                        goto mmu_exception;
                    val = (int8_t)rval;
                }
                break;
            case 1: /* lh */
                {
                    uint16_t rval;
                    if (target_read<uint16_t>(s, &rval, addr))
                        goto mmu_exception;
                    val = (int16_t)rval;
                }
                break;
            case 2: /* lw */
                {
                    uint32_t rval;
                    if (target_read<uint32_t>(s, &rval, addr))
                        goto mmu_exception;
                    val = (int32_t)rval;
                }
                break;
            case 4: /* lbu */
                {
                    uint8_t rval;
                    if (target_read<uint8_t>(s, &rval, addr))
                        goto mmu_exception;
                    val = rval;
                }
                break;
            case 5: /* lhu */
                {
                    uint16_t rval;
                    if (target_read<uint16_t>(s, &rval, addr))
                        goto mmu_exception;
                    val = rval;
                }
                break;
            case 3: /* ld */
                {
                    uint64_t rval;
                    if (target_read<uint64_t>(s, &rval, addr))
                        goto mmu_exception;
                    val = (int64_t)rval;
                }
                break;
            case 6: /* lwu */
                {
                    uint32_t rval;
                    if (target_read<uint32_t>(s, &rval, addr))
                        goto mmu_exception;
                    val = rval;
                }
                break;
            default:
                goto illegal_insn;
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
        case 0x23: /* store */
            funct3 = (insn >> 12) & 7;
            imm = rd | ((insn >> (25 - 5)) & 0xfe0);
            imm = (imm << 20) >> 20;
            addr = s->reg[rs1] + imm;
            val = s->reg[rs2];
            switch(funct3) {
            case 0: /* sb */
                if (target_write<uint8_t>(s, addr, val))
                    goto mmu_exception;
                break;
            case 1: /* sh */
                if (target_write<uint16_t>(s, addr, val))
                    goto mmu_exception;
                break;
            case 2: /* sw */
                if (target_write<uint32_t>(s, addr, val))
                    goto mmu_exception;
                break;
            case 3: /* sd */
                if (target_write<uint64_t>(s, addr, val))
                    goto mmu_exception;
                break;
            default:
                goto illegal_insn;
            }
            NEXT_INSN;
        case 0x13:
            funct3 = (insn >> 12) & 7;
            imm = (int32_t)insn >> 20;
            switch(funct3) {
            case 0: /* addi */
                val = (int64_t)(s->reg[rs1] + imm);
                break;
            case 1: /* slli */
                if ((imm & ~(XLEN - 1)) != 0)
                    goto illegal_insn;
                val = (int64_t)(s->reg[rs1] << (imm & (XLEN - 1)));
                break;
            case 2: /* slti */
                val = (target_long)s->reg[rs1] < (target_long)imm;
                break;
            case 3: /* sltiu */
                val = s->reg[rs1] < (target_ulong)imm;
                break;
            case 4: /* xori */
                val = s->reg[rs1] ^ imm;
                break;
            case 5: /* srli/srai */
                if ((imm & ~((XLEN - 1) | 0x400)) != 0)
                    goto illegal_insn;
                if (imm & 0x400)
                    val = (int64_t)s->reg[rs1] >> (imm & (XLEN - 1));
                else
                    val = (int64_t)((uint64_t)s->reg[rs1] >> (imm & (XLEN - 1)));
                break;
            case 6: /* ori */
                val = s->reg[rs1] | imm;
                break;
            default:
            case 7: /* andi */
                val = s->reg[rs1] & imm;
                break;
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
        case 0x1b:/* OP-IMM-32 */
            funct3 = (insn >> 12) & 7;
            imm = (int32_t)insn >> 20;
            val = s->reg[rs1];
            switch(funct3) {
            case 0: /* addiw */
                val = (int32_t)(val + imm);
                break;
            case 1: /* slliw */
                if ((imm & ~31) != 0)
                    goto illegal_insn;
                val = (int32_t)(val << (imm & 31));
                break;
            case 5: /* srliw/sraiw */
                if ((imm & ~(31 | 0x400)) != 0)
                    goto illegal_insn;
                if (imm & 0x400)
                    val = (int32_t)val >> (imm & 31);
                else
                    val = (int32_t)((uint32_t)val >> (imm & 31));
                break;
            default:
                goto illegal_insn;
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
        case 0x33:
            imm = insn >> 25;
            val = s->reg[rs1];
            val2 = s->reg[rs2];
            if (imm == 1) {
                funct3 = (insn >> 12) & 7;
                switch(funct3) {
                case 0: /* mul */
                    val = (int64_t)((int64_t)val * (int64_t)val2);
                    break;
                case 1: /* mulh */
                    val = (int64_t)mulh64(val, val2);
                    break;
                case 2:/* mulhsu */
                    val = (int64_t)mulhsu64(val, val2);
                    break;
                case 3:/* mulhu */
                    val = (int64_t)mulhu64(val, val2);
                    break;
                case 4:/* div */
                    val = div64(val, val2);
                    break;
                case 5:/* divu */
                    val = (int64_t)divu64(val, val2);
                    break;
                case 6:/* rem */
                    val = rem64(val, val2);
                    break;
                case 7:/* remu */
                    val = (int64_t)remu64(val, val2);
                    break;
                default:
                    goto illegal_insn;
                }
            } else {
                if (imm & ~0x20)
                    goto illegal_insn;
                funct3 = ((insn >> 12) & 7) | ((insn >> (30 - 3)) & (1 << 3));
                switch(funct3) {
                case 0: /* add */
                    val = (int64_t)(val + val2);
                    break;
                case 0 | 8: /* sub */
                    val = (int64_t)(val - val2);
                    break;
                case 1: /* sll */
                    val = (int64_t)(val << (val2 & (XLEN - 1)));
                    break;
                case 2: /* slt */
                    val = (target_long)val < (target_long)val2;
                    break;
                case 3: /* sltu */
                    val = val < val2;
                    break;
                case 4: /* xor */
                    val = val ^ val2;
                    break;
                case 5: /* srl */
                    val = (int64_t)((uint64_t)val >> (val2 & (XLEN - 1)));
                    break;
                case 5 | 8: /* sra */
                    val = (int64_t)val >> (val2 & (XLEN - 1));
                    break;
                case 6: /* or */
                    val = val | val2;
                    break;
                case 7: /* and */
                    val = val & val2;
                    break;
                default:
                    goto illegal_insn;
                }
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
        case 0x3b: /* OP-32 */
            imm = insn >> 25;
            val = s->reg[rs1];
            val2 = s->reg[rs2];
            if (imm == 1) {
                funct3 = (insn >> 12) & 7;
                switch(funct3) {
                case 0: /* mulw */
                    val = (int32_t)((int32_t)val * (int32_t)val2);
                    break;
                case 4:/* divw */
                    val = div32(val, val2);
                    break;
                case 5:/* divuw */
                    val = (int32_t)divu32(val, val2);
                    break;
                case 6:/* remw */
                    val = rem32(val, val2);
                    break;
                case 7:/* remuw */
                    val = (int32_t)remu32(val, val2);
                    break;
                default:
                    goto illegal_insn;
                }
            } else {
                if (imm & ~0x20)
                    goto illegal_insn;
                funct3 = ((insn >> 12) & 7) | ((insn >> (30 - 3)) & (1 << 3));
                switch(funct3) {
                case 0: /* addw */
                    val = (int32_t)(val + val2);
                    break;
                case 0 | 8: /* subw */
                    val = (int32_t)(val - val2);
                    break;
                case 1: /* sllw */
                    val = (int32_t)((uint32_t)val << (val2 & 31));
                    break;
                case 5: /* srlw */
                    val = (int32_t)((uint32_t)val >> (val2 & 31));
                    break;
                case 5 | 8: /* sraw */
                    val = (int32_t)val >> (val2 & 31);
                    break;
                default:
                    goto illegal_insn;
                }
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
        case 0x73:
            funct3 = (insn >> 12) & 7;
            imm = insn >> 20;
            if (funct3 & 4)
                val = rs1;
            else
                val = s->reg[rs1];
            funct3 &= 3;
            switch(funct3) {
            case 1: /* csrrw */
                s->minstret = GET_INSN_COUNTER();
                s->mcycle = GET_CYCLE_COUNTER();
                if (csr_read(s, &val2, static_cast<CSR>(imm), true))
                    goto illegal_insn;
                val2 = (int64_t)val2;
                err = csr_write(s, static_cast<CSR>(imm), val);
                if (err < 0)
                    goto illegal_insn;
                if (rd != 0)
                    s->reg[rd] = val2;
                if (err > 0) {
                    s->pc = GET_PC() + 4;
                    if (err == 2)
                        JUMP_INSN;
                    else
                        goto done_interp;
                }
                break;
            case 2: /* csrrs */
            case 3: /* csrrc */
                s->minstret = GET_INSN_COUNTER();
                s->mcycle = GET_CYCLE_COUNTER();
                if (csr_read(s, &val2, static_cast<CSR>(imm), (rs1 != 0)))
                    goto illegal_insn;
                val2 = (int64_t)val2;
                if (rs1 != 0) {
                    if (funct3 == 2)
                        val = val2 | val;
                    else
                        val = val2 & ~val;
                    err = csr_write(s, static_cast<CSR>(imm), val);
                    if (err < 0)
                        goto illegal_insn;
                } else {
                    err = 0;
                }
                if (rd != 0)
                    s->reg[rd] = val2;
                if (err > 0) {
                    s->pc = GET_PC() + 4;
                    if (err == 2)
                        JUMP_INSN;
                    else
                        goto done_interp;
                }
                break;
            case 0:
                switch(imm) {
                case 0x000: /* ecall */
                    if (insn & 0x000fff80)
                        goto illegal_insn;
                    s->pending_exception = CAUSE_USER_ECALL + s->iflags_PRV;
                    goto exception;
                case 0x001: /* ebreak */
                    if (insn & 0x000fff80)
                        goto illegal_insn;
                    s->pending_exception = CAUSE_BREAKPOINT;
                    goto exception;
                case 0x102: /* sret */
                    {
                        if (insn & 0x000fff80)
                            goto illegal_insn;
                        if (s->iflags_PRV < PRV_S ||
                            (s->iflags_PRV == PRV_S && (s->mstatus & MSTATUS_TSR)))
                            goto illegal_insn;
                        s->pc = GET_PC();
                        handle_sret(s);
                        goto done_interp;
                    }
                    break;
                case 0x302: /* mret */
                    {
                        if (insn & 0x000fff80)
                            goto illegal_insn;
                        if (s->iflags_PRV < PRV_M)
                            goto illegal_insn;
                        s->pc = GET_PC();
                        handle_mret(s);
                        goto done_interp;
                    }
                    break;
                case 0x105: /* wfi */
                    if (insn & 0x00007f80)
                        goto illegal_insn;
                    if (s->iflags_PRV == PRV_U ||
                        (s->iflags_PRV == PRV_S && (s->mstatus & MSTATUS_TW)))
                        goto illegal_insn;
                    /* go to power down if no enabled interrupts are
                       pending */
                    if ((s->mip & s->mie) == 0) {
                        s->iflags_I = true;
                        s->pc = GET_PC() + 4;
                        goto done_interp;
                    }
                    break;
                default:
                    if ((imm >> 5) == 0x09) {
                        /* sfence.vma */
                        if (insn & 0x00007f80)
                            goto illegal_insn;
                        if (s->iflags_PRV == PRV_U ||
                            (s->iflags_PRV == PRV_S && (s->mstatus & MSTATUS_TVM)))
                            goto illegal_insn;
                        if (rs1 == 0) {
                            tlb_flush_all(s);
                        } else {
                            tlb_flush_vaddr(s, s->reg[rs1]);
                        }
                        /* the current code TLB may have been flushed */
                        s->pc = GET_PC() + 4;
                        JUMP_INSN;
                    } else {
                        goto illegal_insn;
                    }
                    break;
                }
                break;
            default:
                goto illegal_insn;
            }
            NEXT_INSN;
        case 0x0f: /* misc-mem */
            funct3 = (insn >> 12) & 7;
            switch(funct3) {
            case 0: /* fence */
                if (insn & 0xf00fff80)
                    goto illegal_insn;
                break;
            case 1: /* fence.i */
                if (insn != 0x0000100f)
                    goto illegal_insn;
                break;
            default:
                goto illegal_insn;
            }
            NEXT_INSN;
        case 0x2f: { // atomics
            funct3 = (insn >> 12) & 7; // width
            // width = 2 (32-bit variant) or width = 3 (64-bit variant)
            if ((funct3 != 2) && (funct3 != 3))
                goto illegal_insn;
            uint32_t funct5 = (insn >> 27); // func
            addr = s->reg[rs1];
            // 64 bit variants
            if (funct3 & 1) {
                uint64_t rval;
                switch (static_cast<Atomic>(funct5)) {
                case Atomic::lr:
                    if (rs2 != 0)
                        goto illegal_insn;
                    if (target_read<uint64_t>(s, &rval, addr))
                        goto mmu_exception;
                    val = (int64_t)rval;
                    s->ilrsc = addr;
                    break;
                case Atomic::sc:
                    if (s->ilrsc == addr) {
                        if (target_write<uint64_t>(s, addr, s->reg[rs2]))
                            goto mmu_exception;
                        val = 0;
                    } else {
                        val = 1;
                    }
                    break;
                default:
                    if (funct5 > 4 && (funct5 & 3))
                        goto illegal_insn;
                    if (target_read<uint64_t>(s, &rval, addr))
                        goto mmu_exception;
                    val = (int64_t)rval;
                    val2 = s->reg[rs2];
                    switch (static_cast<Atomic>(funct5)) {
                    case Atomic::amoswap:
                        break;
                    case Atomic::amoadd:
                        val2 = (int64_t)(val + val2);
                        break;
                    case Atomic::amoxor:
                        val2 = (int64_t)(val ^ val2);
                        break;
                    case Atomic::amoand:
                        val2 = (int64_t)(val & val2);
                        break;
                    case Atomic::amoor:
                        val2 = (int64_t)(val | val2);
                        break;
                    case Atomic::amomin:
                        if ((int64_t)val < (int64_t)val2)
                            val2 = (int64_t)val;
                        break;
                    case Atomic::amomax:
                        if ((int64_t)val > (int64_t)val2)
                            val2 = (int64_t)val;
                        break;
                    case Atomic::amominu:
                        if ((uint64_t)val < (uint64_t)val2)
                            val2 = (int64_t)val;
                        break;
                    case Atomic::amomaxu:
                        if ((uint64_t)val > (uint64_t)val2)
                            val2 = (int64_t)val;
                        break;
                    default:
                        goto illegal_insn;
                    }
                    if (target_write<uint64_t>(s, addr, val2))
                        goto mmu_exception;
                    break;
                }
            // 32 bit variants
            } else {
                uint32_t rval;
                switch (static_cast<Atomic>(funct5)) {
                case Atomic::lr:
                    if (rs2 != 0)
                        goto illegal_insn;
                    if (target_read<uint32_t>(s, &rval, addr))
                        goto mmu_exception;
                    val = (int32_t)rval;
                    s->ilrsc = addr;
                    break;
                case Atomic::sc:
                    if (s->ilrsc == addr) {
                        if (target_write<uint32_t>(s, addr, s->reg[rs2]))
                            goto mmu_exception;
                        val = 0;
                    } else {
                        val = 1;
                    }
                    break;
                default:
                    if (funct5 > 4 && (funct5 & 3))
                        goto illegal_insn;
                    if (target_read<uint32_t>(s, &rval, addr))
                        goto mmu_exception;
                    val = (int32_t)rval;
                    val2 = s->reg[rs2];
                    switch (static_cast<Atomic>(funct5)) {
                    case Atomic::amoswap:
                        break;
                    case Atomic::amoadd:
                        val2 = (int32_t)(val + val2);
                        break;
                    case Atomic::amoxor:
                        val2 = (int32_t)(val ^ val2);
                        break;
                    case Atomic::amoand:
                        val2 = (int32_t)(val & val2);
                        break;
                    case Atomic::amoor:
                        val2 = (int32_t)(val | val2);
                        break;
                    case Atomic::amomin:
                        if ((int32_t)val < (int32_t)val2)
                            val2 = (int32_t)val;
                        break;
                    case Atomic::amomax:
                        if ((int32_t)val > (int32_t)val2)
                            val2 = (int32_t)val;
                        break;
                    case Atomic::amominu:
                        if ((uint32_t)val < (uint32_t)val2)
                            val2 = (int32_t)val;
                        break;
                    case Atomic::amomaxu:
                        if ((uint32_t)val > (uint32_t)val2)
                            val2 = (int32_t)val;
                        break;
                    default:
                        goto illegal_insn;
                    }
                    if (target_write<uint32_t>(s, addr, val2))
                        goto mmu_exception;
                    break;
                }
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
        }
        default:
            goto illegal_insn;
        }
        /* update PC for next instruction */
    jump_insn: ;
    } /* end of main loop */

 illegal_insn:
    s->pending_exception = CAUSE_ILLEGAL_INSTRUCTION;
    s->pending_tval = insn;
#ifdef DUMP_ILLEGAL_INSN
        {
            fprintf(stderr, "ILLEGAL INSTRUCTION\n");
            target_ulong pc = GET_PC();
            target_ulong ppc;
            if (!get_phys_addr(s, &ppc, pc, ACCESS_CODE)) {
                fprintf(stderr, "p    %08" PRIx64, ppc);
            } else {
                ppc = pc;
                fprintf(stderr, "v    %08" PRIx64, ppc);
            }
            fprintf(stderr, ":   %08" PRIx32 "   ", insn);
            fprintf(stderr, "\n");
        }
#endif

 mmu_exception:
 exception:
    s->pc = GET_PC();
    if (s->pending_exception >= 0) {
        raise_exception(s, s->pending_exception, s->pending_tval);
    }
    /* we exit because XLEN may have changed */
 done_interp:
    n_cycles--;
the_end:
    s->minstret = GET_INSN_COUNTER();
    s->mcycle = GET_CYCLE_COUNTER();
}

void riscv_cpu_run(RISCVCPUState *s, uint64_t cycles_end)
{
    while (!s->iflags_I && !s->iflags_H &&
        s->mcycle < cycles_end) {
        riscv_cpu_interpret(s, cycles_end);
    }
}

/* Note: the value is not accurate when called in riscv_cpu_interp() */
uint64_t riscv_cpu_get_mcycle(const RISCVCPUState *s)
{
    return s->mcycle;
}

void riscv_cpu_set_mcycle(RISCVCPUState *s, uint64_t cycles)
{
    s->mcycle = cycles;
}

void riscv_cpu_set_mip(RISCVCPUState *s, uint32_t mask)
{
    s->mip |= mask;
    /* exit from power down if an interrupt is pending */
    s->iflags_I &= !(s->mip & s->mie);

    //if (s->iflags_I && (s->mip & s->mie) != 0)
        //s->iflags_I = false;
}

void riscv_cpu_reset_mip(RISCVCPUState *s, uint32_t mask)
{
    s->mip &= ~mask;
}

uint32_t riscv_cpu_get_mip(const RISCVCPUState *s)
{
    return s->mip;
}

bool riscv_cpu_get_power_down(const RISCVCPUState *s)
{
    return s->iflags_I;
}

void riscv_cpu_set_power_down(RISCVCPUState *s, bool v)
{
    s->iflags_I = v;
}

bool riscv_cpu_get_shuthost(const RISCVCPUState *s)
{
    return s->iflags_H;
}

void riscv_cpu_set_shuthost(RISCVCPUState *s, bool v)
{
    s->iflags_H = v;
}

int riscv_cpu_get_max_xlen(const RISCVCPUState *)
{
    return XLEN;
}

RISCVCPUState *riscv_cpu_init(PhysMemoryMap *mem_map)
{
    RISCVCPUState *s = reinterpret_cast<RISCVCPUState *>(calloc(1, sizeof(*s)));
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
    return s;
}

void riscv_cpu_end(RISCVCPUState *s)
{
    free(s);
}

uint64_t riscv_cpu_get_misa(const RISCVCPUState *s)
{
    return s->misa;
}

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

template <typename DERIVED> class i_state_access {

    DERIVED &derived(void) {
        return *static_cast<DERIVED *>(this);
    }

    const DERIVED &derived(void) const {
        return *static_cast<const DERIVED *>(this);
    }

public:

    target_ulong read_register(RISCVCPUState *s, uint32_t reg) {
        return derived().do_read_register(s, reg);
    }

    void write_register(RISCVCPUState *s, uint32_t reg, target_ulong val) {
        derived().do_write_register(s, reg, val);
    }

    target_ulong read_mcycle(RISCVCPUState *s) {
        return derived().do_read_mcycle(s);
    }

    void write_mcycle(RISCVCPUState *s, target_ulong val) {
        return derived().do_write_mcycle(s, val);
    }

    target_ulong read_minstret(RISCVCPUState *s) {
        return derived().do_read_minstret(s);
    }

    void write_minstret(RISCVCPUState *s, target_ulong val) {
        return derived().do_write_minstret(s, val);
    }

    target_ulong read_pc(RISCVCPUState *s) {
        return derived().do_read_pc(s);
    }

    void write_pc(RISCVCPUState *s, target_ulong val) {
        return derived().do_write_pc(s, val);
    }

};

class state_access: public i_state_access<state_access> {
private:
    friend i_state_access<state_access>;

    void do_write_register(RISCVCPUState *s, uint32_t reg, target_ulong val) {
        assert(reg != 0);
        s->reg[reg] = val;
    }

    target_ulong do_read_register(RISCVCPUState *s, uint32_t reg) {
        return s->reg[reg];
    }

    target_ulong do_read_mcycle(RISCVCPUState *s) {
        return s->mcycle;
    }

    void do_write_mcycle(RISCVCPUState *s, target_ulong val) {
        s->mcycle = val;
    }

    target_ulong do_read_minstret(RISCVCPUState *s) {
        return s->minstret;
    }

    void do_write_minstret(RISCVCPUState *s, target_ulong val) {
        s->minstret = val;
    }

    target_ulong do_read_pc(RISCVCPUState *s) {
        return s->pc;
    }

    void do_write_pc(RISCVCPUState *s, target_ulong val) {
        s->pc = val;
    }
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

static inline int32_t insn_U_imm(uint32_t insn) {
    return (int32_t)(insn & 0xfffff000);
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
    return ((insn >> 5) & 0b1110000000) | (insn >> 24);
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

static void dump_insn(const char *insn) {
    fprintf(stdout, "%s\n", insn);
}

//??D An execute_OP function is only invoked when the opcode
//    has been decoded enough to preclude any other instruction.
//    In some cases, further checks are needed to ensure the
//    instruction is valid.

template <typename STATE_ACCESS>
static inline bool execute_illegal_insn_exception(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) pc;
    raise_exception(s, CAUSE_ILLEGAL_INSTRUCTION, insn);
    return false;
}

template <typename STATE_ACCESS>
static inline bool execute_misaligned_fetch_exception(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc) {
    (void) a;
    raise_exception(s, CAUSE_MISALIGNED_FETCH, pc);
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_jump_insn(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc) {
    a.write_pc(s, pc);
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_next_insn(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc) {
    a.write_pc(s, pc + 4);
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_LR_W(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    if ((insn & 0b00000001111100000000000000000000) == 0 ) {
        dump_insn("LR_W");
        return true;
    } else {
        return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

template <typename STATE_ACCESS>
static inline bool execute_SC_W(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("SC_W");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOSWAP_W(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOSWAP_W");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOADD_W(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOADD_W");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOXOR_W(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOXOR_W");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOAND_W(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOAND_W");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOOR_W(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOOR_W");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOMIN_W(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOMIN_W");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOMAX_W(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOMAX_W");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOMINU_W(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOMINU_W");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOMAXU_W(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOMAXU_W");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_LR_D(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    if ((insn & 0b00000001111100000000000000000000) == 0 ) {
        (void) a; (void) s; (void) pc; (void) insn;
        dump_insn("LR_D");
        return true;
    } else {
        return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

template <typename STATE_ACCESS>
static inline bool execute_SC_D(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("SC_D");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOSWAP_D(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOSWAP_D");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOADD_D(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOADD_D");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOXOR_D(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOXOR_D");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOAND_D(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOAND_D");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOOR_D(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOOR_D");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOMIN_D(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOMIN_D");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOMAX_D(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOMAX_D");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOMINU_D(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOMINU_D");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_AMOMAXU_D(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("AMOMAXU_D");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_ADDW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("ADDW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_SUBW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("SUBW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_SLLW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("SLLW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_SRLW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("SRLW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_SRAW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("SRAW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_MULW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("MULW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_DIVW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("DIVW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_DIVUW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("DIVUW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_REMW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("REMW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_REMUW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("REMUW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_SRLIW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("SRLIW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_SRAIW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("SRAIW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_ADDIW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("ADDIW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_SLLIW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    if (insn_funct7(insn) == 0) {
        (void) a; (void) s; (void) pc; (void) insn;
        dump_insn("SLLIW");
        return true;
    } else {
        return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

template <typename STATE_ACCESS>
static inline bool execute_CSRRW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("CSRRW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_CSRRS(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("CSRRS");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_CSRRC(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("CSRRC");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_CSRRWI(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("CSRRWI");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_CSRRSI(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("CSRRSI");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_CSRRCI(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("CSRRCI");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_ECALL(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("ECALL");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_EBREAK(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("EBREAK");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_URET(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("URET");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_SRET(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("SRET");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_MRET(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("MRET");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_WFI(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("WFI");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_FENCE(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("FENCE");
    // Really do nothing
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline bool execute_FENCE_I(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("FENCE_I");
    // Really do nothing
    return execute_next_insn(a, s, pc);
}

template <typename V> struct shift_left_binop {
    V operator()(V a, V b) {
        return a << (b & (XLEN-1));
    }
};

template <typename V> struct shift_right_binop {
    V operator()(V a, V b) {
        return a >> (b & (XLEN-1));
    }
};

template <typename V> struct div64_binop {
    int64_t operator()(int64_t a, int64_t b) {
        if (b == 0) {
            return -1;
        } else if (a == ((int64_t)1 << (XLEN - 1)) && b == -1) {
            return a;
        } else {
            return a / b;
        }
    }
};

template <typename V> struct divu64_binop {
    uint64_t operator()(uint64_t a, uint64_t b) {
        if (b == 0) {
            return -1;
        } else {
            return a / b;
        }
    }
};

template <typename V> struct rem64_binop {
    int64_t operator()(int64_t a, int64_t b) {
        if (b == 0) {
            return a;
        } else if (a == ((int64_t)1 << (XLEN - 1)) && b == -1) {
            return 0;
        } else {
            return a % b;
        }
    }
};

template <typename V> struct remu64_binop {
    uint64_t operator()(uint64_t a, uint64_t b) {
        if (b == 0) {
            return a;
        } else {
            return a % b;
        }
    }
};

template <typename V> struct mulh64_binop {
    uint64_t operator()(int64_t a, int64_t b) {
        return ((int128_t)a * (int128_t)b) >> 64;
    }
};

template <typename V> struct mulhsu64_binop {
    uint64_t operator()(int64_t a, uint64_t b) {
        return ((int128_t)a * (int128_t)b) >> 64;
    }
};

template <typename V> struct mulhu64_binop {
    uint64_t operator()(uint64_t a, uint64_t b) {
        return ((int128_t)a * (int128_t)b) >> 64;
    }
};

template <template <typename> class ARI, typename V, typename U, typename STATE_ACCESS>
static inline bool execute_arithmetic_vu(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    ARI<V> arith;
    uint32_t rd = insn_rd(insn);
    if (rd != 0) {
        // Ensure rs1 and rs2 are loaded in order: do not nest with call to arith as
        // the order of evaluation of arguments in a function call is undefined.
        target_ulong rs1 = a.read_register(s, insn_rs1(insn));
        target_ulong rs2 = a.read_register(s, insn_rs2(insn));
        target_ulong val = arith(static_cast<V>(rs1), static_cast<U>(rs2));
        a.write_register(s, rd, val);
    }
    return execute_next_insn(a, s, pc);
}

template <template <typename> class ARI, typename V, typename STATE_ACCESS>
static inline bool execute_arithmetic(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    return execute_arithmetic_vu<ARI, V, V>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_ADD(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("ADD");
    return execute_arithmetic<std::plus, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_SUB(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("SUB");
    return execute_arithmetic<std::minus, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_SLL(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("SLL");
    return execute_arithmetic<shift_left_binop, target_ulong>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_SLT(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("SLT");
    return execute_arithmetic<std::less, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_SLTU(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("SLTU");
    return execute_arithmetic<std::less, target_ulong>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_XOR(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("XOR");
    return execute_arithmetic<std::bit_xor, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_SRL(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("SRL");
    return execute_arithmetic<shift_right_binop, target_ulong>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_SRA(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("SRA");
    return execute_arithmetic<shift_right_binop, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_OR(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("OR");
    return execute_arithmetic<std::bit_or, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_AND(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("AND");
    return execute_arithmetic<std::bit_and, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_MUL(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("MUL");
    return execute_arithmetic<std::multiplies, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_MULH(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("MULH");
    return execute_arithmetic<mulh64_binop, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_MULHSU(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("MULHSU");
    return execute_arithmetic_vu<mulhsu64_binop, target_long, target_ulong>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_MULHU(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("MULHU");
    return execute_arithmetic<mulhu64_binop, target_ulong>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_DIV(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("DIV");
    return execute_arithmetic<div64_binop, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_DIVU(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("DIVU");
    return execute_arithmetic<divu64_binop, target_ulong>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_REM(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("REM");
    return execute_arithmetic<rem64_binop, target_ulong>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_REMU(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("REMU");
    return execute_arithmetic<remu64_binop, target_ulong>(a, s, pc, insn);
}

template <typename V> struct shift_left_immediate_binop {
    V operator()(V a, V b) {
        return a << b;
    }
};

template <typename V> struct shift_right_immediate_binop {
    V operator()(V a, V b) {
        return a >> b;
    }
};

template <template <typename> class ARI, typename V, typename STATE_ACCESS>
static inline bool execute_arithmetic_immediate(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    ARI<V> arith;
    uint32_t rd = insn_rd(insn);
    if (rd != 0) {
        target_ulong rs1 = a.read_register(s, insn_rs1(insn));
        target_ulong val = arith(static_cast<V>(rs1), static_cast<V>(insn_I_imm(insn)));
        a.write_register(s, rd, val);
    }
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline bool execute_SRLI(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("SRLI");
    return execute_arithmetic_immediate<shift_right_immediate_binop, target_ulong>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_SRAI(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("SRAI");
    return execute_arithmetic_immediate<shift_right_immediate_binop, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_ADDI(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("ADDI");
    return execute_arithmetic_immediate<std::plus, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_SLTI(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("SLTI");
    return execute_arithmetic_immediate<std::less, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_SLTIU(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("SLTIU");
    return execute_arithmetic_immediate<std::less, target_ulong>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_XORI(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("XORI");
    return execute_arithmetic_immediate<std::bit_xor, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_ORI(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("ORI");
    return execute_arithmetic_immediate<std::bit_or, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_ANDI(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("ANDI");
    return execute_arithmetic_immediate<std::bit_and, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_SLLI(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    if ((insn & (0b111111 << 26)) == 0) {
        dump_insn("SLLI");
        return execute_arithmetic_immediate<shift_left_immediate_binop, target_ulong>(a, s, pc, insn);
    } else {
        return execute_illegal_insn_exception(a, s, pc, insn);
    }
}

template <typename STATE_ACCESS>
static inline bool execute_SB(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("SB");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_SH(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("SH");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_SW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("SW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_SD(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("SD");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_LB(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("LB");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_LH(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("LH");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_LW(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("LW");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_LD(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("LD");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_LBU(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("LBU");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_LHU(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("LHU");
    return true;
}

template <typename STATE_ACCESS>
static inline bool execute_LWU(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    (void) a; (void) s; (void) pc; (void) insn;
    dump_insn("LWU");
    return true;
}

template <template <typename> class BRANCH, typename V, typename STATE_ACCESS>
static inline bool execute_branch(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    BRANCH<V> branch;
    target_ulong rs1 = a.read_register(s, insn_rs1(insn));
    target_ulong rs2 = a.read_register(s, insn_rs2(insn));
    if (branch(static_cast<V>(rs1), static_cast<V>(rs2))) {
        target_ulong new_pc = (int64_t)(pc + insn_B_imm(insn));
        if (new_pc & 3) {
            return execute_misaligned_fetch_exception(a, s, new_pc);
        } else {
            return execute_jump_insn(a, s, new_pc);
        }
    }
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline bool execute_BEQ(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("BEQ");
    return execute_branch<std::equal_to, target_ulong>(a, s, pc, insn);
}


template <typename STATE_ACCESS>
static inline bool execute_BNE(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("BNE");
    return execute_branch<std::not_equal_to, target_ulong>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_BLT(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("BLT");
    return execute_branch<std::less, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_BGE(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("BGE");
    return execute_branch<std::greater_equal, target_long>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_BLTU(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("BLTU");
    return execute_branch<std::less, target_ulong>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_BGEU(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("BGEU");
    return execute_branch<std::greater_equal, target_ulong>(a, s, pc, insn);
}

template <typename STATE_ACCESS>
static inline bool execute_LUI(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("LUI");
    uint32_t rd = insn_rd(insn);
    if (rd != 0)
        a.write_register(s, rd, insn_U_imm(insn));
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline bool execute_AUIPC(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("AUIPC");
    uint32_t rd = insn_rd(insn);
    if (rd != 0)
        a.write_register(s, rd, (int64_t)(pc + insn_U_imm(insn)));
    return execute_next_insn(a, s, pc);
}

template <typename STATE_ACCESS>
static inline bool execute_JAL(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("JAL");
    target_ulong new_pc = (int64_t)(pc + insn_J_imm(insn));
    if (new_pc & 3)
        return execute_misaligned_fetch_exception(a, s, new_pc);
    uint32_t rd = insn_rd(insn);
    if (rd != 0)
        a.write_register(s, rd, new_pc + 4);
    return execute_jump_insn(a, s, new_pc);
}

template <typename STATE_ACCESS>
static inline bool execute_JALR(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    dump_insn("JALR");
    target_ulong val = pc + 4;
    target_ulong new_pc = (int64_t)(a.read_register(s, insn_rs1(insn)) + insn_I_imm(insn)) & ~1;
    if (new_pc & 3)
        return execute_misaligned_fetch_exception(a, s, new_pc);
    uint32_t rd = insn_rd(insn);
    if (rd != 0)
        a.write_register(s, rd, val);
    return execute_jump_insn(a, s, new_pc);
}

template <typename STATE_ACCESS>
static bool execute_SFENCE_VMA(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    // rs1 and rs2 are arbitrary, rest is set
    if ((insn & 0b11111110000000000111111111111111) == 0b00010010000000000000000001110011) {
        (void) a; (void) s; (void) pc; (void) insn;
        dump_insn("SFENCE_VMA");
        return true;
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
static inline bool execute_atomic_group(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
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
static inline bool execute_arithmetic_32_group(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
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
static inline bool execute_shift_right_immediate_32_group(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
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
static inline bool execute_arithmetic_immediate_32_group(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
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
static inline bool execute_env_trap_int_mm_group(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
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
static inline bool execute_csr_env_trap_int_mm_group(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
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
static inline bool execute_fence_group(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
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
static inline bool execute_shift_right_immediate_group(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
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
static inline bool execute_arithmetic_group(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
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
static inline bool execute_arithmetic_immediate_group(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
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
static inline bool execute_store_group(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
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
static inline bool execute_load_group(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
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
static inline bool execute_branch_group(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
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
static inline bool execute_insn(STATE_ACCESS a, RISCVCPUState *s, target_ulong pc, uint32_t insn) {
    //std::cerr << "insn: " << std::bitset<32>(insn) << '\n';
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

/// \brief Loads the next instruction.
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param pc Receives current pc.
/// \param insn Receives fetched instruction.
/// \return Returns true if load succeeded, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static bool fetch_insn(STATE_ACCESS a, RISCVCPUState *s, target_ulong *pc, uint32_t *insn) {
    // Get current pc from state
    target_ulong vaddr = a.read_pc(s);
    // Translate pc address from virtual to physical
    // First, check TLB
    int tlb_idx = (vaddr >> PG_SHIFT) & (TLB_SIZE - 1);
    uintptr_t mem_addend;
    // TLB match
    if (s->tlb_code[tlb_idx].vaddr == (vaddr & ~PG_MASK)) {
        mem_addend = s->tlb_code[tlb_idx].mem_addend;
    // TLB miss
    } else {
        target_ulong paddr;
        // Walk page table and obtain the physical address
        if (get_phys_addr(s, &paddr, vaddr, ACCESS_CODE)) {
            raise_exception(s, CAUSE_FETCH_PAGE_FAULT, vaddr);
            return false;
        }
        // Walk memory map to find the range that contains the physical address
        PhysMemoryRange *pr = get_phys_mem_range(s->mem_map, paddr);
        // We only execute directly from RAM (as in "random access memory", which includes ROM)
        if (!pr || !pr->is_ram) {
            raise_exception(s, CAUSE_FAULT_FETCH, vaddr);
            return false;
        }
        // Update TLB with the new mapping between virtual and physical
        tlb_idx = (vaddr >> PG_SHIFT) & (TLB_SIZE - 1);
        uint8_t *ptr = pr->phys_mem + (uintptr_t)(paddr - pr->addr);
        s->tlb_code[tlb_idx].vaddr = vaddr & ~PG_MASK;
        s->tlb_code[tlb_idx].mem_addend = (uintptr_t)ptr - vaddr;
        mem_addend = s->tlb_code[tlb_idx].mem_addend;
    }

    // code_ptr = (uint8_t *)(mem_addend + (uintptr_t)vaddr);
    // code_end = (uint8_t *)(mem_addend + (uintptr_t)((vaddr & ~PG_MASK) + PG_MASK - 1));
    // code_to_pc_addend = vaddr - (uintptr_t)code_ptr;

    // Finally load the instruction
    *pc = vaddr;
    *insn = *reinterpret_cast<uint32_t *>(mem_addend + (uintptr_t)vaddr);
    return true;
}

/// \brief Interpreter status code
enum class interpreter_status {
    done, ///< mcycle reached target value
    halted, ///< iflags_H is set, indicating the machine is permanently halted
    idle ///< iflags_I is set, indicating the machine is waiting for an interrupt
};

/// \brief Tries to run the interpreter until mcycle hits a target
/// \tparam STATE_ACCESS Class of CPU state accessor object.
/// \param a CPU state accessor object.
/// \param s CPU state.
/// \param mcycle_end Target value for mcycle.
/// \returns Returns a status code that tells if the loop hit the target mcycle or stopped early.
/// \details The interpret may stop early if the machine halts permanently or becomes temporarily idle (waiting for interrupts).
template <typename STATE_ACCESS>
interpreter_status interpret(STATE_ACCESS a, RISCVCPUState *s, uint64_t mcycle_end) {

    // The external loop continues until the CPU halts,
    // becomes idle, or mcycle reaches mcycle_end
    for ( ;; ) {

        // If the cpu is halted, report it
        if (s->iflags_H) {
            return interpreter_status::halted;
        }

        // If we reached the target mcycle, report it
        if (a.read_mcycle(s) >= mcycle_end) {
            return interpreter_status::done;
        }

        // The idle flag is set if there were no pending interrupts when the machine executed a WFI instruction.
        // Any attempt to externally set a pending interrupt clears the idle flag.
        // Finding it set, there is nothing else to do and we simply report it back to the callee.
        if (s->iflags_I) {
            return interpreter_status::idle;
        }

        // The check interrupt flag is set whenever there are enabled pending interrupts.
        // If so, we raise the interrupt.
        if (s->iflags_CI) {
            raise_interrupt(s);
        }

        target_ulong pc = 0;
        uint32_t insn = 0;

        // The inner loops continues until there is an interrupt condition
        for ( ;; )  {

            // Increment the cycle counter mcycle
            target_ulong mcycle = a.read_mcycle(s) + 1;
            a.write_mcycle(s, mcycle);
            // Try to fetch the next instruction
            if (fetch_insn(a, s, &pc, &insn)) {
                // Try to execute it
                if (execute_insn(a, s, pc, insn)) {
                    // If successful, increment the number of retired instructions minstret
                    a.write_minstret(s, a.read_minstret(s)+1);
                }
                // If the check interrupt flag is active, break from the inner loop.
                // This will give the outer loop an opportunity to handle it.
                if (s->iflags_CI) break;
            }

            // If we reached the target mcycle, we are done
            if (mcycle >= mcycle_end) {
                return interpreter_status::done;
            }
        }
    }
}

// Explicit instantiation just to test everything compiles fine.
int foo(void) {
    state_access a;
    interpret(a, nullptr, 0);
    return 0;
}

#if 0
int gmain(void) {
    execute_insn(nullptr, 0x34202f73);
    execute_insn(nullptr, 0x00800f93);
    execute_insn(nullptr, 0x03ff0a63);
    execute_insn(nullptr, 0x80000f17);
    execute_insn(nullptr, 0xfe0f0f13);
    execute_insn(nullptr, 0x000f0067);
    execute_insn(nullptr, 0x000f5463);
    execute_insn(nullptr, 0x0040006f);
    execute_insn(nullptr, 0x5391e193);
    execute_insn(nullptr, 0xfc3f2023);
    execute_insn(nullptr, 0x00000073);
    execute_insn(nullptr, 0x30200073);
    execute_insn(nullptr, 0x08b6a72f);
    execute_insn(nullptr, 0x0ff0000f);
    execute_insn(nullptr, 0x00119193);
    execute_insn(nullptr, 0x1005a5af);
    execute_insn(nullptr, 0x18b5272f);
    return 0;
}
#endif






