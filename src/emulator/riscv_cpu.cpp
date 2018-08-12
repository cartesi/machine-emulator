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
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <fcntl.h>

#define XLEN 64
#define MXL   2

#include "cutils.h"
#include "iomem.h"
#include "riscv_cpu.h"

#ifdef DUMP_INSN
#include "dis/riscv-opc.h"
#endif


//#define DUMP_INVALID_MEM_ACCESS
//#define DUMP_MMU_EXCEPTIONS
//#define DUMP_INTERRUPTS
//#define DUMP_INVALID_CSR
//#define DUMP_EXCEPTIONS
//#define DUMP_CSR

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

/* Note: converted to correct bit position at runtime */
#define CAUSE_INTERRUPT  ((uint32_t)1 << 31)

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

    /*??D these are what makes our flags register */
    uint8_t priv; /* see PRV_x */
    BOOL power_down_flag;
    BOOL shuthost_flag;

    /*??D change to icause and itval? */
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

static no_inline int target_read_slow(RISCVCPUState *s, mem_uint_t *pval,
                                      target_ulong addr, int size_log2);
static no_inline int target_write_slow(RISCVCPUState *s, target_ulong addr,
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
    fprintf(stderr, "priv=%c", priv_str[s->priv]);
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
#define TARGET_READ_WRITE(size, uint_type, size_log2)                   \
static inline __exception int target_read_u ## size(RISCVCPUState *s, uint_type *pval, target_ulong addr)                              \
{\
    uint32_t tlb_idx;\
    tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);\
    if (likely(s->tlb_read[tlb_idx].vaddr == (addr & ~(PG_MASK & ~((size / 8) - 1))))) { \
        *pval = *(uint_type *)(s->tlb_read[tlb_idx].mem_addend + (uintptr_t)addr);\
    } else {\
        mem_uint_t val;\
        int ret;\
        ret = target_read_slow(s, &val, addr, size_log2);\
        if (ret)\
            return ret;\
        *pval = val;\
    }\
    return 0;\
}\
\
static inline __exception int target_write_u ## size(RISCVCPUState *s, target_ulong addr,\
                                          uint_type val)                \
{\
    uint32_t tlb_idx;\
    tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);\
    if (likely(s->tlb_write[tlb_idx].vaddr == (addr & ~(PG_MASK & ~((size / 8) - 1))))) { \
        *(uint_type *)(s->tlb_write[tlb_idx].mem_addend + (uintptr_t)addr) = val;\
        return 0;\
    } else {\
        return target_write_slow(s, addr, val, size_log2);\
    }\
}

TARGET_READ_WRITE(32, uint32_t, 2)
TARGET_READ_WRITE(64, uint64_t, 3)

/* return 0 if OK, != 0 if exception */
template <typename T>
static inline int target_read(RISCVCPUState *s, T *pval, target_ulong addr)  {
    uint32_t tlb_idx;
    tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (likely(s->tlb_read[tlb_idx].vaddr == (addr & ~(PG_MASK & ~(sizeof(T) - 1))))) {
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
    if (likely(s->tlb_write[tlb_idx].vaddr == (addr & ~(PG_MASK & ~(sizeof(T) - 1))))) {
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
        priv = s->priv;
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
        if (pte_size_log2 == 2)
            pte = phys_read<uint32_t>(s, pte_addr);
        else
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
                if (pte_size_log2 == 2)
                    phys_write<uint32_t>(s, pte_addr, pte);
                else
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
static no_inline int target_read_slow(RISCVCPUState *s, mem_uint_t *pval,
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
static no_inline int target_write_slow(RISCVCPUState *s, target_ulong addr,
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

struct __attribute__((packed)) unaligned_u32 {
    uint32_t u32;
};

/* unaligned access at an address known to be a multiple of 2 */
static uint32_t get_insn32(uint8_t *ptr)
{
#if defined(EMSCRIPTEN)
    return ((uint16_t *)ptr)[0] | (((uint16_t *)ptr)[1] << 16);
#else
    return ((struct unaligned_u32 *)ptr)->u32;
#endif
}

/* return 0 if OK, != 0 if exception */
static no_inline __exception int target_read_insn_slow(RISCVCPUState *s,
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

/* addr must be aligned */
static inline __exception int target_read_insn_u16(RISCVCPUState *s, uint16_t *pinsn,
                                                   target_ulong addr)
{
    uint32_t tlb_idx;
    uintptr_t mem_addend;

    tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (likely(s->tlb_code[tlb_idx].vaddr == (addr & ~PG_MASK))) {
        mem_addend = s->tlb_code[tlb_idx].mem_addend;
    } else {
        if (target_read_insn_slow(s, &mem_addend, addr))
            return -1;
    }
    *pinsn = *(uint16_t *)(mem_addend + (uintptr_t)addr);
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

/* return the complete mstatus with the SD bit */
static target_ulong get_mstatus(RISCVCPUState *s, target_ulong mask)
{
    target_ulong val;
    BOOL sd;
    val = s->mstatus & mask;
    sd = ((val & MSTATUS_FS) == MSTATUS_FS) |
        ((val & MSTATUS_XS) == MSTATUS_XS);
    if (sd)
        val |= (target_ulong)1 << (XLEN - 1);
    return val;
}

static void set_mstatus(RISCVCPUState *s, target_ulong val)
{
    target_ulong mod, mask;

    /* flush the TLBs if change of MMU config */
    mod = s->mstatus ^ val;
    if ((mod & (MSTATUS_MPRV | MSTATUS_SUM | MSTATUS_MXR)) != 0 ||
        ((s->mstatus & MSTATUS_MPRV) && (mod & MSTATUS_MPP) != 0)) {
        tlb_flush_all(s);
    }
    mask = MSTATUS_MASK & ~MSTATUS_FS;
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
static int csr_read(RISCVCPUState *s, target_ulong *pval, CSR csr, BOOL will_write)
{
    target_ulong val;

    if (csr_is_read_only(csr) && will_write) return -1;
    if (csr_priv(csr) > s->priv) return -1;

    switch(csr) {
    case CSR::ucycle:
        {
            uint32_t counteren;
            if (s->priv < PRV_M) {
                if (s->priv < PRV_S)
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
            if (s->priv < PRV_M) {
                if (s->priv < PRV_S)
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
        if (s->priv == PRV_S && s->mstatus & MSTATUS_TVM)
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
        if (csr != 0xc01 && csr != 0xc81) {
            fprintf(stderr, "csr_read: invalid CSR=0x%x\n", static_cast<int>(csr));
        }
#endif
        *pval = 0;
        return -1;
    }
    *pval = val;
    return 0;
}

/* return -1 if invalid CSR, 0 if OK, 1 if the interpreter loop must be
   exited, 2 if TLBs have been flushed. */
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
    if (s->priv != priv) {
        tlb_flush_all(s);
        s->priv = priv;
        /* ??D shouldn't we clear s->ilrsc here?
         * so it fails because of a context switch? */
    }
}

static void raise_exception(RISCVCPUState *s, uint32_t cause, target_ulong tval)
{
    BOOL deleg;
    target_ulong causel;
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
        flag = (cause & CAUSE_INTERRUPT) == 0;
        if (cause == CAUSE_SUPERVISOR_ECALL)
            flag = 0;
#endif
        if (flag) {
            fprintf(stderr, "raise_exception: cause=0x%08x tval=0x", cause);
            print_target_ulong(tval);
            fprintf(stderr, "\n");
            dump_regs(s);
        }
    }
#endif

    if (s->priv <= PRV_S) {
        /* delegate the exception to the supervisor priviledge */
        if (cause & CAUSE_INTERRUPT)
            deleg = (s->mideleg >> (cause & (XLEN - 1))) & 1;
        else
            deleg = (s->medeleg >> cause) & 1;
    } else {
        deleg = 0;
    }

    causel = cause & 0x7fffffff;
    if (cause & CAUSE_INTERRUPT)
        causel |= (target_ulong)1 << (XLEN-1);

    if (deleg) {
        s->scause = causel;
        s->sepc = s->pc;
        s->stval = tval;
        s->mstatus = (s->mstatus & ~MSTATUS_SPIE) |
            (((s->mstatus >> s->priv) & 1) << MSTATUS_SPIE_SHIFT);
        s->mstatus = (s->mstatus & ~MSTATUS_SPP) |
            (s->priv << MSTATUS_SPP_SHIFT);
        s->mstatus &= ~MSTATUS_SIE;
        set_priv(s, PRV_S);
        s->pc = s->stvec;
    } else {
        s->mcause = causel;
        s->mepc = s->pc;
        s->mtval = tval;
        s->mstatus = (s->mstatus & ~MSTATUS_MPIE) |
            (((s->mstatus >> s->priv) & 1) << MSTATUS_MPIE_SHIFT);
        s->mstatus = (s->mstatus & ~MSTATUS_MPP) |
            (s->priv << MSTATUS_MPP_SHIFT);
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
    /* s->mstatus = (s->mstatus & ~(1 << spp)) |
        (spie << spp); */
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
    /* s->mstatus = (s->mstatus & ~(1 << mpp)) |
        (mpie << mpp); */
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
    switch(s->priv) {
    case PRV_M:
        if (s->mstatus & MSTATUS_MIE)
            enabled_ints = ~s->mideleg;
        break;
    case PRV_S:
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

static __exception int raise_interrupt(RISCVCPUState *s)
{
    uint32_t mask;
    int irq_num;
    mask = get_pending_irq_mask(s);
    if (mask == 0)
        return 0;
    irq_num = ctz32(mask);
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

#if XLEN == 64 && defined(HAVE_INT128)

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

#else

#if XLEN == 64
#define UHALF uint32_t
#define UHALF_LEN 32
#else
#error unsupported XLEN
#endif

static uint64_t mulhu64(uint64_t a, uint64_t b)
{
    UHALF a0, a1, b0, b1, r2, r3;
    uint64_t r00, r01, r10, r11, c;
    a0 = a;
    a1 = a >> UHALF_LEN;
    b0 = b;
    b1 = b >> UHALF_LEN;

    r00 = (uint64_t)a0 * (uint64_t)b0;
    r01 = (uint64_t)a0 * (uint64_t)b1;
    r10 = (uint64_t)a1 * (uint64_t)b0;
    r11 = (uint64_t)a1 * (uint64_t)b1;

    //    r0 = r00;
    c = (r00 >> UHALF_LEN) + (UHALF)r01 + (UHALF)r10;
    //    r1 = c;
    c = (c >> UHALF_LEN) + (r01 >> UHALF_LEN) + (r10 >> UHALF_LEN) + (UHALF)r11;
    r2 = c;
    r3 = (c >> UHALF_LEN) + (r11 >> UHALF_LEN);

    //    *plow = ((uint64_t)r1 << UHALF_LEN) | r0;
    return ((uint64_t)r3 << UHALF_LEN) | r2;
}

#undef UHALF

static inline uint64_t mulh64(int64_t a, int64_t b)
{
    uint64_t r1;
    r1 = mulhu64(a, b);
    if (a < 0)
        r1 -= a;
    if (b < 0)
        r1 -= b;
    return r1;
}

static inline uint64_t mulhsu64(int64_t a, uint64_t b)
{
    uint64_t r1;
    r1 = mulhu64(a, b);
    if (a < 0)
        r1 -= a;
    return r1;
}

#endif

#define GET_PC() (target_ulong)((uintptr_t)code_ptr + code_to_pc_addend)
#define GET_INSN_COUNTER() (minstret_addend - n_cycles)
#define GET_CYCLE_COUNTER() (mcycle_addend - n_cycles)

#define C_NEXT_INSN code_ptr += 2; break
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

static void no_inline riscv_cpu_interpret(RISCVCPUState *s, uint64_t mcycle_addend) {
    uint32_t opcode, insn, rd, rs1, rs2, funct3;
    int32_t imm, cond, err;
    target_ulong addr, val, val2;
    uint64_t minstret_addend;
    uint64_t n_cycles;
    uint8_t *code_ptr, *code_end;
    target_ulong code_to_pc_addend;

    if (s->mcycle >= mcycle_addend)
        return;

    n_cycles = mcycle_addend - s->mcycle;

    minstret_addend = s->minstret + n_cycles;

    s->pending_exception = -1;
    n_cycles++;
    /* Note: we assume NULL is represented as a zero number */
    code_ptr = NULL;
    code_end = NULL;
    code_to_pc_addend = s->pc;

    /* we use a single execution loop to keep a simple control flow
       for emscripten */
    for(;;) {

#if 0
    fprintf(stderr, " mstatus=");
    print_target_ulong(s->mstatus);
    fprintf(stderr, "\n");
#endif

        if (unlikely(!--n_cycles || s->shuthost_flag)) {
            s->pc = GET_PC();
            goto the_end;
        }
        if (unlikely(code_ptr >= code_end)) {
            uint32_t tlb_idx;
            uint16_t insn_high;
            uintptr_t mem_addend;
            target_ulong addr;

            s->pc = GET_PC();

            /* check pending interrupts */
            if (unlikely((s->mip & s->mie) != 0)) {
                if (raise_interrupt(s)) {
                    goto the_end;
                }
            }

            addr = s->pc;
            tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
            if (likely(s->tlb_code[tlb_idx].vaddr == (addr & ~PG_MASK))) {
                /* TLB match */
                mem_addend = s->tlb_code[tlb_idx].mem_addend;
            } else {
                if (unlikely(target_read_insn_slow(s, &mem_addend, addr)))
                    goto mmu_exception;
            }
            code_ptr = (uint8_t *)(mem_addend + (uintptr_t)addr);
            code_end = (uint8_t *)(mem_addend +
                                   (uintptr_t)((addr & ~PG_MASK) + PG_MASK - 1));
            code_to_pc_addend = addr - (uintptr_t)code_ptr;
            if (unlikely(code_ptr >= code_end)) {
                /* instruction is potentially half way between two
                   pages ? */
                insn = *(uint16_t *)code_ptr;
                if ((insn & 3) == 3) {
                    /* instruction is half way between two pages */
                    if (unlikely(target_read_insn_u16(s, &insn_high, addr + 2)))
                        goto mmu_exception;
                    insn |= insn_high << 16;
                }
            } else {
                insn = get_insn32(code_ptr);
            }
        } else {
            /* fast path */
            insn = get_insn32(code_ptr);
        }
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
#if XLEN >= 64
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
#endif
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
#if XLEN >= 64
            case 3: /* sd */
                if (target_write<uint64_t>(s, addr, val))
                    goto mmu_exception;
                break;
#endif
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
#if XLEN >= 64
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
#endif
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
#if XLEN >= 64
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
#endif
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
                if (csr_read(s, &val2, static_cast<CSR>(imm), TRUE))
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
                    s->pending_exception = CAUSE_USER_ECALL + s->priv;
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
                        if (s->priv < PRV_S || 
                            (s->priv == PRV_S && (s->mstatus & MSTATUS_TSR)))
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
                        if (s->priv < PRV_M)
                            goto illegal_insn;
                        s->pc = GET_PC();
                        handle_mret(s);
                        goto done_interp;
                    }
                    break;
                case 0x105: /* wfi */
                    if (insn & 0x00007f80)
                        goto illegal_insn;
                    if (s->priv == PRV_U ||
                        (s->priv == PRV_S && (s->mstatus & MSTATUS_TW)))
                        goto illegal_insn;
                    /* go to power down if no enabled interrupts are
                       pending */
                    if ((s->mip & s->mie) == 0) {
                        s->power_down_flag = TRUE;
                        s->pc = GET_PC() + 4;
                        goto done_interp;
                    }
                    break;
                default:
                    if ((imm >> 5) == 0x09) {
                        /* sfence.vma */
                        if (insn & 0x00007f80)
                            goto illegal_insn;
                        if (s->priv == PRV_U ||
                            (s->priv == PRV_S && (s->mstatus & MSTATUS_TVM)))
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
        case 0x2f:
            funct3 = (insn >> 12) & 7;
#define OP_A(size)                                                      \
            {                                                           \
                uint ## size ##_t rval;                                 \
                                                                        \
                addr = s->reg[rs1];                                     \
                funct3 = insn >> 27;                                    \
                switch(funct3) {                                        \
                case 2: /* lr.w */                                      \
                    if (rs2 != 0)                                       \
                        goto illegal_insn;                              \
                    if (target_read_u ## size(s, &rval, addr))          \
                        goto mmu_exception;                             \
                    val = (int## size ## _t)rval;                       \
                    s->ilrsc = addr;                                 \
                    break;                                              \
                case 3: /* sc.w */                                      \
                    if (s->ilrsc == addr) {                          \
                        if (target_write_u ## size(s, addr, s->reg[rs2])) \
                            goto mmu_exception;                         \
                        val = 0;                                        \
                    } else {                                            \
                        val = 1;                                        \
                    }                                                   \
                    break;                                              \
                case 1: /* amiswap.w */                                 \
                case 0: /* amoadd.w */                                  \
                case 4: /* amoxor.w */                                  \
                case 0xc: /* amoand.w */                                \
                case 0x8: /* amoor.w */                                 \
                case 0x10: /* amomin.w */                               \
                case 0x14: /* amomax.w */                               \
                case 0x18: /* amominu.w */                              \
                case 0x1c: /* amomaxu.w */                              \
                    if (target_read_u ## size(s, &rval, addr))          \
                        goto mmu_exception;                             \
                    val = (int## size ## _t)rval;                       \
                    val2 = s->reg[rs2];                                 \
                    switch(funct3) {                                    \
                    case 1: /* amiswap.w */                             \
                        break;                                          \
                    case 0: /* amoadd.w */                              \
                        val2 = (int## size ## _t)(val + val2);          \
                        break;                                          \
                    case 4: /* amoxor.w */                              \
                        val2 = (int## size ## _t)(val ^ val2);          \
                        break;                                          \
                    case 0xc: /* amoand.w */                            \
                        val2 = (int## size ## _t)(val & val2);          \
                        break;                                          \
                    case 0x8: /* amoor.w */                             \
                        val2 = (int## size ## _t)(val | val2);          \
                        break;                                          \
                    case 0x10: /* amomin.w */                           \
                        if ((int## size ## _t)val < (int## size ## _t)val2) \
                            val2 = (int## size ## _t)val;               \
                        break;                                          \
                    case 0x14: /* amomax.w */                           \
                        if ((int## size ## _t)val > (int## size ## _t)val2) \
                            val2 = (int## size ## _t)val;               \
                        break;                                          \
                    case 0x18: /* amominu.w */                          \
                        if ((uint## size ## _t)val < (uint## size ## _t)val2) \
                            val2 = (int## size ## _t)val;               \
                        break;                                          \
                    case 0x1c: /* amomaxu.w */                          \
                        if ((uint## size ## _t)val > (uint## size ## _t)val2) \
                            val2 = (int## size ## _t)val;               \
                        break;                                          \
                    default:                                            \
                        goto illegal_insn;                              \
                    }                                                   \
                    if (target_write_u ## size(s, addr, val2))          \
                        goto mmu_exception;                             \
                    break;                                              \
                default:                                                \
                    goto illegal_insn;                                  \
                }                                                       \
            }

            switch(funct3) {
            case 2:
                OP_A(32);
                break;
#if XLEN >= 64
            case 3:
                OP_A(64);
                break;
#endif
            default:
                goto illegal_insn;
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
        default:
            goto illegal_insn;
        }
        /* update PC for next instruction */
    jump_insn: ;
    } /* end of main loop */
 illegal_insn:
    s->pending_exception = CAUSE_ILLEGAL_INSTRUCTION;
    s->pending_tval = insn;
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

#undef OP_A

void riscv_cpu_run(RISCVCPUState *s, uint64_t cycles_end)
{
    while (!s->power_down_flag && !s->shuthost_flag &&
        s->mcycle < cycles_end) {
        riscv_cpu_interpret(s, cycles_end);
    }
}

/* Note: the value is not accurate when called in riscv_cpu_interp() */
uint64_t riscv_cpu_get_mcycle(RISCVCPUState *s)
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
    if (s->power_down_flag && (s->mip & s->mie) != 0)
        s->power_down_flag = FALSE;
}

void riscv_cpu_reset_mip(RISCVCPUState *s, uint32_t mask)
{
    s->mip &= ~mask;
}

uint32_t riscv_cpu_get_mip(RISCVCPUState *s)
{
    return s->mip;
}

BOOL riscv_cpu_get_power_down(RISCVCPUState *s)
{
    return s->power_down_flag;
}

void riscv_cpu_set_power_down(RISCVCPUState *s, BOOL v)
{
    s->power_down_flag = v;
}

BOOL riscv_cpu_get_shuthost(RISCVCPUState *s)
{
    return s->shuthost_flag;
}

void riscv_cpu_set_shuthost(RISCVCPUState *s, BOOL v)
{
    s->shuthost_flag = v;
}

int riscv_cpu_get_max_xlen(void)
{
    return XLEN;
}

RISCVCPUState *riscv_cpu_init(PhysMemoryMap *mem_map)
{
    RISCVCPUState *s = reinterpret_cast<RISCVCPUState *>(mallocz(sizeof(*s)));
    s->mem_map = mem_map;
    s->power_down_flag = FALSE;
    s->shuthost_flag = FALSE;
    s->pc = 0x1000;
    s->priv = PRV_M;
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

uint64_t riscv_cpu_get_misa(RISCVCPUState *s)
{
    return s->misa;
}
