#include <cstdio>
#include <cinttypes>
#include <cstdint>

/// \file
/// \brief Interpreter implementation.
/// \details \{
/// This code assumes the host's byte-ordering is the same as RISC-V's.
/// RISC-V is little endian, and so is x86.
/// There is a static_assert to prevent the code from compiling otherwise.
///
/// This code assumes the modulo operator is such that
///
///      (a/b)*b + a%b = a
///
/// i.e., the sign of the result is the sign of a.
/// This is only guaranteed from C++11 forward.
///
///   https://en.cppreference.com/w/cpp/language/operator_arithmetic
///
/// RISC-V does not define this (at least I have not found it
/// in the documentation), but the tests seem assume this behavior.
///
///   https://github.com/riscv/riscv-tests/blob/master/isa/rv64um/rem.S
///
/// EVM defines the same behavior. See the yellowpaper.
///
/// This code assumes right-shifts of negative values are arithmetic shifts.
/// This is implementation-defined in C and C++.
/// Most compilers indeed do arithmetic shifts:
///
///   https://docs.microsoft.com/en-us/cpp/c-language/right-shifts
///
///   https://gcc.gnu.org/onlinedocs/gcc-7.3.0/gcc/Integers-implementation.html#Integers-implementation
///   (clang should behave the same as gcc, but does not document it)
///   (I have not found documentation for icc)
///
/// EVM does not have a shift operator.
/// Solidity defines shift as division, which means it rounds negative numbers towards zero.
/// WARNING: An arithmetic shift right would "round" a negative number away from zero!
///
/// The code assumes narrowing conversions of signed types are modulo operations.
/// This is implementation-defined in C and C++.
/// Most compilers indeed do modulo narrowing:
///
///   https://docs.microsoft.com/en-us/cpp/c-language/demotion-of-integers
///
///   https://gcc.gnu.org/onlinedocs/gcc-7.3.0/gcc/Integers-implementation.html#Integers-implementation
///   (clang should behave the same as gcc, but does not document it)
///   (I have not found documentation for icc)
///
/// Signed integer overflows are UNDEFINED according to C and C++.
/// We do not assume signed integers handle overflow with modulo arithmetic.
/// Detecting and preventing overflows is awkward and costly.
/// Fortunately, GCC offers intrinsics that have well-defined overflow behavior.
///
///   https://gcc.gnu.org/onlinedocs/gcc-7.3.0/gcc/Integer-Overflow-Builtins.html#Integer-Overflow-Builtins
/// \}

// GCC complains about __int128 with -pedantic or -pedantic-errors
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;
#pragma GCC diagnostic pop

#include "machine.h"
#include "machine-state.h"
#include "state-access.h"
#include "logged-state-access.h"
#include "virtual-state-access.h"
#include "rtc.h"
#include "meta.h"
#include "riscv-constants.h"
#include "unique-c-ptr.h"
#include "rom.h"
#include "interpret.h"

namespace cartesi {

/// \brief Memory range peek callback. See ::pma_peek.
static bool memory_peek(const pma_entry &pma, uint64_t page_address, const uint8_t **page_data, uint8_t *scratch) {
    // If page_address is not aligned, or if it is out of range, return error
    if ((page_address & (PMA_PAGE_SIZE-1)) != 0 ||
        page_address > pma.get_length()) {
        *page_data = nullptr;
        return false;
    }
    // If page is only partially inside range, copy to scratch
    if (page_address + PMA_PAGE_SIZE > pma.get_length()) {
        memset(scratch, 0, PMA_PAGE_SIZE);
        memcpy(scratch, pma.get_memory().get_host_memory() + page_address, pma.get_length() - page_address);
        *page_data = scratch;
        return true;
    // Otherwise, return pointer direclty into host memory
    } else {
        *page_data = pma.get_memory().get_host_memory() + page_address;
        return true;
    }
}

static void print_uint64_t(uint64_t a) {
    fprintf(stderr, "%016" PRIx64, a);
}

static const char *reg_name[32] = {
"zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
"s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
"a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
"s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
};

void dump_regs(const machine_state &s) {
    int i, cols;
    const char priv_str[] = "USHM";
    cols = 256 / XLEN;
    fprintf(stderr, "pc = ");
    print_uint64_t(s.pc);
    fprintf(stderr, " ");
    for(i = 1; i < 32; i++) {
        fprintf(stderr, "%-3s= ", reg_name[i]);
        print_uint64_t(s.x[i]);
        if ((i & (cols - 1)) == (cols - 1))
            fprintf(stderr, "\n");
        else
            fprintf(stderr, " ");
    }
    fprintf(stderr, "priv=%c", priv_str[s.iflags.PRV]);
    fprintf(stderr, " mstatus=");
    print_uint64_t(s.mstatus);
    fprintf(stderr, " cycles=%" PRId64, s.mcycle);
    fprintf(stderr, " insns=%" PRId64, s.minstret);
    fprintf(stderr, "\n");
#if 1
    fprintf(stderr, "mideleg=");
    print_uint64_t(s.mideleg);
    fprintf(stderr, " mie=");
    print_uint64_t(s.mie);
    fprintf(stderr, " mip=");
    print_uint64_t(s.mip);
    fprintf(stderr, "\n");
#endif
}

/// \brief Obtain PMA entry overlapping with target physical address.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param paddr Target physical address.
/// \returns Corresponding entry if found, or a sentinel entry
/// for an empty range.
/// \details This is the same as ::naked_find_pma_entry, except it
/// does not perform naked accesses to the machine state.
/// Rather, it goes through the state accessor object so all
/// accesses can be recorded if need be.
template <typename T, typename STATE_ACCESS>
static pma_entry &find_pma_entry(STATE_ACCESS &a, uint64_t paddr) {
    auto note = a.make_scoped_note("find_pma_entry"); (void) note;
    int i = 0;
    for (auto &pma: a.get_naked_state().pmas) {
        a.read_pma(pma, i++);
        if (paddr >= pma.get_start() &&
            paddr + sizeof(T) <= pma.get_start() + pma.get_length())
            return pma;
        if (pma.get_length() == 0)
            break;
    }
    return a.get_naked_state().empty_pma;
}

/// \brief Write an aligned word to memory.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param paddr Physical address of word.
/// \param val Value to write.
/// \returns True if succeeded, false otherwise.
template <typename STATE_ACCESS>
static inline bool write_ram_uint64(STATE_ACCESS &a, uint64_t paddr, uint64_t val) {
    pma_entry &pma = find_pma_entry<uint64_t>(a, paddr);
    if (!pma.get_istart_M() || !pma.get_istart_W())
        return false;
    uintptr_t haddr = reinterpret_cast<uintptr_t>(pma.get_memory().get_host_memory() + (paddr - pma.get_start()));
    // log writes to memory
    a.write_memory(paddr, haddr, val);
    return true;
}

/// \brief Read an aligned word from memory.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param paddr Physical address of word.
/// \param pval Pointer to word.
/// \returns True if succeeded, false otherwise.
template <typename STATE_ACCESS>
static inline bool read_ram_uint64(STATE_ACCESS &a, uint64_t paddr, uint64_t *pval) {
    pma_entry &pma = find_pma_entry<uint64_t>(a, paddr);
    if (!pma.get_istart_M() || !pma.get_istart_R()) return false;
    uintptr_t haddr = reinterpret_cast<uintptr_t>(pma.get_memory().get_host_memory() + (paddr - pma.get_start()));
    a.read_memory(paddr, haddr, pval);
    return true;
}

/// \brief Walk the page table and translate a virtual address to the corresponding physical address
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param vaddr Virtual address
/// \param ppaddr Pointer to physical address.
/// \param xwr_shift Encodes the access mode by the shift to the XWR triad (PTE_XWR_R_SHIFT,
///  PTE_XWR_R_SHIFT, or PTE_XWR_R_SHIFT)
/// \returns True if succeeded, false otherwise.
template <typename STATE_ACCESS>
static bool translate_virtual_address(STATE_ACCESS a, uint64_t *ppaddr, uint64_t vaddr, int xwr_shift) {
    auto note = a.make_scoped_note("translate_virtual_address"); (void) note;
    auto priv = a.read_iflags_PRV();
    uint64_t mstatus = a.read_mstatus();

    // When MPRV is set, data loads and stores use privilege in MPP
    // instead of the current privilege level (code access is unaffected)
    if ((mstatus & MSTATUS_MPRV_MASK) && xwr_shift != PTE_XWR_C_SHIFT) {
        priv = (mstatus & MSTATUS_MPP_MASK) >> MSTATUS_MPP_SHIFT;
    }

    // M-mode code does not use virtual memory
    if (priv == PRV_M) {
        *ppaddr = vaddr;
        return true;
    }

    uint64_t satp = a.read_satp();

    // In RV64, mode can be
    //   0: Bare: No translation or protection
    //   8: sv39: Page-based 39-bit virtual addressing
    //   9: sv48: Page-based 48-bit virtual addressing
    int mode = (satp >> 60) & 0xf;
    if (mode == 0) {
        *ppaddr = vaddr;
        return true;
    } else if (mode < 8 || mode > 9) {
        return false;
    }
    // Here we know we are in sv39 or sv48 modes

    // Page table hierarchy of sv39 has 3 levels, and sv48 has 4 levels
    // ??D It doesn't seem like restricting to one or the other will
    //     simplify the code much. However, we may want to use sv39
    //     to reduce the size of the log sent to the blockchain
    int levels = mode - 8 + 3;

    // The least significant 12 bits of vaddr are the page offset
    // Then come levels virtual page numbers (VPN)
    // The rest of vaddr must be filled with copies of the
    // most significant bit in VPN[levels]
    // Hence, the use of arithmetic shifts here
    int vaddr_shift = XLEN - (PAGE_NUMBER_SHIFT + levels * 9);
    if ((((int64_t)vaddr << vaddr_shift) >> vaddr_shift) != (int64_t) vaddr)
        return false;

    // The least significant 44 bits of satp contain the physical page number for the root page table
    const int satp_ppn_bits = 44;
    // Initialize pte_addr with the base address for the root page table
    uint64_t pte_addr = (satp & (((uint64_t)1 << satp_ppn_bits) - 1)) << PAGE_NUMBER_SHIFT;
    // All page table entries have 8 bytes
    const int pte_size_log2 = 3;
    // Each page table has 4k/pte_size entries
    // To index all entries, we need vpn_bits
    const int vpn_bits = 12 - pte_size_log2;
    uint64_t vpn_mask = (1 << vpn_bits) - 1;
    for (int i = 0; i < levels; i++) {
        // Mask out VPN[levels-i-1]
        vaddr_shift = PAGE_NUMBER_SHIFT + vpn_bits * (levels - 1 - i);
        uint64_t vpn = (vaddr >> vaddr_shift) & vpn_mask;
        // Add offset to find physical address of page table entry
        pte_addr += vpn << pte_size_log2; //??D we can probably save this shift here
        // Read page table entry from physical memory
        uint64_t pte = 0;
        if (!read_ram_uint64(a, pte_addr, &pte)) {
            return false;
        }
        // The OS can mark page table entries as invalid,
        // but these entries shouldn't be reached during page lookups
        if (!(pte & PTE_V_MASK))
            return false;
        // Clear all flags in least significant bits, then shift back to multiple of page size to form physical address
        uint64_t ppn = (pte >> 10) << PAGE_NUMBER_SHIFT;
        // Obtain X, W, R protection bits
        int xwr = (pte >> 1) & 7;
        // xwr != 0 means we are done walking the page tables
        if (xwr != 0) {
            // These protection bit combinations are reserved for future use
            if (xwr == 2 || xwr == 6)
                return false;
            // (We know we are not PRV_M if we reached here)
            if (priv == PRV_S) {
                // If SUM is set, forbid S-mode code from accessing U-mode memory
                if ((pte & PTE_U_MASK) && !(mstatus & MSTATUS_SUM_MASK))
                    return false;
            } else {
                // Forbid U-mode code from accessing S-mode memory
                if (!(pte & PTE_U_MASK))
                    return false;
            }
            // MXR allows read access to execute-only pages
            if (mstatus & MSTATUS_MXR_MASK)
                // Set R bit if X bit is set
                xwr |= (xwr >> 2);
            // Check protection bits against requested access
            if (((xwr >> xwr_shift) & 1) == 0)
                return false;
            // Check page, megapage, and gigapage alignment
            uint64_t vaddr_mask = ((uint64_t)1 << vaddr_shift) - 1;
            if (ppn & vaddr_mask)
                return false;
            // Decide if we need to update access bits in pte
            bool update_pte = !(pte & PTE_A_MASK) || (!(pte & PTE_D_MASK) && xwr_shift == PTE_XWR_W_SHIFT);
            pte |= PTE_A_MASK;
            if (xwr_shift == PTE_XWR_W_SHIFT)
                pte |= PTE_D_MASK;
            // If so, update pte
            if (update_pte)
                write_ram_uint64(a, pte_addr, pte); // Can't fail since read succeeded earlier
            // Add page offset in vaddr to ppn to form physical address
            *ppaddr = (vaddr & vaddr_mask) | (ppn & ~vaddr_mask);
            return true;
        // xwr == 0 means we have a pointer to the start of the next page table
        } else {
            pte_addr = ppn;
        }
    }
    return false;
}

/// \brief Replaces an entry in the TLB with a new one.
/// \param pma PMA entry for range.
/// \param vaddr Target virtual address.
/// \param paddr Target physical address.
/// \param tlb TLB entry to replace.
/// \returns Offset from Target virtual address to host address
static inline uintptr_t tlb_replace(pma_entry &pma, uint64_t vaddr, uint64_t paddr, tlb_entry &tlb) {
    tlb.vaddr = vaddr & ~PAGE_OFFSET_MASK;
    uint8_t *ptr = pma.get_memory().get_host_memory() + (uintptr_t)(paddr - pma.get_start());
    tlb.mem_addend = (uintptr_t)ptr - vaddr;
    return tlb.mem_addend;
}

/// \brief Checks for a TLB hit.
/// \tparam T Type of access needed (uint8_t, uint16_t, uint32_t, uint64_t).
/// \param tlb TLB entry to check.
/// \param vaddr Target virtual address.
/// \returns True on hit, false otherwise.
template <typename T>
static inline bool tlb_hit(const tlb_entry &tlb, uint64_t vaddr) {
    // Make sure misaligned accesses are always considered a miss
    // Otherwise, we could report a hit for a word that goes past the end of the PMA range.
    // Aligned accesses cannot do so because the PMA ranges
    // are always page-aligned.
    return (tlb.vaddr == (vaddr & ~(PAGE_OFFSET_MASK & ~(sizeof(T) - 1))));
}

/// \brief Invalidates all TLB entries.
/// \param s Pointer to machine state.
static void tlb_flush_all(machine_state &s) {
    s.init_tlb();
}

/// \brief Invalidates a specific mapping.
/// \param s Pointer to machine state.
/// \param vaddr Target virtual address.
static void tlb_flush_vaddr(machine_state &s, uint64_t vaddr) {
    (void) vaddr;
    //??D Optimize depending on how often it is used
    tlb_flush_all(s);
}

/// \brief Checks if CSR is read-only.
/// \param CSR_address Address of CSR in file.
/// \returns true if read-only, false otherwise.
static inline bool csr_is_read_only(CSR_address csraddr) {
    // 0xc00--0xcff, 0xd00--0xdff, and 0xf00--0xfff are all read-only.
    // so as long as bits 0xc00 are set, the register is read-only
    return ((to_underlying(csraddr) & 0xc00) == 0xc00);
}

/// \brief Extract privilege level from CSR address.
/// \param CSR_address Address of CSR in file.
/// \returns Privilege level.
static inline uint32_t csr_priv(CSR_address csr) {
    return (to_underlying(csr) >> 8) & 3;
}

/// \brief Changes privilege level.
/// \param a Machine state accessor object.
/// \param previous_prv Previous privilege level.
/// \param new_prv New privilege level.
template <typename STATE_ACCESS>
static void set_priv(STATE_ACCESS &a, int previous_prv, int new_prv) {
    if (previous_prv != new_prv) {
        tlb_flush_all(a.get_naked_state());
        a.write_iflags_PRV(new_prv);
        //??D new priv 1.11 draft says invalidation should
        //happen within a trap handler, although it could
        //also happen in xRET insn.
        a.write_ilrsc(-1); // invalidate reserved address
    }
}

/// \brief Raise an exception (or interrupt).
/// \param a Machine state accessor object.
/// \param cause Exception (or interrupt) mcause (or scause).
/// \param tval Associated tval.
template <typename STATE_ACCESS>
static void raise_exception(STATE_ACCESS &a, uint64_t cause, uint64_t tval) {
    auto note = a.make_scoped_note("raise_exception"); (void) note;
#if defined(DUMP_EXCEPTIONS) || defined(DUMP_MMU_EXCEPTIONS) || defined(DUMP_INTERRUPTS)
    {
        int flag;
        flag = 0;
#ifdef DUMP_MMU_EXCEPTIONS
        if (cause == MCAUSE_INSN_ACCESS_FAULT ||
            cause == MCAUSE_LOAD_ACCESS_FAULT ||
            cause == MCAUSE_STORE_AMO_ACCESS_FAULT ||
            cause == MCAUSE_FETCH_PAGE_FAULT ||
            cause == MCAUSE_LOAD_PAGE_FAULT ||
            cause == MCAUSE_STORE_AMO_PAGE_FAULT)
            flag = 1;
#endif
#ifdef DUMP_INTERRUPTS
        flag |= (cause & MCAUSE_INTERRUPT_FLAG) != 0;
#endif
#ifdef DUMP_EXCEPTIONS
        flag |= (cause & MCAUSE_INTERRUPT_FLAG) == 0;
#endif
        if (flag) {
            fprintf(stderr, "raise_exception: cause=0x");
            print_uint64_t(cause);
            fprintf(stderr, " tval=0x");
            print_uint64_t(tval);
            fprintf(stderr, "\n");
            dump_regs(a.get_naked_state());
        }
    }
#endif

    // Check if exception should be delegated to supervisor privilege
    // For each interrupt or exception number, there is a bit at mideleg
    // or medeleg saying if it should be delegated
    bool deleg = false;
    auto priv = a.read_iflags_PRV();
    if (priv <= PRV_S) {
        if (cause & MCAUSE_INTERRUPT_FLAG) {
            // Clear the MCAUSE_INTERRUPT_FLAG bit before shifting
            deleg = (a.read_mideleg() >> (cause & (XLEN - 1))) & 1;
        } else {
            deleg = (a.read_medeleg() >> cause) & 1;
        }
    }

    if (deleg) {
        a.write_scause(cause);
        a.write_sepc(a.read_pc());
        a.write_stval(tval);
        uint64_t mstatus = a.read_mstatus();
        mstatus = (mstatus & ~MSTATUS_SPIE_MASK) | (((mstatus >> priv) & 1) << MSTATUS_SPIE_SHIFT);
        mstatus = (mstatus & ~MSTATUS_SPP_MASK) | (priv << MSTATUS_SPP_SHIFT);
        mstatus &= ~MSTATUS_SIE_MASK;
        a.write_mstatus(mstatus);
        set_priv(a, priv, PRV_S);
        a.write_pc(a.read_stvec());
#ifdef DUMP_COUNTERS
        if (cause & MCAUSE_INTERRUPT_FLAG) {
            a.get_naked_state().count_si++;
        } else {
            // Do not count environment calls
            if (cause >= MCAUSE_ECALL_BASE && cause <= MCAUSE_ECALL_BASE + PRV_M)
                a.get_naked_state().count_se++;
        }
#endif
    } else {
        a.write_mcause(cause);
        a.write_mepc(a.read_pc());
        a.write_mtval(tval);
        uint64_t mstatus = a.read_mstatus();
        mstatus = (mstatus & ~MSTATUS_MPIE_MASK) | (((mstatus >> priv) & 1) << MSTATUS_MPIE_SHIFT);
        mstatus = (mstatus & ~MSTATUS_MPP_MASK) | (priv << MSTATUS_MPP_SHIFT);
        mstatus &= ~MSTATUS_MIE_MASK;
        a.write_mstatus(mstatus);
        set_priv(a, priv, PRV_M);
        a.write_pc(a.read_mtvec());
#ifdef DUMP_COUNTERS
        if (cause & MCAUSE_INTERRUPT_FLAG) {
            a.get_naked_state().count_mi++;
        } else {
            // Do not count environment calls
            if (cause >= MCAUSE_ECALL_BASE && cause <= MCAUSE_ECALL_BASE + PRV_M)
                a.get_naked_state().count_me++;
        }
#endif
    }
}

/// \brief Obtains a mask of pending and enabled interrupts.
/// \param a Machine state accessor object.
/// \returns The mask.
template <typename STATE_ACCESS>
static inline uint32_t get_pending_irq_mask(STATE_ACCESS &a) {

    uint64_t mip = a.read_mip();
    uint64_t mie = a.read_mie();

    uint32_t pending_ints = mip & mie;
    if (pending_ints == 0)
        return 0;

    uint32_t enabled_ints = 0;
    auto priv = a.read_iflags_PRV();
    switch (priv) {
        case PRV_M: {
            uint64_t mstatus = a.read_mstatus();
            if (mstatus & MSTATUS_MIE_MASK) {
                enabled_ints = ~a.read_mideleg();
            }
            break;
        }
        case PRV_S: {
            uint64_t mstatus = a.read_mstatus();
            uint64_t mideleg = a.read_mideleg();
            // Interrupts not set in mideleg are machine-mode
            // and cannot be masked by supervisor mode
            enabled_ints = ~mideleg;
            if (mstatus & MSTATUS_SIE_MASK)
                enabled_ints |= mideleg;
            break;
        }
        default:
            assert(a.get_naked_state().iflags.PRV == PRV_U);
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

/// \brief Raises an interrupt if any are enabled and pending.
/// \param a Machine state accessor object.
template <typename STATE_ACCESS>
static void raise_interrupt_if_any(STATE_ACCESS &a) {
    auto note = a.make_scoped_note("raise_interrupt_if_any"); (void) note;
    uint32_t mask = get_pending_irq_mask(a);
    if (mask != 0) {
        uint64_t irq_num = ilog2(mask);
        raise_exception(a, irq_num | MCAUSE_INTERRUPT_FLAG, 0);
    }
}

/// \brief Obtains the RD field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_rd(uint32_t insn) {
    return (insn >> 7) & 0b11111;
}

/// \brief Obtains the RS1 field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_rs1(uint32_t insn) {
    return (insn >> 15) & 0b11111;
}

/// \brief Obtains the RS2 field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_rs2(uint32_t insn) {
    return (insn >> 20) & 0b11111;
}

/// \brief Obtains the immediate value from a I-type instruction.
/// \param insn Instruction.
static inline int32_t insn_I_get_imm(uint32_t insn) {
    return (int32_t)insn >> 20;
}

/// \brief Obtains the unsigned immediate value from a I-type instruction.
/// \param insn Instruction.
static inline uint32_t insn_I_get_uimm(uint32_t insn) {
    return insn >> 20;
}

/// \brief Obtains the immediate value from a U-type instruction.
/// \param insn Instruction.
static inline int32_t insn_U_get_imm(uint32_t insn) {
    return static_cast<int32_t>(insn & 0xfffff000);
}

/// \brief Obtains the immediate value from a B-type instruction.
/// \param insn Instruction.
static inline int32_t insn_B_get_imm(uint32_t insn) {
    int32_t imm = ((insn >> (31 - 12)) & (1 << 12)) |
        ((insn >> (25 - 5)) & 0x7e0) |
        ((insn >> (8 - 1)) & 0x1e) |
        ((insn << (11 - 7)) & (1 << 11));
    imm = (imm << 19) >> 19;
    return imm;
}

/// \brief Obtains the immediate value from a J-type instruction.
/// \param insn Instruction.
static inline int32_t insn_J_get_imm(uint32_t insn) {
    int32_t imm = ((insn >> (31 - 20)) & (1 << 20)) |
        ((insn >> (21 - 1)) & 0x7fe) |
        ((insn >> (20 - 11)) & (1 << 11)) |
        (insn & 0xff000);
    imm = (imm << 11) >> 11;
    return imm;
}

/// \brief Obtains the immediate value from a S-type instruction.
/// \param insn Instruction.
static inline int32_t insn_S_get_imm(uint32_t insn) {
    return (static_cast<int32_t>(insn & 0xfe000000) >> (25 - 5)) | ((insn >> 7) & 0b11111);
}

/// \brief Obtains the opcode field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_opcode(uint32_t insn) {
    //std::cerr << "opcode: " << std::bitset<7>(insn & 0b1111111) << '\n';
    return insn & 0b1111111;
}

/// \brief Obtains the funct3 field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct3(uint32_t insn) {
    //std::cerr << "funct3: " << std::bitset<3>((insn >> 12) & 0b111) << '\n';
    return (insn >> 12) & 0b111;
}

/// \brief Obtains the concatanation of funct3 and funct7 fields from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct3_funct7(uint32_t insn) {
    //std::cerr << "funct3_funct7: " << std::bitset<10>(((insn >> 5) & 0b1110000000) | (insn >> 24)) << '\n';
    return ((insn >> 5) & 0b1110000000) | (insn >> 25);
}

/// \brief Obtains the concatanation of funct3 and funct5 fields from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct3_funct5(uint32_t insn) {
    //std::cerr << "funct3_funct5: " << std::bitset<8>(((insn >> 7) & 0b11100000) | (insn >> 27)) << '\n';
    return ((insn >> 7) & 0b11100000) | (insn >> 27);
}

/// \brief Obtains the funct7 field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct7(uint32_t insn) {
    //std::cerr << "funct7: " << std::bitset<7>((insn >> 25) & 0b1111111) << '\n';
    return (insn >> 25) & 0b1111111;
}

/// \brief Obtains the funct6 field from an instruction.
/// \param insn Instruction.
/// \details I.e., the first 6 bits.
static inline uint32_t insn_get_funct6(uint32_t insn) {
    //std::cerr << "funct6: " << std::bitset<6>((insn >> 26) & 0b111111) << '\n';
    return (insn >> 26) & 0b111111;
}

/// \brief Read an aligned word from virtual memory.
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param vaddr Virtual address for word.
/// \param pval Pointer to word receiving value.
/// \returns True if succeeded, false otherwise.
template <typename T, typename STATE_ACCESS>
static inline bool read_virtual_memory(STATE_ACCESS &a, uint64_t vaddr, T *pval)  {
    using U = std::make_unsigned_t<T>;
    int tlb_idx = (vaddr >> PAGE_NUMBER_SHIFT) & (TLB_SIZE - 1);
    tlb_entry &tlb = a.get_naked_state().tlb_read[tlb_idx];
    if (!avoid_tlb<STATE_ACCESS>::value && tlb_hit<T>(tlb, vaddr)) {
        *pval = *reinterpret_cast<T *>(tlb.mem_addend + (uintptr_t)vaddr);
        return true;
    // No support for misaligned accesses: They are handled by a trap in BBL
    } else if (vaddr & (sizeof(T)-1)) {
        raise_exception(a, MCAUSE_LOAD_ADDRESS_MISALIGNED, vaddr);
        return false;
    // Deal with aligned accesses
    } else {
        uint64_t paddr;
        if (!translate_virtual_address(a, &paddr, vaddr, PTE_XWR_R_SHIFT)) {
            raise_exception(a, MCAUSE_LOAD_PAGE_FAULT, vaddr);
            return false;
        }
        pma_entry &pma = find_pma_entry<T>(a, paddr);
        if (pma.get_istart_E() || !pma.get_istart_R()) {
            raise_exception(a, MCAUSE_LOAD_ACCESS_FAULT, vaddr);
            return false;
        } else if (pma.get_istart_M()) {
            uintptr_t mem_addend = tlb_replace(pma, vaddr, paddr, tlb);
            uintptr_t haddr = mem_addend + static_cast<uintptr_t>(vaddr);
            a.read_memory(paddr, haddr, pval);
            return true;
        } else {
            uint64_t offset = paddr - pma.get_start();
            uint64_t val;
            virtual_state_access<STATE_ACCESS> da(a);
            // If we do not know how to read, we treat this as a PMA violation
            if (!pma.get_device().get_driver()->
                read(pma, &da, offset, &val, size_log2<U>::value)) {
                raise_exception(a, MCAUSE_LOAD_ACCESS_FAULT, vaddr);
                return false;
            }
            *pval = static_cast<T>(val);
            // device logs its own state accesses
            return true;
        }
    }
}

/// \brief Writes an aligned word to virtual memory.
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param vaddr Virtual address for word.
/// \param val Value to write.
/// \returns True if succeeded, false if exception raised.
template <typename T, typename STATE_ACCESS>
static inline bool write_virtual_memory(STATE_ACCESS &a, uint64_t vaddr, uint64_t val) {
    using U = std::make_unsigned_t<T>;
    uint32_t tlb_idx = (vaddr >> PAGE_NUMBER_SHIFT) & (TLB_SIZE - 1);
    tlb_entry &tlb = a.get_naked_state().tlb_write[tlb_idx];
    if (!avoid_tlb<STATE_ACCESS>::value && tlb_hit<T>(tlb, vaddr)) {
        *reinterpret_cast<T *>(tlb.mem_addend + (uintptr_t)vaddr) = static_cast<T>(val);
        return true;
    // No support for misaligned accesses: They are handled by a trap in BBL
    } else if (vaddr & (sizeof(T)-1)) {
        raise_exception(a, MCAUSE_STORE_AMO_ADDRESS_MISALIGNED, vaddr);
        return false;
    // Deal with aligned accesses
    } else {
        uint64_t paddr;
        if (!translate_virtual_address(a, &paddr, vaddr, PTE_XWR_W_SHIFT)) {
            raise_exception(a, MCAUSE_STORE_AMO_PAGE_FAULT, vaddr);
            return false;
        }
        pma_entry &pma = find_pma_entry<T>(a, paddr);
        if (pma.get_istart_E() || !pma.get_istart_W()) {
            raise_exception(a, MCAUSE_STORE_AMO_ACCESS_FAULT, vaddr);
            return false;
        } else if (pma.get_istart_M()) {
            uintptr_t mem_addend = tlb_replace(pma, vaddr, paddr, tlb);
            uintptr_t haddr = mem_addend + (uintptr_t) vaddr;
            // write to memory
            a.write_memory(paddr, haddr, static_cast<T>(val));
            return true;
        } else {
            uint64_t offset = paddr - pma.get_start();
            virtual_state_access<STATE_ACCESS> da(a);
            // If we do not know how to write, we treat this as a PMA violation
            if (!pma.get_device().get_driver()->
                write(pma, &da, offset, val, size_log2<U>::value)) {
                raise_exception(a, MCAUSE_STORE_AMO_ACCESS_FAULT, vaddr);
                return false;
            }
            return true;
        }
    }
}

static void dump_insn(machine &m, uint64_t pc, uint32_t insn, const char *name) {
    state_access a(m);
#ifdef DUMP_INSN
    fprintf(stderr, "%s\n", name);
    uint64_t ppc;
    if (!translate_virtual_address(a, &ppc, pc, PTE_XWR_C_SHIFT)) {
        ppc = pc;
        fprintf(stderr, "v    %08" PRIx64, ppc);
    } else {
        fprintf(stderr, "p    %08" PRIx64, ppc);
    }
    fprintf(stderr, ":   %08" PRIx32 "   ", insn);
    fprintf(stderr, "\n");
//    dump_regs(s);
#else
    (void) a;
    (void) pc;
    (void) insn;
    (void) name;
#endif
}

/// \brief Instruction fetch status code
enum class execute_status: int {
    illegal, ///< Illegal instruction: exception raised
    retired ///< Instruction was retired: exception may or may not have been raised
};

/// \brief Raises an illegal instruction exception.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return execute_status::illegal
/// \details This function is tail-called whenever the caller decoded enough of the instruction to identify it as illegal.
template <typename STATE_ACCESS>
static inline execute_status raise_illegal_insn_exception(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    (void) a; (void) pc;
    raise_exception(a, MCAUSE_ILLEGAL_INSN, insn);
    return execute_status::illegal;
}

/// \brief Raises an misaligned-fetch exception.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return execute_status::retired
/// \details This function is tail-called whenever the caller identified that the next value of pc is misaligned.
template <typename STATE_ACCESS>
static inline execute_status raise_misaligned_fetch_exception(STATE_ACCESS &a, uint64_t pc) {
    (void) a;
    raise_exception(a, MCAUSE_INSN_ADDRESS_MISALIGNED, pc);
    return execute_status::retired;
}

/// \brief Returns from execution due to raised exception.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param insn Instruction.
/// \return execute_status::retired
/// \details This function is tail-called whenever the caller identified a raised exception.
template <typename STATE_ACCESS>
static inline execute_status advance_to_raised_exception(STATE_ACCESS &a) {
    (void) a;
    return execute_status::retired;
}

/// \brief Advances pc to the next instruction.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return execute_status::retired
/// \details This function is tail-called whenever the caller wants move to the next instruction.
template <typename STATE_ACCESS>
static inline execute_status advance_to_next_insn(STATE_ACCESS &a, uint64_t pc) {
    a.write_pc(pc + 4);
    return execute_status::retired;
}

/// \brief Changes pc arbitrarily, potentially causing a jump.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return execute_status::retired
/// \details This function is tail-called whenever the caller wants to jump.
template <typename STATE_ACCESS>
static inline execute_status execute_jump(STATE_ACCESS &a, uint64_t pc) {
    a.write_pc(pc);
    return execute_status::retired;
}

/// \brief Execute the LR instruction.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
template <typename T, typename STATE_ACCESS>
static inline execute_status execute_LR(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    T val = 0;
    if (!read_virtual_memory<T>(a, vaddr, &val))
        return advance_to_raised_exception(a);
    a.write_ilrsc(vaddr);
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0)
        a.write_x(rd, static_cast<uint64_t>(val));
    return advance_to_next_insn(a, pc);
}

/// \brief Execute the SC instruction.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
template <typename T, typename STATE_ACCESS>
static inline execute_status execute_SC(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    uint64_t val = 0;
    uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    if (a.read_ilrsc() == vaddr) {
        if (!write_virtual_memory<T>(a, vaddr, static_cast<T>(a.read_x(insn_get_rs2(insn)))))
            return advance_to_raised_exception(a);
        a.write_ilrsc(-1);
    } else {
        val = 1;
    }
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0)
        a.write_x(rd, val);
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the LR.W instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_LR_W(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    (void) a; (void) pc; (void) insn;
    if ((insn & 0b00000001111100000000000000000000) == 0 ) {
        dump_insn(a.get_naked_machine(), pc, insn, "lr.w");
        auto note = a.make_scoped_note("lr.w"); (void) note;
        return execute_LR<int32_t>(a, pc, insn);
    } else {
        return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Implementation of the SC.W instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SC_W(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sc.w");
    auto note = a.make_scoped_note("sc.w"); (void) note;
    return execute_SC<int32_t>(a, pc, insn);
}

template <typename T, typename STATE_ACCESS, typename F>
static inline execute_status execute_AMO(STATE_ACCESS &a, uint64_t pc, uint32_t insn, const F &f) {
    uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    T valm = 0;
    if (!read_virtual_memory<T>(a, vaddr, &valm))
        return execute_status::retired;
    T valr = static_cast<T>(a.read_x(insn_get_rs2(insn)));
    valr = f(valm, valr);
    if (!write_virtual_memory<T>(a, vaddr, valr))
        return execute_status::retired;
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0)
        a.write_x(rd, static_cast<uint64_t>(valm));
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the AMOSWAP.W instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOSWAP_W(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amoswap.w");
    auto note = a.make_scoped_note("amoswap.w"); (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { (void) valm; return valr; });
}

/// \brief Implementation of the AMOADD.W instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOADD_W(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amoadd.w");
    auto note = a.make_scoped_note("amoadd.w"); (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm + valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOXOR_W(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm ^ valr; });
}

/// \brief Implementation of the AMOAND.W instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOAND_W(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amoand.w");
    auto note = a.make_scoped_note("amoand.w"); (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm & valr; });
}

/// \brief Implementation of the AMOOR.W instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOOR_W(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amoor.w");
    auto note = a.make_scoped_note("amoor.w"); (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm | valr; });
}

/// \brief Implementation of the AMOMIN.W instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOMIN_W(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amomin.w");
    auto note = a.make_scoped_note("amomin.w"); (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm < valr? valm: valr; });
}

/// \brief Implementation of the AMOMAX.W instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOMAX_W(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amomax.w");
    auto note = a.make_scoped_note("amomax.w"); (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm > valr? valm: valr; });
}

/// \brief Implementation of the AMOMINU.W instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOMINU_W(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amominu.w");
    auto note = a.make_scoped_note("amominu.w"); (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t {
        return static_cast<uint32_t>(valm) < static_cast<uint32_t>(valr)? valm: valr;
    });
}

/// \brief Implementation of the AMOMAXU.W instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOMAXU_W(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amomaxu.w");
    auto note = a.make_scoped_note("amomaxu.w"); (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t {
        return static_cast<uint32_t>(valm) > static_cast<uint32_t>(valr)? valm: valr;
    });
}

/// \brief Implementation of the LR.D instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_LR_D(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    if ((insn & 0b00000001111100000000000000000000) == 0 ) {
        dump_insn(a.get_naked_machine(), pc, insn, "lr.d");
        auto note = a.make_scoped_note("lr.d"); (void) note;
        return execute_LR<uint64_t>(a, pc, insn);
    } else {
        return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Implementation of the SC.D instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SC_D(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sc.d");
    auto note = a.make_scoped_note("sc.d"); (void) note;
    return execute_SC<uint64_t>(a, pc, insn);
}

/// \brief Implementation of the AMOSWAP.D instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOSWAP_D(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amoswap.d");
    auto note = a.make_scoped_note("amoswap.d"); (void) note;
    return execute_AMO<int64_t>(a, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { (void) valm; return valr; });
}

/// \brief Implementation of the AMOADD.D instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOADD_D(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amoadd.d");
    auto note = a.make_scoped_note("amoadd.d"); (void) note;
    return execute_AMO<int64_t>(a, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm + valr; });
}

template <typename STATE_ACCESS>
static inline execute_status execute_AMOXOR_D(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    return execute_AMO<int64_t>(a, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm ^ valr; });
}

/// \brief Implementation of the AMOAND.D instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOAND_D(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amoand.d");
    auto note = a.make_scoped_note("amoand.d"); (void) note;
    return execute_AMO<int64_t>(a, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm & valr; });
}

/// \brief Implementation of the AMOOR.D instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOOR_D(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amoor.d");
    auto note = a.make_scoped_note("amoor.d"); (void) note;
    return execute_AMO<int64_t>(a, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm | valr; });
}

/// \brief Implementation of the AMOMIN.D instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOMIN_D(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amomin.d");
    auto note = a.make_scoped_note("amomin.d"); (void) note;
    return execute_AMO<int64_t>(a, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm < valr? valm: valr; });
}

/// \brief Implementation of the AMOMAX.D instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOMAX_D(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amomax.d");
    auto note = a.make_scoped_note("amomax.d"); (void) note;
    return execute_AMO<int64_t>(a, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm > valr? valm: valr; });
}

/// \brief Implementation of the AMOMINU.D instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOMINU_D(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amominu.d");
    auto note = a.make_scoped_note("amominu.d"); (void) note;
    return execute_AMO<uint64_t>(a, pc, insn,
        [](uint64_t valm, uint64_t valr) -> uint64_t { return valm < valr? valm: valr; });
}

/// \brief Implementation of the AMOMAXU.D instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AMOMAXU_D(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "amomaxu.d");
    auto note = a.make_scoped_note("amomaxu.d"); (void) note;
    return execute_AMO<uint64_t>(a, pc, insn,
        [](uint64_t valm, uint64_t valr) -> uint64_t { return valm > valr? valm: valr; });
}

/// \brief Implementation of the ADDW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_ADDW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "addw");
    auto note = a.make_scoped_note("addw"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        // Discard upper 32 bits
        int32_t rs1w = static_cast<int32_t>(rs1);
        int32_t rs2w = static_cast<int32_t>(rs2);
        int32_t val = 0;
        __builtin_add_overflow(rs1w, rs2w, &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the SUBW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SUBW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "subw");
    auto note = a.make_scoped_note("subw"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        // Convert 64-bit to 32-bit
        int32_t rs1w = static_cast<int32_t>(rs1);
        int32_t rs2w = static_cast<int32_t>(rs2);
        int32_t val = 0;
        __builtin_sub_overflow(rs1w, rs2w, &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the SLLW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SLLW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sllw");
    auto note = a.make_scoped_note("sllw"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(rs1) << (rs2 & 31);
        return static_cast<uint64_t>(rs1w);
    });
}

/// \brief Implementation of the SRLW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SRLW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "srlw");
    auto note = a.make_scoped_note("srlw"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(static_cast<uint32_t>(rs1) >> (rs2 & 31));
        return static_cast<uint64_t>(rs1w);
    });
}

/// \brief Implementation of the SRAW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SRAW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sraw");
    auto note = a.make_scoped_note("sraw"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(rs1) >> (rs2 & 31);
        return static_cast<uint64_t>(rs1w);
    });
}

/// \brief Implementation of the MULW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_MULW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "mulw");
    auto note = a.make_scoped_note("mulw"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(rs1);
        int32_t rs2w = static_cast<int32_t>(rs2);
        int32_t val = 0;
        __builtin_mul_overflow(rs1w, rs2w, &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the DIVW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_DIVW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "divw");
    auto note = a.make_scoped_note("divw"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
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

/// \brief Implementation of the DIVUW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_DIVUW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "divuw");
    auto note = a.make_scoped_note("divuw"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        uint32_t rs1w = static_cast<uint32_t>(rs1);
        uint32_t rs2w = static_cast<uint32_t>(rs2);
        if (rs2w == 0) {
            return static_cast<uint64_t>(-1);
        } else {
            return static_cast<uint64_t>(static_cast<int32_t>(rs1w / rs2w));
        }
    });
}

/// \brief Implementation of the REMW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_REMW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "remw");
    auto note = a.make_scoped_note("remw"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
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

/// \brief Implementation of the REMUW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_REMUW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    (void) a; (void) pc; (void) insn;
    dump_insn(a.get_naked_machine(), pc, insn, "remuw");
    auto note = a.make_scoped_note("remuw"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
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
static inline bool rdcounteren(STATE_ACCESS &a, CSR_address csraddr) {
    uint64_t counteren = MCOUNTEREN_RW_MASK;
    auto priv = a.read_iflags_PRV();
    if (priv < PRV_M) {
        counteren &= a.read_mcounteren();
        if (priv < PRV_S) {
            counteren &= a.read_scounteren();
        }
    }
    return (((counteren >> (static_cast<int>(csraddr) & 0x1f)) & 1) != 0);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_cycle(STATE_ACCESS &a, CSR_address csraddr, bool *status) {
    if (rdcounteren(a, csraddr)) {
        return read_csr_success(a.read_mcycle(), status);
    } else {
        return read_csr_fail(status);
    }
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_instret(STATE_ACCESS &a, CSR_address csraddr, bool *status) {
    if (rdcounteren(a, csraddr)) {
        return read_csr_success(a.read_minstret(), status);
    } else {
        return read_csr_fail(status);
    }
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_time(STATE_ACCESS &a, CSR_address csraddr, bool *status) {
    if (rdcounteren(a, csraddr)) {
        uint64_t mtime = rtc_cycle_to_time(a.read_mcycle());
        return read_csr_success(mtime, status);
    } else {
        return read_csr_fail(status);
    }
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sstatus(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mstatus() & SSTATUS_R_MASK, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sie(STATE_ACCESS &a, bool *status) {
    uint64_t mie = a.read_mie();
    uint64_t mideleg = a.read_mideleg();
    return read_csr_success(mie & mideleg, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_stvec(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_stvec(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_scounteren(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_scounteren(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sscratch(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_sscratch(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sepc(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_sepc(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_scause(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_scause(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_stval(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_stval(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sip(STATE_ACCESS &a, bool *status) {
    // Ensure values are are loaded in order: do not nest with operator
    uint64_t mip = a.read_mip();
    uint64_t mideleg = a.read_mideleg();
    return read_csr_success(mip & mideleg, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_satp(STATE_ACCESS &a, bool *status) {
    uint64_t mstatus = a.read_mstatus();
    auto priv = a.read_iflags_PRV();
    if (priv == PRV_S && (mstatus & MSTATUS_TVM_MASK)) {
        return read_csr_fail(status);
    } else {
        return read_csr_success(a.read_satp(), status);
    }
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mstatus(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mstatus() & MSTATUS_R_MASK, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_misa(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_misa(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_medeleg(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_medeleg(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mideleg(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mideleg(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mie(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mie(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mtvec(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mtvec(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mcounteren(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mcounteren(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mscratch(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mscratch(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mepc(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mepc(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mcause(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mcause(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mtval(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mtval(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mip(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mip(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mcycle(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mcycle(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_minstret(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_minstret(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mvendorid(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mvendorid(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_marchid(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_marchid(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mimpid(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mimpid(), status);
}

/// \brief Reads the value of a CSR given its address
/// \param a Machine state accessor object.
/// \param csraddr Address of CSR in file.
/// \param status Returns the status of the operation (true for success, false otherwise).
/// \returns Register value.
template <typename STATE_ACCESS>
static uint64_t read_csr(STATE_ACCESS &a, CSR_address csraddr, bool *status) {

    if (csr_priv(csraddr) > a.read_iflags_PRV())
        return read_csr_fail(status);

    switch (csraddr) {
        case CSR_address::ucycle: return read_csr_cycle(a, csraddr, status);
        case CSR_address::uinstret: return read_csr_instret(a, csraddr, status);
        case CSR_address::utime: return read_csr_time(a, csraddr, status);

        case CSR_address::sstatus: return read_csr_sstatus(a, status);
        case CSR_address::sie: return read_csr_sie(a, status);
        case CSR_address::stvec: return read_csr_stvec(a, status);
        case CSR_address::scounteren: return read_csr_scounteren(a, status);
        case CSR_address::sscratch: return read_csr_sscratch(a, status);
        case CSR_address::sepc: return read_csr_sepc(a, status);
        case CSR_address::scause: return read_csr_scause(a, status);
        case CSR_address::stval: return read_csr_stval(a, status);
        case CSR_address::sip: return read_csr_sip(a, status);
        case CSR_address::satp: return read_csr_satp(a, status);

        case CSR_address::mstatus: return read_csr_mstatus(a, status);
        case CSR_address::misa: return read_csr_misa(a, status);
        case CSR_address::medeleg: return read_csr_medeleg(a, status);
        case CSR_address::mideleg: return read_csr_mideleg(a, status);
        case CSR_address::mie: return read_csr_mie(a, status);
        case CSR_address::mtvec: return read_csr_mtvec(a, status);
        case CSR_address::mcounteren: return read_csr_mcounteren(a, status);

        case CSR_address::mscratch: return read_csr_mscratch(a, status);
        case CSR_address::mepc: return read_csr_mepc(a, status);
        case CSR_address::mcause: return read_csr_mcause(a, status);
        case CSR_address::mtval: return read_csr_mtval(a, status);
        case CSR_address::mip: return read_csr_mip(a, status);

        case CSR_address::mcycle: return read_csr_mcycle(a, status);
        case CSR_address::minstret: return read_csr_minstret(a, status);

        case CSR_address::mvendorid: return read_csr_mvendorid(a, status);
        case CSR_address::marchid: return read_csr_marchid(a, status);
        case CSR_address::mimpid: return read_csr_mimpid(a, status);

        // All hardwired to zero
        case CSR_address::tselect:
        case CSR_address::tdata1:
        case CSR_address::tdata2:
        case CSR_address::tdata3:
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
static bool write_csr_sstatus(STATE_ACCESS &a, uint64_t val) {
    uint64_t mstatus = a.read_mstatus();
    return write_csr_mstatus(a, (mstatus & ~SSTATUS_W_MASK) | (val & SSTATUS_W_MASK));
}

template <typename STATE_ACCESS>
static bool write_csr_sie(STATE_ACCESS &a, uint64_t val) {
    uint64_t mask = a.read_mideleg();
    uint64_t mie = a.read_mie();
    a.write_mie((mie & ~mask) | (val & mask));
    a.get_naked_state().set_brk_from_mip_mie();
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_stvec(STATE_ACCESS &a, uint64_t val) {
    a.write_stvec(val & ~3);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_scounteren(STATE_ACCESS &a, uint64_t val) {
    a.write_scounteren(val & SCOUNTEREN_RW_MASK);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_sscratch(STATE_ACCESS &a, uint64_t val) {
    a.write_sscratch(val);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_sepc(STATE_ACCESS &a, uint64_t val) {
    a.write_sepc(val & ~3);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_scause(STATE_ACCESS &a, uint64_t val) {
    a.write_scause(val);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_stval(STATE_ACCESS &a, uint64_t val) {
    a.write_stval(val);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_sip(STATE_ACCESS &a, uint64_t val) {
    uint64_t mask = a.read_mideleg();
    uint64_t mip = a.read_mip();
    mip = (mip & ~mask) | (val & mask);
    a.write_mip(mip);
    a.get_naked_state().set_brk_from_mip_mie();
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_satp(STATE_ACCESS &a, uint64_t val) {
    uint64_t satp = a.read_satp();
    int mode = satp >> 60;
    int new_mode = (val >> 60) & 0xf;
    if (new_mode == 0 || (new_mode >= 8 && new_mode <= 9))
        mode = new_mode;
    // no ASID implemented
    a.write_satp((val & (((uint64_t)1 << 44) - 1)) | ((uint64_t)mode << 60));
    // Since MMU configuration was changted, flush the TLBs
    // This does not need to be done within the blockchain
    tlb_flush_all(a.get_naked_state());
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mstatus(STATE_ACCESS &a, uint64_t val) {
    uint64_t mstatus = a.read_mstatus() & MSTATUS_R_MASK;

    // If MMU configuration was changed, flush the TLBs
    // This does not need to be done within the blockchain
    uint64_t mod = mstatus ^ val;
    if ((mod & (MSTATUS_MPRV_MASK | MSTATUS_SUM_MASK | MSTATUS_MXR_MASK)) != 0 ||
        ((mstatus & MSTATUS_MPRV_MASK) && (mod & MSTATUS_MPP_MASK) != 0)) {
        tlb_flush_all(a.get_naked_state());
    }

    // Modify only bits that can be written to
    mstatus = (mstatus & ~MSTATUS_W_MASK) | (val & MSTATUS_W_MASK);
    // Update the SD bit
    if ((mstatus & MSTATUS_FS_MASK) == MSTATUS_FS_MASK) mstatus |= MSTATUS_SD_MASK;
    // Store results
    a.write_mstatus(mstatus);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_medeleg(STATE_ACCESS &a, uint64_t val) {
    const uint64_t mask = (1 << (MCAUSE_STORE_AMO_PAGE_FAULT + 1)) - 1;
    a.write_medeleg((a.read_medeleg() & ~mask) | (val & mask));
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mideleg(STATE_ACCESS &a, uint64_t val) {
    const uint64_t mask = MIP_SSIP_MASK | MIP_STIP_MASK | MIP_SEIP_MASK;
    a.write_mideleg((a.read_mideleg() & ~mask) | (val & mask));
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mie(STATE_ACCESS &a, uint64_t val) {
    const uint64_t mask = MIP_MSIP_MASK | MIP_MTIP_MASK | MIP_SSIP_MASK | MIP_STIP_MASK | MIP_SEIP_MASK;
    a.write_mie((a.read_mie() & ~mask) | (val & mask));
    a.get_naked_state().set_brk_from_mip_mie();
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mtvec(STATE_ACCESS &a, uint64_t val) {
    a.write_mtvec(val & ~3);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mcounteren(STATE_ACCESS &a, uint64_t val) {
    a.write_mcounteren(val & MCOUNTEREN_RW_MASK);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_minstret(STATE_ACCESS &a, uint64_t val) {
    // In Spike, QEMU, and riscvemu, mcycle and minstret are the aliases for the same counter
    // QEMU calls exit (!) on writes to mcycle or minstret
    a.write_minstret(val-1); // The value will be incremented after the instruction is executed
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mcycle(STATE_ACCESS &a, uint64_t val) {
    // We can't allow writes to mcycle because we use it to measure the progress in machine execution.
    // The specs say it is an MRW CSR, read-writeable in M-mode.
    // BBL enables all counters in both M- and S-modes.
    // In Spike, QEMU, and riscvemu, mcycle and minstret are the aliases for the same counter.
    // QEMU calls exit (!) on writes to mcycle or minstret.
    // We instead raise an exception.
    (void) a; (void) val;
    return false;
}

template <typename STATE_ACCESS>
static bool write_csr_mscratch(STATE_ACCESS &a, uint64_t val) {
    a.write_mscratch(val);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mepc(STATE_ACCESS &a, uint64_t val) {
    a.write_mepc(val & ~3);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mcause(STATE_ACCESS &a, uint64_t val) {
    a.write_mcause(val);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mtval(STATE_ACCESS &a, uint64_t val) {
    a.write_mtval(val);
    return true;
}

template <typename STATE_ACCESS>
static bool write_csr_mip(STATE_ACCESS &a, uint64_t val) {
    const uint64_t mask = MIP_SSIP_MASK | MIP_STIP_MASK;
    uint64_t mip = a.read_mip();
    mip = (mip & ~mask) | (val & mask);
    a.write_mip(mip);
    a.get_naked_state().set_brk_from_mip_mie();
    return true;
}

/// \brief Writes a value to a CSR given its address
/// \param a Machine state accessor object.
/// \param csraddr Address of CSR in file.
/// \param val New register value.
/// \returns The status of the operation (true for success, false otherwise).
template <typename STATE_ACCESS>
static bool write_csr(STATE_ACCESS &a, CSR_address csraddr, uint64_t val) {
#if defined(DUMP_CSR)
    fprintf(stderr, "csr_write: csr=0x%03x val=0x", static_cast<int>(csraddr));
    print_uint64_t(val);
    fprintf(stderr, "\n");
#endif
    if (csr_is_read_only(csraddr)) return false;
    if (csr_priv(csraddr) > a.read_iflags_PRV()) return false;

    switch (csraddr) {
        case CSR_address::sstatus: return write_csr_sstatus(a, val);
        case CSR_address::sie: return write_csr_sie(a, val);
        case CSR_address::stvec: return write_csr_stvec(a, val);
        case CSR_address::scounteren: return write_csr_scounteren(a, val);

        case CSR_address::sscratch: return write_csr_sscratch(a, val);
        case CSR_address::sepc: return write_csr_sepc(a, val);
        case CSR_address::scause: return write_csr_scause(a, val);
        case CSR_address::stval: return write_csr_stval(a, val);
        case CSR_address::sip: return write_csr_sip(a, val);

        case CSR_address::satp: return write_csr_satp(a, val);

        case CSR_address::mstatus: return write_csr_mstatus(a, val);
        case CSR_address::medeleg: return write_csr_medeleg(a, val);
        case CSR_address::mideleg: return write_csr_mideleg(a, val);
        case CSR_address::mie: return write_csr_mie(a, val);
        case CSR_address::mtvec: return write_csr_mtvec(a, val);
        case CSR_address::mcounteren: return write_csr_mcounteren(a, val);

        case CSR_address::mscratch: return write_csr_mscratch(a, val);
        case CSR_address::mepc: return write_csr_mepc(a, val);
        case CSR_address::mcause: return write_csr_mcause(a, val);
        case CSR_address::mtval: return write_csr_mtval(a, val);
        case CSR_address::mip: return write_csr_mip(a, val);

        case CSR_address::mcycle: return write_csr_mcycle(a, val);
        case CSR_address::minstret: return write_csr_minstret(a, val);

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
        //case CSR_address::mimpid: // read-only
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
static inline execute_status execute_csr_RW(STATE_ACCESS &a, uint64_t pc, uint32_t insn, const RS1VAL &rs1val) {
    CSR_address csraddr = static_cast<CSR_address>(insn_I_get_uimm(insn));
    // Try to read old CSR value
    bool status = true;
    uint64_t csrval = 0;
    // If rd=r0, we do not read from the CSR to avoid side-effects
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0)
        csrval = read_csr(a, csraddr, &status);
    if (!status)
        return raise_illegal_insn_exception(a, pc, insn);
    // Try to write new CSR value
    //??D When we optimize the inner interpreter loop, we
    //    will have to check if there was a change to the
    //    memory manager and report back from here so we
    //    break out of the inner loop
    if (!write_csr(a, csraddr, rs1val(a, insn)))
        return raise_illegal_insn_exception(a, pc, insn);
    if (rd != 0)
        a.write_x(rd, csrval);
    return advance_to_next_insn(a, pc);

}

/// \brief Implementation of the CSRRW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_CSRRW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "csrrw");
    auto note = a.make_scoped_note("csrrw"); (void) note;
    return execute_csr_RW(a, pc, insn,
        [](STATE_ACCESS &a, uint32_t insn) -> uint64_t { return a.read_x(insn_get_rs1(insn)); }
    );
}

/// \brief Implementation of the CSRRWI instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_CSRRWI(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "csrrwi");
    auto note = a.make_scoped_note("csrrwi"); (void) note;
    return execute_csr_RW(a, pc, insn,
        [](STATE_ACCESS, uint32_t insn) -> uint64_t { return static_cast<uint64_t>(insn_get_rs1(insn)); }
    );
}

template <typename STATE_ACCESS, typename F>
static inline execute_status execute_csr_SC(STATE_ACCESS &a, uint64_t pc, uint32_t insn, const F &f) {
    CSR_address csraddr = static_cast<CSR_address>(insn_I_get_uimm(insn));
    // Try to read old CSR value
    bool status = false;
    uint64_t csrval = read_csr(a, csraddr, &status);
    if (!status)
        return raise_illegal_insn_exception(a, pc, insn);
    // Load value of rs1 before potentially overwriting it
    // with the value of the csr when rd=rs1
    uint32_t rs1 = insn_get_rs1(insn);
    uint64_t rs1val = a.read_x(rs1);
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0)
        a.write_x(rd, csrval);
    if (rs1 != 0) {
        //??D When we optimize the inner interpreter loop, we
        //    will have to check if there was a change to the
        //    memory manager and report back from here so we
        //    break out of the inner loop
        if (!write_csr(a, csraddr, f(csrval, rs1val)))
            return raise_illegal_insn_exception(a, pc, insn);
    }
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the CSRRS instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_CSRRS(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "csrrs");
    auto note = a.make_scoped_note("csrrs"); (void) note;
    return execute_csr_SC(a, pc, insn, [](uint64_t csr, uint64_t rs1) -> uint64_t { return csr | rs1; });
}

/// \brief Implementation of the CSRRC instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_CSRRC(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "csrrc");
    auto note = a.make_scoped_note("csrrc"); (void) note;
    return execute_csr_SC(a, pc, insn, [](uint64_t csr, uint64_t rs1) -> uint64_t {
        return csr & ~rs1;
    });
}

template <typename STATE_ACCESS, typename F>
static inline execute_status execute_csr_SCI(STATE_ACCESS &a, uint64_t pc, uint32_t insn, const F &f) {
    CSR_address csraddr = static_cast<CSR_address>(insn_I_get_uimm(insn));
    // Try to read old CSR value
    bool status = false;
    uint64_t csrval = read_csr(a, csraddr, &status);
    if (!status)
        return raise_illegal_insn_exception(a, pc, insn);
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0)
        a.write_x(rd, csrval);
    uint32_t rs1 = insn_get_rs1(insn);
    if (rs1 != 0) {
        //??D When we optimize the inner interpreter loop, we
        //    will have to check if there was a change to the
        //    memory manager and report back from here so we
        //    break out of the inner loop
        if (!write_csr(a, csraddr, f(csrval, rs1)))
            return raise_illegal_insn_exception(a, pc, insn);
    }
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the CSRRSI instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_CSRRSI(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "csrrsi");
    auto note = a.make_scoped_note("csrrsi"); (void) note;
    return execute_csr_SCI(a, pc, insn, [](uint64_t csr, uint32_t rs1) -> uint64_t { return csr | rs1; });
}

/// \brief Implementation of the CSRRCI instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_CSRRCI(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "csrrci");
    auto note = a.make_scoped_note("csrrci"); (void) note;
    return execute_csr_SCI(a, pc, insn, [](uint64_t csr, uint32_t rs1) -> uint64_t { return csr & ~rs1; });
}

/// \brief Implementation of the ECALL instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_ECALL(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "ecall");
    auto note = a.make_scoped_note("ecall"); (void) note;
    //??D Need another version of raise_exception that does not modify mtval
    auto priv = a.read_iflags_PRV();
    uint64_t mtval = a.read_mtval();
    raise_exception(a, MCAUSE_ECALL_BASE + priv, mtval);
    return execute_status::retired;
}

/// \brief Implementation of the EBREAK instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_EBREAK(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    (void) a;
    dump_insn(a.get_naked_machine(), pc, insn, "ebreak");
    auto note = a.make_scoped_note("ebreak"); (void) note;
    //??D Need another version of raise_exception that does not modify mtval
    raise_exception(a, MCAUSE_BREAKPOINT, a.read_mtval());
    return execute_status::retired;
}

/// \brief Implementation of the URET instruction. // no U-mode traps
template <typename STATE_ACCESS>
static inline execute_status execute_URET(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "uret");
    auto note = a.make_scoped_note("uret"); (void) note;
    return raise_illegal_insn_exception(a, pc, insn);
}

/// \brief Implementation of the SRET instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SRET(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sret");
    auto note = a.make_scoped_note("sret"); (void) note;
    auto priv = a.read_iflags_PRV();
    uint64_t mstatus = a.read_mstatus();
    if (priv < PRV_S || (priv == PRV_S && (mstatus & MSTATUS_TSR_MASK))) {
        return raise_illegal_insn_exception(a, pc, insn);
    } else {
        int spp = (mstatus & MSTATUS_SPP_MASK) >> MSTATUS_SPP_SHIFT;
        /* set the IE state to previous IE state */
        int spie = (mstatus & MSTATUS_SPIE_MASK) >> MSTATUS_SPIE_SHIFT;
        mstatus = (mstatus & ~MSTATUS_SIE_MASK) | (spie << MSTATUS_SIE_SHIFT);
        /* set SPIE to 1 */
        mstatus |= MSTATUS_SPIE_MASK;
        /* set SPP to U */
        mstatus &= ~MSTATUS_SPP_MASK;
        a.write_mstatus( mstatus);
        set_priv(a, priv, spp);
        a.write_pc(a.read_sepc());
        return execute_status::retired;
    }
}

/// \brief Implementation of the MRET instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_MRET(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "mret");
    auto note = a.make_scoped_note("mret"); (void) note;
    auto priv = a.read_iflags_PRV();
    if (priv < PRV_M) {
        return raise_illegal_insn_exception(a, pc, insn);
    } else {
        uint64_t mstatus = a.read_mstatus();
        int mpp = (mstatus & MSTATUS_MPP_MASK) >> MSTATUS_MPP_SHIFT;
        /* set the IE state to previous IE state */
        int mpie = (mstatus & MSTATUS_MPIE_MASK) >> MSTATUS_MPIE_SHIFT;
        mstatus = (mstatus & ~MSTATUS_MIE_MASK) | (mpie << MSTATUS_MIE_SHIFT);
        /* set MPIE to 1 */
        mstatus |= MSTATUS_MPIE_MASK;
        /* set MPP to U */
        mstatus &= ~MSTATUS_MPP_MASK;
        a.write_mstatus(mstatus);
        set_priv(a, priv, mpp);
        a.write_pc(a.read_mepc());
        return execute_status::retired;
    }
}

/// \brief Implementation of the WFI instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_WFI(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "wfi");
    auto note = a.make_scoped_note("wfi"); (void) note;
    auto priv = a.read_iflags_PRV();
    uint64_t mstatus = a.read_mstatus();
    if (priv == PRV_U || (priv == PRV_S && (mstatus & MSTATUS_TW_MASK)))
        return raise_illegal_insn_exception(a, pc, insn);
    uint64_t mip = a.read_mip();
    uint64_t mie = a.read_mie();
    // Go to power down if no enabled interrupts are pending
    if ((mip & mie) == 0) {
        a.set_iflags_I();
        a.get_naked_state().brk = true; // set brk so the outer loop can skip time if it wants too
    }
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the FENCE instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_FENCE(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    (void) insn;
    dump_insn(a.get_naked_machine(), pc, insn, "fence");
    auto note = a.make_scoped_note("fence"); (void) note;
    // Really do nothing
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the FENCE.I instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_FENCE_I(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    (void) insn;
    dump_insn(a.get_naked_machine(), pc, insn, "fence.i");
    auto note = a.make_scoped_note("fence.i"); (void) note;
    // Really do nothing
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS, typename F>
static inline execute_status execute_arithmetic(STATE_ACCESS &a, uint64_t pc, uint32_t insn, const F &f) {
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        // Ensure rs1 and rs2 are loaded in order: do not nest with call to f() as
        // the order of evaluation of arguments in a function call is undefined.
        uint64_t rs1 = a.read_x(insn_get_rs1(insn));
        uint64_t rs2 = a.read_x(insn_get_rs2(insn));
        // Now we can safely invoke f()
        a.write_x(rd, f(rs1, rs2));
    }
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the ADD instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_ADD(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "add");
    auto note = a.make_scoped_note("add"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        uint64_t val = 0;
        __builtin_add_overflow(rs1, rs2, &val);
        return val;
    });
}

/// \brief Implementation of the SUB instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SUB(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sub");
    auto note = a.make_scoped_note("sub"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        uint64_t val = 0;
        __builtin_sub_overflow(rs1, rs2, &val);
        return val;
    });
}

/// \brief Implementation of the SLL instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SLL(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sll");
    auto note = a.make_scoped_note("sll"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return rs1 << (rs2 & (XLEN-1));
    });
}

/// \brief Implementation of the SLT instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SLT(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "slt");
    auto note = a.make_scoped_note("slt"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return static_cast<int64_t>(rs1) < static_cast<int64_t>(rs2);
    });
}

/// \brief Implementation of the SLTU instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SLTU(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sltu");
    auto note = a.make_scoped_note("sltu"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return rs1 < rs2;
    });
}

/// \brief Implementation of the XOR instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_XOR(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "xor");
    auto note = a.make_scoped_note("xor"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return rs1 ^ rs2;
    });
}

/// \brief Implementation of the SRL instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SRL(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "srl");
    auto note = a.make_scoped_note("srl"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return rs1 >> (rs2 & (XLEN-1));
    });
}

/// \brief Implementation of the SRA instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SRA(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sra");
    auto note = a.make_scoped_note("sra"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return static_cast<uint64_t>(static_cast<int64_t>(rs1) >> (rs2 & (XLEN-1)));
    });
}

/// \brief Implementation of the OR instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_OR(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "or");
    auto note = a.make_scoped_note("or"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return rs1 | rs2;
    });
}

/// \brief Implementation of the AND instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AND(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "and");
    auto note = a.make_scoped_note("and"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return rs1 & rs2;
    });
}

/// \brief Implementation of the MUL instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_MUL(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "mul");
    auto note = a.make_scoped_note("mul"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int64_t srs1 = static_cast<int64_t>(rs1);
        int64_t srs2 = static_cast<int64_t>(rs2);
        int64_t val = 0;
        __builtin_mul_overflow(srs1, srs2, &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the MULH instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_MULH(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "mulh");
    auto note = a.make_scoped_note("mulh"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int64_t srs1 = static_cast<int64_t>(rs1);
        int64_t srs2 = static_cast<int64_t>(rs2);
        return static_cast<uint64_t>((static_cast<int128_t>(srs1) * static_cast<int128_t>(srs2)) >> 64);
    });
}

/// \brief Implementation of the MULHSU instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_MULHSU(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "mulhsu");
    auto note = a.make_scoped_note("mulhsu"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int64_t srs1 = static_cast<int64_t>(rs1);
        return static_cast<uint64_t>((static_cast<int128_t>(srs1) * static_cast<int128_t>(rs2)) >> 64);
    });
}

/// \brief Implementation of the MULHU instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_MULHU(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "mulhu");
    auto note = a.make_scoped_note("mulhu"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return static_cast<uint64_t>((static_cast<int128_t>(rs1) * static_cast<int128_t>(rs2)) >> 64);
    });
}

/// \brief Implementation of the DIV instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_DIV(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "div");
    auto note = a.make_scoped_note("div"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
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

/// \brief Implementation of the DIVU instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_DIVU(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "divu");
    auto note = a.make_scoped_note("divu"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        if (rs2 == 0) {
            return static_cast<uint64_t>(-1);
        } else {
            return rs1 / rs2;
        }
    });
}

/// \brief Implementation of the REM instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_REM(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "rem");
    auto note = a.make_scoped_note("rem"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
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

/// \brief Implementation of the REMU instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_REMU(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "remu");
    auto note = a.make_scoped_note("remu"); (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        if (rs2 == 0) {
            return rs1;
        } else {
            return rs1 % rs2;
        }
    });
}

template <typename STATE_ACCESS, typename F>
static inline execute_status execute_arithmetic_immediate(STATE_ACCESS &a, uint64_t pc, uint32_t insn, const F &f) {
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        uint64_t rs1 = a.read_x(insn_get_rs1(insn));
        int32_t imm = insn_I_get_imm(insn);
        a.write_x(rd, f(rs1, imm));
    }
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the SRLI instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SRLI(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "srli");
    auto note = a.make_scoped_note("srli"); (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return rs1 >> (imm & (XLEN - 1));
    });
}

/// \brief Implementation of the SRAI instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SRAI(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "srai");
    auto note = a.make_scoped_note("srai"); (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return static_cast<uint64_t>(static_cast<int64_t>(rs1) >> (imm & (XLEN - 1)));
    });
}

/// \brief Implementation of the ADDI instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_ADDI(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "addi");
    auto note = a.make_scoped_note("addi"); (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return rs1+imm;
    });
}

/// \brief Implementation of the SLTI instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SLTI(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "slti");
    auto note = a.make_scoped_note("slti"); (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return static_cast<int64_t>(rs1) < static_cast<int64_t>(imm);
    });
}

/// \brief Implementation of the SLTIU instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SLTIU(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sltiu");
    auto note = a.make_scoped_note("sltiu"); (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return rs1 < static_cast<uint64_t>(imm);
    });
}

/// \brief Implementation of the XORI instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_XORI(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "xori");
    auto note = a.make_scoped_note("xori"); (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return rs1 ^ imm;
    });
}

/// \brief Implementation of the ORI instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_ORI(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "ori");
    auto note = a.make_scoped_note("ori"); (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return rs1 | imm;
    });
}

/// \brief Implementation of the ANDI instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_ANDI(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "andi");
    auto note = a.make_scoped_note("andi"); (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return rs1 & imm;
    });
}

/// \brief Implementation of the SLLI instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SLLI(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    if ((insn & (0b111111 << 26)) == 0) {
        dump_insn(a.get_naked_machine(), pc, insn, "slli");
        auto note = a.make_scoped_note("slli"); (void) note;
        return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
            // No need to mask lower 6 bits in imm because of the if condition a above
            // We do it anyway here to prevent problems if this code is moved
            return rs1 << (imm & 0b111111);
        });
    } else {
        return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Implementation of the ADDIW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_ADDIW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "addiw");
    auto note = a.make_scoped_note("addiw"); (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return static_cast<uint64_t>(static_cast<int32_t>(rs1) + imm);
    });
}

/// \brief Implementation of the SLLIW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SLLIW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    if (insn_get_funct7(insn) == 0) {
        dump_insn(a.get_naked_machine(), pc, insn, "slliw");
        auto note = a.make_scoped_note("slliw"); (void) note;
        return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
            // No need to mask lower 5 bits in imm because of the if condition a above
            // We do it anyway here to prevent problems if this code is moved
            int32_t rs1w = static_cast<int32_t>(rs1) << (imm & 0b11111);
            return static_cast<uint64_t>(rs1w);
        });
    } else {
        return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Implementation of the SRLIW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SRLIW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "srliw");
    auto note = a.make_scoped_note("srliw"); (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        // No need to mask lower 5 bits in imm because of funct7 test in caller
        // We do it anyway here to prevent problems if this code is moved
        int32_t rs1w = static_cast<int32_t>(static_cast<uint32_t>(rs1) >> (imm & 0b11111));
        return static_cast<uint64_t>(rs1w);
    });
}

/// \brief Implementation of the SRAIW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SRAIW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sraiw");
    auto note = a.make_scoped_note("sraiw"); (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(rs1) >> (imm & 0b11111);
        return static_cast<uint64_t>(rs1w);
    });
}

template <typename T, typename STATE_ACCESS>
static inline execute_status execute_S(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    int32_t imm = insn_S_get_imm(insn);
    uint64_t val = a.read_x(insn_get_rs2(insn));
    if (write_virtual_memory<T>(a, vaddr+imm, val)) {
        return advance_to_next_insn(a, pc);
    } else {
        return advance_to_raised_exception(a);
    }
}

/// \brief Implementation of the SB instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SB(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sb");
    auto note = a.make_scoped_note("sb"); (void) note;
    return execute_S<uint8_t>(a, pc, insn);
}

/// \brief Implementation of the SH instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SH(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sh");
    auto note = a.make_scoped_note("sh"); (void) note;
    return execute_S<uint16_t>(a, pc, insn);
}

/// \brief Implementation of the SW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sw");
    auto note = a.make_scoped_note("sw"); (void) note;
    return execute_S<uint32_t>(a, pc, insn);
}

/// \brief Implementation of the SD instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_SD(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "sd");
    auto note = a.make_scoped_note("sd"); (void) note;
    return execute_S<uint64_t>(a, pc, insn);
}

template <typename T, typename STATE_ACCESS>
static inline execute_status execute_L(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    int32_t imm = insn_I_get_imm(insn);
    T val;
    if (read_virtual_memory<T>(a, vaddr+imm, &val)) {
        // This static branch is eliminated by the compiler
        if (std::is_signed<T>::value) {
            a.write_x(insn_get_rd(insn), static_cast<int64_t>(val));
        } else {
            a.write_x(insn_get_rd(insn), static_cast<uint64_t>(val));
        }
        return advance_to_next_insn(a, pc);
    } else {
        return advance_to_raised_exception(a);
    }
}

/// \brief Implementation of the LB instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_LB(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "lb");
    auto note = a.make_scoped_note("lb"); (void) note;
    return execute_L<int8_t>(a, pc, insn);
}

/// \brief Implementation of the LH instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_LH(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "lh");
    auto note = a.make_scoped_note("lh"); (void) note;
    return execute_L<int16_t>(a, pc, insn);
}

/// \brief Implementation of the LW instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_LW(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "lw");
    auto note = a.make_scoped_note("lw"); (void) note;
    return execute_L<int32_t>(a, pc, insn);
}

/// \brief Implementation of the LD instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_LD(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "ld");
    auto note = a.make_scoped_note("ld"); (void) note;
    return execute_L<int64_t>(a, pc, insn);
}

/// \brief Implementation of the LBU instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_LBU(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "lbu");
    auto note = a.make_scoped_note("lbu"); (void) note;
    return execute_L<uint8_t>(a, pc, insn);
}

/// \brief Implementation of the LHU instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_LHU(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "lhu");
    auto note = a.make_scoped_note("lhu"); (void) note;
    return execute_L<uint16_t>(a, pc, insn);
}

/// \brief Implementation of the LWU instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_LWU(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "lwu");
    auto note = a.make_scoped_note("lwu"); (void) note;
    return execute_L<uint32_t>(a, pc, insn);
}

template <typename STATE_ACCESS, typename F>
static inline execute_status execute_branch(STATE_ACCESS &a, uint64_t pc, uint32_t insn, const F &f) {
    uint64_t rs1 = a.read_x(insn_get_rs1(insn));
    uint64_t rs2 = a.read_x(insn_get_rs2(insn));
    if (f(rs1, rs2)) {
        uint64_t new_pc = (int64_t)(pc + insn_B_get_imm(insn));
        if (new_pc & 3) {
            return raise_misaligned_fetch_exception(a, new_pc);
        } else {
            return execute_jump(a, new_pc);
        }
    }
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the BEQ instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_BEQ(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "beq");
    auto note = a.make_scoped_note("beq"); (void) note;
    return execute_branch(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool { return rs1 == rs2; });
}


/// \brief Implementation of the BNE instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_BNE(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "bne");
    auto note = a.make_scoped_note("bne"); (void) note;
    return execute_branch(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool { return rs1 != rs2; });
}

/// \brief Implementation of the BLT instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_BLT(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "blt");
    auto note = a.make_scoped_note("blt"); (void) note;
    return execute_branch(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool {
        return static_cast<int64_t>(rs1) < static_cast<int64_t>(rs2);
    });
}

/// \brief Implementation of the BGE instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_BGE(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "bge");
    auto note = a.make_scoped_note("bge"); (void) note;
    return execute_branch(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool {
        return static_cast<int64_t>(rs1) >= static_cast<int64_t>(rs2);
    });
}

/// \brief Implementation of the BLTU instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_BLTU(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "bltu");
    auto note = a.make_scoped_note("bltu"); (void) note;
    return execute_branch(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool {
        return rs1 < rs2;
    });
}

/// \brief Implementation of the BGEU instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_BGEU(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "bgeu");
    auto note = a.make_scoped_note("bgeu"); (void) note;
    return execute_branch(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool {
        return rs1 >= rs2;
    });
}

/// \brief Implementation of the LUI instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_LUI(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "lui");
    auto note = a.make_scoped_note("lui"); (void) note;
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0)
        a.write_x(rd, insn_U_get_imm(insn));
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the AUIPC instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_AUIPC(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "auipc");
    auto note = a.make_scoped_note("auipc"); (void) note;
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0)
        a.write_x(rd, pc + insn_U_get_imm(insn));
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the JAL instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_JAL(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "jal");
    auto note = a.make_scoped_note("jal"); (void) note;
    uint64_t new_pc = pc + insn_J_get_imm(insn);
    if (new_pc & 3) {
        return raise_misaligned_fetch_exception(a, new_pc);
    }
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0)
        a.write_x(rd, pc + 4);
    return execute_jump(a, new_pc);
}

/// \brief Implementation of the JALR instruction.
template <typename STATE_ACCESS>
static inline execute_status execute_JALR(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    dump_insn(a.get_naked_machine(), pc, insn, "jalr");
    auto note = a.make_scoped_note("jalr"); (void) note;
    uint64_t val = pc + 4;
    uint64_t new_pc = static_cast<int64_t>(a.read_x(insn_get_rs1(insn)) + insn_I_get_imm(insn)) & ~static_cast<uint64_t>(1);
    if (new_pc & 3)
        return raise_misaligned_fetch_exception(a, new_pc);
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0)
        a.write_x(rd, val);
    return execute_jump(a, new_pc);
}

/// \brief Implementation of the SFENCE.VMA instruction.
template <typename STATE_ACCESS>
static execute_status execute_SFENCE_VMA(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    // rs1 and rs2 are arbitrary, rest is set
    if ((insn & 0b11111110000000000111111111111111) == 0b00010010000000000000000001110011) {
        dump_insn(a.get_naked_machine(), pc, insn, "sfence.vma");
        auto note = a.make_scoped_note("sfence.vma"); (void) note;
        auto priv = a.read_iflags_PRV();
        uint64_t mstatus = a.read_mstatus();
        if (priv == PRV_U || (priv == PRV_S && (mstatus & MSTATUS_TVM_MASK)))
            return raise_illegal_insn_exception(a, pc, insn);
        uint32_t rs1 = insn_get_rs1(insn);
        if (rs1 == 0) {
            tlb_flush_all(a.get_naked_state());
        } else {
            tlb_flush_vaddr(a.get_naked_state(), a.get_naked_state().x[rs1]);
        }
        //??D The current code TLB may have been flushed
        // a.get_naked_state().brk = true;
        return advance_to_next_insn(a, pc);
    } else {
        return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Executes an instruction of the atomic group.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
/// \details See [Load-Reserved/Store-Conditional Instructions](riscv-spec-v2.2.pdf#section.7.2) and
///  [Atomic Memory Operations](riscv-spec-v2.2.pdf#section.7.3).
template <typename STATE_ACCESS>
static inline execute_status execute_atomic_group(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
#ifdef DUMP_COUNTERS
    a.get_naked_state().count_amo++;
#endif
    switch (static_cast<insn_atomic_funct3_funct5>(insn_get_funct3_funct5(insn))) {
        case insn_atomic_funct3_funct5::LR_W: return execute_LR_W(a, pc, insn);
        case insn_atomic_funct3_funct5::SC_W: return execute_SC_W(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOSWAP_W: return execute_AMOSWAP_W(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOADD_W: return execute_AMOADD_W(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOXOR_W: return execute_AMOXOR_W(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOAND_W: return execute_AMOAND_W(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOOR_W: return execute_AMOOR_W(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOMIN_W: return execute_AMOMIN_W(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOMAX_W: return execute_AMOMAX_W(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOMINU_W: return execute_AMOMINU_W(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOMAXU_W: return execute_AMOMAXU_W(a, pc, insn);
        case insn_atomic_funct3_funct5::LR_D: return execute_LR_D(a, pc, insn);
        case insn_atomic_funct3_funct5::SC_D: return execute_SC_D(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOSWAP_D: return execute_AMOSWAP_D(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOADD_D: return execute_AMOADD_D(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOXOR_D: return execute_AMOXOR_D(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOAND_D: return execute_AMOAND_D(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOOR_D: return execute_AMOOR_D(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOMIN_D: return execute_AMOMIN_D(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOMAX_D: return execute_AMOMAX_D(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOMINU_D: return execute_AMOMINU_D(a, pc, insn);
        case insn_atomic_funct3_funct5::AMOMAXU_D: return execute_AMOMAXU_D(a, pc, insn);
        default: return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Executes an instruction of the arithmetic-32 group.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
/// \details See [Integer Computational Instructions](riscv-spec-v2.2.pdf#section.2.4).
template <typename STATE_ACCESS>
static inline execute_status execute_arithmetic_32_group(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    switch (static_cast<insn_arithmetic_32_funct3_funct7>(insn_get_funct3_funct7(insn))) {
        case insn_arithmetic_32_funct3_funct7::ADDW: return execute_ADDW(a, pc, insn);
        case insn_arithmetic_32_funct3_funct7::SUBW: return execute_SUBW(a, pc, insn);
        case insn_arithmetic_32_funct3_funct7::SLLW: return execute_SLLW(a, pc, insn);
        case insn_arithmetic_32_funct3_funct7::SRLW: return execute_SRLW(a, pc, insn);
        case insn_arithmetic_32_funct3_funct7::SRAW: return execute_SRAW(a, pc, insn);
        case insn_arithmetic_32_funct3_funct7::MULW: return execute_MULW(a, pc, insn);
        case insn_arithmetic_32_funct3_funct7::DIVW: return execute_DIVW(a, pc, insn);
        case insn_arithmetic_32_funct3_funct7::DIVUW: return execute_DIVUW(a, pc, insn);
        case insn_arithmetic_32_funct3_funct7::REMW: return execute_REMW(a, pc, insn);
        case insn_arithmetic_32_funct3_funct7::REMUW: return execute_REMUW(a, pc, insn);
        default: return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Executes an instruction of the shift-rightimmediate-32 group.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_shift_right_immediate_32_group(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    switch (static_cast<insn_shift_right_immediate_32_funct7>(insn_get_funct7(insn))) {
        case insn_shift_right_immediate_32_funct7::SRLIW: return execute_SRLIW(a, pc, insn);
        case insn_shift_right_immediate_32_funct7::SRAIW: return execute_SRAIW(a, pc, insn);
        default: return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Executes an instruction of the arithmetic-immediate-32 group.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
/// \details See [Integer Computational Instructions](riscv-spec-v2.2.pdf#section.2.4).
template <typename STATE_ACCESS>
static inline execute_status execute_arithmetic_immediate_32_group(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    switch (static_cast<insn_arithmetic_immediate_32_funct3>(insn_get_funct3(insn))) {
        case insn_arithmetic_immediate_32_funct3::ADDIW: return execute_ADDIW(a, pc, insn);
        case insn_arithmetic_immediate_32_funct3::SLLIW: return execute_SLLIW(a, pc, insn);
        case insn_arithmetic_immediate_32_funct3::shift_right_immediate_32_group:
            return execute_shift_right_immediate_32_group(a, pc, insn);
        default: return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Executes an instruction of the environment, trap, interrupt, or memory management groups.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
/// \details See [Environment Call and Breakpoints](riscv-spec-v2.2.pdf#section.2.9),
///  [Machine-Mode Privileged Instructions](riscv-privileged-v1.10.pdf#section.3.2), and
///  [Supervisor Instructions](riscv-privileged-v1.10.pdf#section.4.2).
template <typename STATE_ACCESS>
static inline execute_status execute_env_trap_int_mm_group(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    switch (static_cast<insn_env_trap_int_group_insn>(insn)) {
        case insn_env_trap_int_group_insn::ECALL: return execute_ECALL(a, pc, insn);
        case insn_env_trap_int_group_insn::EBREAK: return execute_EBREAK(a, pc, insn);
        case insn_env_trap_int_group_insn::URET: return execute_URET(a, pc, insn);
        case insn_env_trap_int_group_insn::SRET: return execute_SRET(a, pc, insn);
        case insn_env_trap_int_group_insn::MRET: return execute_MRET(a, pc, insn);
        case insn_env_trap_int_group_insn::WFI: return execute_WFI(a, pc, insn);
        default: return execute_SFENCE_VMA(a, pc, insn);
    }
}

/// \brief Executes an instruction of the CSR, environment, trap, interrupt, or memory management groups.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
///  \details See [Control and Status Register Instructions](riscv-spec-v2.2.pdf#section.2.8),
///  [Environment Call and Breakpoints](riscv-spec-v2.2.pdf#section.2.9),
///  [Machine-Mode Privileged Instructions](riscv-privileged-v1.10.pdf#section.3.2), and
///  [Supervisor Instructions](riscv-privileged-v1.10.pdf#section.4.2).
template <typename STATE_ACCESS>
static inline execute_status execute_csr_env_trap_int_mm_group(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    switch (static_cast<insn_csr_env_trap_int_mm_funct3>(insn_get_funct3(insn))) {
        case insn_csr_env_trap_int_mm_funct3::CSRRW: return execute_CSRRW(a, pc, insn);
        case insn_csr_env_trap_int_mm_funct3::CSRRS: return execute_CSRRS(a, pc, insn);
        case insn_csr_env_trap_int_mm_funct3::CSRRC: return execute_CSRRC(a, pc, insn);
        case insn_csr_env_trap_int_mm_funct3::CSRRWI: return execute_CSRRWI(a, pc, insn);
        case insn_csr_env_trap_int_mm_funct3::CSRRSI: return execute_CSRRSI(a, pc, insn);
        case insn_csr_env_trap_int_mm_funct3::CSRRCI: return execute_CSRRCI(a, pc, insn);
        case insn_csr_env_trap_int_mm_funct3::env_trap_int_mm_group:
             return execute_env_trap_int_mm_group(a, pc, insn);
        default: return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Executes an instruction of the fence group.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
///  See [Memory Model](riscv-spec-v2.2.pdf#section.2.7).
template <typename STATE_ACCESS>
static inline execute_status execute_fence_group(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    if (insn == 0x0000100f) {
        return execute_FENCE_I(a, pc, insn);
    } else if (insn & 0xf00fff80) {
        return raise_illegal_insn_exception(a, pc, insn);
    } else {
        return execute_FENCE(a, pc, insn);
    }
}

/// \brief Executes an instruction of the shift-right-immediate group.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
template <typename STATE_ACCESS>
static inline execute_status execute_shift_right_immediate_group(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    switch (static_cast<insn_shift_right_immediate_funct6>(insn_get_funct6(insn))) {
        case insn_shift_right_immediate_funct6::SRLI: return execute_SRLI(a, pc, insn);
        case insn_shift_right_immediate_funct6::SRAI: return execute_SRAI(a, pc, insn);
        default: return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Executes an instruction of the arithmetic group.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
///  See [Integer Computational Instructions](riscv-spec-v2.2.pdf#section.2.4).
template <typename STATE_ACCESS>
static inline execute_status execute_arithmetic_group(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    //std::cerr << "funct3_funct7: " << std::bitset<10>(insn_get_funct3_funct7(insn)) << '\n';
    switch (static_cast<insn_arithmetic_funct3_funct7>(insn_get_funct3_funct7(insn))) {
        case insn_arithmetic_funct3_funct7::ADD: return execute_ADD(a, pc, insn);
        case insn_arithmetic_funct3_funct7::SUB: return execute_SUB(a, pc, insn);
        case insn_arithmetic_funct3_funct7::SLL: return execute_SLL(a, pc, insn);
        case insn_arithmetic_funct3_funct7::SLT: return execute_SLT(a, pc, insn);
        case insn_arithmetic_funct3_funct7::SLTU: return execute_SLTU(a, pc, insn);
        case insn_arithmetic_funct3_funct7::XOR: return execute_XOR(a, pc, insn);
        case insn_arithmetic_funct3_funct7::SRL: return execute_SRL(a, pc, insn);
        case insn_arithmetic_funct3_funct7::SRA: return execute_SRA(a, pc, insn);
        case insn_arithmetic_funct3_funct7::OR: return execute_OR(a, pc, insn);
        case insn_arithmetic_funct3_funct7::AND: return execute_AND(a, pc, insn);
        case insn_arithmetic_funct3_funct7::MUL: return execute_MUL(a, pc, insn);
        case insn_arithmetic_funct3_funct7::MULH: return execute_MULH(a, pc, insn);
        case insn_arithmetic_funct3_funct7::MULHSU: return execute_MULHSU(a, pc, insn);
        case insn_arithmetic_funct3_funct7::MULHU: return execute_MULHU(a, pc, insn);
        case insn_arithmetic_funct3_funct7::DIV: return execute_DIV(a, pc, insn);
        case insn_arithmetic_funct3_funct7::DIVU: return execute_DIVU(a, pc, insn);
        case insn_arithmetic_funct3_funct7::REM: return execute_REM(a, pc, insn);
        case insn_arithmetic_funct3_funct7::REMU: return execute_REMU(a, pc, insn);
        default: return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Executes an instruction of the arithmetic-immediate group.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
///  See [Integer Computational Instructions](riscv-spec-v2.2.pdf#section.2.4).
template <typename STATE_ACCESS>
static inline execute_status execute_arithmetic_immediate_group(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    switch (static_cast<insn_arithmetic_immediate_funct3>(insn_get_funct3(insn))) {
        case insn_arithmetic_immediate_funct3::ADDI: return execute_ADDI(a, pc, insn);
        case insn_arithmetic_immediate_funct3::SLTI: return execute_SLTI(a, pc, insn);
        case insn_arithmetic_immediate_funct3::SLTIU: return execute_SLTIU(a, pc, insn);
        case insn_arithmetic_immediate_funct3::XORI: return execute_XORI(a, pc, insn);
        case insn_arithmetic_immediate_funct3::ORI: return execute_ORI(a, pc, insn);
        case insn_arithmetic_immediate_funct3::ANDI: return execute_ANDI(a, pc, insn);
        case insn_arithmetic_immediate_funct3::SLLI: return execute_SLLI(a, pc, insn);
        case insn_arithmetic_immediate_funct3::shift_right_immediate_group:
            return execute_shift_right_immediate_group(a, pc, insn);
        default: return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Executes an instruction of the store group.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
/// \details See [Load and Store Instructions](riscv-spec-v2.2.pdf#section.2.6).
template <typename STATE_ACCESS>
static inline execute_status execute_store_group(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    switch (static_cast<insn_store_funct3>(insn_get_funct3(insn))) {
        case insn_store_funct3::SB: return execute_SB(a, pc, insn);
        case insn_store_funct3::SH: return execute_SH(a, pc, insn);
        case insn_store_funct3::SW: return execute_SW(a, pc, insn);
        case insn_store_funct3::SD: return execute_SD(a, pc, insn);
        default: return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Executes an instruction of the load group.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
/// \details See [Load and Store Instructions](riscv-spec-v2.2.pdf#section.2.6).
template <typename STATE_ACCESS>
static inline execute_status execute_load_group(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    switch (static_cast<insn_load_funct3>(insn_get_funct3(insn))) {
        case insn_load_funct3::LB: return execute_LB(a, pc, insn);
        case insn_load_funct3::LH: return execute_LH(a, pc, insn);
        case insn_load_funct3::LW: return execute_LW(a, pc, insn);
        case insn_load_funct3::LD: return execute_LD(a, pc, insn);
        case insn_load_funct3::LBU: return execute_LBU(a, pc, insn);
        case insn_load_funct3::LHU: return execute_LHU(a, pc, insn);
        case insn_load_funct3::LWU: return execute_LWU(a, pc, insn);
        default: return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Executes an instruction of the branch group.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return Returns true if the execution completed, false if it caused an exception. In that case, raise the exception.
/// \details See [Control Transfer Instructions](riscv-spec-v2.2.pdf#section.2.5).
template <typename STATE_ACCESS>
static inline execute_status execute_branch_group(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
    switch (static_cast<insn_branch_funct3>(insn_get_funct3(insn))) {
        case insn_branch_funct3::BEQ: return execute_BEQ(a, pc, insn);
        case insn_branch_funct3::BNE: return execute_BNE(a, pc, insn);
        case insn_branch_funct3::BLT: return execute_BLT(a, pc, insn);
        case insn_branch_funct3::BGE: return execute_BGE(a, pc, insn);
        case insn_branch_funct3::BLTU: return execute_BLTU(a, pc, insn);
        case insn_branch_funct3::BGEU: return execute_BGEU(a, pc, insn);
        default: return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Decodes and executes an instruction.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return execute_status::illegal if and illegal instruction exception was raised, or
///  execute_status::retired otherwise (Note that some other exception may or may not have been raised)
/// \details The execute_insn function decodes the instruction in multiple levels. When we know for sure that
///  the instruction could only be a &lt;FOO&gt;, a function with the name execute_&lt;FOO&gt; will be called.
///  See [RV32/64G Instruction Set Listings](riscv-spec-v2.2.pdf#chapter.19) and
///  [Instruction listings for RISC-V](riscv-spec-v2.2.pdf#table.19.2).
template <typename STATE_ACCESS>
static inline execute_status execute_insn(STATE_ACCESS &a, uint64_t pc, uint32_t insn) {
//std::cerr << "insn: " << std::bitset<32>(insn) << '\n';
//??D We should probably try doing the first branch on the combined opcode, funct3, and funct7.
//    Maybe it reduces the number of levels needed to decode most instructions.
    switch (static_cast<insn_opcode>(insn_get_opcode(insn))) {
        case insn_opcode::LUI: return execute_LUI(a, pc, insn);
        case insn_opcode::AUIPC: return execute_AUIPC(a, pc, insn);
        case insn_opcode::JAL: return execute_JAL(a, pc, insn);
        case insn_opcode::JALR: return execute_JALR(a, pc, insn);
        case insn_opcode::branch_group: return execute_branch_group(a, pc, insn);
        case insn_opcode::load_group: return execute_load_group(a, pc, insn);
        case insn_opcode::store_group: return execute_store_group(a, pc, insn);
        case insn_opcode::arithmetic_immediate_group: return execute_arithmetic_immediate_group(a, pc, insn);
        case insn_opcode::arithmetic_group: return execute_arithmetic_group(a, pc, insn);
        case insn_opcode::fence_group: return execute_fence_group(a, pc, insn);
        case insn_opcode::csr_env_trap_int_mm_group: return execute_csr_env_trap_int_mm_group(a, pc, insn);
        case insn_opcode::arithmetic_immediate_32_group: return execute_arithmetic_immediate_32_group(a, pc, insn);
        case insn_opcode::arithmetic_32_group: return execute_arithmetic_32_group(a, pc, insn);
        case insn_opcode::atomic_group: return execute_atomic_group(a, pc, insn);
        default: return raise_illegal_insn_exception(a, pc, insn);
    }
}

/// \brief Instruction fetch status code
enum class fetch_status: int {
    exception, ///< Instruction fetch failed: exception raised
    success ///< Instruction fetch succeeded: proceed to execute
};

/// \brief Loads the next instruction.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Receives current pc.
/// \param insn Receives fetched instruction.
/// \return Returns fetch_status::success if load succeeded, fetch_status::exception if it caused an exception.
//          In that case, raise the exception.
template <typename STATE_ACCESS>
static fetch_status fetch_insn(STATE_ACCESS &a, uint64_t *pc, uint32_t *insn) {
    auto note = a.make_scoped_note("fetch_insn"); (void) note;
    // Get current pc from state
    uint64_t vaddr = *pc = a.read_pc();
    // Check TLB for hit
    int tlb_idx = (vaddr >> PAGE_NUMBER_SHIFT) & (TLB_SIZE - 1);
    tlb_entry &tlb = a.get_naked_state().tlb_code[tlb_idx];
    if (!avoid_tlb<STATE_ACCESS>::value && tlb_hit<uint32_t>(tlb, vaddr)) {
        *insn = *reinterpret_cast<uint32_t *>(tlb.mem_addend + (uintptr_t)vaddr);
        return fetch_status::success;
    // TLB miss
    } else {
        uint64_t paddr;
        // Walk page table and obtain the physical address
        if (!translate_virtual_address(a, &paddr, vaddr, PTE_XWR_C_SHIFT)) {
            raise_exception(a, MCAUSE_FETCH_PAGE_FAULT, vaddr);
            return fetch_status::exception;
        }
        // Walk memory map to find the range that contains the physical address
        pma_entry &pma = find_pma_entry<uint32_t>(a, paddr);
        // We only execute directly from RAM (as in "random access memory", which includes ROM)
        // If the range is not memory or not executable, this as a PMA violation
        if (!pma.get_istart_M() || !pma.get_istart_X()) {
            raise_exception(a, MCAUSE_INSN_ACCESS_FAULT, vaddr);
            return fetch_status::exception;
        }
        uintptr_t mem_addend = tlb_replace(pma, vaddr, paddr, tlb);
        uintptr_t haddr = mem_addend + static_cast<uintptr_t>(vaddr);
        a.read_memory(paddr, haddr, insn);
        return fetch_status::success;
    }
}

template <typename STATE_ACCESS>
interpreter_status interpret(STATE_ACCESS &a, uint64_t mcycle_end) {

    static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
        "code assumes little-endian byte ordering");

    static_assert(is_an_i_state_access<STATE_ACCESS>::value,
        "not an i_state_access");

    // If the cpu is halted, we are done
    if (a.read_iflags_H()) {
        return interpreter_status::success;
    }

    // If we reached the target mcycle, we are done
    if (a.get_naked_state().mcycle >= mcycle_end) {
        return interpreter_status::success;
    }


    // Set break flag considering only interrupts, since we
    // know we are not halted
    a.get_naked_state().set_brk_from_mip_mie();

    // Raise the highest priority pending interrupt, if any
    raise_interrupt_if_any(a);

    uint64_t pc = 0;
    uint32_t insn = 0;

#ifdef DUMP_COUNTERS
    a.get_naked_state().count_outers++;
#endif

    // The inner loops continues until there is an interrupt condition
    // or mcycle reaches mcycle_end
    for ( ;; )  {
        // Try to fetch the next instruction
        if (fetch_insn(a, &pc, &insn) == fetch_status::success) {
            // Try to execute it
            if (execute_insn(a, pc, insn) == execute_status::retired) {
                // If successful, increment the number of retired instructions minstret
                // WARNING: if an instruction modifies minstret, it needs to take into
                // account it this unconditional increment and set the value accordingly
                a.write_minstret(a.read_minstret()+1);
                // ??D We could simply ignore writes to minstret.
                //     We already ignore writes to mcycle.
                //     In Spike, QEMU, and riscvemu, mcycle and minstret are the aliases for the same counter
                //     QEMU calls exit (!) on writes to mcycle and minstret
            }
        }
        // Increment the cycle counter mcycle
        // (We do not allow writes to mcycle)
        uint64_t mcycle = a.read_mcycle() + 1;
        a.write_mcycle(mcycle);

        // If the break flag is active, break from the inner loop
        if (a.get_naked_state().brk) {
            return interpreter_status::brk;
        }
        // Otherwise, there can be no pending interrupts
        // An interrupt is pending when mie & mip != 0
        // and when interrupts are not globally disabled
        // in mstatus (MIE or SIE). The logic is a bit
        // complicated by privilege and delegation. See
        // get_pending_irq_mask for details.
        // assert(get_pending_irq_mask(a.get_naked_state()) == 0);
        // For simplicity, we brk whenever mie & mip != 0
        assert((a.get_naked_state().mie & a.get_naked_state().mip) == 0);
        // or whenever iflags.H is set
        assert(!a.get_naked_state().iflags.H);

        // If we reached the target mcycle, we are done
        if (mcycle >= mcycle_end) {
            return interpreter_status::success;
        }
#ifdef DUMP_COUNTERS
        a.get_naked_state().count_inners++;
#endif
    }
}

// Explicit instantiation for state_access
template
interpreter_status
interpret(state_access &a, uint64_t mcycle_end);

// Explicit instantiation for logged_state_access
template
interpreter_status
interpret(logged_state_access &a, uint64_t mcycle_end);

} // namespace cartesi
