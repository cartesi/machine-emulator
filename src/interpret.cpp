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

#include <algorithm>
#include <array>
#include <cstdint>
#include <type_traits>
#include <utility>

#ifdef MICROARCHITECTURE
#include "uarch-machine-state-access.h"
#include "uarch-runtime.h"
#else
#include "record-step-state-access.h"
#include "replay-step-state-access.h"
#include "state-access.h"
#include <cassert>
#endif // MICROARCHITECTURE

#include "compiler-defines.h"
#include "i-state-access.h"
#include "machine-statistics.h"
#include "shadow-tlb.h"

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
///
/// The code assumes that arithmetic operations over pointers result in the same value
/// as arithmetic operations over unsigned integers mapped from pointers, including unsigned overflows.
/// According to the C and C++ standard performing arithmetic operations over unsigned integers
/// mapped from pointers and converting the result back to a pointer is undefined behavior.
/// However in common implementations (such as GCC x86_64) this is fine,
/// because pointers shares the same bit representation as unsigned integers.
/// Furthermore to avoid violating strict aliasing rules when compiler optimizations are enabled,
/// a special aliasing aware read/write is performed to access the memory of such pointers.
/// This assumption is made to optimize the TLB implementation.
///
///   https://gcc.gnu.org/onlinedocs/gcc-7.3.0/gcc/Arrays-and-pointers-implementation.html#Arrays-and-pointers-implementation
/// \}

#include "find-pma-entry.h"
#include "interpret.h"
#include "meta.h"
#include "riscv-constants.h"
#include "rtc.h"
#include "soft-float.h"
#include "strict-aliasing.h"
#include "translate-virtual-address.h"
#include "uint128.h"

namespace cartesi {

enum class rd_kind {
    x0, // rd = 0
    xN, // rd is a positive natural number (1, 2, 3 ... 31)
};

#ifdef DUMP_REGS
static const std::array<const char *, X_REG_COUNT> reg_name{"zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0",
    "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
    "t3", "t4", "t5", "t6"};

static const std::array<const char *, F_REG_COUNT> f_reg_name{"ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7",
    "fs0", "fs1", "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7",
    "fs8", "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11"};

static void print_uint64_t(uint64_t a) {
    std::ignore = fprintf(stderr, "%016" PRIx64, a);
}
#endif

#if defined(DUMP_EXCEPTIONS) || defined(DUMP_MMU_EXCEPTIONS) || defined(DUMP_INTERRUPTS) ||                            \
    defined(DUMP_ILLEGAL_INSN_EXCEPTIONS)
static const char *sbi_ecall_name(uint64_t a7) {
    switch (a7) {
        case 0:
            return "set timer";
        case 1:
            return "console putchar";
        case 2:
            return "console getchar";
        case 3:
            return "clear ipi";
        case 4:
            return "send ipi";
        case 5:
            return "remote fence i";
        case 6:
            return "remote fence vma";
        case 7:
            return "remote fence vma asid";
        case 8:
            return "shutdown";
        default:
            return "unknown";
    }
}

template <typename STATE>
static void dump_exception_or_interrupt(uint64_t cause, STATE &s) {
    uint64_t a7 = s.x[17];
    if ((cause & MCAUSE_INTERRUPT_FLAG) != 0) {
        switch (cause & ~MCAUSE_INTERRUPT_FLAG) {
            case 0:
                std::ignore = fprintf(stderr, "reserved software interrupt");
                break;
            case 1:
                std::ignore = fprintf(stderr, "supervisor software interrupt");
                break;
            case 2:
                std::ignore = fprintf(stderr, "reserved software interrupt");
                break;
            case 3:
                std::ignore = fprintf(stderr, "machine software interrupt");
                break;
            case 4:
                std::ignore = fprintf(stderr, "reserved timer interrupt");
                break;
            case 5:
                std::ignore = fprintf(stderr, "supervisor timer interrupt");
                break;
            case 6:
                std::ignore = fprintf(stderr, "reserved timer interrupt");
                break;
            case 7:
                std::ignore = fprintf(stderr, "machine timer interrupt");
                break;
            case 8:
                std::ignore = fprintf(stderr, "reserved external interrupt");
                break;
            case 9:
                std::ignore = fprintf(stderr, "supervisor external interrupt");
                break;
            case 10:
                std::ignore = fprintf(stderr, "reserved external interrupt");
                break;
            case 11:
                std::ignore = fprintf(stderr, "machine external interrupt");
                break;
            default:
                std::ignore = fprintf(stderr, "unknown interrupt");
                break;
        }
    } else {
        switch (cause) {
            case 0:
                std::ignore = fprintf(stderr, "instruction address misaligned");
                break;
            case 1:
                std::ignore = fprintf(stderr, "instruction access fault");
                break;
            case 2:
                std::ignore = fprintf(stderr, "illegal instruction");
                break;
            case 3:
                std::ignore = fprintf(stderr, "breakpoint");
                break;
            case 4:
                std::ignore = fprintf(stderr, "load address misaligned");
                break;
            case 5:
                std::ignore = fprintf(stderr, "load access fault");
                break;
            case 6:
                std::ignore = fprintf(stderr, "store/amo address misaligned");
                break;
            case 7:
                std::ignore = fprintf(stderr, "store/amo access fault");
                break;
            case 8:
                std::ignore = fprintf(stderr, "ecall %d from u-mode", static_cast<int>(a7));
                break;
            case 9:
                std::ignore = fprintf(stderr, "ecall %s(%d) from s-mode", sbi_ecall_name(a7), static_cast<int>(a7));
                break;
            case 10:
                std::ignore = fprintf(stderr, "ecall %d reserved", static_cast<int>(a7));
                break;
            case 11:
                std::ignore = fprintf(stderr, "ecall %s(%d) from m-mode", sbi_ecall_name(a7), static_cast<int>(a7));
                break;
            case 12:
                std::ignore = fprintf(stderr, "instruction page fault");
                break;
            case 13:
                std::ignore = fprintf(stderr, "load page fault");
                break;
            case 15:
                std::ignore = fprintf(stderr, "store/amo page fault");
                break;
            default:
                std::ignore = fprintf(stderr, "reserved");
                break;
        }
    }
}
#endif

#ifdef DUMP_REGS
template <typename STATE>
static void dump_regs(const STATE &s) {
    const std::array<char, 5> prv_str{"USHM"};
    int cols = 256 / XLEN;
    std::ignore = fprintf(stderr, "pc = ");
    print_uint64_t(s.pc);
    std::ignore = fprintf(stderr, " ");
    for (int i = 1; i < X_REG_COUNT; i++) {
        std::ignore = fprintf(stderr, "%-3s= ", reg_name[i]);
        print_uint64_t(s.x[i]);
        if ((i & (cols - 1)) == (cols - 1)) {
            std::ignore = fprintf(stderr, "\n");
        } else {
            std::ignore = fprintf(stderr, " ");
        }
    }
    for (int i = 0; i < F_REG_COUNT; i++) {
        std::ignore = fprintf(stderr, "%-3s= ", f_reg_name[i]);
        print_uint64_t(s.f[i]);
        if ((i & (cols - 1)) == (cols - 1)) {
            std::ignore = fprintf(stderr, "\n");
        } else {
            std::ignore = fprintf(stderr, " ");
        }
    }
    std::ignore = fprintf(stderr, "prv=%c", prv_str[s.iprv]);
    std::ignore = fprintf(stderr, " mstatus=");
    print_uint64_t(s.mstatus);
    std::ignore = fprintf(stderr, " cycles=%" PRId64, s.mcycle);
    std::ignore = fprintf(stderr, " insns=%" PRId64, s.mcycle - s.icycleinstret);
    std::ignore = fprintf(stderr, "\n");
    std::ignore = fprintf(stderr, "mideleg=");
    print_uint64_t(s.mideleg);
    std::ignore = fprintf(stderr, " mie=");
    print_uint64_t(s.mie);
    std::ignore = fprintf(stderr, " mip=");
    print_uint64_t(s.mip);
    std::ignore = fprintf(stderr, "\n");
}
#endif

/// \brief Checks if a instruction is uncompressed.
/// \param insn Instruction.
static FORCE_INLINE bool insn_is_uncompressed(uint32_t insn) {
    return (insn & 3) == 3;
}

/// \brief Checks if CSR is read-only.
/// \param csraddr Address of CSR in file.
/// \returns true if read-only, false otherwise.
static inline bool csr_is_read_only(CSR_address csraddr) {
    // 0xc00--0xcff, 0xd00--0xdff, and 0xf00--0xfff are all read-only.
    // so as long as bits 0xc00 are set, the register is read-only
    return ((to_underlying(csraddr) & 0xc00) == 0xc00);
}

/// \brief Extract privilege level from CSR address.
/// \param csr Address of CSR in file.
/// \returns Privilege level.
static inline uint32_t csr_prv(CSR_address csr) {
    return (to_underlying(csr) >> 8) & 3;
}

/// \brief Changes privilege level.
/// \param a Machine state accessor object.
/// \param previous_prv Previous privilege level.
/// \param new_prv New privilege level.
/// \details This function is outlined to minimize host CPU code cache pressure.
template <typename STATE_ACCESS>
static FORCE_INLINE void set_prv(STATE_ACCESS a, int new_prv) {
    INC_COUNTER(a.get_statistics(), priv_level[new_prv]);
    a.write_iprv(new_prv);
    // Invalidate all TLB entries
    a.flush_all_tlb();
    INC_COUNTER(a.get_statistics(), tlb_flush_all);
    INC_COUNTER(a.get_statistics(), tlb_flush_set_prv);
    //??D new privileged 1.11 draft says invalidation should
    // happen within a trap handler, although it could
    // also happen in xRET insn.
    a.write_ilrsc(-1); // invalidate reserved address
}

/// \brief Raise an exception (or interrupt).
/// \param a Machine state accessor object.
/// \param pc Machine current program counter.
/// \param cause Exception (or interrupt) mcause (or scause).
/// \param tval Associated tval.
/// \returns The new program counter, pointing to the raised exception trap handler.
/// \details This function is outlined to minimize host CPU code cache pressure.
template <typename STATE_ACCESS>
static NO_INLINE uint64_t raise_exception(STATE_ACCESS a, uint64_t pc, uint64_t cause, uint64_t tval) {
    if (cause == MCAUSE_ILLEGAL_INSN && !insn_is_uncompressed(static_cast<uint32_t>(tval))) {
        // Discard high bits of compressed instructions,
        // this is not performed in the instruction hot loop as an optimization.
        tval = static_cast<uint16_t>(tval);
    }

#if defined(DUMP_EXCEPTIONS) || defined(DUMP_MMU_EXCEPTIONS) || defined(DUMP_INTERRUPTS) ||                            \
    defined(DUMP_ILLEGAL_INSN_EXCEPTIONS)
    {
        int flag;
        flag = 0;
#ifdef DUMP_MMU_EXCEPTIONS
        if (cause == MCAUSE_INSN_ACCESS_FAULT || cause == MCAUSE_LOAD_ACCESS_FAULT ||
            cause == MCAUSE_STORE_AMO_ACCESS_FAULT || cause == MCAUSE_FETCH_PAGE_FAULT ||
            cause == MCAUSE_LOAD_PAGE_FAULT || cause == MCAUSE_STORE_AMO_PAGE_FAULT)
            flag = 1;
#endif
#ifdef DUMP_INTERRUPTS
        flag |= (cause & MCAUSE_INTERRUPT_FLAG) != 0;
#endif
#ifdef DUMP_EXCEPTIONS
        flag |= (cause & MCAUSE_INTERRUPT_FLAG) == 0;
#endif
#ifdef DUMP_ILLEGAL_INSN_EXCEPTIONS
        if (cause == MCAUSE_ILLEGAL_INSN)
            flag = 1;
#endif
        if (flag) {
            std::ignore = fprintf(stderr, "raise_exception: cause=0x");
            print_uint64_t(cause);
            std::ignore = fprintf(stderr, " tval=0x");
            print_uint64_t(tval);
            std::ignore = fprintf(stderr, " (");
            dump_exception_or_interrupt(cause, a.get_naked_state());
            std::ignore = fprintf(stderr, ")\n");
#ifdef DUMP_REGS
            dump_regs(a.get_naked_state());
#endif
        }
    }
#endif

    // Check if exception should be delegated to supervisor privilege
    // For each interrupt or exception number, there is a bit at mideleg
    // or medeleg saying if it should be delegated
    bool deleg = false;
    auto prv = a.read_iprv();
    if (prv <= PRV_S) {
        if (cause & MCAUSE_INTERRUPT_FLAG) {
            // Clear the MCAUSE_INTERRUPT_FLAG bit before shifting
            deleg = (a.read_mideleg() >> (cause & (XLEN - 1))) & 1;
        } else {
            deleg = (a.read_medeleg() >> (cause & (XLEN - 1))) & 1;
        }
    }

    // Every raised exception increases the exception counter, so we can compute minstret later
    a.write_icycleinstret(a.read_icycleinstret() + 1);

    uint64_t new_pc = 0;
    if (deleg) {
        a.write_scause(cause);
        a.write_sepc(pc);
        a.write_stval(tval);
        uint64_t mstatus = a.read_mstatus();
        mstatus = (mstatus & ~MSTATUS_SPIE_MASK) | (((mstatus >> MSTATUS_SIE_SHIFT) & 1) << MSTATUS_SPIE_SHIFT);
        mstatus = (mstatus & ~MSTATUS_SPP_MASK) | (prv << MSTATUS_SPP_SHIFT);
        mstatus &= ~MSTATUS_SIE_MASK;
        a.write_mstatus(mstatus);
        if (prv != PRV_S) {
            set_prv(a, PRV_S);
        }
        new_pc = a.read_stvec();
#ifdef DUMP_COUNTERS
        if (cause & MCAUSE_INTERRUPT_FLAG) {
            INC_COUNTER(a.get_statistics(), sv_int);
        } else if (cause >= MCAUSE_ECALL_BASE && cause <= MCAUSE_ECALL_BASE + PRV_M) { // Do not count environment calls
            INC_COUNTER(a.get_statistics(), sv_ex);
        }
#endif
    } else {
        a.write_mcause(cause);
        a.write_mepc(pc);
        a.write_mtval(tval);
        uint64_t mstatus = a.read_mstatus();
        mstatus = (mstatus & ~MSTATUS_MPIE_MASK) | (((mstatus >> MSTATUS_MIE_SHIFT) & 1) << MSTATUS_MPIE_SHIFT);
        mstatus = (mstatus & ~MSTATUS_MPP_MASK) | (prv << MSTATUS_MPP_SHIFT);
        mstatus &= ~MSTATUS_MIE_MASK;
        a.write_mstatus(mstatus);
        if (prv != PRV_M) {
            set_prv(a, PRV_M);
        }
        new_pc = a.read_mtvec();
#ifdef DUMP_COUNTERS
        if (cause & MCAUSE_INTERRUPT_FLAG) {
            INC_COUNTER(a.get_statistics(), m_int);
        } else if (cause >= MCAUSE_ECALL_BASE && cause <= MCAUSE_ECALL_BASE + PRV_M) { // Do not count environment calls
            INC_COUNTER(a.get_statistics(), m_ex);
        }
#endif
    }
    return new_pc;
}

/// \brief Obtains a mask of pending and enabled interrupts.
/// \param a Machine state accessor object.
/// \returns The mask.
template <typename STATE_ACCESS>
static inline uint32_t get_pending_irq_mask(STATE_ACCESS a) {
    const uint64_t mip = a.read_mip();
    const uint64_t mie = a.read_mie();

    // interrupt trap condition 2: bit i is set in both mip and mie
    const uint32_t pending_ints = mip & mie;
    if (pending_ints == 0) {
        return 0;
    }

    uint32_t enabled_ints = 0;
    auto prv = a.read_iprv();
    switch (prv) {
        // interrupt trap condition 1a: the current privilege mode is M
        case PRV_M: {
            const uint64_t mstatus = a.read_mstatus();
            // interrupt trap condition 1a: ... and the MIE bit in the mstatus
            // register is set
            if (mstatus & MSTATUS_MIE_MASK) {
                // interrupt trap condition 3: bit i is not set in mideleg
                enabled_ints = ~a.read_mideleg();
            }
            break;
        }
        // interrupt trap condition 1b: the current privilege mode has less
        // privilege than M-mode
        case PRV_S: {
            const uint64_t mstatus = a.read_mstatus();
            // Interrupts not set in mideleg are machine-mode
            // and cannot be masked by supervisor mode
            if (mstatus & MSTATUS_SIE_MASK) {
                enabled_ints = -1;
            } else {
                // interrupt trap condition 3: bit i is not set in mideleg
                enabled_ints = ~a.read_mideleg();
            }
            break;
        }
        default:
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

/// \brief Returns the highest priority interrupt number that should be handled.
static inline uint32_t get_highest_priority_irq_num(uint32_t v) {
    // Interrupts for higher privilege modes must be serviced before interrupts for lower privilege modes
    // Multiple simultaneous interrupts destined for M-mode are handled in the following
    // decreasing priority order: MEI, MSI, MTI, SEI, SSI, STI.
    // Multiple simultaneous interrupts destined for supervisor mode are handled in the following
    // decreasing priority order: SEI, SSI, STI.
    // Multiple simultaneous interrupts destined for HS-mode are handled in the following decreasing
    // priority order: SEI, SSI, STI, SGEI, VSEI, VSSI, VSTI.
    const std::array interrupts_priority{
        MIP_MEIP_MASK, MIP_MSIP_MASK, MIP_MTIP_MASK, // Machine interrupts has higher priority
        MIP_SEIP_MASK, MIP_SSIP_MASK, MIP_STIP_MASK  // Supervisor interrupts
    };
    for (const uint32_t mask : interrupts_priority) {
        if ((v & mask) != 0) {
            return ilog2(mask);
        }
    }
    // An interrupt that does not trigger a return in the loop cannot be generated by any program
    assert(false); // LCOV_EXCL_LINE
    // We have to return something just to make the compiler happy
    return ilog2(v); // LCOV_EXCL_LINE
}

/// \brief Raises an interrupt if any are enabled and pending.
/// \param a Machine state accessor object.
/// \param pc Machine current program counter.
template <typename STATE_ACCESS>
static inline uint64_t raise_interrupt_if_any(STATE_ACCESS a, uint64_t pc) {
    const uint32_t mask = get_pending_irq_mask(a);
    if (unlikely(mask != 0)) {
        const uint64_t irq_num = get_highest_priority_irq_num(mask);
        return raise_exception(a, pc, irq_num | MCAUSE_INTERRUPT_FLAG, 0);
    }
    return pc;
}

/// \brief At every tick, set interrupt as pending if the timer is expired
/// \param a Machine state accessor object.
/// \param mcycle Machine current cycle.
template <typename STATE_ACCESS>
static inline void set_rtc_interrupt(STATE_ACCESS a, uint64_t mcycle) {
    const uint64_t timecmp_cycle = rtc_time_to_cycle(a.read_clint_mtimecmp());
    if (timecmp_cycle <= mcycle && timecmp_cycle != 0) {
        const uint64_t mip = a.read_mip();
        a.write_mip(mip | MIP_MTIP_MASK);
    }
}

/// \brief Obtains the id fields an instruction.
/// \param insn Instruction.
static FORCE_INLINE uint32_t insn_get_id(uint32_t insn) {
    return insn & 0b1111'11111'1111111;
}

/// \brief Obtains the funct3 and trailing 0 bits from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct3_000000000000(uint32_t insn) {
    return insn & 0b111000000000000;
}

/// \brief Obtains the funct2 and trailing 0 bits from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct2_0000000000000000000000000(uint32_t insn) {
    return insn & 0b110000000000000000000000000;
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
    return static_cast<int32_t>(insn) >> 20;
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
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_B_get_imm(uint32_t insn) {
    return static_cast<int32_t>(static_cast<uint32_t>(static_cast<int32_t>(insn) >> 31) << 12 |
        ((insn << 1) >> 26) << 5 | ((insn << 20) >> 28) << 1 | ((insn << 24) >> 31) << 11);
}

/// \brief Obtains the immediate value from a J-type instruction.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_J_get_imm(uint32_t insn) {
    return static_cast<int32_t>(static_cast<uint32_t>(static_cast<int32_t>(insn) >> 31) << 20 |
        ((insn << 1) >> 22) << 1 | ((insn << 11) >> 31) << 11 | ((insn << 12) >> 24) << 12);
}

/// \brief Obtains the immediate value from a S-type instruction.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_S_get_imm(uint32_t insn) {
    return (static_cast<int32_t>(insn & 0xfe000000) >> (25 - 5)) | static_cast<int32_t>((insn >> 7) & 0b11111);
}

/// \brief Obtains the 5 most significant bits of the funct7 field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct7_sr2(uint32_t insn) {
    return insn >> 27;
}

/// \brief Obtains the 6 most significant bits of the funct7 field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct7_sr1(uint32_t insn) {
    return insn >> 26;
}

/// \brief Obtains the funct7 field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct7(uint32_t insn) {
    return insn >> 25;
}

/// \brief Obtains the funct7 field concatenated with rs2 field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct7_rs2(uint32_t insn) {
    return insn >> 20;
}

/// \brief Obtains the funct3 field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct3(uint32_t insn) {
    return (insn >> 12) & 0b111;
}

/// \brief Obtains the rounding mode from an instruction and fcsr.
/// \param insn Instruction.
/// \param fcsr Current fcsr.
static FORCE_INLINE uint32_t insn_get_rm(uint32_t insn, uint32_t fcsr) {
    const uint32_t rm = insn_get_funct3(insn);
    // If rm is set to FRM_DYN, it comes from fcsr.frm
    if (likely(rm == FRM_DYN)) {
        return fcsr >> FCSR_FRM_SHIFT;
    }
    return rm;
}

/// \brief Obtains the rs3 field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_rs3(uint32_t insn) {
    return (insn >> 27);
}

/// \brief Obtains the RD field from a compressed instructions that uses the CIW
/// or CL format and RS2 field from CS or CA.
/// \param insn Instruction.
static inline uint32_t insn_get_CIW_CL_rd_CS_CA_rs2(uint32_t insn) {
    return ((insn >> 2) & 0b111) | 0b1000;
}

/// \brief Obtains the RS1 field from a compressed instruction that uses CL, CS, CA or CB format.
/// \param insn Instruction.
static inline uint32_t insn_get_CL_CS_CA_CB_rs1(uint32_t insn) {
    return ((insn >> 7) & 0b111) | 0b1000;
}

/// \brief Obtains the RS2 field from a compressed instruction that uses CR or CSS format.
/// \param insn Instruction.
static inline uint32_t insn_get_CR_CSS_rs2(uint32_t insn) {
    return ((insn >> 2) & 0b11111);
}

/// \brief Obtains the immediate value from a C_J instruction.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_get_C_J_imm(uint32_t insn) {
    return static_cast<int32_t>(
        (static_cast<uint32_t>(static_cast<int32_t>(insn << 19) >> 20) & ~0b11111111111) | // imm[11]
        ((insn >> (11 - 4)) & 0b10000) |                                                   // imm[4]
        ((insn >> (9 - 8)) & 0b1100000000) |                                               // imm[9:8]
        ((insn << (10 - 8)) & 0b10000000000) |                                             // imm[10]
        ((insn >> (7 - 6)) & 0b1000000) |                                                  // imm[6]
        ((insn << (7 - 6)) & 0b10000000) |                                                 // imm[7]
        ((insn >> (3 - 1)) & 0b1110) |                                                     // imm[3:1]
        ((insn << (5 - 2)) & 0b100000)                                                     // imm[5]
    );
}

/// \brief Obtains the immediate value from a C_BEQZ and C_BNEZ instruction.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_get_C_BEQZ_BNEZ_imm(uint32_t insn) {
    return static_cast<int32_t>(
        (static_cast<uint32_t>(static_cast<int32_t>(insn << 19) >> 23) & ~0b11111111) | // imm[8]
        ((insn >> 7) & 0b11000) |                                                       // imm[4:3]
        ((insn << 1) & 0b11000000) |                                                    // imm[7:6]
        ((insn >> 2) & 0b110) |                                                         // imm[2:1]
        ((insn << 3) & 0b100000)                                                        // imm[5]
    );
}

/// \brief Obtains the immediate value from a CL/CS-type instruction.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_get_CL_CS_imm(uint32_t insn) {
    return static_cast<int32_t>(((insn >> (10 - 3)) & 0x38) | ((insn << (6 - 5)) & 0xc0));
}

/// \brief Obtains the immediate value from a CI/CB-type instruction.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE uint32_t insn_get_CI_CB_imm(uint32_t insn) {
    return ((insn >> (12 - 5)) & 0x20) | ((insn >> 2) & 0x1f);
}

/// \brief Obtains the immediate (sign-extended) value from a CI/CB-type instruction.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_get_CI_CB_imm_se(uint32_t insn) {
    return static_cast<int32_t>((static_cast<uint32_t>(static_cast<int32_t>(insn << 19) >> 26) & ~0b11111) | // imm[5]
        ((insn >> 2) & 0b11111)                                                                              // imm[4:0]
    );
}

/// \brief Obtains the immediate value from a C.LW and C.SW instructions.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_get_C_LW_C_SW_imm(uint32_t insn) {
    return static_cast<int32_t>(((insn >> (10 - 3)) & 0x38) | ((insn >> (6 - 2)) & 0x4) | ((insn << (6 - 5)) & 0x40));
}

/// \brief Obtains the immediate value from a CIW-type instruction.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE uint32_t insn_get_CIW_imm(uint32_t insn) {
    return ((insn >> (11 - 4)) & 0x30) | ((insn >> (7 - 6)) & 0x3c0) | ((insn >> (6 - 2)) & 0x4) |
        ((insn >> (5 - 3)) & 0x8);
}

/// \brief Obtains the immediate value from a C.ADDI16SP instruction.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_get_C_ADDI16SP_imm(uint32_t insn) {
    return static_cast<int32_t>(
        (static_cast<uint32_t>(static_cast<int32_t>(insn << 19) >> 22) & ~0b111111111) | // imm[9]
        ((insn >> 2) & 0b10000) |                                                        // imm[4]
        ((insn << 1) & 0b1000000) |                                                      // imm[6]
        ((insn << 4) & 0b110000000) |                                                    // imm[8:7]
        ((insn << 3) & 0b100000)                                                         // imm[5]
    );
}

/// \brief Obtains the immediate value from a C.LUI instruction.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_get_C_LUI_imm(uint32_t insn) {
    return static_cast<int32_t>(
        (static_cast<uint32_t>(static_cast<int32_t>(insn << 19) >> 14) & ~0b11111111111111111) | // imm[17]
        ((insn << 10) & 0b11111000000000000)                                                     // imm[16:12]
    );
}

/// \brief Obtains the immediate value from a C.FLDSP and C.LDSP instructions.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_get_C_FLDSP_LDSP_imm(uint32_t insn) {
    return static_cast<int32_t>(((insn >> (12 - 5)) & 0x20) | ((insn << (6 - 2)) & 0x1c0) | ((insn >> (5 - 3)) & 0x18));
}

/// \brief Obtains the immediate value from a C.LWSP instruction.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_get_C_LWSP_imm(uint32_t insn) {
    return static_cast<int32_t>(((insn >> (12 - 5)) & 0x20) | ((insn << (6 - 2)) & 0xc0) | ((insn >> (4 - 2)) & 0x1c));
}

/// \brief Obtains the immediate value from a C.FSDSP and C.SDSP instructions.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_get_C_FSDSP_SDSP_imm(uint32_t insn) {
    return static_cast<int32_t>(((insn >> (10 - 3)) & 0x38) | ((insn >> (7 - 6)) & 0x1c0));
}

/// \brief Obtains the immediate value from a C.SWSP instruction.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_get_C_SWSP_imm(uint32_t insn) {
    return static_cast<int32_t>(((insn >> (9 - 2)) & 0x3c) | ((insn >> (7 - 6)) & 0xc0));
}

/// \brief Read an aligned word from virtual memory (slow path that goes through virtual address translation).
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \tparam RAISE_STORE_EXCEPTIONS Boolean, when true load exceptions are converted into store exceptions.
/// \param a Machine state accessor object.
/// \param pc Machine current program counter.
/// \param vaddr Virtual address for word.
/// \param pval Pointer to word receiving value.
/// \returns A pair, the first value is true if succeeded, false otherwise.
/// The second value is the input pc if succeeded, otherwise the pc for a raised exception trap.
/// \details This function is outlined to minimize host CPU code cache pressure.
/// Unlike other inline functions in this file, this function does not take PC by reference,
/// instead it returns a new PC in case an exception is raised. This is because the function
/// is outlined, and taking PC by reference would cause the compiler to store it in a stack variable
/// instead of always storing it in register (this is an optimization).
template <typename T, typename STATE_ACCESS, bool RAISE_STORE_EXCEPTIONS = false>
static NO_INLINE std::pair<bool, uint64_t> read_virtual_memory_slow(STATE_ACCESS a, uint64_t pc, uint64_t mcycle,
    uint64_t vaddr, T *pval) {
    using U = std::make_unsigned_t<T>;
    // No support for misaligned accesses: They are handled by a trap in BBL
    if (unlikely(vaddr & (sizeof(T) - 1))) {
        pc = raise_exception(a, pc,
            RAISE_STORE_EXCEPTIONS ? MCAUSE_STORE_AMO_ADDRESS_MISALIGNED : MCAUSE_LOAD_ADDRESS_MISALIGNED, vaddr);
        return {false, pc};
    }
    // Deal with aligned accesses
    uint64_t paddr{};
    if (unlikely(!translate_virtual_address(a, &paddr, vaddr, PTE_XWR_R_SHIFT))) {
        pc = raise_exception(a, pc, RAISE_STORE_EXCEPTIONS ? MCAUSE_STORE_AMO_PAGE_FAULT : MCAUSE_LOAD_PAGE_FAULT,
            vaddr);
        return {false, pc};
    }
    auto &pma = find_pma_entry<T>(a, paddr);
    if (likely(pma.get_istart_R())) {
        if (likely(pma.get_istart_M())) {
            unsigned char *hpage = a.template replace_tlb_entry<TLB_READ>(vaddr, paddr, pma);
            const uint64_t hoffset = vaddr & PAGE_OFFSET_MASK;
            a.read_memory_word(paddr, hpage, hoffset, pval);
            return {true, pc};
        }
        if (likely(pma.get_istart_IO())) {
            const uint64_t offset = paddr - pma.get_start();
            uint64_t val{};
            device_state_access da(a, mcycle);
            // If we do not know how to read, we treat this as a PMA violation
            const bool status = pma.get_device_noexcept().get_driver()->read(pma.get_device_noexcept().get_context(),
                &da, offset, &val, log2_size<U>::value);
            if (likely(status)) {
                *pval = static_cast<T>(val);
                // device logs its own state accesses
                return {true, pc};
            }
        }
    }
    pc = raise_exception(a, pc, RAISE_STORE_EXCEPTIONS ? MCAUSE_STORE_AMO_ACCESS_FAULT : MCAUSE_LOAD_ACCESS_FAULT,
        vaddr);
    return {false, pc};
}

/// \brief Read an aligned word from virtual memory.
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Interpreter loop program counter (will be overwritten).
/// \param vaddr Virtual address for word.
/// \param pval Pointer to word receiving value.
/// \returns True if succeeded, false otherwise.
template <typename T, typename STATE_ACCESS, bool RAISE_STORE_EXCEPTIONS = false>
static FORCE_INLINE bool read_virtual_memory(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint64_t vaddr, T *pval) {
    // Try hitting the TLB
    if (unlikely(!(a.template read_memory_word_via_tlb<TLB_READ>(vaddr, pval)))) {
        // Outline the slow path into a function call to minimize host CPU code cache pressure
        INC_COUNTER(a.get_statistics(), tlb_rmiss);
        T val = 0; // Don't pass pval reference directly so the compiler can store it in a register
        auto [status, new_pc] =
            read_virtual_memory_slow<T, STATE_ACCESS, RAISE_STORE_EXCEPTIONS>(a, pc, mcycle, vaddr, &val);
        *pval = val;
        pc = new_pc;
        return status;
    }
    INC_COUNTER(a.get_statistics(), tlb_rhit);
    return true;
}

/// \brief Writes an aligned word to virtual memory (slow path that goes through virtual address translation).
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Machine current program counter.
/// \param vaddr Virtual address for word.
/// \param val64 Value to write.
/// \returns A pair, the first value is success status if succeeded, execute_status::failure otherwise.
/// The second value is the input pc if succeeded, otherwise the pc for a raised exception trap.
/// \details This function is outlined to minimize host CPU code cache pressure.
/// Unlike other inline functions in this file, this function does not take PC by reference,
/// instead it returns a new PC in case an exception is raised. This is because the function
/// is outlined, and taking PC by reference would cause the compiler to store it in a stack variable
/// instead of always storing it in register (this is an optimization).
template <typename T, typename STATE_ACCESS>
static NO_INLINE std::pair<execute_status, uint64_t> write_virtual_memory_slow(STATE_ACCESS a, uint64_t pc,
    uint64_t mcycle, uint64_t vaddr, uint64_t val64) {
    using U = std::make_unsigned_t<T>;
    // No support for misaligned accesses: They are handled by a trap in BBL
    if (unlikely(vaddr & (sizeof(T) - 1))) {
        pc = raise_exception(a, pc, MCAUSE_STORE_AMO_ADDRESS_MISALIGNED, vaddr);
        return {execute_status::failure, pc};
    }
    // Deal with aligned accesses
    uint64_t paddr{};
    if (unlikely(!translate_virtual_address(a, &paddr, vaddr, PTE_XWR_W_SHIFT))) {
        pc = raise_exception(a, pc, MCAUSE_STORE_AMO_PAGE_FAULT, vaddr);
        return {execute_status::failure, pc};
    }
    auto &pma = find_pma_entry<T>(a, paddr);
    if (likely(pma.get_istart_W())) {
        if (likely(pma.get_istart_M())) {
            unsigned char *hpage = a.template replace_tlb_entry<TLB_WRITE>(vaddr, paddr, pma);
            const uint64_t hoffset = vaddr & PAGE_OFFSET_MASK;
            a.write_memory_word(paddr, hpage, hoffset, static_cast<T>(val64));
            return {execute_status::success, pc};
        }
        if (likely(pma.get_istart_IO())) {
            const uint64_t offset = paddr - pma.get_start();
            device_state_access da(a, mcycle);
            auto status = pma.get_device_noexcept().get_driver()->write(pma.get_device_noexcept().get_context(), &da,
                offset, static_cast<U>(static_cast<T>(val64)), log2_size<U>::value);
            // If we do not know how to write, we treat this as a PMA violation
            if (likely(status != execute_status::failure)) {
                return {status, pc};
            }
        }
    }
    pc = raise_exception(a, pc, MCAUSE_STORE_AMO_ACCESS_FAULT, vaddr);
    return {execute_status::failure, pc};
}

/// \brief Writes an aligned word to virtual memory.
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Interpreter loop program counter (will be overwritten).
/// \param vaddr Virtual address for word.
/// \param val64 Value to write.
/// \returns True if succeeded, false if exception raised.
template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status write_virtual_memory(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint64_t vaddr,
    uint64_t val64) {
    // Try hitting the TLB
    if (unlikely((!a.template write_memory_word_via_tlb<TLB_WRITE>(vaddr, static_cast<T>(val64))))) {
        INC_COUNTER(a.get_statistics(), tlb_wmiss);
        // Outline the slow path into a function call to minimize host CPU code cache pressure
        auto [status, new_pc] = write_virtual_memory_slow<T>(a, pc, mcycle, vaddr, val64);
        pc = new_pc;
        return status;
    }
    INC_COUNTER(a.get_statistics(), tlb_whit);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static void dump_insn([[maybe_unused]] STATE_ACCESS a, [[maybe_unused]] uint64_t pc, [[maybe_unused]] uint32_t insn,
    [[maybe_unused]] const char *name) {
#ifdef DUMP_HIST
    a.get_naked_state().insn_hist[name]++;
#endif
#ifdef DUMP_REGS
    dump_regs(a.get_naked_state());
#endif
#ifdef DUMP_INSN
    uint64_t ppc = 0;
    // If we are running in the microinterpreter, we may or may not be collecting a step access log.
    // To prevent additional address translation end up in the log,
    // the following check will always be false when MICROARCHITECTURE is defined.
    if (std::is_same_v<STATE_ACCESS, state_access> &&
        !translate_virtual_address<STATE_ACCESS, false>(a, &ppc, pc, PTE_XWR_X_SHIFT)) {
        ppc = pc;
        fprintf(stderr, "v    %08" PRIx64, ppc);
    } else {
        fprintf(stderr, "p    %08" PRIx64, ppc);
    }
    fprintf(stderr, ":   %08" PRIx32 "   ", insn);
    fprintf(stderr, "%s\n", name);
#endif
}

/// \brief Raises an illegal instruction exception, updating the pc.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Interpreter loop program counter (will be overwritten).
/// \param insn Instruction.
/// \return execute_status::failure
/// \details This function is tail-called whenever the caller decoded enough of the instruction to identify it as
/// illegal.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status raise_illegal_insn_exception(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    pc = raise_exception(a, pc, MCAUSE_ILLEGAL_INSN, insn);
    return execute_status::failure;
}

/// \brief Raises an misaligned-fetch exception, updating the pc.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Interpreter loop program counter (will be overwritten).
/// \return execute_status::failure
/// \details This function is tail-called whenever the caller identified that the next value of pc is misaligned.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status raise_misaligned_fetch_exception(STATE_ACCESS a, uint64_t &pc, uint64_t new_pc) {
    pc = raise_exception(a, pc, MCAUSE_INSN_ADDRESS_MISALIGNED, new_pc);
    return execute_status::failure;
}

/// \brief Returns from execution due to raised exception, updating the pc.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Interpreter loop program counter (will be overwritten).
/// \return execute_status::failure
/// \details This function is tail-called whenever the caller identified a raised exception.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status advance_to_raised_exception(STATE_ACCESS /*a*/, uint64_t & /*pc*/) {
    return execute_status::failure;
}

/// \brief Advances pc to the next instruction.
/// \tparam size Instruction size
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Interpreter loop program counter (will be overwritten).
/// \param status Status to return, the default is execute_status::success.
/// \return status
/// \details This function is tail-called whenever the caller wants move to the next instruction.
template <uint64_t size = 4, typename STATE_ACCESS>
static FORCE_INLINE execute_status advance_to_next_insn(STATE_ACCESS /*a*/, uint64_t &pc,
    execute_status status = execute_status::success) {
    pc += static_cast<uint32_t>(size);
    return status;
}

/// \brief Changes pc arbitrarily, potentially causing a jump.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Interpreter loop program counter (will be overwritten).
/// \return execute_status::success
/// \details This function is tail-called whenever the caller wants to jump.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_jump(STATE_ACCESS /*a*/, uint64_t &pc, uint64_t new_pc) {
    pc = new_pc;
    return execute_status::success;
}

/// \brief Execute the LR instruction.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Interpreter loop program counter (will be overwritten).
/// \param insn Instruction.
template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LR(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    const uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    T val = 0;
    if (unlikely(!read_virtual_memory<T>(a, pc, mcycle, vaddr, &val))) {
        return advance_to_raised_exception(a, pc);
    }
    a.write_ilrsc(vaddr);
    const uint32_t rd = insn_get_rd(insn);
    if (unlikely(rd == 0)) {
        return advance_to_next_insn(a, pc);
    }
    a.write_x(rd, static_cast<uint64_t>(val));
    return advance_to_next_insn(a, pc);
}

/// \brief Execute the SC instruction.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Interpreter loop program counter (will be overwritten).
/// \param insn Instruction.
template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SC(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    uint64_t val = 0;
    const uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    execute_status status = execute_status::success;
    if (a.read_ilrsc() == vaddr) {
        status = write_virtual_memory<T>(a, pc, mcycle, vaddr, static_cast<T>(a.read_x(insn_get_rs2(insn))));
        if (unlikely(status == execute_status::failure)) {
            return advance_to_raised_exception(a, pc);
        }
    } else {
        val = 1;
    }
    a.write_ilrsc(-1); // Must clear reservation, regardless of failure
    const uint32_t rd = insn_get_rd(insn);
    if (unlikely(rd == 0)) {
        return advance_to_next_insn(a, pc, status);
    }
    a.write_x(rd, val);
    return advance_to_next_insn(a, pc, status);
}

/// \brief Implementation of the LR.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LR_W(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    if (unlikely((insn & 0b00000001111100000000000000000000) != 0)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    dump_insn(a, pc, insn, "lr.w");
    return execute_LR<int32_t>(a, pc, mcycle, insn);
}

/// \brief Implementation of the SC.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SC_W(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "sc.w");
    return execute_SC<int32_t>(a, pc, mcycle, insn);
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_AMO(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn,
    const F &f) {
    const uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    T valm = 0;
    // AMOs never raise load exceptions. Since any unreadable page is also unwritable,
    // attempting to perform an AMO on an unreadable page always raises a store page-fault exception.
    if (unlikely((!read_virtual_memory<T, STATE_ACCESS, true>(a, pc, mcycle, vaddr, &valm)))) {
        return advance_to_raised_exception(a, pc);
    }
    T valr = static_cast<T>(a.read_x(insn_get_rs2(insn)));
    valr = f(valm, valr);
    const execute_status status = write_virtual_memory<T>(a, pc, mcycle, vaddr, valr);
    if (unlikely(status == execute_status::failure)) {
        return advance_to_raised_exception(a, pc);
    }
    const uint32_t rd = insn_get_rd(insn);
    if (unlikely(rd == 0)) {
        return advance_to_next_insn(a, pc, status);
    }
    a.write_x(rd, static_cast<uint64_t>(valm));
    return advance_to_next_insn(a, pc, status);
}

/// \brief Implementation of the AMOSWAP.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOSWAP_W(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amoswap.w");
    return execute_AMO<int32_t>(a, pc, mcycle, insn, [](int32_t /*valm*/, int32_t valr) -> int32_t { return valr; });
}

/// \brief Implementation of the AMOADD.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOADD_W(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amoadd.w");
    return execute_AMO<int32_t>(a, pc, mcycle, insn, [](int32_t valm, int32_t valr) -> int32_t {
        int32_t val = 0;
        __builtin_add_overflow(valm, valr, &val);
        return val;
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOXOR_W(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amoxor.w");
    return execute_AMO<int32_t>(a, pc, mcycle, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm ^ valr; });
}

/// \brief Implementation of the AMOAND.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOAND_W(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amoand.w");
    return execute_AMO<int32_t>(a, pc, mcycle, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm & valr; });
}

/// \brief Implementation of the AMOOR.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOOR_W(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amoor.w");
    return execute_AMO<int32_t>(a, pc, mcycle, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm | valr; });
}

/// \brief Implementation of the AMOMIN.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMIN_W(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amomin.w");
    return execute_AMO<int32_t>(a, pc, mcycle, insn, [](int32_t valm, int32_t valr) -> int32_t {
        if (valm < valr) {
            return valm;
        }
        return valr;
    });
}

/// \brief Implementation of the AMOMAX.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMAX_W(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amomax.w");
    return execute_AMO<int32_t>(a, pc, mcycle, insn, [](int32_t valm, int32_t valr) -> int32_t {
        if (valm > valr) {
            return valm;
        }
        return valr;
    });
}

/// \brief Implementation of the AMOMINU.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMINU_W(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amominu.w");
    return execute_AMO<int32_t>(a, pc, mcycle, insn, [](int32_t valm, int32_t valr) -> int32_t {
        if (static_cast<uint32_t>(valm) < static_cast<uint32_t>(valr)) {
            return valm;
        }
        return valr;
    });
}

/// \brief Implementation of the AMOMAXU.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMAXU_W(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amomaxu.w");
    return execute_AMO<int32_t>(a, pc, mcycle, insn, [](int32_t valm, int32_t valr) -> int32_t {
        if (static_cast<uint32_t>(valm) > static_cast<uint32_t>(valr)) {
            return valm;
        }
        return valr;
    });
}

/// \brief Implementation of the LR.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LR_D(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    if (unlikely((insn & 0b00000001111100000000000000000000) != 0)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    dump_insn(a, pc, insn, "lr.d");
    return execute_LR<uint64_t>(a, pc, mcycle, insn);
}

/// \brief Implementation of the SC.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SC_D(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "sc.d");
    return execute_SC<uint64_t>(a, pc, mcycle, insn);
}

/// \brief Implementation of the AMOSWAP.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOSWAP_D(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amoswap.d");
    return execute_AMO<int64_t>(a, pc, mcycle, insn, [](int64_t /*valm*/, int64_t valr) -> int64_t { return valr; });
}

/// \brief Implementation of the AMOADD.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOADD_D(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amoadd.d");
    return execute_AMO<int64_t>(a, pc, mcycle, insn, [](int64_t valm, int64_t valr) -> int64_t {
        int64_t val = 0;
        __builtin_add_overflow(valm, valr, &val);
        return val;
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOXOR_D(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amoxor.d");
    return execute_AMO<int64_t>(a, pc, mcycle, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm ^ valr; });
}

/// \brief Implementation of the AMOAND.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOAND_D(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amoand.d");
    return execute_AMO<int64_t>(a, pc, mcycle, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm & valr; });
}

/// \brief Implementation of the AMOOR.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOOR_D(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amoor.d");
    return execute_AMO<int64_t>(a, pc, mcycle, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm | valr; });
}

/// \brief Implementation of the AMOMIN.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMIN_D(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amomin.d");
    return execute_AMO<int64_t>(a, pc, mcycle, insn, [](int64_t valm, int64_t valr) -> int64_t {
        if (valm < valr) {
            return valm;
        }
        return valr;
    });
}

/// \brief Implementation of the AMOMAX.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMAX_D(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amomax.d");
    return execute_AMO<int64_t>(a, pc, mcycle, insn, [](int64_t valm, int64_t valr) -> int64_t {
        if (valm > valr) {
            return valm;
        }
        return valr;
    });
}

/// \brief Implementation of the AMOMINU.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMINU_D(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amominu.d");
    return execute_AMO<uint64_t>(a, pc, mcycle, insn, [](uint64_t valm, uint64_t valr) -> uint64_t {
        if (valm < valr) {
            return valm;
        }
        return valr;
    });
}

/// \brief Implementation of the AMOMAXU.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMAXU_D(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "amomaxu.d");
    return execute_AMO<uint64_t>(a, pc, mcycle, insn, [](uint64_t valm, uint64_t valr) -> uint64_t {
        if (valm > valr) {
            return valm;
        }
        return valr;
    });
}

/// \brief Implementation of the ADDW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ADDW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "addw");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        // Discard upper 32 bits
        auto rs1w = static_cast<int32_t>(rs1);
        auto rs2w = static_cast<int32_t>(rs2);
        int32_t val = 0;
        __builtin_add_overflow(rs1w, rs2w, &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the SUBW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SUBW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "subw");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        // Convert 64-bit to 32-bit
        auto rs1w = static_cast<int32_t>(rs1);
        auto rs2w = static_cast<int32_t>(rs2);
        int32_t val = 0;
        __builtin_sub_overflow(rs1w, rs2w, &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the SLLW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLLW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    if (unlikely((insn & 0b11111110000000000111000001111111) != 0b00000000000000000001000000111011)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    dump_insn(a, pc, insn, "sllw");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        const auto rs1w = static_cast<int32_t>(static_cast<uint32_t>(rs1) << (rs2 & 31));
        return static_cast<uint64_t>(rs1w);
    });
}

/// \brief Implementation of the SRLW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRLW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "srlw");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto rs1w = static_cast<int32_t>(static_cast<uint32_t>(rs1) >> (rs2 & 31));
        return static_cast<uint64_t>(rs1w);
    });
}

/// \brief Implementation of the SRAW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRAW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sraw");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        const int32_t rs1w = static_cast<int32_t>(rs1) >> (rs2 & 31);
        return static_cast<uint64_t>(rs1w);
    });
}

/// \brief Implementation of the MULW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_MULW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "mulw");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto rs1w = static_cast<int32_t>(rs1);
        auto rs2w = static_cast<int32_t>(rs2);
        int32_t val = 0;
        __builtin_mul_overflow(rs1w, rs2w, &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the DIVW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_DIVW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    if (unlikely((insn & 0b11111110000000000111000001111111) != 0b00000010000000000100000000111011)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    dump_insn(a, pc, insn, "divw");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto rs1w = static_cast<int32_t>(rs1);
        auto rs2w = static_cast<int32_t>(rs2);
        if (unlikely(rs2w == 0)) {
            return static_cast<uint64_t>(-1);
        }
        if (unlikely(rs2w == -1 && rs1w == (static_cast<int32_t>(1) << (32 - 1)))) {
            return static_cast<uint64_t>(rs1w);
        }
        return static_cast<uint64_t>(rs1w / rs2w);
    });
}

/// \brief Implementation of the DIVUW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_DIVUW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "divuw");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto rs1w = static_cast<uint32_t>(rs1);
        auto rs2w = static_cast<uint32_t>(rs2);
        if (unlikely(rs2w == 0)) {
            return static_cast<uint64_t>(-1);
        }
        return static_cast<uint64_t>(static_cast<int32_t>(rs1w / rs2w));
    });
}

/// \brief Implementation of the REMW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_REMW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    if (unlikely((insn & 0b11111110000000000111000001111111) != 0b00000010000000000110000000111011)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    dump_insn(a, pc, insn, "remw");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto rs1w = static_cast<int32_t>(rs1);
        auto rs2w = static_cast<int32_t>(rs2);
        if (unlikely(rs2w == 0)) {
            return static_cast<uint64_t>(rs1w);
        }
        if (unlikely(rs2w == -1 && rs1w == (static_cast<int32_t>(1) << (32 - 1)))) {
            return static_cast<uint64_t>(0);
        }
        return static_cast<uint64_t>(rs1w % rs2w);
    });
}

/// \brief Implementation of the REMUW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_REMUW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    if (unlikely((insn & 0b11111110000000000111000001111111) != 0b00000010000000000111000000111011)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    dump_insn(a, pc, insn, "remuw");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto rs1w = static_cast<uint32_t>(rs1);
        auto rs2w = static_cast<uint32_t>(rs2);
        if (unlikely(rs2w == 0)) {
            return static_cast<uint64_t>(static_cast<int32_t>(rs1w));
        }
        return static_cast<uint64_t>(static_cast<int32_t>(rs1w % rs2w));
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
static inline bool rdcounteren(STATE_ACCESS a, uint64_t mask) {
    uint64_t counteren = MCOUNTEREN_R_MASK;
    auto prv = a.read_iprv();
    if (prv <= PRV_S) {
        counteren &= a.read_mcounteren();
        if (prv < PRV_S) {
            counteren &= a.read_scounteren();
        }
    }
    return (counteren & mask) == mask;
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_cycle(STATE_ACCESS a, uint64_t mcycle, bool *status) {
    if (rdcounteren(a, MCOUNTEREN_CY_MASK)) {
        return read_csr_success(mcycle, status);
    }
    return read_csr_fail(status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_instret(STATE_ACCESS a, uint64_t mcycle, bool *status) {
    if (unlikely(!rdcounteren(a, MCOUNTEREN_IR_MASK))) {
        return read_csr_fail(status);
    }
    const uint64_t icycleinstret = a.read_icycleinstret();
    const uint64_t minstret = mcycle - icycleinstret;
    return read_csr_success(minstret, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_time(STATE_ACCESS a, uint64_t mcycle, bool *status) {
    if (unlikely(!rdcounteren(a, MCOUNTEREN_TM_MASK))) {
        return read_csr_fail(status);
    }
    const uint64_t mtime = rtc_cycle_to_time(mcycle);
    return read_csr_success(mtime, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sstatus(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_mstatus() & SSTATUS_R_MASK, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_senvcfg(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_senvcfg() & SENVCFG_R_MASK, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sie(STATE_ACCESS a, bool *status) {
    const uint64_t mie = a.read_mie();
    const uint64_t mideleg = a.read_mideleg();
    return read_csr_success(mie & mideleg, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_stvec(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_stvec(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_scounteren(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_scounteren(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sscratch(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_sscratch(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sepc(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_sepc(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_scause(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_scause(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_stval(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_stval(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sip(STATE_ACCESS a, bool *status) {
    // Ensure values are are loaded in order: do not nest with operator
    const uint64_t mip = a.read_mip();
    const uint64_t mideleg = a.read_mideleg();
    return read_csr_success(mip & mideleg, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_satp(STATE_ACCESS a, bool *status) {
    const uint64_t mstatus = a.read_mstatus();
    auto prv = a.read_iprv();
    // When TVM=1, attempts to read or write the satp CSR
    // while executing in S-mode will raise an illegal instruction exception
    if (unlikely(prv == PRV_S && (mstatus & MSTATUS_TVM_MASK))) {
        return read_csr_fail(status);
    }
    return read_csr_success(a.read_satp(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mstatus(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_mstatus() & MSTATUS_R_MASK, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_menvcfg(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_menvcfg() & MENVCFG_R_MASK, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_misa(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_misa(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_medeleg(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_medeleg(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mideleg(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_mideleg(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mie(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_mie(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mtvec(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_mtvec(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mcounteren(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_mcounteren(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mscratch(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_mscratch(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mepc(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_mepc(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mcause(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_mcause(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mtval(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_mtval(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mip(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_mip(), status);
}

static inline uint64_t read_csr_mcycle(uint64_t mcycle, bool *status) {
    return read_csr_success(mcycle, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_minstret(STATE_ACCESS a, uint64_t mcycle, bool *status) {
    const uint64_t icycleinstret = a.read_icycleinstret();
    const uint64_t minstret = mcycle - icycleinstret;
    return read_csr_success(minstret, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mvendorid(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_mvendorid(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_marchid(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_marchid(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_mimpid(STATE_ACCESS a, bool *status) {
    return read_csr_success(a.read_mimpid(), status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_fflags(STATE_ACCESS a, bool *status) {
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return read_csr_fail(status);
    }
    const uint64_t fflags = (a.read_fcsr() & FCSR_FFLAGS_RW_MASK) >> FCSR_FFLAGS_SHIFT;
    return read_csr_success(fflags, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_frm(STATE_ACCESS a, bool *status) {
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return read_csr_fail(status);
    }
    const uint64_t frm = (a.read_fcsr() & FCSR_FRM_RW_MASK) >> FCSR_FRM_SHIFT;
    return read_csr_success(frm, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_fcsr(STATE_ACCESS a, bool *status) {
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return read_csr_fail(status);
    }
    return read_csr_success(a.read_fcsr(), status);
}

/// \brief Reads the value of a CSR given its address
/// \param a Machine state accessor object.
/// \param csraddr Address of CSR in file.
/// \param status Returns the status of the operation (true for success, false otherwise).
/// \returns Register value.
/// \details This function is outlined to minimize host CPU code cache pressure.
template <typename STATE_ACCESS>
static NO_INLINE uint64_t read_csr(STATE_ACCESS a, uint64_t mcycle, CSR_address csraddr, bool *status) {
    if (unlikely(csr_prv(csraddr) > a.read_iprv())) {
        return read_csr_fail(status);
    }

    switch (csraddr) {
        case CSR_address::fflags:
            return read_csr_fflags(a, status);
        case CSR_address::frm:
            return read_csr_frm(a, status);
        case CSR_address::fcsr:
            return read_csr_fcsr(a, status);

        case CSR_address::ucycle:
            return read_csr_cycle(a, mcycle, status);
        case CSR_address::uinstret:
            return read_csr_instret(a, mcycle, status);
        case CSR_address::utime:
            return read_csr_time(a, mcycle, status);

        case CSR_address::sstatus:
            return read_csr_sstatus(a, status);
        case CSR_address::senvcfg:
            return read_csr_senvcfg(a, status);
        case CSR_address::sie:
            return read_csr_sie(a, status);
        case CSR_address::stvec:
            return read_csr_stvec(a, status);
        case CSR_address::scounteren:
            return read_csr_scounteren(a, status);
        case CSR_address::sscratch:
            return read_csr_sscratch(a, status);
        case CSR_address::sepc:
            return read_csr_sepc(a, status);
        case CSR_address::scause:
            return read_csr_scause(a, status);
        case CSR_address::stval:
            return read_csr_stval(a, status);
        case CSR_address::sip:
            return read_csr_sip(a, status);
        case CSR_address::satp:
            return read_csr_satp(a, status);

        case CSR_address::mstatus:
            return read_csr_mstatus(a, status);
        case CSR_address::menvcfg:
            return read_csr_menvcfg(a, status);
        case CSR_address::misa:
            return read_csr_misa(a, status);
        case CSR_address::medeleg:
            return read_csr_medeleg(a, status);
        case CSR_address::mideleg:
            return read_csr_mideleg(a, status);
        case CSR_address::mie:
            return read_csr_mie(a, status);
        case CSR_address::mtvec:
            return read_csr_mtvec(a, status);
        case CSR_address::mcounteren:
            return read_csr_mcounteren(a, status);

        case CSR_address::mscratch:
            return read_csr_mscratch(a, status);
        case CSR_address::mepc:
            return read_csr_mepc(a, status);
        case CSR_address::mcause:
            return read_csr_mcause(a, status);
        case CSR_address::mtval:
            return read_csr_mtval(a, status);
        case CSR_address::mip:
            return read_csr_mip(a, status);

        case CSR_address::mcycle:
            return read_csr_mcycle(mcycle, status);
        case CSR_address::minstret:
            return read_csr_minstret(a, mcycle, status);

        case CSR_address::mvendorid:
            return read_csr_mvendorid(a, status);
        case CSR_address::marchid:
            return read_csr_marchid(a, status);
        case CSR_address::mimpid:
            return read_csr_mimpid(a, status);

        // All hardwired to zero
        case CSR_address::mhartid:
        case CSR_address::mcountinhibit:
        case CSR_address::mconfigptr:
        case CSR_address::mhpmcounter3:
        case CSR_address::mhpmcounter4:
        case CSR_address::mhpmcounter5:
        case CSR_address::mhpmcounter6:
        case CSR_address::mhpmcounter7:
        case CSR_address::mhpmcounter8:
        case CSR_address::mhpmcounter9:
        case CSR_address::mhpmcounter10:
        case CSR_address::mhpmcounter11:
        case CSR_address::mhpmcounter12:
        case CSR_address::mhpmcounter13:
        case CSR_address::mhpmcounter14:
        case CSR_address::mhpmcounter15:
        case CSR_address::mhpmcounter16:
        case CSR_address::mhpmcounter17:
        case CSR_address::mhpmcounter18:
        case CSR_address::mhpmcounter19:
        case CSR_address::mhpmcounter20:
        case CSR_address::mhpmcounter21:
        case CSR_address::mhpmcounter22:
        case CSR_address::mhpmcounter23:
        case CSR_address::mhpmcounter24:
        case CSR_address::mhpmcounter25:
        case CSR_address::mhpmcounter26:
        case CSR_address::mhpmcounter27:
        case CSR_address::mhpmcounter28:
        case CSR_address::mhpmcounter29:
        case CSR_address::mhpmcounter30:
        case CSR_address::mhpmcounter31:
        case CSR_address::mhpmevent3:
        case CSR_address::mhpmevent4:
        case CSR_address::mhpmevent5:
        case CSR_address::mhpmevent6:
        case CSR_address::mhpmevent7:
        case CSR_address::mhpmevent8:
        case CSR_address::mhpmevent9:
        case CSR_address::mhpmevent10:
        case CSR_address::mhpmevent11:
        case CSR_address::mhpmevent12:
        case CSR_address::mhpmevent13:
        case CSR_address::mhpmevent14:
        case CSR_address::mhpmevent15:
        case CSR_address::mhpmevent16:
        case CSR_address::mhpmevent17:
        case CSR_address::mhpmevent18:
        case CSR_address::mhpmevent19:
        case CSR_address::mhpmevent20:
        case CSR_address::mhpmevent21:
        case CSR_address::mhpmevent22:
        case CSR_address::mhpmevent23:
        case CSR_address::mhpmevent24:
        case CSR_address::mhpmevent25:
        case CSR_address::mhpmevent26:
        case CSR_address::mhpmevent27:
        case CSR_address::mhpmevent28:
        case CSR_address::mhpmevent29:
        case CSR_address::mhpmevent30:
        case CSR_address::mhpmevent31:
        case CSR_address::tselect:
        case CSR_address::tdata1:
        case CSR_address::tdata2:
        case CSR_address::tdata3:
            return read_csr_success(0, status);

        default:
            // Invalid CSRs
#ifdef DUMP_INVALID_CSR
            fprintf(stderr, "csr_read: invalid CSR=0x%x\n", static_cast<int>(csraddr));
#endif
            return read_csr_fail(status);
    }
}

template <typename STATE_ACCESS>
static execute_status write_csr_sstatus(STATE_ACCESS a, uint64_t val) {
    const uint64_t mstatus = a.read_mstatus();
    return write_csr_mstatus(a, (mstatus & ~SSTATUS_W_MASK) | (val & SSTATUS_W_MASK));
}

template <typename STATE_ACCESS>
static execute_status write_csr_senvcfg(STATE_ACCESS a, uint64_t val) {
    const uint64_t senvcfg = a.read_senvcfg();
    a.write_senvcfg((senvcfg & ~SENVCFG_W_MASK) | (val & SENVCFG_W_MASK));
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_sie(STATE_ACCESS a, uint64_t val) {
    uint64_t mie = a.read_mie();
    const uint64_t mask = a.read_mideleg();
    mie = (mie & ~mask) | (val & mask);
    a.write_mie(mie);
    return execute_status::success_and_serve_interrupts;
}

template <typename STATE_ACCESS>
static execute_status write_csr_stvec(STATE_ACCESS a, uint64_t val) {
    a.write_stvec(val & ~1);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_scounteren(STATE_ACCESS a, uint64_t val) {
    a.write_scounteren(val & SCOUNTEREN_RW_MASK);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_sscratch(STATE_ACCESS a, uint64_t val) {
    a.write_sscratch(val);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_sepc(STATE_ACCESS a, uint64_t val) {
    a.write_sepc(val & ~1);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_scause(STATE_ACCESS a, uint64_t val) {
    a.write_scause(val);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_stval(STATE_ACCESS a, uint64_t val) {
    a.write_stval(val);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_sip(STATE_ACCESS a, uint64_t val) {
    const uint64_t mask = a.read_mideleg();
    uint64_t mip = a.read_mip();
    mip = (mip & ~mask) | (val & mask);
    a.write_mip(mip);
    return execute_status::success_and_serve_interrupts;
}

template <typename STATE_ACCESS>
static NO_INLINE execute_status write_csr_satp(STATE_ACCESS a, uint64_t val) {
    const uint64_t mstatus = a.read_mstatus();
    auto prv = a.read_iprv();

    // When TVM=1, attempts to read or write the satp CSR
    // while executing in S-mode will raise an illegal instruction exception
    if (unlikely(prv == PRV_S && (mstatus & MSTATUS_TVM_MASK))) {
        return execute_status::failure;
    }

    const uint64_t old_satp = a.read_satp();
    uint64_t stap = old_satp;
    const uint64_t mode = val >> SATP_MODE_SHIFT;

    // Checks for supported MODE
    switch (mode) {
        case SATP_MODE_BARE:
        case SATP_MODE_SV39:
        case SATP_MODE_SV48:
#ifndef NO_SATP_MODE_SV57
        case SATP_MODE_SV57:
#endif
            stap = (val & SATP_PPN_MASK) | (val & SATP_ASID_MASK) | (val & SATP_MODE_MASK);
            break;
        default:
            // Implementations are not required to support all MODE settings,
            // and if satp is written with an unsupported MODE,
            // the entire write has no effect; no fields in satp are modified.
            return execute_status::success;
    }
    a.write_satp(stap);

#ifdef DUMP_COUNTERS
    uint64_t asid = (stap & SATP_ASID_MASK) >> SATP_ASID_SHIFT;
    if (asid != ASID_MAX_MASK) { // Software is not testing ASID bits
        a.get_statistics().max_asid = std::max(a.get_statistics().max_asid, asid);
    }
#endif

    // Changes to MODE and ASID, flushes the TLBs.
    // Note that there is no need to flush the TLB when PPN has changed,
    // because software is required to execute SFENCE.VMA when recycling an ASID.
    const uint64_t mod = old_satp ^ stap;
    if (mod & (SATP_ASID_MASK | SATP_MODE_MASK)) {
        a.flush_all_tlb();
        INC_COUNTER(a.get_statistics(), tlb_flush_all);
        INC_COUNTER(a.get_statistics(), tlb_flush_satp);
        return execute_status::success_and_flush_fetch;
    }
    return execute_status::success;
}

template <typename STATE_ACCESS>
static NO_INLINE execute_status write_csr_mstatus(STATE_ACCESS a, uint64_t val) {
    const uint64_t old_mstatus = a.read_mstatus() & MSTATUS_R_MASK;

    // M-mode software can determine whether a privilege mode is implemented
    // by writing that mode to MPP then reading it back.
    if (PRV_HS == ((val & MSTATUS_MPP_MASK) >> MSTATUS_MPP_SHIFT)) {
        // HS-mode is not supported yet, set val MPP to U-mode
        val = val & ~MSTATUS_MPP_MASK;
    }

    // Modify only bits that can be written to
    uint64_t mstatus = (old_mstatus & ~MSTATUS_W_MASK) | (val & MSTATUS_W_MASK);
    // Is FS enabled?
    if ((mstatus & MSTATUS_FS_MASK) != MSTATUS_FS_OFF) {
        // Implementations may choose to track the dirtiness of the floating-point register state
        // imprecisely by reporting the state to be dirty even when it has not been modified.
        // In our implementation an attempt to set FS to Initial or Clean causes FS to be set to Dirty,
        // therefore FS is always Dirty when enabled.
        mstatus |= MSTATUS_FS_DIRTY;
        // The SD bit is read-only and is set when either the FS, VS, or XS bits encode a Dirty state
        mstatus |= MSTATUS_SD_MASK;
    } else {
        // No FS, VS or XS dirty state, SD bit can be cleared
        mstatus &= ~MSTATUS_SD_MASK;
    }
    // Store results
    a.write_mstatus(mstatus);

    // If MMU configuration was changed, we may have to flush the TLBs
    bool flush_tlb_read = false;
    bool flush_tlb_write = false;
    const uint64_t mod = old_mstatus ^ mstatus;
    if ((mod & MSTATUS_MXR_MASK) != 0) {
        // MXR allows read access to execute-only pages,
        // therefore it only affects read translations
        flush_tlb_read = true;
    }
    if ((mod & MSTATUS_SUM_MASK) != 0) {
        // SUM allows S-mode for accessing U-mode memory, except to code,
        // therefore it only affects read/write translations
        flush_tlb_read = true;
        flush_tlb_write = true;
    }
    if ((mod & MSTATUS_MPRV_MASK) != 0 || ((mstatus & MSTATUS_MPRV_MASK) && (mod & MSTATUS_MPP_MASK) != 0)) {
        // When MPRV is set, data loads and stores use privilege in MPP
        // instead of the current privilege level, but code access is unaffected,
        // therefore it only affects read/write translations
        flush_tlb_read = true;
        flush_tlb_write = true;
    }

    // Flush TLBs when needed
    if (flush_tlb_read) {
        a.template flush_tlb_type<TLB_READ>();
        INC_COUNTER(a.get_statistics(), tlb_flush_read);
    }
    if (flush_tlb_write) {
        a.template flush_tlb_type<TLB_WRITE>();
        INC_COUNTER(a.get_statistics(), tlb_flush_write);
    }
    if (flush_tlb_read || flush_tlb_write) {
        INC_COUNTER(a.get_statistics(), tlb_flush_mstatus);
    }

    // When changing an interrupt enabled bit, we may have to service any pending interrupt
    if ((mod & (MSTATUS_SIE_MASK | MSTATUS_MIE_MASK)) != 0) {
        return execute_status::success_and_serve_interrupts;
    }

    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_menvcfg(STATE_ACCESS a, uint64_t val) {
    uint64_t menvcfg = a.read_menvcfg() & MENVCFG_R_MASK;

    // Modify only bits that can be written to
    menvcfg = (menvcfg & ~MENVCFG_W_MASK) | (val & MENVCFG_W_MASK);
    // Store results
    a.write_menvcfg(menvcfg);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_medeleg(STATE_ACCESS a, uint64_t val) {
    // For exceptions that cannot occur in less privileged modes,
    // the corresponding medeleg bits should be read-only zero
    a.write_medeleg((a.read_medeleg() & ~MEDELEG_W_MASK) | (val & MEDELEG_W_MASK));
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mideleg(STATE_ACCESS a, uint64_t val) {
    const uint64_t mask = MIP_SSIP_MASK | MIP_STIP_MASK | MIP_SEIP_MASK;
    uint64_t mideleg = a.read_mideleg();
    mideleg = (mideleg & ~mask) | (val & mask);
    a.write_mideleg(mideleg);
    return execute_status::success_and_serve_interrupts;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mie(STATE_ACCESS a, uint64_t val) {
    const uint64_t mask = MIP_MSIP_MASK | MIP_MTIP_MASK | MIP_MEIP_MASK | MIP_SSIP_MASK | MIP_STIP_MASK | MIP_SEIP_MASK;
    uint64_t mie = a.read_mie();
    mie = (mie & ~mask) | (val & mask);
    a.write_mie(mie);
    return execute_status::success_and_serve_interrupts;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mtvec(STATE_ACCESS a, uint64_t val) {
    a.write_mtvec(val & ~1);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mcounteren(STATE_ACCESS a, uint64_t val) {
    a.write_mcounteren(val & MCOUNTEREN_RW_MASK);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_minstret(STATE_ACCESS a, uint64_t mcycle, uint64_t val) {
    // Note that mcycle will only be incremented after the instruction is executed,
    // but we have to compute this in advance
    const uint64_t icycleinstret = (mcycle + 1) - val;
    a.write_icycleinstret(icycleinstret);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mcycle(STATE_ACCESS /*a*/, uint64_t /*val*/) {
    // We can't allow writes to mcycle because we use it to measure the progress in machine execution.
    // The specs say it is an MRW CSR, read-writeable in M-mode.
    // BBL enables all counters in both M- and S-modes.
    // In Spike, QEMU, and riscvemu, mcycle and minstret are the aliases for the same counter.
    // QEMU calls exit (!) on writes to mcycle or minstret.
    // We instead raise an exception.
    return execute_status::failure;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mscratch(STATE_ACCESS a, uint64_t val) {
    a.write_mscratch(val);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mepc(STATE_ACCESS a, uint64_t val) {
    a.write_mepc(val & ~1);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mcause(STATE_ACCESS a, uint64_t val) {
    a.write_mcause(val);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mtval(STATE_ACCESS a, uint64_t val) {
    a.write_mtval(val);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mip(STATE_ACCESS a, uint64_t val) {
    const uint64_t mask = MIP_SSIP_MASK | MIP_STIP_MASK | MIP_SEIP_MASK;
    auto mip = a.read_mip();
    mip = (mip & ~mask) | (val & mask);
    a.write_mip(mip);
    return execute_status::success_and_serve_interrupts;
}

template <typename STATE_ACCESS>
static inline execute_status write_csr_fflags(STATE_ACCESS a, uint64_t val) {
    const uint64_t mstatus = a.read_mstatus();
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((mstatus & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return execute_status::failure;
    }
    const uint64_t fcsr = (a.read_fcsr() & ~FCSR_FFLAGS_RW_MASK) | ((val << FCSR_FFLAGS_SHIFT) & FCSR_FFLAGS_RW_MASK);
    a.write_fcsr(fcsr);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static inline execute_status write_csr_frm(STATE_ACCESS a, uint64_t val) {
    const uint64_t mstatus = a.read_mstatus();
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((mstatus & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return execute_status::failure;
    }
    const uint64_t fcsr = (a.read_fcsr() & ~FCSR_FRM_RW_MASK) | ((val << FCSR_FRM_SHIFT) & FCSR_FRM_RW_MASK);
    a.write_fcsr(fcsr);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static inline execute_status write_csr_fcsr(STATE_ACCESS a, uint64_t val) {
    const uint64_t mstatus = a.read_mstatus();
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((mstatus & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return execute_status::failure;
    }
    const uint64_t fcsr = val & FCSR_RW_MASK;
    a.write_fcsr(fcsr);
    return execute_status::success;
}

/// \brief Writes a value to a CSR given its address
/// \param a Machine state accessor object.
/// \param csraddr Address of CSR in file.
/// \param val New register value.
/// \returns The status of the operation (true for success, false otherwise).
/// \details This function is outlined to minimize host CPU code cache pressure.
template <typename STATE_ACCESS>
static NO_INLINE execute_status write_csr(STATE_ACCESS a, uint64_t mcycle, CSR_address csraddr, uint64_t val) {
#if defined(DUMP_CSR)
    fprintf(stderr, "csr_write: csr=0x%03x val=0x", static_cast<int>(csraddr));
    print_uint64_t(val);
    fprintf(stderr, "\n");
#endif
    if (unlikely(csr_is_read_only(csraddr))) {
        return execute_status::failure;
    }
    if (unlikely(csr_prv(csraddr) > a.read_iprv())) {
        return execute_status::failure;
    }

    switch (csraddr) {
        case CSR_address::fflags:
            return write_csr_fflags(a, val);
        case CSR_address::frm:
            return write_csr_frm(a, val);
        case CSR_address::fcsr:
            return write_csr_fcsr(a, val);

        case CSR_address::sstatus:
            return write_csr_sstatus(a, val);
        case CSR_address::senvcfg:
            return write_csr_senvcfg(a, val);
        case CSR_address::sie:
            return write_csr_sie(a, val);
        case CSR_address::stvec:
            return write_csr_stvec(a, val);
        case CSR_address::scounteren:
            return write_csr_scounteren(a, val);

        case CSR_address::sscratch:
            return write_csr_sscratch(a, val);
        case CSR_address::sepc:
            return write_csr_sepc(a, val);
        case CSR_address::scause:
            return write_csr_scause(a, val);
        case CSR_address::stval:
            return write_csr_stval(a, val);
        case CSR_address::sip:
            return write_csr_sip(a, val);

        case CSR_address::satp:
            return write_csr_satp(a, val);

        case CSR_address::mstatus:
            return write_csr_mstatus(a, val);
        case CSR_address::menvcfg:
            return write_csr_menvcfg(a, val);
        case CSR_address::medeleg:
            return write_csr_medeleg(a, val);
        case CSR_address::mideleg:
            return write_csr_mideleg(a, val);
        case CSR_address::mie:
            return write_csr_mie(a, val);
        case CSR_address::mtvec:
            return write_csr_mtvec(a, val);
        case CSR_address::mcounteren:
            return write_csr_mcounteren(a, val);

        case CSR_address::mscratch:
            return write_csr_mscratch(a, val);
        case CSR_address::mepc:
            return write_csr_mepc(a, val);
        case CSR_address::mcause:
            return write_csr_mcause(a, val);
        case CSR_address::mtval:
            return write_csr_mtval(a, val);
        case CSR_address::mip:
            return write_csr_mip(a, val);

        case CSR_address::mcycle:
            return write_csr_mcycle(a, val);
        case CSR_address::minstret:
            return write_csr_minstret(a, mcycle, val);

        // Ignore writes
        case CSR_address::misa:
        case CSR_address::mhpmcounter3:
        case CSR_address::mhpmcounter4:
        case CSR_address::mhpmcounter5:
        case CSR_address::mhpmcounter6:
        case CSR_address::mhpmcounter7:
        case CSR_address::mhpmcounter8:
        case CSR_address::mhpmcounter9:
        case CSR_address::mhpmcounter10:
        case CSR_address::mhpmcounter11:
        case CSR_address::mhpmcounter12:
        case CSR_address::mhpmcounter13:
        case CSR_address::mhpmcounter14:
        case CSR_address::mhpmcounter15:
        case CSR_address::mhpmcounter16:
        case CSR_address::mhpmcounter17:
        case CSR_address::mhpmcounter18:
        case CSR_address::mhpmcounter19:
        case CSR_address::mhpmcounter20:
        case CSR_address::mhpmcounter21:
        case CSR_address::mhpmcounter22:
        case CSR_address::mhpmcounter23:
        case CSR_address::mhpmcounter24:
        case CSR_address::mhpmcounter25:
        case CSR_address::mhpmcounter26:
        case CSR_address::mhpmcounter27:
        case CSR_address::mhpmcounter28:
        case CSR_address::mhpmcounter29:
        case CSR_address::mhpmcounter30:
        case CSR_address::mhpmcounter31:
        case CSR_address::mcountinhibit:
        case CSR_address::mhpmevent3:
        case CSR_address::mhpmevent4:
        case CSR_address::mhpmevent5:
        case CSR_address::mhpmevent6:
        case CSR_address::mhpmevent7:
        case CSR_address::mhpmevent8:
        case CSR_address::mhpmevent9:
        case CSR_address::mhpmevent10:
        case CSR_address::mhpmevent11:
        case CSR_address::mhpmevent12:
        case CSR_address::mhpmevent13:
        case CSR_address::mhpmevent14:
        case CSR_address::mhpmevent15:
        case CSR_address::mhpmevent16:
        case CSR_address::mhpmevent17:
        case CSR_address::mhpmevent18:
        case CSR_address::mhpmevent19:
        case CSR_address::mhpmevent20:
        case CSR_address::mhpmevent21:
        case CSR_address::mhpmevent22:
        case CSR_address::mhpmevent23:
        case CSR_address::mhpmevent24:
        case CSR_address::mhpmevent25:
        case CSR_address::mhpmevent26:
        case CSR_address::mhpmevent27:
        case CSR_address::mhpmevent28:
        case CSR_address::mhpmevent29:
        case CSR_address::mhpmevent30:
        case CSR_address::mhpmevent31:
        case CSR_address::tselect:
        case CSR_address::tdata1:
        case CSR_address::tdata2:
        case CSR_address::tdata3:
            return execute_status::success;

        default:
            // Invalid CSRs
#ifdef DUMP_INVALID_CSR
            fprintf(stderr, "csr_write: invalid CSR=0x%x\n", static_cast<int>(csraddr));
#endif
            return execute_status::failure;
    }
}

template <typename STATE_ACCESS, typename RS1VAL>
static FORCE_INLINE execute_status execute_csr_RW(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn,
    const RS1VAL &rs1val) {
    auto csraddr = static_cast<CSR_address>(insn_I_get_uimm(insn));
    // Try to read old CSR value
    bool status = true;
    uint64_t csrval = 0;
    // If rd=r0, we do not read from the CSR to avoid side-effects
    const uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        csrval = read_csr(a, mcycle, csraddr, &status);
    }
    if (unlikely(!status)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    // Try to write new CSR value
    //??D When we optimize the inner interpreter loop, we
    //    will have to check if there was a change to the
    //    memory manager and report back from here so we
    //    break out of the inner loop
    const execute_status wstatus = write_csr(a, mcycle, csraddr, rs1val(a, insn));
    if (unlikely(wstatus == execute_status::failure)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    // Write to rd only after potential read/write exceptions
    if (unlikely(rd == 0)) {
        return advance_to_next_insn(a, pc, wstatus);
    }
    a.write_x(rd, csrval);
    return advance_to_next_insn(a, pc, wstatus);
}

/// \brief Implementation of the CSRRW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_CSRRW(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "csrrw");
    return execute_csr_RW(a, pc, mcycle, insn,
        [](STATE_ACCESS a, uint32_t insn) -> uint64_t { return a.read_x(insn_get_rs1(insn)); });
}

/// \brief Implementation of the CSRRWI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_CSRRWI(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "csrrwi");
    return execute_csr_RW(a, pc, mcycle, insn,
        [](STATE_ACCESS, uint32_t insn) -> uint64_t { return static_cast<uint64_t>(insn_get_rs1(insn)); });
}

template <typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_csr_SC(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn,
    const F &f) {
    auto csraddr = static_cast<CSR_address>(insn_I_get_uimm(insn));
    // Try to read old CSR value
    bool status = false;
    const uint64_t csrval = read_csr(a, mcycle, csraddr, &status);
    if (unlikely(!status)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    // Load value of rs1 before potentially overwriting it
    // with the value of the csr when rd=rs1
    const uint32_t rs1 = insn_get_rs1(insn);
    const uint64_t rs1val = a.read_x(rs1);
    execute_status wstatus = execute_status::success;
    if (rs1 != 0) {
        //??D When we optimize the inner interpreter loop, we
        //    will have to check if there was a change to the
        //    memory manager and report back from here so we
        //    break out of the inner loop
        wstatus = write_csr(a, mcycle, csraddr, f(csrval, rs1val));
        if (unlikely(wstatus == execute_status::failure)) {
            return raise_illegal_insn_exception(a, pc, insn);
        }
    }
    // Write to rd only after potential read/write exceptions
    const uint32_t rd = insn_get_rd(insn);
    if (unlikely(rd == 0)) {
        return advance_to_next_insn(a, pc, wstatus);
    }
    a.write_x(rd, csrval);
    return advance_to_next_insn(a, pc, wstatus);
}

/// \brief Implementation of the CSRRS instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_CSRRS(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "csrrs");
    return execute_csr_SC(a, pc, mcycle, insn, [](uint64_t csr, uint64_t rs1) -> uint64_t { return csr | rs1; });
}

/// \brief Implementation of the CSRRC instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_CSRRC(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "csrrc");
    return execute_csr_SC(a, pc, mcycle, insn, [](uint64_t csr, uint64_t rs1) -> uint64_t { return csr & ~rs1; });
}

template <typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_csr_SCI(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn,
    const F &f) {
    auto csraddr = static_cast<CSR_address>(insn_I_get_uimm(insn));
    // Try to read old CSR value
    bool status = false;
    const uint64_t csrval = read_csr(a, mcycle, csraddr, &status);
    if (unlikely(!status)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    const uint32_t rs1 = insn_get_rs1(insn);
    execute_status wstatus = execute_status::success;
    if (rs1 != 0) {
        //??D When we optimize the inner interpreter loop, we
        //    will have to check if there was a change to the
        //    memory manager and report back from here so we
        //    break out of the inner loop
        wstatus = write_csr(a, mcycle, csraddr, f(csrval, rs1));
        if (unlikely(wstatus == execute_status::failure)) {
            return raise_illegal_insn_exception(a, pc, insn);
        }
    }
    // Write to rd only after potential read/write exceptions
    const uint32_t rd = insn_get_rd(insn);
    if (unlikely(rd == 0)) {
        return advance_to_next_insn(a, pc, wstatus);
    }
    a.write_x(rd, csrval);
    return advance_to_next_insn(a, pc, wstatus);
}

/// \brief Implementation of the CSRRSI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_CSRRSI(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "csrrsi");
    return execute_csr_SCI(a, pc, mcycle, insn, [](uint64_t csr, uint32_t rs1) -> uint64_t { return csr | rs1; });
}

/// \brief Implementation of the CSRRCI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_CSRRCI(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "csrrci");
    return execute_csr_SCI(a, pc, mcycle, insn, [](uint64_t csr, uint32_t rs1) -> uint64_t { return csr & ~rs1; });
}

/// \brief Implementation of the ECALL instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ECALL(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "ecall");
    auto prv = a.read_iprv();
    pc = raise_exception(a, pc, MCAUSE_ECALL_BASE + prv, 0);
    return execute_status::failure;
}

/// \brief Implementation of the EBREAK instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_EBREAK(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "ebreak");
    pc = raise_exception(a, pc, MCAUSE_BREAKPOINT, pc);
    return execute_status::failure;
}

/// \brief Implementation of the SRET instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRET(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sret");
    auto prv = a.read_iprv();
    uint64_t mstatus = a.read_mstatus();
    if (unlikely(prv < PRV_S || (prv == PRV_S && (mstatus & MSTATUS_TSR_MASK)))) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    auto spp = (mstatus & MSTATUS_SPP_MASK) >> MSTATUS_SPP_SHIFT;
    /* set the IE state to previous IE state */
    auto spie = (mstatus & MSTATUS_SPIE_MASK) >> MSTATUS_SPIE_SHIFT;
    mstatus = (mstatus & ~MSTATUS_SIE_MASK) | (spie << MSTATUS_SIE_SHIFT);
    /* set SPIE to 1 */
    mstatus |= MSTATUS_SPIE_MASK;
    /* set SPP to U */
    mstatus &= ~MSTATUS_SPP_MASK;
    /* An SRET instruction that changes the privilege mode to a mode
     * less privileged than M also sets MPRV = 0 */
    if (spp < PRV_M) {
        mstatus &= ~MSTATUS_MPRV_MASK;
    }
    a.write_mstatus(mstatus);
    if (prv != spp) {
        set_prv(a, spp);
    }
    pc = a.read_sepc();
    return execute_status::success_and_serve_interrupts;
}

/// \brief Implementation of the MRET instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_MRET(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "mret");
    auto prv = a.read_iprv();
    if (unlikely(prv < PRV_M)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    uint64_t mstatus = a.read_mstatus();
    auto mpp = (mstatus & MSTATUS_MPP_MASK) >> MSTATUS_MPP_SHIFT;
    //??D we can save one shift here, but maybe the compiler already does
    /* set the IE state to previous IE state */
    auto mpie = (mstatus & MSTATUS_MPIE_MASK) >> MSTATUS_MPIE_SHIFT;
    mstatus = (mstatus & ~MSTATUS_MIE_MASK) | (mpie << MSTATUS_MIE_SHIFT);
    /* set MPIE to 1 */
    mstatus |= MSTATUS_MPIE_MASK;
    /* set MPP to U */
    mstatus &= ~MSTATUS_MPP_MASK;
    /* An MRET instruction that changes the privilege mode to a mode
     * less privileged than M also sets MPRV = 0 */
    if (mpp < PRV_M) {
        mstatus &= ~MSTATUS_MPRV_MASK;
    }
    a.write_mstatus(mstatus);
    if (prv != mpp) {
        set_prv(a, mpp);
    }
    pc = a.read_mepc();
    return execute_status::success_and_serve_interrupts;
}

/// \brief Implementation of the WFI instruction.
/// \details This function is outlined to minimize host CPU code cache pressure.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_WFI(STATE_ACCESS a, uint64_t &pc, uint64_t &mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "wfi");
    // Check privileges and do nothing else
    auto prv = a.read_iprv();
    const uint64_t mstatus = a.read_mstatus();
    // WFI can always causes an illegal instruction exception in less-privileged modes when TW=1
    if (unlikely(prv == PRV_U || (prv < PRV_M && (mstatus & MSTATUS_TW_MASK)))) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    // We wait for interrupts until the next timer interrupt.
    const uint64_t mcycle_max = rtc_time_to_cycle(a.read_clint_mtimecmp());
    execute_status status = execute_status::success;
    if (mcycle_max > mcycle) {
        // Poll for external interrupts (e.g console or network),
        // this may advance mcycle only when interactive mode is enabled
        const auto [next_mcycle, interrupted] = a.poll_external_interrupts(mcycle, mcycle_max);
        mcycle = next_mcycle;
        if (interrupted) {
            status = execute_status::success_and_serve_interrupts;
        }
    }
    return advance_to_next_insn(a, pc, status);
}

/// \brief Implementation of the FENCE instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FENCE(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    INC_COUNTER(a.get_statistics(), fence);
    dump_insn(a, pc, insn, "fence");
    // Really do nothing
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the FENCE.I instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FENCE_I(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    INC_COUNTER(a.get_statistics(), fence_i);
    dump_insn(a, pc, insn, "fence.i");
    // Really do nothing
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_arithmetic(STATE_ACCESS a, uint64_t &pc, uint32_t insn, const F &f) {
    const uint32_t rd = insn_get_rd(insn);
    // Ensure rs1 and rs2 are loaded in order: do not nest with call to f() as
    // the order of evaluation of arguments in a function call is undefined.
    const uint64_t rs1 = a.read_x(insn_get_rs1(insn));
    const uint64_t rs2 = a.read_x(insn_get_rs2(insn));
    // Now we can safely invoke f()
    a.write_x(rd, f(rs1, rs2));
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the ADD instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ADD(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "add");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        uint64_t val = 0;
        __builtin_add_overflow(rs1, rs2, &val);
        return val;
    });
}

/// \brief Implementation of the SUB instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SUB(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sub");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        uint64_t val = 0;
        __builtin_sub_overflow(rs1, rs2, &val);
        return val;
    });
}

/// \brief Implementation of the SLL instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLL(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sll");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn,
        [](uint64_t rs1, uint64_t rs2) -> uint64_t { return rs1 << (rs2 & (XLEN - 1)); });
}

/// \brief Implementation of the SLT instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLT(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "slt");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn,
        [](uint64_t rs1, uint64_t rs2) -> uint64_t { return static_cast<int64_t>(rs1) < static_cast<int64_t>(rs2); });
}

/// \brief Implementation of the SLTU instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLTU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sltu");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t { return rs1 < rs2; });
}

/// \brief Implementation of the XOR instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_XOR(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "xor");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t { return rs1 ^ rs2; });
}

/// \brief Implementation of the SRL instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRL(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "srl");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn,
        [](uint64_t rs1, uint64_t rs2) -> uint64_t { return rs1 >> (rs2 & (XLEN - 1)); });
}

/// \brief Implementation of the SRA instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRA(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sra");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return static_cast<uint64_t>(static_cast<int64_t>(rs1) >> (rs2 & (XLEN - 1)));
    });
}

/// \brief Implementation of the OR instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_OR(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "or");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t { return rs1 | rs2; });
}

/// \brief Implementation of the AND instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AND(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "and");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t { return rs1 & rs2; });
}

/// \brief Implementation of the MUL instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_MUL(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "mul");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto srs1 = static_cast<int64_t>(rs1);
        auto srs2 = static_cast<int64_t>(rs2);
        int64_t val = 0;
        __builtin_mul_overflow(srs1, srs2, &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the MULH instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_MULH(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "mulh");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto srs1 = static_cast<int64_t>(rs1);
        auto srs2 = static_cast<int64_t>(rs2);
        return static_cast<uint64_t>(static_cast<int64_t>((static_cast<int128_t>(srs1) * srs2) >> 64));
    });
}

/// \brief Implementation of the MULHSU instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_MULHSU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "mulhsu");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto srs1 = static_cast<int64_t>(rs1);
        return static_cast<uint64_t>(
            static_cast<int64_t>((static_cast<int128_t>(srs1) * static_cast<int128_t>(rs2)) >> 64));
    });
}

/// \brief Implementation of the MULHU instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_MULHU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "mulhu");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return static_cast<uint64_t>((static_cast<uint128_t>(rs1) * static_cast<uint128_t>(rs2)) >> 64);
    });
}

/// \brief Implementation of the DIV instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_DIV(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "div");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto srs1 = static_cast<int64_t>(rs1);
        auto srs2 = static_cast<int64_t>(rs2);
        if (unlikely(srs2 == 0)) {
            return static_cast<uint64_t>(-1);
        }
        if (unlikely(srs2 == -1 && srs1 == (INT64_C(1) << (XLEN - 1)))) {
            return static_cast<uint64_t>(srs1);
        }
        return static_cast<uint64_t>(srs1 / srs2);
    });
}

/// \brief Implementation of the DIVU instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_DIVU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "divu");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        if (unlikely(rs2 == 0)) {
            return static_cast<uint64_t>(-1);
        }
        return rs1 / rs2;
    });
}

/// \brief Implementation of the REM instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_REM(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "rem");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto srs1 = static_cast<int64_t>(rs1);
        auto srs2 = static_cast<int64_t>(rs2);
        if (unlikely(srs2 == 0)) {
            return srs1;
        }
        if (unlikely(srs2 == -1 && srs1 == (INT64_C(1) << (XLEN - 1)))) {
            return 0;
        }
        return static_cast<uint64_t>(srs1 % srs2);
    });
}

/// \brief Implementation of the REMU instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_REMU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "remu");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        if (unlikely(rs2 == 0)) {
            return rs1;
        }
        return rs1 % rs2;
    });
}

template <typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_arithmetic_immediate(STATE_ACCESS a, uint64_t &pc, uint32_t insn,
    const F &f) {
    const uint32_t rd = insn_get_rd(insn);
    const uint64_t rs1 = a.read_x(insn_get_rs1(insn));
    const int32_t imm = insn_I_get_imm(insn);
    a.write_x(rd, f(rs1, imm));
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the SRLI instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRLI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "srli");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic_immediate(a, pc, insn,
        [](uint64_t rs1, int32_t imm) -> uint64_t { return rs1 >> (imm & (XLEN - 1)); });
}

/// \brief Implementation of the SRAI instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRAI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "srai");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return static_cast<uint64_t>(static_cast<int64_t>(rs1) >> (imm & (XLEN - 1)));
    });
}

/// \brief Implementation of the ADDI instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ADDI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "addi");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        int64_t val = 0;
        __builtin_add_overflow(static_cast<int64_t>(rs1), static_cast<int64_t>(imm), &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the SLTI instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLTI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "slti");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic_immediate(a, pc, insn,
        [](uint64_t rs1, int32_t imm) -> uint64_t { return static_cast<int64_t>(rs1) < static_cast<int64_t>(imm); });
}

/// \brief Implementation of the SLTIU instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLTIU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sltiu");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic_immediate(a, pc, insn,
        [](uint64_t rs1, int32_t imm) -> uint64_t { return rs1 < static_cast<uint64_t>(imm); });
}

/// \brief Implementation of the XORI instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_XORI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "xori");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t { return rs1 ^ imm; });
}

/// \brief Implementation of the ORI instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ORI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "ori");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t { return rs1 | imm; });
}

/// \brief Implementation of the ANDI instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ANDI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "andi");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t { return rs1 & imm; });
}

/// \brief Implementation of the SLLI instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLLI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    if (unlikely((insn & (0b111111 << 26)) != 0)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    dump_insn(a, pc, insn, "slli");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        // No need to mask lower 6 bits in imm because of the if condition a above
        // We do it anyway here to prevent problems if this code is moved
        return rs1 << (imm & 0b111111);
    });
}

/// \brief Implementation of the ADDIW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ADDIW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "addiw");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        int32_t val = 0;
        __builtin_add_overflow(static_cast<int32_t>(rs1), imm, &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the SLLIW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLLIW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    if (unlikely(insn_get_funct7(insn) != 0)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    dump_insn(a, pc, insn, "slliw");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        // No need to mask lower 5 bits in imm because of the if condition a above
        // We do it anyway here to prevent problems if this code is moved
        const auto rs1w = static_cast<int32_t>(static_cast<uint32_t>(rs1) << (imm & 0b11111));
        return static_cast<uint64_t>(rs1w);
    });
}

/// \brief Implementation of the SRLIW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRLIW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "srliw");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        // No need to mask lower 5 bits in imm because of funct7 test in caller
        // We do it anyway here to prevent problems if this code is moved
        auto rs1w = static_cast<int32_t>(static_cast<uint32_t>(rs1) >> (imm & 0b11111));
        return static_cast<uint64_t>(rs1w);
    });
}

/// \brief Implementation of the SRAIW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRAIW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sraiw");
    if constexpr (rd_kind == rd_kind::x0) {
        // When rd=0 the instruction is a HINT, and we consider it as a soft yield when rs1 == 31
        if (unlikely(insn_get_rs1(insn) == 31 && a.get_soft_yield())) {
            // Force the main interpreter loop to break
            return advance_to_next_insn(a, pc, execute_status::success_and_yield);
        }
        return advance_to_next_insn(a, pc);
    }
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        const int32_t rs1w = static_cast<int32_t>(rs1) >> (imm & 0b11111);
        return static_cast<uint64_t>(rs1w);
    });
}

template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_S(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    const uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    const int32_t imm = insn_S_get_imm(insn);
    const uint64_t val = a.read_x(insn_get_rs2(insn));
    const execute_status status = write_virtual_memory<T>(a, pc, mcycle, vaddr + imm, val);
    if (unlikely(status != execute_status::success)) {
        if (status == execute_status::failure) {
            return advance_to_raised_exception(a, pc);
        }
        return advance_to_next_insn(a, pc, status);
    }
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the SB instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SB(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "sb");
    return execute_S<uint8_t>(a, pc, mcycle, insn);
}

/// \brief Implementation of the SH instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SH(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "sh");
    return execute_S<uint16_t>(a, pc, mcycle, insn);
}

/// \brief Implementation of the SW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SW(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "sw");
    return execute_S<uint32_t>(a, pc, mcycle, insn);
}

/// \brief Implementation of the SD instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SD(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "sd");
    return execute_S<uint64_t>(a, pc, mcycle, insn);
}

template <typename T, rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_L(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    const uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    const int32_t imm = insn_I_get_imm(insn);
    T val = 0;
    if (unlikely(!read_virtual_memory<T>(a, pc, mcycle, vaddr + imm, &val))) {
        return advance_to_raised_exception(a, pc);
    }
    const uint32_t rd = insn_get_rd(insn);
    // don't write x0
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    // This static branch is eliminated by the compiler
    if constexpr (std::is_signed_v<T>) {
        a.write_x(rd, static_cast<int64_t>(val));
    } else {
        a.write_x(rd, static_cast<uint64_t>(val));
    }
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the LB instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LB(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "lb");
    return execute_L<int8_t, rd_kind>(a, pc, mcycle, insn);
}

/// \brief Implementation of the LH instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LH(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "lh");
    return execute_L<int16_t, rd_kind>(a, pc, mcycle, insn);
}

/// \brief Implementation of the LW instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LW(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "lw");
    return execute_L<int32_t, rd_kind>(a, pc, mcycle, insn);
}

/// \brief Implementation of the LD instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LD(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "ld");
    return execute_L<int64_t, rd_kind>(a, pc, mcycle, insn);
}

/// \brief Implementation of the LBU instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LBU(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "lbu");
    return execute_L<uint8_t, rd_kind>(a, pc, mcycle, insn);
}

/// \brief Implementation of the LHU instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LHU(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "lhu");
    return execute_L<uint16_t, rd_kind>(a, pc, mcycle, insn);
}

/// \brief Implementation of the LWU instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LWU(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "lwu");
    return execute_L<uint32_t, rd_kind>(a, pc, mcycle, insn);
}

template <typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_branch(STATE_ACCESS a, uint64_t &pc, uint32_t insn, const F &f) {
    const uint64_t rs1 = a.read_x(insn_get_rs1(insn));
    const uint64_t rs2 = a.read_x(insn_get_rs2(insn));
    if (f(rs1, rs2)) {
        const uint64_t new_pc = static_cast<int64_t>(pc + insn_B_get_imm(insn));
        return execute_jump(a, pc, new_pc);
    }
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the BEQ instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_BEQ(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "beq");
    return execute_branch(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool { return rs1 == rs2; });
}

/// \brief Implementation of the BNE instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_BNE(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "bne");
    return execute_branch(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool { return rs1 != rs2; });
}

/// \brief Implementation of the BLT instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_BLT(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "blt");
    return execute_branch(a, pc, insn,
        [](uint64_t rs1, uint64_t rs2) -> bool { return static_cast<int64_t>(rs1) < static_cast<int64_t>(rs2); });
}

/// \brief Implementation of the BGE instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_BGE(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "bge");
    return execute_branch(a, pc, insn,
        [](uint64_t rs1, uint64_t rs2) -> bool { return static_cast<int64_t>(rs1) >= static_cast<int64_t>(rs2); });
}

/// \brief Implementation of the BLTU instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_BLTU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "bltu");
    return execute_branch(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool { return rs1 < rs2; });
}

/// \brief Implementation of the BGEU instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_BGEU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "bgeu");
    return execute_branch(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool { return rs1 >= rs2; });
}

/// \brief Implementation of the LUI instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LUI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "lui");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    const uint32_t rd = insn_get_rd(insn);
    a.write_x(rd, insn_U_get_imm(insn));
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the AUIPC instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AUIPC(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "auipc");
    if constexpr (rd_kind == rd_kind::x0) {
        return advance_to_next_insn(a, pc);
    }
    const uint32_t rd = insn_get_rd(insn);
    a.write_x(rd, pc + insn_U_get_imm(insn));
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the JAL instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_JAL(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "jal");
    const uint64_t new_pc = pc + insn_J_get_imm(insn);
    if constexpr (rd_kind == rd_kind::x0) {
        return execute_jump(a, pc, new_pc);
    }
    const uint32_t rd = insn_get_rd(insn);
    a.write_x(rd, pc + 4);
    return execute_jump(a, pc, new_pc);
}

/// \brief Implementation of the JALR instruction.
template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_JALR(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "jalr");
    const uint64_t val = pc + 4;
    const uint64_t new_pc =
        static_cast<int64_t>(a.read_x(insn_get_rs1(insn)) + insn_I_get_imm(insn)) & ~static_cast<uint64_t>(1);
    const uint32_t rd = insn_get_rd(insn);
    if constexpr (rd_kind != rd_kind::x0) {
        a.write_x(rd, val);
        return execute_jump(a, pc, new_pc);
    }
    return execute_jump(a, pc, new_pc);
}

/// \brief Implementation of the SFENCE.VMA instruction.
/// \details This function is outlined to minimize host CPU code cache pressure.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SFENCE_VMA(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // rs1 and rs2 are arbitrary, rest is set
    if (unlikely((insn & 0b11111110000000000111111111111111) != 0b00010010000000000000000001110011)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    INC_COUNTER(a.get_statistics(), fence_vma);
    dump_insn(a, pc, insn, "sfence.vma");
    auto prv = a.read_iprv();
    const uint64_t mstatus = a.read_mstatus();

    // When TVM=1, attempts to execute an SFENCE.VMA while executing in S-mode
    // will raise an illegal instruction exception.
    if (unlikely(prv == PRV_U || (prv == PRV_S && (mstatus & MSTATUS_TVM_MASK)))) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    const uint32_t rs1 = insn_get_rs1(insn);
    [[maybe_unused]] const uint32_t rs2 = insn_get_rs2(insn);
    if (rs1 == 0) {
        a.flush_all_tlb();
#ifdef DUMP_COUNTERS
        INC_COUNTER(a.get_statistics(), tlb_flush_all);
        if (rs2 == 0) {
            // Invalidates all address-translation cache entries, for all address spaces
            INC_COUNTER(a.get_statistics(), tlb_flush_fence_vma_all);
        } else {
            // Invalidates all address-translation cache entries matching the
            // address space identified by integer register rs2,
            // except for entries containing global mappings.
            INC_COUNTER(a.get_statistics(), tlb_flush_fence_vma_asid);
        }
#endif
    } else {
        const uint64_t vaddr = a.read_x(rs1);
        a.flush_tlb_vaddr(vaddr);
#ifdef DUMP_COUNTERS
        INC_COUNTER(a.get_statistics(), tlb_flush_vaddr);
        if (rs2 == 0) {
            // Invalidates all address-translation cache entries that contain leaf page table entries
            // corresponding to the virtual address in rs1, for all address spaces.
            INC_COUNTER(a.get_statistics(), tlb_flush_fence_vma_vaddr);
        } else {
            // Invalidates all address-translation cache entries that contain leaf page table entries
            // corresponding to the virtual address in rs1
            // and that match the address space identified by integer register rs2,
            // except for entries containing global mappings.
            INC_COUNTER(a.get_statistics(), tlb_flush_fence_vma_asid_vaddr);
        }
#endif
    }
    return advance_to_next_insn(a, pc, execute_status::success_and_flush_fetch);
}

template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRLI_SRAI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // Use ifs instead of a switch to produce fewer branches for the most frequent instructions
    const auto funct7_sr1 = static_cast<insn_SRLI_SRAI_funct7_sr1>(insn_get_funct7_sr1(insn));
    if (funct7_sr1 == insn_SRLI_SRAI_funct7_sr1::SRLI) {
        return execute_SRLI<rd_kind>(a, pc, insn);
    }
    if (funct7_sr1 == insn_SRLI_SRAI_funct7_sr1::SRAI) {
        return execute_SRAI<rd_kind>(a, pc, insn);
    }
    return raise_illegal_insn_exception(a, pc, insn);
}

template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRLIW_SRAIW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // Use ifs instead of a switch to produce fewer branches for the most frequent instructions
    const auto funct7 = static_cast<insn_SRLIW_SRAIW_funct7>(insn_get_funct7(insn));
    if (funct7 == insn_SRLIW_SRAIW_funct7::SRLIW) {
        return execute_SRLIW<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_SRLIW_SRAIW_funct7::SRAIW) {
        return execute_SRAIW<rd_kind>(a, pc, insn);
    }
    return raise_illegal_insn_exception(a, pc, insn);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMO_W(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    switch (static_cast<insn_AMO_funct7_sr2>(insn_get_funct7_sr2(insn))) {
        case insn_AMO_funct7_sr2::AMOADD:
            return execute_AMOADD_W(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOSWAP:
            return execute_AMOSWAP_W(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::LR:
            return execute_LR_W(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::SC:
            return execute_SC_W(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOXOR:
            return execute_AMOXOR_W(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOOR:
            return execute_AMOOR_W(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOAND:
            return execute_AMOAND_W(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOMIN:
            return execute_AMOMIN_W(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOMAX:
            return execute_AMOMAX_W(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOMINU:
            return execute_AMOMINU_W(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOMAXU:
            return execute_AMOMAXU_W(a, pc, mcycle, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMO_D(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    switch (static_cast<insn_AMO_funct7_sr2>(insn_get_funct7_sr2(insn))) {
        case insn_AMO_funct7_sr2::AMOADD:
            return execute_AMOADD_D(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOSWAP:
            return execute_AMOSWAP_D(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::LR:
            return execute_LR_D(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::SC:
            return execute_SC_D(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOXOR:
            return execute_AMOXOR_D(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOOR:
            return execute_AMOOR_D(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOAND:
            return execute_AMOAND_D(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOMIN:
            return execute_AMOMIN_D(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOMAX:
            return execute_AMOMAX_D(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOMINU:
            return execute_AMOMINU_D(a, pc, mcycle, insn);
        case insn_AMO_funct7_sr2::AMOMAXU:
            return execute_AMOMAXU_D(a, pc, mcycle, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ADD_MUL_SUB(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // Use ifs instead of a switch to produce fewer branches for the most frequent instructions
    const auto funct7 = static_cast<insn_ADD_MUL_SUB_funct7>(insn_get_funct7(insn));
    if (funct7 == insn_ADD_MUL_SUB_funct7::ADD) {
        return execute_ADD<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_ADD_MUL_SUB_funct7::MUL) {
        return execute_MUL<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_ADD_MUL_SUB_funct7::SUB) {
        return execute_SUB<rd_kind>(a, pc, insn);
    }
    return raise_illegal_insn_exception(a, pc, insn);
}

template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLL_MULH(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // Use ifs instead of a switch to produce fewer branches for the most frequent instructions
    const auto funct7 = static_cast<insn_SLL_MULH_funct7>(insn_get_funct7(insn));
    if (funct7 == insn_SLL_MULH_funct7::SLL) {
        return execute_SLL<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_SLL_MULH_funct7::MULH) {
        return execute_MULH<rd_kind>(a, pc, insn);
    }
    return raise_illegal_insn_exception(a, pc, insn);
}

template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLT_MULHSU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // Use ifs instead of a switch to produce fewer branches for the most frequent instructions
    const auto funct7 = static_cast<insn_SLT_MULHSU_funct7>(insn_get_funct7(insn));
    if (funct7 == insn_SLT_MULHSU_funct7::SLT) {
        return execute_SLT<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_SLT_MULHSU_funct7::MULHSU) {
        return execute_MULHSU<rd_kind>(a, pc, insn);
    }
    return raise_illegal_insn_exception(a, pc, insn);
}

template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLTU_MULHU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // Use ifs instead of a switch to produce fewer branches for the most frequent instructions
    const auto funct7 = static_cast<insn_SLTU_MULHU_funct7>(insn_get_funct7(insn));
    if (funct7 == insn_SLTU_MULHU_funct7::SLTU) {
        return execute_SLTU<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_SLTU_MULHU_funct7::MULHU) {
        return execute_MULHU<rd_kind>(a, pc, insn);
    }
    return raise_illegal_insn_exception(a, pc, insn);
}

template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_XOR_DIV(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // Use ifs instead of a switch to produce fewer branches for the most frequent instructions
    const auto funct7 = static_cast<insn_XOR_DIV_funct7>(insn_get_funct7(insn));
    if (funct7 == insn_XOR_DIV_funct7::XOR) {
        return execute_XOR<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_XOR_DIV_funct7::DIV) {
        return execute_DIV<rd_kind>(a, pc, insn);
    }
    return raise_illegal_insn_exception(a, pc, insn);
}

template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRL_DIVU_SRA(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // Use ifs instead of a switch to produce fewer branches for the most frequent instructions
    const auto funct7 = static_cast<insn_SRL_DIVU_SRA_funct7>(insn_get_funct7(insn));
    if (funct7 == insn_SRL_DIVU_SRA_funct7::SRL) {
        return execute_SRL<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_SRL_DIVU_SRA_funct7::SRA) {
        return execute_SRA<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_SRL_DIVU_SRA_funct7::DIVU) {
        return execute_DIVU<rd_kind>(a, pc, insn);
    }
    return raise_illegal_insn_exception(a, pc, insn);
}

template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_OR_REM(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // Use ifs instead of a switch to produce fewer branches for the most frequent instructions
    const auto funct7 = static_cast<insn_OR_REM_funct7>(insn_get_funct7(insn));
    if (funct7 == insn_OR_REM_funct7::OR) {
        return execute_OR<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_OR_REM_funct7::REM) {
        return execute_REM<rd_kind>(a, pc, insn);
    }
    return raise_illegal_insn_exception(a, pc, insn);
}

template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AND_REMU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // Use ifs instead of a switch to produce fewer branches for the most frequent instructions
    const auto funct7 = static_cast<insn_AND_REMU_funct7>(insn_get_funct7(insn));
    if (funct7 == insn_AND_REMU_funct7::AND) {
        return execute_AND<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_AND_REMU_funct7::REMU) {
        return execute_REMU<rd_kind>(a, pc, insn);
    }
    return raise_illegal_insn_exception(a, pc, insn);
}

template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ADDW_MULW_SUBW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // Use ifs instead of a switch to produce fewer branches for the most frequent instructions
    const auto funct7 = static_cast<insn_ADDW_MULW_SUBW_funct7>(insn_get_funct7(insn));
    if (funct7 == insn_ADDW_MULW_SUBW_funct7::ADDW) {
        return execute_ADDW<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_ADDW_MULW_SUBW_funct7::MULW) {
        return execute_MULW<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_ADDW_MULW_SUBW_funct7::SUBW) {
        return execute_SUBW<rd_kind>(a, pc, insn);
    }
    return raise_illegal_insn_exception(a, pc, insn);
}

template <rd_kind rd_kind, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRLW_DIVUW_SRAW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // Use ifs instead of a switch to produce fewer branches for the most frequent instructions
    const auto funct7 = static_cast<insn_SRLW_DIVUW_SRAW_funct7>(insn_get_funct7(insn));
    if (funct7 == insn_SRLW_DIVUW_SRAW_funct7::SRLW) {
        return execute_SRLW<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_SRLW_DIVUW_SRAW_funct7::DIVUW) {
        return execute_DIVUW<rd_kind>(a, pc, insn);
    }
    if (funct7 == insn_SRLW_DIVUW_SRAW_funct7::SRAW) {
        return execute_SRAW<rd_kind>(a, pc, insn);
    }
    return raise_illegal_insn_exception(a, pc, insn);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_privileged(STATE_ACCESS a, uint64_t &pc, uint64_t &mcycle, uint32_t insn) {
    switch (static_cast<insn_privileged>(insn)) {
        case insn_privileged::ECALL:
            return execute_ECALL(a, pc, insn);
        case insn_privileged::EBREAK:
            return execute_EBREAK(a, pc, insn);
        case insn_privileged::SRET:
            return execute_SRET(a, pc, insn);
        case insn_privileged::MRET:
            return execute_MRET(a, pc, insn);
        case insn_privileged::WFI:
            return execute_WFI(a, pc, mcycle, insn);
        default:
            return execute_SFENCE_VMA(a, pc, insn);
    }
}

/// \brief Performs NaN-boxing for a float value.
/// \param val Float value as an unsigned integer.
/// \returns A valid NaN-boxed float value.
template <typename T>
static inline uint64_t float_box(T val) {
    constexpr uint64_t TLEN = sizeof(T) * 8;
    // Any operation that writes a narrower result to an f register must write all 1s to
    // the uppermost FLEN−n bits to yield a legal NaN-boxed value.
    if constexpr (TLEN < FLEN) {
        return val | (UINT64_C(-1) << TLEN);
    } else {
        return val;
    }
}

/// \brief Performs NaN-unboxing for a float value.
/// \tparam T Respective float unsigned type to save the unboxed value.
/// \param val Float value as an unsigned integer.
/// \returns A valid float if the NaN-unboxing succeeds, otherwise the canonical NaN for type T.
template <typename T>
static inline T float_unbox(uint64_t val) {
    constexpr uint64_t TLEN = sizeof(T) * 8;
    static_assert(TLEN == 32 || TLEN == 64, "unsupported soft float length");
    if constexpr (TLEN < FLEN) {
        // Floating-point operations on narrower n-bit operations (n < FLEN),
        // must check if the input operands are correctly NaN-boxed, i.e., all upper FLEN−n bits are 1.
        // If so, the n least-significant bits of the input are used as the
        // input value, otherwise the input value is treated as an n-bit canonical NaN.
        if ((val >> TLEN) != (UINT64_C(-1) >> TLEN)) {
            // The canonical NaN has a positive sign and all significant bits clear except the MSB,
            // a.k.a. the quiet bit.
            if constexpr (TLEN == 32) {
                return i_sfloat32::F_QNAN;
            } else if constexpr (TLEN == 64) {
                return i_sfloat64::F_QNAN;
            }
        }
    }
    // Returns the n least-significant bits of the input.
    return static_cast<T>(val);
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_float_ternary_op_rm(STATE_ACCESS a, uint64_t &pc, uint32_t insn,
    const F &f) {
    const uint64_t fcsr = a.read_fcsr();
    // The rounding mode comes from the insn
    const uint32_t rm = insn_get_rm(insn, fcsr);
    // If the rounding mode is invalid, the instruction is considered illegal
    if (unlikely(rm > FRM_RMM)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    const uint32_t rd = insn_get_rd(insn);
    auto fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
    // We must always check if input operands are properly NaN-boxed.
    T s1 = float_unbox<T>(a.read_f(insn_get_rs1(insn)));
    T s2 = float_unbox<T>(a.read_f(insn_get_rs2(insn)));
    T s3 = float_unbox<T>(a.read_f(insn_get_rs3(insn)));
    // Must store a valid NaN-boxed value.
    a.write_f(rd, float_box(f(s1, s2, s3, rm, &fflags)));
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    return advance_to_next_insn(a, pc);
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_float_binary_op_rm(STATE_ACCESS a, uint64_t &pc, uint32_t insn, const F &f) {
    const uint64_t fcsr = a.read_fcsr();
    // The rounding mode comes from the insn
    const uint32_t rm = insn_get_rm(insn, fcsr);
    // If the rounding mode is invalid, the instruction is considered illegal
    if (unlikely(rm > FRM_RMM)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    const uint32_t rd = insn_get_rd(insn);
    auto fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
    // We must always check if input operands are properly NaN-boxed.
    T s1 = float_unbox<T>(a.read_f(insn_get_rs1(insn)));
    T s2 = float_unbox<T>(a.read_f(insn_get_rs2(insn)));
    // Must store a valid NaN-boxed value.
    a.write_f(rd, float_box(f(s1, s2, rm, &fflags)));
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    return advance_to_next_insn(a, pc);
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_float_unary_op_rm(STATE_ACCESS a, uint64_t &pc, uint32_t insn, const F &f) {
    const uint64_t fcsr = a.read_fcsr();
    // Unary operation should have rs2 set to 0
    if (unlikely(insn_get_rs2(insn) != 0)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    // The rounding mode comes from the insn
    const uint32_t rm = insn_get_rm(insn, fcsr);
    // If the rounding mode is invalid, the instruction is considered illegal
    if (unlikely(rm > FRM_RMM)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    const uint32_t rd = insn_get_rd(insn);
    auto fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
    // We must always check if input operands are properly NaN-boxed.
    T s1 = float_unbox<T>(a.read_f(insn_get_rs1(insn)));
    // Must store a valid NaN-boxed value.
    a.write_f(rd, float_box(f(s1, rm, &fflags)));
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    return advance_to_next_insn(a, pc);
}

template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FS(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    const uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    const int32_t imm = insn_S_get_imm(insn);
    // A narrower n-bit transfer out of the floating-point
    // registers will transfer the lower n bits of the register ignoring the upper FLEN−n bits.
    T val = static_cast<T>(a.read_f(insn_get_rs2(insn)));
    const execute_status status = write_virtual_memory<T>(a, pc, mcycle, vaddr + imm, val);
    if (unlikely(status != execute_status::success)) {
        if (status == execute_status::failure) {
            return advance_to_raised_exception(a, pc);
        }
        return advance_to_next_insn(a, pc, status);
    }
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSW(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "fsw");
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    return execute_FS<uint32_t>(a, pc, mcycle, insn);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSD(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "fsd");
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    return execute_FS<uint64_t>(a, pc, mcycle, insn);
}

template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FL(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    // Loads the float value from virtual memory
    const uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    const int32_t imm = insn_I_get_imm(insn);
    T val = 0;
    if (unlikely(!read_virtual_memory(a, pc, mcycle, vaddr + imm, &val))) {
        return advance_to_raised_exception(a, pc);
    }
    // A narrower n-bit transfer, n < FLEN,
    // into the f registers will create a valid NaN-boxed value.
    const uint32_t rd = insn_get_rd(insn);
    a.write_f(rd, float_box(val));
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FLW(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "flw");
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    return execute_FL<uint32_t>(a, pc, mcycle, insn);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FLD(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, insn, "fld");
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    return execute_FL<uint64_t>(a, pc, mcycle, insn);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMADD_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmadd.s");
    return execute_float_ternary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t s3, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::fma(s1, s2, s3, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMADD_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmadd.d");
    return execute_float_ternary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint64_t s3, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::fma(s1, s2, s3, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMADD(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    switch (static_cast<insn_FM_funct2_0000000000000000000000000>(insn_get_funct2_0000000000000000000000000(insn))) {
        case insn_FM_funct2_0000000000000000000000000::S:
            return execute_FMADD_S(a, pc, insn);
        case insn_FM_funct2_0000000000000000000000000::D:
            return execute_FMADD_D(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMSUB_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmsub.s");
    return execute_float_ternary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t s3, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::fma(s1, s2, s3 ^ i_sfloat32::SIGN_MASK, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMSUB_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmsub.d");
    return execute_float_ternary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint64_t s3, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::fma(s1, s2, s3 ^ i_sfloat64::SIGN_MASK, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMSUB(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    switch (static_cast<insn_FM_funct2_0000000000000000000000000>(insn_get_funct2_0000000000000000000000000(insn))) {
        case insn_FM_funct2_0000000000000000000000000::S:
            return execute_FMSUB_S(a, pc, insn);
        case insn_FM_funct2_0000000000000000000000000::D:
            return execute_FMSUB_D(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FNMADD_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fnmadd.s");
    return execute_float_ternary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t s3, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::fma(s1 ^ i_sfloat32::SIGN_MASK, s2, s3 ^ i_sfloat32::SIGN_MASK,
                static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FNMADD_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fnmadd.d");
    return execute_float_ternary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint64_t s3, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::fma(s1 ^ i_sfloat64::SIGN_MASK, s2, s3 ^ i_sfloat64::SIGN_MASK,
                static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FNMADD(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    switch (static_cast<insn_FM_funct2_0000000000000000000000000>(insn_get_funct2_0000000000000000000000000(insn))) {
        case insn_FM_funct2_0000000000000000000000000::S:
            return execute_FNMADD_S(a, pc, insn);
        case insn_FM_funct2_0000000000000000000000000::D:
            return execute_FNMADD_D(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FNMSUB_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fnmsub.s");
    return execute_float_ternary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t s3, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::fma(s1 ^ i_sfloat32::SIGN_MASK, s2, s3, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FNMSUB_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fnmsub.d");
    return execute_float_ternary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint64_t s3, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::fma(s1 ^ i_sfloat64::SIGN_MASK, s2, s3, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FNMSUB(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    switch (static_cast<insn_FM_funct2_0000000000000000000000000>(insn_get_funct2_0000000000000000000000000(insn))) {
        case insn_FM_funct2_0000000000000000000000000::S:
            return execute_FNMSUB_S(a, pc, insn);
        case insn_FM_funct2_0000000000000000000000000::D:
            return execute_FNMSUB_D(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FADD_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fadd.s");
    return execute_float_binary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::add(s1, s2, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FADD_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fadd.d");
    return execute_float_binary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::add(s1, s2, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSUB_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsub.s");
    return execute_float_binary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::add(s1, s2 ^ i_sfloat32::SIGN_MASK, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSUB_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsub.d");
    return execute_float_binary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::add(s1, s2 ^ i_sfloat64::SIGN_MASK, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMUL_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmul.s");
    return execute_float_binary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::mul(s1, s2, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMUL_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmul.d");
    return execute_float_binary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::mul(s1, s2, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FDIV_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fdiv.s");
    return execute_float_binary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::div(s1, s2, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FDIV_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fdiv.d");
    return execute_float_binary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::div(s1, s2, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_FCLASS(STATE_ACCESS a, uint64_t &pc, uint32_t insn, const F &f) {
    const uint32_t rd = insn_get_rd(insn);
    if (unlikely(rd == 0)) {
        return advance_to_next_insn(a, pc);
    }
    // We must always check if input operands are properly NaN-boxed.
    T s1 = float_unbox<T>(a.read_f(insn_get_rs1(insn)));
    a.write_x(rd, f(s1));
    return advance_to_next_insn(a, pc);
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_float_binary_op(STATE_ACCESS a, uint64_t &pc, uint32_t insn, const F &f) {
    const uint64_t fcsr = a.read_fcsr();
    // We must always check if input operands are properly NaN-boxed.
    T s1 = float_unbox<T>(a.read_f(insn_get_rs1(insn)));
    T s2 = float_unbox<T>(a.read_f(insn_get_rs2(insn)));
    const uint32_t rd = insn_get_rd(insn);
    auto fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK); // NOLINT(misc-const-correctness)
    // Must store a valid NaN-boxed value.
    a.write_f(rd, float_box(f(s1, s2, &fflags)));
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    return advance_to_next_insn(a, pc);
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_float_cmp_op(STATE_ACCESS a, uint64_t &pc, uint32_t insn, const F &f) {
    const uint64_t fcsr = a.read_fcsr();
    // We must always check if input operands are properly NaN-boxed.
    T s1 = float_unbox<T>(a.read_f(insn_get_rs1(insn)));
    T s2 = float_unbox<T>(a.read_f(insn_get_rs2(insn)));
    const uint32_t rd = insn_get_rd(insn);
    auto fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
    // Comparisons with NaNs may set NV (invalid operation) exception flag in fflags
    const uint64_t val = f(s1, s2, &fflags);
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    if (unlikely(rd == 0)) {
        return advance_to_next_insn(a, pc);
    }
    a.write_x(rd, val);
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGNJ_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsgnj.s");
    return execute_float_binary_op<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, const uint32_t * /*fflags*/) -> uint32_t {
            return (s1 & ~i_sfloat32::SIGN_MASK) | (s2 & i_sfloat32::SIGN_MASK);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGNJN_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsgnjn.s");
    return execute_float_binary_op<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, const uint32_t * /*fflags*/) -> uint32_t {
            return (s1 & ~i_sfloat32::SIGN_MASK) | ((s2 & i_sfloat32::SIGN_MASK) ^ i_sfloat32::SIGN_MASK);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGNJX_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsgnjx.s");
    return execute_float_binary_op<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, const uint32_t * /*fflags*/) -> uint32_t {
            return s1 ^ (s2 & i_sfloat32::SIGN_MASK);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGN_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_FSGN_funct3_000000000000>(insn_get_funct3_000000000000(insn))) {
        case insn_FSGN_funct3_000000000000::J:
            return execute_FSGNJ_S(a, pc, insn);
        case insn_FSGN_funct3_000000000000::JN:
            return execute_FSGNJN_S(a, pc, insn);
        case insn_FSGN_funct3_000000000000::JX:
            return execute_FSGNJX_S(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGNJ_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsgnj.d");
    return execute_float_binary_op<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, const uint32_t * /*fflags*/) -> uint64_t {
            return (s1 & ~i_sfloat64::SIGN_MASK) | (s2 & i_sfloat64::SIGN_MASK);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGNJN_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsgnjn.d");
    return execute_float_binary_op<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, const uint32_t * /*fflags*/) -> uint64_t {
            return (s1 & ~i_sfloat64::SIGN_MASK) | ((s2 & i_sfloat64::SIGN_MASK) ^ i_sfloat64::SIGN_MASK);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGNJX_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsgnjx.d");
    return execute_float_binary_op<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, const uint32_t * /*fflags*/) -> uint64_t {
            return s1 ^ (s2 & i_sfloat64::SIGN_MASK);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGN_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_FSGN_funct3_000000000000>(insn_get_funct3_000000000000(insn))) {
        case insn_FSGN_funct3_000000000000::J:
            return execute_FSGNJ_D(a, pc, insn);
        case insn_FSGN_funct3_000000000000::JN:
            return execute_FSGNJN_D(a, pc, insn);
        case insn_FSGN_funct3_000000000000::JX:
            return execute_FSGNJX_D(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMIN_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmin.s");
    return execute_float_binary_op<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t *fflags) -> uint32_t { return i_sfloat32::min(s1, s2, fflags); });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMAX_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmax.s");
    return execute_float_binary_op<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t *fflags) -> uint32_t { return i_sfloat32::max(s1, s2, fflags); });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMINMAX_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_FMIN_FMAX_funct3_000000000000>(insn_get_funct3_000000000000(insn))) {
        case insn_FMIN_FMAX_funct3_000000000000::MIN:
            return execute_FMIN_S(a, pc, insn);
        case insn_FMIN_FMAX_funct3_000000000000::MAX:
            return execute_FMAX_S(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMIN_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmin.d");
    return execute_float_binary_op<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint32_t *fflags) -> uint64_t { return i_sfloat64::min(s1, s2, fflags); });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMAX_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmax.d");
    return execute_float_binary_op<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint32_t *fflags) -> uint64_t { return i_sfloat64::max(s1, s2, fflags); });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMINMAX_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_FMIN_FMAX_funct3_000000000000>(insn_get_funct3_000000000000(insn))) {
        case insn_FMIN_FMAX_funct3_000000000000::MIN:
            return execute_FMIN_D(a, pc, insn);
        case insn_FMIN_FMAX_funct3_000000000000::MAX:
            return execute_FMAX_D(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename ST, typename DT, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_FCVT_F_F(STATE_ACCESS a, uint64_t &pc, uint32_t insn, const F &f) {
    const uint64_t fcsr = a.read_fcsr();
    // The rounding mode comes from the insn
    const uint32_t rm = insn_get_rm(insn, fcsr);
    // If the rounding mode is invalid, the instruction is considered illegal
    if (unlikely(rm > FRM_RMM)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    const uint32_t rd = insn_get_rd(insn);
    auto fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
    // We must always check if input operands are properly NaN-boxed.
    ST s1 = float_unbox<ST>(a.read_f(insn_get_rs1(insn)));
    DT val = f(s1, rm, &fflags);
    // Must store a valid NaN-boxed value.
    a.write_f(rd, float_box(val));
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    return advance_to_next_insn(a, pc);
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_FCVT_X_F(STATE_ACCESS a, uint64_t &pc, uint32_t insn, const F &f) {
    const uint64_t fcsr = a.read_fcsr();
    // The rounding mode comes from the insn
    const uint32_t rm = insn_get_rm(insn, fcsr);
    // If the rounding mode is invalid, the instruction is considered illegal
    if (unlikely(rm > FRM_RMM)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    const uint32_t rd = insn_get_rd(insn);
    auto fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
    // We must always check if input operands are properly NaN-boxed.
    T s1 = float_unbox<T>(a.read_f(insn_get_rs1(insn)));
    const uint64_t val = f(s1, rm, &fflags);
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    if (unlikely(rd == 0)) {
        return advance_to_next_insn(a, pc);
    }
    a.write_x(rd, val);
    return advance_to_next_insn(a, pc);
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_FCVT_F_X(STATE_ACCESS a, uint64_t &pc, uint32_t insn, const F &f) {
    const uint64_t fcsr = a.read_fcsr();
    // The rounding mode comes from the insn
    const uint32_t rm = insn_get_rm(insn, fcsr);
    // If the rounding mode is invalid, the instruction is considered illegal
    if (unlikely(rm > FRM_RMM)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    const uint32_t rd = insn_get_rd(insn);
    auto fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
    const uint64_t s1 = a.read_x(insn_get_rs1(insn));
    T val = f(s1, rm, &fflags);
    // Must store a valid NaN-boxed value.
    a.write_f(rd, float_box(val));
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_S_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.s.d");
    return execute_FCVT_F_F<uint64_t, uint32_t>(a, pc, insn,
        [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return sfloat_cvt_f64_f32(s1, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_D_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.d.s");
    return execute_FCVT_F_F<uint32_t, uint64_t>(a, pc, insn,
        [](uint32_t s1, uint32_t /*rm*/, uint32_t *fflags) -> uint64_t {
            // FCVT.D.S will never round, since it's a widen operation.
            return sfloat_cvt_f32_f64(s1, fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSQRT_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsqrt.s");
    return execute_float_unary_op_rm<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t rm, uint32_t *fflags) -> uint32_t {
        return i_sfloat32::sqrt(s1, static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSQRT_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsqrt.d");
    return execute_float_unary_op_rm<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        return i_sfloat64::sqrt(s1, static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FLE_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fle.s");
    return execute_float_cmp_op<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t s2, uint32_t *fflags) -> uint64_t {
        return static_cast<uint64_t>(i_sfloat32::le(s1, s2, fflags));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FLT_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "flt.s");
    return execute_float_cmp_op<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t s2, uint32_t *fflags) -> uint64_t {
        return static_cast<uint64_t>(i_sfloat32::lt(s1, s2, fflags));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FEQ_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "feq.s");
    return execute_float_cmp_op<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t s2, uint32_t *fflags) -> uint64_t {
        return static_cast<uint64_t>(i_sfloat32::eq(s1, s2, fflags));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCMP_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_FCMP_funct3_000000000000>(insn_get_funct3_000000000000(insn))) {
        case insn_FCMP_funct3_000000000000::LT:
            return execute_FLT_S(a, pc, insn);
        case insn_FCMP_funct3_000000000000::LE:
            return execute_FLE_S(a, pc, insn);
        case insn_FCMP_funct3_000000000000::EQ:
            return execute_FEQ_S(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FLE_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fle.d");
    return execute_float_cmp_op<uint64_t>(a, pc, insn, [](uint64_t s1, uint64_t s2, uint32_t *fflags) -> uint64_t {
        return static_cast<uint64_t>(i_sfloat64::le(s1, s2, fflags));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FLT_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "flt.d");
    return execute_float_cmp_op<uint64_t>(a, pc, insn, [](uint64_t s1, uint64_t s2, uint32_t *fflags) -> uint64_t {
        return static_cast<uint64_t>(i_sfloat64::lt(s1, s2, fflags));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FEQ_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "feq.d");
    return execute_float_cmp_op<uint64_t>(a, pc, insn, [](uint64_t s1, uint64_t s2, uint32_t *fflags) -> uint64_t {
        return static_cast<uint64_t>(i_sfloat64::eq(s1, s2, fflags));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCMP_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_FCMP_funct3_000000000000>(insn_get_funct3_000000000000(insn))) {
        case insn_FCMP_funct3_000000000000::LT:
            return execute_FLT_D(a, pc, insn);
        case insn_FCMP_funct3_000000000000::LE:
            return execute_FLE_D(a, pc, insn);
        case insn_FCMP_funct3_000000000000::EQ:
            return execute_FEQ_D(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_W_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.w.s");
    return execute_FCVT_X_F<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        const auto val = i_sfloat32::cvt_f_i<int32_t>(s1, static_cast<FRM_modes>(rm), fflags);
        // For XLEN > 32, FCVT.W.S sign-extends the 32-bit result.
        return static_cast<uint64_t>(static_cast<int64_t>(val));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_WU_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.wu.s");
    return execute_FCVT_X_F<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        const auto val = i_sfloat32::cvt_f_i<uint32_t>(s1, static_cast<FRM_modes>(rm), fflags);
        // For XLEN > 32, FCVT.WU.S sign-extends the 32-bit result.
        return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(val)));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_L_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.l.s");
    return execute_FCVT_X_F<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        const auto val = i_sfloat32::cvt_f_i<int64_t>(s1, static_cast<FRM_modes>(rm), fflags);
        return static_cast<uint64_t>(val);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_LU_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.lu.s");
    return execute_FCVT_X_F<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        return i_sfloat32::cvt_f_i<uint64_t>(s1, static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_W_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.w.d");
    return execute_FCVT_X_F<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        const auto val = i_sfloat64::cvt_f_i<int32_t>(s1, static_cast<FRM_modes>(rm), fflags);
        // For RV64, FCVT.W.D sign-extends the 32-bit result.
        return static_cast<uint64_t>(static_cast<int64_t>(val));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_WU_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.wu.d");
    return execute_FCVT_X_F<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        const auto val = i_sfloat64::cvt_f_i<uint32_t>(s1, static_cast<FRM_modes>(rm), fflags);
        // For RV64, FCVT.WU.D sign-extends the 32-bit result.
        return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(val)));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_L_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.l.d");
    return execute_FCVT_X_F<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        const auto val = i_sfloat64::cvt_f_i<int64_t>(s1, static_cast<FRM_modes>(rm), fflags);
        return static_cast<uint64_t>(val);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_LU_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.lu.d");
    return execute_FCVT_X_F<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        return i_sfloat64::cvt_f_i<uint64_t>(s1, static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_S_W(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.s.w");
    return execute_FCVT_F_X<uint32_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint32_t {
        return i_sfloat32::cvt_i_f(static_cast<int32_t>(s1), static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_S_WU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.s.wu");
    return execute_FCVT_F_X<uint32_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint32_t {
        return i_sfloat32::cvt_i_f(static_cast<uint32_t>(s1), static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_S_L(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.s.l");
    return execute_FCVT_F_X<uint32_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint32_t {
        return i_sfloat32::cvt_i_f(static_cast<int64_t>(s1), static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_S_LU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.s.lu");
    return execute_FCVT_F_X<uint32_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint32_t {
        return i_sfloat32::cvt_i_f(s1, static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_D_W(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.d.w");
    return execute_FCVT_F_X<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        return i_sfloat64::cvt_i_f(static_cast<int32_t>(s1), static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_D_WU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.d.wu");
    return execute_FCVT_F_X<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        return i_sfloat64::cvt_i_f(static_cast<uint32_t>(s1), static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_D_L(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.d.l");
    return execute_FCVT_F_X<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        return i_sfloat64::cvt_i_f(static_cast<int64_t>(s1), static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_D_LU(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.d.lu");
    return execute_FCVT_F_X<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        return i_sfloat64::cvt_i_f(s1, static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMV_F_X(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // Should have funct3 set to 0
    if (unlikely(insn_get_funct3(insn) != 0)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    const uint32_t rd = insn_get_rd(insn);
    // A narrower n-bit transfer, n < FLEN,
    // into the f registers will create a valid NaN-boxed value.
    a.write_f(rd, float_box(static_cast<T>(a.read_x(insn_get_rs1(insn)))));
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMV_W_X(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmv.w.x");
    return execute_FMV_F_X<uint32_t>(a, pc, insn);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMV_D_X(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmv.d.x");
    return execute_FMV_F_X<uint64_t>(a, pc, insn);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCLASS_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fclass.s");
    return execute_FCLASS<uint32_t>(a, pc, insn, [](uint32_t s1) -> uint64_t { return i_sfloat32::fclass(s1); });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMV_X_W(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmv.x.w");
    const uint32_t rd = insn_get_rd(insn);
    if (unlikely(rd == 0)) {
        return advance_to_next_insn(a, pc);
    }
    const auto val = static_cast<uint32_t>(a.read_f(insn_get_rs1(insn)));
    // For RV64, the higher 32 bits of the destination register are
    // filled with copies of the floating-point number’s sign bit.
    // We can perform this with a sign extension.
    a.write_x(rd, static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(val))));
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMV_FCLASS_S(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_FMV_FCLASS_funct3_000000000000>(insn_get_funct3_000000000000(insn))) {
        case insn_FMV_FCLASS_funct3_000000000000::FMV:
            return execute_FMV_X_W(a, pc, insn);
        case insn_FMV_FCLASS_funct3_000000000000::FCLASS:
            return execute_FCLASS_S(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCLASS_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fclass.d");
    return execute_FCLASS<uint64_t>(a, pc, insn, [](uint64_t s1) -> uint64_t { return i_sfloat64::fclass(s1); });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMV_X_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmv.x.d");
    const uint32_t rd = insn_get_rd(insn);
    if (unlikely(rd == 0)) {
        return advance_to_next_insn(a, pc);
    }
    const uint64_t val = a.read_f(insn_get_rs1(insn));
    a.write_x(rd, val);
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMV_FCLASS_D(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_FMV_FCLASS_funct3_000000000000>(insn_get_funct3_000000000000(insn))) {
        case insn_FMV_FCLASS_funct3_000000000000::FMV:
            return execute_FMV_X_D(a, pc, insn);
        case insn_FMV_FCLASS_funct3_000000000000::FCLASS:
            return execute_FCLASS_D(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_FMV_FCLASS(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_FD_funct7_rs2>(insn_get_funct7_rs2(insn))) {
        case insn_FD_funct7_rs2::FCVT_W_S:
            return execute_FCVT_W_S(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_WU_S:
            return execute_FCVT_WU_S(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_L_S:
            return execute_FCVT_L_S(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_LU_S:
            return execute_FCVT_LU_S(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_W_D:
            return execute_FCVT_W_D(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_WU_D:
            return execute_FCVT_WU_D(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_L_D:
            return execute_FCVT_L_D(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_LU_D:
            return execute_FCVT_LU_D(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_S_D:
            return execute_FCVT_S_D(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_S_W:
            return execute_FCVT_S_W(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_S_WU:
            return execute_FCVT_S_WU(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_S_L:
            return execute_FCVT_S_L(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_S_LU:
            return execute_FCVT_S_LU(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_D_S:
            return execute_FCVT_D_S(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_D_W:
            return execute_FCVT_D_W(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_D_WU:
            return execute_FCVT_D_WU(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_D_L:
            return execute_FCVT_D_L(a, pc, insn);
        case insn_FD_funct7_rs2::FCVT_D_LU:
            return execute_FCVT_D_LU(a, pc, insn);
        case insn_FD_funct7_rs2::FMV_W_X:
            return execute_FMV_W_X(a, pc, insn);
        case insn_FD_funct7_rs2::FMV_D_X:
            return execute_FMV_D_X(a, pc, insn);
        case insn_FD_funct7_rs2::FMV_FCLASS_S:
            return execute_FMV_FCLASS_S(a, pc, insn);
        case insn_FD_funct7_rs2::FMV_FCLASS_D:
            return execute_FMV_FCLASS_D(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FD(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    switch (static_cast<insn_FD_funct7>(insn_get_funct7(insn))) {
        case insn_FD_funct7::FADD_S:
            return execute_FADD_S(a, pc, insn);
        case insn_FD_funct7::FADD_D:
            return execute_FADD_D(a, pc, insn);
        case insn_FD_funct7::FSUB_S:
            return execute_FSUB_S(a, pc, insn);
        case insn_FD_funct7::FSUB_D:
            return execute_FSUB_D(a, pc, insn);
        case insn_FD_funct7::FMUL_S:
            return execute_FMUL_S(a, pc, insn);
        case insn_FD_funct7::FMUL_D:
            return execute_FMUL_D(a, pc, insn);
        case insn_FD_funct7::FDIV_S:
            return execute_FDIV_S(a, pc, insn);
        case insn_FD_funct7::FDIV_D:
            return execute_FDIV_D(a, pc, insn);
        case insn_FD_funct7::FSGN_S:
            return execute_FSGN_S(a, pc, insn);
        case insn_FD_funct7::FSGN_D:
            return execute_FSGN_D(a, pc, insn);
        case insn_FD_funct7::FMINMAX_S:
            return execute_FMINMAX_S(a, pc, insn);
        case insn_FD_funct7::FMINMAX_D:
            return execute_FMINMAX_D(a, pc, insn);
        case insn_FD_funct7::FSQRT_S:
            return execute_FSQRT_S(a, pc, insn);
        case insn_FD_funct7::FSQRT_D:
            return execute_FSQRT_D(a, pc, insn);
        case insn_FD_funct7::FCMP_S:
            return execute_FCMP_S(a, pc, insn);
        case insn_FD_funct7::FCMP_D:
            return execute_FCMP_D(a, pc, insn);
        default:
            return execute_FCVT_FMV_FCLASS(a, pc, insn);
    }
}

template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_L(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t rd, uint32_t rs1,
    int32_t imm) {
    const uint64_t vaddr = a.read_x(rs1);
    T val = 0;
    if (unlikely(!read_virtual_memory<T>(a, pc, mcycle, vaddr + imm, &val))) {
        return advance_to_raised_exception(a, pc);
    }
    // This static branch is eliminated by the compiler
    if constexpr (std::is_signed_v<T>) {
        a.write_x(rd, static_cast<uint64_t>(static_cast<int64_t>(val)));
    } else {
        a.write_x(rd, static_cast<uint64_t>(val));
    }
    return advance_to_next_insn<2>(a, pc);
}

template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_S(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t rs2,
    uint32_t rs1, int32_t imm) {
    const uint64_t vaddr = a.read_x(rs1);
    const uint64_t val = a.read_x(rs2);
    const execute_status status = write_virtual_memory<T>(a, pc, mcycle, vaddr + imm, val);
    if (unlikely(status != execute_status::success)) {
        if (status == execute_status::failure) {
            return advance_to_raised_exception(a, pc);
        }
        return advance_to_next_insn<2>(a, pc, status);
    }
    return advance_to_next_insn<2>(a, pc);
}

template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_FL(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t rd,
    uint32_t rs1, int32_t imm) {
    // Loads the float value from virtual memory
    const uint64_t vaddr = a.read_x(rs1);
    T val = 0;
    if (unlikely(!read_virtual_memory(a, pc, mcycle, vaddr + imm, &val))) {
        return advance_to_raised_exception(a, pc);
    }
    // A narrower n-bit transfer, n < FLEN,
    // into the f registers will create a valid NaN-boxed value.
    a.write_f(rd, float_box(val));
    return advance_to_next_insn<2>(a, pc);
}

template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_FS(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t rs2,
    uint32_t rs1, int32_t imm) {
    const uint64_t vaddr = a.read_x(rs1);
    // A narrower n-bit transfer out of the floating-point
    // registers will transfer the lower n bits of the register ignoring the upper FLEN−n bits.
    T val = static_cast<T>(a.read_f(rs2));
    const execute_status status = write_virtual_memory<T>(a, pc, mcycle, vaddr + imm, val);
    if (unlikely(status != execute_status::success)) {
        if (status == execute_status::failure) {
            return advance_to_raised_exception(a, pc);
        }
        return advance_to_next_insn<2>(a, pc, status);
    }
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.ADDI4SPN instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_ADDI4SPN(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.addi4spn");
    // rd cannot be zero (guaranteed by RISC-V spec design)
    const uint32_t rd = insn_get_CIW_CL_rd_CS_CA_rs2(insn);
    // imm cannot be zero (guaranteed by the jump table)
    const uint32_t imm = insn_get_CIW_imm(insn);
    const uint64_t rs1 = a.read_x(2);
    int64_t val = 0;
    __builtin_add_overflow(static_cast<int64_t>(rs1), static_cast<int64_t>(imm), &val);
    a.write_x(rd, static_cast<uint64_t>(val));
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.FLD instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_FLD(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.fld");
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction
    // exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    const uint32_t rd = insn_get_CIW_CL_rd_CS_CA_rs2(insn);
    const uint32_t rs1 = insn_get_CL_CS_CA_CB_rs1(insn);
    const int32_t imm = insn_get_CL_CS_imm(insn);
    return execute_C_FL<uint64_t>(a, pc, mcycle, rd, rs1, imm);
}

/// \brief Implementation of the C.LW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_LW(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.lw");
    const uint32_t rd = insn_get_CIW_CL_rd_CS_CA_rs2(insn);
    const uint32_t rs1 = insn_get_CL_CS_CA_CB_rs1(insn);
    const int32_t imm = insn_get_C_LW_C_SW_imm(insn);
    return execute_C_L<int32_t>(a, pc, mcycle, rd, rs1, imm);
}

/// \brief Implementation of the C.LD instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_LD(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.ld");
    const uint32_t rd = insn_get_CIW_CL_rd_CS_CA_rs2(insn);
    const uint32_t rs1 = insn_get_CL_CS_CA_CB_rs1(insn);
    const int32_t imm = insn_get_CL_CS_imm(insn);
    return execute_C_L<int64_t>(a, pc, mcycle, rd, rs1, imm);
}

/// \brief Implementation of the C.FSD instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_FSD(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.fsd");
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction
    // exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    const uint32_t rs1 = insn_get_CL_CS_CA_CB_rs1(insn);
    const uint32_t rs2 = insn_get_CIW_CL_rd_CS_CA_rs2(insn);
    const int32_t imm = insn_get_CL_CS_imm(insn);
    return execute_C_FS<uint64_t>(a, pc, mcycle, rs2, rs1, imm);
}

/// \brief Implementation of the C.SW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_SW(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.sw");
    const uint32_t rs1 = insn_get_CL_CS_CA_CB_rs1(insn);
    const uint32_t rs2 = insn_get_CIW_CL_rd_CS_CA_rs2(insn);
    const int32_t imm = insn_get_C_LW_C_SW_imm(insn);
    return execute_C_S<uint32_t>(a, pc, mcycle, rs2, rs1, imm);
}

/// \brief Implementation of the C.SD instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_SD(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.sd");
    const uint32_t rs1 = insn_get_CL_CS_CA_CB_rs1(insn);
    const uint32_t rs2 = insn_get_CIW_CL_rd_CS_CA_rs2(insn);
    const int32_t imm = insn_get_CL_CS_imm(insn);
    return execute_C_S<uint64_t>(a, pc, mcycle, rs2, rs1, imm);
}

/// \brief Implementation of the C.NOP instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_NOP(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.nop");
    // Really do nothing
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.ADDI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_ADDI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.addi");
    // rd cannot be zero (guaranteed by jump table)
    const uint32_t rd = insn_get_rd(insn);
    const int32_t imm = insn_get_CI_CB_imm_se(insn);
    // imm cannot be zero (guaranteed by jump table)
    const uint64_t rd_value = a.read_x(rd);
    int64_t val = 0;
    __builtin_add_overflow(static_cast<int64_t>(rd_value), static_cast<int64_t>(imm), &val);
    a.write_x(rd, static_cast<uint64_t>(val));
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.addiw instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_ADDIW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.addiw");
    // rd cannot be zero (guaranteed by jump table)
    const uint32_t rd = insn_get_rd(insn);
    const uint64_t rd_value = a.read_x(rd);
    const int32_t imm = insn_get_CI_CB_imm_se(insn);
    int32_t val = 0;
    __builtin_add_overflow(static_cast<int32_t>(rd_value), imm, &val);
    a.write_x(rd, static_cast<uint64_t>(val));
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.LI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_LI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.li");
    // rd cannot be zero (guaranteed by jump table)
    const uint32_t rd = insn_get_rd(insn);
    const int32_t imm = insn_get_CI_CB_imm_se(insn);
    a.write_x(rd, static_cast<uint64_t>(imm));
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.ADDI16SP instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_ADDI16SP(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.addi16sp");
    // imm cannot be zero (guaranteed by the jump table)
    const int32_t imm = insn_get_C_ADDI16SP_imm(insn);
    const uint64_t rs1_value = a.read_x(2);
    int64_t val = 0;
    __builtin_add_overflow(static_cast<int64_t>(rs1_value), static_cast<int64_t>(imm), &val);
    a.write_x(2, static_cast<uint64_t>(val));
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.LUI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_LUI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.lui");
    // imm cannot be zero (guaranteed by the jump table)
    const int32_t imm = insn_get_C_LUI_imm(insn);
    // rd cannot be zero (guaranteed by the jump table)
    const uint32_t rd = insn_get_rd(insn);
    a.write_x(rd, static_cast<uint64_t>(imm));
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.SRLI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_SRLI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.srli");
    const uint32_t rs1 = insn_get_CL_CS_CA_CB_rs1(insn);
    // imm cannot be zero (guaranteed by the jump table)
    const uint32_t imm = insn_get_CI_CB_imm(insn);
    const uint64_t rs1_value = a.read_x(rs1);
    a.write_x(rs1, rs1_value >> imm);
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.SRAI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_SRAI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.srai");
    const uint32_t rs1 = insn_get_CL_CS_CA_CB_rs1(insn);
    // imm cannot be zero (guaranteed by the jump table)
    const uint32_t imm = insn_get_CI_CB_imm(insn);
    const auto rs1_value = static_cast<int64_t>(a.read_x(rs1));
    a.write_x(rs1, static_cast<uint64_t>(rs1_value >> imm));
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.ANDI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_ANDI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.andi");
    const uint32_t rs1 = insn_get_CL_CS_CA_CB_rs1(insn);
    const int32_t imm = insn_get_CI_CB_imm_se(insn);
    const uint64_t rs1_value = a.read_x(rs1);
    a.write_x(rs1, rs1_value & static_cast<uint64_t>(imm));
    return advance_to_next_insn<2>(a, pc);
}

template <typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_C_arithmetic(STATE_ACCESS a, uint64_t &pc, uint32_t insn, const F &f) {
    // Ensure rs1 and rs2 are loaded in order: do not nest with call to f() as
    // the order of evaluation of arguments in a function call is undefined.
    const uint32_t rs1 = insn_get_CL_CS_CA_CB_rs1(insn);
    const uint64_t rs1_value = a.read_x(rs1);
    const uint64_t rs2_value = a.read_x(insn_get_CIW_CL_rd_CS_CA_rs2(insn));
    // Now we can safely invoke f()
    a.write_x(rs1, f(rs1_value, rs2_value));
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.SUB instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_SUB(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.sub");
    return execute_C_arithmetic(a, pc, insn, [](uint64_t rs1_value, uint64_t rs2_value) -> uint64_t {
        uint64_t val = 0;
        __builtin_sub_overflow(rs1_value, rs2_value, &val);
        return val;
    });
}

/// \brief Implementation of the C.XOR instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_XOR(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.xor");
    return execute_C_arithmetic(a, pc, insn,
        [](uint64_t rs1_value, uint64_t rs2_value) -> uint64_t { return rs1_value ^ rs2_value; });
}

/// \brief Implementation of the C.OR instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_OR(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.or");
    return execute_C_arithmetic(a, pc, insn,
        [](uint64_t rs1_value, uint64_t rs2_value) -> uint64_t { return rs1_value | rs2_value; });
}

/// \brief Implementation of the C.AND instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_AND(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.and");
    return execute_C_arithmetic(a, pc, insn,
        [](uint64_t rs1_value, uint64_t rs2_value) -> uint64_t { return rs1_value & rs2_value; });
}

/// \brief Implementation of the C.SUBW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_SUBW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.subw");
    return execute_C_arithmetic(a, pc, insn, [](uint64_t rs1_value, uint64_t rs2_value) -> uint64_t {
        // Convert 64-bit to 32-bit
        auto rs1w = static_cast<int32_t>(rs1_value);
        auto rs2w = static_cast<int32_t>(rs2_value);
        int32_t val = 0;
        __builtin_sub_overflow(rs1w, rs2w, &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the C.ADDW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_ADDW(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.addw");
    return execute_C_arithmetic(a, pc, insn, [](uint64_t rs1_value, uint64_t rs2_value) -> uint64_t {
        // Discard upper 32 bits
        auto rs1w = static_cast<int32_t>(rs1_value);
        auto rs2w = static_cast<int32_t>(rs2_value);
        int32_t val = 0;
        __builtin_add_overflow(rs1w, rs2w, &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the C_J instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_J(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.j");
    const uint64_t new_pc = pc + static_cast<uint64_t>(insn_get_C_J_imm(insn));
    return execute_jump(a, pc, new_pc);
}

/// \brief Implementation of the C.BEQZ instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_BEQZ(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.beqz");
    const uint32_t rs1 = insn_get_CL_CS_CA_CB_rs1(insn);
    if (a.read_x(rs1) == 0) {
        const int32_t imm = insn_get_C_BEQZ_BNEZ_imm(insn);
        const uint64_t new_pc = pc + static_cast<uint64_t>(imm);
        return execute_jump(a, pc, new_pc);
    }
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.BNEZ instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_BNEZ(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.bnez");
    const uint32_t rs1 = insn_get_CL_CS_CA_CB_rs1(insn);
    if (a.read_x(rs1) != 0) {
        const int32_t imm = insn_get_C_BEQZ_BNEZ_imm(insn);
        const uint64_t new_pc = pc + static_cast<uint64_t>(imm);
        return execute_jump(a, pc, new_pc);
    }
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.SLLI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_SLLI(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.slli");
    // rd cannot be zero (guaranteed by jump table)
    const uint32_t rd = insn_get_rd(insn);
    // imm cannot be zero (guaranteed by jump table)
    const uint32_t imm = insn_get_CI_CB_imm(insn);
    const uint64_t rs1_value = a.read_x(rd);
    a.write_x(rd, rs1_value << imm);
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.FLDSP instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_FLDSP(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.fldsp");
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction
    // exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    const uint32_t rd = insn_get_rd(insn);
    const int32_t imm = insn_get_C_FLDSP_LDSP_imm(insn);
    return execute_C_FL<uint64_t>(a, pc, mcycle, rd, 0x2, imm);
}

/// \brief Implementation of the C.LWSP instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_LWSP(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.lwsp");
    // rd cannot be zero (guaranteed by jump table)
    const uint32_t rd = insn_get_rd(insn);
    const int32_t imm = insn_get_C_LWSP_imm(insn);
    return execute_C_L<int32_t>(a, pc, mcycle, rd, 0x2, imm);
}

/// \brief Implementation of the C.LDSP instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_LDSP(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.ldsp");
    // rd cannot be zero (guaranteed by jump table)
    const uint32_t rd = insn_get_rd(insn);
    const int32_t imm = insn_get_C_FLDSP_LDSP_imm(insn);
    return execute_C_L<int64_t>(a, pc, mcycle, rd, 0x2, imm);
}

/// \brief Implementation of the C.JR instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_JR(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.jr");
    // rs1 cannot be zero (guaranteed by the jump table)
    const uint32_t rs1 = insn_get_rd(insn);
    const uint64_t new_pc = a.read_x(rs1) & ~static_cast<uint64_t>(1);
    return execute_jump(a, pc, new_pc);
}

/// \brief Implementation of the C.MV instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_MV(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.mv");
    // rd cannot be zero (guaranteed by the jump table)
    const uint32_t rd = insn_get_rd(insn);
    const uint32_t rs2 = insn_get_CR_CSS_rs2(insn);
    const uint64_t val = a.read_x(rs2);
    a.write_x(rd, val);
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.EBREAK instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_EBREAK(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.ebreak");
    pc = raise_exception(a, pc, MCAUSE_BREAKPOINT, pc);
    return advance_to_raised_exception(a, pc);
}

/// \brief Implementation of the C.JALR instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_JALR(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.jalr");
    const uint32_t rs1 = insn_get_rd(insn);
    const uint64_t new_pc = a.read_x(rs1) & ~static_cast<uint64_t>(1);
    const uint64_t val = pc + 2;
    a.write_x(0x1, val);
    return execute_jump(a, pc, new_pc);
}

/// \brief Implementation of the C.ADD instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_ADD(STATE_ACCESS a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.add");
    // rd cannot be zero (guaranteed by the jump table)
    const uint32_t rd = insn_get_rd(insn);
    const uint32_t rs2 = insn_get_CR_CSS_rs2(insn);
    const uint64_t rd_value = a.read_x(rd);
    const uint64_t rs2_value = a.read_x(rs2);
    uint64_t val = 0;
    __builtin_add_overflow(rd_value, rs2_value, &val);
    a.write_x(rd, val);
    return advance_to_next_insn<2>(a, pc);
}

/// \brief Implementation of the C.FSDSP instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_FSDSP(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.fsdsp");
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction
    // exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    const uint32_t rs2 = insn_get_CR_CSS_rs2(insn);
    const int32_t imm = insn_get_C_FSDSP_SDSP_imm(insn);
    return execute_C_FS<uint64_t>(a, pc, mcycle, rs2, 0x2, imm);
}

/// \brief Implementation of the C.SWSP instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_SWSP(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.swsp");
    const uint32_t rs2 = insn_get_CR_CSS_rs2(insn);
    const int32_t imm = insn_get_C_SWSP_imm(insn);
    return execute_C_S<uint32_t>(a, pc, mcycle, rs2, 0x2, imm);
}

/// \brief Implementation of the C.SDSP instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_C_SDSP(STATE_ACCESS a, uint64_t &pc, uint64_t mcycle, uint32_t insn) {
    dump_insn(a, pc, static_cast<uint16_t>(insn), "c.sdsp");
    const uint32_t rs2 = insn_get_CR_CSS_rs2(insn);
    const int32_t imm = insn_get_C_FSDSP_SDSP_imm(insn);
    return execute_C_S<uint64_t>(a, pc, mcycle, rs2, 0x2, imm);
}

/// \brief Instruction fetch status code
enum class fetch_status : int {
    exception, ///< Instruction fetch failed: exception raised
    success    ///< Instruction fetch succeeded: proceed to execute
};

/// \brief Translate fetch pc to a host pointer (slow path that goes through virtual address translation).
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Virtual address for the current instruction being executed.
/// \param vaddr Virtual address to be fetched.
/// \param phptr Receives host pointer.
/// \return Returns fetch_status::success if load succeeded, fetch_status::exception if it caused an exception.
//          In that case, raise the exception.
template <typename STATE_ACCESS>
static FORCE_INLINE fetch_status fetch_translate_pc_slow(STATE_ACCESS a, uint64_t &pc, uint64_t vaddr,
    unsigned char **phptr) {
    uint64_t paddr{};
    // Walk page table and obtain the physical address
    if (unlikely(!translate_virtual_address(a, &paddr, vaddr, PTE_XWR_X_SHIFT))) {
        pc = raise_exception(a, pc, MCAUSE_FETCH_PAGE_FAULT, vaddr);
        return fetch_status::exception;
    }
    // Walk memory map to find the range that contains the physical address
    auto &pma = find_pma_entry<uint16_t>(a, paddr);
    // We only execute directly from RAM (as in "random access memory")
    // If the range is not memory or not executable, this as a PMA violation
    if (unlikely(!pma.get_istart_M() || !pma.get_istart_X())) {
        pc = raise_exception(a, pc, MCAUSE_INSN_ACCESS_FAULT, vaddr);
        return fetch_status::exception;
    }
    unsigned char *hpage = a.template replace_tlb_entry<TLB_CODE>(vaddr, paddr, pma);
    const uint64_t hoffset = vaddr & PAGE_OFFSET_MASK;
    *phptr = hpage + hoffset;
    return fetch_status::success;
}

/// \brief Translate fetch pc to a host pointer.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Virtual address for the current instruction being executed.
/// \param vaddr Virtual address to be fetched.
/// \param phptr Receives the host pointer.
/// \return Returns fetch_status::success if load succeeded, fetch_status::exception if it caused an exception.
//          In that case, raise the exception.
template <typename STATE_ACCESS>
static FORCE_INLINE fetch_status fetch_translate_pc(STATE_ACCESS a, uint64_t &pc, uint64_t vaddr,
    unsigned char **phptr) {
    // Try to perform the address translation via TLB first
    if (unlikely(!(a.template translate_vaddr_via_tlb<TLB_CODE, uint16_t>(vaddr, phptr)))) {
        INC_COUNTER(a.get_statistics(), tlb_cmiss);
        // Outline the slow path into a function call to minimize host CPU code cache pressure
        return fetch_translate_pc_slow(a, pc, vaddr, phptr);
    }
    INC_COUNTER(a.get_statistics(), tlb_chit);
    return fetch_status::success;
}

/// \brief Loads the next instruction.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Virtual address for the current instruction being executed.
/// \param insn Receives the instruction.
/// \param fetch_vaddr_page Fetch virtual address translation page cache.
/// \param fetch_vh_offset Fetch virtual address host pointer offset cache.
/// \return Returns fetch_status::success if load succeeded, fetch_status::exception if it caused an exception.
//          In that case, raise the exception.
template <typename STATE_ACCESS>
static FORCE_INLINE fetch_status fetch_insn(STATE_ACCESS a, uint64_t &pc, uint32_t &insn, uint64_t &fetch_vaddr_page,
    uint64_t &fetch_vh_offset) {
    // Efficiently checks if current pc is in the same page as last pc fetch
    // and it's not crossing a page boundary.
    if (likely((pc ^ fetch_vaddr_page) < (PMA_PAGE_SIZE - 2))) {
        // Fetch pc is in the same page as the last pc fetch and it's not crossing a page boundary,
        // we can just reuse last fetch translation, skipping TLB or slow address translation altogether.
        const unsigned char *hptr = cast_addr_to_ptr<unsigned char *>(pc + fetch_vh_offset);

        // Here we are sure that reading 4 bytes won't cross a page boundary.
        // However pc may not be 4 byte aligned, at best it can only be 2-byte aligned,
        // therefore we must perform a misaligned 4 byte read on a 2 byte aligned pointer.
        // In case pc holds a compressed instruction, insn will store 2 additional bytes,
        // but this is fine because later the instruction decoder will discard them.
        insn = aliased_unaligned_read<uint32_t, uint16_t>(hptr);
        return fetch_status::success;
    }
    // Fetch pc is either not the same as last cache or crossing a page boundary.

    // Perform address translation
    unsigned char *hptr = nullptr;
    if (unlikely(fetch_translate_pc(a, pc, pc, &hptr) == fetch_status::exception)) {
        return fetch_status::exception;
    }
    // Update fetch address translation cache
    fetch_vaddr_page = pc & ~PAGE_OFFSET_MASK;
    fetch_vh_offset = cast_ptr_to_addr<uint64_t>(hptr) - pc;

    // The following code assumes pc is always 2-byte aligned, this is guaranteed by RISC-V spec.
    // If pc is pointing to the very last 2 bytes of a page, it's crossing a page boundary.
    if (unlikely(((~pc & PAGE_OFFSET_MASK) >> 1) == 0)) {
        // Here we are crossing page boundary, this is unlikely (1 in 2048 possible cases)
        insn = aliased_aligned_read<uint16_t>(hptr);
        // If not a compressed instruction, we must read 2 additional bytes from the next page.
        if (unlikely(insn_is_uncompressed(insn))) {
            // We have to perform a new address translation to read the next 2 bytes since we changed pages.
            const uint64_t vaddr = pc + 2;
            if (unlikely(fetch_translate_pc(a, pc, vaddr, &hptr) == fetch_status::exception)) {
                return fetch_status::exception;
            }
            // Update fetch translation cache
            fetch_vaddr_page = vaddr;
            fetch_vh_offset = cast_ptr_to_addr<uint64_t>(hptr) - vaddr;
            // Produce the final 4-byte instruction
            insn |= aliased_aligned_read<uint16_t>(hptr) << 16;
        }
        return fetch_status::success;
    }

    // Here we are sure that reading 4 bytes won't cross a page boundary.
    // However pc may not be 4 byte aligned, at best it can only be 2-byte aligned,
    // therefore we must perform a misaligned 4 byte read on a 2 byte aligned pointer.
    // In case pc holds a compressed instruction, insn will store 2 additional bytes,
    // but this is fine because later the instruction decoder will discard them.
    insn = aliased_unaligned_read<uint32_t, uint16_t>(hptr);
    return fetch_status::success;
}

/// \brief Checks that false brk is consistent with rest of state
template <typename STATE_ACCESS>
static void assert_no_brk([[maybe_unused]] STATE_ACCESS a) {
    assert(get_pending_irq_mask(a) == 0); // LCOV_EXCL_LINE
    assert(a.read_iflags_X() == 0);       // LCOV_EXCL_LINE
    assert(a.read_iflags_Y() == 0);       // LCOV_EXCL_LINE
    assert(a.read_iflags_H() == 0);       // LCOV_EXCL_LINE
}

/// \brief Interpreter hot loop
template <typename STATE_ACCESS>
static NO_INLINE execute_status interpret_loop(STATE_ACCESS a, uint64_t mcycle_end, uint64_t mcycle) {
    // The interpret loop is constantly reading and modifying the pc and mcycle variables,
    // because of this care is taken to make them stack variables that are propagated across inline functions,
    // helping the C++ compiler optimize them into registers instead of stack variables when compiling,
    // making the interpreter loop much faster.
    // Also as an optimization, their values are only committed to machine state when the interpreter loop breaks,
    // this means read_pc()/write_pc() and read_mcycle()/write_mcycle() functions may not access
    // the actual values during interpreter loop, so they should be used with extra care,
    // taking this into account in any instruction execution code.

    // Read machine program counter
    uint64_t pc = a.read_pc();

    // Initialize fetch address translation cache invalidated
    uint64_t fetch_vaddr_page = ~pc;
    uint64_t fetch_vh_offset = 0;

    // The outer loop continues until there is an interruption that should be handled
    // externally, or mcycle reaches mcycle_end
    while (mcycle < mcycle_end) {
        INC_COUNTER(a.get_statistics(), outer_loop);

        if (rtc_is_tick(mcycle)) {
            // Set interrupt flag for RTC
            set_rtc_interrupt(a, mcycle);

            // Polling external interrupts only in WFI instructions is not enough
            // because Linux won't execute WFI instructions while under heavy load,
            // yet external interrupts still need to be triggered.
            // Therefore we poll for external interrupt once a while in the interpreter loop.
            a.poll_external_interrupts(mcycle, mcycle);
        }

        // Raise the highest priority pending interrupt, if any
        pc = raise_interrupt_if_any(a, pc);

#ifndef NDEBUG
        // After raising any exception for a given interrupt, we expect no pending break
        assert_no_brk(a);
#endif

        // Limit mcycle_tick_end up to the next RTC tick, while avoiding unsigned overflows
        const uint64_t mcycle_tick_end = mcycle + std::min(mcycle_end - mcycle, RTC_FREQ_DIV - (mcycle % RTC_FREQ_DIV));

        // The inner loop continues until there is an interrupt condition
        // or mcycle reaches mcycle_tick_end
        while (mcycle < mcycle_tick_end) {
            INC_COUNTER(a.get_statistics(), inner_loop);

            uint32_t insn = 0;

            // Try to fetch the next instruction
            if (likely(fetch_insn(a, pc, insn, fetch_vaddr_page, fetch_vh_offset) == fetch_status::success)) {
                // clang-format off
                // NOLINTBEGIN
                execute_status status; // explicit uninitialized as an optimization

                // This header define the instruction jump table table, which is very large.
                // It also defines the jump table related macros used in the next big switch.
                #include "interpret-jump-table.h"

                // This will use computed goto on supported compilers,
                // otherwise normal switch in unsupported platforms.
                INSN_SWITCH(insn_get_id(insn)) {
                    // The instructions is this switch are ordered so
                    // infrequent instructions are placed at the end.

                    // IM extensions
                    INSN_CASE(LUI_rdN):
                        status = execute_LUI<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(AUIPC_rdN):
                        status = execute_AUIPC<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(JAL_rd0):
                        status = execute_JAL<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(JAL_rdN):
                        status = execute_JAL<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(JALR_rd0):
                        status = execute_JALR<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(JALR_rdN):
                        status = execute_JALR<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(BEQ):
                        status = execute_BEQ(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(BNE):
                        status = execute_BNE(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(BLT):
                        status = execute_BLT(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(BGE):
                        status = execute_BGE(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(BLTU):
                        status = execute_BLTU(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(BGEU):
                        status = execute_BGEU(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(ADDI_rdN):
                        status = execute_ADDI<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLTI_rdN):
                        status = execute_SLTI<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLTIU_rdN):
                        status = execute_SLTIU<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(XORI_rdN):
                        status = execute_XORI<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(ORI_rdN):
                        status = execute_ORI<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(ANDI_rdN):
                        status = execute_ANDI<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLLI_rdN):
                        status = execute_SLLI<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SRLI_SRAI_rdN):
                        status = execute_SRLI_SRAI<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(ADD_MUL_SUB_rdN):
                        status = execute_ADD_MUL_SUB<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLL_MULH_rdN):
                        status = execute_SLL_MULH<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLT_MULHSU_rdN):
                        status = execute_SLT_MULHSU<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLTU_MULHU_rdN):
                        status = execute_SLTU_MULHU<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(XOR_DIV_rdN):
                        status = execute_XOR_DIV<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SRL_DIVU_SRA_rdN):
                        status = execute_SRL_DIVU_SRA<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(OR_REM_rdN):
                        status = execute_OR_REM<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(AND_REMU_rdN):
                        status = execute_AND_REMU<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(ADDIW_rdN):
                        status = execute_ADDIW<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLLIW_rdN):
                        status = execute_SLLIW<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SRLIW_SRAIW_rdN):
                        status = execute_SRLIW_SRAIW<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(ADDW_MULW_SUBW_rdN):
                        status = execute_ADDW_MULW_SUBW<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLLW_rdN):
                        status = execute_SLLW<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SRLW_DIVUW_SRAW_rdN):
                        status = execute_SRLW_DIVUW_SRAW<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(DIVW_rdN):
                        status = execute_DIVW<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(REMW_rdN):
                        status = execute_REMW<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(REMUW_rdN):
                        status = execute_REMUW<rd_kind::xN>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(LD_rdN):
                        status = execute_LD<rd_kind::xN>(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(LW_rdN):
                        status = execute_LW<rd_kind::xN>(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(LWU_rdN):
                        status = execute_LWU<rd_kind::xN>(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(LH_rdN):
                        status = execute_LH<rd_kind::xN>(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(LHU_rdN):
                        status = execute_LHU<rd_kind::xN>(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(LB_rdN):
                        status = execute_LB<rd_kind::xN>(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(LBU_rdN):
                        status = execute_LBU<rd_kind::xN>(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(SD):
                        status = execute_SD(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(SW):
                        status = execute_SW(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(SH):
                        status = execute_SH(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(SB):
                        status = execute_SB(a, pc, mcycle, insn);
                        INSN_BREAK();
                    // C extension
                    INSN_CASE(C_HINT):
                    INSN_CASE(C_NOP):
                        status = execute_C_NOP(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_LUI):
                        status = execute_C_LUI(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_LI):
                        status = execute_C_LI(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_J):
                        status = execute_C_J(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_JR):
                        status = execute_C_JR(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_JALR):
                        status = execute_C_JALR(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_MV):
                        status = execute_C_MV(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_BEQZ):
                        status = execute_C_BEQZ(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_BNEZ):
                        status = execute_C_BNEZ(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_ADDI):
                        status = execute_C_ADDI(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_ADDIW):
                        status = execute_C_ADDIW(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_ADDI4SPN):
                        status = execute_C_ADDI4SPN(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_ADDI16SP):
                        status = execute_C_ADDI16SP(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_ANDI):
                        status = execute_C_ANDI(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_SLLI):
                        status = execute_C_SLLI(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_SRAI):
                        status = execute_C_SRAI(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_SRLI):
                        status = execute_C_SRLI(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_ADD):
                        status = execute_C_ADD(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_SUB):
                        status = execute_C_SUB(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_XOR):
                        status = execute_C_XOR(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_OR):
                        status = execute_C_OR(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_AND):
                        status = execute_C_AND(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_ADDW):
                        status = execute_C_ADDW(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_SUBW):
                        status = execute_C_SUBW(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(C_LD):
                        status = execute_C_LD(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(C_LW):
                        status = execute_C_LW(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(C_LDSP):
                        status = execute_C_LDSP(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(C_LWSP):
                        status = execute_C_LWSP(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(C_SD):
                        status = execute_C_SD(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(C_SW):
                        status = execute_C_SW(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(C_SDSP):
                        status = execute_C_SDSP(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(C_SWSP):
                        status = execute_C_SWSP(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(C_FLD):
                        status = execute_C_FLD(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(C_FLDSP):
                        status = execute_C_FLDSP(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(C_FSD):
                        status = execute_C_FSD(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(C_FSDSP):
                        status = execute_C_FSDSP(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(C_EBREAK):
                        status = execute_C_EBREAK(a, pc, insn);
                        INSN_BREAK();
                    // FD extensions
                    INSN_CASE(FD):
                        status = execute_FD(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(FLD):
                        status = execute_FLD(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(FLW):
                        status = execute_FLW(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(FSD):
                        status = execute_FSD(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(FSW):
                        status = execute_FSW(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(FMADD):
                        status = execute_FMADD(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(FMSUB):
                        status = execute_FMSUB(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(FNMADD):
                        status = execute_FNMADD(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(FNMSUB):
                        status = execute_FNMSUB(a, pc, insn);
                        INSN_BREAK();
                    // A extension
                    INSN_CASE(AMO_D):
                        status = execute_AMO_D(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(AMO_W):
                        status = execute_AMO_W(a, pc, mcycle, insn);
                        INSN_BREAK();
                    // Zicsr extension
                    INSN_CASE(CSRRW):
                        status = execute_CSRRW(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(CSRRS):
                        status = execute_CSRRS(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(CSRRC):
                        status = execute_CSRRC(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(CSRRWI):
                        status = execute_CSRRWI(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(CSRRSI):
                        status = execute_CSRRSI(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(CSRRCI):
                        status = execute_CSRRCI(a, pc, mcycle, insn);
                        INSN_BREAK();
                    // Special instructions that are less frequent
                    INSN_CASE(FENCE):
                        status = execute_FENCE(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(FENCE_I):
                        status = execute_FENCE_I(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(PRIVILEGED):
                        status = execute_privileged(a, pc, mcycle, insn);
                        INSN_BREAK();
                    // Instructions with hints where rd=0
                    INSN_CASE(LUI_rd0):
                        status = execute_LUI<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(AUIPC_rd0):
                        status = execute_AUIPC<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(ADDI_rd0):
                        status = execute_ADDI<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLTI_rd0):
                        status = execute_SLTI<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLTIU_rd0):
                        status = execute_SLTIU<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(XORI_rd0):
                        status = execute_XORI<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(ORI_rd0):
                        status = execute_ORI<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(ANDI_rd0):
                        status = execute_ANDI<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLLI_rd0):
                        status = execute_SLLI<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SRLI_SRAI_rd0):
                        status = execute_SRLI_SRAI<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(ADD_MUL_SUB_rd0):
                        status = execute_ADD_MUL_SUB<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLL_MULH_rd0):
                        status = execute_SLL_MULH<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLT_MULHSU_rd0):
                        status = execute_SLT_MULHSU<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLTU_MULHU_rd0):
                        status = execute_SLTU_MULHU<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(XOR_DIV_rd0):
                        status = execute_XOR_DIV<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SRL_DIVU_SRA_rd0):
                        status = execute_SRL_DIVU_SRA<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(OR_REM_rd0):
                        status = execute_OR_REM<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(AND_REMU_rd0):
                        status = execute_AND_REMU<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(ADDIW_rd0):
                        status = execute_ADDIW<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLLIW_rd0):
                        status = execute_SLLIW<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SRLIW_SRAIW_rd0):
                        status = execute_SRLIW_SRAIW<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(ADDW_MULW_SUBW_rd0):
                        status = execute_ADDW_MULW_SUBW<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SLLW_rd0):
                        status = execute_SLLW<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(SRLW_DIVUW_SRAW_rd0):
                        status = execute_SRLW_DIVUW_SRAW<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(DIVW_rd0):
                        status = execute_DIVW<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(REMW_rd0):
                        status = execute_REMW<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(REMUW_rd0):
                        status = execute_REMUW<rd_kind::x0>(a, pc, insn);
                        INSN_BREAK();
                    INSN_CASE(LD_rd0):
                        status = execute_LD<rd_kind::x0>(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(LW_rd0):
                        status = execute_LW<rd_kind::x0>(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(LWU_rd0):
                        status = execute_LWU<rd_kind::x0>(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(LH_rd0):
                        status = execute_LH<rd_kind::x0>(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(LHU_rd0):
                        status = execute_LHU<rd_kind::x0>(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(LB_rd0):
                        status = execute_LB<rd_kind::x0>(a, pc, mcycle, insn);
                        INSN_BREAK();
                    INSN_CASE(LBU_rd0):
                        status = execute_LBU<rd_kind::x0>(a, pc, mcycle, insn);
                        INSN_BREAK();
                    // Illegal instructions
                    INSN_CASE(ILLEGAL):
                        status = raise_illegal_insn_exception(a, pc, insn);
                        INSN_BREAK();
#ifndef USE_COMPUTED_GOTO
                    // When using a naive switch statement, other cases are impossible.
                    // The following will give a hint to the compiler that it can remove range checks
                    // (relevant for the WebAssembly target, which cannot use computed gotos).
                    default:
                        __builtin_unreachable();
                        break;
#endif
                }
                INSN_SWITCH_OUT();

                // NOLINTEND
                // clang-format on

                // When execute status is above success, we have to deal with special loop conditions,
                // this is very unlikely to happen most of the time
                if (unlikely(status > execute_status::success)) {
                    // We must invalidate the fetch cache whenever privilege mode changes,
                    // either due to a raised exception (execute_status::failure) or
                    // due to MRET/SRET instructions (execute_status::success_and_serve_interrupts)
                    // As a simplification (and optimization), the next line will also invalidate in more cases,
                    // but this it's fine.
                    fetch_vaddr_page = ~pc;
                    // All status above execute_status::success_and_serve_interrupts will require breaking the loop
                    if (unlikely(status >= execute_status::success_and_serve_interrupts)) {
                        // Increment the cycle counter mcycle
                        ++mcycle;

                        if (likely(status == execute_status::success_and_serve_interrupts)) {
                            // We have to break the inner loop to check and serve any pending interrupt immediately
                            break;
                        } // execute_status::success_and_yield or execute_status::success_and_halt
                        // Commit machine state
                        a.write_pc(pc);
                        a.write_mcycle(mcycle);
                        // Got an interruption that must be handled externally
                        return status;
                    }
                }
            }

            // Increment the cycle counter mcycle
            ++mcycle;

#ifndef NDEBUG
            // After a inner loop iteration, there can be no pending interrupts
            assert_no_brk(a);
#endif
        }
    }

    // Commit machine state
    a.write_pc(pc);
    a.write_mcycle(mcycle);
    return execute_status::success;
}

template <typename STATE_ACCESS>
interpreter_break_reason interpret(STATE_ACCESS a, uint64_t mcycle_end) {
    static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "code assumes little-endian byte ordering");
    static_assert(is_an_i_state_access<STATE_ACCESS>::value, "not an i_state_access");

    const uint64_t mcycle = a.read_mcycle();

    // If the cpu is halted, we are done
    if (a.read_iflags_H()) {
        return interpreter_break_reason::halted;
    }

    // If the cpu has yielded manually, we are done
    if (a.read_iflags_Y()) {
        return interpreter_break_reason::yielded_manually;
    }

    // If we reached the target mcycle, we are done
    if (mcycle >= mcycle_end) {
        return interpreter_break_reason::reached_target_mcycle;
    }

    // Just reset the automatic yield flag and continue
    a.write_iflags_X(0);

    // Run the interpreter loop,
    // the loop is outlined in a dedicated function so the compiler can optimize it better
    const execute_status status = interpret_loop(a, mcycle_end, mcycle);

    // Detect and return the reason for stopping the interpreter loop
    if (a.read_iflags_H() != 0) {
        return interpreter_break_reason::halted;
    }
    if (a.read_iflags_Y() != 0) {
        return interpreter_break_reason::yielded_manually;
    }
    if (a.read_iflags_X() != 0) {
        return interpreter_break_reason::yielded_automatically;
    }
    if (status == execute_status::success_and_yield) {
        return interpreter_break_reason::yielded_softly;
    } // Reached mcycle_end
    assert(a.read_mcycle() == mcycle_end); // LCOV_EXCL_LINE
    return interpreter_break_reason::reached_target_mcycle;
}

#ifdef MICROARCHITECTURE
// Explicit instantiation for uarch_machine_state_access
template interpreter_break_reason interpret(uarch_machine_state_access a, uint64_t mcycle_end);
#else
// Explicit instantiation for state_access
template interpreter_break_reason interpret(state_access a, uint64_t mcycle_end);
// Explicit instantiation for record_step_state_access
template interpreter_break_reason interpret(record_step_state_access a, uint64_t mcycle_end);
// Explicit instantiation for replay_step_state_access
template interpreter_break_reason interpret(replay_step_state_access a, uint64_t mcycle_end);
#endif // MICROARCHITECTURE

} // namespace cartesi
