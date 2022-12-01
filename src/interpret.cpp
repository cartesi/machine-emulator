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

#ifdef MICROARCHITECTURE
/// This will go away when we start using a different toolchain to compile interpret.cpp to run in the microarch.
#undef __SIZEOF_INT128__

#include "uarch-machine-state-access.h"
#include "uarch-runtime.h"
#else
#include "state-access.h"
#endif
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

#include "interpret.h"
#include "meta.h"
#include "riscv-constants.h"
#include "rom.h"
#include "rtc.h"
#include "soft-float.h"
#include "strict-aliasing.h"
#include "translate-virtual-address.h"

#ifdef __SIZEOF_INT128__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
using int128_t = __int128;
using uint128_t = unsigned __int128;
#pragma GCC diagnostic pop
#endif

static uint64_t mul64hu(uint64_t a, uint64_t b) {
#ifdef __SIZEOF_INT128__
    return static_cast<uint64_t>((static_cast<uint128_t>(a) * static_cast<uint128_t>(b)) >> 64);
#else
    uint64_t al = static_cast<uint64_t>(static_cast<uint32_t>(a));
    uint64_t ah = a >> 32;
    uint64_t bl = static_cast<uint64_t>(static_cast<uint32_t>(b));
    uint64_t bh = b >> 32;
    uint64_t pl = al * bl;
    uint64_t pm0 = al * bh;
    uint64_t pm1 = ah * bl;
    uint64_t ph = ah * bh;
    uint32_t c = static_cast<uint32_t>(((pl >> 32) + static_cast<uint32_t>(pm0) + static_cast<uint32_t>(pm1)) >> 32);
    return ph + (pm0 >> 32) + (pm1 >> 32) + c;
#endif
}

static int64_t mul64hsu(int64_t a, uint64_t b) {
#ifdef __SIZEOF_INT128__
    return static_cast<int64_t>((static_cast<int128_t>(a) * static_cast<int128_t>(b)) >> 64);
#else
    int64_t h = static_cast<int64_t>(mul64hu(static_cast<uint64_t>(a), static_cast<uint64_t>(b)));
    if (a < INT64_C(0))
        h -= b;
    return h;
#endif
}

static int64_t mul64h(int64_t a, int64_t b) {
#ifdef __SIZEOF_INT128__
    return static_cast<int64_t>((static_cast<int128_t>(a) * static_cast<int64_t>(b)) >> 64);
#else
    int64_t h = static_cast<int64_t>(mul64hu(static_cast<uint64_t>(a), static_cast<uint64_t>(b)));
    if (a < INT64_C(0))
        h -= b;
    if (b < INT64_C(0))
        h -= a;
    return h;
#endif
}

namespace cartesi {

static void print_uint64_t(uint64_t a) {
    (void) fprintf(stderr, "%016" PRIx64, a);
}

static const std::array<const char *, X_REG_COUNT> reg_name{"zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0",
    "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
    "t3", "t4", "t5", "t6"};

static const std::array<const char *, F_REG_COUNT> f_reg_name{"ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7",
    "fs0", "fs1", "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7",
    "fs8", "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11"};

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
            return "unkonwn";
    }
}

template <typename STATE>
static void dump_exception_or_interrupt(uint64_t cause, STATE &s) {
    uint64_t a7 = s.x[17];
    if ((cause & MCAUSE_INTERRUPT_FLAG) != 0) {
        switch (cause & ~MCAUSE_INTERRUPT_FLAG) {
            case 0:
                (void) fprintf(stderr, "reserved software interrupt");
                break;
            case 1:
                (void) fprintf(stderr, "supervisor software interrupt");
                break;
            case 2:
                (void) fprintf(stderr, "reserved software interrupt");
                break;
            case 3:
                (void) fprintf(stderr, "machine software interrupt");
                break;
            case 4:
                (void) fprintf(stderr, "reserved timer interrupt");
                break;
            case 5:
                (void) fprintf(stderr, "supervisor timer interrupt");
                break;
            case 6:
                (void) fprintf(stderr, "reserved timer interrupt");
                break;
            case 7:
                (void) fprintf(stderr, "machine timer interrupt");
                break;
            case 8:
                (void) fprintf(stderr, "reserved external interrupt");
                break;
            case 9:
                (void) fprintf(stderr, "supervisor external interrupt");
                break;
            case 10:
                (void) fprintf(stderr, "reserved external interrupt");
                break;
            case 11:
                (void) fprintf(stderr, "machine external interrupt");
                break;
            default:
                (void) fprintf(stderr, "unknown interrupt");
                break;
        }
    } else {
        switch (cause) {
            case 0:
                (void) fprintf(stderr, "instruction address misaligned");
                break;
            case 1:
                (void) fprintf(stderr, "instruction access fault");
                break;
            case 2:
                (void) fprintf(stderr, "illegal instruction");
                break;
            case 3:
                (void) fprintf(stderr, "breakpoint");
                break;
            case 4:
                (void) fprintf(stderr, "load address misaligned");
                break;
            case 5:
                (void) fprintf(stderr, "load access fault");
                break;
            case 6:
                (void) fprintf(stderr, "store/amo address misaligned");
                break;
            case 7:
                (void) fprintf(stderr, "store/amo access fault");
                break;
            case 8:
                (void) fprintf(stderr, "ecall %d from u-mode", static_cast<int>(a7));
                break;
            case 9:
                (void) fprintf(stderr, "ecall %s(%d) from s-mode", sbi_ecall_name(a7), static_cast<int>(a7));
                break;
            case 10:
                (void) fprintf(stderr, "ecall %d reserved", static_cast<int>(a7));
                break;
            case 11:
                (void) fprintf(stderr, "ecall %s(%d) from m-mode", sbi_ecall_name(a7), static_cast<int>(a7));
                break;
            case 12:
                (void) fprintf(stderr, "instruction page fault");
                break;
            case 13:
                (void) fprintf(stderr, "load page fault");
                break;
            case 15:
                (void) fprintf(stderr, "store/amo page fault");
                break;
            default:
                (void) fprintf(stderr, "reserved");
                break;
        }
    }
}

template <typename STATE>
static void dump_regs(const STATE &s) {
    const std::array<char, 5> priv_str{"USHM"};
    int cols = 256 / XLEN;
    (void) fprintf(stderr, "pc = ");
    print_uint64_t(s.pc);
    (void) fprintf(stderr, " ");
    for (int i = 1; i < X_REG_COUNT; i++) {
        (void) fprintf(stderr, "%-3s= ", reg_name[i]);
        print_uint64_t(s.x[i]);
        if ((i & (cols - 1)) == (cols - 1)) {
            (void) fprintf(stderr, "\n");
        } else {
            (void) fprintf(stderr, " ");
        }
    }
    for (int i = 0; i < F_REG_COUNT; i++) {
        (void) fprintf(stderr, "%-3s= ", f_reg_name[i]);
        print_uint64_t(s.f[i]);
        if ((i & (cols - 1)) == (cols - 1)) {
            (void) fprintf(stderr, "\n");
        } else {
            (void) fprintf(stderr, " ");
        }
    }
    (void) fprintf(stderr, "priv=%c", priv_str[s.iflags.PRV]);
    (void) fprintf(stderr, " mstatus=");
    print_uint64_t(s.mstatus);
    (void) fprintf(stderr, " cycles=%" PRId64, s.mcycle);
    (void) fprintf(stderr, " insns=%" PRId64, s.mcycle - s.minstret);
    (void) fprintf(stderr, "\n");
#if 1
    (void) fprintf(stderr, "mideleg=");
    print_uint64_t(s.mideleg);
    (void) fprintf(stderr, " mie=");
    print_uint64_t(s.mie);
    (void) fprintf(stderr, " mip=");
    print_uint64_t(s.mip);
    (void) fprintf(stderr, "\n");
#endif
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
static inline uint32_t csr_priv(CSR_address csr) {
    return (to_underlying(csr) >> 8) & 3;
}

/// \brief Changes privilege level.
/// \param a Machine state accessor object.
/// \param previous_prv Previous privilege level.
/// \param new_prv New privilege level.
/// \details This function is outlined to minimize host CPU code cache pressure.
template <typename STATE_ACCESS>
static NO_INLINE void set_priv(STATE_ACCESS &a, int new_prv) {
    INC_COUNTER(a.get_statistics(), priv_level[new_prv]);
    a.write_iflags_PRV(new_prv);
    // Invalidate all TLB entries
    a.flush_all_tlb();
    INC_COUNTER(a.get_statistics(), tlb_flush_all);
    INC_COUNTER(a.get_statistics(), tlb_flush_set_priv);
    //??D new priv 1.11 draft says invalidation should
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
static NO_INLINE uint64_t raise_exception(STATE_ACCESS &a, uint64_t pc, uint64_t cause, uint64_t tval) {
    auto note = a.make_scoped_note("raise_exception");
    (void) note;
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
            (void) fprintf(stderr, "raise_exception: cause=0x");
            print_uint64_t(cause);
            (void) fprintf(stderr, " tval=0x");
            print_uint64_t(tval);
            (void) fprintf(stderr, " (");
            dump_exception_or_interrupt(cause, a.get_naked_state());
            (void) fprintf(stderr, ")\n");
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

    // Every raised exception increases the exception counter, so we can compute minstret later
    a.write_minstret(a.read_minstret() + 1);

    uint64_t new_pc = 0;
    if (deleg) {
        a.write_scause(cause);
        a.write_sepc(pc);
        a.write_stval(tval);
        uint64_t mstatus = a.read_mstatus();
        mstatus = (mstatus & ~MSTATUS_SPIE_MASK) | (((mstatus >> MSTATUS_SIE_SHIFT) & 1) << MSTATUS_SPIE_SHIFT);
        mstatus = (mstatus & ~MSTATUS_SPP_MASK) | (priv << MSTATUS_SPP_SHIFT);
        mstatus &= ~MSTATUS_SIE_MASK;
        a.write_mstatus(mstatus);
        if (priv != PRV_S) {
            set_priv(a, PRV_S);
        }
        new_pc = a.read_stvec();
        a.write_pc(new_pc);
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
        mstatus = (mstatus & ~MSTATUS_MPP_MASK) | (priv << MSTATUS_MPP_SHIFT);
        mstatus &= ~MSTATUS_MIE_MASK;
        a.write_mstatus(mstatus);
        if (priv != PRV_M) {
            set_priv(a, PRV_M);
        }
        new_pc = a.read_mtvec();
        a.write_pc(new_pc);
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
static inline uint32_t get_pending_irq_mask(STATE_ACCESS &a) {

    uint64_t mip = a.read_mip();
    uint64_t mie = a.read_mie();

    // interrupt trap condition 2: bit i is set in both mip and mie
    uint32_t pending_ints = mip & mie;
    if (pending_ints == 0) {
        return 0;
    }

    uint32_t enabled_ints = 0;
    auto priv = a.read_iflags_PRV();
    switch (priv) {
        // interrupt trap condition 1a: the current privilege mode is M
        case PRV_M: {
            uint64_t mstatus = a.read_mstatus();
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
            uint64_t mstatus = a.read_mstatus();
            uint64_t mideleg = a.read_mideleg();
            // Interrupts not set in mideleg are machine-mode
            // and cannot be masked by supervisor mode

            // interrupt trap condition 3: bit i is not set in mideleg
            enabled_ints = ~mideleg;
            if (mstatus & MSTATUS_SIE_MASK) {
                enabled_ints |= mideleg;
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

/// \brief Raises an interrupt if any are enabled and pending.
/// \param a Machine state accessor object.
/// \param pc Machine current program counter.
template <typename STATE_ACCESS>
static inline uint64_t raise_interrupt_if_any(STATE_ACCESS &a, uint64_t pc) {
    auto note = a.make_scoped_note("raise_interrupt_if_any");
    (void) note;
    uint32_t mask = get_pending_irq_mask(a);
    if (mask != 0) {
        uint64_t irq_num = ilog2(mask);
        return raise_exception(a, pc, irq_num | MCAUSE_INTERRUPT_FLAG, 0);
    }
    return pc;
}

/// \brief At every tick, set interrupt as pending if the timer is expired
/// \param a Machine state accessor object.
/// \param mcycle Machine current cycle.
template <typename STATE_ACCESS>
static inline void set_rtc_interrupt(STATE_ACCESS &a, uint64_t mcycle) {
    auto note = a.make_scoped_note("set_rtc_interrupt");
    (void) note;
    if (rtc_is_tick(mcycle)) {
        uint64_t timecmp_cycle = rtc_time_to_cycle(a.read_clint_mtimecmp());
        if (timecmp_cycle <= mcycle && timecmp_cycle != 0) {
            uint64_t mip = a.read_mip();
            a.write_mip(mip | MIP_MTIP_MASK);
        }
    }
}

/// \brief Obtains the funct3 and opcode fields an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct3_00000_opcode(uint32_t insn) {
    return insn & 0b111000001111111;
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
    auto imm = static_cast<int32_t>(((insn >> (31 - 12)) & (1 << 12)) | ((insn >> (25 - 5)) & 0x7e0) |
        ((insn >> (8 - 1)) & 0x1e) | ((insn << (11 - 7)) & (1 << 11)));
    imm = (imm << 19) >> 19;
    return imm;
}

/// \brief Obtains the immediate value from a J-type instruction.
/// \param insn Instruction.
/// \details This function is forced to be inline because GCC may not always inline it.
static FORCE_INLINE int32_t insn_J_get_imm(uint32_t insn) {
    auto imm = static_cast<int32_t>(((insn >> (31 - 20)) & (1 << 20)) | ((insn >> (21 - 1)) & 0x7fe) |
        ((insn >> (20 - 11)) & (1 << 11)) | (insn & 0xff000));
    imm = (imm << 11) >> 11;
    return imm;
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
    // std::cerr << "funct7_sr2: " << std::bitset<5>((insn >> 27)) << '\n';
    return insn >> 27;
}

/// \brief Obtains the 6 most significant bits of the funct7 field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct7_sr1(uint32_t insn) {
    // std::cerr << "funct7_sr1: " << std::bitset<6>((insn >> 26)) << '\n';
    return insn >> 26;
}

/// \brief Obtains the funct7 field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct7(uint32_t insn) {
    // std::cerr << "funct7: " << std::bitset<7>((insn >> 25)) << '\n';
    return insn >> 25;
}

/// \brief Obtains the funct7 field concatenated with rs2 field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct7_rs2(uint32_t insn) {
    // std::cerr << "funct7_rs2: " << std::bitset<12>((insn >> 20)) << '\n';
    return insn >> 20;
}

/// \brief Obtains the rm field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_rm(uint32_t insn) {
    // std::cerr << "rm: " << std::bitset<3>((insn >> 12) & 0b111) << '\n';
    return (insn >> 12) & 0b111;
}

/// \brief Obtains the fmt field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_fmt(uint32_t insn) {
    // std::cerr << "fmt: " << std::bitset<3>((insn >> 25) & 0b11) << '\n';
    return (insn >> 25) & 0b11;
}

/// \brief Obtains the rs3 field from an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_rs3(uint32_t insn) {
    // std::cerr << "rs3: " << std::bitset<5>((insn >> 27)) << '\n';
    return (insn >> 27);
}

/// \brief Read an aligned word from virtual memory (slow path that goes through virtual address translation).
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \tparam RAISE_STORE_EXCEPTIONS Boolean, when true load exceptions are converted into store exceptions.
/// \param a Machine state accessor object.
/// \param pc Machine current program counter.
/// \param vaddr Virtual address for word.
/// \param pval Pointer to word receiving value.
/// \returns True if succeeded, false otherwise.
/// \details This function is outlined to minimize host CPU code cache pressure.
template <typename T, typename STATE_ACCESS, bool RAISE_STORE_EXCEPTIONS = false>
static NO_INLINE bool read_virtual_memory_slow(STATE_ACCESS &a, uint64_t pc, uint64_t vaddr, T *pval) {
    using U = std::make_unsigned_t<T>;
    // No support for misaligned accesses: They are handled by a trap in BBL
    if (unlikely(vaddr & (sizeof(T) - 1))) {
        raise_exception(a, pc,
            RAISE_STORE_EXCEPTIONS ? MCAUSE_STORE_AMO_ADDRESS_MISALIGNED : MCAUSE_LOAD_ADDRESS_MISALIGNED, vaddr);
        return false;
        // Deal with aligned accesses
    } else {
        uint64_t paddr{};
        if (unlikely(!translate_virtual_address(a, &paddr, vaddr, PTE_XWR_R_SHIFT))) {
            raise_exception(a, pc, RAISE_STORE_EXCEPTIONS ? MCAUSE_STORE_AMO_PAGE_FAULT : MCAUSE_LOAD_PAGE_FAULT,
                vaddr);
            return false;
        }
        auto &pma = a.template find_pma_entry<T>(paddr);
        if (unlikely(pma.get_istart_E() || !pma.get_istart_R())) {
            raise_exception(a, pc, RAISE_STORE_EXCEPTIONS ? MCAUSE_STORE_AMO_ACCESS_FAULT : MCAUSE_LOAD_ACCESS_FAULT,
                vaddr);
            return false;
        } else if (pma.get_istart_M()) {
            unsigned char *hpage = a.template replace_tlb_entry<TLB_READ>(vaddr, paddr, pma);
            uint64_t hoffset = vaddr & PAGE_OFFSET_MASK;
            a.read_memory_word(paddr, hpage, hoffset, pval);
            return true;
        } else if (pma.get_istart_IO()) {
            uint64_t offset = paddr - pma.get_start();
            uint64_t val{};
            // If we do not know how to read, we treat this as a PMA violation
            if (unlikely(!a.read_device(pma, offset, &val, log2_size<U>::value))) {
                raise_exception(a, pc,
                    RAISE_STORE_EXCEPTIONS ? MCAUSE_STORE_AMO_ACCESS_FAULT : MCAUSE_LOAD_ACCESS_FAULT, vaddr);
                return false;
            }
            *pval = static_cast<T>(val);
            // device logs its own state accesses
            return true;
        } else {
            assert(false);
            return false;
        }
    }
}

/// \brief Read an aligned word from virtual memory.
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Machine current program counter.
/// \param vaddr Virtual address for word.
/// \param pval Pointer to word receiving value.
/// \returns True if succeeded, false otherwise.
template <typename T, typename STATE_ACCESS, bool RAISE_STORE_EXCEPTIONS = false>
static FORCE_INLINE bool read_virtual_memory(STATE_ACCESS &a, uint64_t pc, uint64_t vaddr, T *pval) {
    // Try hitting the TLB
    if (unlikely(!(a.template read_memory_word_via_tlb<TLB_READ>(vaddr, pval)))) {
        // Outline the slow path into a function call to minimize host CPU code cache pressure
        INC_COUNTER(a.get_statistics(), tlb_rmiss);
        return read_virtual_memory_slow<T, STATE_ACCESS, RAISE_STORE_EXCEPTIONS>(a, pc, vaddr, pval);
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
/// \returns True if succeeded, false if exception raised.
/// \details This function is outlined to minimize host CPU code cache pressure.
template <typename T, typename STATE_ACCESS>
static NO_INLINE execute_status write_virtual_memory_slow(STATE_ACCESS &a, uint64_t pc, uint64_t vaddr,
    uint64_t val64) {
    using U = std::make_unsigned_t<T>;
    // No support for misaligned accesses: They are handled by a trap in BBL
    if (unlikely(vaddr & (sizeof(T) - 1))) {
        raise_exception(a, pc, MCAUSE_STORE_AMO_ADDRESS_MISALIGNED, vaddr);
        return execute_status::failure;
        // Deal with aligned accesses
    } else {
        uint64_t paddr{};
        if (unlikely(!translate_virtual_address(a, &paddr, vaddr, PTE_XWR_W_SHIFT))) {
            raise_exception(a, pc, MCAUSE_STORE_AMO_PAGE_FAULT, vaddr);
            return execute_status::failure;
        }
        auto &pma = a.template find_pma_entry<T>(paddr);
        if (unlikely(pma.get_istart_E() || !pma.get_istart_W())) {
            raise_exception(a, pc, MCAUSE_STORE_AMO_ACCESS_FAULT, vaddr);
            return execute_status::failure;
        } else if (pma.get_istart_M()) {
            unsigned char *hpage = a.template replace_tlb_entry<TLB_WRITE>(vaddr, paddr, pma);
            uint64_t hoffset = vaddr & PAGE_OFFSET_MASK;
            a.write_memory_word(paddr, hpage, hoffset, static_cast<T>(val64));
            return execute_status::success;
        } else if (pma.get_istart_IO()) {
            uint64_t offset = paddr - pma.get_start();
            auto status = a.write_device(pma, offset, val64, log2_size<U>::value);
            // If we do not know how to write, we treat this as a PMA violation
            if (unlikely(status == execute_status::failure)) {
                raise_exception(a, pc, MCAUSE_STORE_AMO_ACCESS_FAULT, vaddr);
                return execute_status::failure;
            }
            return status;
        } else {
            assert(false);
            return execute_status::failure;
        }
    }
}

/// \brief Writes an aligned word to virtual memory.
/// \tparam T uint8_t, uint16_t, uint32_t, or uint64_t.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Machine current program counter.
/// \param vaddr Virtual address for word.
/// \param val64 Value to write.
/// \returns True if succeeded, false if exception raised.
template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status write_virtual_memory(STATE_ACCESS &a, uint64_t pc, uint64_t vaddr, uint64_t val64) {
    // Try hitting the TLB
    if (unlikely((!a.template write_memory_word_via_tlb<TLB_WRITE>(vaddr, static_cast<T>(val64))))) {
        INC_COUNTER(a.get_statistics(), tlb_wmiss);
        // Outline the slow path into a function call to minimize host CPU code cache pressure
        return write_virtual_memory_slow<T>(a, pc, vaddr, val64);
    }
    INC_COUNTER(a.get_statistics(), tlb_whit);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static void dump_insn(STATE_ACCESS &a, uint64_t pc, uint32_t insn, const char *name) {
#ifdef DUMP_HIST
    a.get_naked_state().insn_hist[name]++;
#endif
#ifdef DUMP_REGS
    dump_regs(a.get_naked_state());
#endif
#ifdef DUMP_INSN
    uint64_t ppc = 0;
    //??D This will end up in the log, should we ever use this function while
    // collecting a log or consuming a log...
    if (std::is_same<STATE_ACCESS, state_access>::value && !translate_virtual_address(a, &ppc, pc, PTE_XWR_C_SHIFT)) {
        ppc = pc;
        fprintf(stderr, "v    %08" PRIx64, ppc);
    } else {
        fprintf(stderr, "p    %08" PRIx64, ppc);
    }
    fprintf(stderr, ":   %08" PRIx32 "   ", insn);
    fprintf(stderr, "%s\n", name);
#else
    (void) a;
    (void) pc;
    (void) insn;
    (void) name;
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
static FORCE_INLINE execute_status raise_illegal_insn_exception(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
static FORCE_INLINE execute_status raise_misaligned_fetch_exception(STATE_ACCESS &a, uint64_t &pc, uint64_t new_pc) {
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
static FORCE_INLINE execute_status advance_to_raised_exception(STATE_ACCESS &a, uint64_t &pc) {
    (void) a;
    pc = a.read_pc();
    return execute_status::failure;
}

/// \brief Advances pc to the next instruction.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Interpreter loop program counter (will be overwritten).
/// \return execute_status::success
/// \details This function is tail-called whenever the caller wants move to the next instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status advance_to_next_insn(STATE_ACCESS &a, uint64_t &pc) {
    (void) a;
    pc += 4;
    return execute_status::success;
}

/// \brief Advances pc to the next instruction.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Interpreter loop program counter (will be overwritten).
/// \param status Status to return.
/// \return status
/// \details This function is tail-called whenever the caller wants move to the next instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status advance_to_next_insn_with_status(STATE_ACCESS &a, uint64_t &pc,
    execute_status status) {
    (void) a;
    pc += 4;
    return status;
}

/// \brief Changes pc arbitrarily, potentially causing a jump.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Interpreter loop program counter (will be overwritten).
/// \return execute_status::success
/// \details This function is tail-called whenever the caller wants to jump.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_jump(STATE_ACCESS &a, uint64_t &pc, uint64_t new_pc) {
    (void) a;
    pc = new_pc;
    return execute_status::success;
}

/// \brief Execute the LR instruction.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Interpreter loop program counter (will be overwritten).
/// \param insn Instruction.
template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LR(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    T val = 0;
    if (unlikely(!read_virtual_memory<T>(a, pc, vaddr, &val))) {
        return advance_to_raised_exception(a, pc);
    }
    a.write_ilrsc(vaddr);
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        a.write_x(rd, static_cast<uint64_t>(val));
    }
    return advance_to_next_insn(a, pc);
}

/// \brief Execute the SC instruction.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Interpreter loop program counter (will be overwritten).
/// \param insn Instruction.
template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SC(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    uint64_t val = 0;
    uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    execute_status status = execute_status::success;
    if (a.read_ilrsc() == vaddr) {
        status = write_virtual_memory<T>(a, pc, vaddr, static_cast<T>(a.read_x(insn_get_rs2(insn))));
        if (unlikely(status == execute_status::failure)) {
            return advance_to_raised_exception(a, pc);
        }
    } else {
        val = 1;
    }
    a.write_ilrsc(-1); // Must clear reservation, regardless of failure
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        a.write_x(rd, val);
    }
    return advance_to_next_insn_with_status(a, pc, status);
}

/// \brief Implementation of the LR.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LR_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    (void) a;
    (void) pc;
    (void) insn;
    if (unlikely((insn & 0b00000001111100000000000000000000) != 0)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    dump_insn(a, pc, insn, "lr.w");
    auto note = a.make_scoped_note("lr.w");
    (void) note;
    return execute_LR<int32_t>(a, pc, insn);
}

/// \brief Implementation of the SC.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SC_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sc.w");
    auto note = a.make_scoped_note("sc.w");
    (void) note;
    return execute_SC<int32_t>(a, pc, insn);
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_AMO(STATE_ACCESS &a, uint64_t &pc, uint32_t insn, const F &f) {
    uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    T valm = 0;
    // AMOs never raise load exceptions. Since any unreadable page is also unwritable,
    // attempting to perform an AMO on an unreadable page always raises a store page-fault exception.
    if (unlikely((!read_virtual_memory<T, STATE_ACCESS, true>(a, pc, vaddr, &valm)))) {
        return advance_to_raised_exception(a, pc);
    }
    T valr = static_cast<T>(a.read_x(insn_get_rs2(insn)));
    valr = f(valm, valr);
    execute_status status = write_virtual_memory<T>(a, pc, vaddr, valr);
    if (unlikely(status == execute_status::failure)) {
        return advance_to_raised_exception(a, pc);
    }
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        a.write_x(rd, static_cast<uint64_t>(valm));
    }
    return advance_to_next_insn_with_status(a, pc, status);
}

/// \brief Implementation of the AMOSWAP.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOSWAP_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amoswap.w");
    auto note = a.make_scoped_note("amoswap.w");
    (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t {
        (void) valm;
        return valr;
    });
}

/// \brief Implementation of the AMOADD.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOADD_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amoadd.w");
    auto note = a.make_scoped_note("amoadd.w");
    (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t {
        int32_t val = 0;
        __builtin_add_overflow(valm, valr, &val);
        return val;
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOXOR_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amoxor.w");
    auto note = a.make_scoped_note("amoxor.w");
    (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm ^ valr; });
}

/// \brief Implementation of the AMOAND.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOAND_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amoand.w");
    auto note = a.make_scoped_note("amoand.w");
    (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm & valr; });
}

/// \brief Implementation of the AMOOR.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOOR_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amoor.w");
    auto note = a.make_scoped_note("amoor.w");
    (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t { return valm | valr; });
}

/// \brief Implementation of the AMOMIN.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMIN_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amomin.w");
    auto note = a.make_scoped_note("amomin.w");
    (void) note;
    return execute_AMO<int32_t>(a, pc, insn,
        [](int32_t valm, int32_t valr) -> int32_t { return valm < valr ? valm : valr; });
}

/// \brief Implementation of the AMOMAX.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMAX_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amomax.w");
    auto note = a.make_scoped_note("amomax.w");
    (void) note;
    return execute_AMO<int32_t>(a, pc, insn,
        [](int32_t valm, int32_t valr) -> int32_t { return valm > valr ? valm : valr; });
}

/// \brief Implementation of the AMOMINU.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMINU_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amominu.w");
    auto note = a.make_scoped_note("amominu.w");
    (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t {
        return static_cast<uint32_t>(valm) < static_cast<uint32_t>(valr) ? valm : valr;
    });
}

/// \brief Implementation of the AMOMAXU.W instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMAXU_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amomaxu.w");
    auto note = a.make_scoped_note("amomaxu.w");
    (void) note;
    return execute_AMO<int32_t>(a, pc, insn, [](int32_t valm, int32_t valr) -> int32_t {
        return static_cast<uint32_t>(valm) > static_cast<uint32_t>(valr) ? valm : valr;
    });
}

/// \brief Implementation of the LR.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LR_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    if (unlikely((insn & 0b00000001111100000000000000000000) != 0)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    dump_insn(a, pc, insn, "lr.d");
    auto note = a.make_scoped_note("lr.d");
    (void) note;
    return execute_LR<uint64_t>(a, pc, insn);
}

/// \brief Implementation of the SC.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SC_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sc.d");
    auto note = a.make_scoped_note("sc.d");
    (void) note;
    return execute_SC<uint64_t>(a, pc, insn);
}

/// \brief Implementation of the AMOSWAP.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOSWAP_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amoswap.d");
    auto note = a.make_scoped_note("amoswap.d");
    (void) note;
    return execute_AMO<int64_t>(a, pc, insn, [](int64_t valm, int64_t valr) -> int64_t {
        (void) valm;
        return valr;
    });
}

/// \brief Implementation of the AMOADD.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOADD_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amoadd.d");
    auto note = a.make_scoped_note("amoadd.d");
    (void) note;
    return execute_AMO<int64_t>(a, pc, insn, [](int64_t valm, int64_t valr) -> int64_t {
        int64_t val = 0;
        __builtin_add_overflow(valm, valr, &val);
        return val;
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOXOR_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amoxor.d");
    auto note = a.make_scoped_note("amoxor.d");
    (void) note;
    return execute_AMO<int64_t>(a, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm ^ valr; });
}

/// \brief Implementation of the AMOAND.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOAND_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amoand.d");
    auto note = a.make_scoped_note("amoand.d");
    (void) note;
    return execute_AMO<int64_t>(a, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm & valr; });
}

/// \brief Implementation of the AMOOR.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOOR_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amoor.d");
    auto note = a.make_scoped_note("amoor.d");
    (void) note;
    return execute_AMO<int64_t>(a, pc, insn, [](int64_t valm, int64_t valr) -> int64_t { return valm | valr; });
}

/// \brief Implementation of the AMOMIN.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMIN_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amomin.d");
    auto note = a.make_scoped_note("amomin.d");
    (void) note;
    return execute_AMO<int64_t>(a, pc, insn,
        [](int64_t valm, int64_t valr) -> int64_t { return valm < valr ? valm : valr; });
}

/// \brief Implementation of the AMOMAX.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMAX_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amomax.d");
    auto note = a.make_scoped_note("amomax.d");
    (void) note;
    return execute_AMO<int64_t>(a, pc, insn,
        [](int64_t valm, int64_t valr) -> int64_t { return valm > valr ? valm : valr; });
}

/// \brief Implementation of the AMOMINU.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMINU_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amominu.d");
    auto note = a.make_scoped_note("amominu.d");
    (void) note;
    return execute_AMO<uint64_t>(a, pc, insn,
        [](uint64_t valm, uint64_t valr) -> uint64_t { return valm < valr ? valm : valr; });
}

/// \brief Implementation of the AMOMAXU.D instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMOMAXU_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "amomaxu.d");
    auto note = a.make_scoped_note("amomaxu.d");
    (void) note;
    return execute_AMO<uint64_t>(a, pc, insn,
        [](uint64_t valm, uint64_t valr) -> uint64_t { return valm > valr ? valm : valr; });
}

/// \brief Implementation of the ADDW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ADDW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "addw");
    auto note = a.make_scoped_note("addw");
    (void) note;
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
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SUBW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "subw");
    auto note = a.make_scoped_note("subw");
    (void) note;
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
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLLW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sllw");
    auto note = a.make_scoped_note("sllw");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(static_cast<uint32_t>(rs1) << (rs2 & 31));
        return static_cast<uint64_t>(rs1w);
    });
}

/// \brief Implementation of the SRLW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRLW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "srlw");
    auto note = a.make_scoped_note("srlw");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto rs1w = static_cast<int32_t>(static_cast<uint32_t>(rs1) >> (rs2 & 31));
        return static_cast<uint64_t>(rs1w);
    });
}

/// \brief Implementation of the SRAW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRAW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sraw");
    auto note = a.make_scoped_note("sraw");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(rs1) >> (rs2 & 31);
        return static_cast<uint64_t>(rs1w);
    });
}

/// \brief Implementation of the MULW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_MULW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "mulw");
    auto note = a.make_scoped_note("mulw");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto rs1w = static_cast<int32_t>(rs1);
        auto rs2w = static_cast<int32_t>(rs2);
        int32_t val = 0;
        __builtin_mul_overflow(rs1w, rs2w, &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the DIVW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_DIVW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "divw");
    auto note = a.make_scoped_note("divw");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto rs1w = static_cast<int32_t>(rs1);
        auto rs2w = static_cast<int32_t>(rs2);
        if (rs2w == 0) {
            return static_cast<uint64_t>(-1);
        } else if (rs1w == (static_cast<int32_t>(1) << (32 - 1)) && rs2w == -1) {
            return static_cast<uint64_t>(rs1w);
        } else {
            return static_cast<uint64_t>(rs1w / rs2w);
        }
    });
}

/// \brief Implementation of the DIVUW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_DIVUW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "divuw");
    auto note = a.make_scoped_note("divuw");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto rs1w = static_cast<uint32_t>(rs1);
        auto rs2w = static_cast<uint32_t>(rs2);
        if (rs2w == 0) {
            return static_cast<uint64_t>(-1);
        } else {
            return static_cast<uint64_t>(static_cast<int32_t>(rs1w / rs2w));
        }
    });
}

/// \brief Implementation of the REMW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_REMW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "remw");
    auto note = a.make_scoped_note("remw");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto rs1w = static_cast<int32_t>(rs1);
        auto rs2w = static_cast<int32_t>(rs2);
        if (rs2w == 0) {
            return static_cast<uint64_t>(rs1w);
        } else if (rs1w == (static_cast<int32_t>(1) << (32 - 1)) && rs2w == -1) {
            return static_cast<uint64_t>(0);
        } else {
            return static_cast<uint64_t>(rs1w % rs2w);
        }
    });
}

/// \brief Implementation of the REMUW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_REMUW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    (void) a;
    (void) pc;
    (void) insn;
    dump_insn(a, pc, insn, "remuw");
    auto note = a.make_scoped_note("remuw");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto rs1w = static_cast<uint32_t>(rs1);
        auto rs2w = static_cast<uint32_t>(rs2);
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
static inline bool rdcounteren(STATE_ACCESS &a, uint64_t mask) {
    uint64_t counteren = MCOUNTEREN_R_MASK;
    auto priv = a.read_iflags_PRV();
    if (priv <= PRV_S) {
        counteren &= a.read_mcounteren();
        if (priv < PRV_S) {
            counteren &= a.read_scounteren();
        }
    }
    return mask > 0 && (counteren & mask) == mask;
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_cycle(STATE_ACCESS &a, bool *status) {
    if (rdcounteren(a, MCOUNTEREN_CY_MASK)) {
        return read_csr_success(a.read_mcycle(), status);
    } else {
        return read_csr_fail(status);
    }
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_instret(STATE_ACCESS &a, bool *status) {
    if (rdcounteren(a, MCOUNTEREN_IR_MASK)) {
        uint64_t mcycle = a.read_mcycle();
        uint64_t iexcepts = a.read_minstret();
        uint64_t minstret = mcycle - iexcepts;
        return read_csr_success(minstret, status);
    } else {
        return read_csr_fail(status);
    }
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_time(STATE_ACCESS &a, bool *status) {
    if (rdcounteren(a, MCOUNTEREN_TM_MASK)) {
        uint64_t mtime = rtc_cycle_to_time(a.read_mcycle());
        return read_csr_success(mtime, status);
    } else {
        return read_csr_fail(status);
    }
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_hpmcounter(STATE_ACCESS &a, CSR_address csraddr, bool *status) {
    uint64_t mask = UINT64_C(1) << (static_cast<int32_t>(csraddr) - static_cast<int32_t>(CSR_address::ucycle));
    if (rdcounteren(a, mask)) {
        return read_csr_success(0, status);
    } else {
        return read_csr_fail(status);
    }
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_sstatus(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_mstatus() & SSTATUS_R_MASK, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_senvcfg(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_senvcfg() & SENVCFG_R_MASK, status);
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
static inline uint64_t read_csr_menvcfg(STATE_ACCESS &a, bool *status) {
    return read_csr_success(a.read_menvcfg() & MENVCFG_R_MASK, status);
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
    uint64_t mcycle = a.read_mcycle();
    uint64_t iexcepts = a.read_minstret();
    uint64_t minstret = mcycle - iexcepts;
    return read_csr_success(minstret, status);
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

template <typename STATE_ACCESS>
static inline uint64_t read_csr_fflags(STATE_ACCESS &a, bool *status) {
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return read_csr_fail(status);
    }
    uint64_t fflags = (a.read_fcsr() & FCSR_FFLAGS_RW_MASK) >> FCSR_FFLAGS_SHIFT;
    return read_csr_success(fflags, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_frm(STATE_ACCESS &a, bool *status) {
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return read_csr_fail(status);
    }
    uint64_t frm = (a.read_fcsr() & FCSR_FRM_RW_MASK) >> FCSR_FRM_SHIFT;
    return read_csr_success(frm, status);
}

template <typename STATE_ACCESS>
static inline uint64_t read_csr_fcsr(STATE_ACCESS &a, bool *status) {
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
static NO_INLINE uint64_t read_csr(STATE_ACCESS &a, CSR_address csraddr, bool *status) {

    if (csr_priv(csraddr) > a.read_iflags_PRV()) {
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
            return read_csr_cycle(a, status);
        case CSR_address::uinstret:
            return read_csr_instret(a, status);
        case CSR_address::utime:
            return read_csr_time(a, status);

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
            return read_csr_mcycle(a, status);
        case CSR_address::minstret:
            return read_csr_minstret(a, status);

        case CSR_address::mvendorid:
            return read_csr_mvendorid(a, status);
        case CSR_address::marchid:
            return read_csr_marchid(a, status);
        case CSR_address::mimpid:
            return read_csr_mimpid(a, status);

        // All hardwired to zero
        case CSR_address::tselect:
        case CSR_address::tdata1:
        case CSR_address::tdata2:
        case CSR_address::tdata3:
        case CSR_address::mhartid:
        case CSR_address::mcountinhibit:
        case CSR_address::mconfigptr:
            return read_csr_success(0, status);

        default:
            // Hardware performance counters and event selectors are hardwired to zero
            if ((to_underlying(csraddr) >= to_underlying(CSR_address::mhpmcounter3) &&
                    to_underlying(csraddr) <= to_underlying(CSR_address::mhpmcounter31)) ||
                (to_underlying(csraddr) >= to_underlying(CSR_address::mhpmevent3) &&
                    to_underlying(csraddr) <= to_underlying(CSR_address::mhpmevent31))) {
                return read_csr_success(0, status);
            }
            // Shadows of hardware performance counters
            if (to_underlying(csraddr) >= to_underlying(CSR_address::uhpmcounter3) &&
                to_underlying(csraddr) <= to_underlying(CSR_address::uhpmcounter31)) {
                return read_csr_hpmcounter(a, csraddr, status);
            }
            // Invalid CSRs
#ifdef DUMP_INVALID_CSR
            fprintf(stderr, "csr_read: invalid CSR=0x%x\n", static_cast<int>(csraddr));
#endif
            return read_csr_fail(status);
    }
}

template <typename STATE_ACCESS>
static execute_status write_csr_sstatus(STATE_ACCESS &a, uint64_t val) {
    uint64_t mstatus = a.read_mstatus();
    return write_csr_mstatus(a, (mstatus & ~SSTATUS_W_MASK) | (val & SSTATUS_W_MASK));
}

template <typename STATE_ACCESS>
static execute_status write_csr_senvcfg(STATE_ACCESS &a, uint64_t val) {
    uint64_t senvcfg = a.read_senvcfg();
    a.write_senvcfg((senvcfg & ~SENVCFG_W_MASK) | (val & SENVCFG_W_MASK));
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_sie(STATE_ACCESS &a, uint64_t val) {
    uint64_t mie = a.read_mie();
    uint64_t mask = a.read_mideleg();
    mie = (mie & ~mask) | (val & mask);
    a.write_mie(mie);
    if (get_pending_irq_mask(a)) {
        return execute_status::success_and_break_inner_loop;
    }
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_stvec(STATE_ACCESS &a, uint64_t val) {
    a.write_stvec(val & ~3);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_scounteren(STATE_ACCESS &a, uint64_t val) {
    a.write_scounteren(val & SCOUNTEREN_RW_MASK);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_sscratch(STATE_ACCESS &a, uint64_t val) {
    a.write_sscratch(val);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_sepc(STATE_ACCESS &a, uint64_t val) {
    a.write_sepc(val & ~3);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_scause(STATE_ACCESS &a, uint64_t val) {
    a.write_scause(val);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_stval(STATE_ACCESS &a, uint64_t val) {
    a.write_stval(val);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_sip(STATE_ACCESS &a, uint64_t val) {
    uint64_t mask = a.read_mideleg();
    uint64_t mip = a.read_mip();
    mip = (mip & ~mask) | (val & mask);
    a.write_mip(mip);
    if (get_pending_irq_mask(a)) {
        return execute_status::success_and_break_inner_loop;
    }
    return execute_status::success;
}

template <typename STATE_ACCESS>
static NO_INLINE execute_status write_csr_satp(STATE_ACCESS &a, uint64_t val) {
    uint64_t mstatus = a.read_mstatus();
    auto priv = a.read_iflags_PRV();

    // When TVM=1, attempts to read or write the satp CSR
    // while executing in S-mode will raise an illegal instruction exception
    if (unlikely(priv == PRV_S && (mstatus & MSTATUS_TVM_MASK))) {
        return execute_status::failure;
    }

    uint64_t old_satp = a.read_satp();
    uint64_t stap = old_satp;
    uint64_t mode = val >> SATP_MODE_SHIFT;

    // Checks for supported MODE
    switch (mode) {
        case SATP_MODE_BARE:
        case SATP_MODE_SV39:
        case SATP_MODE_SV48:
        case SATP_MODE_SV57:
            stap = (val & SATP_PPN_MASK) | (val & SATP_ASID_MASK) | (val & SATP_MODE_MASK);
            break;
        default:
            // Implementations are not required to support all MODE settings,
            // and if satp is written with an unsupported MODE,
            // the entire write has no effect; no fields in satp are modified.
            break;
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
    uint64_t mod = old_satp ^ stap;
    if (mod & (SATP_ASID_MASK | SATP_MODE_MASK)) {
        a.flush_all_tlb();
        INC_COUNTER(a.get_statistics(), tlb_flush_all);
        INC_COUNTER(a.get_statistics(), tlb_flush_satp);
    }
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mstatus(STATE_ACCESS &a, uint64_t val) {
    uint64_t old_mstatus = a.read_mstatus() & MSTATUS_R_MASK;

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
    uint64_t mod = old_mstatus ^ mstatus;
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

    // When changing an interrupt enabled bit, we may have to break inner loop
    if ((mod & (MSTATUS_SIE_MASK | MSTATUS_MIE_MASK)) && get_pending_irq_mask(a)) {
        return execute_status::success_and_break_inner_loop;
    }

    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_menvcfg(STATE_ACCESS &a, uint64_t val) {
    uint64_t menvcfg = a.read_menvcfg() & MENVCFG_R_MASK;

    // Modify only bits that can be written to
    menvcfg = (menvcfg & ~MENVCFG_W_MASK) | (val & MENVCFG_W_MASK);
    // Store results
    a.write_menvcfg(menvcfg);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_medeleg(STATE_ACCESS &a, uint64_t val) {
    // For exceptions that cannot occur in less privileged modes,
    // the corresponding medeleg bits should be read-only zero
    a.write_medeleg((a.read_medeleg() & ~MEDELEG_W_MASK) | (val & MEDELEG_W_MASK));
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mideleg(STATE_ACCESS &a, uint64_t val) {
    const uint64_t mask = MIP_SSIP_MASK | MIP_STIP_MASK | MIP_SEIP_MASK;
    uint64_t mideleg = a.read_mideleg();
    mideleg = (mideleg & ~mask) | (val & mask);
    a.write_mideleg(mideleg);
    if (get_pending_irq_mask(a)) {
        return execute_status::success_and_break_inner_loop;
    }
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mie(STATE_ACCESS &a, uint64_t val) {
    const uint64_t mask = MIP_MSIP_MASK | MIP_MTIP_MASK | MIP_MEIP_MASK | MIP_SSIP_MASK | MIP_STIP_MASK | MIP_SEIP_MASK;
    uint64_t mie = a.read_mie();
    mie = (mie & ~mask) | (val & mask);
    a.write_mie(mie);
    if (get_pending_irq_mask(a)) {
        return execute_status::success_and_break_inner_loop;
    }
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mtvec(STATE_ACCESS &a, uint64_t val) {
    a.write_mtvec(val & ~3);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mcounteren(STATE_ACCESS &a, uint64_t val) {
    a.write_mcounteren(val & MCOUNTEREN_RW_MASK);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_minstret(STATE_ACCESS &a, uint64_t val) {
    uint64_t mcycle = a.read_mcycle();
    uint64_t iexcepts = mcycle - val;
    a.write_minstret(iexcepts + 1); // The value will be incremented after the instruction is executed
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mcycle(STATE_ACCESS &a, uint64_t val) {
    // We can't allow writes to mcycle because we use it to measure the progress in machine execution.
    // The specs say it is an MRW CSR, read-writeable in M-mode.
    // BBL enables all counters in both M- and S-modes.
    // In Spike, QEMU, and riscvemu, mcycle and minstret are the aliases for the same counter.
    // QEMU calls exit (!) on writes to mcycle or minstret.
    // We instead raise an exception.
    (void) a;
    (void) val;
    return execute_status::failure;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mscratch(STATE_ACCESS &a, uint64_t val) {
    a.write_mscratch(val);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mepc(STATE_ACCESS &a, uint64_t val) {
    a.write_mepc(val & ~3);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mcause(STATE_ACCESS &a, uint64_t val) {
    a.write_mcause(val);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mtval(STATE_ACCESS &a, uint64_t val) {
    a.write_mtval(val);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static execute_status write_csr_mip(STATE_ACCESS &a, uint64_t val) {
    const uint64_t mask = MIP_SEIP_MASK | MIP_SSIP_MASK | MIP_STIP_MASK;
    auto mip = a.read_mip();
    mip = (mip & ~mask) | (val & mask);
    a.write_mip(mip);
    if (get_pending_irq_mask(a)) {
        return execute_status::success_and_break_inner_loop;
    }
    return execute_status::success;
}

template <typename STATE_ACCESS>
static inline execute_status write_csr_fflags(STATE_ACCESS &a, uint64_t val) {
    uint64_t mstatus = a.read_mstatus();
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((mstatus & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return execute_status::failure;
    }
    uint64_t fcsr = (a.read_fcsr() & ~FCSR_FFLAGS_RW_MASK) | ((val << FCSR_FFLAGS_SHIFT) & FCSR_FFLAGS_RW_MASK);
    a.write_fcsr(fcsr);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static inline execute_status write_csr_frm(STATE_ACCESS &a, uint64_t val) {
    uint64_t mstatus = a.read_mstatus();
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((mstatus & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return execute_status::failure;
    }
    uint64_t fcsr = (a.read_fcsr() & ~FCSR_FRM_RW_MASK) | ((val << FCSR_FRM_SHIFT) & FCSR_FRM_RW_MASK);
    a.write_fcsr(fcsr);
    return execute_status::success;
}

template <typename STATE_ACCESS>
static inline execute_status write_csr_fcsr(STATE_ACCESS &a, uint64_t val) {
    uint64_t mstatus = a.read_mstatus();
    // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
    if (unlikely((mstatus & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
        return execute_status::failure;
    }
    uint64_t fcsr = val & FCSR_RW_MASK;
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
static NO_INLINE execute_status write_csr(STATE_ACCESS &a, CSR_address csraddr, uint64_t val) {
#if defined(DUMP_CSR)
    fprintf(stderr, "csr_write: csr=0x%03x val=0x", static_cast<int>(csraddr));
    print_uint64_t(val);
    fprintf(stderr, "\n");
#endif
    if (unlikely(csr_is_read_only(csraddr))) {
        return execute_status::failure;
    }
    if (unlikely(csr_priv(csraddr) > a.read_iflags_PRV())) {
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
            return write_csr_minstret(a, val);

        // Ignore writes
        case CSR_address::misa:
        case CSR_address::mcountinhibit:
        case CSR_address::tselect:
        case CSR_address::tdata1:
        case CSR_address::tdata2:
        case CSR_address::tdata3:
            return execute_status::success;

        default:
            // Ignore writes to hardware performance counters and event selectors
            if ((to_underlying(csraddr) >= to_underlying(CSR_address::mhpmcounter3) &&
                    to_underlying(csraddr) <= to_underlying(CSR_address::mhpmcounter31)) ||
                (to_underlying(csraddr) >= to_underlying(CSR_address::mhpmevent3) &&
                    to_underlying(csraddr) <= to_underlying(CSR_address::mhpmevent31))) {
                return execute_status::success; // NOLINT(readability-simplify-boolean-expr)
            }
            // Invalid CSRs
#ifdef DUMP_INVALID_CSR
            fprintf(stderr, "csr_write: invalid CSR=0x%x\n", static_cast<int>(csraddr));
#endif
            return execute_status::failure;
    }
}

template <typename STATE_ACCESS, typename RS1VAL>
static FORCE_INLINE execute_status execute_csr_RW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn, const RS1VAL &rs1val) {
    auto csraddr = static_cast<CSR_address>(insn_I_get_uimm(insn));
    // Try to read old CSR value
    bool status = true;
    uint64_t csrval = 0;
    // If rd=r0, we do not read from the CSR to avoid side-effects
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        csrval = read_csr(a, csraddr, &status);
    }
    if (unlikely(!status)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    // Try to write new CSR value
    //??D When we optimize the inner interpreter loop, we
    //    will have to check if there was a change to the
    //    memory manager and report back from here so we
    //    break out of the inner loop
    execute_status wstatus = write_csr(a, csraddr, rs1val(a, insn));
    if (unlikely(wstatus == execute_status::failure)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    // Write to rd only after potential read/write exceptions
    if (rd != 0) {
        a.write_x(rd, csrval);
    }
    return advance_to_next_insn_with_status(a, pc, wstatus);
}

/// \brief Implementation of the CSRRW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_CSRRW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "csrrw");
    auto note = a.make_scoped_note("csrrw");
    (void) note;
    return execute_csr_RW(a, pc, insn,
        [](STATE_ACCESS &a, uint32_t insn) -> uint64_t { return a.read_x(insn_get_rs1(insn)); });
}

/// \brief Implementation of the CSRRWI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_CSRRWI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "csrrwi");
    auto note = a.make_scoped_note("csrrwi");
    (void) note;
    return execute_csr_RW(a, pc, insn,
        [](STATE_ACCESS &, uint32_t insn) -> uint64_t { return static_cast<uint64_t>(insn_get_rs1(insn)); });
}

template <typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_csr_SC(STATE_ACCESS &a, uint64_t &pc, uint32_t insn, const F &f) {
    auto csraddr = static_cast<CSR_address>(insn_I_get_uimm(insn));
    // Try to read old CSR value
    bool status = false;
    uint64_t csrval = read_csr(a, csraddr, &status);
    if (unlikely(!status)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    // Load value of rs1 before potentially overwriting it
    // with the value of the csr when rd=rs1
    uint32_t rs1 = insn_get_rs1(insn);
    uint64_t rs1val = a.read_x(rs1);
    execute_status wstatus = execute_status::success;
    if (rs1 != 0) {
        //??D When we optimize the inner interpreter loop, we
        //    will have to check if there was a change to the
        //    memory manager and report back from here so we
        //    break out of the inner loop
        wstatus = write_csr(a, csraddr, f(csrval, rs1val));
        if (unlikely(wstatus == execute_status::failure)) {
            return raise_illegal_insn_exception(a, pc, insn);
        }
    }
    // Write to rd only after potential read/write exceptions
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        a.write_x(rd, csrval);
    }
    return advance_to_next_insn_with_status(a, pc, wstatus);
}

/// \brief Implementation of the CSRRS instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_CSRRS(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "csrrs");
    auto note = a.make_scoped_note("csrrs");
    (void) note;
    return execute_csr_SC(a, pc, insn, [](uint64_t csr, uint64_t rs1) -> uint64_t { return csr | rs1; });
}

/// \brief Implementation of the CSRRC instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_CSRRC(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "csrrc");
    auto note = a.make_scoped_note("csrrc");
    (void) note;
    return execute_csr_SC(a, pc, insn, [](uint64_t csr, uint64_t rs1) -> uint64_t { return csr & ~rs1; });
}

template <typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_csr_SCI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn, const F &f) {
    auto csraddr = static_cast<CSR_address>(insn_I_get_uimm(insn));
    // Try to read old CSR value
    bool status = false;
    uint64_t csrval = read_csr(a, csraddr, &status);
    if (unlikely(!status)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    uint32_t rs1 = insn_get_rs1(insn);
    execute_status wstatus = execute_status::success;
    if (rs1 != 0) {
        //??D When we optimize the inner interpreter loop, we
        //    will have to check if there was a change to the
        //    memory manager and report back from here so we
        //    break out of the inner loop
        wstatus = write_csr(a, csraddr, f(csrval, rs1));
        if (unlikely(wstatus == execute_status::failure)) {
            return raise_illegal_insn_exception(a, pc, insn);
        }
    }
    // Write to rd only after potential read/write exceptions
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        a.write_x(rd, csrval);
    }
    return advance_to_next_insn_with_status(a, pc, wstatus);
}

/// \brief Implementation of the CSRRSI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_CSRRSI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "csrrsi");
    auto note = a.make_scoped_note("csrrsi");
    (void) note;
    return execute_csr_SCI(a, pc, insn, [](uint64_t csr, uint32_t rs1) -> uint64_t { return csr | rs1; });
}

/// \brief Implementation of the CSRRCI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_CSRRCI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "csrrci");
    auto note = a.make_scoped_note("csrrci");
    (void) note;
    return execute_csr_SCI(a, pc, insn, [](uint64_t csr, uint32_t rs1) -> uint64_t { return csr & ~rs1; });
}

/// \brief Implementation of the ECALL instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ECALL(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "ecall");
    auto note = a.make_scoped_note("ecall");
    (void) note;
    auto priv = a.read_iflags_PRV();
    pc = raise_exception(a, pc, MCAUSE_ECALL_BASE + priv, 0);
    return execute_status::failure;
}

/// \brief Implementation of the EBREAK instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_EBREAK(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    (void) a;
    dump_insn(a, pc, insn, "ebreak");
    auto note = a.make_scoped_note("ebreak");
    (void) note;
    pc = raise_exception(a, pc, MCAUSE_BREAKPOINT, pc);
    return execute_status::failure;
}

/// \brief Implementation of the SRET instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRET(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sret");
    auto note = a.make_scoped_note("sret");
    (void) note;
    auto priv = a.read_iflags_PRV();
    uint64_t mstatus = a.read_mstatus();
    if (unlikely(priv < PRV_S || (priv == PRV_S && (mstatus & MSTATUS_TSR_MASK)))) {
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
    if (priv != spp) {
        set_priv(a, spp);
    }
    pc = a.read_sepc();
    if (get_pending_irq_mask(a)) {
        return execute_status::success_and_break_inner_loop;
    }
    return execute_status::success;
}

/// \brief Implementation of the MRET instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_MRET(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "mret");
    auto note = a.make_scoped_note("mret");
    (void) note;
    auto priv = a.read_iflags_PRV();
    if (unlikely(priv < PRV_M)) {
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
    if (priv != mpp) {
        set_priv(a, mpp);
    }
    pc = a.read_mepc();
    if (get_pending_irq_mask(a)) {
        return execute_status::success_and_break_inner_loop;
    }
    return execute_status::success;
}

/// \brief Implementation of the WFI instruction.
/// \details This function is outlined to minimize host CPU code cache pressure.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_WFI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "wfi");
    auto note = a.make_scoped_note("wfi");
    (void) note;
    // Check privileges and do nothing else
    auto priv = a.read_iflags_PRV();
    uint64_t mstatus = a.read_mstatus();
    // WFI can always causes an illegal instruction exception in less-privileged modes when TW=1
    if (unlikely(priv == PRV_U || (priv < PRV_M && (mstatus & MSTATUS_TW_MASK)))) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    execute_status status = a.poll_console();
    return advance_to_next_insn_with_status(a, pc, status);
}

/// \brief Implementation of the FENCE instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FENCE(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    (void) insn;
    INC_COUNTER(a.get_statistics(), fence);
    dump_insn(a, pc, insn, "fence");
    auto note = a.make_scoped_note("fence");
    (void) note;
    // Really do nothing
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the FENCE.I instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FENCE_I(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    (void) insn;
    INC_COUNTER(a.get_statistics(), fence_i);
    dump_insn(a, pc, insn, "fence.i");
    auto note = a.make_scoped_note("fence.i");
    (void) note;
    // Really do nothing
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_arithmetic(STATE_ACCESS &a, uint64_t &pc, uint32_t insn, const F &f) {
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
static FORCE_INLINE execute_status execute_ADD(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "add");
    auto note = a.make_scoped_note("add");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        uint64_t val = 0;
        __builtin_add_overflow(rs1, rs2, &val);
        return val;
    });
}

/// \brief Implementation of the SUB instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SUB(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sub");
    auto note = a.make_scoped_note("sub");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        uint64_t val = 0;
        __builtin_sub_overflow(rs1, rs2, &val);
        return val;
    });
}

/// \brief Implementation of the SLL instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLL(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sll");
    auto note = a.make_scoped_note("sll");
    (void) note;
    return execute_arithmetic(a, pc, insn,
        [](uint64_t rs1, uint64_t rs2) -> uint64_t { return rs1 << (rs2 & (XLEN - 1)); });
}

/// \brief Implementation of the SLT instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLT(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "slt");
    auto note = a.make_scoped_note("slt");
    (void) note;
    return execute_arithmetic(a, pc, insn,
        [](uint64_t rs1, uint64_t rs2) -> uint64_t { return static_cast<int64_t>(rs1) < static_cast<int64_t>(rs2); });
}

/// \brief Implementation of the SLTU instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLTU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sltu");
    auto note = a.make_scoped_note("sltu");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t { return rs1 < rs2; });
}

/// \brief Implementation of the XOR instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_XOR(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "xor");
    auto note = a.make_scoped_note("xor");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t { return rs1 ^ rs2; });
}

/// \brief Implementation of the SRL instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRL(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "srl");
    auto note = a.make_scoped_note("srl");
    (void) note;
    return execute_arithmetic(a, pc, insn,
        [](uint64_t rs1, uint64_t rs2) -> uint64_t { return rs1 >> (rs2 & (XLEN - 1)); });
}

/// \brief Implementation of the SRA instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRA(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sra");
    auto note = a.make_scoped_note("sra");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        return static_cast<uint64_t>(static_cast<int64_t>(rs1) >> (rs2 & (XLEN - 1)));
    });
}

/// \brief Implementation of the OR instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_OR(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "or");
    auto note = a.make_scoped_note("or");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t { return rs1 | rs2; });
}

/// \brief Implementation of the AND instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AND(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "and");
    auto note = a.make_scoped_note("and");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t { return rs1 & rs2; });
}

/// \brief Implementation of the MUL instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_MUL(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "mul");
    auto note = a.make_scoped_note("mul");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto srs1 = static_cast<int64_t>(rs1);
        auto srs2 = static_cast<int64_t>(rs2);
        int64_t val = 0;
        __builtin_mul_overflow(srs1, srs2, &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the MULH instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_MULH(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "mulh");
    auto note = a.make_scoped_note("mulh");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto srs1 = static_cast<int64_t>(rs1);
        auto srs2 = static_cast<int64_t>(rs2);
        return static_cast<uint64_t>(mul64h(srs1, srs2));
    });
}

/// \brief Implementation of the MULHSU instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_MULHSU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "mulhsu");
    auto note = a.make_scoped_note("mulhsu");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto srs1 = static_cast<int64_t>(rs1);
        return static_cast<uint64_t>(mul64hsu(srs1, rs2));
    });
}

/// \brief Implementation of the MULHU instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_MULHU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "mulhu");
    auto note = a.make_scoped_note("mulhu");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t { return mul64hu(rs1, rs2); });
}

/// \brief Implementation of the DIV instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_DIV(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "div");
    auto note = a.make_scoped_note("div");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto srs1 = static_cast<int64_t>(rs1);
        auto srs2 = static_cast<int64_t>(rs2);
        if (srs2 == 0) {
            return static_cast<uint64_t>(-1);
        } else if (srs1 == (INT64_C(1) << (XLEN - 1)) && srs2 == -1) {
            return static_cast<uint64_t>(srs1);
        } else {
            return static_cast<uint64_t>(srs1 / srs2);
        }
    });
}

/// \brief Implementation of the DIVU instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_DIVU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "divu");
    auto note = a.make_scoped_note("divu");
    (void) note;
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
static FORCE_INLINE execute_status execute_REM(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "rem");
    auto note = a.make_scoped_note("rem");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        auto srs1 = static_cast<int64_t>(rs1);
        auto srs2 = static_cast<int64_t>(rs2);
        if (srs2 == 0) {
            return srs1;
        } else if (srs1 == (INT64_C(1) << (XLEN - 1)) && srs2 == -1) {
            return 0;
        } else {
            return static_cast<uint64_t>(srs1 % srs2);
        }
    });
}

/// \brief Implementation of the REMU instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_REMU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "remu");
    auto note = a.make_scoped_note("remu");
    (void) note;
    return execute_arithmetic(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> uint64_t {
        if (rs2 == 0) {
            return rs1;
        } else {
            return rs1 % rs2;
        }
    });
}

template <typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_arithmetic_immediate(STATE_ACCESS &a, uint64_t &pc, uint32_t insn,
    const F &f) {
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
static FORCE_INLINE execute_status execute_SRLI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "srli");
    auto note = a.make_scoped_note("srli");
    (void) note;
    return execute_arithmetic_immediate(a, pc, insn,
        [](uint64_t rs1, int32_t imm) -> uint64_t { return rs1 >> (imm & (XLEN - 1)); });
}

/// \brief Implementation of the SRAI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRAI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "srai");
    auto note = a.make_scoped_note("srai");
    (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        return static_cast<uint64_t>(static_cast<int64_t>(rs1) >> (imm & (XLEN - 1)));
    });
}

/// \brief Implementation of the ADDI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ADDI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "addi");
    auto note = a.make_scoped_note("addi");
    (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        int64_t val = 0;
        __builtin_add_overflow(static_cast<int64_t>(rs1), static_cast<int64_t>(imm), &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the SLTI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLTI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "slti");
    auto note = a.make_scoped_note("slti");
    (void) note;
    return execute_arithmetic_immediate(a, pc, insn,
        [](uint64_t rs1, int32_t imm) -> uint64_t { return static_cast<int64_t>(rs1) < static_cast<int64_t>(imm); });
}

/// \brief Implementation of the SLTIU instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLTIU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sltiu");
    auto note = a.make_scoped_note("sltiu");
    (void) note;
    return execute_arithmetic_immediate(a, pc, insn,
        [](uint64_t rs1, int32_t imm) -> uint64_t { return rs1 < static_cast<uint64_t>(imm); });
}

/// \brief Implementation of the XORI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_XORI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "xori");
    auto note = a.make_scoped_note("xori");
    (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t { return rs1 ^ imm; });
}

/// \brief Implementation of the ORI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ORI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "ori");
    auto note = a.make_scoped_note("ori");
    (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t { return rs1 | imm; });
}

/// \brief Implementation of the ANDI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ANDI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "andi");
    auto note = a.make_scoped_note("andi");
    (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t { return rs1 & imm; });
}

/// \brief Implementation of the SLLI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLLI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    if (unlikely((insn & (0b111111 << 26)) != 0)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    dump_insn(a, pc, insn, "slli");
    auto note = a.make_scoped_note("slli");
    (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        // No need to mask lower 6 bits in imm because of the if condition a above
        // We do it anyway here to prevent problems if this code is moved
        return rs1 << (imm & 0b111111);
    });
}

/// \brief Implementation of the ADDIW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ADDIW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "addiw");
    auto note = a.make_scoped_note("addiw");
    (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        int32_t val = 0;
        __builtin_add_overflow(static_cast<int32_t>(rs1), imm, &val);
        return static_cast<uint64_t>(val);
    });
}

/// \brief Implementation of the SLLIW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLLIW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    if (unlikely(insn_get_funct7(insn) != 0)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    dump_insn(a, pc, insn, "slliw");
    auto note = a.make_scoped_note("slliw");
    (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        // No need to mask lower 5 bits in imm because of the if condition a above
        // We do it anyway here to prevent problems if this code is moved
        int32_t rs1w = static_cast<int32_t>(static_cast<uint32_t>(rs1) << (imm & 0b11111));
        return static_cast<uint64_t>(rs1w);
    });
}

/// \brief Implementation of the SRLIW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRLIW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "srliw");
    auto note = a.make_scoped_note("srliw");
    (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        // No need to mask lower 5 bits in imm because of funct7 test in caller
        // We do it anyway here to prevent problems if this code is moved
        auto rs1w = static_cast<int32_t>(static_cast<uint32_t>(rs1) >> (imm & 0b11111));
        return static_cast<uint64_t>(rs1w);
    });
}

/// \brief Implementation of the SRAIW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRAIW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sraiw");
    auto note = a.make_scoped_note("sraiw");
    (void) note;
    return execute_arithmetic_immediate(a, pc, insn, [](uint64_t rs1, int32_t imm) -> uint64_t {
        int32_t rs1w = static_cast<int32_t>(rs1) >> (imm & 0b11111);
        return static_cast<uint64_t>(rs1w);
    });
}

template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    int32_t imm = insn_S_get_imm(insn);
    uint64_t val = a.read_x(insn_get_rs2(insn));
    execute_status status = write_virtual_memory<T>(a, pc, vaddr + imm, val);
    if (unlikely(status == execute_status::failure)) {
        return advance_to_raised_exception(a, pc);
    }
    return advance_to_next_insn_with_status(a, pc, status);
}

/// \brief Implementation of the SB instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SB(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sb");
    auto note = a.make_scoped_note("sb");
    (void) note;
    return execute_S<uint8_t>(a, pc, insn);
}

/// \brief Implementation of the SH instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SH(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sh");
    auto note = a.make_scoped_note("sh");
    (void) note;
    return execute_S<uint16_t>(a, pc, insn);
}

/// \brief Implementation of the SW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sw");
    auto note = a.make_scoped_note("sw");
    (void) note;
    return execute_S<uint32_t>(a, pc, insn);
}

/// \brief Implementation of the SD instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SD(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "sd");
    auto note = a.make_scoped_note("sd");
    (void) note;
    return execute_S<uint64_t>(a, pc, insn);
}

template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_L(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    int32_t imm = insn_I_get_imm(insn);
    T val;
    if (unlikely(!read_virtual_memory<T>(a, pc, vaddr + imm, &val))) {
        return advance_to_raised_exception(a, pc);
    }
    uint32_t rd = insn_get_rd(insn);
    // don't write x0
    if (rd != 0) {
        // This static branch is eliminated by the compiler
        if (std::is_signed<T>::value) {
            a.write_x(rd, static_cast<int64_t>(val));
        } else {
            a.write_x(rd, static_cast<uint64_t>(val));
        }
    }
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the LB instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LB(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "lb");
    auto note = a.make_scoped_note("lb");
    (void) note;
    return execute_L<int8_t>(a, pc, insn);
}

/// \brief Implementation of the LH instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LH(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "lh");
    auto note = a.make_scoped_note("lh");
    (void) note;
    return execute_L<int16_t>(a, pc, insn);
}

/// \brief Implementation of the LW instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "lw");
    auto note = a.make_scoped_note("lw");
    (void) note;
    return execute_L<int32_t>(a, pc, insn);
}

/// \brief Implementation of the LD instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LD(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "ld");
    auto note = a.make_scoped_note("ld");
    (void) note;
    return execute_L<int64_t>(a, pc, insn);
}

/// \brief Implementation of the LBU instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LBU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "lbu");
    auto note = a.make_scoped_note("lbu");
    (void) note;
    return execute_L<uint8_t>(a, pc, insn);
}

/// \brief Implementation of the LHU instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LHU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "lhu");
    auto note = a.make_scoped_note("lhu");
    (void) note;
    return execute_L<uint16_t>(a, pc, insn);
}

/// \brief Implementation of the LWU instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LWU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "lwu");
    auto note = a.make_scoped_note("lwu");
    (void) note;
    return execute_L<uint32_t>(a, pc, insn);
}

template <typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_branch(STATE_ACCESS &a, uint64_t &pc, uint32_t insn, const F &f) {
    uint64_t rs1 = a.read_x(insn_get_rs1(insn));
    uint64_t rs2 = a.read_x(insn_get_rs2(insn));
    if (f(rs1, rs2)) {
        uint64_t new_pc = static_cast<int64_t>(pc + insn_B_get_imm(insn));
        if (unlikely(new_pc & 3)) {
            return raise_misaligned_fetch_exception(a, pc, new_pc);
        } else {
            return execute_jump(a, pc, new_pc);
        }
    }
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the BEQ instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_BEQ(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "beq");
    auto note = a.make_scoped_note("beq");
    (void) note;
    return execute_branch(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool { return rs1 == rs2; });
}

/// \brief Implementation of the BNE instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_BNE(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "bne");
    auto note = a.make_scoped_note("bne");
    (void) note;
    return execute_branch(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool { return rs1 != rs2; });
}

/// \brief Implementation of the BLT instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_BLT(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "blt");
    auto note = a.make_scoped_note("blt");
    (void) note;
    return execute_branch(a, pc, insn,
        [](uint64_t rs1, uint64_t rs2) -> bool { return static_cast<int64_t>(rs1) < static_cast<int64_t>(rs2); });
}

/// \brief Implementation of the BGE instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_BGE(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "bge");
    auto note = a.make_scoped_note("bge");
    (void) note;
    return execute_branch(a, pc, insn,
        [](uint64_t rs1, uint64_t rs2) -> bool { return static_cast<int64_t>(rs1) >= static_cast<int64_t>(rs2); });
}

/// \brief Implementation of the BLTU instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_BLTU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "bltu");
    auto note = a.make_scoped_note("bltu");
    (void) note;
    return execute_branch(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool { return rs1 < rs2; });
}

/// \brief Implementation of the BGEU instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_BGEU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "bgeu");
    auto note = a.make_scoped_note("bgeu");
    (void) note;
    return execute_branch(a, pc, insn, [](uint64_t rs1, uint64_t rs2) -> bool { return rs1 >= rs2; });
}

/// \brief Implementation of the LUI instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_LUI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "lui");
    auto note = a.make_scoped_note("lui");
    (void) note;
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        a.write_x(rd, insn_U_get_imm(insn));
    }
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the AUIPC instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AUIPC(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "auipc");
    auto note = a.make_scoped_note("auipc");
    (void) note;
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        a.write_x(rd, pc + insn_U_get_imm(insn));
    }
    return advance_to_next_insn(a, pc);
}

/// \brief Implementation of the JAL instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_JAL(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "jal");
    auto note = a.make_scoped_note("jal");
    (void) note;
    uint64_t new_pc = pc + insn_J_get_imm(insn);
    if (unlikely(new_pc & 3)) {
        return raise_misaligned_fetch_exception(a, pc, new_pc);
    }
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        a.write_x(rd, pc + 4);
    }
    return execute_jump(a, pc, new_pc);
}

/// \brief Implementation of the JALR instruction.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_JALR(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "jalr");
    auto note = a.make_scoped_note("jalr");
    (void) note;
    uint64_t val = pc + 4;
    uint64_t new_pc =
        static_cast<int64_t>(a.read_x(insn_get_rs1(insn)) + insn_I_get_imm(insn)) & ~static_cast<uint64_t>(1);
    if (unlikely(new_pc & 3)) {
        return raise_misaligned_fetch_exception(a, pc, new_pc);
    }
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        a.write_x(rd, val);
    }
    return execute_jump(a, pc, new_pc);
}

/// \brief Implementation of the SFENCE.VMA instruction.
/// \details This function is outlined to minimize host CPU code cache pressure.
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SFENCE_VMA(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    // rs1 and rs2 are arbitrary, rest is set
    if (unlikely((insn & 0b11111110000000000111111111111111) != 0b00010010000000000000000001110011)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    INC_COUNTER(a.get_statistics(), fence_vma);
    dump_insn(a, pc, insn, "sfence.vma");
    auto note = a.make_scoped_note("sfence.vma");
    (void) note;
    auto priv = a.read_iflags_PRV();
    uint64_t mstatus = a.read_mstatus();

    // When TVM=1, attempts to execute an SFENCE.VMA while executing in S-mode
    // will raise an illegal instruction exception.
    if (unlikely(priv == PRV_U || (priv == PRV_S && (mstatus & MSTATUS_TVM_MASK)))) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    uint32_t rs1 = insn_get_rs1(insn);
    uint32_t rs2 = insn_get_rs2(insn);
    if (rs1 == 0) {
        a.flush_all_tlb();
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
    } else {
        uint64_t vaddr = a.read_x(rs1);
        a.flush_tlb_vaddr(vaddr);
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
    }
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRLI_SRAI(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_SRLI_SRAI_funct7_sr1>(insn_get_funct7_sr1(insn))) {
        case insn_SRLI_SRAI_funct7_sr1::SRLI:
            return execute_SRLI(a, pc, insn);
        case insn_SRLI_SRAI_funct7_sr1::SRAI:
            return execute_SRAI(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRLIW_SRAIW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_SRLIW_SRAIW_funct7>(insn_get_funct7(insn))) {
        case insn_SRLIW_SRAIW_funct7::SRLIW:
            return execute_SRLIW(a, pc, insn);
        case insn_SRLIW_SRAIW_funct7::SRAIW:
            return execute_SRAIW(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMO_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_AMO_funct7_sr2>(insn_get_funct7_sr2(insn))) {
        case insn_AMO_funct7_sr2::AMOADD:
            return execute_AMOADD_W(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOSWAP:
            return execute_AMOSWAP_W(a, pc, insn);
        case insn_AMO_funct7_sr2::LR:
            return execute_LR_W(a, pc, insn);
        case insn_AMO_funct7_sr2::SC:
            return execute_SC_W(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOXOR:
            return execute_AMOXOR_W(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOOR:
            return execute_AMOOR_W(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOAND:
            return execute_AMOAND_W(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOMIN:
            return execute_AMOMIN_W(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOMAX:
            return execute_AMOMAX_W(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOMINU:
            return execute_AMOMINU_W(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOMAXU:
            return execute_AMOMAXU_W(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AMO_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_AMO_funct7_sr2>(insn_get_funct7_sr2(insn))) {
        case insn_AMO_funct7_sr2::AMOADD:
            return execute_AMOADD_D(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOSWAP:
            return execute_AMOSWAP_D(a, pc, insn);
        case insn_AMO_funct7_sr2::LR:
            return execute_LR_D(a, pc, insn);
        case insn_AMO_funct7_sr2::SC:
            return execute_SC_D(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOXOR:
            return execute_AMOXOR_D(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOOR:
            return execute_AMOOR_D(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOAND:
            return execute_AMOAND_D(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOMIN:
            return execute_AMOMIN_D(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOMAX:
            return execute_AMOMAX_D(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOMINU:
            return execute_AMOMINU_D(a, pc, insn);
        case insn_AMO_funct7_sr2::AMOMAXU:
            return execute_AMOMAXU_D(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ADD_MUL_SUB(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_ADD_MUL_SUB_funct7>(insn_get_funct7(insn))) {
        case insn_ADD_MUL_SUB_funct7::ADD:
            return execute_ADD(a, pc, insn);
        case insn_ADD_MUL_SUB_funct7::MUL:
            return execute_MUL(a, pc, insn);
        case insn_ADD_MUL_SUB_funct7::SUB:
            return execute_SUB(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLL_MULH(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_SLL_MULH_funct7>(insn_get_funct7(insn))) {
        case insn_SLL_MULH_funct7::SLL:
            return execute_SLL(a, pc, insn);
        case insn_SLL_MULH_funct7::MULH:
            return execute_MULH(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLT_MULHSU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_SLT_MULHSU_funct7>(insn_get_funct7(insn))) {
        case insn_SLT_MULHSU_funct7::SLT:
            return execute_SLT(a, pc, insn);
        case insn_SLT_MULHSU_funct7::MULHSU:
            return execute_MULHSU(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SLTU_MULHU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_SLTU_MULHU_funct7>(insn_get_funct7(insn))) {
        case insn_SLTU_MULHU_funct7::SLTU:
            return execute_SLTU(a, pc, insn);
        case insn_SLTU_MULHU_funct7::MULHU:
            return execute_MULHU(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_XOR_DIV(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_XOR_DIV_funct7>(insn_get_funct7(insn))) {
        case insn_XOR_DIV_funct7::XOR:
            return execute_XOR(a, pc, insn);
        case insn_XOR_DIV_funct7::DIV:
            return execute_DIV(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRL_DIVU_SRA(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_SRL_DIVU_SRA_funct7>(insn_get_funct7(insn))) {
        case insn_SRL_DIVU_SRA_funct7::SRL:
            return execute_SRL(a, pc, insn);
        case insn_SRL_DIVU_SRA_funct7::DIVU:
            return execute_DIVU(a, pc, insn);
        case insn_SRL_DIVU_SRA_funct7::SRA:
            return execute_SRA(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_OR_REM(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_OR_REM_funct7>(insn_get_funct7(insn))) {
        case insn_OR_REM_funct7::OR:
            return execute_OR(a, pc, insn);
        case insn_OR_REM_funct7::REM:
            return execute_REM(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_AND_REMU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_AND_REMU_funct7>(insn_get_funct7(insn))) {
        case insn_AND_REMU_funct7::AND:
            return execute_AND(a, pc, insn);
        case insn_AND_REMU_funct7::REMU:
            return execute_REMU(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_ADDW_MULW_SUBW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_ADDW_MULW_SUBW_funct7>(insn_get_funct7(insn))) {
        case insn_ADDW_MULW_SUBW_funct7::ADDW:
            return execute_ADDW(a, pc, insn);
        case insn_ADDW_MULW_SUBW_funct7::MULW:
            return execute_MULW(a, pc, insn);
        case insn_ADDW_MULW_SUBW_funct7::SUBW:
            return execute_SUBW(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_SRLW_DIVUW_SRAW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    switch (static_cast<insn_SRLW_DIVUW_SRAW_funct7>(insn_get_funct7(insn))) {
        case insn_SRLW_DIVUW_SRAW_funct7::SRLW:
            return execute_SRLW(a, pc, insn);
        case insn_SRLW_DIVUW_SRAW_funct7::DIVUW:
            return execute_DIVUW(a, pc, insn);
        case insn_SRLW_DIVUW_SRAW_funct7::SRAW:
            return execute_SRAW(a, pc, insn);
        default:
            return raise_illegal_insn_exception(a, pc, insn);
    }
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_privileged(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
            return execute_WFI(a, pc, insn);
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
            // The canonical NaN has a positive sign and all significand bits clear except the MSB,
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
static FORCE_INLINE execute_status execute_float_ternary_op_rm(STATE_ACCESS &a, uint64_t &pc, uint32_t insn,
    const F &f) {
    uint64_t fcsr = a.read_fcsr();
    // The rounding mode comes from the insn
    uint32_t rm = insn_get_rm(insn);
    // Unless it is set to FRM_DYN, in which case it comes from fcsr.frm
    if (rm == FRM_DYN) {
        rm = fcsr >> FCSR_FRM_SHIFT;
    }
    // If the rounding mode is invalid, the instruction is considered illegal
    if (unlikely(rm > FRM_RMM)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    uint32_t rd = insn_get_rd(insn);
    uint32_t fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
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
static FORCE_INLINE execute_status execute_float_binary_op_rm(STATE_ACCESS &a, uint64_t &pc, uint32_t insn,
    const F &f) {
    uint64_t fcsr = a.read_fcsr();
    // The rounding mode comes from the insn
    uint32_t rm = insn_get_rm(insn);
    // Unless it is set to FRM_DYN, in which case it comes from fcsr.frm
    if (rm == FRM_DYN) {
        rm = fcsr >> FCSR_FRM_SHIFT;
    }
    // If the rounding mode is invalid, the instruction is considered illegal
    if (unlikely(rm > FRM_RMM)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    uint32_t rd = insn_get_rd(insn);
    uint32_t fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
    // We must always check if input operands are properly NaN-boxed.
    T s1 = float_unbox<T>(a.read_f(insn_get_rs1(insn)));
    T s2 = float_unbox<T>(a.read_f(insn_get_rs2(insn)));
    // Must store a valid NaN-boxed value.
    a.write_f(rd, float_box(f(s1, s2, rm, &fflags)));
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    return advance_to_next_insn(a, pc);
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_float_unary_op_rm(STATE_ACCESS &a, uint64_t &pc, uint32_t insn, const F &f) {
    uint64_t fcsr = a.read_fcsr();
    // Unary operation should have rs2 set to 0
    if (unlikely(insn_get_rs2(insn) != 0)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    // The rounding mode comes from the insn
    uint32_t rm = insn_get_rm(insn);
    // Unless it is set to FRM_DYN, in which case it comes from fcsr.frm
    if (rm == FRM_DYN) {
        rm = fcsr >> FCSR_FRM_SHIFT;
    }
    // If the rounding mode is invalid, the instruction is considered illegal
    if (unlikely(rm > FRM_RMM)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    uint32_t rd = insn_get_rd(insn);
    uint32_t fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
    // We must always check if input operands are properly NaN-boxed.
    T s1 = float_unbox<T>(a.read_f(insn_get_rs1(insn)));
    // Must store a valid NaN-boxed value.
    a.write_f(rd, float_box(f(s1, rm, &fflags)));
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    return advance_to_next_insn(a, pc);
}

template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FS(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    int32_t imm = insn_S_get_imm(insn);
    // A narrower n-bit transfer out of the floating-point
    // registers will transfer the lower n bits of the register ignoring the upper FLEN−n bits.
    T val = static_cast<T>(a.read_f(insn_get_rs2(insn)));
    execute_status status = write_virtual_memory<T>(a, pc, vaddr + imm, val);
    if (unlikely(status == execute_status::failure)) {
        return advance_to_raised_exception(a, pc);
    }
    return advance_to_next_insn_with_status(a, pc, status);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsw");
    auto note = a.make_scoped_note("fsw");
    (void) note;
    return execute_FS<uint32_t>(a, pc, insn);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSD(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsd");
    auto note = a.make_scoped_note("fsd");
    (void) note;
    return execute_FS<uint64_t>(a, pc, insn);
}

template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FL(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    // Loads the float value from virtual memory
    uint64_t vaddr = a.read_x(insn_get_rs1(insn));
    int32_t imm = insn_I_get_imm(insn);
    T val = 0;
    if (unlikely(!read_virtual_memory(a, pc, vaddr + imm, &val))) {
        return advance_to_raised_exception(a, pc);
    }
    // A narrower n-bit transfer, n < FLEN,
    // into the f registers will create a valid NaN-boxed value.
    uint32_t rd = insn_get_rd(insn);
    a.write_f(rd, float_box(val));
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FLW(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "flw");
    auto note = a.make_scoped_note("flw");
    (void) note;
    return execute_FL<uint32_t>(a, pc, insn);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FLD(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fld");
    auto note = a.make_scoped_note("fld");
    (void) note;
    return execute_FL<uint64_t>(a, pc, insn);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMADD_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmadd.s");
    auto note = a.make_scoped_note("fmadd.s");
    (void) note;
    return execute_float_ternary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t s3, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::fma(s1, s2, s3, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMADD_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmadd.d");
    auto note = a.make_scoped_note("fmadd.d");
    (void) note;
    return execute_float_ternary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint64_t s3, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::fma(s1, s2, s3, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMADD(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
static FORCE_INLINE execute_status execute_FMSUB_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmsub.s");
    auto note = a.make_scoped_note("fmsub.s");
    (void) note;
    return execute_float_ternary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t s3, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::fma(s1, s2, s3 ^ i_sfloat32::SIGN_MASK, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMSUB_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmsub.d");
    auto note = a.make_scoped_note("fmsub.d");
    (void) note;
    return execute_float_ternary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint64_t s3, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::fma(s1, s2, s3 ^ i_sfloat64::SIGN_MASK, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMSUB(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
static FORCE_INLINE execute_status execute_FNMADD_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fnmadd.s");
    auto note = a.make_scoped_note("fnmadd.s");
    (void) note;
    return execute_float_ternary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t s3, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::fma(s1 ^ i_sfloat32::SIGN_MASK, s2, s3 ^ i_sfloat32::SIGN_MASK,
                static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FNMADD_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fnmadd.d");
    auto note = a.make_scoped_note("fnmadd.d");
    (void) note;
    return execute_float_ternary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint64_t s3, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::fma(s1 ^ i_sfloat64::SIGN_MASK, s2, s3 ^ i_sfloat64::SIGN_MASK,
                static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FNMADD(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
static FORCE_INLINE execute_status execute_FNMSUB_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fnmsub.s");
    auto note = a.make_scoped_note("fnmsub.s");
    (void) note;
    return execute_float_ternary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t s3, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::fma(s1 ^ i_sfloat32::SIGN_MASK, s2, s3, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FNMSUB_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fnmsub.d");
    auto note = a.make_scoped_note("fnmsub.d");
    (void) note;
    return execute_float_ternary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint64_t s3, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::fma(s1 ^ i_sfloat64::SIGN_MASK, s2, s3, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FNMSUB(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
static FORCE_INLINE execute_status execute_FADD_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fadd.s");
    auto note = a.make_scoped_note("fadd.s");
    (void) note;
    return execute_float_binary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::add(s1, s2, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FADD_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fadd.d");
    auto note = a.make_scoped_note("fadd.d");
    (void) note;
    return execute_float_binary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::add(s1, s2, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSUB_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsub.s");
    auto note = a.make_scoped_note("fsub.s");
    (void) note;
    return execute_float_binary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::add(s1, s2 ^ i_sfloat32::SIGN_MASK, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSUB_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsub.d");
    auto note = a.make_scoped_note("fsub.d");
    (void) note;
    return execute_float_binary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::add(s1, s2 ^ i_sfloat64::SIGN_MASK, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMUL_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmul.s");
    auto note = a.make_scoped_note("fmul.s");
    (void) note;
    return execute_float_binary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::mul(s1, s2, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMUL_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmul.d");
    auto note = a.make_scoped_note("fmul.d");
    (void) note;
    return execute_float_binary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::mul(s1, s2, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FDIV_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fdiv.s");
    auto note = a.make_scoped_note("fdiv.s");
    (void) note;
    return execute_float_binary_op_rm<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return i_sfloat32::div(s1, s2, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FDIV_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fdiv.d");
    auto note = a.make_scoped_note("fdiv.d");
    (void) note;
    return execute_float_binary_op_rm<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint32_t rm, uint32_t *fflags) -> uint64_t {
            return i_sfloat64::div(s1, s2, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_FCLASS(STATE_ACCESS &a, uint64_t &pc, uint32_t insn, const F &f) {
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        // We must always check if input operands are properly NaN-boxed.
        T s1 = float_unbox<T>(a.read_f(insn_get_rs1(insn)));
        a.write_x(rd, f(s1));
    }
    return advance_to_next_insn(a, pc);
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_float_binary_op(STATE_ACCESS &a, uint64_t &pc, uint32_t insn, const F &f) {
    uint64_t fcsr = a.read_fcsr();
    // We must always check if input operands are properly NaN-boxed.
    T s1 = float_unbox<T>(a.read_f(insn_get_rs1(insn)));
    T s2 = float_unbox<T>(a.read_f(insn_get_rs2(insn)));
    uint32_t rd = insn_get_rd(insn);
    uint32_t fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
    // Must store a valid NaN-boxed value.
    a.write_f(rd, float_box(f(s1, s2, &fflags)));
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    return advance_to_next_insn(a, pc);
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_float_cmp_op(STATE_ACCESS &a, uint64_t &pc, uint32_t insn, const F &f) {
    uint64_t fcsr = a.read_fcsr();
    // We must always check if input operands are properly NaN-boxed.
    T s1 = float_unbox<T>(a.read_f(insn_get_rs1(insn)));
    T s2 = float_unbox<T>(a.read_f(insn_get_rs2(insn)));
    uint32_t rd = insn_get_rd(insn);
    uint32_t fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
    // Comparisons with NaNs may set NV (invalid operation) exception flag in fflags
    uint64_t val = f(s1, s2, &fflags);
    if (rd != 0) {
        a.write_x(rd, val);
    }
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGNJ_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsgnj.s");
    auto note = a.make_scoped_note("fsgnj.s");
    (void) note;
    return execute_float_binary_op<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, const uint32_t *fflags) -> uint32_t {
            (void) fflags;
            return (s1 & ~i_sfloat32::SIGN_MASK) | (s2 & i_sfloat32::SIGN_MASK);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGNJN_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsgnjn.s");
    auto note = a.make_scoped_note("fsgnjn.s");
    (void) note;
    return execute_float_binary_op<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, const uint32_t *fflags) -> uint32_t {
            (void) fflags;
            return (s1 & ~i_sfloat32::SIGN_MASK) | ((s2 & i_sfloat32::SIGN_MASK) ^ i_sfloat32::SIGN_MASK);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGNJX_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsgnjx.s");
    auto note = a.make_scoped_note("fsgnjx.s");
    (void) note;
    return execute_float_binary_op<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, const uint32_t *fflags) -> uint32_t {
            (void) fflags;
            return s1 ^ (s2 & i_sfloat32::SIGN_MASK);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGN_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
static FORCE_INLINE execute_status execute_FSGNJ_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsgnj.d");
    auto note = a.make_scoped_note("fsgnj.d");
    (void) note;
    return execute_float_binary_op<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, const uint32_t *fflags) -> uint64_t {
            (void) fflags;
            return (s1 & ~i_sfloat64::SIGN_MASK) | (s2 & i_sfloat64::SIGN_MASK);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGNJN_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsgnjn.d");
    auto note = a.make_scoped_note("fsgnjn.d");
    (void) note;
    return execute_float_binary_op<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, const uint32_t *fflags) -> uint64_t {
            (void) fflags;
            return (s1 & ~i_sfloat64::SIGN_MASK) | ((s2 & i_sfloat64::SIGN_MASK) ^ i_sfloat64::SIGN_MASK);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGNJX_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsgnjx.d");
    auto note = a.make_scoped_note("fsgnjx.d");
    (void) note;
    return execute_float_binary_op<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, const uint32_t *fflags) -> uint64_t {
            (void) fflags;
            return s1 ^ (s2 & i_sfloat64::SIGN_MASK);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSGN_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
static FORCE_INLINE execute_status execute_FMIN_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmin.s");
    auto note = a.make_scoped_note("fmin.s");
    (void) note;
    return execute_float_binary_op<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t *fflags) -> uint32_t { return i_sfloat32::min(s1, s2, fflags); });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMAX_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmax.s");
    auto note = a.make_scoped_note("fmax.s");
    (void) note;
    return execute_float_binary_op<uint32_t>(a, pc, insn,
        [](uint32_t s1, uint32_t s2, uint32_t *fflags) -> uint32_t { return i_sfloat32::max(s1, s2, fflags); });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMINMAX_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
static FORCE_INLINE execute_status execute_FMIN_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmin.d");
    auto note = a.make_scoped_note("fmin.d");
    (void) note;
    return execute_float_binary_op<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint32_t *fflags) -> uint64_t { return i_sfloat64::min(s1, s2, fflags); });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMAX_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmax.d");
    auto note = a.make_scoped_note("fmax.d");
    (void) note;
    return execute_float_binary_op<uint64_t>(a, pc, insn,
        [](uint64_t s1, uint64_t s2, uint32_t *fflags) -> uint64_t { return i_sfloat64::max(s1, s2, fflags); });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMINMAX_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
static FORCE_INLINE execute_status execute_FCVT_F_F(STATE_ACCESS &a, uint64_t &pc, uint32_t insn, const F &f) {
    uint64_t fcsr = a.read_fcsr();
    // The rounding mode comes from the insn
    uint32_t rm = insn_get_rm(insn);
    // Unless it is set to FRM_DYN, in which case it comes from fcsr.frm
    if (rm == FRM_DYN) {
        rm = fcsr >> FCSR_FRM_SHIFT;
    }
    // If the rounding mode is invalid, the instruction is considered illegal
    if (rm > FRM_RMM) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    uint32_t rd = insn_get_rd(insn);
    uint32_t fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
    // We must always check if input operands are properly NaN-boxed.
    ST s1 = float_unbox<ST>(a.read_f(insn_get_rs1(insn)));
    DT val = f(s1, rm, &fflags);
    // Must store a valid NaN-boxed value.
    a.write_f(rd, float_box(val));
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    return advance_to_next_insn(a, pc);
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_FCVT_X_F(STATE_ACCESS &a, uint64_t &pc, uint32_t insn, const F &f) {
    uint64_t fcsr = a.read_fcsr();
    // The rounding mode comes from the insn
    uint32_t rm = insn_get_rm(insn);
    // Unless it is set to FRM_DYN, in which case it comes from fcsr.frm
    if (rm == FRM_DYN) {
        rm = fcsr >> FCSR_FRM_SHIFT;
    }
    // If the rounding mode is invalid, the instruction is considered illegal
    if (rm > FRM_RMM) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    uint32_t rd = insn_get_rd(insn);
    uint32_t fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
    // We must always check if input operands are properly NaN-boxed.
    T s1 = float_unbox<T>(a.read_f(insn_get_rs1(insn)));
    uint64_t val = f(s1, rm, &fflags);
    if (rd != 0) {
        a.write_x(rd, val);
    }
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    return advance_to_next_insn(a, pc);
}

template <typename T, typename STATE_ACCESS, typename F>
static FORCE_INLINE execute_status execute_FCVT_F_X(STATE_ACCESS &a, uint64_t &pc, uint32_t insn, const F &f) {
    uint64_t fcsr = a.read_fcsr();
    // The rounding mode comes from the insn
    uint32_t rm = insn_get_rm(insn);
    // Unless it is set to FRM_DYN, in which case it comes from fcsr.frm
    if (rm == FRM_DYN) {
        rm = fcsr >> FCSR_FRM_SHIFT;
    }
    // If the rounding mode is invalid, the instruction is considered illegal
    if (rm > FRM_RMM) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    uint32_t rd = insn_get_rd(insn);
    uint32_t fflags = static_cast<uint32_t>(fcsr & FCSR_FFLAGS_RW_MASK);
    uint64_t s1 = a.read_x(insn_get_rs1(insn));
    T val = f(s1, rm, &fflags);
    // Must store a valid NaN-boxed value.
    a.write_f(rd, float_box(val));
    a.write_fcsr((fcsr & ~FCSR_FFLAGS_RW_MASK) | fflags);
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_S_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.s.d");
    auto note = a.make_scoped_note("fcvt.s.d");
    (void) note;
    return execute_FCVT_F_F<uint64_t, uint32_t>(a, pc, insn,
        [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint32_t {
            return sfloat_cvt_f64_f32(s1, static_cast<FRM_modes>(rm), fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_D_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.d.s");
    auto note = a.make_scoped_note("fcvt.d.s");
    (void) note;
    return execute_FCVT_F_F<uint32_t, uint64_t>(a, pc, insn,
        [](uint32_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
            // FCVT.D.S will never round, since it's a widen operation.
            (void) rm;
            return sfloat_cvt_f32_f64(s1, fflags);
        });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSQRT_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsqrt.s");
    auto note = a.make_scoped_note("fsqrt.s");
    (void) note;
    return execute_float_unary_op_rm<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t rm, uint32_t *fflags) -> uint32_t {
        return i_sfloat32::sqrt(s1, static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FSQRT_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fsqrt.d");
    auto note = a.make_scoped_note("fsqrt.d");
    (void) note;
    return execute_float_unary_op_rm<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        return i_sfloat64::sqrt(s1, static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FLE_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fle.s");
    auto note = a.make_scoped_note("fle.s");
    (void) note;
    return execute_float_cmp_op<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t s2, uint32_t *fflags) -> uint64_t {
        return static_cast<uint64_t>(i_sfloat32::le(s1, s2, fflags));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FLT_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "flt.s");
    auto note = a.make_scoped_note("flt.s");
    (void) note;
    return execute_float_cmp_op<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t s2, uint32_t *fflags) -> uint64_t {
        return static_cast<uint64_t>(i_sfloat32::lt(s1, s2, fflags));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FEQ_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "feq.s");
    auto note = a.make_scoped_note("feq.s");
    (void) note;
    return execute_float_cmp_op<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t s2, uint32_t *fflags) -> uint64_t {
        return static_cast<uint64_t>(i_sfloat32::eq(s1, s2, fflags));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCMP_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
static FORCE_INLINE execute_status execute_FLE_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fle.d");
    auto note = a.make_scoped_note("fle.d");
    (void) note;
    return execute_float_cmp_op<uint64_t>(a, pc, insn, [](uint64_t s1, uint64_t s2, uint32_t *fflags) -> uint64_t {
        return static_cast<uint64_t>(i_sfloat64::le(s1, s2, fflags));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FLT_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "flt.d");
    auto note = a.make_scoped_note("flt.d");
    (void) note;
    return execute_float_cmp_op<uint64_t>(a, pc, insn, [](uint64_t s1, uint64_t s2, uint32_t *fflags) -> uint64_t {
        return static_cast<uint64_t>(i_sfloat64::lt(s1, s2, fflags));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FEQ_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "feq.d");
    auto note = a.make_scoped_note("feq.d");
    (void) note;
    return execute_float_cmp_op<uint64_t>(a, pc, insn, [](uint64_t s1, uint64_t s2, uint32_t *fflags) -> uint64_t {
        return static_cast<uint64_t>(i_sfloat64::eq(s1, s2, fflags));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCMP_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
static FORCE_INLINE execute_status execute_FCVT_W_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.w.s");
    auto note = a.make_scoped_note("fcvt.w.s");
    (void) note;
    return execute_FCVT_X_F<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        int32_t val = i_sfloat32::cvt_f_i<int32_t>(s1, static_cast<FRM_modes>(rm), fflags);
        // For XLEN > 32, FCVT.W.S sign-extends the 32-bit result.
        return static_cast<uint64_t>(static_cast<int64_t>(val));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_WU_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.wu.s");
    auto note = a.make_scoped_note("fcvt.wu.s");
    (void) note;
    return execute_FCVT_X_F<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        uint32_t val = i_sfloat32::cvt_f_i<uint32_t>(s1, static_cast<FRM_modes>(rm), fflags);
        // For XLEN > 32, FCVT.WU.S sign-extends the 32-bit result.
        return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(val)));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_L_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.l.s");
    auto note = a.make_scoped_note("fcvt.l.s");
    (void) note;
    return execute_FCVT_X_F<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        int64_t val = i_sfloat32::cvt_f_i<int64_t>(s1, static_cast<FRM_modes>(rm), fflags);
        return static_cast<uint64_t>(val);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_LU_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.lu.s");
    auto note = a.make_scoped_note("fcvt.lu.s");
    (void) note;
    return execute_FCVT_X_F<uint32_t>(a, pc, insn, [](uint32_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        return i_sfloat32::cvt_f_i<uint64_t>(s1, static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_W_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.w.d");
    auto note = a.make_scoped_note("fcvt.w.d");
    (void) note;
    return execute_FCVT_X_F<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        int32_t val = i_sfloat64::cvt_f_i<int32_t>(s1, static_cast<FRM_modes>(rm), fflags);
        // For RV64, FCVT.W.D sign-extends the 32-bit result.
        return static_cast<uint64_t>(static_cast<int64_t>(val));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_WU_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.wu.d");
    auto note = a.make_scoped_note("fcvt.wu.d");
    (void) note;
    return execute_FCVT_X_F<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        uint32_t val = i_sfloat64::cvt_f_i<uint32_t>(s1, static_cast<FRM_modes>(rm), fflags);
        // For RV64, FCVT.WU.D sign-extends the 32-bit result.
        return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(val)));
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_L_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.l.d");
    auto note = a.make_scoped_note("fcvt.l.d");
    (void) note;
    return execute_FCVT_X_F<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        int64_t val = i_sfloat64::cvt_f_i<int64_t>(s1, static_cast<FRM_modes>(rm), fflags);
        return static_cast<uint64_t>(val);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_LU_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.lu.d");
    auto note = a.make_scoped_note("fcvt.lu.d");
    (void) note;
    return execute_FCVT_X_F<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        return i_sfloat64::cvt_f_i<uint64_t>(s1, static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_S_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.s.w");
    auto note = a.make_scoped_note("fcvt.s.w");
    (void) note;
    return execute_FCVT_F_X<uint32_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint32_t {
        return i_sfloat32::cvt_i_f(static_cast<int32_t>(s1), static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_S_WU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.s.wu");
    auto note = a.make_scoped_note("fcvt.s.wu");
    (void) note;
    return execute_FCVT_F_X<uint32_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint32_t {
        return i_sfloat32::cvt_i_f(static_cast<uint32_t>(s1), static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_S_L(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.s.l");
    auto note = a.make_scoped_note("fcvt.s.l");
    (void) note;
    return execute_FCVT_F_X<uint32_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint32_t {
        return i_sfloat32::cvt_i_f(static_cast<int64_t>(s1), static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_S_LU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.s.lu");
    auto note = a.make_scoped_note("fcvt.s.lu");
    (void) note;
    return execute_FCVT_F_X<uint32_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint32_t {
        return i_sfloat32::cvt_i_f(s1, static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_D_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.d.w");
    auto note = a.make_scoped_note("fcvt.d.w");
    (void) note;
    return execute_FCVT_F_X<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        return i_sfloat64::cvt_i_f(static_cast<int32_t>(s1), static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_D_WU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.d.wu");
    auto note = a.make_scoped_note("fcvt.d.wu");
    (void) note;
    return execute_FCVT_F_X<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        return i_sfloat64::cvt_i_f(static_cast<uint32_t>(s1), static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_D_L(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.d.l");
    auto note = a.make_scoped_note("fcvt.d.l");
    (void) note;
    return execute_FCVT_F_X<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        return i_sfloat64::cvt_i_f(static_cast<int64_t>(s1), static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCVT_D_LU(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fcvt.d.lu");
    auto note = a.make_scoped_note("fcvt.d.lu");
    (void) note;
    return execute_FCVT_F_X<uint64_t>(a, pc, insn, [](uint64_t s1, uint32_t rm, uint32_t *fflags) -> uint64_t {
        return i_sfloat64::cvt_i_f(s1, static_cast<FRM_modes>(rm), fflags);
    });
}

template <typename T, typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMV_F_X(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    // Should have rm set to 0
    if (unlikely(insn_get_rm(insn) != 0)) {
        return raise_illegal_insn_exception(a, pc, insn);
    }
    uint32_t rd = insn_get_rd(insn);
    // A narrower n-bit transfer, n < FLEN,
    // into the f registers will create a valid NaN-boxed value.
    a.write_f(rd, float_box(static_cast<T>(a.read_x(insn_get_rs1(insn)))));
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMV_W_X(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmv.w.x");
    auto note = a.make_scoped_note("fmv.w.x");
    (void) note;
    return execute_FMV_F_X<uint32_t>(a, pc, insn);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMV_D_X(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmv.d.x");
    auto note = a.make_scoped_note("fmv.d.x");
    (void) note;
    return execute_FMV_F_X<uint64_t>(a, pc, insn);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FCLASS_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fclass.s");
    auto note = a.make_scoped_note("fclass.s");
    (void) note;
    return execute_FCLASS<uint32_t>(a, pc, insn, [](uint32_t s1) -> uint64_t { return i_sfloat32::fclass(s1); });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMV_X_W(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmv.x.w");
    auto note = a.make_scoped_note("fmv.x.w");
    (void) note;
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        uint32_t val = static_cast<uint32_t>(a.read_f(insn_get_rs1(insn)));
        // For RV64, the higher 32 bits of the destination register are
        // filled with copies of the floating-point number’s sign bit.
        // We can perform this with a sign extension.
        a.write_x(rd, static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(val))));
    }
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMV_FCLASS_S(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
static FORCE_INLINE execute_status execute_FCLASS_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fclass.d");
    auto note = a.make_scoped_note("fclass.d");
    (void) note;
    return execute_FCLASS<uint64_t>(a, pc, insn, [](uint64_t s1) -> uint64_t { return i_sfloat64::fclass(s1); });
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMV_X_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    dump_insn(a, pc, insn, "fmv.x.d");
    auto note = a.make_scoped_note("fmv.x.d");
    (void) note;
    uint32_t rd = insn_get_rd(insn);
    if (rd != 0) {
        uint64_t val = a.read_f(insn_get_rs1(insn));
        a.write_x(rd, val);
    }
    return advance_to_next_insn(a, pc);
}

template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_FMV_FCLASS_D(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
static FORCE_INLINE execute_status execute_FCVT_FMV_FCLASS(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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
static FORCE_INLINE execute_status execute_FD(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
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

/// \brief Decodes and executes an instruction.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param pc Current pc.
/// \param insn Instruction.
/// \return execute_status::failure if an exception was raised, or
///  execute_status::success otherwise.
/// \details The execute_insn function decodes the instruction in multiple levels. When we know for sure that
///  the instruction could only be a &lt;FOO&gt;, a function with the name execute_&lt;FOO&gt; will be called.
///  See [RV32/64G Instruction Set
///  Listings](https://content.riscv.org/wp-content/uploads/2017/05/riscv-spec-v2.2.pdf#chapter.19) and [Instruction
///  listings for RISC-V](https://content.riscv.org/wp-content/uploads/2017/05/riscv-spec-v2.2.pdf#table.19.2).
template <typename STATE_ACCESS>
static FORCE_INLINE execute_status execute_insn(STATE_ACCESS &a, uint64_t &pc, uint32_t insn) {
    // std::cerr << "insn: " << std::bitset<32>(insn) << '\n';
    //??D We should probably try doing the first branch on the combined opcode, funct3, and funct7.
    //    Maybe it reduces the number of levels needed to decode most instructions.
    auto funct3_00000_opcode = static_cast<insn_funct3_00000_opcode>(insn_get_funct3_00000_opcode(insn));
    switch (funct3_00000_opcode) {
        case insn_funct3_00000_opcode::LB:
            return execute_LB(a, pc, insn);
        case insn_funct3_00000_opcode::LH:
            return execute_LH(a, pc, insn);
        case insn_funct3_00000_opcode::LW:
            return execute_LW(a, pc, insn);
        case insn_funct3_00000_opcode::LD:
            return execute_LD(a, pc, insn);
        case insn_funct3_00000_opcode::LBU:
            return execute_LBU(a, pc, insn);
        case insn_funct3_00000_opcode::LHU:
            return execute_LHU(a, pc, insn);
        case insn_funct3_00000_opcode::LWU:
            return execute_LWU(a, pc, insn);
        case insn_funct3_00000_opcode::SB:
            return execute_SB(a, pc, insn);
        case insn_funct3_00000_opcode::SH:
            return execute_SH(a, pc, insn);
        case insn_funct3_00000_opcode::SW:
            return execute_SW(a, pc, insn);
        case insn_funct3_00000_opcode::SD:
            return execute_SD(a, pc, insn);
        case insn_funct3_00000_opcode::FENCE:
            return execute_FENCE(a, pc, insn);
        case insn_funct3_00000_opcode::FENCE_I:
            return execute_FENCE_I(a, pc, insn);
        case insn_funct3_00000_opcode::ADDI:
            return execute_ADDI(a, pc, insn);
        case insn_funct3_00000_opcode::SLLI:
            return execute_SLLI(a, pc, insn);
        case insn_funct3_00000_opcode::SLTI:
            return execute_SLTI(a, pc, insn);
        case insn_funct3_00000_opcode::SLTIU:
            return execute_SLTIU(a, pc, insn);
        case insn_funct3_00000_opcode::XORI:
            return execute_XORI(a, pc, insn);
        case insn_funct3_00000_opcode::ORI:
            return execute_ORI(a, pc, insn);
        case insn_funct3_00000_opcode::ANDI:
            return execute_ANDI(a, pc, insn);
        case insn_funct3_00000_opcode::ADDIW:
            return execute_ADDIW(a, pc, insn);
        case insn_funct3_00000_opcode::SLLIW:
            return execute_SLLIW(a, pc, insn);
        case insn_funct3_00000_opcode::SLLW:
            return execute_SLLW(a, pc, insn);
        case insn_funct3_00000_opcode::DIVW:
            return execute_DIVW(a, pc, insn);
        case insn_funct3_00000_opcode::REMW:
            return execute_REMW(a, pc, insn);
        case insn_funct3_00000_opcode::REMUW:
            return execute_REMUW(a, pc, insn);
        case insn_funct3_00000_opcode::BEQ:
            return execute_BEQ(a, pc, insn);
        case insn_funct3_00000_opcode::BNE:
            return execute_BNE(a, pc, insn);
        case insn_funct3_00000_opcode::BLT:
            return execute_BLT(a, pc, insn);
        case insn_funct3_00000_opcode::BGE:
            return execute_BGE(a, pc, insn);
        case insn_funct3_00000_opcode::BLTU:
            return execute_BLTU(a, pc, insn);
        case insn_funct3_00000_opcode::BGEU:
            return execute_BGEU(a, pc, insn);
        case insn_funct3_00000_opcode::JALR:
            return execute_JALR(a, pc, insn);
        case insn_funct3_00000_opcode::CSRRW:
            return execute_CSRRW(a, pc, insn);
        case insn_funct3_00000_opcode::CSRRS:
            return execute_CSRRS(a, pc, insn);
        case insn_funct3_00000_opcode::CSRRC:
            return execute_CSRRC(a, pc, insn);
        case insn_funct3_00000_opcode::CSRRWI:
            return execute_CSRRWI(a, pc, insn);
        case insn_funct3_00000_opcode::CSRRSI:
            return execute_CSRRSI(a, pc, insn);
        case insn_funct3_00000_opcode::CSRRCI:
            return execute_CSRRCI(a, pc, insn);
        case insn_funct3_00000_opcode::AUIPC_000:
        case insn_funct3_00000_opcode::AUIPC_001:
        case insn_funct3_00000_opcode::AUIPC_010:
        case insn_funct3_00000_opcode::AUIPC_011:
        case insn_funct3_00000_opcode::AUIPC_100:
        case insn_funct3_00000_opcode::AUIPC_101:
        case insn_funct3_00000_opcode::AUIPC_110:
        case insn_funct3_00000_opcode::AUIPC_111:
            return execute_AUIPC(a, pc, insn);
        case insn_funct3_00000_opcode::LUI_000:
        case insn_funct3_00000_opcode::LUI_001:
        case insn_funct3_00000_opcode::LUI_010:
        case insn_funct3_00000_opcode::LUI_011:
        case insn_funct3_00000_opcode::LUI_100:
        case insn_funct3_00000_opcode::LUI_101:
        case insn_funct3_00000_opcode::LUI_110:
        case insn_funct3_00000_opcode::LUI_111:
            return execute_LUI(a, pc, insn);
        case insn_funct3_00000_opcode::JAL_000:
        case insn_funct3_00000_opcode::JAL_001:
        case insn_funct3_00000_opcode::JAL_010:
        case insn_funct3_00000_opcode::JAL_011:
        case insn_funct3_00000_opcode::JAL_100:
        case insn_funct3_00000_opcode::JAL_101:
        case insn_funct3_00000_opcode::JAL_110:
        case insn_funct3_00000_opcode::JAL_111:
            return execute_JAL(a, pc, insn);
        case insn_funct3_00000_opcode::SRLI_SRAI:
            return execute_SRLI_SRAI(a, pc, insn);
        case insn_funct3_00000_opcode::SRLIW_SRAIW:
            return execute_SRLIW_SRAIW(a, pc, insn);
        case insn_funct3_00000_opcode::AMO_W:
            return execute_AMO_W(a, pc, insn);
        case insn_funct3_00000_opcode::AMO_D:
            return execute_AMO_D(a, pc, insn);
        case insn_funct3_00000_opcode::ADD_MUL_SUB:
            return execute_ADD_MUL_SUB(a, pc, insn);
        case insn_funct3_00000_opcode::SLL_MULH:
            return execute_SLL_MULH(a, pc, insn);
        case insn_funct3_00000_opcode::SLT_MULHSU:
            return execute_SLT_MULHSU(a, pc, insn);
        case insn_funct3_00000_opcode::SLTU_MULHU:
            return execute_SLTU_MULHU(a, pc, insn);
        case insn_funct3_00000_opcode::XOR_DIV:
            return execute_XOR_DIV(a, pc, insn);
        case insn_funct3_00000_opcode::SRL_DIVU_SRA:
            return execute_SRL_DIVU_SRA(a, pc, insn);
        case insn_funct3_00000_opcode::OR_REM:
            return execute_OR_REM(a, pc, insn);
        case insn_funct3_00000_opcode::AND_REMU:
            return execute_AND_REMU(a, pc, insn);
        case insn_funct3_00000_opcode::ADDW_MULW_SUBW:
            return execute_ADDW_MULW_SUBW(a, pc, insn);
        case insn_funct3_00000_opcode::SRLW_DIVUW_SRAW:
            return execute_SRLW_DIVUW_SRAW(a, pc, insn);
        case insn_funct3_00000_opcode::privileged:
            return execute_privileged(a, pc, insn);
        default: {
            // Here we are sure that the next instruction, at best, can only be a floating point instruction,
            // or, at worst, an illegal instruction.
            // Since all float instructions try to read the float state,
            // we can put the next check before all of them.
            // If FS is OFF, attempts to read or write the float state will cause an illegal instruction exception.
            if (unlikely((a.read_mstatus() & MSTATUS_FS_MASK) == MSTATUS_FS_OFF)) {
                return raise_illegal_insn_exception(a, pc, insn);
            }
            switch (funct3_00000_opcode) {
                case insn_funct3_00000_opcode::FSW:
                    return execute_FSW(a, pc, insn);
                case insn_funct3_00000_opcode::FSD:
                    return execute_FSD(a, pc, insn);
                case insn_funct3_00000_opcode::FLW:
                    return execute_FLW(a, pc, insn);
                case insn_funct3_00000_opcode::FLD:
                    return execute_FLD(a, pc, insn);
                case insn_funct3_00000_opcode::FMADD_RNE:
                case insn_funct3_00000_opcode::FMADD_RTZ:
                case insn_funct3_00000_opcode::FMADD_RDN:
                case insn_funct3_00000_opcode::FMADD_RUP:
                case insn_funct3_00000_opcode::FMADD_RMM:
                case insn_funct3_00000_opcode::FMADD_DYN:
                    return execute_FMADD(a, pc, insn);
                case insn_funct3_00000_opcode::FMSUB_RNE:
                case insn_funct3_00000_opcode::FMSUB_RTZ:
                case insn_funct3_00000_opcode::FMSUB_RDN:
                case insn_funct3_00000_opcode::FMSUB_RUP:
                case insn_funct3_00000_opcode::FMSUB_RMM:
                case insn_funct3_00000_opcode::FMSUB_DYN:
                    return execute_FMSUB(a, pc, insn);
                case insn_funct3_00000_opcode::FNMSUB_RNE:
                case insn_funct3_00000_opcode::FNMSUB_RTZ:
                case insn_funct3_00000_opcode::FNMSUB_RDN:
                case insn_funct3_00000_opcode::FNMSUB_RUP:
                case insn_funct3_00000_opcode::FNMSUB_RMM:
                case insn_funct3_00000_opcode::FNMSUB_DYN:
                    return execute_FNMSUB(a, pc, insn);
                case insn_funct3_00000_opcode::FNMADD_RNE:
                case insn_funct3_00000_opcode::FNMADD_RTZ:
                case insn_funct3_00000_opcode::FNMADD_RDN:
                case insn_funct3_00000_opcode::FNMADD_RUP:
                case insn_funct3_00000_opcode::FNMADD_RMM:
                case insn_funct3_00000_opcode::FNMADD_DYN:
                    return execute_FNMADD(a, pc, insn);
                case insn_funct3_00000_opcode::FD_000:
                case insn_funct3_00000_opcode::FD_001:
                case insn_funct3_00000_opcode::FD_010:
                case insn_funct3_00000_opcode::FD_011:
                case insn_funct3_00000_opcode::FD_100:
                case insn_funct3_00000_opcode::FD_111:
                    return execute_FD(a, pc, insn);
                default:
                    return raise_illegal_insn_exception(a, pc, insn);
            }
        }
    }
}

/// \brief Instruction fetch status code
enum class fetch_status : int {
    exception, ///< Instruction fetch failed: exception raised
    success    ///< Instruction fetch succeeded: proceed to execute
};

/// \brief Loads the next instruction (slow path that goes through virtual address translation).
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param vaddr Virtual address for the instruction.
/// \param pinsn Receives fetched instruction.
/// \return Returns fetch_status::success if load succeeded, fetch_status::exception if it caused an exception.
//          In that case, raise the exception.
template <typename STATE_ACCESS>
static FORCE_INLINE fetch_status fetch_insn_slow(STATE_ACCESS &a, uint64_t &pc, uint32_t *pinsn) {
    //??E Unlikely other slow functions, this one is not outlined,
    //    because outlining it can actually degrade performance,
    //    we should change this in the future in case we implement fetch instruction page cache.
    uint64_t paddr{};
    // Walk page table and obtain the physical address
    if (unlikely(!translate_virtual_address(a, &paddr, pc, PTE_XWR_C_SHIFT))) {
        pc = raise_exception(a, pc, MCAUSE_FETCH_PAGE_FAULT, pc);
        return fetch_status::exception;
    }
    // Walk memory map to find the range that contains the physical address
    auto &pma = a.template find_pma_entry<uint32_t>(paddr);
    // We only execute directly from RAM (as in "random access memory", which includes ROM)
    // If the range is not memory or not executable, this as a PMA violation
    if (unlikely(!pma.get_istart_M() || !pma.get_istart_X())) {
        pc = raise_exception(a, pc, MCAUSE_INSN_ACCESS_FAULT, pc);
        return fetch_status::exception;
    }
    unsigned char *hpage = a.template replace_tlb_entry<TLB_CODE>(pc, paddr, pma);
    uint64_t hoffset = pc & PAGE_OFFSET_MASK;
    a.read_memory_word(paddr, hpage, hoffset, pinsn);
    return fetch_status::success;
}

/// \brief Loads the next instruction.
/// \tparam STATE_ACCESS Class of machine state accessor object.
/// \param a Machine state accessor object.
/// \param vaddr Virtual address for the instruction.
/// \param pinsn Receives fetched instruction.
/// \return Returns fetch_status::success if load succeeded, fetch_status::exception if it caused an exception.
//          In that case, raise the exception.
template <typename STATE_ACCESS>
static FORCE_INLINE fetch_status fetch_insn(STATE_ACCESS &a, uint64_t &pc, uint32_t *pinsn) {
    auto note = a.make_scoped_note("fetch_insn");
    (void) note;
    // Try hitting the TLB
    if (unlikely(!(a.template read_memory_word_via_tlb<TLB_CODE>(pc, pinsn)))) {
        INC_COUNTER(a.get_statistics(), tlb_cmiss);
        // Outline the slow path into a function call to minimize host CPU code cache pressure
        return fetch_insn_slow(a, pc, pinsn);
    }
    INC_COUNTER(a.get_statistics(), tlb_chit);
    return fetch_status::success;
}

/// \brief Checks that false brk is consistent with rest of state
template <typename STATE_ACCESS>
static void assert_no_brk(STATE_ACCESS &a) {
    assert(get_pending_irq_mask(a) == 0);
    assert(a.read_iflags_X() == 0);
    assert(a.read_iflags_Y() == 0);
    assert(a.read_iflags_H() == 0);
}

/// \brief Interpreter hot loop
template <typename STATE_ACCESS>
NO_INLINE void interpret_loop(STATE_ACCESS &a, uint64_t mcycle_end, uint64_t mcycle) {
    // Read machine program counter
    uint64_t pc = a.read_pc();

    // The outer loop continues until there is an interruption that should be handled
    // externally, or mcycle reaches mcycle_end
    while (mcycle < mcycle_end) {
        INC_COUNTER(a.get_statistics(), outer_loop);

        // Set interrupt flag for RTC
        set_rtc_interrupt(a, mcycle);

        // Raise the highest priority pending interrupt, if any
        pc = raise_interrupt_if_any(a, pc);
        a.write_pc(pc);

#ifndef NDEBUG
        // After raising any exception for a given interrupt, we expect no pending break
        assert_no_brk(a);
#endif

        // Limit mcycle_tick_end up to the next RTC tick, while avoiding unsigned overflows
        uint64_t mcycle_tick_end = mcycle + std::min(mcycle_end - mcycle, RTC_FREQ_DIV - mcycle % RTC_FREQ_DIV);

        // The inner loop continues until there is an interrupt condition
        // or mcycle reaches mcycle_tick_end
        while (mcycle < mcycle_tick_end) {
            INC_COUNTER(a.get_statistics(), inner_loop);

            uint32_t insn = 0;

            // Try to fetch the next instruction
            if (likely(fetch_insn(a, pc, &insn) == fetch_status::success)) {
                // Try to execute it
                execute_status status = execute_insn(a, pc, insn);

                // Break from the inner/outer loop when an interruption is requested
                if (status >= execute_status::success_and_break_inner_loop) {
                    // Increment the cycle counter mcycle
                    // we have to read mcycle again before incrementing it,
                    // because HTIF console poll can overwrite mcycle while in interactive mode
                    mcycle = a.read_mcycle() + 1;

                    // Commit machine state
                    a.write_pc(pc);
                    a.write_mcycle(mcycle);

                    if (unlikely(status == execute_status::success_and_break_outer_loop)) {
                        // Got an interruption that must be handled externally, such as halt or yield
                        return;
                    }
                    // Got an interruption that should be handled internally, such as timer interruption
                    break;
                }
            }

            // Increment the cycle counter mcycle
            ++mcycle;

            // Commit machine state
            a.write_pc(pc);
            a.write_mcycle(mcycle);

#ifndef NDEBUG
            // After a inner loop iteration, there can be no pending interrupts
            assert_no_brk(a);
#endif
        }
    }
}

template <typename STATE_ACCESS>
interpreter_break_reason interpret(STATE_ACCESS &a, uint64_t mcycle_end) {
    static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "code assumes little-endian byte ordering");
    static_assert(is_an_i_state_access<STATE_ACCESS>::value, "not an i_state_access");

    // This must be the first read because we assume the first log access is a
    // mcycle read in machine::verify_state_transition
    uint64_t mcycle = a.read_mcycle();

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
    a.reset_iflags_X();

    // Run the interpreter loop,
    // the loop is outlined in a dedicated function so the compiler can optimize it better
    interpret_loop(a, mcycle_end, mcycle);

    // Detect and return the reason for stopping the interpreter loop
    if (a.read_iflags_H()) {
        return interpreter_break_reason::halted;
    } else if (a.read_iflags_Y()) {
        return interpreter_break_reason::yielded_manually;
    } else if (a.read_iflags_X()) {
        return interpreter_break_reason::yielded_automatically;
    } else { // Reached mcycle_end
        assert(a.read_mcycle() == mcycle_end);
        return interpreter_break_reason::reached_target_mcycle;
    }
}

#ifdef MICROARCHITECTURE
template interpreter_break_reason interpret(uarch_machine_state_access &a, uint64_t mcycle_end);
#else
// Explicit instantiation for state_access
template interpreter_break_reason interpret(state_access &a, uint64_t mcycle_end);
#endif // MICROARCHITECTURE

} // namespace cartesi
