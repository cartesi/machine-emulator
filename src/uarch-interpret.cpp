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

#include <boost/container/static_vector.hpp>
#include <cinttypes>
#include <cstdio>

#include "riscv-constants.h"
#include "uarch-constants.h"
#include "uarch-interpret.h"

namespace cartesi {

enum class uarch_execute_status : int {
    success, // instruction executed successfully
    halt     // instruction executed successfully and halted the microinterpreter
};
using execute_status = uarch_execute_status;

// Operand decoders

static inline uint8_t operand_rd(uint32_t insn) {
    return (insn << 20) >> 27;
}

static inline uint8_t operand_rs1(uint32_t insn) {
    return (insn << 12) >> 27;
}

static inline uint8_t operand_rs2(uint32_t insn) {
    return (insn << 7) >> 27;
}

static inline int operand_imm12(uint32_t insn) {
    return static_cast<int>(insn) >> 20;
}

static inline int operand_imm20(uint32_t insn) {
    return (static_cast<int>(insn) >> 12) << 12;
}

static inline int operand_jimm20(uint32_t insn) {
    return static_cast<int>((static_cast<int>(insn) >> 31) << 20 | ((insn << 1) >> 22) << 1 |
        ((insn << 11) >> 31) << 11 | ((insn << 12) >> 24) << 12);
}

static inline int operand_shamt5(uint32_t insn) {
    return static_cast<int>((insn << 7) >> 27);
}

static inline int operand_shamt6(uint32_t insn) {
    return static_cast<int>((insn << 6) >> 26);
}

static inline int operand_sbimm12(uint32_t insn) {
    return static_cast<int>((static_cast<int>(insn) >> 31) << 12 | ((insn << 1) >> 26) << 5 |
        ((insn << 20) >> 28) << 1 | ((insn << 24) >> 31) << 11);
}

static inline int operand_simm12(uint32_t insn) {
    return static_cast<int>((static_cast<int>(insn) >> 25) << 5 | (insn << 20) >> 27);
}

struct decoded_insn {
    const uint32_t insn;
    const int32_t imm;
    const uint8_t rd;
    const uint8_t rs1;
    const uint8_t rs2;
};

// Instruction decoders - decode all operands into `decoded_insn`

static inline decoded_insn decode_s(uint32_t insn) {
    return decoded_insn{
        insn,                 // instruction
        operand_simm12(insn), // imm
        0,                    // rd
        operand_rs1(insn),    // rs1
        operand_rs2(insn)     // rs2
    };
}

static inline decoded_insn decode_i_l(uint32_t insn) {
    return decoded_insn{
        insn,
        operand_imm12(insn), // imm
        operand_rd(insn),    // rd
        operand_rs1(insn),   // rs1
        0                    // rs2
    };
}

static inline decoded_insn decode_i_sh5(uint32_t insn) {
    return decoded_insn{
        insn,
        operand_shamt5(insn), // imm
        operand_rd(insn),     // rd
        operand_rs1(insn),    // rs1
        0                     // rs2
    };
}

static inline decoded_insn decode_i_sh6(uint32_t insn) {
    return decoded_insn{
        insn,
        operand_shamt6(insn), // imm
        operand_rd(insn),     // rd
        operand_rs1(insn),    // rs1
        0                     // rs2
    };
}

static inline decoded_insn decode_ir(uint32_t insn) {
    return decoded_insn{
        insn,
        0,                 // imm
        operand_rd(insn),  // rd
        operand_rs1(insn), // rs1
        operand_rs2(insn)  // rs2
    };
}

static inline decoded_insn decode_is(uint32_t insn) {
    return decoded_insn{
        insn,
        operand_simm12(insn), // imm
        0,                    // rd
        operand_rs1(insn),    // rs1
        operand_rs2(insn)     // rs2
    };
}

static inline decoded_insn decode_isb(uint32_t insn) {
    return decoded_insn{
        insn,
        operand_sbimm12(insn), // imm
        0,                     // rd
        operand_rs1(insn),     // rs1
        operand_rs2(insn)      // rs2
    };
}

static inline decoded_insn decode_iu(uint32_t insn) {
    return decoded_insn{
        insn,
        operand_imm20(insn), // imm
        operand_rd(insn),    // rd
        0,                   // rs1
        0                    // rs2
    };
}

static inline decoded_insn decode_iuj(uint32_t insn) {
    return decoded_insn{
        insn,
        operand_jimm20(insn), // imm
        operand_rd(insn),     // rd
        0,                    // rs1
        0                     // rs2
    };
}

static inline decoded_insn decode_nothing(uint32_t insn) {
    return decoded_insn{
        insn,
        0, // imm
        0, // rd
        0, // rs1
        0, // rs2
    };
}

// Execute instruction

template <typename STATE_ACCESS>
static inline execute_status write_pc(STATE_ACCESS &a, uint64_t new_pc) {
    a.write_pc(new_pc);
    if (new_pc == PMA_UARCH_ROM_START) {
        return execute_status::halt;
    }
    return execute_status::success;
}

template <typename STATE_ACCESS>
static inline execute_status advance_pc(STATE_ACCESS &a, uint64_t pc) {
    uint64_t new_pc = pc + 4;
    return write_pc(a, new_pc);
}

template <typename STATE_ACCESS>
static inline execute_status branch(STATE_ACCESS &a, uint64_t new_pc) {
    return write_pc(a, new_pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_LUI(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("lui");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_AUIPC(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("auipc");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_pc() + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_JAL(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("jal");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, pc + 4);
    }
    return branch(a, a.read_pc() + d.imm);
}

template <typename STATE_ACCESS>
static inline execute_status execute_JALR(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("jalr");
    (void) note;
    auto rs1 = a.read_x(d.rs1);
    if (d.rd != 0) {
        a.write_x(d.rd, pc + 4);
    }
    return branch(a, rs1 + d.imm);
}

template <typename STATE_ACCESS>
static inline execute_status execute_BEQ(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("beq");
    (void) note;
    if (a.read_x(d.rs1) == a.read_x(d.rs2)) {
        return branch(a, a.read_pc() + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_BNE(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("bne");
    (void) note;
    if (a.read_x(d.rs1) != a.read_x(d.rs2)) {
        return branch(a, a.read_pc() + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_BLT(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("blt");
    (void) note;
    if (static_cast<int64_t>(a.read_x(d.rs1)) < static_cast<int64_t>(a.read_x(d.rs2))) {
        return branch(a, a.read_pc() + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_BGE(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("bge");
    (void) note;
    if (static_cast<int64_t>(a.read_x(d.rs1)) >= static_cast<int64_t>(a.read_x(d.rs2))) {
        return branch(a, a.read_pc() + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_BLTU(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("bltu");
    (void) note;
    if (a.read_x(d.rs1) < a.read_x(d.rs2)) {
        return branch(a, a.read_pc() + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_BGEU(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("bgeu");
    (void) note;
    if (a.read_x(d.rs1) >= a.read_x(d.rs2)) {
        return branch(a, a.read_pc() + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_LB(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("lb");
    (void) note;
    int8_t i8 = 0;
    a.read_word(a.read_x(d.rs1) + d.imm, &i8);
    if (d.rd != 0) {
        a.write_x(d.rd, i8);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_LHU(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("lhu");
    (void) note;
    uint16_t u16 = 0;
    a.read_word(a.read_x(d.rs1) + d.imm, &u16);
    if (d.rd != 0) {
        a.write_x(d.rd, u16);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_LH(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("lh");
    (void) note;
    int16_t i16 = 0;
    a.read_word(a.read_x(d.rs1) + d.imm, &i16);
    if (d.rd != 0) {
        a.write_x(d.rd, i16);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_LW(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("lw");
    (void) note;
    int32_t i32 = 0;
    a.read_word(a.read_x(d.rs1) + d.imm, &i32); // sign promotion
    if (d.rd != 0) {
        a.write_x(d.rd, i32);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_LBU(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("lbu");
    (void) note;
    uint8_t u8 = 0;
    a.read_word(a.read_x(d.rs1) + d.imm, &u8);
    if (d.rd != 0) {
        a.write_x(d.rd, u8);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SB(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("sb");
    (void) note;
    a.write_word(a.read_x(d.rs1) + d.imm, static_cast<uint8_t>(a.read_x(d.rs2)));
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SH(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("sh");
    (void) note;
    a.write_word(a.read_x(d.rs1) + d.imm, static_cast<uint16_t>(a.read_x(d.rs2)));
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SW(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("sw");
    (void) note;
    a.write_word(a.read_x(d.rs1) + d.imm, static_cast<uint32_t>(a.read_x(d.rs2)));
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_ADDI(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("addi");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_ADDIW(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("addiw");
    (void) note;
    auto rs1 = static_cast<int>(a.read_x(d.rs1));
    if (d.rd != 0) {
        a.write_x(d.rd, rs1 + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLTI(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("slti");
    (void) note;
    if (d.rd != 0) {
        if (static_cast<int64_t>(a.read_x(d.rs1)) < d.imm) {
            a.write_x(d.rd, 1);
        } else {
            a.write_x(d.rd, 0);
        }
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLTIU(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("sltiu");
    (void) note;
    if (d.rd != 0) {
        if (a.read_x(d.rs1) < static_cast<uint64_t>(d.imm)) {
            a.write_x(d.rd, 1);
        } else {
            a.write_x(d.rd, 0);
        }
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_XORI(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("xori");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) ^ d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_ORI(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("ori");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) | d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_ANDI(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("andi");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) & d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLLI(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("slli");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) << d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLLIW(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("slliw");
    (void) note;
    auto rs1 = static_cast<int>(a.read_x(d.rs1));
    if (d.rd != 0) {
        a.write_x(d.rd, rs1 << d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRLI(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("srli");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) >> d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRLW(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("srlw");
    (void) note;
    auto rs1 = static_cast<uint32_t>(a.read_x(d.rs1));
    int32_t rd = rs1 >> a.read_x(d.rs2);
    if (d.rd != 0) {
        a.write_x(d.rd, rd);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRLIW(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("srliw");
    (void) note;
    auto rs1 = static_cast<uint32_t>(a.read_x(d.rs1));
    auto rd = static_cast<int>(rs1 >> d.imm);
    if (d.rd != 0) {
        a.write_x(d.rd, rd);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRAI(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("srai");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, static_cast<int64_t>(a.read_x(d.rs1)) >> d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRAIW(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("sraiw");
    (void) note;
    auto rs1 = static_cast<int>(a.read_x(d.rs1));
    if (d.rd != 0) {
        a.write_x(d.rd, static_cast<int>(rs1) >> d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_ADD(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("add");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) + a.read_x(d.rs2));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_ADDW(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("addw");
    (void) note;
    auto rs1 = static_cast<int>(a.read_x(d.rs1));
    auto rs2 = static_cast<int>(a.read_x(d.rs2));
    if (d.rd != 0) {
        a.write_x(d.rd, rs1 + rs2);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SUB(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("sub");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) - a.read_x(d.rs2));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SUBW(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("subw");
    (void) note;
    auto rs1 = static_cast<int>(a.read_x(d.rs1));
    auto rs2 = static_cast<int>(a.read_x(d.rs2));
    if (d.rd != 0) {
        a.write_x(d.rd, rs1 - rs2);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLL(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("sll");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, static_cast<int64_t>(a.read_x(d.rs1)) << static_cast<int64_t>(a.read_x(d.rs2)));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLLW(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("sllw");
    (void) note;
    auto rs1 = static_cast<int>(a.read_x(d.rs1));
    auto rs2 = static_cast<int>(a.read_x(d.rs2));
    int32_t rd = rs1 << rs2;
    if (d.rd != 0) {
        a.write_x(d.rd, rd);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLT(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("slt");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, static_cast<int64_t>(a.read_x(d.rs1)) < static_cast<int64_t>(a.read_x(d.rs2)) ? 1 : 0);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SLTU(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("sltu");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) < a.read_x(d.rs2) ? 1 : 0);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_XOR(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("xor");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) ^ a.read_x(d.rs2));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRL(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("srl");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) >> a.read_x(d.rs2));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRA(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("sra");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, static_cast<int64_t>(a.read_x(d.rs1)) >> a.read_x(d.rs2));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_SRAW(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("sraw");
    (void) note;
    auto rs1 = static_cast<int>(a.read_x(d.rs1));
    auto rs2 = static_cast<int>(a.read_x(d.rs2));
    int32_t rd = static_cast<int>(rs1) >> rs2;
    if (d.rd != 0) {
        a.write_x(d.rd, rd);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline execute_status execute_OR(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("or");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) | a.read_x(d.rs2));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static execute_status execute_AND(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("and");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) & a.read_x(d.rs2));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static execute_status execute_FENCE(STATE_ACCESS &a, const decoded_insn &, uint64_t pc) {
    auto note = a.make_scoped_note("fence");
    (void) note;
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static execute_status execute_LWU(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("lwu");
    (void) note;
    uint32_t u32 = 0;
    a.read_word(a.read_x(d.rs1) + d.imm, &u32); // sign promotion
    if (d.rd != 0) {
        a.write_x(d.rd, u32);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static execute_status execute_LD(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("ld");
    (void) note;
    uint64_t u64 = 0;
    a.read_word(a.read_x(d.rs1) + d.imm, &u64);
    if (d.rd != 0) {
        a.write_x(d.rd, u64);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static execute_status execute_SD(STATE_ACCESS &a, const decoded_insn &d, uint64_t pc) {
    auto note = a.make_scoped_note("sd");
    (void) note;
    a.write_word(a.read_x(d.rs1) + d.imm, a.read_x(d.rs2));
    return advance_pc(a, pc);
}

using decode_fn = decoded_insn (*)(uint32_t);

#include "clint.h"

template <typename STATE_ACCESS>
static inline void fetch_insn(STATE_ACCESS &a, uint64_t *pc, uint32_t *insn) {
    *pc = a.read_pc();
    a.read_word(*pc, insn);
}

/// \brief Obtains the funct3 and opcode fields an instruction.
/// \param insn Instruction.
static inline uint32_t insn_get_funct3_00000_opcode(uint32_t insn) {
    return insn & 0b111000001111111;
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

// Decode and execute one instruction
template <typename STATE_ACCESS>
static inline execute_status execute_insn(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    switch (static_cast<insn_funct3_00000_opcode>(insn_get_funct3_00000_opcode(insn))) {
        case insn_funct3_00000_opcode::LB:
            return execute_LB(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::LH:
            return execute_LH(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::LW:
            return execute_LW(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::LD:
            return execute_LD(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::LBU:
            return execute_LBU(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::LHU:
            return execute_LHU(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::LWU:
            return execute_LWU(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::SB:
            return execute_SB(a, decode_is(insn), pc);
        case insn_funct3_00000_opcode::SH:
            return execute_SH(a, decode_is(insn), pc);
        case insn_funct3_00000_opcode::SW:
            return execute_SW(a, decode_is(insn), pc);
        case insn_funct3_00000_opcode::SD:
            return execute_SD(a, decode_s(insn), pc);
        case insn_funct3_00000_opcode::FENCE:
            return execute_FENCE(a, decode_nothing(insn), pc);
        case insn_funct3_00000_opcode::ADDI:
            return execute_ADDI(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::SLLI:
            return execute_SLLI(a, decode_i_sh6(insn), pc);
        case insn_funct3_00000_opcode::SLTI:
            return execute_SLTI(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::SLTIU:
            return execute_SLTIU(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::XORI:
            return execute_XORI(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::ORI:
            return execute_ORI(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::ANDI:
            return execute_ANDI(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::ADDIW:
            return execute_ADDIW(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::SLLIW:
            return execute_SLLIW(a, decode_i_sh5(insn), pc);
        case insn_funct3_00000_opcode::SLLW:
            return execute_SLLW(a, decode_ir(insn), pc);
        case insn_funct3_00000_opcode::BEQ:
            return execute_BEQ(a, decode_isb(insn), pc);
        case insn_funct3_00000_opcode::BNE:
            return execute_BNE(a, decode_isb(insn), pc);
        case insn_funct3_00000_opcode::BLT:
            return execute_BLT(a, decode_isb(insn), pc);
        case insn_funct3_00000_opcode::BGE:
            return execute_BGE(a, decode_isb(insn), pc);
        case insn_funct3_00000_opcode::BLTU:
            return execute_BLTU(a, decode_isb(insn), pc);
        case insn_funct3_00000_opcode::BGEU:
            return execute_BGEU(a, decode_isb(insn), pc);
        case insn_funct3_00000_opcode::JALR:
            return execute_JALR(a, decode_i_l(insn), pc);
        case insn_funct3_00000_opcode::AUIPC_000:
        case insn_funct3_00000_opcode::AUIPC_001:
        case insn_funct3_00000_opcode::AUIPC_010:
        case insn_funct3_00000_opcode::AUIPC_011:
        case insn_funct3_00000_opcode::AUIPC_100:
        case insn_funct3_00000_opcode::AUIPC_101:
        case insn_funct3_00000_opcode::AUIPC_110:
        case insn_funct3_00000_opcode::AUIPC_111:
            return execute_AUIPC(a, decode_iu(insn), pc);
        case insn_funct3_00000_opcode::LUI_000:
        case insn_funct3_00000_opcode::LUI_001:
        case insn_funct3_00000_opcode::LUI_010:
        case insn_funct3_00000_opcode::LUI_011:
        case insn_funct3_00000_opcode::LUI_100:
        case insn_funct3_00000_opcode::LUI_101:
        case insn_funct3_00000_opcode::LUI_110:
        case insn_funct3_00000_opcode::LUI_111:
            return execute_LUI(a, decode_iu(insn), pc);
        case insn_funct3_00000_opcode::JAL_000:
        case insn_funct3_00000_opcode::JAL_001:
        case insn_funct3_00000_opcode::JAL_010:
        case insn_funct3_00000_opcode::JAL_011:
        case insn_funct3_00000_opcode::JAL_100:
        case insn_funct3_00000_opcode::JAL_101:
        case insn_funct3_00000_opcode::JAL_110:
        case insn_funct3_00000_opcode::JAL_111:
            return execute_JAL(a, decode_iuj(insn), pc);
        case insn_funct3_00000_opcode::SRLI_SRAI:
            switch (static_cast<insn_SRLI_SRAI_funct7_sr1>(insn_get_funct7_sr1(insn))) {
                case insn_SRLI_SRAI_funct7_sr1::SRLI:
                    return execute_SRLI(a, decode_i_sh6(insn), pc);
                case insn_SRLI_SRAI_funct7_sr1::SRAI:
                    return execute_SRAI(a, decode_i_sh6(insn), pc);
                default:
                    break;
            }
            break;
        case insn_funct3_00000_opcode::SRLIW_SRAIW:
            switch (static_cast<insn_SRLIW_SRAIW_funct7>(insn_get_funct7(insn))) {
                case insn_SRLIW_SRAIW_funct7::SRLIW:
                    return execute_SRLIW(a, decode_i_sh5(insn), pc);
                case insn_SRLIW_SRAIW_funct7::SRAIW:
                    return execute_SRAIW(a, decode_i_sh5(insn), pc);
                default:
                    break;
            }
            break;
        case insn_funct3_00000_opcode::ADD_MUL_SUB:
            switch (static_cast<insn_ADD_MUL_SUB_funct7>(insn_get_funct7(insn))) {
                case insn_ADD_MUL_SUB_funct7::ADD:
                    return execute_ADD(a, decode_ir(insn), pc);
                case insn_ADD_MUL_SUB_funct7::SUB:
                    return execute_SUB(a, decode_ir(insn), pc);
                default:
                    break;
            }
            break;
        case insn_funct3_00000_opcode::SLL_MULH:
            switch (static_cast<insn_SLL_MULH_funct7>(insn_get_funct7(insn))) {
                case insn_SLL_MULH_funct7::SLL:
                    return execute_SLL(a, decode_ir(insn), pc);
                default:
                    break;
            }
            break;
        case insn_funct3_00000_opcode::SLT_MULHSU:
            switch (static_cast<insn_SLT_MULHSU_funct7>(insn_get_funct7(insn))) {
                case insn_SLT_MULHSU_funct7::SLT:
                    return execute_SLT(a, decode_ir(insn), pc);
                default:
                    break;
            }
            break;
        case insn_funct3_00000_opcode::SLTU_MULHU:
            switch (static_cast<insn_SLTU_MULHU_funct7>(insn_get_funct7(insn))) {
                case insn_SLTU_MULHU_funct7::SLTU:
                    return execute_SLTU(a, decode_ir(insn), pc);
                default:
                    break;
            }
            break;
        case insn_funct3_00000_opcode::XOR_DIV:
            switch (static_cast<insn_XOR_DIV_funct7>(insn_get_funct7(insn))) {
                case insn_XOR_DIV_funct7::XOR:
                    return execute_XOR(a, decode_ir(insn), pc);
                default:
                    break;
            }
            break;
        case insn_funct3_00000_opcode::SRL_DIVU_SRA:
            switch (static_cast<insn_SRL_DIVU_SRA_funct7>(insn_get_funct7(insn))) {
                case insn_SRL_DIVU_SRA_funct7::SRL:
                    return execute_SRL(a, decode_ir(insn), pc);
                case insn_SRL_DIVU_SRA_funct7::SRA:
                    return execute_SRA(a, decode_ir(insn), pc);
                default:
                    break;
            }
            break;
        case insn_funct3_00000_opcode::OR_REM:
            switch (static_cast<insn_OR_REM_funct7>(insn_get_funct7(insn))) {
                case insn_OR_REM_funct7::OR:
                    return execute_OR(a, decode_ir(insn), pc);
                default:
                    break;
            }
            break;
        case insn_funct3_00000_opcode::AND_REMU:
            switch (static_cast<insn_AND_REMU_funct7>(insn_get_funct7(insn))) {
                case insn_AND_REMU_funct7::AND:
                    return execute_AND(a, decode_ir(insn), pc);
                default:
                    break;
            }
            break;
        case insn_funct3_00000_opcode::ADDW_MULW_SUBW:
            switch (static_cast<insn_ADDW_MULW_SUBW_funct7>(insn_get_funct7(insn))) {
                case insn_ADDW_MULW_SUBW_funct7::ADDW:
                    return execute_ADDW(a, decode_ir(insn), pc);
                case insn_ADDW_MULW_SUBW_funct7::SUBW:
                    return execute_SUBW(a, decode_ir(insn), pc);
                default:
                    break;
            }
            break;
        case insn_funct3_00000_opcode::SRLW_DIVUW_SRAW:
            switch (static_cast<insn_SRLW_DIVUW_SRAW_funct7>(insn_get_funct7(insn))) {
                case insn_SRLW_DIVUW_SRAW_funct7::SRLW:
                    return execute_SRLW(a, decode_ir(insn), pc);
                case insn_SRLW_DIVUW_SRAW_funct7::SRAW:
                    return execute_SRAW(a, decode_ir(insn), pc);
                default:
                    break;
            }
            break;
        default:
            break;
    }

    throw std::runtime_error("illegal instruction");
}

template <typename STATE_ACCESS>
uarch_interpreter_status uarch_interpret(STATE_ACCESS &a, uint64_t cycle_end) {
    auto cycle = a.read_cycle();
    while (cycle < cycle_end) {
        uint64_t pc = 0;
        uint32_t insn = 0;
        fetch_insn(a, &pc, &insn);
        auto status = execute_insn(a, insn, pc);
        if (status == execute_status::halt) {
            a.write_cycle(0);
            return uarch_interpreter_status::halt;
        }
        cycle = cycle + 1;
        a.write_cycle(cycle);
    }
    return uarch_interpreter_status::success;
}

// Explicit instantiation for uarch_state_access
template uarch_interpreter_status uarch_interpret(uarch_state_access &a, uint64_t uarch_cycle_end);

// Explicit instantiation for uarch_record_state_access
template uarch_interpreter_status uarch_interpret(uarch_record_state_access &a, uint64_t uarch_cycle_end);

// Explicit instantiation for uarch_replay_state_access
template uarch_interpreter_status uarch_interpret(uarch_replay_state_access &a, uint64_t uarch_cycle_end);

} // namespace cartesi
