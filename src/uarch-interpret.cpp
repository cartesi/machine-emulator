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

/// \brief  Bitmask used to obtain the byte offset of a memory address with respect to its 64-bit page.
static constexpr uint64_t u64_offset_mask = sizeof(uint64_t) - 1;

/// \brief  Bitmask used to align a memory address to 64-bit page.
static constexpr uint64_t u64_align_mask = ~u64_offset_mask;

template <typename STATE_ACCESS>
static inline uint64_t read_uint64(STATE_ACCESS &a, uint64_t paddr) {
    assert((paddr & 0b111) == 0);
    return a.read_word(paddr);
}

template <typename STATE_ACCESS>
static inline uint32_t read_uint32(STATE_ACCESS &a, uint64_t paddr) {
    assert((paddr & 0b11) == 0);
    uint64_t palign = paddr & u64_align_mask;
    uint64_t bitoffset = (paddr & u64_offset_mask) << 3;
    uint64_t val64 = read_uint64(a, palign);
    return static_cast<uint32_t>(val64 >> bitoffset);
}

template <typename STATE_ACCESS>
static inline uint16_t read_uint16(STATE_ACCESS &a, uint64_t paddr) {
    assert((paddr & 1) == 0);
    uint64_t palign = paddr & u64_align_mask;
    uint64_t bitoffset = (paddr & u64_offset_mask) << 3;
    uint64_t val64 = read_uint64(a, palign);
    return static_cast<uint16_t>(val64 >> bitoffset);
}

template <typename STATE_ACCESS>
static inline uint8_t read_uint8(STATE_ACCESS &a, uint64_t paddr) {
    uint64_t palign = paddr & u64_align_mask;
    uint64_t bitoffset = (paddr & u64_offset_mask) << 3;
    uint64_t val64 = read_uint64(a, palign);
    return static_cast<uint8_t>(val64 >> bitoffset);
}

template <typename STATE_ACCESS>
static inline void write_uint64(STATE_ACCESS &a, uint64_t paddr, uint64_t val) {
    assert((paddr & 0b111) == 0);
    a.write_word(paddr, val);
}

/// \brief Copies bits from a uint64 word, starting at bit 0, to another uint64 word at the specified bit offset.
/// \param from Source of bits to copy, starting at offset 0.
/// \param count Number of bits to copy.
/// \param to Destination of copy.
/// \param offset Bit offset in destination to copy bits to.
/// \return The uint64_t word containing the copy result.
static inline uint64_t copy_bits(uint64_t from, int count, uint64_t to, uint64_t offset) {
    assert(offset + count <= (sizeof(uint64_t) << 3));
    uint64_t erase_mask = (static_cast<uint64_t>(1) << count) - 1;
    erase_mask = ~(erase_mask << offset);
    return (from << offset) | (to & erase_mask);
}

template <typename STATE_ACCESS>
static inline void write_uint32(STATE_ACCESS &a, uint64_t paddr, uint32_t val) {
    assert((paddr & 0b11) == 0);
    uint64_t palign = paddr & u64_align_mask;
    uint64_t offset = (paddr & u64_offset_mask) << 3;
    uint64_t oldval64 = read_uint64(a, palign);
    uint64_t newval64 = copy_bits(val, sizeof(val) << 3, oldval64, offset);
    write_uint64(a, palign, newval64);
}

template <typename STATE_ACCESS>
static inline void write_uint16(STATE_ACCESS &a, uint64_t paddr, uint16_t val) {
    assert((paddr & 0b1) == 0);
    uint64_t palign = paddr & u64_align_mask;
    uint64_t offset = (paddr & u64_offset_mask) << 3;
    uint64_t oldval64 = read_uint64(a, palign);
    uint64_t newval64 = copy_bits(val, sizeof(val) << 3, oldval64, offset);
    write_uint64(a, palign, newval64);
}

template <typename STATE_ACCESS>
static inline void write_uint8(STATE_ACCESS &a, uint64_t paddr, uint8_t val) {
    uint64_t palign = paddr & u64_align_mask;
    uint64_t offset = (paddr & u64_offset_mask) << 3;
    uint64_t oldval64 = read_uint64(a, palign);
    uint64_t newval64 = copy_bits(val, sizeof(val) << 3, oldval64, offset);
    write_uint64(a, palign, newval64);
}

enum class uarch_execute_status : int {
    success, // instruction executed successfully
    halt     // instruction executed successfully and halted the microinterpreter
};

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

static inline int32_t operand_imm12(uint32_t insn) {
    return static_cast<int32_t>(insn) >> 20;
}

static inline int32_t operand_imm20(uint32_t insn) {
    return static_cast<int32_t>((insn >> 12) << 12);
}

static inline int32_t operand_jimm20(uint32_t insn) {
    return static_cast<int32_t>(static_cast<uint32_t>(static_cast<int32_t>(insn) >> 31) << 20 |
        ((insn << 1) >> 22) << 1 | ((insn << 11) >> 31) << 11 | ((insn << 12) >> 24) << 12);
}

static inline int32_t operand_shamt5(uint32_t insn) {
    return static_cast<int32_t>((insn << 7) >> 27);
}

static inline int32_t operand_shamt6(uint32_t insn) {
    return static_cast<int32_t>((insn << 6) >> 26);
}

static inline int32_t operand_sbimm12(uint32_t insn) {
    return static_cast<int32_t>(static_cast<uint32_t>(static_cast<int32_t>(insn) >> 31) << 12 |
        ((insn << 1) >> 26) << 5 | ((insn << 20) >> 28) << 1 | ((insn << 24) >> 31) << 11);
}

static inline int32_t operand_simm12(uint32_t insn) {
    return static_cast<int32_t>((static_cast<uint32_t>(static_cast<int32_t>(insn) >> 25) << 5) | ((insn << 20) >> 27));
}

struct decoded_insn {
    const uint32_t insn;
    const int32_t imm;
    const uint8_t rd;
    const uint8_t rs1;
    const uint8_t rs2;
};

template <typename STATE_ACCESS>
static void dump_insn(STATE_ACCESS &a, uint64_t pc, uint32_t insn, const char *name) {
#ifdef DUMP_INSN
    fprintf(stderr, "%08" PRIx64, pc);
    fprintf(stderr, ":   %08" PRIx32 "   ", insn);
    fprintf(stderr, "%s\n", name);
#else
    (void) a;
    (void) insn;
    (void) pc;
    (void) name;
#endif
}

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

// Execute instruction

template <typename STATE_ACCESS>
static inline uarch_execute_status write_pc(STATE_ACCESS &a, uint64_t new_pc) {
    a.write_pc(new_pc);
    if (new_pc == PMA_UARCH_RAM_START) {
        return uarch_execute_status::halt;
    }
    return uarch_execute_status::success;
}

template <typename STATE_ACCESS>
static inline uarch_execute_status advance_pc(STATE_ACCESS &a, uint64_t pc) {
    uint64_t new_pc = pc + 4;
    return write_pc(a, new_pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status branch(STATE_ACCESS &a, uint64_t new_pc) {
    return write_pc(a, new_pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_LUI(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_iu(insn);
    dump_insn(a, pc, insn, "lui");
    auto note = a.make_scoped_note("lui");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_AUIPC(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_iu(insn);
    dump_insn(a, pc, insn, "auipc");
    auto note = a.make_scoped_note("auipc");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, pc + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_JAL(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_iuj(insn);
    dump_insn(a, pc, insn, "jal");
    auto note = a.make_scoped_note("jal");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, pc + 4);
    }
    return branch(a, pc + d.imm);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_JALR(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "jalr");
    auto note = a.make_scoped_note("jalr");
    (void) note;
    auto rs1 = a.read_x(d.rs1);
    if (d.rd != 0) {
        a.write_x(d.rd, pc + 4);
    }
    return branch(a, (rs1 + d.imm) & ~static_cast<uint64_t>(1));
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_BEQ(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_isb(insn);
    dump_insn(a, pc, insn, "beq");
    auto note = a.make_scoped_note("beq");
    (void) note;
    if (a.read_x(d.rs1) == a.read_x(d.rs2)) {
        return branch(a, pc + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_BNE(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_isb(insn);
    dump_insn(a, pc, insn, "bne");
    auto note = a.make_scoped_note("bne");
    (void) note;
    auto rs1 = a.read_x(d.rs1);
    auto rs2 = a.read_x(d.rs2);
    if (rs1 != rs2) {
        return branch(a, pc + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_BLT(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_isb(insn);
    dump_insn(a, pc, insn, "blt");
    auto note = a.make_scoped_note("blt");
    (void) note;
    auto rs1 = static_cast<int64_t>(a.read_x(d.rs1));
    auto rs2 = static_cast<int64_t>(a.read_x(d.rs2));
    if (rs1 < rs2) {
        return branch(a, pc + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_BGE(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_isb(insn);
    dump_insn(a, pc, insn, "bge");
    auto note = a.make_scoped_note("bge");
    (void) note;
    auto rs1 = static_cast<int64_t>(a.read_x(d.rs1));
    auto rs2 = static_cast<int64_t>(a.read_x(d.rs2));
    if (rs1 >= rs2) {
        return branch(a, pc + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_BLTU(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_isb(insn);
    dump_insn(a, pc, insn, "bltu");
    auto note = a.make_scoped_note("bltu");
    (void) note;
    auto rs1 = a.read_x(d.rs1);
    auto rs2 = a.read_x(d.rs2);
    if (rs1 < rs2) {
        return branch(a, pc + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_BGEU(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_isb(insn);
    dump_insn(a, pc, insn, "bgeu");
    auto note = a.make_scoped_note("bgeu");
    (void) note;
    auto rs1 = a.read_x(d.rs1);
    auto rs2 = a.read_x(d.rs2);
    if (rs1 >= rs2) {
        return branch(a, pc + d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_LB(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "lb");
    auto note = a.make_scoped_note("lb");
    (void) note;
    int8_t i8 = read_uint8(a, a.read_x(d.rs1) + d.imm);
    if (d.rd != 0) {
        a.write_x(d.rd, i8);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_LHU(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "lhu");
    auto note = a.make_scoped_note("lhu");
    (void) note;
    uint16_t u16 = read_uint16(a, a.read_x(d.rs1) + d.imm);
    if (d.rd != 0) {
        a.write_x(d.rd, u16);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_LH(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "lh");
    auto note = a.make_scoped_note("lh");
    (void) note;
    int16_t i16 = read_uint16(a, a.read_x(d.rs1) + d.imm);
    if (d.rd != 0) {
        a.write_x(d.rd, i16);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_LW(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "lw");
    auto note = a.make_scoped_note("lw");
    (void) note;
    int32_t i32 = read_uint32(a, a.read_x(d.rs1) + d.imm);
    if (d.rd != 0) {
        a.write_x(d.rd, i32);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_LBU(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "lbu");
    auto note = a.make_scoped_note("lbu");
    (void) note;
    uint8_t u8 = read_uint8(a, a.read_x(d.rs1) + d.imm);
    if (d.rd != 0) {
        a.write_x(d.rd, u8);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SB(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_is(insn);
    dump_insn(a, pc, insn, "sb");
    auto note = a.make_scoped_note("sb");
    (void) note;
    auto rs1 = a.read_x(d.rs1);
    auto rs2 = a.read_x(d.rs2);
    write_uint8(a, rs1 + d.imm, static_cast<uint8_t>(rs2));
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SH(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_is(insn);
    dump_insn(a, pc, insn, "sh");
    auto note = a.make_scoped_note("sh");
    (void) note;
    auto rs1 = a.read_x(d.rs1);
    auto rs2 = static_cast<uint16_t>(a.read_x(d.rs2));
    write_uint16(a, rs1 + d.imm, rs2);
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SW(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_is(insn);
    dump_insn(a, pc, insn, "sw");
    auto note = a.make_scoped_note("sw");
    (void) note;
    auto rs1 = a.read_x(d.rs1);
    auto rs2 = static_cast<uint32_t>(a.read_x(d.rs2));
    write_uint32(a, rs1 + d.imm, rs2);
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_ADDI(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "addi");
    auto note = a.make_scoped_note("addi");
    (void) note;
    if (d.rd != 0) {
        int64_t val = 0;
        __builtin_add_overflow(static_cast<int64_t>(a.read_x(d.rs1)), static_cast<int64_t>(d.imm), &val);
        a.write_x(d.rd, static_cast<uint64_t>(val));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_ADDIW(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "addiw");
    auto note = a.make_scoped_note("addiw");
    (void) note;
    auto rs1 = static_cast<int32_t>(a.read_x(d.rs1));
    if (d.rd != 0) {
        int32_t val = 0;
        __builtin_add_overflow(rs1, d.imm, &val);
        a.write_x(d.rd, static_cast<uint64_t>(val));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SLTI(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "slti");
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
static inline uarch_execute_status execute_SLTIU(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "sltiu");
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
static inline uarch_execute_status execute_XORI(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "xori");
    auto note = a.make_scoped_note("xori");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) ^ d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_ORI(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "ori");
    auto note = a.make_scoped_note("ori");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) | d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_ANDI(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "andi");
    auto note = a.make_scoped_note("andi");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) & d.imm);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SLLI(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_sh6(insn);
    dump_insn(a, pc, insn, "slli");
    auto note = a.make_scoped_note("slli");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) << (d.imm & 0b111111));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SLLIW(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_sh5(insn);
    dump_insn(a, pc, insn, "slliw");
    auto note = a.make_scoped_note("slliw");
    (void) note;
    auto rs1 = static_cast<uint32_t>(a.read_x(d.rs1));
    if (d.rd != 0) {
        a.write_x(d.rd, static_cast<int32_t>(rs1 << (d.imm & 0b11111)));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SRLI(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_sh6(insn);
    dump_insn(a, pc, insn, "srli");
    auto note = a.make_scoped_note("srli");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, a.read_x(d.rs1) >> (d.imm & (XLEN - 1)));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SRLW(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "srlw");
    auto note = a.make_scoped_note("srlw");
    (void) note;
    auto rs1 = static_cast<uint32_t>(a.read_x(d.rs1));
    int32_t rd = static_cast<int32_t>(rs1 >> (a.read_x(d.rs2) & 31));
    if (d.rd != 0) {
        a.write_x(d.rd, rd);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SRLIW(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_sh5(insn);
    dump_insn(a, pc, insn, "srliw");
    auto note = a.make_scoped_note("srliw");
    (void) note;
    auto rs1 = static_cast<uint32_t>(a.read_x(d.rs1));
    auto rd = static_cast<int32_t>(rs1 >> (d.imm & 0b11111));
    if (d.rd != 0) {
        a.write_x(d.rd, rd);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SRAI(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_sh6(insn);
    dump_insn(a, pc, insn, "srai");
    auto note = a.make_scoped_note("srai");
    (void) note;
    if (d.rd != 0) {
        a.write_x(d.rd, static_cast<int64_t>(a.read_x(d.rs1)) >> (d.imm & (XLEN - 1)));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SRAIW(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_sh5(insn);
    dump_insn(a, pc, insn, "sraiw");
    auto note = a.make_scoped_note("sraiw");
    (void) note;
    auto rs1 = static_cast<int32_t>(a.read_x(d.rs1));
    if (d.rd != 0) {
        a.write_x(d.rd, static_cast<int32_t>(rs1) >> (d.imm & 0b11111));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_ADD(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "add");
    auto note = a.make_scoped_note("add");
    (void) note;
    if (d.rd != 0) {
        auto rs1 = a.read_x(d.rs1);
        auto rs2 = a.read_x(d.rs2);
        a.write_x(d.rd, rs1 + rs2);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_ADDW(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "addw");
    auto note = a.make_scoped_note("addw");
    (void) note;
    auto rs1 = static_cast<int32_t>(a.read_x(d.rs1));
    auto rs2 = static_cast<int32_t>(a.read_x(d.rs2));
    if (d.rd != 0) {
        int32_t val = 0;
        __builtin_add_overflow(rs1, rs2, &val);
        a.write_x(d.rd, val);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SUB(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "sub");
    auto note = a.make_scoped_note("sub");
    (void) note;
    if (d.rd != 0) {
        auto rs1 = a.read_x(d.rs1);
        auto rs2 = a.read_x(d.rs2);
        a.write_x(d.rd, rs1 - rs2);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SUBW(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "subw");
    auto note = a.make_scoped_note("subw");
    (void) note;
    auto rs1 = static_cast<int32_t>(a.read_x(d.rs1));
    auto rs2 = static_cast<int32_t>(a.read_x(d.rs2));
    if (d.rd != 0) {
        int32_t val = 0;
        __builtin_sub_overflow(rs1, rs2, &val);
        a.write_x(d.rd, val);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SLL(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "sll");
    auto note = a.make_scoped_note("sll");
    (void) note;
    if (d.rd != 0) {
        auto rs1 = a.read_x(d.rs1);
        auto rs2 = a.read_x(d.rs2);
        a.write_x(d.rd, rs1 << (rs2 & (XLEN - 1)));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SLLW(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "sllw");
    auto note = a.make_scoped_note("sllw");
    (void) note;
    auto rs1 = static_cast<int32_t>(a.read_x(d.rs1));
    auto rs2 = static_cast<int32_t>(a.read_x(d.rs2));
    int32_t rd = static_cast<int32_t>(static_cast<uint32_t>(rs1) << (rs2 & 31));
    if (d.rd != 0) {
        a.write_x(d.rd, static_cast<uint64_t>(rd));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SLT(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "slt");
    auto note = a.make_scoped_note("slt");
    (void) note;
    if (d.rd != 0) {
        auto rs1 = static_cast<int64_t>(a.read_x(d.rs1));
        auto rs2 = static_cast<int64_t>(a.read_x(d.rs2));
        a.write_x(d.rd, rs1 < rs2 ? 1 : 0);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SLTU(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "sltu");
    auto note = a.make_scoped_note("sltu");
    (void) note;
    if (d.rd != 0) {
        auto rs1 = a.read_x(d.rs1);
        auto rs2 = a.read_x(d.rs2);
        a.write_x(d.rd, rs1 < rs2 ? 1 : 0);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_XOR(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "xor");
    auto note = a.make_scoped_note("xor");
    (void) note;
    if (d.rd != 0) {
        auto rs1 = a.read_x(d.rs1);
        auto rs2 = a.read_x(d.rs2);
        a.write_x(d.rd, rs1 ^ rs2);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SRL(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "srl");
    auto note = a.make_scoped_note("srl");
    (void) note;
    if (d.rd != 0) {
        auto rs1 = a.read_x(d.rs1);
        auto rs2 = a.read_x(d.rs2);
        a.write_x(d.rd, rs1 >> (rs2 & (XLEN - 1)));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SRA(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "sra");
    auto note = a.make_scoped_note("sra");
    (void) note;
    if (d.rd != 0) {
        auto rs1 = static_cast<int64_t>(a.read_x(d.rs1));
        auto rs2 = a.read_x(d.rs2);
        a.write_x(d.rd, rs1 >> (rs2 & (XLEN - 1)));
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_SRAW(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "sraw");
    auto note = a.make_scoped_note("sraw");
    (void) note;
    auto rs1 = static_cast<int32_t>(a.read_x(d.rs1));
    auto rs2 = static_cast<int32_t>(a.read_x(d.rs2));
    int32_t rd = static_cast<int32_t>(rs1) >> (rs2 & 31);
    if (d.rd != 0) {
        a.write_x(d.rd, rd);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static inline uarch_execute_status execute_OR(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "or");
    auto note = a.make_scoped_note("or");
    (void) note;
    if (d.rd != 0) {
        auto rs1 = a.read_x(d.rs1);
        auto rs2 = a.read_x(d.rs2);
        a.write_x(d.rd, rs1 | rs2);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static uarch_execute_status execute_AND(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_ir(insn);
    dump_insn(a, pc, insn, "and");
    auto note = a.make_scoped_note("and");
    (void) note;
    if (d.rd != 0) {
        auto rs1 = a.read_x(d.rs1);
        auto rs2 = a.read_x(d.rs2);
        a.write_x(d.rd, rs1 & rs2);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static uarch_execute_status execute_FENCE(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    dump_insn(a, pc, insn, "fence");
    auto note = a.make_scoped_note("fence");
    (void) note;
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static uarch_execute_status execute_LWU(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "lwu");
    auto note = a.make_scoped_note("lwu");
    (void) note;
    uint32_t u32 = read_uint32(a, a.read_x(d.rs1) + d.imm);
    if (d.rd != 0) {
        a.write_x(d.rd, u32);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static uarch_execute_status execute_LD(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_i_l(insn);
    dump_insn(a, pc, insn, "ld");
    auto note = a.make_scoped_note("ld");
    (void) note;
    uint64_t u64 = read_uint64(a, a.read_x(d.rs1) + d.imm);
    if (d.rd != 0) {
        a.write_x(d.rd, u64);
    }
    return advance_pc(a, pc);
}

template <typename STATE_ACCESS>
static uarch_execute_status execute_SD(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    auto d = decode_s(insn);
    dump_insn(a, pc, insn, "sd");
    auto note = a.make_scoped_note("sd");
    (void) note;
    write_uint64(a, a.read_x(d.rs1) + d.imm, a.read_x(d.rs2));
    return advance_pc(a, pc);
}

/// \brief Returns true if the opcode field of an instruction matches the provided argument
static inline bool insn_match_opcode(uint32_t insn, uint32_t opcode) {
    return ((insn & 0b1111111)) == opcode;
}

/// \brief Returns true if the opcode and funct3 fields of an instruction match the provided arguments
static inline bool insn_match_opcode_funct3(uint32_t insn, uint32_t opcode, uint32_t funct3) {
    constexpr uint32_t mask = (0b111 << 12) | 0b1111111;
    return ((insn & mask)) == ((funct3 << 12) | opcode);
}

/// \brief Returns true if the opcode, funct3 and funct7 fields of an instruction match the provided arguments
static inline bool insn_match_opcode_funct3_funct7(uint32_t insn, uint32_t opcode, uint32_t funct3, uint32_t funct7) {
    constexpr uint32_t mask = (0b1111111 << 25) | (0b111 << 12) | 0b1111111;
    return ((insn & mask)) == ((funct7 << 25) | (funct3 << 12) | opcode);
}

/// \brief Returns true if the opcode, funct3 and 6 most significant bits of funct7 fields of an instruction match the
/// provided arguments
static inline bool insn_match_opcode_funct3_funct7_sr1(uint32_t insn, uint32_t opcode, uint32_t funct3,
    uint32_t funct7_sr1) {
    constexpr uint32_t mask = (0b111111 << 26) | (0b111 << 12) | 0b1111111;
    return ((insn & mask)) == ((funct7_sr1 << 26) | (funct3 << 12) | opcode);
}

// Decode and execute one instruction
template <typename STATE_ACCESS>
static inline uarch_execute_status execute_insn(STATE_ACCESS &a, uint32_t insn, uint64_t pc) {
    if (insn_match_opcode_funct3(insn, 0b0010011, 0b000)) {
        return execute_ADDI(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0000011, 0b011)) {
        return execute_LD(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b1100011, 0b110)) {
        return execute_BLTU(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b1100011, 0b000)) {
        return execute_BEQ(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0010011, 0b111)) {
        return execute_ANDI(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0110011, 0b000, 0b0000000)) {
        return execute_ADD(a, insn, pc);
    } else if (insn_match_opcode(insn, 0b1101111)) {
        return execute_JAL(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7_sr1(insn, 0b0010011, 0b001, 0b000000)) {
        return execute_SLLI(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0110011, 0b111, 0b0000000)) {
        return execute_AND(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0100011, 0b011)) {
        return execute_SD(a, insn, pc);
    } else if (insn_match_opcode(insn, 0b0110111)) {
        return execute_LUI(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b1100111, 0b000)) {
        return execute_JALR(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0011011, 0b000)) {
        return execute_ADDIW(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7_sr1(insn, 0b0010011, 0b101, 0b000000)) {
        return execute_SRLI(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0011011, 0b101, 0b0000000)) {
        return execute_SRLIW(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b1100011, 0b001)) {
        return execute_BNE(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0000011, 0b010)) {
        return execute_LW(a, insn, pc);
    } else if (insn_match_opcode(insn, 0b0010111)) {
        return execute_AUIPC(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b1100011, 0b111)) {
        return execute_BGEU(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0111011, 0b000, 0b0000000)) {
        return execute_ADDW(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7_sr1(insn, 0b0010011, 0b101, 0b010000)) {
        return execute_SRAI(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0110011, 0b110, 0b0000000)) {
        return execute_OR(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0011011, 0b101, 0b0100000)) {
        return execute_SRAIW(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b1100011, 0b101)) {
        return execute_BGE(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0110011, 0b000, 0b0100000)) {
        return execute_SUB(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0000011, 0b100)) {
        return execute_LBU(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0011011, 0b001, 0b0000000)) {
        return execute_SLLIW(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0110011, 0b101, 0b0000000)) {
        return execute_SRL(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0110011, 0b100, 0b0000000)) {
        return execute_XOR(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0100011, 0b010)) {
        return execute_SW(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0110011, 0b001, 0b0000000)) {
        return execute_SLL(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b1100011, 0b100)) {
        return execute_BLT(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0100011, 0b000)) {
        return execute_SB(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0111011, 0b000, 0b0100000)) {
        return execute_SUBW(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0010011, 0b100)) {
        return execute_XORI(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0110011, 0b101, 0b0100000)) {
        return execute_SRA(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0000011, 0b101)) {
        return execute_LHU(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0100011, 0b001)) {
        return execute_SH(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0111011, 0b101, 0b0000000)) {
        return execute_SRLW(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0000011, 0b110)) {
        return execute_LWU(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0111011, 0b001, 0b0000000)) {
        return execute_SLLW(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0000011, 0b000)) {
        return execute_LB(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0110011, 0b011, 0b0000000)) {
        return execute_SLTU(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0111011, 0b101, 0b0100000)) {
        return execute_SRAW(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0000011, 0b001)) {
        return execute_LH(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0010011, 0b110)) {
        return execute_ORI(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0010011, 0b011)) {
        return execute_SLTIU(a, insn, pc);
    } else if (insn_match_opcode_funct3_funct7(insn, 0b0110011, 0b010, 0b0000000)) {
        return execute_SLT(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0010011, 0b010)) {
        return execute_SLTI(a, insn, pc);
    } else if (insn_match_opcode_funct3(insn, 0b0001111, 0b000)) {
        return execute_FENCE(a, insn, pc);
    }

    throw std::runtime_error("illegal instruction");
}

template <typename STATE_ACCESS>
uarch_interpreter_status uarch_interpret(STATE_ACCESS &a, uint64_t cycle_end) {
    auto cycle = a.read_cycle();
    while (cycle < cycle_end) {
        auto pc = a.read_pc();
        auto insn = read_uint32(a, pc);
        auto status = execute_insn(a, insn, pc);
        if (status == uarch_execute_status::halt) {
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
