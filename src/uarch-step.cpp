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

/// \file
/// \brief This file is be converted to Solidity by the machine-solidity-step.

// NOLINTBEGIN(google-readability-casting,misc-const-correctness,modernize-use-auto,hicpp-use-auto)

#include "uarch-step.h"

#include "uarch-record-state-access.h"
#include "uarch-replay-state-access.h"
#include "uarch-state-access.h"

#include "uarch-constants.h"
#include "uarch-solidity-compat.h"

namespace cartesi {

// Memory read/write access

template <typename UarchState>
static inline uint64 readUint64(const UarchState a, uint64 paddr) {
    require((paddr & 7) == 0, "misaligned readUint64 address");
    return readWord(a, paddr);
}

template <typename UarchState>
static inline uint32 readUint32(const UarchState a, uint64 paddr) {
    require((paddr & 3) == 0, "misaligned readUint32 address");
    uint64 palign = paddr & ~uint64(7);
    uint32 bitoffset = uint32ShiftLeft(uint32(paddr) & uint32(7), 3);
    uint64 val64 = readUint64(a, palign);
    return uint32(uint64ShiftRight(val64, bitoffset));
}

template <typename UarchState>
static inline uint16 readUint16(const UarchState a, uint64 paddr) {
    require((paddr & 1) == 0, "misaligned readUint16 address");
    uint64 palign = paddr & ~uint64(7);
    uint32 bitoffset = uint32ShiftLeft(uint32(paddr) & uint32(7), 3);
    uint64 val64 = readUint64(a, palign);
    return uint16(uint64ShiftRight(val64, bitoffset));
}

template <typename UarchState>
static inline uint8 readUint8(const UarchState a, uint64 paddr) {
    uint64 palign = paddr & ~uint64(7);
    uint32 bitoffset = uint32ShiftLeft(uint32(paddr) & uint32(7), 3);
    uint64 val64 = readUint64(a, palign);
    return uint8(uint64ShiftRight(val64, bitoffset));
}

template <typename UarchState>
static inline void writeUint64(const UarchState a, uint64 paddr, uint64 val) {
    require((paddr & 7) == 0, "misaligned writeUint64 address");
    writeWord(a, paddr, val);
}

/// \brief Copies bits from a uint64 word, starting at bit 0, to another uint64 word at the specified bit offset.
/// \param from Source of bits to copy, starting at offset 0.
/// \param count Number of bits to copy.
/// \param to Destination of copy.
/// \param offset Bit offset in destination to copy bits to.
/// \return The uint64 word containing the copy result.
static inline uint64 copyBits(uint32 from, uint32 count, uint64 to, uint32 offset) {
    require(offset + count <= 64, "copyBits count exceeds limit of 64");
    uint64 eraseMask = uint64ShiftLeft(1, count) - 1;
    eraseMask = ~uint64ShiftLeft(eraseMask, offset);
    return uint64ShiftLeft(from, offset) | (to & eraseMask);
}

template <typename UarchState>
static inline void writeUint32(const UarchState a, uint64 paddr, uint32 val) {
    require((paddr & 3) == 0, "misaligned writeUint32 address");
    uint64 palign = paddr & ~uint64(7);

    uint32 bitoffset = uint32ShiftLeft(uint32(paddr) & uint32(7), 3);
    uint64 oldval64 = readUint64(a, palign);
    uint64 newval64 = copyBits(val, 32, oldval64, bitoffset);
    writeUint64(a, palign, newval64);
}

template <typename UarchState>
static inline void writeUint16(const UarchState a, uint64 paddr, uint16 val) {
    require((paddr & 1) == 0, "misaligned writeUint16 address");
    uint64 palign = paddr & ~uint64(7);
    uint32 bitoffset = uint32ShiftLeft(uint32(paddr) & uint32(7), 3);
    uint64 oldval64 = readUint64(a, palign);
    uint64 newval64 = copyBits(val, 16, oldval64, bitoffset);
    writeUint64(a, palign, newval64);
}

template <typename UarchState>
static inline void writeUint8(const UarchState a, uint64 paddr, uint8 val) {
    uint64 palign = paddr & ~uint64(7);
    uint32 bitoffset = uint32ShiftLeft(uint32(paddr) & uint32(7), 3);
    uint64 oldval64 = readUint64(a, palign);
    uint64 newval64 = copyBits(val, 8, oldval64, bitoffset);
    writeUint64(a, palign, newval64);
}

// Instruction operand decoders

static inline uint8 operandRd(uint32 insn) {
    return uint8(uint32ShiftRight(uint32ShiftLeft(insn, 20), 27));
}

static inline uint8 operandRs1(uint32 insn) {
    return uint8(uint32ShiftRight(uint32ShiftLeft(insn, 12), 27));
}

static inline uint8 operandRs2(uint32 insn) {
    return uint8(uint32ShiftRight(uint32ShiftLeft(insn, 7), 27));
}

static inline int32 operandImm12(uint32 insn) {
    return int32ShiftRight(int32(insn), 20);
}

static inline int32 operandImm20(uint32 insn) {
    return int32(uint32ShiftLeft(uint32ShiftRight(insn, 12), 12));
}

static inline int32 operandJimm20(uint32 insn) {
    int32 a = int32(uint32ShiftLeft(uint32(int32ShiftRight(int32(insn), 31)), 20));
    uint32 b = uint32ShiftLeft(uint32ShiftRight(uint32ShiftLeft(insn, 1), 22), 1);
    uint32 c = uint32ShiftLeft(uint32ShiftRight(uint32ShiftLeft(insn, 11), 31), 11);
    uint32 d = uint32ShiftLeft(uint32ShiftRight(uint32ShiftLeft(insn, 12), 24), 12);
    return int32(uint32(a) | b | c | d);
}

static inline int32 operandShamt5(uint32 insn) {
    return int32(uint32ShiftRight(uint32ShiftLeft(insn, 7), 27));
}

static inline int32 operandShamt6(uint32 insn) {
    return int32(uint32ShiftRight(uint32ShiftLeft(insn, 6), 26));
}

static inline int32 operandSbimm12(uint32 insn) {
    int32 a = int32(uint32ShiftLeft(uint32(int32ShiftRight(int32(insn), 31)), 12));
    uint32 b = uint32ShiftLeft(uint32ShiftRight(uint32ShiftLeft(insn, 1), 26), 5);
    uint32 c = uint32ShiftLeft(uint32ShiftRight(uint32ShiftLeft(insn, 20), 28), 1);
    uint32 d = uint32ShiftLeft(uint32ShiftRight(uint32ShiftLeft(insn, 24), 31), 11);
    return int32(uint32(a) | b | c | d);
}

static inline int32 operandSimm12(uint32 insn) {
    return int32(
        uint32ShiftLeft(uint32(int32ShiftRight(int32(insn), 25)), 5) | uint32ShiftRight(uint32ShiftLeft(insn, 20), 27));
}

// Execute instruction

template <typename UarchState>
static inline void advancePc(const UarchState a, uint64 pc) {
    uint64 newPc = uint64AddUint64(pc, 4);
    return writePc(a, newPc);
}

template <typename UarchState>
static inline void branch(const UarchState a, uint64 pc) {
    return writePc(a, pc);
}

template <typename UarchState>
static inline void executeLUI(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "lui");
    uint8 rd = operandRd(insn);
    int32 imm = operandImm20(insn);
    if (rd != 0) {
        writeX(a, rd, int32ToUint64(imm));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeAUIPC(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "auipc");
    int32 imm = operandImm20(insn);
    uint8 rd = operandRd(insn);
    if (rd != 0) {
        writeX(a, rd, uint64AddInt32(pc, imm));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeJAL(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "jal");
    int32 imm = operandJimm20(insn);
    uint8 rd = operandRd(insn);
    if (rd != 0) {
        writeX(a, rd, uint64AddUint64(pc, 4));
    }
    return branch(a, uint64AddInt32(pc, imm));
}

template <typename UarchState>
static inline void executeJALR(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "jalr");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint64 rs1val = readX(a, rs1);
    if (rd != 0) {
        writeX(a, rd, uint64AddUint64(pc, 4));
    }
    return branch(a, uint64AddInt32(rs1val, imm) & (~uint64(1)));
}

template <typename UarchState>
static inline void executeBEQ(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "beq");
    int32 imm = operandSbimm12(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    uint64 rs1val = readX(a, rs1);
    uint64 rs2val = readX(a, rs2);
    if (rs1val == rs2val) {
        return branch(a, uint64AddInt32(pc, imm));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeBNE(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "bne");
    int32 imm = operandSbimm12(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    uint64 rs1val = readX(a, rs1);
    uint64 rs2val = readX(a, rs2);
    if (rs1val != rs2val) {
        return branch(a, uint64AddInt32(pc, imm));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeBLT(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "blt");
    int32 imm = operandSbimm12(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    int64 rs1val = int64(readX(a, rs1));
    int64 rs2val = int64(readX(a, rs2));
    if (rs1val < rs2val) {
        return branch(a, uint64AddInt32(pc, imm));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeBGE(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "bge");
    int32 imm = operandSbimm12(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    int64 rs1val = int64(readX(a, rs1));
    int64 rs2val = int64(readX(a, rs2));
    if (rs1val >= rs2val) {
        return branch(a, uint64AddInt32(pc, imm));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeBLTU(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "bltu");
    int32 imm = operandSbimm12(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    uint64 rs1val = readX(a, rs1);
    uint64 rs2val = readX(a, rs2);
    if (rs1val < rs2val) {
        return branch(a, uint64AddInt32(pc, imm));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeBGEU(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "bgeu");
    int32 imm = operandSbimm12(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    uint64 rs1val = readX(a, rs1);
    uint64 rs2val = readX(a, rs2);
    if (rs1val >= rs2val) {
        return branch(a, uint64AddInt32(pc, imm));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeLB(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "lb");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint64 rs1val = readX(a, rs1);
    int8 i8 = int8(readUint8(a, uint64AddInt32(rs1val, imm)));
    if (rd != 0) {
        writeX(a, rd, int8ToUint64(i8));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeLHU(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "lhu");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint64 rs1val = readX(a, rs1);
    uint16 u16 = readUint16(a, uint64AddInt32(rs1val, imm));
    if (rd != 0) {
        writeX(a, rd, u16);
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeLH(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "lh");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint64 rs1val = readX(a, rs1);
    int16 i16 = int16(readUint16(a, uint64AddInt32(rs1val, imm)));
    if (rd != 0) {
        writeX(a, rd, int16ToUint64(i16));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeLW(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "lw");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint64 rs1val = readX(a, rs1);
    int32 i32 = int32(readUint32(a, uint64AddInt32(rs1val, imm)));
    if (rd != 0) {
        writeX(a, rd, int32ToUint64(i32));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeLBU(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "lbu");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint64 rs1val = readX(a, rs1);
    uint8 u8 = readUint8(a, uint64AddInt32(rs1val, imm));
    if (rd != 0) {
        writeX(a, rd, u8);
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSB(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "sb");
    int32 imm = operandSimm12(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    uint64 rs1val = readX(a, rs1);
    uint64 rs2val = readX(a, rs2);
    writeUint8(a, uint64AddInt32(rs1val, imm), uint8(rs2val));
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSH(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "sh");
    int32 imm = operandSimm12(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    uint64 rs1val = readX(a, rs1);
    uint64 rs2val = readX(a, rs2);
    writeUint16(a, uint64AddInt32(rs1val, imm), uint16(rs2val));
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSW(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "sw");
    int32 imm = operandSimm12(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    uint64 rs1val = readX(a, rs1);
    uint32 rs2val = uint32(readX(a, rs2));
    writeUint32(a, uint64AddInt32(rs1val, imm), rs2val);
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeADDI(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "addi");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        int64 val = int64AddInt64(int64(rs1val), int64(imm));
        writeX(a, rd, uint64(val));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeADDIW(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "addiw");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    int32 rs1val = uint64ToInt32(readX(a, rs1));
    if (rd != 0) {
        int32 val = int32AddInt32(rs1val, imm);
        writeX(a, rd, int32ToUint64(val));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSLTI(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "slti");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        if (int64(rs1val) < imm) {
            writeX(a, rd, 1);
        } else {
            writeX(a, rd, 0);
        }
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSLTIU(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "sltiu");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        if (rs1val < int32ToUint64(imm)) {
            writeX(a, rd, 1);
        } else {
            writeX(a, rd, 0);
        }
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeXORI(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "xori");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        writeX(a, rd, rs1val ^ int32ToUint64(imm));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeORI(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "ori");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        writeX(a, rd, rs1val | int32ToUint64(imm));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeANDI(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "andi");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        writeX(a, rd, rs1val & int32ToUint64(imm));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSLLI(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "slli");
    int32 imm = operandShamt6(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        writeX(a, rd, uint64ShiftLeft(rs1val, uint32(imm)));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSLLIW(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "slliw");
    int32 imm = operandShamt5(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint32 rs1val = uint32(readX(a, rs1));
    if (rd != 0) {
        writeX(a, rd, int32ToUint64(int32(uint32ShiftLeft(rs1val, uint32(imm)))));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSRLI(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "srli");
    int32 imm = operandShamt6(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        writeX(a, rd, uint64ShiftRight(rs1val, uint32(imm)));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSRLW(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "srlw");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    uint32 rs1val = uint32(readX(a, rs1));
    uint32 rs2val = uint32(readX(a, rs2));
    int32 rdval = int32(uint32ShiftRight(rs1val, rs2val));
    if (rd != 0) {
        writeX(a, rd, int32ToUint64(rdval));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSRLIW(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "srliw");
    int32 imm = operandShamt5(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint32 rs1val = uint32(readX(a, rs1));
    int32 rdval = int32(uint32ShiftRight(rs1val, uint32(imm)));
    if (rd != 0) {
        writeX(a, rd, int32ToUint64(rdval));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSRAI(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "srai");
    int32 imm = operandShamt6(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        writeX(a, rd, uint64(int64ShiftRight(int64(rs1val), uint32(imm))));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSRAIW(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "sraiw");
    int32 imm = operandShamt5(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    int32 rs1val = uint64ToInt32(readX(a, rs1));
    if (rd != 0) {
        writeX(a, rd, int32ToUint64(int32ShiftRight(rs1val, uint32(imm))));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeADD(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "add");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        uint64 rs2val = readX(a, rs2);
        writeX(a, rd, uint64AddUint64(rs1val, rs2val));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeADDW(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "addw");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    int32 rs1val = uint64ToInt32(readX(a, rs1));
    int32 rs2val = uint64ToInt32(readX(a, rs2));
    if (rd != 0) {
        int32 val = int32AddInt32(rs1val, rs2val);
        writeX(a, rd, int32ToUint64(val));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSUB(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "sub");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        uint64 rs2val = readX(a, rs2);
        writeX(a, rd, uint64SubUint64(rs1val, rs2val));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSUBW(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "subw");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    int32 rs1val = uint64ToInt32(readX(a, rs1));
    int32 rs2val = uint64ToInt32(readX(a, rs2));
    if (rd != 0) {
        int32 val = int32SubInt32(rs1val, rs2val);
        writeX(a, rd, int32ToUint64(val));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSLL(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "sll");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        uint32 rs2val = uint32(readX(a, rs2));
        writeX(a, rd, uint64ShiftLeft(rs1val, rs2val));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSLLW(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "sllw");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    uint32 rs1val = uint32(readX(a, rs1));
    uint32 rs2val = uint32(readX(a, rs2));
    int32 rdval = int32(uint32ShiftLeft(rs1val, rs2val));
    if (rd != 0) {
        writeX(a, rd, int32ToUint64(rdval));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSLT(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "slt");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    if (rd != 0) {
        int64 rs1val = int64(readX(a, rs1));
        int64 rs2val = int64(readX(a, rs2));
        uint64 rdval = 0;
        if (rs1val < rs2val) {
            rdval = 1;
        }
        writeX(a, rd, rdval);
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSLTU(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "sltu");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        uint64 rs2val = readX(a, rs2);
        uint64 rdval = 0;
        if (rs1val < rs2val) {
            rdval = 1;
        }
        writeX(a, rd, rdval);
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeXOR(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "xor");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        uint64 rs2val = readX(a, rs2);
        writeX(a, rd, rs1val ^ rs2val);
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSRL(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "srl");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        uint64 rs2val = readX(a, rs2);
        writeX(a, rd, uint64ShiftRight(rs1val, uint32(rs2val)));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSRA(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "sra");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    if (rd != 0) {
        int64 rs1val = int64(readX(a, rs1));
        uint32 rs2val = uint32(readX(a, rs2));
        writeX(a, rd, uint64(int64ShiftRight(rs1val, rs2val)));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSRAW(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "sraw");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    int32 rs1val = uint64ToInt32(readX(a, rs1));
    uint32 rs2val = uint32(readX(a, rs2));
    int32 rdval = int32ShiftRight(rs1val, rs2val);
    if (rd != 0) {
        writeX(a, rd, int32ToUint64(rdval));
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeOR(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "or");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        uint64 rs2val = readX(a, rs2);
        writeX(a, rd, rs1val | rs2val);
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeAND(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "and");
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    if (rd != 0) {
        uint64 rs1val = readX(a, rs1);
        uint64 rs2val = readX(a, rs2);
        writeX(a, rd, rs1val & rs2val);
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeFENCE(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "fence");
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeLWU(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "lwu");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint64 rs1val = readX(a, rs1);
    uint32 u32 = readUint32(a, uint64AddInt32(rs1val, imm));
    if (rd != 0) {
        writeX(a, rd, u32);
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeLD(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "ld");
    int32 imm = operandImm12(insn);
    uint8 rd = operandRd(insn);
    uint8 rs1 = operandRs1(insn);
    uint64 rs1val = readX(a, rs1);
    uint64 u64 = readUint64(a, uint64AddInt32(rs1val, imm));
    if (rd != 0) {
        writeX(a, rd, u64);
    }
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeSD(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "sd");
    int32 imm = operandSimm12(insn);
    uint8 rs1 = operandRs1(insn);
    uint8 rs2 = operandRs2(insn);
    uint64 rs1val = readX(a, rs1);
    uint64 rs2val = readX(a, rs2);
    writeUint64(a, uint64AddInt32(rs1val, imm), rs2val);
    return advancePc(a, pc);
}

template <typename UarchState>
static inline void executeECALL(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "ecall");
    // ECALL conventions
    // a0--a7 are the same as x10--x17
    // syscall is passed in a7
    // arguments are passed in a0--a5
    // return value is in a0 (and maybe also in a1)
    uint64 fn = readX(a, 17); // a7 contains the function number
    if (fn == UARCH_ECALL_FN_HALT) {
        return writeHaltFlag(a, 1);
    }
    if (fn == UARCH_ECALL_FN_PUTCHAR) {
        uint64 c = readX(a, 10);   // a0 contains the character to print
        putCharECALL(a, uint8(c)); // Can be a NOOP in Solidity
        return advancePc(a, pc);
    }
    if (fn == UARCH_ECALL_FN_MARK_DIRTY_PAGE) {
        uint64 paddr = readX(a, 10);             // a0 contains physical address in page to be marked dirty
        uint64 pma_index = readX(a, 11);         // a1 contains a index of PMA where page falls
        markDirtyPageECALL(a, paddr, pma_index); // This MUST be be a NOOP in Solidity
        return advancePc(a, pc);
    }
    if (fn == UARCH_ECALL_FN_WRITE_TLB) {
        uint64 set_index = readX(a, 10);  // a0 contains TLB set (code, read, write)
        uint64 slot_index = readX(a, 11); // a1 contains slot_index to modify
        uint64 vaddr_page = readX(a, 12); // a2 contains vaddr_page to write
        uint64 vp_offset = readX(a, 13);  // a3 contains vp_offset to write
        uint64 pma_index = readX(a, 14);  // a4 contains index of PMA where page falls
        writeTlbECALL(a, set_index, slot_index, vaddr_page, vp_offset,
            pma_index); // WARNING: This CANNOT be a NOOP in Solidity
        return advancePc(a, pc);
    }
    throwRuntimeError(a, "unsupported ecall function");
}

template <typename UarchState>
static inline void executeEBREAK(const UarchState a, uint32 insn, uint64 pc) {
    [[maybe_unused]] auto note = dumpInsn(a, pc, insn, "ebreak");
    throwRuntimeError(a, "uarch aborted");
}

/// \brief Returns true if the opcode field of an instruction matches the provided argument
static inline bool insnMatchOpcode(uint32 insn, uint32 opcode) {
    return ((insn & 0x7f)) == opcode;
}

/// \brief Returns true if the opcode and funct3 fields of an instruction match the provided arguments
static inline bool insnMatchOpcodeFunct3(uint32 insn, uint32 opcode, uint32 funct3) {
    constexpr uint32 mask = (7 << 12) | 0x7f;
    return (insn & mask) == (uint32ShiftLeft(funct3, 12) | opcode);
}

/// \brief Returns true if the opcode, funct3 and funct7 fields of an instruction match the provided arguments
static inline bool insnMatchOpcodeFunct3Funct7(uint32 insn, uint32 opcode, uint32 funct3, uint32 funct7) {
    constexpr uint32 mask = (0x7f << 25) | (7 << 12) | 0x7f;
    return ((insn & mask)) == (uint32ShiftLeft(funct7, 25) | uint32ShiftLeft(funct3, 12) | opcode);
}

/// \brief Returns true if the opcode, funct3 and 6 most significant bits of funct7 fields of an instruction match the
/// provided arguments
static inline bool insnMatchOpcodeFunct3Funct7Sr1(uint32 insn, uint32 opcode, uint32 funct3, uint32 funct7Sr1) {
    constexpr uint32 mask = (0x3f << 26) | (7 << 12) | 0x7f;
    return ((insn & mask)) == (uint32ShiftLeft(funct7Sr1, 26) | uint32ShiftLeft(funct3, 12) | opcode);
}

// Decode and execute one instruction
template <typename UarchState>
static inline void executeInsn(const UarchState a, uint32 insn, uint64 pc) {
    if (insnMatchOpcodeFunct3(insn, 0x13, 0x0)) {
        return executeADDI(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x3, 0x3)) {
        return executeLD(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x63, 0x6)) {
        return executeBLTU(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x63, 0x0)) {
        return executeBEQ(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x13, 0x7)) {
        return executeANDI(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x33, 0x0, 0x0)) {
        return executeADD(a, insn, pc);
    }
    if (insnMatchOpcode(insn, 0x6f)) {
        return executeJAL(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7Sr1(insn, 0x13, 0x1, 0x0)) {
        return executeSLLI(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x33, 0x7, 0x0)) {
        return executeAND(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x23, 0x3)) {
        return executeSD(a, insn, pc);
    }
    if (insnMatchOpcode(insn, 0x37)) {
        return executeLUI(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x67, 0x0)) {
        return executeJALR(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x1b, 0x0)) {
        return executeADDIW(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7Sr1(insn, 0x13, 0x5, 0x0)) {
        return executeSRLI(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x1b, 0x5, 0x0)) {
        return executeSRLIW(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x63, 0x1)) {
        return executeBNE(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x3, 0x2)) {
        return executeLW(a, insn, pc);
    }
    if (insnMatchOpcode(insn, 0x17)) {
        return executeAUIPC(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x63, 0x7)) {
        return executeBGEU(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x3b, 0x0, 0x0)) {
        return executeADDW(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7Sr1(insn, 0x13, 0x5, 0x10)) {
        return executeSRAI(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x33, 0x6, 0x0)) {
        return executeOR(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x1b, 0x5, 0x20)) {
        return executeSRAIW(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x63, 0x5)) {
        return executeBGE(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x33, 0x0, 0x20)) {
        return executeSUB(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x3, 0x4)) {
        return executeLBU(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x1b, 0x1, 0x0)) {
        return executeSLLIW(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x33, 0x5, 0x0)) {
        return executeSRL(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x33, 0x4, 0x0)) {
        return executeXOR(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x23, 0x2)) {
        return executeSW(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x33, 0x1, 0x0)) {
        return executeSLL(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x63, 0x4)) {
        return executeBLT(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x23, 0x0)) {
        return executeSB(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x3b, 0x0, 0x20)) {
        return executeSUBW(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x13, 0x4)) {
        return executeXORI(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x33, 0x5, 0x20)) {
        return executeSRA(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x3, 0x5)) {
        return executeLHU(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x23, 0x1)) {
        return executeSH(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x3b, 0x5, 0x0)) {
        return executeSRLW(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x3, 0x6)) {
        return executeLWU(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x3b, 0x1, 0x0)) {
        return executeSLLW(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x3, 0x0)) {
        return executeLB(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x33, 0x3, 0x0)) {
        return executeSLTU(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x3b, 0x5, 0x20)) {
        return executeSRAW(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x3, 0x1)) {
        return executeLH(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x13, 0x6)) {
        return executeORI(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x13, 0x3)) {
        return executeSLTIU(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3Funct7(insn, 0x33, 0x2, 0x0)) {
        return executeSLT(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0x13, 0x2)) {
        return executeSLTI(a, insn, pc);
    }
    if (insnMatchOpcodeFunct3(insn, 0xf, 0x0)) {
        return executeFENCE(a, insn, pc);
    }
    if (insn == uint32(0x73)) {
        return executeECALL(a, insn, pc);
    }
    if (insn == uint32(0x100073)) {
        return executeEBREAK(a, insn, pc);
    }
    throwRuntimeError(a, "illegal instruction");
}

template <typename UarchState>
UArchStepStatus uarch_step(const UarchState a) {
    // This must be the first read in order to match the first log access in machine::verify_step_uarch
    uint64 cycle = readCycle(a);
    // do not advance if cycle will overflow
    if (cycle == UINT64_MAX) {
        return UArchStepStatus::CycleOverflow;
    }
    // do not advance if machine is halted
    if (readHaltFlag(a) != 0) {
        return UArchStepStatus::UArchHalted;
    }
    // execute next instruction
    uint64 pc = readPc(a);
    uint32 insn = readUint32(a, pc);
    executeInsn(a, insn, pc);
    cycle = cycle + 1;
    writeCycle(a, cycle);
    return UArchStepStatus::Success;
}

// Explicit instantiation for uarch_state_access
template UArchStepStatus uarch_step(const uarch_state_access a);

// Explicit instantiation for uarch_record_state_access
template UArchStepStatus uarch_step(const uarch_record_state_access a);

// Explicit instantiation for uarch_replay_state_access
template UArchStepStatus uarch_step(const uarch_replay_state_access a);

} // namespace cartesi
// NOLINTEND(google-readability-casting,misc-const-correctness,modernize-use-auto,hicpp-use-auto)
