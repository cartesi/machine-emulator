// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

/// @dev This file is generated from C++ by solidity-step/tools/transpile-uarch.lua

pragma solidity ^0.8.30;

import {EmulatorConstants} from "src/EmulatorConstants.sol";
import {StateAccess} from "src/StateAccess.sol";
import {StepLog} from "src/StepLog.sol";

library UArchStep {
    enum UArchStepStatus {
        Success, // one micro instruction was executed successfully
        UArchCycleOverflow, // uarch cycle reached or was already at its maximum value
        UArchHalted // uarch reached or was already at its halted fixed point

    }

    // Memory read/write access

    function readUint64(StepLog.Context memory a, uint64 paddr) private pure returns (uint64) {
        require((paddr & 7) == 0, "misaligned readUint64 address");
        return StateAccess.readWord(a, paddr);
    }

    function readUint32(StepLog.Context memory a, uint64 paddr) private pure returns (uint32) {
        require((paddr & 3) == 0, "misaligned readUint32 address");
        uint64 palign = paddr & ~uint64(7);
        uint32 bitoffset = StateAccess.uint32ShiftLeft(uint32(paddr) & uint32(7), 3);
        uint64 val64 = readUint64(a, palign);
        return uint32(StateAccess.uint64ShiftRight(val64, bitoffset));
    }

    function readUint16(StepLog.Context memory a, uint64 paddr) private pure returns (uint16) {
        require((paddr & 1) == 0, "misaligned readUint16 address");
        uint64 palign = paddr & ~uint64(7);
        uint32 bitoffset = StateAccess.uint32ShiftLeft(uint32(paddr) & uint32(7), 3);
        uint64 val64 = readUint64(a, palign);
        return uint16(StateAccess.uint64ShiftRight(val64, bitoffset));
    }

    function readUint8(StepLog.Context memory a, uint64 paddr) private pure returns (uint8) {
        uint64 palign = paddr & ~uint64(7);
        uint32 bitoffset = StateAccess.uint32ShiftLeft(uint32(paddr) & uint32(7), 3);
        uint64 val64 = readUint64(a, palign);
        return uint8(StateAccess.uint64ShiftRight(val64, bitoffset));
    }

    function writeUint64(StepLog.Context memory a, uint64 paddr, uint64 val) private pure {
        require((paddr & 7) == 0, "misaligned writeUint64 address");
        StateAccess.writeWord(a, paddr, val);
    }

    /// \brief Copies bits from a uint64 word, starting at bit 0, to another uint64 word at the specified bit offset.
    /// \param from Source of bits to copy, starting at offset 0.
    /// \param count Number of bits to copy.
    /// \param to Destination of copy.
    /// \param offset Bit offset in destination to copy bits to.
    /// \return The uint64 word containing the copy result.
    function copyBits(uint32 from, uint32 count, uint64 to, uint32 offset)
        private
        pure
        returns (uint64)
    {
        require(offset + count <= 64, "copyBits count exceeds limit of 64");
        uint64 eraseMask = StateAccess.uint64ShiftLeft(1, count) - 1;
        eraseMask = ~StateAccess.uint64ShiftLeft(eraseMask, offset);
        return StateAccess.uint64ShiftLeft(from, offset) | (to & eraseMask);
    }

    function writeUint32(StepLog.Context memory a, uint64 paddr, uint32 val) private pure {
        require((paddr & 3) == 0, "misaligned writeUint32 address");
        uint64 palign = paddr & ~uint64(7);

        uint32 bitoffset = StateAccess.uint32ShiftLeft(uint32(paddr) & uint32(7), 3);
        uint64 oldval64 = readUint64(a, palign);
        uint64 newval64 = copyBits(val, 32, oldval64, bitoffset);
        writeUint64(a, palign, newval64);
    }

    function writeUint16(StepLog.Context memory a, uint64 paddr, uint16 val) private pure {
        require((paddr & 1) == 0, "misaligned writeUint16 address");
        uint64 palign = paddr & ~uint64(7);
        uint32 bitoffset = StateAccess.uint32ShiftLeft(uint32(paddr) & uint32(7), 3);
        uint64 oldval64 = readUint64(a, palign);
        uint64 newval64 = copyBits(val, 16, oldval64, bitoffset);
        writeUint64(a, palign, newval64);
    }

    function writeUint8(StepLog.Context memory a, uint64 paddr, uint8 val) private pure {
        uint64 palign = paddr & ~uint64(7);
        uint32 bitoffset = StateAccess.uint32ShiftLeft(uint32(paddr) & uint32(7), 3);
        uint64 oldval64 = readUint64(a, palign);
        uint64 newval64 = copyBits(val, 8, oldval64, bitoffset);
        writeUint64(a, palign, newval64);
    }

    // Instruction operand decoders

    function operandRd(uint32 insn) private pure returns (uint8) {
        return uint8(StateAccess.uint32ShiftRight(StateAccess.uint32ShiftLeft(insn, 20), 27));
    }

    function operandRs1(uint32 insn) private pure returns (uint8) {
        return uint8(StateAccess.uint32ShiftRight(StateAccess.uint32ShiftLeft(insn, 12), 27));
    }

    function operandRs2(uint32 insn) private pure returns (uint8) {
        return uint8(StateAccess.uint32ShiftRight(StateAccess.uint32ShiftLeft(insn, 7), 27));
    }

    function operandImm12(uint32 insn) private pure returns (int32) {
        return StateAccess.int32ShiftRight(int32(insn), 20);
    }

    function operandImm20(uint32 insn) private pure returns (int32) {
        return int32(StateAccess.uint32ShiftLeft(StateAccess.uint32ShiftRight(insn, 12), 12));
    }

    function operandJimm20(uint32 insn) private pure returns (int32) {
        int32 a = int32(
            StateAccess.uint32ShiftLeft(uint32(StateAccess.int32ShiftRight(int32(insn), 31)), 20)
        );
        uint32 b = StateAccess.uint32ShiftLeft(
            StateAccess.uint32ShiftRight(StateAccess.uint32ShiftLeft(insn, 1), 22), 1
        );
        uint32 c = StateAccess.uint32ShiftLeft(
            StateAccess.uint32ShiftRight(StateAccess.uint32ShiftLeft(insn, 11), 31), 11
        );
        uint32 d = StateAccess.uint32ShiftLeft(
            StateAccess.uint32ShiftRight(StateAccess.uint32ShiftLeft(insn, 12), 24), 12
        );
        return int32(uint32(a) | b | c | d);
    }

    function operandShamt5(uint32 insn) private pure returns (int32) {
        return int32(StateAccess.uint32ShiftRight(StateAccess.uint32ShiftLeft(insn, 7), 27));
    }

    function operandShamt6(uint32 insn) private pure returns (int32) {
        return int32(StateAccess.uint32ShiftRight(StateAccess.uint32ShiftLeft(insn, 6), 26));
    }

    function operandSbimm12(uint32 insn) private pure returns (int32) {
        int32 a = int32(
            StateAccess.uint32ShiftLeft(uint32(StateAccess.int32ShiftRight(int32(insn), 31)), 12)
        );
        uint32 b = StateAccess.uint32ShiftLeft(
            StateAccess.uint32ShiftRight(StateAccess.uint32ShiftLeft(insn, 1), 26), 5
        );
        uint32 c = StateAccess.uint32ShiftLeft(
            StateAccess.uint32ShiftRight(StateAccess.uint32ShiftLeft(insn, 20), 28), 1
        );
        uint32 d = StateAccess.uint32ShiftLeft(
            StateAccess.uint32ShiftRight(StateAccess.uint32ShiftLeft(insn, 24), 31), 11
        );
        return int32(uint32(a) | b | c | d);
    }

    function operandSimm12(uint32 insn) private pure returns (int32) {
        return int32(
            StateAccess.uint32ShiftLeft(uint32(StateAccess.int32ShiftRight(int32(insn), 25)), 5)
                | StateAccess.uint32ShiftRight(StateAccess.uint32ShiftLeft(insn, 20), 27)
        );
    }

    // Execute instruction

    function advancePc(StepLog.Context memory a, uint64 pc) private pure {
        uint64 newPc = StateAccess.uint64AddUint64(pc, 4);
        return StateAccess.writePc(a, newPc);
    }

    function branch(StepLog.Context memory a, uint64 pc) private pure {
        return StateAccess.writePc(a, pc);
    }

    function executeLUI(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        int32 imm = operandImm20(insn);
        if (rd != 0) {
            StateAccess.writeX(a, rd, StateAccess.int32ToUint64(imm));
        }
        return advancePc(a, pc);
    }

    function executeAUIPC(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm20(insn);
        uint8 rd = operandRd(insn);
        if (rd != 0) {
            StateAccess.writeX(a, rd, StateAccess.uint64AddInt32(pc, imm));
        }
        return advancePc(a, pc);
    }

    function executeJAL(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandJimm20(insn);
        uint8 rd = operandRd(insn);
        if (rd != 0) {
            StateAccess.writeX(a, rd, StateAccess.uint64AddUint64(pc, 4));
        }
        return branch(a, StateAccess.uint64AddInt32(pc, imm));
    }

    function executeJALR(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        if (rd != 0) {
            StateAccess.writeX(a, rd, StateAccess.uint64AddUint64(pc, 4));
        }
        return branch(a, StateAccess.uint64AddInt32(rs1val, imm) & (~uint64(1)));
    }

    function executeBEQ(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandSbimm12(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        uint64 rs2val = StateAccess.readX(a, rs2);
        if (rs1val == rs2val) {
            return branch(a, StateAccess.uint64AddInt32(pc, imm));
        }
        return advancePc(a, pc);
    }

    function executeBNE(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandSbimm12(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        uint64 rs2val = StateAccess.readX(a, rs2);
        if (rs1val != rs2val) {
            return branch(a, StateAccess.uint64AddInt32(pc, imm));
        }
        return advancePc(a, pc);
    }

    function executeBLT(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandSbimm12(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        int64 rs1val = int64(StateAccess.readX(a, rs1));
        int64 rs2val = int64(StateAccess.readX(a, rs2));
        if (rs1val < rs2val) {
            return branch(a, StateAccess.uint64AddInt32(pc, imm));
        }
        return advancePc(a, pc);
    }

    function executeBGE(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandSbimm12(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        int64 rs1val = int64(StateAccess.readX(a, rs1));
        int64 rs2val = int64(StateAccess.readX(a, rs2));
        if (rs1val >= rs2val) {
            return branch(a, StateAccess.uint64AddInt32(pc, imm));
        }
        return advancePc(a, pc);
    }

    function executeBLTU(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandSbimm12(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        uint64 rs2val = StateAccess.readX(a, rs2);
        if (rs1val < rs2val) {
            return branch(a, StateAccess.uint64AddInt32(pc, imm));
        }
        return advancePc(a, pc);
    }

    function executeBGEU(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandSbimm12(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        uint64 rs2val = StateAccess.readX(a, rs2);
        if (rs1val >= rs2val) {
            return branch(a, StateAccess.uint64AddInt32(pc, imm));
        }
        return advancePc(a, pc);
    }

    function executeLB(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        int8 i8 = int8(readUint8(a, StateAccess.uint64AddInt32(rs1val, imm)));
        if (rd != 0) {
            StateAccess.writeX(a, rd, StateAccess.int8ToUint64(i8));
        }
        return advancePc(a, pc);
    }

    function executeLHU(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        uint16 u16 = readUint16(a, StateAccess.uint64AddInt32(rs1val, imm));
        if (rd != 0) {
            StateAccess.writeX(a, rd, u16);
        }
        return advancePc(a, pc);
    }

    function executeLH(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        int16 i16 = int16(readUint16(a, StateAccess.uint64AddInt32(rs1val, imm)));
        if (rd != 0) {
            StateAccess.writeX(a, rd, StateAccess.int16ToUint64(i16));
        }
        return advancePc(a, pc);
    }

    function executeLW(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        int32 i32 = int32(readUint32(a, StateAccess.uint64AddInt32(rs1val, imm)));
        if (rd != 0) {
            StateAccess.writeX(a, rd, StateAccess.int32ToUint64(i32));
        }
        return advancePc(a, pc);
    }

    function executeLBU(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        uint8 u8 = readUint8(a, StateAccess.uint64AddInt32(rs1val, imm));
        if (rd != 0) {
            StateAccess.writeX(a, rd, u8);
        }
        return advancePc(a, pc);
    }

    function executeSB(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandSimm12(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        uint64 rs2val = StateAccess.readX(a, rs2);
        writeUint8(a, StateAccess.uint64AddInt32(rs1val, imm), uint8(rs2val));
        return advancePc(a, pc);
    }

    function executeSH(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandSimm12(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        uint64 rs2val = StateAccess.readX(a, rs2);
        writeUint16(a, StateAccess.uint64AddInt32(rs1val, imm), uint16(rs2val));
        return advancePc(a, pc);
    }

    function executeSW(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandSimm12(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        uint32 rs2val = uint32(StateAccess.readX(a, rs2));
        writeUint32(a, StateAccess.uint64AddInt32(rs1val, imm), rs2val);
        return advancePc(a, pc);
    }

    function executeADDI(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            int64 val = StateAccess.int64AddInt64(int64(rs1val), int64(imm));
            StateAccess.writeX(a, rd, uint64(val));
        }
        return advancePc(a, pc);
    }

    function executeADDIW(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        int32 rs1val = StateAccess.uint64ToInt32(StateAccess.readX(a, rs1));
        if (rd != 0) {
            int32 val = StateAccess.int32AddInt32(rs1val, imm);
            StateAccess.writeX(a, rd, StateAccess.int32ToUint64(val));
        }
        return advancePc(a, pc);
    }

    function executeSLTI(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        if (rd != 0) {
            int64 rs1val = int64(StateAccess.readX(a, rs1));
            if (rs1val < imm) {
                StateAccess.writeX(a, rd, 1);
            } else {
                StateAccess.writeX(a, rd, 0);
            }
        }
        return advancePc(a, pc);
    }

    function executeSLTIU(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            if (rs1val < StateAccess.int32ToUint64(imm)) {
                StateAccess.writeX(a, rd, 1);
            } else {
                StateAccess.writeX(a, rd, 0);
            }
        }
        return advancePc(a, pc);
    }

    function executeXORI(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            StateAccess.writeX(a, rd, rs1val ^ StateAccess.int32ToUint64(imm));
        }
        return advancePc(a, pc);
    }

    function executeORI(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            StateAccess.writeX(a, rd, rs1val | StateAccess.int32ToUint64(imm));
        }
        return advancePc(a, pc);
    }

    function executeANDI(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            StateAccess.writeX(a, rd, rs1val & StateAccess.int32ToUint64(imm));
        }
        return advancePc(a, pc);
    }

    function executeSLLI(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandShamt6(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            StateAccess.writeX(a, rd, StateAccess.uint64ShiftLeft(rs1val, uint32(imm)));
        }
        return advancePc(a, pc);
    }

    function executeSLLIW(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandShamt5(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint32 rs1val = uint32(StateAccess.readX(a, rs1));
        if (rd != 0) {
            StateAccess.writeX(
                a,
                rd,
                StateAccess.int32ToUint64(int32(StateAccess.uint32ShiftLeft(rs1val, uint32(imm))))
            );
        }
        return advancePc(a, pc);
    }

    function executeSRLI(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandShamt6(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            StateAccess.writeX(a, rd, StateAccess.uint64ShiftRight(rs1val, uint32(imm)));
        }
        return advancePc(a, pc);
    }

    function executeSRLW(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        uint32 rs1val = uint32(StateAccess.readX(a, rs1));
        uint32 rs2val = uint32(StateAccess.readX(a, rs2));
        int32 rdval = int32(StateAccess.uint32ShiftRight(rs1val, rs2val));
        if (rd != 0) {
            StateAccess.writeX(a, rd, StateAccess.int32ToUint64(rdval));
        }
        return advancePc(a, pc);
    }

    function executeSRLIW(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandShamt5(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint32 rs1val = uint32(StateAccess.readX(a, rs1));
        int32 rdval = int32(StateAccess.uint32ShiftRight(rs1val, uint32(imm)));
        if (rd != 0) {
            StateAccess.writeX(a, rd, StateAccess.int32ToUint64(rdval));
        }
        return advancePc(a, pc);
    }

    function executeSRAI(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandShamt6(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            StateAccess.writeX(
                a, rd, uint64(StateAccess.int64ShiftRight(int64(rs1val), uint32(imm)))
            );
        }
        return advancePc(a, pc);
    }

    function executeSRAIW(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandShamt5(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        int32 rs1val = StateAccess.uint64ToInt32(StateAccess.readX(a, rs1));
        if (rd != 0) {
            StateAccess.writeX(
                a, rd, StateAccess.int32ToUint64(StateAccess.int32ShiftRight(rs1val, uint32(imm)))
            );
        }
        return advancePc(a, pc);
    }

    function executeADD(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            uint64 rs2val = StateAccess.readX(a, rs2);
            StateAccess.writeX(a, rd, StateAccess.uint64AddUint64(rs1val, rs2val));
        }
        return advancePc(a, pc);
    }

    function executeADDW(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        int32 rs1val = StateAccess.uint64ToInt32(StateAccess.readX(a, rs1));
        int32 rs2val = StateAccess.uint64ToInt32(StateAccess.readX(a, rs2));
        if (rd != 0) {
            int32 val = StateAccess.int32AddInt32(rs1val, rs2val);
            StateAccess.writeX(a, rd, StateAccess.int32ToUint64(val));
        }
        return advancePc(a, pc);
    }

    function executeSUB(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            uint64 rs2val = StateAccess.readX(a, rs2);
            StateAccess.writeX(a, rd, StateAccess.uint64SubUint64(rs1val, rs2val));
        }
        return advancePc(a, pc);
    }

    function executeSUBW(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        int32 rs1val = StateAccess.uint64ToInt32(StateAccess.readX(a, rs1));
        int32 rs2val = StateAccess.uint64ToInt32(StateAccess.readX(a, rs2));
        if (rd != 0) {
            int32 val = StateAccess.int32SubInt32(rs1val, rs2val);
            StateAccess.writeX(a, rd, StateAccess.int32ToUint64(val));
        }
        return advancePc(a, pc);
    }

    function executeSLL(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            uint32 rs2val = uint32(StateAccess.readX(a, rs2));
            StateAccess.writeX(a, rd, StateAccess.uint64ShiftLeft(rs1val, rs2val));
        }
        return advancePc(a, pc);
    }

    function executeSLLW(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        uint32 rs1val = uint32(StateAccess.readX(a, rs1));
        uint32 rs2val = uint32(StateAccess.readX(a, rs2));
        int32 rdval = int32(StateAccess.uint32ShiftLeft(rs1val, rs2val));
        if (rd != 0) {
            StateAccess.writeX(a, rd, StateAccess.int32ToUint64(rdval));
        }
        return advancePc(a, pc);
    }

    function executeSLT(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        if (rd != 0) {
            int64 rs1val = int64(StateAccess.readX(a, rs1));
            int64 rs2val = int64(StateAccess.readX(a, rs2));
            uint64 rdval = 0;
            if (rs1val < rs2val) {
                rdval = 1;
            }
            StateAccess.writeX(a, rd, rdval);
        }
        return advancePc(a, pc);
    }

    function executeSLTU(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            uint64 rs2val = StateAccess.readX(a, rs2);
            uint64 rdval = 0;
            if (rs1val < rs2val) {
                rdval = 1;
            }
            StateAccess.writeX(a, rd, rdval);
        }
        return advancePc(a, pc);
    }

    function executeXOR(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            uint64 rs2val = StateAccess.readX(a, rs2);
            StateAccess.writeX(a, rd, rs1val ^ rs2val);
        }
        return advancePc(a, pc);
    }

    function executeSRL(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            uint64 rs2val = StateAccess.readX(a, rs2);
            StateAccess.writeX(a, rd, StateAccess.uint64ShiftRight(rs1val, uint32(rs2val)));
        }
        return advancePc(a, pc);
    }

    function executeSRA(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        if (rd != 0) {
            int64 rs1val = int64(StateAccess.readX(a, rs1));
            uint32 rs2val = uint32(StateAccess.readX(a, rs2));
            StateAccess.writeX(a, rd, uint64(StateAccess.int64ShiftRight(rs1val, rs2val)));
        }
        return advancePc(a, pc);
    }

    function executeSRAW(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        int32 rs1val = StateAccess.uint64ToInt32(StateAccess.readX(a, rs1));
        uint32 rs2val = uint32(StateAccess.readX(a, rs2));
        int32 rdval = StateAccess.int32ShiftRight(rs1val, rs2val);
        if (rd != 0) {
            StateAccess.writeX(a, rd, StateAccess.int32ToUint64(rdval));
        }
        return advancePc(a, pc);
    }

    function executeOR(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            uint64 rs2val = StateAccess.readX(a, rs2);
            StateAccess.writeX(a, rd, rs1val | rs2val);
        }
        return advancePc(a, pc);
    }

    function executeAND(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        if (rd != 0) {
            uint64 rs1val = StateAccess.readX(a, rs1);
            uint64 rs2val = StateAccess.readX(a, rs2);
            StateAccess.writeX(a, rd, rs1val & rs2val);
        }
        return advancePc(a, pc);
    }

    function executeFENCE(StepLog.Context memory a, uint32, uint64 pc) private pure {
        return advancePc(a, pc);
    }

    function executeLWU(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        uint32 u32 = readUint32(a, StateAccess.uint64AddInt32(rs1val, imm));
        if (rd != 0) {
            StateAccess.writeX(a, rd, u32);
        }
        return advancePc(a, pc);
    }

    function executeLD(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandImm12(insn);
        uint8 rd = operandRd(insn);
        uint8 rs1 = operandRs1(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        uint64 u64 = readUint64(a, StateAccess.uint64AddInt32(rs1val, imm));
        if (rd != 0) {
            StateAccess.writeX(a, rd, u64);
        }
        return advancePc(a, pc);
    }

    function executeSD(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
        int32 imm = operandSimm12(insn);
        uint8 rs1 = operandRs1(insn);
        uint8 rs2 = operandRs2(insn);
        uint64 rs1val = StateAccess.readX(a, rs1);
        uint64 rs2val = StateAccess.readX(a, rs2);
        writeUint64(a, StateAccess.uint64AddInt32(rs1val, imm), rs2val);
        return advancePc(a, pc);
    }

    function executeECALL(StepLog.Context memory a, uint32, uint64 pc) private pure {
        // ECALL conventions
        // a0--a7 are the same as x10--x17
        // syscall is passed in a7
        // arguments are passed in a0--a5
        // return value is in a0 (and maybe also in a1)
        uint64 fn = StateAccess.readX(a, 17); // a7 contains the function number
        if (fn == EmulatorConstants.UARCH_ECALL_FN_HALT) {
            return StateAccess.writeHalt(a, 1);
        }
        if (fn == EmulatorConstants.UARCH_ECALL_FN_PUTCHAR) {
            uint64 c = StateAccess.readX(a, 10); // a0 contains the character to print
            StateAccess.putCharECALL(a, uint8(c)); // Can be a NOOP in Solidity
            return advancePc(a, pc);
        }
        if (fn == EmulatorConstants.UARCH_ECALL_FN_WRITE_TLB) {
            uint64 set_index = StateAccess.readX(a, 10); // a0 contains TLB set (code, read, write)
            uint64 slot_index = StateAccess.readX(a, 11); // a1 contains slot_index to modify
            uint64 vaddr_page = StateAccess.readX(a, 12); // a2 contains vaddr_page to write
            uint64 vp_offset = StateAccess.readX(a, 13); // a3 contains vp_offset to write
            uint64 pma_index = StateAccess.readX(a, 14); // a4 contains index of PMA where page falls
            StateAccess.writeTlbECALL(a, set_index, slot_index, vaddr_page, vp_offset, pma_index); // WARNING: This CANNOT be a NOOP in Solidity
            return advancePc(a, pc);
        }
        StateAccess.throwRuntimeError(a, "unsupported ecall function");
    }

    function executeEBREAK(StepLog.Context memory a, uint32, uint64) private pure {
        StateAccess.throwRuntimeError(a, "uarch aborted");
    }

    /// \brief Returns true if the opcode field of an instruction matches the provided argument
    function insnMatchOpcode(uint32 insn, uint32 opcode) private pure returns (bool) {
        return (insn & 0x7f) == opcode;
    }

    /// \brief Returns true if the opcode and funct3 fields of an instruction match the provided arguments
    function insnMatchOpcodeFunct3(uint32 insn, uint32 opcode, uint32 funct3)
        private
        pure
        returns (bool)
    {
        uint32 mask = (7 << 12) | 0x7f;
        return (insn & mask) == (StateAccess.uint32ShiftLeft(funct3, 12) | opcode);
    }

    /// \brief Returns true if the opcode, funct3 and funct7 fields of an instruction match the provided arguments
    function insnMatchOpcodeFunct3Funct7(uint32 insn, uint32 opcode, uint32 funct3, uint32 funct7)
        private
        pure
        returns (bool)
    {
        uint32 mask = (0x7f << 25) | (7 << 12) | 0x7f;
        return (insn & mask)
            == (
                StateAccess.uint32ShiftLeft(funct7, 25) | StateAccess.uint32ShiftLeft(funct3, 12)
                    | opcode
            );
    }

    /// \brief Returns true if the opcode, funct3 and 6 most significant bits of funct7 fields of an instruction match the
    /// provided arguments
    function insnMatchOpcodeFunct3Funct7Sr1(
        uint32 insn,
        uint32 opcode,
        uint32 funct3,
        uint32 funct7Sr1
    ) private pure returns (bool) {
        uint32 mask = (0x3f << 26) | (7 << 12) | 0x7f;
        return (insn & mask)
            == (
                StateAccess.uint32ShiftLeft(funct7Sr1, 26) | StateAccess.uint32ShiftLeft(funct3, 12)
                    | opcode
            );
    }

    // Decode and execute one instruction

    function executeInsn(StepLog.Context memory a, uint32 insn, uint64 pc) private pure {
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
        StateAccess.throwRuntimeError(a, "illegal instruction");
    }

    function uarchStep(StepLog.Context memory a) internal pure returns (UArchStepStatus) {
        // Report the derived overflow fixed point before all other break reasons.
        uint64 cycle = StateAccess.readCycle(a);
        if (cycle >= EmulatorConstants.UARCH_CYCLE_MAX) {
            return UArchStepStatus.UArchCycleOverflow;
        }
        // Report an existing ordinary halt fixed point.
        if (StateAccess.readHalt(a) != 0) {
            return UArchStepStatus.UArchHalted;
        }
        // Execute next instruction
        uint64 pc = StateAccess.readPc(a);
        uint32 insn = readUint32(a, pc);
        executeInsn(a, insn, pc);
        cycle = cycle + 1;
        StateAccess.writeCycle(a, cycle);
        // Overflow has precedence when this step reaches the cycle limit.
        if (cycle >= EmulatorConstants.UARCH_CYCLE_MAX) {
            return UArchStepStatus.UArchCycleOverflow;
        }
        // ECALL is the only instruction that can halt the uarch.
        if (insn == uint32(0x73)) {
            if (StateAccess.readHalt(a) != 0) {
                return UArchStepStatus.UArchHalted;
            }
        }
        return UArchStepStatus.Success;
    }
}
