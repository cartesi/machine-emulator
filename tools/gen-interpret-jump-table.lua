--[[
This file is used to generate interpret-jump-table.h header used in the interpreter.
It's purpose is to generate a big jump table covering most RISC-V instructions,
so we can decode most instructions with a single jump.
]]

-- List of RISC-V instructions taken from RISC-V spec
local insns = {
    -- RV32I
    { bits = "_________________________0110111", name = "LUI", rd0=true },
    { bits = "_________________________0010111", name = "AUIPC", rd0=true },
    { bits = "_________________________1101111", name = "JAL", rd0=true },
    { bits = "_________________000_____1100111", name = "JALR", rd0=true },
    { bits = "_________________000_____1100011", name = "BEQ" },
    { bits = "_________________001_____1100011", name = "BNE" },
    { bits = "_________________100_____1100011", name = "BLT" },
    { bits = "_________________101_____1100011", name = "BGE" },
    { bits = "_________________110_____1100011", name = "BLTU" },
    { bits = "_________________111_____1100011", name = "BGEU" },
    { bits = "_________________000_____0000011", name = "LB" },
    { bits = "_________________001_____0000011", name = "LH" },
    { bits = "_________________010_____0000011", name = "LW" },
    { bits = "_________________100_____0000011", name = "LBU" },
    { bits = "_________________101_____0000011", name = "LHU" },
    { bits = "_________________000_____0100011", name = "SB" },
    { bits = "_________________001_____0100011", name = "SH" },
    { bits = "_________________010_____0100011", name = "SW" },
    { bits = "_________________000_____0010011", name = "ADDI", rd0=true },
    { bits = "_________________010_____0010011", name = "SLTI", rd0=true },
    { bits = "_________________011_____0010011", name = "SLTIU", rd0=true },
    { bits = "_________________100_____0010011", name = "XORI", rd0=true },
    { bits = "_________________110_____0010011", name = "ORI", rd0=true },
    { bits = "_________________111_____0010011", name = "ANDI", rd0=true },
    { bits = "000000___________001_____0010011", name = "SLLI", rd0=true },
    { bits = "000000___________101_____0010011", name = "SRLI", rd0=true },
    { bits = "010000___________101_____0010011", name = "SRAI", rd0=true },
    { bits = "0000000__________000_____0110011", name = "ADD" },
    { bits = "0100000__________000_____0110011", name = "SUB" },
    { bits = "0000000__________001_____0110011", name = "SLL" },
    { bits = "0000000__________010_____0110011", name = "SLT" },
    { bits = "0000000__________011_____0110011", name = "SLTU" },
    { bits = "0000000__________100_____0110011", name = "XOR" },
    { bits = "0000000__________101_____0110011", name = "SRL" },
    { bits = "0100000__________101_____0110011", name = "SRA" },
    { bits = "0000000__________110_____0110011", name = "OR" },
    { bits = "0000000__________111_____0110011", name = "AND" },
    { bits = "_________________000_____0001111", name = "FENCE" },
    { bits = "00000000000000000000000001110011", name = "ECALL" },
    { bits = "00000000000100000000000001110011", name = "EBREAK" },

    -- RV64I
    { bits = "_________________110_____0000011", name = "LWU" },
    { bits = "_________________011_____0000011", name = "LD" },
    { bits = "_________________011_____0100011", name = "SD" },
    { bits = "_________________000_____0011011", name = "ADDIW", rd0=true },
    { bits = "0000000__________001_____0011011", name = "SLLIW", rd0=true },
    { bits = "0000000__________101_____0011011", name = "SRLIW", rd0=true },
    { bits = "0100000__________101_____0011011", name = "SRAIW", rd0=true },
    { bits = "0000000__________000_____0111011", name = "ADDW" },
    { bits = "0100000__________000_____0111011", name = "SUBW" },
    { bits = "0000000__________001_____0111011", name = "SLLW" },
    { bits = "0000000__________101_____0111011", name = "SRLW" },
    { bits = "0100000__________101_____0111011", name = "SRAW" },

    -- RV32M extension
    { bits = "0000001__________000_____0110011", name = "MUL" },
    { bits = "0000001__________001_____0110011", name = "MULH" },
    { bits = "0000001__________010_____0110011", name = "MULHSU" },
    { bits = "0000001__________011_____0110011", name = "MULHU" },
    { bits = "0000001__________100_____0110011", name = "DIV" },
    { bits = "0000001__________101_____0110011", name = "DIVU" },
    { bits = "0000001__________110_____0110011", name = "REM" },
    { bits = "0000001__________111_____0110011", name = "REMU" },

    -- RV64M
    { bits = "0000001__________000_____0111011", name = "MULW" },
    { bits = "0000001__________100_____0111011", name = "DIVW" },
    { bits = "0000001__________101_____0111011", name = "DIVUW" },
    { bits = "0000001__________110_____0111011", name = "REMW" },
    { bits = "0000001__________111_____0111011", name = "REMUW" },

    -- RV32A
    { bits = "00010__00000_____010_____0101111", name = "LR.W" },
    { bits = "00011____________010_____0101111", name = "SC.W" },
    { bits = "00001____________010_____0101111", name = "AMOSWAP.W" },
    { bits = "00000____________010_____0101111", name = "AMOADD.W" },
    { bits = "00100____________010_____0101111", name = "AMOXOR.W" },
    { bits = "01100____________010_____0101111", name = "AMOAND.W" },
    { bits = "01000____________010_____0101111", name = "AMOOR.W" },
    { bits = "10000____________010_____0101111", name = "AMOMIN.W" },
    { bits = "10100____________010_____0101111", name = "AMOMAX.W" },
    { bits = "11000____________010_____0101111", name = "AMOMINU.W" },
    { bits = "11100____________010_____0101111", name = "AMOMAXU.W" },

    -- RV64A
    { bits = "00010__00000_____011_____0101111", name = "LR.D" },
    { bits = "00011____________011_____0101111", name = "SC.D" },
    { bits = "00001____________011_____0101111", name = "AMOSWAP.D" },
    { bits = "00000____________011_____0101111", name = "AMOADD.D" },
    { bits = "00100____________011_____0101111", name = "AMOXOR.D" },
    { bits = "01100____________011_____0101111", name = "AMOAND.D" },
    { bits = "01000____________011_____0101111", name = "AMOOR.D" },
    { bits = "10000____________011_____0101111", name = "AMOMIN.D" },
    { bits = "10100____________011_____0101111", name = "AMOMAX.D" },
    { bits = "11000____________011_____0101111", name = "AMOMINU.D" },
    { bits = "11100____________011_____0101111", name = "AMOMAXU.D" },

    -- RV32F extension
    { bits = "_________________010_____0000111", name = "FLW" },
    { bits = "_________________010_____0100111", name = "FSW" },
    { bits = "_____00__________________1000011", name = "FMADD.S", rm = true },
    { bits = "_____00__________________1000111", name = "FMSUB.S", rm = true },
    { bits = "_____00__________________1001011", name = "FNMSUB.S", rm = true },
    { bits = "_____00__________________1001111", name = "FNMADD.S", rm = true },
    { bits = "0000000__________________1010011", name = "FADD.S", rm = true },
    { bits = "0000100__________________1010011", name = "FSUB.S", rm = true },
    { bits = "0001000__________________1010011", name = "FMUL.S", rm = true },
    { bits = "0001100__________________1010011", name = "FDIV.S", rm = true },
    { bits = "010110000000_____________1010011", name = "FSQRT.S", rm = true },
    { bits = "0010000__________000_____1010011", name = "FSGNJ.S" },
    { bits = "0010000__________001_____1010011", name = "FSGNJN.S" },
    { bits = "0010000__________010_____1010011", name = "FSGNJX.S" },
    { bits = "0010100__________000_____1010011", name = "FMIN.S" },
    { bits = "0010100__________001_____1010011", name = "FMAX.S" },
    { bits = "110000000000_____________1010011", name = "FCVT.W.S", rm = true },
    { bits = "110000000001_____________1010011", name = "FCVT.WU.S", rm = true },
    { bits = "111000000000_____000_____1010011", name = "FMV.X.W" },
    { bits = "1010000__________010_____1010011", name = "FEQ.S" },
    { bits = "1010000__________001_____1010011", name = "FLT.S" },
    { bits = "1010000__________000_____1010011", name = "FLE.S" },
    { bits = "111000000000_____001_____1010011", name = "FCLASS.S" },
    { bits = "110100000000_____________1010011", name = "FCVT.S.W", rm = true },
    { bits = "110100000001_____________1010011", name = "FCVT.S.WU", rm = true },
    { bits = "111100000000_____000_____1010011", name = "FMV.W.X" },

    -- RV64F
    { bits = "110000000010_____________1010011", name = "FCVT.L.S", rm = true },
    { bits = "110000000011_____________1010011", name = "FCVT.LU.S", rm = true },
    { bits = "110100000010_____________1010011", name = "FCVT.S.L", rm = true },
    { bits = "110100000011_____________1010011", name = "FCVT.S.LU", rm = true },

    -- RV32D
    { bits = "_________________011_____0000111", name = "FLD" },
    { bits = "_________________011_____0100111", name = "FSD" },
    { bits = "_____01__________________1000011", name = "FMADD.D", rm = true },
    { bits = "_____01__________________1000111", name = "FMSUB.D", rm = true },
    { bits = "_____01__________________1001011", name = "FNMSUB.D", rm = true },
    { bits = "_____01__________________1001111", name = "FNMADD.D", rm = true },
    { bits = "0000001__________________1010011", name = "FADD.D", rm = true },
    { bits = "0000101__________________1010011", name = "FSUB.D", rm = true },
    { bits = "0001001__________________1010011", name = "FMUL.D", rm = true },
    { bits = "0001101__________________1010011", name = "FDIV.D", rm = true },
    { bits = "010110100000_____________1010011", name = "FSQRT.D", rm = true },
    { bits = "0010001__________000_____1010011", name = "FSGNJ.D" },
    { bits = "0010001__________001_____1010011", name = "FSGNJN.D" },
    { bits = "0010001__________010_____1010011", name = "FSGNJX.D" },
    { bits = "0010101__________000_____1010011", name = "FMIN.D" },
    { bits = "0010101__________001_____1010011", name = "FMAX.D" },
    { bits = "010000000001_____________1010011", name = "FCVT.S.D", rm = true },
    { bits = "010000100000_____________1010011", name = "FCVT.D.S", rm = true },
    { bits = "1010001__________010_____1010011", name = "FEQ.D" },
    { bits = "1010001__________001_____1010011", name = "FLT.D" },
    { bits = "1010001__________000_____1010011", name = "FLE.D" },
    { bits = "111000100000_____001_____1010011", name = "FCLASS.D", rm = true },
    { bits = "110000100000_____________1010011", name = "FCVT.W.D", rm = true },
    { bits = "110000100001_____________1010011", name = "FCVT.WU.D", rm = true },
    { bits = "110100100000_____________1010011", name = "FCVT.D.W", rm = true },
    { bits = "110100100001_____________1010011", name = "FCVT.D.WU", rm = true },
    -- RV64D
    { bits = "110000100010_____________1010011", name = "FCVT.L.D", rm = true },
    { bits = "110000100011_____________1010011", name = "FCVT.LU.D", rm = true },
    { bits = "111000100000_____000_____1010011", name = "FMV.X.D" },
    { bits = "110100100010_____________1010011", name = "FCVT.D.L", rm = true },
    { bits = "110100100011_____________1010011", name = "FCVT.D.LU", rm = true },
    { bits = "111100100000_____000_____1010011", name = "FMV.D.X" },

    -- Zifencei extension
    { bits = "_________________001_____0001111", name = "FENCE.I" },

    -- Zicsr extension
    { bits = "_________________001_____1110011", name = "CSRRW" },
    { bits = "_________________010_____1110011", name = "CSRRS" },
    { bits = "_________________011_____1110011", name = "CSRRC" },
    { bits = "_________________101_____1110011", name = "CSRRWI" },
    { bits = "_________________110_____1110011", name = "CSRRSI" },
    { bits = "_________________111_____1110011", name = "CSRRCI" },

    -- Privileged
    { bits = "00010000001000000000000001110011", name = "SRET" },
    { bits = "00110000001000000000000001110011", name = "MRET" },
    { bits = "01110000001000000000000001110011", name = "MNRET" },
    { bits = "00010000010100000000000001110011", name = "WFI" },
    { bits = "0001001__________000000001110011", name = "SFENCE.VMA" },

    -- RV64C
    -- C.Q0
    { bits = "________________000___________00", name = "C.ADDI4SPN" },
    { bits = "________________001___________00", name = "C.FLD" },
    { bits = "________________010___________00", name = "C.LW" },
    { bits = "________________011___________00", name = "C.LD" },
    { bits = "________________101___________00", name = "C.FSD" },
    { bits = "________________110___________00", name = "C.SW" },
    { bits = "________________111___________00", name = "C.SD" },
    -- C.Q1
    { bits = "________________000___________01", name = "C.Q1_SET0" }, -- C.NOP/C.ADDI
    { bits = "________________001___________01", name = "C.ADDIW" },
    { bits = "________________010___________01", name = "C.LI" },
    { bits = "________________011___________01", name = "C.Q1_SET1" }, -- C.ADDI16SP/C.LUI
    { bits = "________________100___________01", name = "C.Q1_SET2" }, -- C.SRLI/C.SRAI/C.SRAI64/C.ANDI/C.SUB/C.XOR/C.OR/C.AND/C.SUBW/C.ADDW
    { bits = "________________101___________01", name = "C.J" },
    { bits = "________________110___________01", name = "C.BEQZ" },
    { bits = "________________111___________01", name = "C.BNEZ" },
    -- C.Q2
    { bits = "________________000___________10", name = "C.SLLI" },
    { bits = "________________001___________10", name = "C.FLDSP" },
    { bits = "________________010___________10", name = "C.LWSP" },
    { bits = "________________011___________10", name = "C.LDSP" },
    { bits = "________________100___________10", name = "C.Q2_SET0" }, -- C.JR/C.MV/C.EBREAK/C.JALR/C.ADD
    { bits = "________________101___________10", name = "C.FSDSP" },
    { bits = "________________110___________10", name = "C.SWSP" },
    { bits = "________________111___________10", name = "C.SDSP" },
}

-- Replace FD instructions that needs rounding discarding invalid round modes
local valid_rms = {
    "000", -- rne
    "001", -- rtz
    "010", -- rdn
    "011", -- rup
    "100", -- rmm
    "111", -- dyn
}
for _, insn in ipairs(insns) do
    if insn.rm then
        local lbits, rbits = insn.bits:sub(1, 17), insn.bits:sub(21, 32)
        insn.bits = lbits .. valid_rms[1] .. rbits
        insn.rm = nil
        for i = 2, #valid_rms do
            table.insert(insns, { bits = lbits .. valid_rms[i] .. rbits, name = insn.name })
        end
    end
end

local group_names = {
    -- I
    ["ADD|SUB|MUL"] = "ADD_MUL_SUB",
    ["ADDW|SUBW|MULW"] = "ADDW_MULW_SUBW",
    ["SRL|SRA|DIVU"] = "SRL_DIVU_SRA",
    ["SRLW|SRAW|DIVUW"] = "SRLW_DIVUW_SRAW",
    -- A
    ["LR.W|SC.W|AMOSWAP.W|AMOADD.W|AMOXOR.W|AMOAND.W|AMOOR.W|AMOMIN.W|AMOMAX.W|AMOMINU.W|AMOMAXU.W"] = "AMO_W",
    ["LR.D|SC.D|AMOSWAP.D|AMOADD.D|AMOXOR.D|AMOAND.D|AMOOR.D|AMOMIN.D|AMOMAX.D|AMOMINU.D|AMOMAXU.D"] = "AMO_D",
    -- FD
    ["FMADD.S|FMADD.D"] = "FMADD",
    ["FMSUB.S|FMSUB.D"] = "FMSUB",
    ["FNMADD.S|FNMADD.D"] = "FNMADD",
    ["FNMSUB.S|FNMSUB.D"] = "FNMSUB",
    ["FADD.S|FSUB.S|FMUL.S|FDIV.S|FSQRT.S|FSGNJ.S|FMIN.S|FCVT.W.S|FCVT.WU.S|FMV.X.W|FLE.S|FCVT.S.W|FCVT.S.WU|FMV.W.X|FCVT.L.S|FCVT.LU.S|FCVT.S.L|FCVT.S.LU|FADD.D|FSUB.D|FMUL.D|FDIV.D|FSQRT.D|FSGNJ.D|FMIN.D|FCVT.S.D|FCVT.D.S|FLE.D|FCLASS.D|FCVT.W.D|FCVT.WU.D|FCVT.D.W|FCVT.D.WU|FCVT.L.D|FCVT.LU.D|FMV.X.D|FCVT.D.L|FCVT.D.LU|FMV.D.X"] = "FD",
    ["FSGNJN.S|FMAX.S|FLT.S|FCLASS.S|FSGNJN.D|FMAX.D|FLT.D|FADD.S|FSUB.S|FMUL.S|FDIV.S|FSQRT.S|FCVT.W.S|FCVT.WU.S|FCVT.S.W|FCVT.S.WU|FCVT.L.S|FCVT.LU.S|FCVT.S.L|FCVT.S.LU|FADD.D|FSUB.D|FMUL.D|FDIV.D|FSQRT.D|FCVT.S.D|FCVT.D.S|FCLASS.D|FCVT.W.D|FCVT.WU.D|FCVT.D.W|FCVT.D.WU|FCVT.L.D|FCVT.LU.D|FCVT.D.L|FCVT.D.LU"] = "FD",
    ["FSGNJX.S|FEQ.S|FSGNJX.D|FEQ.D|FADD.S|FSUB.S|FMUL.S|FDIV.S|FSQRT.S|FCVT.W.S|FCVT.WU.S|FCVT.S.W|FCVT.S.WU|FCVT.L.S|FCVT.LU.S|FCVT.S.L|FCVT.S.LU|FADD.D|FSUB.D|FMUL.D|FDIV.D|FSQRT.D|FCVT.S.D|FCVT.D.S|FCLASS.D|FCVT.W.D|FCVT.WU.D|FCVT.D.W|FCVT.D.WU|FCVT.L.D|FCVT.LU.D|FCVT.D.L|FCVT.D.LU"] = "FD",
    ["FADD.S|FSUB.S|FMUL.S|FDIV.S|FSQRT.S|FCVT.W.S|FCVT.WU.S|FCVT.S.W|FCVT.S.WU|FCVT.L.S|FCVT.LU.S|FCVT.S.L|FCVT.S.LU|FADD.D|FSUB.D|FMUL.D|FDIV.D|FSQRT.D|FCVT.S.D|FCVT.D.S|FCLASS.D|FCVT.W.D|FCVT.WU.D|FCVT.D.W|FCVT.D.WU|FCVT.L.D|FCVT.LU.D|FCVT.D.L|FCVT.D.LU"] = "FD",
    -- privileged
    ["ECALL|EBREAK|SRET|MRET|MNRET|WFI|SFENCE.VMA"] = "PRIVILEGED",
    ["SFENCE.VMA"] = "PRIVILEGED",
}

--[[
Instruction mask bits
- 4 bits on the left (1 bit + funct3)
- 7 bits on the right (funtc7)
- Checking these bits is enough to make a big switch covering most uncompressed/compressed instructions.
]]
local mask = "________________xxxx_____xxxxxxx"
local lmask_bits = 4
local rmask_bits = 7
local mask_bits = lmask_bits + rmask_bits

local function tobase2(num, nbits)
    local t = {}
    local bit = 1 << (nbits - 1)
    for i = 1, nbits do
        table.insert(t, ((num & bit) ~= 0) and "1" or "0")
        bit = bit >> 1
    end
    return table.concat(t)
end

local function matchmask(bits, mask)
    assert(#bits == 32 and #mask == 32)
    for i = 1, 32 do
        local b, m = bits:sub(i, i), mask:sub(i, i)
        if b ~= "_" and m ~= "_" and b ~= m then return false end
    end
    return true
end

local labels = { ["ILLEGAL"] = true, [1] = { name = "ILLEGAL", i = 1 << mask_bits } }
local lmask = (1 << lmask_bits) - 1
local rmask = (1 << rmask_bits) - 1
local jumptable = {}
for i = 0, ((1 << mask_bits) - 1) do
    local mask = "________________"
        .. tobase2((i >> rmask_bits) & lmask, lmask_bits)
        .. "_____"
        .. tobase2(i & rmask, rmask_bits)
    local match_insns = {}
    local matches = {}
    local firstindex
    local rd0
    for j, insn in ipairs(insns) do
        if matchmask(insn.bits, mask) and not matches[insn.name] then
            if #matches == 0 then
                rd0 = insn.rd0
            elseif rd0 ~= insn.rd0 then
                rd0 = nil
            end
            matches[insn.name] = true
            table.insert(matches, insn.name)
            firstindex = math.min(firstindex or j, j)
        end
    end
    local namekey = table.concat(matches, "|")
    local name = group_names[namekey] or namekey:gsub("%.", "_"):gsub("|", "_")
    if #name == 0 then name = "ILLEGAL" end
    if not labels[name] then
        labels[name] = true
        if rd0 then
            table.insert(labels, { name = name..'_rd0', i = firstindex * 10 + 1})
            table.insert(labels, { name = name..'_rdN', i = firstindex * 10 + 2})
        else
            table.insert(labels, { name = name, i = firstindex * 10 })
        end
    end
    assert(#name < 18, namekey)
    for rd=0,31 do
        local ename = name
        if rd0 then
            if rd == 0 then
                ename = ename .. '_rd0'
            else
                ename = ename .. '_rdN'
            end
        end
        local emask = mask:sub(1, 20)..tobase2(rd,5)..mask:sub(26, 32)
        local idx = tonumber(emask:match('[0-1]+'), 2)
        jumptable[idx+1] = { name = ename, mask = emask }
    end
end

local f <close> = io.open("src/interpret-jump-table.h", "w")

f:write([[
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

// THIS FILE WAS GENERATED BY "lua tools/gen-interpret-jump-table.lua",
// DO NOT EDIT IT DIRECTLY, EDIT THE GENERATOR SCRIPT INSTEAD.

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic push

#if !defined(NO_COMPUTED_GOTO) && defined(__GNUC__) && !defined(__wasm__)
#define USE_COMPUTED_GOTO
#endif

#ifdef USE_COMPUTED_GOTO

#define INSN_LABEL(x) &&x
#define INSN_CASE(x) x
#define INSN_BREAK() goto NEXT_INSN
#define INSN_SWITCH(x) goto *insn_jumptable[x];
#define INSN_SWITCH_OUT()                                                                                              \
    NEXT_INSN:
#define INSN_JUMPTABLE_TYPE void *

#else

#define INSN_LABEL(x) insn_label_id::x
#define INSN_CASE(x) case insn_label_id::x
#define INSN_BREAK() break
#define INSN_SWITCH(x) switch (insn_jumptable[x])
#define INSN_SWITCH_OUT()
#define INSN_JUMPTABLE_TYPE insn_label_id

]])

table.sort(labels, function(a, b) return a.i < b.i end)
f:write("enum class insn_label_id : unsigned char {\n")
for _, label in ipairs(labels) do
    f:write("    " .. label.name .. ",\n")
end
f:write([[};

#endif // USE_COMPUTED_GOTO

]])

f:write("static const INSN_JUMPTABLE_TYPE insn_jumptable[",#jumptable,"] = {\n")
for i, entry in ipairs(jumptable) do
    f:write()
    f:write(
        string.format("%-32s", "    INSN_LABEL(" .. entry.name .. "),"),
        " // " .. string.format("%4d", (i - 1)) .. " => " .. entry.mask .. "\n"
    )
end
f:write("};\n")

f:write([[

#pragma GCC diagnostic pop
// NOLINTEND(cppcoreguidelines-macro-usage)
]])
