#!/usr/local/bin/luapp

-- Copyright 2019 Cartesi Pte. Ltd.
--
-- This file is part of the machine-emulator. The machine-emulator is free
-- software: you can redistribute it and/or modify it under the terms of the GNU
-- Lesser General Public License as published by the Free Software Foundation,
-- either version 3 of the License, or (at your option) any later version.
--
-- The machine-emulator is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
-- FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
-- for more details.
--
-- You should have received a copy of the GNU Lesser General Public License
-- along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
--

local cartesi = require"cartesi"

local function hexhash(hash)
    return (string.gsub(hash, ".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

local function hexhash8(hash)
    return string.sub(hexhash(hash), 1, 8)
end

local function indentout(level, ...)
    local step = "  "
    io.stdout:write(string.rep(step, level), ...)
end

local function print_log(log)
    local d = 0
    local j = 1
    local i = 1
    while true do
        local bj = log.brackets[j]
        local ai = log.accesses[i]
        if not bj and not ai then break end
        if bj and bj.where <= i then
            if bj.type == "begin" then
                indentout(d, "begin ", bj.text, "\n")
                d = d + 1
            elseif bj.type == "end" then
                d = d - 1
                indentout(d, "end ", bj.text, "\n")
            end
            j = j + 1
        elseif ai then
            local ai = log.accesses[i]
            indentout(d, "hash ", hexhash8(ai.proof.root_hash), "\n")
            if ai.type == "read" then
                indentout(d, "read ", log.notes[i], string.format("@%x",
                    ai.proof.address), ": ", ai.read, "\n")
            else
                assert(ai.type == "write")
                indentout(d, "write ", log.notes[i], string.format("@%x",
                    ai.proof.address), ": ", ai.read, " -> ", ai.written, "\n")
            end
            i = i + 1
        end
    end
end

local function check_proof(proof)
    local hash = proof.target_hash
    for log2_size = proof.log2_size, 63 do
        local bit = (proof.address & (1 << log2_size)) ~= 0
        local first, second
        if bit then
            first, second = proof.sibling_hashes[64-log2_size], hash
        else
            first, second = hash, proof.sibling_hashes[64-log2_size]
        end
        hash = cartesi.keccak(first, second)
    end
    return hash == proof.root_hash
end

local x = {}
x[0] = 0x000
x[1] = 0x008
x[2] = 0x010
x[3] = 0x018
x[4] = 0x020
x[5] = 0x028
x[6] = 0x030
x[7] = 0x038
x[8] = 0x040
x[9] = 0x048
x[10] = 0x050
x[11] = 0x058
x[12] = 0x060
x[13] = 0x068
x[14] = 0x070
x[15] = 0x078
x[16] = 0x080
x[17] = 0x088
x[18] = 0x090
x[19] = 0x098
x[20] = 0x0a0
x[21] = 0x0a8
x[22] = 0x0b0
x[23] = 0x0b8
x[24] = 0x0c0
x[25] = 0x0c8
x[26] = 0x0d0
x[27] = 0x0d8
x[28] = 0x0e0
x[29] = 0x0e8
x[30] = 0x0f0
x[31] = 0x0f8
local addr = { x = x }
addr.pc = 0x100;
addr.mvendorid = 0x108;
addr.marchid = 0x110;
addr.mimpid = 0x118;
addr.mcycle = 0x120;
addr.minstret = 0x128;
addr.mstatus = 0x130;
addr.mtvec = 0x138;
addr.mscratch = 0x140;
addr.mepc = 0x148;
addr.mcause = 0x150;
addr.mtval = 0x158;
addr.misa = 0x160;
addr.mie = 0x168;
addr.mip = 0x170;
addr.medeleg = 0x178;
addr.mideleg = 0x180;
addr.mcounteren = 0x188;
addr.stvec = 0x190;
addr.sscratch = 0x198;
addr.sepc = 0x1a0;
addr.scause = 0x1a8;
addr.stval = 0x1b0;
addr.satp = 0x1b8;
addr.scounteren = 0x1c0;
addr.ilrsc = 0x1c8;

local machine = cartesi.machine{
    machine = cartesi.get_name(),
    processor = addr;
    ram = {
        length = 1 << 20
    },
    rom = {
        backing = "rom.bin",
    },
    interactive = false,
}

addr.x = nil

local function align(v, el)
    return (v >> el << el)
end

machine:update_merkle_tree()

-- check initialization and shadow reads
for i,v in pairs(addr) do
    local r = machine:read_word(v)
    assert(v == r)
end

for i,v in pairs(x) do
    local r = machine:read_word(v)
    assert(v == r)
end

-- check proofs
for i,v in pairs(addr) do
    for el = 3, 63 do
        local a = align(v, el)
        assert(check_proof(assert(machine:get_proof(a, el)), "no proof"), "proof failed")
    end
end

for i,v in pairs(x) do
    for el = 3, 63 do
        local a = align(v, el)
        assert(check_proof(assert(machine:get_proof(a, el), "no proof")), "proof failed")
    end
end

log = machine:step()
print_log(log)

machine:destroy()

print("passed")
