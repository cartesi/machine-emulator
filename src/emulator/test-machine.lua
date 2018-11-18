local cartesi = require"cartesi"

local function hexhash(hash)
    return (string.gsub(hash, ".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

local function print_log(log)
    local indent_step = "  "
    local indent_level = 0
    local j = 1
    local i = 1
    while true do
        local nj = log.notes[j]
        local ai = log.accesses[i]
        if not nj and not ai then break end
        if nj and nj.where <= i then
            if nj.type == "begin" then
                io.stdout:write(string.rep(indent_step, indent_level), "begin ", nj.text, "\n")
                indent_level = indent_level + 1
            elseif nj.type == "end" then
                indent_level = indent_level - 1
                io.stdout:write(string.rep(indent_step, indent_level), "end ", nj.text, "\n")
            else
                assert(nj.type == "point")
                io.stdout:write(string.rep(indent_step, indent_level), nj.text, "\n")
            end
            j = j + 1
        elseif ai then
            local ai = log.accesses[i]
            io.stdout:write(string.rep(indent_step, indent_level), "hash ", hexhash(ai.proof.root_hash), "\n")
            if ai.type == "read" then
                io.stdout:write(string.rep(indent_step, indent_level), "read ", ai.text,
                    string.format("@%x", ai.proof.address), ": ",
                    ai.read, "\n")
            else
                assert(ai.type == "write")
                io.stdout:write(string.rep(indent_step, indent_level), "write ", ai.text,
                    string.format("@%x", ai.proof.address), ": ",
                    ai.read, " -> ", ai.written, "\n")
            end
            i = i + 1
        end
    end
end

local function print_hash(h)
    print(hexhash(h))
end

local function check_proof(proof)
    local hash = proof.target_hash
    for log2_size = proof.log2_size, 63 do
        local bit = (proof.address & (1 << log2_size)) ~= 0
        local first, second
        if bit then
            first, second = proof.sibling_hashes[log2_size], hash
        else
            first, second = hash, proof.sibling_hashes[log2_size]
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
        backing = "cmd",
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
