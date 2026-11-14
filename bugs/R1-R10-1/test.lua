-- R1-R10-1: the uarch-step verifiers accept uarch stores that the native uarch refuses as uarch traps.
--
-- For each store address class that is fixed by the protocol layout (PMA array, shadow TLB, HTIF MMIO, the
-- uarch x0 shadow word), we prepare a before-state whose uarch is about to execute "sd rs2, imm(rs1)" to that
-- address, check that the native uarch refuses the step (trap: log_step_uarch raises), hand-build the step log
-- (every access authenticated by Merkle proofs of the before-state), and require that
--   (a) the regenerated machine-solidity-step (referee verifier, StepVerifier.step on a private anvil) and
--   (b) the C++ replay verifier (cartesi.machine:verify_step_uarch, support)
-- REJECT it (R3: "A verifier refuses a trap whenever the log it receives already authenticates the condition").
-- A control store into uarch RAM must be accepted by both with the native after-hash (validates the crafting).
--
-- Exit 0: all trap logs rejected by both verifiers. Exit 1: some trap log accepted. Exit 2: setup error.
local harness = require("harness")
local cartesi = require("cartesi")
local evm = require("evm_step")
local K = cartesi.keccak256

local V = 0x1122334455667788

local function sh(cmd)
    local p = assert(io.popen(cmd, "r"))
    local out = p:read("a")
    p:close()
    return out
end

---------------------------------------------------------------------------------------------------------------
-- private anvil with the regenerated StepVerifier runtime code (built by the shared EVM harness)
---------------------------------------------------------------------------------------------------------------
local function start_anvil()
    local artifact = harness.WORK .. "/evm/out/StepVerifier.sol/StepVerifier.json"
    local f = io.open(artifact, "rb")
    if not f then harness.setup_error("missing " .. artifact .. " (run bugs/harness/solidity-step/evm/start.sh once)") end
    f:close()
    local code = sh(string.format("jq -r .deployedBytecode.object %q", artifact)):gsub("%s", "")
    if not code:match("^0x[0-9a-fA-F]+$") or #code < 1000 then harness.setup_error("bad StepVerifier artifact") end
    math.randomseed(os.time() ~ tonumber(tostring({}):match("0x(%x+)"), 16))
    for _ = 1, 20 do
        local port = 20000 + math.random(0, 9999)
        local rpc = "http://127.0.0.1:" .. port
        if sh("cast block-number --rpc-url " .. rpc .. " 2>/dev/null"):match("%d") == nil then
            local logf = os.tmpname()
            local pid = sh(string.format(
                "nohup anvil --port %d --hardfork prague --code-size-limit 4000000 --disable-block-gas-limit " ..
                "--silent > %s 2>&1 & echo $!", port, logf)):match("%d+")
            local up = false
            for _ = 1, 100 do
                if sh("cast block-number --rpc-url " .. rpc .. " 2>/dev/null"):match("%d") then up = true; break end
                sh("sleep 0.1")
            end
            os.remove(logf)
            if up then
                local addr = "0x00000000000000000000000000000000005e1f00"
                local codef = os.tmpname()
                local cf = assert(io.open(codef, "w"))
                cf:write(string.format('{"jsonrpc":"2.0","id":1,"method":"anvil_setCode","params":["%s","%s"]}',
                    addr, code))
                cf:close()
                sh(string.format("curl -sS --noproxy '*' -H 'Content-Type: application/json' --data-binary @%s %s",
                    codef, rpc))
                os.remove(codef)
                return pid, rpc, addr
            end
            if pid then os.execute("kill " .. pid .. " 2>/dev/null") end
        end
    end
    harness.setup_error("could not start a private anvil")
end

---------------------------------------------------------------------------------------------------------------
-- hand-built log of one uarch step executing "sd rs2, imm(rs1)" (access order of src/uarch-step.cpp)
---------------------------------------------------------------------------------------------------------------
local function bubble(h, addr, sibs, to_level)
    for l = 5, to_level - 1 do
        local s = sibs[l - 5 + 1]
        if ((addr >> l) & 1) == 0 then h = K(h .. s) else h = K(s .. h) end
    end
    return h
end

local function div_level(a, b)
    for l = 63, 5, -1 do
        if ((a >> l) & 1) ~= ((b >> l) & 1) then return l end
    end
end

local function craft_sd_log(m, rs1, rs2, store_addr)
    local mods = {} -- leaf address -> { data, hash, sibs (before-state siblings of that leaf) }
    local accesses = {}
    local function leaf_data(a32) return mods[a32] and mods[a32].data or m:read_memory(a32, 32) end
    local function sibs_for(a32)
        local out = {}
        for i, s in ipairs(m:get_proof(a32, 5).sibling_hashes) do out[i] = s end
        for maddr, mod in pairs(mods) do
            if maddr ~= a32 then
                local l = div_level(maddr, a32)
                out[l - 5 + 1] = bubble(mod.hash, maddr, mod.sibs, l)
            end
        end
        return out
    end
    local function rd(addr)
        local a32 = addr & ~31
        local d = leaf_data(a32)
        accesses[#accesses + 1] = { type = "read", address = addr, log2_size = 3, read = d, read_hash = K(d),
            sibling_hashes = sibs_for(a32) }
        return string.unpack("<I8", d, (addr & 31) + 1)
    end
    local function wr(addr, val)
        local a32 = addr & ~31
        local d = leaf_data(a32)
        local off = addr & 31
        local nd = d:sub(1, off) .. string.pack("<I8", val) .. d:sub(off + 9)
        accesses[#accesses + 1] = { type = "write", address = addr, log2_size = 3, read = d, read_hash = K(d),
            written = nd, written_hash = K(nd), sibling_hashes = sibs_for(a32) }
        local pre_sibs = mods[a32] and mods[a32].sibs or m:get_proof(a32, 5).sibling_hashes
        mods[a32] = { data = nd, hash = K(nd), sibs = pre_sibs }
    end
    local base = 0x400000 -- uarch shadow state: halt 0x0, cycle 0x8, pc 0x10, x0 0x18, x1 0x20, ...
    local cycle = rd(base + 0x08)
    rd(base + 0x00)
    local pc = rd(base + 0x10)
    rd(pc)
    rd(base + 0x18 + 8 * rs1)
    local v = rd(base + 0x18 + 8 * rs2)
    wr(store_addr, v)
    wr(base + 0x10, pc + 4)
    wr(base + 0x08, cycle + 1)
    return { accesses = accesses, log_type = { has_annotations = false, has_large_data = false } }
end

local function sd_insn(rs2, rs1, imm)
    return ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (3 << 12) | ((imm & 31) << 7) | 0x23
end

-- Prepare the before-state: baremetal-minimal at mcycle 0, uarch about to execute sd at uarch RAM 0x600000.
local function prepare(c)
    local m = harness.machine(harness.config_dir("baremetal-minimal") .. "/machine")
    m:write_memory(0x600000, string.pack("<I4", sd_insn(c.rs2, c.rs1, c.imm)))
    m:write_reg("uarch_pc", 0x600000)
    m:write_reg("uarch_x" .. c.rs1, c.rs1val)
    m:write_reg("uarch_x" .. c.rs2, V)
    return m
end

local CONTROL = { name = "control: uarch RAM 0x600100", rs1 = 1, rs2 = 2, imm = 0, rs1val = 0x600100 }
local CASES = {
    { name = "PMA array (0x10000)", rs1 = 1, rs2 = 2, imm = 0, rs1val = 0x10000 },
    { name = "shadow TLB (0x1000)", rs1 = 1, rs2 = 2, imm = 0, rs1val = 0x1000 },
    { name = "HTIF tohost (0x40008000)", rs1 = 1, rs2 = 2, imm = 0, rs1val = 0x40008000 },
    { name = "uarch x0 shadow word (0x400018)", rs1 = 2, rs2 = 1, imm = 0x18, rs1val = 0x400000 },
}

local function run(e)
    -- control: the crafting reproduces a legitimate store exactly
    do
        local m <close> = prepare(CONTROL)
        local before = m:get_root_hash()
        local log = craft_sd_log(m, CONTROL.rs1, CONTROL.rs2, CONTROL.rs1val + CONTROL.imm)
        local okv, rv = pcall(cartesi.machine.verify_step_uarch, cartesi.machine, before, log)
        local oke, re = e:step(before, log)
        local okn, ne = pcall(m.log_step_uarch, m)
        if not okn then error("setup: control: native uarch refused the legitimate store: " .. tostring(ne)) end
        local native_after = m:get_root_hash()
        if not (okv and rv == native_after) then error("setup: control: C++ verify failed: " .. tostring(rv)) end
        if not (oke and re == native_after) then error("setup: control: EVM step failed: " .. tostring(re)) end
        print(string.format("%-34s native: ok | C++ verify: accepted (= native) | EVM step: accepted (= native)",
            CONTROL.name))
    end

    local violations = 0
    for _, c in ipairs(CASES) do
        local m <close> = prepare(c)
        local before = m:get_root_hash()
        local log = craft_sd_log(m, c.rs1, c.rs2, c.rs1val + c.imm)
        local okv, rv = pcall(cartesi.machine.verify_step_uarch, cartesi.machine, before, log)
        local oke, re = e:step(before, log)
        local okn, ne = pcall(m.log_step_uarch, m)
        if okn then error("setup: " .. c.name .. ": native uarch did not trap; the case is not a trap") end
        print(string.format("%-34s native: TRAP (%s)", c.name, tostring(ne):gsub("\n.*", ""):sub(1, 70)))
        print(string.format("%-34s   C++ verify_step_uarch: %s", "",
            okv and ("ACCEPTED, after-hash " .. harness.hex(rv)) or ("rejected: " .. tostring(rv):sub(1, 80))))
        print(string.format("%-34s   EVM StepVerifier.step: %s", "",
            oke and ("ACCEPTED, after-hash " .. harness.hex(re)) or ("rejected: " .. tostring(re):sub(1, 80))))
        if okv then violations = violations + 1 end
        if oke then violations = violations + 1 end
    end
    return harness.expect(violations == 0,
        "R3: a verifier refuses a uarch trap whenever its log already authenticates the condition " ..
        "(uarch stores to fixed protocol addresses that the uarch memory map does not allow); " ..
        violations .. " acceptance(s) of " .. 2 * #CASES)
end

harness.main(function()
    local pid, rpc, addr = start_anvil()
    local e = evm.connect(rpc, addr)
    local ok, res = pcall(run, e)
    os.remove(e.tmp)
    os.execute("kill " .. pid .. " 2>/dev/null")
    if not ok then error(res, 0) end
    return res
end)
