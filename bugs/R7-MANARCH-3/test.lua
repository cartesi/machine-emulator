-- R7-MANARCH-3: uarch loads outside the documented uarch memory map define a successor (the value 0) on every path.
--
-- The manual's only statement of the uarch memory map (doc/README.md, "The microarchitecture"):
--   "In addition to being able to access all memory ranges and devices visible to the main processor, the uarch
--    includes a private 2MiB of RAM."
-- THREAT_MODEL R3: "The uarch traps when it executes ... an access that its memory map does not allow" and
--   "Running the uarch natively, the computation-hash builders and the log producers refuse every uarch trap
--    instead of defining a successor. A verifier refuses a trap whenever the log it receives already
--    authenticates the condition."
--
-- Before-state: baremetal-minimal at mcycle 0, uarch RAM 0x600000 holds "ld x5, 0(x6)", uarch_pc = 0x600000.
--
-- (A) Hole loads: x6 = an address that no memory range or device of the machine covers (checked at run time
--     against get_address_ranges) and that is not uarch RAM. The documented map does not include it, so the
--     load is a uarch trap. Required: run_uarch and log_step_uarch refuse it; the C++ replay verifier and the
--     regenerated machine-solidity-step (EVM) refuse a log of it (the address comes from the logged x6 read and
--     the logged instruction word, so the log authenticates the condition).
-- (B) Device load: htif_tohost = 0x0101000000000041 and x6 = 0x40008000 (HTIF tohost, a device visible to the
--     main processor). Required: the load either yields the device register (the manual's map, as written) or is
--     refused as a trap on every path (a narrower, documented map). Yielding 0 matches neither.
--
-- A control load from uarch RAM validates the hand-built log (both verifiers accept it with the native
-- after-hash), otherwise exit 2.
-- Exit 0: requirements hold. Exit 1: some load outside the map defines a successor. Exit 2: setup error.
local harness = require("harness")
local cartesi = require("cartesi")
local evm = require("evm_step")
local K = cartesi.keccak256

local LD_X5_0_X6 = 0x00033283
local TOHOST = 0x0101000000000041
local CTRL_VALUE = 0x1122334455667788

local function sh(cmd)
    local p = assert(io.popen(cmd, "r"))
    local out = p:read("a")
    p:close()
    return out
end

---------------------------------------------------------------------------------------------------------------
-- private anvil with the regenerated StepVerifier runtime code (built by the shared EVM harness); same method as
-- bugs/R1-R10-1: anvil_setCode on a random port in 20000-29999, stopped at the end.
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
-- hand-built log of one uarch step executing "ld x5, 0(x6)" (access order of src/uarch-step.cpp:
-- cycle, halt, pc, instruction, x6, loaded word, write x5, write pc, write cycle)
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

local function craft_ld_log(m, load_addr)
    local mods = {}
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
    local base = 0x400000 -- uarch shadow: halt 0x0, cycle 0x8, pc 0x10, x0 0x18, x1 0x20, ...
    local cycle = rd(base + 0x08)
    rd(base + 0x00)
    local pc = rd(base + 0x10)
    rd(pc)
    local a = rd(base + 0x18 + 8 * 6)
    assert(a == load_addr)
    local v = rd(load_addr)
    wr(base + 0x18 + 8 * 5, v)
    wr(base + 0x10, pc + 4)
    wr(base + 0x08, cycle + 1)
    return { accesses = accesses, log_type = { has_annotations = false, has_large_data = false } }, v
end

local function prepare(addr, tohost)
    local m = harness.machine(harness.config_dir("baremetal-minimal") .. "/machine")
    m:write_memory(0x600000, string.pack("<I4", LD_X5_0_X6))
    m:write_memory(0x600100, string.pack("<I8", CTRL_VALUE))
    m:write_reg("uarch_pc", 0x600000)
    m:write_reg("uarch_x6", addr)
    m:write_reg("uarch_x5", 0x77)
    if tohost then m:write_reg("htif_tohost", tohost) end
    return m
end

local function in_some_range(m, addr)
    for _, r in ipairs(m:get_address_ranges()) do
        if addr >= r.start and addr - r.start < r.length then return r.description end
    end
    return nil
end

local function short(e) return (tostring(e):gsub("\n.*", ""):sub(1, 72)) end

-- runs the step natively (run_uarch) and through the log producer; returns
-- run_ok, x5_after_run, log_ok, producer_log_or_err, before_hash
local function native(addr, tohost)
    local m <close> = prepare(addr, tohost)
    local okr, er = pcall(m.run_uarch, m, 1)
    local x5 = m:read_reg("uarch_x5")
    local m2 <close> = prepare(addr, tohost)
    local before = m2:get_root_hash()
    local okl, log = pcall(m2.log_step_uarch, m2)
    return okr, okr and x5 or er, okl, log, before
end

local function run(e)
    -- control: legitimate load from uarch RAM; the crafted log must equal what both verifiers accept natively
    do
        local m <close> = prepare(0x600100)
        local before = m:get_root_hash()
        local log, v = craft_ld_log(m, 0x600100)
        if v ~= CTRL_VALUE then error("setup: control: crafted log read 0x" .. string.format("%x", v)) end
        local okv, rv = pcall(cartesi.machine.verify_step_uarch, cartesi.machine, before, log)
        local oke, re = e:step(before, log)
        local okn, ne = pcall(m.log_step_uarch, m)
        if not okn then error("setup: control: native uarch refused the legitimate load: " .. tostring(ne)) end
        local after = m:get_root_hash()
        if m:read_reg("uarch_x5") ~= CTRL_VALUE then error("setup: control: native load gave a wrong value") end
        if not (okv and rv == after) then error("setup: control: C++ verify failed: " .. tostring(rv)) end
        if not (oke and re == after) then error("setup: control: EVM step failed: " .. tostring(re)) end
        print(string.format("%-36s native: x5=0x%x | C++ verify: accepted (= native) | EVM: accepted (= native)",
            "control: uarch RAM 0x600100", CTRL_VALUE))
    end

    local violations, checks = 0, 0
    local function check(ok, what)
        checks = checks + 1
        if not ok then violations = violations + 1 end
        return ok
    end

    -- (A) holes: no range of the machine covers them; the documented uarch map does not include them
    local HOLES = { 0x8000, 0x90000000, 0x1000000000, 0xfffffffffffffff8 }
    for _, addr in ipairs(HOLES) do
        do
            local mm <close> = prepare(addr)
            local d = in_some_range(mm, addr)
            if d then error(string.format("setup: 0x%x is in range '%s', not a hole", addr, d)) end
        end
        local name = string.format("hole 0x%x", addr)
        local okr, xr, okl, lg = native(addr)
        print(string.format("%-36s run_uarch: %s", name,
            okr and string.format("DEFINED SUCCESSOR, x5=0x%x", xr) or ("refused (" .. short(xr) .. ")")))
        check(not okr, name .. " run_uarch")
        print(string.format("%-36s log_step_uarch: %s", "",
            okl and "LOGGED A SUCCESSOR" or ("refused (" .. short(lg) .. ")")))
        check(not okl, name .. " log_step_uarch")
        local m <close> = prepare(addr)
        local before = m:get_root_hash()
        local log = craft_ld_log(m, addr)
        local okv, rv = pcall(cartesi.machine.verify_step_uarch, cartesi.machine, before, log)
        local oke, re = e:step(before, log)
        print(string.format("%-36s C++ verify_step_uarch: %s", "",
            okv and ("ACCEPTED, after-hash " .. harness.hex(rv)) or ("rejected (" .. short(rv) .. ")")))
        print(string.format("%-36s EVM StepVerifier.step: %s", "",
            oke and ("ACCEPTED, after-hash " .. harness.hex(re)) or ("rejected (" .. short(re) .. ")")))
        check(not okv, name .. " C++ verify")
        check(not oke, name .. " EVM verify")
    end

    -- (B) device: HTIF tohost at its device address
    do
        local addr = 0x40008000
        local name = "HTIF tohost device 0x40008000"
        local okr, xr, okl, lg, before = native(addr, TOHOST)
        local okshadow, xshadow = native(0x330, TOHOST) -- the same register through its shadow address
        print(string.format("%-36s htif_tohost = 0x%x; LD from its shadow 0x330 gives %s", name, TOHOST,
            okshadow and string.format("0x%x", xshadow) or short(xshadow)))
        if okr then
            print(string.format("%-36s run_uarch: x5=0x%x (%s)", "", xr,
                xr == TOHOST and "the device register" or "NOT the device register"))
        else
            print(string.format("%-36s run_uarch: refused (%s)", "", short(xr)))
        end
        local okv, rv
        if okl then
            okv, rv = pcall(cartesi.machine.verify_step_uarch, cartesi.machine, before, lg)
            print(string.format("%-36s log_step_uarch: logged; C++ verify of that log: %s", "",
                okv and "accepted" or ("rejected (" .. short(rv) .. ")")))
        else
            print(string.format("%-36s log_step_uarch: refused (%s)", "", short(lg)))
        end
        -- either the manual's map (the device register) or a trap on every path; 0 is neither
        local manual_map = okr and xr == TOHOST and okl
        local trap_everywhere = (not okr) and (not okl)
        check(manual_map or trap_everywhere, name)
    end

    return harness.expect(violations == 0,
        "R3 + manual uarch memory map: a uarch load outside the documented map (all ranges and devices of the main " ..
        "processor plus uarch RAM) is a trap that native, log producers and verifiers refuse, and a load from a " ..
        "device yields the device register (or is refused everywhere); " .. violations .. " violation(s) of " ..
        checks .. " checks")
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
