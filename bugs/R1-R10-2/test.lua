-- R1-R10-2: the Solidity step verifier (machine-solidity-step Memory.validateStrideLength) rejects every uarch
-- access to the last 32-byte leaf of the 64-bit address space (0xffffffffffffffe0..ff), which the native uarch,
-- the log producer and the C++ verifier accept.
--
-- (Stores there are refused natively: the address is unmapped, a uarch trap; so only loads are probed.)
-- For each probe, a fresh machine whose uarch is about to execute one load whose effective address lies in
-- the top leaf:
--   * native uarch + log producer: m:log_step_uarch() must succeed (no uarch trap), giving the after-hash;
--   * C++ verifier: cartesi.machine:verify_step_uarch(before, log) must return the same after-hash;
--   * referee verifier: the regenerated StepVerifier.step (Dave's UArchStep / AccessLogs / Memory libraries) on a
--     private anvil is REQUIRED to accept the same log with the same after-hash (R2, R3).
-- Control: the same load one leaf lower (0xffffffffffffffd8) must verify on the EVM with the native
-- after-hash (validates the harness).
--
-- Exit 1: some top-leaf log is accepted natively and by the C++ verifier but reverted by the Solidity step.
-- Exit 0: every path agrees (all accept with the same after-hash, or the log producer refuses the step).
-- Exit 2: setup error (no anvil / StepVerifier artifact, control fails).
local harness = require("harness")
local cartesi = require("cartesi")
local evm = require("evm_step")

local function sh(cmd)
    local p = assert(io.popen(cmd, "r"))
    local out = p:read("a")
    p:close()
    return out
end

-- private anvil with the regenerated StepVerifier runtime code (artifact built by the shared EVM harness)
local function start_anvil()
    local artifact = harness.WORK .. "/evm/out/StepVerifier.sol/StepVerifier.json"
    local f = io.open(artifact, "rb")
    if not f then harness.setup_error("missing " .. artifact .. " (run bugs/harness/solidity-step/evm/start.sh once)") end
    f:close()
    local code = sh(string.format("jq -r .deployedBytecode.object %q", artifact)):gsub("%s", "")
    if not code:match("^0x[0-9a-fA-F]+$") or #code < 1000 then harness.setup_error("bad StepVerifier artifact") end
    math.randomseed(os.time() ~ tonumber(tostring({}):match("0x(%x+)"), 16))
    for _ = 1, 20 do
        local port = 30000 + math.random(0, 9999)
        local rpc = "http://127.0.0.1:" .. port
        if sh("cast block-number --rpc-url " .. rpc .. " 2>/dev/null"):match("%d") == nil then
            local pid = sh(string.format(
                "nohup anvil --port %d --hardfork prague --code-size-limit 4000000 --disable-block-gas-limit " ..
                "--silent > /dev/null 2>&1 & echo $!", port)):match("%d+")
            local up = false
            for _ = 1, 100 do
                if sh("cast block-number --rpc-url " .. rpc .. " 2>/dev/null"):match("%d") then up = true; break end
                sh("sleep 0.1")
            end
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

local RAM = 0x80000000
-- I-type load / S-type store with rs1 = x0 and a negative 12-bit immediate: effective address = 2^64 + imm
local function ld_x1(imm) return ((imm & 0xfff) << 20) | (0 << 15) | (3 << 12) | (1 << 7) | 0x03 end
local function lw_x1(imm) return ((imm & 0xfff) << 20) | (0 << 15) | (2 << 12) | (1 << 7) | 0x03 end

local function probe(e, name, insn)
    local m <close> = cartesi.machine({ ram = { length = 1 << 20 } })
    m:write_memory(RAM, string.pack("<I4I4", insn, 0x13))
    m:write_reg("uarch_pc", RAM)
    local before = m:get_root_hash()
    local okl, log = pcall(m.log_step_uarch, m)
    if not okl then
        return { name = name, native = false, err = tostring(log) }
    end
    local after = m:get_root_hash()
    local okv, rv = pcall(cartesi.machine.verify_step_uarch, cartesi.machine, before, log)
    local oke, re = e:step(before, log)
    return {
        name = name, native = true, after = after,
        cpp_ok = okv and rv == after, cpp = okv and harness.hex(rv) or tostring(rv),
        evm_ok = oke and re == after, evm_accepted = oke, evm = oke and harness.hex(re) or tostring(re),
    }
end

local function show(r)
    if not r.native then
        print(string.format("%-40s native/log producer: REFUSED (%s)", r.name, r.err:gsub("\n.*", ""):sub(1, 80)))
        return
    end
    print(string.format("%-40s native/log producer: ok, after-hash %s", r.name, harness.hex(r.after)))
    print(string.format("%-40s C++ verify_step_uarch: %s", "", r.cpp_ok and "ACCEPTED, same after-hash" or ("MISMATCH " .. r.cpp)))
    print(string.format("%-40s EVM StepVerifier.step: %s", "",
        r.evm_ok and "ACCEPTED, same after-hash" or (r.evm_accepted and ("ACCEPTED, different after-hash " .. r.evm)
            or ("REVERTED: " .. r.evm:sub(1, 140)))))
end

local function run(e)
    -- controls: one leaf below the top leaf
    local controls = {
        probe(e, "control ld x1,-40(x0) [0x..ffd8]", ld_x1(-40)),
    }
    for _, r in ipairs(controls) do
        show(r)
        if not (r.native and r.cpp_ok and r.evm_ok) then
            harness.setup_error("control probe did not verify on all paths: " .. r.name)
        end
    end
    local cases = {
        probe(e, "ld x1,-8(x0)  [0xfffffffffffffff8]", ld_x1(-8)),
        probe(e, "lw x1,-32(x0) [0xffffffffffffffe0]", lw_x1(-32)),
    }
    local divergences = 0
    for _, r in ipairs(cases) do
        show(r)
        if r.native then
            if not r.cpp_ok then
                print("    note: the C++ verifier disagrees with the native after-hash")
                divergences = divergences + 1
            end
            if not r.evm_ok then
                divergences = divergences + 1
                local panic1 = r.evm:find("0x4e487b710*1$") or r.evm:find("assert") ~= nil
                if panic1 then print("    (revert is Panic(0x01): Memory.validateStrideLength assertion)") end
            end
        end
    end
    return harness.expect(divergences == 0,
        "R2: 'Every log producer and every log verifier ... The on-chain verifiers' must agree on the canonical hash; " ..
        "R3: 'A verifier must never turn ... a semantic no-op into a rejection'. The Solidity step must accept the " ..
        "log of a uarch access to the last leaf of the address space that the native uarch and the C++ verifier " ..
        "accept; " .. divergences .. " divergence(s) of " .. #cases .. " probes")
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
