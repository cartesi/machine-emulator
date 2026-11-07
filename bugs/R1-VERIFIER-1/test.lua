-- R1-VERIFIER-1: the uarch step verifier must report a bad log as an error, never terminate the process.
-- THREAT_MODEL.md section 4 requires every path that carries relayed logs to "report errors without terminating
-- the process"; R10 requires verifiers to stay safe on every before-state.
-- child.lua builds a 3-access log (uarch_cycle, uarch_halt, uarch_pc reads) against a before-state whose uarch_pc
-- is 2 mod 4 and verifies it (a) in-process through cartesi.machine:verify_step_uarch under pcall and (b) through a
-- spawned cartesi-jsonrpc-machine server. In the default relwithdebinfo build, readUint32's require() is a C
-- assert (uarch-solidity-compat.hpp:253) that stays active, so the verifier aborts with SIGABRT instead of failing.
-- A control run with the honest aligned before-state checks that the same harness gets a normal caught error.
-- Exits 0 only when every path reports an error and survives.
local function run(mode)
    local p = assert(io.popen("lua5.4 ./child.lua " .. mode .. " 2>&1; echo \"EXIT $?\""))
    local out = p:read("a")
    p:close()
    local status = tonumber(out:match("EXIT (%d+)%s*$"))
    return status, out
end

local failures = {}

local cstatus, cout = run("control")
if cstatus ~= 0 or not cout:find("REJECTED") then
    io.stderr:write("harness error: control run did not produce a caught rejection:\n", cout)
    os.exit(2)
end

local lstatus, lout = run("local")
if lstatus == 134 or lout:find("Assertion") then
    failures[#failures + 1] = "Lua/C API verify_step_uarch aborted the process (status "
        .. tostring(lstatus) .. ", uarch-solidity-compat.hpp:253 assert) instead of raising a catchable error"
elseif lstatus ~= 0 or not lout:find("REJECTED") then
    failures[#failures + 1] = "Lua/C API verify_step_uarch did not reject the log (status " .. tostring(lstatus)
        .. "): " .. lout
end

local jstatus, jout = run("jsonrpc")
if jout:find("SERVER%-DEAD") or jout:find("Assertion") then
    failures[#failures + 1] = "JSON-RPC machine.verify_step_uarch killed the cartesi-jsonrpc-machine server (assert abort)"
elseif jstatus ~= 0 or not jout:find("REJECTED") or not jout:find("SERVER%-ALIVE") then
    failures[#failures + 1] = "JSON-RPC verify_step_uarch did not reject the log and survive: " .. jout
end

if #failures > 0 then
    print("R1-VERIFIER-1 FAIL: a relayed uarch step log against a before-state with misaligned uarch_pc aborts the verifier "
        .. "process (SIGABRT from require/assert), which pcall/try-catch cannot catch")
    for _, f in ipairs(failures) do
        print("  - " .. f)
    end
    os.exit(1)
end
print("R1-VERIFIER-1 OK: verifier rejected the misaligned log with a catchable error on every path")
os.exit(0)
