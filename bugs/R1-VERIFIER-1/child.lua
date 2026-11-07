-- Child process for R1-VERIFIER-1 (run by test.lua; see its header).
-- usage: lua5.4 child.lua <mode>
--   control  : the 3-access log against the honest (aligned uarch_pc) before-state; expects a caught error.
--   local    : the 3-access log against a fabricated before-state with uarch_pc = 2 mod 4, verified in-process
--              through the Lua/C API (cm_verify_step_uarch) under pcall.
--   jsonrpc  : the same log sent to a spawned cartesi-jsonrpc-machine server's machine.verify_step_uarch;
--              then checks the server still answers.
-- Prints one result line: "REJECTED <err>", "ACCEPTED <hash>", "SERVER-ALIVE", "SERVER-DEAD <err>".
-- A C assert in the uarch interpreter instead aborts the process that runs the verifier (SIGABRT, status 134).
local cartesi = require("cartesi")
local mode = assert(arg[1], "usage: child.lua control|local|jsonrpc")

local m = cartesi.machine({ ram = { length = 1 << 20 } })
if mode ~= "control" then
    -- Fabricated before-state: uarch_pc misaligned by 2 (an attacker-chosen hash in a Sybil-vs-Sybil match).
    m:write_reg("uarch_pc", m:read_reg("uarch_pc") + 2)
end
local root = m:get_root_hash()

-- Authenticated 64-bit read of a uarch register, exactly as the uarch step log producer emits it:
-- a 32-byte leaf with its proof against root.
local function read_access(reg)
    local addr = m:get_reg_address(reg)
    local leaf = addr & ~31
    local p = m:get_proof(leaf, 5)
    assert(p.root_hash == root)
    return {
        type = "read",
        address = addr,
        log2_size = 3,
        read_hash = p.target_hash,
        read = m:read_memory(leaf, 32),
        sibling_hashes = p.sibling_hashes,
    }
end

local log = {
    log_type = { has_annotations = false, has_large_data = false },
    accesses = { read_access("uarch_cycle"), read_access("uarch_halt"), read_access("uarch_pc") },
}

local function say(s)
    io.stdout:write(s, "\n")
    io.stdout:flush()
end

if mode == "control" or mode == "local" then
    local ok, res = pcall(cartesi.machine.verify_step_uarch, cartesi.machine, root, log)
    say(ok and ("ACCEPTED " .. tostring(res)) or ("REJECTED " .. tostring(res)))
    os.exit(0)
elseif mode == "jsonrpc" then
    local jsonrpc = require("cartesi.jsonrpc")
    local server, address = jsonrpc.spawn_server()
    server:set_cleanup_call(jsonrpc.SHUTDOWN)
    server:set_timeout(10000)
    local ok, res = pcall(server.verify_step_uarch, server, root, log)
    say(ok and ("ACCEPTED " .. tostring(res)) or ("REJECTED " .. tostring(res)))
    -- Is the server still serving (other parties' machines, other tournaments)?
    local alive, err = pcall(function()
        local c <close> = jsonrpc.connect_server(address)
        c:set_timeout(5000)
        return c:get_server_version()
    end)
    if alive then
        say("SERVER-ALIVE")
        pcall(server.shutdown_server, server)
    else
        server:set_cleanup_call(jsonrpc.NOTHING)
        say("SERVER-DEAD " .. tostring(err))
    end
    os.exit(0)
end
error("unknown mode " .. mode)
