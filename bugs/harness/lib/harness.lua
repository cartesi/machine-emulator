-- Helpers for bugs/<ID>/test.lua proofs of concept. Available on LUA_PATH after `. bugs/env.sh`:
--
--   local harness = require("harness")
--   harness.main(function()
--       local cartesi = require("cartesi")
--       local m <close> = harness.machine(harness.config("baremetal-minimal"))  -- setup errors -> exit 2
--       ...
--       return harness.expect(observed == required, "what the threat model requires")  -- true -> 0, false -> 1
--   end)
--
-- Exit status convention (bugs/run.sh): 0 = fixed, 1 = bug present, 2 = harness error.
-- harness.main maps: the function returning true -> 0, returning false -> 1, raising an error -> 2.
-- harness.bug(msg) prints and exits 1 immediately; harness.setup_error(msg) exits 2.

local M = {}

M.REPO = os.getenv("REPO") or error("source bugs/env.sh first")
M.HARNESS = os.getenv("HARNESS")
M.WORK = os.getenv("HARNESS_WORK")
M.CONFIGS = os.getenv("HARNESS_CONFIGS")
M.IMAGES = os.getenv("CARTESI_IMAGES_PATH")

function M.hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

function M.unhex(h)
    h = h:gsub("^0x", "")
    return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end))
end

function M.bug(msg)
    io.stderr:write("BUG PRESENT: ", tostring(msg), "\n")
    os.exit(1, true)
end

function M.setup_error(msg)
    io.stderr:write("HARNESS ERROR: ", tostring(msg), "\n")
    os.exit(2, true)
end

-- Returns ok; prints a verdict line.
function M.expect(ok, what)
    if ok then
        io.stderr:write("OK: ", tostring(what), "\n")
    else
        io.stderr:write("VIOLATED: ", tostring(what), "\n")
    end
    return ok and true or false
end

function M.main(fn)
    local ok, res = xpcall(fn, debug.traceback)
    if not ok then
        io.stderr:write("HARNESS ERROR (uncaught): ", tostring(res), "\n")
        os.exit(2, true)
    end
    if res == true then
        os.exit(0, true)
    elseif res == false then
        os.exit(1, true)
    else
        io.stderr:write("HARNESS ERROR: test function must return true (fixed) or false (bug present)\n")
        os.exit(2, true)
    end
end

-- Read a whole file.
function M.read_file(path)
    local f = assert(io.open(path, "rb"))
    local s = f:read("a")
    f:close()
    return s
end

-- Path of a ready configuration directory under bugs/harness/work/configs (see README).
-- Names: "baremetal-minimal", "linux-rootfs", "valid-template" (stored machines) and their config.json.
function M.config_dir(name)
    return M.CONFIGS .. "/" .. name
end

-- Load a ready configuration as a Lua table (config.lua produced by bugs/harness/configs/make-configs.sh).
function M.config(name)
    local f = io.open(M.config_dir(name) .. "/config.lua", "rb")
    if not f then M.setup_error("missing configuration " .. name .. " (run bugs/harness/configs/make-configs.sh)") end
    local chunk = assert(load(f:read("a"), "=" .. name, "t", {}))
    f:close()
    return chunk()
end

-- Create a machine from a config table (or load a stored machine directory when given a string).
function M.machine(cfg_or_dir, runtime)
    local cartesi = require("cartesi")
    local ok, m = pcall(function()
        if type(cfg_or_dir) == "string" then return cartesi.machine(cfg_or_dir, runtime or {}) end
        return cartesi.machine(cfg_or_dir, runtime or {})
    end)
    if not ok then M.setup_error("cannot create machine: " .. tostring(m)) end
    return m
end

-- Path of a bare-metal binary built by bugs/harness/baremetal/build.sh (e.g. "accept", "reject", "emit-output").
function M.baremetal(name)
    local p = M.WORK .. "/baremetal/" .. name .. ".bin"
    local f = io.open(p, "rb")
    if not f then M.setup_error("missing bare-metal binary " .. p .. " (run bugs/harness/baremetal/build.sh)") end
    f:close()
    return p
end

-- ABI-encode an advance-state input EvmAdvance(uint256 chainId, address appContract, address msgSender,
-- uint256 blockNumber, uint256 blockTimestamp, uint256 prevRandao, uint256 index, bytes payload), as the
-- guest-tools `rollup` utility and libcmt expect it in the rx buffer. Fields default to 0; payload to "".
function M.encode_advance(t)
    t = t or {}
    local cartesi = require("cartesi")
    local function word(v)
        v = v or 0
        if type(v) == "string" then -- 20-byte address or 32-byte raw
            return string.rep("\0", 32 - #v) .. v
        end
        return string.rep("\0", 24) .. string.pack(">I8", v)
    end
    local sel = cartesi.keccak256("EvmAdvance(uint256,address,address,uint256,uint256,uint256,uint256,bytes)"):sub(1, 4)
    local payload = t.payload or ""
    local pad = (32 - #payload % 32) % 32
    return sel
        .. word(t.chain_id)
        .. word(t.app_contract or string.rep("\0", 20))
        .. word(t.msg_sender or string.rep("\0", 20))
        .. word(t.block_number)
        .. word(t.block_timestamp)
        .. word(t.prev_randao)
        .. word(t.index)
        .. word(8 * 32)
        .. word(#payload)
        .. payload
        .. string.rep("\0", pad)
end

-- Run a shell command, returning ok, stdout.
function M.sh(cmd)
    local p = assert(io.popen(cmd, "r"))
    local out = p:read("a")
    local ok, _, code = p:close()
    return ok, out, code
end

return M
