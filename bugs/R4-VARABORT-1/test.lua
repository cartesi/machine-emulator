#!/usr/bin/env lua5.4
-- R4-VARABORT-1: the cartesi-machine CLI cannot compute the claim of an epoch when a rejected input yields with DATA
-- larger than the transmit buffer.
--
-- htif tohost is guest-writable, so any 32-bit DATA is a reachable state (THREAT_MODEL section 2), and the manual
-- says DATA is ignored on reject (doc/README.md, "To accept or reject the previous request"). The machine API handles
-- such a state: it hashes it and the rejection reverts it. But the CLI host loop (src/cartesi-machine.lua,
-- get_and_print_yield) reads the transmit buffer at every yield through machine:receive_cmio_request(), which throws
-- "CMIO request data is too large" when DATA > AR_CMIO_TX_BUFFER_LENGTH (src/machine.cpp). Nothing catches it, so the
-- documented claim-computing tool (cartesi-machine --cmio-advance-state with --mcycle-computation-hash or
-- --uarch-cycle-computation-hash, doc/README.md "Computation hashes") dies with exit 1 and no claim (R4).
--
-- The guest (yield.S, built at test time) yields manual rx-accepted with DATA=32 and the empty outputs root to form
-- a valid template. After the input is delivered it yields manual rx-rejected with the DATA under test, then
-- rx-rejected with DATA=0 forever. Two templates are built: a control (DATA=0x10) and the oversized one
-- (DATA=0x200001). For each, the test runs the CLI in four modes (mcycle computation hash, uarch computation hash of
-- input period 0, which holds the rejecting instruction, and of period 1, which follows it, and plain cmio advance)
-- and checks the correct behavior: exit status 0, and a 32-byte hash file in the hashing modes. The control must pass (else it is a harness error). Exits nonzero while the defect is present.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")

local PARAM = 0x80001000
local MANUAL = cartesi.HTIF_YIELD_CMD_MANUAL
local REJECTED = cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED
local TX_LEN = 1 << cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE
assert(TX_LEN == 0x200000, "harness error: unexpected transmit buffer length")

local function tohost(cmd, reason, data)
    return (cartesi.HTIF_DEV_YIELD << 56) | (cmd << 48) | (reason << 32) | data
end

local repo = assert(os.getenv("REPO_DIR"), "harness error: source bugs/env.sh first")
local cli = repo .. "/src/cartesi-machine.lua"

local tmp = assert(io.popen("mktemp -d"):read("l"), "harness error: mktemp failed")
local _ <close> = setmetatable({}, {
    __close = function()
        os.execute("rm -rf '" .. tmp .. "'")
    end,
})
assert(os.execute("bash ./build.sh " .. tmp), "harness error: failed to build guest yield.bin")
local bin = tmp .. "/yield.bin"

local empty_outputs_root =
    hash_tree.frontier_get_root_hash(hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"))
local input_data = "an ordinary advance-state input"

-- Builds a valid template whose first post-input yield is rx-rejected with the given DATA, and stores it.
local function build_template(name, data)
    local m <close> = cartesi.machine({
        ram = { backing_store = { data_filename = bin }, length = 1 << 20 },
        htif = { yield_manual = true, yield_automatic = true },
    })
    m:write_memory(PARAM, empty_outputs_root .. string.pack("<I8I8", tohost(MANUAL, REJECTED, data), tohost(MANUAL, REJECTED, 0)))
    assert(m:run(1000) == cartesi.BREAK_REASON_YIELDED_MANUALLY, "harness error: template did not yield manually")
    local cmd, yreason, ydata = m:receive_cmio_request()
    assert(
        cmd == MANUAL and yreason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED and ydata == empty_outputs_root,
        "harness error: template is not an rx-accepted yield with the empty outputs root"
    )
    local hash = m:get_root_hash()
    local dir = tmp .. "/" .. name .. "-template"
    m:store(dir)
    return hash, dir
end

-- Reference through the machine API: deliver, run to the rejected yield, hash it, revert. The yield data is not read.
local function reference(hash, dir)
    local m <close> = cartesi.machine(dir)
    assert(m:get_root_hash() == hash, "harness error: stored template hash mismatch")
    m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input_data, hash)
    assert(m:run(1000) == cartesi.BREAK_REASON_YIELDED_MANUALLY, "harness error: guest did not yield manually")
    local th = m:read_reg("htif_tohost")
    assert((th >> 32) & 0xff == REJECTED, "harness error: final yield is not rx-rejected")
    local at_yield = m:get_root_hash()
    return th, at_yield, m:read_reg("mcycle")
end

local function read_file(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local s = f:read("a")
    f:close()
    return s
end

do
    local f = assert(io.open(tmp .. "/input-0.bin", "wb"))
    f:write(input_data)
    f:close()
end

local modes = {
    { name = "mcycle-computation-hash", arg = "--mcycle-computation-hash=log2_mcycle_period:4,filename:%s" },
    -- period 0 holds the rejecting instruction; period 1 lies wholly after it (the reverted fixed point)
    {
        name = "uarch-cycle-computation-hash (period 0)",
        arg = "--uarch-cycle-computation-hash=log2_mcycle_period:4,mcycle_period_index:0,filename:%s",
    },
    {
        name = "uarch-cycle-computation-hash (period 1)",
        arg = "--uarch-cycle-computation-hash=log2_mcycle_period:4,mcycle_period_index:1,filename:%s",
    },
    { name = "plain cmio advance" },
}

local function run_cli(template, mode, out)
    local args = {
        "lua5.4",
        cli,
        "--no-init-splash",
        "--remote-spawn",
        "--remote-address=127.0.0.1:0",
        "--remote-shutdown",
        "--load=" .. template,
        "--cmio-advance-state=input:input-%i.bin,input_file_index_begin:0,input_file_index_end:1",
    }
    if mode.arg then args[#args + 1] = string.format(mode.arg, out) end
    local log = out .. ".log"
    local cmd = "cd '" .. tmp .. "' && " .. table.concat(args, " ") .. " >'" .. log .. "' 2>&1"
    local ok, _, status = os.execute(cmd)
    return ok and 0 or status, read_file(log) or ""
end

local function first_error_line(log)
    return log:match("[^\n]*CMIO request data is too large[^\n]*")
        or log:match("[^\n]*[Ee]rror[^\n]*")
        or log:match("([^\n]*)\n?$")
end

local cases = { { name = "control", data = 0x10 }, { name = "oversized", data = TX_LEN + 1 } }
local failures = {}
for _, case in ipairs(cases) do
    local hash, dir = build_template(case.name, case.data)
    local th, at_yield, mcycle = reference(hash, dir)
    print(
        string.format(
            "%s: template %s; machine API reaches rx-rejected yield tohost=0x%016x at mcycle %d, state hash %s",
            case.name,
            cartesi.tohex(hash),
            th,
            mcycle,
            cartesi.tohex(at_yield)
        )
    )
    for i, mode in ipairs(modes) do
        local out = string.format("%s/%s-%d.bin", tmp, case.name, i)
        local status, log = run_cli(dir, mode, out)
        local result = read_file(out)
        local good = status == 0 and (not mode.arg or (result and #result == 32))
        if good then
            print(
                string.format(
                    "%s: cartesi-machine %s exit 0%s",
                    case.name,
                    mode.name,
                    result and (", hash " .. cartesi.tohex(result)) or ""
                )
            )
        else
            local why = string.format(
                "cartesi-machine %s exited %s%s: %s",
                mode.name,
                tostring(status),
                mode.arg and (result and "" or " with no hash file") or "",
                first_error_line(log)
            )
            print(string.format("%s: %s", case.name, why))
            if case.name == "control" then
                io.stderr:write("harness error: control run failed\n", log)
                os.exit(2)
            end
            failures[#failures + 1] = why
        end
    end
end

if #failures > 0 then
    print(
        string.format(
            "FAILURE: an rx-rejected yield with DATA=0x%x (ignored on reject per the manual) makes the cartesi-machine "
                .. "CLI abort in %d of %d cmio modes ('CMIO request data is too large' from get_and_print_yield), "
                .. "so the honest operator cannot compute its claim (R4)",
            TX_LEN + 1,
            #failures,
            #modes
        )
    )
    os.exit(1)
end
print("OK: the CLI computes the claim for an rx-rejected yield with oversized DATA")
