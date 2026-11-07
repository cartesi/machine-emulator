#!/usr/bin/env lua5.4
-- R1-GUESTTOOLS-1: the honest PRT player (doc/recipes/prt.lua) aborts when a guest yield carries DATA larger
-- than the transmit buffer.
--
-- htif tohost is guest-writable, so any 32-bit DATA in a yield is a reachable state (THREAT_MODEL section 2).
-- machine::receive_cmio_request (src/machine.cpp) throws "CMIO request data is too large" whenever DATA exceeds
-- AR_CMIO_TX_BUFFER_LENGTH (2 MiB) and the yield is not a progress report. prt.lua calls it without a guard at
-- every manual-yield fixed point (run_to_input_mcycle_offset) and at every automatic yield while collecting
-- outputs (run_to_stop), so event_handler.input_added raises. The state transition function handles these states
-- like any other yield (a rejection reverts, a report or output yield resumes), so the honest operator must be able
-- to compute its claim (R4). Here it cannot advance, seal the epoch, or retry.
--
-- The guest (yield.S, built at test time) yields manual rx-accepted with DATA=32 and the empty outputs root to make
-- a valid template. After the first input it takes the yields of one variant:
--   A: manual rx-rejected, DATA=0x200001
--   B: automatic tx-report, DATA=0x200001, then manual rx-accepted, DATA=32 (outputs root unchanged)
--   C: automatic tx-output, DATA=0xffffffff, then manual rx-rejected, DATA=0
-- For each variant it checks the correct behavior: an honest player (prt.new_forked_player on the stored template)
-- processes the input, seals the epoch, and its final state hash equals the one obtained by running the bare
-- machine through the same yields. Exits nonzero while the defect is present.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local prt = require("prt")

local PARAM = 0x80001000
local TOHOST_MANUAL_ACCEPTED_32 = 0x0201000100000020

local function tohost(cmd, reason, data)
    return (cartesi.HTIF_DEV_YIELD << 56) | (cmd << 48) | (reason << 32) | data
end

local MANUAL, AUTOMATIC = cartesi.HTIF_YIELD_CMD_MANUAL, cartesi.HTIF_YIELD_CMD_AUTOMATIC
local OVERSIZED = (1 << cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE) + 1
assert(OVERSIZED == 0x200001, "harness error: unexpected transmit buffer length")

local variants = {
    {
        name = "A",
        what = "manual rx-rejected yield with DATA=0x200001",
        first = tohost(MANUAL, cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED, OVERSIZED),
        later = tohost(MANUAL, cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED, 0),
        rejected = true,
    },
    {
        name = "B",
        what = "automatic tx-report yield with DATA=0x200001 followed by an rx-accepted yield",
        first = tohost(AUTOMATIC, cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT, OVERSIZED),
        later = TOHOST_MANUAL_ACCEPTED_32,
        rejected = false,
    },
    {
        name = "C",
        what = "automatic tx-output yield with DATA=0xffffffff followed by an rx-rejected yield",
        first = tohost(AUTOMATIC, cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT, 0xffffffff),
        later = tohost(MANUAL, cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED, 0),
        rejected = true,
    },
}

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
local input_path = tmp .. "/input-0.bin"
do
    local f = assert(io.open(input_path, "wb"))
    f:write("an ordinary advance-state input")
    f:close()
end
local input_data = "an ordinary advance-state input"

-- Builds the valid template of a variant and stores it. Returns its hash and directory.
local function build_template(variant)
    local m <close> = cartesi.machine({
        ram = { backing_store = { data_filename = bin }, length = 1 << 20 },
        htif = { yield_manual = true, yield_automatic = true },
    })
    m:write_memory(PARAM, empty_outputs_root .. string.pack("<I8I8", variant.first, variant.later))
    local reason = m:run(1000)
    assert(reason == cartesi.BREAK_REASON_YIELDED_MANUALLY, "harness error: template did not yield manually")
    local cmd, yreason, data = m:receive_cmio_request()
    assert(
        cmd == MANUAL and yreason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED and data == empty_outputs_root,
        "harness error: template is not an rx-accepted yield with the empty outputs root"
    )
    local hash = m:get_root_hash()
    local dir = tmp .. "/" .. cartesi.tohex(hash)
    m:store(dir)
    return hash, dir
end

-- Reference: the bare machine runs through the input with the same semantics the player implements (deliver,
-- resume automatic yields, revert on rejection). The yield data is not read: it is opaque guest data.
local function reference_final_hash(hash, dir, variant)
    local m <close> = cartesi.machine(dir)
    assert(m:get_root_hash() == hash, "harness error: stored template hash mismatch")
    m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input_data, hash)
    local yields = {}
    while true do
        local reason = m:run(1000)
        if reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
            yields[#yields + 1] = string.format("automatic tohost=0x%016x", m:read_reg("htif_tohost"))
        elseif reason == cartesi.BREAK_REASON_YIELDED_MANUALLY then
            yields[#yields + 1] = string.format("manual tohost=0x%016x", m:read_reg("htif_tohost"))
            break
        else
            error("harness error: guest did not reach a manual yield")
        end
    end
    -- The machine itself handles this state: it hashes it, and the oversized request is what throws.
    local at_yield_hash = m:get_root_hash()
    local ok, err = pcall(m.receive_cmio_request, m)
    if variant.rejected then
        return hash, at_yield_hash, yields, ok, err
    end
    return at_yield_hash, at_yield_hash, yields, ok, err
end

local failures = {}
for _, variant in ipairs(variants) do
    local hash, dir = build_template(variant)
    local expected, at_yield_hash, yields, direct_ok, direct_err = reference_final_hash(hash, dir, variant)
    print(
        string.format(
            "variant %s: template %s; machine ran to %s (state hash %s)",
            variant.name,
            cartesi.tohex(hash),
            table.concat(yields, ", "),
            cartesi.tohex(at_yield_hash)
        )
    )
    if direct_ok == false then
        print(string.format("variant %s: machine:receive_cmio_request() at the final yield: %s", variant.name, direct_err))
    end

    local contract = { initial_state_hash = hash, machine_directory = dir, geometry = prt.new_geometry(10) }
    local player <close> = prt.new_forked_player(contract, "honest")
    local ok, err = pcall(player.event_handler.input_added, player, 0, input_path)
    local sealed, seal_err = false, nil
    if ok then
        sealed, seal_err = pcall(player.event_handler.epoch_sealed, player, 1)
    else
        -- The same player retrying the event skips it (input_count already advanced), and the seal then fails
        -- because the epoch pair was dropped.
        local retry_ok = pcall(player.event_handler.input_added, player, 0, input_path)
        local seal_ok, seal_e = pcall(player.event_handler.epoch_sealed, player, 1)
        print(
            string.format(
                "variant %s: retry on the same player %s; epoch_sealed %s",
                variant.name,
                retry_ok and "returned without running" or "raised",
                seal_ok and "succeeded" or ("raised: " .. tostring(seal_e))
            )
        )
        -- A restarted player replays the same input and raises again.
        local restarted <close> = prt.new_forked_player(contract, "honest")
        local rok, rerr = pcall(restarted.event_handler.input_added, restarted, 0, input_path)
        print(
            string.format(
                "variant %s: restarted player input_added %s",
                variant.name,
                rok and "succeeded" or ("raised again: " .. tostring(rerr))
            )
        )
    end
    if not ok then
        failures[#failures + 1] = string.format(
            "variant %s (%s): honest player input_added raised '%s'; it cannot seal the epoch or compute its claim",
            variant.name,
            variant.what,
            tostring(err):gsub("\n.*", "")
        )
    elseif not sealed then
        failures[#failures + 1] =
            string.format("variant %s: honest player epoch_sealed raised '%s'", variant.name, tostring(seal_err))
    elseif player.final_state_hash ~= expected then
        failures[#failures + 1] = string.format(
            "variant %s: honest final state %s differs from the machine's %s",
            variant.name,
            cartesi.tohex(player.final_state_hash),
            cartesi.tohex(expected)
        )
    else
        print(string.format("variant %s: honest player sealed the epoch at %s", variant.name, cartesi.tohex(expected)))
    end
end

if #failures > 0 then
    for _, f in ipairs(failures) do
        print("FAILURE: " .. f)
    end
    print(
        "R1-GUESTTOOLS-1: the honest player aborts on a guest yield whose DATA exceeds the transmit buffer "
            .. "(unguarded receive_cmio_request throws 'CMIO request data is too large'), violating R4"
    )
    os.exit(1)
end
print("R1-GUESTTOOLS-1: honest player handled every oversized-DATA yield")
os.exit(0)
