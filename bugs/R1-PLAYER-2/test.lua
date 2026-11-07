#!/usr/bin/env lua5.4
-- R1-PLAYER-2: the PRT player's input-boundary cache keeps at most 8 boundaries per epoch
-- (doc/recipes/prt.lua DEFAULT_MACHINE_CACHE_CAPACITY, machine_cache_methods:consider), so every unit of
-- player work at an adversary-chosen input (opening an mcycle bundle, opening a uarch bundle, building a
-- uarch claim, proving a state transition) first replays every whole input between the nearest retained
-- boundary and the target (new_machine_pair_at_epoch_input_offset -> run_to_epoch_input_offset).
--
-- THREAT_MODEL.md R12: "Each unit is measured from a machine at its starting position. Reaching that position
-- costs at most the mcycles from the nearest retained input boundary, which the application's per-input usage
-- bounds. A7 must cover that cost a bounded number of times for every match". Section 7 lets the adversary send
-- any number of inputs and steer the dispute to any position, so the reach cost must not grow with the number of
-- inputs in the epoch.
--
-- The test boots a bare-metal rolling application (guest.S, built at test time) that accepts every input after
-- burning ~1000 mcycles. A forked honest player (prt.new_forked_player) processes N inputs through
-- event_handler.input_added and seals the epoch. The test then picks the input farthest from a retained boundary
-- and invokes the player's units of work there: collect_mcycle_bundle, collect_uarch_cycle_bundle and
-- event_handler.prove_state_transition. It instruments run_to_epoch_input_offset to measure the mcycles replayed
-- to reach the target input. It does this for N = 64 and N = 512.
--
-- Correct behavior (asserted): the replay that reaches a unit's starting position costs at most a bounded number
-- of inputs' worth of mcycles (here: at most 2x the largest per-input usage), independent of N.
-- On feature/prt-audit it replays ~11 inputs for N=64 and ~95 inputs for N=512 (linear in N; 12287 inputs for
-- N=65536), so the test exits nonzero.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local fs = require("cartesi.filesystem")
local prt = require("prt")

local SLACK_INPUTS = 2 -- allowed reach cost, in units of the largest per-input mcycle usage
local SIZES = { 64, 512 }

local tmp = fs.create_temporary_directory(os.getenv("TMPDIR") or "/tmp", "r1-player-2-")
local _ <close> = setmetatable({}, {
    __close = function()
        os.execute("rm -rf '" .. tmp .. "'")
    end,
})

assert(os.execute("bash ./build.sh " .. tmp), "harness error: failed to build guest.bin")

-- Rolling template: waits at a manual yield with RX_ACCEPTED, transmit buffer holds the empty outputs root.
local template_dir = tmp .. "/template"
local initial_state_hash
do
    local m <close> = cartesi.new():create({ ram = { backing_store = { data_filename = tmp .. "/guest.bin" }, length = 1 << 20 } })
    local empty_root =
        hash_tree.frontier_get_root_hash(hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"))
    m:write_memory(cartesi.AR_CMIO_TX_BUFFER_START, empty_root)
    local br = m:run(1 << 20)
    assert(br == cartesi.BREAK_REASON_YIELDED_MANUALLY, "harness error: guest did not yield")
    assert(m:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED, "harness error: reason")
    m:store(template_dir)
    initial_state_hash = m:get_root_hash()
end

-- Instrument the player's replay of whole inputs (shared player method table).
local replay = nil
local function instrument(player)
    local methods = getmetatable(player).__index
    if methods.__r1_player_2 then
        return
    end
    methods.__r1_player_2 = true
    local original = methods.run_to_epoch_input_offset
    methods.run_to_epoch_input_offset = function(self, pair, first, last)
        local before = pair.machine:read_reg("mcycle")
        local results = table.pack(original(self, pair, first, last))
        if replay then
            replay.mcycles = replay.mcycles + (pair.machine:read_reg("mcycle") - before)
            replay.inputs = replay.inputs + (last - first)
        end
        return table.unpack(results, 1, results.n)
    end
end

local function measure(unit, fn)
    replay = { mcycles = 0, inputs = 0, unit = unit }
    fn()
    local r = replay
    replay = nil
    return r
end

local failures = {}
for _, n in ipairs(SIZES) do
    local dapp_contract = {
        initial_state_hash = initial_state_hash,
        machine_directory = template_dir,
        geometry = prt.new_geometry(10),
    }
    local player <close> = prt.new_forked_player(dapp_contract, "honest")
    instrument(player)
    local per_input_max = 0
    for i = 0, n - 1 do
        local path = string.format("%s/input-%d-%d", tmp, n, i)
        fs.write_file(string.pack("<I8", i), path)
        local before = player.epoch_pair.machine:read_reg("mcycle")
        player.event_handler.input_added(player, i, path)
        local used = player.epoch_pair.machine:read_reg("mcycle") - before
        if used > per_input_max then
            per_input_max = used
        end
    end
    assert(player.input_count == n and not player.epoch_stopped, "harness error: application did not accept inputs")
    player.event_handler.epoch_sealed(player, n)

    -- The adversary steers the dispute to the input farthest past a retained boundary.
    local offsets = {}
    for i, entry in ipairs(player.machine_cache.entries) do
        offsets[i] = entry.epoch_input_offset
    end
    local target, worst = 0, -1
    local j = 1
    for t = 0, n - 1 do
        while offsets[j + 1] and offsets[j + 1] <= t do
            j = j + 1
        end
        if t - offsets[j] > worst then
            target, worst = t, t - offsets[j]
        end
    end

    local results = {
        measure("collect_mcycle_bundle", function()
            player:collect_mcycle_bundle(target, 0)
        end),
        measure("collect_uarch_cycle_bundle", function()
            player:collect_uarch_cycle_bundle(target, 0, 1)
        end),
        measure("prove_state_transition", function()
            local logs = player.event_handler.prove_state_transition(player, target, 0, 1)
            assert(logs.step_log, "harness error: no step log")
        end),
    }
    local bound = SLACK_INPUTS * per_input_max
    print(
        string.format(
            "N=%d inputs, per-input usage <= %d mcycles, retained boundaries {%s}, target input %d",
            n,
            per_input_max,
            table.concat(offsets, ","),
            target
        )
    )
    for _, r in ipairs(results) do
        print(
            string.format(
                "  %-27s replayed %4d whole inputs = %7d mcycles to reach its start (bound %d)",
                r.unit,
                r.inputs,
                r.mcycles,
                bound
            )
        )
        if r.mcycles > bound then
            failures[#failures + 1] = string.format(
                "N=%d: %s at input %d replays %d whole inputs (%d mcycles), more than %d x the per-input usage "
                    .. "(%d mcycles)",
                n,
                r.unit,
                target,
                r.inputs,
                r.mcycles,
                SLACK_INPUTS,
                per_input_max
            )
        end
    end
end

if #failures > 0 then
    for _, f in ipairs(failures) do
        print("  " .. f)
    end
    print(
        "FAIL: reaching an adversary-chosen input costs a number of whole-input replays that grows linearly with the "
            .. "epoch's input count (8-entry boundary cache), not the per-input usage bound R12 requires"
    )
    os.exit(1, true)
end
print("OK: reaching every unit's starting position costs at most the per-input usage bound")
