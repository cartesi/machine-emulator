-- R1-R8-1: the PRT player (doc/recipes/prt.lua) keeps one hash per guest output for the whole input, in the
-- same epoch run that builds its mcycle computation hash (its claim), so the memory it needs to compute the
-- claim grows with the number of outputs a single input emits.
--
-- Requirement (THREAT_MODEL.md, R12): "The memory and storage the honest operator needs to defend its claims do
-- not grow with the number of outputs." (Also section 8 Out of scope: the exclusion of applications that
-- exhaust the operator through outputs "holds as long as the memory and storage that the honest operator needs
-- to defend its claims do not grow with the number of outputs".)
--
-- Method: a bare-metal rollup guest (guest.c) whose input says how many 8-byte outputs to emit (automatic
-- TX_OUTPUT yields, output i holding the counter i), then spins to a fixed mcycle budget and accepts with the correct outputs root. A forked
-- honest player (prt.new_forked_player, the one crisium.lua runs) processes one input through its normal
-- input_added handler. A Lua count hook samples the live Lua heap (after a full collection) during the run.
-- Two runs with the SAME mcycle budget and different output counts (control: SMALL outputs, test: LARGE
-- outputs) must need the same peak memory up to a margin; today the difference is ~70 bytes per output.
--
-- Exit: 0 = peak memory does not grow with the output count, 1 = it grows (bug present), 2 = setup error.

local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local hash_tree = require("cartesi.hash-tree")
    local fs = require("cartesi.filesystem")
    local prt = require("prt")
    local keccak = cartesi.keccak256

    local SMALL = tonumber(os.getenv("R1_R8_1_SMALL") or "1000")
    local LARGE = tonumber(os.getenv("R1_R8_1_LARGE") or "100000")
    local MCYCLES = 32 * LARGE -- same mcycle budget for both inputs (each output costs the guest < 32 mcycles)
    local MARGIN_KIB = 1024 -- allowed difference of peak live heap between the two runs
    local OVERSIZED = (1 << cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE) + 1 -- declared length larger than the tx buffer
    local here = (arg and arg[0] or "./test.lua"):match("^(.*)/[^/]*$") or "."

    local tmp = fs.create_temporary_directory(os.getenv("TMPDIR") or "/tmp", "r1-r8-1-")
    local _ <close> = setmetatable({}, {
        __close = function()
            os.execute("rm -rf '" .. tmp .. "'")
        end,
    })

    -- 1. Build the guest and store a valid-template-style machine: at its first manual yield, rx-accepted,
    -- with the empty outputs root in the tx buffer.
    local guest = tmp .. "/guest.bin"
    local build = string.format("'%s/baremetal/build.sh' -o '%s' '%s/guest.c' > '%s/build.log' 2>&1",
        harness.HARNESS, guest, here, tmp)
    if not os.execute(build) then
        harness.setup_error("guest build failed: " .. harness.read_file(tmp .. "/build.log"))
    end
    local template = tmp .. "/template"
    local initial_state_hash
    do
        local m <close> = harness.machine({ ram = { length = 64 << 20, backing_store = { data_filename = guest } } })
        assert(m:run(cartesi.MCYCLE_MAX) == cartesi.BREAK_REASON_YIELDED_MANUALLY, "guest did not yield")
        local cmd, reason = m:receive_cmio_request()
        assert(cmd == cartesi.HTIF_YIELD_CMD_MANUAL and reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
        m:store(template)
        initial_state_hash = m:get_root_hash()
    end
    local empty_frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")

    -- 2. One honest player, one input that emits `count` outputs of `declared` length; returns the extra peak
    -- live heap (KiB) during the input, the player's output count, and the anomalies it reported.
    local function run_case(label, count, declared)
        -- output i is the counter i (8 bytes), followed by zeros up to the declared length (capped at the tx buffer)
        local tail = string.rep("\0", math.min(declared, 1 << cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE) - 8)
        local frontier = hash_tree.frontier_copy(empty_frontier)
        for i = 0, count - 1 do
            hash_tree.frontier_push_back(frontier, keccak(string.pack("<I8", i) .. tail))
        end
        local root = hash_tree.frontier_get_root_hash(frontier)
        local input = string.pack("<I8I4I4I8", count, declared, 0, MCYCLES) .. root
        local input_path = tmp .. "/input-" .. label .. ".bin"
        fs.write_file(input, input_path)

        local dapp_contract = {
            initial_state_hash = initial_state_hash,
            machine_directory = template,
            geometry = prt.new_geometry(10),
            inputs = {},
            input_paths = {},
        }
        local player <close> = prt.new_forked_player(dapp_contract, "honest-" .. label)
        local anomalies = {}
        function player.anomaly_handler(kind)
            anomalies[kind] = (anomalies[kind] or 0) + 1
        end
        local mcycle0 = player.epoch_pair.machine:read_reg("mcycle")

        collectgarbage()
        collectgarbage()
        local base = collectgarbage("count")
        local peak, samples = base, 0
        debug.sethook(function()
            collectgarbage()
            local now = collectgarbage("count")
            samples = samples + 1
            if now > peak then
                peak = now
            end
        end, "", 20000)
        local ok, err = pcall(player.event_handler.input_added, player, 0, input_path)
        debug.sethook()
        if not ok then
            harness.setup_error("player failed on input " .. label .. ": " .. tostring(err))
        end
        local machine = player.epoch_pair.machine
        local mcycles = machine:read_reg("mcycle") - mcycle0
        local accepted = machine:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED
        local result = {
            extra_kib = peak - base,
            samples = samples,
            output_count = player.output_count,
            mcycles = mcycles,
            accepted = accepted,
            anomalies = anomalies,
        }
        local kinds = {}
        for kind, n in pairs(anomalies) do
            kinds[#kinds + 1] = kind .. "=" .. n
        end
        table.sort(kinds)
        print(string.format(
            "%-9s outputs=%-7d declared_len=%-8d mcycles=%-8d accepted=%s player.output_count=%-7d "
                .. "heap_samples=%-4d extra_peak_heap=%.0f KiB anomalies={%s}",
            label, count, declared, mcycles, tostring(accepted), player.output_count, samples, peak - base,
            table.concat(kinds, ",")))
        return result
    end

    local control = run_case("control", SMALL, 8)
    local large = run_case("large", LARGE, 8)

    -- Setup sanity: both inputs accepted, the player counted every output, the guest's root matched, the two
    -- runs spent the same mcycles (so only the output count differs), and the hook sampled during the run.
    for _, r in ipairs({ control, large }) do
        if not r.accepted or r.anomalies.outputs_merkle_root_mismatch or r.samples < 1 then
            harness.setup_error("unexpected run (not accepted, root mismatch, or too few heap samples)")
        end
    end
    if control.output_count ~= SMALL or large.output_count ~= LARGE then
        harness.setup_error("the player did not count the emitted outputs")
    end
    if math.abs(large.mcycles - control.mcycles) > 64 then
        harness.setup_error("the two inputs did not run the same mcycles")
    end

    -- Informational: one oversized_output anomaly per oversized output (not asserted; see README).
    local over1 = run_case("over-1", 1, OVERSIZED)
    local over4 = run_case("over-4", 4, OVERSIZED)
    print(string.format("info: oversized_output anomalies per input: %d (1 output), %d (4 outputs)",
        over1.anomalies.oversized_output or 0, over4.anomalies.oversized_output or 0))

    local growth = large.extra_kib - control.extra_kib
    print(string.format("peak live heap growth from %d to %d outputs at equal mcycles: %.0f KiB (%.1f bytes/output)",
        SMALL, LARGE, growth, growth * 1024 / (LARGE - SMALL)))
    return harness.expect(growth < MARGIN_KIB, string.format(
        "R12: the memory the honest operator needs to compute its claim must not grow with the number of "
            .. "outputs (peak heap difference %.0f KiB, margin %d KiB)", growth, MARGIN_KIB))
end)
