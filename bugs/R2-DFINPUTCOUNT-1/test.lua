-- R2-DFINPUTCOUNT-1: the PRT stored player (doc/recipes/prt.lua) retains at most 32 input boundaries per
-- epoch, so the number of inputs it replays to reach a disputed input grows with the epoch's input count.
--
-- THREAT_MODEL R12: "Each is measured from a machine at its starting position. Reaching that position costs at
-- most the mcycles from the nearest retained input boundary, which the application's per-input usage bounds. A7
-- must cover that cost a bounded number of times for every match". So the inputs replayed before a per-match
-- operation (here: the leaf proof, event_handler.prove_state_transition, and the machine pair every bundle /
-- uarch-claim operation starts from) must not grow with the number of inputs in the epoch.
--
-- The test runs one stored player on a tiny bare-metal rolling template (accepts every input), measures the
-- worst replay count when the epoch holds N1 inputs and again when it holds N2 = 4*N1 inputs, and requires the
-- second not to exceed the first (or 1). Counts, not timing.
local harness = require("harness")

local N1 = tonumber(os.getenv("N1") or "128")
local N2 = tonumber(os.getenv("N2") or "512")

harness.main(function()
    local cartesi = require("cartesi")
    local ok_prt, prt = pcall(require, "prt")
    if not ok_prt then
        harness.setup_error("cannot load doc/recipes/prt.lua: " .. tostring(prt))
    end

    -- temporary work directory, removed at the end whatever happens
    local okd, tmp = harness.sh("mktemp -d -t r2-dfinputcount-XXXXXX")
    tmp = okd and tmp:gsub("%s+$", "") or nil
    if not tmp or tmp == "" then
        harness.setup_error("mktemp failed")
    end
    local _cleanup <close> = setmetatable({}, {
        __close = function()
            os.execute("rm -rf '" .. tmp .. "'")
        end,
    })

    -- A small rolling template: accept.bin (yields rx-accepted with the empty outputs root, accepts every
    -- request), 4 MiB of RAM and a small page hash-tree cache, stored at its first manual yield.
    local template_dir = tmp .. "/template"
    local template_hash
    do
        local okm, m = pcall(cartesi.machine, {
            ram = { length = 4 << 20, backing_store = { data_filename = harness.baremetal("accept") } },
            hash_tree = { phtc_size = 64 },
        }, {})
        if not okm then
            harness.setup_error("cannot create template machine: " .. tostring(m))
        end
        local br = m:run(cartesi.MCYCLE_MAX)
        if br ~= cartesi.BREAK_REASON_YIELDED_MANUALLY then
            harness.setup_error("template did not yield manually")
        end
        m:store(template_dir)
        template_hash = m:get_root_hash()
        m:destroy()
    end

    local input_path = tmp .. "/input.bin"
    do
        local f = assert(io.open(input_path, "wb"))
        f:write(harness.encode_advance({ payload = "" }))
        f:close()
    end

    local dapp_contract = {
        initial_state_hash = template_hash,
        machine_directory = template_dir,
        geometry = prt.new_geometry(10),
    }
    local epoch_directory = tmp .. "/epoch"
    os.execute("mkdir -p '" .. epoch_directory .. "'")
    local player <close> = prt.new_stored_player(dapp_contract, "honest", nil, epoch_directory)
    local handler = player.event_handler
    if handler ~= prt.stored_event_handler then
        harness.setup_error("not a stored player")
    end
    local anomalies = {}
    player.anomaly_handler = function(kind, message)
        anomalies[#anomalies + 1] = kind .. " " .. message
    end

    -- Count the inputs the player replays: every completed input it runs goes through run_to_input_mcycle_offset.
    local replayed = 0
    local counting = false
    local original_run = player.run_to_input_mcycle_offset
    player.run_to_input_mcycle_offset = function(self, ...)
        if counting then
            replayed = replayed + 1
        end
        return original_run(self, ...)
    end

    local function add_inputs(from, to)
        for i = from, to - 1 do
            handler.input_added(player, i, input_path)
            while handler.idle(player) do
            end
        end
        assert(player.input_count == to, "player did not run every input")
    end

    -- Offsets to probe: the input just before each retained boundary (worst case of the nearest-entry search)
    -- and the last input. Falls back to a spread of offsets if the cache layout is not visible.
    local function probe_offsets(n)
        local offsets, seen = {}, {}
        local function add(k)
            if k >= 0 and k < n and not seen[k] then
                seen[k] = true
                offsets[#offsets + 1] = k
            end
        end
        local cache = player.machine_cache
        local entries = cache and cache.entries
        if type(entries) == "table" and #entries > 0 and type(entries[1].epoch_input_offset) == "number" then
            for j = 2, #entries do
                add(entries[j].epoch_input_offset - 1)
            end
        else
            for k = 0, n - 1, math.max(1, n // 64) do
                add(k)
            end
        end
        add(n - 1)
        return offsets
    end

    local function worst_replay(n, operation)
        local worst, worst_k = 0, nil
        for _, k in ipairs(probe_offsets(n)) do
            replayed, counting = 0, true
            operation(k)
            counting = false
            if replayed > worst then
                worst, worst_k = replayed, k
            end
        end
        return worst, worst_k
    end

    -- Epoch with N1 inputs (still open): the machine pair every per-match unit starts from.
    add_inputs(0, N1)
    local entries_n1 = player.machine_cache.entries and #player.machine_cache.entries
    local r1, k1 = worst_replay(N1, function(k)
        local pair <close> = player:new_machine_pair_at_epoch_input_offset(k)
        assert(pair.machine, "no machine")
    end)
    io.stderr:write(string.format("N=%d inputs: %s retained boundaries (input_gap %s); worst replay %d inputs (k=%s)\n",
        N1, tostring(entries_n1), tostring(player.machine_cache.input_gap), r1, tostring(k1)))

    -- Same epoch grown to N2 inputs and sealed: the leaf proof of a match (delivery + step at input k).
    add_inputs(N1, N2)
    handler.epoch_sealed(player, N2)
    local entries_n2 = player.machine_cache.entries and #player.machine_cache.entries
    local r2, k2 = worst_replay(N2, function(k)
        local logs = handler.prove_state_transition(player, k, 0, 0)
        assert(logs and logs.send_cmio_log and logs.step_log, "no proof")
    end)
    io.stderr:write(string.format("N=%d inputs: %s retained boundaries (input_gap %s); worst replay %d inputs (k=%s)\n",
        N2, tostring(entries_n2), tostring(player.machine_cache.input_gap), r2, tostring(k2)))
    if #anomalies > 0 then
        io.stderr:write("anomalies reported by the player: " .. table.concat(anomalies, "; ") .. "\n")
    end

    return harness.expect(
        r2 <= math.max(r1, 1),
        string.format(
            "R12: reaching a disputed input must replay a number of inputs bounded independently of the epoch's "
                .. "input count (per-match cost bounded by the application's per-input usage); observed %d at "
                .. "%d inputs and %d at %d inputs",
            r1, N1, r2, N2
        )
    )
end)
