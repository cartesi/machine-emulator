-- R2-DFYIELD-1: while it computes its mcycle claim, the PRT player (doc/recipes/prt.lua) copies the tx-buffer
-- payload that each automatic yield DECLARES (tohost DATA, up to 2 MiB, chosen by the guest) out of the machine,
-- and keccak-hashes it for TX_OUTPUT, at every automatic yield. The guest need not write those bytes, so a
-- guest-chosen length, not guest work, sets the host cost per yield of building a part of the claim.
--
-- Requirement (THREAT_MODEL.md section 8, High, rated for a support stand-in as section 3 says): "A defect that
-- lets the guest ... multiply the worst-case cost of an operation listed in R12 by a constant factor, compared
-- with the same operation without the defect ... A cost that the specified semantics require is not a defect."
-- R12 lists "a part of a claim"; section 4: "The outputs Merkle root, the output payloads, and every other yield
-- reason are opaque guest data that the state merely commits to."
--
-- Method: a bare-metal rollup guest (guest.c) makes K automatic yields per input with a chosen reason and declared
-- length, writing only an 8-byte counter to the tx buffer, spins to a fixed mcycle budget and accepts with the
-- correct outputs root (checked first on a plain machine without the player). A fresh forked honest player
-- (prt.new_forked_player, as the "honest" role of prt.lua runs it) processes one input through input_added
-- (run_next_input, the pass that builds its mcycle computation hash).
-- The machine API's receive_cmio_request and cartesi.keccak256 are wrapped to count the payload bytes the pass
-- copies out of the machine and hashes. Three inputs with the same K and the same mcycles:
--   control : TX_OUTPUT yields declaring 8 bytes
--   outputs : TX_OUTPUT yields declaring 2 MiB (nothing beyond the 8-byte counter written)
--   reports : TX_REPORT yields declaring 2 MiB (nothing beyond the 8-byte counter written)
-- Asserted: the payload bytes the claim pass copies and hashes do not grow with the declared length (per-yield
-- excess over the control at most SLACK bytes). Wall-clock times are printed for information only.
--
-- Exit: 0 = the claim pass's work does not depend on the declared payload length, 1 = it does, 2 = setup error.

local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local socket = require("socket")

    -- Counters, active only while the player processes the input.
    local counting = false
    local stats
    local function reset_stats()
        stats = { receive_calls = 0, receive_bytes = 0, keccak_calls = 0, keccak_bytes = 0 }
    end
    reset_stats()

    -- prt.lua captures cartesi.keccak256 at load time, so wrap it before requiring prt.
    local orig_keccak = cartesi.keccak256
    cartesi.keccak256 = function(...)
        if counting then
            stats.keccak_calls = stats.keccak_calls + 1
            for i = 1, select("#", ...) do
                local v = select(i, ...)
                if type(v) == "string" then
                    stats.keccak_bytes = stats.keccak_bytes + #v
                end
            end
        end
        return orig_keccak(...)
    end
    -- Local and JSON-RPC machine objects share one metatable; wrap its receive_cmio_request method.
    do
        local probe <close> = cartesi.machine({ ram = { length = 1 << 20 } })
        local index = getmetatable(probe).__index
        assert(type(index) == "table", "machine methods are not in a table")
        local orig_receive = assert(index.receive_cmio_request)
        index.receive_cmio_request = function(self, ...)
            local r = table.pack(orig_receive(self, ...))
            if counting then
                stats.receive_calls = stats.receive_calls + 1
                if type(r[3]) == "string" then
                    stats.receive_bytes = stats.receive_bytes + #r[3]
                end
            end
            return table.unpack(r, 1, r.n)
        end
    end

    local hash_tree = require("cartesi.hash-tree")
    local fs = require("cartesi.filesystem")
    local prt = require("prt")
    local keccak = orig_keccak

    local K = tonumber(os.getenv("R2_DFYIELD_1_YIELDS") or "50")
    local MCYCLES = 8192 -- same mcycle budget for every input (each yield costs the guest far fewer mcycles)
    local SLACK = 1024 -- allowed per-yield excess of payload bytes copied+hashed over the 8-byte control
    local TX_LEN = 1 << cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE -- 2 MiB, the largest length a yield may declare
    local TX_OUTPUT = cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT
    local TX_REPORT = cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT
    local here = (arg and arg[0] or "./test.lua"):match("^(.*)/[^/]*$") or "."

    local tmp = fs.create_temporary_directory(os.getenv("TMPDIR") or "/tmp", "r2-dfyield-1-")
    local _ <close> = setmetatable({}, {
        __close = function()
            os.execute("rm -rf '" .. tmp .. "'")
        end,
    })

    -- 1. Build the guest and store a valid-template-style machine: at its first manual yield, rx-accepted,
    -- with the empty outputs root in the tx buffer, automatic and manual yields enabled.
    local guest = tmp .. "/guest.bin"
    local build = string.format("'%s/baremetal/build.sh' -o '%s' '%s/guest.c' > '%s/build.log' 2>&1",
        harness.HARNESS, guest, here, tmp)
    if not os.execute(build) then
        harness.setup_error("guest build failed: " .. harness.read_file(tmp .. "/build.log"))
    end
    local template = tmp .. "/template"
    local initial_state_hash
    do
        local m <close> = harness.machine({
            ram = { length = 64 << 20, backing_store = { data_filename = guest } },
            processor = { registers = { htif = {
                iyield = cartesi.HTIF_YIELD_CMD_MANUAL_MASK | cartesi.HTIF_YIELD_CMD_AUTOMATIC_MASK,
            } } },
        })
        assert(m:run(cartesi.MCYCLE_MAX) == cartesi.BREAK_REASON_YIELDED_MANUALLY, "guest did not yield")
        local cmd, reason = m:receive_cmio_request()
        assert(cmd == cartesi.HTIF_YIELD_CMD_MANUAL and reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
        m:store(template)
        initial_state_hash = m:get_root_hash()
    end
    local empty_frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")

    -- 2. One fresh honest player, one input with K automatic yields of `reason` declaring `declared` bytes.
    local function run_case(label, reason, declared)
        local frontier = hash_tree.frontier_copy(empty_frontier)
        if reason == TX_OUTPUT then
            -- output i is the counter i (8 bytes) followed by the zeros of the tx buffer up to the declared length
            local tail = string.rep("\0", declared - 8)
            for i = 0, K - 1 do
                hash_tree.frontier_push_back(frontier, keccak(string.pack("<I8", i) .. tail))
            end
        end
        local root = hash_tree.frontier_get_root_hash(frontier)
        local input = string.pack("<I8I4I4I8", K, declared, reason, MCYCLES) .. root
        local input_path = tmp .. "/input-" .. label .. ".bin"
        fs.write_file(input, input_path)

        -- Independent check of the guest on a plain local machine (no player): K automatic yields with this
        -- reason and declared length, then an accepted manual yield.
        do
            local m <close> = cartesi.machine(template, {})
            m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, m:get_root_hash())
            local seen = 0
            while true do
                local br = m:run(cartesi.MCYCLE_MAX)
                if br == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
                    if m:read_reg("htif_tohost_reason") ~= reason or m:read_reg("htif_tohost_data") ~= declared then
                        harness.setup_error("guest yielded with an unexpected reason or length")
                    end
                    seen = seen + 1
                elseif br == cartesi.BREAK_REASON_YIELDED_MANUALLY then
                    break
                else
                    harness.setup_error("guest stopped with break reason " .. tostring(br))
                end
            end
            if seen ~= K or m:read_reg("htif_tohost_reason") ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
                harness.setup_error("guest did not make " .. K .. " automatic yields and accept")
            end
        end

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

        reset_stats()
        counting = true
        local t0 = socket.gettime()
        local ok, err = pcall(player.event_handler.input_added, player, 0, input_path)
        local dt = socket.gettime() - t0
        counting = false
        if not ok then
            harness.setup_error("player failed on input " .. label .. ": " .. tostring(err))
        end
        local machine = player.epoch_pair.machine
        local r = {
            label = label,
            mcycles = machine:read_reg("mcycle") - mcycle0,
            accepted = machine:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED,
            output_count = player.output_count,
            anomalies = anomalies,
            seconds = dt,
        }
        for k, v in pairs(stats) do
            r[k] = v
        end
        r.payload_bytes = r.receive_bytes + r.keccak_bytes
        local kinds = {}
        for kind, n in pairs(anomalies) do
            kinds[#kinds + 1] = kind .. "=" .. n
        end
        table.sort(kinds)
        print(string.format(
            "%-8s yields=%d declared=%-8d mcycles=%-6d accepted=%s outputs=%-3d receive: %d calls %d B | "
                .. "keccak: %d calls %d B | time %.3f s | anomalies={%s}",
            label, K, declared, r.mcycles, tostring(r.accepted), r.output_count, r.receive_calls, r.receive_bytes,
            r.keccak_calls, r.keccak_bytes, dt, table.concat(kinds, ",")))
        return r
    end

    local control = run_case("control", TX_OUTPUT, 8)
    local outputs = run_case("outputs", TX_OUTPUT, TX_LEN)
    local reports = run_case("reports", TX_REPORT, TX_LEN)

    -- Setup sanity: the player ran every input to its accepted yield, and the three inputs ran the same mcycles
    -- (only the reason and the declared length differ). The guest's yields were checked without the player above.
    -- The player's output count and anomalies are printed, not asserted: a fixed player may track outputs elsewhere.
    for _, r in ipairs({ control, outputs, reports }) do
        if not r.accepted then
            harness.setup_error("input " .. r.label .. " not accepted by the player's run")
        end
        if math.abs(r.mcycles - control.mcycles) > 64 then
            harness.setup_error("the inputs did not run the same mcycles")
        end
    end

    local ok = true
    for _, r in ipairs({ outputs, reports }) do
        local excess = (r.payload_bytes - control.payload_bytes) / K
        local within = excess <= SLACK
        print(string.format(
            "%s: payload bytes copied+hashed by the claim pass %d vs control %d: %.0f extra bytes per yield "
                .. "(allowed %d); time %.2fx the control",
            r.label, r.payload_bytes, control.payload_bytes, excess, SLACK, r.seconds / control.seconds))
        ok = ok and within
    end
    return harness.expect(ok, string.format(
        "section 8 High / R12 'a part of a claim': the work the player's claim pass does per automatic yield "
            .. "must not be multiplied by the payload length the guest declares in tohost (opaque guest data, "
            .. "section 4); %d yields declaring %d bytes each, writing 8", K, TX_LEN))
end)
