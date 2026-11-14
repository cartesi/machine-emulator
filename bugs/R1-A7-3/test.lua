-- R1-A7-3: the stored PRT player (doc/recipes/prt.lua), driven by crisium.lua's main loop, runs a later
-- epoch's input as ONE idle step, to the input's fixed point. crisium.lua observes the chain only between
-- idle steps, so while that step runs no event of the sealed epoch's dispute (a match that puts the honest
-- claim on turn) is observed or answered. The delay grows with the input's mcycle count, up to the
-- per-input limit 2^LOG2_MAX_MCYCLES_PER_ADVANCE_STATE (2^48), which no dispute clock covers.
--
-- Threat model, R4: "The honest operator observes the chain and submits its transactions within the dispute
-- clocks." and "The honest operator defends every epoch whose dispute is open, including while it processes
-- the inputs of later epochs." The recipe itself claims (prt.lua, stored_event_handler): "A stored player
-- only records its inputs and runs them in idle time, so an open epoch never delays a response in a sealed
-- epoch's dispute."
--
-- Setup, as crisium.lua has it once epoch e is sealed and epoch e+1 is open: two stored players (prt.lua,
-- unchanged), epoch e sealed and epoch e+1 open, on a bare-metal template whose correctly designed guest
-- spins for a number of iterations its input names, then accepts. The input sender adds to epoch e+1 one
-- input (recorded through the stored player's input_added, which only stores it), and the test performs
-- ONE step of crisium.lua's idle() (each listener's player.event_handler.idle, newest epoch first), which is
-- the work crisium does between two observations of the chain tip.
--
-- Required: one idle step does a bounded slice of work, so a long input of a later epoch is not run to its
-- end between two observations of the chain. Asserted: after one idle step, a long input (2^27 mcycles)
-- has not been run whole (the epoch machine advanced fewer mcycles than the input needs). A short input
-- (2^20 mcycles) is the control that shows the per-step work scales with the input's length.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local prt = require("prt")

    local here = harness.REPO .. "/bugs/R1-A7-3"
    local guest = here .. "/guest.bin"
    local f = io.open(guest, "rb")
    if not f then
        harness.setup_error("guest.bin missing; run build-guest.sh")
    end
    f:close()

    local base = assert(os.getenv("TMPDIR") or "/tmp")
    local p = assert(io.popen("mktemp -d " .. base .. "/r1-a7-3.XXXXXX"))
    local tmp = assert(p:read("l"))
    p:close()
    local cleanup <close> = setmetatable({}, {
        __close = function()
            os.execute("rm -rf '" .. tmp .. "'")
        end,
    })

    -- Template: the guest at its first manual yield, accepted, empty outputs root in the tx buffer
    local template_dir = tmp .. "/template"
    local template_hash
    do
        local m <close> = cartesi.machine({ ram = { length = 64 << 20, backing_store = { data_filename = guest } } })
        if m:run(math.maxinteger) ~= cartesi.BREAK_REASON_YIELDED_MANUALLY then
            harness.setup_error("guest did not yield manually")
        end
        local reason = (m:read_reg("htif_tohost") >> 32) & 0xffff
        if reason ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            harness.setup_error("guest did not accept")
        end
        m:store(template_dir)
        template_hash = m:get_root_hash()
    end

    -- As prt.load_epoch_checkpoint builds it
    local dapp = {
        initial_state_hash = template_hash,
        machine_directory = template_dir,
        geometry = prt.new_geometry(10),
    }

    local function input_file(name, iterations)
        local path = tmp .. "/" .. name .. ".bin"
        local out = assert(io.open(path, "wb"))
        out:write(string.pack("<I8", iterations))
        out:close()
        return path
    end

    -- Epoch e: sealed (its dispute is open). Epoch e+1: open, receives the later inputs.
    local sealed_dir, open_dir = tmp .. "/epoch-0", tmp .. "/epoch-1"
    os.execute("mkdir -p '" .. sealed_dir .. "' '" .. open_dir .. "'")
    local sealed <close> = prt.new_stored_player(dapp, "honest", nil, sealed_dir)
    sealed.event_handler.epoch_sealed(sealed, 0)
    local open <close> = prt.new_stored_player(dapp, "honest", nil, open_dir)
    local listeners = { { player = sealed }, { player = open } }

    -- crisium.lua idle(): one step of work for every player, between two observations of the tip
    local function crisium_idle()
        local more = false
        for i = #listeners, 1, -1 do
            local player = listeners[i].player
            more = player.event_handler.idle(player) or more
        end
        return more
    end

    local next_input = 0
    local function one_step_over(name, iterations)
        open.event_handler.input_added(open, next_input, input_file(name, iterations))
        next_input = next_input + 1
        local before = open.epoch_pair.machine:read_reg("mcycle")
        local t0 = os.clock()
        crisium_idle()
        local seconds = os.clock() - t0
        local after = open.epoch_pair.machine:read_reg("mcycle")
        local r = {
            needed = 2 * iterations, -- the input runs at least 2 instructions per iteration
            advanced = after - before,
            ran_whole = open.input_count == next_input and not open:has_pending_input(),
            seconds = seconds,
        }
        io.stderr:write(
            string.format(
                "%s input (needs >= %d mcycles): one idle step advanced %d mcycles in %.2f s CPU, ran it whole: %s\n",
                name,
                r.needed,
                r.advanced,
                seconds,
                tostring(r.ran_whole)
            )
        )
        return r
    end

    local short = one_step_over("short", 1 << 19)
    if not short.ran_whole then
        -- A fixed player may slice even the short input; drain it so the long input starts at a boundary.
        repeat
        until not crisium_idle()
    end
    local long = one_step_over("long", 1 << 26)
    io.stderr:write(
        string.format(
            "per-step work ratio long/short: %.1f (input length ratio %d); at the same rate, one step of an input"
                .. " at the 2^%d-mcycle limit would take about %.0f days\n",
            long.advanced / math.max(short.advanced, 1),
            long.needed // short.needed,
            cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE,
            long.seconds / long.advanced * (1 << cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE) / 86400
        )
    )

    return harness.expect(
        long.advanced < long.needed and not long.ran_whole,
        "R4: the honest operator observes the chain within the dispute clocks while it processes later epochs'"
            .. " inputs; one idle step (between two tip observations of crisium.lua) must not run a later"
            .. " epoch's whole input of "
            .. long.needed
            .. " mcycles (advanced "
            .. long.advanced
            .. ")"
    )
end)
