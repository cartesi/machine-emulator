-- R1-R3-3: the PRT referee model (doc/recipes/prt.lua validate_state_transition_response)
-- accepts a ProveStateTransition response that carries a log the transition form does not use
-- (a send_cmio_log away from an input delivery, a reset_uarch_log away from the mcycle-closing
-- uarch cycle) and silently ignores it, returning the honest after-hash.
--
-- R3: "Conditions on the log are validity conditions. A log that fails one must be rejected.
-- Examples are ... duplicate, missing, or trailing data". The deployed referee (Dave
-- CartesiStateTransition) concatenates the logs and requires the buffer to be fully consumed
-- (_requireAccessLogProofFullyConsumed), so it rejects the same proof.
--
-- The test exits 1 while the model accepts any of the superfluous-log responses, 0 once it
-- rejects all of them (raises an error), and 2 on setup errors (including when the control
-- cases fail: the honest responses must still be accepted with the right after-hash).
local harness = require("harness")

-- Finds a local function of prt.lua by name, by walking the upvalues of the closures that the
-- module exports. This is the closure the referee actually runs (settle_uarch_state_hash calls it).
local function find_local_function(module, wanted)
    local seen = {}
    local queue = {}
    for _, v in pairs(module) do
        if type(v) == "function" then
            queue[#queue + 1] = v
        end
    end
    local head = 1
    while head <= #queue do
        local f = queue[head]
        head = head + 1
        if not seen[f] then
            seen[f] = true
            local i = 1
            while true do
                local name, value = debug.getupvalue(f, i)
                if not name then
                    break
                end
                if type(value) == "function" then
                    if name == wanted then
                        return value
                    end
                    queue[#queue + 1] = value
                elseif type(value) == "table" and name ~= "_ENV" then
                    for _, w in pairs(value) do
                        if type(w) == "function" then
                            queue[#queue + 1] = w
                        end
                    end
                end
                i = i + 1
            end
        end
    end
    return nil
end

harness.main(function()
    local cartesi = require("cartesi")
    local prt = require("prt")
    local validate = find_local_function(prt, "validate_state_transition_response")
    if not validate then
        harness.setup_error("validate_state_transition_response not reachable from the prt module")
    end
    local UARCH_CYCLE_MAX = cartesi.UARCH_CYCLE_MAX
    local LOG2_UARCH = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    assert(UARCH_CYCLE_MAX == (1 << LOG2_UARCH) - 1)

    -- A bare-metal rolling template, waiting at a manual yield with the accepted reason (a valid
    -- template), so a delivery changes the state.
    local dir = harness.config_dir("baremetal-template") .. "/machine"
    local function load()
        return harness.machine(dir)
    end
    local input = harness.encode_advance({ payload = "R1-R3-3" })
    local periods_per_input = 4
    local with_input = { geometry = { periods_per_input = periods_per_input }, inputs = { input } }
    local without_input = { geometry = { periods_per_input = periods_per_input }, inputs = {} }

    local function accepted(contract, before, epoch_period_offset, state_transition_offset, response)
        local ok, result = pcall(validate, contract, before, epoch_period_offset, state_transition_offset, response)
        return ok, result
    end

    local failures = {}
    local function require_rejected(what, contract, before, epo, sto, response, honest_after)
        local ok, result = accepted(contract, before, epo, sto, response)
        if ok then
            failures[#failures + 1] = what
            io.stderr:write(
                string.format(
                    "VIOLATED: %s: accepted, after-hash %s (honest after-hash %s)\n",
                    what,
                    harness.hex(result),
                    harness.hex(honest_after)
                )
            )
        else
            io.stderr:write(string.format("OK: %s: rejected (%s)\n", what, tostring(result):gsub("\n.*", "")))
        end
    end
    local function require_control(what, contract, before, epo, sto, response, expected)
        local ok, result = accepted(contract, before, epo, sto, response)
        if not ok or result ~= expected then
            harness.setup_error(string.format("control %s: ok=%s result=%s", what, tostring(ok), tostring(result)))
        end
        io.stderr:write(string.format("control OK: %s -> %s\n", what, harness.hex(result)))
    end

    -- A valid send_cmio_log taken from the template (reused as the superfluous log below), and a
    -- valid reset_uarch_log from the template after one uarch step.
    local spare_send_cmio_log, spare_reset_log
    do
        local m <close> = load()
        local root = m:get_root_hash()
        spare_send_cmio_log = m:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, root)
    end
    do
        local m <close> = load()
        m:run_uarch(1)
        spare_reset_log = m:log_reset_uarch()
    end

    -- Case 1: an ordinary uarch step (input slot with no input, uarch cycle 0 of the slot's first
    -- mcycle) answered with the honest step_log plus a reset_uarch_log.
    do
        local m <close> = load()
        local before = m:get_root_hash()
        local step_log = m:log_step_uarch()
        local after = m:get_root_hash()
        require_control("plain step, honest logs", without_input, before, 0, 0, { step_log = step_log }, after)
        require_rejected(
            "plain step at uarch cycle 0 + superfluous reset_uarch_log",
            without_input,
            before,
            0,
            0,
            { step_log = step_log, reset_uarch_log = spare_reset_log },
            after
        )
        require_rejected(
            "plain step at uarch cycle 0 + superfluous send_cmio_log (slot holds no input)",
            without_input,
            before,
            0,
            0,
            { step_log = step_log, send_cmio_log = spare_send_cmio_log },
            after
        )
    end

    -- Case 2: an ordinary uarch step at a later uarch cycle of the first mcycle of a slot that
    -- holds an input (no delivery there) answered with the honest step_log plus a send_cmio_log.
    do
        local m <close> = load()
        local uarch_cycle = 3
        m:run_uarch(uarch_cycle)
        local before = m:get_root_hash()
        local step_log = m:log_step_uarch()
        local after = m:get_root_hash()
        require_control("mid-mcycle step, honest logs", with_input, before, 0, uarch_cycle, { step_log = step_log }, after)
        require_rejected(
            "step at uarch cycle 3 of an input slot + superfluous send_cmio_log",
            with_input,
            before,
            0,
            uarch_cycle,
            { step_log = step_log, send_cmio_log = spare_send_cmio_log },
            after
        )
        require_rejected(
            "step at uarch cycle 3 + superfluous reset_uarch_log",
            with_input,
            before,
            0,
            uarch_cycle,
            { step_log = step_log, reset_uarch_log = spare_reset_log },
            after
        )
    end

    -- Case 3: the delivery transition (state transition offset 0, first period of a slot that holds
    -- the input): honest send_cmio_log + step_log, plus a reset_uarch_log.
    do
        local m <close> = load()
        local before = m:get_root_hash()
        local send_log = m:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, before)
        local step_log = m:log_step_uarch()
        local after = m:get_root_hash()
        require_control(
            "delivery + step, honest logs",
            with_input,
            before,
            0,
            0,
            { send_cmio_log = send_log, step_log = step_log },
            after
        )
        require_rejected(
            "delivery + step + superfluous reset_uarch_log",
            with_input,
            before,
            0,
            0,
            { send_cmio_log = send_log, step_log = step_log, reset_uarch_log = spare_reset_log },
            after
        )
    end

    -- Case 4: the closing transition (uarch cycle UARCH_CYCLE_MAX) in a later period of the slot
    -- that holds the input: honest step_log + reset_uarch_log, plus a send_cmio_log.
    do
        local m <close> = load()
        m:run_uarch(UARCH_CYCLE_MAX)
        local before = m:get_root_hash()
        local step_log = m:log_step_uarch()
        local reset_log = m:log_reset_uarch()
        local after = m:get_root_hash()
        local epoch_period_offset = 1 -- input slot 0, period 1
        require_control(
            "closing step + reset, honest logs",
            with_input,
            before,
            epoch_period_offset,
            UARCH_CYCLE_MAX,
            { step_log = step_log, reset_uarch_log = reset_log },
            after
        )
        require_rejected(
            "closing step + reset + superfluous send_cmio_log",
            with_input,
            before,
            epoch_period_offset,
            UARCH_CYCLE_MAX,
            { step_log = step_log, reset_uarch_log = reset_log, send_cmio_log = spare_send_cmio_log },
            after
        )
    end

    return harness.expect(
        #failures == 0,
        string.format(
            "R3: a referee must reject a state-transition proof with superfluous (trailing) logs, as Dave's "
                .. "CartesiStateTransition does; the referee model accepted %d of 6 such proofs",
            #failures
        )
    )
end)
