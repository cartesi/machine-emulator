-- R1-A2-1: the PRT referee model in doc/recipes/prt.lua assigns its whole input record to one epoch,
-- with no cap at the input limit per epoch (2^ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH = 2^24).
--
-- Requirement (THREAT_MODEL.md A3): "The input record assigns no more inputs to an epoch than the input limit
-- per epoch." Section 3: the referee model is rated "as if a deployed referee had it" for what it accepts or
-- derives. R4: the honest operator "assigns inputs to epochs exactly as the referee does, including the input
-- limit per epoch (A3)".
--
-- The test builds the model's dapp contract with prt.new_dapp_contract from 2^24 + 1 input paths (the same
-- one-byte file, really read 2^24 + 1 times by the model's own fs.read_file), runs prt.new_referee(...):run
-- against a recording stand-in for the referee server, and counts what the referee publishes for the epoch:
-- the input_added events and the input count of epoch_sealed. The stand-in stops the run at epoch_sealed,
-- before any tournament starts.
--
-- Passes (exit 0) if the referee assigns at most 2^24 inputs to the epoch, or refuses the oversized record
-- (new_dapp_contract or the referee raises an error before sealing more than 2^24). Fails (exit 1) if it seals
-- the epoch with more than 2^24 inputs. A control run with 3 inputs checks that the stand-in reaches the seal.

local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local prt = require("prt")
    local EVENTS = require("prtu").EVENTS

    local LIMIT = 1 << cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
    if LIMIT ~= 1 << 24 then
        harness.setup_error("unexpected input limit per epoch " .. LIMIT)
    end

    local tmp = os.getenv("TMPDIR") or "/tmp"
    local input_path = string.format("%s/r1-a2-1-input-%d.bin", tmp, math.random(1 << 30))
    do
        local f = assert(io.open(input_path, "wb"))
        f:write("x")
        f:close()
    end

    local SENTINEL = {}

    -- A stand-in for the referee server (prtu.run_server): records notifications, stops at the seal.
    local function new_recording_server()
        local rec = { input_added = 0, max_offset = -1, sealed_count = nil, ordered = true }
        local srv = {}
        function srv:accept_subscribers(_)
            return { "subscriber" }
        end
        function srv:notify_all(_, event, arguments)
            if event == EVENTS.input_added then
                local offset = arguments[1]
                if offset ~= rec.input_added then
                    rec.ordered = false
                end
                rec.input_added = rec.input_added + 1
                if offset > rec.max_offset then
                    rec.max_offset = offset
                end
            elseif event == EVENTS.epoch_sealed then
                rec.sealed_count = arguments[1]
                error(SENTINEL)
            end
        end
        setmetatable(srv, {
            __index = function(_, name)
                error("recording server: unexpected call to " .. tostring(name) .. " before the seal")
            end,
        })
        return srv, rec
    end

    -- Returns rec, refusal_error (nil when the referee reached the seal).
    local function referee_publish(n)
        local paths = {}
        for i = 1, n do
            paths[i] = input_path
        end
        local hash = string.rep("\0", 32)
        local ok, dapp_or_err = pcall(prt.new_dapp_contract, hash, paths)
        paths = nil
        if not ok then
            return nil, "new_dapp_contract: " .. tostring(dapp_or_err)
        end
        local srv, rec = new_recording_server()
        local referee = prt.new_referee(dapp_or_err)
        local ok2, err = pcall(referee.run, referee, srv)
        if ok2 then
            return rec, "referee returned without sealing"
        end
        if err ~= SENTINEL then
            return rec, tostring(err)
        end
        return rec, nil
    end

    local result
    local ok, err = pcall(function()
        -- Control: the stand-in reaches the seal with a small record.
        local ctl, ctl_err = referee_publish(3)
        if ctl_err or not ctl or ctl.sealed_count ~= 3 or ctl.input_added ~= 3 then
            harness.setup_error("control run did not reach epoch_sealed with 3 inputs: " .. tostring(ctl_err))
        end
        io.stderr:write("control: 3 inputs -> 3 input_added, epoch_sealed(3)\n")

        local n = LIMIT + 1
        io.stderr:write(string.format("building the referee's dapp contract from %d input paths...\n", n))
        local rec, refusal = referee_publish(n)
        collectgarbage()
        if refusal and (not rec or not rec.sealed_count) then
            io.stderr:write("referee refused the oversized input record: ", refusal, "\n")
            result = harness.expect(true, "A3: the referee assigns no more than 2^24 inputs to an epoch (refused)")
            return
        end
        io.stderr:write(
            string.format(
                "referee published %d input_added events (offsets 0..%d, ordered=%s) and epoch_sealed(%s)\n",
                rec.input_added,
                rec.max_offset,
                tostring(rec.ordered),
                tostring(rec.sealed_count)
            )
        )
        -- Grid: the mcycle claim of this geometry addresses only LIMIT input slots.
        local g = prt.new_geometry(10)
        local slots = (1 << g.mcycle_height) // g.periods_per_input
        io.stderr:write(
            string.format(
                "dispute grid: %d input slots (mcycle_height %d, periods_per_input 2^%d); the input at offset %d"
                    .. " has no position\n",
                slots,
                g.mcycle_height,
                math.floor(math.log(g.periods_per_input, 2) + 0.5),
                LIMIT
            )
        )
        result = harness.expect(
            rec.sealed_count <= LIMIT and rec.max_offset < LIMIT,
            string.format(
                "A3: the input record assigns no more inputs to an epoch than the input limit per epoch"
                    .. " (%d); the referee model sealed the epoch with %d inputs",
                LIMIT,
                rec.sealed_count
            )
        )
    end)
    os.remove(input_path)
    if not ok then
        error(err, 0)
    end
    return result
end)
