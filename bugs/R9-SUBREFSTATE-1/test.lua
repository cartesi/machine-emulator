-- R9-SUBREFSTATE-1: the PRT referee model in doc/recipes stops accepting output proofs for good.
--
-- Drives the real wait_for_outputs of doc/recipes/prt.lua (taken from the module's closures) over
-- the real referee transport (prtu.new_server / game-transport.lua) against a real settled state:
-- the harness's baremetal-template (a valid template running emit-output.bin) after two accepted
-- advance inputs, so the settled state commits to outputs 0 and 1.
--
-- Phase 1: the honest player H (connected before settlement) answers exactly as prt.lua's
--   event_handler.prove_output does: it proves the outputs Merkle root and always offers the
--   epoch's last output (output 1). Output 1 is accepted; H's repeated offer is refused.
-- Phase 2: a party P connects and answers every prove_output request with a valid proof of
--   output 0 (and, if it is ever sent advance_time, pushes the same proof under the request id).
--
-- A5 requires: "the referee accepts every output that the settled state commits to, whenever its
-- valid proof is presented. No party can make it stop accepting them." So output 0 must be
-- accepted. The test runs the referee's own dispatcher loop until it is quiescent (no runnable
-- coroutine, no logical-time boundary, no socket activity) or until a step budget is used.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local socket = require("socket")
    local hash_tree = require("cartesi.hash-tree")
    local prtu = require("prtu")
    local prt = require("prt")
    local output_verifier = require("game-output")
    local keccak = cartesi.keccak256
    local WORD_SIZE = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE
    local WORD_MASK = WORD_SIZE - 1

    ---------------------------------------------------------------------------------------------
    -- A settled state that commits to two outputs.
    ---------------------------------------------------------------------------------------------
    local m <close> = harness.machine(harness.config_dir("baremetal-template") .. "/machine")
    local outputs = {}
    for _, payload in ipairs({ "first input -> output 0", "second input -> output 1" }) do
        m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, payload, m:get_root_hash())
        while true do
            local br = m:run(math.maxinteger)
            local _, reason, data = m:receive_cmio_request()
            if br == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
                if reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT then
                    outputs[#outputs + 1] = data
                end
            elseif br == cartesi.BREAK_REASON_YIELDED_MANUALLY then
                if reason ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
                    harness.setup_error("guest did not accept the input")
                end
                break
            else
                harness.setup_error("unexpected break reason " .. tostring(br))
            end
        end
    end
    if #outputs ~= 2 then
        harness.setup_error("expected 2 outputs, got " .. #outputs)
    end
    local final_state_hash = m:get_root_hash()
    local function prove_word(address)
        local target = address & ~WORD_MASK
        return m:read_memory(target, WORD_SIZE), m:get_proof(target, cartesi.HASH_TREE_LOG2_WORD_SIZE)
    end
    local root_proof = {}
    root_proof.iflags_y_data, root_proof.iflags_y_proof = prove_word(cartesi.machine:get_reg_address("iflags_Y"))
    root_proof.htif_tohost_data, root_proof.htif_tohost_proof =
        prove_word(cartesi.machine:get_reg_address("htif_tohost"))
    root_proof.tx_buffer_data, root_proof.tx_buffer_proof = prove_word(cartesi.AR_CMIO_TX_BUFFER_START)
    local proofs = hash_tree.frontier_next_proofs(
        hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"),
        { keccak(outputs[1]), keccak(outputs[2]) }
    )
    local offers = {}
    for i = 1, 2 do
        offers[i - 1] = { output_index = i - 1, output_data = outputs[i], output_proof = proofs[i] }
    end
    -- Preconditions: every proof is valid under the referee model's own validators.
    local outputs_root = output_verifier.validate_outputs_merkle_root_response(root_proof, final_state_hash)
    for index = 0, 1 do
        local ok, err = pcall(output_verifier.validate_output_response, offers[index], outputs_root)
        if not ok then
            harness.setup_error("proof of output " .. index .. " invalid: " .. tostring(err))
        end
    end
    print(string.format("settled state %s commits to outputs 0 and 1 (outputs root %s)",
        cartesi.tohex(final_state_hash), cartesi.tohex(outputs_root)))

    ---------------------------------------------------------------------------------------------
    -- The referee model's wait_for_outputs, as shipped.
    ---------------------------------------------------------------------------------------------
    local function upvalue(f, name)
        for i = 1, 255 do
            local n, v = debug.getupvalue(f, i)
            if not n then
                break
            end
            if n == name then
                return v, i
            end
        end
        harness.setup_error("prt.lua closure has no upvalue " .. name)
    end
    local referee_run = prt.new_referee({}).run
    local wait_for_outputs = upvalue(upvalue(referee_run, "run_referee"), "wait_for_outputs")
    local _, server_index = upvalue(referee_run, "server")

    local function run_scenario(control)
        local tag = control and "control" or "late"
        local accepted = {} -- output indices the referee reported as accepted, in order
        prtu.story.report_output = function(output)
            accepted[#accepted + 1] = output.output_index
            print(string.format("referee accepted output %d", output.output_index))
        end

        local server = prtu.new_server("127.0.0.1:0")
        debug.setupvalue(referee_run, server_index, server) -- shared by every prt.lua closure
        local dispatcher = server.dispatcher
        local _, port = server.listener:getsockname()

        ---------------------------------------------------------------------------------------------
        -- Players: in-process coroutines on the referee's dispatcher, answering through the real
        -- player-side encoder (prtu.answer_event).
        ---------------------------------------------------------------------------------------------
        local stats = {}
        local function run_player(label, offer)
            local st = { requests = 0, prove_output = 0, advance_time = 0 }
            stats[label] = st
            local client = {
                label = label,
                event_handler = {
                    prove_outputs_merkle_root = function()
                        return root_proof
                    end,
                    prove_output = function()
                        return offer
                    end,
                },
            }
            dispatcher:spawn(function()
                local sock = assert(socket.connect("127.0.0.1", port))
                sock:settimeout(0)
                assert(sock:send(cartesi.tojson({ role = "player", label = label }, -1) .. "\n"))
                local partial
                while true do
                    assert(dispatcher:wake_when_readable(sock) == "io")
                    local line, err
                    line, err, partial = sock:receive("*l", partial)
                    if not line and err ~= "timeout" then
                        return
                    elseif line then
                        local envelope = cartesi.fromjson(line)
                        st.requests = st.requests + 1
                        if envelope.operation == "prove_output" then
                            st.prove_output = st.prove_output + 1
                        end
                        local reply, done
                        if envelope.operation == "advance_time" then
                            -- Also push the offer under the id of every open prove_output request.
                            st.advance_time = st.advance_time + 1
                            local pushed = {}
                            for id, future in pairs(server.scheduled_responses) do
                                if future.event == prtu.EVENTS.prove_output then
                                    pushed[#pushed + 1] = {
                                        id = id,
                                        value = cartesi.tojson(offer, -1, "ProveOutputResponse", prtu.protocol.schemas),
                                    }
                                end
                            end
                            reply = cartesi.tojson({ value = pushed }, -1, "ResponsesEnvelope", prtu.protocol.schemas)
                        else
                            reply, done = prtu.answer_event(client, line)
                        end
                        assert(sock:send(reply .. "\n"))
                        if done then
                            sock:close()
                            return
                        end
                    end
                end
            end)
        end

        local function announced_players()
            local n = 0
            for _, c in ipairs(server.connections) do
                if c.is_player then
                    n = n + 1
                end
            end
            return n
        end

        -- The referee's loop (game-transport server:run), stopped when nothing can happen any more
        -- without new input: no runnable coroutine, no logical-time progress, no socket readiness.
        local STEP_BUDGET = 200000
        local function drive(until_fn)
            for _ = 1, STEP_BUDGET do
                if until_fn and until_fn() then
                    return "condition"
                end
                local progressed
                if dispatcher.ready_first > dispatcher.ready_last then
                    progressed = server:step_time()
                end
                if not progressed then
                    if dispatcher.ready_first > dispatcher.ready_last then
                        local r, w = socket.select(dispatcher.readable.socks, dispatcher.writable.socks, 1.0)
                        if #r == 0 and #w == 0 then
                            return "quiescent"
                        end
                    end
                    dispatcher:step()
                end
            end
            return "budget"
        end

        -- Phase 1: the honest player (and, in the control, the presenter too), then settlement
        -- and wait_for_outputs.
        run_player("honest", offers[1])
        if control then
            run_player("presenter", offers[0])
        end
        local how = drive(function()
            return announced_players() >= (control and 2 or 1)
        end)
        if how ~= "condition" then
            harness.setup_error("players did not connect: " .. how)
        end
        local referee_done, referee_error = false, nil
        dispatcher:spawn(function()
            local ok, err = pcall(wait_for_outputs, final_state_hash)
            referee_done, referee_error = true, ok and "returned" or err
        end)
        how = drive(function()
            return control and accepted[2] ~= nil
        end)
        print(string.format("[%s] phase 1: %s at block %d; honest asked prove_output %d times; accepted {%s}",
            tag, how, server:get_time(), stats.honest.prove_output, table.concat(accepted, ",")))
        if referee_done then
            harness.setup_error("wait_for_outputs ended: " .. tostring(referee_error))
        end
        if accepted[1] ~= 1 then
            harness.setup_error("precondition: the honest player's last output (1) was not accepted first")
        end
        if not control then
            -- Phase 2: a party presents a valid proof of output 0 of the settled state.
            local before = server:get_time()
            run_player("presenter", offers[0])
            how = drive(function()
                return accepted[2] ~= nil
            end)
            if referee_done then
                harness.setup_error("wait_for_outputs ended: " .. tostring(referee_error))
            end
            print(string.format("[%s] phase 2: %s; block %d -> %d; presenter connected=%s", tag, how, before,
                server:get_time(), tostring(announced_players() >= 2)))
        end
        local st = stats.presenter
        print(string.format("[%s] presenter got %d events (prove_output %d, advance_time %d); accepted {%s}", tag,
            st.requests, st.prove_output, st.advance_time, table.concat(accepted, ",")))
        server:close()
        for _, index in ipairs(accepted) do
            if index == 0 then
                return true
            end
        end
        return false
    end

    -- Control: a presenter connected before settlement gets output 0 accepted, so the players,
    -- proofs and driver work and a referee that hears the presenter makes this test pass.
    if not run_scenario(true) then
        harness.setup_error("control failed: output 0 not accepted from a presenter connected before settlement")
    end
    local zero_accepted = run_scenario(false)
    return harness.expect(zero_accepted,
        "A5: the referee accepts every output that the settled state commits to, whenever its valid proof is "
            .. "presented; no party can make it stop accepting them (valid proof of output 0 presented after the "
            .. "honest player's repeated offer of output 1)")
end)
