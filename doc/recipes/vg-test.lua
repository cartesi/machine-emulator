-- Run with make -C doc test-vg. This does not parse or render the README.
local cartesi = require("cartesi")
local util = require("cartesi.util")
local vg = require("rolling-verification-game")
local vgu = require("vgu")
local run_with_server = require("game-test-server")
local initial_hash = cartesi.fromhex(util.read_file("initial-hash"))
local paths = { "input-0.bin", "input-1.bin", "input-2.bin" }
local function run_game(players, input_paths)
    local referee = vg.new_referee(initial_hash, input_paths or paths)
    run_with_server(vgu.protocol, function(server, run_client, wait_connections)
        for index, player in ipairs(players) do
            run_client(nil, function(_, line)
                return vgu.answer_event(player, line)
            end, true)
            wait_connections(index)
        end
        referee:run(server)
    end)
    vgu.close_narration()
    return referee
end
local first <close> = vg.new_player(initial_hash)
local second <close> = vg.new_player(initial_hash)
local referee = run_game({ first, second })
assert(referee.winner.index == 1 and referee.final_hash == first.final_hash)
assert(referee.output and not referee.transition)
print("vg-test: equal claims ok")

-- The losing connection can prove outputs after exhausting its clock. Providers
-- can also join after settlement, with different connections supplying the root
-- and the output. Empty or invalid earlier offers must not suppress their proofs.
local function empty_offer()
    return {}
end
local empty_handlers = {
    __index = function()
        return empty_offer
    end,
}
for _, late_providers in ipairs({ false, true }) do
    run_with_server(vgu.protocol, function(server, run_client, wait_connections)
        local settled = vg.new_referee(initial_hash, {})
        local root_offer = vg.event_handler.prove_outputs_merkle_root(first)
        local output_offer = vg.event_handler.prove_output(first)
        local offers = { prove_outputs_merkle_root = root_offer, prove_output = output_offer }
        local joined, connections = {}, 2
        for index = 1, 2 do
            local client = { event_handler = setmetatable({}, empty_handlers) }
            function client.event_handler.commit_final_hash()
                return index == 1 and cartesi.keccak256("losing claim") or first.final_hash
            end
            local function offer(_, target, operation)
                assert(settled.winner.index == 2 and settled.final_hash == first.final_hash)
                assert(settled.players[1].allowance == 0)
                assert(target == (operation == "prove_output" and root_offer.tx_buffer_data or first.final_hash))
                if late_providers and not joined[operation] then
                    joined[operation] = true
                    local provider = {
                        event_handler = setmetatable({
                            [operation] = function(_, requested)
                                assert(requested == target)
                                return offers[operation]
                            end,
                        }, empty_handlers),
                    }
                    run_client(nil, function(_, line)
                        return vgu.answer_event(provider, line)
                    end, true)
                    connections = connections + 1
                    wait_connections(connections)
                end
                if index == 1 and not late_providers then
                    return offers[operation]
                end
                return index == 1 and {} or { invalid = true }
            end
            function client.event_handler.prove_outputs_merkle_root(self, target)
                return offer(self, target, "prove_outputs_merkle_root")
            end
            function client.event_handler.prove_output(self, target)
                return offer(self, target, "prove_output")
            end
            run_client(nil, function(_, line)
                return vgu.answer_event(client, line)
            end, true)
            wait_connections(index)
        end
        settled:run(server)
        assert(settled.output and settled.output.output == output_offer.output)
        assert(settled.players[1].allowance == 0 and settled.players[2].allowance == 4)
        assert(#server:get_players() == (late_providers and 4 or 2))
    end)
    vgu.close_narration()
end
print("vg-test: permissionless output providers ok")

-- A valid terminal log derives the next hash. It can confirm the opponent's
-- disputed endpoint or contradict it; validity alone does not award its sender.
for _, confirms in ipairs({ false, true }) do
    local pair <close> = first.agreed:fork()
    local log = { step_log = pair.machine:log_step_uarch() }
    local after = pair.machine:get_root_hash()
    local claims = { cartesi.keccak256("first endpoint"), confirms and after or cartesi.keccak256("second endpoint") }
    run_with_server(vgu.protocol, function(server, run_client, wait_connections)
        for index = 1, 2 do
            local client = { event_handler = setmetatable({}, empty_handlers) }
            function client.event_handler.commit_final_hash()
                return claims[index]
            end
            function client.event_handler.commit_bisection()
                return { agree = false, midpoint_hash = claims[index] }
            end
            function client.event_handler.commit_log()
                return { agree = false, log = log }
            end
            run_client(nil, function(_, line)
                return vgu.answer_event(client, line)
            end, true)
            wait_connections(index)
        end
        local settled = vg.new_referee(initial_hash, {})
        settled:run(server)
        assert(settled.transition.valid and settled.transition.after_hash == after)
        assert(settled.transition.player == 1 and settled.winner.index == (confirms and 2 or 1))
        assert(settled.final_hash == claims[settled.winner.index])
    end)
    vgu.close_narration()
end
print("vg-test: terminal proof selects the endpoint owner ok")

if arg[1] ~= "execution" then
    local roles = require("vg-dishonest")
    for _, role in ipairs({ "forger", "tamperer", "quitter" }) do
        for honest_index = 1, 2 do
            local honest <close> = vg.new_player(initial_hash)
            local opponent <close> = role == "forger" and roles.new_forger(initial_hash, 2, "forged-input-2.bin")
                or role == "tamperer" and roles.new_tamperer(initial_hash, 0, 100)
                or roles.new_quitter()
            local players = honest_index == 1 and { honest, opponent } or { opponent, honest }
            local result = run_game(players)
            assert(result.winner.index == honest_index, role .. " defeated the honest player")
            assert(result.final_hash == honest.final_hash and result.output)
            print("vg-test: honest player " .. honest_index .. " defeats " .. role)
        end
    end

    require("vg-fabulist-test")(initial_hash, paths)
end

-- A loaded machine must match its content-addressed snapshot.
assert(not pcall(vg.new_player, string.rep("\0", 32), "mismatch", first.agreed.machine:fork_server()))
assert(vg.usaturating_add(cartesi.MCYCLE_MAX - 2, 3) == cartesi.MCYCLE_MAX)
assert(vg.usaturating_add(math.maxinteger, 2) == math.mininteger + 1)

-- Initial-state checks use the execution break reason and the CMIO yield reason.
-- A halt takes precedence even when the machine still carries an accepted yield.
for _, invalid in ipairs({ "halt", "rejected" }) do
    local machine = first.agreed.machine:fork_server()
    if invalid == "halt" then
        machine:write_reg("iflags_H", 1)
    else
        machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED)
    end
    assert(not pcall(vg.new_player, machine:get_root_hash(), invalid, machine))
    assert(not pcall(machine.read_reg, machine, "mcycle"), "failed constructor left its machine running")
end

-- A failed fork closes the initial machine through the player's scope cleanup
-- and preserves the original error.
do
    local closed = {}
    local function close(machine)
        assert(not closed[machine], "machine closed twice")
        closed[machine] = true
    end
    local initial = {
        shutdown_server = close,
        get_root_hash = function()
            return initial_hash
        end,
        read_reg = function(_, reg)
            assert(reg == "mcycle")
            return 10
        end,
        run = function(_, target)
            assert(target == 10)
            return cartesi.BREAK_REASON_YIELDED_MANUALLY
        end,
        receive_cmio_request = function()
            return cartesi.HTIF_YIELD_CMD_MANUAL, cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED, ""
        end,
        fork_server = function()
            error("injected fork failure")
        end,
    }
    local ok, err = pcall(vg.new_player, initial_hash, "fork failure", initial)
    assert(not ok and tostring(err):find("injected fork failure", 1, true))
    assert(closed[initial])
end

-- Rejections, including consecutive rejections, restore the full boundary state.
do
    local player <close> = vg.new_player(initial_hash)
    vg.event_handler.initial_state(player, initial_hash)
    vg.event_handler.input_added(player, 0, paths[1])
    local accepted = player.latest.machine:get_root_hash()
    local prefix <close> = player.agreed:fork()
    local _, yield_reason = player:run_advance_state_input(prefix, 0, (1 << 48) - 1)
    assert(yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
    assert(not prefix.backup and prefix.machine:get_root_hash() == accepted)
    vg.event_handler.input_added(player, 1, paths[2])
    assert(player.latest.machine:get_root_hash() == accepted)
    vg.event_handler.input_added(player, 2, paths[2])
    assert(player.latest.machine:get_root_hash() == accepted)
    assert(#player.outputs == 1)
    vg.event_handler.epoch_sealed(player, 3)
end

-- Mcycle midpoints replay from the bisection-owned input boundary, even after
-- execution settles its own snapshot. Neither replay nor discarding a candidate
-- changes the agreed pair or the replay checkpoint.
do
    local player <close> = vg.new_player(initial_hash)
    vg.event_handler.initial_state(player, initial_hash)
    vg.event_handler.input_added(player, 0, paths[2])
    vg.event_handler.input_added(player, 1, paths[1])
    vg.event_handler.epoch_sealed(player, 2)

    local virgin <close> = player.agreed:fork()
    local break_reason, yield_reason, input_mcycle_boundary = player:run_advance_state_input(virgin, 0, 0)
    assert(input_mcycle_boundary == virgin.machine:read_reg("mcycle"))
    assert(break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY)
    assert(yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
    assert(virgin.machine:get_root_hash() == initial_hash and not virgin.backup)
    local inside_hash = player:propose_midpoint({ level = "mcycle", input = 0, lo = 0, hi = 2 })
    local candidate = player.tentative
    local input_boundary = player.input_boundary
    assert(input_boundary.machine:get_root_hash() == initial_hash and not input_boundary.backup)
    break_reason = candidate.machine:run(candidate.machine:read_reg("mcycle"))
    assert(break_reason == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    assert(candidate.backup:get_root_hash() == initial_hash)
    player:commit()
    assert(player.agreed == candidate and not player.tentative)

    local interval = { level = "mcycle", input = 0, lo = 1, hi = (1 << 48) - 1 }
    assert(player:propose_midpoint(interval) == initial_hash)
    candidate = player.tentative
    assert(candidate.machine ~= player.agreed.machine and not candidate.backup)
    assert(player.input_boundary == input_boundary and input_boundary.machine:get_root_hash() == initial_hash)
    assert(input_boundary.machine:read_reg("mcycle") == input_mcycle_boundary)
    player:revert()
    assert(not player.tentative and player.agreed.machine:get_root_hash() == inside_hash)
    assert(player.agreed.backup:get_root_hash() == initial_hash)

    assert(player:propose_midpoint(interval) == initial_hash)
    player:commit()
    local agreed_machine = player.agreed.machine
    assert(not player.agreed.backup)
    interval.lo = 1 << 47
    assert(player:propose_midpoint(interval) == initial_hash)
    assert(not player.tentative.backup)
    assert(player.input_boundary == input_boundary and input_boundary.machine:get_root_hash() == initial_hash)
    assert(input_boundary.machine:read_reg("mcycle") == input_mcycle_boundary)
    player:revert()
    assert(player.agreed.machine == agreed_machine and not player.agreed.backup)
    assert(agreed_machine:get_root_hash() == initial_hash)

    -- Finishing an input and advancing to the next one uses the same driver.
    local replay <close> = input_boundary:fork()
    player:run_to_input_boundary(replay, 0, 2)
    assert(not replay.backup and replay.machine:get_root_hash() == player.final_hash)
end

-- Empty epochs finish after establishing the root, without inventing an output.
do
    local a <close> = vg.new_player(initial_hash)
    local b <close> = vg.new_player(initial_hash)
    local empty = run_game({ a, b }, {})
    assert(empty.final_hash == initial_hash and empty.outputs_root and not empty.output)
end

-- Validate terminal logs directly at input inclusion, an ordinary step, and the
-- reset carrying rejection rollback. These checks use the same verifier as disputes.
do
    local player <close> = vg.new_player(initial_hash)
    vg.event_handler.initial_state(player, initial_hash)
    vg.event_handler.input_added(player, 0, paths[2])
    vg.event_handler.epoch_sealed(player, 1)
    local contract = { inputs = { util.read_file(paths[2]) } }
    local function verify(machine, mcycle, cycle, input, expected)
        local before = machine:get_root_hash()
        local logs = {}
        if input then
            logs.send_cmio_log = machine:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, before)
        end
        logs.step_log = machine:log_step_uarch()
        if cycle == cartesi.UARCH_CYCLE_MAX then
            logs.reset_uarch_log = machine:log_reset_uarch()
        end
        assert(
            vg.verify_state_transition(contract, 0, mcycle, cycle, before, logs)
                == (expected or machine:get_root_hash())
        )
        assert(not vg.verify_state_transition(contract, 0, mcycle, cycle, before, {}))
    end
    local included <close> = player.agreed:fork()
    local prefix <close> = player.agreed:fork()
    verify(included.machine, 0, 0, contract.inputs[1])
    player:run_uarch(prefix, 0, 0, 1)
    assert(prefix.machine:get_root_hash() == included.machine:get_root_hash())
    verify(included.machine, 0, 1)
    player:run_uarch(prefix, 0, 0, 2)
    assert(prefix.machine:get_root_hash() == included.machine:get_root_hash())
    local rejected <close> = player.agreed:fork()
    vg.load_cmio_input(rejected, contract.inputs[1])
    player:run_to_stop(rejected, 0, vg.usaturating_add(rejected.backup:read_reg("mcycle"), 1 << 48))
    -- Replay to the instruction that performs the rejecting yield, before its reset.
    local offset = rejected.machine:read_reg("mcycle") - rejected.backup:read_reg("mcycle") - 1
    local boundary <close> = player.agreed:fork()
    player:run_advance_state_input(boundary, 0, offset)
    boundary.machine:run_uarch(cartesi.UARCH_CYCLE_MAX)
    verify(boundary.machine, offset, cartesi.UARCH_CYCLE_MAX, nil, initial_hash)
    local replay <close> = player.agreed:fork()
    player:run_advance_state_input(replay, 0, offset + 1)
    assert(replay.machine:get_root_hash() == initial_hash, "reset did not carry rejection rollback")
    -- With no posted input, verification requires no inclusion log. A uarch
    -- period still has its halted tail and reset, even at a fixed mcycle state.
    local absent <close> = player.agreed:fork()
    local before = absent.machine:get_root_hash()
    local step = absent.machine:log_step_uarch()
    assert(
        vg.verify_state_transition({ inputs = {} }, 0, 0, 0, before, { step_log = step })
            == absent.machine:get_root_hash()
    )
end

-- Multiple outputs in one input, followed by empty and rejected batches, must
-- leave a proof of the last accepted output against the cumulative output root.
do
    local hash_tree = require("cartesi.hash-tree")
    local batches = {
        { accepted = true, "first", "second" },
        { accepted = true },
        { accepted = false, "discarded" },
        { accepted = true, "third", "last" },
        { accepted = true },
    }
    local expected = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
    for _, batch in ipairs(batches) do
        if batch.accepted then
            for _, output in ipairs(batch) do
                hash_tree.frontier_push_back(expected, cartesi.keccak256(output))
            end
        end
        batch.root = hash_tree.frontier_get_root_hash(expected)
    end
    local function new_pair()
        return {
            machine = {
                read_reg = function()
                    return 0
                end,
                get_root_hash = function()
                    return initial_hash
                end,
                batch = { accepted = true },
                send_cmio_response = function(machine)
                    machine.batch = nil
                end,
                run = function(machine)
                    return machine.batch and cartesi.BREAK_REASON_YIELDED_MANUALLY
                        or cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
                end,
                receive_cmio_request = function(machine)
                    local batch = machine.batch
                    return cartesi.HTIF_YIELD_CMD_MANUAL,
                        batch.accepted and cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED
                            or cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED,
                        batch.root
                end,
            },
            snapshot = function(pair)
                pair.backup = { read_reg = pair.machine.read_reg, batch = pair.machine.batch }
            end,
            commit = function(pair)
                pair.backup = nil
            end,
            revert = function(pair)
                pair.machine.batch = pair.backup.batch
                pair:commit()
            end,
        }
    end
    local player = setmetatable({
        inputs = {},
        latest = new_pair(),
        outputs = {},
        outputs_frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"),
        run_to_stop = function(_self, pair, epoch_input_offset, _, on_yield_automatic)
            local batch = batches[epoch_input_offset + 1]
            for _, output in ipairs(batch) do
                on_yield_automatic(cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT, output)
            end
            pair.machine.batch = batch
            return cartesi.BREAK_REASON_YIELDED_MANUALLY
        end,
    }, { __index = vg.player_methods })
    for index = 1, #batches do
        vg.event_handler.input_added(player, index - 1, paths[1])
    end
    local root = hash_tree.frontier_get_root_hash(player.outputs_frontier)
    assert(not player.output_proofs)
    vg.event_handler.epoch_sealed(player)
    assert(not player.outputs_frontier)
    local offer = vg.event_handler.prove_output(player)
    assert(offer.output == "last" and offer.output_index == 3 and #player.outputs == 4)
    assert(require("game-output").validate_output_response(offer, hash_tree.frontier_get_root_hash(expected)))
    local proofs = player.output_proofs
    local replay = new_pair()
    player:run_to_input_boundary(replay, 0, #batches)
    assert(#player.outputs == 4 and player.output_proofs == proofs and not player.outputs_frontier)
    assert(require("game-output").validate_output_response(vg.event_handler.prove_output(player), root))

    -- Reaching the span limit without a fixed point still retains the snapshot.
    player.run_to_stop = function()
        return cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
    end
    local unfinished = new_pair()
    local break_reason = player:run_advance_state_input(unfinished, 0, 1 << 48)
    assert(break_reason == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE and unfinished.backup)
end

-- Malformed final-state and output offers cannot pass the shared proof checks.
do
    local checks = require("game-output")
    local root_offer = first.event_handler.prove_outputs_merkle_root(first)
    local root = checks.validate_outputs_merkle_root_response(root_offer, first.final_hash)
    local output = first.event_handler.prove_output(first)
    assert(checks.validate_output_response(output, root))
    output.output_index = output.output_index + 1
    assert(not pcall(checks.validate_output_response, output, root))
    output.output_index = output.output_index - 1
    output.output_proof.log2_target_size = 1
    assert(not pcall(checks.validate_output_response, output, root))
    root_offer.iflags_y_data = string.rep("\0", 32)
    assert(not pcall(checks.validate_outputs_merkle_root_response, root_offer, first.final_hash))
end
print("vg-test: lifecycle, rollback, terminal proofs and outputs ok")

-- Keep the earlier counterexamples as executable regressions rather than extra
-- chapter walkthroughs. Each changes execution, never transition verification.
local function ignore_rollback(pair)
    pair:commit()
end
local function seal_with_extra_input(self, count)
    vg.event_handler.input_added(self, count, "forged-input-2.bin")
    vg.event_handler.epoch_sealed(self, count + 1)
end
local function run_composite(self, pair, epoch_input_offset, ...)
    pair.machine:set_input_index(epoch_input_offset)
    return vg.player_methods.run_advance_state_input(self, pair, epoch_input_offset, ...)
end
for _, cheat in ipairs({ "no-rollback", "extra-input", "composite" }) do
    local honest <close> = vg.new_player(initial_hash)
    local machine
    if cheat == "composite" then
        local composite = require("dishonest")
        machine = composite.new_rolling_composite_machine(
            first.agreed.machine:fork_server(),
            2,
            100,
            3,
            first.agreed.machine:fork_server(),
            util.read_file("forged-input-2.bin")
        )
    end
    local opponent <close> = vg.new_player(initial_hash, cheat, machine)
    if cheat == "no-rollback" then
        for _, pair in ipairs({ opponent.latest, opponent.agreed }) do
            pair.revert = ignore_rollback
        end
    elseif cheat == "extra-input" then
        opponent.event_handler = setmetatable({ epoch_sealed = seal_with_extra_input }, { __index = vg.event_handler })
    else
        opponent.run_advance_state_input = run_composite
    end
    local result = run_game({ opponent, honest })
    assert(result.winner.index == 2 and result.final_hash == honest.final_hash, cheat .. " defeated honest")
    print("vg-test: legacy " .. cheat .. " rejected")
end

-- Invalid or absent offers leave the settled hash and both player clocks intact.
for _, failed_offer in ipairs({ "prove_outputs_merkle_root", "prove_output" }) do
    local a <close> = vg.new_player(initial_hash)
    local b <close> = vg.new_player(initial_hash)
    a.event_handler = setmetatable({
        [failed_offer] = function()
            return { invalid = true }
        end,
    }, { __index = vg.event_handler })
    b.event_handler = a.event_handler
    local settled = run_game({ a, b }, {})
    assert(settled.winner.index == 1 and settled.final_hash == initial_hash and not settled.output)
    assert(settled.players[1].allowance == 4 and settled.players[2].allowance == 4)
end
-- Seed terminal states after setup. A halted/overflowed machine has no
-- pending yield, while an exception keeps its manual yield with a different reason.
-- Later deliveries are no-ops and saturating targets cannot wrap to an earlier cycle.
for _, terminal in ipairs({ "halt", "overflow", "exception" }) do
    local player <close> = vg.new_player(initial_hash)
    vg.event_handler.initial_state(player, initial_hash)
    local machine = player.latest.machine
    if terminal == "exception" then
        machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION)
    else
        machine:write_reg("iflags_Y", 0)
        machine:write_reg(terminal == "halt" and "iflags_H" or "mcycle", terminal == "halt" and 1 or cartesi.MCYCLE_MAX)
    end
    local hash = machine:get_root_hash()
    local prefix <close> = player.latest:fork()
    player:run_advance_state_input(prefix, 0, 1)
    assert(not prefix.backup and prefix.machine:get_root_hash() == hash)
    for index, path in ipairs(paths) do
        vg.event_handler.input_added(player, index - 1, path)
        assert(player.latest.machine:get_root_hash() == hash)
    end
    vg.event_handler.epoch_sealed(player, #paths)
    assert(player.final_hash == hash)
end

-- The tamperer's bookkeeping follows a fork and is restored with a rejected input.
do
    local roles = require("vg-dishonest")
    local player <close> = roles.new_tamperer(initial_hash, 0, 100)
    vg.event_handler.initial_state(player, initial_hash)
    vg.event_handler.input_added(player, 0, paths[2])
    assert(player.latest.machine:get_root_hash() == initial_hash)
    assert(not player.latest.tampered)
    local replay <close> = player.agreed:fork()
    player:run_to_input_boundary(replay, 0, 1)
    assert(replay.machine:get_root_hash() == initial_hash and not replay.tampered)
end

-- Scope cleanup owns every persistent fork even when a handler fails.
do
    local captured
    local ok = pcall(function()
        local player <close> = vg.new_player(initial_hash)
        captured = player
        player.read_input = function()
            error("input read failed")
        end
        vg.event_handler.input_added(player, 0, paths[1])
    end)
    assert(not ok and not captured.latest and not captured.agreed)
end
print("vg-test: fixed points, tamperer rollback and cleanup ok")

print("vg-test: ok")
