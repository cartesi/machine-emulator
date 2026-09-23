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

-- Setup is ordered and single-use, and a content-addressed snapshot must match.
assert(not pcall(vg.new_player, string.rep("\0", 32), "mismatch", first.initial.machine:fork_server()))
assert(not pcall(vg.event_handler.input_added, first, 0, paths[1]))
assert(not pcall(vg.event_handler.epoch_sealed, first, #paths))
assert(not pcall(vg.event_handler.initial_state, first, initial_hash))
assert(vg.usaturating_add(cartesi.MCYCLE_MAX - 2, 3) == cartesi.MCYCLE_MAX)
assert(vg.usaturating_add(math.maxinteger, 2) == math.mininteger + 1)

-- Rejections, including consecutive rejections, restore the full boundary state.
do
    local player <close> = vg.new_player(initial_hash)
    assert(not pcall(vg.event_handler.initial_state, player, string.rep("\0", 32)))
    vg.event_handler.initial_state(player, initial_hash)
    assert(not pcall(vg.event_handler.input_added, player, 1, paths[1]))
    assert(not pcall(vg.event_handler.epoch_sealed, player, 1))
    vg.event_handler.input_added(player, 0, paths[1])
    local accepted = player.forward.machine:get_root_hash()
    vg.event_handler.input_added(player, 1, paths[2])
    assert(player.forward.machine:get_root_hash() == accepted)
    vg.event_handler.input_added(player, 2, paths[2])
    assert(player.forward.machine:get_root_hash() == accepted)
    assert(#player.outputs == 1)
    vg.event_handler.epoch_sealed(player, 3)
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
            vg.verify_state_transition(contract, 0, mcycle, cycle, before, logs, expected or machine:get_root_hash())
        )
        assert(not vg.verify_state_transition(contract, 0, mcycle, cycle, before, {}, machine:get_root_hash()))
    end
    local included <close> = vg.fork_entry(player.initial)
    verify(included.machine, 0, 0, contract.inputs[1])
    verify(included.machine, 0, 1)
    local rejected <close> = vg.fork_entry(player.initial)
    player:deliver_input(rejected, player.initial)
    player:run_to(rejected, vg.usaturating_add(rejected.input_mcycle_boundary, 1 << 48))
    -- Replay to the instruction that performs the rejecting yield, before its reset.
    local offset = rejected.machine:read_reg("mcycle") - rejected.input_mcycle_boundary - 1
    local boundary <close> = vg.fork_entry(player.initial)
    player:deliver_input(boundary, player.initial)
    player:run_to(boundary, vg.usaturating_add(boundary.input_mcycle_boundary, offset))
    boundary.machine:run_uarch(cartesi.UARCH_CYCLE_MAX)
    verify(boundary.machine, offset, cartesi.UARCH_CYCLE_MAX, nil, initial_hash)
    player:revert_if_rejected(boundary, player.initial)
    assert(boundary.machine:get_root_hash() == initial_hash, "reset did not carry rejection rollback")
    -- With no posted input, verification requires no inclusion log. A uarch
    -- period still has its halted tail and reset, even at a fixed mcycle state.
    local absent <close> = vg.fork_entry(player.initial)
    local before = absent.machine:get_root_hash()
    local step = absent.machine:log_step_uarch()
    assert(
        vg.verify_state_transition(
            { inputs = {} },
            0,
            0,
            0,
            before,
            { step_log = step },
            absent.machine:get_root_hash()
        )
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
    local player = setmetatable({
        started = true,
        inputs = {},
        outputs = {},
        outputs_frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"),
        advance = function(self, _, sink)
            local batch = batches[#self.inputs]
            for _, output in ipairs(batch) do
                sink[#sink + 1] = output
                if batch.accepted then
                    hash_tree.frontier_push_back(expected, cartesi.keccak256(output))
                end
            end
            return batch.accepted and cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED
                or cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED,
                hash_tree.frontier_get_root_hash(expected)
        end,
    }, { __index = vg.player_methods })
    for index = 1, #batches do
        vg.event_handler.input_added(player, index - 1, paths[1])
    end
    player.sealed = true
    local offer = vg.event_handler.prove_output(player)
    assert(offer.output == "last" and offer.output_index == 3 and #player.outputs == 4)
    assert(require("game-output").validate_output_response(offer, hash_tree.frontier_get_root_hash(expected)))
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
local function ignore_rollback(_self, entry)
    if entry.machine:read_reg("iflags_Y") == 0 then
        return
    end
    local _, reason, data = entry.machine:receive_cmio_request()
    return reason, data
end
local function seal_with_extra_input(self, count)
    vg.event_handler.input_added(self, count, "forged-input-2.bin")
    return vg.event_handler.epoch_sealed(self, count + 1)
end
local function deliver_composite(self, entry, boundary)
    entry.machine:set_input_index(entry.input_index)
    return vg.player_methods.deliver_input(self, entry, boundary)
end
for _, cheat in ipairs({ "no-rollback", "extra-input", "composite" }) do
    local honest <close> = vg.new_player(initial_hash)
    local machine
    if cheat == "composite" then
        local composite = require("dishonest")
        machine = composite.new_rolling_composite_machine(
            first.initial.machine:fork_server(),
            2,
            100,
            3,
            first.initial.machine:fork_server(),
            util.read_file("forged-input-2.bin")
        )
    end
    local opponent <close> = vg.new_player(initial_hash, cheat, machine)
    if cheat == "no-rollback" then
        opponent.revert_if_rejected = ignore_rollback
    elseif cheat == "extra-input" then
        opponent.event_handler = setmetatable({ epoch_sealed = seal_with_extra_input }, { __index = vg.event_handler })
    else
        opponent.deliver_input = deliver_composite
    end
    local result = run_game({ opponent, honest })
    assert(result.winner.index == 2 and result.final_hash == honest.final_hash, cheat .. " defeated honest")
    print("vg-test: legacy " .. cheat .. " rejected")
end

-- Invalid or absent offers leave the settled hash intact. They consume the owner's
-- remaining clock but do not transfer its already settled claim to the opponent.
for _, failed_offer in ipairs({ "prove_outputs_merkle_root", "prove_output" }) do
    local a <close> = vg.new_player(initial_hash)
    local b <close> = vg.new_player(initial_hash)
    a.event_handler = setmetatable({
        [failed_offer] = function()
            return { invalid = true }
        end,
    }, { __index = vg.event_handler })
    local settled = run_game({ a, b }, {})
    assert(settled.winner.index == 1 and settled.final_hash == initial_hash and not settled.output)
    assert(settled.players[1].allowance == 0)
end
-- Seed terminal forward states after setup. A halted/overflowed machine has no
-- pending yield, while an exception keeps its manual yield with a different reason.
-- Later deliveries are no-ops and saturating targets cannot wrap to an earlier cycle.
for _, terminal in ipairs({ "halt", "overflow", "exception" }) do
    local player <close> = vg.new_player(initial_hash)
    vg.event_handler.initial_state(player, initial_hash)
    local machine = player.forward.machine
    if terminal == "exception" then
        machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION)
    else
        machine:write_reg("iflags_Y", 0)
        machine:write_reg(terminal == "halt" and "iflags_H" or "mcycle", terminal == "halt" and 1 or cartesi.MCYCLE_MAX)
    end
    local hash = machine:get_root_hash()
    for index, path in ipairs(paths) do
        vg.event_handler.input_added(player, index - 1, path)
        assert(player.forward.machine:get_root_hash() == hash)
    end
    vg.event_handler.epoch_sealed(player, #paths)
    assert(player.final_hash == hash)
end

-- Strategy state follows a fork and is restored with a rejected input.
do
    local roles = require("vg-dishonest")
    local player <close> = roles.new_tamperer(initial_hash, 0, 100)
    vg.event_handler.initial_state(player, initial_hash)
    vg.event_handler.input_added(player, 0, paths[2])
    assert(player.forward.machine:get_root_hash() == initial_hash)
    assert(not player.forward.strategy.tampered)
    local replay <close> = vg.fork_entry(player.initial)
    player:advance(replay)
    assert(replay.machine:get_root_hash() == initial_hash and not replay.strategy.tampered)
end

-- Scope cleanup owns every persistent fork even when a handler fails.
do
    local captured
    local ok = pcall(function()
        local player <close> = vg.new_player(initial_hash)
        captured = player
        vg.event_handler.input_added(player, 1, paths[1])
    end)
    assert(not ok and not captured.initial and not captured.forward and not captured.agreed)
end
print("vg-test: fixed points, strategy rollback and cleanup ok")

print("vg-test: ok")
