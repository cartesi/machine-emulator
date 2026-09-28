-- Run with make -C doc test-vg. This does not parse or render the README.
local cartesi = require("cartesi")
local util = require("cartesi.util")
local vg = require("rolling-verification-game")
local vgu = require("vgu")
local run_with_server = require("vg-test-server")
local initial_hash = cartesi.fromhex(util.read_file("initial-hash"))
local paths = { "input-0.bin", "input-1.bin", "input-2.bin" }
local function run_game(players, input_paths)
    local dapp_contract = vg.make_dapp_contract(initial_hash, input_paths or paths)
    local results
    local server = run_with_server(vgu.protocol, function(server, run_client, wait_connections, observed)
        results = observed
        for index, player in ipairs(players) do
            run_client({ role = "player", label = player.label }, function(_, line)
                return vgu.answer_event(player, line)
            end, true)
            wait_connections(index)
        end
        run_client({ role = "phase_closer" }, function()
            return { value = true }
        end)
        vg.new_referee(dapp_contract):run(server)
    end)
    vgu.close_narration()
    return results, server
end
local first <close> = vg.new_player(initial_hash, "honest 1")
assert(first.tentative_machine.machine:get_root_hash() == initial_hash)
assert(first.tentative_machine.machine ~= first.agreed_machine.machine)
local second <close> = vg.new_player(initial_hash, "honest 2")
local results, first_server = run_game({ first, second })
assert(results.players[first_server.connections[1]] == results.winner and results.final_hash == first.final_hash)
assert(results.output)
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
    local dapp_contract = vg.make_dapp_contract(initial_hash, {})
    local settled
    local root_offer = vg.event_handler.prove_outputs_merkle_root(first)
    local output_offer = vg.event_handler.prove_output(first)
    local server = run_with_server(vgu.protocol, function(server, run_client, wait_connections, observed)
        settled = observed
        local offers = { prove_outputs_merkle_root = root_offer, prove_output = output_offer }
        if late_providers then
            local request_first_valid = server.request_first_valid
            function server:request_first_valid(audience, event, arguments, accept)
                if event == vgu.EVENTS.prove_outputs_merkle_root then
                    -- Join after settlement, before the proof requests fix their audiences.
                    for _, operation in ipairs({ "prove_outputs_merkle_root", "prove_output" }) do
                        local provider = {
                            label = "provider " .. operation,
                            event_handler = setmetatable({
                                [operation] = function(_, requested)
                                    local expected = operation == "prove_output" and root_offer.tx_buffer_data
                                        or first.final_hash
                                    assert(requested == expected)
                                    return offers[operation]
                                end,
                            }, empty_handlers),
                        }
                        run_client({ role = "player", label = provider.label }, function(_, line)
                            return vgu.answer_event(provider, line)
                        end, true)
                    end
                    wait_connections(5)
                end
                return request_first_valid(self, audience, event, arguments, accept)
            end
        end
        for index = 1, 2 do
            local client = { label = "player " .. index, event_handler = setmetatable({}, empty_handlers) }
            function client.event_handler.commit_claim()
                return index == 1 and cartesi.keccak256("losing claim") or first.final_hash
            end
            function client.event_handler.reveal_bisection()
                return index == 2 and first.final_hash or "malformed"
            end
            local function offer(_, target, operation)
                assert(
                    settled.players[server.connections[2]] == settled.winner and settled.final_hash == first.final_hash
                )
                assert(#vg.addresses(settled.players) == 1 and settled.players[next(settled.players)] == settled.winner)
                assert(target == (operation == "prove_output" and root_offer.tx_buffer_data or first.final_hash))
                if index == 1 and not late_providers then
                    return offers[operation]
                end
                return index == 1 and {} or { invalid = true }
            end
            function client.event_handler:prove_outputs_merkle_root(target)
                return offer(self, target, "prove_outputs_merkle_root")
            end
            function client.event_handler:prove_output(target)
                return offer(self, target, "prove_output")
            end
            run_client({ role = "player", label = client.label }, function(_, line)
                return vgu.answer_event(client, line)
            end, true)
            wait_connections(index)
        end
        run_client({ role = "phase_closer" }, function()
            return { value = true }
        end)
        vg.new_referee(dapp_contract):run(server)
    end)
    assert(settled.output and settled.output.output == output_offer.output)
    assert(#vg.addresses(settled.players) == 1 and settled.winner.allowance == 4)
    assert(#server.connections == (late_providers and 4 or 2) + 2) -- Includes admission and stop connections.
    vgu.close_narration()
end
print("vg-test: permissionless output providers ok")

-- Player-selected outputs need not arrive in index order. Repeating an accepted
-- output leaves the wait suspended until the runner stops the game.
do
    local dapp_contract = vg.make_dapp_contract(initial_hash, {})
    local settled
    local offered, resumed = { 0, 0 }, false
    local last = #first.outputs
    assert(last > 1, "output fixture needs distinct outputs")
    local sequence = { last, 1, last }
    local server = run_with_server(vgu.protocol, function(server, run_client, wait_connections, observed)
        settled = observed
        for index = 1, 2 do
            local client = { label = "player " .. index, event_handler = setmetatable({}, empty_handlers) }
            function client.event_handler.commit_claim()
                return first.final_hash
            end
            function client.event_handler.prove_outputs_merkle_root()
                return vg.event_handler.prove_outputs_merkle_root(first)
            end
            function client.event_handler.prove_output()
                offered[index] = offered[index] + 1
                local round = offered[index]
                assert(round <= #sequence, "duplicate output was accepted")
                if round > 1 then
                    local previous = first.output_proofs[sequence[round - 1]].target_address
                    assert(settled.output.output_index == previous, "player-selected output was lost")
                end
                local item = sequence[round]
                return {
                    output_index = first.output_proofs[item].target_address,
                    output = first.outputs[item],
                    output_proof = first.output_proofs[item],
                }
            end
            run_client({ role = "player", label = client.label }, function(_, line)
                return vgu.answer_event(client, line)
            end, true)
            wait_connections(index)
        end
        run_client({ role = "phase_closer" }, function()
            return { value = true }
        end)
        vg.new_referee(dapp_contract):run(server)
        resumed = true
    end)
    assert(offered[1] == #sequence and offered[2] == #sequence)
    assert(settled.output.output_index == first.output_proofs[1].target_address)
    assert(server.stopping and not resumed, "runner stop resumed the proof wait")
    vgu.close_narration()
end
print("vg-test: distinct player-selected outputs and runner stop ok")

-- Every player must prove its committed endpoint. A valid log reaching another
-- player's endpoint is rejected; if neither endpoint is proved, neither wins.
for _, case in ipairs({
    { agree = false, winner = 1 },
    { agree = false, winner = 2 },
    { agree = false },
    { agree = true, winner = 1 },
    { agree = true, winner = 2 },
    { agree = true },
    { last = true, winner = 1 },
}) do
    local pair <close> = first.agreed_machine:fork()
    if case.last then
        pair.machine:run_uarch(cartesi.UARCH_CYCLE_MAX)
    elseif case.agree then
        pair.machine:log_step_uarch()
    end
    local before = pair.machine:get_root_hash()
    local log = { step_log = pair.machine:log_step_uarch() }
    if case.last then
        log.reset_uarch_log = pair.machine:log_reset_uarch()
    end
    local after = pair.machine:get_root_hash()
    local claims = {
        case.winner == 1 and after or cartesi.keccak256("wrong first endpoint"),
        case.winner == 2 and after or cartesi.keccak256("wrong second endpoint"),
    }
    local proofs = {}
    local dapp_contract = vg.make_dapp_contract(initial_hash, {})
    local settled
    local server = run_with_server(vgu.protocol, function(server, run_client, wait_connections, observed)
        settled = observed
        for index = 1, 2 do
            local client = { label = "player " .. index, event_handler = setmetatable({}, empty_handlers) }
            function client.event_handler.commit_claim()
                return claims[index]
            end
            function client.event_handler.reveal_bisection(_self, _agreed_position, tentative_position)
                if case.last then
                    return tentative_position.uarch_cycle > 0 and before or initial_hash
                end
                if case.agree and tentative_position.uarch_cycle == 1 then
                    return before
                end
                return claims[index]
            end
            function client.event_handler.prove_state_transition(
                _self,
                epoch_input_offset,
                input_mcycle_offset,
                uarch_cycle
            )
                if case.last then
                    assert(epoch_input_offset == (1 << 16) - 1 and input_mcycle_offset == (1 << 48) - 1)
                    assert(uarch_cycle == cartesi.UARCH_CYCLE_MAX)
                else
                    assert(
                        epoch_input_offset == 0 and input_mcycle_offset == 0 and uarch_cycle == (case.agree and 1 or 0)
                    )
                end
                proofs[index] = true
                return log
            end
            run_client({ role = "player", label = client.label }, function(_, line)
                return vgu.answer_event(client, line)
            end, true)
            wait_connections(index)
        end
        run_client({ role = "phase_closer" }, function()
            return { value = true }
        end)
        vg.new_referee(dapp_contract):run(server)
    end)
    assert(proofs[1] and proofs[2], "a surviving player was not asked for its proof")
    if case.winner then
        assert(settled.final_hash == claims[case.winner])
    else
        assert(not settled.winner and not settled.final_hash)
    end
    assert(#vg.addresses(settled.players) == (case.winner and 1 or 0))
    if case.winner then
        assert(settled.players[server.connections[case.winner]] == settled.winner)
        assert(settled.winner.allowance == 4)
    end
    vgu.close_narration()
end
print("vg-test: terminal proofs eliminate unsupported endpoints ok")

if arg[1] ~= "execution" then
    local roles = require("vg-dishonest")
    for _, role in ipairs({ "forger", "tamperer", "quitter" }) do
        for honest_index = 1, 2 do
            local honest <close> = vg.new_player(initial_hash)
            local opponent <close> = role == "forger" and roles.new_forger(initial_hash, 2, "forged-input-2.bin")
                or role == "tamperer" and roles.new_tamperer(initial_hash, 0, 100)
                or roles.new_quitter()
            local players = honest_index == 1 and { honest, opponent } or { opponent, honest }
            local result, server = run_game(players)
            assert(
                result.players[server.connections[honest_index]] == result.winner,
                role .. " defeated the honest player"
            )
            assert(result.final_hash == honest.final_hash and result.output)
            print("vg-test: honest player " .. honest_index .. " defeats " .. role)
        end
    end

    -- The early corruption leaves the honest player and the later forger with
    -- different final claims. Both must replay from the epoch start to settle them.
    do
        local tamperer <close> = roles.new_tamperer(initial_hash, 0, 100)
        local honest <close> = vg.new_player(initial_hash)
        local forger <close> = roles.new_forger(initial_hash, 2, "forged-input-2.bin")
        local players = { tamperer, honest, forger }
        local handlers = setmetatable({}, { __index = vg.event_handler })
        function handlers:dispute_started()
            local agreed_machine = self.agreed_machine
            self.disputes = self.disputes + 1
            vg.event_handler.dispute_started(self)
            assert(not agreed_machine.machine)
            assert(self.agreed_machine.machine:get_root_hash() == initial_hash)
            assert(
                self.agreed_position.epoch_input_offset == 0
                    and self.agreed_position.input_mcycle_offset == 0
                    and self.agreed_position.uarch_cycle == 0
            )
        end
        for _, player in ipairs(players) do
            player.disputes, player.event_handler = 0, handlers
        end
        local settled, server = run_game(players)
        assert(
            settled.players[server.connections[2]] == settled.winner
                and settled.final_hash == honest.final_hash
                and settled.output
        )
        assert(tamperer.disputes == 1 and honest.disputes == 2 and forger.disputes == 2)
        assert(#vg.addresses(settled.players) == 1 and settled.players[next(settled.players)] == settled.winner)
        assert(honest.initial.machine:get_root_hash() == initial_hash)
        assert(honest.agreed_machine.machine and honest.agreed_position)
        print("vg-test: repeated disputes eliminate distinct dishonest claims ok")
    end

    require("vg-fabulist-test")(initial_hash, paths)
end

-- A loaded machine must match its content-addressed snapshot.
assert(not pcall(vg.new_player, string.rep("\0", 32), "mismatch", nil, first.agreed_machine.machine:fork_server()))

-- The referee's initial hash must also match the player's own snapshot.
do
    local player <close> = vg.new_player(initial_hash)
    assert(not pcall(vg.event_handler.initial_state, player, string.rep("\0", 32)))
    vg.event_handler.initial_state(player, initial_hash)
end

assert(vg.usaturating_add(cartesi.MCYCLE_MAX - 2, 3) == cartesi.MCYCLE_MAX)
assert(vg.usaturating_add(math.maxinteger, 2) == math.mininteger + 1)

-- Initial-state checks use the execution break reason and the CMIO yield reason.
-- A halt takes precedence even when the machine still carries an accepted yield.
for _, invalid in ipairs({ "halt", "rejected" }) do
    local machine = first.agreed_machine.machine:fork_server()
    if invalid == "halt" then
        machine:write_reg("iflags_H", 1)
    else
        machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED)
    end
    assert(not pcall(vg.new_player, machine:get_root_hash(), invalid, nil, machine))
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
    local ok, err = pcall(vg.new_player, initial_hash, "fork failure", nil, initial)
    assert(not ok and tostring(err):find("injected fork failure", 1, true))
    assert(closed[initial])
end

-- Rejections, including consecutive rejections, restore the full boundary state.
do
    local player <close> = vg.new_player(initial_hash)
    vg.event_handler.initial_state(player, initial_hash)
    vg.event_handler.input_added(player, 0, paths[1])
    local accepted = player.latest.machine:get_root_hash()
    local prefix <close> = player.agreed_machine:fork()
    local _, yield_reason = player:run_to_mcycle(prefix, player.inputs[1], 0, (1 << 48) - 1)
    assert(yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
    assert(prefix.backup:get_root_hash() == initial_hash and prefix.machine:get_root_hash() == accepted)
    vg.event_handler.input_added(player, 1, paths[2])
    assert(player.latest.machine:get_root_hash() == accepted)
    vg.event_handler.input_added(player, 2, paths[2])
    assert(player.latest.machine:get_root_hash() == accepted)
    assert(#player.outputs == 1)
    vg.event_handler.epoch_sealed(player, 3)
end

-- Bisection commits or discards the entire tentative pair. A pending input keeps
-- its rejection checkpoint; after rejection, later midpoints repeat the reverted hash.
do
    local player <close> = vg.new_player(initial_hash)
    vg.event_handler.initial_state(player, initial_hash)
    vg.event_handler.input_added(player, 0, paths[2])
    vg.event_handler.input_added(player, 1, paths[1])
    vg.event_handler.epoch_sealed(player, 2)

    local loaded <close> = player.agreed_machine:fork()
    local input_mcycle_boundary = loaded.machine:read_reg("mcycle")
    player:run_to_mcycle(loaded, player.inputs[1], 0, 0)
    player:run_to_uarch_cycle(loaded, player.inputs[1], 0, 0, 0)
    assert(loaded.machine:get_root_hash() == initial_hash and loaded.backup:get_root_hash() == initial_hash)
    player:run_to_uarch_cycle(loaded, player.inputs[1], 0, 0, 1)
    assert(loaded.machine:get_root_hash() ~= initial_hash and loaded.backup:get_root_hash() == initial_hash)
    local break_reason
    local rejection <close> = player.agreed_machine:fork()
    vg.load_cmio_input(rejection.machine, player.inputs[1], initial_hash)
    repeat
        break_reason = rejection.machine:run(cartesi.MCYCLE_MAX)
    until break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
    assert(break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY)
    local rejected_at = rejection.machine:read_reg("mcycle") - input_mcycle_boundary

    local agreed_position = { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 }
    local tentative_position = { epoch_input_offset = 0, input_mcycle_offset = rejected_at, uarch_cycle = 0 }
    vg.event_handler.dispute_started(player)
    assert(vg.event_handler.reveal_bisection(player, agreed_position, tentative_position) == initial_hash)
    local candidate = player.tentative_machine
    assert(candidate.machine ~= player.agreed_machine.machine and candidate.backup:get_root_hash() == initial_hash)

    tentative_position = { epoch_input_offset = 0, input_mcycle_offset = (rejected_at + 1) // 2, uarch_cycle = 0 }
    local inside_hash = vg.event_handler.reveal_bisection(player, agreed_position, tentative_position)
    assert(not candidate.machine)
    assert(
        player.agreed_machine.machine:get_root_hash() == initial_hash
            and player.agreed_machine.backup:get_root_hash() == initial_hash
    )
    candidate = player.tentative_machine
    local checkpoint = candidate.backup
    assert(checkpoint:get_root_hash() == initial_hash)

    agreed_position = tentative_position
    tentative_position = {
        epoch_input_offset = 0,
        input_mcycle_offset = (agreed_position.input_mcycle_offset + rejected_at + 1) // 2,
        uarch_cycle = 0,
    }
    vg.event_handler.reveal_bisection(player, agreed_position, tentative_position)
    assert(player.agreed_machine == candidate and player.agreed_machine.backup == checkpoint)
    assert(player.agreed_machine.machine:get_root_hash() == inside_hash)
    assert(
        player.tentative_machine.backup ~= checkpoint
            and player.tentative_machine.backup:get_root_hash() == initial_hash
    )

    -- Start another dispute and agree on a point past rejection.
    vg.event_handler.dispute_started(player)
    agreed_position = { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 }
    tentative_position = { epoch_input_offset = 0, input_mcycle_offset = rejected_at, uarch_cycle = 0 }
    assert(vg.event_handler.reveal_bisection(player, agreed_position, tentative_position) == initial_hash)
    candidate = player.tentative_machine
    agreed_position = tentative_position
    tentative_position = { epoch_input_offset = 0, input_mcycle_offset = (3 * rejected_at + 1) // 2, uarch_cycle = 0 }
    assert(vg.event_handler.reveal_bisection(player, agreed_position, tentative_position) == initial_hash)
    assert(
        player.agreed_machine == candidate
            and player.agreed_machine.backup:get_root_hash() == initial_hash
            and player.tentative_machine.backup:get_root_hash() == initial_hash
    )
    assert(player.agreed_machine.machine:read_reg("mcycle") == input_mcycle_boundary)
    assert(player.tentative_machine.machine:read_reg("mcycle") == input_mcycle_boundary)

    -- Finishing an input and advancing to the next one uses the same driver.
    local replay <close> = player.initial:fork()
    player:run_to_input_boundary(replay, player.inputs, 0, 2)
    assert(replay.backup:get_root_hash() == initial_hash and replay.machine:get_root_hash() == player.final_hash)
end

-- Split execution preserves buffered outputs across both continuation and a
-- bisection fork. The first output is not published until the input accepts.
do
    local hash_tree = require("cartesi.hash-tree")
    local player <close> = vg.new_player(initial_hash)
    local input_data = util.read_file(paths[1])
    local probe <close> = player.initial:fork()
    local input_mcycle_boundary = probe.machine:read_reg("mcycle")
    vg.load_cmio_input(probe.machine, input_data, initial_hash)
    while true do
        local break_reason = probe.machine:run(cartesi.MCYCLE_MAX)
        assert(break_reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY)
        local _, yield_reason = probe.machine:receive_cmio_request()
        if yield_reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT then
            break
        end
    end
    local output_offset = probe.machine:read_reg("mcycle") - input_mcycle_boundary
    local split <close> = player.initial:fork()
    local outputs = {}
    local frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
    local reason = player:run_to_mcycle(split, input_data, 0, output_offset, outputs, frontier)
    assert(reason == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    assert(#outputs == 0 and #split.pending_outputs == 1)
    local fork <close> = split:fork()
    assert(fork.pending_outputs ~= split.pending_outputs and fork.pending_outputs[1] == split.pending_outputs[1])
    local fork_outputs, fork_frontier = {}, hash_tree.frontier_copy(frontier)
    player:run_to_mcycle(split, input_data, output_offset, (1 << 48) - 1, outputs, frontier)
    player:run_to_mcycle(fork, input_data, output_offset, (1 << 48) - 1, fork_outputs, fork_frontier)
    assert(split.machine:get_root_hash() == fork.machine:get_root_hash())
    assert(#outputs == 1 and outputs[1] == fork_outputs[1])
    assert(hash_tree.frontier_get_root_hash(frontier) == hash_tree.frontier_get_root_hash(fork_frontier))
    assert(split.backup:get_root_hash() == initial_hash and fork.backup:get_root_hash() == initial_hash)
    local settled_hash = split.machine:get_root_hash()
    player:run_to_mcycle(split, input_data, (1 << 48) - 1, 1 << 48, outputs, frontier)
    assert(split.machine:get_root_hash() == settled_hash and #outputs == 1)
    vg.event_handler.input_added(player, 0, paths[1])
    assert(player.latest.machine:get_root_hash() == settled_hash and player.outputs[1] == outputs[1])
end

-- Leaf zero is a resulting state at every level. The predecessor stays outside
-- the range. The final log uses agreed or tentative according to the final index.
for uarch_cycle = 0, 1 do
    local player <close> = vg.new_player(initial_hash)
    vg.event_handler.input_added(player, 0, paths[1])
    local after_input = player.latest.machine:get_root_hash()
    assert(after_input ~= initial_hash)
    vg.event_handler.dispute_started(player)
    assert(
        vg.event_handler.reveal_bisection(
            player,
            { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 },
            { epoch_input_offset = 1, input_mcycle_offset = 0, uarch_cycle = 0 }
        ) == after_input
    )

    local mcycle <close> = player.initial:fork()
    player:run_to_mcycle(mcycle, player.inputs[1], 0, 1)
    assert(
        vg.event_handler.reveal_bisection(
            player,
            { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 },
            { epoch_input_offset = 0, input_mcycle_offset = 1, uarch_cycle = 0 }
        ) == mcycle.machine:get_root_hash()
    )
    local uarch <close> = player.initial:fork()
    vg.load_cmio_input(uarch.machine, player.inputs[1], initial_hash)
    uarch.machine:log_step_uarch()
    local after_uarch = uarch.machine:get_root_hash()
    assert(
        vg.event_handler.reveal_bisection(
            player,
            { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 },
            { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 1 }
        ) == after_uarch
    )
    local before = initial_hash
    if uarch_cycle == 1 then
        before = after_uarch
        uarch.machine:log_step_uarch()
        after_uarch = uarch.machine:get_root_hash()
    end
    local agreed, tentative = player.agreed_machine, player.tentative_machine
    local unused = uarch_cycle == 0 and tentative or agreed
    local unused_hash = unused.machine:get_root_hash()
    local log = vg.event_handler.prove_state_transition(player, 0, 0, uarch_cycle)
    assert(
        vg.validate_state_transition_response({ inputs = player.inputs }, 0, 0, uarch_cycle, before, log, after_uarch)
    )
    assert(player.agreed_machine == agreed and player.tentative_machine == tentative)
    assert(unused.machine:get_root_hash() == unused_hash)
end

-- Empty epochs finish after establishing the root, without inventing an output.
do
    local a <close> = vg.new_player(initial_hash, "honest 1")
    local b <close> = vg.new_player(initial_hash, "honest 2")
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
    local function verify(machine, input_mcycle_offset, cycle, input, expected)
        local before = machine:get_root_hash()
        local logs = {}
        if input then
            logs.send_cmio_log = machine:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, before)
        end
        logs.step_log = machine:log_step_uarch()
        if cycle == cartesi.UARCH_CYCLE_MAX then
            logs.reset_uarch_log = machine:log_reset_uarch()
        end
        local after = expected or machine:get_root_hash()
        assert(vg.validate_state_transition_response(contract, 0, input_mcycle_offset, cycle, before, logs, after))
        assert(
            not pcall(vg.validate_state_transition_response, contract, 0, input_mcycle_offset, cycle, before, {}, after)
        )
    end
    local included <close> = player.agreed_machine:fork()
    local prefix <close> = player.agreed_machine:fork()
    verify(included.machine, 0, 0, contract.inputs[1])
    player:run_to_uarch_cycle(prefix, player.inputs[1], 0, 0, 1)
    assert(prefix.machine:get_root_hash() == included.machine:get_root_hash())
    verify(included.machine, 0, 1)
    player:run_to_uarch_cycle(prefix, player.inputs[1], 0, 1, 2)
    assert(prefix.machine:get_root_hash() == included.machine:get_root_hash())
    local rejected <close> = player.agreed_machine:fork()
    rejected:snapshot()
    vg.load_cmio_input(rejected.machine, contract.inputs[1], initial_hash)
    local break_reason
    repeat
        break_reason = rejected.machine:run(vg.usaturating_add(rejected.backup:read_reg("mcycle"), 1 << 48))
    until break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
    assert(break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY)
    -- Replay to the instruction that performs the rejecting yield, before its reset.
    local offset = rejected.machine:read_reg("mcycle") - rejected.backup:read_reg("mcycle") - 1
    local boundary <close> = player.agreed_machine:fork()
    player:run_to_mcycle(boundary, player.inputs[1], 0, offset)
    player:run_to_uarch_cycle(boundary, player.inputs[1], offset, 0, cartesi.UARCH_CYCLE_MAX)
    local before_reset = boundary.machine:get_root_hash()
    player.agreed_machine:close()
    player.agreed_machine = boundary:move()
    player.agreed_position =
        { epoch_input_offset = 0, input_mcycle_offset = offset, uarch_cycle = cartesi.UARCH_CYCLE_MAX }
    local log = vg.event_handler.prove_state_transition(player, 0, offset, cartesi.UARCH_CYCLE_MAX)
    assert(
        vg.validate_state_transition_response(
            contract,
            0,
            offset,
            cartesi.UARCH_CYCLE_MAX,
            before_reset,
            log,
            initial_hash
        )
    )
    local replay <close> = player.initial:fork()
    player:run_to_mcycle(replay, player.inputs[1], 0, offset + 1)
    assert(replay.machine:get_root_hash() == initial_hash, "reset did not carry rejection rollback")
    -- With no posted input, verification requires no inclusion log. A uarch
    -- period still has its halted tail and reset, even at a fixed mcycle state.
    local absent <close> = player.initial:fork()
    local before = absent.machine:get_root_hash()
    local step = absent.machine:log_step_uarch()
    assert(
        vg.validate_state_transition_response(
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

-- A previous epoch's last-output proof supplies the prefix for new output proofs.
for _, output_count in ipairs({ 0, 2 }) do
    local hash_tree = require("cartesi.hash-tree")
    local genesis = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
    local previous_hashes = {
        cartesi.keccak256("previous first"),
        cartesi.keccak256("previous second"),
        cartesi.keccak256("previous last"),
    }
    local last_output_proof = hash_tree.frontier_next_proofs(genesis, previous_hashes)[#previous_hashes]
    local player <close> = vg.new_player(initial_hash, "output fixture", last_output_proof)
    assert(player.outputs_frontier ~= player.previous_outputs_frontier)
    assert(hash_tree.frontier_get_leaf_count(player.outputs_frontier) == #previous_hashes)
    vg.event_handler.initial_state(player, initial_hash)
    for index = 1, output_count do
        local output = "new output " .. index
        player.outputs[index] = output
        hash_tree.frontier_push_back(player.outputs_frontier, cartesi.keccak256(output))
    end
    assert(hash_tree.frontier_get_leaf_count(player.previous_outputs_frontier) == #previous_hashes)
    assert(hash_tree.frontier_get_leaf_count(player.outputs_frontier) == #previous_hashes + output_count)
    local root = hash_tree.frontier_get_root_hash(player.outputs_frontier)
    local completed_frontier = player.outputs_frontier
    vg.event_handler.epoch_sealed(player)
    assert(player.previous_outputs_frontier == completed_frontier and not player.outputs_frontier)
    local offer = vg.event_handler.prove_output(player)
    if output_count == 0 then
        assert(next(offer) == nil and #player.output_proofs == 0)
    else
        assert(offer.output_index == #previous_hashes + output_count - 1)
        assert(require("game-output").validate_output_response(offer, root))
    end
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
        local pair = {
            machine = {
                read_reg = function()
                    return 0
                end,
                get_root_hash = function()
                    return initial_hash
                end,
                batch = { accepted = true },
                output_index = 1,
                send_cmio_response = function(machine, _, input_data)
                    machine.batch = batches[tonumber(input_data)]
                    machine.output_index = 0
                end,
                run = function(machine)
                    machine.output_index = machine.output_index + 1
                    return machine.output_index <= #machine.batch and cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
                        or cartesi.BREAK_REASON_YIELDED_MANUALLY
                end,
                receive_cmio_request = function(machine)
                    local batch = machine.batch
                    if machine.output_index <= #batch then
                        return cartesi.HTIF_YIELD_CMD_AUTOMATIC,
                            cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT,
                            batch[machine.output_index]
                    end
                    return cartesi.HTIF_YIELD_CMD_MANUAL,
                        batch.accepted and cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED
                            or cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED,
                        batch.root
                end,
            },
            snapshot = function(pair)
                pair.backup = { read_reg = pair.machine.read_reg, batch = pair.machine.batch }
                pair.pending_outputs = {}
            end,
            revert = function(pair)
                pair.machine.batch = pair.backup.batch
                pair.machine.output_index = #pair.machine.batch + 1
            end,
        }
        pair:snapshot()
        return pair
    end
    local player = setmetatable({
        inputs = {},
        latest = new_pair(),
        outputs = {},
        previous_outputs_frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"),
        outputs_frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"),
        read_input = function(_, epoch_input_offset)
            return tostring(epoch_input_offset + 1)
        end,
    }, { __index = vg.player_methods })
    for index = 1, #batches do
        vg.event_handler.input_added(player, index - 1, paths[1])
    end
    local root = hash_tree.frontier_get_root_hash(player.outputs_frontier)
    assert(not player.output_proofs)
    local completed_frontier = player.outputs_frontier
    vg.event_handler.epoch_sealed(player)
    assert(player.previous_outputs_frontier == completed_frontier and not player.outputs_frontier)
    local offer = vg.event_handler.prove_output(player)
    assert(offer.output == "last" and offer.output_index == 3 and #player.outputs == 4)
    assert(require("game-output").validate_output_response(offer, hash_tree.frontier_get_root_hash(expected)))
    local proofs = player.output_proofs
    local replay = new_pair()
    player:run_to_input_boundary(replay, player.inputs, 0, #batches)
    assert(#player.outputs == 4 and player.output_proofs == proofs and not player.outputs_frontier)
    assert(require("game-output").validate_output_response(vg.event_handler.prove_output(player), root))

    -- Reaching the span limit without a fixed point still retains the snapshot.
    local unfinished = new_pair()
    unfinished.machine.run = function()
        return cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
    end
    local break_reason = player:run_to_mcycle(unfinished, player.inputs[1], 0, 1 << 48)
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
local function ignore_rollback() end
local function seal_with_extra_input(self, count)
    vg.event_handler.input_added(self, count, "forged-input-2.bin")
    vg.event_handler.epoch_sealed(self, count + 1)
end
local function snapshot_composite(pair)
    pair.machine:set_input_index(pair.epoch_input_offset)
    pair.epoch_input_offset = pair.epoch_input_offset + 1
    vg.advancing_pair_methods.snapshot(pair)
end
for _, cheat in ipairs({ "no-rollback", "extra-input", "composite" }) do
    local honest <close> = vg.new_player(initial_hash)
    local machine
    if cheat == "composite" then
        local composite = require("dishonest")
        machine = composite.new_rolling_composite_machine(
            first.agreed_machine.machine:fork_server(),
            2,
            100,
            3,
            first.agreed_machine.machine:fork_server(),
            util.read_file("forged-input-2.bin")
        )
    end
    local opponent <close> = vg.new_player(initial_hash, cheat, nil, machine)
    if cheat == "no-rollback" then
        for _, pair in ipairs({ opponent.initial, opponent.latest, opponent.agreed_machine }) do
            pair.revert = ignore_rollback
        end
    elseif cheat == "extra-input" then
        opponent.event_handler = setmetatable({ epoch_sealed = seal_with_extra_input }, { __index = vg.event_handler })
    else
        for _, pair in ipairs({ opponent.initial, opponent.latest, opponent.agreed_machine }) do
            pair.epoch_input_offset = 0
            pair.snapshot = snapshot_composite
        end
    end
    local result, server = run_game({ opponent, honest })
    assert(
        result.players[server.connections[2]] == result.winner and result.final_hash == honest.final_hash,
        cheat .. " defeated honest"
    )
    print("vg-test: legacy " .. cheat .. " rejected")
end

-- Invalid or absent offers leave the settled hash and both player clocks intact.
for _, failed_offer in ipairs({ "prove_outputs_merkle_root", "prove_output" }) do
    local a <close> = vg.new_player(initial_hash, "honest 1")
    local b <close> = vg.new_player(initial_hash, "honest 2")
    a.event_handler = setmetatable({
        [failed_offer] = function()
            return { invalid = true }
        end,
    }, { __index = vg.event_handler })
    b.event_handler = a.event_handler
    local settled, server = run_game({ a, b }, {})
    assert(
        settled.players[server.connections[1]] == settled.winner
            and settled.final_hash == initial_hash
            and not settled.output
    )
    assert(#vg.addresses(settled.players) == 2)
    for _, player in pairs(settled.players) do
        assert(player.allowance == 4)
    end
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
    player:run_to_mcycle(prefix, player.inputs[1], 0, 1)
    assert(prefix.backup:get_root_hash() == hash and prefix.machine:get_root_hash() == hash)
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
    assert(not player.latest.machine.tampered)
    local replay <close> = player.agreed_machine:fork()
    player:run_to_input_boundary(replay, player.inputs, 0, 1)
    assert(replay.machine:get_root_hash() == initial_hash and not replay.machine.tampered)
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
    assert(
        not ok
            and not captured.initial
            and not captured.latest
            and not captured.agreed_machine
            and not captured.tentative_machine
    )
end
print("vg-test: fixed points, tamperer rollback and cleanup ok")

print("vg-test: ok")
