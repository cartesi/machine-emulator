-- Run with make -C doc test-vg. This does not parse or render the README.
local cartesi = require("cartesi")
local util = require("cartesi.util")
local vg = require("vg")
local vgu = require("vgu")
local run_with_server = require("vg-test-server")
local replay_test = require("vg-replay-test")
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
-- Only the epoch's pair exists before a dispute.
assert(first.epoch_pair.machine:get_root_hash() == initial_hash)
assert(not first.agreed_pair and not first.tentative_pair)
local second <close> = vg.new_player(initial_hash, "honest 2")
local results, first_server = run_game({ first, second })
assert(
    results.players[first_server.connections[1]] == results.winner
        and results.final_state_hash == first.final_state_hash
)
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
                                        or first.final_state_hash
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
                return index == 1 and cartesi.keccak256("losing claim") or first.final_state_hash
            end
            function client.event_handler.reveal_bisection()
                return index == 2 and first.final_state_hash or "malformed"
            end
            local function offer(_, target, operation)
                assert(
                    settled.players[server.connections[2]] == settled.winner
                        and settled.final_state_hash == first.final_state_hash
                )
                assert(#vg.addresses(settled.players) == 1 and settled.players[next(settled.players)] == settled.winner)
                assert(target == (operation == "prove_output" and root_offer.tx_buffer_data or first.final_state_hash))
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
    assert(settled.output and settled.output.output_data == output_offer.output_data)
    assert(#vg.addresses(settled.players) == 1 and settled.winner.allowance == 3)
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
                return first.final_state_hash
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
                    output_data = first.outputs[item],
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
    local pair <close> = first:new_advancing_pair()
    if case.last then
        pair.machine:run_uarch(cartesi.UARCH_CYCLE_MAX)
    elseif case.agree then
        pair.machine:log_step_uarch()
    end
    local root_hash_before = pair.machine:get_root_hash()
    local log = { step_log = pair.machine:log_step_uarch() }
    if case.last then
        log.reset_uarch_log = pair.machine:log_reset_uarch()
    end
    local root_hash_after = pair.machine:get_root_hash()
    local claims = {
        case.winner == 1 and root_hash_after or cartesi.keccak256("wrong first endpoint"),
        case.winner == 2 and root_hash_after or cartesi.keccak256("wrong second endpoint"),
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
                    return tentative_position.uarch_cycle > 0 and root_hash_before or initial_hash
                end
                if case.agree and tentative_position.uarch_cycle == 1 then
                    return root_hash_before
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
        assert(settled.final_state_hash == claims[case.winner])
    else
        assert(not settled.winner and not settled.final_state_hash)
    end
    assert(#vg.addresses(settled.players) == (case.winner and 1 or 0))
    if case.winner then
        assert(settled.players[server.connections[case.winner]] == settled.winner)
        assert(settled.winner.allowance == 3)
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
            if role ~= "quitter" then
                replay_test.measure(honest)
                replay_test.measure(opponent)
            end
            local players = honest_index == 1 and { honest, opponent } or { opponent, honest }
            local result, server = run_game(players)
            assert(
                result.players[server.connections[honest_index]] == result.winner,
                role .. " defeated the honest player"
            )
            assert(result.final_state_hash == honest.final_state_hash and result.output)
            if role ~= "quitter" then
                assert(honest.replay_counts.rounds == 1)
            end
            print("vg-test: honest player " .. honest_index .. " defeats " .. role)
        end
    end

    -- One dispute spans both proof rounds. The early corruption leaves the honest
    -- player and later forger with different claims; proof completion resets their replay.
    do
        local tamperer <close> = roles.new_tamperer(initial_hash, 0, 100)
        local honest <close> = vg.new_player(initial_hash)
        local forger <close> = roles.new_forger(initial_hash, 2, "forged-input-2.bin")
        local players = { tamperer, honest, forger }
        local handlers = setmetatable({}, { __index = vg.event_handler })
        function handlers:dispute_started()
            self.dispute_starts = self.dispute_starts + 1
            assert(self.dispute_starts == 1, "dispute restarted between proof rounds")
            vg.event_handler.dispute_started(self)
        end
        function handlers:prove_state_transition(epoch_input_offset, input_mcycle_offset, uarch_cycle)
            local agreed_pair = self.agreed_pair
            local proof =
                vg.event_handler.prove_state_transition(self, epoch_input_offset, input_mcycle_offset, uarch_cycle)
            self.proofs = self.proofs + 1
            assert(not agreed_pair.machine)
            assert(not self.agreed_pair and not self.agreed_pair_position and not self.tentative_pair_position)
            assert(
                self.agreed_position.epoch_input_offset == 0
                    and self.agreed_position.input_mcycle_offset == 0
                    and self.agreed_position.uarch_cycle == 0
            )
            return proof
        end
        for _, player in ipairs(players) do
            player.dispute_starts, player.proofs, player.event_handler = 0, 0, handlers
        end
        local settled, server = run_game(players)
        assert(
            settled.players[server.connections[2]] == settled.winner
                and settled.final_state_hash == honest.final_state_hash
                and settled.output
        )
        assert(tamperer.dispute_starts == 1 and honest.dispute_starts == 1 and forger.dispute_starts == 1)
        assert(tamperer.proofs == 1 and honest.proofs == 2 and forger.proofs == 2)
        assert(#vg.addresses(settled.players) == 1 and settled.players[next(settled.players)] == settled.winner)
        assert(not honest.epoch_pair)
        assert(not honest.agreed_pair and honest.agreed_position)
        print("vg-test: repeated proof rounds eliminate distinct dishonest claims ok")
    end

    require("vg-fabulist-test")(initial_hash, paths)
end

-- A loaded machine must match its content-addressed snapshot.
assert(not pcall(vg.new_player, string.rep("\0", 32), "mismatch", nil, {
    new_machine = function()
        return first:new_machine()
    end,
}))

assert(vg.usaturating_add(cartesi.MCYCLE_MAX - 2, 3) == cartesi.MCYCLE_MAX)
assert(vg.usaturating_add(math.maxinteger, 2) == math.mininteger + 1)

-- Initial-state checks use the execution break reason and the CMIO yield reason.
-- A halt takes precedence even when the machine still carries an accepted yield.
for _, invalid in ipairs({ "halt", "rejected" }) do
    local machine = first:new_machine()
    if invalid == "halt" then
        machine:write_reg("iflags_H", 1)
    else
        machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED)
    end
    assert(not pcall(vg.new_player, machine:get_root_hash(), invalid, nil, {
        new_machine = function()
            return machine
        end,
    }))
    assert(not pcall(machine.read_reg, machine, "mcycle"), "failed constructor left its machine running")
end

-- A failed constructor closes the loaded machine through the player's scope cleanup
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
        fork_server = function(machine)
            return setmetatable({}, { __index = machine })
        end,
        set_cleanup_call = function() end,
    }
    local invalid_proof = { log2_root_size = 0, log2_target_size = 0 }
    local ok, err = pcall(vg.new_player, initial_hash, "invalid proof", invalid_proof, {
        new_machine = function()
            return initial
        end,
    })
    assert(not ok and tostring(err):find("last_output_proof is not an outputs proof", 1, true))
    assert(closed[initial])
    local count = 0
    for _ in pairs(closed) do
        count = count + 1
    end
    assert(count == 2, "failed constructor leaked the initial machine or its fork")
end

-- Snapshot ownership is consumed by commit or revert; retired servers close immediately.
do
    local player <close> = vg.new_player(initial_hash)
    local pair = player.epoch_pair
    pair:snapshot()
    local committed = pair.backup_machine
    assert(not pcall(pair.snapshot, pair) and pair.backup_machine == committed)
    pair.machine:write_reg("x1", ~pair.machine:read_reg("x1"))
    local committed_hash = pair.machine:get_root_hash()
    pair:commit()
    assert(not pair.backup_machine and pair.machine:get_root_hash() == committed_hash)
    assert(not pcall(committed.get_root_hash, committed), "commit left the backup server running")
    pair:commit()
    pair.revert_root_hash = committed_hash
    pair:snapshot()
    local reverted = pair.backup_machine
    local address = pair.machine:get_server_address()
    pair.machine:write_reg("x1", ~pair.machine:read_reg("x1"))
    pair:revert()
    assert(not pair.backup_machine and pair.machine:get_root_hash() == committed_hash)
    assert(pair.machine:get_server_address() == address, "revert changed the working server address")
    assert(not pcall(reverted.get_root_hash, reverted), "revert left the displaced server running")
    assert(not pcall(pair.revert, pair))
    assert(pair.machine:get_root_hash() == committed_hash)
end

-- Rejections, including consecutive rejections, restore the full boundary state.
do
    local player <close> = vg.new_player(initial_hash)
    assert(player.epoch_pair.revert_root_hash == initial_hash)
    assert(not player.epoch_pair.backup_machine)
    local working = player.epoch_pair.machine
    local address = working:get_server_address()
    vg.event_handler.input_added(player, 0, paths[1])
    assert(player.epoch_pair.machine == working and working:get_server_address() == address)
    local accepted = player.epoch_pair.machine:get_root_hash()
    assert(player.epoch_pair.revert_root_hash == accepted)
    local prefix <close> = player:new_advancing_pair()
    local initial_mcycle = prefix.machine:read_reg("mcycle")
    local _, yield_reason = player:run_to_input_mcycle_offset(prefix, player.inputs[1], 0, (1 << 48) - 1)
    assert(yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
    assert(not prefix.backup_machine and prefix.machine:get_root_hash() == accepted)
    assert(prefix.input_mcycle_base == initial_mcycle)
    vg.event_handler.input_added(player, 1, paths[2])
    assert(player.epoch_pair.machine == working and working:get_server_address() == address)
    assert(player.epoch_pair.machine:get_root_hash() == accepted)
    assert(player.epoch_pair.revert_root_hash == accepted)
    assert(not player.epoch_pair.backup_machine)
    vg.event_handler.input_added(player, 2, paths[2])
    assert(player.epoch_pair.machine == working and working:get_server_address() == address)
    assert(player.epoch_pair.machine:get_root_hash() == accepted)
    assert(player.epoch_pair.revert_root_hash == accepted)
    assert(not player.epoch_pair.backup_machine)
    assert(#player.outputs == 1)
    vg.event_handler.epoch_sealed(player, 3)
end

-- Delivery checks the expected boundary, not a fresh hash of an altered machine.
for _, granularity in ipairs({ "mcycle", "uarch" }) do
    local player <close> = vg.new_player(initial_hash)
    local pair = player.epoch_pair
    pair.machine:write_reg("x1", ~pair.machine:read_reg("x1"))
    local input = util.read_file(paths[1])
    local ok, err
    if granularity == "mcycle" then
        ok, err = pcall(player.run_to_input_mcycle_offset, player, pair, input, 0, 1)
    else
        ok, err = pcall(player.run_to_uarch_cycle, player, pair, input, 0, 0, 1)
    end
    assert(not ok and tostring(err):find("revert root hash does not match the machine root hash", 1, true))
    assert(pair.revert_root_hash == initial_hash)
end

-- A damaged checkpoint cannot silently establish a different rollback boundary.
do
    local player <close> = vg.new_player(initial_hash)
    local pair = player.epoch_pair
    pair:snapshot()
    pair.backup_machine:write_reg("x1", ~pair.backup_machine:read_reg("x1"))
    local ok, err = pcall(pair.revert, pair)
    assert(not ok and tostring(err):find("rollback did not restore the input boundary", 1, true))
    assert(pair.revert_root_hash == initial_hash)
    assert(not pair.backup_machine)
end

-- Bisection commits or discards the entire tentative pair. A pending input keeps
-- its rejection checkpoint; after rejection, later tentative positions repeat the reverted hash.
do
    local player <close> = vg.new_player(initial_hash)
    vg.event_handler.input_added(player, 0, paths[2])
    vg.event_handler.input_added(player, 1, paths[1])
    vg.event_handler.epoch_sealed(player, 2)

    local loaded <close> = player:new_advancing_pair()
    local input_mcycle_base = loaded.machine:read_reg("mcycle")
    player:run_to_input_mcycle_offset(loaded, player.inputs[1], 0, 0)
    player:run_to_uarch_cycle(loaded, player.inputs[1], 0, 0, 0)
    assert(loaded.machine:get_root_hash() == initial_hash and not loaded.backup_machine)
    player:run_to_uarch_cycle(loaded, player.inputs[1], 0, 0, 1)
    assert(loaded.machine:get_root_hash() ~= initial_hash and loaded.backup_machine:get_root_hash() == initial_hash)
    local break_reason
    local rejection <close> = player:new_advancing_pair()
    vg.load_cmio_input(rejection.machine, player.inputs[1], initial_hash)
    repeat
        break_reason = rejection.machine:run(cartesi.MCYCLE_MAX)
    until break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
    assert(break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY)
    local rejected_at = rejection.machine:read_reg("mcycle") - input_mcycle_base

    local agreed_position = { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 }
    local tentative_position = { epoch_input_offset = 0, input_mcycle_offset = rejected_at, uarch_cycle = 0 }
    vg.event_handler.dispute_started(player)
    assert(vg.event_handler.reveal_bisection(player, agreed_position, tentative_position) == initial_hash)
    assert(not player.agreed_pair and not player.tentative_pair)
    assert(player.fixed_point_mcycle_offsets[1] == rejected_at)

    tentative_position = { epoch_input_offset = 0, input_mcycle_offset = (rejected_at + 1) // 2, uarch_cycle = 0 }
    local inside_hash = vg.event_handler.reveal_bisection(player, agreed_position, tentative_position)
    assert(player.agreed_pair.machine:get_root_hash() == initial_hash and not player.agreed_pair.backup_machine)
    local candidate = player.tentative_pair
    local checkpoint = candidate.backup_machine
    assert(checkpoint:get_root_hash() == initial_hash)

    agreed_position = tentative_position
    tentative_position = {
        epoch_input_offset = 0,
        input_mcycle_offset = (agreed_position.input_mcycle_offset + rejected_at + 1) // 2,
        uarch_cycle = 0,
    }
    vg.event_handler.reveal_bisection(player, agreed_position, tentative_position)
    assert(player.agreed_pair == candidate and player.agreed_pair.backup_machine == checkpoint)
    assert(player.agreed_pair.machine:get_root_hash() == inside_hash)
    assert(
        player.tentative_pair.backup_machine ~= checkpoint
            and player.tentative_pair.backup_machine:get_root_hash() == initial_hash
    )

    -- Agree on the active candidate, then on a recorded point past rejection.
    candidate = player.tentative_pair
    agreed_position = tentative_position
    tentative_position = { epoch_input_offset = 0, input_mcycle_offset = rejected_at, uarch_cycle = 0 }
    assert(vg.event_handler.reveal_bisection(player, agreed_position, tentative_position) == initial_hash)
    assert(player.agreed_pair == candidate and candidate.backup_machine and not player.tentative_pair)
    agreed_position = tentative_position
    tentative_position = { epoch_input_offset = 0, input_mcycle_offset = (3 * rejected_at + 1) // 2, uarch_cycle = 0 }
    assert(vg.event_handler.reveal_bisection(player, agreed_position, tentative_position) == initial_hash)
    assert(player.agreed_pair == candidate and candidate.backup_machine and not player.tentative_pair)
    assert(not pcall(vg.event_handler.prove_state_transition, player, 0, rejected_at, 0))
    -- A nonzero uarch reveal materializes the cached agreement by finishing the
    -- existing pair, including rollback, without reconstructing the prefix again.
    tentative_position = { epoch_input_offset = 0, input_mcycle_offset = rejected_at, uarch_cycle = 1 }
    vg.event_handler.reveal_bisection(player, agreed_position, tentative_position)
    assert(player.agreed_pair == candidate and not candidate.backup_machine)
    assert(player.agreed_pair.input_mcycle_base == input_mcycle_base)
    assert(player.agreed_pair.machine:read_reg("mcycle") == input_mcycle_base)
    -- Later offsets observe the restored accept yield, without finalizing the rejected input again.
    local reason, yield_reason, base = player:run_to_input_mcycle_offset(
        player.agreed_pair,
        player.inputs[1],
        tentative_position.input_mcycle_offset,
        tentative_position.input_mcycle_offset + 1
    )
    assert(reason == cartesi.BREAK_REASON_YIELDED_MANUALLY)
    assert(yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED and base == input_mcycle_base)
    assert(not player.agreed_pair.backup_machine and player.agreed_pair.machine:get_root_hash() == initial_hash)

    -- Finishing an input and advancing to the next one uses the same driver.
    local replay <close> = player:new_advancing_pair()
    player:run_to_epoch_input_offset(replay, player.inputs, 0, 2)
    assert(not replay.backup_machine and replay.machine:get_root_hash() == player.final_state_hash)
end

-- Split execution preserves buffered outputs across both continuation and a
-- bisection fork. The first output is not published until the input accepts.
do
    local hash_tree = require("cartesi.hash-tree")
    local player <close> = vg.new_player(initial_hash)
    local input_data = util.read_file(paths[1])
    local probe <close> = player:new_advancing_pair()
    local input_mcycle_base = probe.machine:read_reg("mcycle")
    vg.load_cmio_input(probe.machine, input_data, initial_hash)
    while true do
        local break_reason = probe.machine:run(cartesi.MCYCLE_MAX)
        assert(break_reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY)
        local _, yield_reason = probe.machine:receive_cmio_request()
        if yield_reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT then
            break
        end
    end
    local output_offset = probe.machine:read_reg("mcycle") - input_mcycle_base
    local split <close> = player:new_advancing_pair()
    local outputs = {}
    local frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
    local reason = player:run_to_input_mcycle_offset(split, input_data, 0, output_offset, outputs, frontier)
    assert(reason == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    assert(#outputs == 0 and #split.pending_outputs == 1)
    assert(split.revert_root_hash == initial_hash)
    local fork <close> = split:fork()
    assert(fork.revert_root_hash == initial_hash)
    assert(split.backup_machine ~= fork.backup_machine and fork.backup_machine:get_root_hash() == initial_hash)
    assert(fork.pending_outputs ~= split.pending_outputs and fork.pending_outputs[1] == split.pending_outputs[1])
    local fork_outputs, fork_frontier = {}, hash_tree.frontier_copy(frontier)
    player:run_to_input_mcycle_offset(split, input_data, output_offset, (1 << 48) - 1, outputs, frontier)
    player:run_to_input_mcycle_offset(fork, input_data, output_offset, (1 << 48) - 1, fork_outputs, fork_frontier)
    assert(split.machine:get_root_hash() == fork.machine:get_root_hash())
    assert(#outputs == 1 and outputs[1] == fork_outputs[1])
    assert(hash_tree.frontier_get_root_hash(frontier) == hash_tree.frontier_get_root_hash(fork_frontier))
    assert(not split.backup_machine and not fork.backup_machine)
    assert(split.input_mcycle_base == input_mcycle_base and fork.input_mcycle_base == input_mcycle_base)
    local settled_hash = split.machine:get_root_hash()
    assert(split.revert_root_hash == settled_hash and fork.revert_root_hash == settled_hash)
    player:run_to_input_mcycle_offset(split, input_data, (1 << 48) - 1, 1 << 48)
    assert(split.machine:get_root_hash() == settled_hash and #outputs == 1)
    local completed <close> = split:fork()
    local _, yield_reason, base = player:run_to_input_mcycle_offset(completed, input_data, (1 << 48) - 1, 1 << 48)
    assert(yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED and base == input_mcycle_base)
    assert(not completed.backup_machine and completed.machine:get_root_hash() == settled_hash)
    vg.event_handler.input_added(player, 0, paths[1])
    assert(player.epoch_pair.machine:get_root_hash() == settled_hash and player.outputs[1] == outputs[1])
end

-- Leaf zero is a resulting state at every level. The predecessor stays outside
-- the range. The final log uses agreed or tentative according to the final index.
for uarch_cycle = 0, 1 do
    local player <close> = vg.new_player(initial_hash)
    vg.event_handler.input_added(player, 0, paths[1])
    local after_input = player.epoch_pair.machine:get_root_hash()
    assert(after_input ~= initial_hash)
    vg.event_handler.epoch_sealed(player)
    vg.event_handler.dispute_started(player)
    assert(
        vg.event_handler.reveal_bisection(
            player,
            { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 },
            { epoch_input_offset = 1, input_mcycle_offset = 0, uarch_cycle = 0 }
        ) == after_input
    )

    local mcycle <close> = player:new_advancing_pair()
    player:run_to_input_mcycle_offset(mcycle, player.inputs[1], 0, 1)
    assert(
        vg.event_handler.reveal_bisection(
            player,
            { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 },
            { epoch_input_offset = 0, input_mcycle_offset = 1, uarch_cycle = 0 }
        ) == mcycle.machine:get_root_hash()
    )
    local uarch <close> = player:new_advancing_pair()
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
    local root_hash_before = initial_hash
    if uarch_cycle == 1 then
        root_hash_before = after_uarch
        uarch.machine:log_step_uarch()
        after_uarch = uarch.machine:get_root_hash()
    end
    local agreed, tentative = player.agreed_pair, player.tentative_pair
    local log = vg.event_handler.prove_state_transition(player, 0, 0, uarch_cycle)
    assert(
        vg.validate_state_transition_response({ inputs = player.inputs }, root_hash_before, 0, 0, uarch_cycle, log)
            == after_uarch
    )
    assert(not agreed.machine and not agreed.backup_machine)
    assert(not player.agreed_pair and not player.agreed_pair_position and not player.tentative_pair_position)
    assert(
        player.agreed_position.epoch_input_offset == 0
            and player.agreed_position.input_mcycle_offset == 0
            and player.agreed_position.uarch_cycle == 0
    )
    assert(not tentative.machine and not tentative.backup_machine and not player.tentative_pair)
    assert(player.final_state_hash == after_input and not player.epoch_pair)
end

-- Empty epochs finish after establishing the root, without inventing an output.
do
    local a <close> = vg.new_player(initial_hash, "honest 1")
    local b <close> = vg.new_player(initial_hash, "honest 2")
    local empty = run_game({ a, b }, {})
    assert(empty.final_state_hash == initial_hash and empty.outputs_root and not empty.output)
end

-- Validate terminal logs directly at input inclusion, an ordinary step, and the
-- reset carrying rejection rollback. These checks use the same verifier as disputes.
do
    local player <close> = vg.new_player(initial_hash)
    vg.event_handler.input_added(player, 0, paths[2])
    vg.event_handler.epoch_sealed(player, 1)
    local contract = { inputs = { util.read_file(paths[2]) } }
    local function verify(machine, input_mcycle_offset, cycle, input, expected)
        local root_hash_before = machine:get_root_hash()
        local logs = {}
        if input then
            logs.send_cmio_log =
                machine:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, root_hash_before)
        end
        logs.step_log = machine:log_step_uarch()
        if cycle == cartesi.UARCH_CYCLE_MAX then
            logs.reset_uarch_log = machine:log_reset_uarch()
        end
        local root_hash_after = expected or machine:get_root_hash()
        assert(
            vg.validate_state_transition_response(contract, root_hash_before, 0, input_mcycle_offset, cycle, logs)
                == root_hash_after
        )
        assert(
            not pcall(
                vg.validate_state_transition_response,
                contract,
                root_hash_before,
                0,
                input_mcycle_offset,
                cycle,
                {}
            )
        )
    end
    local included <close> = player:new_advancing_pair()
    local prefix <close> = player:new_advancing_pair()
    verify(included.machine, 0, 0, contract.inputs[1])
    player:run_to_uarch_cycle(prefix, player.inputs[1], 0, 0, 1)
    assert(prefix.machine:get_root_hash() == included.machine:get_root_hash())
    verify(included.machine, 0, 1)
    player:run_to_uarch_cycle(prefix, player.inputs[1], 0, 1, 2)
    assert(prefix.machine:get_root_hash() == included.machine:get_root_hash())
    local rejected <close> = player:new_advancing_pair()
    rejected:snapshot()
    vg.load_cmio_input(rejected.machine, contract.inputs[1], initial_hash)
    local break_reason
    repeat
        break_reason = rejected.machine:run(vg.usaturating_add(rejected.backup_machine:read_reg("mcycle"), 1 << 48))
    until break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
    assert(break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY)
    -- Replay to the instruction that performs the rejecting yield, before its reset.
    local offset = rejected.machine:read_reg("mcycle") - rejected.backup_machine:read_reg("mcycle") - 1
    local boundary <close> = player:new_advancing_pair()
    player:run_to_input_mcycle_offset(boundary, player.inputs[1], 0, offset)
    player:run_to_uarch_cycle(boundary, player.inputs[1], offset, 0, cartesi.UARCH_CYCLE_MAX)
    local before_reset = boundary.machine:get_root_hash()
    player.agreed_pair = boundary:move()
    player.agreed_position =
        { epoch_input_offset = 0, input_mcycle_offset = offset, uarch_cycle = cartesi.UARCH_CYCLE_MAX }
    player.agreed_pair_position = player.agreed_position
    local log = vg.event_handler.prove_state_transition(player, 0, offset, cartesi.UARCH_CYCLE_MAX)
    assert(
        vg.validate_state_transition_response(contract, before_reset, 0, offset, cartesi.UARCH_CYCLE_MAX, log)
            == initial_hash
    )
    local replay <close> = player:new_advancing_pair()
    player:run_to_input_mcycle_offset(replay, player.inputs[1], 0, offset + 1)
    assert(replay.machine:get_root_hash() == initial_hash, "reset did not carry rejection rollback")
    -- With no posted input, verification requires no inclusion log. A uarch
    -- period still has its halted tail and reset, even at a fixed mcycle state.
    local absent <close> = player:new_advancing_pair()
    local root_hash_before = absent.machine:get_root_hash()
    local step = absent.machine:log_step_uarch()
    assert(
        vg.validate_state_transition_response({ inputs = {} }, root_hash_before, 0, 0, 0, { step_log = step })
            == absent.machine:get_root_hash()
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
            revert_root_hash = initial_hash,
            machine = {
                read_reg = function()
                    return 0
                end,
                get_root_hash = function()
                    return initial_hash
                end,
                read_memory = function()
                    return string.rep("\0", 8)
                end,
                get_proof = function()
                    return {}
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
                assert(not pair.backup_machine)
                pair.backup_machine = { read_reg = pair.machine.read_reg, batch = pair.machine.batch }
            end,
            commit = function(pair)
                pair.backup_machine = nil
            end,
            revert = function(pair)
                pair.machine.batch = pair.backup_machine.batch
                pair.machine.output_index = #pair.machine.batch + 1
                pair.backup_machine = nil
            end,
            close = function(pair)
                pair.machine, pair.backup_machine = nil, nil
            end,
        }
        return pair
    end
    local player = setmetatable({
        inputs = {},
        input_base_hashes = { [0] = initial_hash },
        fixed_point_mcycle_offsets = {},
        epoch_pair = new_pair(),
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
    assert(offer.output_data == "last" and offer.output_index == 3 and #player.outputs == 4)
    assert(require("game-output").validate_output_response(offer, hash_tree.frontier_get_root_hash(expected)))
    local proofs = player.output_proofs
    local replay = new_pair()
    -- Replay ignores automatic yields without reading their output payloads.
    local receive_cmio_request = replay.machine.receive_cmio_request
    function replay.machine:receive_cmio_request()
        assert(self.output_index > #self.batch, "replay read an automatic yield")
        return receive_cmio_request(self)
    end
    player:run_to_epoch_input_offset(replay, player.inputs, 0, #batches)
    assert(#player.outputs == 4 and player.output_proofs == proofs and not player.outputs_frontier)
    assert(require("game-output").validate_output_response(vg.event_handler.prove_output(player), root))

    -- Reaching the span limit without a fixed point still retains the snapshot.
    local unfinished = new_pair()
    unfinished.machine.run = function()
        return cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
    end
    player.epoch_pair = unfinished
    player.final_state_hash, player.outputs_merkle_root_proof = nil, nil
    vg.event_handler.input_added(player, #player.inputs, paths[1])
    assert(not player.fixed_point_mcycle_offsets[#player.inputs] and unfinished.backup_machine)
    local ok, err = pcall(vg.event_handler.epoch_sealed, player)
    assert(not ok and tostring(err):find("cannot seal an unfinished input", 1, true))
    assert(not player.final_state_hash and not player.outputs_merkle_root_proof)
    assert(player.epoch_pair == unfinished and unfinished.machine and unfinished.backup_machine)
    player:close()
    assert(not unfinished.machine and not unfinished.backup_machine)
end

-- Malformed final-state and output offers cannot pass the shared proof checks.
do
    local checks = require("game-output")
    local root_offer = first.event_handler.prove_outputs_merkle_root(first)
    local root = checks.validate_outputs_merkle_root_response(root_offer, first.final_state_hash)
    local output = first.event_handler.prove_output(first)
    assert(checks.validate_output_response(output, root))
    output.output_index = output.output_index + 1
    assert(not pcall(checks.validate_output_response, output, root))
    output.output_index = output.output_index - 1
    output.output_proof.log2_target_size = 1
    assert(not pcall(checks.validate_output_response, output, root))
    root_offer.iflags_y_data = string.rep("\0", 32)
    assert(not pcall(checks.validate_outputs_merkle_root_response, root_offer, first.final_state_hash))
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
local function snapshot_composite(pair)
    pair.machine:set_input_index(pair.epoch_input_offset)
    pair.epoch_input_offset = pair.epoch_input_offset + 1
    vg.advancing_pair_methods.snapshot(pair)
end
for _, cheat in ipairs({ "no-rollback", "extra-input", "composite" }) do
    local honest <close> = vg.new_player(initial_hash)
    local overrides = {}
    if cheat == "no-rollback" then
        function overrides:new_advancing_pair()
            local pair = vg.player_methods.new_advancing_pair(self)
            pair.revert = ignore_rollback
            return pair
        end
    elseif cheat == "composite" then
        local composite = require("dishonest")
        function overrides:new_machine()
            return composite.new_rolling_composite_machine(
                vg.player_methods.new_machine(self),
                2,
                100,
                3,
                vg.player_methods.new_machine(self),
                util.read_file("forged-input-2.bin")
            )
        end
        function overrides:new_advancing_pair()
            local pair = vg.player_methods.new_advancing_pair(self)
            pair.epoch_input_offset = 0
            pair.snapshot = snapshot_composite
            return pair
        end
    end
    local opponent <close> = vg.new_player(initial_hash, cheat, nil, overrides)
    if cheat == "extra-input" then
        opponent.event_handler = setmetatable({ epoch_sealed = seal_with_extra_input }, { __index = vg.event_handler })
    end
    local result, server = run_game({ opponent, honest })
    assert(
        result.players[server.connections[2]] == result.winner and result.final_state_hash == honest.final_state_hash,
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
            and settled.final_state_hash == initial_hash
            and not settled.output
    )
    assert(#vg.addresses(settled.players) == 2)
    for _, player in pairs(settled.players) do
        assert(player.allowance == 3)
    end
end
-- Seed terminal states after setup. A halted/overflowed machine has no
-- pending yield, while an exception keeps its manual yield with a different reason.
-- Later deliveries are no-ops and saturating targets cannot wrap to an earlier cycle.
for _, terminal in ipairs({ "halt", "overflow", "exception" }) do
    local player <close> = vg.new_player(initial_hash)
    local machine = player.epoch_pair.machine
    if terminal == "exception" then
        machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION)
    else
        machine:write_reg("iflags_Y", 0)
        machine:write_reg(terminal == "halt" and "iflags_H" or "mcycle", terminal == "halt" and 1 or cartesi.MCYCLE_MAX)
    end
    local hash = machine:get_root_hash()
    local prefix <close> = player.epoch_pair:fork()
    local expected_break, expected_yield = player:run_to_input_mcycle_offset(prefix, player.inputs[1], 0, 1)
    assert(not prefix.backup_machine and prefix.machine:get_root_hash() == hash)
    local break_reason, yield_reason, base = player:run_to_input_mcycle_offset(prefix, nil, 1, 2)
    assert(break_reason == expected_break and yield_reason == expected_yield)
    assert(base == machine:read_reg("mcycle") and prefix.machine:get_root_hash() == hash)
    for index, path in ipairs(paths) do
        vg.event_handler.input_added(player, index - 1, path)
        assert(player.epoch_pair.machine:get_root_hash() == hash)
        assert(player.epoch_pair.revert_root_hash == initial_hash)
        assert(not player.epoch_pair.backup_machine)
    end
    -- Proofs of later no-op deliveries also use the retained, older boundary hash.
    local prefix_uarch <close> = player.epoch_pair:fork()
    player.agreed_pair = player.epoch_pair:fork()
    player.agreed_position = { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 }
    player.agreed_pair_position = player.agreed_position
    vg.event_handler.epoch_sealed(player, #paths)
    assert(player.final_state_hash == hash)
    for index = 0, #paths - 1 do
        assert(player.fixed_point_mcycle_offsets[index + 1] == 0)
        assert(player.input_base_hashes[index + 1] == hash)
        local position = { epoch_input_offset = index, input_mcycle_offset = 1, uarch_cycle = 0 }
        assert(player:recorded_position_hash(position) == hash)
        position.uarch_cycle = 1
        assert(not player:recorded_position_hash(position))
    end
    player:run_to_uarch_cycle(prefix_uarch, player.inputs[1], 0, 0, 1)
    local proof = vg.event_handler.prove_state_transition(player, 0, 0, 0)
    assert(
        vg.validate_state_transition_response({ inputs = player.inputs }, hash, 0, 0, 0, proof)
            == prefix_uarch.machine:get_root_hash()
    )
end

-- The tamperer's bookkeeping follows a fork and is restored with a rejected input.
do
    local roles = require("vg-dishonest")
    local player <close> = roles.new_tamperer(initial_hash, 0, 100)
    vg.event_handler.input_added(player, 0, paths[2])
    assert(player.epoch_pair.machine:get_root_hash() == initial_hash)
    assert(not player.epoch_pair.machine.tampered)
    local loaded <close> = player:new_advancing_pair()
    local replay <close> = loaded:fork()
    player:run_to_epoch_input_offset(replay, player.inputs, 0, 1)
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
            and not captured.initial_machine
            and not captured.epoch_pair
            and not captured.agreed_pair
            and not captured.tentative_pair
    )
end
print("vg-test: fixed points, tamperer rollback and cleanup ok")

replay_test.run(initial_hash, paths)

print("vg-test: ok")
