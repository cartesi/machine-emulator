#!/usr/bin/env lua5.4
-- Scenario for R1-REFEREE-2, driven by test.lua: lua5.4 scenario.lua control|attack
--
-- Runs the real referee model (prt.new_referee over prt.new_dapp_contract, so the real run_referee,
-- run_tournament and wait_for_outputs of doc/recipes/prt.lua, with game-output.lua as the output
-- verifier) on game-test-server with prtu.protocol. Every response travels through the real JSON
-- encoding of prtu.protocol.schemas (ProveOutputResponse: output_index = "Default").
--
-- The settled state is synthetic but well formed: a small machine whose iflags_Y = 1, whose htif_tohost
-- is a manual yield with the accepted reason, and whose tx buffer holds the outputs Merkle root of a
-- full-height (2^63-leaf) outputs tree with two outputs: a withdrawal at index 0 and another notice at
-- index 1. The honest player posts the only claim (a uniform tree whose leaves are that machine's root
-- hash), so the claim wins with no dispute, and the referee then runs wait_for_outputs on that final state.
--
-- Players, in admission order:
--   honest    posts the claim, proves the outputs Merkle root, and answers the first prove_output with the
--             genuine proof of the withdrawal at index 0 (exactly what the honest player serves).
--   attacker  answers the second prove_output with
--               control: the same genuine response again (must be rejected as a duplicate);
--               attack:  the same proof and data, with output_index = target_address = 0 | (1 << 63)
--                        (the Lua integer -2^63, uint64 2^63), an index the height-63 tree does not have.
-- The honest player watches: if a third prove_output request arrives the second offer was accepted;
-- if the second request is still open 3 blocks later it was rejected. Either way it prints the outputs
-- the referee accepted and exits.
--
-- Output lines parsed by test.lua:
--   ACCEPTED <output_index> <decoded notice payload>   (one per story.report_output call, in order)
--   END <reason>
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local prt = require("prt")
local prtu = require("prtu")
local run_with_game_server = require("game-test-server")
local keccak = cartesi.keccak256

local mode = arg[1]
assert(mode == "control" or mode == "attack", "usage: scenario.lua control|attack")
local ATTACK = mode == "attack"
local H = prt.new_geometry(10).mcycle_height
local WORD_SIZE = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE

-- The outputs of the settled state, ABI-encoded as Notice(bytes payload) like the demo's outputs (the
-- referee story decodes every accepted output that way). Output 0 stands for a withdrawal.
local evmu = require("cartesi.evmu")
local function notice(payload)
    return evmu.encode_calldata("Notice(bytes payload)", { evmu.raw(payload) })
end
local PAYLOADS = { "withdraw 100 to 0xa77acc", "hello" }
local OUTPUTS = { notice(PAYLOADS[1]), notice(PAYLOADS[2]) }
local frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
local output_hashes = {}
for i, o in ipairs(OUTPUTS) do
    output_hashes[i] = keccak(o)
end
local output_proofs = hash_tree.frontier_next_proofs(frontier, output_hashes)
for _, h in ipairs(output_hashes) do
    hash_tree.frontier_push_back(frontier, h)
end
local outputs_merkle_root = hash_tree.frontier_get_root_hash(frontier)

-- A settled state that waits at a manual yield with the accepted reason and commits to that root.
local machine = cartesi.machine({ ram = { length = 0x10000 } })
machine:write_reg("iflags_Y", 1)
machine:write_reg(
    "htif_tohost",
    (cartesi.HTIF_DEV_YIELD << cartesi.HTIF_DEV_SHIFT)
        | (cartesi.HTIF_YIELD_CMD_MANUAL << cartesi.HTIF_CMD_SHIFT)
        | (cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED << cartesi.HTIF_REASON_SHIFT)
)
machine:write_memory(cartesi.AR_CMIO_TX_BUFFER_START, outputs_merkle_root)
local final_state_hash = machine:get_root_hash()

local function get_machine_leaf(address)
    local target_address = address & ~(WORD_SIZE - 1)
    return machine:read_memory(target_address, WORD_SIZE),
        machine:get_proof(target_address, cartesi.HASH_TREE_LOG2_WORD_SIZE)
end
local function outputs_merkle_root_proof()
    local iy_data, iy_proof = get_machine_leaf(machine:get_reg_address("iflags_Y"))
    local th_data, th_proof = get_machine_leaf(machine:get_reg_address("htif_tohost"))
    local tx_data, tx_proof = get_machine_leaf(cartesi.AR_CMIO_TX_BUFFER_START)
    return {
        iflags_y_data = iy_data,
        iflags_y_proof = iy_proof,
        htif_tohost_data = th_data,
        htif_tohost_proof = th_proof,
        tx_buffer_data = tx_data,
        tx_buffer_proof = tx_proof,
    }
end

-- The honest claim: a uniform computation-hash tree whose every leaf is the settled state hash.
local R = { [0] = final_state_hash }
for h = 1, H do
    R[h] = keccak(R[h - 1], R[h - 1])
end
local function claim()
    local sib = {}
    for h = 0, H - 1 do
        sib[#sib + 1] = R[h]
    end
    return {
        computation_hash_left = R[H - 1],
        computation_hash_right = R[H - 1],
        final_state_hash_proof = {
            target_address = (1 << H) - 1,
            log2_target_size = 0,
            target_hash = final_state_hash,
            log2_root_size = H,
            root_hash = R[H],
            sibling_hashes = sib,
        },
    }
end

local function copy(t)
    local c = {}
    for k, v in pairs(t) do
        c[k] = v
    end
    return c
end

-- The genuine response for the withdrawal (output 0), as the honest player serves it.
local genuine = { output_index = 0, output_data = OUTPUTS[1], output_proof = output_proofs[1] }
assert(output_proofs[1].target_address == 0)
-- The attacker's response: same data and siblings, index and target address with bit 63 set.
local ALIAS = 0 | (1 << 63)
local aliased_proof = copy(output_proofs[1])
aliased_proof.target_address = ALIAS
local aliased = { output_index = ALIAS, output_data = OUTPUTS[1], output_proof = aliased_proof }

-- Record every output the referee accepts.
local story = prtu.story
local accepted = {}
local original_report_output = story.report_output
story.report_output = function(output)
    accepted[#accepted + 1] = output
    return original_report_output(output)
end
local original_report_winner = story.report_winner
story.report_winner = function(winner)
    print("WINNER " .. (winner and winner.final_state_hash == final_state_hash and "HONEST" or "OTHER"))
    return original_report_winner(winner)
end

local function finish(reason)
    for _, o in ipairs(accepted) do
        local payload = evmu.decode_calldata("Notice(bytes payload)", o.output_data, "raw").payload
        print(string.format("ACCEPTED %d %s", o.output_index, payload))
    end
    print("END " .. reason)
    io.stdout:flush()
    os.exit(0)
end

local function base_handler()
    return {
        input_added = function()
            return true
        end,
        epoch_sealed = function()
            return true
        end,
        reveal_bisection = function()
            return "nothing"
        end,
        seal_divergence = function()
            return "nothing"
        end,
        win_match_by_timeout = function()
            return "nothing"
        end,
        eliminate_match = function()
            return "nothing"
        end,
        prove_outputs_merkle_root = function()
            return "nothing"
        end,
    }
end

local honest = { label = "honest", requests = 0 }
honest.event_handler = base_handler()
honest.event_handler.commit_mcycle_claim = function()
    return claim()
end
honest.event_handler.prove_outputs_merkle_root = function(_, final)
    assert(final == final_state_hash, "unexpected settled state")
    return outputs_merkle_root_proof()
end
honest.event_handler.prove_output = function(self)
    honest.requests = honest.requests + 1
    if honest.requests == 1 then
        return genuine
    elseif honest.requests == 2 then
        -- Still open 3 blocks later means the attacker's offer was rejected.
        return prtu.schedule_response(self, self.block + 3, function()
            finish("second offer rejected")
        end)
    end
    finish("second offer accepted")
end

local attacker = { label = "attacker", requests = 0 }
attacker.event_handler = base_handler()
attacker.event_handler.commit_mcycle_claim = function()
    return "nothing"
end
attacker.event_handler.prove_output = function()
    attacker.requests = attacker.requests + 1
    if attacker.requests == 2 then
        return ATTACK and aliased or genuine
    end
    return "nothing"
end

run_with_game_server(prtu.protocol, function(server, run_client, wait_connections)
    local players = { honest, attacker }
    for i, p in ipairs(players) do
        run_client({ role = "player", label = p.label }, function(event, line)
            p.block = event.block
            return prtu.answer_event(p, line)
        end, true)
        wait_connections(i)
    end
    local closer = prtu.new_phase_closer()
    run_client(cartesi.fromjson(closer.hello), function(_, line)
        return prtu.answer_event(closer, line)
    end, true)
    local referee = prt.new_referee(prt.new_dapp_contract(keccak("initial state"), {}))
    referee:run(server)
end)
print("END referee finished")
