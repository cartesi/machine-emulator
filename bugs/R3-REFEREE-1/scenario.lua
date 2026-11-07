#!/usr/bin/env lua5.4
-- Scenario for R3-REFEREE-1, driven by test.lua: lua5.4 scenario.lua notice|voucher|label_string|label_true
--
-- Runs the real referee model (prt.new_referee over prt.new_dapp_contract, so the real run_referee,
-- open_mcycle_tournament, run_tournament and wait_for_outputs of doc/recipes/prt.lua, with the real
-- prtu.story narration and game-output.lua as the output verifier) on game-test-server with
-- prtu.protocol. Every message travels through the real JSON encoding of prtu.protocol.schemas, and every
-- connection announces itself through the real game-transport announce.
--
-- The settled state is synthetic but well formed (as in R1-REFEREE-2): a small machine whose
-- iflags_Y = 1, whose htif_tohost is a manual yield with the accepted reason, and whose tx buffer holds
-- the outputs Merkle root of a full-height outputs tree with two outputs. The honest player posts a
-- uniform claim whose leaves are that machine's root hash, so the claim wins with no dispute (it is the
-- only computation hash), and the referee then runs wait_for_outputs on that final state.
--
-- Modes:
--   notice        (control) outputs = { Notice("withdraw..."), Notice("hello") }; one honest player.
--   voucher       outputs = { Voucher(0x0101..01, 0, "withdraw..."), Notice("hello") }; one honest player.
--                 The voucher is the ABI encoding the machine-guest-tools rollup interface emits
--                 (cmt_rollup_emit_voucher, selector 0x237a816f).
--   label_string  (control) notice outputs; a second connection announces label "sybil" and posts the
--                 same claim as the honest player.
--   label_true    notice outputs; a second connection announces {"role":"player","label":true} and posts
--                 the same claim as the honest player.
-- The honest player offers output 0 at the first prove_output request and output 1 at the second. A third
-- request means both were accepted, and the scenario ends.
--
-- Output lines parsed by test.lua:
--   WINNER HONEST|OTHER
--   ACCEPTED <output_index>        (printed as story.report_output is entered, i.e. after acceptance)
--   END <reason>
-- If the referee coroutine raises, game-transport's dispatcher rethrows it and this script dies with a
-- Lua traceback (nonzero exit, no END line).
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local prt = require("prt")
local prtu = require("prtu")
local evmu = require("cartesi.evmu")
local run_with_game_server = require("game-test-server")
local keccak = cartesi.keccak256

local mode = arg[1]
local MODES = { notice = true, voucher = true, label_string = true, label_true = true }
assert(MODES[mode], "usage: scenario.lua notice|voucher|label_string|label_true")
local H = prt.new_geometry(10).mcycle_height
local WORD_SIZE = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE

local function notice(payload)
    return evmu.encode_calldata("Notice(bytes payload)", { evmu.raw(payload) })
end
local function voucher(destination, value, payload)
    return evmu.encode_calldata(
        "Voucher(address destination,uint256 value,bytes payload)",
        { destination, value, evmu.raw(payload) }
    )
end
local OUTPUTS
if mode == "voucher" then
    OUTPUTS = { voucher("0x" .. ("01"):rep(20), 0, "withdraw 100 to 0xa77acc"), notice("hello") }
    assert(OUTPUTS[1]:sub(1, 4) == "\x23\x7a\x81\x6f", "unexpected Voucher selector")
else
    OUTPUTS = { notice("withdraw 100 to 0xa77acc"), notice("hello") }
end

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

local function genuine(i)
    return { output_index = i - 1, output_data = OUTPUTS[i], output_proof = output_proofs[i] }
end

-- Observe the referee's narration hooks without changing them.
local story = prtu.story
local original_report_output = story.report_output
story.report_output = function(output)
    print(string.format("ACCEPTED %d", output.output_index))
    io.stdout:flush()
    return original_report_output(output)
end
local original_report_winner = story.report_winner
story.report_winner = function(winner)
    print("WINNER " .. (winner and winner.final_state_hash == final_state_hash and "HONEST" or "OTHER"))
    io.stdout:flush()
    return original_report_winner(winner)
end
local original_report_claims = story.report_claims
story.report_claims = function(...)
    print("CLAIMS_ADMITTED")
    io.stdout:flush()
    return original_report_claims(...)
end

local function finish(reason)
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
        prove_output = function()
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
    if honest.requests <= #OUTPUTS then
        return genuine(honest.requests)
    end
    finish("all outputs accepted")
end

local players = { honest }
if mode == "label_string" or mode == "label_true" then
    -- A Sybil that posts the same (cheap, valid) claim. Only its announced label differs between modes.
    local sybil = { label = (mode == "label_true") and true or "sybil" }
    sybil.event_handler = base_handler()
    sybil.event_handler.commit_mcycle_claim = function()
        return claim()
    end
    players[#players + 1] = sybil
end

run_with_game_server(prtu.protocol, function(server, run_client, wait_connections)
    for i, p in ipairs(players) do
        -- The hello is encoded with cartesi.tojson, so label=true goes on the wire as {"label":true}.
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
