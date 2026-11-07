#!/usr/bin/env lua5.4
-- Scenario for R1-REFEREE-1, driven by test.lua: lua5.4 scenario.lua control|attack
--
-- Runs the real referee model (prt.new_referee over prt.new_dapp_contract) on game-test-server with
-- prtu.protocol and three in-process players that answer through prtu.answer_event. The claims are
-- synthetic: uniform height-62 mcycle trees whose leaves are all one hash (no machine is needed, the
-- referee only checks Merkle consistency until the bisection reaches a leaf, which never happens here).
--
-- Connection admission order (the order passed to partition_claims): attacker-D, second, honest-H.
--   attacker-D posts the dishonest claim D at once (block 1), opens it once, then stops defending it but
--              claims any timeout win.
--   second     control: re-posts D at block +1 and stays passive.
--              attack:  a Sybil that re-posts the HONEST claim at block +3 (the last block before the
--              joining deadline) and stays passive.
--   honest-H   posts the honest claim at once (block 1) and answers every request at the earliest block.
--
-- Output lines parsed by test.lua:
--   CLAIM <short hash> allowance=<a> first_received=<r> posters=<labels>   (one per claim in the bracket)
--   SETTLED <HONEST|DISHONEST|UNKNOWN>
--   TRACE ...                                                                (player actions)
local cartesi = require("cartesi")
local prt = require("prt")
local prtu = require("prtu")
local run_with_game_server = require("game-test-server")
local keccak = cartesi.keccak256

local mode = arg[1]
assert(mode == "control" or mode == "attack", "usage: scenario.lua control|attack")
local ATTACK = mode == "attack"
local H = prt.new_geometry(10).mcycle_height

local function hex(h)
    return "0x" .. (h:gsub(".", function(c) return string.format("%02x", c:byte()) end)):sub(1, 8)
end

-- A uniform computation-hash tree: every leaf is `leaf`, so every node at height h is R[h].
local function uniform(leaf)
    local R = { [0] = leaf }
    for h = 1, H do
        R[h] = keccak(R[h - 1], R[h - 1])
    end
    local t = { R = R, root = R[H] }
    function t.claim()
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
                target_hash = leaf,
                log2_root_size = H,
                root_hash = R[H],
                sibling_hashes = sib,
            },
        }
    end
    function t.reveal(height)
        return {
            turn_left_node = R[height - 1],
            turn_right_node = R[height - 1],
            turn_next_left_node = R[height - 2],
            turn_next_right_node = R[height - 2],
        }
    end
    return t
end

local honest = uniform(keccak("honest final state"))
local dishonest = uniform(keccak("dishonest final state"))

-- Record the bracket the referee built: each claim's clock and the earliest block any holder posted it.
local story = prtu.story
local original_report_claims = story.report_claims
story.report_claims = function(tournament, responses, order)
    if tournament.level == "mcycle" then
        local first, posters = {}, {}
        for _, sender in ipairs(order) do
            local r = responses[sender]
            local h = r.claim.computation_hash
            if first[h] == nil or r.received_at < first[h] then
                first[h] = r.received_at
            end
            posters[h] = (posters[h] and posters[h] .. "," or "") .. sender.label
        end
        for _, claim in ipairs(tournament.claims) do
            local who = claim.computation_hash == honest.root and "honest"
                or (claim.computation_hash == dishonest.root and "dishonest" or "unknown")
            print(
                string.format(
                    "CLAIM %s %s allowance=%d first_received=%d posters=%s",
                    who,
                    hex(claim.computation_hash),
                    claim.allowance,
                    first[claim.computation_hash],
                    posters[claim.computation_hash]
                )
            )
        end
    end
    return original_report_claims(tournament, responses, order)
end

local function new_player(label, tree, opts)
    local p = { label = label, reveals = 0 }
    p.event_handler = {
        input_added = function()
            return true
        end,
        epoch_sealed = function()
            return true
        end,
        commit_mcycle_claim = function(self)
            print(string.format("TRACE block %d: %s commit request (posting %s at block %d)", self.block, label,
                tree == honest and "honest claim" or "dishonest claim", self.block + (opts.delay or 1)))
            if opts.delay then
                return prtu.schedule_response(self, self.block + opts.delay, function()
                    return tree.claim()
                end)
            end
            return tree.claim()
        end,
        reveal_bisection = function(self, hash, _, height)
            if hash ~= tree.root or opts.passive or (opts.max_reveals and self.reveals >= opts.max_reveals) then
                return "nothing"
            end
            self.reveals = self.reveals + 1
            print(string.format("TRACE request block %d: %s reveals at height %d", self.block, label, height))
            return tree.reveal(height)
        end,
        seal_divergence = function()
            return "nothing"
        end,
        win_match_by_timeout = function(self, hash)
            if hash ~= tree.root or opts.passive then
                return "nothing"
            end
            print(string.format("TRACE request block %d: %s claims a timeout win", self.block, label))
            return { computation_hash_left = tree.R[H - 1], computation_hash_right = tree.R[H - 1] }
        end,
        eliminate_match = function()
            return "nothing"
        end,
        prove_outputs_merkle_root = function(_, final)
            local settled = final == honest.R[0] and "HONEST" or (final == dishonest.R[0] and "DISHONEST" or "UNKNOWN")
            print("SETTLED " .. settled)
            io.stdout:flush()
            os.exit(0)
        end,
    }
    return p
end

run_with_game_server(prtu.protocol, function(server, run_client, wait_connections)
    local players = {
        new_player("attacker-D", dishonest, { max_reveals = 1 }),
        ATTACK and new_player("sybil-H", honest, { delay = 3, passive = true })
            or new_player("idle-D", dishonest, { delay = 1, passive = true }),
        new_player("honest-H", honest, {}),
    }
    -- Admit the players one at a time, so the admission order is exactly the list order.
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
print("SETTLED NONE")
