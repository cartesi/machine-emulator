#!/usr/bin/env lua5.4
-- Scenario for R2-REFEREE-1, driven by test.lua: lua5.4 scenario.lua <mode>
--
-- Runs the real referee model (prt.new_referee) on game-test-server with prtu.protocol and three in-process
-- players that answer through prtu.answer_event. Geometry mcycle_height = uarch_height = 3, so a match
-- bisects at heights 3 and 2 and seals at height 1. The disputed transition is real: the first uarch step
-- of a tiny 4 KiB machine. Its log (log_step_uarch) verifies from the initial state hash to `after`.
--
-- Claims (all trees repeat one leaf unless noted):
--   honest  mcycle C_h = all `after` (the true trajectory), uarch H = all `after` (true: leaf 0 = after).
--   sybil1  mcycle C_d = all `false`, uarch S1 = all `false`.
--   sybil2  mcycle C_d (same claim as sybil1), uarch S2 = leaf 0 `sybil2 leaf`, rest `false` (ends at `false`).
-- Connection (= join) order is honest, sybil1, sybil2, so the uarch bracket is H vs S1 with S2 unmatched.
--
-- Modes:
--   control  the honest player answers every request, the transition proof included, in the next block.
--   attack   sybil1 posts its uarch claim 5 blocks late (clock 8-1-5 = 2, the least that still lets it
--            bisect). The honest player answers everything in the next block except the leaf transition
--            proof, which it delivers 2 blocks after the request (standing in for the R12 cost of
--            reaching the disputed position and logging it). Its own uarch clock is 6 blocks.
--   drain    response_budget = 0 and no latency at all: every honest answer lands in the next block.
--            sybil1 joins promptly but answers its own seal late, draining its clock to 1 block
--            (charge_turn_time). The bracket is then sybil1 vs honest (sybil1 connects first).
--
-- Output lines parsed by test.lua:
--   CLOCK <level> <who> <allowance>
--   SEAL <block>                      (block at which the uarch leaf race starts)
--   PROOF_SENT <block>                (block at which the honest proof is received)
--   PROOF_REJECTED <block> <reason>
--   PROOF_ACCEPTED <block>
--   TRANSITION <settled|none>
--   ELIMINATED <level> <block>
--   UARCH_WINNER <who> <final>
--   WINNER <honest|dishonest|none>
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local prt = require("prt")
local prtu = require("prtu")
local run_with_game_server = require("game-test-server")
local keccak = cartesi.keccak256
local EVENTS = prtu.EVENTS

local mode = arg[1]
assert(mode == "control" or mode == "attack" or mode == "drain", "usage: scenario.lua control|attack|drain")

-- The real disputed transition: one uarch step of a tiny machine.
local machine <close> = cartesi.machine({ ram = { length = 4096 } })
local initial = machine:get_root_hash()
local logs = { step_log = machine:log_step_uarch() }
local after = machine:get_root_hash()
assert(cartesi.machine:verify_step_uarch(initial, logs.step_log) == after)
local false_final = keccak("false final")

local geometry = { mcycle_height = 3, uarch_height = 3, periods_per_input = 8, mcycles_per_period = 1 }

local function tree_of(leaves, height)
    local forest = hash_tree.frontier_forest(height, "keccak256")
    for i = 0, (1 << height) - 1 do
        hash_tree.frontier_forest_push_back(forest, leaves(i))
    end
    return prt.new_tree(height, 0, forest)
end
local function repeated(value, height)
    return tree_of(function()
        return value
    end, height)
end

local trees = {
    honest = { mcycle = repeated(after, 3), uarch = repeated(after, 3) },
    sybil1 = { mcycle = repeated(false_final, 3), uarch = repeated(false_final, 3) },
    sybil2 = {
        mcycle = repeated(false_final, 3),
        uarch = tree_of(function(i)
            return i == 0 and keccak("sybil2 leaf") or false_final
        end, 3),
    },
}
-- Names of the claims, per level (S1's uarch tree happens to equal C_d's mcycle tree).
local names = {
    mcycle = {
        [trees.honest.mcycle:get_root_hash()] = "C_h",
        [trees.sybil1.mcycle:get_root_hash()] = "C_d",
    },
    uarch = {
        [trees.honest.uarch:get_root_hash()] = "H",
        [trees.sybil1.uarch:get_root_hash()] = "S1",
        [trees.sybil2.uarch:get_root_hash()] = "S2",
    },
}

local function short(h)
    return h == after and "after" or (h == false_final and "false" or cartesi.tohex(h):sub(1, 10))
end

local server_ref
local honest_opts
-- Narration is replaced by machine-readable lines; nothing is written to disk.
for name in pairs(prtu.story) do
    prtu.story[name] = function() end
end
prtu.story.report_claims = function(tournament)
    for _, claim in ipairs(tournament.claims) do
        print(string.format("CLOCK %s %s %d", tournament.level, names[tournament.level][claim.computation_hash], claim.allowance))
    end
end
prtu.story.report_state_transition = function(_, _, _, obtained)
    print("TRANSITION " .. (obtained and ("settled " .. short(obtained)) or "none"))
end
prtu.story.report_uarch_result = function(_, winner)
    if winner then
        print(string.format("UARCH_WINNER %s %s", names.uarch[winner.computation_hash], short(winner.final_state_hash)))
    else
        print("UARCH_WINNER none none")
    end
end
local in_uarch = false
prtu.story.report_uarch_tournament = function()
    in_uarch = true
end
prtu.story.report_divergence = function(match)
    local level = in_uarch and "uarch" or "mcycle"
    print(string.format("SEALED %s %d %s=%d %s=%d", level, server_ref:get_time(),
        names[level][match.claims[1].computation_hash], match.claims[1].allowance,
        names[level][match.claims[2].computation_hash], match.claims[2].allowance))
end
prtu.story.report_timeout_win = function()
    print("TIMEOUT_WIN " .. server_ref:get_time())
end
prtu.story.report_match_eliminated = function(match)
    print(string.format("ELIMINATED match %d", server_ref:get_time()))
end
prtu.story.report_winner = function(winner)
    print("WINNER " .. (winner and names.mcycle[winner.computation_hash] or "none"))
    io.stdout:flush()
    os.exit(0)
end

-- Generic synthetic-claim handlers (the same responses prt.lua's honest player computes from its trees).
local function new_player(label, my, opts)
    local p = { label = label, trees = {} }
    local function delayed(self, delay, respond)
        if delay and delay > 1 then
            return prtu.schedule_response(self, self.block + delay, respond)
        end
        return respond()
    end
    p.event_handler = {
        input_added = function()
            return true
        end,
        epoch_sealed = function()
            return true
        end,
        commit_mcycle_claim = function(self)
            local t = my.mcycle
            self.trees[t:get_root_hash()] = t
            return {
                computation_hash_left = select(1, t:get_child_hashes(0, 3)),
                computation_hash_right = select(2, t:get_child_hashes(0, 3)),
                final_state_hash_proof = t:get_proof(7),
            }
        end,
        commit_uarch_claim = function(self)
            local t = my.uarch
            self.trees[t:get_root_hash()] = t
            return delayed(self, opts.uarch_join_delay, function()
                local l, r = t:get_child_hashes(0, 3)
                return { computation_hash_left = l, computation_hash_right = r, final_state_hash_proof = t:get_proof(7) }
            end)
        end,
        reveal_bisection = function(self, hash, position, height, other_left)
            local t = self.trees[hash]
            if not t then
                return "nothing"
            end
            local l, r = t:get_child_hashes(position, height)
            local child = (l ~= other_left) and position or position + (1 << (height - 1))
            local nl, nr = t:get_child_hashes(child, height - 1)
            return { turn_left_node = l, turn_right_node = r, turn_next_left_node = nl, turn_next_right_node = nr }
        end,
        seal_divergence = function(self, hash, position, other_left)
            local t = self.trees[hash]
            if not t then
                return "nothing"
            end
            local delay = (t == my.uarch) and opts.uarch_seal_delay or nil
            return delayed(self, delay, function()
                local l, r = t:get_child_hashes(position, 1)
                local response = { turn_left_node = l, turn_right_node = r }
                local leaf = position + ((l ~= other_left) and 0 or 1)
                if leaf ~= 0 then
                    response.agreed_state_hash_proof = t:get_proof(leaf - 1)
                end
                return response
            end)
        end,
        prove_state_transition = function(self)
            if not opts.prover then
                return true -- an acknowledgement, no proof
            end
            local at = self.block + (opts.proof_delay or 1)
            print("PROOF_SENT " .. at)
            return delayed(self, opts.proof_delay, function()
                return logs
            end)
        end,
        win_match_by_timeout = function(self, hash)
            local t = self.trees[hash]
            if not t or not opts.prover then
                return "nothing"
            end
            local l, r = t:get_child_hashes(0, t.height)
            return { computation_hash_left = l, computation_hash_right = r }
        end,
        eliminate_match = function()
            return "nothing"
        end,
        prove_outputs_merkle_root = function()
            return "nothing"
        end,
    }
    return p
end

honest_opts = { prover = true, proof_delay = (mode == "attack") and 2 or 1 }
local sybil1_opts = {}
if mode == "attack" then
    sybil1_opts.uarch_join_delay = 5
elseif mode == "drain" then
    -- Its uarch clock at the seal turn is 4 blocks: answer in the last block before the deadline.
    sybil1_opts.uarch_seal_delay = 3
end

local players
if mode == "drain" then
    -- sybil1 first, so it is claim 1 of the uarch match and seals at height 1.
    players = {
        new_player("sybil1", trees.sybil1, sybil1_opts),
        new_player("honest", trees.honest, honest_opts),
        new_player("sybil2", trees.sybil2, {}),
    }
else
    players = {
        new_player("honest", trees.honest, honest_opts),
        new_player("sybil1", trees.sybil1, sybil1_opts),
        new_player("sybil2", trees.sybil2, {}),
    }
end

run_with_game_server(prtu.protocol, function(server, run_client, wait_connections)
    server_ref = server
    -- Observe the leaf race: when it starts and why the honest proof was rejected.
    local request_first_valid = server.request_first_valid
    server.request_first_valid = function(self, subscriptions, event, arguments, accept)
        if event == EVENTS.prove_state_transition then
            local now = self:get_time()
            print("SEAL " .. now)
            -- Probe the referee's own validator with the valid log at the honest proof's arrival block.
            local at = now + honest_opts.proof_delay
            local ok, value = pcall(accept, logs, nil, at)
            print(string.format("PROBE %d %s", at, ok and ("accepted " .. short(value))
                or ("rejected " .. (tostring(value):match("([^:]+)$"):gsub("^%s+", "")))))
            local inner = accept
            accept = function(response, sender, received_at)
                local ok2, value2 = pcall(inner, response, sender, received_at)
                if ok2 and value2 then
                    print(string.format("PROOF_ACCEPTED %d %s", received_at, sender.label))
                end
                if not ok2 then
                    error(value2, 0)
                end
                return value2
            end
        elseif event == EVENTS.win_match_by_timeout then
            print("TIMEOUT_WIN_OFFERED " .. self:get_time())
        end
        return request_first_valid(self, subscriptions, event, arguments, accept)
    end
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
    prt.new_referee({
        geometry = geometry,
        initial_state_hash = initial,
        inputs = {},
        input_paths = {},
        max_allowance = 8,
        response_budget = mode == "drain" and 0 or 8,
    }):run(server)
end)
print("WINNER none")
