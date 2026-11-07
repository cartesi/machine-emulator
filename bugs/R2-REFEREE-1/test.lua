#!/usr/bin/env lua5.4
-- R2-REFEREE-1: at a sealed uarch leaf, the referee model gives the honest claim only the OPPONENT's
-- remaining clock to prove the transition, and never offers a timeout win. A Sybil with a short clock
-- (a late uarch join, or a clock drained by slow responses) therefore eliminates the honest uarch claim
-- together with itself, a second Sybil wins the uarch tournament, and the dishonest mcycle claim wins.
--
-- prt.lua settle_uarch_state_hash starts both clocks at the seal, accepts a proof only while
-- received_at < min(deadline_one, deadline_two), and otherwise eliminates both claims at the max. Deployed
-- Dave (MatchClocks.classifyTimeoutAt with two running clocks, which prt-bridge.lua relies on for
-- LeafMatchSealed) instead lets the longer clock win by timeout in [min, max), so the honest claim always
-- has its own A7-sized clock. Threat model: section 1 completeness failure (honest claim eliminated, a
-- dishonest claim wins), A7 (the honest proof window is sized by an adversary-chosen clock, not by the
-- honest claim's own clock), R4, section 5 (disagreement between the model and the deployed referee).
--
-- scenario.lua (see its header) runs the real referee model with a real uarch step log:
--   control: the honest proof arrives 1 block after the request; the honest claim must win (harness check).
--   attack:  S1 joins the uarch tournament 5 blocks late (clock 2); the honest proof arrives 2 blocks after
--            the request, while the honest claim's own clock still has 6 blocks.
--   drain:   response_budget 0, honest answers everything in the next block; S1 drains its own clock
--            to 1 block on its seal turn.
-- Correct behavior asserted: in attack and drain the honest claim C_h wins the epoch (as it would under
-- Dave's leaf-race rule, which this test also evaluates on the same clocks).
-- Exit 0: correct. Exit 1: defect present. Exit 2: harness error.

local function run(mode)
    local here = assert(io.popen("pwd")):read("l")
    local cmd = string.format(
        'd=$(mktemp -d) && cd "$d" && timeout 120 lua5.4 "%s/scenario.lua" %s 2>&1; s=$?; cd / && rm -rf "$d"; exit $s',
        here,
        mode
    )
    local p = assert(io.popen(cmd, "r"))
    local out = p:read("a")
    p:close()
    local r = { out = out, sealed = {} }
    for line in out:gmatch("[^\n]+") do
        local block, a, ca, b, cb = line:match("^SEALED uarch (%d+) (%S+)=(%d+) (%S+)=(%d+)$")
        if block then
            r.sealed[#r.sealed + 1] = { block = tonumber(block), [a] = tonumber(ca), [b] = tonumber(cb), first = a }
        end
        r.probe = r.probe or line:match("^PROBE %d+ (.*)$")
        r.proof_sent = r.proof_sent or tonumber(line:match("^PROOF_SENT (%d+)") or "")
        r.uarch_winner = line:match("^UARCH_WINNER (%S+ %S+)") or r.uarch_winner
        r.transition = r.transition or line:match("^TRANSITION (.*)$")
        r.winner = line:match("^WINNER (%S+)") or r.winner
    end
    return r
end

local function harness_error(msg, r)
    io.stderr:write(r and r.out or "", "\n")
    print("HARNESS ERROR: " .. msg)
    os.exit(2)
end

-- Dave's MatchClocks.classifyTimeoutAt for a sealed leaf (both clocks running from the seal instant).
-- A running sole survivor pays no deferred charge, so it wins while its remainder is positive.
local function dave_leaf_race(seal, allowance_one, allowance_two, current)
    local remaining_one = math.max(allowance_one - (current - seal), 0)
    local remaining_two = math.max(allowance_two - (current - seal), 0)
    if remaining_one > 0 and remaining_two > 0 then
        return "NONE"
    elseif remaining_one == 0 and remaining_two == 0 then
        return "ELIMINATE_BOTH"
    elseif remaining_one == 0 then
        return "TWO_WINS"
    else
        return "ONE_WINS"
    end
end

local control = run("control")
if control.winner ~= "C_h" or control.transition ~= "settled after" or control.probe ~= "accepted after" then
    harness_error("control run did not settle the real step log and make the honest claim win", control)
end

local failures = {}
for _, mode in ipairs({ "attack", "drain" }) do
    local r = run(mode)
    local leaf = r.sealed[1]
    if not leaf or not leaf.H or not leaf.S1 or not r.proof_sent or not r.winner then
        harness_error(mode .. " run did not reach the H vs S1 uarch leaf race", r)
    end
    local honest_one = leaf.first == "H"
    local dave_at_short_deadline = dave_leaf_race(
        leaf.block,
        honest_one and leaf.H or leaf.S1,
        honest_one and leaf.S1 or leaf.H,
        leaf.block + leaf.S1
    )
    local honest_wins_in_dave = dave_at_short_deadline == (honest_one and "ONE_WINS" or "TWO_WINS")
    print(
        string.format(
            "%s: leaf sealed at block %d with clocks H=%d S1=%d; honest proof at block %d (%d blocks, own clock %d): "
                .. "referee %s; uarch winner %s; epoch winner %s; Dave classifyTimeoutAt at block %d: %s",
            mode,
            leaf.block,
            leaf.H,
            leaf.S1,
            r.proof_sent,
            r.proof_sent - leaf.block,
            leaf.H,
            r.probe or "?",
            r.uarch_winner or "none",
            r.winner,
            leaf.block + leaf.S1,
            dave_at_short_deadline
        )
    )
    if not honest_wins_in_dave or r.proof_sent - leaf.block >= leaf.H then
        harness_error(mode .. " scenario does not give the honest claim a timeout win under Dave's rule", r)
    end
    if r.winner ~= "C_h" then
        failures[#failures + 1] = string.format(
            "%s: honest proof %d block(s) after the seal, within its own %d-block clock, rejected because S1 had %d; "
                .. "H and S1 both eliminated, %s wins the uarch tournament and %s wins the epoch",
            mode,
            r.proof_sent - leaf.block,
            leaf.H,
            leaf.S1,
            (r.uarch_winner or "none"):match("^(%S+)"),
            r.winner
        )
    end
end

if #failures > 0 then
    print(
        "FAIL: sealed uarch leaf bounds the honest proof by the opponent's clock with no timeout win "
            .. "(prt.lua settle_uarch_state_hash), so a short-clock Sybil eliminates the honest claim -- "
            .. table.concat(failures, "; ")
    )
    os.exit(1)
end
print("OK: the honest claim survives a short-clock opponent at a sealed uarch leaf")
os.exit(0)
