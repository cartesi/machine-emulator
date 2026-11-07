#!/usr/bin/env lua5.4
-- R1-REFEREE-1: a late Sybil re-post of the honest claim shortens the honest claim's clock to 1 block, so
-- the honest claim loses by timeout (doc/recipes/prt.lua partition_claims).
--
-- partition_claims walks the posters of a tournament in connection admission order (game-transport.lua
-- reply_less), and the first poster of a computation hash in that order fixes the merged claim's clock:
--   claim.allowance = allowance - (response.received_at - start_instant)
-- The manual says "Each claim's clock starts with the tournament's allowance, less the blocks between the
-- tournament's opening and the claim's joining" (as Dave does, where a commitment's clock starts at its
-- first join). A Sybil admitted before the honest player (section 7: Sybils, hold any claim including the
-- honest one, race and reorder transactions) can post the honest computation hash at the last joinable
-- block, and the honest claim then gets the Sybil's late clock instead of the clock of its earlier post.
-- With 1 block left the honest claim can never answer a turn (an answer lands at least one block after
-- the request, and must land before start + allowance), so the dishonest claim wins by timeout and its
-- fabricated final state is settled. That eliminates the honest claim (section 1 completeness failure;
-- section 2 Honest claim; A7 sized clocks) and settles a state the transition function does not define.
--
-- The test runs scenario.lua (real prt referee over game-test-server, synthetic claims; see its header):
--   control: the second connection re-posts D; the honest claim must win (harness sanity check).
--   attack:  the second connection is a Sybil that re-posts the honest claim at the last joinable block.
-- Correct behavior asserted in the attack run:
--   1. every claim's clock is the allowance less the blocks to its EARLIEST post (allowance + first
--      received block is the same for every claim in the bracket);
--   2. the honest claim wins and the settled final state is the honest one.
-- Exit 0: correct. Exit 1: defect present. Exit 2: harness error (control run did not behave).

local function run(mode)
    -- The referee writes its story files into the cwd, so run it in a scratch directory.
    local here = assert(io.popen("pwd")):read("l")
    local cmd = string.format(
        'd=$(mktemp -d) && cd "$d" && lua5.4 "%s/scenario.lua" %s 2>&1; s=$?; rm -rf "$d"; exit $s',
        here,
        mode
    )
    local p = assert(io.popen(cmd, "r"))
    local out = p:read("a")
    p:close()
    local claims, settled = {}, nil
    for line in out:gmatch("[^\n]+") do
        local who, hash, a, r, posters = line:match("^CLAIM (%S+) (%S+) allowance=(%-?%d+) first_received=(%-?%d+) posters=(%S+)")
        if who then
            claims[#claims + 1] =
                { who = who, hash = hash, allowance = tonumber(a), first = tonumber(r), posters = posters }
        end
        settled = line:match("^SETTLED (%S+)") or settled
    end
    return out, claims, settled
end

local function dump(tag, out)
    io.stderr:write("---- " .. tag .. " output ----\n" .. out .. "----\n")
end

local cout, cclaims, csettled = run("control")
if csettled ~= "HONEST" or #cclaims ~= 2 then
    dump("control", cout)
    print("HARNESS ERROR: control run did not settle the honest claim (got " .. tostring(csettled) .. ")")
    os.exit(2)
end

local out, claims, settled = run("attack")
if #claims ~= 2 or settled == nil or settled == "NONE" or settled == "UNKNOWN" then
    dump("attack", out)
    print("HARNESS ERROR: attack run produced no usable result (settled " .. tostring(settled) .. ")")
    os.exit(2)
end
io.write(out)

local failed = false
local honest_claim
-- allowance + first post block is tournament allowance + opening block for a correct clock, so it is
-- the same for every claim; a clock taken from a later post makes it smaller.
local base = -math.huge
for _, c in ipairs(claims) do
    base = math.max(base, c.allowance + c.first)
    if c.who == "honest" then
        honest_claim = c
    end
end
for _, c in ipairs(claims) do
    if c.allowance + c.first ~= base then
        failed = true
    end
end
if not honest_claim then
    dump("attack", out)
    print("HARNESS ERROR: no honest claim in the bracket")
    os.exit(2)
end
if failed then
    print(
        string.format(
            "FAIL: honest claim (posted by %s, first posted at block %d) got a clock of %d block(s), but its "
                .. "earliest post entitles it to %d; a late Sybil re-post in earlier admission order set it "
                .. "(partition_claims), so the honest claim %s and the settled final state is %s",
            honest_claim.posters,
            honest_claim.first,
            honest_claim.allowance,
            base - honest_claim.first,
            settled == "HONEST" and "survived" or "lost by timeout",
            settled
        )
    )
    os.exit(1)
end
if settled ~= "HONEST" then
    print("FAIL: the dishonest claim won the tournament after a Sybil re-posted the honest claim; settled " .. settled)
    os.exit(1)
end
print("OK: honest claim keeps the clock of its earliest post and wins the tournament")
os.exit(0)
