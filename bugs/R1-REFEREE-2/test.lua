#!/usr/bin/env lua5.4
-- R1-REFEREE-2: the referee model accepts an output proof whose index has bit 63 set, so every settled
-- output is accepted a second time at index i - 2^63 (uint64 i + 2^63).
--
-- game-output.lua validate_output_response checks output_index == target_address, a leaf target, a
-- height-63 root equal to the settled outputs Merkle root, and the leaf hash, then calls
-- hash_tree.verify_slice. Nothing requires target_address < 2^63: roll_hash_up_tree reads only bits
-- 0..62 for a height-63 tree and verify_slice only checks alignment. A genuine proof for index i thus
-- also verifies with target_address = i | (1 << 63), which the PRT JSON schema carries intact
-- (output_index = "Default"). prt.lua wait_for_outputs deduplicates by output_index, so the aliased
-- index counts as a new output. Anyone may answer prove_output (EVERYONE), so any party can make the
-- referee accept a settled withdrawal twice. The outputs tree has no index 2^63: this accepts a node the
-- committed tree does not hold at the stated index (section 1 soundness failure; A5: an output is
-- accepted only at the output's index of the full-height outputs tree; section 4: proofs are
-- adversarial; R11: the referee, not the proof, fixes the index range of the tree).
--
-- scenario.lua runs the real referee model end to end (see its header):
--   control: the attacker re-sends the genuine index-0 response; it must be rejected (harness check).
--   attack:  the attacker sends the same proof with output_index = target_address = 0 | (1 << 63).
-- Correct behavior asserted in the attack run: every accepted output index is below 2^63 (a valid
-- leaf of the height-63 outputs tree), and output 0 is accepted exactly once.
-- Exit 0: correct. Exit 1: defect present. Exit 2: harness error.

local function run(mode)
    -- The referee writes its story files into the cwd, so run it in a scratch directory.
    local here = assert(io.popen("pwd")):read("l")
    local cmd = string.format(
        'd=$(mktemp -d) && cd "$d" && timeout 120 lua5.4 "%s/scenario.lua" %s 2>&1; s=$?; cd / && rm -rf "$d"; exit $s',
        here,
        mode
    )
    local p = assert(io.popen(cmd, "r"))
    local out = p:read("a")
    p:close()
    local accepted, winner, finish = {}, nil, nil
    for line in out:gmatch("[^\n]+") do
        local index, payload = line:match("^ACCEPTED (%-?%d+) (.*)$")
        if index then
            accepted[#accepted + 1] = { index = math.tointeger(tonumber(index)), payload = payload }
        end
        winner = line:match("^WINNER (%S+)") or winner
        finish = line:match("^END (.*)$") or finish
    end
    return { accepted = accepted, winner = winner, finish = finish, out = out }
end

local function harness_error(msg, r)
    io.stderr:write(r.out, "\n")
    print("HARNESS ERROR: " .. msg)
    os.exit(2)
end

local control = run("control")
if
    control.winner ~= "HONEST"
    or control.finish ~= "second offer rejected"
    or #control.accepted ~= 1
    or control.accepted[1].index ~= 0
then
    harness_error("control run did not accept output 0 once and reject its duplicate", control)
end

local attack = run("attack")
if attack.winner ~= "HONEST" or not attack.finish or #attack.accepted < 1 or attack.accepted[1].index ~= 0 then
    harness_error("attack run did not settle the honest state and accept the genuine output 0", attack)
end

local failed = false
local same_leaf = 0
for _, o in ipairs(attack.accepted) do
    print(string.format("referee accepted output_index=%d (uint64 %s) payload=%q", o.index,
        string.format("%u", o.index):gsub("^%-", ""), o.payload))
    if not math.ult(o.index, 1 << 63) then
        failed = true
        print(string.format("FAIL: referee accepted output_index %d (uint64 0x%016x), outside the 2^63-leaf outputs tree; "
            .. "its proof is the genuine proof of output %d with bit 63 set", o.index, o.index, o.index & ~(1 << 63)))
    end
    if o.index & ~(1 << 63) == 0 then
        same_leaf = same_leaf + 1
    end
end
if same_leaf > 1 then
    failed = true
    print(string.format("FAIL: the settled output at index 0 (%q) was accepted %d times "
        .. "(once at index 0, again at the aliased index -2^63)", attack.accepted[1].payload, same_leaf))
end
if failed then
    print("R1-REFEREE-2: game-output.validate_output_response does not range-check output_index/target_address "
        .. "< 2^63, so prt.lua wait_for_outputs accepts output 0 again at index -2^63 (double execution of a withdrawal)")
    os.exit(1)
end
print("OK: aliased output index rejected; output 0 accepted once (" .. attack.finish .. ")")
os.exit(0)
