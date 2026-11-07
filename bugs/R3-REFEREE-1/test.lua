#!/usr/bin/env lua5.4
-- R3-REFEREE-1: the referee model's narration runs inline on its fatal coroutine and raises on
-- adversary-chosen data, so one accepted voucher proof, or one Sybil announcing a non-string label,
-- terminates the referee for good.
--
-- (a) prt.lua wait_for_outputs accepts any output whose proof verifies against the settled outputs
--     root (game-output.validate_output_response checks only the proof and keccak(output_data)), then
--     calls prtu.story.report_output(output) outside any pcall. report_output decodes every output as
--     Notice(bytes payload) and raises "function selector mismatch" on a Voucher(address,uint256,bytes)
--     (the encoding machine-guest-tools emits for vouchers). game-transport's dispatcher turns any
--     coroutine error into a fatal error, so the referee dies and no further output of the settled state
--     can ever be accepted. The manual says the referee "waits for output proofs indefinitely".
-- (b) game-transport announce stores message.label of any JSON type. open_mcycle_tournament calls
--     story.report_claims, whose table.concat over the posters' labels raises on label = true. A Sybil
--     (section 7) that announces {"role":"player","label":true} and posts any valid claim kills the
--     referee before the first match, so the epoch never settles. The manual says labels "never
--     influence protocol state or ordering".
-- Threat model: A5 (outputs accepted through a valid proof against the settled root), section 5
-- (disagreement between the referee model and the manual's normative model), section 7 (Sybils),
-- section 8 (manual contradiction). Goal of section 1 not broken: referee liveness / output availability.
--
-- scenario.lua runs the real referee model end to end over game-test-server (see its header):
--   notice / label_string are controls that must settle the honest state and accept both outputs.
--   voucher / label_true are the attacks.
-- Correct behavior asserted in the attacks: the honest claim wins, the referee survives, and both outputs
-- of the settled state are accepted (scenario prints "END all outputs accepted" and exits 0).
-- Exit 0: correct. Exit 1: defect present. Exit 2: harness error (a control run did not behave).

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
    local _, _, status = p:close()
    local r = { out = out, status = status, accepted = {}, admitted = false }
    for line in out:gmatch("[^\n]+") do
        local index = line:match("^ACCEPTED (%-?%d+)$")
        if index then
            r.accepted[#r.accepted + 1] = math.tointeger(tonumber(index))
        end
        r.winner = line:match("^WINNER (%S+)") or r.winner
        r.finish = line:match("^END (.*)$") or r.finish
        r.admitted = r.admitted or line == "CLAIMS_ADMITTED"
        -- The first line of the rethrown traceback carries the coroutine's error message.
        r.err = r.err or line:match("^lua5%.4: (.*)$")
    end
    return r
end

local function ok(r)
    return r.status == 0 and r.winner == "HONEST" and r.finish == "all outputs accepted" and #r.accepted == 2
end

for _, control in ipairs({ "notice", "label_string" }) do
    local r = run(control)
    if not ok(r) then
        io.stderr:write(r.out, "\n")
        print("HARNESS ERROR: control run '" .. control .. "' did not settle the honest state and accept both outputs")
        os.exit(2)
    end
end

local failed = false

local v = run("voucher")
if ok(v) then
    print("OK voucher: referee accepted the voucher (output 0) and then the notice (output 1)")
else
    if not (v.winner == "HONEST" and v.accepted[1] == 0) then
        io.stderr:write(v.out, "\n")
        print("HARNESS ERROR: voucher run did not settle the honest state and accept the voucher proof")
        os.exit(2)
    end
    failed = true
    print(string.format(
        "FAIL voucher: referee accepted the valid proof of voucher output 0, then died in story.report_output "
            .. "(exit %s: %s); output 1 of the settled state can never be accepted",
        tostring(v.status),
        tostring(v.err)
    ))
end

local l = run("label_true")
if ok(l) then
    print("OK label_true: a Sybil announcing label=true did not affect the referee")
else
    if not l.admitted then
        io.stderr:write(l.out, "\n")
        print("HARNESS ERROR: label_true run did not reach claim admission")
        os.exit(2)
    end
    failed = true
    print(string.format(
        "FAIL label_true: a Sybil announcing {\"role\":\"player\",\"label\":true} with a valid claim killed the "
            .. "referee in story.report_claims before any match (exit %s: %s); the epoch never settles",
        tostring(l.status),
        tostring(l.err)
    ))
end

if failed then
    print("R3-REFEREE-1: referee narration (prtu.story.report_output / report_claims) raises on adversary-chosen "
        .. "data inside the referee coroutine, and game-transport makes any such error fatal to the referee")
    os.exit(1)
end
print("OK: referee survives vouchers and non-string labels")
os.exit(0)
