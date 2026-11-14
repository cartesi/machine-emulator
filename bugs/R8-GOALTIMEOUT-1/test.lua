-- R8-GOALTIMEOUT-1: the released Dave v3.0.0-alpha.7 response budget (G = 5 min = 25 blocks) is shorter than
-- Ethereum finality, so an honest root claim that acts only on finalized history is charged on every response and
-- loses by timeout after three forced matches (Sepolia constants of the released Deployment.s.sol).
--
-- Requirement (THREAT_MODEL.md):
--   A7  "The dispute constants and clocks leave room for the honest claim to play the logarithmic number of matches
--        that a tournament forces on it ... No rule of the referee may make the honest claim lose by timeout while
--        it acts within its own clock."
--   R4  "The honest operator observes the chain and submits its transactions within the dispute clocks."
--   s.4 "The honest operator acts only on history that its policy treats as final, such as finalized blocks."
--
-- dave.sh runs FinalityLagTimeout.t.sol (forge, vm.roll) on a throw-away copy of the harness's released Dave build:
--   testControlShallowDepthHonestWins        lag 4 blocks (< G): the same choreography ends with the honest claim
--                                            winning 3 forced matches and the root, never charged. Must PASS.
--   testFinalizedHonestSurvivesForcedMatches lag 64 blocks (shortest Ethereum finalization delay): asserts the
--                                            honest claim wins every forced match and the root.
-- Exit 1 if the requirement test fails for the reason claimed (an honest action refused for lack of clock), 0 if
-- it passes, 2 on setup errors (control failing, forge/build missing, unexpected failure).
local harness = require("harness")

harness.main(function()
    local ok, out = harness.sh("bash ./dave.sh")
    if not ok then
        io.stderr:write(out, "\n")
        harness.setup_error("dave.sh failed")
    end
    local res, reason = {}, {}
    for line in out:gmatch("[^\n]+") do
        local st, rest, name = line:match("^%[(%u+)(.-)%]%s+(test%w+)%(%)")
        if st and not res[name] then
            res[name] = st
            reason[name] = rest
        end
    end
    -- Echo forge's result lines and logs; of the per-response trace, keep only the first response of each match
    -- and the last ones before a refusal.
    for line in out:gmatch("[^\n]+") do
        if line:find("^%[%u+") or (line:find("^  %S") and not line:find("honest response"))
                or line:find("honest response 1 at") or line:find("honest response 2%d at") then
            print(line)
        end
    end
    print()

    local ctrl = "testControlShallowDepthHonestWins"
    local req = "testFinalizedHonestSurvivesForcedMatches"
    if res[ctrl] ~= "PASS" then
        io.stderr:write(out, "\n")
        harness.setup_error("control " .. ctrl .. " did not pass: the choreography is broken")
    end
    if res[req] == nil then
        io.stderr:write(out, "\n")
        harness.setup_error(req .. " did not run")
    end
    if res[req] == "FAIL" and not reason[req]:find("R8%-GOALTIMEOUT%-1") then
        io.stderr:write(out, "\n")
        harness.setup_error(req .. " failed for another reason:" .. reason[req])
    end
    return harness.expect(res[req] == "PASS",
        "A7/R4: an honest root claim acting on finalized history (lag 64 blocks) must not lose by timeout in the "
            .. "3 matches that 6 Sybil claims force on it under the released Dave clocks")
end)
