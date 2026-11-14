-- R7-MANTOURN-1: a seal at divergence leaf 0 accepts an agreed-state proof whatever it carries.
--
-- Requirement (THREAT_MODEL R3, section 4): conditions on a log or proof are validity conditions, and a log
-- with trailing data must be rejected; every count and hash a verifier receives was chosen to fool it.
-- At leaf 0 the agreed state is the tournament's initial hash, so the agreed-state proof has nothing to
-- hold: a seal that carries a non-empty proof there must be refused, as a proof with a surplus sibling is
-- refused past leaf 0.
--
-- Part 1, the PRT referee model (doc/recipes/prt.lua validate_seal_response).
-- Part 2, the deployed referee (Dave v3.0.0-alpha.7 Tournament.sealLeafMatch -> Match._requireAgreeState),
--         via a forge test (SealLeafZeroProof.t.sol) on the harness's released build (dave.sh).
-- Exit 1 if either accepts the junk proof at leaf 0 while its controls behave; 0 if both refuse; 2 on setup.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local prt = require("prt")
    local k = cartesi.keccak256
    local violations = {}

    ---------------------------------------------------------------- part 1: referee model
    local init = k("init")
    local a0, a1 = k("a0"), k("a1")
    local tournament = { height = 1, initial_state_hash = init }
    local c1 = { computation_hash = k(a0, a1), computation_hash_left = a0, computation_hash_right = a1 }
    local function seal(other_left, other_right, proof)
        local c2 = { computation_hash = k(other_left, other_right), computation_hash_left = other_left,
            computation_hash_right = other_right }
        local match = prt.new_match(c1, c2, 1)
        return pcall(prt.validate_seal_response, tournament, match,
            { turn_left_node = a0, turn_right_node = a1, agreed_state_hash_proof = proof })
    end
    -- Claim 2 differs at leaf 0 (b0) or only at leaf 1 (b1).
    local b0, b1 = k("b0"), k("b1")
    local function leaf1_proof(extra)
        local p = { target_address = 0, log2_target_size = 0, log2_root_size = 1, target_hash = a0,
            root_hash = c1.computation_hash, sibling_hashes = { a1 } }
        if extra then p.sibling_hashes[2] = extra end
        return p
    end

    local ok, d = seal(b0, a1, nil)
    if not (ok and d.leaf_index == 0 and d.agreed_state_hash == init) then
        harness.setup_error("model control: honest leaf-0 seal (no proof) refused: " .. tostring(d))
    end
    ok, d = seal(a0, b1, leaf1_proof())
    if not (ok and d.leaf_index == 1 and d.agreed_state_hash == a0) then
        harness.setup_error("model control: honest leaf-1 seal refused: " .. tostring(d))
    end
    ok = seal(a0, b1, leaf1_proof(k("trailing")))
    if ok then harness.setup_error("model control: leaf-1 seal with a surplus sibling accepted") end
    print("model controls: leaf-0 seal without proof accepted; leaf-1 honest proof accepted; "
        .. "leaf-1 proof with a surplus sibling refused")

    local junk = { target_address = 12345, log2_target_size = 7, log2_root_size = 3, target_hash = "junk",
        root_hash = "x", sibling_hashes = { "not", "a", "proof" } }
    ok, d = seal(b0, a1, junk)
    print(string.format("model: leaf-0 seal with a junk agreed-state proof (3 junk siblings): %s",
        ok and ("ACCEPTED, divergence at leaf " .. d.leaf_index) or ("refused: " .. tostring(d))))
    if ok then violations[#violations + 1] = "prt.lua validate_seal_response accepts a junk proof at leaf 0" end

    ---------------------------------------------------------------- part 2: Dave (released)
    local _, out = harness.sh("bash ./dave.sh")
    local res = {}
    for line in out:gmatch("[^\n]+") do
        local st, name = line:match("^%[(%u+)[^%]]*%]%s+(test%w+)%(%)")
        if st then res[name] = st end
    end
    for _, c in ipairs({ "testControlLeafZeroEmptyProofAccepted", "testControlLeafOneHonestProofAccepted",
        "testControlLeafOneTrailingWordRejected" }) do
        if res[c] ~= "PASS" then
            io.stderr:write(out, "\n")
            harness.setup_error("Dave control " .. c .. " did not pass")
        end
    end
    print("Dave controls: leaf-0 seal with empty proof accepted; leaf-1 honest proof accepted; "
        .. "leaf-1 proof with a trailing word refused (CommitmentProofWrongSize)")
    for _, t in ipairs({ "testLeafZeroOneTrailingWordRejected", "testLeafZeroJunkProofRejected" }) do
        if res[t] == nil then
            io.stderr:write(out, "\n")
            harness.setup_error("Dave test " .. t .. " did not run")
        end
        local words = t:find("OneTrailing") and 1 or 64
        print(string.format("Dave: sealLeafMatch at leaf 0 with a %d-word junk agreed-state proof: %s", words,
            res[t] == "PASS" and "refused" or "ACCEPTED"))
        if res[t] ~= "PASS" then
            violations[#violations + 1] = "Dave sealLeafMatch accepts a " .. words .. "-word junk proof at leaf 0"
        end
    end

    for _, v in ipairs(violations) do print("VIOLATION (R3 trailing data): " .. v) end
    return harness.expect(#violations == 0,
        "R3: a seal at leaf 0 must refuse an agreed-state proof that carries data")
end)
