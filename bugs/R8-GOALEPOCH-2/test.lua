-- R8-GOALEPOCH-2: the deployed referee (Dave v3.0.0-alpha.7 DaveConsensus + rollups-contracts 3.0.0-alpha.10
-- Application) refuses a valid proof of an output that the valid template commits to, until epoch 0 is accepted.
--
-- Requirement (THREAT_MODEL.md section 2 "Valid template": "Its tx buffer holds the outputs Merkle root of every
-- output that the application accepted before it"; A5: "An outputs Merkle root is defined only for a settled
-- canonical state that waits at a manual yield with the accepted reason. A valid template is such a state." and
-- "Conversely, the referee accepts every output that the settled state commits to, whenever its valid proof is
-- presented. No party can make it stop accepting them.").
--
-- 1. Emulator: build a valid template from a configuration (bare-metal emit-output guest of the harness), deliver
--    one advance input (the guest emits it as output 0 and accepts with the updated outputs Merkle root R).
--    The machine is at an mcycle boundary, pristine uarch, accepted manual yield, tx buffer = R. Its root hash T
--    is the template hash. Write a Solidity fixture with T, R, output 0 and its proof, and the machine validity
--    proof (iflags_Y, htif_tohost, tx-buffer words) of T.
-- 2. Dave (released build, dave.sh): deploy with DaveAppFactory.newDaveApp(T, ...) and call
--    Application.validateOutput(output 0, proof) right after deployment and throughout epoch 0.
--    Controls: the fixture is consistent, and once epoch 0 (no inputs) settles on T, the referee's own
--    stageTournamentResult derives R from T and the same proof is accepted (a tampered output is refused).
-- Exit 1 if the valid proof is refused at deployment while the controls pass; 0 if accepted; 2 on setup errors.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local hash_tree = require("cartesi.hash-tree")
    local k = cartesi.keccak256

    ---------------------------------------------------------------- 1. the valid template
    local m <close> = harness.machine({
        ram = { length = 64 << 20, backing_store = { data_filename = harness.baremetal("emit-output") } },
    }, {})
    local function tohost()
        local v = m:read_reg("htif_tohost")
        return v >> 56, (v >> 48) & 0xff, (v >> 32) & 0xffff, v & 0xffffffff
    end
    local function expect_yield(br_want, cmd_want, reason_want, what)
        local br = m:run(math.maxinteger)
        local _, cmd, reason, len = tohost()
        if br ~= br_want or cmd ~= cmd_want or reason ~= reason_want then
            harness.setup_error(string.format("%s: break %d cmd %d reason %d", what, br, cmd, reason))
        end
        return len
    end
    local frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
    expect_yield(cartesi.BREAK_REASON_YIELDED_MANUALLY, cartesi.HTIF_YIELD_CMD_MANUAL,
        cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED, "genesis accept")
    if m:read_memory(cartesi.AR_CMIO_TX_BUFFER_START, 32) ~= hash_tree.frontier_get_root_hash(frontier) then
        harness.setup_error("genesis template does not hold the empty outputs root")
    end
    local request = harness.encode_advance({ index = 0, payload = "R8-GOALEPOCH-2: an output the template commits to" })
    m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, request, m:get_root_hash())
    local len = expect_yield(cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY, cartesi.HTIF_YIELD_CMD_AUTOMATIC,
        cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT, "output yield")
    local output = m:read_memory(cartesi.AR_CMIO_TX_BUFFER_START, len)
    hash_tree.frontier_push_back(frontier, k(output))
    expect_yield(cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY, cartesi.HTIF_YIELD_CMD_AUTOMATIC,
        cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT, "report yield")
    expect_yield(cartesi.BREAK_REASON_YIELDED_MANUALLY, cartesi.HTIF_YIELD_CMD_MANUAL,
        cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED, "accept after input")
    local R = m:read_memory(cartesi.AR_CMIO_TX_BUFFER_START, 32)
    if R ~= hash_tree.frontier_get_root_hash(frontier) then harness.setup_error("guest outputs root mismatch") end
    if m:read_reg("iflags_Y") == 0 or m:read_reg("uarch_cycle") ~= 0 or m:read_reg("uarch_halt") ~= 0 then
        harness.setup_error("template is not at an accepted manual yield with a reset uarch")
    end
    local T = m:get_root_hash()
    print("valid template: emit-output guest after one accepted input, mcycle " .. m:read_reg("mcycle"))
    print("  template hash T          0x" .. harness.hex(T))
    print("  outputs Merkle root R    0x" .. harness.hex(R) .. " (tx buffer; 1 output, " .. #output .. " bytes)")

    -- Output proof: index 0 of the height-63 outputs tree, siblings bottom-up (pristine subtrees).
    local out_sibs, z = {}, string.rep("\0", 32)
    for i = 1, cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT do
        out_sibs[i] = z
        z = k(z, z)
    end
    local node = k(output)
    for i = 1, #out_sibs do node = k(node, out_sibs[i]) end
    if node ~= R then harness.setup_error("output proof does not fold to R") end

    -- Machine validity proof words (data block + 59 siblings bottom-up, as LibLeafProof folds them).
    local function word_proof(addr)
        local wa = addr & ~31
        local p = m:get_proof(wa, 5)
        local data = m:read_memory(wa, 32)
        if p.target_hash ~= k(data) or p.root_hash ~= T or #p.sibling_hashes ~= 59 then
            harness.setup_error("unexpected proof shape at " .. wa)
        end
        local n = p.target_hash
        for i = 1, 59 do
            n = (((wa >> 5) >> (i - 1)) & 1) == 0 and k(n, p.sibling_hashes[i]) or k(p.sibling_hashes[i], n)
        end
        if n ~= T then harness.setup_error("machine proof does not fold to T at " .. wa) end
        return data, p.sibling_hashes
    end
    local iy_data, iy_sibs = word_proof(cartesi.machine:get_reg_address("iflags_Y"))
    local th_data, th_sibs = word_proof(cartesi.machine:get_reg_address("htif_tohost"))
    local tx_data, tx_sibs = word_proof(cartesi.AR_CMIO_TX_BUFFER_START)

    ---------------------------------------------------------------- fixture
    local function b32(s) return "0x" .. harness.hex(s) end
    local function arr(name, sibs)
        local t = { string.format("    function %s() internal pure returns (bytes32[] memory s) {", name),
            string.format("        s = new bytes32[](%d);", #sibs) }
        for i, h in ipairs(sibs) do t[#t + 1] = string.format("        s[%d] = %s;", i - 1, b32(h)) end
        t[#t + 1] = "    }"
        return table.concat(t, "\n")
    end
    local src = table.concat({
        "// Generated by bugs/R8-GOALEPOCH-2/test.lua from an emulator machine (do not edit).",
        "pragma solidity ^0.8.30;",
        "library GenesisOutputsFixture {",
        "    bytes32 constant TEMPLATE_HASH = " .. b32(T) .. ";",
        "    bytes32 constant OUTPUTS_MERKLE_ROOT = " .. b32(R) .. ";",
        "    bytes32 constant IFLAGS_Y_BLOCK = " .. b32(iy_data) .. ";",
        "    bytes32 constant HTIF_TOHOST_BLOCK = " .. b32(th_data) .. ";",
        "    bytes32 constant TX_BUFFER_BLOCK = " .. b32(tx_data) .. ";",
        '    function output() internal pure returns (bytes memory) { return hex"' .. harness.hex(output) .. '"; }',
        arr("outputSiblings", out_sibs),
        arr("iflagsYSiblings", iy_sibs),
        arr("htifTohostSiblings", th_sibs),
        arr("txBufferSiblings", tx_sibs),
        "}",
        "",
    }, "\n")
    local tmp = os.tmpname()
    local f <close> = assert(io.open(tmp, "w"))
    f:write(src)
    f:flush()

    ---------------------------------------------------------------- 2. Dave (released)
    local _, out = harness.sh("bash ./dave.sh " .. tmp .. " 2>&1")
    os.remove(tmp)
    local res = {}
    for line in out:gmatch("[^\n]+") do
        local st, name = line:match("^%[(%u+)[^%]]*%]%s+(test%w+)%(%)")
        if st then res[name] = st end
    end
    local function dump() io.stderr:write(out, "\n") end
    for _, c in ipairs({ "testControlFixtureConsistent", "testControlAcceptedOnceEpoch0Accepted" }) do
        if res[c] ~= "PASS" then
            dump()
            harness.setup_error("Dave control " .. tostring(c) .. " did not pass (" .. tostring(res[c]) .. ")")
        end
    end
    print("controls: fixture consistent; once epoch 0 (no inputs) is accepted on T, stageTournamentResult derived "
        .. "R from T with the emulator's machine validity proof and validateOutput accepts the same proof "
        .. "(tampered output refused)")
    for _, t in ipairs({ "testTemplateOutputAcceptedAtDeployment", "testTemplateOutputAcceptedThroughoutEpoch0" }) do
        if res[t] == nil then
            dump()
            harness.setup_error("Dave test " .. t .. " did not run")
        end
    end
    -- Show forge's log lines of the two requirement tests.
    local seen = {}
    for line in out:gmatch("[^\n]+") do
        if seen[line] then goto continue end
        seen[line] = true
        if line:match("^%[%u+") or (line:match("^%s+[%w%(%)_ ,%.:]+: ") and not line:match("^%s+Error:")) then
            print("  forge: " .. line)
        end
        ::continue::
    end
    local at_deploy = res.testTemplateOutputAcceptedAtDeployment == "PASS"
    local throughout = res.testTemplateOutputAcceptedThroughoutEpoch0 == "PASS"
    print("Dave: validateOutput(template output 0, valid proof) right after newDaveApp(T): "
        .. (at_deploy and "accepted" or "REFUSED (InvalidOutputsMerkleRoot(R))"))
    print("Dave: accepted at every epoch-0 checkpoint before acceptStagedTournamentResult(0): "
        .. (throughout and "yes" or "NO"))
    if not (at_deploy and throughout) then
        print("VIOLATION (A5): the referee refuses a valid proof of an output the valid template commits to "
            .. "until epoch 0 is accepted")
    end
    return harness.expect(at_deploy and throughout,
        "A5: the referee accepts every output the settled state (the valid template) commits to, whenever "
            .. "its valid proof is presented")
end)
