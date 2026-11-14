-- R8-GOALOUTPUT-1: a voucher that a correctly designed application commits to, in response to an input the
-- InputBox accepts, cannot be executed by the deployed referee within one Ethereum transaction.
--
-- 1. Boots Linux with the manual's rootfs (doc/recipes/rootfs-docs.ext2) running the manual's own libcmt example
--    application `/home/dapp/puppet` ("voucher:<data> -> cmt_rollup_emit_voucher(msg_sender, 0, data), accept").
-- 2. Delivers two advance-state inputs: input 0 is "voucher:" followed by data, sized so that the ABI-encoded
--    EvmAdvance is exactly CanonicalMachine.INPUT_MAX_SIZE (65536 bytes, the largest input the pinned InputBox
--    accepts); input 1 is "voucher:hello" (control). The guest accepts both and the test checks that the
--    outputs Merkle root in the tx buffer commits to the two emitted vouchers (index 0 and 1).
-- 3. Runs a forge test (forge/test/ExecuteOutput.t.sol) against the released Application artifact of the pinned
--    Dave build (cartesi-rollups-contracts 3.0.0-alpha.10), whose outputs-root validator accepts exactly that
--    root: the control checks that both proofs are valid, that the large voucher executes with unlimited gas and
--    that the small one executes within one transaction; the assertion requires the large voucher to execute
--    within the gas one transaction may carry (EIP-7825: 2^24 = 16,777,216, minus the intrinsic calldata gas).
--
-- Exit 1: the large committed voucher cannot be executed within one transaction (bug present).
-- Exit 0: it can (contract fixed), or the guest no longer commits to such a voucher (a documented and enforced
--         output-size bound).
-- Exit 2: setup error (boot, forge build, control failed).
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local MAX = math.maxinteger
    local INPUT_MAX_SIZE = 1 << 16 -- CanonicalMachine.INPUT_MAX_SIZE of cartesi-rollups-contracts 3.0.0-alpha.10
    local here = harness.REPO .. "/bugs/R8-GOALOUTPUT-1"
    local artifact = harness.WORK .. "/dave/released/cartesi-rollups/contracts/out/Application.sol/Application.json"
    local forge_std = harness.WORK .. "/dave/released/cartesi-rollups/contracts/dependencies/forge-std-1.9.6/src/"
    local forge = harness.WORK .. "/foundry/bin/forge"
    for _, p in ipairs({ artifact, forge_std .. "Test.sol", forge, os.getenv("LINUX_IMAGE"),
        os.getenv("ROOTFS_DOCS_IMAGE") }) do
        local f = io.open(p, "rb")
        if not f then harness.setup_error("missing " .. p) end
        f:close()
    end

    local ok, tmp = harness.sh("mktemp -d")
    if not ok then harness.setup_error("mktemp failed") end
    tmp = tmp:gsub("%s+$", "")
    local function cleanup()
        if os.getenv("KEEP_TMP") then
            io.stderr:write("kept " .. tmp .. "\n")
        else
            os.execute("rm -rf '" .. tmp .. "'")
        end
    end
    local function write(name, data)
        local f = assert(io.open(tmp .. "/goal/" .. name, "wb"))
        f:write(data)
        f:close()
    end
    os.execute("mkdir -p '" .. tmp .. "/goal' '" .. tmp .. "/forge/test'")

    -- 1. the manual's puppet application, booted as a rolling template
    local cfg = {
        ram = { length = 0x8000000, backing_store = { data_filename = os.getenv("LINUX_IMAGE") } },
        dtb = { entrypoint = "/home/dapp/puppet" },
        flash_drive = { { backing_store = { data_filename = os.getenv("ROOTFS_DOCS_IMAGE") } } },
    }
    local m <close> = cartesi.machine(cfg, { console = { output_destination = "to_null" } })
    local outputs
    local function run_to_manual_yield()
        outputs = {}
        while true do
            local br = m:run(MAX)
            if br == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
                local _, reason, data = m:receive_cmio_request()
                if reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT then outputs[#outputs + 1] = data end
            elseif br ~= cartesi.BREAK_REASON_CONSOLE_OUTPUT and br ~= cartesi.BREAK_REASON_YIELDED_SOFTLY then
                if br ~= cartesi.BREAK_REASON_YIELDED_MANUALLY then
                    cleanup()
                    harness.setup_error("no manual yield, break reason " .. tostring(br))
                end
                local _, reason, data = m:receive_cmio_request()
                return reason, data
            end
        end
    end
    local reason = run_to_manual_yield()
    if reason ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
        cleanup()
        harness.setup_error("puppet did not reach its first rx-accepted yield")
    end
    io.stderr:write(string.format("puppet template ready at mcycle %d\n", m:read_reg("mcycle")))

    -- 2. inputs: the largest one the InputBox accepts, carrying a voucher request, then a small control
    local dest = harness.unhex("00000000000000000000000000000000000c0ffe")
    local function data_of(n) -- deterministic, mostly nonzero bytes
        local t = {}
        for i = 1, n do t[i] = string.char(0x41 + (i * 7) % 26) end
        return table.concat(t)
    end
    local big_payload_len = ((INPUT_MAX_SIZE - 4 - 9 * 32) // 32) * 32
    local payloads = { "voucher:" .. data_of(big_payload_len - #"voucher:"), "voucher:hello" }
    local committed = {}
    local root
    for i, payload in ipairs(payloads) do
        local input = harness.encode_advance({ msg_sender = dest, index = i - 1, payload = payload })
        if #input > INPUT_MAX_SIZE then
            cleanup()
            harness.setup_error("input larger than the InputBox accepts")
        end
        m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, m:get_root_hash())
        local r, data = run_to_manual_yield()
        io.stderr:write(string.format("input %d: %d bytes (InputBox limit %d), manual yield reason %d, %d output(s)%s\n",
            i - 1, #input, INPUT_MAX_SIZE, r, #outputs,
            #outputs > 0 and string.format(", output bytes %d", #outputs[1]) or ""))
        if r ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            cleanup()
            if i == 1 then
                io.stderr:write("the application no longer commits to the large voucher (input rejected)\n")
                return true
            end
            harness.setup_error("control input not accepted")
        end
        for _, o in ipairs(outputs) do committed[#committed + 1] = o end
        root = data
    end
    if #committed ~= 2 then
        cleanup()
        if #committed == 1 then
            io.stderr:write("the application no longer commits to the large voucher (no output emitted)\n")
            return true
        end
        harness.setup_error("expected two committed vouchers, got " .. #committed)
    end
    local voucher_sel = cartesi.keccak256("Voucher(address,uint256,bytes)"):sub(1, 4)
    for i, o in ipairs(committed) do
        if o:sub(1, 4) ~= voucher_sel then
            cleanup()
            harness.setup_error("output " .. (i - 1) .. " is not a Voucher")
        end
    end

    -- outputs tree of height 63 with two leaves; siblings of each leaf; check the root against the tx buffer
    local zero = { string.rep("\0", 32) }
    for h = 1, 63 do zero[h + 1] = cartesi.keccak256(zero[h], zero[h]) end
    local leaf = { cartesi.keccak256(committed[1]), cartesi.keccak256(committed[2]) }
    local function siblings(idx)
        local s = { leaf[2 - idx] }
        for h = 1, 62 do s[#s + 1] = zero[h + 1] end
        return s
    end
    local computed = cartesi.keccak256(leaf[1], leaf[2])
    for h = 1, 62 do computed = cartesi.keccak256(computed, zero[h + 1]) end
    if #root ~= 32 or computed ~= root then
        cleanup()
        harness.setup_error("tx-buffer root does not commit to the two emitted vouchers")
    end
    io.stderr:write("settled outputs Merkle root (tx buffer) " .. cartesi.tohex(root) .. " commits to both vouchers\n")
    write("root.bin", root)
    for idx = 0, 1 do
        write("output-" .. idx .. ".bin", committed[idx + 1])
        write("siblings-" .. idx .. ".bin", table.concat(siblings(idx)))
    end
    write("count.txt", "2")
    write("big.txt", "0")
    write("small.txt", "1")

    -- 3. forge project in the temp dir
    os.execute(string.format("cp '%s/forge/test/ExecuteOutput.t.sol' '%s/forge/test/'", here, tmp))
    local toml = assert(io.open(tmp .. "/forge/foundry.toml", "w"))
    toml:write(string.format([[
[profile.default]
src = "test"
test = "test"
out = "out"
libs = []
remappings = ["forge-std/=%s"]
solc_version = "0.8.30"
offline = true
evm_version = "prague"
gas_limit = "18446744073709551615"
fs_permissions = [{ access = "read", path = "%s" }, { access = "read", path = "%s" }]
]], forge_std, tmp .. "/goal", harness.WORK .. "/dave/released/cartesi-rollups/contracts/out"))
    toml:close()
    local env = string.format("GOAL_DIR='%s/goal' APPLICATION_ARTIFACT='%s' FOUNDRY_DISABLE_NIGHTLY_WARNING=1 ",
        tmp, artifact)
    local function forge_test(match)
        local okf, out = harness.sh(string.format("cd '%s/forge' && %s '%s' test --offline -vv --match-test '%s' 2>&1",
            tmp, env, forge, match))
        io.stderr:write(out, "\n")
        return okf, out
    end
    local okc, outc = forge_test("test_control")
    if not okc or not outc:find("%[PASS%] test_control") then
        cleanup()
        harness.setup_error("forge control failed")
    end
    local okr, outr = forge_test("test_large_voucher_executes_within_one_transaction")
    cleanup()
    if okr and outr:find("%[PASS%] test_large_voucher") then return true end
    if outr:find("%[FAIL[^\n]*test_large_voucher") then
        return harness.expect(false, "A5: the referee must accept (execute) every output the settled state "
            .. "commits to, whenever its valid proof is presented, within the chain's per-transaction limits")
    end
    harness.setup_error("forge test did not report PASS or FAIL")
end)
