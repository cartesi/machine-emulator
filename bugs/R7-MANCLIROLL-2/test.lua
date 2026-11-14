-- R7-MANCLIROLL-2: the manual's shortcut for a uarch cycle computation hash in a later input
-- ("begin_epoch:false with next_input_offset ... starts there", "needs no epoch files") aborts with
-- "outputs Merkle root mismatch" and prints no claim whenever the application accepted an output before that
-- input.
--
-- Asserted requirement: THREAT_MODEL R4 "From any reachable state, at the position where it is reached, the
-- honest operator can always compute the claim", applied to the cartesi-machine CLI as a tool that computes
-- claims (section 3), and section 8 "A contradiction between the manual and the behavior on a security-relevant
-- point ... takes the severity it would have if the manual were right". doc/README.md ("Computation hashes"):
-- "A period in a later input does not require running the epoch from its start. Given a machine at the state
-- that receives that input, begin_epoch:false with next_input_offset set to the input's zero-based offset in the
-- epoch, counting rejected inputs, starts there."
--
-- Guest: the harness baremetal-template (emit-output.c: every advance payload becomes one output and one report,
-- and the guest accepts with the updated outputs Merkle root, i.e. a correctly designed application). Payload
-- "R" makes it reject.
--
-- Steps (all CLI runs use the manual's server form: --remote-spawn --remote-shutdown, default revert mode fork):
--   ref     from the template, inputs 0..1, begin_epoch:true: uarch hash of period 2^38+100000 (input 1, after
--           its stop) -> H_ref.
--   store   from the template, input 0 only, --store=after0: the machine at the state that receives input 1.
--   control the shortcut with check_outputs_merkle_root:false must print H_ref (validates the setup).
--   control2 the same shortcut, exactly as documented, when input 0 was REJECTED (no output accepted before
--           input 1) must exit 0 and print the reference hash of that case (validates the command form).
--   target  the shortcut exactly as documented (begin_epoch:false,next_input_offset:1, no epoch files) after
--           input 0 was ACCEPTED with one output: must exit 0 and print H_ref.
-- On audit/prt2 the target exits 1 with "outputs Merkle root mismatch at input 1" and prints no hash.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local CLI = assert(os.getenv("CARTESI_MACHINE"), "CARTESI_MACHINE not set")
    local CONFIGS = assert(os.getenv("HARNESS_CONFIGS"), "HARNESS_CONFIGS not set")
    local TEMPLATE = CONFIGS .. "/baremetal-template/machine"
    local LOG2_PERIOD = 10
    local PERIOD = (1 << (48 - LOG2_PERIOD)) + 100000 -- input 1, in the padded tail after it stops
    local UARCH = string.format("--uarch-cycle-computation-hash=log2_mcycle_period:%d,mcycle_period_index:%d",
        LOG2_PERIOD, PERIOD)
    local R = "--no-init-splash --remote-spawn --remote-shutdown"

    local f = io.open(TEMPLATE .. "/config.json", "r")
    if not f then harness.setup_error("missing " .. TEMPLATE .. " (run bugs/harness/configs/make-configs.sh)") end
    f:close()

    local tmp = io.popen("mktemp -d"):read("l")
    if not tmp or tmp == "" then harness.setup_error("mktemp failed") end
    local function cleanup() os.execute("rm -rf '" .. tmp .. "'") end
    local function setup_error(msg)
        cleanup()
        harness.setup_error(msg)
    end

    local function write(path, data)
        local fh = assert(io.open(path, "wb"))
        fh:write(data)
        fh:close()
    end

    -- Run the CLI in a fresh directory holding the given inputs; return exit ok, printed uarch hash, output.
    local function cli(name, inputs, args)
        local dir = tmp .. "/" .. name
        assert(os.execute("mkdir -p '" .. dir .. "'"))
        for i, payload in pairs(inputs) do
            write(string.format("%s/input-%d.bin", dir, i), payload)
        end
        local ok, out = harness.sh(string.format("cd '%s' && %s %s %s 2>&1", dir, CLI, R, args))
        local hash = out:match("Uarch cycle computation hash: (0x%x+)")
        return ok, hash, out
    end

    local function last_lines(out, n)
        local lines = {}
        for l in out:gmatch("[^\n]+") do
            if l ~= "" and not l:match("^Cycles") then lines[#lines + 1] = l end
        end
        return table.concat(lines, "\n", math.max(1, #lines - n + 1))
    end

    -- Case runner: inputs[0], inputs[1]; returns ok, hash of the shortcut (and with check off), ref hash.
    local function case(tag, inputs, extra)
        local ok, ref, out = cli(tag .. "-ref", inputs, string.format(
            "--load='%s' --cmio-advance-state=input_file_index_begin:0,input_file_index_end:2 %s", TEMPLATE, UARCH))
        if not ok or not ref then setup_error(tag .. ": reference run failed:\n" .. last_lines(out, 12)) end
        local after0 = tmp .. "/" .. tag .. "-after0"
        ok, _, out = cli(tag .. "-store", { [0] = inputs[0] }, string.format(
            "--load='%s' --cmio-advance-state=input_file_index_begin:0,input_file_index_end:1 --store='%s'",
            TEMPLATE, after0))
        if not ok then setup_error(tag .. ": storing the machine after input 0 failed:\n" .. last_lines(out, 12)) end
        -- the stored machine must be at the state that receives input 1: an rx-accepted manual yield
        do
            local m <close> = cartesi.machine(after0, {})
            if not m:read_reg("iflags_Y") or m:read_reg("iflags_Y") == 0
                or m:read_reg("htif_tohost_reason") ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
                setup_error(tag .. ": stored machine is not waiting at an rx-accepted manual yield")
            end
        end
        local shortcut = string.format(
            "--load='%s' --cmio-advance-state=input_file_index_begin:1,input_file_index_end:2,"
                .. "begin_epoch:false,next_input_offset:1%s %s",
            after0, extra or "", UARCH)
        local sok, shash, sout = cli(tag .. "-shortcut", { [1] = inputs[1] }, shortcut)
        return ref, sok, shash, sout, after0
    end

    -- control2: input 0 rejected, so no output is accepted before input 1; the documented command must work
    local ref_r, ok_r, hash_r, out_r = case("rejected", { [0] = "R", [1] = "second-input" })
    print(string.format("control2 (input 0 rejected): reference %s, shortcut exit %s, hash %s", ref_r,
        ok_r and "0" or "nonzero", tostring(hash_r)))
    if not ok_r or hash_r ~= ref_r then
        setup_error("control2: the documented shortcut fails even without prior outputs:\n" .. last_lines(out_r, 12))
    end

    -- input 0 accepted with one output
    local inputs = { [0] = "first-input-with-output", [1] = "second-input" }
    local ref, ok, hash, out, after0 = case("accepted", inputs)
    print(string.format("reference (from template, inputs 0..1, begin_epoch:true): %s", ref))

    -- control: same shortcut with the host outputs-root check disabled must give the reference hash
    local cok, chash, cout = cli("control", { [1] = inputs[1] }, string.format(
        "--load='%s' --cmio-advance-state=input_file_index_begin:1,input_file_index_end:2,"
            .. "begin_epoch:false,next_input_offset:1,check_outputs_merkle_root:false %s",
        after0, UARCH))
    print(string.format("control (shortcut + check_outputs_merkle_root:false): exit %s, hash %s",
        cok and "0" or "nonzero", tostring(chash)))
    if not cok or chash ~= ref then
        setup_error("control: shortcut with the check disabled does not reproduce the reference:\n"
            .. last_lines(cout, 12))
    end

    print(string.format("target (documented shortcut after an accepted output): exit %s, hash %s",
        ok and "0" or "nonzero", tostring(hash)))
    if not ok then print("  CLI error: " .. (out:match("lua5%.4: ([^\n]+)") or last_lines(out, 3))) end
    cleanup()
    return harness.expect(ok and hash == ref,
        "R4 / doc/README.md: the documented uarch computation-hash shortcut (begin_epoch:false,next_input_offset) "
            .. "from the machine that receives input 1 must compute the claim " .. ref)
end)
