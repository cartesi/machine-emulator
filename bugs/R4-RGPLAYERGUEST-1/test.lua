-- R4-RGPLAYERGUEST-1: the cartesi-machine CLI cannot compute an epoch's computation hash when the guest accepts
-- an input with an outputs-root length (yield DATA) other than 32.
--
-- Asserted requirement (THREAT_MODEL R4, section 8): from any reachable state the honest operator can always
-- compute the claim, for every guest, whether or not its application is correctly designed. The CLI's
-- --mcycle-computation-hash / --uarch-cycle-computation-hash options are a tool that computes claims.
--
-- Cases (same template, one input each):
--   control  input "a": guest accepts with the empty outputs root and DATA 32 (correctly designed)
--   target   input "z": guest writes the same root to the tx buffer and accepts with DATA 0
-- For each case the CLI must exit 0 and write an mcycle computation hash equal to the claim root that the PRT
-- player (prt.new_forked_player + commit_mcycle_claim) computes for the same template and input. The control
-- validates the comparison (a mismatch there is a setup error, exit 2). The uarch-cycle computation hash of
-- period 0 is run too and reported, but is not asserted: the CLI writes that hash before the abort (it then
-- exits 1), so only the mcycle-level claim is shown to be missing.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local hash_tree = require("cartesi.hash-tree")
    local fs = require("cartesi.filesystem")
    local prt = require("prt")

    local HARNESS = assert(os.getenv("HARNESS"), "HARNESS not set")
    local CLI = assert(os.getenv("CARTESI_MACHINE"), "CARTESI_MACHINE not set")
    local LOG2_PERIOD = 10

    local tmp = io.popen("mktemp -d"):read("l")
    if not tmp or tmp == "" then harness.setup_error("mktemp failed") end
    local function cleanup() os.execute("rm -rf '" .. tmp .. "'") end
    local function setup_error(msg)
        cleanup()
        harness.setup_error(msg)
    end

    -- 1. build the guest and store its template at its first rx-accepted manual yield
    local ok = harness.sh(string.format("'%s/baremetal/build.sh' -o '%s/guest.bin' guest.c > '%s/build.log' 2>&1",
        HARNESS, tmp, tmp))
    if not ok then setup_error("guest build failed:\n" .. (harness.read_file(tmp .. "/build.log") or "")) end
    local template = tmp .. "/template"
    local initial_hash
    do
        local m <close> = cartesi.machine({
            ram = { length = 64 << 20, backing_store = { data_filename = tmp .. "/guest.bin" } },
        })
        local r = m:run(cartesi.MCYCLE_MAX)
        if r ~= cartesi.BREAK_REASON_YIELDED_MANUALLY
            or m:read_reg("htif_tohost_reason") ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            setup_error("template did not reach an rx-accepted manual yield")
        end
        m:store(template)
        initial_hash = m:get_root_hash()
    end

    -- 2. reference claim: the PRT player on the same template and input
    local function player_root(input)
        local geometry = prt.new_geometry(LOG2_PERIOD)
        local player = prt.new_forked_player({
            initial_state_hash = initial_hash,
            machine_directory = template,
            geometry = geometry,
            inputs = { input },
        }, "honest")
        local anomalies = {}
        player.anomaly_handler = function(kind, msg) anomalies[#anomalies + 1] = kind .. " " .. tostring(msg) end
        local input_path = tmp .. "/player-input.bin"
        fs.write_file(input, input_path)
        player.event_handler.input_added(player, 0, input_path)
        repeat until not player.event_handler.idle(player)
        player.event_handler.epoch_sealed(player, 1)
        player.event_handler.commit_mcycle_claim(player)
        return hash_tree.frontier_forest_get_root_hash(player.mcycle_forest), anomalies
    end

    -- 3. the CLI, as an operator computing its claim (revert-mode stored, a mode documented for operators)
    local function cli(case, input, hash_option)
        local dir = string.format("%s/%s-%s", tmp, case, hash_option:match("^%-%-(%a+)"))
        assert(os.execute(string.format("mkdir -p '%s' && cp -r '%s' '%s/m'", dir, template, dir)))
        fs.write_file(input, dir .. "/input-0.bin")
        local cmd = string.format("cd '%s' && %s --load=m,sharing:all --revert-mode=stored "
            .. "--cmio-advance-state=input:input-%%i.bin,input_file_index_begin:0,input_file_index_end:1,"
            .. "check_outputs_merkle_root:false %s,filename:hash.bin > out.txt 2>&1", dir, CLI, hash_option)
        local status = os.execute(cmd)
        local out = harness.read_file(dir .. "/out.txt") or ""
        local h = io.open(dir .. "/hash.bin", "rb")
        local hash = h and h:read("a")
        if h then h:close() end
        return status == true, hash, out
    end
    local function last_lines(s, n)
        local lines = {}
        for l in s:gmatch("[^\n]+") do
            if not l:find("^%s*%[C%]") and not l:find("^stack traceback") and not l:find("^%s+/") then
                lines[#lines + 1] = l
            end
        end
        return table.concat(lines, "\n    ", math.max(1, #lines - n + 1))
    end

    local MCH = "--mcycle-computation-hash=log2_mcycle_period:" .. LOG2_PERIOD
    local UCH = "--uarch-cycle-computation-hash=log2_mcycle_period:" .. LOG2_PERIOD .. ",mcycle_period_index:0"

    local cases = { { "control", "a", "DATA 32" }, { "target", "z", "DATA 0" } }
    local results = {}
    for _, c in ipairs(cases) do
        local name, input, what = c[1], c[2], c[3]
        local ref, anomalies = player_root(input)
        local mok, mhash, mout = cli(name, input, MCH)
        local uok, uhash, uout = cli(name, input, UCH)
        results[name] = {
            ref = ref, mok = mok, mhash = mhash, uok = uok, uhash = uhash,
            m_good = mok and mhash == ref, u_good = uok and uhash ~= nil and #uhash == 32,
        }
        print(string.format("%s (input %q, guest accepts with %s):", name, input, what))
        print(string.format("  PRT player claim root:          %s%s", cartesi.tohex(ref),
            #anomalies > 0 and ("  (anomalies: " .. table.concat(anomalies, "; ") .. ")") or ""))
        print(string.format("  CLI --mcycle-computation-hash:  %s, %s", mok and "exit 0" or "FAILED",
            mhash and cartesi.tohex(mhash) or "no hash written"))
        if not mok then print("    " .. last_lines(mout, 2)) end
        print(string.format("  CLI --uarch-cycle-computation-hash (period 0): %s, %s", uok and "exit 0" or "FAILED",
            uhash and cartesi.tohex(uhash) or "no hash written"))
        if not uok then print("    " .. last_lines(uout, 2)) end
    end
    cleanup()

    local ctl = results.control
    if not ctl.m_good then
        harness.setup_error("control case failed: the CLI must compute the claim of a correctly designed guest")
    end
    local tgt = results.target
    if not tgt.u_good then
        print("note: the uarch-cycle run also exits with an error (" .. (tgt.uhash and "after writing its hash"
            or "without a hash") .. "); not asserted")
    end
    return harness.expect(tgt.m_good,
        "R4 / section 8: the CLI's computation-hash options must compute the claim for every guest, "
            .. "'whether or not its application is correctly designed'; with a guest that accepts with an "
            .. "outputs-root length of 0 the CLI aborts (cartesi-machine.lua flush_pending_outputs: "
            .. "'expected outputs Merkle root in tx buffer') and computes no claim, while the PRT player "
            .. "computes it")
end)
