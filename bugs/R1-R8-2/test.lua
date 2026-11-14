-- R1-R8-2: the honest player of the verification-game recipe (doc/recipes/vg.lua) keeps every output payload of the
-- epoch in its Lua heap, and stops (raises "outputs Merkle root mismatch" out of input_added) when an accepted input
-- leaves in the tx buffer a root that is not the root of the outputs it emitted.
--
-- Requirements (THREAT_MODEL.md):
--   R12 "The memory and storage the honest operator needs to defend its claims do not grow with the number of
--        outputs."
--   R4  "This holds for every guest, whether or not its application is correctly designed (section 8) ..."
--   section 8 "An application that breaks the rollup interface may leave its outputs unprovable, but it must never
--        stop the honest operator from computing claims or producing proofs. Development tools may instead stop and
--        report the violation."
--
-- Check A (root mismatch): a bare-metal guest accepts input "W" with a tx-buffer root that differs from the root of
-- its (zero) outputs. The test drives vg.lua's honest player exactly as the referee's runner does
-- (event_handler.input_added, epoch_sealed, commit_claim) and asserts that input_added does not raise and that the
-- committed claim equals the machine's root hash after that input, computed independently with the Lua API.
--
-- Check B (memory): the same guest accepts input "O"+N after emitting N outputs of 2 MiB each with the correct root.
-- For N = 1 and N = 16, each with a fresh honest player, the test measures the growth of the player's Lua heap
-- (collectgarbage("count") after a full collection) across input_added and asserts that the growth for N = 16
-- exceeds the growth for N = 1 by less than one output (2 MiB), i.e. that it does not grow with the number of
-- outputs. The count is deterministic: no timing is involved.
--
-- Exit 1 if either check fails (bug present), 0 if both hold, 2 on setup errors.

local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local unistd = require("posix.unistd")
    local OUTPUT_SIZE = 1 << cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE
    local HERE = assert(unistd.getcwd())

    local tmp = io.popen("mktemp -d"):read("l")
    if not tmp or tmp == "" then harness.setup_error("mktemp failed") end
    local function cleanup()
        unistd.chdir(HERE)
        os.execute("rm -rf '" .. tmp .. "'")
    end
    local function sh_ok(cmd)
        local ok, _, code = os.execute(cmd)
        return ok and code == 0
    end
    local function write(path, data)
        local f = assert(io.open(path, "wb"))
        f:write(data)
        f:close()
    end

    -- 1. Build the guest and store the epoch's initial machine (waiting at a manual yield with the accepted reason)
    --    under its hash, where vg.lua's players look for it.
    if not sh_ok(string.format("'%s/baremetal/build.sh' -o '%s/guest.bin' '%s/guest.c' > '%s/build.log' 2>&1",
            harness.HARNESS, tmp, HERE, tmp)) then
        local log = harness.read_file(tmp .. "/build.log")
        cleanup()
        harness.setup_error("guest build failed\n" .. log)
    end
    local config = { ram = { length = 64 << 20, backing_store = { data_filename = tmp .. "/guest.bin" } } }

    local function run_to_manual_yield(m)
        while true do
            local br = m:run(cartesi.MCYCLE_MAX)
            if br == cartesi.BREAK_REASON_YIELDED_MANUALLY then
                local _, reason = m:receive_cmio_request()
                return reason
            elseif br ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
                error("guest stopped with break reason " .. tostring(br))
            end
        end
    end

    local initial_hash
    do
        local m <close> = cartesi.machine(config)
        if run_to_manual_yield(m) ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            error("guest did not accept at start")
        end
        initial_hash = m:get_root_hash()
        m:store(tmp .. "/" .. cartesi.tohex(initial_hash))
    end

    local inputs = {
        wrong = "W",
        one = "O" .. string.pack("<I4", 1),
        many = "O" .. string.pack("<I4", 16),
    }
    for name, data in pairs(inputs) do
        write(tmp .. "/" .. name .. ".bin", data)
    end

    -- Independent reference: the root hash after delivering the input to the initial machine and running it to the
    -- next manual yield (what the state transition function defines; neither input is rejected).
    local function reference_hash(data)
        local m <close> = cartesi.machine(tmp .. "/" .. cartesi.tohex(initial_hash))
        m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, m:get_root_hash())
        local reason = run_to_manual_yield(m)
        assert(reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED, "reference run did not accept")
        return m:get_root_hash()
    end

    local results = {}
    local ok, err = pcall(function()
        assert(unistd.chdir(tmp))
        local vg = require("vg")
        local handler = vg.event_handler

        -- Check A: root mismatch
        local ref = reference_hash(inputs.wrong)
        do
            local player <close> = vg.new_player(initial_hash, "honest")
            local ok_in, err_in = pcall(handler.input_added, player, 0, tmp .. "/wrong.bin")
            local claim
            if ok_in then
                local ok_seal, err_seal = pcall(handler.epoch_sealed, player)
                if ok_seal then
                    claim = handler.commit_claim(player)
                else
                    err_in = "epoch_sealed: " .. tostring(err_seal)
                end
            end
            print(string.format("check A: input_added %s%s; claim %s; reference %s", ok_in and "returned" or "raised",
                ok_in and "" or (": " .. tostring(err_in)), claim and cartesi.tohex(claim) or "none",
                cartesi.tohex(ref)))
            results.a = ok_in and claim == ref
        end

        -- Check B: memory retained across one input, as a function of the number of 2 MiB outputs
        local function heap_growth(input_name)
            local player <close> = vg.new_player(initial_hash, "honest")
            collectgarbage("collect")
            collectgarbage("collect")
            local before = collectgarbage("count")
            handler.input_added(player, 0, tmp .. "/" .. input_name .. ".bin")
            collectgarbage("collect")
            collectgarbage("collect")
            local after = collectgarbage("count")
            return (after - before) * 1024, #player.outputs
        end
        local g1, n1 = heap_growth("one")
        local g16, n16 = heap_growth("many")
        print(string.format("check B: heap growth across input_added: %d outputs -> %.2f MiB, %d outputs -> %.2f MiB "
            .. "(difference %.2f MiB; one output is %.2f MiB)", n1, g1 / 2 ^ 20, n16, g16 / 2 ^ 20,
            (g16 - g1) / 2 ^ 20, OUTPUT_SIZE / 2 ^ 20))
        if n1 ~= 1 or n16 ~= 16 then
            -- A fixed player may not keep player.outputs at all; only the heap figures matter then.
            print("note: player.outputs holds " .. tostring(n1) .. " and " .. tostring(n16) .. " entries")
        end
        results.b = (g16 - g1) < OUTPUT_SIZE
    end)
    cleanup()
    if not ok then error(err, 0) end

    local a = harness.expect(results.a,
        "R4/section 8: an accepted input whose outputs root does not match its outputs must not stop the honest "
        .. "player from computing its claim")
    local b = harness.expect(results.b,
        "R12: the memory the honest player retains must not grow with the number of outputs")
    return a and b
end)
