-- R16-RGOUTPUT-1: the stored honest player must seal, and reopen after a restart, an epoch whose application
-- stopped (halt, or a manual yield with a reason other than accepted/rejected, e.g. the TX_EXCEPTION that
-- rollup-http-server raises when the dapp exits).
--
-- Such a final state is reachable (one guest store to tohost) and is an R5 fixed point, so the state transition
-- function defines the epoch's final hash. R4 requires the honest operator to compute and defend that claim; if it
-- cannot, an adversary's claim with an rx-accepted final state and an outputs root of its choice wins unopposed.
--
-- For each stop kind (halt, manual TX_EXCEPTION) this test:
--   1. builds a template (bare-metal yield.S: rx-accepted manual yield, empty outputs root in the tx buffer);
--   2. runs the forked player (control) over one input after which the guest stops, seals, and takes its final hash;
--   3. runs prt.new_stored_player exactly as prt-player.lua's honest kind does (with a next-epoch checkpoint
--      directory), and requires epoch_sealed to succeed with the same final hash;
--   4. runs the stored player without a checkpoint directory, seals, then reopens the sealed epoch directory with
--      new_stored_player (a relaunch during the dispute) and requires it to succeed with the same final hash.
-- It exits nonzero while any of these fail.
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local fs = require("cartesi.filesystem")
local prt = require("prt")

local function sh(cmd)
    assert(os.execute(cmd), "command failed: " .. cmd)
end

local tmp = assert(io.popen("mktemp -d"):read("l"))
local function cleanup()
    os.execute("rm -rf '" .. tmp .. "'")
end

sh("bash ./build.sh '" .. tmp .. "' >/dev/null")
local image = tmp .. "/yield.bin"

local EMPTY = hash_tree.frontier_get_root_hash(hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"))
local function yield_word(cmd, reason, data)
    return (cartesi.HTIF_DEV_YIELD << 56) | (cmd << 48) | (reason << 32) | data
end
local exception = yield_word(cartesi.HTIF_YIELD_CMD_MANUAL, cartesi.HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION, 4)
local variants = {
    { name = "halt", first = 1, later = 1 },
    { name = "tx-exception", first = exception, later = exception },
}

local input = tmp .. "/input.bin"
do
    local f = assert(io.open(input, "wb"))
    f:write("any input")
    f:close()
end

local failures = {}
local function fail(msg)
    failures[#failures + 1] = msg
    io.stderr:write("  FAIL: ", msg, "\n")
end
local function short(err)
    return tostring(err):gsub("\n.*", "")
end

for _, v in ipairs(variants) do
    print("== " .. v.name)
    local base = tmp .. "/" .. v.name
    fs.create_directory(base)
    local tdir = base .. "/template"
    do
        local m <close> = cartesi.machine({
            ram = { backing_store = { data_filename = image }, length = 1 << 20 },
            htif = { yield_manual = true, yield_automatic = true },
        })
        m:write_memory(0x80001000, EMPTY .. string.pack("<I8I8", v.first, v.later))
        assert(m:run(1000) == cartesi.BREAK_REASON_YIELDED_MANUALLY, "template did not yield")
        assert(m:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
        m:store(tdir)
    end
    fs.create_directory(base .. "/checkpoints")
    prt.store_first_epoch_checkpoint(tdir, prt.new_geometry(10), base .. "/checkpoints/epoch-0")
    local dapp, frontier = prt.load_epoch_checkpoint(base .. "/checkpoints/epoch-0")

    -- Control: the forked player.
    local expected
    do
        local fp <close> = prt.new_forked_player(dapp, "forked", frontier)
        fp.event_handler.input_added(fp, 0, input)
        assert(fp.epoch_stopped, "harness: the forked player did not see the epoch stop")
        fp.event_handler.epoch_sealed(fp, 1)
        expected = assert(fp.final_state_hash, "harness: forked player has no final hash")
        print("  forked player sealed, final " .. cartesi.tohex(expected))
    end

    -- The honest node's configuration: stored player with the next epoch's checkpoint directory.
    do
        local _, frontier1 = prt.load_epoch_checkpoint(base .. "/checkpoints/epoch-0")
        local edir = base .. "/state-ck"
        fs.create_directory(edir)
        local sp <close> = prt.new_stored_player(dapp, "honest", frontier1, edir, base .. "/checkpoints/epoch-1")
        sp.event_handler.input_added(sp, 0, input)
        assert(sp.epoch_stopped, "harness: the stored player did not see the epoch stop")
        local ok, err = pcall(sp.event_handler.epoch_sealed, sp, 1)
        if not ok then
            fail(v.name .. ": stored honest player (with checkpoint dir) cannot seal the stopped epoch: " .. short(err))
        elseif sp.final_state_hash ~= expected then
            fail(v.name .. ": stored player sealed a different final hash " .. cartesi.tohex(sp.final_state_hash))
        else
            print("  stored player (checkpoint dir) sealed, final matches")
        end
    end

    -- Relaunch: stored player without checkpoint dir seals, then the sealed epoch is reopened.
    do
        local _, frontier2 = prt.load_epoch_checkpoint(base .. "/checkpoints/epoch-0")
        local edir = base .. "/state-nock"
        fs.create_directory(edir)
        local sealed_ok
        do
            local sp <close> = prt.new_stored_player(dapp, "honest", frontier2, edir)
            sp.event_handler.input_added(sp, 0, input)
            local ok, err = pcall(sp.event_handler.epoch_sealed, sp, 1)
            if not ok then
                fail(v.name .. ": stored player (no checkpoint dir) cannot seal: " .. short(err))
            elseif sp.final_state_hash ~= expected then
                fail(v.name .. ": stored player (no checkpoint dir) sealed a different final hash")
            else
                sealed_ok = true
                print("  stored player (no checkpoint dir) sealed, final matches")
            end
        end
        if sealed_ok then
            local _, frontier3 = prt.load_epoch_checkpoint(base .. "/checkpoints/epoch-0")
            local ok, sp = pcall(prt.new_stored_player, dapp, "honest", frontier3, edir)
            if not ok then
                fail(v.name .. ": relaunched stored player cannot reopen the sealed stopped epoch: " .. short(sp))
            else
                local same = sp.final_state_hash == expected
                sp:__close()
                if not same then
                    fail(v.name .. ": reopened stored player has a different final hash")
                else
                    print("  reopened sealed epoch, final matches")
                end
            end
        end
    end
end

cleanup()
if #failures > 0 then
    print(
        "R16-RGOUTPUT-1: the stored honest player cannot seal (or reopen) an epoch whose application halted or "
            .. "raised TX_EXCEPTION, so it never posts the honest claim for that epoch (R4/R5): "
            .. failures[1]
    )
    os.exit(1)
end
print("R16-RGOUTPUT-1: stored honest player seals and reopens stopped epochs with the canonical final hash")
os.exit(0)
