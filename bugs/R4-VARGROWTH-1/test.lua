#!/usr/bin/env lua5.4
-- R4-VARGROWTH-1: the honest stored player (what prt-player.lua runs for --kind=honest) never retires an
-- epoch. Every epoch leaves state/epoch-N (the epoch machine, up to 8 stored cache entries, inputs, outputs,
-- forests) and checkpoints/epoch-N+1 (a full machine:store) on disk forever, so the disk an honest node
-- needs grows linearly with the application's age, not with any epoch's work. prt.remove_epoch_directory
-- ("after its epoch's dispute") exists but neither prt-player.lua, prt-epoch.lua nor prt-bridge.lua calls
-- it, and nothing removes old checkpoints. Once the disk fills, input_added/commit_epoch_state/the seal's
-- checkpoint store raise on every relaunch, and the honest claim misses its deadlines.
--
-- Threat model: section 1 ("on the resources the deployment was sized for": no finite size works), R4
-- (the honest operator can always compute its claim), R12/A7 (cost bounded by the epoch's work), R8 (the
-- guest below dirties all of RAM per input, so each retained machine diverges fully even on a reflink
-- filesystem), section 2 honest operator's path (storing and reloading the machine).
--
-- The test replays prt-player.lua's per-epoch lifecycle with the real prt.lua code, no chain:
-- load_epoch_checkpoint(checkpoints/epoch-N) -> new_stored_player(dapp, label, frontier, state/epoch-N,
-- checkpoints/epoch-N+1) -> input_added x K -> epoch_sealed, for E epochs, measuring du of state/ +
-- checkpoints/ after each seal. The guest (guest.S, built by build.sh) is a 4 MiB bare-metal rollup app
-- that accepts every input and writes the input's first word into every RAM page.
--
-- Correct behavior: the operator retires settled epochs, so retained disk is bounded by a constant number
-- of epochs. The test fails when (a) retained disk after E epochs exceeds twice that after one epoch AND
-- (b) no operator module (prt-player/prt-epoch/prt-bridge) has any path that removes an epoch directory
-- or a checkpoint (the harness has no chain to settle epochs, so a settlement-driven fix is detected by
-- (b)). Control: the same lifecycle that calls prt.remove_epoch_directory on epoch N-2 and drops old
-- checkpoints after each seal stays flat, showing the space is reclaimable and the measure is sound.
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local fs = require("cartesi.filesystem")
local prt = require("prt")

local E, K = 4, 2
local repo = assert(os.getenv("REPO_DIR"), "source bugs/env.sh")

local function sh(command)
    assert(os.execute(command), "command failed: " .. command)
end
local function capture(command)
    local h = assert(io.popen(command))
    local v = h:read("a")
    h:close()
    return v
end
local function du(path)
    return assert(tonumber(capture("du -sk '" .. path .. "'"):match("^(%d+)")))
end

local root = capture("mktemp -d /tmp/r4-vargrowth-XXXXXX"):gsub("%s+$", "")
sh("bash ./build.sh '" .. root .. "' > /dev/null")

-- (b) Static: does any operator module retire epoch directories or checkpoints?
local retires = false
for _, name in ipairs({ "prt-player.lua", "prt-epoch.lua", "prt-bridge.lua" }) do
    local source = fs.read_file(repo .. "/doc/recipes/" .. name)
    for _, pattern in ipairs({ "remove_epoch_directory", "remove_stored", "remove_directory", "rm %-rf" }) do
        if source:find(pattern) then
            print(string.format("%s references %s", name, pattern))
            retires = true
        end
    end
end

-- The template: the guest at its first manual yield (accepted) with the empty outputs root in the tx buffer.
local function store_template(directory)
    local machine <close> = cartesi.machine({
        processor = { registers = { pc = 0x80000000 } },
        ram = { length = 4 << 20, backing_store = { data_filename = root .. "/guest.bin" } },
        cmio = { rx_buffer = {}, tx_buffer = {} },
    })
    local empty = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
    machine:write_memory(cartesi.AR_CMIO_TX_BUFFER_START, hash_tree.frontier_get_root_hash(empty))
    assert(machine:run(math.maxinteger) == cartesi.BREAK_REASON_YIELDED_MANUALLY)
    machine:store(directory)
end

-- Runs E epochs the way prt-player.lua does; with prune, retires epoch N-2 and checkpoints before N.
local function run(work, prune)
    sh("mkdir -p '" .. work .. "/state' '" .. work .. "/checkpoints'")
    store_template(work .. "/template")
    prt.store_first_epoch_checkpoint(work .. "/template", prt.new_geometry(10), work .. "/checkpoints/epoch-0")
    cartesi.machine:remove_stored(work .. "/template")
    local input, sizes = work .. "/input", {}
    for epoch = 0, E - 1 do
        local checkpoint = work .. "/checkpoints/epoch-" .. epoch
        local dapp, frontier = prt.load_epoch_checkpoint(checkpoint)
        local directory = work .. "/state/epoch-" .. epoch
        if not fs.exists(directory) then
            fs.create_directory(directory)
        end
        do
            local player <close> =
                prt.new_stored_player(dapp, "honest", frontier, directory, work .. "/checkpoints/epoch-" .. (epoch + 1))
            for i = 0, K - 1 do
                local f = assert(io.open(input, "wb"))
                f:write(string.pack("<I8", epoch * 1000 + i + 1))
                f:close()
                player.event_handler.input_added(player, i, input)
            end
            player.event_handler.epoch_sealed(player, K)
        end
        if prune then
            if epoch >= 2 then
                prt.remove_epoch_directory(work .. "/state/epoch-" .. (epoch - 2))
            end
            sh("rm -rf '" .. checkpoint .. "'")
        end
        sizes[#sizes + 1] = du(work .. "/state") + du(work .. "/checkpoints")
        print(
            string.format(
                "%s after epoch %d: retained %d MiB (epoch dir %d MiB, checkpoints %d MiB)",
                prune and "control" or "player ",
                epoch,
                sizes[#sizes] // 1024,
                fs.exists(directory) and du(directory) // 1024 or 0,
                du(work .. "/checkpoints") // 1024
            )
        )
    end
    sh("rm -rf '" .. work .. "'")
    return sizes
end

local ok, result = pcall(function()
    local player = run(root .. "/player", false)
    local control = run(root .. "/control", true)
    return { player = player, control = control }
end)
sh("rm -rf '" .. root .. "'")
if not ok then
    print("harness error: " .. tostring(result))
    os.exit(2)
end

local player, control = result.player, result.control
-- The control must stay bounded, otherwise the measure itself is wrong.
if control[E] > 2 * control[1] then
    print("harness error: the pruned control also grew; measurement unsound")
    os.exit(2)
end
local grows = player[E] > 2 * player[1]
if grows and not retires then
    print(
        string.format(
            "FAIL: honest stored player retains every epoch forever: %d MiB after 1 epoch, %d MiB after %d "
                .. "(+%d MiB/epoch, unbounded with application age; pruned control %d MiB), and no operator "
                .. "module ever removes an epoch directory or checkpoint",
            player[1] // 1024,
            player[E] // 1024,
            E,
            (player[E] - player[1]) // (1024 * (E - 1)),
            control[E] // 1024
        )
    )
    os.exit(1)
end
print("OK: retained disk is bounded or the operator retires settled epochs")
