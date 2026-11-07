#!/usr/bin/env lua5.4
-- R11-FAMOPERATORIO-1: at every input boundary, the honest stored player (prt.new_stored_player, what
-- prt-player.lua runs for --kind=honest) persists each output of the input as its own durable file:
-- commit_epoch_state -> store_outputs -> one fs.write_durable_file (mkostemp + write + fsync + rename)
-- per output into outputs/<offset>.bin. The guest chooses how many outputs an input produces, so one
-- input boundary costs the honest operator O(outputs) fsyncs, O(outputs) inodes and O(outputs) 4 KiB
-- blocks, kept for the epoch directory's lifetime, on top of emulating the outputs. The keccaks are
-- already appended once to outputs.log, so the data could be persisted with O(1) syncs per boundary.
--
-- Threat model: R12 and A7 (the worst-case host cost of a delivery is raised by a guest-chosen constant
-- factor per output: an fsync and an inode per output), R4 (when inodes or the directory run out,
-- commit_epoch_state raises at every relaunch and the honest claim cannot be computed or defended),
-- section 2 honest operator's path (computing claims, storing the machine), section 7 (input payloads
-- chosen to maximize the honest operator's cost).
--
-- The guest (guest.c, built by build.sh, linked with libcmt's own keccak/merkle code) is a correctly
-- designed bare-metal rollup application: it emits N one-byte Notice outputs for an input whose first
-- four bytes encode N, keeps the outputs Merkle root, and accepts. The test drives the real prt.lua
-- stored player through two inputs, one with N_SMALL outputs and one with N_LARGE outputs, and counts
-- the sync operations (write_durable_file, sync_file, sync_directory) and the new files each boundary
-- costs.
--
-- Correct behavior: the persistence cost of an input boundary does not scale with the number of
-- outputs: the large input needs at most SLACK more sync operations and SLACK more files than the small
-- one. The test fails while each output costs its own fsync and inode.
--
-- When the host can mount a loopback ext4 (root), a second check runs the same player in an epoch
-- directory with ample bytes but few inodes and shows that an input with many tiny outputs makes
-- commit_epoch_state raise, and that the relaunched player fails again on the same input.
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local fs = require("cartesi.filesystem")
local prt = require("prt")

local N_SMALL, N_LARGE, SLACK = 1, 2000, 4
local N_INODES = 600 -- outputs of the input in the low-inode check

local function sh(command)
    assert(os.execute(command), "command failed: " .. command)
end
local function capture(command)
    local h = assert(io.popen(command))
    local v = h:read("a")
    h:close()
    return v
end
local function count_files(path)
    return assert(tonumber(capture("find '" .. path .. "' -type f | wc -l")))
end

local root = capture("mktemp -d /tmp/r11-famoperatorio-XXXXXX"):gsub("%s+$", "")
sh("bash ./build.sh '" .. root .. "' > /dev/null")

-- Wall time (informative only; no assertion depends on it).
local has_socket, socket = pcall(require, "socket")
local now = has_socket and socket.gettime or os.clock

-- Counts the persistence operations prt.lua performs through cartesi.filesystem (the same table prt.lua
-- uses), and the time spent in durable writes.
local counts = { durable = 0, durable_outputs = 0, sync_file = 0, sync_directory = 0, durable_time = 0 }
do
    local write_durable_file, sync_file, sync_directory = fs.write_durable_file, fs.sync_file, fs.sync_directory
    fs.write_durable_file = function(data, path, ...)
        counts.durable = counts.durable + 1
        if tostring(path):find("/outputs/", 1, true) then
            counts.durable_outputs = counts.durable_outputs + 1
        end
        local t = now()
        local r = table.pack(write_durable_file(data, path, ...))
        counts.durable_time = counts.durable_time + (now() - t)
        return table.unpack(r, 1, r.n)
    end
    fs.sync_file = function(...)
        counts.sync_file = counts.sync_file + 1
        return sync_file(...)
    end
    fs.sync_directory = function(...)
        counts.sync_directory = counts.sync_directory + 1
        return sync_directory(...)
    end
end
local function syncs()
    return counts.durable + counts.sync_file + counts.sync_directory
end

-- The template: the guest at its first manual yield (accepted), with the empty outputs root it computed.
local function store_template(directory)
    local machine <close> = cartesi.machine({
        processor = { registers = { pc = 0x80000000 } },
        ram = { length = 4 << 20, backing_store = { data_filename = root .. "/guest.bin" } },
        cmio = { rx_buffer = {}, tx_buffer = {} },
    })
    assert(machine:run(math.maxinteger) == cartesi.BREAK_REASON_YIELDED_MANUALLY)
    local _, reason, data = machine:receive_cmio_request()
    local empty = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
    assert(reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED and data == hash_tree.frontier_get_root_hash(empty))
    machine:store(directory)
end

local function write_input(path, n)
    local f = assert(io.open(path, "wb"))
    f:write(string.pack("<I4", n))
    f:close()
end

-- Sets up checkpoints/epoch-0 under work and returns a function that opens (or reopens) the epoch player.
local function setup(work)
    sh("mkdir -p '" .. work .. "/state/epoch-0' '" .. work .. "/checkpoints'")
    store_template(work .. "/template")
    prt.store_first_epoch_checkpoint(work .. "/template", prt.new_geometry(20), work .. "/checkpoints/epoch-0")
    cartesi.machine:remove_stored(work .. "/template")
    return function()
        local dapp, frontier = prt.load_epoch_checkpoint(work .. "/checkpoints/epoch-0")
        return prt.new_stored_player(dapp, "honest", frontier, work .. "/state/epoch-0", work .. "/checkpoints/epoch-1")
    end
end

-- Part 1: persistence cost of one input boundary as a function of the guest-chosen output count.
local function measure()
    local work = root .. "/measure"
    local open = setup(work)
    local epoch = work .. "/state/epoch-0"
    local player <close> = open()
    local result = {}
    for i, n in ipairs({ N_SMALL, N_LARGE }) do
        local input = work .. "/input-" .. i
        write_input(input, n)
        local s0, o0, f0, d0 = syncs(), counts.durable_outputs, count_files(epoch), counts.durable_time
        local t0 = now()
        player.event_handler.input_added(player, i - 1, input)
        local elapsed = now() - t0
        result[i] = {
            outputs = n,
            syncs = syncs() - s0,
            output_writes = counts.durable_outputs - o0,
            files = count_files(epoch) - f0,
            durable_time = counts.durable_time - d0,
            elapsed = elapsed,
        }
        print(
            string.format(
                "input %d: %5d outputs -> %5d sync operations (%5d durable output files), +%5d files in the "
                    .. "epoch directory, %.2f s in durable writes of %.2f s total",
                i - 1,
                n,
                result[i].syncs,
                result[i].output_writes,
                result[i].files,
                result[i].durable_time,
                result[i].elapsed
            )
        )
    end
    assert(player.output_count == N_SMALL + N_LARGE, "player did not record every output")
    print(string.format("outputs/ holds %d files, du of the epoch directory's outputs/: %s",
        count_files(epoch .. "/outputs"), capture("du -sh '" .. epoch .. "/outputs' | cut -f1"):gsub("%s+$", "")))
    return result
end

-- Part 2 (needs root and loop devices): the same player on an epoch directory with ample bytes and few
-- inodes. Returns nil when the environment cannot mount; otherwise a description of what happened.
local function low_inodes()
    local work = root .. "/inodes"
    local image, mnt = root .. "/inodes.ext4", root .. "/mnt"
    sh("mkdir -p '" .. work .. "' '" .. mnt .. "'")
    if not os.execute("truncate -s 256M '" .. image .. "' && mke2fs -q -t ext4 -N 512 '" .. image .. "' 2>/dev/null"
        .. " && mount -o loop '" .. image .. "' '" .. mnt .. "' 2>/dev/null") then
        return nil
    end
    local ok, result = pcall(function()
        -- The epoch directory lives on the small filesystem; the checkpoint lives elsewhere.
        local open = setup(work)
        sh("mkdir -p '" .. mnt .. "/epoch-0' && rmdir '" .. work .. "/state/epoch-0'")
        sh("ln -s '" .. mnt .. "/epoch-0' '" .. work .. "/state/epoch-0'")
        local input = work .. "/input"
        write_input(input, N_INODES)
        local df = function()
            local i = capture("df -iP '" .. mnt .. "' | tail -1 | awk '{print $3 \"/\" $4}'"):gsub("%s+", "")
            local b = capture("df -hP '" .. mnt .. "' | tail -1 | awk '{print $4}'"):gsub("%s+", "")
            return i .. ", bytes free " .. b
        end
        local before = df()
        local errors = {}
        for attempt = 1, 2 do
            local player <close> = open()
            local ok_add, err = pcall(player.event_handler.input_added, player, 0, input)
            errors[attempt] = not ok_add and tostring(err) or nil
        end
        return { before = before, after = df(), errors = errors }
    end)
    os.execute("umount '" .. mnt .. "' 2>/dev/null")
    if not ok then
        error(result, 0)
    end
    return result
end

local ok, measured, inodes = pcall(function()
    local m = measure()
    return m, low_inodes()
end)
sh("rm -rf '" .. root .. "'")
if not ok then
    print("harness error: " .. tostring(measured))
    os.exit(2)
end

local small, large = measured[1], measured[2]
if small.output_writes ~= N_SMALL and small.output_writes ~= 0 then
    print("note: unexpected durable output writes for the small input: " .. small.output_writes)
end
local extra_syncs = large.syncs - small.syncs
local extra_files = large.files - small.files

if inodes then
    print(string.format("low-inode epoch directory (inodes used/free %s) before; after: %s", inodes.before,
        inodes.after))
    for attempt = 1, 2 do
        print(string.format("  %s player, input 0 with %d outputs: %s", attempt == 1 and "first" or "relaunched",
            N_INODES, inodes.errors[attempt] and ("raised: " .. inodes.errors[attempt]) or "committed"))
    end
else
    print("low-inode check skipped (cannot mount a loopback ext4 here)")
end

if extra_syncs > SLACK or extra_files > SLACK then
    print(
        string.format(
            "FAIL: honest stored player persistence is O(outputs) per input boundary: an input with %d outputs "
                .. "costs %d more sync operations (one write_durable_file+fsync per output under outputs/) and "
                .. "%d more files/inodes than one with %d (allowed: %d); %.2f s of its %.2f s went to durable "
                .. "writes, a guest-chosen constant factor over emulation (R12/A7)%s",
            N_LARGE,
            extra_syncs,
            extra_files,
            N_SMALL,
            SLACK,
            large.durable_time,
            large.elapsed,
            (inodes and inodes.errors[1] and inodes.errors[2])
                    and "; with few inodes, commit raises and the relaunched player fails again on the same input (R4)"
                or ""
        )
    )
    os.exit(1)
end
print("OK: persistence cost of an input boundary does not scale with the guest's output count")
