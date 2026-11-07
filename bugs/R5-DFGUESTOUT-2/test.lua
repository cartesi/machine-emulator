#!/usr/bin/env lua5.4
-- R5-DFGUESTOUT-2: the cartesi-machine CLI, used as the honest claim computer (--cmio-advance-state with
-- --mcycle-computation-hash, doc/README.md "Computation hashes"), must not let a guest drive its host memory or disk
-- up without bound (R8 "no guest action may ... cause unbounded host allocation", R12 bounded cost, R4, A7).
--
-- In src/cartesi-machine.lua, run_to_stop calls get_and_print_yield (machine:receive_cmio_request) at every
-- automatic yield, and run_advance_state_input's on_yield_automatic appends every tx-output payload to
-- advance.pending_outputs, which is released only at the input's fixed point (also when the input is rejected),
-- whatever the output file patterns. Every tx-report is written at once to its own file (default
-- input-%i-report-%o.bin), and flush_pending_outputs writes every output of a rejected input to its own file
-- (default rejected-output-%o-input-%i.bin). None of this data affects the computation hash.
--
-- The bare-metal guest (guest.S, built at test time) forms a valid template (manual rx-accepted yield, empty
-- outputs root in the tx buffer). For the input it reads N and a tohost word W, stores W to tohost N times (one
-- automatic yield of the whole 2 MiB tx buffer, about 4 mcycles each), then rejects the input.
--
-- Checks (correct behavior: host cost of the input bounded independently of N):
--   A. memory: with every output/report file pattern disabled, W = automatic tx-output. The peak RSS of the CLI
--      process for N = 64 must exceed the N = 0 control by less than N MiB (half of the 128 MiB of payload).
--   B. disk: with the default patterns, W = automatic tx-report. The bytes the CLI writes to its working directory
--      must not grow with N (N = 64 vs N = 0 control) by N MiB or more.
-- Every run must exit 0 and write a 32-byte computation hash, and the hash of B for N = 64 must equal the hash of
-- the same run with the report pattern disabled (the files carry nothing the claim needs).
-- Exits 1 while the defect is present, 2 on a harness error.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")

local N = 64
local LIMIT = N << 20 -- N MiB

local TX_LEN = 1 << cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE
assert(cartesi.AR_HTIF_START == 0x40008000, "guest.S assumes HTIF at 0x40008000")
assert(cartesi.AR_CMIO_RX_BUFFER_START == 0x60000000, "guest.S assumes rx buffer at 0x60000000")
assert(TX_LEN == 0x200000, "guest.S assumes a 2 MiB tx buffer")

local function tohost(cmd, reason, data)
    return (cartesi.HTIF_DEV_YIELD << 56) | (cmd << 48) | (reason << 32) | data
end
local AUTO = cartesi.HTIF_YIELD_CMD_AUTOMATIC
local W_OUTPUT = tohost(AUTO, cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT, TX_LEN)
local W_REPORT = tohost(AUTO, cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT, TX_LEN)

local repo = assert(os.getenv("REPO_DIR"), "harness error: source bugs/env.sh first")
local cli = repo .. "/src/cartesi-machine.lua"
local here = assert(io.popen("pwd"):read("l"))

local work = assert(io.popen("mktemp -d"):read("l"), "harness error: mktemp failed")
local function cleanup()
    os.execute("rm -rf '" .. work .. "'")
end

local function write_file(path, data)
    local f = assert(io.open(path, "wb"))
    f:write(data)
    f:close()
end

local function read_file(path)
    local f = io.open(path, "rb")
    if not f then
        return nil
    end
    local d = f:read("a")
    f:close()
    return d
end

-- Wrapper that runs the CLI in this same Lua process and records its peak RSS (VmHWM) when it exits.
local WRAPPER = [[
local hwm_file, cli = arg[1], arg[2]
local real_exit = os.exit
os.exit = function(...)
    for line in io.lines("/proc/self/status") do
        local v = line:match("^VmHWM:%s+(%d+)")
        if v then
            local f = io.open(hwm_file, "w")
            f:write(v)
            f:close()
        end
    end
    return real_exit(...)
end
local new_arg = { [0] = cli }
for i = 3, #arg do
    new_arg[#new_arg + 1] = arg[i]
end
arg = new_arg
dofile(cli)
]]

local function build_template()
    local machine <close> = cartesi.machine({
        processor = { registers = { pc = 0x80000000 } },
        ram = { length = 1 << 20, backing_store = { data_filename = work .. "/guest.bin" } },
        cmio = { rx_buffer = {}, tx_buffer = {} },
    })
    machine:write_memory(
        cartesi.AR_CMIO_TX_BUFFER_START,
        hash_tree.frontier_get_root_hash(hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"))
    )
    assert(machine:run(math.maxinteger) == cartesi.BREAK_REASON_YIELDED_MANUALLY, "template did not yield")
    machine:store(work .. "/template")
end

local function du_bytes(dir)
    local total = 0
    local p = io.popen("find '" .. dir .. "' -type f -printf '%s\\n'")
    for line in p:lines() do
        total = total + tonumber(line)
    end
    p:close()
    return total
end

local run_id = 0
-- Runs the CLI on one input (N automatic yields with tohost word w) and returns peak RSS (bytes),
-- bytes written to its working directory (excluding the input and the hash file), and the computation hash.
local function run_cli(n, w, patterns)
    run_id = run_id + 1
    local dir = string.format("%s/run%d", work, run_id)
    assert(os.execute("mkdir -p '" .. dir .. "'"))
    write_file(dir .. "/input-0.bin", string.pack("<I8<I8", n, w))
    local adv = "--cmio-advance-state=input:input-%i.bin,input_file_index_begin:0,input_file_index_end:1"
    if patterns ~= "" then
        adv = adv .. "," .. patterns
    end
    local cmd = string.format(
        "cd '%s' && lua5.4 '%s/wrapper.lua' '%s/hwm.txt' '%s' --no-init-splash --remote-spawn "
            .. "--remote-address=127.0.0.1:0 --remote-shutdown --load='%s/template' '%s' "
            .. "'--mcycle-computation-hash=log2_mcycle_period:4,filename:%s/mch.bin' >'%s/out.log' 2>&1",
        dir,
        work,
        work .. "/" .. run_id,
        cli,
        work,
        adv,
        work .. "/" .. run_id,
        work
    )
    -- hwm and hash files live outside dir so they do not count as disk use
    local ok = os.execute(cmd)
    if not ok then
        error(string.format("CLI failed for N=%d (see output below)\n%s", n, read_file(work .. "/out.log") or ""))
    end
    local hwm = assert(tonumber(read_file(work .. "/" .. run_id .. "/hwm.txt")), "no VmHWM recorded")
    local hash = read_file(work .. "/" .. run_id .. "/mch.bin")
    assert(hash and #hash == cartesi.HASH_SIZE, "CLI did not write a 32-byte computation hash")
    local disk = du_bytes(dir) - (8 + 8)
    return hwm * 1024, disk, hash
end

local MiB = 1 << 20
local ok, res = pcall(function()
    assert(os.execute("bash '" .. here .. "/build.sh' '" .. work .. "'"), "guest build failed")
    write_file(work .. "/wrapper.lua", WRAPPER)
    build_template()
    for i = 1, 8 do
        assert(os.execute("mkdir -p '" .. work .. "/" .. i .. "'"))
    end

    local failures = {}
    -- A. memory, all output/report files disabled.
    local off = "output:,rejected_output:,report:"
    local rss0 = run_cli(0, W_OUTPUT, off)
    local rssN = run_cli(N, W_OUTPUT, off)
    io.write(
        string.format(
            "A memory: tx-output yields, files disabled: peak RSS N=0 %d MiB, N=%d %d MiB (growth %d MiB)\n",
            rss0 // MiB,
            N,
            rssN // MiB,
            (rssN - rss0) // MiB
        )
    )
    if rssN - rss0 >= LIMIT then
        failures[#failures + 1] = string.format(
            "CLI peak RSS grew %d MiB (>= %d MiB) for one rejected input whose guest issued %d automatic 2 MiB "
                .. "tx-outputs with every output file disabled (pending_outputs retains every payload)",
            (rssN - rss0) // MiB,
            LIMIT // MiB,
            N
        )
    end

    -- B. disk, default patterns.
    local _, disk0 = run_cli(0, W_REPORT, "")
    local _, diskN, hashN = run_cli(N, W_REPORT, "")
    local _, _, hashN_off = run_cli(N, W_REPORT, "report:")
    io.write(
        string.format(
            "B disk: tx-report yields, default patterns: written N=0 %d MiB, N=%d %d MiB\n",
            disk0 // MiB,
            N,
            diskN // MiB
        )
    )
    assert(hashN == hashN_off, "harness error: computation hash depends on the report file pattern")
    if diskN - disk0 >= LIMIT then
        failures[#failures + 1] = string.format(
            "CLI wrote %d MiB (>= %d MiB) of report files for one rejected input whose guest issued %d automatic "
                .. "2 MiB tx-reports, with the same computation hash as when no file is written",
            (diskN - disk0) // MiB,
            LIMIT // MiB,
            N
        )
    end
    return failures
end)
cleanup()
if not ok then
    io.stderr:write("harness error: " .. tostring(res) .. "\n")
    os.exit(2)
end
if #res > 0 then
    io.write(
        "FAIL: guest drives the cartesi-machine claim computer's host memory/disk up without bound (R8/R12/R4): "
            .. table.concat(res, "; ")
            .. "\n"
    )
    os.exit(1)
end
io.write("OK: CLI host memory and disk bounded independently of the guest's output count\n")
os.exit(0)
