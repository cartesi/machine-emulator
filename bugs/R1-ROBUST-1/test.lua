-- R1-ROBUST-1: the honest PRT player must not let a guest drive its host memory up without bound.
--
-- Checks R8 ("no guest action may ... cause unbounded host allocation") and R12 (bounded cost of a
-- unit of work) on the honest operator's mandatory path: event_handler.input_added.
--
-- A bare-metal guest (guest.S) takes the template position (manual yield, rx-accepted), then, for
-- the delivered input, issues N automatic TX_OUTPUT yields of the whole 2 MiB tx buffer (one store
-- to tohost each, about 4 mcycles) and finally rejects the input. The honest forked player
-- (prt.new_forked_player) processes the input in input_added. run_to_input_mcycle_offset appends
-- every tx-output payload to pending_outputs and keeps them all until the input reaches a fixed
-- point, and throws them away at the rejection. Host memory therefore grows by about 2 MiB per
-- 4 guest mcycles, without any bound other than the 2^48-mcycle input budget.
--
-- Correct behavior: the peak RSS growth while processing the input stays bounded, independently
-- of N (outputs hashed or streamed and dropped). The test fails if the peak RSS growth while
-- processing N = 64 outputs (128 MiB of payload) is at least N MiB.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local prt = require("prt")

local N = 64
local LIMIT_KIB = N * 1024 -- N MiB: half of the retained payload; a bounded implementation is far below

local function vm_kib(field)
    for line in io.lines("/proc/self/status") do
        local v = line:match("^" .. field .. ":%s+(%d+)")
        if v then
            return tonumber(v)
        end
    end
    error("no " .. field .. " in /proc/self/status")
end

assert(cartesi.AR_HTIF_START == 0x40008000, "guest.S assumes HTIF at 0x40008000")
assert(cartesi.AR_CMIO_RX_BUFFER_START == 0x60000000, "guest.S assumes rx buffer at 0x60000000")
assert(cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE == 21, "guest.S assumes a 2 MiB tx buffer")

local p = io.popen("mktemp -d", "r")
local work = p:read("l")
p:close()
assert(work and #work > 0, "mktemp failed")
local function cleanup()
    os.execute("rm -rf '" .. work .. "'")
end

local function reset_hwm()
    -- Writing 5 to clear_refs resets the peak RSS (VmHWM) to the current RSS.
    local c = io.open("/proc/self/clear_refs", "w")
    if c then
        c:write("5")
        c:close()
    end
end

local function run(n)
    local sub = work .. "/n" .. n
    assert(os.execute("mkdir -p '" .. sub .. "'"))
    -- Valid template: waits at manual rx-accepted yield, tx buffer holds the empty outputs root.
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
    local initial_hash = machine:get_root_hash()
    local machine_dir = sub .. "/machine"
    machine:store(machine_dir)

    local input_path = sub .. "/input-0"
    local f = assert(io.open(input_path, "wb"))
    f:write(string.pack("<I8", n))
    f:close()

    -- Guest mcycles spent on the input (the player reverts the rejected input, so count them here).
    local fh <close> = cartesi.machine(machine_dir)
    local data = assert(io.open(input_path, "rb")):read("a")
    fh:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, initial_hash)
    local m0 = fh:read_reg("mcycle")
    local automatic_yields = 0
    while true do
        local reason = fh:run(math.maxinteger)
        if reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
            assert(reason == cartesi.BREAK_REASON_YIELDED_MANUALLY, "guest did not yield manually")
            break
        end
        automatic_yields = automatic_yields + 1
    end
    assert(automatic_yields == n, "guest did not emit the expected tx-outputs")
    assert(fh:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED)
    local guest_mcycles = fh:read_reg("mcycle") - m0

    local dapp = prt.new_dapp_contract(initial_hash, { input_path })
    dapp.machine_directory = machine_dir
    local player <close> = prt.new_forked_player(dapp, "honest")
    collectgarbage("collect")
    reset_hwm()
    local hwm_before = vm_kib("VmHWM")
    local t0 = os.clock()
    player.event_handler.input_added(player, 0, input_path)
    local cpu = os.clock() - t0
    local growth = vm_kib("VmHWM") - hwm_before
    assert(player.input_count == 1 and player.output_count == 0, "input not processed as rejected")
    io.write(
        string.format(
            "outputs=%d payload=%d MiB guest_mcycles=%d peak_rss_growth=%d MiB host_cpu=%.2fs\n",
            n,
            2 * n,
            guest_mcycles,
            growth // 1024,
            cpu
        )
    )
    return growth, guest_mcycles
end

local ok, err = pcall(function()
    assert(os.execute("bash ./build.sh '" .. work .. "'"), "guest build failed")
    -- Control: the same input with no outputs.
    local control = run(0)
    local growth, guest_mcycles = run(N)
    if growth >= LIMIT_KIB then
        io.write(
            string.format(
                "FAIL: honest player's peak RSS grew %d MiB (>= %d MiB) while processing one rejected input "
                    .. "(control with 0 outputs: %d MiB) whose guest spent %d mcycles re-yielding the 2 MiB tx buffer "
                    .. "as %d automatic tx-outputs: "
                    .. "pending_outputs retains every payload (unbounded guest-driven host allocation, R8/R12)\n",
                growth // 1024,
                LIMIT_KIB // 1024,
                control // 1024,
                guest_mcycles,
                N
            )
        )
        return false
    end
    io.write("OK: peak RSS growth bounded\n")
    return true
end)
cleanup()
if not ok then
    io.stderr:write("harness error: " .. tostring(err) .. "\n")
    os.exit(2)
end
os.exit(err and 0 or 1)
