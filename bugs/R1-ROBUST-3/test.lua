-- R1-ROBUST-3: a guest's automatic yields must not multiply the honest player's host cost per mcycle.
--
-- Checks R12 (bounded worst-case cost of an mcycle, the unit of work that the deployment sizes its
-- clocks for under A7) on the honest operator's mandatory path, event_handler.input_added, of the
-- default honest player (prt.new_forked_player, which drives its machines as JSON-RPC servers).
--
-- A bare-metal guest (guest.S) takes the template position (manual yield, rx-accepted). For the
-- delivered input it runs N iterations of a 4-instruction loop and then rejects the input. In the
-- yield variant each iteration stores an automatic PROGRESS yield of length 0 to HTIF tohost; in the
-- control variant it stores the same word to RAM, so both variants spend the same guest mcycles.
-- Every automatic yield breaks the interpreter, and the player's run_to_stop loop then issues a new
-- remote collect_mcycle_root_hashes call (which re-runs update_hash_tree and ships the partial
-- bundle back and forth). The guest thus chooses a per-mcycle host cost orders of magnitude above
-- native interpretation, paid on the main run and again on every replay a dispute forces.
--
-- Correct behavior: the extra host wall time per guest mcycle that the yields cause stays below
-- LIMIT_US (10 us, about 1000x the cost of a natively interpreted mcycle). The test fails otherwise.
-- The stored player (local machines) is measured too, as a reference only.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local prt = require("prt")

local N = 3000
local LIMIT_US = 10.0

assert(cartesi.AR_HTIF_START == 0x40008000, "guest.S assumes HTIF at 0x40008000")
assert(cartesi.AR_CMIO_RX_BUFFER_START == 0x60000000, "guest.S assumes rx buffer at 0x60000000")

local function now()
    local p = assert(io.popen("date +%s%N", "r"))
    local ns = tonumber(p:read("l"))
    p:close()
    return ns / 1e9
end

local p = io.popen("mktemp -d", "r")
local work = p:read("l")
p:close()
assert(work and #work > 0, "mktemp failed")
local function cleanup()
    os.execute("rm -rf '" .. work .. "'")
end

local initial_hash, template_dir

local function make_template()
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
    initial_hash = machine:get_root_hash()
    template_dir = work .. "/template"
    machine:store(template_dir)
end

local function write_input(name, n, mode)
    local path = work .. "/" .. name
    local f = assert(io.open(path, "wb"))
    f:write(string.pack("<I8I8", n, mode))
    f:close()
    return path
end

-- Guest mcycles and automatic yields the input costs, measured on a local machine.
local function measure_guest(input_path)
    local m <close> = cartesi.machine(template_dir)
    local data = assert(io.open(input_path, "rb")):read("a")
    m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, initial_hash)
    local m0 = m:read_reg("mcycle")
    local yields = 0
    while true do
        local reason = m:run(math.maxinteger)
        if reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
            assert(reason == cartesi.BREAK_REASON_YIELDED_MANUALLY, "guest did not yield manually")
            break
        end
        yields = yields + 1
    end
    assert(m:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED, "guest did not reject")
    return m:read_reg("mcycle") - m0, yields
end

local function mkdir(path)
    assert(os.execute("mkdir -p '" .. path .. "'"), "mkdir failed")
    return path
end

local function time_input_added(kind, input_path, tag)
    local dapp = prt.new_dapp_contract(initial_hash, { input_path })
    dapp.machine_directory = template_dir
    local player <close> = kind == "forked" and prt.new_forked_player(dapp, "honest")
        or prt.new_stored_player(dapp, "honest", nil, mkdir(work .. "/epoch-" .. tag))
    collectgarbage("collect")
    local t0 = now()
    player.event_handler.input_added(player, 0, input_path)
    local dt = now() - t0
    assert(player.input_count == 1 and player.output_count == 0, "input not processed as rejected")
    -- Replay of the same input from the retained boundary at input 0, as a dispute forces.
    local pair <close>, offset = player.machine_cache:nearest_not_past_epoch_input_offset(0)
    assert(offset == 0, "unexpected nearest boundary")
    t0 = now()
    player:run_to_epoch_input_offset(pair, 0, 1)
    local dr = now() - t0
    return dt, dr
end

local ok, err = pcall(function()
    assert(os.execute("bash ./build.sh '" .. work .. "' >/dev/null"), "guest build failed")
    make_template()
    local yield_input = write_input("input-yield", N, 0)
    local plain_input = write_input("input-plain", N, 1)
    local yield_mcycles, yield_count = measure_guest(yield_input)
    local plain_mcycles, plain_yields = measure_guest(plain_input)
    assert(yield_count == N and plain_yields == 0, "unexpected yield counts")
    assert(math.abs(yield_mcycles - plain_mcycles) <= 4, "variants differ in guest mcycles")

    local result = {}
    for _, kind in ipairs({ "stored", "forked" }) do
        local t_plain, r_plain = time_input_added(kind, plain_input, kind .. "-plain")
        local t_yield, r_yield = time_input_added(kind, yield_input, kind .. "-yield")
        local us_run = (t_yield - t_plain) * 1e6 / yield_mcycles
        local us_replay = (r_yield - r_plain) * 1e6 / yield_mcycles
        result[kind] = math.max(us_run, us_replay)
        io.write(
            string.format(
                "%s player: %d guest mcycles, %d automatic yields: input_added %.3fs vs %.3fs without yields "
                    .. "(%.1f us extra per mcycle); replay %.3fs vs %.3fs (%.1f us extra per mcycle)\n",
                kind,
                yield_mcycles,
                yield_count,
                t_yield,
                t_plain,
                us_run,
                r_yield,
                r_plain,
                us_replay
            )
        )
    end
    if result.forked > LIMIT_US then
        io.write(
            string.format(
                "FAIL: guest automatic yields raise the honest (forked) player's host cost to %.1f us per mcycle "
                    .. "(> %.0f us; native interpretation is ~0.01 us): each yield costs a JSON-RPC "
                    .. "collect_mcycle_root_hashes (or run, on replay) round trip, a guest-chosen constant-factor blow-up of the "
                    .. "per-mcycle cost on the input and replay paths (R12/A7)\n",
                result.forked,
                LIMIT_US
            )
        )
        return false
    end
    io.write("OK: automatic yields do not inflate per-mcycle host cost\n")
    return true
end)
cleanup()
if not ok then
    io.stderr:write("harness error: " .. tostring(err) .. "\n")
    os.exit(2)
end
os.exit(err and 0 or 1)
