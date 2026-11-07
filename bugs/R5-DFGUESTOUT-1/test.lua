-- R5-DFGUESTOUT-1: both documented claim computers (the honest PRT player in doc/recipes/prt.lua and the
-- cartesi-machine CLI cmio advance loop) take the outputs Merkle root from receive_cmio_request, whose length is the
-- guest's tohost DATA. A valid template that waits at its manual rx-accepted yield with DATA = 0 (as the manual's
-- low-level rollup loop does: "Initialize reason = RX_ACCEPTED, length = 0 ... Yield manual with ... length as DATA")
-- and whose tx buffer holds the correct (empty) outputs root then makes both hosts crash on an advance-state input
-- larger than the receive buffer. That delivery is a provable no-op (R4/R5): the machine stays at the template's own
-- accepted yield, with the template's DATA, so the host compares the empty string with the 32-byte root.
--
-- Correct behavior (R4: from any reachable state the honest operator can compute the claim; A5: the root is the
-- first 32-byte word of the tx buffer, DATA is opaque guest data, section 4):
--   * prt.new_forked_player(...).event_handler.input_added processes the oversized input (input_count 1,
--     output_count 0);
--   * cartesi-machine --cmio-advance-state ... --mcycle-computation-hash ... exits 0 and writes the computation hash.
-- Controls: the same template with DATA = 32 passes both; the DATA = 0 template passes the player on a small input
-- (the guest then yields accepted with DATA = 32), so only the no-op delivery path is affected.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local prt = require("prt")

assert(cartesi.AR_HTIF_START == 0x40008000, "guest.S assumes HTIF at 0x40008000")

local p = io.popen("mktemp -d", "r")
local work = p:read("l")
p:close()
assert(work and #work > 0, "mktemp failed")
local function cleanup()
    os.execute("rm -rf '" .. work .. "'")
end

local EMPTY_ROOT =
    hash_tree.frontier_get_root_hash(hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"))
local OVERSIZED = (1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE) + 1

local function write_file(path, data)
    local f = assert(io.open(path, "wb"))
    f:write(data)
    f:close()
end

-- Builds and stores a template whose manual rx-accepted yield carries tohost DATA = len.
local function make_template(len)
    local dir = work .. "/template-" .. len
    local machine <close> = cartesi.machine({
        processor = { registers = { pc = 0x80000000 } },
        ram = { length = 1 << 20, backing_store = { data_filename = work .. "/guest-" .. len .. ".bin" } },
        cmio = { rx_buffer = {}, tx_buffer = {} },
    })
    machine:write_memory(cartesi.AR_CMIO_TX_BUFFER_START, EMPTY_ROOT)
    assert(machine:run(math.maxinteger) == cartesi.BREAK_REASON_YIELDED_MANUALLY, "template did not yield")
    assert(machine:read_reg("htif_tohost_cmd") == cartesi.HTIF_YIELD_CMD_MANUAL, "template yield is not manual")
    assert(machine:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED, "not rx-accepted")
    assert(machine:read_reg("htif_tohost_data") == len, "unexpected template DATA")
    assert(machine:read_memory(cartesi.AR_CMIO_TX_BUFFER_START, 32) == EMPTY_ROOT, "tx buffer lacks the empty root")
    assert(
        machine:get_node_hash(cartesi.UARCH_STATE_START_ADDRESS, cartesi.UARCH_STATE_LOG2_SIZE)
            == cartesi.UARCH_PRISTINE_STATE_HASH,
        "uarch not pristine"
    )
    local hash = machine:get_root_hash()
    machine:store(dir)
    return dir, hash
end

-- Reference: the oversized delivery is a no-op whose log verifies.
local function check_noop(dir, hash, input)
    local m <close> = cartesi.machine(dir)
    local log = m:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, hash)
    assert(m:get_root_hash() == hash, "oversized delivery changed the state")
    assert(
        cartesi.machine:verify_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, hash, log, hash)
            == hash,
        "no-op delivery log does not verify"
    )
    -- Still at the template's accepted yield, root in the first tx-buffer word (A5).
    assert(m:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
    assert(m:read_memory(cartesi.AR_CMIO_TX_BUFFER_START, 32) == EMPTY_ROOT)
end

-- Honest forked player processes the input; returns ok, err.
local function run_player(dir, hash, input_path)
    local dapp = prt.new_dapp_contract(hash, { input_path })
    dapp.machine_directory = dir
    local player <close> = prt.new_forked_player(dapp, "honest")
    local ok, err = pcall(player.event_handler.input_added, player, 0, input_path)
    if ok and not (player.input_count == 1 and player.output_count == 0) then
        return false, "input not processed as accepted no-op"
    end
    return ok, err
end

-- CLI claim computation; returns ok, message.
local function run_cli(dir, tag)
    local sub = work .. "/cli-" .. tag
    assert(os.execute("mkdir -p '" .. sub .. "'"))
    write_file(sub .. "/input-0.bin", string.rep("\0", OVERSIZED))
    local mch = sub .. "/mch.bin"
    local cmd = string.format(
        "cd '%s' && timeout 300 lua5.4 '%s/src/cartesi-machine.lua' --no-init-splash "
            .. "--remote-spawn --remote-address=127.0.0.1:0 --remote-shutdown --load='%s' "
            .. "--cmio-advance-state=input:input-%%i.bin,input_file_index_begin:0,input_file_index_end:1 "
            .. "--mcycle-computation-hash=log2_mcycle_period:4,filename:mch.bin > log.txt 2>&1",
        sub,
        os.getenv("REPO_DIR"),
        dir
    )
    local ok = os.execute(cmd)
    local log = assert(io.open(sub .. "/log.txt", "rb")):read("a")
    local f = io.open(mch, "rb")
    local has_mch = f ~= nil
    if f then
        f:close()
    end
    local why = log:match("[^\n]*expected outputs Merkle root[^\n]*")
        or log:match("[^\n]*Merkle root mismatch[^\n]*")
        or log:match("[^\n]*assert[^\n]*")
        or ""
    return (ok and has_mch) and true or false, why
end

local failures = {}
local result, herr = pcall(function()
    assert(os.execute("bash ./build.sh '" .. work .. "' 0 32"), "guest build failed")
    local dir0, hash0 = make_template(0)
    local dir32, hash32 = make_template(32)
    local big_path = work .. "/input-big"
    local big = string.rep("\0", OVERSIZED)
    write_file(big_path, big)
    local small_path = work .. "/input-small"
    write_file(small_path, "hello")
    check_noop(dir0, hash0, big)
    check_noop(dir32, hash32, big)

    -- Controls (must pass, or the harness is wrong).
    local ok, err = run_player(dir32, hash32, big_path)
    assert(ok, "control (player, DATA=32, oversized input) failed: " .. tostring(err))
    ok, err = run_player(dir0, hash0, small_path)
    assert(ok, "control (player, DATA=0, small input) failed: " .. tostring(err))
    ok, err = run_cli(dir32, "32")
    assert(ok, "control (CLI, DATA=32, oversized input) failed: " .. tostring(err))

    -- Subject.
    ok, err = run_player(dir0, hash0, big_path)
    if not ok then
        failures[#failures + 1] = "honest player input_added raised '" .. tostring(err) .. "'"
    end
    ok, err = run_cli(dir0, "0")
    if not ok then
        failures[#failures + 1] = "cartesi-machine CLI aborted without a computation hash ('" .. tostring(err) .. "')"
    end
end)
cleanup()
if not result then
    io.stderr:write("harness error: " .. tostring(herr) .. "\n")
    os.exit(2)
end
if #failures > 0 then
    io.write(
        "FAIL: on a valid template whose accepted yield has tohost DATA = 0 (tx buffer holds the correct empty "
            .. "outputs root), a provable no-op oversized input makes the honest claim computers crash, because they "
            .. "read the root with the guest's DATA as length (R4/A5): "
            .. table.concat(failures, "; ")
            .. "\n"
    )
    os.exit(1)
end
io.write("OK: oversized no-op input processed by the player and the CLI on a DATA = 0 template\n")
os.exit(0)
