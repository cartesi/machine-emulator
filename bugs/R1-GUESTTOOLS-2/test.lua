#!/usr/bin/env lua5.4
-- R1-GUESTTOOLS-2: the honest PRT player (doc/recipes/prt.lua, flush_pending_outputs, called from
-- run_to_input_mcycle_offset in event_handler.input_added) asserts that the outputs Merkle root the guest
-- leaves in the transmit buffer at a manual rx-accepted yield equals the player's own outputs frontier:
--
--     assert(frontier_get_root_hash(outputs_frontier) == outputs_merkle_root, "outputs Merkle root mismatch")
--
-- The transmit buffer is opaque guest data (THREAT_MODEL section 4), and any assignment of guest-writable memory is
-- presumed reachable (section 2). R4 requires the honest operator to compute the claim from any reachable state.
-- The canonical hash of such a state is well defined: the emulator computes it, and the delivery and uarch-step
-- logs that lead to and leave it verify.
--
-- This test builds a valid template from a bare-metal guest (guest.S, built at test time) that writes the root of
-- the empty outputs tree to the transmit buffer and yields manual rx-accepted with DATA=32. After every delivered
-- input, the guest writes PARAM+0x20 to the transmit buffer and yields manual rx-accepted with a chosen DATA.
-- Variants:
--   control  : the true (empty-tree) root, DATA=32           -> the player must advance (harness sanity check)
--   garbage  : 32 bytes of 0xAA, DATA=32                       -> the player must still advance and seal
--   zero-data: the true root, but DATA=0                       -> the player must still advance and seal
-- For each, it delivers input 0 and input 1 through event_handler.input_added and seals the epoch, and requires all
-- three to succeed (the claim must be computable). It also shows, for contrast, that the emulator computes the
-- canonical hash of the state and that the delivery and following uarch-step logs verify.
-- Exits nonzero while the defect is present.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local fs = require("cartesi.filesystem")
local prt = require("prt")

local PARAM = 0x80001000
local TX = cartesi.AR_CMIO_TX_BUFFER_START

local function yield_word(reason, data_length)
    return (cartesi.HTIF_DEV_YIELD << cartesi.HTIF_DEV_SHIFT)
        | (cartesi.HTIF_YIELD_CMD_MANUAL << cartesi.HTIF_CMD_SHIFT)
        | (reason << cartesi.HTIF_REASON_SHIFT)
        | data_length
end

local EMPTY_ROOT =
    hash_tree.frontier_get_root_hash(hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"))
assert(#EMPTY_ROOT == 32, "harness error: empty outputs root")

local workdir = assert(io.popen("mktemp -d"):read("l"), "harness error: mktemp failed")
local _ <close> = setmetatable({}, {
    __close = function()
        os.execute("rm -rf '" .. workdir .. "'")
    end,
})
assert(os.execute("bash ./build.sh " .. workdir), "harness error: failed to build guest.bin")
local bin = workdir .. "/guest.bin"

local function new_template_machine(later_root, later_data_length)
    local m = cartesi.machine({
        ram = { backing_store = { data_filename = bin }, length = 1 << 20 },
    })
    m:write_memory(PARAM, EMPTY_ROOT .. later_root .. string.pack("<I8", yield_word(1, later_data_length)))
    local br = m:run(1000)
    assert(br == cartesi.BREAK_REASON_YIELDED_MANUALLY, "harness error: guest did not yield")
    assert(m:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED, "harness error: reason")
    assert(m:read_memory(TX, 32) == EMPTY_ROOT, "harness error: template does not hold the empty outputs root")
    return m
end

local function write_input(name, data)
    local path = workdir .. "/" .. name
    local f = assert(io.open(path, "wb"))
    f:write(data)
    f:close()
    return path
end

local input_paths = { write_input("input-0", "first input"), write_input("input-1", "second input") }

-- Emulator-side contrast: the canonical hash after input 0 is computable, and the delivery and the uarch step that
-- leaves the accepted state verify.
local function canonical_contrast(template_dir, template_hash)
    local m <close> = cartesi.machine(template_dir)
    assert(m:get_root_hash() == template_hash, "harness error: reloaded template hash")
    local before = m:get_root_hash()
    local log = m:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, "first input", template_hash)
    local after = m:get_root_hash()
    assert(
        cartesi.machine:verify_send_cmio_response(
            cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
            "first input",
            before,
            log,
            template_hash
        ) == after,
        "harness error: delivery log does not verify"
    )
    local br = m:run(m:read_reg("mcycle") + 1000)
    assert(br == cartesi.BREAK_REASON_YIELDED_MANUALLY, "harness error: guest did not yield after input")
    local h0 = m:get_root_hash()
    local ulog = m:log_step_uarch()
    assert(cartesi.machine:verify_step_uarch(h0, ulog) == m:get_root_hash(), "harness error: uarch step")
    return h0, m:read_memory(TX, 32)
end

local function run_variant(name, later_root, later_data_length)
    local template_dir = workdir .. "/" .. name
    local template_hash
    do
        local m <close> = new_template_machine(later_root, later_data_length)
        template_hash = m:get_root_hash()
        m:store(template_dir)
    end
    local canonical, tx_root = canonical_contrast(template_dir, template_hash)
    print(
        string.format(
            "[%s] template %s; after input 0 the emulator's canonical hash is %s (tx holds %s, DATA=%d)",
            name,
            cartesi.tohex(template_hash):sub(1, 18),
            cartesi.tohex(canonical):sub(1, 18),
            cartesi.tohex(tx_root):sub(1, 18),
            later_data_length
        )
    )
    local player <close> = prt.new_forked_player({
        initial_state_hash = template_hash,
        machine_directory = template_dir,
        geometry = prt.new_geometry(10),
    }, "honest")
    local steps = {
        { "input_added(0)", player.event_handler.input_added, player, 0, input_paths[1] },
        { "input_added(1)", player.event_handler.input_added, player, 1, input_paths[2] },
        { "epoch_sealed(2)", player.event_handler.epoch_sealed, player, 2 },
    }
    local errors = {}
    for _, step in ipairs(steps) do
        local ok, err = pcall(table.unpack(step, 2))
        print(string.format("[%s]   %s -> %s", name, step[1], ok and "ok" or ("ERROR: " .. tostring(err))))
        if not ok then
            errors[#errors + 1] = { step = step[1], err = tostring(err) }
        end
    end
    if #errors == 0 then
        assert(player.final_state_hash, "harness error: sealed player has no final state hash")
    end
    return errors
end

local failures = {}

-- Harness sanity: a guest that leaves the true root advances, seals, and claims.
local control = run_variant("control", EMPTY_ROOT, 32)
if #control ~= 0 then
    error("harness error: control variant failed: " .. control[1].step .. ": " .. control[1].err)
end

for _, v in ipairs({
    { "garbage", string.rep("\xAA", 32), 32 },
    { "zero-data", EMPTY_ROOT, 0 },
}) do
    local errors = run_variant(table.unpack(v))
    if #errors ~= 0 then
        local first = errors[1]
        if not first.err:find("outputs Merkle root mismatch", 1, true) then
            error("harness error: unexpected failure in " .. v[1] .. ": " .. first.err)
        end
        failures[#failures + 1] = string.format(
            "%s: %s raised 'outputs Merkle root mismatch'; then %s",
            v[1],
            first.step,
            errors[2] and (errors[2].step .. " raised '" .. errors[2].err .. "'") or "nothing"
        )
    end
end

if #failures > 0 then
    print(
        "FAIL: honest player cannot compute the claim from a reachable rx-accepted state whose transmit buffer does "
            .. "not match its outputs frontier (opaque guest data, R4/section 4), though the emulator computes its "
            .. "canonical hash and its logs verify:"
    )
    for _, f in ipairs(failures) do
        print("  " .. f)
    end
    os.exit(1)
end
print("OK: honest player computes the claim regardless of the guest-written outputs root")
