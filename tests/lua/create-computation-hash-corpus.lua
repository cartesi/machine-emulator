#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: Apache-2.0

local cartesi = require("cartesi")
local filesystem = require("cartesi.filesystem")
local util = require("cartesi.util")

local artifact_dir = assert(os.getenv("CARTESI_COMPUTATION_HASH_CORPUS_PATH"), "corpus path is not set")
local machine_tests_dir = assert(os.getenv("CARTESI_TESTS_PATH"), "machine tests path is not set")
local uarch_tests_dir = assert(os.getenv("CARTESI_TESTS_UARCH_PATH"), "uarch tests path is not set")

local function shell_quote(value)
    return "'" .. value:gsub("'", "'\\''") .. "'"
end

local function mkdir(path)
    local ok, _, status = os.execute("mkdir -p " .. shell_quote(path))
    assert(ok and status == 0, "failed to create " .. path)
end

for _, subdir in ipairs({ "templates", "inputs", "results" }) do
    mkdir(artifact_dir .. "/" .. subdir)
end

local guest_image = machine_tests_dir .. "/computation_hash.bin"
local near_limit_uarch_image = uarch_tests_dir .. "/rv64ui-uarch-computation-hash-near-limit.bin"
local overflow_uarch_image = uarch_tests_dir .. "/rv64ui-uarch-computation-hash-overflow.bin"

local function make_machine_config(options)
    options = options or {}
    return {
        processor = { registers = { pc = 0x80000000 } },
        ram = { length = 1 << 20, backing_store = { data_filename = guest_image } },
        cmio = { rx_buffer = {}, tx_buffer = {} },
        uarch = options.uarch_image and {
            processor = { registers = { pc = options.uarch_pc } },
            ram = { backing_store = { data_filename = options.uarch_image } },
        } or nil,
    }
end

local function make_template(options)
    local cleanup
    if options.custom_uarch_image then
        -- Keep the stock image at its normal entrypoint and place the boundary program elsewhere.
        -- The template starts at the custom PC once. Collector reset returns the PC to the stock
        -- entrypoint, while a later rejection reuses the separately captured custom tail.
        local custom_offset = cartesi.UARCH_RAM_LENGTH // 2
        local stock_machine <close> = cartesi.machine(make_machine_config())
        local stock_uarch_ram = stock_machine:read_memory(cartesi.UARCH_RAM_START_ADDRESS, cartesi.UARCH_RAM_LENGTH)
        local custom = util.read_file(options.custom_uarch_image)
        assert(custom_offset + #custom <= #stock_uarch_ram, "custom uarch program does not fit")
        assert(
            stock_uarch_ram:sub(custom_offset + 1, custom_offset + #custom) == string.rep("\0", #custom),
            "custom uarch program overlaps nonzero stock uarch RAM"
        )
        cleanup, options.uarch_image = filesystem.write_scope_temp_file(
            stock_uarch_ram:sub(1, custom_offset) .. custom .. stock_uarch_ram:sub(custom_offset + #custom + 1)
        )
        options.uarch_pc = cartesi.UARCH_RAM_START_ADDRESS + custom_offset
    end
    local _ <close> = cleanup

    io.stderr:write("Creating computation-hash template " .. options.name .. "\n")
    local machine <close> = cartesi.machine(make_machine_config(options))
    local break_reason = machine:run(math.maxinteger)
    assert(break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY, "guest did not reach its initial CMIO yield")
    assert(machine:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
    if options.configure then
        options.configure(machine)
    end
    local mcycle = machine:read_reg("mcycle")
    machine:store(artifact_dir .. "/templates/" .. options.name)
    return mcycle
end

-- Template: the CMIO guest is at its initial RX-accepted manual yield and the uarch is in its
-- stock state.
-- Use: this is the baseline starting state for cases that need no cycle-boundary fixture.
local initial_mcycle = make_template({ name = "normal" })

-- Template: the CMIO guest is at its initial RX-accepted manual yield with mcycle set to 255 cycles
-- before MCYCLE_MAX. The default imcyclemax remains MCYCLE_MAX.
-- Use: this places the next input against the cycle-counter boundary to test saturated input bounds
-- and mcycle-overflow fixed-point padding.
make_template({
    name = "mcycle-boundary",
    configure = function(machine)
        machine:write_reg("mcycle", cartesi.MCYCLE_MAX - 255)
    end,
})

-- Template: the CMIO guest is at its initial RX-accepted manual yield. A custom uarch program is
-- overlaid halfway through the zero-filled part of stock uarch RAM, and the uarch PC points to that
-- program. The program halts exactly at UARCH_CYCLE_MAX - 1 without reaching uarch-cycle overflow.
-- All other machine state matches the normal template.
-- Use: this verifies that revert-uarch-tail collection can reach the last valid uarch cycle, reset
-- to the stock uarch state, and reuse the captured near-limit tail for a later rejected input.
assert(make_template({
    name = "near-limit-uarch-tail",
    custom_uarch_image = near_limit_uarch_image,
}) == initial_mcycle)

-- Template: the CMIO guest is at its initial RX-accepted manual yield. An infinite loop is overlaid
-- halfway through the zero-filled part of stock uarch RAM, and the uarch PC points to that loop. All
-- other machine state matches the normal template.
-- Use: initial revert-uarch-tail collection runs the loop until uarch-cycle overflow, testing the
-- collector's exact overflow diagnostic before reset.
assert(make_template({
    name = "uarch-overflow-tail",
    custom_uarch_image = overflow_uarch_image,
}) == initial_mcycle)

do
    local machine <close> = cartesi.machine(artifact_dir .. "/templates/near-limit-uarch-tail")
    local mcycle = machine:read_reg("mcycle")
    assert(machine:run_uarch(cartesi.UARCH_CYCLE_MAX) == cartesi.UARCH_BREAK_REASON_UARCH_HALTED)
    assert(
        machine:read_reg("uarch_cycle") == cartesi.UARCH_CYCLE_MAX - 1,
        string.format("near-limit uarch calibration failed: reached %d", machine:read_reg("uarch_cycle"))
    )
    assert(machine:read_reg("mcycle") == mcycle, "near-limit uarch unexpectedly changed mcycle")
end

local actions = { accept = 0, reject = 1, exception = 2, halt = 3, ["manual-other"] = 4 }
local function encode_command(command)
    return string.pack(
        "<c4BBI2I8I8",
        "CHT1",
        assert(actions[command.action]),
        command.output_count or 0,
        command.manual_reason or 0,
        command.terminal_mcycle or 0,
        command.payload or 0
    )
end

do
    local machine <close> = cartesi.machine(artifact_dir .. "/templates/mcycle-boundary")
    machine:send_cmio_response(
        cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
        encode_command({ action = "accept", terminal_mcycle = cartesi.MCYCLE_MAX - 1 }),
        machine:get_root_hash()
    )
    local break_reason = machine:run(cartesi.MCYCLE_MAX)
    assert(
        break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY,
        string.format(
            "boundary calibration stopped with reason %d at mcycle %u",
            break_reason,
            machine:read_reg("mcycle")
        )
    )
    assert(machine:read_reg("mcycle") == cartesi.MCYCLE_MAX - 1)
end

do
    local machine <close> = cartesi.machine(artifact_dir .. "/templates/mcycle-boundary")
    machine:send_cmio_response(
        cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
        encode_command({ action = "accept", terminal_mcycle = cartesi.MCYCLE_MAX }),
        machine:get_root_hash()
    )
    assert(machine:run(cartesi.MCYCLE_MAX) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
    assert(machine:read_reg("mcycle") == cartesi.MCYCLE_MAX)
end

-- Probe the calibrated exact-cycle tail before publishing any boundary cases.
do
    local target = initial_mcycle + 256
    local machine <close> = cartesi.machine(artifact_dir .. "/templates/normal")
    machine:send_cmio_response(
        cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
        encode_command({ action = "accept", terminal_mcycle = target }),
        machine:get_root_hash()
    )
    assert(machine:run(math.maxinteger) == cartesi.BREAK_REASON_YIELDED_MANUALLY)
    assert(
        machine:read_reg("mcycle") == target,
        string.format("exact-cycle calibration failed: wanted %d, reached %d", target, machine:read_reg("mcycle"))
    )
end

local manifest = {}

local function expected_hash_structure(...)
    return "Expected hash structure: " .. table.concat({ ... }, " ")
end

local function add_case(case)
    local input_paths = {}
    for i, command in ipairs(case.commands or {}) do
        local path = string.format("inputs/%s-%d.bin", case.id, i - 1)
        util.write_file(encode_command(command), artifact_dir .. "/" .. path)
        input_paths[#input_paths + 1] = path
    end

    local hash_path = "results/" .. case.id .. ".bin"
    local advance = {
        "input_index_begin:0",
        "input_index_end:" .. #input_paths,
        "output:",
        "rejected_output:",
        "output_proof:",
        "report:",
        "outputs_merkle_root:",
        "outputs_merkle_root_proof:",
        "check_outputs_merkle_root:false",
        "log2_mcycle_computation_hash_period:" .. case.log2_period,
    }
    if #input_paths > 0 then
        advance[#advance + 1] = "input:inputs/" .. case.id .. "-%i.bin"
    end
    if case.level == "mcycle" then
        advance[#advance + 1] = "mcycle_computation_hash:" .. hash_path
        advance[#advance + 1] = "log2_bundle_mcycle_count:" .. (case.log2_bundle_mcycle or 0)
    else
        advance[#advance + 1] = "uarch_cycle_computation_hash:" .. hash_path
        advance[#advance + 1] = "mcycle_period_index:" .. case.period_index
        advance[#advance + 1] = "log2_bundle_uarch_cycle_count:" .. (case.log2_bundle_uarch or 16)
    end

    local argv = {
        "cartesi-machine.lua",
        "--load=templates/" .. case.template,
        "--cmio-advance-state=" .. table.concat(advance, ","),
    }
    if case.remote then
        argv[#argv + 1] = "--remote-spawn"
        argv[#argv + 1] = "--remote-address=127.0.0.1:0"
    else
        argv[#argv + 1] = "--no-revert"
    end
    argv[#argv + 1] = "--max-mcycle=" .. (case.max_mcycle or 2000000000)
    argv[#argv + 1] = "--no-init-splash"

    manifest[#manifest + 1] = {
        id = case.id,
        description = case.description,
        comment = assert(case.comment),
        level = case.level,
        template = "templates/" .. case.template,
        inputs = input_paths,
        geometry = {
            initial_mcycle = initial_mcycle,
            input_count = #input_paths,
            log2_mcycle_period = case.log2_period,
            mcycle_period_index = case.period_index,
            log2_bundle_mcycle_count = case.level == "mcycle" and (case.log2_bundle_mcycle or 0) or nil,
            log2_bundle_uarch_cycle_count = case.level == "uarch" and (case.log2_bundle_uarch or 16) or nil,
        },
        argv = argv,
        requires_jsonrpc = case.remote or false,
        result = hash_path,
        expected = case.expected,
        equivalent_to = case.equivalent_to,
        oracle = case.oracle,
    }
end

local mcycle_cases = {
    {
        id = "mcycle-empty",
        description = "Empty epoch",
        comment = expected_hash_structure(
            "every tree position repeats the epoch's initial fixed-point state root hash."
        ),
        template = "normal",
        commands = {},
        category = "success-hash",
        oracle = "empty-mcycle",
    },
    {
        id = "mcycle-accept",
        description = "One accepted input",
        comment = expected_hash_structure(
            "every position reserved for the input and unprocessed inputs repeats its final state root hash."
        ),
        template = "normal",
        commands = { { action = "accept", terminal_mcycle = initial_mcycle + 128 } },
        category = "success-hash",
        terminal_mcycle = initial_mcycle + 128,
    },
    {
        id = "mcycle-accept-remote",
        description = "Accepted input through snapshot and commit",
        comment = expected_hash_structure(
            "the same sampled state root hashes and final-state padding as mcycle-accept."
        ),
        template = "normal",
        commands = { { action = "accept", terminal_mcycle = initial_mcycle + 128 } },
        category = "success-hash",
        terminal_mcycle = initial_mcycle + 128,
        remote = true,
        equivalent_to = "mcycle-accept",
    },
    {
        id = "mcycle-multiple",
        description = "Multiple accepted inputs",
        comment = expected_hash_structure(
            "each input's reserved positions repeat its final state root hash.",
            "Unprocessed inputs repeat the epoch's final state root hash."
        ),
        template = "normal",
        commands = {
            { action = "accept", terminal_mcycle = initial_mcycle + 128 },
            { action = "accept", terminal_mcycle = initial_mcycle + 256 },
        },
        category = "success-hash",
        terminal_mcycle = initial_mcycle + 256,
    },
    {
        id = "mcycle-output",
        description = "Automatic TX output inside an input",
        comment = expected_hash_structure(
            "after automatic-output handling, all reserved positions repeat the input's final state root hash."
        ),
        template = "normal",
        commands = { { action = "accept", output_count = 2, terminal_mcycle = initial_mcycle + 256 } },
        category = "success-hash",
        terminal_mcycle = initial_mcycle + 256,
    },
    {
        id = "mcycle-reject-accept",
        description = "Rejected input followed by an accepted input",
        comment = expected_hash_structure(
            "positions for the rejected input use its recorded revert root hash.",
            "Later positions repeat the accepted input's final state root hash."
        ),
        template = "normal",
        commands = {
            { action = "reject", terminal_mcycle = initial_mcycle + 128 },
            { action = "accept", terminal_mcycle = initial_mcycle + 256 },
        },
        category = "success-hash",
        terminal_mcycle = initial_mcycle + 256,
        remote = true,
    },
    {
        id = "mcycle-reject-final",
        description = "Final rejected input pads the epoch with its revert root",
        comment = expected_hash_structure(
            "positions for the accepted input repeat its final state root hash.",
            "The rejected and unprocessed input positions use the recorded revert root hash."
        ),
        template = "normal",
        commands = {
            { action = "accept", terminal_mcycle = initial_mcycle + 128 },
            { action = "reject", terminal_mcycle = initial_mcycle + 256 },
        },
        category = "success-hash",
        terminal_mcycle = initial_mcycle + 256,
        remote = true,
    },
    {
        id = "mcycle-exception",
        description = "CMIO exception during an input",
        comment = expected_hash_structure(
            "the state root hash at the exception fixed point repeats through all remaining tree positions."
        ),
        template = "normal",
        commands = { { action = "exception", terminal_mcycle = initial_mcycle + 128, payload = 17 } },
        category = "nonzero-hash",
        terminal_mcycle = initial_mcycle + 128,
    },
    {
        id = "mcycle-halt",
        description = "Halt during an input",
        comment = expected_hash_structure(
            "the state root hash at the halt fixed point repeats through all remaining tree positions."
        ),
        template = "normal",
        commands = { { action = "halt", terminal_mcycle = initial_mcycle + 128 } },
        category = "success-hash",
        terminal_mcycle = initial_mcycle + 128,
    },
    {
        id = "mcycle-halt-nonzero",
        description = "Nonzero halt payload preserves the computation hash",
        comment = expected_hash_structure(
            "the state root hash at the nonzero halt fixed point repeats through all remaining positions."
        ),
        template = "normal",
        commands = { { action = "halt", terminal_mcycle = initial_mcycle + 128, payload = 7 } },
        category = "nonzero-hash",
        terminal_mcycle = initial_mcycle + 128,
    },
    {
        id = "mcycle-manual-other",
        description = "Unexpected manual-yield reason",
        comment = expected_hash_structure(
            "the unexpected-manual-yield fixed-point state root hash fills every remaining tree position."
        ),
        template = "normal",
        commands = {
            { action = "manual-other", manual_reason = 9, terminal_mcycle = initial_mcycle + 128, payload = 23 },
        },
        category = "nonzero-hash",
        stderr_contains = "Unexpected manual yield reason",
    },
    {
        id = "mcycle-before-first-sample",
        description = "Fixed point before the first sample",
        comment = expected_hash_structure(
            "no periodic sampling point is reached. Every position repeats the final state root hash."
        ),
        template = "normal",
        commands = { { action = "accept", terminal_mcycle = initial_mcycle + 128 } },
        category = "success-hash",
        terminal_mcycle = initial_mcycle + 128,
    },
    {
        id = "mcycle-on-sample",
        description = "Fixed point exactly on a sample boundary",
        comment = expected_hash_structure(
            "the state root hash collected after the first 2^19 machine cycles is also the fixed-point",
            "state root hash used to fill the remaining tree positions."
        ),
        template = "normal",
        commands = { { action = "accept", terminal_mcycle = initial_mcycle + (1 << 19) } },
        category = "success-hash",
        terminal_mcycle = initial_mcycle + (1 << 19),
    },
    {
        id = "mcycle-inside-sample",
        description = "Fixed point inside a sampling period",
        comment = expected_hash_structure(
            "the state root hash collected after the first 2^19 machine cycles is followed by repetitions",
            "of the final state root hash reached 127 machine cycles later."
        ),
        template = "normal",
        commands = { { action = "accept", terminal_mcycle = initial_mcycle + (1 << 19) + 127 } },
        category = "success-hash",
        terminal_mcycle = initial_mcycle + (1 << 19) + 127,
        oracle = "small-mcycle",
    },
    {
        id = "mcycle-bundled",
        description = "Bundled form of the accepted-input claim",
        comment = expected_hash_structure(
            "the same tree as mcycle-accept, collected as bundle root hashes covering 2^8 state root hashes each."
        ),
        template = "normal",
        commands = { { action = "accept", terminal_mcycle = initial_mcycle + 128 } },
        category = "success-hash",
        terminal_mcycle = initial_mcycle + 128,
        log2_bundle_mcycle = 8,
        equivalent_to = "mcycle-accept",
    },
    {
        id = "mcycle-before-input-maximum",
        description = "Fixed point one cycle before the saturated input maximum",
        comment = expected_hash_structure(
            "no periodic sampling point is reached.",
            "The MCYCLE_MAX-1 final state root hash pads every reserved position."
        ),
        template = "mcycle-boundary",
        commands = { { action = "accept", terminal_mcycle = cartesi.MCYCLE_MAX - 1 } },
        category = "success-hash",
        terminal_mcycle = "18446744073709551614",
        max_mcycle = "0xffffffffffffffff",
    },
    {
        id = "mcycle-at-input-maximum",
        description = "Exact saturated input maximum with overflow precedence",
        comment = expected_hash_structure(
            "no periodic sampling point is reached.",
            "The mcycle-overflow fixed-point state root hash pads every reserved position."
        ),
        template = "mcycle-boundary",
        commands = { { action = "accept", terminal_mcycle = cartesi.MCYCLE_MAX } },
        category = "nonzero-hash",
        terminal_mcycle = "18446744073709551615",
        stderr_contains = "Mcycle overflow",
        max_mcycle = "0xffffffffffffffff",
    },
}

for _, case in ipairs(mcycle_cases) do
    case.level = "mcycle"
    case.log2_period = 19
    case.expected = {
        category = case.category,
        terminal_mcycle = case.terminal_mcycle,
        stderr_contains = case.stderr_contains,
    }
    add_case(case)
end

-- Use the smallest period whose epoch computation hash tree does not exceed height 63.
local UARCH_LOG2_PERIOD = cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
    + cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
    - 63
local window_start = initial_mcycle + 1024
local window_index = (window_start - initial_mcycle) >> UARCH_LOG2_PERIOD
local function add_uarch_case(case)
    case.level = "uarch"
    case.log2_period = UARCH_LOG2_PERIOD
    case.period_index = case.period_index or window_index
    case.expected = {
        category = case.category,
        terminal_mcycle = case.terminal_mcycle,
        stderr_contains = case.stderr_contains,
    }
    add_case(case)
end

-- Each mcycle subtree below covers state root hashes after uarch cycles, repetitions of the halted
-- state root hash, and the state root hash after reset, as defined by collect_uarch_cycle_root_hashes.

add_uarch_case({
    id = "uarch-empty",
    description = "Empty epoch",
    comment = expected_hash_structure(
        "the subtree root of the final fixed-point, reset-delimited mcycle fills every position",
        "in the selected mcycle period."
    ),
    template = "normal",
    commands = {},
    category = "success-hash",
    period_index = 7,
})
add_uarch_case({
    id = "uarch-target-never-processed",
    description = "Target input is never processed",
    comment = expected_hash_structure(
        "the subtree root of the epoch's final fixed-point, reset-delimited mcycle fills",
        "the selected mcycle period."
    ),
    template = "normal",
    commands = {},
    category = "success-hash",
    period_index = 1 << (48 - UARCH_LOG2_PERIOD),
})
add_uarch_case({
    id = "uarch-before-window",
    description = "Target input terminates before the selected window",
    comment = expected_hash_structure(
        "the subtree root of the input's final fixed-point, reset-delimited mcycle fills",
        "the selected mcycle period."
    ),
    template = "normal",
    commands = { { action = "accept", terminal_mcycle = initial_mcycle + 120 } },
    category = "success-hash",
    terminal_mcycle = initial_mcycle + 120,
})
add_uarch_case({
    id = "uarch-window-start",
    description = "Fixed point at window start",
    comment = expected_hash_structure(
        "the subtree root of the fixed-point, reset-delimited mcycle at the period start",
        "fills every mcycle position."
    ),
    template = "normal",
    commands = { { action = "accept", terminal_mcycle = window_start } },
    category = "success-hash",
    terminal_mcycle = window_start,
})
add_uarch_case({
    id = "uarch-first",
    description = "Fixed point at first mcycle position",
    comment = expected_hash_structure(
        "one collected mcycle subtree root is followed by 511 copies of the fixed-point mcycle subtree root."
    ),
    template = "normal",
    commands = { { action = "accept", terminal_mcycle = window_start + 1 } },
    category = "success-hash",
    terminal_mcycle = window_start + 1,
})
add_uarch_case({
    id = "uarch-middle",
    description = "Fixed point in the middle of the selected window",
    comment = expected_hash_structure(
        "256 collected mcycle subtree roots are followed by 256 copies of the fixed-point mcycle subtree root."
    ),
    template = "normal",
    commands = { { action = "accept", terminal_mcycle = window_start + 256 } },
    category = "success-hash",
    terminal_mcycle = window_start + 256,
})
add_uarch_case({
    id = "uarch-penultimate",
    description = "Fixed point at the penultimate window position",
    comment = expected_hash_structure(
        "511 collected mcycle subtree roots are followed by one fixed-point mcycle subtree root."
    ),
    template = "normal",
    commands = { { action = "accept", terminal_mcycle = window_start + 511 } },
    category = "success-hash",
    terminal_mcycle = window_start + 511,
})
add_uarch_case({
    id = "uarch-final",
    description = "Fixed point at the final window boundary",
    comment = expected_hash_structure(
        "all 512 mcycle positions contain collected mcycle subtree roots. No fixed-point padding remains."
    ),
    template = "normal",
    commands = { { action = "accept", terminal_mcycle = window_start + 512 } },
    category = "success-hash",
    terminal_mcycle = window_start + 512,
})
add_uarch_case({
    id = "uarch-after-window",
    description = "Fixed point immediately after the selected window",
    comment = expected_hash_structure(
        "all 512 mcycle positions contain collected mcycle subtree roots.",
        "Termination is beyond the selected period."
    ),
    template = "normal",
    commands = { { action = "accept", terminal_mcycle = window_start + 513 } },
    category = "success-hash",
    terminal_mcycle = window_start + 513,
    oracle = "small-uarch",
})
add_uarch_case({
    id = "uarch-output",
    description = "Automatic TX output while collecting the selected window",
    comment = expected_hash_structure(
        "all 512 mcycle positions contain collected mcycle subtree roots,",
        "including collection resumed after the automatic yield."
    ),
    template = "normal",
    commands = { { action = "accept", output_count = 1, terminal_mcycle = window_start + 512 } },
    category = "success-hash",
    terminal_mcycle = window_start + 512,
})
add_uarch_case({
    id = "uarch-reject",
    description = "Rejection substitutes the captured revert-uarch tail",
    comment = expected_hash_structure(
        "four mcycle subtree roots advance the main processor to the rejected manual yield.",
        "The revert uarch tail's subtree root fills the remaining positions."
    ),
    template = "normal",
    commands = { { action = "reject", terminal_mcycle = window_start + 4 } },
    category = "success-hash",
    terminal_mcycle = window_start + 4,
    remote = true,
})
add_uarch_case({
    id = "uarch-exception",
    description = "CMIO exception in the selected window",
    comment = expected_hash_structure(
        "four mcycle subtree roots advance the main processor, followed by copies of the exception",
        "fixed-point, reset-delimited mcycle subtree root."
    ),
    template = "normal",
    commands = { { action = "exception", terminal_mcycle = window_start + 4, payload = 17 } },
    category = "nonzero-hash",
    terminal_mcycle = window_start + 4,
})
add_uarch_case({
    id = "uarch-halt",
    description = "Halt in the selected window",
    comment = expected_hash_structure(
        "four mcycle subtree roots advance the main processor, followed by copies of the halt",
        "fixed-point, reset-delimited mcycle subtree root."
    ),
    template = "normal",
    commands = { { action = "halt", terminal_mcycle = window_start + 4 } },
    category = "success-hash",
    terminal_mcycle = window_start + 4,
})
add_uarch_case({
    id = "uarch-mcycle-overflow",
    description = "Mcycle overflow terminates the target input",
    comment = expected_hash_structure(
        "255 mcycle subtree roots advance the main processor, followed by 257 copies of the",
        "mcycle-overflow fixed-point, reset-delimited mcycle subtree root."
    ),
    template = "mcycle-boundary",
    commands = { { action = "accept", terminal_mcycle = cartesi.MCYCLE_MAX } },
    category = "nonzero-hash",
    terminal_mcycle = "18446744073709551615",
    period_index = 0,
    max_mcycle = "0xffffffffffffffff",
    stderr_contains = "Mcycle overflow",
    oracle = "uarch-mcycle-overflow",
})
add_uarch_case({
    id = "uarch-manual-other",
    description = "Unexpected manual yield while collecting the selected window",
    comment = expected_hash_structure(
        "four mcycle subtree roots advance the main processor, followed by copies of the",
        "unexpected-manual-yield fixed-point, reset-delimited mcycle subtree root."
    ),
    template = "normal",
    commands = {
        { action = "manual-other", manual_reason = 9, terminal_mcycle = window_start + 4, payload = 23 },
    },
    category = "nonzero-hash",
    stderr_contains = "Unexpected manual yield reason",
})
add_uarch_case({
    id = "uarch-near-limit-tail",
    description = "Near-limit custom revert tail is captured, reset, and reused on rejection",
    comment = expected_hash_structure(
        "four mcycle subtree roots advance the main processor to the rejected manual yield.",
        "The captured near-limit revert uarch tail's subtree root fills the remaining positions."
    ),
    template = "near-limit-uarch-tail",
    commands = { { action = "reject", terminal_mcycle = window_start + 4 } },
    category = "success-hash",
    terminal_mcycle = window_start + 4,
    remote = true,
})
add_uarch_case({
    id = "uarch-overflow-tail",
    description = "Exact overflow while collecting the boundary revert-uarch tail",
    comment = expected_hash_structure(
        "none. Collecting the initial revert uarch tail reaches uarch-cycle overflow before",
        "the selected mcycle period can be determined."
    ),
    template = "uarch-overflow-tail",
    commands = { { action = "accept", terminal_mcycle = window_start + 4 } },
    category = "error-no-hash",
    stderr_contains = "uarch reached its maximum cycle and cannot advance more uarch cycles",
})
add_uarch_case({
    id = "uarch-bundled",
    description = "Alternative bundle size preserves the selected-window root",
    comment = expected_hash_structure(
        "the same tree as uarch-after-window, collected as bundle root hashes covering",
        "2^8 state root hashes after uarch cycles each."
    ),
    template = "normal",
    commands = { { action = "accept", terminal_mcycle = window_start + 513 } },
    category = "success-hash",
    terminal_mcycle = window_start + 513,
    log2_bundle_uarch = 8,
    equivalent_to = "uarch-after-window",
})

util.write_file(cartesi.tojson(manifest, 2) .. "\n", artifact_dir .. "/manifest.json")
io.stderr:write("Created " .. artifact_dir .. "/manifest.json\n")
