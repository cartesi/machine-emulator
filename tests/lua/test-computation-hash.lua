#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: Apache-2.0

local cartesi = require("cartesi")
local filesystem = require("cartesi.filesystem")
local hash_tree = require("cartesi.hash-tree")
local util = require("cartesi.util")
local tests_util = require("cartesi.tests.util")
local fcntl = require("posix.fcntl")
local unistd = require("posix.unistd")
local syswait = require("posix.sys.wait")

local artifact_dir = assert(os.getenv("CARTESI_COMPUTATION_HASH_CORPUS_PATH"), "corpus path is not set")
local manifest = cartesi.fromjson(filesystem.read_file(artifact_dir .. "/manifest.json"))
local cli = os.getenv("CM_CLI") or "cartesi-machine.lua"
local cli_lua = os.getenv("LUA_CLI") or arg[-1]
local recording = os.getenv("RECORD_COMPUTATION_HASH_CORPUS") == "yes"
local case_filter = os.getenv("COMPUTATION_HASH_CASE")
local case_skip = os.getenv("COMPUTATION_HASH_SKIP")

assert(not recording or (not case_filter and not case_skip), "recording requires the complete corpus")

local function file_exists(path)
    local file = io.open(path, "rb")
    if not file then
        return false
    end
    file:close()
    return true
end

local function output_path(recorded_path)
    if recording then
        return nil, recorded_path
    end
    local path = filesystem.temp_pathname()
    return tests_util.scope_exit(function()
        os.remove(path)
    end), path
end

local function replace_plain(value, old, new)
    local first, last = value:find(old, 1, true)
    if not first then
        return value
    end
    return value:sub(1, first - 1) .. new .. value:sub(last + 1)
end

local function run_case(case)
    local _ <close>, stdout_path = output_path(artifact_dir .. "/results/" .. case.id .. ".stdout")
    local _ <close>, stderr_path = output_path(artifact_dir .. "/results/" .. case.id .. ".stderr")
    local recorded_hash_path = artifact_dir .. "/" .. case.result
    local _ <close>, hash_path = output_path(recorded_hash_path)
    os.remove(stdout_path)
    os.remove(stderr_path)
    os.remove(hash_path)

    local argv = {}
    for word in cli_lua:gmatch("%S+") do
        argv[#argv + 1] = word
    end
    argv[#argv + 1] = cli
    for i = 2, #case.argv do
        argv[#argv + 1] = replace_plain(case.argv[i], case.result, hash_path)
    end
    local pid = assert(unistd.fork())
    if pid == 0 then
        assert(unistd.chdir(artifact_dir))
        local stdin = assert(fcntl.open("/dev/null", fcntl.O_RDONLY))
        local stdout = assert(fcntl.open(stdout_path, fcntl.O_WRONLY | fcntl.O_CREAT | fcntl.O_TRUNC, 420))
        local stderr = assert(fcntl.open(stderr_path, fcntl.O_WRONLY | fcntl.O_CREAT | fcntl.O_TRUNC, 420))
        assert(unistd.dup2(stdin, unistd.STDIN_FILENO))
        assert(unistd.dup2(stdout, unistd.STDOUT_FILENO))
        assert(unistd.dup2(stderr, unistd.STDERR_FILENO))
        unistd.close(stdin)
        unistd.close(stdout)
        unistd.close(stderr)
        local args = { table.unpack(argv, 2) }
        local _, message = unistd.execp(argv[1], args)
        io.stderr:write(message .. "\n")
        os.exit(127)
    end
    local waited_pid, reason, rc = assert(syswait.wait(pid))
    assert(waited_pid == pid)
    assert(reason == "exited", string.format("%s: command terminated because it was %s", case.id, reason))
    local stdout = filesystem.read_file(stdout_path)
    local stderr = filesystem.read_file(stderr_path)
    local category = case.expected.category
    local wants_success = category == "success-hash"
    assert((rc == 0) == wants_success, string.format("%s: unexpected exit status %d\n%s", case.id, rc, stderr))
    if not recording then
        assert(
            rc == case.expected.exit_status,
            string.format("%s: expected exit status %d, got %d", case.id, case.expected.exit_status, rc)
        )
    end

    local wants_hash = category == "success-hash" or category == "nonzero-hash"
    assert(file_exists(hash_path) == wants_hash, case.id .. ": unexpected hash-file presence")
    if wants_hash then
        local hash = filesystem.read_file(hash_path)
        assert(#hash == cartesi.HASH_SIZE, case.id .. ": computation hash is not 32 bytes")
        local label = case.level == "mcycle" and "Mcycle computation hash:" or "Uarch cycle computation hash:"
        local printed = stderr:match(label .. "%s*(0x%x+)")
        assert(printed, case.id .. ": computation hash was not printed")
        assert(cartesi.fromhex(printed) == hash, case.id .. ": printed and stored hashes differ")
        if not recording then
            assert(
                case.expected.computation_hash:match("^0x[0-9a-f][0-9a-f]+$") and #case.expected.computation_hash == 66,
                case.id .. ": invalid manifest computation hash"
            )
            assert(
                case.expected.computation_hash == cartesi.tohex(hash),
                case.id .. ": fresh computation hash differs from manifest"
            )
            assert(
                filesystem.read_file(recorded_hash_path) == hash,
                case.id .. ": fresh computation hash differs from recorded binary result"
            )
        end
    else
        assert(not stderr:find("computation hash:", 1, true), case.id .. ": unexpectedly printed a hash")
        assert(not case.expected.computation_hash, case.id .. ": no-hash case has a manifest computation hash")
    end

    if case.expected.stderr_contains then
        assert(
            stderr:find(case.expected.stderr_contains, 1, true),
            case.id .. ": missing diagnostic " .. case.expected.stderr_contains
        )
    end
    if case.expected.terminal_mcycle then
        local last
        for value in stderr:gmatch("Cycles:%s*(%d+)") do
            last = value
        end
        assert(
            last == tostring(case.expected.terminal_mcycle),
            string.format(
                "%s: expected terminal mcycle %s, got %s",
                case.id,
                tostring(case.expected.terminal_mcycle),
                tostring(last)
            )
        )
    end
    return {
        exit_status = rc,
        hash = wants_hash and filesystem.read_file(hash_path) or nil,
        stderr = stderr,
        stdout = stdout,
    }
end

local function double_hash(hash, count)
    for _ = 1, count do
        hash = cartesi.keccak256(hash, hash)
    end
    return hash
end

local function check_empty_mcycle(case)
    local machine <close> = cartesi.machine(artifact_dir .. "/" .. case.template)
    local height = cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
        + cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
        - case.geometry.log2_mcycle_period
    assert(
        filesystem.read_file(artifact_dir .. "/" .. case.result) == double_hash(machine:get_root_hash(), height),
        case.id .. ": empty-epoch independent reconstruction differs"
    )
    local forest = hash_tree.frontier_forest(height, "keccak256")
    hash_tree.frontier_forest_pad_back(forest, machine:get_root_hash(), 1 << height)
    assert(
        hash_tree.frontier_forest_get_root_hash(forest) == double_hash(machine:get_root_hash(), height),
        case.id .. ": forest-assembled empty epoch differs"
    )
end

local function check_small_mcycle(case)
    local machine <close> = cartesi.machine(artifact_dir .. "/" .. case.template)
    local input = filesystem.read_file(artifact_dir .. "/" .. case.inputs[1])
    machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, machine:get_root_hash())
    local period = 1 << case.geometry.log2_mcycle_period
    local first_sample = case.geometry.initial_mcycle + period
    assert(machine:run(first_sample) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    local sample_hash = machine:get_root_hash()
    assert(machine:run(math.maxinteger) == cartesi.BREAK_REASON_YIELDED_MANUALLY)
    local final_hash = machine:get_root_hash()
    local height = cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
        + cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
        - case.geometry.log2_mcycle_period
    local frontier = hash_tree.frontier(height, "keccak256")
    hash_tree.frontier_push_back(frontier, sample_hash)
    hash_tree.frontier_pad_back(frontier, final_hash, (1 << height) - 1)
    assert(
        filesystem.read_file(artifact_dir .. "/" .. case.result) == hash_tree.frontier_get_root_hash(frontier),
        case.id .. ": independently assembled mcycle tree differs"
    )
    local forest = hash_tree.frontier_forest(height, "keccak256")
    hash_tree.frontier_forest_push_back(forest, sample_hash)
    hash_tree.frontier_forest_pad_back(forest, final_hash, (1 << height) - 1)
    assert(
        hash_tree.frontier_forest_get_root_hash(forest) == hash_tree.frontier_get_root_hash(frontier),
        case.id .. ": forest-assembled mcycle tree differs"
    )
end

local function uarch_mcycle_root(collected, mcycle_index, log2_bundles_per_mcycle)
    local first = collected.mcycle_hash_offsets[mcycle_index]
    local last = collected.mcycle_hash_offsets[mcycle_index + 1] - 1
    local frontier = hash_tree.frontier(log2_bundles_per_mcycle, "keccak256")
    for i = first, last - 2 do
        hash_tree.frontier_push_back(frontier, collected.hashes[i])
    end
    local execution_count = last - first - 1
    hash_tree.frontier_pad_back(
        frontier,
        collected.hashes[last - 1],
        (1 << log2_bundles_per_mcycle) - 1 - execution_count
    )
    hash_tree.frontier_push_back(frontier, collected.hashes[last])
    return hash_tree.frontier_get_root_hash(frontier)
end

local function uarch_period_root(collected, log2_period, log2_bundles_per_mcycle)
    local period = 1 << log2_period
    local group_count = math.min(#collected.mcycle_hash_offsets - 1, period)
    local frontier = hash_tree.frontier(log2_period + log2_bundles_per_mcycle, "keccak256")
    for i = 1, group_count do
        hash_tree.frontier_push_back(
            frontier,
            uarch_mcycle_root(collected, i, log2_bundles_per_mcycle),
            log2_bundles_per_mcycle
        )
    end
    if group_count < period then
        hash_tree.frontier_pad_back(
            frontier,
            uarch_mcycle_root(collected, group_count, log2_bundles_per_mcycle),
            period - group_count,
            log2_bundles_per_mcycle
        )
    end
    return hash_tree.frontier_get_root_hash(frontier)
end

-- The frontier-forest counterpart of uarch_mcycle_root: one mcycle group assembled from the
-- real bundles, the repeated halt bundle, and the reset-ending bundle, as a complete forest.
local function forest_uarch_mcycle_group(collected, mcycle_index, log2_bundles_per_mcycle)
    local first = collected.mcycle_hash_offsets[mcycle_index]
    local last = collected.mcycle_hash_offsets[mcycle_index + 1] - 1
    local group = hash_tree.frontier_forest(log2_bundles_per_mcycle, "keccak256")
    hash_tree.frontier_forest_append(group, collected.hashes, first, last - 2)
    local execution_count = last - first - 1
    hash_tree.frontier_forest_pad_back(
        group,
        collected.hashes[last - 1],
        (1 << log2_bundles_per_mcycle) - 1 - execution_count
    )
    hash_tree.frontier_forest_push_back(group, collected.hashes[last])
    return group
end

-- The frontier-forest counterpart of uarch_period_root: groups append as complete forests,
-- and a fixed point repeats the last group across the remainder of the period.
local function forest_uarch_period_root(collected, log2_period, log2_bundles_per_mcycle)
    local period = 1 << log2_period
    local group_count = math.min(#collected.mcycle_hash_offsets - 1, period)
    local forest = hash_tree.frontier_forest(log2_period + log2_bundles_per_mcycle, "keccak256")
    for i = 1, group_count do
        hash_tree.frontier_forest_push_back(forest, forest_uarch_mcycle_group(collected, i, log2_bundles_per_mcycle))
    end
    if group_count < period then
        hash_tree.frontier_forest_pad_back(
            forest,
            forest_uarch_mcycle_group(collected, group_count, log2_bundles_per_mcycle),
            period - group_count
        )
    end
    return hash_tree.frontier_forest_get_root_hash(forest)
end

local function check_small_uarch(case)
    local log2_bundle = case.geometry.log2_bundle_uarch_cycle_count
    local log2_bundles_per_mcycle = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - log2_bundle
    local period = 1 << case.geometry.log2_mcycle_period
    local window_start = case.geometry.initial_mcycle + case.geometry.mcycle_period_index * period
    local window_end = window_start + period
    local input = filesystem.read_file(artifact_dir .. "/" .. case.inputs[1])

    local machine <close> = cartesi.machine(artifact_dir .. "/" .. case.template)
    local revert_tail = machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, 0).hashes
    machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, machine:get_root_hash())
    assert(machine:run(window_start) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    local collected = machine:collect_uarch_cycle_root_hashes(window_end, log2_bundle, revert_tail)

    local reference <close> = cartesi.machine(artifact_dir .. "/" .. case.template)
    reference:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, 0)
    reference:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, reference:get_root_hash())
    assert(reference:run(window_start) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)

    local boundaries <close> = cartesi.machine(artifact_dir .. "/" .. case.template)
    local boundary_revert_tail = boundaries:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, 0).hashes
    boundaries:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, boundaries:get_root_hash())
    assert(boundaries:run(window_start) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    local boundary_hashes = boundaries:collect_uarch_cycle_root_hashes(window_end, 0, boundary_revert_tail)

    local period_frontier = hash_tree.frontier(case.geometry.log2_mcycle_period + log2_bundles_per_mcycle, "keccak256")
    for mcycle_index = 1, period do
        hash_tree.frontier_push_back(
            period_frontier,
            uarch_mcycle_root(collected, mcycle_index, log2_bundles_per_mcycle),
            log2_bundles_per_mcycle
        )

        assert(reference:run(window_start + mcycle_index) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
        local boundary_last = boundary_hashes.mcycle_hash_offsets[mcycle_index + 1] - 1
        assert(
            reference:get_root_hash() == boundary_hashes.hashes[boundary_last],
            case.id .. ": reset-ending boundary does not match the mcycle state"
        )
    end
    assert(
        filesystem.read_file(artifact_dir .. "/" .. case.result) == hash_tree.frontier_get_root_hash(period_frontier),
        case.id .. ": independently assembled uarch tree differs"
    )
    assert(
        forest_uarch_period_root(collected, case.geometry.log2_mcycle_period, log2_bundles_per_mcycle)
            == hash_tree.frontier_get_root_hash(period_frontier),
        case.id .. ": forest-assembled uarch tree differs"
    )
end

local function check_uarch_mcycle_overflow(case)
    local log2_bundles_per_mcycle = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
        - case.geometry.log2_bundle_uarch_cycle_count
    local machine <close> = cartesi.machine(artifact_dir .. "/" .. case.template)
    assert(machine:read_reg("mcycle") == cartesi.MCYCLE_MAX - 255)
    local revert_tail = machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, 0).hashes
    local input = filesystem.read_file(artifact_dir .. "/" .. case.inputs[1])
    machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, machine:get_root_hash())
    local collected = machine:collect_uarch_cycle_root_hashes(
        cartesi.MCYCLE_MAX,
        case.geometry.log2_bundle_uarch_cycle_count,
        revert_tail
    )
    assert(
        collected.break_reason == cartesi.BREAK_REASON_MCYCLE_OVERFLOW,
        case.id .. ": independent collection did not reach mcycle overflow"
    )
    assert(machine:read_reg("mcycle") == cartesi.MCYCLE_MAX)
    assert(
        #collected.mcycle_hash_offsets == 257,
        case.id .. ": independent collection did not contain 255 transitions and the overflow fixed point"
    )
    assert(
        filesystem.read_file(artifact_dir .. "/" .. case.result)
            == uarch_period_root(collected, case.geometry.log2_mcycle_period, log2_bundles_per_mcycle),
        case.id .. ": independently assembled overflow window differs"
    )
    assert(
        forest_uarch_period_root(collected, case.geometry.log2_mcycle_period, log2_bundles_per_mcycle)
            == uarch_period_root(collected, case.geometry.log2_mcycle_period, log2_bundles_per_mcycle),
        case.id .. ": forest-assembled overflow window differs"
    )
end

local results = {}
local count = 0
for _, case in ipairs(manifest) do
    if
        (not case_filter or case.id:find(case_filter, 1, true))
        and (not case_skip or not case.id:find(case_skip, 1, true))
    then
        results[case.id] = run_case(case)
        count = count + 1
    end
end

for _, case in ipairs(manifest) do
    if results[case.id] and case.equivalent_to and results[case.equivalent_to] then
        local other = results[case.equivalent_to]
        assert(results[case.id].hash == other.hash, case.id .. ": equivalent cases produced different roots")
    end
    if results[case.id] and case.oracle == "empty-mcycle" then
        check_empty_mcycle(case)
    end
    if results[case.id] and case.oracle == "small-mcycle" then
        check_small_mcycle(case)
    end
    if results[case.id] and case.oracle == "small-uarch" then
        check_small_uarch(case)
    end
    if results[case.id] and case.oracle == "uarch-mcycle-overflow" then
        check_uarch_mcycle_overflow(case)
    end
    if results[case.id] then
        io.stderr:write(string.format("%s: passed\n", case.id))
    end
end

if recording then
    for _, case in ipairs(manifest) do
        local result = results[case.id]
        case.expected.exit_status = result.exit_status
        if result and result.hash then
            case.expected.computation_hash = cartesi.tohex(result.hash)
        else
            case.expected.computation_hash = nil
        end
    end
    util.write_file(cartesi.tojson(manifest, 2) .. "\n", artifact_dir .. "/manifest.json")
end

io.stdout:write(string.format("\nPASSED all %d tests\n\n", count))
