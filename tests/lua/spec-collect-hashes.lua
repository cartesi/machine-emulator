--[[
Test suite for collecting root hashes.
]]

local lester = require("cartesi.third-party.lester")
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local tabular = require("cartesi.tabular")
local utils = require("cartesi.utils")
local tests_util = require("cartesi.tests.util")
local has_posix, unistd = pcall(require, "posix.unistd")

local function expect_consistent_root_hash(machine)
    local root_hash = machine:get_root_hash()
    local node_hash = machine:get_node_hash(0, cartesi.HASH_TREE_LOG2_ROOT_SIZE)
    local external_root_hash = tests_util.calculate_emulator_hash(machine)
    expect.equal(root_hash, node_hash)
    expect.equal(external_root_hash, root_hash)
    return root_hash
end

local function expect_mcycle_root_hashes(machine, mcycle_end, mcycle_period, mcycle_phase, log2_bundle_mcycle_count)
    -- this reference implementation does not support the following conditions
    assert(mcycle_end >= 0 and mcycle_end <= math.maxinteger)
    assert(machine:read_reg("iflags_H") == 0, "unsupported call")
    assert(machine:read_reg("iflags_Y") == 0, "unsupported call")
    local break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
    local hashes = {}
    local mcycle_start = machine:read_reg("mcycle")
    local mcycle_first_target = mcycle_start + mcycle_period - mcycle_phase
    local at_fixed_point = false
    for mcycle_target = mcycle_first_target, mcycle_end, mcycle_period do
        break_reason = machine:run(mcycle_target)
        expect_consistent_root_hash(machine)
        if machine:read_reg("mcycle") ~= mcycle_target then
            mcycle_phase = mcycle_period - (mcycle_target - machine:read_reg("mcycle"))
            if break_reason == cartesi.BREAK_REASON_HALTED or break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY then
                table.insert(hashes, machine:get_root_hash())
                at_fixed_point = true
            end
            break
        end
        mcycle_phase = 0
        table.insert(hashes, machine:get_root_hash())
        if break_reason ~= cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then
            if break_reason == cartesi.BREAK_REASON_HALTED or break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY then
                at_fixed_point = true
            end
            break
        end
    end
    if break_reason == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then
        -- this reference implementation does not support partial period
        assert(machine:read_reg("mcycle") == mcycle_end, "unsupported call")
    end
    local back_tree
    if log2_bundle_mcycle_count and log2_bundle_mcycle_count > 0 then
        local bundle_mcycle_count = 1 << log2_bundle_mcycle_count
        if at_fixed_point then
            -- add last root hash padding until last bundle is complete
            while #hashes % bundle_mcycle_count ~= 0 do
                table.insert(hashes, hashes[#hashes])
            end
            -- add a bundle with repetitions of the last root hash
            for _ = 1, bundle_mcycle_count do
                table.insert(hashes, hashes[#hashes])
            end
        elseif #hashes % bundle_mcycle_count ~= 0 then
            back_tree = {
                log2_max_leaves = log2_bundle_mcycle_count,
                leaf_count = #hashes % bundle_mcycle_count,
                hash_function = machine:get_initial_config().hash_tree.hash_function,
                context = {},
            }
        end
        -- bundle the root hashes
        for _ = 1, log2_bundle_mcycle_count do
            local next_hashes = {}
            for i = 0, #hashes // 2 - 1 do
                table.insert(next_hashes, cartesi.keccak256(hashes[i * 2 + 1], hashes[i * 2 + 2]))
            end
            if #hashes % 2 == 1 then
                table.insert(back_tree.context, hashes[#hashes])
            end
            hashes = next_hashes
        end
    end
    return {
        hashes = hashes,
        break_reason = break_reason,
        mcycle_phase = mcycle_phase,
        back_tree = back_tree,
    }
end

local function expect_next_mcycle_uarch_root_hashes(
    machine,
    mcycle,
    hashes,
    reset_indices,
    log2_bundle_uarch_cycle_count
)
    for uarch_cycle = 1, math.maxinteger do
        if machine:run_uarch(uarch_cycle) == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then
            break
        end
        table.insert(hashes, machine:get_root_hash())
        if uarch_cycle % 200 == 0 then -- checking every step would be very slow in CI
            expect_consistent_root_hash(machine)
        end
    end
    expect.equal(machine:read_reg("uarch_halt_flag"), 1)
    local halt_root_hash = expect_consistent_root_hash(machine)
    machine:reset_uarch()
    local reset_root_hash = expect_consistent_root_hash(machine)
    expect.equal(machine:read_reg("uarch_cycle"), 0)
    expect.equal(machine:read_reg("mcycle"), mcycle)
    if log2_bundle_uarch_cycle_count and log2_bundle_uarch_cycle_count > 0 then
        local bundle_uarch_cycle_count = 1 << log2_bundle_uarch_cycle_count
        -- add halt root hash padding until finishing a bundle
        while #hashes % bundle_uarch_cycle_count ~= 0 do
            table.insert(hashes, halt_root_hash)
        end
        -- add repetitions of the halt root hash
        for _ = 1, 2 * bundle_uarch_cycle_count - 1 do
            table.insert(hashes, halt_root_hash)
        end
        table.insert(hashes, reset_root_hash)
        assert(#hashes % bundle_uarch_cycle_count == 0)
    else
        table.insert(hashes, reset_root_hash)
    end
    table.insert(reset_indices, #hashes)
end

local function expect_uarch_cycle_root_hashes(machine, mcycle_end, log2_bundle_uarch_cycle_count)
    -- this reference implementation does not support the following conditions
    assert(mcycle_end >= 0 and mcycle_end <= math.maxinteger, "unsupported call")
    assert(machine:read_reg("iflags_H") == 0, "unsupported call")
    assert(machine:read_reg("iflags_Y") == 0, "unsupported call")
    local hashes = {}
    local reset_indices = {}
    local break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
    local mcycle_start = machine:read_reg("mcycle")
    for mcycle = mcycle_start + 1, mcycle_end do
        expect_next_mcycle_uarch_root_hashes(machine, mcycle, hashes, reset_indices, log2_bundle_uarch_cycle_count)
        if machine:read_reg("iflags_H") ~= 0 then
            break_reason = cartesi.BREAK_REASON_HALTED
            expect_next_mcycle_uarch_root_hashes(machine, mcycle, hashes, reset_indices, log2_bundle_uarch_cycle_count)
            break
        end
        if machine:read_reg("iflags_Y") ~= 0 then
            break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY
            expect_next_mcycle_uarch_root_hashes(machine, mcycle, hashes, reset_indices, log2_bundle_uarch_cycle_count)
            break
        end
        if machine:read_reg("iflags_X") ~= 0 then
            break_reason = cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
            break
        end
    end
    if log2_bundle_uarch_cycle_count and log2_bundle_uarch_cycle_count > 0 then
        -- bundle the root hashes
        for _ = 1, log2_bundle_uarch_cycle_count do
            assert(#hashes % 2 == 0)
            local next_hashes = {}
            for i = 0, #hashes // 2 - 1 do
                table.insert(next_hashes, cartesi.keccak256(hashes[i * 2 + 1], hashes[i * 2 + 2]))
            end
            hashes = next_hashes
            for i = 1, #reset_indices do
                assert(reset_indices[i] % 2 == 0)
                reset_indices[i] = reset_indices[i] // 2
            end
        end
    end
    return {
        hashes = hashes,
        reset_indices = reset_indices,
        break_reason = assert(break_reason),
    }
end

local function create_remote_machine(...)
    local jsonrpc = require("cartesi.jsonrpc")
    return jsonrpc.spawn_server():set_cleanup_call(jsonrpc.SHUTDOWN):create(...)
end

local function create_local_machine(...)
    return cartesi.machine(...)
end

describe("collect hashes", function()
    for _, desc in ipairs({
        {
            name = "local",
            create_machine = create_local_machine,
        },
        {
            name = "remote",
            create_machine = create_remote_machine,
        },
    }) do
        local create_machine = desc.create_machine
        describe(desc.name, function()
            it("should fail when collecting with invalid arguments", function()
                local machine <close> = create_machine({ ram = { length = 0x10000 } })
                machine:run(1)
                expect.fail(function()
                    machine:collect_mcycle_root_hashes(32, 32, 32)
                end, "mcycle_phase must be in")
                expect.fail(function()
                    machine:collect_mcycle_root_hashes(32, 0)
                end, "mcycle_period cannot be 0")
                expect.fail(function()
                    machine:collect_mcycle_root_hashes(machine:read_reg("mcycle") - 1, 32)
                end, "mcycle is past")
                expect.fail(function()
                    machine:collect_uarch_cycle_root_hashes(0)
                end, "mcycle is past")
            end)

            it("should fail when collecting with incompatible back trees", function()
                local machine <close> = create_machine({ ram = { length = 0x10000 } })
                expect.fail(function()
                    machine:collect_mcycle_root_hashes(32, 32, 0, 0, {
                        log2_max_leaves = 1,
                        leaf_count = 1,
                        hash_function = "keccak256",
                        context = {
                            string.rep("\x00", 32),
                        },
                    })
                end, "back tree context is incompatible")
                expect.fail(function()
                    machine:collect_mcycle_root_hashes(32, 32, 0, 0, {
                        log2_max_leaves = 0,
                        leaf_count = 0,
                        hash_function = "sha256",
                        context = {},
                    })
                end)
            end)

            it("should fail when collecting with unsupported machines", function()
                local unrep_machine <close> =
                    create_machine({ ram = { length = 0x10000 }, processor = { registers = { iunrep = 1 } } })
                local soft_machine <close> = create_machine({ ram = { length = 0x10000 } }, { soft_yield = true })
                expect.fail(function()
                    unrep_machine:collect_mcycle_root_hashes(32, 32)
                end, "cannot collect hashes from unreproducible machines")
                expect.fail(function()
                    unrep_machine:collect_uarch_cycle_root_hashes(32)
                end, "cannot collect hashes from unreproducible machines")
                expect.fail(function()
                    soft_machine:collect_mcycle_root_hashes(32, 32)
                end, "cannot collect hashes when soft yield is enabled")
                expect.fail(function()
                    soft_machine:collect_uarch_cycle_root_hashes(32)
                end, "cannot collect hashes when soft yield is enabled")
            end)

            it("should collect zero root hashes", function()
                local mcycle_start = 1
                local mcycle_end = 1
                local mcycle_period = 32
                local mcycle_phase = 1
                local machine <close> = create_machine({ ram = { length = 0x10000 } })
                machine:run(mcycle_start)
                local log2_bundle_mcycle_count = 0
                expect.equal(
                    machine:collect_mcycle_root_hashes(
                        mcycle_end,
                        mcycle_period,
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    ),
                    {
                        hashes = {},
                        break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
                        mcycle_phase = mcycle_phase,
                    }
                )
                expect.equal(
                    machine:collect_mcycle_root_hashes(
                        mcycle_end,
                        mcycle_period,
                        mcycle_phase,
                        log2_bundle_mcycle_count,
                        {
                            log2_max_leaves = log2_bundle_mcycle_count,
                            leaf_count = 0,
                            hash_function = "keccak256",
                            context = {},
                        }
                    ),
                    {
                        hashes = {},
                        break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
                        mcycle_phase = mcycle_phase,
                    }
                )
                expect.equal(machine:collect_uarch_cycle_root_hashes(mcycle_end), {
                    hashes = {},
                    reset_indices = {},
                    break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
                })
            end)

            it("should collect one root hash", function()
                local mcycle_start = 1
                local mcycle_end = 4
                local mcycle_period = 4
                local mcycle_phase = 1
                local machine <close> = create_machine({ ram = { length = 0x10000 } })
                machine:run(mcycle_start)
                local collected = machine:collect_mcycle_root_hashes(mcycle_end, mcycle_period, mcycle_phase)
                expect.equal(machine:read_reg("mcycle"), mcycle_end)
                expect.equal(collected, {
                    hashes = { machine:get_root_hash() },
                    break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
                    mcycle_phase = 0,
                })

                local machine_uarch <close> = create_machine({ ram = { length = 0x10000 } })
                machine_uarch:run(mcycle_start)
                local collected_uarch = machine_uarch:collect_uarch_cycle_root_hashes(mcycle_end)
                expect.equal(machine_uarch:read_reg("mcycle"), mcycle_end)
                expect.equal(machine_uarch:get_root_hash(), machine:get_root_hash())
                expect.equal(#collected_uarch.reset_indices, mcycle_end - mcycle_start)
                expect.equal(
                    collected_uarch.hashes[collected_uarch.reset_indices[#collected_uarch.reset_indices]],
                    machine_uarch:get_root_hash()
                )
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
            end)

            it("should collect when mcycle_end is not aligned with mcycle_period", function()
                local mcycle_end = 7
                local mcycle_period = 4
                local mcycle_start = mcycle_period
                local mcycle_phase = 1
                local compare_machine <close> = cartesi.machine({ ram = { length = 0x10000 } })
                compare_machine:run(mcycle_start)
                local expected_root_hash_period = compare_machine:get_root_hash()
                compare_machine:run(mcycle_end)
                local expected_root_hash_final = compare_machine:get_root_hash()

                local machine <close> = create_machine({ ram = { length = 0x10000 } })
                machine:run(1)
                local collected = machine:collect_mcycle_root_hashes(mcycle_end, mcycle_period, mcycle_phase)
                expect.equal(machine:read_reg("mcycle"), mcycle_end)
                expect.equal(collected, {
                    hashes = { expected_root_hash_period },
                    break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
                    mcycle_phase = mcycle_end % mcycle_period,
                })
                expect.equal(machine:get_root_hash(), expected_root_hash_final)
            end)

            it("should break as halted when collecting with a halted machine", function()
                local mcycle_start = 0
                local mcycle_end = 32
                local mcycle_period = 32
                local mcycle_phase = 1
                local machine <close> = create_machine({ ram = { length = 0x10000 } })
                machine:write_reg("iflags_H", 1)
                local expected_root_hash = machine:get_root_hash()

                expect.equal(machine:collect_mcycle_root_hashes(mcycle_end, mcycle_period, mcycle_phase), {
                    hashes = {},
                    break_reason = cartesi.BREAK_REASON_HALTED,
                    mcycle_phase = mcycle_phase,
                })
                expect.equal(machine:read_reg("mcycle"), mcycle_start)
                expect.equal(machine:get_root_hash(), expected_root_hash)

                local collected_uarch = machine:collect_uarch_cycle_root_hashes(mcycle_end)
                expect.equal(machine:read_reg("mcycle"), mcycle_start)
                expect.equal(machine:get_root_hash(), expected_root_hash)
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_HALTED)
                expect.equal(#collected_uarch.reset_indices, 1)
                expect.equal(collected_uarch.hashes[collected_uarch.reset_indices[1]], expected_root_hash)
            end)

            it("should break as yielded when collecting with a yielded machine", function()
                local mcycle_start = 0
                local mcycle_end = 32
                local mcycle_period = 32
                local mcycle_phase = 1
                local machine <close> = create_machine({ ram = { length = 0x10000 } })
                machine:write_reg("iflags_Y", 1)
                local expected_root_hash = machine:get_root_hash()

                expect.equal(machine:collect_mcycle_root_hashes(mcycle_end, mcycle_period, mcycle_phase), {
                    hashes = {},
                    break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY,
                    mcycle_phase = mcycle_phase,
                })
                expect.equal(machine:read_reg("mcycle"), mcycle_start)
                expect.equal(machine:get_root_hash(), expected_root_hash)

                local collected_uarch = machine:collect_uarch_cycle_root_hashes(mcycle_end)
                expect.equal(machine:read_reg("mcycle"), mcycle_start)
                expect.equal(machine:get_root_hash(), expected_root_hash)
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_YIELDED_MANUALLY)
                expect.equal(#collected_uarch.reset_indices, 1)
                expect.equal(collected_uarch.hashes[collected_uarch.reset_indices[1]], expected_root_hash)
            end)

            it("should break as halted when collecting up to the same mcycle with a halted machine", function()
                local mcycle_end = 0
                local mcycle_period = 32
                local mcycle_phase = 1
                local machine <close> = create_machine({ ram = { length = 0x10000 } })
                machine:write_reg("iflags_H", 1)
                local expected_root_hash = machine:get_root_hash()

                expect.equal(machine:collect_mcycle_root_hashes(mcycle_end, mcycle_period, mcycle_phase), {
                    hashes = {},
                    break_reason = cartesi.BREAK_REASON_HALTED,
                    mcycle_phase = mcycle_phase,
                })
                expect.equal(machine:read_reg("mcycle"), mcycle_end)
                expect.equal(machine:get_root_hash(), expected_root_hash)

                local collected_uarch = machine:collect_uarch_cycle_root_hashes(mcycle_end)
                expect.equal(machine:get_root_hash(), expected_root_hash)
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_HALTED)
                expect.equal(#collected_uarch.reset_indices, 1)
                expect.equal(collected_uarch.hashes[collected_uarch.reset_indices[1]], expected_root_hash)
            end)

            it("should break as yielded when collecting up to the same mcycle with a yielded machine", function()
                local mcycle_end = 0
                local mcycle_period = 32
                local mcycle_phase = 1
                local machine <close> = create_machine({ ram = { length = 0x10000 } })
                machine:write_reg("iflags_Y", 1)
                local expected_root_hash = machine:get_root_hash()

                expect.equal(machine:collect_mcycle_root_hashes(mcycle_end, mcycle_period, mcycle_phase), {
                    hashes = {},
                    break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY,
                    mcycle_phase = mcycle_phase,
                })
                expect.equal(machine:read_reg("mcycle"), mcycle_end)
                expect.equal(machine:get_root_hash(), expected_root_hash)

                local collected_uarch = machine:collect_uarch_cycle_root_hashes(mcycle_end)
                expect.equal(machine:get_root_hash(), expected_root_hash)
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_YIELDED_MANUALLY)
                expect.equal(#collected_uarch.reset_indices, 1)
                expect.equal(collected_uarch.hashes[collected_uarch.reset_indices[1]], expected_root_hash)
            end)

            it("should collect mcycles during mcycle overflow", function()
                local mcycle_period = 32
                local machine <close> = create_machine({ ram = { length = 0x10000 } })
                machine:write_reg("mcycle", cartesi.MCYCLE_MAX - 1)
                local collected = machine:collect_mcycle_root_hashes(
                    cartesi.MCYCLE_MAX,
                    mcycle_period,
                    machine:read_reg("mcycle") % 32
                )
                expect.equal(collected, {
                    hashes = { machine:get_root_hash() },
                    break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
                    mcycle_phase = machine:read_reg("mcycle") % mcycle_period,
                })
                expect.equal(machine:read_reg("mcycle"), cartesi.MCYCLE_MAX)

                expect.equal(
                    machine:collect_mcycle_root_hashes(
                        cartesi.MCYCLE_MAX,
                        mcycle_period,
                        machine:read_reg("mcycle") % 32
                    ),
                    {
                        hashes = {},
                        break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
                        mcycle_phase = machine:read_reg("mcycle") % mcycle_period,
                    }
                )
                expect.equal(machine:read_reg("mcycle"), cartesi.MCYCLE_MAX)
            end)

            it("should collect uarch cycles during mcycle overflows", function()
                local machine <close> = create_machine({ ram = { length = 0x10000 } })
                machine:write_reg("mcycle", cartesi.MCYCLE_MAX - 1)
                local collected_uarch = machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX)
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                local expected_root_hash = machine:get_root_hash()
                expect.equal(collected_uarch.hashes[collected_uarch.reset_indices[1]], expected_root_hash)
                expect.equal(collected_uarch.hashes[collected_uarch.reset_indices[2]], expected_root_hash)
                expect.equal(#collected_uarch.reset_indices, 2)
                expect.equal(machine:read_reg("mcycle"), cartesi.MCYCLE_MAX)

                collected_uarch = machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX)
                expect.equal(machine:get_root_hash(), expected_root_hash)
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                expect.equal(#collected_uarch.reset_indices, 1)
                expect.equal(collected_uarch.hashes[collected_uarch.reset_indices[1]], expected_root_hash)
            end)

            local add_machine_config = {
                ram = {
                    length = 0x10000,
                    backing_store = {
                        data_filename = tests_util.tests_path .. "rv64ui-p-add.bin",
                    },
                },
            }
            local yield_machine_config = {
                ram = {
                    length = 0x10000,
                    backing_store = {
                        data_filename = tests_util.tests_path .. "htif_yield.bin",
                    },
                },
            }
            local console_machine_config = {
                ram = {
                    length = 65536,
                    backing_store = {
                        data_filename = tests_util.tests_path .. "htif_console.bin",
                    },
                },
            }

            it("should bundle mcycle root hashes leaving no back tree context when last bundle is complete", function()
                local max_log2_bundle_mcycle_count = 3
                local mcycle_start = 1
                local mcycle_period = 8
                local mcycle_end = mcycle_period * (1 << max_log2_bundle_mcycle_count) * 2
                local mcycle_phase = mcycle_start % mcycle_period
                for log2_bundle_mcycle_count = 0, max_log2_bundle_mcycle_count do
                    local machine <close> = create_machine(add_machine_config)
                    local compare_machine <close> = cartesi.machine(add_machine_config)
                    machine:run(mcycle_start)
                    compare_machine:run(mcycle_start)
                    local collected = machine:collect_mcycle_root_hashes(
                        mcycle_end,
                        mcycle_period,
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.not_exist(collected.back_tree)
                    local expected_collected = expect_mcycle_root_hashes(
                        compare_machine,
                        mcycle_end,
                        mcycle_period,
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.equal(collected, expected_collected)
                    expect.equal(machine:get_root_hash(), compare_machine:get_root_hash())
                end
            end)

            it("should bundle mcycle root hashes while flushing console output", function()
                local log2_bundle_mcycle_count = 5
                local mcycle_start = 1
                local mcycle_period = 64
                local mcycle_end = mcycle_period * (1 << log2_bundle_mcycle_count) * 2
                local mcycle_phase = mcycle_start % mcycle_period
                local runtime_config = { console = { output_flush_mode = "every_char" } }
                local machine <close> = create_machine(console_machine_config, runtime_config)
                local compare_machine <close> = cartesi.machine(console_machine_config)
                machine:run(mcycle_start)
                compare_machine:run(mcycle_start)
                local collected = machine:collect_mcycle_root_hashes(
                    mcycle_end,
                    mcycle_period,
                    mcycle_phase,
                    log2_bundle_mcycle_count
                )
                expect.not_exist(collected.back_tree)
                local expected_collected = expect_mcycle_root_hashes(
                    compare_machine,
                    mcycle_end,
                    mcycle_period,
                    mcycle_phase,
                    log2_bundle_mcycle_count
                )
                expect.equal(machine:read_reg("mcycle"), compare_machine:read_reg("mcycle"))
                expect.equal(machine:get_root_hash(), compare_machine:get_root_hash())
                expect.equal(collected, expected_collected)
            end)

            if has_posix and desc.name == "local" then
                it("should bundle mcycle root hashes while failing console output flush", function()
                    local log2_bundle_mcycle_count = 5
                    local mcycle_start = 1
                    local mcycle_period = 64
                    local mcycle_end = mcycle_period * (1 << log2_bundle_mcycle_count) * 2
                    local mcycle_phase = mcycle_start % mcycle_period
                    local out_r, out_w = assert(unistd.pipe())
                    local _ <close> = utils.scope_exit(function()
                        unistd.close(out_r)
                        if out_w then
                            unistd.close(out_w)
                        end
                    end)
                    local runtime_config = {
                        console = {
                            output_flush_mode = "every_char",
                            output_destination = "to_fd",
                            output_fd = out_r, -- use the read end of the pipe to intentionally cause a write failure
                        },
                    }
                    local machine <close> = create_machine(console_machine_config, runtime_config)
                    unistd.close(out_w) -- close write end of the pipe
                    out_w = nil
                    local compare_machine <close> = cartesi.machine(console_machine_config)
                    machine:run(mcycle_start)
                    compare_machine:run(mcycle_start)
                    local collected = machine:collect_mcycle_root_hashes(
                        mcycle_end,
                        mcycle_period,
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.exist(collected.console_io_error)
                    expect.truthy(collected.console_io_error:find("console output flush failed"))
                    collected.console_io_error = nil
                    expect.not_exist(collected.back_tree)
                    local expected_collected = expect_mcycle_root_hashes(
                        compare_machine,
                        mcycle_end,
                        mcycle_period,
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.equal(machine:read_reg("mcycle"), compare_machine:read_reg("mcycle"))
                    expect.equal(machine:get_root_hash(), compare_machine:get_root_hash())
                    expect.equal(collected, expected_collected)
                end)
            end

            it("should bundle mcycle root hashes leaving a back tree context when last bundle is incomplete", function()
                local max_log2_bundle_mcycle_count = 3
                local mcycle_start = 1
                local mcycle_period = 8
                local mcycle_end = mcycle_period * ((1 << max_log2_bundle_mcycle_count) + 1)
                local mcycle_phase = mcycle_start % mcycle_period
                for log2_bundle_mcycle_count = 1, max_log2_bundle_mcycle_count do
                    local machine <close> = create_machine(add_machine_config)
                    local compare_machine <close> = cartesi.machine(add_machine_config)
                    machine:run(mcycle_start)
                    compare_machine:run(mcycle_start)
                    local collected = machine:collect_mcycle_root_hashes(
                        mcycle_end,
                        mcycle_period,
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.exist(collected.back_tree)
                    local expected_collected = expect_mcycle_root_hashes(
                        compare_machine,
                        mcycle_end,
                        mcycle_period,
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.equal(collected, expected_collected)
                    expect.equal(machine:get_root_hash(), compare_machine:get_root_hash())
                end
            end)

            it("should bundle mcycle root hashes continuing from a previous back tree context", function()
                local max_log2_bundle_mcycle_count = 3
                local mcycle_start = 1
                local mcycle_period = 8
                local mcycle_end = 1024
                local mcycle_phase = mcycle_start % mcycle_period
                for log2_bundle_mcycle_count = 1, max_log2_bundle_mcycle_count do
                    local machine <close> = create_machine(add_machine_config)
                    local compare_machine <close> = cartesi.machine(add_machine_config)
                    machine:run(mcycle_start)
                    compare_machine:run(mcycle_start)
                    local all_hashes = {}
                    local last_collected = {
                        mcycle_phase = mcycle_phase,
                    }
                    for mcycle_target = mcycle_start + 1, mcycle_end do
                        last_collected = machine:collect_mcycle_root_hashes(
                            mcycle_target,
                            mcycle_period,
                            last_collected.mcycle_phase,
                            log2_bundle_mcycle_count,
                            last_collected.back_tree
                        )
                        tabular.append(all_hashes, last_collected.hashes)
                    end
                    local all_collected = {
                        mcycle_phase = last_collected.mcycle_phase,
                        break_reason = last_collected.break_reason,
                        hashes = all_hashes,
                        back_tree = last_collected.back_tree,
                    }
                    expect.not_exist(all_collected.back_tree)
                    local expected_collected = expect_mcycle_root_hashes(
                        compare_machine,
                        mcycle_end,
                        mcycle_period,
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.equal(all_collected, expected_collected)
                    expect.equal(machine:get_root_hash(), compare_machine:get_root_hash())
                end
            end)

            it("should bundle mcycle root hashes leaving no back tree context when halting", function()
                local max_log2_bundle_mcycle_count = 6
                local mcycle_start = 2
                local mcycle_period = 32
                local mcycle_end = 1024
                local mcycle_phase = mcycle_start % mcycle_period
                for log2_bundle_mcycle_count = 0, max_log2_bundle_mcycle_count do
                    local machine <close> = create_machine(add_machine_config)
                    local compare_machine <close> = cartesi.machine(add_machine_config)
                    machine:run(mcycle_start)
                    compare_machine:run(mcycle_start)
                    local collected = machine:collect_mcycle_root_hashes(
                        mcycle_end,
                        mcycle_period,
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.not_exist(collected.back_tree)
                    local expected_collected = expect_mcycle_root_hashes(
                        compare_machine,
                        mcycle_end,
                        mcycle_period,
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.equal(collected, expected_collected)
                    expect.equal(machine:get_root_hash(), compare_machine:get_root_hash())
                    expect.equal(machine:read_reg("iflags_H"), 1)
                end
            end)

            it("should bundle mcycle root hashes leaving no back tree context when yielding", function()
                local max_log2_bundle_mcycle_count = 6
                local mcycle_start = 3
                local mcycle_period = 4
                local mcycle_end = 1024
                local mcycle_phase = mcycle_start % mcycle_period
                for log2_bundle_mcycle_count = 0, max_log2_bundle_mcycle_count do
                    local machine <close> = create_machine(yield_machine_config)
                    local compare_machine <close> = cartesi.machine(yield_machine_config)
                    machine:run(mcycle_start)
                    compare_machine:run(mcycle_start)
                    local collected = machine:collect_mcycle_root_hashes(
                        mcycle_end,
                        mcycle_period,
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.not_exist(collected.back_tree)
                    local expected_collected = expect_mcycle_root_hashes(
                        compare_machine,
                        mcycle_end,
                        mcycle_period,
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.equal(collected, expected_collected)
                    expect.equal(machine:get_root_hash(), compare_machine:get_root_hash())
                    expect.equal(machine:read_reg("iflags_Y"), 1)
                end
            end)

            it("should bundle uarch cycle root hashes", function()
                local max_log2_uarch_cycle_mcycle_count = 9
                local mcycle_start = 256
                local mcycle_end = mcycle_start + 2
                for log2_uarch_cycle_mcycle_count = 0, max_log2_uarch_cycle_mcycle_count do
                    local machine <close> = create_machine(add_machine_config)
                    local compare_machine <close> = cartesi.machine(add_machine_config)
                    machine:run(mcycle_start)
                    compare_machine:run(mcycle_start)
                    local collected = machine:collect_uarch_cycle_root_hashes(mcycle_end, log2_uarch_cycle_mcycle_count)
                    local expected_collected =
                        expect_uarch_cycle_root_hashes(compare_machine, mcycle_end, log2_uarch_cycle_mcycle_count)
                    expect.equal(collected, expected_collected)
                    expect.equal(machine:get_root_hash(), compare_machine:get_root_hash())
                end
            end)
        end) -- describe remote/local
    end -- for remote/local create

    for _, hash_function in ipairs({ "sha256", "keccak256" }) do
        describe(hash_function, function()
            local big_machine_config = {
                ram = {
                    length = 8191 * 4096, -- non power of 2 on purpose to exercise address range boundaries
                    backing_store = {
                        data_filename = tests_util.images_path .. "linux.bin",
                    },
                },
                flash_drive = {
                    { length = 13 * 4096 }, -- non power of 2 on purpose to exercise address range boundaries
                },
                dtb = {
                    -- let it boot and panic silently when failing to find rootfs
                    bootargs = cartesi.machine:get_default_config().dtb.bootargs .. " loglevel=0",
                },
                hash_tree = {
                    hash_function = hash_function,
                },
            }
            local empty_machine_config = {
                ram = { length = 0x10000 },
                hash_tree = {
                    hash_function = hash_function,
                },
            }
            local yield_machine_config = {
                ram = {
                    length = 8191 * 4096, -- non power of 2 on purpose to exercise address range boundaries
                    backing_store = {
                        data_filename = tests_util.tests_path .. "htif_yield.bin",
                    },
                },
                hash_tree = {
                    hash_function = hash_function,
                },
            }

            local big_last_mcycle
            local big_last_root_hash
            local yield_last_mcycle = 500
            local yield_last_root_hash
            local yield_sparse_hashes = {}

            if hash_function == "keccak256" then
                it("should fail when microarchitecture is not reset", function()
                    local machine <close> = cartesi.machine(empty_machine_config)
                    machine:run_uarch(1)
                    expect.fail(function()
                        machine:collect_mcycle_root_hashes(0, 32, 1)
                    end, "microarchitecture is not reset")
                    expect.fail(function()
                        machine:collect_uarch_cycle_root_hashes(1)
                    end, "microarchitecture is not reset")
                end)
            else
                it("should fail when collecting uarch cycles", function()
                    local machine <close> = cartesi.machine(empty_machine_config)
                    expect.fail(function()
                        machine:collect_uarch_cycle_root_hashes(1)
                    end, "microarchitecture can only be used with hash tree")
                end)
            end

            it("should match sparse periodic root hashes", function()
                --[[
                This test runs a big machine booting a full Linux kernel (without a root filesystem) until it halts.
                It exercises various subsystems (including the TLB) to verify the code correctly mark dirty pages.
                ]]
                local mcycle_start = 1
                local mcycle_period = 8 * 1024 * 1024
                local period_count = 16
                local machine <close> = cartesi.machine(big_machine_config)
                local collect_machine <close> = cartesi.machine(big_machine_config)
                machine:run(mcycle_start)
                collect_machine:run(mcycle_start)
                expect_consistent_root_hash(machine)
                expect.equal(machine:get_root_hash(), collect_machine:get_root_hash())
                local mcycle_phase = machine:read_reg("mcycle") % mcycle_period
                local mcycle_target = machine:read_reg("mcycle") + period_count * mcycle_period
                local collected = collect_machine:collect_mcycle_root_hashes(mcycle_target, mcycle_period, mcycle_phase)
                local expected_collected =
                    expect_mcycle_root_hashes(machine, mcycle_target, mcycle_period, mcycle_phase)
                local halt_exit_code = machine:read_reg("htif_tohost_data") >> 1
                expect.equal(collected, expected_collected)
                expect.equal(collect_machine:get_root_hash(), machine:get_root_hash())
                expect.equal(collected.break_reason, cartesi.BREAK_REASON_HALTED)
                expect.equal(halt_exit_code, 255)
                big_last_mcycle = machine:read_reg("mcycle")
                big_last_root_hash = machine:get_root_hash()
            end)

            it("should match sparse periodic root hashes while yielding", function()
                --[[
                This test runs a small machine that triggers both manual and automatic yields at various points.
                It verifies that root hash collection works correctly even when yields interrupt collection at
                mcycle periods that are not aligned, ensuring robustness across yield and period boundaries.
                ]]
                local mcycle_start = 7 -- use prime numbers on purpose to test corner cases
                local mcycle_phase = 3
                local mcycle_period = 21
                local period_count = yield_last_mcycle // mcycle_period
                local machine <close> = cartesi.machine(yield_machine_config)
                local collect_machine <close> = cartesi.machine(yield_machine_config)
                expect.equal(machine:run(mcycle_start), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                expect.equal(machine:read_reg("mcycle"), mcycle_start)
                collect_machine:run(mcycle_start)
                expect_consistent_root_hash(machine)
                expect.equal(machine:get_root_hash(), collect_machine:get_root_hash())
                local count_manual_yields = 0
                local count_automatic_yields = 0
                local count_halts = 1
                local halt_exit_code
                for _ = 1, period_count * 2 do
                    local mcycle_target = machine:read_reg("mcycle") + period_count * mcycle_period
                    local collected =
                        collect_machine:collect_mcycle_root_hashes(mcycle_target, mcycle_period, mcycle_phase)
                    local expected_collected =
                        expect_mcycle_root_hashes(machine, mcycle_target, mcycle_period, mcycle_phase)
                    expect.equal(collect_machine:read_reg("mcycle"), machine:read_reg("mcycle"))
                    expect.equal(collected, expected_collected)
                    expect.equal(collect_machine:get_root_hash(), machine:get_root_hash())
                    mcycle_phase = collected.mcycle_phase
                    for _, hash in ipairs(collected.hashes) do
                        table.insert(yield_sparse_hashes, hash)
                    end
                    if collected.break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY then
                        collect_machine:write_reg("iflags_Y", 0)
                        machine:write_reg("iflags_Y", 0)
                        count_manual_yields = count_manual_yields + 1
                    elseif collected.break_reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
                        count_automatic_yields = count_automatic_yields + 1
                    elseif collected.break_reason == cartesi.BREAK_REASON_HALTED then
                        halt_exit_code = machine:read_reg("htif_tohost_data") >> 1
                        break
                    else
                        error("unexpected break reason")
                    end
                end
                expect.equal(machine:read_reg("mcycle"), yield_last_mcycle)
                expect.equal(#yield_sparse_hashes, period_count + count_manual_yields + count_halts)
                expect.equal(count_manual_yields, 8)
                expect.equal(count_automatic_yields, 7)
                expect.equal(halt_exit_code, 42)
                yield_last_root_hash = machine:get_root_hash()
            end)

            if hash_function == "keccak256" then
                it("should match dense uarch root hashes", function()
                    --[[
                    This test runs a big machine booting a full Linux kernel (without a root filesystem) until it halts,
                    using microarchitecture stepping for the final mcycles only.
                    This verifies that collecting root hashes via uarch is correct for complete mcycles,
                    while minimizing test runtime by limiting uarch execution to a few mcycles.
                    ]]
                    expect.truthy(big_last_mcycle ~= nil and big_last_root_hash ~= nil)
                    local machine <close> = cartesi.machine(big_machine_config)
                    local collect_machine <close> = cartesi.machine(big_machine_config)
                    local mcycle_count = 2
                    expect.equal(
                        machine:run(big_last_mcycle - mcycle_count),
                        cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
                    )
                    expect_consistent_root_hash(machine)
                    collect_machine:run(big_last_mcycle - mcycle_count)
                    expect.equal(machine:get_root_hash(), collect_machine:get_root_hash())
                    local collected = collect_machine:collect_uarch_cycle_root_hashes(big_last_mcycle)
                    local expected_collected = expect_uarch_cycle_root_hashes(machine, big_last_mcycle)
                    local halt_exit_code = machine:read_reg("htif_tohost_data") >> 1
                    expect.equal(collected, expected_collected)
                    expect.equal(machine:read_reg("mcycle"), big_last_mcycle)
                    expect.equal(machine:get_root_hash(), big_last_root_hash)
                    expect.equal(halt_exit_code, 255)
                end)

                it("should match dense uarch root hashes while yielding", function()
                    expect.truthy(yield_last_mcycle ~= nil and yield_last_root_hash ~= nil)
                    --[[
                    This test verifies that collecting root hashes via microarchitecture stepping remains correct even
                    when execution is interrupted by both manual and automatic yields at various points.
                    It ensures that root hash collection is robust and accurate across different yield scenarios.
                    ]]
                    local mcycle_start = 7 -- use prime numbers on purpose to test corner cases
                    local mcycle_phase = 3
                    local mcycle_period = 21
                    local period_count = yield_last_mcycle // mcycle_period
                    local machine <close> = cartesi.machine(yield_machine_config)
                    local collect_machine <close> = cartesi.machine(yield_machine_config)
                    machine:run(mcycle_start)
                    expect.equal(machine:read_reg("mcycle"), mcycle_start)
                    collect_machine:run(mcycle_start)
                    expect_consistent_root_hash(machine)
                    expect.equal(machine:get_root_hash(), collect_machine:get_root_hash())
                    local mcycle_phase_offset = mcycle_start - mcycle_phase
                    local sparse_hashes_count = 0
                    local count_manual_yields = 0
                    local count_automatic_yields = 0
                    local halt_exit_code
                    for _ = 1, period_count * 2 do
                        local mcycles_to_phase0 = mcycle_period
                            - ((machine:read_reg("mcycle") - mcycle_phase_offset) % mcycle_period)
                        local mcycle_target = machine:read_reg("mcycle") + mcycles_to_phase0
                        local collected = collect_machine:collect_uarch_cycle_root_hashes(mcycle_target)
                        local expected_collected = expect_uarch_cycle_root_hashes(machine, mcycle_target)
                        expect.equal(collect_machine:read_reg("mcycle"), machine:read_reg("mcycle"))
                        expect.equal(collected, expected_collected)
                        expect.equal(collect_machine:get_root_hash(), machine:get_root_hash())
                        mcycles_to_phase0 = (machine:read_reg("mcycle") - mcycle_phase_offset) % mcycle_period
                        local at_fixed_point = machine:read_reg("iflags_Y") ~= 0 or machine:read_reg("iflags_H") ~= 0
                        if mcycles_to_phase0 == 0 or at_fixed_point then
                            expect.equal(yield_sparse_hashes[sparse_hashes_count + 1], machine:get_root_hash())
                            sparse_hashes_count = sparse_hashes_count + 1
                        end
                        if machine:read_reg("iflags_Y") == 1 then
                            collect_machine:write_reg("iflags_Y", 0)
                            machine:write_reg("iflags_Y", 0)
                            count_manual_yields = count_manual_yields + 1
                        elseif machine:read_reg("iflags_X") == 1 then
                            count_automatic_yields = count_automatic_yields + 1
                        elseif machine:read_reg("iflags_H") == 1 then
                            halt_exit_code = machine:read_reg("htif_tohost_data") >> 1
                            break
                        end
                    end
                    expect.equal(machine:read_reg("mcycle"), yield_last_mcycle)
                    expect.equal(machine:get_root_hash(), yield_last_root_hash)
                    expect.equal(count_manual_yields, 8)
                    expect.equal(count_automatic_yields, 7)
                    expect.equal(halt_exit_code, 42)
                    expect.equal(sparse_hashes_count, #yield_sparse_hashes)
                end)
            end -- if keccak256 hash function
        end) -- descibre hash function
    end -- for hash function
end) -- describe collect hashes
