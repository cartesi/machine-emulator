--[[
Test suite for collecting root hashes.
]]

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local filesystem = require("cartesi.filesystem")
local hash_tree = require("cartesi.hash-tree")
local tabular = require("cartesi.tabular")
local util = require("cartesi.util")
local tests_util = require("cartesi.tests.util")
local has_posix, unistd = pcall(require, "posix.unistd")

local function log2_mcycle_period(mcycle_period)
    local log2_period = util.ilog2(mcycle_period)
    assert(1 << log2_period == mcycle_period, "mcycle period must be a power of two")
    return log2_period
end

local function expect_consistent_root_hash(machine)
    local root_hash = machine:get_root_hash()
    local node_hash = machine:get_node_hash(0, cartesi.HASH_TREE_LOG2_ROOT_SIZE)
    local external_root_hash = tests_util.calculate_emulator_hash(machine)
    expect.equal(root_hash, node_hash)
    expect.equal(external_root_hash, root_hash)
    return root_hash
end

local function is_rejected_manual_yield(machine)
    return machine:read_reg("iflags_Y") ~= 0
        and machine:read_reg("htif_tohost_dev") == cartesi.HTIF_DEV_YIELD
        and machine:read_reg("htif_tohost_cmd") == cartesi.HTIF_YIELD_CMD_MANUAL
        and machine:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED
end

-- Root hash that verifiers accept after a state transition ending in the machine state,
-- which is the recorded revert root hash when the machine has rejected an input
local function canonical_root_hash(machine)
    if is_rejected_manual_yield(machine) then
        return machine:read_revert_root_hash()
    end
    return machine:get_root_hash()
end

-- Tail accepted by machines whose revert leaf is pristine, required at entry but never consumed
local pristine_revert_uarch_tail = {
    string.rep("\x00", cartesi.HASH_SIZE),
    string.rep("\x00", cartesi.HASH_SIZE),
}

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
                table.insert(hashes, canonical_root_hash(machine))
                at_fixed_point = true
            end
            break
        end
        mcycle_phase = 0
        table.insert(hashes, canonical_root_hash(machine))
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
    local partial_bundle
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
            partial_bundle = {
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
                table.insert(partial_bundle.context, hashes[#hashes])
            end
            hashes = next_hashes
        end
    end
    return {
        hashes = hashes,
        break_reason = break_reason,
        mcycle_phase = mcycle_phase,
        partial_bundle = partial_bundle,
    }
end

local function expect_next_mcycle_uarch_root_hashes(
    machine,
    mcycle,
    hashes,
    mcycle_hash_offsets,
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
    expect.equal(machine:read_reg("uarch_halt"), 1)
    local halt_root_hash = expect_consistent_root_hash(machine)
    machine:reset_uarch()
    expect_consistent_root_hash(machine)
    local reset_root_hash = canonical_root_hash(machine)
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
        table.insert(hashes, halt_root_hash)
        table.insert(hashes, reset_root_hash)
    end
    table.insert(mcycle_hash_offsets, #hashes + 1)
end

-- Appends the period of the reverted machine, as given by the revert uarch tail
local function expect_revert_uarch_tail_period(
    hashes,
    mcycle_hash_offsets,
    revert_uarch_tail,
    log2_bundle_uarch_cycle_count
)
    for i = 1, #revert_uarch_tail - 2 do
        table.insert(hashes, revert_uarch_tail[i])
    end
    local halt_root_hash = revert_uarch_tail[#revert_uarch_tail - 1]
    local reset_root_hash = revert_uarch_tail[#revert_uarch_tail]
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
        table.insert(hashes, halt_root_hash)
        table.insert(hashes, reset_root_hash)
    end
    table.insert(mcycle_hash_offsets, #hashes + 1)
end

local function expect_uarch_cycle_root_hashes(machine, mcycle_end, log2_bundle_uarch_cycle_count, revert_uarch_tail)
    -- this reference implementation does not support the following conditions
    assert(mcycle_end >= 0 and mcycle_end <= math.maxinteger, "unsupported call")
    assert(machine:read_reg("iflags_H") == 0, "unsupported call")
    assert(machine:read_reg("iflags_Y") == 0, "unsupported call")
    local hashes = {}
    local mcycle_hash_offsets = { 1 }
    local break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
    local mcycle_start = machine:read_reg("mcycle")
    for mcycle = mcycle_start + 1, mcycle_end do
        expect_next_mcycle_uarch_root_hashes(
            machine,
            mcycle,
            hashes,
            mcycle_hash_offsets,
            log2_bundle_uarch_cycle_count
        )
        if machine:read_reg("iflags_H") ~= 0 then
            break_reason = cartesi.BREAK_REASON_HALTED
            expect_next_mcycle_uarch_root_hashes(
                machine,
                mcycle,
                hashes,
                mcycle_hash_offsets,
                log2_bundle_uarch_cycle_count
            )
            break
        end
        if machine:read_reg("iflags_Y") ~= 0 then
            break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY
            if is_rejected_manual_yield(machine) then
                -- the canonical timeline continues from the reverted machine,
                -- whose period is given by the revert uarch tail
                expect_revert_uarch_tail_period(
                    hashes,
                    mcycle_hash_offsets,
                    revert_uarch_tail,
                    log2_bundle_uarch_cycle_count
                )
            else
                expect_next_mcycle_uarch_root_hashes(
                    machine,
                    mcycle,
                    hashes,
                    mcycle_hash_offsets,
                    log2_bundle_uarch_cycle_count
                )
            end
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
            for i = 1, #mcycle_hash_offsets do
                assert((mcycle_hash_offsets[i] - 1) % 2 == 0)
                mcycle_hash_offsets[i] = (mcycle_hash_offsets[i] - 1) // 2 + 1
            end
        end
    end
    return {
        hashes = hashes,
        mcycle_hash_offsets = mcycle_hash_offsets,
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

local function collect_mcycle_root_hashes_in_parts(
    machine,
    targets,
    mcycle_period,
    mcycle_phase,
    log2_bundle_mcycle_count
)
    local hashes = {}
    local last = {
        break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
        mcycle_phase = mcycle_phase,
    }
    for _, target in ipairs(targets) do
        last = machine:collect_mcycle_root_hashes(
            target,
            log2_mcycle_period(mcycle_period),
            last.mcycle_phase,
            log2_bundle_mcycle_count,
            last.partial_bundle
        )
        tabular.append(hashes, last.hashes)
        if last.break_reason ~= cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then
            break
        end
    end
    return {
        hashes = hashes,
        break_reason = last.break_reason,
        mcycle_phase = last.mcycle_phase,
        partial_bundle = last.partial_bundle,
    }
end

local function collect_uarch_cycle_root_hashes_in_parts(
    machine,
    targets,
    log2_bundle_uarch_cycle_count,
    revert_uarch_tail
)
    local hashes = {}
    local mcycle_hash_offsets = { 1 }
    local break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
    for _, target in ipairs(targets) do
        local collected =
            machine:collect_uarch_cycle_root_hashes(target, log2_bundle_uarch_cycle_count, revert_uarch_tail)
        local hash_count = #hashes
        tabular.append(hashes, collected.hashes)
        for i = 2, #collected.mcycle_hash_offsets do
            table.insert(mcycle_hash_offsets, hash_count + collected.mcycle_hash_offsets[i])
        end
        break_reason = collected.break_reason
        if break_reason ~= cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then
            break
        end
    end
    return {
        hashes = hashes,
        mcycle_hash_offsets = mcycle_hash_offsets,
        break_reason = break_reason,
    }
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
                local machine <close> = create_machine({ ram = { length = 4096 } })
                machine:run(1)
                expect.fail(function()
                    machine:collect_mcycle_root_hashes(32, log2_mcycle_period(32), 32)
                end, "mcycle_phase must be in")
                expect.fail(function()
                    machine:collect_mcycle_root_hashes(32, 64)
                end, "log2_mcycle_period must be in")
                expect.fail(function()
                    machine:collect_mcycle_root_hashes(machine:read_reg("mcycle") - 1, log2_mcycle_period(32))
                end, "mcycle is past")
                expect.fail(function()
                    machine:collect_uarch_cycle_root_hashes(0)
                end, "mcycle is past")
            end)

            it("should fail when collecting with an incompatible partial bundle", function()
                local machine <close> = create_machine({ ram = { length = 4096 } })
                expect.fail(function()
                    machine:collect_mcycle_root_hashes(32, log2_mcycle_period(32), 0, 0, {
                        log2_max_leaves = 1,
                        leaf_count = 1,
                        hash_function = "keccak256",
                        context = {
                            string.rep("\x00", 32),
                        },
                    })
                end, "partial bundle is incompatible")
                expect.fail(function()
                    machine:collect_mcycle_root_hashes(32, log2_mcycle_period(32), 0, 0, {
                        log2_max_leaves = 0,
                        leaf_count = 0,
                        hash_function = "sha256",
                        context = {},
                    })
                end)
            end)

            it("should fail when collecting with unsupported machines", function()
                local unrep_machine <close> =
                    create_machine({ ram = { length = 4096 }, processor = { registers = { iunrep = 1 } } })
                local soft_machine <close> = create_machine({ ram = { length = 4096 } }, { soft_yield = true })
                expect.fail(function()
                    unrep_machine:collect_mcycle_root_hashes(32, log2_mcycle_period(32))
                end, "cannot collect hashes from unreproducible machines")
                expect.fail(function()
                    unrep_machine:collect_uarch_cycle_root_hashes(32)
                end, "cannot collect hashes from unreproducible machines")
                expect.fail(function()
                    soft_machine:collect_mcycle_root_hashes(32, log2_mcycle_period(32))
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
                local machine <close> = create_machine({ ram = { length = 4096 } })
                machine:run(mcycle_start)
                local log2_bundle_mcycle_count = 0
                expect.equal(
                    machine:collect_mcycle_root_hashes(
                        mcycle_end,
                        log2_mcycle_period(mcycle_period),
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
                        log2_mcycle_period(mcycle_period),
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
                    mcycle_hash_offsets = { 1 },
                    break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
                })
            end)

            it("should collect one root hash", function()
                local mcycle_start = 1
                local mcycle_end = 4
                local mcycle_period = 4
                local mcycle_phase = 1
                local machine <close> = create_machine({ ram = { length = 4096 } })
                machine:run(mcycle_start)
                local collected =
                    machine:collect_mcycle_root_hashes(mcycle_end, log2_mcycle_period(mcycle_period), mcycle_phase)
                expect.equal(machine:read_reg("mcycle"), mcycle_end)
                expect.equal(collected, {
                    hashes = { machine:get_root_hash() },
                    break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
                    mcycle_phase = 0,
                })

                local machine_uarch <close> = create_machine({ ram = { length = 4096 } })
                machine_uarch:run(mcycle_start)
                local collected_uarch =
                    machine_uarch:collect_uarch_cycle_root_hashes(mcycle_end, 0, pristine_revert_uarch_tail)
                expect.equal(machine_uarch:read_reg("mcycle"), mcycle_end)
                expect.equal(machine_uarch:get_root_hash(), machine:get_root_hash())
                expect.equal(#collected_uarch.mcycle_hash_offsets - 1, mcycle_end - mcycle_start)
                local last_offset = collected_uarch.mcycle_hash_offsets[#collected_uarch.mcycle_hash_offsets]
                expect.equal(collected_uarch.hashes[last_offset - 1], machine_uarch:get_root_hash())
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
            end)

            it("should collect when mcycle_end is not aligned with mcycle_period", function()
                local mcycle_end = 7
                local mcycle_period = 4
                local mcycle_start = mcycle_period
                local mcycle_phase = 1
                local compare_machine <close> = cartesi.machine({ ram = { length = 4096 } })
                compare_machine:run(mcycle_start)
                local expected_root_hash_period = compare_machine:get_root_hash()
                compare_machine:run(mcycle_end)
                local expected_root_hash_final = compare_machine:get_root_hash()

                local machine <close> = create_machine({ ram = { length = 4096 } })
                machine:run(1)
                local collected =
                    machine:collect_mcycle_root_hashes(mcycle_end, log2_mcycle_period(mcycle_period), mcycle_phase)
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
                local machine <close> = create_machine({ ram = { length = 4096 } })
                machine:write_reg("iflags_H", 1)
                local expected_root_hash = machine:get_root_hash()

                expect.equal(
                    machine:collect_mcycle_root_hashes(mcycle_end, log2_mcycle_period(mcycle_period), mcycle_phase),
                    {
                        hashes = { expected_root_hash },
                        break_reason = cartesi.BREAK_REASON_HALTED,
                        mcycle_phase = mcycle_phase,
                    }
                )
                expect.equal(machine:read_reg("mcycle"), mcycle_start)
                expect.equal(machine:get_root_hash(), expected_root_hash)

                local collected_uarch = machine:collect_uarch_cycle_root_hashes(mcycle_end)
                expect.equal(machine:read_reg("mcycle"), mcycle_start)
                expect.equal(machine:get_root_hash(), expected_root_hash)
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_HALTED)
                expect.equal(#collected_uarch.mcycle_hash_offsets, 2)
                expect.equal(collected_uarch.hashes[collected_uarch.mcycle_hash_offsets[2] - 1], expected_root_hash)
            end)

            it("should break as mcycle overflow when collecting with an mcycle overflow machine", function()
                local mcycle_start = 0
                local mcycle_end = 32
                local mcycle_period = 32
                local mcycle_phase = 1
                local machine <close> = create_machine({ ram = { length = 4096 } })
                machine:write_reg("imcyclemax", mcycle_start)
                local expected_root_hash = machine:get_root_hash()

                expect.equal(
                    machine:collect_mcycle_root_hashes(mcycle_end, log2_mcycle_period(mcycle_period), mcycle_phase),
                    {
                        hashes = { expected_root_hash },
                        break_reason = cartesi.BREAK_REASON_MCYCLE_OVERFLOW,
                        mcycle_phase = mcycle_phase,
                    }
                )
                expect.equal(machine:read_reg("mcycle"), mcycle_start)
                expect.equal(machine:get_root_hash(), expected_root_hash)

                local collected_uarch = machine:collect_uarch_cycle_root_hashes(mcycle_end)
                expect.equal(machine:read_reg("mcycle"), mcycle_start)
                expect.equal(machine:get_root_hash(), expected_root_hash)
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
                expect.equal(#collected_uarch.mcycle_hash_offsets, 2)
                expect.equal(collected_uarch.hashes[collected_uarch.mcycle_hash_offsets[2] - 1], expected_root_hash)
            end)

            it("should break as yielded when collecting with a yielded machine", function()
                local mcycle_start = 0
                local mcycle_end = 32
                local mcycle_period = 32
                local mcycle_phase = 1
                local machine <close> = create_machine({ ram = { length = 4096 } })
                machine:write_reg("iflags_Y", 1)
                local expected_root_hash = machine:get_root_hash()

                expect.equal(
                    machine:collect_mcycle_root_hashes(mcycle_end, log2_mcycle_period(mcycle_period), mcycle_phase),
                    {
                        hashes = { expected_root_hash },
                        break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY,
                        mcycle_phase = mcycle_phase,
                    }
                )
                expect.equal(machine:read_reg("mcycle"), mcycle_start)
                expect.equal(machine:get_root_hash(), expected_root_hash)

                local collected_uarch = machine:collect_uarch_cycle_root_hashes(mcycle_end)
                expect.equal(machine:read_reg("mcycle"), mcycle_start)
                expect.equal(machine:get_root_hash(), expected_root_hash)
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_YIELDED_MANUALLY)
                expect.equal(#collected_uarch.mcycle_hash_offsets, 2)
                expect.equal(collected_uarch.hashes[collected_uarch.mcycle_hash_offsets[2] - 1], expected_root_hash)
            end)

            it("should pad bundles when collecting from an existing fixed point", function()
                local mcycle_end = 0
                local mcycle_period = 32
                local mcycle_phase = 1
                local log2_bundle_mcycle_count = 2
                local machine <close> = create_machine({ ram = { length = 4096 } })
                machine:write_reg("iflags_H", 1)
                local expected_root_hash = machine:get_root_hash()
                local expected_bundle_hash = expected_root_hash
                for _ = 1, log2_bundle_mcycle_count do
                    expected_bundle_hash = cartesi.keccak256(expected_bundle_hash, expected_bundle_hash)
                end

                expect.equal(
                    machine:collect_mcycle_root_hashes(
                        mcycle_end,
                        log2_mcycle_period(mcycle_period),
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    ),
                    {
                        hashes = { expected_bundle_hash, expected_bundle_hash },
                        break_reason = cartesi.BREAK_REASON_HALTED,
                        mcycle_phase = mcycle_phase,
                    }
                )
                expect.equal(machine:read_reg("mcycle"), 0)
                expect.equal(machine:get_root_hash(), expected_root_hash)
            end)

            it("should report halt on same-target mcycle and uarch collection", function()
                local mcycle_end = 0
                local mcycle_period = 32
                local mcycle_phase = 1
                local machine <close> = create_machine({ ram = { length = 4096 } })
                machine:write_reg("iflags_H", 1)
                local expected_root_hash = machine:get_root_hash()

                expect.equal(
                    machine:collect_mcycle_root_hashes(mcycle_end, log2_mcycle_period(mcycle_period), mcycle_phase),
                    {
                        hashes = { expected_root_hash },
                        break_reason = cartesi.BREAK_REASON_HALTED,
                        mcycle_phase = mcycle_phase,
                    }
                )
                expect.equal(machine:read_reg("mcycle"), mcycle_end)
                expect.equal(machine:get_root_hash(), expected_root_hash)

                local collected_uarch = machine:collect_uarch_cycle_root_hashes(mcycle_end)
                expect.equal(machine:get_root_hash(), expected_root_hash)
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_HALTED)
                expect.equal(#collected_uarch.mcycle_hash_offsets, 2)
                expect.equal(collected_uarch.hashes[collected_uarch.mcycle_hash_offsets[2] - 1], expected_root_hash)
            end)

            it("should report yield on same-target mcycle and uarch collection", function()
                local mcycle_end = 0
                local mcycle_period = 32
                local mcycle_phase = 1
                local machine <close> = create_machine({ ram = { length = 4096 } })
                machine:write_reg("iflags_Y", 1)
                local expected_root_hash = machine:get_root_hash()

                expect.equal(
                    machine:collect_mcycle_root_hashes(mcycle_end, log2_mcycle_period(mcycle_period), mcycle_phase),
                    {
                        hashes = { expected_root_hash },
                        break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY,
                        mcycle_phase = mcycle_phase,
                    }
                )
                expect.equal(machine:read_reg("mcycle"), mcycle_end)
                expect.equal(machine:get_root_hash(), expected_root_hash)

                local collected_uarch = machine:collect_uarch_cycle_root_hashes(mcycle_end)
                expect.equal(machine:get_root_hash(), expected_root_hash)
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_YIELDED_MANUALLY)
                expect.equal(#collected_uarch.mcycle_hash_offsets, 2)
                expect.equal(collected_uarch.hashes[collected_uarch.mcycle_hash_offsets[2] - 1], expected_root_hash)
            end)

            it("should require the revert uarch tail when collecting with a running machine", function()
                local machine <close> = create_machine({ ram = { length = 4096 } })
                local compare_machine <close> = cartesi.machine({ ram = { length = 4096 } })
                expect.fail(function()
                    machine:collect_uarch_cycle_root_hashes(2)
                end, "revert uarch tail is required")
                expect.fail(function()
                    machine:collect_uarch_cycle_root_hashes(2, 0, { string.rep("\x11", cartesi.HASH_SIZE) })
                end, "revert uarch tail is too short")
                expect.fail(function()
                    machine:collect_uarch_cycle_root_hashes(2, 0, {
                        string.rep("\x11", cartesi.HASH_SIZE),
                        string.rep("\x22", cartesi.HASH_SIZE),
                    })
                end, "revert uarch tail does not end with the revert root hash")
                -- failing calls leave the machine unchanged, so retrying with the tail works
                local collected = machine:collect_uarch_cycle_root_hashes(2, 0, pristine_revert_uarch_tail)
                local expected_collected = expect_uarch_cycle_root_hashes(compare_machine, 2)
                expect.equal(collected, expected_collected)
            end)

            it("should collect the revert uarch tail period when starting from a rejected machine", function()
                local mcycle_end = 32
                local revert_root_hash = string.rep("\x5a", cartesi.HASH_SIZE)
                local revert_uarch_tail = {
                    string.rep("\x01", cartesi.HASH_SIZE),
                    string.rep("\x02", cartesi.HASH_SIZE),
                    revert_root_hash,
                }
                local machine <close> = create_machine({ ram = { length = 4096 } })
                machine:write_revert_root_hash(revert_root_hash)
                machine:write_reg("iflags_Y", 1)
                machine:write_reg("htif_tohost_dev", cartesi.HTIF_DEV_YIELD)
                machine:write_reg("htif_tohost_cmd", cartesi.HTIF_YIELD_CMD_MANUAL)
                machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED)
                local expected_root_hash = machine:get_root_hash()

                -- the tail is required even though the machine is at a fixed point
                expect.fail(function()
                    machine:collect_uarch_cycle_root_hashes(mcycle_end)
                end, "revert uarch tail is required")

                -- the machine is not touched, the period comes entirely from the tail
                expect.equal(machine:collect_uarch_cycle_root_hashes(mcycle_end, 0, revert_uarch_tail), {
                    hashes = revert_uarch_tail,
                    mcycle_hash_offsets = { 1, #revert_uarch_tail + 1 },
                    break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY,
                })
                expect.equal(machine:get_root_hash(), expected_root_hash)

                -- A same-target call still returns the fixed-point period, which requires the tail.
                expect.fail(function()
                    machine:collect_uarch_cycle_root_hashes(machine:read_reg("mcycle"))
                end, "revert uarch tail is required")
                expect.equal(
                    machine:collect_uarch_cycle_root_hashes(machine:read_reg("mcycle"), 0, revert_uarch_tail),
                    {
                        hashes = revert_uarch_tail,
                        mcycle_hash_offsets = { 1, #revert_uarch_tail + 1 },
                        break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY,
                    }
                )
                expect.equal(machine:get_root_hash(), expected_root_hash)

                -- A running same-target call still performs no transition.
                local running_machine <close> = create_machine({ ram = { length = 4096 } })
                expect.equal(running_machine:collect_uarch_cycle_root_hashes(running_machine:read_reg("mcycle")), {
                    hashes = {},
                    mcycle_hash_offsets = { 1 },
                    break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
                })

                -- The mcycle collector substitutes the recorded revert root hash at the fixed point
                expect.equal(machine:collect_mcycle_root_hashes(mcycle_end, log2_mcycle_period(32), 1), {
                    hashes = { revert_root_hash },
                    break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY,
                    mcycle_phase = 1,
                })
                expect.equal(
                    machine:collect_mcycle_root_hashes(machine:read_reg("mcycle"), log2_mcycle_period(32), 1),
                    {
                        hashes = { revert_root_hash },
                        break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY,
                        mcycle_phase = 1,
                    }
                )
            end)

            it("should collect mcycles during mcycle overflow", function()
                local mcycle_period = 32
                local machine <close> = create_machine({ ram = { length = 4096 } })
                machine:write_reg("mcycle", cartesi.MCYCLE_MAX - 1)
                local collected = machine:collect_mcycle_root_hashes(
                    cartesi.MCYCLE_MAX,
                    log2_mcycle_period(mcycle_period),
                    machine:read_reg("mcycle") % 32
                )
                expect.equal(collected, {
                    hashes = { machine:get_root_hash() },
                    break_reason = cartesi.BREAK_REASON_MCYCLE_OVERFLOW,
                    mcycle_phase = machine:read_reg("mcycle") % mcycle_period,
                })
                expect.equal(machine:read_reg("mcycle"), cartesi.MCYCLE_MAX)
                expect.equal(machine:read_reg("iflags_H"), 0)

                expect.equal(
                    machine:collect_mcycle_root_hashes(
                        cartesi.MCYCLE_MAX,
                        log2_mcycle_period(mcycle_period),
                        machine:read_reg("mcycle") % 32
                    ),
                    {
                        hashes = { machine:get_root_hash() },
                        break_reason = cartesi.BREAK_REASON_MCYCLE_OVERFLOW,
                        mcycle_phase = machine:read_reg("mcycle") % mcycle_period,
                    }
                )
                expect.equal(machine:read_reg("mcycle"), cartesi.MCYCLE_MAX)
            end)

            it("should collect uarch cycles during mcycle overflows", function()
                local machine <close> = create_machine({ ram = { length = 4096 } })
                machine:write_reg("mcycle", cartesi.MCYCLE_MAX - 1)
                local collected_uarch =
                    machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, 0, pristine_revert_uarch_tail)
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
                local expected_root_hash = machine:get_root_hash()
                expect.equal(collected_uarch.hashes[collected_uarch.mcycle_hash_offsets[2] - 1], expected_root_hash)
                expect.equal(collected_uarch.hashes[collected_uarch.mcycle_hash_offsets[3] - 1], expected_root_hash)
                expect.equal(#collected_uarch.mcycle_hash_offsets, 3)
                expect.equal(machine:read_reg("mcycle"), cartesi.MCYCLE_MAX)
                expect.equal(machine:read_reg("iflags_H"), 0)

                collected_uarch = machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX)
                expect.equal(machine:get_root_hash(), expected_root_hash)
                expect.equal(collected_uarch.break_reason, cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
                expect.equal(#collected_uarch.mcycle_hash_offsets, 2)
                expect.equal(collected_uarch.hashes[collected_uarch.mcycle_hash_offsets[2] - 1], expected_root_hash)
            end)

            local add_machine_config = {
                ram = {
                    length = 4096, -- non power of 2 on purpose to exercise address range boundaries
                    backing_store = {
                        data_filename = tests_util.tests_path .. "rv64ui-p-add.bin",
                    },
                },
            }
            local yield_machine_config = {
                ram = {
                    length = 8191 * 4096, -- non power of 2 on purpose to exercise address range boundaries
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

            it("should collect the same mcycle hashes across irregular call partitions", function()
                local mcycle_start = 1
                local mcycle_end = 65
                local mcycle_period = 4
                local mcycle_phase = mcycle_start % mcycle_period
                local targets = { 2, 7, 19, 34, mcycle_end }
                for _, log2_bundle_mcycle_count in ipairs({ 0, 2 }) do
                    local one_shot_machine <close> = create_machine(add_machine_config)
                    local partitioned_machine <close> = create_machine(add_machine_config)
                    one_shot_machine:run(mcycle_start)
                    partitioned_machine:run(mcycle_start)

                    local one_shot = one_shot_machine:collect_mcycle_root_hashes(
                        mcycle_end,
                        log2_mcycle_period(mcycle_period),
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    local partitioned = collect_mcycle_root_hashes_in_parts(
                        partitioned_machine,
                        targets,
                        mcycle_period,
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )

                    expect.equal(partitioned, one_shot)
                    expect.equal(partitioned_machine:read_reg("mcycle"), one_shot_machine:read_reg("mcycle"))
                    expect.equal(partitioned_machine:get_root_hash(), one_shot_machine:get_root_hash())
                end
            end)

            it("should collect the same uarch hashes across irregular call partitions", function()
                local mcycle_start = 1
                local mcycle_end = 4
                local targets = { 2, mcycle_end }
                for _, log2_bundle_uarch_cycle_count in ipairs({ 0, 4 }) do
                    local one_shot_machine <close> = create_machine(add_machine_config)
                    local partitioned_machine <close> = create_machine(add_machine_config)
                    one_shot_machine:run(mcycle_start)
                    partitioned_machine:run(mcycle_start)

                    local one_shot = one_shot_machine:collect_uarch_cycle_root_hashes(
                        mcycle_end,
                        log2_bundle_uarch_cycle_count,
                        pristine_revert_uarch_tail
                    )
                    local partitioned = collect_uarch_cycle_root_hashes_in_parts(
                        partitioned_machine,
                        targets,
                        log2_bundle_uarch_cycle_count,
                        pristine_revert_uarch_tail
                    )

                    expect.equal(partitioned, one_shot)
                    expect.equal(partitioned_machine:read_reg("mcycle"), one_shot_machine:read_reg("mcycle"))
                    expect.equal(partitioned_machine:get_root_hash(), one_shot_machine:get_root_hash())
                end
            end)

            it("should use the same fixed-point precedence across advancement APIs", function()
                local cases = {
                    {
                        expected = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
                    },
                    {
                        registers = { iflags_Y = 1 },
                        expected = cartesi.BREAK_REASON_YIELDED_MANUALLY,
                    },
                    {
                        registers = { iflags_H = 1, iflags_Y = 1 },
                        expected = cartesi.BREAK_REASON_HALTED,
                    },
                    {
                        registers = { imcyclemax = 0, iflags_H = 1, iflags_Y = 1 },
                        expected = cartesi.BREAK_REASON_MCYCLE_OVERFLOW,
                    },
                }

                local function make_case_machine(case)
                    local machine = create_machine({ ram = { length = 4096 } })
                    for reg, value in pairs(case.registers or {}) do
                        machine:write_reg(reg, value)
                    end
                    return machine
                end

                for _, case in ipairs(cases) do
                    local run_machine <close> = make_case_machine(case)
                    local root_hash = run_machine:get_root_hash()
                    expect.equal(run_machine:run(0), case.expected)
                    expect.equal(run_machine:get_root_hash(), root_hash)

                    local log_machine <close> = make_case_machine(case)
                    root_hash = log_machine:get_root_hash()
                    local log_filename = filesystem.temp_pathname()
                    local _ <close> = tests_util.scope_exit(function()
                        os.remove(log_filename)
                    end)
                    expect.equal(log_machine:log_step(0, log_filename), case.expected)
                    expect.equal(log_machine:get_root_hash(), root_hash)
                    expect.equal(log_machine:verify_step(root_hash, log_filename, 0), root_hash)

                    local mcycle_machine <close> = make_case_machine(case)
                    root_hash = mcycle_machine:get_root_hash()
                    local collected_mcycle = mcycle_machine:collect_mcycle_root_hashes(0, log2_mcycle_period(4))
                    expect.equal(collected_mcycle.break_reason, case.expected)
                    expect.equal(collected_mcycle.mcycle_phase, 0)
                    if case.expected == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then
                        expect.equal(collected_mcycle.hashes, {})
                    else
                        expect.equal(collected_mcycle.hashes, { root_hash })
                    end
                    expect.equal(mcycle_machine:get_root_hash(), root_hash)

                    local uarch_machine <close> = make_case_machine(case)
                    root_hash = uarch_machine:get_root_hash()
                    local collected = uarch_machine:collect_uarch_cycle_root_hashes(0)
                    expect.equal(collected.break_reason, case.expected)
                    if case.expected == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then
                        expect.equal(collected.hashes, {})
                        expect.equal(collected.mcycle_hash_offsets, { 1 })
                    else
                        expect.equal(#collected.mcycle_hash_offsets, 2)
                        expect.equal(collected.hashes[collected.mcycle_hash_offsets[2] - 1], root_hash)
                    end
                    expect.equal(uarch_machine:get_root_hash(), root_hash)
                end
            end)

            it("should preserve fixed-point streams across earlier partition targets", function()
                local revert_root_hash = string.rep("\x5a", cartesi.HASH_SIZE)
                local cases = {
                    {
                        registers = { iflags_H = 1 },
                    },
                    {
                        registers = { iflags_Y = 1 },
                    },
                    {
                        registers = { imcyclemax = 0, iflags_H = 1, iflags_Y = 1 },
                    },
                    {
                        registers = {
                            iflags_Y = 1,
                            htif_tohost_dev = cartesi.HTIF_DEV_YIELD,
                            htif_tohost_cmd = cartesi.HTIF_YIELD_CMD_MANUAL,
                            htif_tohost_reason = cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED,
                        },
                        rejected = true,
                    },
                }

                local function make_case_machine(case)
                    local machine = create_machine({ ram = { length = 4096 } })
                    if case.rejected then
                        machine:write_revert_root_hash(revert_root_hash)
                    end
                    for reg, value in pairs(case.registers) do
                        machine:write_reg(reg, value)
                    end
                    return machine
                end

                for _, case in ipairs(cases) do
                    local one_shot_machine <close> = make_case_machine(case)
                    local partitioned_machine <close> = make_case_machine(case)
                    local one_shot = one_shot_machine:collect_mcycle_root_hashes(32, log2_mcycle_period(4), 0, 2)
                    local partitioned = collect_mcycle_root_hashes_in_parts(partitioned_machine, { 1, 32 }, 4, 0, 2)
                    expect.equal(partitioned, one_shot)
                    expect.equal(partitioned_machine:get_root_hash(), one_shot_machine:get_root_hash())

                    local one_shot_uarch_machine <close> = make_case_machine(case)
                    local partitioned_uarch_machine <close> = make_case_machine(case)
                    local revert_uarch_tail = case.rejected and { revert_root_hash, revert_root_hash } or nil
                    local one_shot_uarch =
                        one_shot_uarch_machine:collect_uarch_cycle_root_hashes(32, 4, revert_uarch_tail)
                    local partitioned_uarch = collect_uarch_cycle_root_hashes_in_parts(
                        partitioned_uarch_machine,
                        { 1, 32 },
                        4,
                        revert_uarch_tail
                    )
                    expect.equal(partitioned_uarch, one_shot_uarch)
                    expect.equal(partitioned_uarch_machine:get_root_hash(), one_shot_uarch_machine:get_root_hash())
                end
            end)

            it("should bundle mcycle root hashes leaving no partial bundle when the last bundle is complete", function()
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
                        log2_mcycle_period(mcycle_period),
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.not_exist(collected.partial_bundle)
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
                    log2_mcycle_period(mcycle_period),
                    mcycle_phase,
                    log2_bundle_mcycle_count
                )
                expect.not_exist(collected.partial_bundle)
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
                    local _ <close> = tests_util.scope_exit(function()
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
                        log2_mcycle_period(mcycle_period),
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.exist(collected.console_io_error)
                    expect.truthy(collected.console_io_error:find("console output flush failed"))
                    collected.console_io_error = nil
                    expect.not_exist(collected.partial_bundle)
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

            it(
                "should bundle mcycle root hashes leaving a partial bundle when the last bundle is incomplete",
                function()
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
                            log2_mcycle_period(mcycle_period),
                            mcycle_phase,
                            log2_bundle_mcycle_count
                        )
                        expect.exist(collected.partial_bundle)
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
                end
            )

            it("should bundle mcycle root hashes continuing from a previous partial bundle", function()
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
                            log2_mcycle_period(mcycle_period),
                            last_collected.mcycle_phase,
                            log2_bundle_mcycle_count,
                            last_collected.partial_bundle
                        )
                        tabular.append(all_hashes, last_collected.hashes)
                        if
                            last_collected.break_reason == cartesi.BREAK_REASON_HALTED
                            or last_collected.break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY
                            or last_collected.break_reason == cartesi.BREAK_REASON_MCYCLE_OVERFLOW
                        then
                            break
                        end
                    end
                    local all_collected = {
                        mcycle_phase = last_collected.mcycle_phase,
                        break_reason = last_collected.break_reason,
                        hashes = all_hashes,
                        partial_bundle = last_collected.partial_bundle,
                    }
                    expect.not_exist(all_collected.partial_bundle)
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

            it("should bundle mcycle root hashes leaving no partial bundle when halting", function()
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
                        log2_mcycle_period(mcycle_period),
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.not_exist(collected.partial_bundle)
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

            it("should bundle mcycle root hashes leaving no partial bundle when yielding", function()
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
                        log2_mcycle_period(mcycle_period),
                        mcycle_phase,
                        log2_bundle_mcycle_count
                    )
                    expect.not_exist(collected.partial_bundle)
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
                    local collected = machine:collect_uarch_cycle_root_hashes(
                        mcycle_end,
                        log2_uarch_cycle_mcycle_count,
                        pristine_revert_uarch_tail
                    )
                    local expected_collected =
                        expect_uarch_cycle_root_hashes(compare_machine, mcycle_end, log2_uarch_cycle_mcycle_count)
                    expect.equal(collected, expected_collected)
                    expect.equal(machine:get_root_hash(), compare_machine:get_root_hash())
                end
            end)

            it("should end the last uarch bundle with the reset hash", function()
                local log2_bundle_uarch_cycle_count = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
                local bundle_uarch_cycle_count = 1 << log2_bundle_uarch_cycle_count
                local config = { ram = { length = 4096 } }
                local machine <close> = create_machine(config)
                local compare_machine <close> = cartesi.machine(config)
                local revert_root_hash = machine:read_revert_root_hash()
                local collected = machine:collect_uarch_cycle_root_hashes(1, log2_bundle_uarch_cycle_count, {
                    revert_root_hash,
                    revert_root_hash,
                })

                local frontier = hash_tree.frontier(log2_bundle_uarch_cycle_count, "keccak256")
                local execution_uarch_cycle_count = 0
                for uarch_cycle = 1, math.maxinteger do
                    local break_reason = compare_machine:run_uarch(uarch_cycle)
                    if break_reason == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then
                        break
                    end
                    hash_tree.frontier_push_back(frontier, compare_machine:get_root_hash())
                    execution_uarch_cycle_count = execution_uarch_cycle_count + 1
                end
                expect.truthy(execution_uarch_cycle_count > 0)
                expect.truthy(execution_uarch_cycle_count < bundle_uarch_cycle_count - 1)

                local halt_root_hash = compare_machine:get_root_hash()
                local all_halted_bundle_hash = halt_root_hash
                for _ = 1, log2_bundle_uarch_cycle_count do
                    all_halted_bundle_hash = cartesi.keccak256(all_halted_bundle_hash, all_halted_bundle_hash)
                end
                hash_tree.frontier_pad_back(
                    frontier,
                    halt_root_hash,
                    bundle_uarch_cycle_count - execution_uarch_cycle_count - 1
                )
                compare_machine:reset_uarch()
                hash_tree.frontier_push_back(frontier, compare_machine:get_root_hash())

                expect.equal(collected, {
                    hashes = {
                        all_halted_bundle_hash,
                        hash_tree.frontier_get_root_hash(frontier),
                    },
                    mcycle_hash_offsets = { 1, 3 },
                    break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
                })
                expect.equal(machine:get_root_hash(), compare_machine:get_root_hash())
            end)

            it("should include the halt root immediately before an unbundled reset", function()
                local mcycle_start = 256
                local machine <close> = create_machine(add_machine_config)
                local compare_machine <close> = cartesi.machine(add_machine_config)
                machine:run(mcycle_start)
                compare_machine:run(mcycle_start)

                local collected =
                    machine:collect_uarch_cycle_root_hashes(mcycle_start + 1, 0, pristine_revert_uarch_tail)

                for uarch_cycle = 1, math.maxinteger do
                    if compare_machine:run_uarch(uarch_cycle) == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then
                        break
                    end
                end
                local halt_root_hash = compare_machine:get_root_hash()
                compare_machine:reset_uarch()
                local reset_root_hash = compare_machine:get_root_hash()

                expect.equal(#collected.mcycle_hash_offsets, 2)
                local reset_index = collected.mcycle_hash_offsets[2] - 1
                expect.equal(collected.hashes[reset_index - 1], halt_root_hash)
                expect.equal(collected.hashes[reset_index], reset_root_hash)
            end)

            it("should substitute the revert root hash when bundling across a rejected yield", function()
                local log2_bundle_mcycle_count = 2
                local mcycle_period = 4
                local mcycle_end = 1024
                local revert_root_hash = string.rep("\x5a", cartesi.HASH_SIZE)
                local machine <close> = create_machine(yield_machine_config)
                machine:write_revert_root_hash(revert_root_hash)
                -- the bundles that follow a rejected yield contain only revert root hash repetitions
                local revert_bundle_hash = revert_root_hash
                for _ = 1, log2_bundle_mcycle_count do
                    revert_bundle_hash = cartesi.keccak256(revert_bundle_hash, revert_bundle_hash)
                end
                local count_rejected_yields = 0
                local last_collected = { mcycle_phase = 0 }
                for _ = 1, 64 do
                    local collected = machine:collect_mcycle_root_hashes(
                        mcycle_end,
                        log2_mcycle_period(mcycle_period),
                        last_collected.mcycle_phase,
                        log2_bundle_mcycle_count,
                        last_collected.partial_bundle
                    )
                    if collected.break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY then
                        if is_rejected_manual_yield(machine) then
                            expect.equal(collected.hashes[#collected.hashes], revert_bundle_hash)
                            count_rejected_yields = count_rejected_yields + 1
                        end
                        machine:write_reg("iflags_Y", 0)
                    elseif collected.break_reason == cartesi.BREAK_REASON_HALTED then
                        break
                    end
                    last_collected = collected
                end
                -- htif_yield.bin breaks twice on a rejected manual yield, once with the rx-rejected reason
                -- and once with the tx-output automatic reason, which shares the same reason value
                expect.equal(count_rejected_yields, 2)
                expect.equal(machine:read_reg("iflags_H"), 1)
            end)

            it("should collect across a rejected yield using a tail collected in advance", function()
                local machine <close> = create_machine(yield_machine_config)
                local compare_machine <close> = cartesi.machine(yield_machine_config)
                -- run both machines to the first manual yield, where the machine waits for a response
                expect.equal(machine:run(1 << 62), cartesi.BREAK_REASON_YIELDED_MANUALLY)
                compare_machine:run(1 << 62)
                -- collecting on the waiting machine needs no tail and returns its period, which is
                -- the tail for ranges that end rejected after the machine resumes
                local revert_root_hash = machine:get_root_hash()
                local bootstrap = machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX)
                expect.equal(bootstrap.break_reason, cartesi.BREAK_REASON_YIELDED_MANUALLY)
                expect.equal(#bootstrap.mcycle_hash_offsets, 2)
                local revert_uarch_tail = bootstrap.hashes
                expect.equal(revert_uarch_tail[#revert_uarch_tail], revert_root_hash)
                expect.equal(machine:get_root_hash(), revert_root_hash)
                -- record the revert root hash and resume the guest, standing in for
                -- send_cmio_response, whose fromhost response fails this guest's ack checks
                machine:write_revert_root_hash(revert_root_hash)
                machine:write_reg("iflags_Y", 0)
                compare_machine:write_revert_root_hash(revert_root_hash)
                compare_machine:write_reg("iflags_Y", 0)
                -- run until the guest rejects, collecting with the tail in hand
                local count_rejected_yields = 0
                for _ = 1, 32 do
                    local collected = machine:collect_uarch_cycle_root_hashes(1 << 62, 0, revert_uarch_tail)
                    local expected_collected =
                        expect_uarch_cycle_root_hashes(compare_machine, 1 << 62, 0, revert_uarch_tail)
                    expect.equal(collected, expected_collected)
                    expect.equal(machine:get_root_hash(), compare_machine:get_root_hash())
                    if collected.break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY then
                        if is_rejected_manual_yield(machine) then
                            -- the collected stream ends with the period collected before the response
                            for i = 1, #revert_uarch_tail do
                                expect.equal(
                                    collected.hashes[#collected.hashes - #revert_uarch_tail + i],
                                    revert_uarch_tail[i]
                                )
                            end
                            count_rejected_yields = count_rejected_yields + 1
                            break
                        end
                        machine:write_reg("iflags_Y", 0)
                        compare_machine:write_reg("iflags_Y", 0)
                    elseif collected.break_reason == cartesi.BREAK_REASON_HALTED then
                        break
                    end
                end
                expect.equal(count_rejected_yields, 1)
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
                ram = { length = 4096 },
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
            -- htif_yield.bin breaks twice on a rejected manual yield, once with the rx-rejected reason
            -- and once with the tx-output automatic reason, which shares the same reason value
            local yield_rejected_count = 2
            local yield_revert_root_hash = string.rep("\x5a", cartesi.HASH_SIZE)
            -- a fabricated period for the reverted machine, collected as the tail after the rejected yield
            local yield_revert_uarch_tail = {
                string.rep("\x01", cartesi.HASH_SIZE),
                string.rep("\x02", cartesi.HASH_SIZE),
                string.rep("\x03", cartesi.HASH_SIZE),
                yield_revert_root_hash,
            }

            if hash_function == "keccak256" then
                it("should fail when microarchitecture is not reset", function()
                    local machine <close> = cartesi.machine(empty_machine_config)
                    machine:run_uarch(1)
                    expect.fail(function()
                        machine:collect_mcycle_root_hashes(0, log2_mcycle_period(32), 1)
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
                local collected = collect_machine:collect_mcycle_root_hashes(
                    mcycle_target,
                    log2_mcycle_period(mcycle_period),
                    mcycle_phase
                )
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
                local mcycle_period = 32
                local period_count = yield_last_mcycle // mcycle_period
                local machine <close> = cartesi.machine(yield_machine_config)
                local collect_machine <close> = cartesi.machine(yield_machine_config)
                machine:write_revert_root_hash(yield_revert_root_hash)
                collect_machine:write_revert_root_hash(yield_revert_root_hash)
                expect.equal(machine:run(mcycle_start), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                expect.equal(machine:read_reg("mcycle"), mcycle_start)
                collect_machine:run(mcycle_start)
                expect_consistent_root_hash(machine)
                expect.equal(machine:get_root_hash(), collect_machine:get_root_hash())
                local count_manual_yields = 0
                local count_automatic_yields = 0
                local count_rejected_yields = 0
                local count_halts = 1
                local halt_exit_code
                for _ = 1, period_count * 2 do
                    local mcycle_target = machine:read_reg("mcycle") + period_count * mcycle_period
                    local collected = collect_machine:collect_mcycle_root_hashes(
                        mcycle_target,
                        log2_mcycle_period(mcycle_period),
                        mcycle_phase
                    )
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
                        if is_rejected_manual_yield(machine) then
                            -- the entry collected at the rejected yield is the substituted revert root hash
                            expect.equal(collected.hashes[#collected.hashes], yield_revert_root_hash)
                            count_rejected_yields = count_rejected_yields + 1
                        end
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
                expect.equal(count_rejected_yields, yield_rejected_count)
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
                    local collected =
                        collect_machine:collect_uarch_cycle_root_hashes(big_last_mcycle, 0, pristine_revert_uarch_tail)
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
                    local mcycle_period = 32
                    local period_count = yield_last_mcycle // mcycle_period
                    local machine <close> = cartesi.machine(yield_machine_config)
                    local collect_machine <close> = cartesi.machine(yield_machine_config)
                    machine:write_revert_root_hash(yield_revert_root_hash)
                    collect_machine:write_revert_root_hash(yield_revert_root_hash)
                    machine:run(mcycle_start)
                    expect.equal(machine:read_reg("mcycle"), mcycle_start)
                    collect_machine:run(mcycle_start)
                    expect_consistent_root_hash(machine)
                    expect.equal(machine:get_root_hash(), collect_machine:get_root_hash())
                    local mcycle_phase_offset = mcycle_start - mcycle_phase
                    local sparse_hashes_count = 0
                    local count_manual_yields = 0
                    local count_automatic_yields = 0
                    local count_rejected_yields = 0
                    local halt_exit_code
                    for _ = 1, period_count * 2 + 1 do
                        local mcycles_to_phase0 = mcycle_period
                            - ((machine:read_reg("mcycle") - mcycle_phase_offset) % mcycle_period)
                        local mcycle_target = machine:read_reg("mcycle") + mcycles_to_phase0
                        local collected =
                            collect_machine:collect_uarch_cycle_root_hashes(mcycle_target, 0, yield_revert_uarch_tail)
                        local expected_collected =
                            expect_uarch_cycle_root_hashes(machine, mcycle_target, 0, yield_revert_uarch_tail)
                        expect.equal(collect_machine:read_reg("mcycle"), machine:read_reg("mcycle"))
                        expect.equal(collected, expected_collected)
                        expect.equal(collect_machine:get_root_hash(), machine:get_root_hash())
                        mcycles_to_phase0 = (machine:read_reg("mcycle") - mcycle_phase_offset) % mcycle_period
                        local at_fixed_point = machine:read_reg("iflags_Y") ~= 0 or machine:read_reg("iflags_H") ~= 0
                        if mcycles_to_phase0 == 0 or at_fixed_point then
                            expect.equal(yield_sparse_hashes[sparse_hashes_count + 1], canonical_root_hash(machine))
                            sparse_hashes_count = sparse_hashes_count + 1
                        end
                        if machine:read_reg("iflags_Y") == 1 then
                            if is_rejected_manual_yield(machine) then
                                -- the last period is the reverted machine period, ending on the revert root hash
                                expect.equal(
                                    collected.hashes[collected.mcycle_hash_offsets[#collected.mcycle_hash_offsets] - 1],
                                    yield_revert_root_hash
                                )
                                count_rejected_yields = count_rejected_yields + 1
                            end
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
                    expect.equal(count_rejected_yields, yield_rejected_count)
                    expect.equal(halt_exit_code, 42)
                    expect.equal(sparse_hashes_count, #yield_sparse_hashes)
                end)
            end -- if keccak256 hash function
        end) -- descibre hash function
    end -- for hash function
end) -- describe collect hashes

lester.report()
lester.exit()
