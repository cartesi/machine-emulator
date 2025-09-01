--[[
Test suite for computation hashes.
]]

local lester = require("cartesi.third-party.lester")
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local util = require("cartesi.tests.util")

local function expect_consistent_root_hash(machine)
    local root_hash = machine:get_root_hash()
    local node_hash = machine:get_node_hash(0, cartesi.TREE_LOG2_ROOT_SIZE)
    local external_root_hash = util.calculate_emulator_hash(machine)
    expect.equal(root_hash, node_hash)
    expect.equal(external_root_hash, root_hash)
end

local function expect_mcycle_root_hashes(machine, mcycle_end, mcycle_period, mcycle_phase)
    local break_reason
    local hashes = {}
    local mcycle_start = machine:read_reg("mcycle") + mcycle_period - mcycle_phase
    for mcycle_target = mcycle_start, mcycle_end, mcycle_period do
        break_reason = machine:run(mcycle_target)
        expect_consistent_root_hash(machine)
        if machine:read_reg("mcycle") ~= mcycle_target then
            mcycle_phase = mcycle_period - (mcycle_target - machine:read_reg("mcycle"))
            break
        end
        mcycle_phase = 0
        table.insert(hashes, machine:get_root_hash())
        if break_reason ~= cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then
            break
        end
    end
    assert(break_reason, "expect_mcycle_root_hashes failed")
    return {
        hashes = hashes,
        break_reason = break_reason,
        mcycle_phase = mcycle_phase,
    }
end

local function expect_uarch_cycle_root_hashes(machine, mcycle_end)
    local hashes = {}
    local reset_indices = {}
    local break_reason
    local mcycle_start = machine:read_reg("mcycle")
    for mcycle = mcycle_start + 1, mcycle_end do
        if machine:read_reg("iflags_H") ~= 0 then
            break_reason = cartesi.BREAK_REASON_HALTED
            break
        end
        if machine:read_reg("iflags_Y") ~= 0 then
            break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY
            break
        end
        if mcycle ~= mcycle_start + 1 and machine:read_reg("iflags_X") ~= 0 then
            break_reason = cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
            break
        end
        expect.equal(machine:read_reg("uarch_cycle"), 0)
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
        expect_consistent_root_hash(machine)
        machine:reset_uarch()
        expect_consistent_root_hash(machine)
        expect.equal(machine:read_reg("mcycle"), mcycle)
        table.insert(hashes, machine:get_root_hash())
        table.insert(reset_indices, #hashes)
        if mcycle == mcycle_end then
            break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
            break
        end
    end
    assert(break_reason, "expect_uarch_cycle_root_hashes failed")
    return {
        hashes = hashes,
        reset_indices = reset_indices,
        break_reason = break_reason,
    }
end

describe("collect hashes", function()
    it("should fail when collecting with invalid arguments", function()
        local machine <close> = cartesi.machine({ ram = { length = 4096 } })
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

    it("should fail when collecting from unsupported machines", function()
        local unrep_machine <close> =
            cartesi.machine({ ram = { length = 4096 }, processor = { registers = { iunrep = 1 } } })
        local soft_machine <close> = cartesi.machine({ ram = { length = 4096 } }, { soft_yield = true })
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

    it("should succeed when collecting 0 periods", function()
        local machine <close> = cartesi.machine({ ram = { length = 4096 } })
        machine:run(1)
        expect.equal(machine:collect_mcycle_root_hashes(machine:read_reg("mcycle"), 32, 1), {
            hashes = {},
            break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
            mcycle_phase = 1,
        })
        expect.equal(machine:collect_uarch_cycle_root_hashes(machine:read_reg("mcycle")), {
            hashes = {},
            reset_indices = {},
            break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
        })
    end)

    it("should succeed when collecting from halted machines", function()
        local machine <close> = cartesi.machine({ ram = { length = 4096 } })
        machine:write_reg("iflags_H", 1)
        expect.equal(machine:collect_mcycle_root_hashes(32, 32, 1), {
            hashes = {},
            break_reason = cartesi.BREAK_REASON_HALTED,
            mcycle_phase = 1,
        })
        expect.equal(machine:read_reg("mcycle"), 0)
        expect.equal(machine:collect_uarch_cycle_root_hashes(32), {
            hashes = {},
            reset_indices = {},
            break_reason = cartesi.BREAK_REASON_HALTED,
        })
        expect.equal(machine:read_reg("mcycle"), 0)
    end)

    it("should succeed when collecting from yielded machines", function()
        local machine <close> = cartesi.machine({ ram = { length = 4096 } })
        machine:write_reg("iflags_Y", 1)
        expect.equal(machine:collect_mcycle_root_hashes(32, 32, 1), {
            hashes = {},
            break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY,
            mcycle_phase = 1,
        })
        expect.equal(machine:read_reg("mcycle"), 0)
        expect.equal(machine:collect_uarch_cycle_root_hashes(32), {
            hashes = {},
            reset_indices = {},
            break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY,
        })
        expect.equal(machine:read_reg("mcycle"), 0)
    end)

    it("should succeed when collecting mcycles during mcycle overflow", function()
        local machine <close> = cartesi.machine({ ram = { length = 4096 } })
        local MAX_MCYCLE <const> = -1
        machine:write_reg("mcycle", MAX_MCYCLE - 1)
        expect.equal(machine:collect_mcycle_root_hashes(MAX_MCYCLE, 32, machine:read_reg("mcycle") % 32), {
            hashes = {},
            break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
            mcycle_phase = machine:read_reg("mcycle") % 32,
        })
        expect.equal(machine:read_reg("mcycle"), MAX_MCYCLE)
        expect.equal(machine:collect_mcycle_root_hashes(MAX_MCYCLE, 32, machine:read_reg("mcycle") % 32), {
            hashes = {},
            break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
            mcycle_phase = machine:read_reg("mcycle") % 32,
        })
        expect.equal(machine:read_reg("mcycle"), MAX_MCYCLE)
    end)

    it("should succeed when collecting uarch cycles during mcycle overflows", function()
        local machine <close> = cartesi.machine({ ram = { length = 4096 } })
        local MAX_MCYCLE <const> = -1
        machine:write_reg("mcycle", MAX_MCYCLE - 1)
        expect.equal(
            machine:collect_uarch_cycle_root_hashes(MAX_MCYCLE).break_reason,
            cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
        )
        expect.equal(machine:read_reg("mcycle"), MAX_MCYCLE)
        expect.equal(machine:collect_uarch_cycle_root_hashes(MAX_MCYCLE), {
            hashes = {},
            reset_indices = {},
            break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
        })
        expect.equal(machine:read_reg("mcycle"), MAX_MCYCLE)
    end)

    for _, hash_function in pairs({ "sha256", "keccak256" }) do
        describe(hash_function, function()
            local big_machine_config = {
                ram = {
                    length = 8191 * 4096, -- non power of 2 on purpose to exercise address range boundaries
                    backing_store = {
                        data_filename = util.images_path .. "linux.bin",
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
                        data_filename = util.tests_path .. "htif_yield.bin",
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
                -- use prime numbers on purpose to test corner cases
                local mcycle_start = 7
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
                expect.equal(#yield_sparse_hashes, period_count)
                expect.equal(count_manual_yields, 8)
                expect.equal(count_automatic_yields, 7)
                expect.equal(halt_exit_code, 42)
                yield_last_root_hash = machine:get_root_hash()
            end)

            if hash_function == "keccak256" then
                it("should match dense uarch root hashes", function()
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
                    -- use prime numbers on purpose to test corner cases
                    local mcycle_start = 7
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
                        if mcycles_to_phase0 == 0 then
                            local period_index = (machine:read_reg("mcycle") - mcycle_phase_offset) // mcycle_period
                            expect.equal(yield_sparse_hashes[period_index], machine:get_root_hash())
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
            end
        end)
    end
end)
