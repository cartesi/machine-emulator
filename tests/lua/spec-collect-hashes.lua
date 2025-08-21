--[[
Test suite for computation hashes.
]]

local lester = require("cartesi.third-party.lester")
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local util = require("cartesi.tests.util")

local function expect_consistent_root_hash(machine)
    expect.truthy(machine:verify_hash_tree())
    local root_hash = machine:get_root_hash()
    local external_root_hash = util.calculate_emulator_hash(machine)
    local node_hash = machine:get_node_hash(0, cartesi.TREE_LOG2_ROOT_SIZE)
    expect.truthy(machine:verify_hash_tree())
    expect.equal(root_hash, node_hash)
    expect.equal(external_root_hash, root_hash)
end

local function expect_mcycle_root_hashes(machine, mcycle_phase, mcycle_period, period_count)
    local break_reason
    local hashes = {}
    local mcycle_start = machine:read_reg("mcycle") - mcycle_phase
    local mcycle_max = mcycle_start + (period_count * mcycle_period)
    for mcycle = mcycle_start + mcycle_period, mcycle_max, mcycle_period do
        break_reason = machine:run(mcycle)
        expect_consistent_root_hash(machine)
        if break_reason ~= cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then
            break
        end
        table.insert(hashes, machine:get_root_hash())
    end
    local mcycle = machine:read_reg("mcycle")
    mcycle_phase = mcycle % mcycle_period
    return {
        hashes = hashes,
        break_reason = break_reason,
        mcycle_phase = mcycle_phase,
    }
end

local function expect_uarch_cycle_root_hashes(machine, mcycle_count)
    local hashes = {}
    local reset_indices = {}
    local break_reason = "reached_target_mcycle"
    local initial_mcycle = machine:read_reg("mcycle")
    for mcycle = initial_mcycle + 1, initial_mcycle + mcycle_count do
        if machine:read_reg("iflags_H") ~= 0 then
            break_reason = "halted"
            break
        end
        if machine:read_reg("iflags_X") ~= 0 then
            break_reason = "yielded_automatically"
            break
        end
        if machine:read_reg("iflags_Y") ~= 0 then
            break_reason = "yielded_manually"
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
    end
    return {
        hashes = hashes,
        reset_indices = reset_indices,
        break_reason = break_reason,
    }
end

describe("collect hashes", function()
    for _, hash_function in pairs({ "sha256", "keccak256" }) do
        describe(hash_function, function()
            local test_machine_config = {
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

            local test_last_mcycle
            local test_last_root_hash

            it("should match sparse periodic root hashes", function()
                local machine <close> = cartesi.machine(test_machine_config)
                local collect_machine <close> = cartesi.machine(test_machine_config)
                expect_consistent_root_hash(machine)
                expect.equal(machine:get_root_hash(), collect_machine:get_root_hash())
                local mcycle_phase = 0
                local mcycle_period = 8 * 1024 * 1024
                local period_count = 16
                local collected = collect_machine:collect_mcycle_root_hashes(mcycle_phase, mcycle_period, period_count)
                local expected_collected = expect_mcycle_root_hashes(machine, mcycle_phase, mcycle_period, period_count)
                local halt_exit_code = machine:read_reg("htif_tohost_data") >> 1
                expect.equal(collected, expected_collected)
                expect.equal(collect_machine:get_root_hash(), machine:get_root_hash())
                expect.equal(collected.break_reason, cartesi.BREAK_REASON_HALTED)
                expect.equal(halt_exit_code, 255)
                test_last_mcycle = machine:read_reg("mcycle")
                test_last_root_hash = machine:get_root_hash()
            end)

            if hash_function == "keccak256" then
                it("should match dense uarch root hashes", function()
                    expect.truthy(test_last_mcycle ~= nil and test_last_root_hash ~= nil)
                    local machine <close> = cartesi.machine(test_machine_config)
                    local collect_machine <close> = cartesi.machine(test_machine_config)
                    local mcycle_count = 2
                    expect.equal(
                        machine:run(test_last_mcycle - mcycle_count),
                        cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
                    )
                    expect_consistent_root_hash(machine)
                    collect_machine:run(test_last_mcycle - mcycle_count)
                    expect.equal(machine:get_root_hash(), collect_machine:get_root_hash())
                    local collected = collect_machine:collect_uarch_cycle_root_hashes(mcycle_count)
                    local expected_collected = expect_uarch_cycle_root_hashes(machine, mcycle_count)
                    local halt_exit_code = machine:read_reg("htif_tohost_data") >> 1
                    expect.equal(collected, expected_collected)
                    expect.equal(machine:read_reg("mcycle"), test_last_mcycle)
                    expect.equal(machine:get_root_hash(), test_last_root_hash)
                    expect.equal(halt_exit_code, 255)
                end)
            end
        end)
    end
end)
