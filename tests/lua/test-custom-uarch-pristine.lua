--[[
Tests uarch cycle root hash collection with uarch programs that the stock pristine uarch never runs: one
that halts on the last uarch cycle before UARCH_CYCLE_MAX, one that halts on the uarch cycle that reaches
it, and one that never halts. Each run loads a cartesi module that embeds one of these programs as its
pristine uarch, and CUSTOM_UARCH_PRISTINE names it (tests/Makefile test-custom-uarch-pristine).

The halting programs make the machine a stub that rejects every input (see
tests/uarch/custom-pristine-halt.h), so the collector can reach a rejection without a guest.
]]

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local filesystem = require("cartesi.filesystem")
local hash_tree = require("cartesi.hash-tree")
local tests_util = require("cartesi.tests.util")

local pristine = assert(os.getenv("CUSTOM_UARCH_PRISTINE"), "CUSTOM_UARCH_PRISTINE is not set")
local uarch_tests_dir = assert(os.getenv("CARTESI_TESTS_UARCH_PATH"), "uarch tests path is not set")
local image = filesystem.read_file(uarch_tests_dir .. "/rv64ui-uarch-custom-pristine-" .. pristine .. ".bin")

-- Uarch cycle on which each program halts
local halt_cycles = {
    ["halt-before-limit"] = cartesi.UARCH_CYCLE_MAX - 1,
    ["halt-at-limit"] = cartesi.UARCH_CYCLE_MAX,
    ["overflow"] = false,
}
local halt_cycle = halt_cycles[pristine]
assert(halt_cycle ~= nil, "unknown custom pristine uarch " .. pristine)

local LOG2_UARCH_SPAN = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
local LOG2_BUNDLE = 10

local function htif_manual_yield_tohost(reason)
    return (cartesi.HTIF_DEV_YIELD << cartesi.HTIF_DEV_SHIFT)
        | (cartesi.HTIF_YIELD_CMD_MANUAL << cartesi.HTIF_CMD_SHIFT)
        | (reason << cartesi.HTIF_REASON_SHIFT)
end

-- A stub machine at a manual yield that accepted its previous input, where the CLI captures the
-- revert uarch tail
local function new_machine()
    local machine = cartesi.machine({ ram = { length = 4096 }, cmio = { rx_buffer = {}, tx_buffer = {} } })
    machine:write_reg("iflags_Y", 1)
    machine:write_reg("htif_tohost", htif_manual_yield_tohost(cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED))
    return machine
end

-- Root of the uarch cycle subtree of one mcycle in a collection, expanding the halted state root hash
-- entry to the positions before the reset-ending entry, as consumers of the collection do
local function uarch_mcycle_root(collected, mcycle_index, log2_entries_per_mcycle)
    local first = collected.mcycle_hash_offsets[mcycle_index]
    local last = collected.mcycle_hash_offsets[mcycle_index + 1] - 1
    local frontier = hash_tree.frontier(log2_entries_per_mcycle, "keccak256")
    for i = first, last - 2 do
        hash_tree.frontier_push_back(frontier, collected.hashes[i])
    end
    local execution_count = last - first - 1
    hash_tree.frontier_pad_back(
        frontier,
        collected.hashes[last - 1],
        (1 << log2_entries_per_mcycle) - 1 - execution_count
    )
    hash_tree.frontier_push_back(frontier, collected.hashes[last])
    return hash_tree.frontier_get_root_hash(frontier)
end

describe("custom pristine uarch " .. pristine, function()
    it("should be the embedded pristine uarch", function()
        local machine <close> = new_machine()
        expect.equal(machine:read_memory(cartesi.UARCH_RAM_START_ADDRESS, #image), image)
        expect.equal(
            machine:get_node_hash(cartesi.UARCH_STATE_START_ADDRESS, cartesi.UARCH_STATE_LOG2_SIZE),
            cartesi.UARCH_PRISTINE_STATE_HASH
        )
    end)

    if not halt_cycle then
        local overflow_error = "uarch reached its maximum cycle and cannot advance more uarch cycles"

        it("should fail collecting the revert uarch tail at uarch cycle overflow", function()
            local machine <close> = new_machine()
            expect.fail(function()
                machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, 0)
            end, overflow_error)
        end)

        it("should make the CLI report the uarch cycle overflow", function()
            local parent = filesystem.create_temporary_directory(os.getenv("TMPDIR") or "/tmp", "cartesi-test-")
            local stored = parent .. "/machine"
            local input = parent .. "/input.bin"
            local hash = parent .. "/hash.bin"
            local stderr = parent .. "/stderr.txt"
            local _ <close> = tests_util.scope_exit(function()
                pcall(cartesi.machine.remove_stored, cartesi.machine, stored)
                os.remove(input)
                os.remove(hash)
                os.remove(stderr)
                filesystem.remove_directory(parent)
            end)
            do
                local machine <close> = new_machine()
                machine:store(stored)
            end
            filesystem.write_file("input", input)
            local cli_lua = os.getenv("LUA_CLI") or arg[-1]
            local cli = os.getenv("CM_CLI") or "../../src/cartesi-machine.lua"
            local ok = os.execute(
                string.format(
                    "%s %s --load=%s --cmio-advance-state=input:%s"
                        .. " --uarch-cycle-computation-hash=filename:%s,log2_mcycle_period:0,mcycle_period_index:0"
                        .. " --no-revert --no-init-splash >/dev/null 2>%s",
                    cli_lua,
                    cli,
                    stored,
                    input,
                    hash,
                    stderr
                )
            )
            expect.falsy(ok)
            expect.truthy(filesystem.read_file(stderr):find(overflow_error, 1, true))
        end)
        return
    end

    -- State root hashes after each uarch cycle of one mcycle, taken from steps checked by the verifiers
    local stepped = {}

    it("should halt on uarch cycle " .. halt_cycle .. " with logged steps that verify", function()
        local machine <close> = new_machine()
        local initial_root_hash = machine:get_root_hash()
        expect.equal(machine:run_uarch(1), cartesi.UARCH_BREAK_REASON_REACHED_TARGET_UARCH_CYCLE)
        stepped.first = machine:get_root_hash()
        expect.equal(machine:run_uarch(halt_cycle - 1), cartesi.UARCH_BREAK_REASON_REACHED_TARGET_UARCH_CYCLE)
        stepped.before_halt = machine:get_root_hash()
        local log = machine:log_step_uarch()
        stepped.halted = machine:get_root_hash()
        expect.equal(cartesi.machine:verify_step_uarch(stepped.before_halt, log), stepped.halted)
        expect.equal(machine:read_reg("uarch_halt"), 1)
        expect.equal(machine:read_reg("uarch_cycle"), halt_cycle)
        expect.equal(machine:run_uarch(cartesi.UARCH_CYCLE_MAX), cartesi.UARCH_BREAK_REASON_UARCH_HALTED)
        log = machine:log_reset_uarch()
        stepped.reset = machine:get_root_hash()
        expect.equal(cartesi.machine:verify_reset_uarch(stepped.halted, log), stepped.reset)
        -- At a manual yield, the mcycle changes nothing
        expect.equal(stepped.reset, initial_root_hash)
    end)

    it("should halt on uarch cycle " .. halt_cycle .. " when run in one call", function()
        local machine <close> = new_machine()
        expect.equal(machine:run_uarch(cartesi.UARCH_CYCLE_MAX), cartesi.UARCH_BREAK_REASON_UARCH_HALTED)
        expect.equal(machine:read_reg("uarch_cycle"), halt_cycle)
        expect.equal(machine:get_root_hash(), stepped.halted)
    end)

    local tail

    it("should collect the revert uarch tail at a manual yield", function()
        local machine <close> = new_machine()
        local mcycle = machine:read_reg("mcycle")
        local collected = machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, 0)
        tail = collected.hashes
        -- One state root hash per uarch cycle before the halt, then the halted and reset state root hashes
        expect.equal(#tail, halt_cycle + 1)
        expect.equal(tail[1], stepped.first)
        expect.equal(tail[halt_cycle - 1], stepped.before_halt)
        expect.equal(tail[halt_cycle], stepped.halted)
        expect.equal(tail[halt_cycle + 1], stepped.reset)
        expect.equal(machine:get_root_hash(), stepped.reset)
        expect.equal(machine:read_reg("mcycle"), mcycle)
    end)

    it("should reuse the revert uarch tail when the next input is rejected", function()
        local machine <close> = new_machine()
        local mcycle = machine:read_reg("mcycle")
        machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, "input", tail[#tail])
        local collected = machine:collect_uarch_cycle_root_hashes(mcycle + 1, LOG2_BUNDLE, tail)
        expect.equal(collected.break_reason, cartesi.BREAK_REASON_YIELDED_MANUALLY)
        expect.equal(machine:read_reg("htif_tohost_reason"), cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED)
        expect.equal(machine:read_reg("mcycle"), mcycle + 1)
        -- The rejecting mcycle, then the period of the reverted machine, both halting on the same uarch cycle
        local offsets = collected.mcycle_hash_offsets
        expect.equal(#offsets, 3)
        expect.equal(offsets[2] - offsets[1], offsets[3] - offsets[2])
        -- The bundled period of the reverted machine has the root of the unbundled tail
        local unbundled = { hashes = tail, mcycle_hash_offsets = { 1, #tail + 1 } }
        expect.equal(
            uarch_mcycle_root(collected, 2, LOG2_UARCH_SPAN - LOG2_BUNDLE),
            uarch_mcycle_root(unbundled, 1, LOG2_UARCH_SPAN)
        )
    end)
end)

lester.report()
lester.exit()
