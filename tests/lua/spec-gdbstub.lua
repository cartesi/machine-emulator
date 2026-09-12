-- Tests for collection through the GDB runner.
local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local GDBStub = require("cartesi.gdbstub")

describe("GDB collection", function()
    it("collects fixed-point padding without consuming a pending continue", function()
        for _, registers in ipairs({
            { iflags_H = 1 },
            { iflags_Y = 1 },
            { imcyclemax = 0 },
            { mcycle = math.mininteger, imcyclemax = math.mininteger },
        }) do
            local machine <close> = cartesi.machine({ ram = { length = 4096 } })
            for name, value in pairs(registers) do
                machine:write_reg(name, value)
            end
            local stub = GDBStub.new(machine)
            stub.suspended = true
            stub.mode = "run"
            stub.mcycle_end = cartesi.MCYCLE_MAX
            -- The host may have changed the state since the last debugger call.
            stub.break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
            stub.conn = {}
            stub._pump_session = function()
                error("fixed-point collection consumed the GDB session")
            end
            local root = machine:get_root_hash()
            local mcycle = machine:read_reg("mcycle")
            expect.equal(
                stub:collect_mcycle_root_hashes(mcycle, 2, 0, 1),
                machine:collect_mcycle_root_hashes(mcycle, 2, 0, 1)
            )
            expect.equal(
                stub:collect_uarch_cycle_root_hashes(mcycle, 8),
                machine:collect_uarch_cycle_root_hashes(mcycle, 8)
            )
            expect.equal(machine:get_root_hash(), root)
            expect.equal(machine:read_reg("mcycle"), mcycle)
            expect.equal(stub.suspended, true)
            expect.equal(stub.mode, "run")
            expect.equal(stub.mcycle_end, cartesi.MCYCLE_MAX)
            expect.equal(stub.break_reason, cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
        end
    end)

    it("does not trust a fixed-point reason left over from the previous call", function()
        local machine <close> = cartesi.machine({ ram = { length = 4096 } })
        local stub = GDBStub.new(machine)
        local pumps = 0
        stub.conn = {}
        stub._pump_session = function()
            pumps = pumps + 1
        end
        stub.break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY
        stub:collect_mcycle_root_hashes(1, 0, 0, 0)
        stub.break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY
        stub:collect_uarch_cycle_root_hashes(2, 8, { machine:read_revert_root_hash(), machine:read_revert_root_hash() })
        expect.equal(pumps, 2)
        expect.equal(machine:read_reg("mcycle"), 2)
    end)
end)

lester.report()
lester.exit()
