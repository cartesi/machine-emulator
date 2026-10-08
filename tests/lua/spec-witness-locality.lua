-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local cartesi = require("cartesi")
local lester = require("cartesi.third-party.lester")
local cases = require("cartesi.tests.witness-locality")
local expectations = require("cartesi.tests.witness-locality-expectations")
lester.parse_args()

local function tlb_hit(m, set, va)
    local slot = cartesi.AR_SHADOW_TLB_START + set * 8192 + ((va >> 12) & 255) * 32
    return string.unpack("<I8", m:read_memory(slot, 8)) == (va & ~4095)
end

lester.describe("whole-mcycle witness locality", function()
    for _, case in ipairs(cases) do
        lester.it(case.name .. " (" .. case.program .. ", mcycle " .. case.mcycle .. ")", function()
            local m <close> = case.create()
            local expected = assert(expectations[case.name], "missing locality expectation")
            assert(m:read_reg("mcycle") == case.mcycle and m:read_reg("uarch_cycle") == 0)
            if case.name == "ordinary-alu" then
                assert(tlb_hit(m, 0, m:read_reg("pc")), "ALU anchor must have a code TLB hit")
                assert(string.unpack("<I4", m:read_memory(m:read_reg("pc"), 4)) == 0x00000a13, "expected addi x20,x0,0")
            elseif case.name == "tlb-miss-load" or case.name == "amo-both-misses" then
                assert(tlb_hit(m, 0, m:read_reg("pc")), "anchor must have a code TLB hit")
                assert(not tlb_hit(m, 1, m:read_reg("x1")), "anchor must have a read TLB miss")
                assert(not tlb_hit(m, 2, m:read_reg("x1")), "anchor must have a write TLB miss")
            end
            local before = m:get_root_hash()
            local log = m:log_step_uarch(1 << 20)
            assert(m:read_reg("uarch_halt") ~= 0 and m:read_reg("mcycle") == case.mcycle + 1, "incomplete mcycle")
            assert(log:sub(1, 8) == "CTSI\3\0\0\0", "step-log format changed; review locality parser")
            local pages, nodes, siblings = string.unpack("<I8I8I8", log, 17)
            assert(nodes == 0 and #log == 40 + pages * 4136 + siblings * 32, "unexpected log geometry")
            assert(cartesi.machine:verify_step_uarch(before, log, 1 << 20) == m:get_root_hash())
            if case.name == "trap-tlb-flush" then
                assert(
                    m:read_reg("scause") == 12 and m:read_reg("sepc") == 0x19fc,
                    "expected delegated instruction page fault"
                )
                local tlb_pages = 0
                for i = 0, pages - 1 do
                    local page = string.unpack("<I8", log, 41 + i * 4136) << 12
                    if
                        page >= cartesi.AR_SHADOW_TLB_START
                        and page < cartesi.AR_SHADOW_TLB_START + cartesi.AR_SHADOW_TLB_LENGTH
                    then
                        tlb_pages = tlb_pages + 1
                    end
                end
                assert(tlb_pages == 6, "trap must witness all six TLB pages")
            elseif case.name == "tlb-miss-load" or case.name == "amo-both-misses" then
                assert(
                    m:read_reg("pc") == 0x1008 and m:read_reg("x2") == 0x1122334455667788,
                    "load/AMO did not succeed"
                )
                assert(tlb_hit(m, 1, 0x3000), "read TLB was not filled")
                if case.name == "amo-both-misses" then
                    assert(tlb_hit(m, 2, 0x3000), "write TLB was not filled")
                    assert(
                        string.unpack("<I8", m:read_memory(0xa0001000, 8)) == 0x9999999999999999,
                        "AMO did not store"
                    )
                end
            end
            assert(
                pages <= expected.pages and #log <= expected.log_bytes,
                string.format(
                    "%s locality regression: pages %d (limit %d, delta %+d); log bytes %d (limit %d, delta %+d)",
                    case.name,
                    pages,
                    expected.pages,
                    pages - expected.pages,
                    #log,
                    expected.log_bytes,
                    #log - expected.log_bytes
                )
            )
        end)
    end
end)
lester.report()
lester.exit()
