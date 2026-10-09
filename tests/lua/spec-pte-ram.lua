-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local cartesi = require("cartesi")
local lester = require("cartesi.third-party.lester")
lester.parse_args()

local regions = {
    { name = "NVRAM", start = 0xa0000000 },
    { name = "CMIO RX", start = cartesi.AR_CMIO_RX_BUFFER_START },
    { name = "flash", start = 0x90000000 },
}
local accesses = {
    { name = "fetch", instruction = 0x00000013, cause = 1, vaddr = 0x1000 },
    { name = "load", instruction = 0x0000b103, cause = 5, vaddr = 0x3000 },
    { name = "store", instruction = 0x0020b023, cause = 7, vaddr = 0x3000 },
    { name = "AMO", instruction = 0x0020b12f, cause = 7, vaddr = 0x3000 },
}

lester.describe("RAM-only page tables", function()
    for _, mode in ipairs({ 8, 9 }) do
        for _, region in ipairs(regions) do
            for _, location in ipairs({ "root", "leaf" }) do
                for _, access in ipairs(accesses) do
                    local name =
                        string.format("Sv%d %s %s in %s", mode == 8 and 39 or 48, access.name, location, region.name)
                    lester.it(name, function()
                        local config = {
                            ram = { length = 1 << 20 },
                            nvram = { { start = 0xa0000000, length = 4096 } },
                            flash_drive = { { start = 0x90000000, length = 4096 } },
                        }
                        local code = cartesi.AR_RAM_START + 0x1000
                        local data = cartesi.AR_RAM_START + 0x8000
                        local levels = mode - 5
                        local tables = {}
                        for level = 1, levels do
                            tables[level] = cartesi.AR_RAM_START + 0x10000 + (level - 1) * 4096
                        end
                        tables[location == "root" and 1 or levels] = region.start
                        local pc = access.name == "fetch" and access.vaddr or code
                        local function initialize(m)
                            for level = 1, levels - 1 do
                                m:write_memory(tables[level], string.pack("<I8", (tables[level + 1] >> 2) | 1))
                            end
                            local leaf = tables[levels]
                            m:write_memory(leaf + 8, string.pack("<I8", (code >> 2) | 0x0b))
                            m:write_memory(leaf + 24, string.pack("<I8", (data >> 2) | 0x07))
                            m:write_memory(code, string.pack("<I4", access.instruction))
                            m:write_memory(data, string.pack("<I8", 0x1122334455667788))
                            m:write_reg("satp", (mode << 60) | (tables[1] >> 12))
                            m:write_reg("pc", pc)
                            m:write_reg("x1", access.vaddr)
                            m:write_reg("x2", 42)
                            -- MPRV lets data accesses walk while instruction fetch stays physical.
                            m:write_reg("iprv", access.name == "fetch" and 1 or 3)
                            m:write_reg("mstatus", access.name == "fetch" and 0 or 0x20800)
                        end
                        local native <close> = cartesi.machine(config)
                        local guest <close> = cartesi.machine(config)
                        initialize(native)
                        initialize(guest)
                        local before = native:get_root_hash()
                        assert(guest:get_root_hash() == before)
                        local pte_before = native:read_memory(region.start, 4096)
                        local native_log = native:log_step(1)
                        local log = guest:log_step_uarch(1 << 20)
                        assert(guest:read_reg("uarch_halt") ~= 0)
                        assert(cartesi.machine:verify_step(before, native_log, 1) == native:get_root_hash())
                        assert(cartesi.machine:verify_step_uarch(before, log, 1 << 20) == guest:get_root_hash())
                        guest:reset_uarch()
                        assert(guest:get_root_hash() == native:get_root_hash(), "native/uarch roots differ")
                        assert(native:read_reg("mcause") == access.cause, "wrong access-fault cause")
                        assert(native:read_reg("mtval") == access.vaddr, "mtval must be the original virtual address")
                        assert(native:read_reg("mepc") == pc)
                        assert(native:read_reg("x2") == 42)
                        assert(native:read_memory(region.start, 4096) == pte_before, "PTE must not be written")
                        assert(native:read_memory(data, 8) == string.pack("<I8", 0x1122334455667788))
                        local pages = string.unpack("<I8", log, 17)
                        for i = 0, pages - 1 do
                            local page = string.unpack("<I8", log, 41 + i * 4136) << 12
                            assert(page ~= region.start, "out-of-RAM PTE must not be read")
                        end
                    end)
                end
            end
        end
    end
end)
lester.report()
lester.exit()
