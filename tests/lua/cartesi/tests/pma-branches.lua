-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local cartesi = require("cartesi")

-- Split fetch crosses a root-level VPN boundary; data uses a third root entry.
-- Separate branches exercise cold table pages even with a successful lookup cache.
return function(mode, clustered, store_fault, guest_image)
    local config = { ram = { length = 1 << 20 }, flash_drive = {}, nvram = {} }
    if guest_image then
        config.uarch = { ram = { backing_store = { data_filename = guest_image } } }
    end
    for i = 1, 8 do
        config.flash_drive[i] = { start = 0x90000000 + i * 0x10000, length = 0x10000 }
        config.nvram[i] = { start = 0xa0000000 + i * 0x10000, length = 0x10000 }
    end
    local levels = mode - 5
    local boundary = 1 << (12 + 9 * (levels - 1))
    local pc = boundary - 2
    local vdata = 2 * boundary
    local code = cartesi.AR_RAM_START + 4096
    local data = config.nvram[1].start + 0xf000
    local tables = {}
    for i = 1, 1 + 3 * (levels - 1) do
        local region = clustered and 8 or (8 - ((i - 1) % 8))
        local page = clustered and (i - 1) or ((i - 1) // 8)
        tables[i] = config.nvram[region].start + page * 4096
    end
    local function initialize(m)
        local cursor = 1
        local function map(vaddr, paddr, flags)
            local at = tables[1]
            for level = levels - 1, 1, -1 do
                cursor = cursor + 1
                local child = tables[cursor]
                local vpn = (vaddr >> (12 + 9 * level)) & 511
                m:write_memory(at + vpn * 8, string.pack("<I8", (child >> 2) | 1))
                at = child
            end
            local vpn = (vaddr >> 12) & 511
            m:write_memory(at + vpn * 8, string.pack("<I8", (paddr >> 2) | flags))
        end
        map(pc, code, 0x0b)
        map(pc + 2, code + 4096, 0x0b)
        map(vdata, data, store_fault and 0x03 or 0x07)
        local instruction = 0x0020b12f -- amoadd.d x2,x2,(x1)
        m:write_memory(code + 4094, string.pack("<I2", instruction & 0xffff))
        m:write_memory(code + 4096, string.pack("<I2", instruction >> 16))
        m:write_memory(data, string.pack("<I8", 0x1122334455667788))
        m:write_reg("satp", (mode << 60) | (tables[1] >> 12))
        m:write_reg("pc", pc)
        m:write_reg("iprv", 1)
        m:write_reg("x1", vdata)
        m:write_reg("x2", 0x8877665544332211)
    end
    return config, initialize, pc, data
end
