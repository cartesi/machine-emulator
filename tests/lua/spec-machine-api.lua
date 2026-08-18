--[[
Test suite for machine API surface.
Specifically, it provides test coverage for:
    machine.cpp (get_address_name, get_reg_address, read_reg, write_reg, write_word)
    shadow-registers.hpp (shadow_registers_get_what, shadow_registers_get_what_name)
    shadow-tlb.hpp (shadow_tlb_get_what, shadow_tlb_get_what_name)
    shadow-uarch-state.hpp (shadow_uarch_state_get_what, shadow_uarch_state_get_what_name)
    pmas.hpp (pmas_get_what, pmas_get_what_name)
]]

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local cartesi = require("cartesi")
local tests_util = require("cartesi.tests.util")
local describe, it, expect = lester.describe, lester.it, lester.expect

local variants = {
    {
        name = "local",
        create = function(config)
            return cartesi.machine(config)
        end,
    },
    {
        name = "remote",
        create = function(config)
            local jsonrpc = require("cartesi.jsonrpc")
            return jsonrpc.spawn_server():set_cleanup_call(jsonrpc.SHUTDOWN):create(config)
        end,
    },
}

for _, variant in ipairs(variants) do
    describe("machine API (" .. variant.name .. ")", function()
        local machine <close> = variant.create({ ram = { length = 0x1000 } })

        describe("get_address_name", function()
            -- Build table of reg name -> expected get_address_name output.
            -- Names follow shadow_registers_get_what_name / shadow_uarch_state_get_what_name strings.
            local reg_address_names = {}
            for i = 0, 31 do
                reg_address_names["x" .. i] = "x" .. i
                reg_address_names["f" .. i] = "f" .. i
                reg_address_names["uarch_x" .. i] = "uarch.x" .. i
            end
            local identity_regs = {
                "pc",
                "fcsr",
                "mvendorid",
                "marchid",
                "mimpid",
                "mcycle",
                "icycleinstret",
                "mstatus",
                "mtvec",
                "mscratch",
                "mepc",
                "mcause",
                "mtval",
                "misa",
                "mie",
                "mip",
                "medeleg",
                "mideleg",
                "mcounteren",
                "menvcfg",
                "stvec",
                "sscratch",
                "sepc",
                "scause",
                "stval",
                "satp",
                "scounteren",
                "senvcfg",
                "ilrsc",
                "iprv",
                "iunrep",
                "imcyclemax",
            }
            for _, name in ipairs(identity_regs) do
                reg_address_names[name] = name
            end
            local namespaced_regs = {
                iflags_X = "iflags.X",
                iflags_Y = "iflags.Y",
                iflags_H = "iflags.H",
                clint_mtimecmp = "clint.mtimecmp",
                plic_girqpend = "plic.girqpend",
                plic_girqsrvd = "plic.girqsrvd",
                htif_tohost = "htif.tohost",
                htif_fromhost = "htif.fromhost",
                htif_ihalt = "htif.ihalt",
                htif_iconsole = "htif.iconsole",
                htif_iyield = "htif.iyield",
                uarch_halt = "uarch.halt",
                uarch_cycle = "uarch.cycle",
                uarch_pc = "uarch.pc",
            }
            for reg_name, addr_name in pairs(namespaced_regs) do
                reg_address_names[reg_name] = addr_name
            end

            it("should roundtrip get_reg_address through get_address_name", function()
                for reg_name, expected in pairs(reg_address_names) do
                    local paddr = machine:get_reg_address(reg_name)
                    expect.equal(machine:get_address_name(paddr), expected)
                end
            end)

            it("should return correct names for TLB slot fields", function()
                -- shadow_tlb_slot layout (32 bytes): vaddr_page@0, vp_offset@8, pma_index@16, zero_padding_@24
                local tlb_slot_size = 32 -- sizeof(shadow_tlb_slot)
                local tlb_set_bytes = 1024 * tlb_slot_size -- TLB_SET_SLOTS * sizeof(shadow_tlb_slot)
                local tlb_fields = {
                    [0] = "tlb.slot.vaddr_page",
                    [8] = "tlb.slot.vp_offset",
                    [16] = "tlb.slot.pma_index",
                    [24] = "tlb.slot.zero_padding_",
                }
                for set_index = 0, 2 do
                    for _, slot_index in ipairs({ 0, 17 }) do
                        for field_offset, expected in pairs(tlb_fields) do
                            local paddr = cartesi.AR_SHADOW_TLB_START
                                + set_index * tlb_set_bytes
                                + slot_index * tlb_slot_size
                                + field_offset
                            expect.equal(machine:get_address_name(paddr), expected)
                        end
                    end
                end
            end)

            it("should return correct names for PMA entry fields", function()
                -- pmas_entry layout (16 bytes): istart@0, ilength@8
                expect.equal(machine:get_address_name(cartesi.AR_PMAS_START + 0), "pma.istart")
                expect.equal(machine:get_address_name(cartesi.AR_PMAS_START + 8), "pma.ilength")
            end)

            it("should return uarch.ram for uarch RAM address", function()
                expect.equal(machine:get_address_name(cartesi.UARCH_RAM_START_ADDRESS), "uarch.ram")
            end)

            it("should return memory for unmapped address", function()
                expect.equal(machine:get_address_name(cartesi.AR_RAM_START), "memory")
            end)

            it("should return unknown_ for misaligned addresses in each shadow region", function()
                expect.equal(machine:get_address_name(cartesi.AR_SHADOW_STATE_START + 1), "state.unknown_")
                expect.equal(machine:get_address_name(cartesi.AR_SHADOW_TLB_START + 1), "tlb.unknown_")
                expect.equal(machine:get_address_name(cartesi.AR_PMAS_START + 1), "pma.unknown_")
                expect.equal(machine:get_address_name(cartesi.UARCH_SHADOW_START_ADDRESS + 1), "uarch.unknown_")
            end)

            it("should return correct names for peripheral regions", function()
                expect.equal(machine:get_address_name(cartesi.AR_DTB_START), "dtb")
                expect.equal(machine:get_address_name(cartesi.AR_DTB_START + cartesi.AR_DTB_LENGTH - 1), "dtb")
                expect.equal(machine:get_address_name(cartesi.AR_CLINT_START), "clint")
                expect.equal(machine:get_address_name(cartesi.AR_CLINT_START + cartesi.AR_CLINT_LENGTH - 1), "clint")
                expect.equal(machine:get_address_name(cartesi.AR_HTIF_START), "htif")
                expect.equal(machine:get_address_name(cartesi.AR_HTIF_START + cartesi.AR_HTIF_LENGTH - 1), "htif")
                expect.equal(machine:get_address_name(cartesi.AR_PLIC_START), "plic")
                expect.equal(machine:get_address_name(cartesi.AR_PLIC_START + cartesi.AR_PLIC_LENGTH - 1), "plic")
                expect.equal(machine:get_address_name(cartesi.AR_CMIO_RX_BUFFER_START), "cmio.rx_buffer")
                expect.equal(machine:get_address_name(cartesi.AR_CMIO_TX_BUFFER_START), "cmio.tx_buffer")
                expect.equal(machine:get_address_name(cartesi.AR_FIRST_VIRTIO_START), "virtio")
                expect.equal(machine:get_address_name(cartesi.AR_LAST_VIRTIO_END - 1), "virtio")
            end)
        end)

        describe("read_reg and write_reg", function()
            -- Registers whose write must be rejected.
            local read_only = { x0 = true, mvendorid = true, marchid = true, mimpid = true }

            it("should round-trip every shadow register through read_reg/write_reg", function()
                -- Walk the shadow register page (it ends where the shadow TLB
                -- begins) and name each slot through get_address_name. Its dotted
                -- names map to read_reg/write_reg names by turning each "." into
                -- "_" (e.g. "iflags.X" -> "iflags_X").
                local value = 0xfedcba9876543210
                for addr = cartesi.AR_SHADOW_STATE_START, cartesi.AR_SHADOW_TLB_START - 8, 8 do
                    local addr_name = machine:get_address_name(addr)
                    if addr_name ~= "state.unknown_" then
                        local name = addr_name:gsub("%.", "_")
                        if read_only[name] then
                            expect.fail(function()
                                machine:write_reg(name, 1)
                            end, "register is read-only")
                            machine:read_reg(name)
                        else
                            machine:write_reg(name, value)
                            expect.equal(machine:read_reg(name), value)
                        end
                    end
                end
            end)

            it("should round-trip a value through each htif field alias", function()
                -- These aliases share the htif.tohost/htif.fromhost words, so they
                -- have no address of their own and only preserve their sub-field.
                -- A value that fits the narrowest (8-bit) field round-trips.
                local field_aliases = {
                    "htif_tohost_dev",
                    "htif_tohost_cmd",
                    "htif_tohost_reason",
                    "htif_tohost_data",
                    "htif_fromhost_dev",
                    "htif_fromhost_cmd",
                    "htif_fromhost_reason",
                    "htif_fromhost_data",
                }
                for _, name in ipairs(field_aliases) do
                    machine:write_reg(name, 0x5)
                    expect.equal(machine:read_reg(name), 0x5)
                end
            end)
        end)

        describe("write_word", function()
            it("should reject unmapped shadow state addresses", function()
                -- Aligned address inside the shadow register page but past the
                -- register layout, so it forwards to no register.
                expect.fail(function()
                    machine:write_word(cartesi.AR_SHADOW_STATE_START + 0xff8, 0)
                end, "unhandled write to shadow state")
            end)

            it("should reject writes to protected memory ranges", function()
                -- The shadow TLB is in the protected shadow state range, outside
                -- the register page that write_word forwards to write_reg.
                expect.fail(function()
                    machine:write_word(cartesi.AR_SHADOW_TLB_START, 0)
                end, "protected memory range")
            end)

            it("should reject writes to read-only memory ranges", function()
                local ro <close> = variant.create({
                    ram = { length = 0x1000 },
                    nvram = { { start = 0x70000000, length = 0x1000, read_only = true } },
                })
                expect.fail(function()
                    ro:write_word(0x70000000, 0x1234)
                end, "read-only")
            end)
        end)

        describe("write_memory over shadow state", function()
            -- Regression: overwriting the whole shadow state (its special case in
            -- machine::write_memory) resets the hot TLB. Pages written by the guest
            -- through the write TLB but not yet flushed into the dirty-page tree
            -- would lose their pending dirty mark, so a later incremental hash would
            -- not reflect them. write_memory must flush the write TLB dirty pages
            -- before replacing the shadow.
            it("should keep the root hash consistent with memory", function()
                -- auipc t0, 0x2 ; addi t1, x0, 0x42 ; sd t1, 0(t0) ; jal x0, 0
                -- The store dirties page RAM_START+0x2000 through the write TLB.
                local program = string.char(
                    0x97,
                    0x22,
                    0x00,
                    0x00,
                    0x13,
                    0x03,
                    0x20,
                    0x04,
                    0x23,
                    0xb0,
                    0x62,
                    0x00,
                    0x6f,
                    0x00,
                    0x00,
                    0x00
                )
                local m <close> = variant.create({ ram = { length = 1 << 20 } })
                m:write_memory(cartesi.AR_RAM_START, program)
                -- Snapshot the shadow while its TLB references no written page.
                local shadow = m:read_memory(cartesi.AR_SHADOW_STATE_START, cartesi.AR_SHADOW_STATE_LENGTH)
                -- Establish a baseline so the later hash update is incremental.
                m:get_root_hash()
                -- Execute the store, leaving the page dirty in host memory but only
                -- tracked by the write TLB, not yet by the dirty-page tree.
                m:run(100)
                -- Overwrite the shadow with the snapshot, whose TLB no longer
                -- references the written page.
                m:write_memory(cartesi.AR_SHADOW_STATE_START, shadow)
                expect.equal(m:get_root_hash(), tests_util.calculate_emulator_hash(m))
            end)
        end)
    end)
end

lester.report()
lester.exit()
