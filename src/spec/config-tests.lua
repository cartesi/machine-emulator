#!/usr/bin/env lua5.4

-- Copyright 2023 Cartesi Pte. Ltd.
--
-- This file is part of the machine-emulator. The machine-emulator is free
-- software: you can redistribute it and/or modify it under the terms of the GNU
-- Lesser General Public License as published by the Free Software Foundation,
-- either version 3 of the License, or (at your option) any later version.
--
-- The machine-emulator is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
-- FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
-- for more details.
--
-- You should have received a copy of the GNU Lesser General Public License
-- along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
--

local lester = require("spec.util.lester")
local fs = require("spec.util.fs")
local cartesi = require("cartesi")
local util = require("cartesi.util")
local describe, it, expect = lester.describe, lester.it, lester.expect

local default_initial_config = cartesi.machine.get_default_config()

local expected_initial_config = {
    processor = {
        -- these are non zero and depends in our implementation
        marchid = default_initial_config.processor.marchid,
        mimpid = default_initial_config.processor.mimpid,
        mvendorid = default_initial_config.processor.mvendorid,
        misa = default_initial_config.processor.misa,
        mstatus = default_initial_config.processor.mstatus,
        pc = default_initial_config.processor.pc,
        iflags = default_initial_config.processor.iflags,
        ilrsc = default_initial_config.processor.ilrsc,
        -- these we know in advance
        fcsr = 0,
        icycleinstret = 0,
        mcause = 0,
        mcounteren = 0,
        mcycle = 0,
        medeleg = 0,
        menvcfg = 0,
        mepc = 0,
        mideleg = 0,
        mie = 0,
        mip = 0,
        mscratch = 0,
        mtval = 0,
        mtvec = 0,
        satp = 0,
        scause = 0,
        scounteren = 0,
        senvcfg = 0,
        sepc = 0,
        sscratch = 0,
        stval = 0,
        stvec = 0,
        x = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        f = { [0] = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    },
    ram = {
        image_filename = "",
        length = 0x4000,
    },
    rom = {
        bootargs = "",
        image_filename = fs.rom_image,
    },
    tlb = {
        image_filename = "",
    },
    flash_drive = {},
    htif = {
        console_getchar = false,
        yield_automatic = false,
        yield_manual = false,
        fromhost = 0,
        tohost = 0,
    },
    clint = {
        mtimecmp = 0,
    },
    uarch = {
        processor = {
            cycle = 0,
            pc = default_initial_config.uarch.processor.pc,
            x = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        },
        ram = {
            image_filename = "",
            length = 0,
        },
    },
}

local test_config = {
    processor = {
        -- these are hardwired constants, and cannot change
        marchid = default_initial_config.processor.marchid,
        mimpid = default_initial_config.processor.mimpid,
        mvendorid = default_initial_config.processor.mvendorid,
        -- these can be changed, and are set to random values
        pc = 0x070c1efa257e32e4,
        misa = 0xff13504ee4da72f1,
        fcsr = 0x8b337085bc73d6f6,
        icycleinstret = 0xf4310770998bfaab,
        ilrsc = 0x5bf71f0fc1c516e1,
        mcause = 0x73b2dcca2277c070,
        mcounteren = 0x2aeb5bbda1f4be71,
        mcycle = 0x072a8a6e298b61cb,
        medeleg = 0x3d00a03901459100,
        menvcfg = 0x4cf38ec0407ba557,
        mepc = 0x23aab25abacae88d,
        mideleg = 0x2830ed05187f8ab9,
        mie = 0x4b615ac9c32e2a91,
        mip = 0x4abb22a9f342d65c,
        mscratch = 0xa0d39fc9763cdd91,
        mstatus = 0xd02e272900ea57d5,
        mtval = 0x41cea506fd53c830,
        mtvec = 0xa395b0c3b234bfbc,
        satp = 0x2fd3e21cd171c484,
        scause = 0xc41a4593c61098ca,
        scounteren = 0x9fdf00eae96a888d,
        senvcfg = 0xe8c06242796cffa3,
        sepc = 0x0e1151b658feb88a,
        sscratch = 0x59951bc8a8fb4921,
        stval = 0xb1c067c2c1709a51,
        stvec = 0xa9ca605ecb0807b6,
        iflags = 3,
        x = {
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
            26,
            27,
            28,
            29,
            30,
            31,
        },
        f = {
            [0] = 1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
            26,
            27,
            28,
            29,
            30,
            31,
            32,
        },
    },
    ram = {
        image_filename = "",
        length = fs.get_file_length(fs.linux_image),
    },
    rom = {
        image_filename = fs.rom_image,
        bootargs = "test",
    },
    flash_drive = {
        {
            image_filename = fs.rootfs_image,
            length = fs.get_file_length(fs.rootfs_image),
            start = 0x80000000000000,
            shared = false,
        },
        {
            image_filename = "",
            length = 0x4000,
            start = 0x90000000000000,
            shared = false,
        },
    },
    uarch = {
        processor = {
            cycle = 7,
            pc = 0x2000,
            x = {
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                16,
                17,
                18,
                19,
                20,
                21,
                22,
                23,
                24,
                25,
                26,
                27,
                28,
                29,
                30,
                31,
            },
        },
        ram = { image_filename = fs.uarch_ram_image, length = 0x20000 },
    },
    htif = {
        yield_automatic = true,
        yield_manual = true,
        console_getchar = false,
        fromhost = 0x5555555555555555,
        tohost = 0xaaaaaaaaaaaaaaaa,
    },
    rollup = {
        rx_buffer = { image_filename = "", start = 0x60000000, length = 0x1000, shared = false },
        tx_buffer = { image_filename = "", start = 0x60002000, length = 0x1000, shared = false },
        input_metadata = { image_filename = "", start = 0x60004000, length = 0x1000, shared = false },
        voucher_hashes = { image_filename = "", start = 0x60006000, length = 0x1000, shared = false },
        notice_hashes = { image_filename = "", start = 0x60008000, length = 0x1000, shared = false },
    },
    tlb = { image_filename = "" },
    clint = { mtimecmp = 8192 },
}

describe("machine config", function()
    it("should set initial configs correctly", function()
        do
            local machine = cartesi.machine({
                ram = { length = 0x4000 },
                rom = { image_filename = fs.rom_image },
            }, {
                concurrency = { update_merkle_tree = 1 },
            })
            expect.equal(machine:get_initial_config(), expected_initial_config)
            machine:destroy()
        end
        collectgarbage()
    end)

    it("should set initial configs correctly for -1 values", function()
        local machine <close> = cartesi.machine({
            ram = { length = 0x4000 },
            rom = { image_filename = fs.rom_image },
            processor = {
                marchid = -1,
                mvendorid = -1,
                mimpid = -1,
            },
        }, {
            concurrency = { update_merkle_tree = 1 },
        })
        expect.equal(machine:get_initial_config(), expected_initial_config)
    end)

    it("should set missing config fields correctly", function()
        local config = {
            processor = {
                x = {},
                f = {},
            },
            ram = {
                length = 0x4000,
            },
            rom = {
                image_filename = fs.rom_image,
            },
            flash_drive = { {
                length = 0x4000,
                start = 0x80000000000000,
            } },
            uarch = {
                processor = {
                    x = {},
                },
                rom = { length = 0 },
                ram = { length = 0 },
            },
            rollup = {
                rx_buffer = { start = 0x60000000, length = 0x2000 },
                tx_buffer = { start = 0x60002000, length = 0x2000 },
                input_metadata = { start = 0x60004000, length = 0x2000 },
                voucher_hashes = { start = 0x60006000, length = 0x2000 },
                notice_hashes = { start = 0x60008000, length = 0x2000 },
            },
            tlb = {},
            clint = {},
            htif = {},
        }
        local expected_machine_config = {
            processor = expected_initial_config.processor,
            ram = expected_initial_config.ram,
            rom = expected_initial_config.rom,
            flash_drive = {
                {
                    length = 0x4000,
                    start = 0x80000000000000,
                    image_filename = "",
                    shared = false,
                },
            },
            uarch = expected_initial_config.uarch,
            rollup = {
                rx_buffer = { start = 0x60000000, length = 0x2000, image_filename = "", shared = false },
                tx_buffer = { start = 0x60002000, length = 0x2000, image_filename = "", shared = false },
                input_metadata = { start = 0x60004000, length = 0x2000, image_filename = "", shared = false },
                voucher_hashes = { start = 0x60006000, length = 0x2000, image_filename = "", shared = false },
                notice_hashes = { start = 0x60008000, length = 0x2000, image_filename = "", shared = false },
            },
            tlb = expected_initial_config.tlb,
            clint = expected_initial_config.clint,
            htif = expected_initial_config.htif,
        }
        local machine <close> = cartesi.machine(config, {})
        expect.equal(machine:get_initial_config(), expected_machine_config)
    end)

    it("should match with initial config", function()
        local machine <close> = cartesi.machine(test_config)
        expect.equal(machine:get_initial_config(), test_config)
    end)

    it("should match halt flags, yield flags and config", function()
        local machine <close> = cartesi.machine({
            ram = { length = 0x100000 },
            rom = { image_filename = fs.rom_image },
        })
        -- Get machine default config  and test for known fields
        local initial_config = machine:get_initial_config()
        expect.equal(initial_config.processor.marchid, default_initial_config.processor.marchid)
        expect.equal(initial_config.processor.pc, default_initial_config.processor.pc)
        expect.equal(initial_config.ram.length, 0x100000)
        expect.not_equal(initial_config.rom.image_filename, "")
        -- Check machine is not halted
        expect.falsy(machine:read_iflags_H())
        -- Check machine is not yielded
        expect.falsy(machine:read_iflags_Y() or machine:read_iflags_X())
    end)

    it("should fail when attempting to create machine with invalid configs", function()
        -- rom
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = "some/invalid/image.bin" },
                })
            end,
            "error opening image file"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.linux_image },
                })
            end,
            "is too large for range"
        )

        -- ram
        expect.fail(
            function()
                cartesi.machine({
                    ram = { image_filename = "some/invalid/image.bin", length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                })
            end,
            "error opening image file"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { image_filename = fs.linux_image, length = 0 },
                    rom = { image_filename = fs.rom_image },
                })
            end,
            "length cannot be zero"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { image_filename = fs.linux_image, length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                })
            end,
            "too large for range"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = {},
                    rom = { image_filename = fs.rom_image },
                })
            end,
            "invalid length"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0 },
                    rom = { image_filename = fs.rom_image },
                })
            end,
            "length cannot be zero"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 4095 },
                    rom = { image_filename = fs.rom_image },
                })
            end,
            "must be multiple of page size"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { image_filename = true, length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                })
            end,
            "invalid image_filename"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = 0,
                    rom = { image_filename = fs.rom_image },
                })
            end,
            "missing ram"
        )

        -- processor
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    processor = 0,
                })
            end,
            "missing processor"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    processor = { pc = true },
                })
            end,
            "invalid pc"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    processor = { x = { true } },
                })
            end,
            "invalid entry"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    processor = { marchid = 0 },
                })
            end,
            "marchid mismatch"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    processor = { mimpid = 0 },
                })
            end,
            "mimpid mismatch"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    processor = { mvendorid = 0 },
                })
            end,
            "mvendorid mismatch"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    processor = { x = 0 },
                })
            end,
            "invalid processor.x"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    processor = { f = 0 },
                })
            end,
            "invalid processor.f"
        )

        -- uarch.processor
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    uarch = {
                        processor = { x = 0 },
                        ram = { length = 0x4000 },
                        rom = { length = 0x4000 },
                    },
                })
            end,
            "invalid uarch.processor.x"
        )

        -- flash drive
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    flash_drive = { {}, {}, {}, {}, {}, {}, {}, {}, {} },
                })
            end,
            "too many flash drives"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    flash_drive = { false },
                })
            end,
            "memory range not a table"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    flash_drive = { {} },
                })
            end,
            "invalid start"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    flash_drive = { { start = 0x80000000000000, length = 0 } },
                })
            end,
            "length cannot be zero"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    flash_drive = { { start = 0x100000000000000, length = 0x4000 } },
                })
            end,
            "must use at most 56 bits to be addressable"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    flash_drive = { { start = 0, length = 0x4000 } },
                })
            end,
            "overlaps with range of existing"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    flash_drive = { { start = 0, length = 4095 } },
                })
            end,
            "must be multiple of page size"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    flash_drive = {
                        {
                            image_filename = "some/invalid/image.bin",
                            start = 0x80000000000000,
                            length = 0x4000,
                        },
                    },
                })
            end,
            "could not open image file"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    flash_drive = {
                        {
                            image_filename = "some/invalid/image.bin",
                            start = 0x80000000000000,
                        },
                    },
                })
            end,
            "unable to obtain length of image file"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    flash_drive = {
                        {
                            image_filename = fs.rootfs_image,
                            start = 0x80000000000000,
                            length = 0,
                        },
                    },
                })
            end,
            "length cannot be zero"
        )
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    flash_drive = {
                        {
                            image_filename = fs.rootfs_image,
                            start = 0x80000000000000,
                            length = 0x4000,
                        },
                    },
                })
            end,
            "does not match range length"
        )

        -- rollup
        expect.fail(
            function()
                cartesi.machine({
                    ram = { length = 0x4000 },
                    rom = { image_filename = fs.rom_image },
                    rollup = {
                        rx_buffer = { start = 0x60000000, length = 0x2000 },
                        tx_buffer = { start = 0x60002000, length = 0x2000 },
                        input_metadata = { start = 0x60004000, length = 0x2000 },
                        voucher_hashes = { start = 0x60006000, length = 0x2000 },
                        notice_hashes = { start = 0x60008000, length = 0 },
                    },
                })
            end,
            "incomplete rollup configuration"
        )

        -- stored
        expect.fail(function() cartesi.machine("some/invalid/machine") end, "unable to open")
    end)
end)

describe("machine state", function()
    local machine <close> = cartesi.machine(test_config)
    local P = 0xf6b75ab2bc471c7 -- random prime used to test register write

    it("should read CSRs", function()
        -- check read_...
        expect.equal(machine:read_marchid(), test_config.processor.marchid)
        expect.equal(machine:read_mimpid(), test_config.processor.mimpid)
        expect.equal(machine:read_mvendorid(), test_config.processor.mvendorid)
        expect.equal(machine:read_pc(), test_config.processor.pc)
        expect.equal(machine:read_misa(), test_config.processor.misa)
        expect.equal(machine:read_fcsr(), test_config.processor.fcsr)
        expect.equal(machine:read_icycleinstret(), test_config.processor.icycleinstret)
        expect.equal(machine:read_ilrsc(), test_config.processor.ilrsc)
        expect.equal(machine:read_mcause(), test_config.processor.mcause)
        expect.equal(machine:read_mcounteren(), test_config.processor.mcounteren)
        expect.equal(machine:read_mcycle(), test_config.processor.mcycle)
        expect.equal(machine:read_medeleg(), test_config.processor.medeleg)
        expect.equal(machine:read_menvcfg(), test_config.processor.menvcfg)
        expect.equal(machine:read_mepc(), test_config.processor.mepc)
        expect.equal(machine:read_mideleg(), test_config.processor.mideleg)
        expect.equal(machine:read_mie(), test_config.processor.mie)
        expect.equal(machine:read_mip(), test_config.processor.mip)
        expect.equal(machine:read_mscratch(), test_config.processor.mscratch)
        expect.equal(machine:read_mstatus(), test_config.processor.mstatus)
        expect.equal(machine:read_mtval(), test_config.processor.mtval)
        expect.equal(machine:read_mtvec(), test_config.processor.mtvec)
        expect.equal(machine:read_satp(), test_config.processor.satp)
        expect.equal(machine:read_scause(), test_config.processor.scause)
        expect.equal(machine:read_scounteren(), test_config.processor.scounteren)
        expect.equal(machine:read_senvcfg(), test_config.processor.senvcfg)
        expect.equal(machine:read_sepc(), test_config.processor.sepc)
        expect.equal(machine:read_sscratch(), test_config.processor.sscratch)
        expect.equal(machine:read_stval(), test_config.processor.stval)
        expect.equal(machine:read_stvec(), test_config.processor.stvec)
        expect.equal(machine:read_iflags(), test_config.processor.iflags)
        expect.equal(machine:read_uarch_cycle(), test_config.uarch.processor.cycle)
        expect.equal(machine:read_uarch_pc(), test_config.uarch.processor.pc)
        expect.equal(machine:read_uarch_ram_length(), test_config.uarch.ram.length)

        -- check read_csr
        expect.equal(machine:read_csr("marchid"), test_config.processor.marchid)
        expect.equal(machine:read_csr("mimpid"), test_config.processor.mimpid)
        expect.equal(machine:read_csr("mvendorid"), test_config.processor.mvendorid)
        expect.equal(machine:read_csr("pc"), test_config.processor.pc)
        expect.equal(machine:read_csr("misa"), test_config.processor.misa)
        expect.equal(machine:read_csr("fcsr"), test_config.processor.fcsr)
        expect.equal(machine:read_csr("icycleinstret"), test_config.processor.icycleinstret)
        expect.equal(machine:read_csr("ilrsc"), test_config.processor.ilrsc)
        expect.equal(machine:read_csr("mcause"), test_config.processor.mcause)
        expect.equal(machine:read_csr("mcounteren"), test_config.processor.mcounteren)
        expect.equal(machine:read_csr("mcycle"), test_config.processor.mcycle)
        expect.equal(machine:read_csr("medeleg"), test_config.processor.medeleg)
        expect.equal(machine:read_csr("menvcfg"), test_config.processor.menvcfg)
        expect.equal(machine:read_csr("mepc"), test_config.processor.mepc)
        expect.equal(machine:read_csr("mideleg"), test_config.processor.mideleg)
        expect.equal(machine:read_csr("mie"), test_config.processor.mie)
        expect.equal(machine:read_csr("mip"), test_config.processor.mip)
        expect.equal(machine:read_csr("mscratch"), test_config.processor.mscratch)
        expect.equal(machine:read_csr("mstatus"), test_config.processor.mstatus)
        expect.equal(machine:read_csr("mtval"), test_config.processor.mtval)
        expect.equal(machine:read_csr("mtvec"), test_config.processor.mtvec)
        expect.equal(machine:read_csr("satp"), test_config.processor.satp)
        expect.equal(machine:read_csr("scause"), test_config.processor.scause)
        expect.equal(machine:read_csr("scounteren"), test_config.processor.scounteren)
        expect.equal(machine:read_csr("senvcfg"), test_config.processor.senvcfg)
        expect.equal(machine:read_csr("sepc"), test_config.processor.sepc)
        expect.equal(machine:read_csr("sscratch"), test_config.processor.sscratch)
        expect.equal(machine:read_csr("stval"), test_config.processor.stval)
        expect.equal(machine:read_csr("stvec"), test_config.processor.stvec)
        expect.equal(machine:read_csr("iflags"), test_config.processor.iflags)
        expect.equal(machine:read_csr("uarch_cycle"), test_config.uarch.processor.cycle)
        expect.equal(machine:read_csr("uarch_pc"), test_config.uarch.processor.pc)
        expect.equal(machine:read_csr("uarch_ram_length"), test_config.uarch.ram.length)

        -- check if CSR addresses are valid
        local get_csr_addr = cartesi.machine.get_csr_address
        expect.equal(machine:read_word(get_csr_addr("marchid")), test_config.processor.marchid)
        expect.equal(machine:read_word(get_csr_addr("mimpid")), test_config.processor.mimpid)
        expect.equal(machine:read_word(get_csr_addr("mvendorid")), test_config.processor.mvendorid)
        expect.equal(machine:read_word(get_csr_addr("pc")), test_config.processor.pc)
        expect.equal(machine:read_word(get_csr_addr("misa")), test_config.processor.misa)
        expect.equal(machine:read_word(get_csr_addr("fcsr")), test_config.processor.fcsr)
        expect.equal(machine:read_word(get_csr_addr("icycleinstret")), test_config.processor.icycleinstret)
        expect.equal(machine:read_word(get_csr_addr("ilrsc")), test_config.processor.ilrsc)
        expect.equal(machine:read_word(get_csr_addr("mcause")), test_config.processor.mcause)
        expect.equal(machine:read_word(get_csr_addr("mcounteren")), test_config.processor.mcounteren)
        expect.equal(machine:read_word(get_csr_addr("mcycle")), test_config.processor.mcycle)
        expect.equal(machine:read_word(get_csr_addr("medeleg")), test_config.processor.medeleg)
        expect.equal(machine:read_word(get_csr_addr("menvcfg")), test_config.processor.menvcfg)
        expect.equal(machine:read_word(get_csr_addr("mepc")), test_config.processor.mepc)
        expect.equal(machine:read_word(get_csr_addr("mideleg")), test_config.processor.mideleg)
        expect.equal(machine:read_word(get_csr_addr("mie")), test_config.processor.mie)
        expect.equal(machine:read_word(get_csr_addr("mip")), test_config.processor.mip)
        expect.equal(machine:read_word(get_csr_addr("mscratch")), test_config.processor.mscratch)
        expect.equal(machine:read_word(get_csr_addr("mstatus")), test_config.processor.mstatus)
        expect.equal(machine:read_word(get_csr_addr("mtval")), test_config.processor.mtval)
        expect.equal(machine:read_word(get_csr_addr("mtvec")), test_config.processor.mtvec)
        expect.equal(machine:read_word(get_csr_addr("satp")), test_config.processor.satp)
        expect.equal(machine:read_word(get_csr_addr("scause")), test_config.processor.scause)
        expect.equal(machine:read_word(get_csr_addr("scounteren")), test_config.processor.scounteren)
        expect.equal(machine:read_word(get_csr_addr("senvcfg")), test_config.processor.senvcfg)
        expect.equal(machine:read_word(get_csr_addr("sepc")), test_config.processor.sepc)
        expect.equal(machine:read_word(get_csr_addr("sscratch")), test_config.processor.sscratch)
        expect.equal(machine:read_word(get_csr_addr("stval")), test_config.processor.stval)
        expect.equal(machine:read_word(get_csr_addr("stvec")), test_config.processor.stvec)
        expect.equal(machine:read_word(get_csr_addr("iflags")), test_config.processor.iflags)
        expect.equal(machine:read_word(get_csr_addr("uarch_cycle")), test_config.uarch.processor.cycle)
        expect.equal(machine:read_word(get_csr_addr("uarch_pc")), test_config.uarch.processor.pc)
        expect.equal(machine:read_word(get_csr_addr("uarch_ram_length")), test_config.uarch.ram.length)
    end)

    it("should write CSRs", function()
        local pc = P & ~3 -- make sure it is 4-byte aligned
        local a = P

        -- check write_...
        expect.equal(machine:write_pc(pc) or machine:read_pc(), pc)
        expect.equal(machine:write_misa(a) or machine:read_misa(), a)
        expect.equal(machine:write_fcsr(a) or machine:read_fcsr(), a)
        expect.equal(machine:write_icycleinstret(a) or machine:read_icycleinstret(), a)
        expect.equal(machine:write_ilrsc(a) or machine:read_ilrsc(), a)
        expect.equal(machine:write_mcause(a) or machine:read_mcause(), a)
        expect.equal(machine:write_mcounteren(a) or machine:read_mcounteren(), a)
        expect.equal(machine:write_mcycle(a) or machine:read_mcycle(), a)
        expect.equal(machine:write_medeleg(a) or machine:read_medeleg(), a)
        expect.equal(machine:write_menvcfg(a) or machine:read_menvcfg(), a)
        expect.equal(machine:write_mepc(a) or machine:read_mepc(), a)
        expect.equal(machine:write_mideleg(a) or machine:read_mideleg(), a)
        expect.equal(machine:write_mie(a) or machine:read_mie(), a)
        expect.equal(machine:write_mip(a) or machine:read_mip(), a)
        expect.equal(machine:write_mscratch(a) or machine:read_mscratch(), a)
        expect.equal(machine:write_mstatus(a) or machine:read_mstatus(), a)
        expect.equal(machine:write_mtval(a) or machine:read_mtval(), a)
        expect.equal(machine:write_mtvec(a) or machine:read_mtvec(), a)
        expect.equal(machine:write_satp(a) or machine:read_satp(), a)
        expect.equal(machine:write_scause(a) or machine:read_scause(), a)
        expect.equal(machine:write_scounteren(a) or machine:read_scounteren(), a)
        expect.equal(machine:write_senvcfg(a) or machine:read_senvcfg(), a)
        expect.equal(machine:write_sepc(a) or machine:read_sepc(), a)
        expect.equal(machine:write_sscratch(a) or machine:read_sscratch(), a)
        expect.equal(machine:write_stval(a) or machine:read_stval(), a)
        expect.equal(machine:write_stvec(a) or machine:read_stvec(), a)
        expect.equal(machine:write_uarch_cycle(a) or machine:read_uarch_cycle(), a)
        expect.equal(machine:write_uarch_pc(pc) or machine:read_uarch_pc(), pc)
        expect.equal(machine:write_iflags(0) or machine:read_iflags(), 0)

        -- update values for next writes
        pc = pc + 4
        a = ~a

        -- check write_csr
        expect.equal(machine:write_csr("pc", pc) or machine:read_pc(), pc)
        expect.equal(machine:write_csr("misa", a) or machine:read_misa(), a)
        expect.equal(machine:write_csr("fcsr", a) or machine:read_fcsr(), a)
        expect.equal(machine:write_csr("icycleinstret", a) or machine:read_icycleinstret(), a)
        expect.equal(machine:write_csr("ilrsc", a) or machine:read_ilrsc(), a)
        expect.equal(machine:write_csr("mcause", a) or machine:read_mcause(), a)
        expect.equal(machine:write_csr("mcounteren", a) or machine:read_mcounteren(), a)
        expect.equal(machine:write_csr("mcycle", a) or machine:read_mcycle(), a)
        expect.equal(machine:write_csr("medeleg", a) or machine:read_medeleg(), a)
        expect.equal(machine:write_csr("menvcfg", a) or machine:read_menvcfg(), a)
        expect.equal(machine:write_csr("mepc", a) or machine:read_mepc(), a)
        expect.equal(machine:write_csr("mideleg", a) or machine:read_mideleg(), a)
        expect.equal(machine:write_csr("mie", a) or machine:read_mie(), a)
        expect.equal(machine:write_csr("mip", a) or machine:read_mip(), a)
        expect.equal(machine:write_csr("mscratch", a) or machine:read_mscratch(), a)
        expect.equal(machine:write_csr("mstatus", a) or machine:read_mstatus(), a)
        expect.equal(machine:write_csr("mtval", a) or machine:read_mtval(), a)
        expect.equal(machine:write_csr("mtvec", a) or machine:read_mtvec(), a)
        expect.equal(machine:write_csr("satp", a) or machine:read_satp(), a)
        expect.equal(machine:write_csr("scause", a) or machine:read_scause(), a)
        expect.equal(machine:write_csr("scounteren", a) or machine:read_scounteren(), a)
        expect.equal(machine:write_csr("senvcfg", a) or machine:read_senvcfg(), a)
        expect.equal(machine:write_csr("sepc", a) or machine:read_sepc(), a)
        expect.equal(machine:write_csr("sscratch", a) or machine:read_sscratch(), a)
        expect.equal(machine:write_csr("stval", a) or machine:read_stval(), a)
        expect.equal(machine:write_csr("stvec", a) or machine:read_stvec(), a)
        expect.equal(machine:write_csr("uarch_cycle", a) or machine:read_uarch_cycle(), a)
        expect.equal(machine:write_csr("uarch_pc", pc) or machine:read_uarch_pc(), pc)
        expect.equal(machine:write_csr("iflags", 0) or machine:read_iflags(), 0)
    end)

    it("should read/set/reset iflags", function()
        expect.equal(machine:read_iflags_H(), false)
        expect.equal(machine:read_iflags_X(), false)
        expect.equal(machine:read_iflags_Y(), false)
        expect.equal(machine:set_iflags_H() or machine:read_iflags_H(), true)
        expect.equal(machine:set_iflags_X() or machine:read_iflags_X(), true)
        expect.equal(machine:set_iflags_Y() or machine:read_iflags_Y(), true)
        expect.equal(machine:reset_iflags_X() or machine:read_iflags_X(), false)
        expect.equal(machine:reset_iflags_Y() or machine:read_iflags_Y(), false)
    end)

    it("should read/write x registers", function()
        expect.equal(machine:read_x(0), 0)
        for i, defval in ipairs(test_config.processor.x) do
            local addr = cartesi.machine.get_x_address(i)
            local val = i * P
            expect.equal(machine:read_x(i), defval)
            expect.equal(machine:read_word(addr), defval)
            expect.equal(machine:write_x(i, val) or machine:read_x(i), val)
            expect.equal(machine:read_word(addr), val)
        end
    end)

    it("should read/write f registers", function()
        for i = 0, 31 do
            local addr = cartesi.machine.get_f_address(i)
            local defval = test_config.processor.f[i]
            local val = (i + 1) * P
            expect.equal(machine:read_f(i), defval)
            expect.equal(machine:read_word(addr), defval)
            expect.equal(machine:write_f(i, val) or machine:read_f(i), val)
            expect.equal(machine:read_word(addr), val)
        end
    end)

    it("should read/write uarch x registers", function()
        expect.equal(machine:read_uarch_x(0), 0)
        for i, defval in ipairs(test_config.uarch.processor.x) do
            local val = i * P
            expect.equal(machine:read_uarch_x(i), defval)
            expect.equal(machine:write_uarch_x(i, val) or machine:read_uarch_x(i), val)
        end
    end)

    it("should read/write htif device", function()
        expect.equal(machine:read_htif_fromhost(), test_config.htif.fromhost)
        expect.equal(machine:read_csr("htif_fromhost"), test_config.htif.fromhost)
        expect.equal(machine:write_htif_fromhost(P) or machine:read_htif_fromhost(), P)
        expect.equal(machine:write_htif_fromhost_data(0) or machine:read_htif_fromhost(), P & ~0xffffffffffff)
        expect.equal(machine:write_csr("htif_fromhost", ~P) or machine:read_htif_fromhost(), ~P)

        expect.equal(machine:read_htif_tohost(), test_config.htif.tohost)
        expect.equal(machine:read_htif_tohost_data(), test_config.htif.tohost & 0xffffffffffff)
        expect.equal(machine:read_htif_tohost_cmd(), (test_config.htif.tohost >> 48) & 0xff)
        expect.equal(machine:read_htif_tohost_dev(), (test_config.htif.tohost >> 56) & 0xff)
        expect.equal(machine:read_csr("htif_tohost"), test_config.htif.tohost)
        expect.equal(machine:write_htif_tohost(P) or machine:read_htif_tohost(), P)
        expect.equal(machine:write_csr("htif_tohost", ~P) or machine:read_htif_tohost(), ~P)

        expect.equal(machine:read_htif_ihalt(), 0x1)
        expect.equal(machine:read_csr("htif_ihalt"), 0x1)
        -- expect.equal(machine:write_htif_ihalt(P) or machine:read_htif_ihalt(), P) -- missing method?
        expect.equal(machine:write_csr("htif_ihalt", ~P) or machine:read_htif_ihalt(), ~P)

        expect.equal(machine:read_htif_iyield(), 0x3)
        expect.equal(machine:read_csr("htif_iyield"), 0x3)
        -- expect.equal(machine:write_htif_iyield(P) or machine:read_htif_iyield(), P) -- missing method?
        expect.equal(machine:write_csr("htif_iyield", ~P) or machine:read_htif_iyield(), ~P)

        expect.equal(machine:read_htif_iconsole(), 0x2)
        expect.equal(machine:read_csr("htif_iconsole"), 0x2)
        -- expect.equal(machine:write_htif_iconsole(P) or machine:read_htif_iconsole(), P) -- missing method?
        expect.equal(machine:write_csr("htif_iconsole", ~P) or machine:read_htif_iconsole(), ~P)
    end)

    it("should read/write clint device", function()
        expect.equal(machine:read_clint_mtimecmp(), test_config.clint.mtimecmp)
        expect.equal(machine:read_csr("clint_mtimecmp"), test_config.clint.mtimecmp)
        expect.equal(machine:write_clint_mtimecmp(P) or machine:read_clint_mtimecmp(), P)
        expect.equal(machine:write_csr("clint_mtimecmp", ~P) or machine:read_clint_mtimecmp(), ~P)
    end)

    it("should fail when attempting to perform invalid writes", function()
        expect.fail(function() machine:write_csr("unknown_csr", 0) end, "unknown csr")
        expect.fail(function() machine:write_csr("marchid", 0) end, "is read-only")
        expect.fail(function() machine:write_csr("mimpid", 0) end, "is read-only")
        expect.fail(function() machine:write_csr("mvendorid", 0) end, "is read-only")
        expect.fail(function() machine:write_csr("uarch_ram_length", 0) end, "is read-only")
        expect.fail(function() machine:write_pc() end, "got no value")
        expect.fail(function() machine:write_x(1) end, "got no value")
        expect.fail(function() machine:write_x(1, nil) end, "got nil")
        expect.fail(function() machine:write_x(nil, 1) end, "got nil")
        expect.fail(function() machine:write_x(1, false) end, "got boolean")
        expect.fail(function() machine:write_x(0, 0) end, "register index out of range")
        expect.fail(function() machine:write_x(32, 0) end, "register index out of range")
        expect.fail(function() machine:write_f(-1, 0) end, "register index out of range")
        expect.fail(function() machine:write_f(32, 0) end, "register index out of range")
        expect.fail(function() machine:write_uarch_x(-1, 0) end, "register index out of range")
        expect.fail(function() machine:write_uarch_x(0, 0) end, "register index out of range")
    end)

    it("should fail when attempting to perform invalid reads", function()
        expect.fail(function() machine:read_csr("unknown_csr") end, "unknown csr")
        expect.fail(function() machine:read_x(-1, 0) end, "register index out of range")
        expect.fail(function() machine:read_x(32, 0) end, "register index out of range")
        expect.fail(function() machine:read_f(-1, 0) end, "register index out of range")
        expect.fail(function() machine:read_f(32, 0) end, "register index out of range")
        expect.fail(function() machine:read_uarch_x(-1, 0) end, "register index out of range")
        expect.fail(function() machine:read_uarch_x(32, 0) end, "register index out of range")
    end)

    it("it should fail when attempting to get address for invalid registers", function()
        expect.fail(function() cartesi.machine.get_csr_address() end, "got no value")
        expect.fail(function() cartesi.machine.get_csr_address(false) end, "got boolean")
        expect.fail(function() cartesi.machine.get_csr_address("") end, "unknown csr")
        expect.fail(function() cartesi.machine.get_csr_address("unknown_csr") end, "unknown csr")
        expect.fail(function() cartesi.machine.get_x_address(-1) end, "register index out of range")
        expect.fail(function() cartesi.machine.get_x_address(32) end, "register index out of range")
        expect.fail(function() cartesi.machine.get_f_address(-1) end, "register index out of range")
        expect.fail(function() cartesi.machine.get_f_address(32) end, "register index out of range")
    end)

    machine:destroy()
end)

describe("machine rollback", function()
    it("should fail when attempting to perform a snapshot or rollback", function()
        local machine <close> = cartesi.machine(test_config)
        expect.fail(function() machine:snapshot() end, "snapshot is not supported")
        expect.fail(function() machine:rollback() end, "rollback is not supported")
    end)
end)

describe("machine store", function()
    local function remove_temporary_files()
        fs.remove_files({
            "temp_machine/0000000000001000-f000.bin",
            "temp_machine/0000000000020000-6000.bin",
            "temp_machine/0000000060000000-1000.bin",
            "temp_machine/0000000060002000-1000.bin",
            "temp_machine/0000000060004000-1000.bin",
            "temp_machine/0000000060006000-1000.bin",
            "temp_machine/0000000060008000-1000.bin",
            "temp_machine/0000000070000000-20000.bin",
            "temp_machine/0000000080000000-ee1000.bin",
            "temp_machine/0080000000000000-4400000.bin",
            "temp_machine/0090000000000000-4000.bin",
            "temp_machine/config.protobuf",
            "temp_machine/hash",
            "temp_machine",
        })
    end

    lester.before(remove_temporary_files)
    lester.after(remove_temporary_files)

    it("should match hashes and configs between loaded and stored machines", function()
        local saved_machine <close> = cartesi.machine(test_config)
        local saved_machine_hash = util.hexhash(saved_machine:get_root_hash())
        local saved_machine_config = saved_machine:get_initial_config()
        saved_machine:store("temp_machine")

        local loaded_machine <close> = cartesi.machine("temp_machine")
        local loaded_machine_hash = util.hexhash(loaded_machine:get_root_hash())
        local loaded_machine_config = loaded_machine:get_initial_config()

        expect.equal(loaded_machine_hash, saved_machine_hash)

        -- all image filenames are lost and changed when using store
        saved_machine_config.flash_drive[1].image_filename = "temp_machine/0080000000000000-4400000.bin"
        saved_machine_config.flash_drive[2].image_filename = "temp_machine/0090000000000000-4000.bin"
        saved_machine_config.ram.image_filename = "temp_machine/0000000080000000-ee1000.bin"
        saved_machine_config.rollup.input_metadata.image_filename = "temp_machine/0000000060004000-1000.bin"
        saved_machine_config.rollup.notice_hashes.image_filename = "temp_machine/0000000060008000-1000.bin"
        saved_machine_config.rollup.rx_buffer.image_filename = "temp_machine/0000000060000000-1000.bin"
        saved_machine_config.rollup.tx_buffer.image_filename = "temp_machine/0000000060002000-1000.bin"
        saved_machine_config.rollup.voucher_hashes.image_filename = "temp_machine/0000000060006000-1000.bin"
        saved_machine_config.rom.image_filename = "temp_machine/0000000000001000-f000.bin"
        saved_machine_config.tlb.image_filename = "temp_machine/0000000000020000-6000.bin"
        saved_machine_config.uarch.ram.image_filename = "temp_machine/0000000070000000-20000.bin"

        -- bootargs are lost when using store()
        saved_machine_config.rom.bootargs = ""

        expect.equal(loaded_machine_config, saved_machine_config)
    end)

    it("should fail when trying to saving into an invalid directory", function()
        local machine <close> = cartesi.machine(test_config)
        expect.fail(function() machine:store("some/invalid/directory") end, "error creating directory")
    end)
end)
