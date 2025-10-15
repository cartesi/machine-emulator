--[[
Test suite for loading and storing machines.
]]

local lester = require("cartesi.third-party.lester")
local cartesi = require("cartesi")
local filesystem = require("cartesi.filesystem")
local utils = require("cartesi.utils")
local tabular = require("cartesi.tabular")
local tests_util = require("cartesi.tests.util")
local describe, it, expect = lester.describe, lester.it, lester.expect

describe("backing stores", function()
    local a_data = string.rep("A", 0x2000)
    local b_data = string.rep("B", 0x2000)
    local trunc_ro_data = string.rep("C", 0x2000)
    local _ <close>, rw_data_filename = filesystem.write_scope_temp_file(a_data)
    local _ <close>, ro_data_filename = filesystem.write_scope_temp_file(b_data)
    local _ <close>, trunc_ro_data_filename = filesystem.write_scope_temp_file(trunc_ro_data)

    local base_machine_config = {
        ram = {
            length = 0x10000,
            backing_store = {
                data_filename = tests_util.tests_path .. "rv64ui-p-addi.bin",
            },
        },
        flash_drive = {
            { -- read/write + backing file
                backing_store = {
                    data_filename = rw_data_filename,
                },
            },
            { -- read only + backing file
                read_only = true,
                backing_store = {
                    data_filename = ro_data_filename,
                },
            },
            { -- read/write + backing file + in-memory truncate
                length = 0x3000,
                backing_store = {
                    data_filename = trunc_ro_data_filename,
                },
            },
            { -- read/write + no backing file
                length = 0x1000,
            },
            { -- read only + no backing file
                length = 0x1000,
                read_only = true,
            },
        },
        hash_tree = {
            phtc_size = 32,
        },
    }

    it("should store a machine with sharing mode all", function()
        local stored_dirname = filesystem.temp_pathname()
        local expected_root_hash

        do -- store new machine
            local machine <close> = cartesi.machine(base_machine_config)
            machine:run()
            expected_root_hash = machine:get_root_hash()
            machine:store(stored_dirname, cartesi.SHARING_ALL)
        end
        local _ <close> = utils.scope_exit(function()
            cartesi.machine:remove_stored(stored_dirname)
        end)

        do -- load stored machine
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_NONE)
            expect.equal(machine:get_root_hash(), expected_root_hash)
        end
    end)

    it("should store a machine with sharing mode none", function()
        local stored_dirname = filesystem.temp_pathname()
        local cloned_dirname = filesystem.temp_pathname()
        local expected_root_hash

        do -- store new machine
            local machine <close> = cartesi.machine(base_machine_config)
            machine:store(stored_dirname)
            expected_root_hash = machine:get_root_hash()
        end
        local _ <close> = utils.scope_exit(function()
            cartesi.machine:remove_stored(stored_dirname)
        end)

        do -- load stored machine and store a clone
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_NONE)
            expect.equal(machine:get_root_hash(), expected_root_hash)
            machine:run()
            machine:store(cloned_dirname, cartesi.SHARING_NONE)
        end
        local _ <close> = utils.scope_exit(function()
            cartesi.machine:remove_stored(cloned_dirname)
        end)

        do -- load cloned machine
            local machine <close> = cartesi.machine(cloned_dirname, {}, cartesi.SHARING_NONE)
            expect.equal(machine:get_root_hash(), expected_root_hash)
        end
    end)

    it("should store a machine with sharing mode config", function()
        local _ <close>, shared_data_filename = filesystem.write_scope_temp_file(a_data)
        local stored_dirname = filesystem.temp_pathname()
        local cloned_dirname = filesystem.temp_pathname()
        local root_drive = {
            start = 0x0080000000000000,
            length = #a_data,
            backing_store = {
                data_filename = shared_data_filename,
                shared = true,
            },
        }
        local expected_root_hash

        do -- store new machine
            local config = tabular.deep_copy(base_machine_config)
            config.flash_drive[1] = root_drive
            local machine <close> = cartesi.machine(config)
            machine:store(stored_dirname)
            machine:write_memory(root_drive.start, string.rep("X", root_drive.length))
            expected_root_hash = machine:get_root_hash()
        end
        local _ <close> = utils.scope_exit(function()
            cartesi.machine:remove_stored(stored_dirname)
        end)

        do -- load stored machine and store only configured drives
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_CONFIG)
            machine:write_memory(root_drive.start, string.rep("X", root_drive.length))
            machine:run()
            machine:store(cloned_dirname, cartesi.SHARING_CONFIG)
        end
        local _ <close> = utils.scope_exit(function()
            cartesi.machine:remove_stored(cloned_dirname)
        end)

        do -- check stored machine
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_NONE)
            expect.equal(machine:read_reg("mcycle"), 0)
            expect.equal(machine:get_root_hash(), expected_root_hash)
        end
        do -- check cloned machine
            local machine <close> = cartesi.machine(cloned_dirname, {}, cartesi.SHARING_NONE)
            expect.equal(machine:read_reg("mcycle"), 0)
            expect.equal(machine:get_root_hash(), expected_root_hash)
        end
    end)

    it("should clone a stored machine", function()
        local stored_dirname = filesystem.temp_pathname()
        local cloned_dirname = filesystem.temp_pathname()
        local expected_mid_root_hash
        local expected_end_root_hash

        do -- store new machine
            local machine <close> = cartesi.machine(base_machine_config, {})
            machine:run(100)
            machine:store(stored_dirname)
            expected_mid_root_hash = machine:get_root_hash()
            machine:run()
            expected_end_root_hash = machine:get_root_hash()
        end
        local _ <close> = utils.scope_exit(function()
            cartesi.machine:remove_stored(stored_dirname)
        end)

        -- clone machine
        cartesi.machine:clone_stored(stored_dirname, cloned_dirname)
        local _ <close> = utils.scope_exit(function()
            cartesi.machine:remove_stored(cloned_dirname)
        end)

        do -- load cloned machine
            local machine <close> = cartesi.machine(cloned_dirname, {}, cartesi.SHARING_NONE)
            expect.equal(machine:get_root_hash(), expected_mid_root_hash)
            machine:run()
            expect.equal(machine:get_root_hash(), expected_end_root_hash)
        end

        do -- load stored machine
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_NONE)
            expect.equal(machine:get_root_hash(), expected_mid_root_hash)
            machine:run()
            expect.equal(machine:get_root_hash(), expected_end_root_hash)
        end
    end)

    it("should create a machine fully mapped on disk", function()
        local stored_dirname = filesystem.temp_pathname()
        local expected_root_hash

        do -- store new machine
            local machine <close> = cartesi.machine(base_machine_config, {}, stored_dirname)
            machine:run()
            expected_root_hash = machine:get_root_hash()
        end
        local _ <close> = utils.scope_exit(function()
            cartesi.machine:remove_stored(stored_dirname)
        end)

        do -- load stored machine
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_NONE)
            expect.equal(machine:get_root_hash(), expected_root_hash)
        end
    end)

    it("should load a machine fully mapped on disk", function()
        local stored_dirname = filesystem.temp_pathname()
        local expected_mid_root_hash
        local expected_end_root_hash

        do -- store new machine
            local machine <close> = cartesi.machine(base_machine_config, {})
            machine:store(stored_dirname)
            expected_mid_root_hash = machine:get_root_hash()
            machine:run()
            expected_end_root_hash = machine:get_root_hash()
        end
        local _ <close> = utils.scope_exit(function()
            cartesi.machine:remove_stored(stored_dirname)
        end)

        do -- load stored machine
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_ALL)
            expect.equal(machine:get_root_hash(), expected_mid_root_hash)
            machine:run()
            expect.equal(machine:get_root_hash(), expected_end_root_hash)
        end

        do -- load stored machine again
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_ALL)
            expect.equal(machine:get_root_hash(), expected_end_root_hash)
        end
    end)

    it("should replace memory range", function()
        local stored1_dirname = filesystem.temp_pathname()
        local stored2_dirname = filesystem.temp_pathname()
        local expected1_root_hash
        local expected2_root_hash

        do -- store new machine
            local machine <close> = cartesi.machine(base_machine_config, {})
            expected1_root_hash = machine:get_root_hash()
            machine:store(stored1_dirname)
            machine:write_memory(0x0080000000000000, 0x2000, string.rep("X", 0x2000))
            expected2_root_hash = machine:get_root_hash()
            machine:store(stored2_dirname)
        end
        local _ <close> = utils.scope_exit(function()
            cartesi.machine:remove_stored(stored1_dirname)
            cartesi.machine:remove_stored(stored2_dirname)
        end)

        do -- load stored machine
            local machine <close> = cartesi.machine(stored1_dirname, {}, cartesi.SHARING_NONE)
            expect.equal(machine:get_root_hash(), expected1_root_hash)
            machine:replace_memory_range({
                start = 0x0080000000000000,
                length = 0x2000,
                backing_store = {
                    data_filename = stored2_dirname .. "/0080000000000000-2000.bin",
                },
            })
            expect.equal(machine:get_root_hash(), expected2_root_hash)
        end
    end)

    it("should replace memory range with existing clean page tree", function()
        local stored1_dirname = filesystem.temp_pathname()
        local stored2_dirname = filesystem.temp_pathname()
        local expected1_root_hash
        local expected2_root_hash

        do -- store new machine
            local machine <close> = cartesi.machine(base_machine_config, {})
            expected1_root_hash = machine:get_root_hash()
            machine:store(stored1_dirname)
            machine:write_memory(0x0080000000000000, 0x2000, string.rep("X", 0x2000))
            expected2_root_hash = machine:get_root_hash()
            machine:store(stored2_dirname)
        end
        local _ <close> = utils.scope_exit(function()
            cartesi.machine:remove_stored(stored1_dirname)
            cartesi.machine:remove_stored(stored2_dirname)
        end)

        do -- load stored machine
            local machine <close> = cartesi.machine(stored1_dirname, {}, cartesi.SHARING_NONE)
            expect.equal(machine:get_root_hash(), expected1_root_hash)
            machine:replace_memory_range({
                start = 0x0080000000000000,
                length = 0x2000,
                backing_store = {
                    data_filename = stored2_dirname .. "/0080000000000000-2000.bin",
                    dht_filename = stored2_dirname .. "/0080000000000000-2000.dht",
                    dpt_filename = stored2_dirname .. "/0080000000000000-2000.dpt",
                },
            })
            expect.equal(machine:get_root_hash(), expected2_root_hash)
        end
    end)

    it("should create a machine with new shared backing stores", function()
        local filename_prefix = filesystem.temp_pathname()
        local expected_root_hash
        local function make_machine(create)
            return cartesi.machine({
                processor = {
                    backing_store = {
                        create = create,
                        shared = create,
                        data_filename = filename_prefix .. "-processor.bin",
                        dht_filename = filename_prefix .. "-processor.dht",
                        dpt_filename = filename_prefix .. "-processor.dpt",
                    },
                },
                pmas = {
                    backing_store = {
                        create = create,
                        shared = create,
                        data_filename = filename_prefix .. "-pmas.bin",
                        dht_filename = filename_prefix .. "-pmas.dht",
                        dpt_filename = filename_prefix .. "-pmas.dpt",
                    },
                },
                ram = {
                    backing_store = {
                        create = create,
                        shared = create,
                        data_filename = filename_prefix .. "-ram.bin",
                        dht_filename = filename_prefix .. "-ram.dht",
                        dpt_filename = filename_prefix .. "-ram.dpt",
                    },
                    length = 0x4000,
                },
                dtb = {
                    backing_store = {
                        create = create,
                        shared = create,
                        data_filename = filename_prefix .. "-dtb.bin",
                        dht_filename = filename_prefix .. "-dtb.dht",
                        dpt_filename = filename_prefix .. "-dtb.dpt",
                    },
                },
                flash_drive = {
                    {
                        length = 8192,
                        backing_store = {
                            create = create,
                            shared = create,
                            data_filename = filename_prefix .. "-drive0.bin",
                            dht_filename = filename_prefix .. "-drive0.dht",
                            dpt_filename = filename_prefix .. "-drive0.dpt",
                        },
                    },
                },
                cmio = {
                    rx_buffer = {
                        backing_store = {
                            create = create,
                            shared = create,
                            data_filename = filename_prefix .. "-cmio_rx.bin",
                            dht_filename = filename_prefix .. "-cmio_rx.dht",
                            dpt_filename = filename_prefix .. "-cmio_rx.dpt",
                        },
                    },
                    tx_buffer = {
                        backing_store = {
                            create = create,
                            shared = create,
                            data_filename = filename_prefix .. "-cmio_tx.bin",
                            dht_filename = filename_prefix .. "-cmio_tx.dht",
                            dpt_filename = filename_prefix .. "-cmio_tx.dpt",
                        },
                    },
                },
                uarch = {
                    processor = {
                        backing_store = {
                            create = create,
                            shared = create,
                            data_filename = filename_prefix .. "-uarch_processor.bin",
                            dht_filename = filename_prefix .. "-uarch_processor.dht",
                            dpt_filename = filename_prefix .. "-uarch_processor.dpt",
                        },
                    },
                    ram = {
                        backing_store = {
                            create = create,
                            shared = create,
                            data_filename = filename_prefix .. "-uarch_ram.bin",
                            dht_filename = filename_prefix .. "-uarch_ram.dht",
                            dpt_filename = filename_prefix .. "-uarch_ram.dpt",
                        },
                    },
                },
                hash_tree = {
                    phtc_size = 32,
                    create = create,
                    shared = create,
                    phtc_filename = filename_prefix .. "-hash_tree.phtc",
                    sht_filename = filename_prefix .. "-hash_tree.sht",
                },
            })
        end

        local initial_config
        do -- store machine address ranges
            local machine <close> = make_machine(true)
            expected_root_hash = machine:get_root_hash()
            initial_config = machine:get_initial_config()
        end
        local _ <close> = utils.scope_exit(function()
            for _, k, v in tabular.deep_traverse(initial_config) do
                if k:find("^%w+_filename$") then
                    filesystem.remove_file(v)
                end
            end
        end)

        do -- load machine address ranges
            local machine <close> = make_machine()
            expect.equal(machine:get_root_hash(), expected_root_hash)
        end
    end)

    it("should truncate backing store file to a bigger size", function()
        local ram_data = string.rep("\x00", 0x1000)
        local _ <close>, ram_filename = filesystem.write_scope_temp_file(ram_data)
        local expected_ram_size = 0x2000

        do
            local _ <close> = cartesi.machine({
                ram = {
                    length = expected_ram_size,
                    backing_store = {
                        data_filename = ram_filename,
                        truncate = true,
                        shared = true,
                    },
                },
            })
        end

        expect.equal(filesystem.get_file_size(ram_filename), expected_ram_size)
    end)
end)
