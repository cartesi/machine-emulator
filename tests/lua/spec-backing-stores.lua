--[[
Test suite for loading and storing machines.
]]

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local cartesi = require("cartesi")
local filesystem = require("cartesi.filesystem")
local hash_tree = require("cartesi.hash-tree")
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
                start = 0x0080000000000000,
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

    for _, storage in ipairs({
        { "RAM", "ram", "data_filename" },
        { "dense hash tree", "ram", "dht_filename" },
        { "dirty page tree", "ram", "dpt_filename" },
        { "sparse hash tree", "hash_tree", "sht_filename" },
        { "page hash-tree cache", "hash_tree", "phtc_filename" },
    }) do
        for _, make_writable in ipairs({ false, true }) do
            it(
                "should reject shared writes to "
                    .. (make_writable and "a hard-linked " or "a read-only ")
                    .. storage[1]
                    .. " backing file",
                function()
                    local stored_dirname = filesystem.temp_pathname()
                    local cloned_dirname = filesystem.temp_pathname()
                    local _ <close> = tests_util.scope_exit(function()
                        pcall(cartesi.machine.remove_stored, cartesi.machine, cloned_dirname)
                        cartesi.machine:remove_stored(stored_dirname)
                    end)
                    local expected_root_hash
                    do
                        local machine <close> = cartesi.machine({
                            ram = { length = 0x1000 },
                            hash_tree = { phtc_size = 32 },
                        })
                        expected_root_hash = machine:get_root_hash()
                        machine:store(stored_dirname)
                    end

                    local backing_filename
                    do
                        local machine <close> = cartesi.machine(stored_dirname)
                        local config = machine:get_initial_config()
                        local section = config[storage[2]]
                        backing_filename = (section.backing_store or section)[storage[3]]
                    end
                    local quoted_filename = "'" .. backing_filename:gsub("'", "'\\''") .. "'"
                    assert(os.execute("chmod a-w " .. quoted_filename))
                    local load_dirname = stored_dirname
                    local stored_dirs = { stored_dirname }
                    if make_writable then
                        cartesi.machine:clone_stored(stored_dirname, cloned_dirname)
                        -- chmod through the template also changes the clone's shared inode.
                        assert(os.execute("chmod u+w " .. quoted_filename))
                        load_dirname = cloned_dirname
                        stored_dirs[#stored_dirs + 1] = cloned_dirname
                    end
                    expect.fail(function()
                        local _ <close> = cartesi.machine(load_dirname, {}, cartesi.SHARING_ALL)
                    end, make_writable and "multiple hard links" or "backing file")

                    -- Private execution remains safe and leaves both stored machines unchanged.
                    do
                        local machine <close> = cartesi.machine(load_dirname, {}, cartesi.SHARING_NONE)
                        expect.equal(machine:get_root_hash(), expected_root_hash)
                        machine:write_memory(0x80000000, string.rep("B", 8))
                        expect.equal(machine:read_memory(0x80000000, 8), string.rep("B", 8))
                    end
                    for _, dirname in ipairs(stored_dirs) do
                        local machine <close> = cartesi.machine(dirname, {}, cartesi.SHARING_NONE)
                        expect.equal(machine:read_memory(0x80000000, 8), string.rep("\0", 8))
                        expect.equal(machine:get_root_hash(), expected_root_hash)
                    end
                end
            )
        end
    end

    it("should allow shared read-only mappings of hard-linked backing files", function()
        local stored_dirname = filesystem.temp_pathname()
        local cloned_dirname = filesystem.temp_pathname()
        local _ <close> = tests_util.scope_exit(function()
            pcall(cartesi.machine.remove_stored, cartesi.machine, cloned_dirname)
            cartesi.machine:remove_stored(stored_dirname)
        end)
        do
            local machine <close> = cartesi.machine(base_machine_config)
            machine:store(stored_dirname)
        end
        cartesi.machine:clone_stored(stored_dirname, cloned_dirname)
        local machine <close> = cartesi.machine(cloned_dirname, {}, cartesi.SHARING_ALL)
        local drive = machine:get_initial_config().flash_drive[2]
        expect.equal(machine:read_memory(drive.start, #b_data), b_data)
    end)

    it("should store a machine with sharing mode all", function()
        local stored_dirname = filesystem.temp_pathname()
        local expected_root_hash

        do -- store new machine
            local machine <close> = cartesi.machine(base_machine_config)
            machine:run()
            expected_root_hash = machine:get_root_hash()
            machine:store(stored_dirname, cartesi.SHARING_ALL)
        end
        local _ <close> = tests_util.scope_exit(function()
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
        local _ <close> = tests_util.scope_exit(function()
            cartesi.machine:remove_stored(stored_dirname)
        end)

        do -- load stored machine and store a clone
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_NONE)
            expect.equal(machine:get_root_hash(), expected_root_hash)
            machine:run()
            machine:store(cloned_dirname, cartesi.SHARING_NONE)
        end
        local _ <close> = tests_util.scope_exit(function()
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
            start = 0x00c0000000000000,
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
        local _ <close> = tests_util.scope_exit(function()
            cartesi.machine:remove_stored(stored_dirname)
        end)

        do -- load stored machine and store only configured drives
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_CONFIG)
            machine:write_memory(root_drive.start, string.rep("X", root_drive.length))
            machine:run()
            machine:store(cloned_dirname, cartesi.SHARING_CONFIG)
        end
        local _ <close> = tests_util.scope_exit(function()
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

    for _, hash_function in ipairs({ "keccak256", "sha256" }) do
        for _, operation in ipairs({ "store", "close" }) do
            it(
                "should preserve pending write TLB dirty marks on " .. operation .. " (" .. hash_function .. ")",
                function()
                    local stored_dirname = filesystem.temp_pathname()
                    local cloned_dirname = filesystem.temp_pathname()
                    local _ <close> = tests_util.scope_exit(function()
                        cartesi.machine:remove_stored(stored_dirname)
                        if operation == "store" then
                            cartesi.machine:remove_stored(cloned_dirname)
                        end
                    end)
                    local drive_start = 0x90000000
                    local value = 0x0102030405060708
                    local _ <close>, drive_filename = filesystem.write_scope_temp_file(string.rep("A", 0x1000))
                    -- sd a1,0(a0)
                    local _ <close>, ram_filename = filesystem.write_scope_temp_file(string.pack("<I4", 0x00b53023))

                    do
                        local machine <close> = cartesi.machine({
                            ram = { length = 0x1000, backing_store = { data_filename = ram_filename } },
                            flash_drive = {
                                {
                                    start = drive_start,
                                    length = 0x1000,
                                    backing_store = { data_filename = drive_filename, shared = true },
                                },
                            },
                            hash_tree = { phtc_size = 32, hash_function = hash_function },
                        })
                        machine:get_root_hash() -- Persist clean dirty-page trees before the guest write.
                        machine:store(stored_dirname)
                    end

                    do
                        local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_CONFIG)
                        machine:write_reg("x10", drive_start)
                        machine:write_reg("x11", value)
                        machine:run(1)
                        expect.equal(machine:read_memory(drive_start, 8), string.pack("<I8", value))
                        -- Do not hash or flush the TLB before storing or closing.
                        if operation == "store" then
                            machine:store(cloned_dirname, cartesi.SHARING_CONFIG)
                            local restored <close> = cartesi.machine(cloned_dirname)
                            expect.equal(restored:read_memory(drive_start, 8), string.pack("<I8", value))
                            expect.equal(restored:get_root_hash(), tests_util.calculate_emulator_hash(restored))
                        end
                    end

                    if operation == "close" then
                        local restored <close> = cartesi.machine(stored_dirname)
                        expect.equal(restored:read_memory(drive_start, 8), string.pack("<I8", value))
                        expect.equal(restored:get_root_hash(), tests_util.calculate_emulator_hash(restored))
                    end
                end
            )
        end
    end

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
        local _ <close> = tests_util.scope_exit(function()
            cartesi.machine:remove_stored(stored_dirname)
        end)

        -- clone machine
        cartesi.machine:clone_stored(stored_dirname, cloned_dirname)
        local _ <close> = tests_util.scope_exit(function()
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

    it("should rename a stored machine without overwriting", function()
        local stored_dirname = filesystem.temp_pathname()
        local renamed_dirname = filesystem.temp_pathname()
        local occupied_dirname = filesystem.temp_pathname()
        local expected_root_hash

        do
            local machine <close> = cartesi.machine(base_machine_config, {})
            machine:run(100)
            machine:store(stored_dirname)
            expected_root_hash = machine:get_root_hash()
        end
        local _ <close> = tests_util.scope_exit(function()
            for _, dirname in ipairs({ stored_dirname, renamed_dirname, occupied_dirname }) do
                pcall(cartesi.machine.remove_stored, cartesi.machine, dirname)
            end
        end)

        cartesi.machine:rename_stored(stored_dirname, renamed_dirname)
        expect.falsy(os.rename(stored_dirname, stored_dirname))
        do
            local machine <close> = cartesi.machine(renamed_dirname, {}, cartesi.SHARING_NONE)
            expect.equal(machine:get_root_hash(), expected_root_hash)
        end

        cartesi.machine:clone_stored(renamed_dirname, stored_dirname)
        cartesi.machine:clone_stored(renamed_dirname, occupied_dirname)
        expect.fail(function()
            cartesi.machine:rename_stored(stored_dirname, occupied_dirname)
        end, "destination exists")
        do
            local source <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_NONE)
            local destination <close> = cartesi.machine(occupied_dirname, {}, cartesi.SHARING_NONE)
            expect.equal(source:get_root_hash(), expected_root_hash)
            expect.equal(destination:get_root_hash(), expected_root_hash)
        end
    end)

    it("should sync a stored machine", function()
        local stored_dirname = filesystem.temp_pathname()
        local expected_root_hash

        do -- store new machine
            local machine <close> = cartesi.machine(base_machine_config)
            machine:run()
            expected_root_hash = machine:get_root_hash()
            machine:store(stored_dirname, cartesi.SHARING_ALL)
        end
        local _ <close> = tests_util.scope_exit(function()
            cartesi.machine:remove_stored(stored_dirname)
        end)

        -- sync stored machine after the machine using it is closed
        cartesi.machine:sync_stored(stored_dirname)

        do -- load stored machine
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_NONE)
            expect.equal(machine:get_root_hash(), expected_root_hash)
        end
    end)

    it("should sync a stored machine while it is in use", function()
        local stored_dirname = filesystem.temp_pathname()

        do -- store new machine
            local machine <close> = cartesi.machine(base_machine_config)
            machine:store(stored_dirname, cartesi.SHARING_ALL)
        end
        local _ <close> = tests_util.scope_exit(function()
            cartesi.machine:remove_stored(stored_dirname)
        end)

        do -- load stored machine with all backing stores shared and sync while it is running
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_ALL)
            machine:run()
            cartesi.machine:sync_stored(stored_dirname)
        end
    end)

    it("should fail to sync a stored machine with invalid arguments", function()
        expect.fail(function()
            cartesi.machine:sync_stored()
        end, "bad argument")
        expect.fail(function()
            cartesi.machine:sync_stored(filesystem.temp_pathname())
        end, "unable to read file")
    end)

    for _, hash_function in ipairs({ "keccak256", "sha256" }) do
        for _, operation in ipairs({ "sync", "clone" }) do
            it("should preserve cached page hashes after " .. operation .. " (" .. hash_function .. ")", function()
                local stored_dirname = filesystem.temp_pathname()
                local cloned_dirname = filesystem.temp_pathname()
                local _ <close> = tests_util.scope_exit(function()
                    cartesi.machine:remove_stored(stored_dirname)
                    if operation == "clone" then
                        cartesi.machine:remove_stored(cloned_dirname)
                    end
                end)
                local machine <close> = cartesi.machine({
                    ram = { length = 0x20000 },
                    hash_tree = { phtc_size = 32, hash_function = hash_function },
                }, {}, stored_dirname)

                -- Populate every cache entry with non-pristine data, including the final word of each page.
                machine:write_memory(0x80000000, string.rep("A", 0x20000))
                machine:get_root_hash()
                if operation == "sync" then
                    machine:sync_stored(stored_dirname)
                else
                    machine:destroy()
                    machine:clone_stored(stored_dirname, cloned_dirname)
                    machine:load(cloned_dirname, {}, cartesi.SHARING_ALL)
                end

                -- Rehash the penultimate word while reusing its cached sibling at the end of the page.
                for page = 0x80000000, 0x8001f000, 0x1000 do
                    machine:write_memory(page + 0xfc0, "B")
                end
                expect.equal(machine:get_root_hash(), tests_util.calculate_emulator_hash(machine))
            end)
        end
    end

    it("should fail to remove a stored machine containing an extraneous file", function()
        local stored_dirname = filesystem.temp_pathname()

        do -- store new machine
            local machine <close> = cartesi.machine(base_machine_config)
            machine:store(stored_dirname, cartesi.SHARING_ALL)
        end

        -- an extraneous file makes the removal fail, and the file survives
        local extraneous_filename = stored_dirname .. "/extraneous"
        filesystem.write_file(extraneous_filename, "keep")
        expect.fail(function()
            cartesi.machine:remove_stored(stored_dirname)
        end, "unable to remove directory")
        expect.equal(filesystem.read_file(extraneous_filename), "keep")

        -- the machine files were already removed, only the extraneous file remains
        filesystem.remove_file(extraneous_filename)
        assert(os.remove(stored_dirname))
    end)

    it("should create a machine fully mapped on disk", function()
        local stored_dirname = filesystem.temp_pathname()
        local expected_root_hash

        do -- store new machine
            local machine <close> = cartesi.machine(base_machine_config, {}, stored_dirname)
            machine:run()
            expected_root_hash = machine:get_root_hash()
        end
        local _ <close> = tests_util.scope_exit(function()
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
        local _ <close> = tests_util.scope_exit(function()
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
        local _ <close> = tests_util.scope_exit(function()
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
        local _ <close> = tests_util.scope_exit(function()
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

    describe("page hash-tree cache metadata", function()
        -- The persisted layout contains a tag, list size, sentinel links, and compact entries.
        -- Each entry contains next/previous links, page address, borrowed flag, and payload index.
        local capacity = 32
        local entries_offset = 32
        local entry_size = 40
        local payloads_offset = (entries_offset + capacity * entry_size + 4095) & ~4095

        local function write_word(data, offset, value)
            return data:sub(1, offset) .. string.pack("<I8", value) .. data:sub(offset + 9)
        end

        local function write_link(data, offset, target_offset)
            return write_word(data, offset, target_offset - offset)
        end

        local corruptions = {
            {
                "old layout tag",
                function(data)
                    return write_word(data, 0, 0x50485443)
                end,
            },
            {
                "oversized list",
                function(data)
                    return write_word(data, 8, capacity + 1)
                end,
            },
            {
                "short list",
                function(data)
                    return write_word(data, 8, capacity - 1)
                end,
            },
            {
                "null head",
                function(data)
                    return write_word(data, 16, 1)
                end,
            },
            {
                "head outside mapping",
                function(data)
                    return write_link(data, 16, #data + 4096)
                end,
            },
            {
                "unaligned head",
                function(data)
                    return write_link(data, 16, entries_offset + 1)
                end,
            },
            {
                "head inside entry",
                function(data)
                    return write_link(data, 16, entries_offset + 8)
                end,
            },
            {
                "head in metadata padding",
                function(data)
                    return write_link(data, 16, entries_offset + capacity * entry_size)
                end,
            },
            {
                "head in payload",
                function(data)
                    return write_link(data, 16, payloads_offset)
                end,
            },
            {
                "invalid tail",
                function(data)
                    return write_word(data, 24, 1)
                end,
            },
            {
                "invalid next",
                function(data)
                    return write_word(data, entries_offset, 1)
                end,
            },
            {
                "invalid previous",
                function(data)
                    return write_word(data, entries_offset + 8, 1)
                end,
            },
            {
                "self cycle",
                function(data)
                    return write_link(data, entries_offset, entries_offset)
                end,
            },
            {
                "borrowed entry",
                function(data)
                    return write_word(data, entries_offset + 24, 1)
                end,
            },
            {
                "out-of-range payload",
                function(data)
                    return write_word(data, entries_offset + 32, capacity)
                end,
            },
            {
                "overflowing payload",
                function(data)
                    return write_word(data, entries_offset + 32, -1)
                end,
            },
            {
                "duplicate payload",
                function(data)
                    local other = string.unpack("<I8", data, entries_offset + entry_size + 33)
                    return write_word(data, entries_offset + 32, other)
                end,
            },
            {
                "duplicate page address",
                function(data)
                    local other = string.unpack("<I8", data, entries_offset + entry_size + 17)
                    return write_word(data, entries_offset + 16, other)
                end,
            },
        }

        for _, corruption in ipairs(corruptions) do
            it("should reject " .. corruption[1] .. " without following invalid links", function()
                local directory = filesystem.temp_pathname()
                do
                    local machine <close> = cartesi.machine({
                        ram = { length = 2 * capacity * 4096 },
                        hash_tree = { phtc_size = capacity },
                    })
                    machine:write_memory(cartesi.AR_RAM_START, string.rep("A", 2 * capacity * 4096))
                    machine:get_root_hash()
                    machine:store(directory)
                end
                local _ <close> = tests_util.scope_exit(function()
                    cartesi.machine:remove_stored(directory)
                end)
                local filename = directory .. "/hash_tree.phtc"
                local data = filesystem.read_file(filename)
                expect.equal(string.unpack("<I8", data, 9), capacity)
                filesystem.write_file(filename, corruption[2](data))
                for _, sharing in ipairs({ cartesi.SHARING_NONE, cartesi.SHARING_ALL }) do
                    expect.fail(function()
                        local _ <close> = cartesi.machine(directory, {}, sharing)
                    end, "corrupted page hash-tree cache")
                end
            end)
        end

        it("should reject overflowing cache capacities before mapping", function()
            for _, phtc_size in ipairs({ math.maxinteger, -1 }) do
                expect.fail(function()
                    local _ <close> = cartesi.machine({
                        ram = { length = 4096 },
                        hash_tree = { phtc_size = phtc_size },
                    })
                end, "invalid page hash-tree cache capacity")
            end
        end)

        it("should reject truncated and oversized cache files before accessing metadata", function()
            local directory = filesystem.temp_pathname()
            do
                local machine <close> = cartesi.machine({
                    ram = { length = 4096 },
                    hash_tree = { phtc_size = capacity },
                })
                machine:store(directory)
            end
            local _ <close> = tests_util.scope_exit(function()
                cartesi.machine:remove_stored(directory)
            end)
            local filename = directory .. "/hash_tree.phtc"
            local data = filesystem.read_file(filename)
            for _, length in ipairs({ 0, 8, entries_offset - 1, payloads_offset - 1, #data - 1, #data + 1 }) do
                filesystem.write_file(filename, length > #data and data .. "\0" or data:sub(1, length))
                for _, sharing in ipairs({ cartesi.SHARING_NONE, cartesi.SHARING_ALL }) do
                    expect.fail(function()
                        local _ <close> = cartesi.machine(directory, {}, sharing)
                    end, "length")
                end
            end
        end)

        it("should validate unused metadata before entries are handed out", function()
            local directory = filesystem.temp_pathname()
            do
                local _ <close> = cartesi.machine({
                    ram = { length = 4096 },
                    hash_tree = { phtc_size = capacity },
                }, {}, directory)
            end
            local _ <close> = tests_util.scope_exit(function()
                cartesi.machine:remove_stored(directory)
            end)
            local filename = directory .. "/hash_tree.phtc"
            local data = filesystem.read_file(filename)
            expect.equal(string.unpack("<I8", data, 9), 0)
            for _, offset in ipairs({ entries_offset, entries_offset + 8, entries_offset + 32 }) do
                filesystem.write_file(filename, write_word(data, offset, -1))
                expect.fail(function()
                    local _ <close> = cartesi.machine(directory)
                end, "corrupted page hash-tree cache")
            end
        end)

        it("should evict loaded entries without changing cached payloads", function()
            local directory = filesystem.temp_pathname()
            do
                local machine <close> = cartesi.machine({
                    ram = { length = 4096 },
                    flash_drive = {
                        { start = 0x90000000, length = 4096, backing_store = { shared = true } },
                        { start = 0xa0000000, length = 4096 },
                    },
                    hash_tree = { phtc_size = capacity, shared = true },
                }, {}, directory)
                machine:write_memory(0x90000000, string.rep("A", 4096))
                machine:write_memory(0xa0000000, string.rep("B", 4096))
                machine:get_root_hash()
                machine:get_node_hash(0x90000000, cartesi.HASH_TREE_LOG2_WORD_SIZE)
                machine:get_node_hash(0xa0000000, cartesi.HASH_TREE_LOG2_WORD_SIZE)
            end
            local _ <close> = tests_util.scope_exit(function()
                cartesi.machine:remove_stored(directory)
            end)
            local filename = directory .. "/hash_tree.phtc"
            local before = filesystem.read_file(filename)
            do
                local _ <close> = cartesi.machine(directory, {}, cartesi.SHARING_CONFIG)
            end
            local after = filesystem.read_file(filename)
            expect.truthy(string.unpack("<I8", after, 9) < string.unpack("<I8", before, 9))
            expect.equal(after:sub(payloads_offset + 1), before:sub(payloads_offset + 1))
            -- Reload the compacted metadata and exercise both retained and reassigned slots.
            local machine <close> = cartesi.machine(directory, {}, cartesi.SHARING_ALL)
            machine:write_memory(0xa0000000, string.rep("C", 4096))
            expect.equal(machine:get_root_hash(), tests_util.calculate_emulator_hash(machine))
        end)
    end)

    describe("page hash-tree cache eviction", function()
        local drive_start = 0x90000000
        local retained_start = 0xa0000000
        local page_size = 0x1000
        local word_size = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE

        local function make_config(hash_function, phtc_size)
            return {
                ram = { length = page_size },
                flash_drive = {
                    { start = drive_start, length = 2 * page_size },
                    { start = retained_start, length = page_size },
                },
                hash_tree = { hash_function = hash_function, phtc_size = phtc_size },
            }
        end

        local function initialize(machine, data)
            -- sd a1,0(a0), followed by ld a2,0(a0).
            machine:write_memory(0x80000000, string.pack("<I4I4", 0x00b53023, 0x00053603))
            machine:write_reg("x10", drive_start)
            machine:write_reg("x11", 0x0102030405060708)
            machine:write_memory(drive_start, string.rep(data, 2 * page_size))
            machine:write_memory(retained_start, string.rep("R", page_size))
        end

        local function expect_word(machine, address, data, hash_function)
            local expected_hash = cartesi[hash_function](string.rep(data, word_size))
            expect.equal(machine:get_node_hash(address, cartesi.HASH_TREE_LOG2_WORD_SIZE), expected_hash)
            local proof = machine:get_proof(address, cartesi.HASH_TREE_LOG2_WORD_SIZE)
            expect.equal(proof.target_hash, expected_hash)
            hash_tree.verify_slice(proof, hash_function)
        end

        for _, hash_function in ipairs({ "keccak256", "sha256" }) do
            for _, dirty in ipairs({ false, true }) do
                it(
                    "should evict only clean replacement pages ("
                        .. hash_function
                        .. ", dirty="
                        .. tostring(dirty)
                        .. ")",
                    function()
                        for _, phtc_size in ipairs(dirty and { 32 } or { 1, 32, 1024 }) do
                            local original_dir = filesystem.temp_pathname()
                            local replacement_dir = filesystem.temp_pathname()
                            local saved_dir = filesystem.temp_pathname()
                            local saved = false
                            do
                                local machine <close> = cartesi.machine(make_config(hash_function, phtc_size))
                                initialize(machine, "A")
                                machine:get_root_hash()
                                machine:store(original_dir, cartesi.SHARING_ALL)
                                machine:write_memory(drive_start, string.rep("B", 2 * page_size))
                                machine:get_root_hash()
                                if dirty then
                                    machine:write_memory(drive_start, string.rep("C", page_size))
                                end
                                machine:store(replacement_dir, cartesi.SHARING_ALL)
                            end
                            local _ <close> = tests_util.scope_exit(function()
                                cartesi.machine:remove_stored(original_dir)
                                cartesi.machine:remove_stored(replacement_dir)
                                if saved then
                                    cartesi.machine:remove_stored(saved_dir)
                                end
                            end)
                            do
                                local machine <close> = cartesi.machine(original_dir, {}, cartesi.SHARING_NONE)
                                machine:get_root_hash()
                                machine:get_hash_tree_stats(true)
                                machine:get_node_hash(retained_start, cartesi.HASH_TREE_LOG2_PAGE_SIZE)
                                local baseline = machine:get_hash_tree_stats(true).phtc
                                machine:get_node_hash(retained_start, cartesi.HASH_TREE_LOG2_WORD_SIZE)
                                machine:get_node_hash(drive_start, cartesi.HASH_TREE_LOG2_WORD_SIZE)
                                machine:get_node_hash(drive_start + page_size, cartesi.HASH_TREE_LOG2_WORD_SIZE)
                                machine:get_hash_tree_stats(true)
                                local prefix = replacement_dir .. "/0000000090000000-2000"
                                machine:replace_memory_range({
                                    start = drive_start,
                                    length = 2 * page_size,
                                    backing_store = {
                                        data_filename = prefix .. ".bin",
                                        dht_filename = prefix .. ".dht",
                                        dpt_filename = prefix .. ".dpt",
                                    },
                                })
                                if phtc_size > 1 then
                                    machine:get_node_hash(retained_start, cartesi.HASH_TREE_LOG2_WORD_SIZE)
                                    local stats = machine:get_hash_tree_stats(true).phtc
                                    expect.equal(stats.page_hits, baseline.page_hits + (dirty and 2 or 1))
                                    expect.equal(stats.page_misses, 0)
                                end
                                machine:get_node_hash(drive_start + page_size, cartesi.HASH_TREE_LOG2_WORD_SIZE)
                                local stats = machine:get_hash_tree_stats(true).phtc
                                expect.equal(stats.page_hits, baseline.page_hits)
                                expect.equal(stats.page_misses, baseline.page_misses + 1)
                                expect_word(machine, drive_start, dirty and "C" or "B", hash_function)
                                expect_word(machine, drive_start + page_size, "B", hash_function)
                                expect.equal(machine:get_root_hash(), tests_util.calculate_emulator_hash(machine))
                                machine:store(saved_dir, cartesi.SHARING_ALL)
                                saved = true
                            end
                            do
                                local machine <close> = cartesi.machine(saved_dir, {}, cartesi.SHARING_NONE)
                                machine:get_root_hash()
                                machine:get_hash_tree_stats(true)
                                machine:get_node_hash(retained_start, cartesi.HASH_TREE_LOG2_PAGE_SIZE)
                                local baseline = machine:get_hash_tree_stats(true).phtc
                                expect_word(machine, drive_start + page_size, "B", hash_function)
                                local stats = machine:get_hash_tree_stats(true).phtc
                                if phtc_size > 1 then
                                    expect.equal(stats.page_hits, 2 * baseline.page_hits + 2)
                                    expect.equal(stats.page_misses, 0)
                                end
                                expect.equal(machine:get_root_hash(), tests_util.calculate_emulator_hash(machine))
                            end
                        end
                    end
                )
            end

            for _, shared in ipairs({ false, true }) do
                it(
                    "should evict loaded pages with different sharing ("
                        .. hash_function
                        .. ", shared="
                        .. tostring(shared)
                        .. ")",
                    function()
                        local stored_dir = filesystem.temp_pathname()
                        do
                            local config = make_config(hash_function, 256)
                            config.hash_tree.shared = shared
                            config.flash_drive[1].backing_store = { shared = shared }
                            config.flash_drive[2].backing_store = { shared = not shared }
                            local machine <close> = cartesi.machine(config, {}, stored_dir)
                            initialize(machine, "A")
                            machine:get_root_hash()
                            machine:get_node_hash(drive_start, cartesi.HASH_TREE_LOG2_WORD_SIZE)
                            machine:get_node_hash(retained_start, cartesi.HASH_TREE_LOG2_WORD_SIZE)
                        end
                        local _ <close> = tests_util.scope_exit(function()
                            cartesi.machine:remove_stored(stored_dir)
                        end)
                        for _, sharing in ipairs({
                            cartesi.SHARING_CONFIG,
                            cartesi.SHARING_CONFIG,
                            cartesi.SHARING_NONE,
                            cartesi.SHARING_ALL,
                        }) do
                            local machine <close> = cartesi.machine(stored_dir, {}, sharing)
                            machine:get_root_hash()
                            machine:get_hash_tree_stats(true)
                            machine:get_node_hash(drive_start, cartesi.HASH_TREE_LOG2_PAGE_SIZE)
                            local baseline = machine:get_hash_tree_stats(true).phtc
                            machine:get_node_hash(drive_start, cartesi.HASH_TREE_LOG2_WORD_SIZE)
                            local stats = machine:get_hash_tree_stats(true).phtc
                            expect.equal(stats.page_hits, baseline.page_hits + 1)
                            expect.equal(stats.page_misses, 0)
                            machine:get_node_hash(retained_start, cartesi.HASH_TREE_LOG2_WORD_SIZE)
                            stats = machine:get_hash_tree_stats(true).phtc
                            expect.equal(
                                stats.page_hits,
                                baseline.page_hits + (sharing == cartesi.SHARING_CONFIG and 0 or 1)
                            )
                            expect.equal(stats.page_misses, sharing == cartesi.SHARING_CONFIG and 1 or 0)
                            expect_word(machine, drive_start, "A", hash_function)
                            expect_word(machine, retained_start, "R", hash_function)
                            expect.equal(machine:get_root_hash(), tests_util.calculate_emulator_hash(machine))
                        end
                    end
                )
            end
        end

        it("should collect correct uarch hashes after clean range replacement", function()
            local original_dir = filesystem.temp_pathname()
            local replacement_dir = filesystem.temp_pathname()
            do
                local machine <close> = cartesi.machine(make_config("keccak256", 256))
                initialize(machine, "A")
                machine:get_root_hash()
                machine:store(original_dir, cartesi.SHARING_ALL)
                machine:write_memory(drive_start, string.rep("B", 2 * page_size))
                machine:get_root_hash()
                machine:store(replacement_dir, cartesi.SHARING_ALL)
            end
            local _ <close> = tests_util.scope_exit(function()
                cartesi.machine:remove_stored(original_dir)
                cartesi.machine:remove_stored(replacement_dir)
            end)
            local machine <close> = cartesi.machine(original_dir, {}, cartesi.SHARING_NONE)
            local reference <close> = cartesi.machine(replacement_dir, {}, cartesi.SHARING_NONE)
            machine:get_node_hash(drive_start, cartesi.HASH_TREE_LOG2_WORD_SIZE)
            local prefix = replacement_dir .. "/0000000090000000-2000"
            machine:replace_memory_range({
                start = drive_start,
                length = 2 * page_size,
                backing_store = {
                    data_filename = prefix .. ".bin",
                    dht_filename = prefix .. ".dht",
                    dpt_filename = prefix .. ".dpt",
                },
            })
            local revert_tail = { string.rep("\0", cartesi.HASH_SIZE), string.rep("\0", cartesi.HASH_SIZE) }
            local expected = reference:collect_uarch_cycle_root_hashes(1, 0, revert_tail)
            local obtained = machine:collect_uarch_cycle_root_hashes(1, 0, revert_tail)
            expect.equal(obtained.break_reason, expected.break_reason)
            expect.equal(obtained.mcycle_hash_offsets, expected.mcycle_hash_offsets)
            expect.equal(#obtained.hashes, #expected.hashes)
            for i, hash in ipairs(expected.hashes) do
                expect.equal(obtained.hashes[i], hash)
            end
            expect.equal(machine:read_reg("mcycle"), 1)
            expect.equal(machine:get_root_hash(), reference:get_root_hash())
            expect.equal(machine:get_root_hash(), tests_util.calculate_emulator_hash(machine))
        end)
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
        local _ <close> = tests_util.scope_exit(function()
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

    for _, hash_function in ipairs({ "keccak256", "sha256" }) do
        for _, creation in ipairs({
            "anonymous",
            "shared",
            "directory",
            "directory-invalid-size",
            "load",
            "anonymous-dpt",
            "shared-dpt",
            "directory-dpt",
            "load-dpt",
            "reuse",
            "forced",
            "directory-forced",
        }) do
            it(
                "should initialize dirty pages for backing trees (" .. creation .. ", " .. hash_function .. ")",
                function()
                    local filename_prefix = filesystem.temp_pathname()
                    local stored_dirname = filesystem.temp_pathname()
                    local in_directory = creation:find("^directory") ~= nil
                    local load_stored = creation:find("^load") ~= nil
                    local backing_store = {
                        data_filename = filename_prefix .. ".bin",
                        dht_filename = filename_prefix .. ".dht",
                        dpt_filename = filename_prefix .. ".dpt",
                        shared = true,
                        create = true,
                        mark_pages_dirty = false,
                    }
                    local _ <close> = tests_util.scope_exit(function()
                        for _, suffix in ipairs({ ".bin", ".dht", ".dpt" }) do
                            filesystem.remove_file(filename_prefix .. suffix)
                        end
                        if in_directory or load_stored or creation == "forced" then
                            cartesi.machine:remove_stored(stored_dirname)
                        end
                    end)
                    local drive_start = 0x90000000
                    local drive_data = string.rep("A", 0x3000) -- Include power-of-two padding in the dense tree.
                    local config = {
                        ram = { length = 0x1000 },
                        flash_drive = { { start = drive_start, length = #drive_data, backing_store = backing_store } },
                        hash_tree = { phtc_size = 32, hash_function = hash_function },
                    }

                    do
                        local machine <close> = cartesi.machine(config)
                        machine:write_memory(drive_start, drive_data)
                        machine:get_root_hash() -- Leave an existing, initialized, clean dirty-page tree.
                        if load_stored then
                            machine:store(stored_dirname)
                        end
                    end

                    backing_store.create = false
                    local clean_dpt = filesystem.read_file(backing_store.dpt_filename)
                    backing_store.shared = creation == "shared"
                        or creation == "shared-dpt"
                        or creation == "reuse"
                        or creation == "forced"
                    if creation == "anonymous" or creation == "directory" then
                        backing_store.dht_filename = ""
                    elseif creation == "shared" then
                        filesystem.remove_file(backing_store.dht_filename)
                    elseif creation == "directory-invalid-size" then
                        filesystem.write_file(backing_store.dht_filename, "\0")
                    elseif creation == "anonymous-dpt" or creation == "directory-dpt" then
                        backing_store.dpt_filename = ""
                    elseif creation == "shared-dpt" then
                        filesystem.remove_file(backing_store.dpt_filename)
                    elseif creation == "forced" or creation == "directory-forced" then
                        backing_store.mark_pages_dirty = true
                        drive_data = string.rep("B", #drive_data)
                        filesystem.write_file(backing_store.data_filename, drive_data)
                    end

                    if load_stored then
                        local tree_filename
                        do
                            local stored <close> = cartesi.machine(stored_dirname)
                            local stored_bs = stored:get_initial_config().flash_drive[1].backing_store
                            tree_filename = creation == "load" and stored_bs.dht_filename or stored_bs.dpt_filename
                        end
                        filesystem.remove_file(tree_filename)
                    end
                    local directory = in_directory and stored_dirname or nil
                    local machine <close> = load_stored and cartesi.machine(stored_dirname, {}, cartesi.SHARING_ALL)
                        or cartesi.machine(config, {}, directory)
                    if creation == "reuse" then
                        expect.equal(filesystem.read_file(backing_store.dpt_filename), clean_dpt)
                    end
                    expect.equal(
                        machine:get_initial_config().flash_drive[1].backing_store.mark_pages_dirty,
                        backing_store.mark_pages_dirty
                    )
                    expect.equal(machine:read_memory(drive_start, #drive_data), drive_data)
                    expect.equal(machine:get_root_hash(), tests_util.calculate_emulator_hash(machine))
                    if creation == "forced" then
                        machine:store(stored_dirname)
                        local stored <close> = cartesi.machine(stored_dirname)
                        expect.equal(stored:get_initial_config().flash_drive[1].backing_store.mark_pages_dirty, true)
                        expect.equal(stored:get_root_hash(), machine:get_root_hash())
                    end
                end
            )
        end
    end

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

lester.report()
lester.exit()
