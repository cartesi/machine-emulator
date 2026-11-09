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
                    local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
                    local _ <close>, cloned_dirname = tests_util.scope_temp_pathname()
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
        local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
        local _ <close>, cloned_dirname = tests_util.scope_temp_pathname()
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
        local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
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
        local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
        local _ <close>, cloned_dirname = tests_util.scope_temp_pathname()
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
        local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
        local _ <close>, cloned_dirname = tests_util.scope_temp_pathname()
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
                    local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
                    local _ <close>, cloned_dirname = tests_util.scope_temp_pathname()
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
        local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
        local _ <close>, cloned_dirname = tests_util.scope_temp_pathname()
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
        local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
        local _ <close>, renamed_dirname = tests_util.scope_temp_pathname()
        local _ <close>, occupied_dirname = tests_util.scope_temp_pathname()
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
        local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
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

    it("should refuse to sync a stored machine while it is in use", function()
        local _ <close>, stored_dirname = tests_util.scope_temp_pathname()

        do -- store new machine
            local machine <close> = cartesi.machine(base_machine_config)
            machine:store(stored_dirname, cartesi.SHARING_ALL)
        end
        local _ <close> = tests_util.scope_exit(function()
            cartesi.machine:remove_stored(stored_dirname)
        end)

        do -- a machine with all backing stores shared writes its files, so they cannot be synced under it
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_ALL)
            machine:run()
            expect.fail(function()
                cartesi.machine:sync_stored(stored_dirname)
            end, "flock() failed")
        end

        do -- a machine that shares no backing store leaves the files alone
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_NONE)
            machine:run()
            cartesi.machine:sync_stored(stored_dirname)
        end
    end)

    it("should fail to sync a stored machine with invalid arguments", function()
        expect.fail(function()
            cartesi.machine:sync_stored()
        end, "bad argument")
        expect.fail(function()
            local _ <close>, missing = tests_util.scope_temp_pathname()
            cartesi.machine:sync_stored(missing)
        end, "unable to read file")
    end)

    for _, hash_function in ipairs({ "keccak256", "sha256" }) do
        for _, operation in ipairs({ "sync", "clone" }) do
            it("should preserve cached page hashes after " .. operation .. " (" .. hash_function .. ")", function()
                local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
                local _ <close>, cloned_dirname = tests_util.scope_temp_pathname()
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
                    machine:destroy()
                    machine:sync_stored(stored_dirname)
                    machine:load(stored_dirname, {}, cartesi.SHARING_ALL)
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
        local _ <close>, stored_dirname = tests_util.scope_temp_pathname()

        do -- store new machine
            local machine <close> = cartesi.machine(base_machine_config)
            machine:store(stored_dirname, cartesi.SHARING_ALL)
        end

        -- an extraneous file makes the removal fail before any file is removed
        local extraneous_filename = stored_dirname .. "/extraneous"
        filesystem.write_file("keep", extraneous_filename)
        local names = filesystem.list_directory(stored_dirname)
        expect.fail(function()
            cartesi.machine:remove_stored(stored_dirname)
        end, "is not one of its files")
        expect.equal(filesystem.list_directory(stored_dirname), names)
        expect.equal(filesystem.read_file(extraneous_filename), "keep")

        -- forcing the removal removes the extraneous file too
        cartesi.machine:remove_stored(stored_dirname, cartesi.REMOVE_FORCED)
        expect.falsy(filesystem.exists(stored_dirname))
    end)

    it("should create a machine fully mapped on disk", function()
        local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
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

    it("should map images shorter than their memory range followed by zeros", function()
        -- 64 KiB is a whole number of host pages for every supported host page size
        local _ <close>, aligned_filename = filesystem.write_scope_temp_file(string.rep("A", 0x10000))
        local _ <close>, unaligned_filename = filesystem.write_scope_temp_file(string.rep("B", 5000))
        local function new_machine(data_filename, read_only)
            return cartesi.machine({
                ram = { length = 0x1000 },
                flash_drive = {
                    { length = 0x20000, read_only = read_only, backing_store = { data_filename = data_filename } },
                },
            })
        end
        local function expect_drive(machine, data)
            local start = machine:get_initial_config().flash_drive[1].start
            expect.equal(machine:read_memory(start, 0x20000), data .. string.rep("\0", 0x20000 - #data))
        end
        do -- an image that ends on a page boundary leaves no partial page to clear, even when read-only
            local machine <close> = new_machine(aligned_filename, true)
            expect_drive(machine, string.rep("A", 0x10000))
        end
        do -- a writable mapping clears the partial page after an image that ends mid-page
            local machine <close> = new_machine(unaligned_filename, false)
            expect_drive(machine, string.rep("B", 5000))
        end
        -- a read-only mapping cannot clear that partial page
        expect.fail(function()
            local _ <close> = new_machine(unaligned_filename, true)
        end, "possible non zero partial page")
    end)

    it("should create a machine on disk as if storing it and loading it back", function()
        for _, sharing in ipairs({ cartesi.SHARING_NONE, cartesi.SHARING_CONFIG, cartesi.SHARING_ALL }) do
            local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
            local created_config
            do
                local machine <close> = cartesi.machine(base_machine_config, {}, stored_dirname, sharing)
                created_config = machine:get_initial_config()
            end
            local _ <close> = tests_util.scope_exit(function()
                cartesi.machine:remove_stored(stored_dirname)
            end)
            local machine <close> = cartesi.machine(stored_dirname, {}, sharing)
            expect.equal(created_config, machine:get_initial_config())
        end
    end)

    it("should modify the directory of a machine created on disk as its sharing mode allows", function()
        local config = tabular.deep_copy(base_machine_config)
        config.flash_drive[1].backing_store.shared = true
        local flash_start = config.flash_drive[1].start
        local ram_start = cartesi.AR_RAM_START
        for _, sharing in ipairs({ cartesi.SHARING_NONE, cartesi.SHARING_CONFIG, cartesi.SHARING_ALL }) do
            local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
            local flash_filename, ram_filename, ram_data
            do
                local machine <close> = cartesi.machine(config, {}, stored_dirname, sharing)
                local initial_config = machine:get_initial_config()
                flash_filename = initial_config.flash_drive[1].backing_store.data_filename
                ram_filename = initial_config.ram.backing_store.data_filename
                ram_data = filesystem.read_file(ram_filename)
                machine:write_memory(flash_start, string.rep("X", 0x2000))
                machine:write_memory(ram_start, string.rep("Y", 0x1000))
            end
            local _ <close> = tests_util.scope_exit(function()
                cartesi.machine:remove_stored(stored_dirname)
            end)
            expect.equal(filesystem.read_file(rw_data_filename), a_data)
            local flash_data = sharing == cartesi.SHARING_NONE and a_data or string.rep("X", 0x2000)
            expect.equal(filesystem.read_file(flash_filename), flash_data)
            expect.equal(filesystem.read_file(ram_filename) == ram_data, sharing ~= cartesi.SHARING_ALL)
        end
    end)

    it("should store the live state of a machine created on disk", function()
        local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
        local _ <close>, copied_dirname = tests_util.scope_temp_pathname()
        local expected_root_hash
        do
            local machine <close> = cartesi.machine(base_machine_config, {}, stored_dirname)
            machine:run()
            expected_root_hash = machine:get_root_hash()
            machine:store(copied_dirname, cartesi.SHARING_CONFIG)
        end
        local _ <close> = tests_util.scope_exit(function()
            cartesi.machine:remove_stored(stored_dirname)
            cartesi.machine:remove_stored(copied_dirname)
        end)
        local machine <close> = cartesi.machine(copied_dirname, {}, cartesi.SHARING_NONE)
        expect.equal(machine:get_root_hash(), expected_root_hash)
    end)

    it("should load a machine fully mapped on disk", function()
        local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
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
        local _ <close>, stored1_dirname = tests_util.scope_temp_pathname()
        local _ <close>, stored2_dirname = tests_util.scope_temp_pathname()
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
        local _ <close>, stored1_dirname = tests_util.scope_temp_pathname()
        local _ <close>, stored2_dirname = tests_util.scope_temp_pathname()
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

    it("should store a replaced memory range as its replacement", function()
        local flash_start = 0x0080000000000000
        local _ <close>, base_dirname = tests_util.scope_temp_pathname()
        local _ <close>, replacement_dirname = tests_util.scope_temp_pathname()
        local replacement_root_hash
        do
            local machine <close> = cartesi.machine(base_machine_config, {})
            machine:store(base_dirname)
            machine:write_memory(flash_start, string.rep("X", 0x2000))
            replacement_root_hash = machine:get_root_hash()
            machine:store(replacement_dirname)
        end
        local _ <close> = tests_util.scope_exit(function()
            cartesi.machine:remove_stored(base_dirname)
            cartesi.machine:remove_stored(replacement_dirname)
        end)
        local replacement_data_filename = replacement_dirname .. "/0080000000000000-2000.bin"
        for _, case in ipairs({
            { shared = false, sharing = cartesi.SHARING_NONE, current = false },
            { shared = false, sharing = cartesi.SHARING_CONFIG, current = false },
            { shared = false, sharing = cartesi.SHARING_ALL, current = true },
            { shared = true, sharing = cartesi.SHARING_CONFIG, current = true },
            { shared = true, sharing = cartesi.SHARING_ALL, current = true },
        }) do
            -- A shared replacement is written through, so it uses a copy of the replacement image.
            local _ <close>, data_filename =
                filesystem.write_scope_temp_file(filesystem.read_file(replacement_data_filename))
            local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
            local _ <close> = tests_util.scope_exit(function()
                cartesi.machine:remove_stored(stored_dirname)
            end)
            local current_root_hash
            do
                local machine <close> = cartesi.machine(base_dirname, {}, cartesi.SHARING_NONE)
                machine:replace_memory_range({
                    start = flash_start,
                    length = 0x2000,
                    backing_store = { data_filename = data_filename, shared = case.shared },
                })
                -- The initial configuration keeps the original backing store.
                local backing_store = machine:get_initial_config().flash_drive[1].backing_store
                expect.equal(backing_store.data_filename, base_dirname .. "/0080000000000000-2000.bin")
                machine:write_memory(flash_start + 0x1000, "Z")
                current_root_hash = machine:get_root_hash()
                machine:store(stored_dirname, case.sharing)
            end
            local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_NONE)
            -- Unshared ranges roll back to their backing stores, which is now the replacement.
            expect.equal(machine:read_memory(flash_start + 0x1000, 1), case.current and "Z" or "X")
            expect.equal(machine:get_root_hash(), case.current and current_root_hash or replacement_root_hash)
        end
    end)

    it("should replace memory ranges by label", function()
        local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
        do
            local machine <close> = cartesi.machine(base_machine_config, {})
            machine:store(stored_dirname)
        end
        local _ <close> = tests_util.scope_exit(function()
            cartesi.machine:remove_stored(stored_dirname)
        end)
        local machine <close> = cartesi.machine(stored_dirname, {}, cartesi.SHARING_NONE)
        local config = machine:get_initial_config()
        local root_hash = machine:get_root_hash()
        -- Flash drives and NVRAMs answer to their auto labels, and other ranges to fixed labels.
        for label, backing_store in pairs({
            flashdrive0 = config.flash_drive[1].backing_store,
            [".ram"] = config.ram.backing_store,
            [".cmio-rx-buffer"] = config.cmio.rx_buffer.backing_store,
        }) do
            local _ <close>, data_filename =
                filesystem.write_scope_temp_file(filesystem.read_file(backing_store.data_filename))
            machine:replace_memory_range({ label = label, backing_store = { data_filename = data_filename } })
            expect.equal(machine:get_root_hash(), root_hash)
        end
        expect.equal(machine:get_initial_config(), config)
        expect.fail(function()
            machine:replace_memory_range({ label = ".shadow-state", backing_store = {} })
        end, "attempted replace of protected memory range")
        expect.fail(function()
            machine:replace_memory_range({ label = ".pmas", backing_store = {} })
        end, "attempted replace of read-only memory range")
        expect.fail(function()
            machine:replace_memory_range({ label = "flashdrive1", backing_store = {} })
        end, "attempted replace of read-only memory range")
        expect.fail(function()
            machine:replace_memory_range({ label = ".nothing", backing_store = {} })
        end, 'no memory range with label ".nothing"')
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
                local _ <close>, directory = tests_util.scope_temp_pathname()
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
                filesystem.write_file(corruption[2](data), filename)
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
            local _ <close>, directory = tests_util.scope_temp_pathname()
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
                filesystem.write_file(length > #data and data .. "\0" or data:sub(1, length), filename)
                for _, sharing in ipairs({ cartesi.SHARING_NONE, cartesi.SHARING_ALL }) do
                    expect.fail(function()
                        local _ <close> = cartesi.machine(directory, {}, sharing)
                    end, "length")
                end
            end
        end)

        it("should validate unused metadata before entries are handed out", function()
            local _ <close>, directory = tests_util.scope_temp_pathname()
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
                filesystem.write_file(write_word(data, offset, -1), filename)
                expect.fail(function()
                    local _ <close> = cartesi.machine(directory)
                end, "corrupted page hash-tree cache")
            end
        end)

        local initialized_tag = 0x0250485443

        local function read_tag(directory)
            return (string.unpack("<I8", filesystem.read_file(directory .. "/hash_tree.phtc")))
        end

        it("should keep a stored cache uninitialized while it changes, until a store or destruction", function()
            local _ <close>, directory = tests_util.scope_temp_pathname()
            local _ <close>, stored_directory = tests_util.scope_temp_pathname()
            local _ <close> = tests_util.scope_exit(function()
                for _, dir in ipairs({ directory, stored_directory }) do
                    pcall(cartesi.machine.remove_stored, cartesi.machine, dir, cartesi.REMOVE_FORCED)
                end
            end)
            local machine <close> = cartesi.machine({
                ram = { length = 4096 },
                hash_tree = { phtc_size = capacity },
            }, {}, directory)
            machine:get_root_hash()
            expect.equal(read_tag(directory), 0)
            expect.fail(function()
                machine:sync_stored(directory)
            end, "flock() failed")
            expect.equal(read_tag(directory), 0)
            machine:store(stored_directory)
            expect.equal(read_tag(stored_directory), initialized_tag)
            machine:get_node_hash(cartesi.AR_RAM_START, cartesi.HASH_TREE_LOG2_WORD_SIZE)
            expect.equal(read_tag(directory), 0)
            machine:destroy()
            expect.equal(read_tag(directory), initialized_tag)
            machine:sync_stored(directory)
            expect.equal(read_tag(directory), initialized_tag)
        end)

        it("should rebuild a stored cache left uninitialized by an interrupted change", function()
            local _ <close>, directory = tests_util.scope_temp_pathname()
            do
                local machine <close> = cartesi.machine({
                    ram = { length = 4096 },
                    hash_tree = { phtc_size = capacity },
                }, {}, directory)
                machine:write_memory(cartesi.AR_RAM_START, string.rep("A", 4096))
                machine:get_node_hash(cartesi.AR_RAM_START, cartesi.HASH_TREE_LOG2_WORD_SIZE)
            end
            local _ <close> = tests_util.scope_exit(function()
                cartesi.machine:remove_stored(directory)
            end)
            -- A process stopped mid-change leaves the tag uninitialized and the rest of the cache in any state
            local filename = directory .. "/hash_tree.phtc"
            local data = filesystem.read_file(filename)
            data = write_word(write_word(data, 0, 0), entries_offset + 24, 1)
            data = data:sub(1, payloads_offset) .. string.rep("\255", #data - payloads_offset)
            filesystem.write_file(data, filename)
            for _, sharing in ipairs({ cartesi.SHARING_NONE, cartesi.SHARING_ALL }) do
                local machine <close> = cartesi.machine(directory, {}, sharing)
                expect.equal(machine:get_root_hash(), tests_util.calculate_emulator_hash(machine))
                expect.equal(
                    machine:get_node_hash(cartesi.AR_RAM_START, cartesi.HASH_TREE_LOG2_WORD_SIZE),
                    cartesi.keccak256(string.rep("A", 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE))
                )
            end
        end)

        it("should reuse stored entries without touching cached payloads", function()
            local _ <close>, directory = tests_util.scope_temp_pathname()
            local pages = { 0x80000000, 0x90000000, 0x90001000, 0xa0000000 }
            local contents = { "R", "A", "B", "C" }
            do
                local machine <close> = cartesi.machine({
                    ram = { length = 4096 },
                    flash_drive = {
                        { start = 0x90000000, length = 2 * 4096 },
                        { start = 0xa0000000, length = 4096 },
                    },
                    hash_tree = { phtc_size = capacity },
                }, {}, directory)
                for i, page in ipairs(pages) do
                    machine:write_memory(page, string.rep(contents[i], 4096))
                end
                machine:get_root_hash()
                for _, page in ipairs(pages) do
                    machine:get_node_hash(page, cartesi.HASH_TREE_LOG2_WORD_SIZE)
                end
            end
            local _ <close> = tests_util.scope_exit(function()
                cartesi.machine:remove_stored(directory)
            end)
            local filename = directory .. "/hash_tree.phtc"
            local payloads = filesystem.read_file(filename):sub(payloads_offset + 1)
            local word_size = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE
            for _, sharing in ipairs({ cartesi.SHARING_NONE, cartesi.SHARING_ALL }) do
                do
                    local _ <close> = cartesi.machine(directory, {}, sharing)
                end
                expect.equal(filesystem.read_file(filename):sub(payloads_offset + 1), payloads)
                -- Each stored entry must still describe the page its metadata names, so every query is a hit
                local machine <close> = cartesi.machine(directory, {}, sharing)
                machine:get_root_hash()
                for i, page in ipairs(pages) do
                    machine:get_hash_tree_stats(true)
                    machine:get_node_hash(page, cartesi.HASH_TREE_LOG2_PAGE_SIZE)
                    local baseline = machine:get_hash_tree_stats(true).phtc
                    local expected = cartesi.keccak256(string.rep(contents[i], word_size))
                    expect.equal(machine:get_node_hash(page, cartesi.HASH_TREE_LOG2_WORD_SIZE), expected)
                    local stats = machine:get_hash_tree_stats(true).phtc
                    expect.equal(stats.page_hits, baseline.page_hits + 1)
                    expect.equal(stats.page_misses, 0)
                end
            end
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

        -- Compares uarch cycle root hashes of the next mcycle with a reference that rebuilt its hash tree from memory
        local function expect_uarch_hashes(stored_dir, sharing)
            local reference <close> = cartesi.machine(stored_dir, { clear_hash_tree = true }, cartesi.SHARING_NONE)
            local machine <close> = cartesi.machine(stored_dir, {}, sharing)
            local revert_tail = { string.rep("\0", cartesi.HASH_SIZE), string.rep("\0", cartesi.HASH_SIZE) }
            local expected = reference:collect_uarch_cycle_root_hashes(1, 0, revert_tail)
            local obtained = machine:collect_uarch_cycle_root_hashes(1, 0, revert_tail)
            expect.equal(obtained.mcycle_hash_offsets, expected.mcycle_hash_offsets)
            expect.equal(#obtained.hashes, #expected.hashes)
            for i, hash in ipairs(expected.hashes) do
                expect.equal(obtained.hashes[i], hash)
            end
            expect.equal(machine:get_root_hash(), reference:get_root_hash())
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
                            local _ <close>, original_dir = tests_util.scope_temp_pathname()
                            local _ <close>, replacement_dir = tests_util.scope_temp_pathname()
                            local _ <close>, saved_dir = tests_util.scope_temp_pathname()
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
                    "should reuse loaded pages with different sharing ("
                        .. hash_function
                        .. ", shared="
                        .. tostring(shared)
                        .. ")",
                    function()
                        local _ <close>, stored_dir = tests_util.scope_temp_pathname()
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
                            expect.equal(stats.page_hits, baseline.page_hits + 1)
                            expect.equal(stats.page_misses, 0)
                            expect_word(machine, drive_start, "A", hash_function)
                            expect_word(machine, retained_start, "R", hash_function)
                            expect.equal(machine:get_root_hash(), tests_util.calculate_emulator_hash(machine))
                        end
                    end
                )
            end

            for _, shared in ipairs({ false, true }) do
                it(
                    "should not reuse pages left stale by a mixed sharing session ("
                        .. hash_function
                        .. ", shared="
                        .. tostring(shared)
                        .. ")",
                    function()
                        local _ <close>, stored_dir = tests_util.scope_temp_pathname()
                        do
                            local config = make_config(hash_function, 256)
                            config.hash_tree.shared = shared
                            config.flash_drive[1].backing_store = { shared = shared }
                            config.flash_drive[2].backing_store = { shared = not shared }
                            local machine <close> = cartesi.machine(config, {}, stored_dir)
                            initialize(machine, "A")
                            machine:write_reg("x10", retained_start)
                            machine:get_root_hash()
                            machine:get_node_hash(retained_start, cartesi.HASH_TREE_LOG2_WORD_SIZE)
                        end
                        local _ <close> = tests_util.scope_exit(function()
                            cartesi.machine:remove_stored(stored_dir)
                        end)
                        -- The retained drive and the hash tree are persisted differently, so the stored drive and
                        -- the stored cache disagree after this session while the drive pages remain clean
                        do
                            local machine <close> = cartesi.machine(stored_dir, {}, cartesi.SHARING_CONFIG)
                            machine:write_memory(retained_start, string.rep("S", page_size))
                            machine:get_root_hash()
                            machine:get_node_hash(retained_start, cartesi.HASH_TREE_LOG2_WORD_SIZE)
                        end
                        local retained = shared and "R" or "S"
                        if hash_function == "keccak256" then
                            expect_uarch_hashes(stored_dir, cartesi.SHARING_NONE)
                        end
                        for _, sharing in ipairs({ cartesi.SHARING_NONE, cartesi.SHARING_ALL }) do
                            local machine <close> = cartesi.machine(stored_dir, {}, sharing)
                            expect_word(machine, retained_start, retained, hash_function)
                            expect.equal(machine:get_root_hash(), tests_util.calculate_emulator_hash(machine))
                        end
                    end
                )
            end
        end

        it("should not reuse pages left stale by a range replacement on a shared cache", function()
            local _ <close>, original_dir = tests_util.scope_temp_pathname()
            local _ <close>, replacement_dir = tests_util.scope_temp_pathname()
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
            -- The replacement's pages enter the stored cache, but the stored drive keeps the original contents
            do
                local machine <close> = cartesi.machine(original_dir, {}, cartesi.SHARING_ALL)
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
                expect_word(machine, drive_start, "B", "keccak256")
                expect_word(machine, drive_start + page_size, "B", "keccak256")
            end
            expect_uarch_hashes(original_dir, cartesi.SHARING_NONE)
            local machine <close> = cartesi.machine(original_dir, {}, cartesi.SHARING_NONE)
            expect_word(machine, drive_start, "A", "keccak256")
            expect_word(machine, drive_start + page_size, "A", "keccak256")
            expect.equal(machine:get_root_hash(), tests_util.calculate_emulator_hash(machine))
        end)

        it("should collect correct uarch hashes after clean range replacement", function()
            local _ <close>, original_dir = tests_util.scope_temp_pathname()
            local _ <close>, replacement_dir = tests_util.scope_temp_pathname()
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

    describe("remove_stored", function()
        -- Stores a small machine and returns its parent owner, directory, and file names.
        local function store_machine()
            local owner, dir = tests_util.scope_temp_pathname()
            local machine <close> = cartesi.machine({ ram = { length = 0x1000 } })
            machine:store(dir)
            return owner, dir, filesystem.list_directory(dir)
        end

        it("should remove a stored machine in the default mode", function()
            local _ <close>, dir = store_machine()
            cartesi.machine:remove_stored(dir)
            expect.falsy(filesystem.exists(dir))
        end)

        it("should rename and remove stored machines named with trailing separators", function()
            local _ <close>, dir = store_machine()
            local _ <close>, renamed_dir = tests_util.scope_temp_pathname()
            cartesi.machine:rename_stored(dir .. "/", renamed_dir .. "/")
            expect.falsy(filesystem.exists(dir))
            do
                local _ <close> = cartesi.machine(renamed_dir)
            end
            cartesi.machine:remove_stored(renamed_dir .. "//")
            expect.falsy(filesystem.exists(renamed_dir))
        end)

        it("should refuse stored machine names ending in . or .. before changing anything", function()
            local _ <close>, dir, names = store_machine()
            local _ <close> = tests_util.scope_exit(function()
                cartesi.machine:remove_stored(dir)
            end)
            local _ <close>, other_dir = tests_util.scope_temp_pathname()
            for _, suffix in ipairs({ "/.", "/..", "/./", "/../" }) do
                expect.fail(function()
                    cartesi.machine:remove_stored(dir .. suffix)
                end, "directory name cannot end in")
                expect.fail(function()
                    cartesi.machine:rename_stored(dir .. suffix, other_dir)
                end, "directory name cannot end in")
            end
            expect.equal(filesystem.list_directory(dir), names)
            expect.falsy(filesystem.exists(other_dir))
            local _ <close> = cartesi.machine(dir)
        end)

        it("should complete an interrupted removal in the default mode", function()
            local _ <close>, dir, names = store_machine()
            -- The config is removed last, so an interrupted removal leaves it with some of the other files
            for i, name in ipairs(names) do
                if name ~= "config.json" and i % 2 == 0 then
                    filesystem.remove_file(dir .. "/" .. name)
                end
            end
            cartesi.machine:remove_stored(dir, cartesi.REMOVE_STORED)
            expect.falsy(filesystem.exists(dir))
        end)

        it("should remove an empty directory in the default mode", function()
            local _ <close>, dir = tests_util.scope_temp_pathname()
            filesystem.create_directory(dir)
            cartesi.machine:remove_stored(dir)
            expect.falsy(filesystem.exists(dir))
        end)

        it("should remove a directory without a loadable config only when forced", function()
            local _ <close>, stored_dir = store_machine()
            local _ <close>, unrelated_dir = tests_util.scope_temp_pathname()
            filesystem.create_directory(unrelated_dir)
            filesystem.write_file("data", unrelated_dir .. "/notes.txt")
            local _ <close> = tests_util.scope_exit(function()
                for _, dir in ipairs({ stored_dir, unrelated_dir }) do
                    pcall(cartesi.machine.remove_stored, cartesi.machine, dir, cartesi.REMOVE_FORCED)
                end
            end)
            -- An interrupted store leaves the stored files without a config
            filesystem.remove_file(stored_dir .. "/config.json")
            for _, dir in ipairs({ stored_dir, unrelated_dir }) do
                local names = filesystem.list_directory(dir)
                expect.fail(function()
                    cartesi.machine:remove_stored(dir)
                end, "config.json")
                expect.equal(filesystem.list_directory(dir), names)
                cartesi.machine:remove_stored(dir, cartesi.REMOVE_FORCED)
                expect.falsy(filesystem.exists(dir))
            end
        end)

        it("should refuse to remove a directory with entries that are not files", function()
            local _ <close>, dir = store_machine()
            filesystem.create_directory(dir .. "/subdirectory")
            local _ <close> = tests_util.scope_exit(function()
                filesystem.remove_directory(dir .. "/subdirectory")
                cartesi.machine:remove_stored(dir)
            end)
            local names = filesystem.list_directory(dir)
            for _, mode in ipairs({ cartesi.REMOVE_STORED, cartesi.REMOVE_FORCED }) do
                expect.fail(function()
                    cartesi.machine:remove_stored(dir, mode)
                end, "is not a file")
                expect.equal(filesystem.list_directory(dir), names)
            end
        end)

        it("should reject an unknown removal mode", function()
            local _ <close>, dir = store_machine()
            local _ <close> = tests_util.scope_exit(function()
                cartesi.machine:remove_stored(dir)
            end)
            expect.fail(function()
                cartesi.machine:remove_stored(dir, cartesi.REMOVE_FORCED + 1)
            end, "unknown remove mode")
            expect.truthy(filesystem.exists(dir .. "/config.json"))
        end)
    end)

    it("should rehash the ancestors of page hashes stored by an interrupted update", function()
        local ram_length = 0x10000
        local page = string.rep("B", 4096)
        local page_hash
        do
            local machine <close> = cartesi.machine({ ram = { length = ram_length } })
            machine:write_memory(cartesi.AR_RAM_START, page)
            page_hash = machine:get_node_hash(cartesi.AR_RAM_START, cartesi.HASH_TREE_LOG2_PAGE_SIZE)
        end
        local _ <close>, directory = tests_util.scope_temp_pathname()
        do
            local machine <close> = cartesi.machine({ ram = { length = ram_length } }, {}, directory)
            machine:get_root_hash()
            machine:write_memory(cartesi.AR_RAM_START, page)
        end
        local _ <close> = tests_util.scope_exit(function()
            cartesi.machine:remove_stored(directory)
        end)
        -- An update interrupted after storing the page hash in its leaf leaves the page dirty and its ancestors stale
        local filename = string.format("%s/%016x-%x.dht", directory, cartesi.AR_RAM_START, ram_length)
        local data = filesystem.read_file(filename)
        local leaf_offset = (ram_length // 4096) * #page_hash
        filesystem.write_file(data:sub(1, leaf_offset) .. page_hash .. data:sub(leaf_offset + #page_hash + 1), filename)
        for _, sharing in ipairs({ cartesi.SHARING_NONE, cartesi.SHARING_ALL }) do
            local machine <close> = cartesi.machine(directory, {}, sharing)
            expect.equal(machine:get_root_hash(), tests_util.calculate_emulator_hash(machine))
        end
    end)

    it("should rehash the stale ancestors of a range left by an interrupted update", function()
        local ram_log2_size = 18
        local _ <close>, directory = tests_util.scope_temp_pathname()
        do
            local machine <close> = cartesi.machine({ ram = { length = 1 << ram_log2_size } }, {}, directory)
            machine:get_root_hash()
            -- Leave a page dirty in the stored dirty-page tree, as an interrupted update would
            machine:write_memory(cartesi.AR_RAM_START, string.rep("R", 4096))
        end
        local _ <close> = tests_util.scope_exit(function()
            cartesi.machine:remove_stored(directory)
        end)
        -- An update interrupted after storing the RAM leaf leaves the inner nodes above it stale, and once left
        -- nodes marked as queued for update, freezing them. Each 64-byte node holds its left child, right child and
        -- parent indices (8 bytes each), its log2 size (4 bytes), 4 bytes that once held that mark, and its hash.
        local filename = directory .. "/hash_tree.sht"
        local data = filesystem.read_file(filename)
        local node_size = 64
        local nodes = {}
        for offset = 0, #data - node_size, node_size do
            nodes[#nodes + 1] = data:sub(offset + 1, offset + node_size)
        end
        local ram_leaf
        for index, node in ipairs(nodes) do
            local left, _, _, log2_size = string.unpack("<i8i8i8I4", node)
            if left == -1 and log2_size == ram_log2_size then
                expect.falsy(ram_leaf)
                ram_leaf = index
            end
        end
        expect.truthy(ram_leaf)
        local stale = {}
        local parent = string.unpack("<i8", nodes[ram_leaf], 17)
        while parent ~= 0 do
            stale[parent + 1] = true
            parent = string.unpack("<i8", nodes[parent + 1], 17)
        end
        for index, node in ipairs(nodes) do
            node = node:sub(1, 28) .. string.pack("<I4", 1) .. node:sub(33)
            if stale[index] then
                node = node:sub(1, 32) .. string.rep("\0", 32)
            end
            nodes[index] = node
        end
        filesystem.write_file(table.concat(nodes), filename)
        for _, sharing in ipairs({ cartesi.SHARING_NONE, cartesi.SHARING_ALL }) do
            local machine <close> = cartesi.machine(directory, {}, sharing)
            expect.equal(machine:get_root_hash(), tests_util.calculate_emulator_hash(machine))
        end
    end)

    it("should reject loading stores and clones whose config was not written", function()
        local _ <close>, stored_dir = tests_util.scope_temp_pathname()
        local _ <close>, cloned_dir = tests_util.scope_temp_pathname()
        do
            local machine <close> = cartesi.machine({ ram = { length = 0x1000 } })
            machine:get_root_hash()
            machine:store(stored_dir, cartesi.SHARING_ALL)
        end
        cartesi.machine:clone_stored(stored_dir, cloned_dir)
        local config = filesystem.read_file(stored_dir .. "/config.json")
        local _ <close> = tests_util.scope_exit(function()
            for _, dir in ipairs({ stored_dir, cloned_dir }) do
                filesystem.write_file(config, dir .. "/config.json")
                cartesi.machine:remove_stored(dir)
            end
        end)
        -- The config is written last, so an interrupted store or clone leaves it missing or still zero-filled
        for _, dir in ipairs({ stored_dir, cloned_dir }) do
            local filename = dir .. "/config.json"
            filesystem.remove_file(filename)
            expect.fail(function()
                local _ <close> = cartesi.machine(dir)
            end, "config.json")
            filesystem.write_file(string.rep("\0", #config), filename)
            expect.fail(function()
                local _ <close> = cartesi.machine(dir)
            end, "parse error")
        end
    end)

    it("should create a machine with new shared backing stores", function()
        local _ <close>, filename_prefix = tests_util.scope_temp_pathname()
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
                    local _ <close>, filename_prefix = tests_util.scope_temp_pathname()
                    local _ <close>, stored_dirname = tests_util.scope_temp_pathname()
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
                        filesystem.write_file("\0", backing_store.dht_filename)
                    elseif creation == "anonymous-dpt" or creation == "directory-dpt" then
                        backing_store.dpt_filename = ""
                    elseif creation == "shared-dpt" then
                        filesystem.remove_file(backing_store.dpt_filename)
                    elseif creation == "forced" or creation == "directory-forced" then
                        backing_store.mark_pages_dirty = true
                        drive_data = string.rep("B", #drive_data)
                        filesystem.write_file(drive_data, backing_store.data_filename)
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
