#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later
--
-- This program is free software: you can redistribute it and/or modify it under
-- the terms of the GNU Lesser General Public License as published by the Free
-- Software Foundation, either version 3 of the License, or (at your option) any
-- later version.
--
-- This program is distributed in the hope that it will be useful, but WITHOUT ANY
-- WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
-- PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
--
-- You should have received a copy of the GNU Lesser General Public License along
-- with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
--

local cartesi = require("cartesi")
local util = require("cartesi.util")

local function stderr_unsilenceable(fmt, ...) io.stderr:write(string.format(fmt, ...)) end
local stderr = stderr_unsilenceable

local function adjust_images_path(path)
    if not path then return "" end
    return string.gsub(path, "/*$", "") .. "/"
end

-- Print help and exit
local function help()
    stderr(
        [=[
Usage:

  %s [options] [command] [arguments]

where options are:
  --help
    display this information.

  --version
    display cartesi machine version information and exit.

  --version-json
    display cartesi machine semantic version and exit.

  --remote-address=<address>
    use a remote cartesi machine listening to <address> instead of
    running a local cartesi machine.

  --remote-shutdown
    shutdown the remote cartesi machine after the execution.

  --no-remote-create
    use existing cartesi machine in the remote server instead of creating a new one.

  --no-remote-destroy
    do not destroy the cartesi machine in the remote server after the execution.

  --ram-image=<filename>
    name of file containing RAM image (default: "linux.bin").

  --no-ram-image
    forget settings for RAM image.

  --ram-length=<number>
    set RAM length.

  --dtb-image=<filename>
    name of file containing DTB image (default: auto generated flattened device tree).

  --no-bootargs
    clear default bootargs.

  --append-bootargs=<string>
    append <string> to bootargs.

  --no-root-flash-drive
    clear default root flash drive and associated bootargs parameters.

  --flash-drive=<key>:<value>[,<key>:<value>[,...]...]
    defines a new flash drive, or modify an existing flash drive definition
    flash drives appear as /dev/pmem[0-7].

    <key>:<value> is one of
        label:<label>
        filename:<filename>
        start:<number>
        length:<number>
        shared
        mount:<string>
        user:<string>

        label (mandatory)
        identifies the flash drive. init attempts to mount it as /mnt/<label>.

        filename (optional)
        gives the name of the file containing the image for the flash drive.
        when omitted or set to the empty, the drive starts filled with 0.

        start (optional)
        sets the starting physical memory offset for flash drive in bytes.
        when omitted, drives start at 1 << 55 and are spaced by 1 << 52.
        if any start offset is set, all of them must be set.

        length (optional)
        gives the length of the flash drive in bytes (must be multiple of 4Ki).
        if omitted, the length is computed from the image in filename.
        if length and filename are set, the image file size must match length.

        shared (optional)
        target modifications to flash drive modify image file as well.
        by default, image files are not modified and changes are lost.

        mount (optional)
        whether the flash drive should be mounted automatically in init.
        by default, the drive is mounted if there is an image file backing it,
        you can use "mount:false" to disables auto mounting,
        you can also use "mount:<path>" to choose a custom mount point.

        user (optional)
        changes the user ownership of the mounted directory when mount is true,
        otherwise changes the user ownership of the respective /dev/pmemX device,
        this option is useful to allow dapp's user access the flash drive,
        by default the mounted directory ownership is configured by the filesystem being mounted,
        in case mount is false the default ownership is set to the root user.

    (an option "--flash-drive=label:root,filename:rootfs.ext2" is implicit)

  --replace-flash-drive=<key>:<value>[,<key>:<value>[,...]...]
  --replace-memory-range=<key>:<value>[,<key>:<value>[,...]...]
    replaces an existing flash drive or cmio memory range right after
    machine instantiation.
    (typically used in conjunction with the --load=<directory> option.)

    <key>:<value> is one of
        filename:<filename>
        start:<number>
        length:<number>
        shared

    semantics are the same as for the --flash-drive option with the following
    difference: start and length are mandatory, and must match those of a
    previously existing flash drive or cmio memory memory range.

  --cmio-rx-buffer=<key>:<value>[,<key>:<value>[,...]...]
  --cmio-tx-buffer=<key>:<value>[,<key>:<value>[,...]...]

    <key>:<value> is one of
        filename:<filename>
        start:<number>
        length:<number>
        shared

    semantics are the same as for the --flash-drive option with the following
    difference: start and length are mandatory.

  --no-cmio
    do not define values for cmio-rx-buffer, cmio-tx-buffer, and htif yield
    for use with cmios. default defined values are equivalent to the following
    options:

    --cmio-rx-buffer=start:0x60000000,length:2<<20
    --cmio-tx-buffer=start:0x60200000,length:2<<20

  --cmio-advance-state=<key>:<value>[,<key>:<value>[,...]...]
    advances the state of the machine through a number of inputs in an epoch

    <key>:<value> is one of
        epoch_index:<number>
        input:<filename-pattern>
        input_index_begin:<number>
        input_index_end:<number>
        output:<filename-pattern>
        report:<filename-pattern>
        outputs_root_hash:<filename-pattern>
        hashes

        epoch_index
        the index of the epoch (the value of %%e).

        input (default: "epoch-%%e-input-%%i.bin")
        the pattern that derives the name of the file read for input %%i
        of epoch index %%e.

        input_index_begin (default: 0)
        index of first input to advance (the first value of %%i).

        input_index_end (default: 0)
        one past index of last input to advance (one past last value of %%i).

        output (default: "epoch-%%e-input-%%i-output-%%o.bin")
        the pattern that derives the name of the file written for output %%o
        of input %%i of epoch %%e.

        report (default: "epoch-%%e-input-%%i-report-%%o.bin")
        the pattern that derives the name of the file written for report %%o
        of input %%i of epoch %%e.

        outputs_root_hash (default: "epoch-%%e-input-%%i-outputs-root-hash.bin")
        the pattern that derives the name of the file written for outputs root
        hash of input %%i of epoch %%e.

        hashes
        print out hashes before every input.

    the input index ranges in {input_index_begin, ..., input_index_end-1}.
    for each input, "%%e" is replaced by the epoch index, "%%i" by the
    input index, and "%%o" by the output or report index.

  --cmio-inspect-state=<key>:<value>[,<key>:<value>[,...]...]
    inspect the state of the machine with a query.
    the query happens after the end of --cmio-advance-state.

    <key>:<value> is one of
        query:<filename>
        report:<filename-pattern>

        query (default: "query.bin")
        the name of the file from which to read the query.

        report (default: "query-report-%%o.bin")
        the pattern that derives the name of the file written for report %%o
        of the query.

    while the query is processed, "%%o" is replaced by the current report index.

  --concurrency=<key>:<value>[,<key>:<value>[,...]...]
    configures the number of threads used in some implementation parts.

    <key>:<value> is one of
        update_merkle_tree:<number>

        update_merkle_tree (optional)
        defines the number of threads to use while calculating the merkle tree.
        when omitted or defined as 0, the number of hardware threads is used if
        it can be identified or else a single thread is used.

  --htif-no-console-putchar
    suppress any console output during machine run,
    this includes anything written to machine's stdout or stderr.

  --skip-root-hash-check
    skip merkle tree root hash check when loading a stored machine,
    assuming the stored machine files are not corrupt,
    this is only intended to speed up machine loading in emulator tests.

    DON'T USE THIS OPTION IN PRODUCTION

  --skip-version-check
    skip emulator version check when loading a stored machine,
    assuming the stored machine is compatible with current emulator version,
    this is only intended to test old snapshots during emulator development.

    DON'T USE THIS OPTION IN PRODUCTION

  --max-mcycle=<number>
    stop at a given mcycle (default: 2305843009213693952).

  --max-uarch-cycle=<number>
    stop at a given micro cycle.

  -i or --htif-console-getchar
    run in interactive mode.

  -it
    run in interactive mode like -i,
    but also sets terminal features and size in the guest to match with the host.
    This option will copy TERM, LANG, LC_ALL environment variables from the host to the guest,
    allowing the use of true colors and special characters when the host terminal supports.

  --no-htif-yield-manual
    do not honor yield requests with manual reset by target.

  --no-htif-yield-automatic
    do not honor yield requests with automatic reset by target.

  --store=<directory>
    store machine to <directory>, where "%%h" is substituted by the
    state hash in the directory name.

  --load=<directory>
    load machine previously stored in <directory>.

  --initial-hash
    print initial state hash before running machine.

  --final-hash
    print final state hash when done.

  --periodic-hashes=<number-period>[,<number-start>]
    prints root hash every <number-period> cycles. If <number-start> is given,
    the periodic hashing will start at that mcycle. This option implies
    --initial-hash and --final-hash.
    (default: none)

  --log-uarch-step
    advance one micro step and print access log.

  --log-uarch-reset
    reset the microarchitecture state and print the access log.

  --auto-uarch-reset
    reset uarch automatically after halt.

  --store-config[=<filename>]
    store initial machine config to <filename>. If <filename> is omitted,
    print the initial machine config to stderr.

  --load-config=<filename>
    load initial machine config from <filename>. If a field is omitted on
    machine_config table, it will fall back into the respective command-line
    argument or into the default value.

  --uarch-ram-image=<filename>
    name of file containing microarchitecture RAM image.

  --dump-memory-ranges
    dump all memory ranges to disk when done.

  --assert-rolling-template
    exit with failure in case the generated machine is not Rolling Cartesi Machine templates compatible.

  --quiet
    suppress cartesi-machine.lua output.
    exceptions: --initial-hash, --final-hash and text emitted from the target.

  --no-init-splash
    don't show cartesi machine splash on boot.

  --no-default-init
    don't use cartesi machine default init value (USER=dapp)

  --append-init=<string>
    append a command to machine's init script to be executed with root privilege.
    The command is executed on boot after mounting flash drives and before running the entrypoint.
    You can pass this option multiple times.

  --append-init-file=<filename>
    like --append-init, but use contents from a file.

  --append-entrypoint=<string>
    append a command to machine's entrypoint script to be executed with dapp privilege.
    The command is executed after the machine is initialized and before the final entrypoint command.
    You can pass this option multiple times.

  --append-entrypoint-file=<filename>
    like --append-entrypoint, but use contents from a file.

  --gdb[=<address>]
    listen at <address> and wait for a GDB connection to debug the machine.
    If <address> is omitted, '127.0.0.1:1234' is used by default.
    The host GDB client must have support for RISC-V architecture.

    host GDB can connect with the following command:
        gdb -ex "set arch riscv:rv64" -ex "target remote <address>" [elf]

        elf (optional)
        the binary elf file with symbols and debugging information to be debugged, such as:
        - vmlinux (for kernel debugging)
        - BBL elf (for debugging the BBL boot loader)
        - a test elf (for debugging tests)

    to perform cycle stepping in a debug session,
    use the command "stepc" after adding the following in your ~/.gdbinit file:
      source <emulator-path>/tools/gdb/gdbinit

and command and arguments:

  command
    the full path to the program inside the target system.
    (default: /bin/sh)

  arguments
    the given command arguments.

<number> can be specified in decimal (e.g., 16) or hexadeximal (e.g., 0x10),
with a suffix multiplier (i.e., Ki, Mi, Gi for 2^10, 2^20, 2^30, respectively),
or a left shift (e.g., 2 << 20).

<address> is one of the following formats:
  <host>:<port>
   unix:<path>

<host> can be a host name, IPv4 or IPv6 address.

]=],
        arg[0]
    )
    os.exit()
end

local remote
local remote_protocol = "jsonrpc"
local remote_address
local remote_shutdown = false
local remote_create = true
local remote_destroy = true
local images_path = adjust_images_path(os.getenv("CARTESI_IMAGES_PATH"))
local flash_image_filename = { root = images_path .. "rootfs.ext2" }
local flash_label_order = { "root" }
local flash_shared = {}
local flash_mount = {}
local flash_user = {}
local flash_start = {}
local flash_length = {}
local memory_range_replace = {}
local ram_image_filename = images_path .. "linux.bin"
local ram_length = 64 << 20
local dtb_image_filename = nil
local bootargs = "quiet earlycon=sbi console=hvc0 rootfstype=ext2 root=/dev/pmem0 rw init=/usr/sbin/cartesi-init"
local init_splash = true
local append_bootargs = ""
local default_init = "USER=dapp\n"
local append_init = ""
local append_entrypoint = ""
local cmio = {
    rx_buffer = { start = 0x60000000, length = 2 << 20 },
    tx_buffer = { start = 0x60200000, length = 2 << 20 },
}
local uarch
local cmio_advance
local cmio_inspect
local concurrency_update_merkle_tree = 0
local skip_root_hash_check = false
local skip_version_check = false
local htif_no_console_putchar = false
local htif_console_getchar = false
local htif_yield_automatic = true
local htif_yield_manual = true
local initial_hash = false
local final_hash = false
local initial_proof = {}
local final_proof = {}
local periodic_hashes_period = math.maxinteger
local periodic_hashes_start = 0
local dump_memory_ranges = false
local max_mcycle = math.maxinteger
local max_uarch_cycle = 0
local log_uarch_step = false
local auto_uarch_reset = false
local log_uarch_reset = false
local store_dir
local load_dir
local cmdline_opts_finished = false
local store_config = false
local load_config = false
local gdb_address
local exec_arguments = {}
local assert_rolling_template = false

local function parse_memory_range(opts, what, all)
    local f = util.parse_options(opts, {
        filename = true,
        shared = true,
        length = true,
        start = true,
    })
    f.image_filename = f.filename
    f.filename = nil
    if f.image_filename == true then f.image_filename = "" end
    assert(not f.shared or f.shared == true, "invalid " .. what .. " shared value in " .. all)
    f.start = assert(util.parse_number(f.start), "invalid " .. what .. " start in " .. all)
    f.length = assert(util.parse_number(f.length), "invalid " .. what .. " length in " .. all)
    return f
end

-- List of supported options
-- Options are processed in order
-- For each option,
--   first entry is the pattern to match
--   second entry is a callback
--     if callback returns true, the option is accepted.
--     if callback returns false, the option is rejected.
local options = {
    {
        "^%-h$",
        function(all)
            if not all then return false end
            help()
            return true
        end,
    },
    {
        "^%-%-help$",
        function(all)
            if not all then return false end
            help()
            return true
        end,
    },
    {
        "^%-%-version$",
        function(all)
            if not all then return false end
            print(string.format("cartesi-machine %s", cartesi.VERSION))
            if cartesi.GIT_COMMIT then print(string.format("git commit: %s", cartesi.GIT_COMMIT)) end
            if cartesi.BUILD_TIME then print(string.format("build time: %s", cartesi.BUILD_TIME)) end
            print(string.format("platform: %s", cartesi.PLATFORM))
            print(string.format("compiler: %s", cartesi.COMPILER))
            print("Copyright Cartesi and individual authors.")
            os.exit()
            return true
        end,
    },
    {
        "^%-%-version%-json$",
        function(all)
            if not all then return false end
            print("{")
            print(string.format('  "version": "%s",', cartesi.VERSION))
            print(string.format('  "version_major": %d,', cartesi.VERSION_MAJOR))
            print(string.format('  "version_minor": %d,', cartesi.VERSION_MINOR))
            print(string.format('  "version_patch": %d,', cartesi.VERSION_PATCH))
            print(string.format('  "version_label": "%s",', cartesi.VERSION_LABEL))
            print(string.format('  "marchid": %d,', cartesi.MARCHID))
            print(string.format('  "mimpid": %d,', cartesi.MIMPID))
            -- the following works only when luaposix is available in the system
            local ok, stdlib = pcall(require, "posix.stdlib")
            if ok and stdlib then
                -- use realpath to get images real filenames,
                -- tools could use this information to detect linux/rootfs versions
                local ram_image = stdlib.realpath(images_path .. "linux.bin")
                local rootfs_image = stdlib.realpath(images_path .. "rootfs.ext2")
                if ram_image then print(string.format('  "default_ram_image": "%s",', ram_image)) end
                if rootfs_image then print(string.format('  "default_rootfs_image": "%s",', rootfs_image)) end
            end
            if cartesi.GIT_COMMIT then print(string.format('  "git_commit": "%s",', cartesi.GIT_COMMIT)) end
            if cartesi.BUILD_TIME then print(string.format('  "build_time": "%s",', cartesi.BUILD_TIME)) end
            print(string.format('  "compiler": "%s",', cartesi.COMPILER))
            print(string.format('  "platform": "%s"', cartesi.PLATFORM))
            print("}")
            os.exit()
            return true
        end,
    },
    {
        "^%-%-dtb%-image%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            dtb_image_filename = o
            return true
        end,
    },
    {
        "^%-%-no%-bootargs$",
        function(all)
            if not all then return false end
            bootargs = ""
            return true
        end,
    },
    {
        "^%-%-append%-bootargs%=(.*)$",
        function(o)
            if not o then return false end
            if #o == 0 then return true end
            if #append_bootargs == 0 then
                append_bootargs = o
            else
                append_bootargs = append_bootargs .. " " .. o
            end
            return true
        end,
    },
    {
        "^%-%-ram%-length%=(.+)$",
        function(n)
            if not n then return false end
            ram_length = assert(util.parse_number(n), "invalid RAM length " .. n)
            return true
        end,
    },
    {
        "^%-%-ram%-image%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            ram_image_filename = o
            return true
        end,
    },
    {
        "^%-%-no%-ram%-image$",
        function(all)
            if not all then return false end
            ram_image_filename = ""
            return true
        end,
    },
    {
        "^%-%-uarch%-ram%-image%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            uarch = uarch or {}
            uarch.ram = uarch.ram or {}
            uarch.ram.image_filename = o
            return true
        end,
    },
    {
        "^%-%-htif%-console%-getchar$",
        function(all)
            if not all then return false end
            htif_console_getchar = true
            return true
        end,
    },
    {
        "^%-i$",
        function(all)
            if not all then return false end
            htif_console_getchar = true
            return true
        end,
    },
    {
        "^%-it$",
        function(all)
            if not all then return false end
            htif_console_getchar = true
            local term, lang, lc_all = os.getenv("TERM"), os.getenv("LANG"), os.getenv("LC_ALL")
            if term then append_init = append_init .. "export TERM=" .. term .. "\n" end
            if lang then append_init = append_init .. "export LANG=" .. lang .. "\n" end
            if lc_all then append_init = append_init .. "export LC_ALL=" .. lc_all .. "\n" end
            local stty <close> = assert(io.popen("stty size"))
            local line = assert(stty:read(), "command failed: stty size")
            if line then
                local rows, cols = line:match("^([0-9]+) ([0-9]+)$")
                if rows and cols then
                    append_init = append_init .. "busybox stty rows " .. rows .. " cols " .. cols .. "\n"
                end
            end
            return true
        end,
    },
    {
        "^%-%-no%-htif%-yield%-manual$",
        function(all)
            if not all then return false end
            htif_yield_manual = false
            return true
        end,
    },
    {
        "^%-%-no%-htif%-yield%-automatic$",
        function(all)
            if not all then return false end
            htif_yield_automatic = false
            return true
        end,
    },
    {
        "^%-%-no%-cmio$",
        function(all)
            if not all then return false end
            cmio = nil
            return true
        end,
    },
    {
        "^(%-%-flash%-drive%=(.+))$",
        function(all, opts)
            if not opts then return false end
            local f = util.parse_options(opts, {
                label = true,
                filename = true,
                shared = true,
                mount = true,
                user = true,
                length = true,
                start = true,
            })
            assert(f.label, "missing flash drive label in " .. all)
            f.image_filename = f.filename
            f.filename = nil
            if f.image_filename == true then f.image_filename = "" end
            assert(not f.shared or f.shared == true, "invalid flash drive shared value in " .. all)
            if f.mount == nil then
                -- mount only if there is a file backing
                if f.image_filename and f.image_filename ~= "" then
                    f.mount = "/mnt/" .. f.label
                else
                    f.mount = false
                end
            elseif f.mount == "true" then
                f.mount = "/mnt/" .. f.label
            elseif f.mount == "false" then
                f.mount = false
            end
            if f.start then f.start = assert(util.parse_number(f.start), "invalid flash drive start in " .. all) end
            if f.length then f.length = assert(util.parse_number(f.length), "invalid flash drive length in " .. all) end
            local d = f.label
            if not flash_image_filename[d] then
                flash_label_order[#flash_label_order + 1] = d
                flash_image_filename[d] = ""
            end
            flash_image_filename[d] = f.image_filename or flash_image_filename[d]
            flash_start[d] = f.start or flash_start[d]
            flash_length[d] = f.length or flash_length[d]
            flash_shared[d] = f.shared or flash_shared[d]
            flash_mount[d] = f.mount or flash_mount[d]
            flash_user[d] = f.user or flash_user[d]
            return true
        end,
    },
    {
        "^(%-%-replace%-flash%-drive%=(.+))$",
        function(all, opts)
            if not opts then return false end
            memory_range_replace[#memory_range_replace + 1] = parse_memory_range(opts, "flash drive", all)
            return true
        end,
    },
    {
        "^(%-%-replace%-memory%-range%=(.+))$",
        function(all, opts)
            if not opts then return false end
            memory_range_replace[#memory_range_replace + 1] = parse_memory_range(opts, "flash drive", all)
            return true
        end,
    },
    {
        "^(%-%-cmio%-advance%-state%=(.+))$",
        function(all, opts)
            if not opts then return false end
            local r = util.parse_options(opts, {
                epoch_index = true,
                input = true,
                input_index_begin = true,
                input_index_end = true,
                outputs_root_hash = true,
                output = true,
                report = true,
                hashes = true,
            })
            assert(not r.hashes or r.hashes == true, "invalid hashes value in " .. all)
            r.epoch_index = assert(util.parse_number(r.epoch_index), "invalid epoch index in " .. all)
            r.input = r.input or "epoch-%e-input-%i.bin"
            r.input_index_begin = r.input_index_begin or 0
            r.input_index_begin = assert(util.parse_number(r.input_index_begin), "invalid input index begin in " .. all)
            r.input_index_end = r.input_index_end or 0
            r.input_index_end = assert(util.parse_number(r.input_index_end), "invalid input index end in " .. all)
            r.output = r.output or "epoch-%e-input-%i-output-%o.bin"
            r.report = r.report or "epoch-%e-input-%i-report-%o.bin"
            r.outputs_root_hash = r.outputs_root_hash or "epoch-%e-input-%i-outputs_root_hash.bin"
            r.next_input_index = r.input_index_begin
            cmio_advance = r
            return true
        end,
    },
    {
        "^(%-%-cmio%-inspect%-state%=(.+))$",
        function(_, opts)
            if not opts then return false end
            local r = util.parse_options(opts, {
                query = true,
                report = true,
            })
            r.query = r.query or "query.bin"
            r.report = r.report or "query-report-%o.bin"
            cmio_inspect = r
            return true
        end,
    },
    {
        "^%-%-cmio%-inspect%-state$",
        function(all)
            if not all then return false end
            cmio_inspect = {
                query = "query.bin",
                report = "query-report-%o.bin",
            }
            return true
        end,
    },
    {
        "^(%-%-concurrency%=(.+))$",
        function(all, opts)
            if not opts then return false end
            local c = util.parse_options(opts, {
                update_merkle_tree = true,
            })
            c.update_merkle_tree =
                assert(util.parse_number(c.update_merkle_tree), "invalid update_merkle_tree number in " .. all)
            concurrency_update_merkle_tree = c.update_merkle_tree
            return true
        end,
    },
    {
        "^%-%-htif%-no%-console%-putchar$",
        function(all)
            if not all then return false end
            htif_no_console_putchar = true
            return true
        end,
    },
    {
        "^%-%-skip%-root%-hash%-check$",
        function(all)
            if not all then return false end
            skip_root_hash_check = true
            return true
        end,
    },
    {
        "^%-%-skip%-version%-check$",
        function(all)
            if not all then return false end
            skip_version_check = true
            return true
        end,
    },
    {
        "^(%-%-initial%-proof%=(.+))$",
        function(all, opts)
            if not opts then return false end
            local p = util.parse_options(opts, {
                address = true,
                log2_size = true,
                filename = true,
            })
            p.cmdline = all
            p.address = assert(util.parse_number(p.address), "invalid address in " .. all)
            p.log2_size = assert(util.parse_number(p.log2_size), "invalid log2_size in " .. all)
            assert(p.log2_size >= 3, "log2_size must be at least 3 in " .. all)
            initial_proof[#initial_proof + 1] = p
            return true
        end,
    },
    {
        "^(%-%-final%-proof%=(.+))$",
        function(all, opts)
            if not opts then return false end
            local p = util.parse_options(opts, {
                address = true,
                log2_size = true,
                filename = true,
            })
            p.cmdline = all
            p.address = assert(util.parse_number(p.address), "invalid address in " .. all)
            p.log2_size = assert(util.parse_number(p.log2_size), "invalid log2_size in " .. all)
            assert(p.log2_size >= 3, "log2_size must be at least 3 in " .. all)
            final_proof[#final_proof + 1] = p
            return true
        end,
    },
    {
        "^%-%-no%-root%-flash%-drive$",
        function(all)
            if not all then return false end
            assert(flash_image_filename.root and flash_label_order[1] == "root", "no root flash drive to remove")
            flash_image_filename.root = nil
            flash_start.root = nil
            flash_length.root = nil
            flash_shared.root = nil
            table.remove(flash_label_order, 1)
            bootargs = "quiet earlycon=sbi console=hvc0"
            return true
        end,
    },
    {
        "^%-%-dump%-memory%-ranges$",
        function(all)
            if not all then return false end
            dump_memory_ranges = true
            return true
        end,
    },
    {
        "%-%-assert%-rolling%-template",
        function(all)
            if not all then return false end
            assert_rolling_template = true
            return true
        end,
    },
    {
        "%-%-quiet",
        function(all)
            if not all then return false end
            stderr = function() end
            return true
        end,
    },
    {
        "^%-%-log%-uarch%-step$",
        function(all)
            if not all then return false end
            log_uarch_step = true
            return true
        end,
    },
    {
        "^%-%-log%-uarch%-reset$",
        function(all)
            if not all then return false end
            log_uarch_reset = true
            return true
        end,
    },
    {
        "^(%-%-max%-mcycle%=(.*))$",
        function(all, n)
            if not n then return false end
            max_mcycle = assert(util.parse_number(n), "invalid option " .. all)
            return true
        end,
    },
    {
        "^(%-%-max%-uarch%-cycle%=(.*))$",
        function(all, n)
            if not n then return false end
            max_uarch_cycle = assert(util.parse_number(n), "invalid option " .. all)
            return true
        end,
    },
    {
        "^%-%-auto%-uarch%-reset$",
        function(all)
            if not all then return false end
            auto_uarch_reset = true
            return true
        end,
    },
    {
        "^%-%-load%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            load_dir = o
            return true
        end,
    },
    {
        "^%-%-store%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            store_dir = o
            return true
        end,
    },
    {
        "^%-%-remote%-address%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            remote_address = o
            return true
        end,
    },
    {
        "^%-%-remote%-shutdown$",
        function(o)
            if not o then return false end
            remote_shutdown = true
            return true
        end,
    },
    {
        "^%-%-no%-remote%-create$",
        function(o)
            if not o then return false end
            remote_create = false
            return true
        end,
    },
    {
        "^%-%-no%-remote%-destroy$",
        function(o)
            if not o then return false end
            remote_destroy = false
            return true
        end,
    },
    {
        "^%-%-initial%-hash$",
        function(all)
            if not all then return false end
            initial_hash = true
            return true
        end,
    },
    {
        "^%-%-final%-hash$",
        function(all)
            if not all then return false end
            final_hash = true
            return true
        end,
    },
    {
        "^(%-%-periodic%-hashes%=(.*))$",
        function(all, v)
            if not v then return false end
            string.gsub(v, "^([^%,]+),(.+)$", function(p, s)
                periodic_hashes_period = assert(util.parse_number(p), "invalid period " .. all)
                periodic_hashes_start = assert(util.parse_number(s), "invalid start " .. all)
            end)
            if periodic_hashes_period == math.maxinteger then
                periodic_hashes_period = assert(util.parse_number(v), "invalid period " .. all)
                periodic_hashes_start = 0
            end
            initial_hash = true
            final_hash = true
            return true
        end,
    },
    {
        "^%-%-store%-config(%=?)(%g*)$",
        function(o, v)
            if not o then return false end
            if o == "=" then
                if not v or #v < 1 then return false end
                store_config = v
            else
                store_config = stderr
            end
            return true
        end,
    },
    {
        "^%-%-load%-config%=(%g*)$",
        function(o)
            if not o or #o < 1 then return false end
            load_config = o
            return true
        end,
    },
    {
        "^(%-%-cmio%-rx%-buffer%=(.+))$",
        function(all, opts)
            if not opts then return false end
            cmio = cmio or {}
            cmio.rx_buffer = parse_memory_range(opts, "cmio rx buffer", all)
            return true
        end,
    },
    {
        "^(%-%-cmio%-tx%-buffer%=(.+))$",
        function(all, opts)
            if not opts then return false end
            cmio = cmio or {}
            cmio.tx_buffer = parse_memory_range(opts, "tx buffer", all)
            return true
        end,
    },
    {
        "^%-%-no%-init%-splash$",
        function(all)
            if not all then return false end
            init_splash = false
            return true
        end,
    },
    {
        "^%-%-no%-default%-init$",
        function(all)
            if not all then return false end
            default_init = ""
            return true
        end,
    },
    {
        "^%-%-append%-init%=(.*)$",
        function(o)
            if not o then return false end
            if #o == 0 then return true end
            append_init = append_init .. o .. "\n"
            return true
        end,
    },
    {
        "^%-%-append%-init%-file%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            local f <close> = assert(io.open(o, "rb"))
            local contents = assert(f:read("*a"))
            if not contents:find("\n$") then contents = contents .. "\n" end
            append_init = append_init .. contents
            return true
        end,
    },
    {
        "^%-%-append%-entrypoint%=(.*)$",
        function(o)
            if not o then return false end
            if #o == 0 then return true end
            append_entrypoint = append_entrypoint .. o .. "\n"
            return true
        end,
    },
    {
        "^%-%-append%-entrypoint%-file%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            local f <close> = assert(io.open(o, "rb"))
            local contents = assert(f:read("*a"))
            if not contents:find("\n$") then contents = contents .. "\n" end
            append_entrypoint = append_entrypoint .. contents
            return true
        end,
    },
    {
        "^%-%-gdb(%=?)(.*)$",
        function(o, address)
            if o == "=" and #o > 0 then
                gdb_address = address
                return true
            elseif o == "" then
                gdb_address = "127.0.0.1:1234"
                return true
            end
            return false
        end,
    },
    {
        ".*",
        function(all)
            if not all then return false end
            local not_option = all:sub(1, 1) ~= "-"
            if not_option or all == "--" then
                cmdline_opts_finished = true
                if not_option then exec_arguments = { all } end
                return true
            end
            error("unrecognized option " .. all)
        end,
    },
}

-- Process command line options
for _, a in ipairs(arg) do
    if not cmdline_opts_finished then
        for _, option in ipairs(options) do
            if option[2](a:match(option[1])) then break end
        end
    else
        exec_arguments[#exec_arguments + 1] = a
    end
end

local function print_root_hash(machine, print)
    (print or stderr)("%u: %s\n", machine:read_mcycle(), util.hexhash(machine:get_root_hash()))
end

local function store_memory_range(r, indent, output)
    local function comment_default(u, v) output(u == v and " -- default\n" or "\n") end
    output("{\n")
    output("%s  start = 0x%x,", indent, r.start)
    comment_default(0, r.start)
    output("%s  length = 0x%x,", indent, r.length)
    comment_default(0, r.length)
    if r.image_filename and r.image_filename ~= "" then
        output("%s  image_filename = %q,\n", indent, r.image_filename)
    end
    output("%s  shared = %s,", indent, tostring(r.shared or false))
    comment_default(false, r.shared)
    output("%s},\n", indent)
end

local function store_machine_config(config, output)
    local function comment_default(u, v) output(u == v and " -- default\n" or "\n") end

    local def
    if remote then
        def = remote.machine.get_default_config()
    else
        def = cartesi.machine.get_default_config()
    end
    output("return {\n")
    output("  processor = {\n")
    output("    x = {\n")
    local processor = config.processor or { x = {} }
    for i = 1, 31 do
        local xi = processor.x[i] or def.processor.x[i]
        output("      0x%x,", xi)
        comment_default(xi, def.processor.x[i])
    end
    output("    },\n")
    output("    f = {\n")
    for i = 0, 31 do
        local xi = processor.f[i] or def.processor.f[i]
        if i == 0 then
            output("      [0] = 0x%x,", xi)
        else
            output("      0x%x,", xi)
        end
        comment_default(xi, def.processor.f[i])
    end
    output("    },\n")
    local order = {}
    for i, v in pairs(def.processor) do
        if type(v) == "number" then order[#order + 1] = i end
    end
    table.sort(order)
    for _, csr in ipairs(order) do
        local c = processor[csr] or def.processor[csr]
        output("    %s = 0x%x,", csr, c)
        comment_default(c, def.processor[csr])
    end
    output("  },\n")
    local ram = config.ram or {}
    output("  ram = {\n")
    output("    length = 0x%x,", ram.length or def.ram.length)
    comment_default(ram.length, def.ram.length)
    output("    image_filename = %q,", ram.image_filename or def.ram.image_filename)
    comment_default(ram.image_filename, def.ram.image_filename)
    output("  },\n")
    local dtb = config.dtb or {}
    output("  dtb = {\n")
    output("    image_filename = %q,", dtb.image_filename or def.dtb.image_filename)
    comment_default(dtb.image_filename, def.dtb.image_filename)
    output("    bootargs = %q,", dtb.bootargs or def.dtb.bootargs)
    comment_default(dtb.bootargs, def.dtb.bootargs)
    output("    init = %q,", dtb.init or def.dtb.init)
    comment_default(dtb.init, def.dtb.init)
    output("    entrypoint = %q,", dtb.entrypoint or def.dtb.entrypoint)
    comment_default(dtb.entrypoint, def.dtb.entrypoint)
    output("  },\n")
    local tlb = config.tlb or {}
    output("  tlb = {\n")
    output("    image_filename = %q,", tlb.image_filename or def.tlb.image_filename)
    comment_default(tlb.image_filename, def.tlb.image_filename)
    output("  },\n")
    local htif = config.htif or {}
    output("  htif = {\n")
    output("    tohost = 0x%x,", htif.tohost or def.htif.tohost)
    comment_default(htif.tohost, def.htif.tohost)
    output("    fromhost = 0x%x,", htif.fromhost or def.htif.fromhost)
    comment_default(htif.fromhost, def.htif.fromhost)
    output("    console_getchar = %s,", tostring(htif.console_getchar or false))
    comment_default(htif.console_getchar or false, def.htif.console_getchar)
    output("    yield_automatic = %s,", tostring(htif.yield_automatic or false))
    comment_default(htif.yield_automatic or false, def.htif.yield_automatic)
    output("    yield_manual = %s,", tostring(htif.yield_manual or false))
    comment_default(htif.yield_manual or false, def.htif.yield_manual)
    output("  },\n")
    local clint = config.clint or {}
    output("  clint = {\n")
    output("    mtimecmp = 0x%x,", clint.mtimecmp or def.clint.mtimecmp)
    comment_default(clint.mtimecmp, def.clint.mtimecmp)
    output("  },\n")
    output("  flash_drive = {\n")
    for _, f in ipairs(config.flash_drive) do
        output("    ")
        store_memory_range(f, "    ", output)
    end
    output("  },\n")
    if config.cmio then
        output("  cmio = {\n")
        output("    rx_buffer = ")
        store_memory_range(config.cmio.rx_buffer, "    ", output)
        output("    tx_buffer = ")
        store_memory_range(config.cmio.tx_buffer, "    ", output)
        output("  },\n")
    end
    output("  uarch = {\n")
    output("    ram = {\n")
    output("      image_filename = %q,", config.uarch.ram.image_filename or def.uarch.ram.image_filename)
    comment_default(config.uarch.ram.image_filename, def.uarch.ram.image_filename)
    output("    },\n")
    output("    processor = {\n")
    output("      x = {\n")
    for i = 1, 31 do
        local xi = config.uarch.processor.x[i] or def.uarch.processor.x[i]
        output("        0x%x,", xi)
        comment_default(xi, def.uarch.processor.x[i])
    end
    output("      },\n")
    output("      pc = 0x%x,", config.uarch.processor.pc or def.uarch.processor.pc)
    comment_default(config.uarch.processor.pc, def.uarch.processor.pc)
    output("      cycle = 0x%x", config.uarch.processor.cycle or def.uarch.processor.cycle)
    comment_default(config.uarch.processor.cycle, def.uarch.processor.cycle)
    output("    },\n")
    output("  }\n")
    output("}\n")
end

local function resolve_flash_starts(label_order, start)
    local auto_start = 1 << 55
    if next(start) == nil then
        for _, label in ipairs(label_order) do
            start[label] = auto_start
            auto_start = auto_start + (1 << 52)
        end
    else
        local missing = {}
        local found = {}
        for _, label in ipairs(label_order) do
            local quoted = string.format("'%s'", label)
            if start[label] then
                found[#found + 1] = quoted
            else
                missing[#missing + 1] = quoted
            end
        end
        if #missing > 0 then
            error(
                string.format(
                    "flash drive start set for %s but missing for %s",
                    table.concat(found, ", "),
                    table.concat(missing, ", ")
                )
            )
        end
    end
end

local function dump_value_proofs(machine, desired_proofs, has_htif_console_getchar)
    if #desired_proofs > 0 then assert(not has_htif_console_getchar, "proofs are meaningless in interactive mode") end
    for _, desired in ipairs(desired_proofs) do
        local proof = machine:get_proof(desired.address, desired.log2_size)
        local out = desired.filename and assert(io.open(desired.filename, "wb")) or io.stdout
        out:write("{\n")
        util.dump_json_proof(proof, out, 1)
        out:write("}\n")
    end
end

local function create_machine(config_or_dir, runtime)
    if remote then return remote.machine(config_or_dir, runtime) end
    return cartesi.machine(config_or_dir, runtime)
end

local remote_shutdown_deleter = {}
if remote_address then
    stderr("Connecting to %s remote cartesi machine at '%s'\n", remote_protocol, remote_address)
    local protocol = require("cartesi." .. remote_protocol)
    remote = assert(protocol.stub(remote_address))
    local v = assert(remote.get_version())
    stderr("Connected: remote version is %d.%d.%d\n", v.major, v.minor, v.patch)
    local shutdown = function() remote.shutdown() end
    if remote_shutdown then
        setmetatable(remote_shutdown_deleter, {
            __gc = function()
                stderr("Shutting down remote cartesi machine\n")
                pcall(shutdown)
            end,
        })
    end
end

local runtime = {
    concurrency = {
        update_merkle_tree = concurrency_update_merkle_tree,
    },
    htif = {
        no_console_putchar = htif_no_console_putchar,
    },
    skip_root_hash_check = skip_root_hash_check,
    skip_version_check = skip_version_check,
}

local main_machine
if remote and not remote_create then
    main_machine = remote.get_machine()
elseif load_dir then
    stderr("Loading machine: please wait\n")
    main_machine = create_machine(load_dir, runtime)
else
    -- Resolve all device starts and lengths
    resolve_flash_starts(flash_label_order, flash_start)

    -- Build machine config
    local config = {
        processor = {
            -- Request automatic default values for versioning CSRs
            mimpid = -1,
            marchid = -1,
            mvendorid = -1,
        },
        dtb = {
            image_filename = dtb_image_filename,
            bootargs = bootargs,
            init = "",
            entrypoint = "",
        },
        ram = {
            image_filename = ram_image_filename,
            length = ram_length,
        },
        htif = {
            console_getchar = htif_console_getchar,
            yield_automatic = htif_yield_automatic,
            yield_manual = htif_yield_manual,
        },
        cmio = cmio,
        uarch = uarch,
        flash_drive = {},
    }

    -- show splash on init
    if init_splash then
        config.dtb.init = config.dtb.init
            .. ([[
echo "
         .
        / \
      /    \
\---/---\  /----\
 \       X       \
  \----/  \---/---\
       \    / CARTESI
        \ /   MACHINE
         '
"
]]):gsub("\\", "\\\\")
    end

    for _, label in ipairs(flash_label_order) do
        local devname = "pmem" .. #config.flash_drive
        config.flash_drive[#config.flash_drive + 1] = {
            image_filename = flash_image_filename[label],
            shared = flash_shared[label],
            start = flash_start[label],
            length = flash_length[label] or -1,
        }
        -- auto mount
        local mount = flash_mount[label]
        local chownpath = "/dev/" .. devname
        if label ~= "root" and mount then
            local cmd = table.concat({
                'busybox mkdir -p "',
                mount,
                '" && busybox mount /dev/',
                devname,
                ' "',
                mount,
                '"',
            })
            config.dtb.init = config.dtb.init .. cmd .. "\n"
            chownpath = mount
        end
        -- change permission
        local user = flash_user[label]
        if label ~= "root" and user then
            local cmd = table.concat({
                "busybox chown ",
                user,
                ": ",
                chownpath,
            })
            config.dtb.init = config.dtb.init .. cmd .. "\n"
        end
        do -- create a map of the label in /run/drive-label for flashdrive tool
            local cmd = table.concat({
                'busybox mkdir -p /run/drive-label && echo "',
                label,
                '" > /run/drive-label/',
                devname,
            })
            config.dtb.init = config.dtb.init .. cmd .. "\n"
        end
    end

    if #append_bootargs > 0 then config.dtb.bootargs = config.dtb.bootargs .. " " .. append_bootargs end
    if #default_init > 0 then config.dtb.init = config.dtb.init .. default_init end
    if #append_init > 0 then config.dtb.init = config.dtb.init .. append_init end
    if #append_entrypoint > 0 then config.dtb.entrypoint = config.dtb.entrypoint .. append_entrypoint end
    if #exec_arguments > 0 then config.dtb.entrypoint = config.dtb.entrypoint .. table.concat(exec_arguments, " ") end

    if load_config then
        local env = {}
        local ok, ret = loadfile(load_config, "t", env)
        if ok then
            local chunk = ok
            ok, ret = pcall(chunk)
        end
        if not ok then
            stderr("Failed to load machine config (%s):\n", load_config)
            error(ret)
        end
        config = setmetatable(ret, { __index = config })
    end

    main_machine = create_machine(config, runtime)
end

-- obtain config from instantiated machine
local main_config = main_machine:get_initial_config()

for _, r in ipairs(memory_range_replace) do
    main_machine:replace_memory_range(r)
end

if type(store_config) == "string" then
    store_config = assert(io.open(store_config, "w"))
    store_machine_config(main_config, function(...) store_config:write(string.format(...)) end)
    store_config:close()
end

local htif_yield_reason_guest_to_host = {
    [cartesi.machine.HTIF_YIELD_REASON_PROGRESS] = "progress",
    [cartesi.machine.HTIF_YIELD_REASON_RX_ACCEPTED] = "rx-accepted",
    [cartesi.machine.HTIF_YIELD_REASON_RX_REJECTED] = "rx-rejected",
    [cartesi.machine.HTIF_YIELD_REASON_TX_OUTPUT] = "tx-output",
    [cartesi.machine.HTIF_YIELD_REASON_TX_REPORT] = "tx-report",
    [cartesi.machine.HTIF_YIELD_REASON_TX_EXCEPTION] = "tx-exception",
}

-- local htif_yield_reason_host_to_guest = {
--     [cartesi.machine.HTIF_YIELD_REASON_ADVANCE_STATE] = "advance-state",
--     [cartesi.machine.HTIF_YIELD_REASON_INSPECT_STATE] = "inspect-state",
-- }

local htif_yield_mode = {
    [cartesi.machine.HTIF_YIELD_MANUAL] = "Manual",
    [cartesi.machine.HTIF_YIELD_AUTOMATIC] = "Automatic",
}

local function is_power_of_two(value) return value > 0 and ((value & (value - 1)) == 0) end

local function ilog2(value)
    value = assert(math.tointeger(value), "expected integer")
    assert(value ~= 0, "expected non-zero integer")
    local log = 0
    while value ~= 0 do
        log = log + 1
        value = value >> 1
    end
    return value
end

local function check_cmio_memory_range_config(range, name)
    assert(range, string.format("cmio range %s must be defined", name))
    assert(not range.shared, string.format("cmio range %s cannot be shared", name))
    assert(
        is_power_of_two(range.length),
        string.format("cmio range %s length not a power of two (%u)", name, range.length)
    )
    local log = ilog2(range.length)
    local aligned_start = (range.start >> log) << log
    assert(
        aligned_start == range.start,
        string.format("cmio range %s start not aligned to its power of two size", name)
    )
    range.image_filename = nil
end

local function check_cmio_htif_config(htif)
    assert(not htif.console_getchar, "console getchar must be disabled for cmio")
    assert(htif.yield_manual, "yield manual must be enabled for cmio")
    assert(htif.yield_automatic, "yield automatic must be enabled for cmio")
end

local function set_yield_data(machine, reason, data)
    local m16 = (1 << 16) - 1
    local m32 = (1 << 32) - 1
    machine:write_htif_fromhost_data((reason & (m16 << 32)) | (data & m32))
end

local function get_yield(machine)
    local m16 = (1 << 16) - 1
    local m32 = (1 << 32) - 1
    local cmd = machine:read_htif_tohost_cmd()
    local data = machine:read_htif_tohost_data()
    local reason = data >> 32
    return cmd, reason & m16, data & m32
end

local function get_and_print_yield(machine, htif)
    local cmd, reason, data = get_yield(machine)
    if cmd == cartesi.machine.HTIF_YIELD_AUTOMATIC and reason == cartesi.machine.HTIF_YIELD_REASON_PROGRESS then
        stderr("Progress: %6.2f" .. (htif.console_getchar and "\n" or "\r"), data / 10)
    else
        local cmd_str = htif_yield_mode[cmd] or "Unknown"
        local reason_str = htif_yield_reason_guest_to_host[reason] or "unknown"
        stderr("\n%s yield %s (0x%06x data)\n", cmd_str, reason_str, data)
        stderr("Cycles: %u\n", machine:read_mcycle())
    end
    return cmd, reason, data
end

local function instantiate_filename(pattern, values)
    -- replace escaped % with something safe
    pattern = string.gsub(pattern, "%\\%%", "\0")
    pattern = string.gsub(pattern, "%%(%a)", function(s) return values[s] or s end)
    -- restore escaped %
    return (string.gsub(pattern, "\0", "%"))
end

local function save_cmio_state_with_format(machine, config, advance, length, format, index)
    local values = { e = advance.epoch_index, i = advance.next_input_index - 1, o = index }
    local name = instantiate_filename(format, values)
    stderr("Storing %s\n", name)
    local f = assert(io.open(name, "wb"))
    assert(f:write(machine:read_memory(config.start, length)))
    f:close()
end

local function save_cmio_report(machine, config, advance, length)
    return save_cmio_state_with_format(machine, config, advance, length, advance.report, advance.report_index)
end

local function save_cmio_output(machine, config, advance, length)
    return save_cmio_state_with_format(machine, config, advance, length, advance.output, advance.output_index)
end

local function save_cmio_outputs_root_hash(machine, config, advance, length)
    return save_cmio_state_with_format(machine, config, advance, length, advance.outputs_root_hash)
end

local function load_memory_range(machine, config, filename)
    stderr("Loading %s\n", filename)
    local f = assert(io.open(filename, "rb"))
    local s = assert(f:read("*a"))
    f:close()
    machine:write_memory(config.start, s)
    return #s
end

local function load_cmio_input(machine, config, advance)
    local values = { e = advance.epoch_index, i = advance.next_input_index }
    machine:replace_memory_range(config.rx_buffer) -- clear
    return load_memory_range(machine, config.rx_buffer, instantiate_filename(advance.input, values))
end

local function load_cmio_query(machine, config, inspect)
    machine:replace_memory_range(config.rx_buffer) -- clear
    return load_memory_range(machine, config.rx_buffer, inspect.query) -- load query payload
end

local function dump_exception(machine, config, length)
    local payload = machine:read_memory(config.start, length)
    stderr("cmio exception with payload: %q\n", payload)
end

local function save_cmio_inspect_state_report(machine, config, inspect, length)
    local values = { o = inspect.report_index }
    local name = instantiate_filename(inspect.report, values)
    stderr("Storing %s\n", name)
    local f = assert(io.open(name, "wb"))
    assert(f:write(machine:read_memory(config.start, length)))
    f:close()
end

local function store_machine(machine, config, dir)
    assert(not config.htif.console_getchar, "hashes are meaningless in interactive mode")
    stderr("Storing machine: please wait\n")
    local h = util.hexhash(machine:get_root_hash())
    local name = instantiate_filename(dir, { h = h })
    machine:store(name)
end

local function dump_pmas(machine)
    for _, v in ipairs(machine:get_memory_ranges()) do
        local filename = string.format("%016x--%016x.bin", v.start, v.length)
        local file <close> = assert(io.open(filename, "w"))
        assert(file:write(machine:read_memory(v.start, v.length)))
    end
end

local machine = main_machine
local config = main_config
local gdb_stub
if gdb_address then
    assert(
        periodic_hashes_start == 0 and periodic_hashes_period == math.maxinteger,
        "periodic hashing is not supported when debugging"
    )
    gdb_stub = require("cartesi.gdbstub").new(machine)
    local address, port = gdb_address:match("^(.*):(%d+)$")
    assert(address and port, "invalid address for GDB")
    gdb_stub:listen_and_wait_gdb(address, tonumber(port))
end
if config.htif.console_getchar then stderr("Running in interactive mode!\n") end
if store_config == stderr then store_machine_config(config, stderr) end
if cmio_advance or cmio_inspect then
    check_cmio_htif_config(config.htif)
    assert(config.cmio, "cmio device must be present")
    assert(remote_address, "cmio requires --remote-address for snapshot/rollback")
    check_cmio_memory_range_config(config.cmio.tx_buffer, "tx-buffer")
    check_cmio_memory_range_config(config.cmio.rx_buffer, "rx-buffer")
end
local cycles = machine:read_mcycle()
if initial_hash then
    assert(not config.htif.console_getchar, "hashes are meaningless in interactive mode")
    print_root_hash(machine, stderr_unsilenceable)
end
dump_value_proofs(machine, initial_proof, config.htif.console_getchar)
local exit_code = 0
local next_hash_mcycle
if periodic_hashes_start ~= 0 then
    next_hash_mcycle = periodic_hashes_start
else
    next_hash_mcycle = periodic_hashes_period
end
-- the loop runs at most until max_mcycle. iterations happen because
--   1) we stopped to print a hash
--   2) the machine halted, so iflags_H is set
--   3) the machine yielded manual, so iflags_Y is set
--   4) the machine yielded automatic, so iflags_X is set
-- if the user selected the cmio advance state, then at every yield manual we check the reason
-- if the reason is rx-rejected, we rollback, otherwise it must be rx-accepted.
-- we then feed the next input, reset iflags_Y, snapshot, and resume the machine
-- the machine can now continue processing and may yield automatic to produce outputs and reports we save
-- once all inputs for advance state have been consumed, we check if the user selected cmio inspect state
-- if so, we feed the query, reset iflags_Y, and resume the machine
-- the machine can now continue processing and may yield automatic to produce reports we save
while math.ult(cycles, max_mcycle) do
    local next_mcycle = math.min(next_hash_mcycle, max_mcycle)
    if gdb_stub and gdb_stub:is_connected() then
        gdb_stub:run(next_mcycle)
    else
        machine:run(next_mcycle)
    end
    cycles = machine:read_mcycle()
    -- deal with halt
    if machine:read_iflags_H() then
        exit_code = machine:read_htif_tohost_data() >> 1
        if exit_code ~= 0 then
            stderr("\nHalted with payload: %u\n", exit_code)
        else
            stderr("\nHalted\n")
        end
        stderr("Cycles: %u\n", cycles)
        break
    -- deal with yield manual
    elseif machine:read_iflags_Y() then
        local _, reason, data = get_and_print_yield(machine, config.htif)
        -- there are advance state inputs to feed
        if reason == cartesi.machine.HTIF_YIELD_REASON_TX_EXCEPTION then
            dump_exception(machine, config.cmio.tx_buffer, data)
            exit_code = 1
        elseif cmio_advance and cmio_advance.next_input_index < cmio_advance.input_index_end then
            -- save only if we have already run an input
            if cmio_advance.next_input_index > cmio_advance.input_index_begin then
                save_cmio_outputs_root_hash(machine, config.cmio.tx_buffer, cmio_advance, 32)
            end
            if reason == cartesi.machine.HTIF_YIELD_REASON_RX_REJECTED then
                machine:rollback()
                cycles = machine:read_mcycle()
            else
                assert(reason == cartesi.machine.HTIF_YIELD_REASON_RX_ACCEPTED, "invalid manual yield reason")
            end
            stderr("\nEpoch %d before input %d\n", cmio_advance.epoch_index, cmio_advance.next_input_index)
            if cmio_advance.hashes then print_root_hash(machine) end
            machine:snapshot()
            local input_length = load_cmio_input(machine, config.cmio, cmio_advance)
            if cmio_advance.hashes then print_root_hash(machine) end
            machine:reset_iflags_Y()
            set_yield_data(machine, cartesi.machine.HTIF_YIELD_REASON_ADVANCE_STATE, input_length)
            cmio_advance.output_index = 0
            cmio_advance.report_index = 0
            cmio_advance.next_input_index = cmio_advance.next_input_index + 1
        else
            -- there are outputs of a prevous advance state to save
            if cmio_advance and cmio_advance.next_input_index > cmio_advance.input_index_begin then
                save_cmio_outputs_root_hash(machine, config.cmio.tx_buffer, cmio_advance, 32)
            end
            -- there is an inspect state query to feed
            if cmio_inspect and cmio_inspect.query then
                stderr("\nBefore query\n")
                local input_length = load_cmio_query(machine, config.cmio, cmio_inspect)
                machine:reset_iflags_Y()
                set_yield_data(machine, cartesi.machine.HTIF_YIELD_REASON_INSPECT_STATE, input_length)
                cmio_inspect.report_index = 0
                cmio_inspect.query = nil
                cmio_advance = nil
            end
        end
    -- deal with yield automatic
    elseif machine:read_iflags_X() then
        local _, reason, length = get_and_print_yield(machine, config.htif)
        -- we have fed an advance state input
        if cmio_advance and cmio_advance.next_input_index > cmio_advance.input_index_begin then
            if reason == cartesi.machine.HTIF_YIELD_REASON_TX_OUTPUT then
                save_cmio_output(machine, config.cmio.tx_buffer, cmio_advance, length)
                cmio_advance.output_index = cmio_advance.output_index + 1
            elseif reason == cartesi.machine.HTIF_YIELD_REASON_TX_REPORT then
                save_cmio_report(machine, config.cmio.tx_buffer, cmio_advance, length)
                cmio_advance.report_index = cmio_advance.report_index + 1
            end
        -- ignore other reasons
        -- we have feed the inspect state query
        elseif cmio_inspect and not cmio_inspect.query then
            if reason == cartesi.machine.HTIF_YIELD_REASON_TX_REPORT then
                save_cmio_inspect_state_report(machine, config.cmio.tx_buffer, cmio_inspect, length)
                cmio_inspect.report_index = cmio_inspect.report_index + 1
            end
            -- ignore other reasons
        end
        -- otherwise ignore
    end
    if machine:read_iflags_Y() then break end
    if cycles == next_hash_mcycle then
        print_root_hash(machine)
        next_hash_mcycle = next_hash_mcycle + periodic_hashes_period
    end
end
-- Advance micro cycles
if max_uarch_cycle > 0 then
    -- Save halt flag before micro cycles
    local previously_halted = machine:read_iflags_H()
    if machine:run_uarch(max_uarch_cycle) == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then
        -- Microarchitecture  halted. This means that one "macro" instruction was totally executed
        -- The mcycle counter was incremented, unless the machine was already halted
        if machine:read_iflags_H() and not previously_halted then stderr("Halted\n") end
        stderr("Cycles: %u\n", machine:read_mcycle())
        if auto_uarch_reset then
            machine:reset_uarch()
        else
            stderr("uCycles: %u\n", machine:read_uarch_cycle())
        end
    end
end
if gdb_stub then gdb_stub:close() end
if log_uarch_step then
    assert(not config.htif.console_getchar, "micro step proof is meaningless in interactive mode")
    stderr("Gathering micro step log: please wait\n")
    util.dump_log(machine:log_uarch_step({ proofs = true, annotations = true }), io.stderr)
end
if log_uarch_reset then
    stderr("Resetting microarchitecture state: please wait\n")
    util.dump_log(machine:log_uarch_reset({ proofs = true, annotations = true }), io.stderr)
end
if dump_memory_ranges then dump_pmas(machine) end
if final_hash then
    assert(not config.htif.console_getchar, "hashes are meaningless in interactive mode")
    print_root_hash(machine, stderr_unsilenceable)
end
dump_value_proofs(machine, final_proof, config.htif.console_getchar)
if store_dir then store_machine(machine, config, store_dir) end
if assert_rolling_template then
    local cmd, reason = get_yield(machine)
    if not (cmd == cartesi.machine.HTIF_YIELD_MANUAL and reason == cartesi.machine.HTIF_YIELD_REASON_RX_ACCEPTED) then
        exit_code = 2
    end
end
if not remote or remote_destroy then machine:destroy() end
os.exit(exit_code, true)
