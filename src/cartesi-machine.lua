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
    print(string.format(
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

  --remote-spawn
    spawns a remote cartesi machine,
    when --remote-address is specified, it listens on the specified address,
    otherwise it listens on "127.0.0.1:0".

  --remote-address=<ip>:<port>
    use a remote cartesi machine listening to <ip>:<port> instead of
    running a local cartesi machine.

  --remote-health-check
    checks health of remote server and exit

  --remote-fork[=<ip>:<port>]
    fork the remote cartesi machine before the execution,
    in case an address is specified the new forked server will be rebound to it.

  --remote-shutdown
    shutdown the remote cartesi machine after the execution.

  --no-remote-create
    use existing cartesi machine in the remote server instead of creating
    a new one.

  --no-remote-destroy
    do not destroy the cartesi machine in the remote server after the execution.

  --no-rollback
    disable rollback for advance and inspect states.
    this allows to perform advance and inspect states on local cartesi machines,
    however the state is never reverted, even in case inspects or rejected advances.

    DON'T USE THIS OPTION IN PRODUCTION

  --ram-image=<filename>
    name of file containing RAM image (default: "linux.bin").

  --no-ram-image
    forget settings for RAM image.

  --ram-length=<number>
    set RAM length.

  --dtb-image=<filename>
    name of file containing DTB image
    (default: auto generated flattened device tree).

  --no-bootargs
    clear default bootargs.

  --append-bootargs=<string>
    append <string> to bootargs.

  --no-root-flash-drive
    clear default root flash drive and associated bootargs parameters.

  --flash-drive=<key>:<value>[,<key>:<value>[,...]...]
    defines a new flash drive, or modify an existing flash drive definition.
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
        when mount is true, changes the user ownership of the mounted directory,
        otherwise changes the user ownership of the /dev/pmemX device.
        this option is useful to allow dapp's user access the flash drive.
        by default the mounted directory ownership is configured by the
        filesystem being mounted.
        in case mount is false, the default ownership is set to the root user.

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
        shared

    semantics are the same as for the --flash-drive option.

  --cmio-advance-state=<key>:<value>[,<key>:<value>[,...]...]
    advances the state of the machine through a number of inputs.

    <key>:<value> is one of
        input:<filename-pattern>
        input_index_begin:<number>
        input_index_end:<number>
        output:<filename-pattern>
        report:<filename-pattern>
        output_hashes_root_hash:<filename-pattern>
        hashes

        input (default: "input-%%i.bin")
        the pattern that derives the name of the file read for input %%i.

        input_index_begin (default: 0)
        index of first input to advance (the first value of %%i).

        input_index_end (default: 0)
        one past index of last input to advance (one past last value of %%i).

        output (default: "input-%%i-output-%%o.bin")
        the pattern that derives the name of the file written for output %%o
        of input %%i.

        report (default: "input-%%i-report-%%o.bin")
        the pattern that derives the name of the file written for report %%o
        of input %%i.

        outputs_root_hash (default: "input-%%i-output-hashes-root-hash.bin")
        the pattern that derives the name of the file written for outputs root
        hash of input %%i.

        hashes
        print out hashes before every input.

    the input index ranges in {input_index_begin, ..., input_index_end-1}.
    for each input, "%%i" is replaced by the input index, and "%%o" by the output
    or report index.

  --cmio-inspect-state=<key>:<value>[,<key>:<value>[,...]...]
    inspect the state of the machine with a query.
    the query happens after the end of --cmio-advance-state.

    <key>:<value> is one of
        query:<filename>
        report:<filename-pattern>
        hashes

        query (default: "query.bin")
        the name of the file from which to read the query.

        report (default: "query-report-%%o.bin")
        the pattern that derives the name of the file written for report %%o
        of the query.

        hashes
        print out hashes before every query.

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
    suppress any console output during machine run.
    this includes anything written to machine's stdout or stderr.

  --skip-root-hash-check
    skip merkle tree root hash check when loading a stored machine.
    i.e., assume the stored machine files are not corrupt.
    this is only intended to speed up machine loading in emulator tests.

    DON'T USE THIS OPTION IN PRODUCTION

  --skip-root-hash-store
    skip merkle tree root hash saving when storing a machine.
    i.e., assume the stored machine will use --skip-root-hash-check when loading.
    this is only intended to speed up machine saving in emulator tests.

    DON'T USE THIS OPTION IN PRODUCTION

  --skip-version-check
    skip emulator version check when loading a stored machine.
    i.e., assume the stored machine is compatible with current emulator version.
    this is only intended to test old snapshots during emulator development.

    DON'T USE THIS OPTION IN PRODUCTION

  --max-mcycle=<number>
    stop at a given mcycle (default: 2305843009213693952).

  --max-uarch-cycle=<number>
    stop at a given micro cycle.

  --unreproducible
    run machine in unreproducible mode.
    unreproducible machines will advance time normally when its CPU is idle.
    i.e., when sleeping 1 second on the guest, 1 second will pass on the host.
    this is automatically implied by all options marked as NON REPRODUCIBLE.

    NON REPRODUCIBLE OPTION, DON'T USE THIS OPTION IN PRODUCTION

  --sync-init-date
    set the guest date to match the host date on initialization.
    this option is recommended when using TLS connections or when sharing
    host directories systems.
    this is is automatically implied with --network or --volume options.

    NON REPRODUCIBLE OPTION, DON'T USE THIS OPTION IN PRODUCTION

  --virtio-9p=<tag>:<directory>
    add a VirtIO Plan9 filesystem device for sharing a host directory
    in the guest.
    the filesystem will have a tag can be used to mount the host directory
    in the guest using the following command:

        busybox mount -t 9p <tag> <mountpoint>

    NON REPRODUCIBLE OPTION, DON'T USE THIS OPTION IN PRODUCTION

  -v or --volume=<host_directory>:<guest_directory>
    like --virtio-9p, but also appends init commands to auto mount the
    host directory in the guest directory.
    mount tags are incrementally set to "vfs0", "vfs1", ...

    this option implies --sync-init-date.

    NON REPRODUCIBLE OPTION, DON'T USE THIS OPTION IN PRODUCTION

  --virtio-net=<iface>
    add a VirtIO network device using host TUN/TAP interface.
    this allows the use of the host network from inside the machine.
    this is more efficient and has fewer limitations than the user-space
    networking option (--virtio-net=user...).

    run the following commands in the host before starting the emulator:

        sudo modprobe tun
        sudo ip link add br0 type bridge
        sudo ip tuntap add dev tap0 mode tap user $USER
        sudo ip link set dev tap0 master br0
        sudo ip link set dev br0 up
        sudo ip link set dev tap0 up
        sudo ip addr add 10.0.2.2/24 dev br0
        sudo sysctl -w net.ipv4.ip_forward=1
        sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

    (in the example above, the host public internet interface is eth0,
    but this depends on your host.)

    then, start the machine with using --virtio-net=tap0 and
    execute the following commands in the guest (with root privilege):

        busybox ip link set dev eth0 up
        busybox ip addr add 10.0.2.15/24 dev eth0
        busybox ip route add default via 10.0.2.2 dev eth0
        echo "nameserver 8.8.8.8" > /etc/resolv.conf

    NON REPRODUCIBLE OPTION, DON'T USE THIS OPTION IN PRODUCTION

  --virtio-net=user
    add a VirtIO network device using host user-space networking.
    this allows the use of the host network from inside the machine.
    you don't need root privilege or any configuration in the host to use this.
    although this mode is easier to use, it has the following limitations:
      - there is an additional an emulation layer of the TCP/IP stack;
      - not all IP protocols are emulated, but TCP and UDP should work;
      - host cannot connect to guest TCP ports.
    the implementation uses the libslirp TCP/IP emulator library.

    you must execute the following commands in the guest (with root privilege):

        busybox ip link set dev eth0 up
        busybox ip addr add 10.0.2.15/24 dev eth0
        busybox ip route add default via 10.0.2.2 dev eth0
        echo 'nameserver 10.0.2.3' > /etc/resolv.conf

    the network settings configuration is fixed to the following:
        Network:      10.0.2.0
        Netmask:      255.255.255.0
        Host/Gateway: 10.0.2.2
        DHCP Start:   10.0.2.15
        Nameserver:   10.0.2.3

    NON REPRODUCIBLE OPTION, DON'T USE THIS OPTION IN PRODUCTION

  -n or --network
    like --virtio-net=user, but automatically appends init commands to
    initialize the network in the guest.

    this option implies --sync-init-date.

    NON REPRODUCIBLE OPTION, DON'T USE THIS OPTION IN PRODUCTION

  -p=... or --port-forward=[hostip:]hostport[:guestip][:guestport][/protocol]
    redirect incoming TCP or UDP connections.
    bind the host hostip:hostport to the guest guestip:guestport.
    protocol can be "tcp" or "udp".
    if host ip is absent, it's set to "127.0.0.1".
    if guest ip is absent, it's set to "10.0.2.15".
    if guest port is absent, it's set to the same as host port.
    if protocol is absent, it's set to "tcp".
    you can pass this option multiple times.
    this options requires --network or --virtio-net=user option.

    NON REPRODUCIBLE OPTION, DON'T USE THIS OPTION IN PRODUCTION

  -i or --htif-console-getchar
    run in interactive mode using a HTIF console device.

    NON REPRODUCIBLE OPTION, DON'T USE THIS OPTION IN PRODUCTION

  --virtio-console
    add a VirtIO console device.
    VirtIO console is more responsive than the HTIF console and
    supports terminal size.

    NON REPRODUCIBLE OPTION, DON'T USE THIS OPTION IN PRODUCTION

  -it
    run in enhanced interactive mode using a VirtIO console device.
    the console is resizable, more responsive, and support more features
    than the -i option.

    like --virtio-console, but automatically appends init commands to forward
    TERM and LANG environment variables from the host to the guest,
    allowing the use of true colors and special characters (when supported).

    this option implies --sync-init-date.

    NON REPRODUCIBLE OPTION, DON'T USE THIS OPTION IN PRODUCTION

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
    prints root hash every <number-period> cycles.
    if <number-start> is given, the periodic hashing will start at that mcycle.
    this option implies --initial-hash and --final-hash.
    (default: none)

  --log-step=<mcycle-count>,<filename>
    log and save a step of <mcycle-count> mcycles to <filename>.

  --log-step-uarch
    advance one micro step and print access log.

  --log-reset-uarch
    reset the microarchitecture state and print the access log.

  --auto-reset-uarch
    reset uarch automatically after halt.

  --store-config[=<filename>]
    store initial machine config as Lua script to <filename>.
    If <filename> is omitted, print the initial machine config to stdout.

  --store-json-config[=<filename>]
    store initial machine config as JSON to <filename>.
    If <filename> is omitted, print the initial machine config to stdout.

  --load-config=<filename>
    load initial machine config from Lua script <filename>. If a field is omitted on
    the config table, it will fall back into the respective command-line
    argument or into the default value.

  --load-json-config=<filename>
    load initial machine config from JSON <filename>. If a field is omitted on
    the config table, it will fall back into the respective command-line
    argument or into the default value.

  --uarch-ram-image=<filename>
    name of file containing microarchitecture RAM image.

  --dump-memory-ranges
    dump all memory ranges to disk when done.

  --assert-rolling-template
    exit with failure in case the generated machine is not compatible with
    Rolling Cartesi Machine templates.

  --quiet
    suppress cartesi-machine.lua output.
    exceptions: --initial-hash, --final-hash and text emitted from the target.

  --no-init-splash
    don't show cartesi machine splash on boot.

  -u=<name> or --user=<name>
    appends to init the user who should execute the entrypoint command.
    when omitted, the user is set to "dapp" by rootfs init script.

  -e=<name>=<value> or --env=<name>=<value>
    appends to init an environment variable export.

  -w=<dir> or --workdir=<dir>
    appends to init the entrypoint working directory.

  -h=<name> or --hostname=<name>
    appends to init a machine hostname change.

  --append-init=<string>
    append <string> to the machine's init script, to execute as root.
    <string> is executed on boot after mounting flash drives but before
    running the entrypoint.
    you can pass this option multiple times.

  --append-init-file=<filename>
    like --append-init, but read contents from a file.

  --append-entrypoint=<string>
    append a <string> to the machine's entrypoint script, to execute as dapp.
    <string> is executed after the machine is initialized, and before the
    command and arguments passed last in the command line.
    you can pass this option multiple times.

  --append-entrypoint-file=<filename>
    like --append-entrypoint, but read contents from a file.

  --gdb[=<ip>:<port>]
    listen at <ip>:<port> and wait for a GDB connection to debug the machine.
    if <ip>:<port> is omitted, '127.0.0.1:1234' is used by default.
    the host GDB client must have support for RISC-V architecture.

    host GDB can connect with the following command:
        gdb -ex "set arch riscv:rv64" -ex "target remote <ip>:<port>" [elf]

        elf (optional)
        the binary elf file with symbols and debugging information
        to be debugged, such as:
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

]=],
        arg[0]
    ))
    os.exit()
end

local remote_closer = {}
local remote_spawn
local remote_address
local remote_health_check = false
local remote_fork = false
local remote_shutdown = false
local remote_create = true
local remote_destroy = true
local perform_rollbacks = true
local default_config = cartesi.machine:get_default_config()
local images_path = adjust_images_path(os.getenv("CARTESI_IMAGES_PATH"))
local flash_image_filename = { root = images_path .. "rootfs.ext2" }
local flash_label_order = { "root" }
local flash_shared = {}
local flash_mount = {}
local flash_user = {}
local flash_start = {}
local flash_length = {}
local unreproducible = false
local virtio = {}
local virtio_net_user_config
local virtio_volume_count = 0
local has_virtio_console = false
local has_network = false
local has_sync_init_date = false
local memory_range_replace = {}
local ram_image_filename = images_path .. "linux.bin"
local ram_length = 128 << 20 -- 128MB
local dtb_image_filename = nil
local bootargs = default_config.dtb.bootargs
local init_splash = true
local append_bootargs = ""
local append_init = ""
local append_entrypoint = ""
local uarch
local cmio
local cmio_advance
local cmio_inspect
local concurrency_update_merkle_tree = 0
local skip_root_hash_check = false
local skip_root_hash_store = false
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
local log_step_uarch = false
local auto_reset_uarch = false
local log_reset_uarch = false
local store_dir
local load_dir
local cmdline_opts_finished = false
local store_config = false
local store_json_config = false
local load_config = false
local load_json_config = false
local gdb_address
local exec_arguments = {}
local assert_rolling_template = false
local log_step_mcycle_count
local log_step_filename

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

local function parse_cmio_buffer(opts, what, all)
    local f = util.parse_options(opts, {
        filename = true,
        shared = true,
    })
    f.image_filename = f.filename
    f.filename = nil
    if f.image_filename == true then f.image_filename = "" end
    assert(not f.shared or f.shared == true, "invalid " .. what .. " shared value in " .. all)
    return f
end

local function handle_sync_init_date(all)
    if not all then return false end
    if has_sync_init_date then return end
    unreproducible = true
    has_sync_init_date = true
    -- round up time by 1, to decrease chance of guest time being in the past
    local seconds = os.time() + 1
    append_init = append_init .. "busybox date -s @" .. seconds .. " >> /dev/null\n"
end

local function handle_virtio_9p(tag, host_directory)
    if not tag or not host_directory then return false end
    unreproducible = true
    table.insert(virtio, { type = "p9fs", tag = tag, host_directory = host_directory })
    return true
end

local function handle_volume_option(host_directory, guest_directory)
    if not host_directory or not guest_directory then return false end
    unreproducible = true
    local tag = "vfs" .. virtio_volume_count
    virtio_volume_count = virtio_volume_count + 1
    table.insert(virtio, { type = "p9fs", tag = tag, host_directory = host_directory })
    append_init = append_init .. "busybox mkdir -p " .. guest_directory .. " && "
    append_init = append_init .. "busybox mount -t 9p " .. tag .. " " .. guest_directory .. "\n"
    -- sync guest date with host date, otherwise file system updates will have wrong dates
    handle_sync_init_date(true)
    return true
end

local function handle_htif_console_getchar(all)
    if not all then return false end
    htif_console_getchar = true
    unreproducible = true
    return true
end

local function handle_user(user)
    if not user then return false end
    append_init = append_init .. "USER=" .. user .. "\n"
    return true
end

local function handle_env(name, value)
    if not name or not value then return false end
    append_init = append_init .. "export " .. name .. "=" .. value .. "\n"
    return true
end

local function handle_workdir(value)
    if not value then return false end
    append_init = append_init .. "WORKDIR=" .. value .. "\n"
    return true
end

local function handle_hostname(name)
    if not name then return false end
    append_init = append_init .. "busybox hostname " .. name .. "\n"
    return true
end

local function parse_ipv4(s)
    local a, b, c, d = s:match("^([0-9]+)%.([0-9]+)%.([0-9]+)%.([0-9]+)$")
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    assert(a and b and c and d and a <= 255 and b <= 255 and c <= 255 and d <= 255, "malformed IPv4 " .. s)
    return (a << 24) | (b << 18) | (c << 8) | d
end

local function handle_port_forward_option(opts)
    if not opts then return false end
    assert(virtio_net_user_config, "--port-forward option requires --network or --virtio-net=user option")
    local host_ip, guest_ip, host_port, guest_port, proto
    for s in opts:gmatch("[%w.]+") do
        if (not host_port or not guest_port) and s:find("^[0-9]+$") then
            if not host_port then
                host_port = tonumber(s)
            else
                guest_port = tonumber(s)
            end
        elseif (not host_ip or not guest_ip) and s:find("^[0-9]+%.[0-9]+%.[0-9]+%.[0-9]+$") then
            if not host_ip then
                host_ip = parse_ipv4(s)
            else
                guest_ip = parse_ipv4(s)
            end
        elseif proto == nil and (s == "tcp" or s == "udp") then
            proto = s
        else
            error("malformed --port-forward option")
        end
    end
    host_ip = host_ip or parse_ipv4("127.0.0.1")
    guest_ip = guest_ip or parse_ipv4("10.0.2.15")
    assert(host_port, "malformed --port-forward option")
    guest_port = guest_port or host_port
    local is_udp = proto == "udp"
    virtio_net_user_config.hostfwd = virtio_net_user_config.hostfwd or {}
    table.insert(virtio_net_user_config.hostfwd, {
        is_udp = is_udp,
        host_ip = host_ip,
        guest_ip = guest_ip,
        host_port = host_port,
        guest_port = guest_port,
    })
    return true
end

local function handle_virtio_net(mode, opts)
    if not mode then return false end
    unreproducible = true
    if mode == "user" then
        if not virtio_net_user_config then
            virtio_net_user_config = { type = "net-user" }
            table.insert(virtio, virtio_net_user_config)
        end
    else
        table.insert(virtio, { type = "net-tuntap", iface = opts })
    end
    return true
end

local function handle_network_option(opts)
    if not opts then return false end
    if has_network then return true end
    handle_virtio_net("user")
    has_network = true
    -- initialize network
    append_init = append_init
        .. [[
busybox ip link set dev eth0 up
busybox ip addr add 10.0.2.15/24 dev eth0
busybox ip route add default via 10.0.2.2 dev eth0
[ -w /etc ] && echo 'nameserver 10.0.2.3' > /etc/resolv.conf
]]
    -- sync guest date with host date, otherwise SSL connections may fail to validate certificates
    handle_sync_init_date(true)
    return true
end

local function handle_virtio_console(all)
    if not all then return false end
    if has_virtio_console then return end
    unreproducible = true
    has_virtio_console = true
    -- Switch from HTIF Console (hvc0) to VirtIO console (hvc1)
    bootargs = bootargs:gsub("console=hvc0", "console=hvc1")
    table.insert(virtio, 1, { type = "console" })
end

local function handle_interactive(all)
    if not all then return false end
    handle_virtio_console(true)
    handle_sync_init_date(true)
    -- Expose current terminal features to the virtual terminal
    local term, lang = os.getenv("TERM"), os.getenv("LANG")
    if term then append_init = append_init .. "export TERM=" .. term .. "\n" end
    if lang and lang:find("utf8") then append_init = append_init .. "export LANG=C.utf8\n" end
    return true
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
        "^%-%-unreproducible$",
        function(all)
            if not all then return false end
            unreproducible = true
            return true
        end,
    },
    {
        "^%-%-sync%-init-date$",
        handle_sync_init_date,
    },
    {
        "^%-%-virtio%-9p%=([%w_-]+):(.*)$",
        handle_virtio_9p,
    },
    {
        "^%-v%=([^:]+):(.*)$",
        handle_volume_option,
    },
    {
        "^%-%-volume%=([^:]+):(.*)$",
        handle_volume_option,
    },
    {
        "^%-%-virtio%-console$",
        handle_virtio_console,
    },
    {
        "^%-%-virtio%-net%=([%w+]+),?([%w:,]*)$",
        handle_virtio_net,
    },
    {
        "^%-%-network=?([%w:,]*)$",
        handle_network_option,
    },
    {
        "^%-n=?([%w:,]*)$",
        handle_network_option,
    },
    {
        "^%-%-port%-forward=([0-9:.]+/?[udptcp]*)$",
        handle_port_forward_option,
    },
    {
        "^%-p=([0-9:.]+/?[udptcp]*)$",
        handle_port_forward_option,
    },
    {
        "^%-%-htif%-console%-getchar$",
        handle_htif_console_getchar,
    },
    {
        "^%-i$",
        handle_htif_console_getchar,
    },
    {
        "^%-it$",
        handle_interactive,
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
                input = true,
                input_index_begin = true,
                input_index_end = true,
                output_hashes_root_hash = true,
                output = true,
                report = true,
                hashes = true,
            })
            assert(not r.hashes or r.hashes == true, "invalid hashes value in " .. all)
            r.input = r.input or "input-%i.bin"
            r.input_index_begin = r.input_index_begin or 0
            r.input_index_begin = assert(util.parse_number(r.input_index_begin), "invalid input index begin in " .. all)
            r.input_index_end = r.input_index_end or 0
            r.input_index_end = assert(util.parse_number(r.input_index_end), "invalid input index end in " .. all)
            r.output = r.output or "input-%i-output-%o.bin"
            r.report = r.report or "input-%i-report-%o.bin"
            r.output_hashes_root_hash = r.output_hashes_root_hash or "input-%i-output-hahes-root-hash.bin"
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
                hashes = true,
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
        "^%-%-skip%-root%-hash%-store$",
        function(all)
            if not all then return false end
            skip_root_hash_store = true
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
            bootargs = bootargs:gsub(" root=$", "")
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
        "^%-%-log%-step%=(.*),(.*)$",
        function(count, filename)
            if (not count) or not filename then return false end
            log_step_mcycle_count = assert(util.parse_number(count), "invalid steps " .. count)
            log_step_filename = filename
            return true
        end,
    },
    {
        "^%-%-log%-step%-uarch$",
        function(all)
            if not all then return false end
            log_step_uarch = true
            return true
        end,
    },
    {
        "^%-%-log%-reset%-uarch$",
        function(all)
            if not all then return false end
            log_reset_uarch = true
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
        "^%-%-auto%-reset%-uarch$",
        function(all)
            if not all then return false end
            auto_reset_uarch = true
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
        "^%-%-remote%-spawn$",
        function(o)
            if not o then return false end
            remote_spawn = true
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
        "^%-%-remote%-fork(%=?)(.*)$",
        function(o, v)
            if not o then return false end
            if o == "=" then
                if not v or #v < 1 then return false end
                remote_fork = v
            elseif #v ~= 0 then
                return false
            else
                remote_fork = true
            end
            return true
        end,
    },
    {
        "^%-%-remote%-health%-check$",
        function(o)
            if not o then return false end
            remote_health_check = true
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
        "^%-%-no%-rollback$",
        function(o)
            if not o then return false end
            perform_rollbacks = false
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
            elseif #v ~= 0 then
                return false
            else
                store_config = true
            end
            return true
        end,
    },
    {
        "^%-%-store%-json%-config(%=?)(%g*)$",
        function(o, v)
            if not o then return false end
            if o == "=" then
                if not v or #v < 1 then return false end
                store_json_config = v
            elseif #v ~= 0 then
                return false
            else
                store_json_config = true
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
        "^%-%-load%-json%-config%=(%g*)$",
        function(o)
            if not o or #o < 1 then return false end
            load_json_config = o
            return true
        end,
    },
    {
        "^(%-%-cmio%-rx%-buffer%=(.+))$",
        function(all, opts)
            if not opts then return false end
            cmio = cmio or {}
            cmio.rx_buffer = parse_cmio_buffer(opts, "cmio rx buffer", all)
            return true
        end,
    },
    {
        "^(%-%-cmio%-tx%-buffer%=(.+))$",
        function(all, opts)
            if not opts then return false end
            cmio = cmio or {}
            cmio.tx_buffer = parse_cmio_buffer(opts, "tx buffer", all)
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
        "^%-u%=(.*)$",
        handle_user,
    },
    {
        "^%-%-user%=(.*)$",
        handle_user,
    },
    {
        "^%-e%=([%w_]+)%=(.*)$",
        handle_env,
    },
    {
        "^%-%-env%=([%w_]+)%=(.*)$",
        handle_env,
    },
    {
        "^%-w%=(.*)$",
        handle_workdir,
    },
    {
        "^%-%-workdir%=(.*)$",
        handle_workdir,
    },
    {
        "^%-h%=(.*)$",
        handle_hostname,
    },
    {
        "^%-%-hostname%=(.*)$",
        handle_hostname,
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
    (print or stderr)("%u: %s\n", machine:read_reg("mcycle"), util.hexhash(machine:get_root_hash()))
end

local function dump_value_proofs(machine, desired_proofs, config)
    if #desired_proofs > 0 then
        assert(config.processor.iunrep == 0, "proofs are meaningless in unreproducible mode")
    end
    for _, desired in ipairs(desired_proofs) do
        local proof = machine:get_proof(desired.address, desired.log2_size)
        local out = desired.filename and assert(io.open(desired.filename, "wb")) or io.stdout
        out:write("{\n")
        util.dump_json_proof(proof, out, 1)
        out:write("}\n")
    end
end

local function new_machine()
    assert(not remote_health_check or remote_address, "missing remote address")
    if remote_address then
        local jsonrpc = require("cartesi.jsonrpc")
        local new_m = assert(jsonrpc.connect_server(remote_address))
        if remote_fork then
            local fork_address, fork_pid
            new_m, fork_address, fork_pid = assert(new_m:fork_server())
            stderr("Forked JSONRPC remote cartesi machine at '%s' with pid %d\n", fork_address, fork_pid)
            if remote_fork ~= true then
                new_m:rebind_server(remote_fork)
                stderr("Rebound forked JSONRPC remote cartesi machine at '%s'\n", remote_fork)
            end
        end
        if remote_health_check then os.exit(0, true) end
        stderr("Connected to JSONRPC remote cartesi machine at '%s'\n", remote_address)
        local shutdown = function() new_m:shutdown_server() end
        setmetatable(remote_closer, {
            __gc = function()
                local address = new_m:get_server_address()
                if remote_shutdown then
                    local ok, err = pcall(shutdown)
                    if ok then
                        stderr("Shutdown JSONRPC remote cartesi machine at '%s'\n", address)
                    else
                        stderr("Failed to shutdown JSONRPC remote cartesi machine: %s\n", err)
                    end
                else
                    stderr("Left alive JSONRPC remote cartesi machine at '%s'\n", address)
                end
                if remote_fork then
                    stderr("Left alive original JSONRPC remote cartesi machine at '%s'\n", remote_address)
                end
            end,
        })
        return new_m
    else
        return cartesi.new()
    end
end

local runtime_config = {
    concurrency = {
        update_merkle_tree = concurrency_update_merkle_tree,
    },
    htif = {
        no_console_putchar = htif_no_console_putchar,
    },
    skip_root_hash_check = skip_root_hash_check,
    skip_root_hash_store = skip_root_hash_store,
    skip_version_check = skip_version_check,
}

if remote_spawn then
    local jsonrpc = require("cartesi.jsonrpc")
    local server <close>, address, pid = jsonrpc.spawn_server(remote_address)
    server:set_cleanup_call(jsonrpc.NOTHING) -- we will perform shutdown manually
    stderr("Spawned JSONRPC remote cartesi machine at '%s' with pid %d\n", address, pid)
    remote_address = address
end

local main_machine
if remote_address and not remote_create then
    main_machine = new_machine()
elseif load_dir then
    stderr("Loading machine: please wait\n")
    main_machine = new_machine():load(load_dir, runtime_config)
else
    -- Build machine config
    local config = {
        processor = {
            iunrep = unreproducible and 1 or 0,
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
        virtio = virtio,
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
    if #append_init > 0 then config.dtb.init = config.dtb.init .. append_init end
    if #append_entrypoint > 0 then config.dtb.entrypoint = config.dtb.entrypoint .. append_entrypoint end
    if #exec_arguments > 0 then config.dtb.entrypoint = config.dtb.entrypoint .. table.concat(exec_arguments, " ") end

    if load_config then
        local env = {}
        local chunk, err = loadfile(load_config, "t", env)
        if not chunk then
            stderr("Failed to load machine config (%s):\n", load_config)
            error(err)
        end
        local ok, ret = pcall(chunk)
        if not ok then
            stderr("Failed to load machine config (%s):\n", load_config)
            error(ret)
        end
        config = setmetatable(ret, { __index = config })
    elseif load_json_config then
        local f <close> = assert(io.open(load_json_config, "rb"))
        config = setmetatable(cartesi.fromjson(f:read("a")), { __index = config })
    end

    main_machine = new_machine():create(config, runtime_config)
end

for _, r in ipairs(memory_range_replace) do
    main_machine:replace_memory_range(r.start, r.length, r.shared, r.image_filename)
end

local function dump_config(what, whatdef, out, indent)
    if type(what) == "table" then
        local next_indent = indent .. "  "
        local keys = {}
        for k in pairs(what) do
            table.insert(keys, k)
        end
        table.sort(keys)
        if #keys > 0 then
            out:write("{\n")
            for _, k in ipairs(keys) do
                local v, vdef = what[k], whatdef and whatdef[k]
                out:write(next_indent)
                if type(k) == "string" then out:write(k, " = ") end
                dump_config(v, vdef, out, next_indent)
                out:write(",")
                if v == vdef then out:write(" -- default") end
                out:write("\n")
            end
            out:write(indent, "}")
        else
            out:write("{}")
        end
    elseif math.type(what) == "integer" then
        out:write(string.format("0x%x", what))
    else
        out:write(string.format("%q", what))
    end
end

local function serialize_config(out, config, format)
    if format == "json" then
        out:write(cartesi.tojson(config, 2), "\n")
    elseif format == "lua" then
        out:write("return ")
        dump_config(config, default_config, out, "")
        out:write("\n")
    end
end

-- obtain config from instantiated machine
local main_config = main_machine:get_initial_config()

if type(store_config) == "string" then
    local f <close> = assert(io.open(store_config, "w"))
    serialize_config(f, main_config, "lua")
elseif store_config then
    serialize_config(io.stdout, main_config, "lua")
end

if type(store_json_config) == "string" then
    local f <close> = assert(io.open(store_json_config, "w"))
    serialize_config(f, main_config, "json")
elseif store_json_config then
    serialize_config(io.stdout, main_config, "json")
end

local cmio_yield_automatic_reason = {
    [cartesi.CMIO_YIELD_AUTOMATIC_REASON_PROGRESS] = "progress",
    [cartesi.CMIO_YIELD_AUTOMATIC_REASON_TX_OUTPUT] = "tx-output",
    [cartesi.CMIO_YIELD_AUTOMATIC_REASON_TX_REPORT] = "tx-report",
}

local cmio_yield_manual_reason = {
    [cartesi.CMIO_YIELD_MANUAL_REASON_RX_ACCEPTED] = "rx-accepted",
    [cartesi.CMIO_YIELD_MANUAL_REASON_RX_REJECTED] = "rx-rejected",
    [cartesi.CMIO_YIELD_MANUAL_REASON_TX_EXCEPTION] = "tx-exception",
}

local cmio_yield_command = {
    [cartesi.CMIO_YIELD_COMMAND_MANUAL] = "Manual",
    [cartesi.CMIO_YIELD_COMMAND_AUTOMATIC] = "Automatic",
}

local function check_cmio_htif_config(htif)
    assert(not htif.console_getchar, "console getchar must be disabled for cmio")
    assert(htif.yield_manual, "yield manual must be enabled for cmio")
    assert(htif.yield_automatic, "yield automatic must be enabled for cmio")
end

local function get_and_print_yield(machine, htif)
    local cmd, reason, data = machine:receive_cmio_request()
    if cmd == cartesi.CMIO_YIELD_COMMAND_AUTOMATIC and reason == cartesi.CMIO_YIELD_AUTOMATIC_REASON_PROGRESS then
        stderr("Progress: %6.2f" .. (htif.console_getchar and "\n" or "\r"), string.unpack("I4", data) / 10)
        return cmd, reason, data
    end
    local cmd_str = cmio_yield_command[cmd] or "Unknown"
    local reason_str = "unknown"
    if cmd == cartesi.CMIO_YIELD_COMMAND_AUTOMATIC then
        reason_str = cmio_yield_automatic_reason[reason] or reason_str
    elseif cmd == cartesi.CMIO_YIELD_COMMAND_MANUAL then
        reason_str = cmio_yield_manual_reason[reason] or reason_str
    end
    stderr("\n%s yield %s (%d) (0x%06x data)\n", cmd_str, reason_str, reason, #data)
    stderr("Cycles: %u\n", machine:read_reg("mcycle"))
    return cmd, reason, data
end

local function instantiate_filename(pattern, values)
    -- replace escaped % with something safe
    pattern = string.gsub(pattern, "%\\%%", "\0")
    pattern = string.gsub(pattern, "%%(%a)", function(s) return values[s] or s end)
    -- restore escaped %
    return (string.gsub(pattern, "\0", "%"))
end

local function save_cmio_state_with_format(advance, data, format, index)
    local values = { i = advance.next_input_index - 1, o = index }
    local name = instantiate_filename(format, values)
    stderr("Storing %s\n", name)
    local f = assert(io.open(name, "wb"))
    assert(f:write(data))
    f:close()
end

local function save_cmio_report(advance, data)
    return save_cmio_state_with_format(advance, data, advance.report, advance.report_index)
end

local function save_cmio_output(advance, data)
    return save_cmio_state_with_format(advance, data, advance.output, advance.output_index)
end

local function save_cmio_output_hashes_root_hash(advance, data)
    return save_cmio_state_with_format(advance, data, advance.output_hashes_root_hash)
end

local function load_cmio_input(machine, advance)
    local values = { i = advance.next_input_index }
    local filename = instantiate_filename(advance.input, values)
    local f = assert(io.open(filename, "rb"))
    local data = assert(f:read("*a"))
    f:close()
    machine:send_cmio_response(cartesi.CMIO_YIELD_REASON_ADVANCE_STATE, data)
end

local function load_cmio_query(machine, inspect)
    local f = assert(io.open(inspect.query, "rb"))
    local data = assert(f:read("*a"))
    f:close()
    machine:send_cmio_response(cartesi.CMIO_YIELD_REASON_INSPECT_STATE, data)
end

local function save_cmio_inspect_state_report(inspect, data)
    local values = { o = inspect.report_index }
    local name = instantiate_filename(inspect.report, values)
    stderr("Storing %s\n", name)
    local f = assert(io.open(name, "wb"))
    assert(f:write(data))
    f:close()
end

local function store_machine(machine, config, dir)
    assert(config.processor.iunrep == 0, "hashes are meaningless in unreproducible mode")
    stderr("Storing machine: please wait\n")
    local values = {}
    if dir:find("%%h") then values.h = util.hexhash(machine:get_root_hash()) end
    local name = instantiate_filename(dir, values)
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
if config.processor.iunrep ~= 0 then stderr("Running in unreproducible mode!\n") end
if cmio_advance or cmio_inspect then
    check_cmio_htif_config(config.htif)
    assert(remote_address or not perform_rollbacks, "cmio requires --remote-address for snapshot/commit/rollback")
end
if initial_hash then
    assert(config.processor.iunrep == 0, "hashes are meaningless in unreproducible mode")
    print_root_hash(machine, stderr_unsilenceable)
end
dump_value_proofs(machine, initial_proof, config)
local exit_code = 0
local next_hash_mcycle
if periodic_hashes_start ~= 0 then
    next_hash_mcycle = periodic_hashes_start
else
    next_hash_mcycle = periodic_hashes_period
end

-- To snapshot, we fork the current machine server to create a backup of the current machine.
-- We leave the backup server alone, and keep going with the current server.
-- If we already had a backup server, we simply shut it down.
local backup_machine = nil
local function do_snapshot(m)
    if perform_rollbacks then
        if backup_machine then backup_machine:shutdown_server() end
        backup_machine = m:fork_server()
    end
end

-- To commit, we simply shut down the backup server.
local function do_commit()
    if perform_rollbacks then
        if backup_machine then
            backup_machine:shutdown_server()
            backup_machine = nil
        end
    end
end

-- To rollback, we get rid of the current machine server, then rebind the backup
-- server with the address of the original one, and start communicating with it instead
local function do_rollback(m)
    if perform_rollbacks then
        assert(backup_machine, "no snapshot to rollback to")
        local address = m:get_server_address()
        m:shutdown_server()
        m:swap(backup_machine)
        m:rebind_server(address)
        backup_machine = nil
    end
end

-- Make sure we do not leave backup servers lying around when we exit.
-- luacheck: push ignore 211
local backup_closer <close> = setmetatable({}, {
    __close = function()
        -- If we have a backup on exit, we probably raised an error, so we rollback
        if backup_machine then do_rollback(machine) end
    end,
})
-- luacheck: pop

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
while math.ult(machine:read_reg("mcycle"), max_mcycle) do
    local next_mcycle = math.min(next_hash_mcycle, max_mcycle)
    if gdb_stub and gdb_stub:is_connected() then
        gdb_stub:run(next_mcycle)
    else
        machine:run(next_mcycle)
    end
    -- deal with halt
    if machine:read_reg("iflags_H") ~= 0 then
        exit_code = machine:read_reg("htif_tohost_data") >> 1
        if exit_code ~= 0 then
            stderr("\nHalted with payload: %u\n", exit_code)
        else
            stderr("\nHalted\n")
        end
        stderr("Cycles: %u\n", machine:read_reg("mcycle"))
        break
    -- deal with yield manual
    elseif machine:read_reg("iflags_Y") ~= 0 then
        local _, reason, data = get_and_print_yield(machine, config.htif)
        -- there was an exception
        if reason == cartesi.CMIO_YIELD_MANUAL_REASON_TX_EXCEPTION then
            stderr("cmio exception with payload: %q\n", data)
            exit_code = 1
            do_rollback(machine)
            break
        -- there are advance state inputs to feed
        elseif cmio_advance and cmio_advance.next_input_index < cmio_advance.input_index_end then
            -- previous reason was an accept
            if reason == cartesi.CMIO_YIELD_MANUAL_REASON_RX_ACCEPTED then
                do_commit()
                -- save only if we have already run an input and have just accepted it
                if cmio_advance.next_input_index > cmio_advance.input_index_begin then
                    assert(#data == 32, "expected root hash in tx buffer")
                    save_cmio_output_hashes_root_hash(cmio_advance, data)
                end
            -- previous reason was a reject
            elseif reason == cartesi.CMIO_YIELD_MANUAL_REASON_RX_REJECTED then
                do_rollback(machine)
            else
                error("unexpected manual yield reason")
            end
            stderr("\nBefore input %d\n", cmio_advance.next_input_index)
            if cmio_advance.hashes then print_root_hash(machine) end
            do_snapshot(machine)
            load_cmio_input(machine, cmio_advance)
            if cmio_advance.hashes then print_root_hash(machine) end
            cmio_advance.output_index = 0
            cmio_advance.report_index = 0
            cmio_advance.next_input_index = cmio_advance.next_input_index + 1
        else
            if cmio_advance and cmio_advance.next_input_index > cmio_advance.input_index_begin then
                -- there are outputs of a previous advance state to save
                if reason == cartesi.CMIO_YIELD_MANUAL_REASON_RX_ACCEPTED then
                    assert(#data == 32, "expected root hash in tx buffer")
                    save_cmio_output_hashes_root_hash(cmio_advance, data)
                    do_commit()
                elseif reason == cartesi.CMIO_YIELD_MANUAL_REASON_RX_REJECTED then
                    do_rollback(machine)
                end
                cmio_advance = nil
            end
            -- not done with inspect state query
            if cmio_inspect then
                -- haven't even fed it
                if cmio_inspect.query then
                    stderr("\nBefore query\n")
                    if cmio_inspect.hashes then print_root_hash(machine) end
                    do_snapshot(machine)
                    load_cmio_query(machine, cmio_inspect)
                    if cmio_inspect.hashes then print_root_hash(machine) end
                    cmio_inspect.report_index = 0
                    cmio_inspect.query = nil
                -- fed it already
                else
                    stderr("\nAfter query\n")
                    do_rollback(machine)
                    cmio_inspect = nil
                end
            end
        end
    -- deal with yield automatic
    elseif machine:read_reg("iflags_X") ~= 0 then
        local _, reason, data = get_and_print_yield(machine, config.htif)
        -- we have fed an advance state input
        if cmio_advance and cmio_advance.next_input_index > cmio_advance.input_index_begin then
            if reason == cartesi.CMIO_YIELD_AUTOMATIC_REASON_TX_OUTPUT then
                save_cmio_output(cmio_advance, data)
                cmio_advance.output_index = cmio_advance.output_index + 1
            elseif reason == cartesi.CMIO_YIELD_AUTOMATIC_REASON_TX_REPORT then
                save_cmio_report(cmio_advance, data)
                cmio_advance.report_index = cmio_advance.report_index + 1
            end
        -- ignore other reasons
        -- we have feed the inspect state query
        elseif cmio_inspect and not cmio_inspect.query then
            if reason == cartesi.CMIO_YIELD_AUTOMATIC_REASON_TX_REPORT then
                save_cmio_inspect_state_report(cmio_inspect, data)
                cmio_inspect.report_index = cmio_inspect.report_index + 1
            end
            -- ignore other reasons
        end
        -- otherwise ignore
    end
    if machine:read_reg("iflags_Y") ~= 0 then
        -- commit any pending snapshot
        do_commit()
        break
    end
    if machine:read_reg("mcycle") == next_hash_mcycle then
        print_root_hash(machine)
        next_hash_mcycle = next_hash_mcycle + periodic_hashes_period
    end
end
-- log step
if log_step_mcycle_count then
    stderr(string.format("Logging step of %d cycles to %s\n", log_step_mcycle_count, log_step_filename))
    print_root_hash(machine, stderr_unsilenceable)
    machine:log_step(log_step_mcycle_count, log_step_filename)
    print_root_hash(machine, stderr_unsilenceable)
end
-- Advance micro cycles
if max_uarch_cycle > 0 then
    -- Save halt flag before micro cycles
    local previously_halted = machine:read_reg("iflags_H") ~= 0
    if machine:run_uarch(max_uarch_cycle) == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then
        -- Microarchitecture  halted. This means that one "macro" instruction was totally executed
        -- The mcycle counter was incremented, unless the machine was already halted
        if machine:read_reg("iflags_H") ~= 0 and not previously_halted then stderr("Halted\n") end
        stderr("Cycles: %u\n", machine:read_reg("mcycle"))
        if auto_reset_uarch then
            machine:reset_uarch()
        else
            stderr("uCycles: %u\n", machine:read_reg("uarch_cycle"))
        end
    end
end
if gdb_stub then gdb_stub:close() end
if log_step_uarch then
    assert(config.processor.iunrep == 0, "micro step proof is meaningless in unreproducible mode")
    stderr("Gathering micro step log: please wait\n")
    util.dump_log(machine:log_step_uarch(cartesi.ACCESS_LOG_TYPE_ANNOTATIONS), io.stderr)
end
if log_reset_uarch then
    stderr("Resetting microarchitecture state: please wait\n")
    util.dump_log(machine:log_reset_uarch(cartesi.ACCESS_LOG_TYPE_ANNOTATIONS), io.stderr)
end
if dump_memory_ranges then dump_pmas(machine) end
if final_hash then
    assert(config.processor.iunrep == 0, "hashes are meaningless in unreproducible mode")
    print_root_hash(machine, stderr_unsilenceable)
end
dump_value_proofs(machine, final_proof, config)
if store_dir then store_machine(machine, config, store_dir) end
if assert_rolling_template then
    local cmd, reason = machine:receive_cmio_request()
    if not (cmd == cartesi.CMIO_YIELD_COMMAND_MANUAL and reason == cartesi.CMIO_YIELD_MANUAL_REASON_RX_ACCEPTED) then
        exit_code = 2
    end
end
if not remote_address or remote_destroy then machine:destroy() end
os.exit(exit_code, true)
