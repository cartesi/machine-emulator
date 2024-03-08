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
    use existing cartesi machine in the remote server instead of creating
    a new one.

  --no-remote-destroy
    do not destroy the cartesi machine in the remote server after the execution.

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
    replaces an existing flash drive or rollup memory range right after
    machine instantiation.
    (typically used in conjunction with the --load=<directory> option.)

    <key>:<value> is one of
        filename:<filename>
        start:<number>
        length:<number>
        shared

    semantics are the same as for the --flash-drive option with the following
    difference: start and length are mandatory, and must match those of a
    previously existing flash drive or rollup memory memory range.

  --rollup-rx-buffer=<key>:<value>[,<key>:<value>[,...]...]
  --rollup-tx-buffer=<key>:<value>[,<key>:<value>[,...]...]
  --rollup-input-metadata=<key>:<value>[,<key>:<value>[,...]...]
  --rollup-voucher-hashes=<key>:<value>[,<key>:<value>[,...]...]
  --rollup-notice-hashes=<key>:<value>[,<key>:<value>[,...]...]
    defines the individual the memory ranges used by rollups.

    <key>:<value> is one of
        filename:<filename>
        start:<number>
        length:<number>
        shared

    semantics are the same as for the --flash-drive option with the following
    difference: start and length are mandatory.

  --no-rollup
    do not define values for rollup-rx-buffer, rollup-tx-buffer,
    rollup-input-metadata, rollup-voucher-hashes, rollup-notice hashes,
    and htif yield for use with rollups.
    default defined values are equivalent to the following options:

    --rollup-rx-buffer=start:0x60000000,length:2<<20
    --rollup-tx-buffer=start:0x60200000,length:2<<20
    --rollup-input-metadata=start:0x60400000,length:4096
    --rollup-voucher-hashes=start:0x60600000,length:2<<20
    --rollup-notice-hashes=start:0x60800000,length:2<<20

  --rollup-advance-state=<key>:<value>[,<key>:<value>[,...]...]
    advances the state of the machine through a number of inputs in an epoch

    <key>:<value> is one of
        epoch_index:<number>
        input:<filename-pattern>
        input_metadata:<filename-pattern>
        input_index_begin:<number>
        input_index_end:<number>
        voucher:<filename-pattern>
        voucher_hashes: <filename>
        notice:<filename-pattern>
        notice_hashes: <filename>
        report:<filename-pattern>
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

        input_metadata (default: "epoch-%%e-input-metadata-%%i.bin")
        the pattern that derives the name of the file read for
        input metadata %%i of epoch index %%e.

        voucher (default: "epoch-%%e-input-%%i-voucher-%%o.bin")
        the pattern that derives the name of the file written for voucher %%o
        of input %%i of epoch %%e.

        voucher_hashes (default: "epoch-%%e-input-%%i-voucher-hashes.bin")
        the pattern that derives the name of the file written for the voucher
        hashes of input %%i of epoch %%e.

        notice (default: "epoch-%%e-input-%%i-notice-%%o.bin")
        the pattern that derives the name of the file written for notice %%o
        of input %%i of epoch %%e.

        notice_hashes (default: "epoch-%%e-input-%%i-notice-hashes.bin")
        the pattern that derives the name of the file written for the notice
        hashes of input %%i of epoch %%e.

        report (default: "epoch-%%e-input-%%i-report-%%o.bin")
        the pattern that derives the name of the file written for report %%o
        of input %%i of epoch %%e.

        hashes
        print out hashes before every input.

    the input index ranges in {input_index_begin, ..., input_index_end-1}.
    for each input, "%%e" is replaced by the epoch index, "%%i" by the
    input index, and "%%o" by the voucher, notice, or report index.

  --rollup-inspect-state=<key>:<value>[,<key>:<value>[,...]...]
    inspect the state of the machine with a query.
    the query happens after the end of --rollup-advance-state.

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
    suppress any console output during machine run.
    this includes anything written to machine's stdout or stderr.

  --skip-root-hash-check
    skip merkle tree root hash check when loading a stored machine.
    i.e., assume the stored machine files are not corrupt.
    this is only intended to speed up machine loading in emulator tests.

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
    host directory in the guest.
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
    exit with failure in case the generated machine is not compatible with
    Rolling Cartesi Machine templates.

  --quiet
    suppress cartesi-machine.lua output.
    exceptions: --initial-hash, --final-hash and text emitted from the target.

  --no-init-splash
    don't show cartesi machine splash on boot.

  --no-default-init
    don't use cartesi machine default init value (USER=dapp)

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

  --gdb[=<address>]
    listen at <address> and wait for a GDB connection to debug the machine.
    if <address> is omitted, '127.0.0.1:1234' is used by default.
    the host GDB client must have support for RISC-V architecture.

    host GDB can connect with the following command:
        gdb -ex "set arch riscv:rv64" -ex "target remote <address>" [elf]

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
local unreproducible = false
local virtio = {}
local virtio_net_user_config = false
local virtio_volume_count = 0
local has_virtio_console = false
local has_network = false
local has_sync_init_date = false
local memory_range_replace = {}
local ram_image_filename = images_path .. "linux.bin"
local ram_length = 128 << 20 -- 128MB
local dtb_image_filename = nil
local bootargs = "quiet earlycon=sbi console=hvc0"
    -- rootfs related arguments must come at the end to be replaced by --no-root-flash-drive
    .. " rootfstype=ext2 root=/dev/pmem0 rw init=/usr/sbin/cartesi-init"
local init_splash = true
local append_bootargs = ""
local default_init = "busybox stty -onlcr\nUSER=dapp\n"
local append_init = ""
local append_entrypoint = ""
local rollup = {
    rx_buffer = { start = 0x60000000, length = 2 << 20 },
    tx_buffer = { start = 0x60200000, length = 2 << 20 },
    input_metadata = { start = 0x60400000, length = 4096 },
    voucher_hashes = { start = 0x60600000, length = 2 << 20 },
    notice_hashes = { start = 0x60800000, length = 2 << 20 },
}
local uarch
local rollup_advance
local rollup_inspect
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
echo 'nameserver 10.0.2.3' > /etc/resolv.conf
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
        "^%-%-no%-rollup$",
        function(all)
            if not all then return false end
            rollup = nil
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
        "^(%-%-rollup%-advance%-state%=(.+))$",
        function(all, opts)
            if not opts then return false end
            local r = util.parse_options(opts, {
                epoch_index = true,
                input = true,
                input_metadata = true,
                input_index_begin = true,
                input_index_end = true,
                voucher = true,
                voucher_hashes = true,
                notice = true,
                notice_hashes = true,
                report = true,
                hashes = true,
            })
            assert(not r.hashes or r.hashes == true, "invalid hashes value in " .. all)
            r.epoch_index = assert(util.parse_number(r.epoch_index), "invalid epoch index in " .. all)
            r.input = r.input or "epoch-%e-input-%i.bin"
            r.input_metadata = r.input_metadata or "epoch-%e-input-metadata-%i.bin"
            r.input_index_begin = r.input_index_begin or 0
            r.input_index_begin = assert(util.parse_number(r.input_index_begin), "invalid input index begin in " .. all)
            r.input_index_end = r.input_index_end or 0
            r.input_index_end = assert(util.parse_number(r.input_index_end), "invalid input index end in " .. all)
            r.voucher = r.voucher or "epoch-%e-input-%i-voucher-%o.bin"
            r.voucher_hashes = r.voucher_hashes or "epoch-%e-input-%i-voucher-hashes.bin"
            r.notice = r.notice or "epoch-%e-input-%i-notice-%o.bin"
            r.notice_hashes = r.notice_hashes or "epoch-%e-input-%i-notice-hashes.bin"
            r.report = r.report or "epoch-%e-input-%i-report-%o.bin"
            r.next_input_index = r.input_index_begin
            rollup_advance = r
            return true
        end,
    },
    {
        "^(%-%-rollup%-inspect%-state%=(.+))$",
        function(_, opts)
            if not opts then return false end
            local r = util.parse_options(opts, {
                query = true,
                report = true,
            })
            r.query = r.query or "query.bin"
            r.report = r.report or "query-report-%o.bin"
            rollup_inspect = r
            return true
        end,
    },
    {
        "^%-%-rollup%-inspect%-state$",
        function(all)
            if not all then return false end
            rollup_inspect = {
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
            bootargs = bootargs:gsub(" rootfstype=.*$", "")
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
        "^(%-%-rollup%-rx%-buffer%=(.+))$",
        function(all, opts)
            if not opts then return false end
            rollup = rollup or {}
            rollup.rx_buffer = parse_memory_range(opts, "rollup rx buffer", all)
            return true
        end,
    },
    {
        "^(%-%-rollup%-tx%-buffer%=(.+))$",
        function(all, opts)
            if not opts then return false end
            rollup = rollup or {}
            rollup.tx_buffer = parse_memory_range(opts, "tx buffer", all)
            return true
        end,
    },
    {
        "^(%-%-rollup%-input%-metadata%=(.+))$",
        function(all, opts)
            if not opts then return false end
            rollup = rollup or {}
            rollup.input_metadata = parse_memory_range(opts, "rollup input metadata", all)
            return true
        end,
    },
    {
        "^(%-%-rollup%-voucher%-hashes%=(.+))$",
        function(all, opts)
            if not opts then return false end
            rollup = rollup or {}
            rollup.voucher_hashes = parse_memory_range(opts, "rollup voucher hashes", all)
            return true
        end,
    },
    {
        "^(%-%-rollup%-notice%-hashes%=(.+))$",
        function(all, opts)
            if not opts then return false end
            rollup = rollup or {}
            rollup.notice_hashes = parse_memory_range(opts, "rollup notice hashes", all)
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

local function store_value(key, value, indent, output)
    -- skip empty values
    if value == nil or (type(value) == "table" and next(value) == nil) then return end
    -- add key
    if key ~= nil then
        output("%s%s = ", indent, key)
    else
        output("%s", indent)
    end
    -- add value
    if type(value) == "table" then
        output("{\n", key)
        if type(next(value)) == "string" then
            for k, v in pairs(value) do
                store_value(k, v, "  " .. indent, output)
            end
        elseif #value > 0 then
            for _, v in ipairs(value) do
                store_value(nil, v, "  " .. indent, output)
            end
        end
        output("%s},\n", indent)
    elseif type(value) == "string" then
        output('"%s",\n', value)
    else
        output("%s,\n", value)
    end
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
    local plic = config.plic or {}
    output("  plic = {\n")
    output("    girqpend = 0x%x,", plic.girqpend or def.plic.girqpend)
    output("    girqsrvd = 0x%x,", plic.girqsrvd or def.plic.girqsrvd)
    comment_default(plic.girqpend, def.plic.girqpend)
    output("  },\n")
    output("  flash_drive = {\n")
    for _, f in ipairs(config.flash_drive) do
        output("    ")
        store_memory_range(f, "    ", output)
    end
    output("  },\n")
    store_value("virtio", config.virtio, "  ", output)
    if config.rollup then
        output("  rollup = {\n")
        output("    rx_buffer = ")
        store_memory_range(config.rollup.rx_buffer, "    ", output)
        output("    tx_buffer = ")
        store_memory_range(config.rollup.tx_buffer, "    ", output)
        output("    input_metadata = ")
        store_memory_range(config.rollup.input_metadata, "    ", output)
        output("    voucher_hashes = ")
        store_memory_range(config.rollup.voucher_hashes, "    ", output)
        output("    notice_hashes = ")
        store_memory_range(config.rollup.notice_hashes, "    ", output)
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
        rollup = rollup,
        uarch = uarch,
        flash_drive = {},
        virtio = virtio,
    }

    -- show splash on init
    if init_splash then
        config.dtb.init = config.dtb.init
            .. ([[
busybox stty -onlcr; cat <<EOF
         .
        / \
      /    \
\---/---\  /----\
 \       X       \
  \----/  \---/---\
       \    / CARTESI
        \ /   MACHINE
         '

EOF
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

local htif_yield_reason = {
    [cartesi.machine.HTIF_YIELD_REASON_PROGRESS] = "progress",
    [cartesi.machine.HTIF_YIELD_REASON_RX_ACCEPTED] = "rx-accepted",
    [cartesi.machine.HTIF_YIELD_REASON_RX_REJECTED] = "rx-rejected",
    [cartesi.machine.HTIF_YIELD_REASON_TX_VOUCHER] = "tx-voucher",
    [cartesi.machine.HTIF_YIELD_REASON_TX_NOTICE] = "tx-notice",
    [cartesi.machine.HTIF_YIELD_REASON_TX_REPORT] = "tx-report",
    [cartesi.machine.HTIF_YIELD_REASON_TX_EXCEPTION] = "tx-exception",
}

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

local function check_rollup_memory_range_config(range, name)
    assert(range, string.format("rollup range %s must be defined", name))
    assert(not range.shared, string.format("rollup range %s cannot be shared", name))
    assert(
        is_power_of_two(range.length),
        string.format("rollup range %s length not a power of two (%u)", name, range.length)
    )
    local log = ilog2(range.length)
    local aligned_start = (range.start >> log) << log
    assert(
        aligned_start == range.start,
        string.format("rollup range %s start not aligned to its power of two size", name)
    )
    range.image_filename = nil
end

local function check_rollup_htif_config(htif)
    assert(htif.yield_manual, "yield manual must be enabled for rollup")
    assert(htif.yield_automatic, "yield automatic must be enabled for rollup")
end

local function get_yield(machine)
    local cmd = machine:read_htif_tohost_cmd()
    local data = machine:read_htif_tohost_data()
    local reason = data >> 32
    return cmd, reason, data
end

local function get_and_print_yield(machine, htif)
    local cmd, reason, data = get_yield(machine)
    if cmd == cartesi.machine.HTIF_YIELD_AUTOMATIC and reason == cartesi.machine.HTIF_YIELD_REASON_PROGRESS then
        stderr("Progress: %6.2f" .. (htif.console_getchar and "\n" or "\r"), data / 10)
    else
        local cmd_str = htif_yield_mode[cmd] or "Unknown"
        local reason_str = htif_yield_reason[reason] or "unknown"
        stderr("\n%s yield %s (0x%06x data)\n", cmd_str, reason_str, data)
        stderr("Cycles: %u\n", machine:read_mcycle())
    end
    return cmd, reason, data
end

local function save_rollup_hashes(machine, range, filename)
    stderr("Storing %s\n", filename)
    local hash_len = 32
    local f = assert(io.open(filename, "wb"))
    local zeros = string.rep("\0", hash_len)
    local offset = 0
    while offset < range.length do
        local hash = machine:read_memory(range.start + offset, 32)
        if hash == zeros then break end
        assert(f:write(hash))
        offset = offset + hash_len
    end
    f:close()
end

local function instantiate_filename(pattern, values)
    -- replace escaped % with something safe
    pattern = string.gsub(pattern, "%\\%%", "\0")
    pattern = string.gsub(pattern, "%%(%a)", function(s) return values[s] or s end)
    -- restore escaped %
    return (string.gsub(pattern, "\0", "%"))
end

local function save_rollup_voucher_and_notice_hashes(machine, config, advance)
    local values = { e = advance.epoch_index, i = advance.next_input_index - 1 }
    save_rollup_hashes(machine, config.voucher_hashes, instantiate_filename(advance.voucher_hashes, values))
    save_rollup_hashes(machine, config.notice_hashes, instantiate_filename(advance.notice_hashes, values))
end

local function load_memory_range(machine, config, filename)
    stderr("Loading %s\n", filename)
    local f = assert(io.open(filename, "rb"))
    local s = assert(f:read("*a"))
    f:close()
    machine:write_memory(config.start, s)
end

local function load_rollup_input_and_metadata(machine, config, advance)
    local values = { e = advance.epoch_index, i = advance.next_input_index }
    machine:replace_memory_range(config.input_metadata) -- clear
    load_memory_range(machine, config.input_metadata, instantiate_filename(advance.input_metadata, values))
    machine:replace_memory_range(config.rx_buffer) -- clear
    load_memory_range(machine, config.rx_buffer, instantiate_filename(advance.input, values))
    machine:replace_memory_range(config.voucher_hashes) -- clear
    machine:replace_memory_range(config.notice_hashes) -- clear
end

local function load_rollup_query(machine, config, inspect)
    machine:replace_memory_range(config.rx_buffer) -- clear
    load_memory_range(machine, config.rx_buffer, inspect.query) -- load query payload
end

local function save_rollup_advance_state_voucher(machine, config, advance)
    local values = { e = advance.epoch_index, i = advance.next_input_index - 1, o = advance.voucher_index }
    local name = instantiate_filename(advance.voucher, values)
    stderr("Storing %s\n", name)
    local f = assert(io.open(name, "wb"))
    -- skip address and offset to reach payload length
    local length = string.unpack(">I8", machine:read_memory(config.start + 3 * 32 - 8, 8))
    -- add address, offset, and payload length to amount to be read
    length = length + 3 * 32
    assert(f:write(machine:read_memory(config.start, length)))
    f:close()
end

local function save_rollup_advance_state_notice(machine, config, advance)
    local values = { e = advance.epoch_index, i = advance.next_input_index - 1, o = advance.notice_index }
    local name = instantiate_filename(advance.notice, values)
    stderr("Storing %s\n", name)
    local f = assert(io.open(name, "wb"))
    -- skip offset to reach payload length
    local length = string.unpack(">I8", machine:read_memory(config.start + 2 * 32 - 8, 8))
    -- add offset and payload length to amount to be read
    length = length + 2 * 32
    assert(f:write(machine:read_memory(config.start, length)))
    f:close()
end

local function dump_exception(machine, config)
    -- skip offset to reach payload length
    local length = string.unpack(">I8", machine:read_memory(config.start + 2 * 32 - 8, 8))
    -- add offset and payload length to amount to be read
    local payload = machine:read_memory(config.start + 2 * 32, length)
    stderr("Rollup exception with payload: %q\n", payload)
end

local function save_rollup_advance_state_report(machine, config, advance)
    local values = { e = advance.epoch_index, i = advance.next_input_index - 1, o = advance.report_index }
    local name = instantiate_filename(advance.report, values)
    stderr("Storing %s\n", name)
    local f = assert(io.open(name, "wb"))
    -- skip offset to reach payload length
    local length = string.unpack(">I8", machine:read_memory(config.start + 2 * 32 - 8, 8))
    -- add offset and payload length to amount to be read
    length = length + 2 * 32
    assert(f:write(machine:read_memory(config.start, length)))
    f:close()
end

local function save_rollup_inspect_state_report(machine, config, inspect)
    local values = { o = inspect.report_index }
    local name = instantiate_filename(inspect.report, values)
    stderr("Storing %s\n", name)
    local f = assert(io.open(name, "wb"))
    -- skip offset to reach payload length
    local length = string.unpack(">I8", machine:read_memory(config.start + 2 * 32 - 8, 8))
    -- add offset and payload length to amount to be read
    length = length + 2 * 32
    assert(f:write(machine:read_memory(config.start, length)))
    f:close()
end

local function store_machine(machine, config, dir)
    assert(config.processor.iunrep == 0, "hashes are meaningless in unreproducible mode")
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
if config.processor.iunrep ~= 0 then stderr("Running in unreproducible mode!\n") end
if store_config == stderr then store_machine_config(config, stderr) end
if rollup_advance or rollup_inspect then
    check_rollup_htif_config(config.htif)
    assert(config.rollup, "rollup device must be present")
    assert(remote_address, "rollup requires --remote-address for snapshot/rollback")
    check_rollup_memory_range_config(config.rollup.tx_buffer, "tx-buffer")
    check_rollup_memory_range_config(config.rollup.rx_buffer, "rx-buffer")
    check_rollup_memory_range_config(config.rollup.input_metadata, "input-metadata")
    check_rollup_memory_range_config(config.rollup.voucher_hashes, "voucher-hashes")
    check_rollup_memory_range_config(config.rollup.notice_hashes, "notice-hashes")
end
local cycles = machine:read_mcycle()
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
-- the loop runs at most until max_mcycle. iterations happen because
--   1) we stopped to print a hash
--   2) the machine halted, so iflags_H is set
--   3) the machine yielded manual, so iflags_Y is set
--   4) the machine yielded automatic, so iflags_X is set
-- if the user selected the rollup advance state, then at every yield manual we check the reason
-- if the reason is rx-rejected, we rollback, otherwise it must be rx-accepted.
-- we then feed the next input, reset iflags_Y, snapshot, and resume the machine
-- the machine can now continue processing and may yield automatic to produce vouchers, notices, and reports we save
-- once all inputs for advance state have been consumed, we check if the user selected rollup inspect state
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
        local _, reason = get_and_print_yield(machine, config.htif)
        -- there are advance state inputs to feed
        if reason == cartesi.machine.HTIF_YIELD_REASON_TX_EXCEPTION then
            dump_exception(machine, config.rollup.tx_buffer)
            exit_code = 1
        elseif rollup_advance and rollup_advance.next_input_index < rollup_advance.input_index_end then
            -- save only if we have already run an input
            if rollup_advance.next_input_index > rollup_advance.input_index_begin then
                save_rollup_voucher_and_notice_hashes(machine, config.rollup, rollup_advance)
            end
            if reason == cartesi.machine.HTIF_YIELD_REASON_RX_REJECTED then
                machine:rollback()
                cycles = machine:read_mcycle()
            else
                assert(reason == cartesi.machine.HTIF_YIELD_REASON_RX_ACCEPTED, "invalid manual yield reason")
            end
            stderr("\nEpoch %d before input %d\n", rollup_advance.epoch_index, rollup_advance.next_input_index)
            if rollup_advance.hashes then print_root_hash(machine) end
            machine:snapshot()
            load_rollup_input_and_metadata(machine, config.rollup, rollup_advance)
            if rollup_advance.hashes then print_root_hash(machine) end
            machine:reset_iflags_Y()
            machine:write_htif_fromhost_data(0) -- tell machine it is an rollup_advance state, but this is default
            rollup_advance.voucher_index = 0
            rollup_advance.notice_index = 0
            rollup_advance.report_index = 0
            rollup_advance.next_input_index = rollup_advance.next_input_index + 1
        else
            -- there are outputs of a prevous advance state to save
            if rollup_advance and rollup_advance.next_input_index > rollup_advance.input_index_begin then
                save_rollup_voucher_and_notice_hashes(machine, config.rollup, rollup_advance)
            end
            -- there is an inspect state query to feed
            if rollup_inspect and rollup_inspect.query then
                stderr("\nBefore query\n")
                load_rollup_query(machine, config.rollup, rollup_inspect)
                machine:reset_iflags_Y()
                machine:write_htif_fromhost_data(1) -- tell machine it is an inspect state
                rollup_inspect.report_index = 0
                rollup_inspect.query = nil
                rollup_advance = nil
            end
        end
    -- deal with yield automatic
    elseif machine:read_iflags_X() then
        local _, reason = get_and_print_yield(machine, config.htif)
        -- we have fed an advance state input
        if rollup_advance and rollup_advance.next_input_index > rollup_advance.input_index_begin then
            if reason == cartesi.machine.HTIF_YIELD_REASON_TX_VOUCHER then
                save_rollup_advance_state_voucher(machine, config.rollup.tx_buffer, rollup_advance)
                rollup_advance.voucher_index = rollup_advance.voucher_index + 1
            elseif reason == cartesi.machine.HTIF_YIELD_REASON_TX_NOTICE then
                save_rollup_advance_state_notice(machine, config.rollup.tx_buffer, rollup_advance)
                rollup_advance.notice_index = rollup_advance.notice_index + 1
            elseif reason == cartesi.machine.HTIF_YIELD_REASON_TX_REPORT then
                save_rollup_advance_state_report(machine, config.rollup.tx_buffer, rollup_advance)
                rollup_advance.report_index = rollup_advance.report_index + 1
            end
        -- ignore other reasons
        -- we have feed the inspect state query
        elseif rollup_inspect and not rollup_inspect.query then
            if reason == cartesi.machine.HTIF_YIELD_REASON_TX_REPORT then
                save_rollup_inspect_state_report(machine, config.rollup.tx_buffer, rollup_inspect)
                rollup_inspect.report_index = rollup_inspect.report_index + 1
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
    assert(config.processor.iunrep == 0, "micro step proof is meaningless in unreproducible mode")
    stderr("Gathering micro step log: please wait\n")
    util.dump_log(machine:log_uarch_step({ proofs = true, annotations = true }), io.stderr)
end
if log_uarch_reset then
    stderr("Resetting microarchitecture state: please wait\n")
    util.dump_log(machine:log_uarch_reset({ proofs = true, annotations = true }), io.stderr)
end
if dump_memory_ranges then dump_pmas(machine) end
if final_hash then
    assert(config.processor.iunrep == 0, "hashes are meaningless in unreproducible mode")
    print_root_hash(machine, stderr_unsilenceable)
end
dump_value_proofs(machine, final_proof, config)
if store_dir then store_machine(machine, config, store_dir) end
if assert_rolling_template then
    local cmd, reason = get_yield(machine)
    if not (cmd == cartesi.machine.HTIF_YIELD_MANUAL and reason == cartesi.machine.HTIF_YIELD_REASON_RX_ACCEPTED) then
        exit_code = 2
    end
end
if not remote or remote_destroy then machine:destroy() end
os.exit(exit_code, true)
