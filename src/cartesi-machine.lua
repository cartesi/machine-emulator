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

local bash = require("cartesi.bash")
-- forward compiled package declarations so handle_bash_completion can run clean
local cartesi, util, hash_tree
local MCYCLE_MAX

local function stderr_unsilenceable(fmt, ...) io.stderr:write(string.format(fmt, ...)) end
local stderr = stderr_unsilenceable

local function errorf(fmt, ...) error(string.format(fmt, ...), 2) end

local function assertf(value, fmt, ...)
    if value then return value, fmt, ... end
    error(string.format(fmt, ...), 2)
end

-- Unsigned minimum. Cycle counters are unsigned 64-bit integers, which math.min compares as signed.
local function umin(a, b)
    if math.ult(a, b) then return a end
    return b
end

-- Unsigned saturating addition, optionally limited to a maximum below MCYCLE_MAX.
local function usaturating_add(a, b, maximum)
    maximum = maximum or MCYCLE_MAX
    if math.ult(maximum, b) or math.ult(maximum - b, a) then return maximum end
    return a + b
end

-- Shortcuts for the break reason a run returns and the reason a manual yield carries.
local function is_halted(break_reason) return break_reason == cartesi.BREAK_REASON_HALTED end
local function is_mcycle_overflow(break_reason) return break_reason == cartesi.BREAK_REASON_MCYCLE_OVERFLOW end
local function is_yielded_manual(break_reason) return break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY end
local function is_yielded_automatic(break_reason) return break_reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY end
local function is_target_mcycle(break_reason) return break_reason == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE end
-- A machine stopped at a halt, a manual yield, or an mcycle overflow no longer advances on its own.
local function is_at_fixed_point(break_reason)
    return is_halted(break_reason) or is_yielded_manual(break_reason) or is_mcycle_overflow(break_reason)
end
local function is_rx_accepted(yield_reason) return yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED end
local function is_rx_rejected(yield_reason) return yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED end
local function is_tx_exception(yield_reason) return yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION end
local function is_tx_output(yield_reason) return yield_reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT end
local function is_tx_report(yield_reason) return yield_reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT end

local function adjust_images_path(path)
    if not path then return "" end
    return string.gsub(path, "/*$", "") .. "/"
end

-- Print help
local function print_help()
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

  --dump-constants
    print the constants of the cartesi Lua module to stdout and exit,
    one <NAME>=<value> shell assignment per line, sorted by name
    (e.g. CARTESI_HTIF_YIELD_MANUAL_REASON_RX_REJECTED=2).
    integer values that do not fit a signed 64-bit integer are printed in
    hexadecimal. string values are printed single-quoted, and constants
    with non-printable contents are omitted.
    intended for shell scripts:
        eval "$(cartesi-machine --dump-constants)"

  --bash-completion
    print a bash completion script for this program to stdout and exit.
    Install with: source <(cartesi-machine --bash-completion)

  --assert-version=<major>.<minor>[.<patch>]
    exit with failure in case the cartesi machine emulator version mismatches

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

  --revert-mode=<fork|stored|none>
    select how advance and inspect states are reverted (default: fork).

    fork snapshots by forking a remote machine server.

    stored snapshots a machine loaded from <directory> with sharing:all or
    created with --create=<directory> by cloning it to <directory>.revert.
    accepted state is synced before the snapshot is removed, and rejected or
    inspected state is replaced by the synced snapshot.

    none disables snapshots. inspect states and rejected advances are not reverted.

    DON'T USE revert-mode=none IN PRODUCTION

  --no-revert
    alias for --revert-mode=none.

  --ram-image=<filename>
    name of file containing RAM image (default: "linux.bin").

  --no-ram-image
    forget settings for RAM image.

  --ram-length=<number>
    set RAM length.

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
        start:<number>
        length:<number>
        data_filename:<filename>
        dht_filename:<filename>
        dpt_filename:<filename>
        shared
        create
        truncate
        read_only
        mke2fs
        mount:<string>
        user:<string>

        label (optional)
        identifies the flash drive. init attempts to mount it as /mnt/<label>.
        the machine always assigns the auto label "flashdriveN" (where N is
        the zero-based index). the user label is an optional additional alias
        that can be used to refer to the flash drive in --replace-memory-range.
        user labels must contain only lowercase letters, digits, and hyphens,
        must start with a lowercase letter, must not match flashdriveN or
        nvramN (reserved for auto-generated labels), must be unique across all
        flash drives and NVRAMs, and must be at most 31 characters long.
        if omitted, no user label is set.

        start (optional)
        sets the starting physical memory offset for flash drive in bytes.
        when omitted, flash drives' starts are computed automatically as follows:
        assume the lengths of RAM and of all flash drives are powers of two (otherwise,
        round them up to the next power of two for the purposes of this description).
        each flash drive starts at the lowest address that is aligned to its length and
        is past the end of the previous flash drive (or past the end of RAM, in the case
        of the first flash drive).
        flash drives with explicit starts are ignored by this computation, and overlaps
        with them are rejected when the machine is created.

        length (optional)
        gives the length of the flash drive in bytes (must be multiple of 4Ki).
        if omitted, the length is computed from the image in filename.
        if length and filename are set, the image file size must match length.

        data_filename (optional)
        gives the name of the file containing the data for the flash drive.
        when omitted or set to the empty, the drive starts filled with 0.

        dht_filename (optional)
        gives the name of the file containing the dense hash tree for the flash drive.
        (this is the part of the hash tree that subintends the entire address
        range for the drive, down to one hash per page.)
        when omitted or set to the empty, the hash tree will be built from scratch.

        dpt_filename (optional)
        gives the name of the file containing the dirty page tree for the flash drive.
        when omitted or set to the empty, the dirty page tree will be built from scratch.

        shared (optional)
        target modifications to flash drive modify the memory and hash tree files.
        by default, image files are not modified and changes are lost.

        create (optional)
        create the backing storage file, shared must also be true.

        truncate (optional)
        truncate the memory length to match memory lengths different from the backing storage,
        in case of shared flash drive, then it also truncates the underlying backing file.
        by default, when a length is present it must also match the backing storage length.

        read_only (optional)
        mark flash drive as read-only, disallowing write attempts from the host or the guest.
        by default, flash drives are not read-only, thus writable.

        mke2fs (optional)
        whether the flash drive should be formatted as an ext2 filesystem in init.
        by default, the drive is formatted as ext2 filesystem if there is no backing file,
        you can use "mke2fs:false" to disable ext2 formatting.

        mount (optional)
        whether the flash drive should be mounted automatically in init.
        by default, the drive is mounted if there is an image file backing it or is formatted (mke2fs option),
        you can use "mount:false" to disable auto mounting,
        you can also use "mount:<path>" to choose a custom mount point.

        user (optional)
        when mount is true, changes the user ownership of the mounted directory,
        otherwise changes the user ownership of the /dev/pmemX device.
        this option is useful to allow dapp's user access the flash drive.
        by default the mounted directory ownership is configured by the
        filesystem being mounted.
        in case mount is false, the default ownership is set to the root user.

    (an option "--flash-drive=label:root,data_filename:rootfs.ext2" is implicit)

  --nvram=<key>:<value>[,<key>:<value>[,...]...]
    defines a new NVRAM, or modify an existing NVRAM definition.
    NVRAMs use the UIO framework and appear as /dev/uio[0-7].
    unlike flash drives, NVRAMs have no filesystem layer.

    <key>:<value> is one of
        label:<label>
        start:<number>
        length:<number>
        data_filename:<filename>
        dht_filename:<filename>
        dpt_filename:<filename>
        shared
        create
        truncate
        read_only
        user:<string>

        label (optional)
        the machine always assigns the auto label "nvramN" (where N is the
        zero-based index). the user label is an optional additional alias that
        can be used to refer to the NVRAM in --replace-memory-range.
        user labels must contain only lowercase letters, digits, and hyphens,
        must start with a lowercase letter, must not match flashdriveN or
        nvramN (reserved for auto-generated labels), must be unique across all
        flash drives and NVRAMs, and must be at most 31 characters long.
        if omitted, no user label is set.

        start (optional)
        sets the starting physical memory offset for the NVRAM in bytes.
        when omitted, NVRAMs' starts are computed automatically as follows:
        assume the lengths of RAM and of all NVRAMs and flash drives are powers of two
        (otherwise, round them up to the next power of two for the purposes of this
        description).
        each NVRAM starts at the lowest address that is aligned to its length and is
        past the end of the previous NVRAM (in the case of the first NVRAM, past the
        end of the last automatically placed flash drive, or past the end of RAM if
        there is none).
        NVRAMs with explicit starts are ignored by this computation, and overlaps
        with them are rejected when the machine is created.

        length (optional)
        gives the length of the NVRAM in bytes (must be multiple of 4Ki).
        if omitted, the length is computed from the image in data_filename.

        data_filename (optional)
        gives the name of the file containing the data for the NVRAM.
        when omitted or set to empty, the NVRAM starts filled with 0.

        dht_filename, dpt_filename, shared, create, truncate, read_only
        semantics are the same as for the --flash-drive option.

        user (optional)
        changes the user ownership of the /dev/uioN device.
        this option is useful to allow dapp's user access the NVRAM.
        the default ownership is set to the root user.

  --replace-memory-range=<key>:<value>[,<key>:<value>[,...]...]
    replaces an existing memory range right after machine instantiation.
    (typically used in conjunction with the --load=<directory> option.)

    <key>:<value> is one of
        label:<string>
        start:<number>
        length:<number>
        data_filename:<filename>
        dht_filename:<filename>
        dpt_filename:<filename>
        shared

    the memory range can be identified by label, by start and length, or both.
    when both label and start/length are given, they must be consistent with
    the existing memory range. when only label is given, start and length are
    resolved from the machine's initial configuration.

  --ram=<key>:<value>[,<key>:<value>[,...]...]
  --dtb=<key>:<value>[,<key>:<value>[,...]...]
  --processor=<key>:<value>[,<key>:<value>[,...]...]
  --cmio-rx-buffer=<key>:<value>[,<key>:<value>[,...]...]
  --cmio-tx-buffer=<key>:<value>[,<key>:<value>[,...]...]
  --pmas=<key>:<value>[,<key>:<value>[,...]...]
  --uarch-ram=<key>:<value>[,<key>:<value>[,...]...]
  --uarch-processor=<key>:<value>[,<key>:<value>[,...]...]
    configures file storage for other memory ranges in the machine

    <key>:<value> is one of
        data_filename:<filename>
        dht_filename:<filename>
        dpt_filename:<filename>
        shared
        create
        truncate

    semantics are the same as for the --flash-drive option.

  --hash-tree=<key>:<value>[,<key>:<value>[,...]...]
    configures the global hash tree of the machine

    <key>:<value> is one of
        hash_function:<string>
        sht_filename:<filename>
        phtc_filename:<filename>
        phtc_size:<number>
        shared

        hash_function (default: "keccak256")
		hashing algorithm used for the tree

        sht_filename (optional)
        gives the name of the file containing the sparse hash-tree for the machine.
		(this is the part of the hash tree from the root down to leaves that subintend
        entire memory ranges, such as flash-drives or the ram.)
        when omitted or set to the empty, the hash tree will be built from scratch.

        phtc_filename (optional)
        gives the name of the file containing the page hash-tree cache for the machine.
        (this is a cache with the dense hash-trees for a subset of the pages in the
        machine, all the way down to 256-bit words.)
        when omitted or set to the empty, the page hash-tree cache will start empty.

        phtc_size (default: 2048)
        give the maximum number of pages in the cache.

        shared (optional)
        target modifications to machine state modify the sparse hash tree file.
        by default, the file is not modified and changes are lost.

  --cmio-advance-state=<key>:<value>[,<key>:<value>[,...]...]
    advances the state of the machine through a number of inputs.

    <key>:<value> is one of
        input:<filename-pattern>
        input_index_begin:<number>
        input_index_end:<number>
        output:<filename-pattern>
        rejected_output:<filename-pattern>
        output_proof:<filename-pattern>
        last_output_proof:<filename>
        format:<lua|json>
        report:<filename-pattern>
        outputs_merkle_root:<filename-pattern>
        outputs_merkle_root_proof:<filename-pattern>
        check_outputs_merkle_root:<boolean>
        print_input_state_hashes
        mcycle_computation_hash:<filename>
        log2_mcycle_computation_hash_period:<number>
        log2_bundle_mcycle_count:<number>
        uarch_cycle_computation_hash:<filename>
        mcycle_period_index:<number>
        log2_bundle_uarch_cycle_count:<number>

        any file pattern can be set to the empty string to disable writing
        that file.

        input (default: "input-%%i.bin")
        the pattern that derives the name of the file read for input %%i.

        input_index_begin (default: 0)
        index of first input to advance (the first value of %%i).

        input_index_end (default: 0)
        one past index of last input to advance (one past last value of %%i).

        output (default: "output-%%o-input-%%i.bin")
        the pattern that derives the name of the file written for each accepted
        output. "%%o" is the global output index across all accepted inputs, and
        "%%i" is the input it came from.

        rejected_output (default: "rejected-output-%%o-input-%%i.bin")
        the pattern that derives the name of the file written for each output of
        a rejected input. "%%o" is the would-be global output index, and "%%i"
        is the input.

        output_proof (default: "output-%%o-input-%%i-proof.<format>")
        write the proof of each accepted output against the final outputs Merkle
        root. serialized according to "format". when left at the default,
        its extension tracks "format".

        last_output_proof (no default)
        read the previous run's last output proof from this file and resume the
        outputs Merkle tree. omit it for the genesis run. read according to
        "format".

        format (optional)
        selects the format of output proofs. when omitted, it is inferred from
        the filename extension (.json/.lua), defaulting to Lua.

        report (default: "input-%%i-report-%%o.bin")
        the pattern that derives the name of the file written for report %%o
        of input %%i.

        outputs_merkle_root (default: "input-%%i-outputs-merkle-root.bin")
        the pattern that derives the name of the file written for the outputs
        Merkle root after input %%i.

        outputs_merkle_root_proof (default: "input-%%i-outputs-merkle-root-proof.<format>")
        write the proof that the outputs Merkle root occupied the tx buffer
        when input %%i was accepted. serialized according to "format". when left
        at the default, its extension tracks "format".

        check_outputs_merkle_root (default: true)
        check that the outputs Merkle root maintained by the host matches
        the one written by the guest. requires the genesis run or
        last_output_proof.

        print_input_state_hashes
        print the machine state root hash before and after delivering every input.

        mcycle_computation_hash (default: "")
        write the epoch's 32-byte mcycle computation hash to this file. it is
        the root of the tree of state hashes sampled at the configured period.
        unused tree positions reserved for an input repeat its final state hash.
        a rejected input uses its revert root. the hash is printed when determined. requires
        log2_mcycle_computation_hash_period.

        log2_mcycle_computation_hash_period (no default)
        log2 of the number of mcycles between sampled state root hashes. must be
        at most 48. an epoch computation hash tree taller than 63 emits a warning.
        enables the mcycle computation hash unless
        uarch_cycle_computation_hash is selected.

        log2_bundle_mcycle_count (default: 0)
        collect one subtree root for every 2^log2_bundle_mcycle_count state root hashes.
        bundling does not change the computation hash.
        log2_mcycle_computation_hash_period + log2_bundle_mcycle_count must be
        at most 48, the maximum number of mcycles per advance-state input.

        uarch_cycle_computation_hash (default: "")
        write the 32-byte uarch cycle computation hash for the period selected
        by mcycle_period_index. the hash covers every uarch transition,
        including repetitions of the halt state and reset. it is printed when determined. requires
        log2_mcycle_computation_hash_period and cannot be combined with
        mcycle_computation_hash.

        mcycle_period_index (no default)
        0-based index of the mcycle computation hash period covered by
        uarch_cycle_computation_hash.

        log2_bundle_uarch_cycle_count (default: 16)
        collect one subtree root for every 2^log2_bundle_uarch_cycle_count
        uarch transitions. bundling does not change the computation hash.
        must be between 0 and 19.

    the input index ranges in {input_index_begin, ..., input_index_end-1}.
    "%%i" is replaced by the input index. "%%o" is replaced by the global output
    index for output, rejected_output, and output_proof, but by the per-input
    report index for report.

  --cmio-inspect-state=<key>:<value>[,<key>:<value>[,...]...]
    inspect the state of the machine with a query.
    the query happens after the end of --cmio-advance-state.

    <key>:<value> is one of
        query:<filename>
        report:<filename-pattern>
        print_query_state_hashes

        query (default: "query.bin")
        the name of the file from which to read the query.

        report (default: "query-report-%%o.bin")
        the pattern that derives the name of the file written for report %%o
        of the query.

        print_query_state_hashes
        print the machine state root hash before and after delivering the query.

    while the query is processed, "%%o" is replaced by the current report index.

  --concurrency=<key>:<value>[,<key>:<value>[,...]...]
    configures the number of threads used in some implementation parts.

    <key>:<value> is one of
        update_hash_tree:<number>

        update_hash_tree (optional)
        defines the number of threads to use while calculating the hash tree.
        when omitted or defined as 0, the number of hardware threads is used if
        it can be identified or else a single thread is used.

    --console-io=<key>:<value>[,<key>:<value>[,...]...]
        console input/output runtime options,
        allowing console redirection to pipes or files.

        <key>:<value> is one of
            output_destination:<string>
            output_flush_mode:<string>
            output_fd:<number>
            output_filename:<filename>
            input_source:<string>
            input_fd:<number>
            input_filename:<filename>
            tty_rows:<number>
            tty_cols:<number>

            output_destination (default: "to_stdout")
            the console output destination, can be one of:
                - "to_null", write to nowhere (no console output)
                - "to_stdout", write to host's stdout
                - "to_stderr", write to host's stderr
                - "to_fd", write to a host's file descriptor
                - "to_file", write to a host's file

            output_flush_mode (default: "every_line" if non-interactive, otherwise "every_char")
            the console output flush mode, can be one of:
                - "when_full", flush when buffer is full
                - "every_char", flush after every new character
                - "every_line", flush after every new line (or when buffer is full)

            output_fd (default: -1)
            host's file descriptor to write the console output,
            this option automatically sets output destination to "to_fd".

            output_filename (default: "")
            host's file name to append the console output,
            this option automatically sets output destination to "to_file".

            input_source (default: "from_null" if non-interactive, otherwise "from_stdin")
            the console input source, can be one of:
                - "from_null", read from nowhere (no console input)
                - "from_stdin", read from host's stdin
                - "from_fd", read from a host's file descriptor
                - "from_file", read from a host's file

            input_fd (default: -1)
            host's file descriptor to feed to the console input,
            this option automatically sets input source to "from_fd".

            input_filename (default: "")
            host's file name to feed to the console input,
            this option automatically sets input source to "from_file".

            tty_rows (default: 25)
            tty_cols (default: 80)
            terminal size, only relevant when input source is different from stdin.

  --skip-version-check
    skip emulator version check when loading a stored machine.
    i.e., assume the stored machine is compatible with current emulator version.
    this is only intended to test old snapshots during emulator development.

    DON'T USE THIS OPTION IN PRODUCTION

  --no-reserve
    don't reserve swap memory for flash drives.

    DON'T USE THIS OPTION IN PRODUCTION

  --max-mcycle=<number>
    stop at a given mcycle (default: 2^64-1).

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
    host directories.
    this is automatically implied with --network or --volume options.

    NON REPRODUCIBLE OPTION, DON'T USE THIS OPTION IN PRODUCTION

  --virtio-9p=tag:<tag>,host_directory:<directory>
    add a VirtIO Plan9 filesystem device for sharing a host directory
    in the guest.
    the filesystem will have a tag that can be used to mount the host directory
    in the guest using the following command:

        busybox mount -t 9p <tag> <mountpoint>

    NON REPRODUCIBLE OPTION, DON'T USE THIS OPTION IN PRODUCTION

  --volume=host_directory:<directory>,guest_directory:<directory>
  -v <host-directory>:<guest-directory>
    like --virtio-9p, but also appends init commands to auto mount the
    host directory in the guest directory.
    mount tags are incrementally set to "vfs0", "vfs1", ...

    this option implies --sync-init-date.

    NON REPRODUCIBLE OPTION, DON'T USE THIS OPTION IN PRODUCTION

  --virtio-net=<iface>
    add a VirtIO network device using host TUN/TAP interface.
    this allows the use of the host network from inside the machine.
    this is more efficient and has fewer limitations than the user-space
    networking option (--virtio-net=user).

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
      - there is an additional emulation layer of the TCP/IP stack;
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

  --port-forward=host_address:[hostip:]hostport,guest_address:[guestip:]guestport,protocol:<tcp|udp>
  -p [hostip:]hostport:guestport[/protocol]
    redirect incoming TCP or UDP connections.
    bind the host hostip:hostport to the guest guestip:guestport.
    each address is "[ip:]port", and protocol can be "tcp" or "udp".
    if host ip is absent, it's set to "127.0.0.1".
    if guest ip is absent, it's set to "10.0.2.15".
    if guest port is absent, it's set to the same as host port.
    if protocol is absent, it's set to "tcp".
    the short -p form is docker-compatible. it requires both ports, has no
    guest ip field, and takes an optional "/tcp" or "/udp" suffix protocol
    defaulting to tcp.
    use the long form to set a guest ip.
    you can pass this option multiple times.
    this option requires --network or --virtio-net=user option.

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

  --create=<directory>
    initializes a machine using fully on-disk state stored to <directory>,
    the effect is similar as creating a machine and using --store=<directory>,
    however this is the only safe way to create machines with large address spaces
    or to propagate "shared" backing stores to configuration files.

    MUST BE USED WITH --revert-mode=stored or none

  --load=<directory>[,<key>:<value>[,...]...]
    load machine stored in <directory>.

    <key>:<value> is one of
        clone:<source_directory>
        sharing:<mode>
        sync

        clone (optional)
        clones previously stored machine from <source_directory> to <directory> and loads it.
        writable address ranges use reference links on copy-on-write filesystems.
        read-only address ranges use hard links to avoid unnecessary copying.
        files sparsity is preserved to minimize storage usage.

        sharing (optional)
        affects how address ranges modifications reflect the loaded backing stores:
            none: keeps state in-memory only; no backing store modifications.
            config: only configured "shared" backing stores operate on-disk and are modified.
            all: keeps state on-disk, modifying all backing stores.
        the default mode is "none", but if clone is present then the default mode is "all".
        mode "config" MUST BE USED WITH --revert-mode=none.
        mode "all" MUST BE USED WITH --revert-mode=stored or none.

        sync (optional)
        flush the machine state held in the backing stores of <directory> to
        permanent storage before exiting. with a sharing mode other than "none"
        there is no final store, and process exit does not guarantee the
        modifications are durable on disk; sync fsyncs every backing store file,
        the directory, and its parent before exit.
        requires a sharing mode other than "none".

  --store=<directory>[,<key>:<value>[,...]...]
    store machine to <directory>, where "%%h" is substituted by the
    state hash in the directory name.

    <key>:<value> is one of
        sharing:<mode>

        sharing (optional)
        affects how address ranges modifications reflect the new backing stores:
            none: copies backing stores as they were during load (rarely useful).
            config: store "shared" backing stores from current state; others are copied as they were during load.
            all: (default) store current state for all backings stores.

  --initial-hash[=<filename>]
    print initial state hash before running machine.
    if <filename> is given, write the raw state hash to it instead.

  --final-hash[=<filename>]
    print final state hash when done.
    if <filename> is given, write the raw state hash to it instead.

  --print-mcycle-root-hashes=<log2_mcycle_period>[,start:<mcycle>][,log2_bundle_mcycle_count:<count>]
    prints root hash every 2^log2_mcycle_period cycles, and where the machine stops.
    if start: is given, the hashing will start at that mcycle.
    if log2_bundle_mcycle_count: is given, prints instead one subtree root for
    every 2^log2_bundle_mcycle_count hashes, with the cycle range it covers.
    this option implies --initial-hash and --final-hash.
    (default: none)

  --print-uarch-cycle-root-hashes=<count>[,start:<mcycle>][,log2_bundle_uarch_cycle_count:<count>]
    prints root hash every uarch cycle for <count> mcycles.
    if start: is given, the hashing will start at that mcycle.
    if log2_bundle_uarch_cycle_count: is given, prints instead one subtree root
    for every 2^log2_bundle_uarch_cycle_count hashes, with the range it covers.

  --initial-proof=<key>:<value>[,<key>:<value>[,...]...]
    print a Merkle proof for a target region of the initial machine state.

    <key>:<value> is one of
        address:<number>
        log2_size:<number>
        label:<label>
        filename:<filename>

        address and log2_size
        give the starting offset and the log2 of the size of the target
        region in bytes. log2_size must be at least 5 (a 32-byte word).

        label (alternative to address and log2_size)
        names a flash drive or nvram whose start and length supply the
        target region's address and log2_size.

        filename (optional)
        redirects the proof to a file. when omitted, the proof is printed
        to stdout.

        format:<lua|json> (optional)
        selects the output format. when omitted, it is inferred from the
        filename extension (.json/.lua), defaulting to Lua.

    the proof is printed as a Lua table unless format:json is given.

  --final-proof=<key>:<value>[,<key>:<value>[,...]...]
    like --initial-proof, but for the final machine state.

  --log-step=<filename>,count:<mcycle-count>
    log and save a step of <mcycle-count> mcycles to <filename>.

  --log-step-uarch=<filename>[,count:<uarch-cycle-count>][,dump]
    log <uarch-cycle-count> uarch cycles (default 1) to <filename>
    as a binary step log. logging stops early at the uarch halt, so a count at
    or above the per-mcycle uarch budget records one whole mcycle.
    append ",dump" to also write a human-readable printout to stderr.

  --log-reset-uarch=<filename>
    reset the uarch state and write a binary step log to <filename>.

  --log-send-cmio-response=<filename>,<key>:<value>[,<key>:<value>[,...]...]
    send a cmio response to the rx buffer and write a binary step log to a file.
    runs after the machine has reached its terminal state. the machine should be
    in a yielded state (iflags.Y == 1); otherwise the logged transition is a no-op.

    <key>:<value> is one of
        reason:<number>
        filename:<path>
        data:<text>
        data-file:<path>
        encoding:hex|base64|utf8

        reason (required)
        the cmio yield reason (e.g., a HTIF_YIELD_*_REASON_* constant).

        filename (required)
        path of the step log file to write.

        data | data-file (exactly one required)
        the response payload, given inline or read from a file.

        encoding (optional, default hex)
        how to read data: "hex" for a 0x-prefixed hex string, "base64", or
        "utf8" for literal text. does not apply to data-file, which is
        always read as raw bytes.

  --auto-reset-uarch
    reset uarch automatically after halt.

  --store-config[=<filename>][,format:<lua|json>]
    store initial machine config to <filename>.
    If <filename> is omitted, print the initial machine config to stdout.
    the format is taken from format: if given, else the filename extension
    (.json/.lua), defaulting to Lua.

  --load-config=<filename>[,format:<lua|json>]
    load initial machine config from <filename>. If a field is omitted on
    the config table, it will fall back into the respective command-line
    argument or into the default value.
    the format is taken from format: if given, else the filename extension
    (.json/.lua), defaulting to Lua.

  --uarch-ram-image=<filename>
    name of file containing uarch RAM image.

  --dump-memory-ranges[=<dir>]
    dump all memory ranges to files under <dir>.
    If <dir> is omitted, files are written to the current directory.

  --assert-rolling-template
    exit with failure in case the generated machine is not compatible with
    Rolling Cartesi Machine templates.

  --quiet
    suppress cartesi-machine.lua output.
    exceptions: --initial-hash, --final-hash and text emitted from the target.

  --no-init-splash
    don't show cartesi machine splash on boot.

  -u <name> or --user=<name>
    appends to init the user who should execute the entrypoint command.
    when omitted, the user is set to "dapp" by rootfs init script.

  -e <name>=<value> or --env=<name>=<value>
    appends to init an environment variable export.

  -w <dir> or --workdir=<dir>
    appends to init the entrypoint working directory.

  -h <name> or --hostname=<name>
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

  --gdb-fd=<fd>
    wait for a GDB connection on the inherited listening TCP socket <fd>.
    this option is mutually exclusive with --gdb.

and command and arguments:

  command
    the full path to the program inside the target system.
    (default: /bin/sh)

  arguments
    the given command arguments.

<number> can be specified in decimal (e.g., 16) or hexadecimal (e.g., 0x10),
with a suffix multiplier (i.e., Ki, Mi, Gi for 2^10, 2^20, 2^30, respectively),
or a left shift (e.g., 2 << 20).

]=],
        arg[0]
    ))
end

local remote_closer = {}
local images_path = adjust_images_path(os.getenv("CARTESI_IMAGES_PATH"))
-- The values parsed from the command-line options, assembled in place by the option handlers
-- below. Fields default to nil unless initialized here.
local cmdline = {
    remote_spawn = nil,
    remote_address = nil,
    remote_health_check = false,
    remote_fork = false,
    remote_shutdown = false,
    remote_create = true,
    remote_destroy = true,
    revert_mode = "fork",
    flash_label_to_index = { root = 1 },
    flash_drives = {
        {
            label = "root",
            backing_store = { data_filename = images_path .. "rootfs.ext2" },
        },
    },
    flash_drive_count = 1,
    nvram_label_to_index = {},
    nvrams = {},
    nvram_count = 0,
    virtio_net_user_config = nil,
    virtio_volume_count = 0,
    has_virtio_console = false,
    has_network = false,
    has_sync_init_date = false,
    memory_range_replace = {},
    init_splash = true,
    append_bootargs = "",
    append_init = "",
    append_entrypoint = "",
    cmio_advance = nil,
    cmio_inspect = nil,
    -- The machine configuration, passed to machine:create. It is the requested ("command line")
    -- config; after creation, the machine's actual config is read back into initial_config.
    config = {
        processor = {
            registers = {
                iunrep = 0,
            },
        },
        ram = {
            length = 128 << 20, -- 128MB
            backing_store = {
                data_filename = images_path .. "linux.bin",
                dht_filename = "",
                dpt_filename = "",
            },
        },
        dtb = {
            init = "",
            entrypoint = "",
        },
        flash_drive = {},
        nvram = {},
        tlb = {},
        virtio = {},
        cmio = {
            rx_buffer = {},
            tx_buffer = {},
        },
        pmas = {},
        uarch = {
            processor = {
                registers = {},
                backing_store = {
                    data_filename = "",
                    dht_filename = "",
                    dpt_filename = "",
                },
            },
            ram = {
                backing_store = {
                    data_filename = "",
                    dht_filename = "",
                    dpt_filename = "",
                },
            },
        },
        hash_tree = {},
    },
    console = {},
    concurrency_update_hash_tree = 0,
    skip_version_check = false,
    no_reserve = false,
    initial_hash = false,
    final_hash = false,
    initial_proof = {},
    final_proof = {},
    mcycle_root_hashes_log2_period = nil,
    mcycle_root_hashes_start = 0,
    mcycle_root_hashes_log2_bundle = 0,
    uarch_cycle_root_hashes_start = nil,
    uarch_cycle_root_hashes_count = nil,
    uarch_cycle_root_hashes_log2_bundle = 0,
    dump_memory_ranges_dir = false,
    max_mcycle = nil,
    max_uarch_cycle = 0,
    auto_reset_uarch = false,
    store_dir = nil,
    load_dir = nil,
    create_dir = nil,
    clone_dir = nil,
    load_sharing = nil,
    load_sync = nil,
    store_sharing = nil,
    opts_finished = false,
    store_config = false,
    store_config_format = nil,
    load_config = false,
    load_config_format = nil,
    gdb = nil,
    exec_arguments = {},
    assert_rolling_template = false,
    log_step_mcycle_count = nil,
    log_step_filename = nil,
    log_step_uarch = nil,
    log_reset_uarch = nil,
    log_send_cmio_response = nil,
}
-- Epoch geometry, assigned from the exported rollup constants after the requires, before any
-- option is parsed.
local ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
local ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
local ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE

-- Default omitted backing-store filenames to ""
local function set_empty_omitted_filenames(f)
    local bs = f.backing_store
    bs.data_filename = bs.data_filename or ""
    bs.dht_filename = bs.dht_filename or ""
    bs.dpt_filename = bs.dpt_filename or ""
end

local function parse_memory_range(keys, all, opts)
    local f = util.parse_options(keys, all, opts)
    f.backing_store = {
        data_filename = f.data_filename,
        dht_filename = f.dht_filename,
        dpt_filename = f.dpt_filename,
        shared = f.shared,
        create = f.create,
        truncate = f.truncate,
    }
    f.data_filename = nil
    f.dht_filename = nil
    f.dpt_filename = nil
    f.shared = nil
    f.create = nil
    f.truncate = nil
    return f
end

-- Map a sharing sub-option ("none"/"config"/"all") to its constant. The map is
-- populated once cartesi is required, since the options table that calls
-- to_sharing is built before that.
local to_sharing_map
local function to_sharing(s)
    if not s then return nil end
    return assert(to_sharing_map[s])
end

-- Resolve the serialization format for a dump/load: an explicit format sub-key
-- wins, else the filename extension (.json/.lua), else Lua (the default).
local function resolve_format(format, filename)
    if format then return format end
    if filename then
        local ext = filename:match("%.([^.]+)$")
        if ext == "json" or ext == "lua" then return ext end
    end
    return "lua"
end

-- Override existing boolean with a new one
local function override_bool(prev, b)
    if b == nil then return prev end
    return b
end

-- Override existing memory range entry with new options (shared between flash drives and NVRAMs).
-- The entry uses the same format as machine config (label, backing_store, read_only, start, length).
-- Extra keys (mount, mke2fs, user) are stored alongside and ignored by the machine config.
local function override_memory_range(entry, opts)
    entry.label = opts.label or entry.label
    entry.start = opts.start or entry.start
    entry.length = opts.length or entry.length
    entry.user = opts.user or entry.user
    entry.read_only = override_bool(entry.read_only, opts.read_only)
    local entry_bs = entry.backing_store
    local opts_bs = opts.backing_store
    entry_bs.data_filename = opts_bs.data_filename or entry_bs.data_filename
    entry_bs.dht_filename = opts_bs.dht_filename or entry_bs.dht_filename
    entry_bs.dpt_filename = opts_bs.dpt_filename or entry_bs.dpt_filename
    entry_bs.shared = override_bool(entry_bs.shared, opts_bs.shared)
    entry_bs.create = override_bool(entry_bs.create, opts_bs.create)
    entry_bs.truncate = override_bool(entry_bs.truncate, opts_bs.truncate)
end

-- Backing-store sub-keys shared by every plain backing-store option (--ram=,
-- --dtb=, --processor=, --uarch-ram=, --uarch-processor=, --pmas=,
-- --cmio-rx-buffer=, --cmio-tx-buffer=). Referenced as the bash-completion
-- hint on each of those option entries.
local backing_store_keys = {
    data_filename = "file",
    dht_filename = "file",
    dpt_filename = "file",
    shared = "boolean",
    create = "boolean",
    truncate = "boolean",
}

local function parse_backing_store(keys, all, opts, def)
    local f = util.parse_options(keys, all, opts)
    if def then
        for i, v in pairs(def) do
            if f[i] == nil then f[i] = v end
        end
    end
    return f
end

local function handle_sync_init_date()
    if cmdline.has_sync_init_date then return true end
    cmdline.config.processor.registers.iunrep = 1
    cmdline.has_sync_init_date = true
    -- round up time by 1, to decrease chance of guest time being in the past
    local seconds = os.time() + 1
    cmdline.append_init = cmdline.append_init .. "busybox date -s @" .. seconds .. " >> /dev/null\n"
    return true
end

local function handle_virtio_9p(tag, host_directory)
    cmdline.config.processor.registers.iunrep = 1
    table.insert(cmdline.config.virtio, { type = "p9fs", tag = tag, host_directory = host_directory })
    return true
end

local function handle_volume_option(host_directory, guest_directory)
    cmdline.config.processor.registers.iunrep = 1
    local tag = "vfs" .. cmdline.virtio_volume_count
    cmdline.virtio_volume_count = cmdline.virtio_volume_count + 1
    table.insert(cmdline.config.virtio, { type = "p9fs", tag = tag, host_directory = host_directory })
    cmdline.append_init = cmdline.append_init .. "busybox mkdir -p " .. guest_directory .. " && "
    cmdline.append_init = cmdline.append_init .. "busybox mount -t 9p " .. tag .. " " .. guest_directory .. "\n"
    -- sync guest date with host date, otherwise file system updates will have wrong dates
    handle_sync_init_date()
    return true
end

local function handle_htif_console_getchar()
    cmdline.config.processor.registers.htif.iconsole = cmdline.config.processor.registers.htif.iconsole
        | cartesi.HTIF_CONSOLE_CMD_GETCHAR_MASK
    cmdline.config.processor.registers.iunrep = 1
    cmdline.console.input_source = cmdline.console.input_source or "from_stdin"
    cmdline.console.output_flush_mode = cmdline.console.output_flush_mode or "every_char"
    return true
end

local function handle_user(_, _, user)
    cmdline.append_init = cmdline.append_init .. "USER=" .. user .. "\n"
    return true
end

local function handle_env(_, _, opts)
    local name, value = opts:match("^([%w_]+)=(.+)$")
    assertf(name and value, "invalid env %s, expected NAME=VALUE", opts)
    cmdline.append_init = cmdline.append_init .. "export " .. name .. "=" .. value .. "\n"
    return true
end

local function handle_workdir(_, _, value)
    cmdline.append_init = cmdline.append_init .. "WORKDIR=" .. value .. "\n"
    return true
end

local function handle_hostname(_, _, name)
    cmdline.append_init = cmdline.append_init .. "busybox hostname " .. name .. "\n"
    return true
end

local function parse_ipv4(s)
    local a, b, c, d = s:match("^([0-9]+)%.([0-9]+)%.([0-9]+)%.([0-9]+)$")
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    assertf(a and b and c and d and a <= 255 and b <= 255 and c <= 255 and d <= 255, "malformed IPv4 %s", s)
    return (a << 24) | (b << 18) | (c << 8) | d
end

-- Parse a port-forward address "[ip:]port" into (ip-or-nil, port).
local function parse_port_forward_address(s, all)
    local ip, port = s:match("^(%d+%.%d+%.%d+%.%d+):(%d+)$")
    if ip then return parse_ipv4(ip), tonumber(port) end
    port = s:match("^(%d+)$")
    assertf(port, "invalid address %q in %s", s, all)
    return nil, tonumber(port)
end

local function add_port_forward(host_ip, host_port, guest_ip, guest_port, is_udp)
    assert(cmdline.virtio_net_user_config, "--port-forward option requires --network or --virtio-net=user option")
    assert(host_port, "missing host port in port forward")
    cmdline.virtio_net_user_config.hostfwd = cmdline.virtio_net_user_config.hostfwd or {}
    table.insert(cmdline.virtio_net_user_config.hostfwd, {
        is_udp = is_udp,
        host_ip = host_ip or parse_ipv4("127.0.0.1"),
        guest_ip = guest_ip or parse_ipv4("10.0.2.15"),
        host_port = host_port,
        guest_port = guest_port or host_port,
    })
    return true
end

local function handle_virtio_net(mode)
    cmdline.config.processor.registers.iunrep = 1
    if mode == "user" then
        if not cmdline.virtio_net_user_config then
            cmdline.virtio_net_user_config = { type = "net-user" }
            table.insert(cmdline.config.virtio, cmdline.virtio_net_user_config)
        end
    else
        table.insert(cmdline.config.virtio, { type = "net-tuntap", iface = mode })
    end
    return true
end

local function handle_network_option()
    if cmdline.has_network then return true end
    handle_virtio_net("user")
    cmdline.has_network = true
    -- initialize network
    cmdline.append_init = cmdline.append_init
        .. [[
busybox ip link set dev eth0 up
busybox ip addr add 10.0.2.15/24 dev eth0
busybox ip route add default via 10.0.2.2 dev eth0
[ -w /etc ] && echo 'nameserver 10.0.2.3' > /etc/resolv.conf
]]
    -- sync guest date with host date, otherwise SSL connections may fail to validate certificates
    handle_sync_init_date()
    return true
end

local function handle_virtio_console()
    if cmdline.has_virtio_console then return true end
    cmdline.config.processor.registers.iunrep = 1
    cmdline.console.input_source = cmdline.console.input_source or "from_stdin"
    cmdline.console.output_flush_mode = cmdline.console.output_flush_mode or "every_char"
    cmdline.has_virtio_console = true
    -- Switch from HTIF Console (hvc0) to VirtIO console (hvc1)
    cmdline.config.dtb.bootargs = cmdline.config.dtb.bootargs:gsub("console=hvc0", "console=hvc1")
    table.insert(cmdline.config.virtio, 1, { type = "console" })
    return true
end

local function handle_interactive()
    handle_virtio_console()
    handle_sync_init_date()
    -- Expose current terminal features to the virtual terminal
    local term, lang = os.getenv("TERM"), os.getenv("LANG")
    if term then cmdline.append_init = cmdline.append_init .. "export TERM=" .. term .. "\n" end
    if lang and lang:find("utf8") then cmdline.append_init = cmdline.append_init .. "export LANG=C.utf8\n" end
    return true
end

local options -- forward declaration for handle_bash_completion

local function handle_bash_completion()
    -- Register the canonical names plus whatever the user invoked
    -- this script as (e.g. ./cartesi-machine), so `source <(...)`
    -- works from any invocation path.
    local progs = { "cartesi-machine", "cartesi-machine.lua" }
    local self = arg[0]
    if self and self ~= progs[1] and self ~= progs[2] then progs[#progs + 1] = self end
    bash.dump_bash_completion(options, progs)
    os.exit()
end

-- List of supported options
-- Options are processed in order
-- Payload encodings accepted by --log-send-cmio-response, named after the
-- --hex-payload/--base64-payload/--utf8-payload options of rollup.cpp in
-- machine-guest-tools. cartesi is only required later, so decode lazily.
local ENCODINGS = {
    hex = function(v) return cartesi.fromhex(v) end,
    base64 = function(v) return cartesi.frombase64(v) end,
    utf8 = function(v) return v end,
}

-- For each option,
--   first entry is the pattern to match
--   second entry is a callback
--     if callback returns true, the option is accepted.
--     if callback returns false, the option is rejected.
--   optional third entry is a bash-completion hint: a string like "file",
--     "dir", "number", "hostport", "netif" (trailing `?` means the value is
--     optional, i.e. the flag accepts both bare and `=value` forms), or a
--     util.parse_options keys spec for compound `key:val,...` arguments. If
--     present, the dispatcher forwards it to the callback as a first
--     leading argument (callbacks that ignore the hint declare `_`).
options = {
    {
        "--help",
        function()
            print_help()
            os.exit()
            -- return true
        end,
    },
    {
        "--bash-completion",
        handle_bash_completion,
    },
    {
        "--version",
        function()
            print(string.format("cartesi-machine %s", cartesi.VERSION))
            if cartesi.GIT_COMMIT then print(string.format("git commit: %s", cartesi.GIT_COMMIT)) end
            if cartesi.BUILD_TIME then print(string.format("build time: %s", cartesi.BUILD_TIME)) end
            print(string.format("platform: %s", cartesi.PLATFORM))
            print(string.format("compiler: %s", cartesi.COMPILER))
            print("Copyright Cartesi and individual authors.")
            os.exit()
            -- return true
        end,
    },
    {
        "--version-json",
        function()
            print("{")
            print(string.format('  "version": "%s",', cartesi.VERSION))
            print(string.format('  "version_major": %d,', cartesi.VERSION_MAJOR))
            print(string.format('  "version_minor": %d,', cartesi.VERSION_MINOR))
            print(string.format('  "version_patch": %d,', cartesi.VERSION_PATCH))
            print(string.format('  "version_label": "%s",', cartesi.VERSION_LABEL))
            print(string.format('  "marchid": %d,', cartesi.MARCHID))
            print(string.format('  "mimpid": %d,', cartesi.MIMPID))
            if cartesi.GIT_COMMIT then print(string.format('  "git_commit": "%s",', cartesi.GIT_COMMIT)) end
            if cartesi.BUILD_TIME then print(string.format('  "build_time": "%s",', cartesi.BUILD_TIME)) end
            print(string.format('  "compiler": "%s",', cartesi.COMPILER))
            print(string.format('  "platform": "%s"', cartesi.PLATFORM))
            print("}")
            os.exit()
            -- return true
        end,
    },
    {
        "--dump-constants",
        function()
            local names = {}
            for name, value in pairs(cartesi) do
                if math.type(value) == "integer" or (type(value) == "string" and not value:find("[^\32-\126]")) then
                    names[#names + 1] = name
                end
            end
            table.sort(names)
            for _, name in ipairs(names) do
                local value = cartesi[name]
                if math.type(value) == "integer" then
                    print(string.format(value >= 0 and "CARTESI_%s=%d" or "CARTESI_%s=0x%x", name, value))
                else
                    print(string.format("CARTESI_%s='%s'", name, (value:gsub("'", "'\\''"))))
                end
            end
            os.exit()
            -- return true
        end,
    },
    {
        "--assert-version=",
        function(_, all, v)
            local major, minor, patch = v:match("^(%d+)%.(%d+)%.?(%d*)$")
            assertf(major, "invalid option %s", all)
            major, minor, patch = tonumber(major), tonumber(minor), tonumber(patch)
            if
                major ~= cartesi.VERSION_MAJOR
                or minor ~= cartesi.VERSION_MINOR
                or (patch and patch ~= cartesi.VERSION_PATCH)
            then
                errorf(
                    "emulator version mismatch, expected (%d.%d.%s) but got (%d.%d.%d)",
                    major,
                    minor,
                    patch or "x",
                    cartesi.VERSION_MAJOR,
                    cartesi.VERSION_MINOR,
                    cartesi.VERSION_PATCH
                )
            end
            return true
        end,
    },
    {
        "--dtb-image=",
        function(_, _, opts)
            cmdline.config.dtb.backing_store = cmdline.config.dtb.backing_store or {}
            cmdline.config.dtb.backing_store.data_filename = opts
            return true
        end,
        "file",
    },
    {
        "--no-bootargs",
        function()
            cmdline.config.dtb.bootargs = ""
            return true
        end,
    },
    {
        "--append-bootargs=",
        function(_, _, opts)
            if #cmdline.append_bootargs == 0 then
                cmdline.append_bootargs = opts
            else
                cmdline.append_bootargs = cmdline.append_bootargs .. " " .. opts
            end
            return true
        end,
    },
    {
        "--dtb=",
        function(keys, all, opts)
            cmdline.config.dtb.backing_store = parse_backing_store(keys, all, opts, cmdline.config.dtb.backing_store)
            return true
        end,
        backing_store_keys,
    },
    {
        "--processor=",
        function(keys, all, opts)
            cmdline.config.processor.backing_store =
                parse_backing_store(keys, all, opts, cmdline.config.processor.backing_store)
            return true
        end,
        backing_store_keys,
    },
    {
        "--uarch-processor=",
        function(keys, all, opts)
            cmdline.config.uarch.processor.backing_store =
                parse_backing_store(keys, all, opts, cmdline.config.uarch.processor.backing_store)
            return true
        end,
        backing_store_keys,
    },
    {
        "--ram-length=",
        function(_, _, n)
            cmdline.config.ram.length = assertf(util.parse_number(n), "invalid RAM length %s", n)
            return true
        end,
    },
    {
        "--ram-image=",
        function(_, _, opts)
            cmdline.config.ram.backing_store.data_filename = opts
            return true
        end,
        "file",
    },
    {
        "--no-ram-image",
        function()
            cmdline.config.ram.backing_store.data_filename = ""
            return true
        end,
    },
    {
        "--ram=",
        function(keys, all, opts)
            cmdline.config.ram.backing_store = parse_backing_store(keys, all, opts, cmdline.config.ram.backing_store)
            return true
        end,
        backing_store_keys,
    },
    {
        "--pmas=",
        function(keys, all, opts)
            cmdline.config.pmas.backing_store = parse_backing_store(keys, all, opts, cmdline.config.pmas.backing_store)
            return true
        end,
        backing_store_keys,
    },
    {
        "--uarch-ram-image=",
        function(_, _, opts)
            cmdline.config.uarch.ram.backing_store.data_filename = opts
            return true
        end,
        "file",
    },
    {
        "--uarch-ram=",
        function(keys, all, opts)
            cmdline.config.uarch.ram.backing_store =
                parse_backing_store(keys, all, opts, cmdline.config.uarch.ram.backing_store)
            return true
        end,
        backing_store_keys,
    },
    {
        "--hash-tree=",
        function(keys, all, opts)
            local h = util.parse_options(keys, all, opts)
            h.sht_filename = h.sht_filename or ""
            h.phtc_filename = h.phtc_filename or ""
            h.hash_function = h.hash_function or "keccak256"
            for i, v in pairs(h) do
                cmdline.config.hash_tree[i] = v
            end
            return true
        end,
        {
            hash_function = { keccak256 = "keccak256", sha256 = "sha256" },
            sht_filename = "file",
            phtc_filename = "file",
            phtc_size = "number",
            shared = "boolean",
        },
    },
    {
        "--unreproducible",
        function()
            cmdline.config.processor.registers.iunrep = 1
            return true
        end,
    },
    {
        "--sync-init-date",
        handle_sync_init_date,
    },
    {
        "--virtio-9p=",
        function(keys, all, opts)
            local p = util.parse_options(keys, all, opts)
            assertf(p.tag and p.host_directory, "need tag and host_directory in %s", all)
            return handle_virtio_9p(p.tag, p.host_directory)
        end,
        { tag = "string", host_directory = "dir" },
    },
    {
        "--volume=",
        function(keys, all, opts)
            local v = util.parse_options(keys, all, opts)
            assertf(v.host_directory and v.guest_directory, "need host_directory and guest_directory in %s", all)
            return handle_volume_option(v.host_directory, v.guest_directory)
        end,
        { host_directory = "dir", guest_directory = "dir" },
    },
    {
        -- docker bind-mount short form: -v <host_dir>:<guest_dir>
        "-v=",
        function(_, all, value)
            local host_dir, guest_dir = value:match("^([^:]+):(.+)$")
            assertf(host_dir, "invalid option %s", all)
            return handle_volume_option(host_dir, guest_dir)
        end,
        "dir",
    },
    {
        "--virtio-console",
        handle_virtio_console,
    },
    {
        "--virtio-net=",
        function(_, _, value) return handle_virtio_net(value) end,
    },
    {
        "--network",
        handle_network_option,
    },
    {
        "-n",
        handle_network_option,
    },
    {
        "--port-forward=",
        function(keys, all, opts)
            local p = util.parse_options(keys, all, opts)
            assertf(p.host_address, "need host_address in %s", all)
            local host_ip, host_port = parse_port_forward_address(p.host_address, all)
            local guest_ip, guest_port
            if p.guest_address then
                guest_ip, guest_port = parse_port_forward_address(p.guest_address, all)
            end
            return add_port_forward(host_ip, host_port, guest_ip, guest_port, p.protocol == "udp")
        end,
        { host_address = "string", guest_address = "string", protocol = { tcp = "tcp", udp = "udp" } },
    },
    {
        -- docker publish short form: -p [hostip:]hostport:guestport[/protocol]
        "-p=",
        function(_, all, value)
            local body, protocol = value:match("^(.-)/([a-z]+)$")
            if not body then
                body, protocol = value, "tcp"
            end
            assertf(protocol == "tcp" or protocol == "udp", "invalid protocol in %s", all)
            local host_ip, host_port, guest_port = body:match("^(%d+%.%d+%.%d+%.%d+):(%d+):(%d+)$")
            if host_ip then
                return add_port_forward(
                    parse_ipv4(host_ip),
                    tonumber(host_port),
                    nil,
                    tonumber(guest_port),
                    protocol == "udp"
                )
            end
            host_port, guest_port = body:match("^(%d+):(%d+)$")
            assertf(host_port, "invalid option %s", all)
            return add_port_forward(nil, tonumber(host_port), nil, tonumber(guest_port), protocol == "udp")
        end,
    },
    {
        "--htif-console-getchar",
        handle_htif_console_getchar,
    },
    {
        "-i",
        handle_htif_console_getchar,
    },
    {
        "-it",
        handle_interactive,
    },
    {
        "--console-io=",
        function(keys, all, opts)
            local c = util.parse_options(keys, all, opts)
            if c.output_fd then
                assert(
                    c.output_destination == nil or c.output_destination == "to_fd",
                    "conflicting console output destination option"
                )
                c.output_destination = "to_fd"
                cmdline.console.output_fd = c.output_fd
            end
            if c.output_filename then
                assert(
                    c.output_destination == nil or c.output_destination == "to_file",
                    "conflicting console output destination option"
                )
                c.output_destination = "to_file"
                cmdline.console.output_filename = c.output_filename
            end
            if c.input_fd then
                assert(c.input_source == nil or c.input_source == "from_fd", "conflicting console input source option")
                c.input_source = "from_fd"
                cmdline.console.input_fd = c.input_fd
            end
            if c.input_filename then
                assert(
                    c.input_source == nil or c.input_source == "from_file",
                    "conflicting console input source option"
                )
                c.input_source = "from_file"
                cmdline.console.input_filename = c.input_filename
            end
            if c.output_destination then cmdline.console.output_destination = c.output_destination end
            if c.output_flush_mode then cmdline.console.output_flush_mode = c.output_flush_mode end
            if c.output_buffer_size then cmdline.console.output_buffer_size = c.output_buffer_size end
            if c.input_source then cmdline.console.input_source = c.input_source end
            if c.input_buffer_size then cmdline.console.input_buffer_size = c.input_buffer_size end
            if c.tty_cols then cmdline.console.tty_cols = c.tty_cols end
            if c.tty_rows then cmdline.console.tty_rows = c.tty_rows end
            return true
        end,
        {
            output_destination = {
                to_null = "to_null",
                to_stdout = "to_stdout",
                to_stderr = "to_stderr",
                to_fd = "to_fd",
                to_file = "to_file",
                to_buffer = "to_buffer",
            },
            output_flush_mode = {
                when_full = "when_full",
                every_char = "every_char",
                every_line = "every_line",
            },
            output_buffer_size = "number",
            output_fd = "number",
            output_filename = "file",
            input_source = {
                from_null = "from_null",
                from_stdin = "from_stdin",
                from_fd = "from_fd",
                from_file = "from_file",
                from_buffer = "from_buffer",
            },
            input_buffer_size = "number",
            input_fd = "number",
            input_filename = "file",
            tty_cols = "number",
            tty_rows = "number",
        },
    },
    {
        "--no-htif-yield-manual",
        function()
            cmdline.config.processor.registers.htif.iyield = cmdline.config.processor.registers.htif.iyield
                & ~cartesi.HTIF_YIELD_CMD_MANUAL_MASK
            return true
        end,
    },
    {
        "--no-htif-yield-automatic",
        function()
            cmdline.config.processor.registers.htif.iyield = cmdline.config.processor.registers.htif.iyield
                & ~cartesi.HTIF_YIELD_CMD_AUTOMATIC_MASK
            return true
        end,
    },
    {
        "--flash-drive=",
        function(keys, all, opts)
            local f = parse_memory_range(keys, all, opts)
            if f.label and cmdline.flash_label_to_index[f.label] then
                local prev_f = cmdline.flash_drives[cmdline.flash_label_to_index[f.label]]
                override_memory_range(prev_f, f)
                prev_f.mount = override_bool(prev_f.mount, f.mount)
                prev_f.mke2fs = override_bool(prev_f.mke2fs, f.mke2fs)
            else
                cmdline.flash_drive_count = cmdline.flash_drive_count + 1
                cmdline.flash_drives[cmdline.flash_drive_count] = f
                if f.label then cmdline.flash_label_to_index[f.label] = cmdline.flash_drive_count end
            end
            return true
        end,
        {
            "data_filename", -- positional: --flash-drive=foo.ext2
            label = "string",
            data_filename = "file",
            dht_filename = "file",
            dpt_filename = "file",
            shared = "boolean",
            create = "boolean",
            truncate = "boolean",
            length = "number",
            start = "number",
            read_only = "boolean",
            mount = "string",
            mke2fs = "boolean",
            user = "string",
        },
    },
    {
        "--nvram=",
        function(keys, all, opts)
            local f = parse_memory_range(keys, all, opts)
            if f.label and cmdline.nvram_label_to_index[f.label] then
                local prev_f = cmdline.nvrams[cmdline.nvram_label_to_index[f.label]]
                override_memory_range(prev_f, f)
            else
                cmdline.nvram_count = cmdline.nvram_count + 1
                cmdline.nvrams[cmdline.nvram_count] = f
                if f.label then cmdline.nvram_label_to_index[f.label] = cmdline.nvram_count end
            end
            return true
        end,
        {
            "data_filename", -- positional: --nvram=foo.bin
            label = "string",
            data_filename = "file",
            dht_filename = "file",
            dpt_filename = "file",
            shared = "boolean",
            create = "boolean",
            truncate = "boolean",
            length = "number",
            start = "number",
            read_only = "boolean",
            user = "string",
        },
    },
    {
        "--replace-memory-range=",
        function(keys, all, opts)
            local f = parse_memory_range(keys, all, opts)
            cmdline.memory_range_replace[#cmdline.memory_range_replace + 1] = f
            return true
        end,
        {
            label = "string",
            data_filename = "file",
            dht_filename = "file",
            dpt_filename = "file",
            shared = "boolean",
            length = "number",
            start = "number",
            read_only = "boolean",
        },
    },
    {
        "--cmio-advance-state=",
        function(keys, all, opts)
            local r = util.parse_options(keys, all, opts)
            r.input = r.input or "input-%i.bin"
            r.input_index_begin = r.input_index_begin or 0
            r.input_index_end = r.input_index_end or 0
            -- %o is the global output index (the proof's target_address), %i the input it came from.
            -- An empty value ("") disables writing that file.
            r.output = r.output or "output-%o-input-%i.bin"
            r.rejected_output = r.rejected_output or "rejected-output-%o-input-%i.bin"
            -- When the user does not override output_proof, the default filename's extension tracks
            -- "format" (default lua), so format:json alone yields a .json file. An explicit
            -- output_proof is left as the user wrote it (format still selects the content).
            r.output_proof = r.output_proof or ("output-%o-input-%i-proof." .. (r.format or "lua"))
            r.report = r.report or "input-%i-report-%o.bin"
            r.outputs_merkle_root = r.outputs_merkle_root or "input-%i-outputs-merkle-root.bin"
            -- Like output_proof, the default extension tracks "format" while an explicit value is left as-is.
            r.outputs_merkle_root_proof = r.outputs_merkle_root_proof
                or ("input-%i-outputs-merkle-root-proof." .. (r.format or "lua"))
            if r.check_outputs_merkle_root == nil then r.check_outputs_merkle_root = true end
            -- log2_mcycle_computation_hash_period enables the epoch computation hash: the mcycle
            -- one by default, or the uarch cycle one covering the period mcycle_period_index
            -- selects. The *_computation_hash keys name the files that receive them, and the
            -- other log2 sub-keys set the bundling. The epoch geometry is fixed, matching the
            -- on-chain dispute.
            local wants_mcycle_ch = r.mcycle_computation_hash
            local wants_uarch_cycle_ch = r.uarch_cycle_computation_hash or r.mcycle_period_index
            if wants_mcycle_ch or wants_uarch_cycle_ch or r.log2_mcycle_computation_hash_period then
                assertf(r.log2_mcycle_computation_hash_period, "need log2_mcycle_computation_hash_period in %s", all)
                local log2_period = r.log2_mcycle_computation_hash_period
                assertf(log2_period >= 0, "invalid log2_mcycle_computation_hash_period in %s", all)
                assertf(
                    log2_period <= ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE,
                    "log2_mcycle_computation_hash_period cannot exceed the mcycles of an input in %s",
                    all
                )
                local log2_epoch_computation_hash_leaf_count = ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
                    + ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
                    - log2_period
                if log2_epoch_computation_hash_leaf_count > 63 then
                    stderr_unsilenceable(
                        "Warning: computation hash tree height %d exceeds 63\n",
                        log2_epoch_computation_hash_leaf_count
                    )
                end
                assertf(r.input_index_begin == 0, "computation hash requires input_index_begin 0 in %s", all)
                assertf(
                    r.input_index_end <= 1 << ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH,
                    "input_index_end past the inputs of an epoch in %s",
                    all
                )
                if wants_uarch_cycle_ch then
                    assertf(
                        not wants_mcycle_ch,
                        "uarch_cycle_computation_hash cannot be combined with mcycle_computation_hash in %s",
                        all
                    )
                    r.uarch_cycle_computation_hash = r.uarch_cycle_computation_hash or ""
                    assertf(r.mcycle_period_index, "need mcycle_period_index in %s", all)
                    -- When an epoch has fewer than 2^64 periods, check the index against their
                    -- exclusive upper bound. Otherwise every 64-bit mcycle_period_index is valid.
                    if log2_epoch_computation_hash_leaf_count < 64 then
                        assertf(
                            math.ult(r.mcycle_period_index, 1 << log2_epoch_computation_hash_leaf_count),
                            "mcycle_period_index past the periods of an epoch in %s",
                            all
                        )
                    end
                    r.log2_bundle_uarch_cycle_count = r.log2_bundle_uarch_cycle_count
                        or math.min(16, ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - 1)
                    local log2_bundle = r.log2_bundle_uarch_cycle_count
                    assertf(
                        log2_bundle >= 0 and log2_bundle < ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE,
                        "log2_bundle_uarch_cycle_count must be in {0, ..., %d} in %s",
                        ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - 1,
                        all
                    )
                else
                    r.mcycle_computation_hash = r.mcycle_computation_hash or ""
                    r.log2_bundle_mcycle_count = r.log2_bundle_mcycle_count or 0
                    assertf(
                        r.log2_bundle_mcycle_count >= 0
                            and log2_period + r.log2_bundle_mcycle_count
                                <= ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE,
                        "computation hash bundle cannot exceed the mcycles of an input in %s",
                        all
                    )
                end
            end
            r.next_input_index = r.input_index_begin
            cmdline.cmio_advance = r
            return true
        end,
        {
            input = "file",
            input_index_begin = "number",
            input_index_end = "number",
            outputs_merkle_root = "file",
            outputs_merkle_root_proof = "file",
            output = "file",
            rejected_output = "file",
            output_proof = "file",
            last_output_proof = "file",
            format = { lua = "lua", json = "json" },
            report = "file",
            check_outputs_merkle_root = "boolean",
            print_input_state_hashes = "boolean",
            mcycle_computation_hash = "file",
            log2_mcycle_computation_hash_period = "number",
            log2_bundle_mcycle_count = "number",
            uarch_cycle_computation_hash = "file",
            mcycle_period_index = "number",
            log2_bundle_uarch_cycle_count = "number",
        },
    },
    {
        "--cmio-inspect-state=",
        function(keys, all, opts)
            local r = util.parse_options(keys, all, opts)
            r.query = r.query or "query.bin"
            r.report = r.report or "query-report-%o.bin"
            cmdline.cmio_inspect = r
            return true
        end,
        {
            query = "file",
            report = "file",
            print_query_state_hashes = "boolean",
        },
    },
    {
        "--cmio-inspect-state",
        function()
            cmdline.cmio_inspect = {
                query = "query.bin",
                report = "query-report-%o.bin",
            }
            return true
        end,
    },
    {
        "--concurrency=",
        function(keys, all, opts)
            local c = util.parse_options(keys, all, opts)
            c.update_hash_tree = assertf(c.update_hash_tree, "invalid update_hash_tree number in %s", all)
            cmdline.concurrency_update_hash_tree = c.update_hash_tree
            return true
        end,
        { update_hash_tree = "number" },
    },
    {
        "--skip-version-check",
        function()
            cmdline.skip_version_check = true
            return true
        end,
    },
    {
        "--no-reserve",
        function()
            cmdline.no_reserve = true
            return true
        end,
    },
    {
        "--initial-proof=",
        function(keys, all, opts)
            local p = util.parse_options(keys, all, opts)
            assertf(p.address and p.log2_size or p.label, "need address and log2_size or label in %s", all)
            p.cmdline = all
            p.format = resolve_format(p.format, p.filename)
            cmdline.initial_proof[#cmdline.initial_proof + 1] = p
            return true
        end,
        {
            label = "string",
            address = "number",
            log2_size = "number",
            filename = "file",
            format = { lua = "lua", json = "json" },
        },
    },
    {
        "--final-proof=",
        function(keys, all, opts)
            local p = util.parse_options(keys, all, opts)
            assertf(p.address and p.log2_size or p.label, "need address and log2_size or label in %s", all)
            p.cmdline = all
            p.format = resolve_format(p.format, p.filename)
            cmdline.final_proof[#cmdline.final_proof + 1] = p
            return true
        end,
        {
            label = "string",
            address = "number",
            log2_size = "number",
            filename = "file",
            format = { lua = "lua", json = "json" },
        },
    },
    {
        "--no-root-flash-drive",
        function()
            assert(cmdline.flash_drives[1] and cmdline.flash_drives[1].label == "root", "no root flash drive to remove")
            cmdline.flash_drives[1] = nil
            cmdline.flash_label_to_index.root = nil
            cmdline.config.dtb.bootargs =
                cmdline.config.dtb.bootargs:gsub(cartesi.DTB_BOOTARGS_ROOT_PART:gsub("[^%w]", "%%%1"), "")
            cmdline.config.dtb.bootargs =
                cmdline.config.dtb.bootargs:gsub(cartesi.DTB_BOOTARGS_INIT_PART:gsub("[^%w]", "%%%1"), "")
            return true
        end,
    },
    {
        "--dump-memory-ranges",
        function()
            cmdline.dump_memory_ranges_dir = true
            return true
        end,
    },
    {
        "--dump-memory-ranges=",
        function(_, _, v)
            cmdline.dump_memory_ranges_dir = v
            return true
        end,
        "dir",
    },
    {
        "--assert-rolling-template",
        function()
            cmdline.assert_rolling_template = true
            return true
        end,
    },
    {
        "--quiet",
        function()
            stderr = function() end
            return true
        end,
    },
    {
        "--log-step=",
        function(keys, all, opts)
            local o = util.parse_options(keys, all, opts)
            assertf(o.filename and o.count, "need filename and count in %s", all)
            cmdline.log_step_mcycle_count = o.count
            cmdline.log_step_filename = o.filename
            return true
        end,
        {
            "filename",
            filename = "file",
            count = "number",
        },
    },
    {
        "--log-step-uarch=",
        function(keys, all, opts)
            local o = util.parse_options(keys, all, opts)
            assertf(o.filename, "need filename in %s", all)
            cmdline.log_step_uarch = { filename = o.filename, count = o.count or 1, dump = o.dump }
            return true
        end,
        {
            "filename",
            filename = "file",
            count = "number",
            dump = "boolean",
        },
    },
    {
        "--log-reset-uarch=",
        function(keys, all, opts)
            local o = util.parse_options(keys, all, opts)
            assertf(o.filename, "need filename in %s", all)
            cmdline.log_reset_uarch = { filename = o.filename }
            return true
        end,
        {
            "filename",
            filename = "file",
        },
    },
    {
        "--log-send-cmio-response=",
        function(keys, all, opts)
            local o = util.parse_options(keys, all, opts)
            assert(o.reason, "missing reason for --log-send-cmio-response")
            assert(o.filename, "missing filename for --log-send-cmio-response")
            local sources = (o.data and 1 or 0) + (o["data-file"] and 1 or 0)
            assert(sources == 1, "--log-send-cmio-response requires exactly one of data:, data-file:")
            if o["data-file"] then
                assert(not o.encoding, "--log-send-cmio-response encoding does not apply to data-file:")
            else
                o.encoding = o.encoding or "hex"
                assert(ENCODINGS[o.encoding], "--log-send-cmio-response encoding must be one of hex, base64, utf8")
            end
            cmdline.log_send_cmio_response = o
            return true
        end,
        {
            "filename",
            reason = "number",
            filename = "file",
            data = "string",
            ["data-file"] = "file",
            encoding = "string",
        },
    },
    {
        "--max-mcycle=",
        function(_, all, n)
            cmdline.max_mcycle = assertf(util.parse_number(n), "invalid option %s", all)
            return true
        end,
    },
    {
        "--max-uarch-cycle=",
        function(_, all, n)
            cmdline.max_uarch_cycle = assertf(util.parse_number(n), "invalid option %s", all)
            return true
        end,
    },
    {
        "--auto-reset-uarch",
        function()
            cmdline.auto_reset_uarch = true
            return true
        end,
    },
    {
        "--create=",
        function(_, _, opts)
            if not opts or #opts < 1 then return false end
            cmdline.create_dir = opts
            return true
        end,
        "dir",
    },
    {
        "--load=",
        function(keys, all, opts)
            local o = util.parse_options(keys, all, opts)
            assertf(o.directory, "need directory in %s", all)
            cmdline.clone_dir = o.clone
            cmdline.load_sharing = to_sharing(o.sharing)
            if cmdline.clone_dir and not cmdline.load_sharing then cmdline.load_sharing = cartesi.SHARING_ALL end
            cmdline.load_dir = o.directory
            cmdline.load_sync = o.sync
            if cmdline.load_sync then
                assertf(
                    cmdline.load_sharing and cmdline.load_sharing ~= cartesi.SHARING_NONE,
                    "sync requires a sharing mode other than none in %s",
                    all
                )
            end
            return true
        end,
        {
            "directory",
            directory = "dir",
            clone = "dir",
            sharing = { none = "none", config = "config", all = "all" },
            sync = "boolean",
        },
    },
    {
        "--store=",
        function(keys, all, opts)
            local o = util.parse_options(keys, all, opts)
            assertf(o.directory, "need directory in %s", all)
            cmdline.store_sharing = to_sharing(o.sharing)
            cmdline.store_dir = o.directory
            return true
        end,
        {
            "directory",
            directory = "dir",
            sharing = { none = "none", config = "config", all = "all" },
        },
    },
    {
        "--remote-spawn",
        function()
            cmdline.remote_spawn = true
            return true
        end,
    },
    {
        "--remote-address=",
        function(_, _, opts)
            if not opts or #opts < 1 then return false end
            cmdline.remote_address = opts
            return true
        end,
    },
    {
        "--remote-fork",
        function()
            cmdline.remote_fork = true
            return true
        end,
    },
    {
        "--remote-fork=",
        function(_, _, v)
            cmdline.remote_fork = v
            return true
        end,
        "hostport",
    },
    {
        "--remote-health-check",
        function()
            cmdline.remote_health_check = true
            return true
        end,
    },
    {
        "--remote-shutdown",
        function()
            cmdline.remote_shutdown = true
            return true
        end,
    },
    {
        "--no-remote-create",
        function()
            cmdline.remote_create = false
            return true
        end,
    },
    {
        "--no-remote-destroy",
        function()
            cmdline.remote_destroy = false
            return true
        end,
    },
    {
        "--revert-mode=",
        function(keys, all, opts)
            cmdline.revert_mode = util.parse_options(keys, all, opts).mode
            return true
        end,
        {
            "mode",
            mode = { fork = "fork", stored = "stored", none = "none" },
        },
    },
    {
        "--no-revert",
        function()
            cmdline.revert_mode = "none"
            return true
        end,
    },
    {
        "--initial-hash",
        function()
            cmdline.initial_hash = true
            return true
        end,
    },
    {
        "--initial-hash=",
        function(_, _, v)
            cmdline.initial_hash = v
            return true
        end,
        "filename",
    },
    {
        "--final-hash",
        function()
            cmdline.final_hash = true
            return true
        end,
    },
    {
        "--final-hash=",
        function(_, _, v)
            cmdline.final_hash = v
            return true
        end,
        "filename",
    },
    {
        "--print-mcycle-root-hashes=",
        function(keys, all, opts)
            local o = util.parse_options(keys, all, opts)
            cmdline.mcycle_root_hashes_log2_period = assertf(o.log2_mcycle_period, "need log2_mcycle_period in %s", all)
            assertf(
                cmdline.mcycle_root_hashes_log2_period >= 0 and cmdline.mcycle_root_hashes_log2_period < 63,
                "log2_mcycle_period must be in {0, ..., 62} in %s",
                all
            )
            cmdline.mcycle_root_hashes_start = o.start or 0
            cmdline.mcycle_root_hashes_log2_bundle = o.log2_bundle_mcycle_count or 0
            cmdline.initial_hash = true
            cmdline.final_hash = true
            return true
        end,
        {
            "log2_mcycle_period",
            log2_mcycle_period = "number",
            start = "number",
            log2_bundle_mcycle_count = "number",
        },
    },
    {
        "--print-uarch-cycle-root-hashes=",
        function(keys, all, opts)
            local o = util.parse_options(keys, all, opts)
            cmdline.uarch_cycle_root_hashes_count = assertf(o.count, "need count in %s", all)
            cmdline.uarch_cycle_root_hashes_start = o.start or 0
            cmdline.uarch_cycle_root_hashes_log2_bundle = o.log2_bundle_uarch_cycle_count or 0
            return true
        end,
        {
            "count",
            count = "number",
            start = "number",
            log2_bundle_uarch_cycle_count = "number",
        },
    },
    {
        -- bare: dump config to stdout in Lua
        "--store-config",
        function()
            cmdline.store_config = true
            cmdline.store_config_format = resolve_format(nil, nil)
            return true
        end,
    },
    {
        -- value: a positional filename and/or a format sub-key
        "--store-config=",
        function(keys, all, opts)
            local o = util.parse_options(keys, all, opts)
            cmdline.store_config = o.filename or true
            cmdline.store_config_format = resolve_format(o.format, o.filename)
            return true
        end,
        {
            "filename",
            filename = "file",
            format = { lua = "lua", json = "json" },
        },
    },
    {
        "--load-config=",
        function(keys, all, opts)
            local o = util.parse_options(keys, all, opts)
            assertf(o.filename, "need filename in %s", all)
            cmdline.load_config = o.filename
            cmdline.load_config_format = resolve_format(o.format, o.filename)
            return true
        end,
        {
            "filename",
            filename = "file",
            format = { lua = "lua", json = "json" },
        },
    },
    {
        "--cmio-rx-buffer=",
        function(keys, all, opts)
            if not opts then return false end
            cmdline.config.cmio.rx_buffer.backing_store =
                parse_backing_store(keys, all, opts, cmdline.config.cmio.rx_buffer.backing_store)
            return true
        end,
        backing_store_keys,
    },
    {
        "--cmio-tx-buffer=",
        function(keys, all, opts)
            if not opts then return false end
            cmdline.config.cmio.tx_buffer.backing_store =
                parse_backing_store(keys, all, opts, cmdline.config.cmio.tx_buffer.backing_store)
            return true
        end,
        backing_store_keys,
    },
    {
        "--no-init-splash",
        function()
            cmdline.init_splash = false
            return true
        end,
    },
    {
        "-u=",
        handle_user,
    },
    {
        "--user=",
        handle_user,
    },
    {
        "-e=",
        handle_env,
    },
    {
        "--env=",
        handle_env,
    },
    {
        "-w=",
        handle_workdir,
    },
    {
        "--workdir=",
        handle_workdir,
    },
    {
        "-h=",
        handle_hostname,
    },
    {
        "--hostname=",
        handle_hostname,
    },
    {
        "--append-init=",
        function(_, _, opts)
            cmdline.append_init = cmdline.append_init .. opts .. "\n"
            return true
        end,
    },
    {
        "--append-init-file=",
        function(_, _, opts)
            local contents = util.read_file(opts)
            if not contents:find("\n$") then contents = contents .. "\n" end
            cmdline.append_init = cmdline.append_init .. contents
            return true
        end,
        "file",
    },
    {
        "--append-entrypoint=",
        function(_, _, opts)
            cmdline.append_entrypoint = cmdline.append_entrypoint .. opts .. "\n"
            return true
        end,
    },
    {
        "--append-entrypoint-file=",
        function(_, _, opts)
            local contents = util.read_file(opts)
            if not contents:find("\n$") then contents = contents .. "\n" end
            cmdline.append_entrypoint = cmdline.append_entrypoint .. contents
            return true
        end,
        "file",
    },
    {
        "--gdb",
        function()
            assert(not cmdline.gdb or cmdline.gdb.address, "--gdb and --gdb-fd are mutually exclusive")
            cmdline.gdb = { address = "127.0.0.1:1234" }
            return true
        end,
    },
    {
        "--gdb=",
        function(_, _, address)
            assert(not cmdline.gdb or cmdline.gdb.address, "--gdb and --gdb-fd are mutually exclusive")
            cmdline.gdb = { address = address }
            return true
        end,
        "hostport",
    },
    {
        "--gdb-fd=",
        function(_, all, value)
            local fd = tonumber(value)
            assert(math.type(fd) == "integer" and fd >= 0, "invalid GDB socket file descriptor in " .. all)
            assert(not cmdline.gdb or cmdline.gdb.fd, "--gdb and --gdb-fd are mutually exclusive")
            cmdline.gdb = { fd = fd }
            return true
        end,
        "number",
    },
}

-- Dispatch for a plain-string option name. A trailing "=" marks a
-- value-taking option; otherwise the entry is a flag. The handler is always
-- called as handler(hint, all, value), with value == nil for flags and "all"
-- the option as typed (reconstructed as name=value for the short space form).
-- A hint table may name a positional sub-key in its array part (hint[1]); that
-- is read by parse_options, so it needs no separate threading here.
-- Returns whether the entry matched and whether it consumed the next argument.
local function try_named_option(option, a, nextarg)
    local name, handler, hint = option[1], option[2], option[3]
    if name:sub(-1) == "=" then
        local bare = name:sub(1, #name - 1)
        if a:sub(1, #name) == name then -- attached: --foo=value or -x=value
            local value = a:sub(#name + 1)
            assertf(#value > 0, "missing value for option %s", bare)
            handler(hint, a, value)
            return true, false
        elseif a == bare and bare:sub(1, 2) ~= "--" then -- bare short name
            -- short value options additionally take the value from the next argument
            if nextarg ~= nil and nextarg:sub(1, 1) ~= "-" then
                handler(hint, bare .. "=" .. nextarg, nextarg)
                return true, true
            end
            if bare == "-h" then error("did you mean --help?") end
            errorf("missing value for option %s", bare)
        end
        -- A bare long value option ("--foo" with no "=value") is left unmatched:
        -- an optional-value sibling flag entry ("--foo") matches it, otherwise the
        -- catch-all reports an unrecognized option (as it does today).
        return false, false
    end
    if a == name then -- flag
        handler(hint, a, nil)
        return true, false
    end
    return false, false
end

if #arg == 1 and arg[1] == "--bash-completion" then handle_bash_completion() end

-- Finally load the dependencies
cartesi = require("cartesi")
util = require("cartesi.util")
hash_tree = require("cartesi.hash-tree")

-- And perform the dependent initializations
MCYCLE_MAX = cartesi.MCYCLE_MAX
cmdline.max_mcycle = MCYCLE_MAX
ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE = cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH = cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
assert(
    (1 << ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE) - 1 == cartesi.UARCH_CYCLE_MAX,
    "uarch cycle limit does not match the rollup geometry"
)
local default_config = cartesi.machine:get_default_config()
cmdline.config.dtb.bootargs = default_config.dtb.bootargs
cmdline.config.hash_tree.hash_function = default_config.hash_tree.hash_function
cmdline.config.processor.registers.htif = {
    iconsole = cartesi.HTIF_CONSOLE_CMD_PUTCHAR_MASK,
    iyield = cartesi.HTIF_YIELD_CMD_AUTOMATIC_MASK | cartesi.HTIF_YIELD_CMD_MANUAL_MASK,
}
to_sharing_map = {
    none = cartesi.SHARING_NONE,
    config = cartesi.SHARING_CONFIG,
    all = cartesi.SHARING_ALL,
}

-- Process command line options
local argi = 1
while argi <= #arg do
    local a = arg[argi]
    if cmdline.opts_finished then
        cmdline.exec_arguments[#cmdline.exec_arguments + 1] = a
        argi = argi + 1
    else
        local nextarg = arg[argi + 1]
        local matched, consumed = false, false
        for _, option in ipairs(options) do
            matched, consumed = try_named_option(option, a, nextarg)
            if matched then break end
        end
        if not matched then
            -- not a recognized option: "--" or a non-option argument ends
            -- option processing; a leftover "-..." is an error.
            local not_option = a:sub(1, 1) ~= "-"
            assertf(not_option or a == "--", "unrecognized option %s", a)
            cmdline.opts_finished = true
            if not_option then cmdline.exec_arguments = { a } end
        end
        argi = argi + (consumed and 2 or 1)
    end
end

local function print_root_hash(machine, print)
    (print or stderr)("%u: %s\n", machine:read_reg("mcycle"), cartesi.tohex(machine:get_root_hash()))
end

local function dump_value_proofs(machine, desired_proofs, config)
    if #desired_proofs > 0 then
        assert(config.processor.registers.iunrep == 0, "proofs are meaningless in unreproducible mode")
    end
    for _, desired in ipairs(desired_proofs) do
        if not desired.address or not desired.log2_size then
            local drive = util.find_drive(config, "flash_drive", desired.label)
                or util.find_drive(config, "nvram", desired.label)
            assertf(drive, "flash-drive or nvram not found with label %s in %s", desired.label, desired.cmdline)
            desired.log2_size = drive.log2_size
            desired.address = drive.start
        end
        assertf(
            desired.log2_size >= cartesi.HASH_TREE_LOG2_WORD_SIZE,
            "log2_size must be at least %u in %s",
            cartesi.HASH_TREE_LOG2_WORD_SIZE,
            desired.cmdline
        )
        local proof = machine:get_proof(desired.address, desired.log2_size)
        local out = desired.filename and assert(io.open(desired.filename, "wb")) or io.stdout
        if desired.format == "lua" then
            out:write("return ")
            util.dump_table(proof, out)
        end
        if desired.format == "json" then out:write(cartesi.tojson(proof, 2, "Proof"), "\n") end
        if desired.filename then out:close() end
    end
end

local function new_machine()
    assert(not cmdline.remote_health_check or cmdline.remote_address, "missing remote address")
    if cmdline.remote_address then
        local jsonrpc = require("cartesi.jsonrpc")
        local new_m = assert(jsonrpc.connect_server(cmdline.remote_address))
        if cmdline.remote_fork then
            local fork_address, fork_pid
            new_m, fork_address, fork_pid = assert(new_m:fork_server())
            stderr("Forked JSONRPC remote cartesi machine at '%s' with pid %d\n", fork_address, fork_pid)
            if cmdline.remote_fork ~= true then
                new_m:rebind_server(cmdline.remote_fork)
                stderr("Rebound forked JSONRPC remote cartesi machine at '%s'\n", cmdline.remote_fork)
            end
        end
        if cmdline.remote_health_check then os.exit(0, true) end
        stderr("Connected to JSONRPC remote cartesi machine at '%s'\n", cmdline.remote_address)
        local shutdown = function() new_m:shutdown_server() end
        setmetatable(remote_closer, {
            __gc = function()
                local address = new_m:get_server_address()
                if cmdline.remote_shutdown then
                    local ok, err = pcall(shutdown)
                    if ok then
                        stderr("Shutdown JSONRPC remote cartesi machine at '%s'\n", address)
                    else
                        stderr("Failed to shutdown JSONRPC remote cartesi machine: %s\n", err)
                    end
                else
                    stderr("Left alive JSONRPC remote cartesi machine at '%s'\n", address)
                end
                if cmdline.remote_fork then
                    stderr("Left alive original JSONRPC remote cartesi machine at '%s'\n", cmdline.remote_address)
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
        update_hash_tree = cmdline.concurrency_update_hash_tree,
    },
    console = cmdline.console,
    skip_version_check = cmdline.skip_version_check,
    no_reserve = cmdline.no_reserve,
}

if cmdline.remote_spawn then
    local jsonrpc = require("cartesi.jsonrpc")
    local server <close>, address, pid = jsonrpc.spawn_server(cmdline.remote_address)
    server:set_cleanup_call(jsonrpc.NOTHING) -- we will perform shutdown manually
    stderr("Spawned JSONRPC remote cartesi machine at '%s' with pid %d\n", address, pid)
    cmdline.remote_address = address
end

if cmdline.create_dir then
    assert(
        not (cmdline.remote_address and not cmdline.remote_create),
        "cannot use --create and --no-remote-create at the same time"
    )
    assert(not cmdline.load_dir, "cannot use --create and --load at the same time")
    assert(
        cmdline.revert_mode == "stored" or cmdline.revert_mode == "none",
        "--create requires --revert-mode=stored or none"
    )
end

if cmdline.load_sharing and cmdline.load_sharing ~= cartesi.SHARING_NONE then
    assert(
        cmdline.revert_mode == "stored" or cmdline.revert_mode == "none",
        "shared stored machines require --revert-mode=stored or none"
    )
end
if cmdline.revert_mode == "stored" then
    assertf(cmdline.load_dir or cmdline.create_dir, "--revert-mode=stored requires --load or --create")
    if cmdline.load_dir then
        assert(cmdline.load_sharing == cartesi.SHARING_ALL, "--revert-mode=stored requires --load sharing:all")
    end
end

local stored_machine_dir = cmdline.load_dir or cmdline.create_dir
local stored_backup_dir = stored_machine_dir and (stored_machine_dir .. ".revert")

local main_machine = new_machine()
if cmdline.load_dir then
    stderr("Loading machine: please wait\n")
    if cmdline.clone_dir then main_machine:clone_stored(cmdline.clone_dir, cmdline.load_dir) end
    main_machine = main_machine:load(cmdline.load_dir, runtime_config, cmdline.load_sharing)
elseif not (cmdline.remote_address and not cmdline.remote_create) then
    -- Use the command-line config (a --load-config file may still override it below).
    local config = cmdline.config

    -- show splash on init
    if cmdline.init_splash then
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

    for idx = 1, cmdline.flash_drive_count do
        local entry = cmdline.flash_drives[idx]
        if entry then -- skip removed drives (e.g. --no-root-flash-drive)
            set_empty_omitted_filenames(entry)
            local dt_label = entry.label or "flashdrive" .. #config.flash_drive
            if not entry.length then entry.length = -1 end
            if entry.mke2fs == nil then entry.mke2fs = entry.backing_store.data_filename == "" end
            if entry.mount == nil then
                -- mount only if there is a file backing
                if entry.backing_store.data_filename ~= "" or entry.mke2fs then
                    if entry.label then
                        entry.mount = "/mnt/" .. entry.label
                    else
                        entry.mount = false
                    end
                else
                    entry.mount = false
                end
            elseif entry.mount == "true" then
                if entry.label then
                    entry.mount = "/mnt/" .. entry.label
                else
                    entry.mount = false
                end
            elseif entry.mount == "false" then
                entry.mount = false
            end
            if entry.label == "root" and entry.read_only then -- Mount root filesystem as read-only
                config.dtb.bootargs = config.dtb.bootargs:gsub("%f[^%s%z]rw%f[%s%z]", "ro")
            end
            config.flash_drive[#config.flash_drive + 1] = entry
            if entry.label ~= "root" and (entry.mke2fs or entry.mount or entry.user) then
                config.dtb.init = config.dtb.init .. string.format("dev=$(flashdrive %s)\n", dt_label)
                if entry.mke2fs then
                    config.dtb.init = config.dtb.init
                        .. string.format('busybox mke2fs -F -b 4096 -I 256 -L "%s" "$dev" > /dev/null\n', dt_label)
                end
                if entry.mount then
                    config.dtb.init = config.dtb.init
                        .. string.format(
                            'busybox mkdir -p "%s" && busybox mount%s "$dev" "%s"\n',
                            entry.mount,
                            entry.read_only and " -o ro" or "",
                            entry.mount
                        )
                end
                if entry.user then
                    local chownpath = entry.mount or "$dev"
                    config.dtb.init = config.dtb.init
                        .. string.format('busybox chown %s: "%s"\n', entry.user, chownpath)
                end
            end
        end
    end

    for idx = 1, cmdline.nvram_count do
        local entry = cmdline.nvrams[idx]
        if entry then
            set_empty_omitted_filenames(entry)
            local dt_label = entry.label or "nvram" .. #config.nvram
            if not entry.length then entry.length = -1 end
            config.nvram[#config.nvram + 1] = entry
            config.dtb.init = config.dtb.init .. string.format("dev=$(nvram %s)\n", dt_label)
            if entry.read_only then
                config.dtb.init = config.dtb.init .. 'busybox chmod 0444 "$dev"\n'
            else
                config.dtb.init = config.dtb.init .. 'busybox chmod 0664 "$dev"\n'
            end
            if entry.user then
                config.dtb.init = config.dtb.init .. string.format('busybox chown %s: "$dev"\n', entry.user)
            end
        end
    end

    if #cmdline.append_bootargs > 0 then config.dtb.bootargs = config.dtb.bootargs .. " " .. cmdline.append_bootargs end
    if #cmdline.append_init > 0 then config.dtb.init = config.dtb.init .. cmdline.append_init end
    if #cmdline.append_entrypoint > 0 then
        config.dtb.entrypoint = config.dtb.entrypoint .. cmdline.append_entrypoint
    end
    if #cmdline.exec_arguments > 0 then
        config.dtb.entrypoint = config.dtb.entrypoint .. table.concat(cmdline.exec_arguments, " ")
    end

    if cmdline.load_config and cmdline.load_config_format == "json" then
        config = setmetatable(cartesi.fromjson(util.read_file(cmdline.load_config)), { __index = config })
    elseif cmdline.load_config then
        local env = {}
        local chunk, err = loadfile(cmdline.load_config, "t", env)
        if not chunk then
            stderr("Failed to load machine config (%s):\n", cmdline.load_config)
            error(err)
        end
        local ok, ret = pcall(chunk)
        if not ok then
            stderr("Failed to load machine config (%s):\n", cmdline.load_config)
            error(ret)
        end
        config = setmetatable(ret, { __index = config })
    end

    main_machine = main_machine:create(config, runtime_config, cmdline.create_dir)
end

local function serialize_config(out, config, format)
    if format == "json" then
        out:write(cartesi.tojson(config, 2), "\n")
    elseif format == "lua" then
        out:write("return ")
        util.dump_table(config, out, default_config)
        out:write("\n")
    end
end

-- obtain config from instantiated machine
local initial_config = main_machine:get_initial_config()

for _, r in ipairs(cmdline.memory_range_replace) do
    set_empty_omitted_filenames(r)
    main_machine:replace_memory_range(r)
end

if type(cmdline.store_config) == "string" then
    local f <close> = assert(io.open(cmdline.store_config, "w"))
    serialize_config(f, initial_config, cmdline.store_config_format)
elseif cmdline.store_config then
    serialize_config(io.stdout, initial_config, cmdline.store_config_format)
end

local cmio_yield_automatic_reason = {
    [cartesi.HTIF_YIELD_AUTOMATIC_REASON_PROGRESS] = "progress",
    [cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT] = "tx-output",
    [cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT] = "tx-report",
}

local cmio_yield_manual_reason = {
    [cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED] = "rx-accepted",
    [cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED] = "rx-rejected",
    [cartesi.HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION] = "tx-exception",
}

local cmio_yield_command = {
    [cartesi.HTIF_YIELD_CMD_MANUAL] = "Manual",
    [cartesi.HTIF_YIELD_CMD_AUTOMATIC] = "Automatic",
}

local function check_cmio_htif_config(htif)
    assert((htif.iconsole & cartesi.HTIF_CONSOLE_CMD_GETCHAR_MASK) == 0, "console getchar must be disabled for cmio")
    assert(
        htif.iyield == (cartesi.HTIF_YIELD_CMD_MANUAL_MASK | cartesi.HTIF_YIELD_CMD_AUTOMATIC_MASK),
        "yield manual must be enabled for cmio"
    )
end

local function report_mcycles(machine) stderr("Cycles: %u\n", machine:read_reg("mcycle")) end

local function report_uarch_cycles(machine) stderr("uCycles: %u\n", machine:read_reg("uarch_cycle")) end

local function get_and_print_yield(machine, htif)
    local cmd, yield_reason, data = machine:receive_cmio_request()
    if cmd == cartesi.HTIF_YIELD_CMD_AUTOMATIC and yield_reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_PROGRESS then
        stderr(
            "Progress: %6.2f" .. ((htif.iconsole & cartesi.HTIF_CONSOLE_CMD_GETCHAR_MASK) ~= 0 and "\n" or "\r"),
            string.unpack("I4", data) / 10
        )
        return cmd, yield_reason, data
    end
    local cmd_str = cmio_yield_command[cmd] or "Unknown"
    local reason_str = "unknown"
    if cmd == cartesi.HTIF_YIELD_CMD_AUTOMATIC then
        reason_str = cmio_yield_automatic_reason[yield_reason] or reason_str
    elseif cmd == cartesi.HTIF_YIELD_CMD_MANUAL then
        reason_str = cmio_yield_manual_reason[yield_reason] or reason_str
    end
    stderr("\n%s yield %s (%d) (0x%06x data)\n", cmd_str, reason_str, yield_reason, #data)
    report_mcycles(machine)
    return cmd, yield_reason, data
end

local function instantiate_filename(pattern, values)
    -- replace escaped % with something safe
    pattern = string.gsub(pattern, "%\\%%", "\0")
    pattern = string.gsub(pattern, "%%(%d+)(%a)", function(p, s) return string.sub(values[s] or s, 1, p) end)
    pattern = string.gsub(pattern, "%%(%a)", function(s) return values[s] or s end)
    -- restore escaped %
    return (string.gsub(pattern, "\0", "%"))
end

-- An empty pattern ("") disables writing the file. "%i" is the producing input (the just-run
-- input), "%o" the index argument (a global output index, or a per-input report index).
local function save_cmio_state_with_format(advance, data, format, index)
    if format == "" then return end
    local values = { i = advance.next_input_index - 1, o = index }
    local name = instantiate_filename(format, values)
    stderr("Storing %s\n", name)
    util.write_file(data, name)
end

local function save_cmio_report(advance, data)
    return save_cmio_state_with_format(advance, data, advance.report, advance.report_index)
end

local function save_cmio_output(advance, data, index)
    return save_cmio_state_with_format(advance, data, advance.output, index)
end

local function save_cmio_rejected_output(advance, data, index)
    return save_cmio_state_with_format(advance, data, advance.rejected_output, index)
end

local function save_cmio_outputs_merkle_root(advance, data)
    return save_cmio_state_with_format(advance, data, advance.outputs_merkle_root)
end

-- Serializes a Proof to a string in the resolved format. Lua keeps hashes raw (like
-- machine:get_proof), JSON base64-encodes them via the "Proof" schema.
local function serialize_proof(proof, format)
    if format == "json" then return cartesi.tojson(proof, 2, "Proof") .. "\n" end
    local parts = {}
    util.dump_table(proof, {
        write = function(_, ...)
            for i = 1, select("#", ...) do
                parts[#parts + 1] = (select(i, ...))
            end
        end,
    })
    return "return " .. table.concat(parts) .. "\n"
end

-- Reads back a Proof written by serialize_proof, in the resolved format (explicit format wins,
-- else the filename extension).
local function read_proof(filename, format)
    local contents = util.read_file(filename)
    if resolve_format(format, filename) == "json" then return cartesi.fromjson(contents, "Proof") end
    return assert(load(contents, filename, "t", {}))()
end

-- Writes the epoch's output proofs, one per accepted output, keyed by global output index
-- "%o" (= target_address) and producing input "%i".
local function save_cmio_output_proofs(advance)
    if advance.output_proof == "" then return end
    local proofs = hash_tree.frontier_next_proofs(advance.frontier, advance.output_hashes)
    local format = resolve_format(advance.format, advance.output_proof)
    for i, proof in ipairs(proofs) do
        local values = { i = advance.output_inputs[i], o = proof.target_address }
        local name = instantiate_filename(advance.output_proof, values)
        stderr("Storing %s\n", name)
        util.write_file(serialize_proof(proof, format), name)
    end
end

-- Writes the proof, in the machine state in which the just-accepted input was accepted, that the
-- outputs Merkle root occupied the first word of the tx buffer (its 32 bytes are exactly one
-- tree word). This ties the outputs Merkle root, against which "output_proof" proves each output,
-- back into the machine state hash. Must be called while the machine still sits at the accept yield.
local function save_cmio_outputs_merkle_root_proof(advance, proof)
    if advance.outputs_merkle_root_proof == "" then return end
    local values = { i = advance.next_input_index - 1 }
    local name = instantiate_filename(advance.outputs_merkle_root_proof, values)
    local format = resolve_format(advance.format, advance.outputs_merkle_root_proof)
    stderr("Storing %s\n", name)
    util.write_file(serialize_proof(proof, format), name)
end

-- Once the just-run input was accepted or rejected, commit or discard its buffered outputs. Accepted outputs
-- are saved, added to the running hash-tree frontier (for the root check), and accumulated for the
-- end-of-epoch proofs. Otherwise (a reject, halt, or exception) the outputs go to their own files
-- and never enter the tree.
local function flush_pending_outputs(machine, advance, yield_reason, data)
    if is_rx_accepted(yield_reason) then
        for _, output in ipairs(advance.pending_outputs) do
            save_cmio_output(advance, output, advance.global_output_index)
            local leaf = cartesi.keccak256(output)
            advance.output_hashes[#advance.output_hashes + 1] = leaf
            advance.output_inputs[#advance.output_inputs + 1] = advance.next_input_index - 1
            hash_tree.frontier_push_back(advance.running_frontier, leaf)
            advance.global_output_index = advance.global_output_index + 1
        end
        assert(#data == cartesi.HASH_SIZE, "expected outputs Merkle root in tx buffer")
        save_cmio_outputs_merkle_root(advance, data)
        if advance.check_outputs_merkle_root then
            assertf(
                hash_tree.frontier_get_root_hash(advance.running_frontier) == data,
                "outputs Merkle root mismatch at input %d",
                advance.next_input_index - 1
            )
        end
        -- The accept-state proof that the tx buffer holds this root hash (target_hash = keccak256(data)).
        local proof = machine:get_proof(cartesi.AR_CMIO_TX_BUFFER_START, cartesi.HASH_TREE_LOG2_WORD_SIZE)
        assert(proof.target_hash == cartesi.keccak256(data), "tx buffer does not hold the outputs Merkle root")
        save_cmio_outputs_merkle_root_proof(advance, proof)
    else
        for position, output in ipairs(advance.pending_outputs) do
            save_cmio_rejected_output(advance, output, advance.global_output_index + position - 1)
        end
    end
    advance.pending_outputs = {}
end

local function load_cmio_input(machine, advance, revert_root_hash)
    local values = { i = advance.next_input_index }
    local data = util.read_file(instantiate_filename(advance.input, values))
    -- The pre-input root hash is recorded so the EVM verifier can prove a reject
    -- restores this state, regardless of how the host implements the revert.
    machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_root_hash)
end

local function load_cmio_query(machine, inspect)
    local data = util.read_file(inspect.query)
    machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_INSPECT_STATE, data)
end

local function save_cmio_inspect_state_report(inspect, data)
    if inspect.report == "" then return end
    local values = { o = inspect.report_index }
    local name = instantiate_filename(inspect.report, values)
    stderr("Storing %s\n", name)
    util.write_file(data, name)
end

local function store_machine(machine, config, dir, sharing)
    assert(config.processor.registers.iunrep == 0, "hashes are meaningless in unreproducible mode")
    stderr("Storing machine: please wait\n")
    local values = {}
    if dir:find("%%%d*h") then values.h = cartesi.tohex(machine:get_root_hash()) end
    local name = instantiate_filename(dir, values)
    machine:store(name, sharing)
end

local function dump_memory_ranges(machine, dir)
    local prefix = type(dir) == "string" and dir .. "/" or ""
    if prefix ~= "" then assertf(os.execute("mkdir " .. dir), "could not create directory %s", dir) end
    for _, v in ipairs(machine:get_address_ranges()) do
        -- Only memory ranges hold state. Device ranges are always pristine, so skip them.
        if v.is_memory then
            local filename = prefix .. string.format("%016x--%016x.bin", v.start, v.length)
            util.write_file(machine:read_memory(v.start, v.length), filename)
        end
    end
end

-- The machine runs in one of two modes, and combinations that make no sense are precluded right
-- away. In cmio mode (--cmio-advance-state and/or --cmio-inspect-state), the host feeds requests,
-- optionally making a computation hash. In a plain run, it can instead print mcycle root hashes
-- or uarch cycle root hashes, one excluding the other. Debugging combines with any of them, but
-- hash collection assumes the debugger only observes, so that combination warns.
local mcycle_root_hashes = cmdline.mcycle_root_hashes_log2_period ~= nil
local computation_hash = cmdline.cmio_advance
    and (cmdline.cmio_advance.mcycle_computation_hash or cmdline.cmio_advance.uarch_cycle_computation_hash)
if cmdline.cmio_advance or cmdline.cmio_inspect then
    assert(not cmdline.uarch_cycle_root_hashes_count, "cmio cannot be combined with printing uarch cycle root hashes")
    assert(not mcycle_root_hashes, "cmio cannot be combined with printing mcycle root hashes")
end
if cmdline.gdb and (mcycle_root_hashes or cmdline.uarch_cycle_root_hashes_count or computation_hash) then
    stderr("Warning: writing to registers or memory from GDB produces hashes of states the computation never visits\n")
end
if cmdline.uarch_cycle_root_hashes_count then
    assert(not mcycle_root_hashes, "printing uarch cycle root hashes cannot be combined with mcycle root hashes")
end
-- Sampling any hashes needs a reproducible machine.
if mcycle_root_hashes or computation_hash then
    assert(initial_config.processor.registers.iunrep == 0, "hashes are meaningless in unreproducible mode")
end
-- The uarch only runs in machines configured with keccak256.
if cmdline.cmio_advance and cmdline.cmio_advance.uarch_cycle_computation_hash then
    assert(
        initial_config.hash_tree.hash_function == "keccak256",
        "uarch cycle computation hash requires the keccak256 hash function"
    )
end
local machine = main_machine
local gdb_stub
if cmdline.gdb then
    gdb_stub = require("cartesi.gdbstub").new(machine, cmdline.max_mcycle)
    if cmdline.gdb.fd then
        gdb_stub:wait_gdb_fd(cmdline.gdb.fd)
    else
        local address, port = cmdline.gdb.address:match("^(.*):(%d+)$")
        assert(address and port, "invalid address for GDB")
        gdb_stub:wait_gdb_address_port(address, tonumber(port))
    end
end
if initial_config.processor.registers.iunrep ~= 0 then stderr("Running in unreproducible mode!\n") end
if cmdline.cmio_advance or cmdline.cmio_inspect then
    check_cmio_htif_config(initial_config.processor.registers.htif)
    if cmdline.revert_mode == "fork" then
        assert(cmdline.remote_address, "--revert-mode=fork requires --remote-address for cmio")
    end
end
-- Seed the outputs Merkle tree frontier once, at the epoch start. With last_output_proof, resume the
-- genesis-rooted tree from the previous epoch's last output, so this epoch's outputs continue at
-- their running global indices. Otherwise start empty at genesis. The seed frontier produces the
-- end-of-epoch proofs, and a copy tracks the running per-input root check.
if cmdline.cmio_advance then
    local depth = cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT
    if cmdline.cmio_advance.last_output_proof then
        local proof = read_proof(cmdline.cmio_advance.last_output_proof, cmdline.cmio_advance.format)
        assertf(
            proof.log2_root_size == depth and proof.log2_target_size == 0,
            "%s is not an outputs proof",
            cmdline.cmio_advance.last_output_proof
        )
        cmdline.cmio_advance.frontier = hash_tree.frontier(proof, "keccak256")
        cmdline.cmio_advance.global_output_index = proof.target_address + 1
    else
        cmdline.cmio_advance.frontier = hash_tree.frontier(depth, "keccak256")
        cmdline.cmio_advance.global_output_index = 0
    end
    cmdline.cmio_advance.running_frontier = hash_tree.frontier_copy(cmdline.cmio_advance.frontier)
    cmdline.cmio_advance.output_hashes = {}
    cmdline.cmio_advance.output_inputs = {}
    cmdline.cmio_advance.pending_outputs = {}
end
if cmdline.initial_hash then
    assert(initial_config.processor.registers.iunrep == 0, "hashes are meaningless in unreproducible mode")
    if type(cmdline.initial_hash) == "string" then
        util.write_file(machine:get_root_hash(), cmdline.initial_hash)
    else
        print_root_hash(machine, stderr_unsilenceable)
    end
end
dump_value_proofs(machine, cmdline.initial_proof, initial_config)
local exit_code = 0

-- Select the snapshot implementation once. Callers do not need to know which mode is active.
local snapshot = function() end

local commit = function() end

local revert = function() end

local has_snapshot = function() return false end

if cmdline.revert_mode == "fork" then
    local backup_machine = nil
    snapshot = function(m)
        if backup_machine then backup_machine:shutdown_server() end
        backup_machine = m:fork_server()
    end

    commit = function()
        if backup_machine then
            backup_machine:shutdown_server()
            backup_machine = nil
        end
    end

    revert = function(m)
        assert(backup_machine, "no snapshot to revert to")
        local address = m:get_server_address()
        m:shutdown_server()
        m:swap(backup_machine)
        m:rebind_server(address)
        backup_machine = nil
    end

    has_snapshot = function() return backup_machine ~= nil end
elseif cmdline.revert_mode == "stored" then
    local stored_backup = false

    snapshot = function(m)
        m:destroy()
        m:clone_stored(stored_machine_dir, stored_backup_dir)
        m:sync_stored(stored_backup_dir)
        m:load(stored_machine_dir, runtime_config, cartesi.SHARING_ALL)
        stored_backup = true
    end

    commit = function(m)
        m:sync_stored(stored_machine_dir)
        if stored_backup then
            m:remove_stored(stored_backup_dir)
            stored_backup = false
        end
    end

    revert = function(m)
        assert(stored_backup, "no stored snapshot to revert to")
        m:destroy()
        m:remove_stored(stored_machine_dir)
        m:rename_stored(stored_backup_dir, stored_machine_dir)
        m:load(stored_machine_dir, runtime_config, cartesi.SHARING_ALL)
        stored_backup = false
    end

    has_snapshot = function() return stored_backup end

    -- Cloning fails without overwriting anything if the backup directory already exists.
    snapshot(machine)
    commit(machine)
end

-- Make sure an error does not leave a fork or an incomplete stored transaction behind.
-- luacheck: push ignore 211
local backup_closer <close> = setmetatable({}, {
    __close = function()
        -- If we have a backup on exit, we probably raised an error, so we revert
        if has_snapshot() then revert(machine) end
    end,
})
-- luacheck: pop

-- run_to_stop resumes the machine through a "runner": any object with a
-- run(self, mcycle_end) method returning the break reason, exactly like machine:run. The machine
-- itself is the plain runner; gdb_stub, the two hash-printing runners, and
-- the computation-hash object below are the others. The runner is the only thing that knows the
-- mode. The machine and gdb_stub also implement the two collect calls, and the hash-sampling
-- runners advance through either, so hashes can be collected while GDB drives the machine.

-- Prints the hashes one uarch cycle collect call returned. Without bundling, each hash after a uarch
-- cycle is printed as "<mcycle>,<uarch_cycle>: <hash>", and each hash after an implicit uarch reset
-- (the entries immediately before each mcycle hash offset) as "<mcycle>: <hash>", at the machine
-- cycle the reset completed. With bundling, each entry is instead a bundle root covering a range
-- of bundle_size uarch cycles, printed as "<mcycle>,<first>-<mcycle>,<last>: <hash>". A uarch halt
-- repeats until the reset, so the ranges continue past it, and the reset entry, whose last covered
-- position is the completed machine cycle, is printed as "<mcycle>,<first>-<mcycle+1>: <hash>".
local function print_collected_uarch_hashes(hashes, mcycle_hash_offsets, mcycle, bundle_size)
    local next_offset = 2
    local uarch_cycle = 1
    for i, hash in ipairs(hashes) do
        if mcycle_hash_offsets[next_offset] == i + 1 then
            if bundle_size == 1 then
                stderr("%u: %s\n", mcycle + 1, cartesi.tohex(hash))
            else
                stderr("%u,%u-%u: %s\n", mcycle, uarch_cycle, mcycle + 1, cartesi.tohex(hash))
            end
            mcycle = mcycle + 1
            uarch_cycle = 1
            next_offset = next_offset + 1
        else
            if bundle_size == 1 then
                stderr("%u,%u: %s\n", mcycle, uarch_cycle, cartesi.tohex(hash))
            else
                stderr(
                    "%u,%u-%u,%u: %s\n",
                    mcycle,
                    uarch_cycle,
                    mcycle,
                    uarch_cycle + bundle_size - 1,
                    cartesi.tohex(hash)
                )
            end
            uarch_cycle = uarch_cycle + bundle_size
        end
    end
end

local LOG2_HASHES_PER_CHUNK = 8 -- target about 256 returned hashes per collect call
local LOG2_ESTIMATED_UARCH_CYCLES_PER_MCYCLE = 10 -- assume about 1024 uarch cycles per mcycle

local function uarch_hashes_chunk_size(log2_bundle)
    -- Each mcycle also produces an all-halted bundle and a bundle ending at the reset state.
    local cycle_bundle_count = log2_bundle < LOG2_ESTIMATED_UARCH_CYCLES_PER_MCYCLE
            and (1 << (LOG2_ESTIMATED_UARCH_CYCLES_PER_MCYCLE - log2_bundle))
        or 1
    local estimated_hashes_per_mcycle = cycle_bundle_count + 2
    return math.max(1, (1 << LOG2_HASHES_PER_CHUNK) // estimated_hashes_per_mcycle)
end

-- The --print-uarch-cycle-root-hashes runner. collect_uarch_cycle_root_hashes samples the machine state hash
-- after every uarch cycle for the count machine cycles that follow start, resetting the uarch
-- between machine cycles, optionally bundling every 2^log2_bundle samples into a subtree root, and
-- each result is printed. Outside that window the machine runs plainly, all in this same call, so a
-- stop is only reported once we reach the real target.
local function uarch_cycle_root_hashes_runner_run(self, mcycle_end)
    local m = self.machine
    -- Run plainly up to the window start (once), and print the hash the window starts from.
    if self.start then
        if math.ult(m:read_reg("mcycle"), self.start) then
            local break_reason = self.runner:run(umin(self.start, mcycle_end))
            -- stopped before start (a halt, a yield, or max_mcycle): report it
            if m:read_reg("mcycle") ~= self.start then return break_reason end
        end
        print_root_hash(m)
        self.window_end = self.start + self.count
        self.start = nil
    end
    -- Collect within the window, one uarch cycle at a time.
    local mcycle = m:read_reg("mcycle")
    local collection_end = umin(self.window_end, mcycle_end)
    if math.ult(mcycle, collection_end) then
        -- The revert uarch tail only matters when the run stops at a rejected manual yield, which
        -- never happens outside cmio mode. The minimal valid tail suffices: a single uarch cycle
        -- landing on the machine's recorded revert root hash.
        local revert_root_hash = m:read_revert_root_hash()
        local fake_revert_uarch_tail = { revert_root_hash, revert_root_hash }
        while math.ult(mcycle, collection_end) do
            local chunk_end = usaturating_add(mcycle, self.chunk_size, collection_end)
            local collected =
                self.runner:collect_uarch_cycle_root_hashes(chunk_end, self.log2_bundle, fake_revert_uarch_tail)
            print_collected_uarch_hashes(collected.hashes, collected.mcycle_hash_offsets, mcycle, 1 << self.log2_bundle)
            mcycle = m:read_reg("mcycle")
            -- A stop inside the window is reported (a serviced automatic yield resumes the window).
            -- Hide artificial chunk boundaries from run_to_stop.
            if not is_target_mcycle(collected.break_reason) or mcycle == mcycle_end then
                return collected.break_reason
            end
        end
    end
    -- Past the window, run plainly.
    return self.runner:run(mcycle_end)
end
local function make_uarch_cycle_root_hashes_runner(runner, start, count, log2_bundle)
    return {
        machine = machine,
        runner = runner,
        start = start,
        count = count,
        chunk_size = uarch_hashes_chunk_size(log2_bundle),
        log2_bundle = log2_bundle,
        run = uarch_cycle_root_hashes_runner_run,
    }
end

-- Prints the hashes one collect call returned. Without bundling, each hash is a state hash printed as
-- "<mcycle>: <hash>" at its own period boundary (the first at mcycle + period - mcycle_phase, then
-- every period), and, when the machine stopped at a fixed point, the hash of the stopped state at
-- the mcycle where it stopped, on a period boundary or not. With bundling, each hash is instead a
-- bundle root covering bundle_size samples (fill of them left over from the previous call),
-- printed as "<first>-<last>: <hash>" with the boundaries of the first and last samples it covers.
-- A fixed point repeats until the end of its bundle, so the ranges continue past it.
local function print_collected_hashes(m, hashes, mcycle, period, mcycle_phase, bundle_size, fill, at_fixed_point)
    local boundary = mcycle + period - mcycle_phase
    if bundle_size == 1 then
        for i = 1, #hashes - (at_fixed_point and 1 or 0) do
            stderr("%u: %s\n", boundary, cartesi.tohex(hashes[i]))
            boundary = boundary + period
        end
        -- A machine already stopped on entry collects nothing.
        if at_fixed_point and #hashes > 0 then
            stderr("%u: %s\n", m:read_reg("mcycle"), cartesi.tohex(hashes[#hashes]))
        end
        return
    end
    for i, hash in ipairs(hashes) do
        local first = boundary + ((i - 1) * bundle_size - fill) * period
        local last = boundary + (i * bundle_size - 1 - fill) * period
        stderr("%u-%u: %s\n", first, last, cartesi.tohex(hash))
    end
end

-- The --print-mcycle-root-hashes runner. collect_mcycle_root_hashes samples the machine state hash every
-- `period` mcycles (starting at `start`, or at mcycle 0), plus wherever the machine stops advancing,
-- optionally bundling every 2^log2_bundle samples into a subtree root, and each result is printed.
-- self.mcycle_phase and self.partial_bundle thread across calls so the sampling and bundling stay
-- continuous.
local function mcycle_hashes_chunk_size(log2_period, log2_bundle)
    local log2_chunk_size = log2_period + log2_bundle + LOG2_HASHES_PER_CHUNK
    if log2_chunk_size >= 64 then return MCYCLE_MAX end
    return 1 << log2_chunk_size
end

local function mcycle_root_hashes_runner_run(self, mcycle_end)
    local m = self.machine
    -- Delay sampling to a start mcycle by running plainly up to it (once), then collect from there
    -- in this same call, so a stop is only reported once we reach the real target.
    if self.start then
        if math.ult(m:read_reg("mcycle"), self.start) then
            local break_reason = self.runner:run(umin(self.start, mcycle_end))
            -- stopped before start (a halt, a yield, or max_mcycle): report it
            if m:read_reg("mcycle") ~= self.start then return break_reason end
        end
        print_root_hash(m)
        self.start = nil
    end
    local mcycle_phase = self.mcycle_phase
    local partial_bundle = self.partial_bundle
    local collected
    repeat
        local mcycle = m:read_reg("mcycle")
        local fill = partial_bundle and partial_bundle.leaf_count or 0
        local chunk_end = usaturating_add(mcycle, self.chunk_size, mcycle_end)
        collected = self.runner:collect_mcycle_root_hashes(
            chunk_end,
            self.log2_period,
            mcycle_phase,
            self.log2_bundle,
            partial_bundle
        )
        if collected.console_io_error then stderr("Console I/O error: %s\n", collected.console_io_error) end
        local at_fixed_point = is_at_fixed_point(collected.break_reason)
        print_collected_hashes(
            m,
            collected.hashes,
            mcycle,
            self.period,
            mcycle_phase,
            1 << self.log2_bundle,
            fill,
            at_fixed_point
        )
        mcycle_phase = collected.mcycle_phase
        partial_bundle = collected.partial_bundle
    until not is_target_mcycle(collected.break_reason) or chunk_end == mcycle_end
    self.mcycle_phase = mcycle_phase
    self.partial_bundle = partial_bundle
    return collected.break_reason
end
local function make_mcycle_root_hashes_runner(runner, log2_period, start, log2_bundle)
    return {
        machine = machine,
        runner = runner,
        period = 1 << log2_period,
        chunk_size = mcycle_hashes_chunk_size(log2_period, log2_bundle),
        log2_period = log2_period,
        start = start,
        log2_bundle = log2_bundle,
        mcycle_phase = 0,
        run = mcycle_root_hashes_runner_run,
    }
end

-- The mcycle computation hash commits to an epoch's state history. Each input occupies
-- 2^ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE mcycles, sampled every
-- 2^log2_mcycle_computation_hash_period mcycles, and an epoch occupies
-- 2^ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH inputs. The tree excludes the state at the start of
-- the first input. If an input stops before using its full mcycle budget, its final state hash fills
-- the remaining tree positions reserved for that input. A rejected input uses its revert root
-- hash. The epoch's final state also fills the tree segments reserved for unprocessed inputs.
-- Bundles are interior nodes of the same tree, so they shorten the frontier without changing its
-- root.
--
-- The claim is a runner while an input executes. Its other methods delimit inputs and the epoch.
-- boot and inspect queries bypass it.

-- Adds a collection's entries to the epoch-tree frontier. At a fixed point, the final returned
-- entry fills every unfilled position in the tree segment reserved for the current input.
local function mcycle_computation_hash_push_collected(self, collected)
    local count = umin(#collected.hashes, self.input_entry_capacity - self.input_entry_count)
    for i = 1, count do
        hash_tree.frontier_push_back(self.frontier, collected.hashes[i])
    end
    self.input_entry_count = self.input_entry_count + count
    if not is_at_fixed_point(collected.break_reason) then return end
    assert(#collected.hashes > 0, "fixed-point mcycle collection has no final entry")
    self.pad_entry = collected.hashes[#collected.hashes]
    hash_tree.frontier_pad_back(self.frontier, self.pad_entry, self.input_entry_capacity - self.input_entry_count)
    self.input_entry_count = self.input_entry_capacity
end

local function mcycle_computation_hash_begin_epoch(self)
    local log2_entries_per_input = ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE - self.log2_period - self.log2_bundle
    self.frontier =
        hash_tree.frontier(ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH + log2_entries_per_input, self.hash_type)
    self.input_entry_capacity = 1 << log2_entries_per_input
    self.pad_entry = nil
end

-- Input delivery does not advance mcycle. Open at the pre-delivery boundary, exclude that boundary
-- from the samples, and limit collection to one input's mcycle budget.
local function mcycle_computation_hash_begin_input(self, input_index)
    self.input_index = input_index
    self.input_entry_count = 0
    self.mcycle_phase = 0
    self.partial_bundle = nil
    self.input_mcycle_end =
        usaturating_add(self.machine:read_reg("mcycle"), 1 << ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE)
end

-- Samples the input's state hashes up to mcycle_end and adds each returned entry to the epoch-tree
-- frontier. self.mcycle_phase and self.partial_bundle preserve the sampling period and partial
-- bundle across calls.
local function mcycle_computation_hash_run(self, mcycle_end)
    local m = self.machine
    mcycle_end = umin(self.input_mcycle_end, mcycle_end)
    local collected = {
        mcycle_phase = self.mcycle_phase,
        partial_bundle = self.partial_bundle,
    }
    local chunk_end = m:read_reg("mcycle")
    repeat
        chunk_end = usaturating_add(chunk_end, self.chunk_size, mcycle_end)
        collected = self.runner:collect_mcycle_root_hashes(
            chunk_end,
            self.log2_period,
            collected.mcycle_phase,
            self.log2_bundle,
            collected.partial_bundle
        )
        if collected.console_io_error then stderr("Console I/O error: %s\n", collected.console_io_error) end
        mcycle_computation_hash_push_collected(self, collected)
    until not is_target_mcycle(collected.break_reason) or chunk_end == mcycle_end
    self.mcycle_phase = collected.mcycle_phase
    self.partial_bundle = collected.partial_bundle
    return collected.break_reason
end

-- A completed input must have filled every position in its reserved tree segment.
local function mcycle_computation_hash_end_input(self)
    if not self.input_entry_count then return end
    assert(self.input_entry_count == self.input_entry_capacity, "mcycle computation hash input is incomplete")
    self.input_entry_count = nil
end

-- Fill the tree segments reserved for unprocessed inputs with the final fixed-point entry. If no
-- input ran, obtain that entry directly from the waiting, halted, or overflowed machine.
local function mcycle_computation_hash_end_epoch(self)
    self:end_input()
    local pad = self.pad_entry
    if not pad then
        local collected = self.machine:collect_mcycle_root_hashes(
            self.machine:read_reg("mcycle"),
            self.log2_period,
            0,
            self.log2_bundle
        )
        assert(is_at_fixed_point(collected.break_reason), "mcycle computation hash ended outside a fixed point")
        pad = collected.hashes[#collected.hashes]
        assert(pad, "fixed-point mcycle collection has no final entry")
    end
    local root = hash_tree.frontier_get_root_hash(self.frontier, pad)
    stderr("\nMcycle computation hash: %s\n", cartesi.tohex(root))
    if self.filename ~= "" then
        stderr("Storing %s\n", self.filename)
        util.write_file(root, self.filename)
    end
end

local function make_mcycle_computation_hash(m, advance, runner)
    local log2_period = advance.log2_mcycle_computation_hash_period
    return {
        machine = m,
        runner = runner,
        chunk_size = mcycle_hashes_chunk_size(log2_period, advance.log2_bundle_mcycle_count),
        log2_period = log2_period,
        log2_bundle = advance.log2_bundle_mcycle_count,
        hash_type = initial_config.hash_tree.hash_function,
        filename = advance.mcycle_computation_hash,
        begin_epoch = mcycle_computation_hash_begin_epoch,
        begin_input = mcycle_computation_hash_begin_input,
        run = mcycle_computation_hash_run,
        end_input = mcycle_computation_hash_end_input,
        end_epoch = mcycle_computation_hash_end_epoch,
    }
end

-- The uarch cycle computation hash expands one period of the mcycle claim into the transitions a
-- bottom-level dispute verifies. For each machine cycle in that period, the tree reserves
-- 2^ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE leaves. They cover execution through uarch halt,
-- repetitions of the halt state, and the implicit reset. For a rejected input, the state after
-- reset has the recorded revert root hash. At a fixed point, collection returns one more group of
-- uarch state hashes
-- without advancing the main machine. That group's subtree root fills each remaining machine-cycle
-- position in the selected period.
-- collect_uarch_cycle_root_hashes returns bundle roots in hashes. mcycle_hash_offsets marks where
-- the entries for each machine cycle begin. A bundle root replaces a complete subtree without
-- changing the claim root.

-- Adds the entries for one machine cycle to the frontier.
-- The final two entries are the all-halted bundle and the bundle ending in the reset hash.
-- Push the execution bundles, fill the remaining positions before the final one with copies of
-- the all-halted bundle (possibly none), and close with the reset-ending bundle.
local function uarch_cycle_computation_hash_push_mcycle(self, frontier, entries, first, last)
    local bundle_capacity = 1 << self.log2_bundles_per_mcycle
    local execution_bundle_count = last - first - 1
    for i = first, last - 2 do
        hash_tree.frontier_push_back(frontier, entries[i])
    end
    hash_tree.frontier_pad_back(frontier, entries[last - 1], bundle_capacity - 1 - execution_bundle_count)
    hash_tree.frontier_push_back(frontier, entries[last])
end

-- Adds each machine cycle's entries to the uarch computation-hash tree and emits its root when
-- complete.
-- A collection ending at a fixed point includes one extra group that does not advance the main
-- machine. Its subtree root fills every unfilled machine-cycle position in the selected period.
local function uarch_cycle_computation_hash_push_collected(self, collected)
    local mcycle_hash_offsets = collected.mcycle_hash_offsets
    local count = umin(#mcycle_hash_offsets - 1, self.period - self.mcycle_count)
    for i = 1, count do
        uarch_cycle_computation_hash_push_mcycle(
            self,
            self.frontier,
            collected.hashes,
            mcycle_hash_offsets[i],
            mcycle_hash_offsets[i + 1] - 1
        )
    end
    self.mcycle_count = self.mcycle_count + count

    if self.mcycle_count < self.period and is_at_fixed_point(collected.break_reason) then
        local pad_frontier = hash_tree.frontier(self.log2_bundles_per_mcycle, self.hash_type)
        uarch_cycle_computation_hash_push_mcycle(
            self,
            pad_frontier,
            collected.hashes,
            mcycle_hash_offsets[count],
            mcycle_hash_offsets[count + 1] - 1
        )
        local pad_mcycle_root = hash_tree.frontier_get_root_hash(pad_frontier)
        hash_tree.frontier_pad_back(
            self.frontier,
            pad_mcycle_root,
            self.period - self.mcycle_count,
            self.log2_bundles_per_mcycle
        )
        self.mcycle_count = self.period
    end

    if self.mcycle_count < self.period then return end
    local root = hash_tree.frontier_get_root_hash(self.frontier)
    stderr("\nUarch cycle computation hash: %s\n", cartesi.tohex(root))
    if self.filename ~= "" then
        stderr("Storing %s\n", self.filename)
        util.write_file(root, self.filename)
    end
end

local function uarch_cycle_computation_hash_begin_epoch(self)
    self.frontier = hash_tree.frontier(self.log2_period + self.log2_bundles_per_mcycle, self.hash_type)
    self.mcycle_count = 0
end

-- Capture the target input's pre-delivery fixed-point uarch tail. Its final entry is the boundary
-- root that delivery records as the revert root, allowing collection to model a later rejection.
-- Other inputs need no uarch collection.
local function uarch_cycle_computation_hash_begin_input(self, input_index)
    if input_index ~= self.target_input then return end
    local m = self.machine
    local mcycle = m:read_reg("mcycle")
    self.input_mcycle_end = usaturating_add(mcycle, 1 << ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE)
    self.target_mcycle_start = usaturating_add(mcycle, self.target_offset * self.period, self.input_mcycle_end)
    self.target_mcycle_end = usaturating_add(self.target_mcycle_start, self.period, self.input_mcycle_end)
    self.revert_uarch_tail = m:collect_uarch_cycle_root_hashes(MCYCLE_MAX, 0).hashes
end

-- Run plainly outside the target period and collect uarch state hashes within it.
local function uarch_cycle_computation_hash_run(self, mcycle_end)
    if not self.target_mcycle_start then return self.runner:run(mcycle_end) end
    local m = self.machine
    local mcycle = m:read_reg("mcycle")
    mcycle_end = umin(self.input_mcycle_end, mcycle_end)
    local break_reason
    -- Run plainly up to the target period, or to mcycle_end when it comes first. A stop short of
    -- the wanted mcycle is reported to the caller, and so is a call that ends before the period.
    if math.ult(mcycle, self.target_mcycle_start) then
        local wanted_mcycle = umin(self.target_mcycle_start, mcycle_end)
        break_reason = self.runner:run(wanted_mcycle)
        if not is_target_mcycle(break_reason) or wanted_mcycle ~= self.target_mcycle_start then return break_reason end
        mcycle = self.target_mcycle_start
    end
    -- Add the groups returned for machine cycles within the target period.
    local collection_end = umin(self.target_mcycle_end, mcycle_end)
    while math.ult(mcycle, collection_end) do
        local chunk_end = usaturating_add(mcycle, self.chunk_size, collection_end)
        local collected =
            self.runner:collect_uarch_cycle_root_hashes(chunk_end, self.log2_bundle, self.revert_uarch_tail)
        break_reason = collected.break_reason
        -- At a fixed point, the final group does not represent a machine cycle that advanced the
        -- main processor.
        uarch_cycle_computation_hash_push_collected(self, collected)
        mcycle = m:read_reg("mcycle")
        if not is_target_mcycle(break_reason) then break end
    end
    -- Past the target period, run plainly. A stop inside it is instead reported as is.
    if (not break_reason or is_target_mcycle(break_reason)) and math.ult(m:read_reg("mcycle"), mcycle_end) then
        break_reason = self.runner:run(mcycle_end)
    end
    return break_reason
end

-- If the input stopped before reaching the target period, collect one group of uarch state hashes
-- at the fixed point. Its subtree root fills every machine-cycle position in the period.
local function uarch_cycle_computation_hash_end_input(self)
    if not self.target_mcycle_start then return end
    self.target_mcycle_start, self.target_mcycle_end, self.revert_uarch_tail = nil, nil, nil
    if self.mcycle_count < self.period then
        uarch_cycle_computation_hash_push_collected(
            self,
            self.machine:collect_uarch_cycle_root_hashes(MCYCLE_MAX, self.log2_bundle)
        )
    end
end

-- If the epoch never processed the target input, collect one group of uarch state hashes at the
-- epoch's final fixed point and use its subtree root for every machine-cycle position.
local function uarch_cycle_computation_hash_end_epoch(self)
    self:end_input()
    if self.mcycle_count < self.period then
        uarch_cycle_computation_hash_push_collected(
            self,
            self.machine:collect_uarch_cycle_root_hashes(MCYCLE_MAX, self.log2_bundle)
        )
    end
end

local function make_uarch_cycle_computation_hash(m, advance, runner)
    local log2_period = advance.log2_mcycle_computation_hash_period
    local log2_periods_per_input = ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE - log2_period
    return {
        machine = m,
        runner = runner,
        period = 1 << log2_period,
        chunk_size = uarch_hashes_chunk_size(advance.log2_bundle_uarch_cycle_count),
        log2_period = log2_period,
        log2_bundle = advance.log2_bundle_uarch_cycle_count,
        hash_type = initial_config.hash_tree.hash_function,
        log2_bundles_per_mcycle = ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - advance.log2_bundle_uarch_cycle_count,
        target_input = advance.mcycle_period_index >> log2_periods_per_input,
        target_offset = advance.mcycle_period_index & ((1 << log2_periods_per_input) - 1),
        filename = advance.uarch_cycle_computation_hash,
        begin_epoch = uarch_cycle_computation_hash_begin_epoch,
        begin_input = uarch_cycle_computation_hash_begin_input,
        run = uarch_cycle_computation_hash_run,
        end_input = uarch_cycle_computation_hash_end_input,
        end_epoch = uarch_cycle_computation_hash_end_epoch,
    }
end

-- The do-nothing computation hash, for an epoch that does not compute one. Its lifecycle methods are
-- no-ops and its run just delegates to the given runner (the machine itself, or gdb), so
-- run_advance_state_epoch drives every epoch through the same calls without testing whether a
-- computation hash is wanted.
local function null_computation_hash_noop() end
local function null_computation_hash_run(self, mcycle_end) return self.runner:run(mcycle_end) end
local function make_null_computation_hash(runner)
    return {
        runner = runner,
        begin_epoch = null_computation_hash_noop,
        begin_input = null_computation_hash_noop,
        run = null_computation_hash_run,
        end_input = null_computation_hash_noop,
        end_epoch = null_computation_hash_noop,
    }
end

-- Resumes the machine, running to each target cycle with the given runner (the machine itself for
-- a plain run) and servicing each automatic yield through on_yield_automatic(yield_reason, data),
-- until it reaches a fixed point or max_mcycle, and returns the break reason it stopped for.
-- This is the host's inner loop. A terminal manual yield is left unread, for the caller to
-- service.
local function run_to_stop(m, on_yield_automatic, runner)
    while true do
        local break_reason = runner:run(cmdline.max_mcycle)
        if is_at_fixed_point(break_reason) or is_target_mcycle(break_reason) then
            return break_reason
        elseif is_yielded_automatic(break_reason) then
            local _, yield_reason, data = get_and_print_yield(m, initial_config.processor.registers.htif)
            on_yield_automatic(yield_reason, data)
        end
        -- any other reason (a soft yield or console output) just keeps going
    end
end

-- Prints the halt banner and records the guest exit code.
local function report_halt(m)
    exit_code = m:read_reg("htif_tohost_data") >> 1
    if exit_code ~= 0 then
        stderr("\nHalted with payload: %u\n", exit_code)
    else
        stderr("\nHalted\n")
    end
    report_mcycles(m)
end

-- Prints the mcycle overflow banner. The machine stopped at its mcycle limit without completing
-- its work, so the run is reported as a failure.
local function report_mcycle_overflow(m)
    exit_code = 1
    stderr("\nMcycle overflow\n")
    report_mcycles(m)
end

-- Prints the cmio exception banner and its payload. The guest gave up on the epoch, so the run
-- is reported as a failure.
local function report_exception(data)
    exit_code = 1
    stderr("cmio exception with payload: %q\n", data)
end

-- Prints the unexpected manual yield banner. The guest broke the cmio protocol, so the run is
-- reported as a failure.
local function report_unexpected_manual_yield(yield_reason)
    exit_code = 1
    stderr("\nUnexpected manual yield reason %d\n", yield_reason)
end

-- Reports where a run stopped: the halt banner on a halt, the overflow banner on an mcycle
-- overflow, or the manual yield it left unread.
local function report_stop(m, break_reason)
    if is_halted(break_reason) then
        report_halt(m)
    elseif is_mcycle_overflow(break_reason) then
        report_mcycle_overflow(m)
    elseif is_yielded_manual(break_reason) then
        get_and_print_yield(m, initial_config.processor.registers.htif)
    end
end

-- The inner loop of a run with no cmio requests ignores automatic yields.
local function ignore_yield_automatic() end

-- Runs the inspect-state query against the machine at an accept manual yield, saving its reports
-- and reverting the state afterward, leaving cmio_inspect nil. First reaches that accept yield: it
-- boots the machine when inspecting on its own, and is a noop right after an advance-state epoch
-- (already there). The yield is announced only when reached by advancing, since after an epoch the
-- advance loop already announced this same yield.
local function run_inspect_state_query(m, runner)
    local htif = initial_config.processor.registers.htif
    local mcycle = m:read_reg("mcycle")
    -- Boot always runs the machine plainly, and only the query itself runs with the runner. If the
    -- machine did not stop at a manual yield (it halted, or ran out of mcycles), it is not at an
    -- accept yield waiting for a request, so there is nothing to inspect.
    local break_reason = run_to_stop(m, ignore_yield_automatic, m)
    if not is_yielded_manual(break_reason) then return end
    -- Announce the yield we advanced to reach (after an epoch it is the epoch's already-announced
    -- accept yield, at the same mcycle, so skip it). load_cmio_query is the gate on the reason: it
    -- fails unless the machine is at an rx-accepted manual yield, rejecting a reject or exception.
    if m:read_reg("mcycle") ~= mcycle then get_and_print_yield(m, htif) end
    commit(m)
    stderr("\nBefore query\n")
    if cmdline.cmio_inspect.print_query_state_hashes then print_root_hash(m) end
    snapshot(m)
    load_cmio_query(m, cmdline.cmio_inspect)
    if cmdline.cmio_inspect.print_query_state_hashes then print_root_hash(m) end
    cmdline.cmio_inspect.report_index = 0
    local function on_yield_automatic(yield_reason, data)
        if is_tx_report(yield_reason) then
            save_cmio_inspect_state_report(cmdline.cmio_inspect, data)
            cmdline.cmio_inspect.report_index = cmdline.cmio_inspect.report_index + 1
        end
    end
    break_reason = run_to_stop(m, on_yield_automatic, runner)
    report_stop(m, break_reason)
    stderr("\nAfter query\n")
    revert(m)
    cmdline.cmio_inspect = nil
end

-- Drives an advance-state epoch actively, as the README host loop does. Boots to the rolling
-- template's first accept yield, then for each input snapshots, feeds, resumes until the input
-- is accepted or rejected, collecting outputs and reports, and commits or reverts. Every input
-- processed, a halt, an mcycle overflow, an exception, or an unexpected manual yield is a fixed
-- point that determines the values placed in all later tree positions reserved by the claim. Only
-- reaching max_mcycle leaves the computation hash undetermined. At any of these fixed points the
-- interrupted input's outputs are flushed as rejected and its snapshot is committed (a fixed
-- point is sticky, so there is no state worth restoring), and output proofs are written only on
-- full completion.
-- Leaves the machine wherever the epoch stopped. A trailing inspect query, if any, runs against that
-- state and does nothing unless it is an accept yield. Boot always runs the machine plainly. The
-- inputs run with the claim, which either collects a computation hash (advancing through the
-- given runner) or delegates to the runner directly (the machine itself, or gdb).
local function run_advance_state_epoch(m, runner)
    local htif = initial_config.processor.registers.htif
    local advance = cmdline.cmio_advance
    local claim = advance.mcycle_computation_hash and make_mcycle_computation_hash(m, advance, runner)
        or advance.uarch_cycle_computation_hash and make_uarch_cycle_computation_hash(m, advance, runner)
        or make_null_computation_hash(runner)
    claim:begin_epoch()
    -- outputs are buffered until the input is accepted or rejected, reports are saved at once
    local function on_yield_automatic(yield_reason, data)
        if is_tx_output(yield_reason) then
            advance.pending_outputs[#advance.pending_outputs + 1] = data
        elseif is_tx_report(yield_reason) then
            save_cmio_report(advance, data)
            advance.report_index = advance.report_index + 1
        end
    end
    -- boot plainly to the rolling template's first accept yield, then process each input in turn.
    -- break_reason holds where the last resume stopped, and decides how the epoch closes below.
    local break_reason = run_to_stop(m, ignore_yield_automatic, m)
    if is_yielded_manual(break_reason) then
        get_and_print_yield(m, htif)
        commit(m)
        local revert_root_hash
        for input_index = advance.input_index_begin, advance.input_index_end - 1 do
            stderr("\nBefore input %d\n", input_index)
            -- the claim opens the input at its boundary, before it is fed (the uarch cycle claim
            -- collects the boundary's revert uarch tail there). Capture and snapshot that boundary
            -- so a rejection restores the same root hash the input records. Feeding does not
            -- advance mcycle.
            claim:begin_input(input_index)
            revert_root_hash = m:get_root_hash()
            snapshot(m)
            if advance.print_input_state_hashes then print_root_hash(m) end
            load_cmio_input(m, advance, revert_root_hash)
            if advance.print_input_state_hashes then print_root_hash(m) end
            advance.report_index = 0
            -- labeling: from now the producing input is next_input_index - 1
            advance.next_input_index = input_index + 1
            break_reason = run_to_stop(m, on_yield_automatic, claim)
            -- a halt, overflow, or max_mcycle before the accept or reject yield ends the epoch;
            -- it closes below
            if not is_yielded_manual(break_reason) then break end
            local _, yield_reason, data = get_and_print_yield(m, htif)
            if is_rx_accepted(yield_reason) then
                flush_pending_outputs(m, advance, yield_reason, data)
                commit(m)
            elseif is_rx_rejected(yield_reason) then
                assert(
                    cmdline.revert_mode ~= "none"
                        or not (advance.mcycle_computation_hash or advance.uarch_cycle_computation_hash),
                    "the computation hash of a rejected input requires reverts"
                )
                flush_pending_outputs(m, advance, yield_reason, data)
                revert(m)
            elseif is_tx_exception(yield_reason) then
                -- an exception is a fixed point like a halt: report it, flush the interrupted input's
                -- outputs as rejected, and end the epoch, leaving the machine at the exception
                -- yield (no revert). A following inspect query fails against this non-accept yield,
                -- which the CLI just reports.
                report_exception(data)
                flush_pending_outputs(m, advance, yield_reason, data)
                commit(m)
                claim:end_epoch()
                return
            else
                -- An unexpected manual yield is a protocol violation, but still a fixed point, and
                -- fixed points are sticky, so it ends the epoch the same way an exception does.
                -- The claim is finalized so callers can dispute the computation that led here. In
                -- particular, the uarch claim may still need to pad a selected period that
                -- execution never reached.
                report_unexpected_manual_yield(yield_reason)
                flush_pending_outputs(m, advance, yield_reason, data)
                commit(m)
                claim:end_epoch()
                return
            end
            claim:end_input()
        end
    end
    if is_halted(break_reason) then
        report_halt(m)
        flush_pending_outputs(m, advance)
        commit(m)
        claim:end_epoch()
    elseif is_mcycle_overflow(break_reason) then
        report_mcycle_overflow(m)
        flush_pending_outputs(m, advance)
        commit(m)
        claim:end_epoch()
    elseif is_yielded_manual(break_reason) then
        save_cmio_output_proofs(advance)
        claim:end_epoch()
    end
end

-- Pick the runner for the run. The machine itself is the plain runner, or gdb_stub when
-- debugging, and the hash-sampling runners advance through one of them. In cmio mode those were
-- precluded up front, so the runner is the machine or gdb, and requests run with it (a
-- computation hash advances through it too).
local runner = gdb_stub or machine
if cmdline.uarch_cycle_root_hashes_count then
    runner = make_uarch_cycle_root_hashes_runner(
        runner,
        cmdline.uarch_cycle_root_hashes_start,
        cmdline.uarch_cycle_root_hashes_count,
        cmdline.uarch_cycle_root_hashes_log2_bundle
    )
elseif mcycle_root_hashes then
    local start = cmdline.mcycle_root_hashes_start ~= 0 and cmdline.mcycle_root_hashes_start or nil
    runner = make_mcycle_root_hashes_runner(
        runner,
        cmdline.mcycle_root_hashes_log2_period,
        start,
        cmdline.mcycle_root_hashes_log2_bundle
    )
end

-- The host drives an advance-state epoch (which may end with an inspect query) actively, an
-- inspect-state query on its own, or otherwise just runs the machine to a stop.
if cmdline.cmio_advance then
    run_advance_state_epoch(machine, runner)
    -- an inspect query, if any, runs against the state the epoch left; it does nothing unless that
    -- is an accept yield (a completed epoch), so it is safe to always attempt
    if cmdline.cmio_inspect then run_inspect_state_query(machine, runner) end
elseif cmdline.cmio_inspect then
    run_inspect_state_query(machine, runner)
else
    report_stop(machine, run_to_stop(machine, ignore_yield_automatic, runner))
end
-- log step
if cmdline.log_step_mcycle_count then
    stderr(string.format("Logging step of %d cycles to %s\n", cmdline.log_step_mcycle_count, cmdline.log_step_filename))
    print_root_hash(machine, stderr_unsilenceable)
    local log = machine:log_step(cmdline.log_step_mcycle_count)
    util.write_file(log, cmdline.log_step_filename)
    print_root_hash(machine, stderr_unsilenceable)
end
-- Advance micro cycles
if cmdline.max_uarch_cycle > 0 then
    -- Save halt flag before micro cycles
    local previously_halted = machine:read_reg("iflags_H") ~= 0
    local break_reason = machine:run_uarch(cmdline.max_uarch_cycle)
    if break_reason == cartesi.UARCH_BREAK_REASON_UARCH_CYCLE_OVERFLOW then
        exit_code = 1
        stderr("\nUarch cycle overflow\n")
        report_mcycles(machine)
        report_uarch_cycles(machine)
    elseif break_reason == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then
        -- The uarch halted after completing one main processor instruction.
        -- The mcycle counter was incremented unless the machine was already halted.
        local newly_halted = machine:read_reg("iflags_H") ~= 0 and not previously_halted
        if cmdline.auto_reset_uarch then machine:reset_uarch() end
        if newly_halted then
            report_halt(machine)
        else
            report_mcycles(machine)
        end
        if not cmdline.auto_reset_uarch then report_uarch_cycles(machine) end
    end
end
if gdb_stub then gdb_stub:close() end
if cmdline.log_step_uarch then
    assert(initial_config.processor.registers.iunrep == 0, "micro step proof is meaningless in unreproducible mode")
    stderr("Gathering micro step log: please wait\n")
    local log = machine:log_step_uarch(cmdline.log_step_uarch.count)
    util.write_file(log, cmdline.log_step_uarch.filename)
    if cmdline.log_step_uarch.dump then
        io.stderr:write(cartesi.machine:dump_step_uarch(log, cmdline.log_step_uarch.count))
    end
end
if cmdline.log_reset_uarch then
    stderr("Resetting uarch state: please wait\n")
    util.write_file(machine:log_reset_uarch(), cmdline.log_reset_uarch.filename)
end
if cmdline.log_send_cmio_response then
    local o = cmdline.log_send_cmio_response
    local data
    if o["data-file"] then
        local f <close> = assert(io.open(o["data-file"], "rb"))
        data = assert(f:read("*a"))
    else
        data = ENCODINGS[o.encoding](o.data)
    end
    stderr("Logging cmio response: please wait\n")
    util.write_file(machine:log_send_cmio_response(o.reason, data, machine:get_root_hash()), o.filename)
end
if cmdline.dump_memory_ranges_dir then dump_memory_ranges(machine, cmdline.dump_memory_ranges_dir) end
if cmdline.final_hash then
    assert(initial_config.processor.registers.iunrep == 0, "hashes are meaningless in unreproducible mode")
    if type(cmdline.final_hash) == "string" then
        util.write_file(machine:get_root_hash(), cmdline.final_hash)
    else
        print_root_hash(machine, stderr_unsilenceable)
    end
end
dump_value_proofs(machine, cmdline.final_proof, initial_config)
if cmdline.store_dir then store_machine(machine, initial_config, cmdline.store_dir, cmdline.store_sharing) end
if cmdline.load_sync then
    stderr("Syncing machine: please wait\n")
    machine:sync_stored(cmdline.load_dir)
end
if cmdline.assert_rolling_template then
    local cmd, yield_reason = machine:receive_cmio_request()
    if not (cmd == cartesi.HTIF_YIELD_CMD_MANUAL and is_rx_accepted(yield_reason)) then exit_code = 2 end
end
if not cmdline.remote_address or cmdline.remote_destroy then machine:destroy() end
os.exit(exit_code, true)
