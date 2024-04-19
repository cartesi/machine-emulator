---
title: Linux environment
---

:::note
[The host perspective](../host/index.md) section describes in detail the `cartesi-machine` command-line utility and the general structure of Cartesi Machines.
In order to avoid repetition, this section assumes familiarity with the material presented there.
:::

The most direct way for target developers to familiarize themselves with the embedded Linux environment is to run the Cartesi Machine emulator in interactive mode.
The `cartesi/playground` Docker image comes pre-installed with the emulator and all its support files.
Inside the playground, the following command instructs the emulator to load the default machine configuration and run a shell in interactive mode

```bash
cartesi-machine -i -- sh
```

Once executed, the Cartesi Machine boots Linux and drops into an interactive shell (The `sh` argument in the command-line.)

```
%machine.target.linux.interactive-ls
```

The session shows a user changing the working directory to `/bin/` and listing its contents.
The user then does the same with directory `/usr/bin/`, before finally leaving the emulator with the `exit` command.
The point of the exercise is that, from the inside, the environment will be familiar to any regular Unix user.

One of the key differences is that, unlike stand-alone systems, most embedded systems are not self-hosting.
None of the utilities visible inside the `/usr/bin/` and `/bin/` directories were built with a compiler that ran inside a Cartesi Machine.
They were built in a separate host system, on which a cross-compiling toolchain for the target architecture has been installed.
In the case of Linux, the key elements in the toolchain are the GNU Compiler Collection and the GNU C Library.
Support for RISC-V is upstream in the official [GCC compiler collection](https://gcc.gnu.org/).
Nevertheless, building a cross-compiler is time-consuming, even with the help of specialized tools such as [crosstool-ng](https://crosstool-ng.github.io/).
The [Emulator SDK](https://github.com/cartesi/machine-emulator-sdk) includes a Docker image `cartesi/toolchain` with the toolchain pre-installed.
The same toolchain is available in the `cartesi/playground` Docker image.

## Target "Hello world!"

Other than using a cross-compiler in the host to create executables for a different target platform, cross-development is not that different from hosted development.
As an example, consider the simple task of compiling the ubiquitous &ldquo;Hello world!&rdquo; program in the C++ programming language to run in the target.
(Printing 5 lines, to at least offer a taste of the programming language.)

```c++ title="hello.cpp"
#include <iostream>

int main(int argc, char *argv[]) {
    for (int i = 0; i < 5; i++) {
        std::cout << i+1 << ": Hello world from C++!\n";
    }
    return 0;
}
```

To produce the binary in the playground, run

```bash
riscv64-cartesi-linux-gnu-g++ -O2 -o hello-cpp hello.cpp
```

Note the prefix `riscv64-cartesi-linux-gnu-` to the typical `g++` command.
This prefix identifies the cross-compiler.
The resulting file is a RISC-V executable suitable for running on the target.
This can be see by running the command

```bash
file hello-cpp
```

which produces

```
hello-cpp: ELF 64-bit LSB executable, UCB RISC-V, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-riscv64-lp64.so.1, for GNU/Linux 5.5.19, with debug_info, not stripped
```

If the bare `gcc` command was used instead, the resulting binary would be suitable for running on the host.

The executable can now be placed inside a new `hello.ext2` file-system:

```bash
mkdir hello
cp hello-cpp hello
genext2fs -b 1024 -d hello hello.ext2
```

The `hello-cpp` program can then be run from using the `cartesi-machine` command-line utility as follows:

```bash
cartesi-machine \
    --flash-drive=label:hello,filename:hello.ext2 \
    -- /mnt/hello/hello-cpp
```

The output is

```
%machine.target.linux.hello-cpp
```

To create the &ldquo;Hello world!&rdquo; program in Rust, first create a Cargo project:

```bash
cargo new hello-rust
```

Then, edit the `hello-rust/src/main.rs` file so it contains our modified program:

```rust title="main.rs"
fn main() {
    for i in 1..6 {
        println!("{}: Hello world from Rust!", i);
    }
}
```

Cross-compiling in Rust requires an additional configuration step.
To that end, create a file with the following JSON object:

```json title="riscv64ima-cartesi-linux-gnu.json"
{
  "arch": "riscv64",
  "code-model": "medium",
  "cpu": "generic-rv64",
  "crt-static-respected": true,
  "data-layout": "e-m:e-p:64:64-i64:64-i128:128-n64-S128",
  "dynamic-linking": true,
  "env": "gnu",
  "executables": true,
  "features": "+m,+a",
  "has-rpath": true,
  "is-builtin": false,
  "llvm-abiname": "lp64",
  "llvm-target": "riscv64",
  "max-atomic-width": 64,
  "os": "linux",
  "position-independent-executables": true,
  "relro-level": "full",
  "target-family": ["unix"],
  "linker-flavor": "gcc",
  "linker": "riscv64-cartesi-linux-gnu-gcc",
  "pre-link-args": {
    "gcc": []
  },
  "post-link-args": {
    "gcc": [
      "-Wl,--allow-multiple-definition",
      "-Wl,--start-group,-lc,-lm,-lgcc,-lstdc++,-lsupc++,--end-group"
    ]
  },
  "target-pointer-width": "64",
  "panic-strategy": "abort"
}
```

Now invoke Cargo with with the following command-line:

```bash
cargo build -Z build-std=std,core,alloc,panic_abort,proc_macro --target riscv64ima-cartesi-linux-gnu.json --release
```

The compiled program should appear in `hello-rust/target/riscv64ima-cartesi-linux-gnu/release/hello-rust`.

One of the advantages of running Linux is the large number of well-established software development tools available.
By default, the `rootfs.ext2` root file-system includes the `ash` shell, and a Lua interpreter, both of which can be used for scripting.

For example, to run the shell script version of the &ldquo;Hello world!&rdquo; program:

```bash title="hello.sh"
#!/bin/sh

for i in $(seq 1 5); do
    echo "$i: Hello world from sh!"
done
```

```bash
cp hello.sh hello
chmod +x hello/hello.sh
genext2fs -b 1024 -d hello hello.ext2
cartesi-machine \
    --flash-drive=label:hello,filename:hello.ext2 \
    -- /mnt/hello/hello.sh
```

Running these commands produce an output that is very similar to the C++ version.

## The root file-system

The `fs/` submodule in the [Emulator SDK](https://github.com/cartesi/machine-emulator-sdk) uses the [Buildroot](https://buildroot.org/) tool to create the root file-system `rootfs.ext2` (mounted as `/`).
Buildroot is a highly configurable tool, and an explanation of how to use it to its full potential is beyond the scope of this documentation.
Please refer to its [manual](https://buildroot.org/downloads/manual/manual.html).

Even relative to other embedded Linux root file-systems, the Cartesi-provided `rootfs.ext2` is very simple.
The only significant customization is the Cartesi-provided `/sbin/init` script, which performs a few initialization tasks before handing control to the application chosen by the developer to run inside the Cartesi Machine, and finally shuts down after the application exits.

As is typical in the field, `rootfs.ext2` uses [BusyBox](https://busybox.net/) to consolidate tiny versions of many common UNIX utilities (`ls`, `cd`, `rm`, etc) into a single binary.
It also includes a variety of typical command-line utilities, as can be seen in the listings of directories `/bin/` and `/usr/bin/` above.

Using Buildroot, it is rather easy to add new packages, or to remove unnecessary ones.
Hundreds of packages are available for installation.
To that end, from inside the Emulator SDK, change into the `fs/` directory and run `make config`.
This will bring up a textual menu interface, from which the option `Target packages` can be selected.

For example, additional scripting languages are available from the `Interpreter languages and scripting` section.
After selecting the options for `4th`, `lua`, `qjs`, `perl`, `php`, `python3`, `ruby`, and `tcl` and replacing the old `rootfs.ext2` with the freshly generated one, all these scripting languages become available for use inside the Cartesi Machine.

Here are &ldquo;Hello world!&rdquo; programs for each of these languages:

```4th title="hello.4th"
6 1 do i <# # #> type ." : Hello world from Forth!" cr loop
```

```js title="hello.js"
#!/usr/bin/env qjs

for (var i = 1; i <= 5; i++) {
  console.log(i + ": Hello world from JavaScript!");
}
```

```lua title="hello.lua"
#!/usr/bin/env lua

for i = 1, 5 do
    print(i .. ": Hello world from Lua!")
end
```

```perl title="hello.pl"
#!/usr/bin/env perl

for my $i (1..5){
	print("$i: Hello from Perl!\n");
}
```

```php title="hello.php"
#!/usr/bin/env php
<?php
for ($i = 1; $i <= 5; $i++) {
    print "$i: Hello world from PHP!\n";
}
?>
```

```python title="hello.py"
#!/usr/bin/env python3

for i in range(1,6):
    print("{}: Hello world from Python3".format(i))
```

```ruby title="hello.rb"
#!/usr/bin/env ruby

for i in 1..5 do
    puts "%d: Hello world from Ruby!" % i
end
```

```tcl title="hello.tcl"
#!/usr/bin/env tclsh

for {set i 1} {$i <= 5} {incr i} {
    puts "$i: Hello world from TCL!"
}
```

The following shell script invokes all of them:

```bash title="all.sh"
#!/bin/sh

cd $(dirname $0)

./hello-cpp
./hello-rust
4th cxq hello.4th
./hello.lua
./hello.js
./hello.pl
./hello.php
./hello.py
./hello.rb
./hello.sh
./hello.tcl
```

After adding all these files to `hello.ext2` (with _execute_ permissions), the result of the command line

```bash
cartesi-machine \
    --flash-drive=label:hello,filename:hello.ext2 \
    -- "/mnt/hello/all.sh"
```

is as follows:

```

         .
        / \
      /    \
\---/---\  /----\
 \       X       \
  \----/  \---/---\
       \    / CARTESI
        \ /   MACHINE
         '

1: Hello world from C++!
2: Hello world from C++!
3: Hello world from C++!
4: Hello world from C++!
5: Hello world from C++!
1: Hello world from Rust!
2: Hello world from Rust!
3: Hello world from Rust!
4: Hello world from Rust!
5: Hello world from Rust!
1: Hello world from Forth!
2: Hello world from Forth!
3: Hello world from Forth!
4: Hello world from Forth!
5: Hello world from Forth!
1: Hello world from Lua!
2: Hello world from Lua!
3: Hello world from Lua!
4: Hello world from Lua!
5: Hello world from Lua!
1: Hello world from JavaScript!
2: Hello world from JavaScript!
3: Hello world from JavaScript!
4: Hello world from JavaScript!
5: Hello world from JavaScript!
1: Hello world from Perl!
2: Hello world from Perl!
3: Hello world from Perl!
4: Hello world from Perl!
5: Hello world from Perl!
1: Hello world from PHP!
2: Hello world from PHP!
3: Hello world from PHP!
4: Hello world from PHP!
5: Hello world from PHP!
1: Hello world from Python3
2: Hello world from Python3
3: Hello world from Python3
4: Hello world from Python3
5: Hello world from Python3
1: Hello world from Ruby!
2: Hello world from Ruby!
3: Hello world from Ruby!
4: Hello world from Ruby!
5: Hello world from Ruby!
1: Hello world from sh!
2: Hello world from sh!
3: Hello world from sh!
4: Hello world from sh!
5: Hello world from sh!
1: Hello world from TCL!
2: Hello world from TCL!
3: Hello world from TCL!
4: Hello world from TCL!
5: Hello world from TCL!

Halted
Cycles: 205939605
```

The take-away message is that developers can use the tools they are most familiar with to accomplish the task at hand.

:::note
Note that your cycle count may vary, since your new `rootfs.ext2` may differ from the one used to produce the results above.
:::

:::note
As of version 0.4.0 of the `rootfs.ext2`, the Ruby interpreter does not compile.
We are working on a fix.
:::

## Flash drives

Flash drives are simply regions of physical memory under the control of Linux's `mtd-ram` driver.
The flash drives 0&ndash;7 receive device names `flash.0`&ndash;`flash.7`, and the driver makes them accessible as block devices `/dev/mtdblock0`&ndash;`/dev/mtdblock7`.

The kernel command-line parameters `rootfstype=ext2 root=/dev/mtdblock0 rw` declare that the root file-system is of type `ext2`, that it resides in device `/dev/mtdblock0`, i.e., flash drive 0, and that it should be mounted read-write.
Partitioning information for flash drives and, in particular, custom labels can be specified with the `mtdparts` parameter in the Linux kernel command line.
The format for the parameter is documented in the [source-code](https://elixir.bootlin.com/linux/v5.5.19/source/drivers/mtd/parsers/cmdlinepart.c) for the kernel module responsible for parsing it.
For example, the parameter `mtdparts=flash.0:-(root)` specifies a single partition with label `root` for `flash.0`.

A flash drive holds whatever data is made available by the emulator in the corresponding target physical memory region.
The data can come from an image file specified during machine instantiation, from an image file specified after instantiation via the `machine:replace_memory_range(<memory_range_config>)`, or through external state access method `machine:write_memory()`.

The Cartesi-provided `/sbin/init` script scans flash drives 1&ndash;7 for valid file-systems.
When a valid file-system is detected, the script automatically mounts the file-system at `/mnt/<label>`, using the corresponding `<label>` from the `mtdparts` kernel parameter.
In this fashion, file-systems present in all flash drives are available for use right after Linux boots.

This was the case with the command

```bash
cartesi-machine \
    --flash-drive=label:hello,filename:hello.ext2 \
    -- "/mnt/hello/all.sh"
```

The `cartesi-machine` command-line utility instructed the emulator to add a new flash drive, initialized with the contents of the `hello.ext2` image file.
It gave the label `hello` to that flash drive using the kernel command-line parameter `mtdparts=flash.0:-(root);flash.1:-(hello)`.
The `/sbin/init` script identified a valid file-system in the device, and used its label to mount it at `/mnt/hello`.
It then executed the command `/mnt/hello/all.sh`, causing all the &ldquo;Hello world!&rdquo; messages to be printed to screen.

### Raw flash drives

Raw flash drives, i.e., flash drives containing free-format data, are not mounted.
Instead, the data in raw flash drives are read from/written to directly by accessing the underlying block device.
The layout and contents of data written to raw flash drives is completely up to application developers.

Depending on the layout and contents, it may be simple or difficult to read from/write to raw flash drives from the command line.
The most popular tool for reading and writing block devices is the `dd` command-line utility.
Another alternative is the `devio` tool.
Some scripting languages, like the Lua programming language, have packing and unpacking libraries that can be very helpful.

For example, consider the previously discussed Cartesi Machine that operates as an arbitrary-precision calculator

```bash
\rm -f output.raw
truncate -s 4K output.raw
echo "6*2^1024 + 3*2^512" > input.raw
truncate -s 4K input.raw
cartesi-machine \
    --flash-drive="label:input,length:1<<12,filename:input.raw" \
    --flash-drive="label:output,length:1<<12,filename:output.raw,shared" \
    -- $'dd status=none if=$(flashdrive input) | lua -e \'print((string.unpack("z", io.read("a"))))\' | bc | dd status=none of=$(flashdrive output)'
luapp5.3 -e 'print((string.unpack("z", io.read("a"))))' < output.raw
```

The input is a null-terminated string containing the expression to be evaluated.
This string is stored inside a raw flash drive with label `input`.
The output is once again a null-terminated string with the result, this time stored inside a raw flash drive with label `output`.

The command executed inside the machine is

```bash
dd status=none if=$(flashdrive input) | \
    lua -e 'print((string.unpack("z", io.read("a"))))' | \
    bc | \
    dd status=none of=$(flashdrive output)
```

The `flashdrive` command-line utility prints the name of the device corresponding to a given label.
In this case, `flashdrive input` prints `/dev/mtdblock1` and `flashdrive output` prints `/dev/mtdblock2` (recall `/dev/mtdblock0` is the root file-system, defined by default to load the `rootfs.ext2` image).

The first command, `dd status=none if=$(flashdrive input)` therefore reads the entire 4KiB of the raw input flash drive and sends it to the standard output.
The second command, `lua -e 'print((string.unpack("z", io.read("a"))))'` extracts the first null-terminated string and prints it to standard out.
This is the meaning of the `"z"` format argument to the `string.unpack()` function.
There are a variety of other formats available, including reading integers of different sizes, big- or little-endian etc.
Please see the [documentation for the `string.unpack()`](https://www.lua.org/manual/5.3/manual.html#6.4.2) function for more details.
The string is received by the `bc` command-line utility.
In the example, that string is `6*2^1024 + 3*2^512\n`.
The `bc` command-line utility computes the value of the expression and sends it to standard out.
This is finally received by the last command, `dd status=none of=$(flashdrive output)`, which writes it to the raw output flash drive.
(No need to null-terminate, since the drive is already completely filled with zeros.)

## Initialization

By default, a Cartesi Machine starts its execution from the image loaded into ROM.
In order to boot Linux, the Cartesi-provided `rom.bin` image first builds a [<i>devicetree</i>](http://devicetree.org/) describing the hardware.
The organization of a Cartesi Machine is defined during machine instantiation from its configuration.
This includes the number, starts, and lengths of all flash drives and rollup memory ranges, the amount of RAM, and which HTIF commands are supported (yield manual, yield automatic, console getchar etc).
The `rom.bin` program reads a Cartesi-specific low-level description of this organization from special machine registers and translates it into a devicetree that Linux can understand.
The configuration also includes the initial contents of ROM, RAM, all flash drives and rollup memory ranges, all registers, and the command-line parameters to be passed to the Linux kernel.
The latter is also added to the devicetree.

Once the devicetree is ready, `rom.bin` jumps to the image loaded into RAM, passing the address of the devicetree (which resides at the end of RAM) in a register.
The Cartesi-provided `linux.bin` image is composed of the Linux kernel linked with the Berkeley Boot Loader (BBL).
BBL is a thin abstraction layer that isolates Linux from details of the particular RISC-V machine on which it is running.
The abstraction layer gives Linux the ability to perform tasks such as powering the machine down and outputting a character to the console.
Once this functionality has been installed, BBL jumps to the kernel entrypoint.
The Linux kernel reads the devicetree to find out about the machine organization, loads the appropriate drivers, and performs its own initialization.

When the kernel initialization is complete, it tries to mount a root file-system.
The information of where this root file-system resides comes from the kernel command-line parameter.
In normal situations, this will reside in `/dev/mtdblock0`.
Once the root file-system is mounted, the kernel executes `/sbin/init`.

The Cartesi-provided `/sbin/init` script in `rootfs.ext2` sets up a basic Linux environment on which applications can run.
In particular, it goes over the available flash drive devices (`/dev/mtdblock1`&ndash;`/dev/mtdblock7`) looking for valid file-systems, and mounting them at the appropriate `/mnt/<label>` mount points.
The Linux kernel passes to `/sbin/init`, unmodified, everything after the separator `--` in its own command-line.
Once its initialization tasks are complete, the Cartesi-provided `/sbin/init` concatenates all its arguments into a string and executes them in a shell.

This is how the commands passed to `cartesi-machine` come to be executed in the Linux environment that runs inside the Cartesi Machine.
Given a proper `rootfs.ext2` and an appropriate command-line, the applications can run any general computation, consuming input from any flash drives, and writing outputs to any flash drives.
Once the application exits, control returns to `/sbin/init`.
The script then unmounts all file-systems and gracefully halts the machine.

## Cartesi-specific devices

The Linux kernel produced in the `kernel/` directory of the [Cartesi Machine SDK](https://github.com/cartesi/machine-emulator-sdk) includes two Cartesi-specific device drivers, accessible via `/dev/yield` and `/dev/rollup`.
The `/dev/yield` device allows target applications to return control back to the host, while signaling a variety of conditions that may require its attention.
The `/dev/rollup` device allows target applications to interact with Cartesi Rollups, receiving requests and returning responses.
(Internally, the `/dev/rollup` device uses the `/dev/yield` device.)

### ioctl for /dev/yield

The `/dev/yield` device can be controlled directly via its `ioctl` interface.
This is how the `/opt/cartesi/bin/yield` command-line utility operates.
The only `ioctl` request code exported is `IOCTL_YIELD`.
It takes as argument a structure `yield_request` defined as follows:

```C
struct yield_request {
    __u8 dev;
    __u8 cmd;
    __u16 reason;
    __u32 data;
};
```

The `dev` field must take the value `HTIF_DEVICE_YIELD`.

The `cmd` field can take one of two values: `HTIF_YIELD_MANUAL` or `HTIF_YIELD_AUTOMATIC`.
Sending either a manual yield or an automatic yield command to the device causes the emulator to return control to the host, giving it access to the `reason` and `data` fields.

Manual yields are used when the target application needs some kind of manual intervention from the host that modifies the machine state before resuming, typically when it needs some kind of input or throws an exception.
In that case, the Y bit in the `iflags` CSR will be set, and must be externally reset before the machine can continue executing.
Automatic yields are used when the target application has produced some data for the host, and can be resumed without further action, automatically.
The X bit in the `iflags` CSR will be set instead, and will be automatically reset when the machine is resumed.

The `HTIF_YIELD_REASON_PROGRESS` value for the `reason` field is used with automatic yields.
In this case, the value of the `data` field should contain an integer with the progress in parts per thousand.

The remaining values for the `reason` field are in conjunction with the `/dev/rollup` device.

### ioctl for /dev/rollup

The `/dev/rollup` device also exposes an `ioctl` interface.
It exports a variety of `ioctl` requests.
These are used, for example, by the `/opt/cartesi/bin/rollup` and `/opt/cartesi/bin/rollup-http-server` command-line utilities.

Recall that Cartesi Rollups is a mechanism by which a target application receives requests for processing and produces responses to those requests.
There are two types of rollup requests: advance-state requests and inspect-state requests.
There are four types of rollup responses: vouchers, notices, reports, and exceptions.

The `ioctl` request `IOCTL_ROLLUP_FINISH` is used to transition between one rollup request to the next.
It takes as argument a structure `rollup_finish` defined as follows:

```C
struct rollup_finish {
    /* True if previous request should be accepted */
    /* False if previous request should be rejected */
    bool accept_previous_request;

    int next_request_type; /* either CARTESI_ROLLUP_ADVANCE or CARTESI_ROLLUP_INSPECT */
    int next_request_payload_length;
};
```

The `accept_previous_request` field is set to `true` when accepting the previous request, or to `false` when rejecting it.
As a result, the `/dev/rollup` device will issue an yield manual command to the `/dev/yield` device, passing as `reason` field, respectively, `HTIF_YIELD_REASON_RX_ACCEPTED` or `HTIF_YIELD_REASON_RX_REJECTED`.
Upon return, the value of field `next_request_type` will contain `CARTESI_ROLLUP_ADVANCE` if the next request is an advance-state request, or `CARTESI_ROLLUP_INSPECT` if the next request is an inspect-state request.
Moreover, the `next_request_payload_length` field will contain the length of the request payload.

To obtain the advance-state request data, the target application should then use the `ioctl` request `IOCTL_ROLLUP_READ_ADVANCE_STATE`.
It takes as argument a structure `rollup_advance_state` defined as follows:

```C
struct rollup_bytes {
    unsigned char *data;
    uint64_t length;
};

struct rollup_input_metadata {
    uint8_t msg_sender[CARTESI_ROLLUP_ADDRESS_SIZE];
    uint64_t block_number;
    uint64_t timestamp;
    uint64_t epoch_index;
    uint64_t input_index;
};

struct rollup_advance_state {
    struct rollup_input_metadata metadata;
    struct rollup_bytes payload;
};
```

The `payload` field should contain a `rollup_bytes` structure, where the `payload.data` points to a buffer that can hold `payload.length` bytes.
Note that the value of `payload.length` should be no less than the value of `next_request_payload_length` returned in the `rollup_finish` argument to the previous `ioctl` request `IOCTL_ROLLUP_FINISH`.
Upon return, the `payload.data` buffer will contain the advance-state request payload.
This data comes from what the host wrote to the `rollup.rx_buffer` memory range.
In addition, the `metadata` field will contain all the associated input metadata.
This data comes from what the host wrote to the `rollup.input_metadata` memory range.

To obtain the inspect-state request data, the target application should then use the `ioctl` request `IOCTL_ROLLUP_READ_ADVANCE_STATE`.
It takes as argument a structure `rollup_advance_state` defined as follows:

```C
struct rollup_inspect_state {
    struct rollup_bytes payload;
};
```

The `payload` field should contain a `rollup_bytes` structure, where the `payload.data` points to a buffer that can hold `payload.length` bytes.
Note that the value of `payload.length` should be no less than the value of `next_request_payload_length` returned in the `rollup_finish` argument to the previous `ioctl` request `IOCTL_ROLLUP_FINISH`.
Upon return, the `payload.data` buffer will contain the inspect-state request payload.
This data comes from what the host wrote to the `rollup.rx_buffer` memory range.

While processing a request, to produce a voucher, the target application should use the `ioctl` request `IOCTL_ROLLUP_WRITE_VOUCHER`.
It takes as argument a structure `rollup_voucher` defined as follows:

```C
struct rollup_voucher {
    uint8_t address[CARTESI_ROLLUP_ADDRESS_SIZE];
    struct rollup_bytes payload;
    uint64_t index;
};
```

The `address` field should contain the desired voucher address.
The `payload` field should contain a `rollup_bytes` structure with the desired voucher payload.
The `/dev/rollup` device copies this data to the `rollup.tx_buffer` memory range for the host to read.
Then, the `/dev/rollup` device issues an yield automatic command to the `/dev/yield` device, passing as `reason` field `HTIF_YIELD_REASON_TX_VOUCHER`.
Upon return, the `index` field contains the index of the emitted voucher.

While processing a request, to produce a rollup notice, the target application should use the `ioctl` request `IOCTL_ROLLUP_WRITE_NOTICE`.
It takes as argument a structure `rollup_notice` defined as follows:

```C
struct rollup_notice {
    struct rollup_bytes payload;
    uint64_t index;
};
```

The `payload` field should contain a `rollup_bytes` structure with the desired notice payload.
The `/dev/rollup` device copies this data to the `rollup.tx_buffer` memory range for the host to read.
Then, the `/dev/rollup` device issues an yield automatic command to the `/dev/yield` device, passing as `reason` field `HTIF_YIELD_REASON_TX_NOTICE`.
Upon return, the `index` field contains the index of the emitted notice.

While processing a request, to produce a rollup report, the target application should use the `ioctl` request `IOCTL_ROLLUP_WRITE_REPORT`.
It takes as argument a structure `rollup_report` defined as follows:

```C
struct rollup_report {
    struct rollup_bytes payload;
};
```

The `payload` field should contain a `rollup_bytes` structure with the desired report payload.
The `/dev/rollup` device copies this data to the `rollup.tx_buffer` memory range for the host to read.
Then, the `/dev/rollup` device issues an yield automatic command to the `/dev/yield` device, passing as `reason` field `HTIF_YIELD_REASON_TX_REPORT`.

Finally, to throw a rollup exception, the target application should use the `ioctl` request
`IOCTL_ROLLUP_THROW_EXCEPTION`.
It takes as argument a structure `rollup_exception` defined as follows:

```C
struct rollup_exception {
    struct rollup_bytes payload;
};
```

The `payload` field should contain a `rollup_bytes` structure with the desired exception payload.
The `/dev/rollup` device copies this data to the `rollup.tx_buffer` memory range for the host to read.
Then, the `/dev/rollup` device issues an yield _manual_ command to the `/dev/yield` device, passing as `reason` field `HTIF_YIELD_REASON_TX_EXCEPTION`.
