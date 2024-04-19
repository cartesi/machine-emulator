---
title: System architecture
---

The RISC-V ISA, on which Cartesi Machines are based, consists of a minimal 32-bit integer instruction set to which several extensions can be added.
The standard defines a privileged architecture with features commonly used by modern operating systems, such as multiple privilege levels, paged-based virtual-memory, timers, interrupts, exceptions and traps, etc.
Implementations are free to select the combination of extensions that better suit their needs.

The Cartesi Machine architecture can be separated into a processor and a board.
The processor performs the computations, executing the traditional fetch-execute loop while maintaining a variety of registers.
The board defines the surrounding environment with an assortment of memories (ROM, RAM, flash drives, rollup memory ranges) and a number of devices.
To make verification possible, a Cartesi Machine maps its entire state to the physical address space in a well-defined way.
This includes the internal states of the processor, the board, and of all attached devices.
The contents of the address space therefore completely define the Cartesi Machine.
Fortunately, this modification does not limit the operating system or the applications it hosts in any significant way.

Both the processor and board are implemented in the emulator.
A full description of the RISC-V ISA is out of the scope of this documentation (See the volumes [1 and 2](https://riscv.org/technical/specifications/) of the ISA specification for details.)
This section describes Cartesi's RISC-V architecture, the modifications made to support verification, the devices supported by the emulator, and the process the machine follows to boot the Linux kernel.

## The processor

Following RISC-V terminology, Cartesi Machines implement the `RV64IMAZicsr_Zifencei` ISA.
The letters after RV specify the extension set.
This selection corresponds to a 64-bit machine, integer arithmetic with multiplication and division, atomic operations, as well as the optional supervisor and user privilege levels.
In addition, Cartesi Machines support the Sv39 mode of address translation and memory protection.
Sv39 provides a 39-bit protected virtual address space, divided into 4KiB pages, organized by a three-level page table.
This set of features creates a balanced compromise between the simplicity demanded by a blockchain implementation and the flexibility expected from off-chain computations.

There are a total of 98 instructions, out of which 28 simply narrow or widen, respectively, their 64-bit or 32-bit counterparts.
This being a RISC ISA, most instructions are very simple and can be emulated in a few lines of high-level code.
In contrast, the x86 ISA defines at least 2000 (potentially complex) instructions.
In fact, the only complex operation in RISC-V is the virtual-to-physical address translation.
Instruction decoding is particularly simple due to the reduced number of formats (only 4, all taking 32-bits).

The entire processor state fits within 512&nbsp;bytes, which are divided into 64 registers, each one holding 64-bits.
It consists of 32 general-purpose integer registers and 26 control and status registers (CSRs).
Most of these registers are defined by the RISC-V&nbsp;ISA; the remaining are Cartesi-specific.
The processor makes its entire state available, externally-only and read-only, by mapping individual registers to the lowest 512 bytes in the physical address space (in the <i>processor shadow</i>).
The adjacent&nbsp;1.5KiB are reserved for future use.
The entire mapping is given in the following table:

<center>
<table>
<tr>
  <th>Offset</th>             <th>Register</th>
  <th>Offset</th>             <th>Register</th>
  <th>Offset</th>             <th>Register</th>
  <th>Offset</th>             <th>Register</th>
</tr>
<tr>
  <td><tt>0x000</tt></td>     <td><tt>x0 </tt></td>
  <td><tt>0x120</tt></td>     <td><tt>mcycle</tt></td>
  <td><tt>0x160</tt></td>     <td><tt>misa</tt></td>
  <td><tt>0x1a0</tt></td>     <td><tt>sepc</tt></td>
</tr>
<tr>
  <td><tt>0x008</tt></td>     <td><tt>x1 </tt></td>
  <td><tt>0x128</tt></td>     <td><tt>minstret</tt></td>
  <td><tt>0x168</tt></td>     <td><tt>mie</tt></td>
  <td><tt>0x1a8</tt></td>     <td><tt>scause</tt></td>
</tr>
<tr>
  <td><tt>&hellip;</tt></td> <td><tt>&hellip;</tt></td>
  <td><tt>0x130</tt></td>    <td><tt>mstatus</tt></td>
  <td><tt>0x170</tt></td>    <td><tt>mip</tt></td>
  <td><tt>0x1b0</tt></td>    <td><tt>stval</tt></td>
</tr>
<tr>
  <td><tt>0x0f8</tt></td>    <td><tt>x31</tt></td>
  <td><tt>0x138</tt></td>    <td><tt>mtvec</tt></td>
  <td><tt>0x178</tt></td>    <td><tt>medeleg</tt></td>
  <td><tt>0x1b8</tt></td>    <td><tt>satp</tt></td>
</tr>
<tr>
  <td><tt>0x100</tt></td>    <td><tt>pc</tt></td>
  <td><tt>0x140</tt></td>    <td><tt>mscratch</tt></td>
  <td><tt>0x180</tt></td>    <td><tt>mideleg</tt></td>
  <td><tt>0x1c0</tt></td>    <td><tt>scounteren</tt></td>
</tr>
<tr>
  <td><tt>0x108</tt></td>    <td><tt>mvendorid</tt></td>
  <td><tt>0x148</tt></td>    <td><tt>mepc</tt></td>
  <td><tt>0x188</tt></td>    <td><tt>mcounteren</tt></td>
  <td><tt>0x1c8</tt></td>    <td><tt>ilrsc</tt></td>
</tr>
<tr>
  <td><tt>0x110</tt></td>    <td><tt>marchid</tt></td>
  <td><tt>0x150</tt></td>    <td><tt>mcause</tt></td>
  <td><tt>0x190</tt></td>    <td><tt>stvec</tt></td>
  <td><tt>0x1d0</tt></td>    <td><tt>iflags </tt></td>
</tr>
<tr>
  <td><tt>0x118</tt></td>    <td><tt>mimpid</tt></td>
  <td><tt>0x158</tt></td>    <td><tt>mtval</tt></td>
  <td><tt>0x198</tt></td>    <td><tt>sscratch</tt></td>
  <td><tt></tt></td>         <td><tt></tt></td>
</tr>
</table>
</center>

The only generally relevant standard register is&nbsp;`mcycle`.
Since its value is advanced at every CPU cycle, it can be used to identify a particular step in the computation being performed by a Cartesi Machine.
This is a key component of the verification process, and can also be used to bound the amount of computation.

The registers whose names start with &ldquo;`i`&rdquo; are Cartesi additions, and have the following semantics:

* The layout for register&nbsp;<tt>iflags</tt> can be seen below:<p></p>
<center>
<table>
<tr>
  <th> Bits </th>
  <td><tt>63&ndash;5</tt></td>
  <td><tt>4&ndash;3</tt></td>
  <td><tt>2</tt></td>
  <td><tt>1</tt></td>
  <td><tt>0</tt></td>
</tr>
<tr>
  <th> Field </th>
  <td><i>Reserved</i></td>
  <td><tt>PRV</tt></td>
  <td><tt>X</tt></td>
  <td><tt>Y</tt></td>
  <td><tt>H</tt></td>
</tr>
</table>
</center>

Bit `PRV` gives the current privilege level (0 for User, 1 for Supervisor, and 3 for Machine), bit `X` is set to 1 when the processor has yielded automatic, bit `Y` is set to 1 when the processor has yielded manual, bit `H` is set to 1 to signal the processor has been permanently halted.
* Register&nbsp;`ilrsc` holds the reservation address for the&nbsp;LR/SC atomic memory operations;

## The board

The interaction between board and processor happens through interrupts and the memory bus. Devices are mapped to the processor's physical address space.
The mapping can be seen in the following table:

<center>
<table>
<tr>
  <th> Physical address </th>
  <th> Mapping </th>
</tr>
<tr>
  <td> <tt>0x00000000&ndash;0x000003ff</tt> </td>
  <td> Processor shadow </td>
</tr>
<tr>
  <td> <tt>0x00000800&ndash;0x00000bff</tt> </td>
  <td> Board shadow </td>
</tr>
<tr>
  <td> <tt>0x00001000&ndash;0x000ffff</tt> </td>
  <td> ROM (Bootstrap &amp; Devicetree) </td>
</tr>
<tr>
  <td> <tt>0x02000000&ndash;0x020bffff</tt> </td>
  <td> Core Local Interruptor </td>
</tr>
<tr>
  <td> <tt>0x40008000&ndash;0x40008fff</tt> </td>
  <td> Host-Target Interface </td>
</tr>
<tr>
  <td> <tt> 0x60000000&ndash;0x600fffff</tt>  (<i>configurable</i>) </td>
  <td> Rollup RX buffer </td>
</tr>
<tr>
  <td> <tt> 0x60200000&ndash;0x602FFFFF</tt>  (<i>configurable</i>) </td>
  <td> Rollup TX buffer </td>
</tr>
<tr>
  <td> <tt> 0x60400000&ndash;0x60400FFF</tt>  (<i>configurable</i>) </td>
  <td> Rollup Input Metadata </td>
</tr>
<tr>
  <td> <tt> 0x60600000&ndash;0x606FFFFF</tt>  (<i>configurable</i>) </td>
  <td> Rollup Voucher Hashes </td>
</tr>
<tr>
  <td> <tt> 0x60800000&ndash;0x608FFFFF</tt>  (<i>configurable</i>) </td>
  <td> Rollup Notice Hashes </td>
</tr>
<tr>
  <td> <tt>0x80000000&ndash;</tt><i>configurable</i> </td>
  <td> RAM </td>
</tr>
<tr>
  <td> <i> configurable </i> </td>
  <td> Flash drive 0 </td>
</tr>
<tr>
  <td> &hellip;</td>
  <td> &hellip;</td>
</tr>
<tr>
  <td> <i> configurable </i> </td>
  <td> Flash drive 7 </td>
</tr>
</table>
</center>

There are 60KiB of ROM starting at address&nbsp;`0x1000`, where execution starts by default.
The amount of RAM is user-configurable, but always starts at address&nbsp;`0x80000000`.
Finally, a number of additional physical memory ranges can be set aside for flash-memory devices.
These will typically be preloaded with file-system images, but can also hold raw data.

The board maps two non-memory devices to the physical address space: CLINT and HTIF.

### CLINT

The Core Local Interruptor (or CLINT) controls the timer interrupt.
The active addresses are&nbsp;`0x0200bff8`&nbsp;(`mtime`) and&nbsp;`0x02004000`&nbsp;(`mtimecmp`).
The CLINT issues a hardware interrupt whenever&nbsp;`mtime` equals&nbsp;`mtimecmp`.
Since Cartesi Machines must ensure reproducibility, the processor's clock and the timer are locked by a constant frequency divisor of&nbsp;`100`.
In other words, `mtime` is incremented once for every 100 increments of&nbsp;`mcycle`.
There is no notion of wall-clock time.

### HTIF

The Host-Target Interface (HTIF) mediates communication with the external world.
It is mapped to a physical memory starting at `0x40008000`, where registers can be accessed at the following offsets:

<center>
<table>
<tr>
  <th>Offset</th>             <th>Register</th>
</tr>
<tr>
  <td><tt>0x000</tt></td>     <td><tt>tohost</tt></td>
</tr>
<tr>
  <td><tt>0x008</tt></td>     <td><tt>fromhost</tt></td>
</tr>
<tr>
  <td><tt>0x010</tt></td>     <td><tt>ihalt</tt></td>
</tr>
<tr>
  <td><tt>0x018</tt></td>     <td><tt>iconsole</tt></td>
</tr>
<tr>
  <td><tt>0x020</tt></td>     <td><tt>iyield</tt></td>
</tr>
<tr>
  <td><tt>0x028</tt></td>     <td><i>Reserved</i></td>
</tr>
<tr>
  <td><tt>&hellip;</tt></td>     <td><tt>&hellip;</tt></td>
</tr>
<tr>
  <td><tt>0x218</tt></td>     <td><i>Reserved</i></td>
</tr>
</table>
</center>

The format of CSRs `tohost` and `fromhost` are as follows: <p></p>
<center>
<table>
<tr>
  <th> Bits </th>
  <td><tt>63&ndash;56</tt></td>
  <td><tt>55&ndash;48</tt></td>
  <td><tt>47&ndash;0</tt></td>
</tr>
<tr>
  <th> Field </th>
  <td><tt>DEV</tt></td>
  <td><tt>CMD</tt></td>
  <td><tt>DATA</tt></td>
</tr>
</table>
</center>

Interactions with Cartesi's HTIF device follow the following protocol:

1. start by writing 0 to `fromhost`;
1. write the <i>request</i> to `tohost`;
1. read the <i>response</i> from `fromhost`.

Cartesi's HTIF supports 3 subdevices: Halt, Console, and Yield.
These are identified by the following values for the field `DEV`.

<center>
<table>
<tr>
  <th colspan="2"> `DEV` </th>
</tr>
<tr>
  <th> Name </th>
  <th> Value </th>
</tr>
<tr>
  <td><tt>HTIF_DEVICE_HALT</tt></td>
  <td>0</td>
</tr>
<tr>
  <td><tt>HTIF_DEVICE_CONSOLE</tt></td>
  <td>1</td>
</tr>
<tr>
  <td><tt>HTIF_DEVICE_YIELD</tt></td>
  <td>2</td>
</tr>
</table>
</center>

Registers `ihalt`, `iconsole`, and `iyield` are bit masks specifying the commands that are available for the respective devices.
Unavailable commands are silently ignored by the machine.

##### Halt

<center>
<table>
<tr>
  <th colspan="2"> `CMD` </th>
</tr>
<tr>
  <th> Name </th>
  <th> Value </th>
</tr>
<tr>
  <td><tt>HTIF_HALT_HALT</tt></td>
  <td>0</td>
</tr>
</table>
</center>

The Halt device (`DEV=HTIF_DEVICE_HALT`) is used to halt the machine.
This will permanently set bit `H` in `iflags` and return control back to the host.

Send request `CMD=HTIF_HALT_HALT` and `DATA` containing bit 0 set to&nbsp;1.
Bits 47&ndash;1 can be set to an arbitrary exit code.

##### Console

<center>
<table>
<tr>
  <th colspan="2"> `CMD` </th>
</tr>
<tr>
  <th> Name </th>
  <th> Value </th>
</tr>
<tr>
  <td><tt>HTIF_CONSOLE_GETCHAR</tt></td>
  <td>0</td>
</tr>
<tr>
  <td><tt>HTIF_CONSOLE_PUTCHAR</tt></td>
  <td>1</td>
</tr>
</table>
</center>

The Console device (`DEV=HTIF_DEVICE_CONSOLE`) can be used to input/output characters.

To input a  character from console (in interactive sessions), request `CMD=HTIF_CONSOLE_GETCHAR`, `DATA=0`, then read response `CMD=HTIF_CONSOLE_GETCHAR`, `DATA=<ch>+1`. (`DATA=0` means no character was available);

To output a character `<ch>` to console, request `CMD=HTIF_CONSOLE_PUTCHAR`, with `DATA=<ch>`.

##### Yield

The Yield device can be used to return control to the host.
It uses a slight refinement to the format of CSRs `tohost` and `fromhost`, by splitting out a `REASON` field from `DATA`:<p></p>
<center>
<table>
<tr>
  <th> Bits </th>
  <td><tt>63&ndash;56</tt></td>
  <td><tt>55&ndash;48</tt></td>
  <td><tt>47&ndash;32</tt></td>
  <td><tt>31&ndash;0</tt></td>
</tr>
<tr>
  <th> Field </th>
  <td><tt>DEV</tt></td>
  <td><tt>CMD</tt></td>
  <td><tt>REASON</tt></td>
  <td><tt>DATA</tt></td>
</tr>
</table>
</center>

There are two types of yield: _automatic_ and _manual_.

<center>
<table>
<tr>
  <th colspan="2"> `CMD` </th>
</tr>
<tr>
  <th> Name </th>
  <th> Value </th>
</tr>
<tr>
  <td><tt>HTIF_YIELD_AUTOMATIC</tt></td>
  <td>0</td>
</tr>
<tr>
  <td><tt>HTIF_YIELD_MANUAL</tt></td>
  <td>1</td>
</tr>
</table>
</center>

To issue an automatic yield, request `CMD=HTIF_YIELD_AUTOMATIC`.
An automatic yield sets the bit `X` in `iflags` and returns control back to the host.
There are currently 4 supported reasons for automatic yields:

<center>
<table>
<tr>
  <th colspan="2"> `REASON` </th>
</tr>
<tr>
  <th> Name </th>
  <th> Value </th>
</tr>
<tr>
  <td><tt>HTIF_YIELD_REASON_PROGRESS</tt></td>
  <td>0</td>
</tr>
<tr>
  <td><tt>HTIF_YIELD_REASON_TX_VOUCHER</tt></td>
  <td>3</td>
</tr>
<tr>
  <td><tt>HTIF_YIELD_REASON_TX_NOTICE</tt></td>
  <td>4</td>
</tr>
<tr>
  <td><tt>HTIF_YIELD_REASON_TX_REPORT</tt></td>
  <td>5</td>
</tr>
</table>
</center>

To report `progress`, set `REASON=HTIF_YIELD_REASON_PROGRESS`, and `DATA=<permil>`, where `<permil>` gives the progress in parts per thousand.
The other reasons for automatic yield signal the production of Cartesi Rollups responses.
`REASON=HTIF_YIELD_REASON_TX_VOUCHER`, `REASON=HTIF_YIELD_REASON_TX_NOTICE`, and `REASON=HTIF_YIELD_REASON_TX_REPORT` denote, respectively, transfers of a voucher, a notice, and a report from target to host.
The `DATA` field in `tohost` is ignored in these cases.

To issue a manual yield, request `CMD=HTIF_YIELD_MANUAL`.
A manual yield sets the bit `Y` in `iflags` and returns control back to the host.
There are currently 3 supported reasons for manual yields, all used with Cartesi Rollups:

<center>
<table>
<tr>
  <th colspan="2"> `REASON` </th>
</tr>
<tr>
  <th> Name </th>
  <th> Value </th>
</tr>
<tr>
  <td><tt>HTIF_YIELD_REASON_RX_ACCEPTED</tt></td>
  <td>1</td>
</tr>
<tr>
  <td><tt>HTIF_YIELD_REASON_RX_REJECTED</tt></td>
  <td>2</td>
</tr>
<tr>
  <td><tt>HTIF_YIELD_REASON_TX_EXCEPTION</tt></td>
  <td>6</td>
</tr>
</table>
</center>

To accept or reject the previous request, set `REASON=HTIF_YIELD_REASON_RX_ACCEPTED` or
`REASON=HTIF_YIELD_REASON_RX_REJECTED`, respectively.
The `DATA` field in `tohost` is ignored in these cases.
Upon return, the `DATA` field in `fromhost` will contain the type of the next request:

<center>
<table>
<tr>
  <th colspan="2"> `DATA` in response </th>
</tr>
<tr>
  <th> Name </th>
  <th> Value </th>
</tr>
<tr>
  <td><tt>HTIF_YIELD_ADVANCE_STATE</tt></td>
  <td>0</td>
</tr>
<tr>
  <td><tt>HTIF_YIELD_INSPECT_STATE</tt></td>
  <td>1</td>
</tr>
</table>
</center>

The signal the throwing of a rollup exception, set `REASON=HTIF_YIELD_REASON_TX_EXCEPTION`.
The `DATA` field in `tohost` is ignored in this case.

Before resuming the emulator after a manual yield, the host must manually reset the `Y` bit in `iflags`.
Otherwise, the emulator will immediately return with no changes to its state.

### Rollup

In order to interact with Cartesi Rollups, the host application controlling the emulator and the target application running inside the emulator  must follow an agreed-upon protocol, mediated by the HTIF Yield device.

The low-level view of what happens inside the machine is as follows:
```
Initialize
Repeat
    `voucher_index` = 0
    `notice_index` = 0
    `reason` = HTIF_YIELD_REASON_RX_ACCEPTED
    Yield manual with `reason` as `REASON` in `tohost`
    If `DATA` in `fromhost` is `HTIF_YIELD_ADVANCE_STATE`
        Read input metadata from Rollup Input Metadata
        Read input data from Rollup RX Buffer
        Process advance-state request
        For each voucher to emit
            Write voucher data to Rollup TX Buffer
            Write voucher hash to slot `voucher_index` in Rollup Voucher Hashes
            `voucher_index` = `voucher_index` + 1
            Yield automatic with HTIF_YIELD_REASON_TX_VOUCHER as `REASON` in `tohost`
        End
        For each notice to emit
            Write notice data to Rollup TX Buffer
            Write notice hash to slot `notice_index` in Rollup Notice Hashes
            `notice_index` = `notice_index` + 1
            Yield automatic with HTIF_YIELD_REASON_TX_NOTICE as `REASON` in `tohost`
        End
        For each report to emit
            Write report data to Rollup TX Buffer
            Yield automatic with HTIF_YIELD_REASON_TX_REPORT as `REASON` in `tohost`
        End
        If exception to emit
            Write exception data to Rollup TX Buffer
            Yield automatic with HTIF_YIELD_REASON_TX_EXCEPTION as `REASON` in `tohost`
        ElseIf input rejected
            `reason` = HTIF_YIELD_REASON_RX_REJECTED
        End
    End
    If `DATA` in `fromhost` is `HTIF_YIELD_INSPECT_STATE`
        Read query data from Rollup RX Buffer
        Process inspect-state request
        For each report
            Write report data to Rollup TX Buffer
            Yield automatic with HTIF_YIELD_REASON_TX_REPORT as `REASON` in `tohost`
        End
        If exception
            Write exception data to Rollup TX Buffer
            Yield automatic with HTIF_YIELD_REASON_TX_EXCEPTION as `REASON` in `tohost`
        ElseIf input rejected
            `reason` = HTIF_YIELD_REASON_RX_REJECTED
        End
    End
End
```
At a higher level, the target application running inside the emulator is supported by the `/dev/rollup` Linux device driver via its `ioctl` interface, or by even higher-level interfaces based on it, such as `/opt/cartesi/bin/rollup` command-line utility or the HTTP API exposed by the `/opt/cartesi/bin/rollup-http-server` command-line utility.
It is the `/dev/rollup` device that copies data to and from all rollup memory ranges, and that uses the `/dev/yield` device to perform the required yields.

There are two types of request: advance-state requests and inspect-state requests.
The loop processes one request per iteration.
To transition between requests, the application accepts or rejects the previous request by issuing a command to the HTIF yield device, or throws an exception.
The return from the yield defines the type of the next request.

When the application identifies an advance-state request, it obtains input medatada from the Rollup Input Metadata memory range, and input from the Rollup RX Buffer memory range.
While processing advance-state requests, the application can emit vouchers, notices, reports, or exceptions.
It writes the data for all these to the Rollup TX buffer memory range.
Moreover, when emitting the ith voucher (respectively, notice) in response to a given input, it writes its hash to the ith 32-byte slot in the Rollup Voucher Hashes (respectively, Rollup Notice Hashes) memory range.
It then issues the appropriate command to the HTIF yield device.

When an application identifies an inspect-state request, it obtains the query from the Rollup RX buffer memory range.
While processing inspect-state requests, the application can emit vouchers, or exceptions.
It writes data for all these to the Rollup TX buffer memory range and sends the appropriate command to the HTIF yield device.

The format for all these request and response data are as follows: <a title="#rollup-format"></a>

<center>
<table>
<tr>
  <th colspan="2">Format for input metadata</th>
</tr>
<tr>
  <th>Offset (bytes) </th>             <th>Field</th>
</tr>
<tr>
  <td><tt>0&ndash;31</tt></td>     <td>message sender (address hash)</td>
</tr>
<tr>
  <td><tt>32&ndash;63</tt></td>     <td>block number (number)</td>
</tr>
<tr>
  <td><tt>64&ndash;95</tt></td>     <td>time stamp (number)</td>
</tr>
<tr>
  <td><tt>96&ndash;127</tt></td>     <td>epoch index (number)</td>
</tr>
<tr>
  <td><tt>128&ndash;159</tt></td>     <td>input index (number)</td>
</tr>
<tr>
  <th colspan="2">Format for voucher</th>
</tr>
<tr>
  <th>Offset (bytes) </th>             <th>Field</th>
</tr>
<tr>
  <td><tt>0&ndash;31</tt></td>     <td>address (address hash)</td>
</tr>
<tr>
  <td><tt>32&ndash;63</tt></td>     <td>offset (number, always 64)</td>
</tr>
<tr>
  <td><tt>64&ndash;95</tt></td>     <td>length (number)</td>
</tr>
<tr>
  <td><tt>96&ndash;96+length-1</tt></td>     <td>payload (raw data)</td>
</tr>
<tr>
  <th colspan="2">Format for input, notice, report, and exception </th>
</tr>
<tr>
  <th>Offset (bytes) </th>             <th>Field</th>
</tr>
<tr>
  <td><tt>0&ndash;31</tt></td>     <td>offset (number, always 32)</td>
</tr>
<tr>
  <td><tt>32&ndash;63</tt></td>     <td>length (number)</td>
</tr>
<tr>
  <td><tt>64&ndash;64+length-1</tt></td>     <td>payload (raw data)</td>
</tr>
</table>
</center>
All numbers are encoded as 256-bit big-endian integers.
Address hashes are encoded in the least significant 160-bits of a zero-padded 256-bit big-endian integer.

In the host, the loop is as follows:
```
While bit `H` in `iflags` is not set (machine has not halted)
    Snapshot machine state
    Resume machine
    If bit `Y` in `iflags` is set (i.e. manual yield)
        If `REASON` in `tohost` is HTIF_YIELD_REASON_RX_REJECTED
            Discard vouchers and notices emitted from previous request, if any
            Rollback machine state
        End
        If `REASON` in `tohost` is HTIF_YIELD_REASON_TX_EXCEPTION
            Read exception data from Rollup TX Buffer
            Discard vouchers and notices emitted from previous request, if any
            Rollback machine state
        End
        If `REASON` in `tohost` is HTIF_YIELD_REASON_RX_ACCEPTED
            If previous request was advance-state
                Read Rollup Voucher Hashes for previous request
                Read Rollup Notice Hashes for previous request
            End
            Obtain the next request from an external source
            If advance-state request
                Clear Rollup Voucher Hashes
                Clear Rollup Notice Hashes
                Write input data to Rollup RX Buffer
                Write input metadata to Rollup Input Metadata
                Write HTIF_YIELD_ADVANCE_STATE to `DATA` in `fromhost`
            End
            If inspect-state request
                Write query data to Rollup RX Buffer
                Write HTIF_YIELD_INSPECT_STATE to `DATA` in `fromhost`
            End
            Clear `Y` bit in `iflags`
        End
    End
    If bit `X` in `iflags` is set (i.e. automatic yield)
        If `REASON` in `tohost` is HTIF_YIELD_REASON_TX_VOUCHER
            Read voucher data from rollup memory ranges
        End
        If `REASON` in `tohost` is HTIF_YIELD_REASON_TX_NOTICE
            Read notice data from rollup memory ranges
        End
        If `REASON` in `tohost` is HTIF_YIELD_REASON_TX_REPORT
            Read report data from Rollup TX Buffer
        End
    End
End
```
In production, the host application controlling the emulator is the Server Manager
While prototyping, it can be the `cartesi-machine` command-line utility, or even a custom script using the Lua API.

### PMAs

The physical memory mapping is described by Physical Memory Attribute records (PMAs) that start at address `0x00000800` (the <i>board shadow</i>) .
Each PMA consists of 2 64-bit words.
The first word gives the start of a range and the second word its length.
These words are readable both internally and externally.
Since the ranges must be aligned to 4KiB page boundaries, the lowest 12-bits of each word are available for attributes.
The meaning of each attribute field is as follows:
<center>
<table>
<tr>
  <th> Bits </th>
  <td><tt>63&ndash;12</tt></td>
  <td><tt>11&ndash;8</tt></td>
  <td><tt>7</tt></td>
  <td><tt>6</tt></td>
  <td><tt>5</tt></td>
  <td><tt>4</tt></td>
  <td><tt>3</tt></td>
  <td><tt>2</tt></td>
  <td><tt>1</tt></td>
  <td><tt>0</tt></td>
</tr>
<tr>
  <th> Field </th>
  <td><tt>start</tt></td>
  <td><tt>DID</tt></td>
  <td><tt>IW</tt></td>
  <td><tt>IR</tt></td>
  <td><tt>X</tt></td>
  <td><tt>W</tt></td>
  <td><tt>R</tt></td>
  <td><tt>E</tt></td>
  <td><tt>IO</tt></td>
  <td><tt>M</tt></td>
</tr>
<tr> <td colspan="11"> </td> </tr>
<tr>
  <th> Bits </th>
  <td><tt>63&ndash;12</tt></td>
  <td colspan="9"><tt>11&ndash;0</tt></td>
</tr>
<tr>
  <th> Field </th>
  <td><tt>length</tt></td>
  <td colspan="9"><i>Reserved (=0)</i></td>
</tr>
</table>
</center>

The `M`, `IO`, and `E` bits are mutually exclusive, and respectively mark the range as memory, I/O mapped, or excluded.
Bits `R`, `W`, and&nbsp;`X` mark read, write, and execute permissions, respectively.
The `IR` and&nbsp;`IW` bits mark the range as idempotent for reads and writes, respectively.
Finally, the `DID` gives the device id, which can have the following values:

<center>
<table>
<tr>
  <th> Name </th>
  <th> Value </th>
</tr>
<tr>
  <td><tt>PMA_MEMORY_DID</tt></td>
  <td>0</td>
</tr>
<tr>
  <td><tt>PMA_SHADOW_DID</tt></td>
  <td>1</td>
</tr>
<tr>
  <td><tt>PMA_FLASH_DRIVE_DID</tt></td>
  <td>2</td>
</tr>
<tr>
  <td><tt>PMA_CLINT_DID</tt></td>
  <td>3</td>
</tr>
<tr>
  <td><tt>PMA_HTIF_DID</tt></td>
  <td>4</td>
</tr>
<tr>
  <td><tt>PMA_DHD_DID</tt></td>
  <td>5</td>
</tr>
<tr>
  <td><tt>PMA_ROLLUP_RX_BUFFER_DID</tt></td>
  <td>6</td>
</tr>
<tr>
  <td><tt>PMA_ROLLUP_TX_BUFFER_DID</tt></td>
  <td>7</td>
</tr>
<tr>
  <td><tt>PMA_ROLLUP_INPUT_METADATA_DID</tt></td>
  <td>8</td>
</tr>
<tr>
  <td><tt>PMA_ROLLUP_VOUCHER_HASHES_DID</tt></td>
  <td>9</td>
</tr>
<tr>
  <td><tt>PMA_ROLLUP_NOTICE_HASHES_DID</tt></td>
  <td>10</td>
</tr>
</table>
</center>

The list of PMA records ends with an invalid PMA entry for which `length=0`.

## Linux setup

By default, `pc` starts at `0x1000`, pointing to the start of the ROM region.
Before control reaches the RAM image (and ultimately the Linux kernel), a small program residing in ROM builds a [<i>devicetree</i>](http://devicetree.org/) describing the hardware.
Cartesi's ROM image `rom.bin` containing this program can be generated from the `rom/` directory of the [Cartesi Machine SDK](https://github.com/cartesi/machine-emulator-sdk).
To do so, it goes over the PMA entries identifying the devices and their locations in the physical address space.
It also looks for a null-terminated string, starting at the last 4k of the ROM region, that will be used as the command-line for the Linux kernel.
Once the devicetree is ready, the ROM program sets register&nbsp;`x10` to 0 (the value of&nbsp;`mhartid`), `x11` to point to the devicetree (which it places at the end of the RAM region), and then jumps to RAM-base at&nbsp; address `0x80000000`.
This is where the entry point of the RAM image is expected to reside.

The `dtc` command-line utility can be used to inspect the devicetree:

```bash
cartesi-machine \
    --append-rom-bootargs="single=yes" \
    --rollup \
    -- "dtc -I dtb -O dts /sys/firmware/fdt"
```

The result is

```
%machine.target.architecture.dtc
```

The `memory@80000000` section describes 64MiB of RAM starting at address `0x80000000`.
The `flash@8000000000000000` describes flash drive 0: a memory region of 60MiB, starting at address `0x8000000000000000`, under the control of the `mtd-ram` driver, with name `flash.0`.
This will eventually become available as block device `/dev/mtdblock0`.
The `rollup` section specifies the starts and lengths of all rollup memory ranges.
The `yield` section specifies that the machine will process automatic and manual yields.
Finally, section `chosen` includes the `bootargs` string that will be used as the kernel command-line parameters.
Notice the specification of the root file-system pointing to `/dev/mtdblock0`, i.e., `flash.0`, and the `mtdparts` giving it the label `root`.
Also notice the command `dtc -I dtb -O dts /sys/firmware/fdt` coming directly from the `cartesi-machine` command line.

Linux support for RISC-V is upstream in the [Linux kernel archives](https://www.kernel.org/).
The kernel runs in supervisor mode, on top of a Supervisor Binary Interface (SBI) provided by a machine-mode shim: the Berkeley Boot Loader (BBL).
The BBL is linked against the Linux kernel and this resulting RAM image is preloaded into RAM.
Cartesi's RAM image `linux.bin` can be generated from the `kernel/` directory of the [Cartesi Machine SDK](https://github.com/cartesi/machine-emulator-sdk).
The SBI provides a simple interface through which the kernel interacts with CLINT and HTIF.
Besides implementing the SBI, the BBL also installs a trap that catches invalid instruction exceptions.
This mechanism can be used, for example, to emulate floating-point instructions, although it is more efficient to setup the target toolchain to replace floating point instructions with calls to a soft-float implementation instead.
After installing the trap, BBL switches to supervisor mode and cedes control to the kernel entry point.

After completing its own initialization, the kernel mounts the root file-system and eventually cedes control to&nbsp;`/sbin/init`.
Cartesi's root file-system `rootfs.ext2` can be generated from the `fs/` directory in the [Cartesi Machine SDK](https://github.com/cartesi/machine-emulator-sdk).
The Cartesi-provided `/sbin/init` script scans all flash devices `/dev/mtdblock1`&ndash;`/dev/mtdblock7` for valid file-systems.
When a file-system is found, the script obtains the corresponding `<label>` (set in the `mtdparts` kernel command-line parameter) by inspecting `/sys/block/mtdblock*/device/name` and mounts the filesystem at `/mnt/<label>`.
The kernel passes to `/sbin/init` as command-line parameters all arguments after the separator&nbsp;`--`&nbsp;in the `bootargs` string it found in the devicetree.
The Cartesi-provided `/sbin/init` script concatenates all arguments into a string and executes the command in this string in a shell.
When the shell returns, `/sbin/init` unmount all file-systems and gracefully halts the machine.

