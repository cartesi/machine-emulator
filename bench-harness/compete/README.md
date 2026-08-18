# Cross-emulator benchmark harness (tail-call.md items 19-22)

Everything needed to reproduce the cartesi / qemu-system / qemu-icount / RVVM
comparison on AArch64 and the earlier rv8 comparison on AMD64. The measurements
themselves live in `tail-call.md` items 19-22; this file is the method.

The guiding constraint: **one binary, one work definition, one guest software
path**. Both full-system columns run the same static `stress-ng`, the same
fixed bogo-ops, the same kernel and the same four-line init, so the columns
differ only in the emulator and the root device name.

## Files here

| File | Role |
| --- | --- |
| `drive.py` | The runner. Phases: `calibrate`, `run`, `run_sys`, `run_icount`, `report`. |
| `compete.lua` | cartesi column: boots the guest, runs one command, reports cpu-time + mcycle. |
| `bench-init` | The four-line guest init, identical on both full-system columns. |
| `ops.json` | Calibrated fixed bogo-ops per workload (the numbers actually used). |
| `bisect.lua` | Checkpoint-hash harness: bisects the first divergent mcycle between two builds. |
| `logstep.lua` | `log_step` record→replay oracle over SUM-toggling syscall windows. |
| `rv8-modern-binaries.patch` | The three rv8 fixes needed to run modern binaries at all. |
| `linux.bin` | Directly bootable RVVM OpenSBI + Linux image used by the AArch64 board. |
| `linux.config` | Exact Linux configuration used to build the kernel in `linux.bin`. |

`drive.py` resolves paths relative to its own location: it expects the working
tree described under *Layout* below, with the campaign build directory as a
sibling. It is committed as it ran; adjust the constants at the top if you
relocate it.

## Operation counts

`ops.json`, as calibrated and as used for every number in items 19-22:

```
nop 118367   regs 35970   branch 45180   tree 2      qsort 1    memcpy 108
zlib 41      hash 56298   syscall 34718  double 200  sieve 1276 int64 393
matrixprod 16
```

They are wildly different magnitudes because a stress-ng "bogo-op" means a
different amount of work per stressor (one `tree` op is a whole build-and-walk;
one `nop` op is ~70k retired guest instructions). `drive.py calibrate` produced
them by running each stressor for 5 wall seconds under `qemu-riscv64` and
scaling the reported bogo-op count to land near 6 seconds:

```python
cmd = f"qemu-riscv64 {SNG} --no-rand-seed {ARGS[wl]} --timeout 5 --metrics-brief"
ops[wl] = max(1, int(bogo_ops_from_metrics) * 6 // 5)
```

Fixed ops (not fixed time) is what makes the columns comparable: every emulator
performs identical guest work, so wall time is the only free variable. The
`--no-rand-seed` flag keeps the work deterministic across runs and emulators.

## The exact QEMU command line

```
qemu-system-riscv64 -M virt -m 512M -smp 1 -display none \
  -serial file:serial.log -snapshot \
  -drive file=rootfs-bench.ext2,format=raw,if=none,id=d0 \
  -device virtio-blk-device,drive=d0 \
  -kernel Image-ctsi -dtb run.dtb -no-reboot
```

The `qemu-icount` column is the identical line plus `-icount shift=0,sleep=off`.
QEMU 8.2, OpenSBI as shipped (the `virt` board's default firmware).

Notes that cost time to discover:

- **`-kernel Image-ctsi`, not `linux.bin`.** Our `linux.bin` is a BBL-style
  bundle whose first 2 MiB are the cartesi M-mode shim; booting it as an
  S-mode kernel traps with `scause=2` (illegal instruction). OpenSBI replaces
  that shim, so the inner `Image` must be extracted:
  ```sh
  dd if=$IMAGES/linux.bin of=Image-ctsi bs=1M skip=2      # verify: "RISCV" magic at +0x30
  ```
  This is byte-identical to `linux.bin` from 2 MiB onward — same kernel as the
  cartesi column, which is the point.
- **virtio-blk, not nvdimm.** The cartesi column roots on `/dev/pmem0`; QEMU
  8.2's `virt` board has no nvdimm, so the rootfs attaches as virtio-blk and
  the guest roots on `/dev/vda`. The ctsi kernel has `VIRTIO_BLK`/`VIRTIO_MMIO`
  built in, so no kernel rebuild was needed. This is the *only* guest-visible
  difference between the two full-system columns.
- **`-snapshot`** keeps each run's writes off the shared image.

## Passing the workload into the guest

The cartesi machine exposes its entrypoint through a DTB node. For parity, the
QEMU column fabricates the same node so `bench-init` reads it identically on
both sides. Base DTB dumped once from the board:

```sh
qemu-system-riscv64 -M virt,dumpdtb=virt.dtb -m 512M -smp 1 -display none
```

then per run (`sys_dtb()` in `drive.py`):

```sh
cp virt.dtb run.dtb
fdtput -c run.dtb /cartesi-machine                       # FDT_ERR_EXISTS here is benign
fdtput -t s run.dtb /chosen bootargs \
  "quiet earlycon=sbi console=hvc0 root=/dev/vda rw init=/usr/sbin/bench-init"
fdtput -t s run.dtb /cartesi-machine entrypoint "$ENTRY"
```

The entrypoint goes on `/cartesi-machine`, **not** `/chosen` — that is where
the cartesi DTB puts it and therefore where `bench-init` looks. The cartesi
column passes the same string through `dtb.entrypoint` in `compete.lua`, with
`root=/dev/pmem0` as the only difference.

`bench-init` (mode 0755 at `/usr/sbin/bench-init`), identical on both columns:

```sh
#!/bin/busybox sh
busybox mkdir -p /proc /dev /sys
busybox mount -t proc proc /proc
busybox mount -t sysfs sys /sys
busybox mount -t devtmpfs devtmpfs /dev 2> /dev/null
ENTRY=/proc/device-tree/cartesi-machine/entrypoint
[ -f "$ENTRY" ] && . "$ENTRY"
busybox poweroff -f
```

It exists to sidestep `cartesi-init`, whose service startup would otherwise be
measured as part of the workload and differ between the columns. Three details
are load-bearing: `/proc` must be mounted because `/proc/device-tree` is where
the entrypoint is read from; the `2> /dev/null` on devtmpfs suppresses an
EBUSY under cartesi that otherwise corrupts the parsed output; and
`poweroff -f` is what ends the timed region.

## Timing and completion detection

**cartesi columns.** `compete.lua` measures `os.clock()` (cpu time) across a
single `machine:run(1 << 62)`, which returns when the guest halts via
`poweroff -f`. It prints `elapsed mcycle reason`; the runner asserts
`reason == 1` (halted) and reads mcycle as the determinism check — the same
workload must retire exactly the same mcycle on every build, and it does.

**QEMU columns.** Wall time around the whole process (`time.monotonic()`), which
exits on guest poweroff because of `-no-reboot`. Completion is verified from
the serial log rather than the exit status:

```python
ok = b"successful run" in open("serial.log", "rb").read()
```

stress-ng prints "successful run completed" only after finishing its ops, so a
crashed or short run scores `None` rather than a fast time. rv8 and qemu-user
use the process return code.

**Boot baseline.** Every full-system number has the guest's own boot subtracted.
The baseline is the median of three runs of the identical command with the
entrypoint set to `true` — same kernel, same init, same mounts, no workload:

```python
base = statistics.median(boot_baseline(build) for _ in range(3))
t = run_cartesi(build, wl, ops[wl], base)   # reported time is (measured - base)
```

Each emulator gets its own baseline (they boot at different speeds), so what is
compared is workload time, not boot time. Re-derive the baseline whenever the
host or build changes — item 20 used a same-day re-run of the old build to bound
host drift at 5-8%, which is the right habit before trusting any cross-day
comparison.

## Building the benchmark filesystem

`rootfs-bench.ext2` is the stock guest rootfs plus two files. It is a copy so
that the tracked image stays pristine.

**1. musl cross-toolchain.** The distro `riscv64-linux-gnu-gcc` produces
glibc-static binaries that fault under rv8's proxy syscall layer, so the shared
binary is musl-static:

```sh
git clone https://github.com/kraj/musl && cd musl && git checkout v1.2.5
./configure --target=riscv64 --prefix=$COMP/musl-rv \
  CC=riscv64-linux-gnu-gcc CROSS_COMPILE=riscv64-linux-gnu-
make -j && make install          # yields $COMP/musl-rv/bin/musl-gcc
```

**2. zlib into the musl sysroot** (the `zlib` stressor will not build without it):

```sh
git clone https://github.com/madler/zlib && cd zlib && git checkout v1.3.1
CC=$COMP/musl-rv/bin/musl-gcc ./configure --static --prefix=$COMP/musl-rv
make -j && make install
```

**3. stress-ng, static:**

```sh
git clone https://github.com/ColinIanKing/stress-ng && cd stress-ng   # 0.17.06
make CC=$COMP/musl-rv/bin/musl-gcc STATIC=1 -j
```

**4. Inject into a copy of the rootfs:**

```sh
cp $IMAGES/rootfs.ext2 rootfs-bench.ext2
e2cp stress-ng/stress-ng rootfs-bench.ext2:/usr/bin/stress-ng-musl
e2cp -P 755 bench-init    rootfs-bench.ext2:/usr/sbin/bench-init
debugfs -R "stat /usr/bin/stress-ng-musl" rootfs-bench.ext2   # verify
```

The identical `/usr/bin/stress-ng-musl` is what qemu-user and rv8 execute
directly from the host filesystem, which is what makes "same binary" literally
true across all five columns.

## RVVM full-system benchmark on AArch64

The AArch64 board in item 22 used full-system RVVM, not the user-mode rv8
runner below. The measured RVVM revision was LekKit/RVVM commit
`33ea63aa959cad202573cb5e0f7248db85f84683` (`v0.7-git-g33ea63a`). Build the
unmodified revision with its documented Makefile:

```sh
git clone https://github.com/LekKit/RVVM.git
cd RVVM
git checkout 33ea63aa959cad202573cb5e0f7248db85f84683
make
```

On the measured macOS/AArch64 host the executable was
`release.darwin.arm64/rvvm_arm64`. Do not use an instrumented RVVM build for
timings.

### Boot image provenance

The committed `linux.bin` is an RVVM firmware image and boots directly as the
first RVVM argument; it is not the normal Cartesi `linux.bin`. Its layout is:

```text
0x000000-0x041c6f  upstream OpenSBI generic fw_jump.bin
0x041c70-0x1fffff  zero padding
0x200000-0x10bb81f Linux Image
```

The components and resulting artifact are fixed by these identities:

```text
OpenSBI v1.3.1
  commit 057eb10b6d523540012e6947d5c9f63e95244e94
  fw_jump.bin sha256 920fa1bcd5d4b623496abe70a62b6f473f55d7c05cb538062ee507208d138e8f
Linux cartesi/linux v6.5.13-ctsi-2-uio-test1
  source tar sha256 ca2142b0fd3fce1cb80b661080a09f288d62bdc61a0b5e3ece44246bc8d6b16c
  Image sha256 c570a15a4cd484088e72f8f28bf74e404888904ed00768433a68b33f10c8c4c0
  config sha256 26b71073edfa022c727f05d6557e14aaaa8bacba9d305d638cec466af82cb919
linux.bin
  size 17545248 bytes
  sha256 c2370b05b683d511851279c5c3f637873a334898597db283c11a2da413bffa13
```

The image was packed without changing either component:

```sh
cp fw_jump.bin linux.bin
truncate -s 2097152 linux.bin
dd if=Image of=linux.bin bs=1048576 seek=2 conv=notrunc
```

The kernel configuration adds the generic PCI host, NVMe block device and
8250 UART support needed by RVVM. The exact configuration is committed as
`linux.config`; rebuilding the kernel is unnecessary for the benchmark.
Upstream OpenSBI is required because the Cartesi OpenSBI port uses the
emulator's custom single-hart HTIF conventions and is not an RVVM firmware.

### RVVM machine and guest setup

Use the same `rootfs-bench.ext2`, `/usr/sbin/bench-init`, static stress-ng
binary and `ops.json` described above. RVVM exposes its image as NVMe and does
not have QEMU's `-snapshot`, so make an APFS clone before every boot (`cp -c`
on macOS; use a reflink or ordinary copy elsewhere). Never benchmark against
the shared source image directly.

Generate RVVM's base DTB once. This first boot also proves that the committed
image reaches Linux; without `/cartesi-machine/entrypoint`, `bench-init` simply
powers off:

```sh
RVVM=RVVM/release.darwin.arm64/rvvm_arm64
BOOTARGS='quiet earlycon=uart8250,mmio,0x10000000 console=ttyS0 root=/dev/nvme0n1 rw init=/usr/sbin/bench-init'
cp -c rootfs-bench.ext2 rvvm-rootfs.ext2
$RVVM linux.bin -i rvvm-rootfs.ext2 -m 512M -smp 1 -nogui -nonet -nosound \
  -cmdline "$BOOTARGS" -dumpdtb rvvm-base.dtb
```

For each timed boot, inject the command through the same DTB node read by the
Cartesi and QEMU guests, clone a fresh drive, then invoke RVVM without `-k`:

```sh
ENTRY='/usr/bin/stress-ng-musl --no-rand-seed --cpu 1 --cpu-method int64 --cpu-ops 393'
cp rvvm-base.dtb rvvm-run.dtb
fdtput -c rvvm-run.dtb /cartesi-machine
fdtput -t s rvvm-run.dtb /chosen bootargs "$BOOTARGS"
fdtput -t s rvvm-run.dtb /cartesi-machine entrypoint "$ENTRY"
cp -c rootfs-bench.ext2 rvvm-rootfs.ext2
$RVVM linux.bin -i rvvm-rootfs.ext2 -m 512M -smp 1 -nogui -nonet -nosound \
  -dtb rvvm-run.dtb
```

Measure monotonic wall time around the whole RVVM process. Accept a workload
sample only when RVVM exits with status zero and its combined output contains
`successful run completed`. For each host session, first measure three boots
with `ENTRY=true` and take their median. Run every workload in `ops.json` three
times, interleaving emulators in each workload/repetition cell as the AArch64
runner did. Report each sample as total wall time minus that emulator's median
boot baseline, then report the median of the three adjusted samples. The item
22 RVVM baseline samples were 0.115197209, 0.114415208 and 0.114806709 seconds;
their median was 0.114806709 seconds. Recompute rather than reuse that number.

## rv8

rv8's `rv-jit` is kept for the register-mapping lineage only, and it is
**user-mode**: no supervisor mode, syscalls proxied to the host. It cannot run
`syscall` or `zlib` at all. Three fixes were needed before it would run any
modern binary — `rv8-modern-binaries.patch`:

- **Loader SIGBUS on large BSS.** It file-maps `p_memsz`, so any segment whose
  memory size exceeds its file size maps past EOF. Fixed by mapping the file
  part to `p_filesz` rounded up, anonymously mapping the remainder, and
  memsetting only the file-backed tail.
- **Unknown syscalls panicked.** Now default to `-ENOSYS` (-38).
- **`sigaltstack`/`prctl`/`setitimer` must succeed.** Return 0 rather than
  aborting.

Build and run:

```sh
make -C rv8                       # after applying the patch
LD_LIBRARY_PATH=rv8/build/linux_x86_64/lib \
  rv8/build/linux_x86_64/bin/rv-jit -- stress-ng/stress-ng $ARGS
```

## Running it

```sh
python3 drive.py calibrate     # regenerates ops.json (only if the binary changes)
python3 drive.py run           # cartesi jit + stock, qemu-user, rv8
python3 drive.py run_sys       # qemu-system
python3 drive.py run_icount    # qemu-system -icount shift=0,sleep=off
python3 drive.py report        # medians table
```

Results accumulate in `results.json` as `(emulator, workload, rep, seconds)`
with `None` for failures, so phases can run independently and `report` can be
re-run at any time.

## Layout the scripts assume

```
<scratchpad>/campaign/builds/<name>/cartesi.so     # one build per directory
<scratchpad>/compete/{drive.py,compete.lua,ops.json,bench-init,...}
<scratchpad>/compete/{Image-ctsi,virt.dtb,rootfs-bench.ext2}
<scratchpad>/compete/{stress-ng/,rv8/,musl-rv/}
```

Builds are selected by directory name (`LUA_CPATH=<dir>/?.so`), which is how
several emulator versions are compared in one session without reinstalling.

## Correctness harnesses

Not part of the comparison, but used throughout items 20-22 and cheap to re-run:

- `bisect.lua` — prints the root hash at each of a list of mcycle checkpoints.
  Diffing two builds' output locates the first divergent window; repeated
  bisection narrows it to a single instruction. This is what identified the
  one 32-byte shadow row behind the item-20 memcpy scare.
- `logstep.lua` — boots into a syscall-heavy region and calls `log_step`, whose
  internal record→replay root-hash assertion is the correctness oracle for
  TLB-visible state. Windows are chosen to cross SUM toggles and traps.
- Instruments compiled behind `MYDEFS=-DTLB_FILL_LOG`, each enabled by its own
  environment variable at run time: `TLB_FILL_LOG` (every shadow TLB fill),
  `TC_PUB_LOG` (published trace fragments), `TC_ABORT_LOG` (rejected fragments
  with their entry chains), `TC_REC_LOG` (recording begin/end reasons).
  `TC_ONLINE_STATS`, `TC_ONLINE_STATS_DETAILS` and `TC_ONLINE_EXEC_STATS` need
  no special build.
