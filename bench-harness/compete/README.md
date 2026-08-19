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
| `images/cartesi/linux.bin` | Cartesi OpenSBI + Linux image consumed by `compete.lua`. |
| `images/qemu/Image` | Raw Linux image passed to QEMU's `-kernel` option. |
| `images/rvvm/linux.bin` | Upstream OpenSBI + Linux image consumed by RVVM. |
| `images/SHA256SUMS` | Fixed identities of all three committed platform artifacts. |
| `verify_images.py` | Verifies hashes and that every image contains the same kernel. |
| `guest/stress-ng-musl` | Exact static RISC-V benchmark executable used by every emulator. |
| `prepare-rootfs.sh` | Reproducibly assembles `rootfs-bench.ext2` from the test rootfs. |
| `linux.config` | Exact Linux configuration used to build the shared kernel. |

`drive.py` resolves all kernel paths relative to its own location. In
particular, it never falls back to `tests/build/images` or another host-local
`linux.bin`. It expects the working tree described under *Layout* below, with
the campaign build directory as a sibling.

These are guest-platform artifacts, not host-platform artifacts. AMD64 and
AArch64 hosts must use these same three files and hashes. The emulator selects
the Cartesi, QEMU or RVVM envelope; the host architecture selects none of them.

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
  -kernel images/qemu/Image -dtb run.dtb -no-reboot
```

The `qemu-icount` column is the identical line plus `-icount shift=0,sleep=off`.
QEMU 8.2, OpenSBI as shipped (the `virt` board's default firmware).

Notes that cost time to discover:

- **`-kernel images/qemu/Image`, not either `linux.bin`.** The `linux.bin`
  files include an M-mode OpenSBI firmware selected for their emulator.
  Booting one as an S-mode kernel traps with `scause=2` (illegal instruction).
  QEMU supplies its own OpenSBI, so it receives the committed raw kernel.
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

`rootfs-bench.ext2` is generated, not committed. Run:

```sh
./prepare-rootfs.sh
```

The script uses the repository's `make -C tests images` target. That target
downloads `machine-guest-tools` `v0.18.0-test8` and verifies the base image
against the SHA-256 in `dependencies.lock`:

```text
base rootfs.ext2       a240082c3b5988f40e6ab0677bf362a057a13431ac6f2c409568bcc87510b243
guest/stress-ng-musl   26caa5259058a82388e537d18d6ac8afee8e0bbb56ddcfd2a13e79e05e508608
bench-init             694eaef1b15466e29328405c75fb72f6408d75c1df6e58e8c85e15c7135a40be
rootfs-bench.ext2      3f6ad0dba2a74d62792794b411dd0791fae194fdf639512b7c9feddb1829eee9
```

The assembly restores the injected files' exact measured ownership, mode and
ext2 timestamps, plus the measured superblock write time. The result is
byte-identical to the filesystem used for the recorded benchmark, not merely
content-equivalent. Its final hash is checked before it replaces the output.
`drive.py` and `matrix.py` refuse to run if that generated image is absent or
has a different hash.

The committed stress-ng binary is the exact payload extracted from the image
used for the recorded measurements. Its build provenance is stress-ng
`V0.17.06` commit `e6bda983cb48a201b6af173204372c7b37d6411f`, musl
`v1.2.5` commit `0784374d561435f7c787a555aeab8ede699ed298`, and zlib
`v1.3.1` commit `51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf`. It is static,
so rebuilding those inputs is not required to reproduce the benchmark. The
same committed executable is injected into every full-system guest and run
directly by qemu-user and rv8.

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
timings. `rvvm.py` selects RVVM's documented host-specific build directory for
macOS/AArch64 and Linux/x86-64. Set the `RVVM` environment variable to an exact
executable path for a different layout or host.

### Boot image provenance

The three committed artifacts use one byte-identical Linux kernel. The Cartesi
and RVVM files place their platform's firmware before it; QEMU supplies its own
firmware and receives the raw kernel directly:

```text
images/cartesi/linux.bin  Cartesi OpenSBI at 0, Linux Image at 0x200000
images/qemu/Image         raw Linux Image
images/rvvm/linux.bin     upstream OpenSBI at 0, zero padding, Linux Image at 0x200000
```

The components and resulting artifact are fixed by these identities:

```text
OpenSBI v1.3.1
  commit 057eb10b6d523540012e6947d5c9f63e95244e94
  fw_jump.bin sha256 920fa1bcd5d4b623496abe70a62b6f473f55d7c05cb538062ee507208d138e8f
Cartesi OpenSBI v1.3.1-ctsi-2
  commit 5612514832be90d2df920eb1fe89a18c57bacbf5
  source tar sha256 35082380131117aa8424d1b81ca9e6e0280baa9bffbcf3f46080a652e4cb4385
Linux cartesi/linux v6.5.13-ctsi-2-uio-test1
  source tar sha256 ca2142b0fd3fce1cb80b661080a09f288d62bdc61a0b5e3ece44246bc8d6b16c
  Image sha256 c570a15a4cd484088e72f8f28bf74e404888904ed00768433a68b33f10c8c4c0
  config sha256 26b71073edfa022c727f05d6557e14aaaa8bacba9d305d638cec466af82cb919
images/cartesi/linux.bin
  size 17545256 bytes
  sha256 551ed4dae2b82ed59b4055f18d525a77f5ee35605acbf1238ff83e0cf9bfc3f1
images/qemu/Image
  size 15448096 bytes
  sha256 c570a15a4cd484088e72f8f28bf74e404888904ed00768433a68b33f10c8c4c0
images/rvvm/linux.bin
  size 17545248 bytes
  sha256 c2370b05b683d511851279c5c3f637873a334898597db283c11a2da413bffa13
```

The RVVM image was packed without changing either component:

```sh
cp fw_jump.bin images/rvvm/linux.bin
truncate -s 2097152 images/rvvm/linux.bin
dd if=images/qemu/Image of=images/rvvm/linux.bin bs=1048576 seek=2 conv=notrunc
```

The kernel configuration adds the generic PCI host, NVMe block device and
8250 UART support needed by RVVM. The exact configuration is committed as
`linux.config`; rebuilding the kernel is unnecessary for the benchmark.
Upstream OpenSBI is required because the Cartesi OpenSBI port uses the
emulator's custom single-hart HTIF conventions and is not an RVVM firmware.
The Cartesi image is the corresponding `fw_payload.bin` built with
`PLATFORM=cartesi` from cartesi/opensbi tag `v1.3.1-ctsi-2`. The shared Linux
source is cartesi/linux tag `v6.5.13-ctsi-2-uio-test1`; `linux.config` records
the benchmark configuration. Run `python3 verify_images.py` before measuring:
it checks every full artifact and compares the exact embedded kernel spans,
not an open-ended suffix (the Cartesi bundle has eight trailing padding bytes).
`drive.py` and `matrix.py` run the same verification automatically before a
benchmark phase.

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
$RVVM images/rvvm/linux.bin -i rvvm-rootfs.ext2 -m 512M -smp 1 -nogui -nonet -nosound \
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
$RVVM images/rvvm/linux.bin -i rvvm-rootfs.ext2 -m 512M -smp 1 -nogui -nonet -nosound \
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
<scratchpad>/compete/{virt.dtb,rootfs-bench.ext2}
<scratchpad>/compete/images/{cartesi/linux.bin,qemu/Image,rvvm/linux.bin}
<scratchpad>/compete/{guest/stress-ng-musl,rv8/}
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
