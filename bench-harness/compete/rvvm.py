"""RVVM full-system column, per bench-harness/compete/README.md.

Same rootfs, same bench-init, same ops.json as every other full-system column.
RVVM has no -snapshot, so each boot gets a fresh copy of the drive image.
"""
import os, platform, shutil, statistics, subprocess, sys, time

COMP = os.path.dirname(os.path.abspath(__file__))


def default_rvvm():
    os_name = {"darwin": "darwin", "linux": "linux"}.get(sys.platform)
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x86_64"}.get(platform.machine().lower())
    assert os_name and arch, "set RVVM to the RVVM executable for this host"
    return os.path.join(COMP, f"RVVM/release.{os_name}.{arch}/rvvm_{arch}")


RVVM = os.environ.get("RVVM") or default_rvvm()
# The RVVM firmware image (upstream OpenSBI + Linux), committed next to this
# script in the repo; resolved relative to the harness so the column runs
# wherever the harness is checked out.
LINBIN = os.path.join(COMP, "images/rvvm/linux.bin")
ROOTFS_SRC = os.path.join(COMP, "rootfs-bench.ext2")
BOOTARGS = ("quiet earlycon=uart8250,mmio,0x10000000 console=ttyS0 "
            "root=/dev/nvme0n1 rw init=/usr/sbin/bench-init")


def base_dtb():
    """Dump RVVM's base DTB once; also proves the image reaches Linux."""
    dtb = os.path.join(COMP, "rvvm-base.dtb")
    if not os.path.exists(dtb):
        drive = os.path.join(COMP, "rvvm-rootfs.ext2")
        shutil.copyfile(ROOTFS_SRC, drive)
        subprocess.run([RVVM, LINBIN, "-i", drive, "-m", "512M", "-smp", "1",
                        "-nogui", "-nonet", "-nosound", "-cmdline", BOOTARGS,
                        "-dumpdtb", dtb], capture_output=True, timeout=300)
    return dtb


def run_dtb(entry):
    """Inject the entrypoint through the same DTB node the other guests read."""
    dtb = os.path.join(COMP, "rvvm-run.dtb")
    shutil.copyfile(base_dtb(), dtb)
    subprocess.run(["fdtput", "-c", dtb, "/cartesi-machine"], capture_output=True)
    subprocess.run(["fdtput", "-t", "s", dtb, "/chosen", "bootargs", BOOTARGS], check=True)
    subprocess.run(["fdtput", "-t", "s", dtb, "/cartesi-machine", "entrypoint", entry], check=True)
    return dtb


def run_once(entry):
    """One timed RVVM boot. Returns seconds, or None if the run did not complete."""
    dtb = run_dtb(entry)
    drive = os.path.join(COMP, "rvvm-rootfs.ext2")
    shutil.copyfile(ROOTFS_SRC, drive)          # never benchmark the shared image
    # Flush the copy before timing: leaving ~350 MB of dirty pages to write
    # back during the run intermittently stalled RVVM by 40x (observed on
    # int64 and memcpy) and is a property of the harness, not the emulator.
    subprocess.run(["sync"], check=True)
    t0 = time.monotonic()
    r = subprocess.run([RVVM, LINBIN, "-i", drive, "-m", "512M", "-smp", "1",
                        "-nogui", "-nonet", "-nosound", "-dtb", dtb],
                       capture_output=True, timeout=1800)
    t = time.monotonic() - t0
    if entry == "true":
        return t if r.returncode == 0 else None
    out = r.stdout + r.stderr
    ok = r.returncode == 0 and b"successful run completed" in out
    return t if ok else None


def boot_baseline(reps=3):
    samples = [run_once("true") for _ in range(reps)]
    samples = [s for s in samples if s is not None]
    assert samples, "rvvm boot baseline failed"
    return statistics.median(samples)


def run_workload(wl, ops, baseline, sng_args):
    entry = "/usr/bin/stress-ng-musl " + sng_args(wl, ops)
    t = run_once(entry)
    return None if t is None else t - baseline
