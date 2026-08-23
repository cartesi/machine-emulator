#!/usr/bin/env python3
"""Five-emulator matrix: cartesi stock/lightning/copy-patch, qemu-system,
qemu-icount, rvvm. Protocol of bench-harness/compete/matrix.py: one static
stress-ng, fixed bogo-ops from ops.json, per-emulator boot baseline
subtracted, 3 reps interleaved, medians. Also reports the boot row itself
(median boot-to-halt of the trivial entrypoint), the test the board does
not normally measure."""
import json, os, shutil, statistics, subprocess, sys, time

COMP = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, COMP)
import drive, rvvm
from drive import WORKLOADS, sng_args, wall, qemu_sys_cmd, sys_dtb

# Each cartesi column is a directory holding that build's cartesi.so,
# resolved from MATRIX_BUILDS (default: builds/ next to this script, with
# stock/, light/ and cp/ subdirectories). The RVVM binary resolves through
# rvvm.py's RVVM environment variable as for every other column.
BUILDS_ROOT = os.environ.get("MATRIX_BUILDS") or os.path.join(COMP, "builds")
BUILDS = {"cartesi-stock": os.path.join(BUILDS_ROOT, "stock"),
          "cartesi-light": os.path.join(BUILDS_ROOT, "light"),
          "cartesi-cp": os.path.join(BUILDS_ROOT, "cp")}
CARTESI_LINUX = os.path.join(COMP, "images/cartesi/linux.bin")
ROOTFS = os.path.join(COMP, "rootfs-bench.ext2")
ICOUNT = " -icount shift=0,sleep=off"
# The interpreter is resolved from PATH (override with LUA); the MacPorts
# path this used to hardcode does not exist on Linux hosts.
LUA = os.environ.get("LUA") or shutil.which("lua5.4") or "lua5.4"
# Default keeps the AArch64 board's filename; MATRIX_OUT redirects a run on
# another host, so it cannot overwrite a board it is not comparable to --
# these differ by host, not merely by build.
OUT = os.environ.get("MATRIX_OUT") or os.path.join(COMP, "results-matrix5.json")

def cartesi_run(so_dir, guest):
    lua = os.path.join(COMP, "compete.lua")
    env = dict(os.environ, LUA_CPATH=f"{so_dir}/?.so;;")
    t, r = wall(f"{LUA} {lua} {CARTESI_LINUX} {ROOTFS} '{guest}'", env=env)
    out = r.stdout.strip().splitlines()[-1].split()
    assert len(out) == 3 and int(out[2]) == 1, f"cartesi {so_dir}: {r.stdout} {r.stderr}"
    return float(out[0])

def qemu_run(entry, icount):
    t, _ = wall(qemu_sys_cmd(sys_dtb(entry)) + (ICOUNT if icount else ""))
    ok = b"successful run" in open(os.path.join(COMP, "serial.log"), "rb").read() \
        if entry != "true" else True
    return t if ok else None

def main(reps=3):
    ops = json.load(open(os.path.join(COMP, "ops.json")))
    results = []
    print("== warmup", flush=True)
    for name, d in BUILDS.items():
        cartesi_run(d, "true")
    qemu_run("true", False); qemu_run("true", True); rvvm.run_once("true")
    print("== boot baselines (median of 3)", flush=True)
    boots = {}
    for name, d in BUILDS.items():
        boots[name] = statistics.median(cartesi_run(d, "true") for _ in range(3))
    boots["qemu-system"] = statistics.median(qemu_run("true", False) for _ in range(3))
    boots["qemu-icount"] = statistics.median(qemu_run("true", True) for _ in range(3))
    boots["rvvm"] = rvvm.boot_baseline()
    for k, v in boots.items():
        results.append((k, "boot", 0, v))
        print(f"boot {k}: {v:.2f}s", flush=True)
    for rep in range(1, reps + 1):
        for wl in WORKLOADS:
            entry = "/usr/bin/stress-ng-musl " + sng_args(wl, ops[wl])
            for name, d in BUILDS.items():
                t = cartesi_run(d, entry) - boots[name]
                results.append((name, wl, rep, t))
                print(f"{name} {wl} r{rep} {t:.2f}s", flush=True)
            t = qemu_run(entry, False)
            results.append(("qemu-system", wl, rep, None if t is None else t - boots["qemu-system"]))
            print(f"qemu-system {wl} r{rep} {t and '%.2fs' % (t - boots['qemu-system'])}", flush=True)
            t = qemu_run(entry, True)
            results.append(("qemu-icount", wl, rep, None if t is None else t - boots["qemu-icount"]))
            print(f"qemu-icount {wl} r{rep} {t and '%.2fs' % (t - boots['qemu-icount'])}", flush=True)
            t = rvvm.run_once(entry)
            results.append(("rvvm", wl, rep, None if t is None else t - boots["rvvm"]))
            print(f"rvvm {wl} r{rep} {t and '%.2fs' % (t - boots['rvvm'])}", flush=True)
            json.dump(results, open(OUT, "w"))
    print("done", flush=True)

if __name__ == "__main__":
    main()
