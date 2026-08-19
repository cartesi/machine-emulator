"""Full board: cartesi jit/stock vs qemu-system, qemu-icount and RVVM.

Same protocol as tail-call.md items 19-22: one static musl stress-ng, fixed
bogo-ops from ops.json, each emulator's own boot baseline subtracted, three
reps interleaved per workload/rep cell, medians reported.
"""
import json, os, statistics, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drive, rvvm
from drive import COMP, WORKLOADS, sng_args, wall, run_cartesi, boot_baseline, qemu_sys_cmd, sys_dtb

JIT, STOCK = "new-jit", "new-stock"
ICOUNT = " -icount shift=0,sleep=off"
OUT = os.path.join(COMP, "results-matrix.json")


def qemu_run(wl, ops, icount, baseline):
    entry = "/usr/bin/stress-ng-musl " + sng_args(wl, ops)
    t, _ = wall(qemu_sys_cmd(sys_dtb(entry)) + (ICOUNT if icount else ""))
    ok = b"successful run" in open(os.path.join(COMP, "serial.log"), "rb").read()
    return t - baseline if ok else None


def qemu_base(icount):
    return statistics.median(wall(qemu_sys_cmd(sys_dtb("true")) + (ICOUNT if icount else ""))[0]
                             for _ in range(3))


def main(reps=3):
    drive.verify_images(require_rootfs=True)
    ops = json.load(open(os.path.join(COMP, "ops.json")))
    # Warm caches first: a cold first boot is a large outlier, and a skewed
    # baseline would corrupt every sample for that emulator.
    print("== warmup", flush=True)
    boot_baseline(JIT); boot_baseline(STOCK)
    qemu_base(False); qemu_base(True); rvvm.run_once("true")
    print("== boot baselines (median of 3, subtracted from every sample)", flush=True)
    base = {
        "cartesi-jit":   statistics.median(boot_baseline(JIT) for _ in range(3)),
        "cartesi-stock": statistics.median(boot_baseline(STOCK) for _ in range(3)),
        "qemu-system":   qemu_base(False),
        "qemu-icount":   qemu_base(True),
        "rvvm":          rvvm.boot_baseline(),
    }
    for k, v in base.items():
        print(f"   {k:<14} {v:.3f}s", flush=True)

    results = []
    for rep in range(1, reps + 1):
        for wl in WORKLOADS:
            o = ops[wl]
            cell = {
                "cartesi-jit":   lambda: run_cartesi(JIT, wl, o, base["cartesi-jit"]),
                "cartesi-stock": lambda: run_cartesi(STOCK, wl, o, base["cartesi-stock"]),
                "qemu-system":   lambda: qemu_run(wl, o, False, base["qemu-system"]),
                "qemu-icount":   lambda: qemu_run(wl, o, True, base["qemu-icount"]),
                "rvvm":          lambda: rvvm.run_workload(wl, o, base["rvvm"], sng_args),
            }
            for emu, fn in cell.items():          # interleaved within the cell
                try:
                    t = fn()
                except Exception as exc:
                    t = None
                    print(f"   {emu} {wl} r{rep} EXC {exc}", flush=True)
                results.append((emu, wl, rep, t))
                print(f"{emu} {wl} r{rep} {'%.2fs' % t if t is not None else 'FAIL'}", flush=True)
            json.dump(results, open(OUT, "w"))
    print("MATRIX-DONE", flush=True)


main(int(sys.argv[1]) if len(sys.argv) > 1 else 3)
