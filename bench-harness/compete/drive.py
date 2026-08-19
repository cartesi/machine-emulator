#!/usr/bin/env python3
"""Cross-emulator benchmark driver.

Phases:
  calibrate  -- 5s per workload under qemu-user, records target ops in ops.json
  run        -- fixed-ops runs, 3 reps interleaved, under all emulators
  report     -- medians table

One binary (static musl stress-ng), one fixed-ops work definition per
workload, wall-clock timing. cartesi columns are full-system (boot baseline
subtracted); qemu/rv8 are user-mode. syscall excluded under rv8.
"""
import json, os, re, statistics, subprocess, sys, time
from verify_images import verify_images

COMP = os.path.dirname(os.path.abspath(__file__))
CAMP = os.path.join(os.path.dirname(COMP), "campaign")
CARTESI_LINUX = os.path.join(COMP, "images/cartesi/linux.bin")
SNG = os.path.join(COMP, "stress-ng/stress-ng")
RVJIT = os.path.join(COMP, "rv8/build/linux_x86_64/bin/rv-jit")
ROOTFS = os.path.join(COMP, "rootfs-bench.ext2")
ENV_RV8 = dict(os.environ, LD_LIBRARY_PATH=os.path.join(COMP, "rv8/build/linux_x86_64/lib"))

ARGS = {
    "sieve": "--cpu 1 --cpu-method sieve", "double": "--cpu 1 --cpu-method double",
    "int64": "--cpu 1 --cpu-method int64", "matrixprod": "--cpu 1 --cpu-method matrixprod",
    "nop": "--nop 1", "memcpy": "--memcpy 1", "hash": "--hash 1", "zlib": "--zlib 1",
    "regs": "--regs 1", "qsort": "--qsort 1", "branch": "--branch 1", "tree": "--tree 1",
    "syscall": "--syscall 1",
}
OPSFLAG = {w: ("--cpu-ops" if w in ("sieve", "double", "int64", "matrixprod")
               else f"--{w}-ops") for w in ARGS}
WORKLOADS = ["nop", "regs", "branch", "tree", "qsort", "memcpy", "zlib", "hash",
             "syscall", "double", "sieve", "int64", "matrixprod"]

def sng_args(wl, ops):
    return f"--no-rand-seed {ARGS[wl]} {OPSFLAG[wl]} {ops}"

def wall(cmd, env=None):
    t0 = time.monotonic()
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env)
    return time.monotonic() - t0, r

def calibrate():
    ops = {}
    for wl in WORKLOADS:
        cmd = f"qemu-riscv64 {SNG} --no-rand-seed {ARGS[wl]} --timeout 5 --metrics-brief"
        _, r = wall(cmd)
        m = re.search(r"metrc:.*?\]\s+\S+\s+(\d+)\s", r.stderr + r.stdout)
        assert m, f"{wl}: no metrics in output:\n{r.stderr}\n{r.stdout}"
        # target ~10s under qemu
        ops[wl] = max(1, int(m.group(1)) * 6 // 5)  # ~6s under qemu
        print(f"calibrated {wl}: ops={ops[wl]}", flush=True)
    json.dump(ops, open(os.path.join(COMP, "ops.json"), "w"), indent=1)

def run_cartesi(build, wl, ops, boot_baseline):
    so = os.path.join(CAMP, "builds", build)
    cmd = ("/usr/bin/stress-ng-musl " + sng_args(wl, ops)) if wl else "true"
    lua = os.path.join(COMP, "compete.lua")
    guest = cmd if wl else "true"
    env = dict(os.environ, LUA_CPATH=f"{so}/?.so;;")
    _, r = wall(f"lua5.4 {lua} {CARTESI_LINUX} {ROOTFS} '{guest}'", env=env)
    out = r.stdout.strip().splitlines()[-1].split()
    assert len(out) == 3 and int(out[2]) == 1, f"cartesi {build} {wl}: {r.stdout} {r.stderr}"  # 1 = halted
    return float(out[0]) - boot_baseline

def boot_baseline(build):
    so = os.path.join(CAMP, "builds", build)
    lua = os.path.join(COMP, "compete.lua")
    env = dict(os.environ, LUA_CPATH=f"{so}/?.so;;")
    _, r = wall(f"lua5.4 {lua} {CARTESI_LINUX} {ROOTFS} true", env=env)
    return float(r.stdout.strip().splitlines()[-1].split()[0])

def run(reps=3):
    ops = json.load(open(os.path.join(COMP, "ops.json")))
    results = []  # (emulator, wl, rep, seconds)
    boots = {b: statistics.median(boot_baseline(b) for _ in range(3))
             for b in ("args-jit-park", "stock")}
    print(f"boot baselines: {boots}", flush=True)
    for rep in range(1, reps + 1):
        for wl in WORKLOADS:
            o = ops[wl]
            t = run_cartesi("args-jit-park", wl, o, boots["args-jit-park"])
            results.append(("cartesi-jit", wl, rep, t)); print(f"cartesi-jit {wl} r{rep} {t:.2f}s", flush=True)
            t = run_cartesi("stock", wl, o, boots["stock"])
            results.append(("cartesi-stock", wl, rep, t)); print(f"cartesi-stock {wl} r{rep} {t:.2f}s", flush=True)
            t, r = wall(f"qemu-riscv64 {SNG} {sng_args(wl, o)}")
            assert r.returncode == 0, f"qemu {wl}: {r.stderr[-300:]}"
            results.append(("qemu-user", wl, rep, t)); print(f"qemu-user {wl} r{rep} {t:.2f}s", flush=True)
            if wl != "syscall":
                t, r = wall(f"{RVJIT} -- {SNG} {sng_args(wl, o)}", env=ENV_RV8)
                ok = r.returncode == 0
                results.append(("rv8", wl, rep, t if ok else None))
                print(f"rv8 {wl} r{rep} {'%.2fs' % t if ok else 'FAIL rc=' + str(r.returncode)}", flush=True)
        json.dump(results, open(os.path.join(COMP, "results.json"), "w"))
    report()

def report():
    results = json.load(open(os.path.join(COMP, "results.json")))
    med = {}
    for emu, wl, rep, t in results:
        if t is not None:
            med.setdefault((emu, wl), []).append(t)
    emus = ["cartesi-jit", "cartesi-stock", "qemu-system", "qemu-icount", "qemu-user", "rv8"]
    print(f"\n{'workload':<12}" + "".join(f"{e:>15}" for e in emus))
    for wl in WORKLOADS:
        row = f"{wl:<12}"
        for e in emus:
            v = med.get((e, wl))
            row += f"{statistics.median(v):>14.2f}s" if v else f"{'-':>15}"
        print(row)


# ---- qemu-system: our kernel + rootfs behind OpenSBI on the virt board ----
IMAGE_CTSI = os.path.join(COMP, "images/qemu/Image")
VIRT_DTB = os.path.join(COMP, "virt.dtb")

def qemu_sys_cmd(dtb):
    return (f"qemu-system-riscv64 -M virt -m 512M -smp 1 -display none "
            f"-serial file:{os.path.join(COMP, 'serial.log')} -snapshot "
            f"-drive file={os.path.join(COMP, 'rootfs-bench.ext2')},format=raw,if=none,id=d0 "
            f"-device virtio-blk-device,drive=d0 -kernel {IMAGE_CTSI} -dtb {dtb} -no-reboot")

def sys_dtb(entry):
    dtb = os.path.join(COMP, "run.dtb")
    subprocess.run(f"cp {VIRT_DTB} {dtb}", shell=True, check=True)
    subprocess.run(f"fdtput -c {dtb} /cartesi-machine", shell=True)
    subprocess.run(["fdtput", "-t", "s", dtb, "/chosen", "bootargs",
        "quiet earlycon=sbi console=hvc0 root=/dev/vda rw init=/usr/sbin/bench-init"], check=True)
    subprocess.run(["fdtput", "-t", "s", dtb, "/cartesi-machine", "entrypoint", entry], check=True)
    return dtb

def run_icount(reps=3):
    ops = json.load(open(os.path.join(COMP, "ops.json")))
    results = json.load(open(os.path.join(COMP, "results.json")))
    icount = " -icount shift=0,sleep=off"
    base = statistics.median(wall(qemu_sys_cmd(sys_dtb("true")) + icount)[0] for _ in range(3))
    print(f"qemu-icount boot baseline: {base:.2f}s", flush=True)
    for rep in range(1, reps + 1):
        for wl in WORKLOADS:
            entry = "/usr/bin/stress-ng-musl " + sng_args(wl, ops[wl])
            t, r = wall(qemu_sys_cmd(sys_dtb(entry)) + icount)
            ok = b"successful run" in open(os.path.join(COMP, "serial.log"), "rb").read()
            results.append(("qemu-icount", wl, rep, t - base if ok else None))
            print(f"qemu-icount {wl} r{rep} {'%.2fs' % (t - base) if ok else 'FAIL'}", flush=True)
        json.dump(results, open(os.path.join(COMP, "results.json"), "w"))
    report()

def run_sys(reps=3):
    ops = json.load(open(os.path.join(COMP, "ops.json")))
    results = json.load(open(os.path.join(COMP, "results.json")))
    base = statistics.median(wall(qemu_sys_cmd(sys_dtb("true")))[0] for _ in range(3))
    print(f"qemu-system boot baseline: {base:.2f}s", flush=True)
    for rep in range(1, reps + 1):
        for wl in WORKLOADS:
            entry = "/usr/bin/stress-ng-musl " + sng_args(wl, ops[wl])
            t, r = wall(qemu_sys_cmd(sys_dtb(entry)))
            ok = b"successful run" in open(os.path.join(COMP, "serial.log"), "rb").read()
            results.append(("qemu-system", wl, rep, t - base if ok else None))
            print(f"qemu-system {wl} r{rep} {'%.2fs' % (t - base) if ok else 'FAIL'}", flush=True)
        json.dump(results, open(os.path.join(COMP, "results.json"), "w"))
    report()

if __name__ == "__main__":
    verify_images()
    {"calibrate": calibrate, "run": run, "run_sys": run_sys, "run_icount": run_icount, "report": report}[sys.argv[1]]()
