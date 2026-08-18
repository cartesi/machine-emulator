"""Stage 2: focused paired run, sieve/int64/branch, current vs no-crossmap.

Pinned to one CPU, builds interleaved within each repetition with alternating
order, each build's own median boot baseline (>=7 samples) subtracted.
mcycle and exit reason are recorded per sample and must match across builds.
"""
import json, os, statistics, subprocess, sys, time

COMP = "/tmp/claude-0/-home-user-machine-emulator/df7f391d-37d7-5139-b76a-fda20c029be9/scratchpad/compete"
CAMP = "/tmp/claude-0/-home-user-machine-emulator/df7f391d-37d7-5139-b76a-fda20c029be9/scratchpad/campaign"
IMAGES = "/home/user/machine-emulator/tests/build/images"
ROOTFS = os.path.join(COMP, "rootfs-bench.ext2")
CPU = "2"                                   # SMT off; cpu0 avoided (interrupts)
BUILDS = {"current": "xmap-new-jit", "no-crossmap": "xmap-abl-no-crossmap"}
ARGS = {"sieve": "--cpu 1 --cpu-method sieve", "int64": "--cpu 1 --cpu-method int64",
        "branch": "--branch 1"}
OPSFLAG = {"sieve": "--cpu-ops", "int64": "--cpu-ops", "branch": "--branch-ops"}
ops = json.load(open(os.path.join(COMP, "ops.json")))

def run(build, entry):
    """One pinned boot. Returns (elapsed_cpu_s, mcycle, reason)."""
    env = dict(os.environ, LUA_CPATH=f"{CAMP}/builds/{BUILDS[build]}/?.so;;")
    r = subprocess.run(["taskset", "-c", CPU, "lua5.4", os.path.join(COMP, "compete.lua"),
                        IMAGES, ROOTFS, entry], capture_output=True, text=True, env=env)
    out = r.stdout.strip().splitlines()[-1].split()
    return float(out[0]), int(out[1]), int(out[2])

def workload_entry(wl):
    return f"/usr/bin/stress-ng-musl --no-rand-seed {ARGS[wl]} {OPSFLAG[wl]} {ops[wl]}"

# Warm both builds, then >=7 boot baselines each.
for b in BUILDS: run(b, "true")
base, base_raw = {}, {}
for b in BUILDS:
    s = [run(b, "true")[0] for _ in range(7)]
    base_raw[b] = s
    base[b] = statistics.median(s)
    print(f"baseline {b:<12} median {base[b]:.3f}s from {[round(x,3) for x in s]}", flush=True)

samples = []
for rep in range(1, 11):
    order = ["current", "no-crossmap"] if rep % 2 else ["no-crossmap", "current"]
    for wl in ("sieve", "int64", "branch"):
        for pos, b in enumerate(order):
            raw, mcyc, reason = run(b, workload_entry(wl))
            samples.append({"build": b, "workload": wl, "rep": rep, "order_pos": pos,
                            "order": "-".join(order), "raw_s": raw, "baseline_s": base[b],
                            "net_s": raw - base[b], "mcycle": mcyc, "reason": reason})
            print(f"rep{rep:<3}{wl:<8}{b:<12}pos{pos} raw={raw:7.3f} net={raw-base[b]:7.3f} "
                  f"mcycle={mcyc} reason={reason}", flush=True)
    json.dump({"baselines": base, "baseline_samples": base_raw, "cpu": CPU,
               "samples": samples}, open("/tmp/claude-0/xmap/results/stage2.json", "w"), indent=1)
print("STAGE2-DONE", flush=True)
