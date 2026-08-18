"""Stage 3: TC_ONLINE_STATS / TC_ONLINE_EXEC_STATS diagnostic series.

Counter-perturbed runs; elapsed times here are NOT mixed into stage 2's result.
3 runs per (build, workload) plus boot-only, full stdout+stderr saved.
"""
import json, os, re, statistics, subprocess

COMP = "/tmp/claude-0/-home-user-machine-emulator/df7f391d-37d7-5139-b76a-fda20c029be9/scratchpad/compete"
CAMP = "/tmp/claude-0/-home-user-machine-emulator/df7f391d-37d7-5139-b76a-fda20c029be9/scratchpad/campaign"
IMAGES = "/home/user/machine-emulator/tests/build/images"
ROOTFS = os.path.join(COMP, "rootfs-bench.ext2")
RAW = "/tmp/claude-0/xmap/results/raw_stats"; os.makedirs(RAW, exist_ok=True)
CPU = "2"
BUILDS = {"current": "xmap-new-jit", "no-crossmap": "xmap-abl-no-crossmap"}
ARGS = {"sieve": "--cpu 1 --cpu-method sieve", "int64": "--cpu 1 --cpu-method int64",
        "branch": "--branch 1"}
OPSFLAG = {"sieve": "--cpu-ops", "int64": "--cpu-ops", "branch": "--branch-ops"}
ops = json.load(open(os.path.join(COMP, "ops.json")))

FIELDS = [("installed", r"installed (\d+)"), ("aborted", r"aborted (\d+)"),
          ("short_aborted", r"\(short (\d+)"), ("compile_aborted", r"compile (\d+)"),
          ("invalidated", r"invalidated (\d+)"), ("flushes", r"flushes (\d+)"),
          ("links", r"links (\d+)"), ("register_links", r"register-links (\d+)"),
          ("episodes", r"episodes (\d+)"), ("trace_insns", r"trace-insns (\d+)"),
          ("compile_ms", r"compile-ms (\d+)"), ("trace_ms", r"trace-ms (\d+)"),
          ("ctx_entry_bails", r"ctx-entry-bails (\d+)")]

def run(build, wl, rep):
    entry = "true" if wl == "boot" else \
            f"/usr/bin/stress-ng-musl --no-rand-seed {ARGS[wl]} {OPSFLAG[wl]} {ops[wl]}"
    env = dict(os.environ, LUA_CPATH=f"{CAMP}/builds/{BUILDS[build]}/?.so;;",
               TC_ONLINE_STATS="1", TC_ONLINE_EXEC_STATS="1")
    r = subprocess.run(["taskset", "-c", CPU, "lua5.4", os.path.join(COMP, "compete.lua"),
                        IMAGES, ROOTFS, entry], capture_output=True, text=True, env=env)
    blob = r.stdout + r.stderr
    open(f"{RAW}/{build}.{wl}.r{rep}.log", "w").write(blob)
    rec = {"build": build, "workload": wl, "rep": rep}
    last = r.stdout.strip().splitlines()[-1].split()
    rec["elapsed_s"], rec["mcycle"], rec["reason"] = float(last[0]), int(last[1]), int(last[2])
    for name, pat in FIELDS:
        m = re.search(pat, blob)
        rec[name] = int(m.group(1)) if m else None
    return rec

recs = []
for build in BUILDS:
    for wl in ("boot", "sieve", "int64", "branch"):
        for rep in (1, 2, 3):
            rec = run(build, wl, rep)
            recs.append(rec)
            print(f"{build:<12}{wl:<8}r{rep} mcycle={rec['mcycle']:>12} "
                  f"episodes={rec['episodes']} trace_insns={rec['trace_insns']} "
                  f"installed={rec['installed']}", flush=True)
json.dump(recs, open("/tmp/claude-0/xmap/results/stage3.json", "w"), indent=1)
print("STAGE3-DONE", flush=True)
