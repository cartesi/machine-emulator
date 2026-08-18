"""Isolated ablations: which of the three upstream changes moves which row.

Each variant is the post-merge tree with exactly ONE change reverted, so
(variant - baseline_build) isolates that change's contribution. All four
builds are interleaved within every workload/rep cell.
"""
import json, os, statistics, sys
sys.path.insert(0, '.')
from drive import run_cartesi, boot_baseline, WORKLOADS, COMP

BUILDS = ["new-jit", "abl-no-ctx256", "abl-no-fpcsr", "abl-no-crossmap"]
ops = json.load(open(os.path.join(COMP, "ops.json")))
for b in BUILDS: boot_baseline(b)                      # warmup
base = {b: statistics.median(boot_baseline(b) for _ in range(3)) for b in BUILDS}
for b in BUILDS: print(f"baseline {b:<16} {base[b]:.3f}s", flush=True)
res = []
for rep in (1, 2, 3):
    for wl in WORKLOADS:
        for b in BUILDS:
            t = run_cartesi(b, wl, ops[wl], base[b])
            res.append((b, wl, rep, t))
            print(f"{b} {wl} r{rep} {t:.2f}s", flush=True)
    json.dump(res, open(os.path.join(COMP, "results-ablate.json"), "w"))
print("ABLATE-RUN-DONE", flush=True)
