import json, math, os, statistics, sys
COMP = os.path.dirname(os.path.abspath(__file__))
WLS = ["nop","regs","branch","tree","qsort","memcpy","zlib","hash","syscall",
       "double","sieve","int64","matrixprod"]
EMUS = ["cartesi-jit","cartesi-stock","qemu-system","qemu-icount","rvvm"]

d = json.load(open(os.path.join(COMP, "results-matrix.json")))
# The RVVM column was re-measured at 5 reps after a harness fix (sync before
# timing); prefer those samples where present.
rv5 = os.path.join(COMP, "results-rvvm5.json")
if os.path.exists(rv5):
    d = [r for r in d if r[0] != "rvvm"] + json.load(open(rv5))
med, miss = {}, []
for emu, wl, rep, t in d:
    if t is not None:
        med.setdefault((emu, wl), []).append(t)
for emu in EMUS:
    for wl in WLS:
        if (emu, wl) not in med:
            miss.append(f"{emu}/{wl}")
cell = {k: statistics.median(v) for k, v in med.items()}
nrep = {k: len(v) for k, v in med.items()}

print(f"{'workload':<11}" + "".join(f"{e.replace('cartesi-',''):>13}" for e in EMUS))
for wl in WLS:
    row = f"{wl:<11}"
    for emu in EMUS:
        row += f"{cell[(emu,wl)]:13.3f}" if (emu, wl) in cell else f"{'--':>13}"
    print(row)

def geo(emu):
    vals = [cell[(emu, wl)] for wl in WLS if (emu, wl) in cell and cell[(emu, wl)] > 0]
    return math.exp(sum(map(math.log, vals)) / len(vals)) if vals else float("nan")
g = {e: geo(e) for e in EMUS}
print(f"{'geomean':<11}" + "".join(f"{g[e]:13.3f}" for e in EMUS))
print(f"{'time / jit':<11}" + "".join(f"{g[e]/g['cartesi-jit']:13.3f}" for e in EMUS))
print()
print("reps per cell:", sorted(set(nrep.values())), "| incomplete cells:", miss or "none")
# negative or absurd samples are a protocol smell, not a result
bad = [(e,w,round(t,3)) for e,w,r,t in d if t is not None and t < 0]
if bad: print("NEGATIVE SAMPLES (baseline drift):", bad[:10])
