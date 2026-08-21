
## Correction: the branch regression is in both stressor builds; the matrix cp rows do not reproduce (2026-08-21)

The previous entry's claim that the chain-start branch regression is
confined to the rootfs stressor is wrong. Same-session interleaved runs
on the compete protocol (musl build, boot-subtracted medians):

    build                       branch   regs
    prechain (10, no chainstart)  0.83   3.32
    chain-start at 10 slots       1.14   3.10
    tip (chain-start, 16 slots)   1.16   2.00
    lightning                     0.70   1.90

Chain-start owns the whole musl branch regression (+37% at fixed slot
count; the slot raise is neutral there), so branch is a real
competitive loss to lightning. The slot raise owns the whole musl regs
win, closing cp's worst row to within 5% of lightning.

The falsified claim came from trusting the matrix run's cp rows, which
do not reproduce: the same tip binary that measured branch 0.87 and
regs 3.32 inside the matrix run measures 1.16 and 2.00 in every
interleaved session since, while lightning's rows reproduce exactly
(0.72 then, 0.70 now). Same binary, deterministic guest, stable within
each process population, cp-specific. Untested hypothesis, for the next
session: per-process placement of the JIT heap relative to the library
text decides which exits fit direct branch range versus far-jump
islands, and the interleaved qemu runs bias the mmap layout; instrument
by logging heap and text bases per run and correlating with the mode.
Until that is understood, per-workload cp rows in the recorded matrix
carry that uncertainty; the geomean stands on the breadth of the other
rows. The branch fix itself (a cheap front-cache pre-check before the
full chain-start probe) is unchanged and remains the top lever, now
worth roughly +40% on branch in both stressor builds.

## Standing and next steps (2026-08-21, tip 2d81c4d8)

Where the backend stands after the slot raise, on the compete matrix:
geomean 1.46 against stock (lightning 1.62, rvvm 1.19, qemu-system
2.06, qemu-icount 2.23), ahead of lightning on 8 of 13 workloads. The
cp rows of the recorded matrix carry the reproducibility caveat from
the correction above; the cross-checked interleaved numbers are the
ones to trust for regs (2.00 vs lightning 1.90) and branch (1.16 vs
0.70). Remaining losses to lightning: branch, memcpy (3.66 vs 2.54),
double (1.82 vs 1.63), regs and syscall by a hair. Boards and machine
tests fully green at the tip; determinism gates unchanged throughout.

Next steps, ranked by measured headroom:

1. Chain-start probe cost. Chain-start entries regressed branch about
   +40% in both stressor builds (rootfs 1.24 -> 2.07 balanced, musl
   0.83 -> 1.14 compete) while buying the coverage the regs and qsort
   wins ride on. The probe pays its full head-map lookup on every
   chain start and branch-heavy code breaks chains constantly, mostly
   missing. Try a front-cache pre-check (one load and compare against
   the direct-mapped cache) before the full probe, or a per-head miss
   throttle. Gate on both branch variants recovering toward prechain
   with regs/qsort/sieve holding. Reference build for A/B at
   /tmp/cp-prechain (04d81ae5).

2. The cp performance bimodality. Same tip binary, deterministic
   formation (CP_STATS identical), yet process populations settle into
   modes 40-65% apart on musl regs/branch while lightning reproduces
   exactly. Hypothesis to test first: JIT-heap placement relative to
   the library text decides which exits fit direct branch range versus
   far-jump islands; qemu's memory pressure during the matrix biased
   mmap. Instrument with an env-gated line logging heap base and text
   base per run, correlate against the mode, then re-record the matrix
   once the mechanism is understood.

3. memcpy. 3.66 vs lightning 2.54. The probe-tax theory is falsified
   (memoization moved nothing); the measured lead is cross-page trace
   continuation, 29% of its formations end at a page crossing. This is
   increment-style work on the recorder (continue formation across the
   crossing through a validated link rather than finishing the trace).

4. Residuals, cheaper or conditional: double vs lightning wants the FP
   arithmetic stencil families; amd64's clang slot ceiling lifts from
   6 to 7 by branching far-jump/lookup through memory, worth doing at
   the next amd64 board; the hygiene increment (clang-tidy and format
   via the toolchain container, the reps/warmup protocol run) before
   any merge upstream; the parked memoization
   (cp/probe-memo-parked) is only worth revisiting with captures
   hoisted to the loop-carry preheader, and only after 1 and 2 change
   the profile again.
