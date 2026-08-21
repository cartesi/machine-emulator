
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
