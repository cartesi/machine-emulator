# Hot side exits are permanently blacklisted by a single uncollectable instruction

Measured on AMD64, commit `1de75b65`, canonical benchmark images
(`verify_images.py` clean). All counters below come from instrumentation on the
experimental branch `claude/xmap-sieve`, enabled by `TC_EXIT_STATS=1`.

## Symptom

62% of all wall time across seven workloads is spent outside generated code.
For `zlib` and `qsort` the escapes are overwhelmingly guard (side) exits that
have no linked side trace:

| workload | escapes | trace-end | side (guard) | entry-cd | entry-ctx | call-miss | stay/escape |
| --- | --- | --- | --- | --- | --- | --- | --- |
| zlib | 140.5 M | 0.2% | **99.6%** | 0.2% | 0.0% | 0.0% | 0.02 |
| qsort | 47.1 M | 41.1% | **58.7%** | 0.2% | 0.0% | 0.0% | 0.01 |
| memcpy | 0.98 M | 12.4% | 87.0% | 0.1% | 0.0% | 0.6% | 0.94 |
| int64 | 65.8 M | **99.6%** | 0.1% | 0.3% | 0.0% | 0.0% | 0.00 |

`stay/escape` is the ratio of exits that reach another trace to exits that
return to the interpreter. On `zlib` only one exit in fifty stays in generated
code. `memcpy`, where linking works, has 140x fewer escapes.

Entry-side costs are negligible everywhere: countdown refusals 0.1-0.3%,
translation-context guard 0.0%, cross-mapping call validation <=0.6%.

## Causal chain (each step measured)

1. **A recording fails to compile.** `zlib` 39 times, `qsort` 26.
2. **That blacklists the head immediately.** The compile-abort path calls
   `tc_online_penalize(head, permanent = true)`, which jumps straight to
   `max_penalty` with no strikes. Per-site counts of penalty calls that
   blacklist: site 7 (root compile abort) **34/37** on `zlib`, **25/25** on
   `qsort`; site 2 (side compile abort) 3/3.
3. **Every side link to that pc is then refused.** `tc_online_begin_side`
   rejects blacklisted targets: **2104 of 2202 trips (95.5%)** on `zlib`,
   403/454 on `qsort`. No other refusal reason fires at all (`busy`,
   `already-linked`, `disabled`, `pool-full` are all zero).
4. **The refusal arms a permanent retry loop.** It sets
   `link->hotcount = UINT16_MAX`, so the exit re-trips after 65,535 more
   executions, is refused again, and repeats forever. Arithmetic confirms it:
   140 M executions / 65,535 = 2,136 predicted trips vs 2,202 measured.
5. **Result:** the hottest single side exit executes **112,355,249** times and
   never acquires a trace.

## Root cause: which instructions

Decoded from `TC_FP_DEBUG` on `zlib` (counts per run):

| encoding | n | decode | class |
| --- | --- | --- | --- |
| `c0102573` | 5 | `CSRRS csr=time` | refused |
| `10017973` | 4 | `CSRRCI csr=sstatus` | refused |
| `100024f3` | 2 | `CSRRS csr=sstatus` | refused |
| `0737a7af`, `00f7202f`, `00f5202f` | 6 | **`AMOADD.w`** | failed |
| `1207f7d3` | 2 | FP-OP | failed |

It is **not** register pressure and **not** a budget overflow. Budget failures
(nodes/exits) take the `!budget_abort` path and deliberately do not blacklist;
the 34 permanent blacklists at site 7 are all non-budget. Note `AMO_W` and
`AMO_D` are both declared collectable (`TC_LIGHTNING_CAN_COLLECT`), yet
`AMOADD.w` reports `failed`, so it enters the AMO collector and fails inside
it — that is a distinct defect worth isolating.

**The disproportion is the real problem.** One uncollectable instruction
anywhere in a recording permanently poisons that head, and if the head happens
to be the target of a hot guard exit, the cost is ~112 M interpreter escapes
for the rest of the run.

## Proposed solution

Two independent changes. Measure them separately; either may stand alone.

**A. Stop permanent blacklisting on compile abort (policy).** Treat an
uncollectable instruction like the budget case: strike rather than blacklist,
or blacklist only after `max_penalty` distinct failures. Rationale: the
penalty is keyed on the head pc, but the failure is caused by one instruction
possibly deep inside the recording — a shorter recording from the same head
may well compile. Cheapest variant: pass `permanent = false` at sites 2 and 7
and let the existing strike ladder run.

**B. Stage the missing opcodes (coverage).** In rough order of measured
frequency on `zlib`: `AMOADD.w` (6, and already advertised as collectable, so
likely a bug rather than a gap), `CSRRS csr=time` (5), `CSRRCI/CSRRS
csr=sstatus` (6). The sstatus accesses are the SUM toggles already familiar
from the context-TLB work.

A third, smaller item: when a side link is refused for a reason that can never
change (`blacklisted`), `UINT16_MAX` re-arming buys nothing but a retry every
65,535 exits. Either give up permanently or make the refusal recoverable — the
current behaviour is the worst of both.

## Verification

Success criterion: `tc-side: blacklisted` falls sharply and `stay/escape`
rises on `zlib`/`qsort`, with `escape` counts dropping proportionally. Gate on
identical final `mcycle` per workload (the harness already asserts halt reason
and mcycle), then re-run the paired protocol in `xmap/stage2.py`.

Reproduce the measurement with:

```sh
TC_EXIT_STATS=1 TC_ONLINE_STATS=1 taskset -c 2 lua5.4 compete.lua \
  images/cartesi/linux.bin rootfs-bench.ext2 \
  "/usr/bin/stress-ng-musl --no-rand-seed --zlib 1 --zlib-ops 41"
```

## Not established

- **AArch64.** Not measured; no such host available here. The mechanism is
  host-independent by inspection — all 19 `__x86_64__`/`__aarch64__`
  conditionals in `interpret-tc.cpp` are register-roster and ABI setup, none in
  the collector, `begin_side`, or the penalty code — and the `zlib` and `qsort`
  gaps against RVVM agree across hosts to within 1% (2.19x vs 2.21x, 2.07x vs
  2.10x). But it is a prediction. One `TC_EXIT_STATS=1` run on AArch64 settles
  it. Expect one difference: `fp_inline_supported` defaults **off** on AArch64,
  so the FP-OP failures should decline cleanly there rather than blacklist.
- **Why `AMOADD.w` fails** despite being declared collectable.
- **Whether either fix recovers the time.** No fix has been implemented or
  measured. The escape counts predict the opportunity; they do not prove it is
  realisable.
- **Nothing about RVVM's internals.** This documents where our time goes, not
  that RVVM's margin is reachable.
