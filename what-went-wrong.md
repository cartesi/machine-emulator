# What went wrong with the online trace JIT

## Outcome

The transactional trace collector and side-exit linker added substantial policy,
lifetime, and code-generation complexity, but produced only a small aggregate
speedup over the already-linked online Lightning implementation.

The clean exploratory single-run comparison was:

| Workload | Linked checkpoint | Transactional side traces |
| --- | ---: | ---: |
| sieve | 7.17 s | 6.43 s |
| qsort | 25.21 s | 24.17 s |
| zlib | 25.63 s | 25.35 s |
| hash | 13.74 s | 13.93 s |
| double | 47.98 s | 48.05 s |
| syscall | 22.98 s | 23.18 s |
| total | 142.71 s | 141.11 s |

This is about a 1.1% aggregate improvement. Sieve and qsort improved, but the
other results are effectively flat at the precision of one run. All established
guest cycle counts and final hashes remained exact.

An earlier run reported extreme regressions in double and zlib. Those timings
were invalid: an abandoned sieve diagnostic was still consuming host CPU. The
table above comes from the repeated clean run after that process was removed.

## Why the payoff was small

We solved a trace-coverage problem that was not the main performance bottleneck.

The portable tail-call interpreter is already efficient. It keeps the PC,
countdown, fetch mapping, and interpreter context in fixed host registers, and
uses tail calls for instruction dispatch. Consequently, removing dispatch has a
lower ceiling than it would in a conventional switch interpreter.

Generated traces still pay significant boundary costs:

- guest registers are materialized at exits and loaded again at the next trace
  entry;
- conditional instructions require guards and side-exit state reconstruction;
- a linked edge still loads an indirect target;
- a cross-page edge also performs the inline code-TLB hit check;
- short traces amortize these costs over very few guest instructions;
- memory operations retain their address-translation and access costs; and
- unsupported operations, notably floating-point operations, return to the
  interpreter.

Transactional recording made paths cross code pages coherently. Side traces
made alternative branch paths compilable and linkable. Neither change made the
execution of an individual linked edge much cheaper. They mostly increased the
number of paths to which the existing boundary costs apply.

## Later profiling: qsort was not running the generated traces

Time profiling corrected the original diagnosis for qsort. In matched
20-second, 1 ms sampling runs, generated code accounted for only 1.14% of the
pre-register-linking run and 1.21% of the register-linking run. The profiles
were otherwise effectively identical. Portable memory handlers accounted for
about 36.5% of samples, portable control-flow handlers for about 25%, and data
translation and miss helpers for only 1.5--1.9%.

Almost all generated-code samples came from one five-instruction byte-copy
loop at `0x7fff9def31f0`: 204 of 208 generated-code samples in the
register-linking profile. The 27-instruction cyclic qsort trace at
`0x55558b9b6eee` received only one sample. The software data-TLB hit checks are
visible costs inside the byte-copy trace, but generated code is too small a
fraction of the complete run for them to explain qsort's aggregate result.

A subsequent in-page direct-call experiment did not improve qsort. Three paired
runs had medians of 24.33 s before the change and 24.34 s after it. A new
20-second profile attributed about 0.94% of 12,322 samples to generated code;
almost all of those samples were still in the byte-copy trace. These results
invalidate the earlier claim that merely using the function returned by the
call-target lookup would expose the comparator traces.

Counters then measured trace reachability directly. The generated traces were
entered 40,506,086 times, but the byte-copy trace alone accounted for
40,322,631 entries (99.55%). Two short comparator functions were called at the
following measured rates:

- `0x55558ba524b0`: 216,161,906 calls;
- `0x55558ba524e2`: 146,276,352 calls.

Those totals closely reproduce the earlier AOT capture counts of 216,161,664
and 146,276,180. Each comparator had zero generated-code entries and neither
was ever found as an exact installed call head. The qsort predecessor side
fragments at `0x7fff9deac90c` and `0x7fff9deac866` likewise had zero
generated-code entries.

Compile logs initially made this look like only an exact-map publication bug:
both comparator heads appeared in successful Lightning compilation messages.
Publishing the first side fragment in the generic exact map disproved that
explanation. A qsort run remained correct and unchanged at 24.42 s, but both
comparator heads still had zero exact hits. The comparator code had been
generated provisionally and then destroyed when a later fragment in the same
transaction failed; repeated reuse of the same Lightning buffer made that
lifecycle visible. The fragments were compiled, but never installed.

Additional counters classified installed call and return heads. Before the
comparator heads were recoverable, qsort measured 69,312 installed call-head hits:
13,317 in the current fetch page, 53,854 code-TLB hits, and 53,854 exact recorded
host mappings. Installed return heads had 1,668 hits: none in-page and all 1,668
with an exact code-TLB mapping. This supported measuring a validated cross-page
entry, but did not yet establish that the comparator calls would hit it.

## Return-bounded call-target traces recovered qsort

The collector now identifies an indirect return through the separate Lightning
execution object held by the collecting state-access adapter. A recording that
was explicitly started at a hot call target may therefore publish the function
body without depending on later caller fragments. There is no opcode switch or
supervisor-side test for a particular return instruction.

Two rejected variants established the safe boundary:

- Truncating every recording at a compiled indirect return was incorrect during
  boot: the guest exited with status 255 after 23,852,087 cycles.
- Restricting the rule to call-target recordings but compiling through the
  indirect return was also incorrect: the guest exited with status 255 after
  70,652,976 cycles.

The accepted variant ends the generated trace immediately before the indirect
return and lets the portable handler execute that final dynamic transfer. With
call dispatch disabled for an isolation run, it completed qsort correctly and
made the two comparator traces visible. Their measured exact-head and mapping
counts were:

| Comparator | Exact call-head hits | Exact recorded mappings | Same-page hits |
| --- | ---: | ---: | ---: |
| `0x55558ba524b0` | 216,160,743 | 216,153,929 | 0 |
| `0x55558ba524e2` | 146,276,132 | 146,270,049 | 0 |

This measurement justified enabling the cross-page call entry. The generated
entry checks the hot code-TLB page and recorded host offset, updates the fast PC,
fetch tag, fetch offset, and PMA index on a match, and branches to the normal
trace entry. A miss or remap resumes through the ordinary fetch continuation.
Live AArch64 disassembly confirmed that sequence. The comparator body then ends
at its portable return instruction rather than executing the indirect return in
generated code.

An instrumented correctness run entered the generated comparator bodies
215,756,677 and 146,000,591 times. After removing those counters and compilation
logging, three interleaved paired qsort runs measured:

| Version | Run 1 | Run 2 | Run 3 | Median |
| --- | ---: | ---: | ---: | ---: |
| register-linking checkpoint | 23.87 s | 24.41 s | 24.92 s | 24.41 s |
| return-bounded call traces | 18.97 s | 19.68 s | 18.95 s | 18.97 s |

The median wall time fell by 22.3%, equivalent to 1.29 times the throughput.
All six runs executed exactly 16,528,861,707 guest cycles and exited with status
zero. The complete machine suite also passed all 267 tests.

A full-run 1 ms sampling profile collected 16,610 main-thread samples. At least
2,994 samples (18.0%) had their top frame in generated memory; the report omits
unknown sites with fewer than five samples, so this is a lower bound. The two
comparator code regions accounted for most of those generated samples. This is
the missing dynamic coverage that the previous profile, with about 0.94% in
generated code, did not have.

These measurements supersede the earlier unmeasured explanations that side-map
publication alone was sufficient or that transaction rollback was merely a
secondary possibility. Rollback of a hot call-target recording was the measured
installation failure; validated cross-page entry was then necessary because
both comparator targets had zero same-page hits.

## Cross-workload result of return-bounded call traces

Five non-qsort workloads were measured in three interleaved repetitions against
the saved register-linking checkpoint. The medians were:

| Workload | Register-linking checkpoint | Return-bounded call traces | Change |
| --- | ---: | ---: | ---: |
| sieve | 6.46 s | 6.42 s | -0.6% |
| zlib | 25.85 s | 25.95 s | +0.4% |
| hash | 13.98 s | 13.93 s | -0.4% |
| double | 48.03 s | 47.75 s | -0.6% |
| syscall | 22.99 s | 27.95 s | **+21.6%** |

Sieve, zlib, hash, and double were effectively unchanged at this measurement
precision. Syscall showed a large, repeatable regression: the checkpoint ran in
23.06, 22.95, and 22.99 seconds, while return-bounded call traces ran in 27.95,
28.19, and 26.85 seconds. All 30 executions exited with status zero, and both
versions executed exactly the same guest cycles for every workload. Final
hashes were stable within each build; hashes between builds are not directly
comparable because rebuilding `uarch.bin` incorporates changed source-location
metadata.

This result rules out treating the new call-target entry mechanism as uniformly
neutral outside qsort.

### Syscall regression: call-target collection displaced its useful loop

Matched 1 ms sampling profiles showed that the regression was not time spent in
the generated call-entry adapter. The register-linking checkpoint had 273 of
13,706 main-thread top-frame samples (1.99%) in generated memory. Return-bounded
call traces had only 2 of 15,780 (0.013%). Portable handlers expanded in the
missing trace's place: for example, `C_BNEZ` rose from 30 to 489 samples, `LBU`
from 10 to 416, and `C_ADD` from 200 to 430.

Address-correlated compilation logs identified the useful generated region as
a nine-instruction cyclic trace headed at guest PC `0x55558ba8383e`. It supplied
essentially all the generated-code samples in the checkpoint. With
return-bounded call-target collection enabled, that head was never compiled.
A nearby 15-instruction cycle at `0x55558ba838e4` was compiled instead but did
not appear among sampled generated top frames.

Recorder capacity and a general backend failure were ruled out. The checkpoint
installed 159 traces with no flush, while the new version installed 168 with no
flush; both reported 221 compile failures. The change affected which hot trace
won collection, not whether the trace pool or compiler remained operational.

A causal ablation retained the mapping-validating `call_fn` dispatch but did
not let an uncompiled call target start a recording. This was the only source
change. Three syscall runs took 22.87, 22.93, and 23.06 seconds (22.93-second
median), recovering the checkpoint's 22.99-second median from the new version's
27.95 seconds. All runs executed exactly 16,815,982,316 guest cycles and had the
same final hash and zero exit status. A profile of the ablation restored 276 of
14,493 samples (1.90%) to generated memory, and compilation logs restored the
`0x55558ba8383e` trace.

Therefore the 21.6% regression is a trace-selection failure caused by adding
call targets to the same 64-counter bank used for loop heads. Direct counters
resolved the remaining ambiguity. Under the regressing policy, the loop hook at
`0x55558ba8383e` ran 244,325,627 times and its counter tripped 238,602 times;
none of those trips occurred while the recorder was active. Recorder occupancy
was not the failure. The same counter slot received 43,375 hooks from other
heads, including 17,962 call hooks, and was reset seven times by call heads.

Those call updates changed the loop counter's phase. Each of the loop head's
three probation recordings started on the loop's exit iteration and followed
calls through four code pages. The resulting page fragments had lengths 11, 3,
9, and 15. The three-instruction fragment violated the four-instruction minimum,
so the transaction was rejected. The same path repeated three times and the
head was blacklisted. Later counter trips therefore could not request another
recording.

A second causal test retained both call-target and loop recording but gave them
separate 64-entry counter banks. Call collection remained active, including
17,247 call hooks whose numeric index collided with this loop's index. The loop
then tripped after 1,020 hooks on its taken path, recorded the expected
nine-instruction single-page cycle, and published it. The instrumented syscall
run fell from 27.57 to 23.84 seconds and remained exact. Thus shared-counter
phase interference—not the single recorder, code generation, or call-entry
adapter—is the measured cause. Call and loop hotness must not share a counter
bank.

### Implemented loop-only clock and six-workload result

The retained implementation uses a loop-only 64-counter bank to decide loop
recordings. The original mixed bank is still updated by both event classes and
decides call recordings, preserving the established call-policy clock while
preventing calls from shifting a loop's sampling phase.

Changing the loop phase exposed a pre-existing cross-page linking correctness
failure during Linux boot. Qsort initially halted after 10,710,074 cycles with
a kernel null-instruction-page panic, before the workload started. A trace-count
bisection was exact: caps of 15, 23, and 27 installed fragments completed qsort
at the expected 16,528,861,707 cycles, while caps of 28 and 29 panicked. The
first failing transaction had three fragments:
`0xffffffff80401ef8 -> 0xffffffff80140d28 -> 0xffffffff8040a9c0`.

Publishing the fragments while withholding cross-page links completed
correctly. Withholding only the first edge also completed correctly. Its
predecessor ends in `c.jr ra`, a guarded indirect return from
`0xffffffff80401f0c` to `0xffffffff80140d28`. Replacing the inline code-TLB
transition with the successor's generated mapping-validating entry still
panicked. These experiments established a safe temporary workaround—do not
directly link a cross-page successor after an indirect return—but did not prove
that the return itself was invalid. Suppressing the upstream edge also made the
rest of the transaction unreachable.

The temporary workaround was then measured against the saved return-bounded
call-body build in three interleaved repetitions:

| Workload | Call-body baseline | Loop-only clock | Change |
| --- | ---: | ---: | ---: |
| sieve | 6.46 s | 5.29 s | **-18.1%** |
| qsort | 19.04 s | 23.58 s | **+23.8%** |
| zlib | 25.56 s | 25.79 s | +0.9% |
| hash | 13.90 s | 13.42 s | -3.5% |
| double | 47.78 s | 47.80 s | +0.0% |
| syscall | 28.02 s | 23.12 s | **-17.5%** |

All 36 measured runs exited with status zero. Each workload had identical guest
cycle counts and final hashes in both builds. There were two host-time outliers:
the first call-body double run took 331.33 seconds and the first loop-only hash
run took 41.77 seconds; the other double runs were 47.45--47.88 seconds and the
other hash runs were 13.27--13.92 seconds. The table uses the three-run median,
which is unaffected by either single outlier.

The loop-only clock recovered syscall as predicted and also improved sieve, but
the temporary return restriction removed part of qsort's cross-page chaining
benefit. This was not a reason to treat cross-page returns as semantically
invalid; the generated successor needed to be inspected.

### Actual failure: staged JALR source/destination aliasing

A complete instruction dump of all three fragments located the defect after
the return. The first fragment returns correctly to `0xffffffff80140d28`. The
second fragment ends with:

```text
auipc ra, 714
jalr  -890(ra)
```

The JALR has `rd == rs1 == ra`. Architecturally, its target must be computed
from the old `ra`, then its link address is written to `ra`. The staged path
held the target as a lazy expression, wrote the link address first, and only
then asked the execution object to emit the indirect-target guard. The guard
therefore read the new `ra`. On failure, its side exit resumed at the JALR with
the old target base already overwritten, producing the invalid jump that led
to the kernel null-PC panic.

This also explains why withholding the preceding cross-page return appeared to
fix the problem: it merely prevented the malformed successor trace from being
entered. The return and its code-page transition were correct.

An alternative hypothesis—that one-instruction recording had crossed an
outer-loop interrupt boundary—was tested directly. Recordings are now cancelled
without penalty on interrupt entry, exception-serving status, and instruction
fetch exceptions. This cancellation fired on a different boot recording, but
the same three-fragment transaction was still published and still panicked.
Thus asynchronous-boundary cancellation is a valid independent correctness
guard, but it was not the cause of this failure.

The JALR and C.JALR staged paths now emit/materialize the indirect target before
writing the link register. Cross-page returns and cross-page register-preserving
links were re-enabled. The previously failing qsort boot then completed at the
exact expected 16,528,861,707 cycles.

Three fresh interleaved repetitions compared the return-blocking workaround
with the corrected JALR ordering:

| Workload | Return workaround | Correct JALR order | Change |
| --- | ---: | ---: | ---: |
| sieve | 5.27 s | 5.32 s | +0.9% |
| qsort | 24.12 s | 23.03 s | **-4.5%** |
| zlib | 26.27 s | 25.65 s | -2.4% |
| hash | 13.31 s | 13.32 s | +0.1% |
| double | 47.80 s | 48.18 s | +0.8% |
| syscall | 23.07 s | 23.30 s | +1.0% |

All 36 runs exited with status zero and used identical guest cycle counts for
each workload. Final hashes differ between the two builds because changing
`interpret.cpp` required rebuilding the embedded uarch image; hashes were
stable within each build. The corrected ordering recovers 4.5% on qsort and
2.4% on zlib relative to the workaround. The remaining difference from the
19.04-second call-body qsort result is therefore trace-selection policy, not an
inherent cross-page-return restriction.

## Why the workloads behaved differently

Sieve is the best case: it has integer-heavy, predictable loops, so eliminating
dispatch across a larger fraction of execution produces a visible improvement.

Qsort benefits from linking more of the comparator and partition control flow,
including a repeatedly hot alternative path. Its loops are short and perform
substantial memory traffic, however, so guard, register-materialization, and
memory-access costs consume most of the potential gain.

Zlib and hash are also memory-heavy and have more complicated control flow.
The earlier assumption that syscall simply lacked profitable integer traces was
wrong: its nine-instruction cycle is valuable, but call-target collection
prevented that loop from being selected. Double is dominated by floating-point
handlers that this backend does not compile. Extra integer-trace coverage
therefore has little effect on the other workloads.

## Earlier policy work was not qsort's limiting factor

The LuaJIT-style policy work was useful for avoiding obvious pathologies:

- hot counters delayed compilation;
- failed heads were penalized or blacklisted;
- trace publication was transactional;
- side traces were bounded and did not recursively grow an unbounded tree; and
- side traces were identified by both guard PC and the root trace's expected
  successor.

This stopped repeated compilation and maintained correctness, but better trace
identification cannot create a large speedup when the compiled code itself has
little advantage over the interpreter. Each workload installed roughly 120--170
fragments, while only a small subset was likely responsible for meaningful
dynamic execution. Much of the added machinery therefore managed traces with
negligible performance value.

## Conclusion

Trace linking and side exits, by themselves, did not justify their complexity.
The failure was dynamic coverage, not the measured cost of data translation:
qsort spent about 99% of its time outside generated code because its two hot
leaf comparators were never installed independently and calls could not enter
them across code pages.

Return-bounded call-target recording changes that conclusion for qsort. It
raises generated-code sampling from about 0.94% to at least 18.0% and reduces
the repeated median from 24.41 s to 18.97 s. This is the first measured payoff
large enough to justify continuing the experiment.

The cross-workload measurements make the next development decision a policy
problem. Return-bounded call traces are worth 22.3% on qsort, but their current
hotness integration costs 21.6% on syscall by starving its profitable loop. The
next step is to separate or prioritize loop and call-target hotness so call-body
discovery cannot displace an established loop candidate, then repeat both qsort
and syscall measurements before retaining the mechanism. Adding more trace
coverage without preserving the measured loop winners would repeat the same
mistake.
