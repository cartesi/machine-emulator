# Tail-call interpreter experiment

## 1. Current conclusion

A tail-call threaded interpreter, built from Mike Pall's design advice but
with no assembly, beats the stock computed-goto interpreter on AArch64
while reusing the stock instruction semantics unchanged (built with
`make tailcall=yes`). The campaign also made the stock interpreter itself
faster: the countdown mcycle (section 5.18) and the typed fast pc
(section 5.19) are stock-loop products of the tail-call work, together
worth about 6.5% under Clang on the M3 Max. Against that improved stock,
the tail-call interpreter stands at -7.1% under Clang and -10.3% under
GCC 15 in aggregate over the six continuity workloads, which composes to
about -13% under Clang against the stock interpreter as it stood before
the campaign. Every variant of every iteration retired identical cycles
and produced identical root hashes and guest exits against a same-source
stock build.

The result is architecture-specific. On x86-64 (Raptor Lake) the shipped
defaults measured +1.4% under Clang 22 and +10.9% under GCC 16, and the
only win was Clang with the next-instruction pre-load disabled, at a
marginal -1.2% (section 5.14). Those numbers predate the register-budget
series that followed (the six-slot signature of 5.16, page segments and
the fetch-tag demotion of 5.17, and the typed fast pc of 5.19), which
brings the handler signature down to four register slots with no
stack-argument traffic; a two-phase re-measurement campaign is queued
for that hardware (section 8c).

On AArch64, the register discipline Pall obtains from assembly is
obtained here from pinned global register variables (x23-x25 and x27
hold pc, the cycle countdown, the fetch tag, and the context pointer),
with the preserve_none convention and guaranteed tail calls layered on
where the compiler provides them (Clang). On x86-64 the smaller register
file changes that balance and the default is the argument-passing shape
instead. The design is in section 3, the iteration history in section 5
(the single most consequential step was the next-instruction pre-load of
5.9), and the register evolution from nine handler slots to four, with
an identified floor of two, is the ledger of section 8d.

Beyond the interpreter, an ahead-of-time trace oracle riding the handler
convention measured -18.5% against the tail-call interpreter itself
(sieve -52.7%), roughly -25% against stock (section 8b, item 2). For
scale, the best offline native AOT result of the earlier tracing
experiments, entered and left through the stock loop's boundary, was
-2.9% aggregate.

A copy-and-patch JIT now compiles what the recorder records, from
stencils built against the same handler contract, so a trace is entered
and left by a jump (section 5.20). It is exact over full boots and
measures -16.8% over ten workloads, as a bimodal result that coverage
explains completely: -30% to -77% where it executes most of the guest's
instructions, and a few percent of loss where it executes almost none.
On x86-64 it rides the argument shape, so unlike every pinned-register
configuration in this document it starts from parity with stock rather
than from a deficit, which is why the workloads it cannot help cost so
little. That figure was -5.6% until two selection bugs were found and
fixed (section 5.21): the compressed load/store family had been excluded
from the compiled set for a misattributed reason, cutting every hot loop
short at its first `c.lw`, and the head table discarded compiled traces
permanently and in proportion to how many were compiled. Neither was
visible in the emitted code, which is the recurring lesson of this
experiment's trace work. For scale, a parallel branch pairing the same
contract with a GNU lightning backend and a further-developed recorder
reaches -16.0% on the same ten workloads and host.

## 2. Background and motivation

Earlier tracing experiments on this codebase showed that Clang's lowering
of the stock computed-goto loop is host and compiler sensitive, and that
compiling trace machinery into `interpret_loop` damaged stock code
generation by tens of percent even when no trace ran. Pall's diagnosis of interpreter loops (lua-l, February 2011,
"Suggestions on implementing an efficient instruction set simulator in
LuaJIT2") predicts exactly this: the register allocator cannot maintain a
consistent assignment across a large computed-goto graph, and slow paths
poison fast paths. His remedy is a fixed register assignment for all
handlers, fast paths that keep everything in registers, slow paths moved out
of line, and replicated dispatch at the end of every handler.

Two preliminary experiments framed the work:

- The whole emulator builds on macOS with MacPorts GCC 14
  (`make CC=gcc-mp-14 CXX=g++-mp-14`), produces bit-identical machine
  hashes, and one microbenchmark ran 13.7% faster than the Clang build.
  The benchmark turned out to measure the exception-heavy path, not plain
  dispatch (a mistyped config key, silently ignored by `cm_create`,
  turned the intended addi/bne loop into a trap loop), but compiler slack
  in the dispatch shape is real even between good compilers.
- Linking a GCC-compiled `interpret.o` into the Clang build is
  mechanically easy but semantically unsound: libc++ and libstdc++
  disagree on `std::string` layout, so every `machine` member after `m_c`
  sits at a different offset, and the mixed build diverged at mcycle 1.
  `interpret.cpp` has almost no libstdc++ symbol dependency but a real
  layout dependency through `machine`'s inline accessors, which member
  reordering cannot fix.

## 3. Design

This section records the design as first built; the structure is
unchanged today, but the handler signature has since evolved from the
nine slots shown here to four (the ledger of section 8d tracks each
step). The stock switch bodies are perfectly uniform, so the
implementation is mechanical and semantics are shared, not duplicated:

- `interpret-tc-cases.inc` (generated): 153 `TC_CASE(LABEL, execute_...)`
  entries extracted from the stock `INSN_CASE` region of `interpret.cpp`.
- `interpret-tc-table.inc` (generated): the 65536-entry dispatch table
  extracted from `interpret-jump-table.hpp` with `INSN_LABEL` rewritten to
  `TC_LABEL`, expanded into function pointers.
- `interpret.cpp`, guarded by `#ifdef TAILCALL_INTERPRET`: the handler
  macro, the fetch helpers, and `interpret_loop_tc`. The flag is off by
  default. Only the direct `state_access` instantiation uses the
  tail-call loop; uarch, record, replay, and collect instantiations keep
  the stock loop over the same `execute_FOO` bodies. (The stock loop
  itself later adopted two findings of the campaign, the countdown of
  5.18 and the typed fast pc of 5.19, for every instantiation.)

The original nine-slot handler signature (preserve_none, AArch64
arguments in x20-x28):

    execute_status tc_handler_FOO(state_access a,        // x20, x21
        uint64_t pc,                                     // x22
        uint64_t mcycle,                                 // x23
        uint32_t insn,                                   // w24
        uint64_t mcycle_tick_end,                        // x25
        tc_context *tcc,                                 // x26
        uint64_t fetch_vaddr_page,                       // x27
        host_addr fetch_vf_offset);                      // x28

Each handler executes its instruction via the stock `execute_FOO`, performs
the same status handling as the stock post-switch code, advances mcycle,
fetches the next instruction, and dispatches with `[[clang::musttail]]`
through the table. Dispatch is replicated per handler so each indirect
branch site keeps its own target history. `tcc` holds the loop state that
must survive a return to the outer loop (pc, mcycle, the fetch cache) and
is kept coherent at every outlined-helper call and chain exit. The fetch
fast path and the code-TLB consult are inline in each handler; the page
walk and the page-boundary crossing are out of line.

Two ABI rules proved essential:

- preserve_none argument registers (x20-x28) are callee-saved in the
  standard convention, so handler state survives calls into ordinary cold
  helpers without spilling.
- Outlined helpers must take and return values, never references. A real
  call taking `uint64_t &pc` makes the handler's pc address-taken, and
  Clang then homes pc on the stack for the whole dispatch tail, putting a
  store-load round trip on the critical fetch chain of every instruction.

Build with `make tailcall=yes`. The switch compiles interpret-tc.cpp (the
tail-call translation unit, see section 5.12) with the pinned-register
flags and -fno-stack-protector, and gives interpret.o only the routing
define. TC_PAGE_SEGMENT=1 selects the page-segment shape of 5.17
(default off), and the args shape on AArch64 additionally requires
clearing the pinned-register reservations (TC_FFIXED_FLAGS=, see 5.17).
The historical campaigns predate the switch and were built with
hand-passed OPTFLAGS.

## 4. Measurement protocol

Six stress-ng continuity workloads (sieve, qsort, zlib, hash, double,
syscall), run by the tracing-experiment harness against install
prefixes, Apple M3 Max, macOS, Apple clang 17. Timings are user CPU
from single no-warm-up repetitions unless stated; where warmup and measured
pairs exist they agreed to within noise on every workload. Correctness
gates, not timing, are the acceptance criterion: every pair in every table
below matched guest cycles, final root hash, and guest exit byte for byte
(sieve retires 16,802,042,474 cycles; after the rootfs refresh of 5.11 it
retires 16,791,353,500). A stray runaway process from an
older experiment consumed one core during part of the campaign; pairs ran
under like conditions, so relative comparisons stand.

## 5. Iteration history and findings

### 5.1 Naive tail-call (musttail only)

| Workload | Stock (s) | Tail-call (s) | Change |
|---|---:|---:|---:|
| sieve | 30.94 | 28.37 | -8.3% |
| qsort | 30.30 | 33.45 | +10.4% |
| zlib | 25.51 | 35.29 | +38.3% |
| hash | 31.73 | 30.40 | -4.2% |
| double | 53.40 | 56.32 | +5.5% |
| syscall | 32.73 | 34.24 | +4.6% |
| **Total** | **204.61** | **218.07** | **+6.6%** |

Disassembly showed every handler paying a five-register-pair prologue
because cold paths (raise, TLB miss) contain calls and Clang does not
shrink-wrap the frame into the cold blocks.

### 5.2 preserve_none

The convention removes the callee-saved burden; the prologue shrank to one
x29/x30 pair. Every workload improved:

| Workload | Stock (s) | Tail-call (s) | Change |
|---|---:|---:|---:|
| sieve | 30.86 | 26.63 | -13.7% |
| qsort | 30.23 | 31.74 | +5.0% |
| zlib | 25.43 | 34.17 | +34.4% |
| hash | 31.74 | 28.70 | -9.6% |
| double | 53.55 | 54.40 | +1.6% |
| syscall | 32.60 | 33.17 | +1.7% |
| **Total** | **204.41** | **208.81** | **+2.2%** |

This mirrors CPython 3.14's experience: their tail-call interpreter also
lost to computed goto until preserve_none. The same structure is used by
upb, wasm3, and deegen/luajit-remake.

### 5.3 Outlining the fetch miss path (zlib chain)

Attempting to shrink handler text for zlib produced a chain of falsified
hypotheses, resolved by reading the assembly:

| zlib configuration | user (s) | vs stock 25.5 |
|---|---:|---:|
| Fetch fully inline | 34.17 | +34% |
| Whole miss path outlined, preserve_most | 42.17 | +65% |
| Whole miss path outlined, plain convention | 42.44 | +67% |
| TLB consult inline, walk and crossing outlined | 38.57 | +51% |
| Same split, by-value helper ABI | 33.91 | +33% |

The convention change mattering nothing while outlining anything hurt
pointed away from call frequency. Disassembly found pc stored to and
reloaded from the stack on the hot path of every handler, caused by the
outlined helpers' reference parameters (section 3). With by-value helpers
the split became a strict improvement over fully-inline, handlers shrank
from about 200 to 82 instructions, and sieve improved further.

### 5.4 By-value fix, full table

| Workload | Stock (s) | Tail-call (s) | Change |
|---|---:|---:|---:|
| sieve | 30.89 | 26.02 | -15.8% |
| qsort | 30.32 | 31.65 | +4.4% |
| zlib | 25.62 | 33.91 | +32.4% |
| hash | 31.67 | 29.20 | -7.8% |
| double | 53.42 | 53.35 | -0.1% |
| syscall | 32.84 | 32.71 | -0.4% |
| **Total** | **204.76** | **206.84** | **+1.0%** |

Excluding zlib the tail-call interpreter beats stock by 3.5%.

### 5.5 Fetch cache in argument registers

Promoting `fetch_vaddr_page` and `fetch_vf_offset` to handler arguments
removed the last two memory loads from the dispatch tail (the hit path now
reads only the instruction and the handler pointer). Timing did not move
(sieve 25.95, zlib 33.97). The loads were already hidden by the
out-of-order core. Retained anyway for the near-ideal code shape.

### 5.6 Shared dispatcher (rejected)

Collapsing all handler tails into one shared dispatch function (single
indirect branch site, 43-instruction handlers) tested whether zlib's
residual was branch-target or i-cache pressure from replication:

| Workload | Stock (s) | Replicated tails (s) | Shared site (s) |
|---|---:|---:|---:|
| sieve | 30.88 | 25.95 | 34.03 |
| zlib | 25.53 | 33.97 | 35.75 |

Both workloads regressed and the variant was reverted. Disassembly of both
builds supports attributing the regression to prediction rather than to
added overhead. In the shared build the dispatcher carries the one x29/x30
frame pair (its miss paths contain calls) while the handlers become
frameless, because with a call-free hot path ending in a direct branch
Clang successfully shrink-wraps the raise-path frame into the cold block.
Both builds therefore pay exactly one frame pair per dispatched
instruction, and the remaining per-instruction delta is a single taken
unconditional branch. The 26-point sieve swing is thus almost entirely the
loss of per-site indirect-branch target history, empirically vindicating
Pall's replication advice on this core, and zlib's residual is neither
dispatch-site pressure nor handler text size.

The shrink-wrapping observation cuts the other way for the retained
variant: its handlers keep an unconditional frame pair only because the
inline fetch tail's two cold calls (walk and crossing) sit inside the hot
function. Section 5.7 removes them, with a much larger effect than the
frame pair predicts.

### 5.7 Miss continuation

The handler tail was restructured so only the fetch-cache hit path remains
inline (tick check, hit check, instruction load, table dispatch) and every
other fetch outcome leaves by `[[clang::musttail]]` to one shared
`tc_fetch_miss` continuation with the handler signature. No call is then
reachable from a handler's fetch tail. Never-raising handlers (BEQ and
kin) become fully frameless; handlers whose execute body can raise still
carry an entry frame because Clang declines to sink the save past multiple
tail-call exits.

The measured effect far exceeds the removed frame instructions:

| Workload | Stock (s) | Tail-call (s) | Change |
|---|---:|---:|---:|
| sieve | 31.10 | 21.63 | -30.4% |
| qsort | 30.38 | 28.05 | -7.7% |
| zlib | 25.79 | 32.42 | +25.7% |
| hash | 31.73 | 27.65 | -12.9% |
| double | 53.34 | 51.21 | -4.0% |
| syscall | 33.00 | 27.60 | -16.4% |
| **Total** | **205.34** | **188.56** | **-8.2%** |

The correct attribution is not the frame pair. Evicting the entire miss
machinery from the handler function removed the miss-path register
pressure and the hoisted setup (TLB base and offset constants computed
ahead of the hit check in every earlier variant) from the hot path, and
left the allocator a small dense function. This is the same
miss-preparations-ahead-of-dispatch disease the earlier tracing
experiments diagnosed in Clang's decoded-cache loop, removed here by
making the miss path a
different function rather than by fighting the allocator. The feared cost
of the shared miss-dispatch site did not materialize; zlib improved to its
best value. Every workload improved over section 5.4, qsort flipped from
loss to a 7.7% win, and the aggregate went from +1.0% to -8.2%.

### 5.8 GCC and the tail-call structure

GCC 14 compiles the same source with none of the enabling attributes.
`[[clang::musttail]]` is ignored, but inspection of the linked library
shows GCC's sibling-call optimization nonetheless emits every handler
transition as a branch, zero call-shaped transitions and 151 direct tail
branches. (An earlier claim of 266 residual call-shaped transitions was a
misreading of unrelocated object-file disassembly, where a pending
external relocation displays as a self-targeted `bl` annotated with the
containing handler's symbol; those are cold helper calls residing inside
handlers, not transitions.) The regression is therefore attributable to
the standard convention alone: no preserve_none, so AAPCS leaves x0-x7
and the ninth argument (the vf_offset feeding the instruction load)
passes through the stack, and every handler carries four callee-saved
register pairs of ABI shuffling. One repetition each, hashes identical to
the Clang builds:

| Workload | GCC stock (s) | GCC tail-call (s) | Change |
|---|---:|---:|---:|
| sieve | 28.86 | 25.63 | -11.2% |
| zlib | 25.58 | 28.12 | +9.9% |

Two conclusions were drawn at the time. First, some structural benefit
survives the worse ABI: the tail-call form beats GCC's own stock loop on
sieve. Second, and diagnostically important, GCC's tail-call zlib (+9.9%,
and 28.12s absolute) was far better than Clang's pre-pre-load +25.7%
(32.42s) despite visibly worse per-dispatch code, which localized the
zlib residual to Clang's generated shape and led to the counters run and
ultimately the pre-load fix of section 5.9.

A later full-suite run corrected the first impression: the two-workload
sample was unrepresentatively favorable. Under GCC 14 (no-pre-load shape
via `TC_PRELOAD_ENABLED`), one repetition each, all pairs hash-identical:

| Workload | GCC stock (s) | GCC tail-call (s) | Change |
|---|---:|---:|---:|
| sieve | 28.76 | 25.86 | -10.1% |
| qsort | 29.81 | 35.90 | +20.4% |
| zlib | 25.67 | 28.27 | +10.1% |
| hash | 30.62 | 31.15 | +1.7% |
| double | 56.56 | 61.95 | +9.5% |
| syscall | 31.72 | 36.08 | +13.7% |
| **Total** | **203.14** | **219.21** | **+7.9%** |

GCC therefore regresses 7.9% aggregate with the tail-call structure in
this form, winning only sieve. The design's wins are not compiler-neutral
structure: they are enabled by keeping the interpreter state in registers
across every boundary. Transitions are already branch-shaped under GCC,
so GCC 15's musttail would add only a guarantee, not speed; the entire
gap is the register budget (the ninth argument on the stack in the fetch
chain, callee-save shuffling per handler). Section 5.10 closes that gap
with pinned global register variables.

### 5.9 Next-instruction pre-load

Prompted by the counters diagnosis of section 6, each handler
pre-decodes its fall-through successor before executing its
own semantics: predicted pc, the instruction word fetched at it, and the
resolved dispatch target, produced by one reusable `tc_predecode_next`
built on the same fetch primitives as the generic tail. The prediction is
verified before use (execution status is plain success, and for
conditional branches the architectural pc equals the predicted pc;
straight-line handlers need no pc comparison because success implies the
fall-through). The generated case list classifies each handler:
straight-line pre-load, guarded pre-load (conditional branches), or none
(store-capable handlers, whose stores over the fall-through bytes must be
observed by the next fetch; always-jumping handlers; raising handlers).
Pre-decoding performs only side-effect-free host reads through the valid
fetch mapping, so stock semantics are preserved exactly, including
same-page self-modifying code, translation changes, and traps.

The first implementation regressed sieve 27% while barely helping zlib:
it recomputed the instruction length from the instruction word at
runtime, five instructions sitting at the head of the dependency chain
the rotation was supposed to shorten, plus a redundant pc guard. The
repair came from first principles (rotating (fetch;execute)* into
fetch;(execute;fetch)* must not add work): each handler serves exactly
one encoding length, so the length is a compile-time constant per case,
and the pre-decode's loads then replace the generic tail's loads
one-for-one. Clang even merges the predicted-pc add with the execute
body's own pc advance. One repetition, identical cycles and hashes on
every pair:

| Workload | Stock (s) | Tail-call (s) | Change |
|---|---:|---:|---:|
| sieve | 30.26 | 23.52 | -22.3% |
| qsort | 29.70 | 25.03 | -15.7% |
| zlib | 24.70 | 25.53 | +3.4% |
| hash | 31.06 | 25.06 | -19.3% |
| double | 52.33 | 48.86 | -6.6% |
| syscall | 32.26 | 26.69 | -17.3% |
| **Total** | **200.31** | **174.69** | **-12.8%** |

Every workload except sieve improved over section 5.7 (sieve sits within
a couple percent of its best), and zlib collapsed from +26% to +3.4%: its
stall was the serial fetch chain, and overlapping it with execution
removed it. The clumsy-versus-free comparison is itself a finding:
pre-load buys chain latency with issue slots, so on a wide core it is
profitable exactly when it adds no instructions, which the static length
makes possible.

GCC 14 is the counterexample that proves the register-budget condition.
The same pre-load source regressed both poles under GCC relative to its
own best tail-call build (sieve 25.63 to 27.70 seconds, zlib 28.12 to
28.83, hashes identical): without preserve_none, the predicted word and
dispatch target become hot-path stack traffic on handlers that already
spill their ninth argument. The pre-load is therefore compiled in only
when preserve_none is available (`TC_PRELOAD_ENABLED`), so each compiler
gets its measured-best shape from one source.

A closing hardware-counters run on the final pre-load build corrected
the mechanism section 6 predicted. The prediction on record was that
mispredicts would stay at ~22 per 1000 guest instructions with the gain
coming purely from latency overlap. Instead the counted indirect
mispredicts collapsed below stock (zlib 22.5 to 3.40 per 1000, stock
3.52; sieve 8.7 to 4.3), while the identical-source GCC build without
the pre-load stayed at 21.7. Since the predictor's inputs did not
change, the consistent interpretation is that loading the dispatch
target a whole execute-body early lets the core redirect from the known
register value almost immediately on a wrong prediction, and such early
redirects neither cost nor count like late mispredicts. Final figures
for the pre-load build: zlib 39.6 host instructions per guest
instruction at 8.57 cycles per guest instruction and IPC 4.62 (stock:
29.5, 8.29, 3.56), sieve 35.6 at 5.81 and IPC 6.13. The tail-call
interpreter now pays essentially stock's cycle price on stock's best
workload and wins everywhere else.

### 5.10 Pinned global registers for GCC

GCC's native substitute for preserve_none is stronger than argument
passing: file-scope register variables (`register uint64_t mcycle
asm("x23");` and friends, x22-x27, under a GCC-only guard) bind the
interpreter's hot state permanently to call-saved registers. The state is
never passed at all; the handler signature shrinks to the accessor and
the instruction word, and the values survive helpers, cold calls, and
external code because call-saved discipline preserves them. pc is the one
exception (execute_* takes it by reference and register globals have no
address), so handlers bind it to a local and sync one register move at
each exit; the same proxying covers the privileged handler's by-reference
mcycle.

The first attempt crashed the benchmark harness while passing every
C-API exactness check, which isolated a lesson worth recording: the
reservation removes those registers from the compiler's save/restore
discipline, but the interpreter is itself a callee, and its caller
(liblua here) may hold live values in call-saved registers. The crash was
lua's own state corrupted across machine:run. The fix is a boundary
wrapper that saves the six registers' incoming values before the run and
restores them after, so the globals own the registers only while the
interpreter runs. With it, every workload passes the cycle and hash gates
through both the C API and the Lua host (the unrelated GCC Lua teardown
segfault from section 5.8 remains, after results are written).

One repetition each against the same GCC stock baselines as before, all
pairs hash-identical:

| Workload | GCC stock (s) | GCC pinned tail-call (s) | Change |
|---|---:|---:|---:|
| sieve | 28.76 | 22.17 | -22.9% |
| qsort | 29.81 | 28.20 | -5.4% |
| zlib | 25.67 | 23.67 | -7.8% |
| hash | 30.62 | 27.12 | -11.4% |
| double | 56.56 | 55.53 | -1.8% |
| syscall | 31.72 | 28.14 | -11.3% |
| **Total** | **203.14** | **184.83** | **-9.0%** |

GCC flips from +7.9% to -9.0% aggregate, faster than its stock on every
workload, and this is the experiment's first configuration on any
compiler to beat stock on zlib. Cross-compiler, Clang keeps the better
aggregate (174.69 total on its own same-day stock baselines) and wins
qsort, hash, double, and syscall, while pinned GCC wins the two most
chain-bound workloads, sieve (22.17 vs 23.32) and zlib (23.67 vs 25.47).
That split suggests full pinning beats argument-passing exactly where the
dispatch chain dominates, and motivates trying pinned globals under
Clang (section 8, attempts item 5).

Separately, the GCC-built Lua module segfaults deterministically at process
exit after producing correct results (teardown only; the C API path used in
earlier GCC validation does not exhibit it). Diagnosed and fixed in section
5.13.

### 5.11 GCC 15

GCC 15.2 replaced GCC 14 (via MacPorts) and was measured with the same
harness against a freshly fetched rootfs, so absolute times and cycle
counts in this and later sections are not comparable to the earlier
tables; comparisons are against same-day, same-source stock baselines as
always. One repetition each, all pairs cycle- and hash-identical:

| Workload | GCC15 stock (s) | GCC15 pinned (s) | Change | GCC15 pinned+preload (s) |
|---|---:|---:|---:|---:|
| sieve | 28.81 | 21.12 | -26.7% | 22.69 |
| qsort | 29.37 | 27.36 | -6.8% | 27.58 |
| zlib | 27.08 | 24.84 | -8.3% | 24.88 |
| hash | 30.27 | 26.28 | -13.2% | 26.50 |
| double | 56.28 | 55.42 | -1.5% | 55.23 |
| syscall | 30.94 | 26.35 | -14.8% | 27.17 |
| **Total** | **202.75** | **181.37** | **-10.5%** | **184.05** |

GCC 15 improves the pinned shape's aggregate from GCC 14's -9.0% to
-10.5% and reaches near parity with Clang's preserve_none shape measured
the same day (181.37 vs 179.21, with the same pole split: GCC wins sieve
and zlib, Clang wins qsort, hash, and double). Re-enabling the pre-load
under GCC 15 (possible now that the pinned globals restore the register
budget, section 8 attempts item 5) is a small net loss (+1.5% over pinned alone,
sieve +7.4%, zlib neutral), much milder than GCC 14's regression. The
uniform shape adopted in section 5.12 keeps the pre-load on anyway; the
cost of uniformity under GCC 15 is those 1.5 points.

### 5.12 Pinned registers on AArch64: one shape for both compilers

Making TC_GLOBAL_REGS, TC_PRELOAD_ENABLED, and the calling convention
independently overridable from the build allowed measuring the full cross
product, and ended with one AArch64 source shape serving both compilers:
pinned globals in x23-x28, pre-load on, plus preserve_none and musttail where
the compiler has them. Clang needs -ffixed-x23 through -ffixed-x28 (wired via
MYCXXFLAGS so the flags reach only the host build, not the uarch cross build).
Three Clang-specific obstacles, each diagnosed from disassembly:

- Clang restricts named register variables to integer and pointer types,
  rejecting the host_addr strong type. The register holds the raw
  uint64_t; TC_ENTER binds a read-only local of the strong type and the
  few writers cast.
- Clang assumes -ffixed registers cannot change across calls, and
  deleted the boundary save/restore of the caller's x23-x28 around the
  run (section 5.10's caller-save lesson) as dead code. The save/restore
  therefore goes through volatile asm the compiler cannot analyze, held
  by a scope_exit so exceptional unwinds restore too.
- Clang's preserve_none argument order assigns arguments to x20-x28 in
  order and ignores -ffixed reservations while doing it. With the state
  originally pinned at x22-x27, the insn argument landed in x22 and every
  dispatch clobbered the pinned pc with the instruction word. The failure
  was not incorrectness but a 45x slowdown: the fetch-cache hit check
  always failed and tc_fetch_miss recovered the true pc from the context
  on every instruction. Pinning at x23-x28 leaves x20-x22 for the
  (accessor, insn) arguments and resolves the collision.

musttail remains required under Clang: without it, sibling-call
optimization converts 150 of 156 dispatch sites but leaves the six
fattest handlers (FD, FMADD, FMSUB, FNMADD, FNMSUB, PRIVILEGED) with real
calls. GCC emits all transitions as branches, as before.

Measured progression under Clang, against same-day stock baselines, all
gated (the first two are from the campaign preceding the renumber):

| Clang shape | Total (s) | vs stock |
|---|---:|---:|
| preserve_none args + preload (5.9 shape) | 179.21 | -11.1% |
| pinned x22-x27, musttail, no preload | 195.24 | -4.4% |
| pinned x22-x27 + preload | 183.70 | -10.1% |
| pinned x23-x28 + preload + preserve_none | 181.25 | -11.4% |

Without the pre-load, pinned Clang reproduces the serial-fetch-chain
disease on zlib (36.33 vs stock 27.22); with it, zlib returns to parity
(27.22 vs 27.09). Composing preserve_none over the pinned shape recovers
the handler-frame savings and closes the remaining gap: the unified AArch64
shape is the best Clang result measured in the whole experiment. The same
campaign re-validated GCC 15 on the renumbered registers (-9.1% vs own
stock, unchanged from -9.2% before the renumber):

| Workload | Clang stock (s) | Clang unified (s) | GCC15 stock (s) | GCC15 unified (s) |
|---|---:|---:|---:|---:|
| sieve | 30.58 | 25.57 | 28.80 | 22.89 |
| qsort | 30.05 | 26.10 | 29.44 | 27.80 |
| zlib | 27.09 | 27.22 | 27.08 | 24.86 |
| hash | 31.26 | 25.31 | 30.56 | 26.69 |
| double | 53.15 | 49.81 | 58.66 | 57.11 |
| syscall | 32.51 | 27.24 | 31.97 | 28.27 |
| **Total** | **204.64** | **181.25 (-11.4%)** | **206.51** | **187.62 (-9.1%)** |

The register reservation is TU-wide under both compilers (GCC's
declarations reserve for the whole translation unit, Clang's -ffixed is a
per-compile flag), and interpret.cpp also instantiates the stock loop for
record, replay, and collect, which must not lose six registers for a loop
they never run. The tail-call machinery therefore moved to its own
translation unit, interpret-tc.cpp, which includes interpret.cpp for the
instruction semantics (guarded so the explicit instantiations stay in
interpret.o) and exports one non-template entry, interpret_loop_tc_run,
for direct execution. The `make tailcall=yes` switch compiles it with the
-ffixed flags; interpret.o gets only the routing define and full register
freedom for the stock instantiations. A side effect is that the earlier
campaigns, built with library-wide -ffixed, taxed all non-interpreter
code slightly. The split shape measured (gated, same protocol): Clang
179.73 vs stock 203.73 (-11.8%, the best Clang aggregate of the
experiment), GCC 15 at 184.45 with a negligible-drift anchor,
about -10.6% vs its stock. These are the numbers of record for
`make tailcall=yes`.

One methodology trap cost a debugging detour and is worth recording: the
embedded uarch image compiles interpret.cpp with asserts enabled, so it
contains __LINE__ values that shift with unrelated edits to that file.
Root hashes therefore differ between builds of different source revisions
while every architectural state, memory range, and shadow structure
matches (the divergence was ultimately two bytes, one assert's line
number, found by byte-diffing dumped memory ranges). Hash gates are only
valid between builds of identical source; rebuild the stock anchor
whenever interpret.cpp changes.

### 5.13 The GCC exit segfault, diagnosed and fixed

The teardown crash noted in section 5.10 is not TC-related and under GCC
15 affects stock builds too. lldb places the crash in
dyld::ThreadLocalVariables::finalizeList called from exit(), jumping to an
address in unmapped memory. GCC on macOS implements thread_local with
emutls: the first use of any TLS variable registers a per-thread finalizer
(emutls_destroy, code inside the image) that dyld never unregisters. The
only TLS variables in the library are the C API's two thread_local
std::string buffers in cm.cpp, which luaopen_cartesi exercises on load.
When the host dlcloses the module (Lua's package teardown at state close),
the finalizer dangles and exit() jumps into the unmapped image. The C API
path never dlcloses, which is why it never crashed. Linux glibc marks DSOs
with pending TLS destructors nodelete, and Clang's native macOS TLVs are
tracked per image, so this configuration is the one runtime combination
that leaves the dangling pointer.

The fix follows what the mainstream runtimes do: a constructor in cm.cpp
(gated to Apple GCC) pins its own image with dlopen(RTLD_NOLOAD |
RTLD_NODELETE) as soon as it loads, so dlclose never unmaps it. Leaking
the buffers instead was rejected (the C API is a public FFI boundary,
and hosts with thread churn would leak one buffer pair per dead thread),
as was pinning in the Lua binding (any host language can dlclose the
library). The fix shipped independently of the tail-call flag.

### 5.14 x86-64 measurements and constraints

The compile-only predictions were replaced by a full campaign on real
x86-64 hardware (Raptor Lake), using Clang 22.1.8 and GCC 16.1.1. Stock
baselines reproduced within 0.1%, and all 357 runs agreed on mcycle, exit
reason, and root hash. The auto-detected defaults are `TC_GLOBAL_REGS=0`
and `TC_USE_PRESERVE_NONE=1` for both compilers, with
`TC_PRELOAD_ENABLED=1` for Clang only.

| Build | Total (s) | vs stock |
|---|---:|---:|
| Clang stock | 61.97 | -- |
| Clang `tailcall=yes` | 62.82 | +1.4% |
| Clang tail-call, `TC_PRELOAD_ENABLED=0` | 61.26 | **-1.2%** |
| GCC stock | 61.30 | -- |
| GCC `tailcall=yes` | 67.96 | +10.9% |
| GCC tail-call, `TC_PRELOAD_ENABLED=1` | 70.94 | +15.7% |
| GCC tail-call, pinned | 66.32 | +8.2% |

The countdown and GCC 16's preserve_none support improve substantially on
the previous x86-64 branch state (Clang +2.6% to +1.4%, GCC +25.8% to
+10.9%), but no x86-64 configuration reproduces the AArch64 headline. The
only win is Clang without the pre-load, driven primarily by `regs` (-15.0%)
and `nop` (-12.5%); complex workloads remain around parity or regress
slightly.

The pre-load question was settled for this register budget (and reopened
later at four slots, section 8d). On Clang,
disabling it saves 2.6 percentage points in aggregate. On zlib it removes
6.2 host instructions and 0.6 stores per guest instruction: the predicted
dispatch target no longer spills through a red-zone slot on every dispatch.
Unlike AArch64, x86-64 has too few registers for the overlap to pay for its
spill traffic. Forcing the pre-load on under GCC costs another 4.8 points,
so the GCC default reaches the right answer even though the condition's
stated rationale is stale.

| Build, workload | Host insn/guest | Cycles/guest | IPC | Stores/guest | Branch miss/1k |
|---|---:|---:|---:|---:|---:|
| Clang stock, zlib | 31.6 | 7.06 | 4.48 | 0.86 | 18.4 |
| Clang tail-call, zlib | 39.1 | 7.55 | 5.18 | 2.21 | 18.2 |
| Clang tail-call, no pre-load, zlib | 32.9 | 7.01 | 4.69 | 1.61 | 18.4 |
| GCC stock, zlib | 29.5 | 6.98 | 4.23 | 0.82 | 18.2 |
| GCC tail-call, zlib | 36.7 | 7.39 | 4.97 | 3.13 | 18.6 |
| GCC tail-call, pinned, zlib | 42.7 | 7.66 | 5.57 | 3.82 | 18.6 |
| GCC stock, nop | 14.9 | 3.33 | 4.47 | 0.05 | 16.7 |
| GCC tail-call, nop | 22.8 | 4.39 | 5.19 | 2.06 | 16.7 |
| GCC tail-call, pinned, nop | 20.3 | 3.74 | 5.42 | 0.14 | 16.7 |

Pinned GCC beats its argument shape by 2.4 points overall, confirming that
pinning trades state traffic for locals traffic rather than eliminating
traffic. It is handler-dependent: on nop it collapses stores from 2.06 to
0.14 per guest instruction, while on zlib it executes more instructions and
stores than the argument shape. Branch-miss rates are unchanged across the
x86-64 builds, so the dispatch-site prediction mechanism discussed in
sections 5.6 and 6 does not explain this host's result; register pressure and
spill traffic do.

The campaign also exposed two configuration hazards:

- GCC 16's x86-64 preserve_none argument registers collide with the pinned
  rbx/r12-r15 set. `TC_GLOBAL_REGS=1` with the auto-detected
  `TC_USE_PRESERVE_NONE=1` compiles but corrupts state at runtime (`mcycle is
  past`). The pinned measurements therefore explicitly used
  `TC_USE_PRESERVE_NONE=0`; the source now rejects the combination at
  compile time (section 5.16).
- Clang cannot use the pinned shape on x86-64 even with preserve_none
  disabled: it rejects general-purpose global register variables on this
  target. The unified pinned shape is therefore AArch64-only, not merely
  blocked by preserve_none's argument order.

The pre-load default was consequently narrowed to `TC_GLOBAL_REGS`, which
preserves the measured AArch64 shape and selects the winning no-pre-load
shape for x86-64 Clang; both guards are implemented. The stock loop
remains the x86-64 default pending the queued re-measurement of 8c.

### 5.15 Countdown mcycle

mcycle is not architectural state between observation points, so the
chain no longer carries it. A single pinned countdown of cycles until the
tick end replaces the (mcycle, mcycle_tick_end) register pair: handlers
retire an instruction with one decrement-and-test, and the architectural
mcycle is materialized as tcc->mcycle_tick_end minus the countdown at the
points that observe it (the 47 load/store/AMO/CSR cases whose semantics
take mcycle for device accesses, the privileged handler, and chain
exits). The countdown is compared as signed because WFI's interactive
poll can advance mcycle past the tick end, driving it negative; two's
complement keeps the materialization identity exact there too.

The change shrinks the pinned set to x23-x27 (x28 returns to the
allocator), drops the args-shape signature from nine slots to eight (one
step closer to fitting x86-64's argument registers), and gives trace
exits their natural form: a compiled trace needs no per-instruction
accounting, only an entry guard (enter only if the countdown covers the
longest run to any exit) and a constant adjustment at each exit, with a
per-iteration decrement at loop back-edges. Measured against a same-day
stock anchor, all pairs cycle- and hash-identical:

| Workload | Clang stock (s) | Clang countdown (s) | GCC15 countdown (s) |
|---|---:|---:|---:|
| sieve | 30.52 | 25.80 | 22.82 |
| qsort | 29.81 | 25.48 | 28.03 |
| zlib | 27.21 | 27.50 | 24.71 |
| hash | 31.59 | 24.92 | 26.58 |
| double | 52.49 | 48.27 | 55.30 |
| syscall | 32.24 | 26.32 | 26.76 |
| **Total** | **203.86** | **178.29 (-12.5%)** | **184.20** |

Clang improves from -11.8% to -12.5% (better on five of six workloads,
each delta small), the best result of the experiment; GCC 15 is
unchanged within noise (184.20 vs 184.45, about -10.8% vs its stock).
The compiler does not fuse the decrement into a flag-setting subtract
(it emits sub, mov, cmp, branch where subs plus one branch would do), so
a little is still on the table if that shape ever matters.

### 5.16 One-pointer accessor and the six-slot signature

The x86-64 campaign left the register budget as the standing diagnosis,
and a disassembly study against GCC 16.1 made it exact. GCC 16's x86-64
preserve_none passes arguments in only six registers (r12-r15, rdi, rsi,
measured with a probe function), where Clang's uses twelve. The
eight-slot handler signature therefore overflows GCC's set by exactly
two, and the overflow lands on the fetch-cache pair: every handler
loaded both fields from incoming stack slots at entry and stored both
back before every dispatch, a store-to-load round trip through memory at
the head of the critical fetch chain, section 5.8's ninth-argument
disease reborn as arguments seven and eight. The same study settled two
side questions. Adding [[gnu::musttail]] to the preserve_none shape
leaves GCC 16's output byte-identical (every dispatch is already a
sibling call), while in the plain-convention shape IPA-SRA rewrote
tc_fetch_miss's signature, sibling calls became impossible there, and
GCC silently emitted that dispatch as a real call carrying a live frame
per fetch miss; the same build with the attribute compiles clean with
the call gone. The attribute is free where codegen is already right and
turns this silent-regression class into a compile error.

Two of the eight slots turned out to be cold cargo. state_access carried
{processor_state*, machine*}, but all sixteen of its machine uses are
cold paths (device and slow memory access, PMA reads, TLB refill,
console, counters, dirty marking at walk and fill time). The context
pointer is likewise never touched by the hot dispatch path. Both are now
derived instead of passed. penumbra_state gained a host-only
back-pointer to the machine (set at construction, never hashed, never in
the backing file), and state_access shrank to the processor-state
reference alone, so the accessor occupies one register in every
instantiation, the stock loop included. tc_context moved into a penumbra
scratch area, placement-newed by the outer loop, so the args shape
derives it from the state pointer at a constant offset.

The signature is then six slots (accessor, insn, pc, countdown, and the
fetch-cache pair), which fits every convention in play fully in
registers: SysV x86-64 has exactly six argument GPRs, GCC 16's
preserve_none six, Clang's twelve, and AAPCS eight, so even GCC 14/15's
x86-64 args shape stops spilling. Static evidence under GCC 16.1 on
x86-64, same protocol as the 5.14 disassembly work: stack-argument
traffic zero (was two loads and two stores per dispatch), aggregate
handler text -11%, push/pop -68%, and the lean and memory handlers' hot
paths contain no stack memory access at all (BNE is fully frameless, and
LD's TLB-hit path runs entirely in registers, the data-TLB consult
folding into disp32 addressing off the state pointer). The remaining
stack traffic is cold-block spill save/restores and the fat handlers'
execute bodies (FD, the AMOs, PRIVILEGED), operand pressure the stock
loop pays as well.

The first AArch64 measurement caught a regression hiding in the cleanup:
freeing x27 by deriving the context in the pinned shape cost GCC 15
about two points aggregate, reproducible across repetitions. The context
offset in the penumbra exceeds AArch64's scaled load immediate range, so
the derivation put address arithmetic on the mcycle materialization of
every memory instruction, and the pinned shape gains nothing from the
freed register because its state never travels through arguments. The
context pointer is therefore pinned again (x27, r15 on x86-64) while the
context storage stays in the penumbra; x86-64's args shape keeps
deriving it, which disp32 addressing makes free there.

Same-day anchors, one repetition (a second GCC repetition agreed within
noise), all 48 runs of the campaign cycle- and hash-identical:

| Workload | Clang stock (s) | Clang tc (s) | GCC15 stock (s) | GCC15 tc (s) |
|---|---:|---:|---:|---:|
| sieve | 29.70 | 25.69 | 27.97 | 22.81 |
| qsort | 29.78 | 25.48 | 29.23 | 27.22 |
| zlib | 26.98 | 27.71 | 27.06 | 24.67 |
| hash | 31.17 | 24.94 | 30.19 | 26.54 |
| double | 51.74 | 48.27 | 56.19 | 55.19 |
| syscall | 32.23 | 26.43 | 31.04 | 26.70 |
| **Total** | **201.60** | **178.52 (-11.4%)** | **201.68** | **183.13 (-9.2%)** |

The absolute tail-call times equal or beat 5.15's record on every
workload under both compilers (GCC's qsort improves by 0.8 seconds); the
relative aggregates read lower than 5.15's -12.5% and -10.8% only
because the same-day stock anchors ran about a percent faster than on
the earlier campaign's day. The cost of the whole change is one
host-only page per machine instance, the penumbra padding that houses
the back-pointer and the context. The x86-64 shapes, the ones this
series targets, are re-measured by the queued campaign of 8c, by now at
four slots (8d).

Also in this round, GCC 16's AArch64 preserve_none turned out to use the
same plain attribute spelling as Clang and x86-64 (the target-string
spelling the source speculatively gated on is rejected), so the enable
collapses to a __has_attribute probe and the GCC 16 AArch64 build now
compiles; its argument order is x20-x28 like Clang's, composing with the
pinned set unchanged. The x86-64 combination of pinned registers and
preserve_none, which corrupts state at runtime (section 5.14), is now a
compile error.

### 5.17 Page segments and the fetch-tag demotion

The fetch-cache tag is consulted per instruction only because the future
is unknown. The page-segment idea (filed as 8c item 2) proves
straight-line fetches safe in advance instead: fuse the two exit reasons
into one segment countdown, min(tick_remaining, floor(bytes_to_page_end
/ 4)), conservative because four bytes is the maximum instruction
length; when it fires early (compressed instructions), re-derive and
continue, about twice per page. Straight-line handlers then need no
per-instruction hit check at all. Taken branches and jumps (~12% of
instructions) validate the target page and recompute the bound.
Everything that can change the mapping is already on cold or
chain-exiting paths and kills the segment through the existing
invalidation hook. Stores need nothing: only the mapping check is
amortized, every fetch still reads guest RAM, so same-page
self-modifying code is observed exactly as today. fetch_vaddr_page then
demotes to the context, read only by the control-flow minority.

The first implementation (TC_PAGE_SEGMENT, default off) passed every
gate (36 runs across six configurations, cycle- and hash-identical with
the prior campaigns) and produced the intended x86-64 code shape: the
ADDI dispatch tail fell from 17 instructions to 9, frameless, with GCC
16 folding the table load into the indirect jump. Measured on AArch64,
though, it lost to the flag-off tail-call build on every workload: +4.8%
aggregate under Clang and +3.3% under GCC 15 (sieve worst at about +7%).
The first diagnosis blamed the exit that replaced the check: fusing the
page bound into the countdown makes every segment expiry a full chain
exit through the outer loop, and the tighten-only rule makes hot loops
inherit the page position of their loop head, restarting the chain every
few dozen instructions. The v2 refinement keeps the removed check but
makes segment expiry a tail call into an in-chain resegmentation
continuation (the tc_fetch_miss pattern) that re-derives the bound from
the current pc and the true tick end, held in a new context field, and
re-dispatches without leaving the chain.

v2 measured almost identically on AArch64 (Clang +4.9%, GCC 15 +2.8%
against the flag-off build, every gate green across both rounds), which
corrects the diagnosis: the exit cost was a minor term. The structural
reason is that under the pre-load the per-instruction page check was
already amortized -- the eor/cmp/b.hi in the hot path is the
predecode's guard, paid once as part of the rotation -- so on this
shape the segment scheme can only convert a three-instruction guard
into a two-instruction one, while charging the tighten to every checked
dispatch (taken branches, stores, jumps) and growing handler text with
the dual tails. On the pre-load shape there is no headroom by
construction. The scheme's target is therefore exclusively the
no-pre-load x86-64 args shape, where the removed check is the generic
tail's own and the ADDI dispatch falls from 17 instructions to 9,
frameless. The flag stays off; the x86-64 measurement, with v2's
bounded expiry in place, happens on hardware.

The register the scheme was meant to free is now actually freed: under
the flag the args shape drops fetch_vaddr_page from the signature (five
slots: accessor, insn, pc, countdown, vf_offset), the tag lives in the
context alone, control transfers and cold paths read it there, and
invalidation writes only the context copy. Static effect under GCC 16.1
on x86-64: the no-pre-load shape's stack stores fall 29% and loads 23%
against the six-slot segment build, with the LD hit path fully
frameless; the pre-load shape's stores fall 23% and its LD hot path
drops from five spill round trips to three, so the pre-load re-test on
this architecture is an open question rather than a foregone loss. The
demoted shape passes the full gates (cm-cli specs plus the six-workload
harness, cycle- and hash-identical against stock anchors), validated on
AArch64 by forcing the args shape. One build caveat from that exercise:
the AArch64 args shape must clear the pinned-register reservations
(make tailcall=yes TC_FFIXED_FLAGS=), because Clang's preserve_none
assigns arguments into x23-x27 and the -ffixed flags of the default
pinned shape make that combination crash at run time.

The AArch64 gate run doubles as a first timing hint for the demotion:
the demoted args shape with the pre-load measured -10.4% against stock
under Clang, two points better than the pinned segment build (-8.5%)
though still behind the shipped pinned shape without segments (-12.8%,
cross-day anchors, args-vs-pinned and the freed register conflated). A
released register recovering two points on the architecture with
register slack is the encouraging case for the architecture without it.

### 5.18 Countdown mcycle in the stock loop

The countdown of 5.15 is a stock-uniformity companion: the stock loop
still carried mcycle and the tick end live across the whole
computed-goto function and paid increment, compare, branch per
instruction, where the countdown pays one decrement-and-sign-test and
frees a register. In the TC loop that was worth 0.7 points on a core
with allocator slack; the stock loop is the opposite regime, the
ten-thousand-instruction function whose GCC register allocation the
accessor incident showed to be one memory dependency away from
collapse, on the architecture where registers are scarcest and in the
default Linux build. The transformation is 5.15 verbatim: the 47
observation cases materialize mcycle on demand as base minus remaining,
the privileged case proxies its by-reference mcycle, and both raising
fetches and retirements pay one signed decrement. The record, replay,
and collect logs are unaffected because the counter is a loop local and
only materialized values reach the accessors. It landed in the stock
interpreter first, before any further TC work, with the uarch image
rebuild accepted as part of the change.

Measured, it is the largest stock-loop win of the whole experiment:
against same-day stock anchors on the M3, Clang -5.4% aggregate with
every workload improving, GCC 15 -2.3%. The gates exercised the 5.12
same-source discipline in its strongest form yet: editing interpret.cpp
rebuilds the embedded uarch image, whose bytes change from both the
shifted assert line numbers and the uarch's own recompiled inner loop,
so the root hash moves while every architectural value stays put
(cycles, exits, and cross-compiler hashes agreed throughout).
Attribution was proven, not assumed: relinking the countdown build
against the uarch image generated from the pre-change source reproduces
the old anchors bit for bit on all six workloads.

### 5.19 Typed fast pc through both loops

The typed fast pc (filed as 8c item 3) keeps pc as a fast address: the
handler state holds the host address of the current instruction, typed
as fast_addr so the two spaces cannot mix silently, and vf_offset
leaves the hot path entirely. The fetch is a plain load through the
fast pc, the advance is the same add it always was, and the fetch-cache
tag and the page-segment allowance move to host space unchanged,
because a per-page mapping preserves the offset bits.

The contract change is that the execute bodies receive the fast pc as
such, written in the type, and any body that wants the architectural pc
translates back explicitly through the accessor's fetch mapping. The
observation points are few and mostly cold (AUIPC and the JAL/JALR link
values, and mepc/mtval on every raise), so the raise paths pay for the
translation only when they actually raise, and the type system marks
every observation site. pc-relative control flow needs no translation
at all: branch and JAL targets are same-mapping adds, valid in host
space, and the host-space tag check catches cross-page targets exactly
as the virtual one did. Targets that are born virtual (JALR, trap
vectors, MRET) come out of their bodies typed as virtual addresses, so
the type system itself forces them through the translating miss path.

The change is not TC-local: typing pc through the execute bodies
changes the shared semantics, stock loop included. That is a feature,
not a cost. The stock loop runs the same fetch economics (it carried
the virtual pc and the vf offset and added them per fetch), so it
collects the same register relief and the same shortened fetch
expression, and one uniform representation serves every instantiation
instead of a TC-only dialect. It landed as an interpreter-wide refactor
gated by the full hash suite rather than behind a TC flag. The pass's
verification items all held: every observation point was found by the
type change itself (the build breaks where a fast pc meets a virtual
consumer), branch bodies were confirmed unable to raise with the C
extension enabled (2-byte alignment leaves misaligned-target exceptions
unreachable), and mapping invalidations poison the host-space tag
exactly as they poison the virtual one.

Measured on AArch64, every gate held across a 54-run campaign with
same-batch pre-change anchors: cycles and exits identical over nine
configurations, and the attribution build (new source linked against
the uarch image generated from the pre-change source) reproduced the
anchor hashes bit for bit, so the root-hash shift is entirely the
embedded image. Timing against the same-batch anchors: Clang stock
-1.2%, GCC 15 stock +0.3%, Clang tail-call +0.1%, GCC 15 tail-call
-0.7%, i.e. neutral with a small Clang stock win, as expected on the
architecture where the removed offset add was already folded into
addressing. The refactor's real product is the register economics on
x86-64: with segments the args signature is four slots (accessor, insn,
fast pc, countdown) and the ADDI dispatch tail under GCC 16 is about
ten instructions whose fetch is a single load through the pc register
with the fall-through folded into the addressing mode. The port also
uncovered one hazard worth its own sentence: when a register leaves the
pinned set, the boundary save/restore asm must shrink with it, because
a hard-coded write to a now-allocatable register silently clobbers
compiler-owned state (the crash presented as a jump to address zero out
of a musttail chain).

### 5.20 Copy-and-patch: compiling traces from stencils

Section 8b item 4 asked for a backend that honors the register contract. This
is it, built by the copy-and-patch method (Xu and Kjolstad, OOPSLA 2021; the
transactional.blog tutorial): the per-case code that the AOT experiment emitted
as C++ text is instead compiled once at build time with its operands left as
relocations, and the JIT builds a trace by copying those bodies back to back and
writing the recorded instruction's operands into the holes. There is no register
allocation and no instruction selection, because the stencils were compiled
against the interpreter's own handler contract; entering and leaving a trace
moves no state and is a plain jump.

`make tailcall=yes jit=yes`. It composes with the online recorder of 8b item 3,
which now installs what it records instead of discarding it.

**The stencil unit is compiled and never linked.** That is what makes the method
work here. Not linking frees it to be built `-fno-pic`, so no operand reaches
its use through a GOT and every body is relocatable by `memcpy`; and it makes an
undefined symbol the mechanism rather than an error, since a hole is exactly a
symbol the linker would have resolved. `tools/gen-tc-stencils.lua` reads the
object file, extracts each `tc_stencil_*` body with the relocations inside it,
and emits `interpret-tc-stencils.inc`.

The contract a stencil must satisfy is that its code reaches nothing but its own
holes and the state registers, and the extractor enforces it rather than the
case list asserting it. Three escapes had to be closed before that check was
worth anything. A call between two functions of one section needs no relocation, so
`-ffunction-sections` is not tidiness but the thing that turns those calls into
relocations the checker can see; the same applies to identical-code folding,
which replaced one stencil body with a jump to another, and to cold-block
partitioning, which split a body across two sections. The third is the operand
materialized relative to its own instruction, described under the measurements
below. With all three closed the check found the real cases: 34 of 153 do not
belong in the compiled set (floating point, CSR, atomics, `PRIVILEGED`, and the
compressed memory forms), leaving 119 compiled. The compressed memory forms
turned out not to belong on that list at all, and getting them back was worth
more than everything else in this section put together; the campaign that
found out why is at the end of it.

Three source-level mechanisms carry operands into the code:

- Operand getters become holes under `TC_STENCIL_TU`, one hole per getter. That
  is not cosmetic: it means the JIT fills a hole by calling the very getter it
  stands for, so no table maps cases to immediate formats and no such table can
  fall out of step with the encodings.
- Register fields carry a byte offset rather than an index, because a relocation
  can contribute `symbol+addend` and never `symbol*8`. As an index the operand
  costs a materializing instruction and a scaled addressing mode; as an offset
  it folds into the displacement of the access itself. Getting there also meant
  widening the operand path, since a round trip through `uint32_t` or `int`
  makes the compiler materialize and re-extend the relocated value -- three
  instructions where the fold costs none.
- A literal register index (`a.read_x(2)` in the compressed stack forms) would
  address the wrong register silently under that scheme, so `do_read_x` calls an
  undefined symbol when a constant index is not a multiple of eight. The
  extractor then rejects it by name at build time. It fired on exactly the cases
  predicted, which is how they came to be excluded by evidence rather than by
  inspection.

The result on x86-64 is the intended shape. `ADDI` compiles to six
instructions, five after the trailing jump is elided:

    mov  $imm32,%eax           # R_X86_64_32   the immediate
    cltq
    add  rs1(%r12),%rax        # R_X86_64_32S  folded into the displacement
    mov  %rax,rd(%r12)         # R_X86_64_32S
    add  $4,%r14               # pc
    jmp  cont                  # R_X86_64_PLT32, dropped on fall-through

`preserve_none` is the convention the technique assumes, and the stencils carry
it: the state is in r12 and pc in r14 across every tail call, and nothing spills
at a boundary. Composing it with the JIT required lifting the recorder's
requirement for the pinned-register shape, because on x86-64 the two cannot
coexist -- preserve_none's argument registers are the pinned set itself. The
argument shape is now the JIT's default there, and the recorder works in both,
which also made the JIT build under Clang on this host for the first time. On
AArch64 the two compose already and the pinned shape keeps the attribute.

Accounting is the block scheme of the AOT bodies, realized as three more
stencils rather than as machine code the emitter writes by hand: an entry guard
proving the countdown covers the block, a charge at the end of one, and a loop
back edge. Straight-line steps carry no accounting at all.

Two correctness findings are worth recording because neither is visible in code
review and both were found by differential execution:

1. **The side exit owed a countdown test.** Every handler tests the countdown
   after retiring an instruction and before dispatching the next; a trace tests
   it once per block instead, which leaves that test owed at the exit. Without
   it a trace whose last step exhausts the countdown dispatches one instruction
   past the boundary. It presented as a machine stopped at `--max-mcycle=N`
   reporting `N+1`, and a bisection on the root hash located it exactly.
2. **W^X has to be restored on every path.** The cache is made writable to emit
   into, which un-executes the traces already in it; a build that gave up
   partway returned without restoring, and the next entry into any installed
   trace faulted on its first instruction. It is a `scope_exit` now.

**Trace identity is the host page, not the address space.** A compiled trace
holds the instructions that were at a virtual pc rather than a way to fetch
them, so what must still hold at entry is that the pc names the same memory.
Keying on the address space (satp, privilege, an invalidation counter) was tried
first and is what a global epoch invites: it refused 99.6% of head hits, because
any address-space change invalidated every trace permanently. Comparing host
pages instead, through the code TLB the interpreter already maintains, is both
more precise and self-correcting -- the same physical page mapped into two
processes is one page, so context switches cost nothing, and a TLB flush merely
makes the consult miss once. That change alone took entries from 425k to 967k
and refusals from 117M to 0.6M. Nothing counts invalidation events, because the
structure that gets invalidated is the one being asked.

Gates: cycle-, exit- and hash-identical to a same-source no-JIT build over a
full Linux boot and workload (2.36G cycles), at three intermediate `mcycle`
bounds as well as at the end, and the cm-cli spec suite passes 52/52. Every
configuration measured along the way agreed bit for bit, including both
head-table sizes and all three hotness thresholds.

**Measured across six workloads: -9.1% aggregate, and bimodal.** Best of three,
pinned, under GCC 16 on Raptor Lake, against same-build stock and tail-call
anchors. stress-ng supplies the cpu-method workloads, bounded by operation count
rather than by time so the guest work is identical in every run; all eighteen
runs were cycle- and hash-identical across the three builds, which makes the
timing table double as the correctness gate.

| workload | stock | tailcall | jit | jit vs stock | trace coverage |
|---|---:|---:|---:|---:|---:|
| sieve | 1.78s | 1.81s | 1.87s | +5.1% | 0.3% |
| int64 | 1.73s | 1.71s | 1.74s | +0.6% | 0.3% |
| double | 3.18s | 3.21s | 3.34s | +5.0% | 0.4% |
| matrix | 2.21s | 2.12s | 2.15s | -2.7% | 0.3% |
| sha256 | 6.38s | 6.18s | 5.79s | -9.2% | 5.0% |
| gzip | 2.79s | 2.79s | 1.53s | **-45.2%** | 86.1% |
| **total** | **18.07s** | **17.82s** | **16.42s** | **-9.1%** | |

The single number to take from this is not the aggregate but the correlation:
coverage explains every row. Where the JIT executes 86% of guest instructions it
is 45% faster; where it executes a third of a percent it is 0 to 5% slower,
which is the profiling shell and the recorder charging their usual few percent
against no return at all. Nothing in between appears, because coverage itself is
bimodal -- gzip has one loop that accounts for 41.9M of its 42.9M trace entries,
while sieve's hottest head sees 19k entries out of 173k and the loop that
actually runs the workload is never entered.

An earlier draft of this section reported -28% from the gzip workload alone.
That was the one workload in the set where the backend does what it can do, and
generalizing from it was wrong: the backend is not the limit on five of six
workloads, trace selection is. Whatever keeps sieve's inner loop from being
entered is worth more than any further work on the emitted code, and it is not
head-table pressure -- doubling the table lifts sieve's entries from 173k to
271k and its coverage from 0.3% to 0.4%, which is to say not at all.

How the gzip figure moved along the way is still the more useful record of what
this kind of backend is sensitive to.

**Pinning matters on a hybrid host.** The first campaign measured parity and
concluded that coverage was the limit. It was measuring core migration: this
part has P-cores and E-cores, an unpinned run lands on both, and user time then
says nothing about work done. `perf` contradicted the stopwatch -- 28% fewer
instructions at equal time -- which is what exposed it. Every number here is
`taskset`-pinned, and the protocol should stay that way on any hybrid part.

**A stencil that materializes an operand relative to itself is not
relocatable.** Both compilers sometimes choose `lea sym(%rip)` for an operand
under `-fno-pic`, and for the compressed memory forms, whose register fields
reach the access through a helper's parameters, both do it consistently. Such a
stencil computes a different number when copied, and no patch repairs it: the
value wanted is a small absolute constant and the encoding can only reach
addresses near the instruction. The patcher rejected these at run time by range
check, which was safe but silent -- it discarded whole traces. The extractor now
rejects them by name at build time, and excluding the 32 affected cases *raised*
coverage from 71.5% to 83.9% and trace entries from 0.9M to 42.9M, because the
recorder truncates at them instead of forming traces that get thrown away. The
lesson generalizes: the checker has to test that an operand is absolute, not
merely that its symbol is a hole.

**A signed operand must be narrowed in the source, not by the encoding.**
Folding the successor guard and the branch offsets into displacements, by
widening those holes instead of narrowing them through `int32_t`, took a
conditional branch from 13 host instructions to 9. It also broke the Clang
build, and only the Clang build: a hole carries the low 32 bits of a value that
may be negative, and whether those bits are sign- or zero-extended is decided by
the instruction the compiler chose around the site. GCC picked a sign-extending
form and Clang a zero-extending one, which turned every backward branch offset
into a large positive number and trapped the guest a few hundred thousand cycles
in. The narrowing cast is back, so the sign extension is written down rather than
inferred; the folding was worth under 1% and is not worth a correctness property
that holds by luck of encoding selection. The general rule the patcher now
records: what a 32-bit site does with its bits belongs to the stencil source,
because the relocation type cannot express it.

**Tracing more, by lowering the hotness threshold, makes it slower.** It looks
like the obvious lever and it moves the wrong way: against 3.21s at the shipped
threshold of 2048, 512 gives 3.37s and 128 gives 3.31s, and coverage falls with
each. Recording runs in one-instruction chains, so paying for it more often
loses more than the extra traces return. The tuning inherited from the shell was
already right.

**Reading the emitted code under a debugger.** Static disassembly of a stencil
shows what one instruction costs; it does not show what a trace costs, because
which paths run and which jumps survive layout are properties of the assembled
trace. Stepping one is worth the trouble, and needs a way in: trace addresses are
not symbols, and a breakpoint set on the code cache before the JIT writes there
is erased by the write. `TC_JIT_BREAK=<head pc>` therefore raises `SIGTRAP` just
after that trace is compiled, so a session lands with the address in hand and the
code already in place.

Stepped through gzip's hottest trace (seven guest instructions, 73% of all trace
entries in that run), 48 host instructions retire per iteration, and the mix
names its own overheads:

- Three `cltq`. Every immediate arrived as `mov $imm,%eax` plus a sign
  extension, because the compiler treats the hole as a 32-bit address. Naming
  the encoding instead -- `movq $imm32`, one instruction, sign-extending by
  definition -- removes them, and removes the compiler's freedom to pick the
  zero-extending form that broke Clang. That is the fix described above, arrived
  at from the disassembly rather than from the crash.
- Four `jmp`. Fall-through elision only fires when the continuation jump is
  physically last, and a stencil whose exit block the compiler sinks to the end
  keeps its jump in the middle. Recovering these means outlining the cold block,
  which needs the internal branch into it repatched, and that branch carries no
  relocation to find it by.
- `mov $0x87d693,%eax; shr $0x1a,%eax; je` -- a runtime test of a field of an
  instruction word that is known when the trace is compiled. Copy-and-patch
  substitutes values; it does not fold, so a case serving several encodings pays
  to re-discriminate on every execution. The fix is a stencil variant per
  discriminated form, which the table can hold but the generator cannot yet
  derive.
- Six `add $N,%r14`, one pc advance per instruction, where a block needs one.
  Deferring them is not free: an execute body may read pc, and every exit must
  see the true one, so the emitter would have to flush pending advances before
  any pc-reading or exit-carrying step.

Whole-workload, the JIT retires 30.4 host instructions per guest instruction
against stock's 43.5 and the tail-call interpreter's 48.1 (71.9G, 102.6G and
113.5G over 2.36G guest instructions). Compiled code is far leaner than either
loop; what dilutes it to -28% is the 16% still interpreted and the guards and
accounting a trace pays that straight-line compiled code does not.

What is left is two different things, and the table separates them. On a
workload the tracer covers, what remains is the technique's own ceiling: inside
compiled code each instruction still reads and
writes the guest register file in memory, because copy-and-patch substitutes
values into fixed bodies and cannot allocate a guest register into a host one
across a trace. Per instruction, compiled code costs about two thirds of an
interpreted one. Closing further means either fusing guards with the operations
they guard (a variant per recorded branch outcome, which the stencil table can
hold) or keeping pc and the hottest guest registers live across a block, which
is where a bespoke backend would start to differ from this one.

On the five workloads it does not cover, none of that matters yet. The backend
is idle and the shell is charging rent, and the question is why a tight integer
loop that the compiled set fully supports never becomes a trace that gets
entered. Trace formation, not translation, is where the next measurement
belongs: which sites the hooks fire at, what the recorder does with them, and
whether a head once installed is ever reached again.

That question is answered below, twice over, and the premise in it is wrong:
the compiled set did not fully support sieve's loop. Both answers were worth
several points each.

**A second workload set, and the head consult answers the last question.** The
six-workload table above bounds guest work by operation count. A ten-workload
run through `bench-harness/bench.lua` bounds it by mcycle instead -- boot to
256 Mi, then measure exactly 1 Gi more -- which makes the root hash at the end
of the window an exact gate rather than an approximate one, and makes the
comparison below possible at all. Same host and compiler, best of three,
against a same-source stock anchor; all forty runs were cycle- and
hash-identical. Coverage here is window-only, whole-process trace instructions
less the boot phase, so it is not the same quantity as the column above.

| workload | stock | tailcall | +recorder | jit | vs stock | coverage |
|---|---:|---:|---:|---:|---:|---:|
| memcpy | 1.089 | 1.098 | 1.187 | **0.452** | -58.5% | 90.2% |
| zlib | 1.370 | 1.342 | 1.387 | **1.159** | -15.4% | 44.0% |
| hash | 1.264 | 1.190 | 1.233 | **1.013** | -19.9% | 33.8% |
| nop | 0.677 | 0.669 | 0.671 | **0.634** | -6.4% | 7.8% |
| tree | 2.503 | 2.518 | 2.558 | 2.561 | +2.3% | 8.3% |
| qsort | 1.372 | 1.413 | 1.417 | 1.410 | +2.8% | 6.5% |
| regs | 0.874 | 0.870 | 0.860 | 0.864 | -1.1% | 1.1% |
| sieve | 1.160 | 1.161 | 1.183 | 1.213 | +4.6% | 0.1% |
| branch | 1.168 | 1.187 | 1.214 | 1.196 | +2.4% | 0.0% |
| double | 2.975 | 2.991 | 3.003 | 3.145 | +5.7% | 0.0% |
| **total** | **14.452** | **14.439** | **14.713** | **13.647** | **-5.6%** | |

The bimodality reproduces on a set chosen without reference to it, and the
uncovered end is now quantified rather than described: the six workloads under
10% coverage aggregate to +3.9% against stock, which is the whole cost of
having a tracer that finds nothing. Two figures in the table are new. The
tail-call baseline this JIT rides is free on this host -- 14.439 against
stock's 14.452 -- because on x86-64 the JIT selects the argument shape with
preserve_none rather than the pinned globals; nothing has to be won back before
the backend's own gain counts. And the recorder is +1.9% over that baseline,
consistent with the shell measurement of 8b item 1.

The open question at the end of the previous paragraph -- whether a head once
installed is ever reached again -- has an answer, and it is the head consult of
this section, not the recorder. `TC_JIT_STATS` separates a head hit that
entered from one refused because `head_key` did not match the current host code
page. The refusals dominate on exactly the workloads that get no coverage:
`double` refuses 9,063,950 against 136,752 entries, `tree` 15,851,855 against
2,300,259, `sieve` 350,654 against 224,168. The pc comparison ahead of that
check is exact, so these are not slot collisions; they are hits on a head whose
page is not, at that moment, the page the trace was compiled from. Whether the
mapping genuinely changed or the code TLB slot merely does not currently hold
that page -- `tc_jit_code_page` returns 0 in both cases -- is what the next
measurement has to separate, because the two want opposite fixes. Head-table
pressure was already excluded by the doubling experiment above; this is a
second, independent way for an installed head to go unused, and on `double` it
accounts for 98.5% of the times the guest arrived at one.

**Cross-check against a lightning backend.** A parallel branch
(`feat/tailcall-interpreter`) reached the same goal by a different route: GNU
lightning emitting into the same handler contract, on top of the online
recorder carried further -- an exact PC-to-trace map, integer coverage, and
conservative trace linking. It was measured with this harness on this host, so
the two are comparable, with two caveats stated up front. Each is scored
against its own stock anchor, because this branch's commit changes
`interpret.cpp` and its stock measures 14.452s where the other's measured
14.005s; and the lightning branch requires the pinned register shape on
x86-64, which costs it +11.9% against stock before any trace runs.

| workload | copy-and-patch | lightning | difference |
|---|---:|---:|---:|
| memcpy | -58.5% | -68.7% | 10.2 pts |
| zlib | -15.4% | -28.2% | 12.8 pts |
| hash | -19.9% | -37.1% | 17.2 pts |
| nop | -6.4% | -81.4% | 75.1 pts |
| regs | -1.1% | -21.4% | 20.2 pts |
| sieve | +4.6% | -68.8% | 73.4 pts |
| qsort | +2.8% | +3.2% | -0.5 pts |
| branch | +2.4% | +4.7% | -2.3 pts |
| tree | +2.3% | +8.7% | -6.4 pts |
| double | +5.7% | +14.8% | -9.1 pts |
| **total** | **-5.6%** | **-16.0%** | **10.4 pts** |

Lightning is ahead by 10.4 points aggregate, and 148 of those points are sieve
and nop alone, where this branch's coverage is 0.1% and 7.8%. On those two the
backend is not running, so nothing about emitted code is being compared; what
is being compared is trace selection, and the branch that carried item 3
further wins it outright. The four workloads where neither backend gets work
go the other way, by the margin the free baseline and the cheaper shell
predict.

What the comparison cannot settle is how much of the rest is code quality. On
memcpy, the one workload where this branch reaches 90% coverage, it finishes in
0.452s against lightning's 0.332s, or -58.8% against -74.6% measured from each
one's own tail-call baseline. That is a real difference and it is in the
direction the technique's ceiling predicts -- copy-and-patch cannot allocate a
guest register into a host one across a trace, and lightning does -- but the
lightning run's coverage on that workload was never recorded, so the two
numbers are not known to describe the same amount of compiled execution. Taking
them as a codegen comparison would repeat the mistake the -28% draft made.

The two results are complementary rather than competing, and they decompose
cleanly: this branch's entry cost is the thing lightning cannot fix, since the
pinned shape is what its backend emits into, and lightning's selection is the
thing this branch has not imported. Combining them is the obvious next
experiment and needs no new invention on either side.

### 5.21 Two selection bugs, and -16.8%

Section 5.20 ended by naming trace selection as the limit and asking why a hot
loop the compiled set supports never becomes a trace that runs. The answer was
two bugs, both in selection, neither visible in the emitted code. Fixing them
took the aggregate from -5.5% to -16.8% over the ten workloads of 5.20, which
is past the -16.0% the GNU lightning backend of the sibling branch reaches on
the same harness and host. Everything below is gated as before: cycle- and
hash-identical to the same-source stock build on all ten workloads and over a
472M-cycle boot-to-halt.

**The compressed load/store family was excluded for the wrong reason.** Sieve's
hot loop is eleven instructions and the compiled set covered the first six, so
its trace truncated at the seventh, could not be cyclic, and exited to the
interpreter on every iteration: 38,522 entries of six instructions each, 0.1%
coverage. The seventh instruction was a `c.lw`.

That family was excluded because both compilers materialize its register fields
with `lea sym(%rip)` instead of folding them into a displacement, and 5.20
attributed that to how the bodies reach the fields -- "through a helper's
parameters". The direction was right and the cause was one level down: it is
not the parameter, it is the parameter's *type*. `execute_C_L` and `execute_C_S`
declared their register selector `uint32_t`, and a relocated value that round
trips through a narrower type has to be materialized into a register and
re-extended. That is not a new finding, it is the one `reg_index` was
introduced for, written down in i-state-access.hpp and quoted in 5.20's own
operand rules; the compressed helpers simply predate it and were never
converted. Widening four parameters admitted the whole family. Three narrow
*immediates* reached their use the same way and did need their encoding named,
so `TC_STENCIL_ZEXT` joins `TC_STENCIL_SEXT` as its unsigned twin: `movl $sym`
is absolute by definition and costs the one instruction the fold would have
saved, in the five bodies that could not fold anyway.

The compiled set went from 119 cases to 135, and the stencil table got *smaller*
than the workaround tried first, because folding beats materializing. `C_LDSP`
and `C_LWSP` are in it: they call the same widened `execute_C_L`, and their
`rd` write now folds to an absolute `R_X86_64_32S` displacement like every
other case. They were briefly kept out on the theory that recovering them would
need `insn_get_rd` -- shared with a hundred uncompressed cases -- to name its
encoding and deoptimize all of them; that theory was formed before the widening
and retested after it, which is the only reason it did not survive into this
document as a false constraint. `C_FLD` and `C_FSD` came back with them and are
aggregate-neutral. What is still out is out for reasons the extractor cannot
see or that no widening reaches: softfloat calls, CSR and atomic slow paths,
`PRIVILEGED` writing the mcycle block accounting derives, and `C_FLDSP`/
`C_FSDSP`.

**The head table was discarding compiled traces, permanently.** Fixing the
compiled set alone made zlib and hash *worse*, which is the diagnostic: more
compilable instructions meant more traces, and more traces meant more of them
lost. The head table was 64 slots, direct-mapped, and installed by assignment,
so a later trace made an earlier one unreachable -- and because its head stayed
in the installed set, the recorder would never record it again either. The loss
was permanent and it scaled with the compiled set rather than with anything
about the workload. It also explains 5.20's finding that doubling the table
moved sieve's coverage from 0.3% to 0.4%: doubling a structure that evicts
still evicts.

The map is now the exact, open-addressed, non-evicting one that 8b item 6
reached independently on the lightning branch. It is the `installed_set` that
was already there, which was already exact and already sized at four times the
pool -- it only needed to carry what each head resolves to. A probe stops at
the first empty slot, so a pc that is no head at all still costs one load and
one comparison, and at that load factor a hit almost never leaves its first
slot. The per-`interpret()` rebuild of the old table went with it: the map
lives with the pool it describes and already outlives an interpret call.

**A latent unsoundness found on the way.** A trace's key -- the host page its
instructions were read from -- was taken from the *last* recorded instruction.
Recording proceeds one instruction per chain, so the mapping can move under a
recording; such a trace holds instructions from two host pages and was
installed under the second, and entering it later would execute the first
page's instructions. The key is now fixed at the head, where it belongs, and
any recording that sees its page move is discarded. Aggregate-neutral, so this
one is correctness at no cost.

Measured with the harness and protocol of 5.20 -- pinned, median of five, 1 Gi
guest cycles after a 256 Mi boot, against the same-source stock anchor:

| workload | stock | tailcall | jit before | jit after | vs stock | lightning |
|---|---:|---:|---:|---:|---:|---:|
| nop | 0.670 | 0.669 | 0.628 | **0.157** | -76.6% | -81.4% |
| memcpy | 1.086 | 1.114 | 0.452 | **0.431** | -60.3% | -68.7% |
| sieve | 1.157 | 1.166 | 1.215 | **0.557** | -51.9% | -68.8% |
| hash | 1.250 | 1.184 | 1.007 | **0.755** | -39.6% | -37.1% |
| zlib | 1.381 | 1.352 | 1.120 | **0.969** | -29.8% | -28.2% |
| regs | 0.875 | 0.864 | 0.865 | **0.779** | -11.0% | -21.4% |
| branch | 1.173 | 1.193 | 1.197 | **1.185** | +1.0% | +4.7% |
| qsort | 1.391 | 1.439 | 1.425 | **1.429** | +2.7% | +3.2% |
| tree | 2.455 | 2.543 | 2.579 | **2.568** | +4.6% | +8.7% |
| double | 2.976 | 2.997 | 3.124 | **3.168** | +6.5% | +14.8% |
| **total** | **14.414** | **14.521** | **13.612** | **11.999** | **-16.8%** | **-16.0%** |

Coverage moved with it, and it is the whole story: sieve 0.5% to 88%, nop 7.8%
to 95%, zlib 44% to 65%, memcpy 85% to 92%. The bimodality of 5.20 is intact --
it is still coverage that decides every row -- but the covered set is now most
of the workloads instead of one of them. Against the lightning backend the two
now trade: it keeps a wide lead where its recorder covers more (sieve, nop,
regs), this one wins hash and zlib outright, and it loses less on all four
workloads neither covers, which is the near-free baseline of 5.20 still paying.

**What the numbers say to do next.** The `stale` counter of 5.20 is now the
largest identified loss and it is concentrated exactly on the workloads that
still lose: qsort refuses 32.7M head hits against 5.5M entries, tree 59.2M
against 17.5M. Splitting the counter settles what 5.20 could not: 99.6% of
those are `remap`, not a code-TLB miss -- the head is found, the TLB holds its
page, and the page is a different host page than the one recorded. A head
installed once, in a context that then almost never runs, monopolizes its pc
forever, because identity is the pc alone while the thing identified is (pc,
page).

Widening identity to the pair was tried and reverted: it broke the hash gate
and cost 5%. Both are explained by the key bug above -- with the key taken from
the last instruction, widening the identity admits mis-keyed traces rather than
separating well-keyed ones. That fix is now in, so the experiment is worth
repeating, and it needs a policy for how many contexts one head may install
before the pool gives up on it. That, and not the emitted code, is where the
next several points are.

The remaining soundness item is stores into a page holding a trace, which needs
the write-TLB refusal described in 8b item 3; until then a guest that modifies
its own code would execute the recorded instructions, and the flag stays
experimental for that reason among others.

## 6. Hardware counters explain zlib

Eliminated first by construction and measurement: per-handler prologue
cost, outlining call frequency, reference-parameter stack traffic,
fetch-cache memory traffic, dispatch-site replication, handler text size,
and (after section 5.8's cross-compiler result suggested it) the shared
miss-dispatch site: cloning the fetch continuation per handler, giving
miss dispatches 153 private indirect sites, left zlib exactly unchanged
(32.43 vs 32.42 seconds), so the clone was reverted.

Instruments CPU Counters recordings (M3, `cm-counters` template sampling
BRANCH_MISPRED_NONSPEC, BRANCH_INDIR_MISPRED_NONSPEC, INST_BRANCH_INDIR,
L1I_CACHE_MISS_DEMAND, MAP_DISPATCH_BUBBLE_IC, MAP_DISPATCH_BUBBLE_ITLB,
plus the fixed cycle and instruction counters; totals aggregated from the
`counters-profile` table of each trace) then settled it. Per guest
instruction, full runs including boot, one recording each:

| Run | Host insn/guest | Cycles/guest | IPC | Indir mispred /1k guest |
|---|---:|---:|---:|---:|
| clang stock zlib | 29.5 | 8.23 | 3.58 | 3.5 |
| clang tail-call zlib | 36.2 | 11.43 | 3.16 | 22.5 |
| gcc tail-call zlib | 45.8 | 9.07 | 5.05 | 21.6 |
| clang tail-call sieve | 31.1 | 5.73 | 5.43 | 8.7 |

Host indirect branches per guest instruction are 1.01-1.04 in every run
(one dispatch per instruction), a strong internal consistency check.

Two findings:

1. The stock loop's single dispatch site predicts zlib almost perfectly
   (0.35% of indirect dispatches mispredict): with long global history at
   one site, the predictor effectively learns zlib's instruction stream.
   Per-handler sites raise the rate 6x (2.2%) under both compilers.
   Together with the tail-call form's ~23% higher host instruction count,
   this accounts for roughly two thirds of the stock advantage on zlib.
   Replicated sites are therefore not universally good: they win on
   narrow streams (sieve) and lose to single-site global history on wide
   ones (zlib).

2. The Clang-vs-GCC gap is instruction-level parallelism, not prediction.
   GCC executes 27% more host instructions per guest instruction yet
   finishes each in 21% fewer cycles, sustaining IPC 5.05 against Clang's
   3.16 at equal mispredict rates. Clang's lean handler is a single
   serial dependency chain (instruction load, table load, indirect
   branch), so every dispatch mispredict and load-latency gap leaves the
   wide core with nothing to issue; GCC's register save/restore filler is
   independent of that chain and soaks up the dead slots. Lean code lost
   to fat code because it has no independent work to hide stalls behind.

The indicated fix was the one element of Pall's design not yet
implemented: pre-load the next instruction inside the handler. Section
5.9 implements it and resolves zlib; its closing counters run, recorded
there, corrected the mechanism predicted here.

## 7. Implications for tracing

- The earlier tracing experiments measured a +66% "tracing shell"
  penalty from compiling trace machinery into the stock loop's CFG. In
  the tail-call structure, hotcounts and trace entries become ordinary
  functions behind an ABI-fixed boundary and cannot perturb stock
  handler code generation.
- A trace executor or native backend can share the handler convention, so
  entering and leaving a trace moves no state. This is the LuaJIT
  architecture (interpreter and JIT sharing register conventions); the
  earlier experiments measured that boundary cost as the decisive one
  for short traces.
- The sieve result from section 5.6 quantifies per-site branch prediction:
  dispatch sites private to a code region are worth double-digit percent
  on predictable code. Trace-side dispatch should be per-trace, never
  shared.
- If specific handlers still leave slack, each can be replaced by a
  hand-written assembly function honoring the same convention, one at a
  time, measured one at a time. So far no assembly has been needed.

## 8. Portability and promotion

The original work in this section targeted GCC 14, which lacks
preserve_none and musttail; section 5.8 showed the tail-call structure
regressing 7.9% aggregate without them. The attempts were:

1. TRIED, SPLIT BY CONVENTION. Slimming the handler signature to eight
   integer slots (fetch-cache fields back in the tc_context) regressed
   Clang 5-7% with the pre-load in place: the demoted fields feed the
   head of the pre-load's dependency chain, where register residency now
   matters (the earlier neutrality measurement predates the pre-load).
   The fields stay in registers under preserve_none; section 5.17 later
   demotes the tag without this cost by proving straight-line fetches
   safe in advance.
2. RESOLVED, MOOT. The linked library shows GCC 14 already emits every
   transition as a branch (zero call-shaped transitions); the earlier
   count of residual `bl` transitions was an unrelocated-object
   misreading. Nothing to convert.
3. DONE, LARGE WIN (section 5.10). GCC global register variables pin the
   interpreter's hot state in call-saved registers under a GCC-only
   guard, flipping GCC from +7.9% to -9.0% aggregate. No -ffixed flags
   or library-wide changes were needed; see 5.10 for the caller-save
   boundary lesson learned on the way.
4. OPEN, NEVER TRIED. Profile-guided optimization as an orthogonal probe
   (-fprofile-generate / -fprofile-use, one workload of training).
5. DONE, UNIFIED AARCH64 SHAPE (sections 5.11 and 5.12). Pinned globals under
   Clang, composed with preserve_none and the pre-load, are the best
   Clang result measured (-11.4%), and the pre-load under GCC 15 costs
   1.5 points. One shape serves both compilers on AArch64; the defaults in
   interpret-tc.cpp select it, with every choice overridable from the build.

Rejected: -fcall-saved-xN per TU (silent ABI mismatch with
default-convention TUs, the same hazard class as the mixed-toolchain
divergence in section 2); attribute-level layout tinkering (noise at this
scale).

Remaining before promotion:

1. DONE. `make tailcall=yes` compiles interpret-tc.cpp with the pinned
   register flags; interpret.o gets only the routing define (section
   5.12).
2. DONE. The interpret-tc.cpp defaults select the unified shape on AArch64
   for both compilers.
3. DONE. Run a full x86-64 timing campaign (section 5.14). The result is
   near parity for Clang only after disabling the pre-load, and a regression
   for GCC under every measured shape.
4. DONE (section 5.16). The pinned x86-64 shape with preserve_none is a
   compile error.
5. DONE. The pre-load default follows the pinned shape; on x86-64 Clang
   this is worth 2.6 points and does not change AArch64.
6. OPEN. Complete the formal gates on the experimental flag (section 9).

GCC 16 does provide preserve_none on both AArch64 and x86-64, under the
same plain attribute spelling Clang uses (section 5.16). On x86-64 it
improves the argument-passing shape substantially but passes arguments in
only six registers, so by itself it does not dissolve the architecture's
register-budget problem; the register series does (six slots in 5.16,
four with segments and the typed pc, section 8d). The +10.9% default
predates those changes, and composing the convention with pinning
remains invalid because their registers overlap (now a compile error).

The register contract's payoff outside the interpreter is now measured
twice over: the AOT oracle of 8b item 2, and the copy-and-patch backend of
5.20, whose stencils are only relocatable into a chain at all because that
contract is fixed and identical on both sides of the splice.

Standing goal: a single interpreter implementation, so there is one loop
to audit instead of two. Currently blocked by portability (x86-64 has
not yet measured a consistently winning shape; the queued campaign of 8c
re-prices that at four slots) and by the flat cost models of the uarch
and zk builds, where the tail-call shape's instruction-count overhead
(section 6: 35-46 host instructions per guest instruction against
stock's ~29) would directly inflate proof cost. The remaining probe
there is a TC-shaped uarch build compared on retired uarch cycles, which
are architectural and exact. Until both are measured, the stock loop
remains the portable fallback and the verified paths (record, replay,
collect, uarch, zk) stay on it.

## 8b. Next work: the jitter on the tail-call structure

Section 7's arguments now have a concrete staging. The guiding worry is
the cost of trace collection and lookup; the answer is LuaJIT's shape,
already validated piecemeal by the earlier tracing prototypes: hotcounts
only at taken backward branches and call targets (the 64-entry colliding
16-bit counter prototype), trace-head lookup only at those same sites,
per-page trace tables with eviction, probation and blacklisting so cold
or failing heads stop paying. In the tail-call structure all of it is
local to the handlers that host the hooks; the fetch-tail hit path stays
untouched, which the stock loop could never offer (its instrumented
shell cost +66% with tracing idle).

1. DONE, GREEN LIGHT. Shell cost: the selective hotcounts and head
   lookup live behind -DTC_JIT_SHELL=1 (hooks in the conditional-branch
   handlers for taken-backward edges and TC_HOOK_CALL wrappers on the
   JAL/JALR/C_JALR cases; a 64-counter, 64-head tc_hot_state in the
   context). Measured against same-source no-shell controls, all pairs
   hash-identical: Clang +1.71%, GCC 15 +1.40% aggregate, versus +66%
   for the stock loop's instrumented shell. The split confirms the
   boundary argument: workloads with few hook events sit at noise
   (qsort -0.2%, zlib +0.3%, double +0.4%), so instrumentation no
   longer poisons uninstrumented handlers, and the residual is honest
   per-event cost concentrated where events are dense (sieve +3.8%,
   syscall +6.0%). Both concentrations are upper bounds for a real
   tracer, which replaces its hottest sites with trace entries and
   avoids the head probe at unestablished sites.
2. DONE, DECISIVE. AOT through the interpreter's convention: traces
   captured offline (machine-emulator-2's aot-six-capture build against
   the current images, TRACE_HOT_THRESHOLD=64, TRACE_MAX_COUNT=1024),
   emitted by scratch/tracing-experiment/gen-tc-traces.lua as functions
   with the handler signature whose bodies are the recorded sequences:
   per step, the TC case's own execute expression with the recorded
   word, the handler macro's status handling, the countdown decrement,
   and a pc guard against the recorded successor; cyclic traces loop
   natively; every exit leaves through the interpreter's fetch tail.
   Dispatch rides the shell's head probe (-DTC_AOT=1, trace file in
   TC_AOT_TRACES, 64 traces per workload). The first round, against the
   tail-call interpreter itself, gated on cycles and hashes (two
   re-anchors on the evolving shape follow below; the current figure is
   -18.5%):

   | Workload | Change |
   |---|---:|
   | sieve | -49.5% |
   | zlib | -22.0% |
   | hash | -19.4% |
   | qsort | -12.9% |
   | syscall | -10.0% |
   | double | -1.6% |
   | aggregate | -16.9% |

   That is roughly -27% against stock, versus the old campaign's -2.9%
   AOT ceiling through the stock loop's boundary: the shared-convention
   entry and exit were the decisive cost, as section 7 predicted. zlib,
   unmoved by every interpreter-side iteration, drops 22%. Caveats: an
   execution oracle (recorded bytes are not re-verified and stores do
   not invalidate; the gates validate every run), offline traces, a
   64-trace budget, and double barely moves (19.5% capture coverage).

   A re-run of the same oracle on the current shape (six-slot accessor,
   countdown, re-pinned context; same captures, gates identical
   including against stock) anchored at -15.3% against the tail-call
   interpreter, preserving the old margin on a faster baseline. The one
   real shift is qsort, -12.9% to -6.7%, because the countdown rewrite
   sped its interpreter baseline specifically.

   The trace macros and generator then moved to block-granular
   accounting, realizing 5.15's prediction and 8c's countdown eviction
   where it belongs: the entry guard proves the body fits before the
   tick end, the back-edge guard proves it for the next iteration,
   straight-line steps carry no accounting at all, early exits charge a
   static pending count, cyclic prologues are charged once where the
   loop begins so the constants hold on every iteration, mcycle
   observers materialize from the pending index, and traces containing
   mcycle-writing steps (PRIVILEGED) are rejected at selection (none of
   the six workloads' captures contain any). Gates held across two
   rounds. The M3 timing carries a conditions caveat the protocol
   requires stating: the block round ran under three times the
   background load of the per-step round (mean 10 against 3.5, the
   repetition peaking at 29), and still measured best-of-two -1.0%
   aggregate, with hash at -24% -- the per-step decrement is a serial
   dependency chain through the countdown register across the whole
   trace body, and hash's long traces were bound by it -- against +5%
   on zlib and double that the load asymmetry can account for. The
   expected beneficiary is x86-64, where the removed per-step work is
   real instruction count and the freed register rotates into trace
   bodies (the args shape spills the entry countdown naturally once no
   step touches it); it travels with the queued Raptor campaign.

   The typed fast pc (5.19) required one repair and rewarded it: trace
   heads must stay keyed by the architectural pc (fast encodings are
   not stable across mappings or runs), so the hook converts at its
   probe sites and the generated back-edge guards compare against the
   eagerly encoded head, with the mapping offset provably stable inside
   a trace. Without the repair every probe misses silently, gates stay
   green, and the oracle measures as nothing, a failure mode worth
   remembering. Re-anchored on the current shape, all gates bit-exact:
   -18.5% against the tail-call interpreter (sieve -52.7%, hash -34.2%,
   zlib -16.8%), the best trace result of the experiment; hash nearly
   doubled its margin as block accounting's removal of the per-step
   countdown chain composed with the typed pc's leaner trace bodies.
3. DONE, FORMATION PROTOTYPE. `-DTC_ONLINE=1` records both loop and call
   heads into a fixed 1024-slot pool, closes traces on cycles, page exits,
   or 64 instructions, installs by bump pointer, uses a separate
   open-addressed installed-head set so collisions in the 64-slot dispatch
   table cannot cause re-recording, and retains a penalty blacklist across
   flush-all. Normal handler chains contain no per-instruction recorder
   call: a hot hook leaves a pending request in the context, returns to the
   outer loop, and recording proceeds through one-instruction chains only
   for the duration of a trace.

   Two code-shape failures were found while bringing it up. Calling recorder
   setup directly from the inlined hook gave every conditional handler a
   frame for a cold call, so setup moved behind the outer-loop boundary.
   More severely, writing the pinned countdown before and inside the
   `recording` conditional made Clang 22 hoist `x24 = 1` onto the false path,
   reducing all execution to one-instruction chains. Computing the countdown
   in ordinary locals and writing the pinned register exactly once after the
   branch fixes the lowering. A full sieve run then recorded 653 traces (62
   short aborts, no flush), retired the stock 16,791,353,500 cycles with the
   identical root hash and exit, and took 26.34 user seconds against the
   measured shell's 25.71 (+2.4%), formation overhead in the same
   low-single-digit range as the shell.

   The prototype deliberately keeps one pool per host thread. Production
   still needs the decided LuaJIT memory policy: allocate the fixed pool at
   machine creation, keep profiling/traces/blacklists per machine across
   interpret() calls, add intrusive per-page membership for store
   invalidation, and flush-all on exhaustion. No recency ordering belongs on
   the entry path; if flush-thrash appears, use an epoch stamp and cold
   second-chance sweep rather than an LRU list.

4. DONE, COPY-AND-PATCH (section 5.20). The backend is stencils compiled
   against the handler contract and patched at run time, so a trace is
   entered and left by a jump with no state marshalled: the objection to
   MIR was that its standard ABI would re-marshal at every boundary, and
   copy-and-patch removes the boundary rather than paying it. 119 of the
   153 cases compile, and the register contract makes register allocation
   a non-question, as predicted. It is exact, cycle- and hash-identical
   over a full boot, and measures -9.1% aggregate over six workloads,
   ranging from -45% where it covers 86% of executed instructions to +5%
   where it covers almost none. That is this section's boundary argument
   paying off where the traces are, and it closes the backend item; what
   the spread now points at is item 3's selection, not item 4's codegen.

   A second, independently chosen set of ten workloads reproduced the
   shape at -5.6% and localized the limit to selection (5.20), and
   section 5.21 then fixed it: the compiled set was missing the
   compressed load/store family for a misattributed reason, and the head
   table was discarding compiled traces permanently and in proportion to
   how many were compiled. The same ten workloads now measure -16.8%,
   against -16.0% for the parallel GNU lightning branch on the same host
   and harness, so the boundary argument of this section is no longer the
   thing under test. Selection is, and it still holds the largest
   identified loss: the head consult refuses 32.7M hits on qsort against
   5.5M entries, because trace identity is the pc alone while the thing
   identified is the pc together with the host page it was read from.

## 8c. The register-budget series: filed ideas and the queued campaign

Section 5.16 established what each of the six slots is for: three
irreducibles (accessor, insn, pc), the fetch-cache pair whose eviction
costs a measured 5-7% because its reads sit at the head of the fetch
chain, and the countdown, whose per-instruction touch is a predictable
write rather than a chain-head read. Four ideas followed, attacking the
slots in that inventory. Two are implemented and have their own history
entries (5.17 and 5.19); two remain filed. None of them is worth
anything on AArch64, where the accounting hides in issue slack and the
pinned shape holds its registers for free; the target is x86-64.

1. FILED. Evict the countdown by unrolling the accounting, not the
   loop. Four phase-templated copies of each handler (the same TC_CASE
   macro with a phase parameter, four generated tables), where phases
   0-2 dispatch with no accounting and phase 3 decrements a
   memory-resident count by four; the outer loop Duff-enters at the
   phase that makes the tick boundary land exactly on a check.
   Exactness survives because the phase is a compile-time constant per
   copy: the mcycle materialization and every exit path fold their
   phase offset. The audited source grows by a phase constant and the
   entry computation; the binary grows 4x (handler text and tables),
   and per-(handler, phase) indirect sites split branch-target history
   four ways, which 5.14's flat branch-miss rates suggest this host
   tolerates. If the segment machinery of 5.17 wins on x86-64, the
   eviction becomes a cheaper increment on it, and its remaining
   ceiling -- by then just the decrement, test, and branch -- can be
   bounded first with an unsound measurement-only build that compiles
   the tick test out (gates knowingly red, timing valid).

2. DONE (section 5.17). Page segments prove straight-line fetches safe
   in advance and demote the fetch tag to the context: a measured
   AArch64 loss, the intended x86-64 code shape, default off, queued
   for hardware.

3. DONE (section 5.19). The typed fast pc dissolves vf_offset into pc
   itself, through both loops; neutral on AArch64, and the last step
   to the four-slot args signature. Its stock-uniformity companion,
   the countdown in the stock loop, is section 5.18.

4. FILED, Linux-only. Registers held purely to reach per-machine state
   (the pinned context pointer in r15, the accessor pointer itself in
   the args shape) can be returned to the allocator by placing the
   pointer in initial-exec thread-local storage
   (-ftls-model=initial-exec, or local-exec in the main executable),
   making each access a single fs-relative load instead of a pinned
   callee-saved register. The pointer is set once at interpret entry
   (one machine per thread while it runs, which interpret already
   assumes), each handler loads it on demand, and the allocator
   regains the register between uses. Caveats: Darwin's TLV mechanism
   and GCC's emutls are call-based (see the dlclose incident of 5.13),
   so this is a Linux-target technique, measured on Raptor or not at
   all; and the accessor pointer through TLS re-adds a per-handler
   load that the current argument passing does not pay, so it prices
   register relief against load slots exactly like the rest of the
   series.

The implemented pair brings the x86-64 args signature to four slots
(accessor, insn, fast pc, countdown) and strips straight-line handlers
to the real work plus dispatch; the filed pair would take it toward the
two-slot floor of 8d. The freed registers and removed instructions are
also exactly what the pre-load lacked on this architecture: its loss
was the predicted state spilling across the execute body (5.14, and
still -1.9% on the six-slot shape), so the pre-load is re-measured on
the four-slot shape rather than written off. Both filed ideas are the
interpreter converging on per-block accounting without translation, the
same amortization traces collect at block lengths of tens instead of
four; if their ceilings do not clear a few percent, the trace path
collects the same win anyway and they stay filed.

### The queued Raptor campaign

Two phases per compiler with the usual gates. Phase one is the landing
gate: main stock against branch stock, which that machine has never
measured with the cold-owner fix, the countdown, and the typed pc
composed (the countdown alone was -5.4% under Clang on the M3, and
instruction count converts to time on this host). Phase two is the
tail-call two-by-two against those same-batch stock anchors:

| | no pre-load | pre-load |
|---|---|---|
| no segments (six slots) | `tailcall=yes` as shipped | `TC_PRELOAD_ENABLED=1` |
| segments + demotion (four slots) | `TC_PAGE_SEGMENT=1` | `TC_PAGE_SEGMENT=1 TC_PRELOAD_ENABLED=1` |

The no-pre-load column isolates the segment machinery, now carrying the
typed-pc dividend (the dispatch fetch is a single load with the
fall-through folded into pc's addressing). The pre-load row tests
whether the freed registers finally let the pre-load pay on this
architecture: its loss was always predicted-state spill traffic, the
demotion at six slots already cut LD's hot-path spill round trips from
five to three, and at four slots 5.14's verdict is genuinely open.
Both configuration recommendations from the second x86-64 round are now
defaults, so the campaign measures the shipped shape: the tail-call
translation unit compiles with -fno-stack-protector, and the pre-load
default follows the pinned shape alone.

## 8d. The register ledger

A running summary of the hot-path register evolution, kept up to date as
the series advances. The measure is the handler contract: the values
that must cross every handler boundary in the args shape, with the
pinned set of the register-global shape alongside.

| stage | args slots | contents | pinned set (AArch64) |
|---|---|---|---|
| original design (section 3) | 9 | a (2 regs), pc, mcycle, tick end, insn, tcc, fetch tag, fetch offset | x23-x28 (6) |
| countdown (5.15) | 8 | mcycle and the tick end fuse into one countdown | x23-x27 (5) |
| one-pointer accessor and penumbra context (5.16) | 6 | a shrinks to one pointer, tcc derived from the state | 5, x27 re-pinned after the offset regression |
| segments plus demotion (5.17) | 5 | the fetch tag moves to the context, read only by control transfers | 5 |
| typed fast pc (5.19) | 4 | the fetch offset dissolves into pc itself | x23, x24, x25, x27 (4) |

Each step removed a register by finding that its content was derivable
rather than essential. mcycle is not architectural between observation
points, only its materialization is, so a countdown and a memory base
replaced the pair. The machine pointer was cold cargo reachable through
the penumbra back-pointer, so the accessor halved. The context sits at a
constant offset from the state, so its pointer became derivable, with
the AArch64 re-pin as the one concession to load immediate range. The
tag is consulted per instruction only when the future is unknown, and
the segment bound proves straight-line fetches safe in advance, so the
tag retreated to control transfers. The fetch offset existed only to
turn pc into an address, so making pc be the address eliminated it,
K-cancellation keeping the architectural pc recoverable exactly.

The visible consequence tracks the slot count: the GCC 16 x86-64
dispatch tail went from 22 instructions with two stack-argument round
trips (8 slots), to 17 in registers (6), to 9 frameless with the check
gone (segments), to about 10 whose entire fetch is one load with the
fall-through folded into pc's addressing mode (4). The stock loop rode
along: the countdown freed one of its two hot loop registers, and the
typed pc merged its pc and offset into one.

The same GCC 16.1 disassembly tracks what the freed registers do to
the pre-load, whose x86-64 loss was always the predicted state
spilling across the execute body (5.14). Hot-path stack round trips
with the pre-load enabled, LD as the representative memory op:

| shape | LD spill round trips | ALU handlers |
|---|---:|---:|
| six slots, pre-load | 5 | some |
| five slots (segments + demotion) | 3 | few |
| four slots (typed pc) | 1 | 0 |

At four slots the predicted word and dispatch target finally fit the
register file, so the pre-load's cost side is one residual spill on
memory ops against its unchanged benefit, the next fetch chain
overlapping the current execute body (the mechanism that collapsed
zlib on AArch64 in 5.9). The 5.14 verdict was rendered at five spills;
the two-by-two campaign re-prices it at one.

The identified floor: insn is the message and pc is the control point,
genuinely irreducible. The countdown can leave via block accounting
(the phase idea of 8c for the interpreter; already real inside traces,
where it is charged per block), and the accessor pointer can leave via
initial-exec TLS on the Linux target (the fourth idea of 8c). The args
contract could therefore reach two slots, insn and pc: an interpreter
whose entire inter-handler state is the instruction and where it came
from, with everything else derivable, deposited, or proven unnecessary
in advance. Whether the slots below six actually price as wins is what
the pending x86-64 campaign measures.

## 9. Validation status

Every timing pair in this document passed cycle, hash, and exit equality
against same-source stock builds, including full Linux boots and the
357-run x86-64 campaign. Section 5.12 records the uarch __LINE__ caveat
that makes same-source a hard requirement, and 5.18 the attribution
protocol used when a change legitimately rebuilds the embedded uarch
image (relink the new build against the old-source image and require
the old anchors bit for bit). The routine gates for any change are the
cm-cli spec suite and the six-workload harness; formatting and format
checks pass.

The copy-and-patch build (section 5.20) is gated the same way and to the
same standard: cycle-, exit- and hash-identical to a same-source no-JIT
build over a full Linux boot and a 2.36G-cycle workload, plus the cm-cli
spec suite at 52/52, under both compilers on x86-64. Its own gaps are
stated in 5.20 and are not covered by those gates: a guest that writes to
a page holding a compiled trace would execute the recorded instructions,
because the write-TLB refusal of 8b item 3 is not built yet, and the
generated stencil table is x86-64 only. Section 5.21 removes one gap that
was not on that list at all: a trace was keyed by the host page of its
*last* recorded instruction, so a recording whose mapping moved under it
-- which one-instruction-per-chain recording allows -- was installed
under a page that did not hold most of its instructions.

The changes of 5.21 were gated to the same standard, with the ten-workload
harness and a 472M-cycle boot-to-halt, under GCC. Two things they were not
run against: the cm-cli spec suite, and Clang.

The ten-workload measurement of 5.20 uses a fixed-work variant of the
protocol, `bench-harness/bench.lua`: each variant is built into its own
directory, boots to 256 Mi mcycles, then runs exactly 1 Gi more, and the
root hash at that exact mcycle is compared across variants. Bounding the
window by mcycle rather than by guest operation count makes the hash gate
exact instead of approximate, which is what lets the timing table double
as the gate; all forty runs of that campaign agreed. Two operational
notes belong with it. `cartesi-machine.lua` does not prepend the build
directory to `package.cpath`, so on a host with the emulator installed a
bare invocation silently gates and times the installed library rather
than the build under test; every invocation must set `LUA_CPATH`. And the
recorder's pools are per-thread statics that outlive a machine object, so
each workload must run in its own process. The `taskset` pinning of 5.20
applies to this harness for the same reason it applies to the other.

Remaining before the experiment can be promoted: the tail-call
translation unit still fails the project's clang-tidy policy
(macro-generated handlers, inline assembly, casts, and the
pinned-register shape, with the lint target also lacking the unit's
compile flags), the full machine and host/uarch test suites have not
been run against the flag, and the generated .inc extraction scripts
and the trace tooling live in a session scratchpad and would need to
become checked-in tools (the .inc files are one-shot extractions and
must be regenerated if the stock switch or jump table changes). The
emutls exit-crash fix in cm.cpp (section 5.13) shipped independently of
the flag.
