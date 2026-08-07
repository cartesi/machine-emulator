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

The online GNU lightning backend now runs on x86-64 as well, and it is
the first configuration on that architecture to beat the stock loop by a
wide margin: -16.0% aggregate over ten workloads against stock and -24.9%
against the pinned tail-call interpreter it rides, on a Raptor Lake i9
under GCC 16 (section 8b, item 9). The split is the one the design
predicts: workloads whose hot code the backend covers collapse (sieve
-68.8%, nop -81.4%, memcpy -68.7%, hash -37.1%), while workloads it
cannot collect pay the recorder's few percent and nothing else (double
+14.8%). The port cost the interpreter nothing and the backend four
bugs, three of them architecture-neutral and latent on AArch64. Those
numbers were taken on the pinned interpreter substrate, itself +11.9%
against stock on that host; the backend contract has since been
re-expressed on the four-slot preserve_none argument shape (8b item
10), which removes that substrate tax and needs no pinned registers,
no reservations, and no compiler restriction on x86-64. It is gated
bit-exact on both architectures; its timing campaign is queued for the
same hardware, and an interim run of the full five-build protocol on
other silicon already confirms the attribution: the args backend beat
the pinned backend on all four uncovered workloads and reached -18.7%
aggregate against stock (8b item 10). A clang-20 build of the same
contract then exposed a live emitter defect the GCC gates could not
see -- a side-trace division spilling through the unmaintained frame
pointer -- which must be fixed before further gating is trusted (8b
item 10).

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

The trace backend is `make tailcall=yes lightning=yes
MYINTERPRET_CXXFLAGS=-DTC_ONLINE=1`, which links the bundled GNU
lightning (`make bundle-lightning`). The generated code emits into the
register contract of the selected interpreter shape: pinned on AArch64,
and on x86-64 the four-slot preserve_none argument assignment (the
build adds TC_PAGE_SEGMENT=1 there, needs GCC 16.1+ or Clang, and
reserves nothing; the pinned x86-64 shape of 8b item 9 remains
reachable with TC_GLOBAL_REGS=1 and GCC, which then implies
TC_USE_PRESERVE_NONE=0 and the r14 reservation). See 8b item 10.

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
16-bit counter prototype), exact persistent trace entries independent of
those counters, exponential retry penalties and eventual blacklisting, and
flush-all when the fixed trace pool is exhausted. LuaJIT does not evict an
installed trace because another PC collides with its hot counter: it patches
the exact bytecode head with the trace number, and patches side exits directly.
In the tail-call structure all of it is
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
   open-addressed installed-head set so counter collisions cannot cause
   re-recording, and retains a penalty blacklist across
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

4. DONE, GNU LIGHTNING GREEN LIGHT. MIR's standard-ABI boundary was avoided:
   GNU lightning 2.2.3 emits directly into the pinned AArch64 handler contract.
   The first vertical slice replaces the hottest cyclic sieve head with a
   generated 440-byte body, keeps state/pc/countdown/fetch/context in
   x20/x23/x24/x25/x27, and branches directly to the interpreter fetch-tail
   continuation on side exits. `jit_tramp(0)` is only lightning's generator
   declaration that this code shares the caller's frame; the emitted body has
   no runtime trampoline, stack adjustment, LR save, prologue, epilogue, or
   argument reshuffle.

   Five M3 Max repetitions after one warmup, all at the identical
   16,791,353,500 cycles, root hash, and exit, measured these medians:

   | sieve variant | wall | user | wall vs portable | wall vs AOT |
   |---|---:|---:|---:|---:|
   | current portable tail-call | 22.34 | 24.19 | -- | -- |
   | 64 compiled-C AOT traces | 10.19 | 12.08 | -54.4% | -- |
   | lightning hottest head | 9.29 | 11.15 | -58.4% | -8.8% |

   This is deliberately a backend-quality probe rather than a full JIT: the
   other 63 installed sieve heads remain the compiled-C AOT bodies, and the
   generated head is specialized from the captured oracle. It nonetheless
   answers the boundary and code-quality questions cleanly. A contract-native
   runtime backend can beat the best AOT result, and the direct entry is real;
   the next implementation step is to lower the online recorder's staged
   trace representation through lightning, then replace the remaining AOT
   bodies and add the per-machine executable pool and invalidation policy from
   item 3.

5. DONE, PHASE-B VERTICAL SLICE. The online recorder now feeds a separate
   Lightning execution/collection object. A thin state-access adapter carries
   that object, but does not implement collection itself. Collector entry
   points are generated from the same `TC_CASE(..., EXPR)` source as the normal
   tail-call handlers, and their 65,536-entry dispatch table is generated from
   the existing `interpret-tc-table.inc`; there is no second decoder or
   instruction-specific staging switch. A temporary capability trait limits
   this first backend slice to operations observed in the hottest sieve
   traces, so unsupported traces return to the recorder's ordinary penalty
   path.

   The online compiler replays the recorded words twice through that collector
   (register discovery, then Lightning emission), installs the resulting head,
   and enters it with the unchanged pinned-register contract. The first
   ten-operation version installed one 472-byte cyclic head. Five M3 Max
   repetitions after one warmup all produced the exact 16,791,353,500 cycles,
   root hash, and guest exit; median wall/user time was 14.35/16.23 seconds,
   35.8% below the portable tail-call wall time.

   The next coverage step began following the LuaJIT policy rather than trying
   to reproduce the offline AOT count. Penalties moved from a colliding 64-slot
   array to a persistent open-addressed table; permanent backend-NYI failures
   blacklist after one attempt, while short formation failures retain three
   rounds of probation. This reduced failed sieve
   recordings from 2,349 to 711 (63 short, 641 compile, 7 dispatch collisions),
   despite adding more candidates. Generated mappings retain their Lightning
   owner and are reclaimed at the existing flush-all boundary.

   Supporting one-shot traces and split prefix/cycle accounting, then adding
   only `C.ADDIW` and `C.BEQZ`, unlocked the decisive second head: a
   64-instruction, 1,644-byte straight trace. Five repetitions after one warmup
   measured 8.67/10.54 seconds wall/user, still bit-exact: 61.2% below portable,
   14.9% below the 64-head compiled-C AOT result, and 6.7% below the hand-written
   Lightning/AOT hybrid. Three more observed semantics installed two small
   388-byte roots (four live heads total); the exact final smoke was 8.61
   seconds, no material improvement, confirming that installed-head count is
   not the target. The remaining production work is the per-machine executable
   pool and per-page invalidation policy from item 3; until then this remains an
   execution oracle for workloads without self-modifying code.

6. DONE, INTEGER COVERAGE AND EXACT HEADS. The collection object now lowers
   the RV64 integer instruction families directly through operation-owned
   callbacks: base and compressed integer arithmetic, comparisons, branches,
   direct and guarded indirect jumps, all integer load/store widths, and the M
   extension including high multiply and RISC-V's division corner cases. The
   normal execution expressions remain the single semantic source; the state
   accessor merely carries the separate execution/collection object. There is
   no central lowering opcode switch.

   Broad coverage exposed the policy error precisely. A one-way 64-head table
   filled with boot and kernel traces, excluding sieve's hot heads; replacement
   thrashed badly, and four-way associativity recovered the workload only as a
   compromise. LuaJIT's actual split is stronger: its 64 hashed counters only
   detect heat, while a successful root is installed at its exact bytecode PC.
   The online backend now mirrors that split with a fixed open-addressed exact
   PC-to-trace map. Hash collisions probe for another slot; they never reject,
   replace, or evict compiled code. An installed hit bypasses hot counting.
   Pool exhaustion keeps the final trace and triggers a global flush only when
   the next recording requests a slot. The AOT table uses the same exact-map
   rule.

   Five M3 Max sieve runs, without a warmup, were 7.85, 7.71, 7.81, 7.63, and
   7.84 seconds wall time (median 7.81; median user 9.61). Every run retired
   exactly 16,791,353,500 cycles with the same final hash and guest exit. All
   four decisive sieve heads installed; the run retained 104 traces, rejected
   687 short formations and 185 backend failures, and performed no flush. The
   exact-head result is 65.0% below the 22.34-second portable tail-call median,
   23.4% below the 10.19-second 64-head compiled-C AOT median, and 9.9% below
   the earlier 8.67-second online median.

7. DONE, CONSERVATIVE TRACE LINKING. Each bounded straight trace now records
   its normal successor and carries a patchable target slot. When either end
   of a predecessor/successor pair is installed, the cold installation path
   patches the slot; the execution entry path remains the exact head lookup
   from item 6. At a linked boundary the generated code flushes the guest
   registers used by that independently allocated fragment and jumps directly
   into the successor, whose normal entry reloads its own allocation. A
   64-instruction fragment may continue recording a successor in the same code
   page, so long in-page paths can form chains without a new hot-head event.

   A same-page link needs no entry or exit stub because both fragments share
   the pinned handler contract and the current fast-pc mapping. Cross-page
   links add a generated code-translation node before the jump. The node
   performs only the verified hot code-TLB path: it checks the recorded
   successor page's hot tag, loads the host offset and PMA index, re-encodes
   the pinned fast pc, and updates the fetch offset, page tag, and context.
   A hit jumps directly to the patched trace. A miss leaves the successor pc
   encoded with the old deposit and branches to the existing fetch
   continuation, which decodes it and performs the normal refill or page walk.
   There is no privilege-address test, baked host mapping, runtime trampoline,
   or page walk in generated code.

   Two rejected policies established the boundary around this mechanism.
   Allowing cross-page traces while leaving the fast pc encoded for the old
   page produced pathological execution; treating only PCs with the high bit
   clear as eligible avoided the symptom but was an architecture-specific
   supervisor/user heuristic and was removed. After the translation node was
   added, automatically admitting every short page fragment was still
   pathological: qsort exceeded 74 seconds while compiling 149 mostly short
   straight fragments before completion. Trace linking is sound, but short
   fragments must not become globally visible before their whole chain proves
   profitable.

   One no-warm-up M3 Max run per workload compared the conservative linker
   with the item-6 exact-head build. All runs reproduced the established guest
   cycles, final root hash, and exit. `links` counts statically patched pairs,
   not dynamic link executions, and the single timings are exploratory:

   | workload | exact heads (wall s) | linked (wall s) | change | installed links |
   |---|---:|---:|---:|---:|
   | sieve | 7.81 (five-run median) | 7.17 | -8.2% | 9 |
   | qsort | 24.86 | 25.21 | +1.4% | 4 |
   | zlib | 25.90 | 25.63 | -1.0% | 9 |
   | hash | 13.85 | 13.74 | -0.8% | 12 |
   | double | 48.06 | 47.98 | -0.2% | 5 |
   | syscall | 22.88 | 22.98 | +0.4% | 9 |
   | **total** | **143.36** | **142.71** | **-0.5%** | **48** |

   Except for sieve, the changes are noise-sized; the result is a correctness
   and mechanism checkpoint, not yet a qsort win. Qsort's hottest offline
   fragments are straight paths of 9, 16, and 15 instructions around a
   5-instruction cyclic comparator loop. The current minimum rejects those
   straight fragments, and the comparator loop leaves through a guarded side
   exit while this stage links only normal straight-trace ends. The four qsort
   links therefore do not form its hot partition/comparator/return cycle.

   The initial x86-64 campaign attributed a 22-cycle full-boot divergence to
   cross-page links and temporarily disabled them. That attribution did not
   survive the completed fix set. With the cyclic call-target trim fixed
   (item 9), cross-page links reproduce the default build byte for byte on
   ARM64 and emulated x86-64 boots and on the three workloads originally
   reported as failures (sieve, zlib, and hash). Reintroducing the cyclic trim
   bug makes both linked and unlinked runs diverge. Cross-page links are
   therefore enabled again; they were not the cause.

8. NEXT, TRANSACTIONAL CHAINS AND SIDE EXITS. Record page-bounded successor
   fragments into provisional pool slots, invisible to the exact head map.
   Commit and patch the group only after it closes onto its root, an installed
   trace, or another profitable cyclic fragment; discard it as a unit on NYI,
   instability, or the length bound. This imports LuaJIT's central policy
   property: a hot root may grow side traces, but an incomplete side path does
   not pollute global dispatch. Each generated guard exit then receives the
   same patchable successor slot and hot-exit counter as a straight end.
   Repeated exits record a provisional side chain and patch directly once it
   closes. Keep all selection and patching off the entry path, measure dynamic
   link hits separately from installed links, and retain the existing exact
   map, persistent NYI blacklist, and flush-all pool policy.

   The first performance gate is qsort: recover its call/comparator/return
   chain without regressing the other five workloads. Once selection proves
   useful, linked fragments can share a register assignment (or carry explicit
   boundary moves) so hot links no longer flush and reload every mapped guest
   register. Per-page membership and invalidation remain required before this
   execution oracle becomes a production JIT.

9. DONE, THE BACKEND ON X86-64. The backend was AArch64-only by
   construction, not merely untested there: it named lightning's
   `JIT_R3`-`JIT_R6` and `JIT_V5`-`JIT_V8`, which do not exist in the
   x86-64 register namespace, and the guard that said so
   (`TC_LIGHTNING currently targets the pinned-register AArch64 shape`)
   sat inside the `#ifndef TC_GLOBAL_REGS` block, so defining that macro
   on the command line bypassed the diagnostic instead of tripping it.
   The handler contract is now expressed once per architecture and the
   emitter names no lightning register of its own:

   | | AArch64 | x86-64 (SysV, GCC) |
   |---|---|---|
   | state pointer | JIT_V1 = x20 | `_RDI` |
   | fast pc, countdown, fetch tag, context | x23, x24, x25, x27 | rbx, r12, r13, r15 |
   | guest registers | 8 | 4 (r14, rsi, r8, r9) |
   | emitter scratch | x9, x22, x26 | rax, r10, r11 |
   | left to lightning | x8, x16-x18 | rcx, rdx |

   Three properties of the host had to be established rather than
   assumed. First, every register generated code touches must be either
   call-clobbered or reserved for the whole translation unit, because the
   interpreter frames below the chain expect the call-saved set intact;
   x86-64 has no spare call-clobbered register once the contract and the
   scratch set are paid for, so r14 is reserved with `-ffixed-r14` and
   added to the boundary save/restore of 5.12, which buys the fourth
   guest register and simultaneously makes it harmless for lightning to
   pick r14 as its own temporary. Second, lightning's allocator hands out
   any register its liveness analysis believes dead, and it cannot see
   that an indirect jump out of generated code leaves with the handler
   contract loaded; the contract registers are therefore declared
   `jit_live` at every leave, which makes them live along every path back
   to the entry. On AArch64 this was free luck: lightning's allocation
   order there begins with x8 and x16-x18, which the backend never uses,
   so it never reached the JIT_V registers. Third, two registers must
   stay free for lightning's own temporaries (large immediates, and the
   fixed operands of x86 shifts, divisions, and high multiplies), because
   a spill under `jit_tramp` addresses through a frame pointer this build
   does not maintain. Clang is rejected at configure time: it has no
   general-purpose global register variables on this target (5.14), so
   `lightning=yes` implies GCC and `TC_USE_PRESERVE_NONE=0` here.

   Four guest registers is too few to compile anything interesting, so
   guests that outgrow the budget now stay in the shadow state and are
   read and written in place instead of failing the trace. The fallback
   is cheap by construction (a spilled guest read is one `ldxi` where a
   mapped one is a `movr`, and it adds no scratch pressure) and it also
   removes an AArch64 ceiling, where traces touching more than eight
   guests failed to compile at all. On x86-64 it is the difference
   between 22 and 161 installed traces on a Linux boot.

   The gates then found four defects, three of them architecture-neutral
   and latent on AArch64 because the shapes that expose them need either
   the spilled-guest fallback or the boot path to occur:

   - `emit_binary` materialized a non-register left operand into the
     destination without checking that the right operand was not already
     living there, so `add rd, rs1, rd` with `rs1` spilled compiled as
     `rd = rs1 + rs1`. Two ordering hazards of the same family were
     repaired with it: the memory-access helpers reloaded the host offset
     before recomputing the address, and the condition helpers evaluated
     both operands at a depth that let the second clobber the first.
   - The W-form bodies lost their 32-bit wrap. `value_cast<uint64_t>` of
     a value the type system already knew was 32 bits wide emitted no
     node, so `value_cast<uint64_t>(wrapping_add(value_cast<int32_t>(rs1),
     imm))` kept the full 64-bit sum where RISC-V requires the low 32
     bits sign-extended. Widening now materializes the narrower type's
     wrap-around at exactly the point the C++ conversion happens. The bug
     is invisible until a 32-bit add or multiply overflows, which is why
     `hash` was the only workload of ten that caught it.
   - The call-target trim that drops a trace's closing return (item 6)
     was applied to cyclic traces too. For those the last entry is the
     instruction that closes the loop, so removing it turned the recorded
     back-edge into an unconditional one that both skipped the closing
     branch and retired one instruction per iteration without charging
     for it. It is now refused for cyclic traces.
   - The first gated run misattributed the cyclic-trim divergence to
     cross-page trace linking. Retesting after the complete fix set shows
     cross-page links exact; see the amendment to item 7.

   The bisection switches that found these are retained as environment
   variables on cold paths (`TC_LIGHTNING_NO_SPILL`, `NO_CYCLE`,
   `NO_LINK`, `NO_SIDE`, `NO_STRAIGHT`, `NO_FAST`, `TRIM`, `MAX_TRACES`,
   `DUMP`); the one that would have sat on the trace-entry path is behind
   `-DTC_LIGHTNING_DEBUG=1`. Isolating a mechanism, then bisecting the
   trace pool, then bisecting the trace length was what made each of the
   four tractable; the last one took four instructions of disassembly to
   read once the length bisection named instruction 63 of a 64-entry
   trace.

   Measured on Raptor Lake (i9-14900K), GCC 16.1.1, ten stress-ng
   workloads run for 1 Gi guest cycles each after a 256 Mi boot, median
   of three repetitions. Fixed guest work makes wall time the only
   variable, and the root hash at the same mcycle is the gate: all ten
   workloads and a full boot-to-halt matched the stock build byte for
   byte on every configuration in the table.

   | workload | stock | pinned TC | + recorder | lightning | vs stock | vs pinned |
   |---|---:|---:|---:|---:|---:|---:|
   | sieve | 1.116 | 1.239 | 1.321 | 0.348 | -68.8% | -71.9% |
   | nop | 0.635 | 0.627 | 0.660 | 0.118 | -81.4% | -81.2% |
   | memcpy | 1.062 | 1.306 | 1.442 | 0.332 | -68.7% | -74.6% |
   | hash | 1.146 | 1.304 | 1.369 | 0.721 | -37.1% | -44.7% |
   | zlib | 1.317 | 1.436 | 1.494 | 0.945 | -28.2% | -34.2% |
   | regs | 0.804 | 0.876 | 0.863 | 0.632 | -21.4% | -27.9% |
   | qsort | 1.366 | 1.534 | 1.611 | 1.410 | +3.2% | -8.1% |
   | branch | 1.139 | 1.209 | 1.210 | 1.192 | +4.7% | -1.4% |
   | tree | 2.480 | 2.839 | 2.893 | 2.696 | +8.7% | -5.0% |
   | double | 2.940 | 3.297 | 3.313 | 3.375 | +14.8% | +2.4% |
   | **total** | **14.005** | **15.667** | **16.176** | **11.769** | **-16.0%** | **-24.9%** |

   That is 767 MIPS aggregate for stock against 912 for the backend, with
   3.1 GIPS on sieve and 9.1 on nop. Each workload installs 210-270
   traces with no pool flush and 25-49 patched links.

   Two readings of the table matter more than the aggregate. The backend
   must ride the pinned tail-call interpreter, which costs +11.9% against
   stock on this host (consistent with the +8.2% of 5.14 for the pinned
   GCC shape, on a source three register-budget steps newer), so about
   twelve of the twenty-five points it wins over its own baseline are
   spent reaching that baseline; a backend on the argument shape, if the
   contract could be expressed there, would start from stock instead.
   And `double` is the honest floor of the whole approach: the backend
   does not collect floating point, so that workload pays the recorder's
   few percent and receives nothing, which is the shape every uncovered
   workload will have until coverage grows.

10. DONE, GATED, THE ARGS-SHAPE CONTRACT ON X86-64. Item 9's closing
    observation became the work: the backend rode the pinned interpreter
    only because pinning was the one expressed register contract, and the
    substrate tax was twelve of its twenty-five points. With GCC 14/15 out
    of scope the pin has no other x86-64 justification, so the contract
    was re-expressed on the four-slot preserve_none argument assignment.
    A probe settled the register question first: GCC 16.1 and Clang 22
    assign preserve_none arguments identically on both architectures
    (x86-64: r12, r13, r14, r15, then rdi, rsi, with GCC stopping at six
    and Clang continuing through rdx, rcx, r8, r9, r11, rax; AArch64:
    x20-x28 then x0-x2), so one args contract per architecture serves
    both compilers, and the four slots land in SysV callee-saved
    registers that survive cold helper calls for free.

    The port had two layers. First, TC_PAGE_SEGMENT composed with the
    shell, the recorder, and the backend (the fences fell; only the AOT
    prototype stays fenced). Trace dispatch sites extend the countdown to
    the true tick end before entering generated code (base and countdown
    move together, preserving the materialization identity, and removing
    the spurious entry bails a page-end segment bound would cause), the
    fetch-tail continuation re-tightens from the trace's final pc before
    the chain resumes, and recording chains move both countdown bases so
    segment expiry cannot extend a one-instruction chain past its
    instruction. Second, the contract itself: state pointer r12, fast pc
    r14, countdown r15, insn r13 dead but untouched; the fetch tag and
    the context hold no registers, context fields reached from the state
    pointer at a constant disp32 offset. The guest roster grows to five
    (rbx, rdi, rsi, r8, r9) against the pinned shape's four, scratch and
    lightning's rcx/rdx are unchanged, and nothing is reserved: under the
    preserve_none chain the entry call site already assumes every
    register clobbered, so the call-clobbered-or-reserved rule of item 9
    is vacuous and -ffixed-r14 plus its boundary save/restore slot
    retreat to the pinned shape. `lightning=yes` on x86-64 now selects
    this shape (TC_PAGE_SEGMENT=1, preserve_none required, GCC 16.1+ and
    Clang both accepted, GCC's musttail applied); the pinned x86-64 shape
    remains reachable with TC_GLOBAL_REGS=1. Two mechanical consequences:
    the collection entry points needed inert countdown state (the case
    expressions name it for their mcycle argument, and the args shape
    resolves those names to handler locals), and the two lightning
    continuations became templates because the args shapes spell the
    STATE_ACCESS type in the handler parameter list.

    Gates, no timing (emulated wall time is meaningless). On the M3,
    stock and pinned-lightning builds of the ported source were byte
    identical on a Linux boot and a full sieve (262 traces installed, 104
    links, no flush), so the port is a no-op for the shipped AArch64
    shape. On emulated x86-64 under GCC 16.1, stock, the four-slot
    interpreter, and the four-slot backend agreed byte for byte on
    cycles, root hash, and guest exit across boot, sieve, hash, and qsort
    (sieve installed 246 traces and 89 links with no flush, and hash is
    the workload that catches W-form wrap defects). The x86-64 root
    hashes equal the M3's on every gate, the determinism guarantee doing
    double duty as a cross-architecture check.

    The queued campaign on the i9-14900K prices the port. Protocol: the
    fixed-work harness of section 9 (bench-harness/bench.lua), the ten
    workloads of item 9, 256 Mi boot plus 1 Gi measured cycles, median
    of three repetitions, every run gated on the root hash at the exact
    final mcycle against the same-day stock anchor. Five same-source
    builds:

    1. stock, the anchor;
    2. the four-slot interpreter (`tailcall=yes` with
       `MYINTERPRET_CXXFLAGS=-DTC_PAGE_SEGMENT=1`), re-anchoring the
       -1.3% of 8c, which was measured on different silicon;
    3. the four-slot interpreter with the recorder armed
       (`-DTC_PAGE_SEGMENT=1 -DTC_ONLINE=1`, no lightning), pricing
       shell plus formation on the args substrate;
    4. the args-contract backend (`tailcall=yes lightning=yes
       MYINTERPRET_CXXFLAGS=-DTC_ONLINE=1`, GCC 16.1);
    5. the pinned backend of item 9 (`TC_GLOBAL_REGS=1` with
       `TC_USE_PRESERVE_NONE=0`, GCC), same day, so the two contracts
       compare on one set of anchors instead of across campaigns.

    Predictions, recorded before the run. Build 2 lands near stock,
    around -1.3%. Build 3 adds the recorder's low single digits,
    concentrated where hook events are dense. Build 4 roughly keeps
    build 5's absolute times on the covered workloads (the trace bodies
    are the same code modulo register naming, with five mapped guests
    instead of four working in its favor), while the uncovered
    workloads (double, tree, branch, qsort) fall from their
    pinned-substrate prices to roughly build 3's, so the aggregate
    against stock should improve from item 9's -16.0% by most of the
    twelve-point substrate tax. If build 4 fails to beat build 5 on the
    uncovered workloads, the substrate-tax attribution of item 9 is
    wrong and the difference lives in the contract itself. A secondary
    question rides along at no protocol cost: build 4 under Clang, the
    first backend configuration that compiler can build on this
    architecture, priced against the same anchors.

    An interim run of the exact five-build protocol was measured before
    the i9-14900K campaign, on different silicon: a 4-vCPU cloud Intel
    Xeon (2.80 GHz, generic virtualized model), Ubuntu 24.04, GCC 16.0.1
    trunk 20260315 (r16-8100, pre-release with preserve_none). Same
    source for all five builds, same compiler, non-interpreter objects
    shared byte for byte; the pinned build reproduced item 9's shape
    against the new Makefile defaults with TC_GLOBAL_REGS=1,
    TC_USE_PRESERVE_NONE=0, TC_PAGE_SEGMENT=0 and the r14 reservation
    passed by hand (TC_FFIXED_FLAGS=-ffixed-r14). All 150 runs gated:
    one root hash and one final mcycle per workload across every
    variant and repetition. Medians of three interleaved repetitions:

    | workload | stock | four-slot | + recorder | args backend | pinned backend | args vs stock | args vs pinned |
    |---|---:|---:|---:|---:|---:|---:|---:|
    | sieve | 2.522 | 2.488 | 2.666 | 0.727 | 0.710 | -71.2% | +2.4% |
    | nop | 1.324 | 1.146 | 1.198 | 0.247 | 0.264 | -81.3% | -6.4% |
    | memcpy | 2.333 | 2.575 | 2.970 | 0.717 | 0.761 | -69.3% | -5.8% |
    | hash | 2.446 | 2.585 | 2.714 | 1.478 | 1.484 | -39.6% | -0.4% |
    | zlib | 2.762 | 2.861 | 3.080 | 2.005 | 2.075 | -27.4% | -3.4% |
    | regs | 1.654 | 1.721 | 1.759 | 1.281 | 1.624 | -22.6% | -21.1% |
    | qsort | 3.052 | 3.258 | 3.448 | 2.699 | 3.030 | -11.6% | -10.9% |
    | branch | 2.512 | 2.676 | 2.739 | 2.667 | 2.688 | +6.2% | -0.8% |
    | tree | 6.189 | 6.656 | 6.711 | 6.120 | 6.694 | -1.1% | -8.6% |
    | double | 7.488 | 7.779 | 7.970 | 8.305 | 9.006 | +10.9% | -7.8% |
    | **total** | **32.282** | **33.745** | **35.255** | **26.246** | **28.336** | **-18.7%** | **-7.4%** |

    Against the recorded predictions. Build 2 did not land near -1.3%
    on this host: the four-slot interpreter costs +4.5% aggregate here
    (sieve alone matches at -1.3%; nop is -13.4%, memcpy +10.4%), so
    that re-anchor remains open for the Raptor Lake run. Build 3 adds
    +4.5% over build 2, the top of the predicted low single digits.
    Build 4 kept or beat build 5's absolute times on every covered
    workload, with regs the standout at -21.1% (the fifth mapped guest
    working exactly as predicted), and the uncovered workloads fell
    from their pinned prices as predicted: branch and tree land at or
    below build 3, double lands within +4.2% of it, and qsort improves
    outright to -11.6% against stock. The falsification test failed to
    fire: build 4 beats build 5 on all four uncovered workloads (qsort
    -10.9%, branch -0.8%, tree -8.6%, double -7.8%), so the
    substrate-tax attribution of item 9 stands. Aggregate on this host:
    pinned backend -12.2% against stock, args backend -18.7% (333 MIPS
    stock, 409 args).

    The secondary Clang question was then answered on the same host
    with clang-20 (the environment cannot reach apt.llvm.org, so Clang
    22 itself was not installable; clang-20.1.2 passes the contract
    probe with the identical r12-r15 assignment). The build compiles,
    and what runs, gates: sieve, nop and qsort match the campaign
    hashes, with paired interleaved runs putting the clang backend
    within noise of the GCC one (sieve +1.3%, nop -4.7%, qsort -3.7%).
    The other seven workloads segfault during boot, and the crash
    diagnosed to a live architecture-neutral emitter defect, not a
    clang miscompile. TC_LIGHTNING_DUMP output is byte-identical
    between the two builds up to the crash, and the fault lands in
    generated code at `mov %rax,-0x8(%rbp)` ahead of `xor %rdx,%rdx;
    div %r10`: a division's fixed operands ran lightning out of
    temporaries inside a side trace with spilled guests, and its
    allocator spilled under jit_tramp through the frame pointer this
    build does not maintain -- the exact hazard item 9's
    two-free-registers rule was meant to exclude, one register short
    for this shape. The GCC build emits the identical bytes at the
    identical buffer offset (verified by scanning its generated pages
    at the end of the same boot), so every gated GCC run of that trace
    has been silently storing eight bytes through a stale %rbp that
    happens to be mapped and dead there; clang-20 merely reaches the
    trace with %rbp holding an unmapped value and turns the scribble
    into a segfault. TC_LIGHTNING_NO_SIDE=1 or TC_LIGHTNING_NO_SPILL=1
    avoids the shape and completes with the campaign hash. The fix
    belongs to the emitter: division and remainder need a third
    guaranteed-free register, or operands pre-materialized through
    backend scratch, before the two-register rule can be called
    sufficient.

    One protocol note rode along: a fresh stock pass taken with the
    clang pairs ran 11-27% faster than the morning anchors on this
    shared host, so absolute times drift between sessions here and
    only interleaved same-session ratios are meaningful. The campaign
    tables above are internally interleaved and unaffected.

## 8c. The register-budget series: filed ideas and the four-slot campaign

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

### The four-slot x86-64 campaign

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

The argument-signature build error was repaired on the x86-64 fixes
branch. A subsequent run on a different x86-64 processor measured the
four-slot argument shape both without and with the next-instruction
pre-load (`PL`):

| workload | stock | four-slot | four-slot + PL | four-slot vs stock | PL vs four-slot |
|---|---:|---:|---:|---:|---:|
| sieve | 7.57 | 6.80 | 8.27 | -10.2% | +21.7% |
| qsort | 10.13 | 10.36 | 11.45 | +2.3% | +10.5% |
| zlib | 18.49 | 17.87 | 21.90 | -3.4% | +22.6% |
| hash | 2.24 | 2.16 | 2.36 | -3.6% | +9.6% |
| double | 22.41 | 22.76 | 22.71 | +1.6% | -0.2% |
| syscall | 3.29 | 3.31 | 3.56 | +0.7% | +7.5% |
| **total** | **64.12** | **63.26** | **70.25** | **-1.3%** | **+11.1%** |

The four-slot shape is therefore the fastest portable x86-64 result in
this run, slightly ahead of stock in aggregate. The hoped-for pre-load
reversal did not occur: it loses 11.1% overall and loses materially on
five of the six workloads. Four argument slots describe only the values
crossing the handler boundary. Pre-load then keeps the predicted word and
dispatch target live across the current execute body, consuming the
capacity that the reduced signature freed. Earlier six-slot counters and
disassembly identified spill traffic as the loss there, but these timings
alone do not establish the residual four-slot mechanism. Distinguishing
spills and moves from front-end pressure or discarded predictions requires
disassembly and hardware counters from this measured build on the same
processor; until then the cause remains open and PL stays disabled.

One anchor from the campaign's target hardware does exist, taken as a
by-product of the backend port (8b, item 9): on the i9-14900K under GCC
16.1.1, the pinned tail-call interpreter measures +11.9% against stock
over ten workloads at 1 Gi guest cycles each. That is the same sign and
roughly the same magnitude as 5.14's +8.2% for the pinned GCC shape,
measured on a source that has since gained the countdown, the six-slot
accessor, and the typed pc, which is itself the finding: none of the
register-budget series has yet moved the pinned shape's x86-64 deficit,
and the shape survives only because the backend needs its register
contract.

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

The x86-64 backend campaign of 8b item 9 used a fixed-work variant of
the protocol, now checked in as `bench-harness/bench.lua`: each variant
is built into its own directory, boots to 256 Mi mcycles, then runs a
further 1 Gi, and the root hash at that exact mcycle is compared across
variants. Fixed guest work makes wall time the only variable and makes
the hash gate exact rather than approximate. Two operational notes cost
time and are worth recording. `cartesi-machine.lua` does not prepend the
build directory to `package.cpath`, so on a host with the emulator
installed a bare invocation silently gates and times the *installed*
library; every invocation must set `LUA_CPATH`. And the online
recorder's trace pool is a per-thread static that outlives a machine
object, so each workload must run in its own process or traces recorded
against one machine's mapping are offered to the next.

Remaining before the experiment can be promoted: the tail-call
translation unit still fails the project's clang-tidy policy
(macro-generated handlers, inline assembly, casts, and the
pinned-register shape, with the lint target also lacking the unit's
compile flags), the full machine and host/uarch test suites have not
been run against the flag, the default x86-64 argument shape (six
slots, no segments) still does not compile because the typed-pc
migration never reached it (the four-slot segment shape is the one that
compiles and gates, sections 8c and 8b item 10), and the generated .inc
extraction scripts and the trace tooling live in a session scratchpad
and would need to become checked-in tools (the .inc files are one-shot
extractions and must be regenerated if the stock switch or jump table
changes). The emutls exit-crash fix in cm.cpp (section 5.13) shipped
independently of the flag.

The backend carries its own promotion list, unchanged in substance by
the x86-64 port. It remains an execution oracle: recorded code bytes
are re-validated only through the code-TLB tag at entry and at
cross-page boundaries, there is no per-page trace membership and
therefore no store invalidation, so it is valid for gated benchmarks
and not for production. One open defect is known and live: side-trace
division with spilled guests can run lightning's allocator out of
temporaries and spill under jit_tramp through the unmaintained frame
pointer -- the GCC build has been executing that silent eight-byte
store through a stale, luckily-mapped %rbp on gated runs, and the
clang-20 build turns it into a boot segfault on seven of ten workloads
(8b item 10). Coverage stops at the integer instruction
families, which the `double` column prices exactly. And the pinned
x86-64 register contract is at its floor: with four guest registers,
one more consumer of the register file would have to come out of the
spilled-guest fallback rather than out of the budget (the args contract
of 8b item 10 relaxes this to five guests with none reserved).
