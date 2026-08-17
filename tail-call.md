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
contract then exposed a live defect the GCC gates could not see -- a
side-trace division spilling through a frame pointer the build never
established, lightning's tramp precondition having been broken from
day one -- now fixed by establishing a real frame in penumbra scratch
at every generated entry, at no measurable cost; the clang-20 backend
then completes all ten workloads gated, 4.7% faster in aggregate than
the GCC one (8b item 10).

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

The trace backend is `make tailcall=yes lightning=yes`; `lightning=yes`
enables the online recorder and links the bundled GNU lightning (`make
bundle-lightning`). The generated code emits into the
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

   A useful comparison point is Ayush Shukla's RISC-V block recompiler
   (https://shuklaayu.sh/blog/riscv-recompiler): every generated block uses
   the same selected hot guest-register set, and `preserve_none` plus
   `musttail` carries unchanged values across block edges without spills or
   moves. Try that fixed common mapping as the simplest linked-fragment shape,
   selected from whole-workload guest-register frequency, against both the
   current independent allocations and predecessor-compatible allocations
   with explicit boundary moves. Keep it experimental: the same measurements
   show that a wide fixed argument set can lose when its extra register
   pressure outweighs the saved boundary traffic.

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
    avoids the shape and completes with the campaign hash.

    The repair did not stay in the register discipline. jit_tramp(N) is
    a promise from the caller -- assume callee-saves are saved and at
    least N stack bytes exist (body.texi) -- and lightning's spill
    slots are FP-relative with no spill-free mode, so declaring tramp 0
    without ever establishing FP had broken the library's precondition
    from day one; the div spill was merely the first allocator spill to
    land on the broken promise. The fix makes the promise true: every
    generated entry (normal, linked, call; side traces are fragments
    with their own entries) saves the incoming rbp at a frame base in
    the tail of the machine's penumbra scratch, points FP there, and
    declares jit_tramp(256) for bytes actually reserved; every leave
    restores rbp through the same constant offset. Lightning may now
    spill whenever its allocator wants, and the two-registers rule
    stops being a correctness rule. One contract correction was found
    on the way: rbp is NOT clobberable under the preserve_none chain.
    Probed on both compilers, GCC 16 and clang-20 keep values live in
    rbp across preserve_none calls -- only rsp joins it in the
    preserved set -- so item 10's "every register clobbered at the
    entry call site" holds for all registers except rbp, and generated
    code must treat rbp as the callee-saved register it uses (a
    clobbering variant of the fix crashed the GCC build, whose chain
    keeps state in rbp, while clang's chain happened not to). The
    pinned x86-64 shape keeps the spill-forbidding discipline (tramp 0,
    rbp untouched); AArch64 has never reached a spill and its emitted
    code is unchanged.

    Post-fix, the same interleaved protocol (ten workloads, three
    reps, every run gated on the campaign hashes -- all 90 runs
    passed): the fix costs nothing measurable on the GCC backend
    (-0.5% aggregate, within noise), and the clang-20 backend, now
    completing all ten workloads, is -4.7% aggregate against the GCC
    one, with regs the standout at -22.2%:

    | workload | args pre-fix | args fixed (GCC 16) | args fixed (clang-20) |
    |---|---:|---:|---:|
    | sieve | 0.640 | 0.614 | 0.622 |
    | nop | 0.205 | 0.207 | 0.221 |
    | memcpy | 0.578 | 0.599 | 0.606 |
    | hash | 1.225 | 1.221 | 1.241 |
    | zlib | 1.708 | 1.727 | 1.697 |
    | regs | 1.080 | 1.076 | 0.837 |
    | qsort | 2.179 | 2.212 | 2.095 |
    | branch | 2.306 | 2.342 | 2.251 |
    | tree | 5.384 | 5.216 | 4.909 |
    | double | 6.096 | 6.073 | 5.810 |
    | **total** | **21.401** | **21.287** | **20.289** |

    One protocol note rode along: a fresh stock pass taken with the
    clang pairs ran 11-27% faster than the morning anchors on this
    shared host, so absolute times drift between sessions here and
    only interleaved same-session ratios are meaningful. The campaign
    tables above are internally interleaved and unaffected.

    The claimed AArch64 no-op was then confirmed natively on the M3.
    Pre-fix and post-fix builds of the pinned backend agree byte for
    byte on cycles, root hashes, and guest exits over full sieve,
    hash, and qsort runs, with recorder statistics identical line for
    line (262 traces installed, 104 links, 54 register links, equal
    load/store counters), and interleaved medians of three repetitions
    within noise (sieve -0.5%, hash -0.3%, qsort -0.2%). The frame
    establishment is compiled only into the args-shape entries, and
    this measurement closes the loop on that claim.

11. DONE, GATED, PER-PAGE STORE INVALIDATION. The execution-oracle
    caveat was the standing production blocker: recorded bytes were
    re-validated only through the code-TLB tag, so a guest store over
    traced code would leave installed traces executing the old program,
    and every measured run was certified only after the fact by its
    hash gate. The repair realizes item 3's filed policy, built on one
    invariant: a page hosting recorded trace bytes is never mapped by a
    hot write-TLB slot. While a page sits in a hot write slot, stores
    to it are silent, so the write TLB is the observability boundary.
    Installation evicts the trace's source pages from the hot write set
    (hot side only; the shadow TLB is architectural state and stays
    untouched, so hashing sees nothing), and the machine notifies a
    penumbra-resident write hook wherever a page becomes store-writable
    again (the slot fill after a walk, and the re-verifying promotion a
    poisoned slot goes through) or is written outside the TLB entirely
    (the dirty-marking choke point, which covers page-table A/D updates
    and slow stores, and the host-side writers write_memory,
    fill_memory, and write_word, which cmio and virtio funnel through).
    The hook is null unless the backend arms it, costs two instructions
    on cold paths and nothing on any hot path, and the generated store
    fast path is untouched: a store hitting a poisoned slot simply
    misses and side-exits, which is also how a trace storing over its
    own code invalidates itself before the store retires.

    Membership is an open-addressed host-page set (host pages, not
    virtual: aliased mappings reach the same bytes), with each trace
    recording the pages its bytes came from. Invalidating a written
    page kills its traces: a dead flag makes the exact and side head
    maps report absence, which both stops dispatch and makes the head
    hot-countable and re-recordable again; incoming patchable link
    slots are cleared by code-range comparison, effective immediately
    because generated code loads them per execution; and the pool slot
    with its generated code survives until flush-all, so no pointer
    into a dead trace ever dangles. Two windows closed on the way.
    Stores during a recording session run through hot slots and are
    silent, so installation re-verifies every recorded word against
    guest memory before freezing its semantics into generated code.
    And an instruction whose bytes cross a page boundary keeps its
    second half on a page the entry's mapping offset says nothing
    about, so such recordings are refused outright, which also keeps
    the verification read in bounds and the membership exact.

    Gates, both architectures, on top of the item 10 campaign results.
    Boot, sieve, hash, and qsort reproduce the recorded hashes byte for
    byte with the mechanism armed. A new SMC gate pauses two billion
    cycles into sieve, overwrites the executing code page with
    compressed illegal instructions through the host API, and resumes
    to a fixed target: stock and backend agree exactly, and the M3 and
    the emulated x86-64 produce the same final root hash, the
    determinism guarantee holding through a mid-run host write and the
    invalidations it triggers (six on the M3, five on x86-64). The
    counters also caught what the oracle era could not see: even a
    plain sieve boot writes over pages hosting traced boot-loop code
    (one invalidation and a few verify rejections per run), stale
    execution the gates never observed only because those traces
    happened not to be re-entered afterward. The backend no longer
    depends on that luck.

    The interim host priced the mechanism ahead of the queued Raptor
    campaign, with the section-9 protocol interleaving pre- and
    post-invalidation builds of the same source (150 runs, every hash
    identical to the campaign anchors, the hook armed throughout).
    Stock is untouched at -0.3% aggregate -- the null-hook checks on
    the write-TLB and dirty paths price at nothing, as predicted -- and
    the backend pays +1.3% aggregate (seven of ten workloads a point or
    two up), the install-time re-verification and page bookkeeping
    priced against the coherence they buy. The backend's aggregate
    against same-tip stock is -18.6%, unchanged from the pre-mechanism
    -18.7%.

    The per-machine pool followed. tc_online_state was a per-thread
    static that outlived machine objects; it now follows the write
    hook's ownership pattern -- the penumbra carries an opaque tc_state
    pointer with a tc_state_free destructor, the machine destructor
    releases it, and the loop allocates on first use -- so traces,
    maps, penalties and generated code die with the machine that
    produced them, and the TC_ONLINE_STATS report moves from a process
    atexit hook into the deleter, one report per machine. Gated on the
    campaign hashes, plus a new gate the old lifetime could not pass:
    two machines running sieve and qsort interleaved in one process in
    64 Mi windows, then a third machine after both are destroyed, each
    reproducing its canonical single-machine hash exactly.

11. DONE, GATED, FLOATING POINT: HARD FLOAT AND TRACE COVERAGE. Two
    layers, ported and built in one pass on the interim host. First the
    eb-hard-floats branch's fast path came aboard unchanged: add, mul,
    fma, div and sqrt run on the host FPU when uniform guards prove the
    result and flags bit-identical to soft-float (round-to-nearest
    resolved, NX already sticky, operands zero-or-normal, result
    strictly normal), everything else falls back, and the scope
    arms only when the host FP environment is at its defaults. All
    hashes exact; double fell 14% on stock and 22% on the backend,
    which moved from +9% over stock on its worst workload to parity.

    Then trace coverage. The FP bodies compute on concrete words and
    cannot stage through the collecting access, so coverage takes two
    shapes. FP loads and stores stage as inline IR -- the integer
    memory ops' hot-TLB fast path, the f register file reached directly
    in the shadow with no roster slots, NaN-boxing an or-mask, FS
    guarded in three instructions because this implementation keeps FS
    binary (enabling forces Dirty and write_f never touches mstatus).
    The FD and FMADD families stage as one call each into the real
    execute body on the live machine state, hard-float accelerated
    inside; the helper pre-bails on exactly the raise conditions (FS
    off, invalid dynamic rounding mode -- decode illegality cannot
    reach an installed trace while byte verification and store
    invalidation hold), so it retires completely or touches nothing,
    and non-success exits like a guard miss. The call protocol flushes
    and reloads the caller-saved half of the roster, and helpers
    realign rsp themselves (the chain runs at 8 mod 16). Gated
    bit-exact across the suite.

    The payoff was not where expected, and the diagnosis produced a
    measured policy problem. Recordings on double never reached the FP
    instructions: its hot method bodies run past max_len = 64 before
    closing their cycle (user-space aborts were dominated by exactly
    that length), so the recording cap, not staging, was the coverage
    limit. Raising it to 256 lifted double's installs from 213 to 305
    with every gate intact, but priced the integer suite as a
    redistribution: nop -52% (its 66-instruction cycle finally closes),
    regs -37% (through long straights), sieve +9.8% and qsort +11.7%
    (recording four times longer before a reject on churn-heavy
    formation), aggregate a wash at -0.2%. A cycle-only variant that
    truncated non-cyclic recordings back to 64 at publication kept
    nop's win, lost regs' (a straight win), and recovered neither
    qsort nor sieve, isolating their regression to recording length
    itself rather than to the installed straights.

    The conflict resolved as a per-head dynamic cap, because the
    failure type at finish is already the signal: a recording that
    ends cap-bound without closing a cycle is length-starved, not
    malformed, so it doubles its head's cap toward 256 and abandons
    without penalty -- bounded spend per head, since the shifts only
    grow twice and the penalty wall still catches heads that keep
    failing at full length -- while a closed cycle proves the length
    its head needs and shrinks the cap to the smallest fit. The state
    shares the penalty set's keying and survives flushes with it.
    Measured with the section-9 protocol (90 interleaved runs, every
    hash the campaign anchor's):

    | workload | stock hard-float | backend cap 64 | backend dynamic | dyn vs 64 |
    |---|---:|---:|---:|---:|
    | sieve | 2.126 | 0.607 | 0.530 | -12.7% |
    | nop | 1.268 | 0.212 | 0.103 | -51.4% |
    | memcpy | 2.121 | 0.604 | 0.610 | +1.0% |
    | hash | 2.232 | 1.247 | 1.239 | -0.6% |
    | zlib | 2.546 | 1.723 | 1.735 | +0.7% |
    | regs | 1.616 | 1.080 | 0.695 | -35.6% |
    | qsort | 2.595 | 2.161 | 2.165 | +0.2% |
    | branch | 2.172 | 2.330 | 2.305 | -1.1% |
    | tree | 4.920 | 5.007 | 5.039 | +0.6% |
    | double | 4.372 | 4.688 | 4.736 | +1.0% |
    | **total** | **25.968** | **19.659** | **19.157** | **-2.6%** |

    The dynamic cap dominates both static settings: every flat-256 win
    survives (nop -51.4%, regs -35.6%), every flat-256 tax vanishes
    (qsort +0.2%; sieve turns its +9.8% loss into a -12.7% win from
    selective escalation), and no workload pays more than one percent.
    Short aborts fall by two thirds because starved heads escalate
    once instead of dying at 64 repeatedly. The backend stands at
    -26.2% aggregate against hard-float stock on this host.
    Loop-versus-call hotness separation remains the open policy item.
    double itself is a wash under the helper-call FP coverage (the
    helpers price near the interpreter's own hard-float bodies, so
    only the dispatch around FP is saved); inlining guarded host-FPU
    sequences into generated code is the next coverage lever.

    The inline emission was then built, in two increments, through the
    same type change that stages the integer bodies: the collecting
    access's fcsr and mstatus reads became tokens whose comparisons
    emit guards (the FS-off check is the FS guard, a dynamic rounding
    mode registers the frm guard), float_unbox carries operands into
    typed register handles whose sign flips map to hardware negates,
    fp_* dispatch points named by the bodies (concrete words still
    route to i_float) emit lightning's portable FP ops -- fmar/fmsr
    and friends map one-to-one onto the FMADD family, gated on host
    FMA because lightning silently emits a double-rounded mul-add
    without it -- and the write of the provably unchanged fcsr elides.
    All guard misses of one instruction share one side exit. The
    second increment added compares (whose 0/1 result stages through
    a context slot as integer IR, so compare-and-branch pairs compile
    end to end), sign injection and moves (pure integer IR on a
    word-typed view of the register file), and the float-width
    conversions. FCLASS, FMIN/FMAX and the int-float conversions
    still decline to the helpers. Inline FP is x86-64-only until the
    AArch64 v-register question is audited.

    Two findings came out of the measurement, both worth more than
    the feature. First, guard strength must be derived per family
    from its own proof, not inherited: a first cut borrowed the
    arithmetic zero-or-normal operand guard and strictly-normal
    result guard for compares and widening, and ran double at twice
    the helper build's time with byte-identical trace formation -- an
    infinity in a hot compare and every zero through a widen bailed
    per iteration, and the exit-and-re-enter churn ate the loops.
    Compares round nothing and can raise only NV, which needs the NaN
    a not-NaN guard excludes; widening is exact for every non-NaN
    including infinities and subnormals and needs no result guard at
    all. Both versions were sound -- hashes never wavered, which is
    exactly why the correctness gates could not see the difference --
    and only the paired timing could. Second, with the guards right,
    inlining priced at parity with the helpers: 90 gated runs, medians
    over three interleaved repetitions on the interim host (derated
    about 20% by a restart mid-session, which the interleaving
    absorbs), inline vs helper aggregate +0.2%, every workload within
    +-5%, double -0.3%. The inlined families were not the bottleneck:
    double's hot loop still takes its helper trips at the declined
    int-float conversions, and elsewhere FP is too sparse for the
    difference between a twenty-instruction helper call and an inline
    sequence to matter. Before more emission work, the next diagnostic
    is a per-family bail and decline counter to attribute double's
    remaining +9% over hard-float stock -- the qsort lesson again:
    coverage and dynamic behavior, not per-edge cost, tend to bind.
    The int-float conversions (host truncation is RTZ, which compiled
    code encodes statically, plus encoding-order range guards against
    the saturation cases) are the designed next increment if the
    counters say they matter.

    The AArch64 follow-up separated formation from execution policy.
    Publishing independently compilable page-local regions from a bounded
    recording does reach the FP bodies that the old atomic transaction
    discarded. Lightning's `JIT_F0`-`JIT_F2` mapping to v8-v10 is usable
    under the JIT's `preserve_none` tail-call contract, and the resulting
    traces remain hash-exact. It is not safe to enable blindly, however: a
    seven-instruction hash loop (integer-to-double helper followed by inline
    add and multiply) repeatedly misses the inline guards and becomes more
    than ten times slower. Dense helper-only FP regions similarly make
    double pathological. Keep AArch64 inline FP opt-in until exits can
    demote a bad instruction or trace based on observed bail frequency.

    The bounded-continuation experiment does not test whether the dynamic
    64 -> 128 -> 256 policy should be removed. Its narrower question is
    whether a recording that reaches its current cap can publish that bounded
    prefix, immediately record another bounded region at the exact successor,
    and let ordinary successor links compose a path longer than the existing
    maximum of 256. The original head still learns its larger dynamic cap for
    future recordings, and the continuation inherits the cap that ended the
    current region; no individual recording or generated trace becomes
    unbounded.

    The first measurement mixed Linux boot and workload formation and therefore
    answered the wrong question. Its 259-instruction chain was boot code, while
    its claim that continuation code contained no FP also described the combined
    live pool rather than a clean `double` phase. The benchmark already supplies
    an architectural boundary: it boots to exactly 268435456 mcycles, then makes
    a second run call for the fixed 2^30-mcycle workload. Setting
    `TC_ONLINE_RESET_MCYCLE=268435456` now destroys the boot-generated code and
    clears boot hotness, penalties, learned caps, and statistics at that boundary.

    Clearing counters was still insufficient experimental isolation: a bad boot
    trace could dominate before the boundary at which it would be destroyed.
    The same setting therefore also defers online recording until the requested
    architectural mcycle. This changes neither workload length nor the machine
    state; it only prevents Linux formation from affecting whether the workload
    phase is reached.

    The corrected result preserves the earlier research conclusion: `double`
    needs a much longer dynamically traversable FP trace. The first implementation
    merely installed later fragments. The hot root at `0x7fffa370f19e` reached an
    FP fragment at logical offset 13, but a three-instruction page connector at
    offsets 17--20 was discarded by the global four-instruction minimum. Every
    later FP fragment was consequently detached. Retaining the short fragments
    of cap-bound recordings, which may be needed as internal connectors,
    produces one
    structurally continuous chain through offset 102: the continuation beginning
    at offset 64 contains 38 instructions, 19 of them FP. Arbitrary short roots
    remain rejected, and the dynamic 64 -> 128 -> 256 cap remains unchanged.

    Structural connectivity is not dynamic traversal. Generated-entry counters
    show the root and its first FP fragment executing about 1.5 million times,
    while the connector and every later fragment, including the offset-64
    continuation, execute zero times. A side-exit counter localizes the break:
    the last guard in the four-instruction FP fragment fires on every entry. It
    is the second `FD` instruction in the `FLD, FD, FD, JAL` fragment. The inline
    arithmetic proof requires sticky NX; exact arithmetic can leave NX clear, so
    this specialization can miss indefinitely and portable re-execution resumes
    outside the generated chain.

    The next call is cross-page. Its early call hook still carries the caller's
    fetch mapping and therefore cannot enter the already-installed callee trace.
    Bypassing that mapping check made the later fragments execute millions of
    times but changed the computation hash, so it was rejected. A short helper
    side bridge was also rejected: once hot it failed to make useful mcycle
    progress. The remaining implementation problem is therefore precise: after
    a guarded FP instruction retires portably, re-enter the compiled successor
    only through the ordinary fetch-miss transition, preserving its pc,
    countdown, mapping, and register contracts. Success means nonzero generated
    entry counts in the offset-20, offset-51, and offset-64 FP regions with the
    exact computation hash.

    Do not infer a 144-instruction ceiling from the installed graph, and do not
    remove the dynamic cap. The experiment has established the necessary
    length-capped chain formation and exposed the recovery edge that prevents
    `double` from traversing it; only after that edge works can this workload say
    whether bounded linking makes dynamic cap growth unnecessary.

    The guard-miss attribution above was wrong, and the instrumentation that
    proved it wrong found the real cause. Per-guard-class bail counters
    (TC_ONLINE_EXEC_STATS) show the sticky-NX guard never fired in the double
    window; every persistent miss was the strictly-normal result guard, and
    the raw bits it tested were always zero. Dumping the generated code
    (TC_ONLINE_DUMP_CODE) exposed the reason: lightning 2.2.3's AArch64 FPU
    backend emits FP loads and stores whose byte displacement lies in
    [256, 4095] unscaled into the scaled imm12 field, so every such access
    lands at eight times the intended offset (four for singles). Operands
    loaded garbage, the result store missed the staging slot, and the
    readback tested a never-written zero. The correctness gates could not see
    it: every affected instruction bailed and retired portably, so the bug
    silently converted the whole AArch64 inline FP fast path into a
    constant-miss detour. The bundled lightning is fixed (the u12 branches of
    the FPU loads and stores now require alignment and shift by the access
    size, mirroring the integer backend), and every earlier AArch64
    inline-FP measurement in this section -- the ten-times-slower hash loop,
    the pathological dense helper regions, and the double chain that never
    traversed -- was measuring this bug, not FP policy.

    With the fix, the same protocol reverses the structural conclusions at
    bit-identical hashes. A logmap window (stress-ng cpu-method logmap,
    hardware double, no libm; added to the workload suite as the clean
    rounding-heavy probe, while matrixprod, trig, and hyperbolic turn out to
    be long double and therefore soft binary128 with no guest FP at all)
    drops from 82.0M guard bails to zero, and its 26-instruction cyclic FP
    trace stays resident instead of bailing on entry. The double window
    drops from 4.59M bails to 58K, the survivors being genuinely small
    results, and the chain now executes deep: fragments at logical offsets
    18 through 64, including a 36-instruction continuation with 20 FP
    entries, run 1.1M-3.0M times each where every count was previously zero.
    That is the success criterion stated above, met with the exact
    computation hash.

    The default nevertheless stays opt-in on AArch64. zlib forms a hot loop
    around FD instructions whose guards miss persistently for real (an fcvt
    with a non-RNE static rounding mode declines to the helper, and a
    neighboring result genuinely leaves the strictly-normal proof), and each
    miss pays trace entry, guard bail, and portable re-execution, taking the
    workload from 17.6s to an aborted run past twenty minutes. The residual
    double misses are the same class at smaller scale. Bail-frequency
    demotion -- dropping a persistently missing instruction to its helper,
    or refusing to re-enter the trace at that pc -- is the prerequisite for
    an AArch64 default, and the x86-64 default deserves a zlib check for the
    same hazard.

    Two build hazards surfaced on the way. The lightning bundle must be
    regenerated from a clean tree after the displacement fix, because a
    partially cleaned tree relinks stale objects. And a from-scratch
    configure that picked a different host compiler emitted compare-branch
    sequences with the flag-setting comparison missing entirely -- an entry
    countdown check reduced to a bare conditional branch acting on stale
    flags, which livelocks the chain once the countdown goes negative. The
    bundle recipe now pins CC and compiles with -fno-strict-aliasing, and a
    regenerated bundle restores the correct cmp-plus-branch entry sequence,
    gated by the logmap window hash. A review pass in the same round also
    fixed the staged read-only fcsr CSR read to return the raw register
    exactly as the interpreter does, where the staged version masked
    reserved bits an adversarial guest can set.

12. DONE, GATED, THE X86-64 CHECK: A SIBLING LIGHTNING BUG, AND THE PRICE
    OF COMPOSITION. Item 11 ended by doubting that the displacement bug
    was an AArch64-only class, and testing the fixed tree on x86-64
    confirmed the doubt the hard way: eight of the ten workloads corrupted
    the guest kernel during boot (an Oops in get_page_from_freelist
    dereferencing a garbage pointer, then a panic), before any timing
    window opened. The failure bisected cleanly. TC_LIGHTNING_MAX_TRACES
    isolated the first bad install (the 344th compile: head
    ffffffff800d1074, 27 entries, a spilled straight trace formed during
    boot); and a TC_LIGHTNING_DEBUG build with TC_LIGHTNING_MAX_ENTER --
    record and install everything unchanged, refuse only to enter traces
    at or past a pool index -- cleared the crash at exactly that trace's
    index and at no earlier one. That pins the defect inside the trace
    body and exonerates the new composition and installation bookkeeping
    entirely. An AddressSanitizer build ran past the corruption point
    without a report, which is consistent rather than exculpatory: the
    corrupting store is emitted code, invisible to instrumentation.

    The disassembly names the bug. Entry [08] of the trace is sltiu
    a5,a5,1 -- a seqz -- staged through lightning's lti_u with a5 mapped
    to %rdi, and the emitted tail of the idiom reads mov $0x0,%edi; setb
    %bh. Encoding SPL, BPL, SIL or DIL as a byte register requires a bare
    REX prefix (0x40) even when no extended register forces one; lightning
    2.2.3's x86-64 _cc emits REX only when one does. Without it, modrm
    values 4 through 7 name the legacy high-byte registers AH, CH, DH and
    BH. Two corruptions flow from the one missing byte: the seqz result
    stays at the idiom's zero forever, and the flag lands in bits 8-15 of
    %rbx -- which held guest x9, the base register of every guarded TLB
    access in the trace. Guard and access use the same corrupted base, so
    the guard passes and the trace reads the wrong guest page. The same
    missing-REX class sits in lightning's register byte stores (_str_c,
    _sti_c, _stxr_c, _stxi_c), where a value in SIL or DIL would store
    AH or CH instead; that instance is latent in this backend, whose
    staged byte stores always source an emitter scratch (rax/r10/r11),
    but the setcc instance is live because comparison destinations can be
    the guest registers rdi and rsi. Five x86-64 campaigns never saw it
    because the trigger is allocation luck -- a setcc destination must
    land on rdi or rsi inside an installed trace -- and the composed
    trace population spent that luck on a trace formed during kernel
    boot. Every earlier campaign passed its hash gates, so the published
    numbers stand; the bug they were exposed to simply never fired. The
    vendored lightning now defines reg8_rex_p (register numbers 4-7 on
    x86-64 non-Windows) and forces the bare REX in _cc and the four byte
    stores; with the regenerated bundle the boot corruption is gone and
    the full suite, logmap included (canonized against hard-float stock:
    same hash, 11.58s stock to 3.45s backend), is hash-identical to
    canon.

    The verdict pattern across the two architectures is worth stating
    once: the same vendored backend carried two severe encoding bugs, and
    each hid behind a different mechanism. The AArch64 displacement bug
    hid behind guard bails, which demoted a correctness fault to a silent
    performance fault; the x86-64 REX bug hid behind register-allocation
    luck, which made it a time bomb. Neither was visible to hash gates
    until the trace population shifted. Generated-code paths need
    correctness pressure that does not depend on the traces the workload
    happens to form.

    The zlib check item 11 asked for comes back clean on x86-64: with
    TC_ONLINE_EXEC_STATS, zlib retires its window in 2.2s with zero
    FP-guard bails, logmap with zero, and double with 35K result-small
    bails over the 1Gi window -- genuinely small results, three orders
    below AArch64's pre-fix 4.59M. No workload shows the persistent-miss
    detour, so bail-frequency demotion is not a prerequisite for the
    x86-64 default.

    Composition, however, is not free here. Pricing 238cf0c5 in
    isolation -- its parent source against the tip, both on the fixed
    bundle, eleven workloads, three interleaved reps, medians, every run
    hash-gated -- gives:

        workload    parent     tip     delta
        nop          0.119    0.258  +116.8%
        memcpy       0.715    0.718    +0.4%
        hash         1.302    1.335    +2.5%
        zlib         1.986    2.166    +9.1%
        regs         0.837    1.414   +68.9%
        qsort        2.643    2.936   +11.1%
        branch       2.611    2.606    -0.2%
        tree         6.496    6.510    +0.2%
        sieve        0.640    0.729   +13.9%
        double       5.627    5.093    -9.5%
        logmap       3.432    3.483    +1.5%
        aggregate   26.408   27.248    +3.2%

    double gets the intended win: bounded FP chains compose and stay
    resident. But the tight integer loops pay for it, and the recorder
    statistics on nop say exactly how. The parent installs 223 traces
    with 328 escalations and 79 links; the tip installs 825 traces with
    133 continuations, 580 links, and eight and a half times the
    register-link boundary traffic (2,289 boundary loads plus stores
    against 268). The mechanism: under the parent policy a cap-bound loop
    head escalates, abandons, re-records longer, and closes a cycle, so
    the loop spins inside one cyclic trace with its guests pinned in
    registers. Under composition the bounded region is published at the
    loop head immediately -- and an installed head can never re-record,
    so the cap escalation it still dutifully learns can never be spent.
    The cycle is permanently forfeited, and the loop instead crosses a
    trace boundary every base_len instructions, paying the guest
    store/load contract each time. For instruction mixes that do real
    work per entry the boundary tax drowns; for nop and regs it is the
    workload. The filed fix is to make composition yield to cycle
    formation rather than forfeit it: when a cap-bound recording contains
    a taken back-edge to its own chain head, prefer the old
    escalate-and-abandon so the head can re-record and close, or allow a
    longer cycle-closing recording to replace the installed bounded head.
    Composition would then serve the chains it was built for -- straight
    FP regions past max_len -- without taxing every loop whose body
    outgrows the base cap.

    The filed fix is in, in its simplest form: a cap-bound recording
    below max_len escalates and abandons exactly as before composition,
    and composition engages only at max_len, where a loop has no cycle
    left to lose and the recorder has already spent two cheap extra
    recordings proving the head straight. No back-edge detection is
    needed -- the cap policy already encodes the distinction. At
    prototype scale (one interleaved rep per cell, every run hash-gated)
    the verdict is clean: nop returns to parent speed (+0.8%), zlib
    -1.9%, qsort +2.6%, sieve -2.2%, and the composition wins survive
    delayed engagement -- double keeps -7.2% -- while regs flips from
    the tip's +69% regression to a -55% win over the parent: its hot
    loop body genuinely outgrows max_len, so it is exactly the customer
    composition was built for, and 256-entry regions with continuation
    chaining beat both the parent's lone straight trace and the tip's
    64-entry fragments. The nop recorder statistics confirm the
    mechanism: continuations drop from 133 to 0, links from 580 to 136,
    and boundary traffic returns to parent levels. Composition at
    max_len only is strictly better than both predecessors on every
    cell measured.

13. DONE, GATED, THE INT-FLOAT CONVERSIONS STAGE. Item 11's designed
    increment, built to its design. Float to integer stages only the
    static-RTZ encodings compiled code uses -- exactly the host
    truncation -- behind the NX-sticky fcsr guard and a pair of range
    compares whose bounds are exact in both float widths; NaN fails both
    compares, so the saturating NV cases are excluded wholesale, and the
    W forms sign-extend through the context staging slot as integer IR,
    the same route the compare results take. DYN and the other static
    modes decline. Integer to float splits on exactness: 32-bit sources
    into double convert exactly under every rounding mode and carry no
    guards at all, while the rounding cases (anything into single, and
    64-bit sources into double) stage like the rounded arithmetic --
    RNE resolved, NX sticky -- and no case carries a result guard,
    because an integer never converts to a subnormal, infinite or NaN.
    The unsigned 64-bit source rides the signed host convert and bails
    on a set sign bit. One hygiene fix rode along: a body that requests
    the dynamic-frm guard and then declines could leak the request into
    the next staged instruction's guard set; the collect wrapper now
    clears it per instruction.

    Measurement is cheaper than the campaign habits suggested: a
    jitted bench run costs 10-15 seconds wall (create 0.1s, boot 2.7s,
    window 2-7s, root hash 5.5s -- the hash is the largest fixed cost
    after the window), so an 18-run interleaved comparison is a
    five-minute job with no protocol tricks; boot-once-store-load
    shaves the boot besides. One drift observation while switching
    protocols: the same build's double window measured 5.2s in one
    session hour and 6.6-6.9s a few hours later under either protocol
    -- the host moved 30%, reaffirming that only same-table interleaved
    ratios mean anything. Three-rep medians, every run hash-identical
    to canon: hash -3.1% (faster in all three reps -- its
    seven-instruction loop paid one conversion helper per iteration,
    the densest conversion site in the suite), double -1.0% (all three
    reps), logmap -0.5% (noise). zlib and nop single reps at parity. Attribution says the
    coverage is real: double's FP fallback list no longer contains any
    FCVT word -- what remains is atomics and fences, which are not FP
    staging's business -- and its residual 35K result-small bails drop
    to zero. The interesting surprise is hash: its int-to-double now
    stages, feeding the inline add/mul chain, and the chain's small
    products surface 3.1M result-small bails over the window -- yet the
    workload still nets its -3.1%, the bail cost drowned by the saved
    helper trips on x86-64. That is the bail-frequency-demotion
    scenario in miniature -- benign here where a bail is cheap, the
    exact hazard the AArch64 default waits on -- and hash is the
    workload to watch when demotion lands.

14. DONE, SURVEY: WHAT THE PEER JITTERS KNOW THAT WE DON'T. A pass
    over LuaJIT 2.x, rv8 (CARRV 2017), QEMU TCG and RVVM's RVJIT,
    x86-64 focus, ranked against this backend's measured bottlenecks.
    First the validation: most of their machinery we already carry,
    often in stronger form. rv8 pins twelve profile-chosen guest
    registers statically and spills nineteen to memory; our per-trace
    dynamic mapping with register-links is strictly ahead, and QEMU
    keeps no persistent guest-register mapping at all. RVVM's jTLB
    (pc-to-block cache) is our exact head map; its dirty-page block
    eviction is our write hook and hpage machinery; rv8's branch-tail
    dynamic linking and QEMU's goto_tb patching are our link stubs;
    LuaJIT's penalty-doubling and blacklisting are the recorder's
    penalty set. What remains, ranked by payoff-here times simplicity:

    1. Same-page TLB re-probe elision (LuaJIT's CSE/load-forwarding,
       applied to guarded translations). Our own trace dumps show
       three identical eleven-instruction probe sequences for the same
       base register and offset back to back, and the design makes
       elision a theorem: a read miss exits the trace and stores go
       through the separate write set, so the read TLB is immutable
       across one trace execution -- every repeat probe of a proven
       page is redundant by construction. The slowest workloads
       (tree, qsort, memcpy) are exactly the probe-bound ones. High
       payoff, moderate complexity: a staging-engine memo keyed on
       base node and offset, page-identical first, cross-iteration
       later only for provably invariant bases.
    2. Constant folding with symbolic auipc/lui (the one idea all
       three translators share: rv8's fusion table turns auipc+addi
       and auipc+ld into immediate-address moves, RVVM tracks auipc
       symbolically, TCG folds constants per TB -- and our IR does not
       fold imm-op-imm at all, even though the trace knows pc
       statically at every entry). High simplicity, medium payoff:
       kernel code is auipc-rich, constant addresses shrink probes by
       the whole index computation, and it compounds with idea 1.
    3. Stage the atomics. The FP-debug fallback lists on double are
       topped not by FP at all but by AMO words: every kernel
       spinlock and refcount breaks a trace or takes a helper. On a
       single-hart machine an AMO is a guarded load-op-store through
       the existing memory staging and store-invalidation path, and
       LR/SC reservations clear on any trace exit. Medium-high
       payoff, moderate complexity; QEMU spent 8.x making guest
       atomics inline for the harder multi-core case.
    4. Bail-frequency demotion (already filed as the AArch64
       prerequisite; LuaJIT's abort-penalty escalation validates the
       shape, at instruction rather than trace granularity).
    5. Cyclic-trace guard hoisting, LuaJIT LOOP made cheap: LuaJIT
       peels one iteration so invariant guards CSE against the
       pre-roll; we do not need the peeling, because the invariants
       are provable directly -- fcsr and FS cannot change inside a
       trace whose staged FP proves them unchanged -- so a cycle can
       emit those guards once in a preheader and drop them from the
       body. Medium payoff on the FP loops, moderate complexity.
    6. Sparse exit state (LuaJIT snapshots): consecutive guards share
       one snapshot and unmodified slots are never stored; our
       boundary and exit code stores every mapped guest. Dirty-guest
       tracking would shave the measured composition boundary tax.
       Medium-low payoff now that cycle precedence removed the worst
       of it.
    7. Victim TLB and dynamic TLB sizing (QEMU: 8-entry fully
       associative victim TLB behind the direct-mapped table, +11%
       average on SPECint plus kernel boots, up to +26%; dynamic
       resizing by use rate, part of the VEE'19 Qelt work that took
       softmmu to 1.76-2.18x). Parked: our hot TLB mirrors the
       canonical shadow TLB, which is hashed state -- any geometry or
       replacement change is a machine-spec change that breaks every
       equivalence gate. Worth the owner's consideration precisely
       because QEMU's numbers say the direct-mapped conflict misses
       are expensive; not actionable from the backend alone.
    8. Known-bits tracking (TCG's fold_masks): would drop redundant
       sign extensions around W-form chains. Low-medium payoff,
       needs IR plumbing.
    9. CISC memory-operand ALU for spilled guests (rv8 embeds
       [rbp+off] operands in ALU ops to cut icache pressure):
       lightning exposes no memory-operand ALU, so this is backend
       surgery for the rare spilled-trace case. Filed only.

    Not applicable: LuaJIT allocation sinking (language-level), rv8
    return inline-caching (covered by linked call targets and
    expected-pc side links). The survey's overall message is that the
    architecture is not missing a load-bearing mechanism; the gap is
    optimization passes over what the staging already sees --
    redundancy elimination first, constants second, coverage of the
    atomics third.

    Ideas 1 and 2 are in, and the measurement carries a lesson of its
    own. Load forwarding and constant-address probes shrink the
    diagnostic trace 20.5% (2497 to 1985 bytes), and a first cut that
    let known constants replace register reads outright priced the
    mistake: re-materializing 64-bit immediates where a live register
    already held the value cost nop +4.1% and double +1.7% against
    the forwarding wins, netting +0.4%. Constants must track
    alongside the registers and be spent only where they beat one --
    address formation and its probe. With that split, three-rep
    interleaved medians, all 84 runs of both cuts hash-identical to
    canon: hash -1.6%, nop -1.4%, memcpy -1.2%, double -1.1%, qsort
    -0.5%, tree +0.4%, sieve +2.3%, aggregate -0.4%. The counted
    savings are real but the host's out-of-order core was already
    hiding most of the redundant probe cost behind predicted branches
    and L1 hits -- the qsort lesson in a new coat: instruction count
    is not time. The elision theorem and the constant machinery stay
    (they are what a weaker in-order host, and idea 3's atomics,
    build on), but the next point of attack for memory-bound
    workloads is coverage, not code density.

15. FILED: SPEAK THE STANDARD DIALECT. The survey made the private
    vocabulary a cost: every mechanism here has a peer with an
    established name, and a reader fluent in LuaJIT or QEMU should not
    need a glossary. The rename, to be applied as one mechanical pass
    over code and doc: "bail" -> guard exit taken through a side exit
    (the shared "bail island" -> exit stub group, LuaJIT's exit
    stubs); "collect"/"collecting state access" -> translate /
    translating state access (QEMU's term for exactly this phase; our
    "record" already matches the industry's trace-recording usage and
    stays); "composed bounded recordings"/"continuation" -> trace
    stitching (the TraceMonkey/V8 term); page-local "fragments" ->
    page-local blocks (QEMU's translation-block page constraint);
    "straight" trace -> linear trace; closed "cycle" -> loop trace
    (LuaJIT's looping trace); "decline" -> NYI fallback (LuaJIT's
    NYI); "whole-instruction helper" -> helper call (QEMU helpers).
    Already-standard names stay: head, root, side trace, link,
    penalty, blacklist, trampoline, hotcount. Names with no peer
    concept keep their local names and a comment: the countdown
    budget, the penumbra, register-links (cross-trace register
    mapping inheritance, which none of the surveyed engines do).

16. DONE, GATED, THE ATOMICS STAGE. Survey idea 3, the coverage
    attack, and the first solid timing win of the optimization-pass
    series: aggregate -2.2% (three interleaved reps, every canon
    workload hash-identical, syscall agreeing across builds), landing
    exactly where the fallback lists said it would -- tree -5.4%,
    qsort -4.3%, nop -3.7%, syscall -2.9%, memcpy -1.2%, against
    sieve +5.9% and hash +2.3%. On a single-hart machine an AMO needs
    no atomicity against anything: AMOSWAP/ADD/XOR/AND/OR stage as
    the read probe, the operation, and the write probe, evolving the
    hot TLB exactly as the interpreter's two accesses would, with any
    miss, hooked page, or misaligned address exiting to the portable
    instruction. LR is the guarded load plus the reservation write;
    SC compiles its success path behind a reservation guard whose
    mismatch exit hands the failure path to portable re-execution --
    nothing clears a reservation inside a trace, so the exit is as
    rare as the failure. The min/max bodies select on a comparison
    the staging cannot express and keep their helper.

    The first cut shipped a bug worth its own paragraph. A lazy IR
    node re-emits on every consumption, and the AMO consumes its
    loaded value twice: once feeding the store, and again for rd
    after the store. The re-emitted load read the just-updated
    memory, so an AMOADD returned old-plus-addend and an AMOSWAP
    returned its own rs2. The value now materializes once through the
    context staging slot. Two diagnosis lessons came with the fix.
    Boot passed and every workload's gate failed, and the standard
    mcycle bisection then pointed at an innocent c.addi: the
    countdown seed shifts trace-entry decisions near the end of a
    run, so the first divergent cycle moves with the probe target,
    and target-parameterized bisection is confounded on this backend.
    What actually cornered the bug was run-restart invariance --
    run(a);run(b) must equal run(b), and the staged build broke it --
    plus a Merkle subtree descent that localized the divergence to
    the shadow page in logarithmic probes. Both belong in the
    permanent toolbox.

17. DONE, GATED: BAIL-FREQUENCY DEMOTION, WITH THE WHEEL ALREADY
    INVENTED.
    Every mature speculative compiler has shipped the mechanism this
    backend still needs, and they converge. HotSpot's uncommon traps
    are the closest shape: per-bytecode-site trap state, a recompile
    after PerBytecodeTrapLimit=4 failures at one site, and a next
    compilation that consults the trap history and emits the generic
    path wherever any trap is recorded, with reprofiling hysteresis
    between recompiles and a give-up cutoff. SpiderMonkey counts
    fixable bailouts per compiled script against
    frequentBailoutThreshold=10, maps each bailout kind to an action,
    and sets per-cause script flags the next compile consults. V8
    needs almost no counters because its feedback is monotonic: a
    deopt resumes before the failed operation, re-execution widens
    the feedback, and the next compile is generic at that site by
    construction -- monotonicity is what makes deopt loops
    structurally impossible. LuaJIT alone never demotes (trace mcode
    is immutable): hot exits get side traces at hotexit=10, and an
    exit that also fails side-tracing gets a stub trace linking
    straight to the interpreter, making the exit permanently cheap
    instead of the instruction slower. The design that follows for
    this backend reinvents nothing: a saturating per-exit counter in
    the side-exit records (LuaJIT's snapshot counter), a single-digit
    limit (HotSpot's per-site 4), demotion by recompiling the trace
    with the offending instruction's fp_decline_map bit set (the
    trap-history-consulted recompile; the map is already the
    mechanism discovery declines use), and monotonic growth of that
    map as the loop-prevention (V8's lesson), with the existing
    penalty and blacklist as the backstop. LuaJIT's stub-trace trick
    is the filed refinement for a trace that bails at its first
    staged instruction, where a recompile buys nothing.

    Built to that design, with one placement lesson the prior art
    does not spell out because their exits already run compiler
    runtime code: the first cut checked the limit at trace entry, and
    the check -- inlined into every handler site of the chain --
    priced at +3.1% aggregate, +4.9% on a workload that never bails.
    Everything now lives on the cold bail path: the shared exit
    island bumps the trace's counter, records the bailing entry,
    compares against the baked-in limit (TC_BAIL_LIMIT, default 8,
    zero disables), and posts a pending demotion that the RTC tick
    boundary consumes; the demoted address joins the per-machine set,
    the trace dies through the store-invalidation machinery, and the
    head's re-record compiles the instruction as its helper. Gated at
    parity: aggregate +0.2%, every canon workload hash-identical,
    hash taking two demotions and dropping from 3.1M guard exits per
    window to 45 (the tick-boundary latency) at -0.7% -- so on this
    host the bail and the helper cost about the same, and the
    mechanism's value is the insurance it was built for. The AArch64
    question it exists to answer -- whether demotion rescues zlib and
    flips the inline-FP default -- now ships as a tested mechanism
    with one knob.

18. DONE IN PART: THE AARCH64 ZLIB REGRESSION, TRACED TO ITS MECHANISM.
    The suite bisection put the 16.4s -> 21s AArch64 zlib regression on
    item 12's cycle precedence, and this entry prices what that policy
    actually traded. Reverting it at the tip does not recover the loss,
    it deepens it (24.2s): the atomics stage of item 16 had meanwhile
    made zlib's hot loops recordable end to end (they contain an AMO
    that used to stop every recording early), and cap-bound publication
    retained every sub-min_len page fragment as a chain connector. The
    hot loop bodies weave across a page boundary, so composition
    published their weave points as two-to-six-entry traces that
    execute tens of millions of times, each execution paying the trace
    entry and exit contract for a handful of instructions. Cycle
    precedence had been masking that pathology by suppressing
    composition, not fixing it.

    What ships is the unconditional half of the repair: publication now
    drops sub-min_len page fragments even at a cap bound. On the tip
    policy it is parity everywhere (six-workload bench and zlib
    hash-identical, timing within noise), and it removes the landmine
    under any future composition work. With the precedence policy also
    reverted it recovers zlib completely -- 15.7s against the tip's
    21.2s, better than the pre-atomics 16.4s baseline, the atomics
    stage finally contributing its intended win -- but the revert
    re-opens exactly the integer-loop regressions precedence fixed, on
    this host too. The frontier, interleaved and hash-gated:

    | config | zlib | regs | nop | double | qsort |
    |---|---:|---:|---:|---:|---:|
    | tip (cycle precedence) | 21.2 | 0.180 | 0.054 | 2.11 | 1.35 |
    | fragment fix + revert | 15.7 | 0.77 | 0.127 | 2.15 | 1.45 |
    | pure interpreter, no traces | 25.4 | -- | -- | -- | -- |

    zlib's 15.7 is genuine trace value (9.7s under the no-trace
    interpreter), carried by continuation-chain webs of base-cap
    regions: the fast build holds 202 continuation traces with 3911
    entries where the tip holds 8 with 126. Six mechanisms tried to
    hold both ends of the frontier and every one failed a measured
    gate. Chain promotion in both forms (item 12's filed fix) re-lost
    zlib whole: assembling the observed cycle and killing the chain
    trades a working web for a cyclic trace that bails mid-iteration.
    Three record-time shape predicates priced worse than either pure
    policy -- page-weave detection is too narrow (the decisive
    recordings are straight prefixes of branchy regions), backward-step
    detection too broad (calls and returns step backward), and both
    create granularity mixtures that cost more than uniform anything.
    A persistent per-head loop mark earned by an observed back edge
    (LuaJIT's discriminator, applied retroactively) marked only seven
    heads on zlib and still cost 4.5s: those seven are the hot deflate
    loops, bodies of 76-162 instructions, and their closed cycles lose
    to the web they replaced even though nop's equally short loop wins
    as a cycle. Identical record-time evidence, opposite optima: the
    choice between a cycle, a max_len chain, and a base-cap web is
    decided by the body's side-exit behavior at execution time, which
    no recording-moment signal predicts.

    The filed follow-up is therefore execution-time trace
    profitability, on item 17's counters: a trace whose executions
    mostly exit early is a bad commitment whatever its shape, and the
    bail accounting that already demotes instructions is the natural
    place to demote a trace back to the interpreter or a head from
    cycle to web. Until that lands, cycle precedence stays: it wins
    four of the five sensitive workloads and holds zlib at +28% over
    the recoverable floor, which the frontier table now prices
    exactly.

    A first execution-time campaign has since run and sharpened that
    filing with five more verified failure mechanisms, each caught by
    counters or event logs rather than timing alone. The design under
    trial was publish-and-compose by default, a persistent loop mark
    earned when a connected continuation wraps to its chain head, an
    escalating cycle chase for marked heads, and a demotion to a
    permanent web mark when a cyclic trace heats one side exit. The
    ledger: killing the chain at mark time loses a race, since the
    web re-forms around the marked head before its chase completes
    and the chase aborts into the fresh neighbors four entries in,
    collecting penalties until the blacklist ends it; killing only
    the head leaves the old chain to price the rest of the loop body,
    and the chase's continuation declines at the surviving nodes;
    letting the chase record through installed territory installs its
    max_len region but still strands the tail; letting its chain
    conquer installed nodes churns the regions of other workloads;
    and the single-exit hotcount verdict is wrong in both directions
    at once -- five of zlib's six trialed cycles never concentrate
    2048 divergences in one exit and keep losing quietly, while nop's
    good cycle accumulates them over a 1 Gi window and gets demoted,
    after which the re-closure ban leaves the head cycle-less for
    good. A demoted head also re-closes micro-cycles over inner
    mini-loops (16 and 25 entries, three million entries each) unless
    re-closure is banned outright. The refined requirements are
    therefore aggregate divergence accounting per trace across all
    its exits against a windowed entry count, verdicts that can be
    revisited rather than terminal marks, and coverage replacement
    that is atomic against re-formation instead of kill-then-chase.
    Every experimental patch and its measured verdict is kept under
    scratch/tracing-experiment.

19. SURVEY: HOW THE PEERS PRICE COVERAGE, SHAPE, AND VERDICTS. The
    campaign's three refined requirements are not novel; the mature
    systems each solved them structurally. Layered coverage:
    DynamoRIO and Pin keep a basic-block cache that always covers hot
    code and build traces above it, so an early trace exit falls into
    blocks, not the interpreter, and HotSpot, V8 and JavaScriptCore
    are the same shape vertically, with deoptimization landing in a
    tier that never went away. No one kills the base tier to build
    the optimized artifact, which is exactly the race our
    kill-then-chase variants kept losing. Profile-selected shape:
    HHVM runs profiling tracelets first and a separate region
    selector merges them into compilation regions from observed edge
    weights, and HotSpot compiles against branch profiles gathered in
    the cheap tier; the shape decision our record-time predicates
    could not make is made there from accumulated counts, with the
    small-unit web itself serving as the profiler. Revisitable
    verdicts: HotSpot reprofiles between recompiles and cuts off per
    method, V8 recompiles routinely on widened feedback, and LuaJIT's
    permanent blacklist is its most criticized weakness; Dynamo adds
    the coarse phase trigger, flushing the whole fragment cache when
    trace-formation rate spikes. For branchy loop bodies the field
    split three ways: LuaJIT grows side-trace trees entered from
    compiled code, TraceMonkey's trace explosion on such bodies is
    why Mozilla moved to method compilation, and QEMU and rv8
    dissolve the choice by making block boundaries nearly free. The
    synthesis for this backend: the web is the permanent base tier
    and the profiler, promotions are atomic overlays on the exact
    head map over a still-living web, and demotion is the reverse
    map swap, with windowed link and side counters as the evidence.

    The synthesis was then built and measured in seven increments
    (the shadow-promotion campaign, patches shadow-promote through
    shadow-promote7 in scratch/tracing-experiment), each step forced
    by an event or counter rather than a prediction. The lifecycle
    that emerged: publish bounded coverage first, always; earn a
    loop mark from a connected wrap or from any cap-bound root the
    backward-branch probe tripped; shadow the marked head's node so
    lookups miss while cached links keep serving it; chase the cycle
    through installed territory, immune to the scheduling race that
    otherwise blacklists whichever head records second; and on
    publication repoint the head map before killing the shadowed
    predecessor, whose cleared inbound links release the flow
    trapped in the old coverage -- without that kill a structurally
    perfect overlay executes 39K times while the stale web executes
    2.6M. Each end of the frontier fell to this machinery
    separately: one increment held zlib at 16.3s with loops broken,
    and two increments later regs sat at 0.19 and qsort beat its
    tip anchor while zlib slid to 22.6. The execution-time verdict
    that was meant to hold both -- demote a cyclic overlay on its
    third distinct hot side exit, the tree-explosion signal, with
    re-closure banned after demotion -- kept the loop side intact
    but could not rescue zlib: with every chase succeeding, its
    hundred-plus marked heads install six thousand traces across
    five pool flushes, and the marks' surviving each flush turns
    promotion into a permanent re-formation economy. The mechanisms
    are now all present and severally proven; what remains is churn
    budgeting -- per-generation chase quotas, flush-aware cooldowns,
    hysteresis -- which is its own measured campaign.

    Three more increments (shadow-promote8 through 10) ran that
    campaign and ended it with a sharper conclusion. The bet-once bit
    (LuaJIT's permanent per-PC penalty, HotSpot's recompilation
    cutoff) moved nothing: counters showed the six thousand installs
    were never re-chases but duplicate coverage from the universal
    record-through, six times the 956 traces the plain web needs.
    Restricting record-through to marked chases and sourcing marks
    from the collision itself restored the lean economy: zlib 16.7,
    qsort 1.14 against the tip's 1.36, the best zlib and qsort of
    the whole experiment in one build. The chase budget then priced
    the mega-chains (a 3928-entry chain had duplicated the hot code)
    at 1.3s of zlib without touching regs, which is the
    falsification that matters: regs's 0.19 under the broad economy
    never came from its own head's overlay -- its 472-entry body has
    no closable cycle at all -- but from the duplicated big-region
    coverage that the universal record-through laid everywhere, the
    same coverage that costs zlib six pool flushes. The frontier is
    therefore not per-head but per-workload coverage economy: regs
    wants broad big regions and tolerates duplication, zlib wants
    lean small ones. The mechanisms of items 18-19 price either
    economy correctly and cannot hold both, exactly the trade rv8
    dissolves structurally with a global static register mapping
    that makes region boundaries nearly free. That mapping -- a
    profile-chosen fixed guest-to-host assignment shared by every
    trace, replacing the per-trace negotiated register links whose
    boundary contract is the entire web tax on tight loops -- is the
    filed successor, and it is backend surgery, not recorder policy.
    Best shippable candidates from the campaign, pending that work:
    shadow-promote10 recovers 62% of the zlib gap and 19% of qsort
    at the price of regs, and the tip policy remains the shipping
    compromise.

    The filed successor got its first measurement on the interim
    amd64 host, and at this register budget it is falsified. The
    implementation is the full shape (TC_STATIC_REGS, opt-in): one
    fixed guest-to-host assignment pre-mapped identically in every
    trace, chosen by trace-dump frequency across tree, qsort, zlib
    and regs (a5, a0, a4, a1, ra); everything else spills to the
    shadow; the linked entry becomes universal -- valid from any
    predecessor and any page, with the code-mapping validation built
    in -- and the fast-link gates accept any pair, so link
    boundaries verifiably carry zero register traffic (tree: 212 of
    232 links register-linked, no loads, stores or moves). The
    boundaries were not the binding cost. Balanced 13, three
    interleaved reps, all hash-gated: aggregate +1.3% against the
    dynamic mapping, with regs +6.1%, sieve +5.1%, memcpy +4.6%,
    qsort +3.5%, tree itself +2.2%, and only int64 (-4.7%) winning.
    The diagnosis is measured, not inferred (no PMU in this
    container, so the instrument is disassembly of the hottest trace
    under both regimes, over identical trace populations -- same
    heads, lengths and execution counts both ways). regs's hottest
    trace (256 entries, 2.6M entries executed) grows from 1627 to
    1710 instructions (+5.1%) and from 319 to 370 shadow x-file
    accesses (+16%) under the static mapping, and the offset
    histogram names the cause: the added accesses sit at x18 and x19
    -- the s-registers the regs stressor lives in, which the dynamic
    pick had kept in host registers and the ABI-frequency five (a5,
    a0, a4, a1, ra) does not cover. That single trace touches eleven
    distinct guest registers heavily; no global five covers it.
    int64's hottest trace moves the other way, 590 to 576
    instructions and 88 to 75 shadow accesses: its loop works in
    exactly the a-registers the global set holds, so its body
    shrank and its boundaries freed -- the -4.7% win is the shape
    rv8 promises, delivered only where the working set fits the
    pinned set. So the register budget is the binding constraint
    with names attached: rv8 pins twelve and spills nineteen; this
    backend's four-slot args contract and emitter scratch leave
    five, and at five the dynamic per-trace pick beats any global
    five by more than the freed boundaries return. The experiment
    stays in the tree as the opt-in knob; the successor to the
    successor is a bigger pinned budget (the 8d ledger question:
    reclaiming rcx/rdx from lightning), at which point the global
    mapping deserves its re-run.

    The campaign closed with a balanced validation against the real
    baselines rather than the intra-JIT control: a 13-workload set
    chosen from the stress-ng sources to span dispatch floor,
    register pressure, branch misprediction, pointer chasing,
    callback sorting, memory streaming, compression, hash batteries,
    the kernel boundary, and four cpu methods (scalar FP, bit
    arrays, integer ALU, blocked FP arrays), the guest image's
    trimmed stress-ng permitting no more. Fixed-work protocol,
    1 Gi window after a 256 Mi boot, three interleaved reps, every
    workload root-hash-identical across all three builds. The
    balanced set is bench-harness/bench.lua's default table, and
    bench-harness/compare.sh runs the whole comparison -- variants
    interleaved innermost, per-workload root-hash gate across every
    run -- from installed prefixes; the raw table of this run is
    bench-balanced-3way.txt in the scratch area. Medians:

    | workload | stock | tail-call | jit | jit vs stock |
    |---|---:|---:|---:|---:|
    | nop | 0.730 | 0.532 | 0.055 | -92% |
    | memcpy | 1.532 | 1.160 | 0.336 | -78% |
    | hash | 1.731 | 1.460 | 0.755 | -56% |
    | sieve | 1.672 | 1.468 | 0.846 | -49% |
    | int64 | 1.957 | 1.217 | 0.992 | -49% |
    | qsort | 1.825 | 1.599 | 1.085 | -41% |
    | zlib | 1.898 | 2.030 | 1.146 | -40% |
    | syscall | 1.969 | 1.648 | 1.462 | -26% |
    | branch | 1.633 | 1.270 | 1.297 | -21% |
    | regs | 0.865 | 0.878 | 0.700 | -19% |
    | double | 2.131 | 2.160 | 2.188 | +2.6% |
    | matrixprod | 1.631 | 1.601 | 1.647 | +1% |
    | tree | 2.730 | 2.618 | 2.922 | +7% |
    | aggregate | 22.31 | 19.64 | 15.43 | -31% |

    The baselines reframe the campaign. The jit wins ten of the
    thirteen workloads and takes 31% off the stock aggregate; the
    losses are pointer chasing (tree, +7%), where traces add
    overhead without value, and dense FP at one to three percent.
    zlib, the subject of the whole investigation, is a 40% win over
    stock under fixed work, and the tail-call loop alone loses zlib
    to stock before the jit recovers it, the section 6 predictor
    story measured once more. The regs regression that drove a dozen
    increments was always relative to the cycle-precedence jit
    policy; against non-jit execution the same build wins regs by
    19%. The intra-jit frontier stands as documented, and the
    coverage-economy successor remains the path to holding both of
    its ends.

    The same balanced three-way re-ran on the interim amd64 host
    (compare.sh, 117 runs, every workload root-hash-identical across
    all three builds), with one build caveat: the tailcall-only
    six-slot configuration no longer compiles at the tip -- its
    TC_HOT_PARAMS branch kept the untyped uint64_t pc while the outer
    loop and the case bodies moved to the typed fast pc -- so the
    middle column is tailcall with TC_PAGE_SEGMENT=1, the exact
    interpreter shape the x86-64 jit sits on. The raw per-run lines
    are committed as bench-harness/results-amd64-balanced-3way.txt,
    since the interim host's scratch area does not outlive its
    session. Medians:

    | workload | stock | tail-call | jit | jit vs stock |
    |---|---:|---:|---:|---:|
    | nop | 1.288 | 1.121 | 0.120 | -91% |
    | regs | 1.697 | 1.682 | 0.373 | -78% |
    | sieve | 2.417 | 2.447 | 0.643 | -73% |
    | memcpy | 2.377 | 2.536 | 0.703 | -70% |
    | hash | 2.436 | 2.499 | 1.299 | -47% |
    | int64 | 2.697 | 2.340 | 1.598 | -41% |
    | zlib | 2.744 | 2.841 | 1.969 | -28% |
    | qsort | 3.048 | 3.106 | 2.669 | -12% |
    | double | 5.087 | 5.322 | 5.055 | -0.6% |
    | syscall | 3.215 | 3.372 | 3.240 | +0.8% |
    | matrixprod | 2.536 | 2.739 | 2.699 | +6.4% |
    | branch | 2.463 | 2.611 | 2.632 | +6.9% |
    | tree | 5.544 | 6.001 | 6.186 | +12% |
    | aggregate | 37.55 | 38.62 | 29.19 | -22% |

    The jit takes 22% off stock, winning nine of thirteen, and the
    hosts disagree instructively. This machine is about half the
    speed of the primary host and inverts the tail-call middle
    column: the page-segment interpreter loses 2.8% to stock here
    where the primary host's tail-call loop won 12%, consistent with
    a weaker branch predictor collecting less from the chain and the
    page-segment fetch trade. The jit's mix shifts the same way:
    regs quadruples its win (-78% against the primary's -19%) while
    qsort (-12% vs -41%), zlib (-28% vs -40%), syscall (+0.8% vs
    -26%) and branch (+6.9% vs -21%) all give back predictor-bound
    ground, and tree's pointer-chasing loss deepens to +12%. The
    stable conclusions survive the host change: dispatch-floor and
    register-pressure workloads are transformed, dense FP is flat,
    tree is the one structural loss, and the aggregate verdict --
    the jit beats both interpreters comfortably -- holds at half
    the margin.

    The build rot that forced the page-segment middle column is
    since repaired: the six-slot shape's TC_HOT_PARAMS branch has
    been migrated to the typed fast pc, dissolving the fetch offset
    argument into pc and settling the signature at five slots. Every
    shape compiles again under Clang and GCC on both architectures;
    the five-slot runtime still owes its gate run on x86-64
    hardware, where the amd64 column of this table is the anchor to
    beat.

18. DONE, GATED: THE REGISTER-PRESSURE LADDER -- r13, RANKED SLOT
    ASSIGNMENT, AND rcx/rdx ALL SHIPPED. The
    static-mapping falsification asked where more registers could
    come from on amd64. Four venues surveyed: r13 (the insn argument,
    dead in every trace and on every leave -- tc_fetch_miss,
    tc_lightning_trip and the continue path all ignore it, and SysV
    preserves it across helpers), rcx/rdx (lightning's fixed
    operands), r14 parked through bodies (pc is touched only at
    boundaries, but its entry value carries the mapping deposit and
    must be stored), and the XMM file as spill space -- rejected by
    the owner on hardware grounds: the gpr-xmm round trip is ~10+
    cycles on Zen and competes for FP ports, worse than the L1 hit
    it replaces.

    r13 as the sixth guest: -1.4% aggregate, balanced 13, all
    gated. tree, the structural loss, moves for the first time
    (-5.9%, every rep), memcpy -3.0%, syscall -2.1%; regs shows
    +7.1% inside its known layout band while its own hot trace got
    leaner (1627 to 1577 instructions -- 50 hot body instructions
    saved against 16 cold flush stores added). Shipped.

    rcx/rdx as slots 7-8: correct but falsified at +2.1% aggregate
    (qsort +5.6%, tree +5.2%, memcpy +3.8% against nop -4.8%, regs
    -1.6%), and the disassembly names the mechanism before the
    timing does: regs's hot trace uses rcx 46 times and rdx 22 times
    as guests yet nets zero fewer instructions, because first-use
    slot assignment hands the new registers to whichever guests
    appear first -- not the hottest -- while every trace pays two
    more roster stores at every exit site. The parking machinery
    written for the first cut turned out to re-implement what
    lightning already does: its fixed-operand emitters consult
    per-node liveness (jit_reg_free_p over the reglive set its
    optimizer computes) and preserve an occupied rcx or rdx into a
    temp themselves, with jit_live at indirect-jump seams -- which
    the backend already emits -- as the client's whole obligation.
    Gates with the slots enabled and no hand parking confirm it,
    int64's shift-division-multiply mix included, so the parking is
    removed rather than dormant. The refinement that re-arms the
    slots is therefore allocation policy alone: slot assignment
    ranked by discovery-time use count, so extra registers go to hot
    guests and lukewarm ones spill -- at which point slots 7-8, and
    the r14 parking rung above them, deserve the re-measure.

    The peer check, read from source rather than lore, says the
    filed policy is the consensus and first-use is the outlier.
    QEMU TCG keeps no persistent guest-to-host mapping at all on
    x86-64: tcg_reg_alloc_start marks every guest global
    memory-resident at translation-block entry and
    save_globals/tcg_reg_alloc_bb_end force them back to the env
    struct at every block end; within the block a backward liveness
    pass (liveness_pass_1) stamps per-op dead/sync bits and register
    preference sets, and eviction under pressure takes the first
    occupied register in the static tcg_target_reg_alloc_order --
    positional, not LRU, not counted. Dynarmic is the same shape,
    blunter: guest registers live in a state struct off r15, the
    allocator frees a register by exact use counting
    (total_uses/accumulated_uses per value) and picks victims by
    preferring empty registers, with a source-comment TODO admitting
    it never got around to LRU. LuaJIT, the nearest relative to this
    backend, allocates per trace by reverse linear scan where the
    eviction victim is the minimum of a blended cost -- IR reference
    order as a live-interval proxy, a +64 weight for PHIs so
    loop-carried values hold their registers, weak references
    evicted first, constants rematerialized rather than spilled --
    and its side traces inherit the parent trace's exit register
    assignments as allocation hints (lj_snap_regspmap feeding
    REGSP_HINT, coalesced in asm_head_side), which is structurally
    our register-links/preferred_mapping negotiation. With rv8
    (offline profile ranks guests by frequency, hottest 12 pinned
    globally) and RVVM (lazy bind, LRU reclaim) from the earlier
    survey, the field divides cleanly: whoever hands out scarce
    registers ranks candidates by liveness, weight, frequency, or
    recency -- never by order of appearance -- and nobody but rv8
    keeps a global static map on a 16-register file, and rv8 only
    with profiles deciding who deserves it. Both halves agree with
    what our gates already priced: the static-mapping falsification
    and the first-use failure at slots 7-8 are the same lesson the
    peers learned, and use-count-ranked slot assignment is rv8's
    ranking applied at our discovery time, with LuaJIT's cost model
    as the dynamic refinement above it. (Dynarmic was read from an
    identical-content fork mirror; upstream was unreachable through
    this session's proxy.)

    Built, and both falsified rungs flipped. The implementation is
    small because the two-pass structure already carried it: the
    discovery pass counts every staged read and write per guest
    (map_guest is called once per access), and before emission the
    slot assignment re-ranks hottest-first, ties broken on guest
    number for determinism. Slot values never shape the node graph
    -- only emission consults them -- so re-ranking between the
    passes cannot diverge the two, and the preferred-mapping
    permutation for links composes on top unchanged. Ranked at the
    same six registers, against the tip it replaced: -2.5%
    aggregate, balanced 13, all gates green (tree -6.7%, int64
    -3.0%, double -2.6%, syscall -1.9%, regs -1.4%, zlib -1.0%; nop
    +2.5% is 3 ms of noise on the shortest run). The one-line
    re-arm of rcx/rdx as slots 7-8 -- the pair that lost 2.1% under
    first-use -- then adds another -0.8% on top (regs -2.9%, branch
    -2.3%, double -2.2%, matrixprod -1.6%; syscall +2.1% and nop's 9
    ms inside their noise bands), about -3.3% combined. The
    disassembly names the mechanism the timing implies: regs's hot
    trace (same head, 2.6M executions) pays 319 x-file memory
    accesses under five first-use slots, 338 under eight first-use
    slots -- extra registers, more traffic, the falsified cut --
    and 267 under eight ranked slots, with the entry roster now
    carrying x9, x15, x18-x22 and x27, including the x18/x19 pair
    whose memory residence diagnosed the static-mapping loss, and
    rcx/rdx used 39 and 38 times as guests in the body. int64's
    roster takes x2 and x10-x16 and its body traffic stays flat;
    its -3.0% arrived with ranking alone and held. Both changes
    shipped.

    The two follow-ups were then built and measured, and both came
    back flat, which closes the ladder on this host. LuaJIT-style
    weighting (loop-body uses priced 8x over prelude uses) was a
    wash at -0.3% aggregate with large split swings -- tree -4.4%
    and branch -2.3% against int64 +5.8% and qsort +3.9%, the
    prelude-hot guests of exactly the workloads rcx/rdx serve being
    pushed off their slots -- so plain counts stand. And r14 parked
    through bodies (TC_PARK_PC, env-gated): pc is boundary-only in
    traces, so entries park it in a context staging slot, r14
    joins the pool as ranked slot 9, boundaries restore the
    contract with one load plus a compile-time delta from the
    head, and register-linked seams stay parked, bumping the
    staging slot in memory for the successor's parked entry to
    inherit. Correct on the first build -- all thirteen gates
    green -- and +0.1% aggregate on the same-build A/B, split just
    as wide: tree -3.8% and memcpy -2.1% against sieve +4.3%, zlib
    +4.0%, int64 +3.4%. Not an idle mechanism either way: 154 of
    zlib's 380 traces and 177 of tree's 400 occupy the ninth slot.
    The fixed accounting -- one park store per entry, one restore
    per slow leave, three memory ops per parked seam -- simply
    cancels the marginal value of a register that by construction
    carries the ninth-hottest guest. The ladder's yield curve is
    now measured end to end: -2.5% for ranking the six slots it
    started with, -0.8% for slots 7-8, +0.1% for slot 9. The
    machinery stays env-gated and off by default; the register
    budget on this host is spent.

19. DONE: THE COMPETITION, MEASURED, NOT QUOTED. The same static
    musl stress-ng 0.17.06 (musl 1.2.5, zlib 1.3.1, gcc-14), the
    same fixed bogo-ops per workload, wall-clock, medians of three,
    on the AMD host. Two comparisons with different standing. The
    fair one is qemu-system-riscv64 8.2 (virt board, OpenSBI): OUR
    kernel -- the inner Image extracted at 0x200000 of linux.bin,
    whose first 2 MiB are the cartesi M-mode shim OpenSBI replaces
    -- our rootfs on virtio-blk, and an identical four-line
    bench-init on both sides (mount proc/sys/dev, source
    /cartesi-machine/entrypoint from the DTB, poweroff), boot
    baselines subtracted. The context one is rv8's rv-jit, kept for
    the register-mapping lineage but user-mode only: no supervisor
    mode, syscalls proxied to the host, and it took three fixes to
    run modern binaries at all (its loader file-maps p_memsz and
    SIGBUSes on any large bss; unknown syscalls panicked instead of
    returning ENOSYS; sigaltstack/prctl/setitimer must lie
    success). It cannot run syscall or zlib at all.

    Seconds, medians (jit = this backend, sys = qemu-system, icnt =
    qemu-system with -icount shift=0,sleep=off):
      workload    jit    stock   sys    icnt   rv8     jit/icnt
      nop         6.47   20.24   0.96   1.39   0.17    4.7x*
      regs        6.62   36.85   4.23   4.24   2.60    1.6x
      branch      1.74    1.77   5.14   4.98   1.29    0.35x
      tree        6.01    7.46   6.19   5.93   1.47    1.0x
      qsort       8.24    8.15   5.52   5.93   2.82    1.4x
      memcpy      5.11   19.01   4.10   5.59   5.51    0.91x
      zlib        9.68   14.27   4.57   6.02   --      1.6x
      hash        8.52   14.15   3.65   4.29   2.69    2.0x
      syscall     6.19    6.40   1.70   1.75   --      3.5x
      double      6.31    7.65   2.96   2.91  14.39    2.2x
      sieve       6.19   26.46   3.90   4.85   1.84    1.3x
      int64       7.80    8.09   3.28   3.25   0.65    2.4x
      matrixprod  6.21    8.03   4.03   4.20   2.86    1.5x

    Geomean excluding nop: 1.6x behind plain qemu-system, 1.44x
    behind it with icount on. The icount reference measures what
    instruction accounting costs TCG: +8% geomean (memory-heavy
    rows pay 25-36%, ALU rows nothing), far below the folklore
    2-3x, because icount counts without committing -- each block's
    statically-known instruction total is decremented once at
    block entry and timer deadlines land at block boundaries, so
    nops stay deleted (1.39s against our 6.47s) and virtual time
    has block granularity. That is the same per-block amortization
    our traces use for the countdown; the difference we still pay
    for is instruction-exact tick semantics at every exit and the
    hashable state. nop (starred) is not speed at all: a bogo-op
    is ~70k real guest instructions (measured by mcycle delta,
    69-76k across op counts, no SIGILL involved), and TCG and rv8
    delete architectural nops as dead x0-writes -- rv8's 0.17s
    would be 49 Ginsn/s -- while this machine may not skip an
    instruction: mcycle exactness, deterministic interrupts and
    the hashable state ARE the product. rv8's two real
    embarrassments are instructive: double at 14.4s (2.3x slower
    than us -- FP softness) and memcpy 5.5s (slower than us),
    against its int64 at 12x us on tight user-mode ALU loops.

    The residual, then, measured rather than attributed. Episode
    accounting (TC_ONLINE_EXEC_STATS: countdown deltas at the two
    generated-code entry sites and the two leave handlers count
    guest instructions retired inside generated code, linked
    transits included, plus compile wall time) decomposes every
    deficit, and most of the mechanisms first written here were
    wrong. Coverage (share of retired instructions inside traces),
    mean episode length, and retire rates, boot subtracted:
      workload    insns    cover  ep-len  Minsn/s  icount-Minsn/s
      syscall     603M     15.1%    157      95       345
      hash        3.6G     74.5%     74     413       845
      int64       2.3G      0.1%     28     280       706
      double      816M      0.1%     25     132       281
      zlib        4.5G     63.3%     20     434       744
      branch      609M      0.3%     22     336       122
      tree        925M     64.8%     18     156       156
      memcpy      6.7G     99.2%   3901    1406      1195
      qsort       2.3G     12.8%     12     279       390
      regs       16.9G     95.8%   3712    2522      3994
      sieve       8.6G     96.9%    313    1211      1768
      matrixprod  2.4G     38.4%    147     381       579
      nop         8.2G     97.4%   5617    1310      5876
    Compile time is 16-78 ms everywhere -- never the story. The
    law in the table: wherever coverage exceeds 95% the backend
    retires 1.2-2.5 Ginsn/s and is competitive (memcpy beats the
    icount column outright); the losses live where coverage
    collapses, and each collapse has a measured cause. int64 and
    double are not register-allocation losses: coverage is 0.1%
    because this musl build keeps stress_mwc32 out of line -- two
    jal per loop iteration to a distant page -- and the recording
    dies at instruction 15 of the loop, exactly the first call,
    three times, then the head blacklists (TC_ONLINE_DEBUG shows
    begin/abort extra=15 at head 44cf0; the glibc image inlined
    the generator, which is why the earlier campaigns saw a clean
    31-instruction cycle at 15M entries on the same workload).
    syscall is 15% covered with 157-insn episodes and 48 ms of
    compile: flat kernel paths that never get hot, not churn. And
    branch, our 3x win, is not won by the traces at all --
    coverage 0.3% -- it is the tail-call interpreter at 336
    Minsn/s against a TCG that collapses to 122 on dense
    taken-branch torture, our 5.14s measurement of its TB-exit
    pathology. The one row where the register story is real is
    regs: 95.8% covered, in-trace 2.5 Ginsn/s against TCG's 4.0,
    where per-block allocation over a free host file genuinely
    outruns our eight slots. Filed, in payoff order: record
    through short out-of-line calls (int64 and double sit at 0.1%
    coverage and 1/2.5 of the icount column's speed; trace-rate
    execution likely flips both rows), kernel-path coverage for
    syscall-shaped loads, and regs-style block code quality last,
    per its measured 1.6x ceiling.

    The first filed item was then built three times, measured three
    times, and lives behind TC_ONLINE_INLINE_RETRY, off by default.
    All three forms rescue the starved loops identically -- musl
    int64 goes 0.1% -> 26% coverage and 8.6 -> 5.1 s, double 0.1%
    -> 12% -- and all three were judged on the canonical suite.
    Unconditional pass-through: +50% aggregate (syscall +300%,
    tree +90%); scoped to first-attempt loop-head recordings: +25%
    (syscall +171%); scoped to a one-shot retry for heads that
    demonstrably starved: still +18% (syscall +138%, tree +20%),
    and the syscall stats name the mechanism exactly -- 18002
    installed traces against the baseline's 532, seventeen
    pool-wide flushes, 4.4 s of compilation against 0.14 s. Kernel
    code holds thousands of individually lukewarm loop heads that
    starve at installed traces; granting each a single inlining
    retry floods the pool, and the flush-alls evict the good
    traces with the noise. The persistent other side: qsort
    improves under every form (-14% to -20%), with hash, sieve and
    zlib around -3%, so selective inlining has real value when the
    retry population is small. The refinement this evidence funds
    -- filed, not built -- is to grant the retry only to hot
    heads: int64's one blazing loop qualifies, syscall's thousand
    lukewarm ones do not. Disposition: env-gated off; the gated-on
    musl rows fall from 2.4x to 1.6x (int64) and 2.2x to 1.7x
    (double) behind the icount column.

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
library; every invocation must set `LUA_CPATH`. The online recorder's
trace pool was originally a per-thread static that outlived a machine
object, which forced each workload into its own process; the recorder
state is per-machine now (8b item 10), and the one-process-per-workload
protocol is kept for measurement hygiene rather than correctness.

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

The backend carries its own promotion list. The execution-oracle
caveat is retired: per-page trace membership and store invalidation
(8b item 11) make recorded bytes coherent with guest memory by
construction, so correctness no longer leans on the per-run hash gate.
The pool is per-machine now -- profiling, traces, blacklists and
generated code are owned and freed by the machine that produced them
-- leaving coverage as the remaining production item. The tramp-spill defect a clang-20 build
exposed -- side-trace division spilling through a frame pointer the
build never established, a silent eight-byte scribble under GCC -- is
fixed on the args shape by establishing a real frame in the penumbra
scratch tail at every generated entry and restoring rbp at every
leave, making the jit_tramp declaration true (8b item 10); the pinned
x86-64 shape keeps the spill-forbidding discipline instead. Coverage
stops at the integer instruction
families, which the `double` column prices exactly. And the pinned
x86-64 register contract is at its floor: with four guest registers,
one more consumer of the register file would have to come out of the
spilled-guest fallback rather than out of the budget (the args contract
of 8b item 10 relaxes this to five guests with none reserved).
