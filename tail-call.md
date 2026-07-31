# Tail-call interpreter experiment

## 1. Current conclusion

A tail-call threaded interpreter, built from Mike Pall's design advice but
with no assembly, beats the stock computed-goto interpreter by 11.8% under
Clang and 10.6% under GCC 15, in aggregate over the six continuity
workloads, from one source-code shape shared by both compilers (section
5.12, built with `make tailcall=yes`), while reusing the stock
instruction semantics unchanged. Every
variant of every iteration retired identical cycles and produced identical
root hashes and guest exits against a same-source stock build. For scale,
tracing.md's best offline native AOT result was -2.9% aggregate against
the plain interpreter.

The register discipline Pall obtains from assembly is obtained here from
pinned global register variables (x23-x28 hold pc, mcycle, the tick limit,
the fetch cache, and the context pointer), with the preserve_none
convention and guaranteed tail calls layered on where the compiler
provides them (Clang). Each instruction handler is a separate function
with one fixed signature and dispatches by tail call through the jump
table. A handler pre-decodes its fall-through successor (instruction word
and dispatch target, using its compile-time instruction length) in
parallel with executing its own semantics, verifies the prediction, and
dispatches through it; the generic fetch tail handles everything else, and
every non-hit fetch leaves by tail call so the hot path reaches no call.
Handlers whose semantics cannot raise are fully frameless; the rest keep
one x29/x30 pair for their cold raise blocks.

The decisive last step (section 5.9) was hardware-counter driven: zlib's
former +26% residual was low IPC from a serial fetch chain with nothing to
overlap it, and rotating the loop so the fetch of instruction n+1 overlaps
the execution of instruction n removed it, but only once the rotation was
made free by passing each handler's instruction length as a compile-time
constant instead of recomputing it from the instruction word at the head of
the very chain being shortened.

## 2. Background and motivation

tracing.md records that Clang's lowering of the stock computed-goto loop is
host and compiler sensitive, and that compiling trace machinery into
`interpret_loop` damaged stock code generation by tens of percent even when
no trace ran. Pall's diagnosis of interpreter loops (lua-l, February 2011,
"Suggestions on implementing an efficient instruction set simulator in
LuaJIT2") predicts exactly this: the register allocator cannot maintain a
consistent assignment across a large computed-goto graph, and slow paths
poison fast paths. His remedy is a fixed register assignment for all
handlers, fast paths that keep everything in registers, slow paths moved out
of line, and replicated dispatch at the end of every handler.

Two preliminary experiments framed the work:

- The whole emulator builds on macOS with MacPorts GCC 14
  (`make CC=gcc-mp-14 CXX=g++-mp-14`), produces bit-identical machine hashes,
  and one exception-path microbenchmark ran 13.7% faster than the Clang
  build. Compiler slack in the dispatch shape is real even between good
  compilers.
- Linking a GCC-compiled `interpret.o` into the Clang build is mechanically
  easy (nine unresolved symbols, all shimmable) but semantically unsound.
  libc++ and libstdc++ disagree on `std::string` layout, so
  `sizeof(machine_config)` differs (2000 vs 2232 bytes), every `machine`
  member after `m_c` sits at a different offset, and the mixed build
  diverged at mcycle 1 (instruction access fault instead of illegal
  instruction, the PMA list read at the wrong offset). `interpret.cpp` has
  almost no libstdc++ symbol dependency but a real layout dependency through
  `machine`'s inline accessors. Reordering members cannot fix it because
  constructor initialization order forces the divergent members first.
  Incidentally, `cm_create` silently ignores unknown config keys, which is
  how an `image_filename` key (the correct key is
  `backing_store.data_filename`) turned the intended addi/bne loop of the
  GCC microbenchmark into a trap loop; the 13.7% therefore describes the
  exception-heavy path, not plain dispatch.

## 3. Design

The stock switch bodies are perfectly uniform, so the implementation is
mechanical and semantics are shared, not duplicated:

- `interpret-tc-cases.inc` (generated): 153 `TC_CASE(LABEL, execute_...)`
  entries extracted from the stock `INSN_CASE` region of `interpret.cpp`.
- `interpret-tc-table.inc` (generated): the 65536-entry dispatch table
  extracted from `interpret-jump-table.hpp` with `INSN_LABEL` rewritten to
  `TC_LABEL`, expanded into function pointers.
- `interpret.cpp`, guarded by `#ifdef TAILCALL_INTERPRET`: the handler
  macro, the fetch helpers, and `interpret_loop_tc`. The stock interpreter
  is untouched and the flag is off by default. Only the direct
  `state_access` instantiation uses the tail-call loop; uarch, record,
  replay, and collect instantiations keep the stock loop over the same
  `execute_FOO` bodies.

Handler signature (preserve_none, AArch64 arguments in x20-x28):

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
flags and gives interpret.o only the routing define. The historical
campaigns predate the switch and were built with hand-passed OPTFLAGS.

## 4. Measurement protocol

Six stress-ng workloads from the tracing.md continuity suite (sieve, qsort,
zlib, hash, double, syscall), run by the tracing-experiment harness against
install prefixes, Apple M3 Max, macOS, Apple clang 17. Timings are user CPU
from single no-warm-up repetitions unless stated; where warmup and measured
pairs exist they agreed to within noise on every workload. Correctness
gates, not timing, are the acceptance criterion: every pair in every table
below matched guest cycles, final root hash, and guest exit byte for byte
(sieve retires 16,802,042,474 cycles). A stray runaway process from an
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
function. Restructuring those continuations to be reached without a call
from the hot path would let handlers drop their last frame instructions.
Section 5.7 does this, with a much larger effect than the frame pair
predicts.

### 5.7 Miss continuation (current best)

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
miss-preparations-ahead-of-dispatch disease tracing.md diagnosed in
Clang's decoded-cache loop, removed here by making the miss path a
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

### 5.10 Pinned global registers for GCC (current best under GCC)

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
Clang (section 8, item 5).

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
budget, section 8 item 5) is a small net loss (+1.5% over pinned alone,
sieve +7.4%, zlib neutral), much milder than GCC 14's regression. The
uniform shape adopted in section 5.12 keeps the pre-load on anyway; the
cost of uniformity under GCC 15 is those 1.5 points.

### 5.12 Pinned registers under Clang: one shape for both compilers

Making TC_GLOBAL_REGS, TC_PRELOAD_ENABLED, and the calling convention
independently overridable from the build allowed measuring the full cross
product, and ended with one source shape serving both compilers: pinned
globals in x23-x28, pre-load on, plus preserve_none and musttail where the
compiler has them. Clang needs -ffixed-x23 through -ffixed-x28 (wired via
MYCXXFLAGS so the flags reach only the host build, not the uarch cross
build). Three Clang-specific obstacles, each diagnosed from disassembly:

- Clang restricts named register variables to integer and pointer types,
  rejecting the host_addr strong type. The register holds the raw
  uint64_t; TC_ENTER binds a read-only local of the strong type and the
  few writers cast.
- Clang assumes -ffixed registers cannot change across calls. It deleted
  the entire save/restore of the caller's x23-x28 around the run (the
  callee-saved values of the embedding host, liblua's VM state in the
  observed crash), because a same-value restore of registers no call can
  change is dead code by its reasoning. The boundary save/restore
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
the handler-frame savings and closes the remaining gap: the unified shape
is the best Clang result measured in the whole experiment. The same
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
the buffers instead was rejected: the C API is a public FFI boundary and
hosts with thread churn (Go in particular) would leak one buffer pair per
dead thread, with cm_set_temp_string's buffer sized by returned JSON
configs. Pinning in the Lua binding instead was rejected because any
host language can dlclose the library. The harness's os.exit(0, false)
workaround in run-workload.lua predates the fix and is now redundant.

### 5.14 x86-64 shape (compile-only inspection)

Compile-and-disassemble only (GCC 14.2 in an emulated amd64 Debian
container, Clang via -target on the host); no timings, which need real
x64 hardware.

- GCC, args shape (no pinning, no preserve_none): every transition is
  branch-shaped, so the structure survives, but the nine-slot hot state
  overflows SysV's six integer argument registers. Each dispatch performs
  three stack loads at entry, three stack stores at exit, and heavy
  register shuffling, in handlers whose real work is a handful of
  instructions. A regression against stock is near certain.
- GCC, pinned: x86-64 has exactly six callee-saved GPRs (rbx, rbp,
  r12-r15). Pinning all six leaves handlers no callee-saved scratch, so
  anything live across a cold call spills. The viable experiment is a
  partial pin (pc, mcycle, the fetch cache pair) with the rest demoted to
  the context, a different shape from AArch64's.
- Clang, preserve_none args: compiles with musttail honored, the
  convention's twelve argument registers hold the whole state, no
  boundary stack traffic. Structurally equivalent to the healthy
  pre-pinning AArch64 Clang shape, consistent with CPython's x86-64
  tail-call result.

Consequence: on x86-64 Clang can ship the args shape today, while GCC
wants either the stock loop or a to-be-designed partial pin. The
defaults already encode this (TC_GLOBAL_REGS is AArch64-only).

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
5.9 implements it and resolves zlib.

A closing counters run on the final pre-load build corrected the
mechanism. The prediction on record was that mispredicts would stay at
~22 per 1000 guest instructions with the gain coming purely from latency
overlap. Instead the counted indirect mispredicts collapsed below stock
(zlib 22.5 to 3.40 per 1000, stock 3.52; sieve 8.7 to 4.3), while the
identical-source GCC build without the pre-load stayed at 21.7. Since the
predictor's inputs did not change, the consistent interpretation is that
loading the dispatch target a whole execute-body early lets the core
redirect from the known register value almost immediately on a wrong
prediction, and such early redirects neither cost nor count like late
mispredicts. Final figures for the pre-load build: zlib 39.6 host
instructions per guest instruction at 8.57 cycles per guest instruction
and IPC 4.62 (stock: 29.5, 8.29, 3.56), sieve 35.6 at 5.81 and IPC 6.13.
The tail-call interpreter now pays essentially stock's cycle price on
stock's best workload and wins everywhere else.

### 5.9 Next-instruction pre-load (current best)

Each handler pre-decodes its fall-through successor before executing its
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

## 7. Relevance to the tracing plan

- The +66% "tracing shell" penalty in tracing.md came from compiling trace
  machinery into the stock loop's CFG. In the tail-call structure,
  hotcounts and trace entries become ordinary functions behind an
  ABI-fixed boundary and cannot perturb stock handler code generation.
- A trace executor or native backend can share the handler convention, so
  entering and leaving a trace moves no state. This is the LuaJIT
  architecture (interpreter and JIT sharing register conventions), which
  the doc's amortization findings say is the decisive boundary cost.
- The sieve result from section 5.6 quantifies per-site branch prediction:
  dispatch sites private to a code region are worth double-digit percent
  on predictable code. Trace-side dispatch should be per-trace, never
  shared.
- If specific handlers still leave slack, each can be replaced by a
  hand-written assembly function honoring the same convention, one at a
  time, measured one at a time. So far no assembly has been needed.

## 8. Next work: closing the GCC gap

GCC 14 lacks preserve_none and musttail, and section 5.8 shows the
tail-call structure regressing 7.9% aggregate without them. Planned
attempts, in order:

1. TRIED, SPLIT BY CONVENTION. Slimming the handler signature to eight
   integer slots (fetch-cache fields back in the tc_context) regressed
   Clang 5-7% with the pre-load in place: the demoted fields feed the
   head of the pre-load's dependency chain, where register residency now
   matters (the earlier neutrality measurement predates the pre-load).
   Keep the fields in registers under preserve_none; if pursued for GCC,
   the signature must differ by convention (a parameter-pack macro on the
   same TC_PRELOAD_ENABLED condition).
2. RESOLVED, MOOT. The linked library shows GCC 14 already emits every
   transition as a branch (zero call-shaped transitions); the earlier
   count of residual `bl` transitions was an unrelocated-object
   misreading. Nothing to convert.
3. DONE, LARGE WIN (section 5.10). GCC global register variables pin the
   interpreter's hot state in call-saved registers under a GCC-only
   guard, flipping GCC from +7.9% to -9.0% aggregate. No -ffixed flags
   or library-wide changes were needed; see 5.10 for the caller-save
   boundary lesson learned on the way.
4. Profile-guided optimization as an orthogonal probe
   (-fprofile-generate / -fprofile-use, one workload of training).
5. DONE, UNIFIED SHAPE (sections 5.11 and 5.12). Pinned globals under
   Clang, composed with preserve_none and the pre-load, are the best
   Clang result measured (-11.4%), and the pre-load under GCC 15 costs
   1.5 points. One shape now serves both compilers; the per-compiler
   defaults in interpret.cpp select it, with every choice overridable
   from the build.

Rejected: -fcall-saved-xN per TU (silent ABI mismatch with
default-convention TUs, the same hazard class as the mixed-toolchain
divergence in section 2); attribute-level layout tinkering (noise at this
scale).

Remaining before promotion:

1. DONE. `make tailcall=yes` compiles interpret-tc.cpp with the pinned
   register flags; interpret.o gets only the routing define (section
   5.12).
2. DONE. The interpret.cpp defaults select the unified shape on AArch64
   for both compilers.
3. Run the formal gates on the flag, and a full timing campaign on the
   TU-split shape (the recorded campaigns used library-wide -ffixed).

Standing goal: a single interpreter implementation, so there is one loop
to audit instead of two. Currently blocked by portability (section 5.14:
GCC on x86-64 has neither preserve_none nor the register budget for the
full pin) and by the flat cost models of the uarch and zk builds, where
the tail-call shape's instruction-count overhead (section 6: 35-46 host
instructions per guest instruction against stock's ~29) would directly
inflate proof cost. Both blockers are measurable: a partial-pin x64
variant timed on real hardware, and a TC-shaped uarch build compared on
retired uarch cycles, which are architectural and exact. Neither has been
measured; until they are, the stock loop remains the portable fallback
and the verified paths (record, replay, collect, uarch, zk) stay on it.

## 8b. Next work: the jitter on the tail-call structure

Section 7's arguments now have a concrete staging. The guiding worry is
the cost of trace collection and lookup; the answer is LuaJIT's shape,
which the tracing.md prototypes already validated piecemeal: hotcounts
only at taken backward branches and call targets (the 64-entry colliding
16-bit counter prototype), trace-head lookup only at those same sites,
per-page trace tables with eviction, probation and blacklisting so cold
or failing heads stop paying. In the tail-call structure all of it is
local to the handlers that host the hooks; the fetch-tail hit path stays
untouched, which the stock loop could never offer (its instrumented
shell cost +66% with tracing idle).

1. Shell cost. Add the selective hotcounts and head lookup to the
   backward-branch and call handlers, no recording, no traces. Measure
   the six workloads against the plain tail-call build. Target is noise;
   the stock-loop equivalent was +66%. This number alone decides whether
   to continue.
2. AOT through the interpreter's convention. Reuse the tracing-experiment
   offline generator, but emit traces as C functions honoring the
   handler convention (pinned registers, preserve_none where available),
   compiled by the host compiler and dispatched from the head table.
   Zero new backend code, production-quality trace bodies, and it
   isolates the one question tracing.md left open: how much of the old
   -2.9% AOT ceiling was boundary cost that the shared-convention
   entry and exit remove.
3. Backend choice, only after 2 shows margin. MIR generates standard-ABI
   code, so every trace entry and exit would re-marshal the interpreter
   state, exactly the boundary cost the LuaJIT architecture avoids, and
   the prior experiments recorded short traces, where boundary
   dominates. MIR behind a marshalling shim is acceptable as a cheap
   probe; the endgame backend must honor the register contract (traces
   are straight-line with side exits, register allocation is nearly
   trivial, which is why LuaJIT's backend is bespoke). The pinned shape
   helps here: with state at fixed registers under both compilers, the
   backend targets one contract regardless of how the host emulator was
   built.

## 9. Validation status

All timing pairs in this document passed cycle, hash, and exit equality
against same-source stock builds, including full Linux boots (see section
5.12 for the uarch __LINE__ caveat that makes same-source a hard
requirement). The formal project gates (formatting, clang-tidy, the 267
machine tests, the 102 host/uarch comparisons) have not been run on the
experimental flag and are required before this becomes more than an
experiment. The generated .inc files are one-shot extractions; if the
stock switch or jump table changes, they must be regenerated (the
extraction scripts live in the session scratchpad and should be made into
checked-in tools if the experiment is promoted). The emutls exit-crash fix
in cm.cpp (section 5.13) is a product change independent of the flag and
can be upstreamed on its own.
