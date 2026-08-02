# Tail-call interpreter on x86-64: measurement, defects and tuning

## 0. Introduction

`tail-call.md` section 5.16 closes with "The x86-64 shapes, the ones the
six-slot signature actually targets, await re-measurement on hardware." This
document is that re-measurement, plus everything that came out of chasing it.

**What this is.** An independent evaluation of `feat/tailcall-interpreter` at
`0ff046c1` on an Intel i9-14900K (Raptor Lake), under GCC 16.1.1 and
Clang 22.1.8, against merge-base `c1d19122` on `main`. It is written for the
branch author: it assumes `tail-call.md` and refers to its sections by number.

**What I did.** Three things, in order:

1. **Measured** the branch as it stands (sections 1-9). Everything was
   re-derived from scratch — no result from my previous round was assumed to
   still hold, and several did not.
2. **Fixed and tuned** it for this hardware (sections 10-15), in small
   x86-64-gated changes that leave the AArch64 shape compiling exactly as
   section 5.16 measured it. Seven commits, ~150 lines, no restructuring of
   the design.
3. **Explained where the remaining time goes** (sections 13 and 16), so the
   stopping point is a measurement rather than an opinion.

**How to read it.** Sections 1-9 are findings about your branch, most
important first. Section 4 is the one I would read before anything else — it
is a 32.7% regression in the default Linux build configuration. Sections
10-15 are what I changed and what each change is worth. Section 16 is the
conclusion.

**Ground rules for every number here.** Guest work is identical across builds
by construction (a fixed 2 Gi mcycle window after an untimed boot), the
baseline is always `main` built with the same compiler, and **all 5763 runs
across 49 builds agreed on final mcycle, guest exit reason and root hash.**
Where I got something wrong mid-round — and I did, twice — the correction is
in the text rather than quietly removed.

**Headline.** `make tailcall=yes` goes from -1.6% to **-6.9%** under Clang and
from +1.4% to **-2.2%** under GCC (the latter with PGO, section 15.3). The
32.7% GCC stock regression is closed to +0.1%. The fastest configuration on
this machine is Clang `tailcall=yes` at 59.29 s against main's 63.67 s.

## 1. Summary

**The six-slot signature works, and it works dramatically for GCC.** The
tail-call interpreter went from +10.9% against stock to **+0.7%** under GCC 16
and from +1.4% to **-1.7%** under Clang 22. Tuned (section 6) Clang reaches
**-5.0%**. That is the first time any x86-64 tail-call configuration has been
a clear win here, and GCC's ~10 point improvement is the largest single
movement across both rounds.

**But the same commit regresses the stock interpreter under GCC by 32.7%**, and
that is the finding that matters most. `0ff046c1` changes `state_access` for
every instantiation, the stock loop included. On x86-64/GCC 16 the accessor's
new machine back-pointer indirection collapses the stock computed-goto loop:
IPC 4.76 → 3.30 on qsort, with 39% more loads and 99% more stores for only 4%
more instructions. Since Linux builds default to `CC=gcc` and `tailcall=yes` is
off by default, **the branch as it stands would ship a 32.7% slower emulator to
the default Linux configuration.** I isolated it to that one commit by bisect,
and to the accessor indirection specifically by a one-line diagnostic revert
that restores stock performance exactly (section 4).

Five findings, most important first:

1. **GCC stock regression, +32.7%** (section 4). Caused by `owner()` reaching
   the machine through `*m_s.penumbra.owner` instead of a stored reference.
   Restoring the stored reference recovers stock exactly and costs nothing
   else. Clang stock is *helped* by the same change (-2.8%), so this is
   GCC-specific.
2. **`-fno-stack-protector` still only reaches GCC builds** (section 5), which
   is unchanged from the previous round and still unfixed. Arch's Clang
   defaults to `-fstack-protector-strong`; the flag sits inside the
   `findstring gcc` block. 200 canary instructions across 39 handlers, paid
   once per dispatched instruction. Worth 1.5% here.
3. **The pre-load is a net loss on x86-64 Clang as shipped** (-1.9%), and
   `TC_PRELOAD_ENABLED` still enables it. Section 11 shows the overlap itself
   was never the problem -- it does exactly what section 5.9 designed it to do
   on this core too -- and that one redundant re-test was the entire cost.
   Removing it makes the pre-load a win here.
4. **My previous class-1 finding no longer holds.** Last round, demoting the
   eight conditional-branch cases recovered 97% of the pre-load loss. With the
   six-slot signature it recovers 45%, and with the fused miss of section 11.2
   it recovers nothing at all. Please disregard that recommendation.
5. **The JIT shell reproduces again** at +1.75%, against +1.71% on AArch64.
   Section 8b's dependency continues to hold on this hardware.

Everything the commit message claims about code shape is confirmed on x86-64:
`BNE` is fully frameless under both compilers, and GCC's push/pop across all
153 handlers dropped to 70 instructions total.

## 2. Environment and protocol

| | |
|---|---|
| CPU | Intel Core i9-14900K (Raptor Lake), runs pinned to one P-core |
| OS | Arch Linux, kernel 7.1.5 |
| Compilers | GCC 16.1.1 (20260728), Clang 22.1.8 |
| Guest images | `/usr/share/cartesi-machine/images/{linux.bin,rootfs.ext2}` |
| stress-ng in guest | 0.17.06 |
| Build type | default `relwithdebinfo` (`-O2 -g`) |

Boot 256 Mi mcycles untimed, then time a fixed 2 Gi mcycle window with
`os.clock()`, best of 3, `taskset -c 2`. Guest work is identical across builds
by construction. **All 5763 runs across 49 builds agreed on final mcycle,
guest exit reason and root hash** -- including every experimental variant in
sections 10-15.

Two protocol changes from the previous round, both of which matter:

- **The baseline is now `main`, not the branch's own stock build.** Last round
  I compared the tail-call build against the stock loop *on the branch*. That
  is no longer safe, because `0ff046c1` changes the stock loop too. Both
  baselines are built from merge-base `c1d19122`. Reading the branch's own
  stock build as a baseline would have hidden the GCC regression entirely and
  reported the tail-call loop as a 24% win over "stock".
- **The harness now refuses to run if `cartesi.so` is missing from the build
  directory.** My first attempt at building `main` failed on the uarch step
  (it needs Docker), Lua silently fell back to the system-installed module, and
  the numbers looked plausible while measuring the wrong emulator. The
  give-away was a different root hash. Fixed by copying the generated
  `uarch/uarch-pristine-*.c` into the worktree and asserting the module path.

Workload set is unchanged from the previous round: `qsort`, `zlib`, `hash`,
`syscall` from the doc's six, `fp` standing in for `double`, no substitute for
`sieve` (stress-ng 0.17.06 here has neither `--sieve` nor `--double`), plus the
repo's own `bench-harness` stressors, 17 total.

## 3. Results

### Clang 22.1.8

| Workload | main stock | branch stock | `tailcall=yes` | tuned (section 6) |
|---|---:|---:|---:|---:|
| fp | 2.80 | 2.63 (-6.0%) | 2.57 (-8.1%) | 2.38 (**-15.1%**) |
| regs | 1.82 | 1.72 (-5.4%) | 1.59 (-12.6%) | 1.54 (**-15.2%**) |
| branch | 2.58 | 2.22 (-14.0%) | 2.20 (-14.5%) | 2.21 (-14.0%) |
| hash | 2.67 | 2.47 (-7.6%) | 2.49 (-6.8%) | 2.34 (-12.5%) |
| nop | 1.32 | 1.33 (+0.4%) | 1.22 (-7.9%) | 1.06 (**-20.1%**) |
| randlist | 4.19 | 4.18 (-0.1%) | 3.93 (-6.3%) | 3.77 (-9.9%) |
| crypt | 3.14 | 2.85 (-9.1%) | 2.91 (-7.3%) | 2.84 (-9.5%) |
| cpu | 3.74 | 3.58 (-4.4%) | 3.52 (-6.0%) | 3.43 (-8.3%) |
| zlib | 2.78 | 2.69 (-3.3%) | 2.85 (+2.4%) | 2.62 (-5.7%) |
| qsort | 2.71 | 2.66 (-1.9%) | 2.73 (+0.6%) | 2.58 (-5.0%) |
| memcpy | 2.23 | 2.19 (-1.7%) | 2.39 (+7.4%) | 2.14 (-4.0%) |
| heapsort | 2.56 | 2.44 (-4.7%) | 2.58 (+0.7%) | 2.46 (-3.9%) |
| tsearch | 4.00 | 3.88 (-2.9%) | 4.01 (+0.4%) | 3.87 (-3.2%) |
| tree | 4.29 | 4.25 (-0.8%) | 4.36 (+1.5%) | 4.22 (-1.6%) |
| syscall | 6.04 | 5.96 (-1.3%) | 5.89 (-2.3%) | 5.99 (-0.8%) |
| matrix-3d | 9.70 | 9.78 (+0.8%) | 10.01 (+3.1%) | 9.66 (-0.4%) |
| malloc | 7.06 | 7.00 (-0.7%) | 7.29 (+3.2%) | 7.30 (+3.5%) |
| **Total** | **63.62** | **61.83 (-2.8%)** | **62.52 (-1.7%)** | **60.41 (-5.0%)** |

### GCC 16.1.1

| Workload | main stock | branch stock | `tailcall=yes` | pinned |
|---|---:|---:|---:|---:|
| heapsort | 2.47 | 4.63 (**+87.4%**) | 2.46 (-0.3%) | 2.77 (+12.3%) |
| regs | 1.76 | 2.96 (**+68.2%**) | 1.78 (+1.4%) | 1.83 (+4.0%) |
| randlist | 3.73 | 6.08 (+62.8%) | 3.79 (+1.7%) | 4.08 (+9.3%) |
| qsort | 2.66 | 3.96 (+48.8%) | 2.64 (-1.0%) | 2.89 (+8.6%) |
| fp | 2.43 | 3.51 (+44.5%) | 2.44 (+0.4%) | 2.62 (+7.9%) |
| hash | 2.34 | 3.37 (+43.6%) | 2.35 (+0.2%) | 2.62 (+11.8%) |
| branch | 2.26 | 3.15 (+39.4%) | 2.23 (-1.4%) | 2.30 (+1.9%) |
| memcpy | 2.23 | 3.04 (+36.6%) | 2.22 (-0.1%) | 2.57 (+15.5%) |
| zlib | 2.67 | 3.53 (+32.5%) | 2.61 (-2.2%) | 2.84 (+6.4%) |
| tree | 4.26 | 5.57 (+30.6%) | 4.26 (-0.0%) | 4.50 (+5.6%) |
| tsearch | 3.93 | 5.12 (+30.3%) | 4.02 (+2.3%) | 4.20 (+6.7%) |
| cpu | 3.52 | 4.58 (+29.9%) | 3.50 (-0.7%) | 3.64 (+3.3%) |
| crypt | 2.93 | 3.80 (+29.5%) | 3.20 (+9.0%) | 3.24 (+10.6%) |
| nop | 1.28 | 1.64 (+28.6%) | 1.30 (+1.8%) | 1.27 (-0.5%) |
| syscall | 6.00 | 7.44 (+23.8%) | 5.84 (-2.7%) | 5.98 (-0.3%) |
| malloc | 7.08 | 8.33 (+17.5%) | 7.11 (+0.4%) | 7.42 (+4.7%) |
| matrix-3d | 9.25 | 10.01 (+8.2%) | 9.50 (+2.7%) | 10.08 (+8.9%) |
| **Total** | **60.82** | **80.71 (+32.7%)** | **61.26 (+0.7%)** | **64.86 (+6.6%)** |

Read the GCC table by column, not by row. `tailcall=yes` is now essentially at
parity with main's stock loop on almost every workload — a genuine ~10 point
improvement over the previous round, and exactly what the six-slot signature
was for. The problem is the second column.

Pinned lost its previous advantage: it was +8.2% against +10.9% for the args
shape last round, and is now +6.6% against +0.7%. That inverts the section
5.14 conclusion that "pinned GCC beats its argument shape by 2.4 points". Once
the args shape stops spilling, pinning has nothing left to win and its own
locals traffic dominates. Since `TC_ONLINE` currently requires the pinned
shape, that is worth knowing before the online tracer is measured here.

## 4. The GCC stock regression

### 4.1 Isolation

Bisected by building the stock (no `tailcall=yes`) configuration at three
points, GCC, same protocol:

| Tree | qsort | regs |
|---|---:|---:|
| `main` (c1d19122) | 0.675 s | 0.443 s |
| branch at `0ff046c1~1` | 0.668 s | 0.442 s |
| branch at `0ff046c1` | 0.996 s | 0.741 s |

Every commit before the six-slot change leaves the GCC stock loop at main's
performance. The regression appears entirely at `0ff046c1`.

### 4.2 Root cause

`0ff046c1` does three separable things: it shrinks `state_access` to one
reference and reaches the machine via `*m_s.penumbra.owner`; it adds
`owner` and `scratch[511]` to `penumbra_state`; and it relocates `tc_context`
into that scratch area. Only the first affects the stock loop.

I confirmed this directly. Keeping the entire commit but restoring the stored
reference:

```c++
    processor_state &m_s;
    machine &m_m;              // restored
    explicit state_access(machine &m) : m_s(m.get_state()), m_m(m) {}
    machine &owner() const { return m_m; }   // was: *m_s.penumbra.owner
```

| Build | qsort | regs | zlib |
|---|---:|---:|---:|
| `main` stock | 0.675 s | 0.443 s | 0.675 s |
| branch stock | 0.996 s | 0.741 s | 0.892 s |
| branch stock + stored reference | **0.669 s** | **0.441 s** | **0.678 s** |

Exact recovery on all three, hashes identical. The penumbra layout change and
the `tc_context` relocation are innocent; the accessor indirection is the whole
cost.

### 4.3 Why it costs so much

Hardware counters on qsort, per guest instruction:

| Build | host insn/guest | cycles/guest | IPC | loads/guest | stores/guest | br-miss/1k |
|---|---:|---:|---:|---:|---:|---:|
| main-gcc-stock | 33.4 | 7.02 | 4.76 | 5.55 | 1.01 | 10.3 |
| **branch gcc-stock** | 34.7 | **10.52** | **3.30** | **7.74** | **2.01** | 10.8 |
| branch gcc-tc | 37.1 | 6.98 | 5.31 | 4.56 | 1.12 | 9.6 |
| main-clang-stock | 34.9 | 7.18 | 4.86 | 5.62 | 1.08 | 10.4 |
| branch clang-stock | 34.7 | 6.96 | 4.99 | 5.57 | 1.08 | 10.5 |
| branch clang-tc tuned | 34.2 | 6.81 | 5.03 | 5.06 | 1.62 | 9.7 |

The regression is **not** the indirection being executed. Instruction count
rises only 3.9%, and `regs` — which barely touches the machine at all — is the
worst-hit workload at +68%. What rises is memory traffic: +39% loads, +99%
stores, IPC collapsing from 4.76 to 3.30. That is pervasive spill/reload
traffic across the whole loop body, not a hot pointer chase.

The mechanism is the one `tail-call.md` section 2 is built on. Adding a load
through `m_s.penumbra.owner` inside functions that inline into the
ten-thousand-instruction computed-goto function introduces a memory dependency
GCC cannot hoist, and its register allocator falls off a cliff across the
entire function. The same source change costs Clang's stock loop nothing
(-2.8%, it is faster), and costs the tail-call build nothing under either
compiler, because each handler is small and ABI-bounded.

So this is simultaneously the branch's most serious defect and the strongest
evidence yet for its own thesis: a monolithic computed-goto loop has no stable
code generation under GCC, and the handler boundary is what makes it stable.
The tail-call build absorbed a change that cost the stock loop a third of its
throughput.

### 4.4 Suggested fix

The one-pointer accessor is load-bearing for the six-slot signature, so it
cannot simply be reverted. But the stock loop does not need it. The narrowest
fix is to keep the stored `machine &` and pay one extra register only where it
does not matter — the stock instantiations — while the tail-call handler
signature keeps its single-slot accessor. If a single `state_access` type must
serve both, caching the back-pointer in a member at construction
(`machine &m_m{*m.get_state().penumbra.owner};`) restores the direct reference
without reintroducing the constructor's dependency on `machine`'s definition.

Whatever the shape, the gate should be: **`main` stock and branch stock must
match under GCC.** They currently differ by 32.7%.

## 5. Configuration items still open from the previous round

### 5.1 The stack protector still only reaches GCC builds

Unchanged and still costing Clang. `src/Makefile:255` remains inside
`ifneq (,$(findstring gcc,$(CC)))`, and Arch enables
`-fstack-protector-strong` by default in both compilers.

| Build | canary instructions | spread over |
|---|---:|---|
| `clang-stock` | 8 | `interpret_loop`, once per call |
| `clang-tc` | **200** | 39 of 153 handlers, once per dispatched instruction |
| `gcc-stock`, `gcc-tc` | 0 | protected by the flag |

Worth 1.5% on the tail-call build here (62.52 → 61.60). The general point
stands and is worth stating once in `tail-call.md`: **the tail-call structure
converts per-function costs into per-instruction costs.** Anything the
toolchain adds per function — canaries, CFI, profiling counters, sanitizer
prologues — is amortised over a whole tick by the stock loop and paid 153 times
per tick here.

Caveat from the previous round, still true: do not apply the flag globally.
Adding it to the *stock* Clang loop cost 4% by perturbing register allocation
in that one huge function. It belongs on `TC_INTERPRET_CXXFLAGS` only.

### 5.2 The pre-load default is still not narrowed

Section 5.14 concluded "the pre-load default should consequently be narrowed to
`TC_GLOBAL_REGS`", but `TC_PRELOAD_ENABLED` still reads
`TC_GLOBAL_REGS || (defined(__clang__) && __has_attribute(preserve_none))`, so
x86-64 Clang still gets it. It is still a loss, though a smaller one than
before: 61.60 → 60.41, **-1.9%**.

### 5.3 What changed since last round: the class-1 result is dead

Last round I reported that 97% of the pre-load loss came from the eight
conditional-branch (class 1) handlers, and recommended a per-class knob. **That
is no longer true.** Re-measured on the six-slot signature, all three builds
with the stack protector off:

| Configuration | Total (s) |
|---|---:|
| pre-load as shipped | 61.60 |
| class-1 demoted to class 0 | 61.07 |
| pre-load fully off | 60.41 |

Demoting the eight branch handlers now recovers 0.53 s of the 1.19 s total —
**45%, not 97%**. Freeing two argument slots redistributed the register
pressure, so the loss is no longer concentrated in the branch cases. The
per-class knob I previously suggested is not worth adding; narrowing
`TC_PRELOAD_ENABLED` to `TC_GLOBAL_REGS`, exactly as section 5.14 says, gets
the full 1.9%.

This is the one place where a previous conclusion was invalidated by the new
code, and it is a good outcome — it means the six-slot change fixed the
specific pathology the class-1 finding was describing.

## 6. Best configuration on this machine (as measured, before section 10)

This is the hand-configured best of the *unmodified* branch. Sections 10-15
fold both levers into the defaults, so the equivalent build is now plain
`make tailcall=yes`; section 16.1 has the final numbers.

```sh
make -j32 cartesi.so CC=clang CXX=clang++ tailcall=yes \
     MYINTERPRET_CXXFLAGS="-fno-stack-protector -DTC_PRELOAD_ENABLED=0"
```

**60.41 s against main's 63.62 s: -5.0%**, winning 16 of 17 workloads
(`malloc` +3.5% is the sole loss), with `nop` -20.1%, `regs` -15.2% and
`fp` -15.1%. Both levers are configuration, not code.

Ranked, all against main stock for the same compiler:

| Build | Total (s) | vs main stock |
|---|---:|---:|
| clang tuned (above) | 60.41 | **-5.0%** |
| clang `tailcall=yes` + `-fno-stack-protector` | 61.60 | -3.2% |
| clang `tailcall=yes` + no pre-load | 61.18 | -3.8% |
| clang `tailcall=yes` (as shipped) | 62.52 | -1.7% |
| clang stock (branch) | 61.83 | -2.8% |
| **clang stock (main)** | **63.62** | -- |
| gcc `tailcall=yes` (as shipped) | 61.26 | +0.7% |
| **gcc stock (main)** | **60.82** | -- |
| gcc `tailcall=yes` pinned | 64.86 | +6.6% |
| gcc stock (branch) | 80.71 | **+32.7%** |

## 7. Code shape: the six-slot claims verified on x86-64

Section 5.16's static claims were made under GCC 16.1 on x86-64 and they hold
here. Across all 153 handlers:

| Build | handler insns | frameless | stack mem-ops | push+pop |
|---|---:|---:|---:|---:|
| clang-tc | 15561 | 62/153 | 1713 | 423 |
| clang-tc, no SSP | 14915 | 62/153 | 1554 | 434 |
| clang-tc tuned | 12323 | 62/153 | 1130 | 362 |
| gcc-tc | 19383 | 27/153 | 2386 | **70** |
| gcc-tc pinned | 24534 | 44/153 | 4368 | 344 |

`BNE` is fully frameless under both compilers, as claimed. GCC's push/pop total
across every handler is 70 instructions, against 499 pushes and 1487 pops in
the eight-slot shape I measured last round — the ABI shuffling is gone. GCC's
handler text is still 25% larger than Clang's and it keeps more stack mem-ops,
but those are cold-block spills and fat execute bodies, as section 5.16 says.

Worth noting against the previous round's numbers: Clang's frameless count rose
from 53/153 to 62/153 and handler text fell ~7%, so the six-slot signature
helped Clang too, just less spectacularly than GCC.

## 8. TC_JIT_SHELL

Measured on the tuned Clang configuration against its own no-shell control:
**+1.75%** (60.41 → 61.47). Against +1.71% on AArch64 in section 8b, this
reproduces for the third consecutive round and remains the most portable
result in the whole experiment. Section 8b's boundary argument is safe on this
hardware.

`TC_AOT` remains unmeasurable here — `TC_AOT_TRACES` is `#include`d but never
defined in-tree, no trace file is tracked, and the generator
(`gen-tc-traces.lua`) and capture build live in another checkout. `TC_ONLINE`
is gated on `TC_GLOBAL_REGS`, so on x86-64 it is reachable only through the
pinned shape, which is now the *slowest* tail-call configuration here (+6.6%);
any online-tracing result on this machine would start from that handicap.

## 9. Recommendation

Sections 10-13 implement items 1-3 below and measure the result; this section
is what I would ask you to take from the round.

1. **Fix the GCC stock regression before anything else** (sections 4 and 10).
   It is a 32.7% slowdown in the default Linux build configuration. Add a
   same-compiler `main`-stock-vs-branch-stock check to whatever gate this
   branch has to land -- it is the check that would have caught it, and the
   one I had to invent mid-round after realising the branch's own stock build
   is no longer a valid baseline.
2. Move `-fno-stack-protector` onto `TC_INTERPRET_CXXFLAGS` (section 5.1).
   Not onto `INTERPRET_CXXFLAGS` -- that costs the stock Clang loop 4%.
3. **Fuse the pre-decode miss into the dispatch target** (section 11.2). This
   is the one I would most like you to take upstream: it removes a redundant
   re-test of the fetch-cache hit from every dispatch, and it is what turns the
   pre-load from a 1.25% loss into a 1.10% win on x86-64 Clang. It should be a
   small win on AArch64 too, since it strictly removes a test and a branch, but
   I cannot measure that.
4. Retract two things I sent in earlier rounds, both invalidated by the
   six-slot signature: the per-class pre-load knob (now worth -0.06%, i.e.
   nothing) and "pinned GCC beats its argument shape by 2.4 points" from
   section 5.14 (now +6.6% against +1.3%, inverted).

The residual GCC stock +4.2% and the two structural items in section 13 are
the parts I could not close without the kind of refactor this exercise was
asked to avoid.

## 10. Fixing the GCC stock regression

Implemented, measured, committed. The accessor's width is an x86-64 register
budget question and the two compilers want opposite answers.

The tail-call handler signature is **six slots with the one-pointer accessor
and seven with a stored `machine &`**. Clang's x86-64 preserve_none passes
twelve arguments in registers, so seven still fits and storing is free — in
fact 1.0% *faster*, because the handlers stop loading the back-pointer too.
GCC's passes six, so storing spills on every dispatch and costs 6.4%.

Measured, all against the merge-base stock for the same compiler:

| Accessor shape | GCC stock | GCC `tailcall=yes` | Clang `tailcall=yes` |
|---|---:|---:|---:|
| branch as-is (one pointer) | +32.5% | +0.6% | (baseline) |
| stored `machine &` | **+0.0%** | +7.8% | **-1.0%** |
| one pointer, `owner()` out-of-lined | +4.2% | +1.4% | n/a |

So on x86-64 Clang stores the reference and GCC keeps the one-pointer accessor
with the load merely out-of-lined. Both macros are gated on `__x86_64__`, so
AArch64 compiles exactly the shape section 5.16 measured.

Two things I got wrong on the way, both worth recording:

- **`[[gnu::cold]]` on `owner()` looked excellent on three workloads and was a
  disaster on the full suite.** It fixed GCC stock better than plain
  `noinline` (0.66 s vs 0.68 s on qsort) but cost GCC's tail-call build 23%
  aggregate and Clang's stock loop 22% on `regs`, because `cold` also
  optimizes callers for size and wrecks the TLB refill path. Only the
  out-of-lining is wanted. I now measure the full suite before believing any
  spot check.
- **Gating the accessor layout on `TAILCALL_INTERPRET` would be unsound.**
  `state-access.hpp` is included by ~25 translation units and only two receive
  that define, so the class layout would differ across TUs within one build —
  the same hazard class as the mixed-toolchain divergence in section 2.

**Residual: GCC stock is still +4.2%.** The out-of-lined call is not free on
the TLB refill path. Closing it properly is your call, and the clean fix is on
your side of the design: if the tail-call handler took `processor_state &`
instead of `state_access`, the accessor's width would stop being an ABI
question and both compilers could store the reference.

## 11. Why the pre-load does not pay on x86-64, and what fixed it

This was the question I was asked to settle, so it got the most attention.

### 11.1 The pre-load works; the loop is the wrong shape for it

Topdown, differenced to isolate the workload window, `TC_PRELOAD_ENABLED=0`
against `=1` on the *same* build:

| Build | wl | Retiring | FE-bound | BE-bound | Bad-spec | insns | cycles |
|---|---|---:|---:|---:|---:|---:|---:|
| clang, no pre-load | qsort | 78.6% | 4.5% | 10.4% | 10.9% | 75.7G | 14.53G |
| clang, pre-load | qsort | 84.4% | 3.6% | **6.3%** | 6.7% | 84.8G | 15.10G |
| gcc, no pre-load | qsort | 81.7% | 5.0% | 10.1% | 9.4% | 81.0G | 15.45G |
| gcc, pre-load | qsort | 86.5% | 2.7% | **4.2%** | 7.3% | 91.5G | 16.04G |
| clang, no pre-load | zlib | 70.5% | 4.1% | 11.6% | 17.6% | 67.6G | 14.66G |
| clang, pre-load | zlib | 76.6% | 4.4% | **5.8%** | 16.1% | 80.2G | 15.54G |
| gcc, no pre-load | zlib | 73.2% | 5.9% | 7.2% | 16.5% | 68.3G | 14.82G |
| gcc, pre-load | zlib | 80.1% | 4.2% | **3.0%** | 15.5% | 81.5G | 15.43G |

**The overlap does exactly what section 5.9 designed it to do**: backend-bound
slots fall by 4 to 6 points, under both compilers, on both workloads. The
mechanism is not broken on x86-64.

It lost anyway because **this loop is not stall-bound**. Retiring is already
70–82% of issue slots without the pre-load, so the core is throughput-bound,
and there is very little stall left to hide. The pre-load bought its 4–6 point
stall reduction with **12–19% more host instructions**, and on a
retirement-bound loop extra instructions convert almost directly into cycles:
net +4% (qsort) to +6% (zlib).

That is the whole answer, and it is the same for both compilers, which is why
it never looked like a register-budget problem the way section 5.14 assumed.
Contrast AArch64, where section 6 records the tail-call build at IPC 3.16 on
zlib — heavily stalled, plenty for the overlap to hide.

### 11.2 Where the instructions went, and removing them

Disassembly of `ADDI_rdN`, hit path only:

| | instructions |
|---|---:|
| no pre-load | 23 |
| pre-load as shipped | 26 |
| pre-load, miss fused (this change) | 24 |

The three extra instructions were one redundancy. The fetch-cache hit was
computed at the *top* of the handler by `tc_predecode_next`, and then the
dispatch tail tested `tc_next.hit` again at the *bottom*, after the execute
body:

```
  cmp    $0xffd,%rcx        <- re-testing the hit computed 20 instructions ago
  ja     <generic tail>
  jmp    *%r8
```

two instructions and a branch per dispatch, plus one `mov` to keep the
comparison operand live. 23 → 26 is +13%, which matches the +12% measured
instruction increase almost exactly.

**The fix is to fuse the miss into the dispatch target.** A pre-decode miss
now sets `next.handler = tc_fetch_miss` instead of a flag, so the tail
dispatches through `next.handler` unconditionally. `tc_fetch_miss` already
carries the handler signature, ignores the instruction word, and recomputes
the fetch from the architectural pc — so routing a miss through it is exactly
what the inline generic tail would have done. The bottom of the handler
becomes a bare `jmp *%rcx`.

With the re-test gone the overlap is finally profitable:

| Build | Total (s) | vs no pre-load |
|---|---:|---:|
| clang, no pre-load | 60.08 | -- |
| clang, pre-load as shipped | 60.83 | +1.25% |
| **clang, pre-load + fused miss** | **59.42** | **-1.10%** |
| gcc, no pre-load | 61.96 | -- |
| gcc, pre-load as shipped | 63.47 | +2.43% |
| gcc, pre-load + fused miss | 61.98 | +0.02% |

So the pre-load is re-enabled for Clang and stays off for GCC, whose six
argument registers leave nothing over even fused (dead even, so not worth the
code). `TC_PRELOAD_FUSED_MISS` defaults on for x86-64 only; it should help
AArch64 too — it strictly removes a test and a branch — but that wants a
measurement on your hardware before it changes the shape section 5.16 tuned.

### 11.3 Two things that turned out not to matter

- **Per-class pre-load knob: no longer needed.** Demoting the eight class-1
  conditional-branch cases with the fused miss in place is worth -0.06%, i.e.
  nothing. The fused miss removed the pathology that made class 1 special (it
  was 97% of the loss at eight slots, 45% at six, and is now noise). The knob
  I recommended two rounds ago should not be added.
- **GCC's computed-goto flags are harmless to the handlers.** The tail-call TU
  inherits `-fno-gcse -fno-crossjumping -freorder-blocks-algorithm=simple`,
  tuned for one huge function. Countermanding them for the 153 small ones is
  +0.24% — slightly worse. Leave them.

## 12. Result after the first four changes

`make tailcall=yes` under Clang, no extra flags. (Sections 14-15 then went
after GCC; section 16.1 is the final state.)

| Workload | main stock (s) | tuned branch (s) | change |
|---|---:|---:|---:|
| nop | 1.32 | 1.03 | **-22.4%** |
| branch | 2.56 | 2.09 | **-18.2%** |
| regs | 1.82 | 1.52 | **-16.2%** |
| fp | 2.79 | 2.37 | -15.1% |
| hash | 2.68 | 2.33 | -12.9% |
| crypt | 3.14 | 2.77 | -11.7% |
| cpu | 3.74 | 3.31 | -11.6% |
| randlist | 4.17 | 3.73 | -10.6% |
| syscall | 6.03 | 5.62 | -6.8% |
| tsearch | 3.99 | 3.79 | -5.0% |
| heapsort | 2.56 | 2.44 | -4.8% |
| qsort | 2.71 | 2.58 | -4.7% |
| zlib | 2.78 | 2.66 | -4.3% |
| tree | 4.29 | 4.16 | -3.0% |
| malloc | 7.09 | 6.94 | -2.1% |
| memcpy | 2.23 | 2.22 | -0.5% |
| matrix-3d | 9.67 | 9.69 | +0.2% |
| **Total** | **63.57** | **59.26** | **-6.8%** |

Every workload wins or ties, against five of seventeen winning in the shipped
state. Summary of the whole round, all against merge-base stock for the same
compiler:

| Configuration | shipped | after this work |
|---|---:|---:|
| Clang `tailcall=yes` | -1.6% | **-6.8%** |
| Clang stock | -2.5% | +0.2% |
| GCC `tailcall=yes` | +0.6% | +1.3% |
| GCC stock | **+32.7%** | **+4.2%** |

`TC_JIT_SHELL` on the final configuration costs **+1.97%**, against +1.71% on
AArch64 — section 8b's dependency survives all of this.

## 13. Why I stopped on the Clang side

The topdown budget of the Clang configuration says where its remaining time
is. This is what closed out the Clang work; sections 14 and 15 then went after
GCC, which had a different answer.

| Build | wl | Retiring | FE-bound | BE-bound | Bad-spec |
|---|---|---:|---:|---:|---:|
| main clang stock | qsort | 78.4% | 9.2% | 9.3% | 9.0% |
| tuned branch | qsort | **84.2%** | 3.1% | 5.6% | 10.0% |
| main clang stock | zlib | 65.3% | 13.4% | 11.5% | 13.1% |
| tuned branch | zlib | **76.3%** | 4.1% | 8.8% | 17.5% |

The tuned build retires 84% of issue slots on qsort. Front-end bound is down
to 3–4% from the stock loop's 9–13%, which is the tail-call structure's own
doing and also **rules out the next thing I would have tried**: profile-guided
handler ordering to pack the 61 KiB of handler text against a 32 KiB L1i
cannot recover much of a 3% front-end share. (Consistent with the earlier
finding that `-falign-functions=32/64` was pure layout luck, ±13% per workload
with no aggregate signal.)

What is left is not dispatch:

- **Retirement-bound.** At 84% retiring the only remaining lever is fewer host
  instructions per guest instruction, which means shorter `execute_*` bodies —
  shared with the stock interpreter, not a property of this design.
- **`matrix-3d` (+0.2%) and `memcpy` (-0.5%)** are the two flat workloads and
  they explain themselves. `matrix-3d` is dominated by soft-float execute
  bodies, so dispatch improvements cannot reach it. `memcpy` runs in
  store-capable handlers, which are class 0 by construction — a store over the
  fall-through bytes must be observed by the next fetch — so they can never
  pre-load. Both are structural, not defects.
- **Bad speculation is now the largest non-retiring term on zlib (17.5%)** and
  it went *up* slightly with the tail-call form. That is the dispatch-site
  prediction question from sections 5.6 and 6, and nothing cheap remains: the
  design already gives every handler its own indirect site.

The two structural items that would matter are both yours to weigh, and both
are larger than "avoid huge refactors" allows: making the handler take
`processor_state &` so the accessor width stops being an ABI question
(section 10), and giving the raise and TLB-refill paths the section 5.7
treatment so the 91 call-carrying handlers become frameless.

## 14. Chasing the GCC tail-call build

Section 13 concluded on the Clang side. GCC was left at +1.4% against its own
stock loop, so I went back for it specifically. One change came out of it,
worth 0.83%, and six other ideas measured as wash-or-worse. The negative
results are the more useful half, so they are all recorded.

Note the bar is higher for GCC than the percentages suggest: **GCC's stock
computed-goto loop is 4.5% faster than Clang's on this machine** (60.84 s
against 63.73 s). GCC's tail-call build at +0.6% is 61.24 s absolute, which
beats Clang's *stock* loop comfortably; it is only "behind" because it is
measured against a much stronger baseline.

### 14.1 What worked: the attribute the tail-call build does not need

The `[[gnu::noinline]]` I put on `state_access::owner()` in section 10 is
there to keep the back-pointer load out of the stock computed-goto loop. A
`tailcall=yes` build does not have that loop for this accessor —
`interpret()` routes `state_access` to `interpret_loop_tc_run` under
`if constexpr`, so `interpret_loop<state_access>` is never instantiated. The
attribute was therefore pure cost, and `owner()` was the **single most
frequent call target in the whole GCC tail-call build**: 125 calls across the
handlers, ahead of `raise_exception` (114) and `init_hot_tlb_slot` (112).

Gated on a build-wide `CM_TAILCALL_BUILD` define — deliberately not
`TAILCALL_INTERPRET`, which only reaches two of the ~25 translation units that
include the header — GCC's tail-call build goes **61.68 → 61.17 s, +1.5% to
+0.7%**. Clang and the GCC stock build are untouched.

### 14.2 What did not work

| Idea | Result | Why |
|---|---|---|
| `-finline-limit=100` on the TC TU | wash (61.72 → 61.91) | Handler text -18% and frameless 31→62/153, `regs` -11.5% and `nop` -7.2% — but it also stops inlining the soft-float bodies, and `matrix-3d` (the largest workload) pays +4.9%. |
| Move the `noinline` to the 13 cold `owner()` callers | worse for TC | Helps the *stock* loop more than attributing `owner()` does, but costs the tail-call build ~1.3%: frameless drops 31→13 and handler text grows 13%. |
| Plain SysV instead of `preserve_none` | much worse | `push`/`pop` across the handlers goes 118 → 774. Confirms the convention is load-bearing, not incidental. |
| `-freorder-blocks-and-partition` | neutral | Output essentially unchanged; the interpreter's `-freorder-blocks-algorithm=simple` already fixes layout. |
| `-fipa-ra -fipa-icf` | no-op | Byte-identical output; already on at -O2. |
| `-fno-tree-tail-merge` | neutral/worse | +164 handler instructions, no timing gain. |
| Pre-load for GCC, with the fused miss | +0.27% | Re-tested after 14.1 changed the register pressure. `nop` -20.8% and `regs` -9.9%, cancelled by `memcpy` +7.1%, `hash` +3.2%, `fp` +3.0%. The existing gate reaches the right answer. |

### 14.3 Why GCC's handlers are 35% bigger, and why it does not matter much

GCC emits 19383 instructions across the 153 handlers against Clang's 14347.
That sounds like the explanation for the gap, and it is not: the *hot paths*
are equivalent. On `ADDI` GCC's hot path is **23 instructions against Clang's
24**, and GCC actually emits the tighter dispatch — it folds the jump-table
load into the branch as `jmp *(%rax,%r8,8)` where Clang needs a separate
`mov` then `jmp *%rcx`.

The extra 35% is all cold blocks: raise paths, TLB refill, page-crossing. They
cost i-cache footprint, not executed instructions, and section 13's topdown
already showed front-end bound is not where this loop's time goes.

So GCC's remaining gap to Clang is not code quality per handler. It is the
pre-load, which Clang can afford (twelve argument registers) and GCC cannot
(six), and which is worth -1.1% to Clang and +0.27% to GCC. That is the same
register-budget conclusion section 5.16 reached, now with the pre-load's own
cost removed so the comparison is clean.

### 14.4 Where GCC stood at this point

(Section 15.3 later improves this with PGO.)

| Build | Total (s) | vs main stock, same compiler |
|---|---:|---:|
| main gcc stock | 60.84 | -- |
| gcc stock, branch + fixes | 63.51 | +4.4% |
| **gcc `tailcall=yes`** | **61.24** | **+0.6%** |
| main clang stock | 63.73 | -- |
| **clang `tailcall=yes`** | **59.40** | **-6.8%** |

GCC's tail-call build is now within noise of the strongest baseline on the
machine. I do not have another lever for it that does not require the two
structural changes in section 13 — and of those, the first (handler takes
`processor_state &`) is the one that would help GCC most, because it would let
the accessor store the machine reference *and* keep six slots, closing both
the +4.4% stock residual and the last of the tail-call gap in one move.

## 15. Structural experiments

Section 14 exhausted the flag-level ideas for GCC. These three needed changes
with more structure to them. The first closed the last defect; the second was
marginal; the third produced the most surprising result in the document.

### 15.1 The accessor shape belongs to the build, not just the compiler

Section 10 left GCC's stock loop at +4.2% — the residual cost of out-of-lining
`owner()`. That residual is now gone, and the `[[gnu::noinline]]` workaround
with it.

The observation is that the accessor's two costs **never apply to the same
build**:

- storing the machine reference costs one handler argument slot (six become
  seven), which Clang's twelve `preserve_none` argument registers absorb and
  GCC's six do not — it costs GCC's tail-call build 6.4%;
- the one-pointer accessor's back-pointer load, inlined into the stock
  computed-goto loop, costs GCC's stock loop a third of its throughput.

A tail-call build has no stock loop for this accessor, and a non-tail-call
build has no handler signature to widen. So GCC now stores the reference
exactly when there is no tail-call loop to feed, keyed on the build-wide
`CM_TAILCALL_BUILD` define introduced in section 14.1.

| Build | before | after |
|---|---:|---:|
| GCC stock | +4.2% | **+0.1%** |
| GCC `tailcall=yes` | +0.7% | +0.7% |
| Clang stock | +0.2% | +0.2% |
| Clang `tailcall=yes` | -6.9% | -6.9% |

Keying a class layout off a build flag is confined to one link — `state_access`
is internal, and only `cm.h`, `cm-jsonrpc.h` and `cm-version.h` are installed.
That is the distinction I drew in section 10 when I rejected gating on
`TAILCALL_INTERPRET`: that define reaches two of ~25 translation units, so it
would have differed *within* a build; `CM_TAILCALL_BUILD` is global to one.

### 15.2 Selective pre-load by handler weight (marginal, not taken)

The pre-load's per-workload split suggests it pays for lean handlers and loses
for fat ones whose execute bodies already consume the registers. I tested that
directly by demoting the 36 "fat" class-2 cases — loads, FP, CSR — to class 0
and enabling the pre-load for the rest.

| | vs no selective pre-load |
|---|---:|
| GCC | -0.13% |
| Clang | -0.16% |

Both are below this campaign's noise floor. The per-workload wins are real and
large (`nop` -20.8%, `regs` -10.9%) but the losses simply moved: `memcpy`
+3.0%, `zlib` +2.1%, `fp` +2.0% — workloads whose handlers I did *not* demote,
so the classification is not capturing the right property. Not taken; it would
mean hand-maintaining a classification in a generated file for nothing.

### 15.3 PGO, and an inversion worth knowing about

`tail-call.md` section 8 lists profile-guided optimization as an untried
orthogonal probe. It is worth trying, and the result is not orthogonal at all.

The repository's own `luacartesi-pgo` target is broken here for an unrelated
reason (`cartesi-machine.lua:2570` dereferences a nil
`ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE`), so I drove it manually — which is
better anyway, because it let me **train on a workload deliberately outside the
measurement set**: the guest running `tar c -C / bin | gzip | sha256sum`, the
repository's own choice of PGO workload. No stress-ng workload is in the
training profile, so none of the numbers below are overfitted to what they
measure.

| Build | no PGO | with PGO | PGO effect |
|---|---:|---:|---:|
| GCC stock | 60.88 | 65.50 | **+7.6%** |
| GCC `tailcall=yes` | 61.30 | 59.50 | **-2.9%** |
| Clang stock | 63.81 | 59.82 | **-6.3%** |
| Clang `tailcall=yes` | 59.34 | 60.55 | **+2.0%** |

**PGO helps each compiler's weaker shape and hurts its stronger one.** Under
GCC it is worth 2.9% to the tail-call build and actively harms the monolithic
loop by 7.6%; under Clang it is worth 6.3% to the monolithic loop and harms
the tail-call build by 2.0%. I did not expect the Clang half and would not have
predicted its sign.

The honest reading is that this is *not* the clean argument for the design it
first looked like. A GCC-only result would have been one — 153 small
ABI-bounded functions are exactly what a per-function profile should optimise
well, and one ten-thousand-instruction computed-goto function is exactly what
it should optimise badly. The Clang inversion says the effect is dominated by
compiler-specific heuristics, not by the structure.

What it *is*, concretely, is the best GCC configuration on this machine:

```sh
make cartesi.so CC=gcc CXX=g++ tailcall=yes \
     MYCXXFLAGS=-fprofile-generate MYSOLDFLAGS=-fprofile-generate MYLDFLAGS=-fprofile-generate
# ...train...
make cartesi.so CC=gcc CXX=g++ tailcall=yes \
     "MYCXXFLAGS=-fprofile-use -Wno-missing-profile -fprofile-correction"
```

**59.53 s against main GCC stock's 60.85 s: -2.2%**, and within 0.4% of the
fastest build measured. Per workload, `regs` -15.1%, `syscall` -7.7%,
`nop` -4.9%, `qsort` -3.7%, `malloc` -3.3%, `tree` -3.2%, against `fp` +2.6%
and `hash` +2.3%.

## 16. Conclusion

### 16.1 Where the branch stands on this hardware

One campaign, same day, all builds interleaved, every run cycle- and
hash-identical:

| Build | Total (s) | vs own main stock |
|---|---:|---:|
| **Clang `tailcall=yes`** | **59.29** | **-6.9%** |
| GCC `tailcall=yes` + PGO | 59.53 | -2.2% |
| Clang stock + PGO | 59.76 | -6.1% |
| main GCC stock | 60.85 | -- |
| GCC `tailcall=yes` | 61.27 | +0.7% |
| main Clang stock | 63.67 | -- |

The tail-call interpreter is a real win on x86-64 under Clang and a small one
under GCC once PGO is applied. Both beat the strongest baseline this machine
has, which is GCC's stock loop at 60.85 s — a bar 4.4% higher than Clang's
stock loop, and the reason GCC's percentages look worse than its absolute
times deserve.

Note the top three land within 0.8% of each other by three different routes.
There appears to be a floor near 59.3 s for this workload set on this machine,
and all of Clang's tail-call shape, GCC's tail-call shape with PGO, and
Clang's stock loop with PGO reach it. That is worth knowing before investing
in further micro-optimisation of dispatch: section 13's topdown says the same
thing from the other direction, with the tuned build retiring 84% of issue
slots.

### 16.2 What I would ask you to take upstream

In descending order of how much I think it matters:

1. **The GCC stock regression** (sections 4, 10, 15.1). 32.7% in the default
   Linux build configuration, from one isolated commit, with a known fix. Even
   if you take nothing else, take this — and add a same-compiler
   `main`-stock-vs-branch-stock check to the gate, since the branch's own
   stock build is no longer a valid baseline.
2. **Fusing the pre-decode miss into the dispatch target** (section 11.2). It
   removes a redundant re-test of the fetch-cache hit from every dispatch and
   is what turns the pre-load from a 1.25% loss into a 1.10% win on x86-64
   Clang. It strictly removes a test and a branch, so it should help AArch64
   too, but I cannot measure that.
3. **`-fno-stack-protector` on the tail-call TU** (section 5.1). The general
   hazard is worth a sentence in `tail-call.md`: the tail-call structure
   converts per-function costs into per-instruction costs, so anything the
   toolchain adds per function is amortised over a tick by the stock loop and
   paid 153 times per tick here.
4. **Two retractions from my earlier rounds**, both invalidated by the
   six-slot signature: the per-class pre-load knob (now worth -0.06%) and
   section 5.14's "pinned GCC beats its argument shape by 2.4 points" (now
   +6.6% against +0.7%, inverted).

### 16.3 What I could not close

- **GCC's tail-call build without PGO** sits at +0.7%. Section 14 records six
  measured dead ends. Its *hot* paths are already equal to Clang's — 23
  instructions against 24 on `ADDI`, with a tighter dispatch — so this is not
  a code-quality gap; it is the pre-load, which Clang can afford with twelve
  argument registers and GCC cannot with six.
- **The 91 call-carrying handlers keep their frames.** Giving the raise and
  TLB-refill paths the section 5.7 treatment is the remaining structural item,
  and it needs restructuring `execute_*` bodies shared with the stock
  interpreter — beyond what this exercise was scoped to touch.
- **`matrix-3d` and `memcpy` do not move** and structurally cannot: one is
  dominated by soft-float execute bodies that dispatch improvements never
  reach, the other runs in store-capable handlers that are class 0 by
  construction, because a store over the fall-through bytes must be observed
  by the next fetch.

### 16.4 On the design itself

Two of `tail-call.md`'s claims reproduce here independently of raw speed, and
they are the ones I would keep.

The first is section 8b's: `TC_JIT_SHELL` costs **+1.97%** on the final
configuration, against +1.71% on AArch64 — the third consecutive round it has
reproduced, and the most portable number in the whole experiment. Whatever
happens to the interpreter, the boundary argument the tracing plan rests on
holds on this hardware.

The second is section 2's, and it arrived as a defect rather than a
demonstration. A single added indirection — one load, on cold paths, in an
accessor — cost the monolithic computed-goto loop a third of its throughput
under GCC, while the same change cost the 153-handler build nothing under
either compiler. That is the register-allocation fragility the whole design
exists to escape, measured accidentally and about as starkly as it could be.

## Appendix: reproduction

```sh
# baselines from merge-base (needs uarch/uarch-pristine-*.c copied in,
# otherwise the uarch step wants Docker and the harness will load the
# system-installed module instead)
git worktree add <wt> c1d19122 && cp uarch/uarch-pristine-*.c <wt>/uarch/
make -C <wt>/src -j32 cartesi.so CC=clang CXX=clang++      # main clang stock
make -C <wt>/src -j32 cartesi.so CC=gcc   CXX=g++          # main gcc stock

make -j32 cartesi.so CC=clang CXX=clang++ tailcall=yes
make -j32 cartesi.so CC=gcc   CXX=g++     tailcall=yes
make -j32 cartesi.so CC=gcc   CXX=g++     tailcall=yes \
     MYINTERPRET_CXXFLAGS="-DTC_GLOBAL_REGS=1 -DTC_USE_PRESERVE_NONE=0"
make -j32 cartesi.so CC=clang CXX=clang++ tailcall=yes \
     MYINTERPRET_CXXFLAGS="-fno-stack-protector -DTC_PRELOAD_ENABLED=0"
```

Each build's `cartesi.so` is stashed in its own directory and driven by a Lua
harness modelled on `bench-harness/bench-stress.lua`: boot 256 Mi mcycles
untimed, time a 2 Gi mcycle window with `os.clock()`, report elapsed time,
mcycle, exit reason and `get_root_hash()`. Per-handler profiles come from
`perf record` against the built `.so`, which the tail-call structure makes
trivial since every handler is its own symbol. Raw per-run data is in
`tail-call-x86_64-rawdata.tsv` (5763 rows: rep, build, workload, seconds,
MIPS, mcycle, exit reason, root hash).

The four changes of sections 10-13 are on branch `x86_64-tuning`:

```
ab78c5f9 fix(interpret): recover the x86-64 stock interpreter under GCC
cd748a6d build: keep the stack protector off the tail-call translation unit
d7d87975 perf(interpret): narrow the pre-load default to the pinned shape
8f1888e3 perf(interpret): fuse the pre-decode miss into the dispatch target
7d0520eb perf(interpret): drop the owner() out-of-lining in tail-call builds
94e92d13 perf(interpret): pick the accessor shape per build, not just per compiler
```

The third and fourth read as if they cancel: the third turns the pre-load off
for x86-64 Clang and the fourth turns it back on. They do not. The narrowing
was correct while the re-test was there, and the fusion is what changed the
economics. The history is left honest rather than squashed.
