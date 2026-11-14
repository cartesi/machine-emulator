# R3-VARDIRTY-2: a failed log producer leaves a half-applied transition

## What is asserted

A host allocation failure (`std::bad_alloc`, as under a memory limit) inside a log producer must not leave the
machine at a state that no transition produces. After `log_step_uarch` or `log_send_cmio_response` fails inside a
running process, the test requires that the machine be either at the before-state (not applied) or at the
after-state of a control run of the same transition (fully applied). Any third root hash is a violation (exit 1).

Requirements (THREAT_MODEL.md):

- Section 4: "A host fault, such as a full disk or an output channel that refuses a write, may stop the honest
  operator, but the emulator must never turn one into a wrong hash, a wrong proof, or a directory that O2
  guarantees but that later loads as a different state."
- R4: "No reachable state makes a log producer fail, overflow, or exceed its resource bounds (R12)." and "Input
  delivery with the referee parameters of its position never fails."
- R9: "'Interrupted or failed updates' means updates that fail inside a running process, which then keeps using
  the machine." The model expects a machine to stay usable after a failed call. O2's "combination that no execution
  reaches" covers only stops (crash, kill, power loss).

## How it works

- `nth-new.cpp` is an LD_PRELOAD replacement of the global `operator new`. While its arm file exists it counts
  requests and throws `std::bad_alloc` for the N-th one (once). `test.lua` builds it with `g++` into a temp dir.
- `child.lua <op>` (one process per N, so a crash in one does not affect the others) builds two fresh machines,
  applies the transition to one without injection (control, giving the after-hash), arms the injector and runs the
  logged call on the other, then classifies the outcome: `OK`, `UNCHANGED` (failed, at before-state), `COMPLETE`
  (failed, at after-state), `PARTIAL` (failed, at a third state), or `CRASH` (process died: a stop, allowed).
  For `PARTIAL` it also retries the same logged call, as an operator that keeps the machine would, and reports
  whether the retry reaches the control after-hash and whether the retry's log verifies from the canonical
  before-hash.
  - `step`: `log_step_uarch()` on `bugs/harness` config `baremetal-minimal` (mcycle 0, pristine uarch).
  - `send`: `log_send_cmio_response(ADVANCE_STATE, 4096 bytes, revert = root, LARGE_DATA)` on config
    `baremetal-template` (waiting at a manual yield with the accepted reason).
- `test.lua` first counts the requests of each call without injection, then sweeps N = 1, 2, ... until four results
  after the transition is fully applied (failures there come from verification or result conversion). It exits 2
  if no injected failure is seen or a call fails without injection.

Defect: the recording state accessors apply each write to the machine and then allocate to log it
(`src/uarch-record-state-access.hpp` `log_write_access`: the functor writes, then `log_written_hash`,
`log_written_data`, `log_access` allocate; `src/record-send-cmio-state-access.hpp` `log_before_write*` and
`log_write_memory_with_padding`), and `send_cmio_response` writes `imcyclemax`, the revert root hash, the rx buffer,
`htif.fromhost` and `iflags.Y` one after another. An exception between two writes unwinds with the transition
partly applied, and nothing rolls it back.

Not asserted (reported only): failures after the last write (`COMPLETE`) report an error although the transition
was applied, so a blind retry steps twice; and `CRASH` (std::terminate inside the result conversion).

## Run

```sh
bugs/run.sh R3-VARDIRTY-2      # needs g++ and the in-tree build and harness configs; about 1.5-2 minutes
```

## Expected output on audit/prt2 (exit 1)

Observed twice (about 2.5 minutes each; lines shortened):

```
step (calibration: 3939 requests while armed): N=1..19 UNCHANGED, N=20..28 PARTIAL, N=29..32 COMPLETE
send (calibration: 4492 requests while armed): N=1..17 UNCHANGED, N=18..24 PARTIAL, N=25..25 CRASH, N=26..48 PARTIAL, N=49..52 COMPLETE
step N=20: PARTIAL ... state: uarch_cycle=0 uarch_pc=0x600000 mid_root=0x60e5... | control: uarch_cycle=1 uarch_pc=0x600004
    before=0x99d6... after=0x2754... | retry_root==control_after:true retry_log_verifies_from_canonical_before:false
step N=25: PARTIAL ... state: uarch_cycle=0 uarch_pc=0x600004 mid_root=0x84d9... | control: uarch_cycle=1 uarch_pc=0x600004
    ... | retry_root==control_after:false retry_log_verifies_from_canonical_before:false
send N=18: PARTIAL ... state: iflags_Y=1 imcyclemax=281474980237027 htif_fromhost=0x201000000000000 revert_root_hash_written=false
    ... | retry_root==control_after:true retry_log_verifies_from_canonical_before:false
send N=22: PARTIAL ... iflags_Y=1 ... revert_root_hash_written=true ... retry_log_verifies_from_canonical_before:false
send N=45: PARTIAL ... iflags_Y=1 ... htif_fromhost=0x1000 revert_root_hash_written=true ... retry_log_verifies_from_canonical_before:false
VIOLATED: THREAT_MODEL section 4 / R4 / R9: a host allocation failure inside a log producer ...
run.sh: R3-VARDIRTY-2: exit 1 (bug present)
```

Reading the result:

- `step` N=20..24: a register of the uarch was written, but neither `uarch_pc` nor `uarch_cycle`. N=25..28:
  `uarch_pc` advanced to 0x600004 while `uarch_cycle` stayed 0. A retry of `log_step_uarch` on that machine then
  executes the next uarch instruction and ends at a root different from the control's (a wrong hash), and its log
  does not verify from the canonical before-hash.
- `send` N=18..48: `imcyclemax` written (then the revert root hash, the rx buffer, `htif.fromhost`) while
  `iflags.Y` is still 1. A retry of `log_send_cmio_response` happens to reach the control after-hash, because the
  writes are absolute, but its log starts from the half-applied root, so it does not verify from the canonical
  before-hash that the referee supplies: no delivery proof can be produced from that machine.
- `CRASH` (std::terminate) and `COMPLETE` (transition applied, error reported) are printed but not asserted.

Allocation counts depend on the build; the sweep finds the window whatever they are. Once logging no longer
leaves a half-applied transition on failure (for example, rollback on exception or no allocation between the
writes), every failure is `UNCHANGED` or `COMPLETE` and the test exits 0.
