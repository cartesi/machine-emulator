## R4-RGPLAYERGUEST-1

**Title.** The `cartesi-machine` CLI computes no mcycle computation hash when a guest accepts an input with an outputs-root length other than 32 bytes. It also stops by default when the root differs from the host's outputs tree.

**Severity.** Medium. Under a second reading, where the CLI counts as a development tool that "may instead stop and report the violation", it is Out of scope.

### Problem

When the guest yields manually with the accepted reason, `run_advance_state_input` in `src/cartesi-machine.lua` calls
`flush_pending_outputs` before `builder:end_input`, whichever computation-hash builder is selected.
`flush_pending_outputs` runs `assert(#data == cartesi.HASH_SIZE, "expected outputs Merkle root in tx buffer")` on the
yield's DATA field, which is the length of the outputs root. With the default `check_outputs_merkle_root:true`, it then
asserts that the root equals the host's outputs frontier (`"outputs Merkle root mismatch at input %d"`).
`check_outputs_merkle_root:false` turns off only the comparison. The length assert stays.

Both values are guest data. Section 4 says: "The outputs Merkle root, the output payloads, and every other yield reason
are opaque guest data that the state merely commits to." The transition function does not interpret them, so the state
is still an accepted fixed point and its computation hash is well defined. The PRT player computes that hash for the
same template and input.

When the assert fires, the CLI process exits with a Lua error. It writes no `--mcycle-computation-hash` file and prints
no hash. A guest that breaks the rollup interface in this way therefore stops the tool that the manual presents as
computing the honest claim. In the operator this tool stands in for, any claim could then win, including a fabricated
final state and its outputs (section 8).

The CLI is not consistent here. Its own help (lines 524-527) says unexpected fixed points ("halt, mcycle overflow,
exception, or unexpected manual yield") "finalize the epoch without output proofs". Other guests that break the
interface therefore still get a computation hash. An accepted yield with a malformed root does not.

### Component, role and area

The component is the `cartesi-machine` CLI (`src/cartesi-machine.lua`), in its `--cmio-advance-state` loop with
`--mcycle-computation-hash` (and `--uarch-cycle-computation-hash`). The AUDIT.md table says: "The PRT player and bridge
in `doc/recipes`, the `cartesi-machine` CLI, and the Lua helper libraries ... | Support. No production deployment runs
the player, the bridge or the CLI." The manual presents its computation-hash options as computing the claim. Under
"Computation hashes" it says the utility "computes two kinds while `--cmio-advance-state` feeds an epoch". The PRT
section says: "The honest player's mcycle claim must equal the hash `cartesi-machine` produced under Computation
hashes." So the CLI is a tool that computes claims, and it stands in for the honest operator. The area is how outputs
are handled at each accepted input.

### Location

- `src/cartesi-machine.lua`, `flush_pending_outputs` (lines 3679-3704):
  - the length assert at line 3689;
  - the root comparison at lines 3691-3696, which applies only when `check_outputs_merkle_root` is true (the default).
- `run_advance_state_input` (lines 4691-4729), which calls `flush_pending_outputs` at line 4723 (accepted path),
  before `builder:end_input` at line 4727.
- The help text for `end_epoch` (lines 524-527) and `check_outputs_merkle_root` (lines 561-564).

### Evidence and test

`bugs/R4-RGPLAYERGUEST-1/` contains the following files.

- `guest.c` is a bare-metal rollup guest that never emits outputs. It writes the root of the empty outputs tree to the
  tx buffer and yields manual RX_ACCEPTED. The DATA field is 32, unless the input's first byte is `z` (DATA 0) or `Z`
  (DATA 0xffffffff).
- `test.lua` builds the guest with `bugs/harness/baremetal/build.sh` and stores the template at the guest's first
  rx-accepted yield. It then runs two one-input epochs from that template:
  - control, input `a`, which accepts with DATA 32;
  - target, input `z`, which accepts with DATA 0 and the same correct root.

  For each case it runs
  `cartesi-machine --load=m,sharing:all --revert-mode=stored --cmio-advance-state=input:input-%i.bin,input_file_index_begin:0,input_file_index_end:1,check_outputs_merkle_root:false --mcycle-computation-hash=log2_mcycle_period:10,filename:hash.bin`.
  It requires exit 0 and a `hash.bin` equal to the claim root that the PRT player (`prt.new_forked_player`,
  `commit_mcycle_claim`) computes for the same template and input. If the control case fails, the test exits 2 as a
  setup error. The test also runs `--uarch-cycle-computation-hash=log2_mcycle_period:10,mcycle_period_index:0` and
  prints the result, but does not assert it.
- `README.md` describes the test.

Run it with `bugs/run.sh R4-RGPLAYERGUEST-1`. It takes about 12 seconds and needs docker for the guest build. On
audit/prt2 it prints:

```
control (input "a", guest accepts with DATA 32):
  PRT player claim root:          0xd40f85187f86adf471b897339ccf89cb2441bfc7b7682005df4acd73efa07de1
  CLI --mcycle-computation-hash:  exit 0, 0xd40f85187f86adf471b897339ccf89cb2441bfc7b7682005df4acd73efa07de1
  CLI --uarch-cycle-computation-hash (period 0): exit 0, 0x51b2e2a7750c3eae24a1b314d63a00eb0ff70928331966987de89daf50ac463e
target (input "z", guest accepts with DATA 0):
  PRT player claim root:          0x90b54dcba435398699526ee87d4e5d191a3fe198642205716a4f017862273ec4
  CLI --mcycle-computation-hash:  FAILED, no hash written
    Cycles: 2478012
    lua5.4: /home/user/machine-emulator/src/cartesi-machine.lua:3689: expected outputs Merkle root in tx buffer
  CLI --uarch-cycle-computation-hash (period 0): FAILED, 0xa8f4787036b168642c6c192a812ef64cf2572ac62b97ef57b5610d186501e698
    Cycles: 2478012
    lua5.4: /home/user/machine-emulator/src/cartesi-machine.lua:3689: expected outputs Merkle root in tx buffer
note: the uarch-cycle run also exits with an error (after writing its hash); not asserted
VIOLATED: R4 / section 8: the CLI's computation-hash options must compute the claim for every guest, ...
run.sh: R4-RGPLAYERGUEST-1: exit 1 (bug present)
```

The prover ran it three times and the reviewer ran it twice. It exited 1 every time.

The reviewer checked that a correct fix makes the test pass. It made a scratch copy of `src/cartesi-machine.lua` with
only the line 3689 assert removed, pointed `CARTESI_MACHINE` at it and ran `test.lua` against it. The target's mcycle
computation hash was then `0x90b54dcb...273ec4`, equal to the PRT player's, and the test exited 0. The test was not
modified. The uarch-cycle hash is written before the abort, so only the missing mcycle-level claim is asserted. The
candidate was found, proved and reviewed on `claude-opus-5-5`, with no fallback.

### Trigger and reachability

Any guest that yields manual RX_ACCEPTED with a DATA field other than 32 triggers the stop. With the default
`check_outputs_merkle_root:true`, so does any guest that accepts with a root that differs from the host's frontier.
Three kinds of guest do this:

- an application that breaks the rollup interface;
- a buggy application;
- a correctly designed application that an input has taken over. Section 4 says: "Any input may take control of the
  firmware, the kernel, the rollup libraries, and the application."

The yield's DATA field (in `htif.tohost`) and the tx buffer are guest-writable. Section 2 says: "Any assignment of
guest-writable memory and registers is presumed reachable." The state is therefore reachable from any valid template
after one input.

### Rating

1. **Out of scope.** The following exclusions were checked:
   - *Applications that are not correctly designed.* This exclusion does not cover the defect under the best-supported
     reading. It covers "only what such an application gets, which is its outputs and its own correctness". It adds:
     "An application that breaks the rollup interface may leave its outputs unprovable, but it must never stop the
     honest operator from computing claims or producing proofs. Development tools may instead stop and report the
     violation." The last sentence covers the CLI only if its computation-hash run counts as a development tool rather
     than as a tool that computes claims (see the readings below).
   - *Stalls of an application that halts or yields with another reason.* This does not apply, because the guest
     accepts.
   - *Deliberate state change through the machine API.* This does not apply, because only running and delivering inputs
     happen.
2. **Role.** The component is Support (AUDIT.md table, quoted above). Section 3 says: "A defect that only a support
   component shows is Medium when it would rate High or Critical in the role the component stands in for, such as ...
   the honest operator for an implementation of an operator or a tool that computes claims." This clause covers the
   CLI's `--mcycle-computation-hash`, which the manual says produces the honest player's mcycle claim. The settled
   reading of this campaign applies too: "When a Support component (the PRT player, the CLI) fails on its own operator
   path, rate it under section 3's stand-in rule". No honest-operator component shows the defect: the PRT player,
   built on the emulator's `collect_mcycle_root_hashes`, computes the claim.
3. **High and Medium cases.** In the stood-in honest-operator role, no listed High or Medium case fits. The trigger is
   a reachable guest state, not data the operator may decline, not an unreachable state, and not a host setup. As a
   support defect, it matches the Medium case "A defect that only a support component shows, when section 3 rates it
   Medium".
4. **Critical (in the stood-in role).** R4 says: "From any reachable state, at the position where it is reached, the
   honest operator can always compute the claim ... This holds for every guest, whether or not its application is
   correctly designed (section 8)." The defect breaks this at a reachable state. "Computing claims" is also on the
   honest operator's path (section 2). Section 3 caps it at Medium for Support.

Two readings give different classes:

- **Best-supported reading: Medium.** The computation-hash options make the CLI a tool that computes claims, standing
  in for the honest operator. Three facts support this:
  - the manual's statement that the honest player's claim "must equal the hash `cartesi-machine` produced";
  - section 3's separate naming of "a tool that computes claims";
  - the CLI's own help, which promises a computation hash for other interface-breaking fixed points.
- **Second reading: Out of scope.** The CLI is a development tool, and its assertion error "report[s] the violation".
  What decides between them is whether section 8's "development tools" includes a tool whose documented job is
  computing the claim. The text does not say, and the campaign's settled reading favours the first.

### Possible solution and risks

In `flush_pending_outputs`, do not assert on the tx-buffer length or root on the accepted path. If `#data` is not
`cartesi.HASH_SIZE`, or (with `check_outputs_merkle_root`) the root differs from the frontier, print a warning and
continue. Then mark the epoch so that output proofs and `outputs_merkle_root_proof` are not written, because the
referee could not use them. This would be like the PRT player's `outputs_merkle_root_mismatch` anomaly, and like the
CLI's existing treatment of unexpected fixed points. The computation-hash builder then reaches `end_input` as for any
other accepted input.

There are three risks:

- **Users who rely on the loud failure.** Developers who use the CLI to catch application bugs lose the hard failure.
  A distinct non-zero exit status after the hash is written, or a strict option, would keep that.
- **Malformed root saved to disk.** `save_cmio_outputs_merkle_root` would write a root file whose length is not 32. It
  should be skipped or flagged.
- **Resumable runs.** These must record the mark so that a later invocation does not produce proofs for the epoch.

### Risk of not fixing it

No deployment runs the CLI, so no funds are exposed. Anyone who computes or checks claims with the CLI, as the manual
shows, gets no claim when a guest accepts with a malformed outputs root. Any input sender can cause this with one
accepted input, by taking over the application or by targeting a misbehaving one. An operator built on this flow
would leave the epoch undefended, and a dishonest claim could settle unopposed. As mitigations outside the code, use
the PRT player or the emulator's `collect_mcycle_root_hashes` API, which compute the claim. The manual could also state
that the CLI stops on such guests.
