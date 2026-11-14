## R7-MANARCH-1

**Title.** The manual's specification of an advance-state delivery leaves out two hashed-state writes that every delivery path makes: `imcyclemax = mcycle + 2^48 - 1` (saturating) and zero padding of the rx buffer.

**Severity.** Medium

### Problem

The threat model makes the manual the specification ("The emulator's user manual is the specification it refers to";
section 2: "The manual's documented semantics define it on every state"). The manual describes an advance-state
delivery in three places, and each lists the same four state changes:

- the `#### Rollup` host loop (doc/README.md ~7795-7799): "Write the current state hash to the state at
  AR_SHADOW_REVERT_ROOT_HASH_START / Write ABI-encoded EvmAdvance(...) to CMIO RX buffer ... / Write
  HTIF_YIELD_REASON_ADVANCE_STATE to `REASON` and `length` as `DATA` in `fromhost` / Reset register `iflags_Y` to 0";
- the prose after it (~7855-7861): the call records the state hash, "also writes the request to the CMIO RX buffer
  and its type and length to the HTIF register `fromhost`, and unblocks the machine by clearing its `iflags_Y`
  register";
- the `send_cmio_response` API text (~4943-4953): it "writes `<data>` into `cmio.rx_buffer`, records the reason and
  length in `htif_fromhost`, and clears `iflags_Y`", and records the revert root hash for advance-state delivery.

The implemented delivery makes two more writes. Both change the state hash:

1. It sets `imcyclemax` to `mcycle + 2^48 - 1`, saturating at `2^64 - 1`. The access log shows a write at `0x2f8`.
   The manual never says that a delivery writes `imcyclemax`. Its register list says only "Register `imcyclemax`
   holds the inclusive mcycle limit", and the configuration default is `0xffffffffffffffff`.
2. It zero-fills the rx buffer from the end of the input up to the next power of two, at least 32 bytes. After a
   longer earlier input, bytes the manual's delivery would leave in place are zeroed. The manual mentions no padding.

So a delivery implemented from the manual (by a second node, or by an auditor checking `SendCmioResponse.sol` against
the specification) reaches a different state hash from the one every implemented path computes. All implemented paths
agree with each other, because they share `src/send-cmio-response.cpp`, and so does the regenerated step. The goal of
section 1 is therefore not broken. What is broken is the rule that the manual defines the transition function: the
manual gives the wrong transition for a step that is on every input boundary, and R13 makes "The accesses each logged
transition makes" part of the protocol.

### Component, role and area

Input delivery: `send_cmio_response` and its log producer and replay. AUDIT.md table: "Interpreter, state-access
layers, devices, uarch program, hash tree, log producers, ..., input delivery, ... | Honest operator". The same code
is regenerated into `SendCmioResponse.sol` (Referee verifier), which agrees with the emulator. The disagreement is
between all of them and the manual (doc/README.md, `#### Rollup` and the `send_cmio_response` API text), which is
the specification.

### Location

- `src/send-cmio-response.cpp`, `send_cmio_response`: `writeImcyclemax(a, imcyclemax)` (~l.66-71) and
  `writeMemoryWithPadding(a, AR_CMIO_RX_BUFFER_START, data, dataLength, writeLengthLog2Size)` (~l.75).
- `src/state-access.hpp` `do_write_memory_with_padding` (~l.450-463): `fill_memory(paddr + data_length, 0, ...)`.
- doc/README.md: host loop ~7790-7799, prose ~7855-7861, API text ~4943-4953, register list ~7384.

### Evidence and test

`bugs/R7-MANARCH-1/` contains `test.lua`, the test, and `README.md`, which describes it. Run it with
`bugs/run.sh R7-MANARCH-1`. It takes under 1 s and needs the built emulator and
`bugs/harness/work/configs/baremetal-template`.

The test loads the harness valid template `baremetal-template`, which waits at an rx-accepted manual yield. It then
compares two deliveries:

- (A) `send_cmio_response(ADVANCE_STATE, input, root)`;
- (B) the manual's four writes, done literally with `write_memory` (revert root hash, rx buffer) and `write_reg`
  (`htif_fromhost`, `iflags_Y`).

For each extra effect, the test passes if (A) and (B) reach the same root hash, or if some paragraph or list item of
doc/README.md names that effect together with a delivery. Case 1 delivers to the template itself. Case 2 delivers a
short input after the guest accepted a 1316-byte input, with `imcyclemax` copied from (A) to (B) so that only the rx
buffer can differ.

The reviewer re-ran it four times, and it exited 1 each time with the same output:

```
case 1: mcycle 3526372, imcyclemax before 0xffffffffffffffff
  send_cmio_response : imcyclemax 0x100000035cee3 fromhost 0x144 iflags_Y 0 root b6d9e351...
  manual's 4 writes  : imcyclemax 0xffffffffffffffff fromhost 0x144 iflags_Y 0 root 46e884f7...
  log_send_cmio_response writes imcyclemax (0x2f8): true
  manual documents that a delivery writes imcyclemax: no
  roots equal once imcyclemax is copied from (A): true
case 2: previous input 1316 bytes, new input 324 bytes
  root (A) 8f51cc9d...
  root (B) 71600514... (B with imcyclemax copied from A)
  rx buffer differs at offsets [0x144, 0x1ff]: (A) zero, (B) previous input's bytes
  manual documents zero padding of the rx buffer by a delivery: no
  - delivery sets imcyclemax (0x100000035cee3) but the manual's delivery lists no such write; root hashes differ
  - delivery zero-fills the rx buffer past the input (offsets 0x144-0x1ff) but the manual's delivery only writes the input; root hashes differ
VIOLATED: an advance-state delivery changes the state exactly as the manual documents it ...
run.sh: R7-MANARCH-1: exit 1 (bug present)
```

Case 1 shows that `imcyclemax` is the only difference: the roots match once it is copied. The prover reports that the
test exits 0 against a copy of the manual with one added sentence that documents both effects. The reviewer did not
change the test.

### Trigger and reachability

Every advance-state delivery that changes the state triggers effect 1. That includes the first input delivered to any
valid template, and the honest operator performs such deliveries on its path ("Delivering inputs"). Effect 2 needs an
input shorter than an earlier one whose bytes still lie past the new input's end, rounded up to the next power of two
of at least 32 bytes. Any input sender can arrange this by posting two inputs of different lengths. No unreachable
state is involved.

### Rating

1. Out of scope: no. The trigger is an ordinary delivery on the honest operator's path. The exclusion "The effect of a
   deliberate state change made through the machine API, when the API performs it as documented" does not apply,
   because the finding is that `send_cmio_response` does more than it is documented to do. No snapshot, obligation
   violation, unreproducible machine or misdesigned application is needed.
2. Role: input delivery is "Honest operator" in the AUDIT.md table. Section 3 says this role covers "The transition
   function, its log producers, ... input delivery ... in every deployment". The regenerated step (Referee verifier)
   agrees with the emulator, so no verifier or path divergence exists. The defect is a disagreement with the
   specification. Section 8: "A contradiction between the manual and the behavior on a security-relevant point is a
   defect in one of the two. It takes the severity it would have if the manual were right." This clause covers the
   component: the point is the hashed result of the input-boundary transition, which R13 makes part of the protocol.
3. High and Medium cases: if the manual's four-write delivery were right, every implemented path would deviate from it
   in the same deterministic way. That matches "An undocumented deterministic deviation, consistent across all paths,
   in behavior that no correct guest relies on for isolation or data integrity (R7)". The guest cannot read
   `imcyclemax` (R8). A correct guest reads only the `length` bytes that `fromhost` reports, so it relies on neither
   effect. Rating: Medium.
4. Critical: not reached under the preferred reading. Under a literal reading, "The manual's documented semantics
   define it on every state" (section 2) together with R3 would make the deviation a wrong transition. R7's "In these
   areas, any deviation lets an input subvert a correct guest, even a deviation that is consistent across all paths",
   with "The rx buffer, the tx buffer, and the yield interface (contents, lengths, and reason encoding)", would make
   the rx-buffer padding Critical, if bytes past the delivered length count as rx-buffer "contents".

Readings: Medium is preferred. Critical follows under the literal readings in step 4: section 2 for the whole
delivery, and R7's area list for the padding. These facts favor Medium: no correct guest can observe the padding as a
change to its input, and all paths, the deployed verifier included, agree. Low follows if the manual's delivery texts
are read as non-exhaustive illustrations, and if the blockchain chapter's "Each input owns 2<sup>48</sup> mcycles of
the epoch, counted from the state that receives it" (~2689, ~9021), together with "imcyclemax holds the inclusive
mcycle limit", counts as documenting effect 1. That reading is weaker. Those sentences describe the computation-hash
grid and never name a write to `imcyclemax`, its exact value or its saturation. Nothing in the manual documents
effect 2 at all. Under that reading too, effect 2 remains an undocumented change to hashed rx-buffer contents.

### Possible solution and risks

Document both effects in doc/README.md. In the host loop, add a step before the rx write, for example "Set register
`imcyclemax` to `mcycle` + 2^48 - 1 (saturating at 2^64 - 1)". After the rx write, add "zero-fill the CMIO RX buffer
from the end of the input to the next power of two of at least 32 bytes". Make the prose after the loop and the
`send_cmio_response` API text say the same, and the register list should say that an advance-state delivery sets
`imcyclemax`. This is a documentation-only fix, so it carries no protocol risk. Changing the code to match the
current manual would instead be wrong: it would drop the per-input mcycle limit that the dispute grid relies on (R5,
R6), and it would change the protocol version (R13).

### Risk of not fixing it

The goal is not exposed in a deployment that runs only these implementations, since all paths agree. The risk lies in
the specification. An independent implementation of delivery written from the manual (a second node, a verifier port,
a ZK or alternative step) would compute different input-boundary hashes and lose disputes, or fail to detect
divergences. Auditors who check `SendCmioResponse.sol` against the manual would see writes the specification does not
explain. No party needs to trigger it: it happens on every delivery. Until the manual is fixed, the only mitigation
outside the code is to treat `src/send-cmio-response.cpp` as normative.
