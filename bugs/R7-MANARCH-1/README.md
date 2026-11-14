# R7-MANARCH-1: the manual's advance-state delivery omits the `imcyclemax` write and the rx-buffer zero padding

## What is asserted

On the harness valid template `baremetal-template` (waiting at an rx-accepted manual yield), the test compares:

- **(A)** `machine:send_cmio_response(HTIF_YIELD_REASON_ADVANCE_STATE, input, root_hash)`, which is the implemented
  delivery (`src/send-cmio-response.cpp`). The log producer, the replay and the regenerated `SendCmioResponse.sol`
  use the same code.
- **(B)** only the state changes listed in the manual's description of a delivery (`doc/README.md`, the
  `#### Rollup` host loop, the prose after it, and the `send_cmio_response` API text): the revert root hash at
  `AR_SHADOW_REVERT_ROOT_HASH_START`, the input bytes in the CMIO RX buffer, reason and length in `htif_fromhost`,
  and `iflags_Y = 0`.

It checks two extra effects of (A):

1. **`imcyclemax`.** (A) sets it to `mcycle + 2^48 - 1`, saturating. The access log of `log_send_cmio_response`
   shows a write at `0x2f8`. (B) leaves it unchanged.
2. **Zero padding of the rx buffer.** After an earlier, longer input, (A) zeroes the bytes from the end of the new
   input up to the next power of two (at least 32 bytes). (B) leaves the earlier input's bytes there. For this
   check, `imcyclemax` is copied from (A) to (B).

For each effect, the test passes if (A) and (B) reach the same root hash, or if the manual documents that effect of
a delivery. Documented here means that some paragraph or list item of `doc/README.md` names the effect
(`imcyclemax`, or rx buffer together with zero/pad) and the delivery (`send_cmio_response`, deliver, advance-state).
The test fails if some effect is undocumented and changes the root hash.

## Requirement

- THREAT_MODEL.md, intro: "The emulator's user manual is the specification it refers to".
- Section 2, *State transition function*: "The manual's documented semantics define it on every state".
- R7: "The emulator implements the RISC-V specification and the devices as the manual documents them, departing
  only where the manual documents a deviation", including "The rx buffer, the tx buffer, and the yield interface
  (contents, lengths, and reason encoding)".
- Section 8: "A contradiction between the manual and the behavior on a security-relevant point is a defect in one
  of the two. It takes the severity it would have if the manual were right."

## Run

```sh
bugs/run.sh R7-MANARCH-1
```

It runs in under 1 s. It needs the built emulator and `bugs/harness/work/configs/baremetal-template`.

## Expected output on audit/prt2 (exit 1)

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

The test exits 0 once both effects are documented as effects of a delivery, or once the delivery stops making them.
This was checked by running it against a copy of the manual with one added sentence that documents both effects.
