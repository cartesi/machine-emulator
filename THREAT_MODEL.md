# Threat Model

This document defines the security model of the Cartesi Machine emulator. It covers what must hold, who the adversary
is, what counts as a vulnerability, and what does not. It describes concepts, not code locations, so it stays valid
when code is reorganized. The emulator's user manual is the specification it refers to, in particular the manual's
blockchain perspective. It covers disputes that a permissionless refereed tournament bisects down to a single uarch
transition, which the referee then verifies.

## 1. Security goal

> Suppose one honest operator runs the emulator correctly, on the resources the deployment was sized for, and the
> chain includes its transactions within the dispute clocks. Then no adversary can make a correctly designed
> application settle a state that differs from the one the state transition function defines, or accept an output
> that the settled state does not commit to.

There are two ways to break it, and both are critical:

- **Soundness failure.** From a reachable before-state, a verifier accepts a proof of a transition that the state
  transition function does not produce. Or a proof verifier accepts a node that the committed tree does not hold at
  the stated index and height.
- **Completeness failure.** The honest operator computes a wrong hash, cannot produce a proof that verifies, or
  cannot respond in time. If the honest claim is eliminated, a dishonest claim can win.

The emulator does not move funds itself. It is the referee's ground truth. A bug in it is a bug in every contract
that settles on it.

## 2. Terms

- **State.** Everything that can influence a future transition. The state is mapped into the physical address space
  and hashed in full. It includes:
  - memories, the receive buffer, and the transmit buffer;
  - the processor, uarch, and device registers, including the input's mcycle deadline and the unreproducible mode;
  - any cached address-translation state;
  - the range descriptors;
  - the revert root hash.
- **Content hash.** The Merkle root of the actual contents of a state.
- **Reproducible machine.** A machine created without the unreproducible mode.
- **Dispute constants.** The fixed values that size the dispute grid:
  - the input limit per epoch;
  - the mcycle limit per input;
  - the uarch cycle limit per mcycle;
  - the sampling period of computation hashes.
- **Position.** A point in the dispute grid: input slot, mcycle within the input, and uarch cycle within the mcycle.
- **Input's mcycle deadline.** The last mcycle the current input can reach. Reaching it stops the input. An
  advance-state delivery that changes the state sets it to the delivery's mcycle plus the mcycle limit per input,
  minus one, saturating at the largest mcycle.
- **Revert root hash.** A hash held in the state. It records the content hash of the state to which the current input
  was delivered.
- **Rejecting instruction.** The instruction that yields manually with the rejected reason.
- **Canonical state.** The state that the protocol assigns to a position. It is the state that the transition forms
  reach from the valid template, with one exception, which follows a rejected input:
  - The exception covers every mcycle boundary from the one that ends the rejecting instruction until the next
    delivery that changes the state.
  - At those boundaries, the canonical state is the state to which the rejected input was delivered.
  - The uarch trajectory of every later mcycle starts from that state.

  The rejected contents are discarded, not reverted in place.
- **Canonical hash.** The content hash of the canonical state. At the mcycle boundary that ends the rejecting
  instruction, transitions obtain it from the revert root hash. At later boundaries covered by the exception, it is
  the content hash of that state itself. Every rule about agreement or verification speaks of the canonical hash.
- **Transition form.** What the referee verifies at a position. The position, the dispute constants, and the on-chain
  input record determine it. There are three forms:
  - an ordinary uarch step;
  - at the start of an input slot that holds an input, the delivery of that input followed by a uarch step;
  - at the end of an mcycle, a uarch step followed by the uarch reset.
- **Referee parameters.** Everything a verifier takes from the referee rather than from the proof:
  - the before-hash;
  - the transition form;
  - the tree index and height at which each node of a computation-hash or extraction proof is authenticated, and the
    height of its tree;
  - the input bytes and the request type;
  - the revert root hash;
  - the hash function.
- **Valid template.** A reproducible machine that meets all of these conditions:
  - it was created from a configuration by operations the manual specifies;
  - it is at an mcycle boundary, with the uarch in its pristine reset state;
  - it is waiting at a manual yield with the accepted reason;
  - its transmit buffer holds the outputs Merkle root of every output that the application accepted before it, which
    at genesis is the root of the empty outputs tree;
  - it uses the hash function of its deployment's verifiers;
  - its content hash, recomputed from its contents alone, matches the on-chain commitment.
- **Reachable state.** A state that some input sequence produces from a valid template. Any assignment of
  guest-writable memory and registers is presumed reachable. A state is unreachable only if no input sequence produces
  it from any valid template.
- **State transition function.** The map from a state at one position, together with the referee parameters of its
  transition form, to the hash at the next position. The manual's documented semantics define it on every state. On a
  canonical state, it yields the canonical hash. The pinned artifacts of a deployment must implement it. Section 6
  constrains it.
- **Correctly designed application.** One that meets two conditions:
  - On every input sequence, its guest follows the rollup interface that the manual specifies. After each input, it
    yields manually with the accepted or the rejected reason. When it accepts, it leaves in the transmit buffer the
    outputs Merkle root of every output it accepted. That includes the outputs its template already commits to, and
    the outputs emitted while processing the inputs it accepted.
  - It bounds its own mcycle usage. Every input yields manually no later than the input's mcycle deadline, and the
    total stays within what the deployment was sized for (A7).
- **Honest claim.** The claim the honest operator computes, at every level. It includes the trajectory the claim
  commits to, not only its final state.
- **Honest operator's path.** Every operation the honest operator performs to defend its claim:
  - obtaining its valid template;
  - advancing the machine;
  - delivering inputs;
  - storing and reloading the machine;
  - computing claims;
  - producing proofs.

## 3. What the emulator provides to the protocol

- **Canonical hashes, and Merkle proofs of any aligned node of the canonical state.**
- **For each transition form, a producer that logs it and a verifier that replays the log.** Both work under the
  deployment's hash function. The verifiers also run on-chain.
- **Computation hashes.** These are Merkle trees of canonical hashes sampled along the computation, and they are the
  claims that the dispute bisects. At the mcycle level, a computation hash spans an epoch, with one leaf per sampling
  period. At the uarch level, it spans the uarch cycles of one sampling period. A computation hash can be built whole
  or in parts.

Only advance-state inputs are part of the verified history (R4).

## 4. Trust boundaries

```
  untrusted                            |  trusted by the honest operator
  -------------------------------------+-----------------------------------------
  input senders (any bytes, any count) |  the emulator binary and its build
  dishonest claimants (any number,     |  the operator's host, keys, and node
    any logs, any proofs, any timing)  |  the intent of every host API caller
  guest code after it reads an input   |  the valid template it chose to defend
  data relayed by the node from others |  the hash primitives and the chain
```

- **The guest has two roles.** With respect to containment, the guest is fully adversarial. Any input may take control
  of the firmware, the kernel, the rollup libraries, and the application. It may then run any instruction stream at
  any privilege level. With respect to semantics, the guest is a victim. A correct guest relies on the emulator to
  implement the specified architecture exactly (R7).
- **What the emulator interprets.** Of everything the guest communicates to the host, the transition function
  interprets only these:
  - halt;
  - manual and automatic yields;
  - the accepted and rejected reasons of a manual yield;
  - the other device commands the manual specifies.

  The outputs Merkle root, the output payloads, and every other yield reason are opaque guest data that the state
  merely commits to.
- **Logs and proofs are adversarial.** A verifier must assume that every count, index, address, size, and hash it
  receives was chosen to fool it.
- **Host API callers are trusted in intent, not in data.** Whoever can call the API can change anything, by design.
  But much of what a node passes through the API comes from outside the node: input payloads, logs, proofs, and
  hashes. Every path that carries such data must be memory-safe and bounded, and must report errors without
  terminating the process. The honest operator cannot decline some of this data, such as input payloads, because it
  must process them to compute its claim. No host API, local or remote, is an authentication boundary. Exposing one
  to an untrusted party is outside this model.
- **Snapshots are trusted input.** This model makes no guarantee about loading a snapshot that the emulator did not
  write and that does not meet every condition of a valid template. A
  template the operator did not create is defended only once it meets every condition of a valid template.

## 5. Deployment obligations the emulator relies on

The goal holds only if the deployment meets these obligations. A deployment that violates any of them breaks the goal
even when the emulator is correct. The manual's permissionless refereed tournament is the normative model of what the
referee verifies and derives. The simplifications that the manual lists for it are not normative, and neither are its
clock values. Any other disagreement between a deployed referee and the model is a defect in one of the two.

- **A1. Agreed before-state.** In any match against the honest claim, the before-hash given to a verifier must be one
  of two things:
  - a canonical hash on which the claims agree, either the match's own claims or, for a uarch-level match, the claims
    of its enclosing match, authenticated as a leaf at its position;
  - the canonical hash that the epoch starts from, as settled on-chain.

  A uarch-level claim counts only if its last leaf, authenticated as in A2, is one of the two states that its
  enclosing match disagrees on. The uarch result decides the enclosing match only through the winner's last leaf,
  never through who posted it.
- **A2. Position-derived parameters.** The referee derives the transition form, and the tree index and height at
  which each node is authenticated, from three sources: the disputed position, the on-chain input record, and its own
  constants. A
  hash is accepted as a computation-hash leaf only when it is authenticated at height zero of the full tree, never as
  the root of a subtree.
- **A3. Referee-held inputs.** Input bytes come from the on-chain input record. The request type is always advance
  state. The input record assigns no more inputs to an epoch than the input limit per epoch.
- **A4. Revert hash.** At delivery, the revert root hash given to the verifier equals the before-hash.
- **A5. Outputs only from accepted states.** An outputs Merkle root is defined only for a settled canonical state that
  waits at a manual yield with the accepted reason. A valid template is such a state. Extracting the root requires
  authenticating that status in the same state. In any other final state, the transmit buffer holds guest data with no
  meaning. Examples: after a halt, after a manual yield with any reason other than accepted or rejected, or after a
  stop at the input's mcycle deadline without a manual yield. The settled state is the last leaf of the winning
  claim, authenticated as in A2.

  An output is accepted only through a proof that authenticates a hash as a leaf of the full-height outputs tree.
  That hash is the hash of the output's exact encoded bytes, as the guest emitted them. The leaf sits at height zero
  and at the output's index. That tree's root must be the one extracted from the settled state.
- **A6. One version per deployment.** Every verifier, every pinned artifact, and every honest operator in a
  deployment implements the same state transition function (R13).
- **A7. Sized clocks.** The dispute constants and clocks leave room for the honest claim to play the logarithmic
  number of matches that a tournament forces on it, at the worst-case costs of R12.

## 6. Rules

**R1. Determinism.** For a reproducible machine, the canonical hash at the next position is a pure function of the
canonical state at the current position and the referee parameters of its transition form. It must not depend on any
of the following:

- host OS, CPU, or endianness;
- compiler or optimization level;
- thread count or parallel scheduling;
- memory layout or uninitialized data;
- wall-clock time or timing;
- undefined behavior.

No configuration, runtime option, or file outside the hashed state, other than the referee parameters, may change
any transition. Time inside the machine derives only from the cycle counter. Floating-point results must be bit-exact
and independent of the host's floating-point hardware.

**R2. One transition function, many implementations.** Wherever two of the following reach the same position, they
must agree on its canonical hash:

- native interpretation;
- the uarch running the interpreter, plus the uarch reset;
- every log producer and every log verifier;
- the on-chain verifiers;
- the computation-hash builders, whole or in parts;
- input delivery;
- every way of copying, persisting, restoring, or sharing a machine.

A run may stop and resume, for example at a cycle target, at a yield, or for console output. Stopping and resuming
must leave the state exactly as an uninterrupted run would. Agreement includes every boundary of the dispute grid and
of a run:

- fixed points;
- input boundaries;
- the first input after a rejection;
- the last uarch cycle of an mcycle;
- the last mcycle of an input;
- every limit set by a dispute constant;
- interrupts.

**R3. Verifier soundness.** Fix the referee parameters. Every log that a verifier accepts must then yield the same
after-hash, and that after-hash must be the canonical hash that the state transition function defines. Two kinds of
condition must not be confused:

- **Conditions on the log** are validity conditions. A log that fails one must be rejected. Examples: wrong order,
  wrong address, wrong size, duplicate, missing, or trailing data, inconsistent hashes, overflow, misalignment.
- **Conditions on the authenticated state or on the referee parameters** are semantics. They define the successor,
  which may be a no-op.

A verifier must never turn a log defect into an accepted no-op, nor a semantic no-op into a rejection.

**R4. Honest completeness.** From any reachable state, at the position where it is reached, the honest operator can
always:

- compute the claim;
- produce every requested node and proof;
- log the transition so that it verifies.

In particular:

- Input delivery never fails. When its preconditions on the state or the input do not hold (R5), it is a no-op that
  can be proved.
- The uarch completes one main-processor step, including traps, interrupts, and page walks. It halts no later than the
  uarch step that brings its cycle count to the last uarch position of the mcycle. That position belongs to the reset
  that closes the mcycle.
- No reachable state makes a log producer fail, overflow, or exceed its resource bounds (R12).
- After a rejection, every hash the honest operator commits to follows R6, however it is computed.
- Inspect-state requests are outside the verified history. Nothing from one may reach a state on the honest
  operator's path, and their results carry no guarantee.

**R5. Fixed points.** The fixed points of the main processor are:

- a halt;
- a manual yield;
- reaching the input's mcycle deadline.

From one of these, the canonical hash at every following mcycle boundary repeats until the next delivery that changes
the state. Within each such mcycle, the uarch follows the same trajectory every time, and its reset returns to the same
canonical state. Uarch steps leave the state unchanged in two cases: when the uarch is halted, and when its cycle
count has reached the last uarch position of the mcycle. Only the reset leaves those states.

An advance-state delivery changes the state only when both of the following hold:

- the input fits in the receive buffer;
- the machine waits at a manual yield with the accepted reason.

That delivery records the revert root hash and sets the input's mcycle deadline. Every other advance-state delivery is
a no-op.

**R6. Revert.** The revert root hash is written only by an advance-state delivery that changes the state, and it is
written with the value the referee supplied (A4). The input's mcycle deadline is likewise written only by such a
delivery.

Every mcycle-level path applies the rejection exception of the canonical state (section 2).
From the rejecting instruction until the next delivery that changes the state, the uarch-level hashes are content
hashes of these states:

- in the mcycle of the rejecting instruction, before the closing reset, states of the rejecting machine;
- in every later mcycle, the uarch trajectory that starts from the canonical state.

**R7. Faithful architecture.** The emulator implements the RISC-V specification and the devices as the manual
documents them, departing only where the manual documents a deviation. A correct guest relies on the architecture for
isolation and data integrity in the areas listed below. In these areas, any deviation lets an input subvert a correct
guest, even a deviation that is consistent across all paths:

- privilege levels;
- address translation and memory permissions;
- atomics and fences;
- traps and interrupts;
- the receive buffer, the transmit buffer, and the yield interface: contents, lengths, and reason encoding.

**R8. Guest containment.**

- The main processor reaches only the ranges that the range descriptors declare, with the declared permissions. The
  range descriptors themselves are read-only to the guest.
- Guest memory accesses cannot address any of the following:
  - the processor registers;
  - the uarch state and uarch memory;
  - the cached translation state;
  - the revert root hash;
  - the input's mcycle deadline;
  - the unreproducible mode.
- The guest reaches device registers only through the device semantics that the manual specifies. It changes
  processor registers and cached translation state only through instruction semantics. It can never change any of the
  following: the cycle counter, the input's mcycle deadline, the revert root hash, or the unreproducible mode.
- No guest action may corrupt host memory, crash or hang the host, or cause unbounded host allocation.

**R9. Hash integrity.** The content hash must equal the root of the actual contents. This applies to every cached,
incremental, or persisted hash, after any sequence of documented operations. It includes interrupted or failed
updates, and every snapshot the emulator itself writes. Precomputed hashes, such as those of empty subtrees, must be
correct for every supported hash function. In every tree the emulator defines, two different contents must never share
a root without a break of the hash primitive. That rules out confusing leaves with inner nodes, ambiguous heights, and
lost lengths.

**R10. Verifiers are safe on every before-state.** Cached or derived fields of a state may disagree with what they
derive from. Examples are cached translations and range descriptors. A verifier must remain memory-safe, bounded, and
deterministic whatever their values. Such disagreements are semantics (R3), not log defects. Stale cached translations
are architectural, and their effect must be reproduced exactly. A verifier may depend on the referee parameters, on
the constants of its protocol version, and on the authenticated log data, and on nothing else.

**R11. The referee fixes the parameters.** Every referee parameter comes from the referee, never from the proof.

- Each deployment fixes one hash function, which no proof can select. Every machine it disputes uses that hash
  function for life.
- Every transition form has exactly one verifier path.

**R12. Bounded cost.** Every unit of work has a worst case in host time and memory that is bounded and at most linear in
the cycles or bytes it covers. The units are:

- an mcycle;
- a uarch cycle;
- a delivery;
- a reset;
- a log;
- a part of a claim;
- a uarch-level claim.

Each unit is measured from a machine at its starting position. Reaching that position costs at most the mcycles from
the nearest retained input boundary, which the application's per-input usage bounds. A7 must cover that cost a bounded
number of times for every match, at either level, that the tournaments force on the honest claim. Every honest proof
fits the chain's per-transaction limits. The total cost of an epoch is the application's mcycle usage times these
bounds. Bounding that usage is the application's job, and sizing the deployment for it is the deployment's job (A7).

**R13. The transition function is the protocol.** These are all part of it:

- the interpreter semantics;
- the state layout;
- the device behavior;
- the uarch program and its pristine state;
- the hash-tree construction and hash functions;
- the computation-hash construction, including its sampling period and padding;
- the map from position to transition form;
- the dispute constants.

Changing any of them creates a new protocol version, and versions must never be mixed within a deployment (A6). The
honest operator must be able to detect and refuse a mismatch between its build and a deployment. Every artifact pinned
on-chain must be reproducibly buildable from audited source: the uarch program and its pristine hash, and the
verifier code.

**R14. Unreproducible machines stay outside the verifiable domain.** The unreproducible mode is fixed at creation and
recorded in the hashed state. In a reproducible machine, the host reaches the state only through deliveries and
deliberate host API changes. That rules out host devices, any other host input, and host-driven interrupts or timing.
Output to the host, such as console output, must not affect the state.

## 7. Adversary capabilities

Section 4 already lists the adversary's control over the guest and over logs and proofs. In addition, the
adversary can:

- post any number of claims (Sybils), with any computation hash, and abandon or defend them at will;
- hold any claim, including the honest one, and answer for it;
- under the honest claim, post uarch-level claims that end at the honest state along a fabricated trajectory;
- steer the dispute to any position of the honest computation, and force the honest claim through a logarithmic number
  of matches;
- send any number of inputs the deployment accepts, with payloads chosen to maximize the honest operator's
  cost (R12), including payloads larger than the receive buffer;
- race and reorder transactions within the chain's rules.

The adversary is not assumed to break the hash functions, to compromise the honest operator's host, or to censor the
chain beyond the dispute clocks.

## 8. Severity

**Critical**: breaks the goal. Except for the cases listed under High and Medium, violating any rule or obligation
at a reachable state, or anywhere on the honest operator's path, is critical. The following cases are critical as
well, even though they might look minor:

- a verifier defect, triggered by fabricated log data or a fabricated before-state, that can change the after-hash
  accepted for a reachable before-state;
- a unit of work whose worst-case cost a guest can make unbounded, super-linear, or larger than what the deployment
  was sized for;
- an honest proof that cannot fit the chain's per-transaction limits;
- memory corruption or code execution through any relayed data;
- a crash, hang, out-of-bounds read, or unbounded allocation caused by relayed data that the honest operator must
  process.

**High**: does not break the goal, but removes a margin that the goal relies on.

- A verifier that misbehaves only on demonstrably unreachable before-states, with no path into a reachable state.
  Misbehaving means being nondeterministic, accepting a wrong or second after-hash, not being memory-safe, or being
  unbounded. In an off-chain verifier, memory-safety defects that relayed logs or proofs can trigger are classified
  by the relayed-data entries instead.
- A divergence between paths only at demonstrably unreachable states.
- A crash, hang, out-of-bounds read, or unbounded allocation caused by relayed data that the honest operator may
  decline.
- A pinned artifact that cannot be reproducibly rebuilt, while the deployed artifact matches its audited source.
- A node that cannot detect a version mismatch, while every node in fact runs the deployment's version.
- A guest-triggered constant-factor increase in the worst-case cost of a unit of work that stays within what the
  deployment was sized for.

**Medium**: violates a rule or the manual without affecting the goal.

- An undocumented deterministic deviation, consistent across all paths, in behavior that no correct guest relies on
  for isolation or data integrity (R7).
- A verifier that accepts trailing data that does not affect its result (R3).
- Persistence defects off the honest operator's path (R9).

A contradiction between the manual and the behavior on a security-relevant point is a defect in one of the two. It
takes the severity it would have if the manual were right.

**Out of scope for the emulator.**

- Deliberate state changes made through the host API (section 4).
- An application that halts, yields manually with a reason other than accepted or rejected, or never yields, and so
  stalls. A5 governs what can then be extracted from its state.
- An application that is not correctly designed.
- Guest software that an input can subvert, as long as R7 and R8 hold.
- Defects triggered only by loading a snapshot that the emulator did not write and that does not meet the conditions
  of a valid template (section 4). Once a snapshot meets them, nothing it carries outside the hashed state may affect
  any transition (R1).
- Breaking the hash primitives.
- Nondeterminism in unreproducible machines (R14).
- Average-case performance that does not change the worst-case cost of any unit of work (R12).
