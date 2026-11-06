# Threat Model

This document defines the security model of the Cartesi Machine emulator. It covers what must hold, who the adversary
is, what counts as a vulnerability, and what does not. It describes concepts, not code locations, so it stays valid
when code is reorganized. The emulator's user manual is the specification it refers to, in particular the manual's
blockchain perspective. It covers disputes that a permissionless refereed tournament bisects down to a single uarch
transition, which the referee then verifies. Disputes settled by other proof forms, such as a step of the main
processor verified inside a proof system, are outside its scope.

## 1. Security goal

> Suppose one honest operator runs the emulator correctly, on the resources the deployment was sized for, and the
> chain includes its transactions within the dispute clocks. Then no adversary can make a correctly designed
> application settle a state that differs from the one the state transition function defines, or accept an output
> that the settled state does not commit to.

There are two ways to break it, and both are critical.

- **Soundness failure.** From a reachable before-state, a verifier accepts a proof of a transition that the state
  transition function does not produce. Or a proof verifier accepts a node that the committed tree does not hold at
  the stated index and height.
- **Completeness failure.** The honest operator computes a wrong hash, cannot produce a proof that verifies, or
  cannot respond in time. If the honest claim is eliminated, a dishonest claim can win.

The emulator does not move funds itself. It is the referee's ground truth. A bug in it is a bug in every contract
that settles on it.

## 2. Terms

- **State.** Everything that can influence a future transition. The state is mapped into the physical address space
  and hashed in full. It includes the following.
  - Memories, the rx buffer, and the tx buffer.
  - The processor, uarch, and device registers, including `imcyclemax` and the unreproducible mode.
  - Any cached address-translation state.
  - The PMA entries.
  - The revert root hash.
- **Content hash.** The Merkle root of the actual contents of a state.
- **Cached hash-tree data.** Data that a stored machine carries next to its contents, such as the hashes and change
  records kept to speed up hashing. It is outside the state hash, and loading does not check it. The root hash of a
  machine loaded with it, and any verification of its hash tree, read it.
- **Reproducible machine.** A machine created without the unreproducible mode.
- **Deployment.** A referee with its verifiers and dispute constants, the on-chain input record it reads, and the
  validator nodes that defend an application's claims before it.
- **What the deployment was sized for.** The worst-case costs, clocks and host resources that a deployment provisions
  for (A7).
- **Epoch.** As many consecutive input slots as the input limit per epoch, whose final state one tournament settles.
  The on-chain input record fills a prefix of them.
- **On-chain input record.** The inputs, in order and with their bytes, that the deployment assigns to each epoch.
- **Claim and match.** A claim is a computation hash that a party commits to on-chain. A match is a bisection between
  two claims that disagree. It ends by timeout, by a nested tournament at the finer level, or, at the finest level, by
  the referee verifying one transition at the disputed position.
- **Pristine uarch.** The uarch program and uarch state that a uarch reset produces, whose hash a deployment fixes
  on-chain.
- **Dispute constants.** The fixed values that size the dispute grid. They are the input limit per epoch, the mcycle
  limit per input, the uarch cycle limit per mcycle, and the sampling period of computation hashes.
- **Position.** A point in the dispute grid, made of an input slot, an mcycle within the input, and a uarch cycle
  within the mcycle.
- **`imcyclemax`.** The register that holds the last mcycle the current input can reach. Reaching it stops the input.
  An advance-state delivery that changes the state sets it to the delivery's mcycle plus the mcycle limit per input,
  minus one, saturating at the largest mcycle.
- **Revert root hash.** A hash held in the state. It records the content hash of the state to which the current input
  was delivered.
- **Rejecting instruction.** The instruction that yields manually with the rejected reason.
- **Canonical state.** The state that the protocol assigns to a position. It is the state that the transition forms
  reach from the valid template, with one exception, which follows a rejected input.
  - The exception covers every mcycle boundary from the one that ends the rejecting instruction until the next
    delivery that changes the state.
  - At those boundaries, the canonical state is the state to which the rejected input was delivered.
  - The uarch trajectory of every later mcycle starts from that state.

  The rejected contents are discarded, not reverted in place.
- **Canonical hash.** The content hash of the canonical state. At the mcycle boundary that ends the rejecting
  instruction, transitions obtain it from the revert root hash. At later boundaries covered by the exception, it is
  the content hash of that state itself. Every rule about agreement or verification speaks of the canonical hash.
- **Transition form.** What the referee verifies at a position. The position, the dispute constants, and the on-chain
  input record determine it. There are three forms.
  - An ordinary uarch step.
  - At the start of an input slot that holds an input, the delivery of that input followed by a uarch step.
  - At the end of an mcycle, a uarch step followed by the uarch reset.
- **Referee parameters.** Everything a verifier takes from the referee rather than from the proof.
  - The before-hash.
  - The transition form.
  - The tree index and height at which each node of a computation-hash proof, or of a proof that extracts the outputs
    Merkle root (A5), is authenticated, and the height of its tree.
  - The input bytes and the request type.
  - The revert root hash.
  - The hash function.
- **Valid template.** A reproducible machine that meets all of these conditions.
  - It was created from a configuration, without disabling any of the emulator's consistency checks, and changed only
    by running it and delivering inputs.
  - Its registers hold only values that the RISC-V specification and the manual allow for them.
  - It is at an mcycle boundary, with the uarch in its pristine reset state.
  - It is waiting at a manual yield with the accepted reason.
  - Its tx buffer holds the outputs Merkle root of every output that the application accepted before it, which at
    genesis is the root of the empty outputs tree.
  - It uses the hash function of its deployment's verifiers.
  - Its content hash, recomputed from its contents alone, matches the on-chain commitment. For a stored machine,
    "recomputed from its contents alone" means after rebuilding its cached hash-tree data (O1). A root hash read from
    a machine loaded without that rebuild does not check this condition.
- **Reachable state.** A state that some input sequence produces from a valid template. Any assignment of
  guest-writable memory and registers is presumed reachable. A state is unreachable only if no input sequence produces
  it from any valid template.
- **State transition function.** The map from a state at one position, together with the referee parameters of its
  transition form, to the hash at the next position. The manual's documented semantics define it on every state,
  except one where the uarch traps, which has no successor (R3). On a canonical state, it yields the canonical hash.
  The uarch program and the verifier code that a deployment fixes on-chain must implement it. Section 6 constrains
  it.
- **Correctly designed application.** One that meets two conditions.
  - On every input sequence, its guest follows the rollup interface that the manual specifies. After each input, it
    yields manually with the accepted or the rejected reason. When it accepts, it leaves in the tx buffer the outputs
    Merkle root of every output it accepted. That includes the outputs its template already commits to, and the
    outputs emitted while processing the inputs it accepted.
  - It bounds its own mcycle usage. Every input yields manually no later than `imcyclemax`, and the total stays within
    what the deployment was sized for (A7).
- **Honest operator.** A party that runs the emulator correctly to defend the result that the state transition
  function defines. The goal assumes at least one.
- **Honest claim.** The claim the honest operator computes, at every level. It includes the trajectory the claim
  commits to, not only its final state.
- **Honest operator's path.** Every operation the honest operator performs to defend its claim.
  - Obtaining its valid template. For a template the operator did not produce, this includes rebuilding its cached
    hash-tree data (O1).
  - Observing the chain.
  - Advancing the machine.
  - Delivering inputs.
  - Storing and reloading the machine. Reloading means loading a directory that O2 guarantees. A directory that its
    process was writing or sharing when it stopped is never reloaded (O2).
  - Computing claims.
  - Producing proofs.
  - Submitting transactions.
  - Restarting after a stop (O2).

Other sections define these terms: computation hash and the component roles (section 3), the machine API and data from
other parties (section 4), a directory that O2 guarantees (section 5), and a uarch trap (R3).

## 3. What the emulator provides to the protocol

- **Canonical hashes, and Merkle proofs of any aligned node of the canonical state.**
- **For each transition form, a producer that logs it and a verifier that replays the log.** Both work under the
  deployment's hash function. The verifiers also run on-chain.
- **Computation hashes.** These are Merkle trees of canonical hashes sampled along the computation, and they are the
  claims that the dispute bisects. At the mcycle level, a computation hash spans an epoch, with one leaf per sampling
  period. At the uarch level, it spans the uarch cycles of one sampling period. A computation hash can be built whole
  or in parts.

Only advance-state inputs are part of the verified history (R4).

A defect is rated by the most critical role among the components that show it (section 8). The roles are these.

- **Referee verifier.** A verifier whose acceptance settles disputes, such as the on-chain verifiers.
- **Referee model.** An implementation of the manual's referee model (section 5). It stands in for that normative
  model, and a disagreement between the two on what a referee verifies or derives is a defect in one of them, rated
  as if the manual were right, unless the manual's model itself violates one of A1 to A8; then the manual is the
  defect, rated as a defect of the referee model. A defect in what it accepts or derives is rated as if a deployed
  referee had it. Which claim a timeout or an elimination decides is part of what it derives. A defect that only
  changes how long a claim may take to respond, or only crashes or stalls the model, even when that stops other
  matches (A8), is rated as support. A defect it only inherits from a copy of a verifier that it calls is rated by
  that copy's role, and as a referee defect only if a referee verifier shares it. What it authenticates or derives
  under A1 to A5 is its own, whichever library does the work.
- **Honest operator.** The software that a production validator node runs on the honest operator's path. The
  transition function, its log producers, the computation-hash builders, the hash tree and its node proofs, input
  delivery, and storing, loading, cloning and syncing machines (within the limits of O1 and O2) play this role in
  every deployment.
- **Guest software.** The libraries and tools that implement the rollup interface for applications inside the
  machine. A defect in them is in scope only where an application depends on them as documented, and would be
  correctly designed if they worked as documented. A defect that lets an input make such an application deviate from
  the rollup interface is Critical, as an R7 deviation in the rx buffer, the tx buffer and the yield interface. Any
  other defect in them is Low.
- **Support.** Everything else used only for tests, demonstrations, development or diagnostics. Examples are copies
  of the verifiers whose acceptance settles nothing, implementations of an operator that no deployment runs, and
  development tools. A defect that only a support component shows is Medium when it would rate High or Critical in
  the role the component stands in for, such as a referee verifier for a copy of a verifier, or the honest operator
  for an implementation of an operator or a tool that computes claims. A library stands in for the most critical role
  among the components that reach the defect through it. Any other support defect is Low. A component in another role
  that shares the defect is rated by its own role.

Beyond those, which components play which role is a fact about deployments, not about the code. Each review states
it.

## 4. Trust boundaries

```
  untrusted                            |  trusted by the honest operator
  -------------------------------------+-----------------------------------------
  input senders (any bytes, any count) |  the emulator binary and its build
  dishonest claimants (any number,     |  the operator's host, keys, and node
    any logs, any proofs, any timing)  |  the intent of every machine API caller
  guest code after it reads an input   |  the valid template it chose to defend
  data relayed by the node from others |  the hash primitives and the chain
```

- **The guest has two roles.** With respect to containment, the guest is fully adversarial. Any input may take control
  of the firmware, the kernel, the rollup libraries, and the application. It may then run any instruction stream at
  any privilege level. With respect to semantics, the guest is a victim. A correct guest relies on the emulator to
  implement the specified architecture exactly (R7).
- **What the emulator interprets.** Of everything the guest communicates to the host, the transition function
  interprets only halt, manual and automatic yields, the accepted and rejected reasons of a manual yield, and the
  other device commands the manual specifies. The outputs Merkle root, the output payloads, and every other yield
  reason are opaque guest data that the state merely commits to.
- **Logs and proofs are adversarial.** A verifier must assume that every count, index, address, size, and hash it
  receives was chosen to fool it.
- **Callers of the machine API are trusted in intent, not in data.** The machine API is the C, Lua and JSON-RPC
  interface to a machine. Whoever can call it can change anything, by design. But much of what a node passes through
  it comes from other parties (input payloads, logs, proofs, and hashes). Every path that carries such data must be
  memory-safe and bounded, and must report errors without terminating the process. The honest operator must process
  the on-chain input record, the claims and moves it has to answer, and anything it needs to compute its own claim. It
  may decline logs and proofs that it only verifies for its own information. The machine API, local or remote, is not
  an authentication boundary. Exposing it to an untrusted party is outside this model.
- **Snapshots are trusted input.** This model makes no guarantee about loading a snapshot that the emulator did not
  write and that does not meet every condition of a valid template. A template the operator did not create is defended
  only once it meets every condition of a valid template. A snapshot's cached hash-tree data is not part of any
  valid-template condition, so a snapshot the operator did not write is defended only after that data is rebuilt (O1).
  A directory that O2 does not guarantee is not a snapshot the emulator wrote.
- **The chain is trusted as far as the operator's input policy confirms it.** The honest operator acts only on
  history that its policy treats as final, such as finalized blocks. A reorganization deeper than that is a failure of
  the chain, not an adversary capability, and the honest operator need not recover from it. Acting on history before
  it is final, and recovering when that history is replaced, is outside this model.
- **The operator's host is provisioned.** The goal assumes the resources the deployment was sized for, including CPU,
  memory and storage, and a host environment set up as the emulator documents. Host output channels, such as the
  console, accept every write the emulator makes, blocking if needed, and the manual must state this requirement.
  Sharing the host with other work that the deployment was sized for is not a fault. A host fault, such as a full disk
  or an output channel that refuses a write, may stop the honest operator, but the emulator must never turn one into a
  wrong hash, a wrong proof, or a directory that O2 guarantees but that later loads as a different state.

## 5. Obligations the emulator relies on

The goal holds only if the operator and the deployment meet these obligations. A violation of any of them breaks the
goal even when the emulator is correct.

### Operator obligations

- **O1. Adopting a stored machine rebuilds its hash tree.** An operator who adopts a stored machine it did not produce
  rebuilds the cached hash-tree data from the contents when loading it, and only then compares the root hash with the
  on-chain commitment.
- **O2. After a stop, resume only from a guaranteed directory.** A process that stops (crash, kill, or power loss)
  leaves every stored directory it was writing or sharing in an unspecified state. The operator discards those
  directories and resumes from a guaranteed one, such as the snapshot taken before the current input. The emulator
  guarantees a stored directory only when it was synced after the last change to its contents and, if a machine used it
  with shared backing storage, that machine was destroyed without a crash before that sync. Loading it without sharing
  and the documented atomic rename do not change it. A machine that uses it with sharing changes the directory on any
  call, read-only queries included, so loading the directory again with sharing ends the guarantee until the next
  destroy and sync. A stop at any other point, even partway through an instruction or an API call, can leave
  registers, memory and the hash tree in a combination that no execution reaches.

O1 and O2 bind the emulator too. The tools and reference implementations that ship with it must follow them, and the
emulator must make them possible to follow. A defect that defeats the rebuild itself, or that damages a directory
while O2 guarantees it, is not excused by them.

### Deployment obligations

The manual's permissionless refereed tournament is the normative model of what the referee verifies and derives. The
simplifications that the manual lists for it are not normative, and neither are its clock values. Any other
disagreement between a deployed referee and the model is a defect in one of the two.

- **A1. Agreed before-state.** In any match against the honest claim, the before-hash given to a verifier must be one
  of two things.
  - A canonical hash on which the claims agree, either the match's own claims or, for a uarch-level match, the claims
    of its enclosing match, authenticated as a leaf at its position.
  - The canonical hash that the epoch starts from, as settled on-chain.

  A uarch-level claim counts only if its last leaf, authenticated as in A2, is one of the two states that its
  enclosing match disagrees on. The uarch result decides the enclosing match only through the winner's last leaf,
  never through who posted it.
- **A2. Position-derived parameters.** The referee derives the transition form, and the tree index and height at
  which each node is authenticated, from three sources. They are the disputed position, the on-chain input record, and
  its own constants. A hash is accepted as a computation-hash leaf only when it is authenticated at height zero of the
  full tree, never as the root of a subtree.
- **A3. Referee-held inputs.** Input bytes come from the on-chain input record. The request type is always advance
  state. The input record assigns no more inputs to an epoch than the input limit per epoch. It accepts no input so
  large that the honest proof of its delivery would exceed the chain's per-transaction limits.
- **A4. Revert hash.** At delivery, the revert root hash given to the verifier equals the before-hash.
- **A5. Outputs only from accepted states.** An outputs Merkle root is defined only for a settled canonical state that
  waits at a manual yield with the accepted reason. A valid template is such a state. Extracting the root requires
  authenticating that status in the same state. In any other final state, the tx buffer holds guest data with no
  meaning. Examples are a halt, a manual yield with any reason other than accepted or rejected, and a stop at
  `imcyclemax` without a manual yield. The settled state is the last leaf of the winning claim, authenticated as in A2.

  An output is accepted only through a proof that authenticates a hash as a leaf of the full-height outputs tree.
  That hash is the hash of the output's exact encoded bytes, as the guest emitted them. The leaf sits at height zero
  and at the output's index. That tree's root must be the one extracted from the settled state.

  Conversely, the referee accepts every output that the settled state commits to, whenever its valid proof is
  presented. No party can make it stop accepting them.
- **A6. One version per deployment.** Every verifier, the uarch program fixed on-chain, and every honest operator in
  a deployment implements the same state transition function (R13).
- **A7. Sized clocks.** The dispute constants and clocks leave room for the honest claim to play the logarithmic
  number of matches that a tournament forces on it, at the worst-case costs of R12, while the honest operator also
  processes the inputs of later epochs. No rule of the referee may make the honest claim lose by timeout while it acts
  within its own clock.
- **A8. Isolated matches.** Failing to process one match's data, for any reason, must not stop, delay or decide any
  other match.

## 6. Rules

**R1. Determinism.** For a reproducible machine, the canonical hash at the next position is a pure function of the
canonical state at the current position and the referee parameters of its transition form. It must not depend on any
of the following.

- Host OS, CPU, or endianness.
- Compiler or optimization level.
- Thread count or parallel scheduling.
- Memory layout or uninitialized data.
- Wall-clock time or timing.
- Undefined behavior.

No configuration, runtime option, or file outside the hashed state, other than the referee parameters, may change
any transition. Time inside the machine derives only from the cycle counter. Floating-point results must be bit-exact
and independent of the host's floating-point hardware.

Cached hash-tree data is outside the hashed state. On the honest operator's path, it was either written by the
operator's own process into a directory that O2 guarantees, or rebuilt from the contents on adoption (O1). This rule
applies to it only in those two cases.

**R2. One transition function, many implementations.** Wherever two of the following reach the same position, they
must agree on its canonical hash.

- Native interpretation.
- The uarch running the interpreter, plus the uarch reset.
- Every log producer and every log verifier.
- The on-chain verifiers.
- The computation-hash builders, whole or in parts.
- Input delivery.
- Every way of copying, persisting, restoring, or sharing a machine.

Every register and every configuration value that affects a transition has one source of truth in the hashed state,
and every path reads it from there.

A run may stop and resume, for example at a cycle target, at a yield, or for console output. Stopping and resuming
must leave the state exactly as an uninterrupted run would. Agreement includes every boundary of the dispute grid and
of a run.

- Fixed points.
- Input boundaries.
- The first input after a rejection.
- The last uarch cycle of an mcycle.
- The last mcycle of an input.
- Every limit set by a dispute constant.
- Interrupts.

**R3. Verifier soundness.** Fix the referee parameters. Every log that a verifier accepts must then yield the same
after-hash, and that after-hash must be the canonical hash that the state transition function defines. Two kinds of
condition must not be confused.

- **Conditions on the log** are validity conditions. A log that fails one must be rejected. Examples are wrong order,
  wrong address, wrong size, duplicate, missing, or trailing data, inconsistent hashes, overflow, and misalignment.
- **Conditions on the authenticated state or on the referee parameters** are semantics. They define the successor,
  which may be a no-op.

A verifier must never turn a log defect into an accepted no-op, nor a semantic no-op into a rejection.

A uarch trap is the one condition on the authenticated state that has no successor. The uarch traps when it executes
an instruction it does not implement, an environment call it does not define or with arguments that call does not
accept, an access that its memory map does not allow, or an abort it executes deliberately. A pristine uarch program
must never trap from a reachable state. Such a trap means the uarch failed to implement the main-processor step, which
nothing can recover from, and it is Critical (R2, R4). Running the uarch natively, the computation-hash builders and
the log producers refuse every uarch trap instead of defining a successor. A verifier refuses a trap whenever the log
it receives already authenticates the condition. Detecting any other trap would need the verifier to authenticate
extra state. A verifier that accepts a trap its log does not authenticate has a High defect (section 8), because the
acceptance matters only from an unreachable before-state. R4 asks for proofs only from reachable states, so refusing
a trap from an unreachable state never breaks it.

**R4. Honest completeness.** From any reachable state, at the position where it is reached, the honest operator can
always compute the claim, produce every requested node and proof, and log the transition so that it verifies. In
particular, the following hold.

- This holds for every guest, whether or not its application is correctly designed (section 8), at the costs of R12
  for the mcycles the guest actually runs. Whether those fit the clocks is for the application and the deployment
  (A7).
- Every reproducible configuration that the emulator accepts, using the deployment's hash function and holding only
  register values that the RISC-V specification and the manual allow, yields a machine on which this rule holds. A
  configuration that would not is rejected when the machine is created.
- Input delivery with the referee parameters of its position never fails. When its preconditions on the state or the
  input do not hold (R5), it is a no-op that can be proved.
- The uarch completes one main-processor step, including traps, interrupts, and page walks. It halts no later than the
  uarch step that brings its cycle count to the last uarch position of the mcycle. That position belongs to the reset
  that closes the mcycle.
- No reachable state makes a log producer fail, overflow, or exceed its resource bounds (R12).
- After a rejection, every hash the honest operator commits to follows R6, however it is computed.
- Inspect-state requests are outside the verified history. Nothing from one may reach a state on the honest
  operator's path, and their results carry no guarantee.
- The honest operator observes the chain and submits its transactions within the dispute clocks. After a stop, it
  restarts from a directory that O2 guarantees and keeps defending its claim.
- The honest operator defends every epoch whose dispute is open, including while it processes the inputs of later
  epochs. It assigns inputs to epochs exactly as the referee does, including the input limit per epoch (A3).

**R5. Fixed points.** The fixed points of the main processor are a halt, a manual yield, and reaching `imcyclemax`.

From one of these, the canonical hash at every following mcycle boundary repeats until the next delivery that changes
the state. Within each such mcycle, the uarch follows the same trajectory every time, and its reset returns to the same
canonical state. Uarch steps leave the state unchanged in two cases, which are when the uarch is halted, and when its
cycle count has reached the last uarch position of the mcycle. Only the reset leaves those states.

An advance-state delivery changes the state only when the input fits in the rx buffer and the machine waits at a
manual yield with the accepted reason. That delivery records the revert root hash and sets `imcyclemax`. Every other
advance-state delivery is a no-op.

**R6. Revert.** The revert root hash is written only by an advance-state delivery that changes the state, and it is
written with the value the referee supplied (A4). `imcyclemax` is likewise written only by such a delivery.

Every path that produces a hash for a claim, a node or a proof applies the rejection exception of the canonical state
(section 2). The machine itself is not reverted. Its own root hash is then the content hash of the rejecting machine,
and the honest operator continues from the machine to which the input was delivered. From the rejecting instruction
until the next delivery that changes the state, the uarch-level hashes are content hashes of these states.

- In the mcycle of the rejecting instruction, before the closing reset, states of the rejecting machine.
- In every later mcycle, the uarch trajectory that starts from the canonical state.

**R7. Faithful architecture.** The emulator implements the RISC-V specification and the devices as the manual
documents them, departing only where the manual documents a deviation. A correct guest relies on the architecture for
isolation and data integrity in the areas listed below. In these areas, any deviation lets an input subvert a correct
guest, even a deviation that is consistent across all paths.

- Privilege levels.
- Address translation and memory permissions.
- Atomics and fences.
- Traps and interrupts.
- The rx buffer, the tx buffer, and the yield interface (contents, lengths, and reason encoding).

**R8. Guest containment.**

- The main processor reaches only the ranges that the PMA entries declare, with the declared permissions. The PMA
  entries themselves are read-only to the guest.
- Guest memory accesses cannot address the processor registers, the uarch state and uarch memory, the cached
  translation state, the revert root hash, `imcyclemax`, or the unreproducible mode.
- The guest reaches device registers only through the device semantics that the manual specifies. It changes
  processor registers and cached translation state only through instruction semantics. It can never change the cycle
  counter, `imcyclemax`, the revert root hash, or the unreproducible mode.
- No guest action may corrupt host memory, crash or hang the host, or cause unbounded host allocation.

**R9. Hash integrity.** The content hash must equal the root of the actual contents. This applies to every cached,
incremental, or persisted hash, after any sequence of documented operations. It includes interrupted or failed
updates, and every snapshot the emulator itself writes. Precomputed hashes, such as those of empty subtrees, must be
correct for every supported hash function. In every tree the emulator defines, two different contents
must never share a root without a break of the hash primitive. That rules out confusing leaves with inner nodes,
ambiguous heights, and lost lengths.

"Interrupted or failed updates" means updates that fail inside a running process, which then keeps using the machine.
"Every snapshot the emulator itself writes" means a directory that O2 guarantees.

**R10. Verifiers are safe on every before-state.** Cached or derived fields of a state may disagree with what they
derive from. Examples are cached translations and PMA entries. A verifier must remain memory-safe, bounded, and
deterministic whatever their values. Such disagreements are semantics (R3), not log defects. Stale cached translations
are architectural, and their effect must be reproduced exactly. A verifier may depend on the referee parameters, on
the constants of its protocol version, and on the authenticated log data, and on nothing else. Its outcome, including
whether it rejects, must not depend on its build configuration, such as the build type or whether assertions are
enabled.

**R11. The referee fixes the parameters.** Every referee parameter comes from the referee, never from the proof.

- Each deployment fixes one hash function, which no proof can select. Every machine it disputes uses that hash
  function for life.
- Every transition form has exactly one verifier path.

**R12. Bounded cost.** Each of the following operations has a worst case in host time and memory that is bounded and at
most linear in the cycles it executes or the bytes it covers. They are an mcycle, a uarch cycle, a delivery, a reset,
a log, a part of a claim, a uarch-level claim, a Merkle proof of the state, and storing, loading, cloning or syncing a
machine. Where a computation hash repeats the hash of a fixed point, the repetitions cost a bounded amount per run of
them, not per cycle.

Each is measured from a machine at its starting position. Reaching that position costs at most the mcycles from the
nearest retained input boundary, which the application's per-input usage bounds. A7 must cover that cost a bounded
number of times for every match, at either level, that the tournaments force on the honest claim. The total cost of an
epoch is the application's mcycle usage times these bounds. Bounding that usage is the application's job, and sizing
the deployment for it is the deployment's job (A7).

The honest operator's own work outside the emulator, such as observing the chain, keeping and persisting its own
records, and restarting, has a bounded cost per input, per yield, and per match, and its total grows only with the
inputs, yields, and matches of the epochs still open. That total must not grow with the application's age, with the
number of past epochs, or with chain activity that does not belong to the application. The memory and storage the
honest operator needs to defend its claims do not grow with the number of outputs. Every transaction the honest
operator sends, proofs included, fits the chain's per-transaction limits in the worst case of what it carries.

**R13. The transition function is the protocol.** These are all part of it.

- The interpreter semantics.
- The state layout.
- The device behavior.
- The uarch program and its pristine state.
- The hash-tree construction and hash functions.
- The computation-hash construction, including its padding.
- The map from position to transition form.
- The accesses each logged transition makes, and their order.
- The dispute constants.

Changing any of them creates a new protocol version, and versions must never be mixed within a deployment (A6). Every
version that changes the state transition function changes the machine-identification registers in the hashed state.
The honest operator must be able to detect and refuse a mismatch between its build and a deployment. The check must
refuse every pairing of its build with a deployment of another released version. The uarch program, its pristine
hash, and the verifier code that a deployment fixes on-chain must be reproducibly buildable from audited source.

**R14. Unreproducible machines stay outside the verifiable domain.** The unreproducible mode is fixed at creation and
recorded in the hashed state. In a reproducible machine, the host reaches the state only through deliveries and
deliberate changes through the machine API. That rules out host devices, any other host input, and host-driven
interrupts or timing. Output to the host, such as console output, must not affect the state.

## 7. Adversary capabilities

Section 4 already lists the adversary's control over the guest and over logs and proofs. In addition, the
adversary can do the following.

- Post any number of claims (Sybils), with any computation hash, and abandon or defend them at will.
- Hold any claim, including the honest one, and answer for it.
- Under the honest claim, post uarch-level claims that end at the honest state along a fabricated trajectory.
- Steer the dispute to any position of the honest computation, and force the honest claim through a logarithmic number
  of matches.
- Send any number of inputs the deployment accepts, with payloads chosen to maximize the honest operator's
  cost (R12), including payloads larger than the rx buffer.
- Raise activity on the chain that does not belong to the application, such as inputs to other applications that
  share its input record.
- Race and reorder transactions within the chain's rules.

The adversary is not assumed to break the hash functions, to compromise the honest operator's host, or to censor the
chain beyond the dispute clocks.

## 8. Severity

The scale is Critical, High, Medium, Low and Out of scope. The class headers describe the classes. The listed cases
and "How to rate" decide them.

**Critical** breaks the goal. Except for the cases listed under High and Medium, violating any rule or obligation
at a reachable state, or anywhere on the honest operator's path, is critical. The following cases are critical as
well, even though they might look minor.

- A verifier defect that lets some log be accepted, for a reachable before-state, with an after-hash other than the
  canonical one.
- An operation listed in R12 whose worst-case cost a guest can make unbounded, super-linear, or larger than what the
  deployment was sized for.
- An honest proof or transaction that cannot fit the chain's per-transaction limits, other than the delivery proof of
  an input that A3 requires the input record to refuse.
- Memory corruption or code execution through data from other parties that the honest operator must process
  (section 4).
- A crash, hang, out-of-bounds read, or unbounded allocation caused by data from other parties that the honest
  operator must process.

**High** does not break the goal, but removes a margin that the goal relies on.

- A verifier that misbehaves only on demonstrably unreachable before-states. Misbehaving means being
  nondeterministic, accepting a wrong or second after-hash (such as accepting a uarch trap, R3), not being
  memory-safe, or being unbounded. When a component runs a verifier on logs or proofs from other parties,
  memory-safety defects that data the honest operator must process can trigger are classified by the Critical entries
  on such data instead.
- A divergence between paths only at demonstrably unreachable states.
- A crash, hang, or memory-safety defect in the emulator that only demonstrably unreachable states trigger.
- A crash, hang, memory-safety defect or unbounded allocation in a component in the honest-operator role, caused by
  data from other parties that the honest operator may decline.
- A uarch program or verifier code fixed on-chain that cannot be reproducibly rebuilt, while what is deployed matches
  its audited source.
- A node that cannot detect a version mismatch, while every node in fact runs the deployment's version.
- A defect that lets the guest, or host load that the deployment was sized for, multiply the worst-case cost of an
  operation listed in R12 by a constant factor, compared with the same operation without the defect, while staying
  within what the deployment was sized for. A cost that the specified semantics require is not a defect. When the
  sizing is unknown, rate such a constant-factor increase High and a super-linear or unbounded one Critical.

**Medium** violates a rule or the manual without affecting the goal.

- An undocumented deterministic deviation, consistent across all paths, in behavior that no correct guest relies on
  for isolation or data integrity (R7).
- A referee verifier that accepts trailing data that does not affect its result (R3). A support verifier that does so
  is Low.
- A defect that only a support component shows, when section 3 rates it Medium.
- A machine API operation off the honest operator's path that, used as documented, leaves the hash tree, the cached
  state of the machine or a stored directory inconsistent with the machine's contents (R9).
- A hash-integrity defect that shows only under a hash function that no referee verifier supports (R9).
- A persistence operation that fails loudly, without a wrong hash or damage to a directory that O2 guarantees, in an
  uncommon host setup that the manual documents, or while cleaning up after a stop.

A contradiction between the manual and the behavior on a security-relevant point is a defect in one of the two. It
takes the severity it would have if the manual were right.

**Low** is a real defect that violates no rule or obligation of this model, or one that this model rates Low.
Examples are a defect in a tool's diagnostics, a failure that needs misuse of an API by its trusted caller, a
portability gap on an unsupported host, and a defect in guest software that only an application outside its intended
use can reach.

**Out of scope for the emulator.**

- The effect of a deliberate state change made through the machine API, when the API performs it as documented
  (section 4).
- Defects that need an untrusted party to call the machine API directly, local or remote (section 4). Data from other
  parties that a trusted caller passes through it stays in scope.
- Defects that need the deployment to violate one of A1 to A8, unless the emulator's own behavior is what makes the
  obligation fail, such as a worst-case cost or proof size larger than the deployment was sized for, or unless an
  implementation of the referee model is what violates it (section 3).
- The stall of an application that halts, yields manually with a reason other than accepted or rejected, or never
  yields, and what the application loses by it. A5 governs what can then be extracted from its state.
- An application that is not correctly designed, other than through a defect in guest software that section 3 puts in
  scope. That exclusion covers only what such an application gets, which is its outputs and its own correctness. The
  honest operator still defends the trajectory the state transition function defines, for any application, because
  its claims depend only on state hashes (R4). If it stopped, any claim could win, a fabricated final state and its
  outputs included. An application that breaks the rollup interface may leave its outputs unprovable, but it must
  never stop the honest operator from computing claims or producing proofs. Development tools may instead stop and
  report the violation.
- An application that tries to exhaust the honest operator through the number of its outputs or yields. Each costs
  the guest mcycles, which the application's own bound limits (section 2). This holds as long as the memory and
  storage that the honest operator needs to defend its claims do not grow with the number of outputs, and each yield
  costs it a bounded amount (R12). Keeping outputs to prove them later is not on the honest operator's path.
- Guest software that an input can subvert, as long as R7 and R8 hold, other than the defects that section 3 puts in
  scope.
- Defects triggered only by loading a snapshot that the emulator did not write and that does not meet the conditions
  of a valid template (section 4). Once a snapshot meets them, nothing it carries outside the hashed state may affect
  any transition (R1), crash the honest operator, or corrupt its memory.
- Defects that need the cached hash-tree data of a stored machine the operator did not produce to survive its
  adoption without a rebuild (O1).
- Defects that need the honest operator to reload a stored directory that O2 does not guarantee, such as one being
  written or shared when its process stopped, or one that a machine used with sharing after its last sync.
- Host faults, such as a full disk, as long as the emulator does not turn them into a wrong hash, a wrong proof, or a
  directory that O2 guarantees but that later loads as a different state (section 4).
- Reorganizations of the chain deeper than the operator's input policy (section 4).
- Breaking the hash primitives.
- Nondeterminism in unreproducible machines (R14).
- Average-case performance that does not change the worst-case cost of any operation listed in R12.

### How to rate

Apply the classes in this order, and stop at the first that fits.

1. **Out of scope.** Does the defect need something the list above excludes? Check the trigger, not the symptom. A
   wrong hash that needs a reload of a directory that was being written or shared when its process crashed is out of
   scope by O2. A wrong hash after documented operations, destroying the machine, and a sync is not. The entries about
   applications exclude what an application loses, never an emulator defect that its guest triggers (R4, R5, R8).
2. **Role.** This step selects the role and stops nothing. Which component shows the defect, and what role does it
   play (section 3)? Defects in the referee model, in guest software and in support components are rated as section 3
   says. A defect that only a support component shows is never above Medium. A finding in a support component often
   points at a defect in the transition function, a referee verifier, the referee model or the honest operator. Rate
   that defect.
3. **High and Medium cases.** Does it match one of the listed cases? Unreachable states need an argument, not an
   assertion. State why no input sequence from any valid template produces the state.
4. **Critical.** Otherwise, does it violate a rule or obligation at a reachable state or on the honest operator's
   path? Name the rule.
5. **Low.** Otherwise it is Low.

State the trigger, the affected component and its role, and the rule or obligation in every rating. When two readings
of the model give different classes, give both and say which facts would decide.
