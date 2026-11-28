# Threat model of the Cartesi Machine emulator

This document is the security model of the Cartesi Machine emulator. It says what the emulator must guarantee, what
it relies on, and how severe a defect is. It is for anyone who reviews, audits or reports defects in the emulator. It
is also for those who build or run validators, which must meet the obligations of section 5. Sections 1 to 7 define
the model. Section 8 records precedents.

## How to use this document

Rate a defect with section 7, then look for a precedent in section 8.

### The system in brief

The Cartesi Machine is a deterministic RISC-V emulator that runs Linux. At any point of execution it can produce a
hash of its entire state. Parties to a dispute agree on an initial state hash and disagree on a later one. A
blockchain referee bisects the computation until one small transition is in dispute. The honest party then proves
that transition on-chain.

The machine runs in two ways that must agree exactly. `machine:run` executes the instructions of the main processor with
an interpreter that runs on the host. The microarchitecture (uarch) is a much smaller machine that runs the same
interpreter, compiled to a fixed program (`machine:run_uarch`). A dispute is bisected down to one uarch cycle, whose
step the on-chain state transition verifier replays from a log of state accesses with Merkle proofs. The log given to a
state transition verifier may come from an adversary. A second way to prove transitions, not yet in production,
replays a log of many mcycles with the state transition verifier that runs inside a zkVM.

## 1. Security goal

> Suppose one honest validator runs the emulator correctly, on the resources the deployment was sized for, and the
> chain includes its transactions without missing any deadline. Then no adversary can make a correctly designed
> application settle a state that differs from the one the state transition function defines, or accept an output
> that the settled state does not commit to.

There are two ways to break it. Both are critical.

- **Soundness failure.** From a reachable before-state, a state transition verifier accepts a proof of a transition that
  the state transition function does not produce. Or a Merkle proof verifier accepts a node that the committed tree does
  not hold at the stated index and height.
- **Completeness failure.** The honest validator computes a wrong hash, cannot produce a proof that verifies, or
  misses a deadline. If its claim is eliminated, a dishonest claim can win.

The goal assumes that the deployment runs validators of more than one implementation. A defect in one implementation
that the others do not share leaves them to defend the honest claim. It removes a margin rather than breaking the goal
(section 7).

The emulator does not move funds itself. It is the referee's ground truth. A bug in it is a bug in every contract
that settles on it.

## 2. Terms

The manual defines the state (everything mapped into the physical address space), the state hash, epochs and input
indices, computation hashes and their sampling period, positions and the limit on each of their levels, claims and
matches in the permissionless refereed tournament, advance-state requests, `imcyclemax`, the revert root hash, and the
state transition function. `cm.h` and the manual define the machine instance. This document uses these terms as they
do. The terms below are its own. Each is defined before the terms that use it.

- **Cached hash-tree data.** Data that a stored machine carries next to its contents (page hashes, dense trees,
  dirty-page trees and the sparse tree). It is outside the state hash. Loading does not check it. The root hash of
  a loaded machine, `cartesi-machine-stored-hash`, and hash-tree verification (`cm_verify_hash_tree`) all read it.
- **Reproducible machine.** A machine created without the unreproducible mode (P5).
- **Dispute constants.** The limit on each level of a position and the sampling period of computation hashes.
- **Referee.** The party that runs the permissionless refereed tournament. On-chain, it is the Dave contracts. The
  referee model in `doc/recipes` documents it (section 5). At the first level of the tournament a claim is an mcycle
  claim, and at the second a uarch claim.
- **State transition verifier.** The function the referee runs to check a state transition proof (a log of state
  accesses with Merkle proofs) against the before state hash and obtain the after state hash. It is part of the referee.
  The on-chain state transition verifier is the step in machine-solidity-step. It is the only one used in production.
  The off-chain state transition verifiers are `verify_step_uarch`, `verify_reset_uarch`, `verify_send_cmio_response`
  and `verify_step`, in C, Lua and JSON-RPC. They serve tests and the manual's referee
  model. The build of `verify_step` that runs inside the RISC Zero zkVM is not yet in production. In this document it
  is an off-chain state transition verifier.
- **Log producer.** A function that performs one transition on a machine instance and records its state transition
  proof. The log producers are `log_step_uarch`, `log_reset_uarch`, `log_send_cmio_response` and `log_step`.
- **State hash collector.** A function that runs a machine instance and collects its state hash at regular intervals
  of mcycles or uarch cycles. The state hash collectors are `collect_mcycle_root_hashes` and
  `collect_uarch_cycle_root_hashes`.
- **Referee parameters.** What the referee supplies to its state transition verifier, rather than taking it from the
  proof.
  - The before state hash.
  - Which transition to verify (a uarch step, the uarch reset, or an advance-state request followed by a uarch step).
    The referee derives it from the position.
  - The tree index and height at which each node of a computation-hash proof, or of a proof that extracts the outputs
    Merkle root (A3), is authenticated, and the height of its tree.
  - The input bytes and the request type.
  - The revert root hash.
  - The hash function.
- **Valid template.** A reproducible machine that meets all of these conditions.
  - It was created from a configuration by operations the manual specifies.
  - It is at an mcycle boundary, with the uarch in its pristine reset state.
  - It is waiting at a manual yield with the rx-accepted reason.
  - Its tx buffer holds the outputs Merkle root of every output that the application accepted before it. At genesis,
    that is the root of the empty outputs tree.
  - It uses the hash function of its deployment's state transition verifiers.
  - Its state hash, computed from its contents alone, matches the on-chain commitment. For a stored machine, "computed
    from its contents alone" means after rebuilding its cached hash-tree data (O1). None of the readers of the cache
    listed under cached hash-tree data checks this condition.
- **Reachable state.** A state that some input sequence produces from a valid template. Any assignment of
  guest-writable memory and registers is presumed reachable. So is any state that is not plainly unreachable. A state
  is unreachable only if no input sequence produces it from any valid template. A state whose uarch is not pristine at
  an mcycle boundary is unreachable.
- **Correctly designed application.** One that meets three conditions.
  - Its own code is correct, so no input takes control of it.
  - On every input sequence, its guest follows the rollup interface that the manual specifies. After each input, it
    yields manually with the accepted or the rx-rejected reason. When it accepts, it leaves in the tx buffer the
    outputs Merkle root of every output it accepted. That includes the outputs its template already commits to, and
    the outputs emitted while processing the inputs it accepted.
  - It bounds its own mcycle usage. Every input yields manually no later than `imcyclemax`. Its total mcycle usage
    stays within what the deployment was sized for (A5).
- **Validator.** A node that computes claims and defends them in disputes. The known validators are the sling node
  (in the `dave` repository), the Cartesi Rollups Node, and crisium (the `cartesi/crisium` repository), with the PRT
  player and PRT bridge it uses. In this document, crisium includes them. An honest validator runs the
  emulator correctly and meets the obligations of section 5. The honest claim at each level is the computation hash
  the honest validator computes. It commits to every sampled state, not only the final one.
- **Input policy.** Which block a validator treats as final when it reads inputs from the chain. It is the chain's
  `finalized` or `safe` block, or the block a given number of blocks below the tip. crisium takes it as
  `--input-policy` and defaults to `finalized`.
- **Honest validator's path.** Every operation the honest validator performs to defend its claim.
  - Obtaining its valid template. For a template the validator did not produce, this includes rebuilding its cached
    hash-tree data (O1).
  - Advancing the machine.
  - Sending advance-state requests.
  - Storing and reloading the machine. Reloading means loading a directory whose last operation was a sync. A
    directory that a process was using read-write when that process stopped is never reloaded (O2).
  - Computing claims.
  - Producing proofs.

## 3. Principles

**P1. One state transition function.** The state transition function is implemented in two ways.

- A machine instance implements it with access to the entire state, given the referee parameters. It implements all
  of it except the revert after a rejected input. The host performs that revert, by restoring a copy of the machine it
  kept from before sending the request. The log producers and the state hash collectors implement the revert too,
  using the revert root hash as the next state hash.
- A state transition verifier implements it with only the before state hash, the referee parameters and a state
  transition proof.

From every reachable state, all implementations must agree. They reach the same state hash at every position, at
every boundary of the dispute grid and of a run, however the run is split, stopped or resumed. The state transition
verifier accepts the proof that a log producer records and returns the after state hash that the machine instance
computes. Any other proof it either rejects or accepts with that same after state hash.

Since a state transition verifier sees the state only through its hash, the state hash must commit to the entire
state and nothing outside the state may influence a transition. For a reproducible machine, that rules out the host
OS, CPU or endianness, the compiler, thread count, memory layout, uninitialized data, timing and undefined behavior.
Time inside the machine derives only from the cycle counter. Floating-point results are bit-exact on every host.
Every hash an implementation reports must equal a computation from scratch over the state values, whatever cached
hash-tree data it reads. Two different states never share a hash without a break of the hash primitive. Cached
hash-tree data on the honest validator's path was either written by the validator's own process and synced, or
rebuilt on adoption (O1 and O2). P1 does not cover cached hash-tree data in other cases, nor a machine instance after
a failed call (O2).

Everything that determines the state transition function is part of the protocol. That includes the interpreter, the
state layout, the devices, the uarch program and its pristine state, the hash-tree construction and hash functions,
the computation-hash construction, the map from position to transition, and the dispute constants. Changing any of
them creates a new protocol version, which must never be mixed with another within a deployment (A4). The honest
validator must be able to detect and refuse a mismatch between its build and a deployment. The uarch program, its
pristine hash, and the state transition verifier code that a deployment fixes on-chain must be reproducibly buildable
from audited source.

**P2. Proofs are adversarial.** A state transition verifier must assume that every count, index, address, size and
hash in a proof was chosen to fool it. On every before-state, reachable or not, it stays memory-safe, bounded and
deterministic. It depends only on the referee parameters, the constants of its protocol version and the data that the
proof authenticates. Every referee parameter comes from the referee, never from the proof. No proof can select the
hash function, or make the state transition verifier check a transition other than the one the referee chose.

**P3. The honest validator can always finish.** From every reachable state, at the position where it is reached, the
honest validator can compute its claims, produce every requested node and proof, and log every transition so that it
verifies. Every operation it uses has a cost in host time and memory with a bound that no state and no input can
exceed.

- Running the machine, updating its hash tree, sending an advance-state request and collecting state hashes cost at
  most linearly in what they cover.
- Running, logging and verifying one uarch-level transition cost at most a constant, and its proof fits the chain's
  per-transaction limits.
- Storing, loading, cloning and syncing a machine cost at most linearly in its size.

A5 requires the deployment to size its clocks for these costs. Inspect-state requests are outside the verified
history. Nothing from one may reach a state on the honest validator's path. Their results carry no guarantee.

**P4. The guest is contained, and the architecture is faithful.** The emulator implements the RISC-V specification and
the devices as the manual documents them, departing only where the manual documents a deviation. A correct guest
relies on the architecture for isolation and data integrity, in privilege levels, address translation and memory
permissions, atomics and fences, traps and interrupts, and the rx buffer, tx buffer and yield interface. In these
areas, any deviation lets an input subvert a correct guest, even a deviation that is consistent across all
implementations. This holds for deviations that a correct guest can meet in its own operation. Privileged code
already controls the application, including the outputs Merkle root it reports. A deviation that only privileged code
can reach, by setting up the condition itself, gives an input nothing that taking over the kernel does not already
give it.

The guest reaches the state only through instruction and device semantics, and only within the ranges and permissions
that the PMA entries declare. It can never change the PMA entries, the cycle counter, `imcyclemax`, the revert root
hash, the unreproducible mode, or the uarch state. No guest action may corrupt host memory, crash or hang the host, or
cause unbounded host allocation.

**P5. Unreproducible machines stay outside the verifiable domain.** For prototyping, the emulator lets factors outside
the state influence a transition, such as files on the host, the wall-clock time, console input and networking,
through the VirtIO devices and HTIF console input. A machine that allows them is unreproducible. The unreproducible
mode is fixed at creation and recorded in the state. An unreproducible machine is never a valid template, so nothing
it produces reaches a dispute. In a reproducible machine, the host reaches the state only through advance-state
requests and deliberate changes through the machine API. Its output to the host, such as console output, does not
affect the state.

## 4. Trust boundaries

The honest validator trusts its own host and node software, the key that signs its transactions, its build of the
emulator, the valid template it defends, the hash functions, and the chain up to the block its input policy treats as
final. It trusts nothing it receives from other parties (P2). The rest of this section says where these boundaries
fall.

- **The application is trusted.** The model assumes the application is correctly designed and implemented. A guest
  that an input takes over through a defect in the application is outside the model. Such a guest can write any outputs
  Merkle root and drain the application's funds, with no defect in the state transition function or in the dispute
  resolution protocol. Defects in the guest software that Cartesi ships (the Linux kernel and its modules, OpenSBI, and
  machine-guest-tools) are in scope. The emulator is responsible for implementing the architecture exactly (P4), so
  that correct guest software behaves as specified.
- **Outputs are the application's.** The state transition function depends on manual yields and their reasons (input
  handling and exceptions), on halts and on reaching `imcyclemax`. It does not depend on automatic yields, which carry
  the outputs, nor on the outputs Merkle root. Those are data in the state, which the state hash commits to. Their
  correctness is the application's responsibility.
- **Callers of the machine API are trusted in intent, not in data.** The machine API is the C, Lua and JSON-RPC
  interface to a machine. Whoever can call it can change anything, by design. But much of what a node passes through
  it comes from other parties (input payloads, logs, proofs, and hashes). Every path that carries such data must be
  memory-safe and bounded, and must report errors without terminating the process. The honest validator cannot decline
  some of this data, such as input payloads, because it must process them to compute its claim. The machine API, local
  or remote, is not an authentication boundary. Exposing it to an untrusted party is outside this model.
- **Stored machines are defended only as valid templates.** This model makes no guarantee about loading a stored
  machine that does not meet every condition of a valid template. A stored machine that the validator did not produce
  is defended only once it meets them, and only after its cached hash-tree data is rebuilt (O1), since that data is
  part of no condition. A directory that a process was using read-write (with `CM_SHARING_CONFIG` or `CM_SHARING_ALL`)
  when that process stopped is not a valid stored machine (O2).
- **The chain is trusted up to the block the input policy treats as final.** A reorganization deeper than that is a
  failure of the chain, not an adversary capability. A validator defect that only such a reorganization triggers is out
  of scope (section 8), although surviving one is desirable. crisium stops with an error instead of claiming.

## 5. Obligations the emulator relies on

The security goal of section 1 holds only if the validator and the deployment meet these obligations. A violation of any
of them breaks the goal even when the emulator is correct.

### Validator obligations

- **O1. Adopting a stored machine rebuilds its hash tree.** A validator that adopts a stored machine it did not produce
  rebuilds the cached hash-tree data from the contents when loading it (the `clear_hash_tree` runtime option, or
  `--clear-hash-tree`), and only then compares the root hash with the on-chain commitment.
- **O2. After a stop or a failed call, resume from a synced directory.**
  - **Read-write use.** A machine instance created in a stored directory, or loaded from one, with `CM_SHARING_NONE`
    keeps every change in memory and never writes to the directory. With `CM_SHARING_CONFIG` it writes the backing
    stores that the configuration marks as shared. With `CM_SHARING_ALL` it writes all of them, along with the cached
    hash-tree data. A directory is in read-write use from the moment a machine instance with either of these two
    sharing modes is created in it or loaded from it, until that instance is destroyed. Any call on the instance, even
    a query such as reading the state hash, may write to the directory.
  - **Synced directory.** A stored directory whose machine instance was destroyed with a successful `cm_destroy`, and
    which was then synced with a successful `cm_sync_stored`. A directory written by `cm_store` or `cm_clone_stored`,
    and then synced, is also a synced directory.
  - **What the emulator guarantees.** After `cm_destroy` succeeds, processes on the same host see a valid stored
    machine in the directory. A synced directory also survives a crash or power loss of the system. A call that
    rejects its arguments leaves the machine instance unchanged. The emulator guarantees nothing else. Any other
    failure of a call comes from the host or from a broken internal invariant. The emulator reports it and keeps the
    machine instance safe to destroy. After such a failure, the machine instance and the directory it was using
    read-write may hold a combination of registers, memory and hash tree that no execution reaches. So may a directory
    in read-write use when the process using it stops at any point before `cm_destroy` succeeds.
  - **What validators must do.** After a call fails other than by rejecting its arguments, or after the process stops
    before `cm_destroy` succeeds, the validator discards the machine instance and the directory it was using
    read-write. After a crash or power loss of the system, it also discards every directory whose `cm_sync_stored` had
    not succeeded. It resumes from a synced directory, such as the snapshot it took before the current input.

O1 and O2 bind the emulator too. The tools and recipes that ship with it must follow them. The emulator must make
them possible to follow. A defect that defeats the rebuild itself, or that damages a directory whose last operation
was a sync and that nothing has touched since, is not excused by them.

### Deployment obligations

The deployed referee must meet these obligations. The referee model in `doc/recipes` is documentation. It explains
the process and may simplify it. Where it departs from the deployed referee other than by a simplification, the
documentation is wrong. No production component uses it.

- **A1. Agreed before-state.** When a match reaches the first leaf on which its claims disagree, the referee verifies
  the transition into that leaf. The before state hash that it gives its state transition verifier must be one that
  both claims are bound to. It is one of these.
  - The previous leaf, which both claims hold, authenticated by a Merkle proof at its position in each claim.
  - For the first leaf of an mcycle claim, the state hash the epoch starts from, as settled on-chain.
  - For the first leaf of a uarch claim, the leaf on which the claims of the mcycle match that started the uarch
    dispute last agree.

  A uarch claim counts only if its last leaf, authenticated as in A2, is one of the two state hashes the mcycle match
  disagrees on. The outcome of the uarch dispute decides the mcycle match only through the winning uarch claim's last
  leaf, never through who posted it.
- **A2. The referee derives every other parameter.** The referee derives the transition, the tree index and height at
  which each node is authenticated, the input bytes and the revert root hash from the disputed position, the on-chain
  input record and its own constants. A hash is accepted as a computation-hash leaf only when it is authenticated at
  height zero of the full tree, never as the root of a subtree. The request type is always advance state. The input
  record assigns no more inputs to an epoch than the input limit per epoch. For an advance-state request, the revert
  root hash equals the before state hash.
- **A3. Outputs only from accepted states.** An outputs Merkle root is defined only for a settled state that
  waits at a manual yield with the rx-accepted reason. A valid template is such a state. Extracting the root requires
  authenticating that status in the same state. In any other final state, the tx buffer holds guest data with no
  meaning. Examples are a halt, a manual yield with any reason other than accepted or rejected, and a stop at
  `imcyclemax` without a manual yield. The settled state is the last leaf of the winning claim,
  authenticated as in A2.

  An output is accepted only through a proof that authenticates a hash as a leaf of the full-height outputs tree.
  That hash is the hash of the output's exact encoded bytes, as the guest emitted them. The leaf sits at height zero
  and at the output's index. That tree's root must be the one extracted from the settled state.
- **A4. One version per deployment.** Every state transition verifier, the uarch program fixed on-chain, and every
  honest validator in a deployment implements the same state transition function (P1).
- **A5. Sized clocks.** The dispute constants and clocks leave room for the honest claim to play the logarithmic
  number of matches that a tournament forces on it, at the worst-case costs of P3.

## 6. Adversary capabilities

Beyond its control over proofs (P2), the adversary can do the following.

- Post any number of claims, with any computation hash, and abandon or defend them at will.
- Hold any claim, including the honest one, and answer for it.
- Under the honest claim, post uarch claims that end at the honest state hash along a fabricated trajectory.
- Steer the dispute to any position of the honest computation, and force the honest claim through a logarithmic number
  of matches.
- Send any number of inputs the deployment accepts, with payloads chosen to maximize the honest validator's
  cost (P3), including payloads larger than the rx buffer.
- Race and reorder transactions within the chain's rules.

The adversary is not assumed to break the hash functions, to compromise the honest validator's host, or to censor the
chain so that the honest validator misses a deadline.

## 7. Severity

The scale is Critical, High, Medium, Low and Out of scope.

**Critical** breaks the goal. Except for the cases listed under High and Medium, violating any principle or obligation
at a reachable state, or anywhere on the honest validator's path, is critical. The following cases are critical as
well, even though they might look minor.

- A state transition verifier defect, triggered by fabricated log data or a fabricated before-state, that can change the
  after-hash accepted for a reachable before-state.
- An operation listed in P3 whose cost an input can make exceed its bound, or grow faster than linearly in what it
  covers.
- An honest proof that cannot fit the chain's per-transaction limits.
- Memory corruption or code execution through any data from other parties (section 4).
- A crash, hang, out-of-bounds read, or unbounded allocation caused by data from other parties that the honest
  validator must process.

**High** does not break the goal, but removes a margin that the goal relies on.

- A state transition verifier that is not memory-safe, is unbounded or is nondeterministic, only on before-states that
  no execution reaches. Accepting a wrong or second after-hash on such a before-state is out of scope, because the
  honest claim never holds such a state (A1).
- A crash, hang, out-of-bounds read, or unbounded allocation caused by data from other parties that the honest
  validator may decline.
- The uarch program or the on-chain state transition verifier cannot be rebuilt from its audited source, bit for bit,
  although what is deployed was in fact built from that source. Nobody can then check the deployment against the
  source. If what is deployed does not match the audited source, the defect is Critical.
- A node that cannot detect a version mismatch with its deployment, while every node in fact runs the deployment's
  version.
- An input that raises the cost of an operation listed in P3 by a constant factor, while the cost stays within its
  bound.
- A defect that crashes or stalls crisium, or makes it miss a deadline, while the sling node and the Cartesi Rollups
  Node are unaffected. This assumes that they share no code with crisium other than the emulator (section 8).

**Medium** violates a principle or obligation without affecting the goal.

- An undocumented deterministic deviation, consistent across all implementations, in behavior that no correct guest
  relies on for isolation or data integrity (P4).
- A divergence between implementations only at a state no execution reaches.
- An on-chain state transition verifier that accepts trailing data that does not affect its result.
- Defects in storing, loading, cloning or syncing machines that leave a wrong hash or a damaged directory, off the
  honest validator's path.
- A defect that only an off-chain state transition verifier shows is at most Medium. No production component uses the
  off-chain state transition verifiers (section 2).
- A defect only in the recipes other than crisium (the referee model and the other demonstrations), or only in the
  CLI, is at most Medium. This assumes that no validator depends on them in operation (section 8).

A contradiction between the manual and the behavior on a security-relevant point is a defect in one of the two. It
takes the severity it would have if the manual were right.

**Low** is a real defect that violates no principle or obligation of this model. Examples are a defect in a tool's
diagnostics, a failure that needs misuse of an API by its trusted caller, a portability gap on an unsupported host,
and a defect in guest tools that only an application outside their intended use can reach.

**Out of scope for the emulator.**

- Deliberate state changes made through the machine API (section 4).
- An application that halts, yields manually with a reason other than accepted or rejected, or never yields, and so
  stalls. A3 governs what can then be extracted from its state.
- An application that is not correctly designed gets no guarantee about its outputs or its own correctness. A
  validator must still defend the trajectory the state transition function defines, since its claims depend only on
  state hashes. Breaking the rollup interface can leave outputs unprovable, but must not stop a validator from
  computing claims or producing proofs. The CLI, a development tool, stops and reports the violation instead.
- An application that tries to exhaust the honest validator through its outputs. Each output costs the guest mcycles,
  so what a node spends to prove outputs grows at most linearly with the computation, which A5 sizes. A node that
  serves proofs of every output keeps every output hash. crisium keeps less, since it proves only
  the epoch's last output.
- Guest software that an input can subvert, as long as P4 holds.
- Defects triggered only by loading a stored machine that does not meet the conditions of a valid template (section 4).
  Once a snapshot meets them, nothing it carries outside the hashed state may affect any transition (P1).
- Defects that need the cached hash-tree data of a stored machine the validator did not produce to survive its
  adoption without a rebuild (O1).
- Defects that need a stored directory to be reloaded after the process using it read-write stopped, without a later
  sync (O2).
- Defects that need a machine instance to be used after a call on it failed, other than by rejecting its arguments
  (O2). A failure that is not reported, or that crashes the process, is in scope.
- Breaking the hash primitives.
- Nondeterminism in unreproducible machines (P5).
- Average-case performance that does not change the worst-case cost of any operation listed in P3.

### How to rate

Rate a defect in these steps.

1. **Locate it.** Find the component where the defect lives, not where it shows. A defect that shows up in a recipe
   may be caused by the emulator. In that case, rate the emulator defect, not its effect on the recipe.
2. **Out of scope.** Does its trigger need something the out-of-scope list excludes? Check the trigger, not the
   symptom. A wrong hash that needs a reload after a crash is out of scope by O2. A wrong hash after documented
   operations and a sync is not.
3. **Principle.** Name the principle or obligation it violates. If it violates none, it is Low.
4. **Severity.** A violation at a reachable state or on the honest validator's path is Critical, unless it matches one
   of the High or Medium cases. A state that is not plainly unreachable is rated as reachable (section 2).
5. **Component limit.** A defect only in an off-chain state transition verifier, in the recipes other than crisium, or
   in the CLI is at most Medium. A defect only in crisium is at most High.

State the trigger, the affected component, and the principle or obligation in every rating. When two readings of the
model give different classes, give both and say which facts would decide.

## 8. Precedents

These cases have been rated. Apply them to like cases. Where a rating depends on the Dave contracts, the sling node or
the Cartesi Rollups Node, which this repository cannot confirm, the precedent states what it assumes about them. If an
assumption fails, rate the case again.

| Case | Rating | Basis |
|---|---|---|
| A poisoned hash-tree cache in a stored machine the validator did not produce | Out of scope by O1 | The rebuild discards it. A defect that lets poisoned data survive the rebuild is in scope. `clear_hash_tree` once kept a stale dirty-page tree, and was fixed. |
| A wrong state after reloading a directory that a process was using read-write when that process stopped | Out of scope by O2 | A shipped tool or recipe that reloads such a directory is itself a defect. Closing one window of a stop does not help, because the emulator guarantees only a synced directory. |
| An application that floods outputs or yields in a tight loop | Out of scope | The application breaks only itself, and what a node spends grows at most linearly with the mcycles the outputs cost. |
| A chain reorganization deeper than the validator's input policy | Out of scope | A failure of the chain (section 4). |
| The referee model accepts an output proof at an aliased index | Medium | The referee model is documentation. A deployed referee with the same defect would be Critical. |
| A referee-model defect in clocks or timeouts | Medium | The referee model is documentation, and may simplify clocks. |
| An emulator defect in yield data other than the `tohost` register | Medium if no validator reads that data, Critical if one does | This assumes that the sling node and the Cartesi Rollups Node read only `tohost` at yields. |
| An application breaks the rollup interface and crisium stops | High | The application is at fault, but a validator must keep defending. |
| A defect only in the CLI, or only in the recipes other than crisium | At most Medium | This assumes that no validator depends on them in operation. |
| A defect that crashes or stalls crisium, or makes it miss a deadline, and no other validator | High | This assumes that the sling node and the Cartesi Rollups Node share no code with crisium other than the emulator, so they defend the honest claim when crisium fails. |
| crisium fails to load or refuses a valid template, such as a read-only one or one that already commits to outputs | High | crisium cannot defend the honest claim, wherever the failure happens. |
| A guest-tools defect that only applications ABI-decoding arbitrary senders' payloads with libcmt reach | Low | It is outside the intended use of the guest tools. |
| A uarch trap (an illegal instruction, an EBREAK, an unknown ECALL or an invalid `WRITE_TLB` index) | Critical at a reachable state | The uarch program failed to implement the main processor's transition, which nothing can recover from. `machine:run_uarch`, the log producer and the on-chain and off-chain state transition verifiers refuse the step with the same message. The honest validator sees the failure while it builds its uarch computation hash, before anyone asks for a proof. |
| A step from a uarch that is not running the pristine program, which `machine:run_uarch` and the state transition verifiers treat differently, such as a store to memory that is not writable | Medium | Such a uarch does not implement the state transition function (P1), and a non-pristine uarch at an mcycle boundary is unreachable (section 2). Every path must still stay memory-safe, bounded and deterministic on it (P2). |
| A defect that needs `skip_version_check`, a custom uarch RAM, a host write, or a uarch program that runs about 2^20 cycles in one mcycle | High, or Medium for a divergence | These states are unreachable. A path that crashes, hangs or is nondeterministic there is High. A divergence between paths there is Medium. |
| A node that detects a version mismatch only through `marchid` and the pristine uarch hash | Low | The template hash covers `marchid`, and the pristine hash ties the state transition verifier to the uarch program. A state transition verifier change released without a uarch program change would escape both checks. |
| A deviation from the architecture that only privileged code reaches, by setting up the condition itself | Medium | Privileged code already controls the application and its outputs, so the deviation gives an input nothing more (P4). |
| A defect that needs a machine stored with sharing none or config, such as a stored copy that keeps the hash tree of the directory it was loaded from | Medium, off the honest validator's path | crisium stores only with sharing all. This assumes that the sling node and the Cartesi Rollups Node do too. |
| A CLI recovery procedure that picks the wrong copy after a host stop at a precise moment, failing loudly while a synced copy survives | Low | No wrong hash, no correct application affected, and manual recovery works. The CLI is a development tool. Validators such as crisium fall back to the other copy when one fails to load. |
| Queries on a machine loaded with sharing, after its directory was synced | Out of scope by O2 | Any call on such a machine, even a read-only one, may rewrite its directory. The directory is trusted again only once it is a synced directory. |
| A defect that starts from `replace_memory_range` | Medium, off the honest validator's path | It is a documented operation. This assumes that no validator calls it in operation. |
| A configuration that creation accepts but whose transitions cannot be proven | Critical | Creation must refuse it. Creation refuses memory ranges inside the uarch state hash tree node. A stored machine built by hand with such a range is not a valid template (section 4), although loading also refuses it. |
| Resource exhaustion that the guest does not cause, such as a full disk or host CPU contention | Out of scope | Sizing the host is the validator's job (section 1). A full disk that kills the process is a stop (O2). |
| A defect that needs console descriptors the validator made non-blocking | Out of scope | Console descriptors are the validator's to configure. |
| A defect in a Lua helper library, such as proof verification in `cartesi.hash-tree`, or in guest software that Cartesi ships, such as libcmt | The higher of its own rating and that of the most severe use through which the defect can be triggered | Where crisium depends on a library, its share is at most High. Where only the recipes other than crisium or the CLI depend on it, at most Medium. Guest software is in scope only where a correctly designed application depends on it. |
| A load that rebuilds the hash tree but still fails on a missing or malformed cached file it does not use | Low | The load fails loudly, and nothing it reads reaches a hash, so O1 holds. A defect that lets cached data survive the rebuild is in scope. |
| A stored machine whose configuration makes a load use excessive memory, such as an unbounded page hash-tree cache size | Low | The validator trusts the valid template it defends, its configuration included (section 4). |
| A `write_reg` or whole-shadow write that changes registers the machine treats as fixed, or sets the console GETCHAR bit on a reproducible machine | Out of scope | A deliberate state change made through the machine API, whose caller is trusted (section 4). The caller can change any register, so making some read-only would protect nothing. |
| A log function or `reset_uarch` that does not refuse an unreproducible machine | Low | An unreproducible machine is never a valid template, so nothing these functions produce reaches a dispute (P5). |
