## R2-DFOUTPUT-1

**Title.** The PRT stored player refuses every valid template whose tx buffer already commits to outputs, because `prt.store_first_epoch_checkpoint` requires the root of the empty outputs tree.

**Severity.** Medium (preferred reading: a support component standing in for a Critical honest-operator failure). Low under the alternative reading that a PRT deployment always starts from a genesis template with no earlier outputs.

### Problem

The recipes create the checkpoint for epoch 0 in one place only, `prt.store_first_epoch_checkpoint(template_directory,
geometry, directory)`. The function builds its outputs frontier with `new_outputs_frontier()` and no argument, so it
always gets the empty height-63 outputs tree. It then asserts that the template's tx-buffer word equals that empty
root:

```lua
local outputs_frontier = new_outputs_frontier()
...
assert(
    machine:read_memory(CMIO_TX_BUFFER_ADDRESS, WORD_SIZE) == outputs_root,
    "template machine has an output history"
)
```

The function takes no frontier or last-output proof, and it writes `output_count = 0` into `epoch.json`. A template
whose tx buffer holds the outputs Merkle root of earlier outputs therefore always fails here. `crisium.lua` opens epoch 0
only once `checkpoints/epoch-0` exists (`open_epochs`), and `prt-demo.lua` makes that directory with this same function.
On such a template the player never computes or posts its epoch-0 claim.

The threat model counts these templates as valid. Section 2 says: "Its tx buffer holds the outputs Merkle root of every
output that the application accepted before it, which at genesis is the root of the empty outputs tree." The manual also
documents how to make them ("For a non-genesis template, use
`--assert-rolling-template=outputs_merkle_root:<filename>`", doc/README.md, "Rolling Cartesi Machine templates").
`DaveConsensus` accepts any `initialMachineStateHash`. Claims depend only on state hashes. If an honest operator behaved
like this player, it could not defend a deployment built on such a template. Section 8 says what follows: "If it stopped,
any claim could win, a fabricated final state and its outputs included." That would be a completeness failure
(section 1). The player is a support component, so the defect is capped at Medium. The rest of the player handles an
earlier output history: `new_stored_player` and `new_forked_player` take a `previous_outputs_frontier`, and
`begin_epoch` checks the template's tx buffer against it. Only the epoch-0 checkpoint function ignores that history.

The bridge documentation states the assumption without restricting templates: "the template's checkpoint holds an empty
one" (doc/recipes/prt-lua-bridge.md, "Checkpoints"). The same function also has the separate defect R1-O1-3 (it loads
the template without `clear_hash_tree`). That defect has a different trigger and a different fix.

### Component, role and area

The PRT player in `doc/recipes`. AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support. No production
deployment runs the player, the bridge or the CLI." It stands in for the honest operator, on the step of the honest
operator's path that obtains the valid template and starts epoch 0. No component in the honest-operator role shows the
defect. The emulator itself and the `cartesi-machine` CLI accept non-genesis templates.

### Location

- `doc/recipes/prt.lua` `store_first_epoch_checkpoint` (lines 2741-2777). The assert is at lines 2759-2762, and
  `output_count = 0` is at line 2771.
- `doc/recipes/prt.lua` `new_outputs_frontier` (lines 2462-2473): with no argument it returns the empty frontier.
- `doc/recipes/crisium.lua` `open_epochs` (lines 223-237): requires `checkpoints/epoch-0` and checks that it is the
  template.
- `doc/recipes/prt-demo.lua` lines 76 and 131: the callers.

### Evidence and test

`bugs/R2-DFOUTPUT-1/` contains `test.lua`, `README.md` and this entry. Run the test with `bugs/run.sh R2-DFOUTPUT-1`. It
takes about 1 s, uses only the in-tree emulator and the harness `baremetal-template` configuration, and works in a
`mktemp -d` directory that it removes when it finishes.

The test loads `baremetal-template`. That is `emit-output.bin`, stored at its first rx-accepted yield with the empty
outputs root. The test delivers one advance-state input with `send_cmio_response` and runs the machine to the next manual
rx-accepted yield. On the way it records the single tx-output automatic yield and folds `keccak256(output)` into a
height-63 frontier. It then checks three things: the tx buffer holds that frontier's root (not the empty root), the
uarch is pristine, and exactly one output was emitted. It stores the machine as the template. This machine was created
from a configuration and changed only by running it and delivering inputs, so it is a valid template with an output
history.

Next the test calls `prt.store_first_epoch_checkpoint(template, prt.new_geometry(11), checkpoints/epoch-0, frontier)`.
The fourth argument is the template's frontier, passed in case a fix accepts it. The current function ignores it. The
test requires the call to succeed. After that, the checkpoint must be the template, and a `prt.new_stored_player`
started from it must seal the empty epoch 0 at the template hash and build the epoch-0 mcycle tree (the claim).

On audit/prt2 it prints the following and exits 1 in every run (3 of 3 by the prover, 4 of 4 by the reviewer):

```
template 2c90bc70741e7396488305fcecf2c88a6485eeab2835a767ce76b7e873a11307 commits to 1 earlier output, outputs root 216f25b9b5aab8d25c776949fc906d26cb82c31bc3db560dbdbf961e6ad6921d
store_first_epoch_checkpoint raised: /home/user/machine-emulator/doc/recipes/prt.lua:2759: template machine has an output history
VIOLATED: valid template (tx buffer holds the outputs root of every output accepted before it): the honest operator must obtain it and compute the epoch-0 claim (R4)
run.sh: R2-DFOUTPUT-1: exit 1 (bug present)
```

The reviewer repaired the test. The prover's version also failed when the checkpoint did not carry the template's output
history, or when the player reported `outputs_merkle_root_mismatch`. Those checks concern output proofs and diagnostics,
not R4. They are now printed as `note:` lines and do not decide the exit status. In their place, a check that the player
builds the epoch-0 mcycle tree now counts.

The reviewer ran the test with two scratch copies of `prt.lua`, neither committed. (A) The function takes an optional
fourth frontier argument, seeds the frontier with it and writes its leaf count. With this copy the test exits 0 and both
notes are satisfied. (B) The assert is simply removed. With this copy the test also exits 0. It notes that the
checkpoint does not carry the history and that the player reports
`outputs_merkle_root_mismatch at the epoch's start`.

### Trigger and reachability

No adversary is needed. Any deployment whose template has an output history triggers it. Such a template is a machine
produced, as the manual documents, by delivering inputs to an earlier template and storing it at an rx-accepted yield
(for example a migrated or continued application). It is checked with
`--assert-rolling-template=outputs_merkle_root:<file>` and deployed with its hash as `DaveConsensus`'s initial machine
state hash. The failing state is the template itself, a valid template by section 2, so it is reachable. The test builds
one from the harness configuration with one input.

### Rating

1. Out of scope: no. The template meets every condition of a valid template, so the exclusion "Defects triggered only by
   loading a snapshot that the emulator did not write and that does not meet the conditions of a valid template" does not
   apply. The application follows the rollup interface (it accepts with the outputs root of every output it accepted), so
   "An application that is not correctly designed" does not apply either. In any case that exclusion "covers only what such
   an application gets", and it adds that "it must never stop the honest operator from computing claims". No deployment
   obligation A1 to A8 is violated: `DaveConsensus` accepts any initial state hash, and it seals epoch 0 with outputs root
   `bytes32(0)`, which `crisium.lua` already expects (`eth.zero`) whatever the template.
2. Role: Support. AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support". This clause covers the component.
   Section 3: "A defect that only a support component shows is Medium when it would rate High or Critical in the role the
   component stands in for, such as ... the honest operator for an implementation of an operator". The player is such an
   implementation of an operator, so the clause covers it. Step 2: "A defect that only a support component shows is never
   above Medium." No component in the honest-operator role shows the defect.
3. High and Medium cases: section 8, Medium: "A defect that only a support component shows, when section 3 rates it
   Medium." This fits once step 4 rates the stood-in role High or Critical.
4. Critical, in the stood-in role: R4, "From any reachable state, at the position where it is reached, the honest operator
   can always compute the claim". The honest operator's path includes "Obtaining its valid template" and "Computing
   claims". Section 8: "violating any rule or obligation ... anywhere on the honest operator's path, is critical." An
   honest operator that refused a valid template would be Critical, so the support player rates Medium.

Two readings give different classes:

- **Medium (preferred).** The threat model's definition of a valid template explicitly includes templates whose tx buffer
  commits to earlier outputs, and the manual documents how to make and check them. The threat model defines what a bug
  is, so the documented limitation in the player's comment ("the template machine with an empty output history") and in
  prt-lua-bridge.md does not excuse a stand-in for the honest operator.
- **Low.** The manual says "A template is the genesis of a Cartesi Rollups application", and the bridge documentation says
  "the template's checkpoint holds an empty one". If PRT deployments are taken to start only from genesis templates, this
  is a documented limitation of a demonstration tool that violates no rule.

The deciding fact is whether a PRT deployment may legitimately be created with a non-genesis template. Nothing in the
manual or in Dave forbids it, and the threat model's definition anticipates it.

### Possible solution and risks

Give `store_first_epoch_checkpoint` an optional fourth argument holding the template's outputs frontier (or the proof of
its last output, from which `hash_tree.frontier(<last_output_proof>, "keccak256")` rebuilds it). Seed the frontier with
`new_outputs_frontier(previous_outputs_frontier)` and write `output_count` from its leaf count. Then add a crisium or
prt-demo option to supply it. If the operator has only the root and no frontier, the player could still store the
checkpoint and compute claims. It should not assert; it should report that the output history is unknown, because claims
do not depend on outputs. Risks: a frontier that does not match the template's root must still be refused (the existing
assert does this when given the right frontier). Existing genesis runs are unchanged when the argument is omitted.

### Risk of not fixing it

The PRT player and the Lua bridge cannot defend, or even watch as a sentinel, any application whose template carries an
earlier output history. Anyone who uses the recipes as the reference for an operator, for a migrated or continued
application, inherits a node that never posts a claim, and then any claim could win. No production deployment runs the
player (AUDIT.md), and the production node's behavior is outside this campaign. Until it is fixed, the mitigation is to
deploy PRT applications only from genesis templates, or to write the epoch-0 checkpoint by hand.
