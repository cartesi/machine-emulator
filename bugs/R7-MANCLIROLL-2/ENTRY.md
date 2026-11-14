## R7-MANCLIROLL-2

**Title.** The manual's uarch computation-hash shortcut for a later input (`begin_epoch:false,next_input_offset`, "needs no epoch files") aborts with "outputs Merkle root mismatch" and prints no claim whenever an earlier input accepted an output.

**Severity.** Medium (Low under the alternative reading below)

### Problem

doc/README.md ("Computation hashes") documents how to compute a uarch cycle computation hash for a period in a later
input without running the epoch from its start:

> The uarch cycle computation hash needs no epoch files. [...] A period in a later input does not require running
> the epoch from its start. Given a machine at the state that receives that input, `begin_epoch:false` with
> `next_input_offset` set to the input's zero-based offset in the epoch, counting rejected inputs, starts there.

The CLI help says the same ("use begin_epoch:false and next_input_offset in --cmio-advance-state when starting from a
later input. no epoch files are required for uarch computation hashes.").

In that mode, with no `outputs_frontier` or `last_output_proof`, the `cartesi-machine` CLI starts its host copy of
the outputs Merkle tree empty, while the guest's tx buffer commits to every output accepted earlier in the epoch (and
before it), as a correctly designed application must. `check_outputs_merkle_root` defaults to true, so at the
target input's rx-accepted yield the CLI asserts "outputs Merkle root mismatch at input k" and exits 1. When the target
period lies after the input stops (the period is completed in `end_input`, after the flush), no claim is printed at
all; when it lies inside the input, the hash is printed but the process still exits 1. Any correctly designed
application that accepted at least one output before the target input triggers it, including the manual's own
rolling-calculator example, whose inputs each emit an output.

The claim computed by a tool that computes claims is what the honest operator defends. The documented route to the
uarch-level claim of a later input, which keeps the cost of reaching the period at "the mcycles from the nearest
retained input boundary" (R12), fails for essentially every real application. The behavior contradicts the manual on
a point about computing claims (completeness), which section 8 rates "as if the manual were right".

### Component, role and area

The `cartesi-machine` CLI (`src/cartesi-machine.lua`), `--cmio-advance-state` output bookkeeping combined with
`--uarch-cycle-computation-hash`. Role from the AUDIT.md table: "The PRT player and bridge in `doc/recipes`, the
`cartesi-machine` CLI, and the Lua helper libraries ... | Support. No production deployment runs the player, the
bridge or the CLI." The PRT player (`doc/recipes/prt.lua`) computes its claims through the Lua API, not through the
CLI, and does not share the defect. The emulator API (`collect_uarch_cycle_root_hashes`) behaves correctly: with the
check disabled, the same shortcut prints the correct hash.

### Location

- `src/cartesi-machine.lua`, `initialize_cmio_outputs` (about lines 3533-3557): with `begin_epoch:false`, no
  `outputs_frontier` file and no `last_output_proof`, `advance.outputs_frontier` falls back to an empty frontier.
- `src/cartesi-machine.lua`, `flush_pending_outputs` (about lines 3679-3697): `assertf(frontier root == data,
  "outputs Merkle root mismatch at input %d", ...)` when `check_outputs_merkle_root` (default true, line 2084).
- `src/cartesi-machine.lua`, `run_advance_state_input` (about lines 4712-4730): `flush_pending_outputs` runs before
  `builder:end_input(runner)`, and `uarch_cycle_computation_hash_end_input` (about lines 4458-4473) is where a period
  after the input's stop is completed.
- doc/README.md, "Computation hashes", the paragraphs starting "The uarch cycle computation hash needs no epoch files"
  (about lines 2686-2715); CLI help text for `check_outputs_merkle_root` and the `--uarch-cycle-computation-hash`
  notes (about lines 558-562 and 635-637).

### Evidence and test

`bugs/R7-MANCLIROLL-2/` contains `test.lua` (the test), `README.md` (the prover's description) and this entry. Run
with `bugs/run.sh R7-MANCLIROLL-2` (about 1 s). The test uses the harness `baremetal-template` guest
(`emit-output.c`: every advance payload becomes one output and one report, and the guest accepts with the updated
outputs Merkle root; payload `R` makes it reject). All CLI runs use `--remote-spawn --remote-shutdown`; the period is
`log2_mcycle_period:10`, `mcycle_period_index:2^38+100000`, which lies in input 1, after it stops.

1. Reference: from the template, inputs 0..1 with `begin_epoch:true`.
2. `--store` after input 0; the test checks the stored machine waits at an rx-accepted manual yield (the state that
   receives input 1).
3. control2 (setup check): input 0 rejected, so no output precedes input 1; the documented shortcut must exit 0 and
   match its reference.
4. control (setup check): input 0 accepted with one output; the shortcut plus `check_outputs_merkle_root:false` must
   match the reference.
5. target: the shortcut exactly as documented (`input_file_index_begin:1,input_file_index_end:2,begin_epoch:false,
   next_input_offset:1`, no epoch files) after input 0 accepted one output; asserts exit 0 and the reference hash.

A failing control exits 2. On audit/prt2 the reviewer re-ran it twice (the prover three times), each time with exit 1
and this output:

```
control2 (input 0 rejected): reference 0x7a27bb69b189b51003d4a579564d67f7b520f83b5f62e1f473f291fdb96bf8fa, shortcut exit 0, hash 0x7a27bb69b189b51003d4a579564d67f7b520f83b5f62e1f473f291fdb96bf8fa
reference (from template, inputs 0..1, begin_epoch:true): 0xad98ec9470b66bb1d00bb11b1c4518d7a214e8e5d70e8ae8c76f7d60807a5710
control (shortcut + check_outputs_merkle_root:false): exit 0, hash 0xad98ec9470b66bb1d00bb11b1c4518d7a214e8e5d70e8ae8c76f7d60807a5710
target (documented shortcut after an accepted output): exit nonzero, hash nil
  CLI error: /home/user/machine-emulator/src/cartesi-machine.lua:3692: outputs Merkle root mismatch at input 1
VIOLATED: R4 / doc/README.md: the documented uarch computation-hash shortcut (begin_epoch:false,next_input_offset) from the machine that receives input 1 must compute the claim 0xad98ec9470b66bb1d00bb11b1c4518d7a214e8e5d70e8ae8c76f7d60807a5710
run.sh: R7-MANCLIROLL-2: exit 1 (bug present)
```

The controls show that the command form is right and that only the host outputs-root check stops the run. A fix in
the CLI (for example not checking against an unknown host frontier in this mode) makes the test exit 0. The test was
not modified by the reviewer. Found, proved and reviewed on Opus 5.5; no fallback model was used.

### Trigger and reachability

Triggered by the operator running the manual's documented command, on any correctly designed application that
accepted at least one output before the target input in the epoch, or before the epoch (the guest's root also commits
to outputs its template already commits to). The state is reachable: a single accepted input that emits one output,
delivered to a valid template, produces it (the test does exactly this from the harness template). No adversary is
needed; an adversary can only choose to steer a uarch-level dispute into a later input, which the honest claim must
then answer.

### Rating

1. Out of scope: no. The trigger is a correctly designed application and the documented CLI command. The exclusion
   "An application that is not correctly designed ... Development tools may instead stop and report the violation"
   does not apply, because the application follows the rollup interface (the controls show its root is the correct
   one). No snapshot outside the valid-template conditions, no O1/O2 case, no host fault and no deployment violation
   is involved.
2. Role: the `cartesi-machine` CLI is Support per the AUDIT.md table. Section 3: "A defect that only a support
   component shows is Medium when it would rate High or Critical in the role the component stands in for, such as
   ... the honest operator for an implementation of an operator or a tool that computes claims." The clause covers
   this component: `--uarch-cycle-computation-hash` is a tool that computes claims, so it stands in for the honest
   operator. Section 8 step 2: "A defect that only a support component shows is never above Medium." Only the CLI
   shows it (the PRT player computes claims through the Lua API).
3. High and Medium cases: in the stood-in honest-operator role, no listed High or Medium case fits (it is not an
   unreachable-state case, a constant-factor cost case, or "A persistence operation that fails loudly ... in an
   uncommon host setup that the manual documents"). For the Support component itself, the case that applies is "A
   defect that only a support component shows, when section 3 rates it Medium."
4. Critical (in the stood-in role): R4 "From any reachable state, at the position where it is reached, the honest
   operator can always compute the claim". "Computing claims" is on the honest operator's path (section 2). The
   documented claim-computing operation fails from a reachable state, which in the honest-operator role is Critical.
   Section 8 also says "A contradiction between the manual and the behavior on a security-relevant point is a defect
   in one of the two. It takes the severity it would have if the manual were right." Stood-in Critical, so Support
   Medium.

Alternative reading (Low): the claim stays computable by other documented means, so R4 is not broken in the
stood-in role: running the epoch from its start with `begin_epoch:true`, passing `check_outputs_merkle_root:false`
(whose help text says the host tree is initialized "from outputs_frontier or last_output_proof, or start empty at
genesis"), or passing a frontier or last output proof. Under that reading the defect is a documentation or
diagnostics gap of a development tool ("a defect in a tool's diagnostics"), Low. Against it: the manual, which is the
specification, documents the exact failing command and mentions none of these options; running from the epoch start
gives up the bound "Reaching that position costs at most the mcycles from the nearest retained input boundary" (R12);
keeping a last output proof is "not on the honest operator's path" (section 8); and the readings settled for this
campaign rate a Support component that fails on its own operator path under the stand-in rule. The deciding fact is
whether a documented opt-out found only in the CLI help (not in the manual's shortcut) keeps the claim "computable"
for R4. The reviewer judges Medium best supported.

### Possible solution and risks

Either fix the CLI or the manual. In the CLI: when `begin_epoch:false` and neither `outputs_frontier` nor
`last_output_proof` gives the host tree, do not check the guest's root against an empty host frontier (skip the check
with a warning, or default `check_outputs_merkle_root` to false in that case, at least when only a uarch computation
hash is requested), and also avoid writing output files and proofs at host indices that start at 0 (with the check
disabled today the output is named `output-0-input-1.bin` instead of global index 1). Alternatively, refuse the
command up front with a message naming the required option. In the manual: state that the shortcut needs
`check_outputs_merkle_root:false` (or a frontier) whenever earlier outputs exist, and give the command. Risks:
silently skipping the check removes a diagnostic that catches applications that break the rollup interface in other
modes; it must be limited to the case where the host frontier is genuinely unknown.

### Risk of not fixing it

No production deployment runs the CLI, so the goal is not directly threatened. An operator implementation or test
setup built on the CLI that follows the manual cannot compute uarch-level claims for any later input of a typical
application, and would either lose uarch-level matches by timeout or fall back to rerunning the epoch from its start.
Mitigation outside the code: pass `check_outputs_merkle_root:false` (or a correct `outputs_frontier`/
`last_output_proof`) with the shortcut.
