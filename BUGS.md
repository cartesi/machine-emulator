# Bugs

Confirmed issues of the audit, ordered by severity. Severities, roles and rules follow `THREAT_MODEL.md`. The process
and every rejected candidate are in `AUDIT_REPORT.md`. Run a test with `bugs/run.sh <ID>`; it exits 1 while the bug is
present and 0 once it is fixed. IDs take the form `R<round>-<ANGLE>-<n>`: the round, the hunter's angle, and the
candidate's number within that angle.

Flags required by `AUDIT.md` (fallback-only confirmations, issues without a proof of concept, tests that model a
component instead of running it):

- None yet.

Where the threat model can be read two ways, the severity column gives the reviewer's preferred reading first.

| ID | Title | Component | Role | Cited rules | Severity |
|---|---|---|---|---|---|
| [R1-A2-1](#r1-a2-1) | PRT referee model (prt.lua new_dapp_contract/run_epoch) seals an epoch with its whole input record, no 2^24 cap, unlike DaveConsensus and vg.lua | doc/recipes/prt.lua new_dapp_contract, run_epoch (PRT referee model) | Referee model | A3, R4, section 3 (Referee model), section 5 (unlisted model/deployed disagreeme | Critical / Low |
| [R1-A7-1](#r1-a7-1) | Released Dave COMMITMENT_BUDGET (120 min, 2^18-mcycle leaf) is sized for average uarch density; sfence.vma/fdiv.d-dense leaves need about 11-12 h and 3 h to build | Dave v3.0.0-alpha.7 ArbitrationConstants/ClockBudgets/Deployment.s.sol vs collect_uarch_cycle_root_hashes cost | Referee model (deployed referee); overrunning operation is H | A7, R12, R4, section 8 Critical (R12 cost beyond sizing), section 1 completeness | Critical (preferred) / Medium (if section 3's 'only changes how long a claim may take to respond' covers Dave's clock sizing) |
| [R1-GUEST-2](#r1-guest-2) | rollup --utf8-payload accept/reject/finish consumes a non-UTF-8 input, then exits 1 with no request printed: the app halts or accepts an input it never saw | machine-guest-tools v0.18.1-test1 sys-utils/rollup/rollup.cpp (encode_payload, write_advance_state, finish_request_and_g | Guest software | Section 2 correctly designed application; section 3 Guest software (R7 rx buffer | Critical (reading A: --utf8-payload documented for rollup apps facing arbitrary senders) / Low (reading B: option scoped to UTF-8 text payloads) |
| [R1-O1-2](#r1-o1-2) | Unhashed config.json hash_tree.phtc_size survives clear_hash_tree, so a template's distributor sets the honest operator's adoption memory without bound (12 kB/entry) | Emulator core: loading stored machines (machine_config::load, hash_tree / page_hash_tree_cache sized from stored phtc_si | Honest operator | Section 8 OOS snapshot clause, R12, R4, O1 (section 5), section 2 honest operato | Critical / Low (if the whole template directory, unhashed config included, is trusted input) |
| [R1-O2-3](#r1-o2-3) | Failed collect_mcycle_root_hashes (non-console exception, e.g. bad_alloc) drops context-only dirty marks; hash tree, later roots and stored snapshots mismatch contents | collect_mcycle_root_hashes / collect_mcycle_hashes_state_access / hash tree dirty tracking | Honest operator | R9, section 4 (host faults), section 1 completeness | Critical (preferred: host fault turned into a wrong hash, R9 failed update) / Low (if memory exhaustion is not a covered host fault or continuing after an error |
| [R1-R7-1](#r1-r7-1) | The LR/SC reservation is keyed by virtual address and survives satp writes and sfence.vma, so after a remap an SC succeeds on another physical page and writes it. | Interpreter (src/interpret.cpp execute_LR/execute_SC; ilrsc not cleared by write_csr_satp or execute_SFENCE_VMA), shared | Honest operator | R7 | Critical / Medium |
| [R1-R10-1](#r1-r10-1) | Regenerated Solidity StepVerifier and C++ verify_step_uarch accept uarch stores to the PMA array, shadow TLB, HTIF and uarch_x0, which the native uarch refuses as traps | machine-solidity-step regenerated (EmulatorCompat.writeWord/AccessLogs.writeWord via UArchStep store helpers); C++ uarch | Referee verifier (regenerated machine-solidity-step); C++ ve | R3, R2, R10; section 8 High (verifier misbehaving on unreachable before-states) | High |
| [R1-R10-2](#r1-r10-2) | Off-by-one in Memory.validateStrideLength makes the on-chain step verifier revert on uarch accesses to the top 32-byte leaf, which native uarch and C++ verifier accept | machine-solidity-step src/Memory.sol validateStrideLength (identical in released, regenerated and Dave machine/step) | Referee verifier | R2, R3, section 8 High (divergence at unreachable states) | High (preferred: divergence between paths at an unreachable state) / Low (if rejecting at an unreachable state is not a divergence) |
| [R1-R12-2](#r1-r12-2) | The uarch issues a TLB flush's 768 write_tlb ecalls through an out-of-line 14-instruction wrapper: 17,492 uarch cycles (22 per slot) even with a full TLB, about 5-6x what is needed | uarch program TLB-flush path: src/interpret.cpp flush_tlb_slot/flush_tlb_set/flush_all_tlb/set_prv compiled into the uar | Honest operator (AUDIT.md: 'Interpreter, ..., uarch program, | R12, A7, section 8 High constant-factor case; fix implies R13/A6 version change | High (preferred reading); Low under the alternative reading that 'defect' excludes code-generation efficiency of a correct implementation |
| [R1-R13-1](#r1-r13-1) | Regenerating machine-solidity-step v0.17.0-test1 from audit/prt2 fails to compile: UArchStep.sol uses undeclared TLB_NUM_SETS (added by afd5f9d), so the referee verifier cannot be rebuilt from audited source | machine-solidity-step v0.17.0-test1 regenerated from audit/prt2 (generate_UArchStep.sh, EmulatorConstants template/lua); | Referee verifier (AUDIT.md table); root cause in uarch progr | R13, A6 | High; Critical under the reading that every deployment must ship hand-edited or stale verifier code |
| [R1-R8-3](#r1-r8-3) | Each collect_mcycle_root_hashes call re-marks and word-compares all 256 write-TLB pages even when nothing changed. A guest that yields every 1-2 mcycles makes each yield cost about 6x more. | collect_mcycle_root_hashes / hash tree (src/machine.cpp update_hash_tree, mark_write_tlb_dirty_pages) | Honest operator | R12, A7, section 8 High (constant-factor cost) | High (preferred: guest-induced constant-factor increase of R12 'a part of a claim', sizing unknown) / Out of scope (literal reading of the yield-count exclusion |
| [R1-A3-1](#r1-a3-1) | PRT player opens epoch N+1's listener from epoch N's seal block, so it misses the inputs DaveConsensus defers past the 2^24 limit and crash-loops | doc/recipes/crisium.lua open_epochs (line 267) + doc/recipes/prt-epoch.lua poll (lines 37, 73, 96) | Support (PRT player, AUDIT.md table), standing in for the ho | R4 (last bullet), A3, section 8 Critical 'crash ... data the honest operator mus | Medium |
| [R1-A6-2](#r1-a6-2) | PRT player and deployer check deployments only by pristine uarch hash, never CM_MARCHID, so they accept another version's verifier with an unchanged uarch image | doc/recipes/crisium.lua (start-up check, lines 128-132), doc/recipes/prt-deploy.lua (lines 44-48), doc/recipes/prt-lua-b | Support (PRT player/deployer in doc/recipes), standing in fo | R13, A6 | Medium (preferred: R13 check must hold against later releases); Low (if only versions already released count) |
| [R1-A7-3](#r1-a7-3) | The stored PRT player runs a later epoch's whole input in one crisium idle step, so the sealed epoch's dispute is not observed or answered until that input finishes | PRT stored player and crisium main loop (doc/recipes/prt.lua, doc/recipes/crisium.lua) | Support, standing in for the honest operator | R4, A7, section 3 support rule, section 8 Medium case | Medium (reading A: Critical in the stood-in honest role, so Medium for support; reading B: High as a constant factor, still Medium for support) |
| [R1-A8-3](#r1-a8-3) | PRT referee model: logical time needs every connected player's advance_time reply, so one claimant that goes silent with its socket open freezes every other match. | doc/recipes/prt.lua referee over doc/recipes/game-transport.lua (step_time, send_next_event) and game-clock.lua barrier_ | Referee model (AUDIT.md table), its stalls rated as support  | A8 (also A7 in the stood-in role); section 3 Referee model and Support clauses;  | Medium / Low |
| [R1-A8-4](#r1-a8-4) | The PRT bridge keeps a pending cleanup with no deadline over the honest claim's newly due move, so the move waits for the cleanup's inclusion and can miss its clock | doc/recipes/prt-bridge.lua methods:tick (pending-job preference); prt-transactions.lua submit (bump_blocks) | Support (PRT bridge), standing in for the honest operator's  | R4, A7 (section 1 completeness) | Medium (support, stands in for an honest-operator R4 violation) / Low if the clocks are read as having slack for honest self-delay |
| [R1-BOUNDARY-1](#r1-boundary-1) | PRT bridge observe() fetches, keeps, re-sorts and rescans every TournamentCreated log of the shared, permissionless tournament factory after the seal, so its chain observation grows with foreign chain activity | PRT bridge, doc/recipes/prt-bridge.lua methods:observe with prt-log-history.lua, started by prt-epoch.lua with first_blo | Support (AUDIT.md: PRT player and bridge in doc/recipes), st | R12, section 7 (raise foreign chain activity), section 3 Support, section 8 Medi | Medium |
| [R1-BOUNDARY-3](#r1-boundary-3) | crisium get_seal fetches, retains and re-decodes every consensus log since deployment, so restart and per-epoch observation cost grow with past epochs | doc/recipes/crisium.lua get_seal/seal_history (lines 125, 207-219) with doc/recipes/prt-log-history.lua | Support (AUDIT.md: PRT player in doc/recipes), standing in f | R12 (operator-work clause), section 2 honest operator's path (observing the chai | Medium (preferred: literal R12, stand-in Critical) / Low (if R12 tolerates small per-epoch growth) |
| [R1-O1-3](#r1-o1-3) | PRT player's store_first_epoch_checkpoint loads the template without clear_hash_tree and records a cached-tree root that crisium compares with the on-chain hash, so a valid template is refused | PRT player in doc/recipes: prt.lua store_first_epoch_checkpoint (2743-2776), assert_rolling_template; crisium.lua:236; p | Support (AUDIT.md: "The PRT player and bridge in doc/recipes | O1, section 5 binding clause, section 2 honest operator's path (obtaining the va | Medium (preferred reading); Out of scope under the literal-exclusion reading |
| [R1-O2-1](#r1-o2-1) | PRT stored player, after a power loss, restarts from its unsynced machine.revert clone, deletes the synced epoch machine, trusts the stale cached hash tree, and records wrong roots. | doc/recipes/prt.lua stored player: stored_machine_pair_methods:commit, revert_interrupted_input, reopen_epoch_directory | Support (PRT player), standing in for the honest operator | O2, R4, section 5 (O1/O2 bind reference implementations), section 3 Support | Medium (Out of scope under a literal reading of the O2 reload exclusion) |
| [R1-O2-2](#r1-o2-2) | Reopening a sealed epoch after a stop past the seal commit replaces the synced epoch machine with an unsynced clone and deletes machine.revert, leaving no O2-guaranteed copy | PRT stored player epoch directory, doc/recipes/prt.lua (seal_epoch_state, revert_interrupted_input, reopen_epoch_directo | Support (PRT player), standing in for the honest operator | O2, R4, section 5 (tools must follow O2), section 3 support rule | Medium (preferred); Out of scope under a broad reading of the host-fault exclusion |
| [R1-R12-3](#r1-r12-3) | PRT epoch listener poll() and bridge observe() re-copy, re-sort and rescan every processed log on each per-block observation: per-input and per-match observation cost grows with logs already seen | doc/recipes/prt-epoch.lua poll(), doc/recipes/prt-bridge.lua observe() (with prt-log-history.lua; driven per block by cr | Support (PRT player and bridge), standing in for the honest  | R12 (honest operator's own work: bounded cost per input/match), R4, A7 | Medium (Critical, or High under the second reading, in the stood-in honest-operator role; support caps it at Medium) |
| [R1-R2-1](#r1-r2-1) | write_reg("iunrep") changes the hashed unreproducible-mode register while every guard reads the config copy, so store writes a directory its own load refuses | machine::write_reg case reg::iunrep (src/machine.cpp ~1444); machine::is_unreproducible reading m_c config copy (src/mac | Rest of the machine API, off the honest operator's path (wri | R2, R14, R9 (section 8 Medium API-operation case), manual "creation-time mode" | Medium (preferred); Low under the trusted-caller-misuse reading; Out of scope if the deliberate-change exclusion is read to cover every consequence |
| [R1-R3-3](#r1-r3-3) | prt.lua validate_state_transition_response accepts state-transition proofs with superfluous send_cmio/reset_uarch logs, ignoring them; Dave rejects them as trailing data | doc/recipes/prt.lua validate_state_transition_response (same code in doc/README.md lines 9465, 10874) | Referee model | R3 (log validity: trailing/duplicate data), section 3 referee-model clause, sect | Medium / Low (if unused named response fields are not part of the proof) |
| [R1-R6-1](#r1-r6-1) | cartesi-machine --print-uarch-cycle-root-hashes passes a fake revert uarch tail {revert_root_hash, revert_root_hash}, printing wrong uarch hashes for the mcycle after a rejection | cartesi-machine CLI, src/cartesi-machine.lua uarch_cycle_root_hashes_runner_run | Support | R6, R4 (via section 3 support-Medium clause) | Medium (preferred: CLI printer counts as a tool that computes claims); Low (if read as a tool's diagnostics) |
| [R1-R8-1](#r1-r8-1) | PRT player keeps one keccak per guest output for the whole input in the claim-computing run (pending_output_hashes), so claim-computation memory grows with the number of outputs | PRT player, doc/recipes/prt.lua run_to_input_mcycle_offset / flush_pending_outputs / run_next_input | Support (AUDIT.md: PRT player), standing in for the honest o | R12, section 8 outputs exclusion, section 3 support rule | Medium (preferred reading); Low (alternative reading) |
| [R1-R8-2](#r1-r8-2) | vg.lua honest player asserts the tx-buffer outputs root equals its output frontier; a guest accepting with a mismatched root makes input_added raise, so no claim is computed | doc/recipes/vg.lua honest player (flush_pending_outputs line 429, via run_to_input_mcycle_offset and event_handler:input | Support (not named in the AUDIT.md table, falls under sectio | R4, section 8 (not-correctly-designed exclusion: 'must never stop the honest ope | Medium; Out of scope if vg.lua's player counts as a development tool |
| [R2-DFGUESTSTATE-1](#r2-dfgueststate-1) | Manual and generated DTB declare Sv39 only, but every path accepts satp MODE=9 and performs four-level Sv48 walks | Interpreter (src/interpret.cpp write_csr_satp, src/riscv-warl.hpp WARL_satp, src/translate-virtual-address.hpp), src/dtb | Honest operator | R7, section 8 Medium deviation case, section 8 manual-contradiction clause, R13  | Medium / Critical (literal R7) / Low (manual read as non-exhaustive) |
| [R2-DFINPUTCOUNT-1](#r2-dfinputcount-1) | PRT stored player keeps only 32 input boundaries per epoch, so per-match replay to reach a disputed input grows linearly with the epoch's input count (about n/16) | PRT stored player, doc/recipes/prt.lua (STORED_MACHINE_CACHE_CAPACITY=32 at 901, machine_cache_methods:consider 1217-124 | Support (AUDIT.md: PRT player in doc/recipes), standing in f | R12, A7, section 1 completeness, section 3 support clause, section 8 step 4 | Medium (support stand-in for a Critical R12 per-match cost in the honest-operator role) / Low (if 'nearest retained input boundary' leaves retention to the oper |
| [R2-DFINPUTCOUNT-2](#r2-dfinputcount-2) | PRT player fetches epoch 0's InputAdded logs only from the DaveConsensus deployment block, but the constructor seals prior inputs into epoch 0, so crisium crash-loops | doc/recipes/crisium.lua (first_block line 125, open_epochs first_input_block line 267) with prt-epoch.lua poll (line 37, | Support (PRT player), standing in for the honest operator | R4, section 1 completeness, section 8 Critical (crash on data the operator must  | Medium / Low (if apps created before and apart from their DaveConsensus are unsupported) |
| [R2-DFOUTPUT-1](#r2-dfoutput-1) | PRT stored player refuses every valid non-genesis template: store_first_epoch_checkpoint asserts the tx buffer holds the empty outputs root, so epoch 0 never starts | doc/recipes/prt.lua store_first_epoch_checkpoint (2741-2777), required by crisium.lua open_epochs and prt-demo.lua | Support (PRT player), standing in for the honest operator | R4, section 2 valid template and honest operator's path, section 3 support claus | Medium / Low |
| [R2-DFSTORED-1](#r2-dfstored-1) | After an O1 adoption with clear_hash_tree, store with sharing none/config copies the template's stale .dht/.dpt files, so the synced snapshot reloads with the stale root | Emulator core: machine::store (src/machine.cpp, unshared branch) with hash_tree::clear (src/hash-tree.cpp:744) | Honest operator (AUDIT.md: 'storing, loading, cloning and sy | R9, R1, O1, O2, section 5 'O1 and O2 bind the emulator too' | Medium (preferred: store with sharing none/config is off the honest operator's path) / Critical (if a production node stores an adopted template with none/confi |
| [R2-DFYIELD-1](#r2-dfyield-1) | PRT player's claim pass copies (and for TX_OUTPUT keccak-hashes) the guest-declared tx-buffer payload, up to 2 MiB, at every automatic yield, multiplying per-yield claim cost ~75-100x | PRT player, doc/recipes/prt.lua (run_next_input -> run_to_input_mcycle_offset on_yield_automatic -> run_to_stop/receive_ | Support (stands in for the honest operator computing claims) | R12 ('a part of a claim'), section 8 High constant-factor case, section 3 suppor | Medium (preferred: support stand-in for High constant-factor R12 case) / Out of scope (broad reading of outputs/yields exclusion) |

<!--
Template for each issue. Copy it below the index, in the same order as the index.

## <ID>

**Title.** <one line>

**Severity.** <Critical | High | Medium>

### Problem

<What goes wrong, and how it threatens the security goal of section 1, or why it still violates a rule.>

### Component, role and area

<The component, its role from the AUDIT.md table, and the area within it.>

### Location

<Files and functions.>

### Evidence and test

<What `bugs/<ID>/` contains (test, guest programs, configurations, crafted logs or proofs, inputs, scripts), how to
run it, and what it prints on audit/prt2. Say which model found, proved and reviewed it if a fallback was used.>

### Trigger and reachability

<Who triggers it and how. For an unreachable state, why no input sequence from any valid template produces it.>

### Rating

1. Out of scope: <why not, quoting the exclusions checked>.
2. Role: <component and role, quoting section 3>.
3. High and Medium cases: <the case that fits, quoted, or why none does>.
4. Critical: <the rule or obligation violated at a reachable state or on the honest operator's path, quoted>.

<If two readings give different classes, give both and the facts that would decide.>

### Possible solution and risks

<The fix, and what it could break.>

### Risk of not fixing it

<What a deployment that leaves it unfixed is exposed to, who can trigger it, and any mitigation outside the code.>
-->

## R1-A2-1

**Title.** The PRT referee model in `doc/recipes/prt.lua` seals an epoch with its whole input record and never caps it at the input limit per epoch (2^24), so inputs past the grid fall out of the verified history.

**Severity.** Critical (preferred reading: rated as a deployed referee, per section 3). Low under the alternative reading in which the model's input files are the trusted referee operator's configuration.

### Problem

The model's dapp contract takes every input path it is given as the epoch's input record
(`inputs = map(input_paths, fs.read_file)`) and checks neither their count nor their size. `run_epoch` announces every
input with `input_added` (offsets 0..n-1) and seals the epoch with `epoch_sealed(#dapp_contract.inputs)`. Nothing caps
n at the input limit per epoch, 2^`ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH` = 2^24. The deployed referee does cap it:
`DaveConsensus.sol` seals at most `MAX_INPUTS_PER_EPOCH = 1 << ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH` inputs per
epoch (`lowerBound + pendingInputs.min(MAX_INPUTS_PER_EPOCH)`) and leaves the rest pending for later epochs.

The dispute grid that the model derives addresses only 2^24 input slots. For the model's geometry
(`new_geometry(10)`), `mcycle_height = 24 + 48 - 10 = 62` and `periods_per_input = 2^38`.
`validate_state_transition_response` only ever looks up `dapp_contract.inputs[epoch_input_offset + 1]` with
`epoch_input_offset < 2^24`. An input at offset 2^24 or later is therefore part of the sealed epoch, but no transition
form delivers it. The referee settles a state that leaves it out, and it is never carried into a later epoch. The model's
honest player applies the limit and stops on that input (`assert(epoch_input_offset < 1 << LOG2_MAX_ADVANCE_STATES_PER_EPOCH,
"input offset past the epoch's input limit")` in `add_pending_input`). It then never posts its claim, so any claim can win.
That is a completeness failure in the sense of section 1. The cap the honest operator applies is what R4 requires, so
the player is not at fault.

This breaks deployment obligation A3, which section 5 says "breaks the goal even when the emulator is correct". The
manual's list of the model's simplifications ("The model simplifies the PRT contracts in a few ways", doc/README.md)
does not mention dropping the limit. The recipes' verification-game model `vg.lua` does enforce it
(`#input_paths <= INPUTS_PER_EPOCH` in its `new_dapp_contract`). The manual itself states "the maximum number of inputs per epoch
(2<sup>24</sup>)". The manual shows the same `run_epoch` code, so the manual's model has the same gap.

### Component, role and area

The PRT referee model in `doc/recipes`, role **Referee model** (AUDIT.md: "The PRT referee model in `doc/recipes` |
Referee model"). The area is the model's input record and epoch sealing: the dapp contract and the simulated blockchain
publication of the epoch. The honest player's assert is the expected reaction of a support component, not a defect.

### Location

- `doc/recipes/prt.lua` `new_dapp_contract` (around lines 851-861): `inputs = map(input_paths, fs.read_file)`, with no bound.
- `doc/recipes/prt.lua` `run_epoch` (around lines 806-811): one `input_added` per path, then
  `epoch_sealed({ #dapp_contract.inputs })`.
- `doc/recipes/prt.lua` `new_geometry` (around line 831) and `validate_state_transition_response` (around lines 266-292):
  the grid covers 2^24 input slots.
- `doc/recipes/prt.lua` `add_pending_input` (around line 2211): the honest player's assert.
- The manual (`doc/README.md`, around line 9419) reproduces the same `run_epoch`.
- For comparison, `DaveConsensus.sol` (pinned Dave v3.0.0-alpha.7, `bugs/harness/work/dave/released/...`, lines 39 and
  472) has the cap.

### Evidence and test

`bugs/R1-A2-1/` contains `test.lua` and `README.md`. Run it with `bugs/run.sh R1-A2-1`. The test writes a one-byte input
file and calls the model's exported `prt.new_dapp_contract(hash, paths)` with 2^24 + 1 copies of its path, so the model
really reads the file 2^24 + 1 times. It then runs `prt.new_referee(contract):run(server)` against a stand-in for the
referee server. The stand-in counts the `input_added` events, records the count passed to `epoch_sealed`, and stops the
run there, before any tournament starts. A control run with 3 inputs checks that the stand-in reaches the seal. The test
exits 0 if the referee seals the epoch with at most 2^24 inputs or refuses the oversized record, 1 if it seals the epoch
with more, and 2 on a setup error.

On audit/prt2 it prints:

```
control: 3 inputs -> 3 input_added, epoch_sealed(3)
building the referee's dapp contract from 16777217 input paths...
referee published 16777217 input_added events (offsets 0..16777216, ordered=true) and epoch_sealed(16777217)
dispute grid: 16777216 input slots (mcycle_height 62, periods_per_input 2^38); the input at offset 16777216 has no position
VIOLATED: A3: the input record assigns no more inputs to an epoch than the input limit per epoch (16777216); the referee model sealed the epoch with 16777217 inputs
run.sh: R1-A2-1: exit 1 (bug present)
```

The reviewer re-ran it twice. Both runs exited 1 with identical output, in about 26 s each and about 800 MB peak RSS (the
prover reports 3 identical runs). The test asserts A3 directly, and either correct fix (cap at 2^24, or refuse the
record) makes it exit 0. Found, proved and reviewed on Opus 5.5, with no fallback model.

### Trigger and reachability

The trigger is whoever fills the model's input record: a Lua caller of the exported `new_dapp_contract` /
`new_referee`, with more than 2^24 inputs for one epoch. Through the `prt.lua referee` command line, the same record
would need 2^24 + 1 path arguments, which exceeds the exec argument limit. In the model, the record is the referee
process's configuration, which the manual describes as files that "represent the inputs posted to the blockchain".
Rated as a deployed referee (section 3), the record is filled by input senders, whom section 4 makes untrusted with "any
bytes, any count". Section 7 lets the adversary "Send any number of inputs the deployment accepts". 2^24 + 1 inputs in
one epoch are then within the adversary's power. No machine state is involved, so no reachability argument about states
is needed.

### Rating

1. Out of scope: no. The candidate exclusion is "Defects that need the deployment to violate one of A1 to A8, unless ...
   an implementation of the referee model is what violates it (section 3)". Here the model's own `run_epoch` is what
   seals the over-limit epoch, so the exception applies and the exclusion does not. Section 5 also says that the
   manual's listed simplifications are not normative, and that "Any other disagreement between a deployed referee and
   the model is a defect in one of the two". Dave caps the epoch, the model does not, and that difference is not listed.
2. Role: the PRT referee model in `doc/recipes`, role Referee model (AUDIT.md). Section 3 says: "A defect in what it
   accepts or derives is rated as if a deployed referee had it." The model accepts the record and derives the epoch's
   input count, so this clause covers the component and this defect. Where the manual's model shares the gap, section 3
   says "then the manual is the defect, rated as a defect of the referee model", which gives the same rating. This is
   not a defect that "only changes how long a claim may take to respond, or only crashes or stalls the model".
3. High and Medium cases: none fits. The defect is not a verifier misbehaving on unreachable states, a crash in a
   component in the honest-operator role, or a constant-factor cost increase.
4. Critical: A3 is violated: "The input record assigns no more inputs to an epoch than the input limit per epoch". With
   R4, the honest operator "assigns inputs to epochs exactly as the referee does, including the input limit per epoch
   (A3)", which is impossible against this referee. Section 8 says: "violating any rule or obligation at a reachable
   state, or anywhere on the honest operator's path, is critical".

Alternative reading: the model's referee is "one trusted process" (manual), and its input files are its operator's
configuration of "the epoch's input files". Nothing untrusted fills them, and the CLI cannot even carry 2^24 + 1 paths.
Supplying an over-limit epoch would then be "a failure that needs misuse of an API by its trusted caller", which is
**Low**. The deciding fact is whether section 3's "rated as if a deployed referee had it" makes the model's input files
stand for a sender-filled on-chain input record (Critical), or whether they stay trusted configuration (Low). The
reviewer prefers the first reading. It follows section 3, the referee-model exception to the A1-A8 exclusion, section 5's
rule that unlisted disagreements with the deployed referee are defects, and section 4's untrusted input senders.

### Possible solution and risks

Enforce the limit where the model builds or seals the epoch. The model has a single epoch, so `new_dapp_contract` (or
`run_epoch`) should either refuse a record of more than `1 << LOG2_MAX_ADVANCE_STATES_PER_EPOCH` inputs with an error,
or seal only the first 2^24 inputs and leave the rest unannounced, the way DaveConsensus leaves them pending. The same
place could also enforce A3's second clause (no input whose honest delivery proof would exceed the per-transaction
limits). The manual's copy of `run_epoch` should match, or the manual should list this as a simplification and state
that the operator must keep the record within the limit. Risks: none for records at or below the limit. A truncating
fix must keep `input_added` and `epoch_sealed` consistent, so the honest player's "sealed input count mismatch" assert
still holds. The sibling verification-game model already does the first option: `vg.lua`'s `new_dapp_contract` has
`assert(#initial_state_hash == 32 and #input_paths <= INPUTS_PER_EPOCH, "invalid epoch")`. The PRT model lacks this
check.

### Risk of not fixing it

The model is a demonstration and no deployment runs it as its referee. But it is the normative stand-in documented next to
the manual, and code derived from it would inherit a referee that assigns inputs to an epoch beyond what the grid can
dispute. Such a referee silently drops inputs from the verified history and stops an honest operator that applies the
limit. In the model itself, triggering it needs a Lua-level caller that supplies more than 2^24 inputs. The deployed
Dave contracts already cap the epoch, which mitigates the risk for real deployments.

## R1-A7-1

**Title.** The released Dave clocks give the uarch-level commitment a budget sized for average uarch density. A guest
running dense heavy instructions makes the honest leaf build take 1.5 to 6 times `COMMITMENT_BUDGET`.

**Severity.** Critical. Under an alternative reading of section 3 it is Medium (see Rating).

### Problem

Dave v3.0.0-alpha.7 gives the honest claim `COMMITMENT_BUDGET` = 120 minutes to build the commitment it joins an
inner (uarch-level) tournament with. `ClockBudgets.sol` says: "joining an inner tournament first takes `commitment`
seconds to build the commitment". The parent's refill and the root allowance cover only that budget plus inclusions.
Any time past it is charged as join lateness (`Tournament.joinTournament` -> `Clock.initializePausedAt`). It comes
out of the censorship budget `C`, and the join reverts with `TournamentIsClosed` once the child's allowance has run
out.

With `log2step = [38, 0]`, the level-1 commitment covers one level-0 leaf: 2^18 mcycles, with one hash per executed
uarch cycle. Dave sized the budget from a reference leaf build rate of 173 mcycles/s, measured on a workload of 566
executed uarch cycles per mcycle (`docs/measurements/constants.md`). `docs/dimensioning.md` states the design choice:
"Coordinates are dimensioned to the worst case. Clocks are dimensioned to the average case", and "leaf-level dense
build within the commitment budget | aggregate | trusted app | average density". Dave rests this on an assumption
that the application developer is "trusted specifically to keep input-reachable behavior disputable".

The threat model assumes no such thing. The guest may be taken over by any input and "run any instruction stream at
any privilege level" (section 4). A correctly designed application bounds only its mcycle usage (section 2). R12 puts
the per-cycle worst case on the deployment: "The total cost of an epoch is the application's mcycle usage times these
bounds. Bounding that usage is the application's job, and sizing the deployment for it is the deployment's job
(A7)". The worst-case cost per mcycle of a uarch-level claim is far above the average Dave priced:

- `sfence.vma` in S-mode: 17,329 uarch cycles per mcycle, 28-31 times the control's host cost;
- `fdiv.d` in U-mode, which needs no privilege: 4,487 uarch cycles per mcycle, 7.2-8.0 times the control.

Scaled to Dave's own reference host with no hardware slack, one leaf build takes about 11.3-12.4 h for `sfence.vma`
and about 2.9-3.2 h for `fdiv.d`, against a 2 h budget. With the slack of 2 that Dave's own derivation assumes, it
takes about 23 h and 6 h.

What this does to the security goal, a completeness failure: "The honest operator ... cannot respond in time". The
dispute adversary chooses where to diverge (section 7: "Steer the dispute to any position of the honest
computation"). It can therefore put the inner tournament on a dense leaf.

- On testnet constants (`C` = 8 h, child allowance about 10.3 h), one `sfence.vma`-dense leaf cannot be joined in
  time on the reference host.
- On mainnet constants (`C` = 1 week), each forced delegation over a dense leaf costs the honest claim about 9-21 h
  of `C`, beyond the 2 h the refill restores. That time is not available for the censorship that `C` is meant to
  absorb ("A correct commitment must survive `censorship` seconds of adversarial delay in total"). An adversary that
  censors within the dispute clocks, plus one dense delegation, or a series of dense delegations forced through
  Sybils, exhausts the honest clock. The honest claim then loses by timeout.

### Component, role and area

- Dave v3.0.0-alpha.7 released arbitration constants and clock model. AUDIT.md role: "Referee model, as the deployed
  referee. Audit the released constants".
- The cost they fail to cover is that of `collect_uarch_cycle_root_hashes`, the uarch-level claim builder that the
  Dave node calls for dense leaf builds (`cartesi-rollups/node/src/engine/machine_stf.rs`, `big_cycle_roots`).
  AUDIT.md role: Honest operator.
- Area: dispute clock sizing (A7) against the R12 worst-case cost of a uarch-level claim.

### Location

- `bugs/harness/work/dave/released/prt/contracts/src/arbitration-config/ArbitrationConstants.sol`:
  `COMMITMENT_BUDGET = 120 minutes`, `log2step` `[38, 0]`, `height` `[54, 38]`.
- `.../prt/contracts/src/arbitration-config/ClockBudgets.sol`: `refill`, `maxAllowance`.
- `.../prt/contracts/script/Deployment.s.sol`: censorship budget 1 week (mainnet), 8 hours (testnet), 0 (devnet);
  inclusion budget 5 minutes.
- `.../prt/contracts/src/tournament/Tournament.sol`: `joinTournament` (`TournamentIsClosed`,
  `initializePausedAt`), `_isClosed`.
- Rationale: `.../docs/dimensioning.md` ("The rule", "Worked examples") and `.../docs/measurements/constants.md`.
- Emulator, honest operator: `collect_uarch_cycle_root_hashes` (its cost is what the uarch semantics require; it is
  not itself the defect).

### Evidence and test

`bugs/R1-A7-1/` contains:

- `test.lua`, the test;
- `README.md`;
- `guests/ctrl.S`, `guests/fdiv.S` and `guests/sfence.S`: bare-metal guests. Each enters a loop in U-mode (`ctrl`:
  `addi`; `fdiv`: `fdiv.d`) or in S-mode (`sfence`: `sfence.vma`) with bare translation. The test builds them at run
  time with `bugs/harness/baremetal/build.sh`.

Run it with `bugs/run.sh R1-A7-1`. It takes about 20 s and needs the toolchain image for the guest build.

The test parses `COMMITMENT_BUDGET`, `log2step`, the reference rate, the density and the hardware slack from the
released Dave sources. It then measures, for each guest:

- the exact number of executed uarch cycles per mcycle (a deterministic count);
- the host cost per mcycle of `collect_uarch_cycle_root_hashes`, in interleaved rounds. Only the ratio R to the
  control is used, so the host's speed cancels out.

It projects one 2^18-mcycle leaf on Dave's reference host as `R * min(1, D_ctrl/566) * 2^18 / 173 s`, with no
hardware slack. It then asserts that the projection is at most `COMMITMENT_BUDGET` for both dense guests.

On audit/prt2 it exits 1. The reviewer ran it 3 times, and every run exited 1. A typical run prints:

```
Dave released: COMMITMENT_BUDGET 120 min, log2step [38, 0] -> one leaf = 2^18 mcycles
Dave reference: 173 mcycles/s at 566.0 usteps/mcycle (hardware slack 2) -> average-density leaf build 1515 s (0.42 h), 3031 s with slack
guest    usteps/mc ratio(cnt)  ms/mc(host)    ratio(host)  leaf h slack1  leaf h slack2
ctrl           544       0.96         9.25           1.00           0.40           0.81
sfence       17329      30.62       262.04          28.33          11.46          22.93
fdiv          4487       7.93        69.27           7.49           3.03           6.06
budget: 2.00 h (COMMITMENT_BUDGET)
VIOLATED: A7/R12: honest uarch-level claim over one 2^18-mcycle leaf of a guest running sfence.vma in S-mode ... projects to 11.46 h ... with NO hardware slack ...
VIOLATED: A7/R12: honest uarch-level claim over one 2^18-mcycle leaf of a guest running fdiv.d in U-mode ... projects to 3.03 h ... with NO hardware slack ...
run.sh: R1-A7-1: exit 1 (bug present)
```

The margins are wide:

- The threshold is a host ratio of about 4.9. `sfence.vma` measures 28-31 and `fdiv.d` measures 7.2-8.0.
- A purely count-based projection, which does not depend on timing, also fails: about 12.9 h for `sfence.vma` and
  3.3 h for `fdiv.d`.

The test passes once the released clocks or strides are sized for the worst-case density. That fix would be a larger
`COMMITMENT_BUDGET`, or a smaller level-0 stride.

The test does not drive the chain. In particular, it does not show `TournamentIsClosed` on an honest late join; that
consequence is derived from the contract code above. A1 to A8 compliance of the clock arithmetic itself was not
re-checked. The candidate was found, proved and reviewed by Opus 5.5, with no fallback model.

### Trigger and reachability

The trigger needs two parties.

- A guest region of 2^18 mcycles that is dense in heavy uarch instructions. Any input may produce it in an
  otherwise correctly designed application: section 4 says an input "may then run any instruction stream at any
  privilege level". The input stays within the application's mcycle bound, which `imcyclemax` enforces. For the
  U-mode `fdiv.d` case, an application that legitimately runs floating-point-heavy user code is enough. No
  compromise is needed.
- A dispute adversary that posts a claim diverging inside that region. Section 7 allows it to "Steer the dispute to
  any position of the honest computation, and force the honest claim through a logarithmic number of matches".

Both are reachable, and no unreachability argument applies.

### Rating

1. Out of scope: no.
   - The exclusion "Defects that need the deployment to violate one of A1 to A8" has two carve-outs, and both cover
     this case: "unless the emulator's own behavior is what makes the obligation fail, such as a worst-case cost ...
     larger than the deployment was sized for, or unless an implementation of the referee model is what violates it
     (section 3)". Dave is that implementation; AUDIT.md: "Referee model, as the deployed referee. Audit the released
     constants".
   - "Average-case performance that does not change the worst-case cost of any operation listed in R12" does not
     apply. The finding is about the worst case.
   - "An application that is not correctly designed" does not apply. Section 2 requires a correctly designed
     application only to bound "its own mcycle usage", not its uarch density. Dave's trusted-density assumption is
     outside the threat model.
2. Role: two components show the defect.
   - Dave's released constants play "Referee model" (section 3).
   - The overrunning operation, `collect_uarch_cycle_root_hashes`, plays "Honest operator" (AUDIT.md table).
   - Section 3: "A defect is rated by the most critical role among the components that show it."
3. High and Medium cases: none fits on the preferred reading.
   - The High case on constant-factor cost increases needs "a defect that lets the guest ... multiply the worst-case
     cost ... compared with the same operation without the defect". Here the cost is the one "the specified
     semantics require", so there is no emulator defect.
   - The defect is the mismatch between that cost and the sizing.
4. Critical: two clauses apply.
   - Section 8 lists as Critical "An operation listed in R12 whose worst-case cost a guest can make unbounded,
     super-linear, or larger than what the deployment was sized for". R12 lists "a uarch-level claim".
   - It also violates A7: "The dispute constants and clocks leave room for the honest claim to play the logarithmic
     number of matches that a tournament forces on it, at the worst-case costs of R12". This happens at a reachable
     state, on the honest operator's path ("Computing claims"). The resulting timeout is a completeness failure under
     section 1.

Alternative reading: Medium. Section 3 says of the referee model: "A defect that only changes how long a claim may
take to respond, or only crashes or stalls the model ... is rated as support". If undersized clocks in Dave count as
"only" changing how long a claim may take to respond, the defect is rated as support. Section 3 then gives Medium,
because it "would rate High or Critical in the role the component stands in for".

Facts that decide between the readings:

- whether the support clause covers the deployed referee's clock sizing, or only clock differences in a model whose
  clock values are not normative (section 5: "neither are its clock values");
- whether the "worst-case cost larger than what the deployment was sized for" case counts the honest-operator
  builder as a component that shows the defect.

The reviewer prefers Critical. The goal's premise, "on the resources the deployment was sized for", fails exactly
here, and AUDIT.md tells auditors to audit the released constants as the deployed referee. Both readings rate the
defect Medium or above.

### Possible solution and risks

Size the clocks for the worst-case density of R12 rather than the average. Options:

- Raise `COMMITMENT_BUDGET` to cover a leaf of `sfence.vma`-class instructions. That is about 30 times the
  average-density build, plus slack.
- Shrink the level-0 stride, for example with more levels or a smaller `log2step(0)`, so that a worst-case leaf fits
  the current budget.
- Have the emulator lower the worst-case uarch cost of the heaviest instructions. That would be a new protocol
  version (R13).
- Alternatively, make the trusted-density assumption an explicit deployment obligation, with tooling that enforces
  it.

Risks:

- A larger budget lengthens every dispute and delays settlement.
- More levels change the contract-client compatibility boundary ("Coordinated-bump checklist" in constants.md) and
  the root-slowdown derivation.
- Changing uarch costs changes the pristine uarch hash and the step.

### Risk of not fixing it

- On testnet constants, an adversary that controls any input able to drive a guest into a 2^18-mcycle
  `sfence.vma`-dense region can make the honest claim unable to join the inner tournament in time on the reference
  host. It can do the same with an application whose own U-mode code is `fdiv`/`fsqrt`-dense, combined with
  censorship within `C`. A dishonest claim then wins the epoch.
- On mainnet, the same overrun silently consumes the week-long censorship budget at every forced dense delegation.
  The honest claim is left exposed to censorship the deployment claims to survive.
- The only mitigation outside the code is Dave's documented trust assumption: that validators defend only
  applications whose input-reachable behavior stays near average density. Nothing in the protocol checks or
  enforces it.

## R1-GUEST-2

**Title.** `rollup --utf8-payload accept|reject|finish` consumes an advance-state input whose payload is not valid
UTF-8, then exits 1 without printing the request. An input sender can make an application that uses the tool as the
manual shows halt, or accept an input it never saw.

**Severity.** Critical (preferred reading). Low under the reading that `--utf8-payload` is documented only for
payloads that are UTF-8 text (see Rating).

### Problem

`rollup accept` (and `reject` and `finish`) first calls `cmt_rollup_finish`. That call yields manually with the
accepted (or rejected) reason and receives the next request into the rx buffer. Only after that does the tool build
its JSON output. In `--utf8-payload` mode, `encode_payload` returns the raw payload bytes as a `std::string`, and
`nlohmann::json::dump(2)` runs with its default strict error handler, so it throws `type_error.316` on any invalid
UTF-8 byte. `finish_request_and_get_next` catches the exception, prints it to stderr, and returns 1. Nothing is
printed on stdout.

By then the input has been delivered and the yield that answered the previous one has completed. The application gets
no request and exit status 1. It cannot tell this from a failure that happened before the yield, and the tool
documents no failure after the input is consumed. What happens next depends on how the application handles errors:

- If it stops when the tool fails (`exit`, `set -e`), cartesi-init halts the machine. The application then deviates
  from the rollup interface: it does not yield manually with the accepted or rejected reason after that input.
  Every later input is lost. Under A5, the outputs of the halted state cannot be extracted.
- If it retries `rollup accept`, the tool accepts the consumed input. The application never saw it and emitted
  nothing for it.
- If it continues with `rollup reject`, as the manual's `calc.sh` does when anything in its loop fails, the input is
  rejected whatever it contains.

Section 1 requires that no adversary can make a correctly designed application settle a state other than the one
the state transition function defines. Section 3 counts a guest-software defect that lets an input make such an
application deviate from the rollup interface as an R7 deviation in the rx buffer and the yield interface. Any
input sender can trigger this one with a single payload byte such as `0xff`.

### Component, role and area

`machine-guest-tools` v0.18.1-test1, the `rollup` command-line tool in the guest root file system (the
`rootfs-tools.ext2` that the harness pins as `rootfs.ext2`). Role from the AUDIT.md table: "`machine-guest-tools`
v0.18.1-test1 | Guest software". Area: encoding the payload of the next request in `--utf8-payload` mode after the
`finish` yield.

### Location

`sys-utils/rollup/rollup.cpp` in machine-guest-tools v0.18.1-test1:

- `encode_payload`: for `encoding::utf8` it returns `{data, length}` without validating or escaping the bytes.
- `write_advance_state` (and `write_inspect_state`): `std::cout << j.dump(2)`. nlohmann's strict handler throws
  `type_error.316` for invalid UTF-8.
- `finish_request_and_get_next`: `cmt_rollup_finish(r, &f)` (the yield, which receives the input) runs before
  `write_advance_state`. The `catch` prints `x.what()` and returns 1.

### Evidence and test

`bugs/R1-GUEST-2/` contains `test.lua` (the test) and `README.md` (description, the documented scope of
`--utf8-payload`, and the expected output). There are no other support files. The test uses the harness config
`linux-rootfs` (harness `linux.bin` with the pinned guest-tools `rootfs.ext2`) and sets the entrypoint to a shell echo
application. The application calls `rollup --utf8-payload accept|reject` and checks its exit status. It prints each
request's payload, emits the payload as a notice and accepts. If the tool returns no request, it prints a message
and exits 3. The test delivers four advance-state inputs through the machine API (`send_cmio_response` with
`harness.encode_advance`): `hello`, `h\xc3\xa9llo` (valid UTF-8), `h\xffllo` (invalid UTF-8) and `bye`. The first two
are controls and must each be accepted with one notice, otherwise the test exits 2. **Asserted:** after each input,
the machine reaches a manual yield with the accepted or the rejected reason. A second run, which is informative and
not asserted, uses an application that retries `rollup accept` when it fails.

Run `bugs/run.sh R1-GUEST-2` (about 4 s, two short Linux boots). On audit/prt2 it prints (excerpt):

```
[stop on failure] input 1 (payload "hello"): accepted, 1 output(s) emitted
[stop on failure] input 2 (payload "héllo"): accepted, 1 output(s) emitted
[stop on failure] input 3 (payload "h\255llo"): halted, 0 output(s) emitted
[stop on failure] guest console: [json.exception.type_error.316] invalid UTF-8 byte at index 1: 0xFF
[stop on failure] guest console: app: rollup --utf8-payload accept failed: no request obtained, stopping
VIOLATION: after input 3 (payload "h\255llo", not valid UTF-8) the machine halted instead of yielding manually with the accepted or the rejected reason
  cause: `rollup --utf8-payload accept` received the input (its accept yield returned) and then failed to print it: nlohmann type_error.316 (invalid UTF-8), exit 1, empty stdout
[retry on failure] input 3 (payload "h\255llo"): accepted, 0 output(s) emitted
[retry on failure] input 4 (payload "bye"): accepted, 1 output(s) emitted
INFO: with retry, input 3 was ACCEPTED with no notice: the application never saw it
run.sh: R1-GUEST-2: exit 1 (bug present)
```

Exit status 1. The prover reported four runs with exit 1, and the reviewer re-ran it twice with exit 1. The test
exits 0 once the tool prints a request for such a payload (by escaping, replacement or a documented fallback
encoding), or once it ends that input at an accepted or rejected yield in some other defined way. No fallback model
was used. The candidate was found by a hunter (angle GUEST), proved by a prover and reviewed, all on Opus 5.5.

### Trigger and reachability

Any input sender can trigger it. Threat model section 4: "input senders (any bytes, any count)". The sender sends
an advance-state input whose payload contains a byte sequence that is not valid UTF-8, such as `0xff`. The input
box ABI-encodes any payload, and a small payload fits in the rx buffer, so the delivery changes the state (R5). The
application only has to use `rollup --utf8-payload accept`, `reject` or `finish`. The manual's rolling calculator
`calc.sh` (doc/README.md) uses exactly these commands, and the PRT recipes run it. No special machine state is needed.
The input is the first one processed after any accepted or rejected yield.

### Rating

1. Out of scope: no exclusion covers it. "The stall of an application that halts ..." excludes what an application
   loses by halting on its own. Here an input makes guest software that section 3 puts in scope cause the halt.
   "An application that is not correctly designed, other than through a defect in guest software that section 3
   puts in scope" and "Guest software that an input can subvert, as long as R7 and R8 hold, other than the defects
   that section 3 puts in scope" both defer to section 3 (step 2). The trigger is an ordinary input. It needs no
   machine API call by an untrusted party, no snapshot and no violation of a deployment obligation.
2. Role: Guest software (AUDIT.md: "`machine-guest-tools` v0.18.1-test1 | Guest software"). Section 3, which
   covers this component: "A defect in them is in scope only where an application depends on them as documented,
   and would be correctly designed if they worked as documented. A defect that lets an input make such an
   application deviate from the rollup interface is Critical, as an R7 deviation in the rx buffer, the tx buffer and
   the yield interface. Any other defect in them is Low."
3. High and Medium cases: none fits. The listed High and Medium cases are about verifiers, path divergences,
   emulator crashes, honest-operator components, reproducible builds, version detection, constant-factor cost,
   support components, the machine API, hash integrity and persistence. None concerns guest software. Section 3
   gives guest software only Critical or Low.
4. Critical: the guest-software clause applies. The test's application uses only documented commands and options.
   `rollup --help`, quoted in the manual, says `finish` (and its shortcuts `accept` and `reject`) "print the next
   request to stdout", with "<data> contains arbitrary data in the selected payload encoding", and documents no
   failure after the request is received. If the tool worked as documented, the application would print, emit and
   accept every input. It would then meet section 2 ("After each input, it yields manually with the accepted or the
   rejected reason"), so it is correctly designed. A single input makes it halt instead, which is a deviation from
   the rollup interface. The obligation broken is section 2's correctly designed application, which section 3
   rates "as an R7 deviation in the rx buffer, the tx buffer and the yield interface". With retry-on-failure error
   handling, the consumed rx-buffer contents never reach the application before it accepts.

Two readings give different classes:

- **Reading A, Critical (preferred).** Using `--utf8-payload` in an application that receives inputs from anyone is
  documented use. The manual's own canonical rollup application, `calc.sh`, uses `rollup --utf8-payload
  accept/reject` on untrusted inputs, and the help text promises that `finish` prints the next request. The manual's
  sentence "Use the default 0x-prefixed hex or `--base64-payload` instead when payloads contain arbitrary binary
  data rather than text" is about the host encoder `cartesi-rollup-data.lua`, where the developer chooses the
  payloads. It does not tell an application to expect its tool to consume an input and print nothing.
- **Reading B, Low.** The option is documented as "encode/decode <data> fields in JSON values as UTF-8 text". A
  JSON string cannot carry invalid UTF-8, and the manual advises hex or base64 for arbitrary binary data. Under
  this reading, an application that selects a text-only encoding while senders can send any bytes is "outside its
  intended use" (section 8, Low: "a defect in guest software that only an application outside its intended use
  can reach"). Also, the manual's own `calc.sh` survives the input: when its loop fails, it calls `rollup reject`
  next, which rejects the consumed input.

Deciding facts: whether the guest `rollup` tool's documented contract for `--utf8-payload` covers advance-state
payloads that are not UTF-8 text (the help text says neither yes nor no), and whether an application may treat a
nonzero exit of `rollup accept` as fatal. Nothing in the tool's documentation says that a failure can follow a
completed yield. I prefer A because the manual presents `--utf8-payload` as the way to write the calculator, a rollup
application exposed to arbitrary senders, and because the defect is reached through the input, not through misuse by
the application.

### Possible solution and risks

Make the tool's output total in `--utf8-payload` mode. Options:

- (a) Dump with `nlohmann::json::error_handler_t::replace`. This is lossy: the application sees U+FFFD instead of the
  bytes, so two different payloads can look the same to it.
- (b) Fall back to a lossless, documented representation for non-UTF-8 payloads, such as hex with a flag field.
  Applications must handle the new shape.
- (c) Add a documented error path that reports, on stdout or through a distinct exit status, that the request was
  received but could not be encoded, so the application can still reject it.

Whatever the choice, document that any nonzero exit of `finish`, `accept` or `reject` after the yield means the
input was consumed. Apply the same review to the other places that print payload-derived JSON (`write_inspect_state`,
`gio`). The risks are behavioral changes for existing applications that parse the output. Option (a) may hide
attacker-controlled differences between payloads from the application.

### Risk of not fixing it

Any input sender can halt, with one non-UTF-8 byte, every application that uses `rollup --utf8-payload` and stops
when the tool fails. All later inputs are then lost and the outputs become unprovable (A5). An application that
retries instead accepts an input it never processed. Applications that, like `calc.sh`, carry on with `rollup
reject` only lose the input. Outside the code, the mitigation is to use the default hex or `--base64-payload`
encoding in the guest, or to treat every failure of `rollup accept/reject/finish` as "input consumed, reject it".

## R1-O1-2

**Title.** The unhashed `hash_tree.phtc_size` in a template's `config.json` survives the O1 rebuild, so whoever ships
the directory sets the memory the honest operator spends adopting it, without bound.

**Severity.** Critical (preferred reading). Low under the reading that the whole template directory, unhashed
configuration included, is trusted input (see Rating).

### Problem

The capacity of the page hash-tree cache, `hash_tree.phtc_size`, is read from the stored `config.json` of a machine
directory. It is not part of the hashed state: it does not change the root hash. Loading with
`clear_hash_tree = true`, the rebuild that O1 requires before an operator trusts the root hash of a template it did
not produce, clears the cache's contents but keeps its capacity. No runtime option can override the capacity. The
cache maps `phtc_size` entries of about 12 KiB each, and both its initialization and `clear()` write every entry.
The peak memory of adopting a template therefore grows linearly with a number that the template's distributor
chooses freely, independent of the machine's size. A sparse `hash_tree.phtc` of the matching length costs the
distributor no disk.

A distributor can thus ship a directory whose hashed contents form a valid template, and whose root hash after the
rebuild matches the on-chain commitment, but which the honest operator cannot adopt on the host the deployment was
sized for. The load either fails with an error, as when a memory budget makes the mapping fail, or is killed when
it exhausts the host's memory. An operator that cannot obtain its valid template cannot defend the honest claim.
That is a completeness failure (section 1). The inflated value is also copied into every directory the operator
later stores or clones from that machine.

### Component, role and area

Emulator core: loading stored machines. AUDIT.md component table: "Interpreter, state-access layers, devices, uarch
program, hash tree, log producers, ..., input delivery, and storing, loading, cloning and syncing machines |
Honest operator". The area is the hash tree's page hash-tree cache, sized from the loaded configuration.

### Location

- `src/machine-config.cpp`, `machine_config::load` and `adjust_ht_backing_store_config`: the stored `hash_tree`
  configuration, `phtc_size` included, is taken from `config.json`. Only the filenames and the sharing mode are
  adjusted. `src/json-util.cpp:1784` reads `phtc_size` with no bound.
- `src/hash-tree.cpp:979` (`hash_tree::hash_tree`): builds `m_page_cache` with `config.phtc_size`.
- `src/page-hash-tree-cache.hpp:413-453` (constructor): maps `get_storage_length(num_entries)`, calls
  `m_map.reserve(num_entries)`, and initializes every entry and payload of an uninitialized file. The checks at
  461-472 refuse only zero and `ptrdiff_t` overflow. `clear()` at 597-604 writes every payload.
- `src/machine.cpp:326` (`machine::machine`): `clear_hash_tree` runs `clear_hash_tree()` on the cache as sized.
  Nothing resets or bounds the capacity.
- `src/machine.cpp:504-516, 566`: `store` and `clone_stored` write or clone a phtc of the same capacity.
- `src/machine-runtime-config.hpp`: no runtime field sets the cache capacity.

### Evidence and test

`bugs/R1-O1-2/` contains `test.lua` (the test), `child.lua` (adopts one directory in a child process and reports its
root hash, peak RSS `VmHWM`, CPU time and loaded `phtc_size`), and `README.md`. Run it with
`bugs/run.sh R1-O1-2`. `R1O12_BIG=<n>` changes the large capacity, which defaults to 65536.

The test copies the harness's stored `baremetal-template` machine as the control. That machine has 64 MiB of RAM,
waits at a manual yield with the accepted reason, was stored with the default `phtc_size` 4096, and covers 19403
pages. The test then makes copies that differ only in `config.json` `hash_tree.phtc_size` (16384 and 65536), each
with an empty sparse `hash_tree.phtc` of the exact length. The length formula is checked against the file the
emulator wrote. Each copy is adopted as O1 requires, by loading without sharing with `clear_hash_tree = true` and
then calling `get_root_hash()`. The test requires the root hash to be unchanged. It also requires the peak memory to
be no larger than the larger of 2x the control's and the control's plus a cache covering every page of the machine.
Output on audit/prt2, the same on two reviewer runs apart from a few kB:

```
machine covers 19403 pages (75.8 MiB)
control: phtc_size=4096   VmHWM= 139732 kB cpu=0.28 s root=428a6bb8...ac75
crafted: phtc_size=16384  VmHWM= 287940 kB cpu=0.35 s root=428a6bb8...ac75  (2.06x control memory)
crafted: phtc_size=65536  VmHWM= 880080 kB cpu=0.77 s root=428a6bb8...ac75  (6.30x control memory)
marginal cost: 12.0 kB of peak resident memory per phtc entry (MID->BIG)
phtc_size survives clear_hash_tree: stored 65536 entries -> loaded 65536
allowed peak: 372568 kB (max of 2.0x control, control + 19403 pages x 12 KiB)
VIOLATED: R12 ... must cost at most 372568 kB of peak memory (bounded by the machine's size); observed 880080 kB, 6.30x the control's 139732 kB
run.sh: R1-O1-2: exit 1 (bug present)
```

Reviewer repair: the prover's limit was 2x the control alone. A fix that clamps the capacity to the machine's own
page count, about 323 MB here, would still have failed it. The limit now also allows the control plus 12 KiB per
page of the machine. The test still exits 1, with a 2.4x margin.

Two more reviewer checks, not part of the test:

- A machine created from a configuration with `hash_tree.phtc_size = 65536`, from the same template's config, is
  accepted. Its `store()` writes `"phtc_size":65536` and an 807 MB `hash_tree.phtc`. So a directory that the
  emulator itself writes, for a machine created from a configuration with no check disabled, carries the value.
- In a child under `prlimit --as=2GiB`, the control adopts normally (139 MB). The same contents with
  `phtc_size = 262144` fail to load, with `unable to map backing file '.../hash_tree.phtc' to memory: Cannot
  allocate memory`.

The trend is linear at about 12 kB per entry. By extrapolation, not run, about 2^20 entries (12 GB) exhaust this
16 GB host. Found, proved and reviewed on Opus 5.5. No fallback was used.

### Trigger and reachability

The trigger is whoever produces or relays the template directory the honest operator adopts. They set
`hash_tree.phtc_size` in `config.json`, either at creation or by editing it, and ship a `hash_tree.phtc` of the
matching length, which may be sparse. The honest operator triggers the cost on its own path by following O1: it
loads the directory with `clear_hash_tree` to rebuild the cached data and compare the root hash with the on-chain
commitment. Every load path reads the value. The hashed contents are a valid template. The root hash is the
committed one, and the test checks this against the stored `root-hash.txt`. No unreachable state is involved.

### Rating

1. Out of scope: not excluded. The snapshot exclusion covers "Defects triggered only by loading a snapshot that the
   emulator did not write and that does not meet the conditions of a valid template (section 4)". The contents here
   meet every condition: "created from a configuration, without disabling any of the emulator's consistency
   checks", and with the committed content hash "after rebuilding its cached hash-tree data (O1)". An
   emulator-written directory with the same value exists (above). The same entry continues: "Once a snapshot meets
   them, nothing it carries outside the hashed state may affect any transition (R1), crash the honest operator, or
   corrupt its memory." That covers this case. The O1 exclusion ("Defects that need the cached hash-tree data of a
   stored machine the operator did not produce to survive its adoption without a rebuild (O1)") does not apply. The
   operator performs the rebuild, and the capacity survives it. Section 5 adds: "A defect that defeats the rebuild
   itself ... is not excused by them."
2. Role: Honest operator. Section 3: "storing, loading, cloning and syncing machines (within the limits of O1 and O2)
   play this role in every deployment". The AUDIT.md row quoted above lists loading machines as Honest operator.
   The clause covers this component directly. The defect is on the honest operator's path, section 2: "Obtaining its
   valid template. For a template the operator did not produce, this includes rebuilding its cached hash-tree data
   (O1)."
3. High and Medium cases: none fits. The constant-factor case is "A defect that lets the guest, or host load that
   the deployment was sized for, multiply the worst-case cost of an operation listed in R12 by a constant factor".
   Here the trigger is neither the guest nor host load. The factor is not constant either: the distributor picks it
   freely, and the same entry says "When the sizing is unknown, rate ... a super-linear or unbounded one Critical."
   The cost does not arise only from unreachable states. No Medium case concerns loading on the operator's path.
4. Critical: violated on the honest operator's path. Section 8, Out of scope (snapshots): "nothing it carries outside
   the hashed state may ... crash the honest operator". The adoption fails, or exhausts the host's memory, from an
   unhashed value. R12: "storing, loading, cloning or syncing a machine" has a worst case "bounded and at most
   linear in the cycles it executes or the bytes it covers". The cost is set by `phtc_size`, not by the machine's
   contents. R4/section 1: an operator that cannot adopt its valid template "cannot respond in time". Section 8:
   "violating any rule or obligation ... anywhere on the honest operator's path, is critical."

Second reading, Low: section 4 lists "the valid template it chose to defend" as trusted and says "Snapshots are
trusted input". `phtc_size` is a documented configuration field (manual, "Fields `hash_tree.phtc_size` ... control
the *page hash-tree cache*"), plain in `config.json`. On that reading, choosing or accepting a huge value is a
trusted party's configuration choice that the deployment sizes for: "a failure that needs misuse of an API by its
trusted caller" (Low). Two facts would decide, and the text points to the first reading. First, whether the
section 8 sentence about what a snapshot "carries outside the hashed state" covers unhashed configuration values as
well as cached hashes. Second, whether "the bytes it covers" in R12 means the machine's state, or also the logical
length of a stored cache file. Taken literally, the second meaning would make even a sparse file count.

### Possible solution and risks

Do not take the cache capacity from the stored directory when it is adopted. Under `clear_hash_tree`, the file is
being rebuilt anyway. Either reset the capacity to the default or to a new runtime option, recreating
`hash_tree.phtc` at that length, or clamp it to the number of pages that the machine's address ranges cover.
Optionally also refuse, at creation and on load, a `phtc_size` above that page count.

Risks: the phtc file layout depends on the capacity, so a shared load must resize or recreate the file before
mapping it. Directories stored afterwards get a different `hash_tree.phtc` length, and tools that check that length
must follow. Operators that deliberately use a large cache for speed would need the runtime option. The root hash
must stay unaffected, because the cache is only a cache. The test checks this.

### Risk of not fixing it

Anyone who distributes or relays a template, for example an application's published snapshot or a mirror of it, can
make every honest operator that adopts it as O1 prescribes fail to load it. They can also make the load consume all
of the host's memory, while the directory's root hash still matches the on-chain commitment. The emulator offers no
documented setting against this. An operator can mitigate it outside the code. It can inspect `config.json` and
reset `hash_tree.phtc_size`, recreating `hash_tree.phtc` at the matching length, before loading. It can also build
the template itself from its configuration, or load under a memory limit and treat a failure as a sabotaged
directory.

## R1-O2-3

**Title.** A failed `collect_mcycle_root_hashes` loses the dirty marks it holds only in its context, so the hash tree, later root hashes and stored snapshots no longer match the machine's contents

**Severity.** Critical (preferred reading: a host fault turned into a wrong hash, which R9 covers for failed updates). Low under the alternative reading that an allocation failure is not a host fault the model covers.

### Problem

During `collect_mcycle_root_hashes`, the interpreter runs with `collect_mcycle_hashes_state_access`. That state
access records two kinds of writes only in a local `context.dirty_pages` set: memory writes that do not go through
the write TLB (`do_write_memory_word`, used for example by the page walk when it sets a PTE's A or D bit) and
writes to the shadow TLB (`do_write_tlb`). The collection copies those marks into the dirty page trees only after
`interpret_with_console` returns. The `try` around the call catches only `machine_console_exception`. Any other
exception thrown inside the interpreter, for example `std::bad_alloc` when `context.dirty_pages` grows past its
reservation of 4096 pages under a memory limit, unwinds and drops the set. The contents have changed, but the
affected pages are not marked dirty. Every later `update_hash_tree` skips them. The cached root hash, node hashes and
proofs then no longer match the contents. The caller gets an error and keeps the machine (Lua, C API, JSON-RPC
server). If it keeps using it, as R9 allows, every later root hash, computation hash and proof it produces from that
machine is wrong, which is a completeness failure of section 1 ("The honest operator computes a wrong hash"). A
snapshot stored afterwards carries the stale cached hash-tree data, and loading it gives the wrong root.

### Component, role and area

`collect_mcycle_root_hashes` and its state access `collect_mcycle_hashes_state_access`, with the hash tree's dirty
page tracking. AUDIT.md table: "Interpreter, state-access layers, devices, uarch program, hash tree, log producers,
`collect_mcycle_root_hashes` and `collect_uarch_cycle_root_hashes`, ... | Honest operator". Area: error handling of
the mcycle hash collection (dirty-page bookkeeping on an exception).

### Location

- `src/machine.cpp`, `machine::collect_mcycle_root_hashes`: `context` declared at line 2472. The `try`/`catch
  (const machine_console_exception &)` around `interpret_with_console` is at lines 2495-2510. The marking of
  `context.dirty_pages` into the dirty page trees, which runs only after a normal return, is at lines 2512-2517.
- `src/collect-mcycle-hashes-state-access.hpp`: `mark_dirty_word` (lines 77-83, inserts into `m_c.dirty_pages`),
  `do_write_memory_word` (lines 464-467), `do_write_tlb` (lines 497-501), `do_write_mcycle` (lines 147-158).
- `src/translate-virtual-address.hpp:77`: the page walk writes the PTE A/D update with `a.write_memory_word`, which
  does not use the write TLB.
- Reservation of the set: `src/machine.cpp:2482` (at most 4096 entries); growth beyond it allocates.

### Evidence and test

`bugs/R1-O2-3/` contains:

- `test.sh`: builds `fail-new.cpp` with `g++` into a temporary directory and runs `check.lua` under `LD_PRELOAD`.
- `fail-new.cpp`: a fault injector that replaces the global `operator new`. While an arm file exists, every request
  of at least 100000 bytes throws `std::bad_alloc`, as an allocator under a memory limit would. Inside the armed
  collection the only such request is the rehash of `context.dirty_pages` when it grows past 4096 pages.
- `guest.lua`: assembles a bare-metal guest (no toolchain needed). In M-mode it writes one Sv39 1 GiB identity leaf
  PTE with A=0 and D=0 at 0x80010010, sets `satp`, runs `sfence.vma` and enters S-mode. It spins, then stores to
  8000 distinct pages. The first store makes the page walk set the D bit, a write to the page-table page outside the
  write TLB.
- `check.lua`: runs a control (the same collection without a fault must leave `get_root_hash()` equal to the root
  rebuilt by `clear_hash_tree()`, else exit 2). It then runs the machine to mcycle 1000000, arms the injector, calls
  `collect_mcycle_root_hashes(start + 2^24, 24, 0, 0)` under `pcall`, requires that the failure was injected and
  that the D bit is now set (else exit 2), and asserts that `get_root_hash()` equals the rebuilt root and that
  `verify_hash_tree()` is true.
- `README.md`: description and expected output.

Run `bugs/run.sh R1-O2-3` (about 3 s). On audit/prt2 it exits 1 on every run (prover: 4 runs; reviewer: 2 more
runs, identical output):

```
control: no fault, cached root == rebuilt root 0xc458e981dcffb765bef61ae9f90223981ff6507f175d36f02f3fecd16c5ea93c
collect_mcycle_root_hashes failed as injected: std::bad_alloc
after the failure: mcycle=1000000 (started at 1000000), leaf PTE at 0x80010010 = 0x200000cf (D bit set)
page 0x80010000 (in RAM) is not marked dirty but is dirty
! FAILED!
get_root_hash() after the failure    0x53e7b6b510b05d7fe2b78bc0dedf3bbb3ace4d456b1c67094d871a82fef3ff3c
root rebuilt by clear_hash_tree()    0xd6fa527c0529e1b0090a3779c67a15912dc88233ce93697318df983de74a3713
verify_hash_tree() after the failure false
page-table page 0x80010000 node hash: cached 0x9240..., rebuilt 0xde53...
VIOLATED: R9: after collect_mcycle_root_hashes fails inside a running process (host allocation failure), ...
run.sh: R1-O2-3: exit 1 (bug present)
```

`verify_hash_tree()` names exactly the page-table page. The reviewer also checked, with a scratch variant of
`check.lua` that is not part of `bugs/R1-O2-3/`, that `m:store(dir)` after the failure writes a snapshot whose loaded
root hash is the stale 0x53e7... while the root rebuilt from its contents is 0xd6fa....

Side observation, not asserted: after the failure, `mcycle` keeps its starting value while other registers and
memory have advanced, because the interpreter writes `mcycle` only when it leaves its loop. That is a related
consequence of the same unhandled exception and is not covered by this test.

### Trigger and reachability

Two things are needed. First, during a collection period the guest makes a write that does not go through the write
TLB or refills the TLB. Any guest with paging does this all the time (PTE A/D updates on page walks, shadow TLB
refills), including the Linux guests of every template. Second, an exception other than a console error is thrown
inside the interpreter. On the honest operator's path this is a host allocation failure. The only allocation inside
the interpreter is the growth of `context.dirty_pages`, which happens when a period touches more than 4096 distinct
pages. A guest can do that with ordinary stores (the test touches 8000), within the linear cost of R12. Under
`RLIMIT_AS`, a container memory limit or a memory-capped host, that allocation can fail with `std::bad_alloc`. The
error reaches the caller (`cm_collect_mcycle_root_hashes` returns an error; the JSON-RPC server catches
`std::exception` and keeps serving the same machine), and a node that retries or keeps using the machine, or
stores it, computes from a hash tree that no longer matches the contents. No unreachable state is involved.

### Rating

1. Out of scope: not excluded. The relevant exclusion is "Host faults, such as a full disk, as long as the emulator
   does not turn them into a wrong hash, a wrong proof, or a directory that O2 guarantees but that later loads as a
   different state (section 4)". Here the emulator turns the fault into a wrong hash, so the exclusion does not
   apply. Section 4 says the same: "A host fault ... may stop the honest operator, but the emulator must never turn
   one into a wrong hash". No other exclusion applies: the machine was not loaded from a directory O2 does not
   guarantee, no untrusted party calls the API, and the API is used as documented (`cm.h` documents no state of the
   machine as unusable after an error).
2. Role: `collect_mcycle_root_hashes`, its state access and the hash tree are listed in the AUDIT.md table as
   "Honest operator". Section 3: "the computation-hash builders, the hash tree and its node proofs ... play this role
   in every deployment." The clause covers this component directly.
3. High and Medium cases: none fits. The only candidate is "A machine API operation off the honest operator's path
   that, used as documented, leaves the hash tree ... inconsistent with the machine's contents (R9)". It does not
   fit, because computing claims ("Computing claims" in the honest operator's path) is exactly what
   `collect_mcycle_root_hashes` does. No High case fits: the state is reachable, and no data from other parties is
   needed.
4. Critical: R9 is violated on the honest operator's path. "R9. Hash integrity. The content hash must equal the root
   of the actual contents. This applies to every cached, incremental, or persisted hash, after any sequence of
   documented operations. It includes interrupted or failed updates, and every snapshot the emulator itself writes."
   and "'Interrupted or failed updates' means updates that fail inside a running process, which then keeps using
   the machine." Section 8: "violating any rule or obligation at a reachable state, or anywhere on the honest
   operator's path, is critical."

Two readings. Critical (preferred): an allocation failure is a host resource fault like the full disk named in
section 4, and R9 explicitly covers a process that keeps using the machine after a failed update. Low: if an
allocation failure inside the interpreter is read as outside "host faults", or as impossible on a host provisioned
"on the resources the deployment was sized for", or if continuing after an API error counts as "misuse of an API by
its trusted caller". What would decide it: whether the model's host-fault clause covers memory exhaustion (the
text names "such as a full disk", which suggests resource exhaustion in general), and whether the manual documents
that a machine must be discarded after any failed call (it currently does not; R9's definition says the opposite).

### Possible solution and risks

Copy `context.dirty_pages` into the dirty page trees on every exit from the interpreter, normal or exceptional,
for example with a scope guard or a `catch (...)` that marks and rethrows, in `machine::collect_mcycle_root_hashes`
(and check `collect_uarch_cycle_root_hashes` and every other path that uses a context-only dirty set for the same
pattern). Alternatively, conservatively mark the whole affected address ranges dirty, or invalidate the hash tree,
when an exception escapes. The marking on the error path should not allocate, so that it cannot fail for the same reason.
The page whose insertion threw had not been written yet (`do_write_memory_word` marks before writing), so it needs no
mark. Separately, the interpreter should write `mcycle` back, or the machine should be declared unusable, when an
exception escapes, because otherwise the state itself is left in a combination no execution reaches. Risks: a
`catch (...)` must not swallow the exception or change the collection's results on success; a performance cost only
on the error path.

### Risk of not fixing it

A validator node whose host hits a memory limit during hash collection, and that retries or keeps the machine (for
example a long-running JSON-RPC machine server), silently computes wrong root hashes, computation hashes and
proofs from then on, and a snapshot it stores afterwards reloads with the wrong root. Its honest claim can then be
wrong or unprovable, and a dishonest claim can win. The guest can raise the chance by touching many pages per period,
but the fault itself comes from the host. Mitigation outside the code: treat any error from
`collect_mcycle_root_hashes` (other than a reported console error) as fatal for the machine, discard it and reload
from the last guaranteed snapshot, or call `clear_hash_tree()` (or verify with `verify_hash_tree()`) before using it
again.

## R1-R7-1

**Title.** The LR/SC reservation is keyed by virtual address and survives `satp` writes and `sfence.vma`, so after a remap an SC succeeds on a physical word in another 4 KiB page that the LR never reserved.

**Severity.** Critical (R7, "Atomics and fences" and "Address translation", read as written). Medium under a narrower reading. See Rating.

### Problem

`execute_LR` stores the **virtual** address of the access in `ilrsc`. `execute_SC` succeeds whenever
`ilrsc == vaddr`. Only three places write `ilrsc`: LR, SC (which always clears it) and `set_prv` (traps, `sret`,
`mret`). A `satp` write (`write_csr_satp`) and `sfence.vma` (`execute_SFENCE_VMA`) leave it unchanged. Take a hart
that runs `lr.d` at VA V (physical P1), then remaps V to P2 in another physical page without a trap or xRET (a
`csrw satp` or a store to the leaf PTE, then `sfence.vma`), then runs `sc.d` at V. The SC succeeds (rd = 0) and
writes P2.

The RISC-V specification forbids this:

- Privileged spec, Sv32 section, inherited by Sv39: "For implementations with both page-based virtual memory and the A
  standard extension, the LR/SC reservation set must lie completely within a single base physical page (i.e., a
  naturally aligned 4 KiB physical-memory region)."
- Unprivileged A/Zalrsc: "The SC must fail if the address is not within the reservation set of the most recent LR in
  program order". When an SC fails, it "does not write to memory, and it writes a nonzero value to rd".

P2 lies in a different physical page from P1, so it cannot be in the reservation set, and the SC must fail.

The manual (doc/README.md, "The main processor") says the main processor implements `RV64IMAFDCZicsr_Zifencei` with
Sv39. It describes `ilrsc` only as the register that "holds the reservation address for the LR/SC atomic memory
operations". It documents no deviation here. The behavior is deterministic and the same on every path: native
interpretation and the uarch reach the same root hash, and the regenerated step replays the uarch. So nothing breaks
in the dispute. The defect is an architectural deviation in an area that R7 lists ("Atomics and fences"; "Address
translation and memory permissions"). There, R7 says "any deviation lets an input subvert a correct guest, even a
deviation that is consistent across all paths". A guest that relies on the specified LR/SC semantics can complete a
read-modify-write on a word it never load-reserved.

### Component, role and area

The interpreter (main-processor A extension and Sv39 address translation). The uarch program compiles the same
`interpret.cpp`, and the regenerated machine-solidity-step implements the uarch, so all of them show the same
behavior. AUDIT.md table: "Interpreter, state-access layers, devices, uarch program, ... | Honest operator". The
regenerated step is "Referee verifier". It shows the deviation only because it faithfully implements the same state
transition function, not because its verification is unsound.

### Location

`src/interpret.cpp`:

- `execute_LR` (around line 1292): `a.write_ilrsc(vaddr)`.
- `execute_SC` (around line 1313): `if (a.read_ilrsc() == vaddr) { ...write_virtual_memory... }`.
- `set_prv` (around line 380): the only other place that clears `ilrsc`.
- `write_csr_satp` (around line 2233) and `execute_SFENCE_VMA` (around line 3574) do not touch `ilrsc`.

### Evidence and test

`bugs/R1-R7-1/` contains `test.lua` and `README.md`. Run it with `bugs/run.sh R1-R7-1`, which takes under a second.

The test builds a bare machine with 1 MiB of RAM, two Sv39 roots, and code at VA 0x5000. It runs in S-mode with
`mie = 0` and `mstatus.MIE = 0`. It checks that every program reaches its final `j .` at pc 0x5010, still in S-mode,
so no trap happened. P1 = 0x80020000 and P2 = 0x80021000 both start at 0x1111, and the SC stores 0x9999. Each case
runs twice: natively (`run`) and through the uarch (`run_uarch` plus `reset_uarch` per mcycle). The two runs must
reach equal root hashes, or the test exits 2. The cases are these.

- **Baseline.** `lr.d; nop; nop; sc.d` with no remap. It must succeed, or the test exits 2. The reviewer added this
  case.
- **Control, per variant.** The same program as the remap case, but the "remap" keeps VA 0x1000 on P1. The result
  must be consistent (success writes P1, failure writes nothing, P2 is untouched), or the test exits 2. The reviewer
  relaxed this check. The prover's version required success, but the spec allows that SC to fail, and the
  invalidate-on-remap fix makes it fail.
- **Remap, variant `satp`.** `lr.d x6,(x5); csrw satp,x7; sfence.vma; sc.d x9,x8,(x5)`. The new root maps VA 0x1000
  to P2.
- **Remap, variant `pte`.** The `csrw` is replaced by `sd x10,0(x11)`, which overwrites the leaf PTE of VA 0x1000
  through a mapping of the leaf table.

In both remap variants the test asserts that `x9 != 0`, that P1 is 0x1111 and that P2 is 0x1111. On audit/prt2 it
exits 1, deterministically: three runs by the prover and three by the reviewer gave the same result. It prints:

```
baseline (native)            pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
baseline (uarch)             pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
satp control (native)        pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
satp control (uarch)         pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
satp remap   (native)        pc=0x5010 prv=1 x9(sc rd)=0 P1=0x1111 P2=0x9999
satp remap   (uarch)         pc=0x5010 prv=1 x9(sc rd)=0 P1=0x1111 P2=0x9999
VIOLATED: satp: R7 (Atomics; Address translation): after LR at VA 0x1000 (P1) and a remap of VA 0x1000 to P2 in another 4 KiB physical page, the SC lies outside every legal reservation set and must fail (rd != 0) without writing memory
pte control (native)         pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
pte control (uarch)          pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
pte remap   (native)         pc=0x5010 prv=1 x9(sc rd)=0 P1=0x1111 P2=0x9999
pte remap   (uarch)          pc=0x5010 prv=1 x9(sc rd)=0 P1=0x1111 P2=0x9999
VIOLATED: pte: R7 (Atomics; Address translation): after LR at VA 0x1000 (P1) and a remap of VA 0x1000 to P2 in another 4 KiB physical page, the SC lies outside every legal reservation set and must fail (rd != 0) without writing memory
run.sh: R1-R7-1: exit 1 (bug present)
```

The test exits 0 under either fix below: keying the reservation by physical address, or invalidating it on `satp`
writes and `sfence.vma`. All agents ran on the primary model, with no fallback.

### Trigger and reachability

The guest triggers it. It needs code that runs, in S-mode (or in M-mode with `mstatus.MPRV`), an LR, a change of
translation for the reserved virtual address, and an SC to the same virtual address, with no trap and no xRET in
between. Every trap, `sret` and `mret` calls `set_prv` and clears the reservation.

The state is reachable. Section 4 says "Any input may take control of the firmware, the kernel, ... It may then run
any instruction stream at any privilege level", and section 2 says "Any assignment of guest-writable memory and
registers is presumed reachable". Page tables, `satp` (written through instruction semantics) and the code all lie
in guest-writable RAM and registers. The test sets them through the machine API only for brevity. A valid template
running an S-mode kernel can execute the same instruction sequence.

A user-mode program cannot trigger the remap without a trap. The exception is a U-mode store to a page table that
the kernel maps writable to it, which a correct kernel does not do.

### Rating

1. Out of scope: no. The trigger is guest instructions, not a machine API call. "The effect of a deliberate state
   change made through the machine API" does not apply: the test uses the API only to set up guest-writable state,
   which a guest can produce itself. "Guest software that an input can subvert, as long as R7 and R8 hold" does not
   apply either, because R7 itself does not hold. No snapshot, reload, host fault or deployment obligation is
   involved.
2. Role: the interpreter, plus the uarch program built from it. AUDIT.md: "Interpreter, ... uarch program, ... |
   Honest operator". Section 3: "The transition function, its log producers, ... play this role in every
   deployment." That clause covers this component. The regenerated step ("Referee verifier") shares the semantics
   but stays sound with respect to the state transition function as implemented, so the role does not raise the
   rating beyond what R7 gives.
3. High and Medium cases: no High case fits. The paths do not diverge (they agree), and the state is reachable. The
   candidate Medium case is "An undocumented deterministic deviation, consistent across all paths, in behavior that
   no correct guest relies on for isolation or data integrity (R7)". The deviation is undocumented, deterministic and
   consistent across paths. But R7 says "A correct guest relies on the architecture for isolation and data integrity
   in the areas listed below. In these areas, any deviation lets an input subvert a correct guest, even a deviation
   that is consistent across all paths", and lists "Address translation and memory permissions" and "Atomics and
   fences". LR/SC reservation semantics under address translation fall in both areas. So under the text as written,
   the Medium case, which covers behavior "no correct guest relies on", does not fit.
4. Critical: this violates R7 at a reachable state. R7 says "The emulator implements the RISC-V specification ...
   departing only where the manual documents a deviation", and the manual documents none for LR/SC. Section 8 says
   "violating any rule or obligation at a reachable state ... is critical". Under the reading in steps 3 and 4,
   **Critical**.

**Second reading: Medium.** The Medium case can instead be read as a question of fact about this particular
behavior. On that reading it fits, and the rating is **Medium**, if no correct guest actually relies on an SC failing
after a remap made between its own LR and SC with no trap. The facts for this reading:

- Every trap and xRET already clears the reservation. So a user-mode victim is never exposed through a kernel remap,
  and preemption also clears it.
- Only S-mode or M-mode code that remaps between its own LR and SC sees the deviation.
- The Zalrsc text recommends that software invalidate reservations with a scratch SC "if necessary when changing
  virtual to physical address mappings". Linux follows that advice on exception return.

That reading would settle on Medium if one could show that no supported guest software (kernel, OpenSBI or bare-metal
runtime) remaps inside an LR/SC window. The categorical wording of R7 ("any deviation ... even a deviation that is
consistent across all paths"), which answers exactly the Medium case's argument, supports the first reading better.
Both readings rate it Medium or above.

### Possible solution and risks

There are two options.

- **Clear `ilrsc` on every `satp` write and every `sfence.vma`** (in `write_csr_satp` and `execute_SFENCE_VMA`). This
  is the smaller change. The spec allows an SC to fail at any time outside the constrained LR/SC loop, and SYSTEM
  instructions and stores end that loop, so this fix never breaks forward progress. It does not cover a remap by a
  plain store to a PTE that is still cached in the TLB with no `sfence.vma`. That case is fine: the stale translation
  is architectural, the SC then still goes to P1, and that is allowed.
- **Store the physical address of the LR access in `ilrsc`, and compare it with the translated physical address in
  SC.** This follows the spec directly. It needs a translation before the comparison, and it changes the state
  accesses that SC logs.

Either fix changes the state transition function, and so the uarch program, its pristine hash, the regenerated step
and the logged accesses (R13). It needs a new protocol version and a new `marchid`. It must not be mixed with
deployed versions (A6).

### Risk of not fixing it

The dispute game itself is not exposed: every path computes the same (non-compliant) successor, so claims, proofs
and verification still agree. The exposure is a correct guest that relies on the specified atomics under address
translation. It can see an SC succeed on a word that was never load-reserved, and silently corrupt that word's
read-modify-write. Only code running in S-mode or M-mode that changes the mapping between its own LR and SC can
trigger it. Guest software can mitigate it by issuing an SC to a scratch word after every remap, as the spec
recommends.

## R1-R10-1

**Title.** The uarch-step verifiers (the regenerated machine-solidity-step and the C++ replay) accept uarch stores to
the PMA array, the shadow TLB, HTIF and `uarch_x0`. The native uarch refuses these stores as uarch traps.

**Severity.** High

### Problem

The native uarch refuses a uarch store (`sd`/`sw`/`sh`/`sb`) whose physical address falls in a range that the uarch
may not write. Examples are the PMA array, the shadow TLB, HTIF MMIO, read-only or unknown shadow slots, and the uarch
`x0` shadow word. `log_step_uarch` throws for such a store, so the step has no successor. In THREAT_MODEL.md that is a
uarch trap: "The uarch traps when it executes [...] an access that its memory map does not allow" (R3).

The uarch-step verifiers do not perform these checks. The regenerated machine-solidity-step implements a uarch store
as a plain word write in the Merkle tree. So does the C++ replay behind `machine::verify_step_uarch`. Both check only
that the logged address equals the computed address and that the Merkle proof matches. They then accept the log and
define a successor state in which the protected word has been overwritten.

The log authenticates the store address. `rs1` comes from a logged and authenticated register read, and the
immediate comes from the logged instruction word. The protocol constants fix the meaning of each of these addresses:
the board map in doc/README.md and the uarch shadow table. So the log "already authenticates the condition", and R3
requires the verifier to refuse it. Accepting it gives a successor to a state that the state transition function says
has none. It also makes the referee verifier disagree with the honest operator's log producer, which R2 forbids.

The defect does not break the goal of section 1 by itself. The before-states that trigger it need non-pristine uarch
registers or uarch RAM, which no valid template reaches (see reachability). What it removes is a margin. The referee
would accept a fabricated uarch step that overwrites the PMA entries, the shadow TLB or other protected state, if any
other defect ever made such a before-state agreed or reachable.

### Component, role and area

- `machine-solidity-step` v0.17.0-test1 regenerated from `audit/prt2`. AUDIT.md role: **Referee verifier**. Area:
  uarch-step verification of stores, in `UArchStep.sol` (`executeSD`/`SW`/`SH`/`SB` through `writeUint*`), which calls
  `EmulatorCompat.writeWord`, which calls `AccessLogs.writeWord`. Dave's `CartesiStateTransition` calls it and
  inherits the defect. Under section 3 that inheritance is rated by the copy's role.
- The C++ replay `uarch_replay_state_access` (`machine::verify_step_uarch`). Role: **Support**, under "Off-chain
  verifiers (the C, Lua and JSON-RPC verify functions)".
- Shared source: `src/uarch-step.cpp`, from which both are translated or compiled, has no memory-map check on stores
  (`writeUint64`/`32`/`16`/`8` call `writeWord`). The only native check is in `machine::write_word`, and the
  verifiers never execute it.

### Location

- `bugs/harness/work/solidity-step/step/src/EmulatorCompat.sol`, `writeWord` (line ~127).
- `bugs/harness/work/solidity-step/step/src/AccessLogs.sol`, `writeWord` (line ~146).
- `src/uarch-replay-state-access.hpp`: `do_write_word` (line ~358) and `check_write_word_access` (line ~259).
- For comparison, the native refusal: `src/machine.cpp`, `machine::write_word` (lines 2030-2075). It is reached
  through `src/uarch-state-access.hpp` `do_write_word` and `src/uarch-record-state-access.hpp` `do_write_word`.
- `src/uarch-step.cpp`, `writeUint64`/`writeUint32`/`writeUint16`/`writeUint8` (lines ~69-115).

### Evidence and test

`bugs/R1-R10-1/` contains `test.lua` (the test), `README.md` (what it asserts and the expected output) and this
entry. Run it with `bugs/run.sh R1-R10-1`. It takes about 3 s. It needs the in-tree emulator, the harness config
`baremetal-minimal`, foundry (`anvil`, `cast`), `jq`, and the StepVerifier artifact built by the shared EVM harness
(`bugs/harness/work/evm/out`).

For each case, the test loads `baremetal-minimal` and writes `sd rs2, imm(rs1)` at uarch RAM 0x600000. It sets
`uarch_pc` = 0x600000 and the source and base registers. It then checks that the native `log_step_uarch` refuses the
step. Next it hand-builds the step log in the access order of `src/uarch-step.cpp`, with every access carrying Merkle
proofs of the before-state. It requires both of these to reject that log:

- the regenerated `StepVerifier.step`. The test installs its runtime code with `anvil_setCode` on a private anvil, on
  a random port in 20000-29999, and stops that anvil at the end.
- `cartesi.machine:verify_step_uarch`.

A control store to uarch RAM 0x600100 must be accepted by the native uarch and by both verifiers, all with the same
after-hash. This validates the log crafting. If the control fails, the test exits 2.

On audit/prt2, the test exits 1 and prints:

```
control: uarch RAM 0x600100        native: ok | C++ verify: accepted (= native) | EVM step: accepted (= native)
PMA array (0x10000)                native: TRAP (attempted memory write to read-only PMAs at address 0x10000(65536))
                                     C++ verify_step_uarch: ACCEPTED, after-hash 7bff4949b4df...b2b8508397e
                                     EVM StepVerifier.step: ACCEPTED, after-hash 7bff4949b4df...b2b8508397e
shadow TLB (0x1000)                native: TRAP (attempted memory word write to protected memory range shadow state at )
                                     C++ verify_step_uarch: ACCEPTED, after-hash 700bad410769...87d5a190c8a
                                     EVM StepVerifier.step: ACCEPTED, after-hash 700bad410769...87d5a190c8a
HTIF tohost (0x40008000)           native: TRAP (attempted memory write to HTIF device at address 0x40008000(1073774592)
                                     C++ verify_step_uarch: ACCEPTED, after-hash 10be391cfc97...30ed40f84c7dbf
                                     EVM StepVerifier.step: ACCEPTED, after-hash 10be391cfc97...30ed40f84c7dbf
uarch x0 shadow word (0x400018)    native: TRAP (register is read-only)
                                     C++ verify_step_uarch: ACCEPTED, after-hash e852b4251bd0...cfe4693568ecbd
                                     EVM StepVerifier.step: ACCEPTED, after-hash e852b4251bd0...cfe4693568ecbd
VIOLATED: R3: a verifier refuses a uarch trap whenever its log already authenticates the condition (uarch stores to
fixed protocol addresses that the uarch memory map does not allow); 8 acceptance(s) of 8
run.sh: R1-R10-1: exit 1 (bug present)
```

(The hashes are abbreviated here. The test prints them in full.)

The reviewer re-ran the test three times with exit 1 and identical output. One more run during a host disk-full
episode exited 2 (harness error), which is unrelated to the defect. Once both verifiers refuse these stores, the
trap cases count 0 acceptances and the test exits 0. The test changes no audited code.

Other variants of the same root cause, not exercised by the test:

- The verifiers also accept stores that the native refuses to read-only shadow registers such as `mvendorid`,
  `marchid` and `mimpid`.
- They accept stores to unknown shadow slots, such as the revert-root-hash word.
- They accept stores to the sentinel above every range.
- They accept stores to gaps of the uarch-state node.

### Trigger and reachability

A dishonest claimant in a uarch-level match would need the verifier to start from a before-state whose uarch is about
to execute such a store. It would then submit a hand-built log, which "Logs and proofs are adversarial" (section 4)
allows.

No input sequence from any valid template produces such a before-state:

- Every mcycle starts from the pristine uarch. A valid template has "the uarch in its pristine reset state", and every
  mcycle ends with the uarch reset. So the uarch registers and uarch RAM at any reachable position are those that the
  pristine program produces from a reachable main state.
- The guest cannot alter the uarch state. R8 says "Guest memory accesses cannot address [...] the uarch state and
  uarch memory".
- The pristine program issues stores only through `uarch_bridge_state_access`:
  - shadow-register writes through `bridge_write_reg`;
  - TLB writes through the dedicated `write_tlb` ecall, which the verifiers check;
  - memory-word writes (`do_write_memory_word`), which the interpreter performs only after its PMA lookup has found a
    writable memory range.
- The PMA array, the shadow ranges and HTIF are not writable memory in the PMA entries. Those entries are fixed at
  creation and read-only to the guest (R8). HTIF writes are emulated by updating the `htif_*` shadow registers.
- Hence the pristine program never stores to these addresses from a reachable state.

If it ever did, the native uarch would trap from a reachable state. R3 calls that Critical, but it would be a separate
defect in the uarch program, not this one.

### Rating

1. Out of scope: no. The trigger is a crafted log that a dishonest claimant submits to a referee verifier. Section 4
   says "Logs and proofs are adversarial. A verifier must assume that every count, index, address, size, and hash it
   receives was chosen to fool it." No exclusion of section 8 applies:
   - It does not need an untrusted party to call the machine API. The test uses the API only to build the before-state
     and the proofs.
   - It does not need a deployment that violates one of A1 to A8.
   - It does not need a snapshot that the emulator did not write.
2. Role: the regenerated machine-solidity-step is a **Referee verifier** (AUDIT.md: "`machine-solidity-step`
   v0.17.0-test1, with its generated code and constants regenerated from `audit/prt2` | Referee verifier"). Section 3
   defines that role as "A verifier whose acceptance settles disputes, such as the on-chain verifiers". This clause
   covers the Solidity step. The C++ `verify_step_uarch` is Support ("Off-chain verifiers (the C, Lua and JSON-RPC
   verify functions) | Support"). It shares the defect, but the referee role is the most critical one, so it decides.
3. High and Medium cases: High. Section 8 High lists "A verifier that misbehaves only on demonstrably unreachable
   before-states. Misbehaving means [...] accepting a wrong or second after-hash (such as accepting a uarch trap, R3)."
   R3 requires "A verifier refuses a trap whenever the log it receives already authenticates the condition". Here the
   trap condition is decided by the store address, which comes from authenticated log data, together with protocol
   constants (R10: "A verifier may depend on the referee parameters, on the constants of its protocol version, and on
   the authenticated log data"). The before-states are unreachable for the reasons given above. Both clauses cover a
   referee verifier, which is this component's role.
4. Critical: not reached. Critical would require the pristine uarch to execute such a store from a reachable state,
   and none is known.

Two readings. Doc/README.md says "code running in the uarch has access to the entire state of the Cartesi Machine"
and "In addition to being able to access all memory ranges and devices visible to the main processor, the uarch
includes a private 2MiB of RAM". It does not define the uarch memory map precisely.

- Reading A, preferred: the native `machine::write_word` is the uarch memory map. Then these stores are uarch traps
  and the verifiers are wrong. The class is High, as a referee verifier, and the test asserts the right behavior.
  Supporting facts:
  - The manual calls the uarch shadow "read-only".
  - The uarch writes the TLB only through a dedicated ecall that the verifiers check.
  - The log producers refuse these stores.
  - R3 defines traps by what the uarch memory map allows.
- Reading B: if the manual meant that the uarch may store anywhere as a plain word write, the defect would sit in the
  native uarch and its log producers. They would then be refusing steps that the referee accepts. That is a divergence
  between paths (R2), and also High: "A divergence between paths only at demonstrably unreachable states", in the
  honest-operator role. Under B, a correct fix would make the native accept, and this test would keep failing.

Either reading gives High. The fact that would decide between them is the maintainers' statement of the uarch memory
map.

### Possible solution and risks

Make the verifiers check the store's address before accepting it.

- In `uarch_replay_state_access::do_write_word` and in the Solidity step (`EmulatorCompat.writeWord`, or the
  `writeUint*` helpers of the generated `UArchStep.sol`), refuse every address in a range that the native
  `machine::write_word` refuses. That covers:
  - the PMA array and the shadow TLB;
  - device ranges (CLINT, HTIF, PLIC);
  - unknown or read-only slots of the processor shadow and the uarch shadow, including `uarch_x0`;
  - addresses outside every range.
  Implement this as an allow-list of the writable shadow slots plus the uarch RAM, plus a deny-list of the
  fixed-layout ranges.
- Alternatively, move the check into `src/uarch-step.cpp`, for example as a `require` on the store address, so that
  the native, record, replay and generated Solidity paths share one definition.

Risks:

- The fix changes the accesses and the acceptance of the uarch-step verifier, which is part of the protocol (R13).
  It needs a new protocol version and consistent regeneration of the step (A6).
- The check must not refuse any store that the pristine uarch performs from a reachable state. Otherwise it would
  break R4 completeness. Examples to keep allowed:
  - writable shadow registers;
  - flash drives and other memory ranges whose addresses vary by configuration. For these the verifier cannot decide
    from constants alone, so the check should be limited to the fixed-layout ranges.
- Gas cost per store rises slightly.

### Risk of not fixing it

A deployed referee accepts a fabricated successor for uarch states that should have none. That successor can rewrite
the PMA entries, the shadow TLB, `uarch_x0` or other protected state. Today this is exploitable only from before-states
that no valid template reaches. The goal still holds, but a margin is gone. Any future defect that lets a dishonest
claimant get such a before-state agreed, or makes the pristine uarch reach one, would turn into an accepted wrong
transition. The trigger is any dishonest claimant in a uarch-level match. No mitigation outside the code is known,
other than keeping the before-state agreed as A1 requires.

## R1-R10-2

**Title.** Off-by-one in `Memory.validateStrideLength` makes the on-chain step verifier revert on any uarch access to
the last 32-byte leaf of the address space, which the native uarch, the log producer and the C++ verifier accept.

**Severity.** High

### Problem

`Memory.validateStrideLength` in machine-solidity-step checks `stride * s < MAX_STRIDE`, where
`MAX_STRIDE = MAX_SIZE - 1 = 2^59 - 1` and `s` is the region size in 32-byte leaves. The correct bound for a region
inside the 2^59-leaf tree is `stride * s + s <= 2^59`. Because `s` is a power of two and `2^59 - 1` is odd, the check
rejects exactly one region: the single leaf at stride `2^59 - 1`, bytes `0xffffffffffffffe0..0xffffffffffffffff`.
Every `readLeaf`, `writeLeaf`, `readWord` and `writeWord` of `AccessLogs` builds its region through
`Memory.regionFromStride`, so a uarch step whose log accesses that leaf reverts with `Panic(0x01)`.

The native uarch and the C++ verifier define a successor for such a step. A uarch load from an unmapped address in
the top leaf reads zeros and completes, and `verify_step_uarch` accepts the log with the native after-hash. The
on-chain verifier refuses the same log. This breaks R2: "Wherever two of the following reach the same position, they
must agree on its canonical hash. ... Every log producer and every log verifier. The on-chain verifiers." The address
of the access is a condition on the authenticated state, not on the log, so the revert also turns semantics into a
rejection (R3: "Conditions on the authenticated state or on the referee parameters are semantics. They define the
successor").

It does not break the goal of section 1. The pristine uarch never accesses the top leaf from a reachable state (see
"Trigger and reachability"), so the honest operator never needs a proof there. It removes a margin: the deployed
verifiers and the off-chain paths disagree on which states have a successor.

### Component, role and area

machine-solidity-step v0.17.0-test1, `src/Memory.sol` (unchanged in the released tag, in the step regenerated from
`audit/prt2`, and in Dave's `machine/step`, all byte-identical). It is reached through `AccessLogs.sol` and
`UArchStep.sol`, which Dave's `CartesiStateTransition` calls. AUDIT.md component table: "`machine-solidity-step`
v0.17.0-test1, with its generated code and constants regenerated from `audit/prt2` | Referee verifier". Area: memory
region validation of the access-log replay.

### Location

- `src/Memory.sol` of machine-solidity-step: `uint64 constant MAX_STRIDE = MAX_SIZE - 1;` (line 66) and
  `validateStrideLength` (lines 98-104, `assert(Stride.unwrap(stride) * s < MAX_STRIDE);`), called by
  `regionFromStride` (line 36).
- Callers: `src/AccessLogs.sol` (`readLeaf` line 83, `writeLeaf` line 110, `readWord` line 128, `writeWord` line
  154, and a write at line 216). Harness copies: `bugs/harness/work/solidity-step/{released,regenerated,regenerated-patched}/src/`
  and `bugs/harness/work/dave/{released,patched}/machine/step/src/Memory.sol`, md5 `cde00923a8c6954c1d4addc67d1f6ba1`
  for all.

### Evidence and test

`bugs/R1-R10-2/` contains `test.lua` and `README.md`. Run `bugs/run.sh R1-R10-2` (about 10 s). It needs the in-tree
emulator, the shared StepVerifier artifact `bugs/harness/work/evm/out/StepVerifier.sol/StepVerifier.json`, `anvil`,
`cast`, `jq` and `curl`. The test starts its own anvil on a random port in 30000-39999, installs the regenerated
`StepVerifier` runtime code with `anvil_setCode`, and kills that anvil at the end.

For each probe it builds a fresh machine (1 MiB RAM), writes one load instruction at `0x80000000` and sets `uarch_pc`
there. It then runs `m:log_step_uarch()`, `cartesi.machine:verify_step_uarch(before, log)`, and `StepVerifier.step`
on the EVM. It requires all three to give the native after-hash, or the native path to refuse the step. The control,
`ld x1,-40(x0)` at `0xffffffffffffffd8` (one leaf lower), must verify on all three paths, or the test exits 2. The
probes are `ld x1,-8(x0)` (address `0xfffffffffffffff8`) and `lw x1,-32(x0)` (address `0xffffffffffffffe0`). Stores
to the top leaf are not probed because the native uarch traps on them.

On audit/prt2 it prints, on each of two runs by the reviewer (exit 1 both times):

```
control ld x1,-40(x0) [0x..ffd8]   native/log producer: ok, after-hash 32bdd705...16df2f
                                   C++ verify_step_uarch: ACCEPTED, same after-hash
                                   EVM StepVerifier.step: ACCEPTED, same after-hash
ld x1,-8(x0)  [0xfffffffffffffff8] native/log producer: ok, after-hash af91d506...798d11
                                   C++ verify_step_uarch: ACCEPTED, same after-hash
                                   EVM StepVerifier.step: REVERTED: execution reverted: panic: assertion failed (0x01) data=0x4e487b71...01
    (revert is Panic(0x01): Memory.validateStrideLength assertion)
lw x1,-32(x0) [0xffffffffffffffe0] native/log producer: ok, after-hash e90de323...07cacb9
                                   C++ verify_step_uarch: ACCEPTED, same after-hash
                                   EVM StepVerifier.step: REVERTED: execution reverted: panic: assertion failed (0x01) data=0x4e487b71...01
    (revert is Panic(0x01): Memory.validateStrideLength assertion)
VIOLATED: R2: ... 2 divergence(s) of 2 probes
run.sh: R1-R10-2: exit 1 (bug present)
```

The test exits 0 after either fix: a Solidity bound that admits the top leaf, or a native uarch that traps on the
access. Found by the R10 hunter (duplicate R1-R3-2 merged), proved and reviewed on Opus 5.5. No fallback was used.

### Trigger and reachability

Trigger: a uarch step from a before-state whose uarch executes a load (or fetch) with its effective address in
`0xffffffffffffffe0..0xffffffffffffffff`. Any party could submit such a step to the referee, but only from a
before-state that the referee would accept (A1). The test builds that state through the machine API
(`write_reg("uarch_pc", 0x80000000)` plus a hand-written instruction).

Such a state is unreachable from any valid template:

- At every mcycle boundary of a reachable state the uarch is pristine (valid template; the closing reset), and the
  guest cannot address the uarch state or uarch RAM (R8; the uarch ranges are registered with `pmas = false`). So
  the uarch registers, its pc included, follow the pristine program, which is fixed code in uarch RAM.
- The pristine program addresses only fixed regions: its own RAM (`0x600000..0x800000`), the uarch shadow
  (`0x400000`), the processor shadow registers (`0x0..0x1000`), the shadow TLB (`0x1000..0x7000`) and the PMA array
  (`0x10000..0x11000`). It addresses main-processor memory only through `read/write_memory_word` after `find_pma`
  matched a PMA, or through a TLB hit. On every hit, `uarch-bridge-state-access.hpp`'s `do_verify_cold_tlb_slot` runs
  `shadow_tlb_verify_slot`, which requires the physical page to lie inside the slot's memory PMA
  (`interpret.cpp:1081`, `1197`, `5646`).
- `machine_address_ranges::check` refuses any range whose start or end exceeds `AR_ADDRESSABLE_MASK` ("must use at
  most 56 bits to be addressable"). So no PMA, and no reachable TLB entry, reaches the top leaf.
- A main-processor access to `0xfff...f8` matches no PMA, so it raises an access fault without reading memory.

Hence no input sequence from any valid template makes the uarch touch the top leaf, and the honest operator never
needs to prove such a step.

### Rating

1. Out of scope: no. The trigger is a before-state, not a deliberate state change whose effect is at issue ("The
   effect of a deliberate state change made through the machine API" excludes what the change does to the machine,
   not a verifier's disagreement on the resulting state; R10 requires verifiers to be safe "on every before-state").
   The defect needs no untrusted call to the machine API, no deployment violation of A1 to A8, no snapshot the
   emulator did not write, and no reload that O2 does not guarantee.
2. Role: the component is `machine-solidity-step` `Memory.sol`, whose AUDIT.md role is "Referee verifier". Section 3
   defines it as "A verifier whose acceptance settles disputes, such as the on-chain verifiers". That clause covers
   this component directly. Dave's `CartesiStateTransition` (Referee model) only inherits it from this copy:
   "A defect it only inherits from a copy of a verifier that it calls is rated by that copy's role".
3. High and Medium cases: High, "A divergence between paths only at demonstrably unreachable states." The native
   uarch and log producer, the C++ log verifier and the on-chain verifier are all paths that R2 lists ("Every log
   producer and every log verifier. The on-chain verifiers."). At this state the first three agree on an after-hash
   and the on-chain verifier refuses to produce one. The state is demonstrably unreachable (argument above).
4. Critical: not applicable. No reachable state or step on the honest operator's path triggers it, so R4 ("From any
   reachable state ... log the transition so that it verifies") and R2 at reachable states hold.

Second reading: the first High bullet defines a verifier's misbehaviour as "being nondeterministic, accepting a wrong
or second after-hash ..., not being memory-safe, or being unbounded", which does not list rejecting a log. R3 also
says "R4 asks for proofs only from reachable states, so refusing a trap from an unreachable state never breaks it."
If refusing a valid log at an unreachable state were not a divergence between paths, the defect would violate no
rule and be Low. This review prefers High. The divergence bullet is separate from the misbehaviour list and is not
limited by it. The R3 sentence covers refusing a uarch trap, but here the native uarch does not trap: it defines a
successor. The deciding facts would be whether the threat model counts one path rejecting where another defines a
successor as a divergence, and whether the manual meant the uarch memory map to allow reads of unmapped addresses.

### Possible solution and risks

Fix the bound in `validateStrideLength`, for example `assert(uint256(Stride.unwrap(stride)) * s + s <= MAX_SIZE);`.
For an aligned region this equals `stride * s < MAX_SIZE`. Widening to `uint256` keeps an oversized stride from a
crafted log from reverting with an arithmetic panic instead of the assertion. This changes deployed verifier code,
so it needs a new step release and a Dave rebuild. It changes no transition at a reachable state. Risk: low. It
admits exactly one more region, the top leaf. The proof replay for that leaf (index `2^59 - 1`) was not exercised
past the assertion in this review, so the fix needs a replay test that reads the top leaf and checks the native
after-hash.

Another option is to make the native uarch and the C++ verifier trap on any uarch access outside the declared ranges.
That would also restore agreement, but it changes the off-chain transition function and is more invasive.

### Risk of not fixing it

No current exposure. The pristine uarch never reaches the top leaf from a reachable state, so neither the honest
operator nor an adversary can use the divergence against a deployment. What remains is a lost margin: the on-chain
verifier and the off-chain implementations disagree at some before-states. A future uarch change, a new PMA layout
near the top of the address space, or a relaxed 56-bit limit would turn it into a completeness failure (Critical by
R4) without any change to the Solidity code. Keeping the 56-bit address-range limit and the TLB slot verification
keeps it unreachable.

## R1-R12-2

**Title.** In the uarch program every TLB flush issues its 768 `write_tlb` ecalls through a non-inlined 14-instruction
wrapper, so a flush costs 17,492 uarch cycles (22 per slot) where about 3 to 4 per slot would do, even with a full TLB.

**Severity.** High (under the reading preferred here; Low under the alternative reading given at the end of Rating).

### Problem

A full TLB flush happens on `sfence.vma`, on every `satp` write and on every privilege change (`set_prv`, so on every
trap, interrupt and xRET). The interpreter writes all 768 slots (3 sets of 256), and in the uarch program each slot
write is a call to `ua_write_tlb_ECALL`. That function is compiled out of line (no LTO, separate translation unit) into
14 instructions: 5 moves of the arguments into temporaries, 2 instructions to load the ecall number, 5 moves back into
`a0`-`a4`, `ecall` and `ret`. The calling loop adds 8 instructions per slot, which rematerialize constants that do not
change between slots. A flush therefore costs 22 uarch cycles per slot, 17,492 uarch cycles per flush mcycle, against
629 for an `addi` that misses the code TLB. The cost is the same whatever the TLB holds.

With all 768 slots valid, the semantics do require 768 slot writes, and in the uarch the only way to write a slot is a
`write_tlb` ecall. Issued from an inlined loop (slot index, `ecall`, increment, branch, the other arguments kept in
registers), they need about 3 to 4 uarch cycles each, so about 2,300 to 3,100 uarch cycles plus the control's 629.
The out-of-line wrapper thus multiplies the worst-case uarch cost of a flushing mcycle by about 5 to 6. Flushing
mcycles are the most expensive mcycles in uarch cycles: 768 slot writes dwarf a page walk or a trap entry. A guest can
execute them back to back, for example across the 2^10 mcycles that one uarch-level claim spans (doc/README.md: a uarch
period is "at most 2^10" mcycle bundles of 2^20 uarch transitions). The honest operator executes and hashes every one
of those uarch cycles to build the uarch-level claim, and R12 bounds that work only "per run" for fixed-point
repetitions, not for executed cycles. So the defect multiplies the worst-case cost of an mcycle executed by the uarch
and of a uarch-level claim by a constant factor that the semantics do not require.

It does not break the goal by itself. It removes margin from the dispute clocks that A7 sizes "at the worst-case costs
of R12".

The other half of the original claim, that already invalid slots are rewritten, only affects the average case: with a
full TLB nothing can be skipped, and a check per slot would make the worst case slightly more expensive. Section 8 puts
"Average-case performance that does not change the worst-case cost of any operation listed in R12" out of scope, so
this entry does not count it as a defect, and the test does not assert it.

### Component, role and area

The uarch program, in its TLB-flush path: the interpreter's `flush_tlb_slot`, `flush_tlb_set` and `flush_all_tlb` as
compiled into the uarch, and the uarch bridge's `do_write_tlb` with `ua_write_tlb_ECALL`. AUDIT.md's components table
gives "Interpreter, state-access layers, devices, uarch program, ... `collect_uarch_cycle_root_hashes` ..." the role
"Honest operator". The native interpreter flushes the same way, but natively the per-slot cost is small and writing
the slots of a full TLB is required, so the native path is not affected in its worst case.

### Location

- `src/interpret.cpp`: `set_prv` (about line 380, calls `flush_all_tlb`), `flush_tlb_slot`, `flush_tlb_set`,
  `flush_all_tlb`, `flush_tlb_vaddr` (lines 885-937), and the callers at lines 500, 2279, 2341, 2858, 3592 and 3607
  (`satp`/`mstatus` writes, `sfence.vma`).
- `uarch/uarch-bridge-state-access.hpp`: `do_write_tlb` (line 190) calls `ua_write_tlb_ECALL`.
- `uarch/uarch-ecall.c`: `ua_write_tlb_ECALL` (lines 44-59), an out-of-line function whose `asm` moves each `"r"`
  operand into the clobbered argument registers.
- `uarch/uarch-ram.elf.objdump`: `ua_write_tlb_ECALL` at 0x600b90-0x600bc4 (14 instructions) and the flush loop body
  at 0x602430-0x60244c (8 instructions, `jal ra,600b90`), repeated for each of the three sets.

### Evidence and test

`bugs/R1-R12-2/` contains `test.lua` and `README.md`. The test builds two bare-metal guests from RISC-V encodings in
Lua, so it needs no toolchain and only the in-tree emulator build. Run `bugs/run.sh R1-R12-2`. It takes about one
second.

1. The decisive part, the worst case. Pages 0..254 each start with `j next page` (256 code slots). Page 255 loads
   from pages 256..511 and stores to pages 512..767 (256 read and 256 write slots), then runs `sfence.vma x0, x0;
   addi; j .`. The test checks that all 768 shadow-TLB slots are valid before the `sfence.vma`. It runs that mcycle
   and the following `addi` with the pristine uarch program (`run_uarch` to halt, then `reset_uarch`). Uarch cycle
   counts are exact, with no timing involved. It asserts `(sfence cycles - addi cycles) / 768 <= 8`, about twice
   what an inlined ecall loop needs.
2. A diagnostic, not asserted. A guest alternates `sfence.vma` and `addi` with an almost empty TLB. The test
   single-steps one flush and counts its `write_tlb` ecalls.

On audit/prt2 it prints the following and exits 1 (deterministic, two runs identical):

```
full TLB: 768 of 768 slots valid before sfence.vma, 0 after; sfence.vma 17492 uarch cycles, following addi 629
almost empty TLB (diagnostic): 1 slots valid before, 768 write_tlb ecalls, 767 of them to slots already invalid, 17492 uarch cycles
full-TLB flush cost over the control: 21.96 uarch cycles per slot (bound 8)
VIOLATED: R12 / section 8 High: flushing a full TLB costs 21.96 uarch cycles per slot (more than 8) beyond an addi; ...
run.sh: R1-R12-2: exit 1 (bug present)
```

The prover's test asserted only the almost-empty case, which a fix that skips invalid slots would pass while leaving
the worst case unchanged. The reviewer revised it so that the full-TLB worst case decides. That case fails for the
same reason, 21.96 uarch cycles per slot. In a manual measurement (not part of the test, timings noisy on a shared
host), running the full-TLB flush mcycle one uarch cycle at a time with a root hash after each, as
`collect_uarch_cycle_root_hashes` does, took about 5.8 s of host CPU, against about 0.01 s for an ordinary mcycle with
an empty TLB. Each extra uarch cycle costs a full step and a hash update. Found, proved and reviewed with
`claude-opus-5-5`; no fallback model was used.

### Trigger and reachability

Any guest code, at any privilege level, after it reads an input: `sfence.vma`, a `satp` write, or any trap or xRET
(even a U-mode `ecall` pays two flushes). The section 4 adversary "may then run any instruction stream at any
privilege level". The state is reachable, because the flush costs the same from every state. The worst case, a full
TLB, takes only touching 768 suitably spaced pages, which the test's guest does from a configuration-created machine.
An adversary steers a dispute to such an mcycle, or fills a uarch period with such mcycles, and forces the honest
operator to compute uarch-level claims over them (section 7: "Steer the dispute to any position of the honest
computation").

### Rating

1. Out of scope: no. "Average-case performance that does not change the worst-case cost of any operation listed in
   R12" does not apply, because the wrapper overhead is paid in the worst case (full TLB, flush every mcycle), as
   the test shows. It does apply to the "rewrites already invalid slots" part, which this entry therefore does not
   count. No other exclusion fits. The trigger is ordinary guest execution from a valid template, with no API misuse,
   snapshot, O1/O2 or A1-A8 violation.
2. Role: the uarch program, which AUDIT.md's table puts under "Honest operator". Section 3: "The transition function,
   its log producers, the computation-hash builders ... play this role in every deployment." That clause covers this
   component directly.
3. High and Medium cases: the section 8 High case applies: "A defect that lets the guest, or host load that the
   deployment was sized for, multiply the worst-case cost of an operation listed in R12 by a constant factor,
   compared with the same operation without the defect, while staying within what the deployment was sized for. A
   cost that the specified semantics require is not a defect. When the sizing is unknown, rate such a
   constant-factor increase High." The operations are "an mcycle" (as executed by the uarch) and "a uarch-level
   claim" (R12). The factor is about 5 to 6 on a flushing mcycle, and on a uarch-level claim whose mcycles all flush.
   It is constant, because it is bounded by 768 slots per flush, and it stays far below the uarch cycle limit per
   mcycle (2^20 - 1). The 768 ecalls are required. The 21 extra instructions per ecall are not required by any
   semantics. The clause covers this component, because it speaks of any defect that multiplies an R12 operation's
   worst-case cost. The sizing is unknown, so the class is High.
4. Critical: not reached. It does not make any R12 operation unbounded, super-linear or larger than sizing.

The two readings differ in what counts as "a defect". The reading preferred here takes the clause's only stated
exception, "A cost that the specified semantics require is not a defect", as the test. On that reading, avoidable
per-slot overhead on the dominant worst-case path is a defect, and the class is High. An alternative reading holds
that "defect" means a mistake in logic, such as redundant or repeated work, and not code-generation efficiency of a
correct implementation; the comment in `flush_tlb_slot` records that writing every slot is deliberate. On that
reading this is a performance improvement, Low or not a defect. Two facts favor the first reading. The excess is
literally redundant work: 10 register moves that undo each other, plus constants rematerialized for every slot. And it
sits on the worst-case path, not spread over every instruction. What would decide it is whether the maintainers treat
the uarch cycle cost of the worst-case mcycle as a sized quantity under A7.

### Possible solution and risks

Make the uarch ecall wrappers `static inline` in `uarch-ecall.h`, binding the operands directly to `a0`-`a4`/`a7` with
register variables (`register uint64_t a0 asm("a0") = ...`) instead of `mv` from `"r"` operands, or enable LTO for the
uarch build. Optionally flush the write set first, and hoist loop-invariant arguments. The flush loop then costs about 3
to 4 uarch cycles per slot. Skipping already invalid slots is not needed for the worst case, and it would add a load
and a compare per slot.

Risks: any change to the uarch program changes its pristine hash, the uarch trajectory of every mcycle, and the
accesses each logged transition makes. That makes it a new protocol version (R13, A6). The regenerated
`machine-solidity-step` constants and the on-chain pristine hash must be updated together, and the new uarch must be
rebuilt reproducibly. Register-variable asm must keep the ecall's clobbers exact. Otherwise the compiler may assume an
argument register survives the ecall, which would be a uarch-versus-native divergence (R2) that the existing
differential tests should catch.

### Risk of not fixing it

Any input sender who takes control of the guest can make every mcycle of a dispute region cost about 17,500 uarch
cycles instead of about 3,000, and so make each uarch-level claim the honest operator must compute over such a region
about 5 to 6 times as expensive. The same holds for every proof of a uarch step there. That consumes margin in the
clocks that A7 sizes. If a deployment sized its uarch-level clocks without measuring flush-heavy mcycles, this factor
moves it toward the Critical case "larger than what the deployment was sized for". Outside the code, the mitigation is
to size the uarch-level clocks for the measured worst case: a period of 2^10 mcycles that each flush a full TLB.

## R1-R13-1

**Title.** The on-chain step verifier cannot be rebuilt from audited source. Regenerating machine-solidity-step
v0.17.0-test1 from audit/prt2 produces a `UArchStep.sol` that uses `TLB_NUM_SETS`, which nothing declares, so the
build fails.

**Severity.** High (preferred reading). Critical under the reading that a deployment must ship hand-edited verifier
code (see Rating).

### Problem

Commit afd5f9d ("fix: refuse out-of-range TLB indices in the uarch WRITE_TLB ecall") added this check to
`executeECALL` in `src/uarch-step.cpp`:

```cpp
if (set_index >= TLB_NUM_SETS || slot_index >= TLB_SET_SIZE) {
```

The commit message says "UArchStep.sol picks up the check when it is regenerated". It does not.

- The pinned translator `helper_scripts/generate_UArchStep.sh` adds the `EmulatorConstants.` prefix only to names
  that `src/EmulatorConstants.sol` defines (lines 40 and 60).
- `EmulatorConstants.sol` is built from `templates/EmulatorConstants.sol.template` and
  `helper_scripts/generate_EmulatorConstants.lua`. Neither one defines `TLB_NUM_SETS`. The template hand-codes
  `TLB_SET_SIZE = 256` and `TLB_SLOT_LENGTH = 32`.
- So the regenerated `src/UArchStep.sol:1090` keeps the bare identifier `TLB_NUM_SETS`, and solc 0.8.30 stops with
  `Error (7576): Undeclared identifier`.

The result is that the referee verifier for this emulator version cannot be built from audited source with the
pinned generator, in any order of the project's `generate-*` targets.

- To deploy it, someone has to edit the generated code or the template by hand, outside any audited source. The
  shared harness does this with `bugs/harness/solidity-step/patches/01-tlb-num-sets.sh`, which adds
  `uint64 constant TLB_NUM_SETS = 3;`.
- The only other buildable code is the released v0.17.0-test1 `UArchStep.sol`. It implements a different state
  transition function: `CM_MARCHID` 22 instead of 23, a different `UARCH_PRISTINE_STATE_HASH`, no TLB index check,
  and the old halt/overflow precedence. Deploying it would mix versions, against A6.

This breaks R13: "The uarch program, its pristine hash, and the verifier code that a deployment fixes on-chain must
be reproducibly buildable from audited source." It also removes the margin that A6 relies on, because the one
verifier that matches the emulator exists only as an unaudited hand edit.

### Component, role and area

- **Component.** machine-solidity-step v0.17.0-test1 regenerated from audit/prt2, meaning its generator, templates
  and the generated `UArchStep.sol` and `EmulatorConstants.sol`. AUDIT.md assigns it this role: "`machine-solidity-step`
  v0.17.0-test1, with its generated code and constants regenerated from `audit/prt2` | Referee verifier".
- **Root cause.** The uarch step source of the emulator, `src/uarch-step.cpp`. In the AUDIT.md table, "uarch program"
  is Honest operator. This source is also the input of the verifier generator.
- **Area.** Generating the on-chain step from C++, and the constants that the generated code uses.

### Location

- `src/uarch-step.cpp:890`, `executeECALL`, the `UARCH_ECALL_FN_WRITE_TLB` case. The constant itself is defined in
  `src/shadow-tlb.hpp:34` and exported as `CM_TLB_NUM_SETS` (`src/cm.h:106`) and `cartesi.TLB_NUM_SETS`
  (`src/clua-cartesi.cpp:337`).
- machine-solidity-step v0.17.0-test1 (pinned checkout `bugs/harness/work/solidity-step/released`):
  - `helper_scripts/generate_UArchStep.sh:40,60`: the list of constants that get the prefix.
  - `templates/EmulatorConstants.sol.template:28-30`: hand-coded TLB constants, with no `TLB_NUM_SETS`.
  - `helper_scripts/generate_EmulatorConstants.lua`: does not emit `TLB_NUM_SETS`.
  - `Makefile:53`: `build: generate-step generate-reset generate-send-cmio-response generate-constants generate-prod`
    followed by `forge build`.
- Regenerated output: `src/UArchStep.sol:1090`.

### Evidence and test

`bugs/R1-R13-1/` contains `test.sh` and `README.md`. Run the test with `bugs/run.sh R1-R13-1`. It takes about 1 s.
`MSS_DIR=<checkout> bugs/run.sh R1-R13-1` tests a candidate fix of the generator.

The test does the following, in a temporary directory, and modifies nothing shared:

1. It copies the untouched pinned checkout.
2. It runs `make generate-constants generate-step generate-reset generate-send-cmio-response generate-prod` with
   `EMULATOR_DIR` pointing at this repository's `src/`.
   - A `docker` shim runs `generate_EmulatorConstants.lua` with the in-tree Lua module instead of the emulator
     image. The harness checked that the two give identical constants.
   - The constants are generated first, which is the fixed point of the project's order and the more lenient
     choice. The project's literal `make build` order also fails.
3. It runs `forge build --offline --use 0.8.30`.
4. It checks that `TLB_NUM_SETS`, `TLB_SET_SIZE` and `TLB_SLOT_LENGTH` are defined in `EmulatorConstants.sol` when
   `UArchStep.sol` uses them, and that they equal `cartesi.TLB_NUM_SETS`, `TLB_SET_SIZE` and
   `SHADOW_TLB_SLOT_SIZE`.

It exits 1 on a compiler error or on a missing or wrong constant, 0 if the verifier builds and the constants agree,
and 2 on setup errors.

On audit/prt2 it prints the following and exits 1. The reviewer ran it three times and got the same result each
time.

```
== regenerated UArchStep.sol: TLB bound check (generated from src/uarch-step.cpp)
   1090:                set_index >= TLB_NUM_SETS
== forge build --use 0.8.30 (the project's build: src/ and the test/ contracts that import it)
   Error: Compiler run failed:
   Error (7576): Undeclared identifier.
       --> src/UArchStep.sol:1090:30:
FAIL (R13): the verifier regenerated from audited source with the pinned generator does not build
== TLB constants of EmulatorConstants.sol vs the emulator
   TLB_NUM_SETS: not defined in EmulatorConstants.sol (emulator: 3)
FAIL (R13): UArchStep.sol uses TLB_NUM_SETS, which EmulatorConstants.sol does not define
   TLB_SET_SIZE = 256 (emulator: 256) OK
   TLB_SLOT_LENGTH = 32 (emulator: 32) OK
run.sh: R1-R13-1: exit 1 (bug present)
```

The reviewer also ran two controls on a scratch copy of the pinned checkout, with
`uint64 constant TLB_NUM_SETS = <v>;` added to the template:

- **v = 3.** Line 1090 regenerates as `EmulatorConstants.TLB_NUM_SETS`, the build succeeds, and the test prints
  `PASS` and exits 0.
- **v = 4.** The build succeeds, but the test prints
  `FAIL (R13/A6): TLB_NUM_SETS = 4 in EmulatorConstants.sol, emulator has 3` and exits 1.

A fix on the emulator side that stops using an undeclared name would also make the test pass. The test flags a
missing constant only when the generated code uses it.

The harness log `bugs/harness/work/solidity-step/build-status.txt` records the same failure of the pure
regeneration.

Opus 5.5 found, proved and reviewed this candidate, with no fallback. It merges R1-A6-1 and R1-PREPARE-1.

### Trigger and reachability

No adversary is involved and no machine state is needed. Anyone who regenerates the step for this emulator version,
as AUDIT.md defines the referee verifier and as the project's `make build` does, hits the failure every time. That
includes every deployment that wants a verifier matching audit/prt2. The failure does not depend on any input
sequence.

### Rating

1. **Out of scope: no.**
   - The trigger is building the verifier from its pinned generator and this branch. It needs no API misuse, no
     untrusted snapshot, no host fault and no deployment that violates A1 to A8.
   - The exclusion "Defects that need the deployment to violate one of A1 to A8, unless the emulator's own behavior
     is what makes the obligation fail" does not apply. The build fails before any deployment exists. Here it is the
     emulator's change that makes A6 hard to meet.
2. **Role: Referee verifier.**
   - AUDIT.md: "`machine-solidity-step` v0.17.0-test1, with its generated code and constants regenerated from
     `audit/prt2` | Referee verifier". This clause covers the generator and its generated output.
   - Section 3: "Referee verifier. A verifier whose acceptance settles disputes, such as the on-chain verifiers."
   - The root cause in `src/uarch-step.cpp` is in the "uarch program" row (Honest operator). The defect is rated by
     the more critical role, Referee verifier. It is not a support component, so the Medium cap does not apply.
3. **High and Medium cases: High.**
   - The listed case: "A uarch program or verifier code fixed on-chain that cannot be reproducibly rebuilt, while
     what is deployed matches its audited source."
   - The verifier code fixed on-chain cannot be rebuilt from audited source. No deployed code yet differs from
     audited source in a way that changes what a verifier accepts.
   - The rule violated is R13: "The uarch program, its pristine hash, and the verifier code that a deployment fixes
     on-chain must be reproducibly buildable from audited source."
4. **Critical: not reached under this reading.**
   - Building the verifier is not one of the operations of the honest operator's path that section 2 lists.
   - It is not a rule violation at a reachable state.
   - No verifier accepts a wrong after-hash because of it.

**Two readings.**

- **Critical reading.** The High case is conditioned on "what is deployed matches its audited source". No audited
  source produces a buildable verifier that matches this emulator. So every deployment of this version must ship
  either:
  - a hand edit. Any value other than 3, or other drift, breaks A6 and R2.
  - the stale released step (marchid 22, old pristine hash, no TLB check). That breaks A6 and makes honest reset
    and step proofs disagree with the on-chain verifier, a completeness failure.

  Under this reading the qualifier fails, and a resulting version mix would be a violation of A6 and R13 that the
  emulator itself caused, so it would not be excluded.
- **What decides.** Whether the deployment process ships the regenerated verifier only from an audited, fixed
  generator, or ships the hand-patched or stale code. Today no audited source builds.

### Possible solution and risks

- **Generator side.** In machine-solidity-step, emit `TLB_NUM_SETS` from `generate_EmulatorConstants.lua`, as
  `cartesi.TLB_NUM_SETS`. Also emit `TLB_SET_SIZE` and `TLB_SLOT_LENGTH` (`cartesi.TLB_SET_SIZE`,
  `cartesi.SHADOW_TLB_SLOT_SIZE`) instead of hand-coding them in the template, so that nothing hand-written can
  drift from the emulator.
- **Ordering.** The generator should also make `generate-step` independent of the order of `generate-constants`. The
  translator reads the existing `EmulatorConstants.sol`, so the project's literal `make build` order, which runs
  `generate-step` first, fails on the first pass even with a fixed template.
- **Emulator side.** Add a CI job to the emulator that regenerates the step and runs `forge build` and the replay
  tests. Any change to `uarch-step.cpp` that uses a new constant would then fail at once.
- **Risks.**
  - A wrong `TLB_NUM_SETS` value in Solidity would make the on-chain verifier diverge from the emulator on the
    WRITE_TLB ecall, either accepting or refusing differently. The value must come from the emulator, not be
    hand-typed.
  - Regenerating also changes `CM_MARCHID` and `UARCH_PRISTINE_STATE_HASH`. Dave's fixtures and the
    machine-solidity-step tests that expect the old values, `testCmMarchId` and two mock tests on halt/overflow
    precedence, need updating. Those are stale expectations, not separate defects.

### Risk of not fixing it

The audited emulator version has no verifier that can be built from audited source. A deployment must either
hand-patch the generated Solidity, which leaves unaudited code that a referee verifier relies on, or deploy the stale
released step. The stale step implements a different state transition function, with a different marchid and
pristine hash, which mixes versions (A6) and makes the honest operator's proofs fail on-chain. Nobody needs to
trigger it: every regeneration fails. The mitigation outside the code is to release a fixed machine-solidity-step
together with this emulator version and audit it.

## R1-R8-3

**Title.** Every `collect_mcycle_root_hashes` call re-marks and word-compares every page mapped by the write TLB, even when nothing was written since the last call. A guest that fills the write TLB and loops on automatic yields makes each yield about 6x more expensive than it needs to be.

**Severity.** High under the preferred reading: a guest multiplies the worst-case cost of "a part of a claim" (R12) by a constant factor, with the deployment's sizing unknown. Out of scope under the alternative reading, which takes the section 8 exclusion for "the number of its outputs or yields" literally, because each yield still has a bounded cost.

### Problem

`machine::collect_mcycle_root_hashes` calls `update_hash_tree()` on entry. That function runs
`mark_write_tlb_dirty_pages()`, which marks dirty the page of every valid slot of the 256-slot write TLB
(`TLB_SET_SIZE = 256`), whether or not anything was written there since the hash tree was last updated. `m_ht.update`
then looks up each marked page and compares all 128 of its 32-byte words against the page hash-tree cache. Inside the
call this marking is not needed. The collect state access records every write in `context.dirty_pages`
(`collect-mcycle-hashes-state-access.hpp`, `m_c.dirty_pages.insert`), and the loop marks only those pages before each
`m_ht.update`. So when a call returns, the hash tree is already up to date. If the next call follows with no other
mutation in between, its entry marking repeats about 1 MiB of comparisons for nothing.

A call returns at every automatic yield: the loop breaks on any break reason other than `reached_target_mcycle`.
The honest operator's builder then calls it again (`doc/recipes/prt.lua`, `run_to_stop` -> `mcycle_computation_hash_run`).
A guest can yield automatically every one or two mcycles. With a full write TLB, it pays the 256-page re-scan once
per yield.

So the per-call constant term of the cost of "a part of a claim" grows from about 17 pages (the always-dirty pages)
to about 272 pages. Measured in time, it grows from about 30 us to about 190 us per yield. For a yield-every-2-mcycles
guest, which is already the most expensive per-mcycle pattern without this defect, that raises the worst-case cost of
computing the mcycle-level claim from about 15 us to about 95 us per mcycle. That is about 6x. It erodes the A7 margin:
the clocks are sized for "the worst-case costs of R12". It does not produce a wrong hash.

The hunter called this "rehashing". That is not accurate. The number of hash computations per call is the same with
and without a full TLB (59 in the test). The extra work is marking, looking up and comparing unchanged pages.

### Component, role and area

`collect_mcycle_root_hashes` and the hash tree (`src/machine.cpp`, the hash-tree update and its page cache). Role:
honest operator. The AUDIT.md table lists "Interpreter, state-access layers, devices, uarch program, hash tree, log
producers, `collect_mcycle_root_hashes` and `collect_uarch_cycle_root_hashes`, ..." as "Honest operator".

### Location

- `src/machine.cpp`: `machine::collect_mcycle_root_hashes` (from line 2424). It calls `update_hash_tree()` on entry
  (line 2451) and breaks on any reason other than `reached_target_mcycle` (around line 2557).
- `src/machine.cpp`: `machine::update_hash_tree` (line 1645), `machine::mark_write_tlb_dirty_pages` (line 1639) and
  `machine::mark_write_tlb_dirty_page` (line 1619).
- `src/collect-mcycle-hashes-state-access.hpp`: write tracking into `context.dirty_pages` (lines 78 and 82).
- Caller on the honest operator's path: `doc/recipes/prt.lua`, `run_to_stop` (line 1396) and
  `mcycle_computation_hash_run` (line 1576).

### Evidence and test

`bugs/R1-R8-3/` contains `test.lua` (the test, with a hand-assembled bare-metal guest inlined as six instruction words)
and `README.md`. Run it with `bugs/run.sh R1-R8-3`. It runs in well under a second.

The guest runs on a machine with 4 MiB of RAM. It stores non-zero data to N distinct pages, which fills N write-TLB
slots, and then loops on `sd t1,0(t4); j .` with `t1` set to an automatic yield (progress). After one warm-up call,
the test makes 64 calls to `collect_mcycle_root_hashes(MCYCLE_MAX, 10, 0, 0)`. Each call runs 2 mcycles to the next
yield and writes no memory. The test then reads `get_hash_tree_stats`. The control uses N = 1 and the subject uses
N = 256. The test asserts, deterministically and without timing, that pages visited per call (`page_hits +
page_misses`) with a full TLB are at most the control plus 16.

Output on audit/prt2 (the reviewer re-ran it twice; the prover reports four runs, all exit 1). The CPU times vary and
are printed for information only:

```
control  (1 write-TLB slot):    17.0 pages, 2048.0 words compared, 59.0 hashes, 2.0 mcycles per collect call (29.7 us, info)
full TLB (256 write-TLB slots): 272.0 pages, 34688.0 words compared, 59.0 hashes, 2.0 mcycles per collect call (183.1 us, info)
ratio of hash-tree pages visited per call: 16.0x
VIOLATED: R12 / section 8 High: a collect_mcycle_root_hashes call that resumes at an automatic yield with no memory written must not re-visit every page mapped by the write TLB (per-call hash-tree work must not grow with valid write-TLB slots)
run.sh: R1-R8-3: exit 1 (bug present)
```

The page counts, word counts and hash counts are identical across runs. The test exits 0 once a call that resumes
with an up-to-date hash tree skips the re-scan of unchanged write-TLB pages. The reviewer made no changes to the test.

### Trigger and reachability

The guest triggers it. Any input that takes control of the guest (section 4: "Any input may take control of the
firmware, the kernel, the rollup libraries, and the application") can store to 256 distinct pages and then yield
automatically in a loop. Any assignment of guest-writable memory and registers is presumed reachable. Ordinary guests
that touch many pages, such as Linux, also tend to keep the write TLB full, so a large part of this overhead is paid
at every automatic yield even without an adversary. Ordinary guests yield far less often, though.

### Rating

1. **Out of scope.** Two exclusions were checked.
   - "Average-case performance that does not change the worst-case cost of any operation listed in R12." This does
     not apply: the per-mcycle worst case of computing a claim is a guest that yields every one or two mcycles, and the
     defect multiplies exactly that case by about 6x in time.
   - "An application that tries to exhaust the honest operator through the number of its outputs or yields. ... This
     holds as long as ... each yield costs it a bounded amount (R12)." The per-yield cost here stays bounded (at most
     256 pages). But "How to rate" step 1 says: "The entries about applications exclude what an application loses,
     never an emulator defect that its guest triggers". The defect is the avoidable size of each yield's cost in the
     emulator, not the number of yields, so under the preferred reading the exclusion does not cover it.
2. **Role.** Honest operator. Section 3: "The transition function, its log producers, the computation-hash builders,
   the hash tree and its node proofs ... play this role in every deployment". The AUDIT.md table names
   `collect_mcycle_root_hashes` and the hash tree as honest operator. These clauses cover this component directly.
3. **High and Medium cases.** Section 8, High: "A defect that lets the guest, or host load that the deployment was
   sized for, multiply the worst-case cost of an operation listed in R12 by a constant factor, compared with the same
   operation without the defect, while staying within what the deployment was sized for. A cost that the specified
   semantics require is not a defect. When the sizing is unknown, rate such a constant-factor increase High". R12 lists
   "a part of a claim". The specified semantics do not require re-scanning pages that the collect call itself already
   tracked as unchanged. The factor is constant (bounded by the 256 write-TLB slots), so the case is High.
4. **Critical.** This step does not apply. The cost stays linear in mcycles, with a bounded constant per call, so it is
   not "unbounded, super-linear". It would be Critical only if the inflated cost exceeded what a given deployment was
   sized for, which is unknown.

**Two readings.** Under the literal reading of the yield exclusion (any cost that is bounded per yield is excluded),
this is Out of scope. Under the reading that step 1 supports (application exclusions never excuse an emulator defect
that the guest triggers, and the High constant-factor case covers it), it is High. The text favours the second
reading. The threat model does not say whether "each yield costs it a bounded amount (R12)" means any bound, or the
R12 worst case of the same operation without a defect. Settling that would decide the class.

### Possible solution and risks

Track whether the hash tree may be stale with respect to writes made through the untracked fast path. Set a flag on
`machine::run`, `write_memory`, `write_reg`, shadow writes, loads, TLB changes and every other mutation that does not
mark dirty pages itself. Make `update_hash_tree` run `mark_write_tlb_dirty_pages()` only when the flag is set, and
clear it after a successful update. `collect_mcycle_root_hashes`, whose state access tracks every write, would then
leave the flag clear when it returns. As a secondary improvement, avoid the per-call `result.hashes.reserve` of up to
16384 hashes (512 KiB) when the call ends at an early yield.

Risk: missing a single mutation path that writes through the write TLB without setting the flag would leave pages
unmarked and produce a stale root hash. That is an R9 violation on the honest operator's path, which is Critical. The
change needs a test that compares against `verify_hash_tree` after every API operation sequence, and a careful audit
of every writer.

### Risk of not fixing it

A guest, controlled by any input that subverts it, can make the honest operator's mcycle-level claim computation about
6x slower per mcycle than the worst case without the defect, for as many mcycles as the application's own bound
allows. A deployment whose clocks and hardware were sized on measurements of the cost without the defect loses that
margin (A7). If the margin is thin, the honest claim could time out. Mitigation outside the code: size A7 against
this measured worst case, a guest yielding every one or two mcycles with a full write TLB.

## R1-A3-1

**Title.** The PRT player never fetches the inputs DaveConsensus defers past an epoch's input limit, so it crash-loops and stops defending the next epoch.

**Severity.** Medium

### Problem

The pinned DaveConsensus seals each epoch as `[lo, lo + min(pending, 2^24))` (`_nextInputIndexUpperBound`) and leaves
the rest of the pending inputs for the next epoch. Every input it defers in this way was added to the InputBox at or
before the block of epoch N's `EpochSealed` log. That is the condition for it to be pending when the seal ran.

`crisium.lua` (`open_epochs`) opens epoch N+1's listener with
`first_input_block = previous_seal and eth.small(previous_seal.log.blockNumber) or first_block`. The listener in
`prt-epoch.lua` then fetches InputAdded logs only from that block on (`history:get_logs(address, self.first_input_block,
...)`). It never sees the deferred inputs that were added in blocks before epoch N's seal. The next input it does see
fails the `index == self.input_begin + #self.inputs` check ("input stream has a gap or duplicate", prt-epoch.lua:73). If
no later input arrives, epoch N+1's seal fails `"sealed input count mismatch"` (prt-epoch.lua:96). The assertion
propagates out of `pass()`, so crisium dies. `prt-supervise.sh` relaunches it, and it rebuilds the listener with the same
`first_input_block`. The same failure therefore repeats on every restart. The player cannot compute or defend its claim
for epoch N+1, or for any later epoch.

In the role the player stands in for, this is a completeness failure (section 1: the honest operator "cannot respond in
time. If the honest claim is eliminated, a dishonest claim can win"). It also breaks R4 directly, because the player does
not assign inputs to epochs as the referee does once the input limit binds.

### Component, role and area

The PRT player in `doc/recipes`: `crisium.lua` (how it opens each epoch's listener) and `prt-epoch.lua` (the epoch
input/seal listener). AUDIT.md table: "The PRT player and bridge in `doc/recipes`, ... | Support. No production
deployment runs the player, the bridge or the CLI." Area: observing the chain (fetching the on-chain input record) and
assigning inputs to epochs.

### Location

- `doc/recipes/crisium.lua`, `open_epochs`, line 267: `first_input_block = previous_seal and
  eth.small(previous_seal.log.blockNumber) or first_block`. The comment above it only considers inputs "logged in the
  previous seal's block".
- `doc/recipes/prt-epoch.lua`, `methods:poll`, line 37 (fetch from `self.first_input_block`), line 73 (gap assert),
  lines 96-99 (sealed count assert). `M.new` lines 165-167 document the "only from the block that sealed the previous
  epoch on" choice.
- Referee behavior relied on: `bugs/harness/work/dave/released/cartesi-rollups/contracts/src/DaveConsensus.sol`,
  `_nextInputIndexUpperBound` (lines 470-472) and the seal at lines 270-271. `prt-contracts.patch` does not change it.

### Evidence and test

`bugs/R1-A3-1/` contains `test.lua` and `README.md`. Run it with `bugs/run.sh R1-A3-1`. It needs no chain and no machine,
and it runs in under a second.

The test loads the real `prt-epoch.lua`, with the dispute bridge stubbed because the bridge is outside the defect. It
drives the listener against a fake chain whose `logs()` honours `fromBlock`, a fake ABI and a recording player. It
computes `first_input_block` by extracting the expression crisium.lua passes to `epoch.new` from crisium's source and
evaluating it. As a setup check, it confirms that the pinned DaveConsensus source still contains the
`min(MAX_INPUTS_PER_EPOCH)` cap. Epoch 0 is sealed at block 100 as `[0, 2^24)`. Input `2^24` was added at block 50.

The test has two scenarios:
1. The backlog input plus input `2^24+1` at block 120, with epoch 1 sealed as `[2^24, 2^24+2)`.
2. The backlog input only, with epoch 1 sealed as `[2^24, 2^24+1)`.

For each scenario, the test asserts that epoch 1's listener delivers offsets `0..n-1`, accepts the seal and opens the
dispute. A control run of each scenario with `first_input_block = first_block` must pass, or the test exits 2.

On audit/prt2 it prints the following and exits 1 (reproduced twice by the reviewer):

```
[backlog input + one input after the seal] crisium first_input_block = 100 (epoch 0 sealed at block 100, deferred input 16777216 added at block 50)
[backlog input + one input after the seal] fetched InputAdded/EpochSealed from block(s) 100,100; poll ok=false error: .../doc/recipes/prt-epoch.lua:73: input stream has a gap or duplicate; delivered offsets {}; epoch_sealed {}
[backlog input only] ... poll ok=false error: .../doc/recipes/prt-epoch.lua:96: sealed input count mismatch; delivered offsets {}; epoch_sealed {}
VIOLATED: R4: 'It assigns inputs to epochs exactly as the referee does, including the input limit per epoch (A3)' - ...
run.sh: R1-A3-1: exit 1 (bug present)
```

The reviewer ran the test against a copy of crisium.lua whose expression was changed to `first_input_block =
first_block` (with `RECIPES_DIR` pointed at the copy). Both scenarios then passed and the test exited 0.

Limitation: the test evaluates crisium's expression with only `previous_seal`, `next_epoch`, `first_block`, `eth` and
`math` in scope. A fix that computes the block elsewhere, or that uses other crisium locals, makes the test exit 2
(setup error) rather than 0, so the test's extraction must be updated together with such a fix.

Opus 5.5 found, proved and reviewed it. No fallback model was used.

### Trigger and reachability

An input sender triggers it. More than 2^24 inputs for the application must be pending (added since epoch N's lower bound)
when DaveConsensus seals epoch N. That seal happens when epoch N-1's tournament settles, so inputs accumulate for the
whole length of a dispute. Section 4 lists "input senders (any bytes, any count)" as untrusted, and section 7 lets the
adversary "Send any number of inputs the deployment accepts". The InputBox accepts them, and the consensus defers the
excess exactly as A3 requires ("The input record assigns no more inputs to an epoch than the input limit per epoch"). An
honest application with heavy traffic reaches the same state with no adversary. No guest state is involved. The state is
a chain history that every deployment admits.

### Rating

1. Out of scope: no. The trigger is an input flood, which is an adversary capability (section 7), not an exclusion. The
   deployment meets A3: the referee caps each epoch at the limit, so "Defects that need the deployment to violate one of
   A1 to A8" does not apply. The trigger is not a reorganization, a host fault, a snapshot, an O1/O2 case or an
   application that is not correctly designed. The player is not one of AUDIT.md's excluded items. Those are the
   validator nodes, `prt-dishonest.lua`, and the `*-test.lua` and `*-test.sh` harnesses.
2. Role: Support. AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support. No production deployment runs
   the player". Section 3: "A defect that only a support component shows is Medium when it would rate High or Critical
   in the role the component stands in for, such as ... the honest operator for an implementation of an operator or a
   tool that computes claims." This clause covers crisium/prt-epoch, which is an implementation of the honest operator
   that no deployment runs. No component in another role shares the defect: the emulator and the referee are correct
   here, and the validator nodes are out of scope.
3. High and Medium cases: in the stood-in honest-operator role, no High case fits. The state is reachable, not
   "demonstrably unreachable". The data is the on-chain input record, which the honest operator "must process"
   (section 4), not data it "may decline". So the stood-in rating falls through to step 4. For the support component
   itself, the Medium case "A defect that only a support component shows, when section 3 rates it Medium" fits.
4. Critical (stood-in role): R4: "The honest operator defends every epoch whose dispute is open, including while it
   processes the inputs of later epochs. It assigns inputs to epochs exactly as the referee does, including the input
   limit per epoch (A3)." Section 8 Critical: "violating any rule or obligation at a reachable state, or anywhere on the
   honest operator's path, is critical", and "A crash ... caused by data from other parties that the honest operator
   must process." Observing the chain is on the honest operator's path. Critical in the stood-in role makes it Medium for
   the support component.

Another reading: someone could argue that a flood of more than 2^24 inputs (about 16.8 million InputBox transactions within
one dispute) is impractical. However, section 4 ("any count") and section 7 admit it, and heavy honest traffic also
reaches it. The model does not price input submission, so the class stays Medium. A reader who treated the player as
standing in for nothing would get Low ("Any other support defect is Low"). The section 3 clause about "implementations of
an operator that no deployment runs" rules that out.

### Possible solution and risks

Epoch N+1's listener must fetch from a block at or before the block of input `inputIndexLowerBound` of its range. One
option is for epoch N's listener, which already receives inputs past its limit in its own log stream, to record the block
of the first input with index at least `input_begin + 2^24` and hand it to epoch N+1. That value must be persisted in the
checkpoint so it survives a restart. Another option: when the previous seal was full (`upper - lower == 2^24`), carry
forward the previous epoch's `first_input_block` instead of the seal block.

Fetching from `first_block` (the consensus deployment block) is correct but conflicts with R12: the operator's work
"must not grow with the application's age, with the number of past epochs". The fix must also keep the restart path (O2)
working and keep the "input logged in the previous seal's block" case working.

### Risk of not fixing it

The PRT recipes and demonstration break once an application receives more than 2^24 inputs during one dispute. The player
then crash-loops forever and stops defending every later epoch. Any input sender can trigger it, given enough
transactions. Production validator nodes are out of scope, but a node modelled on these recipes would inherit a
completeness failure that lets a dishonest claim win by timeout. One mitigation outside the code is to restart the player
by hand with a `first_input_block` at or before the backlog, but the code exposes no option for that.

## R1-A6-2

**Title.** The PRT player and deployer check a deployment's version only by its pristine uarch hash, never by
`CM_MARCHID`, so they accept a verifier of another version whose uarch image is unchanged.

**Severity.** Medium (preferred reading). Low under the reading that R13's check only has to refuse the versions
released so far (see Rating).

### Problem

Before it plays, `doc/recipes/crisium.lua` (the PRT player) checks the deployed `CartesiStateTransition` against its
own emulator in one way only. It compares `UARCH_PRISTINE_STATE_HASH()` with `cartesi.UARCH_PRISTINE_STATE_HASH`.
`doc/recipes/prt-deploy.lua` makes the same single check when it deploys. The pristine hash covers the uarch program
image and the uarch state that a reset produces. It does not cover the verifier's step, reset and delivery code
(`UArchStep.sol`, `UArchReset.sol`, `SendCmioResponse.sol`, generated from `uarch-step.cpp`,
`uarch-reset-state.cpp` and `send-cmio-response.cpp`). Those decide R13's "accesses each logged transition makes,
and their order", which are part of the protocol. The verifier also publishes `CM_MARCHID`, "so a claimer can
compare it with its own emulator before joining". R13 makes the machine-identification registers change with every
version that changes the transition function. No recipe reads `CM_MARCHID`. `doc/recipes/prt-lua-bridge.md`
presents the pristine comparison as the version check ("A matching `CM_MARCHID` does not guarantee that, which is
why each player compares the deployed verifier's pristine hash with the emulator's before playing").

A version that changes only uarch-step, reset or delivery code keeps the pristine hash. This branch's history has
such a change: 4310fa3 ("fix!: report a uarch that halts on its last cycle as halted") says "Root hashes are
unchanged, but a logged step at the cycle limit now also reads the halt flag, so the Solidity step must be
regenerated". afd5f9d (TLB index check) also changed only `src/uarch-step.cpp`. Against a deployment of such a
version, the player starts and plays with a verifier that implements another transition function than its own
emulator. R13 asks the opposite: "The honest operator must be able to detect and refuse a mismatch between its
build and a deployment. The check must refuse every pairing of its build with a deployment of another released
version." A mixed deployment breaks A6. Proofs the honest operator logs may then be rejected on-chain (the test
shows one), which is a completeness failure of section 1.

### Component, role and area

The PRT player and deployer in `doc/recipes` (`crisium.lua`, `prt-deploy.lua`). AUDIT.md component table: "The PRT
player and bridge in `doc/recipes`, ... | Support. No production deployment runs the player, the bridge or the
CLI." The area is the start-up and deployment version check. The player is an implementation of an operator, so it
stands in for the honest operator.

### Location

- `doc/recipes/crisium.lua`, lines 128-132: the only start-up check of the deployed verifier
  (`UARCH_PRISTINE_STATE_HASH()` vs `cartesi.UARCH_PRISTINE_STATE_HASH`).
- `doc/recipes/prt-deploy.lua`, lines 44-48: the same check at deployment.
- `doc/recipes/prt-lua-bridge.md`, lines 193-196: documents the pristine check as the version check.
- Dave `prt/contracts/src/state-transition/CartesiStateTransition.sol` (v3.0.0-alpha.7): `CM_MARCHID` and
  `UARCH_PRISTINE_STATE_HASH`, published for this comparison.

### Evidence and test

`bugs/R1-A6-2/` contains `test.lua` (the test), `run-crisium.sh` (starts the real `doc/recipes/crisium.lua` in
sentinel mode against one application and prints ACCEPTED once it passes its start-up checks and writes its first
status file, REFUSED if it exits before), `deploy.lua` (deploys a Dave build with the real `prt-deploy.lua`, with
the deployer's constants set to the deployed verifier's own), `foundry.toml` (build settings for the variant
verifiers) and `README.md`.

The test compiles Dave's `CartesiStateTransition.sol` over the untouched machine-solidity-step v0.17.0-test1 sources
(`CM_MARCHID` 22, step code without the TLB index check and with the old halt/overflow order) twice: "released" as
is (pristine `0x558f...3926`), and "other" with only `UARCH_PRISTINE_STATE_HASH` set to this build's
(`0x89ae...43d7`). It starts its own anvil on a free port from 18700 up and makes three full Dave deployments:
"ours" (the harness's patched Dave build over the step regenerated from this branch, `CM_MARCHID` 23), "other" and
"released". As a witness that "other" implements another transition function, it logs a uarch step with this
branch's emulator at `uarch_cycle = UARCH_CYCLE_MAX`: "ours" accepts it with the emulator's after-hash, "other"
rejects it. It then runs the player against each: the controls require "ours" ACCEPTED and "released" REFUSED, and
the assertion requires "other" REFUSED.

Run: `bugs/run.sh R1-A6-2` (about 10 s; needs `work/dave/patched`, `work/solidity-step/released`,
`work/configs/baremetal-minimal`, forge/anvil/cast). It removes its temp dir and stops its anvil. Output on
audit/prt2 (reviewer re-ran it twice, identical):

```
  this build: MARCHID 23, pristine 0x89ae34ba1dc65a8a3668b484bcedf897665c803c41dc9ef9f1faf147b9d443d7; deployed 'ours' CM_MARCHID 23
  deployed 'other': CM_MARCHID 22, pristine 0x89ae34ba1dc65a8a3668b484bcedf897665c803c41dc9ef9f1faf147b9d443d7
  witness step (uarch cycle at its limit): the deployment of this build's version accepts the emulator's log, 'other' refuses it: InvalidAccessLogProofLength(consumed 1920, provided 3840)
  player vs 'ours': ACCEPTED
  player vs 'released': REFUSED
    lua5.4: /home/user/machine-emulator/doc/recipes/crisium.lua:128: emulator and Solidity pristine uarch hashes differ
  player vs 'other': ACCEPTED
VIOLATED: R13: the player must refuse a deployment of another version (CM_MARCHID 22, v0.17.0-test1 step code) even when its pristine uarch hash equals this build's (MARCHID 23)
run.sh: R1-A6-2: exit 1 (bug present)
```

The reviewer also ran an out-of-tree copy of the test with a copy of `crisium.lua` that also compares
`CM_MARCHID()` with `cartesi.MARCHID`: "ours" ACCEPTED, "released" REFUSED, "other" REFUSED ("emulator and Solidity
marchid differ"), exit 0. Found, proved and reviewed on Opus 5.5 (no fallback).

### Trigger and reachability

Trigger: an operator starts the player (or deploys with `prt-deploy.lua`) against a deployment whose verifier was
generated from a version with the same uarch image as its own build but different step, reset or delivery code. No
adversary action is needed beyond publishing or pointing at such a deployment. The pairing in the test is modeled:
the released machine-solidity-step versions in the harness (v0.16.0 at fb00a32 and v0.17.0-test1 at 6f91eb9) both
have `CM_MARCHID` 22 and pristine `0x558f...`, which the player refuses. What makes the pairing realistic is that
versions that change only uarch-step code keep the pristine hash, as 4310fa3 and afd5f9d show on this branch; a
later release made of such changes would pair with this build's release and pass the check in both directions.

### Rating

1. Out of scope: not excluded. The exclusion "Defects that need the deployment to violate one of A1 to A8" does not
   apply, because the defect is the missing detection, which section 8 rates even with no mismatch present ("A node
   that cannot detect a version mismatch, while every node in fact runs the deployment's version"), and R13 puts the
   detection on the honest operator. No other exclusion of section 8 fits.
2. Role: Support (AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support"). Section 3: "A defect that
   only a support component shows is Medium when it would rate High or Critical in the role the component stands in
   for, such as ... the honest operator for an implementation of an operator". This clause covers the player, an
   implementation of an operator. No component in another role shares the defect in this campaign (the emulator
   exposes `MARCHID`; production nodes are out of scope).
3. High and Medium cases: in the stood-in honest-operator role it matches High, "A node that cannot detect a version
   mismatch, while every node in fact runs the deployment's version" (and would be Critical by R13/A6 with a
   mismatch present). Hence the Medium case "A defect that only a support component shows, when section 3 rates it
   Medium". Section 8 step 2: "A defect that only a support component shows is never above Medium."
4. Critical: not applicable (support component). The rule violated is R13: "The honest operator must be able to
   detect and refuse a mismatch between its build and a deployment. The check must refuse every pairing of its build
   with a deployment of another released version."

Two readings. If "another released version" includes versions released after this build (the check runs for the
build's lifetime, and R13 names the machine-identification registers as what every version changes), the check
fails R13 by construction and the rating is Medium. If it covers only versions already released, the check refuses
every existing pairing today (both known releases have a different pristine hash) and the defect is Low (a latent
design gap that violates no rule yet). Deciding facts: whether any released or planned version shares this build's
pristine hash with a different `CM_MARCHID` or step code, and whether R13's check is meant to hold against future
releases. The reviewer prefers the first reading.

### Possible solution and risks

In `crisium.lua` and `prt-deploy.lua`, also compare `CM_MARCHID()` with `cartesi.MARCHID` and refuse on mismatch,
keeping the pristine comparison (the marchid alone does not change within a release cycle or between pre-releases,
as `prt-lua-bridge.md` notes). Update `prt-lua-bridge.md` to say that both are checked. Risk: a deployment built
from a step whose `CM_MARCHID` was not regenerated with the emulator would be refused; that is the intended effect.
Neither value covers every protocol element (for example a step change released without a marchid bump), so the
check still relies on R13's discipline of bumping the machine-identification registers.

### Risk of not fixing it

An operator who uses the recipes as the model for its node's version check can join a deployment of another version
whose uarch image matches its own, and fail to have its proofs verified on-chain, losing its claim. The production
nodes are out of scope here and may check `CM_MARCHID` themselves. Mitigation outside the code: compare the
deployed verifier's `CM_MARCHID` with the emulator's `MARCHID` by hand before joining.

## R1-A7-3

**Title.** The stored PRT player runs a later epoch's whole input in one idle step, so crisium cannot see or answer the sealed epoch's dispute until that input finishes (up to 2^48 mcycles).

**Severity.** Medium

### Problem

`crisium.lua` reads the chain tip only between steps. When the tip has not changed, it calls `idle()`, and that call
runs `player.event_handler.idle` once for every listener. For a stored player with a pending input,
`stored_event_handler.idle` calls `event_handler.idle`, which calls `run_next_input`. That function calls
`run_to_input_mcycle_offset(..., MAX_MCYCLES_PER_ADVANCE_STATE)` and runs the input to its fixed point in one call, with
no way to stop partway. Only after it returns does the loop read the tip again, run `pass()`, and tick the sealed
epoch's dispute bridge.

So one input of the open epoch e+1 delays every observation of, and every answer in, the dispute of the sealed epoch
e. The delay is as long as that input runs, and the per-input limit allows up to 2^48 mcycles. The recipe's own comment
at `stored_event_handler` claims the opposite: "A stored player only records its inputs and runs them in idle time, so
an open epoch never delays a response in a sealed epoch's dispute." The agreed-pair path has the same structure.
`stored_event_handler.idle` calls `advance_agreed_pair`, which runs `run_to_epoch_input_offset` over one whole input per
step. The test does not exercise that path.

The deployed clock model (`ClockBudgets.sol` in the pinned Dave release) charges each honest response one inclusion
time, plus a censorship budget for the whole commitment. A level-0 match has a tree height of 54, so the honest claim
can be on turn up to 54 times in each match, across a logarithmic number of matches. If every one of those turns waits
for a full later-epoch input, the delay comes out of the honest claim's allowance. Once the per-input run time is
large compared with that allowance divided by the number of turns, the honest claim loses by timeout. Then a dishonest
claim can win, which is the completeness failure of section 1. This is the scenario that R4 rules out: "The honest
operator defends every epoch whose dispute is open, including while it processes the inputs of later epochs."

### Component, role and area

The PRT player (`doc/recipes/prt.lua`, the stored player's idle scheduling) and the crisium main loop
(`doc/recipes/crisium.lua`). Role, from the AUDIT.md table: "The PRT player and bridge in `doc/recipes` ... | Support.
No production deployment runs the player, the bridge or the CLI." The component stands in for the honest operator. The
area is the scheduling of later-epoch work against the defense of a sealed epoch.

### Location

- `doc/recipes/crisium.lua`: the main loop (`while true do ... elseif not idle() then`, around lines 361-382) and
  `idle()` (around lines 336-343).
- `doc/recipes/prt.lua`:
  - `stored_event_handler` and its comment (around lines 2180-2186).
  - `event_handler.idle` (around line 2189).
  - `player_meta.__index:run_next_input` (around line 2243), which calls `run_to_input_mcycle_offset` with
    `MAX_MCYCLES_PER_ADVANCE_STATE`.
  - `player_meta.__index:run_to_input_mcycle_offset` (around line 2066).
  - `stored_player_methods:advance_agreed_pair` (around line 2984), through `run_to_epoch_input_offset`.
  - `stored_event_handler.idle` (around line 3021).

### Evidence and test

`bugs/R1-A7-3/` contains these files.

- `test.lua`: the test.
- `guest.c`: a correctly designed bare-metal rollup guest. It reads a little-endian iteration count from the first 8
  bytes of the rx buffer, spins that many times at 2 instructions per iteration, and accepts with the empty outputs
  root.
- `guest.bin`: the built guest.
- `build-guest.sh`: rebuilds `guest.bin` with the harness bare-metal builder.
- `README.md`: notes on the test.

The test builds a template from the guest at its first accepted manual yield. It opens two stored players with the
recipe unchanged: epoch 0 is sealed (`epoch_sealed`) and epoch 1 is open. It adds one input to epoch 1 through
`input_added`, which only records it. Then it runs exactly one crisium `idle()` step, newest listener first, as
`crisium.lua` does, and reads the epoch machine's `mcycle` before and after.

- The control is a 2^19-iteration input (at least 2^20 mcycles).
- The assertion uses a 2^26-iteration input (at least 2^27 mcycles). One idle step must not run it whole: the machine
  must advance fewer mcycles than the input needs, and the input must still be pending or partly done.

Run it with `bugs/run.sh R1-A7-3`. During this review the root volume was full, so the test was run with
`TMPDIR=/dev/shm/...`. The test puts its temporary files under `$TMPDIR` and removes them. On `audit/prt2` it exits 1
on every run (two runs by the reviewer, three by the prover) and prints:

```
short input (needs >= 1048576 mcycles): one idle step advanced 1048797 mcycles in 0.11 s CPU, ran it whole: true
long input (needs >= 134217728 mcycles): one idle step advanced 134217948 mcycles in 2.93 s CPU, ran it whole: true
per-step work ratio long/short: 128.0 (input length ratio 128); at the same rate, one step of an input at the 2^48-mcycle limit would take about 71 days
VIOLATED: R4: the honest operator observes the chain within the dispute clocks while it processes later epochs' inputs; one idle step (between two tip observations of crisium.lua) must not run a later epoch's whole input of 134217728 mcycles (advanced 134217948)
run.sh: R1-A7-3: exit 1 (bug present)
```

The verdict depends only on mcycle counts, which are deterministic. The CPU times and the day estimate vary from run
to run. The test is a proxy for R4. A 3-second input does not break any clock by itself. What the test shows is that
the work of one step grows linearly with the input's length (ratio 128 for a length ratio of 128), so nothing bounds
the step. A fix whose slice is at least 2^27 mcycles would still fail this test. A fix with a smaller time or mcycle
slice passes it. All agents ran on claude-opus-5-5, with no fallback model.

### Trigger and reachability

Two parties combine to trigger it.

1. An input sender adds to the open epoch e+1 an input that a correctly designed application processes for a long
   time, within its own per-input bound.
2. While that input runs, the adversary puts the honest claim on turn in the dispute of the sealed epoch e. It can do
   this by posting claims and moves, timed for when the input starts.

Both are adversary capabilities in section 7: "Send any number of inputs the deployment accepts, with payloads chosen
to maximize the honest operator's cost (R12)", "Steer the dispute to any position of the honest computation, and force
the honest claim through a logarithmic number of matches", and "Race and reorder transactions within the chain's
rules". The state is reachable: the test reaches it from a valid template, using only input delivery and the recipe as
written. Whether a timeout follows depends on how long each input runs compared with the clock allowance, as set out
under Rating.

### Rating

1. Out of scope: no. The trigger is an input sequence and dispute moves, not a machine API call by an untrusted party,
   a snapshot that was not written by the emulator, a reload outside O2, or a host fault. "An application that is not
   correctly designed" does not apply, because the guest bounds its mcycles per input and accepts. "Average-case
   performance that does not change the worst-case cost of any operation listed in R12" does not apply either. The
   defect is the worst-case latency of the honest response, which grows with the input's length. "Defects that need
   the deployment to violate one of A1 to A8" does not apply: a deployment that meets A7 would budget the honest
   operator's costs, not one input run of scheduling delay for every turn.
2. Role: Support. AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support. No production deployment runs
   the player, the bridge or the CLI." Section 3: "A defect that only a support component shows is Medium when it would
   rate High or Critical in the role the component stands in for, such as ... the honest operator for an
   implementation of an operator". This clause covers the player and the crisium loop, which implement an operator. No
   honest-operator component in the AUDIT.md table (interpreter, hash tree, log producers, input delivery, storing and
   loading) shows the defect. It lies in the player's scheduling.
3. High and Medium cases: section 8 lists "A defect that only a support component shows, when section 3 rates it
   Medium." Section 3 rates it Medium if it would be High or Critical in the honest-operator role, so step 4 decides
   that.
4. In the honest-operator role, R4 is violated at a reachable state: "The honest operator observes the chain and
   submits its transactions within the dispute clocks." and "The honest operator defends every epoch whose dispute is
   open, including while it processes the inputs of later epochs." A component in that role that does not observe the
   chain for as long as one later input runs can miss the dispute clocks. That would be Critical, so the support rating
   is Medium.

There are two readings.

- Reading A, preferred: R4's clause on later epochs is a requirement on the operator's implementation. A defense that
  stalls for one later-epoch input on every turn violates it, so the stood-in rating is Critical, and the support
  rating is Medium.
- Reading B: A7 says the clocks "leave room for the honest claim to play the logarithmic number of matches ... while
  the honest operator also processes the inputs of later epochs." The extra delay is then a bounded constant factor:
  at most one input run per turn, with at most 54 turns per match at level 0. In the honest-operator role that would
  be the High case "multiply the worst-case cost ... by a constant factor". That still rates Medium for a support
  component.

Only a reading under which response latency is entirely the deployment's sizing problem, and not a defect of the
operator, would make this Low. The facts that decide are the following.

- The per-input run time that a deployment is sized for. The pinned constants size an inner commitment at
  `COMMITMENT_BUDGET = 120 minutes`.
- How that run time compares with the honest allowance divided by the number of turns. The allowance is censorship
  plus inclusions and refills in `ClockBudgets.maxAllowance`.
- Whether A7 must budget an implementation's scheduling latency. The clock model budgets one inclusion per response.

### Possible solution and risks

Make idle work preemptible.

1. Run a pending input (and an agreed-pair replay) in bounded slices, for example up to an mcycle target that is a
   multiple of the sampling period or a time budget, through the existing `run_to_stop` with an intermediate
   `mcycle_end`. Keep the epoch builder and the pair's revert snapshot across slices.
2. Return to the crisium loop after each slice, so that it reads the tip between slices.
3. Alternatively, run later-epoch work in a separate process from the dispute bridge.

The risks are these. Slicing an input splits `run_to_input_mcycle_offset` across calls. The computation-hash builder,
the pending outputs, the rejection revert, `pair:commit()`, and the restart state that O2 guarantees then have to stay
consistent at every slice boundary. A crash between slices must resume from the last committed input boundary, not
from a half-run input. `check_backlog` and `input_count` bookkeeping need the same care.

### Risk of not fixing it

The player is not run in production, so no deployed node is exposed. Anyone who uses the recipe or the crisium loop as
an operator, or as the model for one, inherits the latency. In that setting, an input sender plus a claimant can time a
long, legitimately bounded input to delay every honest response in the sealed epoch's dispute. When each input runs
long enough compared with the clock allowance, that can eliminate the honest claim by timeout. The recipe's comment
asserts the opposite, which hides the issue. Outside the code, a deployment can limit how long the application runs
each input, or run the dispute of each sealed epoch in its own process.

## R1-A8-3

**Title.** In the PRT referee model, logical time advances only once every connected player answers `advance_time`, so one claimant that keeps its connection open and stops answering freezes every other match.

**Severity.** Medium (support rating of a referee-model stall that violates A8). Under a second reading it is Low; see Rating.

### Problem

The referee in `doc/recipes/prt.lua referee` runs in logical blocks over the `game-transport.lua` server. Before it
moves to the next block, it sends an `advance_time` notification to every connected player. It then waits, with no
bound, until each one has replied (`step_time` calls `clock:barrier_ready(self.batch)`). Each connection also has at
most one outstanding event (`send_next_event` sends nothing while `connection.current_event` is set). A player that
stops answering a request therefore never receives, and never answers, the `advance_time` queued behind it. A player
that answers nothing at all has the same effect. In both cases no block after the current one ever comes.

Match deadlines are counted in these blocks. In a match whose on-turn claim has walked away, the other claim wins
only when its timeout-win response is accepted in a later block. When time stops, that match never settles, and
neither does the tournament. So one claimant that stops processing its own match stops every other match, including
the honest claim's. A8 forbids this: "Failing to process one match's data, for any reason, must not stop, delay or
decide any other match." The model stands in for the referee. A deployed referee with this behavior would let any
claimant keep the honest claim from ever winning, with no cost beyond an open connection.

The manual documents the behavior ("A player that connects and never answers therefore stalls the demonstration,
where a blockchain would let its deadline pass", doc/README.md, "Clocks and logical time"). The closing paragraph that
lists the model's simplifications of the PRT contracts does not include it.

### Component, role and area

The PRT referee model in `doc/recipes`: `doc/recipes/prt.lua` (referee) over `doc/recipes/game-transport.lua` (server
block clock) and `doc/recipes/game-clock.lua`. AUDIT.md role: "The PRT referee model in `doc/recipes` | Referee model".
Area: logical-time advancement and per-connection event delivery.

### Location

- `doc/recipes/game-transport.lua`, `server_meta.__index.step_time` (around lines 1011-1137). After a batch of
  `advance_time` notifications, `if not self.clock:barrier_ready(self.batch) then return end`. A new block is opened
  by `self.batch = { entry }`, with `entry.pending[connection] = true` for every player in `self:get_players()`.
- `doc/recipes/game-clock.lua`, `clock.__index.barrier_ready`, which is false while any entry has a pending
  connection. There is no timeout.
- `doc/recipes/game-transport.lua`, `send_next_event` / `send_event` (lines 438-454). There is one outstanding event
  per connection, so a connection stuck on a request also holds back its `advance_time`. In the receive loop of
  `adopt` (around lines 564-603), a connection's pending entries are dropped only when it closes or sends a malformed
  reply.

### Evidence and test

`bugs/R1-A8-3/` contains the following.

- `test.sh` runs two real referee tournaments with `prt.lua referee` on loopback ports. It uses the harness's
  bare-metal `baremetal-template` (`emit-output.bin` at its first accepted yield) and three inputs. Each tournament has
  four player processes and the `phase_closer`, joined in an order that makes the referee pair them as
  `match 1 = P1 vs quitter` and `match 2 = honest vs "quitter 1"`. In the control run, P1 is a third
  `prt-dishonest.lua quitter` ("quitter 2"), which leaves after posting its claim. In the silent run, P1 is
  `silent-quitter.lua`. The test requires that match 2, which does not involve P1, settles in the silent run as it
  does in the control run. The bound is 10 times the control's settle time, and at least 60 s. The test prints the
  highest logical block that the honest player saw, as count-based evidence. It starts no chain, and it kills every
  process it starts.
- `silent-quitter.lua` wraps `prt-dishonest.lua`'s quitter. It posts the same kind of fabricated claim, then keeps
  its socket open and never answers the next request (it blocks at `reveal_bisection` of match 1).
- `README.md` describes the test.

Run with `bugs/run.sh R1-A8-3` (about 70 s). The reviewer re-ran it twice on audit/prt2. Both runs exited 1 with the
same output, ending with these lines:

```
control: Tournament winner is claim 0x84cc13c6....; match 2 settled after 1s; honest saw logical block 12
silent: tournament after 60s:
  Round 1, match 1, at the mcycle level: claim 0x6776c3d1... against claim 0x1a22b0c7....
  Round 1, match 2, at the mcycle level: claim 0x84cc13c6... against claim 0x0e6cdf5f....
silent: silent: stops answering at reveal_bisection, connection kept open; honest saw logical block 3
FAIL (A8): match 2 (honest vs quitter 1) did not settle within 60s (control: 1s)
run.sh: R1-A8-3: exit 1 (bug present)
```

In the control run, match 2 settles within about 1 s, at logical block 12, and the honest claim wins the tournament.
In the silent run, logical time stays at block 3. That is the block in which the honest player received its own
`reveal_bisection` for match 2. Its answer could be accepted only in block 4, which never comes. The test exits 0 once
match 2 settles despite the silent claimant. It exits 2 on setup errors (the control does not settle, a player does
not connect, or the referee dies). No process was left behind. Found, proved and reviewed on Opus 5.5, with no
fallback.

The prover saw another problem that this test does not cover. A TCP connection that closes before announcing a role
crashes the referee (`game-transport.lua:567: unexpected connection loss: closed`).

### Trigger and reachability

Any party that can connect to the referee as a player triggers it. The test uses a claimant that posts a valid join
(a fabricated claim, as the quitter does) and then keeps the connection open while answering nothing more. Threat
model section 4 lists "dishonest claimants (any number, any logs, any proofs, any timing)" as untrusted, and section 7
lets the adversary "abandon or defend [claims] at will". Code reading suggests that a player with no claim, which
answers no `advance_time`, has the same effect, because the barrier covers every connected player. The test does not
exercise that case. No property of the template or the inputs is involved. Any epoch reaches the state once a match
needs a later block.

### Rating

1. Out of scope: no. The exclusion "Defects that need the deployment to violate one of A1 to A8" makes an exception
   for the case where "an implementation of the referee model is what violates it (section 3)", and that is this
   case. The trigger is a dishonest claimant's timing. It is not a snapshot, an O1/O2 situation, a host fault, an
   application stall or a direct API call by an untrusted party. The test harnesses (`*-test.sh`) and
   `prt-dishonest.lua` are out of scope as components, but the defect is in the referee and transport, not in them.
2. Role: the AUDIT.md table gives "The PRT referee model in `doc/recipes` | Referee model". Section 3, "Referee model",
   says: "A defect that only changes how long a claim may take to respond, or only crashes or stalls the model, even
   when that stops other matches (A8), is rated as support." That clause covers this component and this symptom
   exactly: a stall that stops other matches. The support rule then applies: "A defect that only a support component
   shows is Medium when it would rate High or Critical in the role the component stands in for." The referee model
   "stands in for that normative model", and "A defect in what it accepts or derives is rated as if a deployed referee
   had it." A deployed referee in which one claimant's silence stops every other match would violate A8 at a
   reachable state, which is Critical by step 4. The deployed Dave contracts do not share the defect, since block time
   advances on-chain.
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium." This case
   applies, so the class is Medium. Section 8 step 2 also caps it: "A defect that only a support component shows is
   never above Medium."
4. Critical: not reached. For the record, the obligation violated is A8: "Failing to process one match's data, for
   any reason, must not stop, delay or decide any other match." In the stood-in role, A7 would also fail: "No rule of
   the referee may make the honest claim lose by timeout while it acts within its own clock." The honest claim cannot
   win at all.

Second reading (Low). Two facts decide between the readings.

- (a) Section 5 says that "The simplifications that the manual lists for it are not normative, and neither are its
  clock values." The stall is documented in the manual's clock section, which contrasts it with "a blockchain [that]
  would let its deadline pass". If that sentence counts as a listed simplification, or the barrier counts as part of
  the non-normative clock, then the model follows a non-normative simplification. It is then not a defect under
  section 3, which leaves Low or no defect. The reviewer judges this reading weaker. The manual's explicit list ("The
  model simplifies the PRT contracts in a few ways ...") does not include the stall. "Clock values" reads as the
  numeric allowances, not as whether logical time can advance at all.
- (b) If "the role the component stands in for" is read as the referee model itself, the referee-model clause sends
  stalls back to support, and the rule "Any other support defect is Low" applies. The reviewer judges this reading
  circular. It would also make the words "rated as support" in place of "Low" pointless.

If the manual's description is taken as the normative model, then "the manual's model itself violates one of A1 to
A8", and section 3 makes the manual the defect, "rated as a defect of the referee model". That gives the same support
rating, Medium.

### Possible solution and risks

Option 1: let logical time advance without waiting on players that do not answer. Two ways to do this:

- Bound each `advance_time` barrier with a wall-clock timeout, and drop the players that miss it from that barrier,
  or treat them as departed.
- Keep `advance_time` out of the one-outstanding-event queue, so that a connection stuck on a request does not hold
  back the clock. Then close connections that leave a request unanswered past a wall-clock bound.

Either way, only a timeout-win or elimination response, sent by any player, settles a match, as the model already
requires.

Risks of option 1:

- The recipe runs the tournament twice and requires identical narration. Wall-clock timeouts make the transcript
  depend on scheduling unless the bound is generous and dropping a player is narrated deterministically.
- A slow honest player (a long uarch-level computation or proof) must never be dropped. A drop would itself make the
  honest claim lose by timeout (A7). The bound must therefore exceed the worst-case response time that R12 implies,
  or apply only to the barrier and not to the match clocks.

Option 2: state in the manual's list of simplifications that a silent connected player stalls the model, which makes
the behavior non-normative. This makes it a documented limitation of the demonstration and leaves the code unchanged.

Separately, make the receive loop of an unannounced connection close the connection rather than `assert`, so that an
early disconnect does not crash the referee.

### Risk of not fixing it

No production deployment runs the referee model. The deployed referee (Dave) advances by block time and does not
share the stall. The risk is that the demonstration and its tests misrepresent A8. Any participant that connects to
a model referee can freeze every match and keep the honest claim from winning, which a deployed referee must never
allow. Anyone who builds an off-chain referee or a test network on this transport inherits the freeze. Outside the
code, the mitigation is to run the model only with trusted players and an external wall-clock watchdog.

## R1-A8-4

**Title.** The PRT bridge keeps working on a pending cleanup transaction of another match, which has no deadline, instead of sending the honest claim's newly due move, so that move can miss its clock.

**Severity.** Medium

### Problem

`methods:tick` of the PRT bridge sorts the due jobs by expiry, earliest first. When the signer already has a
pending transaction whose job is still due, though, the bridge selects that job, overriding the earliest-expiring one.
It attempts only the selected job ("Keep working on a useful pending action. Do not oscillate between two eligible
actions belonging to the same account.").

Permissionless cleanups have open windows (`last = math.maxinteger`): `eliminateMatchByTimeout`,
`eliminateInnerTournament`, and the bridge's own `tryRecoveringBond` and `stageTournamentResult`. When one of them is
pending and the honest claim then comes on turn, the bridge neither prepares nor attempts the honest move
(`advanceMatch`, a seal, or a leaf proof) until the cleanup is mined. The journal re-prices that cleanup only every
`bump_blocks` (3 blocks, +15%). As a result, the honest move's latency becomes the remaining inclusion time of the
cleanup plus its own inclusion time, instead of its own inclusion time alone.

The deployed Dave clocks provision exactly one inclusion budget `G` per honest response. Lateness beyond that budget
is charged to the non-refillable censorship budget, and the root allowance holds only one inclusion in reserve for
the action in flight. So this self-inflicted delay can make the honest claim's response land after its clock expires,
even though the chain includes every transaction within one inclusion. The honest claim is then eliminated by
timeout, which is a completeness failure under section 1: "cannot respond in time. If the honest claim is
eliminated, a dishonest claim can win."

The adversary can repeat the trigger at every honest turn, each time with a Sybil match of its own. Each repetition
draws up to one more inclusion per response from the honest claim's clock.

### Component, role and area

The PRT bridge in `doc/recipes` schedules the player's transactions over its nonce, using the transaction journal
`doc/recipes/prt-transactions.lua`. The AUDIT.md table gives its role: "The PRT player and bridge in `doc/recipes`
... | Support. No production deployment runs the player, the bridge or the CLI." It stands in for the honest
operator's transaction submission, which the threat model lists among the honest operator's path: "Submitting
transactions."

### Location

- `doc/recipes/prt-bridge.lua`, `methods:tick` (line 692 onwards). The pending-candidate selection at lines 729-735
  (`if job.key == candidate.job then selected = job`) and the `preferred` filter in the attempt loop stop every other
  due job from being attempted.
- `doc/recipes/prt-bridge.lua`, `methods:jobs` (line 348 onwards). It derives the open-ended cleanups:
  `eliminateMatchByTimeout` (line 407), `eliminateInnerTournament` (line 426), `tryRecoveringBond` (line 442).
- `doc/recipes/prt-transactions.lua`, `methods:submit`. A resubmission of the same job waits `bump_blocks`
  (line 188; default 3 at line 306).

### Evidence and test

`bugs/R1-A8-4/` contains `test.lua` and `README.md`. Run it with `bugs/run.sh R1-A8-4`. It takes about a second and
uses no chain and no machine.

The test drives the real `bridge.tick`, `attempt` and `jobs`, and the real journal (nonces, pending candidate, bump
interval, replacement), over a mock chain. Only the bridge's `refresh` and `prepare` are stubbed. One tournament holds
two matches:

- a match of two adversary claims that becomes eliminable by timeout;
- a match of the honest claim `H`, on turn from tip 9 with deadline block 20 (11 blocks on its clock).

The mock chain includes every transaction 6 blocks after its nonce's first publication, so every inclusion fits well
within one inclusion budget. The test asserts R4: the honest `advanceMatch` lands before block 20. The test prints
this on audit/prt2 and exits 1, deterministically (five runs):

```
control (no pending cleanup):
  tip 9: published advanceMatch at nonce 0
  honest advanceMatch due from tip 9, window closes at block 20: first published at tip 9, lands in block 15
pending cleanup, included 6 blocks after publication:
  tip 8: published eliminateMatchByTimeout at nonce 0
  tip 11: published eliminateMatchByTimeout at nonce 0
  tip 14: published advanceMatch at nonce 1
  honest advanceMatch due from tip 9, window closes at block 20: first published at tip 14, lands in block 20
informational: pending cleanup never included:
  ... (eliminateMatchByTimeout re-published at tips 8, 11, 14, 17; advanceMatch never published)
VIOLATED: R4: with every transaction included 6 blocks after publication, the honest advanceMatch must land before its deadline (block 20) although a cleanup of another match is pending (control: published at tip 9, lands in block 15; with the pending cleanup: published at tip 14, lands in block 20)
```

The control (nothing pending) is a setup check that exits 2 if it fails. The third scenario is printed for
information only.

The prover's original version asserted two things that the threat model does not require:

- that the move is published at the same tip as in the control ("no delay");
- that the move is published even when the chain never includes the cleanup.

The reviewer replaced both with the inclusion-window assertion above. With the fix suggested below, applied to a
scratch copy, the test exits 0 (`advanceMatch` replaces the cleanup at nonce 0 at tip 9 and lands in block 14), and
`doc/recipes/prt-bridge-test.lua` still exits 0.

Models: hunted, proved and reviewed on Opus 5.5. No fallback was used.

### Trigger and reachability

The adversary needs a match of two of its own Sybil claims, which section 7 allows: "Post any number of claims
(Sybils) ... and abandon or defend them at will"; "Hold any claim". It times that match so that it becomes
eliminable shortly before the honest claim comes on turn, for example at the block before the adversary's own
`advanceMatch` against the honest claim. The adversary controls both deadlines, because it chooses when its claims
join and when they stop answering. The honest bridge runs with cleanup on by default (`crisium.lua`: `cleanup =
options.cleanup ~= "no"`), so it publishes the elimination. The honest move then waits for that elimination's
inclusion.

The delay is bounded by one pending transaction per honest response. Once the cleanup is mined, nothing is pending,
and expiry order puts the honest move first. The same holds for the honest claim's own open-ended jobs
(`tryRecoveringBond`, `stageTournamentResult`).

The harm needs the honest claim's balance at a turn to be less than two inclusions. That state is reachable within
the deployed model. Dave's root allowance is `C + 2G + (L - 1)(T + 2G)` (`ClockBudgets.maxAllowance`), and an honest
claim that has absorbed censorship up to `C` keeps only the in-flight reserve `G` for its next response. The section
7 adversary may censor within the clocks. Alternatively, the adversary can repeat the trigger at many honest turns
and raise chain activity so that each inclusion approaches `G`. The excess of every honest response is then drawn
from the same ledger.

### Rating

1. Out of scope: no. The trigger is a Sybil match timed by the adversary, an ordinary capability in section 7. It
   needs no machine API access by an untrusted party, no unguaranteed directory, no snapshot or deep chain reorg,
   and no violation of A1 to A8 by the deployment. The pinned Dave clocks follow their own model, and the bridge's
   delay defeats that model.
2. Role: Support. AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support. No production deployment runs
   the player, the bridge or the CLI." This clause covers `prt-bridge.lua` and `prt-transactions.lua`. Section 3: "A
   defect that only a support component shows is Medium when it would rate High or Critical in the role the
   component stands in for, such as ... the honest operator for an implementation of an operator ... Any other
   support defect is Low." The bridge stands in for the honest operator's "Submitting transactions."
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium." This
   applies if the stood-in rating (step 4) is High or Critical. No other listed High or Medium case fits better.
4. Critical, in the stood-in honest-operator role: R4 requires that "The honest operator observes the chain and
   submits its transactions within the dispute clocks." Section 8 says: "violating any rule or obligation at a
   reachable state, or anywhere on the honest operator's path, is critical." The violation happens at a reachable
   state: an honest claim on turn with a balance of more than one inclusion and less than two, while a cleanup is
   pending. Every transaction lands within one inclusion, yet the honest response lands after its clock expires
   (the test: block 20 against deadline 20). That is a completeness failure under section 1. So the defect would be
   Critical in the honest-operator role, and Medium as a support defect.

Two readings:

- (a) Medium, preferred. Dave's dimensioning provisions one inclusion per honest response and charges any excess to
  a non-refillable budget. That makes an adversary-triggered extra inclusion an erosion of the clocks that A7 sizes
  "for the honest claim", and a lost move once the balance is at its reserve.
- (b) Low. The goal's assumption "the chain includes its transactions within the dispute clocks" is read to absorb
  any bounded inclusion latency, so a delay of one extra inclusion per response never breaks R4 unless the clocks
  are sized tighter than two inclusions per response.

What decides between them is whether the threat model's clocks budget one inclusion per honest response, as the
pinned Dave model does, or leave unstated slack for honest self-delay.

### Possible solution and risks

In `methods:tick`, keep the pending job only when it expires no later than the earliest due job. For example:
`if job.key == candidate.job and job.last <= eligible[1].last then selected = job`. Otherwise the earliest-expiring
job replaces the pending candidate at the same nonce, through the existing `obsolete` path.

Risks:

- The replacement must outbid the pending candidate (+15%), so at the fee ceiling it is blocked like any bump.
- The dropped cleanup goes back to the queue. It is permissionless and has no deadline, so the only loss is a later
  cleanup.
- Oscillation between two deadline-bound jobs is still prevented, because the pending job is kept whenever it is
  the earliest.

A further option is to skip bump waiting when the selected job differs from the pending one, which the journal
already does. The other-epoch branch has the same pattern ("Another epoch's pending transaction is left alone until
it is mined") and deserves the same review.

### Risk of not fixing it

The bridge is not run by any production deployment, so no deployed dispute is exposed. Anyone who copies the
reference player's scheduling into a validator node inherits it. An adversary with Sybil claims can then add up to
one inclusion of delay to each honest response, eroding the honest claim's clock and, at its margin, eliminating it
by timeout. The demos and tests built on the bridge can also lose an honest claim under congestion. Running with
`--cleanup=no` avoids the permissionless cleanups, but not the honest claim's own open-ended jobs
(`tryRecoveringBond`, `stageTournamentResult`).

## R1-BOUNDARY-1

**Title.** The PRT bridge fetches, keeps, re-sorts and rescans every log of the shared, permissionless tournament
factory on every observation, so its chain observation grows with chain activity that does not belong to the
application.

**Severity.** Medium

### Problem

`methods:observe` of the PRT bridge fetches the logs of `{factory, consensus, root}` from `first_block` (the seal block,
as `prt-epoch.lua` starts it) up to the observation head. The tournament factory is shared: `DaveAppFactory` passes
one immutable `TOURNAMENT_FACTORY` to every `DaveConsensus` it creates, and `MultiLevelTournamentFactory.instantiate`
is permissionless (its own interface says "Anyone can call `instantiate`"). Every `TournamentCreated` log that the
factory emits after the seal, whether from another application's epoch seal or from anyone calling `instantiate`, is
therefore fetched, kept for the life of the bridge in `prt-log-history.lua` and in the bridge's `decoded` cache,
appended to `logs`, `table.sort`ed and walked again on every observation, and put into `snapshot.events`, which
later bridge code walks again. The bridge only needs its own root's `TournamentCreated`, which is in the seal block,
and it discards every foreign one in the walk (`address == self.root` fails). `TournamentCreated` has no indexed
parameters, so the factory's logs cannot be narrowed by topic; the bridge must bound the block range instead.

This does not break the goal by itself (the bridge is not run by any deployment), but it violates R12, which requires
the honest operator's chain observation not to grow with chain activity that does not belong to the application. A
real operator built like this bridge would be slowed, per observation and in memory, by foreign activity during an
open dispute, eating into the clock margin that R4 and A7 rely on.

### Component, role and area

The PRT bridge in `doc/recipes` (chain observation), with the log history it uses. AUDIT.md: "The PRT player and
bridge in `doc/recipes`, ... | Support. No production deployment runs the player, the bridge or the CLI." It stands
in for the honest operator's observing of the chain.

### Location

- `doc/recipes/prt-bridge.lua`, `methods:observe`: line 57 (`addresses = { self.factory, self.consensus, self.root }`),
  lines 58-59 (`first_blocks[self.factory] = self.first_block`, no upper bound), the fetch loop (66-105,
  `logs[#logs + 1] = log` for every factory log), `table.sort(logs, log_less)` (line 110), the walk that adds every
  decoded event to `events` (111-179), and the returned `events` and `logs`.
- `doc/recipes/prt-log-history.lua`, `get_logs_of`/`fetch`: keeps every fetched log per address until a reset.
- `doc/recipes/prt-epoch.lua` (around line 126): `first_block = self.seal_block` when it creates the bridge.
- Pinned Dave v3.0.0-alpha.7: `prt/contracts/src/ITournamentFactory.sol` (event without indexed fields, "Anyone can
  call `instantiate`"), `MultiLevelTournamentFactory.instantiate` (lines 79-92, external, no access control, emits
  `TournamentCreated`), `cartesi-rollups/contracts/src/DaveAppFactory.sol` (one immutable `TOURNAMENT_FACTORY` for
  every application).

### Evidence and test

`bugs/R1-BOUNDARY-1/` contains `test.lua` and `README.md`. Run `bugs/run.sh R1-BOUNDARY-1` (under a second; an
optional argument sets K, default 3000). The test builds a mock chain in the style of the pruning fixture of
`prt-bridge-test.lua` (log records behind read-counting proxies, a stub ABI returning decoded events) with a fixed
application history: the root's `TournamentCreated` and `EpochSealed` in seal block 1, and three events of the root.
After the seal, the factory emits K `TournamentCreated` logs of other tournaments. A bridge `new_observer` (with
`first_block = seal_block = 1`, as `prt-epoch.lua` starts it) observes once, then four more times while the head
advances with no new log. It runs once with K = 0 and once with K = 3000 and requires four counts to stay within 64 of
the control: log records handed to the bridge, `#snapshot.logs`, `#snapshot.events`, and field reads on log records
during the four later observations. On audit/prt2 it prints:

```
fetched  control (K=0) = 5        with K=3000 foreign factory logs = 3005     grows with K
logs     control (K=0) = 5        with K=3000 foreign factory logs = 3005     grows with K
events   control (K=0) = 5        with K=3000 foreign factory logs = 3005     grows with K
reads    control (K=0) = 352      with K=3000 foreign factory logs = 852972   grows with K
VIOLATED: R12: the honest operator's chain observation 'must not grow ... with chain activity that does not belong to the application' (foreign TournamentCreated logs of the shared tournament factory)
run.sh: R1-BOUNDARY-1: exit 1 (bug present)
```

The `reads` count varies slightly between runs (for example 842812, 852972) because Lua 5.4's `table.sort`
randomizes its pivot on large arrays; it is always about 280 reads per foreign log against 352 in the control, and
the exit status is always 1. The prover ran it twice and with K = 10000 (exit 1 each time); the reviewer re-ran it
twice (exit 1 both times).

The reviewer also checked that the test passes once the defect is fixed: a scratch copy of `prt-bridge.lua` that,
when `seal_block` is known, reads the factory once over `[first_block, seal_block]`, keeps only the root's
`TournamentCreated`, and fetches only `{consensus, root}` incrementally, makes the test print 5, 5, 5, 332 for both
K = 0 and K = 3000 (and for K = 10000) and exit 0. The test asserts the R12 property, not the current design.

### Trigger and reachability

Anyone, during an open dispute of the application: by calling `instantiate` on the shared factory any number of
times (section 7: "Raise activity on the chain that does not belong to the application"), or with no adversary at
all, through other applications created by the same `DaveAppFactory`, each of whose epoch seals emits a
`TournamentCreated` on the same factory. The bridge observes on every `refresh` (`methods:refresh`, line 337, called again at line 601), for as long as the epoch's dispute is open. No emulator state is involved; the trigger is ordinary
chain activity, so there is no reachability condition.

### Rating

1. Out of scope: no. The trigger is chain activity, which section 7 grants the adversary ("Raise activity on the chain
   that does not belong to the application, such as inputs to other applications that share its input record"). The
   closest exclusion, "Average-case performance that does not change the worst-case cost of any operation listed in
   R12", does not fit: the worst-case cost of each observation and the bridge's memory grow without bound with K.
   AUDIT.md excludes "the validator nodes (the sling node ... and the Cartesi Rollups Node)", not the bridge, which
   its table lists as in-scope Support.
2. Role: Support (AUDIT.md table above). Section 3: "Support. ... Examples are ... implementations of an operator that
   no deployment runs ... A defect that only a support component shows is Medium when it would rate High or Critical
   in the role the component stands in for, such as ... the honest operator for an implementation of an operator".
   This clause covers the bridge: it is the chain-observation part of an implementation of an operator, so it stands
   in for the honest operator, and section 2 lists "Observing the chain" on the honest operator's path. Step 2 also
   says "A defect that only a support component shows is never above Medium".
3. High and Medium cases: the Medium case "A defect that only a support component shows, when section 3 rates it
   Medium" fits, given the rating in the honest-operator role from step 4. No High case fits in that role: the
   constant-factor case speaks of "an operation listed in R12" multiplied "by a constant factor", while here the
   growth is unbounded in K.
4. Critical (in the stood-in role): R12, "The honest operator's own work outside the emulator, such as observing the
   chain, keeping and persisting its own records, and restarting, has a bounded cost per input, per yield, and per
   match, and its total grows only with the inputs, yields, and matches of the epochs still open. That total must not
   grow with the application's age, with the number of past epochs, or with chain activity that does not belong to
   the application." Section 8: "violating any rule or obligation ... anywhere on the honest operator's path, is
   critical." In the honest-operator role this is Critical, so section 3 rates the support defect Medium.

Both readings considered give Medium: whether the stood-in rating is Critical (step 4) or High (if one read the
constant-factor case as covering it), section 3 maps it to Medium. The bridge would be Low only if it were not taken
to stand in for the honest operator, which the quoted example of section 3 contradicts.

### Possible solution and risks

When the seal block is known, read the factory only over `[first_block, seal_block]` (once, then cache), keep only the
`TournamentCreated` whose `tournament` is the root named by the consensus's `EpochSealed`, and fetch only the consensus
and the tournaments reached from the root incrementally. Alternatively, take the root's creation log from the seal
transaction's receipt. Risks: the seal block can hold other applications' `TournamentCreated` logs (bounded by the
block gas limit, so a constant); a reorg of the seal block must still reset the cached creation log (the bridge
already asserts the seal is canonical on every observation); and a bridge started without `seal_block` (the generic
path) must keep reading the factory until it finds the root, then stop. The related full re-sort and rescan of the
application's own logs on each observation is a separate candidate (R1-R12-3).

### Risk of not fixing it

The bridge is not run by any deployment, so no deployment is exposed directly. Code that follows it as a reference
for a validator node inherits a chain observation whose time and memory per observation grow with every
`TournamentCreated` on the shared factory during a dispute, which anyone can raise at gas cost and which other
applications raise without intent; with enough of it, observations slow until the operator risks missing its dispute
clocks. Outside the code, an operator can only shorten the dispute window it watches or restart the bridge, which
does not help because a restart refetches from the seal block.

## R1-BOUNDARY-3

**Title.** crisium's seal lookup fetches, keeps and re-decodes every consensus log since the deployment block, so the
player's restart and each new epoch cost work and memory that grow with the number of past epochs.

**Severity.** Medium (preferred reading). Low under a reading that would excuse the growth because each past epoch
adds only a few small logs (see Rating).

### Problem

`get_seal(number)` in `doc/recipes/crisium.lua` looks up the seal of one epoch by asking the process-wide
`seal_history` (a `prt-log-history` object) for every log the consensus has emitted since
`getDeploymentBlockNumber()`, with no topic filter. It then decodes them in order with `abi:event` until it finds
`EpochSealed(number)`. `open_epochs` calls it once for every epoch it opens, and `pass()` calls `open_epochs` on every
pass. `prt-log-history.lua` never drops a log except on a reorg rewind. The result:

- a relaunch fetches every consensus log since deployment (`EpochSealed`, `EpochStaged`, `SentryClaim`, ...);
- the process keeps all of them in memory for as long as it lives;
- every new epoch decodes all of them again.

Only the seal of the previous epoch is needed, and `epochNumber` is an indexed topic of `EpochSealed`
(`IDaveConsensus.sol`), so a constant-cost lookup is available.

This does not break the goal of section 1 at realistic ages, since the logs are small. It violates the letter of R12:
"The honest operator's own work outside the emulator, such as observing the chain, keeping and persisting its own
records, and restarting, has a bounded cost per input, per yield, and per match, and its total grows only with the
inputs, yields, and matches of the epochs still open. That total must not grow with the application's age, with the
number of past epochs, or with chain activity that does not belong to the application."

### Component, role and area

The PRT player process `doc/recipes/crisium.lua`, with `doc/recipes/prt-log-history.lua`. AUDIT.md role: "The PRT
player and bridge in `doc/recipes`, ... | Support. No production deployment runs the player, the bridge or the CLI."
It stands in for the honest operator's chain observation and restart. Area: observing consensus seals.

### Location

- `doc/recipes/crisium.lua`: `first_block = getDeploymentBlockNumber()` (line 125); `seal_history =
  log_history.new(chain)` and `get_seal` (lines 207-219); `open_epochs` (from line 222), which `pass()` calls.
- `doc/recipes/prt-log-history.lua`: `get_logs`/`get_logs_of` keep every fetched log in `self.logs` and never prune
  it.

### Evidence and test

`bugs/R1-BOUNDARY-3/` contains `README.md` and `test.lua`. Run it with `bugs/run.sh R1-BOUNDARY-3` (optional
arguments `E_small E_large`, default 2 and 200). Set `CRISIUM_LUA=<file>` to test a candidate fix. The test loads the
real `crisium.lua` in-process, with the real `prt-log-history.lua` and the real ABI decoding of the pinned Dave
artifacts (`bugs/harness/work/dave/patched`). It stubs only the transport (`prt-rpc`, an in-memory mock chain), the
checkpoint loader and player (`prt`), the epoch listener (`prt-epoch`), `prt-bridge.read_geometry`, `prt-dishonest`
and `prt-websocket`, none of which takes part in `get_seal`. The mock consensus holds `EpochSealed(k)` for
k = 0..E-1 and `EpochStaged(k)` for k = 0..E-2. The test runs two phases:

1. A restart from checkpoint `epoch-E`, which needs the seal of epoch E-1.
2. Epoch E is sealed, checkpoint `epoch-(E+1)` appears, and the player opens epoch E+1.

In each phase the test counts the logs `eth_getLogs` hands over and the logs `abi:event` decodes. It requires both
counts to stay within 4 logs of the E = 2 value at E = 200. On audit/prt2 it prints the following (plus a harmless
"Relink ... IFUNC" loader warning on stderr) and exits 1:

```
past epochs    2 (consensus logs    5): restart fetched    3 decoded    3 (1 requests) | new epoch fetched    2 decoded    5 (1 requests)
past epochs  200 (consensus logs  401): restart fetched  399 decoded  399 (1 requests) | new epoch fetched    2 decoded  401 (1 requests)
VIOLATION restart: logs fetched grow from 3 (2 past epochs) to 399 (200 past epochs)
VIOLATION restart: logs decoded grow from 3 (2 past epochs) to 399 (200 past epochs)
VIOLATION new epoch: logs decoded grow from 5 (2 past epochs) to 401 (200 past epochs)
VIOLATED: R12: crisium's seal lookup must not grow with the number of past epochs (restart and per-epoch observation cost)
run.sh: R1-BOUNDARY-3: exit 1 (bug present)
```

The reviewer re-ran it four times with the same output and exit 1. The reviewer also ran a scratch copy of
`crisium.lua` whose `get_seal` uses a fresh history filtered by `abi:topics("EpochSealed", number)`. With that copy
the test printed 1 fetched and 1 decoded in both phases for both E, and exited 0. So the test fails because of the
defect and passes once it is fixed. All agents ran on Opus 5.5; no fallback was used.

### Trigger and reachability

No adversary is needed. The passage of time triggers it: every sealed epoch adds at least an `EpochStaged` and an
`EpochSealed` log, and sentry claims add `SentryClaim` logs. Every relaunch pays for the whole history once, and every
epoch opened afterwards decodes it again. Memory grows for the life of the process. Every deployment reaches this
state after enough epochs.

### Rating

1. Out of scope: no. The trigger is the normal sealing of epochs. None of the exclusions applies. The entry "Average-case
   performance that does not change the worst-case cost of any operation listed in R12" does not cover it. The
   operator-work clause of R12 is a separate requirement, and the defect makes the worst-case cost of a restart and of
   an epoch opening grow with age without bound.
2. Role: Support. Per AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support". Section 3: "A defect that
   only a support component shows is Medium when it would rate High or Critical in the role the component stands in
   for, such as ... the honest operator for an implementation of an operator". crisium.lua is "an implementation of
   an operator that no deployment runs", so it stands in for the honest operator. This clause covers the component.
   No component in another role in scope shares the defect (validator nodes are out of scope per AUDIT.md).
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium." It applies
   if the defect would rate High or Critical in the honest-operator role. In that role, the High case "multiply the
   worst-case cost of an operation listed in R12 by a constant factor" does not fit, because the growth is unbounded
   in the number of past epochs, not a constant factor. Step 4 then applies to the stand-in role.
4. Critical (in the stand-in role): "violating any rule or obligation at a reachable state, or anywhere on the honest
   operator's path, is critical". The honest operator's path includes "Observing the chain" and "Restarting after a
   stop" (section 2). R12 says the operator's own work "must not grow with the application's age, with the number of
   past epochs". So the defect is Critical for the honest operator, which makes it **Medium** for this support
   component.

Two readings. R12 has no materiality threshold. The preferred reading takes its "must not grow" literally: the
stand-in rating is Critical, so the support rating is Medium. Another reading would treat growth of a few hundred
bytes and a few decodes per past epoch as no real threat to the operator's provisioned resources, so it would not
rate High or Critical even for a real operator. The defect would then be Low. What would decide is whether R12's
operator-work clause allows growth that is linear in the age but small per epoch. Its text says it does not.

### Possible solution and risks

In `get_seal`, fetch only the needed log: filter the query by `abi:topics("EpochSealed", number)`. Alternatively,
keep a seal history whose start block moves to the previous seal's block, and drop logs older than the oldest open
epoch. In either case the process should not keep logs of finished epochs. Risks:

- The filtered query must keep the reorg handling of `prt-log-history`, with the history keyed per epoch number.
- `first_input_block` is derived from `previous_seal.log.blockNumber`, so the returned event must still carry its
  log.
- An RPC node still scans its index from the deployment block for a topic-filtered query. That is node-side cost, not
  the operator's own records.

### Risk of not fixing it

The player is a reference implementation that no deployment runs. Anyone who models a production node on it inherits
observation work and memory that grow with the application's lifetime, and restarts that slow down with age. That
would eventually conflict with A7 sizing for a long-lived application. No adversary can accelerate it beyond the rate
at which epochs are sealed and sentry claims are posted. No option of the player mitigates it: `--first-epoch` does not
change where `get_seal` starts, which is always the deployment block.

## R1-O1-3

**Title.** The PRT player adopts the template without rebuilding its cached hash-tree data. `prt.store_first_epoch_checkpoint` records a root read from that cache, crisium compares it with the on-chain template hash, and a valid template whose cache is stale is refused on every start.

**Severity.** Medium

### Problem

`prt.store_first_epoch_checkpoint` is how the PRT player adopts the application's template. `prt-demo.lua` calls it before it launches the players, and once more for each sentinel. The function clones the template directory and loads the clone with `cartesi.machine(temporary_directory)`, which does not pass `{ clear_hash_tree = true }`. On the tree loaded from the cache, it runs `assert_rolling_template`, whose pristine-uarch check calls `get_node_hash`. It then writes `machine:get_root_hash()` into `epoch.json` as `initial_state_hash` and `final_state_hash`. The root it writes therefore comes from the cached hash-tree data, not from the contents.

Next, `crisium.lua` asserts that this `final_state_hash` equals the application's on-chain template hash ("epoch 0's checkpoint is not the template"). That is a comparison with the on-chain commitment made before any rebuild, which O1 forbids. The rebuild happens only later, in `new_stored_player`.

Take a valid template that someone else distributed and whose cached data does not match its contents. The player records a wrong hash for it and refuses to defend it. The checkpoint directory then exists, so on a relaunch `store_first_epoch_checkpoint` returns early, keeps the wrong hash, and the refusal repeats on every start.

In the role the player stands in for, this is a completeness failure: the honest operator cannot obtain its valid template, so it cannot respond, and a dishonest claim can win by default. The reverse case only fails later. If the cache matches the on-chain hash but the contents do not, crisium passes and `new_stored_player`'s rebuild then aborts. So the defect is a stall, not the adoption of a wrong state.

### Component, role and area

The component is the PRT player in `doc/recipes`. AUDIT.md lists it as "The PRT player and bridge in `doc/recipes` ... | Support. No production deployment runs the player". The area is template adoption and the epoch-0 checkpoint.

### Location

- `doc/recipes/prt.lua`, `store_first_epoch_checkpoint`, lines 2743-2776. The load without a rebuild is at line 2757: `cartesi.machine(temporary_directory)`. The function also calls `assert_rolling_template` (lines 956-969) and records `template_hash = machine:get_root_hash()`.
- `doc/recipes/crisium.lua:236`: `assert(manifest.final_state_hash:lower() == template_hash, "epoch 0's checkpoint is not the template")`.
- `doc/recipes/prt-demo.lua:76` and `:131` call the function. `doc/recipes/prt.lua` `new_stored_player`, lines 3206-3218, is the only place where the template is rebuilt.

### Evidence and test

`bugs/R1-O1-3/` contains `test.lua` and `README.md`. Run the test with `bugs/run.sh R1-O1-3`. It takes about 3 s and needs the in-tree build and `bugs/harness/work/configs/baremetal-template`. It does the following:

1. It stores the harness `baremetal-template`, a valid template whose content hash is `0x428a6bb8...ac75`, together with its cached hash-tree data.
2. Control: on an untouched copy, `store_first_epoch_checkpoint` records the content hash.
3. It makes only the cached data stale. It overwrites 32 bytes at offset 96 of the RAM `.dht` and marks the RAM `.dpt` clean. No `.bin` file and no `config.json` changes. Control: loading with `clear_hash_tree` still gives `0x428a...ac75`.
4. It calls `prt.store_first_epoch_checkpoint(template, prt.new_geometry(10), out)` and requires that the recorded hashes equal the content hash.

On audit/prt2 it prints the following. The reviewer re-ran it twice and got the same output and exit 1 both times:

```
control: untouched template, epoch-0 checkpoint records 0x428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
template content hash (rebuilt with clear_hash_tree): 0x428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
root read from the stale cached data (no rebuild):    0x0f8f9593489424e02efc1b2d019ef86be51d4a29d95bb2b2e8e5faf93ac63f82
epoch-0 checkpoint initial_state_hash: 0x0f8f9593489424e02efc1b2d019ef86be51d4a29d95bb2b2e8e5faf93ac63f82
epoch-0 checkpoint final_state_hash:   0x0f8f9593489424e02efc1b2d019ef86be51d4a29d95bb2b2e8e5faf93ac63f82
epoch-0 checkpoint machine rebuilt:    0x428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75 (differs from the manifest: new_stored_player would abort too)
VIOLATED: O1: adopting a stored machine rebuilds the cached hash-tree data, and only then compares/records the root hash (...)
run.sh: R1-O1-3: exit 1 (bug present)
```

The reviewer then tested the fix. It placed an out-of-tree copy of `prt.lua` first on `LUA_PATH_5_4`, with `{ clear_hash_tree = true }` added to that one load. The test then printed `0x428a...ac75` for both recorded hashes and "(matches the manifest)", and exited 0. Opus 5.5 found, proved and reviewed the issue, with no fallback.

### Trigger and reachability

Anyone who distributes the template directory can trigger this. They hand the operator a valid template whose cached hash-tree data does not match its contents: a stale, corrupted or deliberately altered `.dht`/`.dpt`, or a dirty-page record that is wrongly clean. The manual says the stored template "is the artifact distributed to anyone who wants to run the application in their own Cartesi Node", and it tells operators to load a directory they did not produce with `--clear-hash-tree` "before trusting its state hash".

Such a directory is still a valid template. Its contents, and the content hash rebuilt from them, are unchanged. THREAT_MODEL section 4 says: "A snapshot's cached hash-tree data is not part of any valid-template condition". No machine state has to be reached, because the trigger is the directory the operator adopts.

### Rating

1. **Out of scope: no, under the reading judged best supported.** The exclusion checked is "Defects that need the cached hash-tree data of a stored machine the operator did not produce to survive its adoption without a rebuild (O1)." Here the cache survives because the shipped tool itself skips the rebuild. Section 5 makes that the tool's defect: "O1 and O2 bind the emulator too. The tools and reference implementations that ship with it must follow them". That clause covers this component, a reference player shipped in `doc/recipes`. The snapshot exclusion ("loading a snapshot ... that does not meet the conditions of a valid template") does not apply, because the template is valid.
2. **Role: Support.** AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support." Section 3: "A defect that only a support component shows is Medium when it would rate High or Critical in the role the component stands in for, such as ... the honest operator for an implementation of an operator". The player is an implementation of an operator. No honest-operator component shares the defect: the emulator's `clear_hash_tree` rebuild works, as the test's control shows.
3. **High and Medium cases: Medium.** "A defect that only a support component shows, when section 3 rates it Medium." The stood-in role's rating, given in step 4, is Critical. No High or Medium case fits it in the honest-operator role, since it is not a case about unreachable states or data the operator may decline.
4. **Critical in the stood-in role.** Section 2, honest operator's path: "Obtaining its valid template. For a template the operator did not produce, this includes rebuilding its cached hash-tree data (O1)." O1: "rebuilds the cached hash-tree data from the contents when loading it, and only then compares the root hash with the on-chain commitment." Section 1, completeness failure: the honest operator "cannot respond in time". Section 8: "violating any rule or obligation ... anywhere on the honest operator's path, is critical." That is Critical in the honest-operator role, so Medium for the support player.

There is a second reading. It applies the section 8 exclusion "need the cached hash-tree data ... to survive its adoption without a rebuild (O1)" literally, to any component, and then the issue is Out of scope. The facts that decide between the readings are textual. The exclusion would have to cover the case where the shipped tool's own adoption skips the rebuild. Section 5 says those tools "must follow" O1, and that a defect that "defeats the rebuild itself" is not excused. That supports the first reading.

### Possible solution and risks

In `store_first_epoch_checkpoint`, load the clone with `cartesi.machine(temporary_directory, { clear_hash_tree = true })` before `assert_rolling_template` and `get_root_hash`. Optionally, compare the result with the on-chain template hash there. The rebuild costs one full hash of the template at adoption, which `new_stored_player` already pays. It does not rewrite the stale cache in the checkpoint directory. Later loads of that directory rebuild (`new_stored_player`) or come from the operator's own process, so this is harmless. Alternatively, rebuild in the clone with sharing so that the stored cache is refreshed too.

Checkpoints written before the fix keep the wrong hash, because the function returns early when the directory exists. Operators must delete `checkpoints/epoch-0` once.

### Risk of not fixing it

An operator who runs the reference player on a template it did not produce, and whose cached data is stale or was altered by the distributor, never defends epoch 0. Until someone notices and rebuilds the template by hand, a dishonest claim can win by default. Because the player is support, no production deployment is exposed directly. The risk is that the reference implementation teaches the pattern O1 forbids: trusting the cached root of a received template. Outside the code, operators can mitigate it by re-storing a received template with `--clear-hash-tree` before handing it to the player.

## R1-O2-1

**Title.** After a power loss, the PRT stored player restarts from its unsynced backup clone (`machine.revert`),
discards the synced epoch machine, and trusts the clone's cached hash tree, recording wrong root hashes.

**Severity.** Medium

### Problem

`stored_machine_pair_methods:commit` in `doc/recipes/prt.lua` refreshes the backup of the epoch machine after
`state.json` already records the new input boundary: it removes `machine.revert`, clones the (synced) epoch machine
into `machine.revert` under that final name, and only then syncs it. If the process stops between the clone and its
sync (power loss), `machine.revert` is a directory that was being written when its process stopped, so O2 does not
guarantee it, while the epoch machine `machine`, synced by `commit_epoch_state` before `state.json` was written, is
guaranteed.

On relaunch, `revert_interrupted_input` prefers the backup: if the backup's contents, rehashed with
`clear_hash_tree`, match the root hash in `state.json`, it removes the guaranteed epoch machine and replaces it with
a clone of the unsynced backup. `reopen_epoch_directory` then loads that clone with `SHARING_ALL` and without
`clear_hash_tree` (`new_stored_machine`), so the player keeps using cached hash-tree data that was never synced. The
contents check cannot detect damage to that cached data, and the load check compares only the cached root. The
player then advances, and as pages change their stale leaf hashes enter the root: it silently records root hashes
(and would build computation hashes and proofs) that are not the content hashes of its machine. An honest operator
built like this would commit a wrong claim and lose its dispute, which is a completeness failure of section 1 in
the role the player stands in for.

### Component, role and area

The PRT player in `doc/recipes` (`prt.lua`, stored player and its epoch directory, crash recovery). AUDIT.md table:
"The PRT player and bridge in `doc/recipes`, the `cartesi-machine` CLI, and the Lua helper libraries ... | Support.
No production deployment runs the player, the bridge or the CLI." It stands in for the honest operator. The
emulator's `clone_stored`, `sync_stored` and `load` behave as documented; no component in another role shows the
defect.

### Location

- `doc/recipes/prt.lua`, `stored_machine_pair_methods:commit` (clone into `<directory>.revert` under its final
  name, sync afterwards; around lines 1137-1150), called by `run_next_input` right after `commit_epoch_state`
  (around lines 2268-2270).
- `doc/recipes/prt.lua`, `revert_interrupted_input` (around lines 2864-2880): picks the backup by a content rehash
  (`get_stored_root_hash`, lines 2850-2861), removes the synced epoch machine, clones the backup without a sync.
- `doc/recipes/prt.lua`, `reopen_epoch_directory` (around lines 3066-3102) and `new_stored_machine` (lines
  1007-1012): load the epoch machine with `SHARING_ALL` and without `clear_hash_tree`.

### Evidence and test

`bugs/R1-O2-1/` contains:

- `test.lua`: runs `doc/recipes/prt.lua`'s stored player, loaded unchanged as a module, in child processes on the
  harness `baremetal-template` configuration, with two advance inputs. (1) Control: a fresh epoch directory gets
  inputs 0 and 1 without a stop and records root R. (2) Crash: a fresh epoch directory gets input 0; the power loss
  is modelled right before the player syncs the not-yet-synced clone of the epoch machine (`machine.revert`): one
  4 KiB block of that clone's RAM `.dht` (leaf hashes of RAM pages 0..127) reads back as zeros, and the process
  exits with `os.exit` without cleanup. Directories already synced are untouched. (3) Relaunch: a new process opens
  the same epoch directory and is delivered inputs 0 and 1, as a restarted listener does; it records root R'. The
  test asserts R' == R and also prints the relaunched machine's content hash rebuilt with `clear_hash_tree`.
- `player.lua`: the driver (`run` and `crash` modes; `crash` wraps `clone_stored`/`sync_stored` to model the loss).
- `README.md`: description of the mechanism and the test.

Run `bugs/run.sh R1-O2-1` (about 10 s, about 100 MB in a `mktemp -d` directory that it removes). On audit/prt2 it
exits 1, deterministically (re-run twice by the reviewer), printing:

```
POWER LOSS before syncing /tmp/r1-o2-1.XXXXXX/crashed/machine.revert
uninterrupted player, root after input 1:          0x45dfda061ef00a368c1950bbfdca9bd0b2c6a9c0270b63d0e16e3db3dec0cba1
relaunched player, root it records after input 1:  0x2ff8357c3ac58955664922c4616289535d729a6d82f113c9de5d5f8d6a578a12
relaunched player's machine, contents rehashed:    0x45dfda061ef00a368c1950bbfdca9bd0b2c6a9c0270b63d0e16e3db3dec0cba1
VIOLATED: R4/O2: after a power loss the stored player must resume from a guaranteed directory and record the same root hash as an uninterrupted player (...)
run.sh: R1-O2-1: exit 1 (bug present)
```

The relaunched player passes all its own checks; its machine's contents hash to R, but it records R'. The reviewer
applied a tmp+sync+rename commit (clone into `machine.revert.tmp`, sync, remove the old backup, `rename_stored`) to a
scratch copy of `prt.lua` placed first on `LUA_PATH_5_4`; the modelled loss then hits `machine.revert.tmp`, the
relaunch falls back to the synced epoch machine, records R, and the test exits 0. Found, proved and reviewed on
Opus 5.5 (no fallback).

### Trigger and reachability

A host stop (power loss) of the player process after the clone into `machine.revert` and before its sync, at the end
of any input, followed by a relaunch on the same epoch directory. No adversary action is needed beyond inputs that
make the guest run (any input); the window opens once per input. The damaged state is the cached hash-tree data of
an unsynced clone, which O2 explicitly allows to be anything ("leaves every stored directory it was writing or
sharing in an unspecified state"); losing cached data while contents survive is a plausible outcome of unflushed
writeback across separate files. No unreachability argument is involved.

### Rating

1. Out of scope: not excluded. The closest exclusion is "Defects that need the honest operator to reload a stored
   directory that O2 does not guarantee, such as one being written or shared when its process stopped". Here the
   reload of the unguaranteed directory is not an external precondition imposed on the audited code: it is the
   audited component's own choice, and the defect is that choice. Section 5 binds it: "O1 and O2 bind the emulator
   too. The tools and reference implementations that ship with it must follow them", and "A defect that defeats the
   rebuild itself, or that damages a directory while O2 guarantees it, is not excused by them" (the player deletes
   the guaranteed epoch machine). The "Host faults" exclusion applies only "as long as the emulator does not turn
   them into a wrong hash"; the player does turn the stop into a wrong hash.
2. Role: Support (AUDIT.md table above). Section 3: "A defect that only a support component shows is Medium when it
   would rate High or Critical in the role the component stands in for, such as ... the honest operator for an
   implementation of an operator". The player is an implementation of an operator that no deployment runs; it
   stands in for the honest operator. "How to rate" step 2: "A defect that only a support component shows is never
   above Medium."
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium." That
   requires the stood-in rating to be High or Critical, which step 4 gives.
4. Critical (in the stood-in honest-operator role): O2 "The operator discards those directories and resumes from a
   guaranteed one", and R4 "After a stop, it restarts from a directory that O2 guarantees and keeps defending its
   claim", violated on the honest operator's path ("Restarting after a stop (O2)", section 2); the result is a
   completeness failure ("The honest operator computes a wrong hash"). Critical for the honest operator, hence
   Medium for this support component.

Two readings: under the reading above (section 5 binds reference implementations to O2), Medium. Under a literal
reading of the out-of-scope entry ("need the honest operator to reload a stored directory that O2 does not
guarantee"), it would be Out of scope. The second reading would make O2 unenforceable on the very tools section 5
says must follow it, so the first is better supported. The deciding fact is whether the out-of-scope entry covers a
component under audit that itself performs the forbidden reload; the text of section 5 says it does not excuse it.

### Possible solution and risks

Make the backup refresh atomic, as other parts of `prt.lua` already do for checkpoints: clone into
`machine.revert.tmp`, `sync_stored` it, then remove the old `machine.revert` and `rename_stored` the temporary into
place (and sync the epoch directory). Add `machine.revert.tmp` (and the same for `pair`/`agreed` if they use the same
pair) to the names that `clear_epoch_directory` and `remove_epoch_leftovers` remove, so a leftover temporary does not
make reopening fail. Independently, `revert_interrupted_input` should prefer the epoch machine synced before
`state.json` was written when it matches, and the reopened epoch machine could be loaded with `clear_hash_tree` (at
the cost of a full rehash per reopen). Risks: a crash between removing the old backup and the rename leaves no
backup, so the reopen logic must handle the backup's absence (it already falls back to the epoch machine and
re-creates the backup); extra syncs cost I/O per input.

### Risk of not fixing it

The player and its stored mode are a reference implementation, not run by deployments; operators who copy its
crash-recovery design would, after a power loss at the end of an input, silently defend a wrong claim and lose
disputes. Anyone running the recipes for testing can get wrong root hashes after an unclean shutdown. Mitigation
outside the code: after any unclean stop, delete `machine.revert` before relaunching, or rebuild the epoch
directory from the template.

## R1-O2-2

**Title.** After a stop just past the seal commit, reopening the sealed epoch swaps the synced epoch machine for an
unsynced clone and deletes `machine.revert`, so no O2-guaranteed copy is left and a later power loss blocks every
reopen.

**Severity.** Medium

### Problem

`seal_epoch_state` destroys and syncs the epoch machine, commits the sealed `state.json`, and only then removes
`machine.revert`. Suppose the player stops between those last two steps (crash, `kill -9` or power loss). On the
relaunch, `reopen_epoch_directory` calls `revert_interrupted_input`. `machine.revert` rehashes to the sealed root hash,
so branch 1 runs: it removes the synced `machine/`, then runs `clone_stored(machine.revert, machine)` and never calls
`sync_stored`. Next, the sealed-epoch path of `reopen_epoch_directory` removes `machine.revert` ("A sealed epoch no
longer needs the backup").

After that, the epoch directory holds no machine directory that O2 guarantees. `machine/` was changed and never synced,
and the synced backup is gone. On the next relaunch there is no backup, so `revert_interrupted_input` asserts that
`machine/` rehashes to `state.json`'s root hash. If a power loss has dropped the unsynced clone data, that assertion
fails with "the epoch machine does not match its state". Every later relaunch fails the same way. The player has no
fallback, such as clearing the epoch directory and replaying from the epoch checkpoint (`crisium.lua` `new_player`
calls `new_stored_player` directly). The honest player therefore stops defending the sealed epoch's claim, which in
the honest-operator role is a completeness failure (section 1).

### Component, role and area

The PRT stored player in `doc/recipes/prt.lua`, specifically its epoch directory and its restart path. AUDIT.md
assigns it this role: "The PRT player and bridge in `doc/recipes` ... Support. No production deployment runs the
player". It stands in for the honest operator's storing, reloading and restart after a stop.

### Location

- `doc/recipes/prt.lua`, `seal_epoch_state` (about lines 2720-2739): it commits `state.json` before removing
  `machine.revert`.
- `doc/recipes/prt.lua`, `revert_interrupted_input` (about lines 2864-2880): branch 1 runs `clone_stored` with no
  `sync_stored`, while branch 2 does sync its clone.
- `doc/recipes/prt.lua`, `reopen_epoch_directory` (about lines 3124-3127): it removes `machine.revert` for a sealed
  epoch without checking that `machine/` is synced.

### Evidence and test

`bugs/R1-O2-2/` contains three files:

- `test.lua`, the test.
- `player.lua`, the child process. It runs one player step per process: `seal-crash`, `reopen`, and the control's
  `reopen-synced-clone`.
- `README.md`.

Run it with `bugs/run.sh R1-O2-2`. It takes about 15-25 s and needs `strace` and the harness `baremetal-template`
configuration.

The test opens an epoch from `baremetal-template`, runs one input and seals. Through an `fs.exists` hook, the seal
process exits with `os.exit(17, false)` (no cleanup, the disk left as `kill -9` leaves it) right after the sealed
`state.json` commit and before `machine.revert` is removed. The test checks that `state.json` is sealed and that
`machine/` and `machine.revert/` both rehash to its root hash. It then relaunches under `strace -f -y` and makes two
checks:

- **(A)** Some machine directory must remain that matches `state.json` and was synced after its last change to file
  data and directory entries.
- **(B)** The test models a power loss: every file the relaunch changed and did not sync becomes a hole of the same
  size, which O2 allows because it leaves such files unspecified. The next relaunch must then reopen the sealed epoch.

A control in the same run applies the same steps to a relaunch whose `clone_stored` calls are each followed by
`sync_stored`. The control must pass both checks, or the test exits 2.

The reviewer re-ran the test twice on audit/prt2. It exited 1 both times. It prints:

```
control: after the relaunch, machine: matches state.json=true, files changed and not synced=0, entries synced=true
control: relaunch after the power loss: status 0
player: after the relaunch, machine: matches state.json=true, files changed and not synced=26, entries synced=false
player: after the relaunch, machine.revert does not exist
player: power loss discarded the data of 26 unsynced file(s)
player: reopen failed: .../doc/recipes/prt.lua:2874: the epoch machine does not match its state
control (reopen with synced clones): A and B hold
VIOLATED: O2/R4: after relaunching a sealed epoch, its directory keeps a machine directory at state.json's root hash that was synced after its last change
VIOLATED: O2/R4: after a power loss that follows that relaunch, the next relaunch reopens the sealed epoch
run.sh: R1-O2-2: exit 1 (bug present)
```

The power loss is modeled, not injected at the block layer, and the model is conservative: it keeps every directory
entry and drops only the data of unsynced files. Check (A) does not depend on the model. It applies O2's definition of a
guaranteed directory to the traced syscalls. The test ran on the temp directory's ext4, where `clone_file` copies. A
reflink clone also needs `sync_stored` to be durable (prt.lua's own comment on `get_stored_root_hash`). No reviewer
changes were made to the test. Opus 5.5 found, proved and reviewed the issue; no fallback model was used.

### Trigger and reachability

No adversary is needed. The trigger is two stops of the honest player's host:

1. A crash, kill or power loss inside the window of `seal_epoch_state` between the `state.json` write and the removal
   of `machine.revert`. That window covers `fs.sync_directory`, `remove_evicted` and the removal of the files the
   previous `state.json` named.
2. A power loss after the relaunch, before the kernel writes back the clone.

Both stops happen on the honest operator's path ("Restarting after a stop (O2)"). They work with any template and any
inputs, and the sealed epoch is reached on every epoch.

### Rating

1. **Out of scope: no.** I checked the exclusion "Defects that need the honest operator to reload a stored directory
   that O2 does not guarantee, such as one being written or shared when its process stopped". It does not apply. The
   first relaunch reloads `machine.revert`, which was synced. The defect is that the relaunch itself discards the only
   guaranteed copy. I also checked "Host faults, such as a full disk, as long as the emulator does not turn them into
   a wrong hash, ...". The second stop is a power loss, but O2 names power loss as an ordinary stop the operator
   resumes from: "A process that stops (crash, kill, or power loss) ... The operator discards those directories and
   resumes from a guaranteed one". Section 5 adds "The tools and reference implementations that ship with it must
   follow them". The trigger is the player's restart logic, not the fault.
2. **Role: Support.** The AUDIT.md table rows the PRT player as "Support. No production deployment runs the player".
   Section 3: "A defect that only a support component shows is Medium when it would rate High or Critical in the role
   the component stands in for, such as ... the honest operator for an implementation of an operator". That clause
   covers this component, an implementation of an operator.
3. **High and Medium cases.** "A defect that only a support component shows, when section 3 rates it Medium." This
   case applies through step 4's rating in the stood-in role. No High case fits.
4. **Critical in the stood-in role.** In the honest-operator role, the defect violates two clauses on the honest
   operator's path. R4: "After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim".
   O2: "The emulator guarantees a stored directory only when it was synced after the last change to its contents".
   Both would rate Critical, so the support rule gives **Medium**.

Alternative reading: if the host-fault exclusion were read to cover any power loss that ends in a loud failure, with
no wrong hash, the issue would be Out of scope. I judge that reading weaker. O2 and R4 make recovery from a power loss
an explicit requirement, and the fault here only exposes a guarantee the restart had already destroyed.

### Possible solution and risks

In `revert_interrupted_input` branch 1, call `cartesi.machine:sync_stored(machine_directory)` after `clone_stored`, as
branch 2 already does for its clone. The control in the test models exactly this fix. Another fix is to remove
`machine.revert` for a sealed epoch only after `machine/` is synced. The cost is one extra sync of a machine directory
per relaunch, a bounded per-restart cost. The fix touches only the restart path and does not change hashes.

### Risk of not fixing it

An operator that copies the reference player can lose the ability to restart a sealed epoch. That takes a stop inside
the seal window, then a power loss soon after the relaunch. It then stops defending that epoch's claim, and a
dishonest claim can win by timeout. No adversary can trigger it directly. As mitigations outside the code, an operator
can sync the filesystem after every relaunch, or recover by clearing the epoch directory and replaying the epoch from
its checkpoint.

## R1-R12-3

**Title.** The PRT epoch listener (`prt-epoch.lua` `poll()`) and the PRT bridge (`prt-bridge.lua` `observe()`) copy,
sort and rescan every log already processed on every observation, so the cost of observing one more input or match log
grows with the number already seen, and the total over an epoch is quadratic.

**Severity.** Medium

### Problem

Both observers get their logs from `prt-log-history.lua`, which fetches only new blocks but keeps every fetched log.
They then redo all the work on all of those logs on every call:

- `poll()` (`prt-epoch.lua` lines 35-66) copies every InputBox and consensus log fetched since the epoch's first block
  into a new table, `table.sort`s it (`less` decodes `blockNumber` and `logIndex` with `eth.small` on every
  comparison), and walks it again to check duplicates, block hashes and the `applied` prefix. Only after that does it
  handle the logs past `#self.applied`.
- `observe()` (`prt-bridge.lua` lines 64-203) copies every log of the factory, consensus, root and inner tournaments
  fetched since the seal, sorts them with `log_less`, and replays all of them to rebuild `contexts`, `matches`,
  `events` and the duplicate and block-hash checks from scratch.

The PRT player `crisium.lua` runs `pass()` on every new block (lines 360-372): each listener polls, and each sealed
epoch's bridge ticks, which observes at least once (`refresh()`). So with n logs already in an open epoch or dispute,
every block costs O(n log n) work on logs that were already processed, and an adversary who adds one input or one
match log per block makes the honest work of an epoch O(n^2 log n) instead of O(n).

R12 requires: "The honest operator's own work outside the emulator, such as observing the chain, keeping and
persisting its own records, and restarting, has a bounded cost per input, per yield, and per match". The cost of
observing one more input or one more match log here is not bounded: it grows with the number of inputs (up to
2^24 per epoch, `ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH = 24`) or match logs already seen. In the role the player
stands in for, this threatens the goal through completeness: an honest operator whose observation work grows
quadratically with adversarial inputs and Sybil moves may fall behind the dispute clocks (R4, "observes the chain and
submits its transactions within the dispute clocks"; A7 sizes clocks for the worst-case costs of R12).

The unfiltered fetch of the shared factory's logs is a separate candidate (R1-BOUNDARY-1) and is not tested here.

### Component, role and area

The PRT player's epoch listener and dispute bridge in `doc/recipes` (`prt-epoch.lua`, `prt-bridge.lua`, with
`prt-log-history.lua` and the player loop in `crisium.lua`). AUDIT.md table: "The PRT player and bridge in
`doc/recipes`, ... | Support. No production deployment runs the player, the bridge or the CLI." It stands in for the
honest operator (section 3: "implementations of an operator that no deployment runs"). Area: chain observation.

### Location

- `doc/recipes/prt-epoch.lua`, `methods:poll()` (lines 25-135; the full copy, sort and rescan at lines 35-66).
- `doc/recipes/prt-bridge.lua`, `methods:observe()` (lines 48-204; the full copy at 64-105, sort at 110, replay at
  111-179), called by `refresh()` (336-344) from `tick()` (692).
- `doc/recipes/prt-log-history.lua`, which keeps every fetched log in `self.logs` and returns all of them from
  `get_logs_of()`.
- `doc/recipes/crisium.lua`, `pass()` (295-320) and the main loop (360-380), which poll and tick on every new block.

### Evidence and test

`bugs/R1-R12-3/` contains `test.lua` (the test), `README.md` (the prover's description) and this entry. Run it with
`bugs/run.sh R1-R12-3` (about 1 s; no chain and no emulator machine needed).

The test loads the real `prt-epoch` and `prt-bridge` modules against an in-memory chain whose logs are proxies that
count reads of their fields (the mock's own reads are not counted, and the ABI decoder is a table lookup). For the
listener it lets `poll()` deliver K `InputAdded` logs, marks them processed, appends one more input and counts the
field reads of the K old logs during the next `poll()`. For the bridge it lets `observe()` see K `CommitmentJoined`
logs in the root tournament, appends one more and counts the reads of the K old logs during the next `observe()`. It
asserts that going from K=300 to K=3000 at most doubles that count (plus 64), which an incremental implementation,
even one with logarithmic lookups, meets; the prover's scratch incremental `poll()` read 1 field at both sizes.
Counts, not time, so it is deterministic.

On audit/prt2 the reviewer re-ran it twice; both runs printed the same counts and exited 1:

```
prt-epoch poll (K inputs): field reads of already-processed logs in one observation after one new log: K=300 -> 7188, K=3000 -> 90974 (x12.7)
VIOLATED: prt-epoch poll (K inputs): R12 bounded cost per input/match: the work of one observation on logs already processed must not grow with their number
prt-bridge observe (K commitments): field reads of already-processed logs in one observation after one new log: K=300 -> 11775, K=3000 -> 155055 (x13.2)
VIOLATED: prt-bridge observe (K commitments): R12 bounded cost per input/match: the work of one observation on logs already processed must not grow with their number
run.sh: R1-R12-3: exit 1 (bug present)
```

The growth (x12.7 and x13.2 for x10 logs) is the K log K of the sort plus the linear rescan. The test was not
modified by the reviewer. All agents ran on Opus 5.5; no fallback model was used.

### Trigger and reachability

Any input sender ("Send any number of inputs the deployment accepts", section 7) adds inputs for the application to
the InputBox, at most 2^24 per epoch; any dishonest claimant ("Post any number of claims (Sybils)") adds joins and
match logs to the dispute. Each new block then makes the player re-sort and rescan every log of the open epoch and of
each open dispute. Nothing has to be unreachable: these are ordinary chain histories, and the player polls on every
new header by design.

### Rating

1. Out of scope: no. The trigger is inputs and Sybil claims, which section 7 grants the adversary. It is not
   "Average-case performance that does not change the worst-case cost of any operation listed in R12": the defect
   raises the worst case (adversarial inputs and match logs, one per block) from linear to quadratic. It needs no
   untrusted call to the machine API, no deployment violation, and no reorganization.
2. Role: Support. AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support." This clause covers both
   `prt-epoch.lua` (the player's listener, driven by `crisium.lua`) and `prt-bridge.lua`. Section 3: "A defect that only
   a support component shows is Medium when it would rate High or Critical in the role the component stands in for,
   such as ... the honest operator for an implementation of an operator". The player stands in for the honest
   operator. No component in the honest-operator role in this campaign shares the code (the validator nodes are out
   of scope).
3. High and Medium cases: for the support component, "A defect that only a support component shows, when section 3
   rates it Medium." That depends on the stood-in rating, which falls to step 4 (Critical); the High constant-factor
   case does not fit because the factor grows with the number of inputs and match logs, and the Critical bullet "An
   operation listed in R12 whose worst-case cost a guest can make unbounded, super-linear" names the operations of
   R12's first paragraph, which do not include observing the chain.
4. Critical (in the stood-in honest-operator role): R12, "The honest operator's own work outside the emulator, such as
   observing the chain, ... has a bounded cost per input, per yield, and per match", is violated on the honest
   operator's path ("Observing the chain", section 2): the cost of observing one more input or match log grows as
   O(n log n) in the n logs already seen. Critical in the stood-in role, hence Medium for the support component.

Second reading: R12 also says the total "grows only with the inputs, yields, and matches of the epochs still open",
and the rescan is limited to the open epoch and its dispute (after the seal `poll()` returns early, and the bridge
fetches from the seal on). If "bounded cost per input" were read as satisfied whenever the work depends only on
open-epoch items, with the number of observations treated as a deployment constant (epoch and dispute duration over
the block time), the defect would be a constant-factor multiplication of the honest work (High in the stood-in role)
and still Medium for the support component. Only a reading that drops "bounded cost per input" entirely would make it
Low. The facts that decide between the first two readings are whether the polls per epoch count as a constant; both
give Medium here.

### Possible solution and risks

Process logs incrementally. In `poll()`, keep the duplicate set and per-block hash map across calls and handle only
the logs past those already applied (the history returns logs per address in fetch order, so a merge of the new tail
suffices). In `observe()`, keep `contexts`, `matches`, `deleted`, `recovered`, `events` and the duplicate and block
maps as persistent state, and apply only the new tail of each address's logs, in global order. Risks: reorg handling.
Today a reorg is handled by `history:reset()` plus a full rebuild; an incremental version must roll its derived state
back to the common ancestor (or rebuild from scratch only on a reorg), and must keep the global log order across
addresses when new logs of different tournaments arrive in the same observation. The bridge's snapshot currently
returns fresh `events` and `logs` arrays, which callers may iterate; those consumers would need to accept incremental
or shared tables.

### Risk of not fixing it

A player run from these recipes slows down quadratically when an adversary floods an epoch with inputs or a dispute
with Sybil joins and moves, and may miss the dispute clocks while it rescans. No production deployment runs the
player, so the direct exposure is limited to demonstrations and tests; the risk is that a production node modeled on
these recipes inherits the rescan. Mitigation outside the code: longer poll intervals reduce the per-epoch total but
not the per-observation O(n log n), and lengthen reaction times.

## R1-R2-1

**Title.** `write_reg("iunrep", ...)` changes the hashed unreproducible-mode register while every guard reads the config copy, and `store` then writes a directory that refuses to load

**Severity.** Medium

### Problem

The unreproducible mode is kept in two places: the hashed shadow register `iunrep` and the copy in the machine's
configuration (`m_c.processor.registers.iunrep`). Every behavior that depends on the mode reads the config copy.
That includes the uarch refusal, the refusals of `collect_mcycle_root_hashes` and `collect_uarch_cycle_root_hashes`,
the `store` refusal, and host interrupt polling. The two copies are compared only when a machine is created or
loaded. `machine::write_reg` refuses writes to the machine-ID registers (`mvendorid`, `marchid`, `mimpid`), which
the same load-time check binds to the configuration. It has no such guard for `iunrep`.

After `write_reg("iunrep", 1)` on a reproducible machine, the root hash commits to an unreproducible machine. The
machine still runs, logs uarch steps, collects computation hashes and stores. `store` writes the shadow state with
`iunrep = 1` next to a `config.json` with `"iunrep":0`. Loading that directory fails with "iunrep mismatch between
shadow state and config". The reverse write (0 on an unreproducible machine) produces a hash that says reproducible
while the machine refuses the uarch and the collectors.

This violates R2: "Every register and every configuration value that affects a transition has one source of truth in
the hashed state, and every path reads it from there." It also contradicts the manual, which calls `iunrep` "a
creation-time mode", and R14: "The unreproducible mode is fixed at creation and recorded in the hashed state." No
valid template and no honest-operator operation reaches the split state, so the goal of section 1 is not affected.
The defect is a machine API operation, used as documented, that leaves the machine's cached state and its stored
directory inconsistent with its contents.

### Component, role and area

- `machine::write_reg` belongs to "the rest of the machine API (C, Lua and JSON-RPC)". A production validator node
  does not plausibly write `iunrep` on the honest operator's path, so this use is off that path.
- The guarded paths (uarch, collectors, `store` and load) belong to "interpreter, state-access layers, ..., and
  storing, loading, cloning and syncing machines", which is the honest-operator role. They behave correctly on every
  machine where the two copies agree, and the copies always agree unless `write_reg("iunrep")` was called.
- Area: the source of truth for the unreproducible mode, and its consistency between the machine and a stored
  directory.

### Location

- `src/machine.cpp`, `machine::write_reg`, `case reg::iunrep:` (around line 1444). It writes
  `m_s->shadow.registers.iunrep` with no read-only check. Compare `case reg::mvendorid` / `marchid` / `mimpid`
  (around lines 1354-1359), which throw "register is read-only".
- `src/machine.hpp`, `machine::is_unreproducible()` (around line 857). It returns
  `m_c.processor.registers.iunrep != 0`, which is the config copy.
- `src/machine.cpp`, callers of `is_unreproducible()`: `store` (around line 430), uarch (around line 2194),
  `poll_external_interrupts` (around line 2348), and the collectors (around lines 2445, 2619, 2770).
- `src/machine.cpp`, `validate_processor_shadow` (around lines 222-224). It is the only comparison of the two copies,
  and it runs at create and load only.

### Evidence and test

`bugs/R1-R2-1/` contains `test.lua` and `README.md`. The test uses the shared harness configuration
`baremetal-minimal`, a reproducible bare-metal machine. It first checks, as a control, that `log_step_uarch` works on
a fresh copy of the machine. It then calls `write_reg("iunrep", 1)`. It exits 0 in either of two cases:

- the write is refused;
- every path follows the hashed register: `log_step_uarch` refuses, and `store` either refuses or writes a directory
  that loads back with the same root hash and `iunrep`.

Run with `bugs/run.sh R1-R2-1`. It takes about a second. On audit/prt2 it prints the following and exits 1. The
prover ran it three times and the reviewer twice more, with the same result every time.

```
write_reg('iunrep', 1) accepted; read_reg('iunrep') = 1; root hash changed: true
VIOLATION: log_step_uarch succeeded on a machine whose hashed iunrep is 1 (the guard reads the config copy, not the hashed register)
store succeeded
VIOLATION: store wrote a directory that refuses to load: .../bugs/R1-R2-1/test.lua:75: iunrep mismatch between shadow state and config
VIOLATED: R2/R14: iunrep must have one source of truth in the hashed state (write refused, or every path follows it)
run.sh: R1-R2-1: exit 1 (bug present)
```

The reviewer also checked two facts by hand. After the write, `run` and `collect_mcycle_root_hashes` still succeed.
The stored `config.json` holds `"iunrep":0` while the stored shadow holds 1. Either fix in "Possible solution" makes
the test exit 0. The test was not modified. No fallback model was used.

### Trigger and reachability

Only a trusted caller of the machine API triggers it, by calling `write_reg("iunrep", v)` with `v` different from
the configured value, locally or over JSON-RPC. No guest action triggers it. R8 makes `iunrep` unreachable from guest
memory accesses, and no instruction writes it: the interpreter never calls `write_iunrep`. No input triggers it
either, because delivery does not touch `iunrep`.

A valid template is "created from a configuration ... and changed only by running it and delivering inputs", so its
two copies always agree. Every machine the honest operator stores, loads, clones or syncs therefore keeps them in
agreement. The split state is reachable only through this API call, and the honest-operator path never makes it.

### Rating

1. Out of scope. The exclusions checked are these.
   - "The effect of a deliberate state change made through the machine API, when the API performs it as documented
     (section 4)." This clause covers the component (`write_reg` is a machine API operation), but it does not cover
     the defect. The documented effect is that the register changes ("The value of any register can be changed with
     the `machine:write_reg` ... method"). That effect, the hash now committing to `iunrep = 1`, is out of scope. The
     emulator's own copy of the mode then disagreeing with the register, and `store` writing a directory its own
     `load` refuses, are not documented effects of the write. The Medium case quoted in step 3 is written for exactly
     such a documented API use, and it would be empty if this exclusion swallowed it.
   - "Defects that need an untrusted party to call the machine API directly" does not apply: the caller is trusted.
   - The exclusion for snapshots the emulator did not write does not apply: the emulator wrote this directory.
   - The O2 exclusion does not apply: there is no stop and no sharing.
2. Role. `write_reg` is "the rest of the machine API", which is honest operator only "where a production validator
   node plausibly calls it on the honest operator's path". No node writes `iunrep`, so this use is off the path. The
   paths that show the inconsistency (`store`/load, uarch, collectors) are honest operator. Section 3 says they play
   this role "within the limits of O1 and O2", and they misbehave only on a machine that the off-path call produced.
3. High and Medium cases. Section 8 Medium: "A machine API operation off the honest operator's path that, used as
   documented, leaves the hash tree, the cached state of the machine or a stored directory inconsistent with the
   machine's contents (R9)." This clause covers the component. `write_reg` is off the path and used as documented
   ("The value of any register can be changed"). It leaves the cached config copy that every guard reads
   inconsistent with the hashed register, and `store` then writes a directory whose `config.json` disagrees with its
   shadow state and does not load. The manual contradiction points the same way: "A contradiction between the manual
   and the behavior on a security-relevant point ... takes the severity it would have if the manual were right." The
   manual calls `iunrep` "a creation-time mode", and R14 says "fixed at creation". No High case applies, since the
   state is not reached by any input sequence from a valid template and no verifier or honest path diverges on a
   reachable state.
4. Critical. Not reached, because step 3 matched. R2 ("one source of truth in the hashed state, and every path reads
   it from there") is violated structurally. But it is observable only after the off-path API write, never at a
   reachable state or on the honest operator's path.

Other readings:

- **Low.** "A failure that needs misuse of an API by its trusted caller". Writing a register the manual calls
  "creation-time" could be called misuse. The deciding fact is whether the manual's general statement that any
  register can be written counts as documenting writes to `iunrep`. The code refuses the analogous machine-ID
  registers, and the manual does not list `iunrep` as read-only. On that text the write is documented use, so Medium
  is the better-supported reading.
- **Out of scope.** If the first exclusion is read to cover every consequence of a documented write, including the
  emulator's own inconsistency, the defect is out of scope. That reading would empty the Medium case above, so it is
  not preferred.

### Possible solution and risks

The preferred fix makes `iunrep` read-only to the host. `write_reg(reg::iunrep, ...)` would throw "register is
read-only", as for `mvendorid`/`marchid`/`mimpid`. `init_processor` would write the configured value straight into
the shadow, as it already does for the machine-ID registers. The manual's `write_reg` paragraph would list the
read-only registers. Risk: any tool or test that writes `iunrep` after creation breaks. That use is unsupported in any
case, because such a machine cannot be stored and reloaded.

An alternative or addition is to have `is_unreproducible()` read the shadow register, so that there is a single
source of truth. Risk: the VirtIO devices and the TTY setup are fixed at creation from the config, so a machine whose
register flips to 0 would keep host devices while it claims to be reproducible. Read-only is the safer fix.

### Risk of not fixing it

A trusted caller (a development tool, a debugger, a test script, or a careless integration) that writes `iunrep` gets
a machine whose hash claims one mode while it behaves as the other. It can keep computing hashes and storing, and the
stored directory then cannot be loaded. Untrusted parties and guests cannot trigger it, and the honest operator's path
never writes `iunrep`, so the security goal is not exposed. Mitigation outside the code: never call `write_reg` on
`iunrep`.

## R1-R3-3

**Title.** The PRT referee model's `validate_state_transition_response` accepts a state-transition proof that carries
a log its transition form does not use (a `reset_uarch_log` on a non-closing step, a `send_cmio_log` away from an
input delivery), ignores it, and returns the honest after-hash. The deployed referee (Dave) rejects the same proof as
trailing data.

**Severity.** Medium (preferred reading). Low under the reading that the response's named fields are a message
schema, so an unused field is not part of the proof (see Rating).

### Problem

R3 makes the shape of a log a validity condition: "Conditions on the log are validity conditions. A log that fails
one must be rejected. Examples are wrong order, wrong address, wrong size, duplicate, missing, or trailing data". The
referee model in `doc/recipes/prt.lua` chooses which logs of the `ProveStateTransition` response to verify from the
position alone. It reads `response.send_cmio_log` only when `state_transition_offset == 0`, `input_period_offset == 0`
and the slot holds an input. It reads `response.reset_uarch_log` only when `uarch_cycle == UARCH_CYCLE_MAX`. It never
checks that the other fields are absent. A response with an extra, validly produced log is therefore accepted, and
the extra log is silently dropped.

The deployed referee, Dave v3.0.0-alpha.7 `CartesiStateTransition.transitionState`, receives the same logs
concatenated in one `proofs` buffer and calls `_requireAccessLogProofFullyConsumed` after the last log of the form, so
it reverts with `InvalidAccessLogProofLength` (its comment: "exact consumption rejects both trailing data and
truncated proofs"). The model and the deployed referee thus disagree on what a referee verifies, which section 5
calls "a defect in one of the two". The PRT bridge (`doc/recipes/prt-ethereum.lua` `transition_proof`) already
enforces the exact shape when it encodes a response for Dave ("transition has the wrong reset shape", "unexpected
input-delivery proof"); the model does not.

The after-hash is not affected: every accepted response still yields the canonical after-hash, because the ignored
log is not applied. The goal of section 1 is not broken. The defect is the acceptance of trailing data that does not
affect the result, which R3 forbids and section 8 lists as Medium for a referee.

### Component, role and area

`doc/recipes/prt.lua`, the PRT referee model in `doc/recipes`. AUDIT.md: "The PRT referee model in `doc/recipes` |
Referee model". The area is the referee's leaf-level verification of a state transition
(`settle_uarch_state_hash` calls `validate_state_transition_response`). The manual reproduces the same function in
`doc/README.md`. `doc/recipes/prt-ethereum.lua` `verify_transition` (support, an off-chain native check) has the same
shape and is not asserted.

### Location

- `doc/recipes/prt.lua`, `validate_state_transition_response` (lines 265-293), called from
  `settle_uarch_state_hash` (around line 424).
- `doc/README.md`, the same function in "The state transition function" (line 9465) and in the full recipe listing
  (line 10874).
- For comparison: Dave `prt/contracts/src/state-transition/CartesiStateTransition.sol` `transitionState` and
  `_requireAccessLogProofFullyConsumed` (pinned under `bugs/harness/work/dave/released/`);
  `doc/recipes/prt-ethereum.lua` `transition_proof` (lines 168-189).

### Evidence and test

`bugs/R1-R3-3/` contains `test.lua` and `README.md`. Run `bugs/run.sh R1-R3-3` (about 2 s; needs the in-tree build
and the harness config `bugs/harness/work/configs/baremetal-template`).

The test loads the real `prt` module and finds the local closure `validate_state_transition_response` by walking the
upvalues of the module's exported functions, so it runs the code the referee runs. It uses the bare-metal rolling
template (waiting at a manual yield with the accepted reason) and logs produced by the emulator itself
(`log_step_uarch`, `log_send_cmio_response`, `log_reset_uarch`).

- Four controls: the honest response is accepted with the correct after-hash for each transition form (plain step at
  uarch cycle 0 of a slot without input, step at uarch cycle 3 of a slot with an input, delivery plus step, closing
  step plus reset in period 1). A failed control exits 2.
- Six responses with one extra validly produced log: a reset log on the plain step (uarch cycle 0 and uarch cycle
  3), a reset log on delivery plus step, a send_cmio log on the plain step in a slot without input, a send_cmio log on
  the step at uarch cycle 3 of a slot with an input, and a send_cmio log on the closing step plus reset. The test
  requires each to be rejected (the function raises an error).

On audit/prt2 every control prints `control OK: ...`, each of the six prints
`VIOLATED: <case>: accepted, after-hash X (honest after-hash X)` with X equal to the honest after-hash, and the run
ends with `VIOLATED: R3: a referee must reject a state-transition proof with superfluous (trailing) logs, as Dave's
CartesiStateTransition does; the referee model accepted 6 of 6 such proofs` and `run.sh: R1-R3-3: exit 1 (bug
present)`. The reviewer re-ran it twice with identical output and exit 1. The prover reports that a patched copy of
`prt.lua` that checks the response shape made the test exit 0 with the controls still passing. Found, proved and
reviewed with `claude-opus-5-5`; no fallback was used.

### Trigger and reachability

Any claimant in a leaf match answers `ProveStateTransition` with the honest logs of the form plus an extra log. Section
4 lets dishonest claimants send "any logs, any proofs", and section 7 lets the adversary "Hold any claim, including the
honest one, and answer for it". Any position and any reachable before-state work, including the valid template
itself; no special state is needed. The honest player never sends an extra log, so the honest claim is not harmed.

### Rating

1. Out of scope: no. The trigger is a dishonest claimant's proof, which section 4 places in the adversary's power. None
   of the exclusions of section 8 applies; in particular the A1-A8 exclusion does not, since no obligation is
   violated by the deployment ("unless an implementation of the referee model is what violates it").
2. Role: referee model (AUDIT.md: "The PRT referee model in `doc/recipes` | Referee model"). Section 3: "A defect in
   what it accepts or derives is rated as if a deployed referee had it." The clause covers this component and this
   defect, which is in what the model accepts. The defect is in the model's own dispatch of logs, not inherited from
   the off-chain verifiers it calls (each of `verify_step_uarch`, `verify_send_cmio_response` and
   `verify_reset_uarch` correctly checks the log it is given), so the AUDIT.md rule that a defect shown "only through
   them is rated as theirs" does not apply.
3. High and Medium cases: Medium, "A referee verifier that accepts trailing data that does not affect its result
   (R3)." A deployed referee with the model's behaviour is exactly that: in Dave's encoding the extra log is bytes
   after the last consumed log of the form, which Dave rejects for that reason, and the accepted after-hash is the
   honest one. The case speaks of a referee verifier; it covers the model through the section 3 clause above. No High
   case fits: there is no wrong or second after-hash and no unreachable-state behaviour.
4. Critical: not reached. Every accepted response yields the canonical after-hash, so R3's first sentence ("Every log
   that a verifier accepts must then yield the same after-hash, and that after-hash must be the canonical hash") holds;
   only R3's log-validity condition is violated.

Two readings. Preferred (Medium): the `ProveStateTransition` response is the proof. The manual presents the function
as "a representation of what the blockchain uses to validate a state transition", the blockchain receives one
concatenated buffer, and the bridge enforces the exact shape. An unused log is then trailing (or duplicate) data of
the proof. Alternative (Low, or no defect): the response is a table of independently verified logs and an unused
named field is like an unknown key of a message, not part of any log; the model then matches the manual's own model
line for line, and the disagreement with Dave is only an encoding difference that affects no claim. The fact that
would decide is whether the manual's referee model treats the response as the exact proof; the manual does not state
an exactness requirement on the response shape, and its own listing has the same behaviour, so a fix belongs in both
`prt.lua` and `doc/README.md`.

### Possible solution and risks

In `validate_state_transition_response` (and the copy in `doc/README.md`), require the shape of the response to match
the transition form before verifying: `assert((response.send_cmio_log ~= nil) == (state_transition_offset == 0 and
input_period_offset == 0 and input_data ~= nil), ...)` and `assert((response.reset_uarch_log ~= nil) == (uarch_cycle ==
UARCH_CYCLE_MAX), ...)`, and optionally reject any other key of `response`. The honest player's
`prove_state_transition` already produces exactly these shapes, so the honest path is unaffected. The risk is low: a
player that adds an unneeded field would now be rejected, which matches Dave. The same check could be added to
`prt-ethereum.lua` `verify_transition` for consistency.

### Risk of not fixing it

No settled state or output changes: the extra log is ignored and the after-hash stays canonical. What remains is a
referee model that is more permissive than R3 and than the deployed referee, so tests and demonstrations run against
the model can accept proofs that Dave reverts, and a referee implemented from the manual's listing would accept
trailing proof data. Only a claimant who sends a malformed proof can trigger it, and it gains nothing beyond what the
honest proof gives.

## R1-R6-1

**Title.** `cartesi-machine --print-uarch-cycle-root-hashes` prints made-up uarch hashes for the mcycle after a
rejection: it passes a fake revert uarch tail made of the revert root hash twice.

**Severity.** Medium (Low under the reading that treats the printer as diagnostics; see Rating).

### Problem

When the window of `--print-uarch-cycle-root-hashes` contains a rejecting instruction, the CLI prints, for the mcycle
that follows it, two hashes labelled `<rej>,1` and `<rej+1>`, both equal to the revert root hash. R6 requires the
uarch-level hashes of every mcycle after the rejecting instruction to be "the uarch trajectory that starts from the
canonical state", that is, the per-uarch-cycle state hashes of the machine to which the rejected input was delivered
(44 hashes in the test, the first `a6f7bf8f...`). The first printed hash claims to be the state after uarch cycle 1
and is not; the uarch trajectory is collapsed to a single cycle.

The cause is that the runner hands `collect_uarch_cycle_root_hashes` a fabricated `revert_uarch_tail`
`{ revert_root_hash, revert_root_hash }`. The library documents that this tail is "the state root hashes after each
uarch cycle of the machine corresponding to the revert root hash", which the caller must obtain by running the same
function on that machine, and at a rejected manual yield it emits that tail as the extra period. The library itself is
correct: given the real tail, the same chunked calls return the required trajectory. The code comment justifying the
fake tail ("which never happens outside cmio mode") is false: the CLI's default yield settings allow manual yields, so
any guest that rejects stops the run there, with or without cmio options.

Threat to the goal: none directly, because the CLI is not run by a deployment. The tool's output is exactly the set of
uarch-level hashes (or, with bundling, the subtree roots) that a uarch-level computation hash is built from. A user who
computes or checks uarch-level claims with it after a rejection gets a wrong trajectory, which in the honest-operator
role would be a completeness failure (wrong uarch-level claim).

### Component, role and area

`cartesi-machine` CLI, role Support (AUDIT.md: "The PRT player and bridge in `doc/recipes`, the `cartesi-machine` CLI,
and the Lua helper libraries ... | Support. No production deployment runs the player, the bridge or the CLI."). Area:
the `--print-uarch-cycle-root-hashes` runner. The library function `collect_uarch_cycle_root_hashes` (role Honest
operator) does not show the defect.

### Location

`src/cartesi-machine.lua`, `uarch_cycle_root_hashes_runner_run` (lines 4053-4061 on audit/prt2):

```lua
-- The revert uarch tail only matters when the run stops at a rejected manual yield, which
-- never happens outside cmio mode. ...
local revert_root_hash = m:read_revert_root_hash()
local fake_revert_uarch_tail = { revert_root_hash, revert_root_hash }
...
self.runner:collect_uarch_cycle_root_hashes(chunk_end, self.log2_bundle, fake_revert_uarch_tail)
```

Contract of the tail: `src/cm.h`, documentation of `cm_collect_uarch_cycle_root_hashes` (`revert_uarch_tail`, and the
paragraph on the rejected manual yield).

### Evidence and test

`bugs/R1-R6-1/` contains `test.lua` and `README.md`. Run with `bugs/run.sh R1-R6-1` (about 1 s). The test:

1. loads the shared `baremetal-template` configuration (the `emit-output` guest waiting at an accepted manual yield)
   and computes the uarch trajectory of one mcycle from it with `collect_uarch_cycle_root_hashes(MCYCLE_MAX, 0)`
   (44 hashes; the last equals the template's root hash);
2. delivers the advance-state payload `R` (the guest rejects it), runs 30 mcycles, stores the machine in a
   `mktemp -d` directory, and finds the rejecting mcycle on the in-memory machine;
3. runs `cartesi-machine --load=<stored> --print-uarch-cycle-root-hashes=8,start:3526402`, checks that the hash
   printed for the reset of the rejecting mcycle is the revert root hash, and collects the hashes printed after it;
4. exits 1 if any printed hash differs from the trajectory of step 1, 0 otherwise, 2 on setup errors.

On audit/prt2 it exits 1 on every run (three runs by the prover, three by the reviewer), printing:

```
rejecting mcycle 3526406; revert root hash 428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
required: 44 uarch-level hashes for mcycle 3526406 (trajectory from the canonical state), first a6f7bf8f8873acb46fd11c6fdbfdde23c49fde9a9bc3cc03257645c26fb53425
printed:  2 hashes after the rejection:
  3526406,1: 428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
  3526407: 428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
first difference at entry 1 (3526406,1): printed 428a6bb8..., required a6f7bf8f...
VIOLATED: R6: in every later mcycle, the uarch-level hashes printed by --print-uarch-cycle-root-hashes are the uarch trajectory that starts from the canonical state
run.sh: R1-R6-1: exit 1 (bug present)
```

The reviewer ran the test against a scratch copy of the CLI whose only change is to pass the real tail (computed with
`collect_uarch_cycle_root_hashes(MCYCLE_MAX, 0)` on the template); it printed the 44-hash trajectory
(`3526406,1: a6f7bf8f...`, `3526406,2: a05f14b2...`, ...) and the test exited 0. The reviewer also relaxed the test so
that printing fewer hashes after the rejection, or none, is accepted (only a printed hash that differs from the
required one fails), so that a fix that declines to print the period instead of computing it passes rather than ending
in a setup error. Found by the R6 hunter, proved and reviewed in campaign round 1.

### Trigger and reachability

A trusted CLI user runs `--print-uarch-cycle-root-hashes` over a window that contains a rejecting instruction. Any
guest that rejects an input reaches it; the test reaches it from the shared valid bare-metal template by delivering an
advance-state input, running, and storing the machine, all documented operations. No untrusted party is involved
beyond the input sender choosing a payload that the guest rejects.

### Rating

1. Out of scope: no. The trigger is a guest rejection of an input, reachable from a valid template, followed by a
   documented CLI option. It needs no "deliberate state change made through the machine API", no untrusted caller of
   the machine API, no violation of A1 to A8, and no non-guaranteed directory (the loaded directory was stored and
   not shared). The application is correctly designed (it yields with the rejected reason as the rollup interface
   allows).
2. Role: the `cartesi-machine` CLI, Support per the AUDIT.md table quoted above; that clause names the CLI, so it
   covers this component. Section 3: "A defect that only a support component shows is Medium when it would rate High
   or Critical in the role the component stands in for, such as ... the honest operator for an implementation of an
   operator or a tool that computes claims." The printer computes the per-uarch-cycle state hashes and, with
   `log2_bundle_uarch_cycle_count`, their subtree roots, which are the leaves and parts of uarch-level computation
   hashes ("A computation hash can be built whole or in parts", section 3). It therefore stands in for the honest
   operator. The honest-operator library it calls (`collect_uarch_cycle_root_hashes`) does not share the defect: the
   wrong hashes come only from the tail the CLI fabricates, and the real tail yields the correct output.
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium." In the
   honest-operator role the defect would be Critical (step 4), so section 3 rates it Medium.
4. Critical (for the role it stands in for): R4, "After a rejection, every hash the honest operator commits to follows
   R6, however it is computed", and R6, "In every later mcycle, the uarch trajectory that starts from the canonical
   state." The printed `<rej>,1` hash is not a state of that trajectory, at a reachable state.

Second reading: the example "a defect in a tool's diagnostics" under Low could be read to cover the CLI's printing
options, which the manual presents as a way to "see" state hashes. Under that reading the class is Low. The deciding
fact is whether `--print-uarch-cycle-root-hashes` counts as a tool that computes claims; its output is the claim
material itself (state hashes and bundle roots), not a diagnostic message about it, which is why Medium is the reading
taken here.

### Possible solution and risks

Pass the real tail: let the user supply the machine to which the rejected input was delivered (for example a
`--revert-machine=<dir>` option, or the snapshot the CLI itself takes before each cmio delivery) and compute the tail
with `collect_uarch_cycle_root_hashes(MCYCLE_MAX, 0)` on it, checking that its last entry equals the recorded revert
root hash. When no such machine is available, stop printing at the reset of the rejecting mcycle and say that the
following period needs the reverted machine, instead of printing fabricated hashes. Risk: low; it changes only the
CLI's output after a rejection, and scripts that parse that output would see the extra (correct) period or a message
in its place.

### Risk of not fixing it

No deployment runs the CLI, so the goal is not affected. Developers, auditors or operators who use the printer to
compute, compare or debug uarch-level claims after a rejected input get a wrong trajectory, labelled as real state
hashes, and could build or trust a wrong uarch-level commitment, or misdiagnose a correct implementation. Mitigation
outside the code: do not use the printer across a rejection; compute the period after it with
`collect_uarch_cycle_root_hashes` on the pre-delivery machine.

## R1-R8-1

**Title.** The PRT player keeps one hash per guest output for a whole input, in the same run that computes its claim, so the memory it needs to compute the claim grows with the number of outputs.

**Severity.** Medium

### Problem

While the PRT player runs an input, `run_to_input_mcycle_offset` installs an `on_yield_automatic` closure. For every
automatic yield with the TX_OUTPUT reason, the closure appends `keccak(output_data)` to the Lua table
`pending_output_hashes`. The table is folded into the outputs frontier only at the input's fixed point, by
`flush_pending_outputs`, when the input is accepted. On any other outcome it is dropped when the function returns. The
player does this in the epoch run that also feeds the mcycle computation-hash builder (`run_next_input`, called from
`input_added` and `idle`). That run is how the player computes its claim. Within one input, the run therefore holds
about 88 bytes of Lua heap per output: a 32-byte string plus its table slot.

Each output costs the guest only a few mcycles (a store to the tx buffer and an automatic yield). The mcycle limit per
input is 2^48 (`cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE` = 48). So a single input can make the claim
computation's memory grow, in principle up to tens of bytes per mcycle the guest runs. That is far beyond the machine's
own fixed memory. A host that runs out of memory stops the claim computation. In the role the player stands in for,
that is the completeness failure of section 1: the honest operator "cannot respond in time. If the honest claim is
eliminated, a dishonest claim can win". The threat model rules this out explicitly. R12: "The memory and storage the
honest operator needs to defend its claims do not grow with the number of outputs."

Nothing in the claim needs these hashes. The claim depends only on state hashes. The hashes serve only to check the
outputs root and to prove the input's last output, which the frontier could do in constant memory (63 hashes).

The secondary observation in the triage item, one `oversized_output` anomaly line per oversized output, is not part of
this entry. R12 allows a bounded cost per yield, and the test only reports it.

### Component, role and area

The PRT player in `doc/recipes` (`prt.lua`, run by `crisium.lua` and by the forked players), in its epoch execution and
output bookkeeping. AUDIT.md table: "The PRT player and bridge in `doc/recipes`, the `cartesi-machine` CLI, ... |
Support. No production deployment runs the player, the bridge or the CLI." It is an implementation of an operator that
computes claims, so it stands in for the honest operator (section 3).

### Location

`doc/recipes/prt.lua`:

- `player_meta.__index:run_to_input_mcycle_offset`, lines 2066-2126. Line 2080 creates `pending_output_hashes`. The
  `on_yield_automatic` closure (2083-2091) appends one hash per TX_OUTPUT yield at line 2088.
- `flush_pending_outputs`, lines 1419-1437, which folds the list into the frontier only at acceptance.
- `player_meta.__index:run_next_input`, lines 2243-2272, the claim-building epoch run that passes `last_output` and
  `self.outputs_frontier`, which enables the closure.

### Evidence and test

`bugs/R1-R8-1/` contains:

- `test.lua`, the test.
- `guest.c`, a bare-metal rollup guest. Each input carries an output count, a declared length, an mcycle budget and the
  outputs root to accept with. The guest emits that many automatic TX_OUTPUT yields, where output i is the 8-byte
  counter i. It then spins to the mcycle budget and accepts with the root.
- `README.md`.

The test builds the guest with `bugs/harness/baremetal/build.sh` into a temporary directory. It stores a template at
the guest's first manual yield (rx-accepted, empty outputs root). For each case, a fresh `prt.new_forked_player` runs
one input through its normal `input_added` handler, which is the claim-building epoch run. A Lua count hook samples the
live Lua heap after a full collection during the run.

There are two cases. The control emits 1000 outputs and the test emits 100000. Both run exactly 3,200,186 mcycles. The
test exits 2 unless both inputs are accepted with no root mismatch, `player.output_count` equals the emitted count, and
the mcycles are equal. It asserts that the peak heap of the test minus that of the control is under 1 MiB.

Run `bugs/run.sh R1-R8-1` (about 80 s). It prints this on audit/prt2. The reviewer's run printed the same numbers as
the prover's.

```
control   outputs=1000    declared_len=8        mcycles=3200186  accepted=true player.output_count=1000    heap_samples=17   extra_peak_heap=161 KiB anomalies={}
large     outputs=100000  declared_len=8        mcycles=3200186  accepted=true player.output_count=100000  heap_samples=1666 extra_peak_heap=8659 KiB anomalies={}
over-1    outputs=1       declared_len=2097153  mcycles=3200186  accepted=true player.output_count=1       heap_samples=0    extra_peak_heap=0 KiB anomalies={oversized_output=1}
over-4    outputs=4       declared_len=2097153  mcycles=3200186  accepted=true player.output_count=4       heap_samples=0    extra_peak_heap=0 KiB anomalies={oversized_output=4}
info: oversized_output anomalies per input: 1 (1 output), 4 (4 outputs)
peak live heap growth from 1000 to 100000 outputs at equal mcycles: 8497 KiB (87.9 bytes/output)
VIOLATED: R12: the memory the honest operator needs to compute its claim must not grow with the number of outputs (peak heap difference 8497 KiB, margin 1024 KiB)
run.sh: R1-R8-1: exit 1 (bug present)
```

The reviewer also checked that the test passes once the defect is fixed, using a scratch copy of `prt.lua` that was
not committed. In that copy, the closure pushes each output's hash into a copy of the outputs frontier and holds back
only the last hash. At acceptance it proves the last hash against the copy, pushes it, and installs the copy. With it,
the roots still match (no `outputs_merkle_root_mismatch`), the growth is 7 KiB (0.1 bytes/output), and the test exits 0.
The test was not modified. Found, proved and reviewed on Opus 5.5 (no fallback).

### Trigger and reachability

An input sender triggers it. After the guest reads an input, it may run any instruction stream (section 4). That
includes a loop of automatic TX_OUTPUT yields, for example with zero- or eight-byte outputs, before it yields manually.
No special state is needed. Any valid template whose guest can be driven to emit outputs reaches it, including a
correctly designed application that emits many outputs for one input. Its memory cost is bounded per input only by the
mcycles the input runs (at most 2^48), and the table is released at the input's end.

### Rating

1. Out of scope: not excluded. The relevant exclusion reads: "An application that tries to exhaust the honest operator
   through the number of its outputs or yields. ... This holds as long as the memory and storage that the honest
   operator needs to defend its claims do not grow with the number of outputs, and each yield costs it a bounded amount
   (R12)." Here the claim-computing run's memory grows with the number of outputs, so the condition of the exclusion
   fails. The exclusion of applications that are not correctly designed "covers only what such an application gets",
   and "it must never stop the honest operator from computing claims", so it does not apply either. "Keeping outputs to
   prove them later is not on the honest operator's path" does not excuse it: the player does this keeping inside the
   run that computes the claim, so the cost lands on that path.
2. Role: the PRT player is Support (AUDIT.md table, quoted above). Section 3: "A defect that only a support component
   shows is Medium when it would rate High or Critical in the role the component stands in for, such as ... the honest
   operator for an implementation of an operator or a tool that computes claims." The player computes claims, so the
   defect is rated as if the honest operator had it, and then capped at Medium. No component in another role shares
   it. The emulator's own `collect_mcycle_root_hashes` and the frontier helpers keep no per-output list.
3. High and Medium cases, in the honest-operator role: none fits. The constant-factor case ("multiply the worst-case
   cost of an operation listed in R12 by a constant factor") does not fit, because the memory of a part of a claim goes
   from constant to linear in the output count, not up by a constant factor.
4. Critical, in the honest-operator role: R12, "The memory and storage the honest operator needs to defend its claims
   do not grow with the number of outputs", is violated at a reachable state, on the honest operator's path ("Computing
   claims", section 2). The Critical case "An operation listed in R12 whose worst-case cost a guest can make ... larger
   than what the deployment was sized for" also fits, since a guest controls the output count up to the per-input mcycle
   limit. Critical in the stood-in role makes it Medium for the support component.

Another reading gives Low. Under it, the hashes are memory for "keeping outputs to prove them later", which is "not on
the honest operator's path". Memory linear in the mcycles run is allowed by R12's first paragraph ("at most linear in
the cycles it executes"). So no rule is violated. What decides between the readings is whether "the memory ... the
honest operator needs to defend its claims" means the memory its claim-computing run actually consumes, or only what an
ideal operator strictly needs. The reviewer prefers the first reading. The exclusion in section 8 exists to stop
exhaustion through outputs, and a run that runs out of memory stops the claim whatever the memory was for.

### Possible solution and risks

In `run_to_input_mcycle_offset`, replace `pending_output_hashes` with a working copy of the outputs frontier
(`hash_tree.frontier_copy`), taken at input start. On each output, push the previously held hash into the copy and hold
only the newest hash and data. At acceptance, prove the held hash against the copy (`prove_next_output`), push it, and
install the copy as the player's outputs frontier (or swap the reference in `self.outputs_frontier`). On rejection or
at any other fixed point, drop the copy. Memory per input is then O(tree height). The reviewer's scratch version of
this passes the test with matching roots.

Risks: the frontier must be installed by reference or replaced in place, because `self.outputs_frontier` and
`previous_outputs_frontier` are compared for `output_count`. The last-output proof must still be taken before the last
push. The stored player persists the frontier and the last output, and its files and restart path must see the same
values as before. Pushing per output also costs about 63 hash operations per output in the worst case, compared with
the same total today, so it adds no asymptotic cost.

### Risk of not fixing it

No production deployment runs the player, so no deployment is directly exposed. Anyone who runs the recipe player,
`crisium.lua`, as a validator or sentinel for a real application is exposed. Any input sender can make one input's
claim computation exhaust the host's memory by having the guest emit many outputs. The player then cannot compute or
defend its claim. The player is also the reference that production operators may copy, and this per-output bookkeeping
would carry the same exhaustion into them. Mitigation outside the code: none practical, beyond provisioning memory for
the worst-case number of outputs an input can emit within its mcycle limit.

## R1-R8-2

**Title.** The honest player in `vg.lua` stops computing its claim when an accepted input leaves an outputs root that does not match its outputs.

**Severity.** Medium. Under a second reading, where `vg.lua`'s player counts as a development tool, it is Out of scope.

### Problem

When an input is accepted, `flush_pending_outputs` in `doc/recipes/vg.lua` hashes the outputs the input emitted into
the outputs frontier. It then runs
`assert(hash_tree.frontier_get_root_hash(outputs_frontier) == outputs_merkle_root, "outputs Merkle root mismatch")`.
The tx-buffer root is opaque guest data. Section 4 says: "The outputs Merkle root, the output payloads, and every
other yield reason are opaque guest data that the state merely commits to." The guest controls that root. If the root
it leaves does not match its outputs, `event_handler:input_added` raises. Then `state_hashes_before_inputs` and
`input_mcycle_lengths` are not recorded for the input, and `epoch_sealed` and `commit_claim` cannot produce the final
state hash. The state transition function still defines that final state and its hash. The player that stands in for
the honest operator therefore stops computing its claim. In the operator this player models, that lets any claim win,
including a fabricated final state and its outputs (section 8). The PRT player in the same directory handles the same
condition correctly: `prt.lua` reports an `outputs_merkle_root_mismatch` anomaly and continues.

### Component, role and area

The component is the honest player of the verification-game recipe, `doc/recipes/vg.lua` (`vg.new_player`,
`event_handler`). It is not listed by name in the AUDIT.md table, but it falls under the row "The PRT player and bridge
in `doc/recipes`, the `cartesi-machine` CLI, and the Lua helper libraries ... | Support. No production deployment runs
the player, the bridge or the CLI". It also fits section 3's "Support. Everything else used only for tests,
demonstrations, development or diagnostics". The player is an implementation of an operator that computes claims, so
it stands in for the honest operator. The area is how outputs are tracked while inputs are processed.

### Location

- `doc/recipes/vg.lua`: `flush_pending_outputs` (lines 421-430, the assert at line 429).
- `player_methods:run_to_input_mcycle_offset` (lines 434-480, which calls it at line 474).
- `event_handler:input_added` (lines 563-577), from which the error escapes.

### Evidence and test

`bugs/R1-R8-2/` contains the following files.

- `guest.c` is a bare-metal guest. It is built at test time with `bugs/harness/baremetal/build.sh` and handles inputs
  as follows:
  - At start, it accepts with the empty outputs root.
  - On input `W`, it emits nothing and accepts with a root that is not the root of its outputs (every byte XOR 0x5a).
  - On input `O`+N, it emits N outputs of 2 MiB and accepts with the correct root.
- `test.lua` stores the initial machine under its hash. It then drives `vg.new_player(initial_hash, "honest")` the way
  the referee's runner does, through `event_handler.input_added`, `epoch_sealed` and `commit_claim`.
  - Check A asserts two things: `input_added` for input `W` returns, and the committed claim equals the root hash after
    that input, computed independently with the Lua API.
  - Check B measures how much the player's Lua heap grows for 1 and for 16 outputs of 2 MiB. It is printed only, not
    asserted (see below).
- `README.md` describes the test.

Run it with `bugs/run.sh R1-R8-2`. It takes a few seconds and needs docker for the guest build. On audit/prt2 it
prints:

```
check A: input_added raised: /home/user/machine-emulator/doc/recipes/vg.lua:429: outputs Merkle root mismatch; claim none; reference 0xb40f71eb6f11e3ecd48da7b04c5fabe0958e62f9146c3f8bc9b1a698f8def78d
check B: heap growth across input_added: 1 outputs -> 2.00 MiB, 16 outputs -> 32.00 MiB (difference 30.00 MiB; one output is 2.00 MiB)
VIOLATED: R4/section 8: an accepted input whose outputs root does not match its outputs must not stop the honest player from computing its claim
note (not asserted): the honest player's Lua heap grows with the number of outputs it keeps for prove_output; section 8 puts keeping outputs to prove them later off the honest operator's path
run.sh: R1-R8-2: exit 1 (bug present)
```

The result was the same (exit 1) in every run. The reviewer repaired the test:

- **Before the repair.** The prover's version also failed the test when check B failed.
- **Why check B no longer decides the result.** The payloads are kept for `prove_output`, and section 8 says "Keeping
  outputs to prove them later is not on the honest operator's path". A correct fix of the stop alone would therefore
  still have failed the test.
- **After the repair.** A copy of `vg.lua` in which the assert at line 429 only writes a warning (put first on
  `LUA_PATH_5_4`) makes the test print `check A: input_added returned; claim 0xb40f...f78d; reference 0xb40f...f78d`
  and exit 0.

The candidate was found, proved and reviewed on `claude-opus-5-5`, with no fallback.

### Trigger and reachability

Any guest that accepts an input while leaving in the tx buffer a root other than the root of its outputs triggers the
stop. Three kinds of guest do this:

- An application that breaks the rollup interface.
- A buggy application.
- A correctly designed application that an input has taken over. Section 4 says: "Any input may take control of the
  firmware, the kernel, the rollup libraries, and the application."

The tx buffer is guest-writable, and section 2 says: "Any assignment of guest-writable memory and registers is
presumed reachable." The state is therefore reachable from any valid template. The input sender needs only one
accepted input.

### Rating

1. **Out of scope.** The following exclusions were checked:
   - *Applications that are not correctly designed.* This exclusion does not cover the defect. It covers "only what
     such an application gets, which is its outputs and its own correctness", and it adds: "An application that breaks
     the rollup interface may leave its outputs unprovable, but it must never stop the honest operator from computing
     claims or producing proofs. Development tools may instead stop and report the violation." That last permission
     covers this player only if the player is a development tool. Section 3 lists "implementations of an operator that
     no deployment runs" and "development tools" as separate examples, and the manual presents `vg.lua`'s honest player
     as the player that defends an epoch. So the best-supported reading is that it is an operator implementation, not a
     development tool, and the defect is in scope.
   - *Stalls of an application that halts or yields with another reason.* This does not apply, because the guest
     accepts.
   - *Exhausting the operator through outputs.* This exclusion ("Keeping outputs to prove them later is not on the
     honest operator's path") applies to the memory growth of check B, which is therefore not part of this finding.
2. **Role.** The component is Support. Section 3 says: "A defect that only a support component shows is Medium when it
   would rate High or Critical in the role the component stands in for, such as ... the honest operator for an
   implementation of an operator or a tool that computes claims." This clause covers `vg.lua`'s honest player, which
   computes and commits claims. Only this support component shows the defect: `prt.lua` reports
   `outputs_merkle_root_mismatch` as an anomaly instead.
3. **High and Medium cases.** Two cases were checked:
   - In the stood-in honest-operator role, no listed High or Medium case fits. The trigger is a guest state, not data
     the operator may decline, and not an unreachable state.
   - As a support defect, it matches the Medium case "A defect that only a support component shows, when section 3
     rates it Medium".
4. **Critical (in the stood-in role).** The defect would be Critical in the honest-operator role. R4 says: "From any
   reachable state ... the honest operator can always compute the claim ... This holds for every guest, whether or not
   its application is correctly designed (section 8)." The defect breaks this at a reachable state. Section 3 caps it at
   Medium for Support.

Two readings give different classes:

- **Best-supported reading: Medium.** The player is an implementation of an operator that stands in for the honest
  operator.
- **Second reading: Out of scope.** The player is a development tool, which may "stop and report the violation". The
  raised error does report the violation.

What decides between them is whether section 3's "a tool that computes claims" counts as a section 8 "development
tool". The manual's description of `vg.lua` as the player of the verification game, and its distinct listing from
development tools in section 3, favour the first reading.

### Possible solution and risks

In `flush_pending_outputs`, replace the assert with a report and continue. For example, log the mismatch, or record a
flag that disables output proofs for the epoch, as `prt.lua` does with `report_anomaly`. Then `input_added` records the
input's hash and length whatever the root holds.

The main risk is in `epoch_sealed` and `prove_output`. They would then build proofs from a frontier whose root differs
from the root extracted from the settled state, and the referee would reject those proofs. That is harmless, but
`prove_output` should not offer them, and should answer "nothing" when the roots disagree. Separately, the player could
keep only output hashes plus the last payload, as `prt.lua` does, to bound its memory. That is a hardening step, not
part of this fix.

### Risk of not fixing it

`vg.lua` is a recipe that no deployment runs, so no funds are exposed. Anyone who builds an operator from this
manual-documented recipe inherits a player that any input sender can stop, by taking over the application or by
targeting a misbehaving one, with a single accepted input. In a real deployment, that would let a dishonest claim
settle unopposed. As a mitigation outside the code, the manual could state that the honest player must tolerate a
mismatched outputs root, and point to `prt.lua`'s behaviour.

## R2-DFGUESTSTATE-1

**Title.** The manual and the generated device tree declare Sv39 address translation, but every path accepts a satp
write with MODE = 9 and walks four-level Sv48 page tables

**Severity.** Medium

### Problem

The manual's section "The main processor" (doc/README.md, around line 7312) describes the processor's
address translation as: "In addition, Cartesi Machines support the Sv39 mode of address translation and memory
protection. Sv39 provides a 39-bit protected virtual address space, divided into 4KiB pages, organized by a
three-level page table." The device tree that the emulator writes into every machine says
`mmu-type = "riscv,sv39"` (src/dtb.cpp, also listed in the manual around line 8000). The RISC-V privileged
specification says of satp: "Implementations are not required to support all MODE settings, and if satp is written
with an unsupported MODE, the entire write has no effect; no fields in satp are modified."

The interpreter instead accepts MODE = 9 (Sv48): a `csrw satp` with MODE = 9 takes effect, the guest reads it back,
and address translation then performs four-level walks with 512 GiB terapages. Only Sv57 is compiled out
(`NO_SATP_MODE_SV57`). The behavior is deterministic and the same on the native and uarch paths (the Solidity step
replays the same uarch execution), so it is not a divergence between paths. It is an undocumented deviation from
the architecture the manual describes, in the address-translation area that R7 lists.

It does not threaten the goal of section 1: the satp write needs S- or M-mode, Sv48 walks are implemented as the
RISC-V specification defines them, PMA checks on physical addresses still apply, and the shipped kernel follows
the device tree and runs in Sv39. It still violates R7 ("The emulator implements the RISC-V specification and the
devices as the manual documents them, departing only where the manual documents a deviation"), and section 8 makes
the contradiction between the manual and the behavior a defect in one of the two.

The manual is not fully consistent on the point: its flash-drive notes (around lines 7493-7513) reason about "the
Sv48 address space" of the Linux kernel. Those notes describe kernel layout limits; they do not state that the
processor supports Sv48, and the processor section, the device tree and the shipped kernel's behavior all say Sv39.

### Component, role and area

The interpreter (CSR write of satp and virtual address translation), shared by the native path and the uarch
program. AUDIT.md table: "Interpreter, state-access layers, devices, uarch program, ... | Honest operator". Area:
address translation (R7). The manual (doc/README.md) is the other side of the contradiction.

### Location

- src/interpret.cpp, `write_csr_satp` (around lines 2243-2262): the switch accepts `SATP_MODE_SV48`.
- src/riscv-warl.hpp, `WARL_satp` (around lines 97-110): accepts `SATP_MODE_SV48`.
- src/translate-virtual-address.hpp, `translate_virtual_address` (around lines 135-156): walks
  `mode - SATP_MODE_SV39 + 3` levels, so four for MODE = 9.
- src/riscv-constants.hpp, line 32: only `NO_SATP_MODE_SV57` is defined.
- src/dtb.cpp, line 105: `fdt.prop_string("mmu-type", "riscv,sv39")`.
- doc/README.md, "The main processor" (around lines 7306-7320).

### Evidence and test

`bugs/R2-DFGUESTSTATE-1/` contains `test.lua` (the test) and `README.md` (what it asserts and why). Run with
`bugs/run.sh R2-DFGUESTSTATE-1`; it takes under a second.

The test builds fresh 1 MiB machines in M-mode, runs `csrw satp, x5; csrr x6, satp; ld x7, 0(x8)` for 3 mcycles,
and asserts that, unless the manual's "The main processor" section mentions Sv48, a write of satp with MODE = 9
leaves satp at its previous value 0. Controls, which exit 2 if they fail: a MODE = 8 write is accepted, and a
MODE = 10 write (Sv57, compiled out) is ignored. Information lines show that after the MODE = 9 write an M-mode load
with MPRV = 1, MPP = S from VA `0x8080020000`, which only Sv48 can translate, returns the data at PA `0x80020000`
through a root-level terapage, that the same load under Sv39 raises a load page fault, and that the uarch path
(`run_uarch` and `reset_uarch` per mcycle) behaves the same. On audit/prt2 it exits 1 on every run (the reviewer ran
it three times) and prints:

```
control: write 0x8000000000080010 (Sv39) -> satp 0x8000000000080010 (accepted)
control: write 0xa000000000080010 (Sv57) -> satp 0x0000000000000000 (ignored, WARL)
probe:   write 0x9000000000080010 (Sv48) -> satp 0x9000000000080010, guest read-back 0x9000000000080010 (MODE 9)
info:    MPRV load from VA 0x8080020000 (translatable only by Sv48): loaded 0x5356343821212121 from PA 0x80020000 via a root-level terapage
info:    same load with the same table under Sv39: faulted (mcause=0xd, 13 = load page fault)
info:    uarch path: satp 0x9000000000080010, read-back 0x9000000000080010, Sv48-only load translated
manual, 'The main processor': documents Sv39 = true, documents Sv48 = false
VIOLATION: satp.MODE=9 (Sv48) write took effect (satp=0x9000000000080010), but the manual documents only Sv39 (three-level page tables) and the WARL rule requires the write to have no effect
VIOLATED: R7: address translation as the manual documents it: a write of satp with an undocumented MODE (Sv48) must have no effect unless the manual documents Sv48
run.sh: R2-DFGUESTSTATE-1: exit 1 (bug present)
```

The test exits 0 after either fix: the interpreter ignoring MODE = 9, or the manual's processor section documenting
Sv48. Its manual check is a plain search for "Sv48" in that section, so a fix of the manual must actually document
Sv48 support there. The reviewer also booted the pinned `linux.bin` (cartesi/linux v6.18.56-ctsi-1) with the
guest-tools rootfs: satp was `0x8000000000080c05` (MODE 8, Sv39) from the first sample at mcycle 5,000,000 until the
machine halted, so the shipped kernel follows the device tree and does not use Sv48. Found, proved and reviewed on
Opus 5.5; no fallback model.

### Trigger and reachability

Any guest code running in S- or M-mode that writes satp with MODE = 9. Section 4: "Any input may take control of the
firmware, the kernel, the rollup libraries, and the application. It may then run any instruction stream at any
privilege level." Section 2: "Any assignment of guest-writable memory and registers is presumed reachable." The
state is therefore reachable from any valid template. A correct guest that writes MODE = 9 is one that probes satp
modes as the RISC-V specification allows; it gets Sv48 where the manual promises it would stay in its previous mode.

### Rating

1. Out of scope: no exclusion applies. The trigger is guest code, and "The entries about applications exclude what
   an application loses, never an emulator defect that its guest triggers (R4, R5, R8)". No machine API change,
   snapshot, O1 or O2 exclusion is involved.
2. Role: the interpreter and the uarch program, "Honest operator" in the AUDIT.md table. Section 3: "The transition
   function, ... play this role in every deployment."
3. High and Medium cases: section 8 Medium, "An undocumented deterministic deviation, consistent across all paths,
   in behavior that no correct guest relies on for isolation or data integrity (R7)", together with "A contradiction
   between the manual and the behavior on a security-relevant point is a defect in one of the two. It takes the
   severity it would have if the manual were right." If the manual were right (Sv39 only), the emulator departs
   from the RISC-V specification's WARL rule for satp. The deviation is deterministic and the same on the native,
   uarch and step paths. No correct guest relies on MODE = 9 being ignored for isolation or data integrity: a guest
   that follows the manual never writes MODE = 9; one that probes modes as the specification allows gets a
   specification-conformant Sv48 with PMA checks intact; and writing satp already needs S-mode. The clause covers
   this component: it rates behavior of the transition function.
4. Critical: not reached under the preferred reading.

Two other readings give different classes.

- Critical (literal R7): R7 says that in the listed areas, address translation among them, "any deviation lets an
  input subvert a correct guest, even a deviation that is consistent across all paths". Read literally, no
  address-translation behavior is one "that no correct guest relies on", the Medium case does not fit, and step 4
  rates a violation of R7 at a reachable state Critical. What decides: whether the Medium case may judge whether a
  correct guest relies on the specific behavior, or whether R7's list settles that for the whole area.
- Low or no defect: if "support the Sv39 mode" is read as non-exhaustive, and the flash-drive notes' references to
  "the Sv48 address space" as documenting Sv48, the behavior is documented and conforms to the RISC-V specification
  (Sv48 is optional). Against this: the processor section describes only three-level tables, the device tree the
  emulator generates (and the manual lists) says `riscv,sv39`, and the shipped kernel runs Sv39.

### Possible solution and risks

Either change the interpreter or the manual, and keep the device tree consistent with the choice.

- Code: remove `SATP_MODE_SV48` from `write_csr_satp`, `WARL_satp` and `translate_virtual_address` (for example a
  `NO_SATP_MODE_SV48` guard like the Sv57 one). This changes the state transition function, so under R13 it is a new
  protocol version that must change the machine-identification registers, regenerate the uarch program, its
  pristine hash and the Solidity step. Guests that probe satp and currently use Sv48 would fall back to Sv39; the
  shipped kernel already uses Sv39. It shortens the worst-case page walk, which reduces step log size.
- Documentation: state in "The main processor" that Sv48 is supported (and Sv57 is not), and consider advertising
  `riscv,sv48` in the device tree, whose `mmu-type` binding names the largest supported mode. Changing the device
  tree changes the guest's boot trajectory (the kernel would pick Sv48), which also changes canonical hashes of new
  templates, though not the transition function.

### Risk of not fixing it

No loss of soundness or completeness: all paths agree, and the behavior is reachable only by code that already runs
in S- or M-mode. A guest or tool author who relies on the manual's Sv39-only description, or on the device tree, may
assume that a MODE = 9 write leaves satp unchanged, and get four-level translation instead. Mitigation outside the
code: treat the manual's processor section as incomplete and rely on the device tree's `mmu-type` when choosing a
mode.

## R2-DFINPUTCOUNT-1

**Title.** The PRT stored player keeps only 32 input boundaries per epoch, so every per-match unit replays a number of inputs that grows linearly with the epoch's input count (up to about n/16).

**Severity.** Medium

### Problem

The stored player in `doc/recipes/prt.lua` (the one the bridge and `crisium.lua` run) retains machines at input
boundaries in a cache of `STORED_MACHINE_CACHE_CAPACITY = 32` entries. When the cache is full,
`machine_cache_methods:consider` evicts an entry closer than `input_gap` to its predecessor, and if there is none it
doubles `input_gap`. Entry zero is always kept. So with `n` inputs in the epoch the retained boundaries end up
`input_gap/2` to `input_gap` apart, with `input_gap` about `n/16`.

Every unit of work the player does for a match starts from a machine at an exact input boundary, which it gets from
`new_machine_pair_at_epoch_input_offset`. That covers the leaf proof (`event_handler.prove_state_transition`), opening
an mcycle bundle during a bisection (`collect_mcycle_bundle`), building a uarch claim
(`build_uarch_cycle_computation_hash`) and opening a uarch bundle (`collect_uarch_cycle_bundle`). The function forks
the nearest retained entry not past the target (`find_nearest_entry`), and `run_to_epoch_input_offset` then replays
every input between that entry and the target: delivery, a run to the fixed point (up to the mcycle limit per input),
and a stored-pair commit for each. The worst replay is therefore about `n/16` complete inputs per unit. At the
pinned input limit of 2^24 inputs per epoch that is about 2^20 inputs, each of which may legitimately use up to the
application's per-input mcycle budget.

The stored player's agreed pair (`advance_agreed_pair`) does not remove this cost. It walks a machine forward one
input per idle step from the start of the cache gap that holds the dispute interval, so the same replay is done in
idle time while the match's clock runs. It serves only the current bisection and is dropped when a match lies
elsewhere. The per-match replay distance is unchanged.

The code's own comment states the intent that this violates: "The stored player, which the bridge runs, keeps more
input boundaries, so reaching a disputed input replays only a few inputs." (`prt.lua:899-901`).

In the role the player stands in for, this breaks R12. The cost of reaching the position of a per-match operation is
no longer bounded by the application's per-input usage, but by `n/16` times it. An adversary that sends many inputs
and steers each of the logarithmic number of matches to a position just before a retained boundary multiplies the
honest operator's per-match work by a factor that grows with the input count. If the deployment sized the clocks for
the R12 bound (A7), the honest claim can then run out of time. That is a completeness failure (section 1: the honest
operator "cannot respond in time. If the honest claim is eliminated, a dishonest claim can win").

### Component, role and area

The PRT player in `doc/recipes` (`prt.lua`, stored player). AUDIT.md component table: "The PRT player and bridge in
`doc/recipes`, the `cartesi-machine` CLI, and the Lua helper libraries ... | Support. No production deployment runs
the player, the bridge or the CLI." It stands in for the honest operator. Area: the machine cache of input
boundaries and the replay that every per-match unit starts with.

### Location

- `doc/recipes/prt.lua:901`: `local STORED_MACHINE_CACHE_CAPACITY = 32` (used by the stored cache at ~1336).
- `doc/recipes/prt.lua:1217-1245`: `machine_cache_methods:consider` (eviction and `input_gap` doubling).
- `doc/recipes/prt.lua:1247-1258`: `find_nearest_entry`.
- `doc/recipes/prt.lua:2055-2060`: `player_meta.__index:new_machine_pair_at_epoch_input_offset`, and the stored
  override at `3040-3052` (agreed-pair shortcut).
- `doc/recipes/prt.lua:2150-2172`: `run_to_epoch_input_offset` (the replay loop).
- Callers: `event_handler.prove_state_transition` (1956-1977), `collect_mcycle_bundle` (2296),
  `build_uarch_cycle_computation_hash` (2315), `collect_uarch_cycle_bundle` (2334).
- `doc/recipes/prt.lua:2984-3018`: `advance_agreed_pair` (walks one input per idle step inside one cache gap).

The manual (`doc/README.md`, verification-game section on the machine cache) documents the bounded cache for
`vg.lua` ("maintains at most a fixed number of machines spread throughout the epoch ... It uses bounded memory") and
says the PRT player offers each completed input boundary "to the same machine cache the verification game uses". It
does not state a bound on the replay; it does not list the sparse cache as an accepted cost of the honest operator.

### Evidence and test

`bugs/R2-DFINPUTCOUNT-1/` contains `test.lua` and `README.md`. The test uses the emulator's Lua API and the real
`prt.lua` module (`require("prt")`), with no chain. It:

1. builds in a temporary directory a small rolling template: the harness bare-metal guest `accept.bin` (accepts every
   request with the empty outputs root), 4 MiB of RAM, stored at its first rx-accepted manual yield;
2. opens `prt.new_stored_player` on it (geometry `prt.new_geometry(10)`);
3. delivers N1 = 128 empty-payload inputs through `stored_event_handler.input_added` and `idle`;
4. for the input just before each retained boundary (and the last input) calls
   `player:new_machine_pair_at_epoch_input_offset(k)` and counts the completed inputs replayed, by wrapping
   `run_to_input_mcycle_offset` on the player instance;
5. grows the epoch to N2 = 512 inputs, seals it with `epoch_sealed(512)`, and repeats the measurement with the leaf
   proof of a match, `stored_event_handler.prove_state_transition(player, k, 0, 0)` (delivery and step at input `k`;
   that path does not call `run_to_input_mcycle_offset` itself, so every counted call is a replayed input);
6. requires `worst_replay(N2) <= max(worst_replay(N1), 1)`: the replay to reach a disputed input must not grow with
   the epoch's input count. It measures counts, not time.

Run: `bugs/run.sh R2-DFINPUTCOUNT-1` (about 50-70 s). On audit/prt2 it prints, identically on every run:

```
N=128 inputs: 32 retained boundaries (input_gap 4); worst replay 5 inputs (k=66)
N=512 inputs: 32 retained boundaries (input_gap 16); worst replay 23 inputs (k=270)
VIOLATED: R12: reaching a disputed input must replay a number of inputs bounded independently of the epoch's input count (per-match cost bounded by the application's per-input usage); observed 5 at 128 inputs and 23 at 512 inputs
run.sh: R2-DFINPUTCOUNT-1: exit 1 (bug present)
```

The reviewer re-ran it twice (exit 1 both times, same output) and ran a control: the same unmodified test against an
out-of-tree copy of `prt.lua` whose only change is `STORED_MACHINE_CACHE_CAPACITY = 1 << 20` (every boundary
retained). The control reports 0 replayed inputs at both sizes and exits 0, so the test fails for the cache policy and
passes once the replay is bounded. Found by the DFINPUTCOUNT hunter, proved and reviewed on Opus 5.5; no fallback.

### Trigger and reachability

Any input sender triggers it by sending inputs: the replay grows with the number of inputs in the disputed epoch,
whatever their payloads (the test uses empty payloads on an application that accepts everything, a correctly
designed application). Section 7 lets the adversary "Send any number of inputs the deployment accepts" and "Steer the
dispute to any position of the honest computation, and force the honest claim through a logarithmic number of
matches", so it can choose a disputed input just before a retained boundary in each match. No unreachable state is
involved: the state is an ordinary epoch of a valid template with many inputs.

### Rating

1. Out of scope: no. The trigger is the number of inputs and the dispute position, both adversary capabilities of
   section 7. The exclusion "An application that tries to exhaust the honest operator through the number of its
   outputs or yields" covers outputs and yields, not inputs. "Average-case performance that does not change the
   worst-case cost of any operation listed in R12" does not apply, because the worst-case cost of reaching a disputed
   position grows. No obligation A1 to A8 has to be violated, and the application is correctly designed.
2. Role: the component is the PRT stored player, Support by the AUDIT.md table ("The PRT player and bridge in
   `doc/recipes` ... | Support"). Section 3: "A defect that only a support component shows is Medium when it would
   rate High or Critical in the role the component stands in for, such as ... the honest operator for an
   implementation of an operator". The player is an implementation of an operator, so it is rated as the honest
   operator would be and capped at Medium.
3. High and Medium cases, in the honest-operator role: the High case "A defect that lets the guest, or host load that
   the deployment was sized for, multiply the worst-case cost of an operation listed in R12 by a constant factor"
   does not fit: the trigger is the input count, not the guest or host load, and the factor grows with `n`. The
   Critical list's "An operation listed in R12 whose worst-case cost a guest can make unbounded ..." is guest-driven
   and does not fit either. Section 8 Medium, "A defect that only a support component shows, when section 3 rates it
   Medium", is the case that applies to the component itself.
4. Critical, in the honest-operator role: R12, "Each is measured from a machine at its starting position. Reaching
   that position costs at most the mcycles from the nearest retained input boundary, which the application's
   per-input usage bounds. A7 must cover that cost a bounded number of times for every match, at either level, that
   the tournaments force on the honest claim." Here reaching the position costs up to about `n/16` inputs' worth of
   mcycles, which the per-input usage does not bound. Section 8: "violating any rule or obligation at a reachable
   state, or anywhere on the honest operator's path, is critical." Critical for an honest operator, so Medium for the
   support player.

Second reading. R12 says "the nearest retained input boundary" without saying which boundaries an operator must
retain. If that phrase is read as leaving retention to the operator, with the deployment sizing its clocks for
whatever gap the operator keeps, then the sparse cache is a sizing matter and not a rule violation: Low (no rule
violated). If instead the growth is read as the High constant-factor case (the factor is bounded by the input limit,
up to about 2^20), the honest-operator rating is High, and the support rating is still Medium. The preferred reading
is the first one above: the relative clause "which the application's per-input usage bounds" makes the distance to
the nearest retained boundary bounded by one input's usage, and R12's last paragraph lets the operator's storage
grow with the inputs of open epochs, so retaining every boundary is what the model expects. What would decide is
whether the maintainers intend "retained input boundary" to mean every input boundary of an open epoch.

### Possible solution and risks

Retain every input boundary of an open or disputed epoch in the stored player (stored machines are reflink clones in
the recipes' setup, and R12 allows storage that grows with the inputs of open epochs), or at least cap `input_gap` at
a constant and let the cache grow with `n`. Risks: disk use grows with the input count (a stored Linux machine is
hundreds of MB without reflinks, so the recipes' reflink mount becomes a requirement), the stored state file that
lists the entries grows, and `remove_evicted`/reopen logic must still clean up after a stop (O2). The default fork-based
cache of `vg.lua` can keep its bounded design since it is a demonstration; the manual's statement about the PRT
player sharing that cache should then be updated.

### Risk of not fixing it

The player is support, so no production deployment is exposed directly. But it is the reference that shows how to
defend a claim, and it understates the cost of doing so: a node that copies its cache policy would let any input
sender, by filling an epoch with inputs, make each match's replay grow linearly with the epoch's input count, up to
about 2^20 inputs per unit at the pinned limit, and lose by timeout under clocks sized for R12. Mitigation outside the
code: run it only on epochs with few inputs, or size the clocks for the replay of `n/16` inputs per unit.

## R2-DFINPUTCOUNT-2

**Title.** The PRT player fetches epoch 0's inputs only from the DaveConsensus deployment block, but DaveConsensus seals into epoch 0 every input the application already had, so the player crash-loops.

**Severity.** Medium

### Problem

The pinned DaveConsensus seals epoch 0 in its constructor. It computes `inputIndexUpperBound =
_nextInputIndexUpperBound(0)`, which is `min(InputBox.getNumberOfInputs(app), 2^24)`, and emits `EpochSealed(0, 0,
inputIndexUpperBound, ...)`. Every input the application received before the consensus existed therefore belongs to
epoch 0 in the on-chain input record.

`crisium.lua` sets `first_block = getDeploymentBlockNumber()` of the consensus (line 125). In `open_epochs` it opens
epoch 0's listener with `first_input_block = previous_seal and eth.small(previous_seal.log.blockNumber) or
first_block` (line 267). For epoch 0 there is no previous seal, so the listener in `prt-epoch.lua` (`poll`, line 37)
fetches InputAdded logs only from the consensus deployment block on. It never sees inputs in earlier blocks. When it
applies `EpochSealed(0, 0, n)` with `n > 0` inputs it has not seen, the assert `inputIndexUpperBound == input_begin +
#inputs` fails with "sealed input count mismatch" (`prt-epoch.lua:96`). If some inputs were in the deployment block and
some before it, it fails "input stream has a gap or duplicate" (line 73) instead. The error leaves `pass()` and the
process exits. `prt-supervise.sh` relaunches it, and it rebuilds the listener with the same `first_input_block`, so it
fails the same way on every launch. The player never computes or defends epoch 0's claim, nor any later epoch's.

In the role the player stands in for, this is a completeness failure of section 1: the honest operator "cannot respond
in time. If the honest claim is eliminated, a dishonest claim can win." It also breaks R4 directly, because the player
does not assign inputs to epochs as the referee does.

### Component, role and area

The PRT player in `doc/recipes`: `crisium.lua` (how it derives epoch 0's first input block) and `prt-epoch.lua` (the
epoch input and seal listener). AUDIT.md table: "The PRT player and bridge in `doc/recipes`, ... | Support. No
production deployment runs the player, the bridge or the CLI." It stands in for the honest operator. The DaveConsensus
constructor (referee model, deployed referee) behaves as designed and is not the defect.

### Location

- `doc/recipes/crisium.lua`: `first_block` (line 125), `open_epochs` (`first_input_block`, line 267).
- `doc/recipes/prt-epoch.lua`: `methods:poll` (`history:get_logs(address, self.first_input_block, ...)`, line 37; asserts
  at lines 73 and 95-98); `M.new` (`first_input_block = args.first_input_block or args.first_block`, line 167).
- For reference: `cartesi-rollups/contracts/src/DaveConsensus.sol` of Dave v3.0.0-alpha.7, constructor lines 141-145,
  `_nextInputIndexUpperBound` line 470 (identical in `work/dave/released` and `work/dave/patched`).

### Evidence and test

`bugs/R2-DFINPUTCOUNT-2/` contains:

- `test.sh`: the test. It starts a private anvil on a free port from 18640 (never 8545/8546) and stops it at exit. It
  deploys the pinned Dave contracts of `work/dave/patched` (Tournament, CartesiStateTransition, the parameters
  provider, MultiLevelTournamentFactory, InputBox, ApplicationFactory) with permissionless entry points only. In
  scenario A, `ApplicationFactory.newApplication` creates an application whose outputs Merkle root validator is the
  precomputed address of the deployer's next contract creation. Account 1, an untrusted input sender, then adds two
  inputs with `InputBox.addInput` in blocks 10 and 11, and the deployer creates the DaveConsensus at that address in
  block 14, which emits `EpochSealed(0, 0, 2)`. Scenario B, the control, has the same shape, except that both inputs
  are mined in the consensus's own deployment block. The test checks these premises on chain. It then runs the real
  `crisium.lua` in sentinel mode on each application with `--input-policy=0 --status-file=...`. The control must report
  epoch 0 sealed with 2 inputs, or the test exits 2. Scenario A runs twice from the same state directory, a launch and
  a relaunch as `prt-supervise.sh` would do. Each must report epoch 0 sealed with 2 inputs (exit 0). Dying on the
  listener's input-assignment checks, or sealing another count, is a violation (exit 1). Anything else exits 2. The
  300 s wait is a setup timeout, not part of the verdict.
- `make-checkpoint.lua`: stores epoch 0's checkpoint from `configs/baremetal-template` with
  `prt.store_first_epoch_checkpoint`, as `prt-demo.lua` does.
- `README.md`: the description above and the expected output.

Run with `bugs/run.sh R2-DFINPUTCOUNT-2` (about 21 s). The reviewer re-ran it on audit/prt2 and got exit 1. It prints:

```
scenario A: app 0x61c3..., consensus 0xa513... deployed at block 14; inputs 0,1 at blocks 10,11; EpochSealed(0, 0, 2)
scenario B: app 0x23dB..., consensus 0x8A79... deployed at block 18; inputs 0,1 at blocks 18,18; EpochSealed(0, 0, 2)  [control]
== control: crisium on application B (inputs in the consensus deployment block)
control result: sealed 2
== crisium on application A (inputs before the consensus deployment), launch 1 and a relaunch
launch 1: exited 1; error: lua5.4: doc/recipes/prt-epoch.lua:96: sealed input count mismatch
launch 2: exited 1; error: lua5.4: doc/recipes/prt-epoch.lua:96: sealed input count mismatch
VIOLATED: R4 'It assigns inputs to epochs exactly as the referee does': the consensus sealed inputs [0, 2) into epoch 0, but the player fetched epoch 0's InputAdded logs only from block 14 (consensus deployment) and died on every launch (2 of 2) instead of delivering them
run.sh: R2-DFINPUTCOUNT-2: exit 1 (bug present)
```

The prover reports exit 1 on 3 runs, and exit 0 with an uncommitted copy of `crisium.lua` whose epoch-0 fallback is
block 0. The test asserts what a correct player must do (seal epoch 0 with the inputs the consensus assigned), so any
correct fix makes it pass. Found, proved and reviewed on Opus 5.5; no fallback model.

### Trigger and reachability

The deployer chooses the deployment shape, and any input sender supplies the inputs. The shape is an application
created with `ApplicationFactory.newApplication` that names, as its validator, the address at which a DaveConsensus
will be created later (CREATE or CREATE2 address precomputation), with the consensus created in a later block. Between
the two blocks, anyone may add inputs: `InputBox.addInput` only requires that the application has code and is not
foreclosed. The DaveConsensus constructor accepts any `appContract` and deliberately counts all of its pending inputs
into epoch 0. All entry points are public and documented, and the resulting on-chain input record meets A3.

It is not reachable through `DaveAppFactory.newDaveApp`, which creates the application and its consensus in one
transaction. `prt-deploy.lua` uses that path, so the recipe demo does not show the defect. Inputs cannot be sent ahead
to a predicted application address, because `InputBox.addInput` reverts with `ApplicationNotDeployed` while the address
has no code. `Application.migrateToOutputsMerkleRootValidator` is restricted to the application's deployment block
(`onDeploymentBlock`), so migrating to a consensus created in that block cannot trigger it either: the inputs are then
in the consensus deployment block, which the listener fetches (scenario B).

### Rating

1. Out of scope: no. The trigger is a deployment of the pinned referee through public factory and InputBox entry
   points, plus inputs from untrusted senders (section 7: "Send any number of inputs the deployment accepts"). It does
   not "need the deployment to violate one of A1 to A8": A3 holds, since the input record assigns 2 inputs to epoch 0,
   within the limit. No other exclusion (outputs or yields, snapshots, O1 or O2, reorganizations, host faults) is
   involved.
2. Role: the PRT player in `doc/recipes`, Support by AUDIT.md ("Support. No production deployment runs the player").
   Section 3: "A defect that only a support component shows is Medium when it would rate High or Critical in the role
   the component stands in for, such as ... the honest operator for an implementation of an operator". The player is
   an implementation of an operator, so this clause covers it, and the defect is never above Medium.
3. High and Medium cases: section 8, Medium, "A defect that only a support component shows, when section 3 rates it
   Medium." No High case fits in the stand-in role: the crash is caused by the on-chain input record, which the honest
   operator must process, not by data it "may decline".
4. Critical in the stand-in role: R4, "The honest operator defends every epoch whose dispute is open ... It assigns
   inputs to epochs exactly as the referee does, including the input limit per epoch (A3)", and "After a stop, it
   restarts from a directory that O2 guarantees and keeps defending its claim". Section 8, Critical: "violating any rule
   or obligation at a reachable state, or anywhere on the honest operator's path, is critical", and "A crash, hang,
   out-of-bounds read, or unbounded allocation caused by data from other parties that the honest operator must
   process." Capped by step 2: **Medium**.

Second reading: Low, if an application created separately from, and before, its DaveConsensus is not a deployment the
player has to support. The fact that decides is whether the recipes or the manual restrict the player to
`DaveAppFactory` deployments. Neither does: `crisium.lua` says "From its application's address it discovers the
consensus", and the pinned DaveConsensus constructor takes any application and handles its pending inputs. The
threat model defines a deployment as "A referee with its verifiers and dispute constants, the on-chain input record it
reads, and the validator nodes", with no restriction on how the application was created. Medium is the better
supported reading.

Related to R1-A3-1 (the previous-seal branch of the same `first_input_block` expression, for later epochs and backlogs
past the 2^24 cap). This one is the `first_block` branch for epoch 0, with another trigger, and it needs its own fix.

### Possible solution and risks

For epoch 0, start the input fetch at the block where the application could first receive inputs, the application's
`getDeploymentBlockNumber()` (an `IApplication` function in cartesi-rollups-contracts 3.0.0-alpha.10). InputBox rejects
inputs to an address without code, so no input of the application is older. Keep `first_block` (the consensus
deployment) for the consensus and tournament logs. A fetch from block 0 also makes the test pass, but it scans the
whole chain, which R12 forbids ("must not grow ... with chain activity that does not belong to the application").
Risk: a wider first fetch for epoch 0, bounded by the application's lifetime before its consensus. An application
whose `getOutputsMerkleRootValidator` is not an `Application` from this factory needs a fallback, such as InputBox's
own deployment block.

### Risk of not fixing it

A deployment that uses the player and creates its application before its DaveConsensus, in a different block, is
exposed to any party who adds an input in between. The player then crash-loops on epoch 0 and never defends a claim,
so a dishonest claim can win epoch 0 by timeout. Mitigation outside the code: deploy through
`DaveAppFactory.newDaveApp`, or create the consensus in the application's deployment block. No production deployment
runs the player, but a node that copies its epoch-0 logic inherits the failure.

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

## R2-DFSTORED-1

**Title.** After an O1 adoption with `clear_hash_tree`, `store` with sharing `none` or `config` copies the template's
un-rebuilt `.dht`/`.dpt` files, so the operator's own synced snapshot reloads with the stale root hash.

**Severity.** Medium (preferred reading: storing with sharing `none` or `config` is a machine API operation off the
honest operator's path). Critical under the reading in which a production validator node stores an adopted template
with sharing `none` or `config` and later reloads that snapshot without a rebuild; see Rating.

### Problem

An operator adopts a stored machine it did not produce. As O1 requires, it loads it with `clear_hash_tree = true`.
The root hash `H` is then the content hash, and `verify_hash_tree()` succeeds. If the operator then calls
`machine:store(dir, SHARING_NONE)` or `machine:store(dir, SHARING_CONFIG)` and `sync_stored(dir)`, the new directory
holds the right contents. But for every range that is not shared, it also holds byte copies of the template's
original `.dht` and `.dpt` files. The rebuild never touched those files. Reloading this directory without a rebuild
gives the template's stale cached root instead of `H`, and `verify_hash_tree()` fails.

The directory was written by the emulator in the operator's own process, synced, and never used with sharing, so O2
guarantees it. R1 lets the honest operator reload such a directory without a rebuild. R9 requires every persisted hash
in every snapshot the emulator itself writes to equal the root of the actual contents. An operator that relied on
such a snapshot would compute a wrong hash and wrong claims from it, which is a completeness failure (section 1).
That outcome needs a node that stores with these modes. Otherwise the defect still violates R9.

`store` with sharing `all`, the default of the Lua binding and of the CLI, writes the in-memory trees and is correct.

### Component, role and area

Emulator core, storing machines: `machine::store`. In the AUDIT.md component table, "storing, loading, cloning and
syncing machines" has the role Honest operator. Area: how `store` persists the cached hash-tree data of ranges that it
copies from the initial backing stores, after `hash_tree::clear` rebuilt only the in-memory trees.

### Location

- `src/machine.cpp`, `machine::store`, unshared branch of the `store_address_range` lambda (about lines 460-480).
  `os::copy_file(c.data_filename, ...)` copies the initial data. When both tree files exist, it then runs
  `os::copy_file(c.dht_filename, dht_filename)` and `os::copy_file(c.dpt_filename, dpt_filename)` without checking
  that the trees still describe the data. In the same mode, the `.sht`/`.phtc` files are written blank.
- `src/hash-tree.cpp`, `hash_tree::clear` (line 744), called from `machine::clear_hash_tree` when the runtime config
  sets `clear_hash_tree`. It marks the in-memory dirty-page trees dirty and clears the in-memory dense trees. For an
  unshared load these are private mappings, so the files on disk keep the old data.
- `src/cm.h`, `cm_store` documents the modes: "CM_SHARING_NONE: Copies backing stores from the initial machine state
  (rarely useful). CM_SHARING_CONFIG: Store current machine state for shared backing stores; others are copied from
  the initial state."

### Evidence and test

`bugs/R2-DFSTORED-1/` contains `test.lua` (the test) and `README.md` (what it asserts and its expected output). Run it
with `bugs/run.sh R2-DFSTORED-1`. It takes about 8 s and uses about 300 MB in a `mktemp` directory under `/tmp`, which
it removes at exit.

The test copies `bugs/harness/work/configs/baremetal-template/machine` and fills its cache with a SHARING_ALL load,
`get_root_hash` and a sync. It then overwrites 64 bytes at offset 0x100000 of the RAM `.bin`, outside the emulator,
so the cached data describes other contents. The result models a foreign template whose contents are valid but whose
cache is stale. Cached data is not a valid-template condition.

The test records the stale cached root (plain load) and `H` (load with `clear_hash_tree`, which verifies). It exits 2
if they are equal. Then, for each mode `all`, `config` and `none`, it does the following:

1. Loads the template with `clear_hash_tree = true` and checks that the root is `H`.
2. Stores the machine with that mode and destroys it.
3. Runs `sync_stored` on the new directory.
4. Reloads the directory without a rebuild and records the root and the result of `verify_hash_tree()`.
5. As a precondition (exit 2 on failure), reloads it with a rebuild and checks that the contents give `H`.

The test asserts that, in every mode, the reloaded root equals `H` and the tree verifies.

On audit/prt2 it exits 1. The reviewer ran it twice and the prover three times, with the same output each time. The
`page ... is not marked dirty but is dirty` / `! FAILED!` lines that `verify_hash_tree` prints are left out here:

```
template stale cached root: 0x428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
template content hash (O1): 0xfda9eee87acd2a16b42a3c18191da8ece80e878b4fd228d3797954dc0b3dd27d
store sharing=all    reload root 0xfda9eee8...dd27d  (== content hash)  verify_hash_tree=true
store sharing=config reload root 0x428a6bb8...2ac75  (== STALE template cache)  verify_hash_tree=false
store sharing=none   reload root 0x428a6bb8...2ac75  (== STALE template cache)  verify_hash_tree=false
OK: R9/O1: after an O1 rebuild, store(dir, sharing=all) + sync_stored, ...
VIOLATED: R9/O1: after an O1 rebuild, store(dir, sharing=config) + sync_stored, ...
VIOLATED: R9/O1: after an O1 rebuild, store(dir, sharing=none) + sync_stored, ...
run.sh: R2-DFSTORED-1: exit 1 (bug present)
```

SHARING_ALL is the passing control. The rebuild precondition shows that only the cached data is wrong. The test exits
0 once `store` writes cached data that matches the stored contents. All agents ran on Opus 5.5 (`claude-opus-5-5`),
and no fallback was used.

### Trigger and reachability

The honest operator triggers it with documented operations alone. No adversary or guest action is needed beyond
supplying a template whose cached hash-tree data is stale. Anyone who distributes the template, or a damaged copy of
it, can supply one.

1. Adopt a valid template the operator did not produce with `clear_hash_tree` (O1).
2. Call `store(dir, SHARING_NONE)`, or `store(dir, SHARING_CONFIG)` with at least one range configured as not shared.
3. Run `sync_stored(dir)`.
4. Later, load `dir` without `clear_hash_tree`.

No state reachability is involved. The template satisfies every valid-template condition, and section 4 says "A
snapshot's cached hash-tree data is not part of any valid-template condition". The operator's own snapshots, written
from consistent trees, never trigger it.

### Rating

1. Out of scope: no.
   - "Defects that need the cached hash-tree data of a stored machine the operator did not produce to survive its
     adoption without a rebuild (O1)" does not apply. The operator did rebuild, and the emulator re-emitted the
     pre-rebuild files into a new snapshot. Section 5 says: "O1 and O2 bind the emulator too ... A defect that defeats
     the rebuild itself, or that damages a directory while O2 guarantees it, is not excused by them."
   - "Defects triggered only by loading a snapshot that the emulator did not write and that does not meet the
     conditions of a valid template" does not apply. The template meets them, and the reloaded directory is one the
     emulator wrote.
   - "Defects that need the honest operator to reload a stored directory that O2 does not guarantee" does not apply.
     The directory was stored, synced, and never used with sharing.
   - How to rate, step 1: "A wrong hash after documented operations, destroying the machine, and a sync is not" out
     of scope.
2. Role: `machine::store`. The AUDIT.md table gives "storing, loading, cloning and syncing machines" the role Honest
   operator. Section 3 says these "play this role in every deployment" "(within the limits of O1 and O2)", and the
   limits are respected here. That clause covers this component.
3. High and Medium cases: Medium fits under the preferred reading: "A machine API operation off the honest operator's
   path that, used as documented, leaves the hash tree, the cached state of the machine or a stored directory
   inconsistent with the machine's contents (R9)." This clause covers `store` with sharing `none` or `config` if that
   operation is off the honest operator's path. The manual calls `none` "rarely useful". Both modes store the initial
   state of unshared ranges instead of the current one. The Lua binding and the CLI default to `all`. The only
   operator implementation in this repository, the PRT player (Support), stores with the default `all`
   (`doc/recipes/prt.lua` line 2712). An operator that wants its own copy of an adopted template gets a correct one
   from `store(dir, SHARING_ALL)`.
4. Critical, under the alternative reading: "Storing and reloading the machine" is on the honest operator's path
   (section 2). If a production validator node stores an adopted template with sharing `none` or `config`, the
   defect violates R9 on that path: "The content hash must equal the root of the actual contents. This applies to
   every cached, incremental, or persisted hash, after any sequence of documented operations. It includes ... every
   snapshot the emulator itself writes", which means "a directory that O2 guarantees". The cached data is the kind R1
   lets the operator rely on: "it was either written by the operator's own process into a directory that O2
   guarantees, or rebuilt from the contents on adoption (O1). This rule applies to it". A reload without a rebuild
   would then give a wrong hash, a completeness failure, which section 8 rates "Critical" ("anywhere on the honest
   operator's path").

What decides between the readings: whether a production validator node (the Cartesi Rollups Node or the Dave sling
node, both outside this audit) calls `store` with sharing `none` or `config` on a machine adopted with
`clear_hash_tree`, and later reloads that snapshot without a rebuild. The threat model does not say whether a
documented but rarely useful mode of a component in the Honest operator role counts as "on the honest operator's
path".

### Possible solution and risks

In the unshared branch of `machine::store`, stop treating the source tree files as a trusted pair once the in-memory
trees were cleared. One fix records in the machine that it was loaded with `clear_hash_tree`, or that
`clear_hash_tree` was called since the load. For copied ranges, `store` then writes blank `.dht`/`.dpt` files with the
existing `os::truncate_file` path, so the next load rehashes those ranges. A simpler fix always writes blank trees for
copied ranges.

Risks:

- A load after a store with these modes rehashes the copied ranges. That cost is linear and bounded (R12), but slower
  than reusing trees.
- The in-memory trees must not be written instead of blank ones. With sharing `none` or `config` after the machine
  ran, the in-memory trees describe the current contents, not the copied initial ones.
- `clone_stored` has the same copying behavior. It is excused by O1, because loading a clone of a foreign directory is
  an adoption that must rebuild. The manual could say so explicitly.

### Risk of not fixing it

A node that adopts a template with `clear_hash_tree` and keeps its own copy through `store` with sharing `none` or
`config` would hold a synced, O2-guaranteed snapshot that reloads with the template's stale root. If it trusted that
root, it would defend wrong claims, and a dishonest claim could win. Anyone who distributes a template with stale
cached data, or a damaged copy of one, can trigger it.

Mitigations outside the code:

- Store adopted machines only with sharing `all`, which is the default.
- Alternatively, reload every snapshot derived from a foreign template with `clear_hash_tree`.
- Document in `cm_store` and the manual that `none` and `config` copy the source directory's cached hash-tree data
  unchanged.

## R2-DFYIELD-1

**Title.** The PRT player's claim pass copies, and for outputs keccak-hashes, the tx-buffer payload length that each automatic yield declares (up to 2 MiB), multiplying its per-yield cost by a guest-chosen length.

**Severity.** Medium (support component standing in for the honest operator, where it would rate High). Out of scope under a broad reading of the outputs/yields exclusion of section 8; see Rating.

### Problem

While the PRT player computes its mcycle-level claim for an epoch, `run_next_input` calls
`run_to_input_mcycle_offset` with a `last_output` table, which defines an `on_yield_automatic` callback. `run_to_stop`
then calls `receive_cmio_request(machine)` at every automatic yield. `machine:receive_cmio_request()` returns
`min(htif_tohost_data, 2 MiB)` bytes of the tx buffer. DATA is a length the guest declares in `tohost`, and the guest
does not have to write those bytes. For `TX_OUTPUT` the callback then keccak-hashes the payload. For `TX_REPORT` and
any other reason it reads the payload and drops it.

So one guest store to `tohost` (a few mcycles) makes the player copy up to 2 MiB, over JSON-RPC for a forked player,
and hash up to 2 MiB more. The emulator's own claim work for the same mcycles (`collect_mcycle_root_hashes`) reads no
payload at all. The computation hash depends only on state hashes. Section 4 says "The outputs Merkle root, the output
payloads, and every other yield reason are opaque guest data that the state merely commits to", and section 8 says
"Keeping outputs to prove them later is not on the honest operator's path". So the claim's semantics do not require
this work. Any guest, after it reads an input, can multiply the host cost of each automatic yield in the claim pass by
a large constant. Measured here: about 75-100x the time of an otherwise identical input, at the same mcycle count.
The hunter measured 170x locally and 470x over JSON-RPC for a tight yield loop.

This does not break the goal of section 1 by itself, because the factor is bounded. It removes the cost margin that
A7 sizes the clocks for (R12 "a part of a claim"), which is the High constant-factor case of section 8. The player is
a support component, so it is capped at Medium.

### Component, role and area

The PRT player in `doc/recipes` (`prt.lua`), the input pass that builds its mcycle computation hash. AUDIT.md
component table: "The PRT player and bridge in `doc/recipes`, the `cartesi-machine` CLI, ... | Support. No production
deployment runs the player, the bridge or the CLI." The player is "an implementation of an operator" that "computes
claims" (THREAT_MODEL.md section 3), so it stands in for the honest operator. The `cartesi-machine` CLI's `run_to_stop`
(`src/cartesi-machine.lua`, which calls `get_and_print_yield` at every automatic yield) follows the same pattern and
is also Support. It is not tested here.

### Location

- `doc/recipes/prt.lua`: `receive_cmio_request` (about line 972), `run_to_stop` (about lines 1396-1410),
  `player_meta.__index:run_to_input_mcycle_offset` (about lines 2066-2124; the callback at 2081-2091 runs
  `keccak(output_data)` for `TX_OUTPUT`), `player_meta.__index:run_next_input` (about lines 2243-2272, the only
  caller that passes `last_output`, so the only one that enables the callback).
- `src/clua-i-machine.cpp` `machine_obj_index_receive_cmio_request` and `src/machine.cpp`
  `machine::receive_cmio_request`: these return the declared length of tx-buffer bytes. They work as documented; the
  defect is in how the caller uses them.
- The dispute replays (`run_to_epoch_input_offset`, `build_uarch_cycle_computation_hash` and others) pass no
  `last_output` and are not affected.

### Evidence and test

`bugs/R2-DFYIELD-1/` contains:

- `guest.c`, a bare-metal rollup guest built with `bugs/harness/baremetal/build.sh`. It boots by accepting with the
  empty outputs root. For each advance input it makes `count` automatic yields with the reason and declared length the
  input selects, writing only an 8-byte counter to the tx buffer. It then spins to a fixed mcycle budget and accepts
  with the outputs root the host passes in.
- `test.lua`. It stores a valid-template-style machine and checks the guest on a plain machine without the player.
  Then, for each of three inputs (the same 50 yields and 8375 mcycles each), it runs a fresh forked honest player
  (`prt.new_forked_player`) through `event_handler.input_added`, which calls `run_next_input`. It wraps the machine's
  `receive_cmio_request` method and `cartesi.keccak256` to count the payload bytes the pass copies and hashes. The
  inputs are `control` (TX_OUTPUT declaring 8 bytes), `outputs` (TX_OUTPUT declaring 2 MiB) and `reports` (TX_REPORT
  declaring 2 MiB). The test asserts that the per-yield excess over the control is at most 1024 bytes. It exits 2 on
  setup errors: the guest does not behave, an input is not accepted, or the mcycle counts differ.
- `README.md`, the prover's description.

Run: `bugs/run.sh R2-DFYIELD-1` (about 10 s). It exited 1 on both of the reviewer's runs, with identical byte
counts each time. It prints:

```
control  yields=50 declared=8        mcycles=8375   accepted=true outputs=50  receive: 51 calls 432 B | keccak: 361 calls 20304 B | time 0.030 s | anomalies={}
outputs  yields=50 declared=2097152  mcycles=8375   accepted=true outputs=50  receive: 51 calls 104857632 B | keccak: 361 calls 104877504 B | time 2.949 s | anomalies={}
reports  yields=50 declared=2097152  mcycles=8375   accepted=true outputs=0   receive: 51 calls 104857632 B | keccak: 138 calls 8832 B | time 2.968 s | anomalies={}
outputs: payload bytes copied+hashed by the claim pass 209735136 vs control 20736: 4194288 extra bytes per yield (allowed 1024); time 97.96x the control
reports: payload bytes copied+hashed by the claim pass 104866464 vs control 20736: 2096915 extra bytes per yield (allowed 1024); time 98.60x the control
VIOLATED: section 8 High / R12 'a part of a claim': ...
run.sh: R2-DFYIELD-1: exit 1 (bug present)
```

Timings vary between runs (74-98x on the second run); the byte counts do not, and only the byte counts are asserted.
The player reports no anomaly and the outputs root matches, so the guest is a correctly designed application. The
`reports` case alone isolates the defect: its payload is read on the claim path and thrown away. The prover reports
that a scratch `prt.lua` whose `run_to_stop` does not read automatic-yield payloads makes the test exit 0. Found,
proved and reviewed by Opus 5.5; no fallback model was used.

### Trigger and reachability

Any guest code after it reads an input (section 4, "guest code after it reads an input" is untrusted) can trigger
this. Each automatic yield is one store of `yield | automatic | reason | DATA` to `tohost`, with DATA up to the 2 MiB
tx-buffer length, and costs the guest a few mcycles. Section 2 says "Any assignment of guest-writable memory and
registers is presumed reachable", and the test reaches the state from a stored template through ordinary input
delivery. No unreachability argument is needed. Automatic yields are enabled in the default configuration, and every
honest player runs `run_next_input` on every input.

### Rating

1. Out of scope. The exclusion that comes closest is "An application that tries to exhaust the honest operator
   through the number of its outputs or yields. Each costs the guest mcycles, which the application's own bound limits
   (section 2). This holds as long as ... each yield costs it a bounded amount (R12)." The preferred reading is that it
   does not cover this defect. The trigger is not the number of yields: the test keeps the yields (50) and the mcycles
   (8375) fixed and changes only the declared length, and the cost grows 75-100x. "How to rate" says "Check the
   trigger, not the symptom" and that the application entries "exclude what an application loses, never an emulator
   defect that its guest triggers". The clause's proviso, "a bounded amount (R12)", points at R12, and section 8 rates
   a defect that multiplies an R12 cost by a constant factor as High even though the cost stays bounded. The guest is
   correctly designed, so the "not correctly designed" exclusion does not apply either, and in any case it never
   excuses the honest operator's claim work (R4). Under the broad reading, where any per-yield cost with a constant
   upper bound (2 MiB) satisfies "bounded amount", the finding is Out of scope.
2. Role. The defect is in the PRT player, a component in the Support role per AUDIT.md: "The PRT player and bridge in
   `doc/recipes` ... | Support". Section 3: "A defect that only a support component shows is Medium when it would rate
   High or Critical in the role the component stands in for, such as ... the honest operator for an implementation of
   an operator or a tool that computes claims." This clause covers the player, which computes claims. No component in
   the honest-operator role shares the defect: `collect_mcycle_root_hashes` and the machine API read no payload unless
   asked.
3. High and Medium cases. In the honest-operator role the defect matches section 8 High: "A defect that lets the guest
   ... multiply the worst-case cost of an operation listed in R12 by a constant factor, compared with the same
   operation without the defect, while staying within what the deployment was sized for. A cost that the specified
   semantics require is not a defect. When the sizing is unknown, rate such a constant-factor increase High". R12 lists
   "a part of a claim". The claim's semantics do not require payload reads: section 4 calls output payloads and other
   yield reasons "opaque guest data that the state merely commits to", and section 8 says "Keeping outputs to prove
   them later is not on the honest operator's path". If the factor exceeded the deployment's sizing it would be
   Critical in that role. Either way, the support cap gives the Medium case "A defect that only a support component
   shows, when section 3 rates it Medium."
4. Critical. Not reached. The support cap in step 2 ("never above Medium") applies.

Two readings: Medium under the narrow reading of the outputs/yields exclusion (preferred), and Out of scope under the
broad one. The deciding question is whether "each yield costs it a bounded amount (R12)" is met by any constant upper
bound per yield, or only by a per-yield cost that no defect has multiplied, as the High constant-factor clause
requires. The threat model does not say. A second, smaller question is whether output hashing inside the claim pass
counts as a cost that "the specified semantics require". The threat model puts keeping outputs off the honest
operator's path, so this review says no. The `reports` half of the test does not depend on that question.

### Possible solution and risks

In `run_to_stop` or the callback, read only the reason (`htif_tohost_reason`) at an automatic yield, and never copy
the payload of a non-output yield. Move output tracking (reading and hashing `TX_OUTPUT` payloads to build the
outputs frontier and the last-output proof) out of the claim pass. For example, do it in a separate pass or machine
that does not delay the claim, or only when output proofs are wanted. The automatic-yield callback should be limited
to that pass. Risks: the player's output proofs and the outputs-root anomaly check depend on the frontier built in
this pass, so moving it must keep `commit_epoch_state`, the stored `outputs_frontier` and `last_output`, and
`prove_outputs_merkle_root` consistent across restarts (O2). A narrower fix that only stops reading report payloads
removes the `reports` half and still hashes up to 2 MiB per output in the claim pass, so the test keeps exiting 1 for
`outputs`. The CLI's `run_to_stop` could get the same treatment, but as a development tool it may keep printing
payloads.

### Risk of not fixing it

No production deployment runs the player, so a real deployment is not exposed. The risk is to anyone who uses the
player, or copies its loop into a validator node, as a model of an honest operator. Such a node takes about 2-5 ms
(local) or tens of ms (JSON-RPC) per automatic yield on the claim path instead of tens of microseconds. Any input
sender whose input reaches guest code that loops on automatic yields can impose this, within the application's
mcycle bound. That can push claim computation for an epoch, and processing of later epochs, past clocks sized for the
emulator's own costs. Mitigations outside the code: disable automatic yields where outputs are not needed, or size
the clocks for 2 MiB of copying and hashing per few mcycles.
