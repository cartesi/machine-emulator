Hunt for bugs in the `audit/prt2` branch and in the external components pinned below.

`THREAT_MODEL.md` defines what a bug is and how severe it is. Every agent reads it first and uses its terms. Do not
modify it. For PRT semantics, trust the manual (`doc/README.md`) in this branch.

## Components

Section 3 of the threat model rates a defect by the most critical role among the components that show it. The roles
in this campaign:

| Component | Role |
|---|---|
| Interpreter, state-access layers, devices, uarch program, hash tree, log producers, `collect_mcycle_root_hashes` and `collect_uarch_cycle_root_hashes`, input delivery, and storing, loading, cloning and syncing machines | Honest operator |
| The rest of the machine API (C, Lua and JSON-RPC) | Honest operator where a production validator node plausibly calls it on the honest operator's path. When unsure, give both ratings. |
| `machine-solidity-step` [v0.17.0-test1](https://github.com/cartesi/machine-solidity-step/releases/tag/v0.17.0-test1), with its generated code and constants regenerated from `audit/prt2` | Referee verifier |
| Dave [v3.0.0-alpha.7](https://github.com/cartesi/dave/releases/tag/v3.0.0-alpha.7) (`prt/contracts`, `cartesi-rollups/contracts`, with `machine/step` replaced by the regenerated step), and the `cartesi-rollups-contracts` 3.0.0-alpha.10 it pins (input box, output validation) | Referee model, as the deployed referee. Audit the released constants, not `doc/recipes/prt-contracts.patch`. |
| The PRT referee model in `doc/recipes` | Referee model |
| `machine-guest-tools` [v0.18.1-test1](https://github.com/cartesi/machine-guest-tools/releases/tag/v0.18.1-test1) | Guest software |
| Off-chain verifiers (the C, Lua and JSON-RPC verify functions) | Support. A defect that the referee model in `doc/recipes` shows only through them is rated as theirs. |
| The PRT player and bridge in `doc/recipes`, the `cartesi-machine` CLI, and the Lua helper libraries (`cartesi.evmu`, the frontier and forest functions of `cartesi.hash-tree`, `cartesi.filesystem`, the JSON bindings) | Support. No production deployment runs the player, the bridge or the CLI. |

Not in scope: ZK proving, the Linux kernel, OpenSBI, the validator nodes (the sling node in the Dave repository and the
Cartesi Rollups Node), the dishonest strategies (`prt-dishonest.lua`) and the test harnesses (`*-test.lua`,
`*-test.sh`).

## Rules for every agent

- This is a blind hunt: do not read reports of earlier audits or bug hunts. The history of `audit/prt2` may be read,
  but not other branches.
- Hunters report every candidate, even one they believe is out of scope or minor. Triage and reviewers apply the
  exclusions.
- Rate with "How to rate" in section 8, step by step, quoting the rule, obligation or definition violated. A claim that
  a state is unreachable needs an argument that no input sequence from any valid template produces it.
- Say how the finding threatens the goal of section 1, or why it still violates a rule.
- Do not report typos, style or missing tests.

## Process

Use a workflow. The orchestrator only orchestrates, and only it writes `BUGS.md` and `AUDIT_REPORT.md` and commits. It
keeps the campaign state (candidates, outcomes, angles run, the stop count) in `AUDIT_REPORT.md`, so that it can resume
after a compaction. The audit runs for days, so spend tokens only on candidates rated Medium or above.

1. **Prepare.** One agent builds the shared harnesses under `bugs/harness/`:
   - `machine-solidity-step` regenerated from the emulator image built from `audit/prt2` (its `generate-*` targets,
     replay tests included), with an EVM harness for it, reporting if it fails to build or to pass its tests;
   - an independent rebuild of the uarch with the toolchain pinned in the `Dockerfile`, its pristine hash checked
     against the regenerated step;
   - a local chain running the pinned Dave contracts, built with `prt-contracts.patch` for the PRT recipes and without
     it for tests of the contracts themselves;
   - a runner that stops and restarts the PRT player from its stored state;
   - a bare-metal guest builder, machine configurations and a sanitizer build of the emulator.

   The orchestrator must be able to re-run every harness. If a tool cannot be installed, find another (for an EVM,
   solc-js with `revm`) or list the area as uncovered.
2. **Hunt.** Run at most 10 hunters at a time. Each gets one angle derived from the threat model, reasons first,
   reports at most 5 candidates, strongest first, and lists what it did not cover. From round 2, hunters also get this
   campaign's earlier candidates with their outcomes and the areas left uncovered, but no summary of what is out of
   scope. Vary the strategy between rounds: start with one angle per rule or obligation, search for variants of each
   confirmed bug, then follow data flow from untrusted inputs, check R4 at every reachable state, and inventory every
   assert and error of the honest operator file by file. Run dynamic and differential testing across paths, and a
   check of the code against the manual's promises, at least once.
3. **Triage.** One agent deduplicates the candidates across hunters and earlier rounds and rates each without a test.
   It drops the ones below Medium, with the reason, and keeps the ones it is unsure about. It gives every candidate an
   ID `R<round>-<ANGLE>-<n>`, such as `R2-DATAFLOW-3`, that never changes.
4. **Prove.** Prove each remaining candidate with a test `bugs/<ID>/test.lua` (or `test.sh`), run by `bugs/run.sh <ID>`,
   with all its support code (guest programs, configurations, crafted logs or proofs, inputs, scripts). The test
   asserts the behavior the threat model requires, so it exits 1 deterministically on `audit/prt2` and the pinned
   components, and 0 once the bug is fixed. Prefer Lua scripts that use the emulator's Lua API. Ask for a failing test,
   not for an exploit. A candidate whose test cannot be made to fail is refuted on evidence.
5. **Review.** One independent reviewer per candidate re-runs its test, tries to disprove it, and checks scope, role,
   reachability and severity, quoting the exact clause it relies on and whether that clause covers the component. Add
   a second reviewer only when the first is inconclusive.
6. **Second opinion.** After the third round, and whenever the reading of the threat model changes, a fresh reviewer
   re-checks every candidate dropped or refuted on a reading of the threat model rather than on evidence.

**Models.** Pin every agent to an exact model ID. Hunters start on Opus 5.5 at high effort (`claude-opus-5-5`). After
the first round that confirms no new issue, half of them move to Fable 5.2 at high effort (`claude-fable-5-2`), and
after the second, all of them. Only the hunters and the orchestrator use Fable 5.2; every other agent runs on Opus 5.5
at high effort.

**Blocked agents.** If a safety classifier blocks an agent, or the agent says it was stopped partway, retry once on the
same model with a rephrased prompt, then on a less capable model. If it is still blocked, report the issue without a
proof of concept. Flag in `BUGS.md` every such issue and every issue that only a fallback model confirmed.

Pass large workflow arguments through files, and clean up scratch space after each round.

**Stop** when three consecutive rounds whose hunters all run on Fable 5.2, each with a different strategy, confirm no
new issue. At least one of them withholds this campaign's findings: its hunters do not read `BUGS.md`,
`AUDIT_REPORT.md`, `bugs/` or the campaign's commits, and the report gives how many findings they rediscovered. A change
in the reading of the threat model resets the count. Then finish the open candidates, re-run every confirmed test, and
end the audit. A pinned component that cannot be fetched is skipped and listed as uncovered.

## Output

Each time a bug is confirmed, add it to `BUGS.md` with its test and support code, update `AUDIT_REPORT.md`, then commit
and push. `BUGS.md` holds the template for each issue.

`AUDIT_REPORT.md` describes:

- the strategies, angles, rounds and models used, with the agents, tokens and confirmed issues of each round;
- every candidate, with its outcome and the reason;
- the blocked agents and the fallbacks used;
- what was left uncovered;
- any gap or ambiguity found in the threat model, with the finding that exposed it.
