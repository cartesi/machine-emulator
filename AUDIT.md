Review the `feature/prt-audit` branch, together with the two external components pinned below.

Scope:
- The emulator. This covers the C/C++/Lua sources that ship in its package: the C and Lua libraries, the `cartesi-machine` CLI, and the embedded uarch program.
- `machine-solidity-step` (https://github.com/cartesi/machine-solidity-step/releases/tag/v0.17.0-test1), the on-chain verifiers.
- `machine-guest-tools` (https://github.com/cartesi/machine-guest-tools/releases/tag/v0.18.0), the guest software that implements the rollup interface.
- The experimental Lua PRT validator. It is made of the `doc/recipes/prt*.lua` modules and the `doc/recipes/game-*.lua` modules they load. The dishonest strategies (`prt-dishonest.lua`) and the test harnesses (`*-test.lua`) are not part of it. It contains two parts:
  - the player and the bridge, which are the honest operator;
  - the referee model.

Out of scope:
- ZK proving;
- the Linux kernel;
- OpenSBI;
- the Dave and Cartesi Rollups Node validators.

For PRT semantics, trust `doc/README.md` in this branch.

`THREAT_MODEL.md` defines what a bug is and how severe it is. Every agent reads it first and uses its terms. Every finding must:
- show how it threatens the security goal in section 1, and cite whichever rules, obligations or definitions of the threat model it violates. The following describe the role each component plays toward the goal; they are not limits:
  - `machine-solidity-step` is the referee's verifier. It must accept exactly the honest transitions, within the chain's limits.
  - `machine-guest-tools` makes an application correctly designed in the sense of section 2. Inputs must not be able to make it break the rollup interface or commit a wrong output. Rate a finding there as Critical when an input can make an application that uses these tools as documented commit a wrong output or outputs Merkle root.
  - The player and the bridge are the honest operator. A defect there can eliminate the honest claim, compute a wrong claim, or miss a deadline.
  - The referee model stands in for the deployed referee. Rate a defect there as if a deployed referee had it.
- take its severity from section 8, including the reachability test;
- assume that the deployed referee meets A1-A7, except when reviewing the referee model itself;
- exclude anything that section 8 lists as out of scope for the emulator, unless the finding is in a component this prompt puts in scope.

Do not report documentation issues, missing tests or typos. Do not modify `THREAT_MODEL.md`.

Budget: this runs on a subscription, so tokens are limited.
- Run at most 6 hunting agents at a time.
- Each hunter gets one angle derived from the threat model, and reports at most 5 candidates, strongest first.
- Use one disproving reviewer per candidate. Add a second reviewer only when the first is inconclusive.
- Do inline any check you can do in a few tool calls instead of spawning an agent.

Bound the hunt so that the audit ends within days, not weeks:
- Run at most 3 hunting rounds.
- Drop an angle after a round that produces no new candidate.
- Once hunting stops, finish confirming the open candidates and end the audit.
- List in `AUDIT_REPORT.md` what was left uncovered. If a pinned component cannot be fetched, skip it and list it there as uncovered.

Process (use a workflow):
1. Hunt. Agents reason first and then propose candidates.
2. Prove each candidate with a test under `bugs/` that fails deterministically on `feature/prt-audit`. Include all the support code the test needs to reproduce the failure: guest programs, machine configurations, crafted logs or proofs, inputs, and helper scripts. Write tests and support code as Lua scripts that use the emulator's Lua API whenever possible.
3. Have independent reviewers try to disprove each candidate. They check scope, obligations, reachability and severity.
4. If cybersecurity safeguards block a reviewer, retry with a less capable model. If it is still blocked, report the issue without a proof of concept and flag that. In `BUGS.md`, also flag any issue that only a fallback model confirmed.

Output:
- `BUGS.md` begins with an index table ordered by severity, with the columns ID, title, component, cited rules, and severity. The issues follow in the same order. Each issue gives:
  - the problem;
  - the component and area;
  - the cited rules, obligations or definitions;
  - the location;
  - the evidence, the test, and its support code;
  - the scenario and its reachability;
  - a possible solution;
  - the severity;
  - the risks.
- `AUDIT_REPORT.md` describes the process:
  - the angles, rounds, agents and models used;
  - every candidate, with its outcome and the reason;
  - the blocked reviewers;
  - what was left uncovered;
  - any gaps found in the threat model.

Each time a bug is confirmed, add it to `BUGS.md`, add its test and support code, update `AUDIT_REPORT.md`, then commit and push right away. Only the orchestrator writes these files and commits.
