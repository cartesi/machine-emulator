# PRT Audit Report (`audit/prt2`)

Status: **in progress**. Phase: round 1, Hunt.

This file is the campaign state of the audit that `AUDIT.md` defines. The orchestrator rewrites it after every step so
that it can resume after a compaction or a container restart. Confirmed issues are in `BUGS.md`, with their tests under
`bugs/`.

## Campaign state

| Item | Value |
|---|---|
| Branch audited | `audit/prt2` at `20a788c` (docs: prepare PRT audit) |
| Current phase | Round 1 Hunt (workflow run `wf_df71eb4e-501`, hunter reports in the scratchpad `campaign/r1/`) |
| Rounds completed | 0 |
| Stop count (consecutive clean all-Fable rounds, different strategies) | 0 of 3 |
| Withheld-findings round done | no |
| Second opinion (after round 3) done | no |
| Hunter models for the next round | all `claude-opus-5-5`, high effort |
| Confirmed issues | 0 |
| Open candidates | none |

## Process deviations and notes

- **An earlier audit's report was in the tree.** Commit `20a788c` carried an `AUDIT_REPORT.md` of a completed audit of
  another branch (`feature/prt-audit`), while `BUGS.md` was the empty template and `bugs/` did not exist. `AUDIT.md`
  makes `AUDIT_REPORT.md` the campaign state, so the orchestrator opened it to resume, and read about the first half of
  it (summary, process, and the candidate tables of its early rounds) before recognizing it as the report of an earlier
  audit, which the blind-hunt rule forbids reading. It stopped reading there and replaced the file with this one. The
  old text remains in git at `20a788c`. Consequences and mitigations:
  - No agent of this campaign is given anything from that report. Every agent is told not to read the history of
    `AUDIT_REPORT.md` or `BUGS.md` before this campaign's first commit.
  - The orchestrator derives every angle from `THREAT_MODEL.md` and the strategies `AUDIT.md` prescribes, not from what
    it read. It only orchestrates, so it proposes no candidates itself.
  - The requester should treat the orchestrator, not the hunters, as non-blind.
- **Concurrency.** The workflow runtime caps concurrent agents at the CPU count minus two, which is 2 on this 4-CPU
  container, below the 10 hunters `AUDIT.md` allows.

## Setup and harnesses

Prepare ran as one agent on `claude-opus-5-5` at high effort (451,832 tokens, 80 minutes). The orchestrator re-ran
`bugs/harness/check-all.sh`: 11 quick checks PASS, the two long ones (PRT demo, player restart) were run by the agent
only. `bugs/harness/README.md` documents every harness; `bugs/harness/setup.sh` rebuilds all of them (artifacts live in
the untracked `bugs/harness/work/`).

| Harness | Status | Notes |
|---|---|---|
| `bugs/run.sh`, `bugs/env.sh` | ok | Exit 0 fixed, 1 bug present, 2 harness error |
| Emulator in-tree build, guest images of `dependencies.lock` | ok | Checksums verified |
| Bare-metal guest builder, machine configurations | ok | Pinned `riscv64-unknown-elf-gcc` in Docker; five configurations, including a Linux valid template |
| ASan and UBSan build | ok | `HARNESS_SANITIZE=1` |
| Independent uarch rebuild | ok | Pristine hash `0x89ae34ba1dc65a8a3668b484bcedf897665c803c41dc9ef9f1faf147b9d443d7` agrees between the rebuild, the in-tree build, the Lua constant and the regenerated `EmulatorConstants.sol` |
| `machine-solidity-step` `v0.17.0-test1` (`6f91eb9b`) regenerated | **partial** | The pure regeneration does not compile: `UArchStep.sol` uses `TLB_NUM_SETS`, which nothing defines. A labelled variant (`regenerated-patched`, adds `TLB_NUM_SETS = 3`) builds: replay 56/56, prod 14/15 (`marchid` 23 against the expected 22), mock 3/5 (the tests expect overflow to win over halt). Seeded into round 1 triage as R1-PREPARE-1 |
| EVM harness for the step | ok | anvil (Foundry 1.5.1) with a `StepVerifier` contract over the patched variant, and a Lua client |
| Local chain with Dave `v3.0.0-alpha.7` (`7eb6c6be`) and `cartesi-rollups-contracts` 3.0.0-alpha.10 | ok | Built with and without `prt-contracts.patch`, with the patched regenerated step. Patched: the PRT demo settles end to end. Released: Dave's own suites pass 427/447 and 17/19 (fixtures recorded against the previous step) |
| PRT player stop and restart runner | ok | Needs a reflink file system; the scripts loop-mount an XFS image |
| `machine-guest-tools` `v0.18.1-test1` | fetched | rootfs, deb and tarball match `dependencies.lock` |

## Rounds

| Round | Strategy | Hunter models | Agents | Tokens | Raw candidates | Kept by triage | Confirmed | Clean |
|---|---|---|---|---|---|---|---|---|

## Candidates

None yet.

## Blocked agents and fallbacks

None yet.

## Left uncovered

Pending.

## Gaps and ambiguities in the threat model

None yet.
