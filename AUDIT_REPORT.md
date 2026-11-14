# PRT Audit Report (`audit/prt2`)

Status: **in progress**. Phase: Prepare (step 1 of `AUDIT.md`).

This file is the campaign state of the audit that `AUDIT.md` defines. The orchestrator rewrites it after every step so
that it can resume after a compaction or a container restart. Confirmed issues are in `BUGS.md`, with their tests under
`bugs/`.

## Campaign state

| Item | Value |
|---|---|
| Branch audited | `audit/prt2` at `20a788c` (docs: prepare PRT audit) |
| Current phase | Prepare (workflow run `wf_1ad3b14b-a88`) |
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

Pending (Prepare).

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
