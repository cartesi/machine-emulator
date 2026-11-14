# Campaign records

Raw records of the `audit/prt2` campaign, kept so that every candidate in `AUDIT_REPORT.md` can be traced.

- `r<round>/hunt-<ANGLE>.json`: each hunter's full report (candidates with location, trigger, rating steps and
  evidence, and the areas it did not cover). `r1/hunt-PREPARE.json` is the observation of the Prepare agent.
- `r<round>/triage.json`: the triage agent's rating of every candidate of the round, with IDs.
- `outcomes.json`: prover and reviewer results for every candidate that was proved, and the second opinions' verdicts.
- `second-opinion-<n>.json` and `second-opinion-<n>-result.json`: what each second-opinion pass re-checked and decided.
- `readings.md`: the readings of `THREAT_MODEL.md` that the second opinions settled.
- `final-rerun.log`: the last run of every confirmed test (`<ID> exit <status> <seconds>`).

Paths inside these files that point under `/tmp/.../scratchpad/` refer to scratch space that no longer exists. Tests of
refuted candidates remain under `bugs/<ID>/` with a README; only confirmed issues have an `ENTRY.md` and appear in
`BUGS.md`.
