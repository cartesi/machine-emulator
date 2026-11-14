# R1-R13-3: do not reproduce on audit/prt2

Candidate: the machine-identification registers (`mvendorid`, `marchid`, `mimpid`) cannot tell released
pre-releases apart, because `marchid` is bumped by hand once per release cycle, `mimpid = major*1000+minor`, and
the label and patch are encoded nowhere.

Requirement (THREAT_MODEL.md, R13): "Every version that changes the state transition function changes the
machine-identification registers in the hashed state. The honest operator must be able to detect and refuse a
mismatch between its build and a deployment. The check must refuse every pairing of its build with a deployment of
another released version."

## What the test asserts

`test.lua` collects every released emulator version it can find in the records this audit may read:

- the pinned machine-solidity-step history (`bugs/harness/work/dave/src/machine/step`, the v0.16.0 clone with its
  history). Each commit that moved to an emulator tag records that tag's generated `UARCH_PRISTINE_STATE_HASH`,
  and from v0.21.0 on also `CM_MARCHID`;
- machine-solidity-step v0.17.0-test1 (`bugs/harness/work/solidity-step/released`), generated for emulator
  v0.23.0-test2;
- this branch's `CHANGELOG.md`, which records one "Bumped MARCHID version to N" per minor release.

A different pristine hash means a different uarch program, and R13 counts that as a change to the STF. For each
released version whose pristine hash differs from this build's, the test asserts two things:

1. The build's (`mvendorid`, `marchid`, `mimpid`) differ from every value that version can carry. A pre-release
   that publishes no `marchid` gets the range between the previous minor's bump and its own.
2. `cartesi.machine` refuses to create a machine that carries that version's registers.

The test exits 1 if either check fails for any version, and 0 otherwise. As information only, it also prints
pairs of released versions that share registers although their STFs differ. It does not assert on them, because
no change to audit/prt2 can alter past releases.

## Result on audit/prt2: exit 0 (not reproduced for this build)

```
this build: 0.23.0-test2 marchid=23 mimpid=23 pristine=0x89ae34ba...
released v0.21.0-test1 .. v0.21.0  mimpid=21 marchid in [20,21]   (5 distinct uarch programs)
released v0.22.0        pristine=0x558f38f2.. mimpid=22 marchid 22
released v0.23.0-test2  pristine=0x558f38f2.. mimpid=23 marchid 22
note: 5 released uarch programs with mimpid 21 but marchid only in [20,21]: at least two released versions
      with different STF share all identification registers
OK: R13: ...
```

- **This build.** At HEAD, `marchid` is 23 (6e3e4d3). No released version on record has 23, so every pairing of
  this build with a deployment of a released version is refused. The template check (`validate_processor_shadow`)
  rejects the other version's `marchid` or `mimpid`, and the on-chain `CM_MARCHID` (22 or less) differs from 23.
- **The candidate's examples.** The v0.22.0 and v0.23.0-test2 registers differ in `mimpid`. Those two versions
  also share the pristine hash and identical generated contracts: the v0.17.0-test1 changelog says "The generated
  contracts and emulator constants are unchanged from v0.16.0". The test cannot read the contents of
  v0.22.0-testN or v0.23.0-test1. The blind rule forbids other emulator histories, and this clone has no tags.
- **Commits that shared registers.** In this branch, 4310fa3..3fbc670 carry `marchid` 22 and `mimpid` 23, the
  same as released v0.23.0-test2, and they do change the STF. These are development commits, not releases, and
  6e3e4d3 bumped `marchid` before HEAD.
- **Past releases (not asserted).** The released v0.21.0 pre-releases have 5 different pristine hashes. They all
  share `mimpid` 21, and their `marchid` can only be 20 or 21. Two released versions with different STFs therefore
  share all three registers (pigeonhole). This assumes that the CHANGELOG's single bump per minor is complete and
  that `mimpid` used the same formula then. Those are defects of past releases outside this audit's components,
  and no fix to audit/prt2 can change them. The labelling scheme that allowed them is unchanged at HEAD, so the
  next pre-release that changes the STF without a manual `marchid` bump would repeat them. That is a process risk,
  and no test at this commit can show it.

## Run

```sh
bugs/run.sh R1-R13-3
```

It needs the shared harness: the in-tree emulator build, the pinned Dave clone with its `machine/step` history,
and `work/solidity-step/released`. It runs in about a second. If a record is missing, it exits 2.
