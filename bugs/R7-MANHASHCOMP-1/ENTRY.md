## R7-MANHASHCOMP-1

**Title.** The manual's output verifier (`doc/recipes/verify-output-proof.lua`) executes each proof file as a Lua
chunk, so an 18-byte proof hangs it and a 46-byte proof makes it allocate gigabytes before any check runs.

**Severity.** Medium (alternative reading: Low)

### Problem

The manual's "Output verification" section prints `doc/recipes/verify-output-proof.lua` as the script that verifies
an output "from the settled state hash and those artifacts alone, without instantiating any machine". It reads the
outputs Merkle root proof and the output proof with

```lua
local function read_proof(name)
    return assert(loadfile(name, "t", {}))()
end
```

so it runs each proof file as Lua code before it checks a single field. The empty environment removes the globals,
but not loops, string concatenation or the string methods reached through the string metatable. A proof file
`while true do end` never returns. `return { iflags_y_data = ("x"):rep(1 << 29) }` (46 bytes) allocates 512 MiB, and
an 85-byte loop over 1 GiB strings allocates until the host runs out of memory. Everything the script checks after
that (root hash, heights, address, accepted yield, leaf hash) is written to treat the proof as adversarial, but the
decoding step is neither bounded in CPU nor in memory.

THREAT_MODEL section 4 says "Logs and proofs are adversarial. A verifier must assume that every count, index,
address, size, and hash it receives was chosen to fool it" and "Every path that carries such data must be
memory-safe and bounded, and must report errors without terminating the process." A party that uses the manual's
verifier to check an output proof that another party hands it (the prover who wants the output believed) can be
hung or exhausted by that proof. This does not threaten the goal of section 1 directly: no on-chain referee, no
referee model and no honest-operator component shares the reader. It violates the boundedness that section 4
requires of every path that carries proofs.

### Component, role and area

`doc/recipes/verify-output-proof.lua`, a manual recipe that demonstrates off-chain output verification (A5). The
AUDIT.md table does not name it. It is not part of "The PRT referee model in `doc/recipes`" (the `prt*.lua` player
and model do not use it; the player decodes proofs as JSON) and it is not a test harness. Section 3 puts it in
Support: "Everything else used only for tests, demonstrations, development or diagnostics. Examples are copies of
the verifiers whose acceptance settles nothing". Area: proof decoding (`read_proof`).

The CLI has the same reader (`src/cartesi-machine.lua` `read_proof`, `load(contents, filename, "t", {})()` for the
default `lua` format), used by `--cmio-advance-state=...,last_output_proof:<file>`. That file is the operator's own
artifact from the previous epoch, so the CLI instance is Low, and the test does not assert on it.

### Location

- `doc/recipes/verify-output-proof.lua`, `read_proof` (lines 11-13), called at lines 35-36 before any check.
- `doc/README.md`, "Output verification" (around lines 8889-9010), which prints the same code.
- Same pattern, Low: `src/cartesi-machine.lua` `read_proof` (around line 3446) with `resolve_format` defaulting to
  `lua`.

### Evidence and test

`bugs/R7-MANHASHCOMP-1/` contains `test.sh` (the test), `runcase.py` (runs the verifier once under an
`RLIMIT_CPU` of 5 s of CPU time and an `RLIMIT_AS` limit and prints exit, signal, peak RSS and stderr as JSON) and
`README.md`. Run it with `bugs/run.sh R7-MANHASHCOMP-1` (about 7 s, peak memory about 1 GiB). The test writes a
32-byte zero state hash, a 1-byte output and four proof files, and runs `lua5.4 verify-output-proof.lua <hash>
<proof> <control proof> <output>` for each:

- control `return {}`: exit 1 (`attempt to index a nil value (local 'proof')`), peak RSS 14808 KiB;
- case 1 `while true do end` (18 bytes): killed by signal 24 (SIGXCPU) after 5 s of CPU;
- case 2, 46 bytes, `("x"):rep(1 << 29)`: peak RSS 1063324 KiB, 1048516 KiB above the control, before the first
  check fails;
- case 3, 85 bytes, a loop building 2^20 strings of 1 GiB each, under a 2 GB address-space limit:
  `lua5.4: not enough memory`.

It prints a `VIOLATION:` line for each case, then `FAIL: ...` and `run.sh: R7-MANHASHCOMP-1: exit 1 (bug present)`.
It exits 1 when a crafted proof hangs the verifier, makes it allocate 256 MiB or more beyond the control, makes it run
out of memory, or is accepted; 0 when every crafted file is rejected promptly with bounded memory, as a data-only
decoder gives (for example `cartesi.fromjson(contents, "Proof")`, which the CLI already uses for `.json` proofs); 2
on setup errors. The reviewer re-ran it and got the same output and exit 1. The CPU limit is CPU time, not wall
clock, so the result does not depend on machine load. All agents ran on Opus 5.5; no fallback was used.

### Trigger and reachability

Anyone who hands a proof file to a party that verifies an output with the manual's script: the prover of an output,
a relayer, or whoever serves stored proofs. The trigger is a few bytes of proof file; no machine state is involved,
so reachability of a machine state is not a question. The manual's own demonstration runs the script on artifacts
that the operator's calculator saved, which is the fact behind the alternative Low reading below.

### Rating

1. Out of scope: not excluded. The trigger is a proof file, and section 4 says "Logs and proofs are adversarial". It
   does not need "an untrusted party to call the machine API directly" (the script is not the machine API), a
   snapshot, a deployment that violates A1 to A8, or a host fault. AUDIT.md's "Not in scope" list (test harnesses
   `*-test.lua`, `*-test.sh`, the dishonest strategies, the validator nodes) does not cover this recipe.
2. Role: Support. Section 3: "Support. Everything else used only for tests, demonstrations, development or
   diagnostics. Examples are copies of the verifiers whose acceptance settles nothing" and "A defect that only a
   support component shows is Medium when it would rate High or Critical in the role the component stands in for,
   such as a referee verifier for a copy of a verifier, or the honest operator for an implementation of an operator
   or a tool that computes claims." This clause covers the recipe. Output validation (A5) is in scope, so the
   stood-in role exists. No component in a higher role shares the reader: the PRT player and bridge decode proofs
   with the JSON bindings, and the CLI instance reads only the operator's own file.
3. High and Medium cases: in the honest-operator stand-in (a node that checks an output proof it received for its
   own information), the High case "A crash, hang, memory-safety defect or unbounded allocation in a component in
   the honest-operator role, caused by data from other parties that the honest operator may decline" fits, and
   section 4 lets it decline such proofs ("It may decline logs and proofs that it only verifies for its own
   information"). In the referee-verifier stand-in, a verifier that hangs or allocates without bound on proof data
   violates section 4's "Every path that carries such data must be memory-safe and bounded" at any state, which is
   at least High. Either way the stand-in rating is High or above, so the Medium case "A defect that only a support
   component shows, when section 3 rates it Medium" applies. Step 2 caps it: "A defect that only a support component
   shows is never above Medium."
4. Critical: not reached; the support cap applies.

Alternative reading (Low): if the script only ever reads the operator's own artifacts, as the manual's single
demonstration does ("Running the script over the artifacts the Rolling Cartesi Machine calculator saved"), then no
data from other parties reaches it, no rule is violated, and section 8's Low ("a real defect that violates no rule or
obligation of this model") applies. The deciding fact is the script's purpose. The manual presents it as verifying an
output "from the settled state hash and those artifacts alone", that is, with the settled hash as the only trust
anchor, and section 4 requires every verifier to treat the proofs it receives as adversarial. That reading supports
Medium, and the reviewer prefers it.

### Possible solution and risks

Decode proofs as data, never as code. Have the recipe (and the manual's printed copy) read proofs with
`cartesi.fromjson(contents, "Proof")` and have the CLI save the output proofs as JSON, or add a data-only parser for
the Lua table format the CLI writes. Apply the same change to the CLI's `read_proof` default. Risks: proof files
already saved in the Lua format would need converting or a parser for that format; the manual's commands and
artifact names (`*.lua`) change. A sandbox with an instruction-count hook would bound the loop but not the single
`string.rep` allocation of case 2, so it is not a sufficient fix.

### Risk of not fixing it

Users who copy the manual's verifier to check output proofs from other parties can be hung or driven out of memory
by a tiny crafted file. The damage is a denial of service of the verifying process, not a wrong acceptance: the
checks after decoding stay sound, and on-chain output validation is unaffected. Mitigation outside the code: run the
script only on proofs one produced oneself, or under CPU and memory limits.
