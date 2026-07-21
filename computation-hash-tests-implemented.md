# Computation-hash tests: implementation overview

The computation-hash test suite is a portable, manifest-driven integration test for the real
`cartesi-machine.lua` command-line interface. It builds deterministic machine and uarch fixtures,
generates stored-machine templates and CMIO inputs, executes the manifest from fresh template copies,
and validates the resulting computation hashes with both behavioral checks and independent
hash-tree reconstruction.

No `machine.cpp` behavior or reset semantics were changed for these tests.

## Data flow

1. The Makefile-managed toolchain builds the machine and uarch assembly fixtures.
2. `tests/lua/create-computation-hash-examples.lua` creates stored-machine templates, binary CMIO
   inputs, and a portable `manifest.json`.
3. `tests/lua/test-computation-hash-examples.lua` reads the manifest and invokes each CLI argv array
   from the artifact root.
4. The driver validates process results, diagnostics, terminal counters, and computation-hash files.
5. Selected cases are checked with independently assembled hash trees, and equivalent execution
   modes are required to produce byte-identical roots.

The generated artifact has this layout:

```text
tests/build/computation-hash-examples/
├── manifest.json
├── templates/
├── inputs/
└── results/
```

All paths stored in the manifest are relative to the artifact root, so the artifact remains
relocatable. It contains no stored golden computation hashes. Hashes are produced by executing the
manifest commands.

## Deterministic machine guest

`tests/machine/src/computation_hash.S` implements a bare-metal CMIO guest controlled by a compact
binary command format. Each command contains:

- the `CHT1` magic.
- an action: accept, reject, exception, halt, or an unexpected manual yield.
- an automatic TX-output count.
- a manual-yield reason.
- the requested terminal mcycle.
- an optional action payload.

The guest can emit automatic TX outputs before its terminal action. It waits away from the final
instruction tail, then jumps into a calibrated NOP sled so that the terminal HTIF store retires at
the exact requested mcycle. The artifact generator probes this invariant before publishing normal
or boundary cases.

After an accept or reject, the guest returns to its command loop so a case can process multiple
inputs. An accepted response declares a 32-byte output payload. The suite disables
`check_outputs_merkle_root`, because this bare-metal control guest does not compute the expected
outputs root. Output-root verification is outside the computation-hash scenarios' scope.

## Uarch boundary fixtures

Two uarch programs exercise limits that would otherwise be impractical:

- `tests/uarch/computation-hash-near-limit.S` halts at `UARCH_CYCLE_MAX - 1`.
- `tests/uarch/computation-hash-overflow.S` loops until collection reaches the exact uarch-overflow
  diagnostic.

The generator reads the stock uarch RAM image from a default machine and overlays each custom
program at offset `UARCH_RAM_LENGTH // 2`. The boundary template begins with its uarch PC at that
custom program.
The collector can therefore capture the custom boundary tail once, while an ordinary reset still
returns to the stock uarch entrypoint. A later rejected input reuses the separately captured tail.
This covers near-limit capture, reset, and rejection without adding a test hook or changing reset
behavior.

The generator asserts that the near-limit program halts at exactly `UARCH_CYCLE_MAX - 1` without
changing mcycle.

## Portable artifact generator

`tests/lua/create-computation-hash-examples.lua` creates four templates:

- `normal`.
- `mcycle-boundary`, starting close to `MCYCLE_MAX`.
- `near-limit-uarch-tail`.
- `uarch-overflow-tail`.

It writes each case's CMIO commands as binary input files, constructs the corresponding relative
`cartesi-machine.lua` argv array, and serializes the manifest with the existing `cartesi.tojson`.
Temporary custom uarch images used to build stored templates are removed afterward.

The manifest is a top-level array of cases. Each case includes a comment describing its expected
hash structure, along with its level, template, inputs, collection geometry, command-line argv,
expected outcome, equivalence relationship, and optional independent oracle. It currently contains
37 cases: 18 mcycle cases and 19 uarch cases.

The uarch collection period uses the smallest value whose epoch computation hash tree does not
exceed height 63:

`ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH + ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE - 63`.

In general, an epoch computation hash has
`2^(ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH + ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE - log2_period)`
state hashes. The frontier represents this tree structurally without materializing its capacity.

## Scenario coverage

### Mcycle level

The mcycle cases cover:

- an empty epoch and a single accepted input.
- local versus remote execution.
- multiple inputs and automatic TX outputs.
- rejection followed by acceptance and a final rejected input.
- exception, zero and nonzero halt, and unexpected manual-yield paths.
- non-fixed-point truncation.
- fixed points before the first sample, on a sample boundary, and inside a sampling period.
- bundled versus unbundled collection.
- a terminal fixed point at `MCYCLE_MAX - 1`.
- exact `MCYCLE_MAX`, including overflow precedence.

### Uarch level

The uarch cases cover:

- an empty epoch and a target input that is never processed.
- termination before the selected window.
- fixed points at the window start, first, middle, penultimate, and final positions.
- termination immediately after the window.
- automatic TX output within the selected window.
- accept, reject/revert, exception, halt, mcycle overflow, unexpected manual yield, and truncation.
- substitution of the captured revert-uarch tail.
- a captured tail ending at `UARCH_CYCLE_MAX - 1` followed by stock reset and later rejection.
- exact uarch overflow during boundary-tail collection.
- bundled versus unbundled uarch collection.

## Native Lua command execution

`tests/lua/test-computation-hash-examples.lua` reads `manifest.json` with the existing
`cartesi.fromjson`. It uses the repository's `luaposix` dependency to execute each case:

1. `fork` creates a child process.
2. The child changes directory to the artifact root.
3. Standard input is redirected from `/dev/null`, and stdout and stderr are redirected to per-case
   files.
4. `execp` invokes the manifest argv directly, without passing the CLI arguments through a shell.
5. The parent uses `wait` to obtain the exit status.

The runner checks every case for:

- the declared success or failure category.
- hash-file presence or absence.
- a 32-byte hash when one is expected.
- equality between the hash printed by the CLI and the stored binary hash.
- required literal diagnostics.
- the declared terminal mcycle.

Cases may be selected with `COMPUTATION_HASH_CASE` or excluded with `COMPUTATION_HASH_SKIP`.

## Independent oracles and equivalence checks

The suite includes checks that do not merely compare two outputs from the computation-hash CLI
path:

- **Empty mcycle epoch:** obtain the template's fixed-point state hash and repeatedly hash it with
  itself through the exported tree height.
- **Small mcycle tree:** run a machine independently to the sampling boundary and terminal fixed
  point, then assemble and pad the epoch frontier with `cartesi.hash-tree`.
- **Small uarch tree:** collect uarch bundles separately, assemble every mcycle subtree, validate
  reset-ending hashes against independently executed mcycle states, and assemble the selected
  period root.
- **Mcycle-overflow uarch window:** collect the 255 real mcycle transitions up to `MCYCLE_MAX`
  directly, verify the overflow fixed-point group is present, and independently assemble it with
  fixed-point padding across the remainder of the 512-mcycle window.

The manifest also declares equivalence pairs. The driver requires byte-identical roots for:

- local and remote execution of the same accepted input.
- bundled and unbundled mcycle collection.
- bundled and unbundled uarch collection.

## Production changes

The production changes are in `src/cartesi-machine.lua`, `src/cartesi/hash-tree.lua`, and
`src/cartesi/util.lua`.

The mcycle and uarch computation-hash collectors previously calculated the end of an input with
ordinary addition:

```lua
mcycle + MAX_MCYCLES_PER_INPUT
```

That expression can wrap when an input starts close to `MCYCLE_MAX`. Both collectors now use the
existing `usaturating_add`, making the input boundary stop at `MCYCLE_MAX`. The uarch collector also
saturates the selected window's start and end at that input boundary, so a window crossing
`MCYCLE_MAX` retains its real transitions instead of wrapping and being mistaken for an empty
window. This is a production overflow correction exposed by the boundary scenarios, not a
test-specific reset mechanism.

The computation-hash CLI now warns when the requested epoch tree height exceeds 63, but it no
longer rejects that geometry. Uarch period-index validation handles the complete unsigned index
range when the tree contains at least `2^64` leaves. The hash-tree frontier checks available
capacity structurally, so tall trees do not require `2^height` to fit in a Lua integer.

Numeric CLI parsing now accepts decimal values only through the maximum signed Lua integer and
accepts hexadecimal values as full 64-bit bit patterns. It rejects literal and suffix-shift
overflow with specific diagnostics before downstream unsigned arithmetic is attempted.

## Makefile integration

`tests/Makefile` provides targets to build the fixtures, generate the artifact, run the manifest,
and clean the generated files. Fixture compilation and Lua formatting/static checks use the
Makefile-managed toolchain as required by the workspace build policy.

From the repository root, the main commands are:

```sh
make build-tests-computation-hash-examples-with-toolchain
make test-computation-hash-examples
```

`test-computation-hash-examples` regenerates the artifact when its generator is newer than the
manifest. Missing fixture binaries still require the explicit toolchain-managed build command.
The suite is part of the aggregate `test` target and is also generated and run while CI builds the
tests image. A complete release-build run of all 37 cases remains below the plan's 60-second target
on the development host.

## Validation performed

The completed implementation was validated with:

- fixture compilation and artifact generation through the managed toolchain target.
- Lua formatting, format checks, and `luacheck` inside `toolchain-exec`.
- all 37 manifest cases using the native Lua fork/exec runner.
- targeted independent mcycle, ordinary uarch, and mcycle-overflow uarch oracle cases.
- `git diff --check`.
