# R1-A5-1: a guardian foreclosure stops the referee from accepting a settled state's outputs

**Component.** Dave v3.0.0-alpha.7 `DaveConsensus` (`cartesi-rollups/contracts`), with the
cartesi-rollups-contracts 3.0.0-alpha.10 `Application` it pins. AUDIT.md role: referee model, as the deployed
referee. The test uses the **released** build (`bugs/harness/work/dave/released`), deployed by
`doc/recipes/prt-deploy.lua`, which sets the deployer as the application's guardian.

**Defect.** `stageTournamentResult` and `acceptStagedTournamentResult` both carry `notForeclosed(_APP_CONTRACT)`,
and `Application.foreclose()` (`onlyGuardian`) can be called at any time and cannot be undone. Settling a staged
result is the only way to add an outputs Merkle root to the set that `isOutputsMerkleRootValid` reads. So if the
guardian forecloses after the root tournament has a winner, either before or after staging, that winner's outputs
can never be validated or executed.

**Requirement (THREAT_MODEL.md, A5).** "Conversely, the referee accepts every output that the settled state commits
to, whenever its valid proof is presented. No party can make it stop accepting them."

**Reading assumed.** The test treats the application's guardian as a "party" under A5. The rollups contracts
document foreclosure as an emergency feature (`IConsensus.sol`: "the application guardian should have enough time
to foreclose the application, preventing the claim from ever being accepted"). Whether the guardian is a trusted
part of the deployment, which would put this out of scope or make it Low, is for the reviewer to decide. The test
only shows the behavior.

## What the test does

`test.sh` starts a private anvil on a random port (never 8545, 8546 or 8547), imports the recipe wallets into a
temporary directory and runs `check.lua`, which does the following.

1. Builds a valid template from `guest.bin`. This bare-metal rolling application (source `guest.c`) emits one
   voucher `Voucher(0x…a5a5, 0, "")` per advance input and accepts with the outputs Merkle root.
2. Deploys the released Dave contracts for that template. Epoch 0 is empty and is settled by an unopposed honest
   claim (the flow of `doc/recipes/prt-proof-test.lua`). One input is added, so epoch 1 is sealed over it.
3. The honest player (`doc/recipes/prt.lua`, stored player) processes epoch 1. Its claim wins the root tournament
   unopposed, and the result is staged with the player's machine validity proof. The voucher's output proof comes
   from the player and is checked against the staged outputs root.
4. It takes an `evm_snapshot`, then runs two branches:
   - **control**: the staging period elapses, then `acceptStagedTournamentResult`, `validateOutput(voucher)` and
     `executeOutput(voucher)` must all succeed. Otherwise the test exits 2, a setup error.
   - **foreclosed**: after `evm_revert`, the guardian calls `foreclose()`, then the same three calls run. A5
     requires all three to succeed.

The test exits 1 if the foreclosed branch refuses the settled state's voucher, 0 if it accepts it, and 2 on setup
errors.

## Run

```sh
bugs/run.sh R1-A5-1          # about 20 s
./build-guest.sh             # optional: rebuild guest.bin (2 KB) with the pinned toolchain image (docker)
```

Prerequisites: the in-tree emulator, the released Dave build (`bugs/harness/chain/build-dave.sh released`), and
foundry (anvil, cast) from `bugs/harness`.

## Expected output on audit/prt2 (exit 1)

```
control (no foreclosure): acceptStagedTournamentResult ok
control (no foreclosure): validateOutput(voucher) ok
control (no foreclosure): executeOutput(voucher) ok
guardian called foreclose(); isForeclosed = true
foreclosed: acceptStagedTournamentResult REVERTED ApplicationForeclosed(address) ...
foreclosed: validateOutput(voucher) REVERTED InvalidOutputsMerkleRoot(bytes32) ...
foreclosed: executeOutput(voucher) REVERTED InvalidOutputsMerkleRoot(bytes32) ...
VIOLATED: A5: ...
run.sh: R1-A5-1: exit 1 (bug present)
```
