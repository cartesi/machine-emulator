# Cartesi RISC0 Prover

Proves Cartesi Machine state transitions using RISC Zero's zkvm.
Given a step log, generates a zero-knowledge proof that the
state transition is valid.

## Building

    cd risc0 && make

Prerequisites (versions pinned in CI):

- Docker -- the guest binary is built inside a container to ensure all
  machines produce the same Image ID
- `rzup` with the `cpp` toolchain (2024.1.5) and `r0vm` (3.0.5)
- lua5.4 and a built emulator (for fixtures and the pipeline test)

The CLI binary lands in `risc0/rust/target/debug/cartesi-risc0-cli`.

## Pipeline

1. Prove a step log (produces a STARK receipt):

       cartesi-risc0-cli prove <hash_before> step.log <mcycle> <hash_after> receipt.bin

2. Verify the receipt:

       cartesi-risc0-cli verify receipt.bin <hash_before> <mcycle> <hash_after>

3. Compress the receipt to Groth16 (produces seal + journal for on-chain verification):

       cartesi-risc0-cli compress receipt.bin seal.bin journal.bin

4. Verify the seal:

       cartesi-risc0-cli verify-seal seal.bin journal.bin <hash_before> <mcycle> <hash_after>

Dev mode (fake proofs, for development):

    RISC0_DEV_MODE=1 cartesi-risc0-cli prove <hash_before> step.log <mcycle> <hash_after> receipt.bin

A dev-mode receipt carries no cryptographic proof, so `verify` rejects it
unless `--allow-dev-mode` is passed -- the env var alone is not enough:

    cartesi-risc0-cli --allow-dev-mode verify receipt.bin <hash_before> <mcycle> <hash_after>

## Building with CUDA

    make -C risc0 RISC0_FEATURES=cuda

Embeds the prover in-process with CUDA support (unlike the default
which delegates to the external `r0vm`).

## Export Artifacts

    make -C risc0 export-artifacts

Outputs to `risc0/artifacts/`:
- `cartesi-risc0-guest-step-prover.bin` -- Guest binary (R0BF format)
- `cartesi-risc0-guest-step-prover-image-id.txt` -- Image ID hex

## On-Chain Verification

The Groth16 seal (260 bytes) is submitted to the RISC Zero Verifier
Router on-chain, which runs an `ecPairing` precompile (~300k gas).
See [`solidity/`](solidity/) for the contract and integration tests.

## Testing

    make -C risc0 fixtures     # record step-log fixtures (needs a built emulator)
    make -C risc0 test

`make test` runs:

1. Dev-mode interpreter tests (cargo test with RISC0_DEV_MODE=1) -- always runs
2. Full proving pipeline (prove -> verify -> compress -> verify-seal) -- real proofs
3. Solidity integration tests (forge test against Sepolia fork)

Steps 2-3 are slow (~3 min on M4 Pro) because they generate real proofs.
To skip them during development:

    RISC0_TEST_DEV_ONLY=1 make -C risc0 test

Host-side Rust coverage (needs `cargo install cargo-llvm-cov` and
`rustup component add llvm-tools`): `make -C risc0 coverage` writes
`rust/lcov.info` + `rust/coverage-summary.txt`, covering the dev-mode suite
plus an instrumented run of the real proving pipeline (skipped under
`RISC0_TEST_DEV_ONLY=1`). `make -C risc0/solidity coverage` covers the
on-chain verifier. The zkVM guest itself cannot be instrumented; its behavior
is covered by the reject-fixture and pipeline tests.

The step-log fixtures under `risc0/test/fixtures/` come from `make fixtures`
and survive across test runs; the receipt/seal/journal are derived from them
on demand. `make -C risc0 clean` deletes everything, after which `make
fixtures` must run again before `make test`.

## FAQ

**Why does the build require Docker?**

The guest binary must produce the same Image ID on every machine.
Without Docker, different platforms produce different RISC-V output.
Build with `RISC0_REPRODUCIBLE_BUILD=0` to skip Docker (native Image
ID, valid for testing but not on-chain). Use `--guest-elf` at runtime
to override with a Docker-built guest when needed.

**Image ID mismatch between machines?**

Check same `risc0-build` version, same rzup `cpp` toolchain version
(the C++ replay object is compiled on the host and linked into the
guest, so its compiler is part of the Image ID; `cpp/Makefile` pins
and enforces the version), Docker running, and neither machine has
`RISC0_REPRODUCIBLE_BUILD=0`.
