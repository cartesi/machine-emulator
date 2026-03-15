# Cartesi RISC0 Prover

Proves Cartesi Machine state transitions using RISC Zero's zkvm.
Given a step log, generates a zero-knowledge proof that the
state transition is valid.

## Building

    cd risc0 && make

Docker is required -- the guest binary is built inside a container
to ensure all machines produce the same Image ID.

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

    make -C risc0 test

This runs:

1. Dev-mode interpreter tests (cargo test with RISC0_DEV_MODE=1) -- always runs
2. Full proving pipeline (prove -> verify -> compress -> verify-seal) -- real proofs
3. Solidity integration tests (forge test against Sepolia fork)

Steps 2-3 are slow (~3 min on M4 Pro) because they generate real proofs.
To skip them during development:

    RISC0_TEST_DEV_ONLY=1 make -C risc0 test

Fixtures (step log, receipt, seal, journal) are generated once in
`risc0/test/fixtures/` and reused across pipeline and Solidity tests.
Run `make -C risc0 clean` to regenerate them.

## FAQ

**Why does the build require Docker?**

The guest binary must produce the same Image ID on every machine.
Without Docker, different platforms produce different RISC-V output.
Build with `RISC0_REPRODUCIBLE_BUILD=0` to skip Docker (native Image
ID, valid for testing but not on-chain). Use `--guest-elf` at runtime
to override with a Docker-built guest when needed.

**Image ID mismatch between machines?**

Check same `risc0-build` version, Docker running, and neither
machine has `RISC0_REPRODUCIBLE_BUILD=0`.
