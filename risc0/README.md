# Cartesi RISC0 Prover

Proves Cartesi Machine state transitions using RISC Zero's zkVM.
Given a step log, generates a zero-knowledge proof that the
state transition is valid.

## Building

    cd risc0 && make

Docker is required -- the guest binary is built inside a container
to ensure all machines produce the same Image ID.

## Proving Modes

Dev mode (fake proofs, for development):

    RISC0_DEV_MODE=1 cartesi-risc0-cli prove <hash_before> step.log <mcycle> <hash_after> receipt.bin

Local proving (real proofs, Metal GPU automatic on Apple Silicon):

    cartesi-risc0-cli prove <hash_before> step.log <mcycle> <hash_after> receipt.bin

Groth16 (for on-chain verification, requires Docker):

    cartesi-risc0-cli prove-groth16 <hash_before> step.log <mcycle> <hash_after> seal.bin journal.bin

Verify:

    cartesi-risc0-cli verify receipt.bin <hash_before> <mcycle> <hash_after>
    cartesi-risc0-cli verify-groth16 seal.bin journal.bin <hash_before> <mcycle> <hash_after>

To get a full Groth16 receipt (instead of separate seal/journal):

    cartesi-risc0-cli --groth16 prove <hash_before> step.log <mcycle> <hash_after> receipt.bin

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

## FAQ

**Why does the build require Docker?**

The guest binary must produce the same Image ID on every machine.
Without Docker, different platforms produce different RISC-V output.
Build with `RISC0_REPRODUCIBLE_BUILD=0` to skip Docker (native Image
ID, valid for testing but not on-chain). Use `--guest-elf` at runtime
to override with a Docker-built guest when needed.

**Is `RISC0_DEV_MODE` a build flag?**

No. Runtime environment variable, checked each time you prove.
No recompilation needed to switch modes.

**Image ID mismatch between machines?**

Check same `risc0-build` version, Docker running, and neither
machine has `RISC0_REPRODUCIBLE_BUILD=0`.
