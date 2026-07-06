# Groth16 On-Chain Verification

Integration tests for verifying Cartesi step proofs on-chain via the
RISC Zero Verifier Router on Sepolia.

## Quick Start

The easiest way to run is from the parent directory:

    make -C risc0 fixtures     # Record step-log fixtures (needs a built emulator)
    make -C risc0 test         # Proves, derives seal/journal, runs all tests

To run only the Solidity tests (the seal fixture must already exist):

    make dep                   # Install Foundry dependencies (first time)
    make test                  # Run tests against Sepolia fork

The seal/journal fixtures (`seal.bin`, `journal.bin`) are derived by the
parent `risc0/Makefile` from the recorded step log and shared at
`risc0/test/fixtures/`.

## Prerequisites

- [Foundry](https://getfoundry.sh) installed (`forge`)
- Seal fixture produced by `make -C risc0 fixtures test` (requires Docker,
  a built emulator, and the risc0 toolchain -- see the parent README)
