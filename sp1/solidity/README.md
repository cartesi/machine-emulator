# Groth16 On-Chain Verification

Integration tests for verifying Cartesi step proofs on-chain via the
SP1VerifierGateway on Sepolia.

## Quick Start

The easiest way to run is from the parent directory:

    make -C sp1 fixtures       # Record step-log fixtures (needs a built emulator)
    make -C sp1 seal           # Prove the one-mcycle fixture to a Groth16 seal
    make -C sp1 test-solidity  # Run the on-chain tests

To run only the Solidity tests (the seal fixture must already exist):

    make dep                   # Install Foundry dependencies (first time)
    make test                  # Run tests against Sepolia fork

The seal fixture (`test/fixtures/seal.bin`) is derived by the parent
`sp1/Makefile` from the recorded step log; the journal is `abi.encode` of
values the test states directly. `src/VKeyHash.sol` is regenerated from the
guest before every test run, so a stale vkey fails loudly.

## Prerequisites

- [Foundry](https://getfoundry.sh) installed (`forge`)
- Seal fixture produced by `make -C sp1 seal` (needs ~14-16 GB of RAM and,
  without a GPU, Docker for the gnark stage -- see the parent README)
