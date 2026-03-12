# Groth16 On-Chain Verification

Integration tests for verifying Cartesi step proofs on-chain via the
RISC Zero Verifier Router on Sepolia (`0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187`).

## Quick Start

    make dep                   # Install Foundry dependencies
    make image-id              # Regenerate src/ImageID.sol
    make fixtures              # Generate Groth16 seal + journal (slow, needs Docker)
    make test                  # Run tests against Sepolia fork

## Prerequisites

- [Foundry](https://getfoundry.sh) installed (`forge`)
- `cartesi-risc0-cli` built (`make -C risc0`)
- `cartesi-machine.lua` available
- Docker running (for Groth16 proof generation)
