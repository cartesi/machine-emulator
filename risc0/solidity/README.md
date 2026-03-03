# Groth16 On-Chain Verification (Direct Path)

Solidity contracts and tests for verifying Cartesi step proofs on-chain
via **direct Groth16 verification**. The prover generates a Groth16 seal
locally (or on a GPU), and the on-chain contract verifies it by calling
the RISC Zero Verifier Router (~300k gas).

This is the **direct verification path**. For the alternative aggregated
path via Boundless (~50k gas, different contract interface), see
[`../boundless/`](../boundless/). The two paths are **not
interchangeable** — see the
[comparison in the parent README](../README.md#on-chain-verification).

## What This Tests

The test submits a real Groth16 seal and journal to the RISC Zero verifier
router on a Sepolia fork and checks:

1. A valid proof verifies successfully
2. A tampered journal is rejected
3. A wrong Image ID is rejected
4. The journal decodes correctly into (root_hash_before, mcycle_count, root_hash_after)

## Prerequisites

- [Foundry](https://getfoundry.sh) installed (`forge`)
- `cartesi-risc0-cli` built (`make -C risc0`)
- `cartesi-machine.lua` available (for step log generation)
- Docker running (for Groth16 proof generation)

## Quick Start

    # Install Foundry dependencies
    make dep

    # Regenerate src/ImageID.sol from the guest build
    make image-id

    # Generate Groth16 fixtures (generates step log, then proves — takes several minutes)
    make fixtures

    # Run tests against Sepolia fork
    make test

## RISC Zero Verifier Router

The tests verify against the RISC Zero verifier router on Sepolia:
`0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187`

This is the same contract that Boundless provers submit proofs to.
The router delegates to the appropriate verifier based on the seal's
4-byte selector prefix (Groth16 or SetVerifier).

## Journal Format

The journal is ABI-encoded as `abi.encode(bytes32, uint64, bytes32)` (96 bytes):

- Bytes 0-31: `rootHashBefore`
- Bytes 32-55: zero padding (24 bytes, uint64 left-pad)
- Bytes 56-63: `mcycleCount` (big-endian)
- Bytes 64-95: `rootHashAfter`

The RISC Zero verifier checks that `sha256(journal)` matches the digest
baked into the Groth16 proof.

## Seal Format

The `cartesi-risc0-cli prove-groth16` command outputs a 260-byte seal file:
4-byte selector prefix followed by 256 bytes of raw Groth16 proof data.
The selector is derived from `Groth16ReceiptVerifierParameters` in
risc0-zkvm and tells the RISC Zero Verifier Router which proof system
version was used, so it can route to the correct on-chain verifier.

The `verify-groth16` command accepts seals in either format (260 with
selector, or 256 raw) and requires the expected hash/cycle values:

    cartesi-risc0-cli verify-groth16 <seal-path> <journal-path> <root_hash_before> <mcycle_count> <root_hash_after>
