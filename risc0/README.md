# Cartesi RISC0 Prover

Proves Cartesi Machine state transitions using RISC Zero's zkVM.
Given a step log, generates a zero-knowledge proof (receipt) that the
state transition is valid.

## Verification Layers

Cartesi verifies machine state transitions through 4 progressively
stronger layers. Each layer builds on the one below it.

### Layer 1 — Replay (C++, no ZK)

The emulator records every memory access during a step into a step log,
then replays it to confirm the hashes match. This is the ground truth.

    cartesi-machine --log-step=1,step.log        # record
    cartesi-machine --verify-step=step.log        # replay and check

### Layer 2 — ZK Proof (RISC0 STARK)

Layer 1's replay runs inside RISC Zero's zkVM, producing a cryptographic
receipt. Anyone with the receipt can verify the computation without
re-executing it.

    cartesi-risc0-cli prove <hash_before> step.log <mcycle> <hash_after> receipt.bin
    cartesi-risc0-cli verify receipt.bin <hash_before> <mcycle> <hash_after>

### Layer 3 — Compact Proof (Groth16 SNARK)

The STARK receipt is compressed into a 256-byte Groth16 proof (seal)
and a 96-byte ABI-encoded journal. This is small enough to verify
on-chain.

    cartesi-risc0-cli prove-groth16 <hash_before> step.log <mcycle> <hash_after> seal.bin journal.bin
    cartesi-risc0-cli verify-groth16 seal.bin journal.bin <hash_before> <mcycle> <hash_after>

### Layer 4 — On-Chain Verification (Solidity)

A smart contract receives the seal and journal, reconstructs the
expected journal digest, and calls the RISC Zero Verifier Router to
verify the Groth16 proof on Ethereum. See [`solidity/`](solidity/).

    verifier.verify(seal, imageId, sha256(journal))   // Solidity

## Proof Output

The proof output (receipt) contains a journal with the following public values:

- `root_hash_before` — machine state hash before the step
- `mcycle_count` — number of machine cycles executed
- `root_hash_after` — machine state hash after the step

These values are publicly readable from the receipt and can be verified
on-chain against the guest's Image ID.

## Building

    cd risc0 && make

This builds the C++ replay code for RISC-V, then the Rust host/guest crates.
**Docker is required** — the guest binary is built inside a Docker container
(`risczero/risc0-guest-builder:r0.1.88.0`) to ensure all machines produce the
same Image ID regardless of host platform.

The resulting binary (`cartesi-risc0-cli`) supports all proving modes below
without recompilation.

## Proving Modes

### Dev Mode (fake proofs, for development)

    RISC0_DEV_MODE=1 cartesi-risc0-cli prove <hash_before> step.log <mcycle> <hash_after> receipt.bin

Returns instantly with a fake receipt. Useful for development and testing.
The receipt is NOT verifiable on-chain.

### Local Proving (real proofs)

    cartesi-risc0-cli prove <hash_before> step.log <mcycle> <hash_after> receipt.bin

Generates a real ZK proof by delegating to the `r0vm` binary installed
by `rzup`.

**GPU acceleration:** On Apple Silicon, `r0vm` uses Metal automatically —
no build flags or configuration needed.

### Groth16 Proving (for on-chain verification)

    cartesi-risc0-cli prove-groth16 <hash_before> step.log <mcycle> <hash_after> seal.bin journal.bin

Generates a Groth16 seal (260 bytes) and ABI-encoded journal (96 bytes)
that can be verified on-chain by a Solidity contract. The `prove-groth16`
command handles the full pipeline: STARK generation, recursive compression,
and Groth16 SNARK wrapping.

**Docker is required** for Groth16 compression. The `r0vm` binary
automatically pulls and uses the `risczero/risc0-groth16-prover` Docker
image (multi-arch: amd64 + arm64). On Apple Silicon, it runs natively —
no Rosetta or x86 emulation needed.

To generate a full receipt with Groth16 (instead of separate seal/journal):

    cartesi-risc0-cli --groth16 prove <hash_before> step.log <mcycle> <hash_after> receipt.bin

To verify a Groth16 seal and journal locally before submitting on-chain:

    cartesi-risc0-cli verify-groth16 seal.bin journal.bin <hash_before> <mcycle> <hash_after>

## Building with CUDA (NVIDIA GPU)

On a machine with an NVIDIA GPU and the CUDA toolkit installed:

    make -C risc0 RISC0_FEATURES=cuda

This compiles the RISC0 prover with CUDA support linked into the binary
(in-process proving). Unlike the default build which delegates to the
external `r0vm`, this embeds the prover directly.

To prove:

    cartesi-risc0-cli prove step.log

## Export Artifacts

    make -C risc0 export-artifacts

Outputs to `risc0/artifacts/`:

- `cartesi-risc0-guest-step-prover.bin` — Guest binary (R0BF format)
- `cartesi-risc0-guest-step-prover-image-id.txt` — Image ID as hex string

## On-Chain Verification

The dispute contract submits the Groth16 seal (260 bytes) directly to the
RISC Zero Verifier Router, which runs an `ecPairing` precompile on-chain.

- Contract call: `verifier.verify(seal, imageId, journalDigest)`
- Gas cost: ~300k per proof
- Trust model: fully self-contained, no external dependencies
- Tooling: `cartesi-risc0-cli prove-groth16` then submit to `CartesiStepVerifier`


## FAQ

**Why does the build require Docker?**

The guest binary is compiled inside a Docker container to guarantee the
same Image ID on every machine. Without Docker, the Rust compiler produces
slightly different RISC-V output on different platforms (Mac ARM vs Linux
x86), resulting in different Image IDs. Since all nodes in the Cartesi
network must agree on the same Image ID, reproducible builds are essential.

The Docker image (`risczero/risc0-guest-builder:r0.1.88.0`, linux/amd64)
runs via emulation on Apple Silicon. Only the guest needs Docker — the
host binary is compiled natively.

**What if I can't run Docker (e.g., inside a container)?**

Build with `RISC0_REPRODUCIBLE_BUILD=0` to use native guest compilation:

    RISC0_REPRODUCIBLE_BUILD=0 make -C risc0

Then, to get the canonical Image ID at **runtime**, use `--guest-elf` with
a Docker-built guest binary:

    # On a Docker-capable machine:
    make -C risc0 export-artifacts
    scp risc0/artifacts/cartesi-risc0-guest-step-prover.bin remote:/tmp/

    # On the Docker-less machine, prove with the canonical guest:
    cartesi-risc0-cli --guest-elf /tmp/cartesi-risc0-guest-step-prover.bin prove ...

The `--guest-elf` flag overrides the embedded guest at runtime. The CLI
computes the Image ID from the provided binary. Receipts generated this way
use the canonical Image ID and are verifiable on-chain.

Without `--guest-elf`, the CLI uses the native-built guest, which has a
platform-specific Image ID — valid for testing but not for on-chain
verification.

**How do I check the Image ID?**

    make -C risc0 image-id

**Is `RISC0_DEV_MODE` a build flag?**

No. It is a runtime environment variable checked each time you prove.
You can switch between dev mode and real proving without recompiling.
The only compile-time option related to dev mode is the `disable-dev-mode`
Cargo feature, which permanently prevents dev mode from being used —
intended for production hardening.

**Do I need `--features prove` or `--features metal` to use my GPU?**

No. The default build delegates proving to the external `r0vm` binary
(installed by `rzup`), which is already compiled with Metal support on
Apple Silicon. The `prove` Cargo feature moves the prover in-process
rather than using the external binary, but the result is the same.

**What about CUDA?**

CUDA requires an NVIDIA GPU and is a compile-time decision — it links
CUDA-specific libraries into several RISC0 sub-crates. It is not relevant
on macOS/Apple Silicon. To build for an NVIDIA machine:

    make -C risc0 RISC0_FEATURES=cuda

**What is `RISC0_SKIP_BUILD`?**

A RISC Zero built-in environment variable (not ours). When set to `1`, the
`risc0-build` library skips guest compilation entirely and reuses the
previously generated `methods.rs`. Useful for iterating on host-only code
without waiting for the guest to rebuild. It has no effect on the first
build (there is nothing to reuse).

**The Image ID on my machine doesn't match another machine's. What's wrong?**

If both machines use Docker (the default), the Image ID should be
identical. Check:

1. Same `risc0-build` version in `risc0/rust/methods/Cargo.toml` (currently 3.0.5)
2. Docker is running and available (`docker version`)
3. Neither machine has `RISC0_REPRODUCIBLE_BUILD=0` set

If one machine uses `RISC0_REPRODUCIBLE_BUILD=0` (native build), the Image ID
will differ — this is expected. Native builds produce platform-specific
output.

**What does Groth16 proving require?**

Docker must be running. The `r0vm` binary handles the full STARK-to-Groth16
pipeline and automatically pulls the `risczero/risc0-groth16-prover` Docker
image (~2.4 GB, multi-arch amd64+arm64) on first use. On Apple Silicon,
Docker pulls the native ARM64 image — no Rosetta needed.

Groth16 is required for on-chain verification. The 260-byte seal and
96-byte ABI-encoded journal can be verified by a Solidity contract via
RISC Zero's verifier router.

**Can I generate Groth16 proofs on Apple Silicon?**

Yes, since RISC Zero v3.0.3+. The Groth16 compression runs inside a
Docker container with a portable witness generator (C++ compiled with
Circom's `--no_asm` flag). RISC Zero's official documentation may still
say "Apple Silicon unsupported" — this is outdated.
