# Cartesi SP1 Prover

Proves Cartesi Machine state transitions using Succinct's SP1 zkVM.
Given a step log, generates a zero-knowledge proof that the
state transition is valid.

## Building

    cd sp1 && make all

Prerequisites (versions pinned in CI and `cpp/Dockerfile`):

- SP1 GNU toolchain: extract the `riscv64im` tarball for your host from
  succinctlabs/riscv-gnu-toolchain release 2026.02.13 to
  `~/.sp1/riscv64im-2026.02.13`
- zkevm C SDK: extract `zkevm-sdk-v6.3.1.tar.gz` from the succinctlabs/sp1
  v6.3.1 release to `~/.sp1/zkevm-sdk-v6.3.1`
- `ld.lld` -- the guest must be linked with lld; GNU ld merges everything
  into one RWX segment, which SP1's loader rejects
- `protoc` -- sp1-prover-types compiles .proto files at host build time
- lua5.4 and a built emulator (for fixtures)

The CLI binary lands in `sp1/rust/target/release/cartesi-sp1-cli`.

The canonical guest build runs in Docker with every input pinned:

    docker build -f sp1/cpp/Dockerfile -t cartesi-sp1-guest .
    docker run --rm cartesi-sp1-guest cat /out/guest.elf > guest.elf

A native build produces the same bytes -- the guest is stripped, so its
sha256 is host-independent -- and CI enforces that equality on every run.

## Pipeline

1. Prove a step log (`core` produces a STARK, `groth16` the on-chain form;
   the mode is fixed before proving, so a groth16 proof is a full prove
   rather than a wrap of a core proof):

       cartesi-sp1-cli --guest-elf guest.elf prove <hash_before> step.log <mcycle> <hash_after> proof.bin groth16

2. Verify the proof (deriving the verifying key costs a ~13 s setup; pass
   `--vkey` with the exported key to skip it):

       cartesi-sp1-cli --guest-elf guest.elf verify proof.bin <hash_before> <mcycle> <hash_after>

3. Split a groth16 proof into the seal and journal a contract consumes:

       cartesi-sp1-cli --guest-elf guest.elf seal proof.bin seal.bin journal.bin

4. Verify the seal the way the chain will:

       cartesi-sp1-cli --guest-elf guest.elf verify-seal seal.bin journal.bin <vkey_hash> <hash_before> <mcycle> <hash_after>

Groth16 notes: the wrap needs ~14-16 GB of RAM (a 16 GB VM gets OOM-killed;
24 GB works), the first groth16 prove downloads ~8 GB of circuit artifacts
into `~/.sp1`, and without a GPU the gnark stage runs in the
`ghcr.io/succinctlabs/sp1-gnark` container, published for linux/amd64 only.

## Building with CUDA

    make -C sp1 all SP1_FEATURES=cuda

Auto-detected when `nvidia-smi` is present. The STARK proves on the GPU via
`sp1_gpu_server`, an ordinary child process over a Unix socket -- no Docker.
The separate `groth16-cuda` feature routes the gnark wrap through ICICLE,
whose CUDA backend is licensed software: without a licence it silently falls
back to CPU (`acceleration=none` in the log).

## Export Artifacts

    make -C sp1 export-artifacts

Outputs to `sp1/artifacts/`:

- `cartesi-sp1-replay-steps.elf` -- the guest: the step replayer whose
  acceptance the proof attests
- `cartesi-sp1-replay-steps-vkey-hash.txt` -- vkey hash, the guest's
  on-chain identity
- `cartesi-sp1-replay-steps-vkey.bin` -- full verifying key, for
  `verify --vkey`
- `VKeyHash.sol` -- the same hash as a Solidity constant

The vkey depends on the sp1-sdk version as well as the guest ELF, so an SDK
bump is a consensus change even when the guest bytes are unchanged.

## On-Chain Verification

The 356-byte seal is submitted to the SP1VerifierGateway, which routes on
the seal's 4-byte selector (the circuit version) and checks the proof
against the program vkey and journal (~275k gas measured). See
[`solidity/`](solidity/) for the contract and integration tests.

A production deployment must choose consciously between the shared gateway
(routes are owner-mutable: Succinct can add and freeze verifier versions)
and a pinned SP1VerifierGroth16 deployment (immutable, but stranded if the
circuit version it accepts is ever retired). The tests here run against the
Sepolia gateway; nothing in this repo commits to either choice.

## Testing

    make -C sp1 fixtures       # record step-log fixtures (needs a built emulator)
    make -C sp1 test           # host tests: reject fixtures, sha ABI, journal
    make -C sp1 seal           # prove the one-mcycle fixture to a Groth16 seal
    make -C sp1 test-solidity  # on-chain tests against a Sepolia fork (needs seal)

The reject-fixture tests assert the abort reason each forged log dies with;
the guest writes it to the public-values stream, the one channel every
executor backend carries back to the host. They execute without proving, so
no GPU and no artifact download is needed.

## The sha256 precompile ABI

The precompiles address their buffers as arrays of 8-byte slots each holding
a u32 value -- `w` is 64 slots, `state` is 8 -- which the C headers do not
say. A packed u32 array overruns silently. The contract is pinned by a
comment in `cpp/sp1-runtime.cpp` and enforced by two tests: the sha-abi
guest hashes distinguishing vectors against a reference SHA-256, and probes
the executor's write footprint with canary words bordering both buffers.
After any SDK or toolchain bump, `make -C sp1 test` is the check that the
ABI still holds.

## Licensing

Core SP1 -- prover, executor, SDK, and the C SDK artifacts the guest links
-- is dual MIT/Apache-2.0; proving on hardware you own or rent is
unrestricted. The BUSL 1.1 grant covers only `sp1-cluster`, Succinct's
multi-GPU orchestrator, which this integration does not use. ICICLE's CUDA
backend (optional, `groth16-cuda` only) requires a licence from Ingonyama.

## FAQ

**Why must the guest be linked with lld?**

SP1's loader rejects segments that are both writable and executable. GNU ld
folds the zkvm.ld output into one RWX LOAD segment; lld splits R-X from RW.

**Why is the guest stripped?**

The program is built from PT_LOAD segments plus a symbol-table lookup, so a
symbol table is an input to the vkey that no compiler flag controls.
Stripped builds come out byte-identical across hosts, which also makes a
plain sha256 of the ELF a usable reproducibility check.

**vkey mismatch between machines?**

Check the same toolchain tag (`cpp/Makefile` pins it), the same sp1-sdk
version in `rust/Cargo.toml`, and that both guests are stripped Docker or
Docker-equivalent builds. The reproducibility step in CI compares a
runner-native build against the pinned Docker build byte for byte.
