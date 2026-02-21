# Cartesi ZisK Prover

Proves Cartesi Machine state transitions using ZisK's zkVM.
Given a step log, generates a zero-knowledge proof that the
state transition is valid.

This is a parallel implementation to the [RISC0 prover](../risc0/).
Both provers consume the same step log format and verify the same
public values, but target different proof systems.

## Proof Output

The proof output contains these public values (18 u32 via `set_output()`):

- `root_hash_before` — machine state hash before the step
- `mcycle_count` — number of machine cycles executed
- `root_hash_after` — machine state hash after the step

## How It Works

The step log is passed directly to `ziskemu` (or `cargo-zisk prove`)
as input. The C++ replay code reads the 72-byte header from the log,
replays the state transition, verifies the hashes, and returns the
public values to the Rust guest via output params.

No input conversion is needed — the step log IS the input.

## Prerequisites

### LLVM 20

The C++ interpreter must be compiled with LLVM 20.x (Clang, LLD,
libc++ headers with RISC-V target support).

**Why LLVM 20 specifically?** ZisK's internal compiler uses LLVM 20.1.7.
Version mismatches cause subtle failures with complex C++ templates.

macOS (Homebrew):

    brew install llvm@20
    export LLVM20_DIR=/opt/homebrew/opt/llvm@20

macOS (MacPorts):

    sudo port install llvm-20
    export LLVM20_DIR=/opt/local/libexec/llvm-20

Linux (Ubuntu/Debian):

    wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && sudo ./llvm.sh 20
    sudo apt-get install -y libc++-20-dev
    export LLVM20_DIR=/usr/lib/llvm-20

Note: the `libc++-20-dev` package provides the freestanding C++ headers
needed for cross-compilation. It is not installed by default with LLVM.

### Additional build dependencies (Linux)

The ZisK Rust guest depends on `lib-c` from the ZisK repository, which
requires `nasm` and `libgmp-dev` for finite field assembly:

    sudo apt-get install -y nasm libgmp-dev

The pre-built `cargo-zisk` binary also needs `libomp5` (OpenMP runtime)
and `libopenmpi-dev` (MPI for distributed proving):

    sudo apt-get install -y libomp5 libopenmpi-dev

### Rust

Install via [rustup](https://rustup.rs/).

### ZisK Toolchain

    curl -L https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash
    ~/.zisk/bin/ziskup --nokey   # Skip 33GB proving key

This installs `cargo-zisk` and `ziskemu` to `~/.zisk/bin/`.
To download the proving key later (required for proof generation):

    ~/.zisk/bin/ziskup

## Building

    make LLVM20_DIR=/opt/homebrew/opt/llvm@20 all

This builds:
- `cpp/libcartesi-zisk.a` — freestanding C++ interpreter library
- `rust/target/riscv64ima-zisk-zkvm-elf/release/cartesi-zisk` — ZisK prover ELF

## Usage

### Emulator (fast, no proof)

    ziskemu -e <elf> -i <step.log>

Add `-c` to print public output values to console.

### Constraint Verification

    cargo-zisk verify-constraints -e <elf> -i <step.log>

Catches issues before spending time on proof generation.

### Proof Generation

    cargo-zisk prove -e <elf> -i <step.log> -o <output_dir> -a -y

Flags: `-a` aggregated final proof, `-y` verify after generation.
Requires the proving key (~33GB).

Output: `vadcop_final_proof.bin` (~244KB) + `result.json` (metadata).

### Proof Verification

    cargo-zisk verify -p <output_dir>/vadcop_final_proof.bin

## Testing

    # Generate step logs (one-time setup)
    make -C ../tests create-step-logs

    # Run all tests (ziskemu, fast)
    make test

    # Filtered tests
    make test FILTER=xori

    # With constraint verification (~70-80s each)
    make test FILTER=xori verify=yes

See [test/README.md](test/README.md) for details.

## On-Chain Verification

ZisK's proving pipeline produces a VADCOP proof (`vadcop_final_proof.bin`)
which can be further compressed into an FFLONK SNARK suitable for on-chain
verification on Ethereum (via the BN254 `ecPairing` precompile).

The final FFLONK compression step and corresponding Solidity verifier
are under active development by the ZisK team.

## Key Differences from RISC0

- **Target**: `riscv64ima` (ZisK) vs `riscv32im` (RISC0)
- **Toolchain**: LLVM 20 Clang (ZisK) vs RISC0 C++ toolchain via `rzup`
- **Output format**: 18 u32 via `set_output()` (ZisK) vs 96-byte ABI journal (RISC0)
- **Proof format**: vadcop_final_proof.bin (ZisK) vs STARK receipt / Groth16 seal (RISC0)
- **Tools**: `cargo-zisk` / `ziskemu` (ZisK) vs `cartesi-risc0-cli` (RISC0)
- **Reproducible build**: deterministic without Docker (ZisK) vs Docker container required (RISC0)
