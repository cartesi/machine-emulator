# ZisK Prover Integration

> **Status: Work in Progress**

This is an experimental integration of [ZisK](https://github.com/0xPolygonHermez/zisk) for generating zero-knowledge proofs of Cartesi Machine state transitions. Development and testing have been done on macOS Apple Silicon. Linux and other platforms are untested.

## What It Does

The prover takes a step log (recorded state transition) and generates a ZK proof attesting that:
- Starting from `root_hash_before`
- After executing `mcycle_count` machine cycles
- The machine state becomes `root_hash_after`

These three values are the public outputs of the proof.

## Input Handling

ZisK programs receive all their data through a single input file. For our prover, this means the initial hash, final hash, cycle count, and the step log itself must all be serialized into one binary blob. The prover reads this input, replays the step log, verifies the state transition, and outputs the three public values.

The `lua/step-log-to-zisk-input.lua` script handles this serialization. It reads a step log (which already contains the hashes and cycle count in its header) and produces a binary file in the format ZisK expects. The test harness uses this script automatically.

## ZisK Overview

ZisK is a zkVM that compiles Rust programs to RISC-V and generates zero-knowledge proofs of their execution. The workflow involves several stages:

**cargo-zisk** is the main CLI tool that orchestrates compilation, execution, and proving:

- `cargo-zisk build` compiles Rust to a RISC-V ELF (target: `riscv64ima-zisk-zkvm-elf`)
- `cargo-zisk run` builds and executes via the emulator
- `cargo-zisk verify-constraints` checks that all ZK constraints are satisfied
- `cargo-zisk prove` generates the actual ZK proof
- `cargo-zisk verify` validates a previously generated proof

**ziskemu** is the ZisK emulator. It executes the compiled ELF against input data, allowing you to verify correctness before spending time on proof generation.

**Proving key** (~33GB) contains the cryptographic parameters needed for proof generation. It's only required for `prove`; emulation and constraint verification work without it.

For more details, see the [ZisK documentation](https://0xpolygonhermez.github.io/zisk/).

## Prerequisites

### LLVM 20

The C++ interpreter must be compiled with LLVM 20.x (Clang, LLD, libc++ headers with RISC-V target support).

**Why LLVM 20 specifically?** ZisK's internal compiler is based on LLVM 20.1.7. During development, version mismatches caused subtle failures with complex C++ templates - code would compile but produce incorrect results or fail at link time. Using a matching LLVM version avoids these issues.

**macOS Apple Silicon (Homebrew) - tested:**

```sh
brew install llvm@20
export LLVM20_DIR=/opt/homebrew/opt/llvm@20
```

**macOS (MacPorts) - untested:**

```sh
sudo port install llvm-20
export LLVM20_DIR=/opt/local/libexec/llvm-20
```

**Linux (Ubuntu/Debian) - untested:**

- Build from source

### Rust

Install via [rustup](https://rustup.rs/):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### ZisK Toolchain

Install cargo-zisk and ziskemu:

```sh
curl -L https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash
~/.zisk/bin/ziskup --nokey  # Skip proving key download for faster setup
```

To download the proving key later (required for proof generation):

```sh
~/.zisk/bin/ziskup
```

## Build

```sh
make LLVM20_DIR=/opt/homebrew/opt/llvm@20 all
```

This builds:
- `cpp/libcartesi-zisk.a` - Freestanding C++ interpreter library
- `rust/target/riscv64ima-zisk-zkvm-elf/release/cartesi-zisk` - Cartesi ZisK prover ELF program

## Usage

### Running in ZisK Emulator

Execute the program in ziskemu to verify correctness without generating proofs:

```sh
ziskemu -e rust/target/riscv64ima-zisk-zkvm-elf/release/cartesi-zisk -i <input.bin>
```

Add `-c` to print public output values to console.

### Constraint Verification

Before generating a proof (which takes significant time), verify that all ZK constraints are satisfied:

```sh
cargo-zisk verify-constraints -e rust/target/riscv64ima-zisk-zkvm-elf/release/cartesi-zisk -i <input.bin>
```

This catches issues that would cause proof generation to fail.

### Proof Generation

Generate a ZK proof (requires the proving key):

```sh
cargo-zisk prove -e rust/target/riscv64ima-zisk-zkvm-elf/release/cartesi-zisk -i <input.bin> -o <output_dir> -a -y
```

Flags:

- `-a` generates an aggregated final proof
- `-y` verifies the proof immediately after generation

Output files:

- `result.json` - Proof metadata (cycles, generation time)
- `vadcop_final_proof.bin` - The ZK proof (~244KB)

### Proof Verification

Verify a previously generated proof:

```sh
cargo-zisk verify -p <output_dir>/vadcop_final_proof.bin
```

## Testing

The test harness runs the prover against step logs from the main test suite (tests/build/step-logs/*()

```sh
# Generate step logs first (one-time setup)
make -C ../tests create-step-logs

# Run all tests (ziskemu only, fast)
make test

# Run filtered tests
make test FILTER=xori

# With constraint verification (~70-80s each)
make test FILTER=xori verify=yes
```

See [test/README.md](test/README.md) for details on test options and output files.

## Input Format

The input binary structure:

```text
[0:32]   root_hash_before (SHA256)
[32:40]  mcycle_count (little-endian u64)
[40:72]  root_hash_after (SHA256)
[72:]    step log data
```

The `lua/step-log-to-zisk-input.lua` script converts step logs to this format.
