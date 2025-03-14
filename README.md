# Cartesi Machine Emulator

[![Latest Release](https://img.shields.io/github/v/release/cartesi/machine-emulator?label=version)](https://github.com/cartesi/machine-emulator/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/cartesi/machine-emulator/build.yml?branch=main)](https://github.com/cartesi/machine-emulator/actions)
[![License](https://img.shields.io/github/license/cartesi/machine-emulator)](COPYING)

The Cartesi Machine Emulator is the basis of Cartesi's verifiable computation framework.
It is a portable, deterministic, high-performance RISC-V emulator (a.k.a. a virtual machine) that can run complex computations off-chain but supports on-chain verification via fraud proofs.

Under the hood, the emulator implements the RISC-V RV64GC ISA (including the unprivileged and privileged specifications).
This allows it to boot Linux, which in turn, gives creators access to traditional software development stacks when developing and running their applications.

Written in C++, the Cartesi Machine Emulator is available as a standalone CLI application or as a library for embedding into other applications.
It can be controlled via a well-defined C API that can be easily accessed from multiple programming languages.
In particular, it can be scripted in Lua, for fast prototyping and testing.

*TL;DR:*
> I can use the Cartesi Machine to disprove a dishonest result of a computation `M' = F(M)`, where `F` is a deterministic state transition function that corresponds to running an application on top of the Linux operating system to process some input, `M = (S, I)` is the initial state `S` of the machine and the input `I`, and `M' = (S', O')` is the final state `S'` of the machine and its output `O'`.

## Features

- **Powerful**
  - **High-performance RISC-V emulation**, delivering high execution speed for demanding applications.
  - **Complete RISC-V RV64GC ISA support**, covering both privileged and unprivileged specifications.
  - **Linux kernel execution**, enabling running of standard Linux distributions (e.g., Ubuntu).
  - **Full-featured Linux environment**, enabling applications to use traditional software stacks.
  - **Large state address space**, enabling applications to utilize gigabytes of data.
  - **Forking support**, enabling parallel execution and efficient rollback of state transitions.
  - **State inspection capabilities**, enabling examination of the entire address space and processor.
- **Developer Friendly**
  - **Simple C API**, facilitating integration with various languages (e.g., C++, Rust, Go, Python, JavaScript).
  - **Lua scripting interface**, for rapid prototyping and testing.
  - **JSON-RPC API endpoint**, enabling remote machine control.
  - **Interactive CLI application**, for prototyping in the terminal.
  - **VirtIO network and shared filesystem devices**, allowing access to host state during prototyping.
  - **State serialization**, for storing and loading of machine snapshots.
- **Verifiable**
  - **Deterministic execution**, ensuring every instruction is reproducible (including floating-point).
  - **State Merkle tree computation**, for generating cryptographic proofs.
  - **State transition access logging**, enabling on-chain verification of state transitions.
  - **Cycle-level execution control**, for interactive fraud-proof bisection.
  - **Microarchitecture-based emulation** of its interpreter for simplifying on-chain verification.
  - **Generic I/O interface**, enabling handling of data input/output through state transitions.
- **Portable**
  - **Cross-platform compatibility**, including Linux, macOS and Windows.
  - **WebAssembly compatibility**, bringing all capabilities to browser environments.
  - **Freestanding compilation**, suitable for embedding in other applications (e.g., in a zkVM).
  - **Minimal runtime dependencies**, ensuring easy installation and integration.

## Overview

For a comprehensive technical overview of the Cartesi Machine emulator and its blockchain use cases,
you can watch this detailed presentation by Diego Nehab,
the principal architect of the Cartesi Machine, at the Ethereum Engineering Group:

[![Cartesi Machine Overview](https://img.youtube.com/vi/ofb7MJ8dK0U/0.jpg)](https://www.youtube.com/watch?v=ofb7MJ8dK0U)

In addition, you can watch an insightful interview with Diego Nehab about the Cartesi Machine on Cartesi's YouTube channel:

[![Cartesi Machine Deep Dive](https://img.youtube.com/vi/uUzn_vdWyDM/0.jpg)](https://www.youtube.com/watch?v=uUzn_vdWyDM)

## Getting Started

### Installation

We provide official packages for some distributions, but you can also build from source.

**NOTE:** The official package repositories listed below are not available yet. These instructions explain the installation process once the packages become available.

#### Debian or Ubuntu

We maintain an APT package repository containing binary packages for *amd64*, *arm64* and *riscv64*, you can install with:

```sh
# Add package repository
wget -qO - https://dist.cartesi.io/apt/keys/cartesi-deb-key.gpg | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/cartesi-deb-key.gpg
echo "deb https://dist.cartesi.io/apt stable/" | sudo tee /etc/apt/sources.list.d/cartesi-deb-apt.list
sudo apt-get update
# Install cartesi-machine
sudo apt-get install cartesi-machine
```

The packages provided in this APT repository are known to work with **Debian 12** (Bookworm) and **Ubuntu 24.04** (Noble).

#### Alpine Linux

We maintain an APK package repository containing binary packages for *amd64*, *arm64* and *riscv64*, you can install with:

```sh
# Add package repository
wget -qO /etc/apk/keys/cartesi-apk-key.rsa.pub https://dist.cartesi.io/apk/keys/cartesi-apk-key.rsa.pub
echo "https://dist.cartesi.io/apk/stable" >> /etc/apk/repositories
apk update
# Install cartesi-machine
apk add cartesi-machine
```

#### Arch Linux

We maintain an official Arch Linux package in [AUR](https://aur.archlinux.org/packages/cartesi-machine), you can install with:

```sh
yay -S cartesi-machine
```

#### Homebrew

We maintain a Homebrew tap for macOS, you can install with:

```sh
brew tap cartesi/tap
brew install cartesi-machine
```

#### From Sources

##### System Requirements

- C++ Compiler with support for C++20 (tested with GCC >= 11.x and Clang >= 14.x).
- GNU Make >= 3.81
- Boost >= 1.81
- Lua >= 5.4.4 (optional, required for scripting support and interactive terminal)
- Libslirp >= 4.6.0 (optional, required for networking support)

###### Debian Requirements

```sh
sudo apt-get install build-essential git wget libgomp-dev libboost1.81-dev liblua5.4-dev libslirp-dev lua5.4
```

###### MacPorts Requirements

```sh
sudo port install clang libomp boost181 wget pkgconfig lua54 libslirp
```

###### Homebrew Requirements

```sh
brew install llvm libomp boost wget pkg-config lua libslirp
```

#### Build

First, make sure to have all the system requirements, then run the following to build and install a stable release of the machine:

```sh
# clone a stable branch of the emulator
git clone --branch v0.19.0 https://github.com/cartesi/machine-emulator.git
cd machine-emulator

# patch the sources with required generated files
wget https://github.com/cartesi/machine-emulator/releases/download/v0.19.0/add-generated-files.diff
git apply add-generated-files.diff

# compile
make
```

*Note*: We recommend running only stable releases. If you want to build the `main` development branch, you will need to regenerate files instead of patching the sources, which will require Docker on your system. For more details, please check our [development guide](https://github.com/cartesi/machine-emulator/wiki/Development-Guide).

Finally, you can install it in your system in any path you would like with:

```sh
# install the emulator
sudo make install PREFIX=/usr/local
```

After installation, to boot a Linux system with the `cartesi-machine` command, you will need to also download:

- Guest [Linux image](https://github.com/cartesi/machine-linux-image) and place it at `$PREFIX/cartesi/images/linux.bin`
- Guest [rootfs image](https://github.com/cartesi/machine-rootfs-image) and place it at `$PREFIX/cartesi/images/rootfs.ext2`.

### Usage

Once you have the emulator, guest Linux image, and guest rootfs images installed, you can boot a Linux operating system by running:

```sh
cartesi-machine
```

It should output something similar to:
```

         .
        / \
      /    \
\---/---\  /----\
 \       X       \
  \----/  \---/---\
       \    / CARTESI
        \ /   MACHINE
         '

Nothing to do.

Halted
Cycles: 48415113
```

You can start an interactive terminal to play around with:

```sh
cartesi-machine -it bash
```

And there you have a full Linux running in a RISC-V emulated CPU that you can interact with.
You can check the `cartesi-machine --help` for more information on how to use the CLI application.

### Library

You can use the emulator as library in other applications, its `libcartesi` library provides a [C API](src/machine-c-api.h) that is very simple to use.

Check the following wiki guides on how to use with different languages:
- [C/C++](https://github.com/cartesi/machine-emulator/wiki/Using-the-C-API)
- [Rust](https://github.com/cartesi/machine-emulator/wiki/Using-the-C-API-with-Rust)
- [Go](https://github.com/cartesi/machine-emulator/wiki/Using-the-C-API-with-Go)
- [JavaScript](https://github.com/cartesi/machine-emulator/wiki/Using-the-C-API-with-JavaScript)
- [Python](https://github.com/cartesi/machine-emulator/wiki/Using-the-C-API-with-Python)
- [Lua](https://github.com/cartesi/machine-emulator/wiki/Using-the-Lua-API)
- [WebAssembly](https://github.com/cartesi/machine-emulator/wiki/Using-the-C-API-with-WebAssembly)

## Use Cases

The following projects have been using the emulator:
- [Cartesi Rollups Node](https://github.com/cartesi/rollups-node) - Uses the emulator's library in Go for Layer 2 rollups on Ethereum.
- [Cartesi Dave](https://github.com/cartesi/dave) - Uses the emulator's library in Rust for on-chain fraud-proofs validation.
- [Cartesi CLI](https://github.com/cartesi/cli) - Uses the emulator's CLI in TypeScript for DApp development.

## Related Projects

The Cartesi Machine emulator is directly related to the following important projects that are also maintained by us:
- [Cartesi Machine Guest Tools](https://github.com/cartesi/machine-guest-tools) - System utilities used inside guest machines.
- [Cartesi Machine Linux Image](https://github.com/cartesi/machine-linux-image) - Linux kernel image used by guest machines.
- [Cartesi Machine Rootfs Image](https://github.com/cartesi/machine-rootfs-image) - Root filesystem image used by guest machines.
- [Cartesi Machine Solidity Step](https://github.com/cartesi/machine-solidity-step) - Solidity smart contracts of machine microarchitecture step for on-chain fraud-proofs validation.

## Benchmarks

The emulator's RISC-V interpreter is optimized for high performance given the requirements of on-chain verification.
For detailed performance metrics comparing the emulator against bare-metal execution and other virtual machines,
please see our [benchmarks](https://github.com/cartesi/machine-emulator/wiki/Benchmarks) page.

## Documentation

The Cartesi Machine emulator documentation is undergoing a comprehensive update.
While the full documentation is being refreshed, you can find guides and tutorials in our [wiki](https://github.com/cartesi/machine-emulator/wiki).

## Change Log

Changes between emulator releases are documented in [CHANGELOG](CHANGELOG.md).

## Roadmap

We are continually improving the emulator with new features and enhancements.
Check out our roadmap at [GitHub Projects](https://github.com/cartesi/machine-emulator/projects) to see what's coming in the future.

## Community & Support

- Join our [Discord](https://discord.gg/cartesi) `#cartesi-machine` channel to engage with the emulator users and developers.
- Report issues on our [GitHub Issues](https://github.com/cartesi/machine-emulator/issues).

## Developing

For more detailed information about developing the emulator, including instructions for running tests, using the linter, and code formatting, please refer to our [development guide](https://github.com/cartesi/machine-emulator/wiki/Development-Guide) in the wiki.

## Contributing

Please see our [contributing guidelines](CONTRIBUTING.md) for instructions on how to start contributing to the project.
Note we have a [code of conduct](CODE_OF_CONDUCT.md), please follow it in all your interactions with the project.

## Authors

The Cartesi Machine emulator is actively developed by [Cartesi](https://cartesi.io/)'s Machine Reference Unit, with significant contributions from many open-source developers.
For a complete list of authors, see the [AUTHORS](AUTHORS) file.

## License

The repository and all contributions to it are licensed under the [LGPL 3.0](https://www.gnu.org/licenses/lgpl-3.0.html), unless otherwise specified below or in subdirectory LICENSE / COPYING files.
Please review our [COPYING](COPYING) file for the LGPL 3.0 license and also [LICENSES](LICENSES.md) file for additional information on third-party software licenses.
