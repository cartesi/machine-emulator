> :warning: The Cartesi team keeps working internally on the next version of this repository, following its regular development roadmap. Whenever there's a new version ready or important fix, these are published to the public source tree as new releases.

# Cartesi Machine Emulator

The Cartesi Machine Emulator is the reference off-chain implementation of the Cartesi Machine Specification. It's written in C/C++ with POSIX dependencies restricted to the terminal, process, and memory-mapping facilites. It is distributed as a library and scriptable in the Lua programming language.

The emulator implements RISC-V's RV64IMASU ISA. The letters after RV specify the extension set. This selection corresponds to a 64-bit machine, Integer arithmetic with Multiplication and division, Atomic operations, as well as the optional Supervisor and User privilege levels. In addition, Cartesi Machines support the Sv48 mode of address translation and memory protection.

## Getting Started

### Requirements

- C++ Compiler with support for C++17 (tested with GCC >= 8+ and Clang >= 8.x).
- GNU Make >= 3.81
- Cryptoapp 7.0.0
- GRPC 1.38.0
- Lua 5.3.5
- Boost >= 1.71

Obs: Please note that Apple Clang Version number does not follow upstream LLVM/Clang.

#### Ubuntu 20.04

```
$ apt-get install build-essential automake libtool patchelf cmake pkg-config wget git libreadline-dev libboost-coroutine-dev libboost-context-dev libboost-serialization-dev libssl-dev openssl libc-ares-dev zlib1g-dev ca-certificates
```
#### MacOS

##### MacPorts
```
sudo port install clang-11 automake boost libtool wget cmake pkgconfig c-ares zlib openssl
```

##### Homebrew
```
brew install llvm@11 automake boost libomp wget cmake pkg-config c-ares zlib openssl
```

### Build

```bash
$ make submodules
$ make dep
$ make
```

Cleaning:

```bash
$ make depclean
$ make clean
```

### Install

```bash
$ make install
```

## Running Tests

Copy the tests binaries to a directory called `tests` and run: (Eg.: )

```bash
$ make test
```

The default search path for binaries is `machine-emulator/tests`. Alternatively you can specify the binaries path using the `TEST_PATH` variable as in:

```bash
$ make test TEST_PATH=/full/path/to/test/binaries
```

## Linter

Install clang-tidy-11 and run:

```bash
$ make lint
```

## Usage

```bash
$ build/{uname_arch}/luapp5.3 run.lua
```

## Contributing

Thank you for your interest in Cartesi! Head over to our [Contributing Guidelines](CONTRIBUTING.md) for instructions on how to sign our Contributors Agreement and get started with
Cartesi!

Please note we have a [Code of Conduct](CODE_OF_CONDUCT.md), please follow it in all your interactions with the project.

## Authors

* *Diego Nehab*

## License

The machine-emulator repository and all contributions are licensed under
[LGPL 3.0](https://www.gnu.org/licenses/lgpl-3.0.html). Please review our [COPYING](COPYING) file.

