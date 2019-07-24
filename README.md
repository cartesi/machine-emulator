# Cartesi Machine Emulator

The Cartesi Machine Emulator is the reference off-chain implementation of the Cartesi Machine Specification. It's written in C/C++ with POSIX dependencies restricted to the terminal, process, and memory-mapping facilites. It is distributed as a library and scriptable in the Lua programming language.

The emulator implements RISC-V's RV64IMASU ISA. The letters after RV specify the extension set. This selection corresponds to a 64-bit machine, Integer arithmetic with Multiplication and division, Atomic operations, as well as the optional Supervisor and User privilege levels. In addition, Cartesi Machines support the Sv48 mode of address translation and memory protection.

## Getting Started

### Requirements

- C++ Compiler with support for C++17 (tested with GCC >= 7+ and Clang >= 8.x).
- GNU Make >= 3.81
- Cryptoapp 7.0.0
- GRPC 1.16.0
- Lua 5.3.5

#### Ubuntu 18.04

```
$ apt-get install build-essential wget git libreadline-dev libboost-container-dev \
        libboost-program-options-dev ca-certificates
```
#### MACOSX

```
sudo port install clang-8.0 automake boost libtool wget
```
### Build

```bash
$ make submodules downloads
$ make dep
$ make
```

Cleaning:

```bash
$ make depclean
$ make clean
```

### Install

- TODO

## Running Tests

```bash
$ make test
```

## Usage

```bash
$ build/{uname_arch}/luapp5.3 run.lua
```

## Contributing

Pull requests are welcome. When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change.

Please note we have a code of conduct, please follow it in all your interactions with the project.

## Authors

* *Diego Nehab*

## License

- TODO

## Acknowledgments

- Original work 
