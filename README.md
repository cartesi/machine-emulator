# Cartesi RISC-V Emulator 

The Cartesi RISC-V Emulator is the reference off-chain implementation of the Cartesi Machine Specification. It's written in C/C++ with POSIX dependencies restricted to the terminal, process, and memory-mapping facilites. It is distributed as a library and scriptable in the Lua programming language.

The emulator implements the RV64IMASU ISA. The letters after RV specify the extension set. This selection corresponds to a 64-bit machine, Integer arithmetic with Multiplication and division, Atomic operations, as well as the optional Supervisor and User privilege levels. In addition, Cartesi Machines support the Sv48 mode of address translation and memory protection.

## Getting Started 

### Requirements

- C++ Compiler with support for C++17 (tested with GCC >= 7+ and Apple Clang >= 10.x).   
- GNU Make
- Cryptoapp
- GRPC
- Lua 5.3.5

### Build

```bash
$ make
```

### Install

- TODO

## Running Tests

```bash
$ make test
```

## Usage

```bash
$ luapp run.lua
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
