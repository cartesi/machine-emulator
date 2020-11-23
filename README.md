> :warning: The Cartesi team keeps working internally on the next version of this repository, following its regular development roadmap. Whenever there's a new version ready or important fix, these are published to the public source tree as new releases.

# Cartesi Machine Emulator

The Cartesi Machine Emulator is the reference off-chain implementation of the Cartesi Machine Specification. It's written in C/C++ with POSIX dependencies restricted to the terminal, process, and memory-mapping facilites. It is distributed as a library and scriptable in the Lua programming language.

The emulator implements RISC-V's RV64IMASU ISA. The letters after RV specify the extension set. This selection corresponds to a 64-bit machine, Integer arithmetic with Multiplication and division, Atomic operations, as well as the optional Supervisor and User privilege levels. In addition, Cartesi Machines support the Sv48 mode of address translation and memory protection.

## 1. Getting Started

### 1.1 Requirements

- C++ Compiler with support for C++17 (tested with GCC >= 8+ and Clang >= 8.x).
- GNU Make >= 3.81
- Cryptoapp 7.0.0
- GRPC 1.16.0
- Lua 5.3.5

Obs: Please note that Apple Clang Version number does not follow upstream LLVM/Clang.

#### 1.1.1 Ubuntu 20.04

```
$ apt-get install build-essential automake libtool patchelf wget git libreadline-dev libboost-container-dev libboost-program-options-dev libboost-serialization-dev protobuf-compiler protobuf-compiler-grpc libprotobuf-dev libgrpc++-dev ca-certificates
```
#### 1.1.2 MacOS

##### 1.1.2.1 MacPorts
```
sudo port install clang-9.0 automake boost grpc protobuf3-cpp libtool wget
```

##### 1.1.2.2 Homebrew
```
brew install llvm automake boost grpc protobuf libomp wget
```

### 1.2 Build

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

### 1.3 Install

```bash
$ make install
```

## 2. Running Tests

Copy the tests binaries to a directory called `tests` and run: (Eg.: )

```bash
$ make test
```

The default search path for binaries is `machine-emulator/tests`. Alternatively you can specify the binaries path using the `TEST_PATH` variable as in:

```bash
$ make test TEST_PATH=/full/path/to/test/binaries
```

## 3. Usage

```bash
$ build/{uname_arch}/luapp5.3 run.lua
```
## 4. Building Dockerfile

To build the ```cartesi/machine-emulator``` Docker from source use the following: 
```shell
docker build -t cartesi/machine-emulator -t cartesi/machine-emulator:latest -f .github/workflows/Dockerfile /opt/cartesi
```
The Docker image is used in the ```descartes-tutorials/descartes-env``` container to run the tutorial dApps.

## Contributing

Thank you for your interest in Cartesi! Head over to our [Contributing Guidelines](CONTRIBUTING.md) for instructions on how to sign our Contributors Agreement and get started with
Cartesi!

Please note we have a [Code of Conduct](CODE_OF_CONDUCT.md), please follow it in all your interactions with the project.

## Authors

* *Diego Nehab*

## License

The machine-emulator repository and all contributions are licensed under
[LGPL 3.0](https://www.gnu.org/licenses/lgpl-3.0.html). Please review our [COPYING](COPYING) file.

