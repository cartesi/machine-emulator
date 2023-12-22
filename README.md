# Cartesi Machine Emulator

The Cartesi Machine Emulator is the reference off-chain implementation of the Cartesi Machine Specification. It's written in C/C++ with POSIX dependencies restricted to the terminal, process, and memory-mapping facilities. It is distributed as a library and scriptable in the Lua programming language.

The emulator implements RISC-V's RV64IMASU ISA. The letters after RV specify the extension set. This selection corresponds to a 64-bit machine, Integer arithmetic with Multiplication and division, Atomic operations, as well as the optional Supervisor and User privilege levels. In addition, Cartesi Machines support the Sv48 mode of address translation and memory protection.

## Getting Started

Run `make help` for a list of target options. Here are some of them:

```
Main targets:
* all                                 - build the src/ code. To build from a clean clone, run: make submodules downloads dep all
  uarch                               - build microarchitecture (requires riscv64-cartesi-linux-gnu-* toolchain)
  uarch-with-linux-env                - build microarchitecture using the linux-env docker image
  build-tests-all                     - build all tests (machine, uarch and misc)
  build-tests-machine                 - Build machine emulator tests (requires rv64gc-lp64d riscv64-cartesi-linux-gnu-* toolchain)
  build-tests-machine-with-toolchain  - Build machine emulator tests using the rv64gc-lp64d toolchain docker image
  build-tests-uarch                   - build microarchitecture rv64i instruction tests (requires rv64ima-lp64 riscv64-cartesi-linux-gnu-* toolchain)
  build-tests-uarch-with-toolchain    - build microarchitecture rv64i instruction tests using the rv64ima-lp64 toolchain docker image
  build-tests-misc                    - build miscellaneous tests
  build-tests-misc-with-builder-image - build miscellaneous tests using the cartesi/machine-emulator:builder image
  test-machine                        - Run machine emulator tests
  test-uarch                          - Run uarch tests
  test-misc                           - Run miscellaneous tests
  test                                - Run all tests
  doc                                 - build the doxygen documentation (requires doxygen)
Docker images targets:
  build-emulator-image                - Build the machine-emulator debian based docker image
  build-debian-package                - Build the cartesi-machine.deb package from image
  build-linux-env                     - Build the linux environment docker image
Cleaning targets:
  clean                               - clean the src/ artifacts
  depclean                            - clean + dependencies
  distclean                           - depclean + profile information and downloads
```

### Requirements

- C++ Compiler with support for C++17 (tested with GCC >= 8+ and Clang >= 8.x).
- GNU Make >= 3.81
- GRPC >= 1.45.0
- Lua >= 5.4.4
- Boost >= 1.81

Obs: Please note that Apple Clang Version number does not follow upstream LLVM/Clang.

#### Debian Bookworm

```bash
sudo apt-get install build-essential wget git clang-tidy-15 clang-format-15 \
        libboost1.81-dev libssl-dev \
        ca-certificates pkg-config lua5.4 liblua5.4-dev \
        libgrpc++-dev libprotobuf-dev protobuf-compiler-grpc \
        luarocks

sudo luarocks install --lua-version=5.4 lpeg
sudo luarocks install --lua-version=5.4 dkjson
sudo luarocks install --lua-version=5.4 luasocket
sudo luarocks install --lua-version=5.4 luasec
sudo luarocks install --lua-version=5.4 luaposix
```
#### MacOS

##### MacPorts
```bash
sudo port install clang-15 boost181 wget pkgconfig grpc lua54 lua-luarocks

sudo luarocks install --lua-version=5.4 lpeg
sudo luarocks install --lua-version=5.4 dkjson
sudo luarocks install --lua-version=5.4 luasocket
sudo luarocks install --lua-version=5.4 luasec
sudo luarocks install --lua-version=5.4 luaposix
```

##### Homebrew
```bash
brew install llvm@15 boost wget pkg-config grpc openssl lua luarocks
luarocks --lua-dir=$(brew --prefix)/opt/lua install lpeg
luarocks --lua-dir=$(brew --prefix)/opt/lua install dkjson
luarocks --lua-dir=$(brew --prefix)/opt/lua install luasocket
luarocks --lua-dir=$(brew --prefix)/opt/lua install luasec
luarocks --lua-dir=$(brew --prefix)/opt/lua install luaposix
```

For emulator scripts to work it is expected that `lua5.4` binary is available in the system PATH. If operating system/package manager that you are using provides only `lua` or lua binary named in a different way (e.g. on `Homebrew`), please create symbolic link or alias `lua5.4`.

### Build

```bash
git clone --recurse-submodules -j3 https://github.com/cartesi/machine-emulator.git
make
```

Cleaning:

```bash
make clean
```

Microarchitecture:

If you want to use a pre-built uarch RAM image instead of building one, use the variable `UARCH_RAM_IMAGE` to specify the path to the desired image file.

```bash
$ make UARCH_RAM_IMAGE=<path-to-your-uarch-ram.bin>
```

### Install

```bash
sudo make install PREFIX=/usr/local
```

### Build C libraries in standalone

Both `libcartesi` and `libcartes_jsonrpc` C libraries can be compiled in standalone, either as static or shared library:

```bash
make dep
make bundle-boost
make -C src release=yes libcartesi.a libcartesi_jsonrpc.a libcartesi.so libcartesi_jsonrpc.so
```

The `.a` and `.so` files will be available in `src` directory, you can use any of them to link your application.

You can even use other toolchains to cross compile targeting other platforms:

```bash
# Target WASM with Emscripten toolchain
make -C src release=yes \
  CC=emcc CXX=em++ AR="emar rcs" \
  libcartesi.a

# Target WASM with WASI SDK toolchain
make -C src release=yes \
  CC=/opt/wasi-sdk/bin/clang CXX=/opt/wasi-sdk/bin/clang++ AR="/opt/wasi-sdk/bin/llvm-ar rcs" \
  libcartesi.a

# Target Windows with mingw-w64 toolchain
make -C src release=yes \
  CC=x86_64-w64-mingw32-gcc \
  CXX=x86_64-w64-mingw32-g++ \
  AR="x86_64-w64-mingw32-ar rcs" \
  libcartesi.a
```

## Running Tests

To build and execute the all tests run:

```bash
make build-tests-all
make test
```

To execute the machine test suite run:

```bash
make build-tests-machine-with-toolchain
make test-machine
```

To execute the uarch test suite run:

```bash
make build-tests-uarch-with-toolchain
make test-uarch
```

## Linter

We use clang-tidy 15 as the linter.

### Install

#### Debian Bookworm

You need to install the package clang-tidy-15 and set it as the default executable with update-alternatives.

```bash
apt install clang-tidy-15
update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-15 120
```

### Running Lint

```bash
make lint -j$(nproc)
```

## Code format

We use clang-format to format the code base.

### Install

#### Debian Bookworm

You need to install the package clang-format-15 and set is as the default executable with update-alternatives.

```bash
apt install clang-format-15
update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-15 120
```

### Formatting code

```bash
make format
```

### Checking whether the code is formatted

```bash
make check-format
```

## Coverage

### Dependencies

#### Debian Bookworm

If you want to run the GCC-based coverage, you should install the lcov package with the following command.

```bash
sudo apt install lcov
```

If you want to run the clang-based coverage, you should install the clang package with the following command.

```bash
sudo apt install clang llvm
```

### Compilation

Before running the coverage, you should build the emulator with the flag coverage-toolchain=gcc or coverage-toolchain=clang.
Make sure you run `make clean` to clean up any previous compilation.
For GCC-based coverage run the following command.

```bash
make coverage=yes COVERAGE_TOOLCHAIN=gcc -j$(nproc)
make build-tests-all coverage=yes COVERAGE_TOOLCHAIN=gcc -j$(nproc)
```

For clang-based coverage run the following command.

```bash
make coverage=yes COVERAGE_TOOLCHAIN=clang -j$(nproc)
make build-tests-all coverage=yes COVERAGE_TOOLCHAIN=clang -j$(nproc)
```

### Running coverage

After building the emulator with coverage enable, you should run the following command.
For instance:

```bash
make test coverage-report coverage=yes COVERAGE_TOOLCHAIN=gcc
```

This command will generate a coverage report in the src directory.
For clang coverage, repeat the same command but with the flag coverage-toolchain=clang.

## Contributing

Thank you for your interest in Cartesi! Head over to our [Contributing Guidelines](CONTRIBUTING.md) for instructions on how to sign our Contributors Agreement and get started with
Cartesi!

Please note we have a [Code of Conduct](CODE_OF_CONDUCT.md), please follow it in all your interactions with the project.

## License

The machine-emulator repository and all contributions are licensed under
[LGPL 3.0](https://www.gnu.org/licenses/lgpl-3.0.html). Please review our [COPYING](COPYING) file.
