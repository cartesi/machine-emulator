# Cartesi Machine Emulator

The Cartesi Machine Emulator is the reference off-chain implementation of the Cartesi Machine Specification. It's written in C/C++ with POSIX dependencies restricted to the terminal, process, and memory-mapping facilities. It is distributed as a library and scriptable in the Lua programming language.

The emulator implements RISC-V's RV64IMASU ISA. The letters after RV specify the extension set. This selection corresponds to a 64-bit machine, Integer arithmetic with Multiplication and division, Atomic operations, as well as the optional Supervisor and User privilege levels. In addition, Cartesi Machines support the Sv48 mode of address translation and memory protection.

## Getting Started

Run `make help` for a list of target options. Here are some of them:

```
Cleaning targets:
  clean                      - clean the src/ artifacts
  depclean                   - clean + dependencies
  distclean                  - depclean + profile information and downloads
Docker targets:
  build-debian-image         - Build the machine-emulator debian based docker image
```

### Requirements

- C++ Compiler with support for C++17 (tested with GCC >= 8+ and Clang >= 8.x).
- GNU Make >= 3.81
- GRPC >= 1.45.0
- Lua >= 5.4.4

Obs: Please note that Apple Clang Version number does not follow upstream LLVM/Clang.

#### Debian Bookworm

```
apt-get install ca-certificates build-essential \
        wget git patchelf pkg-config xsltproc \
        lua5.4 luarocks liblua5.4-dev libssl-dev \
        libgrpc++-dev libprotobuf-dev protobuf-compiler-grpc

sudo luarocks install --lua-version=5.4 lpeg
sudo luarocks install --lua-version=5.4 dkjson
sudo luarocks install --lua-version=5.4 luasocket
sudo luarocks install --lua-version=5.4 luasec
sudo luarocks install --lua-version=5.4 luaposix
sudo luarocks install --lua-version=5.4 md5
```
#### MacOS

##### MacPorts
```
sudo port install wget pkgconfig grpc openssl lua lua-luarocks

sudo luarocks install --lua-version=5.4 lpeg
sudo luarocks install --lua-version=5.4 dkjson
sudo luarocks install --lua-version=5.4 luasocket
sudo luarocks install --lua-version=5.4 luasec
sudo luarocks install --lua-version=5.4 luaposix
sudo luarocks install --lua-version=5.4 md5
```

##### Homebrew
```
brew install llvm@12 wget pkg-config grpc openssl lua@5.4 luarocks
luarocks --lua-dir=$(brew --prefix)/opt/lua@5.4 install lpeg
luarocks --lua-dir=$(brew --prefix)/opt/lua@5.4 install dkjson
luarocks --lua-dir=$(brew --prefix)/opt/lua@5.4 install luasocket
luarocks --lua-dir=$(brew --prefix)/opt/lua@5.4 install luasec
luarocks --lua-dir=$(brew --prefix)/opt/lua@5.4 install luaposix
luarocks --lua-dir=$(brew --prefix)/opt/lua@5.4 install md5
```

For emulator scripts to work it is expected that `lua5.4` binary is available in the system PATH. If operating system/package manager that you are using provides only `lua` or lua binary named in a different way (e.g. on `Homebrew`), please create symbolic link or alias `lua5.4`.

### Build

```bash
$ make submodules
$ make downloads
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

The default search path for binaries is `machine-emulator/tests`. Alternatively you can specify the binaries path using the `CARTESI_TESTS_PATH` variable as in:

```bash
$ make test CARTESI_TESTS_PATH=/full/path/to/test/binaries
```

## Linter

We use clang-tidy 14 as the linter.

### Install

#### Debian Bookworm

You need to install the package clang-tidy-15 and set it as the default executable with update-alternatives.

```bash
$ apt install clang-tidy-15
$ update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-15 120
```

### Running Lint

```bash
$ make lint -j$(nproc)
```

## Code format

We use clang-format to format the code base.

### Install

#### Debian Bookworm

You need to install the package clang-format-15 and set is as the default executable with update-alternatives.

```bash
$ apt install clang-format-15
$ update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-15 120
```

### Formatting code

```bash
$ make format
```

### Checking whether the code is formatted

```bash
$ make check-format
```

## Coverage

### Dependencies

#### Debian Bookworm

If you want to run the GCC-based coverage, you should install the lcov package with the following command.

```bash
$ sudo apt install lcov
```

If you want to run the clang-based coverage, you should install the clang package with the following command.

```bash
$ sudo apt install clang llvm
```

### Compilation

Before running the coverage, you should build the emulator with the flag coverage-toolchain=gcc or coverage-toolchain=clang.
Make sure you run `make clean` to clean up any previous compilation.
For GCC-based coverage run the following command.

```bash
$ make coverage-toolchain=gcc -j$(nproc)
```

For clang-based coverage run the following command.

```bash
$ make coverage-toolchain=clang -j$(nproc)
```

### Running coverage

After building the emulator with coverage enable, you should run the following command.
You need to specify the binaries test path using the `CARTESI_TESTS_PATH` variable.
You also need to specify the directory containg the ROM, kernel and rootfs with the `CARTESI_IMAGES_PATH` variable.
For instance:

```bash
$ make coverage=yes test-all coverage-report \
    CARTESI_TESTS_PATH=$(realpath ../tests/build) \
    CARTESI_IMAGES_PATH=$(realpath ./src)
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
