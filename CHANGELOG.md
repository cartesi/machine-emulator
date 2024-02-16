# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Removed gRPC features

## [0.16.0] - 2024-02-09
### Added
- Implemented the UARCH reset feature
- Added soft yield runtime configuration using hints of the SRAIW instruction
- Added shadow uarch state
- Embedded the uarch RAM binary
- Added instructions on how to build `libcartesi.a` in standalone
- Supported compiling `libcartesi_jsonrpc.a` static library
- Added file mapping and terminal support for Windows
- Added the possibility to compile `libcartesi` without `mmap()`
- Supported compiling `libcartesi` as a static library
- Added memory range introspection
- Introduced `-it` option for colored and bigger interactive terminal
- Replaced MTD drives with PMEM drives
- Initialized random entropy from the device tree
- Added root hashes to `catalog.json`
- Replaced proof with `sibling_hashes`

### Changed
- Built device tree automatically into the machine's ROM, eliminating the need for a ROM image
- Enabled rollup by default
- Updated libboost version to 1.81
- Changed stored machine configs from protobuf to JSON
- Removed remote-cartesi-machine-proxy
- Moved uarch generated files to the uarch source directory
- Organized all tests under the tests directory
- Added emulator major and minor versions to the device tree
- Used new rootfs provided by the tools repository
- Used static libraries when compiling executables
- Made it possible to compile `libcartesi` without threading support
- Reimplemented a portable OS time function
- Allowed compiling `libcartesi` without GRPC or Lua installed
- Didn't expose internal symbols in the public C API
- Added support for cross-compiling libcartesi
- Removed `std::filesystem` use from `libcartesi` (unsupported by WASI)
- Made `termios` non-mandatory in `libcartesi` (unsupported by WASI)
- Improved makefile for packaging
- Adjusted bootargs and renamed bootargs command line option
- Introduced machine init and entrypoint config and options
- Removed dump_pmas method
- Removed Lua `md5` dependency by using keccak instead
- Simplified machine hash computation in tests
- Replaced ROM with DTB
- Bumped kernel and rootfs versions
- Replaced crypto++ with tiny sha3 to compute Keccak hash
- Replaced boost filesystem with std filesystem
- Updated mongoose to 7.12 and refactored how it's bundled
- Bundled nlohmann-json into third-party
- Replaced libb64 with a custom base64 implementation
- Removed the unused `--json-steps` option
- Added support for compiling libcartesi to WebAssembly

### Fixed
- Made append options work when empty
- Included missing `climits` in `json-util.cpp`
- Correctly counted optional arguments
- Fixed `protoc` compile errors on Ubuntu
- Fixed the build on MacOS with Homebrew
- Reserved memory for firmware M-mode code in FDT
- Fixed lint errors and warnings

## [0.15.3] - 2024-01-25
### Fixed

- Fixed missing lua modules in docker image
- Fixed upload and download of artifacts on CI
- Fixed protoc compile errors on Ubuntu
- Fixed build on MacOS with homebrew

## [0.15.2] - 2023-08-21
### Changed

- Made emulator patch version not impact machine root hash
- Enabled line buffering for machine stdout in non-interactive mode

## [0.15.1] - 2023-08-17
### Fixed

- Fixed the list of files on the strip and patch installation step

## [0.15.0] - 2023-08-16
### Fixed

- Fixed compile errors with GCC 13.1
- Fixed Lua path being mixed with different Lua version path
- Fixed bug in get\_proto\_access\_log()
- Fixed lint warnings with CLANG 15
- Introduced a workaround for high memory usage when running on QEMU ARM64
- Added deb to release process
- Fixed SIGTTOU handling on jsonrpc remote cartesi machine
- Improved signal handling on remote cartesi machines

### Added

- Added fork support on the jsonrpc remote cartesi machine
- Added log level control on the jsonrpc remote cartesi machine
- Added static analysis for Lua code
- Added code formatter for Lua code
- Added support for to-be-closed variables for machine Lua API
- Added --version and --version-json command-line options in cartesi-machine
- Added --skip-root-hash-check command line option to speed up machine loading in tests
- Added --skip-version-check command line option to allow testing old machine snapshots
- Added --htif-no-console-putchar command line option
- Added support for ARM64 docker images with depot.dev
- Added support for publishing docker images on ghcr.io
- Added tlb\_get\_entry\_hot/cold\_rel\_addr
- Added titles to jsonrpc components in jsonrpc-discover.json
- Added proofs to uarch-riscv-tests json logs
- Added support for Debian packages on the release
- Added uarch-ram.bin to the release

### Changed

- Updated Lua version to 5.4
- Use Lua path environment variables specific for version 5.4
- Move uarch halt from assembler to C++
- Ensure that uarch does not advance to the next micro instruction when iflags.H or iflags.Y is set
- Made flash drive length and ROM image filename optional in machine config
- Updated license/copyright notice in all source code
- Changed docker base image from Ubuntu 22.04 to Debian Bookworm
- Started using system provided protobuf and grpc libraries
- Updated gprc-interfaces
- Updated machine-emulator-defines
- Refactored continuous integration workflow
- Updated ROM, kernel, rootfs and tests versions on CI
- Removed Boost Log dependency
- Renamed concurrecy\_config to concurrency\_runtime\_config
- Optimized the use of machine::get\_proof in uarch\_record\_state\_access
- Reverted iflags fixed point test in uarch-step

## [0.14.0] - 2023-05-03
### Added

- Added uarch halt flag
- Added reset\_uarch\_state
- Added and improved uarch tests
- Added get\_uarch\_x\_address
- Added new jsonrpc-remote-cartesi-machine server
- Added client support for new jsonrpc-remote-cartesi-machine server
- Added command-line support for new jsonrpc-remote-cartesi-machine server in cartesi-machine

### Changed

- Optimized interpreter instruction fetch
- Optimized interpreter hot loop to commit pc/mcycle only when necessary
- Renamed voucher field: address -> destination
- Removed uarch ROM
- Improved uarch support on cartesi-machine.lua
- Refactored uarch interpreter making it easier to port to Solidity
- Changed return type of run\_uarch from void to break reason
- Renamed uarch related method names on machine class
- Removed Alpine image generation from CI
- Removed crypto++ library from third-party. Using system-installed library instead.
- Changed --step command-line option to --step-uarch in cartesi-machine.lua, for consistency
- Removed server-manager implementation from the emulator repository
- Changed marchid to 0xf

## [0.13.0] - 2023-02-16
### Added

- Added support for RISC-V compressed instructions
- Added support for debugging emulator with GDB
- Added return to machine run API informing the reason for breaking the interpreter loop
- Added many new tests to improve testing and coverage of the RISC-V interpreter and the C APIs
- Added coverage workflow with summary reports to the CI
- Added sanitize workflow to the CI, for catching leaks and undefined behavior
- Added support for running RISC-V tests in parallel to the CI
- Added support for passing NULL err\_msg in all C APIs, meaning the error message won't be received

### Fixed

- Fixed interrupts servicing priority, to honor the same priority as in the RISC-V specification
- Fixed some leaks and undefined behaviors caught by the new sanitize workflow
- Fixed invalid SLLW, DIVW, REMW and REMUW instructions not raising illegal instruction exception
- Fixed crash from inside the machine while trying to read shadow PMAs
- Fixed off by one error in X registers when saving machine Lua configs
- Fixed F registers not being handled in Lua configs
- Fixed time advancing incorrectly while in interactive terminals

### Changed

- Optimized and refactored interpreter hot loop
- Removed some dead code and simplified some portions of the code
- Removed brkflag CSR
- Changed marchid to 0xe
- Changed RTC\_FREQ\_DIV from 100 to 8192
- Changed RTC\_CLOCK\_FREQ from 100MHz to 128MHz
- Replaced minstret by icycleinstret CSR
- Reworked all int128 operations to use new portable int128 implementation
- Converted all runtime error messages to lowercase
- Improved CI to run faster using GitHub large runners

## [0.12.0] - 2022-11-25
### Added

- Added support for RISC-V floating-point instructions
- Added read/write virtual memory methods
- Added --quiet flag to cartesi-machine.lua
- Added --assert-rolling-template flag to cartesi-machine.lua
- Added the microarchitecture (RV64I) implementation
- Added new optimizations build options on the Makefile
- Added log messages to remote-cartesi-machine
- Added check-in deadline and retry on remote-cartesi-machine
- Added check-in deadline timeout on the server-manager

### Changed

- Updated emulator implementation with respect to latest RISC-V specification
- Optimized Lua API to avoid allocating a uservalue for error messages for every API call
- Lowered PMA addressable ranges from 64-bit to 56-bit
- Changed marchid to 0xd
- Improved error messages relating to PMAs
- Removed DHD device
- Refactored the shadow
- Exposed TLB in the shadow
- Optimized TLB implementation
- Improved server-manager log messages

### Fixed

- Fixed many instruction inconsistencies with respect to the RISC-V specification.
- Fixed overflow in page table entries due to using large physical address ranges.
- Fixed crash when trying to use too many flash drives.

## [0.11.2] - 2022-10-28
### Changed

- Changed grpc lib version to v1.50

## [0.11.1] - 2022-09-28
### Fixed

- Fixed merkle-tree-hash linking on MacOSX
- Changed the deadline used on GetProof and GetRootHash

## [0.11.0] - 2022-09-02
### Added

- Added method to get existing remote machine
- Added no-remote-create and no-remote-destroy options to cartesi-machine.lua
- Prevent linux from reserving 64Mi of memory when ram-length >= 128Mi
- Added GRPC Health Check service on the server-manager
- Added grpc-health-probe to the server-manager docker image

### Fixed

- Fixed MacOSX build

### Changed

- Enabled emulator TLB
- Improved read\_memory method to read all PMA types
- Changed marchid to 0xc
- Bumped server-manager server version
- Bumped remote-machine server version

## [0.10.1] - 2022-07-14
### Fixed

- Fix Lua bind of static methods for remote machines
- Fix rollup-memory-range decoding of empty payloads at end of file
- Fix server-manager version string

### Changed

- Improve server-manager concurrency violation messages

## [0.10.0] - 2022-07-04
### Added

- Added option to encode/decode exceptions to rollup-memory-range.lua
- Added new tests/log-with-mtime-transition.lua

### Fixed

- Fixed HTIF iconsole read from machine state
- Fixed cartesi/grpc.so so it can be loaded without cartesi.so
- Fix mcycle display when printing final hash after step in cartesi-machine.lua
- Fix cartesi.proof.word\_splice\_assert to check for old word value
- Remove derived mtime and msip from CLINT peek returns so they are not reflected in Merkle tree
- Fix clua\_check\_cm\_merkle\_tree\_proof garbage in Lua stack after return
- Fix clua\_check\_cm\_access\_log to save log\_type
- Fix dump\_pmas() to write pristine pages to PMA files
- Fix verify workflow on CI
- Fixed link warning on MacOSX

### Changed

- Make sure HTIF calls to console getchar is only honored when it is enabled in iconsole
- Simplified Lua bind
- Simplified StartSession logic in server manager
- Make HTIF console getchar react faster to input when enabled
- Remove busy wait in interactive mode
- Updated server-manager GRPC interface due to improvements on input exception handling
- Updated docker images based on Ubuntu to version 22.04
- Updated clang-format version to 14
- Updated clang-tidy version to 14
- Updated libboost version to 1.74
- Improved clua\_dumpstack to limit size of displayed string data and to escape unprintable chars
- Improved machine\_merkle\_tree::dump\_merkle\_tree() to indent and print base address of each node
- Removed active epoch index parameter from server-manager InspectRequest GRPC interface
- Test rollup-init error handling in server-manager tests

## [0.9.0] - 2022-04-20

### Added

- Added rollup-exception handling to cartesi-machine.lua and tests
- Added rollup-exception handling to server-manager

### Fixed

- Fixed machine store/load to include rollup memory ranges
- Fixed make env to append to Lua paths rather than replace them
- Fixed checkin behavior in remote-cartesi-machine-proxy

### Changed

- Changed cartesi-machine.lua to fail with exit code 1 when rollup exception is detected
- Changed machine serialization to use protobuf instead of boost
- Changed cartesi-machine.lua to save voucher and notice hashes on revert
- Changed rollup-memory-range.lua to input/output JSON objects
- Changed to LuaRocks for Lua dependencies
- Changed grpc lib version to v1.45
- Changed dhd and rollup fields in config to optional
- Changed server-manager not to advance until first yield
- Changed server-manager so NewSession accepts only stored machine directories (rather than machine configs)
- Changed server-manager version from v0.1.0 to v0.2.0

## [0.8.0] - 2021-12-28

### Added

- Added control of concurrency to emulator runtime config
- Added new remote-cartesi-machine-proxy
- Added several new Merkle tree implementations with different flavors
- Added new --log2-word-size option to merkle-tree-hash
- Added new cartesi-server-manager to support input/output with rollups
- Added coverage tests with gcc and clang
- Added new --load-config and --store-config options to cartesi-machine.lua
- Added new rollup device in emulator to support Cartesi Servers
- Added rollup-memory-range.lua utility to encode/decode rollup inputs/outputs
- Added more and better tests
- Added new C API to machine class, exposed by libcartesi.so
- Added support for simulating rollups advance/inspect state to cartesi-machine.lua

### Fixed

- Fixed missing method to get CSR addresses in Lua bind
- Fixed missing DHD CSRs in Lua bind
- Fixed potential mcycle overflow in emulator
- Fixed machine::step by moving RTC interrupt handling from machine::run to interpret
- Fixed gRPC threading by stopping/restarting server before/after fork in remote-cartesi-machine
- Fixed terminal configuration in remote-cartesi-machine

### Changed

- Changed marchid to 9
- Changed machine::run to only return on yield, halt, or when max\_mcycle is reached
- Changed WFI to noop to simplify code, thus eliminating flag I from iflags CSR
- Changed cartesi-machine-server to remote-cartesi-machine
- Changed Merkle tree proof structures to be more general
- Changed code with improvements suggested by clang-tidy
- Changed code with clang-format
- Changed Lua bind to use C API, cartesi.so links to libcartesi.so
- Changed from luapp to stock Lua interpreter
- Changed remote-cartesi-machine to check-in with client when starting/rollback/snapshot
- Changed machine::replace\_flash\_drive to machine::replace\_memory\_range
- Changed dependency from system provided gRPC libraries to a specific version added to third-party dependencies

## [Previous Versions]
- [0.7.0]
- [0.6.0]
- [0.5.1]
- [0.5.0]
- [0.4.0]
- [0.3.0]
- [0.2.0]
- [0.1.0]

[Unreleased]: https://github.com/cartesi/machine-emulator/compare/v0.16.0...HEAD
[0.16.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.16.0
[0.15.3]: https://github.com/cartesi/machine-emulator/releases/tag/v0.15.3
[0.15.2]: https://github.com/cartesi/machine-emulator/releases/tag/v0.15.2
[0.15.1]: https://github.com/cartesi/machine-emulator/releases/tag/v0.15.1
[0.15.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.15.0
[0.14.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.14.0
[0.13.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.13.0
[0.12.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.12.0
[0.11.2]: https://github.com/cartesi/machine-emulator/releases/tag/v0.11.2
[0.11.1]: https://github.com/cartesi/machine-emulator/releases/tag/v0.11.1
[0.11.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.11.0
[0.10.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.10.0
[0.9.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.9.0
[0.8.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.8.0
[0.7.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.7.0
[0.6.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.6.0
[0.5.1]: https://github.com/cartesi/machine-emulator/releases/tag/v0.5.1
[0.5.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.5.0
[0.4.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.4.0
[0.3.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.3.0
[0.2.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.2.0
[0.1.0]: https://github.com/cartesi/machine-emulator/releases/tag/v0.1.0
