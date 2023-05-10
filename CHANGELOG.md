# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Fixed

- Fixed compile errors with GCC 13.1
- Fixed Lua path being mixed with different Lua version path

### Added

- Added --version and --version-json command-line options in cartesi-machine

### Changed

- Updated Lua version to 5.4
- Use Lua path environment variables specific for version 5.4

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
- Improved clua\_dumpstack to limit size of diplayed string data and to escape unprintable chars
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
- Fixed machine::step by moving RTC interrup handling from machine::run to interpret
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

[Unreleased]: https://github.com/cartesi/machine-emulator/compare/v0.14.0...HEAD
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
