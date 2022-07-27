# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added

- Added method to get existing remote machine

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

[Unreleased]: https://github.com/cartesi/machine-emulator/compare/v0.9.0...HEAD
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
