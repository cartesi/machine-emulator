#!/bin/bash
# Run the coverage pipeline locally on Ubuntu 24.04, outside Docker.
#
# This reproduces what CI does in the "coverage" job.
#
# Dependencies (install via apt):
#   build-essential gcc g++ gcovr
#   libomp-dev libboost-dev libssl-dev libslirp-dev
#   lua5.4 liblua5.4-dev lua-posix lua-socket lua-lpeg luarocks
#   xxd pkg-config
#   luarocks packages: luacov cluacov (install via: sudo luarocks --lua-version 5.4 install luacov && sudo luarocks --lua-version 5.4 install cluacov)
#   g++-14-riscv64-linux-gnu gcc-riscv64-unknown-elf
#   stress-ng (for the coverage workload test)
#
# The riscv64 cross-compiler packages may require the Debian trixie repos
# or equivalent. On Ubuntu 24.04, you may need to add a PPA or download
# the packages manually.
#
# You must have already initialized submodules:
#   git submodule update --init --recursive
#
# Usage:
#   cd emulator
#   tests/scripts/run-coverage-local.sh [--skip-build] [--skip-tests]
#
# Output:
#   tests/build/coverage/         HTML report and summary

set -euo pipefail

EMULATOR_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$EMULATOR_ROOT"

SKIP_BUILD=false
SKIP_TESTS=false
for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        --skip-tests) SKIP_TESTS=true ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

# Step 1: build everything with coverage instrumentation
if [ "$SKIP_BUILD" = false ]; then
    echo "=== Building emulator with coverage ==="
    make -j"$(nproc)" coverage=yes

    echo "=== Building tests ==="
    make -j"$(nproc)" build-tests-machine-with-toolchain coverage=yes
    make -j"$(nproc)" build-tests-misc coverage=yes
    make -j"$(nproc)" build-tests-uarch-with-toolchain coverage=yes
    make -j"$(nproc)" build-tests-images coverage=yes
fi

# Step 2: set up the environment (paths for Lua, shared libs, etc.)
eval "$(make env)"
cd tests

# Step 3: run the test suite (same targets as CI)
if [ "$SKIP_TESTS" = false ]; then
    echo "=== Running tests ==="
    make -j1 \
        test-save-and-load \
        test-machine \
        test-lua \
        test-jsonrpc \
        test-c-api \
        test-coverage-machine \
        test-uarch-rv64ui \
        test-uarch-interpreter \
        test-coverage-uarch \
        test-machine-with-log-step \
        test-coverage-uarch-pcs \
        coverage=yes
fi

# Step 4: generate the coverage report
echo "=== Generating coverage report ==="
make coverage-report coverage=yes

echo ""
echo "=== Coverage summary ==="
cat build/coverage/coverage.txt
echo ""
echo "HTML report: tests/build/coverage/gcc/index.html"
