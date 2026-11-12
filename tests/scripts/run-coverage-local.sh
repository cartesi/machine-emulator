#!/bin/bash
# Run the coverage pipeline locally, outside the coverage Docker image.
#
# This reproduces what CI does in the "coverage" job. It works on Linux
# (gcc) and macOS (clang/llvm-cov); the toolchain picks GCOV automatically.
#
# Docker must be running: the *-with-toolchain test builds and the uarch PC
# resolution in coverage-report run through `make toolchain-exec`. Everything
# else builds natively.
#
# Native dependencies:
#   Linux (apt): build-essential gcc g++ gcovr libomp-dev libboost-dev
#     libssl-dev libslirp-dev lua5.4 liblua5.4-dev lua-socket lua-lpeg
#     luarocks xxd pkg-config stress-ng
#   macOS (macports): clang gcovr boost openssl libslirp lua54 luarocks
#     pkgconfig stress-ng (llvm provides llvm-cov)
#   luarocks (both): luacov cluacov luaposix
#     (luarocks --lua-version 5.4 install <pkg>)
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
    make -j"$(getconf _NPROCESSORS_ONLN)" coverage=yes

    echo "=== Building tests ==="
    make -j"$(getconf _NPROCESSORS_ONLN)" build-tests-machine-with-toolchain coverage=yes
    make -j"$(getconf _NPROCESSORS_ONLN)" build-tests-misc coverage=yes
    make -j"$(getconf _NPROCESSORS_ONLN)" build-tests-uarch-with-toolchain coverage=yes
    make -j"$(getconf _NPROCESSORS_ONLN)" build-tests-images coverage=yes
fi

# Step 2: set up the environment (paths for Lua, shared libs, etc.)
eval "$(make env)"
cd tests

# Step 3: run the test suite and generate the report (same as CI). coverage-all
# runs the parallel test group, the custom pristine uarch tests and the uarch PC
# collection, then the report, sequenced by order-only prerequisites in the Makefile.
if [ "$SKIP_TESTS" = false ]; then
    echo "=== Running tests and generating coverage report ==="
    make clean-coverage
    make -j"$(getconf _NPROCESSORS_ONLN)" coverage-all coverage=yes
else
    echo "=== Generating coverage report from existing coverage data ==="
    make coverage-report coverage=yes
fi

echo ""
echo "=== Coverage summary ==="
cat build/coverage/coverage.txt
echo ""
echo "HTML report: tests/build/coverage/gcc/index.html"
