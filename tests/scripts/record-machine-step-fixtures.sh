#!/bin/bash

# Copyright Cartesi and individual authors (see AUTHORS)
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
#

# Records the machine step-log fixture set consumed by the risc0 tests
# (sha256 logs for the zkVM hash accelerator).
#
# Usage: record-machine-step-fixtures.sh <fixtures-dir>
#
# Defaults fit the installed emulator in the tests docker image; the
# risc0 Makefile fixtures target overrides them for a repo checkout.

set -e

fixtures_dir=$1
if [ -z "$fixtures_dir" ]; then
    echo "usage: $0 <fixtures-dir>" >&2
    exit 1
fi

lua=${LUA:-lua5.4}
recorders_dir=${RECORDERS_DIR:-/usr/share/cartesi-machine/tests/lua}
tests_path=${MACHINE_TESTS_PATH:-/usr/share/cartesi-machine/tests/data/machine}
jobs=${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu)}

mkdir -p "$fixtures_dir/cartesi-machine-tests"
# The record-*.lua recorders require an empty output dir (they never delete); clear any stale
# reject/one-mcycle fixtures so a re-run starts clean. The recorders recreate the dirs.
rm -rf "$fixtures_dir/reject-machine" "$fixtures_dir/one-mcycle"

# Machine step logs over the test corpus (MACHINE_TEST optionally restricts which)
$lua "$recorders_dir/cartesi-machine-tests.lua" --test-path="$tests_path" --jobs="$jobs" \
    --hash-function=sha256 \
    ${MACHINE_TEST:+--test="$MACHINE_TEST"} \
    --save-step-logs="$fixtures_dir/cartesi-machine-tests" run_step
# One 1-mcycle log for the prove->compress->Sepolia pipeline
$lua "$recorders_dir/record-one-mcycle.lua" --hash-function=sha256 \
    --output-dir="$fixtures_dir/one-mcycle"
# Tampered copies of the logs above that the guest must reject; they record last
$lua "$recorders_dir/record-adversarial-machine.lua" \
    --fixtures-dir="$fixtures_dir" \
    --output-dir="$fixtures_dir/reject-machine"
