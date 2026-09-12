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

# Records the uarch step-log fixture set consumed by the solidity-step tests.
#
# Usage: record-uarch-step-fixtures.sh <fixtures-dir>
#
# Defaults fit the installed emulator in the tests docker image; the
# solidity-step Makefile fixtures target overrides them for a repo checkout.

set -e

fixtures_dir=$1
if [ -z "$fixtures_dir" ]; then
    echo "usage: $0 <fixtures-dir>" >&2
    exit 1
fi

lua=${LUA:-lua5.4}
recorders_dir=${RECORDERS_DIR:-/usr/share/cartesi-machine/tests/lua}
tests_path=${UARCH_TESTS_PATH:-/usr/share/cartesi-machine/tests/data/uarch}
pattern=${UARCH_TEST_PATTERN:-rv64ui%-uarch%-.+%.bin}

mkdir -p "$fixtures_dir"

# Per-cycle step logs over the uarch test corpus
$lua "$recorders_dir/uarch-riscv-tests.lua" --test-path="$tests_path" --test="$pattern" \
    --per-cycle-logs --output-dir="$fixtures_dir/uarch-tests-per-cycle" record_uarch_tests
# One- and two-cycle logs pinning the verifier to a single uarch step
$lua "$recorders_dir/record-uarch-multi-cycle.lua" \
    --output-dir="$fixtures_dir/uarch-multi-cycle"
# CMIO response and uarch reset transition logs
$lua "$recorders_dir/record-send-cmio-response.lua" \
    --output-dir="$fixtures_dir/send-cmio-response"
$lua "$recorders_dir/record-reset-uarch.lua" \
    --output-dir="$fixtures_dir/reset-uarch"
# Tampered copies of the logs above that the verifier must reject; they record last
$lua "$recorders_dir/record-adversarial-uarch.lua" \
    --fixtures-dir="$fixtures_dir" \
    --output-dir="$fixtures_dir/reject-uarch"
$lua "$recorders_dir/record-adversarial-send-cmio-response.lua" \
    --fixtures-dir="$fixtures_dir" \
    --output-dir="$fixtures_dir/reject-send-cmio-response"
