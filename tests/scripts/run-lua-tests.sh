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

# Runs the standalone lua test programs and every spec suite serially. The make
# targets run the same programs in parallel; this script is the entry point for
# the installed tests package (which has no make), so it stays sequential.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

LUA=${1:-lua5.4}

# Plain test programs, run with the "local" machine type.
PROGRAMS=(
htif-console.lua
htif-cmio.lua
htif-yield.lua
log-with-mtime-transition.lua
machine-bind.lua
machine-test.lua
mcycle-overflow.lua
mtime-interrupt.lua
tlb-flush.lua
pma-scan.lua
pma-page-walk.lua
pma-page-walk-branches.lua
soft-float-division.lua
soft-float-sqrt.lua
)

cd $SCRIPT_DIR/../lua

for x in ${PROGRAMS[@]}; do
    test_path="$SCRIPT_DIR/../lua/$x"
    if [ ! -f "$test_path" ]; then
        echo "Skipping $x (not installed)"
        continue
    fi
    echo "Running $x"
    bash -c "${LUA} $test_path local" || exit 1
done

# Lester spec suites, each a standalone program.
for test_path in "$SCRIPT_DIR"/../lua/spec-*.lua; do
    [ -f "$test_path" ] || continue
    echo "Running $(basename "$test_path")"
    bash -c "${LUA} $test_path" || exit 1
done
