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

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

LUA=${1:-lua5.4}

TEST_LIST=(htif-console.lua htif-rollup.lua htif-yield.lua log-with-mtime-transition.lua machine-bind.lua machine-test.lua mcycle-overflow.lua mtime-interrupt.lua)

for x in ${TEST_LIST[@]}; do
    echo "Running $x"
    echo -n 'CTSICTSI' | (bash -c "${LUA} $SCRIPT_DIR/../lua/$x local") || exit 1;
done
