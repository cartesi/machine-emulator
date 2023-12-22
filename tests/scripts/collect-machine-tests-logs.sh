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

if [ "$#" -ne 2 ]; then
    echo $0 "<test_path> <output_path>"
    exit 1;
fi

set -e

test_path=$1
shift
output_path=$1
shift

task() {
    local f=$1
    local b=${output_path}/$(basename $f .bin).json
    echo running $f
    ./cartesi-machine.lua --no-root-backing --ram-image=$f --memory-size=128 --json-steps=$b --batch
    echo compressing $b
    brotli -j $b
}

# Default for unknown OS
max_jobs=1
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    max_jobs=$(nproc)
elif [[ "$OSTYPE" == "darwin"* ]]; then
    max_jobs=$(sysctl -n hw.ncpu)
fi

jobs=0;
for f in ${test_path}/rv64*.bin ${test_path}/sd_pma_overflow.bin; do
    ((jobs++))
    task "$f" &
    # Wait if the number of jobs reaches max_jobs
    if ((jobs >= max_jobs)); then
        echo waiting
        wait -n  # Waits for a single job to finish
        ((jobs--))
    fi
done

wait
