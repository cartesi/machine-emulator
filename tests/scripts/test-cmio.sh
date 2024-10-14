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

set -e

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
remote_cartesi_machine=$1
cartesi_machine=$2
lua=$3
test_path=${CARTESI_TESTS_PATH}
cmio_path=${CARTESI_CMIO_PATH}

server_address=127.0.0.1:6010

tests=(
    "$lua $script_dir/../lua/cmio-test.lua jsonrpc --remote-address=$server_address"
)

is_server_running () {
    echo $cartesi_machine --remote-address=$server_address --max-mcycle=0
    eval $cartesi_machine --remote-address=$server_address --max-mcycle=0 &> /dev/null
}

wait_for_server () {
    for i in $(seq 1 10); do
        if is_server_running
        then
            return 0
        fi
        sleep 1
    done
    echo "server didn't start" >&2
    exit 1
}

wait_for_shutdown () {
    pid=$1

    for i in $(seq 1 10); do
        if ps -p $pid > /dev/null; then
            kill $pid
            echo "waiting for pid: $pid..."
            sleep 1
        fi
    done

    if ps -p $pid > /dev/null; then
        kill $pid
        echo "$0 killed $pid (server was still running after shutdown)" >&2
        exit 1
    fi
}

for test_cmd in "${tests[@]}"
do
    echo $remote_cartesi_machine --server-address=$server_address
    $remote_cartesi_machine --server-address=$server_address &
    server_pid=$!
    wait_for_server
    eval $test_cmd
    retcode=$?
    wait_for_shutdown $server_pid
    if [[ $retcode != 0 ]]
    then
        exit $retcode
    fi
done

eval "$lua $script_dir/../lua/cmio-test.lua local"

