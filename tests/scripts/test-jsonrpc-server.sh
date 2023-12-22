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

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
remote_cartesi_machine=$1
cartesi_machine=$2
cartesi_machine_tests=$3
lua=$4
test_path=${CARTESI_TESTS_PATH}

server_address=127.0.0.1:6001

tests=(
    "$cartesi_machine_tests --remote-address=$server_address --remote-protocol="jsonrpc" --test-path=\"$test_path\" --test='.*' run"
    "$lua $script_dir/../lua/machine-bind.lua jsonrpc --remote-address=$server_address"
    "$lua $script_dir/../lua/machine-test.lua jsonrpc --remote-address=$server_address"
    "$cartesi_machine --remote-address=$server_address --remote-protocol="jsonrpc" --remote-shutdown"
    "$lua $script_dir/../lua/test-jsonrpc-fork.lua --remote-address=$server_address"
)

is_server_running () {
    echo $cartesi_machine --remote-address=$server_address --remote-protocol="jsonrpc" --max-mcycle=0
    eval $cartesi_machine --remote-address=$server_address --remote-protocol="jsonrpc" --max-mcycle=0 &> /dev/null
}

wait_for_server () {
    for i in $(seq 1 10)
    do
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
    sleep 1
    if ps -p $pid > /dev/null
    then
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
