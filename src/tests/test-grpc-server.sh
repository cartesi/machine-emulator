#!/bin/bash

# Copyright 2021 Cartesi Pte. Ltd.
#
# This file is part of the machine-emulator. The machine-emulator is free
# software: you can redistribute it and/or modify it under the terms of the GNU
# Lesser General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# The machine-emulator is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
#

cartesi_machine_server=$1
cartesi_machine=$2
cartesi_machine_tests=$3
test_path=$4

server_address=127.0.0.1:5001
checkin_address=127.0.0.1:5002

tests=(
    "$cartesi_machine_tests --server-address=$server_address --checkin-address=$checkin_address --test-path=\"$test_path\" --test='.*' run"
    "./tests/machine-bind.lua grpc --server-address=$server_address --checkin-address=$checkin_address"
    "./tests/machine-test.lua grpc --server-address=$server_address --checkin-address=$checkin_address"
    "$cartesi_machine --server-address=$server_address --server-shutdown"
)

is_server_running () {
    $cartesi_machine --server=$server_address --max-mcycle=0 &> /dev/null
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
    $cartesi_machine_server --server-address=$server_address &
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
