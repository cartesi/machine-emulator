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

tests=(
     "$cartesi_machine_tests --server=$server_address --test-path=\"$test_path\" --test='.*' run"
     "./tests/machine-bind.lua grpc --server=$server_address"
     "./tests/machine-test.lua grpc --server=$server_address"
     "$cartesi_machine --server=$server_address"
)

for test_cmd in "${tests[@]}"; do
    $cartesi_machine_server --server-address=$server_address &
    for i in $(seq 1 10); do
        $cartesi_machine --server=$server_address --max-mcycle=0 > /dev/null
        if [[ $? == 0 ]]; then
            break
        fi
        sleep 1
    done
    eval $test_cmd
    retcode=$?
    kill %%
    if [[ $retcode != 0 ]]; then
        exit $retcode
    fi
done
