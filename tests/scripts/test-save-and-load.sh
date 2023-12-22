#!/bin/bash

cartesi_machine=${1:-cartesi-machine}

mkdir -m 755 -p /tmp/snapshots
$cartesi_machine --max-mcycle=0 --store=/tmp/snapshots/save_and_load_test
$cartesi_machine --load=/tmp/snapshots/save_and_load_test
rm -rf /tmp/snapshots
