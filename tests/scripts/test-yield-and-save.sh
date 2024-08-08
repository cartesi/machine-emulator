#!/bin/bash

set -e

cartesi_machine=${1:-cartesi-machine}
snapshot_dir="/tmp/snapshots/yield_and_save_test"

mkdir -m 755 -p /tmp/snapshots
bash -c "$cartesi_machine --store=$snapshot_dir ioctl-echo-loop --reports=2 --verbose=1"
if [ ! -d "$snapshot_dir" ] || [ ! "$(ls -A $snapshot_dir)" ]; then
    echo "yield_and_save_test machine was not saved. Test failed!"
    exit 1
fi
rm -rf /tmp/snapshots
