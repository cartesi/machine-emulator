#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo $0 "<test_path> <output_path>"
    exit 1;
fi

set -e

test_path=$1
shift
output_path=$1
shift

#p=$(command nproc) || p=$(command gnproc) || p=4
p=8

task() {
    local f=$1
    local b=${output_path}/$(basename $f .bin).json
    echo running $f
    ./cartesi-machine.lua --no-root-backing --rom-image=${test_path}/bootstrap.bin --ram-image=$f --memory-size=128 --json-steps=$b --batch
    echo compressing $b
    brotli -j $b
}

t=0;
for f in ${test_path}/rv64*.bin  ${test_path}/sd_pma_overflow.bin; do
    (((t++)%p==0)) && echo waiting && wait
    task "$f" &
done
wait
