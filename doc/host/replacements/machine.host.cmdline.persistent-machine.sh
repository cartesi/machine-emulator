#!/bin/bash
cartesi-machine \
    --max-mcycle=$1 \
    --store="machine-store" \
    > /dev/null 2>&1

cartesi-machine \
    --load="machine-store" \
    --initial-hash \
    --final-hash \
    2>&1

rm -r machine-store
