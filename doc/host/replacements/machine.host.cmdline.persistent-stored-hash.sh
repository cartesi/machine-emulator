#!/bin/bash
cartesi-machine \
    --max-mcycle=$1 \
    --store="machine-store" \
    > /dev/null 2>&1

cartesi-machine-stored-hash machine-store \
    2>&1

rm -r machine-store
