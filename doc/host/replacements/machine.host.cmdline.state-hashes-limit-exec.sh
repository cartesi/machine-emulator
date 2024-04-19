#!/bin/bash
cartesi-machine \
    --max-mcycle=$1 \
    --initial-hash \
    --final-hash \
    2>&1
