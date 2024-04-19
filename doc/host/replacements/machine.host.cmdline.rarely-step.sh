#!/bin/bash
cartesi-machine \
    --max-mcycle=$1 \
    --step 2>&1 > /dev/null 
