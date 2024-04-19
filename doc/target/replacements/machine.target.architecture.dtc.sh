#!/bin/bash
cartesi-machine \
    --append-rom-bootargs="single=yes" \
    --rollup \
    -- "dtc -I dtb -O dts /sys/firmware/fdt" 2>&1
