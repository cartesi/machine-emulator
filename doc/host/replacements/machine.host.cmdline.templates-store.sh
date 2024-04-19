#!/bin/bash
cartesi-machine \
    --append-rom-bootargs="single=yes" \
    --flash-drive="label:input,length:1<<12" \
    --flash-drive="label:output,length:1<<12" \
    --max-mcycle=0 \
    --final-hash \
    --store="calculator-template" \
    -- $'dd status=none if=$(flashdrive input) | lua -e \'print((string.unpack("z", io.read("a"))))\' | bc | dd status=none of=$(flashdrive output)' \
    2>&1

rm -r calculator-template
