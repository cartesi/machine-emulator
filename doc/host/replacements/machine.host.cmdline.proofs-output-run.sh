#!/bin/bash
cartesi-machine \
    --append-rom-bootargs="single=yes" \
    --flash-drive="label:input,length:1<<12" \
    --flash-drive="label:output,length:1<<12" \
    --max-mcycle=0 \
    --final-hash \
    --store="calculator-template" \
    -- $'dd status=none if=$(flashdrive input) | lua -e \'print((string.unpack("z", io.read("a"))))\' | bc | dd status=none of=$(flashdrive output)' \
    > /dev/null 2>&1

truncate -s 4K output.raw
echo "6*2^1024 + 3*2^512" > input.raw
truncate -s 4K input.raw

cartesi-machine \
    --load="calculator-template" \
    --replace-flash-drive="start:0x9000000000000000,length:1<<12,filename:input.raw" \
    --replace-flash-drive="start:0xa000000000000000,length:1<<12,filename:output.raw,shared" \
    --final-hash \
    --final-proof="address:0xa000000000000000,log2_size:12,filename:output-proof" \
    2>&1

rm -r calculator-template
rm output-proof
rm input.raw
rm output.raw
