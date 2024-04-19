#!/bin/bash
rm -f output.raw
truncate -s 4K output.raw
echo "6*2^1024 + 3*2^512" > input.raw
truncate -s 4K input.raw
cartesi-machine \
    --append-rom-bootargs="single=yes" \
    --flash-drive="label:input,length:1<<12,filename:input.raw" \
    --flash-drive="label:output,length:1<<12,filename:output.raw,shared" \
    -- $'dd status=none if=$(flashdrive input) | lua -e \'print((string.unpack("z",  io.read("a"))))\' | bc | dd status=none of=$(flashdrive output)' \
    2>&1
rm -f input.raw
rm -f output.raw
