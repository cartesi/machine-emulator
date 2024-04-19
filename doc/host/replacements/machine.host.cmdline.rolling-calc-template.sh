#!/bin/bash
set -x
set -v
rollup-memory-range encode input-metadata > epoch-0-input-metadata-1.bin <<-EOF
{
    "msg_sender": $(printf '"0x%040d"' 1)
    "block_number": 0,
    "time_stamp": 0,
    "epoch_index": 0,
    "input_index": 1
}
EOF
rollup-memory-range encode input  > epoch-0-input-1.bin <<-EOF
{
    "payload": "invalid input"
}
EOF
rollup-memory-range encode input-metadata > epoch-0-input-metadata-2.bin <<-EOF
{
    "msg_sender": $(printf '"0x%040d"' 2)
    "block_number": 0,
    "time_stamp": 0,
    "epoch_index": 0,
    "input_index": 2
}
EOF
rollup-memory-range encode input  > epoch-0-input-2.bin <<-EOF
{
    "payload": "6*2^1024 + 3*2^512"
}
EOF

\rm -rf calc
mkdir calc
cp -f calc.sh calc
chmod +x calc/calc.sh
tar \
    --sort=name \
    --mtime="2022-01-01" \
    --owner=1000 \
    --group=1000 \
    --numeric-owner \
    -cf calc.tar \
    --directory=calc .
\rm -rf calc
genext2fs -f -b 1024 -a calc.tar calc.ext2
\rm -rf calc.tar
\rm -rf calc-template
cartesi-machine \
    --rollup \
    --flash-drive=label:calc,filename:calc.ext2 \
    --store="calc-template" \
    -- /mnt/calc/calc.sh > template.out 2>&1
\rm -rf calc.ext2

# run server
remote-cartesi-machine \
	--server-address=localhost:8080 > server.out 2>&1 &
# wait until connection works
while ! netstat -ntl 2>&1 | grep 8080; do
	sleep 1;
done
# run client
cartesi-machine \
    --remote-address=localhost:8080 \
    --checkin-address=localhost:8081 \
    --remote-shutdown \
    --rollup \
    --rollup-advance-state=epoch_index:0,input_index_begin:1,input_index_end:3,hashes \
    --load="calc-template" \
	> client.out 2>&1

\rm -r epoch-0-input-metadata-1.bin epoch-0-input-1.bin epoch-0-input-metadata-2.bin epoch-0-input-2.bin epoch-0-input-1-notice-hashes.bin epoch-0-input-1-voucher-hashes.bin epoch-0-input-2-notice-0.bin epoch-0-input-2-notice-hashes.bin epoch-0-input-2-voucher-hashes.bin
\rm -rf calc-template
