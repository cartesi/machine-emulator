#!/bin/bash

for i in 1 2; do
	rollup-memory-range encode input-metadata > epoch-0-input-metadata-$i.bin <<-EOF
	{
		"msg_sender": $(printf '"0x%040d"' $i)
		"block_number": 0,
		"time_stamp": 0,
		"epoch_index": 0,
		"input_index": $i
	}
	EOF

	rollup-memory-range encode input  > epoch-0-input-$i.bin <<-EOF
	{
		"payload": "hello from input $i"
	}
	EOF
done
rollup-memory-range encode input  > query.bin <<EOF
{
	"payload": "hello from query"
}
EOF

echo Done creating bins

# run server
remote-cartesi-machine \
	--server-address=localhost:8080 > server.out 2>&1 &
echo Ran server
# wait until connection works
while ! netstat -ntl 2>&1 | grep 8080 > /dev/null; do
	sleep 1;
    echo waiting
done
# run client
cartesi-machine \
    --remote-address=localhost:8080 \
    --checkin-address=localhost:8081 \
    --remote-shutdown \
    --rollup \
    --rollup-advance-state=epoch_index:0,input_index_begin:1,input_index_end:3,hashes \
    --rollup-inspect-state \
    -- ioctl-echo-loop --vouchers=1 --notices=1 --reports=1 --reject=1 \
	> client.out 2>&1

\rm -rf epoch-0-input-1.bin epoch-0-input-1-notice-0.bin epoch-0-input-1-notice-hashes.bin epoch-0-input-1-report-0.bin epoch-0-input-1-voucher-0.bin epoch-0-input-1-voucher-hashes.bin epoch-0-input-2.bin epoch-0-input-2-notice-0.bin epoch-0-input-2-notice-hashes.bin epoch-0-input-2-report-0.bin epoch-0-input-2-voucher-0.bin epoch-0-input-2-voucher-hashes.bin epoch-0-input-metadata-1.bin epoch-0-input-metadata-2.bin query.bin query-report-0.bin
