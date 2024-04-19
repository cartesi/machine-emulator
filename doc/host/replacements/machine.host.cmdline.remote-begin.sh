#!/bin/bash

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
    --max-mcycle=1Mi \
    -- echo "Still here!" > client.out 2>&1
