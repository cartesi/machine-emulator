#!/bin/bash

# run server
remote-cartesi-machine \
	--server-address=localhost:8080 > server.out 2>&1 &
# wait until connection works
while ! netstat -ntl 2>&1 | grep 8080; do
	sleep 1;
done
# run client
lua5.3 run-remote-config.lua \
    localhost:8080 \
    localhost:8081 \
    config.nothing-to-do > client.out 2>&1
