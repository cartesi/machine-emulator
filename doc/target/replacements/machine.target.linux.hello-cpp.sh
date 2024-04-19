#!/bin/bash
cartesi-machine \
    --flash-drive=label:hello,filename:hello.ext2 \
    -- /mnt/hello/hello-cpp \
    2>&1
