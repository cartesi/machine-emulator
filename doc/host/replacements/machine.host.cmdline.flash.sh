#!/bin/bash
cartesi-machine \
    --flash-drive="label:foo,filename:foo.ext2" \
    -- "cat /mnt/foo/bar.txt" \
    2>&1
