#!/bin/bash
cartesi-machine \
    --flash-drive="label:foo,filename:foo.ext2" \
    -- "ls /mnt/foo/*.txt && cp /mnt/foo/bar.txt /mnt/foo/baz.txt && ls /mnt/foo/*.txt" \
    2>&1
