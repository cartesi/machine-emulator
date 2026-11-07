#!/bin/bash
# usage: kill-after-pte.sh <stored dir> <collect|run> <ram file> <pte offset> <expected pte hex16>
# Starts child.lua on the stored machine, waits until the guest's page-walk A-bit write is visible in the shared
# RAM file, waits 1 more second (the child is still inside the same call), then SIGKILLs the child.
set -uo pipefail
dir=$1; mode=$2; ram=$3; off=$4; want=$5
lua5.4 child.lua "$dir" "$mode" &
pid=$!
for _ in $(seq 1 600); do
    got=$(od -An -t x8 -j "$off" -N 8 "$ram" | tr -d ' \n')
    [ "$got" = "$want" ] && break
    kill -0 "$pid" 2>/dev/null || { echo "CHILD-DIED-EARLY"; exit 1; }
    sleep 0.05
done
[ "$got" = "$want" ] || { kill -9 "$pid"; wait "$pid" 2>/dev/null; echo "PTE-NEVER-CHANGED $got"; exit 1; }
sleep 1
kill -0 "$pid" 2>/dev/null || { echo "CHILD-DIED-EARLY"; exit 1; }
kill -9 "$pid"
wait "$pid" 2>/dev/null
echo "KILLED"
