#!/bin/bash
# Starts the PRT player (doc/recipes/crisium.lua, sentinel mode, no checkpoints) against one application and
# reports whether its start-up accepted the deployment:
#   run-crisium.sh <rpc-url> <application> <dave-dir> <work-dir> [timeout-seconds]
# Prints ACCEPTED once the player has passed its start-up checks and written its first status file (it is then
# stopped), REFUSED if it exited before that (its log is in <work-dir>/log), or TIMEOUT.
set -uo pipefail
rpc=$1 app=$2 dave=$3 dir=$4 limit=${5:-120}
rm -rf "$dir"
mkdir -p "$dir/state" "$dir/checkpoints"
lua5.4 "$RECIPES_DIR/crisium.lua" --rpc="$rpc" --application="$app" --state="$dir/state" \
    --checkpoints="$dir/checkpoints" --dave="$dave" --status-file="$dir/status.json" --poll-interval=0.2 \
    > "$dir/log" 2>&1 &
pid=$!
for _ in $(seq 1 $((limit * 10))); do
    if [ -f "$dir/status.json" ]; then
        kill "$pid" 2> /dev/null
        wait "$pid" 2> /dev/null
        echo ACCEPTED
        exit 0
    fi
    if ! kill -0 "$pid" 2> /dev/null; then
        wait "$pid" 2> /dev/null
        echo REFUSED
        exit 0
    fi
    sleep 0.1
done
kill -9 "$pid" 2> /dev/null
wait "$pid" 2> /dev/null
echo TIMEOUT
