#!/bin/bash
# Runs a PRT player and relaunches it whenever it exits, recording its process id in the first
# argument's file. Stopping the supervisor stops the player.
# Usage: prt-supervise.sh PID_FILE COMMAND [ARGUMENT...]
set -u
# Each run of the player leads a process group of its own, which the machine servers it spawns
# join. The group is ended with the player, so no server outlives it.
set -m
pid_file=${1:?missing pid file}
shift
child=
trap '[ -z "$child" ] || kill -TERM -- "-$child" 2> /dev/null; exit 0' TERM INT
while :; do
    "$@" &
    child=$!
    echo "$child" > "$pid_file"
    wait "$child" || echo "Player exited with status $?; relaunching." >&2
    kill -KILL -- "-$child" 2> /dev/null
    sleep 1
done
