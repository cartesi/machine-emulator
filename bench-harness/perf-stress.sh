#!/bin/sh
# Profile a bench-stress workload (or bench-insns filter) with perf.
#
# Usage:
#   ./perf-stress.sh stat <bench-name>     # perf stat counters (IPC, branch/cache misses)
#   ./perf-stress.sh record <bench-name>   # perf record; then: perf report -i perf.data
#   ./perf-stress.sh stat-insns <pattern>  # perf stat on bench-insns.lua --filter <pattern>
#
# Runs pinned to CPU core $PIN (default 2, a P-core on hybrid Intel CPUs).
# Note: counters include Linux guest boot (~20% of executed cycles) and Lua host overhead.

PIN="${PIN:-2}"
MODE="$1"
NAME="$2"

EVENTS="cycles,instructions,branches,branch-misses,L1-dcache-loads,L1-dcache-load-misses,LLC-loads,LLC-load-misses,L1-icache-load-misses"

case "$MODE" in
stat)
    exec taskset -c "$PIN" perf stat -e "$EVENTS" lua5.4 bench-stress.lua "$NAME"
    ;;
record)
    exec taskset -c "$PIN" perf record -F 2000 -o perf.data lua5.4 bench-stress.lua "$NAME"
    ;;
stat-insns)
    exec taskset -c "$PIN" perf stat -e "$EVENTS" lua5.4 bench-insns.lua --filter "$NAME"
    ;;
*)
    echo "usage: $0 stat|record|stat-insns <bench-name-or-pattern>" >&2
    exit 1
    ;;
esac
