#!/usr/bin/env bash
# Fixed-work comparison across emulator builds, the protocol of bench.lua:
# every workload boots to 256 Mi mcycles untimed, runs exactly 1 Gi further
# timed, and reports the root hash at that exact mcycle. Variants are
# interleaved innermost, so each workload's comparison runs back to back,
# and after all repetitions the root hashes are checked for equality per
# workload across every variant and repetition: any divergence fails the
# run. Timing is only comparable within one invocation on a quiet host on
# AC power; confirm a known anchor before trusting a batch.
#
# usage: compare.sh --images DIR [--repetitions N] [--workloads "w1 w2 ..."]
#                   NAME=PREFIX [NAME=PREFIX ...]
#
# Each PREFIX is an installed emulator prefix (make install PREFIX=...).
# Workload names index the command table in bench.lua; the balanced set is
# the default. One line per run is printed to stdout:
#   NAME repR WORKLOAD ELAPSED MCYCLE ROOT_HASH BREAK_REASON

set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
images_dir=
repetitions=3
workloads="nop regs branch tree qsort memcpy zlib hash syscall double sieve int64 matrixprod"
configs=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --images)
            [[ $# -ge 2 ]] || { echo "missing --images value" >&2; exit 2; }
            images_dir=$2
            shift 2
            ;;
        --repetitions)
            [[ $# -ge 2 ]] || { echo "missing --repetitions value" >&2; exit 2; }
            repetitions=$2
            shift 2
            ;;
        --workloads)
            [[ $# -ge 2 ]] || { echo "missing --workloads value" >&2; exit 2; }
            workloads=$2
            shift 2
            ;;
        --*)
            echo "unknown option: $1" >&2
            exit 2
            ;;
        *)
            configs+=("$1")
            shift
            ;;
    esac
done

if [[ -z $images_dir || ${#configs[@]} -lt 2 || ! $repetitions =~ ^[1-9][0-9]*$ ]]; then
    echo "usage: $0 --images DIR [--repetitions N] [--workloads \"w1 w2 ...\"] NAME=PREFIX NAME=PREFIX..." >&2
    exit 2
fi

for item in "${configs[@]}"; do
    prefix=${item#*=}
    if [[ ! -f $prefix/lib/lua/5.4/cartesi.so ]]; then
        echo "missing Lua binding: $prefix/lib/lua/5.4/cartesi.so" >&2
        exit 2
    fi
done

results=$(mktemp)
trap 'rm -f "$results"' EXIT

for ((rep = 1; rep <= repetitions; rep++)); do
    for workload in $workloads; do
        for item in "${configs[@]}"; do
            name=${item%%=*}
            prefix=${item#*=}
            line=$(LUA_PATH_5_4="$prefix/share/lua/5.4/?.lua;;" \
                LUA_CPATH_5_4="$prefix/lib/lua/5.4/?.so;;" \
                DYLD_LIBRARY_PATH="$prefix/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
                LD_LIBRARY_PATH="$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
                lua5.4 "$script_dir/bench.lua" "$images_dir" "$workload")
            echo "$name rep$rep $line" | tee -a "$results"
        done
    done
done

status=0
for workload in $workloads; do
    hashes=$(awk -v w="$workload" '$3 == w { print $6 }' "$results" | sort -u | wc -l)
    if [[ $hashes -ne 1 ]]; then
        echo "HASH MISMATCH: $workload has $hashes distinct root hashes" >&2
        status=1
    fi
done
if [[ $status -eq 0 ]]; then
    echo "hash gate: all workloads root-hash-identical across variants" >&2
fi
exit $status
