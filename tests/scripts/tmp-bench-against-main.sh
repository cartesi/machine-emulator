#!/bin/sh
# TEMPORARY: remove before merge, together with tmp-bench-against-main.lua and its CI job.
# Compares the interpreter of this tree against a base ref on the host it runs on:
#   base    the base ref
#   head    this tree
#   noflag  this tree without the inline-unit-growth interpreter flag
# Reports instructions executed per mcycle (valgrind, exact) and CPU time (best of REPS).
# Run from the root of a tree with submodules, in an environment with the RISC-V toolchain.
set -eu

BASE_URL=${BASE_URL:-https://github.com/cartesi/machine-emulator}
BASE_REF=${BASE_REF:-main}
WORK=${WORK:-/tmp/bench-against-main}
WORKLOADS=${WORKLOADS:-nop regs branch tree qsort memcpy zlib hash syscall double sieve int64 matrixprod}
COUNT_MCYCLES=${COUNT_MCYCLES:-1073741824}
TIME_MCYCLES=${TIME_MCYCLES:-2147483648}
REPS=${REPS:-3}
JOBS=$(nproc)
HEAD=$(pwd)
LUA=tests/scripts/tmp-bench-against-main.lua

mkdir -p "$WORK"
git clone -q --recurse-submodules "$BASE_URL" "$WORK/base"
git -C "$WORK/base" checkout -q --recurse-submodules "$BASE_REF"
echo "base is $(git -C "$WORK/base" rev-parse HEAD)"
cp -a "$HEAD" "$WORK/head"
cp -a "$HEAD" "$WORK/noflag"
sed -i '/inline-unit-growth/d' "$WORK/noflag/src/Makefile"
for v in base head noflag; do
    make -C "$WORK/$v" -j"$JOBS" > "$WORK/$v-build.log" 2>&1 || { tail -50 "$WORK/$v-build.log"; exit 1; }
done
make -C "$WORK/head" build-tests-images > "$WORK/images.log" 2>&1 || { tail -50 "$WORK/images.log"; exit 1; }
IMAGES=$WORK/head/tests/build/images

uname -m; g++ --version | head -1; grep -m1 'model name' /proc/cpuinfo || true

echo
echo "Out-of-line WARL_mstatus call sites in interpret.o"
for v in base head noflag; do
    echo "$v $(objdump -dr "$WORK/$v/src/interpret.o" | grep -c 'WARL_mstatus' || true)"
done

cat > "$WORK/run.sh" <<RUN
#!/bin/sh
# usage: run.sh <count|time> <variant> <workload> <mcycles>
export LUA_CPATH="$WORK/\$2/src/?.so" LD_LIBRARY_PATH="$WORK/\$2/src" BENCH_MCYCLES=\$4
if [ "\$1" = count ]; then
    r=\$(valgrind --tool=cachegrind --cache-sim=no --cachegrind-out-file=/dev/null lua5.4 "$HEAD/$LUA" "$IMAGES" \$3 2>&1 | grep 'I refs' | sed 's/.*: *//; s/,//g')
else
    r=\$(taskset -c 2 lua5.4 "$HEAD/$LUA" "$IMAGES" \$3)
fi
echo "\$2 \$3 \$4 \$r"
RUN
chmod +x "$WORK/run.sh"

for v in base head noflag; do for w in $WORKLOADS; do for n in 0 "$COUNT_MCYCLES"; do
    echo "count $v $w $n"
done; done; done | xargs -P "$JOBS" -L 1 "$WORK/run.sh" > "$WORK/counts.txt"

echo
echo "Instructions per mcycle, and change against base"
awk -v n="$COUNT_MCYCLES" -v wl="$WORKLOADS" '
    { c[$1, $2, $3] = $4 }
    END {
        m = split(wl, W, " ")
        printf "%-11s %9s %9s %9s\n", "workload", "base", "head", "noflag"
        for (i = 1; i <= m; i++) {
            w = W[i]
            b = c["base", w, n] - c["base", w, 0]; h = c["head", w, n] - c["head", w, 0]
            f = c["noflag", w, n] - c["noflag", w, 0]
            B += b; H += h; F += f
            printf "%-11s %9.2f %+8.2f%% %+8.2f%%\n", w, b / n, (h / b - 1) * 100, (f / b - 1) * 100
        }
        printf "%-11s %9.2f %+8.2f%% %+8.2f%%\n", "TOTAL", B / n / m, (H / B - 1) * 100, (F / B - 1) * 100
    }' "$WORK/counts.txt"

: > "$WORK/times.txt"
order="base head noflag"
for rep in $(seq 1 "$REPS"); do
    for w in $WORKLOADS; do
        for v in $order; do "$WORK/run.sh" time "$v" "$w" "$TIME_MCYCLES" >> "$WORK/times.txt"; done
    done
    # shellcheck disable=SC2086
    set -- $order; first=$1; shift; order="$* $first"
done

echo
echo "CPU seconds, best of $REPS, and change against base (shared runner, expect noise)"
awk -v wl="$WORKLOADS" '
    { k = $1 SUBSEP $2; if (!(k in t) || $4 < t[k]) t[k] = $4 }
    END {
        m = split(wl, W, " ")
        printf "%-11s %9s %9s %9s\n", "workload", "base", "head", "noflag"
        for (i = 1; i <= m; i++) {
            w = W[i]; b = t["base", w]; h = t["head", w]; f = t["noflag", w]
            B += b; H += h; F += f
            printf "%-11s %9.3f %+8.2f%% %+8.2f%%\n", w, b, (h / b - 1) * 100, (f / b - 1) * 100
        }
        printf "%-11s %9.3f %+8.2f%% %+8.2f%%\n", "TOTAL", B, (H / B - 1) * 100, (F / B - 1) * 100
    }' "$WORK/times.txt"

echo
echo "raw counts"; cat "$WORK/counts.txt"
echo "raw times"; cat "$WORK/times.txt"
