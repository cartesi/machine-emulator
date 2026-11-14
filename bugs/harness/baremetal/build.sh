#!/bin/bash
# Bare-metal guest builder: C and/or assembly sources -> raw binary that the emulator boots without Linux
# (ram image at 0x80000000, entry = first byte).
#
#   build.sh                         build every examples/* into bugs/harness/work/baremetal/<name>.bin (+ .elf, .dump)
#   build.sh -o out.bin a.c b.S ...  build one binary from the given sources
#
# Sources are compiled with -march=rv64imac_zicsr_zifencei -mabi=lp64 -O2, freestanding, with include paths
# baremetal/include and the emulator's src/ (so htif-defines.h, address-range-defines.h, pmas-defines.h are
# the audited ones). Unless a source defines _start itself, lib/crt0.S and lib/runtime.c are linked in
# (cm-baremetal.h API: HTIF halt/putchar/yield, cmio rx/tx buffers, keccak256, outputs Merkle tree, rollup
# accept/reject/emit output/report/exception).
#
# Compiler: the pinned riscv64-unknown-elf-gcc of the toolchain image cartesi/machine-emulator:toolchain (this
# repository's Dockerfile, docker/build-images.sh), run with docker. Set BAREMETAL_CC=host to use a host
# riscv64-unknown-elf-gcc instead (e.g. Ubuntu's gcc-riscv64-unknown-elf) when docker is unavailable.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../lib/common.sh"

OUT=""
SRCS=()
while [ $# -gt 0 ]; do
    case "$1" in
    -o)
        OUT=$2
        shift 2
        ;;
    *)
        SRCS+=("$1")
        shift
        ;;
    esac
done

CFLAGS="-march=rv64imac_zicsr_zifencei -mabi=lp64 -mcmodel=medany -static -O2 -g -ffreestanding -fno-builtin \
-fno-tree-loop-distribute-patterns -nostdlib -nostartfiles -Wall -Wextra -I/bm/include -I/repo/src"

# Run a shell snippet with the riscv toolchain; /bm = baremetal dir, /repo = repository, /out = output dir,
# /srcs = cwd of the caller (for relative source paths).
run_tc() { # run_tc <outdir> <script>
    local outdir=$1 script=$2
    if [ "${BAREMETAL_CC:-docker}" = host ]; then
        command -v riscv64-unknown-elf-gcc > /dev/null || DIE_STATUS=2 die "no host riscv64-unknown-elf-gcc"
        local tmp
        tmp=$(mktemp -d)
        ln -s "$HERE" "$tmp/bm"
        ln -s "$REPO" "$tmp/repo"
        ln -s "$outdir" "$tmp/out"
        ln -s "$PWD" "$tmp/srcs"
        (cd "$tmp" && bash -euo pipefail -c "${script//\/bm/$tmp/bm}" 2>&1) || {
            rm -rf "$tmp"
            return 1
        }
        rm -rf "$tmp"
    else
        ensure_docker || DIE_STATUS=2 die "docker unavailable (set BAREMETAL_CC=host to use a host compiler)"
        docker image inspect cartesi/machine-emulator:toolchain > /dev/null 2>&1 ||
            "$HARNESS/docker/build-images.sh" toolchain
        docker run --rm --entrypoint bash -u "$(id -u):$(id -g)" -v "$HERE:/bm:ro" -v "$REPO/src:/repo/src:ro" \
            -v "$outdir:/out" -v "$PWD:/srcs:ro" -w /srcs cartesi/machine-emulator:toolchain \
            -euo pipefail -c "$script"
    fi
}

# compile_script <name> <src...>: emits a script building /out/<name>.{elf,bin,dump}
compile_script() {
    local name=$1
    shift
    local s="" objs="" need_rt=yes i=0 f
    for f in "$@"; do
        if grep -qE '^\s*(\.global|\.globl)\s+_start|^[^/]*\b_start\s*\(' "$f" 2> /dev/null; then need_rt=no; fi
    done
    for f in "$@"; do
        i=$((i + 1))
        s+="riscv64-unknown-elf-gcc $CFLAGS -c -o /tmp/$name.$i.o $(map_path "$f"); "
        objs+=" /tmp/$name.$i.o"
    done
    if [ "$need_rt" = yes ]; then
        s+="riscv64-unknown-elf-gcc $CFLAGS -c -o /tmp/$name.crt0.o /bm/lib/crt0.S; "
        s+="riscv64-unknown-elf-gcc $CFLAGS -c -o /tmp/$name.rt.o /bm/lib/runtime.c; "
        objs="/tmp/$name.crt0.o$objs /tmp/$name.rt.o"
    fi
    s+="riscv64-unknown-elf-gcc $CFLAGS -T/bm/lib/link.ld -Wl,--no-warn-rwx-segments -o /out/$name.elf $objs -lgcc; "
    s+="riscv64-unknown-elf-objcopy -S -O binary /out/$name.elf /out/$name.bin; "
    s+="riscv64-unknown-elf-objdump -d /out/$name.elf > /out/$name.dump; "
    echo "$s"
}

# Map a host source path to the container view.
map_path() {
    local p
    p=$(realpath "$1")
    case "$p" in
    "$HERE"/*) echo "/bm/${p#"$HERE"/}" ;;
    "$PWD"/*) echo "/srcs/${p#"$PWD"/}" ;;
    *) DIE_STATUS=2 die "source $1 must be under $HERE or the current directory" ;;
    esac
}

if [ ${#SRCS[@]} -eq 0 ]; then
    outdir="$WORK/baremetal"
    mkdir -p "$outdir"
    script=""
    for f in "$HERE"/examples/*.c "$HERE"/examples/*.S; do
        [ -e "$f" ] || continue
        name=$(basename "${f%.*}")
        script+=$(compile_script "$name" "$f")
    done
    run_tc "$outdir" "$script"
    ls "$outdir"/*.bin
else
    [ -n "$OUT" ] || DIE_STATUS=2 die "-o out.bin required with sources"
    mkdir -p "$(dirname "$OUT")"
    outdir=$(cd "$(dirname "$OUT")" && pwd)
    name=$(basename "${OUT%.bin}")
    run_tc "$outdir" "$(compile_script "$name" "${SRCS[@]}")"
    echo "$outdir/$name.bin"
fi
