#!/bin/bash
# Independent rebuild of the uarch program with the toolchain pinned in this repository's Dockerfile
# (stage `toolchain`: gcc-riscv64-unknown-elf=14.2.0+19, g++-14-riscv64-linux-gnu=14.2.0-19cross1 on
# debian:trixie-20250811), in a Docker stage `uarch-rebuild` appended to a generated copy of the Dockerfile
# (docker/build-images.sh). The stage compiles a fresh copy of the tracked sources (no in-tree build output is
# sent: see the generated .dockerignore), runs uarch/Makefile and compute-uarch-pristine-hash.
#
# Then compares three (four) values of the pristine uarch state hash:
#   (r) the rebuilt one (compute-uarch-pristine-hash in the container, and the emulator's own hash-tree node
#       over the rebuilt uarch-ram.bin, node-hash.lua)
#   (a) the in-tree one (uarch/uarch-pristine-hash.c of `make`, = cartesi.UARCH_PRISTINE_STATE_HASH)
#   (b) the regenerated machine-solidity-step constant (EmulatorConstants.sol UARCH_PRISTINE_STATE_HASH in
#       bugs/harness/work/solidity-step/regenerated, if solidity-step/regenerate.sh has run)
# Writes bugs/harness/work/uarch-rebuild/report.txt; exit 0 iff all available values agree, 1 if they differ,
# 2 on harness errors.
set -uo pipefail
. "$(dirname "$0")/../lib/common.sh"
. "$REPO/bugs/env.sh"
OUT="$WORK/uarch-rebuild"
mkdir -p "$OUT"

"$HARNESS/docker/build-images.sh" uarch ${FORCE:+--force} || DIE_STATUS=2 die "uarch-rebuild image build failed"
cid=$(docker create audit-harness/uarch-rebuild:latest) || DIE_STATUS=2 die "docker create failed"
for f in uarch-ram.bin uarch-pristine-hash.c uarch-pristine-ram.c toolchain-versions.txt uarch-ram.elf; do
    docker cp "$cid:/usr/src/emulator/uarch/$f" "$OUT/$f" > /dev/null || {
        docker rm "$cid" > /dev/null
        DIE_STATUS=2 die "cannot copy $f"
    }
done
docker rm "$cid" > /dev/null

c_hash() { # hex of the uarch_pristine_hash array in a uarch-pristine-hash.c
    grep -o '0x[0-9a-f][0-9a-f]' "$1" | tr -d '\n' | sed 's/0x//g'
}
r_c=0x$(c_hash "$OUT/uarch-pristine-hash.c")
r_node=$(lua5.4 "$HARNESS/uarch-rebuild/node-hash.lua" "$OUT/uarch-ram.bin") || DIE_STATUS=2 die "node-hash failed"
a_c=0x$(c_hash "$REPO/uarch/uarch-pristine-hash.c")
a_lua=$(lua5.4 -e 'local c = require("cartesi"); io.write(c.tohex(c.UARCH_PRISTINE_STATE_HASH))')
b_sol=""
SOL="$WORK/solidity-step/regenerated/src/EmulatorConstants.sol"
if [ -f "$SOL" ]; then
    b_sol=$(grep -A1 'UARCH_PRISTINE_STATE_HASH' "$SOL" | grep -o '0x[0-9a-fA-F]\{64\}' | head -1 | tr 'A-F' 'a-f')
fi
bin_rebuilt=$(sha256sum "$OUT/uarch-ram.bin" | cut -c1-64)
bin_intree=$(sha256sum "$REPO/uarch/uarch-ram.bin" | cut -c1-64)

{
    echo "uarch pristine state hash comparison ($(date -u +%FT%TZ), branch $(git -C "$REPO" rev-parse --abbrev-ref HEAD) $(git -C "$REPO" rev-parse --short HEAD))"
    echo "toolchain of the rebuild:"
    sed 's/^/  /' "$OUT/toolchain-versions.txt"
    echo "rebuilt  compute-uarch-pristine-hash : $r_c"
    echo "rebuilt  hash-tree node of its bin   : $r_node"
    echo "in-tree  uarch/uarch-pristine-hash.c  : $a_c"
    echo "in-tree  cartesi.UARCH_PRISTINE_STATE_HASH: $a_lua"
    echo "solidity regenerated EmulatorConstants: ${b_sol:-(not available: run solidity-step/regenerate.sh)}"
    echo "uarch-ram.bin sha256 rebuilt: $bin_rebuilt"
    echo "uarch-ram.bin sha256 in-tree: $bin_intree"
} > "$OUT/report.txt"
cat "$OUT/report.txt"

status=0
for v in "$r_node" "$a_c" "$a_lua" ${b_sol:+"$b_sol"}; do
    [ "$v" = "$r_c" ] || status=1
done
[ "$bin_rebuilt" = "$bin_intree" ] || status=1
if [ $status = 0 ]; then echo "RESULT: all values agree" | tee -a "$OUT/report.txt"; else echo "RESULT: MISMATCH" | tee -a "$OUT/report.txt"; fi
exit $status
