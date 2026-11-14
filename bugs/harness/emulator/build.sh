#!/bin/bash
# In-tree build of the emulator of this branch: `make` at the repository root.
# The root Makefile builds the uarch with `make uarch-with-toolchain`, i.e. in the Docker image
# cartesi/machine-emulator:toolchain, which docker/build-images.sh builds from this repository's Dockerfile
# (pinned riscv64 compilers). Host packages: see setup.sh (host_deps).
# Idempotent (make). Exit 0 on success.
set -euo pipefail
. "$(dirname "$0")/../lib/common.sh"

ensure_docker || DIE_STATUS=2 die "docker daemon not available (needed for the uarch toolchain)"
"$HARNESS/docker/build-images.sh" toolchain
make -C "$REPO" -j"$(nproc)" > "$WORK/make-intree.log" 2>&1 || {
    tail -30 "$WORK/make-intree.log" >&2
    die "in-tree make failed (log: $WORK/make-intree.log)"
}
log "in-tree build ok: $(ls "$REPO/src/cartesi.so" "$REPO/src/cartesi-jsonrpc-machine" | tr '\n' ' ')"
# Command names that doc/recipes and the docs use (installed names), pointing at the in-tree scripts.
mkdir -p "$WORK/bin"
ln -sf "$REPO/src/cartesi-machine.lua" "$WORK/bin/cartesi-machine"
ln -sf "$REPO/src/cartesi-machine-stored-hash.lua" "$WORK/bin/cartesi-machine-stored-hash"
ln -sf "$REPO/doc/recipes/cartesi-rollup-data.lua" "$WORK/bin/cartesi-rollup-data.lua"
