#!/bin/bash
# Out-of-tree ASan+UBSan build of the emulator (libcartesi, the cartesi Lua modules, cartesi-jsonrpc-machine)
# with the src/Makefile's own `sanitize=yes` mode (-O1 -fsanitize=address,undefined -fno-sanitize-recover=all,
# _FORTIFY_SOURCE=3, _GLIBCXX_ASSERTIONS). The tracked sources are copied to bugs/harness/work/sanitizer (the
# in-tree tree is not touched); the generated uarch-pristine-*.c come from the in-tree build (same pristine uarch).
# Use with:  HARNESS_SANITIZE=1 . bugs/env.sh   (or . bugs/harness/sanitizer/env.sh after . bugs/env.sh)
# Re-running rebuilds incrementally after re-copying changed sources (rsync -c).
set -euo pipefail
. "$(dirname "$0")/../lib/common.sh"

S="$WORK/sanitizer"
mkdir -p "$S"
[ -f "$REPO/uarch/uarch-pristine-hash.c" ] || "$HARNESS/emulator/build.sh"

# copy tracked files (minus bugs/, doc/) + the generated uarch pristine files, only when changed
(cd "$REPO" && git ls-files -z --cached | grep -zv -E '^(bugs/|doc/)' |
    while IFS= read -r -d '' f; do [ -f "$f" ] && printf '%s\0' "$f"; done) > "$S/.files"
rsync -a -c --from0 --files-from="$S/.files" "$REPO/" "$S/"
rsync -a -c "$REPO/uarch/uarch-pristine-ram.c" "$REPO/uarch/uarch-pristine-hash.c" "$S/uarch/"

make -C "$S/src" -j"$(nproc)" sanitize=yes > "$S/build.log" 2>&1 || {
    tail -30 "$S/build.log" >&2
    die "sanitizer build failed (log: $S/build.log)"
}
log "sanitizer build ok: $S/src/{libcartesi-*.so,cartesi.so,cartesi/jsonrpc.so,cartesi-jsonrpc-machine}"
