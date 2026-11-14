#!/bin/bash
# R3-VARGEN-1: the emulator build links stale generated uarch files.
#
# Requirement (THREAT_MODEL.md, R13): "The uarch program, its pristine hash, and the verifier code that a
# deployment fixes on-chain must be reproducibly buildable from audited source." (also A6, R2)
#
# The test copies the tracked sources (src, uarch, tools, Makefile) of this working tree into a temp dir and plants
# generated uarch files (uarch/uarch-pristine-ram.c, uarch/uarch-pristine-hash.c, untracked, as any earlier build
# leaves them) dated 2020-01-01, i.e. older than every source of the uarch program (src/interpret.cpp, ...).
# It then asks the emulator's own build what it would do (make -n -C src libcartesi.a):
#   required: rebuild the uarch from the current sources, or refuse to build
#   bug:      compile the stale files into libcartesi.a next to a freshly compiled native interpreter
# A control run without the generated files checks that the detector recognizes a uarch build in the plan.
# When the bug shows, the two stale objects are really compiled (cheap) and linked into a tiny probe that prints
# the embedded pristine hash, to show that the planted (stale) hash is what the library would carry.
#
# Exit: 0 required behavior, 1 bug present, 2 setup error. Needs only git, make, gcc, tar (no docker, no network).
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/r3-vargen-1.XXXXXX")" || exit 2
trap 'rm -rf "$TMP"' EXIT

setup_error() { echo "SETUP ERROR: $*" >&2; exit 2; }

for t in git make gcc tar; do command -v "$t" >/dev/null || setup_error "missing $t"; done

# Copy of the tracked files only (the working tree's version, so an uncommitted fix is tested too).
copy_tree() {
    mkdir -p "$1" || return 1
    (cd "$REPO" && git ls-files -z src uarch tools Makefile | tar --null -T - -cf -) | tar -xf - -C "$1"
}

# A uarch build appears in a make plan as a recursive make of the uarch, or as the uarch's own build products.
UARCH_BUILD_RE='make( [^ ]+)* -C \.\.( [^ ]+)* uarch|uarch-with-toolchain|make uarch|uarch-ram\.(elf|bin)|compute-uarch-pristine-hash'

# ---- control: a tree without generated files must plan the uarch build -------------------------------------------
CTRL="$TMP/control"
copy_tree "$CTRL" || setup_error "cannot copy tracked sources"
[ -f "$CTRL/src/interpret.cpp" ] && [ -f "$CTRL/uarch/Makefile" ] || setup_error "copy lacks src/interpret.cpp or uarch/Makefile"
[ ! -e "$CTRL/uarch/uarch-pristine-hash.c" ] || setup_error "uarch-pristine-hash.c is tracked?"
(cd "$CTRL" && make -n -C src libcartesi.a >"$TMP/control-plan.txt" 2>&1) ||
    setup_error "control: make -n -C src libcartesi.a failed: $(tail -5 "$TMP/control-plan.txt")"
grep -Eq "$UARCH_BUILD_RE" "$TMP/control-plan.txt" ||
    setup_error "control: no uarch build detected in the plan of a tree without generated files"
echo "control: tree without generated uarch files -> the plan builds the uarch:"
grep -E "$UARCH_BUILD_RE" "$TMP/control-plan.txt" | head -3 | sed 's/^/    /'

# ---- stale: same tree, plus generated files older than the uarch sources -----------------------------------------
STALE="$TMP/stale"
copy_tree "$STALE" || setup_error "cannot copy tracked sources"
STALE_HASH_HEX="$(printf '5a%.0s' $(seq 32))"
{
    echo '// This file is auto-generated and should not be modified'
    echo '// R3-VARGEN-1: STALE uarch pristine hash, left by an earlier build'
    echo 'const unsigned char uarch_pristine_hash[] = {'
    printf '  0x5a,%.0s' $(seq 32)
    echo
    echo '};'
    echo 'const unsigned int uarch_pristine_hash_len = 32;'
} >"$STALE/uarch/uarch-pristine-hash.c"
{
    echo '// This file is auto-generated and should not be modified'
    echo '// R3-VARGEN-1: STALE uarch image, left by an earlier build'
    echo '#include <stddef.h>'
    echo 'unsigned char uarch_pristine_ram[] = { 0x5a, 0x5a, 0x5a, 0x5a };'
    echo 'unsigned int uarch_pristine_ram_len = 4;'
} >"$STALE/uarch/uarch-pristine-ram.c"
touch -d 2020-01-01 "$STALE/uarch/uarch-pristine-hash.c" "$STALE/uarch/uarch-pristine-ram.c" || setup_error "touch"
[ "$STALE/src/interpret.cpp" -nt "$STALE/uarch/uarch-pristine-hash.c" ] || setup_error "sources not newer than planted files"

(cd "$STALE" && make -n -C src libcartesi.a >"$TMP/stale-plan.txt" 2>&1)
stale_status=$?

if [ "$stale_status" -ne 0 ]; then
    echo "stale: the build refuses (make -n exit $stale_status):"
    tail -5 "$TMP/stale-plan.txt" | sed 's/^/    /'
    echo "PASS: generated uarch files older than their sources are not silently linked"
    exit 0
fi
if grep -Eq "$UARCH_BUILD_RE" "$TMP/stale-plan.txt"; then
    echo "stale: the plan rebuilds the uarch from the current sources:"
    grep -E "$UARCH_BUILD_RE" "$TMP/stale-plan.txt" | head -3 | sed 's/^/    /'
    echo "PASS: generated uarch files older than their sources are not silently linked"
    exit 0
fi

# Bug: describe what the plan does.
echo "stale: generated uarch files dated 2020-01-01, src/interpret.cpp dated $(date -r "$STALE/src/interpret.cpp" +%F)"
echo "stale: the plan of 'make -C src libcartesi.a' never builds the uarch; it does:"
grep -E -- '-c -o (interpret|uarch-pristine-hash|uarch-pristine-ram)\.o ' "$TMP/stale-plan.txt" |
    sed -E 's/^.* -c -o ([^ ]+) ([^ ]+)$/    compile \2 -> \1/'
grep -E '^ar ' "$TMP/stale-plan.txt" | grep -q 'uarch-pristine-hash.o' && grep -E '^ar ' "$TMP/stale-plan.txt" | grep -q 'uarch-pristine-ram.o' &&
    echo "    archive both stale uarch-pristine objects into libcartesi.a with the new interpret.o"

# Really compile the two stale objects with the emulator's Makefile, and read back the embedded pristine hash.
if (cd "$STALE" && make -C src uarch-pristine-hash.o uarch-pristine-ram.o >"$TMP/stale-build.txt" 2>&1); then
    cat >"$TMP/probe.c" <<'EOF'
#include <stdio.h>
extern const unsigned char uarch_pristine_hash[];
extern const unsigned int uarch_pristine_hash_len;
extern unsigned int uarch_pristine_ram_len;
int main(void) {
    for (unsigned i = 0; i < uarch_pristine_hash_len; i++) printf("%02x", uarch_pristine_hash[i]);
    printf(" %u\n", uarch_pristine_ram_len);
    return 0;
}
EOF
    if gcc -o "$TMP/probe" "$TMP/probe.c" "$STALE/src/uarch-pristine-hash.o" "$STALE/src/uarch-pristine-ram.o" 2>"$TMP/probe-build.txt"; then
        read -r embedded_hash embedded_len < <("$TMP/probe")
        echo "built objects: embedded uarch pristine hash 0x$embedded_hash, uarch image length $embedded_len bytes"
        [ "$embedded_hash" = "$STALE_HASH_HEX" ] && echo "    = the planted stale hash, not one built from the current uarch sources"
    else
        echo "(could not link the probe: $(head -2 "$TMP/probe-build.txt"))"
    fi
else
    echo "(could not compile the stale objects: $(tail -2 "$TMP/stale-build.txt"))"
fi

echo "FAIL (R13): the build embeds a uarch program and pristine hash that are not built from the audited sources"
echo "            it compiles; it neither rebuilds them nor refuses (src/Makefile generate-uarch-pristine)"
exit 1
