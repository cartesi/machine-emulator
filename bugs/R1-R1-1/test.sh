#!/bin/bash
# R1-R1-1: is the uarch program (uarch-ram.bin, hence the pristine uarch state hash fixed on-chain) reproducibly
# buildable from the audited source, also when the toolchain packages that the Dockerfile leaves unpinned
# drift with the Debian archive?
#
# R13: "The uarch program, its pristine hash, and the verifier code that a deployment fixes on-chain must be
# reproducibly buildable from audited source."
#
# Builds the uarch from `git archive HEAD` in ephemeral containers of cartesi/machine-emulator:toolchain (the
# Dockerfile's `toolchain` stage, built by bugs/harness/docker/build-images.sh), once as is (control) and once
# per alternate build of an unpinned package (alternates.txt), and asserts that every build yields the
# emulator's cartesi.UARCH_PRISTINE_STATE_HASH (and the regenerated EmulatorConstants.sol constant, when the
# harness has it) and the in-tree uarch-ram.bin bytes.
# Exit 0: every build reproduces the hash. 1: some build gives another hash. 2: setup error.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$HERE/../.." && pwd)}"
IMAGE=cartesi/machine-emulator:toolchain
setup_error() { echo "SETUP ERROR: $*" >&2; exit 2; }

command -v docker > /dev/null || setup_error "docker not found"
docker image inspect "$IMAGE" > /dev/null 2>&1 || setup_error "$IMAGE missing (bugs/harness/docker/build-images.sh toolchain)"

T=$(mktemp -d "${TMPDIR:-/tmp}/r1-r1-1.XXXXXX") || setup_error "mktemp"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/src" "$T/alt" "$T/out"

git -C "$REPO" archive HEAD src uarch third-party tools Makefile | tar -x -C "$T/src" || setup_error "git archive"

# expected values: what the emulator (and the regenerated step) carry
expected=$(lua5.4 -e 'local c = require("cartesi"); io.write(c.tohex(c.UARCH_PRISTINE_STATE_HASH))') ||
    setup_error "cannot load the cartesi Lua module"
SOL="${HARNESS_WORK:-$REPO/bugs/harness/work}/solidity-step/regenerated/src/EmulatorConstants.sol"
sol=""
[ -f "$SOL" ] && sol=$(grep -A1 'UARCH_PRISTINE_STATE_HASH' "$SOL" | grep -o '0x[0-9a-fA-F]\{64\}' | head -1 | tr 'A-F' 'a-f')
echo "expected pristine hash (cartesi.UARCH_PRISTINE_STATE_HASH): $expected"
[ -n "$sol" ] && echo "regenerated EmulatorConstants.sol UARCH_PRISTINE_STATE_HASH:   $sol"
intree_bin=""
[ -f "$REPO/uarch/uarch-ram.bin" ] && intree_bin=$(sha256sum "$REPO/uarch/uarch-ram.bin" | cut -c1-64)

# fetch the alternates by content
labels=(control)
debs=("")
while read -r sha1 pkg ver; do
    case "$sha1" in '#'* | '') continue ;; esac
    f="$pkg-$ver.deb"
    curl -sS -L --fail --max-time 300 -o "$T/alt/$f" "https://snapshot.debian.org/file/$sha1" ||
        setup_error "cannot fetch $pkg $ver from snapshot.debian.org"
    [ "$(sha1sum "$T/alt/$f" | cut -c1-40)" = "$sha1" ] || setup_error "sha1 mismatch for $f"
    labels+=("$pkg=$ver")
    debs+=("$f")
done < "$HERE/alternates.txt"

c_hash() { echo "0x$(grep -o '0x[0-9a-f][0-9a-f]' "$1" | tr -d '\n' | sed 's/0x//g')"; }

status=0
for i in "${!labels[@]}"; do
    label=${labels[$i]}
    tag="b$i"
    if ! timeout 1200 docker run --rm --network none --entrypoint bash \
        -e ALT_DEB="${debs[$i]}" -e OUT_UID="$(id -u)" -e OUT_GID="$(id -g)" \
        -v "$T/src:/src:ro" -v "$T/alt:/alt:ro" -v "$T/out:/out" -v "$HERE/in-container.sh:/run.sh:ro" \
        "$IMAGE" /run.sh "$tag"; then
        setup_error "uarch build failed for $label"
    fi
    h=$(c_hash "$T/out/uarch-pristine-hash-$tag.c")
    b=$(sha256sum "$T/out/uarch-ram-$tag.bin" | cut -c1-64)
    ld=$(grep '^ld used' "$T/out/versions-$tag.txt" | sed 's/.*-> //')
    verdict=OK
    [ "$h" = "$expected" ] || verdict=DIFFERS
    [ -z "$sol" ] || [ "$h" = "$sol" ] || verdict=DIFFERS
    [ -z "$intree_bin" ] || [ "$b" = "$intree_bin" ] || verdict=DIFFERS
    [ "$verdict" = OK ] || status=1
    printf '%-56s %s bin %s.. [%s] %s\n' "$label" "$h" "${b:0:12}" "$ld" "$verdict"
    rm -f "$T/out/"*"-$tag."*
done

if [ $status = 0 ]; then
    echo "PASS (R13): every build, including each drift of an unpinned toolchain package, reproduces the pristine uarch hash"
else
    echo "FAIL (R13): a build of the audited source with the Dockerfile's toolchain yields another pristine uarch hash"
fi
exit $status
