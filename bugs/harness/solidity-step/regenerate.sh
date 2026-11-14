#!/bin/bash
# machine-solidity-step v0.17.0-test1, regenerated from the emulator of this branch, built and tested.
#
#   work/solidity-step/released     clone at the tag (commit 6f91eb9b), untouched: the released generated code
#   work/solidity-step/regenerated  copy in which the generate-* targets run against this branch:
#       generate-step, generate-reset, generate-send-cmio-response  read $REPO/src/*.cpp (EMULATOR_DIR shim)
#       generate-constants  runs helper_scripts/generate_EmulatorConstants.lua inside cartesi/machine-emulator:devel,
#                           the emulator image built from this branch's Dockerfile (docker/build-images.sh emulator);
#                           the project's own `make build-emulator-image` call is satisfied by the shim, because the
#                           image is built by the harness (same Dockerfile + proxy CA, see docker/build-images.sh)
#       generate-prod/mock  gpp over templates (AccessLogs.sol)
#       generate-replay     replay tests from uarch step logs REGENERATED from this branch:
#                           test/uarch-bin  = tests/uarch built with the pinned toolchain (make -C tests uarch in
#                                             cartesi/machine-emulator:toolchain) instead of the v0.23.0-test2 deb
#                           test/uarch-log  = tests/lua/uarch-riscv-tests.lua json-step-logs (+ reset and
#                                             send-cmio-response logs) run with the in-tree emulator
#   then forge build and the project's test-mock, test-replay, test-prod targets (solc 0.8.30, forge v1.5.1).
#
# Outputs in work/solidity-step/: diff-summary.txt (released vs regenerated generated code), diff.patch,
# build-status.txt, test-*.log, results.txt, failures.txt; step -> the variant that builds (regenerated, or
# regenerated-patched when the pure regeneration does not compile, see patches/).
# Exit 0 if the pure regeneration builds and all three test targets pass; 1 if the pure regeneration does not
# build or a test target fails; 2 on harness errors (fetch, docker, generation).
# Options: --force (start again from a fresh copy), --no-tests.
set -uo pipefail
. "$(dirname "$0")/../lib/common.sh"
. "$REPO/bugs/env.sh"
R="$WORK/solidity-step"
mkdir -p "$R"
FORCE=no
TESTS=yes
for a in "$@"; do
    case "$a" in
    --force) FORCE=yes ;;
    --no-tests) TESTS=no ;;
    esac
done
export DIE_STATUS=2

command -v gpp > /dev/null || die "gpp not installed (apt-get install gpp)"
"$HARNESS/solidity-step/install-tools.sh" > /dev/null || die "foundry install failed"
ensure_docker || die "docker unavailable"

# 1. sources
clone_at_tag "$MSS_REPO" "$MSS_TAG" "$MSS_COMMIT" "$R/released" || die "clone failed"
(cd "$R/released" && git submodule update --init --depth 1 lib/forge-std > /dev/null 2>&1) || die "forge-std submodule"
if [ "$FORCE" = yes ] || [ ! -d "$R/regenerated" ]; then
    rm -rf "$R/regenerated"
    cp -a "$R/released" "$R/regenerated"
fi

# 2. emulator image from this branch (for generate-constants)
"$HARNESS/docker/build-images.sh" emulator || die "emulator image build failed"
docker run --rm cartesi/machine-emulator:devel cartesi-machine --version > "$R/emulator-image-version.txt" 2>&1 || true

# 3. EMULATOR_DIR shim: src -> this branch, build-emulator-image -> already built
SHIM="$R/emulator-shim"
mkdir -p "$SHIM"
ln -sfn "$REPO/src" "$SHIM/src"
printf 'build-emulator-image:\n\t@docker image inspect cartesi/machine-emulator:devel > /dev/null\n' > "$SHIM/Makefile"

cd "$R/regenerated" || die "no regenerated dir"
make generate-step generate-reset generate-send-cmio-response generate-constants EMULATOR_DIR="$SHIM" \
    > "$R/generate.log" 2>&1 || {
    tail -20 "$R/generate.log" >&2
    die "generation failed (log: $R/generate.log)"
}

# cross-check: the constants generated with the in-tree Lua module must equal the image's
lua5.4 helper_scripts/generate_EmulatorConstants.lua > "$R/constants-intree.txt" 2>&1 || die "in-tree constants"
sed -n '/START OF AUTO-GENERATED CODE/,/END OF AUTO-GENERATED CODE/p' src/EmulatorConstants.sol |
    grep 'constant' > "$R/constants-image.txt"
if ! diff <(grep constant "$R/constants-intree.txt") "$R/constants-image.txt" > "$R/constants-image-vs-intree.diff"; then
    log "WARNING: constants from the emulator image differ from the in-tree build (see constants-image-vs-intree.diff)"
fi

# 4. replay test data regenerated from this branch
if [ ! -f "$REPO/third-party/riscv-tests/isa/rv64ui/add.S" ]; then
    git -C "$REPO" submodule init third-party/riscv-tests > /dev/null
    # the relative submodule URL resolves against the fork remote; the commit lives in cartesi/riscv-tests
    git -C "$REPO" config submodule.tests/riscv-tests.url https://github.com/cartesi/riscv-tests.git
    git -C "$REPO" submodule update --depth 1 third-party/riscv-tests > /dev/null 2>&1 || die "riscv-tests submodule"
fi
docker run --rm --entrypoint bash -v "$REPO:/opt/cartesi/machine-emulator" -w /opt/cartesi/machine-emulator \
    cartesi/machine-emulator:toolchain -c 'make -C tests uarch' > "$R/tests-uarch-build.log" 2>&1 ||
    die "tests/uarch build failed (log: $R/tests-uarch-build.log)"
LOGS="$R/uarch-logs"
rm -rf "$LOGS"
mkdir -p "$LOGS"
(cd "$REPO/tests" && CARTESI_TESTS_UARCH_PATH="$REPO/tests/build/uarch" lua5.4 ./lua/uarch-riscv-tests.lua \
    --output-dir="$LOGS" --create-reset-uarch-log --create-send-cmio-response-log --jobs="$(nproc)" json-step-logs) \
    > "$R/uarch-logs.log" 2>&1 || die "uarch log generation failed (log: $R/uarch-logs.log)"
rm -rf test/uarch-bin test/uarch-log
mkdir -p test/uarch-bin test/uarch-log
(cd "$REPO/tests/build/uarch" && find . -maxdepth 1 -type f ! -name '*.dump' ! -name '*.elf' -exec cp {} "$R/regenerated/test/uarch-bin/" \;)
cp "$LOGS"/*.json test/uarch-log/

# 5. released data, for the comparison only (sha256 pinned by the project's shasum-download)
RD="$R/released-data"
mkdir -p "$RD"
for f in machine-emulator-tests-data.deb uarch-riscv-tests-json-logs.tar.gz; do
    want=$(grep " downloads/$f\$" "$R/released/shasum-download" | cut -c1-64)
    if [ ! -f "$RD/$f" ] || ! verify_sha256 "$RD/$f" "$want" 2> /dev/null; then
        curl -sSfL -o "$RD/$f" "https://github.com/cartesi/machine-emulator/releases/download/v0.23.0-test2/$f" &&
            verify_sha256 "$RD/$f" "$want" || log "WARNING: cannot fetch released $f (comparison skipped)"
    fi
done
if [ -f "$RD/uarch-riscv-tests-json-logs.tar.gz" ] && [ ! -d "$RD/logs" ]; then
    mkdir -p "$RD/logs" && tar --no-same-owner -xzf "$RD/uarch-riscv-tests-json-logs.tar.gz" --strip-components=1 -C "$RD/logs"
fi

# 6. generate-prod + replay, build. If the pure regeneration does not compile, a separately labelled variant
# regenerated-patched gets the minimal harness workaround (patches/README), so that the EVM harness and Dave can
# still be built; results.txt says which variant was built and tested.
make generate-prod generate-replay > "$R/generate2.log" 2>&1 || die "generate-prod/replay failed (log: $R/generate2.log)"
# fixed-point check: the project's `build` order runs generate-step before generate-constants; regenerate in the
# other order and check nothing changes
cp src/UArchStep.sol src/UArchReset.sol src/SendCmioResponse.sol "$R/" 2>/dev/null
make generate-step generate-reset generate-send-cmio-response EMULATOR_DIR="$SHIM" > /dev/null 2>&1
make fmt > /dev/null 2>&1
for f in UArchStep UArchReset SendCmioResponse; do
    cmp -s "$R/$f.sol" "src/$f.sol" || log "WARNING: src/$f.sol changes when regenerated after generate-constants"
    rm -f "$R/$f.sol"
done
VARIANT=regenerated
if forge build --use 0.8.30 > "$R/build.log" 2>&1; then
    echo "pure regeneration: forge build OK" > "$R/build-status.txt"
else
    {
        echo "pure regeneration: forge build FAILED:"
        grep -A6 -E '^Error' "$R/build.log" | head -40 | sed 's/^/    /'
    } > "$R/build-status.txt"
    log "pure regeneration does not compile (see $R/build-status.txt); building the patched variant"
    rm -rf "$R/regenerated-patched"
    cp -a "$R/regenerated" "$R/regenerated-patched"
    cd "$R/regenerated-patched" || die "no patched dir"
    for pf in "$HARNESS"/solidity-step/patches/*.sh; do
        bash "$pf" "$REPO" >> "$R/build-status.txt" 2>&1 || die "workaround $pf failed"
    done
    make generate-constants generate-step generate-reset generate-send-cmio-response generate-prod generate-replay \
        EMULATOR_DIR="$SHIM" > "$R/generate-patched.log" 2>&1 || die "patched generation failed"
    if forge build --use 0.8.30 > "$R/build-patched.log" 2>&1; then
        echo "patched variant (regenerated-patched): forge build OK" >> "$R/build-status.txt"
        VARIANT=regenerated-patched
    else
        echo "patched variant: forge build FAILED (log: build-patched.log)" >> "$R/build-status.txt"
        VARIANT=none
    fi
    cd "$R/regenerated" || die "no regenerated dir"
fi
echo "variant built and tested: $VARIANT" >> "$R/build-status.txt"
ln -sfn "$VARIANT" "$R/step"
cat "$R/build-status.txt"

# 7. diff summary (generated code: src/*.sol; generated replay tests: names only)
{
    echo "machine-solidity-step $MSS_TAG ($MSS_COMMIT): released generated files vs regenerated from"
    echo "machine-emulator $(git -C "$REPO" rev-parse --abbrev-ref HEAD) $(git -C "$REPO" rev-parse HEAD)"
    echo
    echo "== src/ (diff --stat)"
    git -C "$R/regenerated" diff --stat -- src | sed 's/^/  /'
    echo
    echo "== changed EmulatorConstants (released -> regenerated)"
    consts() { tr '\n' ' ' < "$1" | tr -s ' ' | grep -o 'constant [A-Za-z0-9_]* = [^;]*'; }
    cdiff=$(diff <(consts "$R/released/src/EmulatorConstants.sol") <(consts src/EmulatorConstants.sol) | grep '^[<>]' || true)
    echo "${cdiff:-(none)}" | sed 's/^/  /'
    echo
    echo "== replay tests: released logs vs regenerated logs"
    if [ -d "$RD/logs" ]; then
        echo "  only in released : $(comm -23 <(ls "$RD/logs" | sort) <(ls "$LOGS" | sort) | tr '\n' ' ')"
        echo "  only regenerated : $(comm -13 <(ls "$RD/logs" | sort) <(ls "$LOGS" | sort) | tr '\n' ' ')"
        same=0 differ=0
        for f in $(comm -12 <(ls "$RD/logs" | sort) <(ls "$LOGS" | sort)); do
            if cmp -s "$RD/logs/$f" "$LOGS/$f"; then same=$((same + 1)); else differ=$((differ + 1)); fi
        done
        echo "  common logs: $same byte-identical, $differ different"
    else
        echo "  (released logs not available)"
    fi
    echo
    echo "== test/uarch-bin: released deb vs regenerated"
    if [ -f "$RD/machine-emulator-tests-data.deb" ]; then
        rm -rf "$RD/uarch-bin" && mkdir -p "$RD/uarch-bin"
        ar p "$RD/machine-emulator-tests-data.deb" data.tar.xz | tar -xJf - --strip-components=7 -C "$RD/uarch-bin" \
            ./usr/share/cartesi-machine/tests/data/uarch && rm -f "$RD/uarch-bin"/*.dump "$RD/uarch-bin"/*.elf
        same="" differ="" onlyrel="" onlyregen=""
        for f in $(ls "$RD/uarch-bin"); do
            if [ ! -e "test/uarch-bin/$f" ]; then onlyrel+=" $f"
            elif cmp -s "$RD/uarch-bin/$f" "test/uarch-bin/$f"; then same+=" $f"
            else differ+=" $f"; fi
        done
        for f in $(ls test/uarch-bin); do [ -e "$RD/uarch-bin/$f" ] || onlyregen+=" $f"; done
        echo "  identical ($(wc -w <<< "$same")):$same"
        echo "  different ($(wc -w <<< "$differ")):$differ"
        echo "  only in released ($(wc -w <<< "$onlyrel")):$onlyrel"
        echo "  only regenerated ($(wc -w <<< "$onlyregen")):$onlyregen"
    fi
} > "$R/diff-summary.txt"
git -C "$R/regenerated" diff -- src > "$R/diff.patch"
cat "$R/diff-summary.txt"

[ "$VARIANT" != none ] || exit 1
[ "$TESTS" = yes ] || exit 0

# 8. the project's own tests, on the variant that builds
cd "$R/$VARIANT" || die "no $VARIANT"
status=0
echo "tests run on: $VARIANT" > "$R/results.txt"
for t in test-mock test-replay test-prod; do
    make "$t" > "$R/$t.log" 2>&1
    rc=$?
    summary=$(grep -E 'Ran [0-9]+ test suites?' "$R/$t.log" | tail -1)
    echo "$t: exit $rc; $summary" | tee -a "$R/results.txt"
    [ $rc = 0 ] || status=1
done
grep -h -E '^\[FAIL' "$R"/test-*.log | head -80 > "$R/failures.txt" || true
# leave the prod AccessLogs in place for the EVM harness
make generate-prod > /dev/null 2>&1
[ "$VARIANT" = regenerated ] || status=1
exit $status
