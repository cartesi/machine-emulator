#!/bin/bash
# R1-R13-1: the referee verifier (machine-solidity-step v0.17.0-test1, regenerated from this branch with its own
# generate-* targets, no hand edits) must build from audited source (THREAT_MODEL.md R13).
#
# Steps (all in a temporary directory, nothing in the shared harness is modified):
#   1. copy the pinned, untouched machine-solidity-step checkout (bugs/harness/work/solidity-step/released,
#      or $MSS_DIR) to a temp dir;
#   2. run the project's `make generate-step generate-reset generate-send-cmio-response generate-constants
#      generate-prod` with EMULATOR_DIR pointing at this repository's src/. generate-constants normally runs
#      helper_scripts/generate_EmulatorConstants.lua inside the emulator docker image built from this branch;
#      here a `docker` shim runs the same script with the in-tree Lua module (the harness cross-checked that
#      both give identical constants: work/solidity-step/constants-image-vs-intree.diff);
#   3. forge build (solc 0.8.30), as the project's `make build` does;
#   4. the hand-written TLB constants of the constants template that UArchStep.sol relies on must equal the
#      emulator's (cartesi.TLB_NUM_SETS / TLB_SET_SIZE / SHADOW_TLB_SLOT_SIZE) when they are defined.
# Exit 0: the verifier builds from audited source and its TLB constants agree; 1: it does not; 2: setup error.
set -uo pipefail

: "${REPO:?run through bugs/run.sh}"
MSS_DIR="${MSS_DIR:-$HARNESS_WORK/solidity-step/released}"
SOLC_VERSION="${SOLC_VERSION:-0.8.30}"

setup_error() {
    echo "SETUP ERROR: $*" >&2
    exit 2
}

[ -f "$MSS_DIR/Makefile" ] && [ -f "$MSS_DIR/templates/EmulatorConstants.sol.template" ] ||
    setup_error "pinned machine-solidity-step checkout not found at $MSS_DIR (bugs/harness/solidity-step/regenerate.sh)"
[ -f "$MSS_DIR/lib/forge-std/src/Test.sol" ] || setup_error "forge-std submodule missing in $MSS_DIR"
command -v forge > /dev/null || setup_error "forge not found (bugs/harness/solidity-step/install-tools.sh)"
command -v gpp > /dev/null || setup_error "gpp not installed"
lua5.4 -e 'require("cartesi")' 2> /dev/null || setup_error "in-tree cartesi Lua module not loadable"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/r1-r13-1.XXXXXX")" || setup_error "mktemp"
trap 'rm -rf "$TMP"' EXIT

# 1. pristine copy of the pinned generator (sources, templates, helper scripts, forge-std; no git metadata)
W="$TMP/mss"
mkdir -p "$W"
(cd "$MSS_DIR" && tar --exclude=./.git --exclude=./foundry_artifacts --exclude=./cache --exclude=./out \
    --exclude=./downloads --exclude=./test/uarch-bin --exclude=./test/uarch-log -cf - .) | (cd "$W" && tar -xf -) ||
    setup_error "copy of $MSS_DIR failed"
rm -f "$W"/test/UArchReplay_*.t.sol

# 2. EMULATOR_DIR shim (src -> this branch) and docker shim for generate-constants
SHIM="$TMP/emulator"
mkdir -p "$SHIM" "$TMP/bin"
ln -s "$REPO/src" "$SHIM/src"
printf 'build-emulator-image:\n\t@true\n' > "$SHIM/Makefile"
cat > "$TMP/bin/docker" << 'EOF'
#!/bin/bash
# test shim: `docker run ... cartesi/machine-emulator:devel <lua script>` -> run the script with the in-tree module
[ "$1" = run ] || { echo "docker shim: unsupported: $*" >&2; exit 2; }
script="${*: -1}"
exec lua5.4 "./helper_scripts/$(basename "$script")"
EOF
chmod +x "$TMP/bin/docker"

cd "$W" || setup_error "cd $W"
# generate-constants first: generate_UArchStep.sh qualifies the identifiers it finds in src/EmulatorConstants.sol,
# so running it after the constants are regenerated gives the fixed point of the project's `make build` order
# (generate-step, ..., generate-constants), as the harness's regenerate.sh also checks.
if ! PATH="$TMP/bin:$PATH" make generate-constants generate-step generate-reset generate-send-cmio-response \
    generate-prod EMULATOR_DIR="$SHIM" > "$TMP/generate.log" 2>&1; then
    tail -20 "$TMP/generate.log" >&2
    setup_error "generation failed"
fi
grep -q 'CM_MARCHID' src/EmulatorConstants.sol || setup_error "constants were not generated"

echo "== regenerated UArchStep.sol: TLB bound check (generated from src/uarch-step.cpp)"
grep -n -E 'set_index >= ' src/UArchStep.sol | sed 's/^/   /'

status=0

# 3. build the generated verifier sources
echo "== forge build --use $SOLC_VERSION (the project's build: src/ and the test/ contracts that import it)"
if forge build --offline --use "$SOLC_VERSION" > "$TMP/build.log" 2>&1; then
    echo "   build OK"
else
    if grep -q -E 'Error( \([0-9]+\))?:' "$TMP/build.log"; then
        grep -A6 -E '^Error' "$TMP/build.log" | head -20 | sed 's/^/   /'
        echo "FAIL (R13): the verifier regenerated from audited source with the pinned generator does not build"
        status=1
    else
        tail -20 "$TMP/build.log" >&2
        setup_error "forge build failed for a reason other than a compiler error"
    fi
fi

# 4. TLB constants used by the generated UArchStep.sol must match the emulator
echo "== TLB constants of EmulatorConstants.sol vs the emulator"
check_const() { # name solidity_name lua_expr
    local want got
    want=$(lua5.4 -e "io.write(tostring(require('cartesi').$2))")
    got=$(grep -o -E "constant $1 = [0-9]+" src/EmulatorConstants.sol | grep -o -E '[0-9]+$')
    if [ -z "$got" ]; then
        echo "   $1: not defined in EmulatorConstants.sol (emulator: $want)"
        if grep -q -E "[^A-Za-z_.]$1([^A-Za-z_]|$)" src/UArchStep.sol; then
            echo "FAIL (R13): UArchStep.sol uses $1, which EmulatorConstants.sol does not define"
            status=1
        fi
    elif [ "$got" != "$want" ]; then
        echo "FAIL (R13/A6): $1 = $got in EmulatorConstants.sol, emulator has $want"
        status=1
    else
        echo "   $1 = $got (emulator: $want) OK"
    fi
}
check_const TLB_NUM_SETS TLB_NUM_SETS
check_const TLB_SET_SIZE TLB_SET_SIZE
check_const TLB_SLOT_LENGTH SHADOW_TLB_SLOT_SIZE

if [ $status = 0 ]; then
    echo "PASS: the verifier regenerated from audited source builds and its TLB constants match the emulator"
fi
exit $status
