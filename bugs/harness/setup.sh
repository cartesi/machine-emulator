#!/bin/bash
# Rebuild every audit harness from a fresh clone (idempotent: steps whose outputs exist are skipped or are cheap
# re-checks). Run as root in the audit container:  bugs/harness/setup.sh [--force] [--skip-mss-tests]
#   --force           rebuild docker images, the regenerated solidity step and Dave from scratch
#   --skip-mss-tests  do not run machine-solidity-step's own test targets (they take ~7 minutes)
# Prints one line per step and exits non-zero if any step failed (later independent steps still run).
set -uo pipefail
H="$(cd "$(dirname "$0")" && pwd)"
. "$H/lib/common.sh"
FORCE=no
MSS_TESTS=yes
for a in "$@"; do
    case "$a" in
    --force) FORCE=yes ;;
    --skip-mss-tests) MSS_TESTS=no ;;
    *) die "unknown option $a" ;;
    esac
done
F=()
[ "$FORCE" = yes ] && F=(--force)
LOGS="$WORK/setup-logs"
mkdir -p "$LOGS"
failed=()

step() { # step <name> <command...>
    local name=$1
    shift
    local t0=$SECONDS
    if "$@" > "$LOGS/$name.log" 2>&1; then
        printf '[setup] %-22s ok   (%ds)\n' "$name" $((SECONDS - t0))
    else
        printf '[setup] %-22s FAIL (%ds, log %s)\n' "$name" $((SECONDS - t0)) "$LOGS/$name.log"
        tail -5 "$LOGS/$name.log" | sed 's/^/        /'
        failed+=("$name")
    fi
}

host_deps() {
    local pkgs=(build-essential libboost1.83-dev libssl-dev libslirp-dev pkg-config lua5.4 liblua5.4-dev luarocks
        lua-socket lua-posix lua-lpeg lua-dkjson xxd e2tools jq rsync gpp automake autotools-dev libarchive-dev
        git-lfs curl xfsprogs)
    local missing=()
    for p in "${pkgs[@]}"; do dpkg -s "$p" > /dev/null 2>&1 || missing+=("$p"); done
    [ ${#missing[@]} -eq 0 ] && return 0
    [ "$(id -u)" = 0 ] || { echo "missing packages: ${missing[*]} (need root)"; return 1; }
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
}

mss() {
    if [ "$FORCE" = no ] && [ -d "$WORK/solidity-step/step/src" ] && [ -f "$WORK/solidity-step/build-status.txt" ]; then
        echo "regenerated step exists ($(readlink "$WORK/solidity-step/step")); use --force to regenerate"
        return 0
    fi
    local args=("${F[@]}")
    [ "$MSS_TESTS" = no ] && args+=(--no-tests)
    "$H/solidity-step/regenerate.sh" "${args[@]}"
    local rc=$?
    # 1 = the pure regeneration does not build or a test target fails: recorded, not a harness failure
    [ $rc -le 1 ] && [ -d "$WORK/solidity-step/step/src" ]
}

uarch_rebuild() {
    FORCE=${F[0]:-} "$H/uarch-rebuild/rebuild.sh"
    [ $? -le 1 ] # a mismatch is a result, recorded in work/uarch-rebuild/report.txt
}

step host-deps host_deps
step docker ensure_docker
step toolchain-image "$H/docker/build-images.sh" toolchain "${F[@]}"
step emulator "$H/emulator/build.sh"
step images "$H/emulator/fetch-images.sh"
step xgenext2fs "$H/emulator/build-xgenext2fs.sh"
step baremetal "$H/baremetal/build.sh"
step configs "$H/configs/make-configs.sh" "${F[@]}"
step sanitizer "$H/sanitizer/build.sh"
step foundry "$H/solidity-step/install-tools.sh"
step anvil-wrap "$H/anvil-wrap.sh"
step emulator-image "$H/docker/build-images.sh" emulator "${F[@]}"
step solidity-step mss
step uarch-rebuild uarch_rebuild
step evm-step "$H/solidity-step/evm/start.sh"
step dave "$H/chain/build-dave.sh" "${F[@]}"
step prt-fs "$H/chain/reflink-fs.sh"

if [ ${#failed[@]} -gt 0 ]; then
    echo "[setup] FAILED steps: ${failed[*]}"
    exit 1
fi
echo "[setup] all steps ok; run bugs/harness/check-all.sh"
