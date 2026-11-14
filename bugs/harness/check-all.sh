#!/bin/bash
# Run the smoke check of every harness and print one line per harness: PASS / FAIL / SKIP <name> <note>.
#   check-all.sh            quick checks (a few minutes)
#   CHECK_LONG=1 check-all.sh  also the PRT demo on the chain and the player restart runner (tens of minutes)
# Exit 0 iff no check FAILed. Logs: bugs/harness/work/check-logs/<name>.log
set -uo pipefail
H="$(cd "$(dirname "$0")" && pwd)"
. "$H/lib/common.sh"
L="$WORK/check-logs"
mkdir -p "$L"
fails=0

result() { printf '%-4s %-22s %s\n' "$1" "$2" "$3"; [ "$1" = FAIL ] && fails=$((fails + 1)); return 0; }

check() { # check <name> <timeout-seconds> <command...>
    local name=$1 to=$2
    shift 2
    if timeout --kill-after=30 "$to" "$@" > "$L/$name.log" 2>&1; then
        result PASS "$name" "$(tail -1 "$L/$name.log" | cut -c1-110)"
    else
        result FAIL "$name" "exit $? (log $L/$name.log): $(tail -1 "$L/$name.log" | cut -c1-90)"
    fi
}

lua_check() { # lua_check <name> <timeout> <script>
    local name=$1 to=$2 script=$3
    check "$name" "$to" bash -c ". '$REPO/bugs/env.sh' && lua5.4 '$script'"
}

have() { [ -e "$1" ]; }

check runner-selftest 120 "$H/selftest/run-selftest.sh"
if have "$REPO/src/cartesi.so" && have "$WORK/images/linux.bin"; then
    check emulator 300 "$H/emulator/smoke.sh"
else
    result SKIP emulator "not built (setup.sh)"
fi
check images 600 "$H/emulator/fetch-images.sh"
if have "$WORK/baremetal/accept.bin"; then
    lua_check baremetal 300 "$H/baremetal/smoke.lua"
else
    result SKIP baremetal "not built (baremetal/build.sh)"
fi
if have "$WORK/configs/valid-template/.done"; then
    lua_check configs 600 "$H/configs/smoke.lua"
else
    result SKIP configs "not built (configs/make-configs.sh)"
fi
if have "$WORK/sanitizer/src/cartesi.so"; then
    check sanitizer 900 "$H/sanitizer/smoke.sh"
else
    result SKIP sanitizer "not built (sanitizer/build.sh)"
fi
if ensure_docker; then
    check uarch-rebuild 1800 "$H/uarch-rebuild/rebuild.sh"
else
    result SKIP uarch-rebuild "docker unavailable"
fi
if have "$WORK/solidity-step/build-status.txt"; then
    v=$(readlink "$WORK/solidity-step/step")
    note="variant $v; $(head -1 "$WORK/solidity-step/build-status.txt"); tests: $(grep -h -o 'test-[a-z]*: exit [0-9]*' "$WORK/solidity-step/results.txt" 2> /dev/null | tr '\n' ' ')"
    if [ "$v" != none ] && have "$WORK/solidity-step/step/src/UArchStep.sol"; then
        result PASS solidity-step "$note"
    else
        result FAIL solidity-step "$note"
    fi
else
    result SKIP solidity-step "not regenerated (solidity-step/regenerate.sh)"
fi
if have "$WORK/solidity-step/step/src"; then
    check evm-step 900 bash -c "'$H/solidity-step/evm/start.sh' && . '$REPO/bugs/env.sh' && lua5.4 '$H/solidity-step/evm/smoke.lua'"
else
    result SKIP evm-step "no regenerated step"
fi
if have "$WORK/dave/released/.built"; then
    check chain-released 900 "$H/chain/smoke.sh" released
else
    result SKIP chain-released "Dave released not built (chain/build-dave.sh)"
fi
if have "$WORK/dave/patched/.built"; then
    check chain-patched 900 "$H/chain/smoke.sh" patched-stf
else
    result SKIP chain-patched "Dave patched not built (chain/build-dave.sh)"
fi
"$H/chain/stop-chain.sh"
if [ "${CHECK_LONG:-0}" = 1 ] && have "$WORK/dave/patched/.built"; then
    rm -rf "$WORK"/prt-runs/run.*
    check prt-demo 7200 "$H/chain/prt-demo.sh" smoke
    rm -rf "$WORK"/prt-runs/run.*
    check player-restart 7200 "$H/player-restart/run.sh" random smoke
else
    result SKIP prt-demo "long; run with CHECK_LONG=1 (chain/prt-demo.sh smoke)"
    result SKIP player-restart "long; run with CHECK_LONG=1 (player-restart/run.sh random smoke)"
fi
exit $((fails > 0))
