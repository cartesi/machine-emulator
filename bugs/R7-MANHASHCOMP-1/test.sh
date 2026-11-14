#!/bin/bash
# R7-MANHASHCOMP-1: the manual's output verifier (doc/recipes/verify-output-proof.lua, printed under "Output
# verification") must reject a crafted proof file promptly and with bounded memory. It reads each proof with
# assert(loadfile(name, "t", {}))(), i.e. it executes the proof as a Lua chunk before checking anything.
#
# exit 0: every crafted proof is rejected with an error, within the CPU budget and without a large allocation
# exit 1: a crafted proof hangs the verifier or makes it allocate far beyond the proof's size
# exit 2: setup error (the control proof does not behave as expected, missing tools)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$HERE/../.." && pwd)}"
VERIFIER="$REPO/doc/recipes/verify-output-proof.lua"
[ -f "$VERIFIER" ] || { echo "setup: missing $VERIFIER" >&2; exit 2; }
command -v python3 >/dev/null || { echo "setup: python3 missing" >&2; exit 2; }
command -v lua5.4 >/dev/null || { echo "setup: lua5.4 missing" >&2; exit 2; }

# the manual prints the same reader (informational: the test runs the recipe file)
if grep -qF 'return assert(loadfile(name, "t", {}))()' "$REPO/doc/README.md"; then
    echo "info: doc/README.md 'Output verification' prints the same read_proof (loadfile ... ())"
fi

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

head -c 32 /dev/zero >"$T/state-hash.bin"
printf 'x' >"$T/output.bin"
printf 'return {}\n' >"$T/control.lua"
printf 'while true do end\n' >"$T/loop.lua"
printf 'return { iflags_y_data = ("x"):rep(1 << 29) }\n' >"$T/alloc512m.lua"
# string.rep caps one string below 2 GiB, so this one asks for 2^20 strings of 1 GiB each (1 PiB in all)
printf 'local s, t = ("x"):rep(1 << 30), {}\nfor i = 1, 1 << 20 do t[i] = s .. i end\nreturn t\n' >"$T/allocpib.lua"

CPU=5                 # CPU seconds (not wall clock) granted to each verifier run
VMEM_KIB=4000000      # address-space limit for the normal runs (~3.8 GiB)
VMEM_SMALL_KIB=2000000

run() { # <cpu> <vmem-kib> <proof-file>
    python3 -I "$HERE/runcase.py" "$1" "$2" lua5.4 "$VERIFIER" "$T/state-hash.bin" "$3" "$T/control.lua" \
        "$T/output.bin"
}
field() { python3 -I -c 'import json,sys; v=json.loads(sys.argv[1]).get(sys.argv[2]); print("" if v is None else v)' "$1" "$2"; }

echo "== control: proof file 'return {}' (well-formed data, wrong content)"
C="$(run $CPU $VMEM_KIB "$T/control.lua")" || { echo "setup: runcase failed" >&2; exit 2; }
echo "$C"
c_exit="$(field "$C" exit)"; c_sig="$(field "$C" signal)"; c_rss="$(field "$C" maxrss_kib)"
if [ -n "$c_sig" ] || [ -z "$c_exit" ] || [ "$c_exit" = 0 ]; then
    echo "setup: the control proof was not rejected with an error exit (exit=$c_exit signal=$c_sig)" >&2
    exit 2
fi
echo "control: rejected with exit $c_exit, peak RSS ${c_rss} KiB"

fail=0

echo
echo "== case 1: proof file 'while true do end' ($(stat -c %s "$T/loop.lua") bytes), ${CPU} s of CPU allowed"
L="$(run $CPU $VMEM_KIB "$T/loop.lua")" || { echo "setup: runcase failed" >&2; exit 2; }
echo "$L"
l_exit="$(field "$L" exit)"; l_sig="$(field "$L" signal)"
if [ -n "$l_sig" ]; then
    echo "VIOLATION: the verifier never finished on the crafted proof; killed by signal $l_sig after exhausting" \
        "${CPU} s of CPU (the control finished in a fraction of that)"
    fail=1
elif [ "$l_exit" = 0 ]; then
    echo "VIOLATION: the verifier accepted the crafted proof"
    fail=1
else
    echo "ok: rejected with exit $l_exit"
fi

echo
echo "== case 2: proof file of $(stat -c %s "$T/alloc512m.lua") bytes that builds a 512 MiB string"
A="$(run $CPU $VMEM_KIB "$T/alloc512m.lua")" || { echo "setup: runcase failed" >&2; exit 2; }
echo "$A"
a_rss="$(field "$A" maxrss_kib)"; a_exit="$(field "$A" exit)"
extra=$((a_rss - c_rss))
echo "peak RSS ${a_rss} KiB, ${extra} KiB above the control"
if [ "$extra" -ge $((256 * 1024)) ]; then
    echo "VIOLATION: a $(stat -c %s "$T/alloc512m.lua")-byte proof made the verifier allocate ${extra} KiB more than" \
        "the control before any check ran"
    fail=1
elif [ "$a_exit" = 0 ]; then
    echo "VIOLATION: the verifier accepted the crafted proof"
    fail=1
else
    echo "ok: rejected without a large allocation"
fi

echo
echo "== case 3: proof file of $(stat -c %s "$T/allocpib.lua") bytes that asks for 1 PiB of strings (address space" \
    "limited to ${VMEM_SMALL_KIB} KiB)"
H="$(run $CPU $VMEM_SMALL_KIB "$T/allocpib.lua")" || { echo "setup: runcase failed" >&2; exit 2; }
echo "$H"
if grep -q "not enough memory" <<<"$(field "$H" stderr)"; then
    echo "VIOLATION: the verifier kept allocating until the address-space limit for a $(stat -c %s "$T/allocpib.lua")-byte proof" \
        "(allocation failed: 'not enough memory'); without the limit it would exhaust the host"
    fail=1
elif [ -n "$(field "$H" signal)" ] || [ "$(field "$H" exit)" = 0 ]; then
    echo "VIOLATION: the verifier did not reject the crafted proof with an error"
    fail=1
else
    echo "ok: rejected without attempting the allocation"
fi

echo
if [ "$fail" = 1 ]; then
    echo "FAIL: THREAT_MODEL section 4 requires paths carrying proofs from other parties to be bounded and to" \
        "report errors; the manual's output verifier executes the proof file as code"
    exit 1
fi
echo "PASS: every crafted proof was rejected promptly with bounded memory"
exit 0
