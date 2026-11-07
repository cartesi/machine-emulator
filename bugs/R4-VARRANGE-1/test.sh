#!/bin/bash
# R4-VARRANGE-1 -- libcmt ABI decoder accepts wrapping ('negative') dynamic offsets.
#
# cmt_abi_peek_bytes_d (sys-utils/libcmt/src/abi.c) decodes the 32-byte ABI
# offset word as a uint64 and forms `start->begin + offset` WITHOUT checking
# `offset <= cmt_buf_length(start)` (buf.c's cmt_buf_split only compares the
# shifted pointer against begin/end, which a wrap defeats). An offset of
# 2^64 - K therefore wraps the pointer K bytes *below* the ABI frame and the
# decoder returns success with `bytes` pointing outside the input payload, or
# dereferences unmapped memory and crashes.
#
# This test builds a correctly-designed rollup application (app.c) that decodes
# its input payload with libcmt's documented ABI decoder and emits the decoded
# `bytes` as a notice, compiling it against the LIVE pinned libcmt sources so a
# fix to abi.c is exercised. It then delivers three advance-state inputs through
# cmio and asserts (in check.lua) the behavior the threat model requires:
#   * the honest input decodes to "hello";
#   * a wrapping offset is rejected -> no notice built from bytes outside the
#     payload is ever committed (THREAT_MODEL section 1 goal; machine-guest-tools
#     role in AUDIT.md: an input must not make the app commit a wrong output);
#   * a wrapping offset into unmapped memory does not crash/halt the machine
#     (section 8 crash-on-relayed-data clause).
#
# Exit status: 0 when libcmt bounds the offset (bug absent), 1 when the bug is
# present (wrong output committed and/or machine halted), 3 on a harness error.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

: "${MACHINE_GUEST_TOOLS_DIR:?set by bugs/env.sh}"
: "${REPO_DIR:?set by bugs/env.sh}"
LC="$MACHINE_GUEST_TOOLS_DIR/sys-utils/libcmt"
CLI="$REPO_DIR/src/cartesi-machine.lua"
CC=riscv64-linux-gnu-gcc

command -v "$CC" >/dev/null 2>&1 || { echo "INFRA ERROR: $CC not found" >&2; exit 3; }
[ -d "$LC/src" ] || { echo "INFRA ERROR: libcmt sources not found at $LC" >&2; exit 3; }

build="$here/build"
rm -rf "$build"
mkdir -p "$build/root"

# 1. Build the guest application against the LIVE pinned libcmt sources.
#    (A fix in abi.c changes this binary, so the test passes once fixed.)
"$CC" -O2 -static -I"$LC/include" \
    app.c \
    "$LC/src/abi.c" "$LC/src/buf.c" "$LC/src/rollup.c" "$LC/src/io.c" \
    "$LC/src/merkle.c" "$LC/src/keccak.c" "$LC/src/util.c" \
    -o "$build/root/app.rv64" || { echo "INFRA ERROR: guest build failed" >&2; exit 3; }

# 2. Pack the application into an ext2 flash drive.
mke2fs -q -F -b 1024 -d "$build/root" -t ext2 "$build/poc.ext2" 1024 \
    >/dev/null 2>&1 || { echo "INFRA ERROR: mke2fs failed" >&2; exit 3; }

# 3. Generate the three EvmAdvance inputs.
( cd "$build" && lua5.4 "$here/mkinputs.lua" ) \
    || { echo "INFRA ERROR: input generation failed" >&2; exit 3; }

# 4. Boot the application to its first RX-accepted yield and store it as a
#    template, so check.lua can drive each input without re-booting.
rm -rf "$build/tmpl"
lua5.4 "$CLI" --no-init-splash \
    --flash-drive=label:poc,data_filename:"$build/poc.ext2" \
    --store="$build/tmpl" -- '/mnt/poc/app.rv64' \
    >"$build/boot.out" 2>"$build/boot.err" \
    || { echo "INFRA ERROR: template boot/store failed; see $build/boot.err" >&2; exit 3; }

# 5. Drive cmio advance-state over the inputs and assert correct behavior.
lua5.4 "$here/check.lua" "$build/tmpl" \
    "$build/in-0.bin" "$build/in-1.bin" "$build/in-2.bin"
status=$?

exit $status
