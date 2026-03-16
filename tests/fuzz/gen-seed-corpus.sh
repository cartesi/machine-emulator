#!/usr/bin/env bash
# Copyright Cartesi and individual authors (see AUTHORS)
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# Generates seed corpus files for the fuzz-interpret harness.
#
# Each seed file has the layout expected by the harness:
#   [1B priv] [1B flags] [128B CSRs] [256B GPRs] [256B FPRs] [code...]
#
# Usage: gen-seed-corpus.sh <output-dir>

set -euo pipefail

SEED_DIR="${1:?Usage: gen-seed-corpus.sh <output-dir>}"
ISA_BIN_DIR="../../tests/build/riscv-tests/isa"

mkdir -p "$SEED_DIR"

# -- Helper: create seed from control params + a raw binary file --------------
# Args: filename priv_byte flags_byte binary_path
make_seed_from_bin() {
    local name="$1" priv="$2" flags="$3" binfile="$4"
    local outfile="$SEED_DIR/$name"

    printf "\\x$(printf '%02x' "$priv")" > "$outfile"
    printf "\\x$(printf '%02x' "$flags")" >> "$outfile"

    dd if=/dev/zero bs=1 count=128 >> "$outfile" 2>/dev/null  # CSRs
    dd if=/dev/zero bs=1 count=256 >> "$outfile" 2>/dev/null  # GPRs
    dd if=/dev/zero bs=1 count=256 >> "$outfile" 2>/dev/null  # FPRs

    # Append binary code (first 4096 bytes max to keep seeds small)
    dd if="$binfile" bs=1 count=4096 >> "$outfile" 2>/dev/null
}

# -- Generate seeds from compiled riscv-tests ISA binaries --------------------
#
# Test prefixes map to privilege levels and flags:
#   rv64mi-*  → M-mode (priv=3)
#   rv64si-*  → S-mode (priv=1)
#   rv64u*-*  → M-mode (priv=3), these run in M-mode despite the "u" prefix
#   rv64uf-*/rv64ud-* → M-mode + FS=Dirty (flags=0x10)
#
# Each binary is also seeded with VM enabled (flags |= 0x01) in S-mode to
# exercise virtual memory paths.

if [ ! -d "$ISA_BIN_DIR" ]; then
    echo "Error: $ISA_BIN_DIR not found."
    echo "  Build tests first: cd ../../tests && make build-tests-machine"
    exit 1
fi

echo "Generating seed corpus from riscv-tests ISA binaries in $ISA_BIN_DIR..."

for binfile in "$ISA_BIN_DIR"/*.bin; do
    [ -f "$binfile" ] || continue
    name=$(basename "$binfile" .bin)

    # Pick privilege level and flags based on test prefix
    case "$name" in
        rv64mi-*)  priv=3; flags=0x00 ;;  # M-mode tests
        rv64si-*)  priv=1; flags=0x00 ;;  # S-mode tests
        rv64uf-*|rv64ud-*)  priv=3; flags=0x10 ;;  # FP tests: FS=Dirty
        *)         priv=3; flags=0x00 ;;  # Default: M-mode
    esac

    make_seed_from_bin "$name" "$priv" "$flags" "$binfile"

    # Also seed with VM enabled in S-mode
    make_seed_from_bin "${name}-vm" 1 $(printf '0x%02x' $(( flags | 0x01 ))) "$binfile"
done

count=$(find "$SEED_DIR" -type f | wc -l)
echo "Generated $count seed corpus files in $SEED_DIR/"
