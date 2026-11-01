-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

-- Upper bounds for pages, bytes and cycles of page slices (floor 9), on rebased guest/base commit 690d2afd.
-- Increases require review; do not regenerate these during tests.
-- Regenerate: eval "$(make -s env)"; make -C tests run-lua-spec-witness-locality
-- Temporarily lower these limits, then copy the printed values after reviewing the image change.
-- Inspect changed pages: lua5.4 tests/scripts/uarch-pcs-to-pages.lua --stored DIR MCYCLE
-- Run with the matching uarch ELF and riscv64-unknown-elf-nm from the toolchain image.
-- Toolchain: cartesi/machine-emulator:toolchain (Dockerfile target toolchain).
return {
    ["ordinary-alu"] = { pages = 12, cycles = 289, slice_bytes = 14848, log_bytes = 19784 },
    ["tlb-miss-load"] = { pages = 19, cycles = 730, slice_bytes = 18944, log_bytes = 25528 },
    ["amo-both-misses"] = { pages = 23, cycles = 1102, slice_bytes = 28160, log_bytes = 35064 },
    ["trap-tlb-flush"] = { pages = 20, cycles = 515, slice_bytes = 38912, log_bytes = 44424 },
}
