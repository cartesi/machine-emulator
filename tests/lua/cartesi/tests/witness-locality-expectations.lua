-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

-- Upper bounds for pages, bytes and cycles of page slices (512-byte minimum).
-- Increases require review; do not regenerate these during tests.
-- Regenerate: eval "$(make -s env)"; make -C tests run-lua-spec-witness-locality
-- Temporarily lower these limits, then copy the printed values after reviewing the image change.
-- Inspect changed pages: lua5.4 tests/scripts/uarch-pcs-to-pages.lua --stored DIR MCYCLE
-- Run with the matching uarch ELF and riscv64-unknown-elf-nm from the toolchain image.
-- Toolchain: cartesi/machine-emulator:toolchain (Dockerfile target toolchain).
return {
    ["ordinary-alu"] = { pages = 11, cycles = 281, slice_bytes = 15360, log_bytes = 20208 },
    ["tlb-miss-load"] = { pages = 19, cycles = 721, slice_bytes = 18944, log_bytes = 25680 },
    ["amo-both-misses"] = { pages = 22, cycles = 1096, slice_bytes = 24064, log_bytes = 31128 },
    ["trap-tlb-flush"] = { pages = 19, cycles = 509, slice_bytes = 39424, log_bytes = 44816 },
}
