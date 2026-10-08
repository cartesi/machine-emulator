-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

-- Upper bounds measured on layout commit 08a05efc, with the pinned guest
-- toolchain. Increases require review; do not regenerate these during tests.
return {
    ["ordinary-alu"] = { pages = 13, log_bytes = 57200 },
    ["tlb-miss-load"] = { pages = 20, log_bytes = 86792 },
    ["amo-both-misses"] = { pages = 23, log_bytes = 99264 },
    ["trap-tlb-flush"] = { pages = 20, log_bytes = 86088 },
}
