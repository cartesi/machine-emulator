-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

-- Upper bounds for RAM-only PTEs on base commit 3322381a, with the pinned guest
-- toolchain. Increases require review; do not regenerate these during tests.
return {
    ["ordinary-alu"] = { pages = 13, log_bytes = 57200 },
    ["tlb-miss-load"] = { pages = 19, log_bytes = 82752 },
    ["amo-both-misses"] = { pages = 23, log_bytes = 99328 },
    ["trap-tlb-flush"] = { pages = 20, log_bytes = 86088 },
}
