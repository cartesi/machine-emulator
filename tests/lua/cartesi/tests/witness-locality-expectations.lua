-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

-- Upper bounds for page slices (floor 9), on rebased guest/base commit 690d2afd.
-- Increases require review; do not regenerate these during tests.
return {
    ["ordinary-alu"] = { pages = 12, slice_bytes = 14848, log_bytes = 19784 },
    ["tlb-miss-load"] = { pages = 19, slice_bytes = 18944, log_bytes = 25528 },
    ["amo-both-misses"] = { pages = 23, slice_bytes = 28160, log_bytes = 35064 },
    ["trap-tlb-flush"] = { pages = 20, slice_bytes = 38912, log_bytes = 44424 },
}
