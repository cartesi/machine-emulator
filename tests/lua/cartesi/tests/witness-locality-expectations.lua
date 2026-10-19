-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

-- Upper bounds for page slices (floor 9), on guest/base commit 47c35561.
-- Increases require review; do not regenerate these during tests.
return {
    ["ordinary-alu"] = { pages = 13, slice_bytes = 12288, log_bytes = 17336 },
    ["tlb-miss-load"] = { pages = 19, slice_bytes = 18944, log_bytes = 25496 },
    ["amo-both-misses"] = { pages = 23, slice_bytes = 28160, log_bytes = 35128 },
    ["trap-tlb-flush"] = { pages = 20, slice_bytes = 41472, log_bytes = 46760 },
}
