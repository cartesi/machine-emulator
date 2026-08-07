#!/usr/bin/env lua5.4
-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later
--
-- This program is free software: you can redistribute it and/or modify it under
-- the terms of the GNU Lesser General Public License as published by the Free
-- Software Foundation, either version 3 of the License, or (at your option) any
-- later version.
--
-- This program is distributed in the hope that it will be useful, but WITHOUT ANY
-- WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
-- PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
--
-- You should have received a copy of the GNU Lesser General Public License along
-- with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
--

-- Generates the UARCH (keccak256) reject fixtures: valid uarch base fixtures tampered (or
-- replayed with deliberately wrong claimed values) so the keccak replayers -- the Solidity
-- verifier and the C++/Lua host in keccak mode -- must reject identically. The big-machine
-- (sha256) reject fixtures for RISC0 are a separate generator. The manifest's expectError
-- column carries a normalized tag each replayer maps to its own error (C++ message pattern /
-- Solidity selector / RISC0 reject).
--
-- Tampering a page or the pre-state node re-roots root_before via the same fold the
-- replayer uses, so the log still decodes and the rejection fires at its intended layer.

local cartesi = require("cartesi")
local test_util = require("cartesi.tests.util")
local manifest = require("cartesi.tests.step_log_manifest")

local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

local function help()
    stderr("Usage: %s --fixtures-dir=<dir> --output-dir=<dir>\n", arg[0])
    os.exit()
end

local fixtures_dir, output_dir
for _, argument in ipairs(arg) do
    local f = argument:match("^%-%-fixtures%-dir%=(.*)$")
    local o = argument:match("^%-%-output%-dir%=(.*)$")
    if f then
        fixtures_dir = f
    elseif o then
        output_dir = o
    elseif argument == "-h" or argument == "--help" then
        help()
    else
        error("unrecognized option " .. argument)
    end
end
assert(fixtures_dir, "--fixtures-dir is required")
assert(output_dir, "--output-dir is required")

local UARCH_BASE = fixtures_dir .. "/uarch-tests-per-cycle/rv64ui-uarch-add/00000.log"
local RESET_BASE = fixtures_dir .. "/reset-uarch/reset-uarch.log"
-- A reset whose machine is paused on a rejected input: the reset reverts, so the verifier substitutes
-- the recorded revert root instead of recomputing the post root.
local REVERT_RESET_BASE = fixtures_dir .. "/reset-uarch/reset-uarch-rejected.log"

-- Cycle 0 fetches its first instruction at UARCH_PC_INIT (start of uarch RAM).
local PC_INIT = cartesi.UARCH_RAM_START_ADDRESS
local PC_PAGE = PC_INIT >> 12
local PC_OFF = PC_INIT & 0xfff
local INSN_ILLEGAL = 0x00000000
local INSN_EBREAK = 0x00100073
local INSN_ECALL = 0x00000073 -- with pristine x17 (=0), an unknown ecall function

-- A 32-byte value distinct from any real root, for belief/claim mismatches.
local BOGUS = string.rep("\186", 32)

-- Overwrite the 32-bit instruction fetched at PC_INIT, then re-root so the log decodes.
local function inject_uarch_instruction(log, insn)
    for _, page in ipairs(log.pages) do
        if page.index == PC_PAGE then
            local le = string.pack("<I4", insn)
            page.data = page.data:sub(1, PC_OFF) .. le .. page.data:sub(PC_OFF + 5)
            log.root_hash_before = test_util.recompute_step_log_root(log, false, "keccak256")
            return
        end
    end
    error(string.format("page 0x%x not found in base log", PC_PAGE))
end

-- The uarch reset accesses the revert root hash (0xfe0) and htif.tohost, both in shadow page 0,
-- recording that page into the log. htif.tohost has no exported address constant; resolve it from a
-- throwaway machine.
local SHADOW_PAGE = cartesi.AR_SHADOW_REVERT_ROOT_HASH_START >> 12
local REVERT_OFF = cartesi.AR_SHADOW_REVERT_ROOT_HASH_START & 0xfff
local HTIF_TOHOST_OFF
do
    local m <close> = assert(cartesi.machine({ ram = { length = 0x20000 }, uarch = { ram = { backing_store = {} } } }))
    HTIF_TOHOST_OFF = m:get_reg_address("htif_tohost") & 0xfff
end

-- Flip a byte at `off` within the page at `page_idx` WITHOUT re-rooting, so the header pre-root no
-- longer matches. Errors if the page is absent -- a guard that the reset still records this page.
local function tamper_page_byte(log, page_idx, off)
    for _, page in ipairs(log.pages) do
        if page.index == page_idx then
            page.data = page.data:sub(1, off) .. string.char(page.data:byte(off + 1) ~ 0xff) .. page.data:sub(off + 2)
            return
        end
    end
    error(string.format("page 0x%x not recorded in reset log (revert-hash/htif shadow page missing?)", page_idx))
end

-- Each case: tag, kind, base file, and a mutate(log) that tampers the log in place and
-- returns the claimed {before, cycle, after} the manifest hands the verifier. Defaults
-- (real header values) apply when a field is nil.
local cases = {
    -- Framing / header (rejected at decode; claimed values irrelevant)
    {
        tag = "bad_signature",
        kind = "cycle",
        base = UARCH_BASE,
        mutate = function(log)
            log.signature = "\0" .. log.signature:sub(2)
        end,
    },
    {
        tag = "unsupported_hash_function",
        kind = "cycle",
        base = UARCH_BASE,
        mutate = function(log)
            log.hash_function = 99
        end,
    },
    -- Page / node structure
    {
        tag = "page_count_zero",
        kind = "cycle",
        base = UARCH_BASE,
        mutate = function(log)
            log.pages = {}
        end,
    },
    {
        tag = "page_index_not_ascending",
        kind = "cycle",
        base = UARCH_BASE,
        mutate = function(log)
            log.pages[#log.pages].index = log.pages[#log.pages - 1].index
        end,
    },
    {
        tag = "entries_overlap",
        kind = "reset_uarch",
        base = RESET_BASE,
        -- Move the still-aligned uarch-state node onto shadow page 0 so the combined
        -- pages+nodes disjointness walk sees overlapping entries.
        mutate = function(log)
            log.nodes[1].address = 0
        end,
    },
    {
        tag = "node_misaligned",
        kind = "reset_uarch",
        base = RESET_BASE,
        mutate = function(log)
            log.nodes[1].address = log.nodes[1].address ~ 0x08
        end,
    },
    {
        tag = "node_log2_out_of_range",
        kind = "reset_uarch",
        base = RESET_BASE,
        mutate = function(log)
            log.nodes[1].log2_size = 65
        end,
    },
    {
        tag = "nonzero_scratch_hash",
        kind = "cycle",
        base = UARCH_BASE,
        mutate = function(log)
            log.pages[1].scratch_hash = string.rep("\255", 32)
        end,
    },
    {
        tag = "unconsumed_node",
        kind = "reset_uarch",
        base = RESET_BASE,
        mutate = function(log)
            test_util.inject_unconsumed_node(log)
        end,
    },
    {
        -- Same injection on a reverted reset: the revert substitutes the recorded root instead of
        -- recomputing it, so only the explicit unconsumed-node assertion on the revert path catches this.
        tag = "unconsumed_node",
        name = "reset_rejected_unconsumed_node",
        kind = "reset_uarch",
        base = REVERT_RESET_BASE,
        mutate = function(log)
            test_util.inject_unconsumed_node(log)
        end,
    },
    {
        tag = "initial_root_mismatch",
        kind = "cycle",
        base = UARCH_BASE,
        -- Tamper a page byte WITHOUT re-rooting: the header's pre-root no longer matches.
        mutate = function(log)
            local p = log.pages[#log.pages]
            p.data = string.char(p.data:byte(1) ~ 0xff) .. p.data:sub(2)
        end,
    },
    -- The revert root hash and htif.tohost the reset accesses are bound into the proof: tampering
    -- either, in the shadow page the reset records, trips the pre-root recompute.
    {
        tag = "initial_root_mismatch",
        name = "reset_revert_hash_tampered",
        kind = "reset_uarch",
        base = RESET_BASE,
        mutate = function(log)
            tamper_page_byte(log, SHADOW_PAGE, REVERT_OFF)
        end,
    },
    {
        tag = "initial_root_mismatch",
        name = "reset_htif_tohost_tampered",
        kind = "reset_uarch",
        base = RESET_BASE,
        mutate = function(log)
            tamper_page_byte(log, SHADOW_PAGE, HTIF_TOHOST_OFF)
        end,
    },
    {
        tag = "nonzero_cycle_count",
        kind = "reset_uarch",
        base = RESET_BASE,
        mutate = function(log)
            log.requested_cycle_count = 7
        end,
    },
    -- Content traps (instruction injected at PC, log re-rooted)
    {
        tag = "illegal_instruction",
        kind = "cycle",
        base = UARCH_BASE,
        mutate = function(log)
            inject_uarch_instruction(log, INSN_ILLEGAL)
            return { before = log.root_hash_before }
        end,
    },
    {
        tag = "uarch_aborted",
        kind = "cycle",
        base = UARCH_BASE,
        mutate = function(log)
            inject_uarch_instruction(log, INSN_EBREAK)
            return { before = log.root_hash_before }
        end,
    },
    {
        tag = "unsupported_ecall",
        kind = "cycle",
        base = UARCH_BASE,
        mutate = function(log)
            inject_uarch_instruction(log, INSN_ECALL)
            return { before = log.root_hash_before }
        end,
    },
    -- Belief / Layer-2 (valid log; the manifest lies about the transition)
    {
        tag = "root_before_mismatch",
        kind = "cycle",
        base = UARCH_BASE,
        mutate = function(_)
            return { before = BOGUS }
        end,
    },
    {
        tag = "root_after_mismatch",
        kind = "cycle",
        base = UARCH_BASE,
        mutate = function(_)
            return { after = BOGUS }
        end,
    },
    {
        tag = "cycle_count_mismatch",
        kind = "cycle",
        base = UARCH_BASE,
        mutate = function(log)
            return { cycle = log.requested_cycle_count + 1 }
        end,
    },
    {
        tag = "final_root_mismatch",
        kind = "cycle",
        base = UARCH_BASE,
        -- Header claims a post root the replay won't reproduce; claim the same bogus value
        -- so the Layer-1 final-root check fires before the Layer-2 argument check.
        mutate = function(log)
            log.root_hash_after = BOGUS
            return { after = BOGUS }
        end,
    },
    -- Belief / Layer-2 on the reset entrypoint (verifyReset has its own copies of these checks)
    {
        tag = "root_before_mismatch",
        name = "reset_root_before_mismatch",
        kind = "reset_uarch",
        base = RESET_BASE,
        mutate = function(_)
            return { before = BOGUS }
        end,
    },
    {
        tag = "root_after_mismatch",
        name = "reset_root_after_mismatch",
        kind = "reset_uarch",
        base = RESET_BASE,
        mutate = function(_)
            return { after = BOGUS }
        end,
    },
    {
        tag = "final_root_mismatch",
        name = "reset_final_root_mismatch",
        kind = "reset_uarch",
        base = RESET_BASE,
        mutate = function(log)
            log.root_hash_after = BOGUS
            return { after = BOGUS }
        end,
    },
    -- Replay-semantic (decode accepts via hash_before; replay rejects the post-hash)
    {
        tag = "reset_node_wrong_posthash",
        kind = "reset_uarch",
        base = RESET_BASE,
        mutate = function(log)
            local n = log.nodes[1]
            n.hash_after = string.char(n.hash_after:byte(1) ~ 0xff) .. n.hash_after:sub(2)
        end,
    },
}

test_util.prepare_empty_output_dir(output_dir)
local out <close> = assert(io.open(output_dir .. "/" .. manifest.MANIFEST_NAME, "w"))
out:write(manifest.HEADER)

for _, case in ipairs(cases) do
    local log = test_util.read_step_log_file(case.base)
    local claim = case.mutate(log) or {}
    -- Distinct filename when several cases share a tag (same rejection on different entrypoints).
    local name = (case.name or case.tag) .. ".log"
    test_util.write_step_log_file(log, output_dir .. "/" .. name)
    manifest.write_row(out, {
        kind = case.kind,
        name = name,
        hash_function = "keccak256",
        requested_cycle_count = claim.cycle or log.requested_cycle_count,
        initial_root_hash = claim.before or log.root_hash_before,
        final_root_hash = claim.after or log.root_hash_after,
        expect_error = case.tag,
    })
    stderr("adversarial: %-26s (%s)\n", case.tag, case.kind)
end

stderr("\nwrote %d adversarial step logs to %s\n", #cases, output_dir)
