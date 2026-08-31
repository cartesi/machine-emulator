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

-- Records the reset_uarch step-log fixture + its _manifest.csv.
-- Fixtures use keccak256, the Solidity verifier's hash function.
--
-- Writes <output-dir>/{reset-uarch.log, _manifest.csv}.

local cartesi = require("cartesi")
local manifest_mod = require("cartesi.tests.step_log_manifest")
local test_util = require("cartesi.tests.util")

local HASH_FUNCTION = "keccak256"

-- Fixed sentinel revert root hash seeded in the revert-root-hash shadow slot. The reset accesses it,
-- forcing its shadow page into the step log; tests assert it round-trips into the reset proof.
local REVERT_ROOT_HASH = string.rep("\xab", 32)

local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

local function help()
    stderr("Usage: %s --output-dir=<dir>\n", arg[0])
    os.exit()
end

local output_dir
for _, argument in ipairs(arg) do
    local o = argument:match("^%-%-output%-dir%=(.*)$")
    if o then
        output_dir = o
    elseif argument == "-h" or argument == "--help" then
        help()
    else
        error("unrecognized option " .. argument)
    end
end
assert(output_dir, "--output-dir is required")

local function build_machine()
    return assert(cartesi.machine({
        ram = { length = 0x20000 },
        uarch = { ram = { backing_store = {} } },
    }))
end

-- Records a uarch reset step log. The uarch state must be non-pristine to be meaningful;
-- setting uarch_halt is the minimum perturbation.
local function create_reset_uarch_step_log()
    local machine <close> = build_machine()
    local name = "reset-uarch.log"
    local log_path = output_dir .. "/" .. name
    os.remove(log_path)
    machine:write_reg("uarch_halt", 1)
    -- Seed the revert-root-hash slot so the reset accesses it, forcing its shadow page into the log.
    machine:write_memory(cartesi.AR_SHADOW_REVERT_ROOT_HASH_START, REVERT_ROOT_HASH)
    local ctx = {
        kind = "reset_uarch",
        name = name,
        hash_function = HASH_FUNCTION,
        requested_cycle_count = 0,
        revert_root_hash = REVERT_ROOT_HASH,
    }
    ctx.initial_root_hash = machine:get_root_hash()
    machine:log_reset_uarch(log_path)
    ctx.final_root_hash = machine:get_root_hash()
    assert(cartesi.machine:verify_reset_uarch(ctx.initial_root_hash, log_path) == ctx.final_root_hash)
    return ctx
end

-- htif.tohost encoding a pending manual yield rejected by the dapp: the reset detects this and
-- reverts the canonical state to the revert root hash.
local TOHOST_RX_REJECTED = (cartesi.HTIF_DEV_YIELD << 56)
    | (cartesi.HTIF_YIELD_CMD_MANUAL << 48)
    | (cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED << 32)

-- The same manual-yield encoding but rx-accepted: the reset reads tohost yet does NOT revert (only an
-- rx-rejected yield substitutes the revert root), so its canonical post-state is the post-reset root.
local TOHOST_RX_ACCEPTED = (cartesi.HTIF_DEV_YIELD << 56)
    | (cartesi.HTIF_YIELD_CMD_MANUAL << 48)
    | (cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED << 32)

-- Records a uarch reset whose machine is paused on a rejected manual yield. The reset substitutes the
-- recorded revert root hash as its post-state, so the transition ends at REVERT_ROOT_HASH, not at
-- the physical (pristine-uarch) root hash.
local function create_rejected_reset_uarch_step_log()
    local machine <close> = build_machine()
    local name = "reset-uarch-rejected.log"
    local log_path = output_dir .. "/" .. name
    os.remove(log_path)
    machine:write_reg("uarch_halt", 1)
    machine:write_reg("iflags_Y", 1)
    machine:write_reg("htif_tohost", TOHOST_RX_REJECTED)
    machine:write_memory(cartesi.AR_SHADOW_REVERT_ROOT_HASH_START, REVERT_ROOT_HASH)
    local ctx = {
        kind = "reset_uarch",
        name = name,
        hash_function = HASH_FUNCTION,
        requested_cycle_count = 0,
        revert_root_hash = REVERT_ROOT_HASH,
    }
    ctx.initial_root_hash = machine:get_root_hash()
    machine:log_reset_uarch(log_path)
    -- The reset reverted, so the canonical post-state is the revert root hash, not get_root_hash().
    ctx.final_root_hash = REVERT_ROOT_HASH
    assert(cartesi.machine:verify_reset_uarch(ctx.initial_root_hash, log_path) == ctx.final_root_hash)
    return ctx
end

-- Records a uarch reset whose machine is paused on an rx-accepted manual yield. The reset reads
-- htif.tohost but does NOT revert (only rx-rejected substitutes the revert root), so its canonical
-- post-state is the recomputed post-reset root -- exercising the iflags.Y-set-but-not-rejected branch.
local function create_accepted_reset_uarch_step_log()
    local machine <close> = build_machine()
    local name = "reset-uarch-accepted.log"
    local log_path = output_dir .. "/" .. name
    os.remove(log_path)
    machine:write_reg("uarch_halt", 1)
    machine:write_reg("iflags_Y", 1)
    machine:write_reg("htif_tohost", TOHOST_RX_ACCEPTED)
    machine:write_memory(cartesi.AR_SHADOW_REVERT_ROOT_HASH_START, REVERT_ROOT_HASH)
    local ctx = {
        kind = "reset_uarch",
        name = name,
        hash_function = HASH_FUNCTION,
        requested_cycle_count = 0,
        revert_root_hash = REVERT_ROOT_HASH,
    }
    ctx.initial_root_hash = machine:get_root_hash()
    machine:log_reset_uarch(log_path)
    -- Not reverted: the post-state is the actual post-reset root, not the revert root hash.
    ctx.final_root_hash = machine:get_root_hash()
    assert(cartesi.machine:verify_reset_uarch(ctx.initial_root_hash, log_path) == ctx.final_root_hash)
    return ctx
end

test_util.prepare_empty_output_dir(output_dir)
local manifest <close> = assert(io.open(output_dir .. "/" .. manifest_mod.MANIFEST_NAME, "w"))
manifest:write(manifest_mod.HEADER)
manifest_mod.write_row(manifest, create_reset_uarch_step_log())
manifest_mod.write_row(manifest, create_rejected_reset_uarch_step_log())
manifest_mod.write_row(manifest, create_accepted_reset_uarch_step_log())
stderr("\nreset_uarch step logs written to %s\n", output_dir)
