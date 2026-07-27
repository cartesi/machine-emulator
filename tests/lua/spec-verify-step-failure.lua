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

--[[
Failure-mode tests for cartesi.machine:verify_step.

Three flavors of failure are exercised:

  - Layer 2 argument checks (caller-belief mismatch with the log header).
  - Layer 1 / parse-layer corruption (signature, counts, page/sibling
    structure) in the replay_step_state_access constructor.
  - Interpretation-time adversarial logs that are merkle-self-consistent
    but still must be rejected during replay.

Format-corruption coverage lives here, exercised against the
replay_step_state_access parser via verify_step.

The hash-function policy tests also cover the Keccak-256-only verifiers
(verify_step_uarch, verify_reset_uarch, verify_send_cmio_response), which
mirror the on-chain replayer; verify_step itself stays hash-function
agnostic (RISC0 proves SHA-256 logs).
]]

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local lester = require("cartesi.third-party.lester")
lester.parse_args()
local test_util = require("cartesi.tests.util")

local describe, it, expect = lester.describe, lester.it, lester.expect

local HASH_SIZE = cartesi.HASH_SIZE
local LOG2_PAGE_SIZE = cartesi.HASH_TREE_LOG2_PAGE_SIZE
local PAGE_SIZE = 1 << LOG2_PAGE_SIZE
local LOG2_ROOT_SIZE = cartesi.HASH_TREE_LOG2_ROOT_SIZE
local BAD_HASH = string.rep("\0", HASH_SIZE)
local MCYCLE_COUNT = 10

-- Machine configured so log_step touches multiple pages (shadow_state, an
-- instruction page, and the PMA page).
local function build_machine(hash_fn)
    return cartesi.machine({
        hash_tree = hash_fn and { hash_function = hash_fn } or nil,
        ram = { length = 1 << 20 },
        uarch = {
            ram = {
                length = 0x1000,
                backing_store = {
                    data_filename = test_util.create_test_uarch_program(test_util.uarch_programs.default),
                },
            },
        },
    }, {})
end

-- Produce a fresh valid log + endpoint hashes; each call gives an isolated file.
local function produce_valid_log(hash_fn)
    local machine <close> = build_machine(hash_fn)
    machine:write_reg("mcycle", 0)
    local root_hash_before = machine:get_root_hash()
    local filename = os.tmpname()
    os.remove(filename)
    machine:log_step(MCYCLE_COUNT, filename)
    local root_hash_after = machine:get_root_hash()
    return filename, root_hash_before, root_hash_after
end

-- Run verify_step against a corrupted copy produced by `mutate`. Returns (ok, err).
local function verify_corrupted(filename, mutate, root_hash_before, mcycle_count, root_hash_after)
    local corrupted = os.tmpname()
    test_util.copy_step_log(filename, corrupted, mutate)
    local ok, err = pcall(function()
        local obtained_root_hash = cartesi.machine:verify_step(root_hash_before, corrupted, mcycle_count)
        assert(obtained_root_hash == root_hash_after, "obtained root hash does not match root hash after")
    end)
    os.remove(corrupted)
    return ok, err
end

-- Three-cursor sibling computation: replicates replay_step_state_access's tree
-- walk for an arbitrary subset of present page indices, using a pristine
-- machine's node hashes for subtrees that contain none of those pages.
local function get_siblings_for_pages(machine, page_indices)
    table.sort(page_indices)
    local log2_page_count = LOG2_ROOT_SIZE - LOG2_PAGE_SIZE
    local siblings = {}
    local next_page = 1

    local function walk(first_page_index, lpc)
        local range_size = 1 << lpc
        local has_page = next_page <= #page_indices
            and page_indices[next_page] >= first_page_index
            and page_indices[next_page] < first_page_index + range_size
        if not has_page then
            local addr = first_page_index << LOG2_PAGE_SIZE
            local log2_size = lpc + LOG2_PAGE_SIZE
            table.insert(siblings, machine:get_node_hash(addr, log2_size))
            return
        end
        if lpc > 0 then
            walk(first_page_index, lpc - 1)
            walk(first_page_index + (range_size >> 1), lpc - 1)
        else
            next_page = next_page + 1
        end
    end

    walk(0, log2_page_count)
    return siblings
end

-- Run `body(filename, root_hash_before, root_hash_after)` against a freshly
-- produced log. Cleans up the file on the way out.
local function with_valid_log(body)
    local filename, root_hash_before, root_hash_after = produce_valid_log()
    local ok, err = pcall(body, filename, root_hash_before, root_hash_after)
    os.remove(filename)
    if not ok then
        error(err)
    end
end

-- Common pattern: produce a valid log, corrupt it via `mutate`, expect
-- verify_step to fail with an error containing `expected_substring`.
local function expect_corruption_error(expected_substring, mutate, verify_overrides)
    with_valid_log(function(filename, root_hash_before, root_hash_after)
        local args = verify_overrides or {}
        local ok, err = verify_corrupted(
            filename,
            mutate,
            args.root_hash_before or root_hash_before,
            args.mcycle_count or MCYCLE_COUNT,
            args.root_hash_after or root_hash_after
        )
        expect.falsy(ok)
        expect.truthy(err and err:find(expected_substring, 1, true), err)
    end)
end

--------------------------------------------------------------------------------

describe("verify_step", function()
    describe("argument validation (Layer 2)", function()
        it("rejects a wrong root_hash_before argument", function()
            with_valid_log(function(filename)
                local ok, err = pcall(function()
                    cartesi.machine:verify_step(BAD_HASH, filename, MCYCLE_COUNT)
                end)
                expect.falsy(ok)
                expect.truthy(err and err:find("root hash before does not match", 1, true), err)
            end)
        end)

        it("returns the root hash after for the caller to check", function()
            with_valid_log(function(filename, root_hash_before, root_hash_after)
                local obtained = cartesi.machine:verify_step(root_hash_before, filename, MCYCLE_COUNT)
                expect.truthy(obtained == root_hash_after)
                expect.truthy(obtained ~= BAD_HASH)
            end)
        end)

        it("rejects a wrong mcycle_count argument", function()
            with_valid_log(function(filename, root_hash_before)
                local ok, err = pcall(function()
                    cartesi.machine:verify_step(root_hash_before, filename, MCYCLE_COUNT + 1)
                end)
                expect.falsy(ok)
                expect.truthy(err and err:find("mcycle count does not match", 1, true), err)
            end)
        end)
    end)

    describe("header validation", function()
        it("rejects a log shorter than the header", function()
            with_valid_log(function(_, root_hash_before)
                local truncated = os.tmpname()
                do
                    local f <close> = assert(io.open(truncated, "wb"))
                    f:write(string.rep("\0", 16))
                end
                local ok, err = pcall(function()
                    cartesi.machine:verify_step(root_hash_before, truncated, MCYCLE_COUNT)
                end)
                os.remove(truncated)
                expect.falsy(ok)
                expect.truthy(err and err:find("step log shorter than header", 1, true), err)
            end)
        end)

        it("rejects an invalid signature", function()
            expect_corruption_error("invalid step log signature", function(log_data)
                log_data.signature = string.rep("\0", 8)
            end)
        end)

        it("rejects an unsupported hash function type", function()
            expect_corruption_error("unsupported hash function type", function(log_data)
                log_data.hash_function = 0xffff
            end)
        end)

        it("rejects a logged requested_cycle_count that disagrees with the argument", function()
            expect_corruption_error("mcycle count does not match", function(log_data)
                log_data.requested_cycle_count = MCYCLE_COUNT + 1
            end)
        end)

        it("rejects page_count overflow against file size", function()
            expect_corruption_error("page count exceeds step log size", function(log_data)
                log_data.override_page_count = cartesi.MCYCLE_MAX
            end)
        end)

        it("rejects node_count overflow against file size", function()
            expect_corruption_error("node count exceeds step log size", function(log_data)
                log_data.override_node_count = cartesi.MCYCLE_MAX
            end)
        end)

        it("rejects sibling_count that does not match file size", function()
            expect_corruption_error("sibling count does not match step log size", function(log_data)
                log_data.override_sibling_count = 0xffffffff
            end)
        end)

        it("rejects sibling_count whose byte size overflows uint64", function()
            -- 2^59 siblings * 32 bytes == 2^64 wraps to 0, so a header claiming siblings
            -- with no sibling bytes present must still be rejected by the size check.
            expect_corruption_error("sibling count does not match step log size", function(log_data)
                log_data.siblings = {}
                log_data.override_sibling_count = 1 << 59
            end)
        end)
    end)

    describe("hash function policy", function()
        local POLICY_ERROR = "step log hash function not supported by this verifier"

        -- Flip the declared hash function on an otherwise valid Keccak log and expect the
        -- policy error: the check must fire at header parse, before the pre-root recompute
        -- turns the mismatch into an unhelpful "initial root hash mismatch".
        local function expect_sha256_rejection(produce, verify)
            local filename, root_hash_before, root_hash_after = produce()
            local corrupted = os.tmpname()
            test_util.copy_step_log(filename, corrupted, function(log_data)
                log_data.hash_function = 1 -- sha256
            end)
            os.remove(filename)
            local ok, err = pcall(verify, root_hash_before, corrupted, root_hash_after)
            os.remove(corrupted)
            expect.falsy(ok)
            expect.truthy(err and err:find(POLICY_ERROR, 1, true), err)
        end

        it("verify_step accepts a sha256 log", function()
            local filename, root_hash_before, root_hash_after = produce_valid_log("sha256")
            local ok, obtained = pcall(function()
                return cartesi.machine:verify_step(root_hash_before, filename, MCYCLE_COUNT)
            end)
            os.remove(filename)
            expect.truthy(ok, obtained)
            expect.truthy(obtained == root_hash_after)
        end)

        it("verify_step_uarch rejects a log declaring sha256", function()
            expect_sha256_rejection(function()
                local machine <close> = build_machine()
                local root_hash_before = machine:get_root_hash()
                local filename = os.tmpname()
                os.remove(filename)
                machine:log_step_uarch(1, filename)
                return filename, root_hash_before, machine:get_root_hash()
            end, function(root_hash_before, filename)
                cartesi.machine:verify_step_uarch(root_hash_before, filename, 1)
            end)
        end)

        it("verify_reset_uarch rejects a log declaring sha256", function()
            expect_sha256_rejection(function()
                local machine <close> = build_machine()
                local root_hash_before = machine:get_root_hash()
                local filename = os.tmpname()
                os.remove(filename)
                machine:log_reset_uarch(filename)
                return filename, root_hash_before, machine:get_root_hash()
            end, function(root_hash_before, filename)
                cartesi.machine:verify_reset_uarch(root_hash_before, filename)
            end)
        end)

        it("verify_send_cmio_response rejects a log declaring sha256", function()
            local data = "response"
            expect_sha256_rejection(function()
                local machine <close> = build_machine()
                machine:write_reg("iflags_Y", 1)
                local root_hash_before = machine:get_root_hash()
                local filename = os.tmpname()
                os.remove(filename)
                machine:log_send_cmio_response(1, data, BAD_HASH, filename)
                return filename, root_hash_before, machine:get_root_hash()
            end, function(root_hash_before, filename)
                cartesi.machine:verify_send_cmio_response(1, data, root_hash_before, filename, BAD_HASH)
            end)
        end)
    end)

    describe("page validation", function()
        it("rejects an empty page list", function()
            expect_corruption_error("page count is zero", function(log_data)
                log_data.pages = {}
            end)
        end)

        it("rejects page indices not in ascending order", function()
            expect_corruption_error("invalid log format: page index is not in increasing order", function(log_data)
                log_data.pages[2].index = log_data.pages[1].index
            end)
        end)

        it("rejects a non-zero page scratch hash area", function()
            expect_corruption_error("invalid log format: page scratch hash area is not zero", function(log_data)
                log_data.pages[1].scratch_hash = string.rep("\1", HASH_SIZE)
            end)
        end)

        it("rejects modified page data via initial root hash mismatch", function()
            expect_corruption_error("initial root hash mismatch", function(log_data)
                log_data.pages[1].data = string.reverse(log_data.pages[1].data)
            end)
        end)

        -- A page at index 2^52 is beyond the tree's page-index range; the
        -- walk visits root, finds nothing in range, consumes one sibling and
        -- returns -- leaving the extra page unconsumed.
        it("rejects a page with an out-of-range index", function()
            expect_corruption_error("too many pages in log", function(log_data)
                local last = log_data.pages[#log_data.pages]
                log_data.pages = {
                    {
                        index = 1 << (LOG2_ROOT_SIZE - LOG2_PAGE_SIZE),
                        data = last.data,
                        scratch_hash = last.scratch_hash,
                    },
                }
                log_data.siblings = { BAD_HASH }
            end, { root_hash_after = BAD_HASH })
        end)
    end)

    describe("root hash validation (Layer 1)", function()
        it("rejects a corrupted logged root_hash_before", function()
            expect_corruption_error("initial root hash mismatch", function(log_data)
                log_data.root_hash_before = BAD_HASH
            end, { root_hash_before = BAD_HASH })
        end)

        it("rejects a corrupted logged root_hash_after", function()
            expect_corruption_error("final root hash mismatch", function(log_data)
                log_data.root_hash_after = BAD_HASH
            end, { root_hash_after = BAD_HASH })
        end)
    end)

    describe("sibling validation", function()
        it("rejects an extra page that consumes a missing sibling slot", function()
            expect_corruption_error("too many sibling hashes in log", function(log_data)
                local last = log_data.pages[#log_data.pages]
                table.insert(log_data.pages, {
                    index = last.index + 1,
                    data = last.data,
                    scratch_hash = last.scratch_hash,
                })
            end, { root_hash_after = BAD_HASH })
        end)

        it("rejects a removed page that frees a sibling slot", function()
            expect_corruption_error("too many sibling hashes in log", function(log_data)
                table.remove(log_data.pages)
            end, { root_hash_after = BAD_HASH })
        end)

        it("rejects a removed sibling hash", function()
            expect_corruption_error("too few sibling hashes in log", function(log_data)
                table.remove(log_data.siblings)
            end, { root_hash_after = BAD_HASH })
        end)

        it("rejects an extra sibling hash", function()
            expect_corruption_error("too many sibling hashes in log", function(log_data)
                table.insert(log_data.siblings, BAD_HASH)
            end, { root_hash_after = BAD_HASH })
        end)

        it("rejects a modified sibling hash via initial root hash mismatch", function()
            expect_corruption_error("initial root hash mismatch", function(log_data)
                log_data.siblings[1] = BAD_HASH
            end, { root_hash_after = BAD_HASH })
        end)

        it("rejects an empty sibling list", function()
            expect_corruption_error("too few sibling hashes in log", function(log_data)
                log_data.siblings = {}
            end, { root_hash_after = BAD_HASH })
        end)
    end)

    describe("node validation", function()
        -- A uarch step writes only pages, so it consumes no nodes. Converting a sibling
        -- subtree into an unchanged node keeps the pre-state root identical but leaves a
        -- node no write consumes; its hash_after is folded into the post-state root
        -- verbatim, so the replayer must reject it.
        it("rejects an unconsumed subtree-write node", function()
            expect_corruption_error("unconsumed node in step log", function(log_data)
                test_util.inject_unconsumed_node(log_data)
            end)
        end)

        -- The following inject a structurally invalid node; decode validates nodes and the
        -- pages+nodes disjointness before recomputing the root, so each is rejected at parse.
        it("rejects a node whose log2 size is out of range", function()
            expect_corruption_error("node log2 size out of range", function(log_data)
                log_data.nodes = {
                    { address = 0, log2_size = LOG2_ROOT_SIZE + 1, hash_before = BAD_HASH, hash_after = BAD_HASH },
                }
            end)
        end)

        it("rejects a node whose address is not aligned to its size", function()
            expect_corruption_error("node address not aligned to its size", function(log_data)
                log_data.nodes = {
                    {
                        address = PAGE_SIZE,
                        log2_size = LOG2_PAGE_SIZE + 1,
                        hash_before = BAD_HASH,
                        hash_after = BAD_HASH,
                    },
                }
            end)
        end)

        it("rejects a node overlapping a witnessed page", function()
            expect_corruption_error("page or node overlaps a previous entry", function(log_data)
                -- A two-page-aligned node covering the first witnessed page's pair overlaps it.
                local pair_index = log_data.pages[1].index & ~1
                log_data.nodes = {
                    {
                        address = pair_index << LOG2_PAGE_SIZE,
                        log2_size = LOG2_PAGE_SIZE + 1,
                        hash_before = BAD_HASH,
                        hash_after = BAD_HASH,
                    },
                }
            end)
        end)
    end)

    describe("interpret: adversarial log with missing page", function()
        -- An attacker can produce a log where pages + siblings hash to the
        -- agreed root, yet a page the interpreter needs is absent. The
        -- constructor accepts the log; find_page must reject it during replay.
        it("rejects a log with a required page omitted", function()
            local filename, root_hash_before = produce_valid_log()
            local log = test_util.read_step_log_file(filename)
            os.remove(filename)

            assert(#log.pages >= 2, "test needs a machine that produces at least 2 pages per step")

            table.remove(log.pages)
            local kept_indices = {}
            for i, p in ipairs(log.pages) do
                kept_indices[i] = p.index
            end
            local fresh <close> = build_machine()
            log.siblings = get_siblings_for_pages(fresh, kept_indices)

            local adversarial = os.tmpname()
            os.remove(adversarial)
            test_util.write_step_log_file(log, adversarial)
            local ok, err = pcall(function()
                cartesi.machine:verify_step(root_hash_before, adversarial, MCYCLE_COUNT)
            end)
            os.remove(adversarial)
            expect.falsy(ok)
            expect.truthy(err and err:find("required page not found", 1, true), err)
        end)
    end)

    describe("interpret: corrupted PMA data", function()
        it("rejects a log with invalid PMA entries", function()
            local filename = produce_valid_log()
            local log = test_util.read_step_log_file(filename)
            os.remove(filename)
            local hash_fn = log.hash_function == 0 and "keccak256" or "sha256"

            local pma_page_index = cartesi.AR_PMAS_START >> LOG2_PAGE_SIZE
            local pma_pos
            for i, p in ipairs(log.pages) do
                if p.index == pma_page_index then
                    pma_pos = i
                    break
                end
            end
            assert(pma_pos, "PMA page not found in log -- machine config must touch it")

            log.pages[pma_pos].data = string.rep("\xff", PAGE_SIZE)

            -- Walk corrupted PMA page up to root, picking siblings from a
            -- pristine machine to keep the merkle tree self-consistent.
            local fresh <close> = build_machine()
            local pma_addr = pma_page_index << LOG2_PAGE_SIZE
            local node_hash = test_util.merkle_hash(log.pages[pma_pos].data, 0, LOG2_PAGE_SIZE, hash_fn)
            for log2_size = LOG2_PAGE_SIZE, LOG2_ROOT_SIZE - 1 do
                local bit = 1 << log2_size
                local sibling_addr = (pma_addr ~ bit) & ~(bit - 1)
                local sibling = fresh:get_node_hash(sibling_addr, log2_size)
                if (pma_addr & bit) ~= 0 then
                    node_hash = cartesi[hash_fn](sibling, node_hash)
                else
                    node_hash = cartesi[hash_fn](node_hash, sibling)
                end
            end
            local new_root = node_hash

            local indices = {}
            for i, p in ipairs(log.pages) do
                indices[i] = p.index
            end
            log.root_hash_before = new_root
            log.siblings = get_siblings_for_pages(fresh, indices)

            local adversarial = os.tmpname()
            os.remove(adversarial)
            test_util.write_step_log_file(log, adversarial)
            local ok, err = pcall(function()
                cartesi.machine:verify_step(new_root, adversarial, MCYCLE_COUNT)
            end)
            os.remove(adversarial)
            expect.falsy(ok)
            expect.truthy(err and err:find("when initializing", 1, true), err)
        end)
    end)
end)
