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

-- Replay the shared Solidity reject corpus with the C++ host verifier. A wrong
-- post-root is a rejected caller claim, not an exception from the verifier itself.
local cartesi = require("cartesi")
local lester = require("cartesi.third-party.lester")
local manifest = require("cartesi.tests.step_log_manifest")
local reject_errors = require("cartesi.tests.reject_fixture_errors")
local tests_util = require("cartesi.tests.util")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local fixtures = tests_util.reject_fixtures_path

local function hash(hex)
    return cartesi.fromhex(hex)
end

local function replay(row, log)
    local before = hash(row.rootHashBefore)
    if row.kind == "cycle" then
        return cartesi.machine:verify_step_uarch(before, log, tonumber(row.requestedCycleCount))
    elseif row.kind == "reset_uarch" then
        return cartesi.machine:verify_reset_uarch(before, log)
    elseif row.kind == "send_cmio_response" then
        local length = assert(tonumber(row.dataLength))
        local data = length == 0 and "" or row.data:rep(math.ceil(length / #row.data)):sub(1, length)
        return cartesi.machine:verify_send_cmio_response(
            tonumber(row.reason),
            data,
            before,
            log,
            hash(row.revertRootHash)
        )
    end
    error("unmapped reject fixture kind: " .. row.kind)
end

-- Wrong-after rows use a valid transition with a forged claim. Pin the obtained
-- result to independently recorded truth, not merely inequality with the claim.
local function true_after(row)
    if row.kind == "cycle" then
        return manifest.read_claims(fixtures .. "uarch-tests-per-cycle/rv64ui-uarch-add", "00000.log").after
    elseif row.kind == "reset_uarch" then
        return manifest.read_claims(fixtures .. "reset-uarch", "reset-uarch.log").after
    elseif row.name == "cmio_iflags_cleared.log" then
        -- This case changes the pre-state to make CMIO a no-op; its exact result
        -- is the refolded pre-root, not the original yielding machine's result.
        return hash(row.rootHashBefore)
    end
    return manifest.read_claims(fixtures .. "send-cmio-response", "send-cmio-response-1.log").after
end

describe("shared reject fixtures", function()
    local families = { "reject-uarch", "reject-send-cmio-response" }
    -- The installed tests package does not include the make-generated corpus.
    if not tests_util.file_exists(fixtures .. "reject-uarch/_manifest.csv") then
        for _, family in ipairs(families) do
            it(family .. " (fixtures unavailable)", function() end, false)
        end
        return
    end
    for _, family in ipairs(families) do
        local dir = fixtures .. family
        local rows = manifest.read_rows(dir)
        assert(#rows > 0, "empty reject manifest: " .. dir)
        for _, row in ipairs(rows) do
            it(family .. "/" .. row.name .. " rejects " .. row.expectError, function()
                local error_spec = assert(reject_errors.errors[row.expectError], "unmapped reject tag")
                assert(error_spec.cpp_pattern and error_spec.solidity_signature and error_spec.solidity_message)
                local src <close> = assert(io.open(dir .. "/" .. row.name, "rb"))
                local log = assert(src:read("a"))
                local obtained
                local ok, err = pcall(function()
                    local after = replay(row, log)
                    obtained = after
                    assert(after == hash(row.rootHashAfter), "root hash after does not match claimed hash")
                end)
                if row.expectError == "root_after_mismatch" then
                    expect.equal(obtained, true_after(row))
                end
                expect.falsy(ok, "reject fixture was accepted")
                assert(err and err:find(error_spec.cpp_pattern, 1, true), err)
            end)
        end
    end
end)

os.exit(lester.report())
