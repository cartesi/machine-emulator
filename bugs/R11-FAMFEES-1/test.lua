#!/usr/bin/env lua5.4
-- R11-FAMFEES-1: the bridge signs gas = ceil(1.2 * eth_estimateGas(latest)) for joinTournament and
-- winMatchByTimeout (doc/recipes/prt-transactions.lua submit, lines 206-215) with no floor from the action's
-- worst case. Both calls end in the Tournament's pairCommitment. With no dangling commitment at estimation
-- time it is one SSTORE; if any participant joined first, it is Match.create (new Match.State slots, clock
-- start, matchCount, MatchCreated), about 35-65% more gas than the estimate, more than the 20% margin. The
-- honest transaction then reverts out of gas, its nonce is consumed, and the bridge treats the reverted
-- receipt like a successful one (it never reads receipt.status): submit() holds the job back until the
-- observation head (tip - 4) reaches the receipt block, so the resend comes only after the observation depth.
--
-- Threat model: section 1 completeness failure (the honest operator cannot respond in time), A7 (clocks sized
-- for the logarithmic number of matches, not for a delay per Sybil join), R12, the honest operator's path
-- (section 2), section 7 (race and reorder transactions, any number of Sybils). A Sybil join ordered ahead of
-- the honest one in the same block flips the branch; repeating it each round charges the honest clock.
--
-- What it checks, in two parts:
--  1. Gas needed, measured on the pinned Dave v3.0.0-alpha.6 Tournament.sol (compiled with solc 0.8.30 viaIR,
--     OpenZeppelin 5.5.0) executed in ethereumjs (evm/measure.mjs, artifacts in evm/build.json). It runs live
--     when node and an ethereumjs node_modules are found (env NM, evm/node_modules, or the audit scratchpad);
--     otherwise it reads the measurements this script recorded (measured-gas.json). Solidity is not run
--     on a real chain, only in ethereumjs (non-executable on-chain, see evm/measure.mjs).
--  2. The UNMODIFIED doc/recipes/prt-transactions.lua is driven against a mock chain whose eth_estimateGas
--     returns the measured no-dangling estimate. We read the gas it signs, then mine a status-0 (reverted)
--     receipt and count how long submit() withholds the resend.
--
-- Correct behavior: the signed gas covers the gas the call needs on the pairing branch (so a concurrent or
-- front-running join cannot make the honest transaction run out of gas), for every scenario. Exit 1 while
-- the signed gas is below it.
package.path = "./vendor/?.lua;" .. package.path
local json = require("dkjson")

local function sh(cmd)
    local p = io.popen(cmd .. " 2>&1")
    local out = p:read("a")
    local ok = p:close()
    return out, ok
end

local function exists(path)
    local f = io.open(path, "r")
    if f then f:close() end
    return f ~= nil
end

-- Part 1: gas measurements.
local measurements, source
do
    local candidates = {}
    if os.getenv("NM") then candidates[#candidates + 1] = os.getenv("NM") end
    for _, c in ipairs({
        "./evm/node_modules",
        "/tmp/claude-0/-home-user-machine-emulator/de7f2d82-674a-5aff-b14e-44f5364dae6f/scratchpad/evm/node_modules",
    }) do candidates[#candidates + 1] = c end
    for _, nm in ipairs(candidates) do
        if nm and exists(nm .. "/@ethereumjs/evm/dist/esm/index.js") and sh("command -v node >/dev/null && echo y"):find("y") then
            local out, ok = sh("cd evm && NM='" .. nm .. "' node measure.mjs")
            local decoded = ok and json.decode(out:match("(%[.*%])"))
            if decoded then
                measurements, source = decoded, "live ethereumjs run of the pinned Tournament.sol"
                break
            end
        end
    end
    if not measurements then
        local f = assert(io.open("measured-gas.json"))
        measurements, source = assert(json.decode(f:read("a"))), "recorded measurements (measured-gas.json)"
        f:close()
    end
end
print("gas measurements: " .. source)

-- Part 2: the bridge's transaction layer, unmodified, on a mock chain.
local function drive(estimate)
    local tip, receipts, signed, nonce = 16, {}, nil, 0
    local function hash(n) return "0x" .. string.format("%064x", n) end
    local chain = {}
    function chain.rpc(_, method, params)
        if method == "eth_chainId" then return "0x1" end
        if method == "eth_getBlockByNumber" then
            return { number = string.format("0x%x", tip), hash = hash(tip), baseFeePerGas = "0x3b9aca00", gasLimit = "0x3938700" }
        end
        if method == "eth_getTransactionCount" then return string.format("0x%x", nonce) end
        if method == "eth_maxPriorityFeePerGas" then return "0x3b9aca00" end
        if method == "eth_estimateGas" then return string.format("0x%x", estimate) end
        if method == "eth_getTransactionReceipt" then return receipts[params[1]] or json.null end
        error("unexpected " .. method)
    end
    function chain.simulate() return "0x", nil end
    function chain.is_canonical() return true end
    function chain.head() return tip, hash(tip) end
    function chain.sign(_, _, tx) signed = tx; return "0x02aa", hash(0xcd) end
    function chain.publish() return hash(0xcd) end
    local path = os.tmpname(); os.remove(path)
    local tx = require("prt-transactions").new({ chain = chain, path = path })
    local signer = { address = "0x" .. string.rep("11", 20) }
    local job = { key = "job", kind = "joinTournament", first = 0, last = 100000, to = "0x" .. string.rep("22", 20), data = "0x00", value = "1" }
    local r = tx:submit(signer, job, { head = tip - 4, hash = hash(tip - 4) })
    assert(r.published, "first submission was not published")
    local gas = signed.gas
    -- Mined at block 17 with status 0 (out of gas): the nonce is consumed.
    tip, nonce = 17, 1
    receipts[hash(0xcd)] = { transactionHash = hash(0xcd), blockNumber = "0x11", blockHash = hash(17), status = "0x0" }
    local waited = 0
    while waited < 50 do
        tip = tip + 1
        local result = tx:submit(signer, job, { head = tip - 4, hash = hash(tip - 4) })
        if result.published then break end
        assert(result.waiting, "unexpected submit result")
        waited = waited + 1
    end
    os.remove(path)
    return gas, waited
end

local failures = {}
for _, m in ipairs(measurements) do
    local gas, waited = drive(m.estimate_no_dangling)
    assert(gas == m.bridge_gas_limit, string.format("bridge gas %d differs from the measured model %d", gas, m.bridge_gas_limit))
    local covers = gas >= m.needed_after_sybil_join
    print(string.format(
        "%-18s height %2d: estimate(no dangling) %d -> bridge signs %d; needed once a Sybil joined first %d (%s); "
            .. "honest tx with the signed gas after the front-run: %s (with the needed gas: %s); resend withheld %d blocks after the status-0 receipt",
        m.name, m.height, m.estimate_no_dangling, gas, m.needed_after_sybil_join, covers and "covered" or "OUT OF GAS",
        m.honest_tx_with_bridge_gas_after_sybil_join, m.honest_tx_with_needed_gas_after_sybil_join, waited))
    if not covers then
        failures[#failures + 1] = string.format("%s(h=%d): signed %d < needed %d", m.name, m.height, gas, m.needed_after_sybil_join)
    end
end

if #failures > 0 then
    io.stderr:write(
        "FAIL R11-FAMFEES-1: prt-transactions.lua signs ceil(1.2 * estimate at latest) with no worst-case floor, so an honest "
            .. "joinTournament/winMatchByTimeout whose pairing branch is triggered by a front-running Sybil join runs out of gas "
            .. "(its nonce is consumed and the bridge resends only after the observation depth): "
            .. table.concat(failures, "; ") .. "\n")
    os.exit(1)
end
print("OK: the signed gas covers the pairing branch in every scenario")
