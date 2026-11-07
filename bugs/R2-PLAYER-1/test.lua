#!/usr/bin/env lua5.4
-- R2-PLAYER-1: in one prt-player process, every epoch's dispute bridge shares the same signer and the same
-- transaction journal (doc/recipes/prt-player.lua open_epochs), no listener is ever dropped, and pass() ticks
-- every sealed epoch's bridge in epoch order and repeats at once after any publication. bridge:tick()
-- (doc/recipes/prt-bridge.lua) reads journal:pending(signer), i.e. the newest candidate at the account's next
-- nonce whichever epoch signed it, and compares it only with its OWN epoch's due jobs. An older, settled epoch
-- (no due job) therefore cancels the newer epoch's pending joinTournament with a self-transfer at the same nonce;
-- the newer bridge sees its job's candidate as obsolete and re-publishes; submit() (prt-transactions.lua) bumps
-- both fees by bump_percent on each action change and never waits, so the two bridges alternate until fees()
-- hits the fee ceiling. The last publication wins the nonce, and at a 10 gwei base fee with the default limits
-- that is always the cancel. The honest claim never joins its tournament before the window closes.
--
-- Threat model: R4 / section 1 completeness failure (the honest operator cannot respond in time), A7 (clocks are
-- sized for the honest operator's own moves, not for it fighting itself), section 2 honest operator's path.
--
-- The test runs the REAL prt-transactions journal and the REAL prt-bridge tick/attempt/cancel code. As
-- prt-bridge-test.lua does, it overrides only each bridge's observe/jobs/prepare. A fake node implements the
-- RPCs the journal uses, holds one transaction per nonce in its pool with geth's replacement rule (both fees
-- bumped by at least 10%), and mines what it holds at the account's next nonce once per block. Between blocks
-- the player loop is modelled exactly as prt-player.lua's main loop: pass() ticks every sealed epoch's bridge
-- in epoch order and passes again at once while a pass published (status.published) or must retry.
--
-- Correct behaviour asserted (exit 0 once fixed):
--   1. the honest joinTournament of epoch 1 is mined before its window closes, as it is with epoch 1 alone;
--   2. epoch 0's bridge never cancels or replaces a transaction that epoch 1's bridge signed.
package.path = "./vendor/?.lua;" .. package.path
local json = require("dkjson")
local prt = require("prt")
local bridge = require("prt-bridge")
local transactions = require("prt-transactions")

local GWEI = 1000000000
local geometry = prt.new_geometry(10)
local signer = { address = "0x00000000000000000000000000000000000000aa" }
local TOURNAMENT = "0x00000000000000000000000000000000000000bb"

-- Runs one scenario: epochs is a list of { label, has_join } in epoch order. Returns the per-block log.
local function scenario(base_fee, epochs, blocks, window)
    local tip = 100
    local function tip_hash(n)
        return string.format("0x%064x", 0x1000000 + (n or tip))
    end
    local mined, receipts, by_hash, signed, pool = 0, {}, {}, {}, {}
    local join_mined_at
    local publications = {}
    local chain = {}
    function chain.rpc(_, method, params)
        if method == "eth_chainId" then
            return "0x1"
        elseif method == "eth_getBlockByNumber" then
            if params[1] == "0x0" then
                return { hash = tip_hash(0), number = "0x0" }
            end
            return {
                number = string.format("0x%x", tip),
                hash = tip_hash(),
                baseFeePerGas = string.format("0x%x", base_fee),
                gasLimit = "0x1c9c380",
            }
        elseif method == "eth_getTransactionCount" then
            return string.format("0x%x", mined)
        elseif method == "eth_getTransactionReceipt" then
            return receipts[params[1]] or json.null
        elseif method == "eth_maxPriorityFeePerGas" then
            return "0x1"
        elseif method == "eth_estimateGas" then
            return "0x5208"
        elseif method == "eth_getTransactionByHash" then
            return by_hash[params[1]] and {} or json.null
        end
        error("unexpected rpc " .. method)
    end
    function chain.head()
        return tip, tip_hash(), tip, tip_hash()
    end
    function chain.is_canonical()
        return true
    end
    function chain.simulate()
        return "0x"
    end
    local counter = 0
    function chain.sign(_, _, candidate)
        counter = counter + 1
        local raw, hash = string.format("0x02%064x", counter), string.format("0x%064x", counter)
        signed[raw] = candidate
        return raw, hash
    end
    function chain.verify_signed(_, _, candidate)
        return candidate.hash
    end
    -- The node's pool holds one transaction per nonce. A different transaction at a held nonce replaces it only
    -- when it raises both fee fields by at least 10% (geth's default price bump).
    function chain.publish(_, raw)
        local candidate = assert(signed[raw], "unknown raw transaction")
        local held = pool[candidate.nonce]
        if held and held.hash ~= candidate.hash then
            local fee, held_fee = tonumber(candidate.max_fee), tonumber(held.max_fee)
            local tip_fee, held_tip = tonumber(candidate.priority_fee), tonumber(held.priority_fee)
            if fee * 10 < held_fee * 11 or tip_fee * 10 < held_tip * 11 then
                return nil, { code = -32000, message = "replacement transaction underpriced" }
            end
            by_hash[held.hash] = nil
        end
        pool[candidate.nonce], by_hash[candidate.hash] = candidate, true
        publications[#publications + 1] = candidate
        return candidate.hash
    end
    local path = os.tmpname()
    os.remove(path)
    local journal = transactions.new({ chain = chain, path = path })

    local join = {
        key = "0xroot1:0x0:joinTournament:honest",
        kind = "joinTournament",
        first = 0,
        last = tip + 1 + window,
        context = { address = "0xroot1" },
        event = { log = { blockHash = tip_hash(), logIndex = "0x0" } },
        root = "0xclaim",
    }
    -- The bridges of one prt-player process: one per sealed epoch, in epoch order, sharing journal and signer.
    local bridges = {}
    for _, e in ipairs(epochs) do
        local b = bridge.new({
            geometry = geometry,
            chain = chain,
            transactions = journal,
            abi = {},
            root = e.label,
            factory = "factory",
            consensus = "consensus",
            player = {},
            signer = signer,
            label = e.label,
        })
        function b.observe()
            return { head = tip, hash = tip_hash(), tip = tip, tip_hash = tip_hash(), ready = true, order = {} }
        end
        function b.jobs()
            -- A settled epoch has no job. The newer epoch must join until its join is observed on chain.
            if e.has_join and not join_mined_at then
                return { join }
            end
            return {}
        end
        function b.prepare()
            return { signer = signer, to = TOURNAMENT, data = "0x1234", value = "0" }
        end
        b.epoch_label = e.label
        bridges[#bridges + 1] = b
    end
    -- prt-player.lua's pass(): tick every sealed epoch's bridge in order.
    local function pass()
        local published, retry = false, false
        for _, b in ipairs(bridges) do
            local snapshot, did = b:tick()
            published = published or did
            retry = retry or snapshot == nil
        end
        return published or retry
    end

    local log = { blocks = {}, foreign_cancels = 0 }
    local stderr = io.stderr
    io.stderr = { write = function() end } -- silence the bridges' "fee ceiling" chatter
    for _ = 1, blocks do
        publications = {}
        -- The player loop passes again at once while a pass published; the next block comes after it settles.
        local passes = 0
        repeat
            passes = passes + 1
        until not pass() or passes >= 500
        -- Which bridges published, in order, and whether a cancel replaced the join (a foreign replacement).
        local actions = {}
        for i, c in ipairs(publications) do
            actions[#actions + 1] = c.action
            if c.action == "cancel" and i > 1 and publications[i - 1].action == "joinTournament" then
                log.foreign_cancels = log.foreign_cancels + 1
            end
        end
        -- Mine the block: it includes what the node holds at the account's next nonce.
        tip = tip + 1
        local held = pool[mined]
        local entry = { block = tip, passes = passes, publications = #publications, actions = actions }
        if held then
            receipts[held.hash] = {
                transactionHash = held.hash,
                blockNumber = string.format("0x%x", tip),
                blockHash = tip_hash(),
                status = "0x1",
            }
            entry.mined, entry.fee = held.action, held.max_fee
            if held.action == "joinTournament" and not join_mined_at then
                join_mined_at = tip
            end
            pool[mined] = nil
            mined = mined + 1
        end
        log.blocks[#log.blocks + 1] = entry
        if join_mined_at then
            break
        end
    end
    io.stderr = stderr
    os.remove(path)
    log.join_mined_at, log.join_last = join_mined_at, join.last
    log.mined_cancels = 0
    for _, entry in ipairs(log.blocks) do
        if entry.mined == "cancel" then
            log.mined_cancels = log.mined_cancels + 1
        end
    end
    return log
end

local WINDOW = 10
-- Control: epoch 1's bridge alone lands the join in the first block.
local alone = scenario(10 * GWEI, { { label = "epoch1", has_join = true } }, WINDOW, WINDOW)
print(
    string.format(
        "control (epoch 1 alone, 10 gwei): join mined at block %s (window closes at %d)",
        tostring(alone.join_mined_at),
        alone.join_last
    )
)
assert(alone.join_mined_at, "harness error: a single bridge did not land its join")

-- The documented prt-player: epoch 0 (settled, no job) and epoch 1 (must join) in one process.
local both = scenario(10 * GWEI, { { label = "epoch0" }, { label = "epoch1", has_join = true } }, WINDOW, WINDOW)
for _, entry in ipairs(both.blocks) do
    print(
        string.format(
            "block %d: %d passes, %d publications [%s], mined %s at max fee %.1f gwei",
            entry.block,
            entry.passes,
            entry.publications,
            table.concat(entry.actions, ","),
            tostring(entry.mined),
            (tonumber(entry.fee) or 0) / GWEI
        )
    )
end

-- Informative sweep: how often, across base fees, the shared journal lets epoch 0's cancel win the nonce.
local lost = {}
for gwei = 1, 40 do
    local r = scenario(gwei * GWEI, { { label = "epoch0" }, { label = "epoch1", has_join = true } }, 3, 3)
    if not r.join_mined_at then
        lost[#lost + 1] = tostring(gwei)
    end
end
print("base fees (gwei, 1..40) at which the join never lands in 3 blocks: " .. table.concat(lost, " "))

local failures = {}
if not both.join_mined_at then
    failures[#failures + 1] = string.format(
        "the honest joinTournament of epoch 1 was never mined before its window closed at block %d "
            .. "(%d of %d mined transactions were epoch 0's self-transfer cancels)",
        both.join_last,
        both.mined_cancels,
        #both.blocks
    )
end
if both.foreign_cancels > 0 then
    failures[#failures + 1] = string.format(
        "epoch 0's settled bridge cancelled epoch 1's pending join %d times through the shared journal",
        both.foreign_cancels
    )
end
if #failures > 0 then
    print("FAIL R2-PLAYER-1: " .. table.concat(failures, "; "))
    os.exit(1)
end
print("OK: the join lands and no older epoch touches a newer epoch's transaction")
