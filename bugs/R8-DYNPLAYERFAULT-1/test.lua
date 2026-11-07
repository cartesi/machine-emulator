-- R8-DYNPLAYERFAULT-1: the honest bridge's signer wedges for good once its journal holds, at the chain nonce, a
-- candidate that the node does not have and that sits within bump_percent (15%) of the fee or tip ceiling, and the
-- job of that candidate is no longer due.
--
-- prt-transactions submit() derives every replacement's fees from the last journaled candidate of the chain nonce
-- (fees(): priority >= ceil(prev.priority*1.15), fee >= ceil(prev.max_fee*1.15)) and returns nil above the
-- default ceilings (max_fee 100 gwei, max_priority_fee 10 gwei). On nil it only rebroadcasts the stored bytes for
-- the SAME job; a different due job, and the cancel, both get { blocked = "fee ceiling" }. nonce_record() pins all
-- new work to that nonce, which only a mined candidate releases. So when nobody holds the stuck candidate, nothing
-- can ever mine the nonce, whatever the current fees are.
--
-- The test drives the real prt-bridge tick and prt-transactions journal (doc/recipes) on an in-memory EIP-1559 node
-- (mockchain.lua: nonces, blocks, finalized tag, receipts, eth_getTransactionByHash, eth_sendRawTransaction with the
-- geth 10% replacement rule, mining of affordable transactions). Only the bridge's observation (refresh/jobs/prepare)
-- is stubbed, to present two jobs:
--   1. Process 1 answers job A during a fee spike (base fee 50 gwei -> candidate signed at max_fee = 100 gwei; or a
--      9 gwei tip suggestion -> priority 9 gwei, max_fee 11 gwei).
--   2. The candidate never reaches the node: the process dies (or eth_sendRawTransaction's HTTP exchange fails, which
--      prt-cast raises) right after the journal store; or the publication succeeds and the node then loses its mempool.
--   3. The spike ends (1 gwei base fee and tip). Job A's window closes; job B is due for 200 blocks.
--   4. Process 2 is relaunched from journal.json and ticks once per healthy block until B's deadline.
-- Correct behavior (R4 honest completeness, A7: the honest move must be sent within the clocks; section 1 completeness
-- failure otherwise): job B is mined before its deadline. On feature/prt-audit it is never mined: every tick reports
-- "fee ceiling", the chain nonce stays at 0, and the test exits 1.
-- Two controls must recover (20 gwei spike with mempool loss; 9 gwei tip without loss); if they do not, the harness is
-- broken and the test exits 2.
package.path = "./?.lua;./vendor/?.lua;" .. package.path
local mock = require("mockchain")
local transactions = require("prt-transactions")
local bridge = require("prt-bridge")

local GWEI = 1000000000
local function sh(cmd)
    local p = assert(io.popen(cmd))
    local out = p:read("a")
    p:close()
    return (out:gsub("%s+$", ""))
end
local tmp = sh("mktemp -d")

local function job(key, first, last)
    return {
        key = key,
        kind = "advanceMatch",
        root = "0xc1",
        first = first,
        last = last,
        context = { address = "0x00000000000000000000000000000000000000bb" },
        event = { log = { blockHash = "0x" .. key, logIndex = "0x0" } },
    }
end

-- variant: kill | drop | priority-drop | control | priority
local function scenario(variant)
    local dir = tmp .. "/" .. variant
    os.execute("mkdir -p '" .. dir .. "'")
    local chain = mock.new({ base_fee = 1 * GWEI, tip_suggestion = 1 * GWEI })
    local signer = { address = "0x00000000000000000000000000000000000000aa" }
    for _ = 1, 100 do
        chain:mine()
    end
    local jobs_now = {}
    local function launch()
        local manager = transactions.new({ chain = chain, path = dir .. "/journal.json" })
        local b = bridge.new({
            chain = chain,
            abi = {},
            root = "0xroot",
            factory = "0xf",
            consensus = "0xc",
            geometry = {},
            transactions = manager,
            player = {},
            signer = signer,
            label = "honest",
            epoch = 1,
        })
        -- Stubbed observation: a ready snapshot 4 blocks behind the tip and the jobs the referee authorizes.
        b.refresh = function()
            local head, hash, tip, tip_hash = chain:head(4)
            return { head = head, hash = hash, tip = tip, tip_hash = tip_hash, ready = true }
        end
        b.jobs = function()
            local list = {}
            for _, j in ipairs(jobs_now) do
                if not chain.done[j.key] then
                    list[#list + 1] = j
                end
            end
            return list
        end
        b.prepare = function(_, j)
            return { signer = signer, to = j.context.address, data = "0x" .. string.format("%02x", #j.key) .. j.key }
        end
        return b, manager
    end

    -- Process 1: job A at the fee spike.
    if variant == "priority" or variant == "priority-drop" then
        chain.tip_suggestion = 9 * GWEI
    elseif variant == "control" then
        chain.base_fee = 20 * GWEI
    else
        chain.base_fee = 50 * GWEI
    end
    chain:mine()
    local t0 = chain:tip()
    jobs_now = { job("aaaa", 0, t0 + 6) }
    local p1, m1 = launch()
    if variant == "kill" then
        -- SIGKILL, or the eth_sendRawTransaction HTTP exchange failing (prt-cast raises), after the journal store.
        chain.publish_hook = function()
            error("process died before eth_sendRawTransaction reached the node", 0)
        end
    end
    local ok1 = pcall(p1.tick, p1)
    chain.publish_hook = nil
    local a = m1:pending(signer.address)
    assert(a and a.job == "aaaa", "harness: process 1 did not journal a candidate for job A")
    if variant == "kill" then
        assert(not ok1, "harness: process 1 was expected to die during publication")
    end
    if variant == "drop" or variant == "priority-drop" or variant == "control" then
        chain:drop_mempool() -- the node restarts and loses its mempool
    end
    local a_max_fee, a_priority = tonumber(a.max_fee), tonumber(a.priority_fee)

    -- The spike ends; A's window closes and job B is due for 200 blocks.
    chain.base_fee, chain.tip_suggestion = 1 * GWEI, 1 * GWEI
    for _ = 1, 8 do
        chain:mine()
    end
    local t1 = chain:tip()
    local deadline = t1 + 200
    jobs_now = { job("aaaa", 0, t0 + 6), job("bbbb", 0, deadline) }

    -- Process 2: relaunched from the journal, ticks once per healthy block.
    local p2, m2 = launch()
    local errors = {}
    while chain:tip() + 1 < deadline do
        local ok, err = pcall(p2.tick, p2)
        if not ok then
            errors[#errors + 1] = tostring(err)
        end
        if chain.done.bbbb then
            break
        end
        chain:mine()
    end
    local pending = m2:pending(signer.address)
    return {
        variant = variant,
        mined = chain.done.bbbb,
        deadline = deadline,
        tip = chain:tip(),
        nonce = chain:nonce_of(signer.address, chain:tip()),
        blocked = p2.blocked.honest,
        a_max_fee = a_max_fee,
        a_priority = a_priority,
        pending_job = pending and pending.job,
        pending_in_node = pending and (chain.mempool[pending.hash] ~= nil),
        errors = errors,
    }
end

local function describe(r)
    return string.format(
        "%s: A signed at max_fee=%.0f gwei tip=%.0f gwei; job B %s (deadline %d, tip %d); chain nonce=%d; blocked=%s;"
            .. " journal pending job=%s in node=%s; tick errors=%d",
        r.variant,
        r.a_max_fee / GWEI,
        r.a_priority / GWEI,
        r.mined and ("mined at " .. r.mined) or "NEVER mined",
        r.deadline,
        r.tip,
        r.nonce,
        tostring(r.blocked),
        tostring(r.pending_job),
        tostring(r.pending_in_node),
        #r.errors
    )
end

local results = {}
for _, v in ipairs({ "control", "priority", "kill", "drop", "priority-drop" }) do
    local r = scenario(v)
    results[v] = r
    print(describe(r))
    if #r.errors > 0 then
        print("  first tick error: " .. r.errors[1])
    end
end
os.execute("rm -rf '" .. tmp .. "'")

for _, v in ipairs({ "control", "priority" }) do
    local r = results[v]
    if not r.mined or #r.errors > 0 then
        print("HARNESS ERROR: control variant " .. v .. " did not recover; the mock does not model a healthy node")
        os.exit(2)
    end
end
local wedged = {}
for _, v in ipairs({ "kill", "drop", "priority-drop" }) do
    local r = results[v]
    if not r.mined then
        if #r.errors > 0 or r.blocked ~= "fee ceiling" then
            print("HARNESS ERROR: " .. v .. " failed for an unexpected reason")
            os.exit(2)
        end
        wedged[#wedged + 1] = v
    end
end
if #wedged > 0 then
    print(
        "FAIL: honest signer wedged in ["
            .. table.concat(wedged, ", ")
            .. "]: a journaled candidate the node never holds, within 15% of the fee/tip ceiling, blocks every later"
            .. " job and the cancel with 'fee ceiling'; the nonce never advances at a 1 gwei base fee, so job B misses"
            .. " its deadline (R4/A7 completeness)"
    )
    os.exit(1)
end
print("OK: the honest signer recovers and job B is mined before its deadline in every variant")
os.exit(0)
