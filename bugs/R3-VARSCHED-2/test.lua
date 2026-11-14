-- R3-VARSCHED-2: the PRT transaction journal (doc/recipes/prt-transactions.lua) cannot re-price a pending honest
-- move once the move's priority fee has reached --max-priority-fee. methods:fees refuses any replacement whose
-- 15%-bumped priority exceeds the priority cap, even when the max fee needed for inclusion is far below --max-fee;
-- methods:submit then returns blocked = "fee_ceiling" while the node still holds the old candidate. If the base fee
-- rises above that candidate's max fee, the honest move can be neither included nor replaced at its nonce.
--
-- The test drives the real journal over a mock chain (no network, no emulator) in two scenarios:
--   A. the node suggests a tip >= the cap (10 gwei by default) when the move is first signed;
--   B. a move first signed at a 1 gwei tip on a 1 gwei base fee is out-tipped for many blocks, so the journal's
--      own bumps raise its priority to within 15% of the cap, and then the base fee rises.
-- In both, it then raises the base fee to 40 gwei (above the frozen max fee, below --max-fee = 100 gwei) and asserts
-- that the journal publishes, at the same nonce, a replacement that the chain can include at the current base fee
-- (max fee >= base + priority, max fee <= --max-fee) and that a node accepts as a replacement (both fees raised by at
-- least the pool's 10% price bump). It exits 1 while the journal answers "fee_ceiling" instead.
local harness = require("harness")

harness.main(function()
    local json = require("dkjson")
    local evmu = require("cartesi.evmu")
    local journal = require("prt-transactions")
    local GWEI = 1000000000
    local MAX_FEE = 100 * GWEI -- the journal's (and crisium's) default --max-fee
    local MAX_PRIORITY = 10 * GWEI -- default --max-priority-fee

    local tmp = os.getenv("TMPDIR") or "/tmp"
    local ok, out = harness.sh("mktemp -d " .. tmp .. "/r3-varsched-2.XXXXXX")
    local dir = ok and out and out:gsub("%s+$", "")
    if not dir or dir == "" then
        harness.setup_error("mktemp failed")
    end

    local function block_hash(n)
        return string.format("0x%064x", n)
    end

    -- A mock node: every block has the configured base fee, nothing of ours is ever included (the account nonce
    -- stays 0), and the node keeps every published candidate in its pool.
    local function new_chain(state)
        local chain = {}
        function chain.head()
            return state.tip, block_hash(state.tip)
        end
        function chain.is_canonical()
            return true
        end
        function chain.simulate()
            return "0x", nil
        end
        function chain.publish(_, raw)
            return state.published[#state.published].hash
        end
        function chain.rpc(_, method, params)
            if method == "eth_chainId" then
                return "0x7a69"
            elseif method == "eth_getBlockByNumber" then
                local w = params[1]
                local n = w == "latest" and state.tip or w == "finalized" and 0 or tonumber(w)
                return {
                    number = string.format("0x%x", n),
                    hash = block_hash(n),
                    baseFeePerGas = string.format("0x%x", state.base),
                    gasLimit = "0x1c9c380",
                }
            elseif method == "eth_getTransactionCount" then
                return "0x0"
            elseif method == "eth_getTransactionReceipt" then
                return json.null
            elseif method == "eth_getTransactionByHash" then
                return { hash = params[1] } -- the node still holds every candidate
            elseif method == "eth_maxPriorityFeePerGas" then
                return string.format("0x%x", state.suggested)
            elseif method == "eth_estimateGas" then
                return "0x186a0"
            elseif method == "eth_getBalance" then
                return "0x56bc75e2d63100000" -- 100 ETH: funds never limit
            end
            error("unexpected rpc " .. method)
        end
        return chain
    end

    local function run(name, state, prepare)
        state.published = {}
        local chain = new_chain(state)
        local signer = {
            address = "0x" .. string.rep("aa", 20),
            sign = function(_, candidate)
                local hash = string.format("0x%064x", #state.published + 1)
                state.published[#state.published + 1] =
                    { hash = hash, max_fee = candidate.max_fee, priority = candidate.priority_fee }
                return "0x00", hash
            end,
        }
        -- defaults: bump every 3 blocks by 15%, priority 1..10 gwei, max fee 100 gwei
        local t = journal.new({ chain = chain, path = dir .. "/" .. name .. ".json" })
        local intent = { key = "advance", kind = "advanceMatch", first = 0, last = 100000,
            to = "0x" .. string.rep("11", 20), data = "0x01" }
        local function submit()
            return t:submit(signer, intent, { head = state.tip, hash = block_hash(state.tip) })
        end
        local first = submit()
        if not first.published then
            harness.setup_error(name .. ": first submission was not published")
        end
        local last = prepare(submit, first, state)
        io.stderr:write(string.format("%s: pending candidate at nonce 0: max fee %.3f gwei, priority %.3f gwei\n",
            name, tonumber(last.max_fee) / GWEI, tonumber(last.priority_fee) / GWEI))
        -- The adversary fills blocks; the base fee rises above the pending candidate's max fee.
        state.tip, state.base = state.tip + 3, 40 * GWEI
        assert(evmu.bint(last.max_fee) < evmu.bint(state.base), "scenario did not make the candidate unincludable")
        local r = submit()
        local verdict, why
        if r.published then
            local c = r.candidate
            local fee, prio = evmu.bint(c.max_fee), evmu.bint(c.priority_fee)
            local pfee, pprio = evmu.bint(last.max_fee), evmu.bint(last.priority_fee)
            verdict = c.nonce == 0
                and fee >= evmu.bint(state.base) + prio
                and fee <= evmu.bint(MAX_FEE)
                and fee * 10 >= pfee * 11
                and prio * 10 >= pprio * 11
            why = string.format("re-priced at max fee %.3f gwei, priority %.3f gwei", tonumber(c.max_fee) / GWEI,
                tonumber(c.priority_fee) / GWEI)
        else
            verdict = false
            why = "not re-priced: " .. tostring(r.blocked or (r.waiting and "waiting") or (r.rejected and "rejected"))
        end
        io.stderr:write(string.format(
            "%s: tip %d, base fee %d gwei (candidate unincludable; --max-fee %d gwei leaves room): %s -> %s\n", name,
            state.tip, state.base // GWEI, MAX_FEE // GWEI, why, verdict and "OK" or "VIOLATION"))
        return verdict
    end

    -- A: the node suggests a 10 gwei tip at the first signing (base 10 gwei): signed at max fee 30, priority 10 (cap).
    local a = run("A", { tip = 10, base = 10 * GWEI, suggested = 10 * GWEI }, function(_, first)
        return first.candidate
    end)

    -- B: base 1 gwei, suggested tip 1 gwei; the move stays unmined (out-tipped by racing transactions), so every 3
    -- blocks the journal bumps it by 15%, until its priority is within 15% of the 10 gwei cap (the next bump would
    -- exceed the cap). Its max fee is then far below --max-fee.
    local b = run("B", { tip = 10, base = 1 * GWEI, suggested = 1 * GWEI }, function(submit, first, state)
        local last = first.candidate
        local s = 0
        while evmu.bint(last.priority_fee) * 115 <= evmu.bint(MAX_PRIORITY) * 100 do
            s = s + 1
            assert(s < 100, "scenario B: priority never approached the cap")
            state.tip = state.tip + 3 -- the bump interval
            local r = submit()
            if not r.published then
                harness.setup_error("scenario B: bump " .. s .. " not published: " .. tostring(r.blocked or r.waiting))
            end
            last = r.candidate
        end
        io.stderr:write(string.format("B: %d bumps raised the priority to within 15%% of the cap\n", s))
        return last
    end)

    os.execute("rm -rf '" .. dir .. "'")
    return harness.expect(a and b,
        "R4 'The honest operator observes the chain and submits its transactions within the dispute clocks': "
            .. "with --max-fee room left, a pending honest move whose max fee fell below the base fee must be "
            .. "re-priced at its nonce (journal answered fee_ceiling)")
end)
