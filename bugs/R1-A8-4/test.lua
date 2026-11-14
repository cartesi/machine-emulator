-- R1-A8-4: the PRT bridge (doc/recipes/prt-bridge.lua, methods:tick) keeps working on an already pending,
-- deadline-free cleanup transaction of ANOTHER match (eliminateMatchByTimeout of two adversary claims) and
-- does not even attempt a newly due, deadline-bound move of the honest commitment (advanceMatch), so the
-- honest move waits until the cleanup is mined.
--
-- The test drives the real bridge scheduler (methods:tick, attempt, jobs) and the real transaction journal
-- (doc/recipes/prt-transactions.lua: nonces, pending candidate, bump interval, replacement) over a mock chain.
-- Only the observation (refresh) and the calldata preparation (prepare) of the bridge are stubbed.
--
-- Required (THREAT_MODEL.md R4, A8, for the honest operator the bridge stands in for): processing another
-- match must not delay the honest commitment's match; the honest move is published at the first tick at
-- which it is due, exactly as when no cleanup is pending (control), and certainly before its window closes.
local harness = require("harness")

harness.main(function()
    local json = require("dkjson")
    local bridge = require("prt-bridge")
    local journal = require("prt-transactions")
    local prt = require("prt")
    local geometry = prt.new_geometry(10)

    local tmp = assert(os.getenv("TMPDIR") or "/tmp")
    local ok, out = harness.sh("mktemp -d " .. tmp .. "/r1-a8-4.XXXXXX")
    if not ok then
        harness.setup_error("mktemp failed")
    end
    local dir = out:gsub("%s+$", "")

    local function block_hash(n)
        return string.format("0x%064x", n)
    end

    -- Runs one scenario. `prior_cleanup`: the adversaries' own match becomes eliminable one block before
    -- the honest commitment comes on turn (so the cleanup is already pending then). `inclusion_delay`: blocks
    -- between a nonce's first publication and its inclusion (nil: not included within the run).
    -- Returns the tip at which advanceMatch was first published (nil if never within its window) and a log.
    local function scenario(name, prior_cleanup, inclusion_delay)
        local DUE, DEADLINE = 9, 20 -- honest match observed from tip 9; responderDeadline 20 (inclusion < 20)
        local tip = 8
        local published = {} -- nonce -> list of candidates (hash)
        local first_publication = {} -- nonce -> tip
        local log = {}
        local hash_counter = 0
        local signer = {
            address = "0x" .. string.rep("aa", 20),
            sign = function(_, candidate)
                hash_counter = hash_counter + 1
                local hash = string.format("0x%064x", 0xbeef0000 + hash_counter)
                -- the journal publishes right after signing; index the candidate by nonce for the mock chain
                published[candidate.nonce] = published[candidate.nonce] or {}
                table.insert(published[candidate.nonce], { hash = hash, action = candidate.action })
                first_publication[candidate.nonce] = first_publication[candidate.nonce] or tip
                return string.format("0x%02x", candidate.nonce), hash
            end,
        }
        local function mined_count(at)
            local n = 0
            while first_publication[n] and inclusion_delay and first_publication[n] + inclusion_delay <= at do
                n = n + 1
            end
            return n
        end
        local function find(hash)
            for nonce, list in pairs(published) do
                for i, candidate in ipairs(list) do
                    if candidate.hash == hash then
                        return nonce, i, #list
                    end
                end
            end
        end
        local chain = {}
        function chain.head()
            return tip, block_hash(tip)
        end
        function chain.is_canonical()
            return true
        end
        function chain.simulate()
            return nil, nil
        end
        function chain.publish(_, raw)
            local nonce = tonumber(raw:sub(3), 16)
            local list = published[nonce]
            return list[#list].hash
        end
        function chain.rpc(_, method, params)
            if method == "eth_chainId" then
                return "0x7a69"
            elseif method == "eth_getBlockByNumber" then
                local which = params[1]
                local n = which == "latest" and tip or which == "finalized" and 0 or tonumber(which)
                return {
                    number = string.format("0x%x", n),
                    hash = block_hash(n),
                    baseFeePerGas = "0x2540be400",
                    gasLimit = "0x1c9c380",
                }
            elseif method == "eth_getTransactionCount" then
                return string.format("0x%x", mined_count(tip))
            elseif method == "eth_getTransactionReceipt" then
                local nonce, index, count = find(params[1])
                if nonce and index == count and nonce < mined_count(tip) then
                    local at = first_publication[nonce] + inclusion_delay
                    return {
                        transactionHash = params[1],
                        blockNumber = string.format("0x%x", at),
                        blockHash = block_hash(at),
                        status = "0x1",
                        gasUsed = "0x5208",
                    }
                end
                return json.null
            elseif method == "eth_getTransactionByHash" then
                return { hash = params[1] }
            elseif method == "eth_maxPriorityFeePerGas" then
                return "0x3b9aca00"
            elseif method == "eth_estimateGas" then
                return "0x5208"
            elseif method == "eth_getBalance" then
                return "0xde0b6b3a7640000"
            end
            error("unexpected rpc " .. tostring(method))
        end

        local transactions = journal.new({ chain = chain, path = dir .. "/" .. name .. ".json" })
        -- Record every publication (the journal fills the candidate; we index it by nonce).
        local submit = transactions.submit
        function transactions.submit(self, s, intent, observation)
            local result = submit(self, s, intent, observation)
            if result.published then
                local c = result.candidate
                log[#log + 1] = string.format("tip %d: published %s at nonce %d", tip, c.action, c.nonce)
            end
            return result
        end

        local client = bridge.new({
            geometry = geometry,
            chain = chain,
            transactions = transactions,
            abi = {},
            root = "root",
            factory = "factory",
            consensus = "consensus",
            player = { report_anomaly = function() end },
            signer = signer,
            label = "honest",
            epoch = 0,
        })
        client.claims = { root = { root = "H" } }
        function client.prepare(_, job)
            return { signer = signer, to = "0x" .. string.rep("11", 20), data = "0x" .. harness.hex(job.kind) }
        end

        local context = {
            address = "root",
            creation = { log = { blockHash = block_hash(0), logIndex = "0x0" } },
            descriptor = { height = geometry.mcycle_height, kind = 1, startInstant = 0, allowance = 1 },
            joined = { H = { submitter = signer.address } },
            standing = { matchCount = 2 },
        }
        -- Match of two adversary (Sybil) claims, eliminable by timeout: a permissionless cleanup, no deadline.
        local sybil = {
            name = "MatchCreated",
            address = "root",
            matchIdHash = "sybil",
            one = "X1",
            two = "X2",
            -- eligible from the tick at tip 8 (prior_cleanup) or tip 9, the tick the honest move becomes due
            responderDeadline = prior_cleanup and 9 or 10,
            eliminableAt = prior_cleanup and 9 or 10,
            log = { blockHash = block_hash(1), logIndex = "0x0" },
        }
        -- Match of the honest claim H, which is on turn: advanceMatch is due until responderDeadline.
        local honest = {
            name = "MatchCreated",
            address = "root",
            matchIdHash = "honest",
            one = "H",
            two = "X3",
            responderDeadline = DEADLINE,
            eliminableAt = 40,
            log = { blockHash = block_hash(DUE), logIndex = "0x1" },
        }
        function client.refresh()
            local events, matches, deleted = {}, {}, {}
            if mined_count(tip) == 0 or not prior_cleanup then
                events[#events + 1] = sybil
                matches["root:sybil"] = sybil
            end
            if tip >= DUE then
                events[#events + 1] = honest
                matches["root:honest"] = honest
            end
            return {
                ready = true,
                head = tip,
                hash = block_hash(tip),
                tip = tip,
                tip_hash = block_hash(tip),
                order = { context },
                contexts = { root = context },
                events = events,
                matches = matches,
                deleted = deleted,
                recovered = {},
            }
        end

        local advanced_at
        while tip + 1 < DEADLINE and not advanced_at do
            for _ = 1, 4 do
                local _, did = client:tick()
                for nonce, list in pairs(published) do
                    for _, c in ipairs(list) do
                        if c.action == "advanceMatch" and not advanced_at then
                            advanced_at = tip
                        end
                    end
                end
                if not did then
                    break
                end
            end
            tip = tip + 1
        end
        io.stderr:write(name, ":\n")
        for _, line in ipairs(log) do
            io.stderr:write("  ", line, "\n")
        end
        io.stderr:write(
            "  honest advanceMatch due from tip ",
            DUE,
            ", window closes at block ",
            DEADLINE,
            ": ",
            advanced_at and ("first published at tip " .. advanced_at) or "NEVER published within its window",
            "\n"
        )
        return advanced_at, DUE
    end

    local control, due = scenario("control (no pending cleanup)", false, 6)
    if control ~= due then
        os.execute("rm -rf '" .. dir .. "'")
        harness.setup_error("control: the bridge did not publish the honest move as soon as it was due")
    end
    local congested = scenario("pending cleanup, included 6 blocks after publication", true, 6)
    local stuck = scenario("pending cleanup, not included before the honest deadline", true, nil)

    local fine = true
    fine = harness.expect(
        congested == control,
        string.format(
            "A8/R4: a pending cleanup of another match must not delay the honest advanceMatch "
                .. "(control published at tip %d, with the pending cleanup at tip %s)",
            control,
            tostring(congested)
        )
    ) and fine
    fine = harness.expect(
        stuck == control,
        string.format(
            "R4: the honest advanceMatch must be published within its window although a cleanup is pending "
                .. "(control at tip %d, with a stuck cleanup: %s)",
            control,
            stuck and ("tip " .. stuck) or "never"
        )
    ) and fine
    os.execute("rm -rf '" .. dir .. "'")
    return fine
end)
