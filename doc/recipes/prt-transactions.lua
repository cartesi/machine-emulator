-- One exclusive account per signer. Events decide which work is useful;
-- this journal owns signed candidates, nonce reuse, and bounded replacement.
local json = require("dkjson")
local util = require("cartesi.util")
local eth = require("prt-ethereum")
local evmu = require("cartesi.evmu")
local M = {}
local methods = {}

local function quantity(value)
    assert(type(value) == "string" and (value:match("^%d+$") or value:match("^0x%x+$")), "invalid fee quantity")
    assert(#value <= 38, "fee quantity is too large")
    return evmu.bint(value)
end

local function maximum(a, b)
    return a > b and a or b
end

local function minimum(a, b)
    return a < b and a or b
end

local function hex(value)
    return "0x" .. evmu.bint.tobase(evmu.bint(value), 16)
end

function methods:save()
    util.write_file(json.encode(self.state, { indent = true }) .. "\n", self.path .. ".tmp")
    assert(os.rename(self.path .. ".tmp", self.path))
end

function methods:nonce(address, block)
    return eth.small(assert(self.chain:rpc("eth_getTransactionCount", { address, block or "latest" })))
end

-- Never allocate past the current chain nonce, even when pending RPC reports
-- later candidates. A reorg can resurrect every nonce up to high_water.
local function nonce_record(account, nonce)
    assert(nonce >= account.first_nonce, "signer nonce moved before its journal; stop and reconcile the account")
    assert(nonce <= account.high_water + 1, "exclusive signer nonce was consumed outside its journal")
    if nonce <= account.high_water then
        return assert(account.nonces[tostring(nonce)], "missing owned nonce")
    end
end

-- Expose the current signed action, not the journal's nonce-slot structure.
function methods:pending(address)
    local account = self.state.accounts[address:lower()]
    if not account then
        return nil
    end
    local record = nonce_record(account, self:nonce(address))
    return record and record.candidates[#record.candidates]
end

function methods:idle()
    for address in pairs(self.state.accounts) do
        if self:pending(address) then
            return false
        end
    end
    return true
end

-- Query every candidate for this job: a replaced transaction can still win.
-- Both successful and reverted receipts suppress resending until observation
-- catches up. Neither receipt marks the job complete.
function methods:receipt(key)
    local latest
    for _, candidate in ipairs(self.jobs[key] or {}) do
        local receipt = assert(self.chain:rpc("eth_getTransactionReceipt", { candidate.hash }))
        if receipt ~= json.null then
            assert(receipt.transactionHash:lower() == candidate.hash, "receipt transaction mismatch")
            if self.chain:is_canonical(eth.small(receipt.blockNumber), receipt.blockHash) then
                if not latest or eth.small(receipt.blockNumber) > eth.small(latest.blockNumber) then
                    latest = receipt
                end
            end
        end
    end
    return latest
end

function methods:fees(previous, block)
    local base = quantity(assert(block.baseFeePerGas, "EIP-1559 base fee missing"))
    local suggested = quantity(assert(self.chain:rpc("eth_maxPriorityFeePerGas", {})))
    local priority = minimum(maximum(suggested, self.min_priority_fee), self.max_priority_fee)
    local fee = minimum(base * 2 + priority, self.max_fee)
    if previous then
        local multiplier = evmu.bint(100 + self.bump_percent)
        priority = maximum(priority, (quantity(previous.priority_fee) * multiplier + 99) // 100)
        fee = maximum(fee, (quantity(previous.max_fee) * multiplier + 99) // 100)
    end
    if priority > self.max_priority_fee or fee > self.max_fee or fee < base + priority then
        return nil
    end
    return tostring(fee), tostring(priority)
end

-- intent is either the currently eligible job or nil (cancel obsolete work).
-- A call publishes at most once and never waits for mining. Caller must supply
-- a fresh, canonical observation and must revalidate jobs on every tick.
function methods:submit(signer, intent, observation)
    local address = signer.address:lower()
    local block = assert(self.chain:rpc("eth_getBlockByNumber", { "latest", false }))
    local tip = eth.small(block.number)
    local nonce = self:nonce(address, { blockHash = block.hash, requireCanonical = true })
    local account = self.state.accounts[address]
    local record = account and nonce_record(account, nonce)
    if not account then
        assert(self:nonce(address, "pending") == nonce, "exclusive signer already has untracked pending transactions")
    end
    local previous = record and record.candidates[#record.candidates]
    if not intent and not previous then
        return { waiting = true }
    end
    if intent and (tip + 1 < intent.first or tip + 1 >= intent.last) then
        return { waiting = true }
    end
    if intent then
        local receipt = self:receipt(intent.key)
        if receipt and eth.small(receipt.blockNumber) > observation.head then
            return { waiting = true }
        end
    end
    if previous and previous.job == (intent and intent.key) then
        -- A changed branch may need immediate republication at an earlier
        -- height; never wait for the old branch's block count to catch up.
        local attempt = assert(record.last_attempt)
        if self.chain:is_canonical(attempt.block, attempt.block_hash) and tip - attempt.block < self.bump_blocks then
            return { waiting = true }
        end
    end
    local fee, priority = self:fees(previous, block)
    local rebroadcast
    if not fee then
        -- A lost publication at the fee ceiling must not strand an otherwise
        -- affordable signed transaction. Retry identical bytes only for the
        -- same action, after checking the local node no longer has them.
        local same_action = previous and previous.job == (intent and intent.key)
        if
            same_action
            and quantity(previous.max_fee) >= quantity(block.baseFeePerGas) + quantity(previous.priority_fee)
        then
            rebroadcast = assert(self.chain:rpc("eth_getTransactionByHash", { previous.hash })) == json.null
        end
        if not rebroadcast then
            return { blocked = "fee ceiling", nonce = nonce, hash = previous and previous.hash }
        end
    end
    local to, data, value = address, "0x", "0"
    if intent then
        to, data, value = intent.to, intent.data, intent.value or "0"
    end
    -- Use canonical execution state, excluding our own pending transaction.
    -- Inclusion windows are checked separately against the next live block.
    local _, failure = self.chain:simulate(signer, to, data, value, { blockHash = block.hash, requireCanonical = true })
    if failure then
        assert(failure.code == 3, "transaction preflight RPC failure")
        return { rejected = failure }
    end
    local gas, estimate_failure = self.chain:rpc("eth_estimateGas", {
        { from = address, to = to, data = data, value = hex(value) },
        block.number,
    })
    if estimate_failure then
        assert(estimate_failure.code == 3, "gas estimation RPC failure")
        return { rejected = estimate_failure }
    end
    gas = (eth.small(assert(gas)) * 12 + 9) // 10
    assert(gas <= eth.small(block.gasLimit), "estimated transaction exceeds block gas limit")
    local candidate = rebroadcast and previous
        or {
            chain_id = self.state.chain_id,
            nonce = nonce,
            gas = gas,
            to = to,
            data = data,
            value = tostring(value),
            max_fee = fee,
            priority_fee = priority,
            job = intent and intent.key,
            action = intent and intent.kind or "cancel",
            context = intent and intent.context,
            block = tip,
            block_hash = block.hash,
            observation_block = observation.head,
            observation_hash = observation.hash,
        }
    if rebroadcast then
        assert(
            candidate.to == to and candidate.data == data and candidate.value == tostring(value),
            "job changed its signed action"
        )
        if candidate.gas < gas then
            return { blocked = "fee ceiling", nonce = nonce, hash = candidate.hash }
        end
        assert(
            self.chain:verify_signed(signer, candidate, candidate.raw) == candidate.hash,
            "journal signature mismatch"
        )
    else
        candidate.raw, candidate.hash = self.chain:sign(signer, candidate)
    end
    local _, current_hash = self.chain:head()
    if current_hash ~= block.hash or not self.chain:is_canonical(observation.head, observation.hash) then
        return { waiting = true }
    end
    if not account then
        account = { first_nonce = nonce, high_water = nonce, nonces = {} }
        self.state.accounts[address] = account
    end
    record = record or { candidates = {} }
    account.nonces[tostring(nonce)] = record
    account.high_water = math.max(account.high_water, nonce)
    record.last_attempt = { block = tip, block_hash = block.hash }
    if not rebroadcast then
        record.candidates[#record.candidates + 1] = candidate
    end
    if candidate.job and not rebroadcast then
        self.jobs[candidate.job] = self.jobs[candidate.job] or {}
        table.insert(self.jobs[candidate.job], candidate)
    end
    -- The rename precedes EVERY publication, including replacements/cancels.
    -- Persist all candidates, because network acceptance is not consensus.
    self:save()
    local hash, publication_failure = self.chain:publish(candidate.raw)
    if hash then
        assert(hash:lower() == candidate.hash, "published transaction hash mismatch")
    end
    -- A rejected or ambiguously acknowledged publication still owns this nonce.
    -- Retry with higher fees on a later tick; never allocate the next nonce.
    return {
        published = true,
        candidate = candidate,
        rebroadcast = rebroadcast,
        publication_error = publication_failure and publication_failure.code,
    }
end

function M.new(args)
    assert(args.chain and args.path)
    local self = setmetatable({
        chain = args.chain,
        path = args.path,
        bump_blocks = args.bump_blocks or 3,
        bump_percent = args.bump_percent or 15,
        min_priority_fee = quantity(args.min_priority_fee or "1000000000"),
        max_priority_fee = quantity(args.max_priority_fee or "10000000000"),
        max_fee = quantity(args.max_fee or "100000000000"),
        jobs = {},
    }, { __index = methods })
    assert(math.type(self.bump_blocks) == "integer" and self.bump_blocks > 0, "invalid fee bump interval")
    assert(
        math.type(self.bump_percent) == "integer" and self.bump_percent >= 10 and self.bump_percent <= 100,
        "invalid fee bump percent"
    )
    assert(
        self.min_priority_fee > 0
            and self.min_priority_fee <= self.max_priority_fee
            and self.max_priority_fee <= self.max_fee,
        "invalid fee limits"
    )
    local chain_id = assert(self.chain:rpc("eth_chainId", {}))
    local genesis = assert(self.chain:rpc("eth_getBlockByNumber", { "0x0", false })).hash
    local file, _, open_code = io.open(self.path, "r")
    if file then
        local data = file:read("a")
        file:close()
        local state, position, err = json.decode(data)
        assert(not err and state and not data:sub(position):find("%S"), "invalid transaction journal")
        assert(
            state.version == 1 and state.chain_id == chain_id and state.genesis == genesis,
            "transaction journal chain mismatch"
        )
        self.state = state
        for _, account in pairs(state.accounts) do
            for nonce = account.first_nonce, account.high_water do
                assert(account.nonces[tostring(nonce)], "missing owned nonce in journal")
            end
            for nonce, record in pairs(account.nonces) do
                assert(
                    tonumber(nonce) >= account.first_nonce
                        and tonumber(nonce) <= account.high_water
                        and #record.candidates > 0,
                    "invalid nonce journal"
                )
                for _, candidate in ipairs(record.candidates) do
                    assert(
                        candidate.nonce == tonumber(nonce) and candidate.chain_id == chain_id,
                        "invalid journal candidate"
                    )
                    if candidate.job then
                        self.jobs[candidate.job] = self.jobs[candidate.job] or {}
                        table.insert(self.jobs[candidate.job], candidate)
                    end
                end
            end
        end
    else
        assert(open_code == 2, "cannot read transaction journal")
        self.state = { version = 1, chain_id = chain_id, genesis = genesis, accounts = {} }
    end
    return self
end

return M
