-- The journal of one signer's exclusive account. Events decide which work is useful;
-- this journal owns signed candidates, nonce reuse, and bounded replacement. It keeps one record
-- per nonce it has not forgotten, in nonce order from first_nonce.
local json = require("dkjson")
local fs = require("cartesi.filesystem")
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

-- Writes the journal durably, then syncs its directory.
function methods:store()
    fs.write_durable_file(json.encode(self.state, { indent = true }) .. "\n", self.path)
    fs.sync_directory(fs.get_parent_directory(self.path))
end

function methods:nonce(block)
    local count, failure = self.chain:rpc("eth_getTransactionCount", { self.address, block or "latest" })
    return eth.small(assert(count, failure and json.encode(failure)))
end

-- The candidates signed for a job, in signing order.
local function job_candidates(self, key)
    local candidates = {}
    for _, record in ipairs(self.state.records) do
        for _, candidate in ipairs(record.candidates) do
            if candidate.job == key then
                candidates[#candidates + 1] = candidate
            end
        end
    end
    return candidates
end

-- A nonce is settled once one of its candidates has a canonical receipt at or below both the
-- finalized block and the observation head. No reorg can reopen it, and its receipts no longer hold
-- back a resend, so the journal forgets it. The account is exclusive, so its nonces settle in order.
local function forget_settled(self, observation)
    local state = self.state
    local finalized = assert(self.chain:rpc("eth_getBlockByNumber", { "finalized", false }))
    local settled_block = math.min(eth.small(finalized.number), observation.head)
    while #state.records > 0 do
        local settled = false
        for _, candidate in ipairs(state.records[1].candidates) do
            local receipt = assert(self.chain:rpc("eth_getTransactionReceipt", { candidate.hash }))
            if receipt ~= json.null then
                local number = eth.small(receipt.blockNumber)
                if number <= settled_block and self.chain:is_canonical(number, receipt.blockHash) then
                    settled = true
                    break
                end
            end
        end
        if not settled then
            return
        end
        table.remove(state.records, 1)
        state.first_nonce = state.first_nonce + 1
    end
end

-- Never allocate past the current chain nonce, even when pending RPC reports
-- later candidates. A reorg can resurrect every nonce the journal still records.
local function nonce_record(state, nonce)
    if not state.first_nonce then
        return nil
    end
    local index = nonce - state.first_nonce + 1
    assert(index >= 1, "signer nonce moved before its journal; stop and reconcile the account")
    assert(index <= #state.records + 1, "exclusive signer nonce was consumed outside its journal")
    return state.records[index]
end

-- Expose the current signed action, not the journal's nonce-slot structure.
function methods:pending()
    local record = nonce_record(self.state, self:nonce())
    return record and record.candidates[#record.candidates]
end

function methods:idle()
    return not self:pending()
end

-- Query every candidate for this job: a replaced transaction can still win.
-- Both successful and reverted receipts suppress resending until observation
-- catches up. Neither receipt marks the job complete.
function methods:receipt(key)
    local latest
    for _, candidate in ipairs(job_candidates(self, key)) do
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

-- The gas limit of a job's transaction that ran out of gas in the job's latest receipt, if one did. Running
-- out of gas consumes the whole limit, which tells it apart from a revert the contract's state caused.
local function get_exhausted_gas(self, key, receipt)
    if receipt and eth.small(receipt.status) == 0 then
        for _, candidate in ipairs(job_candidates(self, key)) do
            if candidate.hash == receipt.transactionHash:lower() and eth.small(receipt.gasUsed) == candidate.gas then
                return candidate.gas
            end
        end
    end
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
function methods:submit(intent, observation)
    local signer, address, state = self.signer, self.address, self.state
    local block = assert(self.chain:rpc("eth_getBlockByNumber", { "latest", false }))
    local tip = eth.small(block.number)
    local nonce = self:nonce({ blockHash = block.hash, requireCanonical = true })
    local record = nonce_record(state, nonce)
    if not state.first_nonce then
        assert(self:nonce("pending") == nonce, "exclusive signer already has untracked pending transactions")
    end
    local previous = record and record.candidates[#record.candidates]
    if not intent and not previous then
        return { waiting = true }
    end
    if intent and (tip + 1 < intent.first or tip + 1 >= intent.last) then
        return { waiting = true }
    end
    local exhausted_gas
    if intent then
        local receipt = self:receipt(intent.key)
        if receipt and eth.small(receipt.blockNumber) > observation.head then
            return { waiting = true }
        end
        exhausted_gas = get_exhausted_gas(self, intent.key, receipt)
    end
    if previous and previous.job == (intent and intent.key) then
        -- A changed branch may need immediate republication at an earlier
        -- height, so never wait for the old branch's block count to catch up.
        if self.chain:is_canonical(previous.block, previous.block_hash) and tip - previous.block < self.bump_blocks then
            return { waiting = true }
        end
    end
    local fee, priority = self:fees(previous, block)
    if not fee and previous then
        -- At the ceiling, outbid only the newest candidate of the nonce that the node still holds. One it
        -- lost, to a crash before publication or a dropped mempool, cannot be mined through it and sets no
        -- floor, so the next action at the nonce is signed at current fees.
        local held
        for i = #record.candidates, 1, -1 do
            local candidate = record.candidates[i]
            if assert(self.chain:rpc("eth_getTransactionByHash", { candidate.hash })) ~= json.null then
                held = candidate
                break
            end
        end
        if held ~= previous then
            fee, priority = self:fees(held, block)
        end
    end
    if not fee then
        return { blocked = "fee_ceiling", nonce = nonce, hash = previous and previous.hash }
    end
    local to, data, value = address, "0x", "0"
    if intent then
        to, data, value = intent.to, intent.data, intent.value or "0"
    end
    -- A value the account cannot cover can fail either preflight before gas is known.
    -- Report that lower bound first. The full check below includes the gas limit at the fee cap.
    local available = quantity(assert(self.chain:rpc("eth_getBalance", { address, block.number })))
    local needed = quantity(value)
    if available < needed then
        return {
            blocked = "insufficient_funds",
            nonce = nonce,
            needed = tostring(needed),
            available = tostring(available),
        }
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
    -- Twice the estimate covers the pairing branch, the only branch a join or a win can switch to between
    -- the estimate and inclusion, since creating a match costs less than the action that creates it. A job
    -- whose previous transaction ran out of gas anyway doubles that transaction's limit.
    local estimate, gas_limit = eth.small(assert(gas)), eth.small(block.gasLimit)
    assert(estimate <= gas_limit, "estimated transaction exceeds block gas limit")
    gas = math.min(math.max(estimate * 2, (exhausted_gas or 0) * 2), gas_limit)
    local candidate = {
        chain_id = state.chain_id,
        nonce = nonce,
        gas = gas,
        to = to,
        data = data,
        value = tostring(value),
        max_fee = fee,
        priority_fee = priority,
        job = intent and intent.key,
        last = intent and intent.last,
        action = intent and intent.kind or "cancel",
        context = intent and intent.context,
        block = tip,
        block_hash = block.hash,
        observation_block = observation.head,
        observation_hash = observation.hash,
    }
    -- A pool reserves the whole limit at the max fee against the balance, so a shortfall blocks the
    -- transaction before it is signed or stored.
    needed = evmu.bint(candidate.gas) * quantity(candidate.max_fee) + quantity(candidate.value)
    if available < needed then
        return {
            blocked = "insufficient_funds",
            nonce = nonce,
            needed = tostring(needed),
            available = tostring(available),
        }
    end
    candidate.raw, candidate.hash = signer:sign(candidate)
    local _, current_hash = self.chain:head()
    if current_hash ~= block.hash or not self.chain:is_canonical(observation.head, observation.hash) then
        return { waiting = true }
    end
    if not state.first_nonce then
        state.first_nonce = nonce
    end
    if not record then
        record = { candidates = {} }
        state.records[#state.records + 1] = record
    end
    record.candidates[#record.candidates + 1] = candidate
    -- The store precedes EVERY publication, including replacements/cancels.
    -- Persist all unsettled candidates, because network acceptance is not consensus.
    forget_settled(self, observation)
    self:store()
    local hash, publication_failure = self.chain:publish(candidate.raw)
    if hash then
        assert(hash:lower() == candidate.hash, "published transaction hash mismatch")
    end
    -- A rejected or ambiguously acknowledged publication still owns this nonce.
    -- Retry with higher fees on a later tick, and never allocate the next nonce.
    return {
        published = true,
        candidate = candidate,
        publication_error = publication_failure and publication_failure.code,
    }
end

function M.new(args)
    assert(args.chain and args.path and args.signer)
    local self = setmetatable({
        chain = args.chain,
        path = args.path,
        signer = args.signer,
        address = args.signer.address:lower(),
        bump_blocks = args.bump_blocks or 3,
        bump_percent = args.bump_percent or 15,
        min_priority_fee = quantity(args.min_priority_fee or "1000000000"),
        max_priority_fee = quantity(args.max_priority_fee or "10000000000"),
        max_fee = quantity(args.max_fee or "100000000000"),
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
        assert(state.version == 2, "unsupported transaction journal version")
        assert(state.chain_id == chain_id and state.genesis == genesis, "transaction journal chain mismatch")
        assert(state.address == self.address, "transaction journal belongs to another signer")
        assert(type(state.records) == "table" and (state.first_nonce ~= nil or #state.records == 0), "invalid journal")
        for index, record in ipairs(state.records) do
            assert(#record.candidates > 0, "invalid nonce journal")
            for _, candidate in ipairs(record.candidates) do
                assert(
                    candidate.nonce == state.first_nonce + index - 1 and candidate.chain_id == chain_id,
                    "invalid journal candidate"
                )
            end
        end
        self.state = state
    else
        assert(open_code == 2, "cannot read transaction journal")
        self.state = { version = 2, chain_id = chain_id, genesis = genesis, address = self.address, records = {} }
    end
    return self
end

return M
