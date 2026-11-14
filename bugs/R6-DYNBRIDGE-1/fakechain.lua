-- Scriptable fake EVM node for the PRT journal/bridge/listener: blocks with per-block state,
-- an EIP-1559-ish base fee, a one-account mempool with replacement rules, reorgs, drops,
-- injected RPC faults. It reuses prt-rpc's chain methods (head, is_canonical, logs, simulate,
-- publish) by overriding the instance's rpc function.
local json = require("dkjson")
local rpc_client = require("prt-rpc")
local M = {}

local GWEI = 1000000000

local function hx(n)
    return string.format("0x%x", n)
end
M.hx = hx

local Injected = {}
M.Injected = Injected
local function inject(msg)
    error(setmetatable({ msg = msg }, Injected), 0)
end

function M.new(opts)
    opts = opts or {}
    local self = {
        rng = opts.rng,
        F = opts.finality or 12, -- finalized depth
        blocks = {}, -- canonical by number
        byhash = {},
        pool = {}, -- nonce -> tx
        txs = {}, -- hash -> tx
        jobs = opts.jobs or {}, -- data -> job {first,last}
        fault = opts.fault or 0, -- per-RPC failure probability
        ambiguous = opts.ambiguous or 0, -- accept then fail on sendRaw
        drop_on_reorg = opts.drop_on_reorg or 0,
        log = {},
        counter = 0,
        sender = opts.sender,
        inputs = {}, -- logs: list of {address, topics, data, blockNumber}
        priority = opts.priority or GWEI,
    }
    local genesis = { number = 0, base = GWEI, nonce = 0, done = {}, txs = {}, logs = {} }
    self.counter = self.counter + 1
    genesis.hash = string.format("0x%064x", self.counter)
    self.blocks[0] = genesis
    self.byhash[genesis.hash] = genesis
    self.tip = 0
    return setmetatable(self, { __index = M })
end

function M:block(n)
    return self.blocks[n]
end

local function copy(t)
    local r = {}
    for k, v in pairs(t) do
        r[k] = v
    end
    return r
end

-- Executes tx against state s (mutates) in block b; returns status
function M:execute(s, tx, number)
    if tx.to == self.sender then
        return 1
    end
    local job = self.jobs[tx.data]
    if job and not s.done[tx.data] and number >= job.first and number < job.last then
        s.done[tx.data] = number
        return 1
    end
    return 0
end

function M:mine(base_override, opts)
    opts = opts or {}
    local parent = self.blocks[self.tip]
    local base = base_override or parent.next_base or parent.base
    self.counter = self.counter + 1
    local b = {
        number = parent.number + 1,
        parent = parent.hash,
        base = base,
        nonce = parent.nonce,
        done = copy(parent.done),
        txs = {},
        receipts = {},
        logs = {},
    }
    b.hash = string.format("0x%064x", self.counter)
    if not opts.empty then
        while true do
            local tx = self.pool[b.nonce]
            if not tx or tx.max_fee < base then
                break
            end
            self.pool[b.nonce] = nil
            local status = self:execute(b, tx, b.number)
            b.txs[#b.txs + 1] = tx.hash
            b.receipts[tx.hash] = { status = status, gasUsed = status == 1 and 21000 or tx.gas }
            b.nonce = b.nonce + 1
        end
    end
    for _, l in ipairs(opts.logs or {}) do
        local log = copy(l)
        log.blockNumber, log.blockHash, log.logIndex = hx(b.number), b.hash, hx(#b.logs)
        b.logs[#b.logs + 1] = log
    end
    b.next_base = base -- flat unless overridden
    self.blocks[b.number] = b
    self.byhash[b.hash] = b
    self.tip = b.number
    -- prune pool entries with nonce below state
    for n in pairs(self.pool) do
        if n < b.nonce then
            self.pool[n] = nil
        end
    end
    return b
end

-- Removes the last depth blocks; their txs go back to the pool unless dropped.
function M:reorg(depth, newlen, opts)
    assert(self.tip - depth >= self.tip - self.F + 1, "reorg past finality")
    local removed = {}
    for n = self.tip, self.tip - depth + 1, -1 do
        local b = self.blocks[n]
        for _, h in ipairs(b.txs) do
            removed[#removed + 1] = self.txs[h]
        end
        self.blocks[n] = nil
    end
    self.tip = self.tip - depth
    local base_nonce = self.blocks[self.tip].nonce
    for _, tx in ipairs(removed) do
        if tx.nonce >= base_nonce and self.rng() >= self.drop_on_reorg then
            local cur = self.pool[tx.nonce]
            if not cur or cur.max_fee < tx.max_fee then
                self.pool[tx.nonce] = tx
            end
        end
    end
    for _ = 1, newlen do
        self:mine(nil, opts)
    end
end

function M:drop_pool()
    self.pool = {}
end

function M:canonical_receipt(hash)
    for n = self.tip, 0, -1 do
        local b = self.blocks[n]
        if b.receipts and b.receipts[hash] then
            return b, b.receipts[hash]
        end
    end
end

function M:pending_nonce()
    local n = self.blocks[self.tip].nonce
    while self.pool[n] do
        n = n + 1
    end
    return n
end

local function block_json(b)
    if not b then
        return json.null
    end
    return { number = hx(b.number), hash = b.hash, baseFeePerGas = hx(b.base), gasLimit = "0x1c9c380" }
end

function M:resolve(tag)
    if tag == nil or tag == "latest" or tag == "pending" then
        return self.blocks[self.tip]
    elseif tag == "finalized" or tag == "safe" then
        return self.blocks[math.max(0, self.tip - self.F)]
    elseif type(tag) == "table" then
        local b = self.byhash[tag.blockHash]
        if not b then
            return nil, { code = -32001, message = "Resource not found" }
        end
        if self.blocks[b.number] ~= b then
            if tag.requireCanonical then
                return nil, { code = -32000, message = "block not canonical" }
            end
        end
        return b
    else
        local n = tonumber(tag)
        return self.blocks[n]
    end
end

function M:handle(method, p)
    if method == "eth_chainId" then
        return "0x7a69"
    elseif method == "eth_getBlockByNumber" then
        return block_json((self:resolve(p[1])))
    elseif method == "eth_getTransactionCount" then
        if p[2] == "pending" then
            return hx(self:pending_nonce())
        end
        local b, err = self:resolve(p[2])
        if not b then
            return nil, err or { code = -32000, message = "unknown block" }
        end
        return hx(b.nonce)
    elseif method == "eth_getTransactionReceipt" then
        local b, r = self:canonical_receipt(p[1])
        if not b then
            return json.null
        end
        return {
            transactionHash = p[1],
            blockNumber = hx(b.number),
            blockHash = b.hash,
            status = hx(r.status),
            gasUsed = hx(r.gasUsed),
        }
    elseif method == "eth_getTransactionByHash" then
        local tx = self.txs[p[1]]
        if tx and (self.pool[tx.nonce] == tx or self:canonical_receipt(p[1])) then
            return { hash = p[1] }
        end
        return json.null
    elseif method == "eth_maxPriorityFeePerGas" then
        return hx(self.priority)
    elseif method == "eth_estimateGas" or method == "eth_call" then
        local call = p[1]
        local b, err = self:resolve(p[2])
        if not b then
            return nil, err or { code = -32000, message = "unknown block" }
        end
        local s = { done = copy(b.done) }
        local st = self:execute(s, { to = call.to, data = call.data }, b.number + 1)
        if st == 0 then
            return nil, { code = 3, message = "execution reverted" }
        end
        return method == "eth_call" and "0x" or "0x5208"
    elseif method == "eth_getBalance" then
        return "0xffffffffffffffffffffffff"
    elseif method == "eth_sendRawTransaction" then
        local tx = self.txs[self.raw[p[1]]]
        assert(tx, "unknown raw")
        local state_nonce = self.blocks[self.tip].nonce
        if tx.nonce < state_nonce then
            return nil, { code = -32003, message = "nonce too low" }
        end
        local cur = self.pool[tx.nonce]
        if cur == tx then
            return nil, { code = -32000, message = "already known" }
        end
        if cur then
            if tx.max_fee * 10 < cur.max_fee * 11 or tx.priority * 10 < cur.priority * 11 then
                return nil, { code = -32000, message = "replacement transaction underpriced" }
            end
        end
        if tx.nonce > self:pending_nonce() then
            return nil, { code = -32000, message = "nonce gap" }
        end
        self.pool[tx.nonce] = tx
        if self.rng() < self.ambiguous then
            inject("ambiguous publication timeout")
        end
        return tx.hash
    elseif method == "eth_getLogs" then
        local f = p[1]
        local from, to = tonumber(f.fromBlock), tonumber(f.toBlock)
        local addr = f.address
        local set = {}
        if type(addr) == "table" then
            for _, a in ipairs(addr) do
                set[a] = true
            end
        else
            set[addr] = true
        end
        local out = {}
        for n = from, math.min(to, self.tip) do
            for _, l in ipairs(self.blocks[n].logs) do
                if set[l.address] then
                    out[#out + 1] = l
                end
            end
        end
        return out
    end
    error("fake node: unsupported method " .. method)
end

-- A prt-rpc chain bound to this node.
function M:client()
    local node = self
    local chain = rpc_client.new("http://fake:1")
    function chain.rpc(_, method, params)
        if node.rng() < node.fault and method ~= "eth_chainId" then
            inject("injected RPC failure in " .. method)
        end
        local result, err = node:handle(method, params or {})
        if err then
            return nil, err
        end
        return result
    end
    return chain
end

-- A signer that records the transaction in the node registry.
function M:signer(address)
    local node = self
    node.raw = node.raw or {}
    return {
        address = address,
        sign = function(_, c)
            node.counter = node.counter + 1
            local hash = string.format("0x%064x", 1 << 40 | node.counter)
            local raw = "0xraw" .. node.counter
            node.raw[raw] = hash
            node.txs[hash] = {
                hash = hash,
                nonce = c.nonce,
                max_fee = tonumber(c.max_fee),
                priority = tonumber(c.priority_fee),
                gas = c.gas,
                to = c.to,
                data = c.data,
                job = c.job,
            }
            return raw, hash
        end,
    }
end

return M
