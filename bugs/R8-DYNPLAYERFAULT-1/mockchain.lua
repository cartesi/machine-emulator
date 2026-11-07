-- In-memory EIP-1559 chain with one exclusive signer, a mempool, reorgs and fault hooks.
local json = require("dkjson")
local M = {}
local mt = { __index = {} }
local C = mt.__index
local function hx(n) return string.format("0x%x", n) end
local hcount = 0
local function newhash(tag)
    hcount = hcount + 1
    local s = string.format("%s%08x", tag, hcount)
    return "0x" .. string.rep("0", 64 - #s) .. s
end

function M.new(opts)
    opts = opts or {}
    local self = setmetatable({
        blocks = {}, mempool = {}, signed = {}, receipts = {}, nonce_at = {},
        base_fee = opts.base_fee or 1000000000, tip_suggestion = opts.tip_suggestion or 1000000000,
        finality = opts.finality or 64, gas_limit = 30000000, done = {}, log = {},
        revert = opts.revert, -- function(tx, chain) -> true when the call reverts
    }, mt)
    self.blocks[0] = { number = 0, hash = newhash("g"), base = self.base_fee, txs = {}, nonce = {} }
    return self
end

function C:tip() return #self.blocks end
function C:nonce_of(address, number)
    local b = self.blocks[number]
    return b.nonce[address] or 0
end

-- Mines one block: includes the signer's mempool txs in nonce order when affordable.
function C:mine(base_fee)
    if base_fee then self.base_fee = base_fee end
    local parent = self.blocks[#self.blocks]
    local b = { number = parent.number + 1, hash = newhash("b"), base = self.base_fee, txs = {}, nonce = {} }
    for k, v in pairs(parent.nonce) do b.nonce[k] = v end
    local progress = true
    while progress do
        progress = false
        for hash, tx in pairs(self.mempool) do
            local n = b.nonce[tx.from] or 0
            if tx.nonce == n and tx.max_fee >= b.base + 0 then
                b.nonce[tx.from] = n + 1
                local status = 1
                if self.revert and self.revert(tx, self) then status = 0 end
                b.txs[#b.txs + 1] = { hash = hash, status = status, tx = tx }
                self.mempool[hash] = nil
                if status == 1 and tx.job then self.done[tx.job] = b.number end
                progress = true
                break
            elseif tx.nonce < n then
                self.mempool[hash] = nil
            end
        end
    end
    self.blocks[b.number] = b
    for _, t in ipairs(b.txs) do self.receipts[t.hash] = { block = b, status = t.status } end
    return b
end

-- Replaces the last depth blocks with empty ones; their txs return to the mempool unless dropped.
function C:reorg(depth, drop)
    local tipn = #self.blocks
    for n = tipn, tipn - depth + 1, -1 do
        local b = self.blocks[n]
        for _, t in ipairs(b.txs) do
            self.receipts[t.hash] = nil
            if t.tx.job and self.done[t.tx.job] == n then self.done[t.tx.job] = nil end
            if not drop then self.mempool[t.hash] = t.tx end
        end
        self.blocks[n] = nil
    end
    for _ = 1, depth do
        local parent = self.blocks[#self.blocks]
        local b = { number = parent.number + 1, hash = newhash("r"), base = self.base_fee, txs = {}, nonce = {} }
        for k, v in pairs(parent.nonce) do b.nonce[k] = v end
        self.blocks[b.number] = b
    end
end

function C:drop_mempool() self.mempool = {} end

local function block_json(b)
    return { number = hx(b.number), hash = b.hash, baseFeePerGas = hx(b.base), gasLimit = hx(30000000) }
end

local function resolve(self, sel)
    if sel == "latest" or sel == "pending" then return self.blocks[#self.blocks] end
    if sel == "finalized" or sel == "safe" then return self.blocks[math.max(0, #self.blocks - self.finality)] end
    if type(sel) == "table" then
        for n = #self.blocks, 0, -1 do if self.blocks[n].hash == sel.blockHash then return self.blocks[n] end end
        error("unknown block hash")
    end
    return self.blocks[tonumber(sel)]
end

function C:rpc(method, params)
    if self.fault then
        local f = self.fault(method, params)
        if f then error("injected RPC failure in " .. method, 0) end
    end
    if method == "eth_chainId" then return "0x7a69"
    elseif method == "eth_getBlockByNumber" then
        local b = resolve(self, params[1])
        return b and block_json(b) or json.null
    elseif method == "eth_getTransactionCount" then
        local b = resolve(self, params[2])
        local n = b.nonce[params[1]] or 0
        if params[2] == "pending" then
            local again = true
            while again do
                again = false
                for _, tx in pairs(self.mempool) do
                    if tx.from == params[1] and tx.nonce == n then n = n + 1; again = true end
                end
            end
        end
        return hx(n)
    elseif method == "eth_getTransactionReceipt" then
        local r = self.receipts[params[1]]
        if not r then return json.null end
        return { transactionHash = params[1], blockNumber = hx(r.block.number), blockHash = r.block.hash, status = hx(r.status) }
    elseif method == "eth_maxPriorityFeePerGas" then return hx(self.tip_suggestion)
    elseif method == "eth_estimateGas" then return "0x5208"
    elseif method == "eth_getTransactionByHash" then
        if self.mempool[params[1]] or self.receipts[params[1]] then return { hash = params[1] } end
        return json.null
    elseif method == "eth_call" then return "0x"
    end
    error("unsupported " .. method)
end

function C:head(policy)
    local tip = self.blocks[#self.blocks]
    local b = tip
    if type(policy) == "number" then b = self.blocks[math.max(0, tip.number - policy)] end
    return b.number, b.hash, tip.number, tip.hash
end
function C:is_canonical(n, h) local b = self.blocks[n]; return b ~= nil and b.hash == h end
function C:simulate(signer, to, data, value, block)
    if self.fault and self.fault("eth_call") then error("injected RPC failure in eth_call", 0) end
    if self.sim_revert and self.sim_revert(to, data) then return nil, { code = 3, message = "execution reverted" } end
    return "0x"
end
function C:sign(signer, tx)
    local raw = "0x02" .. string.format("%x", hcount + 4096) .. "00"
    local hash = newhash("t")
    self.signed[raw] = { hash = hash, from = signer.address:lower(), nonce = tx.nonce, max_fee = tonumber(tx.max_fee),
        priority = tonumber(tx.priority_fee), job = tx.job, to = tx.to, data = tx.data }
    return raw, hash
end
function C:verify_signed(signer, tx, raw) return self.signed[raw].hash end
function C:publish(raw)
    if self.publish_hook then local r, e = self.publish_hook(raw); if r ~= nil or e ~= nil then return r, e end end
    local tx = self.signed[raw]
    -- replacement rule of geth/anvil: same nonce needs >=10% bump of both fees
    for h, other in pairs(self.mempool) do
        if other.from == tx.from and other.nonce == tx.nonce and h ~= tx.hash then
            if tx.max_fee * 10 < other.max_fee * 11 or tx.priority * 10 < other.priority * 11 then
                return nil, { code = -32000, message = "replacement transaction underpriced" }
            end
            self.mempool[h] = nil
        end
    end
    self.mempool[tx.hash] = tx
    return tx.hash
end
return M
