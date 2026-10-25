-- The logs of a set of addresses up to an observation head, fetched incrementally. Each
-- observation starts from the newest block the history knows is still canonical: the previous
-- head, or the newest block holding a fetched log. Logs after it are dropped and fetched again,
-- so a reorg costs a refetch of the replaced blocks only.
local eth = require("prt-ethereum")
local M = {}
local methods = {}

function M.new(chain)
    return setmetatable({ chain = chain, fetched = {}, logs = {}, blocks = {} }, { __index = methods })
end

-- Forgets everything, so the next observation fetches each address from its first block.
function methods:reset()
    self.fetched, self.logs, self.blocks, self.head, self.head_hash = {}, {}, {}, nil, nil
end

-- Drops the logs of blocks after block.
local function rewind(self, block)
    for address, logs in pairs(self.logs) do
        while #logs > 0 and eth.small(logs[#logs].blockNumber) > block do
            logs[#logs] = nil
        end
        self.fetched[address] = math.min(self.fetched[address], block)
    end
    for number in pairs(self.blocks) do
        if number > block then
            self.blocks[number] = nil
        end
    end
end

-- The newest block among the previous head and the blocks holding logs that is still canonical.
local function common_ancestor(self)
    if self.chain:is_canonical(self.head, self.head_hash) then
        return self.head
    end
    local numbers = {}
    for number in pairs(self.blocks) do
        numbers[#numbers + 1] = number
    end
    table.sort(numbers, function(a, b)
        return a > b
    end)
    for _, number in ipairs(numbers) do
        if self.chain:is_canonical(number, self.blocks[number]) then
            return number
        end
    end
    return -1
end

-- Starts an observation at head, keeping only the logs of blocks still canonical up to it.
function methods:observe(head, hash)
    if self.head then
        rewind(self, math.min(common_ancestor(self), head))
    end
    self.head, self.head_hash = head, hash
end

-- A canonical JSON-RPC quantity has no leading zeros, so its numeric order is its length first,
-- then its string order.
local function is_quantity(value)
    return type(value) == "string" and (value == "0x0" or value:match("^0x[1-9a-f][0-9a-f]*$") ~= nil)
end

-- The logs of an address up to the observation head. An address seen for the first time is
-- fetched from first_block (block zero when omitted). Providers limit the block range or log
-- count of a request in different ways, so the first page is the whole range. A failed request
-- halves the page and a successful one doubles it. A failure on a single block is raised. Each
-- page is recorded as it arrives, so a failure keeps the pages already fetched.
function methods:get_logs(address, first_block)
    local logs = self.logs[address] or {}
    local fetched = self.fetched[address] or (first_block or 0) - 1
    self.logs[address] = logs
    local page = self.head - fetched
    while fetched < self.head do
        local last_block = math.min(fetched + page, self.head)
        local ok, result = pcall(self.chain.logs, self.chain, address, last_block, fetched + 1)
        if ok then
            for _, log in ipairs(result) do
                assert(is_quantity(log.blockNumber) and is_quantity(log.logIndex), "log position is not a quantity")
                logs[#logs + 1] = log
                self.blocks[eth.small(log.blockNumber)] = log.blockHash
            end
            fetched, page = last_block, page * 2
            self.fetched[address] = fetched
        elseif page == 1 then
            error(result, 0)
        else
            page = page // 2
        end
    end
    self.fetched[address] = self.head
    return logs
end

return M
