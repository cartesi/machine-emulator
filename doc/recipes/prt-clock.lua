-- Logical blocks shared by all concurrent referee requests. The server drains
-- each barrier before releasing continuations. Socket arrival never advances time.
local clock = { __index = {} }

function clock.__index.request_block(self)
    return self.before_ordinary and self.block or self.block + 1
end

function clock.__index.advance(self, block)
    assert(math.type(block) == "integer" and block > self.block, "time must advance")
    self.block = block
    self.before_ordinary = true
end

function clock.__index.begin_ordinary(self)
    self.before_ordinary = false
end

function clock.__index.barrier_ready(_, entries)
    for _, entry in ipairs(entries) do
        if next(entry.pending) then
            return false
        end
    end
    return true
end

-- Only supplied future boundaries can move an otherwise idle simulation.
function clock.__index.next_block(self, boundaries)
    local first
    for _, block in ipairs(boundaries) do
        if block > self.block and (not first or block < first) then
            first = block
        end
    end
    return first
end

return function()
    return setmetatable({ block = 0, before_ordinary = false }, clock)
end
