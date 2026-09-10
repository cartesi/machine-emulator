-- Each player keeps callbacks for responses due on later blocks.
local response_queue = { __index = {} }

function response_queue.__index.schedule(self, id, block, respond)
    assert(math.type(id) == "integer" and math.type(block) == "integer")
    self:cancel(id)
    self.pending[#self.pending + 1] = { id = id, block = block, respond = respond }
end

function response_queue.__index.cancel(self, id)
    for index, pending in ipairs(self.pending) do
        if pending.id == id then
            table.remove(self.pending, index)
            return
        end
    end
end

function response_queue.__index.advance(self, block)
    assert(math.type(block) == "integer" and block > self.block, "time must advance")
    self.block = block
    table.sort(self.pending, function(a, b)
        return a.block < b.block or (a.block == b.block and a.id < b.id)
    end)
    local responses = {}
    while self.pending[1] and self.pending[1].block <= block do
        local pending = table.remove(self.pending, 1)
        responses[#responses + 1] = { id = pending.id, value = pending.respond() }
    end
    return responses
end

return function()
    return setmetatable({ pending = {}, block = -1 }, response_queue)
end
