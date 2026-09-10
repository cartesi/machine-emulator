-- Each player keeps callbacks for responses due on later blocks.
local actions = { __index = {} }

function actions.__index.schedule(self, id, block, expires, respond)
    assert(math.type(id) == "integer" and math.type(block) == "integer")
    self:cancel(id)
    self.pending[#self.pending + 1] = { id = id, block = block, expires = expires, respond = respond }
end

function actions.__index.cancel(self, id)
    for index, pending in ipairs(self.pending) do
        if pending.id == id then
            table.remove(self.pending, index)
            return
        end
    end
end

function actions.__index.advance(self, block)
    assert(math.type(block) == "integer" and block > self.block, "time must advance")
    self.block = block
    table.sort(self.pending, function(a, b)
        return a.block < b.block or (a.block == b.block and a.id < b.id)
    end)
    local responses = {}
    for index = #self.pending, 1, -1 do
        local pending = self.pending[index]
        if pending.expires and block >= pending.expires then
            table.remove(self.pending, index)
        end
    end
    while self.pending[1] and self.pending[1].block <= block do
        local pending = table.remove(self.pending, 1)
        responses[#responses + 1] = { id = pending.id, value = pending.respond() }
    end
    return responses
end

return function()
    return setmetatable({ pending = {}, block = -1 }, actions)
end
