-- Pure queue and logical-block checks, included by the documentation's PRT suite.
local new_response_queue = require("prt-response-queue")
local new_clock = require("prt-clock")

local queue = new_response_queue()
local function schedule(id, block)
    queue:schedule(id, block, function()
        return id
    end)
end
schedule(2, 3)
schedule(1, 3)
schedule(3, 2)
assert(#queue:advance(1) == 0)
local responses = queue:advance(3)
assert(#responses == 3 and responses[1].id == 3 and responses[2].id == 1 and responses[3].id == 2)
assert(responses[1].value == 3, "a response lost its callback value")
assert(not pcall(queue.advance, queue, 3), "duplicate block update accepted")
assert(not pcall(queue.advance, queue, 2), "old block update accepted")
schedule(6, 5)
schedule(5, 5)
schedule(4, 6)
responses = queue:advance(7)
assert(responses[1].id == 5 and responses[2].id == 6 and responses[3].id == 4)
assert(#queue:advance(8) == 0 and #queue.pending == 0)
schedule(8, 10)
assert(#queue:advance(9) == 0 and #queue:advance(10) == 1)
schedule(9, 11)
assert(queue:advance(12)[1].id == 9, "a skipped block lost a due response")

local clock = new_clock()
local first, second = clock:request_block(), clock:request_block()
assert(first == second and first == 1, "concurrent requests have different coordinates")
local entries = { { pending = { a = true } }, { pending = { b = true } } }
entries[2].pending.b = nil -- a skip finishes its audience member
assert(not clock:barrier_ready(entries), "early reply released the barrier")
entries[1].pending.a = nil
assert(clock:barrier_ready(entries))
assert(clock:next_block({ 7, 3, 9 }) == 3, "did not choose a supplied boundary")
clock:advance(3)
assert(clock:request_block() == 3)
clock:begin_ordinary()
assert(clock:request_block() == 4)
assert(clock:next_block({ 1, 3, 20 }) == 20, "empty blocks were not skipped")
assert(clock:next_block({}) == nil, "invented a deadline")
assert(not pcall(clock.advance, clock, 3))

return true
