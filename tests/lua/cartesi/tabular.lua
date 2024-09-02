local M = {}

-- convert a table with indexed rows into a table with named rows. e.g.
-- {"foo", 999} -> {name = "foo", cycles = 999} with keys described by md
local function expand_row(metadata, row)
    local expanded_row = {}
    for key, val in ipairs(metadata) do
        expanded_row[val] = row[key]
    end
    return expanded_row
end

-- apply `expand_row` for each row of `t`. e.g.
-- {{ "foo", 999 }} -> {{name = "foo", cycles = 999}} with keys described by md
M.expand = function(metadata, t)
    local expanded_t = {}
    for _, row in ipairs(t) do
        expanded_t[#expanded_t + 1] = expand_row(metadata, row)
    end
    return expanded_t
end

return M
