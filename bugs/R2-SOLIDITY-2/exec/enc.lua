local M = {}
local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
M.hex = hex
function M.append_log(parts, log)
    for _, access in ipairs(log.accesses) do
        if access.log2_size == 3 then
            assert(access.read and #access.read == 32, "word access lacks its Merkle leaf")
            parts[#parts + 1] = access.read
        elseif access.type == "read" then
            assert(access.read and #access.read == 32, "region read is not a bytes32")
            parts[#parts + 1] = access.read
            parts[#parts + 1] = assert(access.read_hash)
        else
            parts[#parts + 1] = assert(access.read_hash)
        end
        for _, sibling in ipairs(access.sibling_hashes) do
            parts[#parts + 1] = sibling
        end
    end
    return parts
end
function M.proof(...)
    local parts = {}
    for _, log in ipairs({ ... }) do M.append_log(parts, log) end
    return hex(table.concat(parts))
end
function M.req(id, fn, args, exp, note)
    local a = {}
    for i, x in ipairs(args) do
        a[i] = string.format('{"t":"%s","v":"%s"}', x[1], x[2])
    end
    local e = exp and ('"' .. hex(exp) .. '"') or "null"
    return string.format('{"id":%d,"fn":"%s","args":[%s],"exp":%s,"note":"%s"}\n', id, fn, table.concat(a, ","), e, note or "")
end
return M
