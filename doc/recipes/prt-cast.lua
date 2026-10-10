-- Chain transport for the PRT recipe. The signer owns an exclusive account.
local json = require("dkjson")
local http = require("socket.http")
local ltn12 = require("ltn12")
local evmu = require("cartesi.evmu")

local M = {}
local methods = {}

local function quote(value)
    return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

function M.run(arguments)
    local command = {}
    for i, value in ipairs(arguments) do
        assert(not tostring(value):find("\0", 1, true), "NUL in command argument")
        command[i] = quote(value)
    end
    local pipe = assert(io.popen(table.concat(command, " ") .. " 2>&1", "r"))
    local output = pipe:read("a")
    local ok, why, status = pipe:close()
    assert(ok, string.format("%s failed (%s %s): %s", arguments[1], why, status, output))
    return output
end

local function decode_json(data)
    local result, position, err = json.decode(data, 1, json.null)
    assert(not err and result ~= nil and not data:sub(position):find("%S"), err or "invalid JSON response")
    return result
end

function methods:rpc(method, params)
    local body = json.encode({ jsonrpc = "2.0", id = 1, method = method, params = params or {} })
    local chunks = {}
    local ok, status = http.request({
        url = self.url,
        method = "POST",
        headers = { ["Content-Type"] = "application/json", ["Content-Length"] = #body },
        source = ltn12.source.string(body),
        sink = ltn12.sink.table(chunks),
    })
    assert(ok and status == 200, "RPC HTTP failure: " .. tostring(status))
    local response = decode_json(table.concat(chunks))
    assert(response.jsonrpc == "2.0" and response.id == 1, "unexpected RPC response")
    if response.error then
        return nil, response.error
    end
    return response.result
end

-- A numeric policy is a number of successor blocks, not a count including
-- the observed block. Consensus tags deliberately have no numeric fallback.
function M.policy(value)
    if type(value) == "string" and value:match("^%d+$") then
        value = tonumber(value)
    end
    assert(
        value == "safe" or value == "finalized" or (math.type(value) == "integer" and value >= 0),
        "observation policy must be a nonnegative block depth, safe, or finalized"
    )
    return value
end

function methods:head(policy)
    local tip = assert(self:rpc("eth_getBlockByNumber", { "latest", false }))
    assert(tip ~= json.null, "latest block unavailable")
    local number = assert(tonumber(tip.number))
    local block = tip
    if policy ~= nil then
        policy = M.policy(policy)
        local selector = type(policy) == "number" and string.format("0x%x", math.max(0, number - policy)) or policy
        block = assert(self:rpc("eth_getBlockByNumber", { selector, false }))
        assert(block ~= json.null, "observation block unavailable: " .. selector)
    end
    assert(tonumber(block.number) <= number, "observation block is ahead of sampled tip")
    return assert(tonumber(block.number)), assert(block.hash), number, assert(tip.hash)
end

function methods:is_canonical(number, hash)
    local block = assert(self:rpc("eth_getBlockByNumber", { string.format("0x%x", number), false }))
    return block ~= json.null and block.hash == hash
end

function methods:logs(address, last_block)
    return assert(self:rpc("eth_getLogs", {
        {
            address = address,
            fromBlock = "0x0",
            toBlock = string.format("0x%x", last_block),
        },
    }))
end

function methods:call(to, data, block)
    return self:rpc("eth_call", { { to = to, data = data }, block or "latest" })
end

function methods:simulate(signer, to, data, value, block)
    value = value or "0"
    return self:rpc("eth_call", {
        { from = signer.address, to = to, data = data, value = "0x" .. evmu.bint.tobase(evmu.bint(value), 16) },
        block or "pending",
    })
end

function methods:send(signer, to, data, value)
    value = value or "0"
    local _, failure = self:simulate(signer, to, data, value)
    if failure then
        -- Anvil reports EVM reverts with code 3. Provider failures must stop the
        -- run instead of permanently suppressing a potentially legal action.
        assert(failure.code == 3, "transaction preflight RPC failure: " .. json.encode(failure))
        return nil, failure
    end
    local arguments = {
        "cast",
        "send",
        "--rpc-url",
        self.url,
        "--keystore",
        signer.keystore,
        "--password-file",
        signer.password_file,
        "--json",
        "--value",
        tostring(value),
        to or "--create",
        data,
    }
    local output = M.run(arguments)
    local receipt = decode_json(output)
    assert(tonumber(receipt.status) == 1, "mined transaction reverted: " .. receipt.transactionHash)
    assert(
        type(receipt.transactionHash) == "string" and #receipt.transactionHash == 66,
        "receipt lacks transaction hash"
    )
    local transaction = assert(self:rpc("eth_getTransactionByHash", { receipt.transactionHash }))
    assert(transaction.from:lower() == signer.address:lower(), "transaction used the wrong signer")
    assert(transaction.input:lower() == data:lower(), "transaction calldata differs from the prepared action")
    assert(
        (not to and transaction.to == json.null) or (to and transaction.to:lower() == to:lower()),
        "transaction has the wrong destination"
    )
    assert(evmu.bint(transaction.value) == evmu.bint(value), "transaction has the wrong value")
    return receipt
end

function M.new(url)
    assert(type(url) == "string")
    return setmetatable({ url = url }, { __index = methods })
end

return M
