-- Chain transport for the PRT recipe. The signer owns an exclusive account.
local json = require("dkjson")
local socket = require("socket")
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
    local pipe = assert(io.popen(table.concat(command, " ") .. " 2>/dev/null", "r"))
    local output = pipe:read("a")
    local ok, why, status = pipe:close()
    -- Tool diagnostics may contain endpoints, signer paths, or credentials.
    assert(ok, string.format("%s failed (%s %s)", arguments[1], why, status))
    return output
end

local function decode_json(data)
    local result, position, err = json.decode(data, 1, json.null)
    assert(not err and result ~= nil and not data:sub(position):find("%S"), err or "invalid JSON response")
    return result
end

-- One HTTP/1.1 exchange: the request, then the response's status and body, which comes with a
-- length or in chunks, and whether the node will close the connection.
function M.exchange(tcp, host, path, body)
    assert(tcp:send(table.concat({
        "POST " .. path .. " HTTP/1.1",
        "Host: " .. host,
        "Content-Type: application/json",
        "Content-Length: " .. #body,
        "",
        body,
    }, "\r\n")))
    local status_line = assert(tcp:receive("*l"))
    local status = assert(tonumber(status_line:match("^HTTP/1%.[01] (%d+)")), "RPC HTTP failure: bad status line")
    local headers = {}
    for line in
        function()
            return assert(tcp:receive("*l"))
        end
    do
        if line == "" then
            break
        end
        local name, value = line:match("^([^:]+):%s*(.-)%s*$")
        headers[name:lower()] = value
    end
    local data
    if (headers["transfer-encoding"] or ""):lower() == "chunked" then
        local chunks = {}
        while true do
            local size = assert(tonumber(assert(tcp:receive("*l")):match("^%x+"), 16), "RPC HTTP failure: bad chunk")
            if size == 0 then
                repeat
                until assert(tcp:receive("*l")) == ""
                break
            end
            chunks[#chunks + 1] = assert(tcp:receive(size))
            assert(tcp:receive("*l"))
        end
        data = table.concat(chunks)
    else
        local length = assert(tonumber(headers["content-length"]), "RPC HTTP failure: response without a length")
        data = length > 0 and assert(tcp:receive(length)) or ""
    end
    return status, data, (headers.connection or ""):lower() == "close"
end

local function close_connection(self)
    if self.connection then
        self.connection:close()
        self.connection = nil
    end
end

-- Posts a request over the chain's persistent connection. An idle connection is readable only if
-- the node closed it, so a readable one is replaced before the request is sent. A request is never
-- sent twice, since after a failure the node may have acted on it or not, and only observing the
-- chain can tell.
local function post(self, body)
    if self.connection and #socket.select({ self.connection }, nil, 0) > 0 then
        close_connection(self)
    end
    if not self.connection then
        self.connection = assert(socket.connect(self.host, self.port))
        self.connection:settimeout(self.timeout or nil)
    end
    local ok, status, data, closing = pcall(M.exchange, self.connection, self.host_header, self.path, body)
    if not ok or closing then
        close_connection(self)
    end
    assert(ok, ok or "RPC HTTP failure: " .. tostring(status))
    return status, data
end

function methods:rpc(method, params)
    local body = json.encode({ jsonrpc = "2.0", id = 1, method = method, params = params or {} })
    local status, data = post(self, body)
    assert(status == 200, "RPC HTTP failure: " .. tostring(status))
    local response = decode_json(data)
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

-- The logs of an address from first_block, or the genesis, through last_block.
function methods:logs(address, last_block, first_block)
    return assert(self:rpc("eth_getLogs", {
        {
            address = address,
            fromBlock = string.format("0x%x", first_block or 0),
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

-- All fields are explicit: signing must not choose a nonce or estimate fees.
function methods:sign(signer, transaction)
    local arguments = {
        "cast",
        "mktx",
        "--keystore",
        signer.keystore,
        "--password-file",
        signer.password_file,
        "--chain",
        tostring(evmu.bint(transaction.chain_id)),
        "--nonce",
        transaction.nonce,
        "--gas-limit",
        transaction.gas,
        "--gas-price",
        transaction.max_fee,
        "--priority-gas-price",
        transaction.priority_fee,
        "--value",
        transaction.value,
        transaction.to,
        transaction.data,
    }
    local raw = M.run(arguments):gsub("%s+$", ""):lower()
    return raw, self:verify_signed(signer, transaction, raw)
end

function methods.verify_signed(_, signer, transaction, raw)
    assert(raw:match("^0x02%x+$") and #raw % 2 == 0, "invalid signed EIP-1559 transaction")
    local decoded = decode_json(M.run({ "cast", "decode-transaction", raw }))
    assert(decoded.signer:lower() == signer.address:lower(), "transaction used the wrong signer")
    assert(decoded.to:lower() == transaction.to:lower(), "transaction has the wrong destination")
    assert(decoded.input:lower() == transaction.data:lower(), "transaction calldata differs from the prepared action")
    for field, expected in pairs({
        type = 2,
        chainId = transaction.chain_id,
        nonce = transaction.nonce,
        gas = transaction.gas,
        value = transaction.value,
        maxFeePerGas = transaction.max_fee,
        maxPriorityFeePerGas = transaction.priority_fee,
    }) do
        assert(evmu.bint(decoded[field]) == evmu.bint(expected), "signed transaction field mismatch: " .. field)
    end
    assert(#decoded.accessList == 0, "unexpected transaction access list")
    assert(type(decoded.hash) == "string" and #decoded.hash == 66, "invalid signed transaction hash")
    return decoded.hash:lower()
end

function methods:publish(raw)
    return self:rpc("eth_sendRawTransaction", { raw })
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

-- A chain at an http:// URL. Each request waits for its answer up to the timeout in seconds, 60 by
-- default, or as long as it takes when the timeout is false.
function M.new(url, timeout)
    assert(type(url) == "string")
    local host, port, path = url:match("^http://([^:/]+):?(%d*)(/?.*)$")
    assert(host, "unsupported RPC URL: " .. url)
    port = tonumber(port) or 80
    return setmetatable({
        url = url,
        host = host,
        port = port,
        host_header = host .. ":" .. port,
        path = path ~= "" and path or "/",
        timeout = timeout == nil and 60 or timeout,
    }, { __index = methods })
end

return M
