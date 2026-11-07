-- A stub Ethereum JSON-RPC node for R1-PLAYER-3, over HTTP/1.1 with keep-alive.
-- Usage: lua5.4 server.lua FIXTURE.json PORT_FILE
--
-- It serves a canned chain whose tip is fixture.tip and whose logs are fixture.logs. Like a node
-- with a block-range limit on log filters (Reth's --rpc.max-blocks-per-filter, or a hosted provider's
-- 2k-10k block cap), it answers eth_getLogs with error -32005 whenever the filter spans more than
-- fixture.max_range blocks. Narrower filters get every matching log in range. It records each
-- eth_getLogs request so the test can show what the callers asked for. Extra methods:
--   test_requests  returns the recorded eth_getLogs requests;
--   test_shutdown  stops the server.
local socket = require("socket")
local json = require("dkjson")

local fixture = assert(json.decode(assert(io.open(arg[1])):read("a")))
local server = assert(socket.bind("127.0.0.1", 0))
local _, port = server:getsockname()
do
    local temporary = arg[2] .. ".tmp"
    local file = assert(io.open(temporary, "w"))
    file:write(tostring(port))
    file:close()
    assert(os.rename(temporary, arg[2]))
end

local requests = {}
local function hex(n)
    return string.format("0x%x", n)
end
local function block_hash(n)
    return string.format("0x%064x", n + 0xb10c0000)
end

local function handle(request)
    local method, params = request.method, request.params or {}
    if method == "eth_getBlockByNumber" then
        local selector = params[1]
        local n = selector == "latest" and fixture.tip or tonumber(selector)
        if not n or n > fixture.tip then
            return json.null
        end
        return { number = hex(n), hash = block_hash(n) }
    elseif method == "eth_getLogs" then
        local filter = params[1]
        local from, to = tonumber(filter.fromBlock), tonumber(filter.toBlock)
        local entry = { fromBlock = from, toBlock = to, address = filter.address }
        requests[#requests + 1] = entry
        if to - from + 1 > fixture.max_range then
            entry.outcome = "refused"
            return nil, { code = -32005, message = "query exceeds max block range " .. fixture.max_range }
        end
        local result = {}
        for _, log in ipairs(fixture.logs) do
            local n = tonumber(log.blockNumber)
            if log.address:lower() == tostring(filter.address):lower() and n >= from and n <= to then
                result[#result + 1] = log
            end
        end
        entry.outcome = "ok"
        return result
    elseif method == "test_requests" then
        return requests
    elseif method == "test_shutdown" then
        return true, nil, true
    end
    return nil, { code = -32601, message = "method not found: " .. tostring(method) }
end

-- Reads one HTTP request from a client, or returns nil when it closed.
local function read_request(client)
    local line = client:receive("*l")
    if not line then
        return nil
    end
    local length = 0
    while true do
        local header = client:receive("*l")
        if not header then
            return nil
        end
        if header == "" then
            break
        end
        local name, value = header:match("^([^:]+):%s*(.-)%s*$")
        if name and name:lower() == "content-length" then
            length = tonumber(value)
        end
    end
    return length > 0 and client:receive(length) or ""
end

local clients, deadline, running = {}, socket.gettime() + 300, true
while running and socket.gettime() < deadline do
    local watched = { server }
    for _, client in ipairs(clients) do
        watched[#watched + 1] = client
    end
    local readable = socket.select(watched, nil, 1)
    for _, ready in ipairs(readable) do
        if ready == server then
            local client = server:accept()
            if client then
                client:settimeout(10)
                clients[#clients + 1] = client
            end
        else
            local body = read_request(ready)
            if not body then
                ready:close()
                for i, client in ipairs(clients) do
                    if client == ready then
                        table.remove(clients, i)
                        break
                    end
                end
            else
                local request = json.decode(body)
                local result, err, stop = handle(request)
                local response = { jsonrpc = "2.0", id = request.id }
                if err then
                    response.error = err
                else
                    response.result = result
                end
                local data = json.encode(response)
                ready:send(table.concat({
                    "HTTP/1.1 200 OK",
                    "Content-Type: application/json",
                    "Content-Length: " .. #data,
                    "",
                    data,
                }, "\r\n"))
                if stop then
                    running = false
                end
            end
        end
    end
end
for _, client in ipairs(clients) do
    client:close()
end
server:close()
