-- A WebSocket client for one JSON-RPC subscription to new block headers. It implements what that
-- needs from RFC 6455 over luasocket: the opening handshake, masked text frames from the client,
-- reassembly of fragmented messages from the server, and answers to pings.
local socket = require("socket")
local cartesi = require("cartesi")
local json = require("dkjson")
local M = {}
local methods = {}

local HANDSHAKE_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

local function rotate(x, n)
    return ((x << n) | (x >> (32 - n))) & 0xffffffff
end

-- SHA-1, which the handshake uses to prove the server understood the request.
function M.sha1(message)
    local h = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 }
    local length = #message
    message = message .. "\128" .. string.rep("\0", (55 - length) % 64) .. string.pack(">I8", length * 8)
    for chunk = 1, #message, 64 do
        local w = {}
        for i = 1, 16 do
            w[i] = string.unpack(">I4", message, chunk + 4 * (i - 1))
        end
        for i = 17, 80 do
            w[i] = rotate(w[i - 3] ~ w[i - 8] ~ w[i - 14] ~ w[i - 16], 1)
        end
        local a, b, c, d, e = table.unpack(h)
        for i = 1, 80 do
            local f, k
            if i <= 20 then
                f, k = (b & c) | (~b & d), 0x5a827999
            elseif i <= 40 then
                f, k = b ~ c ~ d, 0x6ed9eba1
            elseif i <= 60 then
                f, k = (b & c) | (b & d) | (c & d), 0x8f1bbcdc
            else
                f, k = b ~ c ~ d, 0xca62c1d6
            end
            a, b, c, d, e = (rotate(a, 5) + (f & 0xffffffff) + e + k + w[i]) & 0xffffffff, a, rotate(b, 30), c, d
        end
        for i, value in ipairs({ a, b, c, d, e }) do
            h[i] = (h[i] + value) & 0xffffffff
        end
    end
    return string.pack(">I4I4I4I4I4", table.unpack(h))
end

-- The Sec-WebSocket-Accept value a server must answer a Sec-WebSocket-Key with.
function M.get_accept(key)
    return cartesi.tobase64(M.sha1(key .. HANDSHAKE_GUID))
end

local function random_bytes(count)
    local file <close> = assert(io.open("/dev/urandom", "rb"))
    return assert(file:read(count))
end

-- Client frames are masked with a fresh key, as the RFC requires of every client frame.
local function send_frame(self, opcode, payload)
    local mask, length, masked = random_bytes(4), #payload, {}
    for i = 1, length do
        masked[i] = string.char(payload:byte(i) ~ mask:byte((i - 1) % 4 + 1))
    end
    local header = length < 126 and string.pack(">BB", 0x80 | opcode, 0x80 | length)
        or length < 65536 and string.pack(">BBI2", 0x80 | opcode, 0xfe, length)
        or string.pack(">BBI8", 0x80 | opcode, 0xff, length)
    assert(self.tcp:send(header .. mask .. table.concat(masked)))
end

function methods:send(text)
    send_frame(self, 0x1, text)
end

-- The next text message, or nil if none starts within the timeout. Once a message starts, the rest
-- is read without a timeout, so a slow frame never breaks the framing.
function methods:receive(timeout)
    local parts = {}
    while true do
        self.tcp:settimeout(#parts == 0 and timeout or nil)
        local first, err = self.tcp:receive(1)
        if not first then
            assert(err == "timeout" and #parts == 0, err)
            return nil
        end
        self.tcp:settimeout(nil)
        local second = assert(self.tcp:receive(1)):byte()
        assert(second & 0x80 == 0, "the server masked a frame")
        local length = second & 0x7f
        if length == 126 then
            length = string.unpack(">I2", assert(self.tcp:receive(2)))
        elseif length == 127 then
            length = string.unpack(">I8", assert(self.tcp:receive(8)))
        end
        local payload = length > 0 and assert(self.tcp:receive(length)) or ""
        local final, opcode = first:byte() & 0x80 ~= 0, first:byte() & 0x0f
        if opcode == 0x9 then
            send_frame(self, 0xa, payload)
        elseif opcode == 0x8 then
            error("the server closed the websocket")
        elseif opcode == 0x0 or opcode == 0x1 then
            parts[#parts + 1] = payload
            if final then
                return table.concat(parts)
            end
        end
    end
end

-- A WebSocket over a connected socket, after its handshake.
function M.new(tcp)
    return setmetatable({ tcp = tcp }, { __index = methods })
end

-- Opens a WebSocket to a ws:// URL.
function M.connect(url)
    local host, port, path = assert(url:match("^ws://([^:/]+):?(%d*)(/?.*)$"))
    port = tonumber(port) or 80
    local tcp = assert(socket.connect(host, port))
    local key = cartesi.tobase64(random_bytes(16))
    assert(tcp:send(table.concat({
        "GET " .. (path ~= "" and path or "/") .. " HTTP/1.1",
        "Host: " .. host .. ":" .. port,
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: " .. key,
        "Sec-WebSocket-Version: 13",
        "",
        "",
    }, "\r\n")))
    assert(assert(tcp:receive("*l")):match("^HTTP/1%.1 101 "), "the node refused the websocket")
    local headers = {}
    while true do
        local line = assert(tcp:receive("*l"))
        if line == "" then
            break
        end
        local name, value = line:match("^([^:]+):%s*(.-)%s*$")
        headers[name:lower()] = value
    end
    assert(headers["sec-websocket-accept"] == M.get_accept(key), "bad websocket handshake")
    return M.new(tcp)
end

local subscription_methods = {}

-- Subscribes to the new block headers of the node at a ws:// URL.
function M.new_head_subscription(url)
    local websocket = M.connect(url)
    websocket:send(json.encode({ jsonrpc = "2.0", id = 1, method = "eth_subscribe", params = { "newHeads" } }))
    local reply = assert(json.decode(assert(websocket:receive(nil))))
    local id = assert(reply.result, reply.error and reply.error.message)
    return setmetatable({ websocket = websocket, id = id }, { __index = subscription_methods })
end

-- The newest header the node has pushed, or nil if none arrives within the timeout. Headers that
-- queued up meanwhile, as one anvil_mine of many blocks sends, are drained and only the last kept.
function subscription_methods:wait(timeout)
    local latest
    local message = self.websocket:receive(timeout)
    while message do
        local notification = assert(json.decode(message))
        if notification.method == "eth_subscription" and notification.params.subscription == self.id then
            latest = notification.params.result
        end
        message = self.websocket:receive(0)
    end
    return latest
end

return M
