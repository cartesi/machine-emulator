-- Two roles for the R6-DYNBRIDGE-3 test, each run as its own process.
--
--   lua5.4 peer.lua server MODE HOLD_SECONDS
--     A fake node's WebSocket endpoint on 127.0.0.1 (ephemeral port, printed on stdout). It completes the
--     RFC 6455 handshake and answers eth_subscribe, then:
--       MODE "silent":     sends nothing more (control: no frame starts within the timeout);
--       MODE "mid-frame":  sends the first byte (0x81, FIN + text) of the next frame and nothing more.
--     In both modes it keeps the connection open (no FIN, no RST) for HOLD_SECONDS, as a stalled proxy or a
--     half-open TCP connection would, then closes it.
--
--   lua5.4 peer.lua client PORT TIMEOUT
--     The REAL doc/recipes/prt-websocket.lua subscription, used exactly as crisium.lua's idle branch uses it:
--     new_head_subscription(url), then heads:wait(TIMEOUT). Prints one line "returned <seconds> <ok> <value>"
--     once wait returns (with a value, nil, or an error).
local socket = require("socket")
local ws = require("prt-websocket")
local role = arg[1]

if role == "server" then
    local mode, hold = arg[2], tonumber(arg[3] or "30")
    local srv = assert(socket.bind("127.0.0.1", 0))
    local _, port = srv:getsockname()
    io.stdout:write(port, "\n")
    io.stdout:flush()
    srv:settimeout(30)
    local c = assert(srv:accept())
    c:settimeout(30)
    local key
    while true do
        local line = assert(c:receive("*l"))
        if line == "" then
            break
        end
        key = line:match("^Sec%-WebSocket%-Key: (.*)$") or key
    end
    assert(c:send("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        .. "Sec-WebSocket-Accept: " .. ws.get_accept(key) .. "\r\n\r\n"))
    -- the client's masked eth_subscribe frame
    local h = assert(c:receive(2))
    local len = h:byte(2) & 0x7f
    if len == 126 then
        len = string.unpack(">I2", assert(c:receive(2)))
    end
    assert(c:receive(4 + len))
    local reply = '{"jsonrpc":"2.0","id":1,"result":"0x1234"}'
    assert(c:send(string.char(0x81, #reply) .. reply))
    socket.sleep(0.3)
    if mode == "mid-frame" then
        assert(c:send(string.char(0x81))) -- first byte of the next text frame, then silence
    elseif mode ~= "silent" then
        error("unknown mode " .. tostring(mode))
    end
    socket.sleep(hold)
    c:close()
    os.exit(0, true)
elseif role == "client" then
    local port, timeout = arg[2], tonumber(arg[3])
    local heads = ws.new_head_subscription("ws://127.0.0.1:" .. port)
    local t0 = socket.gettime()
    local ok, value = pcall(heads.wait, heads, timeout)
    io.stdout:write(string.format("returned %.3f %s %s\n", socket.gettime() - t0, tostring(ok), tostring(value)))
    io.stdout:flush()
    os.exit(0, true)
else
    error("usage: peer.lua server MODE HOLD | client PORT TIMEOUT")
end
