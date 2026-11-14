-- R6-DYNBRIDGE-3: crisium's WebSocket head subscription (doc/recipes/prt-websocket.lua) reads the rest of a
-- started frame with no timeout, so heads:wait(poll_interval), which crisium.lua's idle branch expects to come
-- back within the poll interval, blocks for as long as a stalled peer keeps the connection open.
--
-- Asserted: with TIMEOUT = 1 s (crisium's default --poll-interval), heads:wait(TIMEOUT) returns (a header, nil or
-- an error) within BOUND = 3 s also when the peer stalls after the first byte of a frame. Control in the same run:
-- the same peer that starts no frame at all makes wait return nil within BOUND (else the test is a harness error).
-- The client is killed after KILL = 10 s; a client still blocked then is the violation (exit 1).
local harness = require("harness")

local TIMEOUT, BOUND, KILL, HOLD = 1, 3, 10, 30

local function sh_quote(s)
    return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

-- Runs one scenario; returns the client's result line (or nil if it had to be killed) and its exit status.
local function scenario(mode)
    local server = assert(io.popen("sh -c " .. sh_quote("echo $$; exec lua5.4 peer.lua server " .. mode .. " "
        .. HOLD), "r"))
    local pid = tonumber(server:read("l"))
    local port = tonumber(server:read("l"))
    if not pid or not port then
        server:close()
        harness.setup_error("fake node did not start (" .. mode .. ")")
    end
    local client = assert(io.popen(string.format("timeout -k 1 %d lua5.4 peer.lua client %d %d 2>&1; echo status=$?",
        KILL, port, TIMEOUT), "r"))
    local out = client:read("a")
    client:close()
    os.execute("kill " .. pid .. " 2>/dev/null")
    server:read("a")
    server:close()
    local status = tonumber(out:match("status=(%d+)"))
    local line = out:match("(returned [^\n]*)")
    io.stderr:write(string.format("[%s] client output: %s\n", mode, (out:gsub("\n", " | "))))
    return line, status
end

harness.main(function()
    -- Control: no frame starts, wait(TIMEOUT) must return nil within BOUND.
    local line, status = scenario("silent")
    local secs, ok, value = (line or ""):match("^returned ([%d.]+) (%S+) (%S+)")
    secs = tonumber(secs)
    if status ~= 0 or not secs or secs > BOUND or ok ~= "true" or value ~= "nil" then
        harness.setup_error("control scenario did not behave as expected (status " .. tostring(status)
            .. ", line " .. tostring(line) .. ")")
    end
    io.stderr:write(string.format("control: wait(%d) with no frame returned nil after %.3f s\n", TIMEOUT, secs))

    -- The stall after the first byte of a frame.
    line, status = scenario("mid-frame")
    secs = tonumber((line or ""):match("^returned ([%d.]+)"))
    if not secs then
        if status ~= 124 and status ~= 137 then
            harness.setup_error("client failed without a result (status " .. tostring(status) .. ")")
        end
        io.stderr:write(string.format("mid-frame stall: wait(%d) still blocked after %d s, killed (status %d)\n",
            TIMEOUT, KILL, status))
    else
        io.stderr:write(string.format("mid-frame stall: wait(%d) returned after %.3f s (%s)\n", TIMEOUT, secs, line))
    end
    return harness.expect(secs ~= nil and secs <= BOUND, string.format(
        "R4 'The honest operator observes the chain and submits its transactions within the dispute clocks': "
            .. "the player's head subscription wait(%d s) must return within %d s (it returned after %s) "
            .. "when the node's connection stalls mid-frame, so crisium's loop keeps reading the tip, or fails "
            .. "loudly so prt-supervise.sh relaunches it", TIMEOUT, BOUND,
        secs and string.format("%.3f s", secs) or ("more than " .. KILL .. " s, still blocked")))
end)
