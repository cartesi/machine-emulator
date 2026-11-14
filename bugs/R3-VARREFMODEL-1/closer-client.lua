-- An arbitrary TCP client that announces the phase-closer role to the PRT referee model.
-- It sends exactly the lines `prt.lua phase_closer <address> [stop]` sends, and holds no secret
-- (there is none to hold): any party able to reach the referee can run it.
--   lua5.4 closer-client.lua <address>          close initial admission
--   lua5.4 closer-client.lua <address> stop     stop the referee
-- Prints what happened on stdout: "answered close_phase" or "refused: <reason>". Exits 0 either way.
local socket = require("socket")
local cartesi = require("cartesi")
local address, command = arg[1], arg[2]
local host, port = assert(address, "missing address"):match("^(.-):(%d+)$")
local sock = assert(socket.connect(host, tonumber(port)))
assert(sock:send(cartesi.tojson({ role = "phase_closer", command = command }, -1) .. "\n"))
sock:settimeout(20)
local line, err = sock:receive("*l")
if not line then
    io.write("refused: ", tostring(err), "\n")
    sock:close()
    return
end
local ok, event = pcall(cartesi.fromjson, line)
if not ok or type(event) ~= "table" or event.operation ~= "close_phase" then
    io.write("refused: unexpected line ", line, "\n")
    sock:close()
    return
end
assert(sock:send(cartesi.tojson({ value = "done", id = event.id }, -1) .. "\n"))
socket.sleep(0.5)
sock:close()
io.write("answered close_phase\n")
