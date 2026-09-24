-- Runs `scenario` as the referee's main logic against a fresh server on a loopback port,
-- speaking the given protocol. The scenario gets the server, a client constructor, and a
-- connection wait. Each client is a coroutine of the same dispatcher that connects, announces
-- itself (as a player unless told otherwise), and answers every event line with what `handler`
-- returns for it: a reply table (encoded as is), "close" to hang up, a raw line to send
-- verbatim, or nil to delay its answer. A typed client handles every line itself.
local cartesi = require("cartesi")
local socket = require("socket")
local transport = require("game-transport")
local function run_with_server(protocol, scenario)
    local server = transport.new_server("127.0.0.1:0", protocol)
    local _, port = server.listener:getsockname()
    local dispatcher = server.dispatcher
    local function run_client(hello, handler, typed)
        -- These clients are independent processes in the real example, not referee children.
        local client = coroutine.create(function()
            local sock = assert(socket.connect("127.0.0.1", port))
            sock:settimeout(0)
            assert(sock:send(cartesi.tojson(hello or { role = "player" }, -1) .. "\n"))
            local partial
            while true do
                assert(dispatcher:wake_when_readable(sock) == "io")
                local line, err
                line, err, partial = sock:receive("*l", partial)
                if not line and err ~= "timeout" then
                    return
                elseif line then
                    local wire_event = cartesi.fromjson(line)
                    local reply, done
                    if typed then
                        reply, done = handler(wire_event, line)
                    elseif wire_event.operation == "finish" then
                        reply, done = { value = true }, true
                    elseif wire_event.id then
                        reply = { value = true }
                    elseif wire_event.operation == "advance_time" then
                        reply = { value = {} }
                    else
                        reply, done = handler(wire_event)
                    end
                    if reply == "close" then
                        sock:close()
                        return
                    elseif type(reply) == "table" then
                        reply.done = done or reply.done
                        reply = cartesi.tojson(reply, -1)
                    end
                    if reply ~= nil then
                        assert(sock:send(reply .. "\n"))
                    end
                    if done then
                        sock:close()
                        return
                    end
                end
            end
        end)
        dispatcher:schedule(client, "start")
    end
    -- Waits until n connections have announced themselves, or been closed for trying (clients
    -- connect asynchronously).
    local function wait_connections(n)
        while true do
            local announced = 0
            for _, connection in ipairs(server.connections) do
                if connection.is_player or connection.is_phase_closer or connection.dead then
                    announced = announced + 1
                end
            end
            if announced >= n then
                return
            end
            dispatcher:schedule(coroutine.running(), "poll")
            coroutine.yield()
        end
    end
    server:run(function()
        scenario(server, run_client, wait_connections)
    end)
end

return run_with_server
