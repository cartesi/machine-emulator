-- The parts of the verification game that do not depend on what is being disputed, shared by
-- verification-game.lua and rolling-verification-game.lua: the narration, the wire protocol,
-- the players' serve loop and fork trick, the referee's request plumbing, and the bisection
-- loop. Each game supplies the machines, the bisection levels, the terminal round, and the
-- verification of the disputed transition.

local cartesi = require("cartesi")
local socket = require("socket")

--------------------------------------------------------------------------------
-- Small utilities
--------------------------------------------------------------------------------

-- With VERIFICATION_GAME_TRACE set, every wire message is dumped to stderr, unbuffered so it
-- survives a redirect. The referee runs with it on, the players with it off, so an empty
-- player transcript also confirms a clean run.
io.stderr:setvbuf("no")
local tracing = os.getenv("VERIFICATION_GAME_TRACE") ~= nil
local function trace_wire(player, direction, line)
    if tracing then
        io.stderr:write(string.format("%s player %s: %s\n", direction, player.index or "?", line))
    end
end

-- The referee narrates the game, kept apart from the wire trace on stderr so the run reads as a
-- story whether or not tracing is on. A hash is shown by its first four bytes.
local function short_hash(hash)
    return cartesi.tohex(hash):sub(1, 10) .. "..."
end

-- The narration is split into phases, each written to its own file so the rendered walkthrough can
-- print a short phase whole and reduce a long bisection to its first and last few lines. phase()
-- opens the file the following eventf() lines go to, closing the previous one. Before the first
-- phase() the narration goes to stdout. Once a phase file is open eventf() echoes to stdout as
-- well, so a live run still shows the story even though its lines are being filed away.
local narration = io.stdout
local function phase(filename)
    if narration ~= io.stdout then
        narration:close()
    end
    narration = assert(io.open(filename, "w"))
end

local function eventf(fmt, ...)
    local line = string.format(fmt, ...)
    narration:write(line, "\n")
    if narration ~= io.stdout then
        io.stdout:write(line, "\n")
    end
end

--------------------------------------------------------------------------------
-- Wire protocol
--
-- Each message is one line, the compact JSON of a Lua value by cartesi.tojson plus a newline.
-- Binary values do not survive plain JSON, so each reply carries a schema, named by the
-- referee, that tags its binary and compound fields. tojson then encodes hashes as Base64 and
-- embeds proofs as nested objects, and fromjson decodes them back. The schema
-- dictionary below, referencing the built-in Proof, holds the schemas every game
-- uses, and each game script adds the entries for its own log and result commitments.
--------------------------------------------------------------------------------

-- Binary step logs travel over the wire as raw bytes (Base64 in the JSON encoding):
-- players read the files the machine writes, and the referee materializes received
-- bytes back into files for the verify methods, which take filenames.
local function read_file(path)
    local f = assert(io.open(path, "rb"))
    local data = f:read("a")
    f:close()
    return data
end

local function write_file(path, data)
    local f = assert(io.open(path, "wb"))
    f:write(data)
    f:close()
end

local SCHEMA_DICT = {
    -- The claimed final state hash a player posts at the start.
    FinalHashCommitment = "Base64",
    -- A single bisection round's reply, the root hash at the mid cycle.
    BisectionCommitment = "Base64",
}

-- Encodes a value and writes it as one line. Returns the truthy byte count on success, or nil and
-- an error on a closed connection, so the caller decides whether a failed send is fatal.
local function send(player, value, schema)
    local line = cartesi.tojson(value, -1, schema, SCHEMA_DICT)
    trace_wire(player, "to", line)
    return player.connection:send(line .. "\n")
end

-- Reads and decodes one full line from a player, blocking until it is in and resuming from any
-- partial parked on the player. Lines the player still owes as drops (replies to superseded
-- requests) are discarded. On the awaited reply the player's in-flight request is cleared.
local function receive(player, schema)
    local conn = player.connection
    conn:settimeout(nil)
    while true do
        local line = assert(conn:receive("*l", player.partial))
        trace_wire(player, "from", line)
        if player.stale_requests_pending > 0 then
            player.stale_requests_pending, player.partial = player.stale_requests_pending - 1, nil
        else
            player.last_request_code, player.last_request_schema, player.partial = nil, nil, nil
            return cartesi.fromjson(line, schema, SCHEMA_DICT)
        end
    end
end

-- Reads a line from whichever connection completes one first, without blocking on any single
-- one. The players table's connection-to-index map links each ready connection back to its
-- player. Bytes accumulate in each player's partial until a line completes. A line a player
-- still owes as a drop is discarded and reading continues, otherwise its in-flight request is
-- cleared and that player and its decoded reply returned.
local function receive_any(players, conns, schema)
    for _, conn in ipairs(conns) do
        conn:settimeout(0)
    end
    while true do
        for _, conn in ipairs(socket.select(conns, nil)) do
            local player = players[players.index_of[conn]]
            local line, status, partial = conn:receive("*l", player.partial)
            if line then
                trace_wire(player, "from", line)
                if player.stale_requests_pending > 0 then
                    player.stale_requests_pending, player.partial = player.stale_requests_pending - 1, nil
                else
                    player.last_request_code, player.last_request_schema, player.partial = nil, nil, nil
                    return player, cartesi.fromjson(line, schema, SCHEMA_DICT)
                end
            elseif status == "closed" then
                player.dead = true
                table.remove(conns, player.index)
            else
                assert(status == "timeout", status)
                player.partial = partial
            end
        end
    end
end

--------------------------------------------------------------------------------
-- Fork trick
--
-- A player holds the agreed lower bound in `agreed` and, while bisecting, a `tentative` forked
-- from it and advanced to the mid cycle. It never runs backward, since the referee never bisects
-- below the agreed machine. Each round the referee names the branch taken at the previous round,
-- so the player promotes the tentative entry on "agree", discards it on "disagree", and does
-- nothing on "start". Both are tables holding the machine, so a game can promote its own
-- position bookkeeping along with it.
--------------------------------------------------------------------------------

-- Applies the branch the referee reported for the previous round. "agree" promotes the tentative
-- entry to the agreed one, "disagree" discards it, "start" has none. A round answered from a
-- fixed point leaves no tentative entry, but that only happens where rounds disagree, so "agree"
-- never finds the slot empty. Either way it is cleared.
local function take_branch(player, branch)
    if branch == "agree" then
        player.agreed.machine:shutdown_server()
        player.agreed = player.tentative
    elseif branch == "disagree" and player.tentative then
        player.tentative.machine:shutdown_server()
    end
    player.tentative = nil
end

--------------------------------------------------------------------------------
-- Players
--------------------------------------------------------------------------------

-- Connects to the referee and serves its requests, loading each code snippet, running it in the
-- player's scope, and sending the value back. The last request is always for the result, whose
-- handler marks the player done, so the loop exits after that reply. Then it shuts down every
-- machine and fork it still holds.
local function run(player)
    local address = assert(arg[2], "missing referee address")
    local host, port = address:match("^(.-):(%d+)$")
    player.connection = assert(socket.connect(host, tonumber(port)))
    repeat
        local request = receive(player)
        -- The trusted referee's snippet runs with the player as its environment, reaching the
        -- player and its operations by name. The referee names the schema its reply is encoded under.
        local chunk = assert(load(request.code, "=referee", "t", player))
        assert(send(player, chunk(), request.schema))
    until player.done
    player.connection:close()
    if player.tentative then
        player.tentative.machine:shutdown_server()
    end
    player.agreed.machine:shutdown_server()
end

-- A player bundles the agreed entry it was handed, which anchors the bisection at the lower
-- bound, the tentative entry it forks while bisecting, and the game's operations as fields the
-- referee invokes by name, each taking the player first so a colon call like
-- player:prove_output() supplies it. It also carries a reference to itself under `player`, since
-- it is the environment the referee's snippets run in.
local function new_player(fields)
    local player = { stale_requests_pending = 0, send_result_delay = 0, run = run }
    for key, value in pairs(fields) do
        player[key] = value
    end
    player.player = player
    return player
end

--------------------------------------------------------------------------------
-- Referee
--------------------------------------------------------------------------------

-- The one place the referee issues a request, used by every wait_for_*. Each player records the
-- request it is handling, cleared once the reply is read. If it is already handling this exact
-- request, its in-flight reply answers it and nothing is sent. If it is handling a superseded
-- one, the new request is sent and the stale reply counted to be dropped. A player handling
-- nothing is simply asked. A player that has posted its result has exited and closed, so the send
-- fails; it is marked dead and skipped from then on.
local function request(player, schema, code)
    if player.dead then
        return
    end
    if player.last_request_code == code and player.last_request_schema == schema then
        return
    end
    if player.last_request_code ~= nil then
        player.stale_requests_pending = player.stale_requests_pending + 1
    end
    if not send(player, { code = code, schema = schema }) then
        player.dead = true
        return
    end
    player.last_request_code, player.last_request_schema = code, schema
end

-- Asks a player to run a snippet (a string.format template plus its arguments) and waits for
-- the single reply, encoded and decoded under the named schema.
local function wait_for_one(player, schema, code, ...)
    request(player, schema, string.format(code, ...))
    return receive(player, schema)
end

-- Broadcasts the request to every player, then collects every reply in completion order through
-- receive_any, so the players compute in parallel and a slow one never holds up a ready one.
-- Returns the replies keyed by player index.
local function wait_for_all(players, schema, code, ...)
    code = string.format(code, ...)
    local conns, replies = {}, {}
    for _, player in ipairs(players) do
        request(player, schema, code)
        conns[#conns + 1] = player.connection
    end
    for _ = 1, #conns do
        local player, reply = receive_any(players, conns, schema)
        replies[player.index] = reply
    end
    return replies
end

-- Broadcasts the request and returns the first reply to arrive, leaving the rest. It shares the
-- request discipline above and does not judge the reply, the caller does. A player that died
-- (exited after posting its result) is skipped, so its closed connection is never polled.
local function wait_for_any(players, schema, code, ...)
    code = string.format(code, ...)
    local conns = {}
    for _, player in ipairs(players) do
        request(player, schema, code)
        if not player.dead then
            conns[#conns + 1] = player.connection
        end
    end
    local _, reply = receive_any(players, conns, schema)
    return reply
end

-- Asks both players for their opening commitment and returns the two, keyed by index.
local function wait_for_final_hash(players)
    return wait_for_all(players, "FinalHashCommitment", "return player:commit_final_hash()")
end

-- Broadcasts one bisection round at `target` on `level`, carrying the branch taken at the
-- previous round, and returns both players' root hashes there, keyed by player index.
local function wait_for_bisection(players, branch, level, target)
    return wait_for_all(
        players,
        "BisectionCommitment",
        "return player:commit_bisection(%q, %q, %d)",
        branch,
        level,
        target
    )
end

-- Sends a player the terminal round and waits for the disputed transition's log commitment,
-- carrying the branch taken at the last bisection round and the position the bisections
-- converged on, which the game's commit_log interprets.
local function wait_for_log(player, branch, ...)
    local code = "return player:commit_log(%q" .. string.rep(", %d", select("#", ...)) .. ")"
    return wait_for_one(player, "LogCommitment", code, branch, ...)
end

-- Waits for both players to connect, collects their commitments, and announces them. It binds the
-- listen address, accepts the two players in turn, numbering them by connection order, and asks both
-- for their final state hash at once so the run-to-halt commitments overlap. The hash needs no
-- checking here, since a wrong hash can win neither the dispute nor the output phase.
local function wait_for_commitments()
    local address = assert(arg[2], "missing listen address")
    local host, port = address:match("^(.-):(%d+)$")
    local listener = assert(socket.bind(host, tonumber(port)))
    -- The connection-to-index map lets receive_any link each ready connection back to its player.
    local players = { index_of = {} }
    for index = 1, 2 do
        local connection = assert(listener:accept())
        players[index] = { index = index, connection = connection, stale_requests_pending = 0 }
        players.index_of[connection] = index
    end
    phase("commitments")
    local commitments = wait_for_final_hash(players)
    for index, player in ipairs(players) do
        player.final_hash = commitments[index]
        eventf("Player %d posted final state hash %s.", index, short_hash(player.final_hash))
    end
    return players
end

-- Bisects one level over [0, hi], updating `state` in place. Each round it sends the running
-- branch and writes back the agreed lower-end hash, player 1's after-hash, the branch, and the
-- converged lower bound `lo`. Bounds are compared and halved as unsigned 64-bit (math.ult and
-- >>), so the mcycle level can use the full MCYCLE_MAX ceiling (-1 as a signed Lua integer),
-- and the small uarch bounds reduce to ordinary arithmetic. Each round is narrated into the
-- level's own phase file, so the rendered walkthrough can show just its ends.
-- docs:begin bisect_level
local function bisect_level(players, level, hi, bisection)
    phase("bisect_" .. level)
    local lo, round = 0, 0
    while math.ult(1, hi - lo) do
        local mid = lo + ((hi - lo) >> 1)
        local hash = wait_for_bisection(players, bisection.branch, level, mid)
        if hash[1] == hash[2] then
            lo, bisection.last_agreed_hash, bisection.branch = mid, hash[1], "agree"
        else
            hi, bisection.hash_after, bisection.branch = mid, hash[1], "disagree"
        end
        round = round + 1
        eventf("%s bisection round %d, interval of disagreement is [0x%x, 0x%x]", level, round, lo, hi)
    end
    return lo
end
-- docs:end bisect_level

return {
    SCHEMA_DICT = SCHEMA_DICT,
    read_file = read_file,
    write_file = write_file,
    short_hash = short_hash,
    phase = phase,
    eventf = eventf,
    take_branch = take_branch,
    new_player = new_player,
    wait_for_one = wait_for_one,
    wait_for_all = wait_for_all,
    wait_for_any = wait_for_any,
    wait_for_log = wait_for_log,
    wait_for_commitments = wait_for_commitments,
    bisect_level = bisect_level,
}
