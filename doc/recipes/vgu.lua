-- VG event schemas, transport bindings, and narration.
local cartesi = require("cartesi")
local transport = require("game-transport")
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

local schemas = {
    Empty = { items = {} },
    InitialState = { items = { "Base64" } },
    InputAdded = { items = { "Default", "Default" } },
    EpochSealed = { items = { "Default" } },
    Bisection = { items = { "Default" } },
    Log = { send_cmio_log = "AccessLog", step_log = "AccessLog", reset_uarch_log = "AccessLog" },
    OutputsRoot = {
        iflags_y_data = "Base64",
        iflags_y_proof = "Proof",
        htif_tohost_data = "Base64",
        htif_tohost_proof = "Proof",
        tx_buffer_data = "Base64",
        tx_buffer_proof = "Proof",
    },
    Output = { output_index = "Default", output = "Base64", output_proof = "Proof" },
}
local define_event = transport.define_event
local events = {
    initial_state = define_event("initial_state", "InitialState", "Default"),
    input_added = define_event("input_added", "InputAdded", "Default"),
    epoch_sealed = define_event("epoch_sealed", "EpochSealed", "Default"),
    commit_final_hash = define_event("commit_final_hash", "Empty", "Base64"),
    commit_bisection = define_event("commit_bisection", "Bisection", "Base64"),
    commit_log = define_event("commit_log", "Bisection", "Log"),
    prove_outputs_merkle_root = define_event("prove_outputs_merkle_root", "Empty", "OutputsRoot"),
    prove_output = define_event("prove_output", "Empty", "Output"),
}
local protocol = transport.new_protocol(events, schemas, "VERIFICATION_GAME_TRACE")
local function new_server(address)
    return transport.new_server(address, protocol)
end
local function answer_event(client, line)
    return transport.answer_event(client, line, protocol)
end
local function run_client(client, address)
    return transport.run_client(client, address, protocol)
end
local function run_server(referee, address)
    return transport.run_server(referee, address, protocol)
end
local function close_narration()
    if narration ~= io.stdout then
        narration:close()
    end
    narration = io.stdout
end
return {
    protocol = protocol,
    EVENTS = events,
    new_server = new_server,
    answer_event = answer_event,
    run_client = run_client,
    run_server = run_server,
    schedule_response = transport.schedule_response,
    phase = phase,
    eventf = eventf,
    short_hash = short_hash,
    close_narration = close_narration,
}
