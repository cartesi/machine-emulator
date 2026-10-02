-- VG event schemas, transport bindings, and narration.
local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local transport = require("game-transport")

-- Enumerate player addresses in admission order.
local function addresses(players)
    local result = {}
    for address in pairs(players) do
        result[#result + 1] = address
    end
    table.sort(result, function(a, b)
        return a.order < b.order
    end)
    return result
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
local narration_phase
local function phase(filename)
    if narration_phase == filename then
        return
    end
    if narration ~= io.stdout then
        narration:close()
    end
    narration = assert(io.open(filename, "w"))
    narration_phase = filename
    narration:setvbuf("line")
end

local function eventf(fmt, ...)
    local line = string.format(fmt, ...)
    narration:write(line, "\n")
    if narration ~= io.stdout then
        io.stdout:write(line, "\n")
    end
end

-- The referee reports semantic events. The story owns their formatting and
-- phase files, keeping presentation out of the game algorithm.
local story = {}

function story.report_claims(players)
    phase("claims")
    for _, sender in ipairs(addresses(players)) do
        local player = players[sender]
        eventf("Player %s claimed %s.", player.label, short_hash(player.final_state_hash))
    end
end

function story.report_bisection(agreed_position, tentative_position)
    if agreed_position.epoch_input_offset ~= tentative_position.epoch_input_offset then
        phase("bisect_input")
    elseif agreed_position.input_mcycle_offset ~= tentative_position.input_mcycle_offset then
        phase("bisect_mcycle")
    else
        phase("bisect_uarch_cycle")
    end
end

function story.report_bisection_progress(interval)
    local position = interval.agreed_position
    local extent = interval.extent
    eventf(
        "Disagreement starts at (0x%x, 0x%x, 0x%x); counts are (0x%x, 0x%x, 0x%x).",
        position.epoch_input_offset,
        position.input_mcycle_offset,
        position.uarch_cycle,
        1 << extent.log2_input_count,
        1 << extent.log2_mcycle_count,
        1 << extent.log2_uarch_cycle_count
    )
end

function story.report_state_transition(player)
    eventf("Player %s's transition proof is valid.", player.label)
end

function story.report_winner(winner)
    phase("verdict")
    if not winner then
        eventf("No players remain.")
        return
    end
    eventf("Player %s wins. Final state hash: %s", winner.label, cartesi.tohex(winner.final_state_hash))
end

function story.report_output(output)
    local ok, decoded = pcall(evmu.decode_calldata, "Notice(bytes payload)", output.output_data, "raw")
    if ok then
        eventf("Result proved against the final state:\n%s", decoded.payload)
    end
end

local schemas = {
    Empty = { items = {} },
    InputAdded = { items = { "Default", "Default" } },
    EpochSealed = { items = { "Default" } },
    Bisection = { items = { "Default", "Default" } },
    Log = { send_cmio_log = "AccessLog", step_log = "AccessLog", reset_uarch_log = "AccessLog" },
    Transition = { items = { "Default", "Default", "Default" } },
    Hash = { items = { "Base64" } },
    OutputsRoot = {
        iflags_y_data = "Base64",
        iflags_y_proof = "Proof",
        htif_tohost_data = "Base64",
        htif_tohost_proof = "Proof",
        tx_buffer_data = "Base64",
        tx_buffer_proof = "Proof",
    },
    Output = { output_index = "Default", output_data = "Base64", output_proof = "Proof" },
}
local define_event = transport.define_event
local events = {
    input_added = define_event("input_added", "InputAdded"),
    epoch_sealed = define_event("epoch_sealed", "EpochSealed"),
    commit_claim = define_event("commit_claim", "Empty", "Base64"),
    dispute_started = define_event("dispute_started", "Empty"),
    reveal_bisection = define_event("reveal_bisection", "Bisection", "Base64"),
    prove_state_transition = define_event("prove_state_transition", "Transition", "Log"),
    prove_outputs_merkle_root = define_event("prove_outputs_merkle_root", "Hash", "OutputsRoot"),
    prove_output = define_event("prove_output", "Hash", "Output"),
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
    narration_phase = nil
end
return {
    protocol = protocol,
    EVENTS = events,
    new_server = new_server,
    answer_event = answer_event,
    run_client = run_client,
    run_server = run_server,
    new_phase_closer = transport.new_phase_closer,
    schedule_response = transport.schedule_response,
    addresses = addresses,
    story = story,
    close_narration = close_narration,
}
