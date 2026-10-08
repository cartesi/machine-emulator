-- VG event schemas, transport bindings, and narration.
local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local util = require("cartesi.util")
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

-- The referee selects story sections at semantic boundaries. Each section owns
-- its file, and every line is also echoed to stdout for a live run.
local story = {}
local narration = io.stdout
local narration_section
local narration_file
local narration_files = {}
local bisection_level

local function select_file(name)
    if narration_file == name then
        return
    end
    if narration ~= io.stdout then
        narration:close()
    end
    narration = assert(io.open(name .. ".txt", narration_files[name] and "a" or "w"))
    narration_file = name
    narration_files[name] = true
    narration:setvbuf("line")
end

function story.section(name)
    narration_section = name
    select_file(name)
end

function story.subsection(name)
    select_file(assert(narration_section) .. "_" .. name)
end

local function eventf(fmt, ...)
    local line = string.format(fmt, ...)
    narration:write(line, "\n")
    if narration ~= io.stdout then
        io.stdout:write(line, "\n")
    end
end

-- The referee reports semantic events. The story owns their formatting and
-- section files, keeping presentation out of the game algorithm.

function story.report_claims(players)
    for _, sender in ipairs(addresses(players)) do
        local player = players[sender]
        eventf("Player %s claimed %s.", player.label, short_hash(player.final_state_hash))
    end
end

function story.report_bisection(agreed_position, tentative_position)
    if agreed_position.epoch_input_offset ~= tentative_position.epoch_input_offset then
        bisection_level = "input"
        story.subsection("inputs")
    elseif agreed_position.input_mcycle_offset ~= tentative_position.input_mcycle_offset then
        bisection_level = "mcycle"
        story.subsection("mcycles")
    else
        bisection_level = "uarch"
        story.subsection("uarch_cycles")
    end
end

function story.report_bisection_progress(interval)
    local position = interval.agreed_position
    local extent = interval.extent
    if bisection_level == "input" then
        story.subsection("inputs")
        eventf(
            "Disagreement is within inputs [0x%x, 0x%x).",
            position.epoch_input_offset,
            position.epoch_input_offset + (1 << extent.log2_input_count)
        )
    elseif bisection_level == "mcycle" then
        story.subsection("mcycles")
        eventf(
            "Disagreement is within input 0x%x and mcycle [0x%x, 0x%x).",
            position.epoch_input_offset,
            position.input_mcycle_offset,
            position.input_mcycle_offset + (1 << extent.log2_mcycle_count)
        )
    else
        story.subsection("uarch_cycles")
        eventf(
            "Disagreement is within input 0x%x, mcycle 0x%x, and uarch cycles [0x%x, 0x%x).",
            position.epoch_input_offset,
            position.input_mcycle_offset,
            position.uarch_cycle,
            position.uarch_cycle + (1 << extent.log2_uarch_cycle_count)
        )
    end
end

function story.report_bisection_eliminations(players, survivors)
    for _, sender in ipairs(addresses(players)) do
        if not survivors[sender] then
            story.subsection("timeouts")
            eventf(
                "Player %s failed to provide a valid tentative hash in time and is eliminated.",
                players[sender].label
            )
        end
    end
end

function story.report_state_transition(player)
    story.subsection("proofs")
    eventf("Player %s's transition proof is valid.", player.label)
end

function story.report_transition_eliminations(players, survivors)
    story.subsection("proofs")
    for _, sender in ipairs(addresses(players)) do
        if not survivors[sender] then
            eventf("Player %s failed to prove its transition and is eliminated.", players[sender].label)
        end
    end
end

function story.report_winner(winner)
    if not winner then
        eventf("No players remain.")
        return
    end
    eventf("Player %s wins.", winner.label)
    eventf("Final state hash is %s.", cartesi.tohex(winner.final_state_hash))
end

-- Optional output-to-input labels are supplied by the calculator example for
-- presentation. Output proofs themselves authenticate no input association.
local ADVANCE = "EvmAdvance(uint256 chainId, address appContract, address msgSender, uint256 blockNumber, "
    .. "uint256 blockTimestamp, uint256 prevRandao, uint256 index, bytes payload)"

function story.report_output(output)
    local ok, decoded = pcall(evmu.decode_calldata, "Notice(bytes payload)", output.output_data, "raw")
    if ok then
        local path = story.output_inputs and story.output_inputs[output.output_index]
        if path then
            local input = evmu.decode_calldata(ADVANCE, util.read_file(path), "raw")
            eventf("Output %d of input %q is %q.", output.output_index, input.payload:gsub("%s+$", ""), decoded.payload)
        else
            eventf("Output %d is %q.", output.output_index, decoded.payload)
        end
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
    narration_section = nil
    narration_file = nil
    narration_files = {}
    bisection_level = nil
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
