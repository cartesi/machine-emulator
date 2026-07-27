-- Load the Cartesi machine module and the EVM ABI helpers
local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")

local EVM_ADVANCE = "EvmAdvance(uint256 chain_id, address app_contract, address msg_sender, "
    .. "uint256 block_number, uint256 block_timestamp, uint256 prev_randao, uint256 index, bytes payload)"
local NOTICE = "Notice(bytes payload)"
local ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

-- Writes formatted text to stderr
local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

-- Encode a raw expression as an EvmAdvance request payload (bc needs a
-- trailing newline to accept the line as a complete expression)
local function encode_advance(expr, index)
    local bint = evmu.bint
    return evmu.encode_calldata(EVM_ADVANCE, {
        chain_id = bint.new(0),
        app_contract = ZERO_ADDRESS,
        msg_sender = string.format("0x%040d", index),
        block_number = bint.new(0),
        block_timestamp = bint.new(0),
        prev_randao = bint.new(0),
        index = bint.new(index),
        payload = evmu.raw(expr .. "\n"),
    })
end

-- Print a string folded into lines of width w
local function fold(s, w)
    for i = 1, #s, w do
        print(s:sub(i, i + w - 1))
    end
end

-- Decode a response inside a notice
local function print_decoded_notice(data)
    fold(evmu.decode_calldata(NOTICE, data, "raw").payload, 68)
end

-- docs:begin storage
-- Load a fresh clone of the rolling-calculator template, operating directly on its backing stores
cartesi.machine:clone_stored("rolling-calculator-template", "machine")
local machine = cartesi.machine("machine", nil, cartesi.SHARING_ALL)

-- Snapshot via storage: backup_machine keeps a copy of the pre-input state.
local backup
local function snapshot(m)
    m:destroy()
    m:clone_stored("machine", "backup_machine")
    m:sync_stored("backup_machine")
    m:load("machine", nil, cartesi.SHARING_ALL)
    backup = true
end

local function commit(m)
    m:sync_stored("machine")
    if backup then
        m:remove_stored("backup_machine")
    end
    backup = nil
end

local function rollback(m)
    assert(backup, "no snapshot to rollback to")
    m:destroy()
    m:remove_stored("machine")
    m:rename_stored("backup_machine", "machine")
    m:load("machine", nil, cartesi.SHARING_ALL)
    backup = nil
end
-- docs:end storage

-- Run the machine until it halts or the expressions run out
local i = 0
local revert_root_hash
repeat
    local break_reason = machine:run(math.maxinteger)
    if break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY then
        local _, yield_reason = machine:receive_cmio_request()
        if yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            commit(machine)
            revert_root_hash = machine:get_root_hash()
            local input <close> = io.open(string.format("expression-%d.txt", i), "r")
            if not input then
                break
            end
            local expr = assert(input:read("l"), string.format("empty expression file: expression-%d.txt", i))
            stderr("feeding expression %d\n%s\n", i, expr)
            snapshot(machine)
            machine:send_cmio_response(
                cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
                encode_advance(expr, i),
                revert_root_hash
            )
            i = i + 1
        elseif i > 0 and yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
            stderr("input rejected\n")
            rollback(machine)
        else
            stderr("machine initialization failed\n")
            break
        end
    elseif break_reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
        local _, yield_reason, data = machine:receive_cmio_request()
        if yield_reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT then
            stderr("result is\n")
            print_decoded_notice(data)
        end
    end
until break_reason == cartesi.BREAK_REASON_HALTED
commit(machine)

-- Make the final on-disk state durable and print its hash
machine:sync_stored("machine")
stderr("final state hash: %s\n", cartesi.tohex(machine:get_root_hash()))
