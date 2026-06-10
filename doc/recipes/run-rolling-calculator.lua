-- Load the JSON-RPC submodule and the EVM ABI helpers
local cartesi = require("cartesi")
local cartesi_jsonrpc = require("cartesi.jsonrpc")
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
        msg_sender = ZERO_ADDRESS,
        block_number = bint.new(0),
        block_timestamp = bint.new(os.time()),
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

-- Connect to remote Cartesi Machine server (and shut it down on exit)
local remote_address = assert(arg[1], "missing remote address")
stderr("Connecting to remote cartesi machine at '%s'\n", remote_address)
local cartesi_jsonrpc_machine <close> =
    assert(cartesi_jsonrpc.connect_server(remote_address)):set_cleanup_call(cartesi_jsonrpc.SHUTDOWN)

-- Print server version (and test connection)
local v = assert(cartesi_jsonrpc_machine:get_server_version())
stderr("Connected: remote version is %d.%d.%d\n", v.major, v.minor, v.patch)

-- Load remote machine from the rolling-calculator template
local machine = cartesi_jsonrpc_machine("rolling-calculator-template")

-- Snapshot via fork: the backup server keeps the pre-input state
local backup
local function snapshot()
    backup = machine:fork_server()
end
local function commit()
    if backup then
        backup:shutdown_server()
    end
    backup = nil
end
local function rollback()
    assert(backup, "no snapshot to rollback to")
    local address = machine:get_server_address()
    machine:shutdown_server()
    machine:swap(backup)
    machine:rebind_server(address)
    backup = nil
end

-- Run the machine until it halts or stdin closes
local i = 0
repeat
    local break_reason = machine:run(math.maxinteger)
    if break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY then
        local _, yield_reason = machine:receive_cmio_request()
        if yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            commit()
            stderr("type expression\n")
            local expr = io.read()
            if not expr then
                break
            end
            stderr("%s\n", expr) -- echo the input so non-tty transcripts make sense
            i = i + 1
            snapshot()
            machine:send_cmio_response(
                machine:get_root_hash(),
                cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
                encode_advance(expr, i)
            )
        elseif i > 0 and yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
            stderr("input rejected\n")
            rollback()
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
commit()
