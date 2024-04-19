-- No need to load the Cartesi module
local cartesi = {}
cartesi.grpc = require"cartesi.grpc"

-- Writes formatted text to stderr
local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

-- Create connection to remote Cartesi Machine server
local remote_address = assert(arg[1], "missing remote address")
local checkin_address = assert(arg[2], "missing checkin address")
stderr("Listening for checkin at '%s'\n", checkin_address)
stderr("Connecting to remote cartesi machine at '%s'\n", remote_address)
local remote = cartesi.grpc.stub(remote_address, checkin_address)

-- Print server version (and test connection)
local v = assert(remote.get_version())
stderr("Connected: remote version is %d.%d.%d\n", v.major, v.minor, v.patch)

-- Instantiate machine from template
local machine = remote.machine("rolling-calculator-template")

-- Get initial config from template
local config = machine:get_initial_config()

-- Print a string splitting it into multiple lines
local function fold(str, w)
    local i = 1
    while i <= #str do
        print(str:sub(i, i+w-1))
        i = i + w
    end
end

-- Encode an unsigned integer into 256-bit big-endian
local function encode_be256(value)
    return string.rep("\0", 32-8)..string.pack(">I8", value)
end

-- Write the input metadata memory range
local function write_input_metadata(machine, input_metadata, i)
    machine:write_memory(input_metadata.start,
        encode_be256(0) .. -- msg_sender
        encode_be256(0) .. -- block_number
        encode_be256(os.time()) .. -- time_stamp
        encode_be256(0) .. -- epoch_index
        encode_be256(i) -- input_index"
    )
end

-- Write the input into the rx_buffer memory range
local function write_input(machine, rx_buffer, input)
    machine:write_memory(rx_buffer.start,
        encode_be256(32) .. -- offset
        encode_be256(#input) .. -- length
        input -- input itself
    )
end

-- Read a notice from the tx_buffer memory range
local function read_notice(machine, tx_buffer, str)
    -- Get length of output, skipping offset
    local length = string.unpack(">I8",
        machine:read_memory(tx_buffer.start+32+24, 8))
    -- Get output itself, skipping offset and length
    return machine:read_memory(tx_buffer.start+64, length)
end

-- Obtain the relevant rollup memory ranges from the initial config
assert(config.rollup, "rollup not enabled in machine")
local rx_buffer = config.rollup.rx_buffer
local tx_buffer = config.rollup.tx_buffer
local input_metadata = config.rollup.input_metadata

-- Run machine until it halts
local i = 0
while not machine:read_iflags_H() do
    machine:run(math.maxinteger)
    local reason = machine:read_htif_tohost_data() >> 32
    -- Machine yielded manual
    if machine:read_iflags_Y() then
        -- Send new request if previous was accepted
        if reason == remote.machine.HTIF_YIELD_REASON_RX_ACCEPTED then
			-- Otherwise, obtain expression from stdin
			stderr("type expression\n") -- prompt for expression
			local expr = io.read()
			if not expr then
				break
			end
            machine:snapshot()
            i = i + 1
			-- Write expression as the input
			write_input(machine, rx_buffer, expr)
			-- Write the input metadata
			write_input_metadata(machine, input_metadata, i)
			-- Tell machine this is an advance-state request
			machine:write_htif_fromhost_data(0)
			-- Reset the Y flag so machine can proceed
			machine:reset_iflags_Y()
        -- Otherwise, rollback to state before processing was attempted
        elseif i > 0 then
            stderr("input rejected\n")
			machine:rollback()
        else
            stderr("machine initialization failed\n")
            break
        end
    -- Machine yielded automatic
    elseif machine:read_iflags_X() then
        -- It output a notice
        if reason == remote.machine.HTIF_YIELD_REASON_TX_NOTICE then
            -- Read notice and print it
            stderr("result is\n")
            fold(read_notice(machine, tx_buffer), 68)
        end
    end
end

-- Shut down remote server
stderr("Shutting down remote cartesi machine\n")
remote.shutdown()
