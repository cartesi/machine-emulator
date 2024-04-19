-- No need to load the Cartesi module
local cartesi = {}
-- Load the gRPC submodule for remote Cartesi Machines
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

-- Instantiate remote machine from configuration
local machine = remote.machine(require(arg[3]))

-- Run machine until it halts or yields
while not machine:read_iflags_H() and not machine:read_iflags_Y() do
    machine:run(math.maxinteger)
end

-- Print machine status
if machine:read_iflags_H() then
    stderr("\nHalted\n")
else
    stderr("\nYielded manual\n")
end
-- Print cycle count
stderr("Cycles: %u\n", machine:read_mcycle())

-- Shut down remote server
stderr("Shutting down remote cartesi machine\n")
remote.shutdown()
