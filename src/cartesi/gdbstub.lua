-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later
--
-- This program is free software: you can redistribute it and/or modify it under
-- the terms of the GNU Lesser General Public License as published by the Free
-- Software Foundation, either version 3 of the License, or (at your option) any
-- later version.
--
-- This program is distributed in the hope that it will be useful, but WITHOUT ANY
-- WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
-- PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
--
-- You should have received a copy of the GNU Lesser General Public License along
-- with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
--

local GDBSTUB_DEBUG_PROTOCOL = false

local signals = {
    SIGINT = 2, -- signal sent to GDB when reaching a fixed number of cycle steps
    SIGQUIT = 3, -- signal sent to GDB when max cycle is reached
    SIGTRAP = 5, -- signal sent to GDB when a breakpoint is reached
    SIGTERM = 15, -- signal sent to GDB when the machine halts
}

local GDBStub = {}
GDBStub.__index = GDBStub

-- Returns x with the order of the bytes reversed.
-- Used to convert 64 bit integers between little-endian and big-endian.
local function bswap64(x) return ("<I8"):unpack((">I8"):pack(x)) end

local function reg2hex(x) return ("%016x"):format(bswap64(x)) end

local function byte2hex(x) return ("%02x"):format(x) end

local function chr2hex(c) return ("%02x"):format(c:byte()) end

local function str2hex(s) return s:gsub(".", chr2hex) end

local function hex2int(x) return tonumber(x, 16) end

local function hex2reg(x) return bswap64(hex2int(x)) end

local function hex2chr(x) return string.char(tonumber(x, 16)) end

local function hex2str(s) return s:gsub("%x%x", hex2chr) end

local function xorchr(c) return string.char(c:byte() ~ 0x20) end

local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...), "\n")
    io.stderr:flush()
end

-- Creates a new GDBStub.
function GDBStub.new(machine)
    return setmetatable({
        machine = machine,
        breakpoints = {},
    }, GDBStub)
end

-- Listens at address:port and waits GDB to connect.
function GDBStub:listen_and_wait_gdb(address, port)
    address = address or "127.0.0.1"
    port = port or 1234
    -- listens and wair for GDB connection
    local socket = require("socket")
    local server = assert(socket.bind(address, port))
    stderr("Waiting GDB to connect at %s:%d...", address, port)
    local conn = assert(server:accept())
    -- GDB connected, we can close the server
    assert(server:close())
    -- the first received byte should be '+'
    local c = assert(conn:receive(1))
    assert(c == "+", "expected acknowledge character on connection start")
    stderr("GDB connected!")
    -- enable TCP nodelay, necessary to have fast interactive session
    assert(conn:setoption("tcp-nodelay", true))
    self.conn = conn
end

-- Receive a packet from GDB.
function GDBStub:_recv()
    -- receive packet data
    local escaped_data, sum = {}, 0
    while true do
        local c = assert(self.conn:receive(1))
        if c == "#" then break end
        sum = sum + c:byte()
        escaped_data[#escaped_data + 1] = c
    end
    escaped_data = table.concat(escaped_data)
    -- validate checksum
    local checksum = assert(self.conn:receive(2))
    if sum % 256 ~= hex2int(checksum) then
        assert(self.conn:send("-")) -- request retransmission
        stderr("Received a packet with invalid checksum from GDB")
        return nil
    end
    -- send packet acknowledge
    if not self.noack then
        assert(self.conn:send("+")) -- send acknowledge packet
    end
    -- escape packet data
    local data = escaped_data:gsub("}(.)", xorchr)
    if GDBSTUB_DEBUG_PROTOCOL then stderr("Packet recv: %s", data) end
    return data
end

-- Send a packet to GDB.
function GDBStub:_send(data)
    -- escape packet data
    local escape_set = { ["#"] = true, ["$"] = true, ["}"] = true, ["*"] = true }
    local escaped_data = data:gsub(".", function(c) return escape_set[c] and "}" .. xorchr(c) or c end)
    -- compute checksum
    local sum = 0
    for c in escaped_data:gmatch(".") do
        sum = sum + c:byte()
    end
    local checksum = byte2hex(sum % 256)
    -- send packet
    local packet_data = "$" .. escaped_data .. "#" .. checksum
    assert(self.conn:send(packet_data))
    if GDBSTUB_DEBUG_PROTOCOL then stderr("Packet sent: %s", data) end
    -- wait for packet acknowledge
    if not self.noack then
        local c = assert(self.conn:receive(1))
        assert(c == "+", "GDB did not acknowledged last packet")
    end
    return true
end

-- Sent to GDB when a packet is handled with success.
function GDBStub:_send_ok() return self:_send("OK") end

-- Sent to GDB when a packet is not handled, due some error.
function GDBStub:_send_error() return self:_send("E01") end

-- Sent to GDB when a packet is not supported.
function GDBStub:_send_unsupported() return self:_send("") end

-- Sent to GDB when stopping the machine, using `signal` as the reason for stopping.
function GDBStub:_send_signal(signal) return self:_send("S" .. byte2hex(signal)) end

-- Sent to GDB when replying custom command packets.
function GDBStub:_send_rcmd_reply(res) return self:_send("O" .. str2hex(tostring(res))) end

-- GDB is asking for a reason why the target halted.
function GDBStub:_handle_target_halt() return self:_send_signal(signals.SIGTRAP) end

-- GDB is asking to execute "v" commands.
function GDBStub:_handle_v_command(_, command)
    if command == "vMustReplyEmpty" then -- GDB is testing if our protocol responds with unknown packets
        return self:_send("") -- Must reply with an empty packet
    elseif command == "vCont?" then -- GDB is checking if we support vCont actions.
        return self:_send_unsupported()
    elseif command:find("^vKill") then -- GDB is killing the machine
        return self:_handle_kill()
    end
end

-- GDB is querying machine or protocol information.
function GDBStub:_handle_query(_, query)
    if query:find("^qSupported:") then -- GDB is checking for supported features.
        local supported_features = {
            ["hwbreak"] = true, -- we only support hardware breakpoints
        }
        local res = {
            "QStartNoAckMode+", -- we want to disable acknowledge packets, since its redundant with TCP
        }
        for feature in query:gmatch("([A-Za-z-]+)%+;?") do
            if supported_features[feature] then table.insert(res, feature .. "+") end
        end
        -- reply with features we support
        res = table.concat(res, ";")
        return self:_send(res)
    elseif query == "qTStatus" then -- GDB is asking whether a trace experiment is currently running
        return self:_send_unsupported()
    elseif query == "qfThreadInfo" or query == "qC" or query:find("^qL") then -- GDB is asking thread info
        return self:_send_unsupported()
    elseif query == "qAttached" then -- GDB is asking if we are attached to an existing process
        return self:_send("1") -- reply with '1', indicating that our remote server is attached
    elseif query == "qSymbol::" then -- GDB is prepared to serve symbol lookup requests
        return self:_send_ok()
    elseif query == "qOffsets" then -- GDB is requesting section offsets that the target used when relocating the image
        -- let GDB decide the text offset based in the binary file being debugged
        return self:_send_unsupported()
    elseif query:find("^qRcmd,") then -- custom command
        local payload = hex2str(query:sub(7))
        if payload:find("^stepc %d+$") then -- step a fixed number of cycles
            self.mcycle_limit = self.machine:read_mcycle() + tonumber(payload:match("^stepc (%d+)$"))
            return self:_send_ok()
        elseif payload:find("^stepu %d+$") then -- step until a cycle number
            self.mcycle_limit = math.max(self.machine:read_mcycle(), tonumber(payload:match("^stepu (%d+)$")))
            return self:_send_ok()
        elseif payload == "stepc_clear" then -- remove stepping breakpoint
            self.mcycle_limit = nil
            return self:_send_ok()
        elseif payload == "cycles" then -- print current cycle
            self:_send_rcmd_reply(string.format("%u\n", self.machine:read_mcycle()))
            return self:_send_ok()
        elseif payload:find("^csr [%w_]+$") then -- read machine CSRs
            local csr_name = payload:match("^csr ([%w_]+)$")
            local read_method_name = "read_" .. csr_name
            local read_method = self.machine[read_method_name]
            if not read_method then return self:_send_unsupported() end
            local ok, res = pcall(read_method, self.machine)
            if not ok or res == nil then return self:_send_unsupported() end
            if math.type(res) == "integer" then
                self:_send_rcmd_reply(string.format("0x%x (%d)\n", res, res))
            else
                self:_send_rcmd_reply(tostring(res) .. "\n")
            end
            return self:_send_ok()
        elseif payload:find("^csr [%w_]+%=.*$") then -- write machine CSRs
            local csr_name, val = payload:match("^csr ([%w_]+)%=(.*)$")
            local write_method_name = "write_" .. csr_name
            local read_method_name = "read_" .. csr_name
            local write_method = self.machine[write_method_name]
            local read_method = self.machine[read_method_name]
            if not write_method or not read_method then return self:_send_unsupported() end
            val = tonumber(val)
            if not val or math.type(val) ~= "integer" then
                self:_send_rcmd_reply("ERROR: malformed CSR integer\n")
                return self:_send_ok()
            end
            local write_ok = pcall(write_method, self.machine, val)
            if not write_ok then return self:_send_unsupported() end
            -- print the new CSR value
            local ok, res = pcall(read_method, self.machine)
            if ok and res ~= nil then
                if math.type(res) == "integer" then
                    self:_send_rcmd_reply(string.format("%s = 0x%x (%d)\n", csr_name, res, res))
                else
                    self:_send_rcmd_reply(tostring(res) .. "\n")
                end
            end
            return self:_send_ok()
        elseif payload == "hash" then -- print machine state hash
            if not self.performed_first_hash then
                self:_send_rcmd_reply("GDB may complain about packet errors due to command timeout, ignore them.\n")
                self:_send_rcmd_reply("Performing first hash, this may take a while...\n")
                self.performed_first_hash = true
            end
            local hash = self.machine:get_root_hash()
            self:_send_rcmd_reply(string.format("%u: %s\n", self.machine:read_mcycle(), str2hex(hash)))
            return self:_send_ok()
        elseif payload:find("^store .*$") then -- store the machine state
            local store_dir = payload:match("^store (.*)$")
            self:_send_rcmd_reply("GDB may complain about packet errors due to command timeout, ignore them.\n")
            self:_send_rcmd_reply("Storing the machine, this may take a while...\n")
            local ok, res = pcall(self.machine.store, self.machine, store_dir)
            if not ok then
                self:_send_rcmd_reply(string.format("ERROR: machine store failed: %s\n", res))
            else
                self:_send_rcmd_reply(string.format('machine stated saved to "%s"\n', store_dir))
            end
            return self:_send_ok()
        elseif payload:find([[^lua ["'].*["']$]]) then -- execute arbitrary lua code
            local source = payload:match([[^lua ["'](.*)["']$]])
            local env = { machine = self.machine }
            setmetatable(env, { __index = _ENV })
            local func, err = load(source, "@gdb_command_chunk", "t", env)
            if not func then
                self:_send_rcmd_reply(string.format("ERROR: %s\n", err))
            else
                local ok, ret = pcall(func)
                if not ok then
                    self:_send_rcmd_reply(string.format("ERROR: %s\n", ret))
                elseif ret ~= nil then
                    self:_send_rcmd_reply(tostring(ret) .. "\n")
                end
            end
            return self:_send_ok()
        elseif payload:find("^breakpc [xXa-fA-F0-9]+$") then
            local pcstr = payload:match("^breakpc ([xXa-fA-F0-9]+)$")
            local pc = tonumber(pcstr)
            if pc then
                if self.breakpoints[pc] then
                    self.breakpoints[pc] = nil
                    self:_send_rcmd_reply(string.format("disabled PC breakpoint at 0x%x\n", pc))
                else
                    self:_send_rcmd_reply(string.format("enabled PC breakpoint at 0x%x\n", pc))
                    self.breakpoints[pc] = true
                end
            else
                self:_send_rcmd_reply(string.format("ERROR: malformed PC address '%s'\n", pcstr))
            end
            return self:_send_ok()
        else -- invalid command
            return self:_send_unsupported()
        end
    end
end

-- GDB is setting a query feature.
function GDBStub:_handle_query_set(_, query)
    if query == "QStartNoAckMode" then
        if self:_send_ok() then
            self.noack = true
            return true
        end
    end
end

-- GDB is setting the thread for the next resume commands.
function GDBStub:_handle_set_thread(payload)
    local c, thread_id = payload:match("^(.)(.*)$")
    assert(c and thread_id, "unexpected set thread payload " .. payload)
    -- a thread-id can also be a literal '-1' to indicate all threads, or '0' to pick any thread.
    if thread_id == "0" or thread_id == "-1" then
        -- indicates that all following c commands refer to the given thread id
        return self:_send_ok()
    else
        return self:_send_error()
    end
end

-- GDB is writing a machine register.
function GDBStub:_handle_write_reg(payload)
    local reg, val = payload:match("^(%x+)=(%x+)$")
    if not (reg and val) then return end
    reg, val = hex2int(reg), hex2reg(val)
    if reg > 0 and reg < 32 then -- machine registers
        self.machine:write_x(reg, val)
        return self:_send_ok()
    elseif reg == 32 then -- machine program counter
        self.machine:write_pc(val)
        return self:_send_ok()
    end
end

-- GDB is asking for all machine registers.
function GDBStub:_handle_read_all_regs()
    local res = {}
    -- read general purposes registers
    for i = 0, 31 do
        table.insert(res, reg2hex(self.machine:read_x(i)))
    end
    -- read program counter
    table.insert(res, reg2hex(self.machine:read_pc()))
    res = table.concat(res)
    return self:_send(res)
end

-- GDB is writing all machine registers.
function GDBStub:_handle_write_all_regs(payload)
    -- parse registers
    local n = 0
    local regs = {}
    for val in payload:gmatch("%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x") do
        regs[n] = hex2reg(val)
        n = n + 1
    end
    if n ~= 33 then
        stderr("GDB sent an unexpected number of registers (%d)", n)
        return
    end
    -- write general purposes registers
    for i = 1, 31 do
        self.machine:write_x(i, regs[i])
    end
    -- write program counter
    self.machine:write_pc(regs[32])
    return self:_send_ok()
end

-- GDB wants to read machine memory.
function GDBStub:_handle_read_mem(payload)
    local address, length = payload:match("^(%x+),(%x+)$")
    if not (address and length) then return end
    address, length = hex2int(address), hex2int(length)
    -- GDB may want to access invalid address ranges when debugging
    local ok, mem = pcall(function() return self.machine:read_virtual_memory(address, length) end)
    if not ok then return self:_send_error() end
    local hexmem = str2hex(mem)
    return self:_send(hexmem)
end

-- GDB wants to write machine memory.
function GDBStub:_handle_write_mem(payload)
    local address, length, hexmem = payload:match("^(%x+),(%x+):(%x+)$")
    if not (address and length) then return end
    address, length = hex2int(address), hex2int(length)
    local mem = hex2str(hexmem)
    assert(#mem == length)
    -- GDB may want to access invalid address ranges when debugging
    local ok = pcall(function() self.machine:write_virtual_memory(address, mem) end)
    if ok then return self:_send_error() end
    return self:_send_ok()
end

-- GDB is asking to let the machine continue.
function GDBStub:_handle_continue()
    local machine = self.machine
    local mcycle = machine:read_mcycle()
    local mcycle_end = self.max_mcycle
    local ult = math.ult -- localized to speed up Lua loop
    if self.mcycle_limit and ult(self.mcycle_limit, self.max_mcycle) then
        -- we want to advance just a fixed number of cycles
        mcycle_end = self.mcycle_limit
    end
    if next(self.breakpoints) then -- at least one breakpoint is set
        local breakpoints = self.breakpoints -- localized to speed up Lua loop
        -- need to run cycle by cycle, while checking breakpoints
        while ult(mcycle, mcycle_end) do
            machine:run(mcycle + 1)
            if breakpoints[machine:read_pc()] then -- breakpoint reached
                return self:_send_signal(signals.SIGTRAP)
            elseif machine:read_iflags_H() then -- machined halted
                return self:_send_signal(signals.SIGTERM)
            elseif machine:read_iflags_Y() or machine:read_iflags_X() then -- machine yielded
                self.yielded = true
                return true -- a reply will be sent to GDB in the next run loop
            end
            mcycle = machine:read_mcycle()
        end
    else -- no breakpoint set, we can run through the fast path
        machine:run(mcycle_end)
    end
    if machine:read_iflags_H() then -- machine halted
        return self:_send_signal(signals.SIGTERM)
    elseif machine:read_mcycle() == self.max_mcycle then -- reached max cycles
        return self:_send_signal(signals.SIGQUIT)
    elseif machine:read_iflags_Y() or machine:read_iflags_X() then -- machine yielded
        self.yielded = true
        return true -- a reply will be sent to GDB in the next run loop
    else -- reached step cycles limit
        return self:_send_signal(signals.SIGINT)
    end
end

-- GDB is requesting to continue past halting signal.
function GDBStub:_handle_continue_signal(payload)
    local signum = payload:match("^(%x+)$")
    if not signum then return end
    return self:_handle_continue()
end

local function parse_breakpoint_address(payload)
    local type, address, kind = payload:match("^(%d+),(%x+),(%x+)$")
    if address and type == "0" or (kind == "4" or kind == "2") then return hex2int(address) end
end

-- GDB is adding a breakpoint.
function GDBStub:_handle_insert_breakpoint(payload)
    local address = parse_breakpoint_address(payload)
    if not address then return end
    self.breakpoints[address] = true
    return self:_send_ok()
end

-- GDB is removing a breakpoint.
function GDBStub:_handle_remove_breakpoint(payload)
    local address = parse_breakpoint_address(payload)
    if not address then return end
    self.breakpoints[address] = nil
    return self:_send_ok()
end

-- GDB is requesting to kill the machine.
function GDBStub:_handle_kill()
    stderr("GDB killed!")
    self:_send_ok()
    self:close()
    os.exit(0) -- exit immediately
    return true
end

-- GDB is detaching (debug session ended).
function GDBStub:_handle_detach()
    self:_send_ok()
    self:close()
    return true
end

-- GDB is asking if extended debugging is supported.
function GDBStub:_handle_extended_debugging() return self:_send_ok() end

-- Packet handler for the GDB protocol.
local gdbstub_handlers = {
    ["!"] = GDBStub._handle_extended_debugging,
    ["k"] = GDBStub._handle_kill,
    ["?"] = GDBStub._handle_target_halt,
    ["c"] = GDBStub._handle_continue,
    ["C"] = GDBStub._handle_continue_signal,
    ["D"] = GDBStub._handle_detach,
    ["m"] = GDBStub._handle_read_mem,
    ["M"] = GDBStub._handle_write_mem,
    -- ['p'] = GDBStub._handle_read_reg,
    ["P"] = GDBStub._handle_write_reg,
    ["g"] = GDBStub._handle_read_all_regs,
    ["G"] = GDBStub._handle_write_all_regs,
    ["Z"] = GDBStub._handle_insert_breakpoint,
    ["z"] = GDBStub._handle_remove_breakpoint,
    ["v"] = GDBStub._handle_v_command,
    ["q"] = GDBStub._handle_query,
    ["Q"] = GDBStub._handle_query_set,
    ["H"] = GDBStub._handle_set_thread,
    -- explicitly unsupported, but GDB may send packets
    ["X"] = false, -- write data to memory, where the data is transmitted in binary
}

-- Handle every packet received from GDB.
function GDBStub:_handle_packet(data)
    local c, payload = data:sub(1, 1), data:sub(2)
    local handler = gdbstub_handlers[data] or gdbstub_handlers[c]
    if handler == false then -- explicitly unsupported
        self:_send_unsupported()
    elseif handler then -- packet handler found
        local ok = handler(self, payload, data)
        if not ok then -- the handler could not process the packet
            stderr("Received an unexpected packet from GDB: %s", data)
            self:_send_unsupported()
        end
    end
end

-- Runs the machine until GDB detaches.
-- The machine runs up to max_mcycle mcycles, or halts, or GDB detaches.
-- The machine may not necessary reaches max_mcycle (in case GDB detached early).
-- This function will return early if the machine yields (to let the caller deal with yields).
-- Returns false if GDB session ended (GDB detached),
-- otherwise true if GDB session is still going on (when yielding).
function GDBStub:run(max_mcycle)
    if not self.conn then return false end
    -- set max mcycle for continue operations
    self.max_mcycle = max_mcycle or math.maxinteger
    -- when resuming from a yield, we have a pending GDB continue packet to reply
    if self.yielded then
        self.yielded = nil
        self:_handle_continue() -- resume handling last continue packet
    end
    -- run while GDB is connected and the machine has not yielded
    while self.conn and not self.yielded do
        local c = assert(self.conn:receive(1))
        if c == "$" then -- incoming packet
            local data = self:_recv()
            if data then -- acknowledged packet
                self:_handle_packet(data)
            end
        elseif c == "-" then -- GDB requested packet requested retransmission
            -- GDB usually asks for retransmission for long running commands (or broken protocol)
            if GDBSTUB_DEBUG_PROTOCOL then stderr("GDB requested packet retransmission\n") end
        else
            error("Received unexpected protocol character from GDB: " .. c)
        end
    end
    return self.yielded
end

-- Returns true if GDB is connected.
function GDBStub:is_connected() return self.conn ~= nil end

-- Closes the GDB connection.
function GDBStub:close()
    if not self.conn then return end
    assert(self.conn:close())
    self.conn = nil
end

return GDBStub
