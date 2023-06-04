#!/usr/bin/env lua5.3

-- Copyright 2023 Cartesi Pte. Ltd.
--
-- This file is part of the machine-emulator. The machine-emulator is free
-- software: you can redistribute it and/or modify it under the terms of the GNU
-- Lesser General Public License as published by the Free Software Foundation,
-- either version 3 of the License, or (at your option) any later version.
--
-- The machine-emulator is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
-- FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
-- for more details.
--
-- You should have received a copy of the GNU Lesser General Public License
-- along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
--
--
-- Note: for grpc machine test to work, remote-cartesi-machine must run on
-- same computer and remote-cartesi-machine execution path must be provided
-- Note: for jsongrpc machine test to work, jsonrpc-remote-cartesi-machine must run on
-- same computer and jsonrpc-remote-cartesi-machine execution path must be provided

local jsonrpc = require("cartesi.jsonrpc")

local remote_address = nil

-- Print help and exit
local function help()
    io.stderr:write(string.format([=[
Usage:

  %s --remote-address=<host>:<port>

where remote-address gives the address of a running
jsonrpc remote Cartesi machine server.

]=], arg[0]))
    os.exit()
end

local options = {
    { "^%-%-h$", function(all)
        if not all then return false end
        help()
    end },
    { "^%-%-help$", function(all)
        if not all then return false end
        help()
    end },
    { "^%-%-remote%-address%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        remote_address = o
        return true
    end },
    { ".*", function(all)
        error("unrecognized option " .. all)
    end }
}

-- Process command line options
for i, argument in ipairs({...}) do
    if argument:sub(1,1) == "-" then
        for j, option in ipairs(options) do
            if option[2](argument:match(option[1])) then
                break
            end
        end
    else
        error("unrecognized argument " .. argument)
    end
end

-- This is a simple test that creates a tree of forked servers
-- Each new child of a given server modifies an additional register

-- The root will have x1--x31 set to zero initially
-- It will then modify x1 to 1 and fork
-- Then x2 to 1 and fork
-- Then x3 to 1 and fork
-- So the ith child will have registers x1-xi set to 1
-- Each child will then do the same, but child i will

local FANOUT = 3
local MAXDEPTH = 3

local function new_x()
    local t = {}
    for i = 1, 31 do
        t[i] = 0
    end
    return t
end

local function clone_x(x)
    local y = {}
    for i = 1, 31 do
        y[i] = x[i]
    end
    return y
end

local function tmprom()
    local name = os.tmpname()
    local f = io.open(name, "wb")
    f:write(string.rep("\0", 4096))
    f:close()
    return name
end

local function fork_tree(address, x, depth)
    local stub = assert(jsonrpc.stub(address))
    local node = {
        address = address,
        stub = stub,
        x = x
    }
    local machine
    if depth == 0 then
        local config = stub.machine.get_default_config()
        config.rom.image_filename = tmprom()
        config.ram.length = 1 << 22
        machine = stub.machine(config)
        os.remove(config.rom.image_filename)
    else
        machine = stub.get_machine()
    end
    local children = {}
    node.children = children
    if depth <= MAXDEPTH then
        for child_index = 1, FANOUT do
            machine:write_x(child_index, depth)
            x[child_index] = depth
            local child = fork_tree(stub.fork(), clone_x(x), depth + 1)
            children[#children+1] = child
        end
    end
    return node
end

local function pre_order(node, f, depth)
    depth = depth or 0
    f(node, depth)
    for i, child in ipairs(node.children) do
        pre_order(child, f, depth+1)
    end
end

local function check_tree(root)
    pre_order(root, function(node, depth)
        local machine = node.stub.get_machine()
        local x = node.x
        io.write(string.rep("  ", depth), "{", table.concat(node.x, ","), "}\n")
        for i = 1, 31 do
            if machine:read_x(i) ~= x[i] then
                error("mismatch in x[" .. i .. "]")
            end
        end
    end)
end

local function kill_tree(root)
    pre_order(root, function(node)
        node.stub.shutdown()
    end)
end

local tree = fork_tree(remote_address, new_x(), 0)
check_tree(tree)
kill_tree(tree)
