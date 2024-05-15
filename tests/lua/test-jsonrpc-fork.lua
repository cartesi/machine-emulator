#!/usr/bin/env lua5.4

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

local jsonrpc = require("cartesi.jsonrpc")

local remote_address = nil

-- Print help and exit
local function help()
    io.stderr:write(string.format(
        [=[
Usage:

  %s --remote-address=<host>:<port>

where remote-address gives the address of a running
jsonrpc remote Cartesi machine server.

]=],
        arg[0]
    ))
    os.exit()
end

local options = {
    {
        "^%-%-h$",
        function(all)
            if not all then return false end
            help()
        end,
    },
    {
        "^%-%-help$",
        function(all)
            if not all then return false end
            help()
        end,
    },
    {
        "^%-%-remote%-address%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            remote_address = o
            return true
        end,
    },
    { ".*", function(all) error("unrecognized option " .. all) end },
}

-- Process command line options
for _, argument in ipairs({ ... }) do
    if argument:sub(1, 1) == "-" then
        for _, option in ipairs(options) do
            if option[2](argument:match(option[1])) then break end
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

local FANOUT = 2
local MAXDEPTH = 2

local function clone_x(x)
    local y = {}
    for i = 1, 31 do
        y[i] = x[i]
    end
    return y
end

local function fork_tree(address, x, depth)
    local stub = assert(jsonrpc.stub(address))
    local node = {
        address = address,
        stub = stub,
    }
    local machine
    if depth == 0 then
        local config = stub.machine.get_default_config()
        x = config.processor.x
        config.ram.length = 1 << 22
        machine = stub.machine(config)
    else
        machine = stub.get_machine()
    end
    node.x = x
    local children = {}
    node.children = children
    if depth <= MAXDEPTH then
        for child_index = 1, FANOUT do
            machine:write_x(child_index, depth)
            x[child_index] = depth
            local child = fork_tree(stub.fork(), clone_x(x), depth + 1)
            children[#children + 1] = child
        end
    end
    return node
end

local function pre_order(node, f, depth)
    depth = depth or 0
    f(node, depth)
    for _, child in ipairs(node.children) do
        pre_order(child, f, depth + 1)
    end
end

local function check_tree(root)
    pre_order(root, function(node, depth)
        local machine = node.stub.get_machine()
        local x = node.x
        io.write(string.rep("  ", depth), "{", table.concat(node.x, ","), "}\n")
        for i = 1, 31 do
            if machine:read_x(i) ~= x[i] then error("mismatch in x[" .. i .. "]") end
        end
    end)
end

local function kill_tree(root)
    pre_order(root, function(node) node.stub.shutdown() end)
end

local tree = fork_tree(remote_address, nil, 0)
check_tree(tree)
kill_tree(tree)
