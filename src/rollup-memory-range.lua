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

local util = require("cartesi.util")
local json = require("dkjson")

local function stderr(fmt, ...) io.stderr:write(string.format(fmt, ...)) end

-- Print help and exit
local function help()
    stderr(
        [=[
Usage:

  %s [action] [what]

[action] can be "encode" or "decode". When encoding, the utility reads
from stdin a JSON object and writes binary data to stdout. Conversely,
when decoding, the utility reads binary data from stdin and writes a
JSON object to stdout.

[what] can be:

    input-metadata
      the JSON representation is
        {
          "msg_sender": <msg-sender>,
          "epoch_index": <number>,
          "input_index": <number>,
          "block_number": <number>,
          "time_stamp": <number>
        }
      where field "msg_sender" contains a 20-byte EVM address in hex
      (e.g., "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").

    input
      the JSON representation is
        {"payload": <string> }

    query
      the JSON representation is
        {"payload": <string> }

    voucher
      the JSON representation is
          {"destination": <address>, "payload": <string>}
      where field "destination" contains a 20-byte EVM address in hex
      (e.g., "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").

    notice
      the JSON representation is
        {"payload": <string> }

    report
      the JSON representation is
        {"payload": <string> }

    exception
      the JSON representation is
        {"payload": <string> }

    voucher-hashes
      the JSON representation is
        [ <hash>, <hash>, ... <hash ]
      (only works for decoding)

    notice-hashes
      the JSON representation is
        [ <hash>, <hash>, ... <hash ]
      (only works for decoding)

]=],
        arg[0]
    )
    os.exit()
end

local function unhex(hex)
    local invalid
    local data = string.gsub(hex, "(%x%x)", function(c)
        local n = tonumber(c, 16)
        if not n then
            invalid = c
            n = 0
        end
        return string.char(n)
    end)
    if invalid then
        return nil, string.format("'%q' not valid hex", invalid)
    else
        return data
    end
end

local function hex(hash)
    if type(hash) ~= "string" then return nil, "expected string, got " .. type(hash) end
    return (string.gsub(hash, ".", function(c) return string.format("%02x", string.byte(c)) end))
end

local function hexhash(hash) return "0x" .. hex(hash) end

if not arg[1] then
    stderr("expected action\n")
    help()
end

if arg[1] == "-h" or arg[1] == "--help" then help() end

if arg[1] ~= "encode" and arg[1] ~= "decode" then
    stderr("unexpected action '%s'\n", arg[1])
    help()
end

local action = arg[1]

local what_table = {
    ["exception"] = true,
    ["input-metadata"] = true,
    ["input"] = true,
    ["query"] = true,
    ["voucher"] = true,
    ["voucher-hashes"] = true,
    ["notice"] = true,
    ["notice-hashes"] = true,
    ["report"] = true,
}

if not arg[2] then
    stderr("%s what?\n", arg[1])
    help()
end

if not what_table[arg[2]] then
    stderr("unexpected what '%s'\n", arg[2])
    help()
end

local what = arg[2]

if arg[3] then error("unexpected option " .. arg[3]) end

local function write_be256(value)
    io.stdout:write(string.rep("\0", 32 - 8))
    io.stdout:write(string.pack(">I8", value))
end

local function errorf(...) error(string.format(...)) end

local function read_json()
    local j, _, e = json.decode(io.read("*a"))
    if not j then error(e) end
    return j
end

local function unhexhash(addr, name)
    if not addr then errorf("missing %s", name) end
    if string.sub(addr, 1, 2) ~= "0x" then errorf("invalid %s %s (missing 0x prefix)", name, addr) end
    if #addr ~= 42 then errorf("%s must contain 40 hex digits (%s has %g digits)", name, addr, #addr - 2) end
    local bin, err = unhex(string.sub(addr, 3))
    if not bin then errorf("invalid %s %s (%s)", name, addr, err) end
    return bin
end

local function check_number(number, name)
    if not number then errorf("missing %s", name) end
    number = util.parse_number(number)
    if not number then errorf("invalid %s %s", name, tostring(number)) end
    return number
end

local function encode_input_metadata()
    local j = read_json()
    j.msg_sender = unhexhash(j.msg_sender, "msg_sender")
    j.block_number = check_number(j.block_number, "block_number")
    j.time_stamp = check_number(j.time_stamp, "time_stamp")
    j.epoch_index = check_number(j.epoch_index, "epoch_index")
    j.input_index = check_number(j.input_index, "input_index")
    io.stdout:write(string.rep("\0", 12))
    io.stdout:write(j.msg_sender)
    write_be256(j.block_number)
    write_be256(j.time_stamp)
    write_be256(j.epoch_index)
    write_be256(j.input_index)
end

local function encode_voucher()
    local j = read_json()
    local payload = assert(j.payload, "missing payload")
    local destination = unhexhash(j.destination, "destination")
    io.stdout:write(string.rep("\0", 12))
    io.stdout:write(destination)
    write_be256(64)
    write_be256(#payload)
    io.stdout:write(payload)
end

local function read_address() return string.sub(assert(io.stdin:read(32)), 13) end

local function read_hash()
    local s = io.stdin:read(32)
    if s and #s == 32 then return s end
end

local function read_be256() return string.unpack(">I8", string.sub(io.stdin:read(32), 25)) end

local function decode_input_metadata()
    local msg_sender = read_address()
    local block_number = read_be256()
    local time_stamp = read_be256()
    local epoch_index = read_be256()
    local input_index = read_be256()
    io.stdout:write(
        json.encode({
            msg_sender = hexhash(msg_sender),
            block_number = block_number,
            time_stamp = time_stamp,
            epoch_index = epoch_index,
            input_index = input_index,
        }, {
            indent = true,
            keyorder = {
                "msg_sender",
                "block_number",
                "time_stamp",
                "epoch_index",
                "input_index",
            },
        }),
        "\n"
    )
end

local function decode_string()
    assert(read_be256() == 32) -- skip offset
    local length = read_be256()
    local payload = length == 0 and "" or assert(io.stdin:read(length))
    io.stdout:write(json.encode({ payload = payload }, { indent = true }), "\n")
end

local function encode_string()
    local j = read_json()
    assert(j.payload, "missing payload")
    write_be256(32)
    write_be256(#j.payload)
    io.stdout:write(j.payload)
end

local function decode_voucher()
    local destination = hexhash(read_address())
    local offset = read_be256()
    assert(offset == 64, "expected offset 64, got " .. offset) -- skip offset
    local length = read_be256()
    local payload = length == 0 and "" or assert(io.stdin:read(length))
    io.stdout:write(
        json.encode({
            destination = destination,
            payload = payload,
        }, {
            indent = true,
            keyorder = {
                "destination",
                "payload",
            },
        }),
        "\n"
    )
end

local function decode_hashes()
    local t = {}
    while 1 do
        local hash = read_hash()
        if not hash then break end
        t[#t + 1] = hexhash(hash)
    end
    io.stdout:write(json.encode(t, { indent = true }), "\n")
end

local action_what_table = {
    encode_input_metadata = encode_input_metadata,
    encode_input = encode_string,
    encode_query = encode_string,
    encode_voucher = encode_voucher,
    encode_notice = encode_string,
    encode_exception = encode_string,
    encode_report = encode_string,
    decode_input_metadata = decode_input_metadata,
    decode_input = decode_string,
    decode_query = decode_string,
    decode_voucher = decode_voucher,
    decode_notice = decode_string,
    decode_exception = decode_string,
    decode_report = decode_string,
    decode_voucher_hashes = decode_hashes,
    decode_notice_hashes = decode_hashes,
}

local action_what_todo = action .. "_" .. string.gsub(what, "%-", "_")

local action_what = action_what_table[action_what_todo]

if not action_what then
    stderr("unexpected action what %s %s\n", action, what)
    help()
end

action_what(arg)
