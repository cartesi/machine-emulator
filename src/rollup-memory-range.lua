#!/usr/bin/env lua5.3

-- Copyright 2021 Cartesi Pte. Ltd.
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

local util = require"cartesi.util"

local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

-- Print help and exit
local function help()
    stderr([=[
Usage:

  %s [action] [what] [what-options]

and [action] [what] can be:

    encode input-metadata
      writes encoded input-metadata to stdout
      options:

        --msg-sender=<address>
        20-byte address in hex, starting with 0x

        --block-number=<number>
        --time-stamp=<number>
        --epoch-index=<number>
        --input-index=<number>

    encode input
      writes encoded input to stdout
      options:

        --payload-filename=<filename>
        read payload from <filename>

        --payload=<payload>
        read payload from command-line

        default is to read payload from stdin

    encode query
      writes encoded query to stdout
      options:

        --payload-filename=<filename>
        read payload from <filename>

        --payload=<payload>
        read payload from command-line

        default is to read payload from stdin

    encode voucher
      writes an encoded voucher to stdout
      options:

        --address=<address>
        20-byte address in hex, starting with 0x

        --payload-filename=<filename>
        read payload from <filename>

        --payload=<payload>
        read payload from command-line

        default is to read payload from stdin

    encode notice
      writes an encoded notice to stdout
      options:

        --payload-filename=<filename>
        read payload from <filename>

        --payload=<payload>
        read payload from command-line

        default is to read payload from stdin

    encode report
      writes an encoded report to stdout
      options:

        --payload-filename=<filename>
        read payload from <filename>

        --payload=<payload>
        read payload from command-line

        default is to read payload from stdin

    decode input-metadata
      writes decoded input-metadata to stdout

    decode input
      writes input payload to stdout

    decode query
      writes query payload to stdout

    decode voucher
        writes voucher address to stderr in hex
        writes voucher payload to stdout

    decode notice
        writes voucher payload to stdout

    decode report
        writes report payload to stdout

    decode voucher-hashes
        writes hashes to stdout in hex, one per line

    decode notice-hashes
        writes hashes to stdout in hex, one per line
]=], arg[0])
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
        return nil, format("'%q' not valid hex", c)
    else
        return data
    end
end

local function hex(hash)
    if type(hash) ~= "string" then
        return nil, "expected string, got " .. type(hash)
    end
    return (string.gsub(hash, ".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

if not arg[1] then
    stderr("expected action\n")
    help()
end

if arg[1] ~= "encode" and arg[1] ~= "decode" then
    stderr("unexpected action '%s'\n", arg[1])
    help()
end

local action = arg[1]

local what_table = {
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

local function write_be256(value)
    io.stdout:write(string.rep("\0", 32-8))
    io.stdout:write(string.pack(">I8", value))
end

local function encode_input_metadata(arg)
    local msg_sender
    local block_number
    local time_stamp
    local epoch_index
    local input_index
    local encode_input_metadata_options = {
        { "^%-%-msg%-sender%=(.+)$", function(o)
            if not o or #o < 1 then return false end
            if string.sub(o, 1, 2) ~= "0x" then
                error("invalid msg-sender " .. o .. " (missing 0x prefix)")
            end
            msg_sender, err = unhex(string.sub(o, 3))
            if not msg_sender then
                error("invalid msg-sender " .. o .. " " .. err)
            end
            if #msg_sender ~= 20 then
                error(string.format("msg-sender must be 20 bytes long (%s is %u bytes long)", o,  #msg_sender))
            end
            return true
        end },
        { "^%-%-block%-number%=(.+)$", function(n)
            if not n then return false end
            block_number = assert(util.parse_number(n), "block number" .. n)
            return true
        end },
        { "^%-%-time%-stamp%=(.+)$", function(n)
            if not n then return false end
            time_stamp = assert(util.parse_number(n), "time stamp" .. n)
            return true
        end },
        { "^%-%-epoch%-index%=(.+)$", function(n)
            if not n then return false end
            epoch_index = assert(util.parse_number(n), "epoch index" .. n)
            return true
        end },
        { "^%-%-input%-index%=(.+)$", function(n)
            if not n then return false end
            input_index = assert(util.parse_number(n), "input index" .. n)
            return true
        end },
        { ".*", function(all)
            error("unrecognized option " .. all)
        end }
    }

    for i = 3, #arg do
        local a = arg[i]
        for j, option in ipairs(encode_input_metadata_options) do
            if option[2](a:match(option[1])) then
                break
            end
        end
    end

    assert(msg_sender, "missing msg-sender")
    assert(block_number, "missing block-number")
    assert(time_stamp, "missing time-stamp")
    assert(epoch_index, "missing epoch-index")
    assert(input_index, "missing input-index")

    io.stdout:write(string.rep("\0", 12))
    io.stdout:write(msg_sender)
    write_be256(block_number)
    write_be256(time_stamp)
    write_be256(epoch_index)
    write_be256(input_index)
end

local function encode_string(arg)
    local payload
    local payload_filename
    local encode_string_options = {
        { "^%-%-payload%-filename%=(.+)$", function(o)
            if not o or #o < 1 then return false end
            assert(not payload, "payload already specified")
            payload_filename = o
            return true
        end },
        { "^%-%-payload%=(.+)$", function(n)
            if not n then return false end
            assert(not payload_filename, "payload filename already specified")
            payload = n
            return true
        end },
        { ".*", function(all)
            error("unrecognized option " .. all)
        end }
    }

    for i = 3, #arg do
        local a = arg[i]
        for j, option in ipairs(encode_string_options) do
            if option[2](a:match(option[1])) then
                break
            end
        end
    end

    if payload_filename then
        local f = assert(io.open(payload_filename, "rb"))
        payload = assert(f:read("*a"))
        f:close()
    elseif not payload then
        payload = assert(io.stdin:read("*a"))
    end

    write_be256(32) -- offset
    write_be256(#payload)
    io.stdout:write(payload)
end

local function encode_voucher(arg)
    local payload
    local payload_filename
    local address
    local encode_voucher_options = {
        { "^%-%-payload%-filename%=(.+)$", function(o)
            if not o or #o < 1 then return false end
            assert(not payload, "payload already specified")
            payload_filename = o
            return true
        end },
        { "^%-%-payload%=(.+)$", function(n)
            if not n then return false end
            assert(not payload_filename, "payload filename already specified")
            payload = n
            return true
        end },
        { "^%-%-address%=(.+)$", function(o)
            if not o or #o < 1 then return false end
            if string.sub(o, 1, 2) ~= "0x" then
                error("invalid address " .. o .. " (missing 0x prefix)")
            end
            address, err = unhex(string.sub(o, 3))
            if not address then
                error("invalid address " .. o .. " " .. err)
            end
            if #address ~= 20 then
                error(string.format("address must be 20 bytes long (%s is %u bytes long)", o,  #address))
            end
            return true
        end },
        { ".*", function(all)
            error("unrecognized option " .. all)
        end }
    }

    for i = 3, #arg do
        local a = arg[i]
        for j, option in ipairs(encode_voucher_options) do
            if option[2](a:match(option[1])) then
                break
            end
        end
    end

    assert(address, "missing address")

    if payload_filename then
        local f = assert(io.open(payload_filename, "rb"))
        payload = assert(f:read("*a"))
        f:close()
    elseif not payload then
        payload = assert(io.stdin:read("*a"))
    end

    io.stdout:write(string.rep("\0", 12))
    io.stdout:write(address)
    write_be256(64)
    write_be256(#payload)
    io.stdout:write(payload)
end

local function read_address()
    return string.sub(io.stdin:read(32), 13)
end

local function read_hash()
    local s = io.stdin:read(32)
    if s and #s == 32 then return s end
end

local function read_be256()
    return string.unpack(">I8", string.sub(io.stdin:read(32), 25))
end

local function decode_input_metadata(arg)
    if arg[3] then
        error("unexpected option " .. arg[3])
    end
    local msg_sender = read_address()
    local block_number = read_be256()
    local time_stamp = read_be256()
    local epoch_index = read_be256()
    local input_index = read_be256()
    io.stdout:write("msg-sender: ", hex(msg_sender), "\n")
    io.stdout:write("block-number: ", block_number, "\n")
    io.stdout:write("time-stamp: ", time_stamp, "\n")
    io.stdout:write("epoch-index: ", epoch_index, "\n")
    io.stdout:write("input-index: ", input_index, "\n")
end

local function decode_string(arg)
    if arg[3] then
        error("unexpected option " .. arg[3])
    end
    assert(read_be256() == 32) -- skip offset
    local length = read_be256()
    io.stdout:write(assert(io.stdin:read(length)))
end

local function encode_string(arg)
    local payload
    local payload_filename
    local encode_voucher_options = {
        { "^%-%-payload%-filename%=(.+)$", function(o)
            if not o or #o < 1 then return false end
            assert(not payload, "payload already specified")
            payload_filename = o
            return true
        end },
        { "^%-%-payload%=(.+)$", function(n)
            if not n then return false end
            assert(not payload_filename, "payload filename already specified")
            payload = n
            return true
        end },
        { ".*", function(all)
            error("unrecognized option " .. all)
        end }
    }

    for i = 3, #arg do
        local a = arg[i]
        for j, option in ipairs(encode_voucher_options) do
            if option[2](a:match(option[1])) then
                break
            end
        end
    end

    if payload_filename then
        local f = assert(io.open(payload_filename, "rb"))
        payload = assert(f:read("*a"))
        f:close()
    elseif not payload then
        payload = assert(io.stdin:read("*a"))
    end

    write_be256(32)
    write_be256(#payload)
    io.stdout:write(payload)

end

local function decode_voucher(arg)
    if arg[3] then
        error("unexpected option " .. arg[4])
    end
    local address = read_address()
    io.stderr:write(hex(address), "\n")
    local offset = read_be256()
    assert(offset == 64, "expected offset 64, got " .. offset) -- skip offset
    local length = read_be256()
    io.stdout:write(assert(io.stdin:read(length)))
end

local function decode_hashes(arg)
    if arg[3] then
        error("unexpected option " .. arg[4])
    end
    while 1 do
        local hash = read_hash()
        if not hash then break end
        io.stdout:write(hex(hash), "\n")
    end
end

local action_what_table = {
    encode_input_metadata = encode_input_metadata,
    encode_input = encode_string,
    encode_query = encode_string,
    encode_voucher = encode_voucher,
    encode_notice = encode_string,
    encode_report = encode_string,
    decode_input_metadata = decode_input_metadata,
    decode_input = decode_string,
    decode_query = decode_string,
    decode_voucher = decode_voucher,
    decode_notice = decode_string,
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
