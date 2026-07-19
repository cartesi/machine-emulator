#!/usr/bin/env lua5.4
-- Host-side mirror of /usr/bin/rollup.
-- Encodes advance/inspect requests for the CMIO rx buffer; decodes
-- voucher/notice/report/exception/delegate-call-voucher records from
-- the CMIO tx buffer.

local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")

local EVM_ADVANCE = "EvmAdvance(uint256,address,address,uint256,uint256,uint256,uint256,bytes)"
local VOUCHER = "Voucher(address,uint256,bytes)"
local DELEGATE = "DelegateCallVoucher(address,bytes)"
local NOTICE = "Notice(bytes)"

local PAYLOAD_SCHEMA_DICT = {
    Base64Payload = { payload = "Base64" },
    HexPayload = { payload = "Hex" },
    Utf8Payload = { payload = "Default" },
}

local USAGE = [[Usage:
    cartesi-rollup-data.lua [options] <direction> <type>

  where [options] can be

    --hex-payload
      encode/decode payload fields as 0x-prefixed hex (default)

    --base64-payload
      encode/decode payload fields as base64

    --utf8-payload
      encode/decode payload fields as UTF-8 text

Reads from stdin and writes to stdout. Encoding subcommands take a
JSON description and write the binary record. Decoding subcommands
take the binary record and write a JSON description.

  encode <type>    JSON stdin -> binary stdout

    encode advance
      encode an advance-state request as binary EvmAdvance calldata.
      The JSON object must contain chain_id, app_contract, msg_sender,
      block_number, block_timestamp, prev_randao, index, and payload
      fields.

    encode inspect
      write the raw inspect-state query payload bytes to stdout. The
      JSON object must contain a single payload field.

  decode <type>    binary stdin -> JSON stdout

    decode advance
      decode an advance-state request, printing a JSON object with
      chain_id, app_contract, msg_sender, block_number, block_timestamp,
      prev_randao, index, and payload fields.

    decode inspect
      wrap the raw query payload bytes in a JSON object with a single
      payload field.

    decode voucher
      decode a voucher, printing destination, value, and payload.

    decode delegate-call-voucher
      decode a delegate-call voucher, printing destination and payload.

    decode notice
      decode a notice, printing the payload.

    decode report
    decode exception
      print a JSON object with a single payload field carrying the raw
      payload bytes hex-encoded.

  where
    chain_id, block_number, block_timestamp, and index are non-negative
      integers,
    app_contract and msg_sender are 20-byte EVM addresses in hex,
    prev_randao is a big-endian 32-byte unsigned integer in hex, and
    payload fields use the selected encoding.

]]

local payload_schema = "HexPayload"

-- Convert a uint256 bint to a 0x-prefixed 64-character hex string.
-- evmu.bint is a 512-bit instance; tobe() returns 64 bytes; last 32 are
-- the uint256 value.
local function uint256_to_hex(v)
    return cartesi.tohex(evmu.bint.tobe(v):sub(33))
end

local function read_json_stdin()
    return cartesi.fromjson(io.read("a"), payload_schema, PAYLOAD_SCHEMA_DICT)
end

local function write_json(t)
    io.write(cartesi.tojson(t, 2, payload_schema, PAYLOAD_SCHEMA_DICT))
    io.write("\n")
end

local function require_field(t, key)
    local v = t[key]
    if v == nil then
        error("missing required field: " .. key)
    end
    return v
end

local encoders = {}
local decoders = {}

function encoders.advance()
    local f = read_json_stdin()
    local bint = evmu.bint
    local bin = evmu.encode_calldata(EVM_ADVANCE, {
        bint.new(require_field(f, "chain_id")),
        require_field(f, "app_contract"),
        require_field(f, "msg_sender"),
        bint.new(require_field(f, "block_number")),
        bint.new(require_field(f, "block_timestamp")),
        bint.new(require_field(f, "prev_randao")),
        bint.new(require_field(f, "index")),
        evmu.raw(require_field(f, "payload")),
    })
    io.write(bin)
end

function encoders.inspect()
    local f = read_json_stdin()
    io.write(require_field(f, "payload"))
end

function decoders.advance()
    local t = evmu.decode_calldata(EVM_ADVANCE, io.read("a"))
    local bint = evmu.bint
    write_json({
        chain_id = bint.touinteger(t[1]),
        app_contract = t[2],
        msg_sender = t[3],
        block_number = bint.touinteger(t[4]),
        block_timestamp = bint.touinteger(t[5]),
        prev_randao = uint256_to_hex(t[6]),
        index = bint.touinteger(t[7]),
        payload = cartesi.fromhex(t[8]),
    })
end

function decoders.inspect()
    write_json({ payload = io.read("a") })
end

function decoders.voucher()
    local t = evmu.decode_calldata(VOUCHER, io.read("a"))
    write_json({
        destination = t[1],
        value = uint256_to_hex(t[2]),
        payload = cartesi.fromhex(t[3]),
    })
end

decoders["delegate-call-voucher"] = function()
    local t = evmu.decode_calldata(DELEGATE, io.read("a"))
    write_json({
        destination = t[1],
        payload = cartesi.fromhex(t[2]),
    })
end

function decoders.notice()
    local t = evmu.decode_calldata(NOTICE, io.read("a"))
    write_json({ payload = cartesi.fromhex(t[1]) })
end

local function decode_raw_payload()
    write_json({ payload = io.read("a") })
end
decoders.report = decode_raw_payload
decoders.exception = decode_raw_payload

local function fail()
    io.stderr:write(USAGE)
    os.exit(1)
end

local argi = 1
while true do
    if arg[argi] == "--hex-payload" then
        payload_schema = "HexPayload"
    elseif arg[argi] == "--base64-payload" then
        payload_schema = "Base64Payload"
    elseif arg[argi] == "--utf8-payload" then
        payload_schema = "Utf8Payload"
    else
        break
    end
    argi = argi + 1
end

local direction = arg[argi]
if not direction or direction == "-h" or direction == "--help" then
    io.stderr:write(USAGE)
    os.exit(direction ~= nil and 0 or 1)
end

local handlers
if direction == "encode" then
    handlers = encoders
elseif direction == "decode" then
    handlers = decoders
else
    fail()
end
local h = handlers[arg[argi + 1] or ""]
if not h or arg[argi + 2] then
    fail()
end
h()
