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

local lpeg = require("lpeg")
local bint_extra = 256
local bint = require("bint")(256 + bint_extra)

local P, R, S, C, Ct, V, Cmt, Carg = lpeg.P, lpeg.R, lpeg.S, lpeg.C, lpeg.Ct, lpeg.V, lpeg.Cmt, lpeg.Carg
local cartesi = require("cartesi")
local keccak256 = cartesi.keccak256

local tinsert = table.insert

local _M = {}

_M.bint = bint

-- Appends to 'output' the entire contents of 'more'
local function tappend(output, more)
    for _, v in ipairs(more) do
        tinsert(output, v)
    end
end

-- Throws formatted error
local function errorf(fmt, ...) error(string.format(fmt, ...)) end

-- Converts 'value' (a bint) to a its 256-bit big-endian representation as a string
local function tobe(value) return bint.tobe(value):sub(bint_extra / 8 + 1) end

-- Converts 'hex' (an hex-encoded sequence of bytes) to the corresponding decoded string
local function fromhex(hex)
    if not hex then return nil, "missing hex string" end
    if type(hex) ~= "string" then return nil, "hex not a string" end
    if string.lower(hex:sub(1, 2)) ~= "0x" then return nil, 'hex string must start with "0x"' end
    if #hex % 2 ~= 0 then return nil, "hex string length must be even" end
    local invalid
    local data = string.gsub(hex:sub(3), "(..)", function(c)
        local n = tonumber(c, 16)
        if not n then
            invalid = c
            n = 0
        end
        return string.char(n)
    end)
    if invalid then
        return nil, string.format("hex string cannot contain %q", invalid)
    else
        return data
    end
end

-- Converts 's' to an hex-encoded string
local function tohex(s)
    if type(s) ~= "string" then return nil, "expected string, got " .. type(s) end
    return "0x" .. (string.gsub(s, ".", function(c) return string.format("%02x", string.byte(c)) end))
end

-- Returns a pattern that saves the current position and an associated message before trying to match 'pat'
-- This is used for error reporting, should the matching fail later on
local function expect(what, pat)
    return Cmt(Carg(1), function(_s, pos, err)
        if pos >= err.pos then
            err.pos = pos
            err.what = what
        end
    end) + pat
end

local opsp = S(" \t\n\r") ^ 0 -- optional spaces
local leadit = R("19") -- non-zero leading digit
local digit = R("09") -- following digits
local idfirst = R("az", "AZ", "__") -- first identifier character
local idrest = R("az", "AZ", "__", "09") -- remaining identifier character
local idnot = -idrest -- the end of an identifier

local identifier = expect("identifier", idfirst * idrest ^ 0)

-- an int or uint size
local int_size_idnot = expect(
    "integer size",
    Cmt((leadit * digit ^ 0) ^ -1 * idnot, function(_s, pos, size)
        if size == "" then return pos, 256 end
        local n = tonumber(size)
        return n >= 8 and n <= 256 and n % 8 == 0 and pos, n
    end)
)

local bytes_size_idnot = expect(
    "bytes size",
    Cmt((leadit * digit ^ 0) ^ -1 * idnot, function(_s, pos, size)
        if size == "" then return pos, nil end
        local n = tonumber(size)
        return n >= 1 and n <= 32 and pos, n
    end)
)

-- grammar to parse a type
local type_spec = P({
    "type_spec",

    data_location = P("memory") + P("calldata") + P("storage"),

    type_spec = V("elementary_type_spec") * opsp * V("array_brackets") * opsp * C(V("data_location") ^ -1) * opsp * C(
        identifier ^ -1
    ) / function(elem, brackets, location, name)
        for _, size in ipairs(brackets) do
            elem = {
                type_name = "array",
                element_type = elem,
                size = size ~= "" and tonumber(size) or nil,
            }
        end
        elem.name = name ~= "" and name or nil
        elem.data_location = location ~= "" and location or nil
        return elem
    end,

    elementary_type_spec = V("int") + V("uint") + V("bytes") + V("address") + V("string") + V("bool") + V("tuple"),

    sized_array_bracket = P("[") * opsp * C(leadit * digit ^ 0) * opsp * expect("closing bracket", P("]")),

    empty_array_bracket = P("[") * opsp * C("") * expect("closing bracket or array size", P("]")),

    array_bracket = V("empty_array_bracket") + V("sized_array_bracket"),

    array_brackets = Ct(V("array_bracket") ^ 0),

    non_empty_component_list = V("type_spec") * opsp * (P(",") * opsp * expect("type spec", V("type_spec"))) ^ 0,

    tuple = P("(")
        * opsp
        * Ct(V("non_empty_component_list") ^ -1)
        * opsp
        * expect("closing parenthesis", P(")"))
        / function(components) return { type_name = "tuple", components = components or {} } end,

    uint = P("uint") * int_size_idnot / function(size) return { type_name = "uint", size = size } end,

    int = P("int") * int_size_idnot / function(size) return { type_name = "int", size = size } end,

    bytes = P("bytes") * bytes_size_idnot / function(size) return { type_name = "bytes", size = size } end,

    address = P("address") * idnot / function() return { type_name = "address" } end,

    bool = P("bool") * idnot / function() return { type_name = "bool" } end,

    string = P("string") * idnot / function() return { type_name = "string" } end,
})

local non_empty_component_list = type_spec * opsp * (P(",") * opsp * expect("type spec", type_spec)) ^ 0

local tuple = P("(")
    * opsp
    * Ct(non_empty_component_list ^ -1)
    * opsp
    * expect("closing parenthesis", P(")"))
    / function(components) return { type_name = "tuple", components = components or {} } end

-- grammar for a function signature
local func_sig = opsp
    * Ct(
        (P("function") * idnot * opsp) ^ -1
            * C(expect("identifier", identifier * opsp))
            * expect("parameters", tuple)
            * opsp
            * (P("returns") * idnot * opsp * expect("return parameters", tuple)) ^ -1
    )
    / function(parts)
        return {
            name = parts[1],
            params = parts[2],
            returns = parts[3] or { type_name = "tuple", components = {} },
        }
    end
    * opsp
    * -1

-- check if the return 'ret' of a call to match() succeeded, otherwise use the 'err' table and the
-- original input 's' to create an error message and throw
local function check_match_error(s, ret, err)
    if not ret then
        local pos = assert(err.pos, "expected error position")
        local line, line_pos = 1, 0
        string.gsub(s:sub(1, pos - 1), "()\n", function(lp)
            line = line + 1
            line_pos = lp
        end)
        local col = pos - line_pos
        local ctx = s:sub(pos, pos + 8)
        if #s - pos > 8 then ctx = ctx .. "..." end
        errorf("expected %s at line %d, column %d (got %q)", err.what, line, col, ctx)
    end
    return ret
end

-- append to 'output' table string pieces of the canonic type signature for 'parsed_type_spec'
local function append_canonic_type_sig(output, parsed_type_spec)
    local tn = parsed_type_spec.type_name
    if tn == "uint" then
        tinsert(output, "uint")
        tinsert(output, parsed_type_spec.size)
    elseif tn == "int" then
        tinsert(output, "int")
        tinsert(output, parsed_type_spec.size)
    elseif tn == "address" then
        tinsert(output, "address")
    elseif tn == "bool" then
        tinsert(output, "bool")
    elseif tn == "string" then
        tinsert(output, "string")
    elseif tn == "bytes" then
        tinsert(output, "bytes")
        if parsed_type_spec.size then tinsert(output, parsed_type_spec.size) end
    elseif tn == "array" then
        append_canonic_type_sig(output, parsed_type_spec.element_type)
        tinsert(output, "[")
        if parsed_type_spec.size then tinsert(output, parsed_type_spec.size) end
        tinsert(output, "]")
    elseif tn == "tuple" then
        tinsert(output, "(")
        for i, comp in ipairs(parsed_type_spec.components) do
            append_canonic_type_sig(output, comp)
            if parsed_type_spec.components[i + 1] then tinsert(output, ",") end
        end
        tinsert(output, ")")
    else
        -- luacov: disable
        error("unknown type name: " .. tostring(tn))
        -- luacov: enable
    end
end

-- returns the canonic type signature for 'parsed_type_spec'
local function canonic_func_sig(parsed_func_sig)
    local output = {}
    tinsert(output, parsed_func_sig.name)
    tinsert(output, "(")
    local ps = parsed_func_sig.params.components
    for i, p in ipairs(ps) do
        append_canonic_type_sig(output, p)
        if ps[i + 1] then tinsert(output, ",") end
    end
    tinsert(output, ")")
    return table.concat(output)
end

-- parsed function signature cache
-- this avoids repeated parsing of the same function signature
-- a parsed function signature will remain in cache at least as long as a string with that signature exists in Lua
-- once the string is collected, the corresponding parsed signature may be collected too
local parsed_func_sig_cache = setmetatable({}, { __mode = "k" })

-- returns a parsed function signature and the corresponding canonic signature
function _M.parse_func_sig(sig)
    assert(type(sig) == "string", "expected string")
    local cached = parsed_func_sig_cache[sig]
    if cached then return cached.parsed_func_sig, cached.func_sel, cached.canonic_func_sig end
    local err = { pos = 0, what = "unknown error" }
    local parsed_sig = check_match_error(sig, func_sig:match(sig, 1, err), err)
    local canonic_sig = canonic_func_sig(parsed_sig)
    local func_sel = keccak256(canonic_sig):sub(1, 4)
    parsed_func_sig_cache[sig] = {
        parsed_func_sig = parsed_sig,
        func_sel = func_sel,
        canonic_func_sig = canonic_sig,
    }
    return parsed_sig, func_sel, canonic_sig
end

local type_spec_only = opsp * type_spec * opsp * -1

-- returns a parsed type
function _M.parse_type_spec(s)
    local err = { pos = 0, what = "unknown error" }
    return check_match_error(s, type_spec_only:match(s, 1, err), err)
end

-- traverses a 'parsed_type_spec' marking all types that are dynamic and otherwise computing the static sizes
local function mark_dynamic_types(parsed_type_spec)
    local tn = parsed_type_spec.type_name
    if tn == "string" then
        parsed_type_spec.is_dynamic = true
    elseif tn == "bytes" then
        if parsed_type_spec.size then
            parsed_type_spec.is_dynamic = false
            parsed_type_spec.static_size = 32
        else
            parsed_type_spec.is_dynamic = true
        end
        parsed_type_spec.is_dynamic = not parsed_type_spec.size
    elseif tn == "array" then
        mark_dynamic_types(parsed_type_spec.element_type)
        parsed_type_spec.is_dynamic = parsed_type_spec.element_type.is_dynamic or not parsed_type_spec.size
        if not parsed_type_spec.is_dynamic then
            parsed_type_spec.static_size = parsed_type_spec.size * parsed_type_spec.element_type.static_size
        end
    elseif tn == "tuple" then
        -- Tuple is dynamic if any of its components is dynamic
        local is_dynamic = false
        local static_size = 0
        for _, component in ipairs(parsed_type_spec.components) do
            mark_dynamic_types(component)
            if component.is_dynamic then
                is_dynamic = true
                static_size = static_size + 32
            else
                static_size = static_size + component.static_size
            end
        end
        parsed_type_spec.is_dynamic = is_dynamic
        parsed_type_spec.static_size = static_size
    else -- "uint", "int", "address", "bool"
        parsed_type_spec.static_size = 32
        parsed_type_spec.is_dynamic = false
    end
end

-- returns true if a 'parsed_type_spec' is a dynamic type, else, returns false and the static size.
-- uses memoization to avoid recomputation.
local function is_dynamic_type(parsed_type_spec)
    if parsed_type_spec.is_dynamic == nil then mark_dynamic_types(parsed_type_spec) end
    return parsed_type_spec.is_dynamic, parsed_type_spec.static_size
end

local append_encoded_value -- forward declaration

-- address and bytes are supposed to be hex-encoded into strings, which are then converted to binary
-- if the content is already binary, we provide a simple wrapper that avoids the round-trip conversion
local raw_meta = { __tostring = function(self) return string.format("raw(%q)", self[1]) end }

-- strings are supposed to be raw strings
-- if the content hex-encoded, we provide a simple wrapper forces conversion to raw before use
local hex_meta = { __tostring = function(self) return string.format("hex(%q)", self[1]) end }

-- returns true if the data is a wrapped binary string
local function is_raw(b) return getmetatable(b) == raw_meta end
_M.is_raw = is_raw

-- returns true if the data is a wrapped hex string
local function is_hex(b) return getmetatable(b) == hex_meta end
_M.is_hex = is_hex

-- wraps a string to tell us it is raw data when we might expect hex-encoded
function _M.raw(s)
    if is_raw(s) then return s end
    assert(type(s) == "string")
    return setmetatable({ s }, raw_meta)
end

-- wraps a string to tell us it is encoded in hex when we might expect raw data
function _M.hex(s)
    if is_hex(s) then return s end
    assert(type(s) == "string")
    return setmetatable({ s }, hex_meta)
end

-- gets the underlying binary data
local function get_raw(b) return b[1] end
_M.get_raw = get_raw

-- gets the underlying hex data
local function get_hex(b) return b[1] end

_M.get_hex = get_hex

-- return binary data when hex is expected
local function get_raw_expect_hex(s)
    if is_raw(s) then return get_raw(s) end
    if is_hex(s) then s = get_hex(s) end
    assert(type(s) == "string", "expected hex-encoded string value")
    return assert(fromhex(s))
end

-- return binary data when binary data is expected
local function get_raw_expect_raw(s)
    if is_raw(s) then return get_raw(s) end
    if is_hex(s) then return assert(fromhex(get_hex(s))) end
    assert(type(s) == "string", "expected raw string value")
    return s
end

-- returns the calldata encoding of an uint 'value'
local function encoded_uint(value, size)
    size = size or 256
    value = assert(bint.new(value), "value not an integer")
    assert(bint.eq(value >> size, 0), "integer value does not fit in target type")
    return tobe(value)
end

-- appends the calldata parts of an uint 'value' into the 'output' table
local function append_encoded_uint(output, value, size) tinsert(output, encoded_uint(value, size)) end

-- appends the calldata parts of an int 'value' into the 'output' table
local function append_encoded_int(output, value, size)
    size = size or 256
    value = assert(bint.new(value), "value not an integer")
    local m1 = bint.one() << (size - 1)
    if value < 0 then
        assert(bint.ule(m1, value), "integer value does not fit in target type")
    else
        assert(bint.ult(value, m1), "integer value does not fit in target type")
    end
    tinsert(output, tobe(value))
end

-- appends the calldata parts of an address 'value' into the 'output' table
local function append_encoded_address(output, value)
    local raw = get_raw_expect_hex(value)
    if #raw ~= 20 then errorf("invalid address length (expected 20 bytes, got %d bytes)", #raw) end
    tinsert(output, "\0\0\0\0\0\0\0\0\0\0\0\0")
    tinsert(output, raw)
end

-- converts bool to 0 or 1
local function check_bool(value)
    if type(value) == "boolean" then
        if value then
            return 1
        else
            return 0
        end
    end
    errorf("expected boolean (got %s)", type(value))
end

-- appends the calldata parts of a bool 'value' into the 'output' table
local function append_encoded_bool(output, value) append_encoded_uint(output, check_bool(value)) end

-- appends 0-padding to the 'output' table
local function append_padding(output, len)
    local padded_len = 32 * ((len + 31) // 32)
    if padded_len > len then tinsert(output, string.rep("\0", padded_len - len)) end
end

-- appends the calldata parts of a string 'value' into the 'output' table
local function append_encoded_string(output, value)
    local raw = get_raw_expect_raw(value)
    local len = #raw
    append_encoded_uint(output, len)
    tinsert(output, raw)
    append_padding(output, len)
end

-- appends the calldata parts of a bytes 'value' into the 'output' table
local function append_encoded_bytes(output, value, size)
    local raw = get_raw_expect_hex(value)
    if not size then return append_encoded_string(output, raw) end
    local len = #raw
    if len ~= size then errorf("bytes has wrong size (expected %d, got %d)", size, len) end
    tinsert(output, raw)
    append_padding(output, len)
end

-- appends the calldata parts of an array 'value' into the 'output' table, tiven its type name 'tn'
local function append_encoded_array(output, values, tn)
    assert(type(values) == "table" and not bint.isbint(values), "array values not in table")
    local dynamic_size = not tn.size
    if not dynamic_size and tn.size ~= #values then
        errorf("invalid value count (expected %u, got %u)", tn.size, #values)
    end
    -- For dynamic arrays, encode length first
    if dynamic_size then append_encoded_uint(output, #values) end
    -- Static elements: encode directly
    if not is_dynamic_type(tn.element_type) then
        for _, value in ipairs(values) do
            append_encoded_value(output, value, tn.element_type)
        end
        return
    end
    -- Dynamic elements: encode offsets first, then data
    local offset = #values * 32 -- Each offset is 32 bytes
    local value_parts = {}
    for _, value in ipairs(values) do
        append_encoded_uint(output, offset)
        local first_part = #value_parts + 1
        append_encoded_value(value_parts, value, tn.element_type)
        for i = first_part, #value_parts do
            offset = offset + #value_parts[i]
        end
    end
    tappend(output, value_parts)
end

-- check that all tuple values are available
local function check_tuple_values(values, parsed_type_spec)
    local comps = parsed_type_spec.components
    local names = parsed_type_spec.component_names
    if not names then
        names = {}
        for i, comp_type in ipairs(comps) do
            local name = comp_type.name
            if name then
                if names[name] then errorf("tuple has repeated component name %q", name) end
                names[name] = i
            end
        end
        parsed_type_spec.component_names = names
    end
    local count = #comps
    for i in pairs(values) do
        if math.type(i) == "integer" and (i > count or i < 1) then
            errorf("unexpected tuple component at index %u", i)
        end
        if type(i) == "string" and not names[i] then errorf("unexpected tuple component with name %q", i) end
    end
    for i, comp_type in ipairs(comps) do
        if values[i] == nil then
            local name = comp_type.name
            if not name then errorf("missing tuple component at index %u", i) end
            if values[name] == nil then errorf("missing tuple component at index %u (or with name %q)", i, name) end
        end
    end
end

-- returns tuple component (assumes it exists)
local function tuple_value(values, i, name)
    local v = values[i]
    if v ~= nil then return v end
    return values[name]
end

-- appends the calldata parts of a tuple 'value' into the 'output' table, given its 'parsed_type_spec'
local function append_encoded_tuple(output, values, parsed_type_spec)
    assert(type(values) == "table" and not bint.isbint(values), "tuple values not in table")
    check_tuple_values(values, parsed_type_spec)
    local comps = parsed_type_spec.components
    local offset = 0
    local dynamic_offset = {} -- index of each dynamic offset in output
    -- For each static value, add encoded data to output
    -- For each dynamic value, add add only a placeholder for yet-unknown offset
    for i, comp_type in ipairs(comps) do
        local is_dynamic, static_size = is_dynamic_type(comp_type)
        if is_dynamic then
            tinsert(output, "") -- placeholder for offset to start of dynamic value
            tinsert(dynamic_offset, #output)
            offset = offset + 32
        else
            append_encoded_value(output, tuple_value(values, i, comp_type.name), comp_type)
            offset = offset + static_size
        end
    end
    -- For each dynamic element, replace its offset and append its parts to output
    local dynamic_index = 1
    for i, comp_type in ipairs(comps) do
        if is_dynamic_type(comp_type) then
            -- replace offset placeholder with correct value
            output[dynamic_offset[dynamic_index]] = encoded_uint(offset)
            dynamic_index = dynamic_index + 1
            local first_part = #output + 1
            append_encoded_value(output, tuple_value(values, i, comp_type.name), comp_type)
            for j = first_part, #output do -- advance offset by size of encoded value
                offset = offset + #output[j]
            end
        end
    end
end

-- appends the calldata parts of 'value' into the 'output' table, assuming a given its 'parsed_type_spec'
function append_encoded_value(output, value, parsed_type_spec)
    local tn = parsed_type_spec.type_name
    if tn == "uint" then
        append_encoded_uint(output, value, parsed_type_spec.size)
    elseif tn == "int" then
        append_encoded_int(output, value, parsed_type_spec.size)
    elseif tn == "address" then
        append_encoded_address(output, value)
    elseif tn == "bool" then
        append_encoded_bool(output, value)
    elseif tn == "string" then
        append_encoded_string(output, value)
    elseif tn == "bytes" then
        append_encoded_bytes(output, value, parsed_type_spec.size)
    elseif tn == "array" then
        append_encoded_array(output, value, parsed_type_spec)
    elseif tn == "tuple" then
        append_encoded_tuple(output, value, parsed_type_spec)
    else
        -- luacov: disable
        error("unknown type name: " .. tostring(tn))
        -- luacov: enable
    end
end

-- returns the binary encoded calldata for a function signature 'func_sig_str' and the corresponpding 'args' table
-- bool values are expected as booleans
-- as in solidity, address and bytes values are expected as hex-encoded strings
-- if you want to pass raw data in a string instead, wrap the value with calldata.raw()
-- as in solidity, string values are expected as raw data
-- if you want to pass them as hex-encoded strings, wrap the value with calldata.hex()
-- int/uint values are expected in any format bint.new accepts
-- tuples and arrays are expected as tables with the corresponding values
function _M.encode_calldata(func_sig_str, args)
    assert(type(func_sig_str) == "string", "expected function signature string")
    assert(type(args) == "table", "expected arguments table")
    local parsed_sig, func_sel = _M.parse_func_sig(func_sig_str)
    -- Start with selector
    local output = { func_sel }
    -- Encode arguments as a tuple
    append_encoded_tuple(output, args, parsed_sig.params)
    return table.concat(output)
end

-- returns the hex-encoded calldata for a 'func_sig' and the corresponpding 'args' table
function _M.encode_calldata_hex(sig, args) return tohex(_M.encode_calldata(sig, args)) end

_M.encode_hex = tohex
_M.decode_hex = fromhex

local decode_value -- forward declaration

-- reads a 32-byte word from 'calldata' at 'offset' and returns it as a bint
local word_padding = string.rep("\0", bint_extra / 8)
local function read_word(calldata, offset)
    if offset + 32 > #calldata then errorf("insufficient calldata for 256-bit word at offset %d", offset) end
    local word = calldata:sub(offset + 1, offset + 32)
    return bint.frombe(word_padding .. word)
end

-- reads a uint value from 'calldata' at 'offset'
local function decode_uint(calldata, offset, size)
    size = size or 256
    local value = read_word(calldata, offset)
    assert(bint.eq(value >> size, 0), "integer value does not fit in target type")
    return value, offset + 32
end

-- reads an int value from 'calldata' at 'offset'
local sign_ext = (-bint.one()) << 256
local function decode_int(calldata, offset, size)
    size = size or 256
    local value = read_word(calldata, offset)
    -- sign-extend to bin_extra bits
    if bint.eq(value >> 255, 1) then value = value | sign_ext end
    local intmax = bint.one() << (size - 1)
    local intmin = (-bint.one()) << (size - 1)
    if value < intmin or value >= intmax then error("integer value does not fit in target type") end
    return value, offset + 32
end

-- reads an address value from 'calldata' at 'offset'
local function decode_address(calldata, offset, prefer)
    local word = read_word(calldata, offset)
    -- Address is stored in the last 20 bytes of the 32-byte word
    local addr_data = tobe(word):sub(-20)
    if prefer ~= "raw" then addr_data = tohex(addr_data) end
    return addr_data, offset + 32
end

-- reads a bool value from 'calldata' at 'offset'
local function decode_bool(calldata, offset)
    local value = read_word(calldata, offset)
    if bint.eq(value, bint.zero()) then
        return false, offset + 32
    elseif bint.eq(value, bint.one()) then
        return true, offset + 32
    else
        error("invalid bool value in calldata (must be 0 or 1)")
    end
end

-- reads a string value from 'calldata' at 'offset'
local function decode_string(calldata, offset, prefer)
    local length, new_offset = decode_uint(calldata, offset)
    local len = bint.tonumber(length)
    local padded_len = 32 * ((len + 31) // 32)
    if new_offset + padded_len > #calldata then errorf("insufficient calldata for string of length %d", len) end
    local str_data = calldata:sub(new_offset + 1, new_offset + len)
    if prefer == "hex" then str_data = tohex(str_data) end
    -- Skip padding
    return str_data, new_offset + padded_len
end

local function decode_bytes_sized(calldata, offset, size, prefer)
    -- Fixed-size bytes
    local padded_len = 32 * ((size + 31) // 32)
    if offset + padded_len > #calldata then errorf("insufficient calldata for bytes%d", size) end
    local bytes_data = calldata:sub(offset + 1, offset + size)
    if prefer ~= "raw" then bytes_data = tohex(bytes_data) end
    return bytes_data, offset + padded_len
end

-- reads a bytes value from 'calldata' at 'offset'
local function decode_bytes(calldata, offset, size, prefer)
    if not size then
        -- Dynamic bytes (same as string but return as hex by default)
        local length, new_offset = decode_uint(calldata, offset)
        local len = bint.tonumber(length)
        local padded_len = 32 * ((len + 31) // 32)
        if new_offset + padded_len > #calldata then errorf("insufficient calldata for bytes of length %d", len) end
        local bytes_data = calldata:sub(new_offset + 1, new_offset + len)
        if prefer ~= "raw" then bytes_data = tohex(bytes_data) end
        return bytes_data, new_offset + padded_len
    end
    return decode_bytes_sized(calldata, offset, size, prefer)
end

-- reads an array value from 'calldata' at 'offset'
local function decode_array(calldata, offset, parsed_type_spec, prefer)
    local element_type = parsed_type_spec.element_type
    local size = parsed_type_spec.size
    local new_offset = offset
    local array_data_start = offset -- Start of the array data section
    if not size then
        -- Dynamic array - read length first
        local size_val
        size_val, new_offset = decode_uint(calldata, new_offset)
        size = bint.touinteger(size_val)
        array_data_start = new_offset -- Array data starts after the length field
    end
    local result = {}
    local is_dynamic_element = is_dynamic_type(element_type)
    if is_dynamic_element then
        -- Dynamic elements: read offset and decode immediately
        for i = 1, size do
            local offset_val = decode_uint(calldata, new_offset + (i - 1) * 32)
            -- Offsets are relative to the start of the array data section
            local element_offset = array_data_start + bint.touinteger(offset_val)
            result[i] = decode_value(calldata, element_offset, element_type, prefer)
        end
        -- Set new_offset to after all the offset fields
        new_offset = new_offset + (size * 32)
        return result, new_offset
    else
        -- Static elements: read sequentially
        for i = 1, size do
            result[i], new_offset = decode_value(calldata, new_offset, element_type, prefer)
        end
        return result, new_offset
    end
end

-- Reads a tuple value from 'calldata' at 'offset'
local function decode_tuple(calldata, offset, parsed_type_spec, prefer)
    local components = parsed_type_spec.components
    local result = {}
    local static_offset = offset -- Position within the static portion
    local tuple_start = offset -- Start of the tuple data
    local _, static_size = is_dynamic_type(parsed_type_spec)
    local new_offset = tuple_start + static_size -- Position to return (end of data)
    -- Process components
    for i, comp_type in ipairs(components) do
        local is_dynamic_component = is_dynamic_type(comp_type)
        if is_dynamic_component then
            local offset_val
            offset_val, static_offset = decode_uint(calldata, static_offset)
            -- Offsets are relative to the start of the tuple
            local dynamic_offset = tuple_start + bint.touinteger(offset_val)
            result[i], new_offset = decode_value(calldata, dynamic_offset, comp_type, prefer)
        else
            result[i], static_offset = decode_value(calldata, static_offset, comp_type, prefer)
        end
        local name = comp_type.name
        if name then result[name] = result[i] end
    end
    return result, new_offset
end

-- Reads a value of the specified type from 'calldata' at 'offset'
function decode_value(calldata, offset, parsed_type_spec, prefer)
    local tn = parsed_type_spec.type_name
    if tn == "uint" then
        return decode_uint(calldata, offset, parsed_type_spec.size)
    elseif tn == "int" then
        return decode_int(calldata, offset, parsed_type_spec.size)
    elseif tn == "address" then
        return decode_address(calldata, offset, prefer)
    elseif tn == "bool" then
        return decode_bool(calldata, offset)
    elseif tn == "string" then
        return decode_string(calldata, offset, prefer)
    elseif tn == "bytes" then
        return decode_bytes(calldata, offset, parsed_type_spec.size, prefer)
    elseif tn == "array" then
        return decode_array(calldata, offset, parsed_type_spec, prefer)
    elseif tn == "tuple" then
        return decode_tuple(calldata, offset, parsed_type_spec, prefer)
    else
        -- luacov: disable
        error("unknown type name: " .. tostring(tn))
        -- luacov: enable
    end
end

-- returns the decoded arguments table for a function signature and calldata
-- tuples and arrays are returned as tables with the corresponding values
-- int/uint are returned as bint numbers
-- bool values are returned as booleans
-- as in solidity, strings values are returned as raw data
-- as in solidity, address and bytes values are returned as hex-encoded strings
-- if you prefer all strings, address, and bytes values returned as hex-encoded strings, set prefer = 'hex'
-- if you prefer all strings, address, and bytes values returned as raw data, set prefer = 'raw'
function _M.decode_calldata(func_sig_str, calldata_raw, prefer)
    assert(type(func_sig_str) == "string", "expected function signature string")
    assert(type(calldata_raw) == "string", "expected calldata string")
    if #calldata_raw < 4 then error("calldata too short (missing function selector)") end
    local calldata_func_sel = calldata_raw:sub(1, 4)
    local parsed_sig, func_sel = _M.parse_func_sig(func_sig_str)
    if func_sel ~= calldata_func_sel then
        errorf("function selector mismatch (expected %s, got %s)", tohex(func_sel), tohex(calldata_func_sel))
    end
    assert(#parsed_sig.params.components ~= 0 or #calldata_raw == 4, "calldata too long")
    return decode_value(calldata_raw, 4, parsed_sig.params, prefer)
end

-- Returns the decoded arguments table for a function signature and hex-encoded calldata
function _M.decode_calldata_hex(func_sig_str, calldata_hex, prefer)
    local calldata_raw = assert(fromhex(calldata_hex))
    return _M.decode_calldata(func_sig_str, calldata_raw, prefer)
end

return _M
