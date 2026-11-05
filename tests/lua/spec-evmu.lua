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

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it = lester.describe, lester.it

describe("cartesi evmu", function()
    local evmu = require("cartesi.evmu")

    local function ptab(output, indent)
        indent = indent or 0
        local spaces = string.rep("  ", indent)
        if type(output) ~= "table" then
            print(spaces .. tostring(output))
            return
        end
        print(spaces .. "{")
        for k, v in pairs(output) do
            local key_str
            if type(k) == "string" then
                key_str = string.format("[%q]", k)
            else
                key_str = "[" .. tostring(k) .. "]"
            end
            if evmu.is_raw(v) or evmu.is_hex(v) then
                v = tostring(v)
            end
            if type(v) == "table" and not evmu.bint.isintegral(v) then
                print(spaces .. "  " .. key_str .. " = ")
                ptab(v, indent + 1)
            else
                local value_str
                if type(v) == "string" then
                    value_str = string.format("%q", v)
                else
                    value_str = tostring(v)
                end
                print(spaces .. "  " .. key_str .. " = " .. value_str .. ",")
            end
        end
        print(spaces .. "}")
    end

    local function tv(a)
        if a == nil then
            return "nil"
        end
        return string.format("%s %s", type(a), tostring(a))
    end

    -- checks that table a is a subset of table b
    local function subtab(a, b, path)
        path = path or "/"
        if evmu.bint.isintegral(a) or evmu.bint.isintegral(b) then
            local ai = evmu.bint.new(a)
            local bi = b and evmu.bint.new(b)
            if not evmu.bint.eq(ai, bi) then
                return nil, string.format("%s value differs (%s vs %s)", path, tostring(a), tostring(b))
            end
            return 1
        end
        if evmu.is_raw(a) then
            a = evmu.get_raw(a)
        end
        if evmu.is_hex(a) then
            a = evmu.get_hex(a)
        end
        if evmu.is_raw(b) then
            b = evmu.get_raw(b)
        end
        if evmu.is_hex(b) then
            a = evmu.get_hex(b)
        end
        local ta, tb = type(a), type(b)
        if ta ~= tb then
            return nil, string.format("%s type differs (%s vs %s)", path, tv(a), tv(b))
        end
        if ta ~= "table" then
            if a ~= b then
                return nil, string.format("%s value differs (%s vs %s)", path, tostring(a), tostring(b))
            end
            return 1
        end
        for i, va in pairs(a) do
            local ev, err = subtab(va, b[i], string.format(path .. tostring(i) .. "/"))
            if not ev then
                return nil, err
            end
        end
        return 1
    end

    local function check_parse_type_spec(s, output)
        assert(subtab(evmu.parse_type_spec(s), output))
    end

    local function check_parse_func_sig(s, expected_output)
        local output = evmu.parse_func_sig(s)
        local ret, err = subtab(expected_output, output)
        if not ret then
            ptab(expected_output)
            ptab(output)
            assert(ret, err)
        end
    end

    local function is_suffix(suffix, s)
        return s:sub(-#suffix) == suffix
    end

    local function check_parse_func_sig_error(s, expected_err)
        local ret, err = pcall(evmu.parse_func_sig, s)
        assert(not ret, "expected function to fail")
        assert(
            is_suffix(expected_err, err),
            string.format("error message mismatch (expected %s, got %s)", expected_err, tostring(err))
        )
    end

    local function check_parse_type_spec_error(s, expected_err)
        local ret, err = pcall(evmu.parse_type_spec, s)
        assert(not ret, "expected error")
        assert(is_suffix(expected_err, err), string.format("expected suffix '%s' in '%s'", expected_err, tostring(err)))
    end

    local function strdiff(a, b)
        local i = 1
        local a_len = #a
        local b_len = #a
        local min_len = math.min(a_len, b_len)
        while i <= min_len and a:byte(i) == b:byte(i) do
            i = i + 1
        end
        if i <= math.max(a_len, b_len) then
            return i, a:sub(i), b:sub(i)
        end
        return nil
    end

    local function check_decode_calldata_hex_error(s, cd, expected_err)
        local ret, err = pcall(evmu.decode_calldata_hex, s, cd)
        assert(not ret, "expected error")
        assert(is_suffix(expected_err, err), string.format("expected suffix '%s' in '%s'", expected_err, tostring(err)))
    end

    local function check_encode_decode_calldata_hex(s, args, expected_cd, prefer)
        local cd = assert(evmu.encode_calldata_hex(s, args))
        if cd ~= expected_cd then
            local i, rest_cd, rest_expected_cd = strdiff(cd, expected_cd)
            error(
                string.format("calldata differs starting at %d (expected '%s', got '%s')", i, rest_expected_cd, rest_cd)
            )
        end
        local decoded_args = assert(evmu.decode_calldata_hex(s, cd, prefer))
        local ret, err = subtab(args, decoded_args)
        if not ret then
            ptab(args)
            ptab(decoded_args)
            error(err)
        end
        check_decode_calldata_hex_error(s, cd .. "deadbeef", "calldata too long")
    end

    local function check_encode_calldata_hex_error(s, args, expected_err)
        local ret, err = pcall(evmu.encode_calldata_hex, s, args)
        assert(not ret, "expected error")
        assert(is_suffix(expected_err, err), string.format("expected suffix '%s' in '%s'", expected_err, tostring(err)))
    end

    local function check_encode_hex(s, expected_hex)
        local hex = assert(evmu.encode_hex(s))
        if hex ~= expected_hex then
            local i, rest_hex, rest_expected_hex = strdiff(hex, expected_hex)
            error(
                string.format(
                    "hex encoding differs starting at %d (expected '%s', got '%s')",
                    i,
                    rest_expected_hex,
                    rest_hex
                )
            )
        end
    end

    local function check_decode_hex(hex, expected_s)
        local s = assert(evmu.decode_hex(hex))
        if s ~= expected_s then
            local i, rest_s, rest_expected_s = strdiff(s, expected_s)
            error(
                string.format("hex decoding differs starting at %d (expected %q, got %q)", i, rest_expected_s, rest_s)
            )
        end
    end

    local function check_decode_hex_error(s, expected_err)
        local ret, err = evmu.decode_hex(s)
        assert(not ret, "expected error")
        assert(is_suffix(expected_err, err), string.format("expected suffix '%s' in '%s'", expected_err, tostring(err)))
    end

    -- luacheck: push ignore 631

    it("hex encoding and decoding", function()
        local all, all_hex = (function()
            local all = {}
            local all_hex = { "0x" }
            for i = 0, 255 do
                all[i + 1] = string.char(i)
                all_hex[i + 2] = string.format("%02x", i)
            end
            return table.concat(all), table.concat(all_hex)
        end)()
        check_encode_hex("", "0x")
        check_encode_hex("\x00", "0x00")
        check_encode_hex("\x00\x01", "0x0001")
        check_encode_hex("\x00\x01\x02", "0x000102")
        check_encode_hex("\x00\x01\x02\x03", "0x00010203")
        check_encode_hex(all, all_hex)
        check_decode_hex("0x", "")
        check_decode_hex("0X00", "\x00")
        check_decode_hex("0x0001", "\x00\x01")
        check_decode_hex("0X000102", "\x00\x01\x02")
        check_decode_hex("0x00010203", "\x00\x01\x02\x03")
        check_decode_hex(all_hex, all)
        check_decode_hex_error("", 'hex string must start with "0x"')
        check_decode_hex_error("0", 'hex string must start with "0x"')
        check_decode_hex_error("0x0", "hex string length must be even")
        check_decode_hex_error("0x0m", 'hex string cannot contain "0m"')
        check_decode_hex_error("0x000102 ", "hex string cannot contain whitespace")
        check_decode_hex_error("0x0001 02", "hex string cannot contain whitespace")
        check_decode_hex_error("0x00\t01", "hex string cannot contain whitespace")
    end)

    it("type spec parsing", function()
        -- check int types
        check_parse_type_spec("int", { type_name = "int", size = 256 })
        check_parse_type_spec("uint", { type_name = "uint", size = 256 })
        for w = 0, 264 do
            if w % 8 == 0 and w >= 8 and w <= 256 then
                check_parse_type_spec(string.format("int%d", w), { type_name = "int", size = w })
                check_parse_type_spec(string.format("uint%d", w), { type_name = "uint", size = w })
            else
                check_parse_type_spec_error(
                    string.format("int%d", w),
                    string.format('expected integer size at line 1, column 4 (got "%d")', w)
                )
                check_parse_type_spec_error(
                    string.format("uint%d", w),
                    string.format('expected integer size at line 1, column 5 (got "%d")', w)
                )
            end
        end
        -- check bytes types
        check_parse_type_spec("bytes", { type_name = "bytes" })
        check_parse_type_spec_error("bytes0", 'expected bytes size at line 1, column 6 (got "0")')
        check_parse_type_spec_error("bytes33", 'expected bytes size at line 1, column 6 (got "33")')
        for w = 1, 32 do
            check_parse_type_spec(string.format("bytes%d", w), { type_name = "bytes", size = w })
        end
        -- check other simple types
        check_parse_type_spec("address", { type_name = "address" })
        check_parse_type_spec("string", { type_name = "string" })
        check_parse_type_spec("bool", { type_name = "bool" })
        -- check array
        check_parse_type_spec("int[]", { type_name = "array", element_type = { type_name = "int", size = 256 } })
        check_parse_type_spec("string[2]", { type_name = "array", element_type = { type_name = "string" }, size = 2 })
        check_parse_type_spec("bytes16[2][]", {
            type_name = "array",
            element_type = {
                type_name = "array",
                element_type = {
                    type_name = "bytes",
                    size = 16,
                },
                size = 2,
            },
        })
        check_parse_type_spec("address[][2]", {
            type_name = "array",
            element_type = { type_name = "array", element_type = { type_name = "address" } },
            size = 2,
        })
        check_parse_type_spec_error("int[0]", 'expected closing bracket or array size at line 1, column 5 (got "0]")')
        check_parse_type_spec_error("int[-1]", 'expected closing bracket or array size at line 1, column 5 (got "-1]")')
        check_parse_type_spec_error("int[", 'expected closing bracket or array size at line 1, column 5 (got "")')
        check_parse_type_spec_error("int[10", 'expected closing bracket at line 1, column 7 (got "")')
        check_parse_type_spec_error("int[10][a", 'expected closing bracket or array size at line 1, column 9 (got "a")')
        -- check tuple
        check_parse_type_spec("()", { type_name = "tuple", components = {} })
        check_parse_type_spec("(int)", { type_name = "tuple", components = { { type_name = "int", size = 256 } } })
        check_parse_type_spec("(int,string)", {
            type_name = "tuple",
            components = {
                { type_name = "int", size = 256 },
                {
                    type_name = "string",
                },
            },
        })
        check_parse_type_spec_error("(,)", 'expected closing parenthesis at line 1, column 2 (got ",)")')
        check_parse_type_spec_error("(int,)", 'expected type spec at line 1, column 6 (got ")")')
        -- check nesting
        check_parse_type_spec("(int[])", {
            type_name = "tuple",
            components = { { type_name = "array", element_type = { size = 256, type_name = "int" } } },
        })
        check_parse_type_spec("(int[])[]", {
            type_name = "array",
            element_type = {
                type_name = "tuple",
                components = { { type_name = "array", element_type = { size = 256, type_name = "int" } } },
            },
        })
        check_parse_type_spec("((int[])[])", {
            type_name = "tuple",
            components = {
                {
                    type_name = "array",
                    element_type = {
                        type_name = "tuple",
                        components = { { type_name = "array", element_type = { size = 256, type_name = "int" } } },
                    },
                },
            },
        })
    end)

    it("function signature parsing", function()
        local function make_int(size, data_location, name)
            return { type_name = "int", size = size or 256, name = name, data_location = data_location }
        end
        local function make_uint(size, data_location, name)
            return { type_name = "uint", size = size or 256, name = name, data_location = data_location }
        end
        local function make_tuple(components, data_location, name)
            return { type_name = "tuple", components = components, name = name, data_location = data_location }
        end
        local empty_tuple = make_tuple({})
        local function make_address(data_location, name)
            return { type_name = "address", name = name, data_location = data_location }
        end
        local function make_bool(data_location, name)
            return { type_name = "bool", name = name, data_location = data_location }
        end

        check_parse_func_sig("_()", { name = "_", params = empty_tuple, returns = empty_tuple })
        check_parse_func_sig("_() returns ()", { name = "_", params = empty_tuple, returns = empty_tuple })
        check_parse_func_sig("function _() returns ()", { name = "_", params = empty_tuple, returns = empty_tuple })
        check_parse_func_sig("a()", { name = "a", params = empty_tuple, returns = empty_tuple })
        check_parse_func_sig("_a()", { name = "_a", params = empty_tuple, returns = empty_tuple })
        check_parse_func_sig("_a0()", { name = "_a0", params = empty_tuple, returns = empty_tuple })
        check_parse_func_sig("_a0a()", { name = "_a0a", params = empty_tuple, returns = empty_tuple })
        check_parse_func_sig("_(int)", { name = "_", params = make_tuple({ make_int() }), returns = empty_tuple })
        check_parse_func_sig("_(uint)", { name = "_", params = make_tuple({ make_uint() }), returns = empty_tuple })
        check_parse_func_sig(
            "_(int a)",
            { name = "_", params = make_tuple({ make_int(nil, nil, "a") }), returns = empty_tuple }
        )
        check_parse_func_sig(
            "_(int memory)",
            { name = "_", params = make_tuple({ make_int(nil, "memory") }), returns = empty_tuple }
        )
        check_parse_func_sig(
            "_(int storage)",
            { name = "_", params = make_tuple({ make_int(nil, "storage") }), returns = empty_tuple }
        )
        check_parse_func_sig(
            "_(int calldata)",
            { name = "_", params = make_tuple({ make_int(nil, "calldata") }), returns = empty_tuple }
        )
        check_parse_func_sig(
            "_(int memory a)",
            { name = "_", params = make_tuple({ make_int(nil, "memory", "a") }), returns = empty_tuple }
        )
        check_parse_func_sig(
            "_(int storage a)",
            { name = "_", params = make_tuple({ make_int(nil, "storage", "a") }), returns = empty_tuple }
        )
        check_parse_func_sig(
            "_(int calldata a)",
            { name = "_", params = make_tuple({ make_int(nil, "calldata", "a") }), returns = empty_tuple }
        )
        check_parse_func_sig(
            "_(int, address)",
            { name = "_", params = make_tuple({ make_int(), make_address() }), returns = empty_tuple }
        )
        check_parse_func_sig("_(int, address memory)", {
            name = "_",
            params = make_tuple({ make_int(), make_address("memory") }),
            returns = empty_tuple,
        })
        check_parse_func_sig(
            "_(int a, address)",
            { name = "_", params = make_tuple({ make_int(nil, nil, "a"), make_address() }), returns = empty_tuple }
        )
        check_parse_func_sig(
            "_(int, address a)",
            { name = "_", params = make_tuple({ make_int(), make_address(nil, "a") }), returns = empty_tuple }
        )
        check_parse_func_sig(
            "_() returns (address) ",
            { name = "_", params = empty_tuple, returns = make_tuple({ make_address() }) }
        )
        check_parse_func_sig(
            "_() returns (address a) ",
            { name = "_", params = empty_tuple, returns = make_tuple({ make_address(nil, "a") }) }
        )
        check_parse_func_sig(
            "_() returns (address memory a) ",
            { name = "_", params = empty_tuple, returns = make_tuple({ make_address("memory", "a") }) }
        )
        check_parse_func_sig(
            "_() returns (address, bool) ",
            { name = "_", params = empty_tuple, returns = make_tuple({ make_address(), make_bool() }) }
        )
        check_parse_func_sig_error("()", 'expected identifier at line 1, column 1 (got "()")')
        check_parse_func_sig_error("\n()", 'expected identifier at line 2, column 1 (got "()")')
        check_parse_func_sig_error("int", 'expected parameters at line 1, column 4 (got "")')
        check_parse_func_sig_error("_(", 'expected closing parenthesis at line 1, column 3 (got "")')
        check_parse_func_sig_error("_(int", 'expected closing parenthesis at line 1, column 6 (got "")')
        check_parse_func_sig_error("_(int, ", 'expected type spec at line 1, column 8 (got "")')
        check_parse_func_sig_error("_() returns ", 'expected return parameters at line 1, column 13 (got "")')
        check_parse_func_sig_error("_() returns (", 'expected closing parenthesis at line 1, column 14 (got "")')
        check_parse_func_sig_error("_() returns (int", 'expected closing parenthesis at line 1, column 17 (got "")')
        check_parse_func_sig_error("_() returns (int, ", 'expected type spec at line 1, column 19 (got "")')
    end)

    it("preserves parameter names beginning with data-location keywords", function()
        for _, location in ipairs({ "memory", "calldata", "storage" }) do
            for _, suffix in ipairs({ "Root", "_x", "1" }) do
                local name = location .. suffix
                local parsed = evmu.parse_type_spec("uint256 " .. name)
                assert(parsed.name == name and parsed.data_location == nil)
                parsed = evmu.parse_type_spec("bytes " .. location .. " " .. name)
                assert(parsed.name == name and parsed.data_location == location)
                parsed = evmu.parse_func_sig("f(uint256 " .. name .. ") returns (uint256 " .. name .. ")")
                assert(parsed.params.components[1].name == name)
                assert(parsed.params.components[1].data_location == nil)
                assert(parsed.returns.components[1].name == name)
                assert(parsed.returns.components[1].data_location == nil)
            end
        end
    end)

    it("encodes and decodes names beginning with data-location keywords", function()
        for _, name in ipairs({ "memoryIndex", "calldataHash", "storageRoot" }) do
            local types = "(uint256 " .. name .. ")"
            local values = { [name] = 7 }
            local data = evmu.encode_abi(types, values)
            assert(data == evmu.encode_abi("(uint256)", { 7 }))
            assert(evmu.decode_abi(types, data)[name] == evmu.bint(7))
            local calldata = evmu.encode_calldata("f" .. types, values)
            assert(calldata == evmu.encode_calldata("f(uint256)", { 7 }))
            assert(evmu.decode_calldata("f" .. types, calldata)[name] == evmu.bint(7))
        end
    end)

    it("keeps cached function signatures while callers retain the parsed table", function()
        local signature = "cache_keep(uint amount)"
        local parsed, selector, canonical = evmu.parse_func_sig(signature)
        collectgarbage("collect")
        collectgarbage("collect")
        local cached, cached_selector, cached_canonical = evmu.parse_func_sig(signature)
        assert(cached == parsed, "retained parsed signature was evicted")
        assert(cached_selector == selector and cached_canonical == canonical)
        assert(canonical == "cache_keep(uint256)")
    end)

    it("collects cached function signatures after callers release the parsed table", function()
        local signature = "cache_release(uint amount)"
        local observed = setmetatable({}, { __mode = "v" })
        local selector, canonical
        do
            local parsed
            parsed, selector, canonical = evmu.parse_func_sig(signature)
            observed[1] = parsed
        end
        collectgarbage("collect")
        collectgarbage("collect")
        assert(observed[1] == nil, "cache retained an unused parsed signature")
        local parsed, new_selector, new_canonical = evmu.parse_func_sig(signature)
        assert(parsed.name == "cache_release")
        assert(new_selector == selector and new_canonical == canonical)
    end)

    it("calldata encoding and decoding", function()
        -- check calldata encoding
        check_encode_decode_calldata_hex("_()", {}, "0xb7ba4583")
        check_encode_decode_calldata_hex(
            "_(int)",
            { 1 },
            "0x9e5758430000000000000000000000000000000000000000000000000000000000000001"
        )
        check_encode_decode_calldata_hex(
            "f(int)",
            { 1 },
            "0x1c008df90000000000000000000000000000000000000000000000000000000000000001"
        )
        check_encode_decode_calldata_hex(
            "f(int, uint)",
            { 1, 2 },
            "0x711a885400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"
        )
        check_encode_calldata_hex_error("f(int, uint)", { 1 }, "missing tuple component at index 2")
        check_encode_decode_calldata_hex(
            "g(int)",
            { "0x10000000000000000000000000" },
            "0x7877b8030000000000000000000000000000000000000010000000000000000000000000"
        )
        -- check overflows
        check_encode_decode_calldata_hex(
            "_(uint8)",
            { 0xff },
            "0x1bf62fa700000000000000000000000000000000000000000000000000000000000000ff"
        )
        check_encode_decode_calldata_hex(
            "_(int8)",
            { -128 },
            "0x6a2b4692ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80"
        )
        check_encode_calldata_hex_error("_(int8)", { 0xff }, "integer value does not fit in target type")
        check_encode_calldata_hex_error("_(int8)", { -129 }, "integer value does not fit in target type")
        check_encode_calldata_hex_error("_(uint8)", { 0x100 }, "integer value does not fit in target type")
        check_encode_calldata_hex_error("_(uint8)", { -1 }, "integer value does not fit in target type")
        check_encode_decode_calldata_hex(
            "_(uint16)",
            { 0xffff },
            "0x5c4b5213000000000000000000000000000000000000000000000000000000000000ffff"
        )
        check_encode_decode_calldata_hex(
            "_(int16)",
            { -32768 },
            "0x69ebd716ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000"
        )
        check_encode_calldata_hex_error("_(int16)", { 0xffff }, "integer value does not fit in target type")
        check_encode_calldata_hex_error("_(int16)", { -32769 }, "integer value does not fit in target type")
        check_encode_calldata_hex_error("_(uint16)", { 0x10000 }, "integer value does not fit in target type")
        check_encode_calldata_hex_error("_(uint16)", { -1 }, "integer value does not fit in target type")
        check_encode_decode_calldata_hex(
            "_(uint)",
            { "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" },
            "0xa29f3781ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )
        check_encode_calldata_hex_error(
            "_(int)",
            { "0x8000000000000000000000000000000000000000000000000000000000000000" },
            "integer value does not fit in target type"
        )
        check_encode_decode_calldata_hex(
            "_(int)",
            { "-0x8000000000000000000000000000000000000000000000000000000000000000" },
            "0x9e5758438000000000000000000000000000000000000000000000000000000000000000"
        )
        check_encode_calldata_hex_error("_(uint)", { -1 }, "integer value does not fit in target type")
        check_encode_calldata_hex_error(
            "_(uint)",
            { "0x10000000000000000000000000000000000000000000000000000000000000000" },
            "integer value does not fit in target type"
        )
        check_encode_decode_calldata_hex(
            "_(int)",
            { "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" },
            "0x9e5758437fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )
        -- check complex types
        check_encode_decode_calldata_hex(
            "_(int[1])",
            { { 1 } },
            "0xe80da2d00000000000000000000000000000000000000000000000000000000000000001"
        )
        check_encode_decode_calldata_hex(
            "_(int[2])",
            { { 1, 2 } },
            "0x2472621500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"
        )
        check_encode_decode_calldata_hex(
            "_(uint, int[1])",
            { 1, { 2 } },
            "0xb1c2ae4d00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"
        )
        check_encode_decode_calldata_hex(
            "_(uint, int[1], uint)",
            { 1, { 2 }, 3 },
            "0x1bc702b7000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003"
        )
        check_encode_decode_calldata_hex(
            "_(int[])",
            { {} },
            "0x8b546acb00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000"
        )
        check_encode_decode_calldata_hex(
            "_(int[])",
            { { 1 } },
            "0x8b546acb000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001"
        )
        check_encode_decode_calldata_hex(
            "_(int[])",
            { { 1, 2 } },
            "0x8b546acb0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"
        )
        check_encode_decode_calldata_hex(
            "_(uint, int[])",
            { 1, { 2 } },
            "0x2ae197ed0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"
        )
        check_encode_decode_calldata_hex(
            "_(uint, int[], uint)",
            { 1, { 2 }, 3 },
            "0xb9f5d30400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"
        )
        check_encode_decode_calldata_hex(
            "_(int[], uint[1])",
            { {}, { 1 } },
            "0x81d0480b000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"
        )
        check_encode_decode_calldata_hex(
            "_(int[], uint[1])",
            { { 1 }, { 2 } },
            "0x81d0480b0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001"
        )
        check_encode_decode_calldata_hex(
            "_(int[], uint[1])",
            { { 1, 2 }, { 3 } },
            "0x81d0480b00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"
        )
        check_encode_decode_calldata_hex(
            "_(int8[2], int[], uint[1])",
            { { 1, 2 }, {}, { 3 } },
            "0xf536915700000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000000"
        )
        check_encode_decode_calldata_hex(
            "_(int8[2], int[], uint[1])",
            { { 1, 2 }, { 3 }, { 4 } },
            "0xf5369157000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003"
        )
        check_encode_decode_calldata_hex(
            "_(int, int8[], int, int[], uint[1])",
            { 1, {}, 2, {}, { 3 } },
            "0x00dee871000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        )
        check_encode_decode_calldata_hex(
            "_(int, int8[], (int, int)[], uint[1])",
            { 1, { 2 }, { { 3, 4 }, { 5, 6 } }, { 7 } },
            "0xc7af7b760000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006"
        )
        check_encode_decode_calldata_hex(
            "_(int, (int8[], (int, int)[2])[], uint[1])",
            { 1, { { { 2, 3 }, { { 4, 5 }, { 6, 7 } } }, { {}, { { 8, 9 }, { 10, 11 } } } }, { 1 } },
            "0x18e7bd6500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000b0000000000000000000000000000000000000000000000000000000000000000"
        )
        -- check strings and bytes
        check_encode_decode_calldata_hex(
            "_(string)",
            { "" },
            "0x6aedeb1300000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000"
        )
        check_encode_decode_calldata_hex(
            "_(string)",
            { "hello world" },
            "0x6aedeb130000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000b68656c6c6f20776f726c64000000000000000000000000000000000000000000"
        )
        check_encode_decode_calldata_hex(
            "_(string)",
            { evmu.hex(evmu.encode_hex("hello world")) },
            "0x6aedeb130000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000b68656c6c6f20776f726c64000000000000000000000000000000000000000000",
            "hex"
        )
        check_encode_decode_calldata_hex(
            "_(bytes5)",
            { evmu.raw("hello") },
            "0x63fa429c68656c6c6f000000000000000000000000000000000000000000000000000000",
            "raw"
        )

        check_encode_decode_calldata_hex(
            "_(bytes)",
            { evmu.raw("hello") },
            "0x9366a78b0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000568656c6c6f000000000000000000000000000000000000000000000000000000",
            "raw"
        )

        check_encode_decode_calldata_hex(
            "_(bytes)",
            { evmu.encode_hex("hello") },
            "0x9366a78b0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000568656c6c6f000000000000000000000000000000000000000000000000000000"
        )

        check_encode_decode_calldata_hex(
            "_(bytes)",
            { "0x" },
            "0x9366a78b00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000"
        )

        check_encode_decode_calldata_hex(
            "_(string,bytes8)",
            { "hello world", "0x0102030405060708" },
            "0x6360493500000000000000000000000000000000000000000000000000000000000000400102030405060708000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b68656c6c6f20776f726c64000000000000000000000000000000000000000000"
        )
        check_encode_calldata_hex_error(
            "_(string,bytes8)",
            { "hello world", "0x01020304050607" },
            "bytes has wrong size (expected 8, got 7)"
        )
        check_encode_calldata_hex_error(
            "_(string,bytes8)",
            { "hello world", "0x010203040506070809" },
            "bytes has wrong size (expected 8, got 9)"
        )
        check_encode_decode_calldata_hex(
            "_(address)",
            { "0x491604c0fdf08347dd1fa4ee062a822a5dd06b5d" },
            "0xd4aa26ba000000000000000000000000491604c0fdf08347dd1fa4ee062a822a5dd06b5d"
        )
        check_encode_decode_calldata_hex(
            "_(address)",
            { evmu.raw(evmu.decode_hex("0x491604c0fdf08347dd1fa4ee062a822a5dd06b5d")) },
            "0xd4aa26ba000000000000000000000000491604c0fdf08347dd1fa4ee062a822a5dd06b5d",
            "raw"
        )
        check_encode_calldata_hex_error(
            "_(address)",
            { evmu.decode_hex("0x491604c0fdf08347dd1fa4ee062a822a5dd06b5d") },
            'hex string must start with "0x"'
        )
        check_encode_calldata_hex_error(
            "_(address)",
            { "0x491604c0fdf08347dd1fa4ee062a822a5dd06b" },
            "invalid address length (expected 20 bytes, got 19 bytes)"
        )
        check_encode_calldata_hex_error(
            "_(address)",
            { evmu.raw(evmu.decode_hex("0x491604c0fdf08347dd1fa4ee062a822a5dd06b")) },
            "invalid address length (expected 20 bytes, got 19 bytes)"
        )
        check_encode_calldata_hex_error(
            "_(address)",
            { evmu.decode_hex("0x491604c0fdf08347dd1fa4ee062a822a5dd06b") },
            'hex string must start with "0x"'
        )
        -- check bool
        check_encode_decode_calldata_hex(
            "_(bool)",
            { true },
            "0x099660c90000000000000000000000000000000000000000000000000000000000000001"
        )
        check_encode_decode_calldata_hex(
            "_(bool)",
            { false },
            "0x099660c90000000000000000000000000000000000000000000000000000000000000000"
        )
        check_encode_calldata_hex_error("_(bool)", { 0 }, "expected boolean (got number)")
        check_encode_calldata_hex_error("_(bool)", { 1 }, "expected boolean (got number)")
        check_encode_calldata_hex_error("_(bool)", { "true" }, "expected boolean (got string)")
        check_encode_calldata_hex_error("_(bool)", { "false" }, "expected boolean (got string)")

        -- check arg type errors
        check_encode_calldata_hex_error(1, nil, "expected function signature string")
        check_encode_calldata_hex_error({}, nil, "expected function signature string")
        check_encode_calldata_hex_error(nil, nil, "expected function signature string")

        check_encode_calldata_hex_error("_(int[])", nil, "expected arguments table")
        check_encode_calldata_hex_error("_(int)", {}, "missing tuple component at index 1")
        check_encode_calldata_hex_error("_(int[])", { 1 }, "array values not in table")
        check_encode_calldata_hex_error("_(int[])", { evmu.bint.new(1) }, "array values not in table")
        check_encode_calldata_hex_error("_(int[2])", { 1 }, "array values not in table")
        check_encode_calldata_hex_error("_(int[2])", { evmu.bint.new(1) }, "array values not in table")
        check_encode_calldata_hex_error("_((int,int))", { 1 }, "tuple values not in table")
        check_encode_calldata_hex_error("_((int,int))", { evmu.bint.new(1) }, "tuple values not in table")

        check_decode_calldata_hex_error(1, "0x", "expected function signature string")
        check_decode_calldata_hex_error({}, "0x", "expected function signature string")
        check_decode_calldata_hex_error(nil, "0x", "expected function signature string")

        check_decode_calldata_hex_error("_()", nil, "missing hex string")
        check_decode_calldata_hex_error("_()", "0x0", "hex string length must be even")
        check_decode_calldata_hex_error("_()", {}, "hex not a string")
        check_decode_calldata_hex_error(
            "_()",
            "0xb7ba45830000000000000000000000000000000000000000000000000000000000000001",
            "calldata too long"
        )

        check_encode_calldata_hex_error("_(address)", { 1 }, "expected hex-encoded string value")
        check_encode_calldata_hex_error("_(address)", { {} }, "expected hex-encoded string value")
        check_encode_calldata_hex_error("_(bytes)", { 1 }, "expected hex-encoded string value")
        check_encode_calldata_hex_error("_(bytes8)", { 1 }, "expected hex-encoded string value")
        check_encode_calldata_hex_error("_(bytes)", { {} }, "expected hex-encoded string value")

        check_encode_calldata_hex_error("_(string)", { 1 }, "expected raw string value")
        check_encode_calldata_hex_error("_(string)", { {} }, "expected raw string value")

        check_encode_calldata_hex_error("_(bool)", { 1 }, "expected boolean (got number)")
        check_encode_calldata_hex_error("_(bool)", { {} }, "expected boolean (got table)")

        check_encode_calldata_hex_error("_(int[3])", { { 1, 2 } }, "invalid value count (expected 3, got 2)")
        check_encode_calldata_hex_error("_(int[3])", { { 1, 2, 3, 4 } }, "invalid value count (expected 3, got 4)")

        check_encode_calldata_hex_error("_(int,int,int)", { 1, 2 }, "missing tuple component at index 3")
        check_encode_calldata_hex_error(
            "_(int,int,int a)",
            { 1, 2 },
            'missing tuple component at index 3 (or with name "a")'
        )

        check_encode_decode_calldata_hex(
            "_(int, int, int a)",
            { [1] = 1, [2] = 2, a = 3 },
            "0xacd77784000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003"
        )
        check_encode_decode_calldata_hex(
            "_(int, int a, int)",
            { [1] = 1, [3] = 3, a = 2 },
            "0xacd77784000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003"
        )
        check_encode_decode_calldata_hex(
            "_(int a, int, int)",
            { [2] = 2, [3] = 3, a = 1 },
            "0xacd77784000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003"
        )

        check_encode_calldata_hex_error("_(int,int,int)", { 1, 2, 3, 4 }, "unexpected tuple component at index 4")
        check_encode_calldata_hex_error(
            "_(int,int,int)",
            { 1, 2, 3, a = 4 },
            'unexpected tuple component with name "a"'
        )

        check_encode_calldata_hex_error("_((int,int,int))", { { 1, 2 } }, "missing tuple component at index 3")
        check_encode_calldata_hex_error("_((int,int,int))", { { 1, 2, 3, 4 } }, "unexpected tuple component at index 4")

        check_decode_calldata_hex_error(
            "_(bool)",
            "0x099660c9000000000000000000000000000000",
            "insufficient calldata for 256-bit word at offset 4"
        )
        check_decode_calldata_hex_error(
            "_(bool)",
            "0x099660c90000000000000000000000000000000000000000000000000000000000000003",
            "invalid bool value in calldata (must be 0 or 1)"
        )

        check_decode_calldata_hex_error(
            "_(uint8)",
            "0x1bf62fa7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", -- -1
            "integer value does not fit in target type"
        )

        check_decode_calldata_hex_error(
            "_(uint8)",
            "0x1bf62fa70000000000000000000000000000000000000000000000000000000000000100", -- 256
            "integer value does not fit in target type"
        )

        check_decode_calldata_hex_error(
            "_(int8)",
            "0x6a2b46920000000000000000000000000000000000000000000000000000000000000100", -- 256
            "integer value does not fit in target type"
        )

        check_decode_calldata_hex_error(
            "_(int8)",
            "0x6a2b4692ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", -- -129
            "integer value does not fit in target type"
        )

        check_decode_calldata_hex_error(
            "_(uint8)",
            "0x6a2b46920000000000000000000000000000000000000000000000000000000000000100",
            "function selector mismatch (expected 0x1bf62fa7, got 0x6a2b4692)"
        )

        check_decode_calldata_hex_error(
            "_(string)",
            "0x6aedeb130000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000b68656c6c6f20776f726c",
            "insufficient calldata for string of length 11"
        )

        check_decode_calldata_hex_error(
            "_(bytes)",
            "0x9366a78b000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000083031323334353637",
            "insufficient calldata for bytes of length 8"
        )

        check_decode_calldata_hex_error("_(bytes7)", "0x155cf58f", "insufficient calldata for bytes7")

        check_decode_calldata_hex_error("_(bytes7)", "0x155cf5", "calldata too short (missing function selector)")
    end)

    -- luacheck: pop
end)

describe("selectorless ABI", function()
    local evmu = require("cartesi.evmu")
    it("encodes nested event tuples and full-width coordinates", function()
        local coordinate = evmu.bint(1) << 91
        local types = "(uint256 cycle,(uint64 height,bytes payload) descriptor,bytes32[] siblings)"
        local values = { coordinate, { 62, "0x1234" }, { "0x" .. string.rep("ab", 32) } }
        local data = evmu.encode_abi(types, values)
        assert(data == evmu.encode_calldata("eventData" .. types, values):sub(5))
        local decoded = evmu.decode_abi(types, data)
        assert(decoded.cycle == coordinate)
        assert(decoded.descriptor.height == evmu.bint(62))
        assert(decoded.descriptor.payload == "0x1234")
        assert(decoded.siblings[1] == values[3][1])
        assert(evmu.decode_abi(types, data, "raw").descriptor.payload == "\x12\x34")
        assert(not pcall(evmu.decode_abi, types, data:sub(1, -2)))
        assert(not pcall(evmu.decode_abi, types, data .. string.rep("\0", 32)))
    end)
    it("handles an empty tuple and rejects a non-tuple type", function()
        assert(evmu.encode_abi("()", {}) == "")
        assert(#evmu.decode_abi("()", "") == 0)
        assert(not pcall(evmu.encode_abi, "uint256", {}))
        assert(not pcall(evmu.decode_abi, "bytes32", string.rep("\0", 32)))
        assert(not pcall(evmu.decode_abi, "()", string.rep("\0", 32)))
    end)
    it("decodes empty arrays of dynamic elements", function()
        local cases = {
            { "(bytes[])", { {} } },
            { "(string[])", { {} } },
            { "(uint256,string[])", { 1, {} } },
            { "((uint256,bytes)[])", { {} } },
            { "(bytes[],uint256)", { {}, 7 } },
            { "(bytes[][])", { { {} } } },
        }
        for _, case in ipairs(cases) do
            local types, values = case[1], case[2]
            local data = evmu.encode_abi(types, values)
            assert(evmu.encode_abi(types, evmu.decode_abi(types, data)) == data, types)
            assert(not pcall(evmu.decode_abi, types, data .. string.rep("\0", 32)), types)
        end
        for _, case in ipairs({ { "f(bytes[])", { {} } }, { "f(string[],uint256)", { {}, 7 } } }) do
            local signature, values = case[1], case[2]
            local calldata = evmu.encode_calldata(signature, values)
            assert(evmu.encode_calldata(signature, evmu.decode_calldata(signature, calldata)) == calldata, signature)
        end
    end)
    it("rejects ABI arrays with holes", function()
        local hash = "0x" .. string.rep("ab", 32)
        local cases = {
            { "(uint8[])", { { 1, nil, 3 } } },
            { "(uint8[])", { { [1] = 1, [3] = 3 } } },
            { "(uint8[])", { { [2] = 2 } } },
            { "(uint8[])", { { [1] = 1, [math.maxinteger] = 3 } } },
            { "(uint8[3],uint256)", { { 1, nil, 3 }, 42 } },
            { "(string[])", { { "a", nil, "c" } } },
            { "(bytes32[])", { { hash, nil, hash } } },
            { "(uint8[][])", { { { 1 }, { 2, nil, 4 } } } },
        }
        for _, case in ipairs(cases) do
            local types, values = case[1], case[2]
            local ok, err = pcall(evmu.encode_abi, types, values)
            assert(not ok and err:find("missing array element at index", 1, true), types)
            ok, err = pcall(evmu.encode_calldata, "f" .. types, values)
            assert(not ok and err:find("missing array element at index", 1, true), types)
        end
    end)
    it("rejects ABI array keys outside the sequence", function()
        for _, key in ipairs({ 0, -1, 1.5, "extra", false }) do
            local values = { 1, 2 }
            values[key] = 3
            local ok, err = pcall(evmu.encode_abi, "(uint8[])", { values })
            assert(not ok and err:find("invalid array index", 1, true), tostring(key))
        end
    end)
    it("encodes false array elements", function()
        local data = evmu.encode_abi("(bool[])", { { false, true, false } })
        local decoded = evmu.decode_abi("(bool[])", data)[1]
        assert(#decoded == 3 and decoded[1] == false and decoded[2] == true and decoded[3] == false)
    end)
    it("rejects overflowing ABI offsets and lengths", function()
        local function word(n)
            return string.rep("\0", 24) .. string.pack(">I8", n)
        end
        local tail = word(1) .. "x" .. string.rep("\0", 31)
        local cases = {
            { "(bytes,bytes)", word(0x7ffffffffffffff0) .. word(64) .. tail },
            { "(string,string)", word(0x7ffffffffffffff0) .. word(64) .. tail },
            { "(bytes,bytes)", word(64) .. word(96) .. word(math.maxinteger) .. tail },
            { "(string,string)", word(64) .. word(96) .. word(math.maxinteger) .. tail },
            { "(bytes[])", word(32) .. word(1) .. word(math.maxinteger) },
            { "(bytes[])", word(32) .. word(1 << 59) },
            { "(bytes[1])", word(32) .. word(math.maxinteger) },
            { "((bytes))", word(32) .. word(math.maxinteger) },
            { "(bytes[],bytes)", word(64) .. word(160) .. word(1) .. word(0x7fffffffffffffd0) .. word(0) .. tail },
            {
                "(address,uint256,bytes,bytes)",
                string.rep("\0", 12)
                    .. string.rep("\x11", 20)
                    .. word(5)
                    .. word(0x7fffffffffffffe0)
                    .. word(128)
                    .. word(0),
            },
        }
        for _, case in ipairs(cases) do
            local types, data = case[1], case[2]
            local ok, err = pcall(evmu.decode_abi, types, data)
            assert(not ok and err:find("insufficient calldata", 1, true), types)
            local signature = "f" .. types
            local _, selector = evmu.parse_func_sig(signature)
            ok, err = pcall(evmu.decode_calldata, signature, selector .. data)
            assert(not ok and err:find("insufficient calldata", 1, true), signature)
        end
    end)
    it("checks dynamic data padding at the input boundary", function()
        for _, types in ipairs({ "(bytes)", "(string)" }) do
            for _, size in ipairs({ 0, 1, 31, 32, 33 }) do
                local values = { evmu.raw(string.rep("x", size)) }
                local data = evmu.encode_abi(types, values)
                local decoded = evmu.decode_abi(types, data, "raw")
                assert(decoded[1] == string.rep("x", size))
                assert(not pcall(evmu.decode_abi, types, data:sub(1, -2)))
            end
        end
    end)
    it("decodes dynamic components whose data is out of order", function()
        local function word(n)
            return string.rep("\0", 24) .. string.pack(">I8", n)
        end
        local function padded(s)
            return s .. string.rep("\0", 32 - #s)
        end
        -- The second component's data comes before the first one's
        local data = word(0x80) .. word(0x40) .. word(2) .. padded("\2\3") .. word(1) .. padded("\1")
        local decoded = evmu.decode_abi("(bytes,bytes)", data, "raw")
        assert(decoded[1] == "\1" and decoded[2] == "\2\3")
    end)
end)

lester.report()
lester.exit()
