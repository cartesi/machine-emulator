--[[
Test suite for cartesi.tojson / cartesi.fromjson schema dictionaries.
Specifically, it provides test coverage for:
    clua-i-machine.cpp (clua_tojson, clua_fromjson, clua_tojsonschemadict)
    clua-cartesi.cpp (cartesi.tojson, cartesi.fromjson)
]]

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local cartesi = require("cartesi")
local describe, it, expect = lester.describe, lester.it, lester.expect

describe("JSON floating-point numbers", function()
    it("should reject non-finite numbers as scalars and inside tables", function()
        for _, number in ipairs({ 0 / 0, math.huge, -math.huge }) do
            for _, value in ipairs({ number, { value = number }, { 1, number, 3 } }) do
                expect.fail(function()
                    cartesi.tojson(value)
                end, "cannot serialize a non-finite number to JSON")
            end
        end
    end)

    it("should preserve finite floating-point numbers", function()
        for _, number in ipairs({ 0.0, -0.0, 1.5, -1.5, 1e308, -1e308, 1e-308, -1e-308 }) do
            for _, value in ipairs({ number, { value = number }, { 1, number, 3 } }) do
                expect.equal(cartesi.fromjson(cartesi.tojson(value)), value)
            end
        end
    end)
end)

describe("JSON table keys", function()
    it("should accept dense arrays regardless of insertion order", function()
        local value = { [3] = "c", [1] = "a", [2] = false }
        expect.equal(cartesi.tojson(value), '["a",false,"c"]')
    end)

    it("should preserve string keys that look like array indices", function()
        expect.equal(cartesi.tojson({ ["1"] = "a", ["2"] = "b" }), '{"1":"a","2":"b"}')
    end)

    it("should reject mixed keys without modifying the table", function()
        local value = { [1] = "a", ["1"] = "b", name = "c" }
        expect.fail(function()
            cartesi.tojson(value)
        end, "table maps cannot contain keys of type number")
        expect.equal(value, { [1] = "a", ["1"] = "b", name = "c" })
        expect.equal(cartesi.tojson({ 42 }), "[42]")
    end)

    it("should reject invalid key types", function()
        for _, key in ipairs({ 0, -1, 1.5, true, {} }) do
            expect.fail(function()
                cartesi.tojson({ [key] = "value" })
            end, "table maps cannot contain keys of type")
        end
    end)

    it("should reject gaps without a schema", function()
        for _, value in ipairs({ { [2] = "b" }, { [1] = "a", [3] = "c" } }) do
            expect.fail(function()
                cartesi.tojson(value)
            end, "array keys must be consecutive integers starting at 1")
            expect.fail(function()
                cartesi.tojson({ values = value }, nil, "Record", { Record = { values = "Default" } })
            end, "array keys must be consecutive integers starting at 1")
        end
    end)

    it("should reject a huge sparse index before expanding the array", function()
        expect.fail(function()
            cartesi.tojson({ [math.maxinteger] = true })
        end, "array keys must be consecutive integers starting at 1")
    end)

    it("should preserve explicitly schematized empty arrays and gaps", function()
        local schemas = { Empty = { items = {} }, Array = { items = "Default" } }
        expect.equal(cartesi.tojson({}, nil, "Empty", schemas), "[]")
        expect.equal(cartesi.tojson({ [2] = "b" }, nil, "Array", schemas), '[null,"b"]')
    end)
end)

describe("JSON NUL bytes", function()
    it("should preserve distinct object keys containing NUL bytes", function()
        local value = { a = 1, ["a\0b"] = 2, ["\0"] = 3, ["a\0"] = 4 }
        local encoded = '{"\\u0000":3,"a":1,"a\\u0000":4,"a\\u0000b":2}'
        expect.equal(cartesi.tojson(value), encoded)
        expect.equal(cartesi.fromjson(encoded), value)
    end)

    it("should use complete object keys for schema lookup", function()
        local schema = { Record = { a = "Hex", ["a\0b"] = "Base64" } }
        local value = { a = "foo", ["a\0b"] = "bar", ["a\0c"] = "plain" }
        local encoded = '{"a":"0x666f6f","a\\u0000b":"YmFy","a\\u0000c":"plain"}'
        expect.equal(cartesi.tojson(value, nil, "Record", schema), encoded)
        expect.equal(cartesi.fromjson(encoded, "Record", schema), value)
    end)

    it("should reject raw NUL bytes anywhere in JSON input", function()
        for _, input in ipairs({ "{}\0", "{}\0garbage", "\0{}", '{"a":"x\0y"}', "[1,\0 2]" }) do
            expect.fail(function()
                cartesi.fromjson(input)
            end, "unexpected NUL byte")
        end
        expect.equal(cartesi.fromjson('"a\\u0000b"'), "a\0b")
        expect.equal(cartesi.tojson("a\0b"), '"a\\u0000b"')
    end)
end)

describe("JSON nesting", function()
    for _, kind in ipairs({ "arrays", "objects" }) do
        local opening = kind == "arrays" and "[" or '{"child":'
        local closing = kind == "arrays" and "]" or "}"
        local function nested_table(depth)
            local value = 42
            for _ = 1, depth do
                value = kind == "arrays" and { value } or { child = value }
            end
            return value
        end
        local function nested_json(depth)
            return string.rep(opening, depth) .. "42" .. string.rep(closing, depth)
        end

        it("should roundtrip nested " .. kind .. " at the depth limit", function()
            local encoded = nested_json(256)
            expect.equal(cartesi.tojson(nested_table(256)), encoded)
            local decoded = cartesi.fromjson(encoded)
            for _ = 1, 256 do
                expect.equal(type(decoded), "table")
                decoded = kind == "arrays" and decoded[1] or decoded.child
            end
            expect.equal(decoded, 42)
        end)

        it("should reject Lua " .. kind .. " beyond the nesting limit", function()
            expect.fail(function()
                cartesi.tojson(nested_table(257))
            end, "nesting depth")
            expect.equal(cartesi.tojson({ 42 }), "[42]")
        end)

        it("should reject JSON " .. kind .. " beyond the nesting limit", function()
            for _, depth in ipairs({ 257, 200000 }) do
                expect.fail(function()
                    cartesi.fromjson(nested_json(depth))
                end, "nesting depth")
            end
            expect.equal(cartesi.fromjson("[42]"), { 42 })
        end)
    end

    it("should reject cyclic Lua tables", function()
        local value = {}
        value.child = value
        expect.fail(function()
            cartesi.tojson(value)
        end, "nesting depth")
        expect.equal(cartesi.fromjson(cartesi.tojson({ 42 })), { 42 })
    end)

    it("should reject cyclic schema dictionaries in both directions", function()
        local schema = {}
        schema.Node = schema
        expect.fail(function()
            cartesi.tojson({}, nil, "Node", schema)
        end, "nesting depth")
        expect.fail(function()
            cartesi.fromjson("{}", "Node", schema)
        end, "nesting depth")
    end)
end)

describe("tojson / fromjson schema dictionary", function()
    local machine <close> = cartesi.machine({ ram = { length = 0x1000 } })
    local HASH = string.rep("\xa5", 32)
    local BINARY = "\0\x01\xfe\xff"

    it("should roundtrip a plain table with no schema", function()
        local t = { a = 1, b = "x", c = true, d = { 1, 2, 3 } }
        expect.equal(cartesi.fromjson(cartesi.tojson(t)), t)
    end)

    it("should serialize bare scalars with no schema", function()
        expect.equal(cartesi.tojson(42), "42")
        expect.equal(cartesi.tojson("str"), '"str"')
        expect.equal(cartesi.fromjson(cartesi.tojson(42)), 42)
        expect.equal(cartesi.fromjson(cartesi.tojson("str")), "str")
    end)

    it("should use object schemas for empty tables", function()
        local schemas = { Record = { label = "Default" }, EmptyRecord = {}, Alias = "EmptyRecord" }
        for _, name in ipairs({ "Record", "EmptyRecord", "Alias", "Proof" }) do
            expect.equal(cartesi.tojson({}, nil, name, schemas), "{}")
            expect.equal(cartesi.tojson(cartesi.fromjson("{}", name, schemas), nil, name, schemas), "{}")
        end
    end)

    it("should distinguish empty arrays, tuples, and objects in nested schemas", function()
        local schemas = {
            Envelope = { array = "Array", tuple = "Tuple", record = "Record" },
            Array = { items = "Record" },
            Tuple = { items = {} },
            Record = {},
        }
        local value = { array = {}, tuple = {}, record = {} }
        local encoded = '{"array":[],"record":{},"tuple":[]}'
        expect.equal(cartesi.tojson(value, nil, "Envelope", schemas), encoded)
        expect.equal(cartesi.fromjson(encoded, "Envelope", schemas), value)
        expect.equal(cartesi.tojson({ {}, {} }, nil, "Array", schemas), "[{},{}]")
        expect.equal(schemas.Record, {})
        expect.equal(schemas.Tuple, { items = {} })
    end)

    it("should reject empty tables without a container schema", function()
        expect.fail(function()
            cartesi.tojson({})
        end, "empty table requires an array or object schema")
        for _, name in ipairs({ "Default", "Base64", "Hex", "ArrayIndex", "Alias" }) do
            expect.fail(function()
                cartesi.tojson({}, nil, name, { Alias = "Default" })
            end, "empty table requires an array or object schema")
        end
        expect.equal(cartesi.tojson({ 42 }), "[42]")
    end)

    it("should reject nested empty tables without their own container schema", function()
        local schemas = { Record = { value = "Default" }, Array = { items = "Default" } }
        for _, name in ipairs({ "Default", "Record" }) do
            expect.fail(function()
                cartesi.tojson({ value = {} }, nil, name, schemas)
            end, "empty table requires an array or object schema")
            expect.fail(function()
                cartesi.tojson({ other = {} }, nil, name, schemas)
            end, "empty table requires an array or object schema")
        end
        expect.fail(function()
            cartesi.tojson({ {} }, nil, "Array", schemas)
        end, "empty table requires an array or object schema")
    end)

    it("should accept empty schema dictionaries in both directions", function()
        expect.equal(cartesi.tojson({ 42 }, nil, "Default", {}), "[42]")
        expect.equal(cartesi.fromjson("[42]", "Default", {}), { 42 })
    end)

    it("should reject non-string keys in schema dictionaries and definitions", function()
        for _, key in ipairs({ 1, true, {} }) do
            for _, schemas in ipairs({ { [key] = {} }, { Record = { [key] = "Default" } } }) do
                expect.fail(function()
                    cartesi.tojson(42, nil, "Default", schemas)
                end, "must be strings")
                expect.fail(function()
                    cartesi.fromjson("42", "Default", schemas)
                end, "must be strings")
            end
        end
    end)

    it("should preserve empty containers in access logs", function()
        local encoded = '{"accesses":[],"brackets":[],"log_type":{},"notes":[]}'
        local log = { accesses = {}, brackets = {}, log_type = {}, notes = {} }
        expect.equal(cartesi.tojson(log, nil, "AccessLog"), encoded)
        expect.equal(cartesi.fromjson(encoded, "AccessLog"), log)
    end)

    it("should preserve empty containers in machine configurations", function()
        local configurations = {
            '{"cmio":{},"dtb":{},"flash_drive":[],"hash_tree":{},"nvram":[],"pmas":{},'
                .. '"processor":{},"ram":{},"uarch":{},"virtio":[]}',
            '{"cmio":{"rx_buffer":{"backing_store":{}},"tx_buffer":{"backing_store":{}}},'
                .. '"dtb":{"backing_store":{}},"flash_drive":[{"backing_store":{}}],'
                .. '"nvram":[{"backing_store":{}}],"pmas":{"backing_store":{}},'
                .. '"processor":{"backing_store":{},"registers":{"clint":{},"htif":{},"iflags":{},"plic":{}}},'
                .. '"ram":{"backing_store":{}},"uarch":{"processor":{"backing_store":{},"registers":{}},'
                .. '"ram":{"backing_store":{}}},"virtio":[{"hostfwd":[],"type":"net-user"}]}',
            '{"cmio":{"rx_buffer":{},"tx_buffer":{}},"flash_drive":[{}],"nvram":[{}],'
                .. '"processor":{"registers":{}},"uarch":{"processor":{},"ram":{}},'
                .. '"virtio":[{"hostfwd":[{}],"type":"net-user"}]}',
        }
        for _, encoded in ipairs(configurations) do
            expect.equal(cartesi.tojson(cartesi.fromjson(encoded), nil, "MachineConfig"), encoded)
        end
        expect.equal(cartesi.tojson({}, nil, "MachineConfig"), "{}")
    end)

    it("should preserve empty containers in runtime and memory range configurations", function()
        expect.equal(cartesi.tojson({}, nil, "MachineRuntimeConfig"), "{}")
        expect.equal(
            cartesi.tojson({ console = {}, concurrency = {} }, nil, "MachineRuntimeConfig"),
            '{"concurrency":{},"console":{}}'
        )
        expect.equal(
            cartesi.tojson({ label = "data", backing_store = {} }, nil, "MemoryRangeConfig"),
            '{"backing_store":{},"label":"data"}'
        )
    end)

    it("should roundtrip machine configurations without changing state or runtime settings", function()
        local config = machine:get_initial_config()
        local encoded = cartesi.tojson(config, nil, "MachineConfig")
        local decoded = cartesi.fromjson(encoded, "MachineConfig")
        expect.equal(decoded, config)
        local copy <close> = cartesi.machine(decoded, { console = {}, concurrency = {} })
        expect.equal(copy:get_root_hash(), machine:get_root_hash())
        local runtime = copy:get_runtime_config()
        copy:set_runtime_config(
            cartesi.fromjson(cartesi.tojson(runtime, nil, "MachineRuntimeConfig"), "MachineRuntimeConfig")
        )
        expect.equal(copy:get_runtime_config(), runtime)
        copy:set_runtime_config({})
        expect.equal(copy:get_runtime_config(), runtime)
    end)

    it("should honor the indent argument", function()
        expect.truthy(cartesi.tojson({ a = 1 }, 2):find("\n", 1, true))
    end)

    it("should serialize a bare hash under the Base64 schema", function()
        local j = cartesi.tojson(HASH, nil, "Base64")
        -- in JSON the hash rides as base64 text (44 chars for 32 bytes), not raw binary
        expect.equal(#cartesi.fromjson(j), 44)
        -- with the schema it decodes back to the original 32 binary bytes
        expect.equal(cartesi.fromjson(j, "Base64"), HASH)
    end)

    it("should encode and decode canonical Base64", function()
        local vectors = {
            { "", "" },
            { "f", "Zg==" },
            { "fo", "Zm8=" },
            { "foo", "Zm9v" },
            { "foob", "Zm9vYg==" },
            { "fooba", "Zm9vYmE=" },
            { "foobar", "Zm9vYmFy" },
        }
        for _, vector in ipairs(vectors) do
            expect.equal(cartesi.tobase64(vector[1]), vector[2])
            expect.equal(cartesi.frombase64(vector[2]), vector[1])
        end

        local all = {}
        for i = 0, 255 do
            all[#all + 1] = string.char(i)
        end
        local all_bytes = table.concat(all)
        expect.equal(cartesi.frombase64(cartesi.tobase64(all_bytes)), all_bytes)
        expect.equal(cartesi.frombase64(" \tZm9v\r\nYmFy\v\f"), "foobar")
    end)

    it("should reject malformed Base64", function()
        for _, base64 in ipairs({
            "A",
            "AAA",
            "====",
            "=AAA",
            "A===",
            "AA=A",
            "AA==AA==",
            "Zm=8",
            "AB==",
            "AAB=",
            "Zm9v!",
        }) do
            expect.fail(function()
                cartesi.frombase64(base64)
            end, "base64")
            expect.fail(function()
                cartesi.fromjson(cartesi.tojson(base64), "Base64")
            end, "base64")
        end
    end)

    it("should encode and decode 0x-prefixed hexadecimal", function()
        expect.equal(cartesi.tohex(BINARY), "0x0001feff")
        expect.equal(cartesi.fromhex("0x0001feff"), BINARY)
        expect.equal(cartesi.fromhex("0X0001FEFF"), BINARY)
        expect.equal(cartesi.tohex(""), "0x")
        expect.equal(cartesi.fromhex("0x"), "")

        local all = {}
        local all_hex = { "0x" }
        for i = 0, 255 do
            all[#all + 1] = string.char(i)
            all_hex[#all_hex + 1] = string.format("%02x", i)
        end
        local all_bytes = table.concat(all)
        local all_encoded = table.concat(all_hex)
        expect.equal(cartesi.tohex(all_bytes), all_encoded)
        expect.equal(cartesi.fromhex(all_encoded), all_bytes)
    end)

    it("should serialize a bare string under the Hex schema", function()
        local j = cartesi.tojson(BINARY, nil, "Hex")
        expect.equal(j, '"0x0001feff"')
        expect.equal(cartesi.fromjson(j, "Hex"), BINARY)
        expect.equal(cartesi.fromjson('"0X0001FEFF"', "Hex"), BINARY)
    end)

    it("should reject malformed hexadecimal", function()
        for _, hex in ipairs({ "", "0001", "0y0001", "0x0", "0x00xz", "0x00 01" }) do
            expect.fail(function()
                cartesi.fromhex(hex)
            end, "hex")
            expect.fail(function()
                cartesi.fromjson(cartesi.tojson(hex), "Hex")
            end, "hex")
        end
    end)

    it("should apply Hex and Base64 fields from a user schema", function()
        local SCHEMA = { Msg = { hex = "Hex", base64 = "Base64" } }
        local msg = { hex = BINARY, base64 = BINARY, label = "hi" }
        local j = cartesi.tojson(msg, nil, "Msg", SCHEMA)
        local plain = cartesi.fromjson(j)
        expect.equal(plain.hex, "0x0001feff")
        expect.equal(plain.base64, "AAH+/w==")
        expect.equal(cartesi.fromjson(j, "Msg", SCHEMA), msg)
    end)

    it("should apply user schema types Base64 and ArrayIndex", function()
        local SCHEMA = { Msg = { hash = "Base64", n = "ArrayIndex" } }
        local msg = { hash = HASH, n = 5, label = "hi" }
        local j = cartesi.tojson(msg, nil, "Msg", SCHEMA)
        -- ArrayIndex is stored 0-based in JSON, hash rides as base64 text
        expect.equal(cartesi.fromjson(j).n, 4)
        expect.equal(#cartesi.fromjson(j).hash, 44)
        -- with the schema, the hash is binary again and the index is 1-based again
        local back = cartesi.fromjson(j, "Msg", SCHEMA)
        expect.equal(back, { hash = HASH, n = 5, label = "hi" })
    end)

    it("should convert ArrayIndex values at the integer boundaries", function()
        for _, value in ipairs({ math.mininteger + 1, 0, 1, math.maxinteger }) do
            local encoded = tostring(value - 1)
            expect.equal(cartesi.tojson(value, nil, "ArrayIndex"), encoded)
            expect.equal(cartesi.fromjson(encoded, "ArrayIndex"), value)
        end
    end)

    it("should reject ArrayIndex conversion overflow", function()
        for _, encoded in ipairs({ "9223372036854775807", "9223372036854775808", "18446744073709551615" }) do
            expect.fail(function()
                cartesi.fromjson(encoded, "ArrayIndex")
            end, "ArrayIndex out of range")
        end
        expect.fail(function()
            cartesi.tojson(math.mininteger, nil, "ArrayIndex")
        end, "ArrayIndex out of range")
        expect.equal(cartesi.fromjson("9223372036854775807"), math.maxinteger)
        expect.equal(cartesi.tojson(math.mininteger), "-9223372036854775808")
    end)

    it("should apply a different schema to each tuple item", function()
        local SCHEMA = { Tuple = { items = { "Base64", "ArrayIndex", "Default", "Hex" } } }
        local tuple = { HASH, 5, true, BINARY }
        local j = cartesi.tojson(tuple, nil, "Tuple", SCHEMA)
        expect.equal(cartesi.fromjson(j), { cartesi.tobase64(HASH), 4, true, "0x0001feff" })
        expect.equal(cartesi.fromjson(j, "Tuple", SCHEMA), tuple)
    end)

    it("should reject a tuple of the wrong length", function()
        local SCHEMA = { Pair = { items = { "Base64", "Default" } } }
        expect.fail(function()
            cartesi.tojson({ HASH }, nil, "Pair", SCHEMA)
        end, "tuple schema")
        expect.fail(function()
            cartesi.fromjson('["a", 1, 2]', "Pair", SCHEMA)
        end, "tuple schema")
    end)

    it("should preserve strings matching object, array, and tuple schema keys", function()
        local schemas = {
            Tuple = { items = { "Base64", "ArrayIndex" } },
            Envelope = { proof = "Proof", array = "Base64Array", tuple = "Tuple" },
        }
        for _, case in ipairs({ { "Proof", "target_hash" }, { "Base64Array", "items" }, { "Tuple", "items" } }) do
            local encoded = cartesi.tojson(case[2], nil, case[1], schemas)
            expect.equal(cartesi.fromjson(encoded, case[1], schemas), case[2])
        end
        local value = { proof = "target_hash", array = "items", tuple = "items" }
        local encoded = cartesi.tojson(value, nil, "Envelope", schemas)
        expect.equal(cartesi.fromjson(encoded, "Envelope", schemas), value)
    end)

    it("should still decode built-in integer enums", function()
        expect.equal(cartesi.fromjson('"halted"', "InterpreterBreakReason"), cartesi.BREAK_REASON_HALTED)
        expect.equal(cartesi.fromjson('"failed"', "InterpreterBreakReason"), cartesi.BREAK_REASON_FAILED)
        expect.equal(cartesi.fromjson('"unknown"', "InterpreterBreakReason"), "unknown")
    end)

    it("should still decode user-defined integer enums and aliases", function()
        local schemas = {
            Status = { failed = -1, pending = 0, done = 1 },
            Alias = "Status",
            Envelope = { status = "Alias" },
        }
        for name, value in pairs(schemas.Status) do
            expect.equal(cartesi.fromjson(cartesi.tojson(name), "Status", schemas), value)
            local encoded = cartesi.tojson({ status = name })
            expect.equal(cartesi.fromjson(encoded, "Envelope", schemas), { status = value })
        end
    end)

    it("should roundtrip a Proof through the machine schema dictionary", function()
        local proof = machine:get_proof(0, 12)
        expect.equal(#proof.root_hash, 32)
        expect.equal(cartesi.fromjson(cartesi.tojson(proof, nil, "Proof"), "Proof"), proof)
    end)

    it("should resolve machine types referenced from a user type", function()
        local proof = machine:get_proof(0, 12)
        local SCHEMA = { Envelope = { final_hash = "Base64", proof = "Proof" } }
        local env = { final_hash = HASH, proof = proof, who = "referee" }
        local back = cartesi.fromjson(cartesi.tojson(env, nil, "Envelope", SCHEMA), "Envelope", SCHEMA)
        expect.equal(back, env)
    end)

    it("should follow a user type that aliases a compound machine type", function()
        local proof = machine:get_proof(0, 12)
        -- a bare top-level alias resolves to its target's schema, not just to a leaf like
        -- Base64; here it reaches the compound Proof object so the hashes still ride as base64
        local SCHEMA = { ProofAlias = "Proof" }
        expect.equal(cartesi.fromjson(cartesi.tojson(proof, nil, "ProofAlias", SCHEMA), "ProofAlias", SCHEMA), proof)
        -- and a multi-hop alias chain resolves the same way
        local CHAIN = { A = "B", B = "Proof" }
        expect.equal(cartesi.fromjson(cartesi.tojson(proof, nil, "A", CHAIN), "A", CHAIN), proof)
    end)

    it("should leave a Default field as a plain table", function()
        -- a field typed "Default" carries no schema, so it rides as a plain nested table while a
        -- sibling Base64 field is still translated
        local SCHEMA = { Msg = { hash = "Base64", meta = "Default" } }
        local msg = { hash = HASH, meta = { a = 1, b = "x", c = { 2, 3 } } }
        expect.equal(cartesi.fromjson(cartesi.tojson(msg, nil, "Msg", SCHEMA), "Msg", SCHEMA), msg)
    end)

    it("should let user types override machine types of the same name", function()
        -- the machine dictionary defines Bracket.where as ArrayIndex (0-based in JSON)...
        expect.equal(cartesi.fromjson(cartesi.tojson({ where = 5 }, nil, "Bracket")).where, 4)
        -- ...but a user Bracket can reinterpret the same field as a Base64 hash,
        -- while the nested "Base64" still resolves from the machine dictionary
        local SCHEMA = { Bracket = { where = "Base64" } }
        local back = cartesi.fromjson(cartesi.tojson({ where = HASH }, nil, "Bracket", SCHEMA), "Bracket", SCHEMA)
        expect.equal(back.where, HASH)
        expect.equal(#back.where, 32)
    end)

    it("should error on an unknown schema name", function()
        expect.fail(function()
            cartesi.tojson({}, nil, "NoSuchType")
        end, "NoSuchType")
        expect.fail(function()
            cartesi.fromjson("{}", "NoSuchType")
        end, "NoSuchType")
    end)
end)

lester.report()
lester.exit()
