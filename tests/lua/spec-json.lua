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
        -- the machine dictionary defines McycleRootHashes.break_reason as InterpreterBreakReason...
        expect.equal(
            cartesi.fromjson('{"break_reason":"halted"}', "McycleRootHashes").break_reason,
            cartesi.BREAK_REASON_HALTED
        )
        -- ...but a user McycleRootHashes can reinterpret the same field as a Base64 hash,
        -- while the nested "Base64" still resolves from the machine dictionary
        local SCHEMA = { McycleRootHashes = { break_reason = "Base64" } }
        local back = cartesi.fromjson(
            cartesi.tojson({ break_reason = HASH }, nil, "McycleRootHashes", SCHEMA),
            "McycleRootHashes",
            SCHEMA
        )
        expect.equal(back.break_reason, HASH)
        expect.equal(#back.break_reason, 32)
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
