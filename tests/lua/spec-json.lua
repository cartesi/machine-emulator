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

describe("tojson / fromjson schema dictionary", function()
    local machine <close> = cartesi.machine({ ram = { length = 0x1000 } })
    local HASH = string.rep("\xa5", 32)

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
