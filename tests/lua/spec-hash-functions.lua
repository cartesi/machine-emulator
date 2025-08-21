--[[
Test suite for hash functions (SHA-256 and Keccak-256).
Specifically, it provides test coverage for:
    sha-256-hasher.cpp
    keccak-256-hasher.cpp
Can be run independently during development the mentioned files.
]]

local lester = require("cartesi.third-party.lester")
local util = require("cartesi.tests.util")
local describe, it, expect = lester.describe, lester.it, lester.expect

describe("hash function", function()
    describe("keccak256", function()
        local keccak256 = require("cartesi").keccak256
        local function hexkeccak256(...)
            return util.tohex(keccak256(...)):lower()
        end

        it("should fail when passing invalid arguments", function()
            expect.fail(function()
                keccak256("a", "b", "c")
            end, "too many arguments")
            expect.fail(function()
                keccak256(1, 2)
            end, "only supported for inputs with size of hash")
            expect.fail(function()
                keccak256()
            end, "too few arguments")
        end)

        it("should match hashes", function()
            expect.equal(hexkeccak256(""), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
            expect.equal(hexkeccak256("0"), "044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d")
            expect.equal(hexkeccak256("test"), "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658")
            expect.equal(
                hexkeccak256(hexkeccak256("")),
                "79482f93ea0d714e293366322922962af38ecdd95cff648355c1af4b40a78b32"
            )
        end)

        it("should match concat hashes", function()
            expect.equal(
                hexkeccak256(string.rep("\x00", 32), string.rep("\x00", 32)),
                hexkeccak256(string.rep("\x00", 64))
            )
            expect.equal(
                hexkeccak256(string.rep("a", 32), string.rep("b", 32)),
                hexkeccak256(string.rep("a", 32) .. string.rep("b", 32))
            )
        end)

        it("should match with special lengths", function()
            local KECCAK_RSIZE = 136
            -- The data lengths are chosen to cover special cases of the KECCAK-256 algorithm
            for data, expected_hash in pairs({
                -- luacheck: push no max line length
                [string.rep("a", 0)] = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                [string.rep("a", 1)] = "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb",
                [string.rep("a", 2)] = "dfa57c542fea29ed292cef0ce135d0e22189365fa59abedc7a310b751ace684f",
                [string.rep("a", 4)] = "a80470dba00d5faf620fd6c51a1ca94668e13cd66fffaee3702f5497a8549053",
                [string.rep("a", 8)] = "a6eb2a81043a7349b2d066b3433ceadd8dd290343e6c41a4e36e82261e0b25cb",
                [string.rep("a", 16)] = "05bf23668a24407fc90dc33375cdeb2c8aef9db64ba12353dbc7e8d103dfba00",
                [string.rep("a", 32)] = "47a01324181e85459310f8fb9b24dc09744323ebdcef26cbf98959effdc76e02",
                [string.rep("a", 64)] = "1036d73cc8350b0635393d79759b10488165e792073f84d4462e22edec243b92",
                [string.rep("a", 128)] = "81555b8e18b3c117311c16373b1aa78c0a84aad7b8f7f4c753d0021fd9a6700e",
                [string.rep("a", KECCAK_RSIZE - 1)] = "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446",
                [string.rep("a", KECCAK_RSIZE / 2)] = "e4b16954d021544d168b5ea23de13c97c762d1f331fe4c7470df3c1000a62fdb",
                [string.rep("a", KECCAK_RSIZE)] = "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e",
                [string.rep("a", KECCAK_RSIZE + 1)] = "d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39",
                [string.rep("a", KECCAK_RSIZE + (KECCAK_RSIZE / 2))] = "5f6404fdb4057bbd7bce17d97cc655fca0c1c4129a083d323d79136f768ae757",
                [string.rep("a", (KECCAK_RSIZE * 2) - 1)] = "132f47effd6c8b1b299efa53fe68aece77ec8ae4eb2e294f668eec94f76001e1",
                [string.rep("a", KECCAK_RSIZE * 2)] = "cf7fcd4f705ee749930d19ca84561a9bf62516bd90a471545fa2f49fdc7e63c8",
                [string.rep("a", (KECCAK_RSIZE * 2) + 1)] = "5a7b8187d2778e614097fac3097573de1fee4d972304d3360796a857029bb176",
                -- luacheck: pop
            }) do
                expect.equal(hexkeccak256(data), expected_hash)
            end
        end)
    end)

    describe("sha256", function()
        local sha256 = require("cartesi").sha256
        local function hexsha256(...)
            return util.tohex(sha256(...)):lower()
        end

        it("should fail when passing invalid arguments", function()
            expect.fail(function()
                sha256("a", "b", "c")
            end, "too many arguments")
            expect.fail(function()
                sha256(1, 2)
            end, "only supported for inputs with size of hash")
            expect.fail(function()
                sha256()
            end, "too few arguments")
        end)

        it("should match hashes", function()
            expect.equal(hexsha256(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            expect.equal(hexsha256("0"), "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9")
            expect.equal(hexsha256("test"), "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
            expect.equal(hexsha256(hexsha256("")), "cd372fb85148700fa88095e3492d3f9f5beb43e555e5ff26d95f5a6adc36f8e6")
        end)

        it("should match concat hashes", function()
            expect.equal(hexsha256(string.rep("\x00", 32), string.rep("\x00", 32)), hexsha256(string.rep("\x00", 64)))
            expect.equal(
                hexsha256(string.rep("a", 32), string.rep("b", 32)),
                hexsha256(string.rep("a", 32) .. string.rep("b", 32))
            )
        end)

        it("should match hashes with special lengths", function()
            local SHA256_LEN_POS = 56
            local SHA256_BUF_SIZE = 64
            -- The data lengths are chosen to cover special cases of the SHA-256 algorithm
            for data, expected_hash in pairs({
                -- luacheck: push no max line length
                [string.rep("a", 0)] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                [string.rep("a", 1)] = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
                [string.rep("a", 2)] = "961b6dd3ede3cb8ecbaacbd68de040cd78eb2ed5889130cceb4c49268ea4d506",
                [string.rep("a", 4)] = "61be55a8e2f6b4e172338bddf184d6dbee29c98853e0a0485ecee7f27b9af0b4",
                [string.rep("a", 8)] = "1f3ce40415a2081fa3eee75fc39fff8e56c22270d1a978a7249b592dcebd20b4",
                [string.rep("a", 16)] = "0c0beacef8877bbf2416eb00f2b5dc96354e26dd1df5517320459b1236860f8c",
                [string.rep("a", 32)] = "3ba3f5f43b92602683c19aee62a20342b084dd5971ddd33808d81a328879a547",
                [string.rep("a", 64)] = "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
                [string.rep("a", 128)] = "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e",
                [string.rep("a", SHA256_LEN_POS - 1)] = "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
                [string.rep("a", SHA256_LEN_POS / 2)] = "9c547cb8115a44883b9f70ba68f75117cd55359c92611875e386f8af98c172ab",
                [string.rep("a", SHA256_LEN_POS)] = "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
                [string.rep("a", SHA256_LEN_POS + 1)] = "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6",
                [string.rep("a", SHA256_LEN_POS + (SHA256_LEN_POS // 2))] = "f5475022feb69870295b9c1e78c5a4919374061d5345167815801879f931ebb0",
                [string.rep("a", (SHA256_LEN_POS * 2) - 1)] = "6374f73208854473827f6f6a3f43b1f53eaa3b82c21c1a6d69a2110b2a79baad",
                [string.rep("a", SHA256_LEN_POS * 2)] = "f54353008a2553262ecdc4a34749563ba0950e8b0fc8652780b0a614b99683c1",
                [string.rep("a", (SHA256_LEN_POS * 2) + 1)] = "ba02731ae695aae5cd49b49d84330b63995733eb22102aca755f0179b1e0e20f",
                [string.rep("a", SHA256_BUF_SIZE - 1)] = "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
                [string.rep("a", SHA256_BUF_SIZE + 1)] = "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
                [string.rep("a", SHA256_BUF_SIZE + (SHA256_BUF_SIZE // 2))] = "ee4caa5518a866f33e174d6e71ba3961a86ca00a7486b132e5a9f01bfaa1d794",
                [string.rep("a", (SHA256_BUF_SIZE * 2) - 1)] = "c57e9278af78fa3cab38667bef4ce29d783787a2f731d4e12200270f0c32320a",
                [string.rep("a", (SHA256_BUF_SIZE * 2) + 1)] = "c12cb024a2e5551cca0e08fce8f1c5e314555cc3fef6329ee994a3db752166ae",
                -- luacheck: pop
            }) do
                expect.equal(hexsha256(data), expected_hash)
            end
        end)
    end)
end)
