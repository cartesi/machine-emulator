local cartesi = require("cartesi")

-- Localize functions used in hotloops (optimization)
local keccak, ult = cartesi.keccak, math.ult

-- Cache table for merkle of zeros
local merkle_zero_keccak_cache = {}
do
    local zero_hash = keccak(("\x00"):rep(8))
    merkle_zero_keccak_cache[8] = zero_hash
    for i = 4, 63 do
        zero_hash = keccak(zero_hash, zero_hash)
        merkle_zero_keccak_cache[1 << i] = zero_hash
    end
end
local PAGE_SIZE <const> = 4096
local page_of_zero = ("\x00"):rep(PAGE_SIZE)
local page_of_zero_hash = merkle_zero_keccak_cache[PAGE_SIZE]

-- Returns merkle keccak hash from a chunk inside a buffer of bytes.
local function merkle_keccak_chunk(data, off, len)
    off = off or 0
    len = len or #data
    assert(len & (len - 1) == 0, "cannot hash non power of two length")
    if len == 8 then
        local word = data:sub(off + 1, off + 8)
        assert(#word == 8, "data out of region bounds")
        return keccak(word)
    elseif len == PAGE_SIZE and data:sub(off + 1, off + PAGE_SIZE) == page_of_zero then
        -- it's common to have page of zeros in the memory,
        -- this an optimization to avoid recomputing it
        return page_of_zero_hash
    else
        local hlen = len >> 1
        local left = merkle_keccak_chunk(data, off, hlen)
        local right = merkle_keccak_chunk(data, off + hlen, hlen)
        return keccak(left, right)
    end
end

-- Returns merkle keccak hash from a region of a list of chunks,
-- the list must be sorted by region start.
local function merkle_keccak_chunks(chunks, off, len, it)
    assert(off % 8 == 0, "non power of two offset")
    assert(len & (len - 1) == 0, "non power of two length")
    local chunk, overlaps, contained
    do -- find chunk overlapping with region
        chunk = chunks[it]
        if chunk and not ult(off, chunk.start + #chunk.data) then -- must advance to next chunk
            it = it + 1
            chunk = chunks[it]
        end
        if chunk then
            local x1, x2, c1, c2 = off, off + len, chunk.start, chunk.start + #chunk.data
            overlaps = ult(x1, c2) and ult(c1, x2)
            contained = overlaps and not ult(x1, c1) and not ult(c2, x2)
        end
    end
    -- hash
    if not overlaps then -- no chunk overlaps, hash with zeros
        return merkle_zero_keccak_cache[len], it
    elseif contained then -- chunk fully contains the region
        return merkle_keccak_chunk(chunk.data, off - chunk.start, len), it
    else -- chunk overlaps with region
        -- combine hashes of the region left and right
        local hlen = len >> 1
        local left, right
        left, it = merkle_keccak_chunks(chunks, off, hlen, it)
        right, it = merkle_keccak_chunks(chunks, off + hlen, hlen, it)
        return keccak(left, right), it
    end
end

-- Calculate merkle keccak hash up to log2_size bytes for buffer data,
-- using zero sibling hashes where needed.
local function merkle_keccak_expanded_chunk(data, log2_size)
    local chunks = {
        { start = 0, data = data },
    }
    return (merkle_keccak_chunks(chunks, 0, 1 << log2_size, 1))
end

-- Return the merkle module
local merkle = {
    keccak_chunk = merkle_keccak_chunk,
    keccak_chunks = merkle_keccak_chunks,
    keccak_expanded_chunk = merkle_keccak_expanded_chunk,
}
return merkle
