local cartesi = require("cartesi")

local _M = {}

function _M.roll_hash_up_tree(proof, target_hash)
    local hash = target_hash
    for log2_size = proof.log2_target_size, proof.log2_root_size - 1 do
        local bit = (proof.target_address & (1 << log2_size)) ~= 0
        local first, second
        local i = proof.log2_root_size - log2_size
        if bit then
            first, second = proof.sibling_hashes[i], hash
        else
            first, second = hash, proof.sibling_hashes[i]
        end
        hash = cartesi.keccak(first, second)
    end
    return hash
end

function _M.slice_assert(root_hash, proof)
    assert(root_hash == proof.root_hash, "proof root_hash mismatch")
    assert(_M.roll_hash_up_tree(proof, proof.target_hash) == root_hash, "node not in tree")
end

function _M.word_slice_assert(root_hash, proof, word)
    assert(proof.log2_target_size == 3, "not a word proof")
    assert(root_hash == proof.root_hash, "proof root_hash mismatch")
    assert(cartesi.keccak(word) == proof.target_hash, "proof target_hash mismatch")
    assert(_M.roll_hash_up_tree(proof, proof.target_hash) == root_hash, "node not in tree")
end

function _M.splice_assert(root_hash, proof, new_target_hash, new_root_hash)
    _M.slice_assert(root_hash, proof)
    assert(_M.roll_hash_up_tree(proof, new_target_hash) == new_root_hash, "new root hash mismatch")
end

function _M.word_splice_assert(root_hash, proof, old_word, new_word, new_root_hash)
    _M.word_slice_assert(root_hash, proof, old_word)
    assert(_M.roll_hash_up_tree(proof, cartesi.keccak(new_word)) == new_root_hash, "new root hash mismatch")
end

function _M.check_proof(proof) return _M.roll_hash_up_tree(proof, proof.target_hash) == proof.root_hash end

return _M
