-- Final-state and output checks shared by the rolling games.
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local keccak = cartesi.keccak256
local WORD_SIZE = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE
local WORD_MASK = WORD_SIZE - 1
local IFLAGS_Y_ADDRESS = cartesi.machine:get_reg_address("iflags_Y")
local HTIF_TOHOST_ADDRESS = cartesi.machine:get_reg_address("htif_tohost")
local CMIO_TX_BUFFER_ADDRESS = cartesi.AR_CMIO_TX_BUFFER_START

-- Authenticates the complete data at one expected machine-tree location. Its size follows the
-- proof, while this protocol requires every machine-validity target to be exactly one word.
local function verify_machine_word(data, proof, address, final_state_hash)
    assert(proof.root_hash == final_state_hash, "machine word proof root mismatch")
    assert(proof.log2_root_size == cartesi.HASH_TREE_LOG2_ROOT_SIZE, "machine word proof not whole-machine")
    assert(proof.target_address == (address & ~WORD_MASK), "machine word proof address mismatch")
    assert(proof.log2_target_size == cartesi.HASH_TREE_LOG2_WORD_SIZE, "machine word proof target not a word")
    assert(#data == 1 << proof.log2_target_size, "machine word data not a word")
    assert(hash_tree.get_data_root_hash(data, proof.log2_target_size) == proof.target_hash, "word data hash mismatch")
    hash_tree.verify_slice(proof)
end

-- Reads a little-endian 64-bit integer at a zero-based byte offset.
local function get_uint64(data, offset)
    return string.unpack("<I8", data, 1 + offset)
end

local function split_tohost(tohost)
    local dev = (tohost & cartesi.HTIF_DEV_MASK) >> cartesi.HTIF_DEV_SHIFT
    local cmd = (tohost & cartesi.HTIF_CMD_MASK) >> cartesi.HTIF_CMD_SHIFT
    local reason = (tohost & cartesi.HTIF_REASON_MASK) >> cartesi.HTIF_REASON_SHIFT
    return dev, cmd, reason
end

-- Establishes that the settled machine is yielded manually with RX_ACCEPTED, then returns the
-- outputs Merkle root authenticated at its tx-buffer word, matching Dave's machine validity proof.
local function validate_outputs_merkle_root_response(result, final_state_hash)
    verify_machine_word(result.iflags_y_data, result.iflags_y_proof, IFLAGS_Y_ADDRESS, final_state_hash)
    assert(get_uint64(result.iflags_y_data, IFLAGS_Y_ADDRESS & WORD_MASK) ~= 0, "final state not yielded")

    verify_machine_word(result.htif_tohost_data, result.htif_tohost_proof, HTIF_TOHOST_ADDRESS, final_state_hash)
    local htif_tohost = get_uint64(result.htif_tohost_data, HTIF_TOHOST_ADDRESS & WORD_MASK)
    local dev, cmd, reason = split_tohost(htif_tohost)
    assert(dev == cartesi.HTIF_DEV_YIELD, "tohost not a yield")
    assert(cmd == cartesi.HTIF_YIELD_CMD_MANUAL, "yield not manual")
    assert(reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED, "yield reason not rx-accepted")

    verify_machine_word(result.tx_buffer_data, result.tx_buffer_proof, CMIO_TX_BUFFER_ADDRESS, final_state_hash)
    return result.tx_buffer_data
end

local function validate_output_response(output, outputs_merkle_root)
    local output_proof = output.output_proof
    assert(output.output_index == output_proof.target_address, "output proof index mismatch")
    assert(output_proof.log2_target_size == 0, "output proof target not a leaf")
    assert(output_proof.log2_root_size == cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "output proof height mismatch")
    assert(output_proof.root_hash == outputs_merkle_root, "output proof root mismatch")
    assert(keccak(output.output) == output_proof.target_hash, "output hash mismatch")
    hash_tree.verify_slice(output_proof)
    return true
end

return {
    validate_outputs_merkle_root_response = validate_outputs_merkle_root_response,
    validate_output_response = validate_output_response,
}
