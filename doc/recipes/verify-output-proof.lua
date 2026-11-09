local cartesi = require("cartesi")
local fs = require("cartesi.filesystem")
local hash_tree = require("cartesi.hash-tree")
local util = require("cartesi.util")

local WORD_MASK = (1 << cartesi.HASH_TREE_LOG2_WORD_SIZE) - 1
local IFLAGS_Y_ADDRESS = cartesi.machine:get_reg_address("iflags_Y")
local HTIF_TOHOST_ADDRESS = cartesi.machine:get_reg_address("htif_tohost")

-- Read a proof saved as a Lua chunk
local function read_proof(name)
    return assert(loadfile(name, "t", {}))()
end

-- Verify the data of the machine word that contains the address against the machine state hash
local function verify_machine_word(data, proof, address, machine_hash)
    assert(proof.root_hash == machine_hash, "proof not rooted at the machine state hash")
    assert(proof.log2_root_size == cartesi.HASH_TREE_LOG2_ROOT_SIZE, "proof not whole-machine")
    assert(proof.log2_target_size == cartesi.HASH_TREE_LOG2_WORD_SIZE, "proof target not a word")
    assert(proof.target_address == address & ~WORD_MASK, "proof at another address")
    assert(#data == WORD_MASK + 1, "data not a word")
    assert(hash_tree.get_data_root_hash(data, proof.log2_target_size) == proof.target_hash, "data does not match proof")
    hash_tree.verify_slice(proof)
end

-- Read the 64-bit register at the address from the data of the word that contains it
local function get_reg(data, address)
    return string.unpack("<I8", data, 1 + (address & WORD_MASK))
end

-- The settled machine state hash, the two proofs, and the output to verify against them
local machine_hash = fs.read_file(assert(arg[1], "missing machine state hash"))
local outputs_merkle_root_proof = read_proof(assert(arg[2], "missing outputs Merkle root proof"))
local output_proof = read_proof(assert(arg[3], "missing output proof"))
local output = fs.read_file(assert(arg[4], "missing output"))

-- The machine must be yielded manually, having accepted its last input
local iflags_y_data = outputs_merkle_root_proof.iflags_y_data
verify_machine_word(iflags_y_data, outputs_merkle_root_proof.iflags_y_proof, IFLAGS_Y_ADDRESS, machine_hash)
assert(get_reg(iflags_y_data, IFLAGS_Y_ADDRESS) ~= 0, "machine not yielded")
local htif_tohost_data = outputs_merkle_root_proof.htif_tohost_data
verify_machine_word(htif_tohost_data, outputs_merkle_root_proof.htif_tohost_proof, HTIF_TOHOST_ADDRESS, machine_hash)
local dev, cmd, reason = util.decode_tohost(get_reg(htif_tohost_data, HTIF_TOHOST_ADDRESS))
assert(dev == cartesi.HTIF_DEV_YIELD, "machine not yielded")
assert(cmd == cartesi.HTIF_YIELD_CMD_MANUAL, "yield not manual")
assert(reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED, "input not accepted")

-- The tx-buffer word of that machine state holds the outputs Merkle root
local outputs_merkle_root = outputs_merkle_root_proof.tx_buffer_data
verify_machine_word(
    outputs_merkle_root,
    outputs_merkle_root_proof.tx_buffer_proof,
    cartesi.AR_CMIO_TX_BUFFER_START,
    machine_hash
)

-- The output proof must target a leaf of the full-height outputs tree, at an index inside it
assert(output_proof.root_hash == outputs_merkle_root, "output proof not rooted at the outputs Merkle root")
assert(output_proof.log2_target_size == 0, "output proof target not a leaf")
assert(output_proof.log2_root_size == cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "output proof height mismatch")
assert(output_proof.target_address >> cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT == 0, "output index out of range")
hash_tree.verify_slice(output_proof)

-- The output proof's target must be the hash of the output itself
assert(cartesi.keccak256(output) == output_proof.target_hash, "output does not match the proof")

print(string.format("output %d verified against the machine state hash", output_proof.target_address))
