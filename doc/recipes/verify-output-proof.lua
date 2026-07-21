local cartesi = require("cartesi")
local util = require("cartesi.util")
local hash_tree = require("cartesi.hash-tree")

-- Read a proof saved as a Lua chunk
local function read_proof(name)
    return assert(loadfile(name, "t", {}))()
end

-- The settled machine state hash, the two proofs, and the output to verify against them
local machine_hash = util.read_file(assert(arg[1], "missing machine state hash"))
local outputs_merkle_root_proof = read_proof(assert(arg[2], "missing outputs Merkle root proof"))
local output_proof = read_proof(assert(arg[3], "missing output proof"))
local output = util.read_file(assert(arg[4], "missing output"))

-- The outputs Merkle root proof must be rooted at the agreed machine state hash
assert(outputs_merkle_root_proof.root_hash == machine_hash, "proof not rooted at the machine state hash")
hash_tree.verify_slice(outputs_merkle_root_proof)

-- The output proof's root is the outputs Merkle root, the value the tx-buffer word holds
assert(
    cartesi.keccak256(output_proof.root_hash) == outputs_merkle_root_proof.target_hash,
    "tx buffer holds another value"
)
hash_tree.verify_slice(output_proof)

-- The output proof's target must be the hash of the output itself
assert(cartesi.keccak256(output) == output_proof.target_hash, "output does not match the proof")

print(string.format("output %d verified against the machine state hash", output_proof.target_address))
