-- Load the Cartesi module
local cartesi = require("cartesi")
local util = require("cartesi.util")
local hash_tree = require("cartesi.hash-tree")

-- Obtain input expression from the command line
local input_expr = assert(arg[1], "missing input expression")

-- Get the result and the halted state hash concretely

-- Load machine from template, silencing its console output
local machine = cartesi.machine("calculator-template", { console = { output_destination = "to_null" } })
local config = machine:get_initial_config()

-- Write input expression to input NVRAM
local input_nvram = assert(util.find_drive(config, "nvram", "input"))
machine:write_memory(input_nvram.start, input_expr .. "\n")

-- Run machine until it halts or yields manual
repeat
    local break_reason = machine:run(math.maxinteger)
until break_reason == cartesi.BREAK_REASON_HALTED or break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY

-- Read result string from output NVRAM and save the halted state hash
local output_nvram = assert(util.find_drive(config, "nvram", "output"))
local result = string.unpack("z", machine:read_memory(output_nvram.start, output_nvram.length))
local halted_state_hash = machine:get_root_hash()

-- Verify the result against the output proof

-- Load output proof (must be a whole-machine proof)
local output_proof = require("output-proof")
assert(output_proof.log2_root_size == cartesi.HASH_TREE_LOG2_ROOT_SIZE, "proof depth mismatch")

-- Reconstruct the root hash of the output NVRAM from the result alone
local output_hash = hash_tree.get_data_root_hash(result, output_nvram.log2_size)

-- Splicing the reconstructed output drive into the proof must reproduce the agreed machine hash
hash_tree.verify_splice(output_proof, output_hash, halted_state_hash)
print("Extraction by proof works!")
print(result)
