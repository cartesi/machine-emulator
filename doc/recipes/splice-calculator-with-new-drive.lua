-- Load the Cartesi module
local cartesi = require("cartesi")
local util = require("cartesi.util")
local hash_tree = require("cartesi.hash-tree")

-- Obtain input expression from the command line
local input_expr = assert(arg[1], "missing input expression")

-- Get instantiated template hash concretely

-- Load machine from template
local machine = cartesi.machine("calculator-template")

-- Find input NVRAM by label
local input_nvram = assert(util.find_drive(machine:get_initial_config(), "nvram", "input"))

-- Write input expression to input NVRAM
machine:write_memory(input_nvram.start, input_expr .. "\n")

-- Get root hash of instantiated template
local instantiated_template_hash = machine:get_root_hash()

-- Verify instantiated template hash using proofs

-- Load input proof (must be a whole-machine proof)
local template_input_proof = require("pristine-input-proof")
assert(template_input_proof.log2_root_size == cartesi.HASH_TREE_LOG2_ROOT_SIZE, "proof depth mismatch")

-- Load actual input hash
local input_hash = hash_tree.get_data_root_hash(input_expr .. "\n", input_nvram.log2_size)

-- Check that instantiated template hash can be obtained directly from input proof and new input hash
hash_tree.verify_splice(template_input_proof, input_hash, instantiated_template_hash)
print("Instantiation by proof works!")
