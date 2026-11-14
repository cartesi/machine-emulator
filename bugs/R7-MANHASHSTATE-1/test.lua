-- R7-MANHASHSTATE-1: the manual's "blockchain way" of template instantiation and result extraction
-- (doc/recipes/splice-calculator-with-new-drive.lua, doc/recipes/slice-calculator-output.lua, built on
-- cartesi.hash-tree verify_splice/verify_slice) binds a whole-machine proof neither to the known state hash
-- nor to the drive the recipe is about.
--
-- The test runs the two recipe files themselves, unmodified, with cartesi.machine replaced by a stand-in that
-- plays the chain's view: the chain knows the template hash M (instantiation) or the agreed final hash M'
-- (extraction) and the drive layout of the template; everything else (the proof, the claimed M', the claimed
-- result) is supplied by the prover. A recipe "accepts" when it runs to completion (prints "... works!") and
-- "refuses" when it raises an error.
--
-- Required (THREAT_MODEL section 1, R11, section 4 "Logs and proofs are adversarial"; manual: "the code first
-- checks the root hash M against the one found in the proof", and verify_splice "confirms that an output NVRAM
-- with exactly this content sits in the machine whose state hash is M'"):
--   (A) instantiation must refuse a pristine-input proof whose root is not M (here: a claimed M' that is not
--       the hash of the instantiated template);
--   (B) extraction must refuse a proof of a node other than the output NVRAM (here: the input NVRAM, whose
--       contents the instantiator chose) together with that node's contents as the "result".
-- Controls: the honest proof and the honest claim are accepted by both recipes (else exit 2).
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local util = require("cartesi.util")
    local hash_tree = require("cartesi.hash-tree")
    local repo = assert(os.getenv("REPO"), "REPO not set (run through bugs/run.sh)")
    local recipes = repo .. "/doc/recipes/"

    -- A small calculator-like template: input and output NVRAMs of the same size (4 KiB), as in the manual.
    local config = {
        ram = { length = 0x100000 },
        nvram = {
            { start = 0xa0000000, length = 0x1000, label = "input" },
            { start = 0xb0000000, length = 0x1000, label = "output" },
        },
    }
    local template <close> = cartesi.machine(config)
    local initial_config = template:get_initial_config()
    local input_nvram = assert(util.find_drive(initial_config, "nvram", "input"))
    local output_nvram = assert(util.find_drive(initial_config, "nvram", "output"))
    local M = template:get_root_hash() -- the template hash the chain knows

    local STUB_TAG = "R7-STUB-UNSUPPORTED"

    -- Stand-in for cartesi.machine: the chain's view of the machine in each recipe.
    --   hash_before_write: the hash the chain knows before the input is written (M)
    --   hash_after_write:  the hash claimed after the write (the prover's M') or the agreed M'
    --   memory:            what read_memory returns at each drive start (the prover's claimed result)
    local function make_stub(view)
        local written = false
        local methods = {}
        function methods:get_initial_config() return initial_config end
        function methods:write_memory(_, _) written = true end
        function methods:get_root_hash()
            if written then return view.hash_after_write end
            return view.hash_before_write
        end
        function methods:run(_) return cartesi.BREAK_REASON_HALTED end
        function methods:read_breakable_reason() return cartesi.BREAK_REASON_HALTED end
        function methods:read_memory(address, length)
            local data = view.memory and view.memory[address] or ""
            data = data:sub(1, length)
            return data .. string.rep("\0", length - #data)
        end
        function methods:destroy() end
        local mt = {
            __index = function(_, k)
                if methods[k] then return methods[k] end
                error(STUB_TAG .. ": method " .. tostring(k) .. " not modelled by the test", 2)
            end,
            __close = function() end,
        }
        return setmetatable({}, mt)
    end

    -- Run a recipe file with arg[1] = expr, the given proof module and the given chain view.
    local function run_recipe(file, proof_module_name, proof, view, expr)
        local chunk = assert(loadfile(recipes .. file))
        local cartesi_proxy = setmetatable({
            machine = function(...) return make_stub(view) end,
        }, { __index = cartesi })
        local saved_cartesi, saved_proof, saved_arg = package.loaded.cartesi, package.loaded[proof_module_name], arg
        package.loaded.cartesi = cartesi_proxy
        package.loaded[proof_module_name] = proof
        arg = { [0] = recipes .. file, expr }
        local ok, err = pcall(chunk, expr)
        package.loaded.cartesi, package.loaded[proof_module_name], arg = saved_cartesi, saved_proof, saved_arg
        if not ok and tostring(err):find(STUB_TAG, 1, true) then
            harness.setup_error("recipe " .. file .. " needs something the stand-in does not model: " .. tostring(err))
        end
        return ok, err
    end

    local expr = "1+1"
    local input_data = expr .. "\n"
    local result_data = "2\n" -- what the calculator writes to the output NVRAM

    -- Honest instantiated machine and honest final (halted) machine.
    local instantiated <close> = cartesi.machine(config)
    instantiated:write_memory(input_nvram.start, input_data)
    local real_M1 = instantiated:get_root_hash()
    local final <close> = cartesi.machine(config)
    final:write_memory(input_nvram.start, input_data)
    final:write_memory(output_nvram.start, result_data)
    local agreed_M2 = final:get_root_hash() -- the agreed final state hash M'

    ---------------------------------------------------------------------------------------------------------
    -- (A) Template instantiation
    ---------------------------------------------------------------------------------------------------------
    local honest_input_proof = template:get_proof(input_nvram.start, input_nvram.log2_size)
    local ok, err = run_recipe("splice-calculator-with-new-drive.lua", "pristine-input-proof", honest_input_proof,
        { hash_before_write = M, hash_after_write = real_M1 }, expr)
    if not ok then harness.setup_error("control: honest instantiation refused: " .. tostring(err)) end

    -- Forged "pristine input proof": arbitrary siblings, root_hash computed from them (it is not M).
    local forged = {
        target_address = input_nvram.start,
        log2_target_size = input_nvram.log2_size,
        log2_root_size = cartesi.HASH_TREE_LOG2_ROOT_SIZE,
        target_hash = string.rep("\1", cartesi.HASH_SIZE),
        sibling_hashes = {},
    }
    for i = 1, forged.log2_root_size - forged.log2_target_size do
        forged.sibling_hashes[i] = cartesi.keccak256(string.pack(">I4", i))
    end
    forged.root_hash = hash_tree.roll_hash_up_tree(forged, forged.target_hash)
    local input_hash = hash_tree.get_data_root_hash(input_data, input_nvram.log2_size)
    local forged_M1 = hash_tree.roll_hash_up_tree(forged, input_hash)
    if forged.root_hash == M or forged_M1 == real_M1 then harness.setup_error("forged proof is not forged") end
    local acceptedA = run_recipe("splice-calculator-with-new-drive.lua", "pristine-input-proof", forged,
        { hash_before_write = M, hash_after_write = forged_M1 }, expr)
    print(string.format("(A) instantiation: forged proof root == M: %s; claimed M' == real instantiated hash: %s;"
        .. " recipe accepted: %s", tostring(forged.root_hash == M), tostring(forged_M1 == real_M1),
        tostring(acceptedA)))

    ---------------------------------------------------------------------------------------------------------
    -- (B) Result extraction
    ---------------------------------------------------------------------------------------------------------
    local honest_output_proof = final:get_proof(output_nvram.start, output_nvram.log2_size)
    ok, err = run_recipe("slice-calculator-output.lua", "output-proof", honest_output_proof,
        { hash_before_write = M, hash_after_write = agreed_M2, memory = { [output_nvram.start] = result_data } },
        expr)
    if not ok then harness.setup_error("control: honest extraction refused: " .. tostring(err)) end

    -- Proof of the INPUT NVRAM of the same final machine, offered as the output proof, with the input
    -- contents as the claimed result.
    local wrong_proof = final:get_proof(input_nvram.start, input_nvram.log2_size)
    local claimed_result = input_data
    local acceptedB = run_recipe("slice-calculator-output.lua", "output-proof", wrong_proof,
        { hash_before_write = M, hash_after_write = agreed_M2, memory = { [output_nvram.start] = claimed_result } },
        expr)
    print(string.format("(B) extraction: proof target 0x%x (output NVRAM is 0x%x); claimed result %q, real output"
        .. " %q; recipe accepted: %s", wrong_proof.target_address, output_nvram.start, claimed_result, result_data,
        tostring(acceptedB)))

    local a = harness.expect(not acceptedA,
        "(A) instantiation by proof must refuse a pristine-input proof whose root is not the template hash M "
            .. "(manual: 'the code first checks the root hash M against the one found in the proof'; section 1, R11)")
    local b = harness.expect(not acceptedB,
        "(B) extraction by proof must refuse a proof of a node other than the output NVRAM "
            .. "(manual: 'an output NVRAM with exactly this content sits in the machine whose state hash is M''; "
            .. "section 1: 'a proof verifier accepts a node that the committed tree does not hold at the stated index')")
    return a and b
end)
