-- Exercise the bridge encoder against the deployed state transition before
-- playing a tournament. The native verifier is the independent result oracle.
local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local eth = require("prt-ethereum")
local hash_tree = require("cartesi.hash-tree")
local util = require("cartesi.util")
local json = require("dkjson")

local function check(chain, transition, provider, player, paths, directory)
    local vectors = {
        { "input delivery", 0, 0, 0 },
        { "ordinary step", 0, 0, 1 },
        { "instruction reset", 0, 0, (1 << 20) - 1 },
        { "late period reset", 2, 2000, (1 << 30) - 1 },
        { "absent input", #paths, 0, 0 },
    }
    local results = {}
    for _, vector in ipairs(vectors) do
        local name, input, period, offset = table.unpack(vector)
        local cycle = (evmu.bint(input) << 68) + (evmu.bint(period) << 30) + offset
        local response = player.event_handler.prove_state_transition(player, input, period, offset)
        local first = (response.send_cmio_log or response.step_log).accesses[1]
        local before = eth.hex(hash_tree.roll_hash_up_tree({
            log2_root_size = 64,
            log2_target_size = math.max(first.log2_size, cartesi.HASH_TREE_LOG2_WORD_SIZE),
            target_address = first.address,
            sibling_hashes = first.sibling_hashes,
        }, first.read_hash))
        local input_data = paths[input + 1] and util.read_file(paths[input + 1])
        local expected = eth.verify_transition(response, cycle, input_data, before)
        local proof = eth.transition_proof(response, cycle, input_data)
        local function call(candidate)
            return chain:call(
                transition,
                evmu.encode_calldata_hex(
                    "transitionState(bytes32,uint256,bytes,address)",
                    { before, cycle, candidate, provider }
                )
            )
        end
        local obtained, failure = call(proof)
        assert(obtained == expected, name .. ": Solidity differs from native: " .. json.encode(failure))
        -- Exact consumption and authentication must reject both length changes
        -- and corruption, including for otherwise valid no-op transitions.
        local raw = assert(eth.raw(proof))
        for _, malformed in ipairs({
            proof .. "00",
            proof:sub(1, -3),
            eth.hex(raw:sub(1, -2) .. string.char(raw:byte(-1) ~ 1)),
        }) do
            local value, err = call(malformed)
            assert(not value and err and err.code == 3, name .. ": malformed proof accepted")
        end
        results[#results + 1] = {
            name = name,
            cycle = tostring(cycle),
            before = before,
            after = obtained,
            proof_bytes = #raw,
            malformed_rejected = 3,
        }
    end
    local file <close> = assert(io.open((directory or ".") .. "/proof-vectors.json", "w"))
    assert(file:write(json.encode(results, { indent = true })))
    io.stderr:write("Native and Solidity verifiers agree on ", #results, " proof classes and malformed vectors.\n")
end

return check
