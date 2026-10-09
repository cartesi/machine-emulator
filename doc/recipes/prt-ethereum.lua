-- Ethereum encodings at the recipe player's boundary. Computation stays in prt.lua.
local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local json = require("dkjson")
local util = require("cartesi.util")
local hash_tree = require("cartesi.hash-tree")
local M = { zero = "0x" .. string.rep("00", 32) }
M.hex, M.raw = evmu.encode_hex, evmu.decode_hex

function M.small(value)
    local n = evmu.bint(value)
    assert(n >= 0 and n < evmu.bint(1) << 63, "coordinate does not fit a Lua integer")
    return evmu.bint.tointeger(n)
end

function M.coordinates(cycle)
    cycle = evmu.bint(cycle)
    assert(cycle >= 0 and cycle < evmu.bint(1) << 92, "cycle outside epoch")
    return M.small(cycle >> 68),
        M.small((cycle >> 30) & ((evmu.bint(1) << 38) - 1)),
        M.small(cycle & ((evmu.bint(1) << 30) - 1))
end

local function type_spec(parameter, names)
    local result = parameter.type
    if result:sub(1, 5) == "tuple" then
        local components = {}
        for i, component in ipairs(parameter.components) do
            components[i] = type_spec(component, names)
        end
        result = "(" .. table.concat(components, ",") .. ")" .. result:sub(6)
    end
    if names and parameter.name ~= "" then
        result = result .. " " .. parameter.name
    end
    return result
end

function M.artifact(directory, name)
    return assert(json.decode(util.read_file(directory .. "/" .. name .. ".sol/" .. name .. ".json")))
end

local abi_methods = {}
function M.abi(artifacts)
    local self = setmetatable({ events = {}, functions = {} }, { __index = abi_methods })
    for _, artifact in ipairs(artifacts) do
        for _, entry in ipairs(artifact.abi) do
            if entry.type == "event" or entry.type == "function" then
                local types = {}
                for i, input in ipairs(entry.inputs) do
                    types[i] = type_spec(input, false)
                end
                local signature = entry.name .. "(" .. table.concat(types, ",") .. ")"
                if entry.type == "event" then
                    self.events[M.hex(cartesi.keccak256(signature))] = entry
                else
                    assert(
                        not self.functions[entry.name] or self.functions[entry.name] == signature,
                        "overloaded function needs an explicit signature: " .. entry.name
                    )
                    self.functions[entry.name] = signature
                end
            end
        end
    end
    return self
end

function abi_methods:calldata(name, arguments)
    return evmu.encode_calldata_hex(assert(self.functions[name], name), arguments)
end

function abi_methods:event(log)
    local entry = self.events[log.topics[1]]
    if not entry then
        return nil
    end
    local types = {}
    for _, input in ipairs(entry.inputs) do
        if not input.indexed then
            types[#types + 1] = type_spec(input, true)
        end
    end
    local value = evmu.decode_abi("(" .. table.concat(types, ",") .. ")", assert(M.raw(log.data)))
    local topic = 2
    for _, input in ipairs(entry.inputs) do
        if input.indexed then
            local decoded = evmu.decode_abi("(" .. type_spec(input, true) .. ")", assert(M.raw(log.topics[topic])))
            value[input.name] = decoded[1]
            topic = topic + 1
        end
    end
    value.name, value.address, value.log = entry.name, log.address, log
    return value
end

function M.siblings(proof)
    local result = {}
    for i, hash in ipairs(proof.sibling_hashes) do
        result[i] = M.hex(hash)
    end
    return result
end

function M.claim(response, height)
    local proof = response.final_state_hash_proof
    local root = cartesi.keccak256(response.computation_hash_left, response.computation_hash_right)
    assert(proof.root_hash == root and proof.log2_root_size == height)
    assert(proof.target_address == (1 << height) - 1 and proof.log2_target_size == 0)
    hash_tree.verify_slice(proof)
    return {
        root = M.hex(root),
        final_state = M.hex(proof.target_hash),
        children = { M.hex(response.computation_hash_left), M.hex(response.computation_hash_right) },
        proof = M.siblings(proof),
    }
end

local function append_log(parts, log)
    for _, access in ipairs(log.accesses) do
        if access.log2_size == 3 then
            -- An eight-byte access authenticates the containing 32-byte leaf.
            -- AccessLogs.readWord/writeWord select the word within that leaf.
            assert(access.read and #access.read == 32, "word access lacks its Merkle leaf")
            parts[#parts + 1] = access.read
        elseif access.type == "read" then
            assert(access.read and #access.read == 32, "region read is not a bytes32")
            parts[#parts + 1] = access.read
            parts[#parts + 1] = assert(access.read_hash)
        else
            parts[#parts + 1] = assert(access.read_hash)
        end
        for _, sibling in ipairs(access.sibling_hashes) do
            parts[#parts + 1] = sibling
        end
    end
end

function M.transition_proof(response, cycle, input_data)
    local _, period, offset = M.coordinates(cycle)
    assert(
        (response.reset_uarch_log ~= nil) == (offset % (1 << 20) == (1 << 20) - 1),
        "transition has the wrong reset shape"
    )
    local parts = {}
    if period == 0 and offset == 0 then
        parts[1] = string.pack(">I8", input_data and #input_data or 0) .. (input_data or "")
        assert((response.send_cmio_log ~= nil) == (input_data ~= nil), "wrong input-delivery proof")
    else
        assert(not response.send_cmio_log, "unexpected input-delivery proof")
    end
    if response.send_cmio_log then
        append_log(parts, response.send_cmio_log)
    end
    append_log(parts, assert(response.step_log))
    if response.reset_uarch_log then
        assert(offset % (1 << 20) == (1 << 20) - 1, "reset outside instruction boundary")
        append_log(parts, response.reset_uarch_log)
    end
    return M.hex(table.concat(parts))
end

-- An independent native verifier checks the encoding seam against Solidity.
-- The caller supplies InputBox bytes, never a player's private input file.
function M.verify_transition(response, cycle, input_data, before)
    local _, period, offset = M.coordinates(cycle)
    local root = assert(M.raw(before))
    if period == 0 and offset == 0 and input_data ~= nil then
        root = cartesi.machine:verify_send_cmio_response(
            cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
            input_data,
            root,
            response.send_cmio_log,
            root
        )
    end
    root = cartesi.machine:verify_step_uarch(root, response.step_log)
    if offset % (1 << 20) == (1 << 20) - 1 then
        root = cartesi.machine:verify_reset_uarch(root, response.reset_uarch_log)
    end
    return M.hex(root)
end

function M.validity_proof(response, final_state)
    require("game-output").validate_outputs_merkle_root_response(response, assert(M.raw(final_state)))
    local result = {}
    for i, name in ipairs({ "iflags_y", "htif_tohost", "tx_buffer" }) do
        local data, proof = response[name .. "_data"], response[name .. "_proof"]
        result[i] = { M.hex(data), M.siblings(proof) }
    end
    return result
end

return M
