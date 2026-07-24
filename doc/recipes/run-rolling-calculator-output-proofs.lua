-- Load the JSON-RPC submodule, the EVM ABI helpers, and the hash-tree helpers
local cartesi = require("cartesi")
local cartesi_jsonrpc = require("cartesi.jsonrpc")
local evmu = require("cartesi.evmu")
local util = require("cartesi.util")
local hash_tree = require("cartesi.hash-tree")

local EVM_ADVANCE = "EvmAdvance(uint256 chain_id, address app_contract, address msg_sender, "
    .. "uint256 block_number, uint256 block_timestamp, uint256 prev_randao, uint256 index, bytes payload)"
local NOTICE = "Notice(bytes payload)"
local ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

-- Writes formatted text to stderr
local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

-- Encode a raw expression as an EvmAdvance request payload (bc needs a
-- trailing newline to accept the line as a complete expression)
local function encode_advance(expr, index)
    local bint = evmu.bint
    return evmu.encode_calldata(EVM_ADVANCE, {
        chain_id = bint.new(0),
        app_contract = ZERO_ADDRESS,
        msg_sender = ZERO_ADDRESS,
        block_number = bint.new(0),
        block_timestamp = bint.new(os.time()),
        prev_randao = bint.new(0),
        index = bint.new(index),
        payload = evmu.raw(expr .. "\n"),
    })
end

-- Print a string folded into lines of width w
local function fold(s, w)
    for i = 1, #s, w do
        print(s:sub(i, i + w - 1))
    end
end

-- Decode a response inside a notice
local function print_decoded_notice(data)
    fold(evmu.decode_calldata(NOTICE, data, "raw").payload, 68)
end

-- Serialize a proof as a Lua chunk and save it
local function save_proof(proof, name)
    local f <close> = assert(io.open(name, "w"))
    f:write("return ")
    util.dump_table(proof, f)
    f:write("\n")
    stderr("saved %s\n", name)
end

-- Connect to remote Cartesi Machine server (and shut it down on exit)
local remote_address = assert(arg[1], "missing remote address")
stderr("Connecting to remote cartesi machine at '%s'\n", remote_address)
local cartesi_jsonrpc_machine <close> =
    assert(cartesi_jsonrpc.connect_server(remote_address)):set_cleanup_call(cartesi_jsonrpc.SHUTDOWN)

-- Print server version (and test connection)
local v = assert(cartesi_jsonrpc_machine:get_server_version())
stderr("Connected: remote version is %d.%d.%d\n", v.major, v.minor, v.patch)

-- Load remote machine from the rolling-calculator template
local machine = cartesi_jsonrpc_machine("rolling-calculator-template")

-- Snapshot via fork: the backup server keeps the pre-input state
local backup
local function snapshot()
    backup = machine:fork_server()
end
local function commit()
    if backup then
        backup:shutdown_server()
    end
    backup = nil
end
local function rollback()
    assert(backup, "no snapshot to rollback to")
    local address = machine:get_server_address()
    machine:shutdown_server()
    machine:swap(backup)
    machine:rebind_server(address)
    backup = nil
end

-- Seed frontier builds the end-of-epoch proofs, a running copy checks each input's root
local seed_frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
local running_frontier = hash_tree.frontier_copy(seed_frontier)
local output_hashes = {} -- keccak256 leaf of every accepted output, in order
local output_inputs = {} -- the input index each accepted output came from
local pending_outputs = {} -- outputs of the current input, buffered until its verdict is known

-- On accept, fold the input's outputs into the tree and save its tx-buffer root-hash proof
local function flush_accepted(input_index, root_hash)
    for _, output in ipairs(pending_outputs) do
        local leaf = cartesi.keccak256(output)
        output_hashes[#output_hashes + 1] = leaf
        output_inputs[#output_inputs + 1] = input_index
        hash_tree.frontier_push_back(running_frontier, leaf)
    end
    pending_outputs = {}
    assert(#root_hash == cartesi.HASH_SIZE, "expected outputs Merkle root in tx buffer")
    assert(hash_tree.frontier_get_root_hash(running_frontier) == root_hash, "outputs Merkle root mismatch")
    local proof = machine:get_proof(cartesi.AR_CMIO_TX_BUFFER_START, cartesi.HASH_TREE_LOG2_WORD_SIZE)
    assert(proof.root_hash == machine:get_root_hash(), "proof root mismatch")
    assert(proof.target_hash == cartesi.keccak256(root_hash), "tx buffer does not hold the outputs Merkle root")
    hash_tree.verify_slice(proof)
    save_proof(proof, string.format("input-%d-outputs-merkle-root-proof.lua", input_index))
end

-- Run the machine until it halts or stdin closes
local i = 0
local revert_root_hash
repeat
    local break_reason = machine:run(math.maxinteger)
    if break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY then
        local _, yield_reason, data = machine:receive_cmio_request()
        if yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            commit()
            revert_root_hash = machine:get_root_hash()
            -- the just-run input was accepted, so close it out before feeding the next one
            if i > 0 then
                flush_accepted(i - 1, data)
            end
            stderr("type expression\n")
            local expr = io.read()
            if not expr then
                break
            end
            stderr("%s\n", expr) -- echo the input so non-tty transcripts make sense
            snapshot()
            machine:send_cmio_response(
                cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
                encode_advance(expr, i),
                revert_root_hash
            )
            i = i + 1
        elseif i > 0 and yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
            stderr("input rejected\n")
            pending_outputs = {} -- discard the rejected input's outputs; the tree is left untouched
            rollback()
        else
            stderr("machine initialization failed\n")
            break
        end
    elseif break_reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
        local _, yield_reason, data = machine:receive_cmio_request()
        if yield_reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT then
            pending_outputs[#pending_outputs + 1] = data -- buffer until the input's verdict is known
            stderr("result is\n")
            print_decoded_notice(data)
        end
    end
until break_reason == cartesi.BREAK_REASON_HALTED
commit()

-- Build, verify, and save one per-output proof against the final root
local proofs = hash_tree.frontier_next_proofs(seed_frontier, output_hashes)
for k, proof in ipairs(proofs) do
    hash_tree.verify_slice(proof)
    save_proof(proof, string.format("output-%d-input-%d-proof.lua", proof.target_address, output_inputs[k]))
end
