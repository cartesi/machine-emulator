-- R6-DYNBRIDGE-2: the PRT epoch listener (doc/recipes/prt-epoch.lua, with prt-log-history.lua and
-- prt-rpc.lua) aborts with "epoch log history was truncated" when, under a numeric input policy
-- (crisium --input-policy=N; the recipe demo uses 8), a reorganization that replaces only blocks above
-- the observation head ends on a shorter branch. The observation head (tip - N) moves back over a block
-- that is still canonical and whose input the listener already delivered.
--
-- Everything is the real recipe code (listener, log history, RPC client head/is_canonical/logs, and the
-- ABI decoder built from the pinned Dave InputBox artifact) except the JSON-RPC node, which is scripted
-- here (eth_getBlockByNumber and eth_getLogs), and the player, whose input_added handler only records
-- what the listener delivers.
--
-- Required (THREAT_MODEL R4: "The honest operator observes the chain and submits its transactions
-- within the dispute clocks"; section 4: "The honest operator acts only on history that its policy
-- treats as final"): a reorganization shallower than the input policy, which leaves every block the
-- listener acted on canonical, must not stop the listener; it keeps polling and, once the head moves
-- forward again, delivers every input exactly once, in order.
local harness = require("harness")

harness.main(function()
    local json = require("dkjson")
    local eth = require("prt-ethereum")
    local evmu = require("cartesi.evmu")
    local rpc_client = require("prt-rpc")
    local epoch = require("prt-epoch")

    local dave = os.getenv("HARNESS_WORK") .. "/dave/patched"
    local artifact_ok, input_box_artifact =
        pcall(eth.artifact, dave .. "/cartesi-rollups/contracts/out", "InputBox")
    if not artifact_ok then
        harness.setup_error("pinned Dave build missing (bugs/harness/chain/build-dave.sh): " .. tostring(input_box_artifact))
    end
    local abi = eth.abi({ input_box_artifact })

    local POLICY = 8 -- the recipe demo's PRT_INPUT_CONFIRMATIONS default
    local INPUT_BOX = "0x00000000000000000000000000000000000000b0"
    local CONSENSUS = "0x00000000000000000000000000000000000000c0"
    local APP = "0x00000000000000000000000000000000000000a0"
    local OTHER_APP = "0x00000000000000000000000000000000000000a1"

    local function hx(n)
        return string.format("0x%x", n)
    end

    -- A scripted node: canonical blocks by number, each with its logs.
    local function new_node()
        local node = { blocks = {}, counter = 0, tip = -1 }
        function node.mine(logs)
            node.counter = node.counter + 1
            local number = node.tip + 1
            local b = { number = number, hash = string.format("0x%064x", node.counter), logs = {} }
            for i, l in ipairs(logs or {}) do
                b.logs[i] = {
                    address = l.address,
                    topics = l.topics,
                    data = l.data,
                    removed = false,
                    blockNumber = hx(number),
                    blockHash = b.hash,
                    logIndex = hx(i - 1),
                    transactionIndex = "0x0",
                }
            end
            node.blocks[number] = b
            node.tip = number
            return b
        end
        -- Replaces the newest depth blocks with newlen fresh blocks.
        function node.reorg(depth, newlen)
            for n = node.tip, node.tip - depth + 1, -1 do
                node.blocks[n] = nil
            end
            node.tip = node.tip - depth
            for _ = 1, newlen do
                node.mine()
            end
        end
        local function block_json(b)
            if not b then
                return json.null
            end
            return { number = hx(b.number), hash = b.hash, parentHash = "0x" .. string.rep("0", 64) }
        end
        function node.handle(method, p)
            if method == "eth_getBlockByNumber" then
                local tag = p[1]
                if tag == "latest" then
                    return block_json(node.blocks[node.tip])
                end
                assert(tag ~= "finalized" and tag ~= "safe", "unexpected tag " .. tostring(tag))
                return block_json(node.blocks[tonumber(tag)])
            elseif method == "eth_getLogs" then
                local f = p[1]
                local addresses = {}
                for _, a in ipairs(type(f.address) == "table" and f.address or { f.address }) do
                    addresses[a] = true
                end
                local out = {}
                for n = tonumber(f.fromBlock), math.min(tonumber(f.toBlock), node.tip) do
                    for _, l in ipairs(node.blocks[n].logs) do
                        local match = addresses[l.address]
                        for i, t in ipairs(f.topics or {}) do
                            if t ~= json.null and l.topics[i] ~= t then
                                match = false
                            end
                        end
                        if match then
                            out[#out + 1] = l
                        end
                    end
                end
                return out
            end
            error("scripted node: unsupported method " .. method)
        end
        node.chain = rpc_client.new("http://scripted-node:1")
        function node.chain.rpc(_, method, params)
            return node.handle(method, params or {})
        end
        return node
    end

    -- An InputAdded log as the InputBox emits it.
    local function input_added(app, index, payload)
        local topics = abi:topics("InputAdded", app)
        topics[3] = eth.hex(evmu.encode_abi("(uint256)", { index }))
        return { address = INPUT_BOX, topics = topics, data = eth.hex(evmu.encode_abi("(bytes)", { eth.hex(payload) })) }
    end

    local function new_listener(node, delivered)
        local player = {
            event_handler = {
                input_added = function(_, offset, path)
                    local f = assert(io.open(path, "rb"))
                    delivered[#delivered + 1] = { offset = offset, data = f:read("a") }
                    f:close()
                end,
                epoch_sealed = function()
                    error("unexpected seal")
                end,
            },
        }
        return epoch.new({
            chain = node.chain,
            abi = abi,
            app = APP,
            input_box = INPUT_BOX,
            consensus = CONSENSUS,
            player = player,
            label = "honest",
            initial_hash = eth.zero,
            previous_outputs_root = eth.zero,
            sentinel = true,
            geometry = {},
            epoch = 0,
            input_begin = 0,
            input_policy = POLICY,
            dispute_policy = 4,
            first_block = 1,
            first_input_block = 1,
        })
    end

    local payloads = { "input-0", "input-1", "input-2", "input-3" }

    -- Inputs 0, 1, 2 in blocks 10, 11, 12 (with an unrelated application's input in block 11), the
    -- tip at 20 so the observation head is 12 and all three are delivered. Then a reorganization of
    -- depth 2 replaced by newlen blocks. Then input 3 in a new block and the head moves past it.
    local function scenario(newlen)
        local node = new_node()
        local delivered = {}
        local listener = new_listener(node, delivered)
        node.mine() -- genesis
        local next_index = 0
        local function poll()
            local ok, err = pcall(listener.poll, listener)
            if not ok then
                return false, tostring(err)
            end
            return true
        end
        for n = 1, 20 do
            local logs
            if n >= 10 and n <= 12 then
                logs = { input_added(APP, next_index, payloads[next_index + 1]) }
                if n == 11 then
                    logs[2] = input_added(OTHER_APP, 0, "other")
                end
                next_index = next_index + 1
            end
            node.mine(logs)
            local ok, err = poll()
            if not ok then
                harness.setup_error("listener failed before the reorganization: " .. err)
            end
        end
        if #delivered ~= 3 then
            harness.setup_error("expected 3 inputs delivered before the reorganization, got " .. #delivered)
        end
        local old_head = node.tip - POLICY
        local old_head_hash = node.blocks[old_head].hash
        node.reorg(2, newlen)
        local r = {
            new_tip = node.tip,
            new_head = node.tip - POLICY,
            old_head = old_head,
            old_head_canonical = node.blocks[old_head] ~= nil and node.blocks[old_head].hash == old_head_hash,
            delivered = delivered,
        }
        local ok, err = poll()
        r.ok_after_reorg, r.err_after_reorg = ok, err
        if not ok then
            return r
        end
        -- The chain moves on: input 3 two blocks later, then enough blocks for it to reach the head
        node.mine()
        node.mine({ input_added(APP, 3, payloads[4]) })
        local input3_block = node.tip
        while node.tip - POLICY < input3_block do
            node.mine()
            ok, err = poll()
            if not ok then
                r.ok_later, r.err_later = false, err
                return r
            end
        end
        r.ok_later = true
        return r
    end

    local function delivered_exactly_once(delivered)
        if #delivered ~= #payloads then
            return false
        end
        for i, d in ipairs(delivered) do
            if d.offset ~= i - 1 or d.data ~= payloads[i] then
                return false
            end
        end
        return true
    end
    local function describe(delivered)
        local parts = {}
        for _, d in ipairs(delivered) do
            parts[#parts + 1] = string.format("%d:%s", d.offset, d.data)
        end
        return "{" .. table.concat(parts, ", ") .. "}"
    end

    -- Control: the same reorganization depth with an equal-length branch (the head does not move back).
    local control = scenario(2)
    print(string.format("control (depth 2 -> 2 blocks): tip %d head %d, old head %d canonical %s; poll %s; delivered %s",
        control.new_tip, control.new_head, control.old_head, tostring(control.old_head_canonical),
        control.ok_after_reorg and (control.ok_later and "ok" or ("ERROR later: " .. control.err_later))
            or ("ERROR: " .. control.err_after_reorg), describe(control.delivered)))
    if not (control.ok_after_reorg and control.ok_later and delivered_exactly_once(control.delivered)) then
        harness.setup_error("control scenario failed; the scripted node does not drive the listener as expected")
    end

    -- Defect scenario: depth 2 replaced by 1 block, so the tip and the head move back by one block.
    local shorter = scenario(1)
    print(string.format("shorter branch (depth 2 -> 1 block): tip %d head %d, old head %d canonical %s; poll %s",
        shorter.new_tip, shorter.new_head, shorter.old_head, tostring(shorter.old_head_canonical),
        shorter.ok_after_reorg and (shorter.ok_later and "ok" or ("ERROR later: " .. shorter.err_later))
            or ("ERROR: " .. shorter.err_after_reorg)))
    if not shorter.old_head_canonical or shorter.new_head >= shorter.old_head or shorter.new_head < 10 then
        harness.setup_error("scenario precondition: the old head must stay canonical and the new head must be lower")
    end
    if not shorter.ok_after_reorg then
        return harness.expect(false, "R4/section 4: a reorganization shallower than the input policy, which leaves "
            .. "every block the listener acted on canonical (old head " .. shorter.old_head .. "), stopped the "
            .. "listener: " .. shorter.err_after_reorg)
    end
    if not shorter.ok_later then
        return harness.expect(false, "R4: the listener failed once the head moved forward again: " .. shorter.err_later)
    end
    print("delivered after the reorganization: " .. describe(shorter.delivered))
    return harness.expect(delivered_exactly_once(shorter.delivered),
        "R4: every input must be delivered exactly once, in order, across a within-policy reorganization")
end)
