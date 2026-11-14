-- R1-A7-2: the root allowance of the released Dave referee has no term for executing the sealed epoch.
--
-- On a private anvil (chain id 11155111, the Sepolia registration of Dave's released Deployment.s.sol: 12 s
-- blocks, TESTNET censorship budget C = 8 h, inclusion budget G = 5 min, commitment budget T = 120 min), with
-- the released Dave contracts (bugs/harness/work/dave/released), this test:
--   1. settles epoch 0 of a bare-metal application whose guest spends 2^30 mcycles on every input and accepts it;
--   2. lets an input sender fill the blocks before the earliest possible acceptStagedTournamentResult with
--      addInput transactions (one per input, the chain's real 30M block gas limit), and lets the HONEST side
--      stage and accept as early as the contracts allow, which seals the epoch and starts its root tournament;
--   3. models the honest operator as executing every sealed input as soon as it is in the mempool, at Dave's
--      own reference emulator speed (1.1 ns per mcycle, docs/dimensioning.md), with no per-input overhead,
--      no hashing and zero inclusion latency (all generous), and computes the first block at which it can
--      have its root commitment, whose last leaf is the state after the last sealed input;
--   4. mines to that block and sends the honest root joinTournament.
-- Required (THREAT_MODEL A7, R4): the honest claim can join the root tournament of every sealed epoch. The test
-- exits 1 if the referee refuses the join (TournamentIsClosed), 0 if it accepts it, 2 on setup errors.
local harness = require("harness")

local BLOCK_SECONDS = 12 -- Deployment.s.sol _registerChain(11155111, TESTNET, 12000 ms)
local CENSORSHIP_SECONDS = 8 * 3600 -- _registerChainKind(TESTNET, 8 hours)
local INCLUSION_SECONDS = 300 -- _getInclusionBudget() = 5 minutes
local GAS_LIMIT = 30000000 -- block gas limit (Ethereum's long-standing value; anvil's default)
local REF_NS_PER_MCYCLE = 1.1 -- Dave docs/dimensioning.md: "about 1.1 ns per big cycle" (unbroken run)
local FLOOD_INPUTS = tonumber(os.getenv("FLOOD_INPUTS") or "80000")
local STAGING_PERIOD = 10 -- claim staging period (blocks), as doc/recipes/prt-deploy.lua

harness.main(function()
    local cartesi = require("cartesi")
    local evmu = require("cartesi.evmu")
    local json = require("dkjson")
    local socket = require("socket")
    local rpcm = require("prt-rpc")
    local eth = require("prt-ethereum")

    local dave = os.getenv("HARNESS_WORK") .. "/dave/released"
    local prt_out = dave .. "/prt/contracts/out"
    local rollups_out = dave .. "/cartesi-rollups/contracts/out"
    local f = io.open(prt_out .. "/Tournament.sol/Tournament.json")
    if not f then
        harness.setup_error("released Dave build missing (bugs/harness/chain/build-dave.sh released)")
    end
    f:close()

    -- private anvil on a free port ------------------------------------------------------------------------
    local probe = assert(socket.bind("127.0.0.1", 0))
    local _, port = probe:getsockname()
    probe:close()
    local tmp = os.getenv("TMPDIR") or "/tmp"
    local logfile = string.format("%s/r1-a7-2-anvil-%d.log", tmp, port)
    local pidp = assert(io.popen(string.format(
        "anvil --host 127.0.0.1 --port %d --chain-id 11155111 --gas-limit %d --block-base-fee-per-gas 0 "
            .. "--hardfork prague --accounts 3 --balance 100000000 --order fees --prune-history 64 > %s 2>&1 & echo $!",
        port, GAS_LIMIT, logfile)))
    local anvil_pid = assert(tonumber(pidp:read("l")))
    pidp:close()
    local function stop_anvil()
        os.execute("kill " .. anvil_pid .. " 2>/dev/null")
        os.remove(logfile)
    end

    local ok, result = xpcall(function()
        local url = "http://127.0.0.1:" .. port
        local chain = rpcm.new(url, false)
        for _ = 1, 100 do
            local okc, r = pcall(chain.rpc, chain, "eth_chainId", {})
            if okc and r then break end
            socket.sleep(0.1)
        end
        assert(chain:rpc("eth_chainId", {}) == "0xaa36a7", "anvil did not start")
        local function rpc(method, params)
            local r, err = chain:rpc(method, params)
            assert(r ~= nil or err == nil, method .. ": " .. json.encode(err))
            return r, err
        end
        local function num(h) return math.tointeger(tonumber(h:sub(3), 16)) end
        local function hexn(n) return string.format("0x%x", n) end
        local function block_number() return num(rpc("eth_blockNumber", {})) end
        local accounts = rpc("eth_accounts", {})
        local deployer, honest, adversary = accounts[1]:lower(), accounts[2]:lower(), accounts[3]:lower()

        local function receipt_of(tx)
            local r = rpc("eth_getTransactionReceipt", { tx })
            return r ~= json.null and r or nil
        end
        local function wait_receipt(tx)
            for _ = 1, 500 do
                local r = receipt_of(tx)
                if r then return r end
                socket.sleep(0.01)
            end
            error("no receipt for " .. tx)
        end
        local function send(from, to, data, value, extra)
            local t = { from = from, to = to, data = data,
                value = value and ("0x" .. evmu.bint.tobase(evmu.bint(value), 16)) or nil }
            for k, v in pairs(extra or {}) do t[k] = v end
            local tx, err = chain:rpc("eth_sendTransaction", { t })
            assert(tx, "eth_sendTransaction: " .. json.encode(err))
            return tx
        end
        local function transact(from, to, data, value)
            local r = wait_receipt(send(from, to, data, value))
            assert(r.status == "0x1", "transaction reverted: " .. (to or "create"))
            return r
        end
        -- batched JSON-RPC over one connection, for the flood
        local function batch(requests)
            local body = json.encode(requests)
            local tcp = assert(socket.connect("127.0.0.1", port))
            local status, data = rpcm.exchange(tcp, "127.0.0.1:" .. port, "/", body)
            tcp:close()
            assert(status == 200, "batch HTTP " .. tostring(status))
            local resp = rpcm.decode_json(data)
            for _, r in ipairs(resp) do
                assert(not r.error, "batch error: " .. json.encode(r.error))
            end
            return resp
        end

        -- deploy the released contracts as doc/recipes/prt-deploy.lua does, with Sepolia's clock model ---
        local artifacts = {}
        local function artifact(name, dir)
            artifacts[name] = eth.artifact(dir or prt_out, name)
            return artifacts[name]
        end
        local function deploy(name, dir, types, args)
            local code = artifact(name, dir).bytecode.object
            assert(code:match("^0x%x+$"), "unlinked " .. name)
            if types then code = code .. eth.hex(evmu.encode_abi(types, args)):sub(3) end
            return assert(transact(deployer, nil, code).contractAddress):lower()
        end
        local zero_address = "0x" .. string.rep("00", 20)
        local implementation = deploy("Tournament")
        local stf = deploy("CartesiStateTransition")
        local provider = deploy("CanonicalTournamentParametersProvider", nil, "(uint64,uint64,uint64)",
            { BLOCK_SECONDS * 1000, CENSORSHIP_SECONDS, INCLUSION_SECONDS })
        local factory = deploy("MultiLevelTournamentFactory", nil, "(address,address,address)",
            { implementation, provider, stf })
        local input_box = deploy("InputBox", rollups_out)
        local app_factory = deploy("ApplicationFactory", rollups_out, "(address)", { zero_address })
        artifact("DaveConsensus", rollups_out)
        local dave_factory = deploy("DaveAppFactory", rollups_out, "(address,address,address)",
            { input_box, app_factory, factory })
        local abi = eth.abi({ artifacts.Tournament, artifacts.InputBox, artifacts.DaveConsensus,
            artifacts.DaveAppFactory })
        local function call(to, name, args, types, from)
            local r, err = chain:rpc("eth_call", { { from = from, to = to, data = abi:calldata(name, args or {}) },
                "latest" })
            assert(r, name .. " reverted: " .. json.encode(err))
            return evmu.decode_abi(types, assert(eth.raw(r)))
        end

        -- template: the spin-accept guest at its first manual yield (accepted, empty outputs root) ---------
        local machine <close> = cartesi.machine({
            ram = { length = 64 << 20, backing_store = { data_filename = "spin-accept.bin" } },
        })
        machine:run()
        assert(machine:read_reg("iflags_Y") == 1, "guest did not yield")
        local template_hash = machine:get_root_hash()
        local WORD = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE
        local function word(address)
            local a = address & ~(WORD - 1)
            return machine:read_memory(a, WORD), machine:get_proof(a, cartesi.HASH_TREE_LOG2_WORD_SIZE)
        end
        local response = {}
        response.iflags_y_data, response.iflags_y_proof = word(cartesi.machine:get_reg_address("iflags_Y"))
        response.htif_tohost_data, response.htif_tohost_proof = word(cartesi.machine:get_reg_address("htif_tohost"))
        response.tx_buffer_data, response.tx_buffer_proof = word(cartesi.AR_CMIO_TX_BUFFER_START)
        local validity_proof = eth.validity_proof(response, eth.hex(template_hash))

        local r = transact(deployer, dave_factory, abi:calldata("newDaveApp", {
            eth.hex(template_hash), STAGING_PERIOD, deployer, {}, { deployer, 0, 0, 0, zero_address }, eth.zero,
        }))
        local app, consensus
        for _, log in ipairs(r.logs) do
            local ev = abi:event(log)
            if ev and ev.name == "DaveAppCreated" then app, consensus = ev.appContract:lower(), ev.daveConsensus:lower() end
        end
        assert(app and consensus, "DaveAppCreated missing")
        local EPOCH_T = "(uint256,uint256,uint256,address,bool,uint256,bytes32,bytes32)"
        local DESC_T = "((bytes32,uint256,uint64,uint64,uint64,uint8,uint64,uint64))"
        local function descriptor(t)
            local d = call(t, "tournamentDescriptor", {}, DESC_T)[1]
            return { height = eth.small(d[4]), start = eth.small(d[7]), allowance = eth.small(d[8]) }
        end
        local function join_args(t, final_state)
            -- a commitment whose leaves all equal final_state (internally consistent; the root join checks
            -- only that final_state is its last leaf)
            local d = descriptor(t)
            local h, sib = final_state, {}
            for i = 1, d.height do
                sib[i] = eth.hex(h)
                h = cartesi.keccak256(h, h)
            end
            return { eth.hex(final_state), sib, sib[d.height], sib[d.height] }
        end
        local function bond(t) return call(t, "bondValue", {}, "(uint256)")[1] end

        -- epoch 0: one claim (the template, no inputs), wait for closure, stage --------------------------
        local e0 = call(consensus, "getCurrentSealedEpoch", {}, EPOCH_T)
        local t0 = e0[4]:lower()
        assert(e0[3] == evmu.bint(0), "epoch 0 should hold no input")
        transact(honest, t0, abi:calldata("joinTournament", join_args(t0, template_hash)), bond(t0))
        local d0 = descriptor(t0)
        local close0 = d0.start + d0.allowance -- first block at which epoch 0 is finished

        -- the honest operator's work per input: run one input of the flood on the template, count mcycles
        local payload = "x"
        local mc0 = machine:read_reg("mcycle")
        machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
            harness.encode_advance({ payload = payload, app_contract = cartesi.fromhex(app),
                msg_sender = cartesi.fromhex(adversary), index = 0 }), template_hash)
        local wall0 = os.clock()
        machine:run()
        local host_seconds = os.clock() - wall0
        local m_in = machine:read_reg("mcycle") - mc0
        assert(machine:read_reg("iflags_Y") == 1 and m_in > 0, "input not processed")
        local t_in = m_in * REF_NS_PER_MCYCLE * 1e-9

        -- the flood: addInput batched through a contract (Flood.sol), one block-filling transaction per block,
        -- low priority; the honest stage and accept go first in their blocks (high priority) ----------------
        local flood = assert(transact(adversary, nil, "0x" .. harness.read_file("Flood.bin"):gsub("%s", ""))
            .contractAddress):lower()
        local function flood_data(n)
            return evmu.encode_calldata_hex("flood(address,address,bytes,uint256)", { input_box, app, eth.hex(payload), n })
        end
        local function estimate(n)
            return num(rpc("eth_estimateGas", { { from = adversary, to = flood, data = flood_data(n), gas = hexn(GAS_LIMIT) } }))
        end
        local g100, g200 = estimate(100), estimate(200)
        local gas_per_input = (g200 - g100) // 100
        local per_tx = (GAS_LIMIT - (g100 - 100 * gas_per_input)) // gas_per_input - 2
        while estimate(per_tx) > GAS_LIMIT do per_tx = per_tx - 1 end
        local tx_gas = estimate(per_tx)
        local flood_txs = (FLOOD_INPUTS + per_tx - 1) // per_tx
        local accept_block = close0 + STAGING_PERIOD -- earliest block at which the epoch can be sealed
        local flood_start = math.min(accept_block - flood_txs - 2, close0 - 1)
        assert(flood_start > block_number() + 1, "epoch 0 too short for this flood")
        rpc("anvil_mine", { hexn(flood_start - 1 - block_number()) })
        rpc("evm_setAutomine", { false })
        local nonce = num(rpc("eth_getTransactionCount", { adversary, "latest" }))
        local inputs_of_tx, left = {}, FLOOD_INPUTS
        for i = 1, flood_txs do
            local n = math.min(per_tx, left)
            left = left - n
            local tx = send(adversary, flood, flood_data(n), nil, { gas = hexn(tx_gas), nonce = hexn(nonce + i - 1),
                maxFeePerGas = "0x1", maxPriorityFeePerGas = "0x1" })
            inputs_of_tx[tx] = n
        end
        local hi = { maxFeePerGas = hexn(10000000000), maxPriorityFeePerGas = hexn(1000000000) }
        local stage_tx, accept_tx
        local inputs_in_block = {}
        while true do
            local b = block_number()
            if b + 1 == close0 then
                stage_tx = send(honest, consensus, abi:calldata("stageTournamentResult", { 0, validity_proof }), nil, hi)
            elseif b + 1 == accept_block then
                accept_tx = send(honest, consensus, abi:calldata("acceptStagedTournamentResult", { 0 }), nil, hi)
            end
            rpc("evm_mine", {})
            local blk = rpc("eth_getBlockByNumber", { hexn(b + 1), false })
            local count = 0
            for _, tx in ipairs(blk.transactions) do
                local n = inputs_of_tx[tx]
                if n then
                    assert(wait_receipt(tx).status == "0x1", "flood transaction reverted")
                    count = count + n
                end
            end
            inputs_in_block[b + 1] = count
            if b + 1 >= accept_block then break end
        end
        local sr = wait_receipt(stage_tx)
        assert(sr.status == "0x1" and num(sr.blockNumber) == close0, "staging failed")
        local ar = wait_receipt(accept_tx)
        assert(ar.status == "0x1" and num(ar.blockNumber) == accept_block, "acceptance failed")
        -- drop the inputs that did not make it into the epoch, return to automine
        local pending = rpc("txpool_status", {})
        rpc("anvil_dropAllTransactions", {})
        rpc("evm_setAutomine", { true })

        local e1 = call(consensus, "getCurrentSealedEpoch", {}, EPOCH_T)
        assert(e1[1] == evmu.bint(1), "epoch 1 not sealed")
        local lower, upper = eth.small(e1[2]), eth.small(e1[3])
        local t1 = e1[4]:lower()
        local d1 = descriptor(t1)
        local sealed = upper - lower
        -- the accept transaction is first in its block: inputs of that block are not in epoch 1
        local counted = 0
        for b = flood_start, accept_block - 1 do counted = counted + (inputs_in_block[b] or 0) end
        assert(counted == sealed, string.format("sealed %d inputs, counted %d", sealed, counted))
        assert(d1.start == accept_block, "root tournament does not start at the sealing block")
        local expected_allowance = CENSORSHIP_SECONDS // BLOCK_SECONDS + 2 * (INCLUSION_SECONDS // BLOCK_SECONDS)
            + (7200 // BLOCK_SECONDS + 2 * (INCLUSION_SECONDS // BLOCK_SECONDS))
        assert(d1.allowance == expected_allowance, "unexpected root allowance " .. d1.allowance)

        -- the honest operator: sequential execution of the sealed inputs, each started no earlier than the
        -- beginning of the block that includes it (it reads the mempool), at the reference speed --------------
        local now = (flood_start - 1) * BLOCK_SECONDS
        for b = flood_start, accept_block - 1 do
            for _ = 1, inputs_in_block[b] or 0 do
                now = math.max(now, (b - 1) * BLOCK_SECONDS) + t_in
            end
        end
        local ready_block = math.max(accept_block + 1, math.ceil(now / BLOCK_SECONDS))
        local close1 = d1.start + d1.allowance

        print(string.format("referee: Sepolia model, C = %d s, G = %d s, T = 7200 s, %d s blocks",
            CENSORSHIP_SECONDS, INCLUSION_SECONDS, BLOCK_SECONDS))
        print(string.format("flood: %d inputs in %d batched transactions (%d gas per input, %d inputs and %d gas "
            .. "per transaction, %d-gas blocks) from block %d; epoch 1 sealed by the honest "
            .. "acceptStagedTournamentResult at block %d (first allowed block)",
            FLOOD_INPUTS, flood_txs, gas_per_input, per_tx, tx_gas, GAS_LIMIT, flood_start, accept_block))
        print(string.format("epoch 1: inputs [%d, %d) = %d inputs; %s left pending for epoch 2", lower, upper,
            sealed, tostring(pending and pending.pending)))
        print(string.format("root tournament: start block %d, allowance %d blocks, closes at block %d",
            d1.start, d1.allowance, close1))
        print(string.format("honest work: %d mcycles/input (guest), %.3f s/input at %.1f ns/mcycle "
            .. "(this host: %.3f s for one input, informative only)", m_in, t_in, REF_NS_PER_MCYCLE, host_seconds))
        print(string.format("honest root commitment ready at block %d at the earliest (%d blocks = %.1f h "
            .. "after the seal)", ready_block, ready_block - accept_block,
            (ready_block - accept_block) * BLOCK_SECONDS / 3600))
        local slack = close1 - (flood_start - 1)
        print(string.format("closure happens first while the reference speed is slower than %.2e mcycles/s "
            .. "(Dave reference %.2e, this host %.2e)", sealed * m_in / (slack * BLOCK_SECONDS),
            1e9 / REF_NS_PER_MCYCLE, m_in / host_seconds))

        -- the honest join, at the first block it can be included --------------------------------------
        if ready_block - 1 > block_number() then rpc("anvil_mine", { hexn(ready_block - 1 - block_number()) }) end
        local args = join_args(t1, cartesi.keccak256("honest final state of epoch 1"))
        local data = abi:calldata("joinTournament", args)
        local v = bond(t1)
        local sim, err = chain:rpc("eth_call", { { from = honest, to = t1, data = data,
            value = "0x" .. evmu.bint.tobase(v, 16) }, "pending" })
        local tx = send(honest, t1, data, v, { gas = hexn(3000000) })
        local jr = wait_receipt(tx)
        print(string.format("honest joinTournament in block %d: %s", num(jr.blockNumber),
            jr.status == "0x1" and "accepted" or ("REVERTED " .. json.encode(err and err.data or sim)
                .. ((err and tostring(err.data):find("0xac57beef", 1, true)) and " = TournamentIsClosed()" or ""))))
        if jr.status == "0x1" then
            local cs = call(t1, "commitmentStanding", { eth.hex(cartesi.keccak256(eth.raw(args[3]), eth.raw(args[4]))) },
                "((bool,bytes32,address,bool,uint64,uint64))")[1]
            print(string.format("honest clock: %d blocks of %d", eth.small(cs[6]), d1.allowance))
        end
        return harness.expect(jr.status == "0x1",
            "A7/R4: the honest claim must be able to join the root tournament of the epoch it defends after "
                .. "executing the inputs the seal assigned to it")
    end, debug.traceback)
    stop_anvil()
    if not ok then error(result, 0) end
    return result
end)
