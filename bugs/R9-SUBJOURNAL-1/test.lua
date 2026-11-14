-- R9-SUBJOURNAL-1: the PRT transaction journal (doc/recipes/prt-transactions.lua) prices a large transaction above
-- the RPC fee cap that geth and reth enforce by default (--rpc.txfeecap = 1 ether, checked on gas * maxFeePerGas in
-- eth_sendRawTransaction), although a max fee under the cap would be included by the next block. The node refuses
-- every candidate, the journal returns { published = true, publication_error = -32000 } (no "blocked" result, so the
-- bridge reports no anomaly), stores a new full candidate every bump interval, and after its 100 gwei ceiling starts
-- over at the same over-cap fee. The honest move is never published.
--
-- Setup: a private anvil (own port, stopped at the end), the recipe's anvil parameters, a gas-burning contract whose
-- call, padded with 94 000 calldata bytes like a large leaf proof, makes eth_estimateGas report about 6.3 M gas (the
-- journal signs 2 x estimate, about 12.6 M, like a winLeafMatch delivering a 64 KiB input: Dave's Gas.WIN_LEAF_MATCH
-- is 5.536 M plus 16 gas per proof byte). Anvil has no fee cap, so chain.publish is wrapped to refuse exactly as
-- geth's SubmitTransaction -> checkTxFee(maxFeePerGas, gas, 1 ether) does: it decodes the raw transaction with cast
-- and refuses it when gas * maxFeePerGas > 1 ether, otherwise forwards it to anvil. The journal runs with crisium's
-- defaults (bump every 3 blocks by 15 %, priority 1..10 gwei, --max-fee 100 gwei) and is called once per block, as
-- the bridge does, while the base fee stays fixed.
--
-- Control: base fee 38 gwei. The first candidate (2 * 38 + 1 = 77 gwei, 0.97 ether) passes the cap and is mined.
-- Test: base fee 40 gwei for 30 blocks. A max fee of base + 1 gwei tip costs about 0.52 ether and is under the cap,
-- so a transaction exists that the node accepts and the next block includes. Required (R4, "The honest operator
-- observes the chain and submits its transactions within the dispute clocks"): the job is mined within the window.
local harness = require("harness")

harness.main(function()
    local json = require("dkjson")
    local socket = require("socket")
    local evmu = require("cartesi.evmu")
    local command = require("prt-command")
    local rpc_client = require("prt-rpc")
    local signing = require("prt-signer")
    local transactions = require("prt-transactions")

    local GWEI = 1000000000
    local FEECAP = evmu.bint("1000000000000000000") -- geth/reth default --rpc.txfeecap (1 ether)
    local WINDOW = tonumber(os.getenv("WINDOW_BLOCKS") or "30")
    local PAD = 94000 -- calldata bytes of a large leaf proof
    local ITERATIONS = 119000 -- burner loop count: estimate about 6.3 M with the padding

    local ok_tmp, tmp_out = harness.sh("mktemp -d " .. (os.getenv("TMPDIR") or "/tmp") .. "/r9-subjournal-1.XXXXXX")
    local dir = ok_tmp and tmp_out and tmp_out:gsub("%s+$", "")
    if not dir or dir == "" then
        error("mktemp failed")
    end
    local anvil_pid

    local function cleanup()
        if anvil_pid then
            os.execute("kill " .. anvil_pid .. " 2>/dev/null; sleep 0.2; kill -9 " .. anvil_pid .. " 2>/dev/null")
        end
        os.execute("rm -rf '" .. dir .. "'")
    end

    local function body()
        -- a free port of our own
        local probe = assert(socket.bind("127.0.0.1", 0))
        local _, port = probe:getsockname()
        probe:close()
        local url = "http://127.0.0.1:" .. port
        -- the recipe's anvil parameters (doc/recipes/prt-demo.sh run_anvil), on our port
        local ok, out = harness.sh(string.format(
            "cd '%s' && (anvil --host 127.0.0.1 --port %d --accounts 10 --balance 10000 --hardfork prague "
                .. "--timestamp 1780000000 --prune-history 256 --silent > anvil.log 2>&1 & echo $!)",
            dir, port))
        anvil_pid = ok and out:match("(%d+)")
        if not anvil_pid then
            error("cannot start anvil")
        end
        local chain = rpc_client.new(url)
        local up = false
        for _ = 1, 100 do
            local okc, n = pcall(chain.rpc, chain, "eth_blockNumber", {})
            if okc and n then
                up = true
                break
            end
            socket.sleep(0.1)
        end
        if not up then
            error("anvil did not start")
        end
        local function rpc(method, args)
            local r, f = chain:rpc(method, args)
            if f then
                error(method .. ": " .. json.encode(f))
            end
            return r
        end

        -- player key (mnemonic index 1, as prt-demo.sh imports its players)
        os.execute("mkdir -p '" .. dir .. "/wallets' && chmod 700 '" .. dir .. "/wallets'")
        local wf = assert(io.open(dir .. "/wallets/password", "w"))
        wf:write("local-prt-demo\n")
        wf:close()
        local okw = harness.sh(string.format(
            "cd '%s' && CAST_UNSAFE_PASSWORD=local-prt-demo cast wallet import player --keystore-dir wallets "
                .. "--mnemonic 'test test test test test test test test test test test junk' --mnemonic-index 1 "
                .. ">/dev/null 2>&1 && echo ok",
            dir))
        if not okw then
            error("cast wallet import failed")
        end
        local signer = signing.new(dir .. "/wallets/player", dir .. "/wallets/password")

        -- gas burner: loops calldataload(0) times (40 gas per iteration), ignores the rest of the calldata
        local runtime = "6000355b8015601057600190036003565b00"
        local init = "6012600c60003960126000f3" .. runtime
        local deployer = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        rpc("evm_setAutomine", { false })
        local h = rpc("eth_sendTransaction", { { from = deployer, data = "0x" .. init, gas = "0x100000" } })
        rpc("evm_mine", {})
        local deployed = rpc("eth_getTransactionReceipt", { h })
        local burner = deployed ~= json.null and deployed.contractAddress
        if type(burner) ~= "string" or rpc("eth_getCode", { burner, "latest" }) ~= "0x" .. runtime then
            error("burner deployment failed")
        end
        local data = string.format("0x%064x", ITERATIONS) .. string.rep("5a", PAD)

        -- geth's SubmitTransaction: checkTxFee(tx.GasPrice() = maxFeePerGas, tx.Gas(), RPCTxFeeCap = 1 ether)
        local stats
        local publish = chain.publish
        function chain:publish(raw)
            local decoded = rpc_client.decode_json(command.run({ "cast", "decode-transaction" }, raw))
            local fee = evmu.bint(decoded.gas) * evmu.bint(decoded.maxFeePerGas)
            if fee > FEECAP then
                stats.refused = stats.refused + 1
                return nil, { code = -32000, message = "tx fee exceeds the configured cap (1.00 ether)" }
            end
            stats.accepted = stats.accepted + 1
            return publish(self, raw)
        end

        local baseline = rpc("evm_snapshot", {})

        local function scenario(name, base_gwei)
            assert(rpc("evm_revert", { baseline }))
            baseline = rpc("evm_snapshot", {})
            stats = { refused = 0, accepted = 0, outcomes = {}, fees = {} }
            local base = base_gwei * GWEI
            local function mine()
                rpc("anvil_setNextBlockBaseFeePerGas", { string.format("0x%x", base) })
                rpc("evm_mine", {})
            end
            mine()
            mine()
            local path = dir .. "/journal-" .. name .. ".json"
            local manager = transactions.new({ chain = chain, path = path })
            local intent = {
                key = "winLeafMatch-like",
                kind = "winLeafMatch",
                to = burner,
                data = data,
                value = "0",
                first = 0,
                last = 1 << 40,
                context = { epoch = "1", root = "fixture" },
            }
            local mined_at, gas
            for b = 1, WINDOW do
                local n, hash = chain:head()
                local r = manager:submit(signer, intent, { head = n, hash = hash })
                local key = r.published and (r.publication_error and "published(refused:" .. r.publication_error .. ")"
                    or "published") or r.blocked or (r.waiting and "waiting") or (r.rejected and "rejected") or "?"
                stats.outcomes[key] = (stats.outcomes[key] or 0) + 1
                if r.candidate then
                    gas = r.candidate.gas
                    stats.fees[#stats.fees + 1] = string.format("%.2f", tonumber(r.candidate.max_fee) / GWEI)
                end
                mine()
                local receipt = manager:receipt(intent.key)
                if receipt then
                    mined_at = b
                    stats.status = tonumber(receipt.status)
                    break
                end
            end
            local account = manager.state.accounts[signer.address]
            local stored = 0
            if account and account.nonces["0"] then
                stored = #account.nonces["0"].candidates
            end
            local f = io.open(path, "rb")
            local size = f and #f:read("a") or 0
            if f then
                f:close()
            end
            local cheapest = gas and (evmu.bint(base) + evmu.bint(GWEI)) * evmu.bint(gas)
            io.stderr:write(string.format(
                "%s: base fee %d gwei, gas limit %s (2 x estimate), node fee cap admits max fee <= %.2f gwei\n",
                name, base_gwei, tostring(gas), gas and tonumber(tostring(FEECAP // evmu.bint(gas))) / GWEI or 0))
            io.stderr:write(string.format("%s: max fees signed (gwei): %s\n", name, table.concat(stats.fees, " ")))
            io.stderr:write(string.format(
                "%s: journal outcomes %s; node accepted %d, refused %d (fee cap); candidates stored at nonce 0: %d; "
                    .. "journal %d bytes; account nonce %d; %s\n",
                name, json.encode(stats.outcomes), stats.accepted, stats.refused, stored, size,
                manager:nonce(signer.address),
                mined_at and string.format("mined after %d block(s), status %d", mined_at, stats.status)
                    or string.format("NOT mined within %d blocks", WINDOW)))
            if cheapest then
                io.stderr:write(string.format("%s: max fee base + 1 gwei would cost %.3f ether (%s the cap)\n", name,
                    tonumber(tostring(cheapest)) / 1e18, cheapest <= FEECAP and "under" or "over"))
            end
            return mined_at, gas, cheapest
        end

        local control_mined, control_gas = scenario("control", 38)
        if not control_gas or control_gas < 12000000 or control_gas > 13200000 then
            error("unexpected gas limit " .. tostring(control_gas) .. " (want about 12.6 M)")
        end
        if not control_mined then
            error("control: a candidate under the fee cap was not mined; the setup is broken")
        end
        local mined, gas, cheapest = scenario("test", 40)
        if not gas or not cheapest or cheapest > FEECAP then
            error("test: no transaction under the cap exists at this base fee; the setup is broken")
        end
        return harness.expect(mined ~= nil, string.format(
            "R4: the honest operator submits its transactions within the dispute clocks: at base fee 40 gwei a max "
                .. "fee under the node's 1 ether cap is includable, so the job must be mined within %d blocks",
            WINDOW))
    end

    local ok, res = xpcall(body, debug.traceback)
    cleanup()
    if not ok then
        error(res)
    end
    return res
end)
