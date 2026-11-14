-- R3-VARSCHED-1: the PRT bridge's transaction journal preflights a job (eth_call, eth_estimateGas) in the
-- context of the latest block (block.number = tip) although the transaction it would send can be included
-- at tip + 1 at the earliest, and although the journal itself treats the job as includable when
-- tip + 1 >= intent.first. A job whose validity STARTS at a block `first` (winMatchByTimeout from the
-- opponent's responderDeadline, winInnerTournament from resultAt) therefore reverts in the preflight at
-- tip = first - 1, is marked rejected for that tip, and is sent only at tip = first. When the window is one
-- block long, [D, D + 1), the honest win is never sent.
--
-- Part 1 (real node): the real journal (prt-transactions.lua), real RPC client (prt-rpc.lua) and real
--   signer (prt-signer.lua) against a private anvil, with a contract whose call is valid from block D.
--   Required: at tip D - 1, submit of a job whose window is [D, D + 1) publishes a transaction that the
--   next block (D) includes successfully. Control in the same run: a transaction with the same call, sent
--   at tip D - 1 by another account, is included in block D with status 1.
-- Part 2 (bridge): the real prt-bridge.lua tick/attempt/jobs and the real journal over a mock chain whose
--   eth_call / eth_estimateGas evaluate validity at the requested block's number (what part 1 observes on
--   anvil). Required: the honest winMatchByTimeout of a match whose opponent's responderDeadline is D lands
--   inside its window when every published transaction is included in the next block.
--   B (asserted): one-block window [D, D + 1). A (informational): window [D, D + 6).
local harness = require("harness")

local PORT = tonumber(os.getenv("VARSCHED_PORT") or "28631")
local URL = "http://127.0.0.1:" .. PORT
-- Well-known anvil test keys (accounts 0 and 1 of the default mnemonic).
local KEY_DEPLOYER = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
local KEY_JOURNAL = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
local KEY_CONTROL = KEY_DEPLOYER -- the control uses an account the journal does not own
local D = 10 -- first block at which the gated call is valid

local function shell_ok(cmd)
    local ok, out = harness.sh(cmd)
    if not ok then
        error("command failed: " .. cmd .. "\n" .. tostring(out))
    end
    return (out:gsub("%s+$", ""))
end

local function part1(dir)
    local json = require("dkjson")
    local rpc = require("prt-rpc")
    local journal = require("prt-transactions")
    local signers = require("prt-signer")
    local eth = require("prt-ethereum")

    local probe = harness.sh("cast chain-id --rpc-url " .. URL .. " 2>/dev/null")
    if probe then
        error("port " .. PORT .. " already answers; set VARSCHED_PORT to a free port")
    end
    local pid = shell_ok(string.format("anvil --port %d --silent > '%s/anvil.log' 2>&1 & echo $!", PORT, dir))
    local function stop()
        os.execute("kill " .. pid .. " 2>/dev/null; sleep 0.2; kill -9 " .. pid .. " 2>/dev/null")
    end
    local ok, res = xpcall(function()
        local chain = rpc.new(URL, 10)
        for _ = 1, 100 do
            if harness.sh("cast chain-id --rpc-url " .. URL .. " >/dev/null 2>&1") then
                break
            end
            os.execute("sleep 0.1")
        end
        -- Gate: runtime "if (block.number < D) revert(); stop"
        --   60 DD 43 10 60 08 57 00 5b 60 00 80 fd   (13 bytes), deployed by a 12-byte init code.
        local runtime = string.format("60%02x431060085700" .. "5b600080fd", D)
        local init = "600d600c600039600d6000f3" .. runtime
        local deployed = json.decode(shell_ok(string.format(
            "cast send --json --rpc-url %s --private-key %s --create 0x%s", URL, KEY_DEPLOYER, init)))
        local gate = assert(deployed.contractAddress, "gate not deployed")
        local tip = chain:head()
        assert(tip < D - 1, "gate deployed too late")
        chain:rpc("anvil_mine", { string.format("0x%x", D - 1 - tip) })
        tip = chain:head()
        assert(tip == D - 1, "could not move the tip to D - 1")

        shell_ok(string.format("printf pw > '%s/pw'", dir))
        shell_ok(string.format(
            "cast wallet import journal --keystore-dir '%s/keys' --private-key %s --unsafe-password pw >/dev/null",
            dir, KEY_JOURNAL))
        local signer = signers.new(dir .. "/keys/journal", dir .. "/pw")
        local transactions = journal.new({ chain = chain, path = dir .. "/journal.json" })
        local head, hash = chain:head()
        local result = transactions:submit(signer, {
            key = "gate",
            kind = "winMatchByTimeout",
            first = D,
            last = D + 1,
            to = gate,
            data = "0x",
            value = "0",
        }, { head = head, hash = hash })
        local lines = { string.format("part 1 (anvil): gated call valid from block %d; journal submit at tip %d "
            .. "for window [%d, %d):", D, tip, D, D + 1) }
        local landed
        if result.published then
            for _ = 1, 50 do -- anvil mines it at once (automine); allow it a moment
                local receipt = chain:rpc("eth_getTransactionReceipt", { result.candidate.hash })
                if receipt ~= json.null then
                    landed = { block = eth.small(receipt.blockNumber), status = eth.small(receipt.status) }
                    break
                end
                os.execute("sleep 0.1")
            end
            lines[#lines + 1] = string.format("  journal published nonce %d; %s", result.candidate.nonce,
                landed and string.format("included in block %d with status %d", landed.block, landed.status)
                    or "not included")
        elseif result.rejected then
            lines[#lines + 1] = string.format("  journal returned rejected (preflight revert code %s: %s), nothing sent",
                tostring(result.rejected.code), tostring(result.rejected.message))
        else
            lines[#lines + 1] = "  journal returned " .. json.encode(result)
        end
        local control
        if not result.published then
            -- Nothing was sent, so the tip is still D - 1: show that the next block would include the call.
            assert(chain:head() == D - 1, "setup: the tip moved")
            local receipt = json.decode(shell_ok(string.format(
                "cast send --json --gas-limit 100000 --rpc-url %s --private-key %s %s 0x", URL, KEY_CONTROL, gate)))
            control = { block = eth.small(receipt.blockNumber), status = eth.small(receipt.status) }
            lines[#lines + 1] = string.format("  control: the same call sent as a transaction at tip %d is included "
                .. "in block %d with status %d", D - 1, control.block, control.status)
            if control.block ~= D or control.status ~= 1 then
                error("setup: control transaction did not succeed in block " .. D .. "\n" .. table.concat(lines, "\n"))
            end
        end
        return {
            lines = lines,
            fine = landed ~= nil and landed.block == D and landed.status == 1,
        }
    end, debug.traceback)
    stop()
    if not ok then
        error(res, 0)
    end
    return res
end

local function part2(dir)
    local json = require("dkjson")
    local bridge = require("prt-bridge")
    local journal = require("prt-transactions")
    local prt = require("prt")
    local geometry = prt.new_geometry(10)

    local function block_hash(n)
        return string.format("0x%064x", n)
    end
    -- Block context of eth_call / eth_estimateGas, as anvil and geth define it: a block hash or number runs
    -- with that block's number, "pending" with the next one (an optional block override of the number wins).
    local current_tip
    local function number_of(block, overrides)
        if overrides and overrides.number then
            return tonumber(overrides.number)
        end
        if type(block) == "table" then
            return tonumber(block.blockHash:sub(3), 16)
        elseif block == "pending" then
            return current_tip + 1
        elseif block == "latest" then
            return current_tip
        end
        return tonumber(block)
    end

    -- Dd: responderDeadline of the opponent (first block the honest timeout win is valid; a running clock is
    -- expired at its deadline). E: first block at which the win is no longer valid (the honest clock is
    -- paused with E - Dd blocks left, and the win needs remaining > overdue).
    local function scenario(name, Dd, E)
        local tip = Dd - 3
        local published, first_publication, log, counter = {}, {}, {}, 0
        local signer = {
            address = "0x" .. string.rep("aa", 20),
            sign = function(_, candidate)
                counter = counter + 1
                local hash = string.format("0x%064x", 0xbeef0000 + counter)
                published[candidate.nonce] = published[candidate.nonce] or {}
                table.insert(published[candidate.nonce], { hash = hash, action = candidate.action })
                first_publication[candidate.nonce] = first_publication[candidate.nonce] or tip
                return string.format("0x%02x", candidate.nonce), hash
            end,
        }
        -- Every published nonce is included in the block after its first publication.
        local function mined_count(at)
            local n = 0
            while first_publication[n] and first_publication[n] + 1 <= at do
                n = n + 1
            end
            return n
        end
        local function find(hash)
            for nonce, list in pairs(published) do
                for i, c in ipairs(list) do
                    if c.hash == hash then
                        return nonce, i, #list
                    end
                end
            end
        end
        local function valid(data, n)
            if data == "0x" .. harness.hex("winMatchByTimeout") then
                return n >= Dd and n < E
            end
            return true
        end
        local chain = {}
        function chain.head()
            return tip, block_hash(tip)
        end
        function chain.is_canonical()
            return true
        end
        function chain.simulate(_, _, _, data, _, block, _, overrides)
            current_tip = tip
            if valid(data, number_of(block, overrides)) then
                return "0x", nil
            end
            return nil, { code = 3, message = "execution reverted" }
        end
        function chain.publish(_, raw)
            local list = published[tonumber(raw:sub(3), 16)]
            return list[#list].hash
        end
        function chain.rpc(_, method, params)
            if method == "eth_chainId" then
                return "0x7a69"
            elseif method == "eth_getBlockByNumber" then
                local w = params[1]
                local n = w == "latest" and tip or w == "finalized" and 0 or tonumber(w)
                return {
                    number = string.format("0x%x", n),
                    hash = block_hash(n),
                    baseFeePerGas = "0x2540be400",
                    gasLimit = "0x1c9c380",
                }
            elseif method == "eth_getTransactionCount" then
                return string.format("0x%x", mined_count(tip))
            elseif method == "eth_getTransactionReceipt" then
                local nonce, index, count = find(params[1])
                if nonce and index == count and nonce < mined_count(tip) then
                    local at = first_publication[nonce] + 1
                    return {
                        transactionHash = params[1],
                        blockNumber = string.format("0x%x", at),
                        blockHash = block_hash(at),
                        status = "0x1",
                        gasUsed = "0x5208",
                    }
                end
                return json.null
            elseif method == "eth_getTransactionByHash" then
                return { hash = params[1] }
            elseif method == "eth_maxPriorityFeePerGas" then
                return "0x3b9aca00"
            elseif method == "eth_estimateGas" then
                current_tip = tip
                if valid(params[1].data, number_of(params[2], params[4])) then
                    return "0x5208"
                end
                return nil, { code = 3, message = "execution reverted" }
            elseif method == "eth_getBalance" then
                return "0xde0b6b3a7640000"
            end
            error("unexpected rpc " .. tostring(method))
        end
        local transactions = journal.new({ chain = chain, path = dir .. "/" .. name:sub(1, 1) .. ".json" })
        local submit = transactions.submit
        function transactions.submit(self, s, intent, observation)
            local result = submit(self, s, intent, observation)
            if result.published then
                log[#log + 1] = string.format("tip %d: published %s at nonce %d", tip, result.candidate.action,
                    result.candidate.nonce)
            elseif result.rejected then
                log[#log + 1] = string.format("tip %d: %s preflight reverted", tip, intent and intent.kind or "cancel")
            end
            return result
        end
        local client = bridge.new({
            geometry = geometry,
            chain = chain,
            transactions = transactions,
            abi = {},
            root = "root",
            factory = "factory",
            consensus = "consensus",
            player = {
                report_anomaly = function() end,
                event_handler = {
                    win_match_by_timeout = function()
                        return { computation_hash_left = "L", computation_hash_right = "R" }
                    end,
                },
            },
            signer = signer,
            label = "honest",
            epoch = 0,
        })
        client.claims = { root = { root = "H" } }
        -- Stub: calldata preparation (the mock chain recognizes the action by its calldata).
        function client.prepare(_, job)
            return { signer = signer, to = "0x" .. string.rep("11", 20), data = "0x" .. harness.hex(job.kind) }
        end
        local context = {
            address = "root",
            creation = { log = { blockHash = block_hash(0), logIndex = "0x0" } },
            descriptor = { height = geometry.mcycle_height, kind = 1, startInstant = 0, allowance = 1 },
            joined = { H = { submitter = signer.address } },
            standing = { matchCount = 1 },
        }
        -- The honest claim H is commitment two at the top height: commitment one is on turn and stops answering.
        local honest = {
            name = "MatchCreated",
            address = "root",
            matchIdHash = "honest",
            one = "X",
            two = "H",
            responderDeadline = Dd,
            eliminableAt = E,
            log = { blockHash = block_hash(1), logIndex = "0x1" },
        }
        -- Stub: the bridge's observation of the tournament.
        function client.refresh()
            return {
                ready = true,
                head = tip,
                hash = block_hash(tip),
                tip = tip,
                tip_hash = block_hash(tip),
                order = { context },
                contexts = { root = context },
                events = { honest },
                matches = { ["root:honest"] = honest },
                deleted = {},
                recovered = {},
            }
        end
        -- Driver (as crisium): one pass at every new tip, and again at once after a pass that returned "again".
        local landed
        while tip < E and not landed do
            for _ = 1, 6 do
                local _, again = client:tick()
                if not again then
                    break
                end
            end
            for nonce, list in pairs(published) do
                if list[#list].action == "winMatchByTimeout" and nonce < mined_count(tip + 1) then
                    landed = landed or first_publication[nonce] + 1
                end
            end
            tip = tip + 1
        end
        local lines = { name .. ":" }
        for _, line in ipairs(log) do
            lines[#lines + 1] = "  " .. line
        end
        lines[#lines + 1] = string.format("  honest winMatchByTimeout valid in blocks [%d, %d): %s", Dd, E,
            landed and ("lands in block " .. landed) or "NEVER lands")
        return landed, lines
    end

    local a, la = scenario("A (informational): next-block inclusion, window [20, 26)", 20, 26)
    local b, lb = scenario("B: next-block inclusion, one-block window [20, 21)", 20, 21)
    local lines = { "part 2 (bridge over mock chain):" }
    for _, l in ipairs(la) do
        lines[#lines + 1] = l
    end
    for _, l in ipairs(lb) do
        lines[#lines + 1] = l
    end
    return { lines = lines, fine = b ~= nil and b >= 20 and b < 21, a = a, b = b }
end

harness.main(function()
    local tmp = os.getenv("TMPDIR") or "/tmp"
    local dir = shell_ok("mktemp -d '" .. tmp .. "/varsched.XXXXXX'")
    local ok, r1, r2 = xpcall(function()
        return part1(dir), part2(dir)
    end, debug.traceback)
    os.execute("rm -rf '" .. dir .. "'")
    if not ok then
        error(r1, 0)
    end
    for _, l in ipairs(r1.lines) do
        io.stderr:write(l, "\n")
    end
    for _, l in ipairs(r2.lines) do
        io.stderr:write(l, "\n")
    end
    return harness.expect(r1.fine and r2.fine, string.format(
        "R4 ('The honest operator observes the chain and submits its transactions within the dispute clocks'): "
            .. "a job valid from the next block must be sent so that the next block includes it "
            .. "(part 1 journal on anvil: %s; part 2 one-block window: %s, informational window [20, 26): %s)",
        r1.fine and "included in block D" or "not sent", r2.b and ("lands in " .. r2.b) or "never lands",
        r2.a and ("lands in " .. r2.a) or "never lands"))
end)
