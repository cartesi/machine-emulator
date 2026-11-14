-- R9-SUBJOURNAL-2: the PRT transaction journal (doc/recipes/prt-transactions.lua, methods:submit) samples the
-- latest block when a submit starts and, after its RPCs and the signing, discards the whole attempt
-- ({ waiting = true }, nothing stored or published) whenever the latest block hash changed, even though the
-- job's window is still open at the new tip and the caller's observation is still canonical. On a chain
-- whose blocks arrive faster than one submit, every attempt is discarded and the honest move is never sent.
--
-- The test runs the real journal, RPC client and cast signer against a private anvil (manual mining), with a
-- transfer job whose window [0, 1000) stays open for the whole test. "A block arrives during the submit" is
-- modelled deterministically by mining one empty block at a fixed point inside every submit:
--   control: no block arrives; the journal must publish at the first attempt (else: setup error, exit 2).
--   A: one block is mined while the keystore signs (the case prt-transactions-test.lua already exercises).
--   B: one block is mined right after eth_estimateGas, before signing.
-- Required (R4, "The honest operator observes the chain and submits its transactions within the dispute
-- clocks"): in A and B, within MAX_ATTEMPTS fresh-observation attempts the journal publishes the job at
-- nonce 0, and that transaction is then included with status 1. On audit/prt2 every attempt returns
-- { waiting = true } and nothing is published, so the test exits 1.
local harness = require("harness")

local PORT = tonumber(os.getenv("SUBJOURNAL2_PORT") or "28693")
local URL = "http://127.0.0.1:" .. PORT
local MAX_ATTEMPTS = 5
-- Well-known anvil test key (account 1 of the default mnemonic); the journal owns this account exclusively.
local KEY_JOURNAL = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

local function shell_ok(cmd)
    local ok, out = harness.sh(cmd)
    if not ok then
        error("command failed: " .. cmd .. "\n" .. tostring(out))
    end
    return (out:gsub("%s+$", ""))
end

harness.main(function()
    local json = require("dkjson")
    local rpc_client = require("prt-rpc")
    local transactions = require("prt-transactions")
    local signing = require("prt-signer")
    local eth = require("prt-ethereum")

    if harness.sh("cast chain-id --rpc-url " .. URL .. " >/dev/null 2>&1") then
        error("port " .. PORT .. " already answers; set SUBJOURNAL2_PORT to a free port")
    end
    local dir = shell_ok("mktemp -d")
    local pid = shell_ok(string.format("anvil --port %d --silent > '%s/anvil.log' 2>&1 & echo $!", PORT, dir))
    local function cleanup()
        os.execute("kill " .. pid .. " 2>/dev/null; sleep 0.2; kill -9 " .. pid .. " 2>/dev/null")
        os.execute("rm -rf '" .. dir .. "'")
    end

    local ok, res = xpcall(function()
        local up = false
        for _ = 1, 100 do
            if harness.sh("cast chain-id --rpc-url " .. URL .. " >/dev/null 2>&1") then
                up = true
                break
            end
            os.execute("sleep 0.1")
        end
        assert(up, "anvil did not start")
        local chain = rpc_client.new(URL, 30)
        local function rpc(method, args)
            local result, failure = chain:rpc(method, args)
            return assert(result, failure and json.encode(failure))
        end
        rpc("evm_setAutomine", { false })
        shell_ok(string.format("printf pw > '%s/pw'", dir))
        shell_ok(string.format(
            "cast wallet import journal --keystore-dir '%s/keys' --private-key %s --unsafe-password pw >/dev/null",
            dir, KEY_JOURNAL))
        local signer = signing.new(dir .. "/keys/journal", dir .. "/pw")
        local baseline = rpc("evm_snapshot", {})

        local function observe()
            local n, hash = chain:head()
            return { head = n, hash = hash }
        end
        local intent = {
            key = "work",
            kind = "transfer",
            to = "0x0000000000000000000000000000000000001234",
            data = "0x",
            value = "0",
            first = 0,
            last = 1000,
            context = { epoch = "1" },
        }

        -- inject(): installs the "block arrives during submit" hook; returns a function that removes it
        local function run(name, inject)
            assert(rpc("evm_revert", { baseline }), "evm_revert failed")
            baseline = rpc("evm_snapshot", {})
            local manager = transactions.new({ chain = chain, path = dir .. "/journal-" .. name .. ".json" })
            local remove = inject and inject() or function() end
            local outcomes, published = {}, nil
            local attempts = 0
            local hook_ok, hook_err = pcall(function()
                for attempt = 1, MAX_ATTEMPTS do
                    attempts = attempt
                    local before = chain:head()
                    local result = manager:submit(signer, intent, observe())
                    local after = chain:head()
                    local kind = result.published and "published" or result.waiting and "waiting"
                        or result.blocked and ("blocked:" .. result.blocked) or result.rejected and "rejected"
                        or json.encode(result)
                    outcomes[#outcomes + 1] = string.format("tip %d->%d %s", before, after, kind)
                    if result.published then
                        published = result
                        return
                    end
                    if not result.waiting then
                        error("unexpected submit result: " .. json.encode(result))
                    end
                end
            end)
            remove()
            if not hook_ok then
                error(hook_err, 0)
            end
            local included
            if published then
                rpc("evm_mine", {})
                local receipt = rpc("eth_getTransactionReceipt", { published.candidate.hash })
                if receipt ~= json.null then
                    included = { block = eth.small(receipt.blockNumber), status = eth.small(receipt.status) }
                end
            end
            local good = published ~= nil and published.candidate.nonce == 0 and published.publication_error == nil
                and included ~= nil and included.status == 1
            io.stderr:write(string.format("%s: %d attempt(s): %s; %s\n", name, attempts, table.concat(outcomes, ", "),
                published and string.format("published nonce %d, %s", published.candidate.nonce,
                    included and string.format("included in block %d with status %d", included.block,
                        included.status) or "not included")
                    or "nothing published"))
            return good
        end

        local control = run("control", nil)
        if not control then
            error("setup: the journal did not publish when no block arrived during the submit")
        end
        local during_sign = run("A (block mined while signing)", function()
            local sign = signer.sign
            signer.sign = function(self, transaction)
                local raw, hash = sign(self, transaction)
                rpc("evm_mine", {})
                return raw, hash
            end
            return function()
                signer.sign = nil
            end
        end)
        local after_estimate = run("B (block mined after eth_estimateGas)", function()
            local original = chain.rpc
            chain.rpc = function(self, method, params)
                local result, failure = original(self, method, params)
                if method == "eth_estimateGas" then
                    assert(original(self, "evm_mine", {}))
                end
                return result, failure
            end
            return function()
                chain.rpc = nil
            end
        end)
        return { a = during_sign, b = after_estimate }
    end, debug.traceback)
    cleanup()
    if not ok then
        error(res, 0)
    end
    return harness.expect(res.a and res.b, string.format(
        "R4: with the job's window [0, 1000) open and the observation canonical, a block arriving during each "
            .. "submit must not stop the journal from publishing within %d attempts "
            .. "(A, block while signing: %s; B, block after eth_estimateGas: %s)",
        MAX_ATTEMPTS, res.a and "published" or "never published", res.b and "published" or "never published"))
end)
