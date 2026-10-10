-- Real signing, mempool, fee changes, mining, and reorgs on disposable Anvil.
local cast = require("prt-cast")
local transactions = require("prt-transactions")
local json = require("dkjson")
local util = require("cartesi.util")
local evmu = require("cartesi.evmu")
local chain = cast.new("http://127.0.0.1:8545")
local signer = { keystore = "wallets/player-0", password_file = "wallets/password" }
signer.address =
    cast.run({ "cast", "wallet", "address", "--keystore", signer.keystore, "--password-file", signer.password_file })
        :gsub("%s+$", "")
        :lower()
local destination = "0x0000000000000000000000000000000000000001"
local function rpc(method, args)
    return assert(chain:rpc(method, args))
end
local function observe()
    local n, hash = chain:head()
    return { head = n, hash = hash }
end
local function intent(key)
    return {
        key = key or "work",
        kind = "transfer",
        to = destination,
        data = "0x",
        value = "0",
        first = 0,
        last = 1000,
        context = { epoch = "1", root = "fixture" },
    }
end
local function mine(count, base_fee)
    for _ = 1, count or 1 do
        if base_fee then
            rpc("anvil_setNextBlockBaseFeePerGas", { string.format("0x%x", base_fee) })
        end
        rpc("evm_mine", {})
    end
end
rpc("evm_setAutomine", { false })
local baseline = rpc("evm_snapshot", {})
local index = 0
local function fresh(options)
    assert(rpc("evm_revert", { baseline }))
    baseline = rpc("evm_snapshot", {})
    index = index + 1
    destination = string.format("0x%040x", 4096 + index)
    local args = options or {}
    args.chain, args.path, args.bump_blocks = chain, "transactions-test-" .. index .. ".json", 2
    return transactions.new(args), args
end
local function submit(manager, job)
    return manager:submit(signer, job, observe())
end
local function successful(manager, key, hash)
    local receipt = assert(manager:receipt(key))
    assert(
        receipt.transactionHash == hash and tonumber(receipt.status) == 1,
        json.encode({ expected = hash, receipt = receipt })
    )
    return receipt
end

-- A fee surge leaves the original pending. Restart the tracker, then replace
-- it at the SAME nonce. No transaction receipt is needed to return from submit.
do
    local manager, args = fresh()
    local first = submit(manager, intent())
    assert(first.published and first.candidate.nonce == 0)
    assert(manager:pending(signer.address).hash == first.candidate.hash)
    assert(not manager:idle() and not manager:receipt("work"))
    assert(not submit(manager, intent()).published, "same-block retry published again")
    mine(1, 50000000000)
    assert(not manager:receipt("work"), "underpriced transaction was unexpectedly mined")
    assert(not submit(manager, intent()).published, "fee bump interval was ignored")
    mine(1, 50000000000)
    manager = transactions.new(args)
    local second = submit(manager, intent())
    assert(second.published and second.candidate.nonce == 0)
    assert(manager:pending(signer.address).hash == second.candidate.hash)
    assert(evmu.bint(second.candidate.max_fee) > evmu.bint(first.candidate.max_fee))
    assert(evmu.bint(second.candidate.priority_fee) > evmu.bint(first.candidate.priority_fee))
    mine()
    successful(manager, "work", second.candidate.hash)
    local delayed = { head = 0, hash = manager.state.genesis }
    assert(not manager:submit(signer, intent(), delayed).published, "unobserved mined work was submitted twice")
    assert(rpc("eth_getTransactionReceipt", { first.candidate.hash }) == json.null)
    assert(manager:idle() and manager:nonce(signer.address) == 1)
end
print("PRT transactions: gas surge, same-nonce replacement, and journal reload passed.")

-- Fee ceilings retain nonce ownership and keep observation available. If fees
-- fall again, publication can resume at the retained nonce.
do
    local manager = fresh({ max_fee = "10000000000", max_priority_fee = "2000000000" })
    assert(submit(manager, intent()).published)
    mine(2, 50000000000)
    local capped = submit(manager, intent())
    assert(capped.blocked == "fee ceiling" and not capped.published)
    assert(not manager:idle() and manager:nonce(signer.address) == 0)
    mine(1, 1000000000)
    if not manager:receipt("work") then
        local resumed = assert(submit(manager, intent()).candidate)
        assert(resumed.nonce == 0)
        mine()
        successful(manager, "work", resumed.hash)
    end
end

-- A dropped candidate and an underpriced replacement both retain the nonce.
-- Every publication can be reconstructed from the already-renamed journal.
do
    local manager, args = fresh()
    local first = submit(manager, intent()).candidate
    rpc("anvil_dropTransaction", { first.hash })
    mine(2)
    local publish = chain.publish
    function chain.publish(_, raw)
        local saved = assert(json.decode(util.read_file(args.path)))
        local candidates = saved.accounts[signer.address].nonces["0"].candidates
        assert(candidates[#candidates].raw == raw, "publication preceded persistence")
        assert(not util.read_file(args.path):find("wallets", 1, true), "journal contains signer configuration")
        return nil, { code = -32000, message = "replacement transaction underpriced" }
    end
    local rejected = submit(manager, intent())
    assert(rejected.published and rejected.publication_error == -32000 and manager:nonce(signer.address) == 0)
    chain.publish = publish
    mine(2)
    local retried = submit(manager, intent()).candidate
    assert(retried.nonce == 0 and evmu.bint(retried.priority_fee) > evmu.bint(rejected.candidate.priority_fee))
    mine()
    successful(manager, "work", retried.hash)
end
print("PRT transactions: fee ceiling, dropped transaction, underpriced replacement, and write-before-publish passed.")

-- Obsolete work is outbid immediately, without waiting for the bump interval.
do
    local manager = fresh()
    local original = submit(manager, intent()).candidate
    local canceled = submit(manager, nil).candidate
    assert(canceled.action == "cancel" and canceled.nonce == original.nonce)
    assert(canceled.to == signer.address and canceled.value == "0" and canceled.data == "0x")
    mine()
    assert(not manager:receipt("work"))
    assert(tonumber(rpc("eth_getTransactionReceipt", { canceled.hash }).status) == 1)
    assert(manager:idle())
end

-- Replacement is not revocation. An older candidate can win, including after
-- publication was acknowledged ambiguously. Receipts identify the actual hash.
do
    local manager = fresh()
    local first = submit(manager, intent()).candidate
    local publish = chain.publish
    function chain.publish()
        return nil, { code = -32000 }
    end
    assert(submit(manager, nil).published)
    chain.publish = publish
    mine()
    successful(manager, "work", first.hash)
    assert(manager:idle())
end

-- A reorg can reopen MULTIPLE previously consumed nonces. Loading the journal
-- must recover high_water, then overwrite each nonce before calling it idle.
do
    local manager, args = fresh()
    local rewind = rpc("evm_snapshot", {})
    local first = submit(manager, intent("one")).candidate
    mine()
    successful(manager, "one", first.hash)
    local second = submit(manager, intent("two")).candidate
    mine()
    assert(second.nonce == 1 and manager:idle())
    successful(manager, "two", second.hash)
    assert(rpc("evm_revert", { rewind }))
    manager = transactions.new(args)
    assert(not manager:receipt("one") and not manager:receipt("two"))
    local cancel0 = submit(manager, nil).candidate
    assert(cancel0.nonce == 0)
    mine()
    assert(not manager:idle(), "lost the higher resurrected nonce")
    local cancel1 = submit(manager, nil).candidate
    assert(cancel1.nonce == 1)
    mine()
    assert(manager:idle() and manager:nonce(signer.address) == 2)
end
print("PRT transactions: immediate cancellation, older-candidate race, and multi-nonce reorg recovery passed.")

-- Simulate process death after recording but before broadcast. Relaunch must
-- reuse the reserved nonce, even though the network never saw the first hash.
do
    local manager, args = fresh()
    local publish = chain.publish
    function chain.publish()
        error("fixture crash before publication")
    end
    assert(not pcall(submit, manager, intent()))
    chain.publish = publish
    manager = transactions.new(args)
    assert(not manager:idle() and manager:nonce(signer.address) == 0)
    mine(2)
    local resumed = submit(manager, intent()).candidate
    assert(resumed.nonce == 0)
    mine()
    successful(manager, "work", resumed.hash)
end

-- A consumed nonce and a reverted receipt are not successful job completion.
-- A later successful retry must supersede that earlier receipt for suppression.
do
    local manager = fresh()
    local failed = submit(manager, intent()).candidate
    rpc("anvil_setCode", { destination, "0x60006000fd" })
    mine()
    local receipt = assert(manager:receipt("work"))
    assert(receipt.transactionHash == failed.hash and tonumber(receipt.status) == 0)
    assert(manager:idle())
    rpc("anvil_setCode", { destination, "0x" })
    local retried = submit(manager, intent()).candidate
    assert(retried.nonce == 1)
    mine()
    successful(manager, "work", retried.hash)
end

-- Crash recovery at the exact fee ceiling republishes the already signed
-- bytes, without inventing a new nonce or bypassing the configured ceiling.
do
    local manager, args = fresh({ max_fee = "3000000000", max_priority_fee = "1000000000" })
    local publish = chain.publish
    local original
    function chain.publish(_, raw)
        original = raw
        error("fixture crash before publication at ceiling")
    end
    assert(not pcall(submit, manager, intent()))
    chain.publish = publish
    manager = transactions.new(args)
    mine(2, 1000000000)
    local resumed = submit(manager, intent())
    assert(resumed.rebroadcast and resumed.candidate.raw == original and resumed.candidate.nonce == 0)
    assert(not submit(manager, intent()).published, "rebroadcast was not throttled")
    mine()
    successful(manager, "work", resumed.candidate.hash)
end

-- A live tip change while the keystore signs invalidates the attempt. Nothing
-- may be published based on the earlier eligibility/deadline calculation.
do
    local manager = fresh()
    local sign = chain.sign
    function chain:sign(account, transaction)
        local raw, hash = sign(self, account, transaction)
        mine()
        return raw, hash
    end
    assert(not submit(manager, intent()).published)
    chain.sign = sign
    assert(manager:idle() and not io.open(manager.path, "r"))
end
-- All nonce consumers enforce exclusive ownership, including idle queries.
-- Otherwise an external transaction could make a pending journal appear done.
do
    local manager = fresh()
    assert(submit(manager, intent()).published)
    mine()
    rpc("anvil_setNonce", { signer.address, "0x2" })
    assert(not pcall(manager.pending, manager, signer.address), "pending accepted an unowned nonce")
    assert(not pcall(manager.idle, manager), "idle accepted an unowned nonce")
    assert(not pcall(submit, manager, intent()), "submission accepted an unowned nonce")
end
print("PRT transaction tests passed.")
