-- Signs transactions with cast for the PRT recipe. The signer owns an exclusive account. Only a player that
-- publishes transactions, the deployment, and the demo load this module.
local json = require("dkjson")
local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local command = require("prt-command")
local rpc_client = require("prt-rpc")
local eth = require("prt-ethereum")

local M = {}
local methods = {}

-- The address of the account in a keystore.
function M.address(keystore, password_file)
    return (
        command
            .run({ "cast", "wallet", "address", "--keystore", keystore, "--password-file", password_file })
            :gsub("%s+$", "")
            :lower()
    )
end

-- All fields are explicit: signing must not choose a nonce or estimate fees.
-- cast signs only the transaction's digest, since the calldata of a proof can exceed the size of a
-- command argument.
function methods:sign(signer, transaction)
    local signature = command
        .run({
            "cast",
            "wallet",
            "sign",
            "--no-hash",
            "--keystore",
            signer.keystore,
            "--password-file",
            signer.password_file,
            cartesi.tohex(eth.transaction_digest(transaction)),
        })
        :gsub("%s+$", "")
    local raw = eth.signed_transaction(transaction, cartesi.fromhex(signature))
    return raw, self:verify_signed(signer, transaction, raw)
end

function methods.verify_signed(_, signer, transaction, raw)
    assert(raw:match("^0x02%x+$") and #raw % 2 == 0, "invalid signed EIP-1559 transaction")
    local decoded = rpc_client.decode_json(command.run({ "cast", "decode-transaction" }, raw))
    assert(decoded.signer:lower() == signer.address:lower(), "transaction used the wrong signer")
    assert(decoded.to:lower() == transaction.to:lower(), "transaction has the wrong destination")
    assert(decoded.input:lower() == transaction.data:lower(), "transaction calldata differs from the prepared action")
    for field, expected in pairs({
        type = 2,
        chainId = transaction.chain_id,
        nonce = transaction.nonce,
        gas = transaction.gas,
        value = transaction.value,
        maxFeePerGas = transaction.max_fee,
        maxPriorityFeePerGas = transaction.priority_fee,
    }) do
        assert(evmu.bint(decoded[field]) == evmu.bint(expected), "signed transaction field mismatch: " .. field)
    end
    assert(#decoded.accessList == 0, "unexpected transaction access list")
    assert(type(decoded.hash) == "string" and #decoded.hash == 66, "invalid signed transaction hash")
    return decoded.hash:lower()
end

function methods:send(signer, to, data, value)
    value = value or "0"
    local _, failure = self:simulate(signer, to, data, value)
    if failure then
        -- Anvil reports EVM reverts with code 3. Provider failures must stop the
        -- run instead of permanently suppressing a potentially legal action.
        assert(failure.code == 3, "transaction preflight RPC failure: " .. json.encode(failure))
        return nil, failure
    end
    local arguments = {
        "cast",
        "send",
        "--rpc-url",
        self.url,
        "--keystore",
        signer.keystore,
        "--password-file",
        signer.password_file,
        "--json",
        "--value",
        tostring(value),
        to or "--create",
        data,
    }
    local output = command.run(arguments)
    local receipt = rpc_client.decode_json(output)
    assert(tonumber(receipt.status) == 1, "mined transaction reverted: " .. receipt.transactionHash)
    assert(
        type(receipt.transactionHash) == "string" and #receipt.transactionHash == 66,
        "receipt lacks transaction hash"
    )
    local transaction = assert(self:rpc("eth_getTransactionByHash", { receipt.transactionHash }))
    assert(transaction.from:lower() == signer.address:lower(), "transaction used the wrong signer")
    assert(transaction.input:lower() == data:lower(), "transaction calldata differs from the prepared action")
    assert(
        (not to and transaction.to == json.null) or (to and transaction.to:lower() == to:lower()),
        "transaction has the wrong destination"
    )
    assert(evmu.bint(transaction.value) == evmu.bint(value), "transaction has the wrong value")
    return receipt
end

-- Adds the signing methods to a chain from prt-rpc.lua, and returns it.
function M.install(chain)
    for name, method in pairs(methods) do
        chain[name] = method
    end
    return chain
end

return M
