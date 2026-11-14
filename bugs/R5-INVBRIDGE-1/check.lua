-- R5-INVBRIDGE-1: prt-transactions.lua methods:submit on a value-bearing job (joinTournament sends the bond as
-- its value) from a signer whose balance is below the value. Required: the documented, non-raising
-- { blocked = "insufficient_funds" } report (prt-bridge.lua report_blocked: "Observing continues").
local harness = require("harness")
harness.main(function()
    local rpc_client = require("prt-rpc")
    local transactions = require("prt-transactions")
    local url, tmp = arg[1], arg[2]
    local chain = rpc_client.new(url)
    local function rpc(method, params)
        local r, e = chain:rpc(method, params)
        if e then
            harness.setup_error(method .. " failed: " .. tostring(e.message))
        end
        return r
    end
    -- A payable stand-in for the tournament: code STOP accepts any value, so a funded call succeeds.
    local tournament = "0x0000000000000000000000000000000000001234"
    rpc("anvil_setCode", { tournament, "0x00" })
    local bond = "1000000000000000000" -- 1 ETH, the value a joinTournament carries
    local signer_address = "0x000000000000000000000000000000000000beef"
    -- The test never needs a signature: each case must stop before signing.
    local signer = {
        address = signer_address,
        sign = function()
            error("fixture: signing was not expected")
        end,
    }
    local function job(value)
        return {
            key = "join",
            kind = "joinTournament",
            to = tournament,
            data = "0x",
            value = value,
            first = 0,
            last = math.maxinteger,
            context = { epoch = "1", root = "fixture" },
        }
    end
    local index = 0
    local function attempt(balance_hex, value)
        rpc("anvil_setBalance", { signer_address, balance_hex })
        rpc("evm_mine", {})
        index = index + 1
        local manager = transactions.new({ chain = chain, path = tmp .. "/journal-" .. index .. ".json" })
        local head, hash = chain:head()
        return pcall(manager.submit, manager, signer, job(value), { head = head, hash = hash })
    end
    local function show(name, ok, result)
        if ok then
            print(
                string.format(
                    "%s: returned blocked=%s needed=%s available=%s",
                    name,
                    tostring(result.blocked),
                    tostring(result.needed),
                    tostring(result.available)
                )
            )
        else
            print(string.format("%s: RAISED %s", name, tostring(result)))
        end
    end

    -- Controls: shortfalls the code already reports gracefully.
    -- (a) gas-only job, zero balance.
    local ok_a, res_a = attempt("0x0", "0")
    show("control (a) value 0, balance 0", ok_a, res_a)
    -- (b) bond job, balance = bond + 1 wei (covers the value, not the gas at the fee cap).
    local ok_b, res_b = attempt(string.format("0x%x", 1000000000000000001), bond)
    show("control (b) value 1 ETH, balance 1 ETH + 1 wei", ok_b, res_b)
    if not (ok_a and res_a.blocked == "insufficient_funds" and ok_b and res_b.blocked == "insufficient_funds") then
        harness.setup_error("controls did not take the documented insufficient_funds path")
    end

    -- Cases under test: the balance is below the bond itself.
    local ok_c, res_c = attempt(string.format("0x%x", 999999999999999999), bond)
    show("case (c) value 1 ETH, balance 1 ETH - 1 wei", ok_c, res_c)
    local ok_d, res_d = attempt("0x0", bond)
    show("case (d) value 1 ETH, balance 0", ok_d, res_d)

    -- What the node answers to the preflight eth_call in case (d): not an EVM revert (code 3).
    local _, failure = chain:simulate(signer, tournament, "0x", bond, "latest")
    print(string.format("preflight eth_call at balance 0: code=%s message=%s", tostring(failure and failure.code),
        tostring(failure and failure.message)))

    local good_c = ok_c and res_c.blocked == "insufficient_funds" and not res_c.published
    local good_d = ok_d and res_d.blocked == "insufficient_funds" and not res_d.published
    return harness.expect(
        good_c and good_d,
        "prt-lua-bridge.md insufficient_funds / prt-bridge.lua 'Reports a transaction the player cannot publish"
            .. " ... Observing continues' (R4: the honest operator keeps submitting within the dispute clocks):"
            .. " a join whose bond exceeds the balance must be reported as blocked, not raise"
    )
end)
