-- R1-R9-1: the per-machine get_uarch_pristine_hash() returns the Keccak-256 pristine uarch hash on a
-- SHA-256 machine, a hash that machine's state does not commit to.
--
-- Asserted requirement (THREAT_MODEL R9): "Precomputed hashes, such as those of empty subtrees, must be correct
-- for every supported hash function."
--
-- For every supported hash function, a freshly created machine holds the pristine uarch (created, never run).
-- The pristine uarch hash that the machine reports must then be the hash of that machine's own uarch subtree,
-- get_node_hash(UARCH_STATE_START_ADDRESS, UARCH_STATE_LOG2_SIZE), or the call must refuse a hash function it
-- has no precomputed value for. Checked on a local machine (C/Lua API) and on a remote one (JSON-RPC).
-- Keccak-256 is the control: if it does not match, the test setup is wrong (exit 2).
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local jsonrpc = require("cartesi.jsonrpc")
    local base = harness.config("baremetal-minimal")

    local function config_with(hash_function)
        local cfg = {}
        for k, v in pairs(base) do
            cfg[k] = v
        end
        cfg.hash_tree = { hash_function = hash_function }
        return cfg
    end

    -- returns ok (true when the reported pristine hash is correct or the call refuses), and a description
    local function check(kind, m, hash_function)
        local subtree = m:get_node_hash(cartesi.UARCH_STATE_START_ADDRESS, cartesi.UARCH_STATE_LOG2_SIZE)
        local okcall, reported = pcall(m.get_uarch_pristine_hash, m)
        if not okcall then
            return true, string.format("%s %s: get_uarch_pristine_hash refused (%s)", kind, hash_function,
                tostring(reported))
        end
        local desc = string.format("%s %s machine: get_uarch_pristine_hash()=%s, own pristine uarch subtree=%s",
            kind, hash_function, harness.hex(reported), harness.hex(subtree))
        print(desc)
        return reported == subtree, desc
    end

    local all_ok = true
    local function run_on(kind, create)
        -- control: Keccak-256
        do
            local m <close> = create(config_with("keccak256"))
            local ok, desc = check(kind, m, "keccak256")
            if not ok then
                harness.setup_error("control failed, Keccak-256 pristine hash mismatch: " .. desc)
            end
        end
        -- SHA-256 must be a supported hash function (machine creation accepts it)
        local okc, created = pcall(create, config_with("sha256"))
        if not okc then
            harness.setup_error("cannot create a sha256 machine: " .. tostring(created))
        end
        local m <close> = created
        local ok, desc = check(kind, m, "sha256")
        all_ok = harness.expect(ok, "R9 (" .. kind .. "): pristine uarch hash reported for a sha256 machine "
            .. "must be correct for sha256 or refused: " .. desc) and all_ok
    end

    run_on("local", function(cfg)
        return cartesi.machine(cfg)
    end)

    do
        run_on("remote", function(cfg)
            return jsonrpc.spawn_server():set_cleanup_call(jsonrpc.SHUTDOWN):create(cfg)
        end)
    end

    return all_ok
end)
