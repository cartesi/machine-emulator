-- R1-A6-2: the PRT player's start-up version check (doc/recipes/crisium.lua) compares only the deployed
-- verifier's UARCH_PRISTINE_STATE_HASH with the emulator's, so it accepts a deployment whose verifier is of
-- another version (CM_MARCHID 22, step code of machine-solidity-step v0.17.0-test1) as long as its pristine uarch
-- hash equals this build's.
--
-- Required (THREAT_MODEL.md R13): "The honest operator must be able to detect and refuse a mismatch between its
-- build and a deployment. The check must refuse every pairing of its build with a deployment of another released
-- version." The player stands in for the honest operator (support role).
--
-- Exit 1: the player starts against the other-version deployment. Exit 0: it refuses it. Exit 2: setup error
-- (including the controls below failing).
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local evm = require("evm_step")
    local WORK, REPO = harness.WORK, harness.REPO
    local HERE = REPO .. "/bugs/R1-A6-2"
    local DAVE = WORK .. "/dave/patched" -- Dave built with the step regenerated from this branch
    local RELEASED_STEP = WORK .. "/solidity-step/released/src" -- machine-solidity-step v0.17.0-test1, untouched

    local function q(s)
        return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
    end
    local function sh(cmd)
        local ok, out = harness.sh(cmd)
        return ok, out
    end
    local function must(cmd, what)
        local ok, out = sh(cmd)
        if not ok then
            error((what or cmd) .. " failed:\n" .. out)
        end
        return out
    end
    local function exists(path)
        local f = io.open(path, "rb")
        if f then
            f:close()
        end
        return f ~= nil
    end
    for _, path in ipairs({
        DAVE .. "/prt/contracts/out/CartesiStateTransition.sol/CartesiStateTransition.json",
        DAVE .. "/prt/contracts/dependencies/@openzeppelin-contracts-5.5.0/utils/math/SafeCast.sol",
        RELEASED_STEP .. "/EmulatorConstants.sol",
        harness.config_dir("baremetal-minimal") .. "/machine",
    }) do
        if not exists(path) then
            harness.setup_error("missing " .. path .. " (bugs/harness/setup.sh)")
        end
    end
    for _, tool in ipairs({ "forge", "anvil", "cast", "curl" }) do
        if not sh("command -v " .. tool .. " > /dev/null") then
            harness.setup_error("missing tool " .. tool)
        end
    end

    local tmp = must("mktemp -d \"${TMPDIR:-/tmp}/r1-a6-2.XXXXXX\""):gsub("%s+$", "")
    local anvil_pid
    local function cleanup()
        if anvil_pid then
            os.execute("kill " .. anvil_pid .. " 2> /dev/null; sleep 0.2; kill -9 " .. anvil_pid .. " 2> /dev/null")
        end
        os.execute("rm -rf " .. q(tmp))
    end

    local ok, result = xpcall(function()
        local ours_pristine = cartesi.tohex(cartesi.UARCH_PRISTINE_STATE_HASH):lower()
        local released_constants = harness.read_file(RELEASED_STEP .. "/EmulatorConstants.sol")
        local released_pristine = assert(
            released_constants:match("UARCH_PRISTINE_STATE_HASH%s*=%s*(0x%x+)"),
            "no pristine hash in the released constants"
        ):lower()
        local released_marchid =
            assert(math.tointeger(tonumber(released_constants:match("CM_MARCHID%s*=%s*(%d+)"))), "no CM_MARCHID")
        if released_marchid == cartesi.MARCHID or released_pristine == ours_pristine then
            error("the released step is not of another version than this build")
        end

        -- 1. Build CartesiStateTransition (Dave's source) over the released v0.17.0-test1 step: "released" as is,
        --    and "other" with its pristine hash set to this build's. "other" stands for a deployment of another
        --    released version whose uarch program is the same as this build's (its step code and CM_MARCHID
        --    differ, its pristine hash does not).
        local function build(name, pristine)
            local p = tmp .. "/build-" .. name
            must(
                table.concat({
                    "mkdir -p " .. q(p .. "/contracts/src/state-transition"),
                    q(p .. "/contracts/dependencies/@openzeppelin-contracts-5.5.0/utils/math"),
                    q(p .. "/step"),
                }, " ")
                    .. " && cp "
                    .. q(DAVE .. "/prt/contracts/src/IDataProvider.sol")
                    .. " "
                    .. q(DAVE .. "/prt/contracts/src/IStateTransition.sol")
                    .. " "
                    .. q(p .. "/contracts/src/")
                    .. " && cp "
                    .. q(DAVE .. "/prt/contracts/src/state-transition/CartesiStateTransition.sol")
                    .. " "
                    .. q(p .. "/contracts/src/state-transition/")
                    .. " && cp "
                    .. q(DAVE .. "/prt/contracts/dependencies/@openzeppelin-contracts-5.5.0/utils/math/SafeCast.sol")
                    .. " "
                    .. q(p .. "/contracts/dependencies/@openzeppelin-contracts-5.5.0/utils/math/")
                    .. " && cp -r "
                    .. q(RELEASED_STEP)
                    .. " "
                    .. q(p .. "/step/src")
                    .. " && cp "
                    .. q(HERE .. "/foundry.toml")
                    .. " "
                    .. q(p .. "/contracts/"),
                "preparing build " .. name
            )
            if pristine ~= released_pristine then
                local file = p .. "/step/src/EmulatorConstants.sol"
                local text = harness.read_file(file)
                local replaced, n = text:gsub(released_pristine, pristine)
                assert(n == 1, "pristine hash not replaced")
                local f = assert(io.open(file, "wb"))
                f:write(replaced)
                f:close()
            end
            must("cd " .. q(p .. "/contracts") .. " && forge build --offline 2>&1", "forge build " .. name)
            local artifact = p .. "/contracts/out/CartesiStateTransition.sol"
            assert(exists(artifact .. "/CartesiStateTransition.json"), "no artifact for " .. name)
            -- A Dave directory identical to the harness's patched build except for CartesiStateTransition.
            local d = tmp .. "/dave-" .. name
            must(
                "mkdir -p "
                    .. q(d .. "/prt/contracts/out")
                    .. " "
                    .. q(d .. "/cartesi-rollups/contracts")
                    .. " && ln -s "
                    .. q(DAVE .. "/cartesi-rollups/contracts/out")
                    .. " "
                    .. q(d .. "/cartesi-rollups/contracts/out")
                    .. " && for f in "
                    .. q(DAVE .. "/prt/contracts/out")
                    .. "/*; do [ \"$(basename \"$f\")\" = CartesiStateTransition.sol ] || ln -s \"$f\" "
                    .. q(d .. "/prt/contracts/out/")
                    .. "; done && ln -s "
                    .. q(artifact)
                    .. " "
                    .. q(d .. "/prt/contracts/out/CartesiStateTransition.sol"),
                "Dave overlay " .. name
            )
            return d
        end
        local dave_other = build("other", ours_pristine)
        local dave_released = build("released", released_pristine)

        -- 2. A chain of our own, the recipe wallets, and three deployments.
        local port
        for candidate = 18700 + (os.time() % 97) * 3, 18700 + 97 * 3 + 300 do
            if select(2, sh("ss -Hltn 'sport = :" .. candidate .. "' 2> /dev/null")) == "" then
                port = candidate
                break
            end
        end
        assert(port, "no free port")
        local rpc = "http://127.0.0.1:" .. port
        anvil_pid = must(
            "nohup anvil --host 127.0.0.1 --port "
                .. port
                .. " --accounts 10 --balance 10000 --hardfork prague --timestamp 1780000000 --prune-history 256 > "
                .. q(tmp .. "/anvil.log")
                .. " 2>&1 & echo $!"
        ):gsub("%s+$", "")
        must(
            "for i in $(seq 1 100); do cast block-number --rpc-url "
                .. rpc
                .. " > /dev/null 2>&1 && exit 0; sleep 0.1; done; exit 1",
            "anvil start"
        )
        must(
            "cd "
                .. q(tmp)
                .. " && mkdir -m 700 wallets"
                .. " && printf '%s\\n' 'test test test test test test test test test test test junk' > wallets/mnemonic"
                .. " && printf '%s\\n' local-prt-demo > wallets/password"
                .. " && CAST_UNSAFE_PASSWORD=local-prt-demo cast wallet import player-0 --keystore-dir wallets"
                .. " --mnemonic wallets/mnemonic --mnemonic-index 0 > /dev/null",
            "wallet import"
        )
        local template = cartesi.tohex(cartesi.keccak256("R1-A6-2 template"))
        local function deploy(dave, pristine, marchid)
            local out = must(
                "cd "
                    .. q(tmp)
                    .. " && PRT_DAVE_DIR="
                    .. q(dave)
                    .. " lua5.4 "
                    .. q(HERE .. "/deploy.lua")
                    .. " "
                    .. rpc
                    .. " "
                    .. template
                    .. (pristine and (" " .. pristine .. " " .. marchid) or "")
                    .. " 2> "
                    .. q(tmp .. "/deploy.log"),
                "deployment with " .. dave
            )
            local app, stf = out:match("^(0x%x+) (0x%x+)")
            assert(app, "deployment output: " .. out)
            return app, stf
        end
        local app_ours, stf_ours = deploy(DAVE)
        local app_other, stf_other = deploy(dave_other, ours_pristine, released_marchid)
        local app_released = deploy(dave_released, released_pristine, released_marchid)

        local function uint_getter(stf, sig)
            local okc, r = evm.connect(rpc, stf):call(cartesi.keccak256(sig):sub(1, 4))
            assert(okc, sig .. " reverted: " .. tostring(r))
            return r
        end
        local other_marchid = string.unpack(">I8", uint_getter(stf_other, "CM_MARCHID()"):sub(25, 32))
        local other_pristine = cartesi.tohex(uint_getter(stf_other, "UARCH_PRISTINE_STATE_HASH()"):sub(1, 32))
        local ours_marchid = string.unpack(">I8", uint_getter(stf_ours, "CM_MARCHID()"):sub(25, 32))
        io.stderr:write(
            string.format(
                "  this build: MARCHID %d, pristine %s; deployed 'ours' CM_MARCHID %d\n"
                    .. "  deployed 'other': CM_MARCHID %d, pristine %s\n",
                cartesi.MARCHID,
                ours_pristine,
                ours_marchid,
                other_marchid,
                other_pristine
            )
        )
        assert(ours_marchid == cartesi.MARCHID, "the harness's patched Dave build is not of this build's version")
        assert(other_marchid ~= cartesi.MARCHID and other_pristine:lower() == ours_pristine, "variant constants")

        -- 3. Witness that 'other' implements another transition function than this build: a uarch step that this
        --    emulator logs, and that the deployment of this build's version accepts, is refused by 'other'
        --    (v0.17.0-test1 checks the uarch cycle limit before reading the halt flag; this branch reads both).
        local m <close> = harness.machine(harness.config_dir("baremetal-minimal") .. "/machine")
        m:write_reg("uarch_cycle", cartesi.UARCH_CYCLE_MAX)
        local before = m:get_root_hash()
        local proofs = evm.concat_logs(m:log_step_uarch())
        local after = m:get_root_hash()
        local function transition(stf)
            local okc, r = evm.connect(rpc, stf):call(evm.abi_encode("transitionState(bytes32,uint256,bytes,address)", {
                { "bytes32", before },
                { "uint", 1 },
                { "bytes", proofs },
                { "uint", 0 },
            }))
            return okc, okc and r:sub(1, 32) or r
        end
        local ok_ours, root_ours = transition(stf_ours)
        assert(ok_ours and root_ours == after, "this build's deployment refuses this build's log: " .. tostring(root_ours))
        local ok_other, why_other = transition(stf_other)
        assert(not ok_other, "'other' accepts the witness log: it does not differ from this build as expected")
        local word = "(" .. string.rep("%x", 64) .. ")"
        local consumed, provided = tostring(why_other):match("data=0xbec81b9d" .. word .. word)
        if consumed then -- InvalidAccessLogProofLength(uint256 consumed, uint256 provided)
            why_other = string.format("InvalidAccessLogProofLength(consumed %d, provided %d)", tonumber(consumed, 16),
                tonumber(provided, 16))
        end
        io.stderr:write("  witness step (uarch cycle at its limit): the deployment of this build's version accepts the "
            .. "emulator's log, 'other' refuses it: ", why_other, "\n")

        -- 4. Start the player against each deployment.
        local function player(app, dave, name)
            local verdict = must(
                "bash "
                    .. q(HERE .. "/run-crisium.sh")
                    .. " "
                    .. rpc
                    .. " "
                    .. app
                    .. " "
                    .. q(dave)
                    .. " "
                    .. q(tmp .. "/player-" .. name)
                    .. " 180",
                "player " .. name
            ):gsub("%s+$", "")
            local log = harness.read_file(tmp .. "/player-" .. name .. "/log")
            io.stderr:write("  player vs '", name, "': ", verdict, "\n")
            if verdict == "REFUSED" then
                io.stderr:write("    ", (log:match("[^\n]*differ[^\n]*") or log:sub(-400)), "\n")
            end
            assert(verdict == "ACCEPTED" or verdict == "REFUSED", "player " .. name .. ": " .. verdict .. "\n" .. log)
            return verdict
        end
        -- Controls: the deployment of this build's version is accepted, the real v0.17.0-test1 one refused.
        assert(player(app_ours, DAVE, "ours") == "ACCEPTED", "control: the player refuses this build's deployment")
        assert(
            player(app_released, dave_released, "released") == "REFUSED",
            "control: the player accepts the released v0.17.0-test1 deployment"
        )
        local verdict = player(app_other, dave_other, "other")
        return harness.expect(
            verdict == "REFUSED",
            string.format(
                "R13: the player must refuse a deployment of another version (CM_MARCHID %d, v0.17.0-test1 step "
                    .. "code) even when its pristine uarch hash equals this build's (MARCHID %d)",
                other_marchid,
                cartesi.MARCHID
            )
        )
    end, debug.traceback)
    cleanup()
    if not ok then
        error(result, 0)
    end
    return result
end)
