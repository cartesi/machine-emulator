-- R4-RGEPOCHS-1: the verification-game referee (doc/recipes/vg.lua) refuses an epoch of more than 2^16 inputs
-- and bisects over a 2^16-input grid, while the manual's state transition grid holds up to 2^24 inputs per epoch
-- (doc/README.md, "The state transition function"), the value of cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH.
--
-- Asserts:
--   (control) the referee's contract constructor accepts an epoch of exactly 2^16 inputs;
--   (A) it accepts an epoch of 2^16 + 1 inputs (any count up to the manual's 2^24 must be accepted);
--   (B) the input extent the referee bisects over (settle_dispute's log2_input_count) is
--       cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH (= 24), read from the referee's own closure.
-- Exit 1 if (A) or (B) fails, 0 if both hold, 2 on setup errors.
local harness = require("harness")

local function upvalue(f, name)
    if type(f) ~= "function" then
        return nil
    end
    local i = 1
    while true do
        local n, v = debug.getupvalue(f, i)
        if not n then
            return nil
        end
        if n == name then
            return v
        end
        i = i + 1
    end
end

harness.main(function()
    local cartesi = require("cartesi")
    local vg = require("vg") -- doc/recipes/vg.lua as a module (it returns its table when required as "vg")
    local MAX_LOG2 = cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
    if MAX_LOG2 ~= 24 then
        harness.setup_error("unexpected ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH " .. tostring(MAX_LOG2))
    end

    -- One tiny input file, referenced by every input of the epoch (the constructor reads each path).
    local mk = assert(io.popen("mktemp -d"))
    local dir = mk:read("l")
    mk:close()
    if not dir or dir == "" then
        harness.setup_error("mktemp -d failed")
    end
    local input = dir .. "/input.bin"
    local f = assert(io.open(input, "wb"))
    f:write("x")
    f:close()
    local function cleanup()
        os.remove(input)
        os.remove(dir)
    end

    local initial_state_hash = string.rep("\0", 32)
    local function paths(n)
        local t = {}
        for i = 1, n do
            t[i] = input
        end
        return t
    end

    -- Control: 2^16 inputs.
    local ok_c, err_c = pcall(vg.new_dapp_contract, initial_state_hash, paths(1 << 16))
    if not ok_c then
        cleanup()
        harness.setup_error("control epoch of 2^16 inputs refused: " .. tostring(err_c))
    end
    print(string.format("control: referee accepts an epoch of %d inputs", 1 << 16))

    -- (A) 2^16 + 1 inputs, within the manual's maximum of 2^24 inputs per epoch.
    local n = (1 << 16) + 1
    local ok_a, err_a = pcall(vg.new_dapp_contract, initial_state_hash, paths(n))
    cleanup()
    local pass_a = ok_a and type(err_a) == "table" and #err_a.input_paths == n
    if pass_a then
        print(string.format("(A) ok: referee accepts an epoch of %d inputs", n))
    else
        print(string.format("(A) FAIL: referee refuses an epoch of %d inputs (<= 2^%d): %s", n, MAX_LOG2, tostring(err_a)))
    end

    -- (B) the referee's bisection extent over inputs.
    local referee = vg.new_referee({})
    local settle_dispute = upvalue(upvalue(referee.run, "run_referee"), "settle_dispute")
    local log2_inputs = upvalue(settle_dispute, "LOG2_INPUTS_PER_EPOCH")
    local pass_b = true
    if log2_inputs == nil then
        print("(B) skipped: settle_dispute has no LOG2_INPUTS_PER_EPOCH upvalue (code changed); (A) decides")
    elseif log2_inputs == MAX_LOG2 then
        print(string.format("(B) ok: referee bisects over 2^%d inputs", log2_inputs))
    else
        pass_b = false
        print(string.format("(B) FAIL: referee bisects over 2^%s inputs, manual's grid is 2^%d", tostring(log2_inputs), MAX_LOG2))
    end

    return harness.expect(pass_a and pass_b,
        "vg.lua referee must settle every epoch within the manual's grid of 2^24 inputs per epoch "
            .. "(doc/README.md 'Within the maximum number of inputs per epoch (2^24)'; THREAT_MODEL section 8, "
            .. "manual contradiction on a security-relevant point)")
end)
