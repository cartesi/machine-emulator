-- Child of test.lua: one logged transition, with the N-th operator new request failing (nth-new.cpp).
-- usage: lua5.4 child.lua step|send
-- Prints one line: "RESULT <op> <kind> <details>". Kinds:
--   OK        the call succeeded (it then must have reached the control after-hash, else NOINJECT-MISMATCH)
--   UNCHANGED the call failed and the machine is still at the before-state
--   COMPLETE  the call failed and the machine is at the control after-state (transition applied, error reported)
--   PARTIAL   the call failed and the machine is at a third state, neither before nor after
local cartesi = require("cartesi")
local harness = require("harness")

local op = assert(arg[1], "usage: child.lua step|send")
local arm = assert(os.getenv("NTH_ARM_FILE"))
local K = tonumber(os.getenv("STEP_K") or "0") -- uarch steps taken before the logged one
local hex = cartesi.tohex

local function arm_on() assert(io.open(arm, "w")):close() end
local function arm_off() os.remove(arm) end

local prepare, apply_control, logged_call, retry_check, describe

if op == "step" then
    local dir = harness.config_dir("baremetal-minimal") .. "/machine"
    prepare = function()
        local m = cartesi.machine(dir, {}, cartesi.SHARING_NONE)
        for _ = 1, K do m:run_uarch(m:read_reg("uarch_cycle") + 1) end
        return m
    end
    apply_control = function(c) c:run_uarch(c:read_reg("uarch_cycle") + 1) end
    logged_call = function(m) return m:log_step_uarch() end
    describe = function(m)
        return string.format("uarch_cycle=%d uarch_pc=0x%x", m:read_reg("uarch_cycle"), m:read_reg("uarch_pc"))
    end
    -- what an operator that keeps using the machine gets when it retries the logged step
    retry_check = function(m, before, after)
        local ok, log = pcall(m.log_step_uarch, m)
        if not ok then return "retry-failed:" .. tostring(log) end
        local okv, vroot = pcall(m.verify_step_uarch, m, before, log)
        return string.format("retry_root==control_after:%s retry_log_verifies_from_canonical_before:%s",
            tostring(m:get_root_hash() == after), tostring(okv and vroot == after))
    end
elseif op == "send" then
    local dir = harness.config_dir("baremetal-template") .. "/machine"
    local data = string.rep("A", tonumber(os.getenv("SEND_LEN") or "4096"))
    local reason = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE
    local logtype = cartesi.ACCESS_LOG_TYPE_LARGE_DATA
    local revert
    prepare = function()
        local m = cartesi.machine(dir, {}, cartesi.SHARING_NONE)
        revert = m:get_root_hash()
        return m
    end
    apply_control = function(c) c:send_cmio_response(reason, data, revert) end
    logged_call = function(m) return m:log_send_cmio_response(reason, data, revert, logtype) end
    describe = function(m)
        return string.format("iflags_Y=%d imcyclemax=%d htif_fromhost=0x%x revert_root_hash_written=%s",
            m:read_reg("iflags_Y"), m:read_reg("imcyclemax"), m:read_reg("htif_fromhost"),
            tostring(m:read_memory(0xfe0, 32) == revert))
    end
    retry_check = function(m, before, after)
        local ok, log = pcall(m.log_send_cmio_response, m, reason, data, revert, logtype)
        if not ok then return "retry-failed:" .. tostring(log) end
        local okv, vroot = pcall(m.verify_send_cmio_response, m, reason, data, before, log, revert)
        return string.format("retry_root==control_after:%s retry_log_verifies_from_canonical_before:%s",
            tostring(m:get_root_hash() == after), tostring(okv and vroot == after))
    end
elseif op == "send" then
    local dir = harness.config_dir("baremetal-template") .. "/machine"
    local data = string.rep("A", tonumber(os.getenv("SEND_LEN") or "4096"))
    local reason = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE
    local logtype = cartesi.ACCESS_LOG_TYPE_LARGE_DATA
    local revert
    prepare = function()
        local m = cartesi.machine(dir, {}, cartesi.SHARING_NONE)
        revert = m:get_root_hash()
        return m
    end
    apply_control = function(c) c:send_cmio_response(reason, data, revert) end
    logged_call = function(m) return m:log_send_cmio_response(reason, data, revert, logtype) end
    describe = function(m)
        return string.format("iflags_Y=%d imcyclemax=%d htif_fromhost=0x%x revert_root_hash_written=%s",
            m:read_reg("iflags_Y"), m:read_reg("imcyclemax"), m:read_reg("htif_fromhost"),
            tostring(m:read_memory(0xfe0, 32) == revert))
    end
    retry_check = function(m, before, after)
        local ok, log = pcall(m.log_send_cmio_response, m, reason, data, revert, logtype)
        if not ok then return "retry-failed:" .. tostring(log) end
        local okv, vroot = pcall(m.verify_send_cmio_response, m, reason, data, before, log, revert)
        local oks, serr = pcall(function()
            local x = prepare() -- fresh, just to show the plain call's view is not needed; keep m intact
            return x
        end)
        return string.format("retry_root==control_after:%s retry_log_verifies_from_canonical_before:%s",
            tostring(m:get_root_hash() == after), tostring(okv and vroot == after))
    end
else
    error("unknown op " .. op)
end

local c = prepare()
local before = c:get_root_hash()
apply_control(c)
local after = c:get_root_hash()
assert(after ~= before, "control transition did not change the state")

local m = prepare()
assert(m:get_root_hash() == before, "fresh machines differ")
arm_on()
local ok, err = pcall(logged_call, m)
arm_off()
local mid = m:get_root_hash()
local line
if ok then
    line = (mid == after) and "OK" or "NOINJECT-MISMATCH"
else
    local kind = (mid == before) and "UNCHANGED" or ((mid == after) and "COMPLETE" or "PARTIAL")
    line = string.format("%s err=[%s] state: %s", kind, tostring(err):gsub("\n", " "), describe(m))
    if kind == "PARTIAL" then
        line = line .. string.format(" mid_root=%s | control: %s before=%s after=%s | %s", hex(mid), describe(c),
            hex(before), hex(after), retry_check(m, before, after))
    end
end
print("RESULT " .. op .. " " .. line)
io.stdout:flush()
os.exit(0)
