-- EVM harness client: verify emulator access logs with the REGENERATED machine-solidity-step contracts deployed
-- on a local anvil (bugs/harness/solidity-step/evm/start.sh deploys StepVerifier and writes
-- bugs/harness/work/evm/{rpc-url,address}). Calls are eth_call through curl, so any proof size works.
--
--   local evm = require("evm_step")
--   local e = evm.connect()                              -- reads rpc-url and address
--   local log = m:log_step_uarch()
--   local ok, root, status = e:step(before_root, log)    -- ok=false, root=revert reason on revert
--   e:reset(root, reset_log); e:step_then_reset(root, step_log, reset_log)
--   e:send_cmio_response(root, reason, data, revert_root, log)
--   e:send_cmio_response_then_step(root, data, send_log, step_log)
--   e:meta_step(root, counter, step_log[, reset_log])
--   evm.encode_log(log) -> proof bytes (same encoding as doc/recipes/prt-ethereum.lua and Dave)
--   evm.data_hash(data) -> the dataHash SendCmioResponse expects (keccak Merkle root of data over the smallest
--                          power-of-two region >= 32 bytes that holds it), its log2 size
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")

local M = {}

local function hex(s) return "0x" .. (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
local function unhex(h)
    h = h:gsub("^0x", "")
    return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end))
end
M.hex, M.unhex = hex, unhex

function M.encode_log(log, parts)
    parts = parts or {}
    for _, access in ipairs(log.accesses) do
        if access.log2_size == 3 then
            assert(access.read and #access.read == 32, "word access lacks its Merkle leaf")
            parts[#parts + 1] = access.read
        elseif access.type == "read" then
            assert(access.read and #access.read == 32, "region read is not a bytes32")
            parts[#parts + 1] = access.read
            parts[#parts + 1] = assert(access.read_hash)
        else
            parts[#parts + 1] = assert(access.read_hash)
        end
        for _, sibling in ipairs(access.sibling_hashes) do
            parts[#parts + 1] = sibling
        end
    end
    return parts
end

local function concat_logs(...)
    local parts = {}
    for i = 1, select("#", ...) do
        local log = select(i, ...)
        if log then M.encode_log(log, parts) end
    end
    return table.concat(parts)
end
M.concat_logs = concat_logs

function M.data_hash(data)
    if #data == 0 then return string.rep("\0", 32), 0 end
    local log2 = cartesi.HASH_TREE_LOG2_WORD_SIZE
    while (1 << log2) < #data do
        log2 = log2 + 1
    end
    return hash_tree.get_data_root_hash(data, log2), log2
end

-- ABI: selector .. head words (static values or offsets) .. tails (dynamic bytes)
local function word_uint(v) return string.rep("\0", 24) .. string.pack(">I8", v) end
local function selector(sig) return cartesi.keccak256(sig):sub(1, 4) end
local function abi_encode(sig, args)
    -- args: { {"bytes32", v} | {"uint", v} | {"bytes", v} }
    local head, tail = {}, {}
    local head_size = 32 * #args
    local tail_size = 0
    for _, a in ipairs(args) do
        local t, v = a[1], a[2]
        if t == "bytes32" then
            assert(#v == 32, "bytes32 argument must be 32 bytes")
            head[#head + 1] = v
        elseif t == "uint" then
            head[#head + 1] = word_uint(v)
        elseif t == "bytes" then
            head[#head + 1] = word_uint(head_size + tail_size)
            local pad = (32 - #v % 32) % 32
            local enc = word_uint(#v) .. v .. string.rep("\0", pad)
            tail[#tail + 1] = enc
            tail_size = tail_size + #enc
        else
            error("unsupported ABI type " .. t)
        end
    end
    return selector(sig) .. table.concat(head) .. table.concat(tail)
end
M.abi_encode = abi_encode

local function read_file(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local s = f:read("a")
    f:close()
    return (s:gsub("%s+$", ""))
end

local client = {}
client.__index = client

function M.connect(rpc_url, address)
    local work = assert(os.getenv("HARNESS_WORK"), "source bugs/env.sh first")
    rpc_url = rpc_url or read_file(work .. "/evm/rpc-url")
    address = address or read_file(work .. "/evm/address")
    assert(rpc_url and address, "StepVerifier not deployed (run bugs/harness/solidity-step/evm/start.sh)")
    return setmetatable({ rpc_url = rpc_url, address = address, tmp = os.tmpname() }, client)
end

-- Raw eth_call; returns ok, return-data (raw) or error message.
function client:call(calldata)
    local body = string.format(
        '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"%s","data":"%s","gas":"0x%x"},"latest"]}',
        self.address,
        hex(calldata),
        1 << 40
    )
    local f = assert(io.open(self.tmp, "wb"))
    f:write(body)
    f:close()
    local p = assert(io.popen(
        string.format("curl -sS --noproxy '*' -H 'Content-Type: application/json' --data-binary @%s %s", self.tmp, self.rpc_url)
    ))
    local out = p:read("a")
    p:close()
    local result = out:match('"result"%s*:%s*"(0x[0-9a-fA-F]*)"')
    if result then return true, unhex(result) end
    local msg = out:match('"message"%s*:%s*"([^"]*)"') or out
    local data = out:match('"data"%s*:%s*"(0x[0-9a-fA-F]*)"')
    return false, msg .. (data and (" data=" .. data) or "")
end

local function ret_root_status(ok, r)
    if not ok then return false, r end
    return true, r:sub(1, 32), r:byte(64)
end

function client:step(root, log)
    return ret_root_status(self:call(abi_encode("step(bytes32,bytes)", { { "bytes32", root }, { "bytes", concat_logs(log) } })))
end

function client:reset(root, log)
    local ok, r = self:call(abi_encode("reset(bytes32,bytes)", { { "bytes32", root }, { "bytes", concat_logs(log) } }))
    if not ok then return false, r end
    return true, r:sub(1, 32)
end

function client:step_then_reset(root, step_log, reset_log)
    return ret_root_status(self:call(abi_encode("stepThenReset(bytes32,bytes)", {
        { "bytes32", root },
        { "bytes", concat_logs(step_log, reset_log) },
    })))
end

function client:send_cmio_response(root, reason, data, revert_root, log)
    local dh = M.data_hash(data)
    local ok, r = self:call(abi_encode("sendCmioResponse(bytes32,uint16,bytes32,uint32,bytes32,bytes)", {
        { "bytes32", root },
        { "uint", reason },
        { "bytes32", dh },
        { "uint", #data },
        { "bytes32", revert_root },
        { "bytes", concat_logs(log) },
    }))
    if not ok then return false, r end
    return true, r:sub(1, 32)
end

function client:send_cmio_response_then_step(root, data, send_log, step_log)
    local dh = M.data_hash(data)
    return ret_root_status(self:call(abi_encode("sendCmioResponseThenStep(bytes32,bytes32,uint32,bytes)", {
        { "bytes32", root },
        { "bytes32", dh },
        { "uint", #data },
        { "bytes", concat_logs(send_log, step_log) },
    })))
end

function client:meta_step(root, counter, step_log, reset_log)
    return ret_root_status(self:call(abi_encode("metaStep(bytes32,uint256,bytes)", {
        { "bytes32", root },
        { "uint", counter },
        { "bytes", concat_logs(step_log, reset_log) },
    })))
end

function client:constants()
    local ok, r = self:call(selector("constants()"))
    assert(ok, r)
    return string.unpack(">I8", r:sub(25, 32)), r:sub(33, 64)
end

return M
