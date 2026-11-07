#!/usr/bin/env lua5.4
-- R12-SECCACHE2-1: loading a stored machine adopts the inner-node hashes of its sparse hash tree (hash_tree.sht) as
-- is. hash_tree.cpp validates only the topology fields (left, right, parent, log2_size) of each sparse node, never its
-- hash; update_sparse_tree recomputes a node only when a descendant range changed, from the STORED hash of the sibling
-- subtree; get_proof uses stored sibling hashes; verify_hash_tree never inspects inner sparse nodes.
--
-- With a 1 MiB RAM machine, sparse node 73 (log2 29, 0x60000000..0x7fffffff) = H(node 74 [0x60000000, log2 28: cmio
-- rx/tx buffers], node 83 [0x70000000, log2 28: the DTB]). Node 83 is "dormant": its parent is not recomputed at load
-- (the guest executes sfence.vma before yielding, so no write-TLB entry of the cmio range survives in the template).
-- Overwriting node 83's 32-byte hash (file offset 83*64+28) leaves the loaded root, cartesi-machine-stored-hash and
-- verify_hash_tree unchanged. Then:
--   * get_proof of an rx-buffer word uses node 83 as its log2-28 sibling, so it does not fold to the root;
--   * the first advance-state delivery writes the rx buffer, node 73 is recomputed as H(74, poisoned 83), and the
--     machine root becomes wrong; get_proof of a DTB word does not fold either.
--
-- The test builds a valid template with a small bare-metal rollup guest (guest.S, built at test time) that yields
-- manual rx-accepted with the empty outputs root, and on each advance-state input increments a counter in its data
-- page and yields rx-accepted again. It stores the template (dir A), copies it to dir B, and overwrites only node
-- 83's hash in B/hash_tree.sht with 0x42 bytes. It checks:
--   (1) every other byte of B is identical to A, and B passes the template checks: cartesi-machine-stored-hash,
--       loaded root hash and verify_hash_tree; B loaded with clear_hash_tree reproduces A (no hashed byte changed);
--   (2) the correct behavior (R1, R2, R9, R4): get_proof of an rx word folds to the root on the fresh load; after
--       one input, B reaches the same root hash as A; verify_hash_tree does not accept a wrong root; get_proof of a
--       DTB word folds after the input; and the cartesi-machine CLI computes the same mcycle computation hash (the
--       honest claim) from A and from B.
-- A is the control and must pass all checks (else harness error, exit 2). Exits 1 while the defect is present.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")

local DATA = 0x80005000 -- the guest's data page
local RX = 0x60000000 -- cmio rx buffer
local DTB = 0x7ff00000 -- device tree
local MANUAL = cartesi.HTIF_YIELD_CMD_MANUAL
local ACCEPTED = cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED

local repo = assert(os.getenv("REPO_DIR"), "harness error: source bugs/env.sh first")
local cli = repo .. "/src/cartesi-machine.lua"
local stored_hash_cli = repo .. "/src/cartesi-machine-stored-hash.lua"

local function harness(msg)
    io.stderr:write("harness error: ", msg, "\n")
    os.exit(2)
end

local tmp = assert(io.popen("mktemp -d"):read("l"), "harness error: mktemp failed")
local _ <close> = setmetatable({}, {
    __close = function()
        os.execute("rm -rf '" .. tmp .. "'")
    end,
})

local function read_file(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local s = f:read("a")
    f:close()
    return s
end

local function write_file(path, data)
    local f = assert(io.open(path, "wb"))
    f:write(data)
    f:close()
end

if not os.execute("bash ./build.sh '" .. tmp .. "'") then harness("failed to build guest.bin") end

local empty_outputs_root =
    hash_tree.frontier_get_root_hash(hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"))
local input_data = "an ordinary advance-state input"
write_file(tmp .. "/input-0.bin", input_data)

-- 1. Build and store the valid template (dir A).
local dirA, dirB = tmp .. "/A", tmp .. "/B"
local template_hash, node73_hash, node83_hash
do
    local m <close> = cartesi.machine({
        ram = { backing_store = { data_filename = tmp .. "/guest.bin" }, length = 1 << 20 },
        htif = { yield_manual = true, yield_automatic = true },
    })
    local page = string.pack("<I8", 0x1111) .. string.rep("\0", 24) .. empty_outputs_root
    m:write_memory(DATA, page)
    if m:run(1000) ~= cartesi.BREAK_REASON_YIELDED_MANUALLY then harness("template did not yield manually") end
    local cmd, reason, ydata = m:receive_cmio_request()
    if not (cmd == MANUAL and reason == ACCEPTED and ydata == empty_outputs_root) then
        harness("template is not an rx-accepted yield with the empty outputs root")
    end
    template_hash = m:get_root_hash()
    node73_hash = m:get_node_hash(0x60000000, 29)
    node83_hash = m:get_node_hash(0x70000000, 28)
    m:store(dirA)
end
print("template A: " .. cartesi.tohex(template_hash))

-- 2. Copy to B and overwrite the hash of one dormant inner node of the sparse hash tree.
if not os.execute(string.format("cp -a '%s' '%s'", dirA, dirB)) then harness("cp failed") end
local SHT_NAME = "hash_tree.sht"
local NODE, PARENT = 83, 73
local NODE_SIZE, HASH_OFF = 64, 28 -- node layout: left, right, parent (i64 each), log2_size (u32), hash (32 bytes)
do
    local path = dirB .. "/" .. SHT_NAME
    local sht = assert(read_file(path), "harness error: no " .. SHT_NAME .. " in stored machine")
    local function node(i)
        local l, r, p, sz = string.unpack("<i8i8i8I4", sht, i * NODE_SIZE + 1)
        return { left = l, right = r, parent = p, log2 = sz, hash = sht:sub(i * NODE_SIZE + HASH_OFF + 1, i * NODE_SIZE + HASH_OFF + 32) }
    end
    local n, p = node(NODE), node(PARENT)
    if not (n.parent == PARENT and n.log2 == 28 and p.right == NODE and p.log2 == 29) then
        harness("unexpected sparse tree topology for nodes 73/83")
    end
    if n.hash ~= node83_hash or p.hash ~= node73_hash then
        harness("sparse nodes 83/73 do not hold get_node_hash(0x70000000,28)/(0x60000000,29) (layout)")
    end
    local f = assert(io.open(path, "r+b"))
    f:seek("set", NODE * NODE_SIZE + HASH_OFF)
    f:write(string.rep("\x42", 32))
    f:close()
end

-- every other byte of B is identical to A
do
    local names, namesB = {}, {}
    for name in io.popen("ls -A '" .. dirA .. "'"):lines() do names[#names + 1] = name end
    for name in io.popen("ls -A '" .. dirB .. "'"):lines() do namesB[#namesB + 1] = name end
    if table.concat(names, "\n") ~= table.concat(namesB, "\n") then harness("file lists differ") end
    local differing = {}
    for _, name in ipairs(names) do
        local a, b = read_file(dirA .. "/" .. name), read_file(dirB .. "/" .. name)
        if a ~= b then
            differing[#differing + 1] = name
            if name == SHT_NAME then
                local s, e = NODE * NODE_SIZE + HASH_OFF + 1, NODE * NODE_SIZE + HASH_OFF + 32
                if #a ~= #b or a:sub(1, s - 1) ~= b:sub(1, s - 1) or a:sub(e + 1) ~= b:sub(e + 1) then
                    harness("hash_tree.sht differs outside node 83's hash")
                end
            end
        end
    end
    if table.concat(differing, ",") ~= SHT_NAME then
        harness("unexpected differing files: " .. table.concat(differing, ","))
    end
    print("B differs from A only in " .. SHT_NAME .. " (32 bytes: hash of sparse node " .. NODE .. ")")
end

local failures = {}
local function check(ok, what)
    if not ok then failures[#failures + 1] = what end
end

local function fold(p)
    local h, addr = p.target_hash, p.target_address
    for i = 1, #p.sibling_hashes do
        local log2 = p.log2_target_size + i - 1
        local s = p.sibling_hashes[i]
        if (addr >> log2) & 1 == 0 then
            h = cartesi.keccak256(h, s)
        else
            h = cartesi.keccak256(s, h)
        end
    end
    return h
end

-- 3. Template checks on B (all must pass, as the claim says).
do
    local out = io.popen("lua5.4 '" .. stored_hash_cli .. "' '" .. dirB .. "' 2>&1"):read("l")
    print("cartesi-machine-stored-hash B: " .. tostring(out))
    if out ~= cartesi.tohex(template_hash) then harness("stored-hash of B differs from the template hash") end
end

-- Loads dir, delivers one input, runs to the next yield. Returns a table of observations.
local function probe(dir, clear)
    local m <close> = cartesi.new()
    m:load(dir, { clear_hash_tree = clear })
    local r = {}
    r.load_root = m:get_root_hash()
    r.load_verify = m:verify_hash_tree()
    r.load_proof_ok = fold(m:get_proof(RX, 5)) == r.load_root
    m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input_data, r.load_root)
    r.brk = m:run(1000)
    r.final_root = m:get_root_hash()
    r.final_verify = m:verify_hash_tree()
    r.final_proof_ok = fold(m:get_proof(DTB, 5)) == r.final_root
    r.mcycle = m:read_reg("mcycle")
    r.counter = string.unpack("<I8", m:read_memory(DATA, 8))
    return r
end

local A = probe(dirA, false)
local B = probe(dirB, false)
local Bc = probe(dirB, true)
for _, x in ipairs({ { "A", A }, { "B", B }, { "B clear_hash_tree", Bc } }) do
    local n, r = x[1], x[2]
    print(
        string.format(
            "%-18s load root %s verify %s rx-proof-folds %s | after input: mcycle %d counter 0x%x root %s verify %s dtb-proof-folds %s",
            n,
            cartesi.tohex(r.load_root),
            tostring(r.load_verify),
            tostring(r.load_proof_ok),
            r.mcycle,
            r.counter,
            cartesi.tohex(r.final_root),
            tostring(r.final_verify),
            tostring(r.final_proof_ok)
        )
    )
end

-- control
if not (A.load_root == template_hash and A.load_verify and A.load_proof_ok and A.final_verify and A.final_proof_ok) then
    harness("control template A fails its own checks")
end
if A.brk ~= cartesi.BREAK_REASON_YIELDED_MANUALLY or A.counter ~= 0x1112 then harness("control guest misbehaved") end
if not (Bc.final_root == A.final_root and Bc.load_root == template_hash) then
    harness("clear_hash_tree load of B disagrees with A: the poisoning touched hashed state")
end
-- B looks like a valid template to every documented check
if not (B.load_root == template_hash and B.load_verify) then harness("B does not pass the template checks") end
if not (B.counter == A.counter and B.mcycle == A.mcycle) then harness("B contents diverged from A") end

check(B.load_proof_ok, "get_proof of an rx-buffer word on the freshly loaded template does not fold to its root")
check(B.final_root == A.final_root, "root hash after one input differs from the clear-cache run")
check(not B.final_verify or B.final_root == A.final_root, "verify_hash_tree accepts the wrong root")
check(B.final_proof_ok, "get_proof of a DTB word after the input does not fold to the reported root")

-- 4. The honest claim through the documented CLI: mcycle computation hash of a one-input epoch.
local function cli_claim(dir, name, extra)
    local out = tmp .. "/" .. name .. ".hash"
    local cmd = string.format(
        "cd '%s' && lua5.4 '%s' --no-init-splash --remote-spawn --remote-address=127.0.0.1:0 --remote-shutdown "
            .. "%s --load='%s' "
            .. "--cmio-advance-state=input:input-%%i.bin,input_file_index_begin:0,input_file_index_end:1 "
            .. "--mcycle-computation-hash=log2_mcycle_period:4,filename:'%s' >'%s.log' 2>&1",
        tmp,
        cli,
        extra or "",
        dir,
        out,
        out
    )
    local ok = os.execute(cmd)
    local h = read_file(out)
    if not ok or not h or #h ~= 32 then
        harness("CLI failed for " .. name .. ":\n" .. (read_file(out .. ".log") or ""))
    end
    return h
end
local claimA = cli_claim(dirA, "A")
local claimB = cli_claim(dirB, "B")
local claimBc = cli_claim(dirB, "Bc", "--clear-hash-tree")
print("CLI mcycle computation hash A: " .. cartesi.tohex(claimA))
print("CLI mcycle computation hash B: " .. cartesi.tohex(claimB))
print("CLI mcycle computation hash B --clear-hash-tree: " .. cartesi.tohex(claimBc))
if claimBc ~= claimA then harness("CLI claim of B with --clear-hash-tree disagrees with A") end
check(claimA == claimB, "cartesi-machine --load computes a different mcycle computation hash (honest claim)")

if #failures > 0 then
    print(
        "FAILURE: a stored template that differs from the valid one only in the hash of one dormant inner node of "
            .. "hash_tree.sht (outside the hashed contents) loads with the right root and passes stored-hash and "
            .. "verify_hash_tree, but then: "
            .. table.concat(failures, "; ")
            .. " (R1, R9, R2, R4)"
    )
    os.exit(1)
end
print("OK: the sparse hash-tree file cannot change the hashes or proofs of a loaded template")
