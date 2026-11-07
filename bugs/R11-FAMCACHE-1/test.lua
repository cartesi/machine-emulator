#!/usr/bin/env lua5.4
-- R11-FAMCACHE-1: loading a stored machine adopts the dense hash-tree files (<range>.dht/.dpt) as is. A transferred
-- template whose hashed contents are exactly the valid template's (same .bin contents, same content hash) but with one
-- wrong interior node in the RAM .dht keeps the right root, passes cartesi-machine-stored-hash and verify_hash_tree,
-- and then computes proofs that do not fold and wrong root hashes and claims.
--
-- The dense tree is a heap array (index 1 = range root, page leaves from 2^(L-1)). For 1 MiB RAM (L = 9), node 131
-- covers pages 6-7 (offset 0x6000, log2 size 13); it is the sibling of node 130 (pages 4-5), which holds the
-- guest's data page 0x80005000. Overwriting node 131 while its parent keeps its stored value changes neither the
-- range root nor the sparse tree, and verify() checks only page leaves and the range root. Afterwards:
--   * get_proof of a word in the data page uses node 131 as its log2-13 sibling, so it does not fold to the root;
--   * when the guest writes the data page, update_dense_trees recomputes node 65 from node 130 and the wrong node 131,
--     so the RAM range root and the machine root become wrong.
--
-- The test builds a valid template with a small bare-metal rollup guest (guest.S, built at test time) that yields
-- manual rx-accepted with the empty outputs root, and on each advance-state input increments a counter in its data
-- page (one dword write) and yields rx-accepted again. It stores the template (dir A), copies it to dir B, and in
-- B/0000000080000000-100000.dht replaces only node 131 (32 bytes) with 0x42 bytes. It checks:
--   (1) every other file in B is byte-identical to A, and B passes the template checks: cartesi-machine-stored-hash,
--       loaded root hash and verify_hash_tree; B loaded with clear_hash_tree reproduces A (no hashed byte changed);
--   (2) the correct behavior (R1, R2, R9, R4): get_proof of the data word folds to the root on the fresh load; after
--       one input, B reaches the same root hash as A; verify_hash_tree does not accept a wrong root; and the
--       cartesi-machine CLI computes the same mcycle computation hash (the honest claim) from A and from B.
-- A is the control and must pass all checks (else harness error). Exits nonzero while the defect is present.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")

local RAM_START = 0x80000000
local DATA = 0x80005000 -- the guest's data page
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
local template_hash, ram_root, sibling_node
do
    local m <close> = cartesi.machine({
        ram = { backing_store = { data_filename = tmp .. "/guest.bin" }, length = 1 << 20 },
        htif = { yield_manual = true, yield_automatic = true },
    })
    -- data page: counter, padding, empty outputs root, then a fixed fill pattern
    local page = string.pack("<I8", 0x1111) .. string.rep("\0", 24) .. empty_outputs_root
    local fill = {}
    for i = 1, 4096 - #page do fill[i] = string.char((i * 37) & 0xff) end
    page = page .. table.concat(fill)
    m:write_memory(DATA, page)
    if m:run(1000) ~= cartesi.BREAK_REASON_YIELDED_MANUALLY then harness("template did not yield manually") end
    local cmd, reason, ydata = m:receive_cmio_request()
    if not (cmd == MANUAL and reason == ACCEPTED and ydata == empty_outputs_root) then
        harness("template is not an rx-accepted yield with the empty outputs root")
    end
    template_hash = m:get_root_hash()
    ram_root = m:get_node_hash(RAM_START, 20)
    sibling_node = m:get_node_hash(RAM_START + 0x6000, 13)
    m:store(dirA)
end
print("template A: " .. cartesi.tohex(template_hash))

-- 2. Copy to B and overwrite one interior node of the RAM dense hash tree.
if not os.execute(string.format("cp -a '%s' '%s'", dirA, dirB)) then harness("cp failed") end
local DHT_NAME = "0000000080000000-100000.dht"
local NODE = 131 -- heap index of the log2-13 node at RAM offset 0x6000 (pages 6-7): sibling of the data page's pair
do
    local path = dirB .. "/" .. DHT_NAME
    local dht = assert(read_file(path), "harness error: no " .. DHT_NAME .. " in stored machine")
    if #dht ~= 512 * 32 then harness("unexpected dense tree size " .. #dht) end
    if dht:sub(32 + 1, 64) ~= ram_root then harness("dense tree index 1 is not the RAM range root (layout)") end
    if dht:sub(NODE * 32 + 1, (NODE + 1) * 32) ~= sibling_node then
        harness("dense tree node 131 is not get_node_hash(0x80006000, 13) (layout)")
    end
    local f = assert(io.open(path, "r+b"))
    f:seek("set", NODE * 32)
    f:write(string.rep("\x42", 32))
    f:close()
end

-- every file other than the RAM .dht is byte-identical
do
    local names = {}
    for name in io.popen("ls -A '" .. dirA .. "'"):lines() do names[#names + 1] = name end
    local namesB = {}
    for name in io.popen("ls -A '" .. dirB .. "'"):lines() do namesB[#namesB + 1] = name end
    if table.concat(names, "\n") ~= table.concat(namesB, "\n") then harness("file lists differ") end
    local differing = {}
    for _, name in ipairs(names) do
        if read_file(dirA .. "/" .. name) ~= read_file(dirB .. "/" .. name) then differing[#differing + 1] = name end
    end
    if table.concat(differing, ",") ~= DHT_NAME then
        harness("unexpected differing files: " .. table.concat(differing, ","))
    end
    print("B differs from A only in " .. DHT_NAME .. " (32 bytes, node " .. NODE .. ")")
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
    local out = io.popen("lua5.4 '" .. stored_hash_cli .. "' '" .. dirB .. "'"):read("l")
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
    local p0 = m:get_proof(DATA, 5)
    r.load_proof_ok = fold(p0) == r.load_root and p0.root_hash == r.load_root
    m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input_data, r.load_root)
    r.brk = m:run(1000)
    r.final_root = m:get_root_hash()
    r.final_verify = m:verify_hash_tree()
    local p1 = m:get_proof(DATA, 5)
    r.final_proof_ok = fold(p1) == r.final_root
    r.mcycle = m:read_reg("mcycle")
    r.counter = string.unpack("<I8", m:read_memory(DATA, 8))
    return r
end

local A = probe(dirA, false)
local B = probe(dirB, false)
local Bc = probe(dirB, true)
for _, x in ipairs({ { "A", A }, { "B", B }, { "B --clear-hash-tree", Bc } }) do
    local n, r = x[1], x[2]
    print(
        string.format(
            "%-20s load root %s verify %s proof-folds %s | after input: mcycle %d counter 0x%x root %s verify %s proof-folds %s",
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

check(B.load_proof_ok, "get_proof of the data word on the freshly loaded template does not fold to its root")
check(B.final_root == A.final_root, "root hash after one input differs from the uninterrupted/clear-cache run")
check(not B.final_verify or B.final_root == A.final_root, "verify_hash_tree accepts the wrong root")
check(B.final_proof_ok, "get_proof of the data word after the input does not fold to the reported root")

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
        "FAILURE: a stored template that differs from the valid one only in one interior node of its RAM .dht "
            .. "(outside the hashed contents) loads with the right root and passes verify_hash_tree, but then: "
            .. table.concat(failures, "; ")
            .. " (R1, R9, R2, R4)"
    )
    os.exit(1)
end
print("OK: the dense hash-tree files cannot change the hashes or proofs of a loaded template")
