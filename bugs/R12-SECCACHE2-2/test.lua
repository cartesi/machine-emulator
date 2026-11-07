#!/usr/bin/env lua5.4
-- R12-SECCACHE2-2: loading a stored machine adopts each range's dirty-page tree (<range>.dpt) as is. Only byte 0
-- (the "initialized" flag) is examined; the invariant "a dirty node has dirty ancestors" is never checked.
-- do_mark_dirty_leaf_position_and_up stops at the first node that is already dirty, and the hash-tree update only
-- descends from a dirty root through dirty children. So if an interior node N is stored dirty under a clean root,
-- every later write to a page under N marks the leaf, stops at N, leaves the root clean, and the update never
-- rehashes that page: the machine reports a stale root hash.
--
-- With a 1 MiB RAM range (0x80000000, 256 pages, dpt = 512-byte heap, leaves at 256..511), the guest's data page
-- 0x80005000 is leaf 261, parent 130, grandparent 65. The test:
--   * builds a valid template with a small bare-metal rollup guest (guest.S, built at test time) that yields manual
--     rx-accepted with the empty outputs root and, on each advance-state input, increments a counter in its data
--     page and yields rx-accepted again; stores it (dir A);
--   * copies A to B and sets byte 65 of B/0000000080000000-100000.dpt to 1 (dpt is not part of the hashed state);
--   * checks B is byte-identical to A elsewhere, and passes the template checks (cartesi-machine-stored-hash,
--     loaded root hash, verify_hash_tree), and B loaded with clear_hash_tree reproduces A;
--   * correct behavior (R1, R2, R4, R9): after one advance-state input, B reports the same root hash as A (and as B
--     loaded with clear_hash_tree), its reported root equals the content hash of what it stores, get_proof of the
--     data page folds to the reported root, and the cartesi-machine CLI computes the same mcycle computation hash
--     (the honest claim) from A and from B.
-- A is the control and must pass all checks (else harness error, exit 2). Exits 1 while the defect is present.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")

local DATA = 0x80005000 -- the guest's data page
local RAM = 0x80000000
local DPT_NAME = "0000000080000000-100000.dpt"
local NODE = 65 -- interior node of the RAM dpt covering pages 4..7 (0x80004000..0x80007fff)
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
local template_hash
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
    m:store(dirA)
end
print("template A: " .. cartesi.tohex(template_hash))

-- 2. Copy to B and mark one interior node of the RAM dirty-page tree dirty (root and other ancestors stay clean).
if not os.execute(string.format("cp -a '%s' '%s'", dirA, dirB)) then harness("cp failed") end
do
    local path = dirB .. "/" .. DPT_NAME
    local dpt = assert(read_file(path), "harness error: no " .. DPT_NAME .. " in stored machine")
    if #dpt ~= 512 then harness("unexpected dpt size " .. #dpt) end
    -- the stored template's dpt is clean everywhere except the init flag at byte 0
    if dpt:byte(1) == 0 or dpt:sub(2) ~= string.rep("\0", 511) then harness("stored dpt of A is not clean") end
    -- node 65 is the grandparent of the data page's leaf: 256 + 5 = 261 -> 130 -> 65
    local leaf = 256 + ((DATA - RAM) >> 12)
    if leaf // 4 ~= NODE then harness("data page is not under dpt node " .. NODE) end
    local f = assert(io.open(path, "r+b"))
    f:seek("set", NODE)
    f:write("\1")
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
            if name == DPT_NAME then
                if #a ~= #b or a:sub(1, NODE) ~= b:sub(1, NODE) or a:sub(NODE + 2) ~= b:sub(NODE + 2) then
                    harness(DPT_NAME .. " differs outside byte " .. NODE)
                end
            end
        end
    end
    if table.concat(differing, ",") ~= DPT_NAME then
        harness("unexpected differing files: " .. table.concat(differing, ","))
    end
    print("B differs from A only in byte " .. NODE .. " of " .. DPT_NAME .. " (0 -> 1)")
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

-- 3. Template checks on B (all must pass).
do
    local out = io.popen("lua5.4 '" .. stored_hash_cli .. "' '" .. dirB .. "' 2>&1"):read("l")
    print("cartesi-machine-stored-hash B: " .. tostring(out))
    if out ~= cartesi.tohex(template_hash) then harness("stored-hash of B differs from the template hash") end
end

-- Loads dir, delivers one input, runs to the next yield, stores the result. Returns a table of observations.
local function probe(dir, clear, name)
    local r = {}
    do
        local m <close> = cartesi.new()
        m:load(dir, { clear_hash_tree = clear })
        r.load_root = m:get_root_hash()
        r.load_verify = m:verify_hash_tree()
        m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input_data, r.load_root)
        r.brk = m:run(1000)
        r.counter = string.unpack("<I8", m:read_memory(DATA, 8))
        r.mcycle = m:read_reg("mcycle")
        r.final_root = m:get_root_hash()
        r.final_verify = m:verify_hash_tree()
        r.final_proof_ok = fold(m:get_proof(DATA, 12)) == r.final_root
        m:store(tmp .. "/" .. name .. "-after")
    end
    -- content hash of the stored post-input state, recomputed from its contents alone
    do
        local m <close> = cartesi.new()
        m:load(tmp .. "/" .. name .. "-after", { clear_hash_tree = true })
        r.rehash_root = m:get_root_hash()
    end
    os.execute("rm -rf '" .. tmp .. "/" .. name .. "-after'")
    return r
end

local A = probe(dirA, false, "A")
local B = probe(dirB, false, "B")
local Bc = probe(dirB, true, "Bc")
for _, x in ipairs({ { "A", A }, { "B", B }, { "B clear_hash_tree", Bc } }) do
    local n, r = x[1], x[2]
    print(string.format("%-18s load root %s verify %s | counter %d root after input %s verify %s rehash %s",
        n, cartesi.tohex(r.load_root):sub(1, 18), tostring(r.load_verify), r.counter,
        cartesi.tohex(r.final_root):sub(1, 18), tostring(r.final_verify), cartesi.tohex(r.rehash_root):sub(1, 18)))
end

-- controls
if A.brk ~= cartesi.BREAK_REASON_YIELDED_MANUALLY or A.counter ~= 0x1112 then harness("guest did not process input") end
if not (A.load_root == template_hash and A.load_verify and A.final_verify and A.final_proof_ok) then
    harness("control A failed its own checks")
end
if A.rehash_root ~= A.final_root then harness("control A root differs from its rehash") end
if not (Bc.final_root == A.final_root and Bc.load_root == template_hash) then
    harness("clear_hash_tree load of B disagrees with A: the poisoning touched hashed state")
end
-- B looks like a valid template to every documented check
if not (B.load_root == template_hash and B.load_verify) then harness("B does not pass the template checks") end
if not (B.counter == A.counter and B.mcycle == A.mcycle and B.brk == A.brk) then harness("B contents diverged from A") end
if B.rehash_root ~= A.final_root then harness("B's stored post-input contents differ from A's") end

check(B.final_root == A.final_root, "root hash after one input differs from the clean run")
check(B.final_root == B.rehash_root, "reported root hash is not the content hash of the machine's own contents")
check(not B.final_verify or B.final_root == A.final_root, "verify_hash_tree accepts the stale root")
check(B.final_proof_ok, "get_proof of the data page does not fold to the reported root")

-- 4. The honest claim through the documented CLI: mcycle computation hash of a one-input epoch.
local function cli_claim(dir, name, extra)
    local out = tmp .. "/" .. name .. ".hash"
    local cmd = string.format(
        "cd '%s' && lua5.4 '%s' --no-init-splash --remote-spawn --remote-address=127.0.0.1:0 --remote-shutdown "
            .. "%s --load='%s' "
            .. "--cmio-advance-state=input:input-%%i.bin,input_file_index_begin:0,input_file_index_end:1 "
            .. "--mcycle-computation-hash=log2_mcycle_period:4,filename:'%s' >'%s.log' 2>&1",
        tmp, cli, extra or "", dir, out, out
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
        "FAILURE: a stored template that differs from the valid one only in byte " .. NODE .. " of its RAM "
            .. "dirty-page tree (an interior node marked dirty under a clean root, outside the hashed contents) "
            .. "loads with the right root and passes stored-hash and verify_hash_tree, but then the guest's write "
            .. "to its data page is never rehashed: "
            .. table.concat(failures, "; ")
            .. " (R1, R9, R2, R4)"
    )
    os.exit(1)
end
print("OK: the dirty-page tree file of a stored template cannot change the hashes of later transitions")
