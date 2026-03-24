#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later
--
-- This program is free software: you can redistribute it and/or modify it under
-- the terms of the GNU Lesser General Public License as published by the Free
-- Software Foundation, either version 3 of the License, or (at your option) any
-- later version.
--
-- This program is distributed in the hope that it will be useful, but WITHOUT ANY
-- WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
-- PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
--
-- You should have received a copy of the GNU Lesser General Public License along
-- with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
--

--- Generates fuzz seed corpus by running RISC-V ISA tests and snapshotting
--- machine state at every unique PC during interesting execution phases.
---
--- Each seed file has the layout expected by the fuzz harnesses:
---   [1B priv] [1B flags] [848B registers_state] [page_table_data...] [code...]
---
--- The script steps through each test one instruction at a time and snapshots
--- the first time each unique PC value is seen (in non-M-mode for VM tests).
--- This naturally captures every distinct instruction the test exercises,
--- with the specific register/CSR state set up for that instruction, while
--- deduplicating loop iterations.
---
--- At each snapshot:
---   - registers_state is read from shadow memory (address 0x0, 848 bytes)
---   - code is read from the current PC (via read_virtual_memory if VM is on)
---   - PC is patched to CODE_START so the harness overlay PTE ensures executability
---   - SV39 page tables are extracted and remapped to the harness layout (VM tests)
---
--- Usage: lua5.4 gen-seed-corpus.lua <output-dir> [--test-path=<path>]

local cartesi = require("cartesi")

-- Fuzz harness constants (must match fuzz-common.h)
local RAM_START <const> = 0x80000000
local RAM_LENGTH <const> = 1 << 16 -- 64 KiB (must match fuzz-common.h)
local PAGE_SIZE <const> = 1 << 12
local PAGE_TABLE_REGION <const> = 5 * PAGE_SIZE
local CODE_START <const> = RAM_START + PAGE_TABLE_REGION
local MAX_CODE_SIZE <const> = 4096

-- Shadow state
local SHADOW_REGISTERS_START <const> = 0x0
local REGISTERS_STATE_SIZE <const> = 106 * 8 -- 848 bytes
local PC_OFFSET <const> = 33 * 8 -- pc is the 34th uint64 in registers_state

-- SV39
local PTE_V <const> = 1 << 0
local PTE_R <const> = 1 << 1
local PTE_W <const> = 1 << 2
local PTE_X <const> = 1 << 3
local PTES_PER_PAGE <const> = PAGE_SIZE // 8 -- 512
local PPN_MASK <const> = (1 << 44) - 1

-- Fuzz harness page table physical addresses
local FUZZ_PT_PADDR = {
    [0] = RAM_START,                  -- l1pt
    [1] = RAM_START + 1 * PAGE_SIZE,  -- user_l2pt
    [2] = RAM_START + 2 * PAGE_SIZE,  -- ext_io_l2pt
    [3] = RAM_START + 3 * PAGE_SIZE,  -- kernel_l2pt
    [4] = RAM_START + 4 * PAGE_SIZE,  -- user_llpt
}

-- Tests that stress supervisor/user modes and virtual memory.
local vm_tests = {
    -- Supervisor mode tests
    { "rv64si-p-csr.bin", 192 },
    { "rv64si-p-dirty.bin", 173 },
    { "rv64si-p-icache-alias.bin", 223 },
    { "rv64si-p-ma_fetch.bin", 121 },
    { "rv64si-p-sbreak.bin", 101 },
    { "rv64si-p-scall.bin", 108 },
    { "rv64si-p-wfi.bin", 87 },
    -- Virtual memory load/store (page faults, demand paging)
    { "rv64ui-v-lb.bin", 13535 },
    { "rv64ui-v-lbu.bin", 13535 },
    { "rv64ui-v-ld.bin", 13717 },
    { "rv64ui-v-lh.bin", 13551 },
    { "rv64ui-v-lhu.bin", 13560 },
    { "rv64ui-v-lw.bin", 13565 },
    { "rv64ui-v-lwu.bin", 13599 },
    { "rv64ui-v-sb.bin", 13247 },
    { "rv64ui-v-sd.bin", 19263 },
    { "rv64ui-v-sh.bin", 13300 },
    { "rv64ui-v-sw.bin", 13307 },
    -- Instruction cache coherence through VM
    { "rv64ui-v-fence_i.bin", 13125 },
    -- Cartesi-specific VM/exception/interrupt tests
    { "pte_reserved_exception.bin", 30 },
    { "xpie_exceptions.bin", 47 },
    { "interrupts.bin", 8209 },
    { "mtime_interrupt.bin", 16404 },
    { "translate_vaddr.bin", 343 },
}

-- Physical-mode tests for register state diversity (no page tables).
local phys_tests = {
    { "rv64mi-p-access.bin", 140 },
    { "rv64mi-p-breakpoint.bin", 111 },
    { "rv64mi-p-csr.bin", 293 },
    { "rv64mi-p-illegal.bin", 357 },
    { "rv64mi-p-ld-misaligned.bin", 365 },
    { "rv64mi-p-lh-misaligned.bin", 117 },
    { "rv64mi-p-lw-misaligned.bin", 177 },
    { "rv64mi-p-ma_addr.bin", 738 },
    { "rv64mi-p-ma_fetch.bin", 134 },
    { "rv64mi-p-mcsr.bin", 99 },
    { "rv64mi-p-sbreak.bin", 107 },
    { "rv64mi-p-scall.bin", 91 },
    { "rv64mi-p-sd-misaligned.bin", 385 },
    { "rv64mi-p-sh-misaligned.bin", 125 },
    { "rv64mi-p-sw-misaligned.bin", 181 },
    { "rv64ua-p-lrsc.bin", 6276 },
    { "lrsc_semantics.bin", 31 },
    { "amo.bin", 162 },
    { "csr_semantics.bin", 378 },
    { "csr_counters.bin", 737 },
    { "illegal_insn.bin", 972 },
    { "access.bin", 97 },
    { "clint_ops.bin", 133 },
    { "shadow_ops.bin", 78 },
    { "compressed.bin", 410 },
}

--- Read a uint64 from a binary string at a byte offset (0-based).
local function read_u64(data, offset)
    return string.unpack("<I8", data, offset + 1)
end

--- Write a uint64 into a binary string at a byte offset (0-based).
local function write_u64(data, offset, val)
    return data:sub(1, offset) .. string.pack("<I8", val) .. data:sub(offset + 9)
end

--- Return true if a PTE is a non-leaf (valid, but no R/W/X).
local function is_non_leaf_pte(pte)
    return (pte & PTE_V) ~= 0 and (pte & (PTE_R | PTE_W | PTE_X)) == 0
end

--- Get the physical address a PTE points to.
local function pte_paddr(pte)
    return ((pte >> 10) & PPN_MASK) << 12
end

--- Rewrite the PPN in a PTE, preserving flags.
local function pte_set_ppn(pte, paddr)
    return (pte & 0x3FF) | ((paddr >> 12) << 10)
end

--- Extract SV39 page tables from a running machine.
--- Walks the tree from satp, collects up to 5 pages, and remaps
--- internal PPNs to the fuzz harness layout.
local function extract_page_tables(machine)
    local satp = machine:read_reg("satp")
    if (satp >> 60) ~= 8 then
        return string.rep("\0", PAGE_TABLE_REGION)
    end

    local root_paddr = (satp & PPN_MASK) << 12
    local l1pt = machine:read_memory(root_paddr, PAGE_SIZE)

    local child_pages = {}
    local orig_paddrs = {}
    for i = 0, PTES_PER_PAGE - 1 do
        local pte = read_u64(l1pt, i * 8)
        if is_non_leaf_pte(pte) then
            local paddr = pte_paddr(pte)
            if not orig_paddrs[paddr] then
                local page_data = machine:read_memory(paddr, PAGE_SIZE)
                child_pages[#child_pages + 1] = { l1_index = i, data = page_data, paddr = paddr }
                orig_paddrs[paddr] = #child_pages
                if #child_pages >= 4 then break end
            end
        end
    end

    local l0_source = nil
    for ci, child in ipairs(child_pages) do
        for i = 0, PTES_PER_PAGE - 1 do
            local pte = read_u64(child.data, i * 8)
            if is_non_leaf_pte(pte) then
                l0_source = {
                    parent_idx = ci,
                    index_in_parent = i,
                    paddr = pte_paddr(pte),
                    data = machine:read_memory(pte_paddr(pte), PAGE_SIZE),
                }
                break
            end
        end
        if l0_source then break end
    end

    local pages = { [0] = l1pt }
    local paddr_to_slot = {}
    paddr_to_slot[root_paddr] = 0

    for ci, child in ipairs(child_pages) do
        local slot = ci
        if l0_source and slot >= 4 then break end
        pages[slot] = child.data
        paddr_to_slot[child.paddr] = slot
    end

    if l0_source then
        pages[4] = l0_source.data
        paddr_to_slot[l0_source.paddr] = 4
    end

    for slot = 0, 4 do
        if not pages[slot] then
            pages[slot] = string.rep("\0", PAGE_SIZE)
        end
    end

    for slot = 0, 3 do
        for i = 0, PTES_PER_PAGE - 1 do
            local pte = read_u64(pages[slot], i * 8)
            if is_non_leaf_pte(pte) then
                local target_slot = paddr_to_slot[pte_paddr(pte)]
                if target_slot then
                    pages[slot] = write_u64(pages[slot], i * 8,
                        pte_set_ppn(pte, FUZZ_PT_PADDR[target_slot]))
                end
            end
        end
    end

    return pages[0] .. pages[1] .. pages[2] .. pages[3] .. pages[4]
end

--- Derive control bytes from machine state.
local function derive_control_bytes(machine)
    local iprv = machine:read_reg("iprv")
    local mstatus = machine:read_reg("mstatus")
    local satp = machine:read_reg("satp")

    local priv_byte
    if iprv == 0 then priv_byte = 0
    elseif iprv == 1 then priv_byte = 1
    else priv_byte = 3
    end

    local flags_byte = 0
    if (satp >> 60) == 8 then flags_byte = flags_byte | 0x01 end
    if (mstatus & (1 << 17)) ~= 0 then flags_byte = flags_byte | 0x02 end
    if (mstatus & (1 << 18)) ~= 0 then flags_byte = flags_byte | 0x04 end
    if (mstatus & (1 << 19)) ~= 0 then flags_byte = flags_byte | 0x08 end
    if ((mstatus >> 13) & 0x3) == 0x3 then flags_byte = flags_byte | 0x10 end

    return string.char(priv_byte, flags_byte)
end

--- Write a seed file.
local function write_seed(path, control_bytes, regs_data, pt_data, code_data)
    local f <close> = assert(io.open(path, "wb"))
    f:write(control_bytes)
    f:write(regs_data)
    if pt_data then f:write(pt_data) end
    f:write(code_data)
end

--- Build a machine with enough RAM to run the test binary.
--- Seeds are produced targeting the fuzz harness layout (CODE_START, page tables),
--- but the machine needs full RAM to execute the test's setup code.
local function build_machine(test_path, ram_image)
    return cartesi.machine({
        ram = {
            length = 32 << 20,
            backing_store = {
                data_filename = test_path .. "/" .. ram_image,
            },
        },
        flash_drive = { {
            start = 0x80000000000000,
            length = 0x40000,
        } },
    })
end

--- Read code from the current PC.
local function read_code_at_pc(machine)
    local pc = machine:read_reg("pc")
    local satp = machine:read_reg("satp")
    local vm_on = (satp >> 60) == 8
    local ok, code
    if vm_on then
        ok, code = pcall(machine.read_virtual_memory, machine, pc, MAX_CODE_SIZE)
    else
        ok, code = pcall(machine.read_memory, machine, pc, MAX_CODE_SIZE)
    end
    if not ok then
        return string.rep("\0", MAX_CODE_SIZE)
    end
    return code
end

--- Take a snapshot at the current machine state.
local function snapshot(machine, seed_path, has_vm)
    local ctl = derive_control_bytes(machine)
    local regs = machine:read_memory(SHADOW_REGISTERS_START, REGISTERS_STATE_SIZE)
    local code = read_code_at_pc(machine)
    regs = write_u64(regs, PC_OFFSET, CODE_START)
    local pt_data = nil
    if has_vm then
        pt_data = extract_page_tables(machine)
    end
    write_seed(seed_path, ctl, regs, pt_data, code)
end

--- Process a test: step one instruction at a time, snapshot at every unique PC.
--- For VM tests, only non-M-mode PCs are considered.
local function process_test(machine, name, expected_cycles, seed_dir, has_vm)
    local seen_pcs = {}
    local seeds = 0

    while true do
        local mcycle = machine:read_reg("mcycle")
        if mcycle >= expected_cycles then break end
        if machine:read_reg("iflags_H") ~= 0 then break end

        local dominated = has_vm and machine:read_reg("iprv") == 3

        if not dominated then
            local pc = machine:read_reg("pc")
            if not seen_pcs[pc] then
                seen_pcs[pc] = true
                snapshot(machine, string.format("%s/%s-snap%d", seed_dir, name, seeds), has_vm)
                seeds = seeds + 1
            end
        end

        machine:run(mcycle + 1)
    end

    return seeds
end

--- Process a list of tests.
local function process_tests(tests, seed_dir, test_path, has_vm)
    local total = 0
    local skipped = 0
    for _, test in ipairs(tests) do
        local ram_image = test[1]
        local expected_cycles = test[2]
        local name = ram_image:gsub("%.bin$", "")

        io.stderr:write(string.format("  %s (%d cycles)...", name, expected_cycles))

        local ok, result = pcall(function()
            local machine <close> = build_machine(test_path, ram_image)
            return process_test(machine, name, expected_cycles, seed_dir, has_vm)
        end)

        if ok then
            if result > 0 then
                io.stderr:write(string.format(" %d seeds\n", result))
                total = total + result
            else
                io.stderr:write(" no interesting points, skipping\n")
                skipped = skipped + 1
            end
        else
            io.stderr:write(string.format(" ERROR: %s\n", result))
            skipped = skipped + 1
        end
    end
    return total, skipped
end

-- Parse arguments
local seed_dir = arg[1]
if not seed_dir then
    io.stderr:write("Usage: lua5.4 gen-seed-corpus.lua <output-dir> [--test-path=<path>]\n")
    os.exit(1)
end

local test_path = os.getenv("CARTESI_TESTS_PATH") or "."

for i = 2, #arg do
    local k, v = arg[i]:match("^%-%-([%w-]+)=(.+)$")
    if k == "test-path" then
        test_path = v
    end
end

os.execute("mkdir -p " .. seed_dir)

local total_seeds = 0
local total_skipped = 0

io.stderr:write("=== VM/Supervisor tests (with page table extraction) ===\n")
local s, k = process_tests(vm_tests, seed_dir, test_path, true)
total_seeds = total_seeds + s
total_skipped = total_skipped + k

io.stderr:write("\n=== Physical-mode tests (register state only) ===\n")
s, k = process_tests(phys_tests, seed_dir, test_path, false)
total_seeds = total_seeds + s
total_skipped = total_skipped + k

io.stderr:write(string.format("\nGenerated %d seed files in %s/ (skipped %d tests)\n",
    total_seeds, seed_dir, total_skipped))
