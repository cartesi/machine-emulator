// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

/// \file
/// \brief Fuzz harness for shadow state bulk writes.
///
/// Unlike fuzz-interpret which sets registers one by one via cm_write_reg(),
/// this harness writes the entire shadow state (registers + TLB) as a single
/// bulk cm_write_memory() call with raw fuzz data. This exercises the shadow
/// state validation, hot TLB reinitialization, and lazy TLB verification
/// paths with hostile inputs — corrupt padding, invalid immutable fields,
/// garbage TLB entries, and arbitrary register values.
///
/// The fuzz input is consumed as:
///
///   1. Control bytes (2 bytes): privilege level and VM/MPRV/SUM/MXR/FS flags
///   2. Registers state (848 bytes): the full registers_state struct, placed
///      directly into the shadow state buffer at the correct offset
///   3. Page table entries (variable, when VM enabled)
///   4. Code/data
///   5. TLB data (remaining bytes): raw data for the shadow TLB region
///
/// Steps 1-4 are consumed by fuzz_create_machine() to set up plausible RAM
/// (code, SV39 page tables). The registers from step 2 are placed into the
/// shadow state buffer at the struct-correct offset, so the same fuzz bytes
/// that produce interesting CSR/GPR/FPR combinations in fuzz-interpret end
/// up in the matching shadow state positions here. Step 5 provides
/// independent bytes for TLB slots.

#include "fuzz-common.h"

#include <address-range-defines.h>

static constexpr size_t SHADOW_STATE_SIZE = AR_SHADOW_STATE_LENGTH_DEF; // 0x8000 = 32 KiB

// Entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) {
        return 0;
    }

    fuzz_reader r{data, size};

    // Read register state from fuzz input
    cartesi::registers_state regs{};
    bool enable_vm = false;
    fuzz_read_registers(r, regs, enable_vm);

    // Set up a machine with plausible RAM: code, page tables, virtual memory
    cm_machine *machine = fuzz_create_machine(r, regs, enable_vm);
    if (!machine) {
        return 0;
    }

    // Discover all PMAs in the machine for crafting plausible TLB entries
    const auto pmas = fuzz_discover_pmas(machine);

    // Build the shadow state with fuzzed registers and crafted TLB entries
    cartesi::shadow_state shadow{};
    shadow.registers = regs;
    fuzz_fill_tlb(r, regs, pmas, shadow.tlb);

    // Write the hostile shadow state
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    cm_write_memory(machine, AR_SHADOW_STATE_START_DEF,
        reinterpret_cast<const uint8_t *>(&shadow), sizeof(shadow));

    // Restore fields that would prevent execution from happening at all.
    // PC: must point to code region, otherwise immediate trap with no useful work.
    // mcycle: a random uint64 is almost certainly > MAX_MCYCLE, so cm_run returns instantly.
    // iflags H/Y: if set, cm_run returns immediately without executing.
    cm_write_reg(machine, CM_REG_PC, CODE_START);
    cm_write_reg(machine, CM_REG_MCYCLE, 0);
    cm_write_reg(machine, CM_REG_IFLAGS_H, 0);
    cm_write_reg(machine, CM_REG_IFLAGS_Y, 0);

    // Run
    cm_break_reason break_reason{};
    cm_run(machine, MAX_MCYCLE, &break_reason);

    // Cleanup
    cm_delete(machine);
    return 0;
}
