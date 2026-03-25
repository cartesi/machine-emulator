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
/// \brief libFuzzer harness for the RISC-V interpreter.
///
/// libFuzzer is a coverage-guided fuzzer: it generates random byte sequences,
/// feeds them to LLVMFuzzerTestOneInput(), and tracks which code paths (edges)
/// are hit. Inputs that reach new edges are saved to a corpus and mutated
/// further, gradually exploring deeper into the interpreter.
///
/// Each fuzz input is decoded into a complete machine state (registers, RAM,
/// page tables, TLB entries) and executed for up to MAX_MCYCLE cycles.
/// See fuzz-common.h for the byte layout.
///
/// Two modes are available (FUZZ_NO_PERSIST env var):
///
///   Persistent (default): one machine is created on the first input and reused.
///     Each iteration zeros RAM and overwrites the shadow state. ~44x faster.
///
///   Fresh (FUZZ_NO_PERSIST=1): a new machine is created and destroyed per input.
///     Slower, but serves as a correctness reference for the persistent reset logic.
///
/// Both modes set registers and TLB via the same shadow-state bulk write, so
/// their edge coverage is comparable. The ~3-4% difference comes from machine
/// constructor/destructor edges that only appear in fresh mode.

#include "fuzz-common.h"

#include <address-range-defines.h>

static constexpr uint64_t SHADOW_STATE_START = AR_SHADOW_STATE_START_DEF;
static constexpr uint64_t SHADOW_STATE_LENGTH = AR_SHADOW_STATE_LENGTH_DEF;

static bool g_persistent = true;
static cm_machine *g_machine = nullptr;
static uint8_t g_zero_ram[RAM_LENGTH] = {};

/// \brief Load fuzz-derived state into the persistent machine (creating it on first call).
///
/// Zeros RAM, writes page tables + code, then overwrites the entire shadow state
/// (registers + TLB) via a single bulk cm_write_memory(). The bulk write triggers
/// hot TLB reinitialization, ensuring no stale state leaks between iterations.
///
/// The fuzz reader is NOT advanced past the code bytes: fuzz_fill_tlb() deliberately
/// reuses them to derive diverse TLB entries without requiring extra input bytes.
static bool setup_persistent(fuzz_reader &r, const cartesi::registers_state &regs, bool enable_vm) {
    if (!g_machine) {
        nlohmann::json config;
        config["ram"]["length"] = RAM_LENGTH;
        const auto config_str = config.dump();
        if (cm_create_new(config_str.c_str(), nullptr, nullptr, &g_machine) != CM_ERROR_OK) {
            fuzz_abort("failed to create persistent machine");
        }
    }

    uint8_t pt_data[PAGE_TABLE_REGION] = {};
    size_t pt_data_size = 0;
    if (enable_vm) {
        pt_data_size = std::min(r.remaining, sizeof(pt_data));
        r.read_bytes(pt_data, pt_data_size);
    }

    // Snapshot code pointer without advancing r (see file-level comment on TLB reuse)
    const uint8_t *code_data = r.data;
    const size_t code_size = std::min(r.remaining, static_cast<size_t>(RAM_LENGTH - PAGE_TABLE_REGION));
    if (code_size < 4) {
        return false;
    }

    // Clear RAM so previous iteration data does not leak
    cm_write_memory(g_machine, RAM_START, g_zero_ram, RAM_LENGTH);

    // Set up SV39 page tables mapping CODE_START when VM is enabled
    if (enable_vm && pt_data_size > 0) {
        cm_write_memory(g_machine, RAM_START, pt_data, pt_data_size);

        const uint64_t l1_page_addr = RAM_START + 1 * PAGE_SIZE;
        const uint64_t l0_page_addr = RAM_START + 4 * PAGE_SIZE;
        const uint64_t code_ppn = CODE_START >> LOG2_PAGE_SIZE;

        const int vpn2 = static_cast<int>((CODE_START >> 30) & 0x1FF);
        const int vpn1 = static_cast<int>((CODE_START >> 21) & 0x1FF);
        const int vpn0 = static_cast<int>((CODE_START >> 12) & 0x1FF);

        const uint64_t l2_pte = PTE_V | ((l1_page_addr >> LOG2_PAGE_SIZE) << 10);
        cm_write_memory(g_machine, RAM_START + vpn2 * 8, reinterpret_cast<const uint8_t *>(&l2_pte), 8);

        const uint64_t l1_pte = PTE_V | ((l0_page_addr >> LOG2_PAGE_SIZE) << 10);
        cm_write_memory(g_machine, l1_page_addr + vpn1 * 8, reinterpret_cast<const uint8_t *>(&l1_pte), 8);

        const uint64_t l0_pte = PTE_V | PTE_R | PTE_W | PTE_X | PTE_U | PTE_A | PTE_D | (code_ppn << 10);
        cm_write_memory(g_machine, l0_page_addr + vpn0 * 8, reinterpret_cast<const uint8_t *>(&l0_pte), 8);
    }

    cm_write_memory(g_machine, CODE_START, code_data, code_size);

    // Build and write the complete shadow state (registers + TLB)
    const auto pmas = fuzz_discover_pmas(g_machine);
    cartesi::shadow_state shadow{};
    shadow.registers = regs;
    if (enable_vm) {
        shadow.registers.satp = SATP_MODE_SV39 | (RAM_START >> LOG2_PAGE_SIZE);
    }
    shadow.registers.mcycle = 0;
    shadow.registers.iflags.H = 0;
    shadow.registers.iflags.Y = 0;
    fuzz_fill_tlb(r, regs, pmas, shadow.tlb);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    cm_write_memory(g_machine, SHADOW_STATE_START, reinterpret_cast<const uint8_t *>(&shadow), SHADOW_STATE_LENGTH);

    return true;
}

/// \brief Fresh-mode setup: create a new machine, write RAM + shadow state.
/// Uses fuzz_create_machine() for RAM, then the same shadow-state path as persistent mode.
static cm_machine *setup_fresh(fuzz_reader &r, const cartesi::registers_state &regs, bool enable_vm) {
    cm_machine *machine = fuzz_create_machine(r, enable_vm);
    if (!machine) {
        return nullptr;
    }

    const auto pmas = fuzz_discover_pmas(machine);
    cartesi::shadow_state shadow{};
    shadow.registers = regs;
    if (enable_vm) {
        shadow.registers.satp = SATP_MODE_SV39 | (RAM_START >> LOG2_PAGE_SIZE);
    }
    shadow.registers.mcycle = 0;
    shadow.registers.iflags.H = 0;
    shadow.registers.iflags.Y = 0;
    fuzz_fill_tlb(r, regs, pmas, shadow.tlb);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    cm_write_memory(machine, SHADOW_STATE_START, reinterpret_cast<const uint8_t *>(&shadow), SHADOW_STATE_LENGTH);

    return machine;
}

/// \brief Called once by libFuzzer before any inputs are processed.
/// Machine creation is deferred to LLVMFuzzerTestOneInput() so its edges
/// are counted (LLVMFuzzerInitialize runs before coverage tracking starts).
extern "C" __attribute__((visibility("default"))) int LLVMFuzzerInitialize(int * /*argc*/, char *** /*argv*/) {
    if (getenv("FUZZ_NO_PERSIST")) {
        g_persistent = false;
    }
    return 0;
}

/// \brief Called by libFuzzer for each fuzz input.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) {
        return 0;
    }

    fuzz_reader r{data, size};

    cartesi::registers_state regs{};
    bool enable_vm = false;
    fuzz_read_registers(r, regs, enable_vm);

    if (g_persistent) {
        if (!setup_persistent(r, regs, enable_vm)) {
            return 0;
        }
        cm_break_reason break_reason{};
        cm_run(g_machine, MAX_MCYCLE, &break_reason);
    } else {
        cm_machine *machine = setup_fresh(r, regs, enable_vm);
        if (!machine) {
            return 0;
        }
        cm_break_reason break_reason{};
        cm_run(machine, MAX_MCYCLE, &break_reason);
        cm_delete(machine);
    }

    return 0;
}
