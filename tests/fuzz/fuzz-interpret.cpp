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
/// \brief Fuzz harness for the RISC-V interpreter.
///
/// Exercises the interpreter with fuzzed register state, CSRs, page tables,
/// and code.
///
/// The fuzz input is consumed as a byte stream and split into:
///
///   1. Control bytes (2 bytes): privilege level and VM/MPRV/SUM/MXR/FS flags
///   2. Registers state (848 bytes): the full registers_state struct
///   3. Page table entries (variable): when virtual memory is enabled, up to
///      4096 bytes are used to construct a 3-level SV39 page table in RAM
///   4. Code/data (remainder): written at the code region in RAM
///
/// Virtual memory setup:
///   When the VM flag is set, the harness builds an SV39 page table from fuzz
///   data. The root page table is placed at a fixed offset in RAM, with PTEs
///   derived from fuzz bytes. This exercises the TLB, page walks, PTE
///   permission checks (U/S, R/W/X, A/D bits), superpage handling, and
///   misaligned superpage faults.
///
/// Seed corpus:
///   For best results, seed with binaries from tests/machine/src/*.S
///   (compiled to raw binary). A helper script is provided — see the Makefile
///   target `fuzz-seed-corpus`.

#include "fuzz-common.h"

// Entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum: control bytes + registers + at least one 4-byte instruction
    if (size < 8) {
        return 0;
    }

    fuzz_reader r{data, size};

    // Read register state from fuzz input
    cartesi::registers_state regs{};
    bool enable_vm = false;
    fuzz_read_registers(r, regs, enable_vm);

    // Create machine with fuzzed registers, page tables, and code
    cm_machine *machine = fuzz_create_machine(r, regs, enable_vm);
    if (!machine) {
        return 0;
    }

    // Run
    cm_break_reason break_reason{};
    cm_run(machine, MAX_MCYCLE, &break_reason);

    // Cleanup
    cm_delete(machine);
    return 0;
}
