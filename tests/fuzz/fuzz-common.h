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
/// \brief Shared utilities for fuzz harnesses.
///
/// Provides the fuzz input reader, constants, and machine setup logic
/// used by all fuzz targets.

#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <machine-c-api.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

#include <json.hpp>

// Constants

static constexpr uint64_t RAM_START = CM_AR_RAM_START;   // 0x80000000
static constexpr uint64_t RAM_LENGTH = 1U << 22;         // 4 MiB — room for page tables + code
static constexpr uint64_t MAX_MCYCLE = 2000;              // bound execution

// SV39 constants (from riscv-constants.h)
static constexpr uint64_t SATP_MODE_SV39 = UINT64_C(8) << 60;
static constexpr int LOG2_PAGE_SIZE = 12;
static constexpr uint64_t PAGE_SIZE = UINT64_C(1) << LOG2_PAGE_SIZE;
static constexpr uint64_t PTE_V = UINT64_C(1) << 0;
static constexpr uint64_t PTE_R = UINT64_C(1) << 1;
static constexpr uint64_t PTE_W = UINT64_C(1) << 2;
static constexpr uint64_t PTE_X = UINT64_C(1) << 3;
static constexpr uint64_t PTE_U = UINT64_C(1) << 4;
static constexpr uint64_t PTE_A = UINT64_C(1) << 6;
static constexpr uint64_t PTE_D = UINT64_C(1) << 7;

// RAM layout:
//   [RAM_START .. +PAGE_TABLE_REGION)  page tables (3 pages = 12 KiB)
//   [CODE_START .. +code_size)         fuzzed instructions
static constexpr uint64_t PAGE_TABLE_REGION = 3 * PAGE_SIZE; // 3 pages for SV39 3-level tables
static constexpr uint64_t CODE_START = RAM_START + PAGE_TABLE_REGION;

// Fuzz input reader

struct fuzz_reader {
    const uint8_t *data;
    size_t remaining;

    template <typename T>
    T read() {
        T val{};
        const auto n = std::min(sizeof(T), remaining);
        std::memcpy(&val, data, n);
        data += n;
        remaining -= n;
        return val;
    }

    void read_bytes(void *dst, size_t n) {
        n = std::min(n, remaining);
        std::memcpy(dst, data, n);
        data += n;
        remaining -= n;
    }

    void skip(size_t n) {
        n = std::min(n, remaining);
        data += n;
        remaining -= n;
    }
};

// CSR block layout (128 bytes)

struct csr_block {
    uint64_t mstatus;
    uint64_t medeleg;
    uint64_t mideleg;
    uint64_t mie;
    uint64_t mip;
    uint64_t mtvec;
    uint64_t mscratch;
    uint64_t mepc;
    uint64_t mcause;
    uint64_t mtval;
    uint64_t stvec;
    uint64_t sscratch;
    uint64_t sepc;
    uint64_t scause;
    uint64_t stval;
    uint64_t menvcfg;
};
static_assert(sizeof(csr_block) == 128);

/// \brief Creates a machine with fuzzed state from the fuzz input.
/// \param r Fuzz reader positioned after any target-specific control bytes.
/// \returns Pointer to the new machine, or nullptr on failure.
/// \details Consumes the fuzz input to set up control flags, CSRs, GPRs, FPRs,
/// page tables, and code. The caller is responsible for calling cm_delete().
static cm_machine *fuzz_create_machine(fuzz_reader &r) {
    // 1. Control bytes

    const uint8_t priv_byte = r.read<uint8_t>();
    const uint8_t flags_byte = r.read<uint8_t>();

    // Privilege level: 0=U, 1=S, 3=M
    static constexpr uint64_t priv_map[] = {0 /*U*/, 1 /*S*/, 3 /*M*/, 3 /*M*/};
    const uint64_t priv = priv_map[priv_byte & 0x3];

    const bool enable_vm = (flags_byte & 0x01) != 0;
    const bool enable_mprv = (flags_byte & 0x02) != 0;
    const bool enable_sum = (flags_byte & 0x04) != 0;
    const bool enable_mxr = (flags_byte & 0x08) != 0;
    const bool enable_fs = (flags_byte & 0x10) != 0; // floating-point dirty state

    // 2. CSR block (128 bytes)

    const auto csrs = r.read<csr_block>();

    // 3. GPR block (256 bytes)

    uint64_t gprs[32] = {};
    r.read_bytes(gprs, sizeof(gprs));

    // 4. FPR block (256 bytes)

    uint64_t fprs[32] = {};
    r.read_bytes(fprs, sizeof(fprs));

    // 5. Page table entries (when VM enabled)

    uint8_t pt_data[PAGE_TABLE_REGION] = {};
    size_t pt_data_size = 0;
    if (enable_vm) {
        pt_data_size = std::min(r.remaining, sizeof(pt_data));
        r.read_bytes(pt_data, pt_data_size);
    }

    // 6. Remaining = code/data

    const uint8_t *code_data = r.data;
    const size_t code_size = r.remaining;

    if (code_size < 4) {
        return nullptr; // need at least one instruction
    }

    // Create machine

    nlohmann::json config;
    config["ram"]["length"] = RAM_LENGTH;
    const auto config_str = config.dump();

    cm_machine *machine = nullptr;
    if (cm_create_new(config_str.c_str(), nullptr, nullptr, &machine) != CM_ERROR_OK) {
        return nullptr;
    }

    // Write page tables into RAM

    if (enable_vm && pt_data_size > 0) {
        cm_write_memory(machine, RAM_START, pt_data, pt_data_size);

        const uint64_t root_ppn = (RAM_START) >> LOG2_PAGE_SIZE;
        const uint64_t l1_page_addr = RAM_START + PAGE_SIZE;
        const uint64_t l0_page_addr = RAM_START + 2 * PAGE_SIZE;
        const uint64_t code_ppn = CODE_START >> LOG2_PAGE_SIZE;

        const int vpn2 = static_cast<int>((CODE_START >> 30) & 0x1FF);
        const int vpn1 = static_cast<int>((CODE_START >> 21) & 0x1FF);
        const int vpn0 = static_cast<int>((CODE_START >> 12) & 0x1FF);

        const uint64_t l2_pte = PTE_V | ((l1_page_addr >> LOG2_PAGE_SIZE) << 10);
        cm_write_memory(machine, RAM_START + vpn2 * 8, reinterpret_cast<const uint8_t *>(&l2_pte), 8);

        const uint64_t l1_pte = PTE_V | ((l0_page_addr >> LOG2_PAGE_SIZE) << 10);
        cm_write_memory(machine, l1_page_addr + vpn1 * 8, reinterpret_cast<const uint8_t *>(&l1_pte), 8);

        const uint64_t l0_pte = PTE_V | PTE_R | PTE_W | PTE_X | PTE_U | PTE_A | PTE_D | (code_ppn << 10);
        cm_write_memory(machine, l0_page_addr + vpn0 * 8, reinterpret_cast<const uint8_t *>(&l0_pte), 8);

        cm_write_reg(machine, CM_REG_SATP, SATP_MODE_SV39 | root_ppn);
    }

    // Write code into RAM

    const auto write_len = std::min(code_size, static_cast<size_t>(RAM_LENGTH - PAGE_TABLE_REGION));
    if (write_len > 0) {
        cm_write_memory(machine, CODE_START, code_data, write_len);
    }

    // Set CSRs

    uint64_t mstatus = csrs.mstatus;
    mstatus = (mstatus & ~(UINT64_C(3) << 11)) | (priv << 11);
    if (enable_mprv) {
        mstatus |= (UINT64_C(1) << 17);
    } else {
        mstatus &= ~(UINT64_C(1) << 17);
    }
    if (enable_sum) {
        mstatus |= (UINT64_C(1) << 18);
    } else {
        mstatus &= ~(UINT64_C(1) << 18);
    }
    if (enable_mxr) {
        mstatus |= (UINT64_C(1) << 19);
    } else {
        mstatus &= ~(UINT64_C(1) << 19);
    }
    if (enable_fs) {
        mstatus |= (UINT64_C(3) << 13);
    }

    cm_write_reg(machine, CM_REG_MSTATUS, mstatus);
    cm_write_reg(machine, CM_REG_MEDELEG, csrs.medeleg);
    cm_write_reg(machine, CM_REG_MIDELEG, csrs.mideleg);
    cm_write_reg(machine, CM_REG_MIE, csrs.mie);
    cm_write_reg(machine, CM_REG_MIP, csrs.mip);
    cm_write_reg(machine, CM_REG_MTVEC, csrs.mtvec);
    cm_write_reg(machine, CM_REG_MSCRATCH, csrs.mscratch);
    cm_write_reg(machine, CM_REG_MEPC, csrs.mepc);
    cm_write_reg(machine, CM_REG_MCAUSE, csrs.mcause);
    cm_write_reg(machine, CM_REG_MTVAL, csrs.mtval);
    cm_write_reg(machine, CM_REG_STVEC, csrs.stvec);
    cm_write_reg(machine, CM_REG_SSCRATCH, csrs.sscratch);
    cm_write_reg(machine, CM_REG_SEPC, csrs.sepc);
    cm_write_reg(machine, CM_REG_SCAUSE, csrs.scause);
    cm_write_reg(machine, CM_REG_STVAL, csrs.stval);
    cm_write_reg(machine, CM_REG_MENVCFG, csrs.menvcfg);

    cm_write_reg(machine, CM_REG_SENVCFG, csrs.menvcfg ^ csrs.mstatus);
    cm_write_reg(machine, CM_REG_MCOUNTEREN, csrs.medeleg & 0xFFFFFFFF);
    cm_write_reg(machine, CM_REG_SCOUNTEREN, csrs.mideleg & 0xFFFFFFFF);

    // Set privilege level
    cm_write_reg(machine, CM_REG_IPRV, priv);

    // Set GPRs

    for (int i = 1; i < 32; i++) {
        cm_write_reg(machine, static_cast<cm_reg>(CM_REG_X0 + i), gprs[i]);
    }

    // Set FPRs

    for (int i = 0; i < 32; i++) {
        cm_write_reg(machine, static_cast<cm_reg>(CM_REG_F0 + i), fprs[i]);
    }
    cm_write_reg(machine, CM_REG_FCSR, fprs[0] & 0xFF);

    // Set PC

    cm_write_reg(machine, CM_REG_PC, CODE_START);

    return machine;
}

#endif // FUZZ_COMMON_H
