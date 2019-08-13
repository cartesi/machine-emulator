// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef MACHINE_CONFIG_H
#define MACHINE_CONFIG_H

#include <cstdint>
#include <string>
#include <boost/container/static_vector.hpp>

#include "riscv-constants.h"

namespace cartesi {

struct processor_config final {
    uint64_t x[32]{};
    uint64_t pc{PC_INIT};
    uint64_t mvendorid{MVENDORID_INIT};
    uint64_t marchid{MARCHID_INIT};
    uint64_t mimpid{MIMPID_INIT};
    uint64_t mcycle{MCYCLE_INIT};
    uint64_t minstret{MINSTRET_INIT};
    uint64_t mstatus{MSTATUS_INIT};
    uint64_t mtvec{MTVEC_INIT};
    uint64_t mscratch{MSCRATCH_INIT};
    uint64_t mepc{MEPC_INIT};
    uint64_t mcause{MCAUSE_INIT};
    uint64_t mtval{MTVAL_INIT};
    uint64_t misa{MISA_INIT};
    uint64_t mie{MIE_INIT};
    uint64_t mip{MIP_INIT};
    uint64_t medeleg{MEDELEG_INIT};
    uint64_t mideleg{MIDELEG_INIT};
    uint64_t mcounteren{MCOUNTEREN_INIT};
    uint64_t stvec{STVEC_INIT};
    uint64_t sscratch{SSCRATCH_INIT};
    uint64_t sepc{SEPC_INIT};
    uint64_t scause{SCAUSE_INIT};
    uint64_t stval{STVAL_INIT};
    uint64_t satp{SATP_INIT};
    uint64_t scounteren{SCOUNTEREN_INIT};
    uint64_t ilrsc{ILRSC_INIT};
    uint64_t iflags{IFLAGS_INIT};
    std::string backing{};
};

struct ram_config final {
    uint64_t length{0};
    std::string backing{};
};

struct rom_config final {
    std::string bootargs{};
    std::string backing{};
};

struct flash_config final {
    uint64_t start{0};
    uint64_t length{0};
    bool shared{false};
    std::string backing{};
};

struct clint_config final {
    uint64_t mtimecmp{0};
    std::string backing{};
};

struct htif_config final {
    uint64_t fromhost{0};
    uint64_t tohost{0};
    std::string backing{};
};

/// \brief FLASH constants
enum FLASH_constants {
    FLASH_MAX = 8 ///< Maximum number of flash drives
};

struct machine_config final {
    processor_config processor{};
    ram_config ram{};
    rom_config rom{};
    boost::container::static_vector<flash_config, FLASH_MAX> flash{};
    clint_config clint{};
    htif_config htif{};
    bool interactive{false};
};

} // namespace cartesi

#endif
