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

#include <array>
#include <boost/container/static_vector.hpp>
#include <cstdint>
#include <optional>
#include <string>

#include "riscv-constants.h"
#include "uarch-config.h"

namespace cartesi {

/// \brief Processor state configuration
struct processor_config final {
    std::array<uint64_t, X_REG_COUNT> x{}; ///< Value of general-purpose registers
    std::array<uint64_t, F_REG_COUNT> f{}; ///< Value of floating-point registers
    uint64_t pc{PC_INIT};                  ///< Value of pc
    uint64_t fcsr{FCSR_INIT};              ///< Value of fcsr CSR
    uint64_t mvendorid{MVENDORID_INIT};    ///< Value of mvendorid CSR
    uint64_t marchid{MARCHID_INIT};        ///< Value of marchid CSR
    uint64_t mimpid{MIMPID_INIT};          ///< Value of mimpid CSR
    uint64_t mcycle{MCYCLE_INIT};          ///< Value of mcycle CSR
    uint64_t minstret{MINSTRET_INIT};      ///< Value of minstret CSR
    uint64_t mstatus{MSTATUS_INIT};        ///< Value of mstatus CSR
    uint64_t mtvec{MTVEC_INIT};            ///< Value of mtvec CSR
    uint64_t mscratch{MSCRATCH_INIT};      ///< Value of mscratch CSR
    uint64_t mepc{MEPC_INIT};              ///< Value of mepc CSR
    uint64_t mcause{MCAUSE_INIT};          ///< Value of mcause CSR
    uint64_t mtval{MTVAL_INIT};            ///< Value of mtval CSR
    uint64_t misa{MISA_INIT};              ///< Value of misa CSR
    uint64_t mie{MIE_INIT};                ///< Value of mie CSR
    uint64_t mip{MIP_INIT};                ///< Value of mip CSR
    uint64_t medeleg{MEDELEG_INIT};        ///< Value of medeleg CSR
    uint64_t mideleg{MIDELEG_INIT};        ///< Value of mideleg CSR
    uint64_t mcounteren{MCOUNTEREN_INIT};  ///< Value of mcounteren CSR
    uint64_t menvcfg{MENVCFG_INIT};        ///< Value of menvcfg CSR
    uint64_t stvec{STVEC_INIT};            ///< Value of stvec CSR
    uint64_t sscratch{SSCRATCH_INIT};      ///< Value of sscratch CSR
    uint64_t sepc{SEPC_INIT};              ///< Value of sepc CSR
    uint64_t scause{SCAUSE_INIT};          ///< Value of scause CSR
    uint64_t stval{STVAL_INIT};            ///< Value of stval CSR
    uint64_t satp{SATP_INIT};              ///< Value of satp CSR
    uint64_t scounteren{SCOUNTEREN_INIT};  ///< Value of scounteren CSR
    uint64_t senvcfg{SENVCFG_INIT};        ///< Value of senvcfg CSR
    uint64_t ilrsc{ILRSC_INIT};            ///< Value of ilrsc CSR
    uint64_t iflags{IFLAGS_INIT};          ///< Value of iflags CSR
    bool brkflag{false};                   ///< Break flag
};

/// \brief RAM state configuration
struct ram_config final {
    uint64_t length{0};           ///< RAM length
    std::string image_filename{}; ///< RAM image file name
};

/// \brief ROM state configuration
struct rom_config final {
    std::string bootargs{};       ///< Bootargs to pass to kernel
    std::string image_filename{}; ///< ROM image file
};

/// \brief Memory range configuration
struct memory_range_config final {
    uint64_t start{0};            ///< Memory range start position
    uint64_t length{0};           ///< Memory range length
    bool shared{false};           ///< Target changes to memory affect image file?
    std::string image_filename{}; ///< Memory range image file name
};

/// \brief Flash constants
enum FLASH_DRIVE_constants {
    FLASH_DRIVE_MAX = 8 ///< Maximum number of flash drives
};

/// \brief List of flash drives
using flash_drive_configs = boost::container::static_vector<memory_range_config, FLASH_DRIVE_MAX>;

/// \brief TLB device state configuration
struct tlb_config final {
    std::string image_filename{}; ///< TLB image file name
};

/// \brief CLINT device state configuration
struct clint_config final {
    uint64_t mtimecmp{MTIMECMP_INIT}; ///< Value of mtimecmp CSR
};

/// \brief HTIF device state configuration
struct htif_config final {
    uint64_t fromhost{FROMHOST_INIT}; ///< Value of fromhost CSR
    uint64_t tohost{TOHOST_INIT};     ///< Value of tohost CSR
    bool console_getchar{false};      ///< Make console getchar available?
    bool yield_manual{false};         ///< Make yield manual available?
    bool yield_automatic{false};      ///< Make yield automatic available?
};

/// \brief Rollup configuration
struct rollup_config {
    memory_range_config rx_buffer{};      ///< RX buffer
    memory_range_config tx_buffer{};      ///< TX buffer
    memory_range_config input_metadata{}; ///< Buffer for input metadata
    memory_range_config voucher_hashes{}; ///< Buffer for the voucher hash array
    memory_range_config notice_hashes{};  ///< Buffer for the notice hash array
};

/// \brief Machine state configuration
/// NOLINTNEXTLINE(bugprone-exception-escape)
struct machine_config final {

    processor_config processor{};          ///< Processor state
    ram_config ram{};                      ///< RAM state
    rom_config rom{};                      ///< ROM state
    flash_drive_configs flash_drive{};     ///< Flash drives state
    tlb_config tlb{};                      ///< TLB device state
    clint_config clint{};                  ///< CLINT device state
    htif_config htif{};                    ///< HTIF device state
    uarch_config uarch{};                  ///< microarchitecture configuration
    std::optional<rollup_config> rollup{}; ///< Rollup state

    /// \brief Get the name where config will be stored in a directory
    static std::string get_config_filename(const std::string &dir);

    /// \brief Get the name where memory range will be stored in a directory
    static std::string get_image_filename(const std::string &dir, uint64_t start, uint64_t length);
    static std::string get_image_filename(const std::string &dir, const memory_range_config &c);

    /// \brief Loads a machine config from a directory
    /// \param dir Directory from whence "config" will be loaded
    /// \returns The config loaded
    static machine_config load(const std::string &dir);

    /// \brief Stores the machine config to a directory
    /// \param dir Directory where "config" will be stored
    void store(const std::string &dir) const;
};

} // namespace cartesi

#endif
