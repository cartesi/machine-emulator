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

#ifndef MACHINE_CONFIG_H
#define MACHINE_CONFIG_H

#include <array>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include "riscv-constants.h"

namespace cartesi {

/// \brief Machine config constants
enum machine_config_constants {
    FLASH_DRIVE_MAX = 8,     ///< Maximum number of flash drives
    VIRTIO_DEVICE_MAX = 16,  ///< Maximum number of virtio devices
    VIRTIO_HOSTFWD_MAX = 16, ///< Maximum number of virtio net user host forward ports
};

/// \brief Processor state config
struct processor_config final {
    std::array<uint64_t, X_REG_COUNT> x{REG_X0, REG_X1, REG_X2, REG_X3, REG_X4, REG_X5, REG_X6, REG_X7, REG_X8, REG_X9,
        REG_X10, REG_X11, REG_X12, REG_X13, REG_X14, REG_X15, REG_X16, REG_X17, REG_X18, REG_X19, REG_X20, REG_X21,
        REG_X22, REG_X23, REG_X24, REG_X25, REG_X26, REG_X27, REG_X28, REG_X29, REG_X30,
        REG_X31};                               ///< Value of general-purpose registers
    std::array<uint64_t, F_REG_COUNT> f{};      ///< Value of floating-point registers
    uint64_t pc{PC_INIT};                       ///< Value of pc
    uint64_t fcsr{FCSR_INIT};                   ///< Value of fcsr CSR
    uint64_t mvendorid{MVENDORID_INIT};         ///< Value of mvendorid CSR
    uint64_t marchid{MARCHID_INIT};             ///< Value of marchid CSR
    uint64_t mimpid{MIMPID_INIT};               ///< Value of mimpid CSR
    uint64_t mcycle{MCYCLE_INIT};               ///< Value of mcycle CSR
    uint64_t icycleinstret{ICYCLEINSTRET_INIT}; ///< Value of icycleinstret CSR
    uint64_t mstatus{MSTATUS_INIT};             ///< Value of mstatus CSR
    uint64_t mtvec{MTVEC_INIT};                 ///< Value of mtvec CSR
    uint64_t mscratch{MSCRATCH_INIT};           ///< Value of mscratch CSR
    uint64_t mepc{MEPC_INIT};                   ///< Value of mepc CSR
    uint64_t mcause{MCAUSE_INIT};               ///< Value of mcause CSR
    uint64_t mtval{MTVAL_INIT};                 ///< Value of mtval CSR
    uint64_t misa{MISA_INIT};                   ///< Value of misa CSR
    uint64_t mie{MIE_INIT};                     ///< Value of mie CSR
    uint64_t mip{MIP_INIT};                     ///< Value of mip CSR
    uint64_t medeleg{MEDELEG_INIT};             ///< Value of medeleg CSR
    uint64_t mideleg{MIDELEG_INIT};             ///< Value of mideleg CSR
    uint64_t mcounteren{MCOUNTEREN_INIT};       ///< Value of mcounteren CSR
    uint64_t menvcfg{MENVCFG_INIT};             ///< Value of menvcfg CSR
    uint64_t stvec{STVEC_INIT};                 ///< Value of stvec CSR
    uint64_t sscratch{SSCRATCH_INIT};           ///< Value of sscratch CSR
    uint64_t sepc{SEPC_INIT};                   ///< Value of sepc CSR
    uint64_t scause{SCAUSE_INIT};               ///< Value of scause CSR
    uint64_t stval{STVAL_INIT};                 ///< Value of stval CSR
    uint64_t satp{SATP_INIT};                   ///< Value of satp CSR
    uint64_t scounteren{SCOUNTEREN_INIT};       ///< Value of scounteren CSR
    uint64_t senvcfg{SENVCFG_INIT};             ///< Value of senvcfg CSR
    uint64_t ilrsc{ILRSC_INIT};                 ///< Value of ilrsc CSR
    uint64_t iprv{IPRV_INIT};                   ///< Value of iprv CSR
    uint64_t iflags_X{IFLAGS_X_INIT};           ///< Value of iflags_X CSR
    uint64_t iflags_Y{IFLAGS_Y_INIT};           ///< Value of iflags_Y CSR
    uint64_t iflags_H{IFLAGS_H_INIT};           ///< Value of iflags_H CSR
    uint64_t iunrep{IUNREP_INIT};               ///< Value of iunrep CSR
};

/// \brief Backing store config
struct backing_store_config final {
    bool shared{false};        ///< Should changes be reflected in backing store?
    bool truncate{false};      ///< Should backing store be truncated to correct size?
    std::string data_filename; ///< Backing store for associated memory address range
    std::string dht_filename;  ///< Backing store for corresponding dense hash-tree
};

/// \brief Config with only backing store config field
struct backing_store_config_only final {
    backing_store_config backing_store;
};

/// \brief RAM state config
struct ram_config final {
    uint64_t length{0};                 ///< RAM length
    backing_store_config backing_store; ///< Backing store
};

/// \brief DTB state config
struct dtb_config final {
    std::string bootargs{
        "quiet earlycon=sbi console=hvc0 root=/dev/pmem0 rw init=/usr/sbin/cartesi-init"}; ///< Bootargs to pass
                                                                                           ///< to kernel
    std::string init;                   ///< Initialization commands to be executed as root on boot
    std::string entrypoint;             ///< Commands to execute the main application
    backing_store_config backing_store; ///< Backing store
};

/// \brief Memory range config
struct memory_range_config final {
    uint64_t start{0xffffffffffffffffUL};  ///< Memory range start position, default is to auto detect
    uint64_t length{0xffffffffffffffffUL}; ///< Memory range length, default is to auto detect
    bool read_only{false};                 ///< Make memory range read-only
    backing_store_config backing_store;    ///< Backing store
};

/// \brief List of flash drives
using flash_drive_configs = std::vector<memory_range_config>;

/// \brief TLB device state config
using tlb_config = backing_store_config_only;

/// \brief CLINT device state config
struct clint_config final {
    uint64_t mtimecmp{MTIMECMP_INIT}; ///< Value of mtimecmp CSR
};

/// \brief PLIC device state config
struct plic_config final {
    uint64_t girqpend{GIRQPEND_INIT}; ///< Value of girqpend CSR
    uint64_t girqsrvd{GIRQSRVD_INIT}; ///< Value of girqsrvd CSR
};

/// \brief HTIF device state config
struct htif_config final {
    uint64_t fromhost{FROMHOST_INIT}; ///< Value of fromhost CSR
    uint64_t tohost{TOHOST_INIT};     ///< Value of tohost CSR
    bool console_getchar{false};      ///< Make console getchar available?
    bool yield_manual{true};          ///< Make yield manual available?
    bool yield_automatic{true};       ///< Make yield automatic available?
};

/// \brief VirtIO console device state config
struct virtio_console_config final {};

/// \brief VirtIO Plan 9 filesystem device state config
struct virtio_p9fs_config final {
    std::string tag;            ///< Guest mount tag
    std::string host_directory; ///< Path to the host shared directory
};

/// \brief VirtIO host forward state config
struct virtio_hostfwd_config final {
    bool is_udp{false};
    uint64_t host_ip{0};
    uint64_t guest_ip{0};
    uint16_t host_port{0};
    uint16_t guest_port{0};
};

/// \brief List of VirtIO host forwards
using virtio_hostfwd_configs = std::vector<virtio_hostfwd_config>;

/// \brief VirtIO user network device state config
struct virtio_net_user_config final {
    virtio_hostfwd_configs hostfwd;
};

/// \brief VirtIO TUN/TAP network device state config
struct virtio_net_tuntap_config final {
    std::string iface; ///< Host's tap network interface (e.g "tap0")
};

/// \brief VirtIO device state config
using virtio_device_config = std::variant<virtio_console_config, ///< Console
    virtio_p9fs_config,                                          ///< Plan 9 filesystem
    virtio_net_user_config,                                      ///< User-mode networking
    virtio_net_tuntap_config                                     ///< TUN/TAP networking
    >;

/// \brief List of VirtIO devices
using virtio_configs = std::vector<virtio_device_config>;

/// \brief CMIO config
struct cmio_config final {
    backing_store_config_only rx_buffer{}; ///< RX buffer config
    backing_store_config_only tx_buffer{}; ///< TX buffer config
};

/// \brief PMAS config
using pmas_config = backing_store_config_only;

/// \brief Uarch RAM config
using uarch_ram_config = backing_store_config_only;

/// \brief Uarch processor config
struct uarch_processor_config final {
    std::array<uint64_t, UARCH_X_REG_COUNT> x{}; ///< Value of general-purpose registers
    uint64_t pc{UARCH_PC_INIT};                  ///< Value of pc
    uint64_t cycle{UARCH_CYCLE_INIT};            ///< Value of ucycle counter
    uint64_t halt_flag{};
};

/// \brief Uarch config
struct uarch_config final {
    uarch_processor_config processor{}; ///< Uarch processor
    uarch_ram_config ram{};             ///< Uarch RAM
};

/// \brief Hash tree config
struct hash_tree_config final {
    std::string hasher{"keccak"}; ///< What hashing function to use?
    bool shared{false};           ///< Should changes be reflected in backing store?
    bool truncate{false};         ///< Should backing store be truncated to correct size?
    std::string sht_filename;     ///< Backing storage for sparse hash-tree
    std::string phtc_filename;    ///< Backing storage for page hash-tree cache
    uint64_t phtc_size{2046};     ///< Max number of pages in page hash-tree cache
};

/// \brief Machine state config
struct machine_config final {
    processor_config processor{};    ///< Processor config
    ram_config ram{};                ///< RAM config
    dtb_config dtb{};                ///< Device Tree config
    flash_drive_configs flash_drive; ///< Flash drives config
    tlb_config tlb{};                ///< Translation Look-aside Buffer config
    clint_config clint{};            ///< Core-Local Interruptor config
    plic_config plic{};              ///< Platform-Level Interrupt Controller config
    htif_config htif{};              ///< Host-Target config InterFace config
    virtio_configs virtio;           ///< VirtIO devices config
    cmio_config cmio{};              ///< Cartesi Machine IO config
    pmas_config pmas{};              ///< Physical Memory Attributes config
    uarch_config uarch{};            ///< Microarchition config
    hash_tree_config hash_tree{};    ///< Hash-tree config

    /// \brief Get the name where config will be stored in a directory
    static std::string get_config_filename(const std::string &dir);

    /// \brief Get the name where the data for an address range will be stored in a directory
    static std::string get_data_filename(const std::string &dir, uint64_t start, uint64_t length);

    /// \brief Get the name where dense hash-tree for an address range will be stored in a directory
    static std::string get_dht_filename(const std::string &dir, uint64_t start, uint64_t length);

    /// \brief Get the name where global sparse hash-tree will be stored in a directory
    static std::string get_sht_filename(const std::string &dir);

    /// \brief Get the name where global page hash-tree cache will be stored in a directory
    static std::string get_phtc_filename(const std::string &dir);

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
