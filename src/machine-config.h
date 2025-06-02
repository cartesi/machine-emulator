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
#include "shadow-registers.h"
#include "shadow-uarch-state.h"

namespace cartesi {

/// \brief Machine config constants
enum machine_config_constants {
    FLASH_DRIVE_MAX = 8,     ///< Maximum number of flash drives
    VIRTIO_DEVICE_MAX = 16,  ///< Maximum number of virtio devices
    VIRTIO_HOSTFWD_MAX = 16, ///< Maximum number of virtio net user host forward ports
};

/// \brief Backing store config
struct backing_store_config final {
    bool shared{false};        ///< Should changes be reflected in backing store?
    bool create{false};        ///< Should backing store be created?
    bool truncate{false};      ///< Should backing store be truncated to correct size?
    std::string data_filename; ///< Backing store for associated memory address range
    std::string dht_filename;  ///< Backing store for corresponding dense hash-tree
    std::string dpt_filename;  ///< Backing store for corresponding dirty-page tree
};

/// \brief Processor state config
struct processor_config final {
    registers_state registers;
    backing_store_config backing_store;
};

/// \brief Config with only backing store config field
struct backing_store_config_only final {
    backing_store_config backing_store;
};

/// \brief RAM state config
struct ram_config final {
    uint64_t length{0};                                   ///< RAM length
    backing_store_config backing_store{.truncate = true}; ///< Backing store
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
    bool read_only{false};                 ///< Make memory range read-only to host
    backing_store_config backing_store;    ///< Backing store
};

/// \brief List of flash drives
using flash_drive_configs = std::vector<memory_range_config>;

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

/// \brief Uarch processor state config
struct uarch_processor_config final {
    uarch_registers_state registers; ///< Uarch registers
    backing_store_config backing_store;
};

/// \brief Uarch config
struct uarch_config final {
    uarch_processor_config processor{};                        ///< Uarch processor
    uarch_ram_config ram{.backing_store = {.truncate = true}}; ///< Uarch RAM
};

/// \brief Hash tree config
struct hash_tree_config final {
    bool shared{false};        ///< Should changes be reflected in backing store?
    bool create{false};        ///< Should backing store be created?
    bool truncate{false};      ///< Should backing store be truncated to correct size?
    std::string sht_filename;  ///< Backing storage for sparse hash-tree
    std::string phtc_filename; ///< Backing storage for page hash-tree cache
    uint64_t phtc_size{8192};  ///< Max number of pages in page hash-tree cache
};

/// \brief Machine state config
struct machine_config final {
    processor_config processor{};    ///< Processor config
    ram_config ram{};                ///< RAM config
    dtb_config dtb{};                ///< Device Tree config
    flash_drive_configs flash_drive; ///< Flash drives config
    virtio_configs virtio;           ///< VirtIO devices config
    cmio_config cmio{};              ///< Cartesi Machine IO config
    pmas_config pmas{};              ///< Physical Memory Attributes config
    uarch_config uarch{};            ///< Microarchitecture config
    hash_tree_config hash_tree{};    ///< Hash-tree config

    /// \brief Get the name where config will be stored in a directory
    static std::string get_config_filename(const std::string &dir);

    /// \brief Get the name where the data for an address range will be stored in a directory
    static std::string get_data_filename(const std::string &dir, uint64_t start, uint64_t length);

    /// \brief Get the name where dense hash-tree for an address range will be stored in a directory
    static std::string get_dht_filename(const std::string &dir, uint64_t start, uint64_t length);

    /// \brief Get the name where dirty-page -tree for an address range will be stored in a directory
    static std::string get_dpt_filename(const std::string &dir, uint64_t start, uint64_t length);

    /// \brief Get the name where global sparse hash-tree will be stored in a directory
    static std::string get_sht_filename(const std::string &dir);

    /// \brief Get the name where global page hash-tree cache will be stored in a directory
    static std::string get_phtc_filename(const std::string &dir);

    static void adjust_backing_store_config(uint64_t start, uint64_t length, const std::string &dir,
        backing_store_config &c);

    static void adjust_hash_tree_config(const std::string &dir, hash_tree_config &c);

    void adjust_backing_stores(const std::string &dir);

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
