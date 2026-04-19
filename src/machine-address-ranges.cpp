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
/// \brief Cartesi machine address ranges.

#include "machine-address-ranges.hpp"

#include <algorithm>
#include <concepts>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <memory>
#include <ranges>
#include <stdexcept>
#include <string>
#include <variant>

#include "address-range-constants.hpp"
#include "address-range-description.hpp"
#include "address-range.hpp"
#include "clint-address-range.hpp"
#include "htif-address-range.hpp"
#include "machine-config.hpp"
#include "machine-console.hpp"
#include "machine-runtime-config.hpp"
#include "memory-address-range.hpp"
#include "meta.hpp"
#include "os-filesystem.hpp"
#include "plic-address-range.hpp"
#include "pmas-constants.hpp"
#include "pmas.hpp"
#include "processor-state.hpp"
#include "scope-remove.hpp"
#include "uarch-pristine.hpp"
#include "uarch-processor-state.hpp"
#include "virtio-address-range.hpp"
#include "virtio-console-address-range.hpp"
#include "virtio-net-tuntap-address-range.hpp"
#include "virtio-net-user-address-range.hpp"
#include "virtio-p9fs-address-range.hpp"

namespace cartesi {

using namespace std::string_literals;

static const auto throw_invalid_argument = [](const char *err) { throw std::invalid_argument{err}; };

static inline auto make_pmas_address_range(const pmas_config &config) {
    static constexpr pmas_flags flags{
        .M = true,
        .IO = false,
        .R = true,
        .W = false,
        .X = false,
        .IR = true,
        .IW = false,
        .DID = PMA_ISTART_DID::memory,
    };
    return std::make_unique<memory_address_range>("PMAs"s, AR_PMAS_START, AR_PMAS_LENGTH, flags, config.backing_store,
        memory_address_range_config{.host_read_only = true});
}

static inline auto make_dtb_address_range(const dtb_config &config) {
    // When we pass a RNG seed in a FDT stored in DTB, Linux will wipe out its contents as a security measure,
    // therefore, we need to make DTB writable, otherwise boot will hang.
    static constexpr pmas_flags dtb_flags{
        .M = true,
        .IO = false,
        .R = true,
        .W = true,
        .X = true,
        .IR = true,
        .IW = true,
        .DID = PMA_ISTART_DID::memory,
    };
    return std::make_unique<memory_address_range>("DTB"s, AR_DTB_START, AR_DTB_LENGTH, dtb_flags, config.backing_store);
}

static inline auto make_shadow_state_address_range(const processor_config &config) {
    static constexpr pmas_flags shadow_state_flags{
        .M = true,
        .IO = false,
        .R = false,
        .W = false,
        .X = false,
        .IR = false,
        .IW = false,
        .DID = PMA_ISTART_DID::shadow_state,
    };
    static constexpr memory_address_range_config shadow_state_config{.host_length = sizeof(processor_state)};
    return std::make_unique<memory_address_range>("shadow state", AR_SHADOW_STATE_START, AR_SHADOW_STATE_LENGTH,
        shadow_state_flags, config.backing_store, shadow_state_config);
}

static inline auto make_shadow_uarch_state_address_range(const uarch_processor_config &config) {
    static constexpr pmas_flags shadow_uarch_state_flags{
        .M = true,
        .IO = false,
        .R = false,
        .W = false,
        .X = false,
        .IR = false,
        .IW = false,
        .DID = PMA_ISTART_DID::shadow_uarch_state,
    };
    static constexpr memory_address_range_config shadow_uarch_state_config{
        .host_length = sizeof(uarch_processor_state)};
    return std::make_unique<memory_address_range>("shadow uarch state", AR_SHADOW_UARCH_STATE_START,
        AR_SHADOW_UARCH_STATE_LENGTH, shadow_uarch_state_flags, config.backing_store, shadow_uarch_state_config);
}

void machine_address_ranges::mark_always_dirty_pages() {
    m_all[m_shadow_uarch_state_index]->get_dirty_page_tree().mark_dirty_pages_and_up(0, AR_SHADOW_UARCH_STATE_LENGTH);
    auto &shadow_dpt = m_all[m_shadow_state_index]->get_dirty_page_tree();
    shadow_dpt.mark_dirty_pages_and_up(AR_SHADOW_REGISTERS_START - AR_SHADOW_STATE_START, AR_SHADOW_REGISTERS_LENGTH);
    shadow_dpt.mark_dirty_pages_and_up(AR_SHADOW_TLB_START - AR_SHADOW_STATE_START, AR_SHADOW_TLB_LENGTH);
}

template <typename AR>
    requires std::derived_from<AR, address_range>
AR &machine_address_ranges::push_back(std::unique_ptr<AR> &&ar_ptr, register_where where) {
    AR &ar_ref = *ar_ptr;               // Get reference to object, already in heap, to return later
    check(ar_ref, where);               // Check if we can register it
    const auto index = m_all.size();    // Get index the new address range will occupy
    m_all.push_back(std::move(ar_ptr)); // Move ptr to list of address ranges
    if (where.pmas) {                   // Register as a PMA
        if (m_pmas.size() >= PMA_MAX) {
            throw std::invalid_argument{"too many PMAs"};
        }
        m_pmas.push_back(index);
    }
    if (where.hash_tree) { // Register with the hash tree
        m_hash_tree.push_back(index);
    }
    if constexpr (std::is_convertible_v<AR *, virtio_address_range *>) { // Register with VirtIO
        m_virtio.push_back(&ar_ref);
    }
    return ar_ref; // Return reference to object in heap
}

static void prepare_ar_backing_store(const backing_store_config &c, uint64_t length, scope_remove &remover) {
    if (!c.shared) {
        return;
    }

    // Create data storage
    if (!c.data_filename.empty()) {
        if (c.create) { // Create new file
            os::truncate_file(c.data_filename, length, true);
            remover.add_file(c.data_filename);
        } else if (c.truncate) { // Truncate existing file
            os::truncate_file(c.data_filename, length, false);
        }
    }

    // Create dht storage only if needed
    if (!c.dht_filename.empty() && (c.create || !os::exists(c.dht_filename))) {
        os::truncate_file(c.dht_filename, memory_address_range::get_dht_storage_length(length), true);
        remover.add_file(c.dht_filename);
    }

    // Create dpt storage only if needed
    if (!c.dpt_filename.empty() && (c.create || !os::exists(c.dpt_filename))) {
        os::truncate_file(c.dpt_filename, memory_address_range::get_dpt_storage_length(length), true);
        remover.add_file(c.dpt_filename);
    }
}

static void prepare_ar_backing_store_for_share(const backing_store_config &from_c, backing_store_config &to_c,
    uint64_t length, bool read_only, scope_remove &remover) {
    to_c.shared = true;
    const uint64_t dht_length = memory_address_range::get_dht_storage_length(length);
    const uint64_t dpt_length = memory_address_range::get_dpt_storage_length(length);
    if (from_c.newly_created()) { // Nothing to copy
        // Prepare data storage
        os::truncate_file(to_c.data_filename, length, true);
        remover.add_file(to_c.data_filename);

        // Prepare dht storage
        os::truncate_file(to_c.dht_filename, dht_length, true);
        remover.add_file(to_c.dht_filename);

        // Prepare dpt storage
        os::truncate_file(to_c.dpt_filename, dpt_length, true);
        remover.add_file(to_c.dpt_filename);

        // Necessary, so the memory is always mapped as writeable in memory address range constructor
        to_c.create = true;
    } else {
        // Prepare data storage
        os::copy_file(from_c.data_filename, to_c.data_filename, length);
        remover.add_file(to_c.data_filename);

        // Prepare dht storage
        if (os::exists(from_c.dht_filename) && os::file_size(from_c.dht_filename) == dht_length) {
            os::copy_file(from_c.dht_filename, to_c.dht_filename, dht_length);
        } else {
            os::truncate_file(to_c.dht_filename, dht_length, true);
        }
        remover.add_file(to_c.dht_filename);

        // Prepare dpt storage
        if (os::exists(from_c.dpt_filename) && os::file_size(from_c.dpt_filename) == dpt_length) {
            os::copy_file(from_c.dpt_filename, to_c.dpt_filename, dpt_length);
        } else {
            os::truncate_file(to_c.dpt_filename, dpt_length, true);
        }
        remover.add_file(to_c.dpt_filename);

        os::change_writable(to_c.data_filename, !read_only);
    }
}

static void prepare_ar_backing_stores(const machine_config &c, scope_remove &remover) {
    prepare_ar_backing_store(c.processor.backing_store, AR_SHADOW_STATE_LENGTH, remover);
    prepare_ar_backing_store(c.pmas.backing_store, AR_PMAS_LENGTH, remover);
    prepare_ar_backing_store(c.dtb.backing_store, AR_DTB_LENGTH, remover);
    prepare_ar_backing_store(c.ram.backing_store, c.ram.length, remover);
    prepare_ar_backing_store(c.cmio.rx_buffer.backing_store, AR_CMIO_RX_BUFFER_LENGTH, remover);
    prepare_ar_backing_store(c.cmio.tx_buffer.backing_store, AR_CMIO_TX_BUFFER_LENGTH, remover);
    prepare_ar_backing_store(c.uarch.processor.backing_store, AR_SHADOW_UARCH_STATE_LENGTH, remover);
    prepare_ar_backing_store(c.uarch.ram.backing_store, AR_UARCH_RAM_LENGTH, remover);
    for (const auto &f : c.flash_drive) {
        prepare_ar_backing_store(f.backing_store, f.length, remover);
    }
    for (const auto &n : c.nvram) {
        prepare_ar_backing_store(n.backing_store, n.length, remover);
    }
}

static void prepare_ar_backing_stores_for_share(const machine_config &from_c, machine_config &to_c,
    scope_remove &remover) {
    prepare_ar_backing_store_for_share(from_c.processor.backing_store, to_c.processor.backing_store,
        AR_SHADOW_STATE_LENGTH, false, remover);
    prepare_ar_backing_store_for_share(from_c.pmas.backing_store, to_c.pmas.backing_store, AR_PMAS_LENGTH, false,
        remover);
    prepare_ar_backing_store_for_share(from_c.dtb.backing_store, to_c.dtb.backing_store, AR_DTB_LENGTH, false, remover);
    prepare_ar_backing_store_for_share(from_c.ram.backing_store, to_c.ram.backing_store, to_c.ram.length, false,
        remover);
    prepare_ar_backing_store_for_share(from_c.cmio.rx_buffer.backing_store, to_c.cmio.rx_buffer.backing_store,
        AR_CMIO_RX_BUFFER_LENGTH, false, remover);
    prepare_ar_backing_store_for_share(from_c.cmio.tx_buffer.backing_store, to_c.cmio.tx_buffer.backing_store,
        AR_CMIO_TX_BUFFER_LENGTH, false, remover);
    prepare_ar_backing_store_for_share(from_c.uarch.processor.backing_store, to_c.uarch.processor.backing_store,
        AR_SHADOW_UARCH_STATE_LENGTH, false, remover);
    prepare_ar_backing_store_for_share(from_c.uarch.ram.backing_store, to_c.uarch.ram.backing_store,
        AR_UARCH_RAM_LENGTH, false, remover);
    for (size_t i = 0; i < to_c.flash_drive.size(); ++i) {
        const auto &from_f = from_c.flash_drive[i];
        auto &to_f = to_c.flash_drive[i];
        prepare_ar_backing_store_for_share(from_f.backing_store, to_f.backing_store, from_f.length, from_f.read_only,
            remover);
    }
    for (size_t i = 0; i < to_c.nvram.size(); ++i) {
        const auto &from_n = from_c.nvram[i];
        auto &to_n = to_c.nvram[i];
        prepare_ar_backing_store_for_share(from_n.backing_store, to_n.backing_store, from_n.length, from_n.read_only,
            remover);
    }
}

machine_address_ranges::machine_address_ranges(const machine_config &config,
    const machine_runtime_config &runtime_config, machine_console &console, const std::string &dir,
    scope_remove &remover) {
    // Copy config
    machine_config c = config;

    // Prepare address ranges backing stores
    if (!dir.empty()) { // Machine that it's fully on-disk
        if (config.processor.registers.iunrep != 0) {
            throw std::invalid_argument{"fully on-disk machines must not be unreproducible"s};
        }
        // Adjust config
        c.adjust_backing_stores(dir);
        // Create backing store directory
        os::create_directory(dir);
        remover.add_directory(dir);
        // Store config
        remover.add_file(c.store(dir));
        // Copy backing stores and mark them as shared
        prepare_ar_backing_stores_for_share(config, c, remover);
    } else { // A machine that may be partially or fully in-memory
        // Create and truncate backing stores as necessary
        prepare_ar_backing_stores(c, remover);
    }

    // Add all address ranges to m_all, and potentially to interpret and hash
    m_shadow_state_index = static_cast<int>(m_all.size()); // NOLINT(cppcoreguidelines-prefer-member-initializer)
    push_back(make_shadow_state_address_range(c.processor), register_where{.hash_tree = true, .pmas = false});
    m_shadow_uarch_state_index = static_cast<int>(m_all.size()); // NOLINT(cppcoreguidelines-prefer-member-initializer)
    push_back(make_shadow_uarch_state_address_range(c.uarch.processor),
        register_where{.hash_tree = true, .pmas = false});
    push_back_uarch_ram(c.uarch.ram);
    push_back_ram(c.ram);
    push_back(make_dtb_address_range(c.dtb), register_where{.hash_tree = true, .pmas = true});
    push_back_flash_drives(c.flash_drive, runtime_config);
    push_back_nvrams(c.nvram, c.flash_drive, runtime_config);
    push_back_cmio(c.cmio);
    push_back(std::make_unique<htif_address_range>(throw_invalid_argument),
        register_where{.hash_tree = false, .pmas = true});
    push_back(std::make_unique<clint_address_range>(throw_invalid_argument),
        register_where{.hash_tree = false, .pmas = true});
    push_back(std::make_unique<plic_address_range>(throw_invalid_argument),
        register_where{.hash_tree = false, .pmas = true});
    push_back(make_pmas_address_range(c.pmas), register_where{.hash_tree = true, .pmas = true});
    push_back_virtio(c.virtio, c.processor.registers.iunrep, console);

    // Sort indices visible to hash tree by the start of corresponding address range
    std::ranges::sort(
        m_hash_tree, [](const auto &a, const auto &b) { return a.get_start() < b.get_start(); },
        [this](const auto i) { return *m_all[i]; });

    // Create descriptions and sort by start address
    auto src =
        m_all | std::views::filter([](auto &ar) { return !ar->is_empty(); }) | std::views::transform([](auto &ar) {
            return address_range_description{.start = ar->get_start(),
                .length = ar->get_length(),
                .description = ar->get_description()};
        });
    std::ranges::copy(src, std::back_inserter(m_descrs));
    std::ranges::sort(m_descrs, [](auto &a, auto &b) { return a.start < b.start; });
}

void machine_address_ranges::push_back_uarch_ram(const uarch_ram_config &uram) {
    // Register uarch RAM
    static constexpr pmas_flags uram_flags{
        .M = true,
        .IO = false,
        .R = true,
        .W = true,
        .X = true,
        .IR = true,
        .IW = true,
        .DID = PMA_ISTART_DID::memory,
    };
    constexpr auto ram_description = "uarch RAM";
    auto &ar = push_back(std::make_unique<memory_address_range>(ram_description, AR_UARCH_RAM_START,
                             AR_UARCH_RAM_LENGTH, uram_flags, uram.backing_store),
        register_where{.hash_tree = true, .pmas = false});
    // Initialize uarch RAM
    if (uram.backing_store.newly_created()) {
        if (uarch_pristine_ram_len > AR_UARCH_RAM_LENGTH) {
            throw std::runtime_error("embedded uarch RAM image does not fit in uarch memory");
        }
        memcpy(ar.get_host_memory(), uarch_pristine_ram, uarch_pristine_ram_len);
    }
}

void machine_address_ranges::check(const address_range &new_ar, register_where where) {
    if (!where.pmas && !where.hash_tree) {
        throw std::runtime_error{"address range "s + new_ar.get_description() + " must be registered somewhere"s};
    }
    const auto start = new_ar.get_start();
    const auto end = new_ar.get_end();
    // Checks if new range is machine addressable space (safe unsigned overflows)
    if (start > AR_ADDRESSABLE_MASK || end > AR_ADDRESSABLE_MASK) {
        throw std::invalid_argument{
            "address range of "s + new_ar.get_description() + " must use at most 56 bits to be addressable"s};
    }
    // Range A overlaps with B if A starts before B ends and A ends after B starts
    for (const auto &ar : m_all) {
        if (start < ar->get_end() && end > ar->get_start()) {
            throw std::invalid_argument{"address range of "s + new_ar.get_description() +
                " overlaps with address range of existing "s + ar->get_description()};
        }
    }
}

void machine_address_ranges::push_back_ram(const ram_config &ram) {
    // Flags for RAM
    static constexpr pmas_flags ram_flags{
        .M = true,
        .IO = false,
        .R = true,
        .W = true,
        .X = true,
        .IR = true,
        .IW = true,
        .DID = PMA_ISTART_DID::memory,
    };
    if (ram.length == 0) {
        throw std::invalid_argument("RAM length cannot be zero");
    }
    push_back(std::make_unique<memory_address_range>("RAM"s, AR_RAM_START, ram.length, ram_flags, ram.backing_store),
        register_where{.hash_tree = true, .pmas = true});
}

/// \brief Validates a user-supplied memory range label (may be empty) and checks for duplicates
/// \param description Description of the entry being validated (e.g., "flash drive 0")
/// \param label User label to validate; an empty label is allowed and skips duplicate checks
/// \param seen_labels Non-empty labels already seen (for duplicate detection)
static void validate_memory_range_label(const std::string &description, const std::string &label,
    const std::vector<std::string> &seen_labels) {
    if (label.empty()) {
        return;
    }
    if (label.size() > MEMORY_RANGE_LABEL_MAX) {
        throw std::invalid_argument{std::string(description)
                .append(" label is too long (max ")
                .append(std::to_string(MEMORY_RANGE_LABEL_MAX))
                .append(" characters)")};
    }
    for (const auto c : label) {
        if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_') {
            throw std::invalid_argument{
                std::string(description).append(" label contains invalid character '").append(1, c).append("'")};
        }
    }
    if (label.front() == '_') {
        throw std::invalid_argument{
            std::string(description).append(" label must not start with underscore (reserved for internal use)")};
    }
    for (const auto &seen : seen_labels) {
        if (seen == label) {
            throw std::invalid_argument{
                std::string(description).append(" has duplicate label \"").append(label).append("\"")};
        }
    }
}

void machine_address_ranges::push_back_flash_drives(const flash_drive_configs &flash_drive,
    const machine_runtime_config &r) {
    if (flash_drive.size() > FLASH_DRIVE_MAX) {
        throw std::invalid_argument{"too many flash drives"};
    }
    // Validate flash drive labels (user labels are optional)
    std::vector<std::string> seen_labels;
    for (size_t i = 0; i < flash_drive.size(); ++i) {
        validate_memory_range_label("flash drive "s + std::to_string(i), flash_drive[i].label, seen_labels);
        if (!flash_drive[i].label.empty()) {
            seen_labels.push_back(flash_drive[i].label);
        }
    }
    // Register all flash drives
    int i = 0; // NOLINT(misc-const-correctness)
    for (const auto &f : flash_drive) {
        const std::string flash_description = "flash drive "s + std::to_string(i);
        // Flags for the flash drive
        const pmas_flags flash_flags{
            .M = true,
            .IO = false,
            .R = true,
            .W = !f.read_only,
            .X = false,
            .IR = true,
            .IW = !f.read_only,
            .DID = PMA_ISTART_DID::flash_drive,
        };
        push_back(std::make_unique<memory_address_range>(flash_description, f.start, f.length, flash_flags,
                      f.backing_store,
                      memory_address_range_config{.host_read_only = f.read_only, .host_no_reserve = r.no_reserve}),
            register_where{.hash_tree = true, .pmas = true});
        i++;
    }
}

void machine_address_ranges::push_back_nvrams(const nvram_configs &nvram, const flash_drive_configs &flash_drive,
    const machine_runtime_config &r) {
    if (nvram.size() > NVRAM_MAX) {
        throw std::invalid_argument{"too many NVRAMs"};
    }
    // Validate NVRAM labels (user labels are optional; seeded with non-empty flash drive labels)
    std::vector<std::string> seen_labels;
    for (const auto &f : flash_drive) {
        if (!f.label.empty()) {
            seen_labels.push_back(f.label);
        }
    }
    for (size_t i = 0; i < nvram.size(); ++i) {
        validate_memory_range_label("nvram "s + std::to_string(i), nvram[i].label, seen_labels);
        if (!nvram[i].label.empty()) {
            seen_labels.push_back(nvram[i].label);
        }
    }
    // Register all NVRAMs
    int i = 0; // NOLINT(misc-const-correctness)
    for (const auto &n : nvram) {
        const std::string nvram_description = "nvram "s + std::to_string(i);
        const pmas_flags nvram_flags{
            .M = true,
            .IO = false,
            .R = true,
            .W = !n.read_only,
            .X = false,
            .IR = true,
            .IW = !n.read_only,
            .DID = PMA_ISTART_DID::nvram,
        };
        push_back(std::make_unique<memory_address_range>(nvram_description, n.start, n.length, nvram_flags,
                      n.backing_store,
                      memory_address_range_config{.host_read_only = n.read_only, .host_no_reserve = r.no_reserve}),
            register_where{.hash_tree = true, .pmas = true});
        i++;
    }
}

void machine_address_ranges::push_back_virtio(const virtio_configs &virtio, uint64_t iunrep, machine_console &console) {
    if (virtio.empty()) {
        return;
    }
    if (virtio.size() > VIRTIO_DEVICE_MAX) {
        throw std::invalid_argument{"too many VirtIO devices"};
    }
    // VirtIO devices are disallowed in unreproducible mode
    if (iunrep == 0) {
        throw std::invalid_argument{"virtio devices are only supported in unreproducible machines"};
    }
    uint32_t virtio_idx = 0;
    for (const auto &c : virtio) {
        const auto where = register_where{.hash_tree = false, .pmas = true};
        const auto visitor = overloads{
            [this, virtio_idx, where, &console](const virtio_console_config &) {
                const auto start = AR_FIRST_VIRTIO_START + (virtio_idx * AR_VIRTIO_LENGTH);
                push_back(std::make_unique<virtio_console_address_range>(start, AR_VIRTIO_LENGTH, virtio_idx, console),
                    where);
            },
            [this, virtio_idx, where](const virtio_p9fs_config &c) {
#ifdef HAVE_POSIX_FS
                const auto start = AR_FIRST_VIRTIO_START + (virtio_idx * AR_VIRTIO_LENGTH);
                push_back(std::make_unique<virtio_p9fs_address_range>(start, AR_VIRTIO_LENGTH, virtio_idx, c.tag,
                              c.host_directory),
                    where);
#else
                (void) c;
                (void) this;
                (void) virtio_idx;
                (void) where;
                throw std::invalid_argument{"virtio 9p device is unsupported in this platform"};
#endif
            },
            [this, virtio_idx, where](const virtio_net_tuntap_config &c) {
#ifdef HAVE_TUNTAP
                const auto start = AR_FIRST_VIRTIO_START + (virtio_idx * AR_VIRTIO_LENGTH);
                push_back(
                    std::make_unique<virtio_net_tuntap_address_range>(start, AR_VIRTIO_LENGTH, virtio_idx, c.iface),
                    where);
#else
                (void) c;
                (void) this;
                (void) virtio_idx;
                (void) where;
                throw std::invalid_argument("virtio network TUN/TAP device is unsupported in this platform");
#endif
            },
            [this, virtio_idx, where](const virtio_net_user_config &c) {
#ifdef HAVE_SLIRP
                if (c.hostfwd.size() > VIRTIO_HOSTFWD_MAX) {
                    throw std::invalid_argument("too many virtio network user host-forwarding ports");
                }
                const auto start = AR_FIRST_VIRTIO_START + (virtio_idx * AR_VIRTIO_LENGTH);
                push_back(std::make_unique<virtio_net_user_address_range>(start, AR_VIRTIO_LENGTH, virtio_idx, c),
                    where);
#else
                (void) c;
                (void) this;
                (void) virtio_idx;
                (void) where;
                throw std::invalid_argument("virtio network user device is unsupported in this platform");
#endif
            },
            [](const auto &) { throw std::invalid_argument("invalid virtio device configuration"); }};
        std::visit(visitor, c);
        ++virtio_idx;
    }
}

void machine_address_ranges::push_back_cmio(const cmio_config &c) {
    const pmas_flags tx_flags{
        .M = true,
        .IO = false,
        .R = true,
        .W = true,
        .X = false,
        .IR = true,
        .IW = true,
        .DID = PMA_ISTART_DID::cmio_tx_buffer,
    };
    const pmas_flags rx_flags{
        .M = true,
        .IO = false,
        .R = true,
        .W = false,
        .X = false,
        .IR = true,
        .IW = true,
        .DID = PMA_ISTART_DID::cmio_rx_buffer,
    };
    push_back(std::make_unique<memory_address_range>("CMIO tx buffer"s, AR_CMIO_TX_BUFFER_START,
                  AR_CMIO_TX_BUFFER_LENGTH, tx_flags, c.tx_buffer.backing_store),
        register_where{.hash_tree = true, .pmas = true});
    push_back(std::make_unique<memory_address_range>("CMIO rx buffer"s, AR_CMIO_RX_BUFFER_START,
                  AR_CMIO_RX_BUFFER_LENGTH, rx_flags, c.rx_buffer.backing_store),
        register_where{.hash_tree = true, .pmas = true});
}

void machine_address_ranges::replace(const memory_range_config &config) {
    for (auto &ar : m_all) {
        if (ar->get_start() == config.start && ar->get_length() == config.length) {
            if (!ar->is_memory() || pmas_is_protected(ar->get_driver_id())) {
                throw std::invalid_argument{
                    std::string{"attempted replace of protected memory range "}.append(ar->get_description())};
            }
            if (ar->is_host_read_only() || !ar->is_writeable()) {
                throw std::invalid_argument{
                    std::string{"attempted replace of read-only memory range "}.append(ar->get_description())};
            }
            if (config.read_only) {
                throw std::invalid_argument{std::string{"attempted replace of read-write memory range "}
                        .append(ar->get_description())
                        .append(" with read-only memory range")};
            }
            // Replace range, preserving original flags.
            // This will automatically start with all pages dirty.
            ar = std::make_unique<memory_address_range>(ar->get_description(), ar->get_start(), ar->get_length(),
                ar->get_flags(), config.backing_store);
            return;
        }
    }
    throw std::invalid_argument{"attempted replace of inexistent memory range"};
}

} // namespace cartesi
