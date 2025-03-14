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

#include "machine-address-ranges.h"

#include <algorithm>
#include <cerrno>
#include <concepts>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <ranges>
#include <stdexcept>
#include <string>
#include <variant>

#include "address-range-constants.h"
#include "address-range-description.h"
#include "address-range.h"
#include "clint-address-range.h"
#include "htif-address-range.h"
#include "machine-config.h"
#include "memory-address-range.h"
#include "os.h"
#include "plic-address-range.h"
#include "pmas-constants.h"
#include "pmas.h"
#include "processor-state.h"
#include "uarch-pristine.h"
#include "uarch-processor-state.h"
#include "unique-c-ptr.h"
#include "virtio-address-range.h"
#include "virtio-console-address-range.h"
#include "virtio-net-tuntap-address-range.h"
#include "virtio-net-user-address-range.h"
#include "virtio-p9fs-address-range.h"

namespace cartesi {

using namespace std::string_literals;

static const auto throw_invalid_argument = [](const char *err) { throw std::invalid_argument{err}; };

static inline auto make_pmas_address_range(const pmas_config &config) {
    static constexpr pmas_flags pmas_flags{
        .M = true,
        .IO = false,
        .R = true,
        .W = false,
        .X = false,
        .IR = true,
        .IW = false,
        .DID = PMA_ISTART_DID::memory,
    };
    return make_memory_address_range("PMAs", AR_PMAS_START, AR_PMAS_LENGTH, pmas_flags, config.backing_store);
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
    return make_memory_address_range("DTB"s, AR_DTB_START, AR_DTB_LENGTH, dtb_flags, config.backing_store);
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
    auto ar = memory_address_range("shadow state", AR_SHADOW_STATE_START, AR_SHADOW_STATE_LENGTH, shadow_state_flags,
        config.backing_store, shadow_state_config);
    // Mark pages that are permanently dirty in the shadow
    auto &dpt = ar.get_dirty_page_tree();
    dpt.clean();
    dpt.mark_dirty_pages_and_up(AR_SHADOW_REGISTERS_START - AR_SHADOW_STATE_START, AR_SHADOW_REGISTERS_LENGTH);
    dpt.mark_dirty_pages_and_up(AR_SHADOW_TLB_START - AR_SHADOW_STATE_START, AR_SHADOW_TLB_LENGTH);
    dpt.ignore_cleans(true);
    return ar;
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
    static constexpr memory_address_range_config shadow_uarch_state_config{.host_length = sizeof(uarch_processor_state)};
    auto ar = make_memory_address_range("shadow uarch state", AR_SHADOW_UARCH_STATE_START, AR_SHADOW_UARCH_STATE_LENGTH,
        shadow_uarch_state_flags, config.backing_store, shadow_uarch_state_config);
    // Mark pages that are permanently dirty in the shadow
    auto &dpt = ar.get_dirty_page_tree();
    dpt.clean();
    dpt.mark_dirty_pages_and_up(0, AR_SHADOW_UARCH_STATE_LENGTH);
    dpt.ignore_cleans(true);
    return ar;
}

template <typename AR>
    requires std::is_rvalue_reference_v<AR &&> && std::derived_from<AR, address_range>
AR &machine_address_ranges::push_back(AR &&ar, register_where where) {
    check(ar, where);                                   // Check if we can register it
    auto ptr = make_moved_unique(std::forward<AR>(ar)); // Move object to heap, now owned by ptr
    AR &ar_ref = *ptr;                                  // Get reference to object, already in heap, to return later
    const auto index = m_all.size();                    // Get index the new address range will occupy
    m_all.push_back(std::move(ptr));                    // Move ptr to list of address ranges
    if (where.pmas) {                                   // Register as a PMA
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

machine_address_ranges::machine_address_ranges(machine_config &c) {
    // Add all address ranges to m_all, and potentially to interpret and merkle
    push_back(make_shadow_state_address_range(c.processor), register_where{.hash_tree = true, .pmas = false});
    push_back(make_shadow_uarch_state_address_range(c.uarch.processor),
        register_where{.hash_tree = true, .pmas = false});
    push_back_uarch_ram(c.uarch.ram);
    push_back_ram(c.ram);
    push_back(make_dtb_address_range(c.dtb), register_where{.hash_tree = true, .pmas = true});
    push_back_flash_drives(c.flash_drive);
    push_back_cmio(c.cmio);
    push_back(make_htif_address_range(throw_invalid_argument), register_where{.hash_tree = false, .pmas = true});
    push_back(make_clint_address_range(throw_invalid_argument), register_where{.hash_tree = false, .pmas = true});
    push_back(make_plic_address_range(throw_invalid_argument), register_where{.hash_tree = false, .pmas = true});
    push_back(make_pmas_address_range(c.pmas), register_where{.hash_tree = true, .pmas = true});
    push_back_virtio(c.virtio, c.processor.registers.iunrep);

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
    auto &ar = push_back(
        make_memory_address_range(ram_description, AR_UARCH_RAM_START, AR_UARCH_RAM_LENGTH, uram_flags, 
            uram.backing_store), register_where{.hash_tree = true, .pmas = false});
    // Initialize uarch RAM
    if (uram.backing_store.data_filename.empty() || uram.backing_store.create) {
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
    push_back(make_memory_address_range("RAM"s, AR_RAM_START, ram.length, ram_flags, ram.backing_store),
        register_where{.hash_tree = true, .pmas = true});
}

void machine_address_ranges::push_back_flash_drives(flash_drive_configs &flash_drive) {
    if (flash_drive.size() > FLASH_DRIVE_MAX) {
        throw std::invalid_argument{"too many flash drives"};
    }
    // Register all flash drives
    int i = 0; // NOLINT(misc-const-correctness)
    for (auto &f : flash_drive) {
        const std::string flash_description = "flash drive "s + std::to_string(i);
        // Auto detect flash drive start address
        if (f.start == UINT64_C(-1)) {
            f.start = AR_DRIVE_START + AR_DRIVE_OFFSET * i;
        }
        // Auto detect flash drive image length
        const auto &image_filename = f.backing_store.data_filename;
        if (f.length == UINT64_C(-1)) {
            if (image_filename.empty()) {
                throw std::runtime_error{
                    "unable to auto-detect length of "s.append(flash_description).append(" with empty image file")};
            }
            auto fp = make_unique_fopen(image_filename.c_str(), "rb");
            if (fseek(fp.get(), 0, SEEK_END) != 0) {
                throw std::system_error{errno, std::generic_category(),
                    "unable to obtain length of image file '"s.append(image_filename)
                        .append("' when initializing ")
                        .append(flash_description)};
            }
            const auto length = ftell(fp.get());
            if (length < 0) {
                throw std::system_error{errno, std::generic_category(),
                    "unable to obtain length of image file '"s.append(image_filename)
                        .append("' when initializing ")
                        .append(flash_description)};
            }
            f.length = length;
        }
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
        push_back(memory_address_range{flash_description, f.start, f.length, flash_flags, f.backing_store,
                      memory_address_range_config{.host_read_only = f.read_only}},
            register_where{.hash_tree = true, .pmas = true});
        i++;
    }
}

void machine_address_ranges::push_back_virtio(const virtio_configs &virtio, uint64_t iunrep) {
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
            [this, virtio_idx, where](const virtio_console_config &) {
                const auto start = AR_FIRST_VIRTIO_START + (virtio_idx * AR_VIRTIO_LENGTH);
                push_back(make_virtio_console_address_range(start, AR_VIRTIO_LENGTH, virtio_idx), where);
            },
            [this, virtio_idx, where](const virtio_p9fs_config &c) {
#ifdef HAVE_POSIX_FS
                const auto start = AR_FIRST_VIRTIO_START + (virtio_idx * AR_VIRTIO_LENGTH);
                push_back(make_virtio_p9fs_address_range(start, AR_VIRTIO_LENGTH, virtio_idx, c.tag, c.host_directory),
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
                push_back(make_virtio_net_tuntap_address_range(start, AR_VIRTIO_LENGTH, virtio_idx, c.iface), where);
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
                push_back(make_virtio_net_user_address_range(start, AR_VIRTIO_LENGTH, virtio_idx, c), where);
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
    push_back(make_memory_address_range("CMIO tx buffer"s, AR_CMIO_TX_BUFFER_START, AR_CMIO_TX_BUFFER_LENGTH, tx_flags,
            c.tx_buffer.backing_store),
        register_where{.hash_tree = true, .pmas = true});
    push_back(make_memory_address_range("CMIO rx buffer"s, AR_CMIO_RX_BUFFER_START, AR_CMIO_RX_BUFFER_LENGTH, rx_flags,
            c.rx_buffer.backing_store),
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
                throw std::invalid_argument{
                    std::string{"attempted replace of read-write memory range "}.append(ar->get_description()).
                        append(" with read-only memory range")};
            }
            // Replace range, preserving original flags.
            // This will automatically start with all pages dirty.
            ar = make_moved_unique(make_memory_address_range(ar->get_description(), ar->get_start(), ar->get_length(),
                ar->get_flags(), config.backing_store));
            return;
        }
    }
    throw std::invalid_argument{"attempted replace of inexistent memory range"};
}

const address_range &machine_address_ranges::find(uint64_t paddr, uint64_t length) const noexcept {
    static auto sentinel = make_empty_address_range("sentinel");
    for (const auto &ar : m_all) {
        if (ar->contains_absolute(paddr, length)) {
            return *ar;
        }
    }
    return sentinel;
}

} // namespace cartesi
