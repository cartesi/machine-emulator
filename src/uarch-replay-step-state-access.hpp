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

#ifndef UARCH_REPLAY_STEP_STATE_ACCESS_HPP
#define UARCH_REPLAY_STEP_STATE_ACCESS_HPP

/// \file
/// \brief State access that replays a uarch step from a binary step log file

#include <algorithm>
#include <cstdint>
#include <cstring>

#include "address-range-constants.hpp"
#include "compiler-defines.hpp"
#include "host-addr.hpp"
#include "i-accept-scoped-notes.hpp"
#include "i-prefer-shadow-uarch-state.hpp"
#include "i-uarch-state-access.hpp"
#include "machine-hash.hpp"
#include "machine-reg.hpp"
#include "scoped-note.hpp"
#include "shadow-tlb.hpp"
#include "shadow-uarch-state.hpp"
#include "step-log.hpp"
#include "strict-aliasing.hpp"
#include "throw.hpp"
#include "uarch-constants.hpp"
#include "uarch-pristine-state-hash.hpp"

namespace cartesi {

/// \brief No-op printout sink; keeps the replay free of host-only machinery for freestanding builds.
struct no_step_printout {
    void begin_bracket(const char * /*text*/) const {}
    void end_bracket(const char * /*text*/) const {}
    void read(const char * /*name*/, uint64_t /*paddr*/, uint64_t /*val*/) const {}
    void write(const char * /*name*/, uint64_t /*paddr*/, uint64_t /*old_val*/, uint64_t /*new_val*/) const {}
};

/// \brief Provides machine state from a uarch step binary log
/// \tparam Printer Printout sink for the replay. Defaults to no_step_printout, which compiles to
/// nothing; the host selects step_dumper to obtain a human-readable dump of the replay.
template <typename Printer = no_step_printout>
// NOLINTNEXTLINE(misc-multiple-inheritance)
class uarch_replay_step_state_access :
    public i_uarch_state_access<uarch_replay_step_state_access<Printer>>,
    public i_accept_scoped_notes<uarch_replay_step_state_access<Printer>>,
    public i_prefer_shadow_uarch_state<uarch_replay_step_state_access<Printer>> {
public:
    struct context {
        step_log log;                      ///< Parsed step log (witnessed tree)
        bool reverted{false};              ///< Set when the reset reverted the state on a rejected input
        machine_hash reverted_root_hash{}; ///< Canonical post-state hash when reverted (the revert root hash)
        Printer printer{};                 ///< Receives the printout; a no-op for the default no_step_printout
    };

private:
    context &m_context; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)

public:
    /// \brief Construct from a log image
    /// \param context Context to be filled with replay step log data
    /// \param log_image Pointer to the step log file bytes
    /// \param log_size Size of the log bytes
    /// \throw runtime_error if the log is malformed or declares a hash function other than
    /// Keccak-256 (the only one the uarch protocol and its on-chain verifier support)
    uarch_replay_step_state_access(context &context, unsigned char *log_image, uint64_t log_size) : m_context(context) {
        m_context.log = step_log::decode(log_image, log_size, hash_function_type::keccak256);
    }

    /// \brief Finish the replay and return the obtained root hash after
    machine_hash finish() {
        // When the reset reverted the state on a rejected input, the canonical root hash after the
        // step is the recorded revert root hash, not the recomputed tree root (which reflects the
        // pristine uarch).
        if (m_context.reverted) {
            return m_context.reverted_root_hash;
        }
        return m_context.log.compute_root_hash();
    }

private:
    host_addr paddr_to_haddr(uint64_t paddr) const {
        const auto paddr_page = paddr & ~PAGE_OFFSET_MASK;
        auto *page_log = m_context.log.find_page(paddr_page);
        const auto offset = paddr & PAGE_OFFSET_MASK;
        return cast_ptr_to_host_addr(page_log->data) + offset;
    }

    /// Like paddr_to_haddr, but invalidates the page's scratch hash so the after-root pass rehashes it.
    host_addr paddr_to_haddr_for_write(uint64_t paddr) const {
        const auto paddr_page = paddr & ~PAGE_OFFSET_MASK;
        auto *page_log = m_context.log.find_page(paddr_page);
        page_log->hash = machine_hash{};
        const auto offset = paddr & PAGE_OFFSET_MASK;
        return cast_ptr_to_host_addr(page_log->data) + offset;
    }

    // -----
    // i_prefer_shadow_uarch_state interface implementation
    // -----
    friend i_prefer_shadow_uarch_state<uarch_replay_step_state_access>;

    uint64_t do_read_shadow_uarch_state(shadow_uarch_state_what what) const {
        const auto paddr = static_cast<uint64_t>(what);
        const auto val = aliased_aligned_read<uint64_t>(paddr_to_haddr(paddr));
        m_context.printer.read(shadow_uarch_state_get_what_name(what), paddr, val);
        return val;
    }

    void do_write_shadow_uarch_state(shadow_uarch_state_what what, uint64_t val) const {
        const auto paddr = static_cast<uint64_t>(what);
        const auto haddr = paddr_to_haddr_for_write(paddr);
        const auto old_val = aliased_aligned_read<uint64_t>(haddr);
        m_context.printer.write(shadow_uarch_state_get_what_name(what), paddr, old_val, val);
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    // -----
    // i_uarch_state_access interface implementation
    // -----
    friend i_uarch_state_access<uarch_replay_step_state_access>;

    uint64_t do_read_word(uint64_t paddr) const {
        const auto val = aliased_aligned_read<uint64_t>(paddr_to_haddr(paddr));
        m_context.printer.read(nullptr, paddr, val);
        return val;
    }

    void do_write_word(uint64_t paddr, uint64_t val) const {
        const auto haddr = paddr_to_haddr_for_write(paddr);
        const auto old_val = aliased_aligned_read<uint64_t>(haddr);
        m_context.printer.write(nullptr, paddr, old_val, val);
        aliased_aligned_write<uint64_t>(haddr, val);
    }

    void do_write_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
        uint64_t pma_index) const {
        const auto write_field = [this, set_index, slot_index](shadow_tlb_what what, uint64_t val) {
            aliased_aligned_write<uint64_t>(
                paddr_to_haddr_for_write(shadow_tlb_get_abs_addr(set_index, slot_index, what)), val);
        };
        write_field(shadow_tlb_what::vaddr_page, vaddr_page);
        write_field(shadow_tlb_what::vp_offset, vp_offset);
        write_field(shadow_tlb_what::pma_index, pma_index);
        write_field(shadow_tlb_what::zero_padding_, UINT64_C(0));
    }

    void do_reset_uarch() const {
        // The log must contain a node covering the full uarch state region; the reset
        // writes the well-known pristine uarch hash into its slot.
        auto *node = m_context.log.try_find_node(UARCH_STATE_START_ADDRESS);
        if (node == nullptr || node->log2_size != static_cast<uint64_t>(UARCH_STATE_LOG2_SIZE)) {
            THROW(std::runtime_error, "reset uarch node not found in log");
        }
        node->hash = get_uarch_pristine_state_hash();
    }

    void do_revert_state() const {
        // The canonical post-state hash is the recorded revert root hash, read raw from its leaf in the
        // witnessed shadow page. finish() returns it instead of the recomputed tree root.
        constexpr uint64_t paddr = AR_SHADOW_REVERT_ROOT_HASH_START;
        const auto *page_log = m_context.log.find_page(paddr & ~PAGE_OFFSET_MASK);
        std::copy_n(page_log->data + (paddr & PAGE_OFFSET_MASK), m_context.reverted_root_hash.size(),
            m_context.reverted_root_hash.begin());
        m_context.reverted = true;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_putchar(uint8_t /*c*/) const {
        return false;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    constexpr const char *do_get_name() const {
        return "uarch_replay_step_state_access";
    }

    // -----
    // i_accept_scoped_notes interface implementation
    // -----
    friend i_accept_scoped_notes<uarch_replay_step_state_access>;

    // A real scoped_note (not the no-op default) so per-instruction brackets reach the printer.
    auto do_make_scoped_note(const char *text) const {
        return scoped_note{*this, text};
    }

    void do_push_begin_bracket(const char *text) const {
        m_context.printer.begin_bracket(text);
    }

    void do_push_end_bracket(const char *text) const {
        m_context.printer.end_bracket(text);
    }
};

} // namespace cartesi

#endif
