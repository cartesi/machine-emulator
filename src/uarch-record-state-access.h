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

#ifndef UARCH_RECORD_STATE_ACCESS
#define UARCH_RECORD_STATE_ACCESS

/// \file
/// \brief State access implementation that record and logs all accesses
#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include "access-log.h"
#include "host-addr.h"
#include "i-hasher.h"
#include "i-state-access.h"
#include "i-uarch-state-access.h"
#include "machine-merkle-tree.h"
#include "machine.h"
#include "meta.h"
#include "pma.h"
#include "riscv-constants.h"
#include "scoped-note.h"
#include "shadow-tlb.h"
#include "shadow-uarch-state.h"
#include "strict-aliasing.h"
#include "uarch-constants.h"
#include "uarch-pristine-state-hash.h"
#include "uarch-pristine.h"
#include "uarch-state.h"

namespace cartesi {

using namespace std::string_literals;

/// \details The uarch_record_state_access logs all access to the machine state.
class uarch_record_state_access : public i_uarch_state_access<uarch_record_state_access> {

    using hasher_type = machine_merkle_tree::hasher_type;
    using hash_type = machine_merkle_tree::hash_type;

    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    machine &m_m; ///< Macro machine
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)
    std::shared_ptr<access_log> m_log; ///< Pointer to access log

    static auto get_hash(hasher_type &hasher, const access_data &data) {
        hash_type hash{};
        get_merkle_tree_hash(hasher, data.data(), data.size(), machine_merkle_tree::get_word_size(), hash);
        return hash;
    }

public:
    /// \brief Constructor from machine and uarch states.
    /// \param um Reference to uarch state.
    /// \param m Reference to machine state.
    explicit uarch_record_state_access(machine &m, access_log::type log_type) :
        m_m(m),
        m_log(std::make_shared<access_log>(log_type)) {
        ;
    }

    /// \brief No copy constructor
    uarch_record_state_access(const uarch_record_state_access &) = delete;
    /// \brief No copy assignment
    uarch_record_state_access &operator=(const uarch_record_state_access &) = delete;
    /// \brief No move constructor
    uarch_record_state_access(uarch_record_state_access &&) = delete;
    /// \brief No move assignment
    uarch_record_state_access &operator=(uarch_record_state_access &&) = delete;
    /// \brief Default destructor
    ~uarch_record_state_access() = default;

    /// \brief Returns const pointer to access log.
    std::shared_ptr<const access_log> get_log() const {
        return m_log;
    }

    /// \brief Returns pointer to access log.
    std::shared_ptr<access_log> get_log() {
        return m_log;
    }

private:
    void do_push_begin_bracket(const char *text) {
        m_log->push_begin_bracket(text);
    }

    void do_push_end_bracket(const char *text) {
        m_log->push_end_bracket(text);
    }

    auto do_make_scoped_note(const char *text) {
        return scoped_note<uarch_record_state_access>{*this, text};
    }

    static std::pair<uint64_t, int> adjust_access(uint64_t paddr, int log2_size) {
        static_assert(cartesi::log2_size_v<uint64_t> <= machine_merkle_tree::get_log2_word_size(),
            "Merkle tree word size must not be smaller than machine word size");
        if (((paddr >> log2_size) << log2_size) != paddr) {
            throw std::invalid_argument{"misaligned access"};
        }
        const auto log2_word_size = machine_merkle_tree::get_log2_word_size();
        const auto log2_access_size = std::max(log2_size, log2_word_size);
        const auto access_paddr = (paddr >> log2_access_size) << log2_access_size;
        return {access_paddr, log2_access_size};
    }

    void log_access(access &&a, const char *text) const {
        m_log->push_access(std::move(a), text);
    }

    static void log_access_type(access &a, access_type type) {
        a.set_type(type);
    }

    static void log_access_range(access &a, uint64_t paddr, int log2_size) {
        a.set_address(paddr);
        a.set_log2_size(log2_size);
    }

    void log_access_siblings_and_read_hash(access &a, uint64_t paddr, int log2_size) const {
        // Since the tree was updated before we started collecting the log, we only update after writes
        const auto proof = m_m.get_proof(paddr, log2_size, skip_merkle_tree_update);
        // The only pieces of data we use from the proof are the target hash and the siblings
        a.set_sibling_hashes(proof.get_sibling_hashes());
        a.set_read_hash(proof.get_target_hash());
    }

    static void log_written_hash(access &a, const hash_type &written_hash) {
        a.get_written_hash().emplace(written_hash);
    }

    const auto &log_read_data(access &a, uint64_t paddr, int log2_size) const {
        // NOLINTBEGIN(bugprone-unchecked-optional-access)
        const auto size = UINT64_C(1) << log2_size;
        a.get_read().emplace();
        a.get_read().value().resize(size);
        m_m.read_memory(paddr, a.get_read().value().data(), size);
        return a.get_read().value();
        // NOLINTEND(bugprone-unchecked-optional-access)
    }

    void log_read_data_if_requested(access &a, uint64_t paddr, int log2_size) const {
        if (m_log->get_log_type().has_large_data()) {
            std::ignore = log_read_data(a, paddr, log2_size);
        }
    }

    void log_written_data(access &a, uint64_t paddr, int log2_size) const {
        // NOLINTBEGIN(bugprone-unchecked-optional-access)
        const auto size = UINT64_C(1) << log2_size;
        a.get_written().emplace();
        a.get_written().value().resize(size);
        m_m.read_memory(paddr, a.get_written().value().data(), size);
        // NOLINTEND(bugprone-unchecked-optional-access)
    }

    void log_written_data_if_requested(access &a, uint64_t paddr, int log2_size) const {
        if (m_log->get_log_type().has_large_data()) {
            log_written_data(a, paddr, log2_size);
        }
    }

    uint64_t log_read_word_access(uint64_t paddr, const char *text) const {
        const auto log2_size = log2_size_v<uint64_t>;
        access a;
        log_access_type(a, access_type::read);
        log_access_range(a, paddr, log2_size);
        const auto [access_paddr, access_log2_size] = adjust_access(paddr, log2_size);
        log_access_siblings_and_read_hash(a, access_paddr, access_log2_size);
        const auto &read_data = log_read_data(a, access_paddr, access_log2_size);
        const auto val_offset = paddr - access_paddr;
        const auto val = get_word_access_data(read_data, val_offset);
        log_access(std::move(a), text);
        return val;
    }

    uint64_t log_read_reg_access(machine_reg reg) const {
        return log_read_word_access(machine_reg_address(reg), machine_reg_get_name(reg));
    }

    template <typename WRITE_UPDATE_F>
    void log_write_access(uint64_t paddr, int log2_size, WRITE_UPDATE_F write_and_update, const char *text) {
        access a;
        log_access_type(a, access_type::write);
        log_access_range(a, paddr, log2_size);
        const auto [access_paddr, access_log2_size] = adjust_access(paddr, log2_size);
        log_access_siblings_and_read_hash(a, access_paddr, access_log2_size);
        // We *need* the read data for small writes, because we splice the written into it
        if (log2_size < machine_merkle_tree::get_log2_word_size()) {
            std::ignore = log_read_data(a, access_paddr, access_log2_size);
        } else {
            log_read_data_if_requested(a, access_paddr, access_log2_size);
        }
        // Call functor to perform the write and update the tree
        write_and_update();
        // The functor updated the tree, so we don't do it again
        log_written_hash(a, m_m.get_merkle_tree_node_hash(access_paddr, access_log2_size, skip_merkle_tree_update));
        // We don't *need* the written for small writes, but it is convenient to always have it (for debugging purposes)
        if (log2_size < machine_merkle_tree::get_log2_word_size()) {
            log_written_data(a, access_paddr, access_log2_size);
        } else {
            log_written_data_if_requested(a, access_paddr, access_log2_size);
        }
        log_access(std::move(a), text);
    }

    void log_write_reg_access(machine_reg reg, uint64_t val) {
        log_write_access(
            machine_reg_address(reg), log2_size_v<uint64_t>,
            [this, reg, val]() {
                m_m.write_reg(reg, val);
                if (!m_m.update_merkle_tree_page(machine_reg_address(reg))) {
                    throw std::invalid_argument{"error updating Merkle tree"};
                };
            },
            machine_reg_get_name(reg));
    }

    // Declare interface as friend to it can forward calls to the "overridden" methods.
    friend i_uarch_state_access<uarch_record_state_access>;

    uint64_t do_read_x(int i) const {
        return log_read_reg_access(machine_reg_enum(machine_reg::uarch_x0, i));
    }

    void do_write_x(int i, uint64_t val) {
        assert(i != 0);
        log_write_reg_access(machine_reg_enum(machine_reg::uarch_x0, i), val);
    }

    uint64_t do_read_pc() const {
        return log_read_reg_access(machine_reg::uarch_pc);
    }

    void do_write_pc(uint64_t val) {
        log_write_reg_access(machine_reg::uarch_pc, val);
    }

    uint64_t do_read_cycle() const {
        return log_read_reg_access(machine_reg::uarch_cycle);
    }

    void do_write_cycle(uint64_t val) {
        log_write_reg_access(machine_reg::uarch_cycle, val);
    }

    uint64_t do_read_halt_flag() const {
        return log_read_reg_access(machine_reg::uarch_halt_flag);
    }

    void do_write_halt_flag(uint64_t val) {
        log_write_reg_access(machine_reg::uarch_halt_flag, val);
    }

    uint64_t do_read_word(uint64_t paddr) const {
        if ((paddr & (sizeof(uint64_t) - 1)) != 0) {
            throw std::runtime_error("misaligned read from uarch");
        }
        return log_read_word_access(paddr, machine::get_what_name(paddr));
    }

    void do_write_word(uint64_t paddr, uint64_t val) {
        if ((paddr & (sizeof(uint64_t) - 1)) != 0) {
            throw std::runtime_error("misaligned write to uarch");
        }
        log_write_access(
            paddr, log2_size_v<uint64_t>,
            [this, paddr, val]() {
                m_m.write_word(paddr, val);
                if (!m_m.update_merkle_tree_page(paddr)) {
                    throw std::invalid_argument{"error updating Merkle tree"};
                };
            },
            machine::get_what_name(paddr));
    }

    void do_write_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
        uint64_t pma_index) {
        const auto slot_paddr = shadow_tlb_get_abs_addr(set_index, slot_index);
        log_write_access(
            slot_paddr, SHADOW_TLB_SLOT_LOG2_SIZE,
            [this, set_index, slot_index, vaddr_page, vp_offset, pma_index]() {
                m_m.write_shadow_tlb(set_index, slot_index, vaddr_page, vp_offset, pma_index);
                // Entire slot is in a single page
                if (!m_m.update_merkle_tree_page(shadow_tlb_get_abs_addr(set_index, slot_index))) {
                    throw std::invalid_argument{"error updating Merkle tree"};
                };
            },
            "tlb.slot");
        // Writes to TLB slots have to be atomic.
        // We can only do atomic writes of entire Merkle tree nodes.
        // Therefore, TLB slot must have a power-of-two size, or at least be aligned to it.
        static_assert(SHADOW_TLB_SLOT_SIZE == sizeof(shadow_tlb_slot), "shadow TLB slot size is wrong");
        static_assert((UINT64_C(1) << SHADOW_TLB_SLOT_LOG2_SIZE) == SHADOW_TLB_SLOT_SIZE,
            "shadow TLB slot log2 size is wrong");
        static_assert(SHADOW_TLB_SLOT_LOG2_SIZE >= machine_merkle_tree::get_log2_word_size(),
            "shadow TLB slot must fill at least an entire Merkle tree word");
    }

    void do_reset_state() {
        //??D I'd like to add an static_assert or some other guard mechanism to
        // guarantee that uarch.ram and uarch.shadow are alone in the entire
        // span of their common Merkle tree parent node
        log_write_access(
            UARCH_STATE_START_ADDRESS, UARCH_STATE_LOG2_SIZE,
            [this]() {
                m_m.reset_uarch();
                // reset_uarch() marks all modified pages as dirty
                if (!m_m.update_merkle_tree()) {
                    throw std::invalid_argument{"error updating Merkle tree"};
                }
            },
            "uarch.state");
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_putchar(uint8_t c) {
        os_putchar(c);
    }

    void do_mark_dirty_page(uint64_t paddr, uint64_t pma_index) {
        // Forward to machine and no need to log
        m_m.mark_dirty_page(paddr, pma_index);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    constexpr const char *do_get_name() const {
        return "uarch_record_state_access";
    }
};

} // namespace cartesi

#endif
