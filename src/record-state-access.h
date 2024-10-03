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

#ifndef RECORD_STATE_ACCESS_H
#define RECORD_STATE_ACCESS_H

/// \file
/// \brief State access implementation that records state accesses to an access log.

#include <cassert>
#include <memory>

#include "i-state-access.h"
#include "machine-merkle-tree.h"
#include "machine.h"
#include "shadow-state.h"

namespace cartesi {

/// \class record_state_access
/// \details This ....
/// access to the machine state. No logs are kept.
class record_state_access : public i_state_access<record_state_access, pma_entry> {
    using hasher_type = machine_merkle_tree::hasher_type;
    using hash_type = machine_merkle_tree::hash_type;
    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    machine &m_m; ///< Associated machine
    machine_state &m_s;
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)
    std::shared_ptr<access_log> m_log; ///< Pointer to access log

    static void get_hash(const access_data &data, hash_type &hash) {
        hasher_type hasher;
        get_merkle_tree_hash(hasher, data.data(), data.size(), machine_merkle_tree::get_word_size(), hash);
    }

public:
    /// \brief Constructor from machine state.
    /// \param m Pointer to machine state.
    explicit record_state_access(machine &m, access_log::type log_type) :
        m_m(m),
        m_s(m.get_state()),
        m_log(std::make_shared<access_log>(log_type)) {
        ;
    }

    /// \brief No copy constructor
    record_state_access(const record_state_access &) = delete;
    /// \brief No copy assignment
    record_state_access &operator=(const record_state_access &) = delete;
    /// \brief No move constructor
    record_state_access(record_state_access &&) = delete;
    /// \brief No move assignment
    record_state_access &operator=(record_state_access &&) = delete;
    /// \brief Default destructor
    ~record_state_access() = default;

    /// \brief Returns const pointer to access log.
    std::shared_ptr<const access_log> get_log(void) const {
        return m_log;
    }

    /// \brief Returns pointer to access log.
    std::shared_ptr<access_log> get_log(void) {
        return m_log;
    }

private:
    /// \brief Logs a read access of a uint64_t word from the machine state.
    /// \param paligned Physical address in the machine state, aligned to a 64-bit word.
    /// \param text Textual description of the access.
    void log_read(uint64_t paligned, const char *text) const {
        static_assert(machine_merkle_tree::get_log2_word_size() >= log2_size<uint64_t>::value,
            "Merkle tree word size must be at least as large as a machine word");
        if ((paligned & (sizeof(uint64_t) - 1)) != 0) {
            throw std::invalid_argument{"paligned is not aligned to word size"};
        }
        const uint64_t pleaf_aligned = paligned & ~(machine_merkle_tree::get_word_size() - 1);
        access a;
        if (m_log->get_log_type().has_proofs()) {
            // We can skip updating the merkle tree while getting the proof because we assume that:
            // 1) A full merkle tree update was called at the beginning of machine::log_load_cmio_input()
            // 2) We called update_merkle_tree_page on all write accesses
            const auto proof =
                m_m.get_proof(pleaf_aligned, machine_merkle_tree::get_log2_word_size(), skip_merkle_tree_update);
            // We just store the sibling hashes in the access because this is the only missing piece of data needed to
            // reconstruct the proof
            a.set_sibling_hashes(proof.get_sibling_hashes());
        }
        a.set_type(access_type::read);
        a.set_address(paligned);
        a.set_log2_size(log2_size<uint64_t>::value);
        // NOLINTBEGIN(bugprone-unchecked-optional-access)
        // we log the leaf data at pleaf_aligned that contains the word at paligned
        a.get_read().emplace();
        a.get_read().value().resize(machine_merkle_tree::get_word_size());
        // read the entire leaf where the word is located
        m_m.read_memory(pleaf_aligned, a.get_read().value().data(), machine_merkle_tree::get_word_size());
        get_hash(a.get_read().value(), a.get_read_hash());
        // NOLINTEND(bugprone-unchecked-optional-access)
        m_log->push_access(std::move(a), text);
    }

    /// \brief Logs a write access before it happens.
    /// \param paligned Physical address of the word in the machine state (Must be aligned to a 64-bit word).
    /// \param val Value to write.
    /// \param text Textual description of the access.
    void log_before_write(uint64_t paligned, uint64_t val, const char *text) {
        static_assert(machine_merkle_tree::get_log2_word_size() >= log2_size<uint64_t>::value,
            "Merkle tree word size must be at least as large as a machine word");
        if ((paligned & (sizeof(uint64_t) - 1)) != 0) {
            throw std::invalid_argument{"paligned is not aligned to word size"};
        }
        // address of the leaf that contains the word at paligned
        const uint64_t pleaf_aligned = paligned & ~(machine_merkle_tree::get_word_size() - 1);
        access a;
        if (m_log->get_log_type().has_proofs()) {
            // We can skip updating the merkle tree while getting the proof because we assume that:
            // 1) A full merkle tree update was called at the beginning of machine::log_load_cmio_input()
            // 2) We called update_merkle_tree_page on all write accesses
            const auto proof =
                m_m.get_proof(pleaf_aligned, machine_merkle_tree::get_log2_word_size(), skip_merkle_tree_update);
            // We just store the sibling hashes in the access because this is the only missing piece of data needed to
            // reconstruct the proof
            a.set_sibling_hashes(proof.get_sibling_hashes());
        }
        a.set_type(access_type::write);
        a.set_address(paligned);
        a.set_log2_size(log2_size<uint64_t>::value);
        // NOLINTBEGIN(bugprone-unchecked-optional-access)
        // we log the entire leaf where the word is located
        a.get_read().emplace();
        a.get_read().value().resize(machine_merkle_tree::get_word_size());
        m_m.read_memory(pleaf_aligned, a.get_read().value().data(), machine_merkle_tree::get_word_size());
        get_hash(a.get_read().value(), a.get_read_hash());
        // the logged written data is the same as the read data, but with the word at paligned replaced by word
        a.set_written(access_data(a.get_read().value()));                    // copy the read data
        const int word_offset = static_cast<int>(paligned - pleaf_aligned);  // offset of word in leaf
        replace_word_access_data(val, a.get_written().value(), word_offset); // replace the word
        // compute the hash of the written data
        a.get_written_hash().emplace();
        get_hash(a.get_written().value(), a.get_written_hash().value());
        // NOLINTEND(bugprone-unchecked-optional-access)
        m_log->push_access(std::move(a), text);
    }

    /// \brief Updates the Merkle tree after the modification of a word in the machine state.
    /// \param paligned Physical address in the machine state, aligned to a 64-bit word.
    void update_after_write(uint64_t paligned) {
        assert((paligned & (sizeof(uint64_t) - 1)) == 0);
        if (m_log->get_log_type().has_proofs()) {
            const bool updated = m_m.update_merkle_tree_page(paligned);
            (void) updated;
            assert(updated);
        }
    }

    /// \brief Logs a write access before it happens, writes, and then update the Merkle tree.
    /// \param paligned Physical address of the word in the machine state (Must be aligned to a 64-bit word).
    /// \param dest Reference to value before writing.
    /// \param val Value to write to \p dest.
    /// \param text Textual description of the access.
    void log_before_write_write_and_update(uint64_t paligned, uint64_t &dest, uint64_t val, const char *text) {
        assert((paligned & (sizeof(uint64_t) - 1)) == 0);
        log_before_write(paligned, val, text);
        dest = val;
        update_after_write(paligned);
    }

    void log_before_write_word_write_and_update(uint64_t paligned, bool &dest, bool val, const char *text) {
        uint64_t dest64 = dest;
        log_before_write_write_and_update(paligned, dest64, val, text);
        dest = dest64;
        update_after_write(paligned);
    }

    // Declare interface as friend to it can forward calls to the "overriden" methods.
    friend i_state_access<record_state_access, pma_entry>;

    void do_push_bracket(bracket_type &type, const char *text) {
        m_log->push_bracket(type, text);
    }

    void do_reset_iflags_Y(void) {
        auto new_iflags = machine_state::packed_iflags(m_m.get_state().iflags.PRV, m_m.get_state().iflags.X,
            false /* Y */, m_m.get_state().iflags.H);
        const uint64_t iflags_addr = shadow_state_get_reg_abs_addr(shadow_state_reg::iflags);
        log_read(iflags_addr, "iflags.Y");
        log_before_write(iflags_addr, new_iflags, "iflags.Y");
        m_m.get_state().iflags.Y = false;
        update_after_write(iflags_addr);
    }

    bool do_read_iflags_Y(void) const {
        log_read(shadow_state_get_reg_abs_addr(shadow_state_reg::iflags), "iflags.Y");
        return m_m.get_state().iflags.Y;
    }

    void do_write_htif_fromhost(uint64_t val) {
        log_before_write_write_and_update(shadow_state_get_reg_abs_addr(shadow_state_reg::htif_fromhost),
            m_m.get_state().htif.fromhost, val, "htif.fromhost");
    }

    void do_write_memory_with_padding(uint64_t paddr, const unsigned char *data, uint64_t data_length,
        int write_length_log2_size) {
        if (paddr & (machine_merkle_tree::get_word_size() - 1)) {
            throw std::invalid_argument("paddr is not aligned to tree leaf size");
        }
        if (!data) {
            throw std::invalid_argument("data is null");
        }
        const uint64_t write_length = static_cast<uint64_t>(1) << write_length_log2_size;
        if (write_length < data_length) {
            throw std::invalid_argument("write_length is less than data_length");
        }
        // We need to compute the hash of the existing data before writing
        // Find the target pma entry
        auto &pma = m_m.find_pma_entry(paddr, write_length);
        if (pma.get_istart_E()) {
            throw std::invalid_argument("address range not entirely in memory PMA");
        }
        access a{};
        a.set_type(access_type::write);
        a.set_address(paddr);
        a.set_log2_size(write_length_log2_size);
        // Always compute the proof, even if we are not logging it, because:
        // (1) we always need to compute read_hash.
        // (2) Depending on the log type, we may also need to compute the proof.
        // (3) proof.target_hash is the  value that we  need for a.read_hash in (1).
        auto proof = m_m.get_proof(paddr, write_length_log2_size);
        // log hash and data before write
        a.set_read_hash(proof.get_target_hash());
        if (m_log->get_log_type().has_large_data()) {
            access_data &data = a.get_read().emplace(write_length);
            memcpy(data.data(), pma.get_memory().get_host_memory(), write_length);
        }
        if (m_log->get_log_type().has_proofs()) {
            // We just store the sibling hashes in the access because this is the only missing piece of data needed to
            // reconstruct the proof
            a.set_sibling_hashes(proof.get_sibling_hashes());
        }
        // write data to memory
        m_m.write_memory(paddr, data, data_length);
        if (write_length > data_length) {
            m_m.fill_memory(paddr + data_length, 0, write_length - data_length);
        }
        // we have to update the merkle tree after every write
        m_m.update_merkle_tree();
        // log hash and written data
        // NOLINTBEGIN(bugprone-unchecked-optional-access)
        a.get_written_hash().emplace();
        hasher_type hasher{};
        get_merkle_tree_hash(hasher, pma.get_memory().get_host_memory(), write_length,
            machine_merkle_tree::get_word_size(), a.get_written_hash().value());
        if (m_log->get_log_type().has_large_data()) {
            access_data &data = a.get_written().emplace(write_length);
            memcpy(data.data(), pma.get_memory().get_host_memory(), write_length);
        }
        // NOLINTEND(bugprone-unchecked-optional-access)
        m_log->push_access(a, "cmio rx buffer");
    }
};

} // namespace cartesi

#endif
