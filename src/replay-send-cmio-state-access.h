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

#ifndef REPLAY_SEND_CMIO_STATE_ACCESS_H
#define REPLAY_SEND_CMIO_STATE_ACCESS_H

/// \file
/// \brief State access implementation that replays recorded state accesses

#include <cassert>
#include <cstdint>
#include <cstring>
#include <ios>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "access-log.h"
#include "i-hasher.h"
#include "i-state-access.h"
#include "machine-merkle-tree.h"
#include "meta.h"
#include "mock-pma-entry.h"
#include "riscv-constants.h"
#include "shadow-state.h"
#include "unique-c-ptr.h"

namespace cartesi {

class replay_send_cmio_state_access;

// Type trait that should return the pma_entry type for a state access class
template <>
struct i_state_access_pma_entry<replay_send_cmio_state_access> {
    using type = mock_pma_entry;
};
// Type trait that should return the fast_addr type for a state access class
template <>
struct i_state_access_fast_addr<replay_send_cmio_state_access> {
    using type = uint64_t;
};

/// \brief Allows replaying a machine::send_cmio_response() from an access log.
class replay_send_cmio_state_access : public i_state_access<replay_send_cmio_state_access> {
    using tree_type = machine_merkle_tree;
    using hash_type = tree_type::hash_type;
    using hasher_type = tree_type::hasher_type;
    using proof_type = tree_type::proof_type;

public:
    struct context {
        /// \brief Constructor replay_send_cmio_state_access context
        /// \param log Access log to be replayed
        /// \param initial_hash Initial root hash
        context(const access_log &log, machine_merkle_tree::hash_type initial_hash) :
            accesses(log.get_accesses()),
            root_hash(initial_hash) {
            ;
        }
        const std::vector<access> &accesses; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
        ///< Index of next access to ne consumed
        unsigned int next_access{};
        ///< Root hash before next access
        machine_merkle_tree::hash_type root_hash;
        ///< Hasher needed to verify proofs
        machine_merkle_tree::hasher_type hasher;
    };

private:
    context &m_context; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)

public:
    /// \brief Constructor from access log
    /// \param context Context with access log and initial root hash
    explicit replay_send_cmio_state_access(replay_send_cmio_state_access::context &context) : m_context{context} {
        if (m_context.accesses.empty()) {
            throw std::invalid_argument{"the access log has no accesses"};
        }
    }

    void get_root_hash(machine_merkle_tree::hash_type &hash) const {
        hash = m_context.root_hash;
    }

    /// \brief Checks if access log was fully consumed after reset operation is finished
    void finish() {
        if (m_context.next_access != m_context.accesses.size()) {
            throw std::invalid_argument{"access log was not fully consumed"};
        }
    }

private:
    friend i_state_access<replay_send_cmio_state_access>;

    std::string access_to_report() const {
        auto index = m_context.next_access + 1;
        switch (index) {
            case 1:
                return "1st access";
            case 2:
                return "2nd access";
            case 3:
                return "3rd access";
            default:
                return std::to_string(index) + "th access";
        }
    }

    static void get_hash(machine_merkle_tree::hasher_type &hasher, const access_data &data,
        machine_merkle_tree::hash_type &hash) {
        get_merkle_tree_hash(hasher, data.data(), data.size(), machine_merkle_tree::get_word_size(), hash);
    }

    /// \brief Checks a logged read and advances log.
    /// \param paligned Physical address in the machine state,
    /// aligned to the access size.
    /// \param log2_size Log2 of access size.
    /// \param text Textual description of the access.
    /// \returns Value read.
    uint64_t check_read(uint64_t paligned, const char *text) {
        static_assert(machine_merkle_tree::get_log2_word_size() >= log2_size_v<uint64_t>,
            "Merkle tree word size must be at least as large as a machine word");
        if ((paligned & (sizeof(uint64_t) - 1)) != 0) {
            throw std::invalid_argument{"address not aligned to word size"};
        }
        if (m_context.next_access >= m_context.accesses.size()) {
            throw std::invalid_argument{"too few accesses in log"};
        }
        const auto &access = m_context.accesses[m_context.next_access];
        if (access.get_type() != access_type::read) {
            throw std::invalid_argument{"expected " + access_to_report() + " to read " + text};
        }
        if (access.get_address() != paligned) {
            std::ostringstream err;
            err << "expected " << access_to_report() << " to read " << text << " address 0x" << std::hex << paligned
                << "(" << std::dec << paligned << ")";
            throw std::invalid_argument{err.str()};
        }
        if (access.get_log2_size() != log2_size_v<uint64_t>) {
            throw std::invalid_argument{"expected " + access_to_report() + " to read 2^" +
                std::to_string(machine_merkle_tree::get_log2_word_size()) + " bytes from " + text};
        }
        if (!access.get_read().has_value()) {
            throw std::invalid_argument{"missing read " + std::string(text) + " data at " + access_to_report()};
        }
        // NOLINTBEGIN(bugprone-unchecked-optional-access)
        const auto &read_data = access.get_read().value();
        if (read_data.size() != machine_merkle_tree::get_word_size()) {
            throw std::invalid_argument{"expected read " + std::string(text) + " data to contain 2^" +
                std::to_string(machine_merkle_tree::get_log2_word_size()) + " bytes at " + access_to_report()};
        }
        // check if logged read data hashes to the logged read hash
        hash_type computed_read_hash{};
        get_hash(m_context.hasher, read_data, computed_read_hash);
        if (access.get_read_hash() != computed_read_hash) {
            throw std::invalid_argument{"logged read data of " + std::string(text) +
                " data does not hash to the logged read hash at " + access_to_report()};
        }
        // NOLINTEND(bugprone-unchecked-optional-access)
        // check proof
        auto proof = access.make_proof(m_context.root_hash);
        if (!proof.verify(m_context.hasher)) {
            throw std::invalid_argument{"Mismatch in root hash of " + access_to_report()};
        }
        m_context.next_access++;
        const uint64_t pleaf_aligned = paligned & ~(machine_merkle_tree::get_word_size() - 1);
        const int word_offset = static_cast<int>(paligned - pleaf_aligned);
        return get_word_access_data(read_data, word_offset);
    }

    /// \brief Checks a logged word write and advances log.
    /// \param paligned Physical address in the machine state,
    /// aligned to a 64-bit word.
    /// \param word Word value to write.
    /// \param text Textual description of the access.
    void check_write(uint64_t paligned, uint64_t word, const char *text) {
        static_assert(machine_merkle_tree::get_log2_word_size() >= log2_size_v<uint64_t>,
            "Merkle tree word size must be at least as large as a machine word");
        if ((paligned & (sizeof(uint64_t) - 1)) != 0) {
            throw std::invalid_argument{"paligned not aligned to word size"};
        }
        if (m_context.next_access >= m_context.accesses.size()) {
            throw std::invalid_argument{"too few accesses in log"};
        }
        const auto &access = m_context.accesses[m_context.next_access];
        if (access.get_type() != access_type::write) {
            throw std::invalid_argument{"expected " + access_to_report() + " to write " + text};
        }
        if (access.get_address() != paligned) {
            std::ostringstream err;
            err << "expected " << access_to_report() << " to write " << text << " to address 0x" << std::hex << paligned
                << "(" << std::dec << paligned << ")";
            throw std::invalid_argument{err.str()};
        }
        if (access.get_log2_size() != log2_size_v<uint64_t>) {
            throw std::invalid_argument{"expected " + access_to_report() + " to write 2^" +
                std::to_string(machine_merkle_tree::get_log2_word_size()) + " bytes to " + text};
        }
        // NOLINTBEGIN(bugprone-unchecked-optional-access)
        // check read
        if (!access.get_read().has_value()) {
            throw std::invalid_argument{"missing read " + std::string(text) + " data at " + access_to_report()};
        }
        const auto &read_data = access.get_read().value();
        if (read_data.size() != machine_merkle_tree::get_word_size()) {
            throw std::invalid_argument{"expected overwritten data from " + std::string(text) + " to contain 2^" +
                std::to_string(access.get_log2_size()) + " bytes at " + access_to_report()};
        }
        // check if read data hashes to the logged read hash
        hash_type computed_read_hash{};
        get_hash(m_context.hasher, read_data, computed_read_hash);
        if (access.get_read_hash() != computed_read_hash) {
            throw std::invalid_argument{"logged read data of " + std::string(text) +
                " does not hash to the logged read hash at " + access_to_report()};
        }
        // check write
        if (!access.get_written_hash().has_value()) {
            throw std::invalid_argument{"missing written " + std::string(text) + " hash at " + access_to_report()};
        }
        const auto &written_hash = access.get_written_hash().value();
        if (!access.get_written().has_value()) {
            throw std::invalid_argument{"missing written " + std::string(text) + " data at " + access_to_report()};
        }
        const auto &written_data = access.get_written().value();
        if (written_data.size() != read_data.size()) {
            throw std::invalid_argument{"expected written " + std::string(text) + " data to contain 2^" +
                std::to_string(access.get_log2_size()) + " bytes at " + access_to_report()};
        }
        // check if written data hashes to the logged written hash
        hash_type computed_written_hash{};
        get_hash(m_context.hasher, written_data, computed_written_hash);
        if (written_hash != computed_written_hash) {
            throw std::invalid_argument{"logged written data of " + std::string(text) +
                " does not hash to the logged written hash at " + access_to_report()};
        }
        // check if word being written matches the logged data
        const uint64_t pleaf_aligned = paligned & ~(machine_merkle_tree::get_word_size() - 1);
        const int word_offset = static_cast<int>(paligned - pleaf_aligned);
        const uint64_t logged_word = get_word_access_data(written_data, word_offset);
        if (word != logged_word) {
            throw std::invalid_argument{"value being written to " + std::string(text) +
                " does not match the logged written value at " + access_to_report()};
        }
        // check if logged written data differs from the logged read data only by the written word
        access_data expected_written_data(read_data);                       // make a copy of read data
        replace_word_access_data(word, expected_written_data, word_offset); // patch with written word
        if (written_data != expected_written_data) {
            throw std::invalid_argument{"logged written data of " + std::string(text) +
                " doesn't differ from the logged read data only by the written word at " + access_to_report()};
        }
        // NOLINTEND(bugprone-unchecked-optional-access)
        // check proof
        auto proof = access.make_proof(m_context.root_hash);
        if (!proof.verify(m_context.hasher)) {
            throw std::invalid_argument{"Mismatch in root hash of " + access_to_report()};
        }
        // Update root hash to reflect the data written by this access
        m_context.root_hash = proof.bubble_up(m_context.hasher, written_hash);
        m_context.next_access++;
    }

    void do_push_bracket(bracket_type & /*type*/, const char * /*text*/) {}

    void do_write_iflags_Y(uint64_t val) {
        check_write(machine_reg_address(machine_reg::iflags_Y), val, "iflags.Y");
    }

    uint64_t do_read_iflags_Y() {
        return check_read(machine_reg_address(machine_reg::iflags_Y), "iflags.Y");
    }

    void do_write_htif_fromhost(uint64_t val) {
        check_write(machine_reg_address(machine_reg::htif_fromhost), val, "htif.fromhost");
    }

    void do_write_memory_with_padding(uint64_t paddr, const unsigned char *data, uint64_t data_length,
        int write_length_log2_size) {
        hasher_type hasher{};
        if (data == nullptr) {
            throw std::invalid_argument("data is null");
        }
        const uint64_t write_length = static_cast<uint64_t>(1) << write_length_log2_size;
        if (write_length < data_length) {
            throw std::invalid_argument{"write length is less than data length"};
        }
        const auto text = std::string("cmio rx buffer");
        if (m_context.next_access >= m_context.accesses.size()) {
            throw std::invalid_argument{"too few accesses in log"};
        }
        const auto &access = m_context.accesses[m_context.next_access];
        if (access.get_address() != paddr) {
            throw std::invalid_argument{"expected address of " + access_to_report() + " to match address of " + text};
        }
        if (access.get_log2_size() != write_length_log2_size) {
            throw std::invalid_argument{"expected " + access_to_report() + " to write 2^" +
                std::to_string(write_length_log2_size) + " bytes to " + text};
        }
        if (access.get_type() != access_type::write) {
            throw std::invalid_argument{"expected " + access_to_report() + " to write " + text};
        }
        // NOLINTBEGIN(bugprone-unchecked-optional-access)
        // if read data is available then its hash and the logged read hash must match
        if (access.get_read().has_value()) {
            hash_type computed_logged_data_hash{};
            get_hash(hasher, access.get_read().value(), computed_logged_data_hash);
            if (computed_logged_data_hash != access.get_read_hash()) {
                throw std::invalid_argument{
                    "hash of read data and read hash at " + access_to_report() + " does not match read hash"};
            }
        }
        if (!access.get_written_hash().has_value()) {
            throw std::invalid_argument{"write " + access_to_report() + " has no written hash"};
        }
        const auto &written_hash = access.get_written_hash().value();
        // compute hash of data argument padded with zeroes
        hash_type computed_data_hash{};
        auto scratch = unique_calloc<unsigned char>(write_length, std::nothrow_t{});
        if (!scratch) {
            throw std::runtime_error("Could not allocate scratch memory");
        }
        memcpy(scratch.get(), data, data_length);
        if (write_length > data_length) {
            memset(scratch.get() + data_length, 0, write_length - data_length);
        }
        get_merkle_tree_hash(hasher, scratch.get(), write_length, machine_merkle_tree::get_word_size(),
            computed_data_hash);
        // check if logged written hash matches the computed data hash
        if (written_hash != computed_data_hash) {
            throw std::invalid_argument{"logged written hash of " + text +
                " does not match the hash of data argument at " + access_to_report()};
        }
        if (access.get_written().has_value()) {
            // if written data is available then its hash and the logged written hash must match
            hash_type computed_hash;
            get_hash(hasher, access.get_written().value(), computed_hash);
            if (computed_hash != written_hash) {
                throw std::invalid_argument{"written hash and written data mismatch at " + access_to_report()};
            }
        }
        // NOLINTEND(bugprone-unchecked-optional-access)
        // check proof
        auto proof = access.make_proof(m_context.root_hash);
        if (!proof.verify(m_context.hasher)) {
            throw std::invalid_argument{"Mismatch in root hash of " + access_to_report()};
        }
        // Update root hash to reflect the data written by this access
        m_context.root_hash = proof.bubble_up(m_context.hasher, written_hash);
        m_context.next_access++;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    constexpr const char *do_get_name() const {
        return "replay_send_cmio_state_access";
    }
};

} // namespace cartesi

#endif
