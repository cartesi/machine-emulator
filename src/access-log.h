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

#ifndef ACCESS_LOG_H
#define ACCESS_LOG_H

/// \file
/// \brief State access log implementation

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <boost/container/small_vector.hpp>

#include "bracket-note.h"
#include "machine-c-api.h"
#include "machine-merkle-tree.h"
#include "strict-aliasing.h"

namespace cartesi {

/// \brief Type of state access
enum class access_type {
    read,  ///< Read operation
    write, ///< Write operation
};

using access_data = boost::container::small_vector<uint8_t, 8>;

static inline void set_word_access_data(uint64_t w, access_data &ad) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *p = reinterpret_cast<uint8_t *>(&w);
    ad.clear();
    ad.insert(ad.end(), p, p + sizeof(w));
}

static inline void replace_word_access_data(uint64_t w, access_data &ad, int offset = 0) {
    assert(ad.size() >= offset + sizeof(uint64_t));
    aliased_aligned_write<uint64_t>(ad.data() + offset, w);
}

static inline uint64_t get_word_access_data(const access_data &ad, int offset = 0) {
    assert(ad.size() >= offset + sizeof(uint64_t));
    return aliased_aligned_read<uint64_t>(ad.data() + offset);
}

/// \brief Records an access to the machine state
class access {

    using hasher_type = machine_merkle_tree::hasher_type;

public:
    using hash_type = machine_merkle_tree::hash_type;
    using sibling_hashes_type = std::vector<hash_type>;
    using proof_type = machine_merkle_tree::proof_type;

    void set_type(access_type type) {
        m_type = type;
    }
    access_type get_type() const {
        return m_type;
    }

    /// \brief Sets log<sub>2</sub> of size of access.
    /// \param log2_size New log<sub>2</sub> of size of access.
    void set_log2_size(int log2_size) {
        m_log2_size = log2_size;
    }

    /// \brief Gets log<sub>2</sub> of size of access.
    /// \returns log<sub>2</sub> of size.
    int get_log2_size() const {
        return m_log2_size;
    }

    /// \brief Sets address of access.
    /// \param address New address.
    void set_address(uint64_t address) {
        m_address = address;
    }

    /// \brief Gets address of access.
    /// \returns Address.
    uint64_t get_address() const {
        return m_address;
    }

    /// \brief Sets data that can be read at address before access.
    /// \param read Data at address.
    void set_read(const access_data &read) {
        m_read = read;
    }
    void set_read(access_data &&read) {
        m_read = std::move(read);
    }

    /// \brief Gets data that can be read at address before access.
    /// \returns Data at address.
    const std::optional<access_data> &get_read() const {
        return m_read;
    }
    std::optional<access_data> &get_read() {
        return m_read;
    }

    /// \brief Sets data that was written at address after access.
    /// \param written New data at address.
    void set_written(const access_data &written) {
        m_written = written;
    }
    void set_written(access_data &&written) {
        m_written = std::move(written);
    }

    /// \brief Gets data that was written at address after access.
    /// \returns Data at address.
    const std::optional<access_data> &get_written() const {
        return m_written;
    }
    std::optional<access_data> &get_written() {
        return m_written;
    }

    /// \brief Sets hash of data that was written at address after access.
    /// \param hash Hash of new data at address.
    void set_written_hash(const hash_type &hash) {
        m_written_hash = hash;
    }

    /// \brief Gets hash of data that was written at address after access.
    /// \returns Hash of written data at address.
    const std::optional<hash_type> &get_written_hash() const {
        return m_written_hash;
    }
    std::optional<hash_type> &get_written_hash() {
        return m_written_hash;
    }

    /// \brief Sets hash of data that can be read at address before access.
    /// \param hash Hash of data at address.
    void set_read_hash(const hash_type &hash) {
        m_read_hash = hash;
    }

    /// \brief Gets hash of data that can be read at address before access.
    /// \returns Hash of data at address.
    const hash_type &get_read_hash() const {
        return m_read_hash;
    }
    hash_type &get_read_hash() {
        return m_read_hash;
    }

    /// \brief Constructs a proof using this access' data and a given root hash.
    /// \param root_hash Hash to be used as the root of the proof.
    /// \return The corresponding proof
    proof_type make_proof(const hash_type root_hash) const {
        // the access can be of data smaller than the merkle tree word size
        // however, the proof must be at least as big as the merkle tree word size
        const int proof_log2_size = std::max(m_log2_size, machine_merkle_tree::get_log2_word_size());
        // the proof address is the access address aligned to the merkle tree word size
        const uint64_t proof_address = m_address & ~(machine_merkle_tree::get_word_size() - 1);
        if (!m_sibling_hashes.has_value()) {
            throw std::runtime_error("can't make proof if access doesn't have sibling hashes");
        }
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        const auto &sibling_hashes = m_sibling_hashes.value();
        const int log2_root_size = proof_log2_size + static_cast<int>(sibling_hashes.size());
        if (m_read.has_value() && m_read.value().size() != (static_cast<uint64_t>(1) << proof_log2_size)) {
            throw std::runtime_error("access read data size is inconsistent with proof size");
        }
        if (m_written.has_value() && m_written.value().size() != (static_cast<uint64_t>(1) << proof_log2_size)) {
            throw std::runtime_error("access written data size is inconsistent with proof size");
        }
        proof_type proof(log2_root_size, proof_log2_size);
        proof.set_root_hash(root_hash);
        proof.set_target_address(proof_address);
        proof.set_target_hash(m_read_hash);
        for (int log2_size = proof_log2_size; log2_size < log2_root_size; log2_size++) {
            proof.set_sibling_hash(sibling_hashes[log2_size - proof_log2_size], log2_size);
        }
        return proof;
    }

    std::optional<sibling_hashes_type> &get_sibling_hashes() {
        return m_sibling_hashes;
    }
    const std::optional<sibling_hashes_type> &get_sibling_hashes() const {
        return m_sibling_hashes;
    }

    void set_sibling_hashes(const sibling_hashes_type &sibling_hashes) {
        m_sibling_hashes = sibling_hashes;
    }

private:
    access_type m_type{0};                               ///< Type of access
    uint64_t m_address{0};                               ///< Address of access
    int m_log2_size{0};                                  ///< Log2 of size of access
    std::optional<access_data> m_read;                   ///< Data before access
    hash_type m_read_hash{};                             ///< Hash of data before access
    std::optional<access_data> m_written;                ///< Written data
    std::optional<hash_type> m_written_hash;             ///< Hash of written data
    std::optional<sibling_hashes_type> m_sibling_hashes; ///< Hashes of siblings in path from address to root
};

/// \brief Log of state accesses
class access_log {
public:
    /// \brief Type of access log
    class type {
        bool m_annotations; ///< Includes annotations
        bool m_large_data;  ///< Includes data bigger than 8 bytes
    public:
        /// \brief Default constructor
        /// \param annotations Include annotations (default false)
        /// \param large_data Include large data (default false)
        explicit type(bool annotations = false, bool large_data = false) :
            m_annotations(annotations),
            m_large_data(large_data) {
            ;
        }
        explicit type(int log_type) :
            m_annotations(static_cast<bool>(log_type & CM_ACCESS_LOG_TYPE_ANNOTATIONS)),
            m_large_data(static_cast<bool>(log_type & CM_ACCESS_LOG_TYPE_LARGE_DATA)) {
            ;
        }

        /// \brief Returns whether log includes annotations
        bool has_annotations() const {
            return m_annotations;
        }

        /// \brief Returns whether log includes data bigger than 8 bytes
        bool has_large_data() const {
            return m_large_data;
        }
    };

private:
    std::vector<access> m_accesses;       ///< List of all accesses
    std::vector<bracket_note> m_brackets; ///< Begin/End annotations
    std::vector<std::string> m_notes;     ///< Per-access annotations
    type m_log_type;                      ///< Log type

public:
    explicit access_log(type log_type) : m_log_type(log_type) {
        ;
    }

    template <typename ACCESSES, typename BRACKETS, typename NOTES>
    access_log(ACCESSES &&accesses, BRACKETS &&brackets, NOTES &&notes, type log_type) :
        m_accesses(std::forward<ACCESSES>(accesses)),
        m_brackets(std::forward<BRACKETS>(brackets)),
        m_notes(std::forward<NOTES>(notes)),
        m_log_type(log_type) {
        ;
    }

    /// \brief Clear the log
    void clear() {
        m_accesses.clear();
        m_notes.clear();
        m_brackets.clear();
    }

    /// \brief Adds a bracket annotation to the log (if the log type includes annotations)
    /// \param type Bracket type
    /// \param text Annotation contents
    void push_bracket(bracket_type type, const char *text) {
        if (m_log_type.has_annotations()) {
            if (type == bracket_type::begin) {
                // make sure we have room for end bracket as well. that way,
                // unless the user use unbalanced brackets, there is no way we
                // would throw an exception for lack of memory on and end bracket
                m_brackets.reserve(m_brackets.size() + 2);
            }
            m_brackets.push_back(bracket_note{.type = type, .where = m_accesses.size(), .text = text});
        }
    }

    /// \brief Adds a new access to the log
    /// \tparam A Type of access
    /// \param a Access object
    /// \param text Annotation contents (added if the log
    /// type includes annotations, ignored otherwise)
    template <typename A>
    void push_access(A &&a, const char *text) {
        m_accesses.push_back(std::forward<A>(a));
        if (m_log_type.has_annotations()) {
            m_notes.emplace_back(text);
        }
    }

    /// \brief Returns the array of notes
    /// \return Constant reference to array
    const std::vector<std::string> &get_notes() const {
        return m_notes;
    }

    /// \brief Returns the array of accesses
    /// \return Constant reference to array
    const std::vector<access> &get_accesses() const {
        return m_accesses;
    }

    /// \brief Returns the array of brackets
    /// \return Constant reference to array
    const std::vector<bracket_note> &get_brackets() const {
        return m_brackets;
    }

    /// \brief Returns the log type
    /// \return Log type
    type get_log_type() const {
        return m_log_type;
    }
};

} // namespace cartesi

#endif
