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

#ifndef UARCH_RECORD_RESET_STATE_ACCESS
#define UARCH_RECORD_RESET_STATE_ACCESS

/// \file
/// \brief State access implementation that record and logs all accesses

#include "i-uarch-reset-state-access.h"
#include "machine.h"
#include "uarch-constants.h"
#include "uarch-machine.h"
#include "uarch-pristine-state-hash.h"
#include "unique-c-ptr.h"

namespace cartesi {

/// \brief Records a uarch state reset operation into an access log.
/// \details The reset operation is logged as a single write access to the entire uarch memory range.
/// This write access restores all registers and ram to their initial values.
class uarch_record_reset_state_access : public i_uarch_reset_state_access<uarch_record_reset_state_access> {
    using tree_type = machine_merkle_tree;
    using hash_type = tree_type::hash_type;
    using hashertype = tree_type::hasher_type;
    using proof_type = tree_type::proof_type;

    ///< uarch state
    uarch_state &m_us;
    ///< big machine
    machine &m_m;
    ///< Pointer to access log
    std::shared_ptr<access_log> m_log;

public:
    /// \brief Constructor from machine and uarch states.
    /// \param us Reference to uarch state.
    /// \param m Reference to machine.
    /// \param log_type Type of access log to be created.
    explicit uarch_record_reset_state_access(uarch_state &us, machine &m, access_log::type log_type) :
        m_us(us),
        m_m(m),
        m_log(std::make_shared<access_log>(log_type)) {}

    /// \brief No copy constructor
    uarch_record_reset_state_access(const uarch_record_reset_state_access &) = delete;
    /// \brief No copy assignment
    uarch_record_reset_state_access &operator=(const uarch_record_reset_state_access &) = delete;
    /// \brief No move constructor
    uarch_record_reset_state_access(uarch_record_reset_state_access &&) = delete;
    /// \brief No move assignment
    uarch_record_reset_state_access &operator=(uarch_record_reset_state_access &&) = delete;
    /// \brief Default destructor
    ~uarch_record_reset_state_access() = default;

    /// \brief Returns const pointer to access log.
    std::shared_ptr<const access_log> get_log(void) const {
        return m_log;
    }

    /// \brief Returns pointer to access log.
    std::shared_ptr<access_log> get_log(void) {
        return m_log;
    }

    /// \brief Adds annotations to the state, bracketing a scope
    class scoped_note {
        std::shared_ptr<access_log> m_log; ///< Pointer to log receiving annotations
        std::string m_text;                ///< String with the text for the annotation

    public:
        /// \brief Constructor adds the "begin" bracketting note
        /// \param log Pointer to access log receiving annotations
        /// \param text Pointer to annotation text
        /// \details A note is added at the moment of construction
        scoped_note(std::shared_ptr<access_log> log, const char *text) : m_log(std::move(log)), m_text(text) {
            m_log->push_bracket(bracket_type::begin, text);
        }

        /// \brief No copy constructors
        scoped_note(const scoped_note &) = delete;

        /// \brief No copy assignment
        scoped_note &operator=(const scoped_note &) = delete;

        /// \brief Default move constructor
        /// \details This is OK because the shared_ptr to log will be
        /// empty afterwards and we explicitly test for this
        /// condition before writing the "end" bracketting note
        scoped_note(scoped_note &&) = default;

        /// \brief Default move assignment
        /// \details This is OK because the shared_ptr to log will be
        /// empty afterwards and we explicitly test for this
        /// condition before writing the "end" bracketting note
        scoped_note &operator=(scoped_note &&) = default;

        /// \brief Destructor adds the "end" bracketting note
        /// if the log shared_ptr is not empty
        /// NOLINTNEXTLINE(bugprone-exception-escape)
        ~scoped_note() {
            m_log->push_bracket(bracket_type::end, m_text.c_str());
        }
    };

private:
    // Declare interface as friend to it can forward calls to the "overriden" methods.
    friend i_uarch_reset_state_access<uarch_record_reset_state_access>;

    void do_push_bracket(bracket_type &type, const char *text) {
        m_log->push_bracket(type, text);
    }

    scoped_note do_make_scoped_note(const char *text) {
        return scoped_note{m_log, text};
    }

    void do_reset_state(void) {
        // The pristine uarch state decided at compile time and never changes.
        // We set all uarch registers and RAM to their initial values and
        // log a single write access to the entire uarch memory range.
        // This write access does not contain any data, just hashes, unless log_type.large_data is enabled.
        access a;
        a.set_type(access_type::write);
        a.set_address(UARCH_STATE_START_ADDRESS);
        a.set_log2_size(UARCH_STATE_LOG2_SIZE);

        // Always compute the proof, even if we are not logging it, because:
        // (1) we always need to compute read_hash.
        // (2) Depending on the log type, we may also need to compute the proof.
        // (3) proof.target_hash is the  value that we  need for a.read_hash in (1).
        auto proof = m_m.get_proof(UARCH_STATE_START_ADDRESS, UARCH_STATE_LOG2_SIZE);
        a.set_read_hash(proof.get_target_hash());
        if (m_log->get_log_type().has_large_data()) {
            // log read data, if debug info is enabled
            a.get_read().emplace(get_uarch_state_image());
        }
        if (m_log->get_log_type().has_proofs()) {
            a.set_proof(std::move(proof));
        }
        a.set_written_hash(uarch_pristine_state_hash);

        // Restore uarch to pristine state
        m_us.halt_flag = false;
        m_us.pc = UARCH_PC_INIT;
        m_us.cycle = UARCH_CYCLE_INIT;
        for (int i = 1; i < UARCH_X_REG_COUNT; i++) {
            m_us.x[i] = UARCH_X_INIT;
        }
        m_us.ram.fill_memory(m_us.ram.get_start(), 0, m_us.ram.get_length());
        m_us.ram.write_memory(m_us.ram.get_start(), uarch_pristine_ram, uarch_pristine_ram_len);
        if (m_log->get_log_type().has_large_data()) {
            // log written data, if debug info is enabled
            a.get_written().emplace(get_uarch_state_image());
        }
        m_log->push_access(a, "uarch_state");
    }

    /// \brief Returns the image of the entire uarch state
    /// \return access_data containing the image of the current uarch state
    access_data get_uarch_state_image(void) {
        constexpr int uarch_data_len = uint64_t{1} << UARCH_STATE_LOG2_SIZE;
        access_data data(uarch_data_len, 0);
        constexpr auto ram_offset = UARCH_RAM_START_ADDRESS - UARCH_STATE_START_ADDRESS;
        // copy shadow state data
        const unsigned char *page_data = nullptr;
        auto peek = m_us.shadow_state.get_peek();
        if (!peek(m_us.shadow_state, m_m, 0, &page_data, data.data())) {
            throw std::runtime_error{"peek failed"};
        }
        // copy ram data
        memcpy(data.data() + ram_offset, m_us.ram.get_memory().get_host_memory(), m_us.ram.get_length());
        return data;
    }
};

} // namespace cartesi

#endif
