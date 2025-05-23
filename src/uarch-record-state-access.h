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
#include "i-hasher.h"
#include "i-state-access.h"
#include "i-uarch-state-access.h"
#include "machine-merkle-tree.h"
#include "machine-state.h"
#include "machine.h"
#include "meta.h"
#include "pma.h"
#include "riscv-constants.h"
#include "shadow-uarch-state.h"
#include "strict-aliasing.h"
#include "uarch-bridge.h"
#include "uarch-constants.h"
#include "uarch-pristine-state-hash.h"
#include "uarch-pristine.h"
#include "uarch-state.h"

namespace cartesi {

/// \details The uarch_record_state_access logs all access to the machine state.
class uarch_record_state_access : public i_uarch_state_access<uarch_record_state_access> {
    using hasher_type = machine_merkle_tree::hasher_type;
    using hash_type = machine_merkle_tree::hash_type;

    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    uarch_state &m_us;
    machine &m_m; ///< Macro machine
    machine_state &m_s;
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)
    std::shared_ptr<access_log> m_log; ///< Pointer to access log

    /// \brief Obtain Memory PMA entry that covers a given physical memory region
    /// \param paddr Start of physical memory region.
    /// \param length Length of physical memory region.
    /// \returns Corresponding entry if found, or a sentinel entry
    /// for an empty range.
    pma_entry &find_memory_pma_entry(uint64_t paddr, uint64_t length) {
        // First, search microarchitecture's private PMA entries
        if (m_us.ram.contains(paddr, length)) {
            return m_us.ram;
        }
        int i = 0;
        // Search machine memory PMA entries (not devices or anything else)
        while (true) {
            auto &pma = m_s.pmas[i];
            // The pmas array always contain a sentinel. It is an entry with
            // zero length. If we hit it, return it
            if (pma.get_length() == 0) {
                return pma;
            }
            if (pma.get_istart_M() && pma.contains(paddr, length)) {
                return pma;
            }
            i++;
        }
    }

    static void get_hash(const access_data &data, hash_type &hash) {
        hasher_type hasher;
        get_merkle_tree_hash(hasher, data.data(), data.size(), machine_merkle_tree::get_word_size(), hash);
    }

public:
    /// \brief Constructor from machine and uarch states.
    /// \param um Reference to uarch state.
    /// \param m Reference to machine state.
    explicit uarch_record_state_access(uarch_state &us, machine &m, access_log::type log_type) :
        m_us(us),
        m_m(m),
        m_s(m.get_state()),
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

    /// \brief Adds annotations to the state, bracketing a scope
    class scoped_note {
        std::shared_ptr<access_log> m_log; ///< Pointer to log receiving annotations
        std::string m_text;                ///< String with the text for the annotation

    public:
        /// \brief Constructor adds the "begin" bracketing note
        /// \param log Pointer to access log receiving annotations
        /// \param text Pointer to annotation text
        /// \details A note is added at the moment of construction
        scoped_note(std::shared_ptr<access_log> log, const char *text) : m_log(std::move(log)), m_text(text) {
            if (m_log) {
                m_log->push_bracket(bracket_type::begin, text);
            }
        }

        /// \brief No copy constructors
        scoped_note(const scoped_note &) = delete;

        /// \brief No copy assignment
        scoped_note &operator=(const scoped_note &) = delete;

        /// \brief Default move constructor
        /// \details This is OK because the shared_ptr to log will be
        /// empty afterwards and we explicitly test for this
        /// condition before writing the "end" bracketing note
        scoped_note(scoped_note &&) = default;

        /// \brief Default move assignment
        /// \details This is OK because the shared_ptr to log will be
        /// empty afterwards and we explicitly test for this
        /// condition before writing the "end" bracketing note
        scoped_note &operator=(scoped_note &&) = default;

        /// \brief Destructor adds the "end" bracketing note
        /// if the log shared_ptr is not empty
        ~scoped_note() {
            if (m_log) {
                try {
                    m_log->push_bracket(bracket_type::end, m_text.c_str());
                } catch (...) { // NOLINT(bugprone-empty-catch)
                    // push_bracket with type begin always reserves space for the end bracket
                    // so either the user using unbalanced with begin/end, or there
                    // is no way we ran out of memory. therefore, if we did run out of
                    // memory, it was because the system is completely screwed anyway *and* the
                    // user is using unbalanced brackets. it's ok to quietly ignore, as the user's
                    // brackets were already unbalanced anyway...
                }
            }
        }
    };

private:
    /// \brief Logs a read access of a uint64_t word from the machine state.
    /// \param paligned Physical address in the machine state, aligned to a 64-bit word.
    /// \param val Value read.
    /// \param text Textual description of the access.
    uint64_t log_read(uint64_t paligned, uint64_t val, const char *text) const {
        static_assert(machine_merkle_tree::get_log2_word_size() >= log2_size<uint64_t>::value,
            "Merkle tree word size must be at least as large as a machine word");
        if ((paligned & (sizeof(uint64_t) - 1)) != 0) {
            throw std::invalid_argument{"paligned is not aligned to word size"};
        }
        const uint64_t pleaf_aligned = paligned & ~(machine_merkle_tree::get_word_size() - 1);
        access a;

        // We can skip updating the merkle tree while getting the proof because we assume that:
        // 1) A full merkle tree update was called at the beginning of machine::log_step_uarch()
        // 2) We called update_merkle_tree_page on all write accesses
        const auto proof =
            m_m.get_proof(pleaf_aligned, machine_merkle_tree::get_log2_word_size(), skip_merkle_tree_update);
        // We just store the sibling hashes in the access because this is the only missing piece of data needed to
        // reconstruct the proof
        a.set_sibling_hashes(proof.get_sibling_hashes());

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
        // ensure that the read data is the same as the value read
        const int word_offset = static_cast<int>(paligned - pleaf_aligned); // offset of word in leaf
        const uint64_t logged_val = get_word_access_data(a.get_read().value(), word_offset);
        if (val != logged_val) {
            throw std::runtime_error("read value does not match logged value");
        }
        // NOLINTEND(bugprone-unchecked-optional-access)
        m_log->push_access(std::move(a), text);
        return val;
    }

    /// \brief Logs a write access to a uint64_t word before it happens.
    /// \param paligned Physical address of the word in the machine state (Must be aligned to a 64-bit word).
    /// \param val Value to write.
    /// \param text Textual description of the access.
    void log_before_write(uint64_t paligned, uint64_t word, const char *text) {
        static_assert(machine_merkle_tree::get_log2_word_size() >= log2_size<uint64_t>::value,
            "Merkle tree word size must be at least as large as a machine word");
        if ((paligned & (sizeof(uint64_t) - 1)) != 0) {
            throw std::invalid_argument{"paligned is not aligned to word size"};
        }
        const uint64_t pleaf_aligned = paligned & ~(machine_merkle_tree::get_word_size() - 1);
        access a;

        // We can skip updating the merkle tree while getting the proof because we assume that:
        // 1) A full merkle tree update was called at the beginning of machine::log_step_uarch()
        // 2) We called update_merkle_tree_page on all write accesses
        const auto proof =
            m_m.get_proof(pleaf_aligned, machine_merkle_tree::get_log2_word_size(), skip_merkle_tree_update);
        // We just store the sibling hashes in the access because this is the only missing piece of data needed to
        // reconstruct the proof
        a.set_sibling_hashes(proof.get_sibling_hashes());

        a.set_type(access_type::write);
        a.set_address(paligned);
        a.set_log2_size(log2_size<uint64_t>::value);
        // NOLINTBEGIN(bugprone-unchecked-optional-access)
        // we log the leaf data at pleaf_aligned that contains the word at paligned
        a.get_read().emplace();
        a.get_read().value().resize(machine_merkle_tree::get_word_size());
        m_m.read_memory(pleaf_aligned, a.get_read().value().data(), machine_merkle_tree::get_word_size());
        get_hash(a.get_read().value(), a.get_read_hash());
        // the logged written data is the same as the read data, but with the word at paligned replaced by word
        a.set_written(access_data(a.get_read().value()));                     // copy the read data
        const int word_offset = static_cast<int>(paligned - pleaf_aligned);   // offset of word in leaf
        replace_word_access_data(word, a.get_written().value(), word_offset); // replace the word
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
        [[maybe_unused]] const bool updated = m_m.update_merkle_tree_page(paligned);
        assert(updated);
    }

    /// \brief Logs a write access before it happens, writes, and then update the Merkle tree.
    /// \param paligned Physical address of the word in the machine state (Must be aligned to a 64-bit word).
    /// \param dest Reference to value before writing.
    /// \param val Value to write to \p dest.
    /// \param text Textual description of the access.
    void log_before_write_write_and_update(uint64_t paligned, uint64_t &dest, uint64_t word, const char *text) {
        assert((paligned & (sizeof(uint64_t) - 1)) == 0);
        log_before_write(paligned, word, text);
        dest = word;
        update_after_write(paligned);
    }

    void log_before_write_write_and_update(uint64_t paligned, bool &dest, bool val, const char *text) {
        auto dest64 = static_cast<uint64_t>(dest);
        log_before_write_write_and_update(paligned, dest64, static_cast<uint64_t>(val), text);
        dest = (dest64 != 0);
        update_after_write(paligned);
    }

    // Declare interface as friend to it can forward calls to the "overridden" methods.
    friend i_uarch_state_access<uarch_record_state_access>;

    void do_push_bracket(bracket_type &type, const char *text) {
        m_log->push_bracket(type, text);
    }

    scoped_note do_make_scoped_note(const char *text) {
        return scoped_note{m_log, text};
    }

    uint64_t do_read_x(int reg) const {
        return log_read(machine_reg_address(machine_reg::uarch_x0, reg), m_us.x[reg], "uarch.x");
    }

    void do_write_x(int reg, uint64_t val) {
        assert(reg != 0);
        log_before_write_write_and_update(machine_reg_address(machine_reg::uarch_x0, reg), m_us.x[reg], val, "uarch.x");
    }

    uint64_t do_read_pc() const {
        return log_read(machine_reg_address(machine_reg::uarch_pc), m_us.pc, "uarch.pc");
    }

    void do_write_pc(uint64_t val) {
        log_before_write_write_and_update(machine_reg_address(machine_reg::uarch_pc), m_us.pc, val, "uarch.pc");
    }

    uint64_t do_read_cycle() const {
        return log_read(machine_reg_address(machine_reg::uarch_cycle), m_us.cycle, "uarch.cycle");
    }

    void do_write_cycle(uint64_t val) {
        log_before_write_write_and_update(machine_reg_address(machine_reg::uarch_cycle), m_us.cycle, val,
            "uarch.cycle");
    }

    bool do_read_halt_flag() const {
        return log_read(machine_reg_address(machine_reg::uarch_halt_flag), static_cast<uint64_t>(m_us.halt_flag),
                   "uarch.halt_flag") != 0;
    }

    void do_set_halt_flag() {
        log_before_write_write_and_update(machine_reg_address(machine_reg::uarch_halt_flag), m_us.halt_flag, true,
            "uarch.halt_flag");
    }

    void do_reset_halt_flag() {
        log_before_write_write_and_update(machine_reg_address(machine_reg::uarch_halt_flag), m_us.halt_flag, false,
            "uarch.halt_flag");
    }

    uint64_t do_read_word(uint64_t paddr) {
        assert((paddr & (sizeof(uint64_t) - 1)) == 0);
        // Find a memory range that contains the specified address
        auto &pma = find_memory_pma_entry(paddr, sizeof(uint64_t));
        if (pma.get_istart_E()) {
            // Memory not found. Try reading a machine state register
            return read_register(paddr);
        }
        if (!pma.get_istart_R()) {
            throw std::runtime_error("pma is not readable");
        }
        // Found a readable memory range. Access host memory accordingly.
        const uint64_t hoffset = paddr - pma.get_start();
        auto *hmem = pma.get_memory().get_host_memory();
        auto data = aliased_aligned_read<uint64_t>(hmem + hoffset);
        log_read(paddr, data, "memory");
        return data;
    }

    /// \brief Reads a uint64 machine state register mapped to a memory address
    /// \param paddr Address of the state register
    /// \param data Pointer receiving register value
    uint64_t read_register(uint64_t paddr) {
        auto data = uarch_bridge::read_register(paddr, m_s);
        const auto *name = uarch_bridge::get_register_name(paddr);
        log_read(paddr, data, name);
        return data;
    }

    void do_write_word(uint64_t paddr, uint64_t data) {
        assert((paddr & (sizeof(uint64_t) - 1)) == 0);
        // Find a memory range that contains the specified address
        auto &pma = find_memory_pma_entry(paddr, sizeof(uint64_t));
        if (pma.get_istart_E()) {
            // Memory not found. Try to write a machine state register
            write_register(paddr, data);
            return;
        }
        if (!pma.get_istart_W()) {
            throw std::runtime_error("pma is not writable");
        }
        // Found a writable memory range. Access host memory accordingly.

        // The proof in the log uses the Merkle tree before the state is modified.
        // But log needs the word value before and after the change.
        // So we first get value before the write
        const uint64_t hoffset = paddr - pma.get_start();
        unsigned char *hmem = pma.get_memory().get_host_memory();
        void *hdata = hmem + hoffset;
        // Log the write access
        log_before_write(paddr, data, "memory");
        // Actually modify the state
        aliased_aligned_write<uint64_t>(hdata, data);

        // When proofs are requested, we always want to update the Merkle tree
        update_after_write(paddr);
    }

    /// \brief Writes a uint64 machine state register mapped to a memory address
    /// \param paddr Address of the state register
    /// \param data New register value
    void write_register(uint64_t paddr, uint64_t data) {
        const auto *name = uarch_bridge::get_register_name(paddr);
        log_before_write(paddr, data, name);
        uarch_bridge::write_register(paddr, m_s, data);
        update_after_write(paddr);
    }

    /// \brief Fallback to error on all other word sizes
    template <typename T>
    void write_register(uint64_t /*paddr*/, T /*data*/) {
        throw std::runtime_error("invalid memory write access from microarchitecture");
    }

    void do_reset_state() {
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

        // We just store the sibling hashes in the access because this is the only missing piece of data needed to
        // reconstruct the proof
        a.set_sibling_hashes(proof.get_sibling_hashes());

        a.set_written_hash(get_uarch_pristine_state_hash());

        // Restore uarch to pristine state
        m_us.halt_flag = false;
        m_us.pc = UARCH_PC_INIT;
        m_us.cycle = UARCH_CYCLE_INIT;
        for (int i = 1; i < UARCH_X_REG_COUNT; i++) {
            m_us.x[i] = UARCH_X_INIT;
        }
        m_us.ram.write_memory(m_us.ram.get_start(), uarch_pristine_ram, uarch_pristine_ram_len);
        m_us.ram.fill_memory(m_us.ram.get_start() + uarch_pristine_ram_len, 0,
            m_us.ram.get_length() - uarch_pristine_ram_len);
        if (m_log->get_log_type().has_large_data()) {
            // log written data, if debug info is enabled
            a.get_written().emplace(get_uarch_state_image());
        }
        m_log->push_access(a, "uarch_state");
    }

    /// \brief Returns the image of the entire uarch state
    /// \return access_data containing the image of the current uarch state
    access_data get_uarch_state_image() {
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
