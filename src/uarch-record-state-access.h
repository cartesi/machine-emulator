// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef UARCH_RECORD_STATE_ACCESS
#define UARCH_RECORD_STATE_ACCESS

/// \file
/// \brief State access implementation that record and logs all accesses

#include "i-uarch-state-access.h"
#include "machine.h"
#include "uarch-bridge.h"
#include "uarch-constants.h"
#include "uarch-machine.h"

namespace cartesi {

/// \details The uarch_record_state_access logs all access to the machine state.
class uarch_record_state_access : public i_uarch_state_access<uarch_record_state_access> {
    uarch_state &m_us;
    machine &m_m; ///< Macro machine
    machine_state &m_s;
    std::shared_ptr<access_log> m_log; ///< Pointer to access log

    /// \brief Obtain Memory PMA entry that covers a given physical memory region
    /// \param paddr Start of physical memory region.
    /// \param length Length of physical memory region.
    /// \returns Corresponding entry if found, or a sentinel entry
    /// for an empty range.
    pma_entry &find_memory_pma_entry(uint64_t paddr, size_t length) {
        // First, search microarchitecture's private PMA entries
        if (m_us.rom.contains(paddr, length)) {
            return m_us.rom;
        }
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
            if (m_log) {
                m_log->push_bracket(bracket_type::end, m_text.c_str());
            }
        }
    };

private:
    /// \brief Logs a read access.
    /// \param paligned Physical address in the machine state, aligned to a 64-bit word.
    /// \param val Value read.
    /// \param text Textual description of the access.
    uint64_t log_read(uint64_t paligned, uint64_t val, const char *text) const {
        static_assert(machine_merkle_tree::get_log2_word_size() == log2_size<uint64_t>::value,
            "Machine and machine_merkle_tree word sizes must match");
        assert((paligned & (sizeof(uint64_t) - 1)) == 0);
        access a;
        if (m_log->get_log_type().has_proofs()) {
            a.set_proof(m_m.get_proof(paligned, machine_merkle_tree::get_log2_word_size()));
        }
        a.set_type(access_type::read);
        a.set_address(paligned);
        a.set_log2_size(machine_merkle_tree::get_log2_word_size());
        set_word_access_data(val, a.get_read());
        m_log->push_access(std::move(a), text);
        return val;
    }

    /// \brief Logs a write access before it happens.
    /// \param paligned Physical address of the word in the machine state (Must be aligned to a 64-bit word).
    /// \param dest Value before writing.
    /// \param val Value to write.
    /// \param text Textual description of the access.
    void log_before_write(uint64_t paligned, uint64_t dest, uint64_t val, const char *text) {
        static_assert(machine_merkle_tree::get_log2_word_size() == log2_size<uint64_t>::value,
            "Machine and machine_merkle_tree word sizes must match");
        assert((paligned & (sizeof(uint64_t) - 1)) == 0);
        access a;
        if (m_log->get_log_type().has_proofs()) {
            a.set_proof(m_m.get_proof(paligned, machine_merkle_tree::get_log2_word_size()));
        }
        a.set_type(access_type::write);
        a.set_address(paligned);
        a.set_log2_size(machine_merkle_tree::get_log2_word_size());
        set_word_access_data(dest, a.get_read());
        set_word_access_data(val, a.get_written());
        m_log->push_access(std::move(a), text);
    }

    /// \brief Updates the Merkle tree after the modification of a word in the machine state.
    /// \param paligned Physical address in the machine state, aligned to a 64-bit word.
    void update_after_write(uint64_t paligned) {
        assert((paligned & (sizeof(uint64_t) - 1)) == 0);
        if (m_log->get_log_type().has_proofs()) {
            bool updated = m_m.update_merkle_tree_page(paligned);
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
        log_before_write(paligned, dest, val, text);
        dest = val;
        update_after_write(paligned);
    }

    void log_before_write_write_and_update(uint64_t paligned, bool &dest, bool val, const char *text) {
        uint64_t dest64 = dest;
        log_before_write_write_and_update(paligned, dest64, val, text);
        dest = dest64;
    }

    // Declare interface as friend to it can forward calls to the "overriden" methods.
    friend i_uarch_state_access<uarch_record_state_access>;

    void do_push_bracket(bracket_type &type, const char *text) {
        m_log->push_bracket(type, text);
    }

    scoped_note do_make_scoped_note(const char *text) {
        return scoped_note{m_log, text};
    }

    uint64_t do_read_x(int reg) const {
        return log_read(shadow_state_get_uarch_x_abs_addr(reg), m_us.x[reg], "uarch.x");
    }

    void do_write_x(int reg, uint64_t val) {
        assert(reg != 0);
        return log_before_write_write_and_update(shadow_state_get_uarch_x_abs_addr(reg), m_us.x[reg], val, "uarch.x");
    }

    uint64_t do_read_pc() const {
        return log_read(shadow_state_get_csr_abs_addr(shadow_state_csr::uarch_pc), m_us.pc, "uarch.pc");
    }

    void do_write_pc(uint64_t val) {
        return log_before_write_write_and_update(shadow_state_get_csr_abs_addr(shadow_state_csr::uarch_pc), m_us.pc,
            val, "uarch.pc");
    }

    uint64_t do_read_cycle() const {
        return log_read(shadow_state_get_csr_abs_addr(shadow_state_csr::uarch_cycle), m_us.cycle, "uarch.cycle");
    }

    void do_write_cycle(uint64_t val) {
        return log_before_write_write_and_update(shadow_state_get_csr_abs_addr(shadow_state_csr::uarch_cycle),
            m_us.cycle, val, "uarch.cycle");
    }

    template <typename T>
    void do_read_word(uint64_t paddr, T *data) {
        // Find a memory range that contains the specified address
        auto &pma = find_memory_pma_entry(paddr, sizeof(T));
        if (pma.get_istart_E()) {
            // Memory not found. Try reading a machine state register
            return read_register(paddr, data);
        }
        if (!pma.get_istart_R()) {
            throw std::runtime_error("pma is not readable");
        }
        // Found a readable memory range. Access host memory accordingly.

        // Log access to aligned 64-bit word that contains T value
        uint64_t hoffset = paddr - pma.get_start();
        auto hmem = pma.get_memory().get_host_memory();
        uint64_t haligned_offset = hoffset & (~(sizeof(uint64_t) - 1));
        auto data64 = aliased_aligned_read<uint64_t>(hmem + haligned_offset);
        uint64_t paligned = paddr & (~(sizeof(uint64_t) - 1));
        log_read(paligned, data64, "memory");
        *data = aliased_aligned_read<T>(hmem + hoffset);
    }

    /// \brief Reads a uint64 machine state register mapped to a memory address
    /// \param paddr Address of the state register
    /// \param data Pointer receiving register value
    void read_register(uint64_t paddr, uint64_t *data) {
        uarch_bridge::read_register(paddr, m_s, m_us, data);
        auto name = uarch_bridge::get_register_name(paddr);
        log_read(paddr, *data, name);
    }

    /// \brief Fallback to error on all other word sizes
    template <typename T>
    void read_register(uint64_t paddr, T *data) {
        (void) paddr;
        (void) data;
        throw std::runtime_error("invalid memory read access from microarchitecture");
    }

    template <typename T>
    void do_write_word(uint64_t paddr, T data) {
        // Find a memory range that contains the specified address
        auto &pma = find_memory_pma_entry(paddr, sizeof(T));
        if (pma.get_istart_E()) {
            // Memory not found. Try to write a machine state register
            return write_register(paddr, data);
        }
        if (!pma.get_istart_W()) {
            throw std::runtime_error("pma is not writable");
        }
        // Found a writable memory range. Access host memory accordingly.

        // The proof in the log uses the Merkle tree before the state is modified.
        // But log needs the word value before and after the change.
        // So we first get value before the write
        uint64_t hoffset = paddr - pma.get_start();
        uint64_t haligned_offset = hoffset & (~(sizeof(uint64_t) - 1));
        unsigned char *hmem = pma.get_memory().get_host_memory();
        void *hdata64 = hmem + haligned_offset;
        auto old_data64 = aliased_aligned_read<uint64_t>(hdata64);
        // Then the value after the write, leaving no trace of our dirty changes
        void *hdata = hmem + hoffset;
        T old_data = aliased_aligned_read<T>(hdata);
        aliased_aligned_write<T>(hdata, data);
        auto new_data64 = aliased_aligned_read<uint64_t>(hdata64);
        aliased_aligned_write<T>(hdata, old_data);
        // ??D At the moment, the blockchain implementation does not know
        // how to use the old_val64 we already send along with the write
        // access to build the new_val64 when writing at smaller granularities.
        // We therefore log a superfluous read access.
        uint64_t paligned = paddr & (~(sizeof(uint64_t) - 1));
        if (sizeof(T) < sizeof(uint64_t)) {
            log_read(paligned, old_data64, "memory (superfluous)");
        }
        // Log the real write access
        log_before_write(paligned, old_data64, new_data64, "memory");
        // Actually modify the state
        aliased_aligned_write<T>(hdata, data);
        // Finaly update the Merkle tree
        update_after_write(paligned);
    }

    /// \brief Writes a uint64 machine state register mapped to a memory address
    /// \param paddr Address of the state register
    /// \param data New register value
    void write_register(uint64_t paddr, uint64_t data) {
        uint64_t old_data = 0;
        uarch_bridge::read_register(paddr, m_s, m_us, &old_data);
        auto name = uarch_bridge::get_register_name(paddr);
        uarch_bridge::write_register(paddr, m_s, data);
        log_before_write_write_and_update(paddr, old_data, data, name);
    }

    /// \brief Fallback to error on all other word sizes
    template <typename T>
    void write_register(uint64_t paddr, T data) {
        (void) paddr;
        (void) data;
        throw std::runtime_error("invalid memory write access from microarchitecture");
    }
};

} // namespace cartesi

#endif
