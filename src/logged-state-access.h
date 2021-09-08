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

#ifndef LOGGED_STATE_ACCESS_H
#define LOGGED_STATE_ACCESS_H

/// \file
/// \brief State access implementation that logs all accesses

#include <cassert>
#include <memory>
#include <string>

#include "access-log.h"
#include "clint.h"
#include "dhd.h"
#include "htif.h"
#include "i-state-access.h"
#include "machine-merkle-tree.h"
#include "machine.h"
#include "pma.h"
#include "shadow.h"
#include "strict-aliasing.h"
#include "unique-c-ptr.h"

namespace cartesi {

/// \details The logged_state_access logs all access to the machine state.
class logged_state_access : public i_state_access<logged_state_access> {

    machine &m_m;                      ///< Machine state
    std::shared_ptr<access_log> m_log; ///< Pointer to access log

public:
    /// \brief Constructor from machine state.
    /// \param m Reference to machine state.
    logged_state_access(machine &m, access_log::type log_type) : m_m(m), m_log(std::make_shared<access_log>(log_type)) {
        ;
    }

    /// \brief No copy constructor
    logged_state_access(const logged_state_access &) = delete;
    /// \brief No move constructor
    logged_state_access(logged_state_access &&) = delete;
    /// \brief No copy assignment
    logged_state_access &operator=(const logged_state_access &) = delete;
    /// \brief No move assignment
    logged_state_access &operator=(logged_state_access &&) = delete;
    /// \brief Default destructor
    ~logged_state_access() = default;

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

    // Declare interface as friend to it can forward calls to the "overriden" methods.
    friend i_state_access<logged_state_access>;

    const machine_state &do_get_naked_state(void) const {
        return m_m.get_state();
    }

    machine_state &do_get_naked_state(void) {
        return m_m.get_state();
    }

    void do_push_bracket(bracket_type &type, const char *text) {
        m_log->push_bracket(type, text);
    }

    scoped_note do_make_scoped_note(const char *text) {
        return scoped_note{m_log, text};
    }

    uint64_t do_read_x(int reg) const {
        return log_read(PMA_SHADOW_START + shadow_get_x_rel_addr(reg), m_m.get_state().x[reg], "x");
    }

    void do_write_x(int reg, uint64_t val) {
        assert(reg != 0);
        return log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_x_rel_addr(reg), m_m.get_state().x[reg],
            val, "x");
    }

    uint64_t do_read_pc(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::pc), m_m.get_state().pc, "pc");
    }

    void do_write_pc(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::pc),
            m_m.get_state().pc, val, "pc");
    }

    uint64_t do_read_minstret(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::minstret), m_m.get_state().minstret,
            "minstret");
    }

    void do_write_minstret(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::minstret),
            m_m.get_state().minstret, val, "minstret");
    }

    uint64_t do_read_mvendorid(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mvendorid), MVENDORID_INIT, "mvendorid");
    }

    uint64_t do_read_marchid(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::marchid), MARCHID_INIT, "marchid");
    }

    uint64_t do_read_mimpid(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mimpid), MIMPID_INIT, "mimpid");
    }

    uint64_t do_read_mcycle(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mcycle), m_m.get_state().mcycle,
            "mcycle");
    }

    void do_write_mcycle(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mcycle),
            m_m.get_state().mcycle, val, "mcycle");
    }

    uint64_t do_read_mstatus(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mstatus), m_m.get_state().mstatus,
            "mstatus");
    }

    void do_write_mstatus(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mstatus),
            m_m.get_state().mstatus, val, "mstatus");
    }

    uint64_t do_read_mtvec(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mtvec), m_m.get_state().mtvec, "mtvec");
    }

    void do_write_mtvec(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mtvec),
            m_m.get_state().mtvec, val, "mtvec");
    }

    uint64_t do_read_mscratch(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mscratch), m_m.get_state().mscratch,
            "mscratch");
    }

    void do_write_mscratch(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mscratch),
            m_m.get_state().mscratch, val, "mscratch");
    }

    uint64_t do_read_mepc(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mepc), m_m.get_state().mepc, "mepc");
    }

    void do_write_mepc(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mepc),
            m_m.get_state().mepc, val, "mepc");
    }

    uint64_t do_read_mcause(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mcause), m_m.get_state().mcause,
            "mcause");
    }

    void do_write_mcause(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mcause),
            m_m.get_state().mcause, val, "mcause");
    }

    uint64_t do_read_mtval(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mtval), m_m.get_state().mtval, "mtval");
    }

    void do_write_mtval(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mtval),
            m_m.get_state().mtval, val, "mtval");
    }

    uint64_t do_read_misa(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::misa), m_m.get_state().misa, "misa");
    }

    void do_write_misa(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::misa),
            m_m.get_state().misa, val, "misa");
    }

    uint64_t do_read_mie(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mie), m_m.get_state().mie, "mie");
    }

    void do_write_mie(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mie),
            m_m.get_state().mie, val, "mie");
    }

    uint64_t do_read_mip(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mip), m_m.get_state().mip, "mip");
    }

    void do_write_mip(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mip),
            m_m.get_state().mip, val, "mip");
    }

    uint64_t do_read_medeleg(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::medeleg), m_m.get_state().medeleg,
            "medeleg");
    }

    void do_write_medeleg(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::medeleg),
            m_m.get_state().medeleg, val, "medeleg");
    }

    uint64_t do_read_mideleg(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mideleg), m_m.get_state().mideleg,
            "mideleg");
    }

    void do_write_mideleg(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mideleg),
            m_m.get_state().mideleg, val, "mideleg");
    }

    uint64_t do_read_mcounteren(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mcounteren), m_m.get_state().mcounteren,
            "mcounteren");
    }

    void do_write_mcounteren(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::mcounteren),
            m_m.get_state().mcounteren, val, "mcounteren");
    }

    uint64_t do_read_stvec(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::stvec), m_m.get_state().stvec, "stvec");
    }

    void do_write_stvec(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::stvec),
            m_m.get_state().stvec, val, "stvec");
    }

    uint64_t do_read_sscratch(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::sscratch), m_m.get_state().sscratch,
            "sscratch");
    }

    void do_write_sscratch(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::sscratch),
            m_m.get_state().sscratch, val, "sscratch");
    }

    uint64_t do_read_sepc(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::sepc), m_m.get_state().sepc, "sepc");
    }

    void do_write_sepc(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::sepc),
            m_m.get_state().sepc, val, "sepc");
    }

    uint64_t do_read_scause(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::scause), m_m.get_state().scause,
            "scause");
    }

    void do_write_scause(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::scause),
            m_m.get_state().scause, val, "scause");
    }

    uint64_t do_read_stval(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::stval), m_m.get_state().stval, "stval");
    }

    void do_write_stval(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::stval),
            m_m.get_state().stval, val, "stval");
    }

    uint64_t do_read_satp(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::satp), m_m.get_state().satp, "satp");
    }

    void do_write_satp(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::satp),
            m_m.get_state().satp, val, "satp");
    }

    uint64_t do_read_scounteren(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::scounteren), m_m.get_state().scounteren,
            "scounteren");
    }

    void do_write_scounteren(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::scounteren),
            m_m.get_state().scounteren, val, "scounteren");
    }

    uint64_t do_read_ilrsc(void) const {
        return log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::ilrsc), m_m.get_state().ilrsc, "ilrsc");
    }

    void do_write_ilrsc(uint64_t val) {
        log_before_write_write_and_update(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::ilrsc),
            m_m.get_state().ilrsc, val, "ilrsc");
    }

    void do_set_iflags_H(void) {
        // The proof in the log uses the Merkle tree before the state is modified.
        // But log needs the word value before and after the change.
        auto old_iflags = m_m.get_state().read_iflags();
        auto new_iflags = machine_state::packed_iflags(m_m.get_state().iflags.PRV, m_m.get_state().iflags.X, m_m.get_state().iflags.Y, true);
        uint64_t iflags_addr = PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::iflags);
        log_read(iflags_addr, old_iflags, "iflags.H (superfluous)");
        log_before_write(iflags_addr, old_iflags, new_iflags, "iflags.H");
        m_m.get_state().iflags.H = true;
        update_after_write(iflags_addr);
    }

    bool do_read_iflags_H(void) const {
        log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::iflags), m_m.get_state().read_iflags(),
            "iflags.H");
        return m_m.get_state().iflags.H;
    }

    void do_set_iflags_X(void) {
        // The proof in the log uses the Merkle tree before the state is modified.
        // But log needs the word value before and after the change.
        auto old_iflags = m_m.get_state().read_iflags();
        auto new_iflags = machine_state::packed_iflags(m_m.get_state().iflags.PRV, true, m_m.get_state().iflags.Y, m_m.get_state().iflags.H);
        uint64_t iflags_addr = PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::iflags);
        log_read(iflags_addr, old_iflags, "iflags.X (superfluous)");
        log_before_write(iflags_addr, old_iflags, new_iflags, "iflags.X");
        m_m.get_state().iflags.X = true;
        update_after_write(iflags_addr);
    }

    void do_set_iflags_Y(void) {
        // The proof in the log uses the Merkle tree before the state is modified.
        // But log needs the word value before and after the change.
        auto old_iflags = m_m.get_state().read_iflags();
        auto new_iflags = machine_state::packed_iflags(m_m.get_state().iflags.PRV, m_m.get_state().iflags.X, true, m_m.get_state().iflags.H);
        uint64_t iflags_addr = PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::iflags);
        log_read(iflags_addr, old_iflags, "iflags.Y (superfluous)");
        log_before_write(iflags_addr, old_iflags, new_iflags, "iflags.Y");
        m_m.get_state().iflags.Y = true;
        update_after_write(iflags_addr);
    }

    void do_reset_iflags_X(void) {
        // The proof in the log uses the Merkle tree before the state is modified.
        // But log needs the word value before and after the change.
        auto old_iflags = m_m.get_state().read_iflags();
        auto new_iflags = machine_state::packed_iflags(m_m.get_state().iflags.PRV, false, m_m.get_state().iflags.Y, m_m.get_state().iflags.H);
        uint64_t iflags_addr = PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::iflags);
        log_read(iflags_addr, old_iflags, "iflags.X (superfluous)");
        log_before_write(iflags_addr, old_iflags, new_iflags, "iflags.X");
        m_m.get_state().iflags.X = false;
        update_after_write(iflags_addr);
    }

    void do_reset_iflags_Y(void) {
        // The proof in the log uses the Merkle tree before the state is modified.
        // But log needs the word value before and after the change.
        auto old_iflags = m_m.get_state().read_iflags();
        auto new_iflags = machine_state::packed_iflags(m_m.get_state().iflags.PRV, m_m.get_state().iflags.X, false, m_m.get_state().iflags.H);
        uint64_t iflags_addr = PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::iflags);
        log_read(iflags_addr, old_iflags, "iflags.Y (superfluous)");
        log_before_write(iflags_addr, old_iflags, new_iflags, "iflags.Y");
        m_m.get_state().iflags.Y = false;
        update_after_write(iflags_addr);
    }

    bool do_read_iflags_X(void) const {
        log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::iflags), m_m.get_state().read_iflags(),
            "iflags.X");
        return m_m.get_state().iflags.X;
    }

    bool do_read_iflags_Y(void) const {
        log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::iflags), m_m.get_state().read_iflags(),
            "iflags.Y");
        return m_m.get_state().iflags.Y;
    }

    uint8_t do_read_iflags_PRV(void) const {
        log_read(PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::iflags), m_m.get_state().read_iflags(),
            "iflags.PRV");
        return m_m.get_state().iflags.PRV;
    }

    void do_write_iflags_PRV(uint8_t val) {
        // The proof in the log uses the Merkle tree before the state is modified.
        // But log needs the word value before and after the change.
        auto old_iflags = m_m.get_state().read_iflags();
        auto new_iflags = machine_state::packed_iflags(val, m_m.get_state().iflags.X, m_m.get_state().iflags.Y, m_m.get_state().iflags.H);
        uint64_t iflags_addr = PMA_SHADOW_START + shadow_get_csr_rel_addr(shadow_csr::iflags);
        log_read(iflags_addr, old_iflags, "iflags.PRV (superfluous)");
        log_before_write(iflags_addr, old_iflags, new_iflags, "iflags.PRV");
        m_m.get_state().iflags.PRV = val;
        update_after_write(iflags_addr);
    }

    uint64_t do_read_clint_mtimecmp(void) const {
        return log_read(PMA_CLINT_START + clint_get_csr_rel_addr(clint_csr::mtimecmp), m_m.get_state().clint.mtimecmp,
            "clint.mtimecmp");
    }

    void do_write_clint_mtimecmp(uint64_t val) {
        log_before_write_write_and_update(PMA_CLINT_START + clint_get_csr_rel_addr(clint_csr::mtimecmp),
            m_m.get_state().clint.mtimecmp, val, "clint.mtimecmp");
    }

    uint64_t do_read_dhd_tstart(void) const {
        return log_read(PMA_DHD_START + dhd_get_csr_rel_addr(dhd_csr::tstart), m_m.get_state().dhd.tstart,
            "dhd.tstart");
    }

    void do_write_dhd_tstart(uint64_t val) {
        log_before_write_write_and_update(PMA_DHD_START + dhd_get_csr_rel_addr(dhd_csr::tstart),
            m_m.get_state().dhd.tstart, val, "dhd.tstart");
    }

    uint64_t do_read_dhd_tlength(void) const {
        return log_read(PMA_DHD_START + dhd_get_csr_rel_addr(dhd_csr::tlength), m_m.get_state().dhd.tlength,
            "dhd.tlength");
    }

    void do_write_dhd_tlength(uint64_t val) {
        log_before_write_write_and_update(PMA_DHD_START + dhd_get_csr_rel_addr(dhd_csr::tlength),
            m_m.get_state().dhd.tlength, val, "dhd.tlength");
    }

    uint64_t do_read_dhd_dlength(void) const {
        return log_read(PMA_DHD_START + dhd_get_csr_rel_addr(dhd_csr::dlength), m_m.get_state().dhd.dlength,
            "dhd.dlength");
    }

    void do_write_dhd_dlength(uint64_t val) {
        log_before_write_write_and_update(PMA_DHD_START + dhd_get_csr_rel_addr(dhd_csr::dlength),
            m_m.get_state().dhd.dlength, val, "dhd.dlength");
    }

    uint64_t do_read_dhd_hlength(void) const {
        return log_read(PMA_DHD_START + dhd_get_csr_rel_addr(dhd_csr::hlength), m_m.get_state().dhd.hlength,
            "dhd.hlength");
    }

    void do_write_dhd_hlength(uint64_t val) {
        log_before_write_write_and_update(PMA_DHD_START + dhd_get_csr_rel_addr(dhd_csr::hlength),
            m_m.get_state().dhd.hlength, val, "dhd.hlength");
    }

    uint64_t do_read_dhd_h(int i) const {
        return log_read(PMA_DHD_START + dhd_get_h_rel_addr(i), m_m.get_state().dhd.h[i], "dhd.h");
    }

    void do_write_dhd_h(int i, uint64_t val) {
        assert(i != 0);
        return log_before_write_write_and_update(PMA_DHD_START + dhd_get_h_rel_addr(i), m_m.get_state().dhd.h[i], val,
            "dhd.h");
    }

    dhd_data do_dehash(const unsigned char *hash, uint64_t hlength, uint64_t &dlength) {
        // no need to log this
        return m_m.get_state().dehash(hash, hlength, dlength);
    }

    uint64_t do_read_htif_fromhost(void) const {
        return log_read(PMA_HTIF_START + htif::get_csr_rel_addr(htif::csr::fromhost), m_m.get_state().htif.fromhost,
            "htif.fromhost");
    }

    void do_write_htif_fromhost(uint64_t val) {
        log_before_write_write_and_update(PMA_HTIF_START + htif::get_csr_rel_addr(htif::csr::fromhost),
            m_m.get_state().htif.fromhost, val, "htif.fromhost");
    }

    uint64_t do_read_htif_tohost(void) const {
        return log_read(PMA_HTIF_START + htif::get_csr_rel_addr(htif::csr::tohost), m_m.get_state().htif.tohost,
            "htif.tohost");
    }

    void do_write_htif_tohost(uint64_t val) {
        log_before_write_write_and_update(PMA_HTIF_START + htif::get_csr_rel_addr(htif::csr::tohost),
            m_m.get_state().htif.tohost, val, "htif.tohost");
    }

    uint64_t do_read_htif_ihalt(void) const {
        return log_read(PMA_HTIF_START + htif::get_csr_rel_addr(htif::csr::ihalt), m_m.get_state().htif.ihalt,
            "htif.ihalt");
    }

    uint64_t do_read_htif_iconsole(void) const {
        return log_read(PMA_HTIF_START + htif::get_csr_rel_addr(htif::csr::iconsole), m_m.get_state().htif.iconsole,
            "htif.iconsole");
    }

    uint64_t do_read_htif_iyield(void) const {
        return log_read(PMA_HTIF_START + htif::get_csr_rel_addr(htif::csr::iyield), m_m.get_state().htif.iyield,
            "htif.iyield");
    }

    uint64_t do_read_pma_istart(int i) const {
        const auto &pmas = m_m.get_pmas();
        uint64_t istart = 0;
        if (i >= 0 && i < static_cast<int>(pmas.size())) {
            istart = pmas[i].get_istart();
        }
        auto rel_addr = shadow_get_pma_rel_addr(i);
        log_read(PMA_SHADOW_START + rel_addr, istart, "pma.istart");
        return istart;
    }

    uint64_t do_read_pma_ilength(int i) const {
        const auto &pmas = m_m.get_pmas();
        uint64_t ilength = 0;
        if (i >= 0 && i < static_cast<int>(pmas.size())) {
            ilength = pmas[i].get_ilength();
        }
        auto rel_addr = shadow_get_pma_rel_addr(i);
        log_read(PMA_SHADOW_START + rel_addr + sizeof(uint64_t), ilength, "pma.ilength");
        return ilength;
    }

    template <typename T>
    void do_read_memory_word(uint64_t paddr, const unsigned char *hpage, uint64_t hoffset, T *pval) const {
        // Log access to aligned 64-bit word that contains T value
        uint64_t haligned_offset = hoffset & (~(sizeof(uint64_t) - 1));
        auto val64 = aliased_aligned_read<uint64_t>(hpage + haligned_offset);
        uint64_t paligned = paddr & (~(sizeof(uint64_t) - 1));
        log_read(paligned, val64, "memory");
        *pval = aliased_aligned_read<T>(hpage + hoffset);
    }

    template <typename T>
    void do_write_memory_word(uint64_t paddr, unsigned char *hpage, uint64_t hoffset, T val) {
        // The proof in the log uses the Merkle tree before the state is modified.
        // But log needs the word value before and after the change.
        // So we first get value before the write
        uint64_t haligned_offset = hoffset & (~(sizeof(uint64_t) - 1));
        void *hval64 = hpage + haligned_offset;
        auto old_val64 = aliased_aligned_read<uint64_t>(hval64);
        // Then the value after the write, leaving no trace of our dirty changes
        void *hval = hpage + hoffset;
        T old_val = aliased_aligned_read<T>(hval);
        aliased_aligned_write<T>(hval, val);
        auto new_val64 = aliased_aligned_read<uint64_t>(hval64);
        aliased_aligned_write<T>(hval, old_val);
        // ??D At the moment, the blockchain implementation does not know
        // how to use the old_val64 we already send along with the write
        // access to build the new_val64 when writing at smaller granularities.
        // We therefore log a superfluous read access.
        uint64_t paligned = paddr & (~(sizeof(uint64_t) - 1));
        if (sizeof(T) < sizeof(uint64_t)) {
            log_read(paligned, old_val64, "memory (superfluous)");
        }
        // Log the real write access
        log_before_write(paligned, old_val64, new_val64, "memory");
        // Actually modify the state
        aliased_aligned_write<T>(hval, val);
        // Finaly update the Merkle tree
        update_after_write(paligned);
    }

    void do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t log2_size) {
        uint64_t size = UINT64_C(1) << log2_size;
        access a;
        if (m_log->get_log_type().has_proofs()) {
            a.set_proof(m_m.get_proof(paddr, static_cast<int>(log2_size)));
        }
        a.set_type(access_type::write);
        a.set_address(paddr);
        a.set_log2_size(static_cast<int>(log2_size));
        // not very efficient way to get read data...
        a.get_read().resize(size);
        m_m.read_memory(paddr, a.get_read().data(), size);
        // more efficient way of getting written data
        a.get_written().insert(a.get_written().end(), data, data + size);
        m_log->push_access(std::move(a), "memory block");
        m_m.write_memory(paddr, data, size);
        if (m_log->get_log_type().has_proofs()) {
            bool updated = m_m.update_merkle_tree();
            assert(updated);
        }
    }

    template <typename T>
    pma_entry &do_find_pma_entry(uint64_t paddr) {
        auto note = this->make_scoped_note("find_pma_entry");
        (void) note;
        int i = 0;
        while (true) {
            auto &pma = this->get_naked_state().pmas[i];
            auto istart = this->read_pma_istart(i);
            auto ilength = this->read_pma_ilength(i);
            (void) istart;
            (void) ilength;
            // The pmas array always contain a sentinel. It is an entry with
            // zero length. If we hit it, return it
            if (pma.get_length() == 0) {
                return pma;
            }
            // Otherwise, if we found an entry where the access fits, return it
            // Note the "strange" order of arithmetic operations.
            // This is to ensure there is no overflow.
            // Since we know paddr >= start, there is no chance of overflow
            // in the first subtraction.
            // Since length is at least 4096 (an entire page), there is no
            // chance of overflow in the second subtraction.
            if (paddr >= pma.get_start() && paddr - pma.get_start() <= pma.get_length() - sizeof(T)) {
                return pma;
            }
            i++;
        }
    }
};

/// \brief Type-trait preventing the use of TLB while
/// accessing memory in the state
template <>
struct avoid_tlb<logged_state_access> {
    static constexpr bool value = true;
};

} // namespace cartesi

#endif
