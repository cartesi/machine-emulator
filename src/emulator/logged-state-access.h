#ifndef LOGGED_STATE_ACCESS_H
#define LOGGED_STATE_ACCESS_H

/// \file
/// \brief State access implementation that logs all accesses

#include <cassert>
#include <string>
#include <memory>

#include "i-state-access.h"
#include "machine-state.h"
#include "shadow.h"
#include "clint.h"
#include "htif.h"
#include "access-log.h"
#include "merkle-tree.h"

/// \class
/// \details The logged_state_access logs all access to the machine state.
class logged_state_access: public i_state_access<logged_state_access> {

    machine_state *m_s; ///< Pointer to machine state
    merkle_tree &m_t;   ///< Merkle tree used for proofs
    std::shared_ptr<access_log> m_log; ///< Pointer to access log

public:

    /// \brief Constructor from machine state and Merkle tree.
    /// \param s Pointer to machine state.
    /// \param t Merkle tree used for proofs.
    logged_state_access(machine_state *s, merkle_tree &t):
        m_s(s),
        m_t(t),
        m_log(std::make_shared<access_log>()) { ; }

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
        std::string m_text; ///< String with the text for the annotation

    public:
        /// \brief Constructor adds the "begin" bracketting note
        /// \param log Pointer to access log receiving annotations
        /// \param text Pointer to annotation text
        /// \details A note is added at the moment of construction
        scoped_note(std::shared_ptr<access_log> log, const char *text):
            m_log(log),
            m_text(text) {
            if (m_log) {
                m_log->annotate(note_type::begin, text);
            }
        }

        // No copy constructors or assignment
        scoped_note(const scoped_note &) = delete;
        scoped_note &operator=(const scoped_note &) = delete;
        // Moves are OK, because the shared_ptr to log will be
        // empty afterwards and we explicitly test for this
        // condition before writing
        scoped_note(scoped_note &&) = default;
        scoped_note &operator=(scoped_note &&) = default;

        /// \brief Destructor adds the "end" bracketting note
        ~scoped_note() {
            if (m_log)
                m_log->annotate(note_type::end, m_text.c_str());
        }
    };

private:

    /// \brief Logs a read access.
    /// \param paligned Physical address in the machine state, aligned to a 64-bit word.
    /// \param val Value read.
    /// \param text Textual description of the access.
    uint64_t log_read(uint64_t paligned, uint64_t val, const char *text) {
        static_assert(merkle_tree::get_log2_word_size() == size_log2<uint64_t>::value,
            "Machine and merkle_tree word sizes must match");
        assert((paligned & (sizeof(uint64_t)-1)) == 0);
        word_access wa;
        bool proven = machine_get_proof(m_s, m_t, paligned, merkle_tree::get_log2_word_size(), wa.proof);
        assert(proven);
        wa.type = access_type::read;
        wa.read = val;
        wa.text = text;
        wa.written = 0;
        m_log->accesses.push_back(wa);
        return val;
    }

    /// \brief Logs a write access before it happens.
    /// \param paligned Physical address of the word in the machine state (Must be aligned to a 64-bit word).
    /// \param dest Value before writing.
    /// \param val Value to write.
    /// \param text Textual description of the access.
    void log_before_write(uint64_t paligned, uint64_t dest, uint64_t val, const char *text) {
        static_assert(merkle_tree::get_log2_word_size() == size_log2<uint64_t>::value,
            "Machine and merkle_tree word sizes must match");
        assert((paligned & (sizeof(uint64_t)-1)) == 0);
        word_access wa;
        bool proven = machine_get_proof(m_s, m_t, paligned, merkle_tree::get_log2_word_size(), wa.proof);
        assert(proven);
        wa.type = access_type::write;
        wa.read = dest;
        wa.written = val;
        wa.text = text;
        m_log->accesses.push_back(wa);
    }

    /// \brief Updates the Merkle tree after the modification of a word in the machine state.
    /// \param paligned Physical address in the machine state, aligned to a 64-bit word.
    void update_after_write(uint64_t paligned) {
        assert((paligned & (sizeof(uint64_t)-1)) == 0);
        bool updated = machine_update_merkle_tree_page(m_s, paligned, m_t);
        assert(updated);
    }

    /// \brief Logs a write access before it happens, writes, and then update the Merkle tree.
    /// \param paligned Physical address of the word in the machine state (Must be aligned to a 64-bit word).
    /// \param dest Reference to value before writing.
    /// \param val Value to write to \p dest.
    /// \param text Textual description of the access.
    void log_before_write_write_and_update(uint64_t paligned, uint64_t &dest, uint64_t val, const char *text) {
        assert((paligned & (sizeof(uint64_t)-1)) == 0);
        log_before_write(paligned, dest, val, text);
        dest = val;
        update_after_write(paligned);
    }

    // Declare interface as friend to it can forward calls to the "overriden" methods.
    friend i_state_access<logged_state_access>;

    void do_annotate(note_type &type, const char *text) {
        m_log->annotate(type, text);
    }

    scoped_note do_make_scoped_note(const char *text) {
        return scoped_note{m_log, text};
    }

    uint64_t do_read_register(int reg) {
        return log_read(m_s->shadow_pma->get_start() + shadow_get_register_rel_addr(reg), m_s->x[reg], "x");
    }

    void do_write_register(int reg, uint64_t val) {
        assert(reg != 0);
        return log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_register_rel_addr(reg), m_s->x[reg], val, "x");
    }

    uint64_t do_read_pc(void) {
        return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::pc), m_s->pc, "pc");
    }

    void do_write_pc(uint64_t val) {
        log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::pc), m_s->pc, val, "pc");
    }

	uint64_t do_read_minstret(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::minstret), m_s->minstret, "minstret");
	}

	void do_write_minstret(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::minstret), m_s->minstret, val, "minstret");
	}

	uint64_t do_read_mvendorid(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mvendorid), m_s->mvendorid, "mvendorid");
	}

	void do_write_mvendorid(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mvendorid), m_s->mvendorid, val, "mvendorid");
	}

	uint64_t do_read_marchid(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::marchid), m_s->marchid, "marchid");
	}

	void do_write_marchid(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::marchid), m_s->marchid, val, "marchid");
	}

	uint64_t do_read_mimpid(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mimpid), m_s->mimpid, "mimpid");
	}

	void do_write_mimpid(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mimpid), m_s->mimpid, val, "mimpid");
	}

	uint64_t do_read_mcycle(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mcycle), m_s->mcycle, "mcycle");
	}

	void do_write_mcycle(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mcycle), m_s->mcycle, val, "mcycle");
	}

	uint64_t do_read_mstatus(void) {
        return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mstatus), m_s->mstatus, "mstatus");
	}

	void do_write_mstatus(uint64_t val) {
        log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mstatus), m_s->mstatus, val, "mstatus");
	}

	uint64_t do_read_mtvec(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mtvec), m_s->mtvec, "mtvec");
	}

	void do_write_mtvec(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mtvec), m_s->mtvec, val, "mtvec");
	}

	uint64_t do_read_mscratch(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mscratch), m_s->mscratch, "mscratch");
	}

	void do_write_mscratch(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mscratch), m_s->mscratch, val, "mscratch");
	}

	uint64_t do_read_mepc(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mepc), m_s->mepc, "mepc");
	}

	void do_write_mepc(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mepc), m_s->mepc, val, "mepc");
	}

	uint64_t do_read_mcause(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mcause), m_s->mcause, "mcause");
	}

	void do_write_mcause(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mcause), m_s->mcause, val, "mcause");
	}

	uint64_t do_read_mtval(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mtval), m_s->mtval, "mtval");
	}

	void do_write_mtval(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mtval), m_s->mtval, val, "mtval");
	}

	uint64_t do_read_misa(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::misa), m_s->misa, "misa");
	}

	void do_write_misa(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::misa), m_s->misa, val, "misa");
	}

	uint64_t do_read_mie(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mie), m_s->mie, "mie");
	}

	void do_write_mie(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mie), m_s->mie, val, "mie");
	}

	uint64_t do_read_mip(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mip), m_s->mip, "mip");
	}

	void do_write_mip(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mip), m_s->mip, val, "mip");
	}

	uint64_t do_read_medeleg(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::medeleg), m_s->medeleg, "medeleg");
	}

	void do_write_medeleg(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::medeleg), m_s->medeleg, val, "medeleg");
	}

	uint64_t do_read_mideleg(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mideleg), m_s->mideleg, "mideleg");
	}

	void do_write_mideleg(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mideleg), m_s->mideleg, val, "mideleg");
	}

	uint64_t do_read_mcounteren(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mcounteren), m_s->mcounteren, "mcounteren");
	}

	void do_write_mcounteren(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::mcounteren), m_s->mcounteren, val, "mcounteren");
	}

	uint64_t do_read_stvec(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::stvec), m_s->stvec, "stvec");
	}

	void do_write_stvec(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::stvec), m_s->stvec, val, "stvec");
	}

	uint64_t do_read_sscratch(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::sscratch), m_s->sscratch, "sscratch");
	}

	void do_write_sscratch(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::sscratch), m_s->sscratch, val, "sscratch");
	}

	uint64_t do_read_sepc(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::sepc), m_s->sepc, "sepc");
	}

	void do_write_sepc(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::sepc), m_s->sepc, val, "sepc");
	}

	uint64_t do_read_scause(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::scause), m_s->scause, "scause");
	}

	void do_write_scause(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::scause), m_s->scause, val, "scause");
	}

	uint64_t do_read_stval(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::stval), m_s->stval, "stval");
	}

	void do_write_stval(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::stval), m_s->stval, val, "stval");
	}

	uint64_t do_read_satp(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::satp), m_s->satp, "satp");
	}

	void do_write_satp(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::satp), m_s->satp, val, "satp");
	}

	uint64_t do_read_scounteren(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::scounteren), m_s->scounteren, "scounteren");
	}

	void do_write_scounteren(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::scounteren), m_s->scounteren, val, "scounteren");
	}

	uint64_t do_read_ilrsc(void) {
		return log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::ilrsc), m_s->ilrsc, "ilrsc");
	}

	void do_write_ilrsc(uint64_t val) {
		log_before_write_write_and_update(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::ilrsc), m_s->ilrsc, val, "ilrsc");
	}

    void do_set_iflags_H(void) {
        // The proof in the log uses the Merkle tree before the state is modified.
        // But log needs the word value before and after the change.
        auto old_iflags = machine_read_iflags(m_s);
        auto new_iflags = machine_encoded_iflags(m_s->iflags_PRV, m_s->iflags_I, true);
        uint64_t iflags_addr = m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::iflags);
        log_before_write(iflags_addr, old_iflags, new_iflags, "iflags_H");
        m_s->iflags_H = true;
        update_after_write(iflags_addr);
    }

    bool do_read_iflags_H(void) {
        log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::iflags), machine_read_iflags(m_s), "iflags_H");
        return m_s->iflags_H;
    }

    void do_set_iflags_I(void) {
        // The proof in the log uses the Merkle tree before the state is modified.
        // But log needs the word value before and after the change.
        auto old_iflags = machine_read_iflags(m_s);
        auto new_iflags = machine_encoded_iflags(m_s->iflags_PRV, true, m_s->iflags_H);
        uint64_t iflags_addr = m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::iflags);
        log_before_write_write_and_update(iflags_addr, old_iflags, new_iflags, "iflags_I");
        m_s->iflags_I = true;
        update_after_write(iflags_addr);
    }

    void do_reset_iflags_I(void) {
        // The proof in the log uses the Merkle tree before the state is modified.
        // But log needs the word value before and after the change.
        auto old_iflags = machine_read_iflags(m_s);
        auto new_iflags = machine_encoded_iflags(m_s->iflags_PRV, false, m_s->iflags_H);
        uint64_t iflags_addr = m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::iflags);
        log_before_write_write_and_update(iflags_addr, old_iflags, new_iflags, "iflags_I");
        m_s->iflags_I = false;
        update_after_write(iflags_addr);
    }

    bool do_read_iflags_I(void) {
        log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::iflags), machine_read_iflags(m_s), "iflags_I");
        return m_s->iflags_I;
    }

    uint8_t do_read_iflags_PRV(void) {
        log_read(m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::iflags), machine_read_iflags(m_s), "iflags_PRV");
        return m_s->iflags_PRV;
    }

    void do_write_iflags_PRV(uint8_t val) {
        // The proof in the log uses the Merkle tree before the state is modified.
        // But log needs the word value before and after the change.
        auto old_iflags = machine_read_iflags(m_s);
        auto new_iflags = machine_encoded_iflags(val, m_s->iflags_I, m_s->iflags_H);
        uint64_t iflags_addr = m_s->shadow_pma->get_start() + shadow_get_csr_rel_addr(shadow_csr::iflags);
        log_before_write_write_and_update(iflags_addr, old_iflags, new_iflags, "iflags_PRV");
        m_s->iflags_PRV = val;
        update_after_write(iflags_addr);
    }

    uint64_t do_read_clint_mtimecmp(void) {
		return log_read(m_s->clint_pma->get_start() + clint_get_csr_rel_addr(clint_csr::mtimecmp), m_s->clint_mtimecmp, "clint_mtimecmp");
    }

    void do_write_clint_mtimecmp(uint64_t val) {
        log_before_write_write_and_update(m_s->clint_pma->get_start() + clint_get_csr_rel_addr(clint_csr::mtimecmp), m_s->clint_mtimecmp, val, "clint_mtimecmp");
    }

    uint64_t do_read_htif_fromhost(void) {
        return log_read(m_s->htif_pma->get_start() + htif::get_csr_rel_addr(htif::csr::fromhost), m_s->htif_fromhost, "htif_fromhost");
    }

    void do_write_htif_fromhost(uint64_t val) {
        log_before_write_write_and_update(m_s->htif_pma->get_start() + htif::get_csr_rel_addr(htif::csr::fromhost), m_s->htif_fromhost, val, "htif_fromhost");
    }

    uint64_t do_read_htif_tohost(void) {
        return log_read(m_s->htif_pma->get_start() + htif::get_csr_rel_addr(htif::csr::tohost), m_s->htif_tohost, "htif_tohost");
    }

    void do_write_htif_tohost(uint64_t val) {
        log_before_write_write_and_update(m_s->htif_pma->get_start() + htif::get_csr_rel_addr(htif::csr::tohost), m_s->htif_tohost, val, "htif_tohost");
    }

    void do_read_pma(const pma_entry &pma, int i) {
        auto istart = pma.get_istart();
        auto ilength = pma.get_ilength();
        auto rel_addr = shadow_get_pma_rel_addr(i);
        log_read(m_s->shadow_pma->get_start() + rel_addr, istart, "pma.istart");
        log_read(m_s->shadow_pma->get_start() + rel_addr + sizeof(uint64_t), ilength, "pma.ilength");
    }

    template <typename T>
    void do_read_memory(uint64_t paddr, uintptr_t haddr, T *val) {
        // Log access to aligned 64-bit word that contains T value
        uintptr_t haligned = haddr & (~(sizeof(uint64_t)-1));
        uint64_t val64 = *reinterpret_cast<uint64_t *>(haligned);
        uint64_t paligned = paddr & (~(sizeof(uint64_t)-1));
        log_read(paligned, val64, "memory");
        *val = *reinterpret_cast<T *>(haddr);
    }

    template <typename T>
    void do_write_memory(uint64_t paddr, uintptr_t haddr, T val) {
        // The proof in the log uses the Merkle tree before the state is modified.
        // But log needs the word value before and after the change.
        // So we get value before the write
        uintptr_t haligned = haddr & (~(sizeof(uint64_t)-1));
        uint64_t old_val64 = *reinterpret_cast<uint64_t *>(haligned);
        // Get the value after the write, leaving no trace of our dirty changes
        T old_val = *reinterpret_cast<T *>(haddr);
        *reinterpret_cast<T *>(haddr) = val;
        uint64_t new_val64 = *reinterpret_cast<uint64_t *>(haligned);
        *reinterpret_cast<T *>(haddr) = old_val;
        // Log the access
        uint64_t paligned = paddr & (~(sizeof(uint64_t)-1));
        log_before_write(paligned, old_val64, new_val64, "memory");
        // Actually modify the state
        *reinterpret_cast<T *>(haddr) = val;
        // Finaly update the Merkle tree
        update_after_write(paligned);
    }

    machine_state *do_get_naked_state(void) {
        return m_s;
    }

    const machine_state *do_get_naked_state(void) const {
        return m_s;
    }

};


/// \brief Type-trait preventing the use of TLB while
/// accessing memory in the state
template <>
struct avoid_tlb<logged_state_access> {
    static constexpr bool value = true;
};


#endif
