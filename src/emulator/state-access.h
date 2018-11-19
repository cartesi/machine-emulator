#ifndef STATE_ACCESS_H
#define STATE_ACCESS_H

/// \file
/// \brief Fast state access implementation

#include <cassert>

#include "i-state-access.h"
#include "machine-state.h"

/// \class state_access
/// \details The state_access class implements fast, direct
/// access to the machine state. No logs are kept.
class state_access: public i_state_access<state_access> {

    machine_state *m_s; ///< Pointer to machine state

public:

    /// \brief Constructor from machine state.
    /// \param s Pointer to machine state.
    state_access(machine_state *s): m_s(s) { ; }

private:
    // Declare interface as friend to it can forward calls to the "overriden" methods.
    friend i_state_access<state_access>;

    void do_annotate(note_type type, const char *text) {
        (void) type; (void) text;
    }

    int do_make_scoped_note(const char *text) {
        (void) text;
        return 0;
    }

    uint64_t do_read_register(int reg) {
        return m_s->x[reg];
    }

    void do_write_register(int reg, uint64_t val) {
        assert(reg != 0);
        m_s->x[reg] = val;
    }

    uint64_t do_read_pc(void) {
        return m_s->pc;
    }

    void do_write_pc(uint64_t val) {
        m_s->pc = val;
    }

	uint64_t do_read_minstret(void) {
		return m_s->minstret;
	}

	void do_write_minstret(uint64_t val) {
		m_s->minstret = val;
	}

	uint64_t do_read_mvendorid(void) {
		return m_s->mvendorid;
	}

	void do_write_mvendorid(uint64_t val) {
		m_s->mvendorid = val;
	}

	uint64_t do_read_marchid(void) {
		return m_s->marchid;
	}

	void do_write_marchid(uint64_t val) {
		m_s->marchid = val;
	}

	uint64_t do_read_mimpid(void) {
		return m_s->mimpid;
	}

	void do_write_mimpid(uint64_t val) {
		m_s->mimpid = val;
	}

	uint64_t do_read_mcycle(void) {
		return m_s->mcycle;
	}

	void do_write_mcycle(uint64_t val) {
		m_s->mcycle = val;
	}

	uint64_t do_read_mstatus(void) {
        return m_s->mstatus;
	}

	void do_write_mstatus(uint64_t val) {
        m_s->mstatus = val;
	}

	uint64_t do_read_mtvec(void) {
		return m_s->mtvec;
	}

	void do_write_mtvec(uint64_t val) {
		m_s->mtvec = val;
	}

	uint64_t do_read_mscratch(void) {
		return m_s->mscratch;
	}

	void do_write_mscratch(uint64_t val) {
		m_s->mscratch = val;
	}

	uint64_t do_read_mepc(void) {
		return m_s->mepc;
	}

	void do_write_mepc(uint64_t val) {
		m_s->mepc = val;
	}

	uint64_t do_read_mcause(void) {
		return m_s->mcause;
	}

	void do_write_mcause(uint64_t val) {
		m_s->mcause = val;
	}

	uint64_t do_read_mtval(void) {
		return m_s->mtval;
	}

	void do_write_mtval(uint64_t val) {
		m_s->mtval = val;
	}

	uint64_t do_read_misa(void) {
		return m_s->misa;
	}

	void do_write_misa(uint64_t val) {
		m_s->misa = val;
	}

	uint64_t do_read_mie(void) {
		return m_s->mie;
	}

	void do_write_mie(uint64_t val) {
		m_s->mie = val;
	}

	uint64_t do_read_mip(void) {
		return m_s->mip;
	}

	void do_write_mip(uint64_t val) {
		m_s->mip = val;
	}

	uint64_t do_read_medeleg(void) {
		return m_s->medeleg;
	}

	void do_write_medeleg(uint64_t val) {
		m_s->medeleg = val;
	}

	uint64_t do_read_mideleg(void) {
		return m_s->mideleg;
	}

	void do_write_mideleg(uint64_t val) {
		m_s->mideleg = val;
	}

	uint64_t do_read_mcounteren(void) {
		return m_s->mcounteren;
	}

	void do_write_mcounteren(uint64_t val) {
		m_s->mcounteren = val;
	}

	uint64_t do_read_stvec(void) {
		return m_s->stvec;
	}

	void do_write_stvec(uint64_t val) {
		m_s->stvec = val;
	}

	uint64_t do_read_sscratch(void) {
		return m_s->sscratch;
	}

	void do_write_sscratch(uint64_t val) {
		m_s->sscratch = val;
	}

	uint64_t do_read_sepc(void) {
		return m_s->sepc;
	}

	void do_write_sepc(uint64_t val) {
		m_s->sepc = val;
	}

	uint64_t do_read_scause(void) {
		return m_s->scause;
	}

	void do_write_scause(uint64_t val) {
		m_s->scause = val;
	}

	uint64_t do_read_stval(void) {
		return m_s->stval;
	}

	void do_write_stval(uint64_t val) {
		m_s->stval = val;
	}

	uint64_t do_read_satp(void) {
		return m_s->satp;
	}

	void do_write_satp(uint64_t val) {
		m_s->satp = val;
	}

	uint64_t do_read_scounteren(void) {
		return m_s->scounteren;
	}

	void do_write_scounteren(uint64_t val) {
		m_s->scounteren = val;
	}

	uint64_t do_read_ilrsc(void) {
		return m_s->ilrsc;
	}

	void do_write_ilrsc(uint64_t val) {
		m_s->ilrsc = val;
	}

    void do_set_iflags_H(void) {
        m_s->iflags_H = true;
    }

    bool do_read_iflags_H(void) {
        return m_s->iflags_H;
    }

    void do_set_iflags_I(void) {
        m_s->iflags_I = true;
    }

    void do_reset_iflags_I(void) {
        m_s->iflags_H = false;
    }

    bool do_read_iflags_I(void) {
        return m_s->iflags_I;
    }

    uint8_t do_read_iflags_PRV(void) {
        return m_s->iflags_PRV;
    }

    void do_write_iflags_PRV(uint8_t val) {
        m_s->iflags_PRV = val;
    }

    uint64_t do_read_clint_mtimecmp(void) {
		return m_s->clint_mtimecmp;
    }

    void do_write_clint_mtimecmp(uint64_t val) {
        m_s->clint_mtimecmp = val;
    }

    uint64_t do_read_htif_fromhost(void) {
        return m_s->htif_fromhost;
    }

    void do_write_htif_fromhost(uint64_t val) {
        m_s->htif_fromhost = val;
    }

    uint64_t do_read_htif_tohost(void) {
        return m_s->htif_tohost;
    }

    void do_write_htif_tohost(uint64_t val) {
        m_s->htif_tohost = val;
    }

    pma_entry *do_read_pma(int i) {
        return &m_s->pmas[i];
    }

    template <typename T>
    void do_read_memory(uint64_t paddr, uintptr_t haddr, T *val) {
        (void) paddr;
        *val = *reinterpret_cast<T *>(haddr);
    }

    template <typename T>
    void do_write_memory(uint64_t paddr, uintptr_t haddr, T val) {
        (void) paddr;
        *reinterpret_cast<T *>(haddr) = val;
    }

    machine_state *do_get_naked_state(void) {
        return m_s;
    }

    const machine_state *do_get_naked_state(void) const {
        return m_s;
    }

};

#endif
