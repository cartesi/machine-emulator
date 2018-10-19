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

    machine_state *m_s;

public:

    state_access(machine_state *s): m_s(s) { ; }

private:
    // Declare interface as friend to it can forward calls to the "overriden" methods.
    friend i_state_access<state_access>;

    uint64_t do_read_register(uint32_t reg) {
        return m_s->reg[reg];
    }

    void do_write_register(uint32_t reg, uint64_t val) {
        assert(reg != 0);
        m_s->reg[reg] = val;
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

    uint64_t do_read_mtimecmp(void) {
		return m_s->mtimecmp;
    }

    void do_write_mtimecmp(uint64_t val) {
        m_s->mtimecmp = val;
    }

    uint64_t do_read_fromhost(void) {
        return m_s->fromhost;
    }

    void do_write_fromhost(uint64_t val) {
        m_s->fromhost = val;
    }

    uint64_t do_read_tohost(void) {
        return m_s->tohost;
    }

    void do_write_tohost(uint64_t val) {
        m_s->tohost = val;
    }

    pma_entry *do_read_pma(int i) {
        return &m_s->physical_memory[i];
    }

    void do_read_memory(pma_entry *pma, uint64_t paddr, uint64_t val, int size_log2) {
        (void) pma; (void) paddr; (void) val; (void) size_log2;
    }

    void do_write_memory(pma_entry *pma, uint64_t paddr, uint64_t val, int size_log2) {
        (void) pma; (void) paddr; (void) val; (void) size_log2;
    }

    machine_state *do_naked(void) {
        return m_s;
    }

    const machine_state *do_naked(void) const {
        return m_s;
    }

};

#endif
