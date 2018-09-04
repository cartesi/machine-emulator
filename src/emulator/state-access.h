#ifndef STATE_ACCESS_H
#define STATE_ACCESS_H

/// \file
/// \brief Fast state access implementation

#include <cassert>

#include "i-state-access.h"
#include "processor-state.h"

/// \class state_access
/// \details The state_access class implements fast, direct
/// access to the machine state. No logs are kept.
class state_access: public i_state_access<state_access> {
private:
    // Declare interface as friend to it can forward calls to the "overriden" methods.
    friend i_state_access<state_access>;

    uint64_t do_read_register(processor_state *s, uint32_t reg) {
        return s->reg[reg];
    }

    void do_write_register(processor_state *s, uint32_t reg, uint64_t val) {
        assert(reg != 0);
        s->reg[reg] = val;
    }

    uint64_t do_read_pc(processor_state *s) {
        return s->pc;
    }

    void do_write_pc(processor_state *s, uint64_t val) {
        s->pc = val;
    }

	uint64_t do_read_minstret(processor_state *s) {
		return s->minstret;
	}

	void do_write_minstret(processor_state *s, uint64_t val) {
		s->minstret = val;
	}

	uint64_t do_read_mcycle(processor_state *s) {
		return s->mcycle;
	}

	void do_write_mcycle(processor_state *s, uint64_t val) {
		s->mcycle = val;
	}

	uint64_t do_read_mstatus(processor_state *s) {
        return s->mstatus;
	}

	void do_write_mstatus(processor_state *s, uint64_t val) {
        s->mstatus = val;
	}

	uint64_t do_read_mtvec(processor_state *s) {
		return s->mtvec;
	}

	void do_write_mtvec(processor_state *s, uint64_t val) {
		s->mtvec = val;
	}

	uint64_t do_read_mscratch(processor_state *s) {
		return s->mscratch;
	}

	void do_write_mscratch(processor_state *s, uint64_t val) {
		s->mscratch = val;
	}

	uint64_t do_read_mepc(processor_state *s) {
		return s->mepc;
	}

	void do_write_mepc(processor_state *s, uint64_t val) {
		s->mepc = val;
	}

	uint64_t do_read_mcause(processor_state *s) {
		return s->mcause;
	}

	void do_write_mcause(processor_state *s, uint64_t val) {
		s->mcause = val;
	}

	uint64_t do_read_mtval(processor_state *s) {
		return s->mtval;
	}

	void do_write_mtval(processor_state *s, uint64_t val) {
		s->mtval = val;
	}

	uint64_t do_read_misa(processor_state *s) {
		return s->misa;
	}

	void do_write_misa(processor_state *s, uint64_t val) {
		s->misa = val;
	}

	uint64_t do_read_mie(processor_state *s) {
		return s->mie;
	}

	void do_write_mie(processor_state *s, uint64_t val) {
		s->mie = val;
	}

	uint64_t do_read_mip(processor_state *s) {
		return s->mip;
	}

	void do_write_mip(processor_state *s, uint64_t val) {
		s->mip = val;
	}

	uint64_t do_read_medeleg(processor_state *s) {
		return s->medeleg;
	}

	void do_write_medeleg(processor_state *s, uint64_t val) {
		s->medeleg = val;
	}

	uint64_t do_read_mideleg(processor_state *s) {
		return s->mideleg;
	}

	void do_write_mideleg(processor_state *s, uint64_t val) {
		s->mideleg = val;
	}

	uint64_t do_read_mcounteren(processor_state *s) {
		return s->mcounteren;
	}

	void do_write_mcounteren(processor_state *s, uint64_t val) {
		s->mcounteren = val;
	}

	uint64_t do_read_stvec(processor_state *s) {
		return s->stvec;
	}

	void do_write_stvec(processor_state *s, uint64_t val) {
		s->stvec = val;
	}

	uint64_t do_read_sscratch(processor_state *s) {
		return s->sscratch;
	}

	void do_write_sscratch(processor_state *s, uint64_t val) {
		s->sscratch = val;
	}

	uint64_t do_read_sepc(processor_state *s) {
		return s->sepc;
	}

	void do_write_sepc(processor_state *s, uint64_t val) {
		s->sepc = val;
	}

	uint64_t do_read_scause(processor_state *s) {
		return s->scause;
	}

	void do_write_scause(processor_state *s, uint64_t val) {
		s->scause = val;
	}

	uint64_t do_read_stval(processor_state *s) {
		return s->stval;
	}

	void do_write_stval(processor_state *s, uint64_t val) {
		s->stval = val;
	}

	uint64_t do_read_satp(processor_state *s) {
		return s->satp;
	}

	void do_write_satp(processor_state *s, uint64_t val) {
		s->satp = val;
	}

	uint64_t do_read_scounteren(processor_state *s) {
		return s->scounteren;
	}

	void do_write_scounteren(processor_state *s, uint64_t val) {
		s->scounteren = val;
	}

	uint64_t do_read_ilrsc(processor_state *s) {
		return s->ilrsc;
	}

	void do_write_ilrsc(processor_state *s, uint64_t val) {
		s->ilrsc = val;
	}

    void do_set_iflags_H(processor_state *s) {
        s->iflags_H = true;
    }

    bool do_read_iflags_H(processor_state *s) {
        return s->iflags_H;
    }

    void do_reset_iflags_I(processor_state *s) {
        s->iflags_H = false;
    }

    bool do_read_iflags_I(processor_state *s) {
        return s->iflags_I;
    }

    uint8_t do_read_iflags_PRV(processor_state *s) {
        return s->iflags_PRV;
    }

    uint64_t do_read_mtimecmp(processor_state *s) {
		return s->mtimecmp;
    }

    void do_write_mtimecmp(processor_state *s, uint64_t val) {
        s->mtimecmp = val;
    }

    uint64_t do_read_fromhost(processor_state *s) {
        return s->fromhost;
    }

    void do_write_fromhost(processor_state *s, uint64_t val) {
        s->fromhost = val;
    }

    uint64_t do_read_tohost(processor_state *s) {
        return s->tohost;
    }

    void do_write_tohost(processor_state *s, uint64_t val) {
        s->tohost = val;
    }
};

#endif
