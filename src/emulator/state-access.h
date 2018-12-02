#ifndef STATE_ACCESS_H
#define STATE_ACCESS_H

/// \file
/// \brief Fast state access implementation

#include <cassert>

#include "i-state-access.h"
#include "machine.h"

namespace cartesi {

/// \class state_access
/// \details The state_access class implements fast, direct
/// access to the machine state. No logs are kept.
class state_access: public i_state_access<state_access> {

    machine &m_m; ///< Associated machine

public:

    /// \brief Constructor from machine state.
    /// \param s Pointer to machine state.
    state_access(machine &m): m_m(m) { ; }

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

    uint64_t do_read_x(int reg) {
        return m_m.get_state().x[reg];
    }

    void do_write_x(int reg, uint64_t val) {
        assert(reg != 0);
        m_m.get_state().x[reg] = val;
    }

    uint64_t do_read_pc(void) {
        return m_m.get_state().pc;
    }

    void do_write_pc(uint64_t val) {
        m_m.get_state().pc = val;
    }

	uint64_t do_read_minstret(void) {
		return m_m.get_state().minstret;
	}

	void do_write_minstret(uint64_t val) {
		m_m.get_state().minstret = val;
	}

	uint64_t do_read_mvendorid(void) {
		return m_m.get_state().mvendorid;
	}

	void do_write_mvendorid(uint64_t val) {
		m_m.get_state().mvendorid = val;
	}

	uint64_t do_read_marchid(void) {
		return m_m.get_state().marchid;
	}

	void do_write_marchid(uint64_t val) {
		m_m.get_state().marchid = val;
	}

	uint64_t do_read_mimpid(void) {
		return m_m.get_state().mimpid;
	}

	void do_write_mimpid(uint64_t val) {
		m_m.get_state().mimpid = val;
	}

	uint64_t do_read_mcycle(void) {
		return m_m.get_state().mcycle;
	}

	void do_write_mcycle(uint64_t val) {
		m_m.get_state().mcycle = val;
	}

	uint64_t do_read_mstatus(void) {
        return m_m.get_state().mstatus;
	}

	void do_write_mstatus(uint64_t val) {
        m_m.get_state().mstatus = val;
	}

	uint64_t do_read_mtvec(void) {
		return m_m.get_state().mtvec;
	}

	void do_write_mtvec(uint64_t val) {
		m_m.get_state().mtvec = val;
	}

	uint64_t do_read_mscratch(void) {
		return m_m.get_state().mscratch;
	}

	void do_write_mscratch(uint64_t val) {
		m_m.get_state().mscratch = val;
	}

	uint64_t do_read_mepc(void) {
		return m_m.get_state().mepc;
	}

	void do_write_mepc(uint64_t val) {
		m_m.get_state().mepc = val;
	}

	uint64_t do_read_mcause(void) {
		return m_m.get_state().mcause;
	}

	void do_write_mcause(uint64_t val) {
		m_m.get_state().mcause = val;
	}

	uint64_t do_read_mtval(void) {
		return m_m.get_state().mtval;
	}

	void do_write_mtval(uint64_t val) {
		m_m.get_state().mtval = val;
	}

	uint64_t do_read_misa(void) {
		return m_m.get_state().misa;
	}

	void do_write_misa(uint64_t val) {
		m_m.get_state().misa = val;
	}

	uint64_t do_read_mie(void) {
		return m_m.get_state().mie;
	}

	void do_write_mie(uint64_t val) {
		m_m.get_state().mie = val;
	}

	uint64_t do_read_mip(void) {
		return m_m.get_state().mip;
	}

	void do_write_mip(uint64_t val) {
		m_m.get_state().mip = val;
	}

	uint64_t do_read_medeleg(void) {
		return m_m.get_state().medeleg;
	}

	void do_write_medeleg(uint64_t val) {
		m_m.get_state().medeleg = val;
	}

	uint64_t do_read_mideleg(void) {
		return m_m.get_state().mideleg;
	}

	void do_write_mideleg(uint64_t val) {
		m_m.get_state().mideleg = val;
	}

	uint64_t do_read_mcounteren(void) {
		return m_m.get_state().mcounteren;
	}

	void do_write_mcounteren(uint64_t val) {
		m_m.get_state().mcounteren = val;
	}

	uint64_t do_read_stvec(void) {
		return m_m.get_state().stvec;
	}

	void do_write_stvec(uint64_t val) {
		m_m.get_state().stvec = val;
	}

	uint64_t do_read_sscratch(void) {
		return m_m.get_state().sscratch;
	}

	void do_write_sscratch(uint64_t val) {
		m_m.get_state().sscratch = val;
	}

	uint64_t do_read_sepc(void) {
		return m_m.get_state().sepc;
	}

	void do_write_sepc(uint64_t val) {
		m_m.get_state().sepc = val;
	}

	uint64_t do_read_scause(void) {
		return m_m.get_state().scause;
	}

	void do_write_scause(uint64_t val) {
		m_m.get_state().scause = val;
	}

	uint64_t do_read_stval(void) {
		return m_m.get_state().stval;
	}

	void do_write_stval(uint64_t val) {
		m_m.get_state().stval = val;
	}

	uint64_t do_read_satp(void) {
		return m_m.get_state().satp;
	}

	void do_write_satp(uint64_t val) {
		m_m.get_state().satp = val;
	}

	uint64_t do_read_scounteren(void) {
		return m_m.get_state().scounteren;
	}

	void do_write_scounteren(uint64_t val) {
		m_m.get_state().scounteren = val;
	}

	uint64_t do_read_ilrsc(void) {
		return m_m.get_state().ilrsc;
	}

	void do_write_ilrsc(uint64_t val) {
		m_m.get_state().ilrsc = val;
	}

    void do_set_iflags_H(void) {
        m_m.get_state().iflags.H = true;
    }

    bool do_read_iflags_H(void) {
        return m_m.get_state().iflags.H;
    }

    void do_set_iflags_I(void) {
        m_m.get_state().iflags.I = true;
    }

    void do_reset_iflags_I(void) {
        m_m.get_state().iflags.H = false;
    }

    bool do_read_iflags_I(void) {
        return m_m.get_state().iflags.I;
    }

    uint8_t do_read_iflags_PRV(void) {
        return m_m.get_state().iflags.PRV;
    }

    void do_write_iflags_PRV(uint8_t val) {
        m_m.get_state().iflags.PRV = val;
    }

    uint64_t do_read_clint_mtimecmp(void) {
		return m_m.get_state().clint.mtimecmp;
    }

    void do_write_clint_mtimecmp(uint64_t val) {
        m_m.get_state().clint.mtimecmp = val;
    }

    uint64_t do_read_htif_fromhost(void) {
        return m_m.get_state().htif.fromhost;
    }

    void do_write_htif_fromhost(uint64_t val) {
        m_m.get_state().htif.fromhost = val;
    }

    uint64_t do_read_htif_tohost(void) {
        return m_m.get_state().htif.tohost;
    }

    void do_write_htif_tohost(uint64_t val) {
        m_m.get_state().htif.tohost = val;
    }

    void do_read_pma(const pma_entry &pma, int i) {
        (void) i; (void) pma;
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

    machine &do_get_naked_machine(void) {
        return m_m;
    }

    const machine &do_get_naked_machine(void) const {
        return m_m;
    }

};

} // namespace cartesi


#endif
