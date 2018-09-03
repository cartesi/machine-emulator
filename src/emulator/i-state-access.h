#ifndef I_STATE_ACCESS_H
#define I_STATE_ACCESS_H

template <typename DERIVED> class i_state_access {

    DERIVED &derived(void) {
        return *static_cast<DERIVED *>(this);
    }

    const DERIVED &derived(void) const {
        return *static_cast<const DERIVED *>(this);
    }

public:

    uint64_t read_register(processor_state *s, uint32_t reg) {
        return derived().do_read_register(s, reg);
    }

    void write_register(processor_state *s, uint32_t reg, uint64_t val) {
        return derived().do_write_register(s, reg, val);
    }

    uint64_t read_pc(processor_state *s) {
        return derived().do_read_pc(s);
    }

    void write_pc(processor_state *s, uint64_t val) {
        return derived().do_write_pc(s, val);
    }

	uint64_t read_minstret(processor_state *s) {
		return derived().do_read_minstret(s);
	}

	void write_minstret(processor_state *s, uint64_t val) {
		return derived().do_write_minstret(s, val);
	}

	uint64_t read_mcycle(processor_state *s) {
		return derived().do_read_mcycle(s);
	}

	void write_mcycle(processor_state *s, uint64_t val) {
		return derived().do_write_mcycle(s, val);
	}

	uint64_t read_mstatus(processor_state *s) {
		return derived().do_read_mstatus(s);
	}

	void write_mstatus(processor_state *s, uint64_t val) {
		return derived().do_write_mstatus(s, val);
	}

	uint64_t read_mtvec(processor_state *s) {
		return derived().do_read_mtvec(s);
	}

	void write_mtvec(processor_state *s, uint64_t val) {
		return derived().do_write_mtvec(s, val);
	}

	uint64_t read_mscratch(processor_state *s) {
		return derived().do_read_mscratch(s);
	}

	void write_mscratch(processor_state *s, uint64_t val) {
		return derived().do_write_mscratch(s, val);
	}

	uint64_t read_mepc(processor_state *s) {
		return derived().do_read_mepc(s);
	}

	void write_mepc(processor_state *s, uint64_t val) {
		return derived().do_write_mepc(s, val);
	}

	uint64_t read_mcause(processor_state *s) {
		return derived().do_read_mcause(s);
	}

	void write_mcause(processor_state *s, uint64_t val) {
		return derived().do_write_mcause(s, val);
	}

	uint64_t read_mtval(processor_state *s) {
		return derived().do_read_mtval(s);
	}

	void write_mtval(processor_state *s, uint64_t val) {
		return derived().do_write_mtval(s, val);
	}

	uint64_t read_misa(processor_state *s) {
		return derived().do_read_misa(s);
	}

	void write_misa(processor_state *s, uint64_t val) {
		return derived().do_write_misa(s, val);
	}

	uint64_t read_mie(processor_state *s) {
		return derived().do_read_mie(s);
	}

	void write_mie(processor_state *s, uint64_t val) {
		return derived().do_write_mie(s, val);
	}

	uint64_t read_mip(processor_state *s) {
		return derived().do_read_mip(s);
	}

	void write_mip(processor_state *s, uint64_t val) {
		return derived().do_write_mip(s, val);
	}

	uint64_t read_medeleg(processor_state *s) {
		return derived().do_read_medeleg(s);
	}

	void write_medeleg(processor_state *s, uint64_t val) {
		return derived().do_write_medeleg(s, val);
	}

	uint64_t read_mideleg(processor_state *s) {
		return derived().do_read_mideleg(s);
	}

	void write_mideleg(processor_state *s, uint64_t val) {
		return derived().do_write_mideleg(s, val);
	}

	uint64_t read_mcounteren(processor_state *s) {
		return derived().do_read_mcounteren(s);
	}

	void write_mcounteren(processor_state *s, uint64_t val) {
		return derived().do_write_mcounteren(s, val);
	}

	uint64_t read_stvec(processor_state *s) {
		return derived().do_read_stvec(s);
	}

	void write_stvec(processor_state *s, uint64_t val) {
		return derived().do_write_stvec(s, val);
	}

	uint64_t read_sscratch(processor_state *s) {
		return derived().do_read_sscratch(s);
	}

	void write_sscratch(processor_state *s, uint64_t val) {
		return derived().do_write_sscratch(s, val);
	}

	uint64_t read_sepc(processor_state *s) {
		return derived().do_read_sepc(s);
	}

	void write_sepc(processor_state *s, uint64_t val) {
		return derived().do_write_sepc(s, val);
	}

	uint64_t read_scause(processor_state *s) {
		return derived().do_read_scause(s);
	}

	void write_scause(processor_state *s, uint64_t val) {
		return derived().do_write_scause(s, val);
	}

	uint64_t read_stval(processor_state *s) {
		return derived().do_read_stval(s);
	}

	void write_stval(processor_state *s, uint64_t val) {
		return derived().do_write_stval(s, val);
	}

	uint64_t read_satp(processor_state *s) {
		return derived().do_read_satp(s);
	}

	void write_satp(processor_state *s, uint64_t val) {
		return derived().do_write_satp(s, val);
	}

	uint64_t read_scounteren(processor_state *s) {
		return derived().do_read_scounteren(s);
	}

	void write_scounteren(processor_state *s, uint64_t val) {
		return derived().do_write_scounteren(s, val);
	}

	uint64_t read_ilrsc(processor_state *s) {
		return derived().do_read_ilrsc(s);
	}

	void write_ilrsc(processor_state *s, uint64_t val) {
		return derived().do_write_ilrsc(s, val);
	}

    void set_iflags_H(processor_state *s) {
        return derived().do_set_iflags_H(s);
    }

    void reset_iflags_I(processor_state *s) {
        return derived().do_reset_iflags_I(s);
    }

	uint64_t read_mtimecmp(processor_state *s) {
		return derived().do_read_mtimecmp(s);
	}

	void write_mtimecmp(processor_state *s, uint64_t val) {
		return derived().do_write_mtimecmp(s, val);
	}

	uint64_t read_fromhost(processor_state *s) {
		return derived().do_read_fromhost(s);
	}

	void write_fromhost(processor_state *s, uint64_t val) {
		return derived().do_write_fromhost(s, val);
	}

	uint64_t read_tohost(processor_state *s) {
		return derived().do_read_tohost(s);
	}

	void write_tohost(processor_state *s, uint64_t val) {
		return derived().do_write_tohost(s, val);
	}

};

#endif
