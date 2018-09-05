#ifndef I_STATE_ACCESS_H
#define I_STATE_ACCESS_H

/// \file
/// \brief State access interface

#include <cstdint>

#include "meta.h"

/// \class i_state_access
/// \details The final "step" function must log all read and write accesses to the state.
/// The "run" function does not need a log, and must be as fast as possible.
/// Both functions share the exact same implementation of what it means to advance the machine state by one cycle.
/// In this common implementation, all state accesses go through a class that implements the i_state_access interface.
/// When looging is needed, a logged_state_access class is used.
/// When no logging is needed, a state_access class is used.
//
/// In a typical design, i_state_access would be pure virtual.
/// For speed, we avoid virtual methods and instead use templates.
/// State access classes inherit from i_state_access, and declare it as friend.
/// They then implement all private do_* methods.
/// Clients call the methods without the do_ prefix, which are inherited from the i_state_access
/// interface and simply forward the call to the methods with do_ prefix implemented by the derived class.
/// This is a form of "static polymorphism" that incurs no runtime cost
///
/// Methods are provided to read and write each state component.
///
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
template <typename DERIVED> class i_state_access { // CRTP

    /// \brief Returns object cast as the derived class
    DERIVED &derived(void) {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
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

    bool read_iflags_H(processor_state *s) {
        return derived().do_read_iflags_H(s);
    }

    void reset_iflags_I(processor_state *s) {
        return derived().do_reset_iflags_I(s);
    }

    bool read_iflags_I(processor_state *s) {
        return derived().do_read_iflags_I(s);
    }

    uint8_t read_iflags_PRV(processor_state *s) {
        return derived().do_read_iflags_PRV(s);
    }

    void write_iflags_PRV(processor_state *s, uint8_t val) {
        return derived().do_write_iflags_PRV(s, val);
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

/// \brief SFINAE test implementation of the i_state_access interface
template <typename DERIVED>
using is_an_i_state_access = std::integral_constant<
    bool,
    is_template_base_of<
        i_state_access,
        typename remove_cvref<DERIVED>::type
    >::value>;

#endif
