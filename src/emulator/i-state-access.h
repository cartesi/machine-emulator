#ifndef I_STATE_ACCESS_H
#define I_STATE_ACCESS_H

/// \file
/// \brief State access interface

#include <cstdint>

#include "meta.h"
#include "machine.h"

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

    machine_state *naked(void) {
        return derived().do_naked();
    }

    const machine_state *naked(void) const {
        return derived().do_naked();
    }

    uint64_t read_register(uint32_t reg) {
        return derived().do_read_register(reg);
    }

    void write_register(uint32_t reg, uint64_t val) {
        return derived().do_write_register(reg, val);
    }

    uint64_t read_pc(void) {
        return derived().do_read_pc();
    }

    void write_pc(uint64_t val) {
        return derived().do_write_pc(val);
    }

	uint64_t read_minstret(void) {
		return derived().do_read_minstret();
	}

	void write_minstret(uint64_t val) {
		return derived().do_write_minstret(val);
	}

	uint64_t read_mcycle(void) {
		return derived().do_read_mcycle();
	}

	void write_mcycle(uint64_t val) {
		return derived().do_write_mcycle(val);
	}

	uint64_t read_mstatus(void) {
		return derived().do_read_mstatus();
	}

	void write_mstatus(uint64_t val) {
		return derived().do_write_mstatus(val);
	}

	uint64_t read_mtvec(void) {
		return derived().do_read_mtvec();
	}

	void write_mtvec(uint64_t val) {
		return derived().do_write_mtvec(val);
	}

	uint64_t read_mscratch(void) {
		return derived().do_read_mscratch();
	}

	void write_mscratch(uint64_t val) {
		return derived().do_write_mscratch(val);
	}

	uint64_t read_mepc(void) {
		return derived().do_read_mepc();
	}

	void write_mepc(uint64_t val) {
		return derived().do_write_mepc(val);
	}

	uint64_t read_mcause(void) {
		return derived().do_read_mcause();
	}

	void write_mcause(uint64_t val) {
		return derived().do_write_mcause(val);
	}

	uint64_t read_mtval(void) {
		return derived().do_read_mtval();
	}

	void write_mtval(uint64_t val) {
		return derived().do_write_mtval(val);
	}

	uint64_t read_misa(void) {
		return derived().do_read_misa();
	}

	void write_misa(uint64_t val) {
		return derived().do_write_misa(val);
	}

	uint64_t read_mie(void) {
		return derived().do_read_mie();
	}

	void write_mie(uint64_t val) {
		return derived().do_write_mie(val);
	}

	uint64_t read_mip(void) {
		return derived().do_read_mip();
	}

	void write_mip(uint64_t val) {
		return derived().do_write_mip(val);
	}

	uint64_t read_medeleg(void) {
		return derived().do_read_medeleg();
	}

	void write_medeleg(uint64_t val) {
		return derived().do_write_medeleg(val);
	}

	uint64_t read_mideleg(void) {
		return derived().do_read_mideleg();
	}

	void write_mideleg(uint64_t val) {
		return derived().do_write_mideleg(val);
	}

	uint64_t read_mcounteren(void) {
		return derived().do_read_mcounteren();
	}

	void write_mcounteren(uint64_t val) {
		return derived().do_write_mcounteren(val);
	}

	uint64_t read_stvec(void) {
		return derived().do_read_stvec();
	}

	void write_stvec(uint64_t val) {
		return derived().do_write_stvec(val);
	}

	uint64_t read_sscratch(void) {
		return derived().do_read_sscratch();
	}

	void write_sscratch(uint64_t val) {
		return derived().do_write_sscratch(val);
	}

	uint64_t read_sepc(void) {
		return derived().do_read_sepc();
	}

	void write_sepc(uint64_t val) {
		return derived().do_write_sepc(val);
	}

	uint64_t read_scause(void) {
		return derived().do_read_scause();
	}

	void write_scause(uint64_t val) {
		return derived().do_write_scause(val);
	}

	uint64_t read_stval(void) {
		return derived().do_read_stval();
	}

	void write_stval(uint64_t val) {
		return derived().do_write_stval(val);
	}

	uint64_t read_satp(void) {
		return derived().do_read_satp();
	}

	void write_satp(uint64_t val) {
		return derived().do_write_satp(val);
	}

	uint64_t read_scounteren(void) {
		return derived().do_read_scounteren();
	}

	void write_scounteren(uint64_t val) {
		return derived().do_write_scounteren(val);
	}

	uint64_t read_ilrsc(void) {
		return derived().do_read_ilrsc();
	}

	void write_ilrsc(uint64_t val) {
		return derived().do_write_ilrsc(val);
	}

    void set_iflags_H(void) {
        return derived().do_set_iflags_H();
    }

    bool read_iflags_H(void) {
        return derived().do_read_iflags_H();
    }

    void set_iflags_I(void) {
        return derived().do_set_iflags_I();
    }

    void reset_iflags_I(void) {
        return derived().do_reset_iflags_I();
    }

    bool read_iflags_I(void) {
        return derived().do_read_iflags_I();
    }

    uint8_t read_iflags_PRV(void) {
        return derived().do_read_iflags_PRV();
    }

    void write_iflags_PRV(uint8_t val) {
        return derived().do_write_iflags_PRV(val);
    }

	uint64_t read_mtimecmp(void) {
		return derived().do_read_mtimecmp();
	}

	void write_mtimecmp(uint64_t val) {
		return derived().do_write_mtimecmp(val);
	}

	uint64_t read_fromhost(void) {
		return derived().do_read_fromhost();
	}

	void write_fromhost(uint64_t val) {
		return derived().do_write_fromhost(val);
	}

	uint64_t read_tohost(void) {
		return derived().do_read_tohost();
	}

	void write_tohost(uint64_t val) {
		return derived().do_write_tohost(val);
	}

    pma_entry *read_pma(int i) {
        return derived().do_read_pma(i);
    }

    void read_memory(pma_entry *entry, uint64_t paddr, uint64_t val, int size_log2) {
        return derived().do_write_memory(entry, paddr, val, size_log2);
    }

    void write_memory(pma_entry *entry, uint64_t paddr, uint64_t val, int size_log2) {
        return derived().do_write_memory(entry, paddr, val, size_log2);
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

/// \brief Type-trait selecting the use of TLB while
/// accessing memory in the state
template <typename STATE_ACCESS>
struct avoid_tlb {
    static constexpr bool value = false;
};

#endif
