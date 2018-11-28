#ifndef I_STATE_ACCESS_H
#define I_STATE_ACCESS_H

/// \file
/// \brief State access interface

#include <cstdint>
#include <type_traits>

#include "meta.h"

// Forward declarations
class machine;
enum class note_type;

/// \class i_state_access
/// \brief Interface for machine state access.
/// \details \{
/// The final "step" function must log all read and write accesses to the state.
/// The "run" function does not need a log, and must be as fast as possible.
/// Both functions share the exact same implementation of what it means to advance the machine state by one cycle.
/// In this common implementation, all state accesses go through a class that implements the i_state_access interface.
/// When looging is needed, a logged_state_access class is used.
/// When no logging is needed, a state_access class is used.
///
/// In a typical design, i_state_access would be pure virtual.
/// For speed, we avoid virtual methods and instead use templates.
/// State access classes inherit from i_state_access, and declare it as friend.
/// They then implement all private do_* methods.
/// Clients call the methods without the do_ prefix, which are inherited from the i_state_access
/// interface and simply forward the call to the methods with do_ prefix implemented by the derived class.
/// This is a form of "static polymorphism" that incurs no runtime cost
///
/// Methods are provided to read and write each state component.
/// \}
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

    /// \brief Returns associated machine.
    machine &get_naked_machine(void) {
        return derived().do_get_naked_machine();
    }

    /// \brief Returns associated machine for read-only access.
    const machine &get_naked_machine(void) const {
        return derived().do_get_naked_machine();
    }

    /// \brief Returns machine state for direct access.
    machine_state &get_naked_state(void) {
        return get_naked_machine().get_state();
    }

    /// \brief Returns machine state for direct read-only access.
    const machine_state &get_naked_state(void) const {
        return get_naked_machine().get_state();
    }

    /// \brief Adds an annotation to the state
    /// \param note_type Type of note to add
    /// \param text String with the text for the annotation
    void annotate(note_type type, const char *text) {
        return derived().do_annotate(type, text);
    }

    /// \brief Adds annotations to the state, bracketing a scope
    /// \param text String with the text for the annotation
    /// \returns An object that, when constructed and destroyed issues an annonation.
    auto make_scoped_note(const char *text) {
        return derived().do_make_scoped_note(text);
    }

    /// \brief Reads from general-purpose register.
    /// \tparam reg Register index.
    /// \returns Register value.
    uint64_t read_x(int reg) {
        return derived().do_read_x(reg);
    }

    /// \brief Writes register to general-purpose register.
    /// \tparam reg Register index.
    /// \tparam val New register value.
    /// \details Writes to register zero *break* the machine. There is an assertion to catch this, but NDEBUG will let the value pass through.
    void write_x(int reg, uint64_t val) {
        return derived().do_write_x(reg, val);
    }

    /// \brief Reads the program counter.
    /// \returns Register value.
    uint64_t read_pc(void) {
        return derived().do_read_pc();
    }

    /// \brief Writes the program counter.
    /// \param val New register value.
    void write_pc(uint64_t val) {
        return derived().do_write_pc(val);
    }

    /// \brief Reads CSR minstret.
    /// \returns Register value.
	uint64_t read_minstret(void) {
		return derived().do_read_minstret();
	}

    /// \brief Writes CSR minstret.
    /// \param val New register value.
	void write_minstret(uint64_t val) {
		return derived().do_write_minstret(val);
	}

    /// \brief Reads CSR mvendorid.
    /// \returns Register value.
	uint64_t read_mvendorid(void) {
		return derived().do_read_mvendorid();
	}

    /// \brief Writes CSR mvendorid.
    /// \param val New register value.
	void write_mvendorid(uint64_t val) {
		return derived().do_write_mvendorid(val);
	}

    /// \brief Reads CSR marchid.
    /// \returns Register value.
	uint64_t read_marchid(void) {
		return derived().do_read_marchid();
	}

    /// \brief Writes CSR marchid.
    /// \param val New register value.
	void write_marchid(uint64_t val) {
		return derived().do_write_marchid(val);
	}

    /// \brief Reads CSR mimpid.
    /// \returns Register value.
	uint64_t read_mimpid(void) {
		return derived().do_read_mimpid();
	}

    /// \brief Writes CSR mimpid.
    /// \param val New register value.
	void write_mimpid(uint64_t val) {
		return derived().do_write_mimpid(val);
	}

    /// \brief Reads CSR mcycle.
    /// \returns Register value.
	uint64_t read_mcycle(void) {
		return derived().do_read_mcycle();
	}

    /// \brief Writes CSR mcycle.
    /// \param val New register value.
	void write_mcycle(uint64_t val) {
		return derived().do_write_mcycle(val);
	}

    /// \brief Reads CSR mstatus.
    /// \returns Register value.
	uint64_t read_mstatus(void) {
		return derived().do_read_mstatus();
	}

    /// \brief Writes CSR mstatus.
    /// \param val New register value.
	void write_mstatus(uint64_t val) {
		return derived().do_write_mstatus(val);
	}

    /// \brief Reads CSR mtvec.
    /// \returns Register value.
	uint64_t read_mtvec(void) {
		return derived().do_read_mtvec();
	}

    /// \brief Writes CSR mtvec.
    /// \param val New register value.
	void write_mtvec(uint64_t val) {
		return derived().do_write_mtvec(val);
	}

    /// \brief Reads CSR mscratch.
    /// \returns Register value.
	uint64_t read_mscratch(void) {
		return derived().do_read_mscratch();
	}

    /// \brief Writes CSR mscratch.
    /// \param val New register value.
	void write_mscratch(uint64_t val) {
		return derived().do_write_mscratch(val);
	}

    /// \brief Reads CSR mepc.
    /// \returns Register value.
	uint64_t read_mepc(void) {
		return derived().do_read_mepc();
	}

    /// \brief Writes CSR mepc.
    /// \param val New register value.
	void write_mepc(uint64_t val) {
		return derived().do_write_mepc(val);
	}

    /// \brief Reads CSR mcause.
    /// \returns Register value.
	uint64_t read_mcause(void) {
		return derived().do_read_mcause();
	}

    /// \brief Writes CSR mcause.
    /// \param val New register value.
	void write_mcause(uint64_t val) {
		return derived().do_write_mcause(val);
	}

    /// \brief Reads CSR mtval.
    /// \returns Register value.
	uint64_t read_mtval(void) {
		return derived().do_read_mtval();
	}

    /// \brief Writes CSR mtval.
    /// \param val New register value.
	void write_mtval(uint64_t val) {
		return derived().do_write_mtval(val);
	}

    /// \brief Reads CSR misa.
    /// \returns Register value.
	uint64_t read_misa(void) {
		return derived().do_read_misa();
	}

    /// \brief Writes CSR misa.
    /// \param val New register value.
	void write_misa(uint64_t val) {
		return derived().do_write_misa(val);
	}

    /// \brief Reads CSR mie.
    /// \returns Register value.
	uint64_t read_mie(void) {
		return derived().do_read_mie();
	}

    /// \brief Writes CSR mie.
    /// \param val New register value.
	void write_mie(uint64_t val) {
		return derived().do_write_mie(val);
	}

    /// \brief Reads CSR mip.
    /// \returns Register value.
	uint64_t read_mip(void) {
		return derived().do_read_mip();
	}

    /// \brief Writes CSR mip.
    /// \param val New register value.
	void write_mip(uint64_t val) {
		return derived().do_write_mip(val);
	}

    /// \brief Reads CSR medeleg.
    /// \returns Register value.
	uint64_t read_medeleg(void) {
		return derived().do_read_medeleg();
	}

    /// \brief Writes CSR medeleg.
    /// \param val New register value.
	void write_medeleg(uint64_t val) {
		return derived().do_write_medeleg(val);
	}

    /// \brief Reads CSR mideleg.
    /// \returns Register value.
	uint64_t read_mideleg(void) {
		return derived().do_read_mideleg();
	}

    /// \brief Writes CSR mideleg.
    /// \param val New register value.
	void write_mideleg(uint64_t val) {
		return derived().do_write_mideleg(val);
	}

    /// \brief Reads CSR mcounteren.
    /// \returns Register value.
	uint64_t read_mcounteren(void) {
		return derived().do_read_mcounteren();
	}

    /// \brief Writes CSR mcounteren.
    /// \param val New register value.
	void write_mcounteren(uint64_t val) {
		return derived().do_write_mcounteren(val);
	}

    /// \brief Reads CSR stvec.
    /// \returns Register value.
	uint64_t read_stvec(void) {
		return derived().do_read_stvec();
	}

    /// \brief Writes CSR stvec.
    /// \param val New register value.
	void write_stvec(uint64_t val) {
		return derived().do_write_stvec(val);
	}

    /// \brief Reads CSR sscratch.
    /// \returns Register value.
	uint64_t read_sscratch(void) {
		return derived().do_read_sscratch();
	}

    /// \brief Writes CSR sscratch.
    /// \param val New register value.
	void write_sscratch(uint64_t val) {
		return derived().do_write_sscratch(val);
	}

    /// \brief Reads CSR sepc.
    /// \returns Register value.
	uint64_t read_sepc(void) {
		return derived().do_read_sepc();
	}

    /// \brief Writes CSR sepc.
    /// \param val New register value.
	void write_sepc(uint64_t val) {
		return derived().do_write_sepc(val);
	}

    /// \brief Reads CSR scause.
    /// \returns Register value.
	uint64_t read_scause(void) {
		return derived().do_read_scause();
	}

    /// \brief Writes CSR scause.
    /// \param val New register value.
	void write_scause(uint64_t val) {
		return derived().do_write_scause(val);
	}

    /// \brief Reads CSR stval.
    /// \returns Register value.
	uint64_t read_stval(void) {
		return derived().do_read_stval();
	}

    /// \brief Writes CSR stval.
    /// \param val New register value.
	void write_stval(uint64_t val) {
		return derived().do_write_stval(val);
	}

    /// \brief Reads CSR satp.
    /// \returns Register value.
	uint64_t read_satp(void) {
		return derived().do_read_satp();
	}

    /// \brief Writes CSR satp.
    /// \param val New register value.
	void write_satp(uint64_t val) {
		return derived().do_write_satp(val);
	}

    /// \brief Reads CSR scounteren.
    /// \returns Register value.
	uint64_t read_scounteren(void) {
		return derived().do_read_scounteren();
	}

    /// \brief Writes CSR scounteren.
    /// \param val New register value.
	void write_scounteren(uint64_t val) {
		return derived().do_write_scounteren(val);
	}

    /// \brief Reads CSR ilrsc.
    /// \returns Register value.
    /// \details This is Cartesi-specific.
	uint64_t read_ilrsc(void) {
		return derived().do_read_ilrsc();
	}

    /// \brief Writes CSR ilrsc.
    /// \param val New register value.
    /// \details This is Cartesi-specific.
	void write_ilrsc(uint64_t val) {
		return derived().do_write_ilrsc(val);
	}

    /// \brief Sets the iflags_H flag.
    /// \details This is Cartesi-specific.
    void set_iflags_H(void) {
        return derived().do_set_iflags_H();
    }

    /// \brief Reads the iflags_H flag.
    /// \returns The flag value.
    /// \details This is Cartesi-specific.
    bool read_iflags_H(void) {
        return derived().do_read_iflags_H();
    }

    /// \brief Sets the iflags_I flag.
    /// \details This is Cartesi-specific.
    void set_iflags_I(void) {
        return derived().do_set_iflags_I();
    }

    /// \brief Resets the iflags_I flag.
    /// \details This is Cartesi-specific.
    void reset_iflags_I(void) {
        return derived().do_reset_iflags_I();
    }

    /// \brief Reads the iflags_I flag.
    /// \returns The flag value.
    /// \details This is Cartesi-specific.
    bool read_iflags_I(void) {
        return derived().do_read_iflags_I();
    }

    /// \brief Reads the current privilege mode from iflags_PRV.
    /// \details This is Cartesi-specific.
    /// \returns Current privilege mode.
    uint8_t read_iflags_PRV(void) {
        return derived().do_read_iflags_PRV();
    }

    /// \brief Changes the privilege mode in iflags_PRV.
    /// \details This is Cartesi-specific.
    void write_iflags_PRV(uint8_t val) {
        return derived().do_write_iflags_PRV(val);
    }

    /// \brief Reads CLINT's mtimecmp.
    /// \returns Register value.
	uint64_t read_clint_mtimecmp(void) {
		return derived().do_read_clint_mtimecmp();
	}

    /// \brief Writes CLINT's mtimecmp.
    /// \param val New register value.
	void write_clint_mtimecmp(uint64_t val) {
		return derived().do_write_clint_mtimecmp(val);
	}

    /// \brief Reads HTIF's fromhost.
    /// \returns Register value.
	uint64_t read_htif_fromhost(void) {
		return derived().do_read_htif_fromhost();
	}

    /// \brief Writes HTIF's fromhost.
    /// \param val New register value.
	void write_htif_fromhost(uint64_t val) {
		return derived().do_write_htif_fromhost(val);
	}

    /// \brief Reads HTIF's tohost.
    /// \returns Register value.
	uint64_t read_htif_tohost(void) {
		return derived().do_read_htif_tohost();
	}

    /// \brief Writes HTIF's tohost.
    /// \param val New register value.
	void write_htif_tohost(uint64_t val) {
		return derived().do_write_htif_tohost(val);
	}

    /// \brief Reads PMA at a given index.
    /// \param pma PMA entry.
    /// \param i Index of PMA index.
    void read_pma(const pma_entry &pma, int i) {
        return derived().do_read_pma(pma, i);
    }

    /// \brief Read from memory.
    /// \tparam T Type of word to read.
    /// \param paddr Target physical address.
    /// \param haddr Corresponding host address.
    /// \returns Value read.
    template <typename T>
    void read_memory(uint64_t paddr, uintptr_t haddr, T *val) {
        static_assert(std::is_integral<T>::value && sizeof(T) <= sizeof(uint64_t), "unsupported type");
        return derived().template do_read_memory<T>(paddr, haddr, val);
    }

    /// \brief Write to memory.
    /// \tparam T Type of word to write.
    /// \param paddr Target physical address.
    /// \param haddr Corresponding host address.
    /// \param val Value to be written.
    template <typename T>
    void write_memory(uint64_t paddr, uintptr_t haddr, T val) {
        static_assert(std::is_integral<T>::value && sizeof(T) <= sizeof(uint64_t), "unsupported type");
        return derived().template do_write_memory<T>(paddr, haddr, val);
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
