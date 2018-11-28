#ifndef EMULATOR_H
#define EMULATOR_H

#include <cstdint>
#include <string>

/// \file
/// \brief Cartesi machine emulator module.

#include "emulator-config.h"
#include "htif.h"
#include "machine.h"
#include "merkle-tree.h"

/// \name Cartesi machine identification
/// \{
#define CARTESI_VENDORID UINT64_C(0x6361727465736920) ///< Value of mvendorid
#define CARTESI_ARCHID UINT64_C(1) ///< Value of marchid
#define CARTESI_IMPID UINT64_C(1) ///< Value of mimpid
/// \}

// Temporary automatic pointers until we move to storing
// these classes as members rather than pointers
namespace detail {

    struct machine_state_deleter {
        void operator()(machine_state *s) const {
			machine_end(s);
        }
    };

	using unique_machine_state_ptr = std::unique_ptr<machine_state,
		machine_state_deleter>;
}

class emulator final {
    //??D There really is no need to store these as pointers
    //    as soon as they are proper objects
    detail::unique_machine_state_ptr m_machine;

    htif m_htif;

    merkle_tree m_tree;

public:

    /// \brief Constructs an emulator from a given configuration.
    /// \params c Configuration.
    emulator(const emulator_config &c);

    /// \brief Destroys an emulator.
    ~emulator();

    /// \brief Returns VENDORID:ARCHID:IMPID as a string.
    /// \returns The identifying string.
    /// \details The result of this function is checked against the machine field in the emulator_configuration.
    static std::string get_name(void);

    /// \brief Runs the emulator.
    /// \params mcycle_end Limit to mcycle.
    /// \details The function returns as soon as mcycle >= mcycle_end, or if the machine is halted before that happens.
    void run(uint64_t mcycle_end);

    /// \brief Returns the machine state within the emulator.
    /// \returns Pointer to machine state.
    const machine_state *get_machine(void) const;
    machine_state *get_machine(void);

    /// \brief Returns the Merkle tree within the emulator.
    /// \returns Merkle tree.
    const merkle_tree &get_merkle_tree(void) const;
    merkle_tree &get_merkle_tree(void);

    /// \brief Verifies the Merkle tree within the emulator.
    /// \returns True if verification passed, false otherwise.
    bool verify_merkle_tree(void);

    /// \brief Updates the Merkle tree for the entire machine state.
    /// \returns True if successful, false otherwise.
    bool update_merkle_tree(void);

    //??D No move or copy construction or assignment yet
    emulator(const emulator &) = delete;
    emulator& operator=(const emulator &) = delete;
    emulator(emulator &&) = delete;
    emulator& operator=(emulator &&) = delete;
};

#endif
