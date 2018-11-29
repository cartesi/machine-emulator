#ifndef EMULATOR_H
#define EMULATOR_H

#include <cstdint>
#include <string>

/// \file
/// \brief Cartesi machine emulator module.

#include "machine-config.h"
#include "htif.h"
#include "machine.h"
#include "merkle-tree.h"

class emulator final {

    machine m_machine;

public:

    /// \brief Constructs an emulator from a given configuration.
    /// \params c Configuration.
    emulator(const machine_config &c);

    /// \brief Destroys an emulator.
    ~emulator();

    /// \brief Returns VENDORID:ARCHID:IMPID as a string.
    /// \returns The identifying string.
    /// \details The result of this function is checked against the machine field in the machine_configuration.
    static std::string get_name(void);

    /// \brief Runs the emulator.
    /// \params mcycle_end Limit to mcycle.
    /// \details The function returns as soon as mcycle >= mcycle_end, or if the machine is halted before that happens.
    void run(uint64_t mcycle_end);

    /// \brief Returns the machine state within the emulator.
    /// \returns Pointer to machine state.
    /// \{
    const machine &get_machine(void) const;
    machine &get_machine(void);
    /// \}

    /// \brief Verifies the Merkle tree within the emulator.
    /// \returns True if verification passed, false otherwise.
    bool verify_merkle_tree(void);

    /// \brief Updates the Merkle tree for the entire machine state.
    /// \returns True if successful, false otherwise.
    bool update_merkle_tree(void);

    /// \brief No copy constructor
    emulator(const emulator &) = delete;
    /// \brief No copy assignment
    emulator& operator=(const emulator &) = delete;
    /// \brief No move constructor
    emulator(emulator &&) = delete;
    /// \brief No move assignment
    emulator& operator=(emulator &&) = delete;
};

#endif
