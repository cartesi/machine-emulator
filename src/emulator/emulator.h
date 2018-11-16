#ifndef EMULATOR_H
#define EMULATOR_H

#include <cstdint>
#include <string>

/// \file
/// \brief Cartesi machine emulator module.

#include "emulator-config.h"

/// \name Cartesi machine identification
/// \{
#define CARTESI_VENDORID UINT64_C(0x6361727465736920) ///< Value of mvendorid
#define CARTESI_ARCHID UINT64_C(1) ///< Value of marchid
#define CARTESI_IMPID UINT64_C(1) ///< Value of mimpid
/// \}

struct emulator;
struct machine_state;
class merkle_tree;

/// \brief Returns VENDORID:ARCHID:IMPID as a string.
/// \returns The identifying string.
/// \details The result of this function is checked against the machine field in the emulator_configuration.
std::string emulator_get_name(void);

/// \brief Creates and returns an emulator configuration with default values.
/// \returns Pointer to newly created emulator configuration.
emulator_config *emulator_config_init(void);

/// \brief Destroys an emulator configuration.
void emulator_config_end(emulator_config *c);

/// \brief Creates and returns an emulator based on a given configuration.
/// \params c Pointer to emulator configuration.
/// \returns Pointer to newly created emulator.
emulator *emulator_init(const emulator_config *c);

/// \brief Destroys an emulator.
/// \params emu Pointer to emulator.
void emulator_end(emulator *emu);

/// \brief Runs an emulator.
/// \params emu Pointer to emulator.
/// \params mcycle_end Limit to mcycle.
/// \details The function returns as soon as mcycle >= mcycle_end, or if the machine is halted before that happens.
void emulator_run(emulator *emu, uint64_t mcycle_end);

/// \brief Returns the machine state within the emulator.
/// \params emu Pointer to emulator.
/// \returns Pointer to machine state.
const machine_state *emulator_get_machine(const emulator *emu);

machine_state *emulator_get_machine(emulator *emu);

/// \brief Returns the Merkle tree within the emulator.
/// \params emu Pointer to emulator.
/// \returns Pointer to Merkle tree.
const merkle_tree *emulator_get_merkle_tree(const emulator *emu);

merkle_tree *emulator_get_merkle_tree(emulator *emu);

/// \brief Verifies the Merkle tree within the emulator.
/// \params emu Pointer to emulator.
/// \returns True if verification passed, false otherwise.
bool emulator_verify_merkle_tree(const emulator *emu);

/// \brief Updates the Merkle tree for the entire machine state.
/// \params emu Pointer to emulator.
/// \returns True if successful, false otherwise.
bool emulator_update_merkle_tree(emulator *emu);

#endif
