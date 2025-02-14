// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

#ifndef CM_MACHINE_C_API_H // NOLINTBEGIN
#define CM_MACHINE_C_API_H

#include "machine-c-version.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// -----------------------------------------------------------------------------
// API definitions
// -----------------------------------------------------------------------------

// Compiler visibility definition
#ifndef CM_API
#define CM_API __attribute__((visibility("default")))
#endif

#define CM_MCYCLE_MAX UINT64_MAX

// -----------------------------------------------------------------------------
// API enums and structures
// -----------------------------------------------------------------------------

/// \brief Constants.
typedef enum cm_constant {
    CM_HASH_SIZE = 32,
    CM_TREE_LOG2_WORD_SIZE = 5,
    CM_TREE_LOG2_PAGE_SIZE = 12,
    CM_TREE_LOG2_ROOT_SIZE = 64,
} cm_constant;

/// \brief Physical memory addresses (only the most useful are exposed in the API).
typedef enum cm_pma_constant {
    CM_PMA_CMIO_RX_BUFFER_START = 0x60000000,
    CM_PMA_CMIO_RX_BUFFER_LOG2_SIZE = 21,
    CM_PMA_CMIO_TX_BUFFER_START = 0x60800000,
    CM_PMA_CMIO_TX_BUFFER_LOG2_SIZE = 21,
    CM_PMA_RAM_START = 0x80000000,
} cm_pma_constant;

/// \brief Error codes returned from the C API.
typedef enum cm_error {
    CM_ERROR_OK = 0,
    CM_ERROR_INVALID_ARGUMENT = -1,
    CM_ERROR_DOMAIN_ERROR = -2,
    CM_ERROR_LENGTH_ERROR = -3,
    CM_ERROR_OUT_OF_RANGE = -4,
    CM_ERROR_LOGIC_ERROR = -5,
    CM_ERROR_RUNTIME_ERROR = -6,
    CM_ERROR_RANGE_ERROR = -7,
    CM_ERROR_OVERFLOW_ERROR = -8,
    CM_ERROR_UNDERFLOW_ERROR = -9,
    CM_ERROR_REGEX_ERROR = -10,
    CM_ERROR_SYSTEM_ERROR = -11,
    CM_ERROR_BAD_TYPEID = -12,
    CM_ERROR_BAD_CAST = -13,
    CM_ERROR_BAD_ANY_CAST = -14,
    CM_ERROR_BAD_OPTIONAL_ACCESS = -15,
    CM_ERROR_BAD_WEAK_PTR = -16,
    CM_ERROR_BAD_FUNCTION_CALL = -17,
    CM_ERROR_BAD_ALLOC = -18,
    CM_ERROR_BAD_ARRAY_NEW_LENGTH = -19,
    CM_ERROR_BAD_EXCEPTION = -20,
    CM_ERROR_BAD_VARIANT_ACCESS = -21,
    CM_ERROR_EXCEPTION = -22,
    CM_ERROR_UNKNOWN = -23,
} cm_error;

/// \brief Reasons for the machine to break from call to cm_run.
typedef enum cm_break_reason {
    CM_BREAK_REASON_FAILED,
    CM_BREAK_REASON_HALTED,
    CM_BREAK_REASON_YIELDED_MANUALLY,
    CM_BREAK_REASON_YIELDED_AUTOMATICALLY,
    CM_BREAK_REASON_YIELDED_SOFTLY,
    CM_BREAK_REASON_REACHED_TARGET_MCYCLE,
} cm_break_reason;

/// \brief Reasons for the machine to break from call to cm_run_uarch.
typedef enum cm_uarch_break_reason {
    CM_UARCH_BREAK_REASON_REACHED_TARGET_CYCLE,
    CM_UARCH_BREAK_REASON_UARCH_HALTED,
    CM_UARCH_BREAK_REASON_FAILED,
} cm_uarch_break_reason;

/// \brief Access log types.
typedef enum cm_access_log_type {
    CM_ACCESS_LOG_TYPE_ANNOTATIONS = 1, ///< Includes annotations
    CM_ACCESS_LOG_TYPE_LARGE_DATA = 2,  ///< Includes data larger than 8 bytes
} cm_access_log_type;

/// \brief Yield device commands.
typedef enum cm_cmio_yield_command {
    CM_CMIO_YIELD_COMMAND_AUTOMATIC,
    CM_CMIO_YIELD_COMMAND_MANUAL,
} cm_cmio_yield_command;

/// \brief Yield reasons.
typedef enum cm_cmio_yield_reason {
    CM_CMIO_YIELD_AUTOMATIC_REASON_PROGRESS = 1,  ///< Progress is available
    CM_CMIO_YIELD_AUTOMATIC_REASON_TX_OUTPUT = 2, ///< Output is available in tx buffer
    CM_CMIO_YIELD_AUTOMATIC_REASON_TX_REPORT = 4, ///< Report is available in tx buffer
    CM_CMIO_YIELD_MANUAL_REASON_RX_ACCEPTED = 1,  ///< Input in rx buffer was accepted
    CM_CMIO_YIELD_MANUAL_REASON_RX_REJECTED = 2,  ///< Input in rx buffer was rejected
    CM_CMIO_YIELD_MANUAL_REASON_TX_EXCEPTION = 4, ///< Exception happened
    CM_CMIO_YIELD_REASON_ADVANCE_STATE = 0,       ///< Input in rx buffer is advance state
    CM_CMIO_YIELD_REASON_INSPECT_STATE = 1,       ///< Input in rx buffer is inspect state
} cm_cmio_yield_reason;

/// \brief Machine x, f, and control and status registers.
typedef enum cm_reg {
    // Processor x registers
    CM_REG_X0,
    CM_REG_X1,
    CM_REG_X2,
    CM_REG_X3,
    CM_REG_X4,
    CM_REG_X5,
    CM_REG_X6,
    CM_REG_X7,
    CM_REG_X8,
    CM_REG_X9,
    CM_REG_X10,
    CM_REG_X11,
    CM_REG_X12,
    CM_REG_X13,
    CM_REG_X14,
    CM_REG_X15,
    CM_REG_X16,
    CM_REG_X17,
    CM_REG_X18,
    CM_REG_X19,
    CM_REG_X20,
    CM_REG_X21,
    CM_REG_X22,
    CM_REG_X23,
    CM_REG_X24,
    CM_REG_X25,
    CM_REG_X26,
    CM_REG_X27,
    CM_REG_X28,
    CM_REG_X29,
    CM_REG_X30,
    CM_REG_X31,
    // Processor f registers
    CM_REG_F0,
    CM_REG_F1,
    CM_REG_F2,
    CM_REG_F3,
    CM_REG_F4,
    CM_REG_F5,
    CM_REG_F6,
    CM_REG_F7,
    CM_REG_F8,
    CM_REG_F9,
    CM_REG_F10,
    CM_REG_F11,
    CM_REG_F12,
    CM_REG_F13,
    CM_REG_F14,
    CM_REG_F15,
    CM_REG_F16,
    CM_REG_F17,
    CM_REG_F18,
    CM_REG_F19,
    CM_REG_F20,
    CM_REG_F21,
    CM_REG_F22,
    CM_REG_F23,
    CM_REG_F24,
    CM_REG_F25,
    CM_REG_F26,
    CM_REG_F27,
    CM_REG_F28,
    CM_REG_F29,
    CM_REG_F30,
    CM_REG_F31,
    // Processor CSRs
    CM_REG_PC,
    CM_REG_FCSR,
    CM_REG_MVENDORID,
    CM_REG_MARCHID,
    CM_REG_MIMPID,
    CM_REG_MCYCLE,
    CM_REG_ICYCLEINSTRET,
    CM_REG_MSTATUS,
    CM_REG_MTVEC,
    CM_REG_MSCRATCH,
    CM_REG_MEPC,
    CM_REG_MCAUSE,
    CM_REG_MTVAL,
    CM_REG_MISA,
    CM_REG_MIE,
    CM_REG_MIP,
    CM_REG_MEDELEG,
    CM_REG_MIDELEG,
    CM_REG_MCOUNTEREN,
    CM_REG_MENVCFG,
    CM_REG_STVEC,
    CM_REG_SSCRATCH,
    CM_REG_SEPC,
    CM_REG_SCAUSE,
    CM_REG_STVAL,
    CM_REG_SATP,
    CM_REG_SCOUNTEREN,
    CM_REG_SENVCFG,
    CM_REG_ILRSC,
    CM_REG_IPRV,
    CM_REG_IFLAGS_X,
    CM_REG_IFLAGS_Y,
    CM_REG_IFLAGS_H,
    CM_REG_IUNREP,
    // Device registers
    CM_REG_CLINT_MTIMECMP,
    CM_REG_PLIC_GIRQPEND,
    CM_REG_PLIC_GIRQSRVD,
    CM_REG_HTIF_TOHOST,
    CM_REG_HTIF_FROMHOST,
    CM_REG_HTIF_IHALT,
    CM_REG_HTIF_ICONSOLE,
    CM_REG_HTIF_IYIELD,
    // Microarchitecture registers
    CM_REG_UARCH_X0,
    CM_REG_UARCH_X1,
    CM_REG_UARCH_X2,
    CM_REG_UARCH_X3,
    CM_REG_UARCH_X4,
    CM_REG_UARCH_X5,
    CM_REG_UARCH_X6,
    CM_REG_UARCH_X7,
    CM_REG_UARCH_X8,
    CM_REG_UARCH_X9,
    CM_REG_UARCH_X10,
    CM_REG_UARCH_X11,
    CM_REG_UARCH_X12,
    CM_REG_UARCH_X13,
    CM_REG_UARCH_X14,
    CM_REG_UARCH_X15,
    CM_REG_UARCH_X16,
    CM_REG_UARCH_X17,
    CM_REG_UARCH_X18,
    CM_REG_UARCH_X19,
    CM_REG_UARCH_X20,
    CM_REG_UARCH_X21,
    CM_REG_UARCH_X22,
    CM_REG_UARCH_X23,
    CM_REG_UARCH_X24,
    CM_REG_UARCH_X25,
    CM_REG_UARCH_X26,
    CM_REG_UARCH_X27,
    CM_REG_UARCH_X28,
    CM_REG_UARCH_X29,
    CM_REG_UARCH_X30,
    CM_REG_UARCH_X31,
    CM_REG_UARCH_PC,
    CM_REG_UARCH_CYCLE,
    CM_REG_UARCH_HALT_FLAG,
    // Views of registers
    CM_REG_HTIF_TOHOST_DEV,
    CM_REG_HTIF_TOHOST_CMD,
    CM_REG_HTIF_TOHOST_REASON,
    CM_REG_HTIF_TOHOST_DATA,
    CM_REG_HTIF_FROMHOST_DEV,
    CM_REG_HTIF_FROMHOST_CMD,
    CM_REG_HTIF_FROMHOST_REASON,
    CM_REG_HTIF_FROMHOST_DATA,
    // Enumeration helpers
    CM_REG_UNKNOWN_,
    CM_REG_FIRST_ = CM_REG_X0,
    CM_REG_LAST_ = CM_REG_UARCH_HALT_FLAG,
} cm_reg;

/// \brief Storage for machine hash.
typedef uint8_t cm_hash[CM_HASH_SIZE];

/// \brief Machine object handle.
/// \details It's used only as an opaque handle to pass machine objects through the C API.
typedef struct cm_machine cm_machine;

// -----------------------------------------------------------------------------
// API functions
// -----------------------------------------------------------------------------

/// \brief Returns the error message set by the very last C API call.
/// \returns A C string, guaranteed to remain valid only until the next CM_API function call.
/// \details The string returned by this function must not be changed nor deallocated, and remains valid until
/// next CM_API function that can return a cm_error code is called.
/// Must be called from the same thread that called the function that produced the error.
/// In case the last CM_API function call on that thread was successful, returns an empty string.
/// \warning Do not use the empty string as an indication that the previous call was successful.
/// This would be error-prone since calls from different threads may see different strings.
/// Instead, use the return code of the previous call itself.
CM_API const char *cm_get_last_error_message();

/// \brief Obtains a JSON object with the default machine config as a string.
/// \param m Pointer to a machine object. Can be NULL (for local machines).
/// \param config Receives the default configuration as a JSON object in a string, guaranteed to remain valid only until
/// the next CM_API function is called from the same thread. Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
/// \details The returned config is not sufficient to run a machine.
/// Additional configurations, such as RAM length, RAM image, flash drives, and entrypoint are still needed.
/// It's unnecessary to base configs on the default config,
/// because unset fields are automatically filled with defaults.
CM_API cm_error cm_get_default_config(const cm_machine *m, const char **config);

/// \brief Gets the address of any x, f, or control state register.
/// \param m Pointer to a machine object. Can be NULL (for local machines).
/// \param reg The register.
/// \param val Receives address of the register.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_get_reg_address(const cm_machine *m, cm_reg reg, uint64_t *val);

// -----------------------------------------------------------------------------
// Machine API functions
// -----------------------------------------------------------------------------

/// \brief Creates a new local machine object.
/// \param new_m Receives the pointer to the new machine object. Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
/// \detail A newly created object is empty (does not hold a machine instance).
/// Use cm_create() or cm_load() to instantiate a machine into the object.
/// Use cm_create_new() or cm_load_new() as single-call shortcuts.
/// Use cm_delete() to delete the object.
CM_API cm_error cm_new(cm_machine **new_m);

/// \brief Clones empty machine object from existing one.
/// \param m Pointer to the existing machine object to clone from.
/// \param new_m Receives the pointer to the new machine object. Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
/// \details The new machine object will be of the same type as \p m.
/// Local if \p m is local, remote on the same host if \p is remote.
/// Regardless, a newly created object is empty (does not hold a machine instance).
/// Use cm_create() or cm_load() to instantiate a machine into the object.
/// Use cm_delete() to delete the object.
CM_API cm_error cm_clone_empty(const cm_machine *m, cm_machine **new_m);

/// \brief Checks if object is empty (does not hold a machine instance).
/// \param m Pointer to the existing machine object.
/// \param yes Receives true if empty, false otherwise.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_is_empty(const cm_machine *m, bool *yes);

/// \brief Deletes a machine object.
/// \param m Pointer to the existing machine object (can be NULL).
/// \details The pointer to the machine object must not be used after this call.
/// \details If the machine object is not empty (has a machine instance),
/// silently calls cm_destroy() to destroy the instance.
CM_API void cm_delete(cm_machine *m);

/// \brief Creates a new machine instance from configuration.
/// \param m Pointer to an empty machine object (does not hold a machine instance).
/// \param config Machine configuration as a JSON object in a string (at least RAM length must be set).
/// An useful config needs at least RAM length and image, a rootfs flash drive image and DTB entrypoint to be set.
/// For example:
/// ```json
/// {
///     "ram": {
///         "length": 134217728,
///         "image_filename": "linux.bin"
///     },
///     "flash_drive": [{
///         "image_filename": "rootfs.ext2"
///     }],
///     "dtb": {
///         "entrypoint": "echo Hello world!"
///     }
/// }
/// ```
/// \param runtime_config Machine runtime configuration as a JSON object in a string (can be NULL).
/// \returns 0 for success, non zero code for error.
/// \details Use cm_destroy() to destroy the machine instance and remove it from the object.
CM_API cm_error cm_create(cm_machine *m, const char *config, const char *runtime_config);

/// \brief Combines cm_new() and cm_create() for convenience.
/// \param config Machine configuration as a JSON object in a string (at least RAM length must be set).
/// \param runtime_config Machine runtime configuration as a JSON object in a string (can be NULL).
/// \param new_m Receives the pointer to the new machine object with a machine instance. Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
/// \details Use cm_destroy() to destroy the machine instance and remove it from the object.
/// \details Use cm_delete() to delete the object.
/// \details See cm_load() and cm_create() for more details.
CM_API cm_error cm_create_new(const char *config, const char *runtime_config, cm_machine **new_m);

/// \brief Loads a new machine instance from a previously stored directory.
/// \param m Pointer to an empty machine object (does not hold a machine instance).
/// \param dir Directory where previous machine is stored.
/// \param runtime_config Machine runtime configuration as a JSON object in a string (can be NULL).
/// \returns 0 for success, non zero code for error.
/// \details Use cm_destroy() to destroy the machine instance and remove it from the object.
CM_API cm_error cm_load(cm_machine *m, const char *dir, const char *runtime_config);

/// \brief Combines cm_new() and cm_load() for convenience.
/// \param dir Directory where previous machine is stored.
/// \param runtime_config Machine runtime configuration as a JSON object in a string (can be NULL).
/// \param new_m Receives the pointer to the new machine object with a machine instance. Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
/// \details Use cm_destroy() to destroy the machine instance and remove it from the object.
/// \details Use cm_delete() to delete the object.
/// \details See cm_load() and cm_create() for more details.
CM_API cm_error cm_load_new(const char *dir, const char *runtime_config, cm_machine **new_m);

/// \brief Stores a machine instance to a directory, serializing its entire state.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param dir Directory where the machine will be stored.
/// \returns 0 for success, non zero code for error.
/// \details The function refuses to store into an existing directory (it will not overwrite an existing machine).
CM_API cm_error cm_store(const cm_machine *m, const char *dir);

/// \brief Destroy a machine instance and remove it from the object.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \returns 0 for success, non zero code for error.
/// \details cm_delete() may fail silently when implicitly calling cm_destroy().
/// To make sure the machine was successfully destroyed, call cm_destroy() explicitly.
/// \details This function does not delete the machine object.
/// You must still call cm_delete() afterwards.
CM_API cm_error cm_destroy(cm_machine *m);

/// \brief Changes the machine runtime configuration.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param runtime_config Machine runtime configuration as a JSON object in a string (can be NULL).
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_set_runtime_config(cm_machine *m, const char *runtime_config);

/// \brief Changes the machine runtime config.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param runtime_config Receives the runtime configuration as a JSON object in a string,
/// guaranteed to remain valid only until the next CM_API function is called from the same thread.
/// Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_get_runtime_config(const cm_machine *m, const char **runtime_config);

/// \brief Replaces a memory range.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param start Range start physical address.
/// \param length Range length in bytes.
/// \param shared[ni] If true, changes to the range from inside the machine will be
/// written to the associated image file in the host.
/// \param image_filename Image file name to load into the range. If NULL, entire
/// range is cleared with zeros.
/// \returns 0 for success, non zero code for error.
/// \details The machine must have been initialized with an existing memory range that
/// has the same start and length specified in the new range.
CM_API cm_error cm_replace_memory_range(cm_machine *m, uint64_t start, uint64_t length, bool shared,
    const char *image_filename);

/// \brief Returns a JSON object with the machine config used to initialize the machine.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param config Receives the initial configuration as a JSON object in a string,
/// guaranteed to remain valid only until the next CM_API function is called from the same thread.
/// Set to NULL on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_get_initial_config(const cm_machine *m, const char **config);

/// \brief Returns a list with all memory ranges in the machine.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param ranges Receives the memory ranges as a JSON object in a string,
/// guaranteed to remain valid only until the next CM_API function is called from the same thread.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_get_memory_ranges(const cm_machine *m, const char **ranges);

/// \brief Obtains the root hash of the Merkle tree.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param hash Valid pointer to cm_hash structure that receives the hash.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_get_root_hash(const cm_machine *m, cm_hash *hash);

/// \brief Obtains the proof for a node in the machine state Merkle tree.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param address Address of target node. Must be aligned to a 2^log2_size boundary.
/// \param log2_size The log base 2 of the size subtended by target node.
/// Must be between CM_TREE_LOG2_WORD_SIZE (for a word) and CM_TREE_LOG2_ROOT_SIZE
/// (for the entire address space), inclusive.
/// \param proof Receives the proof as a JSON object in a string,
/// guaranteed to remain valid only until the next CM_API function is called from the same thread.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_get_proof(const cm_machine *m, uint64_t address, int32_t log2_size, const char **proof);

// ------------------------------------
// Reading and writing
// ------------------------------------

/// \brief Reads the value of a word in the machine state, by its physical address.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param address Word address (aligned to 64-bit boundary).
/// \param val Receives word value.
/// \returns 0 for success, non zero code for error.
/// \warning The implementation is slow when the word falls in a memory range mapped to a device.
CM_API cm_error cm_read_word(const cm_machine *m, uint64_t address, uint64_t *val);

/// \brief Reads the value of a register.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param reg Register to read.
/// \param val Receives the value.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_read_reg(const cm_machine *m, cm_reg reg, uint64_t *val);

/// \brief Writes the value of a register.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param reg Register to write.
/// \param val Value to write.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_write_reg(cm_machine *m, cm_reg reg, uint64_t val);

/// \brief Reads a chunk of data, by its target physical address and length.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param paddr Target physical address to start reading from.
/// \param data Buffer that receives data to read. Must be at least \p length bytes long.
/// \param length Number of bytes to read from \p paddr to \p data.
/// \returns 0 for success, non zero code for error.
/// \details The data can be anywhere in the entire address space.
CM_API cm_error cm_read_memory(const cm_machine *m, uint64_t paddr, uint8_t *data, uint64_t length);

/// \brief Writes a chunk of data to machine memory, by its target physical address and length.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param paddr Target physical address to start writing to.
/// \param data Buffer that contains data to write. Must be at least \p length bytes long.
/// \param length Number of bytes to write starting from \p data to \p paddr.
/// \returns 0 for success, non zero code for error.
/// \details Unlike read_memory(), the entire chunk of data, from \p paddr to \p paddr + \p length,
/// must reside entirely in the same memory range. Moreover, it cannot be mapped to a device.
CM_API cm_error cm_write_memory(cm_machine *m, uint64_t paddr, const uint8_t *data, uint64_t length);

/// \brief Reads a chunk of data from a machine memory range, by its virtual memory.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param address Virtual address to start reading.
/// \param data Receives chunk of memory.
/// \param length Size of chunk in bytes.
/// \returns 0 for success, non zero code for error.
/// \detail The translation is based on the current mapping, as defined in CM_REG_SATP.
CM_API cm_error cm_read_virtual_memory(cm_machine *m, uint64_t address, uint8_t *data, uint64_t length);

/// \brief Writes a chunk of data to a machine memory range, by its virtual address.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param address Virtual address to start writing.
/// \param data Source for chunk of data.
/// \param length Size of chunk in bytes.
/// \returns 0 for success, non zero code for error.
/// \detail The translation is based on the current mapping, as defined in CM_REG_SATP.
CM_API cm_error cm_write_virtual_memory(cm_machine *m, uint64_t address, const uint8_t *data, uint64_t length);

/// \brief Translates a virtual memory address to its corresponding physical memory address.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param vaddr Virtual address to translate.
/// \param paddr Receives the physical memory address.
/// \returns 0 for success, non zero code for error.
/// \detail The translation is based on the current mapping, as defined in CM_REG_SATP.
CM_API cm_error cm_translate_virtual_address(cm_machine *m, uint64_t vaddr, uint64_t *paddr);

// ------------------------------------
// Running
// ------------------------------------

/// \brief Runs the machine until CM_REG_MCYCLE reaches mcycle_end, machine yields, or halts.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param mcycle_end End cycle value.
/// \param break_reason Receives reason for returning (can be NULL). Set to CM_BREAK_REASON_FAILED on failure.
/// \returns 0 for success, non zero code for error.
/// \details You may want to receive cmio requests depending on the run break reason.
CM_API cm_error cm_run(cm_machine *m, uint64_t mcycle_end, cm_break_reason *break_reason);

/// \brief Runs the machine microarchitecture until CM_REG_UARCH_CYCLE reaches uarch_cycle_end or it halts.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param uarch_cycle_end End micro cycle value.
/// \param uarch_break_reason Receives reason for returning (can be NULL).
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_run_uarch(cm_machine *m, uint64_t uarch_cycle_end, cm_uarch_break_reason *uarch_break_reason);

/// \brief Resets the entire microarchitecture state to pristine values.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_reset_uarch(cm_machine *m);

/// \brief Receives a cmio request.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param cmd Receives the yield command (manual or automatic).
/// \param reason Receives the yield reason (see below).
/// \param data Receives the yield data. If NULL, length will still be set without reading any data.
/// \param length Receives the yield data length. Must be initialized to the size of data buffer.
/// \details May fail if machine is not in a valid yield state or data length isn't big enough.
/// In case of an automatic yield with progress reason, length is 4 and data is the per mille progress as an integer.
/// In case of other automatic yields length is variable (up to 2MB) and data is an output or reports.
/// In case of a manual yield with accepted reason, length is 32 and data is filled with the output hashes root hash.
/// In case of a manual yield with rejected reason, length and data can be ignored. Machine state should be reverted.
/// In case of a manual yield with exception reason, data/length point to a message. Machine state is irrecoverable.
/// In case of other manual yields (GIO request), reason is set to the domain, and data/length is filled with an id.
CM_API cm_error cm_receive_cmio_request(const cm_machine *m, uint8_t *cmd, uint16_t *reason, uint8_t *data,
    uint64_t *length);

/// \brief Sends a cmio response.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param reason Reason for sending the response.
/// \param data Response data to send.
/// \param length Length of response data.
/// \returns 0 for success, non zero code for error.
/// \details This method should only be called as a response to cmio requests with manual yield command
/// where the reason is either accepted or a GIO request, may fail otherwise.
CM_API cm_error cm_send_cmio_response(cm_machine *m, uint16_t reason, const uint8_t *data, uint64_t length);

// ------------------------------------
// Logging
// ------------------------------------

/// \brief Runs the machine for the given mcycle count and generates a log of accessed pages and proof data.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param mcycle_count Number of mcycles to run
/// \param log_filename Name of the log file to be generated
/// \param break_reason Receives reason for returning (can be NULL). Set to CM_BREAK_REASON_FAILED on failure.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_log_step(cm_machine *m, uint64_t mcycle_count, const char *log_filename,
    cm_break_reason *break_reason_result);

/// \brief Runs the machine in the microarchitecture for one micro cycle logging all accesses to the state.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param log_type Type of access log to generate.
/// \param log Receives the state access log as a JSON object in a string,
/// guaranteed to remain valid only until the next CM_API function is called from the same thread.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_log_step_uarch(cm_machine *m, int32_t log_type, const char **log);

/// \brief Resets the entire microarchitecture state to pristine values logging all accesses to the state.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param log_type Type of access log to generate.
/// \param log Receives the state access log as a JSON object in a string,
/// guaranteed to remain valid only until the next CM_API function is called from the same thread.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_log_reset_uarch(cm_machine *m, int32_t log_type, const char **log);

/// \brief Sends a cmio response logging all accesses to the state.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param reason Reason for sending the response.
/// \param data Response data to send.
/// \param length Length of response data.
/// \param log_type Type of access log to generate.
/// \param log Receives the state access log as a JSON object in a string,
/// guaranteed to remain valid only until the next CM_API function is called from the same thread.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_log_send_cmio_response(cm_machine *m, uint16_t reason, const uint8_t *data, uint64_t length,
    int32_t log_type, const char **log);

// ------------------------------------
// Verifying
// ------------------------------------

/// \brief Checks the validity of a step log file.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param root_hash_before State hash before step
/// \param log_filename Path to the step log file to be verified
/// \param mcycle_count Number of mcycles in the step
/// \param root_hash_after State hash after step
/// \param break_reason Receives reason for returning (can be NULL). Set to CM_BREAK_REASON_FAILED on failure.
/// \returns 0 for success, non zero code for error
CM_API cm_error cm_verify_step(const cm_machine *m, const cm_hash *root_hash_before, const char *log_filename,
    uint64_t mcycle_count, const cm_hash *root_hash_after, cm_break_reason *break_reason);

/// \brief Checks the validity of a state transition produced by cm_log_step_uarch.
/// \param m Pointer to a machine object. Can be NULL (for local machines).
/// \param root_hash_before State hash before step.
/// \param log State access log to be verified as a JSON object in a string.
/// \param root_hash_after State hash after step.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_verify_step_uarch(const cm_machine *m, const cm_hash *root_hash_before, const char *log,
    const cm_hash *root_hash_after);

/// \brief Checks the validity of a state transition produced by cm_log_verify_reset_uarch.
/// \param m Pointer to a machine object. Can be NULL (for local machines).
/// \param root_hash_before State hash before reset.
/// \param log State access log to be verified as a JSON object in a string.
/// \param root_hash_after State hash after reset.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_verify_reset_uarch(const cm_machine *m, const cm_hash *root_hash_before, const char *log,
    const cm_hash *root_hash_after);

/// \brief Checks the validity of a state transition produced by cm_log_send_cmio_response.
/// \param m Pointer to a machine object. Can be NULL (for local machines).
/// \param reason Reason for sending the response.
/// \param data The response sent when the log was generated.
/// \param length Length of response.
/// \param root_hash_before State hash before response.
/// \param log State access log to be verified as a JSON object in a string.
/// \param root_hash_after State hash after response.
/// \returns 0 for success, non zero code for error.
CM_API cm_error cm_verify_send_cmio_response(const cm_machine *m, uint16_t reason, const uint8_t *data, uint64_t length,
    const cm_hash *root_hash_before, const char *log, const cm_hash *root_hash_after);

// ------------------------------------
// Integrity checking
// ------------------------------------

/// \brief Verifies integrity of Merkle tree against current machine state.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param result True if tree is self-consistent, false otherwise.
/// \returns 0 for success, non zero code for error.
/// \details This method is used only for emulator internal tests.
CM_API cm_error cm_verify_merkle_tree(cm_machine *m, bool *result);

/// \brief Verify integrity of dirty page maps.
/// \param m Pointer to a non-empty machine object (holds a machine instance).
/// \param result True if dirty page maps are consistent, false otherwise.
/// \returns 0 for success, non zero code for error.
/// \details This method is used only for emulator internal tests.
CM_API cm_error cm_verify_dirty_page_maps(cm_machine *m, bool *result);

#ifdef __cplusplus
}
#endif

#endif // NOLINTEND
