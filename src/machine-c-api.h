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
// API enums
// -----------------------------------------------------------------------------

/// \brief Constants.
enum {
    CM_MACHINE_HASH_BYTE_SIZE = 32,
    CM_TREE_LOG2_WORD_SIZE = 5,
    CM_TREE_LOG2_PAGE_SIZE = 12,
    CM_TREE_LOG2_ROOT_SIZE = 64,
};

// ---------------------------------
// API Structures
// ---------------------------------

typedef uint8_t cm_hash[CM_MACHINE_HASH_BYTE_SIZE];

/// \brief Error codes returned from machine emulator C API
typedef enum {
    CM_ERROR_OK = 0,
    CM_ERROR_INVALID_ARGUMENT,
    CM_ERROR_DOMAIN_ERROR,
    CM_ERROR_LENGTH_ERROR,
    CM_ERROR_OUT_OF_RANGE,
    CM_ERROR_LOGIC_ERROR,
    CM_ERROR_RUNTIME_ERROR,
    CM_ERROR_RANGE_ERROR,
    CM_ERROR_OVERFLOW_ERROR,
    CM_ERROR_UNDERFLOW_ERROR,
    CM_ERROR_REGEX_ERROR,
    CM_ERROR_SYSTEM_ERROR,
    CM_ERROR_BAD_TYPEID,
    CM_ERROR_BAD_CAST,
    CM_ERROR_BAD_ANY_CAST,
    CM_ERROR_BAD_OPTIONAL_ACCESS,
    CM_ERROR_BAD_WEAK_PTR,
    CM_ERROR_BAD_FUNCTION_CALL,
    CM_ERROR_BAD_ALLOC,
    CM_ERROR_BAD_ARRAY_NEW_LENGTH,
    CM_ERROR_BAD_EXCEPTION,
    CM_ERROR_BAD_VARIANT_ACCESS,
    CM_ERROR_EXCEPTION,
    CM_ERROR_UNKNOWN
} CM_ERROR;

/// \brief Reasons for a machine run interruption
typedef enum {
    CM_BREAK_REASON_FAILED,
    CM_BREAK_REASON_HALTED,
    CM_BREAK_REASON_YIELDED_MANUALLY,
    CM_BREAK_REASON_YIELDED_AUTOMATICALLY,
    CM_BREAK_REASON_YIELDED_SOFTLY,
    CM_BREAK_REASON_REACHED_TARGET_MCYCLE
} CM_BREAK_REASON;

/// \brief List of CSRs to use with read_csr and write_csr
typedef enum {
    // X registers
    CM_CSR_X0,
    CM_CSR_X1,
    CM_CSR_X2,
    CM_CSR_X3,
    CM_CSR_X4,
    CM_CSR_X5,
    CM_CSR_X6,
    CM_CSR_X7,
    CM_CSR_X8,
    CM_CSR_X9,
    CM_CSR_X10,
    CM_CSR_X11,
    CM_CSR_X12,
    CM_CSR_X13,
    CM_CSR_X14,
    CM_CSR_X15,
    CM_CSR_X16,
    CM_CSR_X17,
    CM_CSR_X18,
    CM_CSR_X19,
    CM_CSR_X20,
    CM_CSR_X21,
    CM_CSR_X22,
    CM_CSR_X23,
    CM_CSR_X24,
    CM_CSR_X25,
    CM_CSR_X26,
    CM_CSR_X27,
    CM_CSR_X28,
    CM_CSR_X29,
    CM_CSR_X30,
    CM_CSR_X31,
    // F registers
    CM_CSR_F0,
    CM_CSR_F1,
    CM_CSR_F2,
    CM_CSR_F3,
    CM_CSR_F4,
    CM_CSR_F5,
    CM_CSR_F6,
    CM_CSR_F7,
    CM_CSR_F8,
    CM_CSR_F9,
    CM_CSR_F10,
    CM_CSR_F11,
    CM_CSR_F12,
    CM_CSR_F13,
    CM_CSR_F14,
    CM_CSR_F15,
    CM_CSR_F16,
    CM_CSR_F17,
    CM_CSR_F18,
    CM_CSR_F19,
    CM_CSR_F20,
    CM_CSR_F21,
    CM_CSR_F22,
    CM_CSR_F23,
    CM_CSR_F24,
    CM_CSR_F25,
    CM_CSR_F26,
    CM_CSR_F27,
    CM_CSR_F28,
    CM_CSR_F29,
    CM_CSR_F30,
    CM_CSR_F31,
    // Machine CSRs
    CM_CSR_PC,
    CM_CSR_FCSR,
    CM_CSR_MVENDORID,
    CM_CSR_MARCHID,
    CM_CSR_MIMPID,
    CM_CSR_MCYCLE,
    CM_CSR_ICYCLEINSTRET,
    CM_CSR_MSTATUS,
    CM_CSR_MTVEC,
    CM_CSR_MSCRATCH,
    CM_CSR_MEPC,
    CM_CSR_MCAUSE,
    CM_CSR_MTVAL,
    CM_CSR_MISA,
    CM_CSR_MIE,
    CM_CSR_MIP,
    CM_CSR_MEDELEG,
    CM_CSR_MIDELEG,
    CM_CSR_MCOUNTEREN,
    CM_CSR_MENVCFG,
    CM_CSR_STVEC,
    CM_CSR_SSCRATCH,
    CM_CSR_SEPC,
    CM_CSR_SCAUSE,
    CM_CSR_STVAL,
    CM_CSR_SATP,
    CM_CSR_SCOUNTEREN,
    CM_CSR_SENVCFG,
    CM_CSR_ILRSC,
    CM_CSR_IFLAGS,
    CM_CSR_IUNREP,
    CM_CSR_CLINT_MTIMECMP,
    CM_CSR_PLIC_GIRQPEND,
    CM_CSR_PLIC_GIRQSRVD,
    CM_CSR_HTIF_TOHOST,
    CM_CSR_HTIF_FROMHOST,
    CM_CSR_HTIF_IHALT,
    CM_CSR_HTIF_ICONSOLE,
    CM_CSR_HTIF_IYIELD,
    // Uarch
    CM_CSR_UARCH_X0,
    CM_CSR_UARCH_X1,
    CM_CSR_UARCH_X2,
    CM_CSR_UARCH_X3,
    CM_CSR_UARCH_X4,
    CM_CSR_UARCH_X5,
    CM_CSR_UARCH_X6,
    CM_CSR_UARCH_X7,
    CM_CSR_UARCH_X8,
    CM_CSR_UARCH_X9,
    CM_CSR_UARCH_X10,
    CM_CSR_UARCH_X11,
    CM_CSR_UARCH_X12,
    CM_CSR_UARCH_X13,
    CM_CSR_UARCH_X14,
    CM_CSR_UARCH_X15,
    CM_CSR_UARCH_X16,
    CM_CSR_UARCH_X17,
    CM_CSR_UARCH_X18,
    CM_CSR_UARCH_X19,
    CM_CSR_UARCH_X20,
    CM_CSR_UARCH_X21,
    CM_CSR_UARCH_X22,
    CM_CSR_UARCH_X23,
    CM_CSR_UARCH_X24,
    CM_CSR_UARCH_X25,
    CM_CSR_UARCH_X26,
    CM_CSR_UARCH_X27,
    CM_CSR_UARCH_X28,
    CM_CSR_UARCH_X29,
    CM_CSR_UARCH_X30,
    CM_CSR_UARCH_X31,
    CM_CSR_UARCH_PC,
    CM_CSR_UARCH_CYCLE,
    CM_CSR_UARCH_HALT_FLAG,
    CM_CSR_UNKNOWN,
    // Views
    CM_CSR_IFLAGS_PRV,
    CM_CSR_IFLAGS_X,
    CM_CSR_IFLAGS_Y,
    CM_CSR_IFLAGS_H,
    CM_CSR_HTIF_TOHOST_DEV,
    CM_CSR_HTIF_TOHOST_CMD,
    CM_CSR_HTIF_TOHOST_REASON,
    CM_CSR_HTIF_TOHOST_DATA,
    CM_CSR_HTIF_FROMHOST_DEV,
    CM_CSR_HTIF_FROMHOST_CMD,
    CM_CSR_HTIF_FROMHOST_REASON,
    CM_CSR_HTIF_FROMHOST_DATA,
} CM_CSR;

/// \brief Return values of uarch_interpret
typedef enum {
    CM_UARCH_BREAK_REASON_REACHED_TARGET_CYCLE,
    CM_UARCH_BREAK_REASON_UARCH_HALTED,
} CM_UARCH_BREAK_REASON;

/// \brief Access log types.
typedef enum {
    CM_ACCESS_LOG_TYPE_PROOFS = 1 << 1,      ///< Includes proofs
    CM_ACCESS_LOG_TYPE_ANNOTATIONS = 1 << 2, ///< Includes annotations
    CM_ACCESS_LOG_TYPE_LARGE_DATA = 1 << 3   ///< Includes data bigger than 8 bytes
} CM_ACCESS_LOG_TYPE;

/// \brief Machine instance handle
/// \details cm_machine* is handle used from C api users
/// to pass the machine object when calling C api functions. Currently,
/// it is merely a pointer to internal C++ object that is internally casted
/// back to original C++ machine type.
typedef struct cm_machine cm_machine;

// ---------------------------------
// API function definitions
// ---------------------------------

/// \brief Creates a new machine instance from configuration.
/// \param config Machine configuration as a JSON string.
/// \param runtime_config Machine runtime configuration as a JSON string.
/// \param new_machine Receives the pointer to new machine instance.
/// \returns 0 for success, non zero code for error.
CM_API int cm_create(const char *config, const char *runtime_config, cm_machine **new_machine);

/// \brief Destroys a machine.
/// \param m Valid pointer to the existing machine instance.
/// \returns 0 for success, non zero code for error.
/// \details This method doesn't deallocate and it's only relevant for remote machines.
CM_API int cm_destroy(cm_machine *m);

/// \brief Deletes a machine.
/// \param m Valid pointer to the existing machine instance.
/// \details The machine is deallocated and its pointer must not be used after this call.
/// Remote machines may want to call destroy method before so it's released in the remote server.
CM_API void cm_delete(cm_machine *m);

/// \brief Create machine instance from previously serialized directory
/// \param dir Directory where previous machine is serialized
/// \param runtime_config Machine runtime configuration. Must be pointer to valid object
/// \param new_machine Receives the pointer to new machine instance
/// \returns 0 for success, non zero code for error
CM_API int cm_load(const char *dir, const char *runtime_config, cm_machine **new_machine);

/// \brief Serialize entire state to directory
/// \param m Pointer to valid machine instance
/// \param dir Directory where the machine will be serialized
/// \details The method changes machine because it updates the root hash
/// \returns 0 for success, non zero code for error
CM_API int cm_store(cm_machine *m, const char *dir);

/// \brief Runs the machine until mcycle reaches mcycle_end or the machine halts.
/// \param m Pointer to valid machine instance
/// \param mcycle_end End cycle value
/// \param break_reason Receives reason for machine run interruption when not NULL
/// \returns 0 for success, non zero code for error
CM_API int cm_run(cm_machine *m, uint64_t mcycle_end, CM_BREAK_REASON *break_reason);

/// \brief Runs the machine for one micro cycle logging all accesses to the state.
/// \param m Pointer to valid machine instance
/// \param log_type Type of access log to generate.
/// \param one_based Use 1-based indices when reporting errors.
/// \param access_log Receives the state access log.
/// \returns 0 for success, non zero code for error
CM_API int cm_log_step_uarch(cm_machine *m, int log_type, bool one_based, const char **access_log);

/// \brief Checks the validity of a state transition
/// \param root_hash_before State hash before step
/// \param log Step state access log
/// \param root_hash_after State hash after step
/// \param one_based Use 1-based indices when reporting errors
/// \returns 0 for successful verification, non zero code for error
CM_API int cm_verify_step_uarch(const cm_hash *root_hash_before, const char *access_log, const cm_hash *root_hash_after,
    bool one_based);

/// \brief Checks the validity of a state transition caused by a uarch state reset
/// \param root_hash_before State hash before step
/// \param log Step state access log produced by cm_log_reset_uarch
/// \param root_hash_after State hash after step
/// \param one_based Use 1-based indices when reporting errors
/// \returns 0 for successful verification, non zero code for error
CM_API int cm_verify_reset_uarch(const cm_hash *root_hash_before, const char *access_log,
    const cm_hash *root_hash_after, bool one_based);

/// \brief Obtains the proof for a node in the Merkle tree.
/// \param m Pointer to a valid machine instance.
/// \param address Address of target node. Must be aligned to a 2^log2_size boundary.
/// \param log2_size The log2 of size subtended by target node.
/// Must be between 3 (for a word) and 64 (for the entire address space), inclusive.
/// \param proof Receives the proof as a JSON string,
/// remains valid until the next time this same function is called on the same thread.
/// \returns 0 for success, non zero code for error.
/// \details If the node is smaller than a page size,
/// then it must lie entirely inside the same PMA range.
CM_API int cm_get_proof(const cm_machine *m, uint64_t address, int log2_size, const char **proof);

/// \brief Obtains the root hash of the Merkle tree
/// \param m Pointer to valid machine instance
/// \param hash Valid pointer to cm_hash structure that  receives the hash.
/// \returns 0 for success, non zero code for error
CM_API int cm_get_root_hash(const cm_machine *m, cm_hash *hash);

/// \brief Verifies integrity of Merkle tree.
/// \param m Pointer to valid machine instance
/// \param result True if tree is self-consistent, false otherwise.
/// \returns 0 for success, non zero code for error
CM_API int cm_verify_merkle_tree(const cm_machine *m, bool *result);

/// \brief Read the value of any CSR
/// \param m Pointer to valid machine instance
/// \param val Receives value read from the CSR
/// \returns 0 for success, non zero code for error
CM_API int cm_read_csr(const cm_machine *m, CM_CSR csr, uint64_t *val);

/// \brief Write the value of any CSR
/// \param m Pointer to valid machine instance
/// \param w CSR to write
/// \param val Value to write
/// \returns 0 for success, non zero code for error
CM_API int cm_write_csr(cm_machine *m, CM_CSR csr, uint64_t val);

/// \brief Gets the address of any CSR
/// \param w The CSR
/// \returns The address of the specified CSR
CM_API uint64_t cm_get_csr_address(CM_CSR csr);

/// \brief Read the value of a word in the machine state.
/// \param m Pointer to valid machine instance
/// \param address Word address (aligned to 64-bit boundary).
/// \param val Receives word value.
/// \returns 0 for success, non zero code for error
/// \warning The current implementation of this function is very slow!
CM_API int cm_read_word(const cm_machine *m, uint64_t address, uint64_t *val);

/// \brief Reads a chunk of data from the machine memory.
/// \param m Pointer to valid machine instance
/// \param address Physical address to start reading.
/// \param data Receives chunk of memory.
/// \param length Size of chunk.
/// \returns 0 for success, non zero code for error
/// \details The entire chunk, from \p address to \p address + \p length must
/// be inside the same PMA region.
CM_API int cm_read_memory(const cm_machine *m, uint64_t address, unsigned char *data, uint64_t length);

/// \brief Writes a chunk of data to the machine memory.
/// \param m Pointer to valid machine instance
/// \param address Physical address to start writing.
/// \param data Source for chunk of data.
/// \param length Size of chunk.
/// \returns 0 for success, non zero code for error
/// \details The entire chunk, from \p address to \p address + \p length must
/// be inside the same PMA region. Moreover, this PMA must be a memory PMA,
/// and not a device PMA.
CM_API int cm_write_memory(cm_machine *m, uint64_t address, const unsigned char *data, size_t length);

/// \brief Reads a chunk of data from the machine virtual memory.
/// \param m Pointer to valid machine instance
/// \param address Virtual address to start reading.
/// \param data Receives chunk of memory.
/// \param length Size of chunk.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_virtual_memory(const cm_machine *m, uint64_t address, unsigned char *data, uint64_t length);

/// \brief Writes a chunk of data to the machine virtual memory.
/// \param m Pointer to valid machine instance
/// \param address Virtual address to start writing.
/// \param data Source for chunk of data.
/// \param length Size of chunk.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_virtual_memory(cm_machine *m, uint64_t address, const unsigned char *data, size_t length);

/// \brief Translates a virtual memory address to its corresponding physical memory address.
/// \param m Pointer to valid machine instance
/// \param vaddr Virtual address to translate.
/// \param paddr Receives the physical memory address.
/// \returns 0 for success, non zero code for error
CM_API int cm_translate_virtual_address(cm_machine *m, uint64_t vaddr, uint64_t *paddr);

/// \brief Reads the value of the mcycle register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_mcycle(const cm_machine *m, uint64_t *val);

/// \brief Checks the value of the iflags_X flag.
/// \param m Pointer to valid machine instance
/// \param val Receives the flag value
/// \returns 0 for success, non zero code for error
CM_API int cm_read_iflags_X(const cm_machine *m, bool *val);

/// \brief Checks the value of the iflags_Y flag.
/// \param m Pointer to valid machine instance
/// \param val Receives the flag value
/// \returns 0 for success, non zero code for error
CM_API int cm_read_iflags_Y(const cm_machine *m, bool *val);

/// \brief Resets the value of the iflags_Y flag.
/// \param m Pointer to valid machine instance
/// \returns 0 for success, non zero code for error
CM_API int cm_reset_iflags_Y(cm_machine *m);

/// \brief Sets the iflags_Y flag.
/// \param m Pointer to valid machine instance
/// \returns 0 for success, non zero code for error
CM_API int cm_set_iflags_Y(cm_machine *m);

/// \brief Checks the value of the iflags_H flag.
/// \param m Pointer to valid machine instance
/// \param val Receives the flag value
/// \returns 0 for success, non zero code for error
CM_API int cm_read_iflags_H(const cm_machine *m, bool *val);

/// \brief Verify if dirty page maps are consistent.
/// \param m Pointer to valid machine instance
/// \param result True if dirty page maps are consistent, false if there is an error.
/// \returns 0 for success, non zero code for error
CM_API int cm_verify_dirty_page_maps(const cm_machine *m, bool *result);

/// \brief Returns the error message set by the very last C API call.
/// \returns A C string, remains valid until next C API call.
/// \details The string returned by this function must not be changed nor deallocated,
/// and remains valid until next C API function that can return a CM_ERROR code is called.
/// In case the last call was successful it returns an empty string.
/// It uses a thread local variable, so it's safe to call from different threads.
CM_API const char *cm_get_last_error_message();

/// \brief Returns the machine initial config.
/// \param m Pointer to a valid machine instance.
/// \param config Receives the initial configuration as a JSON string,
/// remains valid until the next time this same function is called on the same thread.
/// \returns 0 for success, non zero code for error.
CM_API int cm_get_initial_config(const cm_machine *m, const char **config);

/// \brief Returns a JSON string for the default machine config.
/// \returns A C string, remains valid until program ends.
/// The string returned by this function must not be changed nor deallocated.
/// The returned config is not complete to run a machine yet,  configurations such as
/// ram length, ram image, flash drives, bootargs and entrypoint still need to be set.
CM_API const char *cm_get_default_config();

/// \brief Replaces a memory range.
/// \param m Pointer to a valid machine instance.
/// \param start Memory start physical address.
/// \param length Memory length.
/// \param shared If true changes by the machine will be shared to the image file.
/// \param image_filename Image file name to load into the range,
/// in case it's NULL the memory range is cleared with zeros.
/// \returns 0 for success, non zero code for error.
/// \details The machine must contain an existing memory range matching the start and length
/// specified in new range.
CM_API int cm_replace_memory_range(cm_machine *m, uint64_t start, uint64_t length, bool shared,
    const char *image_filename);

/// \brief Do a snapshot of the machine
/// \returns 0 for success, non zero code for error
CM_API int cm_snapshot(cm_machine *m);

/// \brief Performs commit of the machine, discarding last snapshot.
/// \returns 0 for success, non zero code for error
CM_API int cm_commit(cm_machine *m);

/// \brief Performs rollback of the machine, restoring last snapshot.
/// \returns 0 for success, non zero code for error
CM_API int cm_rollback(cm_machine *m);

/// \brief Reads the value of the microarchitecture cycle register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_uarch_cycle(const cm_machine *m, uint64_t *val);

/// \brief Gets the value of the microarchitecture halt flag.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the halt flag.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_uarch_halt_flag(const cm_machine *m, bool *val);

/// \brief Sets the value of the microarchitecture halt flag.
/// \param m Pointer to valid machine instance
/// \returns 0 for success, non zero code for error
CM_API int cm_set_uarch_halt_flag(cm_machine *m);

/// \brief Resets the entire uarch state to pristine values.
/// \param m Pointer to valid machine instance
/// \returns 0 for success, non zero code for error
CM_API int cm_reset_uarch(cm_machine *m);

/// \brief Resets the value of the microarchitecture halt flag.
/// \param m Pointer to valid machine instance
/// \param log_type Type of access log to generate.
/// \param one_based Use 1-based indices when reporting errors.
/// \param access_log Receives the state access log.
/// \returns 0 for success, non zero code for error
CM_API int cm_log_reset_uarch(cm_machine *m, int log_type, bool one_based, const char **access_log);

/// \brief Runs the machine in the microarchitecture until the mcycle advances by one unit or the micro cycles counter
/// (uarch_cycle) reaches uarch_cycle_end
/// \param m Pointer to valid machine instance
/// \param mcycle_end End cycle value
/// \param break_reason Receives status of machine run_uarch when not NULL
/// \returns 0 for success, non zero code for error
CM_API int cm_run_uarch(cm_machine *m, uint64_t uarch_cycle_end, CM_UARCH_BREAK_REASON *break_reason);

/// \brief Returns memory ranges in the machine.
/// \param m Pointer to a valid machine instance.
/// \param ranges Receives the memory ranges as a JSON string,
/// remains valid until the next time this same function is called on the same thread.
/// \returns 0 for success, non zero code for error.
CM_API int cm_get_memory_ranges(cm_machine *m, const char **ranges);

/// \brief Sends cmio response
/// \param m Pointer to valid machine instance
/// \param reason Reason for sending the response.
/// \param data Response data to send
/// \param length Length of response data.
/// \returns 0 for success, non zero code for error
CM_API int cm_send_cmio_response(cm_machine *m, uint16_t reason, const unsigned char *data, size_t length);

/// \brief Send cmio response and returns an access log
/// \param m Pointer to valid machine instance
/// \param reason Reason for sending the response.
/// \param data Response data to send.
/// \param length Length of response data.
/// \param log_type Type of access log to generate.
/// \param one_based Use 1-based indices when reporting errors.
/// \param access_log Receives the state access log.
/// \returns 0 for success, non zero code for error
CM_API int cm_log_send_cmio_response(cm_machine *m, uint16_t reason, const unsigned char *data, size_t length,
    int log_type, bool one_based, const char **access_log);

/// \brief Checks the validity of state transitions caused by cm_send_cmio_response
/// \param reason Reason for sending the response.
/// \param data The response sent when the log was generated.
/// \param length Length of response
/// \param root_hash_before State hash before load.
/// \param access_log State access log to be verified.
/// \param root_hash_after State hash after load.
/// \param one_based Use 1-based indices when reporting errors.
/// \returns 0 for success, non zero code for error
CM_API int cm_verify_send_cmio_response(uint16_t reason, const unsigned char *data, size_t length,
    const cm_hash *root_hash_before, const char *access_log, const cm_hash *root_hash_after, bool one_based);

#ifdef __cplusplus
}
#endif

#endif // NOLINTEND
