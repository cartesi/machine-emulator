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
} cm_uarch_break_reason;

/// \brief Access log types.
typedef enum cm_access_log_type {
    CM_ACCESS_LOG_TYPE_PROOFS = 1,      ///< Includes proofs
    CM_ACCESS_LOG_TYPE_ANNOTATIONS = 2, ///< Includes annotations
    CM_ACCESS_LOG_TYPE_LARGE_DATA = 4,  ///< Includes data larger than 8 bytes
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
typedef enum cm_csr {
    // Processor CSRs
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
    // Device CSRs
    CM_CSR_CLINT_MTIMECMP,
    CM_CSR_PLIC_GIRQPEND,
    CM_CSR_PLIC_GIRQSRVD,
    CM_CSR_HTIF_TOHOST,
    CM_CSR_HTIF_FROMHOST,
    CM_CSR_HTIF_IHALT,
    CM_CSR_HTIF_ICONSOLE,
    CM_CSR_HTIF_IYIELD,
    // Microarchitecture processor CSRs
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
    // Amount of CSRs
    CM_CSR_COUNT,
    // Views of CSRs
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
    CM_CSR_UNKNOWN,
} cm_csr;

/// \brief Storage for machine hash.
typedef uint8_t cm_hash[CM_HASH_SIZE];

/// \brief Machine instance handle.
/// \details It's used only as an opaque handle to pass machine objects through the C API.
typedef struct cm_machine cm_machine;

// -----------------------------------------------------------------------------
// API functions
// -----------------------------------------------------------------------------

/// \brief Returns the error message set by the very last C API call.
/// \returns A C string, guaranteed to remain valid only until the next C API call.
/// \details The string returned by this function must not be changed nor deallocated,
/// and remains valid until next C API function that can return a cm_error code is called.
/// Must be called from the same thread that called the function that produced the error.
/// In case the last call was successful, it returns an empty string.
/// (Do not use the empty string as an indication that the previous call was successful.)
/// (Instead, use the return code of the previous call itself.)
CM_API const char *cm_get_last_error_message();

/// \brief Returns a JSON object with the default machine config as a string.
/// \returns A C string, in case of success, guaranteed to remain valid only until the
/// the next time this same function is called again on the same thread.
/// In case of failure, NULL is returned and last error message is set.
/// \details The returned config is not sufficient to run a machine.
/// Additional configurations, such as RAM length, RAM image, flash drives,
/// and entrypoint are still needed.
CM_API const char *cm_get_default_config();

/// \brief Gets the address of any x, f, or control state register.
/// \param csr The CSR.
/// \returns The address of the specified CSR.
/// In case the CSR is invalid, UINT64_MAX is returned and last error message is set.
CM_API uint64_t cm_get_csr_address(cm_csr csr);

// -----------------------------------------------------------------------------
// Machine API functions
// -----------------------------------------------------------------------------

/// \brief Creates a new machine instance from configuration.
/// \param config Machine configuration as a JSON object in a string.
/// \param runtime_config Machine runtime configuration as a JSON object in a
/// string (can be NULL).
/// \param new_machine Receives the pointer to new machine instance.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_create(const char *config, const char *runtime_config, cm_machine **new_machine);

/// \brief Destroys a machine.
/// \param m Valid pointer to the existing machine instance.
/// \returns 0 for success, non zero code for error.
/// \details This method doesn't deallocate and it's only relevant for remote
/// machines.
CM_API int32_t cm_destroy(cm_machine *m);

/// \brief Deletes a machine.
/// \param m Valid pointer to the existing machine instance.
/// \details The machine is deallocated and its pointer must not be used after this
/// call. Remote machines may want to call destroy method before so it's destroyed in
/// the remote server.
CM_API void cm_delete(cm_machine *m);

/// \brief Loads a new machine instance from a previously stored directory.
/// \param dir Directory where previous machine is stored.
/// \param runtime_config Machine runtime configuration as a JSON object in a string (can be NULL).
/// \param new_machine Receives the pointer to new machine instance.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_load(const char *dir, const char *runtime_config, cm_machine **new_machine);

/// \brief Stores a machine instance to a directory, serializing its entire state.
/// \param m Pointer to a valid machine instance.
/// \param dir Directory where the machine will be stored.
/// \returns 0 for success, non zero code for error.
/// \details The function refuses to store into an existing directory.
CM_API int32_t cm_store(const cm_machine *m, const char *dir);

/// \brief Replaces a memory range.
/// \param m Pointer to a valid machine instance.
/// \param start Range start physical address.
/// \param length Range length in bytes.
/// \param shared[ni] If true, changes to the range from inside the machine will be
/// written to the associated image file in the host.
/// \param image_filename Image file name to load into the range. If NULL, entire
/// range is cleared with zeros.
/// \returns 0 for success, non zero code for error.
/// \details The machine must have been initialized with an existing memory range that
/// has the same start and length specified in the new range.
CM_API int32_t cm_replace_memory_range(cm_machine *m, uint64_t start, uint64_t length, bool shared,
    const char *image_filename);

/// \brief Returns a JSON object with the machine config used to initialize the machine.
/// \param m Pointer to a valid machine instance.
/// \param config Receives the initial configuration as a JSON object in a
/// string, guaranteed to remain valid only until the the next time this same function
/// is called again on the same thread.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_get_initial_config(const cm_machine *m, const char **config);

/// \brief Returns a list with all memory ranges in the machine.
/// \param m Pointer to a valid machine instance.
/// \param ranges Receives the memory ranges as a JSON object in a string,
/// guaranteed to remain valid only until the the next time this same function is
/// called again on the same thread.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_get_memory_ranges(const cm_machine *m, const char **ranges);

/// \brief Obtains the root hash of the Merkle tree.
/// \param m Pointer to a valid machine instance.
/// \param hash Valid pointer to cm_hash structure that receives the hash.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_get_root_hash(const cm_machine *m, cm_hash *hash);

/// \brief Obtains the proof for a node in the machine state Merkle tree.
/// \param m Pointer to a valid machine instance.
/// \param address Address of target node. Must be aligned to a 2^log2_size boundary.
/// \param log2_size The log base 2 of the size subtended by target node.
/// Must be between CM_TREE_LOG2_WORD_SIZE (for a word) and CM_TREE_LOG2_ROOT_SIZE
/// (for the entire address space), inclusive.
/// \param proof Receives the proof as a JSON object in a string, guaranteed to
/// remain valid only until the the next time this same function is called again on
/// the same thread.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_get_proof(const cm_machine *m, uint64_t address, int32_t log2_size, const char **proof);

// ------------------------------------
// Reading and writing
// ------------------------------------

/// \brief Reads the value of a word in the machine state, by its physical address.
/// \param m Pointer to valid machine instance.
/// \param address Word address (aligned to 64-bit boundary).
/// \param val Receives word value.
/// \returns 0 for success, non zero code for error.
/// \details The current implementation of this function is slow when the word falls
/// in a memory range mapped to a device.
CM_API int32_t cm_read_word(const cm_machine *m, uint64_t address, uint64_t *val);

/// \brief Reads the value of a CSR.
/// \param m Pointer to valid machine instance.
/// \param csr CSR to read.
/// \param val Receives the value.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_read_csr(const cm_machine *m, cm_csr csr, uint64_t *val);

/// \brief Writes the value of a CSR.
/// \param m Pointer to valid machine instance.
/// \param csr CSR to write.
/// \param val Value to write.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_write_csr(cm_machine *m, cm_csr csr, uint64_t val);

/// \brief Reads a chunk of data from a machine memory range, by its physical address.
/// \param m Pointer to valid machine instance.
/// \param address Physical address to start reading.
/// \param data Receives chunk of memory.
/// \param length Size of chunk in bytes.
/// \returns 0 for success, non zero code for error.
/// \details The entire chunk must be inside the same memory range.
CM_API int32_t cm_read_memory(const cm_machine *m, uint64_t address, uint8_t *data, uint64_t length);

/// \brief Writes a chunk of data to a machine memory range, by its physical address.
/// \param m Pointer to valid machine instance.
/// \param address Physical address to start writing.
/// \param data Source for chunk of data.
/// \param length Size of chunk in bytes.
/// \returns 0 for success, non zero code for error.
/// \details The entire chunk must be inside the same PMA region.
/// Moreover, unlike cm_read_memory(), the memory range written to must not be mapped to a device.
CM_API int32_t cm_write_memory(cm_machine *m, uint64_t address, const uint8_t *data, uint64_t length);

/// \brief Reads a chunk of data from a machine memory range, by its virtual memory.
/// \param m Pointer to valid machine instance.
/// \param address Virtual address to start reading.
/// \param data Receives chunk of memory.
/// \param length Size of chunk in bytes.
/// \returns 0 for success, non zero code for error.
/// \detail The translation is based on the current mapping, as defined in CM_CSR_SATP.
CM_API int32_t cm_read_virtual_memory(const cm_machine *m, uint64_t address, uint8_t *data, uint64_t length);

/// \brief Writes a chunk of data to a machine memory range, by its virtual address.
/// \param m Pointer to valid machine instance.
/// \param address Virtual address to start writing.
/// \param data Source for chunk of data.
/// \param length Size of chunk in bytes.
/// \returns 0 for success, non zero code for error.
/// \detail The translation is based on the current mapping, as defined in CM_CSR_SATP.
CM_API int32_t cm_write_virtual_memory(cm_machine *m, uint64_t address, const uint8_t *data, uint64_t length);

/// \brief Translates a virtual memory address to its corresponding physical memory address.
/// \param m Pointer to valid machine instance.
/// \param vaddr Virtual address to translate.
/// \param paddr Receives the physical memory address.
/// \returns 0 for success, non zero code for error.
/// \detail The translation is based on the current mapping, as defined in CM_CSR_SATP.
CM_API int32_t cm_translate_virtual_address(const cm_machine *m, uint64_t vaddr, uint64_t *paddr);

/// \brief Reads the value of the CM_CSR_MCYCLE.
/// \param m Pointer to valid machine instance.
/// \param val Receives the value.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_read_mcycle(const cm_machine *m, uint64_t *val);

/// \brief Reads the value of the X flag in CM_CSR_IFLAGS.
/// \param m Pointer to valid machine instance.
/// \param val Receives the value.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_read_iflags_X(const cm_machine *m, bool *val);

/// \brief Reads the value of the Y flag in CM_CSR_IFLAGS.
/// \param m Pointer to valid machine instance.
/// \param val Receives the value.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_read_iflags_Y(const cm_machine *m, bool *val);

/// \brief Resets the value of the Y flag in CM_CSR_IFLAGS.
/// \param m Pointer to valid machine instance.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_reset_iflags_Y(cm_machine *m);

/// \brief Sets the Y flag in CM_CSR_IFLAGS.
/// \param m Pointer to valid machine instance.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_set_iflags_Y(cm_machine *m);

/// \brief Reads the value of the H flag in CM_CSR_IFLAGS.
/// \param m Pointer to valid machine instance.
/// \param val Receives the value.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_read_iflags_H(const cm_machine *m, bool *val);

/// \brief Reads the value of CM_CSR_UARCH_CYCLE.
/// \param m Pointer to valid machine instance.
/// \param val Receives the value.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_read_uarch_cycle(const cm_machine *m, uint64_t *val);

/// \brief Reads the value of CM_CSR_UARCH_HALT_FLAG.
/// \param m Pointer to valid machine instance.
/// \param val Receives the value.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_read_uarch_halt_flag(const cm_machine *m, bool *val);

/// \brief Sets the value of CM_CSR_UARCH_HALT_FLAG.
/// \param m Pointer to valid machine instance.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_set_uarch_halt_flag(cm_machine *m);

// ------------------------------------
// Rolling back
// ------------------------------------

/// \brief Replaces the current snapshot with a copy of the current machine state.
/// \param m Pointer to a valid machine instance.
/// \returns 0 for success, non zero code for error.
/// \detail This function is ignored unless the machine is remote.
CM_API int32_t cm_snapshot(cm_machine *m);

/// \brief Delete current snapshot.
/// \param m Pointer to a valid machine instance.
/// \returns 0 for success, non zero code for error.
/// \detail This function is ignored unless the machine is remote.
CM_API int32_t cm_commit(cm_machine *m);

/// \brief Replaces machine state with copy in current snapshot, and then delete snapshot.
/// \param m Pointer to a valid machine instance.
/// \returns 0 for success, non zero code for error.
/// \detail This function is ignored unless the machine is remote.
CM_API int32_t cm_rollback(cm_machine *m);

// ------------------------------------
// Running
// ------------------------------------

/// \brief Runs the machine until CM_CSR_MCYCLE reaches mcycle_end, machine yields, or halts.
/// \param m Pointer to valid machine instance.
/// \param mcycle_end End cycle value.
/// \param break_reason Receives reason for returning (can be NULL).
/// \returns 0 for success, non zero code for error.
/// \details You may want to receive cmio requests depending on the run break reason.
CM_API int32_t cm_run(cm_machine *m, uint64_t mcycle_end, cm_break_reason *break_reason);

/// \brief Runs the machine microarchitecture until CM_CSR_UARCH_CYCLE reaches uarch_cycle_end or it halts.
/// \param m Pointer to valid machine instance.
/// \param uarch_cycle_end End micro cycle value.
/// \param uarch_break_reason Receives reason for returning (can be NULL).
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_run_uarch(cm_machine *m, uint64_t uarch_cycle_end, cm_uarch_break_reason *uarch_break_reason);

/// \brief Resets the entire microarchitecture state to pristine values.
/// \param m Pointer to valid machine instance.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_reset_uarch(cm_machine *m);

/// \brief Receives a cmio request.
/// \param m Pointer to valid machine instance.
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
CM_API int32_t cm_receive_cmio_request(const cm_machine *m, uint8_t *cmd, uint16_t *reason, uint8_t *data,
    uint64_t *length);

/// \brief Sends a cmio response.
/// \param m Pointer to valid machine instance.
/// \param reason Reason for sending the response.
/// \param data Response data to send.
/// \param length Length of response data.
/// \returns 0 for success, non zero code for error.
/// \details This method should only be called as a response to cmio requests with manual yield command
/// where the reason is either accepted or a GIO request, may fail otherwise.
CM_API int32_t cm_send_cmio_response(cm_machine *m, uint16_t reason, const uint8_t *data, uint64_t length);

// ------------------------------------
// Logging
// ------------------------------------

/// \brief Runs the machine in the microarchitecture for one micro cycle logging all accesses to the state.
/// \param m Pointer to valid machine instance.
/// \param log_type Type of access log to generate.
/// \param log Receives the state access log as a JSON object in a string,
/// remains valid until the next time this same function is called on the same thread.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_log_step_uarch(cm_machine *m, int32_t log_type, const char **log);

/// \brief Resets the entire microarchitecture state to pristine values logging all accesses to the state.
/// \param m Pointer to valid machine instance.
/// \param log_type Type of access log to generate.
/// \param log Receives the state access log as a JSON object in a string,
/// remains valid until the next time this same function is called on the same thread.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_log_reset_uarch(cm_machine *m, int32_t log_type, const char **log);

/// \brief Sends a cmio response logging all accesses to the state.
/// \param m Pointer to valid machine instance.
/// \param reason Reason for sending the response.
/// \param data Response data to send.
/// \param length Length of response data.
/// \param log_type Type of access log to generate.
/// \param log Receives the state access log as a JSON object in a string,
/// remains valid until the next time this same function is called on the same thread.
/// \returns 0 for success, non zero code for error.
CM_API int32_t cm_log_send_cmio_response(cm_machine *m, uint16_t reason, const uint8_t *data, uint64_t length,
    int32_t log_type, const char **log);

// ------------------------------------
// Verifying
// ------------------------------------

/// \brief Checks the validity of a state transition for one microarchitecture cycle.
/// \param root_hash_before State hash before step.
/// \param log State access log to be verified as a JSON object in a string.
/// \param root_hash_after State hash after step.
/// \returns 0 for success, non zero code for error.
/// \details If both root_hash_before and root_hash_after are NULL, no proofs are taken into account.
CM_API int32_t cm_verify_step_uarch(const cm_hash *root_hash_before, const char *log, const cm_hash *root_hash_after);

/// \brief Checks the validity of a state transition produced by a microarchitecture reset.
/// \param root_hash_before State hash before reset.
/// \param log State access log to be verified as a JSON object in a string.
/// \param root_hash_after State hash after reset.
/// \returns 0 for success, non zero code for error.
/// \details If both root_hash_before and root_hash_after are NULL, no proofs are taken into account.
CM_API int32_t cm_verify_reset_uarch(const cm_hash *root_hash_before, const char *log, const cm_hash *root_hash_after);

/// \brief Checks the validity of state transitions produced by a send cmio response.
/// \param reason Reason for sending the response.
/// \param data The response sent when the log was generated.
/// \param length Length of response.
/// \param root_hash_before State hash before response.
/// \param log State access log to be verified as a JSON object in a string.
/// \param root_hash_after State hash after response.
/// \returns 0 for success, non zero code for error.
/// \details If both root_hash_before and root_hash_after are NULL, no proofs are taken into account.
CM_API int32_t cm_verify_send_cmio_response(uint16_t reason, const uint8_t *data, uint64_t length,
    const cm_hash *root_hash_before, const char *log, const cm_hash *root_hash_after);

// ------------------------------------
// Integrity checking
// ------------------------------------

/// \brief Verifies integrity of Merkle tree against current machine state.
/// \param m Pointer to valid machine instance.
/// \param result True if tree is self-consistent, false otherwise.
/// \returns 0 for success, non zero code for error.
/// \details This method is used only for emulator internal tests.
CM_API int32_t cm_verify_merkle_tree(cm_machine *m, bool *result);

/// \brief Verify integrity of dirty page maps.
/// \param m Pointer to valid machine instance.
/// \param result True if dirty page maps are consistent, false otherwise.
/// \returns 0 for success, non zero code for error.
/// \details This method is used only for emulator internal tests.
CM_API int32_t cm_verify_dirty_page_maps(cm_machine *m, bool *result);

#ifdef __cplusplus
}
#endif

#endif // NOLINTEND
