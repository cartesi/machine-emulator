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

#ifndef CM_C_API_H
#define CM_C_API_H

#ifndef __cplusplus
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#else
#include <cassert>
#include <cstddef>
#include <cstdint>
#endif

#include "machine-c-defines.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------
// API Structures
// ---------------------------------

// NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays,modernize-use-using)
typedef uint8_t cm_hash[CM_MACHINE_HASH_BYTE_SIZE];

/// \brief Array of hashes
typedef struct { // NOLINT(modernize-use-using)
    cm_hash *entry;
    size_t count;
} cm_hash_array;

/// brief Error codes returned from machine emulator C API
typedef enum { // NOLINT(modernize-use-using)
    CM_ERROR_OK = 0,
    // Logic errors
    CM_ERROR_INVALID_ARGUMENT,
    CM_ERROR_DOMAIN_ERROR,
    CM_ERROR_LENGTH_ERROR,
    CM_ERROR_OUT_OF_RANGE,
    CM_ERROR_LOGIC_ERROR,
    CM_LOGIC_ERROR_END,
    // Bad optional access error
    CM_ERROR_BAD_OPTIONAL_ACCESS,
    // Runtime errors
    CM_ERROR_RUNTIME_ERROR,
    CM_ERROR_RANGE_ERROR,
    CM_ERROR_OVERFLOW_ERROR,
    CM_ERROR_UNDERFLOW_ERROR,
    CM_ERROR_REGEX_ERROR,
    CM_ERROR_SYSTEM_IOS_BASE_FAILURE,
    CM_ERROR_FILESYSTEM_ERROR,
    CM_ERROR_ATOMIC_TX_ERROR,
    CM_ERROR_NONEXISTING_LOCAL_TIME,
    CM_ERROR_AMBIGOUS_LOCAL_TIME,
    CM_ERROR_FORMAT_ERROR,
    CM_RUNTIME_ERROR_END,
    // Other errors
    CM_ERROR_BAD_TYPEID,
    CM_ERROR_BAD_CAST,
    CM_ERROR_BAD_ANY_CAST,
    CM_ERROR_BAD_WEAK_PTR,
    CM_ERROR_BAD_FUNCTION_CALL,
    CM_ERROR_BAD_ALLOC,
    CM_ERROR_BAD_ARRAY_NEW_LENGTH,
    CM_ERROR_BAD_EXCEPTION,
    CM_ERROR_BAD_VARIANT_ACCESS,
    CM_ERROR_EXCEPTION,
    CM_OTHER_ERROR_END,
    // C API Errors
    CM_ERROR_UNKNOWN
} CM_ERROR;

/// \brief Reasons for a machine run interruption
typedef enum { // NOLINT(modernize-use-using)
    CM_BREAK_REASON_FAILED,
    CM_BREAK_REASON_HALTED,
    CM_BREAK_REASON_YIELDED_MANUALLY,
    CM_BREAK_REASON_YIELDED_AUTOMATICALLY,
    CM_BREAK_REASON_REACHED_TARGET_MCYCLE
} CM_BREAK_REASON;

/// \brief List of CSRs to use with read_csr and write_csr
typedef enum { // NOLINT(modernize-use-using)
    CM_PROC_PC,
    CM_PROC_FCSR,
    CM_PROC_MVENDORID,
    CM_PROC_MARCHID,
    CM_PROC_MIMPID,
    CM_PROC_MCYCLE,
    CM_PROC_ICYCLEINSTRET,
    CM_PROC_MSTATUS,
    CM_PROC_MTVEC,
    CM_PROC_MSCRATCH,
    CM_PROC_MEPC,
    CM_PROC_MCAUSE,
    CM_PROC_MTVAL,
    CM_PROC_MISA,
    CM_PROC_MIE,
    CM_PROC_MIP,
    CM_PROC_MEDELEG,
    CM_PROC_MIDELEG,
    CM_PROC_MCOUNTEREN,
    CM_PROC_MENVCFG,
    CM_PROC_STVEC,
    CM_PROC_SSCRATCH,
    CM_PROC_SEPC,
    CM_PROC_SCAUSE,
    CM_PROC_STVAL,
    CM_PROC_SATP,
    CM_PROC_SCOUNTEREN,
    CM_PROC_SENVCFG,
    CM_PROC_ILRSC,
    CM_PROC_IFLAGS,
    CM_PROC_CLINT_MTIMECMP,
    CM_PROC_HTIF_TOHOST,
    CM_PROC_HTIF_FROMHOST,
    CM_PROC_HTIF_IHALT,
    CM_PROC_HTIF_ICONSOLE,
    CM_PROC_HTIF_IYIELD,
    CM_PROC_UARCH_PC,
    CM_PROC_UARCH_CYCLE,
    CM_PROC_UARCH_HALT_FLAG,
    CM_PROC_UNKNOWN
} CM_PROC_CSR;

/// \brief Return values of uarch_interpret
typedef enum { // NOLINT(modernize-use-using)
    CM_UARCH_BREAK_REASON_REACHED_TARGET_CYCLE,
    CM_UARCH_BREAK_REASON_UARCH_HALTED,
} CM_UARCH_BREAK_REASON;

/// \brief Processor state configuration
typedef struct {                        // NOLINT(modernize-use-using)
    uint64_t x[CM_MACHINE_X_REG_COUNT]; ///< Value of general-purpose registers
    uint64_t f[CM_MACHINE_F_REG_COUNT]; ///< Value of floating-point registers
    uint64_t pc;                        ///< Value of pc
    uint64_t fcsr;                      ///< Value of fcsr CSR
    uint64_t mvendorid;                 ///< Value of mvendorid CSR
    uint64_t marchid;                   ///< Value of marchid CSR
    uint64_t mimpid;                    ///< Value of mimpid CSR
    uint64_t mcycle;                    ///< Value of mcycle CSR
    uint64_t icycleinstret;             ///< Value of icycleinstret CSR
    uint64_t mstatus;                   ///< Value of mstatus CSR
    uint64_t mtvec;                     ///< Value of mtvec CSR
    uint64_t mscratch;                  ///< Value of mscratch CSR
    uint64_t mepc;                      ///< Value of mepc CSR
    uint64_t mcause;                    ///< Value of mcause CSR
    uint64_t mtval;                     ///< Value of mtval CSR
    uint64_t misa;                      ///< Value of misa CSR
    uint64_t mie;                       ///< Value of mie CSR
    uint64_t mip;                       ///< Value of mip CSR
    uint64_t medeleg;                   ///< Value of medeleg CSR
    uint64_t mideleg;                   ///< Value of mideleg CSR
    uint64_t mcounteren;                ///< Value of mcounteren CSR
    uint64_t menvcfg;                   ///< Value of menvcfg CSR
    uint64_t stvec;                     ///< Value of stvec CSR
    uint64_t sscratch;                  ///< Value of sscratch CSR
    uint64_t sepc;                      ///< Value of sepc CSR
    uint64_t scause;                    ///< Value of scause CSR
    uint64_t stval;                     ///< Value of stval CSR
    uint64_t satp;                      ///< Value of satp CSR
    uint64_t scounteren;                ///< Value of scounteren CSR
    uint64_t senvcfg;                   ///< Value of senvcfg CSR
    uint64_t ilrsc;                     ///< Value of ilrsc CSR
    uint64_t iflags;                    ///< Value of iflags CSR
} cm_processor_config;

/// \brief RAM state configuration
typedef struct {                // NOLINT(modernize-use-using)
    uint64_t length;            ///< RAM length
    const char *image_filename; ///< RAM image file name
} cm_ram_config;

/// \brief DTB state configuration
typedef struct {                // NOLINT(modernize-use-using)
    const char *bootargs;       ///< Bootargs to pass to kernel
    const char *init;           ///< Initialization commands to be executed as root on boot
    const char *entrypoint;     ///< Commands to execute the main application
    const char *image_filename; ///< ROM image file
} cm_dtb_config;

/// \brief Memory range configuration
typedef struct {                // NOLINT(modernize-use-using)
    uint64_t start;             ///< Memory range start position
    uint64_t length;            ///< Memory range length
    bool shared;                ///< Target changes to range affect image file?
    const char *image_filename; ///< Memory range image file name
} cm_memory_range_config;

/// \brief Memory range configuration array
typedef struct { // NOLINT(modernize-use-using)
    cm_memory_range_config *entry;
    size_t count;
} cm_memory_range_config_array;

/// \brief TLB device state configuration
typedef struct {                // NOLINT(modernize-use-using)
    const char *image_filename; ///< TLB image file name
} cm_tlb_config;

/// \brief CLINT device state configuration
typedef struct {       // NOLINT(modernize-use-using)
    uint64_t mtimecmp; ///< Value of mtimecmp CSR
} cm_clint_config;

/// \brief HTIF device state configuration
typedef struct {          // NOLINT(modernize-use-using)
    uint64_t fromhost;    ///< Value of fromhost CSR
    uint64_t tohost;      ///< Value of tohost CSR
    bool console_getchar; ///< Make console getchar available?
    bool yield_manual;    ///< Make yield manual available?
    bool yield_automatic; ///< Make yield automatic available?
} cm_htif_config;

/// \brief Rollup state configuration
typedef struct {                           // NOLINT(modernize-use-using)
    bool has_value;                        ///< Represents whether the rest of the struct have been filled
    cm_memory_range_config rx_buffer;      ///< RX buffer memory range
    cm_memory_range_config tx_buffer;      ///< TX buffer memory range
    cm_memory_range_config input_metadata; ///< Input metadata memory range
    cm_memory_range_config voucher_hashes; ///< Voucher hashes memory range
    cm_memory_range_config notice_hashes;  ///< Notice hashes memory range
} cm_rollup_config;

/// \brief microarchitecture RAM configuration
typedef struct {                // NOLINT(modernize-use-using)
    const char *image_filename; ///< RAM image file name
} cm_uarch_ram_config;

/// \brief Microarchitecture processor configuration
typedef struct { // NOLINT(modernize-use-using)
    uint64_t x[CM_MACHINE_UARCH_X_REG_COUNT];
    uint64_t pc;
    uint64_t cycle;
    bool halt_flag;
} cm_uarch_processor_config;

/// \brief Microarchitecture state configuration
typedef struct { // NOLINT(modernize-use-using)
    cm_uarch_processor_config processor;
    cm_uarch_ram_config ram;
} cm_uarch_config;

/// \brief Machine state configuration
typedef struct { // NOLINT(modernize-use-using)
    cm_processor_config processor;
    cm_ram_config ram;
    cm_dtb_config dtb;
    cm_memory_range_config_array flash_drive;
    cm_tlb_config tlb;
    cm_clint_config clint;
    cm_htif_config htif;
    cm_rollup_config rollup;
    cm_uarch_config uarch;
} cm_machine_config;

/// \brief Merkle tree proof structure
/// \details
/// This structure holds a proof that the node spanning a log2_target_size
/// at a given address in the tree has a certain hash.
typedef struct { // NOLINT(modernize-use-using)
    uint64_t target_address;
    size_t log2_target_size;
    cm_hash target_hash;
    size_t log2_root_size;
    cm_hash root_hash;
    cm_hash_array sibling_hashes;
} cm_merkle_tree_proof;

/// \brief Type of state access
typedef enum {       // NOLINT(modernize-use-using)
    CM_ACCESS_READ,  ///< Read operation
    CM_ACCESS_WRITE, ///< Write operation
} CM_ACCESS_TYPE;

/// \brief Type of access log
typedef struct {      // NOLINT(modernize-use-using)
    bool proofs;      ///< Includes proofs
    bool annotations; ///< Includes annotations
    bool large_data;  ///< Includes data bigger than 8 bytes
} cm_access_log_type;

/// \brief Bracket type
typedef enum {        // NOLINT(modernize-use-using)
    CM_BRACKET_BEGIN, ///< Start of scope
    CM_BRACKET_END    ///< End of scope
} CM_BRACKET_TYPE;

/// \brief Bracket note
typedef struct {          // NOLINT(modernize-use-using)
    CM_BRACKET_TYPE type; ///< Bracket type
    uint64_t where;       ///< Where it points to in the log
    char *text;           ///< Note text
} cm_bracket_note;

/// \brief Records an access to the machine state
typedef struct {                   // NOLINT(modernize-use-using)
    CM_ACCESS_TYPE type;           ///< Type of access
    uint64_t address;              ///< Address of access
    int log2_size;                 ///< Log2 of size of access
    cm_hash read_hash;             ///< Hash of data before access
    uint8_t *read_data;            ///< Data before access
    size_t read_data_size;         ///< Size of data before access in bytes
    cm_hash written_hash;          ///< Hash of data after access (if writing)
    uint8_t *written_data;         ///< Data after access (if writing)
    size_t written_data_size;      ///< Size of data after access in bytes
    cm_hash_array *sibling_hashes; ///< Sibling hashes towards root
} cm_access;

/// \brief Array of accesses
typedef struct { // NOLINT(modernize-use-using)
    cm_access *entry;
    size_t count;
} cm_access_array;

/// \brief Array of bracket notes
typedef struct { // NOLINT(modernize-use-using)
    cm_bracket_note *entry;
    size_t count;
} cm_bracket_note_array;

/// \brief Array of notes
typedef struct { // NOLINT(modernize-use-using)
    const char **entry;
    size_t count;
} cm_note_array;

/// \brief Log of state accesses
typedef struct {                    // NOLINT(modernize-use-using)
    cm_access_array accesses;       ///< List of accesses
    cm_bracket_note_array brackets; ///< Begin/End annotations
    cm_note_array notes;            ///< Per-access annotations
    cm_access_log_type log_type;    ///< Log type
} cm_access_log;

/// \brief Concurrency runtime configuration
typedef struct { // NOLINT(modernize-use-using)
    uint64_t update_merkle_tree;
} cm_concurrency_runtime_config;

/// \brief HTIF runtime configuration
typedef struct { // NOLINT(modernize-use-using)
    bool no_console_putchar;
} cm_htif_runtime_config;

/// \brief Machine runtime configuration
typedef struct { // NOLINT(modernize-use-using)
    cm_concurrency_runtime_config concurrency;
    cm_htif_runtime_config htif;
    bool skip_root_hash_check;
    bool skip_version_check;
} cm_machine_runtime_config;

/// \brief Machine instance handle
/// \details cm_machine* is handle used from C api users
/// to pass the machine object when calling C api functions. Currently,
/// it is merely a pointer to internal C++ object that is  internally casted
/// back to original C++ machine type. On some obscure CPU arhitectures
/// where pointer size depend on types, this api might not work
typedef struct cm_machine_tag cm_machine; // NOLINT(modernize-use-using)

/// \brief Semantic version
typedef struct { // NOLINT(modernize-use-using)
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    const char *pre_release;
    const char *build;
} cm_semantic_version;

/// \brief Memory range description
typedef struct { // NOLINT(modernize-use-using)
    uint64_t start;
    uint64_t length;
    const char *description;
} cm_memory_range_descr;

/// \brief Memory range description array
typedef struct { // NOLINT(modernize-use-using)
    cm_memory_range_descr *entry;
    size_t count;
} cm_memory_range_descr_array;

// ---------------------------------
// API function definitions
// ---------------------------------

/// \brief Create new machine config with default parameters
/// \returns Pointer to new default config object
/// \details Object acquired from this function must not be changed and
/// must be deleted with cm_delete_machine_config. To make a custom config based
/// on default config user must make a deep copy of returned object members and then
/// customize
CM_API const cm_machine_config *cm_new_default_machine_config(void);

/// \brief Delete machine config acquired from cm_new_default_machine_config
/// \returns void
CM_API void cm_delete_machine_config(const cm_machine_config *config);

/// \brief Create new machine instance from configuration
/// \param config Machine configuration. Must be pointer to valid object
/// \param runtime_config Machine runtime configuration. Must be pointer to valid object
/// \param new_machine Receives the pointer to new machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_create_machine(const cm_machine_config *config, const cm_machine_runtime_config *runtime_config,
    cm_machine **new_machine, char **err_msg);

/// \brief Create machine instance from previously serialized directory
/// \param dir Directory where previous machine is serialized
/// \param runtime_config Machine runtime configuration. Must be pointer to valid object
/// \param new_machine Receives the pointer to new machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_load_machine(const char *dir, const cm_machine_runtime_config *runtime_config, cm_machine **new_machine,
    char **err_msg);

/// \brief Serialize entire state to directory
/// \param m Pointer to valid machine instance
/// \param dir Directory where the machine will be serialized
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \details The method changes machine because it updates the root hash
/// \returns 0 for success, non zero code for error
CM_API int cm_store(cm_machine *m, const char *dir, char **err_msg);

/// \brief Deletes machine instance
/// \param m Valid pointer to the existing machine instance
CM_API void cm_delete_machine(cm_machine *m);

/// \brief Runs the machine until mcycle reaches mcycle_end or the machine halts.
/// \param m Pointer to valid machine instance
/// \param mcycle_end End cycle value
/// \param break_reason Receives reason for machine run interruption when not NULL
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_machine_run(cm_machine *m, uint64_t mcycle_end, CM_BREAK_REASON *break_reason_result, char **err_msg);

/// \brief Runs the machine for one micro cycle logging all accesses to the state.
/// \param m Pointer to valid machine instance
/// \param log_type Type of access log to generate.
/// \param one_based Use 1-based indices when reporting errors.
/// \param access_log Receives the state access log.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_log_uarch_step(cm_machine *m, cm_access_log_type log_type, bool one_based, cm_access_log **access_log,
    char **err_msg);

/// \brief  Deletes the instance of cm_access_log acquired from cm_step
/// \param acc_log Valid pointer to cm_access_log object
CM_API void cm_delete_access_log(cm_access_log *acc_log);

/// \brief Checks the internal consistency of an access log
/// \param log State access log to be verified
/// \param r Machine runtime configuration to use during verification. Must be pointer to valid object
/// \param one_based Use 1-based indices when reporting errors
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_verify_uarch_step_log(const cm_access_log *log, const cm_machine_runtime_config *runtime_config,
    bool one_based, char **err_msg);

/// \brief Checks the validity of a state transition
/// \param root_hash_before State hash before step
/// \param log Step state access log
/// \param root_hash_after State hash after step
/// \param runtime_config Machine runtime configuration to use during verification. Must be pointer to valid object
/// \param one_based Use 1-based indices when reporting errors
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for successful verification, non zero code for error
CM_API int cm_verify_uarch_step_state_transition(const cm_hash *root_hash_before, const cm_access_log *log,
    const cm_hash *root_hash_after, const cm_machine_runtime_config *runtime_config, bool one_based, char **err_msg);

/// \brief Checks the validity of a state transition caused by a uarch state reset
/// \param root_hash_before State hash before step
/// \param log Step state access log produced by cm_log_uarch_reset
/// \param root_hash_after State hash after step
/// \param runtime_config Machine runtime configuration to use during verification. Must be pointer to valid object
/// \param one_based Use 1-based indices when reporting errors
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for successful verification, non zero code for error
CM_API int cm_verify_uarch_reset_state_transition(const cm_hash *root_hash_before, const cm_access_log *log,
    const cm_hash *root_hash_after, const cm_machine_runtime_config *runtime_config, bool one_based, char **err_msg);

/// \brief Checks the internal consistency of an access log produced by cm_log_uarch_reset
/// \param log State access log to be verified
/// \param r Machine runtime configuration to use during verification. Must be pointer to valid object
/// \param one_based Use 1-based indices when reporting errors
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_verify_uarch_reset_log(const cm_access_log *log, const cm_machine_runtime_config *runtime_config,
    bool one_based, char **err_msg);

/// \brief Obtains the proof for a node in the Merkle tree
/// \param m Pointer to valid machine instance
/// \param address Address of target node. Must be aligned to a 2<sup>log2_size</sup> boundary
/// \param log2_size log<sub>2</sub> of size subintended by target node.
/// Must be between 3 (for a word) and 64 (for the entire address space), inclusive
/// \param proof Receives the proof
/// proof must be deleted with the function cm_delete_merkle_tree_proof
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
/// \details If the node is smaller than a page size, then it must lie entirely inside the same PMA range.
CM_API int cm_get_proof(const cm_machine *m, uint64_t address, int log2_size, cm_merkle_tree_proof **proof,
    char **err_msg);

/// \brief  Deletes the instance of cm_merkle_tree_proof acquired from cm_get_proof
/// \param proof Valid pointer to cm_merkle_tree_proof object
CM_API void cm_delete_merkle_tree_proof(cm_merkle_tree_proof *proof);

/// \brief Obtains the root hash of the Merkle tree
/// \param m Pointer to valid machine instance
/// \param hash Valid pointer to cm_hash structure that  receives the hash.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_get_root_hash(const cm_machine *m, cm_hash *hash, char **err_msg);

/// \brief Verifies integrity of Merkle tree.
/// \param m Pointer to valid machine instance
/// \param result True if tree is self-consistent, false otherwise.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_verify_merkle_tree(const cm_machine *m, bool *result, char **err_msg);

/// \brief Read the value of any CSR
/// \param m Pointer to valid machine instance
/// \param val Receives value read from the CSR
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_csr(const cm_machine *m, CM_PROC_CSR r, uint64_t *val, char **err_msg);

/// \brief Write the value of any CSR
/// \param m Pointer to valid machine instance
/// \param w CSR to write
/// \param val Value to write
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_csr(cm_machine *m, CM_PROC_CSR w, uint64_t val, char **err_msg);

/// \brief Gets the address of any CSR
/// \param w The CSR
/// \returns The address of the specified CSR
CM_API uint64_t cm_get_csr_address(CM_PROC_CSR w);

/// \brief Read the value of a word in the machine state.
/// \param m Pointer to valid machine instance
/// \param word_address Word address (aligned to 64-bit boundary).
/// \param word_value Receives word value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
/// \warning The current implementation of this function is very slow!
CM_API int cm_read_word(const cm_machine *m, uint64_t word_address, uint64_t *word_value, char **err_msg);

/// \brief Reads a chunk of data from the machine memory.
/// \param m Pointer to valid machine instance
/// \param address Physical address to start reading.
/// \param data Receives chunk of memory.
/// \param length Size of chunk.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
/// \details The entire chunk, from \p address to \p address + \p length must
/// be inside the same PMA region.
CM_API int cm_read_memory(const cm_machine *m, uint64_t address, unsigned char *data, uint64_t length, char **err_msg);

/// \brief Writes a chunk of data to the machine memory.
/// \param m Pointer to valid machine instance
/// \param address Physical address to start writing.
/// \param data Source for chunk of data.
/// \param length Size of chunk.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
/// \details The entire chunk, from \p address to \p address + \p length must
/// be inside the same PMA region. Moreover, this PMA must be a memory PMA,
/// and not a device PMA.
CM_API int cm_write_memory(cm_machine *m, uint64_t address, const unsigned char *data, size_t length, char **err_msg);

/// \brief Reads a chunk of data from the machine virtual memory.
/// \param m Pointer to valid machine instance
/// \param address Virtual address to start reading.
/// \param data Receives chunk of memory.
/// \param length Size of chunk.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_virtual_memory(const cm_machine *m, uint64_t address, unsigned char *data, uint64_t length,
    char **err_msg);

/// \brief Writes a chunk of data to the machine virtual memory.
/// \param m Pointer to valid machine instance
/// \param address Virtual address to start writing.
/// \param data Source for chunk of data.
/// \param length Size of chunk.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_virtual_memory(cm_machine *m, uint64_t address, const unsigned char *data, size_t length,
    char **err_msg);

/// \brief Reads the value of a general-purpose register.
/// \param m Pointer to valid machine instance
/// \param i Register index. Between 0 and X_REG_COUNT-1, inclusive.
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_x(const cm_machine *m, int i, uint64_t *val, char **err_msg);

/// \brief Writes the value of a general-purpose register.
/// \param m Pointer to valid machine instance
/// \param i Register index. Between 1 and X_REG_COUNT-1, inclusive.
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_x(cm_machine *m, int i, uint64_t val, char **err_msg);

/// \brief Gets the address of a general-purpose register.
/// \param i Register index. Between 0 and X_REG_COUNT-1, inclusive.
/// \returns Address of the specified register
CM_API uint64_t cm_get_x_address(int i);

/// \brief Gets the address of a general-purpose microarchitecture register.
/// \param i Register index. Between 0 and UARCH_X_REG_COUNT-1, inclusive.
/// \returns Address of the specified register
CM_API uint64_t cm_get_uarch_x_address(int i);

/// \brief Reads the value of a floating-point register.
/// \param m Pointer to valid machine instance
/// \param i Register index. Between 0 and F_REG_COUNT-1, inclusive.
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_f(const cm_machine *m, int i, uint64_t *val, char **err_msg);

/// \brief Writes the value of a floating-point register.
/// \param m Pointer to valid machine instance
/// \param i Register index. Between 0 and F_REG_COUNT-1, inclusive.
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_f(cm_machine *m, int i, uint64_t val, char **err_msg);

/// \brief Gets the address of a floating-point register.
/// \param i Register index. Between 0 and F_REG_COUNT-1, inclusive.
/// \returns Address of the specified register
CM_API uint64_t cm_get_f_address(int i);

/// \brief Reads the value of the pc register.
/// \param m Pointer to valid machine instance
/// \param val Receives the value of the register
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_pc(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the pc register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_pc(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the fcsr register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_fcsr(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the fcsr register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_fcsr(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the mvendorid register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_mvendorid(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Reads the value of the marchid register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_marchid(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Reads the value of the mimpid register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_mimpid(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Reads the value of the mcycle register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_mcycle(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the mcycle register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_mcycle(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the icycleinstret register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_icycleinstret(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the icycleinstret register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_icycleinstret(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the mstatus register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_mstatus(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the mstatus register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_mstatus(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the menvcfg register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_menvcfg(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the menvcfg register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_menvcfg(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the mtvec register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_mtvec(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the mtvec register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_mtvec(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the mscratch register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_mscratch(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the mscratch register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_mscratch(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the mepc register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_mepc(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the mepc register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_mepc(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the mcause register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_mcause(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the mcause register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_mcause(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the mtval register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_mtval(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the mtval register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_mtval(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the misa register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_misa(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the misa register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_misa(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the mie register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_mie(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Reads the value of the mie register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_mie(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the mip register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_mip(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Reads the value of the mip register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_mip(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the medeleg register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_medeleg(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the medeleg register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_medeleg(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the mideleg register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_mideleg(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the mideleg register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_mideleg(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the mcounteren register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_mcounteren(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the mcounteren register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_mcounteren(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the stvec register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_stvec(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the stvec register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_stvec(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the sscratch register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_sscratch(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the sscratch register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_sscratch(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the sepc register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_sepc(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the sepc register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_sepc(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the scause register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_scause(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the scause register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_scause(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the stval register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_stval(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the stval register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_stval(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the satp register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_satp(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the satp register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_satp(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the scounteren register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_scounteren(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the scounteren register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_scounteren(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the senvcfg register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_senvcfg(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the senvcfg register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_senvcfg(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the ilrsc register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_ilrsc(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the ilrsc register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_ilrsc(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the iflags register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_iflags(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Returns packed iflags from its component fields.
/// \param val Receives value of the register.
CM_API uint64_t cm_packed_iflags(int PRV, int X, int Y, int H);

/// \brief Reads the value of the iflags register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_iflags(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of HTIF's tohost register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_htif_tohost(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Reads the value of the device field of HTIF's tohost register.
/// \param m Pointer to valid machine instance
/// \param val Receives the value of the field
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_htif_tohost_dev(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Reads the value of the command field of HTIF's tohost register.
/// \param m Pointer to valid machine instance
/// \param val Receives the value of the field
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_htif_tohost_cmd(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Reads the value of the data field of HTIF's tohost register.
/// \param m Pointer to valid machine instance
/// \param val Receives the value of the field
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_htif_tohost_data(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of HTIF's tohost register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_htif_tohost(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of HTIF's fromhost register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_htif_fromhost(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of HTIF's fromhost register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_htif_fromhost(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Writes the value of the data field in HTIF's fromhost register.
/// \param m Pointer to valid machine instance
/// \param val New value for the field.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_htif_fromhost_data(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of HTIF's halt register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_htif_ihalt(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of HTIF's halt register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_htif_ihalt(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of HTIF's console register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_htif_iconsole(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of HTIF's console register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_htif_iconsole(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of HTIF's yield register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_htif_iyield(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of HTIF's yield register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_htif_iyield(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of CLINT's mtimecmp register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_clint_mtimecmp(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of CLINT's mtimecmp register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_clint_mtimecmp(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Checks the value of the iflags_X flag.
/// \param m Pointer to valid machine instance
/// \param val Receives the flag value
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_iflags_X(const cm_machine *m, bool *val, char **err_msg);

/// \brief Resets the value of the iflags_X flag.
/// \param m Pointer to valid machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_reset_iflags_X(cm_machine *m, char **err_msg);

/// \brief Sets the iflags_X flag.
/// \param m Pointer to valid machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_set_iflags_X(cm_machine *m, char **err_msg);

/// \brief Checks the value of the iflags_Y flag.
/// \param m Pointer to valid machine instance
/// \param val Receives the flag value
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_iflags_Y(const cm_machine *m, bool *val, char **err_msg);

/// \brief Resets the value of the iflags_Y flag.
/// \param m Pointer to valid machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_reset_iflags_Y(cm_machine *m, char **err_msg);

/// \brief Sets the iflags_Y flag.
/// \param m Pointer to valid machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_set_iflags_Y(cm_machine *m, char **err_msg);

/// \brief Checks the value of the iflags_H flag.
/// \param m Pointer to valid machine instance
/// \param val Receives the flag value
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_iflags_H(const cm_machine *m, bool *val, char **err_msg);

/// \brief Sets the iflags_H flag.
/// \param m Pointer to valid machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_set_iflags_H(cm_machine *m, char **err_msg);

/// \brief Verify if dirty page maps are consistent.
/// \param m Pointer to valid machine instance
/// \param result True if dirty page maps are consistent, false if there is an error.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_verify_dirty_page_maps(const cm_machine *m, bool *result, char **err_msg);

/// \brief Returns copy of initialization config.
/// \param m Pointer to valid machine instance
/// \param config Receives the initial configuration.
/// It should be deleted with cm_delete_machine_config.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
/// \details Object acquired from this function must not be changed and
/// must be deleted with cm_delete_machine_config
CM_API int cm_get_initial_config(const cm_machine *m, const cm_machine_config **config, char **err_msg);

/// \brief Returns copy of default system config.
/// \param config Receives the default configuration.
/// It should be deleted with cm_delete_machine_config
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
/// \details Object acquired from this function must not be changed and
/// must be deleted with cm_delete_machine_config
CM_API int cm_get_default_config(const cm_machine_config **config, char **err_msg);

/// \brief Replaces a memory range
/// \param m Pointer to valid machine instance
/// \param new_range Configuration of the new memory range
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
/// \details The machine must contain an existing memory range matching the start and length specified in new_range
CM_API int cm_replace_memory_range(cm_machine *m, const cm_memory_range_config *new_range, char **err_msg);

/// \brief Deletes a machine memory range config
/// \returns void
CM_API void cm_delete_memory_range_config(const cm_memory_range_config *config);

/// \brief Deletes the error message
/// \param err_msg Pointer to error message received from some other function
/// \details This C API is meant to be used for various language bindings.
/// Many of them could not directly call C free function,
/// so this is a convenience function for cleanup of error messages
CM_API void cm_delete_cstring(const char *err_msg);

/// \brief Deletes machine runtime config
/// \returns void
CM_API void cm_delete_machine_runtime_config(const cm_machine_runtime_config *config);

/// \brief Deletes allocated microarchitecture ram config
/// \returns void
CM_API void cm_delete_uarch_ram_config(const cm_uarch_ram_config *config);

/// \brief Deletes allocated dhd microarchitecture config
/// \returns void
CM_API void cm_delete_uarch_config(const cm_uarch_config *config);

/// \brief Deletes semantic version instance
/// \param m Valid pointer to the existing semantic version instance
CM_API void cm_delete_semantic_version(const cm_semantic_version *version);

/// \brief Destroys machine
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_destroy(cm_machine *m, char **err_msg);

/// \brief Do a snapshot of the machine
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_snapshot(cm_machine *m, char **err_msg);

/// \brief Performs rollback
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_rollback(cm_machine *m, char **err_msg);

/// \brief Reads the value of a microarchitecture general-purpose register.
/// \param m Pointer to valid machine instance
/// \param i Register index. Between 0 and UARCH_X_REG_COUNT-1, inclusive.
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_uarch_x(const cm_machine *m, int i, uint64_t *val, char **err_msg);

/// \brief Writes the value of a microarchitecture general-purpose register.
/// \param m Pointer to valid machine instance
/// \param i Register index. Between 1 and UARCH_X_REG_COUNT-1, inclusive.
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_uarch_x(cm_machine *m, int i, uint64_t val, char **err_msg);

/// \brief Reads the value of the microarchitecture pc register.
/// \param m Pointer to valid machine instance
/// \param val Receives the value of the register
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_uarch_pc(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the microarchitecture pc register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_uarch_pc(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Reads the value of the microarchitecture cycle register.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the register.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_read_uarch_cycle(const cm_machine *m, uint64_t *val, char **err_msg);

/// \brief Writes the value of the microarchitecture cycle register.
/// \param m Pointer to valid machine instance
/// \param val New register value.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_write_uarch_cycle(cm_machine *m, uint64_t val, char **err_msg);

/// \brief Gets the value of the microarchitecture halt flag.
/// \param m Pointer to valid machine instance
/// \param val Receives value of the halt flag.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for success, non zero code for error
CM_API int cm_read_uarch_halt_flag(const cm_machine *m, bool *val, char **err_msg);

/// \brief Sets the value of the microarchitecture halt flag.
/// \param m Pointer to valid machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for success, non zero code for error
CM_API int cm_set_uarch_halt_flag(cm_machine *m, char **err_msg);

/// \brief Resets the value of the microarchitecture halt flag.
/// \param m Pointer to valid machine instance
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for success, non zero code for error
CM_API int cm_reset_uarch(cm_machine *m, char **err_msg);

/// \brief Resets the value of the microarchitecture halt flag.
/// \param m Pointer to valid machine instance
/// \param log_type Type of access log to generate.
/// \param one_based Use 1-based indices when reporting errors.
/// \param access_log Receives the state access log.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successfull function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring
/// \returns 0 for success, non zero code for error
CM_API int cm_log_uarch_reset(cm_machine *m, cm_access_log_type log_type, bool one_based, cm_access_log **access_log,
    char **err_msg);

/// \brief Runs the machine in the microarchitecture until the mcycle advances by one unit or the micro cycles counter
/// (uarch_cycle) reaches uarch_cycle_end
/// \param m Pointer to valid machine instance
/// \param mcycle_end End cycle value
/// \param status_result Receives status of machine run_uarch when not NULL
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_machine_run_uarch(cm_machine *m, uint64_t uarch_cycle_end, CM_UARCH_BREAK_REASON *status_result,
    char **err_msg);

/// \brief Returns an array with the description of each memory range in the machine.
/// \param m Pointer to valid machine instance
/// \param mrda Receives pointer to array of memory range descriptions. Must be deleted by the function caller using
/// cm_delete_memory_range_descr_array.
/// \param err_msg Receives the error message if function execution fails
/// or NULL in case of successful function execution. In case of failure error_msg
/// must be deleted by the function caller using cm_delete_cstring.
/// err_msg can be NULL, meaning the error message won't be received.
/// \returns 0 for success, non zero code for error
CM_API int cm_get_memory_ranges(cm_machine *m, cm_memory_range_descr_array **mrda, char **err_msg);

/// \brief Delete memory range description array acquired from cm_get_memory_ranges.
/// \param mrda Pointer to array of memory range descriptions to delete.
/// \returns void
CM_API void cm_delete_memory_range_descr_array(cm_memory_range_descr_array *mrda);

#ifdef __cplusplus
}
#endif

#endif // CM_C_API_H
