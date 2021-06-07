// Copyright 2021 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

/// \file
/// \brief Cartesi machine emulator C API interface

#ifndef CM_C_API_H
#define CM_C_API_H

#include <stdint.h>
#include <assert.h>

#ifndef __cplusplus
#include <stdbool.h>
#endif

#include "machine-c-defines.h"

#ifdef __cplusplus
extern "C" {
#if __GNUC__ >= 5
#pragma GCC visibility push(default)
#endif
#endif


// ---------------------------------
// API Structures
// ---------------------------------

typedef uint8_t cm_hash[CM_MACHINE_HASH_BYTE_SIZE];

typedef struct {
    uint64_t x[CM_MACHINE_X_REG_COUNT];          ///< Value of general-purpose registers
    uint64_t pc;                  ///< Value of pc
    uint64_t mvendorid;    ///< Value of mvendorid CSR
    uint64_t marchid;        ///< Value of marchid CSR
    uint64_t mimpid;          ///< Value of mimpid CSR
    uint64_t mcycle;          ///< Value of mcycle CSR
    uint64_t minstret;      ///< Value of minstret CSR
    uint64_t mstatus;        ///< Value of mstatus CSR
    uint64_t mtvec;            ///< Value of mtvec CSR
    uint64_t mscratch;      ///< Value of mscratch CSR
    uint64_t mepc;              ///< Value of mepc CSR
    uint64_t mcause;          ///< Value of mcause CSR
    uint64_t mtval;            ///< Value of mtval CSR
    uint64_t misa;              ///< Value of misa CSR
    uint64_t mie;                ///< Value of mie CSR
    uint64_t mip;                ///< Value of mip CSR
    uint64_t medeleg;        ///< Value of medeleg CSR
    uint64_t mideleg;        ///< Value of mideleg CSR
    uint64_t mcounteren;  ///< Value of mcounteren CSR
    uint64_t stvec;            ///< Value of stvec CSR
    uint64_t sscratch;      ///< Value of sscratch CSR
    uint64_t sepc;              ///< Value of sepc CSR
    uint64_t scause;          ///< Value of scause CSR
    uint64_t stval;            ///< Value of stval CSR
    uint64_t satp;              ///< Value of satp CSR
    uint64_t scounteren;  ///< Value of scounteren CSR
    uint64_t ilrsc;            ///< Value of ilrsc CSR
    uint64_t iflags;          ///< Value of iflags CSR
} cm_processor_config;

/// \brief RAM state configuration
typedef struct {
    uint64_t length; ///< RAM length
    const char* image_filename; ///< RAM image file name
} cm_ram_config;

/// \brief ROM state configuration
typedef struct {
    const char* bootargs; ///< Bootargs to pass to kernel
    const char* image_filename; ///< ROM image file
} cm_rom_config;

/// \brief Flash drive state configuration
typedef struct {
    uint64_t start;           ///< Flash drive start position
    uint64_t length;          ///< Flash drive length
    bool shared;              ///< Target changes to drive affect image file?
    const char* image_filename; ///< Flash drive image file name
} cm_flash_drive_config;

/// \brief CLINT device state configuration
typedef struct {
    uint64_t mtimecmp; ///< Value of mtimecmp CSR
} cm_clint_config;

/// \brief HTIF device state configuration
typedef struct {
    uint64_t fromhost; ///< Value of fromhost CSR
    uint64_t tohost;     ///< Value of tohost CSR
    bool console_getchar;      ///< Make console getchar available?
    bool yield_progress;       ///< Make yield progress available?
    bool yield_rollup;         ///< Make yield rollup available?
} cm_htif_config;

/// \brief DHD device state configuration
typedef struct {
    uint64_t tstart;           ///< Start of target physical memory range for output data
    uint64_t tlength;          ///< Length of target physical memory range for output data
    const char* image_filename; ///< Data image file name
    uint64_t dlength;          ///< Output data length CSR
    uint64_t hlength;          ///< Input hash length CSR
    uint64_t h[CM_MACHINE_DHD_H_REG_COUNT]; ///< Input hash words
}  cm_dhd_config;

/// \brief Machine state configuration
typedef struct {
    cm_processor_config processor;
    cm_ram_config ram;
    cm_rom_config rom;
    cm_flash_drive_config *flash_drive;
    int flash_drive_count;
    cm_clint_config clint;
    cm_htif_config htif;
    cm_dhd_config dhd;
} cm_machine_config;


/// \brief DHD runtime configuration
typedef struct {
    const char* source_address; ///< Address of dehash source
} cm_dhd_runtime_config;

/// \brief Concurrency runtime configuration
typedef struct {
    uint64_t update_merkle_tree;
} cm_concurrency_config;

/// \brief Machine runtime configuration
typedef struct {
    cm_dhd_runtime_config dhd;
    cm_concurrency_config concurrency;
} cm_machine_runtime_config;

/// \brief Machine instance handle
typedef void cm_machine;

/// \brief Machine operation error message
typedef const char* error_message;


// ---------------------------------
// API function definitions
// ---------------------------------


/// \brief Create new machine config with default parameters
/// \returns const m_machine_config* - pointer to new default config object
/// \details Object acquired from this function must not be changed and
/// must be deleted with cm_delete_machine_config. To make a custom config based
/// on default config user must make a deep copy of returned object members and then
/// customize
const cm_machine_config* cm_new_default_machine_config();

/// \brief Delete machine config acquired from cm_new_default_machine_config
/// \returns void
void cm_delete_machine_config(const cm_machine_config* config);


/// \brief Creates new machine instance from configuration
/// \param config is the machine configuration
/// \param runtime_config is machine runtime configuration
/// \param  new_machine receives the pointer to new machine instance
/// \param error_msg receives the message about result of the operation
/// \returns 0 for success, non zero code for error
int cm_create_machine(const cm_machine_config* config, const cm_machine_runtime_config* runtime_config,
                      cm_machine** new_machine, error_message *err_msg);

/// \brief Deletes machine instance
/// \param m valid pointer to the existing machine instance
void cm_delete_machine(cm_machine* m);


/// \brief Runs the machine until mcycle reaches mcycle_end or the machine halts.
/// \param  m pointer to valid machine instance
/// \param  mcycle_end end cycle value
/// \param error_msg receives the message about result of the operation
/// \returns 0 for success, non zero code for error
int cm_machine_run(cm_machine* m, uint64_t mcycle_end, error_message *err_msg);



/// \brief Reads the value of the mcycle CPU register.
/// \param m pointer to valid machine instance
/// \returns current mcycle value as uint64
uint64_t cm_read_mcycle(const cm_machine* m);


#ifdef __cplusplus

#if __GNUC__ >= 5
#pragma GCC visibility pop
#endif

}
#endif

#endif //CM_C_API_H
