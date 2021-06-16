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

#include <alloca.h>
#include <cstring>
#include <iostream>
#include <exception>
#include <stdexcept>
#include <future>
#include <optional>
#include <regex>
#include <ios>
#include <filesystem>
#include <any>

#include "machine-c-api.h"
#include "riscv-constants.h"
#include "machine-config.h"
#include "machine.h"



// Various cpp - c conversion functions
// Overloads for various classes
// Important:
// convert_from_c C structures are returned by value
// convert_from_c_al C structures are returned as malloced pointers and need to be manually deallocated
// and require manual free

///brief Error codes returned from machine emulator C API
enum CM_ERROR {
    CM_ERROR_OK = 0,
    //Logic errors
    CM_ERROR_INVALID_ARGUMENT = 1,
    CM_ERROR_DOMAIN_ERROR = 2,
    CM_ERROR_LENGTH_ERROR = 3,
    CM_ERROR_OUT_OF_RANGE = 4,
    CM_ERROR_FUTURE_ERROR = 5,
    CM_ERROR_LOGIC_ERROR = 6,
    // Bad optional access error
    CM_ERROR_BAD_OPTIONAL_ACCESS = 7,
    // Runtime errors
    CM_ERROR_RUNTIME_ERROR = 10,
    CM_ERROR_RANGE_ERROR = 11,
    CM_ERROR_OVERFLOW_ERROR = 12,
    CM_ERROR_UNDERFLOW_ERROR = 13,
    CM_ERROR_REGEX_ERROR = 14,
    CM_ERROR_SYSTEM_IOS_BASE_FAILURE = 15,
    CM_ERROR_FILESYSTEM_ERROR = 16,
    CM_ERROR_ATOMIC_TX_ERROR = 17,
    CM_ERROR_NONEXISTING_LOCAL_TIME = 18,
    CM_ERROR_AMBIGOUS_LOCAL_TIME = 19,
    CM_ERROR_FORMAT_ERROR = 20,
    //Other errors
    CM_ERROR_BAD_TYPEID = 30,
    CM_ERROR_BAD_CAST = 31,
    CM_ERROR_BAD_ANY_CAST = 32,
    CM_ERROR_BAD_WEAK_PTR = 33,
    CM_ERROR_BAD_FUNCTION_CALL = 34,
    CM_ERROR_BAD_ALLOC = 35,
    CM_ERROR_BAD_ARRAY_NEW_LENGTH = 36,
    CM_ERROR_BAD_EXCEPTION = 37,
    CM_ERROR_BAD_VARIANT_ACCESS = 38,
    //C API Errors
    CM_ERROR_UNKNOWN = 40,

};


static char *get_error_message_ok() {
    return strdup("OK");
}

static char *get_error_message_unknown() {
    return strdup("Unknown error");
}

static char *get_error_message(const std::exception &ex) {
    return strdup(ex.what());
}

/// \warning: This function rethrows current exception, so it must be called
/// from the catch error handling block
static void convert_cpp_error(const std::exception &cpp_error, int *error_code, char **error_message) {
    try {
        std::rethrow_exception(std::current_exception());
    } catch (std::invalid_argument &ex) {
        *error_code = CM_ERROR_INVALID_ARGUMENT;
    } catch (std::domain_error &ex) {
        *error_code = CM_ERROR_DOMAIN_ERROR;
    } catch (std::length_error &ex) {
        *error_code = CM_ERROR_LENGTH_ERROR;
    } catch (std::out_of_range &ex) {
        *error_code = CM_ERROR_OUT_OF_RANGE;
    }
    catch (std::future_error &ex) {
        *error_code = CM_ERROR_FUTURE_ERROR;
    }
    catch (std::logic_error &ex) {
        *error_code = CM_ERROR_LOGIC_ERROR;
    }
    catch (std::bad_optional_access &ex) {
        *error_code = CM_ERROR_BAD_OPTIONAL_ACCESS;
    }
    catch (std::range_error &ex) {
        *error_code = CM_ERROR_RANGE_ERROR;
    }
    catch (std::overflow_error &ex) {
        *error_code = CM_ERROR_OVERFLOW_ERROR;
    }
    catch (std::underflow_error &ex) {
        *error_code = CM_ERROR_UNDERFLOW_ERROR;
    }
    catch (std::regex_error &ex) {
        *error_code = CM_ERROR_REGEX_ERROR;
    }
    catch (std::ios_base::failure &ex) {
        *error_code = CM_ERROR_SYSTEM_IOS_BASE_FAILURE;
    }
    catch (std::filesystem::filesystem_error &ex) {
        *error_code = CM_ERROR_FILESYSTEM_ERROR;
    }
    catch (std::runtime_error &ex) {
        *error_code = CM_ERROR_RUNTIME_ERROR;
    }
    catch (std::bad_typeid &ex) {
        *error_code = CM_ERROR_BAD_TYPEID;
    }
    catch (std::bad_any_cast &ex) {
        *error_code = CM_ERROR_BAD_ANY_CAST;
    }
    catch (std::bad_cast &ex) {
        *error_code = CM_ERROR_BAD_CAST;
    }
    catch (std::bad_weak_ptr &ex) {
        *error_code = CM_ERROR_BAD_WEAK_PTR;
    }
    catch (std::bad_function_call &ex) {
        *error_code = CM_ERROR_BAD_FUNCTION_CALL;
    }
    catch (std::bad_array_new_length &ex) {
        *error_code = CM_ERROR_BAD_ARRAY_NEW_LENGTH;
    }
    catch (std::bad_alloc &ex) {
        *error_code = CM_ERROR_BAD_ALLOC;
    }
    catch (std::bad_exception &ex) {
        *error_code = CM_ERROR_BAD_EXCEPTION;
    }
    catch (...) {
        *error_code = CM_ERROR_UNKNOWN;
    }
    *error_message = get_error_message(cpp_error);
}


static std::string null_to_empty(const char *s) {
    return std::string{s != NULL ? s : ""};
}


// --------------------------------------------
// Processor configuration conversion functions
// --------------------------------------------
static cartesi::processor_config convert_from_c(const cm_processor_config *c_config) {
    cartesi::processor_config new_cpp_config{};
    //Both C and C++ structs contain only aligned uint64_t values
    //so it is safe to do copy
    assert(sizeof(cm_processor_config) == sizeof(new_cpp_config));
    memmove(&new_cpp_config.x, c_config, sizeof(cm_processor_config));
    return new_cpp_config;
}

static cm_processor_config convert_to_c(const cartesi::processor_config &cpp_config) {
    cm_processor_config new_c_config;
    memset(&new_c_config, 0, sizeof(cm_processor_config));

    assert(sizeof(new_c_config) == sizeof(cpp_config));
    memmove(&new_c_config, &cpp_config.x, sizeof(cm_processor_config));
    return new_c_config;
}


// --------------------------------------------
// Ram configuration conversion functions
// --------------------------------------------
static cartesi::ram_config convert_from_c(const cm_ram_config *c_config) {

    cartesi::ram_config new_cpp_ram_config{};
    new_cpp_ram_config.length = c_config->length;
    new_cpp_ram_config.image_filename = null_to_empty(c_config->image_filename);
    return new_cpp_ram_config;
}

static cm_ram_config convert_to_c(const cartesi::ram_config &cpp_config) {

    cm_ram_config new_c_ram_config;
    memset(&new_c_ram_config, 0, sizeof(cm_ram_config));
    new_c_ram_config.length = cpp_config.length;
    new_c_ram_config.image_filename = strdup(cpp_config.image_filename.c_str());
    return new_c_ram_config;
}

// --------------------------------------------
// Rom configuration conversion functions
// --------------------------------------------

static cartesi::rom_config convert_from_c(const cm_rom_config *c_config) {
    assert(c_config != NULL);
    cartesi::rom_config new_cpp_rom_config{};
    new_cpp_rom_config.bootargs = null_to_empty(c_config->bootargs);
    new_cpp_rom_config.image_filename = null_to_empty(c_config->image_filename);
    return new_cpp_rom_config;
}

static cm_rom_config convert_to_c(const cartesi::rom_config &cpp_config) {
    cm_rom_config new_c_rom_config;
    memset(&new_c_rom_config, 0, sizeof(cm_rom_config));
    new_c_rom_config.bootargs = strdup(cpp_config.bootargs.c_str());
    new_c_rom_config.image_filename = strdup(cpp_config.image_filename.c_str());
    return new_c_rom_config;
}


// ----------------------------------------------
// Flash drive configuration conversion functions
// ----------------------------------------------
static cartesi::flash_drive_config convert_from_c(const cm_flash_drive_config *c_config) {
    cartesi::flash_drive_config new_cpp_flash_drive_config{
            c_config->start,
            c_config->length,
            c_config->shared,
            c_config->image_filename
    };
    return new_cpp_flash_drive_config;
}

static cm_flash_drive_config convert_to_c(const cartesi::flash_drive_config &cpp_config) {

    cm_flash_drive_config new_c_flash_drive_config;
    memset(&new_c_flash_drive_config, 0, sizeof(cm_flash_drive_config));
    new_c_flash_drive_config.start = cpp_config.start;
    new_c_flash_drive_config.length = cpp_config.length;
    new_c_flash_drive_config.shared = cpp_config.shared;
    new_c_flash_drive_config.image_filename = strdup(cpp_config.image_filename.c_str());
    return new_c_flash_drive_config;
}


// ----------------------------------------------
// Clint configuration conversion functions
// ----------------------------------------------
static cartesi::clint_config convert_from_c(const cm_clint_config *c_config) {
    cartesi::clint_config new_cpp_clint_config{};
    new_cpp_clint_config.mtimecmp = c_config->mtimecmp;
    return new_cpp_clint_config;
}

static cm_clint_config convert_to_c(const cartesi::clint_config &cpp_config) {

    cm_clint_config new_c_clint_config;
    memset(&new_c_clint_config, 0, sizeof(cm_clint_config));
    new_c_clint_config.mtimecmp = cpp_config.mtimecmp;
    return new_c_clint_config;
}

// ----------------------------------------------
// HTIF configuration conversion functions
// ----------------------------------------------
static cartesi::htif_config convert_from_c(const cm_htif_config *c_config) {
    cartesi::htif_config new_cpp_htif_config{};
    new_cpp_htif_config.fromhost = c_config->fromhost;
    new_cpp_htif_config.tohost = c_config->tohost;
    new_cpp_htif_config.console_getchar = c_config->console_getchar;
    new_cpp_htif_config.yield_progress = c_config->yield_progress;
    new_cpp_htif_config.yield_rollup = c_config->yield_rollup;

    return new_cpp_htif_config;
}

static cm_htif_config convert_to_c(const cartesi::htif_config &cpp_config) {

    cm_htif_config new_c_htif_config;
    memset(&new_c_htif_config, 0, sizeof(cm_htif_config));
    new_c_htif_config.fromhost = cpp_config.fromhost;
    new_c_htif_config.tohost = cpp_config.tohost;
    new_c_htif_config.console_getchar = cpp_config.console_getchar;
    new_c_htif_config.yield_progress = cpp_config.yield_progress;
    new_c_htif_config.yield_rollup = cpp_config.yield_rollup;
    return new_c_htif_config;
}


// ----------------------------------------------
// HTIF configuration conversion functions
// ----------------------------------------------
static cartesi::dhd_config convert_from_c(const cm_dhd_config *c_config) {
    cartesi::dhd_config new_cpp_dhd_config;
    new_cpp_dhd_config.tstart = c_config->tstart;
    new_cpp_dhd_config.tlength = c_config->tlength;
    new_cpp_dhd_config.image_filename = null_to_empty(c_config->image_filename);
    new_cpp_dhd_config.dlength = c_config->dlength;
    new_cpp_dhd_config.hlength = c_config->hlength;

    assert(sizeof(new_cpp_dhd_config.h) == sizeof(c_config->h));
    memmove(&new_cpp_dhd_config.h, &c_config->h, sizeof(uint64_t) * CM_MACHINE_DHD_H_REG_COUNT);

    return new_cpp_dhd_config;
}

static cm_dhd_config convert_to_c(const cartesi::dhd_config &cpp_config) {

    cm_dhd_config new_c_dhd_config;
    memset(&new_c_dhd_config, 0, sizeof(cm_dhd_config));
    new_c_dhd_config.tstart = cpp_config.tstart;
    new_c_dhd_config.tlength = cpp_config.tlength;
    new_c_dhd_config.image_filename = strdup(cpp_config.image_filename.c_str());
    new_c_dhd_config.dlength = cpp_config.dlength;
    new_c_dhd_config.hlength = cpp_config.hlength;

    assert(sizeof(new_c_dhd_config.h) == sizeof(cpp_config.h));
    memmove(&new_c_dhd_config.h, &cpp_config.h, sizeof(uint64_t) * CM_MACHINE_DHD_H_REG_COUNT);
    return new_c_dhd_config;
}


// ----------------------------------------------
// Runtime configuration conversion functions
// ----------------------------------------------
static cartesi::machine_runtime_config convert_from_c(const cm_machine_runtime_config *c_config) {
    cartesi::machine_runtime_config new_cpp_machine_runtime_config{
            cartesi::dhd_runtime_config{std::string{c_config->dhd.source_address}},
            cartesi::concurrency_config{c_config->concurrency.update_merkle_tree}
    };

    return new_cpp_machine_runtime_config;
}

// ----------------------------------------------
// Configuration conversion functions
// ----------------------------------------------
static cartesi::machine_config convert_from_c(const cm_machine_config *c_config) {
    cartesi::processor_config processor = convert_from_c(&c_config->processor);
    cartesi::ram_config ram = convert_from_c(&c_config->ram);
    cartesi::rom_config rom = convert_from_c(&c_config->rom);
    cartesi::flash_drive_configs flash_configs{};
    for (int i = 0; i < c_config->flash_drive_count; ++i) {
        flash_configs.push_back(convert_from_c(&(c_config->flash_drive[i])));
    }
    cartesi::clint_config clint = convert_from_c(&c_config->clint);
    cartesi::htif_config htif = convert_from_c(&c_config->htif);
    cartesi::dhd_config dhd = convert_from_c(&c_config->dhd);


    cartesi::machine_config new_cpp_machine_config{};
    new_cpp_machine_config.processor = processor;
    new_cpp_machine_config.ram = ram;
    new_cpp_machine_config.rom = rom;
    new_cpp_machine_config.flash_drive = flash_configs;
    new_cpp_machine_config.clint = clint;
    new_cpp_machine_config.htif = htif;
    new_cpp_machine_config.dhd = dhd;

    return new_cpp_machine_config;
}

static const cm_machine_config *convert_to_c(cartesi::machine_config &cpp_config) {
    cm_machine_config *new_machine_config = static_cast<cm_machine_config *>
            (malloc(sizeof(cm_machine_config)));
    memset(new_machine_config, 0, sizeof(cm_machine_config));

    new_machine_config->processor = convert_to_c(cpp_config.processor);
    new_machine_config->ram = convert_to_c(cpp_config.ram);
    new_machine_config->rom = convert_to_c(cpp_config.rom);
    new_machine_config->flash_drive_count = cpp_config.flash_drive.size();
    new_machine_config->flash_drive = new cm_flash_drive_config[cpp_config.flash_drive.size()];
    memset(new_machine_config->flash_drive, 0, sizeof(cm_flash_drive_config) * new_machine_config->flash_drive_count);
    new_machine_config->clint = convert_to_c(cpp_config.clint);
    new_machine_config->htif = convert_to_c(cpp_config.htif);
    new_machine_config->dhd = convert_to_c(cpp_config.dhd);

    return new_machine_config;
}

// ----------------------------------------------
// Machine conversion functions
// ----------------------------------------------

static cartesi::machine *convert_from_c(cm_machine *m) {
    return static_cast<cartesi::machine *>(m);
}

static const cartesi::machine *convert_from_c(const cm_machine *m) {
    return static_cast<const cartesi::machine *>(m);
}

// ----------------------------------------------
// Merkle tree proof conversion functions
// ----------------------------------------------

/// \brief Converts log2_size to index into siblings array
static int cm_log2_size_to_index(int log2_size, int log2_root_size) {
    // We know log2_root_size > 0, so log2_root_size-1 >= 0
    int index = log2_root_size - 1 - log2_size;
    return index;
}

cm_merkle_tree_proof *convert_to_c(const cartesi::machine_merkle_tree::proof_type &proof) {
    cm_merkle_tree_proof *new_merkle_tree_proof = static_cast<cm_merkle_tree_proof *>
    (malloc(sizeof(cm_merkle_tree_proof)));
    memset(new_merkle_tree_proof, 0, sizeof(cm_merkle_tree_proof));

    new_merkle_tree_proof->log2_root_size = proof.get_log2_root_size();
    new_merkle_tree_proof->log2_target_size = proof.get_log2_target_size();
    new_merkle_tree_proof->target_address = proof.get_target_address();

    memmove(&new_merkle_tree_proof->root_hash, static_cast<const uint8_t *>(proof.get_root_hash().data()), sizeof(cm_hash));
    memmove(&new_merkle_tree_proof->target_hash, static_cast<const uint8_t *>(proof.get_target_hash().data()), sizeof(cm_hash));

    new_merkle_tree_proof->sibling_hashes_size = new_merkle_tree_proof->log2_root_size - new_merkle_tree_proof->log2_target_size;
    new_merkle_tree_proof->sibling_hashes = new cm_hash[new_merkle_tree_proof->sibling_hashes_size];
    memset(new_merkle_tree_proof->sibling_hashes, 0, sizeof(cm_hash) * new_merkle_tree_proof->sibling_hashes_size);


    for (int log2_size = new_merkle_tree_proof->log2_target_size;
         log2_size < new_merkle_tree_proof->log2_root_size; ++log2_size) {
        int current_index = cm_log2_size_to_index(log2_size, new_merkle_tree_proof->log2_root_size);
        const cartesi::machine_merkle_tree::hash_type sibling_hash = proof.get_sibling_hash(log2_size);
        memmove(&(new_merkle_tree_proof->sibling_hashes[current_index]),
                static_cast<const uint8_t *>(sibling_hash.data()), sizeof(cm_hash));
    }

    return new_merkle_tree_proof;
}


// -----------------------------------------------------
// Public API functions for generation of default configs
// -----------------------------------------------------
const cm_machine_config *cm_new_default_machine_config() {
    cartesi::machine_config cpp_config = cartesi::machine::get_default_config();

    return convert_to_c(cpp_config);
}

void cm_delete_machine_config(const cm_machine_config *config) {

    free(const_cast<char *>(config->dhd.image_filename));
    free(const_cast<char *>(config->rom.image_filename));
    delete[] config->flash_drive;
    free(const_cast<char *>(config->rom.bootargs));
    free(const_cast<char *>(config->ram.image_filename));

    free(const_cast<cm_machine_config *>(config));
}


int cm_create_machine(const cm_machine_config *config, const cm_machine_runtime_config *runtime_config,
                      cm_machine **new_machine, char **err_msg) {
    try {
        const cartesi::machine_config c = convert_from_c(config);
        const cartesi::machine_runtime_config r = convert_from_c(runtime_config);
        cartesi::machine *m = new cartesi::machine(c, r);
        *new_machine = static_cast<cm_machine *>(m);
        *err_msg = NULL;
        return 0;
    } catch (std::exception &ex) {
        int error_code;
        convert_cpp_error(ex, &error_code, err_msg);
        return error_code;
    } catch (...) {
        *err_msg = get_error_message_unknown();
        return CM_ERROR_UNKNOWN;
    }
}

int
cm_create_machine_from_dir(const char *dir, const cm_machine_runtime_config *runtime_config, cm_machine **new_machine,
                           char **err_msg) {
    try {
        const cartesi::machine_runtime_config r = convert_from_c(runtime_config);
        cartesi::machine *m = new cartesi::machine(std::string{dir}, r);
        *new_machine = static_cast<cm_machine *>(m);
        *err_msg = NULL;
        return 0;
    } catch (std::exception &ex) {
        int error_code;
        convert_cpp_error(ex, &error_code, err_msg);
        return error_code;
    } catch (...) {
        *err_msg = get_error_message_unknown();
        return CM_ERROR_UNKNOWN;
    }
}

int cm_store(cm_machine *m, const char *dir, char **err_msg) {
    try {
        cartesi::machine *cpp_machine = convert_from_c(m);
        cpp_machine->store(std::string{dir});
        *err_msg = NULL;
        return 0;
    } catch (std::exception &ex) {
        int error_code;
        convert_cpp_error(ex, &error_code, err_msg);
        return error_code;
    } catch (...) {
        *err_msg = get_error_message_unknown();
        return CM_ERROR_UNKNOWN;
    }
}

void cm_delete_machine(cm_machine *m) {
    cartesi::machine *car_machine = static_cast<cartesi::machine *>(m);
    delete car_machine;
}

int cm_machine_run(cm_machine *m, uint64_t mcycle_end, char **err_msg) {

    cartesi::machine *cpp_machine = convert_from_c(m);
    try {
        cpp_machine->run(mcycle_end);
        *err_msg = NULL;
        return 0;
    } catch (std::exception &ex) {
        int error_code;
        convert_cpp_error(ex, &error_code, err_msg);
        return error_code;
    } catch (...) {
        *err_msg = get_error_message_unknown();
        return CM_ERROR_UNKNOWN;
    }
}

int cm_update_merkle_tree(cm_machine *m, char **err_msg) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    try {
        bool result = cpp_machine->update_merkle_tree();
        if (result) {
            *err_msg = NULL;
            return 0;
        } else {
            *err_msg = get_error_message_unknown();
            return CM_ERROR_UNKNOWN;
        }
    } catch (std::exception &ex) {
        int error_code;
        convert_cpp_error(ex, &error_code, err_msg);
        return error_code;
    } catch (...) {
        *err_msg = get_error_message_unknown();
        return CM_ERROR_UNKNOWN;
    }
}

int cm_get_proof(const cm_machine *m, uint64_t address, int log2_size, cm_merkle_tree_proof **proof, char **err_msg) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    try {
        const cartesi::machine_merkle_tree::proof_type cpp_proof = cpp_machine->get_proof(address, log2_size);
        *proof = convert_to_c(cpp_proof);
        *err_msg = NULL;
        return 0;
    } catch (std::exception &ex) {
        int error_code;
        convert_cpp_error(ex, &error_code, err_msg);
        return error_code;
    } catch (...) {
        *err_msg = get_error_message_unknown();
        return CM_ERROR_UNKNOWN;
    }
}

void cm_delete_proof(cm_merkle_tree_proof *proof) {
    delete[] proof->sibling_hashes;
    free(proof);
}

void cm_get_root_hash(const cm_machine *m, cm_hash *hash) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    cartesi::machine_merkle_tree::hash_type cpp_hash;
    cpp_machine->get_root_hash(cpp_hash);
    memmove(hash, static_cast<const uint8_t *>(cpp_hash.data()), sizeof(cm_hash));
}

bool cm_verify_merkle_tree(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->verify_merkle_tree();
}

uint64_t cm_read_csr(const cm_machine *m, CM_PROC_CSR r) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    cartesi::machine::csr cpp_csr = static_cast<cartesi::machine::csr>(r);
    return cpp_machine->read_csr(cpp_csr);
}

void cm_write_csr(cm_machine *m, CM_PROC_CSR w, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cartesi::machine::csr cpp_csr = static_cast<cartesi::machine::csr>(w);
    cpp_machine->write_csr(cpp_csr, val);
}

uint64_t cm_get_csr_address(CM_PROC_CSR w) {
    cartesi::machine::csr cpp_csr = static_cast<cartesi::machine::csr>(w);
    return cartesi::machine::get_csr_address(cpp_csr);
}

bool cm_read_word(const cm_machine *m, uint64_t word_address, uint64_t *word_value) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    uint64_t cpp_word_value{0};
    if (cpp_machine->read_word(word_address, cpp_word_value)) {
        *word_value = cpp_word_value;
        return true;
    } else {
        return false;
    }
}

void cm_read_memory(const cm_machine *m, uint64_t address, unsigned char *data, uint64_t length) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->read_memory(address, data, length);
}

void cm_write_memory(cm_machine *m, uint64_t address, const unsigned char *data, size_t length) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_memory(address, data, length);
}

uint64_t cm_read_x(const cm_machine *m, int i) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_x(i);
}

void cm_write_x(cm_machine *m, int i, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_x(i, val);
}

uint64_t cm_get_x_address(int i) {
    return cartesi::machine::get_x_address(i);
}

uint64_t cm_read_pc(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_pc();
}

void cm_write_pc(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_pc(val);
}

uint64_t cm_read_mvendorid(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_mvendorid();
}

uint64_t cm_read_marchid(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_marchid();
}

uint64_t cm_read_mimpid(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_mimpid();
}

uint64_t cm_read_mcycle(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_mcycle();
}

void cm_write_mcycle(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_mcycle(val);
}

uint64_t cm_read_minstret(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_minstret();
}

void cm_write_minstret(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_minstret(val);
}

uint64_t cm_read_mstatus(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_mstatus();
}

void cm_write_mstatus(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_mstatus(val);
}

uint64_t cm_read_mtvec(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_mtvec();
}

void cm_write_mtvec(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_mtvec(val);
}

uint64_t cm_read_mscratch(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_mscratch();
}

void cm_write_mscratch(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_mscratch(val);
}

uint64_t cm_read_mepc(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_mepc();
}

void cm_write_mepc(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_mepc(val);
}

uint64_t cm_read_mcause(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_mcause();
}

void cm_write_mcause(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_mcause(val);
}

uint64_t cm_read_mtval(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_mtval();
}

void cm_write_mtval(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_mtval(val);
}

uint64_t cm_read_misa(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_misa();
}

void cm_write_misa(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_misa(val);
}

uint64_t cm_read_mie(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_mie();
}

void cm_write_mie(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_mie(val);
}

uint64_t cm_read_mip(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_mip();
}

void cm_write_mip(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_mip(val);
}

uint64_t cm_read_medeleg(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_medeleg();
}

void cm_write_medeleg(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_medeleg(val);
}

uint64_t cm_read_mideleg(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_mideleg();
}

void cm_write_mideleg(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_mideleg(val);
}

uint64_t cm_read_mcounteren(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_mcounteren();
}

void cm_write_mcounteren(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_mcounteren(val);
}

uint64_t cm_read_stvec(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_stvec();
}

void cm_write_stvec(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_stvec(val);
}

uint64_t cm_read_sscratch(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_sscratch();
}

void cm_write_sscratch(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_sscratch(val);
}

uint64_t cm_read_sepc(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_sepc();
}

void cm_write_sepc(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_sepc(val);
}

uint64_t cm_read_scause(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_scause();
}

void cm_write_scause(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_scause(val);
}

uint64_t cm_read_stval(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_stval();
}

void cm_write_stval(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_stval(val);
}

uint64_t cm_read_satp(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_satp();
}

void cm_write_satp(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_satp(val);
}

uint64_t cm_read_scounteren(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_scounteren();
}

void cm_write_scounteren(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_scounteren(val);
}

uint64_t cm_read_ilrsc(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_ilrsc();
}

void cm_write_ilrsc(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_ilrsc(val);
}

uint64_t cm_read_iflags(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_iflags();
}

uint64_t cm_packed_iflags(int PRV, int Y, int H) {
    return cartesi::machine_state::packed_iflags(PRV, Y, H);
}

void cm_write_iflags(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_iflags(val);
}

uint64_t cm_read_htif_tohost(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_htif_tohost();
}

uint64_t cm_read_htif_tohost_dev(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_htif_tohost_dev();
}

uint64_t cm_read_htif_tohost_cmd(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_htif_tohost_cmd();
}

uint64_t cm_read_htif_tohost_data(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_htif_tohost_data();
}

void cm_write_htif_tohost(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_htif_tohost(val);
}

uint64_t cm_read_htif_fromhost(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_htif_fromhost();
}

void cm_write_htif_fromhost(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_htif_fromhost(val);
}

void cm_write_htif_fromhost_data(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_htif_fromhost_data(val);
}

uint64_t cm_read_htif_ihalt(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_htif_ihalt();
}

void write_htif_ihalt(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_htif_ihalt(val);
}

uint64_t cm_read_htif_iconsole(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_htif_iconsole();
}

void cm_write_htif_iconsole(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_htif_iconsole(val);
}

uint64_t cm_read_htif_iyield(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_htif_iyield();
}

void cm_write_htif_iyield(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_htif_iyield(val);
}

uint64_t cm_read_clint_mtimecmp(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_clint_mtimecmp();
}

void cm_write_clint_mtimecmp(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_clint_mtimecmp(val);
}

uint64_t cm_read_dhd_tstart(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_dhd_tstart();
}

void cm_write_dhd_tstart(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_dhd_tstart(val);
}

uint64_t cm_read_dhd_tlength(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_dhd_tlength();
}

void cm_write_dhd_tlength(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_dhd_tlength(val);
}

uint64_t cm_read_dhd_dlength(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_dhd_dlength();
}

void cm_write_dhd_dlength(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_dhd_dlength(val);
}

uint64_t cm_read_dhd_hlength(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_dhd_hlength();
}

void cm_write_dhd_hlength(cm_machine *m, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_dhd_hlength(val);
}

void cm_write_dhd_h(cm_machine *m, int i, uint64_t val) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->write_dhd_h(i, val);
}

uint64_t cm_get_dhd_h_address(int i) {
    return cartesi::machine::get_dhd_h_address(i);
}

bool cm_read_iflags_Y(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_iflags_Y();
}

void cm_reset_iflags_Y(cm_machine *m) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->reset_iflags_Y();
}

void cm_set_iflags_Y(cm_machine *m) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->set_iflags_Y();
}

bool cm_read_iflags_H(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_iflags_H();
}

uint8_t cm_read_iflags_PRV(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->read_iflags_PRV();
}

void cm_set_iflags_H(cm_machine *m) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->set_iflags_H();
}

void cm_set_mip(cm_machine *m, uint32_t mask) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->set_mip(mask);
}

void cm_reset_mip(cm_machine *m, uint32_t mask) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->reset_mip(mask);
}

void cm_dump_pmas(const cm_machine *m) {
    //TODO add error handling here
    const cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->dump_pmas();
}

void cm_interact(cm_machine *m) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->interact();
}

bool cm_verify_dirty_page_maps(const cm_machine *m) {
    //TODO add error handling here, vector at can throw
    const cartesi::machine *cpp_machine = convert_from_c(m);
    return cpp_machine->verify_dirty_page_maps();
}

const cm_machine_config *cm_get_serialization_config(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    cartesi::machine_config cpp_config = cpp_machine->get_serialization_config();

    return convert_to_c(cpp_config);
}

const cm_machine_config *cm_get_initial_config(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    cartesi::machine_config cpp_config = cpp_machine->get_initial_config();

    return convert_to_c(cpp_config);
}