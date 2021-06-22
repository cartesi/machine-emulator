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


static char *get_error_message_unknown() {
    const char* err = "Unknown error";
    char *c_str = new char[strlen(err)+1];
    strcpy(c_str, err);
    return c_str;
}

static char *get_error_message(const std::exception &ex) {
    const char* err = ex.what();
    char *c_str = new char[strlen(err)+1];
    strcpy(c_str, err);
    return c_str;
}

static std::string null_to_empty(const char *s) {
    return std::string{s != NULL ? s : ""};
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

// --------------------------------------------
// String conversion (strdup equivalent with new)
// --------------------------------------------
static char *convert_to_c(const std::string &cpp_str) {
    char *c_str = new char[cpp_str.size()+1];
    std::copy(cpp_str.begin(), cpp_str.end(), c_str);
    c_str[cpp_str.size()] = '\0';
    return c_str;
}


// --------------------------------------------
// Processor configuration conversion functions
// --------------------------------------------
static cartesi::processor_config convert_from_c(const cm_processor_config *c_config) {
    cartesi::processor_config new_cpp_config{};
    //Both C and C++ structs contain only aligned uint64_t values
    //so it is safe to do copy
    static_assert(sizeof(cm_processor_config) == sizeof(new_cpp_config));
    memcpy(&new_cpp_config.x, c_config, sizeof(cm_processor_config));
    return new_cpp_config;
}

static cm_processor_config convert_to_c(const cartesi::processor_config &cpp_config) {
    cm_processor_config new_c_config{};
    static_assert(sizeof(new_c_config) == sizeof(cpp_config));
    memcpy(&new_c_config, &cpp_config.x, sizeof(cm_processor_config));
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
    cm_ram_config new_c_ram_config{};
    new_c_ram_config.length = cpp_config.length;
    new_c_ram_config.image_filename = convert_to_c(cpp_config.image_filename);
    return new_c_ram_config;
}

// --------------------------------------------
// Rom configuration conversion functions
// --------------------------------------------

static cartesi::rom_config convert_from_c(const cm_rom_config *c_config) {
    cartesi::rom_config new_cpp_rom_config{};
    new_cpp_rom_config.bootargs = null_to_empty(c_config->bootargs);
    new_cpp_rom_config.image_filename = null_to_empty(c_config->image_filename);
    return new_cpp_rom_config;
}

static cm_rom_config convert_to_c(const cartesi::rom_config &cpp_config) {
    cm_rom_config new_c_rom_config{};
    new_c_rom_config.bootargs = convert_to_c(cpp_config.bootargs);
    new_c_rom_config.image_filename = convert_to_c(cpp_config.image_filename);
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
    cm_flash_drive_config new_c_flash_drive_config{};
    new_c_flash_drive_config.start = cpp_config.start;
    new_c_flash_drive_config.length = cpp_config.length;
    new_c_flash_drive_config.shared = cpp_config.shared;
    new_c_flash_drive_config.image_filename = convert_to_c(cpp_config.image_filename);
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
    cm_clint_config new_c_clint_config{};
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
    cm_htif_config new_c_htif_config{};
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
    cartesi::dhd_config new_cpp_dhd_config{};
    new_cpp_dhd_config.tstart = c_config->tstart;
    new_cpp_dhd_config.tlength = c_config->tlength;
    new_cpp_dhd_config.image_filename = null_to_empty(c_config->image_filename);
    new_cpp_dhd_config.dlength = c_config->dlength;
    new_cpp_dhd_config.hlength = c_config->hlength;

    assert(sizeof(new_cpp_dhd_config.h) == sizeof(c_config->h));
    memcpy(&new_cpp_dhd_config.h, &c_config->h, sizeof(uint64_t) * CM_MACHINE_DHD_H_REG_COUNT);

    return new_cpp_dhd_config;
}

static cm_dhd_config convert_to_c(const cartesi::dhd_config &cpp_config) {

    cm_dhd_config new_c_dhd_config{};
    new_c_dhd_config.tstart = cpp_config.tstart;
    new_c_dhd_config.tlength = cpp_config.tlength;
    new_c_dhd_config.image_filename = convert_to_c(cpp_config.image_filename);
    new_c_dhd_config.dlength = cpp_config.dlength;
    new_c_dhd_config.hlength = cpp_config.hlength;

    assert(sizeof(new_c_dhd_config.h) == sizeof(cpp_config.h));
    memcpy(&new_c_dhd_config.h, &cpp_config.h, sizeof(uint64_t) * CM_MACHINE_DHD_H_REG_COUNT);
    return new_c_dhd_config;
}


// ----------------------------------------------
// Runtime configuration conversion functions
// ----------------------------------------------
static cartesi::machine_runtime_config convert_from_c(const cm_machine_runtime_config *c_config) {
    cartesi::machine_runtime_config new_cpp_machine_runtime_config{
            cartesi::dhd_runtime_config{null_to_empty(c_config->dhd.source_address)},
            cartesi::concurrency_config{c_config->concurrency.update_merkle_tree}
    };

    return new_cpp_machine_runtime_config;
}

// ----------------------------------------------
// Machine configuration conversion functions
// ----------------------------------------------
static cartesi::machine_config convert_from_c(const cm_machine_config *c_config) {

    cartesi::flash_drive_configs flash_configs{};
    for (size_t i = 0; i < c_config->flash_drive_count; ++i) {
        flash_configs.push_back(convert_from_c(&(c_config->flash_drive[i])));
    }

    cartesi::machine_config new_cpp_machine_config{};
    new_cpp_machine_config.processor = convert_from_c(&c_config->processor);
    new_cpp_machine_config.ram = convert_from_c(&c_config->ram);
    new_cpp_machine_config.rom = convert_from_c(&c_config->rom);
    new_cpp_machine_config.flash_drive = flash_configs;
    new_cpp_machine_config.clint =  convert_from_c(&c_config->clint);
    new_cpp_machine_config.htif = convert_from_c(&c_config->htif);
    new_cpp_machine_config.dhd = convert_from_c(&c_config->dhd);

    return new_cpp_machine_config;
}

static const cm_machine_config *convert_to_c(const cartesi::machine_config &cpp_config) {
    cm_machine_config *new_machine_config = new cm_machine_config{};

    new_machine_config->processor = convert_to_c(cpp_config.processor);
    new_machine_config->ram = convert_to_c(cpp_config.ram);
    new_machine_config->rom = convert_to_c(cpp_config.rom);
    new_machine_config->flash_drive_count = cpp_config.flash_drive.size();
    new_machine_config->flash_drive = new cm_flash_drive_config[cpp_config.flash_drive.size()];
    memset(new_machine_config->flash_drive, 0, sizeof(cm_flash_drive_config) * new_machine_config->flash_drive_count);
    for (size_t i = 0; i < new_machine_config->flash_drive_count; ++i) {
        new_machine_config->flash_drive[i] = convert_to_c(cpp_config.flash_drive[i]);
    }
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
// Hash conversion functions
// ----------------------------------------------

cartesi::machine_merkle_tree::hash_type convert_from_c(const cm_hash* c_hash) {
    cartesi::machine_merkle_tree::hash_type cpp_hash; //In emulator this is std::array<unsigned char, hash_size>;
    memcpy(cpp_hash.data(), c_hash, sizeof(cm_hash));
    return cpp_hash;
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

static cm_merkle_tree_proof *convert_to_c(const cartesi::machine_merkle_tree::proof_type &proof) {
    cm_merkle_tree_proof *new_merkle_tree_proof = new cm_merkle_tree_proof{};

    new_merkle_tree_proof->log2_root_size = proof.get_log2_root_size();
    new_merkle_tree_proof->log2_target_size = proof.get_log2_target_size();
    new_merkle_tree_proof->target_address = proof.get_target_address();

    memcpy(&new_merkle_tree_proof->root_hash, static_cast<const uint8_t *>(proof.get_root_hash().data()),
            sizeof(cm_hash));
    memcpy(&new_merkle_tree_proof->target_hash, static_cast<const uint8_t *>(proof.get_target_hash().data()),
            sizeof(cm_hash));

    new_merkle_tree_proof->sibling_hashes_count =
            new_merkle_tree_proof->log2_root_size - new_merkle_tree_proof->log2_target_size;
    new_merkle_tree_proof->sibling_hashes = new cm_hash[new_merkle_tree_proof->sibling_hashes_count];
    memset(new_merkle_tree_proof->sibling_hashes, 0, sizeof(cm_hash) * new_merkle_tree_proof->sibling_hashes_count);


    for (size_t log2_size = new_merkle_tree_proof->log2_target_size;
         log2_size < new_merkle_tree_proof->log2_root_size; ++log2_size) {
        int current_index = cm_log2_size_to_index(log2_size, new_merkle_tree_proof->log2_root_size);
        const cartesi::machine_merkle_tree::hash_type sibling_hash = proof.get_sibling_hash(log2_size);
        memcpy(&(new_merkle_tree_proof->sibling_hashes[current_index]),
                static_cast<const uint8_t *>(sibling_hash.data()), sizeof(cm_hash));
    }

    return new_merkle_tree_proof;
}

static cartesi::machine_merkle_tree::proof_type convert_from_c(const cm_merkle_tree_proof *c_proof) {
    cartesi::machine_merkle_tree::proof_type cpp_proof(c_proof->log2_root_size, c_proof->log2_target_size);
    cpp_proof.set_target_address(c_proof->target_address);

    cpp_proof.set_root_hash(convert_from_c(&c_proof->root_hash));
    cpp_proof.set_target_hash(convert_from_c(&c_proof->target_hash));

    for (int log2_size = cpp_proof.get_log2_target_size();
         log2_size < cpp_proof.get_log2_root_size(); ++log2_size) {
        const int current_index = cm_log2_size_to_index(log2_size, cpp_proof.get_log2_root_size());
        cartesi::machine_merkle_tree::hash_type cpp_sibling_hash = convert_from_c(&c_proof->sibling_hashes[current_index]);
        cpp_proof.set_sibling_hash(cpp_sibling_hash, log2_size);
    }

    return cpp_proof;

}

// ----------------------------------------------
// Access log conversion functions
// ----------------------------------------------

static CM_ACCESS_TYPE convert_to_c(const cartesi::access_type type) {
    if (type == cartesi::access_type::read) {
        return CM_ACCESS_READ;
    } else {
        return CM_ACCESS_WRITE;
    }
}

static cartesi::access_type convert_from_c(const CM_ACCESS_TYPE c_type) {
    if (c_type == CM_ACCESS_READ) {
        return cartesi::access_type::read;
    } else {
        return cartesi::access_type::write;
    }
}

static cartesi::access_log::type convert_from_c(const cm_access_log_type *type) {
    cartesi::access_log::type cpp_type(type->proofs, type->annotations);
    return cpp_type;
}

static cm_access convert_to_c(const cartesi::access &cpp_access) {
    cm_access new_access{};
    new_access.type = convert_to_c(cpp_access.get_type());
    new_access.address = cpp_access.get_address();
    new_access.log2_size = cpp_access.get_log2_size();
    new_access.read_data_size = cpp_access.get_read().size();
    if (new_access.read_data_size > 0) {
        new_access.read_data = new uint8_t[new_access.read_data_size];
        memcpy(new_access.read_data, cpp_access.get_read().data(), new_access.read_data_size);
    } else {
        new_access.read_data = NULL;
    }
    new_access.written_data_size = cpp_access.get_written().size();
    if (new_access.written_data_size > 0) {
        new_access.written_data = new uint8_t[new_access.written_data_size];
        memcpy(new_access.written_data, cpp_access.get_written().data(), new_access.written_data_size);
    } else {
        new_access.written_data = NULL;
    }

    if (cpp_access.get_proof()) {
        new_access.proof = convert_to_c(*cpp_access.get_proof());
    } else {
        new_access.proof = NULL;
    }

    return new_access;
}

static cartesi::access convert_from_c(const cm_access *c_access) {
    cartesi::access cpp_access{};
    cpp_access.set_type(convert_from_c(c_access->type));
    cpp_access.set_log2_size(c_access->log2_size);
    cpp_access.set_address(c_access->address);
    if (c_access->proof != NULL) {
        cartesi::machine_merkle_tree::proof_type proof = convert_from_c(c_access->proof);
        cpp_access.set_proof(proof);
    }

    cartesi::access_data cpp_read_data{};
    for (size_t  i=0; i<c_access->read_data_size; ++i) {
        cpp_read_data.push_back(c_access->read_data[i]); //todo optimize this, use iterators?
    }
    cpp_access.set_read(cpp_read_data);

    cartesi::access_data cpp_written_data{};
    for (size_t  i=0; i<c_access->written_data_size; ++i) {
        cpp_written_data.push_back(c_access->written_data[i]); //todo optimize this, use iterators?
    }
    cpp_access.set_written(cpp_written_data);


    return cpp_access;
}

static void cm_cleanup_access(cm_access *access) {
    cm_delete_proof(access->proof);
    delete [] access->written_data;
    delete [] access->read_data;
}


static CM_BRACKET_TYPE convert_to_c(const cartesi::bracket_type type) {
    if (type == cartesi::bracket_type::begin) {
        return CM_BRACKET_BEGIN;
    } else {
        return CM_BRACKET_END;
    }
}

static cartesi::bracket_type convert_from_c(const CM_BRACKET_TYPE c_type) {
    if (c_type == CM_BRACKET_BEGIN) {
        return cartesi::bracket_type::begin;
    } else {
        return cartesi::bracket_type::end;
    }
}


static cm_bracket_note convert_to_c(const cartesi::bracket_note &cpp_bracket_note) {
    cm_bracket_note new_bracket_note{};
    new_bracket_note.type = convert_to_c(cpp_bracket_note.type);
    new_bracket_note.where = cpp_bracket_note.where;
    new_bracket_note.text = convert_to_c(cpp_bracket_note.text);
    return new_bracket_note;
}

static cartesi::bracket_note convert_from_c(const cm_bracket_note *c_bracket_note) {
    cartesi::bracket_note cpp_bracket_note{};
    cpp_bracket_note.type = convert_from_c(c_bracket_note->type);
    cpp_bracket_note.where = c_bracket_note->where;
    cpp_bracket_note.text = null_to_empty(c_bracket_note->text);
    return cpp_bracket_note;
}

static void cm_cleanup_bracket_note(cm_bracket_note *bracket_note) {
    delete [] bracket_note->text;
}

static cm_access_log *convert_to_c(const cartesi::access_log &cpp_access_log) {
    cm_access_log *new_access_log = new cm_access_log{};

    new_access_log->accesses_count = cpp_access_log.get_accesses().size();
    new_access_log->accesses = new cm_access[new_access_log->accesses_count];
    for (size_t  i = 0; i < new_access_log->accesses_count; ++i) {
        new_access_log->accesses[i] = convert_to_c(cpp_access_log.get_accesses()[i]);
    }

    new_access_log->brackets_count = cpp_access_log.get_brackets().size();
    new_access_log->brackets = new cm_bracket_note[new_access_log->brackets_count];
    for (size_t  i = 0; i < new_access_log->brackets_count; ++i) {
        new_access_log->brackets[i] = convert_to_c(cpp_access_log.get_brackets()[i]);
    }

    new_access_log->notes_count = cpp_access_log.get_notes().size();
    new_access_log->notes = new const char *[new_access_log->notes_count];
    for (size_t  i = 0; i < new_access_log->notes_count; ++i) {
        new_access_log->notes[i] = convert_to_c(cpp_access_log.get_notes()[i]);
    }

    new_access_log->log_type.annotations = cpp_access_log.get_log_type().has_annotations();
    new_access_log->log_type.proofs = cpp_access_log.get_log_type().has_proofs();

    return new_access_log;
}

static cartesi::access_log convert_from_c(const cm_access_log *c_acc_log) {

    std::vector <cartesi::access> accesses;
    for (size_t i = 0; i < c_acc_log->accesses_count; ++i) {
        accesses.push_back(convert_from_c(&c_acc_log->accesses[i]));
    }
    std::vector <cartesi::bracket_note> brackets;
    for (size_t i = 0; i < c_acc_log->brackets_count; ++i) {
        brackets.push_back(convert_from_c(&c_acc_log->brackets[i]));
    }

    std::vector <std::string> notes;
    for (size_t i = 0; i < c_acc_log->notes_count; ++i) {
        notes.push_back(null_to_empty(c_acc_log->notes[i]));
    }
    cartesi::access_log new_cpp_acc_log(accesses, brackets, notes, convert_from_c(&c_acc_log->log_type));
    return new_cpp_acc_log;
}


// -----------------------------------------------------
// Public API functions for generation of default configs
// -----------------------------------------------------
const cm_machine_config *cm_new_default_machine_config() {
    cartesi::machine_config cpp_config = cartesi::machine::get_default_config();

    return convert_to_c(cpp_config);
}

void cm_delete_machine_config(const cm_machine_config *config) {

    delete[] config->dhd.image_filename;
    for (size_t i = 0; i < config->flash_drive_count; ++i) {
     delete[] config->flash_drive[i].image_filename;
    }
    delete[] config->flash_drive;
    delete[] config->rom.image_filename;
    delete[] config->rom.bootargs;
    delete[] config->ram.image_filename;

    delete config;
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

int cm_create_machine_from_dir(const char *dir, const cm_machine_runtime_config *runtime_config, cm_machine **new_machine,
                           char **err_msg) {
    try {
        const cartesi::machine_runtime_config r = convert_from_c(runtime_config);
        cartesi::machine *m = new cartesi::machine(null_to_empty(dir), r);
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

void cm_delete_machine(cm_machine *m) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    delete cpp_machine;
}

int cm_store(cm_machine *m, const char *dir, char **err_msg) {
    try {
        cartesi::machine *cpp_machine = convert_from_c(m);
        cpp_machine->store(null_to_empty(dir));
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

int cm_step(cm_machine *m, const cm_access_log_type log_type, bool one_based,
            cm_access_log **access_log, char **err_msg) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    try {

        cartesi::access_log::type cpp_log_type{log_type.proofs, log_type.annotations};
        cartesi::access_log cpp_access_log = cpp_machine->step(cpp_log_type, one_based);
        *access_log = convert_to_c(cpp_access_log);
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

void cm_delete_access_log(cm_access_log *acc_log) {
    for (size_t i = 0; i < acc_log->notes_count; ++i) {
        delete[] acc_log->notes[i];
    }
    delete[] acc_log->notes;
    for (size_t i = 0; i < acc_log->brackets_count; ++i) {
        cm_cleanup_bracket_note(&acc_log->brackets[i]);
    }
    delete[] acc_log->brackets;
    for (size_t i = 0; i < acc_log->accesses_count; ++i) {
        cm_cleanup_access(&acc_log->accesses[i]);
    }
    delete[] acc_log->accesses;
    delete acc_log;
}

int cm_verify_access_log(const cm_access_log* log, const cm_machine_runtime_config *runtime_config, bool one_based, char **err_msg) {
    try {
        const cartesi::access_log cpp_log = convert_from_c(log);
        const cartesi::machine_runtime_config cpp_runtime_config = convert_from_c(runtime_config);
        cartesi::machine::verify_access_log(cpp_log, cpp_runtime_config, one_based);
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

int cm_verify_state_transition(const cm_hash *root_hash_before,
                               const cm_access_log *log, const cm_hash *root_hash_after,
                               const cm_machine_runtime_config *runtime_config, bool one_based,
                               char **err_msg) {
    try {
        const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
        const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
        const cartesi::access_log cpp_log = convert_from_c(log);
        const cartesi::machine_runtime_config cpp_runtime_config = convert_from_c(runtime_config);
        cartesi::machine::verify_state_transition(cpp_root_hash_before, cpp_log, cpp_root_hash_after,
                                                  cpp_runtime_config, one_based);
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


int cm_dehash(cm_machine *m, const uint8_t *hash, uint64_t hlength,
              uint64_t *out_dlength, uint8_t *out_data, char **err_msg) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    try {
        uint64_t cpp_dlength;
        cartesi::dhd_data cpp_data = cpp_machine->dehash(hash, hlength, cpp_dlength);
        if (cpp_dlength == cartesi::DHD_NOT_FOUND) {
            *out_dlength = CM_DHD_NOT_FOUND;
        } else {
            *out_dlength = cpp_dlength;
            memcpy(out_data, cpp_data.data(), cpp_data.size());
        }
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

int cm_update_merkle_tree_page(cm_machine *m, uint64_t address, char **err_msg) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    try {
        bool result = cpp_machine->update_merkle_tree_page(address);
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
    delete proof;
}


void cm_get_root_hash(const cm_machine *m, cm_hash *hash) {
    const cartesi::machine *cpp_machine = convert_from_c(m);
    cartesi::machine_merkle_tree::hash_type cpp_hash;
    cpp_machine->get_root_hash(cpp_hash);
    memcpy(hash, static_cast<const uint8_t *>(cpp_hash.data()), sizeof(cm_hash));
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

int cm_write_csr(cm_machine *m, CM_PROC_CSR w, uint64_t val, char **err_msg) {
    try {
        cartesi::machine *cpp_machine = convert_from_c(m);
        cartesi::machine::csr cpp_csr = static_cast<cartesi::machine::csr>(w);
        cpp_machine->write_csr(cpp_csr, val);
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

int cm_write_memory(cm_machine *m, uint64_t address, const unsigned char *data, size_t length, char** err_msg) {
    try {
        cartesi::machine *cpp_machine = convert_from_c(m);
        cpp_machine->write_memory(address, data, length);
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

int cm_dump_pmas(const cm_machine *m, char **err_msg) {
    try {
        const cartesi::machine *cpp_machine = convert_from_c(m);
        cpp_machine->dump_pmas();
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

void cm_interact(cm_machine *m) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    cpp_machine->interact();
}

int cm_verify_dirty_page_maps(const cm_machine *m, bool *result, char** err_msg) {
    try {
        const cartesi::machine *cpp_machine = convert_from_c(m);
        *result = cpp_machine->verify_dirty_page_maps();
        *err_msg = NULL;
        return 0;
    } catch (std::exception &ex) {
        int error_code;
        convert_cpp_error(ex, &error_code, err_msg);
        return false;
    } catch (...) {
        *err_msg = get_error_message_unknown();
        return CM_ERROR_UNKNOWN;
    }
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

int cm_replace_flash_drive(cm_machine *m, const cm_flash_drive_config *new_flash, char **err_msg) {
    cartesi::machine *cpp_machine = convert_from_c(m);
    try {
        cartesi::flash_drive_config cpp_flash_config = convert_from_c(new_flash);
        cpp_machine->replace_flash_drive(cpp_flash_config);
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

void cm_delete_error_msg(char* err_msg) {
    delete[] err_msg;
}
