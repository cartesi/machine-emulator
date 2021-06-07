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
    // Bad optional access error
    CM_ERROR_BAD_OPTIONAL_ACCESS = 6,
    // Runtime errors
    CM_ERROR_RANGE_ERROR = 7,
    CM_ERROR_OVERFLOW_ERROR = 8,
    CM_ERROR_UNDERFLOW_ERROR = 9,
    CM_ERROR_REGEX_ERROR = 10,
    CM_ERROR_SYSTEM_IOS_BASE_FAILURE = 11,
    CM_ERROR_FILESYSTEM_ERROR = 12,
    CM_ERROR_ATOMIC_TX_ERROR = 13,
    CM_ERROR_NONEXISTING_LOCAL_TIME = 14,
    CM_ERROR_AMBIGOUS_LOCAL_TIME = 15,
    CM_ERROR_FORMAT_ERROR = 16,
    //Other errors
    CM_ERROR_BAD_TYPEID = 17,
    CM_ERROR_BAD_CAST = 18,
    CM_ERROR_BAD_WEAK_PTR = 19,
    CM_ERROR_BAD_FUNCTION_CALL = 20,
    CM_ERROR_BAD_ALLOC = 21,
    CM_ERROR_BAD_EXCEPTION = 22,
    CM_ERROR_IOS_BASE_FAILURE = 23,
    CM_ERROR_BAD_VARIANT_ACCESS = 24,
    CM_ERROR_UNKNOWN = 25,
};


static error_message get_error_message(int error) {
    static const char* lookup[] = {
            "OK",
            "Argument value has not been accepted", //1 invalid argument
            "Inputs are outside of domain for which operation is defined", //2 domain error
            "Implementation defined length limits for object is exceeded", //3 length error
            "Attempt do access elements out of defined range", //4 out of range
            "Error with asynchronous execution and shared states ", //5 future error
            "Accessing optional object that does not contain a value", //6 bad optional access
            "Result of a computation cannot be represented by the destination type", //7 range error
            "Arithmetic overflow error", //8 overflow error
            "Arithmetic underflow error", //9 underflow error
            "Errors in the regular expressions processing", //10 regex error
            "Failure in input/output operation", //11 system error ios_base_failure
            "Filesystem error", //12 filesystem error
            "Atomic transaction error", //13 tx exception
            "Error in local time conversion", //14 nonexistent local time
            "Attempt to convert ambiguous local time", // 15 ambiguous local time
            "Error in formatting library operation", // 16 format error
            "Bad type: dereferenced null pointer value of polymorphic type", //17 bad typeid
            "Dynamic cast run time check failure", //18 bad cast
            "Weak pointer refers to already deleted object", //19 bad weak ptr
            "Bad function call: function wrapper has no target", //20 bad function call
            "Failure to allocate storage", //21 bad alloc
            "Bad runtime exception", //22 bad expception
            "Failure of input/output function operation", //23 ios base failure
            "Bad variant access", //24 bad variant access
            "Unknown error occurred", //25 unknown error
    };
    return lookup[error];
}

static void convert_cpp_error(const std::exception& err_cpp, int *error_code, error_message *error_message) {
    //TODO convert cpp exceptin type using dynamic cast checks to C error code and
    *error_code = 0;
    *error_message = get_error_message(*error_code);
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
    memmove(&new_cpp_config.x, (void *) c_config, sizeof(cm_processor_config));
    return new_cpp_config;
}

static cm_processor_config convert_to_c(const cartesi::processor_config &cpp_config) {
    cm_processor_config new_c_config;
    memset((void *) &new_c_config, 0, sizeof(cm_processor_config));

    assert(sizeof(new_c_config) == sizeof(cpp_config));
    memmove((void *) &new_c_config, (void *) &cpp_config.x, sizeof(cm_processor_config));
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
    memset((void *) &new_c_ram_config, 0, sizeof(cm_ram_config));
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
    memset((void *) &new_c_rom_config, 0, sizeof(cm_rom_config));
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
    memset((void *) &new_c_flash_drive_config, 0, sizeof(cm_flash_drive_config));
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
    memset((void *) &new_c_clint_config, 0, sizeof(cm_clint_config));
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
    memset((void *) &new_c_htif_config, 0, sizeof(cm_htif_config));
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
    memset((void *) &new_c_dhd_config, 0, sizeof(cm_dhd_config));
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

// ----------------------------------------------
// Machine conversion functions
// ----------------------------------------------

static cartesi::machine *convert_machine_to_cpp(cm_machine *m) {
    return static_cast<cartesi::machine *>(m);
}

static const cartesi::machine *convert_machine_to_cpp(const cm_machine *m) {
    return static_cast<const cartesi::machine *>(m);
}


// -----------------------------------------------------
// Public API functions for generation of default configs
// -----------------------------------------------------
const cm_machine_config *cm_new_default_machine_config() {
    cm_machine_config *new_machine = static_cast<cm_machine_config *>(malloc(sizeof(cm_machine_config)));
    memset(new_machine, 0, sizeof(cm_machine_config));

    cartesi::machine_config cpp_config = cartesi::machine::get_default_config();
    new_machine->processor = convert_to_c(cpp_config.processor);
    new_machine->ram = convert_to_c(cpp_config.ram);
    new_machine->rom = convert_to_c(cpp_config.rom);
    new_machine->flash_drive_count = cpp_config.flash_drive.size();
    new_machine->flash_drive = new cm_flash_drive_config[cpp_config.flash_drive.size()];
    memset(&new_machine->flash_drive, 0, sizeof(new_machine->flash_drive));
    new_machine->clint = convert_to_c(cpp_config.clint);
    new_machine->htif = convert_to_c(cpp_config.htif);
    new_machine->dhd = convert_to_c(cpp_config.dhd);

    return new_machine;
}

void cm_delete_machine_config(const cm_machine_config *config) {

    free(const_cast<char *>(config->dhd.image_filename));
    free(const_cast<char *>(config->rom.image_filename));
    delete [] config->flash_drive;
    free(const_cast<char *>(config->rom.bootargs));
    free(const_cast<char *>(config->ram.image_filename));

    free(config->flash_drive);
    free(const_cast<cm_machine_config *>(config));
}


int cm_create_machine(const cm_machine_config *config, const cm_machine_runtime_config *runtime_config,
                      cm_machine **new_machine, error_message *err_msg) {

    cartesi::machine_config c = convert_from_c(config);
    cartesi::machine_runtime_config r = convert_from_c(runtime_config);

    cartesi::machine *m = new cartesi::machine(c, r);
    *new_machine = reinterpret_cast<cm_machine *>(m);

    return 0;
}

void cm_delete_machine(cm_machine *m) {
    cartesi::machine *car_machine = static_cast<cartesi::machine *>(m);
    delete car_machine;
}

int cm_machine_run(cm_machine *m, uint64_t mcycle_end, error_message *err_msg) {

    cartesi::machine *cpp_machine = convert_machine_to_cpp(m);
    try {
        cpp_machine->run(mcycle_end);
        *err_msg = get_error_message(CM_ERROR_OK);
        return 0;
    } catch (std::exception &ex) {
        int error_code;
        convert_cpp_error(ex, &error_code, err_msg);
        return error_code;
    } catch (...) {
        *err_msg = get_error_message(CM_ERROR_UNKNOWN);
        return CM_ERROR_UNKNOWN;
    }

}

uint64_t cm_read_mcycle(const cm_machine *m) {
    const cartesi::machine *cpp_machine = convert_machine_to_cpp(m);
    return cpp_machine->read_mcycle();
}
