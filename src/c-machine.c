// Copyright 2020 Cartesi Pte. Ltd.
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
/// \brief Cartesi machine emulator client program using C API



#define _POSIX_C_SOURCE 200809L //need for usage of strdup as it is not ANSI C99

#include <alloca.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "machine-c-api.h"


//Clone machine config allocating memory for dynamic members
void clone_machine_config(const cm_machine_config *source, cm_machine_config *target) {
    target->processor = source->processor;
    target->ram = source->ram;
    target->ram.image_filename = strdup(source->ram.image_filename);
    target->rom.bootargs = strdup(source->rom.bootargs);
    target->rom.image_filename = strdup(source->rom.image_filename);

    target->flash_drive_count = source->flash_drive_count;
    target->flash_drive = (cm_flash_drive_config *)malloc(sizeof(cm_flash_drive_config) * source->flash_drive_count);
    memset(target->flash_drive, 0, sizeof(cm_flash_drive_config) * target->flash_drive_count);
    for (int i=0; i<target->flash_drive_count; ++i) {
        target->flash_drive[i] = source->flash_drive[i];
        target->flash_drive[i].image_filename = strdup(source->flash_drive[i].image_filename);
    }

    target->clint = source->clint;
    target->htif = source->htif;
    target->dhd = source->dhd;
    target->dhd.image_filename = strdup(source->dhd.image_filename);


}

//Remove allocated members of machine config
void cleanup_machine_config(cm_machine_config *config) {

    free((char*)config->dhd.image_filename);
    for (int i=0; i<config->flash_drive_count; ++i) {
        free((char*)config->flash_drive[i].image_filename);
    }
    free((char*)config->rom.image_filename);
    free((char*)config->rom.bootargs);
    free((char*)config->ram.image_filename);

}

/* main.c */
int main() {

    printf("Welcome to Cartesi c-machine test/debug simple program...\n");


    //Setup machine config
    printf("Setting up machine configuration\n");
    const cm_machine_config *default_machine_config = cm_new_default_machine_config();

    cm_machine_config my_machine_config;
    clone_machine_config(default_machine_config, &my_machine_config);
    const char rom_image[] = "/opt/cartesi/share/images/rom.bin";
    my_machine_config.rom.image_filename = strdup(rom_image);
    my_machine_config.ram.length = 1 << 20;

    //Setup runtime config
    cm_machine_runtime_config my_runtime_config;
    my_runtime_config.dhd.source_address = "";
    my_runtime_config.concurrency.update_merkle_tree = 1;


    //Create machine
    printf("Creating machine\n");
    cm_machine* my_machine;
    int error_code = 0;
    error_message err_msg;
    if ((error_code = cm_create_machine(&my_machine_config, &my_runtime_config, &my_machine, &err_msg)) != 0) {
        printf("Error creating machine: %d message: %s\n", error_code, err_msg);
    } else {
        printf("Machine successfully created!\n");
    }

    //Run machine to end mcycle
    uint64_t current_mcycle = 0;
    while (current_mcycle < 1000) {
        if ((error_code = cm_machine_run(my_machine, 0xfffffffff, &err_msg)) != 0) {
            printf("Error running macihne: %d message: %s\n", error_code, err_msg);
        }
        current_mcycle =cm_read_mcycle(my_machine);
    }

    printf("Machine stopped after %ld cycles\n", current_mcycle);


    printf("Deleting machine\n");
    cm_delete_machine(my_machine);

    printf("Cleaning up\n");
    cleanup_machine_config(&my_machine_config);
    cm_delete_machine_config(default_machine_config);

    return 0;
}