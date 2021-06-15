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

void print_hash(const uint8_t* hash) {
    for (long unsigned i=0; i<sizeof(cm_hash); ++i) {
        printf("%02X", hash[i] & 0xff);
    }
    printf("\n");
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

    //Get machine hash
    cm_hash my_hash;
    memset(&my_hash, 0, sizeof(my_hash));
    cm_get_root_hash(my_machine, &my_hash);
    printf("Initial hash of the machine is:");
    print_hash(my_hash);

    //Verify merkle tree
    printf("Checking merkle tree %d\n",cm_verify_merkle_tree(my_machine));

    //Read write some register
    cm_write_csr(my_machine, CM_PROC_MCYCLE, 3);
    printf("New value of mcycle is %ld\n", cm_read_csr(my_machine, CM_PROC_MCYCLE));

    //Get csr address
    printf("Address of pc counter is %lx\n", cm_get_csr_address(CM_PROC_PC));;

    // Read word
    uint64_t read_word_value = 0;
    cm_read_word(my_machine, 0x100, &read_word_value);
    printf("Read memory from location 0x100 is %ld\n", read_word_value);

    //Write memory
    uint8_t data_to_write[] = "This is some data";
    cm_write_memory(my_machine, 0x80000000, data_to_write, strlen((char *)data_to_write)+1);

    uint8_t data_read[128];
    cm_read_memory(my_machine, 0x80000000, data_read, strlen((char *)data_to_write)+1);
    printf("Data written '%s' and data read: '%s'\n", data_to_write, data_read);


    uint64_t  x_to_write = 78;
    cm_write_x(my_machine, 4, x_to_write);
    printf("X written '%ld' and x read: '%ld' and x address is %lx\n", x_to_write, cm_read_x(my_machine, 4),
           cm_get_x_address(4));






    //Run machine to end mcycle
    uint64_t current_mcycle = 0;
    while (current_mcycle < 1000) {
        if ((error_code = cm_machine_run(my_machine, 0xfffffffff, &err_msg)) != 0) {
            printf("Error running macihne: %d message: %s\n", error_code, err_msg);
        }
        current_mcycle = cm_read_mcycle(my_machine);
    }

    printf("Machine stopped after %ld cycles\n", current_mcycle);


    printf("Deleting machine\n");
    cm_delete_machine(my_machine);

    printf("Cleaning up\n");
    cleanup_machine_config(&my_machine_config);
    cm_delete_machine_config(default_machine_config);

    return 0;
}