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
    target->ram.length = source->ram.length;
    target->ram.image_filename = strdup(source->ram.image_filename);

    target->rom.bootargs = strdup(source->rom.bootargs);
    target->rom.image_filename = strdup(source->rom.image_filename);

    target->flash_drive_count = source->flash_drive_count;
    target->flash_drive = (cm_flash_drive_config *) malloc(sizeof(cm_flash_drive_config) * source->flash_drive_count);
    memset(target->flash_drive, 0, sizeof(cm_flash_drive_config) * target->flash_drive_count);
    for (size_t i=0; i<target->flash_drive_count; ++i) {
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
    for (size_t i=0; i<config->flash_drive_count; ++i) {
        free((char*)config->flash_drive[i].image_filename);
    }
    free(config->flash_drive);
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

void print_data(const uint8_t* data, int data_size) {
    for (int i=0; i<data_size; ++i) {
        printf("%02X", data[i] & 0xff);
    }
    printf("\n");
}

void print_merkle_tree_proof(const cm_merkle_tree_proof* proof) {
    printf("\n\t\tMerkle tree proof:\n");
    printf("\t\t\ttarget_address: %lx\n", proof->target_address);
    printf("\t\t\tlog2_target_size: %ld\n", proof->log2_target_size);
    printf("\t\t\ttarget_hash:");
    print_hash(proof->target_hash);
    printf("\t\t\tlog2_root_size: %ld\n", proof->log2_root_size);
    printf("\t\t\troot_hash:");
    print_hash(proof->root_hash);
    printf("\t\t\tsibling_hashes_count: %ld\n", proof->sibling_hashes_count);
    //todo print sibling hashes if needed
}

void print_access(const cm_access* cm_acc) {
    printf("\tCM access:\n");
    printf("\t\ttype: %d\n", cm_acc->type);
    printf("\t\taddress %lx\n", cm_acc->address);
    printf("\t\tlog2 size %d\n", cm_acc->log2_size);
    printf("\t\tread data size=%ld data:", cm_acc->read_data_size);
    print_data(cm_acc->read_data, cm_acc->read_data_size);
    printf("\t\twritten data size=%ld data:", cm_acc->written_data_size);
    print_data(cm_acc->written_data, cm_acc->written_data_size);
    printf("\t\tproof:");
    print_merkle_tree_proof(cm_acc->proof);
}

void print_access_log(const cm_access_log* access_log) {

    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    printf("ACCESS LOG:\n");
    for (size_t i=0; i<access_log->accesses_count; ++i) {
        print_access(&access_log->accesses[i]);
    }
    //todo add rest
    printf("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
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
    free((char*)my_machine_config.rom.image_filename); //free cloned image filename
    my_machine_config.rom.image_filename = strdup(rom_image);
    my_machine_config.ram.length = 1 << 20;

    //Setup runtime config
    cm_machine_runtime_config my_runtime_config;
    my_runtime_config.dhd.source_address = "";
    my_runtime_config.concurrency.update_merkle_tree = 1;

    cm_machine* my_machine;
    int error_code = 0;
    char* err_msg;



    printf("Creating machine from directory, expecting error:\n");
    if ((error_code = cm_create_machine_from_dir("/unknown_dir", &my_runtime_config, &my_machine, &err_msg)) != 0) {
        printf("Error creating from directory machine, error code: %d message: %s\n", error_code, err_msg);
        cm_delete_error_msg(err_msg);
    } else {
        printf("Machine successfully created!\n");
    }

    //Create machine
    printf("Creating machine\n");
    if ((error_code = cm_create_machine(&my_machine_config, &my_runtime_config, &my_machine, &err_msg)) != 0) {
        printf("Error creating machine, error code: %d message: %s\n", error_code, err_msg);
        cm_delete_error_msg(err_msg);
    } else {
        printf("Machine successfully created!\n");
    }


    //Update merkle tree
    if ((error_code = cm_update_merkle_tree(my_machine, &err_msg)) != 0) {
        printf("Error updating merkle tree, error code: %d message: %s\n", error_code, err_msg);
        cm_delete_error_msg(err_msg);
    } else {
        printf("Merkle tree successfully updated!\n");
    }


    //Get machine hash
    cm_hash root_hash_step0;
    memset(&root_hash_step0, 0, sizeof(root_hash_step0));
    cm_get_root_hash(my_machine, &root_hash_step0, &err_msg);
    printf("Initial hash of the machine is:");
    print_hash(root_hash_step0);


    cm_merkle_tree_proof *proof;
    //Get proof for first page of memory space
    if ((error_code = cm_get_proof(my_machine, 0, 12, &proof, &err_msg)) != 0) {
        printf("Error getting proof, error code: %d message: %s\n", error_code, err_msg);
        cm_delete_error_msg(err_msg);
    } else {
        printf("Proof acquire is successfull!\n");
        printf("Root hash:\n");
        print_hash(proof->root_hash);
        printf("First page in memory hash:\n");
        print_hash(proof->target_hash);

        cm_delete_proof(proof);
    }

    // Check dehash
    uint8_t dehash_data[10000];
    memset(dehash_data, 0, sizeof(dehash_data));
    uint64_t dehash_data_length = sizeof(dehash_data);
    if ((error_code = cm_dehash(my_machine, proof->target_hash, 32, &dehash_data_length,
                                dehash_data, &err_msg)) != 0) {
        printf("Error performing dehash, error code: %d message: %s\n", error_code, err_msg);
        cm_delete_error_msg(err_msg);
    } else {
        printf("Dehash successfull, size acquired: %ld, first byte: %x\n", dehash_data_length,
               dehash_data[0]);
    }


    //Verify merkle tree
    bool merkle_check;
    printf("Checking merkle tree %d\n", cm_verify_merkle_tree(my_machine, &merkle_check, &err_msg));

    //Read write some register
    if ((error_code = cm_write_csr(my_machine, CM_PROC_MCYCLE, 3, &err_msg))!= 0) {
        printf("Error performing write scr, error code: %d message: %s\n", error_code, err_msg);
        cm_delete_error_msg(err_msg);
    };
    uint64_t reg_value;
    cm_read_csr(my_machine, CM_PROC_MCYCLE, &reg_value, &err_msg);
    printf("New value of mcycle is %ld\n", reg_value);

    //Get csr address
    printf("Address of pc counter is %lx\n", cm_get_csr_address(CM_PROC_PC));;

    // Read word
    uint64_t read_word_value = 0;
    cm_read_word(my_machine, 0x100, &read_word_value, &err_msg);
    printf("Read memory from location 0x100 is %ld\n", read_word_value);

    //Write memory
    uint8_t data_to_write[] = "This is some data";
    if ((error_code = cm_write_memory(my_machine, 0x80000000, data_to_write,
                                     strlen((char *)data_to_write)+1, &err_msg)) !=0) {
        printf("Error writing memory, error code: %d message: %s\n", error_code, err_msg);
        cm_delete_error_msg(err_msg);
    };

    uint8_t data_read[128];
    cm_read_memory(my_machine, 0x80000000, data_read, strlen((char *)data_to_write)+1, &err_msg);
    printf("Data written '%s' and data read: '%s'\n", data_to_write, data_read);


    uint64_t  x_to_write = 78;
    cm_write_x(my_machine, 4, x_to_write, &err_msg);
    cm_read_x(my_machine, 4, &reg_value, &err_msg);
    printf("X written '%ld' and x read: '%ld' and x address is %lx\n", x_to_write, reg_value,
           cm_get_x_address(4));



    //Test step command and access log verifications
    cm_access_log* access_log;
    cm_access_log_type log_type = {true, true};
    if ((error_code = cm_update_merkle_tree(my_machine, &err_msg)) != 0) {
        printf("Error updating merkle tree, error code: %d message: %s\n", error_code, err_msg);
        cm_delete_error_msg(err_msg);
    }
    cm_get_root_hash(my_machine, &root_hash_step0, &err_msg);
    if ((error_code = cm_step(my_machine, log_type, false, &access_log, &err_msg)) != 0) {
        printf("Error performing step, error code: %d message: %s\n", error_code, err_msg);
        cm_delete_error_msg(err_msg);
    } else {
        printf("Step succesfully performed\n");
        print_access_log(access_log);

        //Verify access log
        if ((error_code = cm_verify_access_log(access_log, &my_runtime_config, false, &err_msg)) != 0) {
            printf("Error verifying access log, error code: %d message: %s\n", error_code, err_msg);
            cm_delete_error_msg(err_msg);
        } else {
            printf("Access log successfully verified\n");
        }


        cm_hash root_hash_step1;
        memset(&root_hash_step1, 0, sizeof(root_hash_step1));
        cm_get_root_hash(my_machine, &root_hash_step1, &err_msg);
        if ((error_code = cm_verify_state_transition((const cm_hash *)&root_hash_step0, access_log,
                                                     (const cm_hash *)root_hash_step1,
                                                     &my_runtime_config, false, &err_msg)) != 0) {
            printf("Error verifying state transition, error code: %d message: %s\n", error_code, err_msg);
            cm_delete_error_msg(err_msg);
        } else {
            printf("State transition successfully verified\n");
        }



        cm_delete_access_log(access_log);
    }


    //Run machine to end mcycle
    uint64_t current_mcycle = 0;
    while (current_mcycle < 1000) {
        if ((error_code = cm_machine_run(my_machine, 0xfffffffff, &err_msg)) != 0) {
            printf("Error running macihne: %d message: %s\n", error_code, err_msg);
            cm_delete_error_msg(err_msg);
        }
        cm_read_mcycle(my_machine, &current_mcycle, &err_msg);
    }

    printf("Machine stopped after %ld cycles\n", current_mcycle);


    printf("Deleting machine\n");
    cm_delete_machine(my_machine);

    printf("Cleaning up\n");
    cleanup_machine_config(&my_machine_config);

    cm_delete_machine_config(default_machine_config);

    return 0;
}
