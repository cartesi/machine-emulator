/*
 * VM definitions
 *
 * Copyright (c) 2016-2017 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifndef MACHINE_H
#define MACHINE_H

#include <lua.hpp>
#include <cstdint>

#define VM_MAX_FLASH_DEVICE 4

#define VM_CONFIG_VERSION 1

typedef struct {
    char *filename;
    uint8_t *buf;
    int len;
} VMFileEntry;

typedef struct {
    char *backing;
    char *label;
    bool shared;
    uint64_t address;
    uint64_t size;
} VMFlashEntry;

typedef struct {
    uint64_t ram_size;
    int width, height; /* graphic width & height */
    VMFlashEntry tab_flash[VM_MAX_FLASH_DEVICE];
    int flash_count;
    char *cmdline; /* kernel command line */
    VMFileEntry boot_image; /* boot image file */
    bool interactive; /* should we initialize the console? */
} VirtMachineParams;

struct VirtMachine;
typedef struct VirtMachine VirtMachine;

void __attribute__((format(printf, 1, 2))) vm_error(const char *fmt, ...);

const char *virt_machine_get_name(void);
void virt_machine_set_defaults(VirtMachineParams *p);
void virt_lua_load_config(lua_State *L, VirtMachineParams *p, int tabidx);
void virt_machine_free_config(VirtMachineParams *p);
VirtMachine *virt_machine_init(const VirtMachineParams *p);
uint64_t virt_machine_get_mcycle(VirtMachine *v);
uint64_t virt_machine_get_htif_tohost(VirtMachine *v);
void virt_machine_end(VirtMachine *v);
void virt_machine_advance_mcycle(VirtMachine *v);
int virt_machine_run(VirtMachine *v, uint64_t cycle_end);

#endif
