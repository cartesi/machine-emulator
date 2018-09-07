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
#ifndef EMULATOR_H
#define EMULATOR_H

#include <lua.hpp>
#include <cstdint>

#define VM_MAX_FLASH_DEVICE 4

#define VM_CONFIG_VERSION 1

typedef struct {
    char *filename;
    uint8_t *buf;
    uint64_t len;
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
    VMFileEntry ram_image; /* initial ram contents */
    VMFileEntry rom_image; /* initial rom contents */
    bool interactive; /* should we initialize the console? */
} emulator_config;

typedef struct emulator emulator;

const char *emulator_get_name(void);
void emulator_set_defaults(emulator_config *c);
void emulator_load_lua_config(lua_State *L, emulator_config *c, int tabidx);
void emulator_free_config(emulator_config *c);
emulator *emulator_init(const emulator_config *c);
uint64_t emulator_read_mcycle(emulator *emu);
uint64_t emulator_read_tohost(emulator *emu);
void emulator_end(emulator *emu);
int emulator_run(emulator *emu, uint64_t cycle_end);

#endif
