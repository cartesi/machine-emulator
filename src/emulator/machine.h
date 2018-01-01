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
#include <lua.h>

#define VM_MAX_DRIVE_DEVICE 4

#define VM_CONFIG_VERSION 1

typedef struct {
    char *filename;
    uint8_t *buf;
    int len;
} VMFileEntry;

typedef struct {
    char *device;
    char *filename;
    BlockDevice *block_dev;
} VMDriveEntry;

typedef struct {
    char *cfg_filename;
    uint64_t ram_size;
    BOOL rtc_real_time;
    BOOL rtc_local_time;
    char *display_device; /* NULL means no display */
    int width, height; /* graphic width & height */
    CharacterDevice *console;
    VMDriveEntry tab_drive[VM_MAX_DRIVE_DEVICE];
    int drive_count;

    char *cmdline; /* kernel command line */
    char *input_device; /* NULL means no input */

    /* kernel file */
    VMFileEntry kernel;
} VirtMachineParams;

typedef struct VirtMachine {
    /* console */
    VIRTIODevice *console_dev;
    CharacterDevice *console;
} VirtMachine;

void __attribute__((format(printf, 1, 2))) vm_error(const char *fmt, ...);

const char *virt_machine_get_name(void);
void virt_machine_set_defaults(VirtMachineParams *p);
void virt_lua_load_config(lua_State *L, VirtMachineParams *p, int tabidx);
void vm_add_cmdline(VirtMachineParams *p, const char *cmdline);
char *get_file_path(const char *base_filename, const char *filename);
void virt_machine_free_config(VirtMachineParams *p);
VirtMachine *virt_machine_init(const VirtMachineParams *p);
void virt_machine_end(VirtMachine *s);
int virt_machine_get_sleep_duration(VirtMachine *s, int delay);
void virt_machine_interp(VirtMachine *s, int max_exec_cycle);
BOOL vm_mouse_is_absolute(VirtMachine *s);
void vm_send_mouse_event(VirtMachine *s1, int dx, int dy, int dz,
                         unsigned int buttons);
void vm_send_key_event(VirtMachine *s1, BOOL is_down, uint16_t key_code);
