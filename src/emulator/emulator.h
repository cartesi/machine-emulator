#ifndef EMULATOR_H
#define EMULATOR_H

#include <lua.hpp>
#include <cstdint>

#define VM_MAX_FLASH_DEVICE 8

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
int emulator_update_merkle_tree(emulator *emu);
int emulator_get_merkle_tree_root_hash(emulator *emu, uint8_t *buf, int len);

#endif
