#ifndef EMULATOR_H
#define EMULATOR_H

#include <cstdint>
#include <string>

#include "emulator-config.h"

#define CARTESI_VENDORID UINT64_C(0x6361727465736920)
#define CARTESI_ARCHID 1
#define CARTESI_IMPID 1

typedef struct emulator emulator;

std::string emulator_get_name(void);

emulator_config *emulator_config_init(void);
void emulator_config_end(emulator_config *c);

emulator *emulator_init(const emulator_config *c);
void emulator_end(emulator *emu);

uint64_t emulator_read_mcycle(emulator *emu);
uint64_t emulator_read_tohost(emulator *emu);

int emulator_run(emulator *emu, uint64_t cycle_end);
int emulator_update_merkle_tree(emulator *emu);
int emulator_get_merkle_tree_root_hash(emulator *emu, uint8_t *buf, size_t len);

#endif
