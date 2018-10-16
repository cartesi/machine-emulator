#ifndef MACHINE_H
#define MACHINE_H

typedef struct machine_state machine_state;

#include "i-device-state-access.h"
#include "merkle-tree.h"

typedef bool (*pma_device_read)(i_device_state_access *da, void *context, uint64_t offset, uint64_t *val, int size_log2);
typedef bool (*pma_device_write)(i_device_state_access *da, void *context, uint64_t offset, uint64_t val, int size_log2);
typedef bool (*pma_device_peek)(machine_state *s, void *context, uint64_t offset, uint64_t *val, int size_log2);
typedef bool (*pma_device_update_merkle_tree)(machine_state *s, void *context, uint64_t start, uint64_t length, merkle_tree *t);

// Interrupt pending flags for use with set/reset mip
#define MIP_USIP   (1 << 0)
#define MIP_SSIP   (1 << 1)
#define MIP_HSIP   (1 << 2)
#define MIP_MSIP   (1 << 3)
#define MIP_UTIP   (1 << 4)
#define MIP_STIP   (1 << 5)
#define MIP_HTIP   (1 << 6)
#define MIP_MTIP   (1 << 7)
#define MIP_UEIP   (1 << 8)
#define MIP_SEIP   (1 << 9)
#define MIP_HEIP   (1 << 10)
#define MIP_MEIP   (1 << 11)

machine_state *machine_init(void);
void machine_run(machine_state *s, uint64_t mcycle_end);
void machine_end(machine_state *s);

bool machine_update_merkle_tree(machine_state *s, merkle_tree *t);
bool machine_get_word_value_proof(machine_state *s, merkle_tree *t, uint64_t address, merkle_tree::word_value_proof &proof);

int processor_get_max_xlen(const machine_state *s);

uint64_t processor_read_misa(const machine_state *s);
uint64_t processor_read_mcycle(const machine_state *s);
void processor_write_mcycle(machine_state *s, uint64_t val);

uint64_t processor_read_tohost(const machine_state *s);
void processor_write_tohost(machine_state *s, uint64_t val);

uint64_t processor_read_fromhost(const machine_state *s);
void processor_write_fromhost(machine_state *s, uint64_t val);

uint64_t processor_read_mtimecmp(const machine_state *s);
void processor_write_mtimecmp(machine_state *s, uint64_t val);

bool processor_read_iflags_I(const machine_state *s);
void processor_reset_iflags_I(machine_state *s);

uint32_t processor_read_mip(const machine_state *s);
void processor_set_mip(machine_state *s, uint32_t mask);
void processor_reset_mip(machine_state *s, uint32_t mask);
void processor_set_brk_from_mip_mie(machine_state *s);

bool processor_read_iflags_H(const machine_state *s);
void processor_set_iflags_H(machine_state *s);
void processor_set_brk_from_iflags_H(machine_state *s);

#define RISCV_CLOCK_FREQ 1000000000 // 1 GHz (arbitrary)
#define RISCV_RTC_FREQ_DIV 100      // Set in stone in whitepaper

static inline uint64_t processor_rtc_cycles_to_time(uint64_t cycle_counter) {
    return cycle_counter / RISCV_RTC_FREQ_DIV;
}

static inline uint64_t processor_rtc_time_to_cycles(uint64_t time) {
    return time * RISCV_RTC_FREQ_DIV;
}

uint8_t *board_get_host_memory(machine_state *s, uint64_t paddr);
bool board_register_flash(machine_state *s, uint64_t start, uint64_t length, const char *path, bool shared);
bool board_register_ram(machine_state *s, uint64_t start, uint64_t length);
bool board_register_mmio(machine_state *s, uint64_t start, uint64_t length, void *context,
    pma_device_read read,
    pma_device_write write,
    pma_device_peek peek = nullptr,
    pma_device_update_merkle_tree update_merkle_tree = nullptr);

bool board_register_shadow(machine_state *s, uint64_t start, uint64_t length,
    void *context,
    pma_device_read read,
    pma_device_write write,
    pma_device_peek peek = nullptr,
    pma_device_update_merkle_tree update_merkle_tree = nullptr);

#endif
