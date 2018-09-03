/*
 * RISCV CPU emulator
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

#ifndef PROCESSOR_H
#define PROCESSOR_H

typedef struct processor_state processor_state;

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


processor_state *processor_init(PhysMemoryMap *mem_map);
void processor_run(processor_state *p, uint64_t mcycle_end);
void processor_end(processor_state *p);

int processor_get_max_xlen(const processor_state *p);

uint64_t processor_read_misa(const processor_state *p);
uint64_t processor_read_mcycle(const processor_state *p);
void processor_write_mcycle(processor_state *p, uint64_t val);

uint64_t processor_read_tohost(const processor_state *p);
void processor_write_tohost(processor_state *p, uint64_t val);

uint64_t processor_read_fromhost(const processor_state *p);
void processor_write_fromhost(processor_state *p, uint64_t val);

uint64_t processor_read_mtimecmp(const processor_state *p);
void processor_write_mtimecmp(processor_state *p, uint64_t val);

bool processor_read_iflags_I(const processor_state *p);
void processor_reset_iflags_I(processor_state *p);

uint32_t processor_read_mip(const processor_state *p);
void processor_set_mip(processor_state *p, uint32_t mask);
void processor_reset_mip(processor_state *p, uint32_t mask);
void processor_set_brk_from_mip_mie(processor_state *p);

bool processor_read_iflags_H(const processor_state *p);
void processor_set_iflags_H(processor_state *p);
void processor_set_brk_from_iflags_H(processor_state *s);

#define RISCV_CLOCK_FREQ 1000000000 // 1 GHz (arbitrary)
#define RISCV_RTC_FREQ_DIV 100      // Set in stone in whitepaper

static inline uint64_t processor_rtc_cycles_to_time(uint64_t cycle_counter) {
    return cycle_counter / RISCV_RTC_FREQ_DIV;
}

static inline uint64_t processor_rtc_time_to_cycles(uint64_t time) {
    return time * RISCV_RTC_FREQ_DIV;
}

#endif
