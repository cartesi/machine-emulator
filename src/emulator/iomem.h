/*
 * IO memory handling
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

#ifndef IOMEM_H
#define IOMEM_H

#include "i-device-state-access.h"

typedef bool DeviceWriteFunc(i_device_state_access *a, void *opaque, uint64_t offset, uint64_t val, int size_log2);
typedef bool DeviceReadFunc(i_device_state_access *a, void *opaque, uint64_t offset, uint64_t *val, int size_log2);

#define DEVRAM_PAGE_SIZE_LOG2 12
#define DEVRAM_PAGE_SIZE (1 << DEVRAM_PAGE_SIZE_LOG2)

typedef struct {
    uint64_t addr;
    uint64_t size;
    bool is_ram;
    bool is_backed; /* ram is backed by host file via mmap */
    /* the following is used for RAM access */
    int devram_flags;
    uint8_t *phys_mem;
    /* the following is used for file RAM access */
    int fd;
    /* the following is used for I/O access */
    void *opaque;
    DeviceReadFunc *read_func;
    DeviceWriteFunc *write_func;
} PhysMemoryRange;

#define PHYS_MEM_RANGE_MAX 32

struct PhysMemoryMap {
    int n_phys_mem_range;
    PhysMemoryRange phys_mem_range[PHYS_MEM_RANGE_MAX];
};

PhysMemoryMap *phys_mem_map_init(void);
void phys_mem_map_end(PhysMemoryMap *s);

PhysMemoryRange *cpu_register_ram(PhysMemoryMap *s, uint64_t addr, uint64_t size);

PhysMemoryRange *cpu_register_backed_ram(PhysMemoryMap *s, uint64_t addr, uint64_t size, const char *path, bool shared);

PhysMemoryRange *cpu_register_device(PhysMemoryMap *s, uint64_t addr,
                                     uint64_t size, void *opaque,
                                     DeviceReadFunc *read_func, DeviceWriteFunc *write_func);
PhysMemoryRange *get_phys_mem_range(PhysMemoryMap *s, uint64_t paddr);

#endif /* IOMEM_H */
