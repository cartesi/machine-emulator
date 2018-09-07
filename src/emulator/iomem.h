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

#define DEVRAM_PAGE_SIZE_LOG2 12
#define DEVRAM_PAGE_SIZE    (1 << DEVRAM_PAGE_SIZE_LOG2)

#define PMA_FLAGS_M         (1 << 0)
#define PMA_FLAGS_IO        (1 << 1)
#define PMA_FLAGS_E         (1 << 2)
#define PMA_FLAGS_R         (1 << 3)
#define PMA_FLAGS_W         (1 << 4)
#define PMA_FLAGS_X         (1 << 5)
#define PMA_FLAGS_IR        (1 << 6)
#define PMA_FLAGS_IW        (1 << 7)

#define PMA_FLAGS_RAM       (PMA_FLAGS_M | PMA_FLAGS_X | PMA_FLAGS_W | PMA_FLAGS_R | PMA_FLAGS_IR | PMA_FLAGS_IW)
#define PMA_FLAGS_FLASH     (PMA_FLAGS_M | PMA_FLAGS_W | PMA_FLAGS_R | PMA_FLAGS_IR | PMA_FLAGS_IW)
#define PMA_FLAGS_DEVICE    (PMA_FLAGS_IO | PMA_FLAGS_W | PMA_FLAGS_R)

#define PMA_FLAGS_MASK 0xff

#define PMA_TYPE_MEMORY    (1 << 31)
#define PMA_TYPE_DEVICE    (1 << 30)

#define PMA_TYPE_FLAGS_RAM         (PMA_TYPE_MEMORY | PMA_FLAGS_RAM)
#define PMA_TYPE_FLAGS_FLASH       (PMA_TYPE_MEMORY | PMA_FLAGS_FLASH)
#define PMA_TYPE_FLAGS_DEVICE      (PMA_TYPE_DEVICE | PMA_FLAGS_DEVICE)

typedef struct {
    uint8_t *host_memory;      // start of associated memory region in host
    int backing_file;          // file descryptor for backed memory
} pma_memory;

typedef bool (*pma_device_write)(i_device_state_access *a, void *context, uint64_t offset, uint64_t val, int size_log2);
typedef bool (*pma_device_read)(i_device_state_access *a, void *context, uint64_t offset, uint64_t *val, int size_log2);

typedef struct {
    void *context;
    pma_device_read read;
    pma_device_read write;
} pma_device;

typedef struct {
    uint64_t start;
    uint64_t length;
    uint32_t type_flags;
    union {
        pma_memory memory;
        pma_device device;
    }; // anonymous union
} pma_entry; // Physical memory attributes

#define PMA_ENTRY_MAX 32

typedef struct {
    pma_entry entry[PMA_ENTRY_MAX];
    int count;
} physical_memory_map; // physical memory map

pmm *pmm_init(void);
void pmm_end(pmm *s);

bool processor_pmm_register_ram(physical_memory_map *s, uint64_t paddr, uint64_t size);

PhysMemoryRange *cpu_register_backed_ram(physical_memory_map *s, uint64_t paddr, uint64_t size, const char *path, bool shared);

PhysMemoryRange *cpu_register_device(physical_memory_map *s, uint64_t paddr,
                                     uint64_t size, void *opaque,
                                     DeviceReadFunc *read_func, DeviceWriteFunc *write_func);
PhysMemoryRange *get_phys_mem_range(pmm *s, uint64_t paddr);

#endif /* IOMEM_H */
