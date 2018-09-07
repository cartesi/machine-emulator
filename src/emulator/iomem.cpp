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
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include <sys/mman.h> /* mmap, munmap */
#include <unistd.h> /* close */
#include <fcntl.h> /* open */

#include "iomem.h"

PhysMemoryMap *phys_mem_map_init(void)
{
    PhysMemoryMap *s = reinterpret_cast<PhysMemoryMap *>(calloc(1, sizeof(*s)));
    return s;
}

void phys_mem_map_end(PhysMemoryMap *s)
{
    int i;
    PhysMemoryRange *pr;

    for(i = 0; i < s->n_phys_mem_range; i++) {
        pr = &s->phys_mem_range[i];
        if (pr->is_ram) {
            if (pr->is_backed) {
                munmap(pr->phys_mem, pr->size);
                close(pr->fd);
            } else {
                free(pr->phys_mem);
            }
        }
    }
    free(s);
}

/* return NULL if not found */
/* XXX: optimize */
PhysMemoryRange *get_phys_mem_range(PhysMemoryMap *s, uint64_t paddr)
{
    for (int i = 0; i < s->n_phys_mem_range; i++) {
        PhysMemoryRange *pr = &s->phys_mem_range[i];
        if (paddr >= pr->paddr && paddr < pr->paddr + pr->size)
            return pr;
    }
    return nullptr;
}

static PhysMemoryRange *register_ram_entry(PhysMemoryMap *s, uint64_t paddr,
                                    uint64_t size)
{
    assert(s->n_phys_mem_range < PHYS_MEM_RANGE_MAX);
    assert((size & (DEVRAM_PAGE_SIZE - 1)) == 0 && size != 0);
    PhysMemoryRange *pr = &s->phys_mem_range[s->n_phys_mem_range++];
    pr->is_ram = true;
    pr->paddr = paddr;
    pr->size = size;
    pr->phys_mem = nullptr;
    return pr;
}

PhysMemoryRange *cpu_register_backed_ram(PhysMemoryMap *s, uint64_t paddr,
                                     uint64_t size, const char *path,
                                     bool shared)
{
    int oflag = shared? O_RDWR: O_RDONLY;
    int mflag = shared? MAP_SHARED: MAP_PRIVATE;

    /*??D probably should be careful here to align the size
     * to a 4KiB page boundary and clear the remaining
     * memory by hand, even though the kernel should do this
     * itself */

    PhysMemoryRange *pr = register_ram_entry(s, paddr, size);

    pr->fd = open(path, oflag);
    if (pr->fd < 0) {
        fprintf(stderr, "Could not open file %s\n", path);
        exit(1);
    }

    pr->phys_mem = reinterpret_cast<uint8_t *>(
        mmap(nullptr, size, PROT_READ | PROT_WRITE, mflag, pr->fd, 0));
    if (!pr->phys_mem) {
        fprintf(stderr, "Could not map filed-backed memory\n");
        exit(1);
    }
    pr->is_backed = true;

    return pr;
}



PhysMemoryRange *cpu_register_ram(PhysMemoryMap *s, uint64_t paddr,
                                             uint64_t size)
{
    PhysMemoryRange *pr;

    pr = register_ram_entry(s, paddr, size);

    pr->phys_mem = reinterpret_cast<uint8_t *>(calloc(1, size));
    if (!pr->phys_mem) {
        fprintf(stderr, "Could not allocate VM memory\n");
        exit(1);
    }

    return pr;
}

PhysMemoryRange *cpu_register_device(PhysMemoryMap *s, uint64_t paddr,
                                     uint64_t size, void *opaque,
                                     DeviceReadFunc *read_func, DeviceWriteFunc *write_func)
{
    PhysMemoryRange *pr;
    assert(s->n_phys_mem_range < PHYS_MEM_RANGE_MAX);
    assert(size <= 0xffffffff); //??D ??
    pr = &s->phys_mem_range[s->n_phys_mem_range++];
    pr->paddr = paddr;
    pr->size = size;
    pr->is_ram = false;
    pr->opaque = opaque;
    pr->read_func = read_func;
    pr->write_func = write_func;
    return pr;
}
