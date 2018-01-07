/*
 * VIRTIO driver
 *
 * Copyright (c) 2016 Fabrice Bellard
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
#ifndef VIRTIO_H
#define VIRTIO_H

#include <sys/select.h>
#include "iomem.h"
#include "pci.h"

#define VIRTIO_PAGE_SIZE 4096
#define VIRTIO_ADDR_BITS 64
typedef uint64_t virtio_phys_addr_t;

typedef struct {
    /* PCI only: */
    PCIBus *pci_bus;
    /* MMIO only: */
    PhysMemoryMap *mem_map;
    uint64_t addr;
    IRQSignal *irq;
} VIRTIOBusDef;

typedef struct VIRTIODevice VIRTIODevice;

#define VIRTIO_DEBUG_IO (1 << 0)

void virtio_set_debug(VIRTIODevice *s, int debug_flags);

/* console device */

typedef struct {
    void *opaque;
    void (*write_data)(void *opaque, const uint8_t *buf, int len);
    int (*read_data)(void *opaque, uint8_t *buf, int len);
} CharacterDevice;

VIRTIODevice *virtio_console_init(VIRTIOBusDef *bus, CharacterDevice *cs);
BOOL virtio_console_can_write_data(VIRTIODevice *s);
int virtio_console_get_write_len(VIRTIODevice *s);
int virtio_console_write_data(VIRTIODevice *s, const uint8_t *buf, int buf_len);
void virtio_console_resize_event(VIRTIODevice *s, int width, int height);

#endif /* VIRTIO_H */
