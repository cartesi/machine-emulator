/*
 * Simple PCI bus driver
 * 
 * Copyright (c) 2017 Fabrice Bellard
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
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <stdarg.h>

#include "cutils.h"
#include "pci.h"

//#define DEBUG_CONFIG

typedef struct {
    uint32_t size; /* 0 means no mapping defined */
    uint8_t type;
    uint8_t enabled; /* true if mapping is enabled */
    void *opaque;
    PCIBarSetFunc *bar_set;
} PCIIORegion;

struct PCIDevice {
    PCIBus *bus;
    uint8_t devfn;
    IRQSignal irq[4];
    uint8_t config[256];
    uint8_t next_cap_offset; /* offset of the next capability */
    char *name; /* for debug only */
    PCIIORegion io_regions[PCI_NUM_REGIONS];
};

struct PCIBus {
    int bus_num;
    PCIDevice *device[256];
    PhysMemoryMap *mem_map;
    PhysMemoryMap *port_map;
    uint32_t irq_state[4][8]; /* one bit per device */
    IRQSignal irq[4];
};

static int bus_map_irq(PCIDevice *d, int irq_num)
{
    int slot_addend;
    slot_addend = (d->devfn >> 3) - 1;
    return (irq_num + slot_addend) & 3;
}

static void pci_device_set_irq(void *opaque, int irq_num, int level)
{
    PCIDevice *d = opaque;
    PCIBus *b = d->bus;
    uint32_t mask;
    int i, irq_level;
    
    //    printf("%s: pci_device_seq_irq: %d %d\n", d->name, irq_num, level);
    irq_num = bus_map_irq(d, irq_num);
    mask = 1 << (d->devfn & 0x1f);
    if (level)
        b->irq_state[irq_num][d->devfn >> 5] |= mask;
    else
        b->irq_state[irq_num][d->devfn >> 5] &= ~mask;

    /* compute the IRQ state */
    mask = 0;
    for(i = 0; i < 8; i++)
        mask |= b->irq_state[irq_num][i];
    irq_level = (mask != 0);
    set_irq(&b->irq[irq_num], irq_level);
}

static int devfn_alloc(PCIBus *b)
{
    int devfn;
    for(devfn = 0; devfn < 256; devfn += 8) {
        if (!b->device[devfn])
            return devfn;
    }
    return -1;
}

/* devfn < 0 means to allocate it */
PCIDevice *pci_register_device(PCIBus *b, const char *name, int devfn,
                               uint16_t vendor_id, uint16_t device_id,
                               uint8_t revision, uint16_t class_id)
{
    PCIDevice *d;
    int i;
    
    if (devfn < 0) {
        devfn = devfn_alloc(b);
        if (devfn < 0)
            return NULL;
    }
    if (b->device[devfn])
        return NULL;

    d = mallocz(sizeof(PCIDevice));
    d->bus = b;
    d->name = strdup(name);
    d->devfn = devfn;

    put_le16(d->config + 0x00, vendor_id);
    put_le16(d->config + 0x02, device_id);
    d->config[0x08] = revision;
    put_le16(d->config + 0x0a, class_id);
    d->config[0x0e] = 0x00; /* header type */
    d->next_cap_offset = 0x40;
    
    for(i = 0; i < 4; i++)
        irq_init(&d->irq[i], pci_device_set_irq, d, i);
    b->device[devfn] = d;

    return d;
}

IRQSignal *pci_device_get_irq(PCIDevice *d, unsigned int irq_num)
{
    assert(irq_num < 4);
    return &d->irq[irq_num];
}

static uint32_t pci_device_config_read(PCIDevice *d, uint32_t addr,
                                       int size_log2)
{
    uint32_t val;
    switch(size_log2) {
    case 0:
        val = *(uint8_t *)(d->config + addr);
        break;
    case 1:
        /* Note: may be unaligned */
        if (addr <= 0xfe)
            val = get_le16(d->config + addr);
        else
            val = *(uint8_t *)(d->config + addr);
        break;
    case 2:
        /* always aligned */
        val = get_le32(d->config + addr);
        break;
    default:
        abort();
    }
#ifdef DEBUG_CONFIG
    printf("pci_config_read: dev=%s addr=0x%02x val=0x%x s=%d\n",
           d->name, addr, val, 1 << size_log2);
#endif
    return val;
}

PhysMemoryMap *pci_device_get_mem_map(PCIDevice *d)
{
    return d->bus->mem_map;
}

PhysMemoryMap *pci_device_get_port_map(PCIDevice *d)
{
    return d->bus->port_map;
}

void pci_register_bar(PCIDevice *d, unsigned int bar_num,
                      uint32_t size, int type,
                      void *opaque, PCIBarSetFunc *bar_set)
{
    PCIIORegion *r;
    uint32_t val, config_addr;
    
    assert(bar_num < PCI_NUM_REGIONS);
    assert((size & (size - 1)) == 0); /* power of two */
    assert(size >= 4);
    r = &d->io_regions[bar_num];
    assert(r->size == 0);
    r->size = size;
    r->type = type;
    r->enabled = FALSE;
    r->opaque = opaque;
    r->bar_set = bar_set;
    /* set the config value */
    val = 0;
    if (bar_num == PCI_ROM_SLOT) {
        config_addr = 0x30;
    } else {
        val |= r->type;
        config_addr = 0x10 + 4 * bar_num;
    }
    put_le32(&d->config[config_addr], val);
}

static void pci_update_mappings(PCIDevice *d)
{
    int cmd, i, offset;
    uint32_t new_addr;
    BOOL new_enabled;
    PCIIORegion *r;
    
    cmd = get_le16(&d->config[PCI_COMMAND]);

    for(i = 0; i < PCI_NUM_REGIONS; i++) {
        r = &d->io_regions[i];
        if (i == PCI_ROM_SLOT) {
            offset = 0x30;
        } else {
            offset = 0x10 + i * 4;
        }
        new_addr = get_le32(&d->config[offset]);
        new_enabled = FALSE;
        if (r->size != 0) {
            if ((r->type & PCI_ADDRESS_SPACE_IO) &&
                (cmd & PCI_COMMAND_IO)) {
                new_enabled = TRUE;
            } else {
                if (cmd & PCI_COMMAND_MEMORY) {
                    if (i == PCI_ROM_SLOT) {
                        new_enabled = (new_addr & 1);
                    } else {
                        new_enabled = TRUE;
                    }
                }
            }
        }
        if (new_enabled) {
            /* new address */
            new_addr = get_le32(&d->config[offset]) & ~(r->size - 1);
            r->bar_set(r->opaque, i, new_addr, TRUE);
            r->enabled = TRUE;
        } else if (r->enabled) {
            r->bar_set(r->opaque, i, 0, FALSE);
            r->enabled = FALSE;
        }
    }
}

/* return != 0 if write is not handled */
static int pci_write_bar(PCIDevice *d, uint32_t addr,
                          uint32_t val)
{
    PCIIORegion *r;
    int reg;
    
    if (addr == 0x30)
        reg = PCI_ROM_SLOT;
    else
        reg = (addr - 0x10) >> 2;
    //    printf("%s: write bar addr=%x data=%x\n", d->name, addr, val);
    r = &d->io_regions[reg];
    if (r->size == 0)
        return -1;
    if (reg == PCI_ROM_SLOT) {
        val = val & ((~(r->size - 1)) | 1);
    } else {
        val = (val & ~(r->size - 1)) | r->type;
    }
    put_le32(d->config + addr, val);
    pci_update_mappings(d);
    return 0;
}

static void pci_device_config_write8(PCIDevice *d, uint32_t addr,
                                     uint32_t data)
{
    int can_write;

    if (addr == PCI_STATUS || addr == (PCI_STATUS + 1)) {
        /* write 1 reset bits */
        d->config[addr] &= ~data;
        return;
    }
    
    switch(d->config[0x0e]) {
    case 0x00:
    case 0x80:
        switch(addr) {
        case 0x00:
        case 0x01:
        case 0x02:
        case 0x03:
        case 0x08:
        case 0x09:
        case 0x0a:
        case 0x0b:
        case 0x0e:
        case 0x10 ... 0x27: /* base */
        case 0x30 ... 0x33: /* rom */
        case 0x3d:
            can_write = 0;
            break;
        default:
            can_write = 1;
            break;
        }
        break;
    default:
    case 0x01:
        switch(addr) {
        case 0x00:
        case 0x01:
        case 0x02:
        case 0x03:
        case 0x08:
        case 0x09:
        case 0x0a:
        case 0x0b:
        case 0x0e:
        case 0x38 ... 0x3b: /* rom */
        case 0x3d:
            can_write = 0;
            break;
        default:
            can_write = 1;
            break;
        }
        break;
    }
    if (can_write)
        d->config[addr] = data;
}
                                  

static void pci_device_config_write(PCIDevice *d, uint32_t addr,
                                    uint32_t data, int size_log2)
{
    int size, i;
    uint32_t addr1;
    
#ifdef DEBUG_CONFIG
    printf("pci_config_write: dev=%s addr=0x%02x val=0x%x s=%d\n",
           d->name, addr, data, 1 << size_log2);
#endif
    if (size_log2 == 2 &&
        ((addr >= 0x10 && addr < 0x10 + 4 * 6) ||
         addr == 0x30)) {
        if (pci_write_bar(d, addr, data) == 0)
            return;
    }
    size = 1 << size_log2;
    for(i = 0; i < size; i++) {
        addr1 = addr + i;
        if (addr1 <= 0xff) {
            pci_device_config_write8(d, addr1, (data >> (i * 8)) & 0xff);
        }
    }
    if (PCI_COMMAND >= addr && PCI_COMMAND < addr + size) {
        pci_update_mappings(d);
    }
}


static void pci_data_write(PCIBus *s, uint32_t addr,
                           uint32_t data, int size_log2)
{
    PCIDevice *d;
    int bus_num, devfn, config_addr;
    
    bus_num = (addr >> 16) & 0xff;
    if (bus_num != s->bus_num)
        return;
    devfn = (addr >> 8) & 0xff;
    d = s->device[devfn];
    if (!d)
        return;
    config_addr = addr & 0xff;
    pci_device_config_write(d, config_addr, data, size_log2);
}

static const uint32_t val_ones[3] = { 0xff, 0xffff, 0xffffffff };

static uint32_t pci_data_read(PCIBus *s, uint32_t addr, int size_log2)
{
    PCIDevice *d;
    int bus_num, devfn, config_addr;
    
    bus_num = (addr >> 16) & 0xff;
    if (bus_num != s->bus_num)
        return val_ones[size_log2];
    devfn = (addr >> 8) & 0xff;
    d = s->device[devfn];
    if (!d)
        return val_ones[size_log2];
    config_addr = addr & 0xff;
    return pci_device_config_read(d, config_addr, size_log2);
}

/* warning: only valid for one DEVIO page. Return NULL if no memory at
   the given address */
uint8_t *pci_device_get_dma_ptr(PCIDevice *d, uint64_t addr)
{
    PhysMemoryRange *pr;
    pr = get_phys_mem_range(d->bus->mem_map, addr);
    if (!pr || !pr->is_ram)
        return NULL;
    return pr->phys_mem + (uintptr_t)(addr - pr->addr);
}

void pci_device_set_config8(PCIDevice *d, uint8_t addr, uint8_t val)
{
    d->config[addr] = val;
}

void pci_device_set_config16(PCIDevice *d, uint8_t addr, uint16_t val)
{
    put_le16(&d->config[addr], val);
}

int pci_device_get_devfn(PCIDevice *d)
{
    return d->devfn;
}

/* return the offset of the capability or < 0 if error. */
int pci_add_capability(PCIDevice *d, const uint8_t *buf, int size)
{
    int offset;
    
    offset = d->next_cap_offset;
    if ((offset + size) > 256)
        return -1;
    d->next_cap_offset += size;
    d->config[PCI_STATUS] |= PCI_STATUS_CAP_LIST;
    memcpy(d->config + offset, buf, size);
    d->config[offset + 1] = d->config[PCI_CAPABILITY_LIST];
    d->config[PCI_CAPABILITY_LIST] = offset;
    return offset;
}
