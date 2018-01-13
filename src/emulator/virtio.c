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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <stdarg.h>

#include "cutils.h"
#include "virtio.h"

//#define DEBUG_VIRTIO

/* MMIO addresses - from the Linux kernel */
#define VIRTIO_MMIO_MAGIC_VALUE		0x000
#define VIRTIO_MMIO_VERSION		0x004
#define VIRTIO_MMIO_DEVICE_ID		0x008
#define VIRTIO_MMIO_VENDOR_ID		0x00c
#define VIRTIO_MMIO_DEVICE_FEATURES	0x010
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL	0x014
#define VIRTIO_MMIO_DRIVER_FEATURES	0x020
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL	0x024
#define VIRTIO_MMIO_GUEST_PAGE_SIZE	0x028 /* version 1 only */
#define VIRTIO_MMIO_QUEUE_SEL		0x030
#define VIRTIO_MMIO_QUEUE_NUM_MAX	0x034
#define VIRTIO_MMIO_QUEUE_NUM		0x038
#define VIRTIO_MMIO_QUEUE_ALIGN		0x03c /* version 1 only */
#define VIRTIO_MMIO_QUEUE_PFN		0x040 /* version 1 only */
#define VIRTIO_MMIO_QUEUE_READY		0x044
#define VIRTIO_MMIO_QUEUE_NOTIFY	0x050
#define VIRTIO_MMIO_INTERRUPT_STATUS	0x060
#define VIRTIO_MMIO_INTERRUPT_ACK	0x064
#define VIRTIO_MMIO_STATUS		0x070
#define VIRTIO_MMIO_QUEUE_DESC_LOW	0x080
#define VIRTIO_MMIO_QUEUE_DESC_HIGH	0x084
#define VIRTIO_MMIO_QUEUE_AVAIL_LOW	0x090
#define VIRTIO_MMIO_QUEUE_AVAIL_HIGH	0x094
#define VIRTIO_MMIO_QUEUE_USED_LOW	0x0a0
#define VIRTIO_MMIO_QUEUE_USED_HIGH	0x0a4
#define VIRTIO_MMIO_CONFIG_GENERATION	0x0fc
#define VIRTIO_MMIO_CONFIG		0x100

/* PCI registers */
#define VIRTIO_PCI_DEVICE_FEATURE_SEL	0x000
#define VIRTIO_PCI_DEVICE_FEATURE	0x004
#define VIRTIO_PCI_GUEST_FEATURE_SEL	0x008
#define VIRTIO_PCI_GUEST_FEATURE	0x00c
#define VIRTIO_PCI_MSIX_CONFIG          0x010
#define VIRTIO_PCI_NUM_QUEUES           0x012
#define VIRTIO_PCI_DEVICE_STATUS        0x014
#define VIRTIO_PCI_CONFIG_GENERATION    0x015
#define VIRTIO_PCI_QUEUE_SEL		0x016
#define VIRTIO_PCI_QUEUE_SIZE	        0x018
#define VIRTIO_PCI_QUEUE_MSIX_VECTOR    0x01a
#define VIRTIO_PCI_QUEUE_ENABLE         0x01c
#define VIRTIO_PCI_QUEUE_NOTIFY_OFF     0x01e
#define VIRTIO_PCI_QUEUE_DESC_LOW	0x020
#define VIRTIO_PCI_QUEUE_DESC_HIGH	0x024
#define VIRTIO_PCI_QUEUE_AVAIL_LOW	0x028
#define VIRTIO_PCI_QUEUE_AVAIL_HIGH	0x02c
#define VIRTIO_PCI_QUEUE_USED_LOW	0x030
#define VIRTIO_PCI_QUEUE_USED_HIGH	0x034

#define VIRTIO_PCI_CFG_OFFSET          0x0000
#define VIRTIO_PCI_ISR_OFFSET          0x1000
#define VIRTIO_PCI_CONFIG_OFFSET       0x2000
#define VIRTIO_PCI_NOTIFY_OFFSET       0x3000

#define VIRTIO_PCI_CAP_LEN 16

#define MAX_QUEUE 8
#define MAX_CONFIG_SPACE_SIZE 256
#define MAX_QUEUE_NUM 16

typedef struct {
    uint32_t ready; /* 0 or 1 */
    uint32_t num;
    uint16_t last_avail_idx;
    virtio_phys_addr_t desc_addr;
    virtio_phys_addr_t avail_addr;
    virtio_phys_addr_t used_addr;
    BOOL manual_recv; /* if TRUE, the device_recv() callback is not called */
} QueueState;

#define VRING_DESC_F_NEXT	1
#define VRING_DESC_F_WRITE	2
#define VRING_DESC_F_INDIRECT	4

typedef struct {
    uint64_t addr;
    uint32_t len;
    uint16_t flags; /* VRING_DESC_F_x */
    uint16_t next;
} VIRTIODesc;

/* return < 0 to stop the notification (it must be manually restarted
   later), 0 if OK */
typedef int VIRTIODeviceRecvFunc(VIRTIODevice *s1, int queue_idx,
                                 int desc_idx, int read_size,
                                 int write_size);

/* return NULL if no RAM at this address. The mapping is valid for one page */
typedef uint8_t *VIRTIOGetRAMPtrFunc(VIRTIODevice *s, virtio_phys_addr_t paddr);

struct VIRTIODevice {
    PhysMemoryMap *mem_map;
    PhysMemoryRange *mem_range;
    /* MMIO only */
    IRQSignal *irq;
    VIRTIOGetRAMPtrFunc *get_ram_ptr;
    int debug;

    uint32_t int_status;
    uint32_t status;
    uint32_t device_features_sel;
    uint32_t queue_sel; /* currently selected queue */
    QueueState queue[MAX_QUEUE];

    /* device specific */
    uint32_t device_id;
    uint32_t vendor_id;
    uint32_t device_features;
    VIRTIODeviceRecvFunc *device_recv;
    void (*config_write)(VIRTIODevice *s); /* called after the config
                                              is written */
    uint32_t config_space_size; /* in bytes, must be multiple of 4 */
    uint8_t config_space[MAX_CONFIG_SPACE_SIZE];
};

static uint32_t virtio_mmio_read(void *opaque, uint32_t offset1, int size_log2);
static void virtio_mmio_write(void *opaque, uint32_t offset,
                              uint32_t val, int size_log2);

static void virtio_reset(VIRTIODevice *s)
{
    int i;

    s->status = 0;
    s->queue_sel = 0;
    s->device_features_sel = 0;
    s->int_status = 0;
    for(i = 0; i < MAX_QUEUE; i++) {
        QueueState *qs = &s->queue[i];
        qs->ready = 0;
        qs->num = MAX_QUEUE_NUM;
        qs->desc_addr = 0;
        qs->avail_addr = 0;
        qs->used_addr = 0;
        qs->last_avail_idx = 0;
    }
}

static uint8_t *virtio_mmio_get_ram_ptr(VIRTIODevice *s, virtio_phys_addr_t paddr)
{
    PhysMemoryRange *pr;

    pr = get_phys_mem_range(s->mem_map, paddr);
    if (!pr || !pr->is_ram)
        return NULL;
    return pr->phys_mem + (uintptr_t)(paddr - pr->addr);
}

static void virtio_init(VIRTIODevice *s, VIRTIOBusDef *bus,
                        uint32_t device_id, int config_space_size,
                        VIRTIODeviceRecvFunc *device_recv)
{
    memset(s, 0, sizeof(*s));

    /* MMIO case */
    s->mem_map = bus->mem_map;
    s->irq = bus->irq;
    s->mem_range = cpu_register_device(s->mem_map, bus->addr, VIRTIO_PAGE_SIZE,
       s, virtio_mmio_read, virtio_mmio_write, DEVIO_SIZE8 | DEVIO_SIZE16 |
       DEVIO_SIZE32);
    s->get_ram_ptr = virtio_mmio_get_ram_ptr;
    s->device_id = device_id;
    s->vendor_id = 0xffff;
    s->config_space_size = config_space_size;
    s->device_recv = device_recv;
    virtio_reset(s);
}

static uint16_t virtio_read16(VIRTIODevice *s, virtio_phys_addr_t addr)
{
    uint8_t *ptr;
    if (addr & 1)
        return 0; /* unaligned access are not supported */
    ptr = s->get_ram_ptr(s, addr);
    if (!ptr)
        return 0;
    return *(uint16_t *)ptr;
}

static void virtio_write16(VIRTIODevice *s, virtio_phys_addr_t addr,
                           uint16_t val)
{
    uint8_t *ptr;
    if (addr & 1)
        return; /* unaligned access are not supported */
    ptr = s->get_ram_ptr(s, addr);
    if (!ptr)
        return;
    *(uint16_t *)ptr = val;
}

static void virtio_write32(VIRTIODevice *s, virtio_phys_addr_t addr,
                           uint32_t val)
{
    uint8_t *ptr;
    if (addr & 3)
        return; /* unaligned access are not supported */
    ptr = s->get_ram_ptr(s, addr);
    if (!ptr)
        return;
    *(uint32_t *)ptr = val;
}

static int virtio_memcpy_from_ram(VIRTIODevice *s, uint8_t *buf,
                                  virtio_phys_addr_t addr, int count)
{
    uint8_t *ptr;
    int l;

    while (count > 0) {
        l = min_int(count, VIRTIO_PAGE_SIZE - (addr & (VIRTIO_PAGE_SIZE - 1)));
        ptr = s->get_ram_ptr(s, addr);
        if (!ptr)
            return -1;
        memcpy(buf, ptr, l);
        addr += l;
        buf += l;
        count -= l;
    }
    return 0;
}

static int virtio_memcpy_to_ram(VIRTIODevice *s, virtio_phys_addr_t addr,
                                const uint8_t *buf, int count)
{
    uint8_t *ptr;
    int l;

    while (count > 0) {
        l = min_int(count, VIRTIO_PAGE_SIZE - (addr & (VIRTIO_PAGE_SIZE - 1)));
        ptr = s->get_ram_ptr(s, addr);
        if (!ptr)
            return -1;
        memcpy(ptr, buf, l);
        addr += l;
        buf += l;
        count -= l;
    }
    return 0;
}

static int get_desc(VIRTIODevice *s, VIRTIODesc *desc,
                    int queue_idx, int desc_idx)
{
    QueueState *qs = &s->queue[queue_idx];
    return virtio_memcpy_from_ram(s, (void *)desc, qs->desc_addr +
                                  desc_idx * sizeof(VIRTIODesc),
                                  sizeof(VIRTIODesc));
}

static int memcpy_to_from_queue(VIRTIODevice *s, uint8_t *buf,
                                int queue_idx, int desc_idx,
                                int offset, int count, BOOL to_queue)
{
    VIRTIODesc desc;
    int l, f_write_flag;

    if (count == 0)
        return 0;

    get_desc(s, &desc, queue_idx, desc_idx);

    if (to_queue) {
        f_write_flag = VRING_DESC_F_WRITE;
        /* find the first write descriptor */
        for(;;) {
            if ((desc.flags & VRING_DESC_F_WRITE) == f_write_flag)
                break;
            if (!(desc.flags & VRING_DESC_F_NEXT))
                return -1;
            desc_idx = desc.next;
            get_desc(s, &desc, queue_idx, desc_idx);
        }
    } else {
        f_write_flag = 0;
    }

    /* find the descriptor at offset */
    for(;;) {
        if ((desc.flags & VRING_DESC_F_WRITE) != f_write_flag)
            return -1;
        if (offset < (int) desc.len)
            break;
        if (!(desc.flags & VRING_DESC_F_NEXT))
            return -1;
        desc_idx = desc.next;
        offset -= desc.len;
        get_desc(s, &desc, queue_idx, desc_idx);
    }

    for(;;) {
        l = min_int(count, desc.len - offset);
        if (to_queue)
            virtio_memcpy_to_ram(s, desc.addr + offset, buf, l);
        else
            virtio_memcpy_from_ram(s, buf, desc.addr + offset, l);
        count -= l;
        if (count == 0)
            break;
        offset += l;
        buf += l;
        if (offset == (int) desc.len) {
            if (!(desc.flags & VRING_DESC_F_NEXT))
                return -1;
            desc_idx = desc.next;
            get_desc(s, &desc, queue_idx, desc_idx);
            if ((desc.flags & VRING_DESC_F_WRITE) != f_write_flag)
                return -1;
            offset = 0;
        }
    }
    return 0;
}

static int memcpy_from_queue(VIRTIODevice *s, void *buf,
                             int queue_idx, int desc_idx,
                             int offset, int count)
{
    return memcpy_to_from_queue(s, buf, queue_idx, desc_idx, offset, count,
                                FALSE);
}

static int memcpy_to_queue(VIRTIODevice *s,
                           int queue_idx, int desc_idx,
                           int offset, const void *buf, int count)
{
    return memcpy_to_from_queue(s, (void *)buf, queue_idx, desc_idx, offset,
                                count, TRUE);
}

/* signal that the descriptor has been consumed */
static void virtio_consume_desc(VIRTIODevice *s,
                                int queue_idx, int desc_idx, int desc_len)
{
    QueueState *qs = &s->queue[queue_idx];
    virtio_phys_addr_t addr;
    uint32_t index;

    addr = qs->used_addr + 2;
    index = virtio_read16(s, addr);
    virtio_write16(s, addr, index + 1);

    addr = qs->used_addr + 4 + (index & (qs->num - 1)) * 8;
    virtio_write32(s, addr, desc_idx);
    virtio_write32(s, addr + 4, desc_len);

    s->int_status |= 1;
    set_irq(s->irq, 1);
}

static int get_desc_rw_size(VIRTIODevice *s,
                             int *pread_size, int *pwrite_size,
                             int queue_idx, int desc_idx)
{
    VIRTIODesc desc;
    int read_size, write_size;

    read_size = 0;
    write_size = 0;
    get_desc(s, &desc, queue_idx, desc_idx);

    for(;;) {
        if (desc.flags & VRING_DESC_F_WRITE)
            break;
        read_size += desc.len;
        if (!(desc.flags & VRING_DESC_F_NEXT))
            goto done;
        desc_idx = desc.next;
        get_desc(s, &desc, queue_idx, desc_idx);
    }

    for(;;) {
        if (!(desc.flags & VRING_DESC_F_WRITE))
            return -1;
        write_size += desc.len;
        if (!(desc.flags & VRING_DESC_F_NEXT))
            break;
        desc_idx = desc.next;
        get_desc(s, &desc, queue_idx, desc_idx);
    }

 done:
    *pread_size = read_size;
    *pwrite_size = write_size;
    return 0;
}

/* XXX: test if the queue is ready ? */
static void queue_notify(VIRTIODevice *s, int queue_idx)
{
    QueueState *qs = &s->queue[queue_idx];
    uint16_t avail_idx;
    int desc_idx, read_size, write_size;

    if (qs->manual_recv)
        return;

    avail_idx = virtio_read16(s, qs->avail_addr + 2);
    while (qs->last_avail_idx != avail_idx) {
        desc_idx = virtio_read16(s, qs->avail_addr + 4 +
                                 (qs->last_avail_idx & (qs->num - 1)) * 2);
        if (!get_desc_rw_size(s, &read_size, &write_size, queue_idx, desc_idx)) {
#ifdef DEBUG_VIRTIO
            if (s->debug & VIRTIO_DEBUG_IO) {
                printf("queue_notify: idx=%d read_size=%d write_size=%d\n",
                       queue_idx, read_size, write_size);
            }
#endif
            if (s->device_recv(s, queue_idx, desc_idx,
                               read_size, write_size) < 0)
                break;
        }
        qs->last_avail_idx++;
    }
}

static uint32_t virtio_config_read(VIRTIODevice *s, uint32_t offset,
                                   int size_log2)
{
    uint32_t val;
    switch(size_log2) {
    case 0:
        if (offset < s->config_space_size) {
            val = s->config_space[offset];
        } else {
            val = 0;
        }
        break;
    case 1:
        if (offset < (s->config_space_size - 1)) {
            val = get_le16(&s->config_space[offset]);
        } else {
            val = 0;
        }
        break;
    case 2:
        if (offset < (s->config_space_size - 3)) {
            val = get_le32(s->config_space + offset);
        } else {
            val = 0;
        }
        break;
    default:
        abort();
    }
    return val;
}

static void virtio_config_write(VIRTIODevice *s, uint32_t offset,
                                uint32_t val, int size_log2)
{
    switch(size_log2) {
    case 0:
        if (offset < s->config_space_size) {
            s->config_space[offset] = val;
            if (s->config_write)
                s->config_write(s);
        }
        break;
    case 1:
        if (offset < s->config_space_size - 1) {
            put_le16(s->config_space + offset, val);
            if (s->config_write)
                s->config_write(s);
        }
        break;
    case 2:
        if (offset < s->config_space_size - 3) {
            put_le32(s->config_space + offset, val);
            if (s->config_write)
                s->config_write(s);
        }
        break;
    }
}

static uint32_t virtio_mmio_read(void *opaque, uint32_t offset, int size_log2)
{
    VIRTIODevice *s = opaque;
    uint32_t val;

    if (offset >= VIRTIO_MMIO_CONFIG) {
        return virtio_config_read(s, offset - VIRTIO_MMIO_CONFIG, size_log2);
    }

    if (size_log2 == 2) {
        switch(offset) {
        case VIRTIO_MMIO_MAGIC_VALUE:
            val = 0x74726976;
            break;
        case VIRTIO_MMIO_VERSION:
            val = 2;
            break;
        case VIRTIO_MMIO_DEVICE_ID:
            val = s->device_id;
            break;
        case VIRTIO_MMIO_VENDOR_ID:
            val = s->vendor_id;
            break;
        case VIRTIO_MMIO_DEVICE_FEATURES:
            switch(s->device_features_sel) {
            case 0:
                val = s->device_features;
                break;
            case 1:
                val = 1; /* version 1 */
                break;
            default:
                val = 0;
                break;
            }
            break;
        case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
            val = s->device_features_sel;
            break;
        case VIRTIO_MMIO_QUEUE_SEL:
            val = s->queue_sel;
            break;
        case VIRTIO_MMIO_QUEUE_NUM_MAX:
            val = MAX_QUEUE_NUM;
            break;
        case VIRTIO_MMIO_QUEUE_NUM:
            val = s->queue[s->queue_sel].num;
            break;
        case VIRTIO_MMIO_QUEUE_DESC_LOW:
            val = s->queue[s->queue_sel].desc_addr;
            break;
        case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
            val = s->queue[s->queue_sel].avail_addr;
            break;
        case VIRTIO_MMIO_QUEUE_USED_LOW:
            val = s->queue[s->queue_sel].used_addr;
            break;
#if VIRTIO_ADDR_BITS == 64
        case VIRTIO_MMIO_QUEUE_DESC_HIGH:
            val = s->queue[s->queue_sel].desc_addr >> 32;
            break;
        case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
            val = s->queue[s->queue_sel].avail_addr >> 32;
            break;
        case VIRTIO_MMIO_QUEUE_USED_HIGH:
            val = s->queue[s->queue_sel].used_addr >> 32;
            break;
#endif
        case VIRTIO_MMIO_QUEUE_READY:
            val = s->queue[s->queue_sel].ready;
            break;
        case VIRTIO_MMIO_INTERRUPT_STATUS:
            val = s->int_status;
            break;
        case VIRTIO_MMIO_STATUS:
            val = s->status;
            break;
        case VIRTIO_MMIO_CONFIG_GENERATION:
            val = 0;
            break;
        default:
            val = 0;
            break;
        }
    } else {
        val = 0;
    }
#ifdef DEBUG_VIRTIO
    if (s->debug & VIRTIO_DEBUG_IO) {
        printf("virto_mmio_read: offset=0x%x val=0x%x size=%d\n",
               offset, val, 1 << size_log2);
    }
#endif
    return val;
}

#if VIRTIO_ADDR_BITS == 64
static void set_low32(virtio_phys_addr_t *paddr, uint32_t val)
{
    *paddr = (*paddr & ~(virtio_phys_addr_t)0xffffffff) | val;
}

static void set_high32(virtio_phys_addr_t *paddr, uint32_t val)
{
    *paddr = (*paddr & 0xffffffff) | ((virtio_phys_addr_t)val << 32);
}
#else
static void set_low32(virtio_phys_addr_t *paddr, uint32_t val)
{
    *paddr = val;
}
#endif

static void virtio_mmio_write(void *opaque, uint32_t offset,
                              uint32_t val, int size_log2)
{
    VIRTIODevice *s = opaque;

#ifdef DEBUG_VIRTIO
    if (s->debug & VIRTIO_DEBUG_IO) {
        printf("virto_mmio_write: offset=0x%x val=0x%x size=%d\n",
               offset, val, 1 << size_log2);
    }
#endif

    if (offset >= VIRTIO_MMIO_CONFIG) {
        virtio_config_write(s, offset - VIRTIO_MMIO_CONFIG, val, size_log2);
        return;
    }

    if (size_log2 == 2) {
        switch(offset) {
        case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
            s->device_features_sel = val;
            break;
        case VIRTIO_MMIO_QUEUE_SEL:
            if (val < MAX_QUEUE)
                s->queue_sel = val;
            break;
        case VIRTIO_MMIO_QUEUE_NUM:
            if ((val & (val - 1)) == 0 && val > 0) {
                s->queue[s->queue_sel].num = val;
            }
            break;
        case VIRTIO_MMIO_QUEUE_DESC_LOW:
            set_low32(&s->queue[s->queue_sel].desc_addr, val);
            break;
        case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
            set_low32(&s->queue[s->queue_sel].avail_addr, val);
            break;
        case VIRTIO_MMIO_QUEUE_USED_LOW:
            set_low32(&s->queue[s->queue_sel].used_addr, val);
            break;
#if VIRTIO_ADDR_BITS == 64
        case VIRTIO_MMIO_QUEUE_DESC_HIGH:
            set_high32(&s->queue[s->queue_sel].desc_addr, val);
            break;
        case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
            set_high32(&s->queue[s->queue_sel].avail_addr, val);
            break;
        case VIRTIO_MMIO_QUEUE_USED_HIGH:
            set_high32(&s->queue[s->queue_sel].used_addr, val);
            break;
#endif
        case VIRTIO_MMIO_STATUS:
            s->status = val;
            if (val == 0) {
                /* reset */
                set_irq(s->irq, 0);
                virtio_reset(s);
            }
            break;
        case VIRTIO_MMIO_QUEUE_READY:
            s->queue[s->queue_sel].ready = val & 1;
            break;
        case VIRTIO_MMIO_QUEUE_NOTIFY:
            if (val < MAX_QUEUE)
                queue_notify(s, val);
            break;
        case VIRTIO_MMIO_INTERRUPT_ACK:
            s->int_status &= ~val;
            if (s->int_status == 0) {
                set_irq(s->irq, 0);
            }
            break;
        }
    }
}

void virtio_set_debug(VIRTIODevice *s, int debug)
{
    s->debug = debug;
}

static void virtio_config_change_notify(VIRTIODevice *s)
{
    /* INT_CONFIG interrupt */
    s->int_status |= 2;
    set_irq(s->irq, 1);
}

/*********************************************************************/
/* console device */

typedef struct VIRTIOConsoleDevice {
    VIRTIODevice common;
    CharacterDevice *cs;
} VIRTIOConsoleDevice;

static int virtio_console_recv_request(VIRTIODevice *s, int queue_idx,
                                       int desc_idx, int read_size,
                                       int write_size)
{
    VIRTIOConsoleDevice *s1 = (VIRTIOConsoleDevice *)s;
    CharacterDevice *cs = s1->cs;
    uint8_t *buf;
    (void) write_size;

    if (queue_idx == 1) {
        /* send to console */
        buf = malloc(read_size);
        memcpy_from_queue(s, buf, queue_idx, desc_idx, 0, read_size);
        cs->write_data(cs->opaque, buf, read_size);
        free(buf);
        virtio_consume_desc(s, queue_idx, desc_idx, 0);
    }
    return 0;
}

BOOL virtio_console_can_write_data(VIRTIODevice *s)
{
    QueueState *qs = &s->queue[0];
    uint16_t avail_idx;

    if (!qs->ready)
        return FALSE;
    avail_idx = virtio_read16(s, qs->avail_addr + 2);
    return qs->last_avail_idx != avail_idx;
}

int virtio_console_get_write_len(VIRTIODevice *s)
{
    int queue_idx = 0;
    QueueState *qs = &s->queue[queue_idx];
    int desc_idx;
    int read_size, write_size;
    uint16_t avail_idx;

    if (!qs->ready)
        return 0;
    avail_idx = virtio_read16(s, qs->avail_addr + 2);
    if (qs->last_avail_idx == avail_idx)
        return 0;
    desc_idx = virtio_read16(s, qs->avail_addr + 4 +
                             (qs->last_avail_idx & (qs->num - 1)) * 2);
    if (get_desc_rw_size(s, &read_size, &write_size, queue_idx, desc_idx))
        return 0;
    return write_size;
}

int virtio_console_write_data(VIRTIODevice *s, const uint8_t *buf, int buf_len)
{
    int queue_idx = 0;
    QueueState *qs = &s->queue[queue_idx];
    int desc_idx;
    uint16_t avail_idx;

    if (!qs->ready)
        return 0;
    avail_idx = virtio_read16(s, qs->avail_addr + 2);
    if (qs->last_avail_idx == avail_idx)
        return 0;
    desc_idx = virtio_read16(s, qs->avail_addr + 4 +
                             (qs->last_avail_idx & (qs->num - 1)) * 2);
    memcpy_to_queue(s, queue_idx, desc_idx, 0, buf, buf_len);
    virtio_consume_desc(s, queue_idx, desc_idx, buf_len);
    qs->last_avail_idx++;
    return buf_len;
}

/* send a resize event */
void virtio_console_resize_event(VIRTIODevice *s, int width, int height)
{
    /* indicate the console size */
    put_le16(s->config_space + 0, width);
    put_le16(s->config_space + 2, height);

    virtio_config_change_notify(s);
}

VIRTIODevice *virtio_console_init(VIRTIOBusDef *bus, CharacterDevice *cs)
{
    VIRTIOConsoleDevice *s;

    s = mallocz(sizeof(*s));
    virtio_init(&s->common, bus,
                3, 4, virtio_console_recv_request);
    s->common.device_features = (1 << 0); /* VIRTIO_CONSOLE_F_SIZE */
    s->common.queue[0].manual_recv = TRUE;

    s->cs = cs;
    return (VIRTIODevice *)s;
}
