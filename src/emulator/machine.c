/*
 * VM utilities
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
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>

#include "cutils.h"
#include "iomem.h"
#include "riscv_cpu.h"
#include "virtio.h"
#include "fdt.h"

#include "machine.h"

/* RISCV machine */

typedef struct RISCVMachine {
    VirtMachine common;
    PhysMemoryMap *mem_map;
    RISCVCPUState *cpu_state;
    uint64_t ram_size;
    /* RTC */
    uint64_t timecmp;
    /* PLIC */
    uint32_t plic_pending_irq, plic_served_irq;
    IRQSignal plic_irq[32]; /* IRQ 0 is not used */
    /* HTIF */
    uint64_t htif_tohost, htif_fromhost;

    int virtio_count;
} RISCVMachine;

#define LOW_RAM_SIZE   0x00010000 /* 64KB */
#define RAM_BASE_ADDR  0x80000000
#define CLINT_BASE_ADDR 0x02000000
#define CLINT_SIZE      0x000c0000
#define HTIF_BASE_ADDR 0x40008000
#define VIRTIO_BASE_ADDR 0x40010000
#define VIRTIO_SIZE      0x1000
#define VIRTIO_IRQ       1
#define PLIC_BASE_ADDR 0x40100000
#define PLIC_SIZE      0x00400000

#define RTC_FREQ 10000000
#define RTC_FREQ_DIV 16 /* arbitrary, relative to CPU freq to have a
                           10 MHz frequency */

void __attribute__((format(printf, 1, 2))) vm_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
#ifdef EMSCRIPTEN
    vprintf(fmt, ap);
#else
    vfprintf(stderr, fmt, ap);
#endif
    va_end(ap);
}

/* return -1 if error. */
static int load_file(uint8_t **pbuf, const char *filename)
{
    FILE *f;
    int size;
    uint8_t *buf;

    f = fopen(filename, "rb");
    if (!f) {
        perror(filename);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc(size);
    if (fread(buf, 1, size, f) != size) {
        fprintf(stderr, "%s: read error\n", filename);
        exit(1);
    }
    fclose(f);
    *pbuf = buf;
    return size;
}

static int optboolean(lua_State *L, int tabidx, const char *field, int def) {
    int val = def;
    lua_getfield(L, tabidx, field);
    if (lua_isboolean(L, -1)) {
        val = lua_toboolean(L, -1);
    } else if (!lua_isnil(L, -1)) {
        luaL_error(L, "Invalid %s (expected Boolean).", field);
    }
    lua_pop(L, 1);
    return val;
}

static uint64_t checkuint(lua_State *L, int tabidx, const char *field) {
    lua_Integer ival;
    lua_getfield(L, tabidx, field);
    if (!lua_isinteger(L, -1))
        luaL_error(L, "Invalid %s (expected unsigned integer).", field);
    ival = lua_tointeger(L, -1);
    if (ival < 0)
        luaL_error(L, "Invalid %s (expected unsigned integer).", field);
    lua_pop(L, 1);
    return (uint64_t) ival;
}

static char *dupoptstring(lua_State *L, int tabidx, const char *field) {
    char *val = NULL;
    lua_getfield(L, tabidx, field);
    if (lua_isnil(L, -1)) {
        val = NULL;
    } else if (lua_isstring(L, -1)) {
        val = strdup(lua_tostring(L, -1));
    } else {
        luaL_error(L, "Invalid %s (expected string).", field);
    }
    lua_pop(L, 1);
    return val;
}

static char *dupcheckstring(lua_State *L, int tabidx, const char *field) {
    char *val = NULL;
    lua_getfield(L, tabidx, field);
    if (lua_isstring(L, -1)) {
        val = strdup(lua_tostring(L, -1));
    } else {
        luaL_error(L, "Invalid %s (expected string).", field);
    }
    lua_pop(L, 1);
    return val;
}

void virt_lua_load_config(lua_State *L, VirtMachineParams *p, int tabidx) {

    virt_machine_set_defaults(p);

    if (checkuint(L, tabidx, "version") != VM_CONFIG_VERSION) {
        luaL_error(L, "Emulator does not match version number.");
    }

    lua_getfield(L, tabidx, "machine");
    if (!lua_isstring(L, -1)) {
        luaL_error(L, "No machine string.");
    }
    if (strcmp(virt_machine_get_name(), lua_tostring(L, -1)) != 0) {
        luaL_error(L, "Unsupported machine %s (running machine is %s).",
            lua_tostring(L, -1), virt_machine_get_name());
    }
    lua_pop(L, 1);

    p->ram_size = checkuint(L, tabidx, "memory_size");
    p->ram_size <<= 20;

    p->kernel.filename = dupcheckstring(L, tabidx, "kernel");
    p->kernel.len = load_file(&p->kernel.buf, p->kernel.filename);
    if (p->kernel.len < 0) {
        luaL_error(L, "Unable to load %s.", p->kernel.filename);
    }

    p->cmdline = dupoptstring(L, tabidx, "cmdline");

    for (p->flash_count = 0;
         p->flash_count < VM_MAX_FLASH_DEVICE;
         p->flash_count++) {
        char flash[16];
        snprintf(flash, sizeof(flash), "flash%d", p->flash_count);
        lua_getfield(L, tabidx, flash);
        if (lua_isnil(L, -1)) {
            lua_pop(L, 1);
            break;
        }
        if (!lua_istable(L, -1)) {
            luaL_error(L, "Invalid flash%d.", p->flash_count);
        }
        p->tab_flash[p->flash_count].shared = optboolean(L, -1, "shared", 0);
        p->tab_flash[p->flash_count].backing = dupcheckstring(L, -1, "backing");
        p->tab_flash[p->flash_count].label = dupcheckstring(L, -1, "label");
        p->tab_flash[p->flash_count].address = checkuint(L, -1, "address");
        p->tab_flash[p->flash_count].size = checkuint(L, -1, "size");
        lua_pop(L, 1);
    }

    if (p->flash_count >= VM_MAX_FLASH_DEVICE) {
        luaL_error(L, "too many flash drives (max is %d)", VM_MAX_FLASH_DEVICE);
    }
}

void virt_machine_free_config(VirtMachineParams *p)
{
    int i;
    free(p->cmdline);
    free(p->kernel.filename);
    free(p->kernel.buf);
    for(i = 0; i < p->flash_count; i++) {
        free(p->tab_flash[i].backing);
        free(p->tab_flash[i].label);
    }
}

static uint64_t rtc_get_time(RISCVMachine *m)
{
    uint64_t val;
    val = riscv_cpu_get_cycles(m->cpu_state) / RTC_FREQ_DIV;
    return val;
}

static void rtc_advance_time(RISCVMachine *m, uint64_t amount)
{
    riscv_cpu_advance_cycles(m->cpu_state, amount * RTC_FREQ_DIV);
}

/* Host/Target Interface */
static uint32_t htif_read(void *opaque, uint32_t offset,
                          int size_log2)
{
    RISCVMachine *s = opaque;
    uint32_t val;

    assert(size_log2 == 2);
    switch(offset) {
    case 0:
        val = s->htif_tohost;
        break;
    case 4:
        val = s->htif_tohost >> 32;
        break;
    case 8:
        val = s->htif_fromhost;
        break;
    case 12:
        val = s->htif_fromhost >> 32;
        break;
    default:
        val = 0;
        break;
    }
    return val;
}

static void htif_handle_cmd(RISCVMachine *s)
{
    uint32_t device, cmd;

    device = s->htif_tohost >> 56;
    cmd = (s->htif_tohost >> 48) & 0xff;
    if (s->htif_tohost == 1) {
        /* shuthost */
        exit(0);
    } else if (device == 1 && cmd == 1) {
        uint8_t buf[1];
        buf[0] = s->htif_tohost & 0xff;
        s->common.console->write_data(s->common.console->opaque, buf, 1);
        s->htif_tohost = 0;
        s->htif_fromhost = ((uint64_t)device << 56) | ((uint64_t)cmd << 48);
    } else if (device == 1 && cmd == 0) {
        /* request keyboard interrupt */
        s->htif_tohost = 0;
    } else {
        printf("HTIF: unsupported tohost=0x%016" PRIx64 "\n", s->htif_tohost);
    }
}

static void htif_write(void *opaque, uint32_t offset, uint32_t val,
                       int size_log2)
{
    RISCVMachine *s = opaque;

    assert(size_log2 == 2);
    switch(offset) {
    case 0:
        s->htif_tohost = (s->htif_tohost & ~0xffffffff) | val;
        break;
    case 4:
        s->htif_tohost = (s->htif_tohost & 0xffffffff) | ((uint64_t)val << 32);
        htif_handle_cmd(s);
        break;
    case 8:
        s->htif_fromhost = (s->htif_fromhost & ~0xffffffff) | val;
        break;
    case 12:
        s->htif_fromhost = (s->htif_fromhost & 0xffffffff) |
            (uint64_t)val << 32;
        break;
    default:
        break;
    }
}

/* Clock Interrupt */
static uint32_t clint_read(void *opaque, uint32_t offset, int size_log2)
{
    RISCVMachine *m = opaque;
    uint32_t val;

    assert(size_log2 == 2);
    switch(offset) {
    case 0xbff8:
        val = rtc_get_time(m);
        break;
    case 0xbffc:
        val = rtc_get_time(m) >> 32;
        break;
    case 0x4000:
        val = m->timecmp;
        break;
    case 0x4004:
        val = m->timecmp >> 32;
        break;
    default:
        val = 0;
        break;
    }
    return val;
}

static void clint_write(void *opaque, uint32_t offset, uint32_t val,
                      int size_log2)
{
    RISCVMachine *m = opaque;

    assert(size_log2 == 2);
    switch(offset) {
    case 0x4000:
        m->timecmp = (m->timecmp & ~0xffffffff) | val;
        riscv_cpu_reset_mip(m->cpu_state, MIP_MTIP);
        break;
    case 0x4004:
        m->timecmp = (m->timecmp & 0xffffffff) | ((uint64_t)val << 32);
        riscv_cpu_reset_mip(m->cpu_state, MIP_MTIP);
        break;
    default:
        break;
    }
}

/* Platform-Level Interrupt Controller (PLIC) */
static void plic_update_mip(RISCVMachine *s)
{
    RISCVCPUState *cpu = s->cpu_state;
    uint32_t mask;
    mask = s->plic_pending_irq & ~s->plic_served_irq;
    if (mask) {
        riscv_cpu_set_mip(cpu, MIP_MEIP | MIP_SEIP);
    } else {
        riscv_cpu_reset_mip(cpu, MIP_MEIP | MIP_SEIP);
    }
}

#define PLIC_HART_BASE 0x200000
#define PLIC_HART_SIZE 0x1000

static uint32_t plic_read(void *opaque, uint32_t offset, int size_log2)
{
    RISCVMachine *s = opaque;
    uint32_t val, mask;
    int i;
    assert(size_log2 == 2);
    switch(offset) {
    case PLIC_HART_BASE:
        val = 0;
        break;
    case PLIC_HART_BASE + 4:
        mask = s->plic_pending_irq & ~s->plic_served_irq;
        if (mask != 0) {
            i = ctz32(mask);
            s->plic_served_irq |= 1 << i;
            plic_update_mip(s);
            val = i + 1;
        } else {
            val = 0;
        }
        break;
    default:
        val = 0;
        break;
    }
    return val;
}

static void plic_write(void *opaque, uint32_t offset, uint32_t val,
                       int size_log2)
{
    RISCVMachine *s = opaque;

    assert(size_log2 == 2);
    switch(offset) {
    case PLIC_HART_BASE + 4:
        val--;
        if (val < 32) {
            s->plic_served_irq &= ~(1 << val);
            plic_update_mip(s);
        }
        break;
    default:
        break;
    }
}

static void plic_set_irq(void *opaque, int irq_num, int state)
{
    RISCVMachine *s = opaque;
    uint32_t mask;

    mask = 1 << (irq_num - 1);
    if (state)
        s->plic_pending_irq |= mask;
    else
        s->plic_pending_irq &= ~mask;
    plic_update_mip(s);
}

static uint8_t *get_ram_ptr(RISCVMachine *s, uint64_t paddr)
{
    PhysMemoryRange *pr = get_phys_mem_range(s->mem_map, paddr);
    if (!pr || !pr->is_ram)
        return NULL;
    return pr->phys_mem + (uintptr_t)(paddr - pr->addr);
}

static int riscv_build_fdt(const VirtMachineParams *p, RISCVMachine *m,
    uint8_t *dst)
{
    FDTState *s;
    int size, max_xlen, i, cur_phandle, intc_phandle, plic_phandle;
    char isa_string[128], *q;
    uint32_t misa;
    uint32_t tab[4];

    s = fdt_init();

    cur_phandle = 1;

    fdt_begin_node(s, "");
    fdt_prop_u32(s, "#address-cells", 2);
    fdt_prop_u32(s, "#size-cells", 2);
    fdt_prop_str(s, "compatible", "ucbbar,riscvemu-bar_dev");
    fdt_prop_str(s, "model", "ucbbar,riscvemu-bare");

    /* CPU list */
    fdt_begin_node(s, "cpus");
    fdt_prop_u32(s, "#address-cells", 1);
    fdt_prop_u32(s, "#size-cells", 0);
    fdt_prop_u32(s, "timebase-frequency", RTC_FREQ);

    /* cpu */
    fdt_begin_node_num(s, "cpu", 0);
    fdt_prop_str(s, "device_type", "cpu");
    fdt_prop_u32(s, "reg", 0);
    fdt_prop_str(s, "status", "okay");
    fdt_prop_str(s, "compatible", "riscv");

    max_xlen = riscv_cpu_get_max_xlen();
    misa = riscv_cpu_get_misa(m->cpu_state);
    q = isa_string;
    q += snprintf(isa_string, sizeof(isa_string), "rv%d", max_xlen);
    for(i = 0; i < 26; i++) {
        if (misa & (1 << i))
            *q++ = 'a' + i;
    }
    *q = '\0';
    fdt_prop_str(s, "riscv,isa", isa_string);

    fdt_prop_str(s, "mmu-type", max_xlen <= 32 ? "sv32" : "sv48");
    fdt_prop_u32(s, "clock-frequency", 2000000000);

    fdt_begin_node(s, "interrupt-controller");
    fdt_prop_u32(s, "#interrupt-cells", 1);
    fdt_prop(s, "interrupt-controller", NULL, 0);
    fdt_prop_str(s, "compatible", "riscv,cpu-intc");
    intc_phandle = cur_phandle++;
    fdt_prop_u32(s, "phandle", intc_phandle);
    fdt_end_node(s); /* interrupt-controller */

    fdt_end_node(s); /* cpu */

    fdt_end_node(s); /* cpus */

    fdt_begin_node_num(s, "memory", RAM_BASE_ADDR);
    fdt_prop_str(s, "device_type", "memory");
    tab[0] = (uint64_t)RAM_BASE_ADDR >> 32;
    tab[1] = RAM_BASE_ADDR;
    tab[2] = m->ram_size >> 32;
    tab[3] = m->ram_size;
    fdt_prop_tab_u32(s, "reg", tab, 4);

    fdt_end_node(s); /* memory */

    /* flash */
    for (i = 0; i < p->flash_count; i++) {
        fdt_begin_node_num(s, "flash", p->tab_flash[i].address);
            fdt_prop_u32(s, "#address-cells", 2);
            fdt_prop_u32(s, "#size-cells", 2);
            fdt_prop_str(s, "compatible", "mtd-ram");
            fdt_prop_u32(s, "bank-width", 4);
            tab[0] = p->tab_flash[i].address >> 32;
            tab[1] = p->tab_flash[i].address;
            tab[2] = p->tab_flash[i].size >> 32;
            tab[3] = p->tab_flash[i].size;
            fdt_prop_tab_u32(s, "reg", tab, 4);
            fdt_begin_node_num(s, "fs0", 0);
                fdt_prop_str(s, "label", p->tab_flash[i].label);
                tab[0] = 0;
                tab[1] = 0;
                tab[2] = p->tab_flash[i].size >> 32;
                tab[3] = p->tab_flash[i].size;
                fdt_prop_tab_u32(s, "reg", tab, 4);
            fdt_end_node(s); /* fs */
        fdt_end_node(s); /* flash */
    }

    fdt_begin_node(s, "soc");
    fdt_prop_u32(s, "#address-cells", 2);
    fdt_prop_u32(s, "#size-cells", 2);
    fdt_prop_tab_str(s, "compatible",
                     "ucbbar,riscvemu-bar-soc", "simple-bus", NULL);
    fdt_prop(s, "ranges", NULL, 0);

#if 1
    fdt_begin_node_num(s, "clint", CLINT_BASE_ADDR);
    fdt_prop_str(s, "compatible", "riscv,clint0");

    tab[0] = intc_phandle;
    tab[1] = 3; /* M IPI irq */
    tab[2] = intc_phandle;
    tab[3] = 7; /* M timer irq */
    fdt_prop_tab_u32(s, "interrupts-extended", tab, 4);

    fdt_prop_tab_u64_2(s, "reg", CLINT_BASE_ADDR, CLINT_SIZE);

    fdt_end_node(s); /* clint */
#endif

    fdt_begin_node_num(s, "plic", PLIC_BASE_ADDR);
    fdt_prop_u32(s, "#interrupt-cells", 1);
    fdt_prop(s, "interrupt-controller", NULL, 0);
    fdt_prop_str(s, "compatible", "riscv,plic0");
    fdt_prop_u32(s, "riscv,ndev", 31);
    fdt_prop_tab_u64_2(s, "reg", PLIC_BASE_ADDR, PLIC_SIZE);

    tab[0] = intc_phandle;
    tab[1] = 9; /* S ext irq */
    tab[2] = intc_phandle;
    tab[3] = 11; /* M ext irq */
    fdt_prop_tab_u32(s, "interrupts-extended", tab, 4);

    plic_phandle = cur_phandle++;
    fdt_prop_u32(s, "phandle", plic_phandle);

    fdt_end_node(s); /* plic */

    for(i = 0; i < m->virtio_count; i++) {
        fdt_begin_node_num(s, "virtio", VIRTIO_BASE_ADDR + i * VIRTIO_SIZE);
        fdt_prop_str(s, "compatible", "virtio,mmio");
        fdt_prop_tab_u64_2(s, "reg", VIRTIO_BASE_ADDR + i * VIRTIO_SIZE,
                           VIRTIO_SIZE);
        tab[0] = plic_phandle;
        tab[1] = VIRTIO_IRQ + i;
        fdt_prop_tab_u32(s, "interrupts-extended", tab, 2);
        fdt_end_node(s); /* virtio */
    }

    fdt_end_node(s); /* soc */

    fdt_begin_node(s, "chosen");
    fdt_prop_str(s, "bootargs", p->cmdline ? p->cmdline : "");

    fdt_end_node(s); /* chosen */

    fdt_end_node(s); /* / */

    size = fdt_output(s, dst);
    fdt_end(s);

    return size;
}

static void copy_kernel(const VirtMachineParams *p, RISCVMachine *s)
{
    uint32_t fdt_addr;
    uint8_t *ram_ptr;
    uint32_t *q;

    if (!p->kernel.buf) {
        vm_error("No kernel found\n");
        exit(1);
    }

    if (p->kernel.len > (int) s->ram_size) {
        vm_error("Kernel too big\n");
        exit(1);
    }

    ram_ptr = get_ram_ptr(s, RAM_BASE_ADDR);
    memcpy(ram_ptr, p->kernel.buf, p->kernel.len);

    ram_ptr = get_ram_ptr(s, 0);

    fdt_addr = 0x1000 + 8 * 8;

    riscv_build_fdt(p, s, ram_ptr + fdt_addr);

    /* jump_addr = 0x80000000 */

    q = (uint32_t *)(ram_ptr + 0x1000);
    q[0] = 0x297 + 0x80000000 - 0x1000; /* auipc t0, jump_addr */
    q[1] = 0x597; /* auipc a1, dtb */
    q[2] = 0x58593 + ((fdt_addr - 4) << 20); /* addi a1, a1, dtb */
    q[3] = 0xf1402573; /* csrr a0, mhartid */
    q[4] = 0x00028067; /* jalr zero, t0, jump_addr */
}

static void riscv_flush_tlb_write_range(void *opaque, uint8_t *ram_addr,
                                        size_t ram_size)
{
    RISCVMachine *s = opaque;
    riscv_cpu_flush_tlb_write_range_ram(s->cpu_state, ram_addr, ram_size);
}

void virt_machine_set_defaults(VirtMachineParams *p)
{
    memset(p, 0, sizeof(*p));
}

VirtMachine *virt_machine_init(const VirtMachineParams *p)
{
    RISCVMachine *s;
    int irq_num, i;
    VIRTIOBusDef vbus_s, *vbus = &vbus_s;

    s = mallocz(sizeof(*s));

    s->ram_size = p->ram_size;
    s->mem_map = phys_mem_map_init();
    /* needed to handle the RAM dirty bits */
    s->mem_map->opaque = s;
    s->mem_map->flush_tlb_write_range = riscv_flush_tlb_write_range;

    s->cpu_state = riscv_cpu_init(s->mem_map);

    /* RAM */
    cpu_register_ram(s->mem_map, RAM_BASE_ADDR, p->ram_size, 0);
    cpu_register_ram(s->mem_map, 0x00000000, LOW_RAM_SIZE, 0);

    /* flash */
    for (i = 0; i < p->flash_count; i++) {
        cpu_register_backed_ram(s->mem_map, p->tab_flash[i].address,
            p->tab_flash[i].size, p->tab_flash[i].backing,
            p->tab_flash[i].shared? DEVRAM_FLAG_SHARED: 0);
    }

    cpu_register_device(s->mem_map, CLINT_BASE_ADDR, CLINT_SIZE, s,
                        clint_read, clint_write, DEVIO_SIZE32);
    cpu_register_device(s->mem_map, PLIC_BASE_ADDR, PLIC_SIZE, s,
                        plic_read, plic_write, DEVIO_SIZE32);
    for(i = 1; i < 32; i++) {
        irq_init(&s->plic_irq[i], plic_set_irq, s, i);
    }

    cpu_register_device(s->mem_map, HTIF_BASE_ADDR, 16, s,
        htif_read, htif_write, DEVIO_SIZE32);
    s->common.console = p->console;

    memset(vbus, 0, sizeof(*vbus));
    vbus->mem_map = s->mem_map;
    vbus->addr = VIRTIO_BASE_ADDR;
    irq_num = VIRTIO_IRQ;

    /* virtio console */
    if (p->console) {
        vbus->irq = &s->plic_irq[irq_num];
        s->common.console_dev = virtio_console_init(vbus, p->console);
        vbus->addr += VIRTIO_SIZE;
        irq_num++;
        s->virtio_count++;
    }

    copy_kernel(p, s);

    return (VirtMachine *)s;
}

void virt_machine_end(VirtMachine *s1)
{
    RISCVMachine *s = (RISCVMachine *)s1;
    /* XXX: stop all */
    riscv_cpu_end(s->cpu_state);
    phys_mem_map_end(s->mem_map);
    free(s);
}

void virt_machine_advance_cycle_counter(VirtMachine *s1)
{
    RISCVMachine *m = (RISCVMachine *)s1;
    RISCVCPUState *s = m->cpu_state;
    int64_t skip_ahead = 0;

    /* wait for an event: the only asynchronous event is the RTC timer */
    if (!(riscv_cpu_get_mip(s) & MIP_MTIP)) {
        skip_ahead = m->timecmp - rtc_get_time(m);
        if (skip_ahead <= 0) {
            riscv_cpu_set_mip(s, MIP_MTIP);
            skip_ahead = 0;
        }
    }

    if (!riscv_cpu_get_power_down(s))
        skip_ahead = 0;

    rtc_advance_time(m, skip_ahead);
}

void virt_machine_interp(VirtMachine *s1, int max_exec_cycle)
{
    RISCVMachine *s = (RISCVMachine *)s1;
    riscv_cpu_interp(s->cpu_state, max_exec_cycle);
}

const char *virt_machine_get_name(void)
{
    return "riscv64";
}
