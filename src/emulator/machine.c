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
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>

#include "cutils.h"
#include "iomem.h"
#include "riscv_cpu.h"
#include "fdt.h"

#include "machine.h"

#define Ki(n) (((uint64_t)n) << 10)
#define Mi(n) (((uint64_t)n) << 20)
#define Gi(n) (((uint64_t)n) << 30)

#define LOW_RAM_SIZE     Ki(64)
#define RAM_BASE_ADDR    Gi(2)
#define CLINT_BASE_ADDR  Mi(32)
#define CLINT_SIZE       Ki(768)
#define HTIF_BASE_ADDR   (Gi(1)+Ki(32))
#define HTIF_SIZE  		 16
#define HTIF_CONSOLE_BUF_SIZE (1024)
#define PLIC_BASE_ADDR   (Gi(1)+Mi(1))
#define PLIC_SIZE        Mi(4)
#define PLIC_NIRQS       32
#define PLIC_HART_BASE   Mi(2) /* hardcoded in pk */
#define PLIC_HART_SIZE   Ki(4) /* hardcoded in pk */

#define CLOCK_FREQ 2000000000 /* 2 GHz */
#define RTC_FREQ_DIV 1000     /* arbitrary, relative to CPU freq to have a
                                 2 MHz frequency */

typedef struct {
    int stdin_fd;
    struct termios oldtty;
    int old_fd0_flags;
    uint8_t buf[HTIF_CONSOLE_BUF_SIZE];
    ssize_t buf_len, buf_pos;
    BOOL irq_pending;
} HTIFConsole;

typedef struct RISCVMachine {
    PhysMemoryMap *mem_map;
    RISCVCPUState *cpu_state;
    uint64_t ram_size;
    /* RTC */
    uint64_t timecmp;
    /* PLIC */
    uint32_t plic_pending_irq, plic_served_irq;
    IRQSignal plic_irq[PLIC_NIRQS]; /* IRQ 0 is not used */
    /* HTIF */
    uint64_t htif_tohost, htif_fromhost;
    HTIFConsole *htif_console;
} RISCVMachine;

/* return -1 if error. */
static int load_file(uint8_t **pbuf, const char *filename)
{
    FILE *f;
    int size;
    uint8_t *buf;

    f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Unable to open %s\n", filename);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc(size);
    if ((int) fread(buf, 1, size, f) != size) {
        fprintf(stderr, "Unable to read from %s\n", filename);
        return -1;
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

    p->interactive = optboolean(L, -1, "interactive", 0);

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

static uint64_t rtc_cycles_to_time(uint64_t cycle_counter)
{
    return cycle_counter / RTC_FREQ_DIV;
}

static uint64_t rtc_time_to_cycles(uint64_t time) {
    return time * RTC_FREQ_DIV;
}

static uint64_t rtc_get_time(RISCVMachine *m) {
    return rtc_cycles_to_time(riscv_cpu_get_cycle_counter(m->cpu_state));
}

/* Platform-Level Interrupt Controller (PLIC) */
static void plic_update_mip(RISCVMachine *m)
{
    RISCVCPUState *cpu = m->cpu_state;
    uint32_t mask;
    mask = m->plic_pending_irq & ~m->plic_served_irq;
    if (mask) {
        riscv_cpu_set_mip(cpu, MIP_MEIP | MIP_SEIP);
    } else {
        riscv_cpu_reset_mip(cpu, MIP_MEIP | MIP_SEIP);
    }
}

static uint32_t plic_read(void *opaque, uint32_t offset, int size_log2)
{
    RISCVMachine *m = opaque;
    uint32_t val, mask;
    int i;
    assert(size_log2 == 2);
    switch(offset) {
    case PLIC_HART_BASE:
        val = 0;
        break;
    case PLIC_HART_BASE + 4:
        mask = m->plic_pending_irq & ~m->plic_served_irq;
        if (mask != 0) {
            i = ctz32(mask);
            m->plic_served_irq |= 1 << i;
            plic_update_mip(m);
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
    RISCVMachine *m = opaque;

    assert(size_log2 == 2);
    switch(offset) {
    case PLIC_HART_BASE + 4:
        val--;
        if (val < PLIC_NIRQS) {
            m->plic_served_irq &= ~(1 << val);
            plic_update_mip(m);
        }
        break;
    default:
        break;
    }
}

static void plic_set_irq(void *opaque, int irq_num, int state)
{
    RISCVMachine *m = opaque;
    uint32_t mask;

    mask = 1 << (irq_num - 1);
    if (state)
        m->plic_pending_irq |= mask;
    else
        m->plic_pending_irq &= ~mask;
    plic_update_mip(m);
}


/* Host/Target Interface */
static uint32_t htif_read(void *opaque, uint32_t offset,
                          int size_log2)
{
    RISCVMachine *m = opaque;
    uint32_t val;

    assert(size_log2 == 2);
    switch(offset) {
    case 0:
        val = m->htif_tohost;
        break;
    case 4:
        val = m->htif_tohost >> 32;
        break;
    case 8:
        val = m->htif_fromhost;
        break;
    case 12:
        val = m->htif_fromhost >> 32;
        break;
    default:
        val = 0;
        break;
    }
    return val;
}

static void htif_handle_cmd(RISCVMachine *m)
{
    uint32_t device, cmd;

    device = m->htif_tohost >> 56;
    cmd = (m->htif_tohost >> 48) & 0xff;
    if (m->htif_tohost == 1) {
        riscv_cpu_set_shuthost(m->cpu_state, TRUE);
    } else if (device == 1 && cmd == 1) {
        uint8_t ch = m->htif_tohost & 0xff;
        write(1, &ch, 1);
        m->htif_tohost = 0; // notify that we are done with putchar
        m->htif_fromhost = ((uint64_t)device << 56) | ((uint64_t)cmd << 48);
    } else if (device == 1 && cmd == 0) {
        // request keyboard interrupt
        m->htif_tohost = 0;
    } else {
        printf("HTIF: unsupported tohost=0x%016" PRIx64 "\n", m->htif_tohost);
    }
}

static void htif_write(void *opaque, uint32_t offset, uint32_t val,
                       int size_log2)
{
    RISCVMachine *m = opaque;
    assert(size_log2 == 2);
    switch(offset) {
    case 0:
        m->htif_tohost = (m->htif_tohost & ~0xffffffff) | val;
        break;
    case 4:
        m->htif_tohost = (m->htif_tohost & 0xffffffff) | ((uint64_t)val << 32);
        htif_handle_cmd(m);
        break;
    case 8:
        m->htif_fromhost = (m->htif_fromhost & ~0xffffffff) | val;
        break;
    case 12:
        m->htif_fromhost = (m->htif_fromhost & 0xffffffff) |
            (uint64_t)val << 32;
        if (m->htif_console) {
            m->htif_console->irq_pending = FALSE;
        }
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

static uint8_t *get_ram_ptr(RISCVMachine *m, uint64_t paddr)
{
    PhysMemoryRange *pr = get_phys_mem_range(m->mem_map, paddr);
    if (!pr || !pr->is_ram)
        return NULL;
    return pr->phys_mem + (uintptr_t)(paddr - pr->addr);
}

static int riscv_build_fdt(const VirtMachineParams *p, RISCVMachine *m,
    uint8_t *dst)
{
    FDTState *d;
    int size, max_xlen, i, cur_phandle, intc_phandle, plic_phandle;
    char isa_string[128], *q;
    uint32_t misa;
    uint32_t tab[4];

    d = fdt_init();

    cur_phandle = 1;

    fdt_begin_node(d, ""); /* root */

		fdt_prop_u32(d, "#address-cells", 2);
		fdt_prop_u32(d, "#size-cells", 2);
		fdt_prop_str(d, "compatible", "ucbbar,riscvemu-bar_dev");
		fdt_prop_str(d, "model", "ucbbar,riscvemu-bare");

		/* CPU list */
		fdt_begin_node(d, "cpus");
			fdt_prop_u32(d, "#address-cells", 1);
			fdt_prop_u32(d, "#size-cells", 0);
			fdt_prop_u32(d, "timebase-frequency", CLOCK_FREQ/RTC_FREQ_DIV);
			/* cpu */
			fdt_begin_node_num(d, "cpu", 0);
				fdt_prop_str(d, "device_type", "cpu");
				fdt_prop_u32(d, "reg", 0);
				fdt_prop_str(d, "status", "okay");
				fdt_prop_str(d, "compatible", "riscv");
				max_xlen = riscv_cpu_get_max_xlen();
				misa = riscv_cpu_get_misa(m->cpu_state);
				q = isa_string;
				q += snprintf(isa_string, sizeof(isa_string), "rv%d", max_xlen);
				for(i = 0; i < 26; i++) {
					if (misa & (1 << i))
						*q++ = 'a' + i;
				}
				*q = '\0';
				fdt_prop_str(d, "riscv,isa", isa_string);
				fdt_prop_str(d, "mmu-type", "riscv,sv48");
				fdt_prop_u32(d, "clock-frequency", CLOCK_FREQ);
				fdt_begin_node(d, "interrupt-controller");
					fdt_prop_u32(d, "#interrupt-cells", 1);
					fdt_prop(d, "interrupt-controller", NULL, 0);
					fdt_prop_str(d, "compatible", "riscv,cpu-intc");
					intc_phandle = cur_phandle++;
					fdt_prop_u32(d, "phandle", intc_phandle);
				fdt_end_node(d); /* interrupt-controller */
			fdt_end_node(d); /* cpu */
		fdt_end_node(d); /* cpus */

		fdt_begin_node_num(d, "memory", RAM_BASE_ADDR);
			fdt_prop_str(d, "device_type", "memory");
			tab[0] = (uint64_t)RAM_BASE_ADDR >> 32;
			tab[1] = RAM_BASE_ADDR;
			tab[2] = m->ram_size >> 32;
			tab[3] = m->ram_size;
			fdt_prop_tab_u32(d, "reg", tab, 4);
		fdt_end_node(d); /* memory */

		/* flash */
		for (i = 0; i < p->flash_count; i++) {
			fdt_begin_node_num(d, "flash", p->tab_flash[i].address);
				fdt_prop_u32(d, "#address-cells", 2);
				fdt_prop_u32(d, "#size-cells", 2);
				fdt_prop_str(d, "compatible", "mtd-ram");
				fdt_prop_u32(d, "bank-width", 4);
				tab[0] = p->tab_flash[i].address >> 32;
				tab[1] = p->tab_flash[i].address;
				tab[2] = p->tab_flash[i].size >> 32;
				tab[3] = p->tab_flash[i].size;
				fdt_prop_tab_u32(d, "reg", tab, 4);
				fdt_begin_node_num(d, "fs0", 0);
					fdt_prop_str(d, "label", p->tab_flash[i].label);
					tab[0] = 0;
					tab[1] = 0;
					tab[2] = p->tab_flash[i].size >> 32;
					tab[3] = p->tab_flash[i].size;
					fdt_prop_tab_u32(d, "reg", tab, 4);
				fdt_end_node(d); /* fs */
			fdt_end_node(d); /* flash */
		}

		fdt_begin_node(d, "soc");
			fdt_prop_u32(d, "#address-cells", 2);
			fdt_prop_u32(d, "#size-cells", 2);
			fdt_prop_tab_str(d, "compatible",
							 "ucbbar,riscvemu-bar-soc", "simple-bus", NULL);
			fdt_prop(d, "ranges", NULL, 0);

			fdt_begin_node_num(d, "clint", CLINT_BASE_ADDR);
				fdt_prop_str(d, "compatible", "riscv,clint0");
				tab[0] = intc_phandle;
				tab[1] = 3; /* M IPI irq */
				tab[2] = intc_phandle;
				tab[3] = 7; /* M timer irq */
				fdt_prop_tab_u32(d, "interrupts-extended", tab, 4);
				fdt_prop_tab_u64_2(d, "reg", CLINT_BASE_ADDR, CLINT_SIZE);
			fdt_end_node(d); /* clint */

			fdt_begin_node_num(d, "plic", PLIC_BASE_ADDR);
				fdt_prop_u32(d, "#interrupt-cells", 1);
				fdt_prop(d, "interrupt-controller", NULL, 0);
				fdt_prop_str(d, "compatible", "riscv,plic0");
				fdt_prop_u32(d, "riscv,ndev", 31);
				fdt_prop_tab_u64_2(d, "reg", PLIC_BASE_ADDR, PLIC_SIZE);
				tab[0] = intc_phandle;
				tab[1] = 9; /* S ext irq */
				tab[2] = intc_phandle;
				tab[3] = 11; /* M ext irq */
				fdt_prop_tab_u32(d, "interrupts-extended", tab, 4);
				plic_phandle = cur_phandle++;
				fdt_prop_u32(d, "phandle", plic_phandle);
			fdt_end_node(d); /* plic */

            fdt_begin_node_num(d, "htif", HTIF_BASE_ADDR);
                fdt_prop_str(d, "compatible", "ucb,htif0");
                fdt_prop_tab_u64_2(d, "reg", HTIF_BASE_ADDR, HTIF_SIZE);
                tab[0] = intc_phandle;
                tab[1] = 13; // X HOST
                fdt_prop_tab_u32(d, "interrupts-extended", tab, 2);
            fdt_end_node(d);

		fdt_end_node(d); /* soc */

		fdt_begin_node(d, "chosen");
			fdt_prop_str(d, "bootargs", p->cmdline ? p->cmdline : "");
		fdt_end_node(d);

    fdt_end_node(d); /* root */

    size = fdt_output(d, dst);
    fdt_end(d);

    {
        FILE *f;
        f = fopen("emu.dtb", "wb");
        fwrite(dst, 1, size, f);
        fclose(f);
    }

    return size;
}

static void copy_kernel(const VirtMachineParams *p, RISCVMachine *m)
{
    uint32_t fdt_addr;
    uint8_t *ram_ptr;
    uint32_t *q;

    ram_ptr = get_ram_ptr(m, RAM_BASE_ADDR);
    memcpy(ram_ptr, p->kernel.buf, p->kernel.len);

    ram_ptr = get_ram_ptr(m, 0);

    fdt_addr = 0x1000 + 8 * 8;

    riscv_build_fdt(p, m, ram_ptr + fdt_addr);

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
    RISCVMachine *m = opaque;
    riscv_cpu_flush_tlb_write_range_ram(m->cpu_state, ram_addr, ram_size);
}

void virt_machine_set_defaults(VirtMachineParams *p)
{
    memset(p, 0, sizeof(*p));
}

static HTIFConsole *htif_console_init(void) {
    struct termios tty;
    HTIFConsole *con = mallocz(sizeof(*con));
    memset(&tty, 0, sizeof(tty));
    tcgetattr (0, &tty);
    con->oldtty = tty;
    con->old_fd0_flags = fcntl(0, F_GETFL);
    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    tty.c_oflag |= OPOST;
    tty.c_lflag &= ~(ECHO|ECHONL|ICANON|IEXTEN);
    tty.c_lflag &= ~ISIG;
    tty.c_cflag &= ~(CSIZE|PARENB);
    tty.c_cflag |= CS8;
    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 0;
    tcsetattr (0, TCSANOW, &tty);
    /* Note: the glibc does not properly test the return value of
       write() in printf, so some messages on stdout may be lost */
    fcntl(con->stdin_fd, F_SETFL, O_NONBLOCK);
    return con;
}

static void htif_console_end(HTIFConsole *con) {
    tcsetattr (0, TCSANOW, &con->oldtty);
    fcntl(0, F_SETFL, con->old_fd0_flags);
    free(con);
}

VirtMachine *virt_machine_init(const VirtMachineParams *p)
{
    RISCVMachine *m;
    int i;

    if (!p->kernel.buf) {
        fprintf(stderr, "No kernel found\n");
        return NULL;
    }

    if (p->kernel.len > (int) p->ram_size) {
        fprintf(stderr, "Kernel too big\n");
        return NULL;
    }

    m = mallocz(sizeof(*m));

    m->ram_size = p->ram_size;
    m->mem_map = phys_mem_map_init();
    /* needed to handle the RAM dirty bits */
    m->mem_map->opaque = m;
    m->mem_map->flush_tlb_write_range = riscv_flush_tlb_write_range;

    m->cpu_state = riscv_cpu_init(m->mem_map);

    /* RAM */
    cpu_register_ram(m->mem_map, RAM_BASE_ADDR, p->ram_size, 0);
    cpu_register_ram(m->mem_map, 0x00000000, LOW_RAM_SIZE, 0);

    /* flash */
    for (i = 0; i < p->flash_count; i++) {
        cpu_register_backed_ram(m->mem_map, p->tab_flash[i].address,
            p->tab_flash[i].size, p->tab_flash[i].backing,
            p->tab_flash[i].shared? DEVRAM_FLAG_SHARED: 0);
    }

    cpu_register_device(m->mem_map, CLINT_BASE_ADDR, CLINT_SIZE, m,
                        clint_read, clint_write, DEVIO_SIZE32);

    cpu_register_device(m->mem_map, PLIC_BASE_ADDR, PLIC_SIZE, m,
                        plic_read, plic_write, DEVIO_SIZE32);
    for(i = 1; i < PLIC_NIRQS; i++) {
        irq_init(&m->plic_irq[i], plic_set_irq, m, i);
    }

    cpu_register_device(m->mem_map, HTIF_BASE_ADDR, HTIF_SIZE, m,
        htif_read, htif_write, DEVIO_SIZE32);

    copy_kernel(p, m);

    if (p->interactive) {
        m->htif_console = htif_console_init();
    }

    return (VirtMachine *)m;
}

void virt_machine_end(VirtMachine *v)
{
    RISCVMachine *m = (RISCVMachine *)v;
    if (m->htif_console) {
        htif_console_end(m->htif_console);
    }
    riscv_cpu_end(m->cpu_state);
    phys_mem_map_end(m->mem_map);
    free(m);
}

uint64_t virt_machine_get_cycle_counter(VirtMachine *v) {
    RISCVMachine *m = (RISCVMachine *)v;
    return riscv_cpu_get_cycle_counter(m->cpu_state);
}

const char *virt_machine_get_name(void)
{
    return "riscv64";
}

int virt_machine_run(VirtMachine *v, uint64_t cycles_end)
{
    RISCVMachine *m = (RISCVMachine *)v;
    RISCVCPUState *c = m->cpu_state;
    HTIFConsole *con = m->htif_console;


    for (;;) {

        uint64_t cycles = riscv_cpu_get_cycle_counter(c);

        uint64_t cycles_div_end = cycles + RTC_FREQ_DIV -
            cycles % RTC_FREQ_DIV;
        uint64_t this_cycles_end = cycles_end > cycles_div_end?
            cycles_div_end: cycles_end;

        /* execute as many cycles as possible until shuthost
         * or powerdown */
        riscv_cpu_run(c, this_cycles_end);
        cycles = riscv_cpu_get_cycle_counter(c);

        /* if we reached our target number of cycles, break */
        if (cycles >= cycles_end) {
            return 0;
        }

        /* if we were shutdown, break */
        if (riscv_cpu_get_shuthost(c)) {
            return 1;
        }

        /* check for timer interrupts */
        /* if the timer interrupt is not already pending */
        if (!(riscv_cpu_get_mip(c) & MIP_MTIP)) {
            uint64_t timer_cycles = rtc_time_to_cycles(m->timecmp);
            /* if timer expired, raise interrupt */
            if (timer_cycles <= cycles) {
                riscv_cpu_set_mip(c, MIP_MTIP);
            /* otherwise, if the cpu is powered down, waiting for interrupts,
             * skip time */
            } else if (riscv_cpu_get_power_down(c)) {
                if (timer_cycles < cycles_end) {
                    riscv_cpu_set_cycle_counter(c, timer_cycles);
                } else {
                    riscv_cpu_set_cycle_counter(c, cycles_end);
                }
            }
        }

        /* check for I/O with console */
        if (con) {
            /* if the character we made available has
             * already been consumed */
            if (!con->irq_pending) {
                /* if we don't have any characters left in
                 * buffer, try to obtain more from stdin */
                if (con->buf_pos >= con->buf_len) {
                    fd_set rfds, wfds, efds;
                    int fd_max, ret;
                    struct timeval tv;
                    FD_ZERO(&rfds);
                    FD_ZERO(&wfds);
                    FD_ZERO(&efds);
                    fd_max = con->stdin_fd;
                    FD_SET(con->stdin_fd, &rfds);
                    tv.tv_sec = 0;
                    tv.tv_usec = riscv_cpu_get_power_down(c)? 1000: 0;
                    ret = select(fd_max + 1, &rfds, &wfds, &efds, &tv);
                    if (ret > 0 && FD_ISSET(con->stdin_fd, &rfds)) {
                        con->buf_pos = 0;
                        con->buf_len = read(con->stdin_fd, con->buf,
                            HTIF_CONSOLE_BUF_SIZE);
                        if (con->buf_len <= 0) {
                            con->buf_len = 1;
                            con->buf[0] = 4; /* CTRL+D */
                        }
                    }
                }
                if (con->buf_pos < con->buf_len) {
                    /* feed another character and wake the cpu */
                    m->htif_fromhost = ((uint64_t)1 << 56) |
                            ((uint64_t)0 << 48) | con->buf[con->buf_pos++];
                    con->irq_pending = TRUE;
                    riscv_cpu_set_power_down(c, FALSE);
                }
            }
        }
    }
}
