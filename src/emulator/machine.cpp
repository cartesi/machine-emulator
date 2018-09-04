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
#include <cassert>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <chrono>
#include <thread>

#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

extern "C" {
#include <libfdt.h>
}

#include <lua.hpp>

#include "iomem.h"
#include "processor.h"

#include "machine.h"

#define Ki(n) (((uint64_t)n) << 10)
#define Mi(n) (((uint64_t)n) << 20)
#define Gi(n) (((uint64_t)n) << 30)

#define ROM_BASE_ADDR  Ki(4)
#define ROM_SIZE       Ki(64)
#define RAM_BASE_ADDR      Gi(2)
#define CLINT_BASE_ADDR    Mi(32)
#define CLINT_SIZE         Ki(768)
#define HTIF_BASE_ADDR     (Gi(1)+Ki(32))
#define HTIF_SIZE             16
#define HTIF_CONSOLE_BUF_SIZE (1024)
#define HTIF_CONSOLE_FREQ_DIV (100000)

typedef struct {
    struct termios oldtty;
    int old_fd0_flags;
    uint8_t buf[HTIF_CONSOLE_BUF_SIZE];
    ssize_t buf_len, buf_pos;
    uint64_t previous_mcycle;
    bool getchar_pending;
} HTIFConsole;

using clock_source = std::chrono::system_clock;

typedef struct {
    std::chrono::time_point<clock_source> last_time;
    uint64_t last_mcycle;
} Wallclock;

typedef struct {
    HTIFConsole console;
    Wallclock wallclock;
} interactive_state;

typedef struct RISCVMachine {
    PhysMemoryMap *mem_map;
    processor_state *processor;
    interactive_state *interactive;
} RISCVMachine;


HTIFConsole *get_console(RISCVMachine *m) {
    if (m->interactive) {
        return &m->interactive->console;
    }
    return nullptr;
}

Wallclock *get_wallclock(RISCVMachine *m) {
    if (m->interactive) {
        return &m->interactive->wallclock;
    }
    return nullptr;
}


/* return -1 if error. */
static uint64_t load_file(uint8_t **pbuf, const char *filename)
{
    FILE *f;
    int size;
    uint8_t *buf;

    f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Unable to open %s\n", filename);
        return 0;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = reinterpret_cast<uint8_t *>(calloc(1, size));
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

    p->ram_image.filename = dupcheckstring(L, tabidx, "ram_image");
    p->ram_image.len = load_file(&p->ram_image.buf, p->ram_image.filename);
    if (p->ram_image.len == 0) {
        luaL_error(L, "Unable to load RAM image %s.", p->ram_image.filename);
    }

    p->rom_image.filename = dupoptstring(L, tabidx, "rom_image");
    if (p->rom_image.filename) {
        p->rom_image.len = load_file(&p->rom_image.buf, p->rom_image.filename);
        if (p->rom_image.len == 0) {
            luaL_error(L, "Unable to load ROM image %s.", p->rom_image.filename);
        }
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
    free(p->ram_image.filename);
    free(p->ram_image.buf);
    free(p->rom_image.filename);
    free(p->rom_image.buf);
    for(i = 0; i < p->flash_count; i++) {
        free(p->tab_flash[i].backing);
        free(p->tab_flash[i].label);
    }
}

static void wallclock_adjust(RISCVMachine *m) {
    Wallclock *wc = get_wallclock(m);
    if (wc) {
        // Figure out how much time should have passed in microseconds
        int64_t now_mcycle = processor_read_mcycle(m->processor);
        int64_t should = ((now_mcycle - wc->last_mcycle)*1000000)/RISCV_CLOCK_FREQ;
        // Figure out how much time has passed in microseconds
        auto now_time = clock_source::now();
        int64_t has = std::chrono::duration_cast<std::chrono::microseconds>(now_time - wc->last_time).count();
        // If we are moving too fast, sleep until wallclock catches up
        if (should > has) {
            std::this_thread::sleep_for(std::chrono::microseconds(should-has));
        }
    }
}

static bool htif_read(i_device_state_access *a, void *opaque, uint64_t offset, uint64_t *pval, int size_log2) {
    (void) opaque;

    // Our HTIF only supports aligned 64-bit reads
    if (size_log2 != 3 || offset & 7) return false;

    switch (offset) {
        case 0: // tohost
            *pval = a->read_tohost();
            return true;
        case 8: // from host
            *pval = a->read_fromhost();
            return true;
        default:
            // other reads return zero
            *pval = 0;
            return true;
    }
}

static void htif_poll_stdin(RISCVMachine *m) {
    auto *con = get_console(m);
    processor_state *p = m->processor;

    //??D We do not need to register any access to state here because
    //    the console is always disabled during verifiable execution

    // Check for input from console, if requested by HTIF
    if (con && con->getchar_pending) {
        uint64_t mcycle = processor_read_mcycle(p);
        // If we don't have any characters left in buffer, try to obtain more
        if (con->buf_pos >= con->buf_len && con->previous_mcycle + HTIF_CONSOLE_FREQ_DIV <= mcycle) {
            con->previous_mcycle = mcycle;
            fd_set rfds, wfds, efds;
            int fd_max, ret;
            struct timeval tv;
            FD_ZERO(&rfds);
            FD_ZERO(&wfds);
            FD_ZERO(&efds);
            fd_max = 0;
            FD_SET(0, &rfds);
            tv.tv_sec = 0;
            tv.tv_usec = 0;
            ret = select(fd_max + 1, &rfds, &wfds, &efds, &tv);
            if (ret > 0 && FD_ISSET(0, &rfds)) {
                con->buf_pos = 0;
                con->buf_len = read(0, con->buf, HTIF_CONSOLE_BUF_SIZE);
                // If stdin is closed, pass EOF to client
                if (con->buf_len <= 0) {
                    con->buf_len = 1;
                    con->buf[0] = 4; // CTRL+D
                }
            }
        }
        // If we have data to return
        if (con->buf_pos < con->buf_len) {
            processor_write_fromhost(p, ((uint64_t)1 << 56) | ((uint64_t)0 << 48) | con->buf[con->buf_pos++]);
            con->getchar_pending = false;
        }
    }
}

static bool htif_getchar(i_device_state_access *a, RISCVMachine *m, uint64_t payload) {
    (void) a; (void) payload;
    HTIFConsole *con = get_console(m);
    if (con) {
        con->getchar_pending = true;
        htif_poll_stdin(m);
    }
    return true;
}

static bool htif_putchar(i_device_state_access *a, RISCVMachine *m, uint64_t payload) {
    (void) m;
    uint8_t ch = payload & 0xff;
    if (write(1, &ch, 1) < 1) { ; }
    a->write_fromhost(((uint64_t)1 << 56) | ((uint64_t)1 << 48));
    return true;
}

static bool htif_halt(i_device_state_access *a, RISCVMachine *m, uint64_t payload) {
    (void) m; (void) payload;
    a->set_iflags_H();
    return true;
}

static bool htif_write_tohost(i_device_state_access *a, RISCVMachine *m, uint64_t tohost) {
    // Decode tohost
    uint32_t device = tohost >> 56;
    uint32_t cmd = (tohost >> 48) & 0xff;
    uint64_t payload = (tohost & (~1ULL >> 16));
    // Log write to tohost
    //a->write_tohost(tohost); //??D We may be able to remove this write
    // Immediately clear tohost to signal we received the value
    a->write_tohost(0);
    // Handle commands
    if (device == 0 && cmd == 0 && (payload & 1)) {
        return htif_halt(a, m, payload);
    } else if (device == 1 && cmd == 1) {
        return htif_putchar(a, m, payload);
    } else if (device == 1 && cmd == 0) {
        return htif_getchar(a, m, payload);
    }
    //??D Unknown HTIF commands are sillently ignored
    return true;
}

static bool htif_write_fromhost(i_device_state_access *a, RISCVMachine *m, uint64_t val) {
    (void) m;
    a->write_fromhost(val);
    return true;
}

static bool htif_write(i_device_state_access *a, void *opaque, uint64_t offset, uint64_t val, int size_log2) {
    RISCVMachine *m = reinterpret_cast<RISCVMachine *>(opaque);

    // Our HTIF only supports aligned 64-bit writes
    if (size_log2 != 3 || offset & 7) return false;

    switch (offset) {
        case 0: // tohost
            return htif_write_tohost(a, m, val);
        case 8: // fromhost
            return htif_write_fromhost(a, m, val);
        default:
            // other writes are silently ignored
            return true;
    }
}

static bool clint_read_msip(i_device_state_access *a, RISCVMachine *m, uint64_t *val, int size_log2) {
    (void) m;
    if (size_log2 == 2) {
        *val = ((a->read_mip() & MIP_MSIP) == MIP_MSIP);
        return true;
    }
    return false;
}

static bool clint_read_mtime(i_device_state_access *a, RISCVMachine *m, uint64_t *val, int size_log2) {
    (void) m;
    if (size_log2 == 3) {
        *val = processor_rtc_cycles_to_time(a->read_mcycle());
        return true;
    }
    return false;
}

static bool clint_read_mtimecmp(i_device_state_access *a, RISCVMachine *m, uint64_t *val, int size_log2) {
    (void) m;
    if (size_log2 == 3) {
        *val = a->read_mtimecmp();
        return true;
    }
    return false;
}

/* Clock Interrupt */
static bool clint_read(i_device_state_access *a, void *opaque, uint64_t offset, uint64_t *val, int size_log2) {
    RISCVMachine *m = reinterpret_cast<RISCVMachine *>(opaque);

    // Our CLINT only supports 32 or 64-bit reads
    if (size_log2 < 2) return false;

    switch (offset) {
        case 0: // Machine software interrupt for hart 0
            return clint_read_msip(a, m, val, size_log2);
        case 0xbff8: // mtime
            return clint_read_mtime(a, m, val, size_log2);
        case 0xbffc: // misaligned mtime is not supported
            return false;
        case 0x4000: // mtimecmp
            return clint_read_mtimecmp(a, m, val, size_log2);
        case 0x4004: // misaligned mtimecmp is not supported
            return false;
        default:
            if (offset & ((1 << size_log2) - 1))
                // misaligned reads not supported
                return false;
            // aligned reads return zero
            *val = 0;
            return true;
    }
}

static bool clint_write(i_device_state_access *a, void *opaque, uint64_t offset, uint64_t val, int size_log2) {
    (void) opaque;

    // Our CLINT only supports 32 or 64-bit writes
    if (size_log2 < 2) return false;

    switch (offset) {
        case 0: // Machine software interrupt for hart 0
            if (size_log2 == 2) {
                //??D I don't yet know why Linux tries to raise MSIP when we only have a single hart
                //    It does so repeatedly before and after every command run in the shell
                //    Will investigate.
                if (val & 1) {
                    a->set_mip(MIP_MSIP);
                } else {
                    a->reset_mip(MIP_MSIP);
                }
                return true;
            }
            return false;
        case 0xbff8: // writes to mtime, misaligned or not,
        case 0xbffc: // are not supported
            return false;
        case 0x4000: // mtimecmp
            if (size_log2 == 3) {
                a->write_mtimecmp(val);
                a->reset_mip(MIP_MTIP);
                return true;
            }
            // partial mtimecmp is not supported
            return false;
        case 0x4004: // misaligned mtimecmp
            return false;
        default:
            if (offset & ((1 << size_log2) - 1))
                // misaligned writes not supported
                return false;
            // aligned writes are silently ignored
            return true;
    }
}

static uint8_t *get_ram_ptr(RISCVMachine *m, uint64_t paddr)
{
    PhysMemoryRange *pr = get_phys_mem_range(m->mem_map, paddr);
    if (!pr || !pr->is_ram)
        return NULL;
    return pr->phys_mem + (uintptr_t)(paddr - pr->addr);
}

#define FDT_CHECK(s) do { \
    int err = s; \
    if (err != 0) return err; \
} while (0);

static int fdt_begin_node_num(void *fdt, const char *name, uint64_t num) {
    char name_num[256];
    snprintf(name_num, sizeof(name_num), "%s@%" PRIx64, name, num);
    return fdt_begin_node(fdt, name_num);
}

static int fdt_property_u64_u64(void *fdt, const char *name, uint64_t v0, uint64_t v1) {
    uint32_t tab[4];
    tab[0] = cpu_to_fdt32(v0 >> 32);
    tab[1] = cpu_to_fdt32(v0);
    tab[2] = cpu_to_fdt32(v1 >> 32);
    tab[3] = cpu_to_fdt32(v1);
	return fdt_property(fdt, name, tab, sizeof(tab));
}

static int fdt_build_riscv(const VirtMachineParams *p, const RISCVMachine *m,
    void *buf, int bufsize)
{
    int cur_phandle = 1;
    FDT_CHECK(fdt_create(buf, bufsize));
    FDT_CHECK(fdt_add_reservemap_entry(buf, 0, 0));
    FDT_CHECK(fdt_finish_reservemap(buf));
    FDT_CHECK(fdt_begin_node(buf, ""));
     FDT_CHECK(fdt_property_u32(buf, "#address-cells", 2));
     FDT_CHECK(fdt_property_u32(buf, "#size-cells", 2));
     FDT_CHECK(fdt_property_string(buf, "compatible", "ucbbar,riscvemu-bar_dev"));
     FDT_CHECK(fdt_property_string(buf, "model", "ucbbar,riscvemu-bare"));
     FDT_CHECK(fdt_begin_node(buf, "cpus"));
      FDT_CHECK(fdt_property_u32(buf, "#address-cells", 1));
      FDT_CHECK(fdt_property_u32(buf, "#size-cells", 0));
      FDT_CHECK(fdt_property_u32(buf, "timebase-frequency", RISCV_CLOCK_FREQ/RISCV_RTC_FREQ_DIV));
      FDT_CHECK(fdt_begin_node_num(buf, "cpu", 0));
       FDT_CHECK(fdt_property_string(buf, "device_type", "cpu"));
       FDT_CHECK(fdt_property_u32(buf, "reg", 0));
       FDT_CHECK(fdt_property_string(buf, "status", "okay"));
       FDT_CHECK(fdt_property_string(buf, "compatible", "riscv"));
       int max_xlen = processor_get_max_xlen(m->processor);
       uint32_t misa = processor_read_misa(m->processor);
       char isa_string[128], *q = isa_string;
       q += snprintf(isa_string, sizeof(isa_string), "rv%d", max_xlen);
       for(int i = 0; i < 26; i++) {
           if (misa & (1 << i))
               *q++ = 'a' + i;
       }
       *q = '\0';
       FDT_CHECK(fdt_property_string(buf, "riscv,isa", isa_string));
       FDT_CHECK(fdt_property_string(buf, "mmu-type", "riscv,sv48"));
       FDT_CHECK(fdt_property_u32(buf, "clock-frequency", RISCV_CLOCK_FREQ));
       FDT_CHECK(fdt_begin_node(buf, "interrupt-controller"));
        FDT_CHECK(fdt_property_u32(buf, "#interrupt-cells", 1));
        FDT_CHECK(fdt_property(buf, "interrupt-controller", NULL, 0));
        FDT_CHECK(fdt_property_string(buf, "compatible", "riscv,cpu-intc"));
        int intc_phandle = cur_phandle++;
        FDT_CHECK(fdt_property_u32(buf, "phandle", intc_phandle));
       FDT_CHECK(fdt_end_node(buf)); /* interrupt-controller */
      FDT_CHECK(fdt_end_node(buf)); /* cpu */
     FDT_CHECK(fdt_end_node(buf)); /* cpus */

     FDT_CHECK(fdt_begin_node_num(buf, "memory", RAM_BASE_ADDR));
      FDT_CHECK(fdt_property_string(buf, "device_type", "memory"));
      FDT_CHECK(fdt_property_u64_u64(buf, "reg", RAM_BASE_ADDR, p->ram_size));
     FDT_CHECK(fdt_end_node(buf)); /* memory */

     /* flash */
     for (int i = 0; i < p->flash_count; i++) {
         FDT_CHECK(fdt_begin_node_num(buf, "flash", p->tab_flash[i].address));
          FDT_CHECK(fdt_property_u32(buf, "#address-cells", 2));
          FDT_CHECK(fdt_property_u32(buf, "#size-cells", 2));
          FDT_CHECK(fdt_property_string(buf, "compatible", "mtd-ram"));
          FDT_CHECK(fdt_property_u32(buf, "bank-width", 4));
          FDT_CHECK(fdt_property_u64_u64(buf, "reg", p->tab_flash[i].address, p->tab_flash[i].size));
          FDT_CHECK(fdt_begin_node_num(buf, "fs0", 0));
           FDT_CHECK(fdt_property_string(buf, "label", p->tab_flash[i].label));
           FDT_CHECK(fdt_property_u64_u64(buf, "reg", 0, p->tab_flash[i].size));
          FDT_CHECK(fdt_end_node(buf)); /* fs */
         FDT_CHECK(fdt_end_node(buf)); /* flash */
     }

     FDT_CHECK(fdt_begin_node(buf, "soc"));
      FDT_CHECK(fdt_property_u32(buf, "#address-cells", 2));
      FDT_CHECK(fdt_property_u32(buf, "#size-cells", 2));
      const char comp[] = "ucbbar,riscvemu-bar-soc\0simple-bus";
      FDT_CHECK(fdt_property(buf, "compatible", comp, sizeof(comp)));
      FDT_CHECK(fdt_property(buf, "ranges", NULL, 0));

      FDT_CHECK(fdt_begin_node_num(buf, "clint", CLINT_BASE_ADDR));
       FDT_CHECK(fdt_property_string(buf, "compatible", "riscv,clint0"));
       uint32_t clint[] = {
	       cpu_to_fdt32(intc_phandle),
	       cpu_to_fdt32(3), /* M IPI irq */
	       cpu_to_fdt32(intc_phandle),
	       cpu_to_fdt32(7) /* M timer irq */
       };
       FDT_CHECK(fdt_property(buf, "interrupts-extended", clint, sizeof(clint)));
       FDT_CHECK(fdt_property_u64_u64(buf, "reg", CLINT_BASE_ADDR, CLINT_SIZE));
      FDT_CHECK(fdt_end_node(buf)); /* clint */

      FDT_CHECK(fdt_begin_node_num(buf, "htif", HTIF_BASE_ADDR));
       FDT_CHECK(fdt_property_string(buf, "compatible", "ucb,htif0"));
       FDT_CHECK(fdt_property_u64_u64(buf, "reg", HTIF_BASE_ADDR, HTIF_SIZE));
       uint32_t htif[] = {
           cpu_to_fdt32(intc_phandle),
           cpu_to_fdt32(13) // X HOST
       };
       FDT_CHECK(fdt_property(buf, "interrupts-extended", htif, sizeof(htif)));
      FDT_CHECK(fdt_end_node(buf));

     FDT_CHECK(fdt_end_node(buf)); /* soc */

     FDT_CHECK(fdt_begin_node(buf, "chosen"));
      FDT_CHECK(fdt_property_string(buf, "bootargs", p->cmdline ? p->cmdline : ""));
     FDT_CHECK(fdt_end_node(buf));

    FDT_CHECK(fdt_end_node(buf)); /* root */
    FDT_CHECK(fdt_finish(buf));

    auto size = fdt_totalsize(buf);

#if 0
    {
        FILE *f;
        f = fopen("emu.dtb", "wb");
        fwrite(buf, 1, size, f);
        fclose(f);
    }
#endif

    return size;
}

static void init_ram_and_rom(const VirtMachineParams *p, RISCVMachine *m)
{

    uint8_t *ram_ptr = get_ram_ptr(m, RAM_BASE_ADDR);
    memcpy(ram_ptr, p->ram_image.buf, std::min(p->ram_image.len, p->ram_size));

    uint8_t *rom_ptr = get_ram_ptr(m, ROM_BASE_ADDR);

    if (!p->rom_image.buf) {
        uint32_t fdt_addr = 8 * 8;
        //??D should check for error here.
        fdt_build_riscv(p, m, rom_ptr + fdt_addr, ROM_SIZE-fdt_addr);
        /* jump_addr = RAM_BASE_ADDR */
        uint32_t *q = (uint32_t *)(rom_ptr);
        /* la t0, jump_addr */
        q[0] = 0x297 + RAM_BASE_ADDR - ROM_BASE_ADDR; /* auipc t0, 0x80000000-0x1000 */
        /* la a1, fdt_addr */
          q[1] = 0x597; /* auipc a1, 0  (a1 := 0x1004) */
          q[2] = 0x58593 + ((fdt_addr - (ROM_BASE_ADDR+4)) << 20); /* addi a1, a1, 60 */
        q[3] = 0xf1402573; /* csrr a0, mhartid */
        q[4] = 0x00028067; /* jr t0 */
    } else {
        memcpy(rom_ptr, p->rom_image.buf, std::min(p->rom_image.len, ROM_SIZE));
    }
}

void virt_machine_set_defaults(VirtMachineParams *p)
{
    memset(p, 0, sizeof(*p));
}

static void set_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    flags &= (~(O_NONBLOCK));
    fcntl(fd, F_SETFL, flags);
}

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
}

static void htif_console_init(HTIFConsole *con) {
    memset(con, 0, sizeof(*con));
    struct termios tty;
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
    set_nonblocking(0);
}

static void htif_console_end(HTIFConsole *con) {
    tcsetattr (0, TCSANOW, &con->oldtty);
    fcntl(0, F_SETFL, con->old_fd0_flags);
    set_blocking(0);
}

static void wallclock_init(Wallclock *wc) {
    wc->last_time = clock_source::now();
    wc->last_mcycle = 0;
}

static void wallclock_end(Wallclock *wc) {
    (void) wc;
}

static interactive_state *interactive_init(void) {
    interactive_state *i = reinterpret_cast<interactive_state *>(calloc(1, sizeof(interactive_state)));
    if (i) {
        htif_console_init(&i->console);
        wallclock_init(&i->wallclock);
    }
    return i;
}

static void interactive_end(interactive_state *i) {
    if (i) {
        htif_console_end(&i->console);
        wallclock_end(&i->wallclock);
        free(i);
    }
}

VirtMachine *virt_machine_init(const VirtMachineParams *p)
{
    int i;

    if (!p->ram_image.buf && !p->rom_image.buf) {
        fprintf(stderr, "No ROM or RAM images\n");
        return NULL;
    }

    if (p->rom_image.buf && p->rom_image.len > ROM_SIZE) {
        fprintf(stderr, "ROM image too big (%d vs %d)\n", (int) p->ram_image.len, (int) ROM_SIZE);
        return NULL;
    }

    if (p->ram_image.len >  p->ram_size) {
        fprintf(stderr, "RAM image too big (%d vs %d)\n", (int) p->ram_image.len, (int) p->ram_size);
        return NULL;
    }

    RISCVMachine *m = reinterpret_cast<RISCVMachine *>(calloc(1, sizeof(*m)));

    m->mem_map = phys_mem_map_init();
    m->processor = processor_init(m->mem_map);

    /* RAM */
    cpu_register_ram(m->mem_map, RAM_BASE_ADDR, p->ram_size);
    cpu_register_ram(m->mem_map, ROM_BASE_ADDR, ROM_SIZE);

    /* flash */
    for (i = 0; i < p->flash_count; i++) {
        cpu_register_backed_ram(m->mem_map, p->tab_flash[i].address,
            p->tab_flash[i].size, p->tab_flash[i].backing,
            p->tab_flash[i].shared);
    }

    cpu_register_device(m->mem_map, CLINT_BASE_ADDR, CLINT_SIZE, m, clint_read, clint_write);

    cpu_register_device(m->mem_map, HTIF_BASE_ADDR, HTIF_SIZE, m, htif_read, htif_write);

    init_ram_and_rom(p, m);

    if (p->interactive) {
        m->interactive = interactive_init();
    }

    return (VirtMachine *)m;
}

void virt_machine_end(VirtMachine *v)
{
    RISCVMachine *m = (RISCVMachine *)v;
    interactive_end(m->interactive);
    processor_end(m->processor);
    phys_mem_map_end(m->mem_map);
    free(m);
}

uint64_t virt_machine_read_mcycle(VirtMachine *v) {
    RISCVMachine *m = (RISCVMachine *)v;
    return processor_read_mcycle(m->processor);
}

uint64_t virt_machine_read_tohost(VirtMachine *v) {
    RISCVMachine *m = (RISCVMachine *) v;
    return processor_read_tohost(m->processor);
}

const char *virt_machine_get_name(void)
{
    return "riscv64";
}

int virt_machine_run(VirtMachine *v, uint64_t mcycle_end)
{
    RISCVMachine *m = (RISCVMachine *)v;
    processor_state *p = m->processor;

    // The emulator outer loop breaks only when the machine is halted
    // or when mcycle hits mcycle_end
    for ( ;; ) {

        // If we are halted, do nothing
        if (processor_read_iflags_H(p)) {
            return 1;
        }

        // Run the emulator inner loop until we reach the next multiple of RISCV_RTC_FREQ_DIV
        uint64_t mcycle = processor_read_mcycle(p);
        uint64_t next_timecmp_mcycle = mcycle + RISCV_RTC_FREQ_DIV - mcycle % RISCV_RTC_FREQ_DIV;
        processor_run(p, std::min(next_timecmp_mcycle, mcycle_end));

        // If we hit mcycle_end, we are done
        mcycle = processor_read_mcycle(p);
        if (mcycle >= mcycle_end) {
            return 0;
        }

        // If the timer interrupt is not already pending,
        // check if we should raise a timer interrupt
        if (!(processor_read_mip(p) & MIP_MTIP)) {
            // Get the mcycle corresponding to mtimecmp
            uint64_t timecmp_mcycle = processor_rtc_time_to_cycles(processor_read_mtimecmp(p));
            // If the cpu is waiting for interrupts, we can skip until time hits timecmp
            // CLINT is the only "external" interrupt source
            // IPI (inter-processor interrupt) via MSIP can only be raised "internally"
            if (processor_read_iflags_I(p)) {
                mcycle = std::min(timecmp_mcycle, mcycle_end);
                processor_write_mcycle(p, mcycle);
            }
            // If the timer is expired, raise interrupt
            if (timecmp_mcycle && timecmp_mcycle <= mcycle) {
                processor_set_mip(p, MIP_MTIP);
            }
        }

        // Check if there is user input from stdin
        // This is not used within the blockchain
        htif_poll_stdin(m);

        // Adjust wall clock time with real time if it is behind
        wallclock_adjust(m);
    }
}
