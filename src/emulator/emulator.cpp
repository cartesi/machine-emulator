#include <cassert>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
#include <libfdt.h>
}

#include <lua.hpp>

#include "machine.h"
#include "merkle-tree.h"
#include "emulator.h"
#include "machine.h"
#include "clint.h"
#include "htif.h"
#include "shadow.h"
#include "rtc.h"

#define Ki(n) (((uint64_t)n) << 10)
#define Mi(n) (((uint64_t)n) << 20)
#define Gi(n) (((uint64_t)n) << 30)

#define SHADOW_BASE_ADDR       0
#define SHADOW_SIZE            Ki(4)
#define ROM_BASE_ADDR          Ki(4)
#define ROM_SIZE               Ki(64)
#define RAM_BASE_ADDR          Gi(2)
#define CLINT_BASE_ADDR        Mi(32)
#define CLINT_SIZE             Ki(768)
#define HTIF_BASE_ADDR         (Gi(1)+Ki(32))
#define HTIF_SIZE              Ki(4)

#define CLOCK_FREQ 1000000000 // 1 GHz (arbitrary)

struct emulator {
    machine_state *machine;
    htif_state *htif;
    merkle_tree *tree;
};

/* return -1 if error. */
//??D Change to ifstream and std::vector to simplify code.
static uint64_t load_file(uint8_t **pbuf, const char *filename) {
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

void emulator_load_lua_config(lua_State *L, emulator_config *c, int tabidx) {

    emulator_set_defaults(c);

    if (checkuint(L, tabidx, "version") != VM_CONFIG_VERSION) {
        luaL_error(L, "Emulator does not match version number.");
    }

    lua_getfield(L, tabidx, "machine");
    if (!lua_isstring(L, -1)) {
        luaL_error(L, "No machine string.");
    }
    if (strcmp(emulator_get_name(), lua_tostring(L, -1)) != 0) {
        luaL_error(L, "Unsupported machine %s (running machine is %s).",
            lua_tostring(L, -1), emulator_get_name());
    }
    lua_pop(L, 1);

    c->ram_size = checkuint(L, tabidx, "memory_size");
    c->ram_size <<= 20;

    c->ram_image.filename = dupcheckstring(L, tabidx, "ram_image");
    c->ram_image.len = load_file(&c->ram_image.buf, c->ram_image.filename);
    if (c->ram_image.len == 0) {
        luaL_error(L, "Unable to load RAM image %s.", c->ram_image.filename);
    }

    c->rom_image.filename = dupoptstring(L, tabidx, "rom_image");
    if (c->rom_image.filename) {
        c->rom_image.len = load_file(&c->rom_image.buf, c->rom_image.filename);
        if (c->rom_image.len == 0) {
            luaL_error(L, "Unable to load ROM image %s.", c->rom_image.filename);
        }
    }

    c->interactive = optboolean(L, -1, "interactive", 0);

    c->cmdline = dupoptstring(L, tabidx, "cmdline");

    for (c->flash_count = 0; c->flash_count < VM_MAX_FLASH_DEVICE; c->flash_count++) {
        char flash[16];
        snprintf(flash, sizeof(flash), "flash%d", c->flash_count);
        lua_getfield(L, tabidx, flash);
        if (lua_isnil(L, -1)) {
            lua_pop(L, 1);
            break;
        }
        if (!lua_istable(L, -1)) {
            luaL_error(L, "Invalid flash%d.", c->flash_count);
        }
        c->tab_flash[c->flash_count].shared = optboolean(L, -1, "shared", 0);
        c->tab_flash[c->flash_count].backing = dupcheckstring(L, -1, "backing");
        c->tab_flash[c->flash_count].label = dupcheckstring(L, -1, "label");
        c->tab_flash[c->flash_count].address = checkuint(L, -1, "address");
        c->tab_flash[c->flash_count].size = checkuint(L, -1, "size");
        lua_pop(L, 1);
    }

    if (c->flash_count >= VM_MAX_FLASH_DEVICE) {
        luaL_error(L, "too many flash drives (max is %d)", VM_MAX_FLASH_DEVICE);
    }
}

void emulator_free_config(emulator_config *p) {
    free(p->cmdline);
    free(p->ram_image.filename);
    free(p->ram_image.buf);
    free(p->rom_image.filename);
    free(p->rom_image.buf);
    for (int i = 0; i < p->flash_count; i++) {
        free(p->tab_flash[i].backing);
        free(p->tab_flash[i].label);
    }
}

#define FDT_CHECK(func_call) do { \
    if ((func_call) != 0) return false; \
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

static bool fdt_build_riscv(const emulator_config *p, const emulator *emu, void *buf, int bufsize) {
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
      FDT_CHECK(fdt_property_u32(buf, "timebase-frequency", CLOCK_FREQ/RTC_FREQ_DIV));
      FDT_CHECK(fdt_begin_node_num(buf, "cpu", 0));
       FDT_CHECK(fdt_property_string(buf, "device_type", "cpu"));
       FDT_CHECK(fdt_property_u32(buf, "reg", 0));
       FDT_CHECK(fdt_property_string(buf, "status", "okay"));
       FDT_CHECK(fdt_property_string(buf, "compatible", "riscv"));
       int max_xlen = processor_get_max_xlen(emu->machine);
       uint32_t misa = processor_read_misa(emu->machine);
       char isa_string[128], *q = isa_string;
       q += snprintf(isa_string, sizeof(isa_string), "rv%d", max_xlen);
       for(int i = 0; i < 26; i++) {
           if (misa & (1 << i))
               *q++ = 'a' + i;
       }
       *q = '\0';
       FDT_CHECK(fdt_property_string(buf, "riscv,isa", isa_string));
       FDT_CHECK(fdt_property_string(buf, "mmu-type", "riscv,sv48"));
       FDT_CHECK(fdt_property_u32(buf, "clock-frequency", CLOCK_FREQ));
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

#if 0
    {
        FILE *f;
        f = fopen("emu.dtb", "wb");
        fwrite(buf, 1, size, f);
        fclose(f);
    }
#endif

    return true;
}

static bool init_ram_and_rom(const emulator_config *p, emulator *emu) {
    // Initialize RAM
    uint8_t *ram_ptr = board_get_host_memory(emu->machine, RAM_BASE_ADDR);
    if (!ram_ptr) return false;
    memcpy(ram_ptr, p->ram_image.buf, std::min(p->ram_image.len, p->ram_size));

    // Initialize ROM
    uint8_t *rom_ptr = board_get_host_memory(emu->machine, ROM_BASE_ADDR);
    if (!rom_ptr) return false;
    if (!p->rom_image.buf) {
        uint32_t fdt_addr = 8 * 8;
        if (!fdt_build_riscv(p, emu, rom_ptr + fdt_addr, ROM_SIZE-fdt_addr))
            return false;
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

#if 0
    {
        FILE *f;
        f = fopen("bootstrap.bin", "wb");
        fwrite(rom_ptr, 1, ROM_SIZE, f);
        fclose(f);
    }
#endif

    return true;
}

void emulator_set_defaults(emulator_config *p) {
    memset(p, 0, sizeof(*p));
}

void emulator_end(emulator *emu) {
    htif_end(emu->htif);
    machine_end(emu->machine);
    delete emu->tree;
    free(emu);
}

emulator *emulator_init(const emulator_config *c) {

    if (!c->ram_image.buf && !c->rom_image.buf) {
        fprintf(stderr, "No ROM or RAM images\n");
        return nullptr;
    }

    if (c->rom_image.buf && c->rom_image.len > ROM_SIZE) {
        fprintf(stderr, "ROM image too big (%d vs %d)\n", (int) c->ram_image.len, (int) ROM_SIZE);
        return nullptr;
    }

    if (c->ram_image.len >  c->ram_size) {
        fprintf(stderr, "RAM image too big (%d vs %d)\n", (int) c->ram_image.len, (int) c->ram_size);
        return nullptr;
    }

    emulator *emu = reinterpret_cast<emulator *>(calloc(1, sizeof(*emu)));

    emu->machine = machine_init(CARTESI_VENDORID, CARTESI_ARCHID,
        CARTESI_IMPID);

    if (!emu->machine) {
        fprintf(stderr, "Unable to initialize machine\n");
        goto failed;
    }

    /* RAM */
    if (!board_register_ram(emu->machine, RAM_BASE_ADDR, c->ram_size)) {
        fprintf(stderr, "Unable to allocate RAM\n");
        goto failed;
    }

    if (!board_register_ram(emu->machine, ROM_BASE_ADDR, ROM_SIZE)) {
        fprintf(stderr, "Unable to allocate ROM\n");
        goto failed;
    }

    /* flash */
    for (int i = 0; i < c->flash_count; i++) {
        if (!board_register_flash(emu->machine, c->tab_flash[i].address,
            c->tab_flash[i].size, c->tab_flash[i].backing, c->tab_flash[i].shared)) {
            fprintf(stderr, "Unable to initialize flash drive %d\n", i);
            goto failed;
        }
    }

    if (!board_register_mmio(emu->machine, CLINT_BASE_ADDR, CLINT_SIZE, nullptr,
            &clint_driver)) {
        fprintf(stderr, "Unable to initialize CLINT device\n");
        goto failed;
    }

    emu->htif = htif_init(emu->machine, c->interactive);
    if (!emu->htif) {
        fprintf(stderr, "Unable to initialize HTIF device\n");
        goto failed;
    }

    if (!board_register_mmio(emu->machine, HTIF_BASE_ADDR, HTIF_SIZE, emu->htif,
            &htif_driver)) {
        fprintf(stderr, "Unable to initialize HTIF device\n");
        goto failed;
    }

    if (!board_register_mmio(emu->machine, SHADOW_BASE_ADDR, SHADOW_SIZE,
            emu->machine, &shadow_driver)) {
        fprintf(stderr, "Unable to initialize shadow device\n");
        goto failed;
    }

    if (!init_ram_and_rom(c, emu)) {
        fprintf(stderr, "Unable to initialize RAM and ROM contents\n");
        goto failed;
    }

    emu->tree = new merkle_tree;

    return emu;

failed:
    emulator_end(emu);
    return nullptr;
}

uint64_t emulator_read_mcycle(emulator *emu) {
    return processor_read_mcycle(emu->machine);
}

uint64_t emulator_read_tohost(emulator *emu) {
    return processor_read_tohost(emu->machine);
}

const char *emulator_get_name(void) {
    return "riscv64";
}

int emulator_update_merkle_tree(emulator *emu) {
    machine_update_merkle_tree(emu->machine, emu->tree);
    return 1;
}

int emulator_get_merkle_tree_root_hash(emulator *emu, uint8_t *buf, int len) {
    merkle_tree::keccak_256_hash h;
    if (!emu->tree->is_error(emu->tree->get_merkle_tree_root_hash(h))) {
        memcpy(buf, h.data(), std::min(len, static_cast<int>(h.size())));
        return 1;
    } else {
        return 0;
    }
}

int emulator_run(emulator *emu, uint64_t mcycle_end) {

    // The emulator outer loop breaks only when the machine is halted
    // or when mcycle hits mcycle_end
    for ( ;; ) {

        machine_state *s = emu->machine;

        // If we are halted, do nothing
        if (processor_read_iflags_H(s)) {
            return 1;
        }

        // Run the emulator inner loop until we reach the next multiple of RISCV_RTC_FREQ_DIV
        // ??D This is enough for us to be inside the inner loop for about 98% of the time,
        // according to measurement, so it is not a good target for further optimization
        uint64_t mcycle = processor_read_mcycle(s);
        uint64_t next_rtc_freq_div = mcycle + RTC_FREQ_DIV - mcycle % RTC_FREQ_DIV;
        machine_run(s, std::min(next_rtc_freq_div, mcycle_end));

        // If we hit mcycle_end, we are done
        mcycle = processor_read_mcycle(s);
        if (mcycle >= mcycle_end) {
            return 0;
        }

        // If we managed to run until the next possible frequency divisor
        if (mcycle == next_rtc_freq_div) {
            // Get the mcycle corresponding to mtimecmp
            uint64_t timecmp_mcycle = rtc_time_to_cycle(processor_read_mtimecmp(s));

            // If the processor is waiting for interrupts, we can skip until time hits timecmp
            // CLINT is the only interrupt source external to the inner loop
            // IPI (inter-processor interrupt) via MSIP can only be raised internally
            if (processor_read_iflags_I(s)) {
                mcycle = std::min(timecmp_mcycle, mcycle_end);
                processor_write_mcycle(s, mcycle);
            }

            // If the timer is expired, set interrupt as pending
            if (timecmp_mcycle && timecmp_mcycle <= mcycle) {
                processor_set_mip(s, MIP_MTIP);
            }

            // Perform interactive actions
            htif_interact(emu->htif);
        }
    }
}
