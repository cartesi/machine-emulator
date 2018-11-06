#include <cassert>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

extern "C" {
#include <libfdt.h>
}

#include "machine.h"
#include "merkle-tree.h"
#include "emulator.h"
#include "machine.h"
#include "clint.h"
#include "htif.h"
#include "shadow.h"
#include "rtc.h"
#include "riscv-constants.h"

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

static int get_file_size(const char *name) {
    FILE *f = fopen(name, "rb");
    if (!f) {
        fprintf(stderr, "Unable to open %s\n", name);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    int size = ftell(f);
    fclose(f);
    return size;
}

static int load_file(const char *name, void *buf, int len) {
    FILE *f = fopen(name, "rb");
    if (!f) {
        fprintf(stderr, "Unable to open %s\n", name);
        return -1;
    }
    len = fread(buf, 1, len, f);
    fclose(f);
    return len;
}

emulator_config *emulator_config_init(void) {
    emulator_config *c = new emulator_config;
    // First, initialize all registers with zeros
    memset(c->processor.x, 0, sizeof(c->processor.x));
    c->processor.pc = 0;
    c->processor.mvendorid = 0;
    c->processor.marchid = 0;
    c->processor.mimpid = 0;
    c->processor.mcycle = 0;
    c->processor.minstret = 0;
    c->processor.mstatus = 0;
    c->processor.mtvec = 0;
    c->processor.mscratch = 0;
    c->processor.mepc = 0;
    c->processor.mcause = 0;
    c->processor.mtval = 0;
    c->processor.misa = 0;
    c->processor.mie = 0;
    c->processor.mip = 0;
    c->processor.medeleg = 0;
    c->processor.mideleg = 0;
    c->processor.mcounteren = 0;
    c->processor.stvec = 0;
    c->processor.sscratch = 0;
    c->processor.sepc = 0;
    c->processor.scause = 0;
    c->processor.stval = 0;
    c->processor.satp = 0;
    c->processor.scounteren = 0;
    c->processor.ilrsc = 0;
    c->processor.iflags = 0;
    // Now fill in values different from zero
    // Starting address is 4k
    c->processor.pc = 0x1000;
    // M-mode
    c->processor.iflags = PRV_M << IFLAGS_PRV_SHIFT;
    // No reservation
    c->processor.ilrsc = -1;
    c->processor.mstatus = ((uint64_t)MXL << MSTATUS_UXL_SHIFT) |
        ((uint64_t)MXL << MSTATUS_SXL_SHIFT);
    // Set our extensions in misa
    c->processor.misa = MXL;
    c->processor.misa <<= (XLEN-2); /* set xlen to 64 */
    c->processor.misa |= MISAEXT_S | MISAEXT_U | MISAEXT_I |
        MISAEXT_M | MISAEXT_A;
    // Set our ids
    c->processor.mvendorid = CARTESI_VENDORID;
    c->processor.marchid = CARTESI_ARCHID;
    c->processor.mimpid = CARTESI_IMPID;
    return c;
}

void emulator_config_end(emulator_config *c) {
    delete c;
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

static bool fdt_build_riscv(const emulator_config *c, const emulator *emu, void *buf, int bufsize) {
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
       int max_xlen = machine_get_max_xlen(emu->machine);
       uint32_t misa = machine_read_misa(emu->machine);
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
      FDT_CHECK(fdt_property_u64_u64(buf, "reg", RAM_BASE_ADDR, c->ram.length));
     FDT_CHECK(fdt_end_node(buf)); /* memory */

     /* flash */
     for (const auto &f: c->flash) {
         FDT_CHECK(fdt_begin_node_num(buf, "flash", f.start));
          FDT_CHECK(fdt_property_u32(buf, "#address-cells", 2));
          FDT_CHECK(fdt_property_u32(buf, "#size-cells", 2));
          FDT_CHECK(fdt_property_string(buf, "compatible", "mtd-ram"));
          FDT_CHECK(fdt_property_u32(buf, "bank-width", 4));
          FDT_CHECK(fdt_property_u64_u64(buf, "reg", f.start, f.length));
          FDT_CHECK(fdt_begin_node_num(buf, "fs0", 0));
           FDT_CHECK(fdt_property_string(buf, "label", f.label.c_str()));
           FDT_CHECK(fdt_property_u64_u64(buf, "reg", 0, f.length));
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
      FDT_CHECK(fdt_property_string(buf, "bootargs", c->rom.bootargs.c_str()));
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

static bool init_ram_and_rom(const emulator_config *c, emulator *emu) {

    if (c->ram.backing.empty() && c->rom.backing.empty()) {
        fprintf(stderr, "No ROM or RAM images\n");
        return false;
    }

    if (!c->rom.backing.empty()) {
        int len = get_file_size(c->rom.backing.c_str());
        if (len < 0) {
            fprintf(stderr, "Unable to open ROM image\n");
            return false;
        } else if (len > (int) ROM_SIZE) {
            fprintf(stderr, "ROM image too big (%d vs %d)\n",
                (int) len, (int) ROM_SIZE);
            return false;
        }
    }

    if (!c->ram.backing.empty()) {
        int len = get_file_size(c->ram.backing.c_str());
        if (len < 0) {
            fprintf(stderr, "Unable to open RAM image\n");
            return false;
        } else if (len > (int) c->ram.length) {
            fprintf(stderr, "RAM image too big (%d vs %d)\n",
                (int) len, (int) c->ram.length);
            return false;
        }
    }

    // Initialize RAM
    uint8_t *ram_ptr = machine_get_host_memory(emu->machine, RAM_BASE_ADDR);
    if (!ram_ptr) return false;
    if (load_file(c->ram.backing.c_str(), ram_ptr, c->ram.length) < 0) {
        fprintf(stderr, "Unable to load RAM image\n");
        return false;
    }

    // Initialize ROM
    uint8_t *rom_ptr = machine_get_host_memory(emu->machine, ROM_BASE_ADDR);
    if (!rom_ptr) return false;
    if (c->rom.backing.empty()) {
        uint32_t fdt_addr = 8 * 8;
        if (!fdt_build_riscv(c, emu, rom_ptr + fdt_addr, ROM_SIZE-fdt_addr))
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
        if (load_file(c->rom.backing.c_str(), rom_ptr, ROM_SIZE) < 0) {
            fprintf(stderr, "Unable to load ROM image\n");
            return false;
        }
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

void emulator_end(emulator *emu) {
    htif_end(emu->htif);
    machine_end(emu->machine);
    delete emu->tree;
    free(emu);
}

static bool init_processor_state(const emulator_config *c, emulator *emu) {
    //??D implement load from backing file
    assert(c->processor.backing.empty());
    // General purpose registers
    for (int i = 1; i < 32; i++) {
        machine_write_register(emu->machine, i, c->processor.x[i]);
    }
    // Named registers
    machine_write_pc(emu->machine, c->processor.pc);
    machine_write_mvendorid(emu->machine, c->processor.mvendorid);
    machine_write_marchid(emu->machine, c->processor.marchid);
    machine_write_mimpid(emu->machine, c->processor.mimpid);
    machine_write_mcycle(emu->machine, c->processor.mcycle);
    machine_write_minstret(emu->machine, c->processor.minstret);
    machine_write_mstatus(emu->machine, c->processor.mstatus);
    machine_write_mtvec(emu->machine, c->processor.mtvec);
    machine_write_mscratch(emu->machine, c->processor.mscratch);
    machine_write_mepc(emu->machine, c->processor.mepc);
    machine_write_mcause(emu->machine, c->processor.mcause);
    machine_write_mtval(emu->machine, c->processor.mtval);
    machine_write_misa(emu->machine, c->processor.misa);
    machine_write_mie(emu->machine, c->processor.mie);
    machine_write_mip(emu->machine, c->processor.mip);
    machine_write_medeleg(emu->machine, c->processor.medeleg);
    machine_write_mideleg(emu->machine, c->processor.mideleg);
    machine_write_mcounteren(emu->machine, c->processor.mcounteren);
    machine_write_stvec(emu->machine, c->processor.stvec);
    machine_write_sscratch(emu->machine, c->processor.sscratch);
    machine_write_sepc(emu->machine, c->processor.sepc);
    machine_write_scause(emu->machine, c->processor.scause);
    machine_write_stval(emu->machine, c->processor.stval);
    machine_write_satp(emu->machine, c->processor.satp);
    machine_write_scounteren(emu->machine, c->processor.scounteren);
    machine_write_ilrsc(emu->machine, c->processor.ilrsc);
    machine_write_iflags(emu->machine, c->processor.iflags);
	return true;
}

static bool init_htif_state(const emulator_config *c, emulator *emu) {
    //??D implement load from backing file
	assert(c->htif.backing.empty());
    machine_write_tohost(emu->machine, c->htif.tohost);
    machine_write_fromhost(emu->machine, c->htif.fromhost);
    return true;
}

static bool init_clint_state(const emulator_config *c, emulator *emu) {
    //??D implement load from backing file
	assert(c->clint.backing.empty());
    machine_write_mtimecmp(emu->machine, c->clint.mtimecmp);
    return true;
}

emulator *emulator_init(const emulator_config *c) {

    emulator *emu = reinterpret_cast<emulator *>(calloc(1, sizeof(*emu)));

    emu->machine = machine_init();

    if (!emu->machine) {
        fprintf(stderr, "Unable to initialize machine\n");
        goto failed;
    }

    if (!init_processor_state(c, emu)) {
        fprintf(stderr, "Unable to initialize processor\n");
        goto failed;
    }

    // RAM and ROM
    if (!machine_register_ram(emu->machine, RAM_BASE_ADDR, c->ram.length)) {
        fprintf(stderr, "Unable to allocate RAM\n");
        goto failed;
    }

    if (!machine_register_ram(emu->machine, ROM_BASE_ADDR, ROM_SIZE)) {
        fprintf(stderr, "Unable to allocate ROM\n");
        goto failed;
    }

    if (!init_ram_and_rom(c, emu)) {
        fprintf(stderr, "Unable to initialize RAM and ROM contents\n");
        goto failed;
    }

    /* flash */
    for (const auto &f: c->flash) {
        if (!machine_register_flash(emu->machine, f.start,
            f.length, f.backing.c_str(), f.shared)) {
            fprintf(stderr, "Unable to initialize flash drive '%s'\n",
                f.label.c_str());
            goto failed;
        }
    }

    if (!machine_register_mmio(emu->machine, CLINT_BASE_ADDR,
            CLINT_SIZE, nullptr, &clint_driver) && !init_clint_state(c, emu)) {
        fprintf(stderr, "Unable to initialize CLINT device\n");
        goto failed;
    }

    emu->htif = htif_init(emu->machine, c->interactive);
    if (!emu->htif) {
        fprintf(stderr, "Unable to initialize HTIF device\n");
        goto failed;
    }

    if (!machine_register_mmio(emu->machine, HTIF_BASE_ADDR, HTIF_SIZE,
            emu->htif, &htif_driver) && !init_htif_state(c, emu)) {
        fprintf(stderr, "Unable to initialize HTIF device\n");
        goto failed;
    }

    if (!machine_register_mmio(emu->machine, SHADOW_BASE_ADDR, SHADOW_SIZE,
            emu->machine, &shadow_driver)) {
        fprintf(stderr, "Unable to initialize shadow device\n");
        goto failed;
    }

    emu->tree = new merkle_tree;

    return emu;

failed:
    emulator_end(emu);
    return nullptr;
}

uint64_t emulator_read_mcycle(emulator *emu) {
    return machine_read_mcycle(emu->machine);
}

uint64_t emulator_read_tohost(emulator *emu) {
    return machine_read_tohost(emu->machine);
}

std::string emulator_get_name(void) {
    std::ostringstream os;
    os << CARTESI_VENDORID << ':' << CARTESI_ARCHID << ':' << CARTESI_IMPID;
    return os.str();
}

int emulator_update_merkle_tree(emulator *emu) {
    machine_update_merkle_tree(emu->machine, emu->tree);
    return 1;
}

int emulator_get_merkle_tree_root_hash(emulator *emu, uint8_t *data, size_t len) {
    merkle_tree::digest_type hash;
    int ret = !emu->tree->is_error(emu->tree->get_merkle_tree_root_hash(hash));
    memcpy(data, hash.data(), std::min(len, hash.size()));
    return ret;
}

int emulator_run(emulator *emu, uint64_t mcycle_end) {

    // The emulator outer loop breaks only when the machine is halted
    // or when mcycle hits mcycle_end
    for ( ;; ) {

        machine_state *s = emu->machine;

        // If we are halted, do nothing
        if (machine_read_iflags_H(s)) {
            return 1;
        }

        // Run the emulator inner loop until we reach the next multiple of RISCV_RTC_FREQ_DIV
        // ??D This is enough for us to be inside the inner loop for about 98% of the time,
        // according to measurement, so it is not a good target for further optimization
        uint64_t mcycle = machine_read_mcycle(s);
        uint64_t next_rtc_freq_div = mcycle + RTC_FREQ_DIV - mcycle % RTC_FREQ_DIV;
        machine_run(s, std::min(next_rtc_freq_div, mcycle_end));

        // If we hit mcycle_end, we are done
        mcycle = machine_read_mcycle(s);
        if (mcycle >= mcycle_end) {
            return 0;
        }

        // If we managed to run until the next possible frequency divisor
        if (mcycle == next_rtc_freq_div) {
            // Get the mcycle corresponding to mtimecmp
            uint64_t timecmp_mcycle = rtc_time_to_cycle(machine_read_mtimecmp(s));

            // If the processor is waiting for interrupts, we can skip until time hits timecmp
            // CLINT is the only interrupt source external to the inner loop
            // IPI (inter-processor interrupt) via MSIP can only be raised internally
            if (machine_read_iflags_I(s)) {
                mcycle = std::min(timecmp_mcycle, mcycle_end);
                machine_write_mcycle(s, mcycle);
            }

            // If the timer is expired, set interrupt as pending
            if (timecmp_mcycle && timecmp_mcycle <= mcycle) {
                machine_set_mip(s, MIP_MTIP);
            }

            // Perform interactive actions
            htif_interact(emu->htif);
        }
    }
}
