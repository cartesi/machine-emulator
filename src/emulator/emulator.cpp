#include <cassert>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

#include "machine.h"
#include "merkle-tree.h"
#include "emulator.h"
#include "machine.h"
#include "clint.h"
#include "shadow.h"
#include "rtc.h"
#include "pma.h"
#include "riscv-constants.h"

extern "C" {
#include <libfdt.h>
}

#define CLOCK_FREQ 1000000000 // 1 GHz (arbitrary)

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

static bool fdt_build_riscv(const machine_config &c, const machine &m, void *buf, int bufsize) {
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
       int max_xlen = m.get_max_xlen();
       uint32_t misa = m.read_misa();
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

     FDT_CHECK(fdt_begin_node_num(buf, "memory", PMA_RAM_START));
      FDT_CHECK(fdt_property_string(buf, "device_type", "memory"));
      FDT_CHECK(fdt_property_u64_u64(buf, "reg", PMA_RAM_START, c.ram.length));
     FDT_CHECK(fdt_end_node(buf)); /* memory */

     /* flash */
     for (const auto &f: c.flash) {
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

      FDT_CHECK(fdt_begin_node_num(buf, "clint", PMA_CLINT_START));
       FDT_CHECK(fdt_property_string(buf, "compatible", "riscv,clint0"));
       uint32_t clint[] = {
	       cpu_to_fdt32(intc_phandle),
	       cpu_to_fdt32(3), /* M IPI irq */
	       cpu_to_fdt32(intc_phandle),
	       cpu_to_fdt32(7) /* M timer irq */
       };
       FDT_CHECK(fdt_property(buf, "interrupts-extended", clint, sizeof(clint)));
       FDT_CHECK(fdt_property_u64_u64(buf, "reg", PMA_CLINT_START, PMA_CLINT_LENGTH));
      FDT_CHECK(fdt_end_node(buf)); /* clint */

      FDT_CHECK(fdt_begin_node_num(buf, "htif", PMA_HTIF_START));
       FDT_CHECK(fdt_property_string(buf, "compatible", "ucb,htif0"));
       FDT_CHECK(fdt_property_u64_u64(buf, "reg", PMA_HTIF_START, PMA_HTIF_LENGTH));
       uint32_t htif[] = {
           cpu_to_fdt32(intc_phandle),
           cpu_to_fdt32(13) // X HOST
       };
       FDT_CHECK(fdt_property(buf, "interrupts-extended", htif, sizeof(htif)));
      FDT_CHECK(fdt_end_node(buf));

     FDT_CHECK(fdt_end_node(buf)); /* soc */

     FDT_CHECK(fdt_begin_node(buf, "chosen"));
      FDT_CHECK(fdt_property_string(buf, "bootargs", c.rom.bootargs.c_str()));
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

static bool init_ram_and_rom(const machine_config &c, machine &m) {

    if (c.ram.backing.empty() && c.rom.backing.empty()) {
        fprintf(stderr, "No ROM or RAM images\n");
        return false;
    }

    if (!c.rom.backing.empty()) {
        int len = get_file_size(c.rom.backing.c_str());
        if (len < 0) {
            fprintf(stderr, "Unable to open ROM image\n");
            return false;
        } else if (len > (int) PMA_ROM_LENGTH) {
            fprintf(stderr, "ROM image too big (%d vs %d)\n",
                (int) len, (int) PMA_ROM_LENGTH);
            return false;
        }
    }

    // Initialize RAM
    if (!c.ram.backing.empty()) {
        int len = get_file_size(c.ram.backing.c_str());
        if (len < 0) {
            fprintf(stderr, "Unable to open RAM image\n");
            return false;
        } else if (len > (int) c.ram.length) {
            fprintf(stderr, "RAM image too big (%d vs %d)\n",
                (int) len, (int) c.ram.length);
            return false;
        }
        uint8_t *ram_ptr = m.get_host_memory(PMA_RAM_START);
        if (!ram_ptr) return false;
        if (load_file(c.ram.backing.c_str(), ram_ptr, c.ram.length) < 0) {
            fprintf(stderr, "Unable to load RAM image\n");
            return false;
        }
    }

    // Initialize ROM
    uint8_t *rom_ptr = m.get_host_memory(PMA_ROM_START);
    if (!rom_ptr) return false;
    if (c.rom.backing.empty()) {
        uint32_t fdt_addr = 8 * 8;
        if (!fdt_build_riscv(c, m, rom_ptr + fdt_addr, PMA_ROM_LENGTH-fdt_addr))
            return false;
        /* jump_addr = PMA_RAM_START */
        uint32_t *q = (uint32_t *)(rom_ptr);
        /* la t0, jump_addr */
        q[0] = 0x297 + PMA_RAM_START - PMA_ROM_START; /* auipc t0, 0x80000000-0x1000 */
        /* la a1, fdt_addr */
          q[1] = 0x597; /* auipc a1, 0  (a1 := 0x1004) */
          q[2] = 0x58593 + ((fdt_addr - (PMA_ROM_START+4)) << 20); /* addi a1, a1, 60 */
        q[3] = 0xf1402573; /* csrr a0, mhartid */
        q[4] = 0x00028067; /* jr t0 */
    } else {
        if (load_file(c.rom.backing.c_str(), rom_ptr, PMA_ROM_LENGTH) < 0) {
            fprintf(stderr, "Unable to load ROM image\n");
            return false;
        }
    }

#if 0
    {
        FILE *f;
        f = fopen("bootstrap.bin", "wb");
        fwrite(rom_ptr, 1, PMA_ROM_LENGTH, f);
        fclose(f);
    }
#endif

    return true;
}

emulator::~emulator() {
	// Nothing to do: all members are destroyed automatically
}

static bool init_processor_state(const machine_config &c, machine &m) {
    //??D implement load from backing file
    assert(c.processor.backing.empty());
    // General purpose registers
    for (int i = 1; i < 32; i++) {
        m.write_x(i, c.processor.x[i]);
    }
    // Named registers
    m.write_pc(c.processor.pc);
    m.write_mvendorid(c.processor.mvendorid);
    m.write_marchid(c.processor.marchid);
    m.write_mimpid(c.processor.mimpid);
    m.write_mcycle(c.processor.mcycle);
    m.write_minstret(c.processor.minstret);
    m.write_mstatus(c.processor.mstatus);
    m.write_mtvec(c.processor.mtvec);
    m.write_mscratch(c.processor.mscratch);
    m.write_mepc(c.processor.mepc);
    m.write_mcause(c.processor.mcause);
    m.write_mtval(c.processor.mtval);
    m.write_misa(c.processor.misa);
    m.write_mie(c.processor.mie);
    m.write_mip(c.processor.mip);
    m.write_medeleg(c.processor.medeleg);
    m.write_mideleg(c.processor.mideleg);
    m.write_mcounteren(c.processor.mcounteren);
    m.write_stvec(c.processor.stvec);
    m.write_sscratch(c.processor.sscratch);
    m.write_sepc(c.processor.sepc);
    m.write_scause(c.processor.scause);
    m.write_stval(c.processor.stval);
    m.write_satp(c.processor.satp);
    m.write_scounteren(c.processor.scounteren);
    m.write_ilrsc(c.processor.ilrsc);
    m.write_iflags(c.processor.iflags);
	return true;
}

static bool init_clint_state(const machine_config &c, machine &m) {
    //??D implement load from backing file
	assert(c.clint.backing.empty());
    m.write_clint_mtimecmp(c.clint.mtimecmp);
    return true;
}

emulator::emulator(const machine_config &c):
    m_machine{c} {

    if (!init_processor_state(c, m_machine)) {
		throw std::runtime_error("processor initialization failed");
    }

    // RAM and ROM
    m_machine.register_ram(PMA_RAM_START, c.ram.length);
    m_machine.register_rom(PMA_ROM_START, PMA_ROM_LENGTH);

    if (!init_ram_and_rom(c, m_machine)) {
        throw std::runtime_error("RAM/ROM initialization failed");
    }

    for (const auto &f: c.flash) {
        m_machine.register_flash(f.start, f.length,
            f.backing.c_str(), f.shared);
    }

    clint_register_mmio(m_machine, PMA_CLINT_START, PMA_CLINT_LENGTH);
    if (!init_clint_state(c, m_machine)) {
        throw std::runtime_error("unable to initialize CLINT device");
    }

    m_machine.get_htif().register_mmio(PMA_HTIF_START, PMA_HTIF_LENGTH);

    shadow_register_mmio(m_machine, PMA_SHADOW_START, PMA_SHADOW_LENGTH);
}

std::string emulator::get_name(void) {
    std::ostringstream os;
    os << VENDORID << ':' << ARCHID << ':' << IMPID;
    return os.str();
}

bool emulator::update_merkle_tree(void) {
    return m_machine.update_merkle_tree();
}

bool emulator::verify_merkle_tree(void) {
    return m_machine.get_merkle_tree().verify_tree();
}

const machine &emulator::get_machine(void) const {
    return m_machine;
}

machine &emulator::get_machine(void) {
    return m_machine;
}

void emulator::run(uint64_t mcycle_end) {

    // The emulator outer loop breaks only when the machine is halted
    // or when mcycle hits mcycle_end
    for ( ;; ) {

        // If we are halted, do nothing
        if (m_machine.read_iflags_H()) {
            return;
        }

        // Run the emulator inner loop until we reach the next multiple of RISCV_RTC_FREQ_DIV
        // ??D This is enough for us to be inside the inner loop for about 98% of the time,
        // according to measurement, so it is not a good target for further optimization
        uint64_t mcycle = m_machine.read_mcycle();
        uint64_t next_rtc_freq_div = mcycle + RTC_FREQ_DIV - mcycle % RTC_FREQ_DIV;
        m_machine.run_inner_loop(std::min(next_rtc_freq_div, mcycle_end));

        // If we hit mcycle_end, we are done
        mcycle = m_machine.read_mcycle();
        if (mcycle >= mcycle_end) {
            return;
        }

        // If we managed to run until the next possible frequency divisor
        if (mcycle == next_rtc_freq_div) {
            // Get the mcycle corresponding to mtimecmp
            uint64_t timecmp_mcycle = rtc_time_to_cycle(m_machine.read_clint_mtimecmp());

            // If the processor is waiting for interrupts, we can skip until time hits timecmp
            // CLINT is the only interrupt source external to the inner loop
            // IPI (inter-processor interrupt) via MSIP can only be raised internally
            if (m_machine.read_iflags_I()) {
                mcycle = std::min(timecmp_mcycle, mcycle_end);
                m_machine.write_mcycle(mcycle);
            }

            // If the timer is expired, set interrupt as pending
            if (timecmp_mcycle && timecmp_mcycle <= mcycle) {
                m_machine.set_mip(MIP_MTIP);
            }

            // Perform interactive actions
            m_machine.get_htif().interact();
        }
    }
}
