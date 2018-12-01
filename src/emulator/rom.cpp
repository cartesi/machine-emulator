#include <stdexcept>
#include <cinttypes>
#include <string>

/// \file
/// \brief Bootstrap and device tree in ROM

extern "C" {
#include <libfdt.h>
}

#include "rom.h"
#include "rtc.h"
#include "pma.h"
#include "machine-config.h"

#define CLOCK_FREQ 1000000000 // 1 GHz (arbitrary)

#define FDT_CHECK(func_call) do { \
    auto errval = (func_call); \
    if (errval != 0) \
        throw std::runtime_error{std::string{"device tree error: "} + fdt_strerror(errval)}; \
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

/// \brief Builds the device tree corresponding to a given machine configuration
/// \param c Machine configuration.
/// \param misa Machine misa register.
/// \param max_xlen Maximum XLEN for machine.
/// \param buf Pointer to start of buffer where device tree will be writen.
/// \param buflen Length of buffer.
static void build_device_tree(const machine_config &c, uint64_t misa, int max_xlen, void *buf, uint64_t buflen) {
    int cur_phandle = 1;
    FDT_CHECK(fdt_create(buf, buflen));
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
}

void rom_init(const machine_config &c, uint64_t misa, int max_xlen,
    uint8_t *rom_start, uint64_t length) {
    uint32_t fdt_addr = 8 * 8;
    // jump_addr = PMA_RAM_START
    uint32_t *q = (uint32_t *)(rom_start);
    // la t0, jump_addr
    q[0] = 0x297 + PMA_RAM_START - PMA_ROM_START; // auipc t0, 0x80000000-0x1000
    // la a1, fdt_addr
      q[1] = 0x597; // auipc a1, 0  (a1 := 0x1004)
      q[2] = 0x58593 + ((fdt_addr - (PMA_ROM_START+4)) << 20); // addi a1, a1, 60
    q[3] = 0xf1402573; // csrr a0, mhartid
    q[4] = 0x00028067; // jr t0
    build_device_tree(c, misa, max_xlen, rom_start + fdt_addr, length-fdt_addr);
}
