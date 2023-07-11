// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#include <cinttypes>
#include <sstream>
#include <stdexcept>
#include <string>

/// \file
/// \brief Bootstrap and device tree in ROM

#include "fdt-builder.h"
#include "machine-c-version.h"
#include "pma-constants.h"
#include "riscv-constants.h"
#include "rng-seed.h"
#include "rom.h"
#include "rtc.h"

namespace cartesi {

static std::string misa_to_isa_string(uint64_t misa) {
    std::ostringstream ss;
    ss << "rv64";
    for (int i = 0; i < 26; i++) {
        if (misa & (1 << i)) {
            ss << static_cast<char>('a' + i);
        }
    }
    return ss.str();
}

void rom_init(const machine_config &c, unsigned char *rom_start, uint64_t length) {
    if (length < PMA_ROM_EXTRASPACE_LENGTH_DEF) {
        throw std::runtime_error{"not enough space on ROM for bootargs"};
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    char *bootargs = reinterpret_cast<char *>(rom_start + length - PMA_ROM_EXTRASPACE_LENGTH_DEF);

    if (!c.rom.bootargs.empty()) {
        strncpy(bootargs, c.rom.bootargs.c_str(), PMA_BOOTARGS_LENGTH_DEF);
        bootargs[PMA_BOOTARGS_LENGTH_DEF - 1] = '\0';
    }
}

void rom_init_device_tree(const machine_config &c, unsigned char *rom_start, uint64_t length) {
    using namespace std::string_literals;
    constexpr uint32_t INTC_PHANDLE = 1;
    constexpr uint32_t X_HOST = 13;
    constexpr uint32_t BOOTARGS_MAX_LEN = 4096;

    // Check if bootargs length is not too large
    if (c.rom.bootargs.length() > BOOTARGS_MAX_LEN) {
        throw std::runtime_error{"ROM bootargs is is above maximum length of 4096"};
    }

    FDTBuilder fdt;
    fdt.begin();

    { // root node
        fdt.begin_node("");
        fdt.prop_u32("#address-cells", 2);
        fdt.prop_u32("#size-cells", 2);
        fdt.prop_string("compatible", "ucbbar,riscvemu-bar_dev");
        fdt.prop_string("model", "ucbbar,riscvemu-bare");

        { // chosen
            fdt.begin_node("chosen");
            fdt.prop_string("bootargs", c.rom.bootargs);
            // ??(edubart): make this configurable in machine config?
            fdt.prop("rng-seed", FDT_RNG_SEED, sizeof(FDT_RNG_SEED));
            fdt.end_node();
        }

        // We add emulator version, so can inspect it from inside the machine by reading the FDT
        { // cartesi-machine
            fdt.begin_node("cartesi-machine");
            fdt.prop_string("version", CM_VERSION);
            fdt.end_node();
        }

        { // cpus
            fdt.begin_node("cpus");
            fdt.prop_u32("#address-cells", 1);
            fdt.prop_u32("#size-cells", 0);
            fdt.prop_u32("timebase-frequency", RTC_CLOCK_FREQ / RTC_FREQ_DIV);
            { // cpu
                fdt.begin_node_num("cpu", 0);
                fdt.prop_string("device_type", "cpu");
                fdt.prop_u32("reg", 0);
                fdt.prop_string("status", "okay");
                fdt.prop_string("compatible", "riscv");
                fdt.prop_string("riscv,isa", misa_to_isa_string(c.processor.misa));
                fdt.prop_string("mmu-type", "riscv,sv39");
                fdt.prop_u32("clock-frequency", RTC_CLOCK_FREQ);
                { // interrupt-controller
                    fdt.begin_node("interrupt-controller");
                    fdt.prop_u32("#interrupt-cells", 1);
                    fdt.prop_empty("interrupt-controller");
                    fdt.prop_string("compatible", "riscv,cpu-intc");
                    fdt.prop_u32("phandle", INTC_PHANDLE);
                    fdt.end_node();
                }
                fdt.end_node();
            }
            fdt.end_node();
        }

        { // soc
            fdt.begin_node("soc");
            fdt.prop_u32("#address-cells", 2);
            fdt.prop_u32("#size-cells", 2);
            fdt.prop_string("compatible", "ucbbar,riscvemu-bar-soc\0simple-bus"s);
            fdt.prop_empty("ranges");
            { // clint
                fdt.begin_node_num("clint", PMA_CLINT_START);
                fdt.prop_string("compatible", "riscv,clint0");
                fdt.prop_u64_list<2>("reg", {PMA_CLINT_START, PMA_CLINT_LENGTH});
                fdt.prop_u32_list<4>("interrupts-extended",
                    {INTC_PHANDLE, MIP_MSIP_SHIFT, INTC_PHANDLE, MIP_MTIP_SHIFT});
                fdt.end_node();
            }
            { // htif
                fdt.begin_node_num("htif", PMA_HTIF_START);
                fdt.prop_string("compatible", "ucb,htif0");
                fdt.prop_u64_list<2>("reg", {PMA_HTIF_START, PMA_HTIF_LENGTH});
                fdt.prop_u32_list<2>("interrupts-extended", {INTC_PHANDLE, X_HOST});
                fdt.end_node();
            }
            fdt.end_node();
        }

        { // memory
            fdt.begin_node_num("memory", PMA_RAM_START);
            fdt.prop_string("device_type", "memory");
            fdt.prop_u64_list<2>("reg", {PMA_RAM_START, c.ram.length});
            fdt.end_node();
        }

        // flash
        int drive_index = 0;
        for (const auto &f : c.flash_drive) {
            fdt.begin_node_num("flash", f.start);
            fdt.prop_u32("#address-cells", 2);
            fdt.prop_u32("#size-cells", 2);
            fdt.prop_string("compatible", "mtd-ram");
            fdt.prop_u32("bank-width", 4);
            fdt.prop_u64_list<2>("reg", {f.start, f.length});
            fdt.prop_string("linux,mtd-name", "flash."s + std::to_string(drive_index));
            fdt.end_node();
            drive_index++;
        }

        // rollup
        if (c.rollup.has_value()) {
            const auto &r = c.rollup.value();
            fdt.begin_node("rollup");
            fdt.prop_u32("#address-cells", 2);
            fdt.prop_u32("#size-cells", 2);
            fdt.prop_string("compatible", "ctsi-rollup");
            { // rx_buffer
                fdt.begin_node_num("rx_buffer", r.rx_buffer.start);
                fdt.prop_u64_list<2>("reg", {r.rx_buffer.start, r.rx_buffer.length});
                fdt.end_node();
            }
            { // tx_buffer
                fdt.begin_node_num("tx_buffer", r.tx_buffer.start);
                fdt.prop_u64_list<2>("reg", {r.tx_buffer.start, r.tx_buffer.length});
                fdt.end_node();
            }
            { // input_metadata
                fdt.begin_node_num("input_metadata", r.input_metadata.start);
                fdt.prop_u64_list<2>("reg", {r.input_metadata.start, r.input_metadata.length});
                fdt.end_node();
            }
            { // voucher_hashes
                fdt.begin_node_num("voucher_hashes", r.voucher_hashes.start);
                fdt.prop_u64_list<2>("reg", {r.voucher_hashes.start, r.voucher_hashes.length});
                fdt.end_node();
            }
            { // notice_hashes
                fdt.begin_node_num("notice_hashes", r.notice_hashes.start);
                fdt.prop_u64_list<2>("reg", {r.notice_hashes.start, r.notice_hashes.length});
                fdt.end_node();
            }
            fdt.end_node();
        }

        // yield
        if (c.htif.yield_manual || c.htif.yield_automatic) {
            fdt.begin_node("yield");
            fdt.prop_string("compatible", "ctsi-yield");
            if (c.htif.yield_manual) {
                fdt.prop_empty("manual");
            }
            if (c.htif.yield_automatic) {
                fdt.prop_empty("automatic");
            }
            fdt.end_node();
        }

        fdt.end_node();
    }

    fdt.end();
    fdt.finish(rom_start, length);
}

} // namespace cartesi
