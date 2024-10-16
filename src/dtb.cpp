// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

/// \file
/// \brief Device Tree Blob

#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>

#include "dtb.h"
#include "fdt-builder.h"
#include "machine-c-version.h"
#include "machine-config.h"
#include "pma-constants.h"
#include "riscv-constants.h"
#include "rng-seed.h"
#include "rtc.h"

using namespace std::string_literals;

namespace cartesi {

static std::string misa_to_isa_string(uint64_t misa) {
    std::ostringstream ss;
    ss << "rv64";
    for (int i = 0; i < 26; i++) {
        if ((misa & (1 << i)) != 0) {
            ss << static_cast<char>('a' + i);
        }
    }
    return ss.str();
}

void dtb_init(const machine_config &c, unsigned char *dtb_start, uint64_t dtb_length) {
    using namespace std::string_literals;
    enum : uint32_t { INTC_PHANDLE = 1, PLIC_PHANDLE };
    constexpr uint32_t X_HOST = 13;
    constexpr uint32_t BOOTARGS_MAX_LEN = 4096;

    // Check if bootargs length is not too large
    if (c.dtb.bootargs.length() > BOOTARGS_MAX_LEN) {
        throw std::runtime_error{"DTB bootargs is is above maximum length of 4096"};
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
            fdt.prop_string("bootargs", c.dtb.bootargs);
            // ??(edubart): make this configurable in machine config?
            fdt.prop("rng-seed", FDT_RNG_SEED, sizeof(FDT_RNG_SEED));
            fdt.end_node();
        }

        // We add emulator version, so can inspect it from inside the machine by reading the FDT
        { // cartesi-machine
            fdt.begin_node("cartesi-machine");
            fdt.prop_string("version", CM_VERSION_MAJMIN);
            fdt.prop_string_data("init", c.dtb.init);
            fdt.prop_string_data("entrypoint", c.dtb.entrypoint);
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
            { // plic
                fdt.begin_node_num("plic", PMA_PLIC_START);
                fdt.prop_u32("#interrupt-cells", 1);
                fdt.prop_empty("interrupt-controller");
                fdt.prop_string("compatible", "riscv,plic0");
                fdt.prop_u32("riscv,ndev", PMA_PLIC_MAX_IRQ);
                fdt.prop_u64_list<2>("reg", {PMA_PLIC_START, PMA_PLIC_LENGTH});
                fdt.prop_u32_list<4>("interrupts-extended",
                    {INTC_PHANDLE, MIP_SEIP_SHIFT, INTC_PHANDLE, MIP_MEIP_SHIFT});
                fdt.prop_u32("phandle", PLIC_PHANDLE);
                fdt.end_node();
            }
            { // htif
                fdt.begin_node_num("htif", PMA_HTIF_START);
                fdt.prop_string("compatible", "ucb,htif0");
                fdt.prop_u64_list<2>("reg", {PMA_HTIF_START, PMA_HTIF_LENGTH});
                fdt.prop_u32_list<2>("interrupts-extended", {INTC_PHANDLE, X_HOST});
                fdt.end_node();
            }
            for (uint32_t virtio_idx = 0; virtio_idx < c.virtio.size(); ++virtio_idx) { // virtio
                const uint64_t virtio_paddr = PMA_FIRST_VIRTIO_START + virtio_idx * PMA_VIRTIO_LENGTH;
                const uint32_t plic_irq_id = virtio_idx + 1;
                fdt.begin_node_num("virtio", virtio_paddr);
                fdt.prop_string("compatible", "virtio,mmio");
                fdt.prop_u64_list<2>("reg", {virtio_paddr, PMA_VIRTIO_LENGTH});
                fdt.prop_u32_list<2>("interrupts-extended", {PLIC_PHANDLE, plic_irq_id});
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

        { // reserved memory
            fdt.begin_node("reserved-memory");
            fdt.prop_u32("#address-cells", 2);
            fdt.prop_u32("#size-cells", 2);
            fdt.prop_empty("ranges");
            { // reserve 256KB for firmware M-mode code (such as OpenSBI)
                fdt.begin_node_num("fw_resv", PMA_RAM_START);
                fdt.prop_u64_list<2>("reg", {PMA_RAM_START, 0x40000});
                fdt.prop_empty("no-map");
                fdt.end_node();
            }
            fdt.end_node();
        }

        // drives
        for (const auto &f : c.flash_drive) {
            fdt.begin_node_num("pmem", f.start);
            fdt.prop_string("compatible", "pmem-region");
            fdt.prop_u64_list<2>("reg", {f.start, f.length});
            fdt.prop_empty("volatile");
            fdt.end_node();
        }

        // cmio
        fdt.begin_node("cmio");
        fdt.prop_u32("#address-cells", 2);
        fdt.prop_u32("#size-cells", 2);
        fdt.prop_string("compatible", "ctsi-cmio");
        { // rx_buffer
            fdt.begin_node_num("rx_buffer", PMA_CMIO_RX_BUFFER_START);
            fdt.prop_u64_list<2>("reg", {PMA_CMIO_RX_BUFFER_START, PMA_CMIO_RX_BUFFER_LENGTH});
            fdt.end_node();
        }
        { // tx_buffer
            fdt.begin_node_num("tx_buffer", PMA_CMIO_TX_BUFFER_START);
            fdt.prop_u64_list<2>("reg", {PMA_CMIO_TX_BUFFER_START, PMA_CMIO_TX_BUFFER_LENGTH});
            fdt.end_node();
        }
        fdt.end_node();

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
    fdt.finish(dtb_start, dtb_length);
}

} // namespace cartesi
