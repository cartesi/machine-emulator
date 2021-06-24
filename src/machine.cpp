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

#include <sstream>
#include <cstring>
#include <cinttypes>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <cstdio>
#include <mutex>
#include <future>
#include <thread>

#include <sys/stat.h>

#include "riscv-constants.h"
#include "machine.h"
#include "interpret.h"
#include "clint.h"
#include "htif.h"
#include "dhd.h"
#include "rtc.h"
#include "shadow.h"
#include "rom.h"
#include "unique-c-ptr.h"
#include "state-access.h"
#include "logged-state-access.h"
#include "step-state-access.h"
#include "strict-aliasing.h"

/// \file
/// \brief Cartesi machine implementation

namespace cartesi {

using namespace std::string_literals;

pma_entry::flags machine::m_ram_flags{
    true,                   // R
    true,                   // W
    true,                   // X
    true,                   // IR
    true,                   // IW
    PMA_ISTART_DID::memory  // DID
};

pma_entry::flags machine::m_rom_flags{
    true,                   // R
    false,                  // W
    true,                   // X
    true,                   // IR
    false,                  // IW
    PMA_ISTART_DID::memory  // DID
};

pma_entry::flags machine::m_flash_flags{
    true,                   // R
    true,                   // W
    false,                  // X
    true,                   // IR
    true,                   // IW
    PMA_ISTART_DID::drive  // DID
};


pma_entry machine::make_flash_pma_entry(const flash_drive_config &c) {
    if (c.image_filename.empty()) {
        return make_callocd_memory_pma_entry(c.start,
            c.length).set_flags(m_flash_flags);
    }

    return make_mmapd_memory_pma_entry(c.start,
        c.length, c.image_filename, c.shared).set_flags(m_flash_flags);
}


pma_entry &machine::register_pma_entry(pma_entry &&pma) {
    if (m_s.pmas.capacity() <= m_s.pmas.size()) {
        throw std::runtime_error{"too many PMAs"};
    }
    auto start = pma.get_start();
    if ((start & (PMA_PAGE_SIZE-1)) != 0) {
        throw std::invalid_argument{"PMA start must be aligned to page boundary"};
    }
    auto length = pma.get_length();
    if ((length & (PMA_PAGE_SIZE-1)) != 0) {
        throw std::invalid_argument{"PMA length must be multiple of page size"};
    }
    // Range A overlaps with B if A starts before B ends and A ends after B starts
    for (const auto &existing_pma: m_s.pmas) {
        if (start < existing_pma.get_start() + existing_pma.get_length() &&
            start+length > existing_pma.get_start()) {
            throw std::invalid_argument{"PMA overlaps with existing PMA"};
        }
    }
    m_s.pmas.push_back(std::move(pma));
    return m_s.pmas.back();
}

pma_entry& machine::replace_pma_entry(pma_entry&& new_entry) {
    for(auto & pma: m_s.pmas) {
        if (pma.get_istart() == new_entry.get_istart() && pma.get_ilength() == new_entry.get_ilength()) {
            pma = std::move(new_entry);
            return pma;
        }
    }
    throw std::invalid_argument{"PMA range does not exist"};
}

void machine::replace_flash_drive(const flash_drive_config &new_flash) {
    replace_pma_entry(make_flash_pma_entry(new_flash));
}

void machine::interact(void) {
    m_h.interact();
}

machine::machine(const machine_config &c,
    const machine_runtime_config &r):
    m_s{},
    m_t{},
    m_h{c.htif},
    m_c{c},
    m_r{r} {

    if (m_c.processor.marchid == UINT64_C(-1)) {
        m_c.processor.marchid = MARCHID_INIT;
    }

    if (m_c.processor.marchid != MARCHID_INIT) {
        throw std::invalid_argument{"marchid mismatch."};
    }

    if (m_c.processor.mvendorid == UINT64_C(-1)) {
        m_c.processor.mvendorid = MVENDORID_INIT;
    }

    if (m_c.processor.mvendorid != MVENDORID_INIT) {
        throw std::invalid_argument{"mvendorid mismatch."};
    }

    if (m_c.processor.mimpid == UINT64_C(-1)) {
        m_c.processor.mimpid = MIMPID_INIT;
    }

    if (m_c.processor.mimpid != MIMPID_INIT) {
        throw std::invalid_argument{"mimpid mismatch."};
    }

    // General purpose registers
    for (int i = 1; i < X_REG_COUNT; i++) {
        write_x(i, m_c.processor.x[i]);
    }

    write_pc(m_c.processor.pc);
    write_mcycle(m_c.processor.mcycle);
    write_minstret(m_c.processor.minstret);
    write_mstatus(m_c.processor.mstatus);
    write_mtvec(m_c.processor.mtvec);
    write_mscratch(m_c.processor.mscratch);
    write_mepc(m_c.processor.mepc);
    write_mcause(m_c.processor.mcause);
    write_mtval(m_c.processor.mtval);
    write_misa(m_c.processor.misa);
    write_mie(m_c.processor.mie);
    write_mip(m_c.processor.mip);
    write_medeleg(m_c.processor.medeleg);
    write_mideleg(m_c.processor.mideleg);
    write_mcounteren(m_c.processor.mcounteren);
    write_stvec(m_c.processor.stvec);
    write_sscratch(m_c.processor.sscratch);
    write_sepc(m_c.processor.sepc);
    write_scause(m_c.processor.scause);
    write_stval(m_c.processor.stval);
    write_satp(m_c.processor.satp);
    write_scounteren(m_c.processor.scounteren);
    write_ilrsc(m_c.processor.ilrsc);
    write_iflags(m_c.processor.iflags);

    if (m_c.rom.image_filename.empty()) {
        throw std::invalid_argument{"ROM image filename is undefined"};
    }

    // Register RAM
    if (m_c.ram.image_filename.empty()) {
        register_pma_entry(make_callocd_memory_pma_entry(PMA_RAM_START,
            m_c.ram.length).set_flags(m_ram_flags));
    } else {
        register_pma_entry(make_callocd_memory_pma_entry(PMA_RAM_START,
            m_c.ram.length, m_c.ram.image_filename).set_flags(m_ram_flags));
    }

    // Register ROM
    pma_entry &rom = register_pma_entry(make_callocd_memory_pma_entry(
        PMA_ROM_START, PMA_ROM_LENGTH, m_c.rom.image_filename).set_flags(m_rom_flags));

    // Register all flash drives
    for (const auto &f: m_c.flash_drive) {
        register_pma_entry(make_flash_pma_entry(f));
    }

    // Register HTIF device
    register_pma_entry(make_htif_pma_entry(m_h,
            PMA_HTIF_START, PMA_HTIF_LENGTH));

    // Copy HTIF state to from config to machine
    write_htif_tohost(m_c.htif.tohost);
    write_htif_fromhost(m_c.htif.fromhost);
    // Only command in halt device is command 0 and it is always available
    uint64_t htif_ihalt = static_cast<uint64_t>(true) << HTIF_HALT_HALT;
    write_htif_ihalt(htif_ihalt);
    uint64_t htif_iconsole =
        static_cast<uint64_t>(m_c.htif.console_getchar) << HTIF_CONSOLE_GETCHAR |
        static_cast<uint64_t>(true) << HTIF_CONSOLE_PUTCHAR;
    write_htif_iconsole(htif_iconsole);
    uint64_t htif_iyield =
        static_cast<uint64_t>(m_c.htif.yield_progress) << HTIF_YIELD_PROGRESS |
        static_cast<uint64_t>(m_c.htif.yield_rollup) << HTIF_YIELD_ROLLUP;
    write_htif_iyield(htif_iyield);
    // Resiter CLINT device
    register_pma_entry(make_clint_pma_entry(PMA_CLINT_START, PMA_CLINT_LENGTH));
    // Copy CLINT state to from config to machine
    write_clint_mtimecmp(m_c.clint.mtimecmp);

    // Register shadow device
    register_pma_entry(make_shadow_pma_entry(PMA_SHADOW_START,
            PMA_SHADOW_LENGTH));

    // Add DHD device only if tlength is non-zero...
    if (m_c.dhd.tlength != 0) {
        // ... and also a power of 2...
        if ((m_c.dhd.tlength & (m_c.dhd.tlength-1)) != 0) {
            throw std::invalid_argument{"DHD tlength not a power of 2"};
        }
        // ... and tstart is aligned to that power of 2
        if ((m_c.dhd.tstart & (m_c.dhd.tlength-1)) != 0) {
            throw std::invalid_argument{"DHD tstart not aligned to tlength"};
        }
        // Register associated target range
        if (m_c.dhd.image_filename.empty()) {
            register_pma_entry(make_callocd_memory_pma_entry(
                m_c.dhd.tstart, m_c.dhd.tlength).
                    set_flags(m_rom_flags));
        } else {
            register_pma_entry(make_callocd_memory_pma_entry(
                m_c.dhd.tstart, m_c.dhd.tlength,
                m_c.dhd.image_filename).
                    set_flags(m_rom_flags));
        }
        // Register DHD range itself
        register_pma_entry(make_dhd_pma_entry(PMA_DHD_START, PMA_DHD_LENGTH));
        // Set the DHD source in the state
        m_s.dhd.source = make_dhd_source(r.dhd.source_address);
    }
    // Copy DHD state from config to machine
    write_dhd_tstart(m_c.dhd.tstart);
    write_dhd_tlength(m_c.dhd.tlength);
    write_dhd_dlength(m_c.dhd.dlength);
    write_dhd_hlength(m_c.dhd.hlength);
    for (int i = 0; i < DHD_H_REG_COUNT; i++) {
        write_dhd_h(i, m_c.dhd.h[i]);
    }

    // Initialize PMA extension metadata on ROM
    rom_init(m_c, rom.get_memory().get_host_memory(), PMA_ROM_LENGTH);

    // Clear all TLB entries
    m_s.init_tlb();

    // Add sentinel to PMA vector
    register_pma_entry(make_empty_pma_entry(0, 0));
}

static void load_hash(const std::string &dir, machine::hash_type &h) {
    auto name = dir + "/hash";
    auto fp = unique_fopen(name.c_str(), "rb");
    if (fread(h.data(), 1, h.size(), fp.get()) != h.size()) {
        throw std::runtime_error{"error reading from '" + name + "'"};
    }
}

machine::machine(const std::string &dir, const machine_runtime_config &r):
    machine{machine_config::load(dir), r} {
    hash_type hstored;
    hash_type hrestored;
    load_hash(dir, hstored);
    if (!update_merkle_tree()) {
        throw std::runtime_error{"error updating root hash"};
    }
    m_t.get_root_hash(hrestored);
    if (hstored != hrestored) {
        throw std::runtime_error{"stored and restored hashes do not match"};
    }
}

machine_config machine::get_serialization_config(void) const {
    // Initialize with copy of original config
    machine_config c = m_c;
    // Copy current processor state to config
    for (int i = 1; i < X_REG_COUNT; ++i) {
        c.processor.x[i] = read_x(i);
    }
    c.processor.pc = read_pc();
    c.processor.mvendorid = read_mvendorid();
    c.processor.marchid = read_marchid();
    c.processor.mimpid = read_mimpid();
    c.processor.mcycle = read_mcycle();
    c.processor.minstret = read_minstret();
    c.processor.mstatus = read_mstatus();
    c.processor.mtvec = read_mtvec();
    c.processor.mscratch = read_mscratch();
    c.processor.mepc = read_mepc();
    c.processor.mcause = read_mcause();
    c.processor.mtval = read_mtval();
    c.processor.misa = read_misa();
    c.processor.mie = read_mie();
    c.processor.mip = read_mip();
    c.processor.medeleg = read_medeleg();
    c.processor.mideleg = read_mideleg();
    c.processor.mcounteren = read_mcounteren();
    c.processor.stvec = read_stvec();
    c.processor.sscratch = read_sscratch();
    c.processor.sepc = read_sepc();
    c.processor.scause = read_scause();
    c.processor.stval = read_stval();
    c.processor.satp = read_satp();
    c.processor.scounteren = read_scounteren();
    c.processor.ilrsc = read_ilrsc();
    c.processor.iflags = read_iflags();
    // Copy current CLINT state to config
    c.clint.mtimecmp = read_clint_mtimecmp();
    // Copy current HTIF state to config
    c.htif.tohost = read_htif_tohost();
    c.htif.fromhost = read_htif_fromhost();
    // c.htif.halt = read_htif_ihalt(); // hard-coded to true
    c.htif.console_getchar =
        static_cast<bool>(read_htif_iconsole() & (1 << HTIF_CONSOLE_GETCHAR));
    c.htif.yield_progress =
        static_cast<bool>(read_htif_iyield() & (1 << HTIF_YIELD_PROGRESS));
    c.htif.yield_rollup =
        static_cast<bool>(read_htif_iyield() & (1 << HTIF_YIELD_ROLLUP));
    // Ensure we don't mess with ROM by writing the original bootargs
    // over the potentially modified memory region we serialize
    c.rom.bootargs.clear();
    // Remove image filenames from serialization
    // (they will will be ignored by save and load for security reasons)
    c.ram.image_filename.clear();
    c.rom.image_filename.clear();
    for (auto &f: c.flash_drive) {
        f.image_filename.clear();
    }
    return c;
}

static void store_memory_pma(const pma_entry &pma, const std::string &dir) {
    if (!pma.get_istart_M()) {
        throw std::runtime_error{"attempt to save non-memory PMA"};
    }
    auto name = machine_config::get_image_filename(dir,
        pma.get_start(), pma.get_length());
    auto fp = unique_fopen(name.c_str(), "wb");
    const pma_memory &mem = pma.get_memory();
    if (fwrite(mem.get_host_memory(), 1, pma.get_length(), fp.get()) !=
        pma.get_length()) {
        throw std::runtime_error{"error writing to '" + name + "'"};
    }
}

pma_entry &machine::find_pma_entry(uint64_t paddr, size_t length) {
    return const_cast<pma_entry &>(
        const_cast<const machine *>(this)->find_pma_entry(paddr, length));
}

const pma_entry &machine::find_pma_entry(uint64_t paddr, size_t length) const {
    for (auto &pma: m_s.pmas) {
        // Stop at first empty PMA
        if (pma.get_length() == 0) {
            return pma;
        }
        // Check if data is in range
        if (paddr >= pma.get_start() && pma.get_length() >= length &&
            paddr - pma.get_start() <= pma.get_length() - length) {
            return pma;
        }
    }
    // Last PMA is always the empty range
    return m_s.pmas.back();
}

void machine::store_pmas(const machine_config &c, const std::string &dir) const {
    store_memory_pma(find_pma_entry<uint64_t>(PMA_ROM_START), dir);
    store_memory_pma(find_pma_entry<uint64_t>(PMA_RAM_START), dir);
    // Could iterate over PMAs checking for those with a drive DID
    // but this is easier
    for (const auto &f: c.flash_drive) {
        store_memory_pma(find_pma_entry<uint64_t>(f.start), dir);
    }
}

static void store_hash(const machine::hash_type &h, const std::string &dir) {
    auto name = dir + "/hash";
    auto fp = unique_fopen(name.c_str(), "wb");
    if (fwrite(h.data(), 1, h.size(), fp.get()) != h.size()) {
        throw std::runtime_error{"error writing to '" + name + "'"};
    }
}

void machine::store(const std::string &dir) {
    if (mkdir(dir.c_str(), 0700)) {
        throw std::runtime_error{"error creating directory '" + dir + "'"};
    }
    if (!update_merkle_tree()) {
        throw std::runtime_error{"error updating root hash"};
    }
    hash_type h;
    m_t.get_root_hash(h);
    store_hash(h, dir);
    auto c = get_serialization_config();
    c.store(dir);
    store_pmas(c, dir);
}

machine::~machine() {
#ifdef DUMP_HIST
    fprintf(stderr, "\nInstruction Histogram:\n");
    for (auto v: m_s.insn_hist) {
        fprintf(stderr, "%s: %" PRIu64 "\n", v.first.c_str(), v.second);
    }
#endif
#if DUMP_COUNTERS
#define TLB_HIT_RATIO(s, a, b) (((double)s.stats.b)/(s.stats.a + s.stats.b))
    fprintf(stderr, "\nMachine Counters:\n");
    fprintf(stderr, "inner loops: %" PRIu64 "\n", m_s.stats.inner_loop);
    fprintf(stderr, "outers loops: %" PRIu64 "\n", m_s.stats.outer_loop);
    fprintf(stderr, "supervisor ints: %" PRIu64 "\n", m_s.stats.sv_int);
    fprintf(stderr, "supervisor ex: %" PRIu64 "\n", m_s.stats.sv_ex);
    fprintf(stderr, "machine ints: %" PRIu64 "\n", m_s.stats.m_int);
    fprintf(stderr, "machine ex: %" PRIu64 "\n", m_s.stats.m_ex);
    fprintf(stderr, "atomic mem ops: %" PRIu64 "\n", m_s.stats.atomic_mop);
    fprintf(stderr, "tlb read hit ratio: %.2f\n", TLB_HIT_RATIO(m_s, tlb_rmiss, tlb_rhit));
    fprintf(stderr, "tlb write hit ratio: %.2f\n", TLB_HIT_RATIO(m_s, tlb_wmiss, tlb_whit));
    fprintf(stderr, "tlb code hit ratio: %.2f\n", TLB_HIT_RATIO(m_s, tlb_cmiss, tlb_chit));
    fprintf(stderr, "flush_all: %" PRIu64 "\n", m_s.stats.flush_all);
    fprintf(stderr, "flush_vaddr: %" PRIu64 "\n", m_s.stats.flush_va);
    fprintf(stderr, "fence: %" PRIu64 "\n", m_s.stats.fence);
    fprintf(stderr, "fence.i: %" PRIu64 "\n", m_s.stats.fence_i);
    fprintf(stderr, "fence.vma: %" PRIu64 "\n", m_s.stats.fence_vma);
    fprintf(stderr, "User mode: %" PRIu64 "\n", m_s.stats.priv_level[PRV_U]);
    fprintf(stderr, "Supervisor mode: %" PRIu64 "\n", m_s.stats.priv_level[PRV_S]);
    fprintf(stderr, "Machine mode: %" PRIu64 "\n", m_s.stats.priv_level[PRV_M]);
#endif
}

uint64_t machine::read_x(int i) const {
    return m_s.x[i];
}

uint64_t machine::get_x_address(int i) {
    return PMA_SHADOW_START + shadow_get_x_rel_addr(i);
}

void machine::write_x(int i, uint64_t val) {
    if (i > 0) {
        m_s.x[i] = val;
    }
}

uint64_t machine::read_pc(void) const {
    return m_s.pc;
}

void machine::write_pc(uint64_t val) {
    m_s.pc = val;
}

uint64_t machine::read_mvendorid(void) const {
    return MVENDORID_INIT;
}

uint64_t machine::read_marchid(void) const {
    return MARCHID_INIT;
}

uint64_t machine::read_mimpid(void) const {
    return MIMPID_INIT;
}

uint64_t machine::read_mcycle(void) const {
    return m_s.mcycle;
}

void machine::write_mcycle(uint64_t val) {
    m_s.mcycle = val;
}

uint64_t machine::read_minstret(void) const {
    return m_s.minstret;
}

void machine::write_minstret(uint64_t val) {
    m_s.minstret = val;
}

uint64_t machine::read_mstatus(void) const {
    return m_s.mstatus;
}

void machine::write_mstatus(uint64_t val) {
    m_s.mstatus = val;
}

uint64_t machine::read_mtvec(void) const {
    return m_s.mtvec;
}

void machine::write_mtvec(uint64_t val) {
    m_s.mtvec = val;
}

uint64_t machine::read_mscratch(void) const {
    return m_s.mscratch;
}

void machine::write_mscratch(uint64_t val) {
    m_s.mscratch = val;
}

uint64_t machine::read_mepc(void) const {
    return m_s.mepc;
}

void machine::write_mepc(uint64_t val) {
    m_s.mepc = val;
}

uint64_t machine::read_mcause(void) const {
    return m_s.mcause;
}

void machine::write_mcause(uint64_t val) {
    m_s.mcause = val;
}

uint64_t machine::read_mtval(void) const {
    return m_s.mtval;
}

void machine::write_mtval(uint64_t val) {
    m_s.mtval = val;
}

uint64_t machine::read_misa(void) const {
    return m_s.misa;
}

void machine::write_misa(uint64_t val) {
    m_s.misa = val;
}

uint64_t machine::read_mip(void) const {
    return m_s.mip;
}

void machine::write_mip(uint64_t val) {
    m_s.mip = val;
    m_s.set_brk_from_all();
}

uint64_t machine::read_mie(void) const {
    return m_s.mie;
}

void machine::write_mie(uint64_t val) {
    m_s.mie = val;
    m_s.set_brk_from_all();
}

uint64_t machine::read_medeleg(void) const {
    return m_s.medeleg;
}

void machine::write_medeleg(uint64_t val) {
    m_s.medeleg = val;
}

uint64_t machine::read_mideleg(void) const {
    return m_s.mideleg;
}

void machine::write_mideleg(uint64_t val) {
    m_s.mideleg = val;
}

uint64_t machine::read_mcounteren(void) const {
    return m_s.mcounteren;
}

void machine::write_mcounteren(uint64_t val) {
    m_s.mcounteren = val;
}

uint64_t machine::read_stvec(void) const {
    return m_s.stvec;
}

void machine::write_stvec(uint64_t val) {
    m_s.stvec = val;
}

uint64_t machine::read_sscratch(void) const {
    return m_s.sscratch;
}

void machine::write_sscratch(uint64_t val) {
    m_s.sscratch = val;
}

uint64_t machine::read_sepc(void) const {
    return m_s.sepc;
}

void machine::write_sepc(uint64_t val) {
    m_s.sepc = val;
}

uint64_t machine::read_scause(void) const {
    return m_s.scause;
}

void machine::write_scause(uint64_t val) {
    m_s.scause = val;
}

uint64_t machine::read_stval(void) const {
    return m_s.stval;
}

void machine::write_stval(uint64_t val) {
    m_s.stval = val;
}

uint64_t machine::read_satp(void) const {
    return m_s.satp;
}

void machine::write_satp(uint64_t val) {
    m_s.satp = val;
}

uint64_t machine::read_scounteren(void) const {
    return m_s.scounteren;
}

void machine::write_scounteren(uint64_t val) {
    m_s.scounteren = val;
}

uint64_t machine::read_ilrsc(void) const {
    return m_s.ilrsc;
}

void machine::write_ilrsc(uint64_t val) {
    m_s.ilrsc = val;
}

uint64_t machine::read_iflags(void) const {
    return m_s.read_iflags();
}

void machine::write_iflags(uint64_t val) {
    m_s.write_iflags(val);
    m_s.set_brk_from_all();
}

uint64_t machine::read_htif_tohost(void) const {
    return m_s.htif.tohost;
}

uint64_t machine::read_htif_tohost_dev(void) const {
    return HTIF_DEV_FIELD(m_s.htif.tohost);
}

uint64_t machine::read_htif_tohost_cmd(void) const {
    return HTIF_CMD_FIELD(m_s.htif.tohost);
}

uint64_t machine::read_htif_tohost_data(void) const {
    return HTIF_DATA_FIELD(m_s.htif.tohost);
}

void machine::write_htif_tohost(uint64_t val) {
    m_s.htif.tohost = val;
}

uint64_t machine::read_htif_fromhost(void) const {
    return m_s.htif.fromhost;
}

void machine::write_htif_fromhost(uint64_t val) {
    m_s.htif.fromhost = val;
}

void machine::write_htif_fromhost_data(uint64_t val) {
    m_s.htif.fromhost = HTIF_REPLACE_DATA(m_s.htif.fromhost, val);
}

uint64_t machine::read_htif_ihalt(void) const {
    return m_s.htif.ihalt;
}

void machine::write_htif_ihalt(uint64_t val) {
    m_s.htif.ihalt = val;
}

uint64_t machine::read_htif_iconsole(void) const {
    return m_s.htif.iconsole;
}

void machine::write_htif_iconsole(uint64_t val) {
    m_s.htif.iconsole = val;
}

uint64_t machine::read_htif_iyield(void) const {
    return m_s.htif.iyield;
}

void machine::write_htif_iyield(uint64_t val) {
    m_s.htif.iyield = val;
}

uint64_t machine::read_clint_mtimecmp(void) const {
    return m_s.clint.mtimecmp;
}

void machine::write_clint_mtimecmp(uint64_t val) {
    m_s.clint.mtimecmp = val;
}

uint64_t machine::read_dhd_tstart(void) const {
    return m_s.dhd.tstart;
}

void machine::write_dhd_tstart(uint64_t val) {
    m_s.dhd.tstart = val;
}

uint64_t machine::read_dhd_tlength(void) const {
    return m_s.dhd.tlength;
}

void machine::write_dhd_tlength(uint64_t val) {
    m_s.dhd.tlength = val;
}

uint64_t machine::read_dhd_dlength(void) const {
    return m_s.dhd.dlength;
}

void machine::write_dhd_dlength(uint64_t val) {
    m_s.dhd.dlength = val;
}

uint64_t machine::read_dhd_hlength(void) const {
    return m_s.dhd.hlength;
}

void machine::write_dhd_hlength(uint64_t val) {
    m_s.dhd.hlength = val;
}

uint64_t machine::read_dhd_h(int i) const {
    return m_s.dhd.h[i];
}

void machine::write_dhd_h(int i, uint64_t val) {
    m_s.dhd.h[i] = val;
}

uint64_t machine::get_dhd_h_address(int i) {
    return PMA_DHD_START + dhd_get_h_rel_addr(i);
}

uint64_t machine::read_csr(csr r) const {
    switch (r) {
        case csr::pc: return read_pc();
        case csr::mvendorid: return read_mvendorid();
        case csr::marchid: return read_marchid();
        case csr::mimpid: return read_mimpid();
        case csr::mcycle: return read_mcycle();
        case csr::minstret: return read_minstret();
        case csr::mstatus: return read_mstatus();
        case csr::mtvec: return read_mtvec();
        case csr::mscratch: return read_mscratch();
        case csr::mepc: return read_mepc();
        case csr::mcause: return read_mcause();
        case csr::mtval: return read_mtval();
        case csr::misa: return read_misa();
        case csr::mie: return read_mie();
        case csr::mip: return read_mip();
        case csr::medeleg: return read_medeleg();
        case csr::mideleg: return read_mideleg();
        case csr::mcounteren: return read_mcounteren();
        case csr::stvec: return read_stvec();
        case csr::sscratch: return read_sscratch();
        case csr::sepc: return read_sepc();
        case csr::scause: return read_scause();
        case csr::stval: return read_stval();
        case csr::satp: return read_satp();
        case csr::scounteren: return read_scounteren();
        case csr::ilrsc: return read_ilrsc();
        case csr::iflags: return read_iflags();
        case csr::clint_mtimecmp: return read_clint_mtimecmp();
        case csr::htif_tohost: return read_htif_tohost();
        case csr::htif_fromhost: return read_htif_fromhost();
        case csr::htif_ihalt: return read_htif_ihalt();
        case csr::htif_iconsole: return read_htif_iconsole();
        case csr::htif_iyield: return read_htif_iyield();
        case csr::dhd_tstart: return read_dhd_tstart();
        case csr::dhd_tlength: return read_dhd_tlength();
        case csr::dhd_dlength: return read_dhd_dlength();
        case csr::dhd_hlength: return read_dhd_hlength();
        default:
            throw std::invalid_argument{"unknown CSR"};
            return 0; // never reached
    }
}

void machine::write_csr(csr w, uint64_t val) {
    switch (w) {
        case csr::pc: return write_pc(val);
        case csr::mcycle: return write_mcycle(val);
        case csr::minstret: return write_minstret(val);
        case csr::mstatus: return write_mstatus(val);
        case csr::mtvec: return write_mtvec(val);
        case csr::mscratch: return write_mscratch(val);
        case csr::mepc: return write_mepc(val);
        case csr::mcause: return write_mcause(val);
        case csr::mtval: return write_mtval(val);
        case csr::misa: return write_misa(val);
        case csr::mie: return write_mie(val);
        case csr::mip: return write_mip(val);
        case csr::medeleg: return write_medeleg(val);
        case csr::mideleg: return write_mideleg(val);
        case csr::mcounteren: return write_mcounteren(val);
        case csr::stvec: return write_stvec(val);
        case csr::sscratch: return write_sscratch(val);
        case csr::sepc: return write_sepc(val);
        case csr::scause: return write_scause(val);
        case csr::stval: return write_stval(val);
        case csr::satp: return write_satp(val);
        case csr::scounteren: return write_scounteren(val);
        case csr::ilrsc: return write_ilrsc(val);
        case csr::iflags: return write_iflags(val);
        case csr::clint_mtimecmp: return write_clint_mtimecmp(val);
        case csr::htif_tohost: return write_htif_tohost(val);
        case csr::htif_fromhost: return write_htif_fromhost(val);
        case csr::dhd_tstart: return write_dhd_tstart(val);
        case csr::dhd_tlength: return write_dhd_tlength(val);
        case csr::dhd_dlength: return write_dhd_dlength(val);
        case csr::dhd_hlength: return write_dhd_hlength(val);
        case csr::htif_ihalt: return write_htif_ihalt(val);
        case csr::htif_iconsole: return write_htif_iconsole(val);
        case csr::htif_iyield: return write_htif_iyield(val);
        case csr::mvendorid: [[fallthrough]];
        case csr::marchid: [[fallthrough]];
        case csr::mimpid:
            throw std::invalid_argument{"CSR is read-only"};
        default:
            throw std::invalid_argument{"unknown CSR"};
    }
}

/// \brief Returns the address of a CSR in the shadow
/// \param w The desired CSR
/// \return Address of the specified CSR in the shadow
static inline uint64_t get_csr_addr(shadow_csr w) {
    return cartesi::PMA_SHADOW_START + shadow_get_csr_rel_addr(w);
}

/// \brief Returns the address of a CSR in HTIF
/// \param w The desired CSR
/// \return Address of the specified CSR in HTIF
static inline uint64_t htif_get_csr_addr(htif::csr r) {
    return PMA_HTIF_START + htif::get_csr_rel_addr(r);
}

/// \brief Returns the address of a CSR in DHD
/// \param w The desired CSR
/// \return Address of the specified CSR in DHD
static inline uint64_t dhd_get_csr_addr(dhd_csr r) {
    return PMA_DHD_START + dhd_get_csr_rel_addr(r);
}

/// \brief Returns the address of a CSR in CLINT
/// \param w The desired CSR
/// \return Address of the specified CSR in CLINT
static inline uint64_t clint_get_csr_addr(clint_csr r) {
    return PMA_CLINT_START + clint_get_csr_rel_addr(r);
}

uint64_t machine::get_csr_address(csr w) {
    switch (w) {
        case csr::pc: return get_csr_addr(shadow_csr::pc);
        case csr::mvendorid: return get_csr_addr(shadow_csr::mvendorid);
        case csr::marchid: return get_csr_addr(shadow_csr::marchid);
        case csr::mimpid: return get_csr_addr(shadow_csr::mimpid);
        case csr::mcycle: return get_csr_addr(shadow_csr::mcycle);
        case csr::minstret: return get_csr_addr(shadow_csr::minstret);
        case csr::mstatus: return get_csr_addr(shadow_csr::mstatus);
        case csr::mtvec: return get_csr_addr(shadow_csr::mtvec);
        case csr::mscratch: return get_csr_addr(shadow_csr::mscratch);
        case csr::mepc: return get_csr_addr(shadow_csr::mepc);
        case csr::mcause: return get_csr_addr(shadow_csr::mcause);
        case csr::mtval: return get_csr_addr(shadow_csr::mtval);
        case csr::misa: return get_csr_addr(shadow_csr::misa);
        case csr::mie: return get_csr_addr(shadow_csr::mie);
        case csr::mip: return get_csr_addr(shadow_csr::mip);
        case csr::medeleg: return get_csr_addr(shadow_csr::medeleg);
        case csr::mideleg: return get_csr_addr(shadow_csr::mideleg);
        case csr::mcounteren: return get_csr_addr(shadow_csr::mcounteren);
        case csr::stvec: return get_csr_addr(shadow_csr::stvec);
        case csr::sscratch: return get_csr_addr(shadow_csr::sscratch);
        case csr::sepc: return get_csr_addr(shadow_csr::sepc);
        case csr::scause: return get_csr_addr(shadow_csr::scause);
        case csr::stval: return get_csr_addr(shadow_csr::stval);
        case csr::satp: return get_csr_addr(shadow_csr::satp);
        case csr::scounteren: return get_csr_addr(shadow_csr::scounteren);
        case csr::ilrsc: return get_csr_addr(shadow_csr::ilrsc);
        case csr::iflags: return get_csr_addr(shadow_csr::iflags);
        case csr::htif_tohost: return htif_get_csr_addr(htif::csr::tohost);
        case csr::htif_fromhost: return htif_get_csr_addr(htif::csr::fromhost);
        case csr::htif_ihalt: return htif_get_csr_addr(htif::csr::ihalt);
        case csr::htif_iconsole: return htif_get_csr_addr(htif::csr::iconsole);
        case csr::htif_iyield: return htif_get_csr_addr(htif::csr::iyield);
        case csr::clint_mtimecmp: return clint_get_csr_addr(clint_csr::mtimecmp);
        case csr::dhd_tstart: return dhd_get_csr_addr(dhd_csr::tstart);
        case csr::dhd_tlength: return dhd_get_csr_addr(dhd_csr::tlength);
        case csr::dhd_dlength: return dhd_get_csr_addr(dhd_csr::dlength);
        case csr::dhd_hlength: return dhd_get_csr_addr(dhd_csr::hlength);
        default:
            throw std::invalid_argument{"unknown CSR"};
    }
}

void machine::set_mip(uint32_t mask) {
    m_s.mip |= mask;
    m_s.or_brk_with_mip_mie();
}

void machine::reset_mip(uint32_t mask) {
    m_s.mip &= ~mask;
    m_s.set_brk_from_all();
}

uint8_t machine::read_iflags_PRV(void) const {
    return m_s.iflags.PRV;
}

bool machine::read_iflags_Y(void) const {
    return m_s.iflags.Y;
}

void machine::reset_iflags_Y(void) {
    m_s.iflags.Y = false;
}

void machine::set_iflags_Y(void) {
    m_s.iflags.Y = true;
    m_s.brk = true;
}

bool machine::read_iflags_H(void) const {
    return m_s.iflags.H;
}

void machine::set_iflags_H(void) {
    m_s.iflags.H = true;
    m_s.brk = true;
}

static double now(void) {
    using namespace std::chrono;
    return static_cast<double>(
        duration_cast<microseconds>(
            high_resolution_clock::now().time_since_epoch()).count())*1.e-6;
}

bool machine::verify_dirty_page_maps(void) const {
    // double begin = now();
    static_assert(PMA_PAGE_SIZE == machine_merkle_tree::get_page_size(), "PMA and machine_merkle_tree page sizes must match");
    machine_merkle_tree::hasher_type h;
    auto scratch = unique_calloc<unsigned char>(PMA_PAGE_SIZE);
    if (!scratch) {
        return false;
    }
    bool broken = false;
    if constexpr(!avoid_tlb<machine_state>::value) {
        // Go over the write TLB and mark as dirty all pages currently there
        for (int i = 0; i < TLB_SIZE; ++i) {
            auto &write = m_s.tlb_write[i];
            if (write.vaddr_page != UINT64_C(-1)) {
                write.pma->mark_dirty_page(write.paddr_page -
                    write.pma->get_start());
            }
        }
    }
    // Now go over all memory PMAs verifying that all dirty pages are marked
    for (auto &pma: m_s.pmas) {
        auto peek = pma.get_peek();
        for (uint64_t page_start_in_range = 0; page_start_in_range < pma.get_length(); page_start_in_range += PMA_PAGE_SIZE) {
            uint64_t page_address = pma.get_start() + page_start_in_range;
            if (pma.get_istart_M()) {
                const unsigned char *page_data = nullptr;
                peek(pma, *this, page_start_in_range, &page_data, scratch.get());
                hash_type stored;
                hash_type real;
                m_t.get_page_node_hash(page_address, stored);
                m_t.get_page_node_hash(h, page_data, real);
                bool marked_dirty = pma.is_page_marked_dirty(page_start_in_range);
                bool is_dirty = (real != stored);
                if (is_dirty && !marked_dirty) {
                    broken = true;
                    std::cerr << std::setfill('0') << std::setw(8) << std::hex << page_address << " should have been dirty\n";
                    std::cerr << "  expected " << stored << '\n';
                    std::cerr << "  got " << real << '\n';
                    break;
                }
            } else if (pma.get_istart_IO()) {
                if (!pma.is_page_marked_dirty(page_start_in_range)) {
                    broken = true;
                    std::cerr << std::setfill('0') << std::setw(8) << std::hex << page_address << " should have been dirty\n";
                    std::cerr << "  all pages in IO PMAs must be set to dirty\n";
                    break;
                }
            }
        }
    }
    return !broken;
}

dhd_data machine::dehash(const unsigned char* hash, uint64_t hlength,
    uint64_t &dlength) {
    return m_s.dehash(hash, hlength, dlength);
}

static uint64_t get_task_concurrency(uint64_t value) {
    uint64_t concurrency = value > 0 ? value : std::max(std::thread::hardware_concurrency(), 1U);
    return std::min(concurrency, static_cast<uint64_t>(THREADS_MAX));
}

bool machine::update_merkle_tree(void) {
    machine_merkle_tree::hasher_type gh;
    //double begin = now();
    static_assert(PMA_PAGE_SIZE == machine_merkle_tree::get_page_size(), "PMA and machine_merkle_tree page sizes must match");
    if constexpr(!avoid_tlb<machine_state>::value) {
        // Go over the write TLB and mark as dirty all pages currently there
        for (int i = 0; i < TLB_SIZE; ++i) {
            auto &write = m_s.tlb_write[i];
            if (write.vaddr_page != UINT64_C(-1)) {
                write.pma->mark_dirty_page(write.paddr_page -
                    write.pma->get_start());
            }
        }
    }
    // Now go over all PMAs and updating the Merkle tree
    m_t.begin_update();
    for (auto &pma: m_s.pmas) {
        auto peek = pma.get_peek();
        // Each PMA has a number of pages
        auto pages_in_range = (pma.get_length()+PMA_PAGE_SIZE-1)/PMA_PAGE_SIZE;
        // For each PMA, we launch as many threads (n) as defined on concurrency
        // runtime config or as the hardware supports.
        const uint64_t n = get_task_concurrency(m_r.concurrency.update_merkle_tree);
        // The update_page_node_hash function in the machine_merkle_tree is not thread
        // safe, so we protect it with a mutex
        std::mutex updatex;
        // Each thread is launched as a future, whose value tells if the
        // computation succeeded
        std::vector<std::future<bool>> futures;
        futures.reserve(n);
        for (uint64_t j = 0; j < n; ++j) {
            futures.emplace_back(std::async(std::launch::async, [&](int j) -> bool {
                auto scratch = unique_calloc<unsigned char>(PMA_PAGE_SIZE);
                if (!scratch) {
                    return false;
                }
                machine_merkle_tree::hasher_type h;
                // Thread j is responsible for page i if i % n == j.
                for (uint64_t i = j; i < pages_in_range; i+=n) {
                    uint64_t page_start_in_range = i*PMA_PAGE_SIZE;
                    uint64_t page_address = pma.get_start() + page_start_in_range;
                    const unsigned char *page_data = nullptr;
                    // Skip any clean pages
                    if (!pma.is_page_marked_dirty(page_start_in_range)) {
                        continue;
                    }
                    // If the peek failed, or if it returned a page for update but
                    // we failed updating it, the entire process failed
                    if (!peek(pma, *this, page_start_in_range, &page_data, scratch.get())) {
                        return false;
                    }
                    if (page_data) {
                        hash_type hash;
                        m_t.get_page_node_hash(h, page_data, hash);
                        {
                            std::lock_guard<std::mutex> lock(updatex);
                            if (!m_t.update_page_node_hash(page_address, hash)) {
                                return false;
                            }
                        }
                    }
                }
                return true;
            }, j));
        }
        // Check if any thread failed
        bool succeeded = true;
        for (auto &f: futures) {
            succeeded = succeeded && f.get();
        }
        // If so, we also failed
        if (!succeeded) {
            m_t.end_update(gh);
            return false;
        }
        // Otherwise, mark all pages in PMA as clean and move on to next
        pma.mark_pages_clean();
    }
    //std::cerr << "page updates done in " << now()-begin << "s\n";
    //begin = now();
    bool ret = m_t.end_update(gh);
    //std::cerr << "inner tree updates done in " << now()-begin << "s\n";
    return ret;
}

bool machine::update_merkle_tree_page(uint64_t address) {
    static_assert(PMA_PAGE_SIZE == machine_merkle_tree::get_page_size(), "PMA and machine_merkle_tree page sizes must match");
    // Align address to begining of page
    address &= ~(PMA_PAGE_SIZE-1);
    pma_entry &pma = find_pma_entry<uint64_t>(address);
    uint64_t page_start_in_range = address - pma.get_start();
    machine_merkle_tree::hasher_type h;
    auto scratch = unique_calloc<unsigned char>(PMA_PAGE_SIZE);
    if (!scratch) {
        return false;
    }
    m_t.begin_update();
    const unsigned char *page_data = nullptr;
    auto peek = pma.get_peek();
    if (!peek(pma, *this, page_start_in_range, &page_data, scratch.get())) {
        m_t.end_update(h);
        return false;
    }
    if (page_data) {
        uint64_t page_address = pma.get_start() + page_start_in_range;
        hash_type hash;
        m_t.get_page_node_hash(h, page_data, hash);
        if (!m_t.update_page_node_hash(page_address, hash)) {
            m_t.end_update(h);
            return false;
        }
    }
    pma.mark_clean_page(page_start_in_range);
    return m_t.end_update(h);
}

const boost::container::static_vector<pma_entry, PMA_MAX> &machine::get_pmas(void) const {
    return m_s.pmas;
}

void machine::dump_pmas(void) const {
    auto scratch = unique_calloc<unsigned char>(PMA_PAGE_SIZE);
    for (auto &pma: m_s.pmas) {
        if (pma.get_length() == 0) {
            break;
        }
        char filename[256];
        sprintf(filename, "%016" PRIx64 "--%016" PRIx64 ".bin", pma.get_start(), pma.get_length());
        auto fp = unique_fopen(filename, "wb");
        for (uint64_t page_start_in_range = 0; page_start_in_range < pma.get_length(); page_start_in_range += PMA_PAGE_SIZE) {
            const unsigned char *page_data = nullptr;
            auto peek = pma.get_peek();
            if (!peek(pma, *this, page_start_in_range, &page_data, scratch.get())) {
                throw std::runtime_error{"peek failed"};
            } else if (page_data && fwrite(page_data, 1, PMA_PAGE_SIZE, fp.get()) != PMA_PAGE_SIZE) {
                throw std::system_error{errno, std::generic_category(),
                    "error writing to '"s + filename + "'"s};
            }
        }
    }
}

void machine::get_root_hash(hash_type &hash) const {
    m_t.get_root_hash(hash);
}

bool machine::verify_merkle_tree(void) const {
    return m_t.verify_tree();
}

machine_merkle_tree::proof_type machine::get_proof(uint64_t address,
    int log2_size) const {
    static_assert(PMA_PAGE_SIZE == machine_merkle_tree::get_page_size(), "PMA and machine_merkle_tree page sizes must match");
    // Check for valid target node size
    if (log2_size > machine_merkle_tree::get_log2_root_size() ||
        log2_size < machine_merkle_tree::get_log2_word_size()) {
        throw std::invalid_argument{"invalid log2_size"};
    }
    // Check target address alignment
    if (address & ((~UINT64_C(0)) >> (64-log2_size))) {
        throw std::invalid_argument{"address not aligned to log2_size"};
    }
    // If proof concerns range smaller than a page, we may need to rebuild part
    // of the proof from the contents of a page inside some PMA range.
    // PMA range starts and lengths are multiple of the page size, which is a
    // power of 2.
    // The size of the desired range is smaller than the page size, but its
    // size is a power of 2, and it is aligned to its size.
    // Therefore, it is is either entirely inside a PMA range,
    // or entirely outside it.
    if (log2_size < machine_merkle_tree::get_log2_page_size()) {
        uint64_t length = UINT64_C(1) << log2_size;
        const pma_entry &pma = find_pma_entry(address, length);
        auto scratch = unique_calloc<unsigned char>(PMA_PAGE_SIZE);
        const unsigned char *page_data = nullptr;
        // If the PMA range is empty, we know the desired range is
        // entirely outside of any non-pristine PMA.
        // Therefore, the entire page where it lies is also pristine
        // Otherwise, the entire desired range is inside it.
        if (!pma.get_istart_E()) {
            uint64_t page_start_in_range = (address - pma.get_start()) & (~(PMA_PAGE_SIZE-1));
            auto peek = pma.get_peek();
            if (!peek(pma, *this, page_start_in_range, &page_data, scratch.get())) {
                throw std::runtime_error{"PMA peek failed"};
            }
        }
        return m_t.get_proof(address, log2_size, page_data);
    // If proof concerns range bigger than a page, we already have its hash
    // stored in the tree itself
    } else {
        return m_t.get_proof(address, log2_size, nullptr);
    }
}

void machine::read_memory(uint64_t address, unsigned char *data,
    uint64_t length) const {
    const pma_entry &pma = find_pma_entry(address, length);
    if (!pma.get_istart_M() || pma.get_istart_E()) {
        throw std::invalid_argument{"address range not entirely in memory PMA"};
    }
    memcpy(data, pma.get_memory().get_host_memory()+(address-pma.get_start()),
            length);
}

void machine::write_memory(uint64_t address, const unsigned char *data,
    size_t length) {
    pma_entry &pma = find_pma_entry(address, length);
    if (!pma.get_istart_M() || pma.get_istart_E()) {
        throw std::invalid_argument{"address range not entirely in memory PMA"};
    }
    constexpr const auto log2_page_size = PMA_constants::PMA_PAGE_SIZE_LOG2;
    uint64_t page_in_range = ((address - pma.get_start()) >> log2_page_size)
        << log2_page_size;
    constexpr const auto page_size = PMA_constants::PMA_PAGE_SIZE;
    auto npages = (length+page_size-1)/page_size;
    for (decltype(npages) i = 0; i < npages; ++i) {
        pma.mark_dirty_page(page_in_range);
        page_in_range += page_size;
    }
    memcpy(pma.get_memory().get_host_memory()+(address-pma.get_start()), data,
            length);
}

bool machine::read_word(uint64_t word_address, uint64_t &word_value) const {
    // Make sure address is aligned
    if (word_address & (PMA_WORD_SIZE-1)) {
        return false;
    }
    const pma_entry &pma = find_pma_entry<uint64_t>(word_address);
    // ??D We should split peek into peek_word and peek_page
    // for performance. On the other hand, this function
    // will almost never be used, so one wonders if it is worth it...
    auto scratch = unique_calloc<unsigned char>(PMA_PAGE_SIZE);
    if (!scratch) {
        return false;
    }
    const unsigned char *page_data = nullptr;
    uint64_t page_start_in_range = (word_address - pma.get_start()) & (~(PMA_PAGE_SIZE-1));
    auto peek = pma.get_peek();
    if (!peek(pma, *this, page_start_in_range, &page_data, scratch.get())) {
        return false;
    }
    // If peek returns a page, read from it
    if (page_data) {
        uint64_t word_start_in_range = (word_address - pma.get_start()) & (PMA_PAGE_SIZE-1);
        word_value = aliased_aligned_read<uint64_t>(page_data +
            word_start_in_range);
        return true;
    // Otherwise, page is always pristine
    } else {
        word_value = 0;
        return true;
    }
}

void machine::run_inner_loop(uint64_t mcycle_end) {
    // Call interpret with a non-logging state access object
    state_access a(*this);
    interpret(a, mcycle_end);
}

static uint64_t saturate_next_mcycle(uint64_t mcycle) {
    return (mcycle < UINT64_MAX) ? mcycle + 1 : UINT64_MAX;
}

static uint64_t get_next_mcycle_from_log(const access_log &log) {
    const auto& first_access = log.get_accesses().front();
    auto mcycle_address = PMA_SHADOW_START +
        shadow_get_csr_rel_addr(shadow_csr::mcycle);

    // The first access should always be a read to mcycle
    if (first_access.get_type() != access_type::read ||
        first_access.get_address() != mcycle_address) {
        throw std::invalid_argument{"invalid access log"};
    }

    uint64_t mcycle = get_word_access_data(first_access.get_read());
    return saturate_next_mcycle(mcycle);
}

void machine::verify_access_log(const access_log &log,
    const machine_runtime_config &r, bool one_based) {
    // There must be at least one access in log
    if (log.get_accesses().empty()) {
        throw std::invalid_argument{"too few accesses in log"};
    }
    step_state_access a(log, log.get_log_type().has_proofs(),
        make_dhd_source(r.dhd.source_address), one_based);
    uint64_t next_mcycle = get_next_mcycle_from_log(log);
    interpret(a, next_mcycle);
    a.finish();
}

machine_config machine::get_default_config(void) {
    return machine_config{};
}

void machine::verify_state_transition(const hash_type &root_hash_before,
    const access_log &log, const hash_type &root_hash_after,
    const machine_runtime_config &r, bool one_based) {

    // We need proofs in order to verify the state transition
    if (!log.get_log_type().has_proofs()) {
        throw std::invalid_argument{"log has no proofs"};
    }
    // There must be at least one access in log
    if (log.get_accesses().empty()) {
        throw std::invalid_argument{"too few accesses in log"};
    }
    // It must contain proofs
    if (!log.get_accesses().front().get_proof().has_value()) {
        throw std::invalid_argument{"access has no proof"};
    }
    // Make sure the access log starts from the same root hash as the state
    if (log.get_accesses().front().get_proof().value().get_root_hash() !=
        root_hash_before) {
        throw std::invalid_argument{"mismatch in root hash before step"};
    }
    // Verify all intermediate state transitions
    step_state_access a(log, true /* verify proofs! */,
        make_dhd_source(r.dhd.source_address), one_based);
    uint64_t next_mcycle = get_next_mcycle_from_log(log);
    interpret(a, next_mcycle);
    a.finish();
    // Make sure the access log ends at the same root hash as the state
    hash_type obtained_root_hash;
    a.get_root_hash(obtained_root_hash);
    if (obtained_root_hash != root_hash_after) {
        throw std::invalid_argument{"mismatch in root hash after step"};
    }
}

access_log machine::step(const access_log::type &log_type, bool one_based) {
    hash_type root_hash_before;
    if (log_type.has_proofs()) {
        update_merkle_tree();
        get_root_hash(root_hash_before);
    }
    // Call interpret with a logged state access object
    logged_state_access a(*this, log_type);
    a.push_bracket(bracket_type::begin, "step");
    uint64_t next_mcycle = saturate_next_mcycle(read_mcycle());
    interpret(a, next_mcycle);
    a.push_bracket(bracket_type::end, "step");
    // Verify access log before returning
    if (log_type.has_proofs()) {
        hash_type root_hash_after;
        update_merkle_tree();
        get_root_hash(root_hash_after);
        verify_state_transition(root_hash_before, *a.get_log(),
            root_hash_after, m_r, one_based);
    } else {
        verify_access_log(*a.get_log(), m_r, one_based);
    }
    return std::move(*a.get_log());
}

void machine::run(uint64_t mcycle_end) {
    // The interpreter loop inside this function is not required by
    // specification.  However, this loop is an optimization to reduce
    // the number of calls to machine::run, which can be expensive in
    // some bindings such as gRPC.
    while (read_mcycle() < mcycle_end && !read_iflags_H() && !read_iflags_Y()) {
        run_inner_loop(mcycle_end);
        // Perform interact with htif after every timer interrupt
        if (rtc_is_tick(read_mcycle())) {
            interact();
        }
    }
}

} // namespace cartesi
