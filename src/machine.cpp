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

/// \brief Obtain PMA entry that covers a given physical memory region
/// \param s Pointer to machine state.
/// \param paddr Start of physical memory region.
/// \param length Length of physical memory region.
/// \returns Corresponding entry if found, or a sentinel entry
/// for an empty range.
static inline pma_entry &naked_find_pma_entry(machine_state &s, uint64_t paddr,
    size_t length) {
    for (auto &pma: s.pmas) {
        // Stop at first empty PMA
        if (pma.get_length() == 0)
            return pma;
        // Check if data is in range
        if (paddr >= pma.get_start() && pma.get_length() >= length &&
            paddr - pma.get_start() <= pma.get_length() - length) {
            return pma;
        }
    }
    // Last PMA is always the empty range
    return s.pmas.back();
}

static inline const pma_entry &naked_find_pma_entry(const machine_state &s,
    uint64_t paddr, size_t length) {
    return const_cast<const pma_entry &>(naked_find_pma_entry(
        const_cast<machine_state &>(s), paddr, length));
}

/// \brief Obtain PMA entry covering a physical memory word
/// \param s Pointer to machine state.
/// \param paddr Target physical address.
/// \returns Corresponding entry if found, or a sentinel entry
/// for an empty range.
/// \tparam T Type of word.
template <typename T>
static inline pma_entry &naked_find_pma_entry(machine_state &s, uint64_t paddr) {
    return naked_find_pma_entry(s, paddr, sizeof(T));
}

template <typename T>
static inline const pma_entry &naked_find_pma_entry(const machine_state &s, uint64_t paddr) {
    return const_cast<const pma_entry &>(naked_find_pma_entry<T>(
        const_cast<machine_state &>(s), paddr));
}

pma_entry &machine::register_pma_entry(pma_entry &&pma) {
    if (m_s.pmas.capacity() <= m_s.pmas.size())
        throw std::runtime_error{"too many PMAs"};
    auto start = pma.get_start();
    if ((start & (PMA_PAGE_SIZE-1)) != 0)
        throw std::invalid_argument{"PMA start must be aligned to page boundary"};
    auto length = pma.get_length();
    if ((length & (PMA_PAGE_SIZE-1)) != 0)
        throw std::invalid_argument{"PMA length must be multiple of page size"};
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

void machine::interact(void) {
    m_h.interact();
}

machine::machine(const machine_config &c):
    m_s{},
    m_t{},
    m_h{c.htif},
    m_c{c} {

    // Check compatibility
    if (c.processor.marchid != MARCHID) {
        throw std::invalid_argument{"marchid mismatch."};
    }

    if (c.processor.mimpid != MIMPID) {
        throw std::invalid_argument{"mimpid mismatch."};
    }

    if (c.processor.mvendorid != MVENDORID) {
        throw std::invalid_argument{"mvendorid mismatch."};
    }

    // General purpose registers
    for (int i = 1; i < 32; i++) {
        write_x(i, c.processor.x[i]);
    }

    write_pc(c.processor.pc);
    write_mcycle(c.processor.mcycle);
    write_minstret(c.processor.minstret);
    write_mstatus(c.processor.mstatus);
    write_mtvec(c.processor.mtvec);
    write_mscratch(c.processor.mscratch);
    write_mepc(c.processor.mepc);
    write_mcause(c.processor.mcause);
    write_mtval(c.processor.mtval);
    write_misa(c.processor.misa);
    write_mie(c.processor.mie);
    write_mip(c.processor.mip);
    write_medeleg(c.processor.medeleg);
    write_mideleg(c.processor.mideleg);
    write_mcounteren(c.processor.mcounteren);
    write_stvec(c.processor.stvec);
    write_sscratch(c.processor.sscratch);
    write_sepc(c.processor.sepc);
    write_scause(c.processor.scause);
    write_stval(c.processor.stval);
    write_satp(c.processor.satp);
    write_scounteren(c.processor.scounteren);
    write_ilrsc(c.processor.ilrsc);
    write_iflags(c.processor.iflags);

    if (c.rom.backing.empty())
        throw std::invalid_argument{"ROM backing is undefined"};

    // Register RAM
    if (c.ram.backing.empty()) {
        register_pma_entry(make_callocd_memory_pma_entry(PMA_RAM_START,
            c.ram.length).set_flags(m_ram_flags));
    } else {
        register_pma_entry(make_callocd_memory_pma_entry(PMA_RAM_START,
            c.ram.length, c.ram.backing).set_flags(m_ram_flags));
    }

    // Register ROM
    pma_entry &rom = register_pma_entry(make_callocd_memory_pma_entry(
        PMA_ROM_START, PMA_ROM_LENGTH, c.rom.backing).set_flags(m_rom_flags));

    // Register all flash drives
    for (const auto &f: c.flash) {
        // Flash drive with no backing behaves just like memory, but with
        // different flags
        if (f.backing.empty()) {
            register_pma_entry(make_callocd_memory_pma_entry(f.start,
                f.length).set_flags(m_flash_flags));
        } else {
            register_pma_entry(make_mmapd_memory_pma_entry(f.start,
                f.length, f.backing, f.shared).set_flags(m_flash_flags));
        }
    }

    // Register HTIF device
    register_pma_entry(make_htif_pma_entry(m_h,
            PMA_HTIF_START, PMA_HTIF_LENGTH));

    // Copy HTIF state to from config to machine
    write_htif_tohost(c.htif.tohost);
    write_htif_fromhost(c.htif.fromhost);

    // Resiter CLINT device
    register_pma_entry(make_clint_pma_entry(PMA_CLINT_START, PMA_CLINT_LENGTH));
    // Copy CLINT state to from config to machine
    write_clint_mtimecmp(c.clint.mtimecmp);

    // Register shadow device
    register_pma_entry(make_shadow_pma_entry(PMA_SHADOW_START, PMA_SHADOW_LENGTH));

    // Initialize PMA extension metadata on ROM
    rom_init(c, rom.get_memory().get_host_memory(), PMA_ROM_LENGTH);

    // Clear all TLB entries
    m_s.init_tlb();

    // Add sentinel to PMA vector
    register_pma_entry(make_empty_pma_entry(0, 0));
}

static void load_hash(const std::string &dir, merkle_tree::hash_type &h) {
    auto name = dir + "/hash";
    auto fp = unique_fopen(name.c_str(), "rb");
    if (fread(h.data(), 1, h.size(), fp.get()) != h.size()) {
        throw std::runtime_error{"error reading from '" + name + "'"};
    }
}

machine::machine(const std::string &dir):
    machine{ machine_config::load(dir) } {
    merkle_tree::hash_type hstored, hrestored;
    load_hash(dir, hstored);
    if (!update_merkle_tree() || !get_merkle_tree().get_root_hash(hrestored)) {
        throw std::runtime_error{"error updating root hash"};
    }
    if (hstored != hrestored) {
        throw std::runtime_error{"stored and restored hashes do not match"};
    }
}

machine_config machine::serialization_config(void) const {
    // Initialize with copy of original config
    machine_config c = m_c;
    // Copy current processor state to config
    for (int i = 1; i < 32; ++i) {
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
    // Ensure we don't mess with ROM by writing the original bootargs
    // over the potentially modified memory region we serialize
    c.rom.bootargs.clear();
    // Remove backing names from serialization
    // (they will will be ignored by save and load for security reasons)
    c.ram.backing.clear();
    c.rom.backing.clear();
    for (auto &f: c.flash) {
        f.backing.clear();
    }
    return c;
}

static void store_memory_pma(const pma_entry &pma, const std::string &dir) {
    if (!pma.get_istart_M()) {
        throw std::runtime_error{"attempt to save non-memory PMA"};
    }
    auto name = machine_config::get_backing_name(dir,
        pma.get_start(), pma.get_length());
    auto fp = unique_fopen(name.c_str(), "wb");
    const pma_memory &mem = pma.get_memory();
    if (fwrite(mem.get_host_memory(), 1, pma.get_length(), fp.get()) !=
        pma.get_length()) {
        throw std::runtime_error{"error writing to '" + name + "'"};
    }
}

void machine::store_pmas(const machine_config &c, const std::string &dir) const {
    store_memory_pma(naked_find_pma_entry<uint64_t>(m_s, PMA_ROM_START), dir);
    store_memory_pma(naked_find_pma_entry<uint64_t>(m_s, PMA_RAM_START), dir);
    // Could iterate over PMAs checking for those with a drive DID
    // but this is easier
    for (const auto &f: c.flash) {
        store_memory_pma(naked_find_pma_entry<uint64_t>(m_s, f.start), dir);
    }
}

static void store_hash(const merkle_tree::hash_type &h, const std::string dir) {
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
    merkle_tree::hash_type h;
    if (!update_merkle_tree() || !get_merkle_tree().get_root_hash(h)) {
        throw std::runtime_error{"error updating root hash"};
    }
    store_hash(h, dir);
    auto c = serialization_config();
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

void machine::write_x(int i, uint64_t val) {
    if (i > 0) m_s.x[i] = val;
}

uint64_t machine::read_pc(void) const {
    return m_s.pc;
}

void machine::write_pc(uint64_t val) {
    m_s.pc = val;
}

uint64_t machine::read_mvendorid(void) const {
    return MVENDORID;
}

uint64_t machine::read_marchid(void) const {
    return MARCHID;
}

uint64_t machine::read_mimpid(void) const {
    return MIMPID;
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

void machine::write_mip(uint64_t mip) {
    m_s.mip = mip;
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

void machine::write_htif_tohost(uint64_t val) {
    m_s.htif.tohost = val;
}

uint64_t machine::read_htif_fromhost(void) const {
    return m_s.htif.fromhost;
}

void machine::write_htif_fromhost(uint64_t val) {
    m_s.htif.fromhost = val;
}

uint64_t machine::read_clint_mtimecmp(void) const {
    return m_s.clint.mtimecmp;
}

void machine::write_clint_mtimecmp(uint64_t val) {
    m_s.clint.mtimecmp = val;
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
        case csr::mvendorid: [[fallthrough]];
        case csr::marchid: [[fallthrough]];
        case csr::mimpid:
            throw std::invalid_argument{"CSR is read-only"};
        default:
            throw std::invalid_argument{"unknown CSR"};
    }
}

void machine::set_mip(uint32_t mask) {
    m_s.mip |= mask;
    m_s.iflags.I = false;
    m_s.or_brk_with_mip_mie();
}

void machine::reset_mip(uint32_t mask) {
    m_s.mip &= ~mask;
    m_s.set_brk_from_all();
}

uint8_t machine::read_iflags_PRV(void) const {
    return m_s.iflags.PRV;
}

bool machine::read_iflags_I(void) const {
    return m_s.iflags.I;
}

void machine::reset_iflags_I(void) {
    m_s.iflags.I = false;
}

void machine::set_iflags_I(void) {
    m_s.iflags.I = true;
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
    static_assert(PMA_PAGE_SIZE == merkle_tree::get_page_size(), "PMA and merkle_tree page sizes must match");
    merkle_tree::hasher_type h;
    auto scratch = unique_calloc<unsigned char>(1, PMA_PAGE_SIZE);
    if (!scratch) return false;
    bool broken = false;
    merkle_tree::hash_type pristine = m_t.get_pristine_hash(
        m_t.get_log2_page_size());
    // Go over the write TLB and mark as dirty all pages currently there
    for (int i = 0; i < TLB_SIZE; ++i) {
        auto &write = m_s.tlb_write[i];
        if (write.vaddr_page != UINT64_C(-1)) {
            write.pma->mark_dirty_page(write.paddr_page -
                write.pma->get_start());
        }
    }
    // Now go over all PMAs verifying dirty pages are marked
    for (auto &pma: m_s.pmas) {
        auto peek = pma.get_peek();
        for (uint64_t page_start_in_range = 0; page_start_in_range < pma.get_length(); page_start_in_range += PMA_PAGE_SIZE) {
            const unsigned char *page_data = nullptr;
            uint64_t page_address = pma.get_start() + page_start_in_range;
            peek(pma, *this, page_start_in_range, &page_data, scratch.get());
            merkle_tree::hash_type stored, real;
            m_t.get_page_node_hash(page_address, stored);
            m_t.get_page_node_hash(h, page_data, real);
            bool marked_dirty = pma.is_page_marked_dirty(page_start_in_range);
            bool is_dirty = (real != stored);
            if (marked_dirty != is_dirty && pma.get_istart_M()) {
                broken = true;
                if (is_dirty) {
                    std::cerr << std::setfill('0') << std::setw(8) << std::hex << page_address << " should have been dirty\n";
                    std::cerr << "  expected " << stored << '\n';
                    std::cerr << "  got " << real << '\n';
                } else if (real != pristine) {
                    std::cerr << std::setfill('0') << std::setw(8) << std::hex << page_address << " could have been clean\n";
                    std::cerr << "  still " << stored << '\n';
                }
            }
        }
    }
    return broken;
}

bool machine::update_merkle_tree(void) {
    merkle_tree::hasher_type gh;
    //double begin = now();
    static_assert(PMA_PAGE_SIZE == merkle_tree::get_page_size(), "PMA and merkle_tree page sizes must match");
    // Go over the write TLB and mark as dirty all pages currently there
    for (int i = 0; i < TLB_SIZE; ++i) {
        auto &write = m_s.tlb_write[i];
        if (write.vaddr_page != UINT64_C(-1)) {
            write.pma->mark_dirty_page(write.paddr_page -
                write.pma->get_start());
        }
    }
    // Now go over all PMAs and updating the Merkle tree
    m_t.begin_update();
    for (auto &pma: m_s.pmas) {
        auto peek = pma.get_peek();
        // Each PMA has a number of pages
        auto pages_in_range = (pma.get_length()+PMA_PAGE_SIZE-1)/PMA_PAGE_SIZE;
        // For each PMA, we launch as many threads (n) as the hardware supports.
        const int n = (int) std::thread::hardware_concurrency();
        // The update_page_node_hash function in the merkle_tree is not thread
        // safe, so we protect it with a mutex
        std::mutex updatex;
        // Each thread is launched as a future, whose value tells if the
        // computation succeeded
        std::vector<std::future<bool>> futures;
        futures.reserve(n);
        for (int j = 0; j < n; ++j) {
            futures.emplace_back(std::async(std::launch::async, [&](int j) -> bool {
                auto scratch = unique_calloc<unsigned char>(1, PMA_PAGE_SIZE);
                if (!scratch) return false;
                merkle_tree::hasher_type h;
                // Thread j is responsible for page i if i % n == j.
                for (int i = j; i < (int) pages_in_range; i+=n) {
                    uint64_t page_start_in_range = i*PMA_PAGE_SIZE;
                    uint64_t page_address = pma.get_start() + page_start_in_range;
                    const unsigned char *page_data = nullptr;
                    // Skip any clean pages
                    if (!pma.is_page_marked_dirty(page_start_in_range))
                        continue;
                    // If the peek failed, or if it returned a page for update but
                    // we failed updating it, the entire process failed
                    if (!peek(pma, *this, page_start_in_range, &page_data, scratch.get())) {
                        return false;
                    }
                    if (page_data) {
                        merkle_tree::hash_type hash;
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
        bool failed = false;
        for (auto &f: futures) {
            failed &= f.get();
        }
        // If so, we also failed
        if (failed) {
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
    static_assert(PMA_PAGE_SIZE == merkle_tree::get_page_size(), "PMA and merkle_tree page sizes must match");
    // Align address to begining of page
    address &= ~(PMA_PAGE_SIZE-1);
    pma_entry &pma = naked_find_pma_entry<uint64_t>(m_s, address);
    uint64_t page_start_in_range = address - pma.get_start();
    merkle_tree::hasher_type h;
    auto scratch = unique_calloc<unsigned char>(1, PMA_PAGE_SIZE);
    if (!scratch) return false;
    m_t.begin_update();
    const unsigned char *page_data = nullptr;
    auto peek = pma.get_peek();
    if (!peek(pma, *this, page_start_in_range, &page_data, scratch.get())) {
        m_t.end_update(h);
        return false;
    }
    if (page_data) {
        uint64_t page_address = pma.get_start() + page_start_in_range;
        merkle_tree::hash_type hash;
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

const merkle_tree &machine::get_merkle_tree(void) const {
    return m_t;
}

merkle_tree &machine::get_merkle_tree(void) {
    return m_t;
}

void machine::dump(void) const {
    auto scratch = unique_calloc<unsigned char>(1, PMA_PAGE_SIZE);
    for (auto &pma: m_s.pmas) {
        if (pma.get_length() == 0) break;
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

bool machine::get_proof(uint64_t address, int log2_size, merkle_tree::proof_type &proof) const {
    static_assert(PMA_PAGE_SIZE == merkle_tree::get_page_size(), "PMA and merkle_tree page sizes must match");
    auto scratch = unique_calloc<unsigned char>(1, PMA_PAGE_SIZE);
    if (!scratch) return false;
    const pma_entry &pma = naked_find_pma_entry<uint64_t>(m_s, address);
    const unsigned char *page_data = nullptr;
    uint64_t page_start_in_range = (address - pma.get_start()) & (~(PMA_PAGE_SIZE-1));
    auto peek = pma.get_peek();
    if (!peek(pma, *this, page_start_in_range, &page_data, scratch.get())) {
        return false;
    }
    return m_t.get_proof(address, log2_size, page_data, proof);
}

void machine::read_memory(uint64_t address, unsigned char *data,
    uint64_t length) const {
    const pma_entry &pma = naked_find_pma_entry(m_s, address, length);
    if (!pma.get_istart_M() || pma.get_istart_E())
        throw std::invalid_argument{"address range not entirely in memory PMA"};
    memcpy(data, pma.get_memory().get_host_memory()+(address-pma.get_start()),
            length);
}

void machine::write_memory(uint64_t address, const unsigned char *data,
    size_t length) {
    pma_entry &pma = naked_find_pma_entry(m_s, address, length);
    if (!pma.get_istart_M() || pma.get_istart_E())
        throw std::invalid_argument{"address range not entirely in memory PMA"};
    constexpr const auto page_size_log2 = PMA_constants::PMA_PAGE_SIZE_LOG2;
    uint64_t page_in_range = ((address - pma.get_start()) >> page_size_log2)
        << page_size_log2;
    constexpr const auto page_size = PMA_constants::PMA_PAGE_SIZE;
    int npages = (length+page_size-1)/page_size;
    for (int i = 0; i < npages; ++i) {
        pma.mark_dirty_page(page_in_range);
        page_in_range += page_size;
    }
    memcpy(pma.get_memory().get_host_memory()+(address-pma.get_start()), data,
            length);
}

bool machine::read_word(uint64_t word_address, uint64_t &word_value) const {
    // Make sure address is aligned
    if (word_address & (PMA_WORD_SIZE-1))
        return false;
    const pma_entry &pma = naked_find_pma_entry<uint64_t>(m_s, word_address);
    // ??D We should split peek into peek_word and peek_page
    // for performance. On the other hand, this function
    // will almost never be used, so one wonders if it is worth it...
    auto scratch = unique_calloc<unsigned char>(1, PMA_PAGE_SIZE);
    if (!scratch) return false;
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

void machine::verify_access_log(const access_log &log) {
    step_state_access a(log.get_accesses());
    interpret(a, UINT64_MAX);
    a.finish();
}

void machine::step(access_log &log) {
    update_merkle_tree();
    // Call interpret with a logged state access object
    logged_state_access a(*this);
    a.push_bracket(bracket_type::begin, "step");
    interpret(a, m_s.mcycle+1);
    a.push_bracket(bracket_type::end, "step");
    log = std::move(*a.get_log());
    verify_access_log(log);
}

void machine::run(uint64_t mcycle_end) {

    // The outer loop breaks only when the machine is halted
    // or when mcycle hits mcycle_end
    for ( ;; ) {

        // If we are halted, do nothing
        if (read_iflags_H()) {
            return;
        }

        // Run the emulator inner loop until we reach the next multiple of RISCV_RTC_FREQ_DIV
        // ??D This is enough for us to be inside the inner loop for about 98% of the time,
        // according to measurement, so it is not a good target for further optimization
        uint64_t mcycle = read_mcycle();
        uint64_t next_rtc_freq_div = mcycle + RTC_FREQ_DIV - mcycle % RTC_FREQ_DIV;
        run_inner_loop(std::min(next_rtc_freq_div, mcycle_end));

        // If we hit mcycle_end, we are done
        mcycle = read_mcycle();
        if (mcycle >= mcycle_end) {
            return;
        }

        // If we yielded, we are done
        if (read_iflags_Y()) {
            return;
        }

        // If we managed to run until the next possible frequency divisor
        if (mcycle == next_rtc_freq_div) {
            // Get the mcycle corresponding to mtimecmp
            uint64_t timecmp_mcycle = rtc_time_to_cycle(read_clint_mtimecmp());

            // If the processor is waiting for interrupts, we can skip until time hits timecmp
            // CLINT is the only interrupt source external to the inner loop
            // IPI (inter-processor interrupt) via MSIP can only be raised internally
            if (read_iflags_I()) {
                mcycle = std::min(timecmp_mcycle, mcycle_end);
                write_mcycle(mcycle);
            }

            // If the timer is expired, set interrupt as pending
            if (timecmp_mcycle && timecmp_mcycle <= mcycle) {
                set_mip(MIP_MTIP_MASK);
            }

            // Perform interactive actions
            interact();
        }
    }
}

} // namespace cartesi
