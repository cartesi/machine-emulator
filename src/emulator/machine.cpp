#include <sstream>
#include <cstring>
#include <cinttypes>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <cstdio>

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


namespace cartesi {

using namespace std::string_literals;

std::string get_name(void) {
    std::ostringstream os;
    os << MVENDORID_INIT << ':' << MARCHID_INIT << ':' << MIMPID_INIT;
    return os.str();
}

/// \brief Obtain PMA entry overlapping with target physical address
/// \param s Pointer to machine state.
/// \param paddr Target physical address.
/// \returns Corresponding entry if found, or a sentinel entry
/// for an empty range.
/// \tparam T Type used for memory access
template <typename T>
static inline pma_entry &naked_find_pma_entry(machine_state &s, uint64_t paddr) {
    for (auto &pma: s.pmas) {
        if (paddr >= pma.get_start() &&
            paddr + sizeof(T) <= pma.get_start() + pma.get_length())
            return pma;
    }
    return s.empty_pma;
}

template <typename T>
static inline const pma_entry &naked_find_pma_entry(const machine_state &s, uint64_t paddr) {
    return const_cast<const pma_entry &>(naked_find_pma_entry<T>(
        const_cast<machine_state &>(s), paddr));
}

/// \brief Memory range peek callback. See ::pma_peek.
static bool memory_peek(const pma_entry &pma, uint64_t page_address, const uint8_t **page_data, uint8_t *scratch) {
    // If page_address is not aligned, or if it is out of range, return error
    if ((page_address & (PMA_PAGE_SIZE-1)) != 0 ||
        page_address > pma.get_length()) {
        *page_data = nullptr;
        return false;
    }
    // If page is only partially inside range, copy to scratch
    if (page_address + PMA_PAGE_SIZE > pma.get_length()) {
        memset(scratch, 0, PMA_PAGE_SIZE);
        memcpy(scratch, pma.get_memory().get_host_memory() + page_address, pma.get_length() - page_address);
        *page_data = scratch;
        return true;
    // Otherwise, return pointer direclty into host memory
    } else {
        *page_data = pma.get_memory().get_host_memory() + page_address;
        return true;
    }
}

pma_entry &machine::allocate_pma_entry(pma_entry &&pma) {
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

void machine::register_flash(uint64_t start,
    uint64_t length, const char *path, bool shared) {
    pma_entry::flags f{};
    f.R = true; f.W = true; f.X = false; f.IR = true; f.IW = true;
    f.DID = PMA_ISTART_DID::memory;
    allocate_pma_entry(
        pma_entry{
            start,
            length,
            pma_memory{
                length,
                path,
                pma_memory::mmapd{shared}
            },
            memory_peek
        }.set_flags(f)
    );
}

pma_entry &machine::register_memory(uint64_t start, uint64_t length, bool W) {
    pma_entry::flags f{};
    f.R = true; f.W = W; f.X = true; f.IR = true; f.IW = true;
    f.DID = PMA_ISTART_DID::memory;
    return allocate_pma_entry(
        pma_entry{
            start,
            length,
            pma_memory{
                length,
                pma_memory::callocd{}
            },
            memory_peek
        }.set_flags(f)
    );
}

pma_entry &machine::register_memory(uint64_t start, uint64_t length,
    const std::string &path, bool W) {
    pma_entry::flags f{};
    f.R = true; f.W = W; f.X = true; f.IR = true; f.IW = true;
    f.DID = PMA_ISTART_DID::memory;
    return allocate_pma_entry(
        pma_entry{
            start,
            length,
            pma_memory{
                length,
                path,
                pma_memory::callocd{}
            },
            memory_peek
        }.set_flags(f)
    );
}

void machine::register_mmio(uint64_t start, uint64_t length, pma_peek peek, void *context, const pma_driver *driver, PMA_ISTART_DID DID) {
    pma_entry::flags f{};
    f.R = true; f.W = true; f.X = false; f.IR = false; f.IW = false;
    f.DID = DID;
    allocate_pma_entry(
        pma_entry{
            start,
            length,
            pma_device{
                context,
                driver
            },
            peek
        }.set_flags(f)
    );
}

void machine::register_shadow(uint64_t start, uint64_t length, pma_peek peek, void *context, const pma_driver *driver) {
    pma_entry::flags f{};
    f.R = true; f.W = false; f.X = false; f.IR = false; f.IW = false;
    f.DID = PMA_ISTART_DID::shadow;
    allocate_pma_entry(
        pma_entry{
            start,
            length,
            pma_device{
                context,
                driver
            },
            peek
        }.set_flags(f)
    );
}

uint8_t *machine::get_host_memory(uint64_t paddr) {
    pma_entry &pma = naked_find_pma_entry<uint8_t>(m_s, paddr);
    if (pma.get_istart_M()) {
        return pma.get_memory().get_host_memory();
    } else {
        return nullptr;
    }
}

#if 0
static bool empty_peek(const pma_entry &, uint64_t, const uint8_t **page_data, uint8_t *) {
    *page_data = nullptr;
    return true;
}
#endif

void machine::interact(void) {
    m_h.interact();
}

machine::machine(const machine_config &c):
    m_s{},
    m_t{},
    m_h{*this, c.interactive} {

    if (!c.processor.backing.empty())
        throw std::runtime_error{"processor backing not implemented"};

    // General purpose registers
    for (int i = 1; i < 32; i++) {
        write_x(i, c.processor.x[i]);
    }

    write_pc(c.processor.pc);
    write_mvendorid(c.processor.mvendorid);
    write_marchid(c.processor.marchid);
    write_mimpid(c.processor.mimpid);
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

    if (c.ram.backing.empty() && c.rom.backing.empty())
        throw std::invalid_argument{"ROM and RAM backing are undefined"};

    // Register RAM
    if (c.ram.backing.empty()) {
        register_memory(PMA_RAM_START, c.ram.length, true);
    } else {
        register_memory(PMA_RAM_START, c.ram.length, c.ram.backing, true);
    }

    // Register ROM
    if (c.rom.backing.empty()) {
        auto &rom = register_memory(PMA_ROM_START, PMA_ROM_LENGTH, false);
        rom_init(c, c.processor.misa, XLEN, rom.get_memory().get_host_memory(), PMA_ROM_LENGTH);
    } else {
        register_memory(PMA_ROM_START, PMA_ROM_LENGTH, c.rom.backing, false);
    }

    // Register all flash drives
    for (const auto &f: c.flash) {
        register_flash(f.start, f.length, f.backing.c_str(), f.shared);
    }

    // Register HTIF device
    m_h.register_mmio(PMA_HTIF_START, PMA_HTIF_LENGTH);

    // Copy HTIF state to from config to machine
    if (!c.htif.backing.empty())
        throw std::runtime_error{"HTIF backing not implemented"};
    write_htif_tohost(c.htif.tohost);
    write_htif_fromhost(c.htif.fromhost);

    // Resiter CLINT device
    clint_register_mmio(*this, PMA_CLINT_START, PMA_CLINT_LENGTH);
    // Copy CLINT state to from config to machine
    if (!c.clint.backing.empty())
        throw std::runtime_error{"CLINT backing not implemented"};
    write_clint_mtimecmp(c.clint.mtimecmp);

    // Register shadow device
    shadow_register_mmio(*this, PMA_SHADOW_START, PMA_SHADOW_LENGTH);

    // Clear all TLB entries
    m_s.init_tlb();
}

machine::~machine() {
#if DUMP_COUNTERS
    fprintf(stderr, "inner loops: %" PRIu64 "\n", m_s.count_inners);
    fprintf(stderr, "outers loops: %" PRIu64 "\n", m_s.count_outers);
    fprintf(stderr, "si: %" PRIu64 "\n", m_s.count_si);
    fprintf(stderr, "se: %" PRIu64 "\n", m_s.count_se);
    fprintf(stderr, "mi: %" PRIu64 "\n", m_s.count_mi);
    fprintf(stderr, "me: %" PRIu64 "\n", m_s.count_me);
    fprintf(stderr, "amo: %" PRIu64 "\n", m_s.count_amo);
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
    return m_s.mvendorid;
}

void machine::write_mvendorid(uint64_t val) {
    m_s.mvendorid = val;
}

uint64_t machine::read_marchid(void) const {
    return m_s.marchid;
}

void machine::write_marchid(uint64_t val) {
    m_s.marchid = val;
}

uint64_t machine::read_mimpid(void) const {
    return m_s.mimpid;
}

void machine::write_mimpid(uint64_t val) {
    m_s.mimpid = val;
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
    m_s.set_brk_from_mip_mie();
}

uint64_t machine::read_mie(void) const {
    return m_s.mie;
}

void machine::write_mie(uint64_t val) {
    m_s.mie = val;
    m_s.set_brk_from_mip_mie();
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
    m_s.set_brk_from_iflags_H();
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

void machine::set_mip(uint32_t mask) {
    m_s.mip |= mask;
    m_s.iflags.I = false;
    m_s.set_brk_from_mip_mie();
}

void machine::reset_mip(uint32_t mask) {
    m_s.mip &= ~mask;
    m_s.set_brk_from_mip_mie();
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

bool machine::read_iflags_H(void) const {
    return m_s.iflags.H;
}

void machine::set_iflags_H(void) {
    m_s.iflags.H = true;
    m_s.set_brk_from_iflags_H();
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
    auto scratch = unique_calloc<uint8_t>(1, PMA_PAGE_SIZE);
    if (!scratch) return false;
    bool broken = false;
    merkle_tree::hash_type pristine = m_t.get_pristine_hash(
        m_t.get_log2_page_size());
    // Go over the write TLB and mark as dirty all pages currently there
    for (int i = 0; i < TLB_SIZE; ++i) {
        auto &write = m_s.tlb_write[i];
        if (write.vaddr != UINT64_C(-1)) {
            write.pma->mark_dirty_page(write.paddr - write.pma->get_start());
        }
    }
    // Now go over all PMAs verifying dirty pages are marked
    for (auto &pma: m_s.pmas) {
        auto peek = pma.get_peek();
        for (uint64_t page_start_in_range = 0; page_start_in_range < pma.get_length(); page_start_in_range += PMA_PAGE_SIZE) {
            const uint8_t *page_data = nullptr;
            uint64_t page_address = pma.get_start() + page_start_in_range;
            peek(pma, page_start_in_range, &page_data, scratch.get());
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
    // double begin = now();
    static_assert(PMA_PAGE_SIZE == merkle_tree::get_page_size(), "PMA and merkle_tree page sizes must match");
    merkle_tree::hasher_type h;
    auto scratch = unique_calloc<uint8_t>(1, PMA_PAGE_SIZE);
    if (!scratch) return false;
    // Go over the write TLB and mark as dirty all pages currently there
    for (int i = 0; i < TLB_SIZE; ++i) {
        auto &write = m_s.tlb_write[i];
        if (write.vaddr != UINT64_C(-1)) {
            write.pma->mark_dirty_page(write.paddr - write.pma->get_start());
        }
    }
    // Now go over all PMAs and update the Merkle tree
    m_t.begin_update();
    for (auto &pma: m_s.pmas) {
        auto peek = pma.get_peek();
        for (uint64_t page_start_in_range = 0; page_start_in_range < pma.get_length(); page_start_in_range += PMA_PAGE_SIZE) {
            const uint8_t *page_data = nullptr;
            uint64_t page_address = pma.get_start() + page_start_in_range;
            // Skip any clean pages
            //if (!pma.is_page_marked_dirty(page_start_in_range)) continue;
            // If the peek failed, or if it returned a page for update but
            // we failed updating it, the entire process failed
            if (!peek(pma, page_start_in_range, &page_data, scratch.get())) {
                m_t.end_update(h);
                return false;
            }
            if (page_data) {
                //if (pma.get_istart_M()) {
                    //std::cerr << std::setfill('0') << std::setw(8) << std::hex << page_address << " updated\n";
                    //merkle_tree::hash_type real;
                    //m_t.get_page_node_hash(h, page_data, real);
                    //std::cerr << "  to " << real << '\n';
                //}
                if (!m_t.update_page(h, page_address, page_data)) {
                    m_t.end_update(h);
                    return false;
                }
            }
        }
        pma.mark_pages_clean();
    }
    // std::cerr << "page updates done in " << now()-begin << "s\n";
    // begin = now();
    return m_t.end_update(h);
    // std::cerr << "inner tree updates done in " << now()-begin << "s\n";
}

bool machine::update_merkle_tree_page(uint64_t address) {
    static_assert(PMA_PAGE_SIZE == merkle_tree::get_page_size(), "PMA and merkle_tree page sizes must match");
    // Align address to begining of page
    address &= ~(PMA_PAGE_SIZE-1);
    pma_entry &pma = naked_find_pma_entry<uint64_t>(m_s, address);
    uint64_t page_start_in_range = address - pma.get_start();
    if (!pma.is_page_marked_dirty(page_start_in_range)) return true;
    merkle_tree::hasher_type h;
    auto scratch = unique_calloc<uint8_t>(1, PMA_PAGE_SIZE);
    if (!scratch) return false;
    m_t.begin_update();
    const uint8_t *page_data = nullptr;
    auto peek = pma.get_peek();
    if (!peek(pma, page_start_in_range, &page_data, scratch.get())) {
        m_t.end_update(h);
        return false;
    } else if (page_data && !m_t.update_page(h, pma.get_start() + page_start_in_range, page_data)) {
        m_t.end_update(h);
        return false;
	} // ??D else page is pristine and we do nothing.
	  // Maybe add a check here to make sure it is also pristine in the tree
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
    auto scratch = unique_calloc<uint8_t>(1, PMA_PAGE_SIZE);
    for (auto &pma: m_s.pmas) {
        char filename[256];
        sprintf(filename, "%016" PRIx64 "--%016" PRIx64 ".bin", pma.get_start(), pma.get_length());
        auto fp = unique_fopen(filename, "wb");
        for (uint64_t page_start_in_range = 0; page_start_in_range < pma.get_length(); page_start_in_range += PMA_PAGE_SIZE) {
            const uint8_t *page_data = nullptr;
            auto peek = pma.get_peek();
            if (!peek(pma, page_start_in_range, &page_data, scratch.get())) {
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
    auto scratch = unique_calloc<uint8_t>(1, PMA_PAGE_SIZE);
    if (!scratch) return false;
    const pma_entry &pma = naked_find_pma_entry<uint64_t>(m_s, address);
    const uint8_t *page_data = nullptr;
    uint64_t page_start_in_range = (address - pma.get_start()) & (~(PMA_PAGE_SIZE-1));
    auto peek = pma.get_peek();
    if (!peek(pma, page_start_in_range, &page_data, scratch.get())) {
        return false;
    }
    return m_t.get_proof(address, log2_size, page_data, proof);
}

bool machine::read_word(uint64_t word_address, uint64_t &word_value) const {
    // Make sure address is aligned
    if (word_address & (PMA_WORD_SIZE-1))
        return false;
    const pma_entry &pma = naked_find_pma_entry<uint64_t>(m_s, word_address);
    // ??D We should split peek into peek_word and peek_page
    // for performance. On the other hand, this function
    // will almost never be used, so one wonders if it is worth it...
    auto scratch = unique_calloc<uint8_t>(1, PMA_PAGE_SIZE);
    if (!scratch) return false;
    const uint8_t *page_data = nullptr;
    uint64_t page_start_in_range = (word_address - pma.get_start()) & (~(PMA_PAGE_SIZE-1));
    auto peek = pma.get_peek();
    if (!peek(pma, page_start_in_range, &page_data, scratch.get())) {
        return false;
    }
    // If peek returns a page, read from it
    if (page_data) {
        uint64_t word_start_in_range = (word_address - pma.get_start()) & (PMA_PAGE_SIZE-1);
        word_value = *reinterpret_cast<const uint64_t *>(page_data + word_start_in_range);
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

void machine::step(access_log &log) {
    update_merkle_tree();
    // Call interpret with a logged state access object
    logged_state_access a(*this);
    a.push_bracket(bracket_type::begin, "step");
    interpret(a, m_s.mcycle+1);
    a.push_bracket(bracket_type::end, "step");
    log = std::move(*a.get_log());
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
