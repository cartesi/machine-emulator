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

#ifndef RECORD_STEP_STATE_ACCESS_H
#define RECORD_STEP_STATE_ACCESS_H

#include "compiler-defines.h"
#include "machine.h"

#include "device-state-access.h"
#include "i-state-access.h"
#include "shadow-pmas.h"
#include "unique-c-ptr.h"
#include <map>
#include <optional>
#include <vector>

namespace cartesi {

/// \class record_step_state_access
/// \brief Records machine state access into a step log file
class record_step_state_access : public i_state_access<record_step_state_access, pma_entry> {
    constexpr static int LOG2_ROOT_SIZE = machine_merkle_tree::get_log2_root_size();
    constexpr static int LOG2_PAGE_SIZE = machine_merkle_tree::get_log2_page_size();
    constexpr static uint64_t PAGE_SIZE = UINT64_C(1) << LOG2_PAGE_SIZE;

    using address_type = machine_merkle_tree::address_type;
    using page_data_type = std::array<uint8_t, PAGE_SIZE>;
    using pages_type = std::map<address_type, page_data_type>;
    using hash_type = machine_merkle_tree::hash_type;
    using sibling_hashes_type = std::vector<hash_type>;
    using page_indices_type = std::vector<address_type>;

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    machine &m_m;                       ///<  reference to machine
    std::string m_filename;             ///<  where to save the log
    mutable pages_type m_touched_pages; ///<  copy of all pages touched during execution

public:
    /// \brief Constructor
    /// \param m reference to machine
    /// \param filename where to save the log
    /// \details The log file is saved when finish() is called
    record_step_state_access(machine &m, const std::string &filename) : m_m(m), m_filename(filename) {
        if (os_file_exists(filename.c_str())) {
            throw std::runtime_error("file already exists");
        }
    }
    record_step_state_access(const record_step_state_access &) = delete;
    record_step_state_access(record_step_state_access &&) = delete;
    record_step_state_access &operator=(const record_step_state_access &) = delete;
    record_step_state_access &operator=(record_step_state_access &&) = delete;
    ~record_step_state_access() = default;

    /// \brief Finish recording and save the log file
    void finish() {
        // get sibling hashes of all touched pages
        auto sibling_hashes = get_sibling_hashes();
        uint64_t page_count = m_touched_pages.size();
        uint64_t sibling_count = sibling_hashes.size();

        // Write log file.
        // The log format is as follows:
        // page_count, [(page_index, data, scratch_area), ...], sibling_count, [sibling_hash, ...]
        // We store the page index, instead of the page address.
        // Scratch area is used by the replay to store page hashes, which change during replay
        // This is to work around the lack of dynamic memory allocation when replaying the log in microarchitectures
        auto fp = unique_fopen(m_filename.c_str(), "wb");
        if (fwrite(&page_count, sizeof(page_count), 1, fp.get()) != 1) {
            throw std::runtime_error("Could not write page count to log file");
        }
        for (auto &[address, data] : m_touched_pages) {
            const auto page_index = address >> LOG2_PAGE_SIZE;
            if (fwrite(&page_index, sizeof(page_index), 1, fp.get()) != 1) {
                throw std::runtime_error("Could not write page index to log file");
            }
            if (fwrite(data.data(), data.size(), 1, fp.get()) != 1) {
                throw std::runtime_error("Could not write page data to log file");
            }
            static const hash_type all_zeros{};
            if (fwrite(all_zeros.data(), sizeof(all_zeros), 1, fp.get()) != 1) {
                throw std::runtime_error("Could not write page hash scratch to log file");
            }
        }
        if (fwrite(&sibling_count, sizeof(sibling_count), 1, fp.get()) != 1) {
            throw std::runtime_error("Could not write sibling count to log file");
        }
        for (auto &hash : sibling_hashes) {
            if (fwrite(hash.data(), sizeof(hash), 1, fp.get()) != 1) {
                throw std::runtime_error("Could not write sibling hash to log file");
            }
        }
    }

private:
    friend i_state_access<record_step_state_access, pma_entry>;

    /// \brief Mark a page as touched and save its contents
    /// \param address address of the page
    void touch_page(address_type address) const {
        auto page = address & ~(PAGE_SIZE - 1);
        if (m_touched_pages.find(page) != m_touched_pages.end()) {
            return; // already saved
        }
        auto [it, _] = m_touched_pages.emplace(page, page_data_type());
        m_m.read_memory(page, it->second.data(), it->second.size());
    }

    /// \brief Get the sibling hashes of all touched pages
    sibling_hashes_type get_sibling_hashes() {
        sibling_hashes_type sibling_hashes{};
        // page address are converted to page indices, in order to avoid overflows
        page_indices_type page_indices{};
        // iterate in ascending order of page addresses (the container is ordered by key)
        for (const auto &[address, _] : m_touched_pages) {
            page_indices.push_back(address >> LOG2_PAGE_SIZE);
        }
        auto next_page_index = page_indices.cbegin();
        get_sibling_hashes_impl(0, LOG2_ROOT_SIZE - LOG2_PAGE_SIZE, page_indices, next_page_index, sibling_hashes);
        if (next_page_index != page_indices.cend()) {
            throw std::runtime_error("get_sibling_hashes failed to consume all pages");
        }
        return sibling_hashes;
    }

    /// \brief Recursively get the sibling hashes of all touched pages
    /// \param page_index index of 1st page in range
    /// \param page_count_log2_size log2 of the number of pages in range
    /// \param page_indices indices of all pages
    /// \param next_page_index smallest page index not visited yet
    /// \param sibling_hashes stores the collected sibling hashes during the recursion
    void get_sibling_hashes_impl(address_type page_index, int page_count_log2_size, page_indices_type &page_indices,
        page_indices_type::const_iterator &next_page_index, sibling_hashes_type &sibling_hashes) {
        auto page_count = UINT64_C(1) << page_count_log2_size;
        if (next_page_index == page_indices.cend() || page_index + page_count <= *next_page_index) {
            // we can skip the merkle tree update, because a full update was done before the recording started
            sibling_hashes.push_back(m_m.get_merkle_tree_node_hash(page_index << LOG2_PAGE_SIZE,
                page_count_log2_size + LOG2_PAGE_SIZE, skip_merkle_tree_update));
        } else if (page_count_log2_size > 0) {
            get_sibling_hashes_impl(page_index, page_count_log2_size - 1, page_indices, next_page_index,
                sibling_hashes);
            get_sibling_hashes_impl(page_index + (UINT64_C(1) << (page_count_log2_size - 1)), page_count_log2_size - 1,
                page_indices, next_page_index, sibling_hashes);
        } else {
            ++next_page_index;
        }
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_push_bracket(bracket_type type, const char *text) {
        (void) type;
        (void) text;
    }

    int do_make_scoped_note(const char *text) { // NOLINT(readability-convert-member-functions-to-static)
        (void) text;
        return 0;
    }

    uint64_t do_read_x(int reg) const {
        touch_page(machine_reg_address(machine_reg::x0, reg));
        return m_m.get_state().x[reg];
    }

    void do_write_x(int reg, uint64_t val) {
        assert(reg != 0);
        touch_page(machine_reg_address(machine_reg::x0, reg));
        m_m.get_state().x[reg] = val;
    }

    uint64_t do_read_f(int reg) const {
        touch_page(machine_reg_address(machine_reg::f0, reg));
        return m_m.get_state().f[reg];
    }

    void do_write_f(int reg, uint64_t val) {
        touch_page(machine_reg_address(machine_reg::f0, reg));
        m_m.get_state().f[reg] = val;
    }

    uint64_t do_read_pc() const {
        // get phys address of pc in dhadow
        touch_page(machine_reg_address(machine_reg::pc));
        return m_m.get_state().pc;
    }

    void do_write_pc(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::pc));
        m_m.get_state().pc = val;
    }

    uint64_t do_read_fcsr() const {
        touch_page(machine_reg_address(machine_reg::fcsr));
        return m_m.get_state().fcsr;
    }

    void do_write_fcsr(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::fcsr));
        m_m.get_state().fcsr = val;
    }

    uint64_t do_read_icycleinstret() const {
        touch_page(machine_reg_address(machine_reg::icycleinstret));
        return m_m.get_state().icycleinstret;
    }

    void do_write_icycleinstret(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::icycleinstret));
        m_m.get_state().icycleinstret = val;
    }

    uint64_t do_read_mvendorid() const { // NOLINT(readability-convert-member-functions-to-static)
        touch_page(machine_reg_address(machine_reg::mvendorid));
        return MVENDORID_INIT;
    }

    uint64_t do_read_marchid() const { // NOLINT(readability-convert-member-functions-to-static)
        touch_page(machine_reg_address(machine_reg::marchid));
        return MARCHID_INIT;
    }

    uint64_t do_read_mimpid() const { // NOLINT(readability-convert-member-functions-to-static)
        touch_page(machine_reg_address(machine_reg::mimpid));
        return MIMPID_INIT;
    }

    uint64_t do_read_mcycle() const {
        touch_page(machine_reg_address(machine_reg::mcycle));
        return m_m.get_state().mcycle;
    }

    void do_write_mcycle(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::mcycle));
        m_m.get_state().mcycle = val;
    }

    uint64_t do_read_mstatus() const {
        touch_page(machine_reg_address(machine_reg::mstatus));
        return m_m.get_state().mstatus;
    }

    void do_write_mstatus(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::mstatus));
        m_m.get_state().mstatus = val;
    }

    uint64_t do_read_menvcfg() const {
        touch_page(machine_reg_address(machine_reg::menvcfg));
        return m_m.get_state().menvcfg;
    }

    void do_write_menvcfg(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::menvcfg));
        m_m.get_state().menvcfg = val;
    }

    uint64_t do_read_mtvec() const {
        touch_page(machine_reg_address(machine_reg::mtvec));
        return m_m.get_state().mtvec;
    }

    void do_write_mtvec(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::mtvec));
        m_m.get_state().mtvec = val;
    }

    uint64_t do_read_mscratch() const {
        touch_page(machine_reg_address(machine_reg::mscratch));
        return m_m.get_state().mscratch;
    }

    void do_write_mscratch(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::mscratch));
        m_m.get_state().mscratch = val;
    }

    uint64_t do_read_mepc() const {
        touch_page(machine_reg_address(machine_reg::mepc));
        return m_m.get_state().mepc;
    }

    void do_write_mepc(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::mepc));
        m_m.get_state().mepc = val;
    }

    uint64_t do_read_mcause() const {
        touch_page(machine_reg_address(machine_reg::mcause));
        return m_m.get_state().mcause;
    }

    void do_write_mcause(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::mcause));
        m_m.get_state().mcause = val;
    }

    uint64_t do_read_mtval() const {
        touch_page(machine_reg_address(machine_reg::mtval));
        return m_m.get_state().mtval;
    }

    void do_write_mtval(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::mtval));
        m_m.get_state().mtval = val;
    }

    uint64_t do_read_misa() const {
        touch_page(machine_reg_address(machine_reg::misa));
        return m_m.get_state().misa;
    }

    void do_write_misa(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::misa));
        m_m.get_state().misa = val;
    }

    uint64_t do_read_mie() const {
        touch_page(machine_reg_address(machine_reg::mie));
        return m_m.get_state().mie;
    }

    void do_write_mie(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::mie));
        m_m.get_state().mie = val;
    }

    uint64_t do_read_mip() const {
        touch_page(machine_reg_address(machine_reg::mip));
        return m_m.get_state().mip;
    }

    void do_write_mip(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::mip));
        m_m.get_state().mip = val;
    }

    uint64_t do_read_medeleg() const {
        touch_page(machine_reg_address(machine_reg::medeleg));
        return m_m.get_state().medeleg;
    }

    void do_write_medeleg(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::medeleg));
        m_m.get_state().medeleg = val;
    }

    uint64_t do_read_mideleg() const {
        touch_page(machine_reg_address(machine_reg::mideleg));
        return m_m.get_state().mideleg;
    }

    void do_write_mideleg(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::mideleg));
        m_m.get_state().mideleg = val;
    }

    uint64_t do_read_mcounteren() const {
        touch_page(machine_reg_address(machine_reg::mcounteren));
        return m_m.get_state().mcounteren;
    }

    void do_write_mcounteren(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::mcounteren));
        m_m.get_state().mcounteren = val;
    }

    uint64_t do_read_senvcfg() const {
        touch_page(machine_reg_address(machine_reg::senvcfg));
        return m_m.get_state().senvcfg;
    }

    void do_write_senvcfg(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::senvcfg));
        m_m.get_state().senvcfg = val;
    }

    uint64_t do_read_stvec() const {
        touch_page(machine_reg_address(machine_reg::stvec));
        return m_m.get_state().stvec;
    }

    void do_write_stvec(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::stvec));
        m_m.get_state().stvec = val;
    }

    uint64_t do_read_sscratch() const {
        touch_page(machine_reg_address(machine_reg::sscratch));
        return m_m.get_state().sscratch;
    }

    void do_write_sscratch(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::sscratch));
        m_m.get_state().sscratch = val;
    }

    uint64_t do_read_sepc() const {
        touch_page(machine_reg_address(machine_reg::sepc));
        return m_m.get_state().sepc;
    }

    void do_write_sepc(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::sepc));
        m_m.get_state().sepc = val;
    }

    uint64_t do_read_scause() const {
        touch_page(machine_reg_address(machine_reg::scause));
        return m_m.get_state().scause;
    }

    void do_write_scause(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::scause));
        m_m.get_state().scause = val;
    }

    uint64_t do_read_stval() const {
        touch_page(machine_reg_address(machine_reg::stval));
        return m_m.get_state().stval;
    }

    void do_write_stval(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::stval));
        m_m.get_state().stval = val;
    }

    uint64_t do_read_satp() const {
        touch_page(machine_reg_address(machine_reg::satp));
        return m_m.get_state().satp;
    }

    void do_write_satp(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::satp));
        m_m.get_state().satp = val;
    }

    uint64_t do_read_scounteren() const {
        touch_page(machine_reg_address(machine_reg::scounteren));
        return m_m.get_state().scounteren;
    }

    void do_write_scounteren(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::scounteren));
        m_m.get_state().scounteren = val;
    }

    uint64_t do_read_ilrsc() const {
        touch_page(machine_reg_address(machine_reg::ilrsc));
        return m_m.get_state().ilrsc;
    }

    void do_write_ilrsc(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::ilrsc));
        m_m.get_state().ilrsc = val;
    }

    uint64_t do_read_iprv() const {
        touch_page(machine_reg_address(machine_reg::iprv));
        return m_m.get_state().iprv;
    }

    void do_write_iprv(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::iprv));
        m_m.get_state().iprv = val;
    }

    void do_write_iflags_X(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::iflags_X));
        m_m.get_state().iflags.X = val;
    }

    uint64_t do_read_iflags_X() const {
        touch_page(machine_reg_address(machine_reg::iflags_X));
        return m_m.get_state().iflags.X;
    }

    void do_write_iflags_Y(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::iflags_Y));
        m_m.get_state().iflags.Y = val;
    }

    uint64_t do_read_iflags_Y() const {
        touch_page(machine_reg_address(machine_reg::iflags_Y));
        return m_m.get_state().iflags.Y;
    }

    void do_write_iflags_H(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::iflags_H));
        m_m.get_state().iflags.H = val;
    }

    uint64_t do_read_iflags_H() const {
        touch_page(machine_reg_address(machine_reg::iflags_H));
        return m_m.get_state().iflags.H;
    }

    uint64_t do_read_iunrep() const {
        touch_page(machine_reg_address(machine_reg::iunrep));
        return m_m.get_state().iunrep;
    }

    void do_write_iunrep(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::iunrep));
        m_m.get_state().iunrep = val;
    }

    uint64_t do_read_clint_mtimecmp() const {
        touch_page(machine_reg_address(machine_reg::clint_mtimecmp));
        return m_m.get_state().clint.mtimecmp;
    }

    void do_write_clint_mtimecmp(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::clint_mtimecmp));
        m_m.get_state().clint.mtimecmp = val;
    }

    uint64_t do_read_plic_girqpend() const {
        touch_page(machine_reg_address(machine_reg::plic_girqpend));
        return m_m.get_state().plic.girqpend;
    }

    void do_write_plic_girqpend(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::plic_girqpend));
        m_m.get_state().plic.girqpend = val;
    }

    uint64_t do_read_plic_girqsrvd() const {
        touch_page(machine_reg_address(machine_reg::plic_girqsrvd));
        return m_m.get_state().plic.girqsrvd;
    }

    void do_write_plic_girqsrvd(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::plic_girqsrvd));
        m_m.get_state().plic.girqsrvd = val;
    }

    uint64_t do_read_htif_fromhost() const {
        touch_page(machine_reg_address(machine_reg::htif_fromhost));
        return m_m.get_state().htif.fromhost;
    }

    void do_write_htif_fromhost(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::htif_fromhost));
        m_m.get_state().htif.fromhost = val;
    }

    uint64_t do_read_htif_tohost() const {
        touch_page(machine_reg_address(machine_reg::htif_tohost));
        return m_m.get_state().htif.tohost;
    }

    void do_write_htif_tohost(uint64_t val) {
        touch_page(machine_reg_address(machine_reg::htif_tohost));
        m_m.get_state().htif.tohost = val;
    }

    uint64_t do_read_htif_ihalt() const {
        touch_page(machine_reg_address(machine_reg::htif_ihalt));
        return m_m.get_state().htif.ihalt;
    }

    uint64_t do_read_htif_iconsole() const {
        touch_page(machine_reg_address(machine_reg::htif_iconsole));
        return m_m.get_state().htif.iconsole;
    }

    uint64_t do_read_htif_iyield() const {
        touch_page(machine_reg_address(machine_reg::htif_iyield));
        return m_m.get_state().htif.iyield;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    NO_INLINE std::pair<uint64_t, bool> do_poll_external_interrupts(uint64_t mcycle, uint64_t mcycle_max) {
        (void) mcycle_max;
        return {mcycle, false};
    }

    template <typename T>
    void do_read_memory_word(uint64_t paddr, const unsigned char *hpage, uint64_t hoffset, T *pval) const {
        (void) paddr;
        touch_page(paddr);
        *pval = cartesi::aliased_aligned_read<T>(hpage + hoffset);
    }

    template <typename T>
    void do_write_memory_word(uint64_t paddr, unsigned char *hpage, uint64_t hoffset, T val) {
        (void) paddr;
        touch_page(paddr);
        aliased_aligned_write(hpage + hoffset, val);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_read_memory(uint64_t paddr, const unsigned char *data, uint64_t length) const {
        (void) paddr;
        (void) data;
        (void) length;
        throw std::runtime_error("Unexpected call to do_read_memory");
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) {

        (void) paddr;
        (void) data;
        (void) length;
        throw std::runtime_error("Unexpected call to do_write_memory");
    }

    template <typename T>
    pma_entry &do_find_pma_entry(uint64_t paddr) {
        int i = 0;
        while (true) {
            touch_page(shadow_pmas_get_pma_abs_addr(i));
            auto &pma = m_m.get_state().pmas[i];
            // The pmas array always contain a sentinel. It is an entry with
            // zero length. If we hit it, return it
            if (pma.get_length() == 0) {
                return pma;
            }
            // Otherwise, if we found an entry where the access fits, return it
            // Note the "strange" order of arithmetic operations.
            // This is to ensure there is no overflow.
            // Since we know paddr >= start, there is no chance of overflow
            // in the first subtraction.
            // Since length is at least 4096 (an entire page), there is no
            // chance of overflow in the second subtraction.
            if (paddr >= pma.get_start() && paddr - pma.get_start() <= pma.get_length() - sizeof(T)) {
                return pma;
            }
            i++;
        }
    }

    static unsigned char *do_get_host_memory(pma_entry &pma) {
        return pma.get_memory_noexcept().get_host_memory();
    }

    pma_entry &do_get_pma_entry(int index) {
        auto &pmas = m_m.get_state().pmas;
        const auto last_pma_index = static_cast<int>(pmas.size()) - 1;
        if (index >= last_pma_index) {
            touch_page(shadow_pmas_get_pma_abs_addr(last_pma_index));
            return pmas[last_pma_index];
        }
        touch_page(shadow_pmas_get_pma_abs_addr(index));
        return pmas[index];
    }

    bool do_read_device(pma_entry &pma, uint64_t mcycle, uint64_t offset, uint64_t *pval, int log2_size) {
        device_state_access da(*this, mcycle);
        return pma.get_device_noexcept().get_driver()->read(pma.get_device_noexcept().get_context(), &da, offset, pval,
            log2_size);
    }

    execute_status do_write_device(pma_entry &pma, uint64_t mcycle, uint64_t offset, uint64_t val, int log2_size) {
        device_state_access da(*this, mcycle);
        return pma.get_device_noexcept().get_driver()->write(pma.get_device_noexcept().get_context(), &da, offset, val,
            log2_size);
    }

    template <TLB_entry_type ETYPE, typename T>
    bool do_translate_vaddr_via_tlb(uint64_t vaddr, unsigned char **phptr) {
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        touch_page(tlb_get_entry_hot_abs_addr<ETYPE>(eidx));
        touch_page(tlb_get_entry_cold_abs_addr<ETYPE>(eidx));
        const tlb_hot_entry &tlbhe = m_m.get_state().tlb.hot[ETYPE][eidx];
        if (unlikely(!tlb_is_hit<T>(tlbhe.vaddr_page, vaddr))) {
            return false;
        }
        *phptr = cast_addr_to_ptr<unsigned char *>(tlbhe.vh_offset + vaddr);
        const tlb_cold_entry &tlbce = m_m.get_state().tlb.cold[ETYPE][eidx];
        touch_page(tlbce.paddr_page);
        return true;
    }

    template <TLB_entry_type ETYPE, typename T>
    bool do_read_memory_word_via_tlb(uint64_t vaddr, T *pval) {
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        const tlb_hot_entry &tlbhe = m_m.get_state().tlb.hot[ETYPE][eidx];
        const tlb_cold_entry &tlbce = m_m.get_state().tlb.cold[ETYPE][eidx];
        touch_page(tlb_get_entry_hot_abs_addr<ETYPE>(eidx));
        touch_page(tlb_get_entry_cold_abs_addr<ETYPE>(
            eidx)); // save cold entry to allow reconstruction of paddr during playback
        if (unlikely(!tlb_is_hit<T>(tlbhe.vaddr_page, vaddr))) {
            return false;
        }
        const auto *h = cast_addr_to_ptr<const unsigned char *>(tlbhe.vh_offset + vaddr);
        *pval = cartesi::aliased_aligned_read<T>(h);
        touch_page(tlbce.paddr_page);

        return true;
    }

    template <TLB_entry_type ETYPE, typename T>
    bool do_write_memory_word_via_tlb(uint64_t vaddr, T val) {
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        const tlb_hot_entry &tlbhe = m_m.get_state().tlb.hot[ETYPE][eidx];
        touch_page(tlb_get_entry_hot_abs_addr<ETYPE>(eidx));
        touch_page(tlb_get_entry_cold_abs_addr<ETYPE>(eidx));
        if (unlikely(!tlb_is_hit<T>(tlbhe.vaddr_page, vaddr))) {
            return false;
        }
        touch_page(tlb_get_entry_cold_abs_addr<ETYPE>(
            eidx)); // save cold entry to allow reconstruction of paddr during playback
        const tlb_cold_entry &tlbce = m_m.get_state().tlb.cold[ETYPE][eidx];
        touch_page(tlbce.paddr_page);

        auto *h = cast_addr_to_ptr<unsigned char *>(tlbhe.vh_offset + vaddr);
        aliased_aligned_write(h, val);
        return true;
    }

    template <TLB_entry_type ETYPE>
    unsigned char *do_replace_tlb_entry(uint64_t vaddr, uint64_t paddr, pma_entry &pma) {
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        touch_page(tlb_get_entry_hot_abs_addr<ETYPE>(eidx));
        touch_page(tlb_get_entry_cold_abs_addr<ETYPE>(
            eidx)); // save cold entry to allow reconstruction of paddr during playback
        tlb_hot_entry &tlbhe = m_m.get_state().tlb.hot[ETYPE][eidx];
        tlb_cold_entry &tlbce = m_m.get_state().tlb.cold[ETYPE][eidx];
        // Mark page that was on TLB as dirty so we know to update the Merkle tree
        if constexpr (ETYPE == TLB_WRITE) {
            if (tlbhe.vaddr_page != TLB_INVALID_PAGE) {
                pma_entry &pma = do_get_pma_entry(static_cast<int>(tlbce.pma_index));
                pma.mark_dirty_page(tlbce.paddr_page - pma.get_start());
            }
        }
        const uint64_t vaddr_page = vaddr & ~PAGE_OFFSET_MASK;
        const uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
        unsigned char *hpage = pma.get_memory_noexcept().get_host_memory() + (paddr_page - pma.get_start());
        tlbhe.vaddr_page = vaddr_page;
        tlbhe.vh_offset = cast_ptr_to_addr<uint64_t>(hpage) - vaddr_page;
        tlbce.paddr_page = paddr_page;
        tlbce.pma_index = static_cast<uint64_t>(pma.get_index());
        touch_page(tlbce.paddr_page);
        return hpage;
    }

    template <TLB_entry_type ETYPE>
    void do_flush_tlb_entry(uint64_t eidx) {
        touch_page(tlb_get_entry_hot_abs_addr<ETYPE>(eidx));
        touch_page(tlb_get_entry_cold_abs_addr<ETYPE>(
            eidx)); // save cold entry to allow reconstruction of paddr during playback
        tlb_hot_entry &tlbhe = m_m.get_state().tlb.hot[ETYPE][eidx];
        // Mark page that was on TLB as dirty so we know to update the Merkle tree
        if constexpr (ETYPE == TLB_WRITE) {
            if (tlbhe.vaddr_page != TLB_INVALID_PAGE) {
                tlbhe.vaddr_page = TLB_INVALID_PAGE;
                const tlb_cold_entry &tlbce = m_m.get_state().tlb.cold[ETYPE][eidx];
                pma_entry &pma = do_get_pma_entry(static_cast<int>(tlbce.pma_index));
                pma.mark_dirty_page(tlbce.paddr_page - pma.get_start());
            } else {
                tlbhe.vaddr_page = TLB_INVALID_PAGE;
            }
        } else {
            tlbhe.vaddr_page = TLB_INVALID_PAGE;
        }
    }

    template <TLB_entry_type ETYPE>
    void do_flush_tlb_type() {
        for (uint64_t i = 0; i < PMA_TLB_SIZE; ++i) {
            do_flush_tlb_entry<ETYPE>(i);
        }
    }

    void do_flush_tlb_vaddr(uint64_t vaddr) {
        (void) vaddr;
        // We can't flush just one TLB entry for that specific virtual address,
        // because megapages/gigapages may be in use while this TLB implementation ignores it,
        // so we have to flush all addresses.
        do_flush_tlb_type<TLB_CODE>();
        do_flush_tlb_type<TLB_READ>();
        do_flush_tlb_type<TLB_WRITE>();
    }

    bool do_get_soft_yield() {
        return m_m.get_state().soft_yield;
    }
};

} // namespace cartesi

#endif
