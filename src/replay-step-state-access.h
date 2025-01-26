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

#ifndef REPLAY_STEP_STATE_ACCESS_H
#define REPLAY_STEP_STATE_ACCESS_H

#include <cstdlib>
#include <optional>

#include "clint.h"
#include "compiler-defines.h"
#include "device-state-access.h"
#include "htif.h"
#include "i-state-access.h"
#include "machine-reg.h"
#include "plic.h"
#include "pma-constants.h"
#include "replay-step-state-access-interop.h"
#include "riscv-constants.h"
#include "shadow-pmas.h"
#include "shadow-state.h"
#include "shadow-tlb.h"
#include "shadow-uarch-state.h"
#include "strict-aliasing.h"
#include "uarch-constants.h"
#include "uarch-defines.h"

namespace cartesi {

// \file this code is designed to be compiled for a free-standing environment.
// Environment-specific functions have the prefix "interop_" and are declared in "replay-step-state-access-interop.h"

class mock_pma_entry final {
public:
    struct flags {
        bool M;
        bool IO;
        bool E;
        bool R;
        bool W;
        bool X;
        bool IR;
        bool IW;
        PMA_ISTART_DID DID;
    };

private:
    int m_pma_index;
    uint64_t m_start;
    uint64_t m_length;
    flags m_flags;
    const pma_driver *m_device_driver;
    void *m_device_context;

public:
    mock_pma_entry(int pma_index, uint64_t start, uint64_t length, flags flags, const pma_driver *pma_driver = nullptr,
        void *device_context = nullptr) :
        m_pma_index{pma_index},
        m_start{start},
        m_length{length},
        m_flags{flags},
        m_device_driver{pma_driver},
        m_device_context{device_context} {}

    mock_pma_entry() :
        mock_pma_entry(-1, 0, 0, {false, false, true, false, false, false, false, false, PMA_ISTART_DID{}}) {
        ;
    }

    int get_index() const {
        return m_pma_index;
    }

    flags get_flags() const {
        return m_flags;
    }

    uint64_t get_start() const {
        return m_start;
    }

    uint64_t get_length() const {
        return m_length;
    }

    bool get_istart_M() const {
        return m_flags.M;
    }

    bool get_istart_IO() const {
        return m_flags.IO;
    }

    bool get_istart_E() const {
        return m_flags.E;
    }

    bool get_istart_R() const {
        return m_flags.R;
    }

    bool get_istart_W() const {
        return m_flags.W;
    }

    bool get_istart_X() const {
        return m_flags.X;
    }

    bool get_istart_IR() const {
        return m_flags.IR;
    }

    const pma_driver *get_device_driver() {
        return m_device_driver;
    }

    void *get_device_context() {
        return m_device_context;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void mark_dirty_page(uint64_t address_in_range) {
        (void) address_in_range;
        // Dummy implementation.
    }
};

// \brief checks if a buffer is large enough to hold a data block of N elements of size S starting at a given offset
// \param max The maximum offset allowed
// \param current The current offset
// \param elsize The size of each element
// \param elcount The number of elements
// \param next Receives the start offset of the next data block
// \return true if the buffer is large enough and data doesn't overflow, false otherwise
static inline bool validate_and_advance_offset(uint64_t max, uint64_t current, uint64_t elsize, uint64_t elcount,
    uint64_t *next) {
    uint64_t size{};
    if (__builtin_mul_overflow(elsize, elcount, &size)) {
        return false;
    }
    if (__builtin_add_overflow(current, size, next)) {
        return false;
    }
    return *next <= max;
}

static_assert(sizeof(shadow_tlb_state::hot[0]) == PMA_PAGE_SIZE, "size of hot tlb cache must be PM_PAGE_SIZE bytes");
static_assert(sizeof(shadow_tlb_state::cold[0]) == PMA_PAGE_SIZE, "size of cold tlb cache must be PM_PAGE_SIZE bytes");
static_assert(sizeof(shadow_tlb_state::hot) + sizeof(shadow_tlb_state::cold) == sizeof(shadow_tlb_state),
    "size of shadow tlb state");

// \brief Provides machine state from a step log file
class replay_step_state_access : public i_state_access<replay_step_state_access, mock_pma_entry> {
public:
    using hash_type = std::array<unsigned char, interop_machine_hash_byte_size>;
    static_assert(sizeof(hash_type) == interop_machine_hash_byte_size);

private:
    using address_type = uint64_t;
    using data_type = unsigned char[PMA_PAGE_SIZE];

    struct PACKED page_type {
        address_type index;
        data_type data;
        hash_type hash;
    };

    uint64_t m_page_count{0};                                    ///< Number of pages in the step log
    page_type *m_pages{nullptr};                                 ///< Array of page data
    uint64_t m_sibling_count{0};                                 ///< Number of sibling hashes in the step log
    hash_type *m_sibling_hashes{nullptr};                        ///< Array of sibling hashes
    std::array<std::optional<mock_pma_entry>, PMA_MAX> m_pmas{}; ///< Array of PMA entries

public:
    // \brief Construct a replay_step_state_access object from a log image and expected initial root hash
    // \param log_image Image of the step log file
    // \param log_size The size of the log data
    // \param root_hash_before The expected machine root hash before the replay
    // \throw runtime_error if the initial root hash does not match or the log data is invalid
    replay_step_state_access(unsigned char *log_image, uint64_t log_size, const hash_type &root_hash_before) {
        // relevant offsets in the log data
        uint64_t first_page_offset{};
        uint64_t first_siblng_offset{};
        uint64_t sibling_count_offset{};
        uint64_t end_offset{}; // end of the log data

        // ensure that log_step + size does not overflow
        if (__builtin_add_overflow(cast_ptr_to_addr<uint64_t>(log_image), log_size, &end_offset)) {
            interop_throw_runtime_error("step log size overflow");
        }

        // set page count
        if (!validate_and_advance_offset(log_size, 0, sizeof(m_page_count), 1, &first_page_offset)) {
            interop_throw_runtime_error("page count past end of step log");
        }
        memcpy(&m_page_count, log_image, sizeof(m_page_count));
        if (m_page_count == 0) {
            interop_throw_runtime_error("page count is zero");
        }

        // set page data
        if (!validate_and_advance_offset(log_size, first_page_offset, sizeof(page_type), m_page_count,
                &sibling_count_offset)) {
            interop_throw_runtime_error("page data past end of step log");
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        m_pages = reinterpret_cast<page_type *>(log_image + first_page_offset);

        // set sibling count and hashes
        if (!validate_and_advance_offset(log_size, sibling_count_offset, sizeof(m_sibling_count), 1,
                &first_siblng_offset)) {
            interop_throw_runtime_error("sibling count past end of step log");
        }
        memcpy(&m_sibling_count, log_image + sibling_count_offset, sizeof(m_sibling_count));

        // set sibling hashes
        if (!validate_and_advance_offset(log_size, first_siblng_offset, sizeof(hash_type), m_sibling_count,
                &end_offset)) {
            interop_throw_runtime_error("sibling hashes past end of step log");
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        m_sibling_hashes = reinterpret_cast<hash_type *>(log_image + first_siblng_offset);

        // ensure that we read exactly the expected log size
        if (end_offset != log_size) {
            interop_throw_runtime_error("extra data at end of step log");
        }

        // ensure that the page indexes are in increasing order
        // and that the scratch hash area is all zeros
        static const hash_type all_zeros{};
        for (uint64_t i = 0; i < m_page_count; i++) {
            if (i > 0 && m_pages[i - 1].index >= m_pages[i].index) {
                interop_throw_runtime_error("invalid log format: page index is not in increasing order");
            }
            if (m_pages[i].hash != all_zeros) {
                interop_throw_runtime_error("invalid log format: page scratch hash area is not zero");
            }
        }

        // compute  and check the machine root hash before the replay
        auto computed_root_hash_before = compute_root_hash();
        if (computed_root_hash_before != root_hash_before) {
            interop_throw_runtime_error("initial root hash mismatch");
        }
        // relocate all tlb vh offsets into the logged page data
        relocate_all_tlb_vh_offset<TLB_CODE>();
        relocate_all_tlb_vh_offset<TLB_READ>();
        relocate_all_tlb_vh_offset<TLB_WRITE>();
    }

    replay_step_state_access(const replay_step_state_access &) = delete;
    replay_step_state_access(replay_step_state_access &&) = delete;
    replay_step_state_access &operator=(const replay_step_state_access &) = delete;
    replay_step_state_access &operator=(replay_step_state_access &&) = delete;
    ~replay_step_state_access() = default;

    // \brief Finish the replay and check the final machine root hash
    // \param final_root_hash The expected final machine root hash
    // \throw runtime_error if the final root hash does not match
    void finish(const hash_type &root_hash_after) {
        // reset all tlb vh offsets to zero
        // this is to mimic peek behavior of tlb pma device
        reset_all_tlb_vh_offset<TLB_CODE>();
        reset_all_tlb_vh_offset<TLB_READ>();
        reset_all_tlb_vh_offset<TLB_WRITE>();
        // compute and check machine root hash after the replay
        auto computed_final_root_hash = compute_root_hash();
        if (computed_final_root_hash != root_hash_after) {
            interop_throw_runtime_error("final root hash mismatch");
        }
    }

private:
    friend i_state_access<replay_step_state_access, mock_pma_entry>;

    // \brief Relocate all TLB virtual to host offsets
    // \details Points the vh_offset relative to the logged page data
    template <TLB_entry_type ETYPE>
    void relocate_all_tlb_vh_offset() {
        // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast))
        for (size_t i = 0; i < PMA_TLB_SIZE; ++i) {
            const auto he_address = tlb_get_entry_hot_abs_addr<ETYPE>(i);
            const auto he_page = he_address & ~(PMA_PAGE_SIZE - 1);
            const auto he_offset = he_address - he_page;
            auto *he_log = try_find_page(he_page);
            // if the page containing the tlb hot entries is present in the log
            if (he_log) {
                volatile tlb_hot_entry *tlbhe = reinterpret_cast<tlb_hot_entry *>(he_log->data + he_offset);
                if (tlbhe->vh_offset != 0) {
                    interop_throw_runtime_error("expected vh_offset to be zero");
                }
                // find the logged cold entry page
                const auto ce_addr = tlb_get_entry_cold_abs_addr<ETYPE>(i);
                const auto ce_page = ce_addr & ~(PMA_PAGE_SIZE - 1);
                const auto ce_offset = ce_addr - ce_page;
                auto *ce_log = find_page(ce_page);
                volatile tlb_cold_entry *tlbce = reinterpret_cast<tlb_cold_entry *>(ce_log->data + ce_offset);
                // find the logged page pointed by the cold entry
                auto *log = try_find_page(tlbce->paddr_page);
                if (log) {
                    // point vh_offset to the logged page data
                    tlbhe->vh_offset = cast_ptr_to_addr<uint64_t>(log->data) - tlbhe->vaddr_page;
                }
            }
        }
        // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast))
    }

    // \brief Reset all TLB virtual to host offsets
    // \details Points the vh_offset to zero, replicating the behavior of the tlb pma device
    template <TLB_entry_type ETYPE>
    void reset_all_tlb_vh_offset() {
        // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast))
        for (size_t i = 0; i < PMA_TLB_SIZE; ++i) {
            const auto addr = tlb_get_entry_hot_abs_addr<ETYPE>(i);
            const auto page = addr & ~(PMA_PAGE_SIZE - 1);
            const auto offset = addr - page;
            auto *p = try_find_page(page);
            if (p) {
                volatile tlb_hot_entry *tlbhe = reinterpret_cast<tlb_hot_entry *>(p->data + offset);
                tlbhe->vh_offset = 0;
            }
        }
        // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast))
    }

    /// \brief Try to find a page in the logged data
    /// \param address The physical address of the page
    /// \return A pointer to the page_type structure if found, nullptr otherwise
    page_type *try_find_page(uint64_t address) const {
        const auto page_index = address >> PMA_PAGE_SIZE_LOG2;
        uint64_t min{0};
        uint64_t max{m_page_count};
        while (min < max) {
            auto mid = (min + max) >> 1;
            if (m_pages[mid].index == page_index) {
                return &m_pages[mid];
            }
            if (m_pages[mid].index < page_index) {
                min = mid + 1;
            } else {
                max = mid;
            }
        }
        return nullptr;
    }

    /// \brief Find a page in the logged data
    /// \param address The physical address of the page
    /// \return A pointer to the page_type structure
    page_type *find_page(uint64_t address) const {
        auto *page = try_find_page(address);
        if (page == nullptr) {
            interop_throw_runtime_error("find_page: page not found");
        }
        return page;
    }

    /// \brief Find a page in the logged data
    /// \param address The physical address of the page
    /// \return A pointer to the page_type structure
    page_type *find_page(uint64_t address) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): remove const to reuse code
        return static_cast<const replay_step_state_access *>(this)->find_page(address);
    }

    /// \brief Get the raw memory pointer for a given physical address
    /// \param paddr The physical address
    /// \param size The size of the memory region
    /// \return A pointer to the raw memory
    void *get_raw_memory_pointer(uint64_t paddr, size_t size) const {
        auto page = paddr & ~(PMA_PAGE_SIZE - 1);
        const auto offset = paddr - page;
        auto end_page = (paddr + size - 1) & ~(PMA_PAGE_SIZE - 1);
        if (end_page != page) {
            interop_throw_runtime_error("get_raw_memory_pointer: paddr crosses page boundary");
        }
        auto *data = find_page(page);
        auto *p = data->data + offset;
        return p;
    }

    /// \brief Read a value from raw memory
    /// \tparam T The type of the value to read
    /// \param paddr The physical address
    /// \return The value read
    template <typename T>
    T raw_read_memory(uint64_t paddr) const {
        auto size = sizeof(T);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        volatile T *ptr = reinterpret_cast<T *>(get_raw_memory_pointer(paddr, size));
        return *ptr;
    }

    /// \brief Write a value to raw memory
    /// \tparam T The type of the value to write
    /// \param paddr The physical address
    /// \param val The value to write
    template <typename T>
    void raw_write_memory(uint64_t paddr, T val) {
        auto size = sizeof(T);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        volatile T *ptr = reinterpret_cast<T *>(get_raw_memory_pointer(paddr, size));
        *ptr = val;
    }

    // \brief Compute the current machine root hash
    hash_type compute_root_hash() {
        for (uint64_t i = 0; i < m_page_count; i++) {
            interop_merkle_tree_hash(m_pages[i].data, PMA_PAGE_SIZE,
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                reinterpret_cast<interop_hash_type>(&m_pages[i].hash));
        }

        size_t next_page = 0;
        size_t next_sibling = 0;
        auto root_hash =
            compute_root_hash_impl(0, interop_log2_root_size - PMA_PAGE_SIZE_LOG2, next_page, next_sibling);
        if (next_page != m_page_count) {
            interop_throw_runtime_error("compute_root_hash: next_page != m_page_count");
        }
        if (next_sibling != m_sibling_count) {
            interop_throw_runtime_error("compute_root_hash: sibling hashes not totally consumed");
        }
        return root_hash;
    }

    // \brief Compute the root hash of a memory range recursively
    // \param page_index Index of the first page in the range
    // \param page_count_log2_size Log2 of the size of number of pages in the range
    // \param next_page Index of the next page to be visited
    // \param next_sibling Index of the next sibling hash to be visited
    // \return Resulting root hash of the range
    hash_type compute_root_hash_impl(address_type page_index, int page_count_log2_size, size_t &next_page,
        size_t &next_sibling) {
        // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast))
        auto page_count = UINT64_C(1) << page_count_log2_size;
        if (next_page >= m_page_count || page_index + page_count <= m_pages[next_page].index) {
            if (next_sibling >= m_sibling_count) {
                interop_throw_runtime_error(
                    "compute_root_hash_impl: trying to access beyond sibling count while skipping range");
            }
            return m_sibling_hashes[next_sibling++];
        }
        if (page_count_log2_size > 0) {
            auto left = compute_root_hash_impl(page_index, page_count_log2_size - 1, next_page, next_sibling);
            auto right = compute_root_hash_impl(page_index + (UINT64_C(1) << (page_count_log2_size - 1)),
                page_count_log2_size - 1, next_page, next_sibling);
            hash_type hash{};
            interop_concat_hash(reinterpret_cast<interop_hash_type>(&left), reinterpret_cast<interop_hash_type>(&right),
                reinterpret_cast<interop_hash_type>(&hash));
            return hash;
        }
        if (m_pages[next_page].index == page_index) {
            return m_pages[next_page++].hash;
        }
        if (next_sibling >= m_sibling_count) {
            interop_throw_runtime_error("compute_root_hash_impl: trying to access beyond sibling count");
        }
        return m_sibling_hashes[next_sibling++];
        // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast))
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

    uint64_t do_read_x(int reg) {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::x0, reg));
    }

    void do_write_x(int reg, uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::x0, reg), val);
    }

    uint64_t do_read_f(int reg) {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::f0, reg));
    }

    void do_write_f(int reg, uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::f0, reg), val);
    }

    uint64_t do_read_pc() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::pc));
    }

    void do_write_pc(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::pc), val);
    }

    uint64_t do_read_fcsr() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::fcsr));
    }

    void do_write_fcsr(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::fcsr), val);
    }

    uint64_t do_read_icycleinstret() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::icycleinstret));
    }

    void do_write_icycleinstret(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::icycleinstret), val);
    }

    uint64_t do_read_mvendorid() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mvendorid));
    }

    uint64_t do_read_marchid() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::marchid));
    }

    uint64_t do_read_mimpid() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mimpid));
    }

    uint64_t do_read_mcycle() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mcycle));
    }

    void do_write_mcycle(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mcycle), val);
    }

    uint64_t do_read_mstatus() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mstatus));
    }

    void do_write_mstatus(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mstatus), val);
    }

    uint64_t do_read_mtvec() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mtvec));
    }

    void do_write_mtvec(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mtvec), val);
    }

    uint64_t do_read_mscratch() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mscratch));
    }

    void do_write_mscratch(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mscratch), val);
    }

    uint64_t do_read_mepc() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mepc));
    }

    void do_write_mepc(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mepc), val);
    }

    uint64_t do_read_mcause() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mcause));
    }

    void do_write_mcause(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mcause), val);
    }

    uint64_t do_read_mtval() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mtval));
    }

    void do_write_mtval(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mtval), val);
    }

    uint64_t do_read_misa() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::misa));
    }

    void do_write_misa(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::misa), val);
    }

    uint64_t do_read_mie() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mie));
    }

    void do_write_mie(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mie), val);
    }

    uint64_t do_read_mip() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mip));
    }

    void do_write_mip(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mip), val);
    }

    uint64_t do_read_medeleg() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::medeleg));
    }

    void do_write_medeleg(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::medeleg), val);
    }

    uint64_t do_read_mideleg() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mideleg));
    }

    void do_write_mideleg(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mideleg), val);
    }

    uint64_t do_read_mcounteren() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::mcounteren));
    }

    void do_write_mcounteren(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::mcounteren), val);
    }

    uint64_t do_read_senvcfg() const {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::senvcfg));
    }

    void do_write_senvcfg(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::senvcfg), val);
    }

    uint64_t do_read_menvcfg() const {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::menvcfg));
    }

    void do_write_menvcfg(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::menvcfg), val);
    }

    uint64_t do_read_stvec() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::stvec));
    }

    void do_write_stvec(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::stvec), val);
    }

    uint64_t do_read_sscratch() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::sscratch));
    }

    void do_write_sscratch(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::sscratch), val);
    }

    uint64_t do_read_sepc() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::sepc));
    }

    void do_write_sepc(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::sepc), val);
    }

    uint64_t do_read_scause() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::scause));
    }

    void do_write_scause(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::scause), val);
    }

    uint64_t do_read_stval() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::stval));
    }

    void do_write_stval(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::stval), val);
    }

    uint64_t do_read_satp() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::satp));
    }

    void do_write_satp(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::satp), val);
    }

    uint64_t do_read_scounteren() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::scounteren));
    }

    void do_write_scounteren(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::scounteren), val);
    }

    uint64_t do_read_ilrsc() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::ilrsc));
    }

    void do_write_ilrsc(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::ilrsc), val);
    }

    uint64_t do_read_iprv() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::iprv));
    }

    void do_write_iprv(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::iprv), val);
    }

    uint64_t do_read_iflags_X() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::iflags_X));
    }

    void do_write_iflags_X(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::iflags_X), val);
    }

    uint64_t do_read_iflags_Y() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::iflags_Y));
    }

    void do_write_iflags_Y(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::iflags_Y), val);
    }

    uint64_t do_read_iflags_H() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::iflags_H));
    }

    void do_write_iflags_H(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::iflags_H), val);
    }

    uint64_t do_read_iunrep() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::iunrep));
    }

    void do_write_iunrep(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::iunrep), val);
    }

    uint64_t do_read_clint_mtimecmp() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::clint_mtimecmp));
    }

    void do_write_clint_mtimecmp(uint64_t val) {
        raw_write_memory<uint64_t>(machine_reg_address(machine_reg::clint_mtimecmp), val);
    }

    uint64_t do_read_plic_girqpend() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::plic_girqpend));
    }

    void do_write_plic_girqpend(uint64_t val) {
        raw_write_memory<uint64_t>(machine_reg_address(machine_reg::plic_girqpend), val);
    }

    uint64_t do_read_plic_girqsrvd() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::plic_girqsrvd));
    }

    void do_write_plic_girqsrvd(uint64_t val) {
        raw_write_memory<uint64_t>(machine_reg_address(machine_reg::plic_girqsrvd), val);
    }

    uint64_t do_read_htif_fromhost() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::htif_fromhost));
    }

    void do_write_htif_fromhost(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::htif_fromhost), val);
    }

    uint64_t do_read_htif_tohost() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::htif_tohost));
    }

    void do_write_htif_tohost(uint64_t val) {
        raw_write_memory(machine_reg_address(machine_reg::htif_tohost), val);
    }

    uint64_t do_read_htif_ihalt() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::htif_ihalt));
    }

    uint64_t do_read_htif_iconsole() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::htif_iconsole));
    }

    uint64_t do_read_htif_iyield() {
        return raw_read_memory<uint64_t>(machine_reg_address(machine_reg::htif_iyield));
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    std::pair<uint64_t, bool> do_poll_external_interrupts(uint64_t mcycle, uint64_t mcycle_max) {
        (void) mcycle_max;
        return {mcycle, false};
    }

    uint64_t do_read_pma_istart(int i) {
        return raw_read_memory<uint64_t>(shadow_pmas_get_pma_abs_addr(i));
    }

    uint64_t do_read_pma_ilength(int i) {
        return raw_read_memory<uint64_t>(shadow_pmas_get_pma_abs_addr(i) + sizeof(uint64_t));
    }

    template <typename T>
    void do_read_memory_word(uint64_t paddr, const unsigned char *hpage, uint64_t hoffset, T *pval) {
        (void) hpage;
        (void) hoffset;
        *pval = raw_read_memory<T>(paddr);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_read_memory(uint64_t paddr, const unsigned char *data, uint64_t length) {
        (void) paddr;
        (void) data;
        (void) length;
        return false;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    bool do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) {
        (void) paddr;
        (void) data;
        (void) length;
        return false;
    }

    template <typename T>
    void do_write_memory_word(uint64_t paddr, const unsigned char *hpage, uint64_t hoffset, T val) {
        (void) hpage;
        (void) hoffset;
        raw_write_memory(paddr, val);
    }

    template <typename T>
    mock_pma_entry &do_find_pma_entry(uint64_t paddr) {
        for (size_t i = 0; i < m_pmas.size(); i++) {
            auto &pma = get_pma_entry(static_cast<int>(i));
            if (pma.get_istart_E()) {
                return pma;
            }
            if (paddr >= pma.get_start() && paddr - pma.get_start() <= pma.get_length() - sizeof(T)) {
                return pma;
            }
        }
        interop_throw_runtime_error("do_find_pma_entry failed to find address");
    }

    mock_pma_entry &do_get_pma_entry(int index) {
        const uint64_t istart = read_pma_istart(index);
        const uint64_t ilength = read_pma_ilength(index);
        if (!m_pmas[index]) {
            m_pmas[index] = build_mock_pma_entry(index, istart, ilength);
        }
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        return m_pmas[index].value();
    }

    unsigned char *do_get_host_memory(mock_pma_entry &pma) { // NOLINT(readability-convert-member-functions-to-static)
        (void) pma;
        return nullptr;
    }

    bool do_read_device(mock_pma_entry &pma, uint64_t mcycle, uint64_t offset, uint64_t *pval, int log2_size) {
        device_state_access da(*this, mcycle);
        return pma.get_device_driver()->read(pma.get_device_context(), &da, offset, pval, log2_size);
    }

    execute_status do_write_device(mock_pma_entry &pma, uint64_t mcycle, uint64_t offset, uint64_t val, int log2_size) {
        device_state_access da(*this, mcycle);
        return pma.get_device_driver()->write(pma.get_device_context(), &da, offset, val, log2_size);
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    mock_pma_entry build_mock_pma_entry(int index, uint64_t istart, uint64_t ilength) {
        uint64_t start{};
        mock_pma_entry::flags flags{};
        split_istart(istart, start, flags);
        const pma_driver *driver = nullptr;
        void *device_ctx = nullptr;
        if (flags.IO) {
            switch (flags.DID) {
                case PMA_ISTART_DID::shadow_state:
                    driver = &shadow_state_driver;
                    break;
                case PMA_ISTART_DID::shadow_pmas:
                    driver = &shadow_pmas_driver;
                    break;
                case PMA_ISTART_DID::shadow_TLB:
                    driver = &shadow_tlb_driver;
                    break;
                case PMA_ISTART_DID::CLINT:
                    driver = &clint_driver;
                    break;
                case PMA_ISTART_DID::PLIC:
                    driver = &plic_driver;
                    break;
                case PMA_ISTART_DID::HTIF:
                    driver = &htif_driver;
                    break;
                default:
                    interop_throw_runtime_error("Unsupported device in build_mock_pma_entry");
                    break;
            }
        }
        return mock_pma_entry{index, start, ilength, flags, driver, device_ctx};
    }

    static constexpr void split_istart(uint64_t istart, uint64_t &start, mock_pma_entry::flags &f) {
        f.M = ((istart & PMA_ISTART_M_MASK) >> PMA_ISTART_M_SHIFT) != 0;
        f.IO = ((istart & PMA_ISTART_IO_MASK) >> PMA_ISTART_IO_SHIFT) != 0;
        f.E = ((istart & PMA_ISTART_E_MASK) >> PMA_ISTART_E_SHIFT) != 0;
        f.R = ((istart & PMA_ISTART_R_MASK) >> PMA_ISTART_R_SHIFT) != 0;
        f.W = ((istart & PMA_ISTART_W_MASK) >> PMA_ISTART_W_SHIFT) != 0;
        f.X = ((istart & PMA_ISTART_X_MASK) >> PMA_ISTART_X_SHIFT) != 0;
        f.IR = ((istart & PMA_ISTART_IR_MASK) >> PMA_ISTART_IR_SHIFT) != 0;
        f.IW = ((istart & PMA_ISTART_IW_MASK) >> PMA_ISTART_IW_SHIFT) != 0;
        f.DID = static_cast<PMA_ISTART_DID>((istart & PMA_ISTART_DID_MASK) >> PMA_ISTART_DID_SHIFT);
        start = istart & PMA_ISTART_START_MASK;
    }

    template <TLB_entry_type ETYPE>
    volatile tlb_hot_entry &do_get_tlb_hot_entry(uint64_t eidx) {
        auto addr = tlb_get_entry_hot_abs_addr<ETYPE>(eidx);
        auto size = sizeof(tlb_hot_entry);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        volatile tlb_hot_entry *tlbe = reinterpret_cast<tlb_hot_entry *>(get_raw_memory_pointer(addr, size));
        return *tlbe;
    }

    template <TLB_entry_type ETYPE>
    volatile tlb_cold_entry &do_get_tlb_entry_cold(uint64_t eidx) {
        auto addr = tlb_get_entry_cold_abs_addr<ETYPE>(eidx);
        auto size = sizeof(tlb_cold_entry);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        volatile tlb_cold_entry *tlbe = reinterpret_cast<tlb_cold_entry *>(get_raw_memory_pointer(addr, size));
        return *tlbe;
    }

    template <TLB_entry_type ETYPE, typename T>
    bool do_translate_vaddr_via_tlb(uint64_t vaddr, unsigned char **phptr) {
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        const volatile tlb_hot_entry &tlbhe = do_get_tlb_hot_entry<ETYPE>(eidx);
        if (tlb_is_hit<T>(tlbhe.vaddr_page, vaddr)) {
            *phptr = cast_addr_to_ptr<unsigned char *>(tlbhe.vh_offset + vaddr);
            return true;
        }
        return false;
    }

    template <TLB_entry_type ETYPE, typename T>
    bool do_read_memory_word_via_tlb(uint64_t vaddr, T *pval) {
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        const volatile tlb_hot_entry &tlbhe = do_get_tlb_hot_entry<ETYPE>(eidx);
        if (tlb_is_hit<T>(tlbhe.vaddr_page, vaddr)) {
            const uint64_t poffset = vaddr & PAGE_OFFSET_MASK;
            const volatile tlb_cold_entry &tlbce = do_get_tlb_entry_cold<ETYPE>(eidx);
            *pval = raw_read_memory<T>(tlbce.paddr_page + poffset);
            return true;
        }
        return false;
    }

    template <TLB_entry_type ETYPE, typename T>
    bool do_write_memory_word_via_tlb(uint64_t vaddr, T val) {
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        const volatile tlb_hot_entry &tlbhe = do_get_tlb_hot_entry<ETYPE>(eidx);
        if (tlb_is_hit<T>(tlbhe.vaddr_page, vaddr)) {
            const uint64_t poffset = vaddr & PAGE_OFFSET_MASK;
            const volatile tlb_cold_entry &tlbce = do_get_tlb_entry_cold<ETYPE>(eidx);
            raw_write_memory(tlbce.paddr_page + poffset, val);
            return true;
        }
        return false;
    }

    template <TLB_entry_type ETYPE>
    unsigned char *do_replace_tlb_entry(uint64_t vaddr, uint64_t paddr, mock_pma_entry &pma) {
        const uint64_t eidx = tlb_get_entry_index(vaddr);
        volatile tlb_hot_entry &tlbhe = do_get_tlb_hot_entry<ETYPE>(eidx);
        volatile tlb_cold_entry &tlbce = do_get_tlb_entry_cold<ETYPE>(eidx);
        if constexpr (ETYPE == TLB_WRITE) {
            if (tlbhe.vaddr_page != TLB_INVALID_PAGE) {
                mock_pma_entry &pma = do_get_pma_entry(static_cast<int>(tlbce.pma_index));
                pma.mark_dirty_page(tlbce.paddr_page - pma.get_start());
            }
        }
        const uint64_t vaddr_page = vaddr & ~PAGE_OFFSET_MASK;
        const uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;

        auto *page_type = find_page(paddr_page);
        auto *hpage = page_type->data;

        tlbhe.vaddr_page = vaddr_page;
        tlbhe.vh_offset = cast_ptr_to_addr<uint64_t>(hpage) - vaddr_page;
        tlbce.paddr_page = paddr_page;
        tlbce.pma_index = static_cast<uint64_t>(pma.get_index());
        return hpage;
    }

    template <TLB_entry_type ETYPE>
    void do_flush_tlb_entry(uint64_t eidx) {
        volatile tlb_hot_entry &tlbhe = do_get_tlb_hot_entry<ETYPE>(eidx);
        // Mark page that was on TLB as dirty so we know to update the Merkle tree
        if constexpr (ETYPE == TLB_WRITE) {
            if (tlbhe.vaddr_page != TLB_INVALID_PAGE) {
                tlbhe.vaddr_page = TLB_INVALID_PAGE;
                const volatile tlb_cold_entry &tlbce = do_get_tlb_entry_cold<ETYPE>(eidx);
                mock_pma_entry &pma = do_get_pma_entry(static_cast<int>(tlbce.pma_index));
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
        do_flush_tlb_type<TLB_CODE>();
        do_flush_tlb_type<TLB_READ>();
        do_flush_tlb_type<TLB_WRITE>();
    }

    bool do_get_soft_yield() { // NOLINT(readability-convert-member-functions-to-static)
        return false;
    }
};

} // namespace cartesi

#endif
