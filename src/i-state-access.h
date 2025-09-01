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

#ifndef I_STATE_ACCESS_H
#define I_STATE_ACCESS_H

/// \file
/// \brief State access interface

#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <type_traits>

#include "address-range.h"
#include "assert-printf.h"
#include "i-prefer-shadow-state.h"
#include "meta.h"
#include "poor-type-name.h"
#include "shadow-registers.h"
#include "shadow-tlb.h"

namespace cartesi {

// Forward declarations
enum class bracket_type;

// Type trait that should return the fast_addr type for a state access class
template <typename STATE_ACCESS>
struct i_state_access_fast_addr {};
template <typename STATE_ACCESS>
using i_state_access_fast_addr_t = typename i_state_access_fast_addr<STATE_ACCESS>::type;

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define DEFINE_SA_READ(REG)                                                                                            \
    uint64_t read_##REG() const {                                                                                      \
        if constexpr (!is_an_i_prefer_shadow_state_v<DERIVED>) {                                                       \
            const auto val = derived().do_read_##REG();                                                                \
            dsa_printf("%s::read_" #REG "() = %" PRIu64 "(0x%" PRIx64 ")\n", get_name(), val, val);                    \
            return val;                                                                                                \
        } else {                                                                                                       \
            return prefer_read_shadow_register(shadow_registers_what::REG);                                            \
        }                                                                                                              \
    }

#define DEFINE_SA_WRITE(REG)                                                                                           \
    void write_##REG(uint64_t val) const {                                                                             \
        if constexpr (!is_an_i_prefer_shadow_state_v<DERIVED>) {                                                       \
            derived().do_write_##REG(val);                                                                             \
            dsa_printf("%s::write_" #REG "(%" PRIu64 "(0x%" PRIx64 "))\n", get_name(), val, val);                      \
        } else {                                                                                                       \
            prefer_write_shadow_register(shadow_registers_what::REG, val);                                             \
        }                                                                                                              \
    }
// NOLINTEND(cppcoreguidelines-macro-usage)

/// \class i_state_access
/// \brief Interface for machine state access.
/// \details \{
/// The final "step" function must log all read and write accesses to the state.
/// The "run" function does not need a log, and must be as fast as possible.
/// Both functions share the exact same implementation of what it means to advance the machine state by one cycle.
/// In this common implementation, all state accesses go through a class that implements the i_state_access interface.
/// When logging is needed, a record state access class is used.
/// When no logging is needed, a direct state access class is used.
///
/// In a typical design, i_state_access would be pure virtual.
/// For speed, we avoid virtual methods and instead use templates.
/// State access classes inherit from i_state_access, and declare it as friend.
/// They then implement all private do_* methods.
/// Clients call the methods without the do_ prefix, which are inherited from the i_state_access
/// interface and simply forward the call to the methods with do_ prefix implemented by the derived class.
/// This is a form of "static polymorphism" that incurs no runtime cost
///
/// Methods are provided to read and write each state component.
/// \}
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
template <typename DERIVED>
class i_state_access { // CRTP
    i_state_access() = default;
    friend DERIVED;

    /// \brief Returns object cast as the derived class
    DERIVED &derived() {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived() const {
        return *static_cast<const DERIVED *>(this);
    }

    uint64_t prefer_read_shadow_register(shadow_registers_what what) const {
        const auto val = derived().read_shadow_register(what);
        [[maybe_unused]] const auto *const what_name = shadow_registers_get_what_name(what);
        dsa_printf("%s::read_shadow_register(%s) = %" PRIu64 "(0x%" PRIx64 ")\n", get_name(), what_name, val, val);
        return val;
    }

    void prefer_write_shadow_register(shadow_registers_what what, uint64_t val) const {
        derived().write_shadow_register(what, val);
        [[maybe_unused]] const auto *const what_name = shadow_registers_get_what_name(what);
        dsa_printf("%s::write_shadow_register(%s, %" PRIu64 "(0x%" PRIx64 "))\n", get_name(), what_name, val, val);
    }

public:
    using fast_addr = i_state_access_fast_addr_t<DERIVED>;

    /// \brief Works as vprintf if we are dumping state accesses, otherwise does nothing
    static void dsa_vprintf([[maybe_unused]] const char *fmt, [[maybe_unused]] va_list ap) {
#ifdef DUMP_STATE_ACCESS
        d_vprintf(fmt, ap);
#endif
    }

    /// \brief Works as printf if we are dumping state accesses, otherwise does nothing
    // Better to use C-style variadic function that checks for format!
    // NOLINTNEXTLINE(cert-dcl50-cpp)
    __attribute__((__format__(__printf__, 1, 2))) static void dsa_printf([[maybe_unused]] const char *fmt, ...) {
#ifdef DUMP_STATE_ACCESS
        va_list ap;
        va_start(ap, fmt);
        dsa_vprintf(fmt, ap);
        va_end(ap);
#endif
    }

    /// \brief Reads from general-purpose register.
    /// \param i Register index.
    /// \returns Register value.
    uint64_t read_x(int i) const {
        if constexpr (!is_an_i_prefer_shadow_state_v<DERIVED>) {
            const auto val = derived().do_read_x(i);
            dsa_printf("%s::read_x(%d) = %" PRIu64 "(0x%" PRIx64 ")\n", get_name(), i, val, val);
            return val;
        } else {
            return prefer_read_shadow_register(shadow_registers_get_what(shadow_registers_what::x0, i));
        }
    }

    /// \brief Writes register to general-purpose register.
    /// \param i Register index.
    /// \param val New register value.
    /// \details Writes to register zero *break* the machine.
    /// There is an assertion to catch this, but NDEBUG will let the value pass through.
    void write_x(int i, uint64_t val) const {
        if constexpr (!is_an_i_prefer_shadow_state_v<DERIVED>) {
            derived().do_write_x(i, val);
            dsa_printf("%s::write_x(%d, %" PRIu64 "(0x%" PRIx64 "))\n", get_name(), i, val, val);
        } else {
            prefer_write_shadow_register(shadow_registers_get_what(shadow_registers_what::x0, i), val);
        }
    }

    /// \brief Reads from floating-point register.
    /// \param i Register index.
    /// \returns Register value.
    uint64_t read_f(int i) const {
        if constexpr (!is_an_i_prefer_shadow_state_v<DERIVED>) {
            const auto val = derived().do_read_f(i);
            dsa_printf("%s::read_f(%d) = %" PRIu64 "(0x%" PRIx64 ")\n", get_name(), i, val, val);
            return val;
        } else {
            return prefer_read_shadow_register(shadow_registers_get_what(shadow_registers_what::f0, i));
        }
    }

    /// \brief Writes register to floating-point register.
    /// \param i Register index.
    /// \param val New register value.
    void write_f(int i, uint64_t val) const {
        if constexpr (!is_an_i_prefer_shadow_state_v<DERIVED>) {
            derived().do_write_f(i, val);
            dsa_printf("%s::write_f(%d, %" PRIu64 "(%" PRIx64 "))\n", get_name(), i, val, val);
        } else {
            prefer_write_shadow_register(shadow_registers_get_what(shadow_registers_what::f0, i), val);
        }
    }

    // Define read and write methods for each register in the shadow state
    // NOLINTBEGIN(cppcoreguidelines-macro-usage)
    DEFINE_SA_READ(pc)
    DEFINE_SA_WRITE(pc)
    DEFINE_SA_READ(fcsr)
    DEFINE_SA_WRITE(fcsr)
    DEFINE_SA_READ(mvendorid)
    DEFINE_SA_WRITE(mvendorid)
    DEFINE_SA_READ(marchid)
    DEFINE_SA_WRITE(marchid)
    DEFINE_SA_READ(mimpid)
    DEFINE_SA_WRITE(mimpid)
    DEFINE_SA_READ(mcycle)
    DEFINE_SA_WRITE(mcycle)
    DEFINE_SA_READ(icycleinstret)
    DEFINE_SA_WRITE(icycleinstret)
    DEFINE_SA_READ(mstatus)
    DEFINE_SA_WRITE(mstatus)
    DEFINE_SA_READ(mtvec)
    DEFINE_SA_WRITE(mtvec)
    DEFINE_SA_READ(mscratch)
    DEFINE_SA_WRITE(mscratch)
    DEFINE_SA_READ(mepc)
    DEFINE_SA_WRITE(mepc)
    DEFINE_SA_READ(mcause)
    DEFINE_SA_WRITE(mcause)
    DEFINE_SA_READ(mtval)
    DEFINE_SA_WRITE(mtval)
    DEFINE_SA_READ(misa)
    DEFINE_SA_WRITE(misa)
    DEFINE_SA_READ(mie)
    DEFINE_SA_WRITE(mie)
    DEFINE_SA_READ(mip)
    DEFINE_SA_WRITE(mip)
    DEFINE_SA_READ(medeleg)
    DEFINE_SA_WRITE(medeleg)
    DEFINE_SA_READ(mideleg)
    DEFINE_SA_WRITE(mideleg)
    DEFINE_SA_READ(mcounteren)
    DEFINE_SA_WRITE(mcounteren)
    DEFINE_SA_READ(menvcfg)
    DEFINE_SA_WRITE(menvcfg)
    DEFINE_SA_READ(stvec)
    DEFINE_SA_WRITE(stvec)
    DEFINE_SA_READ(sscratch)
    DEFINE_SA_WRITE(sscratch)
    DEFINE_SA_READ(sepc)
    DEFINE_SA_WRITE(sepc)
    DEFINE_SA_READ(scause)
    DEFINE_SA_WRITE(scause)
    DEFINE_SA_READ(stval)
    DEFINE_SA_WRITE(stval)
    DEFINE_SA_READ(satp)
    DEFINE_SA_WRITE(satp)
    DEFINE_SA_READ(scounteren)
    DEFINE_SA_WRITE(scounteren)
    DEFINE_SA_READ(senvcfg)
    DEFINE_SA_WRITE(senvcfg)
    DEFINE_SA_READ(ilrsc)
    DEFINE_SA_WRITE(ilrsc)
    DEFINE_SA_READ(iprv)
    DEFINE_SA_WRITE(iprv)
    DEFINE_SA_READ(iflags_X)
    DEFINE_SA_WRITE(iflags_X)
    DEFINE_SA_READ(iflags_Y)
    DEFINE_SA_WRITE(iflags_Y)
    DEFINE_SA_READ(iflags_H)
    DEFINE_SA_WRITE(iflags_H)
    DEFINE_SA_READ(iunrep)
    DEFINE_SA_WRITE(iunrep)
    DEFINE_SA_READ(clint_mtimecmp)
    DEFINE_SA_WRITE(clint_mtimecmp)
    DEFINE_SA_READ(plic_girqpend)
    DEFINE_SA_WRITE(plic_girqpend)
    DEFINE_SA_READ(plic_girqsrvd)
    DEFINE_SA_WRITE(plic_girqsrvd)
    DEFINE_SA_READ(htif_tohost)
    DEFINE_SA_WRITE(htif_tohost)
    DEFINE_SA_READ(htif_fromhost)
    DEFINE_SA_WRITE(htif_fromhost)
    DEFINE_SA_READ(htif_ihalt)
    DEFINE_SA_WRITE(htif_ihalt)
    DEFINE_SA_READ(htif_iconsole)
    DEFINE_SA_WRITE(htif_iconsole)
    DEFINE_SA_READ(htif_iyield)
    DEFINE_SA_WRITE(htif_iyield)
    // NOLINTEND(cppcoreguidelines-macro-usage)

    /// \brief Reads PMA entry at a given index.
    /// \param index Index of PMA
    address_range &read_pma(uint64_t index) const {
        auto &ar = derived().do_read_pma(index);
        dsa_printf("%s::read_address_range(%" PRIu64 ") = {%s, 0x%" PRIx64 ", 0x%" PRIx64 "}\n", get_name(), index,
            pmas_get_DID_name(ar.get_driver_id()), ar.get_start(), ar.get_length());
        return ar;
    }

    /// \brief Converts a target physical address to the implementation-defined fast address
    /// \param paddr Target physical address to convert
    /// \param pma_index Index of PMA where address falls
    /// \returns Corresponding implementation-defined fast address
    fast_addr get_faddr(uint64_t paddr, uint64_t pma_index) const {
        const auto val = derived().do_get_faddr(paddr, pma_index);
        [[maybe_unused]] const auto fast_addr_name = std::is_same_v<fast_addr, uint64_t> ? "phys_addr" : "fast_addr";
        dsa_printf("%s::get_faddr(%" PRIu64 "(0x%" PRIx64 ")) = %s{%" PRIu64 "(0x%" PRIx64 ")}\n", get_name(), paddr,
            paddr, fast_addr_name, static_cast<uint64_t>(val), static_cast<uint64_t>(val));
        return val;
    }

    /// \brief Reads a chunk of data from a memory PMA range.
    /// \param paddr Target physical address.
    /// \param data Receives chunk of memory.
    /// \param length Size of chunk.
    /// \returns True if PMA was found and memory fully read, false otherwise.
    /// \details The entire chunk of data must fit inside the same memory
    /// PMA range, otherwise it fails. The search for the PMA range is implicit, and not logged.
    bool read_memory(uint64_t paddr, unsigned char *data, uint64_t length) const {
        return derived().do_read_memory(paddr, data, length);
    }

    /// \brief Writes a chunk of data to a memory PMA range.
    /// \param paddr Target physical address.
    /// \param data Pointer to chunk of data.
    /// \param length Size of chunk.
    /// \returns True if PMA was found and memory fully written, false otherwise.
    /// \details The entire chunk of data must fit inside the same memory
    /// PMA range, otherwise it fails. The search for the PMA range is implicit, and not logged.
    bool write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) const {
        return derived().do_write_memory(paddr, data, length);
    }

    /// \brief Write a data buffer to memory padded with 0
    /// \param paddr Destination physical address.
    /// \param data Pointer to source data buffer.
    /// \param data_length Length of data buffer.
    /// \param write_length_log2_size Log2 size of the total write length.
    void write_memory_with_padding(uint64_t paddr, const unsigned char *data, uint64_t data_length,
        int write_length_log2_size) const {
        derived().do_write_memory_with_padding(paddr, data, data_length, write_length_log2_size);
    }

    /// \brief Reads a word from memory.
    /// \tparam T Type of word to read, potentially unaligned.
    /// \tparam A Type to which \p paddr and \p faddr are known to be aligned.
    /// \param faddr Implementation-defined fast address.
    /// \param pma_index Index of PMA where word falls.
    /// \param pval Pointer to word receiving value.
    /// \warning T must not cross page boundary starting from \p faddr.
    /// \warning T (when A is smaller) may or may not cross a hash tree word boundary starting from \p faddr!
    template <typename T, typename A = T>
    void read_memory_word(fast_addr faddr, uint64_t pma_index, T *pval) const {
        static_assert(std::is_integral_v<T> && sizeof(T) <= sizeof(uint64_t), "unsupported type");
        derived().template do_read_memory_word<T, A>(faddr, pma_index, pval);
        [[maybe_unused]] const auto fast_addr_name = std::is_same_v<fast_addr, uint64_t> ? "phys_addr" : "fast_addr";
        dsa_printf("%s::read_memory_word<%s,%s>(%s{0x%" PRIx64 "}, %" PRIu64 ") = %" PRIu64 "(0x%" PRIx64 ")\n",
            get_name(), poor_type_name_v<T>, poor_type_name_v<A>, fast_addr_name, static_cast<uint64_t>(faddr),
            pma_index, static_cast<uint64_t>(*pval), static_cast<uint64_t>(*pval));
    }

    /// \brief Writes a word to memory.
    /// \tparam T Type of word to write.
    /// \tparam A Type to which \p paddr and \p faddr are known to be aligned.
    /// \param faddr Implementation-defined fast address.
    /// \param val Value to be written.
    /// \warning T must not cross page boundary starting from \p faddr.
    /// \warning T (when A is smaller) may or may not cross a hash tree word boundary starting from \p faddr!
    template <typename T, typename A = T>
    void write_memory_word(fast_addr faddr, uint64_t pma_index, T val) const {
        static_assert(std::is_integral_v<T> && sizeof(T) <= sizeof(uint64_t), "unsupported type");
        derived().template do_write_memory_word<T, A>(faddr, pma_index, val);
        [[maybe_unused]] const auto fast_addr_name = std::is_same_v<fast_addr, uint64_t> ? "phys_addr" : "fast_addr";
        dsa_printf("%s::write_memory_word<%s,%s>(%s{0x%" PRIx64 "}, %" PRIu64 ", %" PRIu64 "(0x%" PRIx64 "))\n",
            get_name(), poor_type_name_v<T>, poor_type_name_v<A>, fast_addr_name, static_cast<uint64_t>(faddr),
            pma_index, static_cast<uint64_t>(val), static_cast<uint64_t>(val));
    }

    /// \brief Reads TLB's vaddr_page
    /// \tparam USE TLB set
    /// \param slot_index Slot index
    /// \returns Value in slot.
    template <TLB_set_index SET>
    uint64_t read_tlb_vaddr_page(uint64_t slot_index) const {
        const auto val = derived().template do_read_tlb_vaddr_page<SET>(slot_index);
        dsa_printf("%s::read_tlb_vaddr_page<%" PRIu64 ">(%" PRIu64 ") = 0x%" PRIx64 "\n", get_name(), SET, slot_index,
            val);
        return val;
    }

    /// \brief Reads TLB's vf_offset
    /// \tparam USE TLB set
    /// \param slot_index Slot index
    /// \returns Value in slot.
    template <TLB_set_index SET>
    fast_addr read_tlb_vf_offset(uint64_t slot_index) const {
        [[maybe_unused]] const auto fast_addr_name = std::is_same_v<fast_addr, uint64_t> ? "phys_addr" : "fast_addr";
        const auto val = derived().template do_read_tlb_vf_offset<SET>(slot_index);
        dsa_printf("%s::read_tlb_vf_offset<%" PRIu64 ">(%" PRIu64 ") = %s{0x%" PRIx64 "}\n", get_name(), SET,
            slot_index, fast_addr_name, static_cast<uint64_t>(val));
        return val;
    }

    /// \brief Reads TLB's pma_index
    /// \tparam USE TLB set
    /// \param slot_index Slot index
    /// \returns Value in slot.
    template <TLB_set_index SET>
    uint64_t read_tlb_pma_index(uint64_t slot_index) const {
        const auto val = derived().template do_read_tlb_pma_index<SET>(slot_index);
        dsa_printf("%s::read_tlb_pma_index<%" PRIu64 ">(%" PRIu64 ") = %" PRIu64 "(0x%" PRIx64 ")\n", get_name(), SET,
            slot_index, val, val);
        return val;
    }

    /// \brief Writes to a TLB slot
    /// \tparam USE TLB set
    /// \param slot_index Slot index
    /// \param vaddr_page Value to write
    /// \param vf_offset Value to write
    /// \param pma_index Value to write
    /// \detail Writes to the TLB must be modify all fields atomically to prevent an inconsistent state.
    /// This simplifies all state access implementations.
    template <TLB_set_index SET>
    void write_tlb(uint64_t slot_index, uint64_t vaddr_page, fast_addr vf_offset, uint64_t pma_index) const {
        derived().template do_write_tlb<SET>(slot_index, vaddr_page, vf_offset, pma_index);
        [[maybe_unused]] const auto fast_addr_name = std::is_same_v<fast_addr, uint64_t> ? "phys_addr" : "fast_addr";
        dsa_printf("%s::write_tlb<%" PRIu64 ">(%" PRIu64 ", 0x%" PRIx64 ", %s{0x%" PRIx64 "}, %" PRIu64 ")\n",
            get_name(), SET, slot_index, vaddr_page, fast_addr_name, static_cast<uint64_t>(vf_offset), pma_index);
    }

    /// \brief Marks a page as dirty
    /// \param faddr Implementation-defined fast address.
    /// \param pma_index Index of PMA where page falls
    /// \details When there is a host machine, the hash tree only updates the hashes for pages that
    /// have been modified. Pages can only be written to if they appear in the write TLB. Therefore,
    /// the hash tree only considers the pages that are currently in the write TLB and those that
    /// have been marked dirty. When a page leaves the write TLB, it is marked dirty.
    /// If the state belongs to a host machine, then this call MUST be forwarded to machine::mark_dirty_page();
    void mark_dirty_page(fast_addr faddr, uint64_t pma_index) const {
        derived().do_mark_dirty_page(faddr, pma_index);
    }

    /// \brief Writes a character to the console
    /// \param c Character to output
    void putchar(uint8_t c) const {
        derived().do_putchar(c);
    }

    constexpr const char *get_name() const {
        return derived().do_get_name();
    }
};

/// \brief SFINAE test implementation of the i_state_access interface
template <typename DERIVED>
using is_an_i_state_access =
    std::integral_constant<bool, is_template_base_of_v<i_state_access, std::remove_cvref_t<DERIVED>>>;

template <typename DERIVED>
constexpr bool is_an_i_state_access_v = is_an_i_state_access<DERIVED>::value;

} // namespace cartesi

#endif
