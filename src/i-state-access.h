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

#include <cstdint>
#include <type_traits>

#include "meta.h"
#include "shadow-tlb.h"

namespace cartesi {

// Forward declarations
enum class bracket_type;

/// \class i_state_access
/// \brief Interface for machine state access.
/// \details \{
/// The final "step" function must log all read and write accesses to the state.
/// The "run" function does not need a log, and must be as fast as possible.
/// Both functions share the exact same implementation of what it means to advance the machine state by one cycle.
/// In this common implementation, all state accesses go through a class that implements the i_state_access interface.
/// When looging is needed, a logged_state_access class is used.
/// When no logging is needed, a state_access class is used.
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
template <typename DERIVED, typename PMA_ENTRY_TYPE>
class i_state_access { // CRTP

    /// \brief Returns object cast as the derived class
    DERIVED &derived() {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived() const {
        return *static_cast<const DERIVED *>(this);
    }

public:
    /// \brief Returns machine state for direct access.
    auto &get_naked_state() {
        return derived().do_get_naked_state();
    }

    /// \brief Adds an annotation bracket to the log
    /// \param type Type of bracket
    /// \param text String with the text for the annotation
    void push_bracket(bracket_type type, const char *text) {
        return derived().do_push_bracket(type, text);
    }

    /// \brief Adds annotations to the state, bracketing a scope
    /// \param text String with the text for the annotation
    /// \returns An object that, when constructed and destroyed issues an annonation.
    auto make_scoped_note(const char *text) {
        return derived().do_make_scoped_note(text);
    }

    /// \brief Reads from general-purpose register.
    /// \param reg Register index.
    /// \returns Register value.
    uint64_t read_x(int reg) {
        return derived().do_read_x(reg);
    }

    /// \brief Writes register to general-purpose register.
    /// \param reg Register index.
    /// \param val New register value.
    /// \details Writes to register zero *break* the machine. There is an assertion to catch this, but NDEBUG will let
    /// the value pass through.
    void write_x(int reg, uint64_t val) {
        return derived().do_write_x(reg, val);
    }

    /// \brief Reads from floating-point register.
    /// \param reg Register index.
    /// \returns Register value.
    uint64_t read_f(int reg) {
        return derived().do_read_f(reg);
    }

    /// \brief Writes register to floating-point register.
    /// \param reg Register index.
    /// \param val New register value.
    void write_f(int reg, uint64_t val) {
        return derived().do_write_f(reg, val);
    }

    /// \brief Reads the program counter.
    /// \returns Register value.
    uint64_t read_pc() {
        return derived().do_read_pc();
    }

    /// \brief Writes the program counter.
    /// \param val New register value.
    void write_pc(uint64_t val) {
        return derived().do_write_pc(val);
    }

    /// \brief Writes CSR fcsr.
    /// \param val New register value.
    void write_fcsr(uint64_t val) {
        return derived().do_write_fcsr(val);
    }

    /// \brief Reads CSR fcsr.
    /// \returns Register value.
    uint64_t read_fcsr() {
        return derived().do_read_fcsr();
    }

    /// \brief Reads CSR icycleinstret.
    /// \returns Register value.
    uint64_t read_icycleinstret() {
        return derived().do_read_icycleinstret();
    }

    /// \brief Writes CSR icycleinstret.
    /// \param val New register value.
    void write_icycleinstret(uint64_t val) {
        return derived().do_write_icycleinstret(val);
    }

    /// \brief Reads CSR mvendorid.
    /// \returns Register value.
    uint64_t read_mvendorid() {
        return derived().do_read_mvendorid();
    }

    /// \brief Reads CSR marchid.
    /// \returns Register value.
    uint64_t read_marchid() {
        return derived().do_read_marchid();
    }

    /// \brief Reads CSR mimpid.
    /// \returns Register value.
    uint64_t read_mimpid() {
        return derived().do_read_mimpid();
    }

    /// \brief Reads CSR mcycle.
    /// \returns Register value.
    uint64_t read_mcycle() {
        return derived().do_read_mcycle();
    }

    /// \brief Writes CSR mcycle.
    /// \param val New register value.
    void write_mcycle(uint64_t val) {
        return derived().do_write_mcycle(val);
    }

    /// \brief Reads CSR mstatus.
    /// \returns Register value.
    uint64_t read_mstatus() {
        return derived().do_read_mstatus();
    }

    /// \brief Writes CSR mstatus.
    /// \param val New register value.
    void write_mstatus(uint64_t val) {
        return derived().do_write_mstatus(val);
    }

    /// \brief Reads CSR menvcfg.
    /// \returns Register value.
    uint64_t read_menvcfg() {
        return derived().do_read_menvcfg();
    }

    /// \brief Writes CSR menvcfg.
    /// \param val New register value.
    void write_menvcfg(uint64_t val) {
        return derived().do_write_menvcfg(val);
    }

    /// \brief Reads CSR mtvec.
    /// \returns Register value.
    uint64_t read_mtvec() {
        return derived().do_read_mtvec();
    }

    /// \brief Writes CSR mtvec.
    /// \param val New register value.
    void write_mtvec(uint64_t val) {
        return derived().do_write_mtvec(val);
    }

    /// \brief Reads CSR mscratch.
    /// \returns Register value.
    uint64_t read_mscratch() {
        return derived().do_read_mscratch();
    }

    /// \brief Writes CSR mscratch.
    /// \param val New register value.
    void write_mscratch(uint64_t val) {
        return derived().do_write_mscratch(val);
    }

    /// \brief Reads CSR mepc.
    /// \returns Register value.
    uint64_t read_mepc() {
        return derived().do_read_mepc();
    }

    /// \brief Writes CSR mepc.
    /// \param val New register value.
    void write_mepc(uint64_t val) {
        return derived().do_write_mepc(val);
    }

    /// \brief Reads CSR mcause.
    /// \returns Register value.
    uint64_t read_mcause() {
        return derived().do_read_mcause();
    }

    /// \brief Writes CSR mcause.
    /// \param val New register value.
    void write_mcause(uint64_t val) {
        return derived().do_write_mcause(val);
    }

    /// \brief Reads CSR mtval.
    /// \returns Register value.
    uint64_t read_mtval() {
        return derived().do_read_mtval();
    }

    /// \brief Writes CSR mtval.
    /// \param val New register value.
    void write_mtval(uint64_t val) {
        return derived().do_write_mtval(val);
    }

    /// \brief Reads CSR misa.
    /// \returns Register value.
    uint64_t read_misa() {
        return derived().do_read_misa();
    }

    /// \brief Writes CSR misa.
    /// \param val New register value.
    void write_misa(uint64_t val) {
        return derived().do_write_misa(val);
    }

    /// \brief Reads CSR mie.
    /// \returns Register value.
    uint64_t read_mie() {
        return derived().do_read_mie();
    }

    /// \brief Writes CSR mie.
    /// \param val New register value.
    void write_mie(uint64_t val) {
        return derived().do_write_mie(val);
    }

    /// \brief Reads CSR mip.
    /// \returns Register value.
    uint64_t read_mip() {
        return derived().do_read_mip();
    }

    /// \brief Writes CSR mip.
    /// \param val New register value.
    void write_mip(uint64_t val) {
        return derived().do_write_mip(val);
    }

    /// \brief Reads CSR medeleg.
    /// \returns Register value.
    uint64_t read_medeleg() {
        return derived().do_read_medeleg();
    }

    /// \brief Writes CSR medeleg.
    /// \param val New register value.
    void write_medeleg(uint64_t val) {
        return derived().do_write_medeleg(val);
    }

    /// \brief Reads CSR mideleg.
    /// \returns Register value.
    uint64_t read_mideleg() {
        return derived().do_read_mideleg();
    }

    /// \brief Writes CSR mideleg.
    /// \param val New register value.
    void write_mideleg(uint64_t val) {
        return derived().do_write_mideleg(val);
    }

    /// \brief Reads CSR iflags.
    /// \returns Register value.
    auto read_iflags() {
        return derived().do_read_iflags();
    }

    /// \brief Writes CSR iflags.
    /// \param val New register value.
    auto write_iflags(uint64_t val) {
        return derived().do_write_iflags(val);
    }

    /// \brief Reads CSR mcounteren.
    /// \returns Register value.
    uint64_t read_mcounteren() {
        return derived().do_read_mcounteren();
    }

    /// \brief Writes CSR mcounteren.
    /// \param val New register value.
    void write_mcounteren(uint64_t val) {
        return derived().do_write_mcounteren(val);
    }

    /// \brief Reads CSR senvcfg.
    /// \returns Register value.
    uint64_t read_senvcfg() {
        return derived().do_read_senvcfg();
    }

    /// \brief Writes CSR senvcfg.
    /// \param val New register value.
    void write_senvcfg(uint64_t val) {
        return derived().do_write_senvcfg(val);
    }

    /// \brief Reads CSR stvec.
    /// \returns Register value.
    uint64_t read_stvec() {
        return derived().do_read_stvec();
    }

    /// \brief Writes CSR stvec.
    /// \param val New register value.
    void write_stvec(uint64_t val) {
        return derived().do_write_stvec(val);
    }

    /// \brief Reads CSR sscratch.
    /// \returns Register value.
    uint64_t read_sscratch() {
        return derived().do_read_sscratch();
    }

    /// \brief Writes CSR sscratch.
    /// \param val New register value.
    void write_sscratch(uint64_t val) {
        return derived().do_write_sscratch(val);
    }

    /// \brief Reads CSR sepc.
    /// \returns Register value.
    uint64_t read_sepc() {
        return derived().do_read_sepc();
    }

    /// \brief Writes CSR sepc.
    /// \param val New register value.
    void write_sepc(uint64_t val) {
        return derived().do_write_sepc(val);
    }

    /// \brief Reads CSR scause.
    /// \returns Register value.
    uint64_t read_scause() {
        return derived().do_read_scause();
    }

    /// \brief Writes CSR scause.
    /// \param val New register value.
    void write_scause(uint64_t val) {
        return derived().do_write_scause(val);
    }

    /// \brief Reads CSR stval.
    /// \returns Register value.
    uint64_t read_stval() {
        return derived().do_read_stval();
    }

    /// \brief Writes CSR stval.
    /// \param val New register value.
    void write_stval(uint64_t val) {
        return derived().do_write_stval(val);
    }

    /// \brief Reads CSR satp.
    /// \returns Register value.
    uint64_t read_satp() {
        return derived().do_read_satp();
    }

    /// \brief Writes CSR satp.
    /// \param val New register value.
    void write_satp(uint64_t val) {
        return derived().do_write_satp(val);
    }

    /// \brief Reads CSR scounteren.
    /// \returns Register value.
    uint64_t read_scounteren() {
        return derived().do_read_scounteren();
    }

    /// \brief Writes CSR scounteren.
    /// \param val New register value.
    void write_scounteren(uint64_t val) {
        return derived().do_write_scounteren(val);
    }

    /// \brief Reads CSR ilrsc.
    /// \returns Register value.
    /// \details This is Cartesi-specific.
    uint64_t read_ilrsc() {
        return derived().do_read_ilrsc();
    }

    /// \brief Writes CSR ilrsc.
    /// \param val New register value.
    /// \details This is Cartesi-specific.
    void write_ilrsc(uint64_t val) {
        return derived().do_write_ilrsc(val);
    }

    /// \brief Sets the iflags_H flag.
    /// \details This is Cartesi-specific.
    void set_iflags_H() {
        return derived().do_set_iflags_H();
    }

    /// \brief Reads the iflags_H flag.
    /// \returns The flag value.
    /// \details This is Cartesi-specific.
    bool read_iflags_H() {
        return derived().do_read_iflags_H();
    }

    /// \brief Sets the iflags_Y flag.
    /// \details This is Cartesi-specific.
    void set_iflags_Y() {
        return derived().do_set_iflags_Y();
    }

    /// \brief Sets the iflags_X flag.
    /// \details This is Cartesi-specific.
    void set_iflags_X() {
        return derived().do_set_iflags_X();
    }

    /// \brief Resets the iflags_Y flag.
    /// \details This is Cartesi-specific.
    void reset_iflags_Y() {
        return derived().do_reset_iflags_Y();
    }

    /// \brief Resets the iflags_X flag.
    /// \details This is Cartesi-specific.
    void reset_iflags_X() {
        return derived().do_reset_iflags_X();
    }

    /// \brief Reads the iflags_Y flag.
    /// \returns The flag value.
    /// \details This is Cartesi-specific.
    bool read_iflags_Y() {
        return derived().do_read_iflags_Y();
    }

    /// \brief Reads the iflags_X flag.
    /// \returns The flag value.
    /// \details This is Cartesi-specific.
    bool read_iflags_X() {
        return derived().do_read_iflags_X();
    }

    /// \brief Reads the current privilege mode from iflags_PRV.
    /// \details This is Cartesi-specific.
    /// \returns Current privilege mode.
    uint8_t read_iflags_PRV() {
        return derived().do_read_iflags_PRV();
    }

    /// \brief Changes the privilege mode in iflags_PRV.
    /// \details This is Cartesi-specific.
    void write_iflags_PRV(uint8_t val) {
        return derived().do_write_iflags_PRV(val);
    }

    /// \brief Reads CSR iunrep.
    /// \returns Register value.
    /// \details This is Cartesi-specific.
    uint64_t read_iunrep() {
        return derived().do_read_iunrep();
    }

    /// \brief Writes CSR iunrep.
    /// \param val New register value.
    /// \details This is Cartesi-specific.
    void write_iunrep(uint64_t val) {
        return derived().do_write_iunrep(val);
    }

    /// \brief Reads CLINT's mtimecmp.
    /// \returns Register value.
    uint64_t read_clint_mtimecmp() {
        return derived().do_read_clint_mtimecmp();
    }

    /// \brief Writes CLINT's mtimecmp.
    /// \param val New register value.
    void write_clint_mtimecmp(uint64_t val) {
        return derived().do_write_clint_mtimecmp(val);
    }

    /// \brief Reads PLIC's girqpend.
    /// \returns Register value.
    uint64_t read_plic_girqpend() {
        return derived().do_read_plic_girqpend();
    }

    /// \brief Writes PLIC's girqpend.
    /// \param val New register value.
    void write_plic_girqpend(uint64_t val) {
        return derived().do_write_plic_girqpend(val);
    }

    /// \brief Reads PLIC's girqsrvd.
    /// \returns Register value.
    uint64_t read_plic_girqsrvd() {
        return derived().do_read_plic_girqsrvd();
    }

    /// \brief Writes PLIC's girqsrvd.
    /// \param val New register value.
    void write_plic_girqsrvd(uint64_t val) {
        return derived().do_write_plic_girqsrvd(val);
    }

    /// \brief Reads HTIF's fromhost.
    /// \returns Register value.
    uint64_t read_htif_fromhost() {
        return derived().do_read_htif_fromhost();
    }

    /// \brief Writes HTIF's fromhost.
    /// \param val New register value.
    void write_htif_fromhost(uint64_t val) {
        return derived().do_write_htif_fromhost(val);
    }

    /// \brief Reads HTIF's tohost.
    /// \returns Register value.
    uint64_t read_htif_tohost() {
        return derived().do_read_htif_tohost();
    }

    /// \brief Writes HTIF's tohost.
    /// \param val New register value.
    void write_htif_tohost(uint64_t val) {
        return derived().do_write_htif_tohost(val);
    }

    /// \brief Reads HTIF's ihalt.
    /// \returns Register value.
    uint64_t read_htif_ihalt() {
        return derived().do_read_htif_ihalt();
    }

    /// \brief Reads HTIF's iconsole.
    /// \returns Register value.
    uint64_t read_htif_iconsole() {
        return derived().do_read_htif_iconsole();
    }

    /// \brief Reads HTIF's iyield.
    /// \returns Register value.
    uint64_t read_htif_iyield() {
        return derived().do_read_htif_iyield();
    }

    /// \brief Poll for external interrupts.
    /// \param mcycle Current machine mcycle.
    /// \param mcycle_max Maximum mcycle to wait for interrupts.
    /// \returns A pair, the first value is the new machine mcycle advanced by the relative elapsed time while
    /// polling, the second value is a boolean that is true when the poll is stopped due do an external interrupt
    /// request.
    /// \details When mcycle_max is greater than mcycle, this function will sleep until an external interrupt
    /// is triggered or mcycle_max relative elapsed time is reached.
    std::pair<uint64_t, bool> poll_external_interrupts(uint64_t mcycle, uint64_t mcycle_max) {
        return derived().do_poll_external_interrupts(mcycle, mcycle_max);
    }

    /// \brief Reads PMA at a given index.
    /// \param pma PMA entry.
    /// \param i Index of PMA index.
    void read_pma(const PMA_ENTRY_TYPE &pma, int i) {
        return derived().do_read_pma(pma, i);
    }

    /// \brief Reads the istart field of a PMA entry
    /// \param p Index of PMA
    uint64_t read_pma_istart(int p) {
        return derived().do_read_pma_istart(p);
    }

    /// \brief Reads the ilength field of a PMA entry
    /// \param p Index of PMA
    uint64_t read_pma_ilength(int p) {
        return derived().do_read_pma_ilength(p);
    }

    /// \brief Reads a chunk of data from a memory PMA range.
    /// \param paddr Target physical address.
    /// \param data Receives chunk of memory.
    /// \param length Size of chunk.
    /// \returns True if PMA was found and memory fully read, false otherwise.
    /// \details The entire chunk of data must fit inside the same memory
    /// PMA range, otherwise it fails. The search for the PMA range is implicit, and not logged.
    bool read_memory(uint64_t paddr, unsigned char *data, uint64_t length) {
        return derived().do_read_memory(paddr, data, length);
    }

    /// \brief Writes a chunk of data to a memory PMA range.
    /// \param paddr Target physical address.
    /// \param data Pointer to chunk of data.
    /// \param length Size of chunk.
    /// \returns True if PMA was found and memory fully written, false otherwise.
    /// \details The entire chunk of data must fit inside the same memory
    /// PMA range, otherwise it fails. The search for the PMA range is implicit, and not logged.
    bool write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) {
        return derived().do_write_memory(paddr, data, length);
    }

    /// \brief Reads a word from memory.
    /// \tparam T Type of word to read.
    /// \param paddr Target physical address.
    /// \param hpage Pointer to page start in host memory.
    /// \param hoffset Offset in page (must be aligned to sizeof(T)).
    /// \param pval Pointer to word receiving value.
    template <typename T>
    void read_memory_word(uint64_t paddr, const unsigned char *hpage, uint64_t hoffset, T *pval) {
        static_assert(std::is_integral<T>::value && sizeof(T) <= sizeof(uint64_t), "unsupported type");
        return derived().template do_read_memory_word<T>(paddr, hpage, hoffset, pval);
    }

    /// \brief Writes a word to memory.
    /// \tparam T Type of word to write.
    /// \param paddr Target physical address.
    /// \param hpage Pointer to page start in host memory.
    /// \param hoffset Offset in page (must be aligned to sizeof(T)).
    /// \param val Value to be written.
    template <typename T>
    void write_memory_word(uint64_t paddr, unsigned char *hpage, uint64_t hoffset, T val) {
        static_assert(std::is_integral<T>::value && sizeof(T) <= sizeof(uint64_t), "unsupported type");
        return derived().template do_write_memory_word<T>(paddr, hpage, hoffset, val);
    }

    /// \brief Obtain PMA entry covering a physical memory word
    /// \param paddr Target physical address.
    /// \returns Corresponding entry if found, or a sentinel entry
    /// for an empty range.
    /// \tparam T Type of word.
    template <typename T>
    PMA_ENTRY_TYPE &find_pma_entry(uint64_t paddr) {
        return derived().template do_find_pma_entry<T>(paddr);
    }

    auto get_host_memory(PMA_ENTRY_TYPE &pma) {
        return derived().do_get_host_memory(pma);
    }

    PMA_ENTRY_TYPE &get_pma_entry(int index) {
        return derived().do_get_pma_entry(index);
    }

    auto read_device(PMA_ENTRY_TYPE &pma, uint64_t mcycle, uint64_t offset, uint64_t *pval, int log2_size) {
        return derived().do_read_device(pma, mcycle, offset, pval, log2_size);
    }

    auto write_device(PMA_ENTRY_TYPE &pma, uint64_t mcycle, uint64_t offset, uint64_t pval, int log2_size) {
        return derived().do_write_device(pma, mcycle, offset, pval, log2_size);
    }

    /// \brief Try to translate a virtual address to a host pointer through the TLB.
    /// \tparam ETYPE TLB entry type.
    /// \tparam T Type of word that would be read with the pointer.
    /// \param vaddr Target virtual address.
    /// \param phptr Pointer to host pointer receiving value.
    /// \returns True if successful (TLB hit), false otherwise.
    template <TLB_entry_type ETYPE, typename T>
    bool translate_vaddr_via_tlb(uint64_t vaddr, unsigned char **phptr) {
        return derived().template do_translate_vaddr_via_tlb<ETYPE, T>(vaddr, phptr);
    }

    /// \brief Try to read a word from memory through the TLB.
    /// \tparam ETYPE TLB entry type.
    /// \tparam T Type of word to read.
    /// \param vaddr Target virtual address.
    /// \param pval Pointer to word receiving value.
    /// \returns True if successful (TLB hit), false otherwise.
    template <TLB_entry_type ETYPE, typename T>
    bool read_memory_word_via_tlb(uint64_t vaddr, T *pval) {
        static_assert(std::is_integral<T>::value && sizeof(T) <= sizeof(uint64_t), "unsupported type");
        return derived().template do_read_memory_word_via_tlb<ETYPE, T>(vaddr, pval);
    }

    /// \brief Try to write a word to memory through the TLB.
    /// \tparam ETYPE TLB entry type.
    /// \tparam T Type of word to write.
    /// \param vaddr Target virtual address.
    /// \param val Value to be written.
    /// \returns True if successful (TLB hit), false otherwise.
    template <TLB_entry_type ETYPE, typename T>
    bool write_memory_word_via_tlb(uint64_t vaddr, T val) {
        static_assert(std::is_integral<T>::value && sizeof(T) <= sizeof(uint64_t), "unsupported type");
        return derived().template do_write_memory_word_via_tlb<ETYPE, T>(vaddr, val);
    }

    /// \brief Replaces an entry in the TLB.
    /// \tparam ETYPE TLB entry type to replace.
    /// \param vaddr Target virtual address.
    /// \param paddr Target physical address.
    /// \param pma PMA entry for the physical address.
    /// \returns Pointer to page start in host memory.
    template <TLB_entry_type ETYPE>
    unsigned char *replace_tlb_entry(uint64_t vaddr, uint64_t paddr, PMA_ENTRY_TYPE &pma) {
        return derived().template do_replace_tlb_entry<ETYPE>(vaddr, paddr, pma);
    }

    /// \brief Invalidates all TLB entries of a type.
    /// \tparam ETYPE TLB entry type to flush.
    template <TLB_entry_type ETYPE>
    void flush_tlb_type() {
        return derived().template do_flush_tlb_type<ETYPE>();
    }

    /// \brief Invalidates all TLB entries of all types.
    void flush_all_tlb() {
        derived().template flush_tlb_type<TLB_CODE>();
        derived().template flush_tlb_type<TLB_READ>();
        derived().template flush_tlb_type<TLB_WRITE>();
    }

    /// \brief Invalidates TLB entries for a specific virtual address.
    /// \param vaddr Target virtual address.
    void flush_tlb_vaddr(uint64_t vaddr) {
        return derived().do_flush_tlb_vaddr(vaddr);
    }

    /// \brief Returns true if soft yield HINT instruction is enabled at runtime
    bool get_soft_yield() {
        return derived().do_get_soft_yield();
    }

    /// \brief Write a data buffer to memory padded with 0
    /// \param paddr Destination physical address.
    /// \param data Pointer to source data buffer.
    /// \param data_length Length of data buffer.
    /// \param write_length_log2_size Log2 size of the total write length.
    void write_memory_with_padding(uint64_t paddr, const unsigned char *data, uint64_t data_length,
        int write_length_log2_size) {
        return derived().do_write_memory_with_padding(paddr, data, data_length, write_length_log2_size);
    }

#ifdef DUMP_COUNTERS
    auto &get_statistics() {
        return derived().do_get_statistics();
    }
#endif
};

/// \brief SFINAE test implementation of the i_state_access interface
template <typename DERIVED>
using is_an_i_state_access =
    std::integral_constant<bool, is_template_base_of<i_state_access, typename remove_cvref<DERIVED>::type>::value>;

} // namespace cartesi

#endif
