// Copyright 2020 Cartesi Pte. Ltd.
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

#ifndef I_VIRTUAL_MACHINE
#define I_VIRTUAL_MACHINE

#include <cstdint>

#include "machine.h"

namespace cartesi {

/// \class i_virtual_machine
/// \brief Interface representing the public API of the Cartesi machine.
/// \details \{
/// Allows clients to reference this interface in order to transparently
/// access a local or remote Cartesi machine instance.
///
/// This interface reflects the public methods of the cartesi class.
/// Every public method has a corresponding private pure virtual
/// method, with the same signature, prefixed with "do_".
/// Classes implementing this interface are required to provide
/// implementations for the pure virtual methods.
/// \}
class i_virtual_machine {
public:
    using hash_type = machine_merkle_tree::hash_type;
    using csr = machine::csr;

    /// \brief Constructor
    i_virtual_machine() = default;

    /// \brief Destructor.
    virtual ~i_virtual_machine() = default;

    i_virtual_machine(const i_virtual_machine &other) = delete;
    i_virtual_machine(i_virtual_machine &&other) noexcept = delete;
    i_virtual_machine &operator=(const i_virtual_machine &other) = delete;
    i_virtual_machine &operator=(i_virtual_machine &&other) noexcept = delete;

    /// \brief Runs the machine until mcycle reaches mcycle_end or the machine halts.
    interpreter_break_reason run(uint64_t mcycle_end) {
        return do_run(mcycle_end);
    }

    /// \brief Serialize entire state to directory
    void store(const std::string &dir) {
        do_store(dir);
    }

    /// \brief Runs the machine for one cycle logging all accesses to the state.
    access_log step(const access_log::type &log_type, bool one_based = false) {
        return do_step(log_type, one_based);
    }

    /// \brief Obtains the proof for a node in the Merkle tree.
    machine_merkle_tree::proof_type get_proof(uint64_t address, int log2_size) const {
        return do_get_proof(address, log2_size);
    }

    /// \brief Obtains the root hash of the Merkle tree.
    void get_root_hash(hash_type &hash) const {
        do_get_root_hash(hash);
    }

    /// \brief Verifies integrity of Merkle tree.
    bool verify_merkle_tree(void) const {
        return do_verify_merkle_tree();
    }

    /// \brief Reads the value of any CSR
    uint64_t read_csr(csr r) const {
        return do_read_csr(r);
    }

    /// \brief Writes the value of any CSR
    void write_csr(csr w, uint64_t val) {
        do_write_csr(w, val);
    }

    /// \brief Reads a chunk of data from the machine memory.
    void read_memory(uint64_t address, unsigned char *data, uint64_t length) const {
        do_read_memory(address, data, length);
    }

    /// \brief Writes a chunk of data to the machine memory.
    void write_memory(uint64_t address, const unsigned char *data, size_t length) {
        do_write_memory(address, data, length);
    }

    /// \brief Reads a chunk of data from the machine virtual memory.
    void read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) const {
        do_read_virtual_memory(address, data, length);
    }

    /// \brief Writes a chunk of data to the machine virtual memory.
    void write_virtual_memory(uint64_t address, const unsigned char *data, size_t length) {
        do_write_virtual_memory(address, data, length);
    }

    /// \brief Reads the value of a general-purpose register.
    uint64_t read_x(int i) const {
        return do_read_x(i);
    }

    /// \brief Writes the value of a general-purpose register.
    void write_x(int i, uint64_t val) {
        do_write_x(i, val);
    }

    /// \brief Reads the value of a floating-point register.
    uint64_t read_f(int i) const {
        return do_read_f(i);
    }

    /// \brief Writes the value of a floating-point register.
    void write_f(int i, uint64_t val) {
        do_write_f(i, val);
    }

    /// \brief Replaces a flash drive.
    void replace_memory_range(const memory_range_config &new_range) {
        do_replace_memory_range(new_range);
    }

    /// \brief Dump all memory ranges to files in current working directory.
    void dump_pmas(void) const {
        do_dump_pmas();
    }

    /// \brief Read the value of a word in the machine state.
    bool read_word(uint64_t word_address, uint64_t &word_value) const {
        return do_read_word(word_address, word_value);
    }

    /// \brief Verify if dirty page maps are consistent.
    bool verify_dirty_page_maps(void) const {
        return do_verify_dirty_page_maps();
    }

    /// \brief Returns copy of initialization config.
    machine_config get_initial_config(void) const {
        return do_get_initial_config();
    }

    /// \brief snapshot
    void snapshot(void) {
        do_snapshot();
    }

    /// \brief destroy
    void destroy(void) {
        do_destroy();
    }

    /// \brief rollback
    void rollback(void) {
        do_rollback();
    }

    /// \brief Reads the pc register
    uint64_t read_pc(void) const {
        return do_read_pc();
    }

    /// \brief Writes the pc register
    void write_pc(uint64_t val) {
        do_write_pc(val);
    };

    /// \brief Reads the fcsr register
    uint64_t read_fcsr(void) const {
        return do_read_fcsr();
    }

    /// \brief Writes the fcsr register
    void write_fcsr(uint64_t val) {
        do_write_fcsr(val);
    }

    /// \brief Reads the mvendorid register
    uint64_t read_mvendorid(void) const {
        return do_read_mvendorid();
    }

    /// \brief Reads the marchid register
    uint64_t read_marchid(void) const {
        return do_read_marchid();
    }

    /// \brief Reads the mimpid register
    uint64_t read_mimpid(void) const {
        return do_read_mimpid();
    }

    /// \brief Reads the mcycle register
    uint64_t read_mcycle(void) const {
        return do_read_mcycle();
    }

    /// \brief Writes the mcycle register
    void write_mcycle(uint64_t val) {
        do_write_mcycle(val);
    }

    /// \brief Reads the icycleinstret register
    uint64_t read_icycleinstret(void) const {
        return do_read_icycleinstret();
    }

    /// \brief Writes the icycleinstret register
    void write_icycleinstret(uint64_t val) {
        do_write_icycleinstret(val);
    }

    /// \brief Reads the mstatus register
    uint64_t read_mstatus(void) const {
        return do_read_mstatus();
    }

    /// \brief Writes the mstatus register
    void write_mstatus(uint64_t val) {
        do_write_mstatus(val);
    }

    /// \brief Reads the menvcfg register
    uint64_t read_menvcfg(void) const {
        return do_read_menvcfg();
    }

    /// \brief Writes the menvcfg register
    void write_menvcfg(uint64_t val) {
        do_write_menvcfg(val);
    }

    /// \brief Reads the mtvec register
    uint64_t read_mtvec(void) const {
        return do_read_mtvec();
    }

    /// \brief Writes the mtvec register
    void write_mtvec(uint64_t val) {
        do_write_mtvec(val);
    }

    /// \brief Reads the mscratch register
    uint64_t read_mscratch(void) const {
        return do_read_mscratch();
    }

    /// \brief Writes the mscratch register
    void write_mscratch(uint64_t val) {
        do_write_mscratch(val);
    }

    /// \brief Reads the mepc register
    uint64_t read_mepc(void) const {
        return do_read_mepc();
    }

    /// \brief Writes the mepc register
    void write_mepc(uint64_t val) {
        do_write_mepc(val);
    }

    /// \brief Reads the mcause register
    uint64_t read_mcause(void) const {
        return do_read_mcause();
    }

    /// \brief Writes the mcause register
    void write_mcause(uint64_t val) {
        do_write_mcause(val);
    }

    /// \brief Reads the mtval register
    uint64_t read_mtval(void) const {
        return do_read_mtval();
    }

    /// \brief Writes the mtval register
    void write_mtval(uint64_t val) {
        do_write_mtval(val);
    }

    /// \brief Reads the misa register
    uint64_t read_misa(void) const {
        return do_read_misa();
    }

    /// \brief Writes the misa register
    void write_misa(uint64_t val) {
        do_write_misa(val);
    }

    /// \brief Reads the mie register
    uint64_t read_mie(void) const {
        return do_read_mie();
    }

    /// \brief Writes the mie register
    void write_mie(uint64_t val) {
        do_write_mie(val);
    }

    /// \brief Reads the mip register
    uint64_t read_mip(void) const {
        return do_read_mip();
    }

    /// \brief Writes the mip register
    void write_mip(uint64_t val) {
        do_write_mip(val);
    }

    /// \brief Reads the medeleg register
    uint64_t read_medeleg(void) const {
        return do_read_medeleg();
    }

    /// \brief Writes the medeleg register
    void write_medeleg(uint64_t val) {
        do_write_medeleg(val);
    }

    /// \brief Reads the mideleg register
    uint64_t read_mideleg(void) const {
        return do_read_mideleg();
    }

    /// \brief Writes the mideleg register
    /// \param val New register value.
    void write_mideleg(uint64_t val) {
        do_write_mideleg(val);
    }

    /// \brief Reads the mcounteren register
    uint64_t read_mcounteren(void) const {
        return do_read_mcounteren();
    }

    /// \brief Writes the mcounteren register
    void write_mcounteren(uint64_t val) {
        do_write_mcounteren(val);
    }

    /// \brief Reads the stvec register
    uint64_t read_stvec(void) const {
        return do_read_stvec();
    }

    /// \brief Writes the stvec register
    void write_stvec(uint64_t val) {
        do_write_stvec(val);
    }

    /// \brief Reads the sscratch register
    uint64_t read_sscratch(void) const {
        return do_read_sscratch();
    }

    /// \brief Writes the sscratch register
    void write_sscratch(uint64_t val) {
        do_write_sscratch(val);
    }

    /// \brief Reads the sepc register
    uint64_t read_sepc(void) const {
        return do_read_sepc();
    }

    /// \brief Writes the sepc register
    void write_sepc(uint64_t val) {
        do_write_sepc(val);
    }

    /// \brief Reads the scause register
    uint64_t read_scause(void) const {
        return do_read_scause();
    }

    /// \brief Writes the scause register
    void write_scause(uint64_t val) {
        do_write_scause(val);
    }

    /// \brief Reads the stval register
    uint64_t read_stval(void) const {
        return do_read_stval();
    }

    /// \brief Writes the stval register
    void write_stval(uint64_t val) {
        do_write_stval(val);
    }

    /// \brief Reads the satp register
    uint64_t read_satp(void) const {
        return do_read_satp();
    }

    /// \brief Writes the satp register
    void write_satp(uint64_t val) {
        do_write_satp(val);
    }

    /// \brief Reads the scounteren register
    uint64_t read_scounteren(void) const {
        return do_read_scounteren();
    }

    /// \brief Writes the scounteren register
    void write_scounteren(uint64_t val) {
        do_write_scounteren(val);
    }

    /// \brief Reads the senvcfg register
    uint64_t read_senvcfg(void) const {
        return do_read_senvcfg();
    }

    /// \brief Writes the senvcfg register
    void write_senvcfg(uint64_t val) {
        do_write_senvcfg(val);
    }

    /// \brief Reads the ilrsc register
    uint64_t read_ilrsc(void) const {
        return do_read_ilrsc();
    }

    /// \brief Writes the ilrsc register
    void write_ilrsc(uint64_t val) {
        do_write_ilrsc(val);
    }

    /// \brief Reads the iflags register
    uint64_t read_iflags(void) const {
        return do_read_iflags();
    }

    /// \brief Reads the H iflag
    bool read_iflags_H(void) const {
        return do_read_iflags_H();
    }

    /// \brief Reads the Y iflag
    bool read_iflags_Y(void) const {
        return do_read_iflags_Y();
    }

    /// \brief Reads the X iflag
    bool read_iflags_X(void) const {
        return do_read_iflags_X();
    }

    /// \brief Sets the H iflag
    void set_iflags_H(void) {
        return do_set_iflags_H();
    }

    /// \brief Sets the Y iflag
    void set_iflags_Y(void) {
        return do_set_iflags_Y();
    }

    /// \brief Sets the X iflag
    void set_iflags_X(void) {
        return do_set_iflags_X();
    }

    /// \brief Resets the Y iflag
    void reset_iflags_Y(void) {
        return do_reset_iflags_Y();
    }

    /// \brief Resets the X iflag
    void reset_iflags_X(void) {
        return do_reset_iflags_X();
    }

    /// \brief Writes the iflags register
    void write_iflags(uint64_t val) {
        return do_write_iflags(val);
    }

    /// \brief Reads htif's tohost
    uint64_t read_htif_tohost(void) const {
        return do_read_htif_tohost();
    }

    /// \brief Reads htif's tohost dev
    uint64_t read_htif_tohost_dev(void) const {
        return do_read_htif_tohost_dev();
    }

    /// \brief Reads htif's tohost cmd
    uint64_t read_htif_tohost_cmd(void) const {
        return do_read_htif_tohost_cmd();
    }

    /// \brief Reads htif's tohost data
    uint64_t read_htif_tohost_data(void) const {
        return do_read_htif_tohost_data();
    }

    /// \brief Writes htif's tohost
    void write_htif_tohost(uint64_t val) {
        do_write_htif_tohost(val);
    }

    /// \brief Reads htif's fromhost
    uint64_t read_htif_fromhost(void) const {
        return do_read_htif_fromhost();
    }

    /// \brief Writes htif's fromhost
    void write_htif_fromhost(uint64_t val) {
        do_write_htif_fromhost(val);
    }

    /// \brief Writes htif's fromhost data
    void write_htif_fromhost_data(uint64_t val) {
        do_write_htif_fromhost_data(val);
    }

    /// \brief Reads htif's ihalt
    uint64_t read_htif_ihalt(void) const {
        return do_read_htif_ihalt();
    }

    /// \brief Writes htif's ihalt
    void write_htif_ihalt(uint64_t val) {
        do_write_htif_ihalt(val);
    }

    /// \brief Reads htif's iconsole
    uint64_t read_htif_iconsole(void) const {
        return do_read_htif_iconsole();
    }

    /// \brief Writes htif's iconsole
    void write_htif_iconsole(uint64_t val) {
        do_write_htif_iconsole(val);
    }

    /// \brief Reads htif's iyield
    uint64_t read_htif_iyield(void) const {
        return do_read_htif_iyield();
    }

    /// \brief Writes htif's iyield
    void write_htif_iyield(uint64_t val) {
        do_write_htif_iyield(val);
    }

    /// \brief Reads clint's mtimecmp
    uint64_t read_clint_mtimecmp(void) const {
        return do_read_clint_mtimecmp();
    }

    /// \brief Writes clint's mtimecmp
    void write_clint_mtimecmp(uint64_t val) {
        do_write_clint_mtimecmp(val);
    }

    /// \brief Reads the value of a microarchitecture register.
    /// \param i Register index. Between 0 and UARCH_X_REG_COUNT-1, inclusive.
    /// \returns The value of the register.
    uint64_t read_uarch_x(int i) const {
        return do_read_uarch_x(i);
    }

    /// \brief Writes the value of a of a microarchitecture register.
    /// \param i Register index. Between 0 and UARCH_X_REG_COUNT-1, inclusive.
    /// \param val New register value.
    void write_uarch_x(int i, uint64_t val) {
        return do_write_uarch_x(i, val);
    }

    /// \brief Reads the value of the microarchitecture pc register.
    /// \returns The current microarchitecture pc value.
    uint64_t read_uarch_pc(void) const {
        return do_read_uarch_pc();
    }

    /// \brief Writes the value ofthe microarchitecture pc register.
    /// \param val New register value.
    void write_uarch_pc(uint64_t val) {
        return do_write_uarch_pc(val);
    }

    /// \brief Reads the value of the microarchitecture cycle counter register.
    /// \returns The current microarchitecture cycle.
    uint64_t read_uarch_cycle(void) const {
        return do_read_uarch_cycle();
    }

    /// \brief Writes the value ofthe microarchitecture pc register.
    /// \param val New register value.
    void write_uarch_cycle(uint64_t val) {
        return do_write_uarch_cycle(val);
    }

    /// \brief Gets the value of the microarchitecture halt flag
    /// \returns The current microarchitecture cycle.
    bool read_uarch_halt_flag(void) const {
        return do_read_uarch_halt_flag();
    }

    /// \brief Sets the microarchitecture halt flag
    void set_uarch_halt_flag() {
        return do_set_uarch_halt_flag();
    }

    /// \brief Resets the microarchitecture halt flag
    void uarch_reset_state() {
        return do_uarch_reset_state();
    }

    /// \brief Reads the value of the microarchitecture ROM length
    /// \returns The value of microarchitecture ROM length
    uint64_t read_uarch_ram_length(void) const {
        return do_read_uarch_ram_length();
    }

    /// \brief Runs the microarchitecture until the machine advances to the next mcycle or the current  micro cycle
    /// (uarch_cycle) reaches uarch_cycle_end \param uarch_cycle_end uarch_cycle limit
    void uarch_run(uint64_t uarch_cycle_end) {
        return do_uarch_run(uarch_cycle_end);
    }

private:
    virtual interpreter_break_reason do_run(uint64_t mcycle_end) = 0;
    virtual void do_store(const std::string &dir) = 0;
    virtual access_log do_step(const access_log::type &log_type, bool one_based = false) = 0;
    virtual machine_merkle_tree::proof_type do_get_proof(uint64_t address, int log2_size) const = 0;
    virtual void do_get_root_hash(hash_type &hash) const = 0;
    virtual bool do_verify_merkle_tree(void) const = 0;
    virtual uint64_t do_read_csr(csr r) const = 0;
    virtual void do_write_csr(csr w, uint64_t val) = 0;
    virtual void do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const = 0;
    virtual void do_write_memory(uint64_t address, const unsigned char *data, size_t length) = 0;
    virtual void do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) const = 0;
    virtual void do_write_virtual_memory(uint64_t address, const unsigned char *data, size_t length) = 0;
    virtual uint64_t do_read_x(int i) const = 0;
    virtual void do_write_x(int i, uint64_t val) = 0;
    virtual uint64_t do_read_f(int i) const = 0;
    virtual void do_write_f(int i, uint64_t val) = 0;
    virtual uint64_t do_read_pc(void) const = 0;
    virtual void do_write_pc(uint64_t val) = 0;
    virtual uint64_t do_read_fcsr(void) const = 0;
    virtual void do_write_fcsr(uint64_t val) = 0;
    virtual uint64_t do_read_mvendorid(void) const = 0;
    virtual uint64_t do_read_marchid(void) const = 0;
    virtual uint64_t do_read_mimpid(void) const = 0;
    virtual uint64_t do_read_mcycle(void) const = 0;
    virtual void do_write_mcycle(uint64_t val) = 0;
    virtual uint64_t do_read_icycleinstret(void) const = 0;
    virtual void do_write_icycleinstret(uint64_t val) = 0;
    virtual uint64_t do_read_mstatus(void) const = 0;
    virtual void do_write_mstatus(uint64_t val) = 0;
    virtual uint64_t do_read_menvcfg(void) const = 0;
    virtual void do_write_menvcfg(uint64_t val) = 0;
    virtual uint64_t do_read_mtvec(void) const = 0;
    virtual void do_write_mtvec(uint64_t val) = 0;
    virtual uint64_t do_read_mscratch(void) const = 0;
    virtual void do_write_mscratch(uint64_t val) = 0;
    virtual uint64_t do_read_mepc(void) const = 0;
    virtual void do_write_mepc(uint64_t val) = 0;
    virtual uint64_t do_read_mcause(void) const = 0;
    virtual void do_write_mcause(uint64_t val) = 0;
    virtual uint64_t do_read_mtval(void) const = 0;
    virtual void do_write_mtval(uint64_t val) = 0;
    virtual uint64_t do_read_misa(void) const = 0;
    virtual void do_write_misa(uint64_t val) = 0;
    virtual uint64_t do_read_mie(void) const = 0;
    virtual void do_write_mie(uint64_t val) = 0;
    virtual uint64_t do_read_mip(void) const = 0;
    virtual void do_write_mip(uint64_t val) = 0;
    virtual uint64_t do_read_medeleg(void) const = 0;
    virtual void do_write_medeleg(uint64_t val) = 0;
    virtual uint64_t do_read_mideleg(void) const = 0;
    virtual void do_write_mideleg(uint64_t val) = 0;
    virtual uint64_t do_read_mcounteren(void) const = 0;
    virtual void do_write_mcounteren(uint64_t val) = 0;
    virtual uint64_t do_read_stvec(void) const = 0;
    virtual void do_write_stvec(uint64_t val) = 0;
    virtual uint64_t do_read_sscratch(void) const = 0;
    virtual void do_write_sscratch(uint64_t val) = 0;
    virtual uint64_t do_read_sepc(void) const = 0;
    virtual void do_write_sepc(uint64_t val) = 0;
    virtual uint64_t do_read_scause(void) const = 0;
    virtual void do_write_scause(uint64_t val) = 0;
    virtual uint64_t do_read_stval(void) const = 0;
    virtual void do_write_stval(uint64_t val) = 0;
    virtual uint64_t do_read_satp(void) const = 0;
    virtual void do_write_satp(uint64_t val) = 0;
    virtual uint64_t do_read_scounteren(void) const = 0;
    virtual void do_write_scounteren(uint64_t val) = 0;
    virtual uint64_t do_read_senvcfg(void) const = 0;
    virtual void do_write_senvcfg(uint64_t val) = 0;
    virtual uint64_t do_read_ilrsc(void) const = 0;
    virtual void do_write_ilrsc(uint64_t val) = 0;
    virtual uint64_t do_read_iflags(void) const = 0;
    virtual bool do_read_iflags_H(void) const = 0;
    virtual bool do_read_iflags_Y(void) const = 0;
    virtual bool do_read_iflags_X(void) const = 0;
    virtual void do_set_iflags_H(void) = 0;
    virtual void do_set_iflags_Y(void) = 0;
    virtual void do_set_iflags_X(void) = 0;
    virtual void do_reset_iflags_Y(void) = 0;
    virtual void do_reset_iflags_X(void) = 0;
    virtual void do_write_iflags(uint64_t val) = 0;
    virtual uint64_t do_read_htif_tohost(void) const = 0;
    virtual uint64_t do_read_htif_tohost_dev(void) const = 0;
    virtual uint64_t do_read_htif_tohost_cmd(void) const = 0;
    virtual uint64_t do_read_htif_tohost_data(void) const = 0;
    virtual void do_write_htif_tohost(uint64_t val) = 0;
    virtual uint64_t do_read_htif_fromhost(void) const = 0;
    virtual void do_write_htif_fromhost(uint64_t val) = 0;
    virtual void do_write_htif_fromhost_data(uint64_t val) = 0;
    virtual uint64_t do_read_htif_ihalt(void) const = 0;
    virtual void do_write_htif_ihalt(uint64_t val) = 0;
    virtual uint64_t do_read_htif_iconsole(void) const = 0;
    virtual void do_write_htif_iconsole(uint64_t val) = 0;
    virtual uint64_t do_read_htif_iyield(void) const = 0;
    virtual void do_write_htif_iyield(uint64_t val) = 0;
    virtual uint64_t do_read_clint_mtimecmp(void) const = 0;
    virtual void do_write_clint_mtimecmp(uint64_t val) = 0;
    virtual void do_replace_memory_range(const memory_range_config &new_range) = 0;
    virtual void do_dump_pmas(void) const = 0;
    virtual bool do_read_word(uint64_t word_address, uint64_t &word_value) const = 0;
    virtual bool do_verify_dirty_page_maps(void) const = 0;
    virtual machine_config do_get_initial_config(void) const = 0;
    virtual void do_snapshot() = 0;
    virtual void do_destroy() = 0;
    virtual void do_rollback() = 0;
    virtual uint64_t do_read_uarch_x(int i) const = 0;
    virtual void do_write_uarch_x(int i, uint64_t val) = 0;
    virtual uint64_t do_read_uarch_pc(void) const = 0;
    virtual void do_write_uarch_pc(uint64_t val) = 0;
    virtual uint64_t do_read_uarch_cycle(void) const = 0;
    virtual void do_write_uarch_cycle(uint64_t val) = 0;
    virtual bool do_read_uarch_halt_flag(void) const = 0;
    virtual void do_set_uarch_halt_flag() = 0;
    virtual void do_uarch_reset_state() = 0;
    virtual uint64_t do_read_uarch_ram_length(void) const = 0;
    virtual void do_uarch_run(uint64_t uarch_cycle_end) = 0;
};

} // namespace cartesi

#endif
