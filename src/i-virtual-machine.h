// Copyright 2020 Cartesi Pte. Ltd.
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

    /// \brief Destructor.
    virtual ~i_virtual_machine(void) {
        ;
    }

    /// \brief Runs the machine until mcycle reaches mcycle_end or the machine halts.
    void run(uint64_t mcycle_end) {
        do_run(mcycle_end);
    }

    /// \brief Serialize entire state to directory
    void store(const std::string &dir) {
        do_store(dir);
    }

    /// \brief Runs the machine for one cycle logging all accesses to the state.
    access_log step(const access_log::type &log_type, bool one_based = false) {
        return do_step(log_type, one_based);
    }

    /// \brief Update the Merkle tree so it matches the contents of the machine state.
    bool update_merkle_tree(void) {
        return do_update_merkle_tree();
    }

    /// \brief Obtains the proof for a node in the Merkle tree.
    machine_merkle_tree::proof_type get_proof(uint64_t address, int log2_size) {
        return do_get_proof(address, log2_size);
    }

    /// \brief Obtains the root hash of the Merkle tree.
    void get_root_hash(hash_type &hash) {
        do_get_root_hash(hash);
    }

    /// \brief Verifies integrity of Merkle tree.
    bool verify_merkle_tree(void) {
        return do_verify_merkle_tree();
    }

    /// \brief Reads the value of any CSR
    uint64_t read_csr(csr r) {
        return do_read_csr(r);
    }

    /// \brief Writes the value of any CSR
    void write_csr(csr w, uint64_t val) {
        do_write_csr(w, val);
    }

    /// \brief Reads a chunk of data from the machine memory.
    void read_memory(uint64_t address, unsigned char *data, uint64_t length) {
        do_read_memory(address, data, length);
    }

    /// \brief Writes a chunk of data to the machine memory.
    void write_memory(uint64_t address, const unsigned char *data, size_t length) {
        do_write_memory(address, data, length);
    }

    /// \brief Reads the value of a general-purpose register.
    uint64_t read_x(int i) {
        return do_read_x(i);
    }

    /// \brief Writes the value of a general-purpose register.
    void write_x(int i, uint64_t val) {
        do_write_x(i, val);
    }

    /// \brief Replaces a flash drive.
    void replace_flash_drive(const flash_drive_config &new_flash) {
        do_replace_flash_drive(new_flash);
    }

    /// \brief Dump all memory ranges to files in current working directory.
    void dump_pmas(void) {
        do_dump_pmas();
    }

    /// \brief Read the value of a word in the machine state.
    bool read_word(uint64_t word_address, uint64_t &word_value) {
        return do_read_word(word_address, word_value);
    }

    /// \brief Verify if dirty page maps are consistent.
    bool verify_dirty_page_maps(void) {
        return do_verify_dirty_page_maps();
    }

    /// \brief Returns copy of initialization config.
    machine_config get_initial_config(void) {
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
    uint64_t read_pc(void) {
        return  do_read_pc();
    }

    /// \brief Writes the pc register
    void write_pc(uint64_t val) {
         do_write_pc(val);
    };

    /// \brief Reads the mvendorid register
    uint64_t read_mvendorid(void) {
        return  do_read_mvendorid();
    }

    /// \brief Reads the marchid register
    uint64_t read_marchid(void) {
        return  do_read_marchid();
    }

    /// \brief Reads the mimpid register
    uint64_t read_mimpid(void) {
        return  do_read_mimpid();
    }

    /// \brief Reads the mcycle register
    uint64_t read_mcycle(void) {
        return  do_read_mcycle();
    }

    /// \brief Writes the mcycle register
    void write_mcycle(uint64_t val) {
         do_write_mcycle(val);
    }

    /// \brief Reads the minstret register
    uint64_t read_minstret(void) {
        return  do_read_minstret();
    }

    /// \brief Writes the minstret register
    void write_minstret(uint64_t val) {
         do_write_minstret(val);
    }

    /// \brief Reads the mstatus register
    uint64_t read_mstatus(void) {
        return  do_read_mstatus();
    }

    /// \brief Writes the mstatus register
    void write_mstatus(uint64_t val) {
         do_write_mstatus(val);
    }

    /// \brief Reads the mtvec register
    uint64_t read_mtvec(void) {
        return  do_read_mtvec();
    }

    /// \brief Writes the mtvec register
    void write_mtvec(uint64_t val) {
         do_write_mtvec(val);
    }

    /// \brief Reads the mscratch register
    uint64_t read_mscratch(void) {
        return  do_read_mscratch();
    }

    /// \brief Writes the mscratch register
    void write_mscratch(uint64_t val) {
         do_write_mscratch(val);
    }

    /// \brief Reads the mepc register
    uint64_t read_mepc(void) {
        return  do_read_mepc();
    }

    /// \brief Writes the mepc register
    void write_mepc(uint64_t val) {
         do_write_mepc(val);
    }

    /// \brief Reads the mcause register
    uint64_t read_mcause(void) {
        return  do_read_mcause();
    }

    /// \brief Writes the mcause register
    void write_mcause(uint64_t val) {
         do_write_mcause(val);
    }

    /// \brief Reads the mtval register
    uint64_t read_mtval(void) {
        return  do_read_mtval();
     }

    /// \brief Writes the mtval register
    void write_mtval(uint64_t val) {
         do_write_mtval(val);
    }

    /// \brief Reads the misa register
    uint64_t read_misa(void) {
        return  do_read_misa();
    }

    /// \brief Writes the misa register
    void write_misa(uint64_t val) {
         do_write_misa(val);
    }

    /// \brief Reads the mie register
    uint64_t read_mie(void) {
        return  do_read_mie();
    }

    /// \brief Writes the mie register
    void write_mie(uint64_t val) {
         do_write_mie(val);
    }

    /// \brief Reads the mip register
    uint64_t read_mip(void) {
        return  do_read_mip();
    }

    /// \brief Writes the mip register
    void write_mip(uint64_t val) {
         do_write_mip(val);
    }

    /// \brief Reads the medeleg register
    uint64_t read_medeleg(void) {
        return  do_read_medeleg();
    }

    /// \brief Writes the medeleg register
    void write_medeleg(uint64_t val) {
         do_write_medeleg(val);
    }

    /// \brief Reads the mideleg register
    uint64_t read_mideleg(void) {
        return  do_read_mideleg();
    }

    /// \brief Writes the mideleg register
    /// \param val New register value.
    void write_mideleg(uint64_t val) {
         do_write_mideleg(val);
    }

    /// \brief Reads the mcounteren register
    uint64_t read_mcounteren(void) {
        return  do_read_mcounteren();
    }

    /// \brief Writes the mcounteren register
    void write_mcounteren(uint64_t val) {
         do_write_mcounteren(val);
    }

    /// \brief Reads the stvec register
    uint64_t read_stvec(void) {
        return  do_read_stvec();
    }

    /// \brief Writes the stvec register
    void write_stvec(uint64_t val) {
         do_write_stvec(val);
    }

    /// \brief Reads the sscratch register
    uint64_t read_sscratch(void) {
        return  do_read_sscratch();
    }

    /// \brief Writes the sscratch register
    void write_sscratch(uint64_t val) {
         do_write_sscratch(val);
    }

    /// \brief Reads the sepc register
    uint64_t read_sepc(void) {
        return  do_read_sepc();
    }

    /// \brief Writes the sepc register
    void write_sepc(uint64_t val) {
         do_write_sepc(val);
    }

    /// \brief Reads the scause register
    uint64_t read_scause(void) {
        return  do_read_scause();
    }

    /// \brief Writes the scause register
    void write_scause(uint64_t val) {
         do_write_scause(val);
    }

    /// \brief Reads the stval register
    uint64_t read_stval(void) {
        return  do_read_stval();
    }

    /// \brief Writes the stval register
    void write_stval(uint64_t val) {
         do_write_stval(val);
    }

    /// \brief Reads the satp register
    uint64_t read_satp(void) {
        return  do_read_satp();
    }

    /// \brief Writes the satp register
    void write_satp(uint64_t val) {
         do_write_satp(val);
    }

    /// \brief Reads the scounteren register
    uint64_t read_scounteren(void) {
        return  do_read_scounteren();
    }

    /// \brief Writes the scounteren register
    void write_scounteren(uint64_t val) {
         do_write_scounteren(val);
    }

    /// \brief Reads the ilrsc register
    uint64_t read_ilrsc(void) {
        return  do_read_ilrsc();
    }

    /// \brief Writes the ilrsc register
    void write_ilrsc(uint64_t val) {
         do_write_ilrsc(val);
    }

    /// \brief Reads the iflags register
    uint64_t read_iflags(void) {
        return  do_read_iflags();
    }

    /// \brief Reads the H iflag
    bool read_iflags_H(void) {
        return do_read_iflags_H();
    }

    /// \brief Reads the Y iflag
    bool read_iflags_Y(void) {
        return do_read_iflags_Y();
    }

    /// \brief Sets the H iflag
    void set_iflags_H(void) {
        return do_set_iflags_H();
    }

    /// \brief Sets the Y iflag
    void set_iflags_Y(void) {
        return do_set_iflags_Y();
    }

    /// \brief Reads the Y iflag
    void reset_iflags_Y(void) {
        return do_reset_iflags_Y();
    }

    /// \brief Writes the iflags register
    void write_iflags(uint64_t val) {
         do_write_iflags(val);
    }

    /// \brief Reads htif's tohost
    uint64_t read_htif_tohost(void) {
        return  do_read_htif_tohost();
    }

    /// \brief Reads htif's tohost dev
    uint64_t read_htif_tohost_dev(void) {
        return do_read_htif_tohost_dev();
    }

    /// \brief Reads htif's tohost cmd
    uint64_t read_htif_tohost_cmd(void) {
        return do_read_htif_tohost_cmd();
    }

    /// \brief Reads htif's tohost data
    uint64_t read_htif_tohost_data(void) {
        return do_read_htif_tohost_data();
    }

    /// \brief Writes htif's tohost
    void write_htif_tohost(uint64_t val) {
         do_write_htif_tohost(val);
    }

    /// \brief Reads htif's fromhost
    uint64_t read_htif_fromhost(void) {
        return  do_read_htif_fromhost();
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
    uint64_t read_htif_ihalt(void) {
        return  do_read_htif_ihalt();
    }

    /// \brief Writes htif's ihalt
    void write_htif_ihalt(uint64_t val)  {
         do_write_htif_ihalt(val);
    }

    /// \brief Reads htif's iconsole
    uint64_t read_htif_iconsole(void) {
        return  do_read_htif_iconsole();
    }

    /// \brief Writes htif's iconsole
    void write_htif_iconsole(uint64_t val) {
         do_write_htif_iconsole(val);
    }

    /// \brief Reads htif's iyield
    uint64_t read_htif_iyield(void) {
        return  do_read_htif_iyield();
    }

    /// \brief Writes htif's iyield
    void write_htif_iyield(uint64_t val)  {
         do_write_htif_iyield(val);
    }

    /// \brief Reads clint's mtimecmp
    uint64_t read_clint_mtimecmp(void) {
        return  do_read_clint_mtimecmp();
    }

    /// \brief Writes clint's mtimecmp
    void write_clint_mtimecmp(uint64_t val) {
         do_write_clint_mtimecmp(val);
    }

    /// \brief Reads dhd's tstart
    uint64_t read_dhd_tstart(void) {
        return  do_read_dhd_tstart();
    }

    /// \brief Writes dhd's tstart
    void write_dhd_tstart(uint64_t val) {
         do_write_dhd_tstart(val);
    }

    /// \brief Reads dhd's tlength
    uint64_t read_dhd_tlength(void) {
        return  do_read_dhd_tlength();
    }

    /// \brief Writes dhd's tlength
    void write_dhd_tlength(uint64_t val) {
         do_write_dhd_tlength(val);
    }

    /// \brief Reads dhd's dlength
    uint64_t read_dhd_dlength(void) {
        return  do_read_dhd_dlength();
    }

    /// \brief Writes dhd's dlength
    void write_dhd_dlength(uint64_t val) {
         do_write_dhd_dlength(val);
    }

    /// \brief Reads dhd's hlength
    uint64_t read_dhd_hlength(void) {
        return  do_read_dhd_hlength();
    }

    /// \brief Writes dhd's hlength
    void write_dhd_hlength(uint64_t val) {
         do_write_dhd_hlength(val);
    }

    /// \brief Reads the value of a dhd h register.
    uint64_t read_dhd_h(int i) {
        return do_read_dhd_h(i);
    }

    /// \brief Writes the value of a dhd h register.
    void write_dhd_h(int i, uint64_t val) {
        do_write_dhd_h(i, val);
    }

private:
    virtual void do_run(uint64_t mcycle_end) = 0;
    virtual void do_store(const std::string &dir) = 0;
    virtual access_log do_step(const access_log::type &log_type, bool one_based = false) = 0;
    virtual bool do_update_merkle_tree(void) = 0;
    virtual machine_merkle_tree::proof_type do_get_proof(uint64_t address, int log2_size) = 0;
    virtual void do_get_root_hash(hash_type &hash) = 0;
    virtual bool do_verify_merkle_tree(void) = 0;
    virtual uint64_t do_read_csr(csr r) = 0;
    virtual void do_write_csr(csr w, uint64_t val) = 0;
    virtual void do_read_memory(uint64_t address, unsigned char *data, uint64_t length) = 0;
    virtual void do_write_memory(uint64_t address, const unsigned char *data, size_t length) = 0;
    virtual uint64_t do_read_x(int i) = 0;
    virtual void do_write_x(int i, uint64_t val) = 0;
    virtual uint64_t do_read_pc(void) = 0;
    virtual void do_write_pc(uint64_t val) = 0;
    virtual uint64_t do_read_mvendorid(void) = 0;
    virtual uint64_t do_read_marchid(void) = 0;
    virtual uint64_t do_read_mimpid(void) = 0;
    virtual uint64_t do_read_mcycle(void) = 0;
    virtual void do_write_mcycle(uint64_t val) = 0;
    virtual uint64_t do_read_minstret(void) = 0;
    virtual void do_write_minstret(uint64_t val) = 0;
    virtual uint64_t do_read_mstatus(void) = 0;
    virtual void do_write_mstatus(uint64_t val) = 0;
    virtual uint64_t do_read_mtvec(void) = 0;
    virtual void do_write_mtvec(uint64_t val) = 0;
    virtual uint64_t do_read_mscratch(void) = 0;
    virtual void do_write_mscratch(uint64_t val) = 0;
    virtual uint64_t do_read_mepc(void) = 0;
    virtual void do_write_mepc(uint64_t val) = 0;
    virtual uint64_t do_read_mcause(void) = 0;
    virtual void do_write_mcause(uint64_t val) = 0;
    virtual uint64_t do_read_mtval(void) = 0;
    virtual void do_write_mtval(uint64_t val) = 0;
    virtual uint64_t do_read_misa(void) = 0;
    virtual void do_write_misa(uint64_t val) = 0;
    virtual uint64_t do_read_mie(void) = 0;
    virtual void do_write_mie(uint64_t val) = 0;
    virtual uint64_t do_read_mip(void) = 0;
    virtual void do_write_mip(uint64_t val) = 0;
    virtual uint64_t do_read_medeleg(void) = 0;
    virtual void do_write_medeleg(uint64_t val) = 0;
    virtual uint64_t do_read_mideleg(void) = 0;
    virtual void do_write_mideleg(uint64_t val) = 0;
    virtual uint64_t do_read_mcounteren(void) = 0;
    virtual void do_write_mcounteren(uint64_t val) = 0;
    virtual uint64_t do_read_stvec(void) = 0;
    virtual void do_write_stvec(uint64_t val) = 0;
    virtual uint64_t do_read_sscratch(void) = 0;
    virtual void do_write_sscratch(uint64_t val) = 0;
    virtual uint64_t do_read_sepc(void) = 0;
    virtual void do_write_sepc(uint64_t val) = 0;
    virtual uint64_t do_read_scause(void) = 0;
    virtual void do_write_scause(uint64_t val) = 0;
    virtual uint64_t do_read_stval(void) = 0;
    virtual void do_write_stval(uint64_t val) = 0;
    virtual uint64_t do_read_satp(void) = 0;
    virtual void do_write_satp(uint64_t val) = 0;
    virtual uint64_t do_read_scounteren(void) = 0;
    virtual void do_write_scounteren(uint64_t val) = 0;
    virtual uint64_t do_read_ilrsc(void) = 0;
    virtual void do_write_ilrsc(uint64_t val) = 0;
    virtual uint64_t do_read_iflags(void) = 0;
    virtual bool do_read_iflags_H(void) = 0;
    virtual bool do_read_iflags_Y(void) = 0;
    virtual void do_set_iflags_H(void) = 0;
    virtual void do_set_iflags_Y(void) = 0;
    virtual void do_reset_iflags_Y(void) = 0;
    virtual void do_write_iflags(uint64_t val) = 0;
    virtual uint64_t do_read_htif_tohost(void) = 0;
    virtual uint64_t do_read_htif_tohost_dev(void) = 0;
    virtual uint64_t do_read_htif_tohost_cmd(void) = 0;
    virtual uint64_t do_read_htif_tohost_data(void) = 0;
    virtual void do_write_htif_tohost(uint64_t val) = 0;
    virtual uint64_t do_read_htif_fromhost(void) = 0;
    virtual void do_write_htif_fromhost(uint64_t val) = 0;
    virtual void do_write_htif_fromhost_data(uint64_t val) = 0;
    virtual uint64_t do_read_htif_ihalt(void) = 0;
    virtual void do_write_htif_ihalt(uint64_t val) = 0;
    virtual uint64_t do_read_htif_iconsole(void) = 0;
    virtual void do_write_htif_iconsole(uint64_t val) = 0;
    virtual uint64_t do_read_htif_iyield(void) = 0;
    virtual void do_write_htif_iyield(uint64_t val) = 0;
    virtual uint64_t do_read_clint_mtimecmp(void) = 0;
    virtual void do_write_clint_mtimecmp(uint64_t val) = 0;
    virtual uint64_t do_read_dhd_tstart(void) = 0;
    virtual void do_write_dhd_tstart(uint64_t val) = 0;
    virtual uint64_t do_read_dhd_tlength(void) = 0;
    virtual void do_write_dhd_tlength(uint64_t val) = 0;
    virtual uint64_t do_read_dhd_dlength(void) = 0;
    virtual void do_write_dhd_dlength(uint64_t val) = 0;
    virtual uint64_t do_read_dhd_hlength(void) = 0;
    virtual void do_write_dhd_hlength(uint64_t val) = 0;
    virtual uint64_t do_read_dhd_h(int i) = 0;
    virtual void do_write_dhd_h(int i, uint64_t val) = 0;
    virtual void do_replace_flash_drive(const flash_drive_config &new_flash) = 0;
    virtual void do_dump_pmas(void) = 0;
    virtual bool do_read_word(uint64_t word_address, uint64_t &word_value) = 0;
    virtual bool do_verify_dirty_page_maps(void) = 0;
    virtual machine_config do_get_initial_config(void) = 0;
    virtual void do_snapshot() = 0;
    virtual void do_destroy() = 0;
    virtual void do_rollback() = 0;
};

} // namespace cartesi

#endif
