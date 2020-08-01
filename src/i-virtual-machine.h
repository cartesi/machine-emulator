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
    using hash_type = merkle_tree::hash_type;
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
    void get_proof(uint64_t address, int log2_size, merkle_tree::proof_type &proof) {
        do_get_proof(address, log2_size, proof);
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

    /// \brief Gets the address of any CSR
    uint64_t get_csr_address(csr w) {
        return do_get_csr_address(w);
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

    /// \brief Gets the address of a general-purpose register.
    uint64_t get_x_address(int i) {
        return do_get_x_address(i);
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

    /// \brief shutdown
    void shutdown(void) {
        do_shutdown();
    }

    /// \brief rollback
    void rollback(void) {
        do_rollback();
    }

    /// \brief Reads the pc register
    uint64_t read_pc(void) {
        return read_csr(csr::pc);
    }

    /// \brief Writes the pc register
    void write_pc(uint64_t val) {
        write_csr(csr::pc, val);
    };

    /// \brief Reads the mvendorid register
    uint64_t read_mvendorid(void) {
        return read_csr(csr::mvendorid);
    }

    /// \brief Writes the mvendorid register
    void write_mvendorid(uint64_t val) {
        write_csr(csr::mvendorid, val);
    }

    /// \brief Reads the marchid register
    uint64_t read_marchid(void) {
        return read_csr(csr::marchid);
    }

    /// \brief Writes the marchid register
    void write_marchid(uint64_t val) {
        write_csr(csr::marchid, val);
    }

    /// \brief Reads the mimpid register
    uint64_t read_mimpid(void) {
        return read_csr(csr::mimpid);
    }

    /// \brief Writes the mimpid register
    void write_mimpid(uint64_t val) {
        write_csr(csr::mimpid, val);
    }

    /// \brief Reads the mcycle register
    uint64_t read_mcycle(void) {
        return read_csr(csr::mcycle);
    }

    /// \brief Writes the mcycle register
    void write_mcycle(uint64_t val) {
        write_csr(csr::mcycle, val);
    }

    /// \brief Reads the minstret register
    uint64_t read_minstret(void) {
        return read_csr(csr::minstret);
    }

    /// \brief Writes the minstret register
    void write_minstret(uint64_t val) {
        write_csr(csr::minstret, val);
    }

    /// \brief Reads the mstatus register
    uint64_t read_mstatus(void) {
        return read_csr(csr::mstatus);
    }

    /// \brief Writes the mstatus register
    void write_mstatus(uint64_t val) {
        write_csr(csr::mstatus, val);
    }

    /// \brief Reads the mtvec register
    uint64_t read_mtvec(void) {
        return read_csr(csr::mtvec);
    }

    /// \brief Writes the mtvec register
    void write_mtvec(uint64_t val) {
        write_csr(csr::mtvec, val);
    }

    /// \brief Reads the mscratch register
    uint64_t read_mscratch(void) {
        return read_csr(csr::mscratch);
    }

    /// \brief Writes the mscratch register
    void write_mscratch(uint64_t val) {
        write_csr(csr::mscratch, val);
    }

    /// \brief Reads the mepc register
    uint64_t read_mepc(void) {
        return read_csr(csr::mepc);
    }

    /// \brief Writes the mepc register
    void write_mepc(uint64_t val) {
        write_csr(csr::mepc, val);
    }

    /// \brief Reads the mcause register
    uint64_t read_mcause(void) {
        return read_csr(csr::mcause);
    }

    /// \brief Writes the mcause register
    void write_mcause(uint64_t val) {
        write_csr(csr::mcause, val);
    }

    /// \brief Reads the mtval register
    uint64_t read_mtval(void) {
        return read_csr(csr::mtval);
     }

    /// \brief Writes the mtval register
    void write_mtval(uint64_t val) {
        write_csr(csr::mtval, val);
    }

    /// \brief Reads the misa register
    uint64_t read_misa(void) {
        return read_csr(csr::misa);
    }

    /// \brief Writes the misa register
    void write_misa(uint64_t val) {
        write_csr(csr::misa, val);
    }

    /// \brief Reads the mie register
    uint64_t read_mie(void) {
        return read_csr(csr::mie);
    }

    /// \brief Writes the mie register
    void write_mie(uint64_t val) {
        write_csr(csr::mie, val);
    }

    /// \brief Reads the mip register
    uint64_t read_mip(void) {
        return read_csr(csr::mip);
    }

    /// \brief Writes the mip register
    void write_mip(uint64_t val) {
        write_csr(csr::mip, val);
    }

    /// \brief Reads the medeleg register
    uint64_t read_medeleg(void) {
        return read_csr(csr::medeleg);
    }

    /// \brief Writes the medeleg register
    void write_medeleg(uint64_t val) {
        write_csr(csr::medeleg, val);
    }

    /// \brief Reads the mideleg register
    uint64_t read_mideleg(void) {
        return read_csr(csr::mideleg);
    }

    /// \brief Writes the mideleg register
    /// \param val New register value.
    void write_mideleg(uint64_t val) {
        write_csr(csr::mideleg, val);
    }

    /// \brief Reads the mcounteren register
    uint64_t read_mcounteren(void) {
        return read_csr(csr::mcounteren);
    }

    /// \brief Writes the mcounteren register
    void write_mcounteren(uint64_t val) {
        write_csr(csr::mcounteren, val);
    }

    /// \brief Reads the stvec register
    uint64_t read_stvec(void) {
        return read_csr(csr::stvec);
    }

    /// \brief Writes the stvec register
    void write_stvec(uint64_t val) {
        write_csr(csr::stvec, val);
    }

    /// \brief Reads the sscratch register
    uint64_t read_sscratch(void) {
        return read_csr(csr::sscratch);
    }

    /// \brief Writes the sscratch register
    void write_sscratch(uint64_t val) {
        write_csr(csr::sscratch, val);
    }

    /// \brief Reads the sepc register
    uint64_t read_sepc(void) {
        return read_csr(csr::sepc);
    }

    /// \brief Writes the sepc register
    void write_sepc(uint64_t val) {
        write_csr(csr::sepc, val);
    }

    /// \brief Reads the scause register
    uint64_t read_scause(void) {
        return read_csr(csr::scause);
    }

    /// \brief Writes the scause register
    void write_scause(uint64_t val) {
        write_csr(csr::scause, val);
    }

    /// \brief Reads the stval register
    uint64_t read_stval(void) {
        return read_csr(csr::stval);
    }

    /// \brief Writes the stval register
    void write_stval(uint64_t val) {
        write_csr(csr::stval, val);
    }

    /// \brief Reads the satp register
    uint64_t read_satp(void) {
        return read_csr(csr::satp);
    }

    /// \brief Writes the satp register
    void write_satp(uint64_t val) {
        write_csr(csr::satp, val);
    }

    /// \brief Reads the scounteren register
    uint64_t read_scounteren(void) {
        return read_csr(csr::scounteren);
    }

    /// \brief Writes the scounteren register
    void write_scounteren(uint64_t val) {
        write_csr(csr::scounteren, val);
    }

    /// \brief Reads the ilrsc register
    uint64_t read_ilrsc(void) {
        return read_csr(csr::ilrsc);
    }

    /// \brief Writes the ilrsc register
    void write_ilrsc(uint64_t val) {
        write_csr(csr::ilrsc, val);
    }

    /// \brief Reads the iflags register
    uint64_t read_iflags(void) {
        return read_csr(csr::iflags);
    }

    /// \brief Reads the H I-flag
    bool read_iflags_H(void) {
        return read_csr(csr::htif_ihalt);
    }

    /// \brief Reads the I I-flag
    bool read_iflags_I(void) {
        return read_csr(csr::htif_iconsole);
    }

    /// \brief Reads the Y I-flag
    bool read_iflags_Y(void) {
        return read_csr(csr::htif_iyield);
    }

    /// \brief Writes the iflags register
    void write_iflags(uint64_t val) {
        write_csr(csr::iflags, val);
    }

    /// \brief Reads htif's tohost
    uint64_t read_htif_tohost(void) {
        return read_csr(csr::htif_tohost);
    }

    /// \brief Reads htif's tohost dev
    uint64_t read_htif_tohost_dev(void) {
        return HTIF_DEV_FIELD(read_htif_tohost());
    }

    /// \brief Reads htif's tohost cmd
    uint64_t read_htif_tohost_cmd(void) {
        return HTIF_CMD_FIELD(read_htif_tohost());
    }

    /// \brief Reads htif's tohost data
    uint64_t read_htif_tohost_data(void) {
        return HTIF_DATA_FIELD(read_htif_tohost());
    }

    /// \brief Writes htif's tohost
    void write_htif_tohost(uint64_t val) {
        write_csr(csr::htif_tohost, val);
    }

    /// \brief Reads htif's fromhost
    uint64_t read_htif_fromhost(void) {
        return read_csr(csr::htif_fromhost);
    }

    /// \brief Writes htif's fromhost
    void write_htif_fromhost(uint64_t val) {
        write_csr(csr::htif_fromhost, val);
    }

    /// \brief Writes htif's fromhost data
    void write_htif_fromhost_data(uint64_t val) {
        write_htif_fromhost(HTIF_REPLACE_DATA(read_htif_fromhost(), val));
    }

    /// \brief Reads htif's ihalt
    uint64_t read_htif_ihalt(void) {
        return read_csr(csr::htif_ihalt);
    }

    /// \brief Writes htif's ihalt
    void write_htif_ihalt(uint64_t val)  {
        write_csr(csr::htif_ihalt, val);
    }

    /// \brief Reads htif's iconsole
    uint64_t read_htif_iconsole(void) {
        return read_csr(csr::htif_iconsole);
    }

    /// \brief Writes htif's iconsole
    void write_htif_iconsole(uint64_t val) {
        write_csr(csr::htif_iconsole, val);
    }

    /// \brief Reads htif's iyield
    uint64_t read_htif_iyield(void) {
        return read_csr(csr::htif_iyield);
    }

    /// \brief Writes htif's iyield
    void write_htif_iyield(uint64_t val)  {
        write_csr(csr::htif_iyield, val);
    }

    /// \brief Reads clint's mtimecmp
    uint64_t read_clint_mtimecmp(void) {
        return read_csr(csr::clint_mtimecmp);
    }

    /// \brief Writes clint's mtimecmp
    void write_clint_mtimecmp(uint64_t val) {
        write_csr(csr::clint_mtimecmp, val);
    }

private:
    virtual void do_run(uint64_t mcycle_end) = 0;
    virtual void do_store(const std::string &dir) = 0;
    virtual access_log do_step(const access_log::type &log_type, bool one_based = false) = 0;
    virtual bool do_update_merkle_tree(void) = 0;
    virtual void do_get_proof(uint64_t address, int log2_size, merkle_tree::proof_type &proof) = 0;
    virtual void do_get_root_hash(hash_type &hash) = 0;
    virtual bool do_verify_merkle_tree(void) = 0;
    virtual uint64_t do_read_csr(csr r) = 0;
    virtual void do_write_csr(csr w, uint64_t val) = 0;
    virtual uint64_t do_get_csr_address(csr w) = 0;
    virtual void do_read_memory(uint64_t address, unsigned char *data, uint64_t length) = 0;
    virtual void do_write_memory(uint64_t address, const unsigned char *data, size_t length) = 0;
    virtual uint64_t do_read_x(int i) = 0;
    virtual void do_write_x(int i, uint64_t val) = 0;
    virtual uint64_t do_get_x_address(int i) = 0;
    virtual void do_replace_flash_drive(const flash_drive_config &new_flash) = 0;
    virtual void do_dump_pmas(void) = 0;
    virtual bool do_read_word(uint64_t word_address, uint64_t &word_value) = 0;
    virtual bool do_verify_dirty_page_maps(void) = 0;
    virtual machine_config do_get_initial_config(void) = 0;
    virtual void do_snapshot() = 0;
    virtual void do_shutdown() = 0;
    virtual void do_rollback() = 0;

};

} // namespace cartesi

#endif
