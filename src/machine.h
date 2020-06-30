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

#ifndef MACHINE_H
#define MACHINE_H

/// \file
/// \brief Cartesi machine interface

#include <memory>

#include "machine-state.h"
#include "machine-config.h"
#include "merkle-tree.h"
#include "access-log.h"
#include "htif.h"

namespace cartesi {

/// \class machine
/// \brief Cartesi Machine implementation
class machine final {

    //??D Ideally, we would hold a unique_ptr to the state. This
    //    would allow us to remove the machine-state.h include and
    //    therefore hide its contents from anyone who includes only
    //    machine.h. Maybe the compiler can do a good job we we are
    //    not constantly going through the extra indirection. We
    //    should test this.
    machine_state m_s;   ///< Opaque machine state
    merkle_tree m_t;     ///< Merkle tree of state
    htif m_h;            ///< HTIF device

    machine_config m_c;  ///< Copy of initialization config

    static pma_entry::flags m_rom_flags;    ///< PMA flags used for ROM
    static pma_entry::flags m_ram_flags;    ///< PMA flags used for RAM
    static pma_entry::flags m_flash_flags;  ///< PMA flags used for flash drives

    /// \brief Allocates a new PMA entry.
    /// \param pma PMA entry to add to machine.
    /// \returns Reference to corresponding entry in machine state.
    pma_entry &register_pma_entry(pma_entry &&pma);

    /// \brief Replaces an existing PMA entry.
    /// \param new_entry The new PMA entry
    /// \returns Reference to the new entry in the machine state.
    /// \details The first PMA entry matching the size and length
    /// of new_entry will be replaced. Throws std::invalid_argument
    /// if a matching PMA entry can't be found
    pma_entry& replace_pma_entry(pma_entry&& new_entry);


    /// \brief Creates a new PMA entry reflecting a flash drive configuration.
    /// \param flash Flash drive configuration.
    /// \returns Reference to New PMA entry.
    static pma_entry make_flash_pma_entry(const flash_drive_config &c);

    /// \brief Runs the machine until mcycle reaches *at most* \p mcycle_end.
    /// \param mcycle_end Maximum value of mcycle before function returns.
    /// \details Several conditions can cause the function to
    ///  break before mcycle reaches \p mcycle_end. The most
    ///  frequent scenario is when the program executes a WFI
    ///  instruction. Another example is when the machine halts.
    void run_inner_loop(uint64_t mcycle_end);

    /// \brief Decides if machine should yield
    bool should_yield(void) const;

public:

    /// \brief Type of hash
    using hash_type = merkle_tree::hash_type;

    /// \brief List of CSRs to use with read_csr and write_csr
    enum class csr {
        pc,
        mvendorid,
        marchid,
        mimpid,
        mcycle,
        minstret,
        mstatus,
        mtvec,
        mscratch,
        mepc,
        mcause,
        mtval,
        misa,
        mie,
        mip,
        medeleg,
        mideleg,
        mcounteren,
        stvec,
        sscratch,
        sepc,
        scause,
        stval,
        satp,
        scounteren,
        ilrsc,
        iflags,
        clint_mtimecmp,
        htif_tohost,
        htif_fromhost,
        htif_ihalt,
        htif_iconsole,
        htif_iyield,
    };

    static const uint64_t MVENDORID = MVENDORID_INIT;
    static const uint64_t MARCHID = MARCHID_INIT;
    static const uint64_t MIMPID = MIMPID_INIT;

    /// \brief Constructor from machine configuration
    explicit machine(const machine_config &c);

    /// \brief Constructor from previously serialized directory
    explicit machine(const std::string &dir);

    /// \brief Serialize entire state to directory
    /// \details The method is not const because it updates the root hash
    void store(const std::string &dir);

    /// \brief No default constructor
    machine(void) = delete;
    /// \brief No copy constructor
    machine(const machine &other) = delete;
    /// \brief No move constructor
    machine(machine &&other) = delete;
    /// \brief No copy assignment
    machine &operator=(const machine &other) = delete;
    /// \brief No move assignment
    machine &operator=(machine &&other) = delete;

    /// \brief Runs the machine until mcycle reaches mcycle_end or the machine halts.
    void run(uint64_t mcycle_end);

    /// \brief Runs the machine for one cycle logging all accesses to the state.
    /// \param log_type Type of access log to generate.
    /// \param one_based Use 1-based indices when reporting errors.
    /// \returns The state access log.
    access_log step(const access_log::type &log_type, bool one_based = false);

    /// \brief Verifies a proof.
    /// \param proof Proof to be verified.
    /// \return True if proof is consistent, false otherwise.
    static bool verify_proof(const merkle_tree::proof_type &proof);

    /// \brief Checks the internal consistency of an access log.
    /// \param log State access log to be verified.
    /// \param one_based Use 1-based indices when reporting errors.
    static void verify_access_log(const access_log &log,
        bool one_based = false);

    /// \brief Checks the validity of a state transition.
    /// \param root_hash_before State hash before step.
    /// \param log Step state access log.
    /// \param root_hash_after State hash after step.
    /// \param one_based Use 1-based indices when reporting errors.
    static void verify_state_transition(const hash_type &root_hash_before,
        const access_log &log, const hash_type &root_hash_after,
        bool one_based = false);

    /// \brief Returns machine state for direct access.
    machine_state &get_state(void) { return m_s; }

    /// \brief Returns machine state for direct read-only access.
    const machine_state &get_state(void) const { return m_s; }

    /// \brief Destructor.
    ~machine();

    /// \brief Update the Merkle tree so it matches the contents of the machine state.
    /// \returns true if succeeded, false otherwise.
    bool update_merkle_tree(void);

    /// \brief Update the Merkle tree after a page has been modified in the machine state.
    /// \param address Any address inside modified page.
    /// \returns true if succeeded, false otherwise.
    bool update_merkle_tree_page(uint64_t address);

    /// \brief Obtains the proof for a node in the Merkle tree.
    /// \param address Address of target node. Must be aligned to a 2<sup>log2_size</sup> boundary.
    /// \param log2_size log<sub>2</sub> of size subintended by target node.
    /// Must be between 3 (for a word) and 64 (for the entire address space), inclusive.
    /// \param proof Receives the proof.
    /// \details If the node is smaller than a page size, then it must lie entirely inside the same PMA range.
    void get_proof(uint64_t address, int log2_size, merkle_tree::proof_type &proof) const;

    /// \brief Obtains the root hash of the Merkle tree.
    /// \param hash Receives the hash.
    void get_root_hash(hash_type &hash) const;

    /// \brief Verifies integrity of Merkle tree.
    /// \returns True if tree is self-consistent, false otherwise.
    bool verify_merkle_tree(void) const;

    /// \brief Read the value of any CSR
    /// \param r CSR to read
    /// \returns The value of the CSR
    uint64_t read_csr(csr r) const;

    /// \brief Write the value of any CSR
    /// \param w CSR to write
    /// \param val Value to write
    void write_csr(csr w, uint64_t val);

    /// \brief Read the value of a word in the machine state.
    /// \param word_address Word address (aligned to 64-bit boundary).
    /// \param word_value Receives word value.
    /// \returns true if succeeded, false otherwise.
    /// \warning The current implementation of this function is very slow!
    bool read_word(uint64_t word_address, uint64_t &word_value) const;

    /// \brief Reads a chunk of data from the machine memory.
    /// \param address Address to start reading.
    /// \param data Receives chunk of memory.
    /// \param length Size of chunk.
    /// \details The entire chunk, from \p address to \p address + \p length must
    /// be inside the same PMA region. Moreover, this PMA must be a memory PMA,
    /// and not a device PMA.
    void read_memory(uint64_t address, unsigned char *data, uint64_t length) const;

    /// \brief Writes a chunk of data to the machine memory.
    /// \param address Address to start writing.
    /// \param data Source for chunk of data.
    /// \param length Size of chunk.
    /// \details The entire chunk, from \p address to \p address + \p length must
    /// be inside the same PMA region. Moreover, this PMA must be a memory PMA,
    /// and not a device PMA.
    void write_memory(uint64_t address, const unsigned char *data, size_t length);

    /// \brief Reads the value of a general-purpose register.
    /// \param i Register index.
    /// \returns The value of the register.
    uint64_t read_x(int i) const;

    /// \brief Writes the value of a general-purpose register.
    /// \param i Register index.
    /// \param val New register value.
    void write_x(int i, uint64_t val);

    /// \brief Reads the value of the pc register.
    /// \returns The value of the register.
    uint64_t read_pc(void) const;

    /// \brief Reads the value of the pc register.
    /// \param val New register value.
    void write_pc(uint64_t val);

    /// \brief Reads the value of the mvendorid register.
    /// \returns The value of the register.
    uint64_t read_mvendorid(void) const;

    /// \brief Reads the value of the mvendorid register.
    /// \param val New register value.
    void write_mvendorid(uint64_t val);

    /// \brief Reads the value of the marchid register.
    /// \returns The value of the register.
    uint64_t read_marchid(void) const;

    /// \brief Reads the value of the marchid register.
    /// \param val New register value.
    void write_marchid(uint64_t val);

    /// \brief Reads the value of the mimpid register.
    /// \returns The value of the register.
    uint64_t read_mimpid(void) const;

    /// \brief Reads the value of the mimpid register.
    /// \param val New register value.
    void write_mimpid(uint64_t val);

    /// \brief Reads the value of the mcycle register.
    /// \returns The value of the register.
    uint64_t read_mcycle(void) const;

    /// \brief Writes the value of the mcycle register.
    /// \param val New register value.
    void write_mcycle(uint64_t val);

    /// \brief Reads the value of the minstret register.
    /// \returns The value of the register.
    uint64_t read_minstret(void) const;

    /// \brief Writes the value of the minstret register.
    /// \param val New register value.
    void write_minstret(uint64_t val);

    /// \brief Reads the value of the mstatus register.
    /// \returns The value of the register.
    uint64_t read_mstatus(void) const;

    /// \brief Writes the value of the mstatus register.
    /// \param val New register value.
    void write_mstatus(uint64_t val);

    /// \brief Reads the value of the mtvec register.
    /// \returns The value of the register.
    uint64_t read_mtvec(void) const;

    /// \brief Writes the value of the mtvec register.
    /// \param val New register value.
    void write_mtvec(uint64_t val);

    /// \brief Reads the value of the mscratch register.
    /// \returns The value of the register.
    uint64_t read_mscratch(void) const;

    /// \brief Writes the value of the mscratch register.
    /// \param val New register value.
    void write_mscratch(uint64_t val);

    /// \brief Reads the value of the mepc register.
    /// \returns The value of the register.
    uint64_t read_mepc(void) const;

    /// \brief Writes the value of the mepc register.
    /// \param val New register value.
    void write_mepc(uint64_t val);

    /// \brief Reads the value of the mcause register.
    /// \returns The value of the register.
    uint64_t read_mcause(void) const;

    /// \brief Writes the value of the mcause register.
    /// \param val New register value.
    void write_mcause(uint64_t val);

    /// \brief Reads the value of the mtval register.
    /// \returns The value of the register.
    uint64_t read_mtval(void) const;

    /// \brief Writes the value of the mtval register.
    /// \param val New register value.
    void write_mtval(uint64_t val);

    /// \brief Reads the value of the misa register.
    /// \returns The value of the register.
    uint64_t read_misa(void) const;

    /// \brief Writes the value of the misa register.
    /// \param val New register value.
    void write_misa(uint64_t val);

    /// \brief Reads the value of the mie register.
    /// \returns The value of the register.
    uint64_t read_mie(void) const;

    /// \brief Reads the value of the mie register.
    /// \param val New register value.
    void write_mie(uint64_t val);

    /// \brief Reads the value of the mip register.
    /// \returns The value of the register.
    uint64_t read_mip(void) const;

    /// \brief Reads the value of the mip register.
    /// \param val New register value.
    void write_mip(uint64_t val);

    /// \brief Reads the value of the medeleg register.
    /// \returns The value of the register.
    uint64_t read_medeleg(void) const;

    /// \brief Writes the value of the medeleg register.
    /// \param val New register value.
    void write_medeleg(uint64_t val);

    /// \brief Reads the value of the mideleg register.
    /// \returns The value of the register.
    uint64_t read_mideleg(void) const;

    /// \brief Writes the value of the mideleg register.
    /// \param val New register value.
    void write_mideleg(uint64_t val);

    /// \brief Reads the value of the mcounteren register.
    /// \returns The value of the register.
    uint64_t read_mcounteren(void) const;

    /// \brief Writes the value of the mcounteren register.
    /// \param val New register value.
    void write_mcounteren(uint64_t val);

    /// \brief Reads the value of the stvec register.
    /// \returns The value of the register.
    uint64_t read_stvec(void) const;

    /// \brief Writes the value of the stvec register.
    /// \param val New register value.
    void write_stvec(uint64_t val);

    /// \brief Reads the value of the sscratch register.
    /// \returns The value of the register.
    uint64_t read_sscratch(void) const;

    /// \brief Writes the value of the sscratch register.
    /// \param val New register value.
    void write_sscratch(uint64_t val);

    /// \brief Reads the value of the sepc register.
    /// \returns The value of the register.
    uint64_t read_sepc(void) const;

    /// \brief Writes the value of the sepc register.
    /// \param val New register value.
    void write_sepc(uint64_t val);

    /// \brief Reads the value of the scause register.
    /// \returns The value of the register.
    uint64_t read_scause(void) const;

    /// \brief Writes the value of the scause register.
    /// \param val New register value.
    void write_scause(uint64_t val);

    /// \brief Reads the value of the stval register.
    /// \returns The value of the register.
    uint64_t read_stval(void) const;

    /// \brief Writes the value of the stval register.
    /// \param val New register value.
    void write_stval(uint64_t val);

    /// \brief Reads the value of the satp register.
    /// \returns The value of the register.
    uint64_t read_satp(void) const;

    /// \brief Writes the value of the satp register.
    /// \param val New register value.
    void write_satp(uint64_t val);

    /// \brief Reads the value of the scounteren register.
    /// \returns The value of the register.
    uint64_t read_scounteren(void) const;

    /// \brief Writes the value of the scounteren register.
    /// \param val New register value.
    void write_scounteren(uint64_t val);

    /// \brief Reads the value of the ilrsc register.
    /// \returns The value of the register.
    uint64_t read_ilrsc(void) const;

    /// \brief Writes the value of the ilrsc register.
    /// \param val New register value.
    void write_ilrsc(uint64_t val);

    /// \brief Reads the value of the iflags register.
    /// \returns The value of the register.
    uint64_t read_iflags(void) const;

    /// \brief Returns packed iflags from its component fields.
    /// \returns The value of the register.
    uint64_t packed_iflags(int PRV, int I, int Y, int H);

    /// \brief Reads the value of the iflags register.
    /// \param val New register value.
    void write_iflags(uint64_t val);

    /// \brief Reads the value of HTIF's tohost register.
    /// \returns The value of the register.
    uint64_t read_htif_tohost(void) const;

    /// \brief Reads the value of the device field of HTIF's tohost register.
    /// \returns The value of the field.
    uint64_t read_htif_tohost_dev(void) const;

    /// \brief Reads the value of the command field of HTIF's tohost register.
    /// \returns The value of the field.
    uint64_t read_htif_tohost_cmd(void) const;

    /// \brief Reads the value of the data field of HTIF's tohost register.
    /// \returns The value of the field.
    uint64_t read_htif_tohost_data(void) const;

    /// \brief Writes the value of HTIF's tohost register.
    /// \param val New register value.
    void write_htif_tohost(uint64_t val);

    /// \brief Reads the value of HTIF's fromhost register.
    /// \returns The value of the register.
    uint64_t read_htif_fromhost(void) const;

    /// \brief Writes the value of HTIF's fromhost register.
    /// \param val New register value.
    void write_htif_fromhost(uint64_t val);

    /// \brief Writes the value of the data field in HTIF's fromhost register.
    /// \param val New value for the field.
    void write_htif_fromhost_data(uint64_t val);

    /// \brief Reads the value of HTIF's halt register.
    /// \returns The value of the register.
    uint64_t read_htif_ihalt(void) const;

    /// \brief Writes the value of HTIF's halt register.
    /// \param val New register value.
    void write_htif_ihalt(uint64_t val);

    /// \brief Reads the value of HTIF's console register.
    /// \returns The value of the register.
    uint64_t read_htif_iconsole(void) const;

    /// \brief Writes the value of HTIF's console register.
    /// \param val New register value.
    void write_htif_iconsole(uint64_t val);

    /// \brief Reads the value of HTIF's yield register.
    /// \returns The value of the register.
    uint64_t read_htif_iyield(void) const;

    /// \brief Writes the value of HTIF's yield register.
    /// \param val New register value.
    void write_htif_iyield(uint64_t val);

    /// \brief Reads the value of CLINT's mtimecmp register.
    /// \returns The value of the register.
    uint64_t read_clint_mtimecmp(void) const;

    /// \brief Writes the value of CLINT's mtimecmp register.
    /// \param val New register value.
    void write_clint_mtimecmp(uint64_t val);

    /// \brief Checks the value of the iflags_I flag.
    /// \returns The flag value.
    bool read_iflags_I(void) const;

    /// \brief Resets the value of the iflags_I flag.
    void reset_iflags_I(void);

    /// \brief Sets the iflags_I flag.
    void set_iflags_I(void);

    /// \brief Checks the value of the iflags_Y flag.
    /// \returns The flag value.
    bool read_iflags_Y(void) const;

    /// \brief Resets the value of the iflags_Y flag.
    void reset_iflags_Y(void);

    /// \brief Sets the iflags_Y flag.
    void set_iflags_Y(void);

    /// \brief Checks the value of the iflags_H flag.
    /// \returns The flag value.
    bool read_iflags_H(void) const;

    /// \brief Checks the value of the iflags_PRV field.
    /// \returns The field value.
    uint8_t read_iflags_PRV(void) const;

    /// \brief Sets the iflags_H flag.
    void set_iflags_H(void);

    /// \brief Sets bits in mip.
    /// \param mask Bits set in \p mask will also be set in mip
    void set_mip(uint32_t mask);

    /// \brief Resets bits in mip.
    /// \param mask Bits set in \p mask will also be reset in mip
    void reset_mip(uint32_t mask);

    /// \brief Dump all memory ranges to files in current working directory.
    /// \returns true if successful, false otherwise.
    void dump_pmas(void) const;

    /// \brief Get read-only access to container with all PMA entries.
    /// \returns The container.
    const boost::container::static_vector<pma_entry, PMA_MAX> &get_pmas(void) const;

    /// \brief Interact with console
    void interact(void);

    /// \brief Verify if dirty page maps are consistent.
    /// \returns true if they are, false if there is an error.
    bool verify_dirty_page_maps(void) const;

    /// \brief Copies the current state into a configuration for serialization
    /// \returns The configuration
    machine_config get_serialization_config(void) const;

    /// \brief Returns copy of initialization config.
    const machine_config &get_initial_config(void) const { return m_c; }

    /// \brief Saves PMAs into files for serialization
    /// \param c Machine config to be stored
    /// \param dir Directory where PMAs will be stored
    void store_pmas(const machine_config &c, const std::string &dir) const;

    /// \brief Replaces a flash drive.
    /// \param new_flash Configuration of the new flash drive.
    /// \details The machine must contain an existing flash
    /// drive matching the start and length specified in new_flash.
    void replace_flash_drive(const flash_drive_config &new_flash);
};

} // namespace cartesi

#endif
