#ifndef MACHINE_H
#define MACHINE_H

/// \file
/// \brief Cartesi machine implementation

#include <memory>

#include "machine-state.h"
#include "machine-config.h"
#include "merkle-tree.h"
#include "htif.h"

namespace cartesi {

// Forward declarations
struct access_log;

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

    /// \brief Allocates a new PMA entry.
    /// \param pma PMA entry to add to machine.
    /// \returns Reference to corresponding entry in machine state.
    pma_entry &allocate_pma_entry(pma_entry &&pma);

    /// \brief Register a new memory range initially filled with zeros.
    /// \param start Start of PMA range.
    /// \param length Length of PMA range.
    /// \param W Value of PMA W flag.
    /// \returns Reference to corresponding entry in machine state.
    pma_entry &register_memory(uint64_t start, uint64_t length, bool W);

    /// \brief Register a new memory range initially filled with the
    /// contents of a backing file.
    /// \param start Start of PMA range.
    /// \param length Length of PMA range.
    /// \param path Path to backing file.
    /// \param W Value of PMA W flag.
    /// \returns Reference to corresponding entry in machine state.
    pma_entry &register_memory(uint64_t start, uint64_t length,
        const std::string &name, bool W);

    /// \brief Runs the machine until mcycle reaches *at most* \p mcycle_end.
    /// \param mcycle_end Maximum value of mcycle before function returns.
    /// \details Several conditions can cause the function to
    ///  break before mcycle reaches \p mcycle_end. The most
    ///  frequent scenario is when the program executes a WFI
    ///  instruction. Another example is when the machine halts.
    void run_inner_loop(uint64_t mcycle_end);

public:

    /// \brief Constructor from machine configuration
    explicit machine(const machine_config &c);

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
    /// \param t Merkle tree.
    /// \param log Receives log of all state accesses.
    void step(access_log &log);

    /// \brief Returns machine state for direct access.
    machine_state &get_state(void) { return m_s; }

    /// \brief Returns machine state for direct read-only access.
    const machine_state &get_state(void) const { return m_s; }

    /// \brief Destructor.
    ~machine();

    /// \brief Returns the associated Merkle tree.
    const merkle_tree &get_merkle_tree(void) const;
    /// \brief Returns the associated Merkle tree.
    merkle_tree &get_merkle_tree(void);

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
    /// \returns true if succeeded, false otherwise.
    bool get_proof(uint64_t address, int log2_size, merkle_tree::proof_type &proof) const;

    /// \brief Read the value of a word in the machine state.
    /// \param word_address Word address (aligned to 64-bit boundary).
    /// \param word_value Receives word value.
    /// \returns true if succeeded, false otherwise.
    /// \warning The current implementation of this function is very slow!
    bool read_word(uint64_t word_address, uint64_t &word_value) const;

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
    uint64_t packed_iflags(int PRV, int I, int H);

    /// \brief Reads the value of the iflags register.
    /// \param val New register value.
    void write_iflags(uint64_t val);

    /// \brief Returns the maximum XLEN for the machine.
    /// \returns The value for XLEN.
    /// \brief Reads the value of HTIF's tohost register.
    /// \returns The value of the register.
    uint64_t read_htif_tohost(void) const;

    /// \brief Writes the value of HTIF's tohost register.
    /// \param val New register value.
    void write_htif_tohost(uint64_t val);

    /// \brief Reads the value of HTIF's fromhost register.
    /// \returns The value of the register.
    uint64_t read_htif_fromhost(void) const;

    /// \brief Writes the value of HTIF's fromhost register.
    /// \param val New register value.
    void write_htif_fromhost(uint64_t val);

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

    /// \brief Sets bits in mip.
    /// \param mask Bits set in \p mask will also be set in mip
    void set_mip(uint32_t mask);

    /// \brief Resets bits in mip.
    /// \param mask Bits set in \p mask will also be reset in mip
    void reset_mip(uint32_t mask);

    /// \brief Checks the value of the iflags_H flag.
    /// \returns The flag value.
    bool read_iflags_H(void) const;

    /// \brief Checks the value of the iflags_PRV field.
    /// \returns The field value.
    uint8_t read_iflags_PRV(void) const;

    /// \brief Sets the iflags_H flag.
    void set_iflags_H(void);

    /// \brief Obtain a pointer into the host memory
    /// corresponding to the target memory at a given address
    /// \param paddr Physical memory address in target.
    /// \returns Pointer to host memory corresponding to \p
    /// paddr, or nullptr if no memory range covers \p paddr
    uint8_t *get_host_memory(uint64_t paddr);

    /// \brief Register a new flash drive.
    /// \param start Start of physical memory range in the target address
    /// space on which to map the flash drive.
    /// \param length Length of physical memory range in the
    /// target address space on which to map the flash drive.
    /// \param path Pointer to a string containing the filename
    /// for the backing file in the host with the contents of the flash drive.
    /// \param shared Whether target modifications to the flash drive are
    /// reflected in the host's backing file.
    /// \details \p length must match the size of the backing file.
    void register_flash(uint64_t start, uint64_t length, const char *path, bool shared);

    /// \brief Register a new memory-mapped IO device.
    /// \param start Start of physical memory range in the target address
    /// space on which to map the device.
    /// \param length Length of physical memory range in the
    /// target address space on which to map the device.
    /// \param peek Peek callback for the range.
    /// \param context Pointer to context to be passed to callbacks.
    /// \param driver Pointer to driver with callbacks.
    /// \param DID PMA device id.
    void register_mmio(uint64_t start, uint64_t length, pma_peek peek, void *context, const pma_driver *driver, PMA_ISTART_DID DID);

    /// \brief Register a new shadow device.
    /// \param start Start of physical memory range in the target address
    /// space on which to map the shadow device.
    /// \param length Length of physical memory range in the
    /// target address space on which to map the shadow device.
    /// \param peek Peek callback for the range.
    /// \param context Pointer to context to be passed to callbacks.
    /// \param driver Pointer to driver with callbacks.
    void register_shadow(uint64_t start, uint64_t length, pma_peek peek, void *context, const pma_driver *driver);

    /// \brief Dump all memory ranges to files in current working directory.
    /// \returns true if successful, false otherwise.
    void dump(void) const;

    /// \brief Get read-only access to container with all PMA entries.
    /// \returns The container.
    const boost::container::static_vector<pma_entry, PMA_MAX> &get_pmas(void) const;

    /// \brief Interact with console
    void interact(void);
};

/// \brief Returns a string describing the implementation
std::string get_name(void);

} // namespace cartesi

#endif
