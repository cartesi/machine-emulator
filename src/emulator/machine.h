#ifndef MACHINE_H
#define MACHINE_H

/// \file
/// \brief Cartesi machine implementation

#include "merkle-tree.h"

// Forward definitions
struct machine_state;
struct pma_device_driver;

/// \brief Creates and initializes a new machine.
/// \returns State of newly created machine.
machine_state *machine_init(void);

/// \brief Runs the machine until mcycle reaches *at most* \p mcycle_end.
/// \param s Machine state.
/// \param mcycle_end Maximum value of mcycle before function returns.
/// \details Several conditions can cause the function to
///  return before mcycle reaches \p mcycle_end. The most
///  frequent scenario is when the program executes a WFI
///  instruction. Another example is when the machine halts
///  before reaching \p mcycle_end.
void machine_run(machine_state *s, uint64_t mcycle_end);

/// \brief Destroys a machine.
/// \param s Machine state.
void machine_end(machine_state *s);

/// \brief Update the Merkle tree so it matches the contents
/// of the machine state.
/// \param s Machine state.
/// \param t Merkle tree.
/// \returns true if succeeded, false otherwise.
bool machine_update_merkle_tree(machine_state *s, merkle_tree *t);

/// \brief Obtains the proof for the word at a given address
/// in the machine state.
/// \param s Machine state.
/// \param t Merkle tree.
/// \param address Address of *aligned* word.
/// \param proof Receives the proof.
/// \returns true if succeeded, false otherwise.
bool machine_get_word_value_proof(const machine_state *s, merkle_tree *t, uint64_t address, merkle_tree::word_value_proof &proof);

/// \brief Reads the value of a general-purpose register.
/// \param s Machine state.
/// \param i Register index.
/// \returns The value of the register.
uint64_t machine_read_register(const machine_state *s, int i);

/// \brief Reads the value of the pc register.
/// \param s Machine state.
/// \param i Register index.
/// \param val New register value.
void machine_write_register(machine_state *s, int i, uint64_t val);

/// \brief Reads the value of the pc register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_pc(const machine_state *s);

/// \brief Reads the value of the pc register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_pc(machine_state *s, uint64_t val);

/// \brief Reads the value of the mvendorid register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_mvendorid(const machine_state *s);

/// \brief Reads the value of the mvendorid register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_mvendorid(machine_state *s, uint64_t val);

/// \brief Reads the value of the marchid register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_marchid(const machine_state *s);

/// \brief Reads the value of the marchid register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_marchid(machine_state *s, uint64_t val);

/// \brief Reads the value of the mimpid register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_mimpid(const machine_state *s);

/// \brief Reads the value of the mimpid register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_mimpid(machine_state *s, uint64_t val);

/// \brief Reads the value of the mcycle register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_mcycle(const machine_state *s);

/// \brief Writes the value of the mcycle register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_mcycle(machine_state *s, uint64_t val);

/// \brief Reads the value of the minstret register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_minstret(const machine_state *s);

/// \brief Writes the value of the minstret register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_minstret(machine_state *s, uint64_t val);

/// \brief Reads the value of the mstatus register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_mstatus(const machine_state *s);

/// \brief Writes the value of the mstatus register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_mstatus(machine_state *s, uint64_t val);

/// \brief Reads the value of the mtvec register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_mtvec(const machine_state *s);

/// \brief Writes the value of the mtvec register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_mtvec(machine_state *s, uint64_t val);

/// \brief Reads the value of the mscratch register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_mscratch(const machine_state *s);

/// \brief Writes the value of the mscratch register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_mscratch(machine_state *s, uint64_t val);

/// \brief Reads the value of the mepc register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_mepc(const machine_state *s);

/// \brief Writes the value of the mepc register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_mepc(machine_state *s, uint64_t val);

/// \brief Reads the value of the mcause register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_mcause(const machine_state *s);

/// \brief Writes the value of the mcause register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_mcause(machine_state *s, uint64_t val);

/// \brief Reads the value of the mtval register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_mtval(const machine_state *s);

/// \brief Writes the value of the mtval register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_mtval(machine_state *s, uint64_t val);

/// \brief Reads the value of the misa register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_misa(const machine_state *s);

/// \brief Writes the value of the misa register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_misa(machine_state *s, uint64_t val);

/// \brief Reads the value of the mie register.
/// \param s Machine state.
/// \returns The value of the register.
uint32_t machine_read_mie(const machine_state *s);

/// \brief Reads the value of the mie register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_mie(machine_state *s, uint32_t val);

/// \brief Reads the value of the mip register.
/// \param s Machine state.
/// \returns The value of the register.
uint32_t machine_read_mip(const machine_state *s);

/// \brief Reads the value of the mip register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_mip(machine_state *s, uint32_t val);

/// \brief Reads the value of the medeleg register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_medeleg(const machine_state *s);

/// \brief Writes the value of the medeleg register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_medeleg(machine_state *s, uint64_t val);

/// \brief Reads the value of the mideleg register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_mideleg(const machine_state *s);

/// \brief Writes the value of the mideleg register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_mideleg(machine_state *s, uint64_t val);

/// \brief Reads the value of the mcounteren register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_mcounteren(const machine_state *s);

/// \brief Writes the value of the mcounteren register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_mcounteren(machine_state *s, uint64_t val);

/// \brief Reads the value of the stvec register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_stvec(const machine_state *s);

/// \brief Writes the value of the stvec register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_stvec(machine_state *s, uint64_t val);

/// \brief Reads the value of the sscratch register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_sscratch(const machine_state *s);

/// \brief Writes the value of the sscratch register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_sscratch(machine_state *s, uint64_t val);

/// \brief Reads the value of the sepc register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_sepc(const machine_state *s);

/// \brief Writes the value of the sepc register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_sepc(machine_state *s, uint64_t val);

/// \brief Reads the value of the scause register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_scause(const machine_state *s);

/// \brief Writes the value of the scause register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_scause(machine_state *s, uint64_t val);

/// \brief Reads the value of the stval register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_stval(const machine_state *s);

/// \brief Writes the value of the stval register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_stval(machine_state *s, uint64_t val);

/// \brief Reads the value of the satp register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_satp(const machine_state *s);

/// \brief Writes the value of the satp register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_satp(machine_state *s, uint64_t val);

/// \brief Reads the value of the scounteren register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_scounteren(const machine_state *s);

/// \brief Writes the value of the scounteren register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_scounteren(machine_state *s, uint64_t val);

/// \brief Reads the value of the ilrsc register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_ilrsc(const machine_state *s);

/// \brief Writes the value of the ilrsc register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_ilrsc(machine_state *s, uint64_t val);

/// \brief Reads the value of the iflags register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_iflags(const machine_state *s);

/// \brief Reads the value of the iflags register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_iflags(machine_state *s, uint64_t val);

/// \brief Returns the maximum XLEN for the machine.
/// \param s Machine state.
/// \returns The value for XLEN.
int machine_get_max_xlen(const machine_state *s);

/// \brief Reads the value of HTIF's tohost register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_tohost(const machine_state *s);

/// \brief Writes the value of HTIF's tohost register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_tohost(machine_state *s, uint64_t val);

/// \brief Reads the value of HTIF's fromhost register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_fromhost(const machine_state *s);

/// \brief Writes the value of HTIF's fromhost register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_fromhost(machine_state *s, uint64_t val);

/// \brief Reads the value of CLINT's mtimecmp register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t machine_read_mtimecmp(const machine_state *s);

/// \brief Writes the value of CLINT's mtimecmp register.
/// \param s Machine state.
/// \param val New register value.
void machine_write_mtimecmp(machine_state *s, uint64_t val);

/// \brief Checks the value of the iflags_I flag.
/// \param s Machine state.
/// \returns The flag value.
bool machine_read_iflags_I(const machine_state *s);

/// \brief Resets the value of the iflags_I flag.
/// \param s Machine state.
void machine_reset_iflags_I(machine_state *s);

/// \brief Sets bits in mip.
/// \param s Machine state.
/// \param mask Bits set in \p mask will also be set in mip
void machine_set_mip(machine_state *s, uint32_t mask);

/// \brief Resets bits in mip.
/// \param s Machine state.
/// \param mask Bits set in \p mask will also be reset in mip
void machine_reset_mip(machine_state *s, uint32_t mask);

/// \brief Updates the brk flag from changes in mip and mie registers.
/// \param s Machine state.
void machine_set_brk_from_mip_mie(machine_state *s);

/// \brief Checks the value of the iflags_H flag.
/// \param s Machine state.
/// \returns The flag value.
bool machine_read_iflags_H(const machine_state *s);

/// \brief Sets the iflags_H flag.
/// \param s Machine state.
void machine_set_iflags_H(machine_state *s);

/// \brief Updates the brk flag from changes in the iflags_H flag.
/// \param s Machine state.
void machine_set_brk_from_iflags_H(machine_state *s);

/// \brief Obtain a pointer into the host memory
/// corresponding to the target memory at a given address
/// \param s Machine state.
/// \param paddr Physical memory address in target.
/// \returns Pointer to host memory corresponding to \p
/// paddr, or nullptr if there is no such address.
uint8_t *machine_get_host_memory(machine_state *s, uint64_t paddr);

/// \brief Register a new flash drive.
/// \param s Machine state.
/// \param start Start of physical memory range in the target address
/// space on which to map the flash drive.
/// \param length Length of physical memory range in the
/// target address space on which to map the flash drive.
/// \param path Pointer to a string containing the filename
/// for the backing file in the host with the contents of the flash drive.
/// \param shared Whether target modifications to the flash drive are
/// reflected in the host's backing file.
/// \details \p length must match the size of the backing file.
/// \returns true if successful, false otherwise.
bool machine_register_flash(machine_state *s, uint64_t start, uint64_t length,
    const char *path, bool shared);

/// \brief Register a new RAM memory range.
/// \param s Machine state.
/// \param start Start of physical memory range in the target address
/// space on which to map the RAM memory.
/// \param length Length of physical memory range in the
/// target address space on which to map the RAM memory.
/// \returns true if successful, false otherwise.
bool machine_register_ram(machine_state *s, uint64_t start, uint64_t length);

/// \brief Register a new memory-mapped IO device.
/// \param s Machine state.
/// \param start Start of physical memory range in the target address
/// space on which to map the device.
/// \param length Length of physical memory range in the
/// target address space on which to map the device.
/// \param context Pointer to context to be passed to callbacks.
/// \param driver Pointer to driver with callbacks.
/// \returns true if successful, false otherwise.
bool machine_register_mmio(machine_state *s, uint64_t start, uint64_t length, void *context, const pma_device_driver *driver);

/// \brief Register a new shadow device.
/// \param s Machine state.
/// \param start Start of physical memory range in the target address
/// space on which to map the shadow device.
/// \param length Length of physical memory range in the
/// target address space on which to map the shadow device.
/// \param context Pointer to context to be passed to callbacks.
/// \param driver Pointer to driver with callbacks.
/// \returns true if successful, false otherwise.
bool machine_register_shadow(machine_state *s, uint64_t start, uint64_t length, void *context, const pma_device_driver *driver);

/// \brief Dump all memory ranges to files.
/// \param s Machine state.
/// \returns true if successful, false otherwise.
bool machine_dump(const machine_state *s);

#endif
