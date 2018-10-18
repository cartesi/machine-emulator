#ifndef MACHINE_H
#define MACHINE_H

/// \file
/// \brief Cartesi machine implementation

/// \brief The opaque machine_state structure stores the
/// entire machine state.
typedef struct machine_state machine_state;

#include "i-device-state-access.h"
#include "merkle-tree.h"

/// \brief Prototype for callback invoked when machine wants
/// to read from a device.
/// \param da Object through which the machine state can be accessed by device.
/// \param context Device context (set during device initialization).
/// \param offset Offset of requested value from device base address.
/// \param val Pointer to word where value should be stored.
/// \param size_log2 log<sub>2</sub> of size of value to read (0 = uint8_t, 1 = uint16_t, 2 = uint32_t, 3 = uint64_t).
typedef bool (*pma_device_read)(i_device_state_access *da, void *context, uint64_t offset, uint64_t *val, int size_log2);

/// \brief Prototype for callback invoked when machine wants
/// to write to a device.
/// \param da Object through which the machine state can be accessed by device.
/// \param context Device context (set during device initialization).
/// \param offset Offset of requested value from device base address.
/// \param val Word to be written at \p offset.
/// \param size_log2 log<sub>2</sub> of size of value to read (0 = uint8_t, 1 = uint16_t, 2 = uint32_t, 3 = uint64_t).
typedef bool (*pma_device_write)(i_device_state_access *da, void *context, uint64_t offset, uint64_t val, int size_log2);

/// \brief Prototype for callback invoked when machine wants
/// to peek into a device with no side-effects.
/// \param s Machine state for naked read-only access.
/// \param context Device context (set during device initialization).
/// \param offset Offset of requested value from device base address.
/// \param val Pointer to word where value should be stored.
/// \param size_log2 log<sub>2</sub> of size of value to read (0 = uint8_t, 1 = uint16_t, 2 = uint32_t, 3 = uint64_t).
typedef bool (*pma_device_peek)(const machine_state *s, void *context, uint64_t offset, uint64_t *val, int size_log2);

/// \brief Prototype for callback invoked when machine needs
/// the device to update its mapped range into a Merkle tree.
/// \param s Machine state for naked read-only access.
/// \param context Device context (set during device initialization).
/// \param start Base address for device.
/// \param length Length of memory region mapped to device.
/// \param kc Keccak hasher object.
/// \param t Merkle tree to be updated.
typedef bool (*pma_device_update_merkle_tree)(const machine_state *s, void *context, uint64_t start, uint64_t length,
    CryptoPP::Keccak_256 &kc, merkle_tree *t);

/// \name Interrupt pending flags for use with set/reset mip
/// \{
#define MIP_USIP   (1 << 0) ///< User software interrupt
#define MIP_SSIP   (1 << 1) ///< Supervisor software interrupt
#define MIP_HSIP   (1 << 2) ///< Reserved
#define MIP_MSIP   (1 << 3) ///< Machine software interrupt
#define MIP_UTIP   (1 << 4) ///< User timer interrupt
#define MIP_STIP   (1 << 5) ///< Supervisor timer interrupt
#define MIP_HTIP   (1 << 6) ///< Reserved
#define MIP_MTIP   (1 << 7) ///< Machine timer interrupt
#define MIP_UEIP   (1 << 8) ///< User external interrupt
#define MIP_SEIP   (1 << 9) ///< Supervisor external interrupt
#define MIP_HEIP   (1 << 10) ///< Reserved
#define MIP_MEIP   (1 << 11) ///< Machine external interrupt
/// \}

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
bool machine_get_word_value_proof(machine_state *s, merkle_tree *t, uint64_t address, merkle_tree::word_value_proof &proof);

/// \brief Returns the maximum XLEN for the machine.
/// \param s Machine state.
/// \returns The value for XLEN.
int processor_get_max_xlen(const machine_state *s);

/// \brief Reads the value of the misa register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t processor_read_misa(const machine_state *s);

/// \brief Reads the value of the mcycle register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t processor_read_mcycle(const machine_state *s);

/// \brief Writes the value of the mcycle register.
/// \param s Machine state.
/// \param val New register value.
void processor_write_mcycle(machine_state *s, uint64_t val);

/// \brief Reads the value of HTIF's tohost register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t processor_read_tohost(const machine_state *s);

/// \brief Writes the value of HTIF's tohost register.
/// \param s Machine state.
/// \param val New register value.
void processor_write_tohost(machine_state *s, uint64_t val);

/// \brief Reads the value of HTIF's fromhost register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t processor_read_fromhost(const machine_state *s);

/// \brief Writes the value of HTIF's fromhost register.
/// \param s Machine state.
/// \param val New register value.
void processor_write_fromhost(machine_state *s, uint64_t val);

/// \brief Reads the value of CLINT's mtimecmp register.
/// \param s Machine state.
/// \returns The value of the register.
uint64_t processor_read_mtimecmp(const machine_state *s);

/// \brief Writes the value of CLINT's mtimecmp register.
/// \param s Machine state.
/// \param val New register value.
void processor_write_mtimecmp(machine_state *s, uint64_t val);

/// \brief Checks the value of the iflags_I flag.
/// \param s Machine state.
/// \returns The flag value.
bool processor_read_iflags_I(const machine_state *s);

/// \brief Resets the value of the iflags_I flag.
/// \param s Machine state.
void processor_reset_iflags_I(machine_state *s);

/// \brief Reads the value of the mip register.
/// \param s Machine state.
/// \returns The value of the register.
uint32_t processor_read_mip(const machine_state *s);

/// \brief Sets bits in mip.
/// \param s Machine state.
/// \param mask Bits set in \p mask will also be set in mip
void processor_set_mip(machine_state *s, uint32_t mask);

/// \brief Resets bits in mip.
/// \param s Machine state.
/// \param mask Bits set in \p mask will also be reset in mip
void processor_reset_mip(machine_state *s, uint32_t mask);

/// \brief Updates the brk flag from changes in mip and mie registers.
/// \param s Machine state.
void processor_set_brk_from_mip_mie(machine_state *s);

/// \brief Checks the value of the iflags_H flag.
/// \param s Machine state.
/// \returns The flag value.
bool processor_read_iflags_H(const machine_state *s);

/// \brief Sets the iflags_H flag.
/// \param s Machine state.
void processor_set_iflags_H(machine_state *s);

/// \brief Updates the brk flag from changes in the iflags_H flag.
/// \param s Machine state.
void processor_set_brk_from_iflags_H(machine_state *s);

/// \brief Obtain a pointer into the host memory
/// corresponding to the target memory at a given address
/// \param s Machine state.
/// \param paddr Physical memory address in target.
/// \returns Pointer to host memory corresponding to \p
/// paddr, or nullptr if there is no such address.
uint8_t *board_get_host_memory(machine_state *s, uint64_t paddr);

/// \brief Register a new flash device.
/// \param s Machine state.
/// \param start Start of physical memory range in the target address
/// space on which to map the flash device.
/// \param length Length of physical memory range in the
/// target address space on which to map the flash device.
/// \param path Pointer to a string containing the filename
/// for the backing file in the host with the contents of the flash device.
/// \param shared Whether target modifications to the flash device are
/// reflected in the host's backing file.
/// \details \p length must match the size of the backing file.
/// \returns true if successful, false otherwise.
bool board_register_flash(machine_state *s, uint64_t start, uint64_t length,
    const char *path, bool shared);

/// \brief Register a new RAM memory range.
/// \param s Machine state.
/// \param start Start of physical memory range in the target address
/// space on which to map the RAM memory.
/// \param length Length of physical memory range in the
/// target address space on which to map the RAM memory.
/// \returns true if successful, false otherwise.
bool board_register_ram(machine_state *s, uint64_t start, uint64_t length);

/// \brief Register a new memory-mapped IO device.
/// \param s Machine state.
/// \param start Start of physical memory range in the target address
/// space on which to map the device.
/// \param length Length of physical memory range in the
/// target address space on which to map the device.
/// \param context Pointer to context to be passed to callbacks.
/// \param read Callback for read operations.
/// \param write Callback for write operations.
/// \param peek Callback for peek operations.
/// \param update_merkle_tree Callback for Merkle tree update operations.
/// \returns true if successful, false otherwise.
bool board_register_mmio(machine_state *s, uint64_t start, uint64_t length, void *context,
    pma_device_read read,
    pma_device_write write,
    pma_device_peek peek = nullptr,
    pma_device_update_merkle_tree update_merkle_tree = nullptr);

/// \brief Register a new shadow device.
/// \param s Machine state.
/// \param start Start of physical memory range in the target address
/// space on which to map the shadow device.
/// \param length Length of physical memory range in the
/// target address space on which to map the shadow device.
/// \param context Pointer to context to be passed to callbacks.
/// \param peek Callback for peek operations.
/// \param update_merkle_tree Callback for Merkle tree update operations.
/// \returns true if successful, false otherwise.
bool board_register_shadow(machine_state *s, uint64_t start, uint64_t length,
    void *context,
    pma_device_peek peek,
    pma_device_update_merkle_tree update_merkle_tree);

#endif
