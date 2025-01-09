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

#ifndef MACHINE_H
#define MACHINE_H

/// \file
/// \brief Cartesi machine interface

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <boost/container/static_vector.hpp>

#include "access-log.h"
#include "host-addr.h"
#include "i-device-state-access.h"
#include "interpret.h"
#include "machine-config.h"
#include "machine-memory-range-descr.h"
#include "machine-merkle-tree.h"
#include "machine-reg.h"
#include "machine-runtime-config.h"
#include "machine-state.h"
#include "os.h"
#include "pma-constants.h"
#include "pma.h"
#include "uarch-interpret.h"
#include "uarch-machine.h"
#include "virtio-device.h"

namespace cartesi {

/// \brief Tag type used to indicate that merkle tree updates should be skipped.
struct skip_merkle_tree_update_t {
    explicit skip_merkle_tree_update_t() = default;
};

/// \brief Tag indicating that merkle tree updates should be skipped.
constexpr skip_merkle_tree_update_t skip_merkle_tree_update;

/// \class machine
/// \brief Cartesi Machine implementation
class machine final {
private:
    //??D Ideally, we would hold a unique_ptr to the state. This
    //    would allow us to remove the machine-state.h include and
    //    therefore hide its contents from anyone who includes only
    //    machine.h. Maybe the compiler can do a good job we we are
    //    not constantly going through the extra indirection. We
    //    should test this.

    mutable machine_state m_s;              ///< Opaque machine state
    mutable machine_merkle_tree m_t;        ///< Merkle tree of state
    std::vector<pma_entry *> m_merkle_pmas; ///< PMAs considered by the Merkle tree: from big machine and uarch
    machine_config m_c;                     ///< Copy of initialization config
    uarch_machine m_uarch;                  ///< Microarchitecture machine
    machine_runtime_config m_r;             ///< Copy of initialization runtime config
    machine_memory_range_descrs m_mrds;     ///< List of memory ranges returned by get_memory_ranges().

    boost::container::static_vector<std::unique_ptr<virtio_device>, VIRTIO_MAX> m_vdevs; ///< Array of VirtIO devices

    static const pma_entry::flags m_dtb_flags;            ///< PMA flags used for DTB
    static const pma_entry::flags m_ram_flags;            ///< PMA flags used for RAM
    static const pma_entry::flags m_flash_drive_flags;    ///< PMA flags used for flash drives
    static const pma_entry::flags m_cmio_rx_buffer_flags; ///< PMA flags used for cmio rx buffer
    static const pma_entry::flags m_cmio_tx_buffer_flags; ///< PMA flags used for cmio tx buffer

    /// \brief Allocates a new PMA entry.
    /// \param pma PMA entry to add to machine.
    /// \returns Reference to corresponding entry in machine state.
    pma_entry &register_pma_entry(pma_entry &&pma);

    /// \brief Creates a new PMA entry reflecting a memory range configuration.
    /// \param description Informative description of PMA entry for use in error messages
    /// \param c Memory range configuration.
    /// \returns New PMA entry (with default flags).
    static pma_entry make_memory_range_pma_entry(const std::string &description, const memory_range_config &c);

    /// \brief Creates a new flash drive PMA entry.
    /// \param description Informative description of PMA entry for use in error messages
    /// \param c Memory range configuration.
    /// \returns New PMA entry with flash drive flags already set.
    static pma_entry make_flash_drive_pma_entry(const std::string &description, const memory_range_config &c);

    /// \brief Creates a new cmio rx buffer PMA entry.
    // \param c Optional cmio configuration
    /// \returns New PMA entry with rx buffer flags already set.
    static pma_entry make_cmio_rx_buffer_pma_entry(const cmio_config &cmio_config);

    /// \brief Creates a new cmio tx buffer PMA entry.
    // \param c Optional cmio configuration
    /// \returns New PMA entry with tx buffer flags already set.
    static pma_entry make_cmio_tx_buffer_pma_entry(const cmio_config &cmio_config);

    /// \brief Saves PMAs into files for serialization
    /// \param config Machine config to be stored
    /// \param directory Directory where PMAs will be stored
    void store_pmas(const machine_config &config, const std::string &directory) const;

    /// \brief Obtain PMA entry that covers a given physical memory region
    /// \param pmas Container of pmas to be searched.
    /// \param s Pointer to machine state.
    /// \param paddr Start of physical memory region.
    /// \param length Length of physical memory region.
    /// \returns Corresponding entry if found, or a sentinel entry
    /// for an empty range.
    template <typename CONTAINER>
    pma_entry &find_pma_entry(const CONTAINER &pmas, uint64_t paddr, uint64_t length);

    template <typename CONTAINER>
    const pma_entry &find_pma_entry(const CONTAINER &pmas, uint64_t paddr, uint64_t length) const;

    /// \brief Returns offset that converts between machine host addresses and target physical addresses
    /// \param pma_index Index of the memory PMA for the desired offset
    host_addr get_hp_offset(uint64_t pma_index) const;

    /// \brief Initializes machine TLB from scratch
    void init_tlb();

    /// \brief Initializes machine TLB from shadow tlb
    /// \param shadow_tlb Shadow TLB loaded from disk
    void init_tlb(const shadow_tlb_state &shadow_tlb);

public:
    /// \brief Type of hash
    using hash_type = machine_merkle_tree::hash_type;

    using reg = machine_reg;

    /// \brief Constructor from machine configuration
    /// \param config Machine config to use instantiating machine
    /// \param runtime Runtime config to use with machine
    explicit machine(const machine_config &config, const machine_runtime_config &runtime = {});

    /// \brief Constructor from previously serialized directory
    /// \param directory Directory to load stored machine from
    /// \param runtime Runtime config to use with machine
    explicit machine(const std::string &directory, const machine_runtime_config &runtime = {});

    /// \brief Serialize entire state to directory
    /// \param directory Directory to store machine into
    void store(const std::string &directory) const;

    /// \brief No default constructor
    machine() = delete;
    /// \brief No copy constructor
    machine(const machine &other) = delete;
    /// \brief No move constructor
    machine(machine &&other) = delete;
    /// \brief No copy assignment
    machine &operator=(const machine &other) = delete;
    /// \brief No move assignment
    machine &operator=(machine &&other) = delete;

    /// \brief Runs the machine until mcycle reaches mcycle_end, the machine halts or yields.
    /// \param mcycle_end Maximum value of mcycle before function returns.
    /// \returns The reason the machine was interrupted.
    /// \details Several conditions can cause the function to break before mcycle reaches mcycle_end. The most
    ///  frequent scenario is when the program executes a WFI instruction. Another example is when the machine halts.
    interpreter_break_reason run(uint64_t mcycle_end);

    /// \brief Runs the machine for the given mcycle count and generates a log of accessed pages and proof data.
    /// \param mcycle_count Number of mcycles to run the machine for.
    /// \param filename Name of the file to store the log.
    /// \returns The reason the machine was interrupted.
    interpreter_break_reason log_step(uint64_t mcycle_count, const std::string &filename);

    /// \brief Checks the validity of a step log file.
    /// \param root_hash_before Hash of the state before the step.
    /// \param log_filename Name of the file containing the log.
    /// \param mcycle_count Number of mcycles the machine was run for.
    /// \param root_hash_after Hash of the state after the step.
    static interpreter_break_reason verify_step(const hash_type &root_hash_before, const std::string &log_filename,
        uint64_t mcycle_count, const hash_type &root_hash_after);

    /// \brief Runs the machine in the microarchitecture until the mcycles advances by one unit or the micro cycle
    /// counter (uarch_cycle) reaches uarch_cycle_end
    /// \param uarch_cycle_end uarch_cycle limit
    uarch_interpreter_break_reason run_uarch(uint64_t uarch_cycle_end);

    /// \brief Advances one micro step and returns a state access log.
    /// \param log_type Type of access log to generate.
    /// \returns The state access log.
    access_log log_step_uarch(const access_log::type &log_type);

    /// \brief Resets the entire uarch state to pristine values.
    void reset_uarch();

    /// \brief Resets the microarchitecture state and returns an access log
    /// \param log_type Type of access log to generate.
    /// \param log_data If true, access data is recorded in the log, otherwise only hashes. The default is false.
    /// \returns The state access log.
    access_log log_reset_uarch(const access_log::type &log_type);

    /// \brief Checks the validity of a state transition caused by log_step_uarch.
    /// \param root_hash_before State hash before step.
    /// \param log Step state access log.
    /// \param root_hash_after State hash after step.
    static void verify_step_uarch(const hash_type &root_hash_before, const access_log &log,
        const hash_type &root_hash_after);

    /// \brief Checks the validity of a state transition caused by log_reset_uarch.
    /// \param root_hash_before State hash before uarch reset
    /// \param log Step state access log.
    /// \param root_hash_after State hash after uarch reset.
    static void verify_reset_uarch(const hash_type &root_hash_before, const access_log &log,
        const hash_type &root_hash_after);

    /// \brief Returns copy of default machine config
    static machine_config get_default_config();

    /// \brief Returns machine state for direct access.
    machine_state &get_state() {
        return m_s;
    }

    /// \brief Returns machine state for direct read-only access.
    const machine_state &get_state() const {
        return m_s;
    }

    /// \brief Returns a list of descriptions for all PMA entries registered in the machine, sorted by start
    machine_memory_range_descrs get_memory_ranges() const {
        return m_mrds;
    }

    /// \brief Destructor.
    ~machine();

    /// \brief Fill file descriptors to be polled by select() for all VirtIO devices.
    /// \param fds Pointer to sets of read, write and except file descriptors to be updated.
    /// \param timeout_us Maximum amount of time to wait in microseconds, this may be updated (always to lower values).
    void prepare_virtio_devices_select(select_fd_sets *fds, uint64_t *timeout_us);

    /// \brief Poll file descriptors that were marked as ready by select() for all VirtIO devices.
    /// \param select_ret Return value from the most recent select() call.
    /// \param fds Pointer to sets of read, write and except file descriptors to be checked.
    /// \returns True if an interrupt was requested, false otherwise.
    /// \details This function process pending events and trigger interrupt requests (if any).
    bool poll_selected_virtio_devices(int select_ret, select_fd_sets *fds, i_device_state_access *da);

    /// \brief Poll file descriptors through select() for all VirtIO devices.
    /// \details Basically call prepare_virtio_devices_select(), select() and poll_selected_virtio_devices().
    /// \param timeout_us Maximum amount of time to wait in microseconds, this may be updated (always to lower values).
    /// \returns True if an interrupt was requested, false otherwise.
    bool poll_virtio_devices(uint64_t *timeout_us, i_device_state_access *da);

    /// \brief Checks if the machine has VirtIO devices.
    /// \returns True if at least one VirtIO device is present.
    bool has_virtio_devices() const;

    /// \brief Checks if the machine has VirtIO console device.
    /// \returns True if at least one VirtIO console is present.
    bool has_virtio_console() const;

    /// \brief Checks if the machine has HTIF console device.
    /// \returns True if HTIF console is present.
    bool has_htif_console() const;

    /// \brief Update the Merkle tree so it matches the contents of the machine state.
    /// \returns true if succeeded, false otherwise.
    bool update_merkle_tree() const;

    /// \brief Update the Merkle tree after a page has been modified in the machine state.
    /// \param address Any address inside modified page.
    /// \returns true if succeeded, false otherwise.
    bool update_merkle_tree_page(uint64_t address);

    /// \brief Obtains the proof for a node in the Merkle tree.
    /// \param address Address of target node. Must be aligned to a 2<sup>log2_size</sup> boundary.
    /// \param log2_size log<sub>2</sub> of size subintended by target node.
    /// Must be between 3 (for a word) and 64 (for the entire address space), inclusive.
    /// \param proof Receives the proof.
    /// \details If the node is
    /// smaller than a page size, then it must lie entirely inside the same PMA range.
    machine_merkle_tree::proof_type get_proof(uint64_t address, int log2_size) const;

    /// \brief Obtains the proof for a node in the Merkle tree without making any modifications to the tree.
    /// \param address Address of target node. Must be aligned to a 2<sup>log2_size</sup> boundary.
    /// \param log2_size log<sub>2</sub> of size subintended by target node.
    /// Must be between 3 (for a word) and 64 (for the entire address space), inclusive.
    /// \param proof Receives the proof.
    /// \details If the node is smaller than a page size, then it must lie entirely inside the same PMA range.
    /// This overload is used to optimize proof generation when the caller knows that the tree is already up to date.
    machine_merkle_tree::proof_type get_proof(uint64_t address, int log2_size,
        skip_merkle_tree_update_t /*unused*/) const;

    /// \brief Obtains the root hash of the Merkle tree.
    /// \param hash Receives the hash.
    void get_root_hash(hash_type &hash) const;

    /// \brief Obtains the hash of a node in the Merkle tree.
    /// \param address Address of target node. Must be aligned to a 2<sup>log2_size</sup> boundary.
    /// \param log2_size log<sub>2</sub> of size subintended by target node.
    /// \returns The hash of the target node.
    hash_type get_merkle_tree_node_hash(uint64_t address, int log2_size) const;

    /// \brief Obtains the hash of a node in the Merkle tree without making any modifications to the tree.
    /// \param address Address of target node. Must be aligned to a 2<sup>log2_size</sup> boundary.
    /// \param log2_size log<sub>2</sub> of size subintended by target node.
    /// \returns The hash of the target node.
    hash_type get_merkle_tree_node_hash(uint64_t address, int log2_size, skip_merkle_tree_update_t /*unused*/) const;

    /// \brief Verifies integrity of Merkle tree.
    /// \returns True if tree is self-consistent, false otherwise.
    bool verify_merkle_tree() const;

    /// \brief Read the value of any register
    /// \param r Register to read
    /// \returns The value of the register
    uint64_t read_reg(reg r) const;

    /// \brief Write the value of any register
    /// \param w Register to write
    /// \param value Value to write
    void write_reg(reg w, uint64_t value);

    /// \brief Gets the address of any register
    /// \param reg The register to obtain address
    /// \returns The address of the register
    static uint64_t get_reg_address(reg r);

    /// \brief Read the value of a word in the machine state.
    /// \param address Word address (aligned to 64-bit boundary).
    /// \returns The value of word at address.
    /// \warning The current implementation of this function is very slow!
    uint64_t read_word(uint64_t address) const;

    /// \brief Reads a chunk of data from the machine memory.
    /// \param address Physical address to start reading.
    /// \param data Receives chunk of memory.
    /// \param length Size of chunk.
    /// \details The entire chunk, from \p address to \p address + \p length must
    /// be inside the same PMA region.
    void read_memory(uint64_t address, unsigned char *data, uint64_t length) const;

    /// \brief Writes a chunk of data to the machine memory.
    /// \param address Physical address to start writing.
    /// \param data Source for chunk of data.
    /// \param length Size of chunk.
    /// \details The entire chunk, from \p address to \p address + \p length must
    /// be inside the same PMA region. Moreover, this PMA must be a memory PMA,
    /// and not a device PMA.
    void write_memory(uint64_t address, const unsigned char *data, uint64_t length);

    /// \brief Fills a memory range with a single byte.
    /// \param address Physical address to start filling.
    /// \param data Byte to fill memory with.
    /// \param length Size of memory range to fill.
    void fill_memory(uint64_t address, uint8_t data, uint64_t length);

    /// \brief Reads a chunk of data from the machine virtual memory.
    /// \param vaddr_start Virtual address to start reading.
    /// \param data Receives chunk of memory.
    /// \param length Size of chunk.
    void read_virtual_memory(uint64_t vaddr_start, unsigned char *data, uint64_t length);

    /// \brief Writes a chunk of data to the machine virtual memory.
    /// \param vaddr_start Virtual address to start writing.
    /// \param data Source for chunk of data.
    /// \param length Size of chunk.
    void write_virtual_memory(uint64_t vaddr_start, const unsigned char *data, uint64_t length);

    /// \brief Translates a virtual memory address to its corresponding physical memory address.
    /// \param vaddr Virtual address to translate.
    /// \returns The corresponding physical address.
    uint64_t translate_virtual_address(uint64_t vaddr);

    /// \brief Get read-only access to container with all PMA entries.
    /// \returns The container.
    const boost::container::static_vector<pma_entry, PMA_MAX> &get_pmas() const;

    /// \brief Obtain PMA entry from the machine state that covers a given physical memory region
    /// \brief Microarchitecture PMAs are not considered.
    /// \param s Pointer to machine state.
    /// \param paddr Start of physical memory region.
    /// \param length Length of physical memory region.
    /// \returns Corresponding entry if found, or a sentinel entry
    /// for an empty range.
    pma_entry &find_pma_entry(uint64_t paddr, uint64_t length);

    const pma_entry &find_pma_entry(uint64_t paddr, uint64_t length) const;

    /// \brief Obtain PMA entry covering a physical memory word
    /// \tparam T Type of word.
    /// \param s Pointer to machine state.
    /// \param paddr Target physical address.
    /// \returns Corresponding entry if found, or a sentinel entry
    /// for an empty range.
    template <typename T>
    const pma_entry &find_pma_entry(uint64_t paddr) const {
        return find_pma_entry(paddr, sizeof(T));
    }

    /// \brief Go over the write TLB and mark as dirty all pages currently there.
    void mark_write_tlb_dirty_pages() const;

    /// \brief Verify if dirty page maps are consistent.
    /// \returns true if they are, false if there is an error.
    bool verify_dirty_page_maps() const;

    /// \brief Copies the current state into a configuration for serialization
    /// \returns The configuration
    machine_config get_serialization_config() const;

    /// \brief Returns copy of initialization config.
    const machine_config &get_initial_config() const;

    /// \brief Returns the machine runtime config.
    const machine_runtime_config &get_runtime_config() const;

    /// \brief Changes the machine runtime config.
    /// \param range Configuration of the new memory range.
    /// \details Some runtime options cannot be changed.
    void set_runtime_config(const machine_runtime_config &r);

    /// \brief Replaces a memory range.
    /// \param range Configuration of the new memory range.
    /// \details The machine must contain an existing memory range
    /// matching the start and length specified in range.
    void replace_memory_range(const memory_range_config &range);

    /// \brief Sends cmio response
    /// \param reason Reason for sending response.
    /// \param data Response data.
    /// \param length Length of response data.
    void send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length);

    /// \brief Converts from machine host address to target physical address
    /// \param haddr Machine host address to convert
    /// \param pma_index Index of PMA where address falls
    /// \returns Corresponding target physical address
    /// \details This method also converts from vh_offset to vp_offset
    uint64_t get_paddr(host_addr haddr, uint64_t pma_index) const;

    /// \brief Converts from target physical address to machine host address
    /// \param paddr Target physical address to convert
    /// \param pma_index Index of PMA where address falls
    /// \returns Corresponding machine host address
    /// \details This method also converts from vp_offset to vh_offset
    host_addr get_host_addr(uint64_t paddr, uint64_t pma_index) const;

    /// \brief Marks a page as dirty
    /// \param haddr Machine host address within page
    /// \param pma_index Index of PMA where address falls
    void mark_dirty_page(host_addr haddr, uint64_t pma_index);

    /// \brief Sends cmio response and returns an access log
    /// \param reason Reason for sending response.
    /// \param data Response data.
    /// \param length Length of response data.
    /// \param log_type Type of access log to generate.
    /// \return The state access log.
    access_log log_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
        const access_log::type &log_type);

    /// \brief Checks the validity of state transitions caused by log_send_cmio_response.
    /// \param reason Reason for sending response.
    /// \param data The response sent when the log was generated.
    /// \param length Length of response
    /// \param root_hash_before State hash before response was sent.
    /// \param log Log containing the state accesses performed by the load operation
    /// \param root_hash_after State hash after response was sent.
    static void verify_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
        const hash_type &root_hash_before, const access_log &log, const hash_type &root_hash_after);
};

} // namespace cartesi

#endif
