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
#include <utility>
#include <vector>

#include <unordered_map>

#include "access-log.h"
#include "address-range-description.h"
#include "address-range.h"
#include "hash-tree.h"
#include "host-addr.h"
#include "i-device-state-access.h"
#include "interpret.h"
#include "machine-config.h"
#include "machine-reg.h"
#include "machine-runtime-config.h"
#include "machine-state.h"
#include "os.h"
#include "pmas-constants.h"
#include "shadow-tlb.h"
#include "uarch-interpret.h"
#include "uarch-state.h"
#include "virtio-address-range.h"

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
    mutable machine_state m_s;                                 ///< Big machine state
    mutable uarch_state m_us;                                  ///< Microarchitecture state
    mutable std::vector<std::unique_ptr<address_range>> m_ars; ///< All address ranges
    machine_config m_c;                                        ///< Copy of initialization config
    machine_runtime_config m_r;                                ///< Copy of initialization runtime config
    std::vector<virtio_address_range *> m_virtio_ars;          ///< VirtIO address ranges
    address_range_descriptions m_ards;                    ///< Address range descriptions listed by get_address_ranges()
    std::unordered_map<std::string, uint64_t> m_counters; ///< Counters used for statistics collection
    std::vector<uint64_t> m_hash_tree_ars;                ///< Indices of address ranges that the Mekrle tree can find
    // hash_tree m_ht;                                       ///< Top level hash tree

    ///< Where to register an address range
    struct register_where {
        bool hash_tree; //< Register with hash tree, so it appears in the root hash
        bool interpret; //< Register so interpret can see (and it also appears as a PMA entries in memory)
    };

    /// \brief Checks if address range can be registered.
    /// \param ar Address range object to register.
    /// \param where Where to register the address range.
    void check_address_range(const address_range &ar, register_where where);

    /// \brief Registers a new address range.
    /// \tparam AR An address range or derived type.
    /// \param ar The address range object to register (as an r-value).
    /// \param where Where to register the address range.
    /// \returns Reference to address range object after it is moved inside the machine.
    /// \details The r-value address range is moved to the heap, and the pointer holding it is added to a container.
    /// Once the address range is moved to the heap, its address will remain valid until it is replaced by
    /// a call to replace_memory_range(), or until the machine is destroyed.
    /// This means pointers to address ranges remain valid even after subsequent calls to register_address_range(),
    /// but may be invalidated by calls to replace_address_range().
    /// For a stronger guarantee, when an address range is replaced, the pointer to the new address range
    /// overwrites the pointer to the old address range at the same index in the container.
    /// This means the an index into the container that owns all address ranges will always refers to same address range
    /// after subsequent calls to register_address_range() and  calls to replace_address_range() as well.
    /// \details Besides the container that stores the address ranges, the machine maintains subsets of address ranges.
    /// The "hash_tree" address range container lists the indices of the address ranges taht will be considered by
    /// the hash tree during the computation of the state hash.
    /// The "interpret" address range container lists the indices of the address ranges that will be visible from within
    /// the interpreter.
    /// When registering an address range with the machine, one must specify \p where else to register it.
    /// The "virtio" address range container holds pointers to every virtio address range that has been registered.
    template <typename AR>
    AR &register_address_range(AR &&ar, register_where where)
        requires std::is_rvalue_reference_v<AR &&> && std::derived_from<AR, address_range>
    {
        check_address_range(ar, where);                     // Check if we can register it
        auto ptr = make_moved_unique(std::forward<AR>(ar)); // Move object to heap, now owned by ptr
        AR &ar_ref = *ptr;                                  // Get reference to object, already in heap, to return later
        const auto index = m_ars.size();                    // Get index new address range will occupy
        m_ars.push_back(std::move(ptr));                    // Move ptr to list of address ranges
        if (where.interpret) {                              // Register with interpreter
            m_s.pmas.push_back(index);
        }
        if (where.hash_tree) { // Register with hash tree
            m_hash_tree_ars.push_back(index);
        }
        if constexpr (std::is_convertible_v<AR *, virtio_address_range *>) { // Register with VirtIO
            m_virtio_ars.push_back(&ar_ref);
        }
        return ar_ref; // Return reference to object in heap
    }

    /// \brief Saves address ranges into files for serialization
    /// \param config Machine config to be stored
    /// \param directory Directory where address ranges will be stored
    void store_address_ranges(const machine_config &config, const std::string &directory) const;

    /// \brief Saves an address range into serialization directory
    /// \param ar Address range to store
    /// \param directory Directory where address range will be stored
    void store_address_range(const address_range &ar, const std::string &directory) const;

    /// \brief Returns offset that converts between machine host addresses and target physical addresses
    /// \param pma_index Index of the memory PMA for the desired offset
    host_addr get_hp_offset(uint64_t pma_index) const;

    /// \brief Initializes microarchitecture
    /// \param c Microarchitecture configuration
    void init_uarch(const uarch_config &c);

    /// \brief Initializes registers
    /// \param p Processor configuration
    /// \param r Machine runtime configuration
    void init_processor(processor_config &p, const machine_runtime_config &r);

    /// \brief Initializes RAM address range
    /// \param ram RAM configuration
    void init_ram_ar(const ram_config &ram);

    /// \brief Initializes flash drive PMAs
    /// \param flash_drive Flash drive configurations
    void init_flash_drive_ars(flash_drive_configs &flash_drive);

    /// \brief Initializes VirtIO device PMAs
    /// \param virtio VirtIO configurations
    /// \param iunrep Initial value of iunrep CSR
    void init_virtio_ars(const virtio_configs &virtio, uint64_t iunrep);

    /// \brief Initializes HTIF device address range
    /// \param h HTIF configuration
    void init_htif_ar(const htif_config &h);

    /// \brief Initializes TTY if needed
    /// \param h HTIF configuration
    /// \param r HTIF runtime configuration
    /// \param iunrep Initial value of iunrep CSR
    void init_tty(const htif_config &h, const htif_runtime_config &r, uint64_t iunrep) const;

    /// \brief Initializes CLINT device address range
    /// \param c CLINT configuration
    void init_clint_ar(const clint_config &c);

    /// \brief Initializes PLIC device address range
    /// \param p PLIC configuration
    void init_plic_ar(const plic_config &p);

    /// \brief Initializes CMIO address ranges
    /// \param c CMIO configuration
    void init_cmio_ars(const cmio_config &c);

    /// \brief Initializes the address ranges involced in the hash tree
    /// \brief h Hash tree configuration
    /// \detail This can only be called after all address ranges have been registerd
    void init_hash_tree(const hash_tree_config &h);

    /// \brief Initializes the address range descriptions returned by get_address_ranges()
    /// \detail This can only be called after all address ranges have been registered
    void init_ars_descriptions();

    /// \brief Initializes contents of the shadow PMAs memory
    /// \param pmas PMA entry for the shadow PMAs
    /// \detail This can only be called after all PMAs have been added
    void init_pmas_contents(const pmas_config &config, memory_address_range &pmas) const;

    /// \brief Initializes contents of machine TLB, from image in disk or with default values
    /// \param config TLB config
    /// \detail This can only be called after all PMAs have been added
    void init_tlb_contents(const tlb_config &config);

    /// \brief Initializes contents of machine DTB, if image was not available
    /// \param config Machine configuration
    /// \param dtb PMA entry for the shadow PMAs
    static void init_dtb_contents(const machine_config &config, memory_address_range &dtb);

    /// \brief Dumps statistics
    void dump_stats();

    /// \brief Dumps instruction histogram
    void dump_insn_hist();

    /// \brief Returns key to counter
    /// \param name Counter name.
    /// \param domain Counter domain. Can be nullptr. Otherwise, should end with a dot '.'
    /// \details The counter is key is the concatenation of \p domain with \p name.
    static std::string get_counter_key(const char *name, const char *domain = nullptr);

public:
    /// \brief Type of hash and proof
    using proof_type = hash_tree::proof_type;

    using reg = machine_reg;

    /// \brief Constructor from machine configuration
    /// \param config Machine config to use instantiating machine
    /// \param runtime Runtime config to use with machine
    explicit machine(machine_config config, machine_runtime_config runtime = {});

    /// \brief Constructor from previously serialized directory
    /// \param directory Directory to load stored machine from
    /// \param runtime Runtime config to use with machine
    explicit machine(const std::string &directory, machine_runtime_config runtime = {});

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
    ///  frequent scenario is when the program executes a WFI instruction. Another example is when the machine
    ///  halts.
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
    static interpreter_break_reason verify_step(const machine_hash &root_hash_before, const std::string &log_filename,
        uint64_t mcycle_count, const machine_hash &root_hash_after);

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
    static void verify_step_uarch(const machine_hash &root_hash_before, const access_log &log,
        const machine_hash &root_hash_after);

    /// \brief Checks the validity of a state transition caused by log_reset_uarch.
    /// \param root_hash_before State hash before uarch reset
    /// \param log Step state access log.
    /// \param root_hash_after State hash after uarch reset.
    static void verify_reset_uarch(const machine_hash &root_hash_before, const access_log &log,
        const machine_hash &root_hash_after);

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

    /// \brief Returns uarch state for direct access.
    uarch_state &get_uarch_state() {
        return m_us;
    }

    /// \brief Returns uarch state for direct read-only access.
    const uarch_state &get_uarch_state() const {
        return m_us;
    }

    /// \brief Returns a list of descriptions for all PMA entries registered in the machine, sorted by start
    address_range_descriptions get_address_ranges() const {
        return m_ards;
    }

    /// \brief Wait for external interrupts requests.
    /// \param mcycle Current value of mcycle.
    /// \param mcycle_max Maximum mcycle after wait.
    /// \returns A pair {new_mcycle, status}, where new_mcycle gives new value for mcycle after wait,
    /// and status will be execute_status::success_and_serve_interrupts if wait was stopped by an
    /// external interrupt request.
    /// \details When mcycle_max is greater than mcycle, this function will sleep until an external interrupt
    /// is triggered or until the amount of time estimated for mcycle to reach mcycle_max has elapsed.
    std::pair<uint64_t, execute_status> poll_external_interrupts(uint64_t mcycle, uint64_t mcycle_max);

    /// \brief Destructor.
    ~machine();

    /// \brief Fill file descriptors to be polled by select() for all VirtIO devices.
    /// \param fds Pointer to sets of read, write and except file descriptors to be updated.
    /// \param timeout_us Maximum amount of time to wait in microseconds, this may be updated (always to lower
    /// values).
    void prepare_virtio_devices_select(select_fd_sets *fds, uint64_t *timeout_us);

    /// \brief Poll file descriptors that were marked as ready by select() for all VirtIO devices.
    /// \param select_ret Return value from the most recent select() call.
    /// \param fds Pointer to sets of read, write and except file descriptors to be checked.
    /// \returns True if an interrupt was requested, false otherwise.
    /// \details This function process pending events and trigger interrupt requests (if any).
    bool poll_selected_virtio_devices(int select_ret, select_fd_sets *fds, i_device_state_access *da);

    /// \brief Poll file descriptors through select() for all VirtIO devices.
    /// \details Basically call prepare_virtio_devices_select(), select() and poll_selected_virtio_devices().
    /// \param timeout_us Maximum amount of time to wait in microseconds, this may be updated (always to lower
    /// values).
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
    proof_type get_proof(uint64_t address, int log2_size) const;

    /// \brief Obtains the proof for a node in the Merkle tree without making any modifications to the tree.
    /// \param address Address of target node. Must be aligned to a 2<sup>log2_size</sup> boundary.
    /// \param log2_size log<sub>2</sub> of size subintended by target node.
    /// Must be between 3 (for a word) and 64 (for the entire address space), inclusive.
    /// \param proof Receives the proof.
    /// \details If the node is smaller than a page size, then it must lie entirely inside the same PMA range.
    /// This overload is used to optimize proof generation when the caller knows that the tree is already up to
    /// date.
    proof_type get_proof(uint64_t address, int log2_size, skip_merkle_tree_update_t /*unused*/) const;

    /// \brief Obtains the root hash of the Merkle tree.
    /// \param hash Receives the hash.
    void get_root_hash(machine_hash &hash) const;

    /// \brief Obtains the hash of a node in the Merkle tree.
    /// \param address Address of target node. Must be aligned to a 2<sup>log2_size</sup> boundary.
    /// \param log2_size log<sub>2</sub> of size subintended by target node.
    /// \returns The hash of the target node.
    machine_hash get_merkle_tree_node_hash(uint64_t address, int log2_size) const;

    /// \brief Obtains the hash of a node in the Merkle tree without making any modifications to the tree.
    /// \param address Address of target node. Must be aligned to a 2<sup>log2_size</sup> boundary.
    /// \param log2_size log<sub>2</sub> of size subintended by target node.
    /// \returns The hash of the target node.
    machine_hash get_merkle_tree_node_hash(uint64_t address, int log2_size, skip_merkle_tree_update_t /*unused*/) const;

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

    /// \brief Read the value of a word from the machine state.
    /// \param paddr Word address (aligned to 64-bit boundary).
    /// \returns The value of word at address.
    /// \details The word can be anywhere in the entire address space.
    uint64_t read_word(uint64_t paddr) const;

    /// \brief Writes the value of a word to the machine state.
    /// \param paddr Word address (aligned to 64-bit boundary).
    /// \details The word can be in a writeable area of the address space.
    /// This includes the shadow state and the shadow uarch state.
    /// (But does NOT include memory-mapped devices, the shadow tlb, shadow PMAs, or unnocupied memory regions.)
    void write_word(uint64_t paddr, uint64_t val);

    /// \brief Reads a chunk of data, by its target physical address and length.
    /// \param paddr Target physical address to start reading from.
    /// \param data Buffer that receives data to read. Must be at least \p length bytes long.
    /// \param length Number of bytes to read from \p paddr to \p data.
    /// \details The data can be anywhere in the entire address space.
    void read_memory(uint64_t paddr, unsigned char *data, uint64_t length) const;

    /// \brief Writes a chunk of data to machine memory, by its target physical address and length.
    /// \param paddr Target physical address to start writing to.
    /// \param data Buffer that contains data to write. Must be at least \p length bytes long.
    /// \param length Number of bytes to write from \p data to \p paddr.
    /// \details Unlike read_memory(), the entire chunk of data, from \p paddr to \p paddr + \p length,
    /// must reside entirely in the same address range. Moreover, it cannot be mapped to a device.
    void write_memory(uint64_t paddr, const unsigned char *data, uint64_t length);

    /// \brief Fills a memory range with a single byte.
    /// \param paddr Target physical address to start filling.
    /// \param val Byte to fill memory with.
    /// \param length Number of bytes to write starting at \p paddr.
    /// \details Unlike read_memory(), the entire chunk of data, from \p paddr to \p paddr + \p length,
    /// must reside entirely in the same address range. Moreover, it cannot be mapped to a device.
    void fill_memory(uint64_t paddr, uint8_t val, uint64_t length);

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

    /// \brief Returns the address range associated to the PMA at a given index
    /// \param index Index of desired address range
    /// \returns Desired address range, or an empty sentinel if index is out of bounds
    const address_range &read_pma(uint64_t index) const noexcept {
        if (index >= m_s.pmas.size()) {
            static constexpr auto sentinel = make_empty_address_range("sentinel");
            return sentinel;
        }
        // NOLINTNEXTLINE(bugprone-narrowing-conversions)
        return *m_ars[static_cast<int>(m_s.pmas[static_cast<int>(index)])];
    }

    /// \brief Returns the address range associated to the PMA at a given index
    /// \param index Index of desired address range
    /// \returns Desired address range, or an empty sentinel if index is out of bounds
    address_range &read_pma(uint64_t index) noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        return const_cast<address_range &>(std::as_const(*this).read_pma(index));
    }

    /// \brief Returns one of the address ranges considered by the Merkle tree
    /// \param index Index of desired address range
    /// \returns Desired address range, or an empty sentinel if index is out of bounds
    const address_range &read_hash_tree_address_range(uint64_t index) const noexcept {
        if (index >= m_hash_tree_ars.size()) {
            static constexpr auto sentinel = make_empty_address_range("sentinel");
            return sentinel;
        }
        // NOLINTNEXTLINE(bugprone-narrowing-conversions)
        return *m_ars[static_cast<int>(m_hash_tree_ars[static_cast<int>(index)])];
    }

    /// \brief Returns one of the address ranges considered by the Merkle tree
    /// \param index Index of desired address range
    /// \returns Desired address range, or an empty sentinel if index is out of bounds
    address_range &read_hash_tree_address_range(uint64_t index) noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        return const_cast<address_range &>(std::as_const(*this).read_hash_tree_address_range(index));
    }

    /// \brief Obtain address range from the machine state that covers a given physical memory region
    /// \param paddr Target physical address of start of region.
    /// \param length Length of region, in bytes.
    /// \returns Corresponding address range if found, or an empty sentinel otherwise.
    /// \warning Microarchitecture address ranges are not considered in the search.
    const address_range &find_address_range(uint64_t paddr, uint64_t length) const noexcept;

    address_range &find_address_range(uint64_t paddr, uint64_t length) noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        return const_cast<address_range &>(std::as_const(*this).find_address_range(paddr, length));
    }

    /// \brief Obtain address range from the machine state that covers a given word in physical memory
    /// \tparam T Type of word.
    /// \param paddr Target physical address of word.
    /// \returns Corresponding address range if found, or an empty sentinel otherwise.
    /// \warning Microarchitecture address ranges are not considered in the search.
    template <typename T>
    const address_range &find_address_range(uint64_t paddr) const {
        return find_address_range(paddr, sizeof(T));
    }

    template <typename T>
    address_range &find_address_range(uint64_t paddr) {
        return find_address_range(paddr, sizeof(T));
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
    void set_runtime_config(machine_runtime_config r);

    /// \brief Replaces a memory range.
    /// \param config Configuration of the new memory range.
    /// \details The machine must contain an existing memory range matching the start and length specified in range.
    void replace_memory_range(const memory_range_config &config);

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

    /// \brief Marks a page as dirty
    /// \param paddr Target phyislcal address within page
    /// \param pma_index Index of PMA where address falls
    void mark_dirty_page(uint64_t paddr, uint64_t pma_index);

    /// \brief Updates a TLB slot
    /// \param set_index TLB_CODE, TLB_READ, or TLB_WRITE
    /// \param slot_index Index of slot to update
    /// \param vaddr_page Virtual address of page to map
    /// \param vh_offset Offset from target virtual addresses to host addresses within page
    /// \param pma_index Index of PMA where address falls
    void write_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, host_addr vh_offset,
        uint64_t pma_index);

    /// \brief Updates a TLB slot
    /// \param set_index TLB_CODE, TLB_READ, or TLB_WRITE
    /// \param slot_index Index of slot to update
    /// \param vaddr_page Virtual address of page to map
    /// \param vp_offset Offset from target virtual addresses to target physical addresses within page
    /// \param pma_index Index of PMA where address falls
    void write_shadow_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
        uint64_t pma_index);

    /// \brief Check consistency of TLB slot
    /// \param set_index TLB_CODE, TLB_READ, or TLB_WRITE
    /// \param slot_index Index of slot to update
    /// \param vaddr_page Virtual address of page to map
    /// \param vp_offset Offset from target virtual addresses to target physical addresses within page
    /// \param pma_index Index of PMA where address falls
    void check_shadow_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
        uint64_t pma_index, const std::string &prefix = "") const;

    /// \brief Reads a TLB register
    /// \param set_index TLB_CODE, TLB_READ, or TLB_WRITE
    /// \param slot_index Index of slot to read
    /// \param reg Register to read from slot
    /// \returns Value of register
    uint64_t read_shadow_tlb(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what reg) const;

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
        const machine_hash &root_hash_before, const access_log &log, const machine_hash &root_hash_after);

    /// \brief Returns a description of what is at a given target physical address
    /// \param paddr Target physical address of interest
    /// \returns Description of what is at that address
    static const char *get_what_name(uint64_t paddr);

    /// \brief Increments a counter
    /// \param name Counter name.
    /// \param domain Counter domain. Can be nullptr. Otherwise, should end with a dot '.'
    /// \details The counter is identified by the concatenation of \p domain with \p name.
    void increment_counter(const char *name, const char *domain = nullptr);

    /// \brief Writes value to counter
    /// \param val Value to write.
    /// \param name Counter name.
    /// \param domain Counter domain. Can be nullptr. Otherwise, should end with a dot '.'
    /// \details The counter is identified by the concatenation of \p domain with \p name.
    void write_counter(uint64_t val, const char *name, const char *domain = nullptr);

    /// \brief Returns value in counter
    /// \param name Counter name.
    /// \param domain Counter domain. Can be nullptr. Otherwise, should end with a dot '.'
    /// \details The counter is identified by the concatenation of \p domain with \p name.
    uint64_t read_counter(const char *name, const char *domain = nullptr);

    /// \brief Returns all counters
    const auto &get_counters() {
        return m_counters;
    }
};

} // namespace cartesi

#endif
