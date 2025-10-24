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

#include <algorithm>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

#include "access-log.h"
#include "address-range.h"
#include "back-merkle-tree.h"
#include "hash-tree-stats.h"
#include "hash-tree.h"
#include "host-addr.h"
#include "i-device-state-access.h"
#include "interpret.h"
#include "machine-address-ranges.h"
#include "machine-config.h"
#include "machine-console.h"
#include "machine-hash.h"
#include "machine-reg.h"
#include "machine-runtime-config.h"
#include "mcycle-root-hashes.h"
#include "os.h"
#include "processor-state.h"
#include "scope-remove.h"
#include "shadow-tlb.h"
#include "uarch-cycle-root-hashes.h"
#include "uarch-interpret.h"
#include "uarch-processor-state.h"
#include "variant-hasher.h"

namespace cartesi {

/// \brief Tag type used to indicate that hash-tree updates should be skipped.
struct skip_hash_tree_update_t {
    explicit skip_hash_tree_update_t() = default;
};

/// \brief Tag indicating that hash-tree updates should be skipped.
constexpr skip_hash_tree_update_t skip_hash_tree_update;

/// \class machine
/// \brief Cartesi Machine implementation
class machine final {
private:
    const machine_config m_c;             ///< Copy of initialization config
    machine_runtime_config m_r;           ///< Copy of initialization runtime config
    machine_console m_console;            ///< Console instance
    mutable machine_address_ranges m_ars; ///< Address ranges
    mutable hash_tree m_ht;               ///< Top level hash tree
    processor_state *m_s;                 ///< Big machine processor state
    uarch_processor_state *m_us;          ///< Microarchitecture processor state

    std::unordered_map<std::string, uint64_t> m_counters; ///< Counters used for statistics collection

    /// \brief Returns offset that converts between machine host addresses and target physical addresses
    /// \param pma_index Index of the memory PMA for the desired offset
    host_addr get_hp_offset(uint64_t pma_index) const {
        const auto &ar = m_ars.read_pma(pma_index);
        if (!ar.is_memory()) [[unlikely]] {
            throw std::domain_error{"attempt to get host to physical offset of PMA that is not a memory range"};
        }
        auto haddr = cast_ptr_to_host_addr(ar.get_host_memory());
        auto paddr = ar.get_start();
        return paddr - haddr;
    }

    /// \brief Initializes processor
    /// \param p Processor configuration
    /// \param r Machine runtime configuration
    void init_processor(const processor_config &p, const machine_runtime_config &r);

    /// \brief Initializes microarchitecture processor
    /// \param c Microarchitecture processor configuration
    void init_uarch_processor(const uarch_processor_config &p);

    /// \brief Initializes console if needed
    void init_console();

    /// \brief Initializes contents of the shadow PMAs memory
    /// \param pmas_config PMAs configuration
    /// \detail This can only be called after all PMAs have been added
    void init_pmas_contents(const pmas_config &config);

    /// \brief Initialize hot TLB contents
    /// \detail This can only be called after all PMAs have been added
    void init_hot_tlb_contents();

    /// \brief Initializes contents of machine DTB, if image was not available
    /// \param config Machine configuration
    void init_dtb_contents(const machine_config &config);

    /// \brief Dumps statistics
    void dump_stats();

    /// \brief Dumps instruction histogram
    void dump_insn_hist();

    /// \brief Returns key to counter
    /// \param name Counter name.
    /// \param domain Counter domain. Can be nullptr. Otherwise, should end with a dot '.'
    /// \details The counter is key is the concatenation of \p domain with \p name.
    static std::string get_counter_key(const char *name, const char *domain = nullptr);

    /// \brief Checks if the machine has VirtIO devices.
    /// \returns True if at least one VirtIO device is present.
    bool has_virtio_devices() const;

    /// \brief Checks if the machine has VirtIO console device.
    /// \returns True if at least one VirtIO console is present.
    bool has_virtio_console() const;

    /// \brief Checks if the machine has HTIF console device.
    /// \returns True if HTIF console is present.
    bool has_htif_console() const;

public:
    /// \brief Shorthand for the proof type
    using proof_type = hash_tree::proof_type;

    /// \brief Shorthand for machine register type
    using reg = machine_reg;

    /// \brief Constructor from machine configuration
    /// \param config Machine config to use instantiating machine
    /// \param runtime Runtime config to use with machine
    /// \param remover Object that may remove created files and directories if construction fails
    explicit machine(machine_config config, machine_runtime_config runtime = {}, const std::string &dir = {},
        scope_remove remover = {});

    /// \brief Constructor from previously serialized directory
    /// \param directory Directory to load stored machine from
    /// \param runtime Runtime config to use with machine
    explicit machine(const std::string &directory, machine_runtime_config runtime = {},
        sharing_mode sharing = sharing_mode::none);

    /// \brief Serialize entire state to directory
    /// \param directory Directory to store machine into
    void store(const std::string &directory, sharing_mode sharing = sharing_mode::all) const;

    /// \brief Clones a machine stored from source directory to destination directory.
    /// \param from_dir Path to the source directory where the machine is stored.
    /// \param to_dir Path to the destination directory where the cloned machine will be stored.
    static void clone_stored(const std::string &from_dir, const std::string &to_dir);

    /// \brief Removes all files and the directory of a previously stored machine.
    /// \param dir Path to the directory containing the stored machine to be removed.
    static void remove_stored(const std::string &dir);

    /// \brief Returns address range that covers a given physical memory region
    /// \param paddr Target physical address of start of region.
    /// \param length Length of region, in bytes.
    /// \returns Corresponding address range if found, or an empty sentinel otherwise.
    const address_range &find_address_range(uint64_t paddr, uint64_t length) const noexcept {
        return m_ars.find(paddr, length);
    }

    /// \brief Returns address range that covers a given physical memory region
    /// \param paddr Target physical address of start of region.
    /// \param length Length of region, in bytes.
    /// \returns Corresponding address range if found, or an empty sentinel otherwise.
    address_range &find_address_range(uint64_t paddr, uint64_t length) noexcept {
        return m_ars.find(paddr, length);
    }

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

    /// \brief Destructor.
    ~machine();

    /// \brief Returns hash-tree statistics
    /// \param clear Clear all statistics after collecting them
    /// \returns Structure containing all statistics
    hash_tree_stats get_hash_tree_stats(bool clear = false) noexcept {
        return m_ht.get_stats(clear);
    }

    /// \brief Runs the machine until mcycle reaches mcycle_end, the machine halts or yields.
    /// \param mcycle_end Maximum value of mcycle before function returns.
    /// \returns The reason the machine was interrupted.
    /// \details Several conditions can cause the function to break before mcycle reaches mcycle_end. The most
    ///  frequent scenario is when the program executes a WFI instruction. Another example is when the machine
    ///  halts.
    interpreter_break_reason run(uint64_t mcycle_end);

    /// \brief Collects the root hashes after every \p mcycle_period machine cycles
    /// until mcycle reaches \p mcycle_end, the machine yields, or halts.
    /// \param mcycle_end Maximum value of mcycle before function returns.
    /// \param mcycle_period Number of machine cycles between root hashes to collect.
    /// \param mcycle_phase Number of machine cycles elapsed since last root hash collected.
    /// \param log2_bundle_mcycle_count Log base 2 of the amount of mcycle root hashes to bundle.
    /// If greater than 0, it collects subtree root hashes for 2^log2_bundle_mcycle_count root hashes.
    /// \param previous_back_tree Optional context to continue collecting bundled root hashes.
    /// \returns The collected mcycle root hashes.
    /// Stores into result.hashes the root hashes after each period.
    /// Stores into result.mcycle_phase the number of machine cycles after last root hash collected.
    /// Stores into result.break_reason the reason the function returned.
    /// Stores into result.back_tree the back tree context to continue collecting bundled root hashes.
    /// \detail The first hash added to \p result.hashes is the root hash after (\p mcycle_period - \p mcycle_phase)
    /// machine cycles (if the function managed to get that far before returning).
    mcycle_root_hashes collect_mcycle_root_hashes(uint64_t mcycle_end, uint64_t mcycle_period, uint64_t mcycle_phase,
        int32_t log2_bundle_mcycle_count, const std::optional<back_merkle_tree> &previous_back_tree = {});

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

    /// \brief Collects the root hashes after every uarch cycle until mcycle reaches \p mcycle_end,
    /// the machine yields, or halts. Implicitly resetting the uarch between mcycles.
    /// \param mcycle_end End machine cycle value to execute, uarch cycle by uarch cycle.
    /// \param log2_bundle_uarch_cycle_count Log base 2 of the amount of uarch cycle root hashes to bundle.
    /// \returns The collected uarch cycle root hashes.
    /// Stores into result.hashes the root hashes after each uarch cycle.
    /// Stores into result.reset_indices the indices of the root hashes after each implicit uarch reset
    /// (i.e., after each machine cycle).
    /// Stores into result.break_reason the reason why the function returned.
    /// \detail The first hash added to \p result.hashes is the root hash after the first uarch cycle, the last is the
    /// root hash at the time function returns (for whatever reason), which always happens right after an uarch reset.
    uarch_cycle_root_hashes collect_uarch_cycle_root_hashes(uint64_t mcycle_end, int32_t log2_bundle_uarch_cycle_count);

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

    /// \brief Returns a list of descriptions for all PMA entries registered in the machine, sorted by start
    const auto &get_address_ranges() const {
        return m_ars.descriptions_view();
    }

    /// \brief Returns machine state for direct access.
    processor_state &get_state() {
        return *m_s;
    }

    /// \brief Returns machine state for direct read-only access.
    const processor_state &get_state() const {
        return *m_s;
    }

    /// \brief Returns uarch state for direct access.
    uarch_processor_state &get_uarch_state() {
        return *m_us;
    }

    /// \brief Returns uarch state for direct read-only access.
    const uarch_processor_state &get_uarch_state() const {
        return *m_us;
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

    /// \brief Fill file descriptors to be polled by select() for all VirtIO devices.
    /// \param fds Pointer to sets of read, write and except file descriptors to be updated.
    /// \param timeout_us Maximum amount of time to wait in microseconds, this may be updated (always to lower
    /// values).
    void prepare_virtio_devices_select(os::select_fd_sets *fds, uint64_t *timeout_us);

    /// \brief Poll file descriptors that were marked as ready by select() for all VirtIO devices.
    /// \param select_ret Return value from the most recent select() call.
    /// \param fds Pointer to sets of read, write and except file descriptors to be checked.
    /// \returns True if an interrupt was requested, false otherwise.
    /// \details This function process pending events and trigger interrupt requests (if any).
    bool poll_selected_virtio_devices(int select_ret, os::select_fd_sets *fds, i_device_state_access *da);

    /// \brief Poll file descriptors through select() for all VirtIO devices.
    /// \details Basically call prepare_virtio_devices_select(), select() and poll_selected_virtio_devices().
    /// \param timeout_us Maximum amount of time to wait in microseconds, this may be updated (always to lower
    /// values).
    /// \returns True if an interrupt was requested, false otherwise.
    bool poll_virtio_devices(uint64_t *timeout_us, i_device_state_access *da);

    /// \brief Update the hash-tree so it matches the contents of the machine state.
    /// \returns True if successful, false otherwise.
    bool update_hash_tree() const;

    /// \brief Update a single page in the hash-tree after it is modified in the machine state.
    /// \param address Any address inside modified page.
    /// \returns true if succeeded, false otherwise.
    bool update_hash_tree_page(uint64_t address) {
        return m_ht.update_page(m_ars, address);
    }

    /// \brief Obtains the proof for a node in the hash-tree.
    /// \param address Address of target node. Must be aligned to a 2<sup>log2_size</sup> boundary.
    /// \param log2_size log<sub>2</sub> of size subintended by target node.
    /// Must be between 3 (for a word) and 64 (for the entire address space), inclusive.
    /// \param proof Receives the proof.
    /// \details If the node is
    /// smaller than a page size, then it must lie entirely inside the same PMA range.
    proof_type get_proof(uint64_t address, int log2_size) const;

    /// \brief Obtains the proof for a node in the hash-tree without making any modifications to the tree.
    /// \param address Address of target node. Must be aligned to a 2<sup>log2_size</sup> boundary.
    /// \param log2_size log<sub>2</sub> of size subintended by target node.
    /// Must be between 3 (for a word) and 64 (for the entire address space), inclusive.
    /// \param proof Receives the proof.
    /// \details If the node is smaller than a page size, then it must lie entirely inside the same PMA range.
    /// This overload is used to optimize proof generation when the caller knows that the tree is already up to
    /// date.
    proof_type get_proof(uint64_t address, int log2_size, skip_hash_tree_update_t /*unused*/) const {
        return m_ht.get_proof(m_ars, address, log2_size);
    }

    /// \brief Obtains the root hash of the hash-tree.
    /// \returns The hash.
    machine_hash get_root_hash() const;

    /// \brief Obtains the hash of a node in the hash-tree.
    /// \param address Address of target node. Must be aligned to a 2<sup>log2_size</sup> boundary.
    /// \param log2_size log<sub>2</sub> of size subintended by target node.
    /// \returns The hash.
    machine_hash get_node_hash(uint64_t address, int log2_size) const;

    /// \brief Obtains the hash of a node in the hash-tree without making any modifications to it.
    /// \param address Address of target node. Must be aligned to a 2<sup>log2_size</sup> boundary.
    /// \param log2_size log<sub>2</sub> of size subintended by target node.
    /// \returns The hash.
    machine_hash get_node_hash(uint64_t address, int log2_size, skip_hash_tree_update_t /*unused*/) const {
        return m_ht.get_node_hash(m_ars, address, log2_size);
    }

    /// \brief Verifies integrity of hash tree without making any modifications to it tree.
    /// \returns True if tree is self-consistent, false otherwise.
    bool verify_hash_tree() const;

    /// \brief Validate integrity of processor shadow.
    void validate_processor_shadow(bool skip_version_check) const;

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
    /// (But does NOT include memory-mapped devices, shadow PMAs, or unnocupied memory regions.)
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

    /// \brief Reads console output buffer data.
    /// \param data Pointer to buffer receiving the console output data.
    /// \param max_length Maximum number of bytes to read.
    /// If 0, no data is read, only the available size is returned.
    /// \returns Number of bytes actually read from the buffer.
    /// \details Reads up to max_length bytes from the console output buffer and removes the read data.
    uint64_t read_console_output(uint8_t *data, uint64_t max_length);

    /// \brief Writes console input buffer data.
    /// \param data Pointer to data to write to the console input buffer.
    /// \param length Number of bytes to write.
    /// If 0, no data is written, only the available space size is returned.
    /// \returns Number of bytes actually written to the buffer.
    /// \details Writes up to length bytes to the console input buffer.
    uint64_t write_console_input(const uint8_t *data, uint64_t length);

    /// \brief Returns the address range associated to the PMA at a given index
    /// \param index Index of desired address range
    /// \returns Desired address range, or an empty sentinel if index is out of bounds
    const address_range &read_pma(uint64_t index) const noexcept {
        return m_ars.read_pma(index);
    }

    /// \brief Returns the address range associated to the PMA at a given index
    /// \param index Index of desired address range
    /// \returns Desired address range, or an empty sentinel if index is out of bounds
    address_range &read_pma(uint64_t index) noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        return const_cast<address_range &>(std::as_const(*this).read_pma(index));
    }

    /// \brief Go over the write TLB and mark as dirty all pages currently there.
    void mark_write_tlb_dirty_pages() const;

    /// \brief Returns copy of initialization config.
    const machine_config &get_initial_config() const;

    /// \brief Returns the machine runtime config.
    const machine_runtime_config &get_runtime_config() const;

    /// \brief Changes the machine runtime config.
    /// \param range Configuration of the new memory range.
    /// \details Some runtime options cannot be changed.
    void set_runtime_config(machine_runtime_config r);

    /// \brief Replaces a memory address range.
    /// \param config Configuration of the new memory address range.
    /// \details A memory address range matching the start and length specified in the config must exist.
    void replace_memory_range(const memory_range_config &config) {
        m_ars.replace(config);
    }

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
    uint64_t get_paddr(host_addr haddr, uint64_t pma_index) const {
        return static_cast<uint64_t>(haddr + get_hp_offset(pma_index));
    }

    /// \brief Converts from target physical address to machine host address
    /// \param paddr Target physical address to convert
    /// \param pma_index Index of PMA where address falls
    /// \returns Corresponding machine host address
    /// \details This method also converts from vp_offset to vh_offset
    host_addr get_host_addr(uint64_t paddr, uint64_t pma_index) const {
        return host_addr{paddr} - get_hp_offset(pma_index);
    }

    /// \brief Marks a page as dirty
    /// \param haddr Machine host address within page
    /// \param pma_index Index of PMA where address falls
    void mark_dirty_page(host_addr haddr, uint64_t pma_index) {
        auto paddr = get_paddr(haddr, pma_index);
        mark_dirty_page(paddr, pma_index);
    }

    /// \brief Marks a page as dirty
    /// \param paddr Target phyislcal address within page
    /// \param pma_index Index of PMA where address falls
    void mark_dirty_page(uint64_t paddr, uint64_t pma_index) {
        auto &ar = read_pma(pma_index);
        ar.get_dirty_page_tree().mark_dirty_page_and_up(paddr - ar.get_start());
    }

    /// \brief Updates a TLB slot
    /// \param set_index TLB_CODE, TLB_READ, or TLB_WRITE
    /// \param slot_index Index of slot to update
    /// \param vaddr_page Virtual address of page to map
    /// \param vh_offset Offset from target virtual addresses to host addresses within page
    /// \param pma_index Index of PMA where address falls
    void write_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, host_addr vh_offset,
        uint64_t pma_index) {
        m_s->penumbra.tlb[set_index][slot_index].vaddr_page = vaddr_page;
        m_s->penumbra.tlb[set_index][slot_index].vh_offset = vh_offset;
        m_s->shadow.tlb[set_index][slot_index].vaddr_page = vaddr_page;
        if (vaddr_page != TLB_INVALID_PAGE) [[likely]] {
            m_s->shadow.tlb[set_index][slot_index].vp_offset = get_paddr(vh_offset, pma_index);
        } else {
            // simply store the vh_offset as vp_offset when vaddr_page is invalid
            // so that the uarch replay can compute the same written hash.
            m_s->shadow.tlb[set_index][slot_index].vp_offset = static_cast<uint64_t>(vh_offset);
        }
        m_s->shadow.tlb[set_index][slot_index].pma_index = pma_index;
        m_s->shadow.tlb[set_index][slot_index].zero_padding_ = 0;
    }

    /// \brief Updates a TLB slot
    /// \param set_index TLB_CODE, TLB_READ, or TLB_WRITE
    /// \param slot_index Index of slot to update
    /// \param vaddr_page Virtual address of page to map
    /// \param vp_offset Offset from target virtual addresses to target physical addresses within page
    /// \param pma_index Index of PMA where address falls
    void write_shadow_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
        uint64_t pma_index) {
        if (vaddr_page != TLB_INVALID_PAGE) [[likely]] {
            auto paddr_page = vaddr_page + vp_offset;
            const auto vh_offset = get_host_addr(paddr_page, pma_index) - vaddr_page;
            write_tlb(set_index, slot_index, vaddr_page, vh_offset, pma_index);
        } else {
            // vp_offset is unused when vaddr_page is invalid but its value needs to be stored in the shadow TLB
            // so that the uarch replay can compute the same written hash.
            write_tlb(set_index, slot_index, TLB_INVALID_PAGE, static_cast<host_addr>(vp_offset), pma_index);
        }
    }

    /// \brief Reads a TLB register
    /// \param set_index TLB_CODE, TLB_READ, or TLB_WRITE
    /// \param slot_index Index of slot to read
    /// \param reg Register to read from slot
    /// \returns Value of register
    uint64_t read_shadow_tlb(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what reg) const {
        switch (reg) {
            case shadow_tlb_what::vaddr_page:
                return m_s->shadow.tlb[set_index][slot_index].vaddr_page;
            case shadow_tlb_what::vp_offset:
                return m_s->shadow.tlb[set_index][slot_index].vp_offset;
            case shadow_tlb_what::pma_index:
                return m_s->shadow.tlb[set_index][slot_index].pma_index;
            case shadow_tlb_what::zero_padding_:
                return m_s->shadow.tlb[set_index][slot_index].zero_padding_;
            default:
                throw std::domain_error{"unknown shadow TLB register"};
        }
    }

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

    /// \brief Returns whether runtime soft yields are enabled
    bool get_soft_yield() const {
        return m_r.soft_yield;
    }

    /// \brief Returns hash tree hash function
    hash_function_type get_hash_function() const {
        return m_c.hash_tree.hash_function;
    }

    /// \brief Returns whether the machine contains a shared address range
    bool has_shared_address_range() const {
        return std::ranges::any_of(m_ars.all(), [](const auto &ar) { return ar.is_backing_store_shared(); });
    }

    /// \brief Writes a character to console output.
    /// \param ch Character to write.
    /// \returns True if console output should be flushed externally.
    bool putchar(uint8_t ch) noexcept {
        return m_console.putchar(ch);
    }

    /// \brief Reads a character from console input.
    /// \returns The character read as an unsigned 8-bit integer (0-255),
    /// or -1 if no character is available (input is idle),
    /// or END_OF_TRANSMISSION_CHAR (value 4) if the input has been closed (EOF).
    /// Followed by a bool indicating if the input needs refilling.
    std::pair<int, bool> getchar() noexcept {
        return m_console.getchar();
    }
};

} // namespace cartesi

#endif
