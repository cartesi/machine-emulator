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

#ifndef I_VIRTUAL_MACHINE_H
#define I_VIRTUAL_MACHINE_H

#include <cstdint>
#include <string>

#include "access-log.h"
#include "address-range-description.h"
#include "interpret.h"
#include "machine-config.h"
#include "machine-merkle-tree.h"
#include "machine.h"
#include "uarch-interpret.h"

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
    using reg = machine_reg;

    /// \brief Constructor
    i_virtual_machine() = default;

    /// \brief Destructor.
    virtual ~i_virtual_machine() = default;

    i_virtual_machine(const i_virtual_machine &other) = delete;
    i_virtual_machine(i_virtual_machine &&other) noexcept = delete;
    i_virtual_machine &operator=(const i_virtual_machine &other) = delete;
    i_virtual_machine &operator=(i_virtual_machine &&other) noexcept = delete;

    /// \brief Clone an object of same underlying type but without a machine instance
    i_virtual_machine *clone_empty() const {
        return do_clone_empty();
    }

    /// \brief Tells if object is empty (does not holds a machine instance)
    bool is_empty() const {
        return do_is_empty();
    }

    /// \brief Create a machine from config
    void create(const machine_config &config, const machine_runtime_config &runtime = {}) {
        do_create(config, runtime);
    }

    /// \brief Load Create a machine from config
    void load(const std::string &directory, const machine_runtime_config &runtime = {}) {
        do_load(directory, runtime);
    }

    /// \brief Runs the machine until mcycle reaches mcycle_end or the machine halts.
    interpreter_break_reason run(uint64_t mcycle_end) {
        return do_run(mcycle_end);
    }

    /// \brief Serialize entire state to directory
    void store(const std::string &dir) const {
        do_store(dir);
    }

    /// \brief  Runs the machine for the given mcycle count and generates a log file of accessed pages and proof data.
    interpreter_break_reason log_step(uint64_t mcycle_count, const std::string &filename) {
        return do_log_step(mcycle_count, filename);
    }

    /// \brief Runs the machine for one micro cycle logging all accesses to the state.
    access_log log_step_uarch(const access_log::type &log_type) {
        return do_log_step_uarch(log_type);
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
    bool verify_merkle_tree() const {
        return do_verify_merkle_tree();
    }

    /// \brief Reads the value of any register
    uint64_t read_reg(reg r) const {
        return do_read_reg(r);
    }

    /// \brief Writes the value of any register
    void write_reg(reg w, uint64_t val) {
        do_write_reg(w, val);
    }

    /// \brief Reads a chunk of data from the machine memory.
    void read_memory(uint64_t address, unsigned char *data, uint64_t length) const {
        do_read_memory(address, data, length);
    }

    /// \brief Writes a chunk of data to the machine memory.
    void write_memory(uint64_t address, const unsigned char *data, uint64_t length) {
        do_write_memory(address, data, length);
    }

    /// \brief Reads a chunk of data from the machine virtual memory.
    void read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) {
        do_read_virtual_memory(address, data, length);
    }

    /// \brief Writes a chunk of data to the machine virtual memory.
    void write_virtual_memory(uint64_t address, const unsigned char *data, uint64_t length) {
        do_write_virtual_memory(address, data, length);
    }

    /// \brief Translates a virtual memory address to its corresponding physical memory address.
    uint64_t translate_virtual_address(uint64_t vaddr) {
        return do_translate_virtual_address(vaddr);
    }

    /// \brief Replaces a flash drive.
    void replace_memory_range(const memory_range_config &new_range) {
        do_replace_memory_range(new_range);
    }

    /// \brief Read the value of a word in the machine state.
    uint64_t read_word(uint64_t address) const {
        return do_read_word(address);
    }

    /// \brief Verify if dirty page maps are consistent.
    bool verify_dirty_page_maps() const {
        return do_verify_dirty_page_maps();
    }

    /// \brief Returns copy of initialization config.
    machine_config get_initial_config() const {
        return do_get_initial_config();
    }

    machine_runtime_config get_runtime_config() const {
        return do_get_runtime_config();
    }

    void set_runtime_config(const machine_runtime_config &r) {
        do_set_runtime_config(r);
    }

    /// \brief destroy
    void destroy() {
        do_destroy();
    }

    /// \brief Resets the microarchitecture state to pristine value
    void reset_uarch() {
        do_reset_uarch();
    }

    /// \brief Resets the microarchitecture state to pristine value and returns an access log
    /// \param log_type Type of access log to generate.
    /// \returns The state access log.
    access_log log_reset_uarch(const access_log::type &log_type) {
        return do_log_reset_uarch(log_type);
    }

    /// \brief Runs the microarchitecture until the machine advances to the next mcycle or the current  micro cycle
    /// (uarch_cycle) reaches uarch_cycle_end \param uarch_cycle_end uarch_cycle limit
    uarch_interpreter_break_reason run_uarch(uint64_t uarch_cycle_end) {
        return do_run_uarch(uarch_cycle_end);
    }

    /// \brief Returns a list of descriptions for all PMA entries registered in the machine, sorted by start
    virtual address_range_descriptions get_address_ranges() const {
        return do_get_address_ranges();
    }

    /// \brief Sends cmio response.
    void send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length) {
        do_send_cmio_response(reason, data, length);
    }

    /// \brief Sends cmio response and returns an access log
    access_log log_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
        const access_log::type &log_type) {
        return do_log_send_cmio_response(reason, data, length, log_type);
    }

    /// \brief Gets the address of any register
    uint64_t get_reg_address(reg r) const {
        return do_get_reg_address(r);
    }

    /// \brief Returns copy of default machine config
    machine_config get_default_config() const {
        return do_get_default_config();
    }

    /// \brief Checks the validity of a state transition caused by log_step.
    interpreter_break_reason verify_step(const hash_type &root_hash_before, const std::string &log_filename,
        uint64_t mcycle_count, const hash_type &root_hash_after) const {
        return do_verify_step(root_hash_before, log_filename, mcycle_count, root_hash_after);
    }

    /// \brief Checks the validity of a state transition caused by log_step_uarch.
    void verify_step_uarch(const hash_type &root_hash_before, const access_log &log,
        const hash_type &root_hash_after) const {
        do_verify_step_uarch(root_hash_before, log, root_hash_after);
    }

    /// \brief Checks the validity of a state transition caused by log_reset_uarch.
    void verify_reset_uarch(const hash_type &root_hash_before, const access_log &log,
        const hash_type &root_hash_after) const {
        do_verify_reset_uarch(root_hash_before, log, root_hash_after);
    }

    /// \brief Checks the validity of state transitions caused by log_send_cmio_response.
    void verify_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
        const hash_type &root_hash_before, const access_log &log, const hash_type &root_hash_after) const {
        do_verify_send_cmio_response(reason, data, length, root_hash_before, log, root_hash_after);
    }

    /// \brief Checks if implementation is jsorpc-virtual-machine
    bool is_jsonrpc_virtual_machine() const {
        return do_is_jsonrpc_virtual_machine();
    }

private:
    virtual i_virtual_machine *do_clone_empty() const = 0;
    virtual bool do_is_empty() const = 0;
    virtual void do_create(const machine_config &config, const machine_runtime_config &runtime) = 0;
    virtual void do_load(const std::string &directory, const machine_runtime_config &runtime) = 0;
    virtual interpreter_break_reason do_run(uint64_t mcycle_end) = 0;
    virtual void do_store(const std::string &dir) const = 0;
    virtual interpreter_break_reason do_log_step(uint64_t mcycle_count, const std::string &filename) = 0;
    virtual access_log do_log_step_uarch(const access_log::type &log_type) = 0;
    virtual machine_merkle_tree::proof_type do_get_proof(uint64_t address, int log2_size) const = 0;
    virtual void do_get_root_hash(hash_type &hash) const = 0;
    virtual bool do_verify_merkle_tree() const = 0;
    virtual uint64_t do_read_reg(reg r) const = 0;
    virtual void do_write_reg(reg w, uint64_t val) = 0;
    virtual void do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const = 0;
    virtual void do_write_memory(uint64_t address, const unsigned char *data, uint64_t length) = 0;
    virtual void do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) = 0;
    virtual void do_write_virtual_memory(uint64_t address, const unsigned char *data, uint64_t length) = 0;
    virtual uint64_t do_translate_virtual_address(uint64_t vaddr) = 0;
    virtual void do_replace_memory_range(const memory_range_config &new_range) = 0;
    virtual uint64_t do_read_word(uint64_t address) const = 0;
    virtual bool do_verify_dirty_page_maps() const = 0;
    virtual machine_config do_get_initial_config() const = 0;
    virtual machine_runtime_config do_get_runtime_config() const = 0;
    virtual void do_set_runtime_config(const machine_runtime_config &r) = 0;
    virtual void do_destroy() = 0;
    virtual void do_reset_uarch() = 0;
    virtual access_log do_log_reset_uarch(const access_log::type &log_type) = 0;
    virtual uarch_interpreter_break_reason do_run_uarch(uint64_t uarch_cycle_end) = 0;
    virtual address_range_descriptions do_get_address_ranges() const = 0;
    virtual void do_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length) = 0;
    virtual access_log do_log_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
        const access_log::type &log_type) = 0;
    virtual uint64_t do_get_reg_address(reg r) const = 0;
    virtual machine_config do_get_default_config() const = 0;
    virtual interpreter_break_reason do_verify_step(const hash_type &root_hash_before, const std::string &log_filename,
        uint64_t mcycle_count, const hash_type &root_hash_after) const = 0;
    virtual void do_verify_step_uarch(const hash_type &root_hash_before, const access_log &log,
        const hash_type &root_hash_after) const = 0;
    virtual void do_verify_reset_uarch(const hash_type &root_hash_before, const access_log &log,
        const hash_type &root_hash_after) const = 0;
    virtual void do_verify_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
        const hash_type &root_hash_before, const access_log &log, const hash_type &root_hash_after) const = 0;
    virtual bool do_is_jsonrpc_virtual_machine() const {
        return false;
    }
};

} // namespace cartesi

#endif // I_VIRTUAL_MACHINE_H
