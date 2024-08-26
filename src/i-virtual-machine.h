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

    /// \brief Constructor
    i_virtual_machine() = default;

    /// \brief Destructor.
    virtual ~i_virtual_machine() = default;

    i_virtual_machine(const i_virtual_machine &other) = delete;
    i_virtual_machine(i_virtual_machine &&other) noexcept = delete;
    i_virtual_machine &operator=(const i_virtual_machine &other) = delete;
    i_virtual_machine &operator=(i_virtual_machine &&other) noexcept = delete;

    /// \brief Runs the machine until mcycle reaches mcycle_end or the machine halts.
    interpreter_break_reason run(uint64_t mcycle_end) {
        return do_run(mcycle_end);
    }

    /// \brief Serialize entire state to directory
    void store(const std::string &dir) {
        do_store(dir);
    }

    /// \brief Runs the machine for one micro cycle logging all accesses to the state.
    access_log log_step_uarch(const access_log::type &log_type, bool one_based = false) {
        return do_log_step_uarch(log_type, one_based);
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
    bool verify_merkle_tree(void) const {
        return do_verify_merkle_tree();
    }

    /// \brief Reads the value of any CSR
    uint64_t read_csr(csr r) const {
        return do_read_csr(r);
    }

    /// \brief Writes the value of any CSR
    void write_csr(csr w, uint64_t val) {
        do_write_csr(w, val);
    }

    /// \brief Reads a chunk of data from the machine memory.
    void read_memory(uint64_t address, unsigned char *data, uint64_t length) const {
        do_read_memory(address, data, length);
    }

    /// \brief Writes a chunk of data to the machine memory.
    void write_memory(uint64_t address, const unsigned char *data, size_t length) {
        do_write_memory(address, data, length);
    }

    /// \brief Reads a chunk of data from the machine virtual memory.
    void read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) const {
        do_read_virtual_memory(address, data, length);
    }

    /// \brief Writes a chunk of data to the machine virtual memory.
    void write_virtual_memory(uint64_t address, const unsigned char *data, size_t length) {
        do_write_virtual_memory(address, data, length);
    }

    /// \brief Translates a virtual memory address to its corresponding physical memory address.
    uint64_t translate_virtual_address(uint64_t vaddr) const {
        return do_translate_virtual_address(vaddr);
    }

    /// \brief Reads the value of a general-purpose register.
    uint64_t read_x(int i) const {
        return do_read_x(i);
    }

    /// \brief Writes the value of a general-purpose register.
    void write_x(int i, uint64_t val) {
        do_write_x(i, val);
    }

    /// \brief Reads the value of a floating-point register.
    uint64_t read_f(int i) const {
        return do_read_f(i);
    }

    /// \brief Writes the value of a floating-point register.
    void write_f(int i, uint64_t val) {
        do_write_f(i, val);
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
    bool verify_dirty_page_maps(void) const {
        return do_verify_dirty_page_maps();
    }

    /// \brief Returns copy of initialization config.
    machine_config get_initial_config(void) const {
        return do_get_initial_config();
    }

    /// \brief destroy
    void destroy(void) {
        do_destroy();
    }

    /// \brief snapshot
    void snapshot(void) {
        do_snapshot();
    }

    /// \brief commit
    void commit(void) {
        do_commit();
    }

    /// \brief rollback
    void rollback(void) {
        do_rollback();
    }

    /// \brief Reads the mcycle register
    uint64_t read_mcycle(void) const {
        return do_read_mcycle();
    }

    /// \brief Writes the mcycle register
    void write_mcycle(uint64_t val) {
        do_write_mcycle(val);
    }

    /// \brief Reads the H iflag
    bool read_iflags_H(void) const {
        return do_read_iflags_H();
    }

    /// \brief Reads the Y iflag
    bool read_iflags_Y(void) const {
        return do_read_iflags_Y();
    }

    /// \brief Reads the X iflag
    bool read_iflags_X(void) const {
        return do_read_iflags_X();
    }

    /// \brief Sets the Y iflag
    void set_iflags_Y(void) {
        return do_set_iflags_Y();
    }

    /// \brief Resets the Y iflag
    void reset_iflags_Y(void) {
        return do_reset_iflags_Y();
    }

    /// \brief Reads htif's tohost
    uint64_t read_htif_tohost(void) const {
        return do_read_htif_tohost();
    }

    /// \brief Reads htif's tohost dev
    uint64_t read_htif_tohost_dev(void) const {
        return do_read_htif_tohost_dev();
    }

    /// \brief Reads htif's tohost cmd
    uint64_t read_htif_tohost_cmd(void) const {
        return do_read_htif_tohost_cmd();
    }

    /// \brief Reads htif's tohost data
    uint64_t read_htif_tohost_data(void) const {
        return do_read_htif_tohost_data();
    }

    /// \brief Writes htif's tohost
    void write_htif_tohost(uint64_t val) {
        do_write_htif_tohost(val);
    }

    /// \brief Reads htif's fromhost
    uint64_t read_htif_fromhost(void) const {
        return do_read_htif_fromhost();
    }

    /// \brief Writes htif's fromhost
    void write_htif_fromhost(uint64_t val) {
        do_write_htif_fromhost(val);
    }

    /// \brief Writes htif's fromhost data
    void write_htif_fromhost_data(uint64_t val) {
        do_write_htif_fromhost_data(val);
    }

    /// \brief Reads the value of a microarchitecture register.
    /// \param i Register index. Between 0 and UARCH_X_REG_COUNT-1, inclusive.
    /// \returns The value of the register.
    uint64_t read_uarch_x(int i) const {
        return do_read_uarch_x(i);
    }

    /// \brief Writes the value of a of a microarchitecture register.
    /// \param i Register index. Between 0 and UARCH_X_REG_COUNT-1, inclusive.
    /// \param val New register value.
    void write_uarch_x(int i, uint64_t val) {
        return do_write_uarch_x(i, val);
    }

    /// \brief Reads the value of the microarchitecture cycle counter register.
    /// \returns The current microarchitecture cycle.
    uint64_t read_uarch_cycle(void) const {
        return do_read_uarch_cycle();
    }

    /// \brief Writes the value ofthe microarchitecture pc register.
    /// \param val New register value.
    void write_uarch_cycle(uint64_t val) {
        return do_write_uarch_cycle(val);
    }

    /// \brief Gets the value of the microarchitecture halt flag
    /// \returns The current microarchitecture cycle.
    bool read_uarch_halt_flag(void) const {
        return do_read_uarch_halt_flag();
    }

    /// \brief Sets the microarchitecture halt flag
    void set_uarch_halt_flag() {
        return do_set_uarch_halt_flag();
    }

    /// \brief Resets the microarchitecture state to pristine value
    void reset_uarch() {
        return do_reset_uarch();
    }

    /// \brief Resets the microarchitecture state to pristine value and returns an access log
    /// \param log_type Type of access log to generate.
    /// \param one_based Use 1-based indices when reporting errors.
    /// \returns The state access log.
    access_log log_reset_uarch(const access_log::type &log_type, bool one_based = false) {
        return do_log_reset_uarch(log_type, one_based);
    }

    /// \brief Runs the microarchitecture until the machine advances to the next mcycle or the current  micro cycle
    /// (uarch_cycle) reaches uarch_cycle_end \param uarch_cycle_end uarch_cycle limit
    uarch_interpreter_break_reason run_uarch(uint64_t uarch_cycle_end) {
        return do_run_uarch(uarch_cycle_end);
    }

    /// \brief Returns a list of descriptions for all PMA entries registered in the machine, sorted by start
    virtual machine_memory_range_descrs get_memory_ranges(void) const {
        return do_get_memory_ranges();
    }

    /// \brief Sends cmio response.
    void send_cmio_response(uint16_t reason, const unsigned char *data, size_t length) {
        do_send_cmio_response(reason, data, length);
    }

    /// \brief Sends cmio response. and returns an access log
    access_log log_send_cmio_response(uint16_t reason, const unsigned char *data, size_t length,
        const access_log::type &log_type, bool one_based) {
        return do_log_send_cmio_response(reason, data, length, log_type, one_based);
    }

private:
    virtual interpreter_break_reason do_run(uint64_t mcycle_end) = 0;
    virtual void do_store(const std::string &dir) = 0;
    virtual access_log do_log_step_uarch(const access_log::type &log_type, bool one_based = false) = 0;
    virtual machine_merkle_tree::proof_type do_get_proof(uint64_t address, int log2_size) const = 0;
    virtual void do_get_root_hash(hash_type &hash) const = 0;
    virtual bool do_verify_merkle_tree(void) const = 0;
    virtual uint64_t do_read_csr(csr r) const = 0;
    virtual void do_write_csr(csr w, uint64_t val) = 0;
    virtual void do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const = 0;
    virtual void do_write_memory(uint64_t address, const unsigned char *data, size_t length) = 0;
    virtual void do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) const = 0;
    virtual void do_write_virtual_memory(uint64_t address, const unsigned char *data, size_t length) = 0;
    virtual uint64_t do_translate_virtual_address(uint64_t vaddr) const = 0;
    virtual uint64_t do_read_x(int i) const = 0;
    virtual void do_write_x(int i, uint64_t val) = 0;
    virtual uint64_t do_read_f(int i) const = 0;
    virtual void do_write_f(int i, uint64_t val) = 0;
    virtual uint64_t do_read_mcycle(void) const = 0;
    virtual void do_write_mcycle(uint64_t val) = 0;
    virtual bool do_read_iflags_H(void) const = 0;
    virtual bool do_read_iflags_Y(void) const = 0;
    virtual bool do_read_iflags_X(void) const = 0;
    virtual void do_set_iflags_Y(void) = 0;
    virtual void do_reset_iflags_Y(void) = 0;
    virtual uint64_t do_read_htif_tohost(void) const = 0;
    virtual uint64_t do_read_htif_tohost_dev(void) const = 0;
    virtual uint64_t do_read_htif_tohost_cmd(void) const = 0;
    virtual uint64_t do_read_htif_tohost_data(void) const = 0;
    virtual void do_write_htif_tohost(uint64_t val) = 0;
    virtual uint64_t do_read_htif_fromhost(void) const = 0;
    virtual void do_write_htif_fromhost(uint64_t val) = 0;
    virtual void do_write_htif_fromhost_data(uint64_t val) = 0;
    virtual void do_replace_memory_range(const memory_range_config &new_range) = 0;
    virtual uint64_t do_read_word(uint64_t address) const = 0;
    virtual bool do_verify_dirty_page_maps(void) const = 0;
    virtual machine_config do_get_initial_config(void) const = 0;
    virtual void do_snapshot() = 0;
    virtual void do_destroy() = 0;
    virtual void do_commit() = 0;
    virtual void do_rollback() = 0;
    virtual uint64_t do_read_uarch_x(int i) const = 0;
    virtual void do_write_uarch_x(int i, uint64_t val) = 0;
    virtual uint64_t do_read_uarch_cycle(void) const = 0;
    virtual void do_write_uarch_cycle(uint64_t val) = 0;
    virtual bool do_read_uarch_halt_flag(void) const = 0;
    virtual void do_set_uarch_halt_flag() = 0;
    virtual void do_reset_uarch() = 0;
    virtual access_log do_log_reset_uarch(const access_log::type &log_type, bool one_based = false) = 0;
    virtual uarch_interpreter_break_reason do_run_uarch(uint64_t uarch_cycle_end) = 0;
    virtual machine_memory_range_descrs do_get_memory_ranges(void) const = 0;
    virtual void do_send_cmio_response(uint16_t reason, const unsigned char *data, size_t length) = 0;
    virtual access_log do_log_send_cmio_response(uint16_t reason, const unsigned char *data, size_t length,
        const access_log::type &log_type, bool one_based) = 0;
};

} // namespace cartesi

#endif
