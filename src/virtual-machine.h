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

#ifndef VIRTUAL_MACHINE_H
#define VIRTUAL_MACHINE_H

#include <cstdint>
#include <string>

#include "access-log.h"
#include "i-virtual-machine.h"
#include "interpret.h"
#include "machine-config.h"
#include "machine-memory-range-descr.h"
#include "machine-merkle-tree.h"
#include "machine-runtime-config.h"
#include "machine.h"
#include "uarch-interpret.h"

namespace cartesi {

/// \class virtual_machine
/// \brief i_virtual_machine implementation pointing to a local machine instance
class virtual_machine : public i_virtual_machine {
public:
    virtual_machine() = default;
    virtual_machine(const virtual_machine &other) = delete;
    virtual_machine(virtual_machine &&other) noexcept = delete;
    virtual_machine &operator=(const virtual_machine &other) = delete;
    virtual_machine &operator=(virtual_machine &&other) noexcept = delete;
    ~virtual_machine() override;

private:
    i_virtual_machine *do_clone_empty() const override;
    bool do_is_empty() const override;
    void do_create(const machine_config &config, const machine_runtime_config &runtime) override;
    void do_load(const std::string &directory, const machine_runtime_config &runtime) override;
    interpreter_break_reason do_run(uint64_t mcycle_end) override;
    interpreter_break_reason do_log_step(uint64_t mcycle_count, const std::string &filename) override;
    void do_store(const std::string &directory) const override;
    access_log do_log_step_uarch(const access_log::type &log_type) override;
    machine_merkle_tree::proof_type do_get_proof(uint64_t address, int log2_size) const override;
    void do_get_root_hash(machine_hash &hash) const override;
    bool do_verify_merkle_tree() const override;
    uint64_t do_read_reg(reg r) const override;
    void do_write_reg(reg w, uint64_t val) override;
    void do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const override;
    void do_write_memory(uint64_t address, const unsigned char *data, uint64_t length) override;
    void do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) override;
    void do_write_virtual_memory(uint64_t address, const unsigned char *data, uint64_t length) override;
    uint64_t do_translate_virtual_address(uint64_t vaddr) override;
    void do_replace_memory_range(const memory_range_config &new_range) override;
    uint64_t do_read_word(uint64_t address) const override;
    bool do_verify_dirty_page_maps() const override;
    machine_config do_get_initial_config() const override;
    machine_runtime_config do_get_runtime_config() const override;
    void do_set_runtime_config(const machine_runtime_config &r) override;
    void do_destroy() override;
    void do_reset_uarch() override;
    access_log do_log_reset_uarch(const access_log::type &log_type) override;
    uarch_interpreter_break_reason do_run_uarch(uint64_t uarch_cycle_end) override;
    machine_memory_range_descrs do_get_memory_ranges() const override;
    void do_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length) override;
    access_log do_log_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
        const access_log::type &log_type) override;
    uint64_t do_get_reg_address(reg r) const override;
    machine_config do_get_default_config() const override;
    interpreter_break_reason do_verify_step(const machine_hash &root_hash_before, const std::string &log_filename,
        uint64_t mcycle_count, const machine_hash &root_hash_after) const override;
    void do_verify_step_uarch(const machine_hash &root_hash_before, const access_log &log,
        const machine_hash &root_hash_after) const override;
    void do_verify_reset_uarch(const machine_hash &root_hash_before, const access_log &log,
        const machine_hash &root_hash_after) const override;
    void do_verify_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
        const machine_hash &root_hash_before, const access_log &log,
        const machine_hash &root_hash_after) const override;

    machine *get_machine();
    const machine *get_machine() const;

    machine *m_machine = nullptr;
};

} // namespace cartesi

#endif // VIRTUAL_MACHINE_H
