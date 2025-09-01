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

#include "local-machine.h"

#include <cstdint>
#include <optional>
#include <string>

#include "access-log.h"
#include "address-range-description.h"
#include "back-merkle-tree.h"
#include "hash-tree-proof.h"
#include "hash-tree-stats.h"
#include "i-machine.h"
#include "interpret.h"
#include "machine-config.h"
#include "machine-hash.h"
#include "machine-runtime-config.h"
#include "machine.h"
#include "mcycle-root-hashes.h"
#include "uarch-cycle-root-hashes.h"
#include "uarch-interpret.h"

namespace cartesi {

i_machine *local_machine::do_clone_empty() const {
    return new local_machine();
}

bool local_machine::do_is_empty() const {
    return m_machine == nullptr;
}

void local_machine::do_create(const machine_config &config, const machine_runtime_config &runtime,
    const std::string &dir) {
    m_machine = new machine(config, runtime, dir);
}

void local_machine::do_load(const std::string &directory, const machine_runtime_config &runtime, sharing_mode sharing) {
    m_machine = new machine(directory, runtime, sharing);
}

local_machine::~local_machine() {
    delete m_machine;
    m_machine = nullptr;
}

machine *local_machine::get_machine() {
    if (m_machine == nullptr) {
        throw std::runtime_error{"no machine"};
    }
    return m_machine;
}

const machine *local_machine::get_machine() const {
    if (m_machine == nullptr) {
        throw std::runtime_error{"no machine"};
    }
    return m_machine;
}

void local_machine::do_store(const std::string &directory, sharing_mode sharing) const {
    get_machine()->store(directory, sharing);
}

void local_machine::do_clone_stored(const std::string &from_dir, const std::string &to_dir) const {
    machine::clone_stored(from_dir, to_dir);
}

interpreter_break_reason local_machine::do_run(uint64_t mcycle_end) {
    return get_machine()->run(mcycle_end);
}

mcycle_root_hashes local_machine::do_collect_mcycle_root_hashes(uint64_t mcycle_end, uint64_t mcycle_period,
    uint64_t mcycle_phase, int32_t log2_bundle_mcycle_count,
    const std::optional<back_merkle_tree> &previous_back_tree) {
    return get_machine()->collect_mcycle_root_hashes(mcycle_end, mcycle_period, mcycle_phase, log2_bundle_mcycle_count,
        previous_back_tree);
}

interpreter_break_reason local_machine::do_log_step(uint64_t mcycle_count, const std::string &filename) {
    return m_machine->log_step(mcycle_count, filename);
}

access_log local_machine::do_log_step_uarch(const access_log::type &log_type) {
    return get_machine()->log_step_uarch(log_type);
}

hash_tree_proof local_machine::do_get_proof(uint64_t address, int log2_size) const {
    return get_machine()->get_proof(address, log2_size);
}

machine_hash local_machine::do_get_root_hash() const {
    return get_machine()->get_root_hash();
}

machine_hash local_machine::do_get_node_hash(uint64_t address, int log2_size) const {
    return get_machine()->get_node_hash(address, log2_size);
}

bool local_machine::do_verify_hash_tree() const {
    return get_machine()->verify_hash_tree();
}

uint64_t local_machine::do_read_reg(reg r) const {
    return get_machine()->read_reg(r);
}

void local_machine::do_write_reg(reg w, uint64_t val) {
    get_machine()->write_reg(w, val);
}

void local_machine::do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const {
    get_machine()->read_memory(address, data, length);
}

void local_machine::do_write_memory(uint64_t address, const unsigned char *data, uint64_t length) {
    get_machine()->write_memory(address, data, length);
}

void local_machine::do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) {
    get_machine()->read_virtual_memory(address, data, length);
}

void local_machine::do_write_virtual_memory(uint64_t address, const unsigned char *data, uint64_t length) {
    get_machine()->write_virtual_memory(address, data, length);
}

uint64_t local_machine::do_translate_virtual_address(uint64_t vaddr) {
    return get_machine()->translate_virtual_address(vaddr);
}

void local_machine::do_replace_memory_range(const memory_range_config &new_range) {
    get_machine()->replace_memory_range(new_range);
}

uint64_t local_machine::do_read_word(uint64_t address) const {
    return get_machine()->read_word(address);
}

void local_machine::do_write_word(uint64_t address, uint64_t value) {
    get_machine()->write_word(address, value);
}

hash_tree_stats local_machine::do_get_hash_tree_stats(bool clear) {
    return get_machine()->get_hash_tree_stats(clear);
}

machine_config local_machine::do_get_initial_config() const {
    return get_machine()->get_initial_config();
}

machine_runtime_config local_machine::do_get_runtime_config() const {
    return get_machine()->get_runtime_config();
}

void local_machine::do_set_runtime_config(const machine_runtime_config &r) {
    get_machine()->set_runtime_config(r);
}

void local_machine::do_destroy() {
    delete get_machine();
    m_machine = nullptr;
}

void local_machine::do_reset_uarch() {
    get_machine()->reset_uarch();
}

access_log local_machine::do_log_reset_uarch(const access_log::type &log_type) {
    return get_machine()->log_reset_uarch(log_type);
}

uarch_interpreter_break_reason local_machine::do_run_uarch(uint64_t uarch_cycle_end) {
    return get_machine()->run_uarch(uarch_cycle_end);
}

uarch_cycle_root_hashes local_machine::do_collect_uarch_cycle_root_hashes(uint64_t mcycle_end,
    int32_t log2_bundle_uarch_cycle_count) {
    return get_machine()->collect_uarch_cycle_root_hashes(mcycle_end, log2_bundle_uarch_cycle_count);
}

address_range_descriptions local_machine::do_get_address_ranges() const {
    return get_machine()->get_address_ranges();
}

void local_machine::do_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length) {
    get_machine()->send_cmio_response(reason, data, length);
}

access_log local_machine::do_log_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
    const access_log::type &log_type) {
    return get_machine()->log_send_cmio_response(reason, data, length, log_type);
}

uint64_t local_machine::do_get_reg_address(reg r) const {
    return machine::get_reg_address(r);
}

machine_config local_machine::do_get_default_config() const {
    return machine::get_default_config();
}

interpreter_break_reason local_machine::do_verify_step(const machine_hash &root_hash_before,
    const std::string &log_filename, uint64_t mcycle_count, const machine_hash &root_hash_after) const {
    return machine::verify_step(root_hash_before, log_filename, mcycle_count, root_hash_after);
}

void local_machine::do_verify_step_uarch(const machine_hash &root_hash_before, const access_log &log,
    const machine_hash &root_hash_after) const {
    machine::verify_step_uarch(root_hash_before, log, root_hash_after);
}

void local_machine::do_verify_reset_uarch(const machine_hash &root_hash_before, const access_log &log,
    const machine_hash &root_hash_after) const {
    machine::verify_reset_uarch(root_hash_before, log, root_hash_after);
}

void local_machine::do_verify_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
    const machine_hash &root_hash_before, const access_log &log, const machine_hash &root_hash_after) const {
    machine::verify_send_cmio_response(reason, data, length, root_hash_before, log, root_hash_after);
}

} // namespace cartesi
