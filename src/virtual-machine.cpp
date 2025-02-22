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

#include "virtual-machine.h"

#include <cstdint>
#include <string>

#include "access-log.h"
#include "address-range-description.h"
#include "i-virtual-machine.h"
#include "interpret.h"
#include "machine-config.h"
#include "machine-merkle-tree.h"
#include "machine-runtime-config.h"
#include "machine.h"
#include "uarch-interpret.h"

namespace cartesi {

i_virtual_machine *virtual_machine::do_clone_empty() const {
    return new virtual_machine();
}

bool virtual_machine::do_is_empty() const {
    return m_machine == nullptr;
}

void virtual_machine::do_create(const machine_config &config, const machine_runtime_config &runtime) {
    m_machine = new machine(config, runtime);
}

void virtual_machine::do_load(const std::string &directory, const machine_runtime_config &runtime) {
    m_machine = new machine(directory, runtime);
}

virtual_machine::~virtual_machine() {
    delete m_machine;
    m_machine = nullptr;
}

machine *virtual_machine::get_machine() {
    if (m_machine == nullptr) {
        throw std::runtime_error{"no machine"};
    }
    return m_machine;
}

const machine *virtual_machine::get_machine() const {
    if (m_machine == nullptr) {
        throw std::runtime_error{"no machine"};
    }
    return m_machine;
}

void virtual_machine::do_store(const std::string &directory) const {
    get_machine()->store(directory);
}

interpreter_break_reason virtual_machine::do_run(uint64_t mcycle_end) {
    return get_machine()->run(mcycle_end);
}

interpreter_break_reason virtual_machine::do_log_step(uint64_t mcycle_count, const std::string &filename) {
    return m_machine->log_step(mcycle_count, filename);
}

access_log virtual_machine::do_log_step_uarch(const access_log::type &log_type) {
    return get_machine()->log_step_uarch(log_type);
}

machine_merkle_tree::proof_type virtual_machine::do_get_proof(uint64_t address, int log2_size) const {
    return get_machine()->get_proof(address, log2_size);
}

void virtual_machine::do_get_root_hash(hash_type &hash) const {
    get_machine()->get_root_hash(hash);
}

bool virtual_machine::do_verify_merkle_tree() const {
    return get_machine()->verify_merkle_tree();
}

uint64_t virtual_machine::do_read_reg(reg r) const {
    return get_machine()->read_reg(r);
}

void virtual_machine::do_write_reg(reg w, uint64_t val) {
    get_machine()->write_reg(w, val);
}

void virtual_machine::do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const {
    get_machine()->read_memory(address, data, length);
}

void virtual_machine::do_write_memory(uint64_t address, const unsigned char *data, uint64_t length) {
    get_machine()->write_memory(address, data, length);
}

void virtual_machine::do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) {
    get_machine()->read_virtual_memory(address, data, length);
}

void virtual_machine::do_write_virtual_memory(uint64_t address, const unsigned char *data, uint64_t length) {
    get_machine()->write_virtual_memory(address, data, length);
}

uint64_t virtual_machine::do_translate_virtual_address(uint64_t vaddr) {
    return get_machine()->translate_virtual_address(vaddr);
}

void virtual_machine::do_replace_memory_range(const memory_range_config &new_range) {
    get_machine()->replace_memory_range(new_range);
}

uint64_t virtual_machine::do_read_word(uint64_t address) const {
    return get_machine()->read_word(address);
}

bool virtual_machine::do_verify_dirty_page_maps() const {
    return get_machine()->verify_dirty_page_maps();
}

machine_config virtual_machine::do_get_initial_config() const {
    return get_machine()->get_initial_config();
}

machine_runtime_config virtual_machine::do_get_runtime_config() const {
    return get_machine()->get_runtime_config();
}

void virtual_machine::do_set_runtime_config(const machine_runtime_config &r) {
    get_machine()->set_runtime_config(r);
}

void virtual_machine::do_destroy() {
    delete get_machine();
    m_machine = nullptr;
}

void virtual_machine::do_reset_uarch() {
    get_machine()->reset_uarch();
}

access_log virtual_machine::do_log_reset_uarch(const access_log::type &log_type) {
    return get_machine()->log_reset_uarch(log_type);
}

uarch_interpreter_break_reason virtual_machine::do_run_uarch(uint64_t uarch_cycle_end) {
    return get_machine()->run_uarch(uarch_cycle_end);
}

address_range_descriptions virtual_machine::do_get_address_ranges() const {
    return get_machine()->get_address_ranges();
}

void virtual_machine::do_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length) {
    get_machine()->send_cmio_response(reason, data, length);
}

access_log virtual_machine::do_log_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
    const access_log::type &log_type) {
    return get_machine()->log_send_cmio_response(reason, data, length, log_type);
}

uint64_t virtual_machine::do_get_reg_address(reg r) const {
    return machine::get_reg_address(r);
}

machine_config virtual_machine::do_get_default_config() const {
    return machine::get_default_config();
}

interpreter_break_reason virtual_machine::do_verify_step(const hash_type &root_hash_before,
    const std::string &log_filename, uint64_t mcycle_count, const hash_type &root_hash_after) const {
    return machine::verify_step(root_hash_before, log_filename, mcycle_count, root_hash_after);
}

void virtual_machine::do_verify_step_uarch(const hash_type &root_hash_before, const access_log &log,
    const hash_type &root_hash_after) const {
    machine::verify_step_uarch(root_hash_before, log, root_hash_after);
}

void virtual_machine::do_verify_reset_uarch(const hash_type &root_hash_before, const access_log &log,
    const hash_type &root_hash_after) const {
    machine::verify_reset_uarch(root_hash_before, log, root_hash_after);
}

void virtual_machine::do_verify_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
    const hash_type &root_hash_before, const access_log &log, const hash_type &root_hash_after) const {
    machine::verify_send_cmio_response(reason, data, length, root_hash_before, log, root_hash_after);
}

} // namespace cartesi
