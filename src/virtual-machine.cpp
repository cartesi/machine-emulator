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

namespace cartesi {

virtual_machine::virtual_machine(const machine_config &c, const machine_runtime_config &r) :
    m_machine(new machine(c, r)) {}

virtual_machine::virtual_machine(const std::string &dir, const machine_runtime_config &r) :
    m_machine(new machine(dir, r)) {}

virtual_machine::~virtual_machine(void) {
    delete m_machine;
}

void virtual_machine::do_store(const std::string &dir) const {
    m_machine->store(dir);
}

interpreter_break_reason virtual_machine::do_run(uint64_t mcycle_end) {
    return m_machine->run(mcycle_end);
}

access_log virtual_machine::do_log_step_uarch(const access_log::type &log_type) {
    return m_machine->log_step_uarch(log_type);
}

machine_merkle_tree::proof_type virtual_machine::do_get_proof(uint64_t address, int log2_size) const {
    return m_machine->get_proof(address, log2_size);
}

void virtual_machine::do_get_root_hash(hash_type &hash) const {
    m_machine->get_root_hash(hash);
}

bool virtual_machine::do_verify_merkle_tree(void) const {
    return m_machine->verify_merkle_tree();
}

uint64_t virtual_machine::do_read_csr(csr r) const {
    return m_machine->read_csr(r);
}

void virtual_machine::do_write_csr(csr w, uint64_t val) {
    m_machine->write_csr(w, val);
}

void virtual_machine::do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const {
    m_machine->read_memory(address, data, length);
}

void virtual_machine::do_write_memory(uint64_t address, const unsigned char *data, uint64_t length) {
    m_machine->write_memory(address, data, length);
}

void virtual_machine::do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) const {
    m_machine->read_virtual_memory(address, data, length);
}

void virtual_machine::do_write_virtual_memory(uint64_t address, const unsigned char *data, uint64_t length) {
    m_machine->write_virtual_memory(address, data, length);
}

uint64_t virtual_machine::do_translate_virtual_address(uint64_t vaddr) const {
    return m_machine->translate_virtual_address(vaddr);
}

void virtual_machine::do_replace_memory_range(const memory_range_config &new_range) {
    m_machine->replace_memory_range(new_range);
}

uint64_t virtual_machine::do_read_word(uint64_t address) const {
    return m_machine->read_word(address);
}

bool virtual_machine::do_verify_dirty_page_maps(void) const {
    return m_machine->verify_dirty_page_maps();
}

machine_config virtual_machine::do_get_initial_config(void) const {
    return m_machine->get_initial_config();
}

void virtual_machine::do_destroy() {
    // destroy is no-op on local machines
}

void virtual_machine::do_snapshot(void) {
    throw std::runtime_error("snapshot is not supported");
}

void virtual_machine::do_commit(void) {
    // no-op, we are always committed
}

void virtual_machine::do_rollback(void) {
    throw std::runtime_error("rollback is not supported");
}

void virtual_machine::do_reset_uarch() {
    m_machine->reset_uarch();
}

access_log virtual_machine::do_log_reset_uarch(const access_log::type &log_type) {
    return m_machine->log_reset_uarch(log_type);
}

uarch_interpreter_break_reason virtual_machine::do_run_uarch(uint64_t uarch_cycle_end) {
    return m_machine->run_uarch(uarch_cycle_end);
}

machine_memory_range_descrs virtual_machine::do_get_memory_ranges(void) const {
    return m_machine->get_memory_ranges();
}

void virtual_machine::do_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length) {
    m_machine->send_cmio_response(reason, data, length);
}

access_log virtual_machine::do_log_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
    const access_log::type &log_type) {
    return m_machine->log_send_cmio_response(reason, data, length, log_type);
}

} // namespace cartesi
