// Copyright 2020 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//
#include "virtual-machine.h"

namespace cartesi {

virtual_machine::virtual_machine(const machine_config &c) {
    m_machine = new machine(c);
}

virtual_machine::virtual_machine(const std::string &dir) {
    m_machine = new machine(dir);
}

virtual_machine::~virtual_machine(void) {
    delete m_machine;
}

void virtual_machine::do_store(const std::string &dir) {
    m_machine->store(dir);
}

void virtual_machine::do_run(uint64_t mcycle_end) {
    m_machine->run(mcycle_end);
}

access_log virtual_machine::do_step(const access_log::type &log_type, bool one_based) {
    return m_machine->step(log_type, one_based);
}

bool virtual_machine::do_update_merkle_tree(void) {
    return m_machine->update_merkle_tree();
}

void virtual_machine::do_get_proof(uint64_t address, int log2_size, merkle_tree::proof_type &proof) {
    m_machine->get_proof(address, log2_size, proof);
}

void virtual_machine::do_get_root_hash(hash_type &hash) {
    m_machine->get_root_hash(hash);
}

bool virtual_machine::do_verify_merkle_tree(void) {
    return m_machine->verify_merkle_tree();
}

uint64_t virtual_machine::do_read_csr(csr r) {
    return m_machine->read_csr(r);
}

void virtual_machine::do_write_csr(csr w, uint64_t val) {
    m_machine->write_csr(w, val);
}

uint64_t virtual_machine::do_get_csr_address(csr w) {
    return get_csr_address(w);
}

void virtual_machine::do_read_memory(uint64_t address, unsigned char *data, uint64_t length) {
    m_machine->read_memory(address, data, length);
}

void virtual_machine::do_write_memory(uint64_t address, const unsigned char *data, size_t length) {
    m_machine->write_memory(address, data, length);
}

uint64_t virtual_machine::do_read_x(int i) {
    return m_machine->read_x(i);
}

void virtual_machine::do_write_x(int i, uint64_t val) {
    m_machine->write_x(i, val);
}

uint64_t virtual_machine::do_get_x_address(int i) {
    return m_machine->get_x_address(i);
}

void virtual_machine::do_replace_flash_drive(const flash_drive_config &new_flash) {
    m_machine->replace_flash_drive(new_flash);
}

void virtual_machine::do_dump_pmas(void) {
    m_machine->dump_pmas();
}

bool virtual_machine::do_read_word(uint64_t word_address, uint64_t &word_value) {
    return m_machine->read_word(word_address, word_value);
}

bool virtual_machine::do_verify_dirty_page_maps(void) {
    return m_machine->verify_dirty_page_maps();
}

machine_config virtual_machine::do_get_initial_config(void) {
    return m_machine->get_initial_config();
}

void virtual_machine::do_shutdown() {
    // shutdown is no-op on local machines
}

void virtual_machine::do_snapshot(void) {
    throw std::runtime_error("snapshot not supported");
}

void virtual_machine::do_rollback(void) {
    throw std::runtime_error("do_rollback is not supported");
}

} // namespace cartesi
