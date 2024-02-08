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

void virtual_machine::do_store(const std::string &dir) {
    m_machine->store(dir);
}

interpreter_break_reason virtual_machine::do_run(uint64_t mcycle_end) {
    return m_machine->run(mcycle_end);
}

access_log virtual_machine::do_log_uarch_step(const access_log::type &log_type, bool one_based) {
    return m_machine->log_uarch_step(log_type, one_based);
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

void virtual_machine::do_write_memory(uint64_t address, const unsigned char *data, size_t length) {
    m_machine->write_memory(address, data, length);
}

void virtual_machine::do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) const {
    m_machine->read_virtual_memory(address, data, length);
}

void virtual_machine::do_write_virtual_memory(uint64_t address, const unsigned char *data, size_t length) {
    m_machine->write_virtual_memory(address, data, length);
}

uint64_t virtual_machine::do_translate_virtual_address(uint64_t vaddr) const {
    return m_machine->translate_virtual_address(vaddr);
}

uint64_t virtual_machine::do_read_x(int i) const {
    return m_machine->read_x(i);
}

void virtual_machine::do_write_x(int i, uint64_t val) {
    m_machine->write_x(i, val);
}

uint64_t virtual_machine::do_read_f(int i) const {
    return m_machine->read_f(i);
}

void virtual_machine::do_write_f(int i, uint64_t val) {
    m_machine->write_f(i, val);
}

uint64_t virtual_machine::do_read_pc(void) const {
    return m_machine->read_pc();
}

void virtual_machine::do_write_pc(uint64_t val) {
    return m_machine->write_pc(val);
}

uint64_t virtual_machine::do_read_fcsr(void) const {
    return m_machine->read_fcsr();
}

void virtual_machine::do_write_fcsr(uint64_t val) {
    return m_machine->write_fcsr(val);
}

uint64_t virtual_machine::do_read_mvendorid(void) const {
    return m_machine->read_mvendorid();
}

uint64_t virtual_machine::do_read_marchid(void) const {
    return m_machine->read_marchid();
}

uint64_t virtual_machine::do_read_mimpid(void) const {
    return m_machine->read_mimpid();
}

uint64_t virtual_machine::do_read_mcycle(void) const {
    return m_machine->read_mcycle();
}

void virtual_machine::do_write_mcycle(uint64_t val) {
    return m_machine->write_mcycle(val);
}

uint64_t virtual_machine::do_read_icycleinstret(void) const {
    return m_machine->read_icycleinstret();
}

void virtual_machine::do_write_icycleinstret(uint64_t val) {
    return m_machine->write_icycleinstret(val);
}

uint64_t virtual_machine::do_read_mstatus(void) const {
    return m_machine->read_mstatus();
}

void virtual_machine::do_write_mstatus(uint64_t val) {
    return m_machine->write_mstatus(val);
}

uint64_t virtual_machine::do_read_mtvec(void) const {
    return m_machine->read_mtvec();
}

void virtual_machine::do_write_mtvec(uint64_t val) {
    return m_machine->write_mtvec(val);
}

uint64_t virtual_machine::do_read_mscratch(void) const {
    return m_machine->read_mscratch();
}

void virtual_machine::do_write_mscratch(uint64_t val) {
    return m_machine->write_mscratch(val);
}

uint64_t virtual_machine::do_read_mepc(void) const {
    return m_machine->read_mepc();
}

void virtual_machine::do_write_mepc(uint64_t val) {
    return m_machine->write_mepc(val);
}

uint64_t virtual_machine::do_read_mcause(void) const {
    return m_machine->read_mcause();
}

void virtual_machine::do_write_mcause(uint64_t val) {
    return m_machine->write_mcause(val);
}

uint64_t virtual_machine::do_read_mtval(void) const {
    return m_machine->read_mtval();
}

void virtual_machine::do_write_mtval(uint64_t val) {
    return m_machine->write_mtval(val);
}

uint64_t virtual_machine::do_read_misa(void) const {
    return m_machine->read_misa();
}

void virtual_machine::do_write_misa(uint64_t val) {
    return m_machine->write_misa(val);
}

uint64_t virtual_machine::do_read_mie(void) const {
    return m_machine->read_mie();
}

void virtual_machine::do_write_mie(uint64_t val) {
    return m_machine->write_mie(val);
}

uint64_t virtual_machine::do_read_mip(void) const {
    return m_machine->read_mip();
}

void virtual_machine::do_write_mip(uint64_t val) {
    return m_machine->write_mip(val);
}

uint64_t virtual_machine::do_read_medeleg(void) const {
    return m_machine->read_medeleg();
}

void virtual_machine::do_write_medeleg(uint64_t val) {
    return m_machine->write_medeleg(val);
}

uint64_t virtual_machine::do_read_mideleg(void) const {
    return m_machine->read_mideleg();
}

void virtual_machine::do_write_mideleg(uint64_t val) {
    return m_machine->write_mideleg(val);
}

uint64_t virtual_machine::do_read_mcounteren(void) const {
    return m_machine->read_mcounteren();
}

void virtual_machine::do_write_mcounteren(uint64_t val) {
    return m_machine->write_mcounteren(val);
}

uint64_t virtual_machine::do_read_menvcfg(void) const {
    return m_machine->read_menvcfg();
}

void virtual_machine::do_write_menvcfg(uint64_t val) {
    return m_machine->write_menvcfg(val);
}

uint64_t virtual_machine::do_read_stvec(void) const {
    return m_machine->read_stvec();
}

void virtual_machine::do_write_stvec(uint64_t val) {
    return m_machine->write_stvec(val);
}

uint64_t virtual_machine::do_read_sscratch(void) const {
    return m_machine->read_sscratch();
}

void virtual_machine::do_write_sscratch(uint64_t val) {
    return m_machine->write_sscratch(val);
}

uint64_t virtual_machine::do_read_sepc(void) const {
    return m_machine->read_sepc();
}

void virtual_machine::do_write_sepc(uint64_t val) {
    return m_machine->write_sepc(val);
}

uint64_t virtual_machine::do_read_scause(void) const {
    return m_machine->read_scause();
}

void virtual_machine::do_write_scause(uint64_t val) {
    return m_machine->write_scause(val);
}

uint64_t virtual_machine::do_read_stval(void) const {
    return m_machine->read_stval();
}

void virtual_machine::do_write_stval(uint64_t val) {
    return m_machine->write_stval(val);
}

uint64_t virtual_machine::do_read_satp(void) const {
    return m_machine->read_satp();
}

void virtual_machine::do_write_satp(uint64_t val) {
    return m_machine->write_satp(val);
}

uint64_t virtual_machine::do_read_scounteren(void) const {
    return m_machine->read_scounteren();
}

void virtual_machine::do_write_scounteren(uint64_t val) {
    return m_machine->write_scounteren(val);
}

uint64_t virtual_machine::do_read_senvcfg(void) const {
    return m_machine->read_senvcfg();
}

void virtual_machine::do_write_senvcfg(uint64_t val) {
    return m_machine->write_senvcfg(val);
}

uint64_t virtual_machine::do_read_ilrsc(void) const {
    return m_machine->read_ilrsc();
}

void virtual_machine::do_write_ilrsc(uint64_t val) {
    return m_machine->write_ilrsc(val);
}

uint64_t virtual_machine::do_read_iflags(void) const {
    return m_machine->read_iflags();
}

bool virtual_machine::do_read_iflags_H(void) const {
    return m_machine->read_iflags_H();
}

bool virtual_machine::do_read_iflags_Y(void) const {
    return m_machine->read_iflags_Y();
}

bool virtual_machine::do_read_iflags_X(void) const {
    return m_machine->read_iflags_X();
}

void virtual_machine::do_set_iflags_H(void) {
    return m_machine->set_iflags_H();
}

void virtual_machine::do_set_iflags_Y(void) {
    return m_machine->set_iflags_Y();
}

void virtual_machine::do_set_iflags_X(void) {
    return m_machine->set_iflags_X();
}

void virtual_machine::do_reset_iflags_Y(void) {
    return m_machine->reset_iflags_Y();
}

void virtual_machine::do_reset_iflags_X(void) {
    return m_machine->reset_iflags_X();
}

void virtual_machine::do_write_iflags(uint64_t val) {
    return m_machine->write_iflags(val);
}

uint64_t virtual_machine::do_read_iunrep(void) const {
    return m_machine->read_iunrep();
}

void virtual_machine::do_write_iunrep(uint64_t val) {
    return m_machine->write_iunrep(val);
}

uint64_t virtual_machine::do_read_htif_tohost(void) const {
    return m_machine->read_htif_tohost();
}

uint64_t virtual_machine::do_read_htif_tohost_dev(void) const {
    return m_machine->read_htif_tohost_dev();
}

uint64_t virtual_machine::do_read_htif_tohost_cmd(void) const {
    return m_machine->read_htif_tohost_cmd();
}

uint64_t virtual_machine::do_read_htif_tohost_data(void) const {
    return m_machine->read_htif_tohost_data();
}

void virtual_machine::do_write_htif_tohost(uint64_t val) {
    return m_machine->write_htif_tohost(val);
}

uint64_t virtual_machine::do_read_htif_fromhost(void) const {
    return m_machine->read_htif_fromhost();
}

void virtual_machine::do_write_htif_fromhost(uint64_t val) {
    return m_machine->write_htif_fromhost(val);
}

void virtual_machine::do_write_htif_fromhost_data(uint64_t val) {
    return m_machine->write_htif_fromhost_data(val);
}

uint64_t virtual_machine::do_read_htif_ihalt(void) const {
    return m_machine->read_htif_ihalt();
}

void virtual_machine::do_write_htif_ihalt(uint64_t val) {
    return m_machine->write_htif_ihalt(val);
}

uint64_t virtual_machine::do_read_htif_iconsole(void) const {
    return m_machine->read_htif_iconsole();
}

void virtual_machine::do_write_htif_iconsole(uint64_t val) {
    return m_machine->write_htif_iconsole(val);
}

uint64_t virtual_machine::do_read_htif_iyield(void) const {
    return m_machine->read_htif_iyield();
}

void virtual_machine::do_write_htif_iyield(uint64_t val) {
    return m_machine->write_htif_iyield(val);
}

uint64_t virtual_machine::do_read_clint_mtimecmp(void) const {
    return m_machine->read_clint_mtimecmp();
}

void virtual_machine::do_write_clint_mtimecmp(uint64_t val) {
    return m_machine->write_clint_mtimecmp(val);
}

uint64_t virtual_machine::do_read_plic_girqpend(void) const {
    return m_machine->read_plic_girqpend();
}

void virtual_machine::do_write_plic_girqpend(uint64_t val) {
    return m_machine->write_plic_girqpend(val);
}

uint64_t virtual_machine::do_read_plic_girqsrvd(void) const {
    return m_machine->read_plic_girqsrvd();
}

void virtual_machine::do_write_plic_girqsrvd(uint64_t val) {
    return m_machine->write_plic_girqsrvd(val);
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

void virtual_machine::do_rollback(void) {
    throw std::runtime_error("rollback is not supported");
}

uint64_t virtual_machine::do_read_uarch_x(int i) const {
    return m_machine->read_uarch_x(i);
}

void virtual_machine::do_write_uarch_x(int i, uint64_t val) {
    m_machine->write_uarch_x(i, val);
}

uint64_t virtual_machine::do_read_uarch_pc(void) const {
    return m_machine->read_uarch_pc();
}

void virtual_machine::do_write_uarch_pc(uint64_t val) {
    m_machine->write_uarch_pc(val);
}

uint64_t virtual_machine::do_read_uarch_cycle(void) const {
    return m_machine->read_uarch_cycle();
}

void virtual_machine::do_write_uarch_cycle(uint64_t val) {
    m_machine->write_uarch_cycle(val);
}

void virtual_machine::do_set_uarch_halt_flag() {
    m_machine->set_uarch_halt_flag();
}

void virtual_machine::do_reset_uarch() {
    m_machine->reset_uarch();
}

access_log virtual_machine::do_log_uarch_reset(const access_log::type &log_type, bool one_based) {
    return m_machine->log_uarch_reset(log_type, one_based);
}

bool virtual_machine::do_read_uarch_halt_flag(void) const {
    return m_machine->read_uarch_halt_flag();
}

uarch_interpreter_break_reason virtual_machine::do_run_uarch(uint64_t uarch_cycle_end) {
    return m_machine->run_uarch(uarch_cycle_end);
}

machine_memory_range_descrs virtual_machine::do_get_memory_ranges(void) const {
    return m_machine->get_memory_ranges();
}

void virtual_machine::do_send_cmio_response(uint16_t reason, const unsigned char *data, size_t length) {
    m_machine->send_cmio_response(reason, data, length);
}

access_log virtual_machine::do_log_send_cmio_response(uint16_t reason, const unsigned char *data, size_t length,
    const access_log::type &log_type, bool one_based) {
    return m_machine->log_send_cmio_response(reason, data, length, log_type, one_based);
}

} // namespace cartesi
