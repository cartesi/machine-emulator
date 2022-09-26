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

#ifndef VIRTUAL_MACHINE
#define VIRTUAL_MACHINE

#include "unique-c-ptr.h"
#include <cstdint>

#include "i-virtual-machine.h"

namespace cartesi {

/// \class virtual_machine
/// \brief i_virtual_machine implementation pointing to a local machine instance
class virtual_machine : public i_virtual_machine {
    using machine = cartesi::machine;
    machine *m_machine;

public:
    virtual_machine(const machine_config &c, const machine_runtime_config &r = {});
    virtual_machine(const std::string &dir, const machine_runtime_config &r = {});
    virtual_machine(const virtual_machine &other) = delete;
    virtual_machine(virtual_machine &&other) noexcept = delete;
    virtual_machine &operator=(const virtual_machine &other) = delete;
    virtual_machine &operator=(virtual_machine &&other) noexcept = delete;
    ~virtual_machine(void) override;

private:
    void do_store(const std::string &dir) override;
    interpreter_break_reason do_run(uint64_t mcycle_end) override;
    access_log do_step_uarch(const access_log::type &log_type, bool one_based = false) override;
    machine_merkle_tree::proof_type do_get_proof(uint64_t address, int log2_size) const override;
    void do_get_root_hash(hash_type &hash) const override;
    bool do_verify_merkle_tree(void) const override;
    uint64_t do_read_csr(csr r) const override;
    void do_write_csr(csr w, uint64_t val) override;
    void do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const override;
    void do_write_memory(uint64_t address, const unsigned char *data, size_t length) override;
    void do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) const override;
    void do_write_virtual_memory(uint64_t address, const unsigned char *data, size_t length) override;
    uint64_t do_read_x(int i) const override;
    void do_write_x(int i, uint64_t val) override;
    uint64_t do_read_f(int i) const override;
    void do_write_f(int i, uint64_t val) override;
    uint64_t do_read_pc(void) const override;
    void do_write_pc(uint64_t val) override;
    uint64_t do_read_fcsr(void) const override;
    void do_write_fcsr(uint64_t val) override;
    uint64_t do_read_mvendorid(void) const override;
    uint64_t do_read_marchid(void) const override;
    uint64_t do_read_mimpid(void) const override;
    uint64_t do_read_mcycle(void) const override;
    void do_write_mcycle(uint64_t val) override;
    uint64_t do_read_icycleinstret(void) const override;
    void do_write_icycleinstret(uint64_t val) override;
    uint64_t do_read_mstatus(void) const override;
    void do_write_mstatus(uint64_t val) override;
    uint64_t do_read_mtvec(void) const override;
    void do_write_mtvec(uint64_t val) override;
    uint64_t do_read_mscratch(void) const override;
    void do_write_mscratch(uint64_t val) override;
    uint64_t do_read_mepc(void) const override;
    void do_write_mepc(uint64_t val) override;
    uint64_t do_read_mcause(void) const override;
    void do_write_mcause(uint64_t val) override;
    uint64_t do_read_mtval(void) const override;
    void do_write_mtval(uint64_t val) override;
    uint64_t do_read_misa(void) const override;
    void do_write_misa(uint64_t val) override;
    uint64_t do_read_mie(void) const override;
    void do_write_mie(uint64_t val) override;
    uint64_t do_read_mip(void) const override;
    void do_write_mip(uint64_t val) override;
    uint64_t do_read_medeleg(void) const override;
    void do_write_medeleg(uint64_t val) override;
    uint64_t do_read_mideleg(void) const override;
    void do_write_mideleg(uint64_t val) override;
    uint64_t do_read_mcounteren(void) const override;
    void do_write_mcounteren(uint64_t val) override;
    uint64_t do_read_menvcfg(void) const override;
    void do_write_menvcfg(uint64_t val) override;
    uint64_t do_read_stvec(void) const override;
    void do_write_stvec(uint64_t val) override;
    uint64_t do_read_sscratch(void) const override;
    void do_write_sscratch(uint64_t val) override;
    uint64_t do_read_sepc(void) const override;
    void do_write_sepc(uint64_t val) override;
    uint64_t do_read_scause(void) const override;
    void do_write_scause(uint64_t val) override;
    uint64_t do_read_stval(void) const override;
    void do_write_stval(uint64_t val) override;
    uint64_t do_read_satp(void) const override;
    void do_write_satp(uint64_t val) override;
    uint64_t do_read_scounteren(void) const override;
    void do_write_scounteren(uint64_t val) override;
    uint64_t do_read_senvcfg(void) const override;
    void do_write_senvcfg(uint64_t val) override;
    uint64_t do_read_hstatus(void) const override;
    void do_write_hstatus(uint64_t val) override;
    uint64_t do_read_hideleg(void) const override;
    void do_write_hideleg(uint64_t val) override;
    uint64_t do_read_hedeleg(void) const override;
    void do_write_hedeleg(uint64_t val) override;
    uint64_t do_read_hie(void) const override;
    void do_write_hie(uint64_t val) override;
    uint64_t do_read_hip(void) const override;
    void do_write_hip(uint64_t val) override;
    uint64_t do_read_hvip(void) const override;
    void do_write_hvip(uint64_t val) override;
    uint64_t do_read_hgatp(void) const override;
    void do_write_hgatp(uint64_t val) override;
    uint64_t do_read_henvcfg(void) const override;
    void do_write_henvcfg(uint64_t val) override;
    uint64_t do_read_htimedelta(void) const override;
    void do_write_htimedelta(uint64_t val) override;
    uint64_t do_read_htval(void) const override;
    void do_write_htval(uint64_t val) override;
    uint64_t do_read_vsepc(void) const override;
    void do_write_vsepc(uint64_t val) override;
    uint64_t do_read_vsstatus(void) const override;
    void do_write_vsstatus(uint64_t val) override;
    uint64_t do_read_vscause(void) const override;
    void do_write_vscause(uint64_t val) override;
    uint64_t do_read_vstval(void) const override;
    void do_write_vstval(uint64_t val) override;
    uint64_t do_read_vstvec(void) const override;
    void do_write_vstvec(uint64_t val) override;
    uint64_t do_read_vsscratch(void) const override;
    void do_write_vsscratch(uint64_t val) override;
    uint64_t do_read_vsatp(void) const override;
    void do_write_vsatp(uint64_t val) override;
    uint64_t do_read_vsie(void) const override;
    void do_write_vsie(uint64_t val) override;
    uint64_t do_read_vsip(void) const override;
    void do_write_vsip(uint64_t val) override;
    uint64_t do_read_ilrsc(void) const override;
    void do_write_ilrsc(uint64_t val) override;
    uint64_t do_read_iflags(void) const override;
    bool do_read_iflags_H(void) const override;
    bool do_read_iflags_Y(void) const override;
    bool do_read_iflags_X(void) const override;
    void do_set_iflags_H(void) override;
    void do_set_iflags_Y(void) override;
    void do_set_iflags_X(void) override;
    void do_reset_iflags_Y(void) override;
    void do_reset_iflags_X(void) override;
    void do_write_iflags(uint64_t val) override;
    uint64_t do_read_htif_tohost(void) const override;
    uint64_t do_read_htif_tohost_dev(void) const override;
    uint64_t do_read_htif_tohost_cmd(void) const override;
    uint64_t do_read_htif_tohost_data(void) const override;
    void do_write_htif_tohost(uint64_t val) override;
    uint64_t do_read_htif_fromhost(void) const override;
    void do_write_htif_fromhost(uint64_t val) override;
    void do_write_htif_fromhost_data(uint64_t val) override;
    uint64_t do_read_htif_ihalt(void) const override;
    void do_write_htif_ihalt(uint64_t val) override;
    uint64_t do_read_htif_iconsole(void) const override;
    void do_write_htif_iconsole(uint64_t val) override;
    uint64_t do_read_htif_iyield(void) const override;
    void do_write_htif_iyield(uint64_t val) override;
    uint64_t do_read_clint_mtimecmp(void) const override;
    void do_write_clint_mtimecmp(uint64_t val) override;
    void do_replace_memory_range(const memory_range_config &new_range) override;
    void do_dump_pmas(void) const override;
    uint64_t do_read_word(uint64_t address) const override;
    bool do_verify_dirty_page_maps(void) const override;
    machine_config do_get_initial_config(void) const override;
    void do_snapshot() override;
    void do_destroy() override;
    void do_rollback() override;
    uint64_t do_read_uarch_x(int i) const override;
    void do_write_uarch_x(int i, uint64_t val) override;
    uint64_t do_read_uarch_pc(void) const override;
    void do_write_uarch_pc(uint64_t val) override;
    uint64_t do_read_uarch_cycle(void) const override;
    void do_write_uarch_cycle(uint64_t val) override;
    uint64_t do_read_uarch_ram_length(void) const override;
    void do_set_uarch_halt_flag() override;
    void do_reset_uarch_state() override;
    bool do_read_uarch_halt_flag(void) const override;
    uarch_interpreter_break_reason do_run_uarch(uint64_t uarch_cycle_end) override;
};

} // namespace cartesi

#endif
