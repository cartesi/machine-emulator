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

#ifndef VIRTUAL_MACHINE
#define VIRTUAL_MACHINE

#include <cstdint>
#include "unique-c-ptr.h"

#include "i-virtual-machine.h"

namespace cartesi {

/// \class virtual_machine
/// \brief i_virtual_machine implementation pointing to a local machine instance
class virtual_machine : public i_virtual_machine {
    using machine = cartesi::machine;
    machine *m_machine;

public:
    virtual_machine(const machine_config &c,
        const machine_runtime_config &r = {});
    virtual_machine(const std::string &dir,
        const machine_runtime_config &r = {});
    virtual ~virtual_machine(void);

private:
    void do_store(const std::string &dir) override;
    void do_run(uint64_t mcycle_end) override;
    access_log do_step(const access_log::type &log_type, bool one_based = false) override;
    bool do_update_merkle_tree(void) override;
    void do_get_proof(uint64_t address, int log2_size, merkle_tree::proof_type &proof) override;
    void do_get_root_hash(hash_type &hash) override;
    bool do_verify_merkle_tree(void) override;
    uint64_t do_read_csr(csr r) override;
    void do_write_csr(csr w, uint64_t val) override;
    uint64_t do_get_csr_address(csr w) override;
    void do_read_memory(uint64_t address, unsigned char *data, uint64_t length) override;
    void do_write_memory(uint64_t address, const unsigned char *data, size_t length) override;
    uint64_t do_read_x(int i) override;
    void do_write_x(int i, uint64_t val) override;
    uint64_t do_read_pc(void) override;
    void do_write_pc(uint64_t val) override;
    uint64_t do_read_mvendorid(void) override;
    uint64_t do_read_marchid(void) override;
    uint64_t do_read_mimpid(void) override;
    uint64_t do_read_mcycle(void) override;
    void do_write_mcycle(uint64_t val) override;
    uint64_t do_read_minstret(void) override;
    void do_write_minstret(uint64_t val) override;
    uint64_t do_read_mstatus(void) override;
    void do_write_mstatus(uint64_t val) override;
    uint64_t do_read_mtvec(void) override;
    void do_write_mtvec(uint64_t val) override;
    uint64_t do_read_mscratch(void) override;
    void do_write_mscratch(uint64_t val) override;
    uint64_t do_read_mepc(void) override;
    void do_write_mepc(uint64_t val) override;
    uint64_t do_read_mcause(void) override;
    void do_write_mcause(uint64_t val) override;
    uint64_t do_read_mtval(void) override;
    void do_write_mtval(uint64_t val) override;
    uint64_t do_read_misa(void) override;
    void do_write_misa(uint64_t val) override;
    uint64_t do_read_mie(void) override;
    void do_write_mie(uint64_t val) override;
    uint64_t do_read_mip(void) override;
    void do_write_mip(uint64_t val) override;
    uint64_t do_read_medeleg(void) override;
    void do_write_medeleg(uint64_t val) override;
    uint64_t do_read_mideleg(void) override;
    void do_write_mideleg(uint64_t val) override;
    uint64_t do_read_mcounteren(void) override;
    void do_write_mcounteren(uint64_t val) override;
    uint64_t do_read_stvec(void) override;
    void do_write_stvec(uint64_t val) override;
    uint64_t do_read_sscratch(void) override;
    void do_write_sscratch(uint64_t val) override;
    uint64_t do_read_sepc(void) override;
    void do_write_sepc(uint64_t val) override;
    uint64_t do_read_scause(void) override;
    void do_write_scause(uint64_t val) override;
    uint64_t do_read_stval(void) override;
    void do_write_stval(uint64_t val) override;
    uint64_t do_read_satp(void) override;
    void do_write_satp(uint64_t val) override;
    uint64_t do_read_scounteren(void) override;
    void do_write_scounteren(uint64_t val) override;
    uint64_t do_read_ilrsc(void) override;
    void do_write_ilrsc(uint64_t val) override;
    uint64_t do_read_iflags(void) override;
    bool do_read_iflags_H(void) override;
    bool do_read_iflags_I(void) override;
    bool do_read_iflags_Y(void) override;
    void do_write_iflags(uint64_t val) override;
    uint64_t do_read_htif_tohost(void) override;
    uint64_t do_read_htif_tohost_dev(void) override;
    uint64_t do_read_htif_tohost_cmd(void) override;
    uint64_t do_read_htif_tohost_data(void) override;
    void do_write_htif_tohost(uint64_t val) override;
    uint64_t do_read_htif_fromhost(void) override;
    void do_write_htif_fromhost(uint64_t val) override;
    void do_write_htif_fromhost_data(uint64_t val) override;
    uint64_t do_read_htif_ihalt(void) override;
    void do_write_htif_ihalt(uint64_t val) override;
    uint64_t do_read_htif_iconsole(void) override;
    void do_write_htif_iconsole(uint64_t val) override;
    uint64_t do_read_htif_iyield(void) override;
    void do_write_htif_iyield(uint64_t val) override;
    uint64_t do_read_clint_mtimecmp(void) override;
    void do_write_clint_mtimecmp(uint64_t val) override;
    uint64_t do_read_dhd_tstart(void) override;
    void do_write_dhd_tstart(uint64_t val) override;
    uint64_t do_read_dhd_tlength(void) override;
    void do_write_dhd_tlength(uint64_t val) override;
    uint64_t do_read_dhd_dlength(void) override;
    void do_write_dhd_dlength(uint64_t val) override;
    uint64_t do_read_dhd_hlength(void) override;
    void do_write_dhd_hlength(uint64_t val) override;
    uint64_t do_read_dhd_h(int i) override;
    void do_write_dhd_h(int i, uint64_t val) override;
    void do_replace_flash_drive(const flash_drive_config &new_flash) override;
    void do_dump_pmas(void) override;
    bool do_read_word(uint64_t word_address, uint64_t &word_value) override;
    bool do_verify_dirty_page_maps(void) override;
    machine_config do_get_initial_config(void) override;
    void do_snapshot() override;
    void do_destroy() override;
    void do_rollback() override;
};

} // namespace cartesi

#endif
