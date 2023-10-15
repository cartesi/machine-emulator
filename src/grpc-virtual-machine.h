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

#ifndef GRPC_VIRTUAL_MACHINE
#define GRPC_VIRTUAL_MACHINE

#include <cstdint>
#include <memory>
#include <string>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#pragma GCC diagnostic ignored "-Wtype-limits"
#include <grpc++/grpc++.h>

#include "cartesi-machine-checkin.grpc.pb.h"
#include "cartesi-machine.grpc.pb.h"
#include "versioning.pb.h"
#pragma GCC diagnostic pop

#include "i-virtual-machine.h"
#include "semantic-version.h"

namespace cartesi {

/// \class grpc_machine_stub
/// \brief GRPC connection to Cartesi Machine Server
class grpc_machine_stub final {

    struct async_checkin_context {
        async_checkin_context(void) : writer(&server_context) {}
        grpc::ServerContext server_context;
        grpc::ServerAsyncResponseWriter<CartesiMachine::Void> writer;
        CartesiMachine::CheckInRequest request;
    };

    std::string m_remote_address;
    std::string m_checkin_address;
    std::unique_ptr<CartesiMachine::Machine::Stub> m_stub;
    CartesiMachine::MachineCheckIn::AsyncService m_checkin_async_service;
    std::unique_ptr<grpc::ServerCompletionQueue> m_completion_queue;
    std::unique_ptr<grpc::Server> m_checkin_server;
    std::optional<async_checkin_context> m_checkin_context;

public:
    grpc_machine_stub(std::string remote_address, std::string checkin_address);
    grpc_machine_stub(const grpc_machine_stub &other) = delete;
    grpc_machine_stub(grpc_machine_stub &&other) noexcept = delete;
    grpc_machine_stub &operator=(const grpc_machine_stub &other) = delete;
    grpc_machine_stub &operator=(grpc_machine_stub &&other) noexcept = delete;
    ~grpc_machine_stub();

    void prepare_checkin(void);
    void wait_checkin_and_reconnect(void);
    CartesiMachine::Machine::Stub *get_stub(void);
    const CartesiMachine::Machine::Stub *get_stub(void) const;
    const std::string &get_remote_address(void) const;
    const std::string &get_checkin_address(void) const;
};

using grpc_machine_stub_ptr = std::shared_ptr<grpc_machine_stub>;

/// \class grpc_virtual_machine
/// \brief GRPC implementation of the i_virtual_machine interface
class grpc_virtual_machine : public i_virtual_machine {
public:
    grpc_virtual_machine(grpc_machine_stub_ptr stub);
    grpc_virtual_machine(grpc_machine_stub_ptr stub, const std::string &dir, const machine_runtime_config &r = {});
    grpc_virtual_machine(grpc_machine_stub_ptr stub, const machine_config &c, const machine_runtime_config &r = {});

    grpc_virtual_machine(const grpc_virtual_machine &other) = delete;
    grpc_virtual_machine(grpc_virtual_machine &&other) noexcept = delete;
    grpc_virtual_machine &operator=(const grpc_virtual_machine &other) = delete;
    grpc_virtual_machine &operator=(grpc_virtual_machine &&other) noexcept = delete;
    ~grpc_virtual_machine() override;

    static semantic_version get_version(const grpc_machine_stub_ptr &stub);

    static void shutdown(const grpc_machine_stub_ptr &stub);

    static machine_config get_default_config(const grpc_machine_stub_ptr &stub);

    static void verify_access_log(const grpc_machine_stub_ptr &stub, const access_log &log,
        const machine_runtime_config &r = {}, bool one_based = false);

    static void verify_state_transition(const grpc_machine_stub_ptr &stub, const hash_type &root_hash_before,
        const access_log &log, const hash_type &root_hash_after, const machine_runtime_config &r = {},
        bool one_based = false);

    static uint64_t get_x_address(const grpc_machine_stub_ptr &stub, int i);
    static uint64_t get_f_address(const grpc_machine_stub_ptr &stub, int i);
    static uint64_t get_uarch_x_address(const grpc_machine_stub_ptr &stub, int i);
    static uint64_t get_csr_address(const grpc_machine_stub_ptr &stub, csr w);

private:
    machine_config do_get_initial_config(void) const override;

    interpreter_break_reason do_run(uint64_t mcycle_end) override;
    void do_store(const std::string &dir) override;
    uint64_t do_read_csr(csr r) const override;
    void do_write_csr(csr w, uint64_t val) override;
    uint64_t do_read_x(int i) const override;
    void do_write_x(int i, uint64_t val) override;
    uint64_t do_read_f(int i) const override;
    void do_write_f(int i, uint64_t val) override;
    void do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const override;
    void do_write_memory(uint64_t address, const unsigned char *data, size_t length) override;
    void do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) const override;
    void do_write_virtual_memory(uint64_t address, const unsigned char *data, size_t length) override;
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
    uint64_t do_read_menvcfg(void) const override;
    void do_write_menvcfg(uint64_t val) override;
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
    uint64_t do_read_hip(void) const override;
    void do_write_hip(uint64_t val) override;
    uint64_t do_read_hvip(void) const override;
    void do_write_hvip(uint64_t val) override;
    uint64_t do_read_hie(void) const override;
    void do_write_hie(uint64_t val) override;
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
    uint64_t do_read_vsip(void) const override;
    void do_write_vsip(uint64_t val) override;
    uint64_t do_read_vsie(void) const override;
    void do_write_vsie(uint64_t val) override;
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
    void do_get_root_hash(hash_type &hash) const override;
    machine_merkle_tree::proof_type do_get_proof(uint64_t address, int log2_size) const override;
    void do_replace_memory_range(const memory_range_config &new_range) override;
    access_log do_step_uarch(const access_log::type &log_type, bool /*one_based = false*/) override;
    void do_destroy() override;
    void do_snapshot() override;
    void do_rollback() override;
    bool do_verify_dirty_page_maps(void) const override;
    void do_dump_pmas(void) const override;
    uint64_t do_read_word(uint64_t address) const override;
    bool do_verify_merkle_tree(void) const override;
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

    grpc_machine_stub_ptr m_stub;
};

} // namespace cartesi

#endif
