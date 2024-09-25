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

#ifndef JSONRPC_VIRTUAL_MACHINE
#define JSONRPC_VIRTUAL_MACHINE

#include <cstdint>
#include <memory>
#include <string>

#include "i-virtual-machine.h"
#include "semantic-version.h"

namespace cartesi {

/// Result of a fork
struct fork_result final {
    std::string address{};
    uint32_t pid{};
};

/// \class jsonrpc_mgr
/// \brief Connection manager to the server
class jsonrpc_mgr;

using jsonrpc_mgr_ptr = std::shared_ptr<jsonrpc_mgr>;

/// \class jsonrpc_virtual_machine
/// \brief JSONRPC implementation of the i_virtual_machine interface
class jsonrpc_virtual_machine final : public i_virtual_machine {
public:
    jsonrpc_virtual_machine(jsonrpc_mgr_ptr mgr);
    jsonrpc_virtual_machine(jsonrpc_mgr_ptr mgr, const std::string &dir, const machine_runtime_config &r = {});
    jsonrpc_virtual_machine(jsonrpc_mgr_ptr mgr, const machine_config &c, const machine_runtime_config &r = {});

    jsonrpc_virtual_machine(const jsonrpc_virtual_machine &other) = delete;
    jsonrpc_virtual_machine(jsonrpc_virtual_machine &&other) noexcept = delete;
    jsonrpc_virtual_machine &operator=(const jsonrpc_virtual_machine &other) = delete;
    jsonrpc_virtual_machine &operator=(jsonrpc_virtual_machine &&other) noexcept = delete;
    ~jsonrpc_virtual_machine() override;

    static semantic_version get_version(const jsonrpc_mgr_ptr &mgr);

    static void shutdown(const jsonrpc_mgr_ptr &mgr);

    static machine_config get_default_config(const jsonrpc_mgr_ptr &mgr);

    static void verify_step_uarch_log(const jsonrpc_mgr_ptr &mgr, const access_log &log, bool one_based = false);

    static void verify_step_uarch_state_transition(const jsonrpc_mgr_ptr &mgr, const hash_type &root_hash_before,
        const access_log &log, const hash_type &root_hash_after, bool one_based = false);

    static void verify_reset_uarch_log(const jsonrpc_mgr_ptr &mgr, const access_log &log, bool one_based = false);

    static void verify_reset_uarch_state_transition(const jsonrpc_mgr_ptr &mgr, const hash_type &root_hash_before,
        const access_log &log, const hash_type &root_hash_after, bool one_based = false);

    static void verify_send_cmio_response_log(const jsonrpc_mgr_ptr &mgr, uint16_t reason, const unsigned char *data,
        uint64_t length, const access_log &log, bool one_based = false);

    static void verify_send_cmio_response_state_transition(const jsonrpc_mgr_ptr &mgr, uint16_t reason,
        const unsigned char *data, uint64_t length, const hash_type &root_hash_before, const access_log &log,
        const hash_type &root_hash_after, bool one_based = false);

    static fork_result fork(const jsonrpc_mgr_ptr &mgr);
    static std::string rebind(const jsonrpc_mgr_ptr &mgr, const std::string &address);
    static uint64_t get_csr_address(const jsonrpc_mgr_ptr &mgr, csr w);

private:
    machine_config do_get_initial_config(void) const override;

    interpreter_break_reason do_run(uint64_t mcycle_end) override;
    void do_store(const std::string &dir) override;
    uint64_t do_read_csr(csr r) const override;
    void do_write_csr(csr w, uint64_t val) override;
    void do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const override;
    void do_write_memory(uint64_t address, const unsigned char *data, uint64_t length) override;
    void do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) const override;
    void do_write_virtual_memory(uint64_t address, const unsigned char *data, uint64_t length) override;
    uint64_t do_translate_virtual_address(uint64_t vaddr) const override;
    uint64_t do_read_mcycle(void) const override;
    bool do_read_iflags_H(void) const override;
    bool do_read_iflags_Y(void) const override;
    bool do_read_iflags_X(void) const override;
    void do_set_iflags_Y(void) override;
    void do_reset_iflags_Y(void) override;
    bool do_read_uarch_halt_flag(void) const override;
    void do_set_uarch_halt_flag(void) override;
    void do_reset_uarch(void) override;
    access_log do_log_reset_uarch(const access_log::type &log_type, bool /*one_based = false*/) override;
    void do_get_root_hash(hash_type &hash) const override;
    machine_merkle_tree::proof_type do_get_proof(uint64_t address, int log2_size) const override;
    void do_replace_memory_range(const memory_range_config &new_range) override;
    access_log do_log_step_uarch(const access_log::type &log_type, bool /*one_based = false*/) override;
    void do_destroy() override;
    void do_snapshot() override;
    void do_commit() override;
    void do_rollback() override;
    bool do_verify_dirty_page_maps(void) const override;
    uint64_t do_read_word(uint64_t address) const override;
    bool do_verify_merkle_tree(void) const override;
    uint64_t do_read_uarch_cycle(void) const override;
    uarch_interpreter_break_reason do_run_uarch(uint64_t uarch_cycle_end) override;
    machine_memory_range_descrs do_get_memory_ranges(void) const override;
    void do_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length) override;
    access_log do_log_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
        const access_log::type &log_type, bool one_based) override;
    jsonrpc_mgr_ptr m_mgr;
};

} // namespace cartesi

#endif
