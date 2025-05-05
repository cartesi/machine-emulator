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

#ifndef JSONRPC_MACHINE_H
#define JSONRPC_MACHINE_H

#include <cstdint>
#include <memory>
#include <string>

#include "access-log.h"
#include "address-range-description.h"
#include "i-machine.h"
#include "interpret.h"
#include "jsonrpc-fork-result.h"
#include "machine-config.h"
#include "machine-runtime-config.h"
#include "semantic-version.h"
#include "uarch-interpret.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <boost/asio/io_context.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/container/static_vector.hpp>
#pragma GCC diagnostic pop

namespace cartesi {

/// \class jsonrpc_machine
/// \brief JSONRPC implementation of the i_machine interface
class jsonrpc_machine final : public i_machine {
public:
    enum class cleanup_call { nothing, destroy, shutdown };

    /// \brief Constructor that connects to existing JSONRPC server and performs a sanity check on its version
    /// \param address Address of the server in "host:port" format to connect to
    /// \param connect_timeout_ms Timeout in milliseconds for the connection attempt
    explicit jsonrpc_machine(std::string address, int64_t connect_timeout_ms);

    /// \brief Constructor that connects to existing JSONRPC server without version verification
    /// \param address Address of the server in "host:port" format to connect to
    explicit jsonrpc_machine(std::string address);

    /// \brief Constructor that spawns a new server
    /// \param address The address to bind the server to
    /// \param spawned Output parameter that will contain information about the spawned server
    jsonrpc_machine(const std::string &address, int64_t spawn_timeout_ms, fork_result &spawned);

    // no copies or assignments
    jsonrpc_machine(const jsonrpc_machine &other) = delete;
    jsonrpc_machine(jsonrpc_machine &&other) noexcept = delete;
    jsonrpc_machine &operator=(const jsonrpc_machine &other) = delete;
    jsonrpc_machine &operator=(jsonrpc_machine &&other) noexcept = delete;

    ~jsonrpc_machine() override;

    /// \brief Asks remote server to shutdown
    void shutdown_server();

    /// \brief Forks remote server
    fork_result fork_server() const;

    /// \brief Ask remote server to change the address from which it accepts connections
    std::string rebind_server(const std::string &address);

    /// \brief Obtains the remote server version
    semantic_version get_server_version() const;

    /// \brief Breaks server out of parent program group
    void emancipate_server() const;

    /// \brief Sets timeout for communicating with server
    void set_timeout(int64_t ms);

    /// \brief Asks server to delay next request by a given amount of time
    void delay_next_request(uint64_t ms) const;

    /// \brief Gets timeout for communicating with server
    int64_t get_timeout() const;

    /// \brief Sets timeout for communicating with server
    void set_cleanup_call(cleanup_call call);

    /// \brief Sets timeout for communicating with server
    cleanup_call get_cleanup_call() const;

    /// \brief Returns address of remote remote server
    const std::string &get_server_address() const;

private:
    i_machine *do_clone_empty() const override;
    bool do_is_empty() const override;
    void do_create(const machine_config &config, const machine_runtime_config &runtime) override;
    void do_load(const std::string &directory, const machine_runtime_config &runtime) override;
    interpreter_break_reason do_run(uint64_t mcycle_end) override;
    void do_collect_mcycle_root_hashes(uint64_t mcycle_phase, uint64_t mcycle_period, uint64_t period_count,
        mcycle_root_hashes &result) override;
    interpreter_break_reason do_log_step(uint64_t mcycle_count, const std::string &filename) override;
    void do_store(const std::string &dir) const override;
    uint64_t do_read_reg(reg r) const override;
    void do_write_reg(reg w, uint64_t val) override;
    void do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const override;
    void do_write_memory(uint64_t address, const unsigned char *data, uint64_t length) override;
    void do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) override;
    void do_write_virtual_memory(uint64_t address, const unsigned char *data, uint64_t length) override;
    uint64_t do_translate_virtual_address(uint64_t vaddr) override;
    void do_reset_uarch() override;
    access_log do_log_reset_uarch(const access_log::type &log_type) override;
    machine_hash do_get_root_hash() const override;
    machine_hash do_get_node_hash(uint64_t address, int log2_size) const override;
    hash_tree_proof do_get_proof(uint64_t address, int log2_size) const override;
    void do_replace_memory_range(const memory_range_config &new_range) override;
    access_log do_log_step_uarch(const access_log::type &log_type) override;
    machine_runtime_config do_get_runtime_config() const override;
    void do_set_runtime_config(const machine_runtime_config &r) override;
    void do_destroy() override;
    uint64_t do_read_word(uint64_t address) const override;
    void do_write_word(uint64_t address, uint64_t value) override;
    machine_config do_get_initial_config() const override;
    hash_tree_stats do_get_hash_tree_stats(bool clear) override;
    bool do_verify_hash_tree() const override;
    uarch_interpreter_break_reason do_run_uarch(uint64_t uarch_cycle_end) override;
    void do_collect_uarch_cycle_root_hashes(uint64_t mcycle_count, uarch_cycle_root_hashes &result) override;
    address_range_descriptions do_get_address_ranges() const override;
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
    bool do_is_jsonrpc_machine() const override;

    void check_server_version(std::chrono::time_point<std::chrono::steady_clock> timeout_at) const;
    template <typename R, typename... Ts>
    void request(const std::string &method, const std::tuple<Ts...> &tp, R &result, bool keep_alive = true) const;
    template <typename R, typename... Ts>
    void request(const std::string &method, const std::tuple<Ts...> &tp, R &result,
        std::chrono::time_point<std::chrono::steady_clock> timeout_at, bool keep_alive) const;

    mutable std::unique_ptr<boost::asio::io_context> m_ioc;     // The io_context is required for all I/O
    mutable std::unique_ptr<boost::beast::tcp_stream> m_stream; // TCP stream for keep alive connections
    cleanup_call m_call{cleanup_call::nothing};
    std::string m_address;
    int64_t m_timeout{-1};
};

} // namespace cartesi

#endif // JSONRPC_MACHINE_H
