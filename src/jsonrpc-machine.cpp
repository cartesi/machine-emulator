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

#include "jsonrpc-machine.h"
#include "os-features.h"

#include <cassert>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>

#ifdef HAVE_FORK
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

// On Linux `environ` is defined in unistd.h, in other platforms we may need to import it.
#ifdef __APPLE__
#include <crt_externs.h>
#define environ (*_NSGetEnviron())
#endif

#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#include <boost/asio/connect.hpp> // IWYU pragma: keep
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp> // IWYU pragma: keep
#include <boost/beast/http.hpp> // IWYU pragma: keep
#include <boost/beast/version.hpp>
#pragma GCC diagnostic pop

#include <json.hpp>

#include "access-log.h"
#include "address-range-description.h"
#include "back-merkle-tree.h"
#include "base64.h"
#include "hash-tree-proof.h"
#include "hash-tree-stats.h"
#include "i-machine.h"
#include "interpret.h"
#include "json-util.h"
#include "jsonrpc-fork-result.h"
#include "jsonrpc-version.h"
#include "machine-config.h"
#include "machine-hash.h"
#include "machine-runtime-config.h"
#include "mcycle-root-hashes.h"
#include "os.h"
#include "scope-exit.h"
#include "semantic-version.h"
#include "uarch-cycle-root-hashes.h"
#include "uarch-interpret.h"

using namespace std::string_literals;
using json = nlohmann::json;

namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;   // from <boost/beast/http.hpp>
namespace asio = boost::asio;   // from <boost/asio.hpp>
using tcp = asio::ip::tcp;      // from <boost/asio/ip/tcp.hpp>

template <typename... Ts, size_t... Is>
static std::string jsonrpc_post_data(const std::string &method, const std::tuple<Ts...> &params,
    std::index_sequence<Is...> /*unused*/) {
    json array = json::array();
    ((array.push_back(json(std::get<Is>(params)))), ...);
    const json j = {{"jsonrpc", "2.0"}, {"method", method}, {"id", 0}, {"params", std::move(array)}};
    return j.dump();
}

template <typename... Ts>
static std::string jsonrpc_post_data(const std::string &method, const std::tuple<Ts...> &params) {
    return jsonrpc_post_data(method, params, std::make_index_sequence<sizeof...(Ts)>{});
}

// Close a socket of a connection we are done processing.
static void shutdown_and_close_socket(auto &socket) {
    // Errors are also silently ignored because at this point all the connection traffic was already processed.
    beast::error_code ec;
    // We deliberately omit shutdown on the sending end of the socket to force an RST packet instead of a FIN packet
    // during close(). This behavior occurs because we've set SO_LINGER to 0 on the TCP socket, which causes it to send
    // RST packets when closed. By sending RST instead of FIN, we avoid leaving the connection in TIME_WAIT state, which
    // helps prevent TCP port exhaustion.
    std::ignore = socket.shutdown(tcp::socket::shutdown_receive, ec);
    std::ignore = socket.close(ec);
}

// Parses an endpoint from an address string in the format "<ip>:<port>"
static asio::ip::tcp::endpoint parse_endpoint(const std::string &address) {
    try {
        const auto colon_pos = address.find_first_of(':');
        if (colon_pos == std::string::npos) {
            throw std::runtime_error("missing port number"s);
        }
        const std::string host = address.substr(0, colon_pos);
        const int port = std::stoi(address.substr(colon_pos + 1));
        if (port <= 0 || port >= 65536) {
            throw std::runtime_error("invalid port number"s);
        }
        return {asio::ip::make_address(host), static_cast<uint16_t>(port)};
    } catch (const std::exception &e) {
        throw std::runtime_error("failed to parse endpoint from address \""s + address + "\": "s + e.what());
    }
}

class expiration {
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    beast::tcp_stream &m_stream;

public:
    expiration(beast::tcp_stream &stream, std::chrono::time_point<std::chrono::steady_clock> timeout_at) :
        m_stream(stream) {
        if (timeout_at != std::chrono::time_point<std::chrono::steady_clock>::max()) {
            beast::get_lowest_layer(m_stream).expires_at(timeout_at);
        } else {
            beast::get_lowest_layer(m_stream).expires_never();
        }
    }
    expiration(const expiration &) = delete;
    expiration &operator=(const expiration &) = delete;
    expiration(expiration &&) = delete;
    expiration &operator=(expiration &&) = delete;
    // NOLINTNEXTLINE(bugprone-exception-escape)
    ~expiration() {
        beast::get_lowest_layer(m_stream).expires_never();
    }
};

static std::string json_post(boost::asio::io_context &ioc, beast::tcp_stream &stream, const std::string &remote_address,
    const std::string &post_data, std::chrono::time_point<std::chrono::steady_clock> timeout_at, bool keep_alive) {
    // Determine remote endpoint from remote address
    const asio::ip::tcp::endpoint remote_endpoint = parse_endpoint(remote_address);

    // Set expiration to ms milliseconds into the future, automatically clear it when function exits
    const expiration exp(stream, timeout_at);

    // Close current stream socket when the remote endpoint is different
    if (stream.socket().is_open()) {
        beast::error_code ec;
        const auto socket_remote_endpoint = stream.socket().remote_endpoint(ec);
        if (ec || socket_remote_endpoint != remote_endpoint) {
            shutdown_and_close_socket(stream.socket());
        }
    }

    // Try to reuse an alive connection to the same endpoint, otherwise connect it
    if (!stream.socket().is_open()) {
        // Connect, we perform an asynchronous operation in order to support timeouts
        stream.async_connect(remote_endpoint, [&](beast::error_code ec) {
            if (ec == beast::error::timeout) {
                throw std::runtime_error("jsonrpc error: timeout");
            }
            if (ec) { // Unexpected error
                throw beast::system_error(ec);
            }
        });
        // Run io service until connect callback is called
        ioc.restart();
        ioc.run();

        // Disable Nagle's algorithm to minimize TCP connection latency
        const boost::asio::ip::tcp::no_delay no_delay_option(true);
        stream.socket().set_option(no_delay_option);

        // Minimize socket close time by setting the linger time to 0.
        // It avoids accumulating socket in TIME_WAIT state after rapid successive requests,
        // which can consume all available ports.
        // It's safe to do this because it is the client who decides to close the connection,
        // after all data is received.
        const boost::asio::socket_base::linger linger_option(true, 0);
        stream.socket().set_option(linger_option);

        // Enable keep alive TCP option for keep alive HTTP connection
        if (keep_alive) {
            const boost::asio::socket_base::keep_alive keep_alive_option(true);
            stream.socket().set_option(keep_alive_option);
        }
    }

    try {
        // Set up a HTTP request message
        http::request<http::string_body> req;
        req.method(http::verb::post); // POST
        req.version(11);              // Only HTTP 1.1 support keep alive connections
        req.target("/");
        req.keep_alive(keep_alive);
        req.set(http::field::host, remote_endpoint.address().to_string());
        req.set(http::field::content_type, "application/json");
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req.body() = post_data;
        req.prepare_payload();

        // Send the HTTP request, we perform an asynchronous operation in order to support timeouts
        http::async_write(stream, req, [&](beast::error_code ec, std::size_t /*bytes_transferred*/) {
            if (ec == beast::error::timeout) {
                throw std::runtime_error("jsonrpc error: timeout");
            }
            if (ec) { // Unexpected error
                throw beast::system_error(ec);
            }
        });
        // Run io service until write callback is called
        ioc.restart();
        ioc.run();

        // Set up HTTP response parser
        beast::flat_buffer buffer;
        http::response_parser<http::string_body> res_parser;
        res_parser.eager(true);
        res_parser.body_limit(std::numeric_limits<uint64_t>::max()); // can receive unlimited amount of data

        // Receive the HTTP response, we perform an asynchronous operation in order to support timeouts
        http::async_read(stream, buffer, res_parser, [&](beast::error_code ec, std::size_t /*bytes_transferred*/) {
            if (ec == beast::error::timeout) {
                throw std::runtime_error("jsonrpc error: timeout");
            }
            if (ec) { // Unexpected error
                throw beast::system_error(ec);
            }
        });
        // Run io service until read callback is called
        ioc.restart();
        ioc.run();

        http::response<http::string_body> res = res_parser.release();
        if (res.result() != http::status::ok) {
            throw std::runtime_error("http error: reason "s + std::string(res.reason()) + " (code "s +
                std::to_string(res.result_int()) + ")"s);
        }

        // Gracefully close the socket
        if (!keep_alive || !res.keep_alive()) {
            shutdown_and_close_socket(stream.socket());
        }

        // Return response body
        return res.body();
    } catch (...) {
        shutdown_and_close_socket(stream.socket());
        // Re-throw exception
        throw;
    }
}

template <typename R, typename... Ts>
static void jsonrpc_request(std::unique_ptr<boost::asio::io_context> &ioc, std::unique_ptr<beast::tcp_stream> &stream,
    const std::string &remote_address, const std::string &method, const std::tuple<Ts...> &tp, R &result,
    std::chrono::time_point<std::chrono::steady_clock> timeout_at, bool keep_alive = true) {
    if (!stream || !ioc) {
        throw std::runtime_error{"remote server was shutdown"s};
    }
    auto request = jsonrpc_post_data(method, tp);
    std::string response_s;
    try {
        response_s = json_post(*ioc, *stream, remote_address, request, timeout_at, keep_alive);
    } catch (const std::exception &x) {
        throw std::runtime_error("jsonrpc error: post error contacting "s + remote_address + " ("s + x.what() + ")"s);
    }
    json response;
    try {
        response = json::parse(response_s);
    } catch (const std::exception &x) {
        throw std::runtime_error("jsonrpc server error: invalid response ("s + x.what() + ")"s);
    }
    if (!response.contains("jsonrpc")) {
        throw std::runtime_error(R"(jsonrpc server error: missing field "jsonrpc")"s);
    }
    if (!response["jsonrpc"].is_string() || response["jsonrpc"] != "2.0") {
        throw std::runtime_error(R"(jsonrpc server error: invalid field "jsonrpc" (expected "2.0"))"s);
    }
    if (!response.contains("id")) {
        throw std::runtime_error(R"(jsonrpc server error: missing field "id")"s);
    }
    if (!response["id"].is_number() || response["id"] != 0) {
        throw std::runtime_error(R"(jsonrpc server error: invalid field "id" (expected 0))"s);
    }
    if (response.contains("error") && response.contains("result")) {
        throw std::runtime_error(R"(jsonrpc server error: response contains both "error" and "result" fields)"s);
    }
    if (!response.contains("error") && !response.contains("result")) {
        throw std::runtime_error(R"(jsonrpc server error: response contain no "error" or "result" fields)"s);
    }
    if (response.contains("error")) {
        const auto &jerror = response["error"];
        if (!jerror.is_object()) {
            throw std::runtime_error(R"(jsonrpc server error: invalid "error" field (expected object))"s);
        }
        if (!jerror.contains("code") || !jerror["code"].is_number_integer()) {
            throw std::runtime_error(R"(jsonrpc server error: invalid "error/code" field (expected integer))"s);
        }
        auto code = jerror["code"].template get<int>();
        if (!jerror.contains("message") || !jerror["message"].is_string()) {
            throw std::runtime_error(R"(jsonrpc server error: invalid "error/message" field (expected string))"s);
        }
        auto message = jerror["message"].template get<std::string>();
        throw std::runtime_error("jsonrpc error: "s + message + " (code "s + std::to_string(code) + ")"s);
    }
    try {
        cartesi::ju_get_field(response, "result"s, result, ""s);
    } catch (const std::exception &x) {
        throw std::runtime_error("jsonrpc server error: "s + x.what());
    }
}

namespace cartesi {

template <typename R, typename... Ts>
void jsonrpc_machine::request(const std::string &method, const std::tuple<Ts...> &tp, R &result,
    bool keep_alive) const {
    // Determine request timeout time
    const auto timeout_at = m_timeout >= 0 ? (std::chrono::steady_clock::now() + std::chrono::milliseconds(m_timeout)) :
                                             std::chrono::time_point<std::chrono::steady_clock>::max();
    // Performs the request
    jsonrpc_request(m_ioc, m_stream, m_address, method, tp, result, timeout_at, keep_alive);
}

template <typename R, typename... Ts>
void jsonrpc_machine::request(const std::string &method, const std::tuple<Ts...> &tp, R &result,
    std::chrono::time_point<std::chrono::steady_clock> timeout_at, bool keep_alive) const {
    jsonrpc_request(m_ioc, m_stream, m_address, method, tp, result, timeout_at, keep_alive);
}

void jsonrpc_machine::shutdown_server() {
    bool result = false;
    request("shutdown", std::tie(), result, false);
    // Destroy ASIO context early to release its socket before the destructor,
    // otherwise we may end up with too many open sockets in garbage collected environments.
    // This will also invalidate any further jsonrpc request.
    m_stream.reset();
    m_ioc.reset();
}

void jsonrpc_machine::delay_next_request(uint64_t ms) const {
    bool result = false;
    request("delay_next_request", std::tie(ms), result);
}

void jsonrpc_machine::set_timeout(int64_t ms) {
    m_timeout = ms;
}

int64_t jsonrpc_machine::get_timeout() const {
    return m_timeout;
}

void jsonrpc_machine::set_cleanup_call(cleanup_call call) {
    m_call = call;
}

auto jsonrpc_machine::get_cleanup_call() const -> cleanup_call {
    return m_call;
}

const std::string &jsonrpc_machine::get_server_address() const {
    return m_address;
}

static inline std::string semver_to_string(uint32_t major, uint32_t minor) {
    return std::to_string(major) + "." + std::to_string(minor);
}

void jsonrpc_machine::check_server_version(std::chrono::time_point<std::chrono::steady_clock> timeout_at) const {
    semantic_version server_version;
    request("get_version", std::tie(), server_version, timeout_at, false);
    if (server_version.major != JSONRPC_VERSION_MAJOR || server_version.minor != JSONRPC_VERSION_MINOR) {
        throw std::runtime_error{"expected server version "s +
            semver_to_string(JSONRPC_VERSION_MAJOR, JSONRPC_VERSION_MINOR) + " (got "s +
            semver_to_string(server_version.major, server_version.minor) + ")"s};
    }
}

jsonrpc_machine::jsonrpc_machine(std::string address, int64_t connect_timeout_ms) :
    m_ioc(new boost::asio::io_context{1}),
    m_stream(new boost::beast::tcp_stream(*m_ioc)),
    m_address(std::move(address)) {
    // Install handler to ignore SIGPIPE lest we crash when a server closes a connection
    os_disable_sigpipe();

    // Determine connection timeout time
    const auto timeout_at = connect_timeout_ms >= 0 ?
        (std::chrono::steady_clock::now() + std::chrono::milliseconds(connect_timeout_ms)) :
        std::chrono::time_point<std::chrono::steady_clock>::max();

    // Verify server compatibility by checking its version against our expected version
    check_server_version(timeout_at);
}

jsonrpc_machine::jsonrpc_machine(std::string address) :
    m_ioc(new boost::asio::io_context{1}),
    m_stream(new boost::beast::tcp_stream(*m_ioc)),
    m_address(std::move(address)) {
    // Install handler to ignore SIGPIPE lest we crash when a server closes a connection
    os_disable_sigpipe();
}

#ifdef HAVE_FORK

static boost::asio::ip::tcp::endpoint address_to_endpoint(const std::string &address) {
    try {
        const auto pos = address.find_last_of(':');
        const std::string ip = address.substr(0, pos);
        const int port = std::stoi(address.substr(pos + 1));
        if (port < 0 || port > 65535) {
            throw std::runtime_error{"invalid port"};
        }
        return {boost::asio::ip::make_address(ip), static_cast<uint16_t>(port)};
    } catch (const std::exception &e) {
        throw std::runtime_error{"invalid endpoint address \"" + address + "\""};
    }
}

static std::string endpoint_to_string(const boost::asio::ip::tcp::endpoint &endpoint) {
    std::ostringstream ss;
    ss << endpoint;
    return ss.str();
}

jsonrpc_machine::jsonrpc_machine(const std::string &address, int64_t spawn_timeout_ms, fork_result &spawned) :
    m_ioc(new boost::asio::io_context{1}),
    m_stream(new boost::beast::tcp_stream(*m_ioc)),
    m_call(cleanup_call::shutdown) {

    // Determine spawn timeout time
    const auto timeout_at = spawn_timeout_ms >= 0 ?
        (std::chrono::steady_clock::now() + std::chrono::milliseconds(spawn_timeout_ms)) :
        std::chrono::time_point<std::chrono::steady_clock>::max();

    // Create a TCP acceptor and bind it to the specified address
    // The acceptor automatically performs open, bind and listen operations
    boost::asio::ip::tcp::acceptor a(*m_ioc,
        address_to_endpoint(address)); // NOLINT(clang-analyzer-optin.cplusplus.VirtualCall)

    // Determine which remote machine binary to use
    const char *bin = getenv("CARTESI_JSONRPC_MACHINE");
    if (bin == nullptr) { // Fallback to default name if not set
        bin = "cartesi-jsonrpc-machine";
    }

    // Prepare command-line arguments for the child process
    char server_fd[256] = "";
    std::ignore = snprintf(server_fd, std::size(server_fd), "--server-fd=%d", a.native_handle());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    char *const args[] = {const_cast<char *>(bin), server_fd, nullptr};

    // Spawn the remote machine as a child process
    pid_t child_pid{};
    if (posix_spawnp(&child_pid, bin, nullptr, nullptr, args, environ) != 0) {
        throw std::system_error{errno, std::generic_category(), "posix_spawnp() failed to spawn server process"};
    }

    // Create a scope exit handler to ensure child processes are properly cleaned up
    // This prevents zombie processes by making sure we wait for the child to exit
    auto child_waiter = make_scope_exit([&] {
        // Close any keep alive open connection first
        if (m_stream && m_stream->socket().is_open()) {
            shutdown_and_close_socket(m_stream->socket());
        }

        // Attempt to gracefully terminate the child process
        std::ignore = kill(child_pid, SIGTERM);

        // Wait for the child process to fully exit
        while (true) {
            const auto wait_ret = waitpid(child_pid, nullptr, 0);

            // If waitpid() was interrupted by a signal (EINTR), we need to retry
            // This can happen if another signal arrives during our waitpid() call
            if (wait_ret == -1 && errno == EINTR) {
                // Send SIGILL to ensure child process termination
                // This helps in case the interrupting signal affected the child's state
                std::ignore = kill(child_pid, SIGILL);
                continue;
            }

            // We can exit the waiting loop when either:
            // 1. waitpid() returns a positive value - this indicates successful wait/child termination
            // 2. waitpid() fails with ECHILD (No child processes) which can happen in two cases:
            //    a. The child was already automatically reaped by our SIGCHLD handler set to SIG_IGN
            //    b. Another SIGCHLD handler in the process has already called waitpid() on this child
            break;
        }
    });

    // Store the local endpoint as our server address for future connections
    m_address = endpoint_to_string(a.local_endpoint());

    // Close the acceptor socket, as its ownership is now transferred to the child process
    boost::system::error_code ec;
    std::ignore = a.close(ec);

    // Install signal handler to ignore SIGPIPE signals that would otherwise
    // terminate the process when writing to a closed socket connection
    os_disable_sigpipe();

    // Verify server compatibility by checking its version against our expected version
    check_server_version(timeout_at);

    // Fork a new server process (grand-child) to avoid zombie processes
    // This allows us to use waitpid() on the original child process while the
    // actual server (grand-child) continues running independently
    fork_result forked_grand_child{};
    request("fork", std::tie(), forked_grand_child, timeout_at, true);

    // Ensures the grand-child process is killed if any exceptions occur during the subsequent initialization steps
    auto grand_child_killer = make_scope_fail([&] {
        // Send SIGILL signal to forcefully terminate the grand-child process
        std::ignore = kill(static_cast<pid_t>(forked_grand_child.pid), SIGILL);
    });

    // Shutdown the original child server process now that we have a forked grand-child
    bool shutdown_result = false;
    request("shutdown", std::tie(), shutdown_result, timeout_at, false);
    m_address = forked_grand_child.address;

    // Rebind the forked server to listen on the originally requested address
    std::string rebind_result;
    request("rebind", std::tie(address), rebind_result, timeout_at, false);
    m_address = rebind_result;

    // At this point, we've confirmed the remote server is properly initialized and running
    spawned.pid = forked_grand_child.pid;
    spawned.address = m_address;
}

#else

jsonrpc_machine::jsonrpc_machine(const std::string & /*address*/, fork_result & /*spawned*/) {
    throw std::runtime_error{"fork() is unsupported in this platform"s};
}

#endif

void jsonrpc_machine::do_load(const std::string &directory, const machine_runtime_config &runtime,
    sharing_mode sharing) {
    bool result = false;
    request("machine.load", std::tie(directory, runtime, sharing), result);
}

bool jsonrpc_machine::do_is_empty() const {
    bool result = false;
    request("machine.is_empty", std::tie(), result);
    return result;
}

i_machine *jsonrpc_machine::do_clone_empty() const {
    auto fork_result = fork_server();
    auto *clone = new jsonrpc_machine(fork_result.address);
    try {
        if (!clone->is_empty()) {
            clone->destroy();
        }
    } catch (...) {
        try {
            clone->shutdown_server();
        } catch (...) { // NOLINT(bugprone-empty-catch)
            // We guard against exceptions here, so clone doesn't leak
        }
        delete clone;
        throw;
    }
    return clone;
}

void jsonrpc_machine::do_create(const machine_config &config, const machine_runtime_config &runtime,
    const std::string &dir) {
    bool result = false;
    request("machine.create", std::tie(config, runtime, dir), result);
}

jsonrpc_machine::~jsonrpc_machine() {
    // If configured to destroy machine, do it
    if (m_stream && m_call == cleanup_call::destroy) {
        try {
            destroy();
        } catch (...) { // NOLINT(bugprone-empty-catch)
            // We guard against exceptions here, which would only mean we failed to cleanup.
            // We do not guarantee that we will cleanup. It's a best-effort thing.
        }
    }
    // If configured to shutdown server, do it
    if (m_stream && m_call == cleanup_call::shutdown) {
        try {
            shutdown_server();
        } catch (...) { // NOLINT(bugprone-empty-catch)
            // We guard against exceptions here, which would only mean we failed to cleanup.
            // We do not guarantee that we will cleanup. It's a best-effort thing.
        }
    }
    // Gracefully close any established keep alive connection
    if (m_stream && m_stream->socket().is_open()) {
        shutdown_and_close_socket(m_stream->socket());
    }
}

machine_config jsonrpc_machine::do_get_initial_config() const {
    machine_config result;
    request("machine.get_initial_config", std::tie(), result);
    return result;
}

machine_runtime_config jsonrpc_machine::do_get_runtime_config() const {
    machine_runtime_config result;
    request("machine.get_runtime_config", std::tie(), result);
    return result;
}

void jsonrpc_machine::do_set_runtime_config(const machine_runtime_config &r) {
    bool result = false;
    request("machine.set_runtime_config", std::tie(r), result);
}

semantic_version jsonrpc_machine::get_server_version() const {
    semantic_version result;
    request("get_version", std::tie(), result);
    return result;
}

interpreter_break_reason jsonrpc_machine::do_run(uint64_t mcycle_end) {
    interpreter_break_reason result = interpreter_break_reason::failed;
    request("machine.run", std::tie(mcycle_end), result);
    return result;
}

mcycle_root_hashes jsonrpc_machine::do_collect_mcycle_root_hashes(uint64_t mcycle_end, uint64_t mcycle_period,
    uint64_t mcycle_phase, int32_t log2_bundle_mcycle_count,
    const std::optional<back_merkle_tree> &previous_back_tree) {
    mcycle_root_hashes result;
    request("machine.collect_mcycle_root_hashes",
        std::tie(mcycle_end, mcycle_period, mcycle_phase, log2_bundle_mcycle_count, previous_back_tree), result);
    return result;
}

interpreter_break_reason jsonrpc_machine::do_log_step(uint64_t mcycle_count, const std::string &filename) {
    interpreter_break_reason result = interpreter_break_reason::failed;
    request("machine.log_step", std::tie(mcycle_count, filename), result);
    return result;
}

void jsonrpc_machine::do_store(const std::string &directory, sharing_mode sharing) const {
    bool result = false;
    request("machine.store", std::tie(directory, sharing), result);
}

void jsonrpc_machine::do_clone_stored(const std::string &from_dir, const std::string &to_dir) const {
    bool result = false;
    request("machine.clone_stored", std::tie(from_dir, to_dir), result);
}

uint64_t jsonrpc_machine::do_read_reg(reg r) const {
    uint64_t result = 0;
    request("machine.read_reg", std::tie(r), result);
    return result;
}

void jsonrpc_machine::do_write_reg(reg w, uint64_t val) {
    bool result = false;
    request("machine.write_reg", std::tie(w, val), result);
}

auto jsonrpc_machine::fork_server() const -> fork_result {
    fork_result result{};
    request("fork", std::tie(), result, false);
    return result;
}

std::string jsonrpc_machine::rebind_server(const std::string &address) {
    std::string result;
    request("rebind", std::tie(address), result, false);
    m_address = result;
    return result;
}

void jsonrpc_machine::emancipate_server() const {
    bool result = false;
    request("emancipate", std::tie(), result);
}

void jsonrpc_machine::do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const {
    std::string result;
    request("machine.read_memory", std::tie(address, length), result);
    std::string bin = cartesi::decode_base64(result);
    if (bin.size() != length) {
        throw std::runtime_error("jsonrpc server error: invalid decoded base64 data length");
    }
    std::memcpy(data, bin.data(), length);
}

void jsonrpc_machine::do_write_memory(uint64_t address, const unsigned char *data, uint64_t length) {
    bool result = false;
    std::string b64 = cartesi::encode_base64(std::span<const unsigned char>{data, length});
    request("machine.write_memory", std::tie(address, b64), result);
}

void jsonrpc_machine::do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) {
    std::string result;
    request("machine.read_virtual_memory", std::tie(address, length), result);
    std::string bin = cartesi::decode_base64(result);
    if (bin.size() != length) {
        throw std::runtime_error("jsonrpc server error: invalid decoded base64 data length");
    }
    std::memcpy(data, bin.data(), length);
}

void jsonrpc_machine::do_write_virtual_memory(uint64_t address, const unsigned char *data, uint64_t length) {
    bool result = false;
    std::string b64 = cartesi::encode_base64(std::span<const unsigned char>{data, length});
    request("machine.write_virtual_memory", std::tie(address, b64), result);
}

uint64_t jsonrpc_machine::do_translate_virtual_address(uint64_t vaddr) {
    uint64_t result = 0;
    request("machine.translate_virtual_address", std::tie(vaddr), result);
    return result;
}

void jsonrpc_machine::do_reset_uarch() {
    bool result = false;
    request("machine.reset_uarch", std::tie(), result);
}

access_log jsonrpc_machine::do_log_reset_uarch(const access_log::type &log_type) {
    not_default_constructible<access_log> result;
    request("machine.log_reset_uarch", std::tie(log_type), result);
    if (!result.has_value()) {
        throw std::runtime_error("jsonrpc server error: missing result");
    }
    return std::move(result).value();
}

machine_hash jsonrpc_machine::do_get_root_hash() const {
    machine_hash hash;
    request("machine.get_root_hash", std::tie(), hash);
    return hash;
}

machine_hash jsonrpc_machine::do_get_node_hash(uint64_t address, int log2_size) const {
    machine_hash hash;
    request("machine.get_node_hash", std::tie(address, log2_size), hash);
    return hash;
}

hash_tree_proof jsonrpc_machine::do_get_proof(uint64_t address, int log2_size) const {
    not_default_constructible<hash_tree_proof> result;
    request("machine.get_proof", std::tie(address, log2_size), result);
    if (!result.has_value()) {
        throw std::runtime_error("jsonrpc server error: missing result");
    }
    return std::move(result).value();
}

void jsonrpc_machine::do_replace_memory_range(const memory_range_config &new_range) {
    bool result = false;
    request("machine.replace_memory_range", std::tie(new_range), result);
}

access_log jsonrpc_machine::do_log_step_uarch(const access_log::type &log_type) {
    not_default_constructible<access_log> result;
    request("machine.log_step_uarch", std::tie(log_type), result);
    if (!result.has_value()) {
        throw std::runtime_error("jsonrpc server error: missing result");
    }
    return std::move(result).value();
}

void jsonrpc_machine::do_destroy() {
    bool result = false;
    request("machine.destroy", std::tie(), result);
}

uint64_t jsonrpc_machine::do_read_word(uint64_t address) const {
    uint64_t result = 0;
    request("machine.read_word", std::tie(address), result);
    return result;
}

void jsonrpc_machine::do_write_word(uint64_t address, uint64_t value) {
    bool result = false;
    request("machine.write_word", std::tie(address, value), result);
}

hash_tree_stats jsonrpc_machine::do_get_hash_tree_stats(bool clear) {
    hash_tree_stats result{};
    request("machine.get_hash_tree_stats", std::tie(clear), result);
    return result;
}

bool jsonrpc_machine::do_verify_hash_tree() const {
    bool result = false;
    request("machine.verify_hash_tree", std::tie(), result);
    return result;
}

uarch_interpreter_break_reason jsonrpc_machine::do_run_uarch(uint64_t uarch_cycle_end) {
    uarch_interpreter_break_reason result = uarch_interpreter_break_reason::reached_target_cycle;
    request("machine.run_uarch", std::tie(uarch_cycle_end), result);
    return result;
}

uarch_cycle_root_hashes jsonrpc_machine::do_collect_uarch_cycle_root_hashes(uint64_t mcycle_end,
    int32_t log2_bundle_uarch_cycle_count) {
    uarch_cycle_root_hashes result;
    request("machine.collect_uarch_cycle_root_hashes", std::tie(mcycle_end, log2_bundle_uarch_cycle_count), result);
    return result;
}

address_range_descriptions jsonrpc_machine::do_get_address_ranges() const {
    address_range_descriptions result;
    request("machine.get_address_ranges", std::tie(), result);
    return result;
}

void jsonrpc_machine::do_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length) {
    bool result = false;
    std::string b64 = cartesi::encode_base64(std::span<const unsigned char>{data, length});
    request("machine.send_cmio_response", std::tie(reason, b64), result);
}

access_log jsonrpc_machine::do_log_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
    const access_log::type &log_type) {
    not_default_constructible<access_log> result;
    std::string b64 = cartesi::encode_base64(std::span<const unsigned char>{data, length});
    request("machine.log_send_cmio_response", std::tie(reason, b64, log_type), result);
    if (!result.has_value()) {
        throw std::runtime_error("jsonrpc server error: missing result");
    }
    return std::move(result).value();
}

uint64_t jsonrpc_machine::do_get_reg_address(reg r) const {
    uint64_t result = 0;
    request("machine.get_reg_address", std::tie(r), result);
    return result;
}

machine_config jsonrpc_machine::do_get_default_config() const {
    machine_config result;
    request("machine.get_default_config", std::tie(), result);
    return result;
}

interpreter_break_reason jsonrpc_machine::do_verify_step(const machine_hash &root_hash_before,
    const std::string &log_filename, uint64_t mcycle_count, const machine_hash &root_hash_after) const {
    interpreter_break_reason result = interpreter_break_reason::failed;
    auto b64_root_hash_before = encode_base64(root_hash_before);
    auto b64_root_hash_after = encode_base64(root_hash_after);
    request("machine.verify_step", std::tie(b64_root_hash_before, log_filename, mcycle_count, b64_root_hash_after),
        result);
    return result;
}

void jsonrpc_machine::do_verify_step_uarch(const machine_hash &root_hash_before, const access_log &log,
    const machine_hash &root_hash_after) const {
    bool result = false;
    auto b64_root_hash_before = encode_base64(root_hash_before);
    auto b64_root_hash_after = encode_base64(root_hash_after);
    request("machine.verify_step_uarch", std::tie(b64_root_hash_before, log, b64_root_hash_after), result);
}

void jsonrpc_machine::do_verify_reset_uarch(const machine_hash &root_hash_before, const access_log &log,
    const machine_hash &root_hash_after) const {
    bool result = false;
    auto b64_root_hash_before = encode_base64(root_hash_before);
    auto b64_root_hash_after = encode_base64(root_hash_after);
    request("machine.verify_reset_uarch", std::tie(b64_root_hash_before, log, b64_root_hash_after), result);
}

void jsonrpc_machine::do_verify_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
    const machine_hash &root_hash_before, const access_log &log, const machine_hash &root_hash_after) const {
    bool result = false;
    std::string b64_data = cartesi::encode_base64(std::span<const unsigned char>{data, length});
    auto b64_root_hash_before = encode_base64(root_hash_before);
    auto b64_root_hash_after = encode_base64(root_hash_after);
    request("machine.verify_send_cmio_response",
        std::tie(reason, b64_data, b64_root_hash_before, log, b64_root_hash_after), result);
}

bool jsonrpc_machine::do_is_jsonrpc_machine() const {
    return true;
}

} // namespace cartesi
