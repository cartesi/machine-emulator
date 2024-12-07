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

#include "jsonrpc-virtual-machine.h"

#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>

#include "os-features.h"

#ifdef HAVE_FORK
#include <sys/time.h>
#include <unistd.h>
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#pragma GCC diagnostic pop

#include "access-log.h"
#include "base64.h"
#include "interpret.h"
#include "json-util.h"
#include "json.hpp"
#include "jsonrpc-version.h"
#include "machine-config.h"
#include "machine-memory-range-descr.h"
#include "machine-merkle-tree.h"
#include "machine-runtime-config.h"
#include "os.h"
#include "semantic-version.h"
#include "uarch-interpret.h"

using namespace std::string_literals;
using json = nlohmann::json;
using hash_type = cartesi::machine_merkle_tree::hash_type;

namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;   // from <boost/beast/http.hpp>
namespace asio = boost::asio;   // from <boost/asio.hpp>
using tcp = asio::ip::tcp;      // from <boost/asio/ip/tcp.hpp>

template <typename... Ts, size_t... Is>
std::string jsonrpc_post_data(const std::string &method, const std::tuple<Ts...> &params,
    std::index_sequence<Is...> /*unused*/) {
    json array = json::array();
    ((array.push_back(json(std::get<Is>(params)))), ...);
    const json j = {{"jsonrpc", "2.0"}, {"method", method}, {"id", 0}, {"params", std::move(array)}};
    return j.dump();
}

template <typename... Ts>
std::string jsonrpc_post_data(const std::string &method, const std::tuple<Ts...> &params) {
    return jsonrpc_post_data(method, params, std::make_index_sequence<sizeof...(Ts)>{});
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
        return {asio::ip::address::from_string(host), static_cast<uint16_t>(port)};
    } catch (std::exception &e) {
        throw std::runtime_error("failed to parse endpoint from address \""s + address + "\": "s + e.what());
    }
}

class expiration {
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    beast::tcp_stream &m_stream;

public:
    expiration(beast::tcp_stream &stream, int64_t ms) : m_stream(stream) {
        if (ms > 0) {
            beast::get_lowest_layer(m_stream).expires_after(std::chrono::milliseconds(ms));
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
    const std::string &post_data, int64_t ms, bool keep_alive) {
    // Determine remote endpoint from remote address
    const asio::ip::tcp::endpoint remote_endpoint = parse_endpoint(remote_address);

    // Set expiration to ms milliseconds into the future, automatically clear it when function exits
    const expiration exp(stream, ms);

    // Close current stream socket when the remote endpoint is different
    if (stream.socket().is_open()) {
        beast::error_code ec;
        const auto socket_remote_endpoint = stream.socket().remote_endpoint(ec);
        if (ec || socket_remote_endpoint != remote_endpoint) {
            // We can silently ignore socket shutdown/close errors from previous connections
            std::ignore = stream.socket().shutdown(tcp::socket::shutdown_both, ec);
            std::ignore = stream.socket().close(ec);
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
        // On MacOS, it avoids accumulating socket in TIME_WAIT state, after rapid successive requests,
        // which can consume all available ports.
        // It is safe to do this because it is the client who decides to close the connection,
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
        res_parser.body_limit(16777216U); // can receive up to 16MB

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
            beast::error_code ec;
            // The response was received so we can silently ignore socket shutdown/close errors
            std::ignore = stream.socket().shutdown(tcp::socket::shutdown_both, ec);
            std::ignore = stream.socket().close(ec);
        }

        // Return response body
        return res.body();
    } catch (...) {
        // Close stream socket on errors
        beast::error_code ec;
        std::ignore = stream.socket().shutdown(tcp::socket::shutdown_both, ec);
        std::ignore = stream.socket().close(ec);
        // Re-throw exception
        throw;
    }
}

template <typename R, typename... Ts>
void jsonrpc_request(boost::asio::io_context &ioc, beast::tcp_stream &stream, const std::string &remote_address,
    const std::string &method, const std::tuple<Ts...> &tp, R &result, int64_t ms, bool keep_alive = true) {
    auto request = jsonrpc_post_data(method, tp);
    std::string response_s;
    try {
        response_s = json_post(ioc, stream, remote_address, request, ms, keep_alive);
    } catch (std::exception &x) {
        throw std::runtime_error("jsonrpc error: post error contacting "s + remote_address + " ("s + x.what() + ")"s);
    }
    json response;
    try {
        response = json::parse(response_s);
    } catch (std::exception &x) {
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
    } catch (std::exception &x) {
        throw std::runtime_error("jsonrpc server error: "s + x.what());
    }
}

namespace cartesi {

void jsonrpc_virtual_machine::shutdown_server() {
    bool result = false;
    jsonrpc_request(m_ioc, m_stream, m_address, "shutdown", std::tie(), result, m_timeout, false);
}

void jsonrpc_virtual_machine::delay_next_request(uint64_t ms) const {
    bool result = false;
    jsonrpc_request(m_ioc, m_stream, m_address, "delay_next_request", std::tie(ms), result, m_timeout);
}

void jsonrpc_virtual_machine::set_timeout(int64_t ms) {
    m_timeout = ms;
}

int64_t jsonrpc_virtual_machine::get_timeout() const {
    return m_timeout;
}

void jsonrpc_virtual_machine::set_cleanup_call(cleanup_call call) {
    m_call = call;
}

auto jsonrpc_virtual_machine::get_cleanup_call() const -> cleanup_call {
    return m_call;
}

const std::string &jsonrpc_virtual_machine::get_server_address() const {
    return m_address;
}

static inline std::string semver_to_string(uint32_t major, uint32_t minor) {
    return std::to_string(major) + "." + std::to_string(minor);
}

void jsonrpc_virtual_machine::check_server_version() const {
    const auto server_version = get_server_version();
    if (server_version.major != JSONRPC_VERSION_MAJOR || server_version.minor != JSONRPC_VERSION_MINOR) {
        throw std::runtime_error{"expected server version "s +
            semver_to_string(JSONRPC_VERSION_MAJOR, JSONRPC_VERSION_MINOR) + " (got "s +
            semver_to_string(server_version.major, server_version.minor) + ")"s};
    }
}

jsonrpc_virtual_machine::jsonrpc_virtual_machine(std::string address) : m_address(std::move(address)) {
    // Install handler to ignore SIGPIPE lest we crash when a server closes a connection
    os_disable_sigpipe();
    check_server_version();
}

#ifdef HAVE_FORK

jsonrpc_virtual_machine::jsonrpc_virtual_machine([[maybe_unused]] const std::string &address,
    [[maybe_unused]] fork_result &spawned) {
    throw std::runtime_error{"fork() is unsupported in this platform"s};
}

#else

static boost::asio::ip::tcp::endpoint address_to_endpoint(const std::string &address) {
    try {
        const auto pos = address.find_last_of(':');
        const std::string ip = address.substr(0, pos);
        const int port = std::stoi(address.substr(pos + 1));
        if (port < 0 || port > 65535) {
            throw std::runtime_error{"invalid port"};
        }
        return {boost::asio::ip::make_address(ip), static_cast<uint16_t>(port)};
    } catch (std::exception &e) {
        throw std::runtime_error{"invalid endpoint address \"" + address + "\""};
    }
}

static std::string endpoint_to_string(const boost::asio::ip::tcp::endpoint &endpoint) {
    std::ostringstream ss;
    ss << endpoint;
    return ss.str();
}

jsonrpc_virtual_machine::jsonrpc_virtual_machine([[maybe_unused]] const std::string &address,
    [[maybe_unused]] fork_result &spawned) {
    // this function first blocks SIGUSR1, SIGUSR2 and SIGALRM.
    // then it double-forks.
    // the grand-child sends the parent a SIGUSR2 and suicides if failed before execing jsonrpc-remote-cartesi-machine.
    // otherwise, jsonrpc-remote-cartesi-machine itself sends the parent a SIGUSR1 to notify it is ready.
    // the parent sets up to receive a SIGALRM after 15 seconds and then waits for SIGUSR1, SIGUSR2 or SIGALRM
    // if it gets SIGALRM, the grand-child is unresponsive, so the parent kills it and the constructor fails.
    // if it gets SIGUSR2, the grand-child failed before exec and suicided, so the constructor fails.
    // if it gets SIGUSR1, jsonrpc-remote-cartesi-machine is ready and the constructor succeeds.
    boost::asio::io_context ioc{1};
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    boost::asio::ip::tcp::acceptor a(ioc, address_to_endpoint(address));
    // already done by constructor
    // a.open(endpoint.protocol());
    // a.set_option(asio::socket_base::reuse_address(true));
    // a.bind(endpoint);
    // a.listen(asio::socket_base::max_listen_connections);
    sigset_t mask{};
    sigset_t omask{};
    sigemptyset(&mask);        // always returns 0
    sigaddset(&mask, SIGUSR1); // always returns 0
    sigaddset(&mask, SIGUSR2); // always returns 0
    sigaddset(&mask, SIGALRM); // always returns 0
    if (sigprocmask(SIG_BLOCK, &mask, &omask) < 0) {
        // sigprocmask can only fail if we screwed up the values. this can't happen.
        // being paranoid, if it *did* happen, we are trying to avoid a situation where
        // our process gets killed when the grand-child or the alarm tries to signal us
        // and the signals are not blocked
        throw std::system_error{errno, std::generic_category(), "sigprocmask failed"};
    }
    bool restore_sigprocmask = true;
    const char *bin = getenv("JSONRPC_REMOTE_CARTESI_MACHINE");
    if (bin == nullptr) {
        bin = "jsonrpc-remote-cartesi-machine";
    }
    auto ppid = getpid();
    bool restore_grand_child = false;
    const int32_t grand_child = cartesi::os_double_fork_or_throw(false);
    if (grand_child == 0) { // grand-child and double-fork() succeeded
        sigprocmask(SIG_SETMASK, &omask, nullptr);
        char sigusr1[256] = "";
        std::ignore = snprintf(sigusr1, std::size(sigusr1), "--sigusr1=%d", ppid);
        char server_fd[256] = "";
        std::ignore = snprintf(server_fd, std::size(server_fd), "--server-fd=%d", a.native_handle());
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        char *args[] = {const_cast<char *>(bin), server_fd, sigusr1, nullptr};
        if (execvp(bin, args) < 0) {
            // here we failed to run jsonrpc-remote-cartesi-machine. nothing we can do.
            kill(ppid, SIGUSR2); // notify parent as soon as possible that we failed.
            exit(1);
        };
        // code never reaches here
    } else if (grand_child > 0) {   // parent and double-fork() succeeded
        restore_grand_child = true; // make sure grand-child is killed if we fail
        m_address = endpoint_to_string(a.local_endpoint());
        a.close();
        struct itimerval ovalue {};
        bool restore_itimer = false;
        try {
            struct itimerval value {};
            memset(&value, 0, sizeof(value));
            value.it_interval.tv_sec = 0;
            value.it_interval.tv_usec = 0;
            value.it_value.tv_sec = 15;
            value.it_value.tv_usec = 0;
            if (setitimer(ITIMER_REAL, &value, &ovalue) < 0) {
                // setitimer only fails if we screwed up with the values. this should not happen.
                // being paranoid, if it *did* happen, and if the grand-child also failed to signal us,
                // we might hang forever in the following call to sigwait.
                // we prefer to give up instead of risking a deadlock.
                throw std::system_error{errno, std::generic_category(), "setitimer failed"};
            }
            restore_itimer = true;
            int sig = 0;
            if (auto ret = sigwait(&mask, &sig); ret != 0) {
                throw std::system_error{ret, std::generic_category(), "sigwait failed"};
            }
            if (sig == SIGALRM) { // grand-child didn't signal us before alarm
                throw std::runtime_error{"grand-child process unresponsive"};
            }
            if (sig == SIGUSR2) { // grand-child signaled us that it failed to exec
                // grand-child will have exited on its own
                restore_grand_child = false;
                throw std::runtime_error{"failed to run '"s + bin + "'"s};
            }
            // grand-child signaled us that everything is fine
            assert(sig == SIGUSR1);
            setitimer(ITIMER_REAL, &ovalue, nullptr);
            restore_itimer = false;
            sigprocmask(SIG_SETMASK, &omask, nullptr);
            restore_sigprocmask = false;
            spawned.pid = grand_child;
            spawned.address = m_address;
            // Install handler to ignore SIGPIPE lest we crash when a server closes a connection
            os_disable_sigpipe();
            check_server_version();
        } catch (...) {
            if (restore_sigprocmask) {
                sigprocmask(SIG_SETMASK, &omask, nullptr);
            }
            if (restore_grand_child) {
                kill(grand_child, SIGTERM);
            }
            if (restore_itimer) {
                setitimer(ITIMER_REAL, &ovalue, nullptr);
            }
            throw;
        }
    }
}

#endif

void jsonrpc_virtual_machine::do_load(const std::string &directory, const machine_runtime_config &runtime) {
    bool result = false;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.load", std::tie(directory, runtime), result, m_timeout);
}

bool jsonrpc_virtual_machine::do_is_empty() const {
    bool result = false;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.is_empty", std::tie(), result, m_timeout);
    return result;
}

i_virtual_machine *jsonrpc_virtual_machine::do_clone_empty() const {
    auto fork_result = fork_server();
    auto *clone = new jsonrpc_virtual_machine(fork_result.address);
    try {
        if (!clone->is_empty()) {
            clone->destroy();
        }
    } catch (...) {
        clone->shutdown_server();
        delete clone;
        throw;
    }
    return clone;
};

void jsonrpc_virtual_machine::do_create(const machine_config &config, const machine_runtime_config &runtime) {
    bool result = false;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.create", std::tie(config, runtime), result, m_timeout);
}

jsonrpc_virtual_machine::~jsonrpc_virtual_machine() {
    // If configured to destroy machine, do it
    if (m_call == cleanup_call::destroy) {
        try {
            destroy();
        } catch (...) { // NOLINT(bugprone-empty-catch)
            // We guard against exceptions here, which would only mean we failed to cleanup.
            // We do not guarantee that we will cleanup. It's a best-effort thing.
        }
    }
    // If configured to shutdown server, do it
    if (m_call == cleanup_call::shutdown) {
        try {
            shutdown_server();
        } catch (...) { // NOLINT(bugprone-empty-catch)
            // We guard against exceptions here, which would only mean we failed to cleanup.
            // We do not guarantee that we will cleanup. It's a best-effort thing.
        }
    }
    // Gracefully close any established keep alive connection
    if (m_stream.socket().is_open()) {
        beast::error_code ec;
        std::ignore = m_stream.socket().shutdown(tcp::socket::shutdown_both, ec);
        std::ignore = m_stream.socket().close(ec);
    }
}

machine_config jsonrpc_virtual_machine::do_get_initial_config() const {
    machine_config result;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.get_initial_config", std::tie(), result, m_timeout);
    return result;
}

machine_runtime_config jsonrpc_virtual_machine::do_get_runtime_config() const {
    machine_runtime_config result;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.get_runtime_config", std::tie(), result, m_timeout);
    return result;
}

void jsonrpc_virtual_machine::do_set_runtime_config(const machine_runtime_config &r) {
    bool result = false;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.set_runtime_config", std::tie(r), result, m_timeout);
}

semantic_version jsonrpc_virtual_machine::get_server_version() const {
    semantic_version result;
    jsonrpc_request(m_ioc, m_stream, m_address, "get_version", std::tie(), result, m_timeout);
    return result;
}

interpreter_break_reason jsonrpc_virtual_machine::do_run(uint64_t mcycle_end) {
    interpreter_break_reason result = interpreter_break_reason::failed;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.run", std::tie(mcycle_end), result, m_timeout);
    return result;
}

void jsonrpc_virtual_machine::do_store(const std::string &directory) const {
    bool result = false;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.store", std::tie(directory), result, m_timeout);
}

uint64_t jsonrpc_virtual_machine::do_read_reg(reg r) const {
    uint64_t result = 0;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.read_reg", std::tie(r), result, m_timeout);
    return result;
}

void jsonrpc_virtual_machine::do_write_reg(reg w, uint64_t val) {
    bool result = false;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.write_reg", std::tie(w, val), result, m_timeout);
}

auto jsonrpc_virtual_machine::fork_server() const -> fork_result {
    fork_result result{};
    jsonrpc_request(m_ioc, m_stream, m_address, "fork", std::tie(), result, m_timeout, false);
    return result;
}

std::string jsonrpc_virtual_machine::rebind_server(const std::string &address) {
    std::string result;
    jsonrpc_request(m_ioc, m_stream, m_address, "rebind", std::tie(address), result, m_timeout, false);
    m_address = result;
    return result;
}

void jsonrpc_virtual_machine::emancipate_server() const {
    bool result = false;
    jsonrpc_request(m_ioc, m_stream, m_address, "emancipate", std::tie(), result, m_timeout);
}

void jsonrpc_virtual_machine::do_read_memory(uint64_t address, unsigned char *data, uint64_t length) const {
    std::string result;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.read_memory", std::tie(address, length), result, m_timeout);
    std::string bin = cartesi::decode_base64(result);
    if (bin.size() != length) {
        throw std::runtime_error("jsonrpc server error: invalid decoded base64 data length");
    }
    std::memcpy(data, bin.data(), length);
}

void jsonrpc_virtual_machine::do_write_memory(uint64_t address, const unsigned char *data, uint64_t length) {
    bool result = false;
    std::string b64 = cartesi::encode_base64(data, length);
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.write_memory", std::tie(address, b64), result, m_timeout);
}

void jsonrpc_virtual_machine::do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) {
    std::string result;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.read_virtual_memory", std::tie(address, length), result,
        m_timeout);
    std::string bin = cartesi::decode_base64(result);
    if (bin.size() != length) {
        throw std::runtime_error("jsonrpc server error: invalid decoded base64 data length");
    }
    std::memcpy(data, bin.data(), length);
}

void jsonrpc_virtual_machine::do_write_virtual_memory(uint64_t address, const unsigned char *data, uint64_t length) {
    bool result = false;
    std::string b64 = cartesi::encode_base64(data, length);
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.write_virtual_memory", std::tie(address, b64), result,
        m_timeout);
}

uint64_t jsonrpc_virtual_machine::do_translate_virtual_address(uint64_t vaddr) {
    uint64_t result = 0;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.translate_virtual_address", std::tie(vaddr), result,
        m_timeout);
    return result;
}

void jsonrpc_virtual_machine::do_reset_uarch() {
    bool result = false;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.reset_uarch", std::tie(), result, m_timeout);
}

access_log jsonrpc_virtual_machine::do_log_reset_uarch(const access_log::type &log_type) {
    not_default_constructible<access_log> result;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.log_reset_uarch", std::tie(log_type), result, m_timeout);
    if (!result.has_value()) {
        throw std::runtime_error("jsonrpc server error: missing result");
    }
    return std::move(result).value();
}

void jsonrpc_virtual_machine::do_get_root_hash(hash_type &hash) const {
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.get_root_hash", std::tie(), hash, m_timeout);
}

machine_merkle_tree::proof_type jsonrpc_virtual_machine::do_get_proof(uint64_t address, int log2_size) const {
    not_default_constructible<machine_merkle_tree::proof_type> result;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.get_proof", std::tie(address, log2_size), result, m_timeout);
    if (!result.has_value()) {
        throw std::runtime_error("jsonrpc server error: missing result");
    }
    return std::move(result).value();
}

void jsonrpc_virtual_machine::do_replace_memory_range(const memory_range_config &new_range) {
    bool result = false;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.replace_memory_range", std::tie(new_range), result, m_timeout);
}

access_log jsonrpc_virtual_machine::do_log_step_uarch(const access_log::type &log_type) {
    not_default_constructible<access_log> result;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.log_step_uarch", std::tie(log_type), result, m_timeout);
    if (!result.has_value()) {
        throw std::runtime_error("jsonrpc server error: missing result");
    }
    return std::move(result).value();
}

void jsonrpc_virtual_machine::do_destroy() {
    bool result = false;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.destroy", std::tie(), result, m_timeout);
}

bool jsonrpc_virtual_machine::do_verify_dirty_page_maps() const {
    bool result = false;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.verify_dirty_page_maps", std::tie(), result, m_timeout);
    return result;
}

uint64_t jsonrpc_virtual_machine::do_read_word(uint64_t address) const {
    uint64_t result = 0;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.read_word", std::tie(address), result, m_timeout);
    return result;
}

bool jsonrpc_virtual_machine::do_verify_merkle_tree() const {
    bool result = false;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.verify_merkle_tree", std::tie(), result, m_timeout);
    return result;
}

uarch_interpreter_break_reason jsonrpc_virtual_machine::do_run_uarch(uint64_t uarch_cycle_end) {
    uarch_interpreter_break_reason result = uarch_interpreter_break_reason::reached_target_cycle;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.run_uarch", std::tie(uarch_cycle_end), result, m_timeout);
    return result;
}

machine_memory_range_descrs jsonrpc_virtual_machine::do_get_memory_ranges() const {
    machine_memory_range_descrs result;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.get_memory_ranges", std::tie(), result, m_timeout);
    return result;
}

void jsonrpc_virtual_machine::do_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length) {
    bool result = false;
    std::string b64 = cartesi::encode_base64(data, length);
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.send_cmio_response", std::tie(reason, b64), result, m_timeout);
}

access_log jsonrpc_virtual_machine::do_log_send_cmio_response(uint16_t reason, const unsigned char *data,
    uint64_t length, const access_log::type &log_type) {
    not_default_constructible<access_log> result;
    std::string b64 = cartesi::encode_base64(data, length);
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.log_send_cmio_response", std::tie(reason, b64, log_type),
        result, m_timeout);
    if (!result.has_value()) {
        throw std::runtime_error("jsonrpc server error: missing result");
    }
    return std::move(result).value();
}

uint64_t jsonrpc_virtual_machine::do_get_reg_address(reg r) const {
    uint64_t result = 0;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.get_reg_address", std::tie(r), result, m_timeout);
    return result;
}

machine_config jsonrpc_virtual_machine::do_get_default_config() const {
    machine_config result;
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.get_default_config", std::tie(), result, m_timeout);
    return result;
}

void jsonrpc_virtual_machine::do_verify_step_uarch(const hash_type &root_hash_before, const access_log &log,
    const hash_type &root_hash_after) const {
    bool result = false;
    auto b64_root_hash_before = encode_base64(root_hash_before);
    auto b64_root_hash_after = encode_base64(root_hash_after);
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.verify_step_uarch",
        std::tie(b64_root_hash_before, log, b64_root_hash_after), result, m_timeout);
}

void jsonrpc_virtual_machine::do_verify_reset_uarch(const hash_type &root_hash_before, const access_log &log,
    const hash_type &root_hash_after) const {
    bool result = false;
    auto b64_root_hash_before = encode_base64(root_hash_before);
    auto b64_root_hash_after = encode_base64(root_hash_after);
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.verify_reset_uarch",
        std::tie(b64_root_hash_before, log, b64_root_hash_after), result, m_timeout);
}

void jsonrpc_virtual_machine::do_verify_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
    const hash_type &root_hash_before, const access_log &log, const hash_type &root_hash_after) const {
    bool result = false;
    std::string b64_data = cartesi::encode_base64(data, length);
    auto b64_root_hash_before = encode_base64(root_hash_before);
    auto b64_root_hash_after = encode_base64(root_hash_after);
    jsonrpc_request(m_ioc, m_stream, m_address, "machine.verify_send_cmio_response",
        std::tie(reason, b64_data, b64_root_hash_before, log, b64_root_hash_after), result, m_timeout);
}

bool jsonrpc_virtual_machine::do_is_jsonrpc_virtual_machine() const {
    return true;
}

} // namespace cartesi
