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

#include "jsonrpc-machine.hpp"
#include "cm-exception.hpp"
#include "os-features.hpp"

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
#include <vector>

#ifdef HAVE_FORK
#include <fcntl.h>
#include <spawn.h>
#include <sys/socket.h>
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

#include "access-log.hpp"
#include "address-range-constants.hpp"
#include "address-range-description.hpp"
#include "back-merkle-tree.hpp"
#include "base64.hpp"
#include "hash-tree-proof.hpp"
#include "hash-tree-stats.hpp"
#include "i-machine.hpp"
#include "interpret.hpp"
#include "json-util.hpp"
#include "jsonrpc-cmio-request.hpp"
#include "jsonrpc-endpoint.hpp"
#include "jsonrpc-fork-result.hpp"
#include "jsonrpc-version.hpp"
#include "machine-config.hpp"
#include "machine-hash.hpp"
#include "machine-runtime-config.hpp"
#include "mcycle-root-hashes.hpp"
#include "os.hpp"
#include "scope-exit.hpp"
#include "semantic-version.hpp"
#include "uarch-cycle-root-hashes.hpp"
#include "uarch-interpret.hpp"

using namespace std::string_literals;
using json = nlohmann::json;

static bool jsonrpc_parse_callback(int depth, json::parse_event_t /*event*/, json & /*parsed*/) {
    if (depth > 256) {
        throw std::runtime_error{"JSON nesting depth exceeds 256"};
    }
    return true;
}

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

// Opens a socket or acceptor that spawned processes do not inherit, which Asio does not do on its own.
static void open_socket(auto &socket, const tcp &protocol) {
#ifdef HAVE_FORK
#ifdef SOCK_CLOEXEC
    const int fd = ::socket(protocol.family(), protocol.type() | SOCK_CLOEXEC, protocol.protocol());
#else
    const int fd = ::socket(protocol.family(), protocol.type(), protocol.protocol());
    if (fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        const int fcntl_errno = errno;
        ::close(fd);
        throw std::system_error{fcntl_errno, std::generic_category(), "unable to set close-on-exec on socket"};
    }
#endif
    if (fd < 0) {
        throw std::system_error{errno, std::generic_category(), "unable to open socket"};
    }
    beast::error_code ec;
    std::ignore = socket.assign(protocol, fd, ec);
    if (ec) {
        ::close(fd);
        throw beast::system_error(ec);
    }
#else
    socket.open(protocol);
#endif
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
    const asio::ip::tcp::endpoint remote_endpoint = cartesi::address_to_endpoint(remote_address);
    if (remote_endpoint.port() == 0) {
        throw std::invalid_argument{"cannot connect to port 0 of \"" + remote_address + "\""};
    }

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
        open_socket(stream.socket(), remote_endpoint.protocol());
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
        response = json::parse(response_s, jsonrpc_parse_callback);
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
        if (!jerror.contains("message") || !jerror["message"].is_string()) {
            throw std::runtime_error(R"(jsonrpc server error: invalid "error/message" field (expected string))"s);
        }
        auto message = jerror["message"].template get<std::string>();
        if (jerror.contains("data") && jerror["data"].is_number_integer()) {
            cartesi::cm_error_code_to_exception(static_cast<cm_error>(jerror["data"].template get<int>()), message);
        }
        throw std::runtime_error(message);
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
    os::disable_sigpipe();

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
    os::disable_sigpipe();
}

#ifdef HAVE_FORK

jsonrpc_machine::jsonrpc_machine(const std::string &address, int64_t spawn_timeout_ms, fork_result &spawned) :
    m_ioc(new boost::asio::io_context{1}),
    m_stream(new boost::beast::tcp_stream(*m_ioc)),
    m_call(cleanup_call::shutdown) {

    // Determine spawn timeout time
    const auto timeout_at = spawn_timeout_ms >= 0 ?
        (std::chrono::steady_clock::now() + std::chrono::milliseconds(spawn_timeout_ms)) :
        std::chrono::time_point<std::chrono::steady_clock>::max();

    // Create a TCP acceptor, bind it to the specified address, and listen on it
    const auto endpoint = address_to_endpoint(address);
    boost::asio::ip::tcp::acceptor a(*m_ioc);
    open_socket(a, endpoint.protocol());
    a.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    a.bind(endpoint);
    a.listen();

    // Determine which remote machine binary to use
    const char *bin = getenv("CARTESI_JSONRPC_MACHINE");
    if (bin == nullptr) { // Fallback to default name if not set
        bin = "cartesi-jsonrpc-machine";
    }

    // The child inherits only the standard streams and the acceptor. Our sockets are close-on-exec, and dup2 clears
    // that flag on the copy, so the acceptor goes to a descriptor other than its own.
    const int acceptor_fd = a.native_handle();
    const int child_acceptor_fd = acceptor_fd == STDERR_FILENO + 1 ? STDERR_FILENO + 2 : STDERR_FILENO + 1;
    posix_spawn_file_actions_t actions{};
    if (const int error = posix_spawn_file_actions_init(&actions); error != 0) {
        throw std::system_error{error, std::generic_category(), "posix_spawn_file_actions_init() failed"};
    }
    auto actions_destroyer = make_scope_exit([&] { std::ignore = posix_spawn_file_actions_destroy(&actions); });
    if (const int error = posix_spawn_file_actions_adddup2(&actions, acceptor_fd, child_acceptor_fd); error != 0) {
        throw std::system_error{error, std::generic_category(), "posix_spawn_file_actions_adddup2() failed"};
    }
    posix_spawnattr_t attributes{};
    if (const int error = posix_spawnattr_init(&attributes); error != 0) {
        throw std::system_error{error, std::generic_category(), "posix_spawnattr_init() failed"};
    }
    auto attributes_destroyer = make_scope_exit([&] { std::ignore = posix_spawnattr_destroy(&attributes); });
    // The child starts with no signals blocked and with the default actions for the signals that stop it, whatever
    // the calling thread blocks or handles. Otherwise a caller that blocks SIGTERM leaves us unable to stop the child.
    sigset_t blocked_signals{};
    sigemptyset(&blocked_signals);
    if (const int error = posix_spawnattr_setsigmask(&attributes, &blocked_signals); error != 0) {
        throw std::system_error{error, std::generic_category(), "posix_spawnattr_setsigmask() failed"};
    }
    sigset_t default_signals{};
    sigemptyset(&default_signals);
    for (const int signal : {SIGINT, SIGTERM, SIGCHLD}) {
        sigaddset(&default_signals, signal);
    }
    if (const int error = posix_spawnattr_setsigdefault(&attributes, &default_signals); error != 0) {
        throw std::system_error{error, std::generic_category(), "posix_spawnattr_setsigdefault() failed"};
    }
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    // Other descriptors of the process may lack close-on-exec, so close everything but what the child needs
    const auto flags =
        static_cast<int16_t>(POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_CLOEXEC_DEFAULT);
#else
    const auto flags = static_cast<int16_t>(POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
#endif
    if (const int error = posix_spawnattr_setflags(&attributes, flags); error != 0) {
        throw std::system_error{error, std::generic_category(), "posix_spawnattr_setflags() failed"};
    }
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    for (const int fd : {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO}) {
        if (const int error = posix_spawn_file_actions_addinherit_np(&actions, fd); error != 0) {
            throw std::system_error{error, std::generic_category(), "posix_spawn_file_actions_addinherit_np() failed"};
        }
    }
#endif

    // Prepare command-line arguments for the child process
    char server_fd[256] = "";
    std::ignore = snprintf(server_fd, std::size(server_fd), "--server-fd=%d", child_acceptor_fd);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    char *const args[] = {const_cast<char *>(bin), server_fd, nullptr};

    // Idle OpenMP threads that spin slow hash-tree updates down on busy hosts. libgomp reads the wait policy only
    // from the environment at startup, so the child gets a passive one unless the caller chose otherwise.
    std::vector<char *> child_environ;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    for (char *const *entry = environ; *entry != nullptr; ++entry) {
        child_environ.push_back(*entry);
    }
    static char passive_wait_policy[] = "OMP_WAIT_POLICY=passive";
    if (getenv("OMP_WAIT_POLICY") == nullptr) {
        child_environ.push_back(passive_wait_policy);
    }
    child_environ.push_back(nullptr);

    // Spawn the remote machine as a child process
    pid_t child_pid{};
    if (const int error = posix_spawnp(&child_pid, bin, &actions, &attributes, args, child_environ.data());
        error != 0) {
        throw std::system_error{error, std::generic_category(), "posix_spawnp() failed to spawn server process"};
    }

#ifdef CODE_COVERAGE
    // In a coverage build, the child flushes its gcov counters to the .gcda files shared by
    // every instrumented process when it exits. A signal that lands during the flush kills
    // the child in the middle of a file rewrite and corrupts the shared counters. Once the
    // child has acknowledged a shutdown request it is already exiting on its own, so we
    // skip signaling it and simply wait.
    bool child_shutdown_requested = false;
#endif

    // Create a scope exit handler to ensure child processes are properly cleaned up
    // This prevents zombie processes by making sure we wait for the child to exit
    auto child_waiter = make_scope_exit([&] {
        // Close any keep alive open connection first
        if (m_stream && m_stream->socket().is_open()) {
            shutdown_and_close_socket(m_stream->socket());
        }

#ifdef CODE_COVERAGE
        const bool signal_child = !child_shutdown_requested;
#else
        const bool signal_child = true;
#endif
        // Attempt to gracefully terminate the child process
        if (signal_child) {
            std::ignore = kill(child_pid, SIGTERM);
        }

        // Wait for the child process to fully exit
        while (true) {
            const auto wait_ret = waitpid(child_pid, nullptr, 0);

            // If waitpid() was interrupted by a signal (EINTR), we need to retry
            // This can happen if another signal arrives during our waitpid() call
            if (wait_ret == -1 && errno == EINTR) {
                // Send SIGILL to ensure child process termination
                // This helps in case the interrupting signal affected the child's state
                if (signal_child) {
                    std::ignore = kill(child_pid, SIGILL);
                }
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
    os::disable_sigpipe();

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
#ifdef CODE_COVERAGE
    child_shutdown_requested = true;
#endif
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

jsonrpc_machine::jsonrpc_machine(const std::string & /*address*/, int64_t /*spawn_timeout_ms*/,
    fork_result & /*spawned*/) {
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
    auto clone = std::make_unique<jsonrpc_machine>(fork_result.address);
    clone->set_timeout(m_timeout);
    clone->set_cleanup_call(cleanup_call::shutdown);
    if (!clone->is_empty()) {
        clone->destroy();
    }
    return clone.release();
}

void jsonrpc_machine::do_create(const machine_config &config, const machine_runtime_config &runtime,
    const std::string &dir, sharing_mode sharing) {
    bool result = false;
    request("machine.create", std::tie(config, runtime, dir, sharing), result);
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

mcycle_root_hashes jsonrpc_machine::do_collect_mcycle_root_hashes(uint64_t mcycle_end, uint64_t log2_mcycle_period,
    uint64_t mcycle_phase, int32_t log2_bundle_mcycle_count,
    const std::optional<back_merkle_tree> &previous_partial_bundle) {
    mcycle_root_hashes result;
    request("machine.collect_mcycle_root_hashes",
        std::tie(mcycle_end, log2_mcycle_period, mcycle_phase, log2_bundle_mcycle_count, previous_partial_bundle),
        result);
    return result;
}

machine_hashes jsonrpc_machine::do_collect_mcycle_bundle(uint64_t bundle_offset, uint64_t log2_mcycle_period,
    int32_t log2_bundle_mcycle_count) {
    machine_hashes result;
    request("machine.collect_mcycle_bundle", std::tie(bundle_offset, log2_mcycle_period, log2_bundle_mcycle_count),
        result);
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

void jsonrpc_machine::do_rename_stored(const std::string &from_dir, const std::string &to_dir) const {
    bool result = false;
    request("machine.rename_stored", std::tie(from_dir, to_dir), result);
}

void jsonrpc_machine::do_remove_stored(const std::string &dir, remove_mode mode) const {
    bool result = false;
    request("machine.remove_stored", std::tie(dir, mode), result);
}

void jsonrpc_machine::do_sync_stored(const std::string &dir) const {
    bool result = false;
    request("machine.sync_stored", std::tie(dir), result);
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
    if (data == nullptr && length > 0) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    std::string result;
    request("machine.read_memory", std::tie(address, length), result);
    std::string bin = cartesi::decode_base64(result);
    if (bin.size() != length) {
        throw std::runtime_error("jsonrpc server error: invalid decoded base64 data length");
    }
    std::memcpy(data, bin.data(), length);
}

void jsonrpc_machine::do_write_memory(uint64_t address, const unsigned char *data, uint64_t length) {
    if (data == nullptr && length > 0) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    bool result = false;
    std::string b64 = cartesi::encode_base64(std::span<const unsigned char>{data, length});
    request("machine.write_memory", std::tie(address, b64), result);
}

void jsonrpc_machine::do_read_virtual_memory(uint64_t address, unsigned char *data, uint64_t length) {
    if (data == nullptr && length > 0) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    std::string result;
    request("machine.read_virtual_memory", std::tie(address, length), result);
    std::string bin = cartesi::decode_base64(result);
    if (bin.size() != length) {
        throw std::runtime_error("jsonrpc server error: invalid decoded base64 data length");
    }
    std::memcpy(data, bin.data(), length);
}

void jsonrpc_machine::do_write_virtual_memory(uint64_t address, const unsigned char *data, uint64_t length) {
    if (data == nullptr && length > 0) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    bool result = false;
    std::string b64 = cartesi::encode_base64(std::span<const unsigned char>{data, length});
    request("machine.write_virtual_memory", std::tie(address, b64), result);
}

uint64_t jsonrpc_machine::do_translate_virtual_address(uint64_t vaddr) {
    uint64_t result = 0;
    request("machine.translate_virtual_address", std::tie(vaddr), result);
    return result;
}

uint64_t jsonrpc_machine::do_read_console_output(uint8_t *data, uint64_t max_length) {
    uint64_t read_len{0};
    if (data == nullptr || max_length == 0) { // Query mode
        uint64_t result = 0;
        request("machine.read_console_output", std::tie(), result);
        read_len = result;
    } else {
        std::string result;
        request("machine.read_console_output", std::tie(max_length), result);
        std::string bin = cartesi::decode_base64(result);
        if (bin.length() > max_length) {
            throw std::runtime_error("jsonrpc server error: invalid decoded base64 data length");
        }
        if (!bin.empty()) {
            std::memcpy(data, bin.data(), bin.length()); // NOLINT(bugprone-not-null-terminated-result)
        }
        read_len = bin.length();
    }
    return read_len;
}

uint64_t jsonrpc_machine::do_write_console_input(const uint8_t *data, uint64_t length) {
    uint64_t result = 0;
    if (data == nullptr || length == 0) { // Query mode
        request("machine.write_console_input", std::tie(), result);
    } else {
        std::string b64 = cartesi::encode_base64(std::span<const unsigned char>{data, length});
        request("machine.write_console_input", std::tie(b64), result);
    }
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

machine_hash jsonrpc_machine::do_read_revert_root_hash() const {
    machine_hash hash;
    request("machine.read_revert_root_hash", std::tie(), hash);
    return hash;
}

void jsonrpc_machine::do_write_revert_root_hash(const_machine_hash_view hash) {
    bool result{};
    auto b64 = encode_base64(hash);
    request("machine.write_revert_root_hash", std::tie(b64), result);
}

machine_hash jsonrpc_machine::do_get_node_hash(uint64_t address, int log2_size) const {
    machine_hash hash;
    request("machine.get_node_hash", std::tie(address, log2_size), hash);
    return hash;
}

hash_tree_proof jsonrpc_machine::do_get_proof(uint64_t address, int log2_target_size, int log2_root_size) const {
    not_default_constructible<hash_tree_proof> result;
    request("machine.get_proof", std::tie(address, log2_target_size, log2_root_size), result);
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

void jsonrpc_machine::do_clear_hash_tree() {
    bool result = false;
    request("machine.clear_hash_tree", std::tie(), result);
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
    uarch_interpreter_break_reason result = uarch_interpreter_break_reason::reached_target_uarch_cycle;
    request("machine.run_uarch", std::tie(uarch_cycle_end), result);
    return result;
}

uarch_cycle_root_hashes jsonrpc_machine::do_collect_uarch_cycle_root_hashes(uint64_t mcycle_end,
    int32_t log2_bundle_uarch_cycle_count, const machine_hashes &revert_uarch_tail) {
    uarch_cycle_root_hashes result;
    const base64_machine_hashes b64_revert_uarch_tail(revert_uarch_tail);
    request("machine.collect_uarch_cycle_root_hashes",
        std::tie(mcycle_end, log2_bundle_uarch_cycle_count, b64_revert_uarch_tail), result);
    return result;
}

machine_hashes jsonrpc_machine::do_collect_uarch_cycle_bundle(uint64_t bundle_offset,
    int32_t log2_bundle_uarch_cycle_count, const machine_hashes &revert_uarch_tail) {
    machine_hashes result;
    const base64_machine_hashes b64_revert_uarch_tail(revert_uarch_tail);
    request("machine.collect_uarch_cycle_bundle",
        std::tie(bundle_offset, log2_bundle_uarch_cycle_count, b64_revert_uarch_tail), result);
    return result;
}

address_range_descriptions jsonrpc_machine::do_get_address_ranges() const {
    address_range_descriptions result;
    request("machine.get_address_ranges", std::tie(), result);
    return result;
}

machine_cmio_request jsonrpc_machine::do_receive_cmio_request(std::span<uint8_t> data) const {
    jsonrpc_cmio_request result;
    const uint64_t max_length = data.size();
    request("machine.receive_cmio_request", std::tie(max_length), result);
    if (!data.empty()) {
        if (result.available_length > data.size()) {
            throw std::invalid_argument{"data buffer length is too small"};
        }
        if (result.data.size() != result.available_length) {
            throw std::runtime_error{"jsonrpc server returned inconsistent CMIO request data length"};
        }
        std::ranges::copy(result.data, data.begin());
    } else if (!result.data.empty()) {
        throw std::runtime_error{"jsonrpc server returned data for a CMIO request length query"};
    }
    return machine_cmio_request{.cmd = result.cmd,
        .reason = result.reason,
        .available_length = result.available_length,
        .data =
            !data.empty() ? std::span<const uint8_t>{data.first(result.available_length)} : std::span<const uint8_t>{}};
}

/// \brief Encodes the data of a cmio response for the server
/// \param data Response data, which can be NULL when \p length is oversized.
/// \param length Response data length.
/// \returns Base64 encoding of the data to send.
/// \details A response that does not fit in the rx buffer is a no-op that never reads its data, so it is sent as
/// the shortest such response, which needs no data from the caller and avoids sending data that is discarded.
static std::string encode_cmio_response_data(const unsigned char *data, uint32_t length) {
    if (length > AR_CMIO_RX_BUFFER_LENGTH) {
        const std::vector<unsigned char> oversized(AR_CMIO_RX_BUFFER_LENGTH + 1);
        return cartesi::encode_base64(std::span<const unsigned char>{oversized});
    }
    if (data == nullptr && length > 0) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    return cartesi::encode_base64(std::span<const unsigned char>{data, length});
}

void jsonrpc_machine::do_send_cmio_response(uint16_t reason, const unsigned char *data, uint32_t length,
    std::optional<const_machine_hash_view> revert_root_hash) {
    bool result = false;
    std::string b64 = encode_cmio_response_data(data, length);
    if (revert_root_hash.has_value()) {
        auto b64_revert_root_hash = encode_base64(*revert_root_hash);
        request("machine.send_cmio_response", std::tie(reason, b64, b64_revert_root_hash), result);
    } else {
        request("machine.send_cmio_response", std::tie(reason, b64), result);
    }
}

access_log jsonrpc_machine::do_log_send_cmio_response(uint16_t reason, const unsigned char *data, uint32_t length,
    const_machine_hash_view revert_root_hash, const access_log::type &log_type) {
    not_default_constructible<access_log> result;
    auto b64_revert_root_hash = encode_base64(revert_root_hash);
    std::string b64 = encode_cmio_response_data(data, length);
    request("machine.log_send_cmio_response", std::tie(reason, b64, b64_revert_root_hash, log_type), result);
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

machine_hash jsonrpc_machine::do_get_uarch_pristine_hash() const {
    machine_hash hash;
    request("machine.get_uarch_pristine_hash", std::tie(), hash);
    return hash;
}

machine_config jsonrpc_machine::do_get_default_config() const {
    machine_config result;
    request("machine.get_default_config", std::tie(), result);
    return result;
}

std::string jsonrpc_machine::do_get_address_name(uint64_t paddr) const {
    std::string result;
    request("machine.get_address_name", std::tie(paddr), result);
    return result;
}

machine_hash jsonrpc_machine::do_verify_step(const_machine_hash_view root_hash_before, const std::string &log_filename,
    uint64_t mcycle_count) const {
    machine_hash result;
    auto b64_root_hash_before = encode_base64(root_hash_before);
    request("machine.verify_step", std::tie(b64_root_hash_before, log_filename, mcycle_count), result);
    return result;
}

machine_hash jsonrpc_machine::do_verify_step_uarch(const_machine_hash_view root_hash_before,
    const access_log &log) const {
    machine_hash result;
    auto b64_root_hash_before = encode_base64(root_hash_before);
    request("machine.verify_step_uarch", std::tie(b64_root_hash_before, log), result);
    return result;
}

machine_hash jsonrpc_machine::do_verify_reset_uarch(const_machine_hash_view root_hash_before,
    const access_log &log) const {
    machine_hash result;
    auto b64_root_hash_before = encode_base64(root_hash_before);
    request("machine.verify_reset_uarch", std::tie(b64_root_hash_before, log), result);
    return result;
}

machine_hash jsonrpc_machine::do_verify_send_cmio_response(uint16_t reason, const unsigned char *data, uint32_t length,
    const_machine_hash_view root_hash_before, const access_log &log, const_machine_hash_view revert_root_hash) const {
    machine_hash result;
    std::string b64_data = encode_cmio_response_data(data, length);
    auto b64_root_hash_before = encode_base64(root_hash_before);
    auto b64_revert_root_hash = encode_base64(revert_root_hash);
    request("machine.verify_send_cmio_response",
        std::tie(reason, b64_data, b64_root_hash_before, log, b64_revert_root_hash), result);
    return result;
}

bool jsonrpc_machine::do_is_jsonrpc_machine() const {
    return true;
}

} // namespace cartesi
